"""
a2s_filter.py - drop fake Source-engine server replies before Steam sees them.

Steam's server browser sends A2S_INFO queries over UDP and servers answer with
name/map/players/max players. Fake servers lie in that reply.
This tool uses WinDivert (via pydivert) to intercept inbound A2S_INFO replies
and validate them before Steam gets to see them:

  1. Sanity rules  - max players > 64, players > max, 255 players, ...
  2. Active probe  - the reply is held, we query the server ourselves with
                     A2S_PLAYER and check that the real player list matches
                     the advertised player count (fakes usually can't).
  3. Duplicate     - many addresses advertising the same server name, or too
     rules           many ports on one IP, are treated as spam farms.

Run from an ELEVATED terminal:
    python src/a2s_filter.py              # dry-run: only logs what it WOULD drop
    python src/a2s_filter.py --enforce    # actually drops fake replies
    python src/a2s_filter.py --selftest   # rule tests, no admin needed
"""
import argparse
import os as _os


def asset_path(*parts):
    """assets/ folder: next to src/ when run from source, inside the bundle when frozen."""
    import sys as _sys
    base = getattr(_sys, "_MEIPASS", None) or _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..")
    return _os.path.normpath(_os.path.join(base, "assets", *parts))


import queue
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HEADER = b"\xff\xff\xff\xff"
CLUSTER_WINDOW = 700    # seconds: fake connect times are spread over ~600s
CLUSTER_MIN_AGE = 900   # seconds: only players connected at least this long count


# ---------------------------------------------------------------- parsing
def parse_a2s_info(payload):
    """Return dict(name, map, players, max_players, bots, appid) or None."""
    if len(payload) < 6 or payload[:4] != HEADER or payload[4] != 0x49:
        return None
    try:
        pos = 6  # skip header(4) + 'I'(1) + protocol(1)
        fields = []
        for _ in range(4):  # name, map, folder, game
            end = payload.index(b"\x00", pos)
            fields.append(payload[pos:end].decode("utf-8", "replace"))
            pos = end + 1
        appid, players, max_players, bots = struct.unpack_from("<HBBB", payload, pos)
        pos += 5
        info = {"name": fields[0], "map": fields[1], "game": fields[3], "appid": appid,
                "players": players, "max_players": max_players, "bots": bots,
                "gameport": None, "steamid": None}
        try:  # extra data flag (EDF) block: real servers advertise their own port + steamid
            pos += 4  # server type, environment, visibility, VAC
            pos = payload.index(b"\x00", pos) + 1  # version string
            edf = payload[pos]
            pos += 1
            if edf & 0x80:
                info["gameport"] = struct.unpack_from("<H", payload, pos)[0]
                pos += 2
            if edf & 0x10:
                info["steamid"] = struct.unpack_from("<Q", payload, pos)[0]
        except (ValueError, struct.error, IndexError):
            pass
        return info
    except (ValueError, struct.error):
        return None


def parse_a2s_players(data):
    """Return list of (name, score, duration) from an A2S_PLAYER reply,
    or None if the data is not a complete, parseable reply."""
    if len(data) < 6 or data[:4] != HEADER or data[4] != 0x44:
        return None
    count = data[5]
    pos, out = 6, []
    try:
        for _ in range(count):
            pos += 1  # index byte
            end = data.index(b"\x00", pos)
            name = data[pos:end].decode("utf-8", "replace")
            pos = end + 1
            score, dur = struct.unpack_from("<if", data, pos)
            pos += 8
            out.append((name, score, dur))
    except (ValueError, struct.error):
        return None
    return out


# ------------------------------------------------------------------ rules
def sanity_reason(info, max_valid):
    p, m = info["players"], info["max_players"]
    if m == 0:
        return "max players is 0"
    if m > max_valid:
        return f"max players {m} > {max_valid}"
    if p > m:
        return f"players {p} > max {m}"
    if p == 255:
        return "players is 255"
    return None


def identity_reason(addr, info):
    """The server's own idea of its port must match where the reply came from."""
    gp = info.get("gameport")
    if gp is not None and gp != addr[1]:
        return f"server claims port {gp} but replied from port {addr[1]}"
    return None


class SteamIdTracker:
    """One game-server steamid belongs to exactly one running server. The same
    steamid answering from several addresses means a copied/spoofed reply."""

    def __init__(self):
        self.ids = {}
        self.lock = threading.Lock()

    def check(self, addr, steamid):
        if not steamid:
            return None
        with self.lock:
            s = self.ids.setdefault(steamid, set())
            s.add(addr)
            if len(s) >= 2:
                return f"steamid {steamid} answers from {len(s)} addresses"
        return None


def is_random_case(name):
    """True for names like 'NiNjahaWk' / 'ShADOWNHaWk': inside a word, a single
    lowercase letter that sits right after an uppercase one, plus several case
    flips. Plain CamelCase ('ShadowHawk') has neither a lone lowercase letter
    between capitals nor that many flips."""
    for word in "".join(c if c.isalpha() else " " for c in name).split():
        if len(word) < 4:
            continue
        flips = sum(1 for a, b in zip(word, word[1:]) if a.isupper() != b.isupper())
        lone = 0
        for k in range(1, len(word)):
            if word[k].islower() and word[k - 1].isupper() and (k + 1 == len(word) or not word[k + 1].islower()):
                lone += 1
        if lone >= 1 and flips >= 3:
            return True
        # a capitals block in the middle of a word ('wiLDBAndIT'): 2+ capitals that are
        # both preceded and followed by a lowercase letter
        k = 1
        while k < len(word) - 1:
            if word[k].isupper() and word[k - 1].islower():
                e = k
                while e < len(word) and word[e].isupper():
                    e += 1
                if e - k >= 2 and e < len(word) and word[e].islower() and flips >= 3:
                    return True
                k = e
            else:
                k += 1
    return False


def padding_indices(info, plist):
    """Indices of the fake 'players' in the list (empty set = list looks normal).

    Three signatures of generated padding:
    1. Connect times: fakes are "base time + random 0..~600s", so a block of 10+
       established players (connected >= CLUSTER_MIN_AGE) inside one CLUSTER_WINDOW.
       Real players join over hours; a few bots (INFO's bots field) may share one
       time and are allowed for. Entries stepping by an exact constant (11, 22, 33...)
       next to that block count too.
    2. Names: fake names are random-case ('NiNjahaWk'). A list where 6+ names and at
       least a quarter of the list look like that is padded."""
    n = len(plist)
    if n < 4:
        return set()
    order = sorted(range(n), key=lambda i: plist[i][2])
    durs = [plist[i][2] for i in order]
    best, bi, j = 0, 0, 0
    for i in range(n):
        while durs[i] - durs[j] > CLUSTER_WINDOW:
            j += 1
        if durs[j] >= CLUSTER_MIN_AGE and i - j + 1 > best:
            best, bi = i - j + 1, j
    cluster_hit = best >= max(10, info["bots"] + 8)
    case_idx = {i for i in range(n) if is_random_case(plist[i][0])}
    case_hit = len(case_idx) >= 6 and len(case_idx) >= 0.25 * n
    if not (cluster_hit or case_hit):
        return set()
    flagged = set()
    if cluster_hit:
        flagged |= {order[k] for k in range(bi, bi + best)}
        runs = {}  # constant step -> sorted positions of runs of >= 3 equally spaced times
        i = 0
        while i < n - 2:
            step = durs[i + 1] - durs[i]
            j = i + 1
            while j + 1 < n and durs[j + 1] - durs[j] == step:
                j += 1
            if j - i + 1 >= 3 and step >= 1:
                runs.setdefault(step, set()).update(range(i, j + 1))
            i = max(j, i + 1)
        for members in runs.values():
            if len(members) >= 6:
                flagged |= {order[k] for k in members}
    if case_hit or len(case_idx) >= 6:
        flagged |= case_idx
    return flagged


def padding_size(info, plist):
    """Number of fake 'players' in the list, or 0 when the list looks normal."""
    return len(padding_indices(info, plist))


def players_reason(info, plist, drop_padding=True, skip=frozenset()):
    """Compare the advertised player count with the real A2S_PLAYER list.
    `skip` may contain 'mismatch', 'names', 'padding' to disable those checks."""
    p, bots = info["players"], info["bots"]
    n = len(plist)
    if "mismatch" not in skip and abs(n - p) > bots + 3:
        return f"A2S_PLAYER lists {n} but INFO says {p}"
    if n >= 4:
        names = [x[0] for x in plist]
        if "names" not in skip:
            if len(set(names)) == 1:
                return "all player names identical"
            if len(set(names)) < n * 0.8:
                return f"only {len(set(names))} unique names in {n} players"
            if len(set(round(x[2], 1) for x in plist)) == 1 and len(set(x[1] for x in plist)) == 1:
                return "all players have identical score and time"
        pad = 0 if "padding" in skip else padding_size(info, plist)
        if pad and drop_padding:
            return f"{pad} of {n} players connected at nearly the same time (bots={bots})"
    return None


def rewrite_info_players(payload, players):
    """Return the A2S_INFO payload with its player-count byte replaced."""
    pos = 6
    for _ in range(4):  # name, map, folder, game
        pos = payload.index(b"\x00", pos) + 1
    pos += 2  # appid
    return payload[:pos] + bytes([max(0, min(255, players))]) + payload[pos + 1:]


class DupTracker:
    """Flags spam farms: same name on many addresses / many ports per IP."""

    def __init__(self, max_same_name, max_per_ip, blocklist_file=None):
        self.max_same_name = max_same_name
        self.max_per_ip = max_per_ip
        self.names = {}   # name stem -> set(addr)
        self.ips = {}     # ip -> set(port)
        self.bad_ips = set()
        self.file = blocklist_file
        self.lock = threading.Lock()
        if self.file:
            try:
                with open(self.file) as f:
                    self.bad_ips = {l.strip() for l in f if l.strip()}
            except OSError:
                pass

    @staticmethod
    def stem(name):
        """'FB-CS.RU | DUST2 #1' and '... #7' share one stem: digits/#/punctuation ignored."""
        return "".join(c for c in name.lower() if c.isalpha())

    def _block(self, ips):
        if not self.file:  # --no-blocklist: judge each reply on its own, remember nothing
            return
        new = set(ips) - self.bad_ips
        if new:
            self.bad_ips |= new
            if self.file:
                try:
                    with open(self.file, "a") as f:
                        f.writelines(i + "\n" for i in sorted(new))
                except OSError:
                    pass

    def check(self, addr, name):
        ip, port = addr
        key = self.stem(name) or name.lower()
        with self.lock:
            if ip in self.bad_ips:
                return f"{ip} was flagged as a spam farm earlier (blocked_ips.txt)"
            s = self.names.setdefault(key, set())
            s.add(addr)
            ports = self.ips.setdefault(ip, set())
            ports.add(port)
            same_ips = {a[0] for a in s}  # a host running #1,#2,#3 on ONE ip is normal
            if len(same_ips) >= self.max_same_name:
                self._block(same_ips)
                return f"name '{name[:30]}' seen on {len(same_ips)} different IPs"
            if len(ports) > self.max_per_ip:
                self._block([ip])
                return f"{len(ports)} ports advertised on {ip}"
        return None


class NameShare:
    """Fake servers copy player names between each other. A real player can
    not be on several servers at once, so flag servers whose player names are
    mostly also listed on other servers."""

    IGNORE = {"", "player", "unnamed", "unconnected"}

    def __init__(self, min_servers, fraction):
        self.min_servers = min_servers  # name on this many OTHER servers counts as shared
        self.fraction = fraction
        self.where = {}  # name -> set(addr)
        self.lock = threading.Lock()

    def check(self, addr, names):
        names = [n for n in names if n.strip().lower() not in self.IGNORE]
        if len(names) < 4:
            return None
        with self.lock:
            shared = 0
            for n in set(names):
                s = self.where.setdefault(n, set())
                s.add(addr)
                if len(s - {addr}) >= self.min_servers:
                    shared += 1
            frac = shared / len(set(names))
        if frac >= self.fraction:
            return f"{shared}/{len(set(names))} player names also on other servers"
        return None


# ------------------------------------------------- name cleanup + country
import bisect
import gzip
import os
import unicodedata

_DROP_CATS = {"So", "Cf", "Cs", "Co", "Cn", "Cc"}


def strip_name(name):
    """Remove emoji, dingbats, block/box characters and invisible characters."""
    out = []
    for c in name:
        o = ord(c)
        if unicodedata.category(c) in _DROP_CATS or 0xFE00 <= o <= 0xFE0F or 0x1F3FB <= o <= 0x1F3FF:
            continue
        out.append(c)
    return " ".join("".join(out).split())


import re

REGION_TAGS = {"EU", "CIS", "NA", "SA", "ASIA", "EUROPE", "WORLD", "INT", "GLOBAL"}
_CS2_RE = re.compile(r"(?<![\w.@-])(?:cs\s?2|cs:?\s?go|counter[\s-]?strike(?:\s?2)?)(?![\w.])", re.I)
_BRACKET_RE = re.compile(r"[\[\(\{<]\s*([^\[\]\(\)\{\}<>]{0,40}?)\s*[\]\)\}>]")
_DOMAINISH = re.compile(r"\w\.[a-z]{2,}", re.I)

# (label, regex) - first match wins; the matched word is removed from the name.
MODES = [
    ("Retake", r"retakes?"),
    ("Surf", r"surf\w*"),
    ("Bhop", r"bhop|bunny\s*hop\w*"),
    ("KZ", r"kz|climb\w*"),
    ("Zombie", r"zombie\w*|zm|zp"),
    ("Jailbreak", r"jail\s*break|jb|jail"),
    ("Hide&Seek", r"hide\s*(?:and|&|n)\s*seek|hns"),
    ("Prop Hunt", r"prop\s*hunt"),
    ("Deathrun", r"death\s*run"),
    ("Minigames", r"mini\s*games?|mg"),
    ("Gun Game", r"gun\s*game|arms\s*race"),
    ("Wingman", r"wingman"),
    ("Arena", r"arena|1v1|2v2"),
    ("AWP", r"awp\w*"),
    ("Aim", r"aim\w*|rifle|pistol"),
    ("DM", r"death\s*match|ffa|free\s*for\s*all|dm|hs\s*only|headshot"),
    ("Casual", r"casual"),
    ("Danger Zone", r"danger\s*zone"),
    ("Comp", r"competitive|comp|5v5|mix|scrim|pug|faceit|matchmaking"),
    ("Classic", r"classic|public|pub"),
]
_MODE_RES = [(lab, re.compile(r"(?<![\w.])(?:" + pat + r")(?![\w.])", re.I)) for lab, pat in MODES]
_MAP_MODES = [("surf_", "Surf"), ("bhop_", "Bhop"), ("kz_", "KZ"), ("xc_", "KZ"), ("aim_", "Aim"),
              ("awp_", "AWP"), ("fy_", "Aim"), ("ar_", "Gun Game"), ("dr_", "Deathrun"),
              ("mg_", "Minigames"), ("jb_", "Jailbreak"), ("ze_", "Zombie"), ("zm_", "Zombie"),
              ("de_", "Classic"), ("cs_", "Classic")]


_SKIN_RE = re.compile(r"(?<![\w.])!(?:ws|wp|skins?|knife|gloves|agents?)(?![\w.])", re.I)


def simplify_name(name, map_name="", country_codes=None, strip_emoji=True, skin_badge=""):
    """Return (mode, rest): a uniform game-mode label and the cleaned server name.

    - country tags like [RU] / (LV) / 'RU |' are removed when `country_codes` is given
      (the real country is shown as a prefix instead)
    - 'CS2', 'CS:GO', 'Counter-Strike 2' are removed (but never inside a domain such as
      bivecs2.ru)
    - the game mode is detected from the name, else from the map prefix
    - '!ws' / '!skins' / '!knife' style weapon-skin commands become `skin_badge`
      (an icon) appended to the name"""
    s = strip_name(name) if strip_emoji else name
    has_skins = bool(_SKIN_RE.search(s))
    if has_skins:
        s = _SKIN_RE.sub(" ", s)

    def drop_tag(m):
        inner = m.group(1).strip()
        up = inner.upper()
        if country_codes is not None and (up in country_codes or up in REGION_TAGS):
            return " "
        if _CS2_RE.fullmatch(inner):
            return " "
        return m.group(0)

    s = _BRACKET_RE.sub(drop_tag, s)
    if country_codes is not None:  # "RU | name" or "name | RU"
        m = re.match(r"\s*([A-Za-z]{2})\s*[|\-:/·•]\s*", s)
        if m and m.group(1).upper() in country_codes:
            s = s[m.end():]
        m = re.search(r"\s*[|\-:/·•]\s*([A-Za-z]{2})\s*$", s)
        if m and m.group(1).upper() in country_codes:
            s = s[:m.start()]
    s = " ".join(t if _DOMAINISH.search(t) else _CS2_RE.sub(" ", t) for t in s.split())
    mode = ""
    for lab, rx in _MODE_RES:
        m = rx.search(s)
        if m:
            mode = lab
            s = s[:m.start()] + " " + s[m.end():]
            break
    if not mode:
        mp = (map_name or "").lower()
        mode = next((lab for pre, lab in _MAP_MODES if mp.startswith(pre)), "Custom")
    s = re.sub(r"[\[\(\{<]\s*[\]\)\}>]", " ", s)  # brackets emptied by the removals above
    s = re.sub(r"\b24\s*[/-]\s*7\b", " ", s)
    s = re.sub(r"[|·•»«—–~]+|\s[-:/]\s", " ", s)
    s = " ".join(s.split()).strip(" -:/|.,")
    if not s:
        s = (strip_name(name) if strip_emoji else name).strip()
    if has_skins and skin_badge:
        s = f"{s} {skin_badge}"
    return mode, s


def flag_text(cc, style):
    if len(cc) != 2 or not cc.isalpha() or cc.upper() == "ZZ":
        return ""
    cc = cc.upper()
    if style == "text":
        return f"[{cc}]"
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in cc)


def rewrite_info_name(payload, new_name):
    """Return the A2S_INFO payload with its server-name field replaced."""
    end = payload.index(b"\x00", 6)
    return payload[:6] + new_name.encode("utf-8")[:240] + payload[end:]


class GeoDB:
    """Local IPv4 -> country lookup from the DB-IP country-lite CSV(.gz)."""

    def __init__(self, path):
        self.starts, self.ends, self.ccs = [], [], []
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as f:
            for line in f:
                lo, hi, cc = line.strip().split(",")[:3]
                if ":" in lo:
                    continue
                self.starts.append(struct.unpack("!I", socket.inet_aton(lo))[0])
                self.ends.append(struct.unpack("!I", socket.inet_aton(hi))[0])
                self.ccs.append(cc)

    def country(self, ip):
        try:
            n = struct.unpack("!I", socket.inet_aton(ip))[0]
        except OSError:
            return ""
        i = bisect.bisect_right(self.starts, n) - 1
        return self.ccs[i] if i >= 0 and n <= self.ends[i] else ""


# ----------------------------------------------------------------- prober
class Prober:
    """Queries A2S_PLAYER through one shared UDP socket."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.port = self.sock.getsockname()[1]
        self.pending = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._rx, daemon=True).start()

    def _rx(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                continue
            with self.lock:
                q = self.pending.get(addr)
            if q is not None:
                q.put(data)

    def _wait(self, q, timeout):
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return None

    def players(self, addr, timeout):
        """Return ('ok', list) | ('unverified', None) | ('none', None)."""
        q = queue.Queue()
        with self.lock:
            self.pending[addr] = q
        try:
            self.sock.sendto(HEADER + b"U" + HEADER, addr)
            data = self._wait(q, timeout)
            if data is None:
                return "none", None
            if data[:4] == HEADER and data[4:5] == b"A" and len(data) >= 9:
                self.sock.sendto(HEADER + b"U" + data[5:9], addr)
                data = self._wait(q, timeout)
                if data is None:
                    return "none", None
            if data[:4] == b"\xff\xff\xff\xfe":
                return "unverified", None  # split packet: responsive, can't parse
            plist = parse_a2s_players(data)
            return ("ok", plist) if plist is not None else ("unverified", None)
        finally:
            with self.lock:
                self.pending.pop(addr, None)


# --------------------------------------------------------------- selftest
def selftest():
    def info_pkt(name, players, mx, bots=0):
        return (HEADER + b"I" + b"\x11" + name.encode() + b"\0de_dust2\0csgo\0Counter-Strike 2\0"
                + struct.pack("<HBBB", 730, players, mx, bots) + b"d\0\0")

    def players_pkt(entries):
        out = HEADER + b"D" + bytes([len(entries)])
        for i, (n, s, d) in enumerate(entries):
            out += bytes([i]) + n.encode() + b"\0" + struct.pack("<if", s, d)
        return out

    for pkt, want in [(info_pkt("real", 10, 64), None), (info_pkt("full", 64, 64), None),
                      (info_pkt("fake", 255, 255), "max players 255 > 64"),
                      (info_pkt("liar", 70, 64), "players 70 > max 64"),
                      (info_pkt("zero", 0, 0), "max players is 0")]:
        assert sanity_reason(parse_a2s_info(pkt), 64) == want, want
    assert parse_a2s_info(HEADER + b"A\x01\x02\x03\x04") is None

    info = parse_a2s_info(info_pkt("x", 5, 64))
    good = parse_a2s_players(players_pkt([(f"p{i}", i, 100.0 + i) for i in range(5)]))
    assert len(good) == 5 and players_reason(info, good) is None
    assert "lists 0" in players_reason(info, parse_a2s_players(players_pkt([])))
    same = parse_a2s_players(players_pkt([("bot", 0, 5.0)] * 5))
    assert "identical" in players_reason(info, same)
    assert parse_a2s_players(HEADER + b"D\x02\x00abc") is None  # truncated

    # padding like 176.32.32.18:27285: ~10 real players + ~50 entries with near-equal connect times
    import random
    rnd = random.Random(1)
    real = [(f"real{i}", rnd.randint(5, 60), rnd.uniform(300, 2800)) for i in range(10)]
    pad = [(f"Pad{i}", rnd.randint(10, 40), rnd.uniform(10480, 11080)) for i in range(53)]
    finfo = parse_a2s_info(info_pkt("fake", 63, 64))
    assert "nearly the same time" in players_reason(finfo, parse_a2s_players(players_pkt(real + pad)))
    # 31.77.169.95:27102: 14 real players (336..7389s) + 16 padded entries (19521..20085s)
    real2 = [336, 429, 493, 584, 620, 756, 781, 1114, 1295, 1302, 1863, 2352, 3038, 7389]
    pad2 = [20008, 19782, 19919, 19740, 19860, 19815, 19549, 19707, 19687, 20085, 19956, 19538, 19982, 19530, 19572, 19521]
    l2 = [(f"r{i}", i, float(d)) for i, d in enumerate(real2)] + [(f"p{i}", i, float(d)) for i, d in enumerate(pad2)]
    assert "nearly the same time" in players_reason(parse_a2s_info(info_pkt("f2", 31, 32)), parse_a2s_players(players_pkt(l2)))
    # the real half alone is fine
    assert players_reason(parse_a2s_info(info_pkt("ok", 14, 32)), parse_a2s_players(players_pkt(l2[:14]))) is None
    # 10 bots on a server that reports 10 bots, plus 14 humans: fine
    l3 = l2[:14] + [(f"Bot{i}", 0, 19800.0) for i in range(10)]
    assert players_reason(parse_a2s_info(info_pkt("b", 14, 32, bots=10)), parse_a2s_players(players_pkt(l3))) is None
    # honest server: 5 humans + 8 bots sharing one connect time must NOT be flagged
    humans = [(f"h{i}", 10 + i, 100.0 + 400 * i) for i in range(5)]
    bots8 = [(f"Bot{i}", 0, 900.0) for i in range(8)]
    binfo = parse_a2s_info(info_pkt("botsrv", 5, 32, bots=8))
    assert players_reason(binfo, parse_a2s_players(players_pkt(humans + bots8))) is None
    # even if INFO's bots count is wrong/zero, 8 bots + 5 humans stays under the 12 threshold
    binfo0 = parse_a2s_info(info_pkt("botsrv", 13, 32, bots=0))
    bots8y = [(f"Bot{i}", 0, 800.0) for i in range(8)]  # young bots; reported bots=0 is a known limit
    assert players_reason(binfo0, parse_a2s_players(players_pkt(humans + bots8y))) is None
    # 20 bots on a bot server (bots=20) with 4 humans: allowed
    b20 = [(f"Bot{i}", 0, 900.0) for i in range(20)]
    binfo20 = parse_a2s_info(info_pkt("botsrv", 4, 32, bots=20))
    assert players_reason(binfo20, parse_a2s_players(players_pkt(humans[:4] + b20))) is None
    # name simplifier
    cc = {"LV", "RU", "DE", "US"}
    assert simplify_name("TACTICA.GG · DEATHMATCH #1", "de_dust2", cc) == ("DM", "TACTICA.GG #1")
    assert simplify_name("[LV] FB-CS.RU | DUST2 #1", "de_dust2", cc) == ("Classic", "FB-CS.RU DUST2 #1")
    assert simplify_name("bivecs2.ru | Surf", "surf_kitsune", cc) == ("Surf", "bivecs2.ru")
    assert simplify_name("CS2 Retake #3 [RU]", "de_mirage", cc) == ("Retake", "#3")
    assert simplify_name("cs2-ru.com Public", "de_dust2", cc) == ("Classic", "cs2-ru.com")
    assert simplify_name("➥███ FB-CS.RU | DUST2 #1", "de_dust2", cc) == ("Classic", "FB-CS.RU DUST2 #1")
    assert simplify_name("LV | Bhop Heaven [CS2]", "bhop_x", cc) == ("Bhop", "Heaven")
    assert simplify_name("[LV] Surf", "surf_x", None) == ("Surf", "[LV]")  # unknown country: keep tag
    assert simplify_name("My Server", "weird_map", cc) == ("Custom", "My Server")
    assert simplify_name("FB DM !ws !knife", "de_dust2", cc, skin_badge="\U0001F3A8") == ("DM", "FB \U0001F3A8")
    assert simplify_name("FB DM !ws", "de_dust2", cc) == ("DM", "FB")
    assert simplify_name("[DM] Arena of Fun", "de_dust2", cc)[0] == "Arena"
    # random-case names
    for nm, want in [("NiNjahaWk", True), ("ShADOWNHaWk", True), ("wOlF", True), ("ShadowHawk", False),
                     ("BlueBerryPie", False), ("MÜnze95", False), ("Seli", False), ("iPhone", False)]:
        assert is_random_case(nm) == want, nm
    rc = [(n, 5, 100.0 + 40 * i) for i, n in enumerate(
        ["NiNjahaWk", "ShADOWNHaWk", "FrOsTeagle", "siLEnTpaNDA", "EPiCreApER", "wiLDBAndIT", "Bob", "Alice", "Carl", "Dave"])]
    assert padding_size(parse_a2s_info(info_pkt("c", 10, 32)), parse_a2s_players(players_pkt(rc))) == 6
    # padded servers: default is to show the real count, padding only dropped on request
    assert players_reason(parse_a2s_info(info_pkt("f2", 31, 32)), parse_a2s_players(players_pkt(l2)), drop_padding=False) is None
    assert padding_size(parse_a2s_info(info_pkt("f2", 31, 32)), parse_a2s_players(players_pkt(l2))) == 16
    assert padding_size(parse_a2s_info(info_pkt("ok", 14, 32)), parse_a2s_players(players_pkt(l2[:14]))) == 0
    rp = rewrite_info_players(info_pkt("f2", 31, 32), 14)
    ri = parse_a2s_info(rp)
    assert ri["players"] == 14 and ri["max_players"] == 32 and ri["name"] == "f2" and ri["map"] == "de_dust2"
    # 31.77.169.95:27190: every entry fake (2735..3326s block + 11/22/33 and 176..220 steps of 11)
    blk = [2809, 3078, 2843, 3272, 2810, 3314, 2737, 3242, 2959, 2743, 3206, 2767, 2746, 3127, 3315, 2871,
           2789, 3154, 3053, 3292, 3326, 2946, 3034, 2748, 2896, 3023, 3155, 2800, 3091, 2873, 2866, 2912,
           2986, 2838, 3000, 3035, 3080, 3212, 2752, 3009, 3194, 3000, 2823, 2735, 3043, 3046, 3016, 2965,
           3197, 2941, 3277, 3126, 3142, 2936, 3191]
    steps = [176, 187, 198, 209, 220, 11, 22, 33]
    l4 = [(f"f{i}", 1, float(x)) for i, x in enumerate(blk + steps)]
    assert padding_size(parse_a2s_info(info_pkt("z", 63, 64)), parse_a2s_players(players_pkt(l4))) == len(l4)
    # real list never has equal-step runs flagged without a cluster
    assert padding_size(parse_a2s_info(info_pkt("ok", 14, 32)), parse_a2s_players(players_pkt(
        [(f"s{i}", 1, float(x)) for i, x in enumerate([10, 20, 30, 40, 50, 60, 70, 500])]))) == 0
    d = DupTracker(max_same_name=3, max_per_ip=10)
    assert d.check(("1.1.1.1", 1), "Free Skins") is None
    assert d.check(("1.1.1.2", 1), "free  skins") is None
    assert "seen on 3" in d.check(("1.1.1.3", 1), "FREE SKINS")
    d3 = DupTracker(3, 10)
    d3.file = "x.txt"  # enable in-memory blocking without touching disk
    d3._block = lambda ips: d3.bad_ips.update(ips)
    assert d3.check(("9.9.9.9", 27015), "TACTICA.GG DM #1") is None
    assert d3.check(("9.9.9.9", 27016), "TACTICA.GG DM #2") is None
    assert d3.check(("9.9.9.9", 27017), "TACTICA.GG DM #3") is None  # same IP: legit host
    assert d3.check(("1.1.1.1", 27015), "➥ FB-CS.RU | DUST2 #1") is None
    assert d3.check(("2.2.2.2", 27015), "➥ FB-CS.RU | DUST2 #2") is None
    assert "3 different IPs" in d3.check(("3.3.3.3", 27015), "➥ FB-CS.RU | DUST2 #7")
    assert "flagged as a spam farm" in d3.check(("1.1.1.1", 27099), "anything")
    d2 = DupTracker(3, 2)
    d2.check(("2.2.2.2", 1), "a"); d2.check(("2.2.2.2", 2), "b")
    assert "3 ports" in d2.check(("2.2.2.2", 3), "c")
    # type 'd', env 'l', visibility 0, vac 1, version string, EDF (port + steamid)
    base = (HEADER + b"I\x11e\0de_dust2\0csgo\0Counter-Strike 2\0" + struct.pack("<HBBB", 730, 5, 64, 0)
            + b"dl\x00\x01" + b"1.41\0" + b"\xb0" + struct.pack("<HQ", 27015, 85568392930616524))
    ei = parse_a2s_info(base)
    assert ei["gameport"] == 27015 and ei["steamid"] == 85568392930616524, ei
    assert identity_reason(("1.2.3.4", 27015), ei) is None
    assert "claims port 27015" in identity_reason(("1.2.3.4", 40062), ei)
    st = SteamIdTracker()
    assert st.check(("1.2.3.4", 27015), ei["steamid"]) is None
    assert "answers from 2" in st.check(("5.6.7.8", 27015), ei["steamid"])
    dupnames = parse_a2s_players(players_pkt([("a", 1, 1.0), ("a", 2, 2.0), ("a", 3, 3.0), ("b", 4, 4.0), ("c", 5, 5.0)]))
    assert "unique names" in players_reason(parse_a2s_info(info_pkt("x", 5, 64)), dupnames)
    ns = NameShare(2, 0.5)
    pool = ["w", "x", "y", "z", "q"]
    assert ns.check(("1.1.1.1", 1), pool) is None
    assert ns.check(("1.1.1.2", 1), pool) is None
    assert "also on other servers" in ns.check(("1.1.1.3", 1), pool)  # 2 other servers share them
    assert ns.check(("9.9.9.9", 1), ["u1", "u2", "u3", "u4"]) is None
    assert strip_name("➥███ FB-CS.RU | DUST2 #1 ✪🔥") == "FB-CS.RU | DUST2 #1", strip_name("➥███ FB-CS.RU | DUST2 #1 ✪🔥")
    assert strip_name("Rīga Server «LV»") == "Rīga Server «LV»"
    assert strip_name("日本 サーバー") == "日本 サーバー"
    assert flag_text("lv", "text") == "[LV]" and flag_text("LV", "emoji") == "\U0001F1F1\U0001F1FB"
    assert flag_text("ZZ", "text") == "" and flag_text("", "emoji") == ""
    pk = info_pkt("old name", 5, 64)
    rp = rewrite_info_name(pk, "[LV] new longer name")
    ri = parse_a2s_info(rp)
    assert ri["name"] == "[LV] new longer name" and ri["players"] == 5 and ri["max_players"] == 64 and ri["map"] == "de_dust2"
    gp = asset_path("geo", "dbip.csv.gz")
    if os.path.exists(gp):
        g = GeoDB(gp)
        assert g.country("8.8.8.8") == "US" and g.country("0.0.0.1") == "ZZ"
        print("geo sample: 45.140.169.187 ->", g.country("45.140.169.187"))
    print("selftest OK")


# ------------------------------------------------------------------- main
RULE_KEYS = ["port", "sanity", "mismatch", "names", "padding", "identity", "steamid", "dups"]


def csv_set(text):
    return {x.strip().upper() if x.strip().isalpha() and len(x.strip()) == 2 else x.strip()
            for x in (text or "").replace(";", ",").split(",") if x.strip()}


def run(a, out=None, handle_box=None):
    """Run the filter until Ctrl+C (CLI) or until handle_box['w'].close() (GUI)."""
    import pydivert  # imported late so --selftest works without it
    out = out or (lambda s: print(s, flush=True))
    off = set(a.disable) if not isinstance(a.disable, str) else csv_set(a.disable.lower())
    block_cc = {c.upper() for c in (csv_set(a.block_countries) if isinstance(a.block_countries, str) else a.block_countries)}
    allow_cc = {c.upper() for c in (csv_set(a.allow_countries) if isinstance(a.allow_countries, str) else a.allow_countries)}

    prober = Prober()
    dups = DupTracker(a.max_same_name, a.max_per_ip,
                      None if a.no_blocklist else a.blocklist)
    geo = None
    if (a.rewrite and not a.no_flags) or block_cc or allow_cc:
        try:
            geo = GeoDB(a.geo_file)
            out(f"loaded {len(geo.starts)} country ranges")
        except OSError as e:
            out(f"no country database ({e}); no flags / country rules")
    port_range = None
    if "port" not in off and a.port_range.lower() != "any":
        lo, hi = a.port_range.split("-")
        port_range = (int(lo), int(hi))
    shares = NameShare(a.share_servers, a.share_fraction)
    steamids = SteamIdTracker()
    cache = {}  # addr -> (expires, reason_or_None, names) from sanity+probe (static part)
    stats = {"seen": 0, "dropped": 0}
    send_lock = threading.Lock()
    pool = ThreadPoolExecutor(max_workers=64)

    flt = ("inbound and udp and udp.PayloadLength > 20 and udp.PayloadLength < 1400 "
           "and udp.SrcPort != 53 and udp.SrcPort != 443 and udp.SrcPort != 123")

    def log(tag, addr, info, why):
        out(f"{time.strftime('%H:%M:%S')} {tag} {addr[0]}:{addr[1]} {info['players']}/"
            f"{info['max_players']} '{info['name'][:40]}' ({why})")

    def static_verdict(addr, info):
        """Return (reason_or_None, player_names, real_player_count_or_None)."""
        why = None if "sanity" in off else sanity_reason(info, a.max_valid)
        if why or a.no_probe:
            return why, [], None
        kind, plist = prober.players(addr, a.timeout)
        if a.dump_ip and addr[0] == a.dump_ip:
            out(f"--- DUMP {addr} INFO={info} probe={kind}")
            for p in plist or []:
                out(f"    {p}")
        if kind == "none":
            return ("no A2S_PLAYER response" if a.strict else None), [], None
        if kind == "ok":
            why = players_reason(info, plist, drop_padding=a.padded == "drop", skip=off)
            pad = 0 if (why or "padding" in off) else padding_size(info, plist)
            real = max(0, len(plist) - pad) if pad else None
            if pad and real == 0:  # nobody real in there: the whole server is a decoy
                why = f"all {len(plist)} listed players are fake padding"
            return why, [p[0] for p in plist], real
        return None, [], None

    def decide(w, pkt, addr, info):
        hit = cache.get(addr)
        real = None
        cc = geo.country(addr[0]) if geo else ""
        if cc and cc in block_cc:
            why, names = f"country {cc} is blocked", []
        elif allow_cc and cc not in allow_cc:
            why, names = f"country {cc or '??'} not in allowed list", []
        elif port_range and not (port_range[0] <= addr[1] <= port_range[1]):
            why, names = f"port {addr[1]} outside {a.port_range}", []
        elif hit and hit[0] > time.time():
            why, names, real = hit[1], hit[2], hit[3]
        else:
            why, names, real = static_verdict(addr, info)
            cache[addr] = (time.time() + a.cache_ttl, why, names, real)
        why = (why or (None if "identity" in off else identity_reason(addr, info))
               or (None if "steamid" in off else steamids.check(addr, info["steamid"]))
               or (None if "dups" in off else dups.check(addr, info["name"]))
               or (shares.check(addr, names) if a.shared_names else None))
        if why:
            stats["dropped"] += 1
            log("DROP      " if a.enforce else "would drop", addr, info, why)
            if a.enforce:
                return
        if real is not None and not why:
            log("ADJUST    " if a.enforce else "would adjust", addr, info, f"showing {real} real players instead")
            try:
                pkt.payload = rewrite_info_players(bytes(pkt.payload), real)
            except Exception as e:
                out(f"player-count rewrite failed: {e!r}")
        if a.rewrite:
            try:
                cc_here = geo.country(addr[0]) if geo else ""
                flag = flag_text(cc_here, a.flag_style) if geo else ""
                if getattr(a, "simplify", True):
                    # tags like [LV] are only removed when we know the real country
                    codes = set(geo.ccs) if flag else None
                    badge = "[WS]" if a.flag_style == "text" else "\U0001F3A8"
                    mode, rest = simplify_name(info["name"], info["map"], codes, not a.keep_emoji, badge)
                    new = f"{flag} {mode} | {rest}".strip()
                else:
                    name = info["name"] if a.keep_emoji else strip_name(info["name"])
                    new = f"{flag} {name}".strip() if flag else name
                if new != info["name"]:
                    pkt.payload = rewrite_info_name(bytes(pkt.payload), new)
            except Exception as e:  # never lose a reply because of cosmetics
                out(f"rewrite failed: {e!r}")
        try:
            with send_lock:
                w.send(pkt)
        except Exception:
            pass  # handle closed while a held reply was still being checked

    out(f"{'ENFORCING' if a.enforce else 'DRY-RUN'}; max slots {a.max_valid}, "
        f"probe={'off' if a.no_probe else 'on'}{' strict' if a.strict else ''}, "
        f"dup name>={a.max_same_name}, ports/ip>{a.max_per_ip}, off={sorted(off)}, "
        f"block={sorted(block_cc)}, allow={sorted(allow_cc)}.")
    with pydivert.WinDivert(flt) as w:
        if handle_box is not None:
            handle_box["w"] = w
        try:
            for pkt in w:
                if pkt.dst_port == prober.port:  # reply to our own probe: let it through
                    with send_lock:
                        w.send(pkt)
                    continue
                info = parse_a2s_info(pkt.payload or b"")
                if info is None:
                    with send_lock:
                        w.send(pkt)
                    continue
                stats["seen"] += 1
                addr = (pkt.src_addr, pkt.src_port)
                pool.submit(decide, w, pkt, addr, info)
        except KeyboardInterrupt:
            pass
        except Exception:
            if handle_box is None:
                raise  # CLI: real error. GUI: handle was closed by Stop.
    out(f"A2S_INFO replies seen: {stats['seen']}, flagged: {stats['dropped']}")
    pool.shutdown(wait=False)


def build_parser():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enforce", action="store_true", help="drop fake replies (default: log only)")
    ap.add_argument("--max-valid", type=int, default=64, help="largest believable max players (CS2: 64)")
    ap.add_argument("--no-probe", action="store_true", help="skip the A2S_PLAYER validation")
    ap.add_argument("--strict", action="store_true", help="also drop servers that never answer A2S_PLAYER")
    ap.add_argument("--timeout", type=float, default=1.0, help="seconds to wait per probe step")
    ap.add_argument("--cache-ttl", type=float, default=300, help="seconds to remember a probe result")
    ap.add_argument("--max-same-name", type=int, default=3, help="drop when this many addresses share a name")
    ap.add_argument("--max-per-ip", type=int, default=10, help="drop when an IP advertises more ports than this")
    ap.add_argument("--blocklist", default="blocked_ips.txt",
                    help="file remembering flagged spam-farm IPs between runs (delete it to reset)")
    ap.add_argument("--no-blocklist", action="store_true", help="don't load/save the blocklist")
    ap.add_argument("--padded", choices=["show", "drop"], default="show",
                    help="servers with fake padded players: 'show' with the real count (default) or 'drop'")
    ap.add_argument("--no-rewrite", dest="rewrite", action="store_false",
                    help="don't touch server names (no emoji strip, no flag)")
    ap.add_argument("--keep-emoji", action="store_true", help="don't strip emoji from names")
    ap.add_argument("--no-simplify", dest="simplify", action="store_false",
                    help="don't rewrite names into the uniform 'flag Mode | Name' style")
    ap.add_argument("--no-flags", action="store_true", help="don't add a country prefix")
    ap.add_argument("--flag-style", choices=["emoji", "text"], default="emoji",
                    help="'emoji' = flag emoji, 'text' = [LV] (Steam on Windows often shows emoji flags as letters)")
    ap.add_argument("--geo-file", default=asset_path("geo", "dbip.csv.gz"))
    ap.add_argument("--port-range", default="26000-28999",
                    help="only accept servers on ports in this range, e.g. 26000-28999; 'any' disables")
    ap.add_argument("--shared-names", action="store_true",
                    help="enable the copied-player-names check (off by default)")
    ap.add_argument("--share-servers", type=int, default=2,
                    help="a player name on this many OTHER servers counts as copied")
    ap.add_argument("--share-fraction", type=float, default=0.5,
                    help="drop when this fraction of a server's names are copied")
    ap.add_argument("--dump-ip", default="", help="print INFO and full player list for this server IP")
    ap.add_argument("--block-countries", default="", help="comma list of country codes to hide, e.g. RU,CN")
    ap.add_argument("--allow-countries", default="", help="if set, ONLY these country codes are shown")
    ap.add_argument("--disable", default="",
                    help="comma list of rules to switch off: " + ",".join(RULE_KEYS))
    ap.add_argument("--selftest", action="store_true")
    return ap


if __name__ == "__main__":
    a = build_parser().parse_args()
    selftest() if a.selftest else run(a)
