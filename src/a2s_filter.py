"""
a2s_filter.py - the engine: drops fake Source-engine server replies before Steam sees them.

Steam's server browser sends A2S_INFO queries over UDP and every server answers with
name / map / players / max players. Fake servers lie in that reply. This module uses
WinDivert (via pydivert) to catch the replies and check each one before Steam reads it:

  1. Sanity     - impossible numbers (max players > 64, 255 players, ...)
  2. Probe      - the reply is held while we ask the server for its real player list
                  (A2S_PLAYER) and compare it with the advertised count; padded lists
                  (identical join times, random-case names) are detected
  3. Identity   - the server must answer from the port it claims, one SteamID = one address
  4. Duplicates - one name on many IPs, or many ports on one IP, is a spam farm

Fake replies are dropped; names and player counts of the rest are rewritten.

    python src/a2s_filter.py              # run with defaults (needs an elevated terminal)
    python src/a2s_filter.py --selftest   # rule tests, no admin needed
"""
import bisect
import gzip
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field


def asset_path(*parts):
    """assets/ folder: next to src/ when run from source, inside the bundle when frozen."""
    base = getattr(sys, "_MEIPASS", None) or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    return os.path.normpath(os.path.join(base, "assets", *parts))


HEADER = b"\xff\xff\xff\xff"
CLUSTER_WINDOW = 700    # seconds: fake connect times are spread over ~600s
CLUSTER_MIN_AGE = 900   # seconds: only players connected at least this long count


# ---------------------------------------------------------------- parsing
def parse_a2s_info(payload):
    """Return dict(name, map, players, max_players, bots, gameport, steamid) or None."""
    if len(payload) < 6 or payload[:4] != HEADER or payload[4] != 0x49:
        return None
    try:
        pos = 6  # skip header(4) + 'I'(1) + protocol(1)
        fields = []
        for _ in range(4):  # name, map, folder, game
            end = payload.index(b"\x00", pos)
            fields.append(payload[pos:end].decode("utf-8", "replace"))
            pos = end + 1
        _appid, players, max_players, bots = struct.unpack_from("<HBBB", payload, pos)
        pos += 5
        info = {"name": fields[0], "map": fields[1], "players": players, "max_players": max_players,
                "bots": bots, "gameport": None, "steamid": None}
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
        pad = 0 if "padding" in skip else len(padding_indices(info, plist))
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
    """Flags spam farms: the same name on many IPs, or many ports on one IP."""

    def __init__(self, max_same_name, max_per_ip):
        self.max_same_name = max_same_name
        self.max_per_ip = max_per_ip
        self.names = {}   # name stem -> set(addr)
        self.ips = {}     # ip -> set(port)
        self.lock = threading.Lock()

    @staticmethod
    def stem(name):
        """'FB-CS.RU | DUST2 #1' and '... #7' share one stem: digits/#/punctuation ignored."""
        return "".join(c for c in name.lower() if c.isalpha())

    def check(self, addr, name):
        ip, port = addr
        key = self.stem(name) or name.lower()
        with self.lock:
            s = self.names.setdefault(key, set())
            s.add(addr)
            ports = self.ips.setdefault(ip, set())
            ports.add(port)
            same_ips = {a[0] for a in s}  # a host running #1,#2,#3 on ONE ip is normal
            if len(same_ips) >= self.max_same_name:
                return f"name '{name[:30]}' seen on {len(same_ips)} different IPs"
            if len(ports) > self.max_per_ip:
                return f"{len(ports)} ports advertised on {ip}"
        return None


# ------------------------------------------------- name cleanup + country
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
    def _pad_count(info, plist):
        return len(padding_indices(info, plist))

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
    assert _pad_count(parse_a2s_info(info_pkt("c", 10, 32)), parse_a2s_players(players_pkt(rc))) == 6
    # padded servers: default is to show the real count, padding only dropped on request
    assert players_reason(parse_a2s_info(info_pkt("f2", 31, 32)), parse_a2s_players(players_pkt(l2)), drop_padding=False) is None
    assert _pad_count(parse_a2s_info(info_pkt("f2", 31, 32)), parse_a2s_players(players_pkt(l2))) == 16
    assert _pad_count(parse_a2s_info(info_pkt("ok", 14, 32)), parse_a2s_players(players_pkt(l2[:14]))) == 0
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
    assert _pad_count(parse_a2s_info(info_pkt("z", 63, 64)), parse_a2s_players(players_pkt(l4))) == len(l4)
    # real list never has equal-step runs flagged without a cluster
    assert _pad_count(parse_a2s_info(info_pkt("ok", 14, 32)), parse_a2s_players(players_pkt(
        [(f"s{i}", 1, float(x)) for i, x in enumerate([10, 20, 30, 40, 50, 60, 70, 500])]))) == 0
    d = DupTracker(max_same_name=3, max_per_ip=10)
    assert d.check(("1.1.1.1", 1), "Free Skins") is None
    assert d.check(("1.1.1.2", 1), "free  skins") is None
    assert "seen on 3" in d.check(("1.1.1.3", 1), "FREE SKINS")
    d3 = DupTracker(3, 10)
    assert d3.check(("9.9.9.9", 27015), "TACTICA.GG DM #1") is None
    assert d3.check(("9.9.9.9", 27016), "TACTICA.GG DM #2") is None
    assert d3.check(("9.9.9.9", 27017), "TACTICA.GG DM #3") is None  # same IP: legit host
    assert d3.check(("1.1.1.1", 27015), "➥ FB-CS.RU | DUST2 #1") is None
    assert d3.check(("2.2.2.2", 27015), "➥ FB-CS.RU | DUST2 #2") is None
    assert "3 different IPs" in d3.check(("3.3.3.3", 27015), "➥ FB-CS.RU | DUST2 #7")
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
MAX_PLAYERS = 64     # largest believable max-player count
PROBE_TIMEOUT = 1.0  # seconds to wait per A2S_PLAYER step
CACHE_TTL = 300      # seconds a probe result is remembered
MAX_SAME_NAME = 3    # the same server name on this many different IPs = spam
MAX_PER_IP = 10      # more ports than this on one IP = spam farm
RULE_KEYS = ["port", "sanity", "mismatch", "names", "padding", "identity", "steamid", "dups"]


@dataclass
class Config:
    disabled: set = field(default_factory=set)         # RULE_KEYS to switch off
    port_range: tuple = (26000, 28999)                 # None = any port
    padded: str = "show"                               # servers with fake players: "show" real count | "drop"
    tidy_names: bool = True                            # uniform "flag Mode | Name" style
    country_prefix: bool = True                        # real country in front of the name
    flag_style: str = "emoji"                          # "emoji" or "text" ([LV])
    block_countries: set = field(default_factory=set)  # hide servers from these countries
    allow_countries: set = field(default_factory=set)  # if set, show ONLY these countries
    geo_file: str = field(default_factory=lambda: asset_path("geo", "dbip.csv.gz"))


def parse_port_range(text):
    """'26000-28999' -> (26000, 28999); 'any' -> None. Raises ValueError on anything else."""
    text = text.strip().lower()
    if text in ("", "any"):
        return None
    lo, hi = (int(x) for x in text.split("-"))
    return lo, hi


def run(cfg, out=None, handle_box=None):
    """Filter until Ctrl+C (CLI) or until handle_box['w'].close() (GUI)."""
    import pydivert  # imported late so --selftest works without it
    out = out or (lambda s: print(s, flush=True))
    off = cfg.disabled
    block_cc, allow_cc = cfg.block_countries, cfg.allow_countries
    prober = Prober()
    dups = DupTracker(MAX_SAME_NAME, MAX_PER_IP)
    geo = None
    if cfg.country_prefix or block_cc or allow_cc:
        try:
            geo = GeoDB(cfg.geo_file)
            out(f"loaded {len(geo.starts)} country ranges")
        except OSError as e:
            out(f"no country database ({e}); no flags / country rules")
    port_range = None if "port" in off else cfg.port_range
    steamids = SteamIdTracker()
    cache = {}  # addr -> (expires, reason_or_None, real_count_or_None)
    stats = {"seen": 0, "dropped": 0}
    send_lock = threading.Lock()
    pool = ThreadPoolExecutor(max_workers=64)

    flt = ("inbound and udp and udp.PayloadLength > 20 and udp.PayloadLength < 1400 "
           "and udp.SrcPort != 53 and udp.SrcPort != 443 and udp.SrcPort != 123")

    def log(tag, addr, info, why):
        out(f"{time.strftime('%H:%M:%S')} {tag} {addr[0]}:{addr[1]} {info['players']}/"
            f"{info['max_players']} '{info['name'][:40]}' ({why})")

    def static_verdict(addr, info):
        """Return (reason_or_None, real_player_count_or_None) from the sanity rules + the probe."""
        why = None if "sanity" in off else sanity_reason(info, MAX_PLAYERS)
        if why:
            return why, None
        kind, plist = prober.players(addr, PROBE_TIMEOUT)
        if kind != "ok":
            return None, None
        why = players_reason(info, plist, drop_padding=cfg.padded == "drop", skip=off)
        pad = 0 if (why or "padding" in off) else len(padding_indices(info, plist))
        real = max(0, len(plist) - pad) if pad else None
        if pad and real == 0:  # nobody real in there: the whole server is a decoy
            why = f"all {len(plist)} listed players are fake padding"
        return why, real

    def new_name(addr, info):
        cc = geo.country(addr[0]) if geo else ""
        flag = flag_text(cc, cfg.flag_style) if geo and cfg.country_prefix else ""
        if cfg.tidy_names:
            # tags like [LV] are only removed when we know the real country
            codes = set(geo.ccs) if flag else None
            badge = "[WS]" if cfg.flag_style == "text" else "\U0001F3A8"
            mode, rest = simplify_name(info["name"], info["map"], codes, True, badge)
            return f"{flag} {mode} | {rest}".strip()
        return f"{flag} {info['name']}".strip()

    def decide(w, pkt, addr, info):
        cc = geo.country(addr[0]) if geo else ""
        real = None
        hit = cache.get(addr)
        if cc and cc in block_cc:
            why = f"country {cc} is blocked"
        elif allow_cc and cc not in allow_cc:
            why = f"country {cc or '??'} not in allowed list"
        elif port_range and not (port_range[0] <= addr[1] <= port_range[1]):
            why = f"port {addr[1]} outside {port_range[0]}-{port_range[1]}"
        elif hit and hit[0] > time.time():
            _, why, real = hit
        else:
            why, real = static_verdict(addr, info)
            cache[addr] = (time.time() + CACHE_TTL, why, real)
        why = (why or (None if "identity" in off else identity_reason(addr, info))
               or (None if "steamid" in off else steamids.check(addr, info["steamid"]))
               or (None if "dups" in off else dups.check(addr, info["name"])))
        if why:
            stats["dropped"] += 1
            log("DROP      ", addr, info, why)
            return
        if real is not None:
            log("ADJUST    ", addr, info, f"showing {real} real players instead")
            try:
                pkt.payload = rewrite_info_players(bytes(pkt.payload), real)
            except Exception as e:
                out(f"player-count rewrite failed: {e!r}")
        if cfg.tidy_names or cfg.country_prefix:
            try:
                name = new_name(addr, info)
                if name != info["name"]:
                    pkt.payload = rewrite_info_name(bytes(pkt.payload), name)
            except Exception as e:  # never lose a reply because of cosmetics
                out(f"rewrite failed: {e!r}")
        try:
            with send_lock:
                w.send(pkt)
        except Exception:
            pass  # handle closed while a held reply was still being checked

    out(f"Filtering on. off={sorted(off)}, block={sorted(block_cc)}, allow={sorted(allow_cc)}.")
    with pydivert.WinDivert(flt) as w:
        if handle_box is not None:
            handle_box["w"] = w
        try:
            for pkt in w:
                info = None if pkt.dst_port == prober.port else parse_a2s_info(pkt.payload or b"")
                if info is None:  # not an A2S_INFO reply (or the reply to our own probe): let it through
                    with send_lock:
                        w.send(pkt)
                    continue
                stats["seen"] += 1
                pool.submit(decide, w, pkt, (pkt.src_addr, pkt.src_port), info)
        except KeyboardInterrupt:
            pass
        except Exception:
            if handle_box is None:
                raise  # CLI: real error. GUI: the handle was closed by Pause/Quit.
    out(f"A2S_INFO replies seen: {stats['seen']}, hidden: {stats['dropped']}")
    pool.shutdown(wait=False)


if __name__ == "__main__":
    selftest() if "--selftest" in sys.argv else run(Config())
