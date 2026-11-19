"""
CS2 Server Filter - Windows app that hides fake Source / CS2 servers from Steam's server browser.

Run:   python src/a2s_gui.py [--minimized]        (or the released CS2ServerFilter.exe)
Needs Administrator rights (packet filtering); the app offers to restart itself elevated.
Filtering is always on and restarts itself whenever a setting changes. Closing the window
keeps it running in the system tray.
"""
import ctypes
import json
import os
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageTk

import a2s_filter
import country_geo

__version__ = "1.0.0"

APP_DIR = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) \
    else os.path.dirname(os.path.abspath(__file__))
ASSETS = a2s_filter.asset_path()
DATA_DIR = os.path.join(os.environ.get("APPDATA") or APP_DIR, "CS2ServerFilter")
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except OSError:
    DATA_DIR = APP_DIR
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
TASK_NAME = "CS2ServerFilter"
REPO_URL = "https://github.com/boomix/CS2-server-browser-fix"

COUNTRIES = dict(x.split(":") for x in (
    "AD:Andorra|AE:United Arab Emirates|AF:Afghanistan|AG:Antigua and Barbuda|AL:Albania|AM:Armenia|"
    "AO:Angola|AR:Argentina|AT:Austria|AU:Australia|AZ:Azerbaijan|BA:Bosnia and Herzegovina|BB:Barbados|"
    "BD:Bangladesh|BE:Belgium|BF:Burkina Faso|BG:Bulgaria|BH:Bahrain|BI:Burundi|BJ:Benin|BN:Brunei|"
    "BO:Bolivia|BR:Brazil|BS:Bahamas|BT:Bhutan|BW:Botswana|BY:Belarus|BZ:Belize|CA:Canada|CD:DR Congo|"
    "CF:Central African Republic|CG:Congo|CH:Switzerland|CI:Ivory Coast|CL:Chile|CM:Cameroon|CN:China|"
    "CO:Colombia|CR:Costa Rica|CU:Cuba|CV:Cape Verde|CY:Cyprus|CZ:Czechia|DE:Germany|DJ:Djibouti|"
    "DK:Denmark|DM:Dominica|DO:Dominican Republic|DZ:Algeria|EC:Ecuador|EE:Estonia|EG:Egypt|ER:Eritrea|"
    "ES:Spain|ET:Ethiopia|FI:Finland|FJ:Fiji|FR:France|GA:Gabon|GB:United Kingdom|GD:Grenada|GE:Georgia|"
    "GH:Ghana|GM:Gambia|GN:Guinea|GQ:Equatorial Guinea|GR:Greece|GT:Guatemala|GW:Guinea-Bissau|GY:Guyana|"
    "HK:Hong Kong|HN:Honduras|HR:Croatia|HT:Haiti|HU:Hungary|ID:Indonesia|IE:Ireland|IL:Israel|IN:India|"
    "IQ:Iraq|IR:Iran|IS:Iceland|IT:Italy|JM:Jamaica|JO:Jordan|JP:Japan|KE:Kenya|KG:Kyrgyzstan|KH:Cambodia|"
    "KM:Comoros|KN:Saint Kitts and Nevis|KP:North Korea|KR:South Korea|KW:Kuwait|KZ:Kazakhstan|LA:Laos|"
    "LB:Lebanon|LC:Saint Lucia|LI:Liechtenstein|LK:Sri Lanka|LR:Liberia|LS:Lesotho|LT:Lithuania|"
    "LU:Luxembourg|LV:Latvia|LY:Libya|MA:Morocco|MC:Monaco|MD:Moldova|ME:Montenegro|MG:Madagascar|"
    "MK:North Macedonia|ML:Mali|MM:Myanmar|MN:Mongolia|MO:Macao|MR:Mauritania|MT:Malta|MU:Mauritius|"
    "MV:Maldives|MW:Malawi|MX:Mexico|MY:Malaysia|MZ:Mozambique|NA:Namibia|NE:Niger|NG:Nigeria|"
    "NI:Nicaragua|NL:Netherlands|NO:Norway|NP:Nepal|NZ:New Zealand|OM:Oman|PA:Panama|PE:Peru|"
    "PG:Papua New Guinea|PH:Philippines|PK:Pakistan|PL:Poland|PR:Puerto Rico|PS:Palestine|PT:Portugal|"
    "PY:Paraguay|QA:Qatar|RO:Romania|RS:Serbia|RU:Russia|RW:Rwanda|SA:Saudi Arabia|SB:Solomon Islands|"
    "SC:Seychelles|SD:Sudan|SE:Sweden|SG:Singapore|SI:Slovenia|SK:Slovakia|SL:Sierra Leone|SM:San Marino|"
    "SN:Senegal|SO:Somalia|SR:Suriname|SS:South Sudan|SV:El Salvador|SY:Syria|SZ:Eswatini|TD:Chad|"
    "TG:Togo|TH:Thailand|TJ:Tajikistan|TL:Timor-Leste|TM:Turkmenistan|TN:Tunisia|TR:Turkey|"
    "TT:Trinidad and Tobago|TW:Taiwan|TZ:Tanzania|UA:Ukraine|UG:Uganda|US:United States|UY:Uruguay|"
    "UZ:Uzbekistan|VA:Vatican City|VE:Venezuela|VN:Vietnam|VU:Vanuatu|WS:Samoa|XK:Kosovo|YE:Yemen|"
    "ZA:South Africa|ZM:Zambia|ZW:Zimbabwe|AW:Aruba|BM:Bermuda|GG:Guernsey|GI:Gibraltar|GL:Greenland|"
    "GU:Guam|IM:Isle of Man|JE:Jersey|KY:Cayman Islands|NC:New Caledonia|PF:French Polynesia|"
    "RE:Reunion|VG:British Virgin Islands|VI:US Virgin Islands|FO:Faroe Islands|AX:Aland Islands").split("|"))


RULES = [  # key, label, description
    ("port", "Port range", "Hide servers outside the port range set on the right."),
    ("sanity", "Impossible player numbers", "Max players 0 or too large, more players than slots, a count of 255."),
    ("mismatch", "Player list must match the count", "Ask each server for its player list; hide it if the list disagrees with the shown count."),
    ("names", "Fake-looking player names", "Hide lists where all names, or all scores and times, are identical or mostly repeated."),
    ("padding", "Detect padded fake players", "Spot generated players (identical join times, random-case names like NiNjaHaWk)."),
    ("identity", "Server port must match its reply", "Hide replies where the server claims a different port than it answered from."),
    ("steamid", "One SteamID = one address", "Hide copies: the same server SteamID answering from several addresses."),
    ("dups", "Duplicate / spam-farm servers", "Same name on several IPs, or too many ports on one IP."),
]


ACCENT = "#3b82f6"
GREEN, AMBER, RED, GRAY = "#22c55e", "#f59e0b", "#ef4444", "#8b93a1"
PRIMARY = ("#3b82f6", "#1f6aa5")
PRIMARY_HOVER = ("#2563eb", "#144870")


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, ""
    else:
        exe = sys.executable
        pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(pyw):
            exe = pyw
        params = f'"{os.path.abspath(__file__)}"'
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, APP_DIR, 1) > 32


def running_processes():
    """Lower-case names of all running processes (Toolhelp snapshot, no subprocess)."""
    from ctypes import wintypes

    class PE(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]

    k = ctypes.windll.kernel32
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = k.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    names = set()
    try:
        pe = PE()
        pe.dwSize = ctypes.sizeof(PE)
        ok = k.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            names.add(pe.szExeFile.lower())
            ok = k.Process32NextW(snap, ctypes.byref(pe))
    finally:
        k.CloseHandle(snap)
    return names


RUN_MODES = {"Always": None, "While Steam is open": {"steam.exe"}, "While CS2 is running": {"cs2.exe"}}


def autostart_command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --minimized'
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return f'"{pyw if os.path.exists(pyw) else sys.executable}" "{os.path.abspath(__file__)}" --minimized'


def set_autostart(on):
    """Scheduled task at logon with highest privileges (starts elevated, no UAC prompt)."""
    if on:
        cmd = ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", autostart_command(), "/SC", "ONLOGON",
               "/RL", "HIGHEST", "/F"]
    else:
        cmd = ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]
    try:
        return subprocess.run(cmd, capture_output=True, creationflags=0x08000000).returncode == 0
    except OSError:
        return False


def tray_image():
    try:
        return Image.open(os.path.join(ASSETS, "icon.png")).convert("RGBA")
    except Exception:
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        ImageDraw.Draw(img).ellipse((4, 4, 60, 60), fill="#3b82f6")
        return img


_GITHUB_PATH = (
    "M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49"
    "-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52"
    ".28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18"
    " 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07"
    "-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38C13.71 14.53 16 11.54 16 8"
    "c0-4.42-3.58-8-8-8z")


def _github_points():
    """Flatten the GitHub mark outline (16x16 box) into polygon points."""
    toks = re.findall(r"[MCcz]|-?\d*\.?\d+", _GITHUB_PATH)
    pts, i, cmd, cur = [], 0, "M", (0.0, 0.0)
    while i < len(toks):
        if toks[i] in "MCcz":
            cmd = toks[i]
            i += 1
            if cmd == "z":
                break
        if cmd == "M":
            cur = (float(toks[i]), float(toks[i + 1]))
            pts.append(cur)
            i += 2
            cmd = "L"
            continue
        v = [float(t) for t in toks[i:i + 6]]
        i += 6
        if cmd == "c":
            v = [v[0] + cur[0], v[1] + cur[1], v[2] + cur[0], v[3] + cur[1], v[4] + cur[0], v[5] + cur[1]]
        p0, p1, p2, p3 = cur, (v[0], v[1]), (v[2], v[3]), (v[4], v[5])
        for k in range(1, 9):
            t = k / 8
            u = 1 - t
            pts.append((u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
                        u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]))
        cur = p3
    return pts


def glyph(kind, size=20):
    """Small white line icons drawn with PIL (pause, play, list, github mark)."""
    S = size * 8
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    c = (240, 244, 248, 255)
    if kind == "pause":
        d.rounded_rectangle((S * .22, S * .15, S * .42, S * .85), radius=S * .05, fill=c)
        d.rounded_rectangle((S * .58, S * .15, S * .78, S * .85), radius=S * .05, fill=c)
    elif kind == "play":
        d.polygon([(S * .25, S * .12), (S * .85, S * .5), (S * .25, S * .88)], fill=c)
    elif kind == "list":  # server browser: window with rows
        d.rounded_rectangle((S * .08, S * .14, S * .92, S * .86), radius=S * .1, outline=c, width=int(S * .07))
        for y in (.36, .53, .70):
            d.line([(S * .24, S * y), (S * .76, S * y)], fill=c, width=int(S * .07))
    elif kind == "github":
        d.polygon([(x / 16 * S, y / 16 * S) for x, y in _github_points()], fill=c)
    small = im.resize((size, size), Image.LANCZOS)
    return ctk.CTkImage(light_image=small, dark_image=small, size=(size, size))


def flag_photo(cc, box=(24, 16)):
    """Flag scaled to fit a fixed box and centred in it, so every row lines up."""
    try:
        im = Image.open(os.path.join(ASSETS, "flags", cc + ".png")).convert("RGBA")
    except Exception:
        return None
    im.thumbnail(box, Image.LANCZOS)
    canvas = Image.new("RGBA", box, (0, 0, 0, 0))
    canvas.paste(im, ((box[0] - im.width) // 2, (box[1] - im.height) // 2), im)
    return ImageTk.PhotoImage(canvas)


DEFAULTS = {
    "autostart": False,
    "run_when": "Always",
    "hide_fakes": True,
    "rules": {k: True for k, _, _ in RULES},
    "port_range": "26000-28999", "padded": "show",
    "simplify": True, "country_prefix": True, "flag_style": "emoji",
    "country_mode": "block", "countries": [],
}


class App(ctk.CTk):
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        super().__init__()
        self.title("CS2 Server Filter")
        self.geometry("820x640")
        self.minsize(720, 560)
        self.after(250, self.set_icon)
        self.s = self.load_settings()
        self.handle_box = {}
        self.thread = None
        self.logq = queue.Queue()
        self.cmdq = queue.Queue()
        self.counts = {}
        self.paused = False
        self.gate_ok = True
        self.loading = True
        self.restart_job = None
        self.restart_pending = False
        self.tray = None
        self.home = country_geo.home_country()
        self.build_ui()
        self.loading = False
        self.after(150, self.pump_log)
        self.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        self.start_tray()
        self.check_gate(initial=True)
        if is_admin():
            self.after(300, self.start)
        self.after(3000, self.poll_gate)
        if "--minimized" in sys.argv and self.tray:
            self.after(500, self.withdraw)

    def set_icon(self):
        try:
            self.iconbitmap(os.path.join(ASSETS, "icon.ico"))
        except Exception:
            pass

    # ------------------------------------------------------------- tray
    def start_tray(self):
        try:
            import pystray
            menu = pystray.Menu(
                pystray.MenuItem("Open", lambda *_: self.cmdq.put("show"), default=True),
                pystray.MenuItem("Open Steam server browser", lambda *_: self.cmdq.put("steam")),
                pystray.MenuItem("Pause / resume filtering", lambda *_: self.cmdq.put("toggle")),
                pystray.MenuItem("Quit", lambda *_: self.cmdq.put("quit")))
            self.tray = pystray.Icon("cs2filter", tray_image(), "CS2 Server Filter", menu)
            self.tray.run_detached()
        except Exception as e:
            self.tray = None
            self.log(f"tray icon unavailable: {e!r}")

    def hide_to_tray(self):
        self.save_settings()
        if self.tray:
            self.withdraw()
        else:
            self.quit_app()

    def show_window(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def quit_app(self):
        self.save_settings()
        self.stop()
        if self.tray:
            try:
                self.tray.stop()
            except Exception:
                pass
        self.destroy()
        os._exit(0)

    def open_steam_browser(self):
        try:
            os.startfile("steam://open/servers")
        except OSError:
            messagebox.showerror("Steam", "Could not open Steam. Is it installed?")

    # ------------------------------------------------------ auto-apply
    def changed(self, *_):
        """Any setting changed: save and restart the filter shortly after the last edit."""
        if self.loading:
            return
        if self.restart_job:
            self.after_cancel(self.restart_job)
        self.restart_job = self.after(1200, self.apply_now)

    def check_gate(self, initial=False):
        """Filtering only runs while the chosen program (Steam / CS2) is running."""
        need = RUN_MODES.get(self.run_var.get())
        ok = True if not need else bool(need & running_processes())
        changed = ok != self.gate_ok
        self.gate_ok = ok
        if initial or not changed:
            return
        if ok:
            if not self.paused:
                self.start()
        else:
            self.stop()
            self.set_status(self.waiting_text(), AMBER)

    def waiting_text(self):
        return "Waiting for CS2 to start" if "CS2" in self.run_var.get() else "Waiting for Steam to start"

    def poll_gate(self):
        try:
            self.check_gate()
        except Exception:
            pass
        self.after(3000, self.poll_gate)

    def apply_now(self):
        self.restart_job = None
        self.save_settings()
        self.check_gate()
        if self.paused or not is_admin() or not self.gate_ok:
            return
        if self.thread and self.thread.is_alive():
            self.restart_pending = True
            self.stop()
        else:
            self.start()

    def watch(self, var):
        var.trace_add("write", self.changed)
        return var

    # ---------------------------------------------------------- settings
    def load_settings(self):
        s = json.loads(json.dumps(DEFAULTS))
        try:
            with open(SETTINGS_FILE, encoding="utf-8") as f:
                saved = json.load(f)
            for k, v in saved.items():
                if k == "rules":
                    s["rules"].update(v)
                elif k in s:
                    s[k] = v
        except (OSError, ValueError):
            pass
        return s

    def save_settings(self):
        self.collect()
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.s, f, indent=2)
        except OSError as e:
            self.log(f"could not save settings: {e}")

    # ---------------------------------------------------------------- UI
    def build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        head = ctk.CTkFrame(self, corner_radius=14)
        head.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        head.grid_columnconfigure(0, weight=1)
        titles = ctk.CTkFrame(head, fg_color="transparent")
        titles.grid(row=0, column=0, padx=18, pady=12, sticky="w")
        ctk.CTkLabel(titles, text="CS2 Server Filter", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        self.status_dot = ctk.CTkLabel(titles, text="● Starting...", text_color=GRAY,
                                       font=ctk.CTkFont(size=13, weight="bold"))
        self.status_dot.pack(anchor="w")
        self.ic_list = glyph("list")
        self.ic_pause, self.ic_play = glyph("pause"), glyph("play")
        ctk.CTkButton(head, text=" Open server browser", image=self.ic_list, compound="left",
                      width=190, height=38, corner_radius=10,
                      font=ctk.CTkFont(size=14, weight="bold"), command=self.open_steam_browser).grid(
            row=0, column=1, padx=6)
        self.btn = ctk.CTkButton(head, text=" Pause", image=self.ic_pause, compound="left", width=105, height=38, corner_radius=10,
                                 fg_color="#4b5563", hover_color="#374151",
                                 font=ctk.CTkFont(size=14, weight="bold"), command=self.toggle)
        self.btn.grid(row=0, column=2, padx=(0, 6))
        self.gh_icon = glyph("github", 24)
        ctk.CTkButton(head, text="", image=self.gh_icon, width=38, height=38, corner_radius=10,
                      fg_color="#374151", hover_color="#4b5563",
                      command=lambda: os.startfile(REPO_URL)).grid(row=0, column=3, padx=(0, 18))
        if not is_admin():
            warn = ctk.CTkFrame(head, fg_color="#7f1d1d", corner_radius=10)
            warn.grid(row=1, column=0, columnspan=4, sticky="ew", padx=14, pady=(0, 12))
            ctk.CTkLabel(warn, text="Needs Administrator rights to filter.").pack(side="left", padx=12, pady=8)
            ctk.CTkButton(warn, text="Restart as Administrator", width=190, fg_color="#b91c1c",
                          hover_color="#991b1b", command=self.restart_admin).pack(side="right", padx=10, pady=6)

        self.tabs = ctk.CTkTabview(self, corner_radius=14)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 8))
        for name in ("Home", "Countries", "Advanced"):
            self.tabs.add(name)
        self.build_home(self.tabs.tab("Home"))
        self.build_countries(self.tabs.tab("Countries"))
        self.build_advanced(self.tabs.tab("Advanced"))
        ctk.CTkLabel(self, text=f"v{__version__}  ·  Country data by DB-IP.com  ·  Not affiliated with Valve  ·  Project page: top-right icon",
                     text_color=GRAY, font=ctk.CTkFont(size=11)).grid(row=2, column=0, pady=(0, 8))
        self.log("Filtering is always on. Changes to settings apply automatically.")

    def switch_row(self, parent, label, var, hint, command=None):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(12, 0))
        ctk.CTkSwitch(row, text=label, variable=var, command=command,
                      font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(row, text=hint, text_color=GRAY, wraplength=680, justify="left").pack(
            anchor="w", padx=(46, 0), pady=(2, 0))

    def build_home(self, tab):
        card = ctk.CTkFrame(tab, corner_radius=12)
        card.pack(fill="x", padx=6, pady=(6, 4))
        self.hide_var = self.watch(ctk.BooleanVar(value=self.s["hide_fakes"]))
        self.switch_row(card, "Hide fake servers", self.hide_var,
                        "Removes servers with made-up player counts, copied servers and spam from Steam's list.")
        self.simplify_var = self.watch(ctk.BooleanVar(value=self.s["simplify"]))
        self.switch_row(card, "Tidy server names", self.simplify_var,
                        "One clean style for every server:  flag  Mode | Name   (emoji and clutter removed).")
        self.flag_var = self.watch(ctk.BooleanVar(value=self.s["country_prefix"]))
        self.switch_row(card, "Show the server's country", self.flag_var,
                        "Puts the real country (from its IP address) in front of the name.")
        self.auto_var = ctk.BooleanVar(value=self.s["autostart"])
        self.switch_row(card, "Start with Windows", self.auto_var,
                        "Runs quietly in the system tray after you log in.", command=self.toggle_autostart)
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(12, 0))
        ctk.CTkLabel(row, text="Filter", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        self.run_var = self.watch(ctk.StringVar(value=self.s["run_when"] if self.s["run_when"] in RUN_MODES
                                                else "Always"))
        ctk.CTkSegmentedButton(row, values=list(RUN_MODES), variable=self.run_var, width=430).pack(
            side="left", padx=14)
        ctk.CTkLabel(card, text="Use \"While Steam is open\" with Start with Windows: the app waits quietly in the tray "
                                "and only filters while Steam is running.",
                     text_color=GRAY, wraplength=680, justify="left").pack(anchor="w", padx=14, pady=(2, 12))
        self.stats = ctk.CTkLabel(tab, text="", text_color=GRAY, font=ctk.CTkFont(size=13))
        self.stats.pack(anchor="w", padx=16, pady=(8, 0))
        ctk.CTkLabel(tab, text="Tip: pick countries to hide in the Countries tab, then press "
                               "\"Open server browser\" and refresh the list.",
                     text_color=GRAY, wraplength=700, justify="left").pack(anchor="w", padx=16, pady=(4, 0))

    def build_advanced(self, tab):
        self.adv_view = ctk.StringVar(value="Filters")
        ctk.CTkSegmentedButton(tab, values=["Filters", "Names", "Activity"], variable=self.adv_view,
                               command=lambda _: self.show_adv(), width=300).pack(pady=(4, 6))
        self.adv_frames = {}
        holder = ctk.CTkFrame(tab, fg_color="transparent")
        holder.pack(fill="both", expand=True)
        for name in ("Filters", "Names", "Activity"):
            self.adv_frames[name] = ctk.CTkFrame(holder, fg_color="transparent")
        self.build_filters(self.adv_frames["Filters"])
        self.build_names(self.adv_frames["Names"])
        self.build_log(self.adv_frames["Activity"])
        self.show_adv()

    def show_adv(self):
        for f in self.adv_frames.values():
            f.pack_forget()
        self.adv_frames[self.adv_view.get()].pack(fill="both", expand=True)

    def build_filters(self, tab):
        self.rule_vars = {}
        ctk.CTkLabel(tab, text="For experts - the defaults are right for most people.",
                     text_color=GRAY).pack(anchor="w", padx=10)
        scroll = ctk.CTkScrollableFrame(tab, corner_radius=12)
        scroll.pack(fill="both", expand=True, padx=6, pady=4)
        for key, label, tip in RULES:
            v = self.watch(ctk.BooleanVar(value=self.s["rules"].get(key, True)))
            self.rule_vars[key] = v
            ctk.CTkSwitch(scroll, text=label, variable=v).pack(anchor="w", padx=8, pady=(8, 0))
            ctk.CTkLabel(scroll, text=tip, text_color=GRAY, wraplength=620, justify="left").pack(
                anchor="w", padx=(52, 8))
        ctk.CTkLabel(scroll, text="Settings", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=8, pady=(18, 0))
        fr = ctk.CTkFrame(scroll, fg_color="transparent")
        fr.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(fr, text="Port range (or 'any')", anchor="w").pack(side="left")
        self.port_var = self.watch(ctk.StringVar(value=str(self.s["port_range"])))
        ctk.CTkEntry(fr, textvariable=self.port_var, width=110, justify="center").pack(side="right")
        fr = ctk.CTkFrame(scroll, fg_color="transparent")
        fr.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(fr, text="Servers with fake padding", anchor="w").pack(side="left")
        self.padded_var = self.watch(ctk.StringVar(value=self.s["padded"]))
        ctk.CTkSegmentedButton(fr, values=["show", "drop"], variable=self.padded_var, width=130).pack(side="right")
        ctk.CTkLabel(scroll, text="show = keep them with the real player count.   drop = hide them.",
                     text_color=GRAY, wraplength=620, justify="left").pack(anchor="w", padx=8)

    def build_names(self, tab):
        card = ctk.CTkFrame(tab, corner_radius=12)
        card.pack(fill="x", padx=6, pady=6)
        fr = ctk.CTkFrame(card, fg_color="transparent")
        fr.pack(anchor="w", padx=14, pady=(14, 4))
        ctk.CTkLabel(fr, text="Country style:").pack(side="left")
        self.style_var = self.watch(ctk.StringVar(value=self.s["flag_style"]))
        ctk.CTkSegmentedButton(fr, values=["emoji", "text"], variable=self.style_var, width=160).pack(
            side="left", padx=10)
        ctk.CTkLabel(card, text="emoji = flag emoji + icons (Steam on Windows may show flags as two letters).\n"
                                "text = [LV] and [WS].", text_color=GRAY, justify="left").pack(
            anchor="w", padx=14, pady=(0, 14))

    def build_log(self, tab):
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.pack(fill="x", padx=8)
        ctk.CTkLabel(bar, text="What the filter has done", text_color=GRAY).pack(side="left")
        ctk.CTkButton(bar, text="Clear", width=70, height=26, fg_color="transparent", border_width=1,
                      command=lambda: self.text.delete("1.0", "end")).pack(side="right")
        self.text = ctk.CTkTextbox(tab, font=("Consolas", 12), wrap="none", corner_radius=10)
        self.text.pack(fill="both", expand=True, padx=6, pady=6)
        self.text._textbox.tag_configure("DROP", foreground="#f87171")
        self.text._textbox.tag_configure("ADJUST", foreground="#fbbf24")

    # --------------------------------------------------------- countries
    def build_countries(self, tab):
        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", padx=6, pady=(4, 2))
        self.cmode = self.watch(ctk.StringVar(
            value="Hide ticked" if self.s["country_mode"] == "block" else "Only ticked"))
        ctk.CTkSegmentedButton(top, values=["Hide ticked", "Only ticked"], variable=self.cmode, width=220).pack(side="left")
        self.ccount = ctk.CTkLabel(top, text="", text_color=ACCENT)
        self.ccount.pack(side="right", padx=8)
        ctk.CTkButton(top, text="Untick all", width=90, fg_color="transparent", border_width=1,
                      command=self.clear_countries).pack(side="right")
        self.search = ctk.StringVar()
        self.search.trace_add("write", lambda *_: self.filter_countries())
        ctk.CTkEntry(top, textvariable=self.search, placeholder_text="Search country", width=180).pack(
            side="right", padx=10)
        ctk.CTkLabel(tab, text=f"Closest to you first ({COUNTRIES.get(self.home, self.home)}).  "
                               "Nothing ticked = servers from every country are shown.",
                     text_color=GRAY).pack(anchor="w", padx=10, pady=(0, 4))
        # plain tk widgets: ~200 customtkinter widgets made the window sluggish to move/resize
        BG, FG = "#262626", "#dce4ee"
        wrap = tk.Frame(tab, bg=BG)
        wrap.pack(fill="both", expand=True, padx=6, pady=4)
        canvas = tk.Canvas(wrap, bg=BG, highlightthickness=0)
        sb = ctk.CTkScrollbar(wrap, command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        self.cscroll = tk.Frame(canvas, bg=BG)
        win = canvas.create_window(0, 0, window=self.cscroll, anchor="nw")
        self.cscroll.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        self.wheel_target = canvas
        for w in (canvas, self.cscroll):
            w.bind("<MouseWheel>", self.country_wheel)
        for c in range(3):
            self.cscroll.grid_columnconfigure(c, weight=1, uniform="c")
        self.cvars, self.cboxes, self.flag_imgs = {}, {}, []
        chosen = set(self.s["countries"])
        ordered = sorted(COUNTRIES, key=lambda c: country_geo.distance_km(self.home, c)
                         if c in country_geo.CENTERS else 1e9)
        for cc in ordered:
            var = tk.BooleanVar(value=cc in chosen)
            var.trace_add("write", lambda *_: self.update_ccount())
            self.watch(var)
            self.cvars[cc] = var
            img = flag_photo(cc)
            if img:
                self.flag_imgs.append(img)
            km = country_geo.distance_km(self.home, cc) if cc in country_geo.CENTERS else None
            dist = "" if km is None or cc == self.home else f"  {int(round(km, -1)):,} km".replace(",", " ")
            self.cboxes[cc] = tk.Checkbutton(
                self.cscroll, text=f" {COUNTRIES[cc]}{dist}", image=img, compound="left", variable=var,
                bg=BG, fg=FG, activebackground=BG, activeforeground=FG, selectcolor="#3a3a3a",
                anchor="w", bd=0, highlightthickness=0, padx=4, pady=3)
            self.cboxes[cc].bind("<MouseWheel>", self.country_wheel)
        self.filter_countries()

    def country_wheel(self, ev):
        self.wheel_target.yview_scroll(int(-ev.delta / 120) * 2, "units")
        return "break"

    def filter_countries(self):
        q = self.search.get().strip().lower()
        i = 0
        for cc, box in self.cboxes.items():
            if not q or q in cc.lower() or q in COUNTRIES[cc].lower():
                box.grid(row=i // 3, column=i % 3, sticky="ew", padx=6, pady=1)
                i += 1
            else:
                box.grid_remove()
        self.update_ccount()

    def update_ccount(self):
        n = sum(1 for v in self.cvars.values() if v.get())
        self.ccount.configure(text=f"{n} ticked")

    def clear_countries(self):
        for v in self.cvars.values():
            v.set(False)

    # ----------------------------------------------------------- control
    def collect(self):
        self.s["autostart"] = self.auto_var.get()
        self.s["run_when"] = self.run_var.get()
        self.s["hide_fakes"] = self.hide_var.get()
        self.s["simplify"] = self.simplify_var.get()
        self.s["country_prefix"] = self.flag_var.get()
        self.s["rules"] = {k: v.get() for k, v in self.rule_vars.items()}
        self.s["port_range"] = self.port_var.get()
        self.s["padded"] = self.padded_var.get()
        self.s["flag_style"] = self.style_var.get()
        self.s["country_mode"] = "block" if self.cmode.get() == "Hide ticked" else "allow"
        self.s["countries"] = sorted(c for c, v in self.cvars.items() if v.get())

    def build_config(self):
        s = self.s
        cc = set(s["countries"])
        return a2s_filter.Config(
            disabled={k for k, _, _ in RULES} if not s["hide_fakes"] else {k for k, on in s["rules"].items() if not on},
            port_range=a2s_filter.parse_port_range(str(s["port_range"])),  # ValueError if malformed
            padded=s["padded"],
            tidy_names=s["simplify"],
            country_prefix=s["country_prefix"],
            flag_style=s["flag_style"],
            block_countries=cc if s["country_mode"] == "block" else set(),
            allow_countries=cc if s["country_mode"] == "allow" else set())

    def set_status(self, text, color):
        self.status_dot.configure(text="● " + text, text_color=color)

    def toggle(self):
        """Pause / resume."""
        if self.paused:
            self.paused = False
            self.btn.configure(text=" Pause", image=self.ic_pause, fg_color="#4b5563", hover_color="#374151")
            self.start()
        else:
            self.paused = True
            self.restart_pending = False
            self.btn.configure(text=" Resume", image=self.ic_play, fg_color=PRIMARY, hover_color=PRIMARY_HOVER)
            self.stop()
            self.set_status("Paused - nothing is filtered", AMBER)

    def toggle_autostart(self):
        on = self.auto_var.get()
        if not set_autostart(on):
            self.auto_var.set(not on)
            messagebox.showerror("Start with Windows", "Could not change the startup task (needs Administrator).")
        else:
            self.log("Will start with Windows (minimized to tray)." if on else "Will no longer start with Windows.")
        self.save_settings()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        if not is_admin():
            self.set_status("Needs Administrator rights", RED)
            return
        if not self.gate_ok:
            self.set_status(self.waiting_text(), AMBER)
            return
        self.save_settings()
        try:
            cfg = self.build_config()
        except ValueError:
            messagebox.showerror("Settings", "Port range must look like 26000-28999 or 'any'.")
            return
        self.handle_box = {}
        self.thread = threading.Thread(target=self.worker, args=(cfg,), daemon=True)
        self.thread.start()
        self.set_status("Filtering is on", GREEN)

    def worker(self, cfg):
        try:
            a2s_filter.run(cfg, out=self.logq.put, handle_box=self.handle_box)
        except Exception as e:
            self.logq.put(f"ERROR: {e!r}")
        self.logq.put("__stopped__")

    def stop(self):
        w = self.handle_box.get("w")
        try:
            if w:
                w.close()
        except Exception:
            pass

    def restart_admin(self):
        self.save_settings()
        if relaunch_as_admin():
            self.quit_app()
        messagebox.showerror("Administrator", "Could not restart with Administrator rights.")

    # --------------------------------------------------------------- log
    def log(self, line):
        self.logq.put(line)

    def pump_log(self):
        while not self.cmdq.empty():
            cmd = self.cmdq.get()
            if cmd == "show":
                self.show_window()
            elif cmd == "steam":
                self.open_steam_browser()
            elif cmd == "toggle":
                self.toggle()
            elif cmd == "quit":
                self.quit_app()
        try:
            while True:
                line = self.logq.get_nowait()
                if line == "__stopped__":
                    if self.restart_pending and not self.paused:
                        self.restart_pending = False
                        self.log("Settings changed - filter restarted.")
                        self.after(200, self.start)
                    elif not self.paused and self.gate_ok:
                        self.set_status("Stopped", GRAY)
                    continue
                tag = ""
                head = line[:30].lower()
                if " drop" in head:
                    tag = "DROP"
                elif " adjust" in head:
                    tag = "ADJUST"
                if tag:
                    self.counts[tag] = self.counts.get(tag, 0) + 1
                self.text.insert("end", line + "\n", tag or None)
                if int(self.text.index("end").split(".")[0]) > 3000:
                    self.text.delete("1.0", "800.0")
                self.text.see("end")
        except queue.Empty:
            pass
        if self.counts:
            self.stats.configure(
                text=f"Fake servers hidden: {self.counts.get('DROP', 0)}      "
                     f"Player counts corrected: {self.counts.get('ADJUST', 0)}")
        self.after(150, self.pump_log)


_MUTEX = None


def single_instance():
    import time
    global _MUTEX
    for _ in range(12):  # a previous instance may still be exiting (e.g. after "Restart as Administrator")
        _MUTEX = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\CS2ServerFilterMutex")
        if ctypes.windll.kernel32.GetLastError() != 183:  # ERROR_ALREADY_EXISTS
            return True
        ctypes.windll.kernel32.CloseHandle(_MUTEX)
        time.sleep(0.25)
    return False


if __name__ == "__main__":
    if not single_instance():
        messagebox.showinfo("CS2 Server Filter", "Already running - look for its icon in the system tray.")
        sys.exit(0)
    App().mainloop()
