#!/usr/bin/env python3
"""
deepscan - see every device on your network by NAME, with vendor, device type,
open ports, live ping graphs, nicknames and new/offline device tracking.

    deepscan                 # scan your network (same as: deepscan all)
    deepscan 10.0.0.0/24     # scan a specific subnet

Keys
  up/down   move            enter   open device page      /   search
  tab       switch panel    r       rescan                s   change sort
  b         toggle sidebar  t       next theme            e   export CSV
  c         copy IP         ctrl+p  command palette       q   quit
  a         credits
Inside a device page:  n nickname   o open its web page   c copy IP   esc back

Everything it remembers lives in ~/.deepscan/
"""
import csv
import ipaddress
import json
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import webbrowser
from collections import deque

from rich.markup import escape
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (DataTable, Footer, Header, Input, Label, ListItem, ListView,
                             ProgressBar, Sparkline, Static)
from textual.worker import get_current_worker

try:  # custom entries in the ctrl+p command palette (newer Textual)
    from textual.app import SystemCommand
except ImportError:
    SystemCommand = None

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
NO_WINDOW = {"creationflags": 0x08000000} if IS_WIN else {}  # no console flashes on Windows

# Put your name here and it shows up on the credits screen (press a)
AUTHOR = "Wyatt Lux"
VERSION = "2.0"

DATA_DIR = Path.home() / ".deepscan"
VENDOR_FILE = DATA_DIR / "vendors.tsv"
HISTORY_FILE = DATA_DIR / "seen.json"
SETTINGS_FILE = DATA_DIR / "settings.json"

# Common ports that say a lot about what a device is
PORTS = {
    22: "SSH", 53: "DNS", 80: "Web", 139: "NetBIOS", 443: "Web (HTTPS)",
    445: "Windows file sharing", 548: "Mac file sharing", 554: "Camera stream (RTSP)",
    631: "Printer (IPP)", 1400: "Sonos", 1883: "Smart home (MQTT)",
    3389: "Remote Desktop", 5000: "UPnP / NAS", 5900: "Screen sharing (VNC)",
    7000: "AirPlay", 8008: "Chromecast", 8060: "Roku", 8080: "Web (alt)",
    9100: "Printer (raw)", 62078: "iPhone/iPad sync",
}


# --------------------------------------------------------------------------- #
#  Small helpers
# --------------------------------------------------------------------------- #
def run(cmd, timeout=10) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="ignore",
                              timeout=timeout, **NO_WINDOW).stdout
    except Exception:
        return ""


def local_ip() -> str:
    """Our LAN IP. connect() on UDP sends nothing; it just picks a route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def local_mac() -> str:
    n = uuid.getnode()
    if (n >> 40) & 1:  # uuid gave us a random fallback, not the real MAC
        return "?"
    return ":".join(f"{(n >> s) & 0xFF:02X}" for s in range(40, -1, -8))


IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
PING_TIME = re.compile(r"time[=<]\s*([\d.]+)", re.I)
PING_TTL = re.compile(r"ttl[=\s]+(\d+)", re.I)


def default_gateways() -> set:
    found = set()
    if IS_WIN:
        lines = run(["ipconfig"]).splitlines()
        for i, line in enumerate(lines):
            if "Gateway" in line:
                nxt = lines[i + 1] if i + 1 < len(lines) else ""
                for cand in (line, nxt if ". :" not in nxt else ""):
                    m = IP_RE.search(cand)
                    if m:
                        found.add(m.group(1))
    elif IS_MAC:
        found.update(re.findall(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", run(["route", "-n", "get", "default"])))
    else:
        found.update(re.findall(r"default via (\d+\.\d+\.\d+\.\d+)", run(["ip", "route"])))
    return found


# --------------------------------------------------------------------------- #
#  Discovery
# --------------------------------------------------------------------------- #
def ping(ip: str):
    """Returns (ms, ttl) if the device replied, else None.
    Even when a device ignores ping, this fills the ARP cache so we still find it."""
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    out = run(cmd, timeout=3)
    ttl = PING_TTL.search(out)
    if not ttl:
        return None
    t = PING_TIME.search(out)
    return (float(t.group(1)) if t else None, int(ttl.group(1)))


def norm_mac(m: str) -> str:
    return ":".join(p.zfill(2) for p in re.split("[:-]", m)).upper()


def read_arp() -> dict:
    """Parse the OS neighbor table -> {ip: mac}. Works on Windows/macOS/Linux."""
    text = run(["arp", "-a"])
    try:  # Linux without net-tools installed
        text += "\n" + Path("/proc/net/arp").read_text()
    except OSError:
        pass
    table = {}
    for line in text.splitlines():
        ip, mac = IP_RE.search(line), MAC_RE.search(line)
        if not (ip and mac):
            continue
        m = norm_mac(mac.group(1))
        if m in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or m.startswith("01:00:5E"):
            continue  # broadcast / incomplete / multicast
        table[ip.group(1)] = m
    return table


def is_randomized(mac: str) -> bool:
    """Locally-administered bit set -> private/random MAC (usually a phone)."""
    try:
        return bool(int(mac[1], 16) & 0x2)
    except (ValueError, IndexError):
        return False


def port_open(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
#  Vendor (manufacturer) lookup - downloads the official list once, then offline
# --------------------------------------------------------------------------- #
def _download(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (deepscan)"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "ignore")


def _parse_ieee(text: str) -> dict:
    db = {}
    for row in csv.reader(text.splitlines()):
        if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1]):
            db[row[1].upper()] = row[2].strip()
    return db


def _parse_wireshark(text: str) -> dict:
    db = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){2}", parts[0]):
            db[parts[0].replace(":", "").upper()] = (parts[2] if len(parts) > 2 else parts[1]).strip()
    return db


def load_vendors() -> dict:
    fresh = VENDOR_FILE.exists() and time.time() - VENDOR_FILE.stat().st_mtime < 90 * 86400
    if not fresh:
        for url, parse in (("https://standards-oui.ieee.org/oui/oui.csv", _parse_ieee),
                           ("https://www.wireshark.org/download/automated/data/manuf", _parse_wireshark)):
            try:
                db = parse(_download(url))
                if len(db) > 1000:
                    DATA_DIR.mkdir(exist_ok=True)
                    VENDOR_FILE.write_text("\n".join(f"{k}\t{v.replace(chr(9), ' ')}" for k, v in db.items()),
                                           encoding="utf-8")
                    return db
            except Exception:
                continue
    db = {}
    try:  # use the cached copy (or an old one if the download failed)
        for line in VENDOR_FILE.read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("\t")
            db[k] = v
    except OSError:
        pass
    return db


_SUFFIX = re.compile(r"[,.]?\s+(inc|corp|corporation|co|ltd|limited|llc|gmbh|technologies|"
                     r"technology|electronics|international)\.?$", re.I)


def short_vendor(name: str) -> str:
    """'Samsung Electronics Co.,Ltd' -> 'Samsung'"""
    if not name:
        return ""
    name = name.split(",")[0].strip()
    for _ in range(3):
        name = _SUFFIX.sub("", name).strip()
    return name


# --------------------------------------------------------------------------- #
#  Name resolution (DNS, mDNS, NetBIOS)
# --------------------------------------------------------------------------- #
def rdns_name(ip: str):
    try:
        name = socket.gethostbyaddr(ip)[0]
        return None if name == ip else name
    except OSError:
        return None


def _encode_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"


def _read_name(data: bytes, off: int):
    """Read a DNS name, following compression pointers. Returns (name, next_offset)."""
    labels, end, jumps = [], None, 0
    while True:
        if off >= len(data) or jumps > 20:
            raise ValueError("bad name")
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((ln & 0x3F) << 8) | data[off + 1]
            jumps += 1
            continue
        if ln == 0:
            return ".".join(labels), (end if end is not None else off + 1)
        labels.append(data[off + 1:off + 1 + ln].decode("utf-8", "ignore"))
        off += 1 + ln


def mdns_name(ip: str, timeout: float = 0.8):
    """Ask the device itself (unicast to port 5353) for its .local name."""
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    query = (struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0, 1, 0, 0, 0)
             + _encode_name(rev) + struct.pack(">HH", 12, 1))  # PTR, IN
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(query, (ip, 5353))
            data, _ = s.recvfrom(4096)
        except OSError:
            return None
    try:
        qd, an = struct.unpack(">HH", data[4:8])
        off = 12
        for _ in range(qd):
            _, off = _read_name(data, off)
            off += 4
        for _ in range(an):
            _, off = _read_name(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 12:
                return _read_name(data, off)[0]
            off += rdlen
    except (ValueError, struct.error, IndexError):
        pass
    return None


def netbios_name(ip: str, timeout: float = 0.8):
    """NBSTAT query on UDP 137 - Windows machines answer with their computer name."""
    query = (struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0, 1, 0, 0, 0)
             + b"\x20" + b"CK" + b"A" * 30 + b"\x00"  # encoded wildcard name "*"
             + struct.pack(">HH", 0x21, 1))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(query, (ip, 137))
            data, _ = s.recvfrom(1024)
        except OSError:
            return None
    if len(data) < 57:
        return None
    for i in range(data[56]):
        entry = data[57 + 18 * i:57 + 18 * (i + 1)]
        if len(entry) < 18:
            break
        name = entry[:15].decode("ascii", "ignore").strip()
        suffix, flags = entry[15], struct.unpack(">H", entry[16:18])[0]
        if name and suffix == 0x00 and not flags & 0x8000:  # unique workstation name
            return name
    return None


def clean(name: str) -> str:
    name = name.rstrip(".")
    for tail in (".local", ".lan", ".home", ".localdomain"):
        if name.lower().endswith(tail):
            return name[: -len(tail)]
    return name


def resolve_all(ip: str) -> dict:
    """{source: name} for every method that answered, best first."""
    found = {}
    for src, fn in (("DNS", rdns_name), ("mDNS", mdns_name), ("NetBIOS", netbios_name)):
        n = fn(ip)
        if n:
            found[src] = clean(n)
    return found


# --------------------------------------------------------------------------- #
#  Guessing what a device is
# --------------------------------------------------------------------------- #
def os_from_ttl(ttl):
    if not ttl:
        return ""
    if ttl <= 64:
        return "Linux / Apple / Android"
    if ttl <= 128:
        return "Windows"
    return "Network equipment"


def guess_type(d: dict) -> str:
    if d["is_me"]:
        return "This computer"
    if d["is_gw"]:
        return "Router / gateway"
    names = " ".join(d["names"].values()).lower()
    v = d["vendor_full"].lower()
    p = set(d["ports"])

    def has(*words):
        return any(w in names for w in words)

    def made_by(*words):
        return any(w in v for w in words)

    if 62078 in p or has("iphone", "ipad"):
        return "iPhone / iPad"
    if {631, 9100} & p or has("printer") or made_by("epson", "brother", "canon", "lexmark", "xerox") \
            or v.startswith("hp ") or "hewlett" in v:
        return "Printer"
    if {8008} & p or has("chromecast", "google-home", "nest"):
        return "Google / Chromecast"
    if 8060 in p or made_by("roku") or has("roku"):
        return "Roku"
    if 1400 in p or made_by("sonos"):
        return "Sonos speaker"
    if made_by("amazon") or has("echo", "kindle", "firetv", "fire-tv"):
        return "Amazon device"
    if has("appletv", "apple-tv"):
        return "Apple TV"
    if has("macbook", "imac", "mac-mini", "macmini", "mac-studio") or 548 in p:
        return "Mac"
    if 3389 in p or has("desktop-", "laptop-") or ("NetBIOS" in d["names"] and (d["ttl"] or 0) > 64):
        return "Windows PC"
    if made_by("raspberry") or has("raspberrypi"):
        return "Raspberry Pi"
    if 554 in p or has("camera", "doorbell", "ring-"):
        return "Camera"
    if made_by("espressif", "tuya", "shelly", "wyze", "signify", "philips lighting") or 1883 in p:
        return "Smart home / IoT"
    if made_by("nintendo"):
        return "Nintendo console"
    if made_by("sony"):
        return "Sony / PlayStation"
    if made_by("microsoft"):
        return "Microsoft / Xbox"
    if has("android", "galaxy", "pixel"):
        return "Android phone"
    if made_by("samsung"):
        return "Samsung device"
    if made_by("apple"):
        return "Apple device"
    if d["private"]:
        return "Phone/tablet (private MAC)"
    guess = os_from_ttl(d["ttl"])
    return f"? {guess}" if guess else "?"


def load_history() -> dict:
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_history(h: dict) -> None:
    try:
        DATA_DIR.mkdir(exist_ok=True)
        HISTORY_FILE.write_text(json.dumps(h, indent=1), encoding="utf-8")
    except OSError:
        pass


def load_settings() -> dict:
    try:
        return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_settings(s: dict) -> None:
    try:
        DATA_DIR.mkdir(exist_ok=True)
        SETTINGS_FILE.write_text(json.dumps(s, indent=1), encoding="utf-8")
    except OSError:
        pass


def copy_text(app, text: str) -> bool:
    if IS_MAC:
        cmds = [["pbcopy"]]
    elif IS_WIN:
        cmds = [["clip"]]
    else:
        cmds = [["wl-copy"], ["xclip", "-selection", "clipboard"]]
    for cmd in cmds:
        try:
            subprocess.run(cmd, input=text, text=True, timeout=3, check=True, **NO_WINDOW)
            return True
        except Exception:
            continue
    try:
        app.copy_to_clipboard(text)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  Presentation helpers
# --------------------------------------------------------------------------- #
CATEGORIES = [
    ("all", "◉ All"),
    ("new", "★ New"),
    ("phones", "📱 Phones & tablets"),
    ("computers", "💻 Computers"),
    ("media", "📺 TV & media"),
    ("smart", "💡 Smart home"),
    ("printers", "🖨  Printers"),
    ("network", "🌐 Network"),
    ("other", "❔ Other"),
    ("offline", "💤 Offline"),
]

TYPE_CATEGORY = {
    "iPhone / iPad": "phones", "Android phone": "phones", "Phone/tablet (private MAC)": "phones",
    "This computer": "computers", "Mac": "computers", "Windows PC": "computers",
    "Raspberry Pi": "computers",
    "Google / Chromecast": "media", "Roku": "media", "Sonos speaker": "media", "Apple TV": "media",
    "Amazon device": "media", "Sony / PlayStation": "media", "Nintendo console": "media",
    "Microsoft / Xbox": "media",
    "Smart home / IoT": "smart", "Camera": "smart",
    "Printer": "printers",
    "Router / gateway": "network",
}

SORTS = ["ip", "name", "type", "ping"]


def category(d: dict) -> str:
    return TYPE_CATEGORY.get(guess_type(d), "other")


def display_name(d: dict) -> str:
    if d["nick"]:
        return d["nick"]
    if d["names"]:
        return next(iter(d["names"].values()))
    return "…" if (d["online"] and not d["names_done"]) else "(unknown)"


def ping_style(ms) -> str:
    if ms is None:
        return ""
    return "green" if ms < 20 else "yellow" if ms < 100 else "red"


def live_summary(d: dict) -> str:
    samples = list(d["live"])
    if not samples:
        return "[dim]Waiting for the first reply…[/]" if d["online"] else "[dim]Device is offline[/]"
    replies = [s for s in samples if s is not None]
    loss = 100 * (len(samples) - len(replies)) / len(samples)
    last = samples[-1]
    last_s = "[red]no reply[/]" if last is None else f"[{ping_style(last)}]{last:.0f} ms[/]"
    avg_s = f"{sum(replies) / len(replies):.0f} ms" if replies else "-"
    loss_s = f"[red]{loss:.0f}%[/]" if loss else "0%"
    return f"Now {last_s}   Average {avg_s}   Lost {loss_s}"


def spark_data(d: dict) -> list:
    data = [s if s is not None else 0 for s in d["live"]]
    return data or [0]


def describe(d: dict, full: bool = False) -> str:
    """Markup text describing one device. full=True for the device page."""
    lines = []
    if full:
        title = f"[b]{escape(display_name(d))}[/b]"
        if d["nick"] and d["names"]:
            title += f"   [dim]calls itself {escape(next(iter(d['names'].values())))}[/]"
        lines += [title, ""]

    status = "[green]online[/]" if d["online"] else f"[dim]offline, last seen {d['last_seen']}[/]"
    head = f"[b]{d['ip']}[/b]   {status}"
    if d["new"]:
        head += "   [b yellow]★ first time on this network[/]"
    lines.append(head)

    if d["names"]:
        names = "   ".join(f"{escape(n)} [dim]({s})[/]" for s, n in d["names"].items())
    elif d["names_done"]:
        names = "[dim]no reply to DNS, mDNS or NetBIOS[/]"
    else:
        names = "[dim]looking up…[/]"
    if d["nick"] and not full:
        names = f"[b]{escape(d['nick'])}[/b] [dim](your nickname)[/]   " + names
    lines.append(f"Name     {names}")
    lines.append(f"Type     {guess_type(d)}")

    if d["vendor_full"]:
        vendor = escape(d["vendor_full"])
    else:
        vendor = "[dim]hidden by a private MAC[/]" if d["private"] else "[dim]unknown[/]"
    lines.append(f"Vendor   {vendor}")
    note = "   [yellow]private MAC (phones do this for privacy)[/]" if d["private"] else ""
    lines.append(f"MAC      {d['mac']}{note}")

    if d["ttl"]:
        ms = "?" if d["ping_ms"] is None else f"{d['ping_ms']:.1f} ms"
        lines.append(f"Ping     {ms}   TTL {d['ttl']} [dim]suggests {os_from_ttl(d['ttl'])}[/]")
    elif d["online"]:
        lines.append("Ping     [dim]ignores ping (found through ARP instead)[/]")

    if not d["online"]:
        pass
    elif not d["ports_done"]:
        lines.append("Ports    [dim]checking…[/]")
    elif d["ports"]:
        if full:
            lines.append("Ports")
            lines += [f"  {p:>5}  {PORTS[p]}" for p in d["ports"]]
        else:
            lines.append("Ports    " + ", ".join(f"{p} [dim]{PORTS[p]}[/]" for p in d["ports"]))
    else:
        lines.append("Ports    [dim]none of the common ones are open[/]")

    seen = f"first {d['first_seen']}"
    if full:
        seen += f", last {d['last_seen']}, in {d['times_seen']} scan{'s' if d['times_seen'] != 1 else ''}"
    lines.append(f"Seen     [dim]{seen}[/]")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Widgets and screens
# --------------------------------------------------------------------------- #
class SearchBox(Input):
    BINDINGS = [Binding("escape", "leave", "Back to list", show=False)]

    def action_leave(self) -> None:
        self.app.query_one("#table", DataTable).focus()


class NickBox(Input):
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def action_cancel(self) -> None:
        self.display = False
        self.screen.set_focus(None)


class DeviceScreen(ModalScreen):
    """Full page for one device. Opens with enter."""

    DEFAULT_CSS = """
    DeviceScreen { align: center middle; }
    #card {
        width: 92; max-width: 96%; height: auto; max-height: 94%;
        border: thick $accent; background: $surface; padding: 1 2;
    }
    #card-body { height: auto; }
    #card-live { margin-top: 1; }
    #card-spark { height: 4; margin-bottom: 1; }
    #nick { display: none; margin-bottom: 1; }
    #card-help { color: $text-muted; }
    """
    BINDINGS = [
        Binding("escape", "close", "Back"),
        Binding("n", "nickname", "Nickname"),
        Binding("o", "open_web", "Open web page"),
        Binding("c", "copy_ip", "Copy IP"),
    ]

    def __init__(self, key: str):
        super().__init__()
        self.device_key = key

    def compose(self) -> ComposeResult:
        with Vertical(id="card"):
            yield Static(id="card-body")
            yield Static(id="card-live")
            yield Sparkline([0], summary_function=max, id="card-spark")
            yield NickBox(placeholder="Type a nickname and press enter (empty clears it)", id="nick")
            yield Static("esc back   n nickname   o open web page   c copy IP", id="card-help")

    def on_mount(self) -> None:
        self.query_one("#card", Vertical).border_title = "Device"
        self.refresh_card()
        self.set_interval(1.0, self.refresh_card)

    def refresh_card(self) -> None:
        d = self.app.devices.get(self.device_key)
        if not d:
            return
        self.query_one("#card-body", Static).update(describe(d, full=True))
        self.query_one("#card-live", Static).update("Live ping   " + live_summary(d))
        self.query_one("#card-spark", Sparkline).data = spark_data(d)

    def action_close(self) -> None:
        self.app.pop_screen()

    def action_nickname(self) -> None:
        box = self.query_one("#nick", NickBox)
        d = self.app.devices.get(self.device_key)
        box.value = d["nick"] if d else ""
        box.display = True
        box.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "nick":
            return
        event.stop()
        self.app.set_nickname(self.device_key, event.value.strip())
        event.input.display = False
        self.set_focus(None)
        self.refresh_card()

    def action_open_web(self) -> None:
        d = self.app.devices.get(self.device_key)
        if not d:
            return
        ports = set(d["ports"])
        if 80 in ports or not ports & {443, 8080}:
            url = f"http://{d['ip']}"
        elif 443 in ports:
            url = f"https://{d['ip']}"
        else:
            url = f"http://{d['ip']}:8080"
        webbrowser.open(url)
        self.app.notify(f"Opening {url}")

    def action_copy_ip(self) -> None:
        self.app.copy_ip(self.device_key)


class CreditsScreen(ModalScreen):
    DEFAULT_CSS = """
    CreditsScreen { align: center middle; }
    #credits {
        width: 64; max-width: 96%; height: auto;
        border: thick $accent; background: $surface; padding: 1 3;
    }
    """
    BINDINGS = [Binding("escape", "close", "Back"), Binding("a", "close", "Back", show=False)]

    def compose(self) -> ComposeResult:
        yield Static(
            f"[b]deepscan[/b] [dim]v{VERSION}[/]\n"
            "See every device on your network by name.\n\n"
            f"[b]Idea, design calls and testing[/b]\n  {escape(AUTHOR)}\n\n"
            "[b]Code[/b]\n  Claude, by Anthropic\n\n"
            "[b]Built with[/b]\n"
            "  Textual and Rich, by Textualize\n"
            "  Manufacturer data from the IEEE registry (Wireshark as backup)\n\n"
            "[dim]For networks you own or have permission to scan.\n"
            "Press esc to go back.[/]",
            id="credits",
        )

    def on_mount(self) -> None:
        self.query_one("#credits").border_title = "Credits"

    def action_close(self) -> None:
        self.app.pop_screen()


# --------------------------------------------------------------------------- #
#  The app
# --------------------------------------------------------------------------- #
class DeepScan(App):
    TITLE = "deepscan"
    CSS = """
    #stats { height: 1; padding: 0 1; background: $boost; }
    #body { height: 1fr; }
    #sidebar { width: 26; border: round $primary; }
    #sidebar > ListItem { padding: 0 1; }
    #main { width: 1fr; }
    #search { border: none; height: 1; padding: 0 1; background: $boost; }
    #search:focus { background: $accent 20%; }
    #table { height: 1fr; }
    #bottom { height: 11; }
    #details { width: 1fr; border: round $accent; padding: 0 1; }
    #livebox { width: 36; border: round $accent; padding: 0 1; }
    #live-text { height: 2; }
    #spark { height: 1fr; }
    #statusbar { height: 1; }
    #status { width: 1fr; padding: 0 1; color: $text-muted; }
    #progress { width: 34; }
    """
    BINDINGS = [
        Binding("r", "rescan", "Rescan"),
        Binding("slash", "focus_search", "Search"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("b", "toggle_sidebar", "Sidebar"),
        Binding("t", "cycle_theme", "Theme"),
        Binding("e", "export", "Export"),
        Binding("a", "credits", "Credits"),
        Binding("c", "copy_selected", "Copy IP", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, network):
        super().__init__()
        self.network = network
        self.devices = {}
        self.vendors = None
        self.gateway = ""
        self.cat_filter = "all"
        self.search_text = ""
        self.sort_by = "ip"
        self.visible_keys = []
        self.selected_key = None
        self._ds_live_busy = False

    # ---- layout ----
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="stats")
        with Horizontal(id="body"):
            yield ListView(*[ListItem(Label(label), id=f"cat-{key}") for key, label in CATEGORIES],
                           id="sidebar")
            with Vertical(id="main"):
                yield SearchBox(placeholder="/  Search by name, IP, vendor, type or port", id="search")
                yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
                with Horizontal(id="bottom"):
                    yield Static("Pick a device to see its details.", id="details")
                    with Vertical(id="livebox"):
                        yield Static("", id="live-text")
                        yield Sparkline([0], summary_function=max, id="spark")
        with Horizontal(id="statusbar"):
            yield Static("", id="status")
            yield ProgressBar(total=100, show_eta=False, id="progress")
        yield Footer()

    def on_mount(self) -> None:
        theme = load_settings().get("theme")
        if theme:
            try:
                self.theme = theme
            except Exception:
                pass
        t = self.query_one("#table", DataTable)
        for key, label, width in (("new", "", 1), ("ip", "IP", 15), ("name", "Name", 24),
                                  ("type", "Type", 22), ("vendor", "Vendor", 14),
                                  ("ping", "Ping", 7)):
            t.add_column(label, key=key, width=width)
        self.query_one("#sidebar").border_title = "Show"
        self.query_one("#details").border_title = "Device"
        self.query_one("#livebox").border_title = "Live ping"
        self.sub_title = str(self.network)
        if self.size.width < 100:
            self.query_one("#sidebar").display = False
        t.focus()
        self.set_interval(1.0, self._ds_live_tick)
        self.scan()

    # ---- filtering, sorting, drawing ----
    def _ds_matches(self, d: dict) -> bool:
        c = self.cat_filter
        if c == "new" and not d["new"]:
            return False
        if c == "offline" and d["online"]:
            return False
        if c not in ("all", "new", "offline") and (not d["online"] or category(d) != c):
            return False
        if self.search_text:
            hay = " ".join([d["ip"], d["mac"], d["nick"], d["vendor_full"], guess_type(d),
                            " ".join(d["names"].values()),
                            " ".join(f"{p} {PORTS[p]}" for p in d["ports"])]).lower()
            return all(word in hay for word in self.search_text.lower().split())
        return True

    def _ds_sort_key(self, d: dict):
        offline_last = not d["online"]
        ip = ipaddress.ip_address(d["ip"])
        if self.sort_by == "name":
            name = display_name(d)
            return (offline_last, name.startswith(("(", "…")), name.lower(), ip)
        if self.sort_by == "type":
            return (offline_last, guess_type(d).startswith("?"), guess_type(d), ip)
        if self.sort_by == "ping":
            return (offline_last, d["ping_ms"] is None, d["ping_ms"] or 0, ip)
        return (offline_last, ip)

    def _ds_cells(self, d: dict) -> list:
        dim = "" if d["online"] else "dim"
        if not d["online"]:
            ping_cell = Text("offline", style="dim")
        elif d["ping_ms"] is not None:
            ms = d["ping_ms"]
            ping_cell = Text("<1 ms" if ms < 1 else f"{ms:.0f} ms", style=ping_style(ms))
        else:
            ping_cell = Text("ok" if d["ttl"] else "-", style="dim")
        return [
            Text("★", style="bold yellow") if d["new"] else Text(""),
            Text(d["ip"], style=dim),
            Text(display_name(d), style=dim or ("bold" if d["nick"] else "")),
            Text(guess_type(d), style=dim),
            Text(d["vendor"] or "-", style=dim),
            ping_cell,
        ]

    def _ds_rebuild_table(self) -> None:
        t = self.query_one("#table", DataTable)
        keep = self.selected_key
        t.clear()
        rows = sorted((d for d in self.devices.values() if self._ds_matches(d)), key=self._ds_sort_key)
        self.visible_keys = [d["key"] for d in rows]
        for d in rows:
            t.add_row(*self._ds_cells(d), key=d["key"])
        if keep in self.visible_keys:
            t.move_cursor(row=self.visible_keys.index(keep))
        if not rows:
            self.query_one("#details", Static).update(
                "[dim]Nothing matches. Clear the search or pick another group on the left.[/]"
                if self.devices else "[dim]Scanning…[/]")
        self._ds_refresh_counts()

    def _ds_refresh_counts(self) -> None:
        counts = {key: 0 for key, _ in CATEGORIES}
        for d in self.devices.values():
            counts["all"] += 1
            if d["new"]:
                counts["new"] += 1
            if d["online"]:
                counts[category(d)] += 1
            else:
                counts["offline"] += 1
        for key, label in CATEGORIES:
            try:
                self.query_one(f"#cat-{key} Label", Label).update(f"{label}  [dim]{counts[key]}[/]")
            except Exception:
                pass

        online = [d for d in self.devices.values() if d["online"]]
        pings = [d["ping_ms"] for d in online if d["ping_ms"] is not None]
        parts = [f"[b]{len(online)}[/b] online"]
        if counts["new"]:
            parts.append(f"[b yellow]★ {counts['new']} new[/]")
        if counts["offline"]:
            parts.append(f"[dim]{counts['offline']} offline[/]")
        if pings:
            parts.append(f"average ping [b]{sum(pings) / len(pings):.0f} ms[/b]")
        if self.gateway:
            parts.append(f"router [b]{self.gateway}[/b]")
        parts.append(f"sorted by [b]{self.sort_by}[/b]")
        self.query_one("#stats", Static).update("    ".join(parts))

    def _ds_show_selected(self) -> None:
        d = self.devices.get(self.selected_key)
        if not d:
            return
        self.query_one("#details", Static).update(describe(d))
        self._ds_refresh_live()

    def _ds_refresh_live(self) -> None:
        d = self.devices.get(self.selected_key)
        if not d:
            return
        self.query_one("#live-text", Static).update(live_summary(d))
        self.query_one("#spark", Sparkline).data = spark_data(d)

    # ---- events ----
    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None and event.row_key.value != self.selected_key:
            self.selected_key = event.row_key.value
            self._ds_show_selected()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is not None:
            self.push_screen(DeviceScreen(event.row_key.value))

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item is not None and event.item.id:
            new = event.item.id[4:]
            if new != self.cat_filter:
                self.cat_filter = new
                self._ds_rebuild_table()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.query_one("#table", DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            self.search_text = event.value.strip()
            self._ds_rebuild_table()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search":
            self.query_one("#table", DataTable).focus()

    # ---- actions ----
    def action_rescan(self) -> None:
        self.scan()

    def action_focus_search(self) -> None:
        if not isinstance(self.screen, ModalScreen):
            self.query_one("#search", Input).focus()

    def action_cycle_sort(self) -> None:
        self.sort_by = SORTS[(SORTS.index(self.sort_by) + 1) % len(SORTS)]
        self._ds_rebuild_table()

    def action_toggle_sidebar(self) -> None:
        bar = self.query_one("#sidebar")
        bar.display = not bar.display

    def action_cycle_theme(self) -> None:
        try:
            names = sorted(self.available_themes)
            i = names.index(self.theme) if self.theme in names else -1
            self.theme = names[(i + 1) % len(names)]
            settings = load_settings()
            settings["theme"] = self.theme
            save_settings(settings)
            self.notify(f"Theme: {self.theme}", timeout=2)
        except Exception:
            self.notify("Themes need a newer Textual. Run: python3 -m pipx upgrade deepscan",
                        severity="warning")

    def action_copy_selected(self) -> None:
        if self.selected_key:
            self.copy_ip(self.selected_key)

    def copy_ip(self, key: str) -> None:
        d = self.devices.get(key)
        if d and copy_text(self, d["ip"]):
            self.notify(f"Copied {d['ip']}", timeout=2)

    def set_nickname(self, key: str, nick: str) -> None:
        d = self.devices.get(key)
        if not d:
            return
        if d["mac"] != "?":
            history = load_history()
            entry = history.setdefault(d["mac"], {"first": d["first_seen"]})
            if nick:
                entry["nick"] = nick
            else:
                entry.pop("nick", None)
            save_history(history)
        self._ds_update(key, nick=nick)
        self.notify(f"Saved nickname for {d['ip']}" if nick else "Nickname cleared", timeout=2)

    def action_export(self) -> None:
        if not self.devices:
            self.notify("Nothing to export yet.", severity="warning")
            return
        path = Path.cwd() / f"deepscan-{datetime.now():%Y%m%d-%H%M%S}.csv"
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ip", "online", "nickname", "name", "all_names", "type", "vendor", "mac",
                            "private_mac", "ping_ms", "ttl", "open_ports", "new", "first_seen",
                            "last_seen"])
                for d in sorted(self.devices.values(), key=lambda d: ipaddress.ip_address(d["ip"])):
                    w.writerow([d["ip"], d["online"], d["nick"],
                                next(iter(d["names"].values()), ""),
                                "; ".join(f"{s}={n}" for s, n in d["names"].items()),
                                guess_type(d), d["vendor_full"], d["mac"], d["private"],
                                d["ping_ms"], d["ttl"], " ".join(map(str, d["ports"])),
                                d["new"], d["first_seen"], d["last_seen"]])
            self.notify(f"Saved {path}", timeout=5)
        except OSError as e:
            self.notify(f"Couldn't save the file: {e}", severity="error")

    def action_credits(self) -> None:
        if not isinstance(self.screen, ModalScreen):
            self.push_screen(CreditsScreen())

    def action_reset_history(self) -> None:
        try:
            HISTORY_FILE.unlink()
        except OSError:
            pass
        self.notify("Device history cleared. The next scan starts fresh.")

    if SystemCommand is not None:
        def get_system_commands(self, screen):
            yield from super().get_system_commands(screen)
            yield SystemCommand("Rescan network", "Run a fresh scan", self.action_rescan)
            yield SystemCommand("Export to CSV", "Save every device to a spreadsheet file",
                                self.action_export)
            yield SystemCommand("Toggle sidebar", "Show or hide the groups on the left",
                                self.action_toggle_sidebar)
            yield SystemCommand("Next theme", "Switch to the next color theme",
                                self.action_cycle_theme)
            yield SystemCommand("Credits", "Who made deepscan", self.action_credits)
            yield SystemCommand("Reset device history",
                                "Forget every device seen before (also clears nicknames)",
                                self.action_reset_history)

    # ---- updates coming from the scan ----
    def _ds_update(self, key: str, **fields) -> None:
        d = self.devices.get(key)
        if not d:
            return
        d.update(fields)
        t = self.query_one("#table", DataTable)
        shown, match = key in self.visible_keys, self._ds_matches(d)
        if shown and match:
            for col, val in zip(("new", "ip", "name", "type", "vendor", "ping"), self._ds_cells(d)):
                t.update_cell(key, col, val)
            self._ds_refresh_counts()
        elif shown or match:
            self._ds_rebuild_table()
        else:
            self._ds_refresh_counts()
        if key == self.selected_key:
            self._ds_show_selected()

    def _ds_set_devices(self, devices: list, gateway: str) -> None:
        old = self.devices
        self.devices = {}
        for d in devices:
            prev = old.get(d["key"])
            d["live"] = prev["live"] if prev else deque(maxlen=60)
            self.devices[d["key"]] = d
        self.gateway = gateway
        self._ds_rebuild_table()
        self._ds_show_selected()

    def _ds_status(self, msg: str) -> None:
        self.query_one("#status", Static).update(msg)

    def _ds_progress(self, msg: str, done: int, total: int) -> None:
        self._ds_status(msg)
        bar = self.query_one("#progress", ProgressBar)
        bar.display = True
        bar.update(total=max(total, 1), progress=done)

    def _ds_scan_done(self, online: int, new: int) -> None:
        self.query_one("#progress", ProgressBar).display = False
        self._ds_rebuild_table()
        extra = f", {new} new" if new else ""
        self._ds_status(f"Scan finished: {online} online{extra}.   enter opens a device   / searches")
        self.notify(f"Found {online} devices{extra}", timeout=3)

    # ---- live ping for the selected device ----
    def _ds_live_key(self):
        if isinstance(self.screen, DeviceScreen):
            return self.screen.device_key
        return self.selected_key

    def _ds_live_tick(self) -> None:
        key = self._ds_live_key()
        d = self.devices.get(key)
        if d and d["online"] and not self._ds_live_busy:
            self._ds_live_busy = True
            self._ds_live_ping(key, d["ip"])

    @work(thread=True, group="live")
    def _ds_live_ping(self, key: str, ip: str) -> None:
        result = ping(ip)
        try:
            self.call_from_thread(self._ds_live_result, key, result)
        except Exception:
            pass

    def _ds_live_result(self, key: str, result) -> None:
        self._ds_live_busy = False
        d = self.devices.get(key)
        if not d:
            return
        if result is None:
            d["live"].append(None)
        else:
            ms, ttl = result
            d["live"].append(ms if ms is not None else 0.5)
            if d["ttl"] is None:
                d["ttl"] = ttl
        if key == self.selected_key:
            self._ds_refresh_live()

    # ---- the scan itself (background thread) ----
    @work(thread=True, exclusive=True, group="scan")
    def scan(self) -> None:
        worker = get_current_worker()

        def ui(fn, *a, **k):
            if not worker.is_cancelled:
                self.call_from_thread(fn, *a, **k)

        try:
            net = self.network
            hosts = [str(h) for h in net.hosts()]

            vendor_pool = ThreadPoolExecutor(max_workers=1)
            vendor_job = vendor_pool.submit(load_vendors) if self.vendors is None else None

            # 1) ping everything (also fills the ARP table)
            pings = {}
            with ThreadPoolExecutor(max_workers=64) as ex:
                futs = {ex.submit(ping, h): h for h in hosts}
                for i, f in enumerate(as_completed(futs), 1):
                    if f.result():
                        pings[futs[f]] = f.result()
                    if i % 8 == 0 or i == len(hosts):
                        ui(self._ds_progress, f"Pinging {net}   {len(pings)} replied", i, len(hosts))

            if vendor_job:
                ui(self._ds_status, "Downloading the manufacturer list (only happens once)…")
                self.vendors = vendor_job.result()
            vendor_pool.shutdown()

            # 2) build the device list, including devices seen before that are gone now
            found = {ip: mac for ip, mac in read_arp().items() if ipaddress.ip_address(ip) in net}
            for ip in pings:
                found.setdefault(ip, "?")
            me = local_ip()
            if ipaddress.ip_address(me) in net:
                found[me] = local_mac()
            gateways = default_gateways()
            gateway = next((g for g in gateways if ipaddress.ip_address(g) in net), "")

            history = load_history()
            had_history = bool(history)
            now = datetime.now().strftime("%Y-%m-%d %H:%M")

            def vendor_of(mac):
                if is_randomized(mac):
                    return ""
                return self.vendors.get(mac.replace(":", "")[:6], "")

            devices, keys = [], {}
            for ip, mac in found.items():
                key = mac if mac != "?" else ip
                if key in [d["key"] for d in devices]:
                    key = f"{key}@{ip}"
                h = history.get(mac, {}) if mac != "?" else {}
                ms, ttl = pings.get(ip, (None, None))
                full = vendor_of(mac)
                devices.append({
                    "key": key, "ip": ip, "mac": mac, "online": True,
                    "names": {}, "names_done": False, "nick": h.get("nick", ""),
                    "vendor_full": full,
                    "vendor": short_vendor(full) or ("(private)" if is_randomized(mac) else ""),
                    "private": is_randomized(mac), "ping_ms": ms, "ttl": ttl,
                    "ports": [], "ports_done": False,
                    "is_me": ip == me, "is_gw": ip in gateways,
                    "new": had_history and not h and mac != "?",
                    "first_seen": h.get("first", now), "last_seen": now,
                    "times_seen": h.get("count", 0) + 1,
                })
                keys[ip] = key

            online_macs = set(found.values())
            for mac, h in history.items():
                if mac in online_macs:
                    continue
                try:
                    if ipaddress.ip_address(h.get("ip", "")) not in net:
                        continue
                except ValueError:
                    continue
                full = vendor_of(mac)
                devices.append({
                    "key": mac, "ip": h["ip"], "mac": mac, "online": False,
                    "names": {"saved": h["name"]} if h.get("name") else {}, "names_done": True,
                    "nick": h.get("nick", ""), "vendor_full": full,
                    "vendor": short_vendor(full) or ("(private)" if is_randomized(mac) else ""),
                    "private": is_randomized(mac), "ping_ms": None, "ttl": None,
                    "ports": [], "ports_done": True, "is_me": False, "is_gw": False, "new": False,
                    "first_seen": h.get("first", "?"), "last_seen": h.get("last", "?"),
                    "times_seen": h.get("count", 1),
                })
            ui(self._ds_set_devices, devices, gateway)

            # 3) names
            names_by_ip = {}
            with ThreadPoolExecutor(max_workers=32) as ex:
                futs = {ex.submit(resolve_all, ip): ip for ip in found}
                for i, f in enumerate(as_completed(futs), 1):
                    ip, names = futs[f], f.result()
                    if ip == me and not names:
                        names = {"local": socket.gethostname()}
                    names_by_ip[ip] = names
                    ui(self._ds_update, keys[ip], names=names, names_done=True)
                    ui(self._ds_progress, "Asking devices for their names", i, len(found))

            # 4) common ports
            remaining = {ip: len(PORTS) for ip in found}
            open_ports = {ip: [] for ip in found}
            total = len(found) * len(PORTS)
            with ThreadPoolExecutor(max_workers=128) as ex:
                futs = {ex.submit(port_open, ip, p): (ip, p) for ip in found for p in PORTS}
                for i, f in enumerate(as_completed(futs), 1):
                    ip, p = futs[f]
                    if f.result():
                        open_ports[ip].append(p)
                    remaining[ip] -= 1
                    if remaining[ip] == 0:
                        ui(self._ds_update, keys[ip], ports=sorted(open_ports[ip]), ports_done=True)
                    if i % 40 == 0 or i == total:
                        ui(self._ds_progress, "Checking common ports", i, total)

            # 5) remember everything (reload first so nicknames set during the scan survive)
            new_count = sum(1 for d in devices if d["online"] and d["new"])
            history = load_history()
            for ip, mac in found.items():
                if mac == "?":
                    continue
                entry = history.setdefault(mac, {"first": now})
                entry.update(last=now, ip=ip, count=entry.get("count", 0) + 1,
                             name=next(iter(names_by_ip.get(ip, {}).values()), entry.get("name", "")))
            save_history(history)

            ui(self._ds_scan_done, len(found), new_count)
        except Exception as e:
            ui(self._ds_status, f"Scan error: {e}")


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    if arg in ("-h", "--help", "help"):
        print(__doc__)
        return
    if arg in ("all", "auto"):
        net = ipaddress.ip_network(f"{local_ip()}/24", strict=False)
    else:
        try:
            net = ipaddress.ip_network(arg, strict=False)
        except ValueError:
            sys.exit(f"'{arg}' isn't a subnet. Try: deepscan all   or   deepscan 192.168.1.0/24")
    if net.num_addresses > 4096:
        sys.exit(f"{net} is too big. Pick a /20 or smaller.")
    DeepScan(net).run()


if __name__ == "__main__":
    main()