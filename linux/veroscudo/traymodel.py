"""The tray's decisions, shared by the Linux tray (tray.py, GTK) and the macOS menu-bar app (tray_macos.py, AppKit).

Same idea as windows/VeroScudo.Tray.psm1: the front ends collect facts and draw; what the icon, the title, the menu and
the notifications say is decided here, from explicit inputs, and unit-tested (tests/test_traymodel.py). The few impure
helpers at the bottom (running a command, reading the log, finding the guard) take no decisions."""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .quality import Quality, describe
from .state import kind_label

# where install.sh puts the program on both platforms: root-owned, named in the sudoers rule
PREFIX = Path("/opt/veroscudo")
BIN = PREFIX / "bin" / "veroscudo"
UNINSTALL = PREFIX / "uninstall.sh"
LOG = Path("/var/log/veroscudo.log")
LOG_GROUP = "admin" if sys.platform == "darwin" else "adm"
REPO_URL = "https://github.com/GomelHawk/VeroScudo"
EXPECT_SECONDS = 120          # "Connecting" may last this long; then the tray says plainly that it is not connected yet
STATES = ("protected", "blocked", "off", "attention")


@dataclass(frozen=True)
class Facts:
    """What the guard reports right now (collected by the front end every few seconds)."""
    configured: bool = True
    name: str = ""
    kind: str | None = None
    armed: bool = False
    up: bool = False
    guard_running: bool = True
    others: tuple[str, ...] = ()          # tunnels of other VPNs next to the active profile's
    expect: str | None = None             # what the user asked for and waits on: connect | reconnect | switch
    config_error: str = ""
    check_enabled: bool = False           # Settings > Connection is on
    quality: Quality | None = None        # the guard's last rating (quality.json), None = none yet / too old


@dataclass(frozen=True)
class View:
    state: str                            # protected | blocked | off | attention  (= the icon)
    title: str
    text: str
    armed: bool
    connected: bool


def tray_state(f: Facts) -> View:
    """State, title and text - the same wording as the Windows tray (ConvertTo-VeroTrayState). Pure."""
    if not f.configured:
        return View("attention", "Not configured",
                    f"config.json is missing or invalid{': ' + f.config_error if f.config_error else ''}. Run the installer "
                    "again, or fix /etc/veroscudo/config.json.", False, False)
    name, label = f.name, kind_label(f.kind)
    if not f.guard_running:
        return View("attention", "Guard not running",
                    "The VeroScudo service is not running, so nothing watches the VPN. Run the installer again"
                    + (" (or: sudo systemctl restart veroscudo)." if sys.platform != "darwin"
                       else " (or: sudo launchctl kickstart -k system/com.gomelhawk.veroscudo)."), f.armed, f.up)
    if not f.armed:
        return View("off", "Off", "The VPN is turned off: normal network, not protected.", False, f.up)
    if f.up:
        text = f"{name} ({label}) is connected and the kill-switch is on."
        if f.others:
            text += f" Note: another tunnel runs next to it ({', '.join(f.others)}) - its traffic is blocked."
        return View("protected", "Protected", text, True, True)
    title, text = {
        "connect": ("Connecting", f"Kill-switch on: traffic is blocked until {name} is connected."),
        "switch": ("Switching", f"Switching to {name}. Traffic stays blocked until it is connected."),
        "reconnect": ("Reconnecting", f"Reconnecting {name}. Traffic stays blocked until the tunnel is back."),
    }.get(f.expect or "", ("Blocked - reconnecting", f"{name} is not connected. Nothing leaves this computer until it is back."))
    return View("blocked", title, text, True, False)


def quality_word(f: Facts, v: View) -> str | None:
    """'Good' / 'Unstable' / 'Bad' while protected and rated, else None - for the tooltip and the menu header. Pure."""
    if v.state != "protected" or not f.check_enabled or f.quality is None or f.quality.state == "checking":
        return None
    return f.quality.state.capitalize()


def tooltip(v: View, awake: bool = False, f: Facts | None = None) -> str:
    """'VeroScudo - Protected, connection good' - the same text as the Windows tray. Pure."""
    word = quality_word(f, v) if f else None
    return f"VeroScudo - {v.title}" + (f", connection {word.lower()}" if word else "") + (", keeping awake" if awake else "")


def menu_head(v: View, f: Facts | None = None) -> str:
    """The disabled first line of the menu: 'VeroScudo - Protected - Unstable'. Pure."""
    word = quality_word(f, v) if f else None
    return f"VeroScudo - {v.title}" + (f" - {word}" if word else "")


def connection_text(f: Facts, v: View) -> str:
    """The status window's Connection row (Windows: the CONNECTION card): the quality while protected, else what the
    guard does about the connection - the two never matter at the same time. Pure."""
    if not f.configured or (v.state == "attention" and not v.armed):
        return "-"
    if v.state == "blocked" or (v.armed and not v.connected):
        return {"connect": "connecting", "switch": "switching", "reconnect": "reconnecting"}.get(f.expect or "", "redialing")
    if v.state == "off" or not v.armed:
        return "connected (VPN off)" if v.connected else "-"
    if not f.check_enabled:
        return "connected (check off)"
    return describe(f.quality) if f.quality else "checking…"


@dataclass(frozen=True)
class MenuState:
    on: bool
    off: bool
    reconnect: bool


def menu_state(v: View) -> MenuState:
    """Turn on: whenever not protected. Turn off: armed or a tunnel is up. Reconnect: armed. Pure (as on Windows)."""
    return MenuState(on=v.state != "protected", off=v.armed or v.connected, reconnect=v.armed)


def transition_notice(last: str | None, v: View, expect: str | None, name: str) -> tuple[str, str, str] | None:
    """The notification for a state change: (title, body, urgency 'normal'|'critical'), or None. The first look (last None)
    and an unchanged state say nothing; a switch or a Reconnect the user started already said what happens. Pure."""
    if last is None or last == v.state:
        return None
    if v.state == "blocked":
        if expect == "connect":
            return ("VeroScudo on - connecting", f"Kill-switch on: traffic is blocked until '{name}' is connected.", "normal")
        if expect in ("switch", "reconnect"):
            return None
        return ("VPN connection lost - traffic blocked", "Reconnecting... nothing leaves this computer until the tunnel is back.",
                "critical")
    if v.state == "protected":
        return ("VPN protected", "Tunnel up, kill-switch on.", "normal")
    if v.state == "off":
        return ("VPN turned off", "Firewall back to normal - traffic is NOT protected.", "normal")
    return ("VeroScudo needs attention", v.text, "critical")


@dataclass
class Expect:
    """What the user asked for and is waiting on (connect / reconnect / switch), so "blocked" reads as "Connecting" and the
    drop notice is not shown for a drop the user caused. Cleared once protected, when turned off, or after
    EXPECT_SECONDS - then `expired` says so once (the tray tells the user plainly that it is still not connected)."""
    kind: str | None = None
    since: float = 0.0

    def start(self, kind: str, now: float | None = None) -> None:
        self.kind, self.since = kind, time.time() if now is None else now

    def update(self, v: View, now: float | None = None) -> bool:
        """Returns True once when the wait ran out while still blocked."""
        if self.kind is None:
            return False
        now = time.time() if now is None else now
        age = now - self.since
        if v.state == "protected" or (not v.armed and age > 20):
            self.kind = None
            return False
        if v.state == "blocked" and age > EXPECT_SECONDS:
            self.kind = None
            return True
        return False


def expired_notice(name: str) -> tuple[str, str, str]:
    return ("VPN not connected yet - traffic blocked",
            f"'{name}' did not connect within 2 minutes. VeroScudo keeps trying; nothing leaves this computer meanwhile.",
            "critical")


def status_rows(f: Facts, v: View, awake: bool, tunnel: str | None) -> list[tuple[str, str]]:
    """The status window's table (and the Copy report). Pure."""
    return [
        ("VPN profile", f"{f.name} ({kind_label(f.kind)})" if f.configured else "-"),
        ("State", v.title),
        ("Tunnel", tunnel or ("connected" if v.connected else "-")),
        ("Firewall", "kill-switch ON" if v.armed else "normal"),
        ("Connection", connection_text(f, v)),
        ("Guard", "running" if f.guard_running else "NOT running"),
        ("Keep awake", "on" if awake else "off"),
    ] + ([("Other VPNs", ", ".join(f.others))] if f.others else [])


# ---------------------------------------------------------------- commands the tray runs
def action_argv(action: str, arg: str | None = None, bin_path: Path = BIN) -> list[str]:
    """on / off / reconnect / use <profile>: passwordless through the sudoers rule install.sh writes, by the full path that
    rule names (sudo -n: never a password prompt nobody can see - a missing rule is reported instead)."""
    if action not in ("on", "off", "reconnect", "use"):
        raise ValueError(f"not a tray action: {action}")
    return ["sudo", "-n", str(bin_path), action] + ([arg] if arg is not None else [])


ADMIN_ACTIONS = {"import", "remove", "default", "set"}


def admin_argv(args: list[str], platform: str = sys.platform, bin_path: Path = BIN) -> list[str]:
    """A change to config.json or the uninstall: asks for an administrator's password first - pkexec on Linux, the macOS
    password dialog through osascript - like the UAC prompt of the Windows tray's Save. Arguments are passed as data,
    never spliced into a command string."""
    if args and args[0] == "uninstall":
        cmd = [str(UNINSTALL)]
    else:
        if not args or args[0] not in ADMIN_ACTIONS:
            raise ValueError(f"not an administrator action: {args[:1]}")
        cmd = [str(bin_path), *args]
    if platform == "darwin":
        script = ['on run argv', 'set cmd to ""',
                  'repeat with a in argv', 'set cmd to cmd & quoted form of (a as text) & " "', 'end repeat',
                  'do shell script cmd with administrator privileges', 'end run']
        return ["osascript"] + [x for line in script for x in ("-e", line)] + cmd
    return ["pkexec", *cmd]


def cancelled(returncode: int, stderr: str, platform: str = sys.platform) -> bool:
    """The user dismissed the password dialog (not an error worth a message). pkexec: 126; osascript: -128."""
    if platform == "darwin":
        return "-128" in stderr or "User canceled" in stderr
    return returncode == 126


def explain_failure(argv: list[str], returncode: int, stderr: str) -> str:
    """One line for a failed tray command."""
    lines = [ln for ln in (stderr or "").strip().splitlines() if ln.strip()]
    if argv[:2] == ["sudo", "-n"] and any("password is required" in ln or "not allowed" in ln for ln in lines):
        return "VeroScudo's sudo rule is missing or outdated - run the installer again."
    last = lines[-1] if lines else f"exit code {returncode}"
    return last.removeprefix("veroscudo: ")


class Runner:
    """Runs tray commands off the GUI thread; the front end drains `done` from its timer (GTK and AppKit both). Each result:
    (tag, argv, returncode, stdout, stderr)."""

    def __init__(self) -> None:
        self.done: queue.Queue = queue.Queue()

    def start(self, tag: str, argv: list[str]) -> None:
        def run() -> None:
            try:
                r = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=600)
                self.done.put((tag, argv, r.returncode, r.stdout, r.stderr))
            except (OSError, subprocess.SubprocessError) as e:
                self.done.put((tag, argv, 127, "", str(e)))
        threading.Thread(target=run, daemon=True).start()

    def results(self) -> list[tuple]:
        out = []
        while True:
            try:
                out.append(self.done.get_nowait())
            except queue.Empty:
                return out


# ---------------------------------------------------------------- facts the tray reads
def guard_running(pgrep: str | None = None) -> bool:
    """The root daemon (`veroscudo daemon`) is alive. Any user may see it in the process list."""
    exe = pgrep or shutil.which("pgrep") or "/usr/bin/pgrep"
    try:
        r = subprocess.run([exe, "-f", "bin/veroscudo daemon"], check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return True                       # cannot tell: do not cry wolf
    return r.returncode == 0


def read_events(path: Path = LOG, n: int = 15) -> list[str] | None:
    """The newest log lines, or None when this user may not read the log (it is root:adm / root:admin, 0640)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [ln.rstrip("\n") for ln in deque(fh, maxlen=n)]
    except FileNotFoundError:
        return []
    except OSError:
        return None


def log_hint() -> str:
    if sys.platform == "darwin":
        return f"The log ({LOG}) is readable by administrators only."
    return f"The log ({LOG}) is readable by members of the '{LOG_GROUP}' group: sudo usermod -aG {LOG_GROUP} $USER, then sign in again."


def config_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


@dataclass
class UpdateInfo:
    checked: float = 0.0
    notified: str = ""


def update_notice(info: UpdateInfo, tag: str | None, newer: bool) -> tuple[str, bool]:
    """(menu text, show a notification) for the latest release - the notification once per tag. Pure."""
    info.checked = time.time()
    if tag and newer:
        show = info.notified != tag
        info.notified = tag
        return f"Update available: {tag}…", show
    return "Check for updates", False


def env_icons(default: Path) -> Path:
    """Icons folder; VEROSCUDO_ICONS points a development run (preview) at the repo's assets."""
    return Path(os.environ.get("VEROSCUDO_ICONS") or default)
