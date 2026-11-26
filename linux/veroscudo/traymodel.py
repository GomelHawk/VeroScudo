"""The tray's decisions, shared by the Linux tray (tray.py, GTK) and the macOS menu-bar app (tray_macos.py, AppKit).

Same idea as windows/VeroScudo.Tray.psm1: the front ends collect facts and draw; what the icon, the title, the menu and
the notifications say is decided here, from explicit inputs, and unit-tested (tests/test_traymodel.py). The few impure
helpers below them (running a command, reading the log, finding the guard) take no decisions.

TrayController (at the end) is what both trays do with those decisions: it reads the facts, follows the state
from look to look, sends the notices and runs the commands. It draws nothing - the front end gives it the hooks
listed in its docstring. Nothing here imports GTK or AppKit."""
from __future__ import annotations

import json
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

from . import __version__, exitinfo, hiddify, keepawake, quality, stats, statuspage, update
from .config import Config, config_path, is_host
from .quality import CheckConfig, Quality, describe
from .state import LOG as _LOG
from .state import LOG_GROUP, StateStore, is_up, kind_label
from .state import switch_notice as profile_switch_text

# where install.sh puts the program on both platforms: root-owned, named in the sudoers rule
PREFIX = Path("/opt/veroscudo")
BIN = PREFIX / "bin" / "veroscudo"
UNINSTALL = PREFIX / "uninstall.sh"
LOG = Path(_LOG)                 # the guard's log; readable by root and LOG_GROUP

# Settings > Behaviour descriptions - the same wording as the Windows tray, with this platform's examples
VM_ABOUT = (("Parallels, VMware Fusion and UTM VMs" if sys.platform == "darwin" else "Docker, libvirt and other VMs")
            + " follow the kill-switch too. Off: VeroScudo leaves them alone. Never covered: a VM in bridged mode - it goes"
              " to the network directly, past VeroScudo.")
UPDATE_ABOUT = "Asks GitHub for the latest version, never while blocked. Nothing is installed automatically."
EXIT_ABOUT = "Shows the country and IP your traffic leaves from (asks ipinfo.io after each connect)."
BEHAVIOUR_NOTE = ("The exit location switch is saved at once (your account only). Each other change asks for an "
                  "administrator's password and takes effect within 15 seconds.")
CHECK_HTTPS_HINT = ("HTTPS checks the real way to a web service (any answer counts) - e.g. api.anthropic.com. No account or "
                    "key is used.")
REPO_URL = "https://github.com/GomelHawk/VeroScudo"
COPYRIGHT = "Copyright © 2026 Dmitry Koshelenko"
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
    auth: str | None = None               # 'missing' / 'rejected': the VPN refused the password, redial paused


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
    if f.auth == "missing":
        return View("attention", "Password missing",
                    f"No password stored for '{name}', so VeroScudo cannot redial it by itself. Store it in the system's VPN "
                    "settings, then Reconnect - traffic stays blocked meanwhile.", f.armed, f.up)
    if f.auth == "rejected":
        return View("attention", "Password rejected",
                    f"The VPN server rejected the password for '{name}'. Store the right one in the system's VPN settings, "
                    "then Reconnect - traffic stays blocked meanwhile.", f.armed, f.up)
    if not f.armed:
        return View("off", "Off", "The VPN is turned off: normal network, not protected.", False, f.up)
    if f.up:
        text = f"{name} ({label}) is connected and the kill-switch is on."
        if f.others:                     # you ARE protected - the note is about something else: amber, like Windows
            text += f" Note: another tunnel runs next to it ({', '.join(f.others)}) - its traffic is blocked."
            return View("attention", "Protected", text, True, True)
        return View("protected", "Protected", text, True, True)
    if f.kind == "hiddify" and f.expect != "switch":     # VeroScudo never dials Hiddify: it waits for you (as Windows)
        return View("blocked", "Blocked - waiting for Hiddify",
                    "Hiddify is not connected. Nothing leaves this computer until you connect it in Hiddify (or turn VeroScudo "
                    "off).", True, False)
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
    """'VeroScudo - Protected, connection good, keeping PC awake' - the same text as the Windows tray (Get-VeroTrayTip).
    Pure."""
    word = quality_word(f, v) if f else None
    t = f"VeroScudo - {v.title}" + (f", connection {word.lower()}" if word else "") + (", keeping PC awake" if awake else "")
    return t[:63]                     # the Windows notification area's limit; long titles are cut the same everywhere


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
        if f.kind == "hiddify" and f.expect != "switch":
            return "waiting for Hiddify"
        return {"connect": "connecting", "switch": "switching", "reconnect": "reconnecting"}.get(f.expect or "", "redialing")
    if v.state == "off" or not v.armed:
        return "connected (VPN off)" if v.connected else "-"
    if not f.check_enabled:
        return "connected (check off)"
    return describe(f.quality) if f.quality else "checking…"


@dataclass(frozen=True)
class ConnView:
    text: str
    tone: str                             # good | warn | bad | normal
    word: str | None                      # Good | Unstable | Bad while protected and rated
    tip: str


def connection_view(f: Facts, v: View, chk: CheckConfig | None = None) -> ConnView:
    """The status window's CONNECTION line: text, colour and tooltip - ConvertTo-VeroConnectionView of the Windows tray.
    Tone: warn while (re)connecting, the rating's colour while protected and rated, else normal. Pure."""
    text, tone, tip = connection_text(f, v), "normal", ""
    if text == "-" or not v.armed:
        return ConnView(text, tone, None, tip)
    if v.state == "blocked" or not v.connected:
        return ConnView(text, "warn", None, tip)
    if not f.check_enabled:
        return ConnView(text, tone, None, tip)
    q = f.quality
    if q is not None and q.state != "checking":
        tone = {"good": "good", "unstable": "warn"}.get(q.state, "bad")
        window = chk.window_minutes if chk else "?"
        tip = (f"{q.checks} checks in the last {window} min: {q.lost} lost ({q.loss_pct:g}%)"
               + (f", {q.slow} slow - over 1 s ({q.slow_pct():g}%)" if q.slow else "")
               + (f", median {q.rtt_ms} ms" if q.rtt_ms is not None else ""))
    if q is not None and q.checks > 0 and q.targets:                  # which address loses the checks
        tip = "\n".join(x for x in (tip, *(f"{label}: {lost} of {checks} lost" for label, checks, lost in q.targets)) if x)
    if chk:
        tip = "\n".join(x for x in (tip, f"Every {chk.interval_seconds} s: " + ", ".join(t.label() for t in chk.targets)) if x)
    return ConnView(text, tone, quality_word(f, v), tip)


def title_tone(f: Facts, v: View) -> str:
    """The status window's title colour (Windows: green protected, red blocked, amber attention or a wait the user started).
    Pure."""
    if v.state == "blocked" and f.expect:
        return "warn"
    return {"protected": "good", "blocked": "bad", "attention": "warn"}.get(v.state, "normal")


def firewall_tone(f: Facts, v: View) -> str:
    """'kill-switch ON' in red while blocked, amber while a connect the user started is under way. Pure."""
    if v.armed and not v.connected:
        return "warn" if f.expect else "bad"
    return "normal"


# the Windows tray's colours; on a light window the amber and green are darker so that they stay readable
TONE_COLOURS = {"good": ("#30c84f", "#1a7f37"), "warn": ("#fcbb2d", "#9d5d00"), "bad": ("#f85046", "#c62828")}


def tone_colour(tone: str, dark: bool) -> str | None:
    """'#rrggbb' for a tone on a dark or a light window; None = the theme's normal text colour. Pure."""
    c = TONE_COLOURS.get(tone)
    return (c[0] if dark else c[1]) if c else None


@dataclass(frozen=True)
class MenuState:
    on: bool
    off: bool
    reconnect: bool


RECONNECT_HIDDIFY = hiddify.RECONNECT_HINT     # the tooltip of the disabled Reconnect


def offers_off(v: View, kind: str | None = None) -> bool:
    """Turn off is offered while armed, or while a tunnel is up that Off would hang up - never Hiddify's: VeroScudo does not
    disconnect it, so with VeroScudo off and Hiddify connected the button says Turn VPN on (not Turn VPN off,
    which would do nothing). Pure (as on Windows)."""
    return v.armed or (v.connected and kind != "hiddify")


def menu_state(v: View, kind: str | None = None) -> MenuState:
    """Turn on: whenever not protected. Turn off: offers_off. Reconnect: armed - never for a Hiddify profile (VeroScudo does
    not start or stop Hiddify: RECONNECT_HIDDIFY). Pure (as on Windows)."""
    return MenuState(on=v.state != "protected", off=offers_off(v, kind), reconnect=v.armed and kind != "hiddify")


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
        if v.title == "Blocked - waiting for Hiddify":                  # VeroScudo never reconnects Hiddify: say who does
            return ("VPN connection lost - traffic blocked", v.text, "critical")
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


def turned_on_elsewhere(last: str | None, v: View, expect: str | None) -> bool:
    """Off -> blocked without a wait the tray started: turned on by `sudo veroscudo on` or a shortcut - call it
    "Connecting" too, not "connection lost" (the Windows tray does the same). Pure."""
    return last == "off" and v.state == "blocked" and expect is None


def expired_notice(name: str) -> tuple[str, str, str]:
    return ("VPN not connected yet - traffic blocked",
            f"'{name}' did not connect within 2 minutes. VeroScudo keeps trying; nothing leaves this computer meanwhile.",
            "critical")


def status_rows(f: Facts, v: View, awake: bool, tunnel: str | None, last_drop: str | None = None,
                foreign: tuple | list | None = None, exit_line: str | None = None,
                service: str | None = None) -> list[tuple[str, str]]:
    """The status window's table (and the Copy report). `last_drop`: last_drop_text's line (shown when given);
    `foreign`: other VPNs as foreign_list found them (else the names in f.others); `exit_line`: the exit location for the
    Copy report (exitinfo.report_line); `service`: the status page's line (statuspage.service_view), when it is on. Pure."""
    rows = [
        ("VPN profile", f"{f.name} ({kind_label(f.kind)})" if f.configured else "-"),
        ("State", v.title),
        ("Tunnel", tunnel or ("connected" if v.connected else "-")),
        ("Firewall", "kill-switch ON" if v.armed else "normal"),
    ]
    if last_drop is not None:
        rows.append(("Last drop", last_drop))
    rows += [
        ("Connection", connection_text(f, v)),
        ("Guard", "running" if f.guard_running else "NOT running"),
        ("Keep awake", "on" if awake else "off"),
    ]
    other = foreign_text(foreign) if foreign is not None else ", ".join(f.others)
    if other:
        rows.append(("Other VPNs", other))
    if exit_line is not None:
        rows.append(("Exit", exit_line))
    if service is not None:
        rows.append(("Service", service))
    return rows


# ---------------------------------------------------------------- status window details
def last_drop_text(rec: dict | None, profile: str, now: float | None = None) -> str:
    """'14:05 - connection lost' (date added when it was not today) for the active profile's newest drop, else '-'. Pure
    (apart from the local time zone)."""
    if not isinstance(rec, dict) or rec.get("profile") != profile:
        return "-"
    try:
        t = time.localtime(float(rec.get("time", 0)))
    except (TypeError, ValueError, OverflowError, OSError):
        return "-"
    today = time.localtime(time.time() if now is None else now)
    when = time.strftime("%H:%M" if t[:3] == today[:3] else "%d %b %H:%M", t)
    why = str(rec.get("why") or "")
    return f"{when} - {why}" if why else when


def filter_events(lines: list[str], after: str = "") -> list[str]:
    """The Recent events view: the lines written after `after` ('YYYY-MM-DD HH:MM:SS', the Clear link's time), without
    the date and the milliseconds (the window is narrow; Copy report keeps them). Pure."""
    out = []
    for ln in lines:
        if after and ln[:19] <= after:
            continue
        if len(ln) > 19 and ln[4] == "-" and ln[7] == "-" and ln[10] == " ":
            ln = ln[11:19] + (ln[23:] if ln[19:20] == "," and ln[20:23].isdigit() else ln[19:])
        out.append(ln)
    return out


def clear_stamp(now: float | None = None) -> str:
    """The time the Clear link saves (eventsClearedAt), in the log's own format."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() if now is None else now))


# ---------------------------------------------------------------- other VPNs (Windows: Get-VeroForeignVpn and its notices)
HIDDIFY_OWNER = hiddify.LABEL      # nm.tunnel_owners names Hiddify's tunnel so


@dataclass(frozen=True)
class Foreign:
    name: str                             # the connection's name, or the interface when no connection owns it
    iface: str
    connection: str | None                # the NetworkManager connection (can be disconnected), None = an app's own tunnel
    configured: bool                      # one of VeroScudo's profiles (not the active one)

    @property
    def kind(self) -> str:
        return "profile" if self.configured else ("not imported" if self.connection else "app")

    @property
    def can_disconnect(self) -> bool:
        return self.connection is not None


def foreign_list(tunnels: list[str], owners: dict[str, str], own_iface: str | None, own_name: str,
                 profiles: tuple | list = ()) -> list[Foreign]:
    """Other VPNs next to the active profile: up tunnel interfaces (nm.other_tunnels) and active VPN connections
    (nm.tunnel_owners: interface -> connection), without the active profile's own. Hiddify's tunnel (owner
    "Hiddify (VPN mode)") is a VPN app's: named, never "disconnected" by VeroScudo, configured or not. Pure."""
    out, seen = [], set()
    for ifc in list(tunnels) + sorted(owners):
        if ifc in seen or (own_iface and ifc == own_iface):
            continue
        seen.add(ifc)
        conn = owners.get(ifc)
        if conn is not None and conn == own_name:
            continue
        if conn == HIDDIFY_OWNER:
            out.append(Foreign(conn, ifc, None, False))
            continue
        out.append(Foreign(conn or ifc, ifc, conn, conn in profiles if conn else False))
    return out


def foreign_text(foreign) -> str:
    """'wg-home (not imported), tun1 (VPN app)' - the status window's Other VPNs line. Pure."""
    label = {"profile": "another profile", "not imported": "not imported", "app": "VPN app"}
    return ", ".join(f"{x.name} ({label[x.kind]})" for x in foreign)


def foreign_notice(x: Foreign) -> tuple[str, str]:
    """(title, body) when another VPN connects while VeroScudo is on - the Windows tray's balloon. Pure."""
    if x.configured:
        body = (f'"{x.name}" is another VeroScudo profile and it is connected too.\nIts traffic is blocked. Switch to it in '
                "the tray menu (VPN profile), or disconnect it.")
    elif x.connection:
        body = f'"{x.name}" connected, but it is not a VeroScudo profile.\nIts traffic is blocked. Disconnect it, or import it in Settings.'
    elif x.name != x.iface:
        body = f'{x.name} ({x.iface}) is up next to VeroScudo.\nIts traffic is blocked. Disconnect it in that app.'
    else:
        body = f'A VPN app\'s tunnel ({x.iface}) is up next to VeroScudo.\nIts traffic is blocked. Disconnect it in that app.'
    return "VeroScudo - another VPN", body


def new_foreign(shown: set, now: list[Foreign]) -> tuple[list[Foreign], set]:
    """The other VPNs not yet announced, and the set to remember: once per detection - a VPN that goes away and comes back
    is announced again. Pure."""
    keys = {x.iface for x in now}
    return [x for x in now if x.iface not in shown], keys


@dataclass(frozen=True)
class Prompt:
    title: str
    text: str
    buttons: tuple[tuple[str, str, bool], ...]     # (answer, label, primary), left to right; 'cancel' is the default


def foreign_prompt(foreign: list[Foreign], profile: str) -> Prompt:
    """Before Turn on: another VPN is connected - Show-ForeignPrompt of the Windows tray. Answers: 'disconnect' (the ones
    that can be disconnected, then on), 'anyway' (on; their traffic stays blocked), 'cancel'. A VPN app's own tunnel cannot
    be ended by VeroScudo: then "Turn on anyway" is offered too (and alone if nothing can be ended). Pure."""
    can = [x for x in foreign if x.can_disconnect]
    cannot = [x for x in foreign if not x.can_disconnect]
    one = len(foreign) == 1
    names = ", ".join(f'"{x.name}"' for x in foreign)
    kind = ""
    if one and foreign[0].kind == "not imported":
        kind = " It is not a VeroScudo profile."
    elif one and foreign[0].configured:
        kind = " It is another VeroScudo profile."
    text = (f"{names} {'is' if one else 'are'} connected.{kind}\nVeroScudo will connect \"{profile}\" and block everything "
            f"else, including {'its' if one else 'their'} traffic.")
    if cannot:
        text += (f"\n\nVeroScudo cannot disconnect a VPN app's own tunnel ({', '.join(x.name for x in cannot)}) - close that "
                 "app first, or turn on anyway (its traffic stays blocked).")
    buttons = [("cancel", "Cancel", False)]
    if cannot:
        buttons.append(("anyway", "Turn on anyway", not can))
    if can:
        label = ("Disconnect what it can and turn on" if cannot else f"Disconnect {foreign[0].name} and turn on" if one
                 else "Disconnect all and turn on")
        buttons.append(("disconnect", label, True))
    return Prompt("VeroScudo - another VPN is connected", text, tuple(buttons))


# ---------------------------------------------------------------- Settings
def remove_question(name: str, platform: str = sys.platform) -> tuple[str, str]:
    """The confirmation before Settings > Remove (the Windows wording, this platform's VPN settings). Pure."""
    where = "System Settings > VPN" if platform == "darwin" else "NetworkManager (Settings > Network > VPN)"
    text = (f"Only VeroScudo forgets it - the VPN connection itself stays in {where}. You do not need to remove profiles to "
            "use another one: select it in the tray menu (VPN profile).")
    return f"Remove '{name}' from VeroScudo?", text


# ---------------------------------------------------------------- commands the tray runs
def action_argv(action: str, arg: str | None = None, bin_path: Path = BIN) -> list[str]:
    """on / off / reconnect / use <profile>: passwordless through the sudoers rule install.sh writes, by the full path that
    rule names (sudo -n: never a password prompt nobody can see - a missing rule is reported instead)."""
    if action not in ("on", "off", "reconnect", "use"):
        raise ValueError(f"not a tray action: {action}")
    return ["sudo", "-n", str(bin_path), action] + ([arg] if arg is not None else [])


ADMIN_ACTIONS = {"import", "remove", "set"}


def admin_argv(args: list[str], platform: str = sys.platform, bin_path: Path = BIN) -> list[str]:
    """A change to config.json or the uninstall: asks for an administrator's password first - pkexec on Linux, the macOS
    password dialog through osascript - like the UAC prompt of the Windows tray's Save. Arguments are passed as data,
    never spliced into a command string."""
    if args and args[0] == "uninstall":
        cmd = [str(UNINSTALL)]
    else:
        if not args or args[0] not in ADMIN_ACTIONS:
            raise ValueError(f"not an administrator action: {args[:1]}")
        cmd = [str(bin_path), args[0], "--", *args[1:]]         # a name that starts with a dash stays a name
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

    def start(self, tag: str, argv: list[str], *more: list[str]) -> None:
        """Runs argv - and then each of `more`, in order, while the previous one succeeded (Disconnect ... and turn on).
        One result: the first command that failed, else the last one."""
        def run() -> None:
            for cmd in (argv, *more):
                try:
                    # errors="replace": output that is not valid text must not end this thread without a result
                    r = subprocess.run(cmd, check=False, capture_output=True, text=True, errors="replace",
                                       timeout=600)
                    res = (tag, cmd, r.returncode, r.stdout, r.stderr)
                except (OSError, subprocess.SubprocessError) as e:
                    res = (tag, cmd, 127, "", str(e))
                if res[2] != 0:
                    break
            self.done.put(res)
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
    """The root daemon (`veroscudo daemon`) is alive. Any user may see it in the process list; only root's processes
    count, so another account's process with that text in its command line is not taken for the guard."""
    exe = pgrep or shutil.which("pgrep") or "/usr/bin/pgrep"
    try:
        r = subprocess.run([exe, "-u", "0", "-f", "bin/veroscudo daemon"], check=False, capture_output=True, text=True,
                           timeout=5)
    except (OSError, subprocess.SubprocessError):
        return True                       # cannot tell: do not cry wolf
    return r.returncode == 0


def read_events(path: Path = LOG, n: int = 40) -> list[str] | None:
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


# ---------------------------------------------------------------- Statistics window (Windows: Show-Stats in VeroScudoTray.ps1)
STATS_TITLE = "VeroScudo - Statistics"
STATS_HEADING = "Last 7 days"
STATS_NOTE = "One bar = 10 minutes. Hover a bar for its time and numbers."
STATS_LEGEND = (("good", "Good (or connected, not rated)"), ("unstable", "Unstable"), ("bad", "Bad or could not connect"),
                ("off", "Not connected"))
STATS_FOOT = ("Good: under 10 % of the checks lost; unstable: 10-50 %, or slow answers (over 1 s); bad: over 50 % lost. Ratings need Settings > Connection; "
              "without it, connected time is green.")
# the chart's geometry in points, top-down, the Windows card's: 144 bars x 4 (3 + 1 gap) = 576 wide, one row per day
STATS_GEOMETRY = {"x": 12, "top": 30, "row_h": 57, "bar_w": 4, "strip_h": 24, "label_h": 20, "width": 600, "height": 438}


def stats_hit(x: float, y: float, rows: int = 7, bars: int = 144) -> tuple[int, int] | None:
    """(row, bar) under a point of the chart (top-down coordinates), or None between the strips - the Windows tray's
    hover rule: only the strip itself and the 2 points above it count. Pure."""
    g = STATS_GEOMETRY
    row = int((y - g["top"]) // g["row_h"])
    in_row = (y - g["top"]) - row * g["row_h"]
    bar = int((x - g["x"]) // g["bar_w"])
    if 0 <= row < rows and 0 <= bar < bars and g["label_h"] <= in_row <= g["label_h"] + 2 + g["strip_h"]:
        return row, bar
    return None


def stats_grid() -> list[tuple[float, str]]:
    """The time grid: (x, label) every 3 hours, '00' ... '24'. Pure."""
    g = STATS_GEOMETRY
    return [(g["x"] + h * 18 * g["bar_w"], f"{h * 3:02d}") for h in range(9)]


def stats_colour(state: str, dark: bool) -> tuple[int, int, int] | None:
    """A bar's colour (r, g, b): green good and 'up', amber unstable, brown bad, grey off (lighter on a light window);
    None for 'future' (not drawn). Pure."""
    if state in ("good", "up"):
        return 48, 200, 79
    if state == "unstable":
        return 232, 163, 61                     # #e8a33d amber - the statistics palette (stats.py): soft amber, brown, green
    if state == "bad":
        return 154, 74, 42                      # #9a4a2a brown: bad, without the glare of a bright red
    if state == "off":
        return (70, 70, 70) if dark else (205, 205, 205)
    return None


def hex_rgb(colour: str) -> tuple[int, int, int]:
    """'#30c84f' -> (48, 200, 79). Pure."""
    c = colour.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def awake_rings(size: float) -> list[tuple[tuple[int, int, int], float, float, float]]:
    """The keep-awake badge as discs to paint in order: (rgb, centre x, centre y from the top, radius) - badge.awake_badge's
    geometry for a front end that draws vector shapes (the macOS menu bar). Pure."""
    from .badge import DARK, GREEN
    u = size / 16.0
    d = 7.0 * u
    c = size - d / 2
    border, hole = 1.4 * u, 1.4 * u + 1.6 * u
    return [(DARK, c, c, d / 2), (GREEN, c, c, d / 2 - border), (DARK, c, c, d / 2 - hole)]


# ---------------------------------------------------------------- the controller both trays share
class TrayController:
    """What the Linux and the macOS tray do, without drawing anything: reads the facts, follows the state from
    look to look (the notices), turns the VPN on and off, takes the results of the commands, checks for updates.

    `nm` is the platform's VPN backend (backend.nm). `ui` is the front end; it has these hooks, all called on the
    GUI thread (a front end that subclasses the controller is its own `ui`):

      notice(title, body, urgency="normal", state="attention")
                                  a desktop notification; `state` names the icon
      message(title, text, error=False)
                                  a modal message box
      choose_foreign(prompt)      the Prompt as a dialog; returns 'disconnect' | 'anyway' | 'cancel'
      config_reloaded()           config.json was read again (self.cfg is new) - in the 3 s pass or right after
                                  an administrator's change; the only signal that it was
      show_state()                icon, tooltip and menu from self.facts / self.view
      show_windows()              after the notices: the open windows
      update_status()             redraw the status window
      update_settings()           fill the settings window from self.cfg again (an administrator's change that
                                  was cancelled or failed: the form shows config.json as it is)
      refresh_soon()              call refresh() once more in about 1.5 s
      show_update(text)           the text of the menu's update item
      open_url(url)               open a web page in the browser
      set_clipboard(text)         put text on the clipboard

    The two platforms differ in a few places; each is a hook above or one of these arguments:
    `menu_name` - what the update notice calls the menu; `refresh_after_admin` - one more pass right after an
    administrator's change was made (else the 3 s timer shows it)."""

    @staticmethod
    def spawn(work) -> None:
        """Runs `work` off the UI thread (the update check asks GitHub: up to 10 s). Tests replace it with a direct call."""
        threading.Thread(target=work, daemon=True, name="veroscudo-tray-work").start()

    def __init__(self, nm, ui=None, store: StateStore | None = None, menu_name: str = "tray menu",
                 refresh_after_admin: bool = False) -> None:
        self.nm = nm
        self.ui = self if ui is None else ui
        self.menu_name = menu_name
        self.refresh_after_admin = refresh_after_admin
        self._update_answers: queue.Queue = queue.Queue()      # (release or None, asked by a click) from the worker
        self._update_busy = False
        self.store = store or StateStore()
        self.cfg: Config | None = None
        self.cfg_error = ""
        self._cfg_mtime = -1.0
        self._kinds: dict[str, str | None] = {}
        self.runner = Runner()
        self.expect = Expect()
        self.awake = keepawake.KeepAwake()
        self.last: str | None = None
        self.facts = Facts(configured=False)
        self.view = tray_state(self.facts)
        self.tunnel: str | None = None
        self.update_tag: str | None = None
        self.update_url = ""
        self.exit = exitinfo.ExitFetch()
        self.protected_since = 0.0
        self._was_up = False
        self.status_page = statuspage.StatusFetch()
        self.foreign: list[Foreign] = []
        self._foreign_at = 0.0
        self._foreign_shown: set = set()
        self.last_drop = "-"

    # ---- facts
    def kind(self, name: str) -> str | None:
        if name not in self._kinds:
            self._kinds[name] = self.nm.kind(name)
        return self._kinds[name]

    def discover(self) -> list[dict]:
        return self.nm.discover()

    @property
    def awake_on(self) -> bool:
        return self.awake.active

    def events(self, view: bool = False) -> list[str] | None:
        """The newest log lines; view=True: as the status window shows them (after Clear, without dates)."""
        ev = read_events()
        if view and ev is not None:
            return filter_events(ev, str(keepawake.get_pref("eventsClearedAt", "") or ""))
        return ev

    def clear_events(self) -> None:
        keepawake.set_pref("eventsClearedAt", clear_stamp())
        self.ui.update_status()

    def stats_week(self, pid: str) -> list:
        return stats.week(self.store.state, pid, window=self.cfg.check.window_minutes if self.cfg else 1)

    def stats_choices(self) -> list[tuple[str, str]]:
        cfg = self.cfg
        return stats.choices(stats.profiles_seen(self.store.state), [(p.id, p.name) for p in cfg.profiles] if cfg else [],
                             cfg.current.id if cfg else None)

    def reload_config(self) -> bool:
        """Reads config.json again when its time stamp changed; True when it did."""
        m = config_mtime(config_path())
        if m == self._cfg_mtime:
            return False
        self._cfg_mtime = m
        try:
            self.cfg, self.cfg_error = Config.load(active=self.store.active), ""
        except (OSError, ValueError, KeyError, TypeError) as e:
            self.cfg, self.cfg_error = None, str(e)
        self._kinds = {}
        self.ui.config_reloaded()
        return True

    def find_foreign(self, force: bool = False) -> list[Foreign]:
        """Other VPNs next to the active profile; asked at most every 10 s (the window refreshes every 3 s)."""
        if force or time.time() - self._foreign_at >= 10:
            self._foreign_at = time.time()
            cfg = self.cfg
            own = self.tunnel
            tunnels = self.nm.other_tunnels(own)
            try:
                owners = self.nm.tunnel_owners()
            except (OSError, subprocess.SubprocessError):
                owners = {}
            self.foreign = foreign_list(tunnels, owners, own, cfg.profile if cfg else "", cfg.names if cfg else ())
        return self.foreign

    def collect(self) -> Facts:
        cfg = self.cfg
        if cfg is None:
            self.tunnel = None                              # nothing of an earlier config is shown as if it still held
            return Facts(configured=False, config_error=self.cfg_error, guard_running=guard_running())
        active = self.store.active
        if active in cfg.names and active != cfg.profile:
            self.cfg = cfg = cfg.with_active(active)
        armed = self.store.armed
        up = is_up(self.nm, self.store, cfg.profile, armed)
        self.tunnel = (self.store.allowed_tunnel(cfg.profile) or self.nm.iface(cfg.profile)) if up else None
        foreign = self.find_foreign()
        self.last_drop = last_drop_text(self.store.last_drop(), cfg.profile)
        return Facts(name=cfg.profile, kind=self.kind(cfg.profile), armed=armed, up=up, guard_running=guard_running(),
                     others=tuple(x.name for x in foreign) if armed else (), expect=self.expect.kind,
                     check_enabled=cfg.check.enabled,
                     quality=quality.read(self.store.home / "quality.json", cfg.profile) if cfg.check.enabled else None,
                     auth=self.store.auth_failed(cfg.profile))

    # ---- the state, look by look
    def _look(self) -> View:
        self.facts = self.collect()
        self.view = tray_state(self.facts)
        return self.view

    def refresh(self) -> None:
        """One pass of the 3 s timer: the facts, the state, what follows from a change of it, the picture."""
        self.reload_config()
        v = self._look()
        if turned_on_elsewhere(self.last, v, self.expect.kind):
            self.expect.start("connect")
            v = self._look()
        if self.expect.update(v):
            self.ui.notice(*expired_notice(self.facts.name), state="blocked")
            v = self._look()
        if self.facts.up and not self._was_up:                         # a tunnel came up: older lookups are not fresh
            self.protected_since, self.exit.refused = time.time(), ""
        self._was_up = self.facts.up
        if v.state == "protected" and self.last != "protected":        # each (re)connect: once, through the new tunnel
            self.protected_since = time.time()
            self.exit.start(self.facts.name)
            self.status_page.on_connected()                            # the service status too - the same rule
        self.exit.poll()
        self.status_page.tick()
        self.ui.show_state()
        noticed = self.switch_notice() or self.foreign_notice(v)
        n = None if noticed else transition_notice(self.last, v, self.facts.expect, self.facts.name)
        if n:
            self.ui.notice(*n, state=v.state)
        self.last = v.state
        self.ui.show_windows()

    def switch_notice(self) -> bool:
        name = self.facts.name
        if self.facts.configured and keepawake.get_pref("lastProfile") != name:       # every switch, once
            keepawake.set_pref("lastProfile", name)
            n = profile_switch_text(self.facts.kind, name)
            if n:
                self.ui.notice("VeroScudo - WireGuard profile", n, state="blocked")
                return True
        return False

    def foreign_notice(self, v: View) -> bool:
        """Another VPN connected while VeroScudo is on: once per detection (it is blocked - say so, and what to do)."""
        if not v.armed:
            self._foreign_shown = set()
            return False
        new, self._foreign_shown = new_foreign(self._foreign_shown, self.foreign)
        if new:
            self.ui.notice(*foreign_notice(new[0]), "critical", state="attention")
            return True
        return False

    # ---- exit location (exitinfo.py)
    def exit_enabled(self) -> bool:
        return self.exit.enabled()

    def set_exit_enabled(self, on: bool) -> None:
        """Your own setting (tray.json): saved at once, no administrator's password."""
        keepawake.set_pref("showExit", bool(on))
        self.ui.update_status()

    def exit_view(self) -> exitinfo.ExitView:
        return exitinfo.exit_view(self.exit.info(), self.view.state, self.facts.name, self.protected_since,
                                  self.exit.checking, self.exit.failure, refused=self.exit.refused,
                                  tunnel_up=self.facts.up, kind=self.facts.kind)

    def refresh_exit(self) -> None:
        """The Refresh link: asked whenever a VPN tunnel is up - otherwise the answer would show your real address."""
        self.exit.refresh(self.facts.name, self.facts.up)
        self.ui.update_status()

    # ---- service status page (statuspage.py)
    def service_view(self) -> statuspage.ServiceView | None:
        return self.status_page.view()

    def status_page_enabled(self) -> bool:
        return self.status_page.enabled()

    def status_page_url(self) -> str:
        return self.status_page.url()

    def set_status_page(self, on: bool) -> None:
        """Your own setting (tray.json): saved at once, no administrator's password."""
        self.status_page.set_enabled(on)
        self.ui.update_status()

    def save_status_url(self, text: str) -> str | None:
        """The status page's address field was left: None when it holds the saved address, '' when the new one
        was saved, else why it was not (nothing saved - the front end puts the saved address back, says why)."""
        text = text.strip()
        if text == self.status_page.url():
            return None
        return self.status_page.set_url(text)

    def refresh_status_page(self) -> None:
        """The service card's Refresh link: a fetch now; "checking..." until it ends."""
        self.status_page.refresh()
        self.ui.update_status()

    # ---- actions
    def request_on(self) -> None:
        """Turn VPN on: first asks when another VPN is connected (it would be blocked silently otherwise)."""
        if not self.cfg:
            self.act("on")
            return
        foreign = self.find_foreign(force=True)
        if not foreign:
            self.act("on")
            return
        answer = self.ui.choose_foreign(foreign_prompt(foreign, self.cfg.profile))
        self._foreign_shown = {x.iface for x in foreign}            # just seen in the question: no notice for them again
        if answer == "disconnect":
            self.act("on", before=[self.nm.down_argv(x.connection) for x in foreign if x.connection])
        elif answer == "anyway":
            self.act("on")

    def act(self, action: str, arg: str | None = None, before: list[list[str]] | None = None) -> None:
        if action == "on":
            self.expect.start("connect")
        elif action == "reconnect":
            if self.facts.kind == "hiddify":
                self.ui.notice("VeroScudo", RECONNECT_HIDDIFY, state="blocked" if self.store.armed else "off")
                return
            if not self.store.armed:
                self.ui.notice("VeroScudo", "The VPN is off - use Turn VPN on.", state="off")
                return
            self.expect.start("reconnect")
            self.ui.notice("VeroScudo - reconnecting", f"Traffic is blocked while '{self.facts.name}' reconnects; "
                           "it flows again once the tunnel is back.", state="blocked")
        elif action == "use":
            self.expect.start("switch")
            armed = self.store.armed
            self.ui.notice("VeroScudo", f"Switching to '{arg}'"
                           + (" - traffic stays blocked until it is connected" if armed else ""),
                           state="blocked" if armed else "off")
        # `before`: other VPNs to disconnect first (as you, through the system's VPN service); a failure stops
        # before the turn on
        self.runner.start(action, *(before or []), action_argv(action, arg))
        self.ui.refresh_soon()

    def toggle_on_off(self) -> None:
        if offers_off(self.view, self.facts.kind):
            self.act("off")
        else:
            self.request_on()

    def admin(self, args: list[str]) -> None:
        self.runner.start("admin:" + args[0], admin_argv(args))

    def save_check(self, enabled: bool, every: int, over: int, rows) -> str:
        """Settings > Connection, Save: '' when the form is valid (the change then asks for an administrator's
        password), else what is wrong with it. rows: (address, method, port) per line."""
        try:
            chk = quality.from_form(enabled, every, over, rows, is_host)
        except ValueError as e:
            return str(e)
        self.admin(["set", "connectionCheck", json.dumps(chk.to_json())])
        return ""

    def drain(self) -> None:
        """The 0.5 s timer: what the commands that ended since the last look came to."""
        for tag, argv, rc, _out, err in self.runner.results():
            is_admin = tag.startswith("admin:")
            if rc == 0:
                if is_admin:
                    self.reload_config()                   # config_reloaded(): the settings show the change
                    if self.refresh_after_admin:
                        self.refresh()
                continue
            if is_admin and cancelled(rc, err):
                self.ui.update_settings()                  # put the option back the way config.json has it
                continue
            what = explain_failure(argv, rc, err)
            if is_admin:
                self.ui.update_settings()
                self.ui.message("The change was not made", what, error=True)
            else:
                self.expect.kind = None
                self.ui.notice(f"VeroScudo - {tag} failed", what, "critical")
        self._take_update_answers()

    # ---- the report and the update check
    def report_text(self) -> str:
        """What the status window's Copy link puts on the clipboard: the state, the table, the last events."""
        f, v = self.facts, self.view
        xl = exitinfo.report_line(self.exit_view()) if self.exit_enabled() else None
        sv = self.service_view()
        rows = status_rows(f, v, self.awake.active, self.tunnel, last_drop=self.last_drop,
                           foreign=self.find_foreign(), exit_line=xl, service=sv.text if sv else None)
        lines = [f"{k:<12} {val}" for k, val in rows]
        ev = read_events(n=15)
        return "\n".join([f"VeroScudo {__version__} - {v.title}", *lines, "", "--- last events",
                          *(ev or [log_hint()])])

    def copy_report(self) -> str:
        text = self.report_text()
        self.ui.set_clipboard(text)
        return text

    def check_updates(self, force: bool = False, clicked: bool = False) -> None:
        """Asks GitHub for the latest release - on a worker, never on the UI thread: the icon keeps following the guard
        while the answer is on its way. The answer is taken on the next drain (0.5 s timer)."""
        if not force and (not self.cfg or not self.cfg.update_check):
            return
        if self.store.armed and not self.facts.up:          # blocked: nothing may leave the machine
            if clicked:
                self.ui.notice("VeroScudo", "Traffic is blocked right now - check again once the VPN is "
                               "connected.", state="blocked")
            return
        if self._update_busy:
            return
        self._update_busy = True

        def work() -> None:
            try:
                rel = update.fetch_latest()
            except Exception:  # noqa: BLE001 - whatever went wrong: no answer
                rel = None
            self._update_answers.put((rel, clicked))
        self.spawn(work)
        self._take_update_answers()                            # already there when the work ran at once (tests)

    def _take_update_answers(self) -> None:
        while True:
            try:
                rel, clicked = self._update_answers.get_nowait()
            except queue.Empty:
                return
            self._update_busy = False
            self._update_answer(rel, clicked)

    def _update_answer(self, rel, clicked: bool) -> None:
        f = keepawake.pref_file().parent / "update.json"       # the user's own folder
        info = UpdateInfo()
        try:
            info.notified = str(json.loads(f.read_text()).get("notified", ""))
        except (OSError, ValueError, AttributeError):
            pass
        text, show = update_notice(info, rel.tag if rel else None, bool(rel and update.is_newer(rel.tag)))
        self.update_tag, self.update_url = (rel.tag, rel.url) if rel and text != "Check for updates" else (None, "")
        self.ui.show_update(text)
        if show:
            self.ui.notice(f"VeroScudo {self.update_tag} is available",
                           f"You run {__version__}. Open the {self.menu_name} to see the release.",
                           state="protected")
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps({"checked": info.checked, "notified": info.notified}))
        except OSError:
            pass
        if not clicked:
            return
        if self.update_url and update.is_release_url(self.update_url):
            self.ui.open_url(self.update_url)
        elif rel is None:
            self.ui.notice("VeroScudo", "The update check got no answer - try again later.", state=self.view.state)
        else:
            self.ui.notice("VeroScudo", f"You have the latest version ({__version__}).", state=self.view.state)

    def update_clicked(self) -> None:
        """The menu's update item: checks now; opens the release page when there is a newer version."""
        self.check_updates(force=True, clicked=True)
