"""veroscudo on|off|reconnect|status|profiles|use <profile>|import [<connection>...]|check|awake|setup [<connection>]|
remove <profile>|set <key> <value>|arm|disarm|watchdog|daemon|boot

reconnect = your Reconnect: block, take the VPN down, redial; traffic again once the tunnel is back.
setup     = the installer's first profile: pick one of the system's VPN connections (or type it in) - root.
remove / set = the tray's Settings (asked for with an administrator's password) - root."""
from __future__ import annotations

import argparse
import grp
import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path

from . import __version__, importer, keepawake, quality
from .backend import firewall, nm
from .config import Config, config_path
from .daemon import Guard
from .state import StateStore, kind_label, switch_notice

LOG = "/var/log/veroscudo.log"
# who may read the log besides root: the administrators' group (Debian/Ubuntu 'adm' also reads the journal, where the
# daemon's output goes anyway; macOS 'admin'). The tray's Status and Open log read it as the signed-in user.
LOG_GROUP = "admin" if sys.platform == "darwin" else "adm"


def share_log(path: str) -> None:
    """root:<admins> 0640 - best effort (the group may not exist; a user's own run cannot chown)."""
    try:
        if os.geteuid() == 0:
            os.chown(path, 0, grp.getgrnam(LOG_GROUP).gr_gid)
        os.chmod(path, 0o640)
    except (KeyError, OSError):
        pass


class SharedLog(logging.handlers.RotatingFileHandler):
    """Bounded like the Windows log (2 MB + one rotated copy); every file it opens - also after a rotation - gets the
    log's owner and mode, not root's umask."""

    def _open(self):
        stream = super()._open()
        share_log(self.baseFilename)
        return stream


def _setup_logging() -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        path = os.environ.get("VEROSCUDO_LOG", LOG)
        if not os.path.exists(path):                     # never world-readable: profile names, servers, decisions
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o640))
        handlers.append(SharedLog(path, maxBytes=2 * 1024 * 1024, backupCount=1))
    except OSError:
        pass
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=handlers)


def is_up(cfg: Config, store: StateStore) -> bool:
    """Connected - and, while armed, let through by the kill-switch as the guard last applied it. A dead WireGuard link stays
    'activated' and only root can read its handshakes; the guard's own verdict (applied.json) is what counts."""
    if not nm.is_connected(cfg.profile):
        return False
    return not store.armed or store.allowed_tunnel(cfg.profile) is not None


def status(cfg: Config, store: StateStore) -> int:
    armed, up = store.armed, is_up(cfg, store)
    state = "off" if not armed else ("protected" if up else "blocked")
    kind = nm.kind(cfg.profile)
    print(f"profile    : {cfg.profile} ({kind_label(kind)})")
    print(f"profiles   : {', '.join(cfg.names)}")
    print(f"armed      : {armed}")
    print(f"connected  : {up}")
    print(f"state      : {state}")
    if not cfg.check.enabled:
        conn = "check off"
    elif state == "protected":
        q = quality.read(store.home / "quality.json", cfg.profile)
        conn = quality.describe(q) if q else "checking…"
    else:
        conn = "-"
    print(f"connection : {conn}")
    # asking the firewall needs root: for a user the answer would always be "inactive", which is wrong and alarming
    ks = ("active" if firewall.is_active() else "inactive") if os.geteuid() == 0 else "unknown (run with sudo to see it)"
    print(f"killswitch : {ks}")
    print(f"tunnel     : {nm.iface(cfg.profile) or '-'}")
    print(f"reconnect  : {store.lock_alive()}")
    others = nm.other_tunnels(nm.iface(cfg.profile))
    if others:
        print(f"attention  : another tunnel next to VeroScudo: {', '.join(others)}")
    notice = switch_notice(kind, cfg.profile)
    if notice:
        print(f"notice     : {notice}")
    return 0


def do_import(names: list[str]) -> int:
    """Without names: list the OS's VPN connections and what would be imported. With names (root): add them to config.json."""
    found = nm.discover()
    if not names:
        if not found:
            print("no VPN connection found - create one in the system's VPN settings first")
        for d in found:
            what = importer.summary(d) if importer.importable(d) else "-"
            print(f"  {d['name']:<28} {what}{'  - ' + d['note'] if d['note'] else ''}")
        print("import: sudo veroscudo import <connection> [<connection> ...]")
        return 0
    if os.geteuid() != 0:
        print("veroscudo: import writes /etc/veroscudo/config.json - run it with sudo", file=sys.stderr)
        return 2
    p = Path(os.environ.get("VEROSCUDO_CONFIG", "/etc/veroscudo/config.json"))
    try:
        text, msgs = importer.add_profiles(p.read_text() if p.exists() else "", found, names)
    except ValueError as e:
        print(f"veroscudo: {e}", file=sys.stderr)
        return 2
    importer.write_config(text, p)
    for m in msgs:
        print(m)
    print("the guard picks the change up within 15 s")
    return 0


def _ask(prompt: str, default: str = "") -> str:
    v = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return v or default


def manual_profile() -> str:
    """config.json text for one profile typed in by hand (the connection must exist in the system's VPN settings)."""
    mac = sys.platform == "darwin"
    while True:
        name = _ask("VPN connection name, exactly as in the system's VPN settings")
        server = _ask("VPN server host name or address")
        port = _ask("VPN port", "4500" if mac else "443")
        proto = _ask("VPN transport, tcp or udp", "udp" if mac else "tcp").lower()
        cfg = {"profiles": [{"profile": name, "server": server, "port": int(port) if port.isdigit() else -1, "protocol": proto}],
               "activeProfile": name, "retrySeconds": 10, "vm": True, "updateCheck": True, "lanAllow": []}
        text = json.dumps(cfg, indent=2) + "\n"
        try:
            Config.from_text(text)
            return text
        except (ValueError, KeyError, TypeError) as e:
            print(f"  not valid: {e} - again")


def choose(found: list[dict]) -> list[str] | None:
    """Numbered list of the system's VPN connections; returns [name], or None for "type it in by hand". Only an importable
    connection can be chosen."""
    usable = [d for d in found if importer.importable(d)]
    print("VPN connections on this computer:")
    for i, d in enumerate(found, 1):
        what = importer.summary(d) if d in usable else "cannot be used"
        print(f"  {i:>2}) {d['name']:<28} {what}{'  - ' + d['note'] if d['note'] else ''}")
    print("   0) none of these - type the settings in")
    while True:
        pick = _ask("Protect which one", "1" if usable else "0")
        if pick == "0":
            return None
        if pick.isdigit() and 1 <= int(pick) <= len(found) and found[int(pick) - 1] in usable:
            return [found[int(pick) - 1]["name"]]
        print("  pick a number from the list (one that can be used), or 0")


def do_setup(names: list[str]) -> int:
    """The installer's first profile. Keeps a valid config.json; with names imports those; else asks."""
    if os.geteuid() != 0:
        print("veroscudo: setup writes /etc/veroscudo/config.json - run it with sudo", file=sys.stderr)
        return 2
    p = config_path()
    if p.exists() and not names:
        try:
            cfg = Config.load(p)
            print(f"config.json kept: profiles {', '.join(cfg.names)}")
            return 0
        except (OSError, ValueError, KeyError, TypeError) as e:
            print(f"config.json is not valid ({e}) - it is replaced by the profile you pick now")
    found = nm.discover()
    if not names:
        if not sys.stdin.isatty():
            print("veroscudo: no config.json yet - name the VPN connection: setup <connection>", file=sys.stderr)
            return 2
        if not found:
            print("No VPN connection found. Create it first in the system's VPN settings (Linux: Settings > Network > VPN;"
                  " macOS: System Settings > VPN) and connect once by hand - or type the settings in now.")
        names = choose(found) if found else None
    if names is None:
        text = manual_profile()
    else:
        raw = p.read_text() if p.exists() and _valid(p) else ""
        try:
            text, msgs = importer.add_profiles(raw, found, [n for n in names if n not in _names(raw)])
        except ValueError as e:
            print(f"veroscudo: {e}", file=sys.stderr)
            return 2
        for m in msgs:
            print(m)
    importer.write_config(text, p)
    print(f"config written: {p}")
    return 0


def _valid(p: Path) -> bool:
    try:
        Config.load(p)
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _names(raw: str) -> set[str]:
    try:
        return set(Config.from_text(raw).names) if raw.strip() else set()
    except (ValueError, KeyError, TypeError):
        return set()


def do_edit(action: str, args: list[str], store: StateStore) -> int:
    """remove <profile> | set <key> <value> - the tray's Settings, run as root."""
    if os.geteuid() != 0:
        print(f"veroscudo: {action} changes /etc/veroscudo/config.json - run it with sudo", file=sys.stderr)
        return 2
    if action not in ("remove", "set"):
        print(f"veroscudo: unknown change '{action}' (there is no default profile: select one in the tray menu or with "
              "`veroscudo use <profile>`)", file=sys.stderr)
        return 2
    want = 2 if action == "set" else 1
    if len(args) != want:
        print(f"veroscudo {action} {'<key> <value>' if action == 'set' else '<profile>'}", file=sys.stderr)
        return 2
    p = config_path()
    try:
        raw = p.read_text()
        if action == "remove":
            if store.armed and store.active == args[0]:
                raise ValueError(f"'{args[0]}' is in use - switch to another profile or turn the VPN off first")
            text = importer.remove_profile(raw, args[0])
            if (store.active or Config.from_text(raw).profile) == args[0]:
                # the profile in use goes: the first remaining one is used from now on (as the Windows tray's Save)
                text = importer.set_default(text, Config.from_text(text).names[0])
        else:
            text = importer.set_option(raw, args[0], args[1])
    except (OSError, ValueError) as e:
        print(f"veroscudo: {e}", file=sys.stderr)
        return 2
    importer.write_config(text, p)
    if action == "remove" and store.active == args[0]:
        store.active_file.unlink(missing_ok=True)       # the selection falls back to the first remaining profile
    print(f"config.json updated ({action} {' '.join(args)}); the guard picks it up within 15 s")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="veroscudo", description="VeroScudo - Master the switch.")
    ap.add_argument("action", choices=["on", "off", "status", "profiles", "use", "import", "check", "awake", "setup", "remove",
                                       "set", "arm", "disarm", "reconnect", "watchdog", "daemon", "boot"])
    ap.add_argument("name", nargs="*", help="profile name (use, remove), connection names (import, setup), "
                                            "key and value (set)")
    ap.add_argument("--version", action="version", version=f"veroscudo {__version__}")
    a = ap.parse_args(argv)
    _setup_logging()
    if a.action == "awake":          # no config, no root: it only holds a sleep inhibitor
        return keepawake.hold()
    if a.action == "import":
        return do_import(a.name)
    if a.action == "setup":
        return do_setup(a.name)
    if a.action in ("remove", "set"):
        return do_edit(a.action, a.name, StateStore())
    a.name = a.name[0] if a.name else None
    store = StateStore()
    try:
        cfg = Config.load(active=store.active)
    except (OSError, ValueError, KeyError, TypeError) as e:
        # fail closed: an armed machine must not boot open because config.json is missing or broken. The daemon exits too
        # (launchd/systemd restart it), so the lockdown stays until the file is fixed and `veroscudo on` is run again.
        if a.action in ("boot", "daemon") and store.armed:
            with store.firewall_lock():
                firewall.apply(firewall.render_lockdown())
                store.set_applied(None, None)
            logging.getLogger("veroscudo").error("config.json unusable (%s) - armed: everything but DHCP is blocked until it is fixed", e)
            return 2
        print(f"veroscudo: {e}", file=sys.stderr)
        return 2
    if a.action == "status":
        return status(cfg, store)
    if a.action == "profiles":
        for n in cfg.names:
            print(("* " if n == cfg.profile else "  ") + f"{n} ({kind_label(nm.kind(n))})")
        return 0
    if a.action == "check":
        problems = nm.check(cfg)
        for line in problems:
            print(line)
        print("check: no problems found" if not problems else f"check: {len(problems)} note(s)")
        return 0
    if a.action == "use" and not a.name:
        print("veroscudo use <profile>   (see: veroscudo profiles)", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("veroscudo: this action needs root (install.sh adds a sudoers rule: sudo veroscudo on|off|use <profile>)", file=sys.stderr)
        return 2
    g = Guard(cfg, store)
    if a.action in ("on", "reconnect", "use"):
        g.attempts = 1              # a command returns; the daemon keeps redialing (the tray must not wait for a dead VPN)
    if a.action == "use":
        try:
            g.use(a.name)
        except ValueError as e:
            print(f"veroscudo: {e}", file=sys.stderr)
            return 2
        notice = switch_notice(nm.kind(a.name), a.name)
        if notice:
            print(f"NOTICE: {notice}")
        return 0
    {"on": g.on, "off": g.off, "arm": g.arm, "disarm": g.disarm, "reconnect": g.renew,
     "watchdog": g.watchdog, "daemon": g.run, "boot": g.boot}[a.action]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
