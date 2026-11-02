"""veroscudo on|off|reconnect|status|profiles|use <profile>|import [<connection>...]|check|awake|arm|disarm|watchdog|daemon|boot

reconnect = your Reconnect: block, take the VPN down, redial; traffic again once the tunnel is back."""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import sys
from pathlib import Path

from . import __version__, importer, keepawake
from .backend import firewall, nm
from .config import Config
from .daemon import Guard
from .state import StateStore, kind_label, switch_notice

LOG = "/var/log/veroscudo.log"


def _setup_logging() -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        # bounded like the Windows log: 2 MB + one rotated copy
        handlers.append(logging.handlers.RotatingFileHandler(os.environ.get("VEROSCUDO_LOG", LOG), maxBytes=2 * 1024 * 1024, backupCount=1))
    except OSError:
        pass
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=handlers)


def status(cfg: Config, store: StateStore) -> int:
    armed, up = store.armed, nm.is_connected(cfg.profile)
    state = "off" if not armed else ("protected" if up else "blocked")
    kind = nm.kind(cfg.profile)
    print(f"profile    : {cfg.profile} ({kind_label(kind)})")
    print(f"profiles   : {', '.join(cfg.names)}")
    print(f"armed      : {armed}")
    print(f"connected  : {up}")
    print(f"state      : {state}")
    print(f"killswitch : {'active' if firewall.is_active() else 'inactive'}")
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
            what = f"{d['vpn_type'] or d['protocol']}  {d['server'] or '-'}:{d['port']}" if d["server"] else "-"
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
    print("restart the daemon to pick them up: sudo systemctl restart veroscudo   (macOS: sudo launchctl kickstart -k system/com.gomelhawk.veroscudo)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="veroscudo", description="VeroScudo - Master the switch.")
    ap.add_argument("action", choices=["on", "off", "status", "profiles", "use", "import", "check", "awake", "arm", "disarm", "reconnect", "watchdog", "daemon", "boot"])
    ap.add_argument("name", nargs="*", help="profile name (for 'use'), connection names (for 'import')")
    ap.add_argument("--version", action="version", version=f"veroscudo {__version__}")
    a = ap.parse_args(argv)
    _setup_logging()
    if a.action == "awake":          # no config, no root: it only holds a sleep inhibitor
        return keepawake.hold()
    if a.action == "import":
        return do_import(a.name)
    a.name = a.name[0] if a.name else None
    store = StateStore()
    cfg = Config.load(active=store.active)
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
