"""veroscudo on|off|status|profiles|use <profile>|awake|arm|disarm|reconnect|watchdog|daemon|boot"""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import sys

from . import __version__, keepawake
from .backend import firewall, nm
from .config import Config
from .daemon import Guard
from .state import StateStore

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
    print(f"profile    : {cfg.profile}")
    print(f"profiles   : {', '.join(cfg.names)}")
    print(f"armed      : {armed}")
    print(f"connected  : {up}")
    print(f"state      : {state}")
    print(f"killswitch : {'active' if firewall.is_active() else 'inactive'}")
    print(f"tunnel     : {nm.iface(cfg.profile) or '-'}")
    print(f"reconnect  : {store.lock_alive()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="veroscudo", description="VeroScudo - Master the switch.")
    ap.add_argument("action", choices=["on", "off", "status", "profiles", "use", "awake", "arm", "disarm", "reconnect", "watchdog", "daemon", "boot"])
    ap.add_argument("name", nargs="?", help="profile name (for 'use')")
    ap.add_argument("--version", action="version", version=f"veroscudo {__version__}")
    a = ap.parse_args(argv)
    _setup_logging()
    if a.action == "awake":          # no config, no root: it only holds a sleep inhibitor
        return keepawake.hold()
    store = StateStore()
    cfg = Config.load(active=store.active)
    if a.action == "status":
        return status(cfg, store)
    if a.action == "profiles":
        for n in cfg.names:
            print(("* " if n == cfg.profile else "  ") + n)
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
        return 0
    {"on": g.on, "off": g.off, "arm": g.arm, "disarm": g.disarm, "reconnect": g.reconnect,
     "watchdog": g.watchdog, "daemon": g.run, "boot": g.boot}[a.action]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
