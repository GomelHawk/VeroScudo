"""Tray indicator (GNOME/KDE via Ayatana AppIndicator). Read-only; actions call `sudo veroscudo on|off`."""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, keepawake, nm, update
from .config import Config
from .state import StateStore

ICONS = Path("/usr/share/veroscudo/icons")


def _single_instance():
    """One tray per session: returns the held lock file, or None when another tray already holds it."""
    f = open(Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp")) / "veroscudo-tray.lock", "w")  # noqa: SIM115 - held until exit
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


def main() -> int:
    lock = _single_instance()
    if lock is None:
        return 0
    import gi  # type: ignore
    gi.require_version("Gtk", "3.0")
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3 as AppIndicator  # type: ignore
    from gi.repository import GLib, Gtk

    store = StateStore()
    cfg = Config.load(active=store.active)
    ind = AppIndicator.Indicator.new("veroscudo", str(ICONS / "off.png"), AppIndicator.IndicatorCategory.APPLICATION_STATUS)
    ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
    menu = Gtk.Menu()
    head = Gtk.MenuItem(label="VeroScudo"); head.set_sensitive(False); menu.append(head)
    menu.append(Gtk.SeparatorMenuItem())
    on_item = Gtk.MenuItem(label="Turn VPN on"); on_item.connect("activate", lambda *_: subprocess.Popen(["sudo", "-n", "veroscudo", "on"])); menu.append(on_item)
    off_item = Gtk.MenuItem(label="Turn VPN off"); off_item.connect("activate", lambda *_: subprocess.Popen(["sudo", "-n", "veroscudo", "off"])); menu.append(off_item)
    prof_item = Gtk.MenuItem(label="VPN profile"); prof_menu = Gtk.Menu(); prof_item.set_submenu(prof_menu); menu.append(prof_item)
    shown = {"active": None}

    def fill_profiles(active: str) -> None:
        for child in prof_menu.get_children():
            prof_menu.remove(child)
        group = None
        for name in cfg.names:
            it = Gtk.RadioMenuItem.new_with_label_from_widget(group, name)
            group = group or it
            it.set_active(name == active)
            # the switch itself runs as root (sudoers: veroscudo use *); the name is checked there against config.json
            it.connect("toggled", lambda w, n=name: w.get_active() and n != shown["active"] and subprocess.Popen(["sudo", "-n", "veroscudo", "use", n]))
            prof_menu.append(it)
        prof_item.set_label(f"VPN profile: {active}")
        prof_menu.show_all()
        shown["active"] = active
    fill_profiles(cfg.profile)
    menu.append(Gtk.SeparatorMenuItem())
    st_item = Gtk.MenuItem(label="Status…"); st_item.connect("activate", lambda *_: subprocess.Popen(["x-terminal-emulator", "-e", "sh", "-c", "veroscudo status; read -p 'Enter to close' _"])); menu.append(st_item)
    awake = keepawake.KeepAwake()
    awake_item = Gtk.CheckMenuItem(label="Keep awake"); menu.append(awake_item)
    awake_item.set_active(awake.set(keepawake.load_pref()))

    def on_awake(item) -> None:
        want = item.get_active()
        held = awake.set(want)
        keepawake.save_pref(held)
        if want and not held:
            item.handler_block(awake_handler); item.set_active(False); item.handler_unblock(awake_handler)
            subprocess.Popen(["notify-send", "-a", "VeroScudo", "Keep awake is not available", "No sleep inhibitor found (systemd-inhibit)."])
    awake_handler = awake_item.connect("toggled", on_awake)
    upd_item = Gtk.MenuItem(label="Check for updates"); menu.append(upd_item)
    latest = {"rel": None}
    upd_file = store.home / "update.json"

    def check_updates(force: bool = False) -> None:
        if not force and not cfg.update_check:
            return
        if store.armed and not nm.is_connected(cfg.profile):      # blocked: nothing may leave the machine
            return
        info = {"checked": 0.0, "notified": ""}
        try:
            info.update(json.loads(upd_file.read_text()))
        except (OSError, ValueError):
            pass
        rel = update.fetch_latest()
        info["checked"] = time.time()
        if rel and update.is_newer(rel.tag):
            latest["rel"] = rel
            upd_item.set_label(f"Update available: {rel.tag}…")
            if info["notified"] != rel.tag:
                subprocess.Popen(["notify-send", "-a", "VeroScudo", f"VeroScudo {rel.tag} is available", f"You run {__version__}. Open the tray menu to see the release."])
                info["notified"] = rel.tag
        else:
            latest["rel"] = None
            upd_item.set_label("Check for updates")
        try:
            upd_file.write_text(json.dumps(info))
        except OSError:
            pass

    def on_update_click(*_):
        check_updates(force=True)
        if latest["rel"] and update.is_release_url(latest["rel"].url):
            subprocess.Popen(["xdg-open", latest["rel"].url])
    upd_item.connect("activate", on_update_click)
    quit_item = Gtk.MenuItem(label="Exit tray (guard keeps running)"); quit_item.connect("activate", Gtk.main_quit); menu.append(quit_item)
    menu.show_all(); ind.set_menu(menu)
    last = {"state": None}

    def refresh():
        nonlocal cfg
        active = store.active
        if active in cfg.names and active != cfg.profile:
            cfg = cfg.with_active(active)
        if cfg.profile != shown["active"]:
            fill_profiles(cfg.profile)
        armed, up = store.armed, nm.is_connected(cfg.profile)
        state = "off" if not armed else ("protected" if up else "blocked")
        if state != last["state"]:
            icon = ICONS / f"{state}.png"
            if not icon.exists():
                print(f"WARNING: missing {icon} - reinstall to fix", file=sys.stderr)
            ind.set_icon_full(str(icon), state)
            ind.set_title({"protected": "VeroScudo - protected", "blocked": "VeroScudo - BLOCKED, reconnecting", "off": "VeroScudo - off"}[state])
            last["state"] = state
        on_item.set_sensitive(state != "protected"); off_item.set_sensitive(armed or up)
        if awake_item.get_active() != awake.active:        # the inhibitor died on its own
            awake_item.handler_block(awake_handler); awake_item.set_active(awake.active); awake_item.handler_unblock(awake_handler)
        return True

    refresh(); GLib.timeout_add_seconds(3, refresh)
    GLib.timeout_add_seconds(120, lambda: (check_updates(), False)[1])
    Gtk.main()
    awake.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
