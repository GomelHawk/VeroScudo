"""Linux tray (Ayatana AppIndicator + GTK 3): the same menu, windows and notifications as the Windows tray.

It runs as the signed-in user and never as root. on / off / reconnect / use go through the sudoers rule install.sh
writes (`sudo -n`, by full path); a change to config.json or the uninstall asks for an administrator's password first
(pkexec), like the UAC prompt of the Windows tray. What it shows and says is decided in traymodel.py.

`python3 -m veroscudo.tray --preview DIR` renders every window into PNGs (no tray icon, nothing changed) for review."""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, keepawake, traymodel, update
from .backend import nm
from .config import Config, config_path
from .state import StateStore, kind_label, switch_notice

ICONS = traymodel.env_icons(Path("/usr/share/veroscudo/icons"))


def _single_instance():
    """One tray per session: returns the held lock file, or None when another tray already holds it."""
    # the user's own runtime folder (Linux XDG_RUNTIME_DIR, macOS TMPDIR): never a shared /tmp another user could hold
    base = os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("TMPDIR") or f"/tmp/veroscudo-{os.getuid()}"
    Path(base).mkdir(mode=0o700, exist_ok=True)
    f = open(Path(base) / "veroscudo-tray.lock", "w")  # noqa: SIM115 - held until exit
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


def _gtk():
    import gi  # type: ignore
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import Gdk, GdkPixbuf, GLib, Gtk, Pango  # type: ignore
    return Gdk, GdkPixbuf, GLib, Gtk, Pango


def icon_path(state: str) -> Path:
    return ICONS / f"{state}.png"


def _popen(argv: list[str]) -> None:
    try:
        subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def notify(title: str, body: str, urgency: str = "normal", state: str = "attention") -> None:
    icon = icon_path(state)
    _popen(["notify-send", "-a", "VeroScudo", "-u", urgency] + (["-i", str(icon)] if icon.exists() else []) + [title, body])


# ---------------------------------------------------------------- windows (GTK; used by the tray and by --preview)
class Windows:
    """The status, settings and about windows. `app` supplies the facts and runs the actions (TrayApp or a preview stub)."""

    def __init__(self, app) -> None:
        self.app = app
        self.Gdk, self.GdkPixbuf, self.GLib, self.Gtk, self.Pango = _gtk()
        self.status = self.settings = self.about = None

    # helpers
    def _pixbuf(self, path: Path, size: int):
        try:
            return self.GdkPixbuf.Pixbuf.new_from_file_at_scale(str(path), size, size, True)
        except Exception:  # noqa: BLE001 - a missing icon must not stop the window
            return None

    def _window(self, title: str, width: int):
        Gtk = self.Gtk
        w = Gtk.Window(title=title)
        w.set_default_size(width, -1)
        w.set_resizable(False)
        w.set_position(Gtk.WindowPosition.CENTER)
        pb = self._pixbuf(ICONS / "app.png", 64)
        if pb:
            w.set_icon(pb)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        w.add(box)
        return w, box

    def _label(self, text: str = "", markup: bool = False, dim: bool = False, wrap: bool = True, xalign: float = 0.0):
        lb = self.Gtk.Label()
        (lb.set_markup if markup else lb.set_text)(text)
        lb.set_xalign(xalign)
        lb.set_line_wrap(wrap)
        lb.set_max_width_chars(52)
        if dim:
            lb.get_style_context().add_class("dim-label")
        return lb

    def _buttons(self, box, *specs):
        bb = self.Gtk.Box(spacing=8)
        bb.set_halign(self.Gtk.Align.END)
        out = []
        for text, cb, primary in specs:
            b = self.Gtk.Button(label=text)
            if primary:
                b.get_style_context().add_class("suggested-action")
            b.connect("clicked", lambda _b, cb=cb: cb())
            bb.pack_start(b, False, False, 0)
            out.append(b)
        box.pack_end(bb, False, False, 0)
        return out

    # status
    def show_status(self) -> None:
        if self.status:
            self.status.present()
            return
        Gtk = self.Gtk
        w, box = self._window("VeroScudo", 460)
        head = Gtk.Box(spacing=14)
        img = Gtk.Image()
        head.pack_start(img, False, False, 0)
        tb = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title, text = self._label(markup=True), self._label(dim=True)
        tb.pack_start(title, False, False, 0)
        tb.pack_start(text, False, False, 0)
        head.pack_start(tb, True, True, 0)
        box.pack_start(head, False, False, 0)
        grid = Gtk.Grid(column_spacing=18, row_spacing=6)
        box.pack_start(grid, False, False, 0)
        box.pack_start(self._label("<b>Recent events</b>", markup=True), False, False, 0)
        tv = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        sw = Gtk.ScrolledWindow()
        sw.set_size_request(-1, 170)
        sw.set_shadow_type(Gtk.ShadowType.IN)
        sw.add(tv)
        box.pack_start(sw, True, True, 0)
        onoff, redo, copy, _ = self._buttons(
            box, ("Turn VPN on", lambda: self.app.toggle_on_off(), True), ("Reconnect", lambda: self.app.act("reconnect"), False),
            ("Copy report", lambda: self.app.copy_report(), False), ("Close", lambda: w.destroy(), False))
        self.status = w
        self._st = dict(img=img, title=title, text=text, grid=grid, tv=tv, sw=sw, onoff=onoff, redo=redo, copy=copy, rows=None)
        w.connect("destroy", lambda *_: setattr(self, "status", None))
        self.update_status()
        w.show_all()

    def update_status(self) -> None:
        if not self.status:
            return
        Gtk, st = self.Gtk, self._st
        f, v = self.app.facts, self.app.view
        pb = self._pixbuf(icon_path(v.state), 64)
        if pb:
            st["img"].set_from_pixbuf(pb)
        st["title"].set_markup(f"<span size='x-large' weight='bold'>{self.GLib.markup_escape_text(v.title)}</span>")
        st["text"].set_text(v.text)
        rows = traymodel.status_rows(f, v, self.app.awake_on, self.app.tunnel)
        if rows != st["rows"]:
            for child in st["grid"].get_children():
                st["grid"].remove(child)
            for i, (k, val) in enumerate(rows):
                st["grid"].attach(self._label(k, dim=True, wrap=False), 0, i, 1, 1)
                st["grid"].attach(self._label(val, wrap=False), 1, i, 1, 1)
            st["grid"].show_all()
            st["rows"] = rows
        ev = self.app.events()
        text = traymodel.log_hint() if ev is None else ("\n".join(ev) or "(no events yet)")
        buf = st["tv"].get_buffer()
        if buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False) != text:
            buf.set_text(text)
            adj = st["sw"].get_vadjustment()
            self.GLib.idle_add(lambda: adj.set_value(adj.get_upper()) or False)     # newest at the bottom
        ms = traymodel.menu_state(v)
        st["onoff"].set_label("Turn VPN off" if (v.armed or v.connected) else "Turn VPN on")
        st["onoff"].set_sensitive(f.configured)
        st["redo"].set_sensitive(ms.reconnect)
        _ = Gtk

    # settings
    def show_settings(self) -> None:
        if self.settings:
            self.settings.present()
            return
        Gtk = self.Gtk
        w, box = self._window("VeroScudo - Settings", 520)
        box.pack_start(self._label("<b>VPN profiles</b>", markup=True), False, False, 0)
        lb = Gtk.ListBox()
        lb.set_selection_mode(Gtk.SelectionMode.SINGLE)
        frame = Gtk.Frame()
        frame.add(lb)
        frame.set_size_request(-1, 150)
        box.pack_start(frame, False, False, 0)
        row = Gtk.Box(spacing=8)
        for text, cb in (("Import…", self.import_dialog), ("Remove", lambda: self._on_selected("remove")),
                         ("Make default", lambda: self._on_selected("default"))):
            b = Gtk.Button(label=text)
            b.connect("clicked", lambda _b, cb=cb: cb())
            row.pack_start(b, False, False, 0)
        box.pack_start(row, False, False, 0)
        box.pack_start(self._label("Profiles are the system's own VPN connections (Settings > Network > VPN); passwords "
                                   "stay with NetworkManager.", dim=True), False, False, 0)
        box.pack_start(Gtk.Separator(), False, False, 0)
        box.pack_start(self._label("<b>Options</b>", markup=True), False, False, 0)
        strict = Gtk.CheckButton(label="Strict kill-switch (always on - cannot be disabled)")
        strict.set_active(True)
        strict.set_sensitive(False)
        box.pack_start(strict, False, False, 0)
        upd = Gtk.CheckButton(label="Check for a new release when the tray starts")
        box.pack_start(upd, False, False, 0)
        vmrow = Gtk.Box(spacing=10)
        vmrow.pack_start(self._label("Containers and VMs (Docker, libvirt)", wrap=False), False, False, 0)
        vm = Gtk.ComboBoxText()
        for key, text in (("auto", "through the tunnel when found"), ("true", "always through the tunnel"),
                          ("false", "no network while on")):
            vm.append(key, text)
        vmrow.pack_start(vm, False, False, 0)
        if sys.platform != "darwin":
            box.pack_start(vmrow, False, False, 0)
        box.pack_start(self._label("Changes ask for an administrator's password and take effect within 15 seconds.",
                                   dim=True), False, False, 0)
        self._buttons(box, ("Close", lambda: w.destroy(), True))
        self.settings = w
        self._se = dict(lb=lb, upd=upd, vm=vm, busy=False)
        upd.connect("toggled", lambda b: self._se["busy"] or self.app.admin(["set", "updateCheck", "true" if b.get_active() else "false"]))
        vm.connect("changed", lambda c: self._se["busy"] or self.app.admin(["set", "vm", c.get_active_id()]))
        w.connect("destroy", lambda *_: setattr(self, "settings", None))
        self.update_settings()
        w.show_all()

    def update_settings(self) -> None:
        if not self.settings:
            return
        se, cfg = self._se, self.app.cfg
        se["busy"] = True
        try:
            for child in se["lb"].get_children():
                se["lb"].remove(child)
            for name in (cfg.names if cfg else []):
                tags = [kind_label(self.app.kind(name))]
                if name == cfg.default_profile:
                    tags.append("default")
                if name == cfg.profile:
                    tags.append("active")
                lab = self._label(f"{name}   <span alpha='60%'>{self.GLib.markup_escape_text(' · '.join(tags))}</span>",
                                  markup=True, wrap=False)
                lab.set_margin_start(8)
                lab.set_margin_top(6)
                lab.set_margin_bottom(6)
                r = self.Gtk.ListBoxRow()
                r.add(lab)
                r.profile = name
                se["lb"].add(r)
            se["lb"].show_all()
            se["upd"].set_active(bool(cfg.update_check) if cfg else True)
            se["vm"].set_active_id({True: "true", False: "false"}.get(cfg.vm, "auto") if cfg else "auto")
        finally:
            se["busy"] = False

    def _on_selected(self, action: str) -> None:
        r = self._se["lb"].get_selected_row()
        if r is None:
            self.message("Select a profile first.")
            return
        self.app.admin([action, r.profile])

    def import_dialog(self) -> None:
        Gtk = self.Gtk
        have = set(self.app.cfg.names) if self.app.cfg else set()
        found = [d for d in self.app.discover() if d["name"] not in have]
        d = Gtk.Dialog(title="Import a VPN connection", transient_for=self.settings, modal=True)
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Import", Gtk.ResponseType.OK)
        area = d.get_content_area()
        area.set_border_width(14)
        area.set_spacing(10)
        area.pack_start(self._label("One connection per import: not every VPN on a computer is for work.", dim=True), False, False, 0)
        lb = Gtk.ListBox()
        for c in found:
            ok = (c["server"] and not c.get("unsupported")) or c["note"].startswith("run as root")
            what = f"{c['vpn_type'] or c['protocol']}  {c['server'] or '?'}:{c['port']}" if ok else c["note"]
            lab = self._label(f"<b>{self.GLib.markup_escape_text(c['name'])}</b>\n<span alpha='60%'>"
                              f"{self.GLib.markup_escape_text(what)}</span>", markup=True, wrap=False)
            lab.set_margin_start(8)
            lab.set_margin_top(4)
            lab.set_margin_bottom(4)
            r = Gtk.ListBoxRow()
            r.add(lab)
            r.set_sensitive(bool(ok))
            r.profile = c["name"]
            lb.add(r)
        if not found:
            area.pack_start(self._label("No other VPN connection found. Create it in Settings > Network > VPN, connect once, "
                                        "then import it here."), False, False, 0)
        else:
            area.pack_start(lb, True, True, 0)
        d.show_all()
        resp = d.run()
        r = lb.get_selected_row()
        d.destroy()
        if resp == Gtk.ResponseType.OK and r is not None:
            self.app.admin(["import", r.profile])

    # about
    def show_about(self) -> None:
        if self.about:
            self.about.present()
            return
        Gtk = self.Gtk
        w, box = self._window("About VeroScudo", 420)
        head = Gtk.Box(spacing=16)
        img = Gtk.Image()
        pb = self._pixbuf(ICONS / "app.png", 64)
        if pb:
            img.set_from_pixbuf(pb)
        head.pack_start(img, False, False, 0)
        tb = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        tb.pack_start(self._label(f"<span size='x-large' weight='bold'>VeroScudo {__version__}</span>", markup=True), False, False, 0)
        tb.pack_start(self._label("Master the switch.", dim=True), False, False, 0)
        head.pack_start(tb, True, True, 0)
        box.pack_start(head, False, False, 0)
        box.pack_start(self._label("VPN on + connection lost = no network until the VPN is back or you turn it off. "
                                   "Two actions, no backdoor.", dim=True), False, False, 0)
        link = Gtk.LinkButton(uri=traymodel.REPO_URL, label="github.com/GomelHawk/VeroScudo")
        link.set_halign(Gtk.Align.START)
        box.pack_start(link, False, False, 0)
        self._buttons(box, ("Uninstall…", self.confirm_uninstall, False), ("Close", lambda: w.destroy(), True))
        self.about = w
        w.connect("destroy", lambda *_: setattr(self, "about", None))
        w.show_all()

    def confirm_uninstall(self) -> None:
        if self.ask("Uninstall VeroScudo?",
                    "Removes the guard, the kill-switch, the tray and the sudo rule. Your VPN connections stay as they are; "
                    "a connected VPN stays connected. config.json is kept for a later install.", "Uninstall"):
            self.app.admin(["uninstall"])

    # dialogs
    def message(self, text: str, secondary: str = "", error: bool = False) -> None:
        Gtk = self.Gtk
        d = Gtk.MessageDialog(message_type=Gtk.MessageType.ERROR if error else Gtk.MessageType.INFO,
                              buttons=Gtk.ButtonsType.OK, text=text)
        d.set_title("VeroScudo")
        if secondary:
            d.format_secondary_text(secondary)
        d.run()
        d.destroy()

    def ask(self, text: str, secondary: str, ok: str) -> bool:
        Gtk = self.Gtk
        d = Gtk.MessageDialog(message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.NONE, text=text)
        d.set_title("VeroScudo")
        d.format_secondary_text(secondary)
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL, ok, Gtk.ResponseType.OK)
        r = d.run()
        d.destroy()
        return r == Gtk.ResponseType.OK


# ---------------------------------------------------------------- the tray
class TrayApp:
    def __init__(self) -> None:
        import gi  # type: ignore
        gi.require_version("AyatanaAppIndicator3", "0.1")
        from gi.repository import AyatanaAppIndicator3 as AppIndicator  # type: ignore
        self.Gdk, _, self.GLib, self.Gtk, _ = _gtk()
        self.store = StateStore()
        self.cfg: Config | None = None
        self.cfg_error = ""
        self._cfg_mtime = -1.0
        self._kinds: dict[str, str | None] = {}
        self.runner = traymodel.Runner()
        self.expect = traymodel.Expect()
        self.awake = keepawake.KeepAwake()
        self.last: str | None = None
        self.facts = traymodel.Facts(configured=False)
        self.view = traymodel.tray_state(self.facts)
        self.tunnel: str | None = None
        self.update_tag: str | None = None
        self.update_url = ""
        self.win = Windows(self)
        self.reload_config()

        Gtk = self.Gtk
        self.ind = AppIndicator.Indicator.new("veroscudo", str(icon_path("off")), AppIndicator.IndicatorCategory.APPLICATION_STATUS)
        self.ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        m = self.menu = Gtk.Menu()
        self.head = self._item("VeroScudo", None)
        self.head.set_sensitive(False)
        m.append(Gtk.SeparatorMenuItem())
        self.on_item = self._item("Turn VPN on", lambda: self.act("on"))
        self.off_item = self._item("Turn VPN off", lambda: self.act("off"))
        self.redo_item = self._item("Reconnect VPN", lambda: self.act("reconnect"))
        self.prof_item = self._item("VPN profile", None)
        self.prof_menu = Gtk.Menu()
        self.prof_item.set_submenu(self.prof_menu)
        self._shown_profiles: tuple | None = None
        m.append(Gtk.SeparatorMenuItem())
        self.status_item = self._item("Status…", self.win.show_status)
        self._item("Open log", self.open_log)
        self._item("Settings…", self.win.show_settings)
        self.awake_item = Gtk.CheckMenuItem(label="Keep awake")
        m.append(self.awake_item)
        self.awake_item.set_active(self.awake.set(keepawake.load_pref()))
        self.awake_handler = self.awake_item.connect("toggled", self.on_awake)
        m.append(Gtk.SeparatorMenuItem())
        self.upd_item = self._item("Check for updates", self.on_update_click)
        self._item("About VeroScudo", self.win.show_about)
        self._item("Exit tray (guard keeps running)", self.quit)
        m.show_all()
        self.ind.set_menu(m)
        self.ind.set_secondary_activate_target(self.status_item)      # middle click: status, like the Windows left click
        self.refresh()
        self.GLib.timeout_add_seconds(3, self.refresh)
        self.GLib.timeout_add(500, self.drain)
        self.GLib.timeout_add_seconds(120, lambda: (self.check_updates(), False)[1])

    def _item(self, label: str, cb):
        it = self.Gtk.MenuItem(label=label)
        if cb:
            it.connect("activate", lambda *_: cb())
        self.menu.append(it)
        return it

    # facts
    def kind(self, name: str) -> str | None:
        if name not in self._kinds:
            self._kinds[name] = nm.kind(name)
        return self._kinds[name]

    def discover(self) -> list[dict]:
        return nm.discover()

    def events(self) -> list[str] | None:
        return traymodel.read_events()

    @property
    def awake_on(self) -> bool:
        return self.awake.active

    def reload_config(self) -> bool:
        m = traymodel.config_mtime(config_path())
        if m == self._cfg_mtime:
            return False
        self._cfg_mtime = m
        try:
            self.cfg, self.cfg_error = Config.load(active=self.store.active), ""
        except (OSError, ValueError, KeyError, TypeError) as e:
            self.cfg, self.cfg_error = None, str(e)
        self._kinds.clear()
        return True

    def collect(self) -> traymodel.Facts:
        cfg = self.cfg
        if cfg is None:
            return traymodel.Facts(configured=False, config_error=self.cfg_error, guard_running=traymodel.guard_running())
        active = self.store.active
        if active in cfg.names and active != cfg.profile:
            self.cfg = cfg = cfg.with_active(active)
        armed = self.store.armed
        up = nm.is_connected(cfg.profile) and (not armed or self.store.allowed_tunnel(cfg.profile) is not None)
        self.tunnel = (self.store.allowed_tunnel(cfg.profile) or nm.iface(cfg.profile)) if up else None
        return traymodel.Facts(name=cfg.profile, kind=self.kind(cfg.profile), armed=armed, up=up,
                               guard_running=traymodel.guard_running(), others=tuple(nm.other_tunnels(self.tunnel) if armed else ()),
                               expect=self.expect.kind)

    def refresh(self) -> bool:
        changed = self.reload_config()
        self.facts = self.collect()
        self.view = v = traymodel.tray_state(self.facts)
        if self.expect.update(v):
            notify(*traymodel.expired_notice(self.facts.name), state="blocked")
            self.facts = self.collect()
            self.view = v = traymodel.tray_state(self.facts)
        self.ind.set_icon_full(str(icon_path(v.state)), v.title)
        self.ind.set_title(traymodel.tooltip(v, self.awake.active))
        self.head.set_label(f"VeroScudo - {v.title}")
        ms = traymodel.menu_state(v)
        self.on_item.set_sensitive(ms.on and self.facts.configured)
        self.off_item.set_sensitive(ms.off)
        self.redo_item.set_sensitive(ms.reconnect)
        self.fill_profiles()
        self.switch_notice()
        n = traymodel.transition_notice(self.last, v, self.facts.expect, self.facts.name)
        if n:
            notify(*n, state=v.state)
        self.last = v.state
        if self.awake_item.get_active() != self.awake.active:          # the inhibitor died on its own
            self.awake_item.handler_block(self.awake_handler)
            self.awake_item.set_active(self.awake.active)
            self.awake_item.handler_unblock(self.awake_handler)
        self.win.update_status()
        if changed:
            self.win.update_settings()
        return True

    def fill_profiles(self) -> None:
        cfg = self.cfg
        key = (tuple(cfg.names), cfg.profile) if cfg else ()
        if key == self._shown_profiles:
            return
        self._shown_profiles = key
        for child in self.prof_menu.get_children():
            self.prof_menu.remove(child)
        if not cfg:
            self.prof_item.set_label("VPN profile")
            self.prof_item.set_sensitive(False)
            return
        self.prof_item.set_sensitive(True)
        group = None
        for name in cfg.names:
            it = self.Gtk.RadioMenuItem.new_with_label_from_widget(group, f"{name} ({kind_label(self.kind(name))})")
            group = group or it
            it.set_active(name == cfg.profile)
            it.connect("toggled", lambda w, n=name: w.get_active() and n != self.cfg.profile and self.switch(n))
            self.prof_menu.append(it)
        self.prof_item.set_label(f"VPN profile: {cfg.profile} ({kind_label(self.kind(cfg.profile))})")
        self.prof_menu.show_all()

    def switch_notice(self) -> None:
        name = self.facts.name
        if self.facts.configured and keepawake.get_pref("lastProfile") != name:       # every switch, once
            keepawake.set_pref("lastProfile", name)
            n = switch_notice(self.facts.kind, name)
            if n:
                notify("VeroScudo - WireGuard profile", n, state="blocked")

    # actions
    def act(self, action: str, arg: str | None = None) -> None:
        if action == "on":
            self.expect.start("connect")
        elif action == "reconnect":
            if not self.store.armed:
                notify("VeroScudo", "The VPN is off - use Turn VPN on.", state="off")
                return
            self.expect.start("reconnect")
            notify("VeroScudo - reconnecting", f"Traffic is blocked while '{self.facts.name}' reconnects; it flows again once "
                   "the tunnel is back.", state="blocked")
        elif action == "use":
            self.expect.start("switch")
            notify("VeroScudo", f"Switching to '{arg}'" + (" - traffic stays blocked until it is connected" if self.store.armed else ""),
                   state="blocked" if self.store.armed else "off")
        self.runner.start(action, traymodel.action_argv(action, arg))
        self.GLib.timeout_add(1500, lambda: (self.refresh(), False)[1])

    def switch(self, name: str) -> None:
        self.act("use", name)

    def toggle_on_off(self) -> None:
        self.act("off" if (self.view.armed or self.view.connected) else "on")

    def admin(self, args: list[str]) -> None:
        self.runner.start("admin:" + args[0], traymodel.admin_argv(args))

    def drain(self) -> bool:
        for tag, argv, rc, _out, err in self.runner.results():
            if rc == 0:
                if tag.startswith("admin:"):
                    self.reload_config()
                    self.win.update_settings()
                continue
            if tag.startswith("admin:") and traymodel.cancelled(rc, err):
                self.win.update_settings()                 # put the option back the way config.json has it
                continue
            what = traymodel.explain_failure(argv, rc, err)
            if tag.startswith("admin:"):
                self.win.update_settings()
                self.win.message("The change was not made", what, error=True)
            else:
                self.expect.kind = None
                notify(f"VeroScudo - {tag} failed", what, "critical")
        return True

    def copy_report(self) -> None:
        f, v = self.facts, self.view
        lines = [f"{k:<12} {val}" for k, val in traymodel.status_rows(f, v, self.awake.active, self.tunnel)]
        ev = self.events()
        text = "\n".join([f"VeroScudo {__version__} - {v.title}", *lines, "", "--- last events", *(ev or [traymodel.log_hint()])])
        cb = self.Gtk.Clipboard.get(self.Gdk.SELECTION_CLIPBOARD)
        cb.set_text(text, -1)
        cb.store()

    def open_log(self) -> None:
        if traymodel.read_events(n=1) is None:
            self.win.message("The log cannot be opened", traymodel.log_hint())
            return
        _popen(["xdg-open", str(traymodel.LOG)])

    def on_awake(self, item) -> None:
        want = item.get_active()
        held = self.awake.set(want)
        keepawake.save_pref(held)
        if want and not held:
            item.handler_block(self.awake_handler)
            item.set_active(False)
            item.handler_unblock(self.awake_handler)
            notify("Keep awake is not available", "No sleep inhibitor found (systemd-inhibit).")
        self.refresh()

    def check_updates(self, force: bool = False) -> None:
        if not force and (not self.cfg or not self.cfg.update_check):
            return
        if self.store.armed and not self.facts.up:          # blocked: nothing may leave the machine
            return
        f = keepawake.pref_file().parent / "update.json"       # the user's own folder
        info = traymodel.UpdateInfo()
        try:
            info.notified = str(json.loads(f.read_text()).get("notified", ""))
        except (OSError, ValueError, AttributeError):
            pass
        rel = update.fetch_latest()
        text, show = traymodel.update_notice(info, rel.tag if rel else None, bool(rel and update.is_newer(rel.tag)))
        self.update_tag, self.update_url = (rel.tag, rel.url) if rel and text != "Check for updates" else (None, "")
        self.upd_item.set_label(text)
        if show:
            notify(f"VeroScudo {self.update_tag} is available", f"You run {__version__}. Open the tray menu to see the release.",
                   state="protected")
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps({"checked": info.checked, "notified": info.notified}))
        except OSError:
            pass

    def on_update_click(self) -> None:
        self.check_updates(force=True)
        if self.update_url and update.is_release_url(self.update_url):
            _popen(["xdg-open", self.update_url])
        elif self.store.armed and not self.facts.up:
            notify("VeroScudo", "Traffic is blocked right now - check again once the VPN is connected.", state="blocked")
        else:
            notify("VeroScudo", f"You have the latest version ({__version__}).", state=self.view.state)

    def quit(self) -> None:
        self.awake.release()
        self.Gtk.main_quit()


# ---------------------------------------------------------------- preview: every window as a PNG, nothing changed
class _PreviewApp:
    def __init__(self, facts: traymodel.Facts) -> None:
        self.facts, self.view = facts, traymodel.tray_state(facts)
        self.cfg = Config.from_text('{"profiles":[{"profile":"CorporateVPN","server":"vpn.example.com","vpnType":"sstp"},'
                                    '{"profile":"wg-home","server":"203.0.113.9","port":51820,"protocol":"udp","vpnType":"wireguard"}],'
                                    '"activeProfile":"CorporateVPN"}')
        self.awake_on, self.tunnel = False, ("ppp0" if facts.up else None)

    def kind(self, name):
        return "wireguard" if name.startswith("wg") else "vpn"

    def events(self):
        return ["2026-11-05 09:12:01 [INFO] ARMED", "2026-11-05 09:12:01 [INFO] kill-switch armed (profile=CorporateVPN, tunnel=up)",
                "2026-11-05 10:40:13 [INFO] VPN 'CorporateVPN' terminated (user_requested=False) -> reconnect",
                "2026-11-05 10:40:23 [INFO] reconnected 'CorporateVPN' after 1 attempt(s)"]

    def discover(self):
        return [{"name": "Office L2TP", "vpn_type": "l2tp", "server": "l2tp.example.com", "port": 1701, "protocol": "udp", "note": ""},
                {"name": "Old IPsec", "vpn_type": "ikev2", "server": "", "port": 4500, "protocol": "udp", "unsupported": True,
                 "note": "policy-based IPsec has no tunnel interface - not supported by VeroScudo on Linux yet"}]

    def toggle_on_off(self):
        pass

    act = admin = copy_report = lambda *a, **k: None   # noqa: E731 - preview buttons do nothing


def preview(outdir: Path) -> int:
    Gdk, _, GLib, Gtk, _ = _gtk()
    outdir.mkdir(parents=True, exist_ok=True)

    def shot(win, name: str) -> None:
        win.show_all()
        end = time.monotonic() + 0.8
        while time.monotonic() < end:
            Gtk.main_iteration_do(False)
        gw = win.get_window()
        pb = Gdk.pixbuf_get_from_window(gw, 0, 0, gw.get_width(), gw.get_height())
        pb.savev(str(outdir / f"{name}.png"), "png", [], [])
        print(outdir / f"{name}.png")
        win.destroy()

    for name, f in {
        "status-protected": traymodel.Facts(name="CorporateVPN", kind="vpn", armed=True, up=True),
        "status-blocked": traymodel.Facts(name="CorporateVPN", kind="vpn", armed=True, up=False),
        "status-off": traymodel.Facts(name="CorporateVPN", kind="vpn"),
        "status-attention": traymodel.Facts(name="CorporateVPN", kind="vpn", armed=True, guard_running=False),
    }.items():
        w = Windows(_PreviewApp(f))
        w.show_status()
        shot(w.status, name)
    w = Windows(_PreviewApp(traymodel.Facts(name="CorporateVPN", armed=True, up=True)))
    w.show_settings()
    shot(w.settings, "settings")
    w.show_about()
    shot(w.about, "about")
    _ = GLib
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--preview"]:
        return preview(Path(argv[1] if len(argv) > 1 else "tray-preview"))
    lock = _single_instance()
    if lock is None:
        return 0
    _, _, _, Gtk, _ = _gtk()
    TrayApp()
    Gtk.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
