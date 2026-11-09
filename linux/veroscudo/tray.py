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
from datetime import datetime, timedelta
from pathlib import Path

from . import __version__, badge, exitinfo, importer, keepawake, quality, stats, statuspage, traymodel, update
from .backend import nm
from .config import Config, config_path, is_host
from .state import StateStore, kind_label, switch_notice

ICONS = traymodel.env_icons(Path("/usr/share/veroscudo/icons"))


def _runtime_base() -> Path:
    # the user's own runtime folder (Linux XDG_RUNTIME_DIR, macOS TMPDIR): never a shared /tmp another user could hold
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("TMPDIR") or f"/tmp/veroscudo-{os.getuid()}")
    base.mkdir(mode=0o700, exist_ok=True)
    return base


def _single_instance():
    """One tray per session: returns the held lock file, or None when another tray already holds it."""
    f = open(_runtime_base() / "veroscudo-tray.lock", "w")  # noqa: SIM115 - held until exit
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


def awake_icon(state: str, out: Path, size: int = 64) -> bool:
    """Writes the state icon with the keep-awake badge (badge.py) to `out`: AppIndicator takes icons by file only. False
    when it cannot be drawn - the tray then shows the plain icon."""
    _, GdkPixbuf, GLib, _, _ = _gtk()
    try:
        pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(icon_path(state)), size, size, False)
        if not pb.get_has_alpha():
            pb = pb.add_alpha(False, 0, 0, 0)
        rs, data = pb.get_rowstride(), pb.get_pixels()
        packed = b"".join(data[y * rs:y * rs + size * 4] for y in range(size))
        nb = GdkPixbuf.Pixbuf.new_from_bytes(GLib.Bytes.new(badge.awake_badge(packed, size)), GdkPixbuf.Colorspace.RGB,
                                             True, 8, size, size, size * 4)
        out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        nb.savev(str(out), "png", [], [])
        return True
    except Exception:  # noqa: BLE001 - a missing or odd icon must not stop the tray
        return False


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
        self.status = self.settings = self.about = self.stats = None

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
    def _dark(self, widget) -> bool:
        """A dark theme: the text is lighter than mid-grey (GTK 3 has no direct question for it)."""
        c = widget.get_style_context().get_color(self.Gtk.StateFlags.NORMAL)
        return (0.299 * c.red + 0.587 * c.green + 0.114 * c.blue) > 0.5

    def _toned(self, label, text: str, tone: str, dark: bool) -> None:
        """Sets a label's text in a tone's colour (traymodel.tone_colour) - the colours of the Windows status window."""
        col = traymodel.tone_colour(tone, dark)
        t = self.GLib.markup_escape_text(text)
        label.set_markup(f"<span foreground='{col}'>{t}</span>" if col else t)

    def _link(self, text: str, cb):
        """A small link (Refresh, Clear) - a label link, so it looks like the Windows tray's link labels."""
        lb = self.Gtk.Label()
        lb.set_markup(f"<small><a href='#'>{self.GLib.markup_escape_text(text)}</a></small>")
        lb.connect("activate-link", lambda *_: (cb(), True)[1])
        return lb

    def _card(self, box, refresh):
        """A full-width line in a thin frame: a small badge, the main text, a grey text on the right and a Refresh link - the
        exit location and the service status page look the same."""
        Gtk = self.Gtk
        frame = Gtk.Frame()
        row = Gtk.Box(spacing=10)
        row.set_border_width(8)
        frame.add(row)
        badge = Gtk.Label()
        css = Gtk.CssProvider()
        css.load_from_data(b"label { background-color: alpha(@theme_fg_color, 0.12); border-radius: 4px; padding: 1px 6px; }")
        badge.get_style_context().add_provider(css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        main = self._label(wrap=False)
        main.set_ellipsize(self.Pango.EllipsizeMode.END)
        right = self._label(dim=True, wrap=False, xalign=1.0)
        right.set_ellipsize(self.Pango.EllipsizeMode.END)          # a long text must not widen the window (full in the tooltip)
        row.pack_start(badge, False, False, 0)
        row.pack_start(main, True, True, 0)
        row.pack_start(right, False, False, 0)
        row.pack_start(self._link("Refresh", refresh), False, False, 0)
        box.pack_start(frame, False, False, 0)
        return frame, badge, main, right

    def show_status(self) -> None:
        self.app.status_page_opened()
        if self.status:
            self.status.present()
            return
        Gtk = self.Gtk
        w, box = self._window("VeroScudo", 480)
        head = Gtk.Box(spacing=14)
        img = Gtk.Image()
        head.pack_start(img, False, False, 0)
        tb = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title, text = self._label(markup=True), self._label(dim=True)
        tb.pack_start(title, False, False, 0)
        tb.pack_start(text, False, False, 0)
        head.pack_start(tb, True, True, 0)
        box.pack_start(head, False, False, 0)
        # where the traffic leaves the tunnel: one line under the header (Settings > Behaviour, "Show exit location")
        loc, badge, place, right = self._card(box, self.app.refresh_exit)
        # the service status page: a line like it, right under it (Settings > Connection, "Show a service status page")
        svc, sbadge, sname, sright = self._card(box, self.app.refresh_status_page)
        sright.set_max_width_chars(30)
        same = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.HORIZONTAL)    # both badges as wide: the two texts start in one column
        for b in (badge, sbadge):
            same.add_widget(b)
        sbadge_css = Gtk.CssProvider()
        sbadge.get_style_context().add_provider(sbadge_css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 1)
        grid = Gtk.Grid(column_spacing=18, row_spacing=6)
        box.pack_start(grid, False, False, 0)
        other = self._label()
        box.pack_start(other, False, False, 0)
        evh = Gtk.Box(spacing=8)
        evh.pack_start(self._label("<b>Recent events</b>", markup=True), True, True, 0)
        # Clear empties this view only: the log stays (the record of what happened; root-owned, rotates by itself).
        # Open log still shows everything.
        evh.pack_end(self._link("Clear", self.app.clear_events), False, False, 0)
        box.pack_start(evh, False, False, 0)
        tv = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        sw = Gtk.ScrolledWindow()
        sw.set_size_request(-1, 170)
        sw.set_shadow_type(Gtk.ShadowType.IN)
        sw.add(tv)
        box.pack_start(sw, True, True, 0)
        onoff, redo, _log, copy = self._buttons(
            box, ("Turn VPN on", lambda: self.app.toggle_on_off(), False), ("Reconnect", lambda: self.app.act("reconnect"), False),
            ("Open log", lambda: self.app.open_log(), False), ("Copy report", self._copy, True))
        self.status = w
        self._st = {"img": img, "title": title, "text": text, "grid": grid, "tv": tv, "sw": sw, "onoff": onoff, "redo": redo,
                    "copy": copy, "rows": None, "loc": loc, "badge": badge, "place": place, "right": right, "other": other,
                    "svc": svc, "sbadge": sbadge, "sname": sname, "sright": sright, "sbadge_css": sbadge_css, "sbadge_look": None}
        w.connect("destroy", lambda *_: setattr(self, "status", None))
        loc.show_all()
        svc.show_all()
        for x in (loc, other, badge, right, svc):            # shown or hidden by update_status only (show_all leaves them alone)
            x.set_no_show_all(True)
        w.show_all()
        self.update_status()

    def _copy(self) -> None:
        self.app.copy_report()
        self._st["copy"].set_label("Copied")

    def update_status(self) -> None:
        if not self.status:
            return
        st, app = self._st, self.app
        f, v = app.facts, app.view
        pb = self._pixbuf(icon_path(v.state), 64)
        if pb:
            st["img"].set_from_pixbuf(pb)
        dark = self._dark(st["title"])                 # asked of a label that is on screen: a new one has no theme yet
        col = traymodel.tone_colour(traymodel.title_tone(f, v), dark)
        attrs = f" foreground='{col}'" if col else ""
        st["title"].set_markup(f"<span size='x-large' weight='bold'{attrs}>{self.GLib.markup_escape_text(v.title)}</span>")
        st["text"].set_text(v.text)
        # exit location
        show = app.exit_enabled()
        st["loc"].set_visible(show)
        if show:
            xv = app.exit_view()
            st["badge"].set_visible(xv.has)
            st["right"].set_visible(xv.has)
            if xv.has:
                alpha = "100%" if xv.fresh else "60%"      # not looked up through the tunnel that is up now: grey
                st["badge"].set_markup(f"<small><b><span alpha='{alpha}'>{self.GLib.markup_escape_text(xv.code or '?')}"
                                       "</span></b></small>")
                st["place"].set_markup(f"<span alpha='{alpha}'>{self.GLib.markup_escape_text(xv.place or xv.code)}</span>")
                # a notice ('refresh failed', a refusal) is long: smaller, and the place gives way (ellipsized)
                st["place"].set_max_width_chars(12 if xv.notice else 52)
                st["right"].set_max_width_chars(29 if xv.notice else 30)
                st["right"].set_line_wrap(xv.notice)                      # a notice may take two lines, all of it shown
                st["right"].set_ellipsize(self.Pango.EllipsizeMode.NONE if xv.notice else self.Pango.EllipsizeMode.END)
                st["right"].set_markup(f"<small>{self.GLib.markup_escape_text(xv.right)}</small>" if xv.notice else
                                       self.GLib.markup_escape_text(xv.right))
                for k in ("loc", "place", "right", "badge"):
                    st[k].set_tooltip_text(xv.tip)
            else:
                st["place"].set_markup(f"<span alpha='60%'>{self.GLib.markup_escape_text(xv.text)}</span>")
                for k in ("loc", "place"):
                    st[k].set_tooltip_text(xv.tip or None)
        # the table: CONNECTION coloured by its rating with the details as a tooltip, the firewall red while blocked
        # the service status page (Settings > Connection): its own line under the exit location, None = off
        sv = app.service_view()
        st["svc"].set_visible(sv is not None)
        if sv is not None:
            bg, fg = statuspage.badge_colours(sv.tone, dark)
            look = (bg, fg)
            if look != st["sbadge_look"]:              # the exit badge's neutral background for "?", else the tone's colour
                rule = f"background-color: {bg}; color: {fg};" if bg else ""
                st["sbadge_css"].load_from_data(f"label {{ {rule} }}".encode())
                st["sbadge_look"] = look
            st["sbadge"].set_markup(f"<small><b>{self.GLib.markup_escape_text(sv.badge)}</b></small>")
            st["sname"].set_text(sv.name)
            st["sright"].set_text(sv.right)
            for k in ("svc", "sbadge", "sname", "sright"):
                st[k].set_tooltip_text(sv.tip)
        cv = traymodel.connection_view(f, v, app.cfg.check if app.cfg else None)
        tones = {"Connection": (cv.tone, cv.tip), "Firewall": (traymodel.firewall_tone(f, v), "")}
        rows = [(k, val, *tones.get(k, ("normal", "")))
                for k, val in traymodel.status_rows(f, v, app.awake_on, app.tunnel, last_drop=app.last_drop, foreign=())]
        if rows != st["rows"]:
            for child in st["grid"].get_children():
                st["grid"].remove(child)
            for i, (k, val, tone, tip) in enumerate(rows):
                st["grid"].attach(self._label(k, dim=True, wrap=False), 0, i, 1, 1)
                vl = self._label(wrap=False)
                self._toned(vl, val, tone, dark)
                if tip:
                    vl.set_tooltip_text(tip)
                st["grid"].attach(vl, 1, i, 1, 1)
            st["grid"].show_all()
            st["rows"] = rows
        other = traymodel.foreign_text(app.foreign)
        st["other"].set_visible(bool(other))
        self._toned(st["other"], f"Other VPNs: {other}" if other else "", "warn", dark)
        ev = app.events(view=True)
        text = traymodel.log_hint() if ev is None else ("\n".join(ev) or "(no events yet)")
        buf = st["tv"].get_buffer()
        if buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False) != text:
            buf.set_text(text)
            adj = st["sw"].get_vadjustment()
            self.GLib.idle_add(lambda: adj.set_value(adj.get_upper()) or False)     # newest at the bottom
        ms = traymodel.menu_state(v, f.kind)
        st["onoff"].set_label("Turn VPN off" if traymodel.offers_off(v, f.kind) else "Turn VPN on")
        st["onoff"].set_sensitive(f.configured)
        st["redo"].set_sensitive(ms.reconnect)
        st["redo"].set_tooltip_text(traymodel.RECONNECT_HIDDIFY if f.kind == "hiddify" else None)

    # settings
    def show_settings(self) -> None:
        """Three tabs, as on Windows and macOS: VPN profiles, Behaviour, Connection."""
        if self.settings:
            self.settings.present()
            return
        Gtk = self.Gtk
        w, box = self._window("VeroScudo - Settings", 560)
        nb = Gtk.Notebook()
        box.pack_start(nb, True, True, 0)

        def page(title: str):
            p = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            p.set_border_width(14)
            nb.append_page(p, Gtk.Label(label=title))
            return p

        # -- VPN profiles
        pp = page("VPN profiles")
        lb = Gtk.ListBox()
        lb.set_selection_mode(Gtk.SelectionMode.SINGLE)
        frame = Gtk.Frame()
        frame.add(lb)
        frame.set_size_request(-1, 170)
        pp.pack_start(frame, False, False, 0)
        row = Gtk.Box(spacing=8)
        for text, cb in (("Import…", self.import_dialog), ("Remove", lambda: self._on_selected("remove"))):
            b = Gtk.Button(label=text)
            b.connect("clicked", lambda _b, cb=cb: cb())
            row.pack_start(b, False, False, 0)
        pp.pack_start(row, False, False, 0)
        pp.pack_start(self._label("Profiles are the system's own VPN connections (Settings > Network > VPN); passwords "
                                  "stay with NetworkManager.", dim=True), False, False, 0)

        # -- Behaviour
        bp = page("Behaviour")

        def option(label: str, about: str, show: bool = True):
            """A short label and one grey line saying what it does - the same texts as the Windows tray."""
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            cb = Gtk.CheckButton(label=label)
            box.pack_start(cb, False, False, 0)
            d = self._label(about, dim=True)
            d.set_margin_start(26)
            box.pack_start(d, False, False, 0)
            if show:
                bp.pack_start(box, False, False, 0)
            return cb

        strict = option("Strict kill-switch (always on)",
                        "When the VPN drops, nothing leaves this computer until it is back or you turn the VPN off.")
        strict.set_active(True)
        strict.set_sensitive(False)
        vm = option("Protect VMs and containers", traymodel.VM_ABOUT)
        upd = option("Check for updates when the tray starts", traymodel.UPDATE_ABOUT)
        loc = option("Show exit location", traymodel.EXIT_ABOUT)
        bp.pack_start(self._label(traymodel.BEHAVIOUR_NOTE, dim=True), False, False, 0)

        # -- Connection
        cp = page("Connection")
        en = Gtk.CheckButton(label="Check the connection quality while protected")
        cp.pack_start(en, False, False, 0)
        more = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        cp.pack_start(more, False, False, 0)
        grid = Gtk.Grid(column_spacing=10, row_spacing=8)
        more.pack_start(grid, False, False, 0)
        lo, hi = quality.INTERVAL_RANGE
        every = Gtk.SpinButton.new_with_range(lo, hi, 1)
        lo, hi = quality.WINDOW_RANGE
        over = Gtk.SpinButton.new_with_range(lo, hi, 1)
        for r, (a, spin, b) in enumerate((("Check every", every, "seconds (10-100)"),
                                          ("Rate the last", over, "minutes (1-10)"))):
            grid.attach(self._label(a, wrap=False), 0, r, 1, 1)
            grid.attach(spin, 1, r, 1, 1)
            grid.attach(self._label(b, dim=True, wrap=False), 2, r, 1, 1)
        more.pack_start(self._label("Good: under 10 % of the checks lost. Unstable: 10-50 %. Bad: over 50 %.", dim=True),
                        False, False, 0)
        more.pack_start(self._label("<b>Addresses</b>  <span alpha='60%'>IP, host name or URL - at least one</span>",
                                    markup=True), False, False, 0)
        tgrid = Gtk.Grid(column_spacing=8, row_spacing=6)
        more.pack_start(tgrid, False, False, 0)
        rows = []
        for i in range(quality.MAX_TARGETS):
            e = Gtk.Entry()
            e.set_width_chars(26)
            e.set_placeholder_text(quality.DEFAULT_HOST if i == 0 else "optional")
            m = Gtk.ComboBoxText()
            m.append("ping", "Ping")
            m.append("tcp", "TCP port")
            m.append("https", "HTTPS")
            port = Gtk.SpinButton.new_with_range(1, 65535, 1)
            port.set_width_chars(6)
            m.connect("changed", lambda c, port=port: port.set_sensitive(c.get_active_id() in quality.PORT_METHODS))
            if i == 0:   # the first address is never empty: cleared, it is 1.1.1.1 again
                e.connect("focus-out-event", self._refill_first)
            tgrid.attach(e, 0, i, 1, 1)
            tgrid.attach(m, 1, i, 1, 1)
            tgrid.attach(port, 2, i, 1, 1)
            rows.append((e, m, port))
        more.pack_start(self._label(traymodel.CHECK_HTTPS_HINT, dim=True), False, False, 0)
        more.pack_start(self._label("The first rating comes one full period after each connect and each change here. "
                                    "The checks go through the VPN tunnel; an address in your local network is not "
                                    "reachable while the kill-switch is on (unless lanAllow lets it through).", dim=True),
                        False, False, 0)
        save = Gtk.Button(label="Save connection settings")
        save.get_style_context().add_class("suggested-action")
        save.set_halign(Gtk.Align.END)
        # the service status page: your own setting (tray.json), saved at once - below the check's Save button
        sp_about = self._label(f"<small>{self.GLib.markup_escape_text(statuspage.ABOUT)}</small>", markup=True, dim=True)
        sp_about.set_margin_start(26)
        cp.pack_end(sp_about, False, False, 0)
        sp_url = Gtk.Entry()
        sp_url.set_margin_start(26)
        sp_url.set_placeholder_text(statuspage.DEFAULT_URL)
        sp_url.set_max_length(statuspage.MAX_URL)
        cp.pack_end(sp_url, False, False, 0)
        sp = Gtk.CheckButton(label=statuspage.LABEL)
        cp.pack_end(sp, False, False, 0)
        cp.pack_end(Gtk.Separator(), False, False, 6)
        cp.pack_end(save, False, False, 0)
        more.show_all()
        more.set_no_show_all(True)                 # shown only while the check box is ticked (show_all leaves it alone)
        en.connect("toggled", lambda b: more.set_visible(b.get_active()))

        self._buttons(box, ("Close", lambda: w.destroy(), True))
        self.settings = w
        self._se = {"lb": lb, "upd": upd, "vm": vm, "loc": loc, "busy": False, "nb": nb, "en": en, "more": more, "every": every,
                    "over": over, "rows": rows, "sp": sp, "sp_url": sp_url}
        # your own settings (tray.json): saved at once, no administrator's password
        loc.connect("toggled", lambda b: self._se["busy"] or self.app.set_exit_enabled(b.get_active()))
        sp.connect("toggled", lambda b: self._se["busy"] or self.app.set_status_page(b.get_active()))
        sp_url.connect("activate", lambda e: self._save_status_url())
        sp_url.connect("focus-out-event", lambda e, _ev: self._save_status_url() and False)
        upd.connect("toggled", lambda b: self._se["busy"] or self.app.admin(["set", "updateCheck", "true" if b.get_active() else "false"]))
        vm.connect("toggled", lambda b: self._se["busy"] or self.app.admin(["set", "vm", "true" if b.get_active() else "false"]))
        save.connect("clicked", lambda _b: self._save_check())
        w.connect("destroy", lambda *_: setattr(self, "settings", None))
        self.update_settings()
        w.show_all()
        more.set_visible(en.get_active())

    @staticmethod
    def _refill_first(entry, _event) -> bool:
        if not entry.get_text().strip():
            entry.set_text(quality.DEFAULT_HOST)
        return False

    def _save_status_url(self) -> bool:
        se = self._se
        if se["busy"]:
            return False
        text = se["sp_url"].get_text().strip()
        if text == self.app.status_page_url():
            return False
        err = self.app.set_status_page_url(text)
        if err:
            se["busy"] = True
            se["sp_url"].set_text(self.app.status_page_url())       # not saved: the saved address again
            se["busy"] = False
            self.message("Not saved", err, error=True)
        return False

    def _save_check(self) -> None:
        se = self._se
        rows = [(e.get_text(), m.get_active_id() or "tcp", p.get_value_as_int()) for e, m, p in se["rows"]]
        try:
            chk = quality.from_form(se["en"].get_active(), se["every"].get_value_as_int(), se["over"].get_value_as_int(),
                                    rows, is_host)
        except ValueError as e:
            self.message("Not saved", str(e), error=True)
            return
        self.app.admin(["set", "connectionCheck", json.dumps(chk.to_json())])

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
            se["vm"].set_active(bool(cfg.vm) if cfg else True)
            se["loc"].set_active(self.app.exit_enabled())
            se["sp"].set_active(self.app.status_page_enabled())
            se["sp_url"].set_text(self.app.status_page_url())
            chk = cfg.check if cfg else quality.CheckConfig()
            se["en"].set_active(chk.enabled)
            se["more"].set_visible(chk.enabled)
            se["every"].set_value(chk.interval_seconds)
            se["over"].set_value(chk.window_minutes)
            for i, (e, m, p) in enumerate(se["rows"]):
                t = chk.targets[i] if i < len(chk.targets) else None
                e.set_text(t.host if t else "")
                m.set_active_id(t.method if t else "tcp")
                p.set_value(t.port if t and t.method in quality.PORT_METHODS else 443)
                p.set_sensitive((t.method if t else "tcp") in quality.PORT_METHODS)
        finally:
            se["busy"] = False

    def _on_selected(self, action: str) -> None:
        r = self._se["lb"].get_selected_row()
        if r is None:
            self.message("Select a profile first.")
            return
        if action == "remove" and not self.ask(*traymodel.remove_question(r.profile), "Remove"):
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
            ok = importer.importable(c) or c["note"].startswith("run as root")
            what = importer.summary(c) if ok else c["note"]
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

    # statistics: 7 days, one row per day on a 24 h grid, one bar per 10 minutes (the Windows tray's Statistics window).
    # Each day's strip is a pixel image (GdkPixbuf from bytes): no cairo binding needed (python3-gi-cairo is not always there).
    STAT_BAR, STAT_STRIP = 4, 24                                        # 144 bars x 4 px (3 px bar + 1 px gap) = 576 px

    def show_stats(self) -> None:
        if self.stats:
            self.stats.present()
            return
        Gtk = self.Gtk
        w, box = self._window("VeroScudo - Statistics", 620)
        box.pack_start(self._label("<span size='x-large' weight='bold'>Last 7 days</span>", markup=True), False, False, 0)
        box.pack_start(self._label("One bar = 10 minutes. Hover a bar for its time and numbers.", dim=True), False, False, 0)
        # one VPN profile at a time: a corporate VPN and a home one are different connections - their problems never mix
        pick = Gtk.Box(spacing=8)
        pick.pack_start(self._label("VPN profile", wrap=False), False, False, 0)
        combo = Gtk.ComboBoxText()
        pick.pack_start(combo, False, False, 0)
        box.pack_start(pick, False, False, 0)
        width = 144 * self.STAT_BAR
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.set_border_width(12)
        frame = Gtk.Frame()
        frame.add(card)
        box.pack_start(frame, False, False, 0)
        axis = Gtk.Fixed()                                               # the time grid's labels: every 3 hours
        axis.set_size_request(width, 16)
        for h in range(9):
            lb = self._label(f"<small>{h * 3:02d}</small>", markup=True, dim=True, wrap=False)
            axis.put(lb, min(max(h * 18 * self.STAT_BAR - 7, 0), width - 14), 0)
        card.pack_start(axis, False, False, 0)
        rows = []
        for _ in range(7):
            head = Gtk.Box(spacing=8)
            day = self._label("", wrap=False)
            tot = self._label("", dim=True, wrap=False, xalign=1.0)
            head.pack_start(day, False, False, 0)
            head.pack_end(tot, False, False, 0)
            img = Gtk.Image()
            ev = Gtk.EventBox()
            ev.add(img)
            ev.set_has_tooltip(True)
            card.pack_start(head, False, False, 0)
            card.pack_start(ev, False, False, 0)
            rows.append((day, tot, img, ev))
        dark = self._dark(box)
        legend = Gtk.Box(spacing=14)
        for state, text in traymodel.STATS_LEGEND:
            legend.pack_start(self._label(f"<span foreground='{self._stat_colour(state, dark)}'>\u25a0</span> <small>{text}</small>",
                                          markup=True, wrap=False), False, False, 0)
        box.pack_start(legend, False, False, 0)
        box.pack_start(self._label(traymodel.STATS_FOOT, dim=True), False, False, 0)

        def fill_choices() -> None:
            current = combo.get_active_id()
            items = self.app.stats_choices()                              # (id, label): renamed = current name
            combo.remove_all()
            for pid, label in items:
                combo.append(pid, label)
            ids = [pid for pid, _ in items]
            combo.set_active(ids.index(current) if current in ids else 0 if ids else -1)

        def fill() -> None:
            week = self.app.stats_week(combo.get_active_id() or "")
            for (day_lb, tot_lb, img, ev), (label, d) in zip(rows, week):
                day_lb.set_text(label)
                tot_lb.set_text(stats.total_text(d))
                img.set_from_pixbuf(self._strip(d, dark))
                ev.bars, ev.label = d.bars, label

        def tip(ev, x, _y, _kb, t) -> bool:
            i = x // self.STAT_BAR
            if not 0 <= i < len(getattr(ev, "bars", ())):
                return False
            t.set_text(f"{ev.label}  {stats.bar_text(ev.bars[i])}")
            return True

        for r in rows:
            r[3].connect("query-tooltip", tip)
        fill_choices()
        fill()
        combo.connect("changed", lambda *_: fill())

        def again() -> None:
            fill_choices()                                                # a profile used for the first time shows up
            fill()

        self._buttons(box, ("Refresh", again, False), ("Close", lambda: w.destroy(), True))
        timer = self.GLib.timeout_add_seconds(60, lambda: (again(), True)[1])     # the picture moves on while open
        self.stats = w
        w.connect("destroy", lambda *_: (self.GLib.source_remove(timer), setattr(self, "stats", None)))
        w.show_all()

    @staticmethod
    def _stat_colour(state: str, dark: bool) -> str:
        """The statistics palette (traymodel.stats_colour - shared with the macOS tray; Windows uses the same values)."""
        return "#{:02x}{:02x}{:02x}".format(*(traymodel.stats_colour(state, dark) or (0, 0, 0)))

    def _strip(self, day, dark: bool):
        """One day's bars as an RGBA image, with the 3-hour grid lines as dotted columns."""
        w, h, bw = 144 * self.STAT_BAR, self.STAT_STRIP, self.STAT_BAR
        px = bytearray(w * h * 4)                                        # transparent
        grid = (128, 128, 128, 110)

        def put(x: int, y: int, c: tuple) -> None:
            o = (y * w + x) * 4
            px[o:o + 4] = bytes(c)

        for b in day.bars:
            if b.state == "future":
                continue
            hx = self._stat_colour(b.state, dark)
            c = (int(hx[1:3], 16), int(hx[3:5], 16), int(hx[5:7], 16), 255)
            x0 = (b.start // 10) * bw
            row = bytes(c) * (bw - 1)
            for y in range(h):
                o = (y * w + x0) * 4
                px[o:o + len(row)] = row
        for k in range(1, 8):                                            # 03 ... 21 (00 and 24 are the edges)
            for y in range(0, h, 3):
                put(k * 18 * bw - 1, y, grid)
        return self.GdkPixbuf.Pixbuf.new_from_bytes(self.GLib.Bytes.new(bytes(px)), self.GdkPixbuf.Colorspace.RGB, True, 8,
                                                    w, h, w * 4)

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
        d.set_default_response(Gtk.ResponseType.CANCEL)          # Enter never confirms a removal by accident
        r = d.run()
        d.destroy()
        return r == Gtk.ResponseType.OK

    _ANSWERS = (("cancel", -6), ("anyway", 1), ("disconnect", 2))     # -6: Gtk.ResponseType.CANCEL

    def foreign_dialog(self, prompt: traymodel.Prompt):
        """Before Turn on, when another VPN is connected (traymodel.foreign_prompt decides the text and the buttons)."""
        Gtk = self.Gtk
        d = Gtk.MessageDialog(message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.NONE,
                              text="Another VPN is connected")
        d.set_title(prompt.title)
        d.format_secondary_text(prompt.text)
        for answer, label, primary in prompt.buttons:
            b = d.add_button(label, dict(self._ANSWERS)[answer])
            if primary:
                b.get_style_context().add_class("suggested-action")
        d.set_default_response(dict(self._ANSWERS)["cancel"])
        d.set_keep_above(True)
        return d

    def choose_foreign(self, prompt: traymodel.Prompt) -> str:
        """'disconnect' | 'anyway' | 'cancel' - nothing happens without a click."""
        d = self.foreign_dialog(prompt)
        r = d.run()
        d.destroy()
        return next((a for a, code in self._ANSWERS if code == r), "cancel")


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
        self.exit = exitinfo.ExitFetch()
        self.protected_since = 0.0
        self._was_up = False
        self.status_page = statuspage.StatusFetch()
        self.foreign: list[traymodel.Foreign] = []
        self._foreign_at = 0.0
        self._foreign_shown: set = set()
        self.last_drop = "-"
        self._badged: dict[str, str] = {}
        self.win = Windows(self)
        self.reload_config()

        Gtk = self.Gtk
        self.ind = AppIndicator.Indicator.new("veroscudo", str(icon_path("off")), AppIndicator.IndicatorCategory.APPLICATION_STATUS)
        self.ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        m = self.menu = Gtk.Menu()
        self.head = self._item("VeroScudo", None)
        self.head.set_sensitive(False)
        m.append(Gtk.SeparatorMenuItem())
        self.on_item = self._item("Turn VPN on", self.request_on)
        self.off_item = self._item("Turn VPN off", lambda: self.act("off"))
        self.redo_item = self._item("Reconnect VPN", lambda: self.act("reconnect"))
        self.prof_item = self._item("VPN profile", None)
        self.prof_menu = Gtk.Menu()
        self.prof_item.set_submenu(self.prof_menu)
        self._shown_profiles: tuple | None = None
        m.append(Gtk.SeparatorMenuItem())
        self.status_item = self._item("Status…", self.win.show_status)
        self._item("Open log", self.open_log)
        self._item("Statistics…", self.win.show_stats)
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

    def events(self, view: bool = False) -> list[str] | None:
        """The newest log lines; view=True: as the status window shows them (after Clear, without dates)."""
        ev = traymodel.read_events()
        if view and ev is not None:
            return traymodel.filter_events(ev, str(keepawake.get_pref("eventsClearedAt", "") or ""))
        return ev

    def clear_events(self) -> None:
        keepawake.set_pref("eventsClearedAt", traymodel.clear_stamp())
        self.win.update_status()

    # exit location (exitinfo.py)
    def stats_week(self, pid: str) -> list:
        return stats.week(self.store.state, pid)

    def stats_choices(self) -> list[tuple[str, str]]:
        cfg = self.cfg
        return stats.choices(stats.profiles_seen(self.store.state), [(p.id, p.name) for p in cfg.profiles] if cfg else [],
                             cfg.current.id if cfg else None)

    def exit_enabled(self) -> bool:
        return self.exit.enabled()

    def set_exit_enabled(self, on: bool) -> None:
        keepawake.set_pref("showExit", bool(on))
        self.win.update_status()

    def exit_view(self) -> exitinfo.ExitView:
        return exitinfo.exit_view(self.exit.info(), self.view.state, self.facts.name, self.protected_since,
                                  self.exit.checking, self.exit.failure, refused=self.exit.refused, tunnel_up=self.facts.up,
                                  kind=self.facts.kind)

    def refresh_exit(self) -> None:
        """The Refresh link: asked whenever a VPN tunnel is up - otherwise the answer would show your real address."""
        self.exit.refresh(self.facts.name, self.facts.up)
        self.win.update_status()

    # service status page (statuspage.py)
    def service_view(self) -> statuspage.ServiceView | None:
        return self.status_page.view()

    def status_page_enabled(self) -> bool:
        return self.status_page.enabled()

    def status_page_url(self) -> str:
        return self.status_page.url()

    def set_status_page(self, on: bool) -> None:
        self.status_page.set_enabled(on)
        self.win.update_status()

    def set_status_page_url(self, url: str) -> str:
        err = self.status_page.set_url(url)
        self.win.update_status()
        return err

    def status_page_opened(self) -> None:
        """The status window opened: nothing to fetch - the status page is looked at after each connect and on Refresh."""

    def refresh_status_page(self) -> None:
        """The service card's Refresh link: a fetch now; "checking..." until it ends."""
        self.status_page.refresh()
        self.win.update_status()

    def find_foreign(self, force: bool = False) -> list[traymodel.Foreign]:
        """Other VPNs next to the active profile; asked at most every 10 s (the window refreshes every 3 s)."""
        if force or time.time() - self._foreign_at >= 10:
            self._foreign_at = time.time()
            cfg = self.cfg
            own = self.tunnel
            tunnels = nm.other_tunnels(own)
            try:
                owners = nm.tunnel_owners()
            except (OSError, subprocess.SubprocessError):
                owners = {}
            self.foreign = traymodel.foreign_list(tunnels, owners, own, cfg.profile if cfg else "", cfg.names if cfg else ())
        return self.foreign

    def icon_file(self, state: str, awake: bool) -> str:
        """The state icon, with the keep-awake badge while Keep awake is on (drawn once per state, kept in the user's
        runtime folder)."""
        plain = str(icon_path(state))
        if not awake:
            return plain
        if state not in self._badged:
            out = _runtime_base() / "veroscudo-icons" / f"{state}-awake.png"
            self._badged[state] = str(out) if awake_icon(state, out) else plain
        return self._badged[state]

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
        foreign = self.find_foreign()
        self.last_drop = traymodel.last_drop_text(self.store.last_drop(), cfg.profile)
        return traymodel.Facts(name=cfg.profile, kind=self.kind(cfg.profile), armed=armed, up=up,
                               guard_running=traymodel.guard_running(), others=tuple(x.name for x in foreign) if armed else (),
                               expect=self.expect.kind, check_enabled=cfg.check.enabled,
                               quality=quality.read(self.store.home / "quality.json", cfg.profile) if cfg.check.enabled else None,
                               auth=self.store.auth_failed(cfg.profile))

    def refresh(self) -> bool:
        changed = self.reload_config()
        self.facts = self.collect()
        self.view = v = traymodel.tray_state(self.facts)
        if traymodel.turned_on_elsewhere(self.last, v, self.expect.kind):
            self.expect.start("connect")
            self.facts = self.collect()
            self.view = v = traymodel.tray_state(self.facts)
        if self.expect.update(v):
            notify(*traymodel.expired_notice(self.facts.name), state="blocked")
            self.facts = self.collect()
            self.view = v = traymodel.tray_state(self.facts)
        if self.facts.up and not self._was_up:                         # a tunnel came up: older lookups are not fresh
            self.protected_since, self.exit.refused = time.time(), ""
        self._was_up = self.facts.up
        if v.state == "protected" and self.last != "protected":        # each (re)connect: once, through the new tunnel
            self.protected_since = time.time()
            self.exit.start(self.facts.name)
            self.status_page.on_connected()                            # the service status too - the same rule
        self.exit.poll()
        self.status_page.tick()
        self.ind.set_icon_full(self.icon_file(v.state, self.awake.active), v.title)
        self.ind.set_title(traymodel.tooltip(v, self.awake.active, self.facts))
        self.head.set_label(traymodel.menu_head(v, self.facts))
        ms = traymodel.menu_state(v, self.facts.kind)
        self.on_item.set_sensitive(ms.on and self.facts.configured)
        self.off_item.set_sensitive(ms.off)
        self.redo_item.set_sensitive(ms.reconnect)
        self.redo_item.set_tooltip_text(traymodel.RECONNECT_HIDDIFY if self.facts.kind == "hiddify" else None)
        self.fill_profiles()
        noticed = self.switch_notice() or self.foreign_notice(v)
        n = None if noticed else traymodel.transition_notice(self.last, v, self.facts.expect, self.facts.name)
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

    def switch_notice(self) -> bool:
        name = self.facts.name
        if self.facts.configured and keepawake.get_pref("lastProfile") != name:       # every switch, once
            keepawake.set_pref("lastProfile", name)
            n = switch_notice(self.facts.kind, name)
            if n:
                notify("VeroScudo - WireGuard profile", n, state="blocked")
                return True
        return False

    def foreign_notice(self, v: traymodel.View) -> bool:
        """Another VPN connected while VeroScudo is on: once per detection (it is blocked - say so, and what to do)."""
        if not v.armed:
            self._foreign_shown = set()
            return False
        new, self._foreign_shown = traymodel.new_foreign(self._foreign_shown, self.foreign)
        if new:
            notify(*traymodel.foreign_notice(new[0]), "critical", state="attention")
            return True
        return False

    # actions
    def request_on(self) -> None:
        """Turn VPN on: first asks when another VPN is connected (it would be blocked silently otherwise)."""
        if not self.cfg:
            self.act("on")
            return
        foreign = self.find_foreign(force=True)
        if not foreign:
            self.act("on")
            return
        answer = self.win.choose_foreign(traymodel.foreign_prompt(foreign, self.cfg.profile))
        self._foreign_shown = {x.iface for x in foreign}            # just seen in the question: no notice for them again
        if answer == "disconnect":
            self.act("on", before=[nm.down_argv(x.connection) for x in foreign if x.connection])
        elif answer == "anyway":
            self.act("on")

    def act(self, action: str, arg: str | None = None, before: list[list[str]] | None = None) -> None:
        if action == "on":
            self.expect.start("connect")
        elif action == "reconnect":
            if self.facts.kind == "hiddify":
                notify("VeroScudo", traymodel.RECONNECT_HIDDIFY, state="blocked" if self.store.armed else "off")
                return
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
        # `before`: other VPNs to disconnect first (as you, through NetworkManager); a failure stops before the turn on
        self.runner.start(action, *(before or []), traymodel.action_argv(action, arg))
        self.GLib.timeout_add(1500, lambda: (self.refresh(), False)[1])

    def switch(self, name: str) -> None:
        self.act("use", name)

    def toggle_on_off(self) -> None:
        if traymodel.offers_off(self.view, self.facts.kind):
            self.act("off")
        else:
            self.request_on()

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
        xl = exitinfo.report_line(self.exit_view()) if self.exit_enabled() else None
        sv = self.service_view()
        lines = [f"{k:<12} {val}" for k, val in traymodel.status_rows(f, v, self.awake.active, self.tunnel, last_drop=self.last_drop,
                                                                     foreign=self.find_foreign(), exit_line=xl,
                                                                     service=sv.text if sv else None)]
        ev = traymodel.read_events(n=15)
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
PREVIEW_EXIT = {"ip": "203.0.113.25", "city": "Example City", "country": "PL", "org": "AS64500 Example Net",
                "source": "ipinfo.io", "profile": "CorporateVPN", "time": "2026-11-05T10:33:00+00:00"}


class _PreviewApp:
    def __init__(self, facts: traymodel.Facts, foreign=(), exit_info=PREVIEW_EXIT, checking=False, exit_fresh=True,
                 exit_failure="", exit_refused="", service=None) -> None:
        self.facts, self.view = facts, traymodel.tray_state(facts)
        self.cfg = Config.from_text('{"profiles":[{"profile":"CorporateVPN","server":"vpn.example.com","vpnType":"sstp"},'
                                    '{"profile":"wg-home","server":"203.0.113.9","port":51820,"protocol":"udp","vpnType":"wireguard"}],'
                                    '"activeProfile":"CorporateVPN","connectionCheck":{"enabled":true,"intervalSeconds":10,'
                                    '"windowMinutes":2,"targets":[{"host":"1.1.1.1","method":"tcp","port":443},'
                                    '{"host":"10.0.0.1","method":"ping"},{"host":"api.example.com","method":"https",'
                                    '"port":443}]}}')
        self.awake_on, self.tunnel = False, ("ppp0" if facts.up else None)
        self.foreign = list(foreign)
        self.last_drop = "10:40 - connection lost"
        self._exit, self._checking, self._fresh = exit_info, checking, exit_fresh
        self._failure, self._refused, self._service = exit_failure, exit_refused, service

    def kind(self, name):
        return "wireguard" if name.startswith("wg") else "vpn"

    def events(self, view=False):
        ev = ["2026-11-05 09:12:01,114 [INFO] ARMED",
              "2026-11-05 09:12:01,220 [INFO] kill-switch armed (profile=CorporateVPN, tunnel=up)",
              "2026-11-05 10:40:13,031 [INFO] VPN 'CorporateVPN' terminated (user_requested=False) -> reconnect",
              "2026-11-05 10:40:23,502 [INFO] reconnected 'CorporateVPN' after 1 attempt(s)"]
        return traymodel.filter_events(ev) if view else ev

    def exit_enabled(self):
        return True

    def stats_choices(self):
        return [("a1", "CorporateVPN"), ("b2", "wg-home"), ("c3", "old-office (removed)")]

    def stats_week(self, profile=""):
        """A made-up week: a lunch-time problem every day, a bad half hour, an evening without VPN, one day with the check off,
        and a morning VeroScudo was on but could not connect (red)."""
        now = datetime(2026, 11, 7, 17, 25)
        rows = []
        for i in range(7):
            m = {}
            for t in range(8 * 60, 19 * 60 + 30):
                if (i == 4 and t > 15 * 60) or (i == 0 and t > now.hour * 60 + now.minute):
                    break
                lost = int(t % 3 == 0) if 12 * 60 + 40 <= t < 13 * 60 + 20 else 3 if (i == 2 and 16 * 60 <= t < 16 * 60 + 30) \
                    else int((t * 7 + i) % 41 == 0)
                down = i == 1 and 9 * 60 + 5 <= t < 9 * 60 + 47                 # on, but the redial kept failing
                m[t] = (0, 0, down) if i == 5 or down else (3, min(lost, 3))
            d = now.date() - timedelta(days=i)
            rows.append((stats.day_label(d, now.date()), stats.day_row(m, until=now.hour * 60 + now.minute + 1 if i == 0 else 1440)))
        return rows

    def exit_view(self):
        return exitinfo.exit_view(self._exit, self.view.state, self.facts.name, checking=self._checking, preview=self._fresh,
                                  failure=self._failure, refused=self._refused, tunnel_up=self.facts.up, kind=self.facts.kind)

    def service_view(self):
        return self._service

    def status_page_enabled(self):
        return True

    def status_page_url(self):
        return statuspage.DEFAULT_URL

    def discover(self):
        return [{"name": "Office L2TP", "vpn_type": "l2tp", "server": "l2tp.example.com", "port": 1701, "protocol": "udp", "note": ""},
                {"name": "Old IPsec", "vpn_type": "ikev2", "server": "", "port": 4500, "protocol": "udp", "unsupported": True,
                 "note": "policy-based IPsec has no tunnel interface - not supported by VeroScudo on Linux yet"}]

    def toggle_on_off(self):
        pass

    act = admin = copy_report = open_log = refresh_exit = clear_events = set_exit_enabled = lambda *a, **k: None
    set_status_page = status_page_opened = refresh_status_page = lambda *a, **k: None
    set_status_page_url = lambda *a, **k: ""


def preview(outdir: Path) -> int:
    Gdk, _, GLib, Gtk, _ = _gtk()
    outdir.mkdir(parents=True, exist_ok=True)

    def shot(win, name: str) -> None:
        win.show()
        end = time.monotonic() + 0.8
        while time.monotonic() < end:
            Gtk.main_iteration_do(False)
        gw = win.get_window()
        pb = Gdk.pixbuf_get_from_window(gw, 0, 0, gw.get_width(), gw.get_height())
        pb.savev(str(outdir / f"{name}.png"), "png", [], [])
        print(outdir / f"{name}.png")
        win.destroy()

    wg = traymodel.Foreign("example-wireguard", "wg1", "example-wireguard", False)
    app_tun = traymodel.Foreign("tun1", "tun1", None, False)
    other_profile = traymodel.Foreign("wg-home", "wg0", "wg-home", True)
    prot = {"name": "CorporateVPN", "kind": "vpn", "armed": True, "up": True}
    up_at = time.time() - 600
    ok = statuspage.service_view({"name": "Example Service", "indicator": "none", "description": "All Systems Operational"},
                                 statuspage.DEFAULT_URL, up_at)
    minor = statuspage.service_view({"name": "Example Service", "indicator": "minor", "description": "Partially Degraded Service"},
                                    statuspage.DEFAULT_URL, up_at)
    gone = statuspage.service_view({"error": "timed out"}, statuspage.DEFAULT_URL, up_at)
    major = statuspage.service_view({"name": "Example Service", "indicator": "major", "description": "Major Outage"},
                                    statuspage.DEFAULT_URL, up_at)
    first = statuspage.service_view(None, statuspage.DEFAULT_URL)
    q3 = quality.Quality("unstable", 22.2, 310, 18, 4, (("1.1.1.1:443", 6, 0), ("10.0.0.1 (ping)", 6, 4),
                                                       ("api.example.com (HTTPS)", 6, 0)))
    for name, (f, kw) in {
        "status-service-ok": (traymodel.Facts(**prot, check_enabled=True, quality=q3), {"service": ok}),
        "status-service-minor": (traymodel.Facts(**prot), {"service": minor}),
        "status-service-unreachable": (traymodel.Facts(**prot), {"service": gone}),
        "status-service-major": (traymodel.Facts(**prot), {"service": major}),
        "status-service-checking": (traymodel.Facts(**prot), {"service": first}),
        "status-service-off": (traymodel.Facts(**prot), {"service": None}),
        "status-exit-refresh-failed": (traymodel.Facts(**prot), {"exit_failure": "ipinfo.io: timed out / cloudflare.com: timed out",
                                                                 "exit_fresh": False}),
        "status-exit-refused": (traymodel.Facts(name="CorporateVPN", kind="vpn"), {"exit_refused": exitinfo.NO_TUNNEL,
                                                                                  "exit_fresh": False}),
        "status-exit-hiddify": (traymodel.Facts(name="Hiddify", kind="hiddify", armed=True, up=True), {}),
        "status-protected": (traymodel.Facts(**prot), {}),
        "status-protected-good": (traymodel.Facts(**prot, check_enabled=True, quality=quality.Quality("good", 0.0, 45, 18, 0)), {}),
        "status-protected-unstable": (traymodel.Facts(**prot, check_enabled=True,
                                                      quality=quality.Quality("unstable", 22.2, 310, 18, 4)), {}),
        "status-protected-bad": (traymodel.Facts(**prot, check_enabled=True, quality=quality.Quality("bad", 61.1, 900, 18, 11)), {}),
        "status-protected-other-vpn": (traymodel.Facts(**prot, others=("example-wireguard", "tun1")), {"foreign": (wg, app_tun)}),
        "status-exit-checking": (traymodel.Facts(**prot), {"checking": True, "exit_info": None}),
        "status-blocked": (traymodel.Facts(name="CorporateVPN", kind="vpn", armed=True, up=False), {"exit_fresh": False}),
        "status-connecting": (traymodel.Facts(name="CorporateVPN", kind="vpn", armed=True, up=False, expect="connect"),
                              {"exit_fresh": False}),
        "status-off": (traymodel.Facts(name="CorporateVPN", kind="vpn"), {"exit_fresh": False}),
        "status-attention": (traymodel.Facts(name="CorporateVPN", kind="vpn", armed=True, guard_running=False), {"exit_fresh": False}),
    }.items():
        w = Windows(_PreviewApp(f, **kw))
        w.show_status()
        shot(w.status, name)
    w = Windows(_PreviewApp(traymodel.Facts(name="CorporateVPN", armed=True, up=True)))
    for i, tab in enumerate(("profiles", "behaviour", "connection")):
        w.show_settings()
        if tab == "connection":
            w._se["en"].set_active(True)
        w._se["nb"].set_current_page(i)
        shot(w.settings, f"settings-{tab}")
    w.show_about()
    shot(w.about, "about")
    w.show_stats()
    shot(w.stats, "stats")
    # dialogs, built as the tray shows them (never run: nothing is answered)
    for name, fl in {"foreign-one": [wg], "foreign-profile": [other_profile], "foreign-app": [app_tun],
                     "foreign-mixed": [wg, app_tun]}.items():
        shot(w.foreign_dialog(traymodel.foreign_prompt(fl, "CorporateVPN")), name)
    d = Gtk.MessageDialog(message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.NONE,
                          text=traymodel.remove_question("wg-home")[0])
    d.format_secondary_text(traymodel.remove_question("wg-home")[1])
    d.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Remove", Gtk.ResponseType.OK)
    shot(d, "msg-remove")
    # the tray icons with the keep-awake badge (and without, for comparison)
    for st in traymodel.STATES:
        if awake_icon(st, outdir / f"icon-{st}-awake.png", 64):
            print(outdir / f"icon-{st}-awake.png")
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
