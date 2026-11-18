"""macOS menu-bar app (AppKit through PyObjC): the same menu, windows and decisions as the Windows and Linux trays.

Runs as the signed-in user, started at login by /Library/LaunchAgents/com.gomelhawk.veroscudo.tray.plist (or by opening
/Applications/VeroScudo.app). on / off / reconnect / use go through the sudoers rule install.sh writes (`sudo -n`, by full
path); a change to config.json or the uninstall asks for an administrator's password (the macOS password dialog). What
it shows and says is decided in traymodel.py, exitinfo.py and stats.py (shared with tray.py, unit-tested). PyObjC is
installed by install.sh into /opt/veroscudo/tray-lib - the root daemon never loads it.

A click on the menu-bar icon opens the menu (the macOS habit); an Option-click opens the Status window (the Windows
tray's left click)."""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import objc  # type: ignore
from AppKit import (  # type: ignore
    NSAlert,
    NSAlertFirstButtonReturn,
    NSAlertSecondButtonReturn,
    NSAlertThirdButtonReturn,
    NSAppearanceNameAqua,
    NSAppearanceNameDarkAqua,
    NSApplication,
    NSApplicationActivationPolicyAccessory,
    NSBackingStoreBuffered,
    NSBezierPath,
    NSBox,
    NSButton,
    NSColor,
    NSCompositingOperationSourceOver,
    NSEventMaskLeftMouseDown,
    NSEventMaskRightMouseDown,
    NSEventModifierFlagOption,
    NSEventTypeLeftMouseDown,
    NSFont,
    NSFontAttributeName,
    NSForegroundColorAttributeName,
    NSImage,
    NSImageView,
    NSLineBreakByTruncatingTail,
    NSMakeRect,
    NSMenu,
    NSMenuItem,
    NSOffState,
    NSOnState,
    NSPasteboard,
    NSPasteboardTypeString,
    NSPopUpButton,
    NSScrollView,
    NSStatusBar,
    NSTabView,
    NSTabViewItem,
    NSTextAlignmentCenter,
    NSTextAlignmentRight,
    NSTextField,
    NSTextView,
    NSTrackingActiveAlways,
    NSTrackingArea,
    NSTrackingInVisibleRect,
    NSTrackingMouseEnteredAndExited,
    NSTrackingMouseMoved,
    NSVariableStatusItemLength,
    NSView,
    NSWindow,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskTitled,
    NSZeroRect,
)
from Foundation import (  # type: ignore
    NSAttributedString,
    NSObject,
    NSRunLoop,
    NSRunLoopCommonModes,
    NSString,
    NSTimer,
)
from PyObjCTools import AppHelper  # type: ignore

from . import __version__, importer, keepawake, quality, stats, statuspage, traymodel
from .backend import nm
from .state import kind_label

ICONS = traymodel.env_icons(Path("/opt/veroscudo/icons"))
CONNECTION_NOTE = ("The first rating comes one full period after each connect and each change here. The checks go through "
                   "the VPN tunnel; an address in your local network is not reachable while the kill-switch is on (unless "
                   "lanAllow lets it through).")
METHODS = ("ping", "tcp", "https")                   # the order of the method pop-up
METHOD_TITLES = ("Ping", "TCP port", "HTTPS")


def method_of(index: int) -> str:
    """The method pop-up's item -> the config's method (TCP when nothing sensible is selected). Pure."""
    return METHODS[index] if 0 <= index < len(METHODS) else "tcp"


def notify(title: str, body: str) -> None:
    """A macOS notification; title and body are passed as data (argv), never as AppleScript text."""
    try:
        subprocess.Popen(["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                          "-e", "end run", title, body], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def _popen(argv: list[str]) -> None:
    try:
        subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def _image(name: str, size: float):
    img = NSImage.alloc().initWithContentsOfFile_(str(ICONS / f"{name}.png"))
    if img is not None:
        img.setSize_((size, size))
    return img


def _with_badge(base, size: float):
    """The state icon with the keep-awake badge (traymodel.awake_rings: badge.py's geometry, the Windows mark), drawn as
    vector shapes on demand - sharp on Retina. The plain icon when it cannot be drawn."""
    rings = traymodel.awake_rings(size)

    def draw(rect):
        base.drawInRect_fromRect_operation_fraction_(NSMakeRect(0, 0, size, size), NSZeroRect, NSCompositingOperationSourceOver, 1.0)
        for rgb, cx, cy, r in rings:
            _rgb(rgb).set()
            NSBezierPath.bezierPathWithOvalInRect_(NSMakeRect(cx - r, (size - cy) - r, 2 * r, 2 * r)).fill()
        return True
    try:
        return NSImage.imageWithSize_flipped_drawingHandler_((size, size), False, draw)
    except Exception:  # noqa: BLE001 - a missing or odd icon must not stop the tray
        return base


def _rgb(rgb, alpha: float = 1.0):
    return NSColor.colorWithSRGBRed_green_blue_alpha_(rgb[0] / 255.0, rgb[1] / 255.0, rgb[2] / 255.0, alpha)


def _tone(tone: str, dark: bool):
    """A tone's colour (traymodel.tone_colour, the Windows status window's colours); the normal text colour otherwise."""
    col = traymodel.tone_colour(tone, dark)
    return _rgb(traymodel.hex_rgb(col)) if col else NSColor.labelColor()


def _dark() -> bool:
    """Dark mode is on (System Settings > Appearance)."""
    try:
        ap = NSApplication.sharedApplication().effectiveAppearance()
        return str(ap.bestMatchFromAppearancesWithNames_([NSAppearanceNameAqua, NSAppearanceNameDarkAqua])) == str(NSAppearanceNameDarkAqua)
    except Exception:  # noqa: BLE001 - before macOS 10.14 there is no dark mode
        return False


def _small_font():
    return NSFont.systemFontOfSize_(NSFont.smallSystemFontSize())


def _draw_text(text: str, x: float, y: float, font, colour) -> None:
    NSString.stringWithString_(text).drawAtPoint_withAttributes_((x, y), {NSFontAttributeName: font,
                                                                            NSForegroundColorAttributeName: colour})


def _text_width(text: str, font) -> float:
    return float(NSString.stringWithString_(text).sizeWithAttributes_({NSFontAttributeName: font}).width)


class FlippedView(NSView):
    """A view laid out top-down, like the Windows and GTK windows."""

    def isFlipped(self):
        return True


class StatsChart(NSView):
    """The Statistics card: a 24 h grid (dotted lines every 3 h), one row per day, 144 bars of 10 minutes each - the
    geometry of the Windows chart (traymodel.STATS_GEOMETRY). Hovering a bar shows its time and numbers."""

    def isFlipped(self):
        return True

    @objc.python_method
    def setup(self, on_hover):
        self.days, self.on_hover, self.hovered = [], on_hover, ""
        opts = NSTrackingMouseMoved | NSTrackingMouseEnteredAndExited | NSTrackingActiveAlways | NSTrackingInVisibleRect
        self.addTrackingArea_(NSTrackingArea.alloc().initWithRect_options_owner_userInfo_(self.bounds(), opts, self, None))

    def drawRect_(self, _rect):
        self.draw()

    @objc.python_method
    def draw(self):
        g = traymodel.STATS_GEOMETRY
        dark = _dark()
        small, ui = _small_font(), NSFont.systemFontOfSize_(13)
        sub, txt = NSColor.secondaryLabelColor(), NSColor.labelColor()
        NSColor.controlBackgroundColor().set()
        NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(self.bounds(), 8, 8).fill()
        grid = NSBezierPath.bezierPath()
        grid.setLineWidth_(1.0)
        grid.setLineDash_count_phase_([1.0, 2.0], 2, 0.0)
        bottom = g["top"] + 7 * g["row_h"] - 8
        for x, lab in traymodel.stats_grid():
            w = _text_width(lab, small)
            _draw_text(lab, min(max(x - w / 2, 0), g["width"] - w), 8, small, sub)
            grid.moveToPoint_((x + 0.5, g["top"] - 4))
            grid.lineToPoint_((x + 0.5, bottom))
        NSColor.separatorColor().set()
        grid.stroke()
        colours = {}
        for i, (label, day) in enumerate(getattr(self, "days", [])):
            y = g["top"] + i * g["row_h"]
            _draw_text(label, g["x"] - 2, y, ui, txt)
            tot = stats.total_text(day)
            _draw_text(tot, g["x"] + 144 * g["bar_w"] - _text_width(tot, small), y + 2, small, sub)
            by = y + g["label_h"] + 2
            for b in day.bars:
                rgb = traymodel.stats_colour(b.state, dark)
                if rgb is None:                                  # future: not drawn
                    continue
                if rgb not in colours:
                    colours[rgb] = _rgb(rgb)
                colours[rgb].set()
                NSBezierPath.fillRect_(NSMakeRect(g["x"] + (b.start // stats.BUCKET_MINUTES) * g["bar_w"], by,
                                                  g["bar_w"] - 1, g["strip_h"]))

    def mouseMoved_(self, event):
        p = self.convertPoint_fromView_(event.locationInWindow(), None)
        self.hover(p.x, p.y)

    def mouseExited_(self, _event):
        self.hover(-1, -1)

    @objc.python_method
    def hover(self, x, y):
        days = getattr(self, "days", [])
        hit = traymodel.stats_hit(x, y, len(days))
        text = f"{days[hit[0]][0]}  {stats.bar_text(days[hit[0]][1].bars[hit[1]])}" if hit else ""
        if text != self.hovered:
            self.hovered = text
            self.setToolTip_(text or None)
            self.on_hover(text)


class Tray(NSObject):
    def init(self):
        self = objc.super(Tray, self).init()     # noqa: PLW0642 - PyObjC's init pattern: init may return another object
        if self is None:
            return None
        self.shown_profiles = None
        self.icons = {}
        self.win = None                          # the Settings window (three tabs, as on Windows and Linux)
        self.win_ui = {}
        self.st_win = None                       # the Status window
        self.st = {}
        self.stats_win = None                    # the Statistics window
        self.stats_ui = {}
        # what happens is decided in traymodel.TrayController; this object is its `ui` (the hooks below), it draws
        self.ctl = traymodel.TrayController(nm, self, menu_name="menu-bar menu", refresh_after_admin=True)
        self.ctl.reload_config()
        self.item = NSStatusBar.systemStatusBar().statusItemWithLength_(NSVariableStatusItemLength)
        self.menu = NSMenu.alloc().init()
        self.menu.setAutoenablesItems_(False)
        self.menu.setDelegate_(self)
        self.head = self.add("VeroScudo", None)
        self.head.setEnabled_(False)
        self.menu.addItem_(NSMenuItem.separatorItem())
        self.on_item = self.add("Turn VPN on", "turnOn:")
        self.off_item = self.add("Turn VPN off", "turnOff:")
        self.redo_item = self.add("Reconnect VPN", "reconnect:")
        self.prof_item = self.add("VPN profile", None)
        self.prof_menu = NSMenu.alloc().init()
        self.prof_menu.setAutoenablesItems_(False)
        self.prof_item.setSubmenu_(self.prof_menu)
        self.menu.addItem_(NSMenuItem.separatorItem())
        self.add("Status…", "status:")
        self.add("Open log", "openLog:")
        self.add("Statistics…", "statistics:")
        self.add("Settings…", "settings:")
        self.awake_item = self.add("Keep awake", "toggleAwake:")
        self.awake_item.setState_(NSOnState if self.ctl.awake.set(keepawake.load_pref()) else NSOffState)
        self.menu.addItem_(NSMenuItem.separatorItem())
        self.upd_item = self.add("Check for updates", "checkUpdates:")
        self.add("About VeroScudo", "about:")
        self.add("Exit menu-bar icon (guard keeps running)", "quit:")
        # the menu is attached only while it is open (iconClick_ / menuDidClose_): with a menu attached for good the
        # icon's own action never runs, and Option-click could not open the Status window
        btn = self.item.button()
        btn.setTarget_(self)
        btn.setAction_("iconClick:")
        btn.sendActionOn_(NSEventMaskLeftMouseDown | NSEventMaskRightMouseDown)
        self.ctl.refresh()
        # in the common run-loop modes: a timer of the default mode alone does not fire while an alert or a menu is open,
        # and the icon would stop following the guard for as long as it stays open
        for seconds, selector, repeats in ((3.0, "tick:", True), (0.5, "drain:", True), (120.0, "autoUpdate:", False),
                                           (60.0, "statsTick:", True)):
            timer = NSTimer.timerWithTimeInterval_target_selector_userInfo_repeats_(seconds, self, selector, None, repeats)
            NSRunLoop.currentRunLoop().addTimer_forMode_(timer, NSRunLoopCommonModes)
        return self

    @objc.python_method
    def add(self, title, action, menu=None, obj=None):
        it = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, action, "")
        if action:
            it.setTarget_(self)
        if obj is not None:
            it.setRepresentedObject_(obj)
        (menu or self.menu).addItem_(it)
        return it

    # ---- the menu-bar icon: click = menu, Option-click = Status
    def iconClick_(self, sender):
        ev = NSApplication.sharedApplication().currentEvent()
        if ev is not None and ev.type() == NSEventTypeLeftMouseDown and (ev.modifierFlags() & NSEventModifierFlagOption):
            self.status_(None)
            return
        self.item.setMenu_(self.menu)
        sender.performClick_(None)               # opens the menu; menuDidClose_ detaches it again

    def menuDidClose_(self, _menu):
        self.item.setMenu_(None)

    @objc.python_method
    def icon(self, state, awake):
        """The state icon, with the keep-awake badge while Keep awake is on (drawn once per state)."""
        key = (state, bool(awake))
        if key not in self.icons:
            img = _image(state, 18)
            self.icons[key] = _with_badge(img, 18) if (img is not None and awake) else img
        return self.icons[key]

    # ---- timers
    def tick_(self, _timer):
        try:                                # one failed pass is logged; the icon keeps following the guard
            self.ctl.refresh()
        except Exception:
            logging.getLogger("veroscudo.tray").exception("refresh")

    def drain_(self, _timer):
        try:                                # one failed pass is logged; later results are still shown
            self.ctl.drain()
        except Exception:
            logging.getLogger("veroscudo.tray").exception("drain")

    def autoUpdate_(self, _timer):
        self.ctl.check_updates(False)

    def statsTick_(self, _timer):
        try:
            if self.stats_win is not None and self.stats_win.isVisible():     # the picture moves on while open
                self.fill_stats()
        except Exception:
            logging.getLogger("veroscudo.tray").exception("statistics")

    # ---- the controller's hooks (traymodel.TrayController)
    @objc.python_method
    def notice(self, title, body, urgency="normal", state="attention"):
        notify(title, body)                 # a macOS notification has no urgency and no icon of its own

    @objc.python_method
    def message(self, title, text, error=False):
        self.alert(title, text)

    @objc.python_method
    def config_reloaded(self):
        self.shown_profiles = None          # the profiles' kinds are asked again: the menu is filled again
        if self.win is not None:
            self.fill_settings()

    @objc.python_method
    def show_state(self):
        ctl = self.ctl
        v = ctl.view
        img = self.icon(v.state, ctl.awake.active)
        if img is not None:
            self.item.button().setImage_(img)
        else:
            self.item.button().setTitle_("VS")
        self.item.button().setToolTip_(traymodel.tooltip(v, ctl.awake.active, ctl.facts))
        self.head.setTitle_(traymodel.menu_head(v, ctl.facts))
        ms = traymodel.menu_state(v, ctl.facts.kind)
        self.on_item.setEnabled_(ms.on and ctl.facts.configured)
        self.off_item.setEnabled_(ms.off)
        self.redo_item.setEnabled_(ms.reconnect)
        self.redo_item.setToolTip_(traymodel.RECONNECT_HIDDIFY if ctl.facts.kind == "hiddify" else None)
        self.fill_menus()

    @objc.python_method
    def show_windows(self):
        self.awake_item.setState_(NSOnState if self.ctl.awake.active else NSOffState)
        self.update_status()                # the settings were filled in config_reloaded already

    @objc.python_method
    def update_settings(self):
        self.fill_settings()

    @objc.python_method
    def refresh_soon(self):
        NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(1.5, self, "tick:", None, False)

    @objc.python_method
    def show_update(self, text):
        self.upd_item.setTitle_(text)

    @objc.python_method
    def open_url(self, url):
        _popen(["open", url])

    @objc.python_method
    def set_clipboard(self, text):
        pb = NSPasteboard.generalPasteboard()
        pb.clearContents()
        pb.setString_forType_(text, NSPasteboardTypeString)

    @objc.python_method
    def fill_menus(self):
        cfg = self.ctl.cfg
        key = (tuple(cfg.names), cfg.profile) if cfg else ()
        if key == self.shown_profiles:
            return
        self.shown_profiles = key
        self.prof_menu.removeAllItems()
        self.prof_item.setEnabled_(bool(cfg))
        if cfg:
            for name in cfg.names:
                it = self.add(f"{name} ({kind_label(self.ctl.kind(name))})", "useProfile:", self.prof_menu, name)
                it.setState_(NSOnState if name == cfg.profile else NSOffState)
            self.prof_item.setTitle_(f"VPN profile: {cfg.profile} ({kind_label(self.ctl.kind(cfg.profile))})")
        else:
            self.prof_item.setTitle_("VPN profile")

    # ---- small building blocks for the windows
    @objc.python_method
    def label(self, view, text, x, y, w, h=20, dim=False):
        t = NSTextField.labelWithString_(text)
        t.setFrame_(NSMakeRect(x, y, w, h))
        if dim:
            t.setTextColor_(NSColor.secondaryLabelColor())
        view.addSubview_(t)
        return t

    @objc.python_method
    def wrapping(self, view, text="", dim=False, small=False):
        t = NSTextField.wrappingLabelWithString_(text)
        if dim:
            t.setTextColor_(NSColor.secondaryLabelColor())
        if small:
            t.setFont_(_small_font())
        view.addSubview_(t)
        return t

    @objc.python_method
    def fit(self, label, x, y, w):
        """Places a wrapping label at (x, y), as high as its text needs; returns that height."""
        h = float(label.cell().cellSizeForBounds_(NSMakeRect(0, 0, w, 10000)).height)
        label.setFrame_(NSMakeRect(x, y, w, h))
        return h

    @objc.python_method
    def field(self, view, x, y, w, text=""):
        f = NSTextField.alloc().initWithFrame_(NSMakeRect(x, y, w, 24))
        f.setStringValue_(text)
        view.addSubview_(f)
        return f

    @objc.python_method
    def button(self, view, title, action, x, y, w):
        b = NSButton.buttonWithTitle_target_action_(title, self, action)
        b.setFrame_(NSMakeRect(x, y, w, 30))
        view.addSubview_(b)
        return b

    @objc.python_method
    def link(self, view, title, action):
        """A small link (Refresh, Clear) - the Windows tray's link labels."""
        b = NSButton.buttonWithTitle_target_action_(title, self, action)
        b.setBordered_(False)
        b.setAttributedTitle_(NSAttributedString.alloc().initWithString_attributes_(
            title, {NSForegroundColorAttributeName: NSColor.linkColor(), NSFontAttributeName: _small_font()}))
        view.addSubview_(b)
        return b

    @objc.python_method
    def set_link_title(self, b, title):
        b.setAttributedTitle_(NSAttributedString.alloc().initWithString_attributes_(
            title, {NSForegroundColorAttributeName: NSColor.linkColor(), NSFontAttributeName: _small_font()}))

    @objc.python_method
    def popup(self, view, x, y, w, titles=(), action=None):
        p = NSPopUpButton.alloc().initWithFrame_pullsDown_(NSMakeRect(x, y, w, 26), False)
        p.addItemsWithTitles_(list(titles))
        if action:
            p.setTarget_(self)
            p.setAction_(action)
        view.addSubview_(p)
        return p

    @objc.python_method
    def window(self, title, w, h):
        win = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, w, h), NSWindowStyleMaskTitled | NSWindowStyleMaskClosable, NSBackingStoreBuffered, False)
        win.setTitle_(title)
        win.setReleasedWhenClosed_(False)
        content = FlippedView.alloc().initWithFrame_(NSMakeRect(0, 0, w, h))
        win.setContentView_(content)
        return win, content

    @objc.python_method
    def present(self, win):
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        win.makeKeyAndOrderFront_(None)

    # ---- the Status window: live, refreshed with the icon (every 3 s) - the Windows and Linux status window
    STATUS_W = 500

    @objc.python_method
    def card(self, c, action):
        """A full-width line in a thin frame: a small badge, the main text, a grey text on the right and a Refresh link - the
        exit location and the service status page look the same. Returns (box, badge, main, right, refresh)."""
        W = self.STATUS_W
        box = NSBox.alloc().initWithFrame_(NSMakeRect(18, 0, W - 36, 34))
        box.setBoxType_(4)                                  # NSBoxCustom: a thin frame, like the GTK frame
        box.setTitlePosition_(0)                            # NSNoTitle
        box.setBorderColor_(NSColor.separatorColor())
        box.setFillColor_(NSColor.clearColor())
        box.setCornerRadius_(6)
        box.setContentViewMargins_((0, 0))
        inner = FlippedView.alloc().initWithFrame_(NSMakeRect(0, 0, W - 36, 34))
        box.setContentView_(inner)
        c.addSubview_(box)
        badge = self.label(inner, "", 10, 8, 30, 18)
        badge.setAlignment_(NSTextAlignmentCenter)
        badge.setFont_(NSFont.boldSystemFontOfSize_(NSFont.smallSystemFontSize()))
        badge.setDrawsBackground_(True)
        badge.setBackgroundColor_(NSColor.quaternaryLabelColor())
        main = self.label(inner, "", 46, 8, 204, 18)
        main.setLineBreakMode_(NSLineBreakByTruncatingTail)
        right = self.label(inner, "", 256, 8, 136, 18, dim=True)
        right.setAlignment_(NSTextAlignmentRight)
        right.setLineBreakMode_(NSLineBreakByTruncatingTail)
        refresh = self.link(inner, "Refresh", action)
        refresh.setFrame_(NSMakeRect(W - 36 - 66, 6, 60, 22))
        return box, badge, main, right, refresh

    @objc.python_method
    def build_status(self):
        W = self.STATUS_W
        win, c = self.window("VeroScudo", W, 560)
        st = {"c": c, "rows": None, "row_views": [], "h": 0}
        st["img"] = NSImageView.alloc().initWithFrame_(NSMakeRect(18, 18, 64, 64))
        c.addSubview_(st["img"])
        st["title"] = self.label(c, "", 96, 18, W - 114, 28)
        st["title"].setFont_(NSFont.boldSystemFontOfSize_(20))
        st["text"] = self.wrapping(c, "", dim=True)
        # where the traffic leaves the tunnel: one line under the header (Settings > Behaviour, "Show exit location")
        st["loc"], st["badge"], st["place"], st["right"], st["refresh"] = self.card(c, "statusRefreshExit:")
        # the service status page: a line like it, right under it (Settings > Connection, "Show a service status page")
        st["svc"], st["sbadge"], st["sname"], st["sright"], st["srefresh"] = self.card(c, "statusRefreshService:")
        st["sname"].setFrame_(NSMakeRect(46, 8, 150, 18))
        st["sright"].setFrame_(NSMakeRect(202, 8, W - 36 - 66 - 202 - 4, 18))
        st["other"] = self.wrapping(c, "")
        st["evh"] = self.label(c, "Recent events", 18, 0, 200, 20)
        st["evh"].setFont_(NSFont.boldSystemFontOfSize_(13))
        # Clear empties this view only: the log stays (the record of what happened; root-owned, rotates by itself).
        # Open log still shows everything.
        st["clear"] = self.link(c, "Clear", "statusClear:")
        st["copy"] = self.link(c, "Copy", "statusCopy:")       # the report (state, exit, service, last events) to the clipboard
        sv = NSScrollView.alloc().initWithFrame_(NSMakeRect(18, 0, W - 36, 170))
        sv.setHasVerticalScroller_(True)
        sv.setBorderType_(2)                                # NSBezelBorder
        tv = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, W - 40, 170))
        tv.setEditable_(False)
        tv.setFont_(NSFont.userFixedPitchFontOfSize_(11))
        sv.setDocumentView_(tv)
        c.addSubview_(sv)
        st["sv"], st["tv"], st["events"] = sv, tv, None
        st["onoff"] = self.button(c, "Turn VPN on", "statusOnOff:", 0, 0, 112)
        st["redo"] = self.button(c, "Reconnect", "reconnect:", 0, 0, 100)
        st["log"] = self.button(c, "Open log", "openLog:", 0, 0, 92)
        st["stats"] = self.button(c, "Statistics", "statistics:", 0, 0, 112)
        self.st_win, self.st = win, st
        self.update_status()
        win.center()

    @objc.python_method
    def update_status(self):
        win, st = self.st_win, self.st
        if win is None or not win.isVisible() and st.get("h"):
            return
        W = self.STATUS_W
        ctl = self.ctl
        f, v = ctl.facts, ctl.view
        dark = _dark()
        img = _image(v.state, 64)
        if img is not None:
            st["img"].setImage_(img)
        st["title"].setStringValue_(v.title)
        st["title"].setTextColor_(_tone(traymodel.title_tone(f, v), dark))
        st["text"].setStringValue_(v.text)
        y = max(18 + 64, 50 + self.fit(st["text"], 96, 50, W - 114)) + 14
        # exit location
        show = ctl.exit_enabled()
        st["loc"].setHidden_(not show)
        if show:
            st["loc"].setFrame_(NSMakeRect(18, y, W - 36, 34))
            xv = ctl.exit_view()
            st["badge"].setHidden_(not xv.has)
            st["right"].setHidden_(not xv.has)
            if xv.has:
                alpha = 1.0 if xv.fresh else 0.6           # not looked up through the tunnel that is up now: grey
                st["badge"].setStringValue_(xv.code or "?")
                st["place"].setStringValue_(xv.place or xv.code)
                # a notice ('refresh failed', a refusal) is long: smaller, and the place gives way (truncated)
                pw = 100 if xv.notice else 204
                st["place"].setFrame_(NSMakeRect(46, 8, pw, 18))
                st["right"].setFrame_(NSMakeRect(46 + pw + 6, 8, W - 36 - 66 - (46 + pw + 6) - 4, 18))
                st["right"].setFont_(_small_font() if xv.notice else NSFont.systemFontOfSize_(NSFont.systemFontSize()))
                st["right"].setStringValue_(xv.right)
                for k in ("badge", "place", "right"):
                    st[k].setAlphaValue_(alpha)
                    st[k].setToolTip_(xv.tip)
            else:
                st["place"].setStringValue_(xv.text)
                st["place"].setFrame_(NSMakeRect(10, 8, W - 36 - 82, 18))
                st["place"].setAlphaValue_(0.6)
                st["place"].setToolTip_(xv.tip or None)
            y += 34 + 12
        # the service status page (Settings > Connection): its own line under the exit location, None = off
        sv = ctl.service_view()
        st["svc"].setHidden_(sv is None)
        if sv is not None:
            st["svc"].setFrame_(NSMakeRect(18, y, W - 36, 34))
            bg, fg = statuspage.badge_colours(sv.tone, dark)    # "?": the exit badge's neutral background
            st["sbadge"].setBackgroundColor_(_rgb(traymodel.hex_rgb(bg)) if bg else NSColor.quaternaryLabelColor())
            st["sbadge"].setTextColor_(_rgb(traymodel.hex_rgb(fg)) if fg else NSColor.labelColor())
            st["sbadge"].setStringValue_(sv.badge)
            st["sname"].setStringValue_(sv.name)
            st["sright"].setStringValue_(sv.right)
            for k in ("sbadge", "sname", "sright"):
                st[k].setToolTip_(sv.tip)
            y += 34 + 12
        # the table: CONNECTION coloured by its rating with the details as a tooltip, the firewall red while blocked
        cv = traymodel.connection_view(f, v, ctl.cfg.check if ctl.cfg else None)
        tones = {"Connection": (cv.tone, cv.tip), "Firewall": (traymodel.firewall_tone(f, v), "")}
        rows = [(k, val, *tones.get(k, ("normal", "")))
                for k, val in traymodel.status_rows(f, v, ctl.awake.active, ctl.tunnel, last_drop=ctl.last_drop, foreign=())]
        if (rows, dark) != st["rows"]:
            for x in st["row_views"]:
                x.removeFromSuperview()
            st["row_views"] = []
            for k, val, tone, tip in rows:
                kl = self.label(st["c"], k, 18, 0, 110, 20, dim=True)
                vl = self.label(st["c"], val, 134, 0, W - 152, 20)
                vl.setTextColor_(_tone(tone, dark))
                vl.setLineBreakMode_(NSLineBreakByTruncatingTail)
                if tip:
                    vl.setToolTip_(tip)
                st["row_views"] += [kl, vl]
            st["rows"] = (rows, dark)
        for i, x in enumerate(st["row_views"]):
            fr = x.frame()
            x.setFrame_(NSMakeRect(fr.origin.x, y + (i // 2) * 22, fr.size.width, 20))
        y += len(rows) * 22 + 8
        other = traymodel.foreign_text(ctl.foreign)
        st["other"].setHidden_(not other)
        if other:
            st["other"].setStringValue_(f"Other VPNs: {other}")
            st["other"].setTextColor_(_tone("warn", dark))
            y += self.fit(st["other"], 18, y, W - 36) + 10
        st["evh"].setFrame_(NSMakeRect(18, y, 200, 20))
        st["clear"].setFrame_(NSMakeRect(W - 18 - 50, y, 50, 20))
        st["copy"].setFrame_(NSMakeRect(W - 18 - 50 - 4 - 56, y, 56, 20))
        y += 24
        st["sv"].setFrame_(NSMakeRect(18, y, W - 36, 170))
        y += 170 + 14
        ev = ctl.events(view=True)
        text = traymodel.log_hint() if ev is None else ("\n".join(ev) or "(no events yet)")
        if text != st["events"]:
            st["events"] = text
            st["tv"].setString_(text)
            st["tv"].scrollToEndOfDocument_(None)             # newest at the bottom
        x = W - 18
        for k in ("stats", "log", "redo", "onoff"):
            w = float(st[k].frame().size.width)
            x -= w
            st[k].setFrame_(NSMakeRect(x, y, w, 30))
            x -= 8
        ms = traymodel.menu_state(v, f.kind)
        st["onoff"].setTitle_("Turn VPN off" if traymodel.offers_off(v, f.kind) else "Turn VPN on")
        st["onoff"].setEnabled_(f.configured)
        st["redo"].setEnabled_(ms.reconnect)
        st["redo"].setToolTip_(traymodel.RECONNECT_HIDDIFY if f.kind == "hiddify" else None)
        h = y + 30 + 18
        if h != st["h"]:                                       # grows or shrinks downwards: the top edge stays
            fr = win.frame()
            top = fr.origin.y + fr.size.height
            win.setContentSize_((W, h))
            st["c"].setFrame_(NSMakeRect(0, 0, W, h))
            fr = win.frame()
            win.setFrameOrigin_((fr.origin.x, top - fr.size.height))
            st["h"] = h

    def status_(self, _):
        if self.st_win is None:
            self.build_status()
        self.set_link_title(self.st["copy"], "Copy")
        self.present(self.st_win)
        self.update_status()

    def statusOnOff_(self, _):
        self.ctl.toggle_on_off()

    def statusCopy_(self, sender):
        self.ctl.copy_report()
        self.set_link_title(sender, "Copied")

    def statusClear_(self, _):
        self.ctl.clear_events()

    def statusRefreshExit_(self, _):
        self.ctl.refresh_exit()

    def statusRefreshService_(self, _):
        self.ctl.refresh_status_page()

    # ---- the Statistics window: 7 days, one row per day, one bar per 10 minutes (Windows: Show-Stats)
    @objc.python_method
    def build_stats(self):
        g = traymodel.STATS_GEOMETRY
        win, c = self.window(traymodel.STATS_TITLE, 640, 682)
        head = self.label(c, traymodel.STATS_HEADING, 20, 16, 300, 30)
        head.setFont_(NSFont.boldSystemFontOfSize_(20))
        note = self.label(c, traymodel.STATS_NOTE, 20, 50, 600, 20, dim=True)
        note.setFont_(_small_font())
        # one VPN profile at a time: a corporate VPN and a home one are different connections - their problems never mix
        self.label(c, "VPN profile", 20, 82, 90, 20)
        pick = self.popup(c, 112, 78, 300, (), "statsProfile:")
        chart = StatsChart.alloc().initWithFrame_(NSMakeRect(20, 112, g["width"], g["height"]))
        # the hovered bar: as a tooltip, and in the note line too (a tooltip waits for the mouse to rest)
        chart.setup(lambda text: note.setStringValue_(text or traymodel.STATS_NOTE))
        c.addSubview_(chart)
        win.setAcceptsMouseMovedEvents_(True)
        dark, lx = _dark(), 20
        for state, text in traymodel.STATS_LEGEND:
            sw = NSBox.alloc().initWithFrame_(NSMakeRect(lx, 564, 12, 12))
            sw.setBoxType_(4)                               # NSBoxCustom: a plain coloured square
            sw.setTitlePosition_(0)
            sw.setBorderWidth_(0)
            sw.setFillColor_(_rgb(traymodel.stats_colour(state, dark)))
            c.addSubview_(sw)
            w = {"good": 190, "unstable": 70, "bad": 150}.get(state, 90)
            self.label(c, text, lx + 18, 560, w, 20, dim=True).setFont_(_small_font())
            lx += w + 26
        foot = self.wrapping(c, traymodel.STATS_FOOT, dim=True, small=True)
        foot.setFrame_(NSMakeRect(20, 584, 600, 40))
        self.button(c, "Refresh", "statsRefresh:", 400, 630, 100)
        close = self.button(c, "Close", "statsClose:", 510, 630, 110)
        close.setKeyEquivalent_("\r")
        self.stats_win, self.stats_ui = win, {"chart": chart, "note": note, "pick": pick}
        self.fill_stats()
        win.center()

    @objc.python_method
    def fill_stats(self):
        pick, chart = self.stats_ui["pick"], self.stats_ui["chart"]
        current = self.selected(pick)                      # the id of the shown profile (renamed: same id, new name)
        items = self.ctl.stats_choices()                   # a profile used for the first time shows up on Refresh
        pick.removeAllItems()
        for pid, label in items:
            pick.addItemWithTitle_(label)
            pick.lastItem().setRepresentedObject_(pid)
        ids = [pid for pid, _ in items]
        if current in ids:
            pick.selectItemAtIndex_(ids.index(current))
        chart.days = self.ctl.stats_week(self.selected(pick))
        chart.setNeedsDisplay_(True)

    def statsProfile_(self, _):
        self.fill_stats()

    def statistics_(self, _):
        if self.stats_win is None:
            self.build_stats()
        else:
            self.fill_stats()
        self.present(self.stats_win)

    def statsRefresh_(self, _):
        self.fill_stats()

    def statsClose_(self, _):
        self.stats_win.close()

    # ---- the Settings window: VPN profiles, Behaviour, Connection
    @objc.python_method
    def build_settings(self):
        W, H = 560, 550
        win = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, W, H), NSWindowStyleMaskTitled | NSWindowStyleMaskClosable, NSBackingStoreBuffered, False)
        win.setTitle_("VeroScudo - Settings")
        win.setReleasedWhenClosed_(False)
        tabs = NSTabView.alloc().initWithFrame_(NSMakeRect(12, 12, W - 24, H - 24))
        win.contentView().addSubview_(tabs)
        ui = {"tabs": tabs}

        def tab(title):
            item = NSTabViewItem.alloc().initWithIdentifier_(title)
            item.setLabel_(title)
            view = NSView.alloc().initWithFrame_(NSMakeRect(0, 0, W - 44, H - 70))
            item.setView_(view)
            tabs.addTabViewItem_(item)
            return view

        top = H - 90                             # the first row inside a tab
        v = tab("VPN profiles")
        self.label(v, "Profile", 16, top, 90)
        ui["prof"] = self.popup(v, 110, top - 3, 300)
        self.button(v, "Remove", "settingsRemove:", 110, top - 40, 110)
        self.label(v, "Import", 16, top - 90, 90)
        ui["imp"] = self.popup(v, 110, top - 93, 300)
        ui["imp_btn"] = self.button(v, "Import", "settingsImport:", 416, top - 95, 90)
        self.label(v, "One connection per import: not every VPN on a computer is for work.", 16, top - 124, W - 70, dim=True)
        self.label(v, "Profiles are the VPN services of System Settings > VPN; passwords stay in the keychain. Each change "
                      "asks for an administrator's password.", 16, 16, W - 70, 40, dim=True)

        v = tab("Behaviour")
        # each option: a short label and one grey line saying what it does - the same texts as the Windows and Linux trays
        y = top

        def option(title, about, action):
            nonlocal y
            cb = NSButton.checkboxWithTitle_target_action_(title, self if action else None, action)
            cb.setFrame_(NSMakeRect(16, y, 460, 22))
            v.addSubview_(cb)
            self.label(v, about, 36, y - 34, W - 90, 34, dim=True)
            y -= 66
            return cb

        strict = option("Strict kill-switch (always on)",
                        "When the VPN drops, nothing leaves this Mac until it is back or you turn the VPN off.", None)
        strict.setState_(NSOnState)
        strict.setEnabled_(False)
        ui["vm"] = option("Protect VMs and containers", traymodel.VM_ABOUT, "settingsVm:")
        ui["upd"] = option("Check for updates when the tray starts", traymodel.UPDATE_ABOUT, "settingsUpdate:")
        ui["loc"] = option("Show exit location", traymodel.EXIT_ABOUT, "settingsExit:")
        self.label(v, traymodel.BEHAVIOUR_NOTE, 16, 10, W - 70, 40, dim=True)

        v = tab("Connection")
        ui["en"] = NSButton.checkboxWithTitle_target_action_("Check the connection quality while protected", self,
                                                             "settingsCheckToggle:")
        ui["en"].setFrame_(NSMakeRect(16, top, 460, 22))
        v.addSubview_(ui["en"])
        more = []
        more.append(self.label(v, "Check every", 16, top - 34, 110))
        ui["every"] = self.field(v, 130, top - 37, 60)
        more += [ui["every"], self.label(v, "seconds (10-100)", 198, top - 34, 200, dim=True)]
        more.append(self.label(v, "Rate the last", 16, top - 64, 110))
        ui["over"] = self.field(v, 130, top - 67, 60)
        more += [ui["over"], self.label(v, "minutes (1-10)", 198, top - 64, 200, dim=True)]
        more.append(self.label(v, "Good: under 10 % lost. Unstable: 10-50 % or slow (over 1 s). Bad: over 50 %.", 16, top - 92,
                               W - 70, dim=True))
        more.append(self.label(v, "Addresses (IP, host name or URL - at least one)", 16, top - 120, W - 70))
        ui["rows"] = []
        for i in range(quality.MAX_TARGETS):
            y = top - 152 - i * 32
            host = self.field(v, 16, y, 250)
            host.setPlaceholderString_(quality.DEFAULT_HOST if i == 0 else "optional")
            m = self.popup(v, 274, y - 1, 120, METHOD_TITLES, "settingsMethod:")
            port = self.field(v, 402, y, 70)
            ui["rows"].append((host, m, port))
            more += [host, m, port]
        more.append(self.label(v, traymodel.CHECK_HTTPS_HINT, 16, top - 256, W - 70, 34, dim=True))
        more.append(self.label(v, CONNECTION_NOTE, 16, top - 312, W - 70, 52, dim=True))
        ui["save"] = self.button(v, "Save connection settings", "settingsSave:", W - 260, top - 350, 210)
        # the service status page: your own setting (tray.json), saved at once - below the check's Save button
        sep = NSBox.alloc().initWithFrame_(NSMakeRect(16, top - 364, W - 70, 1))
        sep.setBoxType_(2)                                  # NSBoxSeparator
        v.addSubview_(sep)
        ui["sp"] = NSButton.checkboxWithTitle_target_action_(statuspage.LABEL, self, "settingsStatusPage:")
        ui["sp"].setFrame_(NSMakeRect(16, top - 392, 460, 22))
        v.addSubview_(ui["sp"])
        ui["sp_url"] = self.field(v, 36, top - 422, W - 90)
        ui["sp_url"].setPlaceholderString_(statuspage.DEFAULT_URL)
        ui["sp_url"].setTarget_(self)
        ui["sp_url"].setAction_("settingsStatusUrl:")         # Return or leaving the field
        self.label(v, statuspage.ABOUT, 36, top - 446, W - 90, 18, dim=True).setFont_(_small_font())
        ui["more"] = more
        self.win, self.win_ui = win, ui
        self.fill_settings()
        win.center()

    @objc.python_method
    def fill_settings(self):
        ui, cfg = self.win_ui, self.ctl.cfg
        if not ui:
            return
        names = list(cfg.names) if cfg else []
        ui["prof"].removeAllItems()
        for n in names:
            tags = [kind_label(self.ctl.kind(n))] + (["active"] if cfg and n == cfg.profile else [])
            ui["prof"].addItemWithTitle_(f"{n}  ({' · '.join(tags)})")
            ui["prof"].lastItem().setRepresentedObject_(n)
        have = set(names)
        found = [d for d in nm.discover() if d["name"] not in have]
        ui["imp"].removeAllItems()
        for d in found:
            ok = importer.importable(d)
            what = "Hiddify (VPN mode)" if d["vpn_type"] == "hiddify" else d["vpn_type"] or d["protocol"]
            ui["imp"].addItemWithTitle_(f"{d['name']}  ({what})" if ok else f"{d['name']}  - {d['note']}")
            ui["imp"].lastItem().setRepresentedObject_(d["name"] if ok else "")
        if not found:
            ui["imp"].addItemWithTitle_("No other VPN service found. Create it in System Settings > VPN, connect once, then "
                                        "import it here.")
            ui["imp"].lastItem().setRepresentedObject_("")
        ui["upd"].setState_(NSOnState if (cfg is None or cfg.update_check) else NSOffState)
        ui["vm"].setState_(NSOnState if (cfg is None or cfg.vm) else NSOffState)
        ui["loc"].setState_(NSOnState if self.ctl.exit_enabled() else NSOffState)
        ui["sp"].setState_(NSOnState if self.ctl.status_page_enabled() else NSOffState)
        ui["sp_url"].setStringValue_(self.ctl.status_page_url())
        chk = cfg.check if cfg else quality.CheckConfig()
        ui["en"].setState_(NSOnState if chk.enabled else NSOffState)
        ui["every"].setStringValue_(str(chk.interval_seconds))
        ui["over"].setStringValue_(str(chk.window_minutes))
        for i, (host, m, port) in enumerate(ui["rows"]):
            t = chk.targets[i] if i < len(chk.targets) else None
            host.setStringValue_(t.host if t else "")
            m.selectItemAtIndex_(METHODS.index(t.method) if t and t.method in METHODS else 1)
            port.setStringValue_(str(t.port if t and t.method in quality.PORT_METHODS else 443))
            port.setEnabled_(not (t and t.method == "ping"))
        self.show_check_fields()

    @objc.python_method
    def show_check_fields(self):
        on = self.win_ui["en"].state() == NSOnState
        for view in self.win_ui["more"]:
            view.setHidden_(not on)

    @objc.python_method
    def selected(self, popup):
        it = popup.selectedItem()
        return str(it.representedObject()) if it is not None and it.representedObject() else ""

    def settings_(self, _):
        if self.win is None:
            self.build_settings()
        self.present(self.win)

    def settingsRemove_(self, _):
        name = self.selected(self.win_ui["prof"])
        if not name:
            self.alert("Select a profile first.", "")
            return
        title, text = traymodel.remove_question(name)
        if self.confirm(title, text, "Remove"):
            self.ctl.admin(["remove", name])

    def settingsImport_(self, _):
        name = self.selected(self.win_ui["imp"])
        if name:
            self.ctl.admin(["import", name])

    def settingsUpdate_(self, sender):
        self.ctl.admin(["set", "updateCheck", "true" if sender.state() == NSOnState else "false"])

    def settingsVm_(self, sender):
        self.ctl.admin(["set", "vm", "true" if sender.state() == NSOnState else "false"])

    def settingsExit_(self, sender):
        self.ctl.set_exit_enabled(sender.state() == NSOnState)

    def settingsCheckToggle_(self, _):
        self.show_check_fields()

    def settingsMethod_(self, _):
        for _host, m, port in self.win_ui["rows"]:
            port.setEnabled_(method_of(m.indexOfSelectedItem()) in quality.PORT_METHODS)

    def settingsStatusPage_(self, sender):
        self.ctl.set_status_page(sender.state() == NSOnState)

    def settingsStatusUrl_(self, sender):
        err = self.ctl.save_status_url(str(sender.stringValue()))
        if err is None:
            return
        if err:
            sender.setStringValue_(self.ctl.status_page_url())   # not saved: the saved address again
            self.alert("Not saved", err)
        self.update_status()

    def settingsSave_(self, _):
        ui = self.win_ui
        if not str(ui["rows"][0][0].stringValue()).strip():      # the first address is never empty: cleared, it is 1.1.1.1
            ui["rows"][0][0].setStringValue_(quality.DEFAULT_HOST)
        try:
            rows = [(str(h.stringValue()), method_of(m.indexOfSelectedItem()), int(str(p.stringValue()) or 443))
                    for h, m, p in ui["rows"]]
            enabled = ui["en"].state() == NSOnState
            every, over = int(str(ui["every"].stringValue()) or 10), int(str(ui["over"].stringValue()) or 1)
        except ValueError as e:
            err = str(e)
        else:
            err = self.ctl.save_check(enabled, every, over, rows)
        if err:
            self.alert("Not saved",
                       err if "Address" in err else "Seconds, minutes and ports must be whole numbers.")

    # ---- actions
    def turnOn_(self, _):
        self.ctl.request_on()

    def turnOff_(self, _):
        self.ctl.act("off")

    def reconnect_(self, _):
        self.ctl.act("reconnect")

    def useProfile_(self, sender):
        name = str(sender.representedObject())
        if self.ctl.cfg and name != self.ctl.cfg.profile:
            self.ctl.act("use", name)

    def toggleAwake_(self, _):
        want = not self.ctl.awake.active
        held = self.ctl.awake.set(want)
        keepawake.save_pref(held)
        if want and not held:
            notify("Keep awake is not available", "No sleep inhibitor found (caffeinate).")
        self.ctl.refresh()

    def openLog_(self, _):
        if traymodel.read_events(n=1) is None:
            self.alert("The log cannot be opened", traymodel.log_hint())
            return
        _popen(["open", "-a", "Console", str(traymodel.LOG)])

    def checkUpdates_(self, _):
        self.ctl.update_clicked()

    def about_(self, _):
        r = self.alert(f"VeroScudo {__version__}",
                       "Master the switch.\n\nVPN on + connection lost = no network until the VPN is back or you turn it off. "
                       f"Two actions, no backdoor.\n\n{traymodel.REPO_URL}\n\n{traymodel.COPYRIGHT}", buttons=("Close", "Open website", "Uninstall…"), icon="app")
        if r == NSAlertSecondButtonReturn:
            _popen(["open", traymodel.REPO_URL])
        elif r == NSAlertThirdButtonReturn and self.confirm(
                "Uninstall VeroScudo?", "Removes the guard, the kill-switch, this menu-bar app and the sudo rule. Your VPN "
                "services stay as they are; a connected VPN stays connected. config.json is kept for a later install.",
                "Uninstall"):
            self.ctl.admin(["uninstall"])

    def quit_(self, _):
        self.ctl.awake.release()
        NSApplication.sharedApplication().terminate_(None)

    # ---- dialogs
    @objc.python_method
    def alert(self, title, text, buttons=("OK",), icon=None):
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        a = NSAlert.alloc().init()
        a.setMessageText_(title)
        a.setInformativeText_(text)
        for b in buttons:
            a.addButtonWithTitle_(b)
        img = _image(icon, 64) if icon else None
        if img is not None:
            a.setIcon_(img)
        return a.runModal()

    @objc.python_method
    def confirm(self, title, text, ok):
        """Cancel is the default (Return never confirms a removal by accident); the action needs a click."""
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        a = NSAlert.alloc().init()
        a.setMessageText_(title)
        a.setInformativeText_(text)
        a.addButtonWithTitle_("Cancel")
        a.addButtonWithTitle_(ok).setKeyEquivalent_("")
        return a.runModal() == NSAlertSecondButtonReturn

    @objc.python_method
    def choose_foreign(self, prompt):
        """Before Turn on, when another VPN is connected (traymodel.foreign_prompt decides the text and the buttons):
        'disconnect' | 'anyway' | 'cancel' - nothing happens without a click (Return does not answer, Esc cancels)."""
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        a = NSAlert.alloc().init()
        a.setAlertStyle_(0)                                 # NSAlertStyleWarning
        a.setMessageText_("Another VPN is connected")
        a.setInformativeText_(prompt.text)
        order = list(reversed(prompt.buttons))              # NSAlert: the first button added is the rightmost
        for answer, label, _primary in order:
            a.addButtonWithTitle_(label).setKeyEquivalent_("\x1b" if answer == "cancel" else "")
        a.window().setTitle_(prompt.title)
        i = int(a.runModal()) - int(NSAlertFirstButtonReturn)
        return order[i][0] if 0 <= i < len(order) else "cancel"


def main(argv: list[str] | None = None) -> int:
    from .tray import _single_instance  # the same one-per-session lock (fcntl) as the Linux tray
    lock = _single_instance()
    if lock is None:
        return 0
    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)     # menu bar only, no Dock icon
    tray = Tray.alloc().init()
    _ = tray
    AppHelper.runEventLoop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
