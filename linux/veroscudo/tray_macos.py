"""macOS menu-bar app (AppKit through PyObjC): the same menu and decisions as the Windows and Linux trays.

Runs as the signed-in user, started at login by /Library/LaunchAgents/com.gomelhawk.veroscudo.tray.plist (or by opening
/Applications/VeroScudo.app). on / off / reconnect / use go through the sudoers rule install.sh writes (`sudo -n`, by full
path); a change to config.json or the uninstall asks for an administrator's password (the macOS password dialog). What
it shows and says is decided in traymodel.py. PyObjC is installed by install.sh into /opt/veroscudo/tray-lib - the root
daemon never loads it."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import objc  # type: ignore
from AppKit import (  # type: ignore
    NSAlert,
    NSBackingStoreBuffered,
    NSButton,
    NSColor,
    NSAlertFirstButtonReturn,
    NSAlertSecondButtonReturn,
    NSAlertThirdButtonReturn,
    NSApplication,
    NSApplicationActivationPolicyAccessory,
    NSImage,
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
    NSTextField,
    NSTextView,
    NSView,
    NSVariableStatusItemLength,
    NSWindow,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskTitled,
)
from Foundation import NSObject, NSTimer  # type: ignore
from PyObjCTools import AppHelper  # type: ignore

from . import __version__, keepawake, quality, traymodel, update
from .backend import nm
from .config import Config, config_path, is_host
from .state import StateStore, kind_label, switch_notice

ICONS = traymodel.env_icons(Path("/opt/veroscudo/icons"))


def notify(title: str, body: str) -> None:
    """A macOS notification; title and body are passed as data (argv), never as AppleScript text."""
    try:
        subprocess.Popen(["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                          "-e", "end run", title, body], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def _image(name: str, size: float):
    img = NSImage.alloc().initWithContentsOfFile_(str(ICONS / f"{name}.png"))
    if img is not None:
        img.setSize_((size, size))
    return img


class Tray(NSObject):
    def init(self):
        self = objc.super(Tray, self).init()     # noqa: PLW0642 - PyObjC's init pattern: init may return another object
        if self is None:
            return None
        self.store = StateStore()
        self.cfg, self.cfg_error, self.cfg_mtime = None, "", -1.0
        self.kinds = {}
        self.runner = traymodel.Runner()
        self.expect = traymodel.Expect()
        self.awake = keepawake.KeepAwake()
        self.last = None
        self.facts = traymodel.Facts(configured=False)
        self.view = traymodel.tray_state(self.facts)
        self.update_url = ""
        self.shown_profiles = None
        self.win = None                          # the Settings window (three tabs, as on Windows and Linux)
        self.win_ui = {}
        self.reload_config()
        self.item = NSStatusBar.systemStatusBar().statusItemWithLength_(NSVariableStatusItemLength)
        self.menu = NSMenu.alloc().init()
        self.menu.setAutoenablesItems_(False)
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
        self.add("Settings…", "settings:")
        self.awake_item = self.add("Keep awake", "toggleAwake:")
        self.awake_item.setState_(NSOnState if self.awake.set(keepawake.load_pref()) else NSOffState)
        self.menu.addItem_(NSMenuItem.separatorItem())
        self.upd_item = self.add("Check for updates", "checkUpdates:")
        self.add("About VeroScudo", "about:")
        self.add("Exit menu-bar icon (guard keeps running)", "quit:")
        self.item.setMenu_(self.menu)
        self.refresh()
        NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(3.0, self, "tick:", None, True)
        NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(0.5, self, "drain:", None, True)
        NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(120.0, self, "autoUpdate:", None, False)
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

    # ---- facts
    @objc.python_method
    def kind(self, name):
        if name not in self.kinds:
            self.kinds[name] = nm.kind(name)
        return self.kinds[name]

    @objc.python_method
    def reload_config(self):
        m = traymodel.config_mtime(config_path())
        if m == self.cfg_mtime:
            return False
        self.cfg_mtime = m
        try:
            self.cfg, self.cfg_error = Config.load(active=self.store.active), ""
        except (OSError, ValueError, KeyError, TypeError) as e:
            self.cfg, self.cfg_error = None, str(e)
        self.kinds = {}
        self.shown_profiles = None
        if self.win is not None:
            self.fill_settings()
        return True

    @objc.python_method
    def collect(self):
        cfg = self.cfg
        if cfg is None:
            return traymodel.Facts(configured=False, config_error=self.cfg_error, guard_running=traymodel.guard_running())
        active = self.store.active
        if active in cfg.names and active != cfg.profile:
            self.cfg = cfg = cfg.with_active(active)
        armed = self.store.armed
        up = nm.is_connected(cfg.profile) and (not armed or self.store.allowed_tunnel(cfg.profile) is not None)
        return traymodel.Facts(name=cfg.profile, kind=self.kind(cfg.profile), armed=armed, up=up,
                               guard_running=traymodel.guard_running(), expect=self.expect.kind, check_enabled=cfg.check.enabled,
                               quality=quality.read(self.store.home / "quality.json", cfg.profile) if cfg.check.enabled else None)

    # ---- timers
    def tick_(self, _timer):
        self.refresh()

    def drain_(self, _timer):
        for tag, argv, rc, _out, err in self.runner.results():
            if rc == 0:
                if tag.startswith("admin:"):
                    self.reload_config()
                    self.refresh()
                continue
            if tag.startswith("admin:") and traymodel.cancelled(rc, err):
                continue
            what = traymodel.explain_failure(argv, rc, err)
            if tag.startswith("admin:"):
                self.alert("The change was not made", what)
            else:
                self.expect.kind = None
                notify(f"VeroScudo - {tag} failed", what)

    def autoUpdate_(self, _timer):
        self.check_updates(False)

    @objc.python_method
    def refresh(self):
        self.reload_config()
        self.facts = self.collect()
        self.view = v = traymodel.tray_state(self.facts)
        if self.expect.update(v):
            notify(*traymodel.expired_notice(self.facts.name)[:2])
            self.facts = self.collect()
            self.view = v = traymodel.tray_state(self.facts)
        img = _image(v.state, 18)
        if img is not None:
            self.item.button().setImage_(img)
        else:
            self.item.button().setTitle_("VS")
        self.item.button().setToolTip_(traymodel.tooltip(v, self.awake.active, self.facts))
        self.head.setTitle_(traymodel.menu_head(v, self.facts))
        ms = traymodel.menu_state(v)
        self.on_item.setEnabled_(ms.on and self.facts.configured)
        self.off_item.setEnabled_(ms.off)
        self.redo_item.setEnabled_(ms.reconnect)
        self.fill_menus()
        if self.facts.configured and keepawake.get_pref("lastProfile") != self.facts.name:
            keepawake.set_pref("lastProfile", self.facts.name)
            n = switch_notice(self.facts.kind, self.facts.name)
            if n:
                notify("VeroScudo", n)
        n = traymodel.transition_notice(self.last, v, self.facts.expect, self.facts.name)
        if n:
            notify(n[0], n[1])
        self.last = v.state
        self.awake_item.setState_(NSOnState if self.awake.active else NSOffState)

    @objc.python_method
    def fill_menus(self):
        cfg = self.cfg
        key = (tuple(cfg.names), cfg.profile) if cfg else ()
        if key == self.shown_profiles:
            return
        self.shown_profiles = key
        self.prof_menu.removeAllItems()
        self.prof_item.setEnabled_(bool(cfg))
        if cfg:
            for name in cfg.names:
                it = self.add(f"{name} ({kind_label(self.kind(name))})", "useProfile:", self.prof_menu, name)
                it.setState_(NSOnState if name == cfg.profile else NSOffState)
            self.prof_item.setTitle_(f"VPN profile: {cfg.profile} ({kind_label(self.kind(cfg.profile))})")

    # ---- the Settings window: VPN profiles, Behaviour, Connection
    @objc.python_method
    def label(self, view, text, x, y, w, h=20, dim=False):
        t = NSTextField.labelWithString_(text)
        t.setFrame_(NSMakeRect(x, y, w, h))
        if dim:
            t.setTextColor_(NSColor.secondaryLabelColor())
        view.addSubview_(t)
        return t

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
    def popup(self, view, x, y, w, titles=(), action=None):
        p = NSPopUpButton.alloc().initWithFrame_pullsDown_(NSMakeRect(x, y, w, 26), False)
        p.addItemsWithTitles_(list(titles))
        if action:
            p.setTarget_(self)
            p.setAction_(action)
        view.addSubview_(p)
        return p

    @objc.python_method
    def build_settings(self):
        W, H = 560, 380
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
        self.button(v, "Make default", "settingsDefault:", 226, top - 40, 130)
        self.label(v, "Import", 16, top - 90, 90)
        ui["imp"] = self.popup(v, 110, top - 93, 300)
        ui["imp_btn"] = self.button(v, "Import", "settingsImport:", 416, top - 95, 90)
        self.label(v, "Profiles are the VPN services of System Settings > VPN; passwords stay in the keychain. Each change "
                      "asks for an administrator's password.", 16, 16, W - 70, 40, dim=True)

        v = tab("Behaviour")
        strict = NSButton.checkboxWithTitle_target_action_("Strict kill-switch (always on - cannot be disabled)", None, None)
        strict.setFrame_(NSMakeRect(16, top, 460, 22))
        strict.setState_(NSOnState)
        strict.setEnabled_(False)
        v.addSubview_(strict)
        ui["upd"] = NSButton.checkboxWithTitle_target_action_("Check for a new release at login", self, "settingsUpdate:")
        ui["upd"].setFrame_(NSMakeRect(16, top - 30, 460, 22))
        v.addSubview_(ui["upd"])
        self.label(v, "Each change asks for an administrator's password and takes effect within 15 seconds.", 16, 16, W - 70,
                   40, dim=True)

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
        more.append(self.label(v, "Good: under 10 % of the checks lost. Unstable: 10-50 %. Bad: over 50 %.", 16, top - 92,
                               W - 70, dim=True))
        more.append(self.label(v, "Addresses (IP, host name or URL - at least one)", 16, top - 120, W - 70))
        ui["rows"] = []
        for i in range(quality.MAX_TARGETS):
            y = top - 152 - i * 32
            host = self.field(v, 16, y, 250)
            host.setPlaceholderString_(quality.DEFAULT_HOST if i == 0 else "optional")
            m = self.popup(v, 274, y - 1, 120, ("Ping", "TCP port"), "settingsMethod:")
            port = self.field(v, 402, y, 70)
            ui["rows"].append((host, m, port))
            more += [host, m, port]
        more.append(self.label(v, "The first rating comes one full period after each connect and each change here. The checks "
                                  "go through the VPN tunnel.", 16, 36, W - 70, 34, dim=True))
        ui["save"] = self.button(v, "Save", "settingsSave:", W - 150, 2, 110)
        ui["more"] = more
        self.win, self.win_ui = win, ui
        self.fill_settings()
        win.center()

    @objc.python_method
    def fill_settings(self):
        ui, cfg = self.win_ui, self.cfg
        if not ui:
            return
        names = list(cfg.names) if cfg else []
        ui["prof"].removeAllItems()
        for n in names:
            tags = [kind_label(self.kind(n))] + (["default"] if cfg and n == cfg.default_profile else []) + \
                   (["active"] if cfg and n == cfg.profile else [])
            ui["prof"].addItemWithTitle_(f"{n}  ({', '.join(tags)})")
            ui["prof"].lastItem().setRepresentedObject_(n)
        have = set(names)
        found = [d for d in nm.discover() if d["name"] not in have]
        ui["imp"].removeAllItems()
        for d in found:
            ok = bool(d["server"]) and not d.get("unsupported")
            ui["imp"].addItemWithTitle_(f"{d['name']}  ({d['vpn_type'] or d['protocol']})" if ok else f"{d['name']}  - {d['note']}")
            ui["imp"].lastItem().setRepresentedObject_(d["name"] if ok else "")
        if not found:
            ui["imp"].addItemWithTitle_("No other VPN service (System Settings > VPN)")
            ui["imp"].lastItem().setRepresentedObject_("")
        ui["upd"].setState_(NSOnState if (cfg is None or cfg.update_check) else NSOffState)
        chk = cfg.check if cfg else quality.CheckConfig()
        ui["en"].setState_(NSOnState if chk.enabled else NSOffState)
        ui["every"].setStringValue_(str(chk.interval_seconds))
        ui["over"].setStringValue_(str(chk.window_minutes))
        for i, (host, m, port) in enumerate(ui["rows"]):
            t = chk.targets[i] if i < len(chk.targets) else None
            host.setStringValue_(t.host if t else "")
            m.selectItemAtIndex_(0 if t and t.method == "ping" else 1)
            port.setStringValue_(str(t.port if t and t.method == "tcp" else 443))
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
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        self.win.makeKeyAndOrderFront_(None)

    def settingsRemove_(self, _):
        name = self.selected(self.win_ui["prof"])
        if name and self.confirm(f"Remove '{name}' from VeroScudo?", "The VPN service itself stays in System Settings.", "Remove"):
            self.admin(["remove", name])

    def settingsDefault_(self, _):
        name = self.selected(self.win_ui["prof"])
        if name:
            self.admin(["default", name])

    def settingsImport_(self, _):
        name = self.selected(self.win_ui["imp"])
        if name:
            self.admin(["import", name])

    def settingsUpdate_(self, sender):
        self.admin(["set", "updateCheck", "true" if sender.state() == NSOnState else "false"])

    def settingsCheckToggle_(self, _):
        self.show_check_fields()

    def settingsMethod_(self, _):
        for _host, m, port in self.win_ui["rows"]:
            port.setEnabled_(m.indexOfSelectedItem() == 1)

    def settingsSave_(self, _):
        ui = self.win_ui
        try:
            rows = [(str(h.stringValue()), "ping" if m.indexOfSelectedItem() == 0 else "tcp", int(str(p.stringValue()) or 443))
                    for h, m, p in ui["rows"]]
            chk = quality.from_form(ui["en"].state() == NSOnState, int(str(ui["every"].stringValue()) or 10),
                                    int(str(ui["over"].stringValue()) or 1), rows, is_host)
        except ValueError as e:
            msg = str(e) if "Address" in str(e) else "Seconds, minutes and ports must be whole numbers."
            self.alert("Not saved", msg)
            return
        if not str(ui["rows"][0][0].stringValue()).strip():
            ui["rows"][0][0].setStringValue_(quality.DEFAULT_HOST)
        self.admin(["set", "connectionCheck", json.dumps(chk.to_json())])

    # ---- actions
    @objc.python_method
    def run_action(self, action, arg=None):
        if action == "on":
            self.expect.start("connect")
        elif action == "reconnect":
            if not self.store.armed:
                notify("VeroScudo", "The VPN is off - use Turn VPN on.")
                return
            self.expect.start("reconnect")
            notify("VeroScudo - reconnecting", f"Traffic is blocked while '{self.facts.name}' reconnects.")
        elif action == "use":
            self.expect.start("switch")
            notify("VeroScudo", f"Switching to '{arg}'" + (" - traffic stays blocked until it is connected" if self.store.armed else ""))
        self.runner.start(action, traymodel.action_argv(action, arg))

    @objc.python_method
    def admin(self, args):
        self.runner.start("admin:" + args[0], traymodel.admin_argv(args))

    def turnOn_(self, _):
        self.run_action("on")

    def turnOff_(self, _):
        self.run_action("off")

    def reconnect_(self, _):
        self.run_action("reconnect")

    def useProfile_(self, sender):
        name = str(sender.representedObject())
        if self.cfg and name != self.cfg.profile:
            self.run_action("use", name)

    def toggleAwake_(self, _):
        want = not self.awake.active
        held = self.awake.set(want)
        keepawake.save_pref(held)
        if want and not held:
            notify("VeroScudo", "Keep awake is not available (caffeinate not found).")
        self.refresh()

    def status_(self, _):
        f, v = self.facts, self.view
        rows = traymodel.status_rows(f, v, self.awake.active, nm.iface(f.name) if f.up else None)
        ev = traymodel.read_events()
        events = traymodel.log_hint() if ev is None else ("\n".join(ev) or "(no events yet)")
        on_off = "Turn VPN off" if (v.armed or v.connected) else "Turn VPN on"
        text = "\n".join(f"{k}:  {val}" for k, val in rows)
        r = self.alert(v.title, v.text + "\n\n" + text, buttons=("Close", on_off, "Copy report"), icon=v.state, details=events)
        if r == NSAlertSecondButtonReturn and f.configured:
            self.run_action("off" if (v.armed or v.connected) else "on")
        elif r == NSAlertThirdButtonReturn:
            pb = NSPasteboard.generalPasteboard()
            pb.clearContents()
            pb.setString_forType_(f"VeroScudo {__version__} - {v.title}\n{text}\n\n--- last events\n{events}", NSPasteboardTypeString)

    def openLog_(self, _):
        if traymodel.read_events(n=1) is None:
            self.alert("The log cannot be opened", traymodel.log_hint())
            return
        subprocess.Popen(["open", "-a", "Console", str(traymodel.LOG)])

    def checkUpdates_(self, _):
        self.check_updates(True)
        if self.update_url and update.is_release_url(self.update_url):
            subprocess.Popen(["open", self.update_url])
        else:
            notify("VeroScudo", f"You have the latest version ({__version__})." if not (self.store.armed and not self.facts.up)
                   else "Traffic is blocked right now - check again once the VPN is connected.")

    @objc.python_method
    def check_updates(self, force):
        if not force and (not self.cfg or not self.cfg.update_check):
            return
        if self.store.armed and not self.facts.up:
            return
        f = keepawake.pref_file().parent / "update.json"
        info = traymodel.UpdateInfo()
        try:
            info.notified = str(json.loads(f.read_text()).get("notified", ""))
        except (OSError, ValueError, AttributeError):
            pass
        rel = update.fetch_latest()
        text, show = traymodel.update_notice(info, rel.tag if rel else None, bool(rel and update.is_newer(rel.tag)))
        self.update_url = rel.url if rel and text != "Check for updates" else ""
        self.upd_item.setTitle_(text)
        if show:
            notify(f"VeroScudo {rel.tag} is available", f"You run {__version__}. Open the menu to see the release.")
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps({"checked": info.checked, "notified": info.notified}))
        except OSError:
            pass

    def about_(self, _):
        r = self.alert(f"VeroScudo {__version__}",
                       "Master the switch.\n\nVPN on + connection lost = no network until the VPN is back or you turn it off. "
                       f"Two actions, no backdoor.\n\n{traymodel.REPO_URL}", buttons=("Close", "Open website", "Uninstall…"), icon="app")
        if r == NSAlertSecondButtonReturn:
            subprocess.Popen(["open", traymodel.REPO_URL])
        elif r == NSAlertThirdButtonReturn and self.confirm(
                "Uninstall VeroScudo?", "Removes the guard, the kill-switch, this menu-bar app and the sudo rule. Your VPN services "
                "stay as they are. config.json is kept for a later install.", "Uninstall"):
            self.admin(["uninstall"])

    def quit_(self, _):
        self.awake.release()
        NSApplication.sharedApplication().terminate_(None)

    # ---- dialogs
    @objc.python_method
    def alert(self, title, text, buttons=("OK",), icon=None, details=None):
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        a = NSAlert.alloc().init()
        a.setMessageText_(title)
        a.setInformativeText_(text)
        for b in buttons:
            a.addButtonWithTitle_(b)
        img = _image(icon, 64) if icon else None
        if img is not None:
            a.setIcon_(img)
        if details is not None:
            sv = NSScrollView.alloc().initWithFrame_(NSMakeRect(0, 0, 460, 170))
            sv.setHasVerticalScroller_(True)
            tv = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 460, 170))
            tv.setEditable_(False)
            tv.setString_(details)
            sv.setDocumentView_(tv)
            tv.scrollToEndOfDocument_(None)
            a.setAccessoryView_(sv)
        return a.runModal()

    @objc.python_method
    def confirm(self, title, text, ok):
        return self.alert(title, text, buttons=(ok, "Cancel")) == NSAlertFirstButtonReturn


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
