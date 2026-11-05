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
    NSScrollView,
    NSStatusBar,
    NSTextView,
    NSVariableStatusItemLength,
)
from Foundation import NSObject, NSTimer  # type: ignore
from PyObjCTools import AppHelper  # type: ignore

from . import __version__, keepawake, traymodel, update
from .backend import nm
from .config import Config, config_path
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
        self = objc.super(Tray, self).init()
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
        self.set_item = self.add("Settings", None)
        self.set_menu = NSMenu.alloc().init()
        self.set_menu.setAutoenablesItems_(False)
        self.set_item.setSubmenu_(self.set_menu)
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
                               guard_running=traymodel.guard_running(), expect=self.expect.kind)

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
        self.item.button().setToolTip_(traymodel.tooltip(v, self.awake.active))
        self.head.setTitle_(f"VeroScudo - {v.title}")
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
        key = (tuple(cfg.names), cfg.profile, cfg.default_profile, cfg.update_check) if cfg else ()
        if key == self.shown_profiles:
            return
        self.shown_profiles = key
        self.prof_menu.removeAllItems()
        self.set_menu.removeAllItems()
        self.prof_item.setEnabled_(bool(cfg))
        if cfg:
            for name in cfg.names:
                it = self.add(f"{name} ({kind_label(self.kind(name))})", "useProfile:", self.prof_menu, name)
                it.setState_(NSOnState if name == cfg.profile else NSOffState)
            self.prof_item.setTitle_(f"VPN profile: {cfg.profile} ({kind_label(self.kind(cfg.profile))})")
        # Settings: one submenu per change - each asks for an administrator's password
        imp = self.add("Import a VPN service", None, self.set_menu)
        imp_menu = NSMenu.alloc().init()
        imp_menu.setAutoenablesItems_(False)
        imp.setSubmenu_(imp_menu)
        have = set(cfg.names) if cfg else set()
        found = [d for d in nm.discover() if d["name"] not in have]
        for d in found:
            ok = bool(d["server"]) and not d.get("unsupported")
            it = self.add(f"{d['name']}  ({d['vpn_type'] or d['protocol']})" if ok else f"{d['name']}  - {d['note']}",
                          "importProfile:", imp_menu, d["name"])
            it.setEnabled_(ok)
        if not found:
            self.add("No other VPN service (System Settings > VPN)", None, imp_menu).setEnabled_(False)
        if cfg:
            for title, action in (("Remove profile", "removeProfile:"), ("Default profile", "defaultProfile:")):
                sub_item = self.add(title, None, self.set_menu)
                sub = NSMenu.alloc().init()
                sub_item.setSubmenu_(sub)
                for name in cfg.names:
                    it = self.add(name, action, sub, name)
                    if action == "defaultProfile:" and name == cfg.default_profile:
                        it.setState_(NSOnState)
            self.set_menu.addItem_(NSMenuItem.separatorItem())
            it = self.add("Check for a new release at login", "toggleUpdateCheck:", self.set_menu)
            it.setState_(NSOnState if cfg.update_check else NSOffState)
        it = self.add("Strict kill-switch (always on)", None, self.set_menu)
        it.setState_(NSOnState)
        it.setEnabled_(False)

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

    def importProfile_(self, sender):
        self.admin(["import", str(sender.representedObject())])

    def removeProfile_(self, sender):
        name = str(sender.representedObject())
        if self.confirm(f"Remove '{name}' from VeroScudo?", "The VPN service itself stays in System Settings.", "Remove"):
            self.admin(["remove", name])

    def defaultProfile_(self, sender):
        self.admin(["default", str(sender.representedObject())])

    def toggleUpdateCheck_(self, _):
        if self.cfg:
            self.admin(["set", "updateCheck", "false" if self.cfg.update_check else "true"])

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
    from .tray import _single_instance          # the same one-per-session lock (fcntl) as the Linux tray
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
