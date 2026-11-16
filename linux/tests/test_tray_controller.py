"""traymodel.TrayController - what both trays do, tested once with a stand-in front end: the state from look
to look and its notices, Turn on next to another VPN, the results of the commands, the update check, the two
settings forms."""
import json
import os
import re
import threading
import types
from pathlib import Path

import pytest

from veroscudo import backend, keepawake, update
from veroscudo import traymodel as tm

SRC = Path(__file__).resolve().parent.parent / "veroscudo"
CONFIG = ('{"profiles":[{"profile":"CorporateVPN","server":"vpn.example.com","vpnType":"sstp"},'
          '{"profile":"wg-home","server":"203.0.113.9","port":51820,"protocol":"udp","vpnType":"wireguard"}],'
          '"activeProfile":"CorporateVPN","updateCheck":true}')


class FakeUi:
    """Every hook the controller calls, recorded as (hook, arguments)."""

    def __init__(self):
        self.calls, self.answer = [], "cancel"

    def notices(self):
        return [c[1:] for c in self.calls if c[0] == "notice"]

    def names(self):
        return [c[0] for c in self.calls]

    def notice(self, title, body, urgency="normal", state="attention"):
        self.calls.append(("notice", title, body, urgency, state))

    def message(self, title, text, error=False):
        self.calls.append(("message", title, text, error))

    def choose_foreign(self, prompt):
        self.calls.append(("choose_foreign", prompt))
        return self.answer

    def show_update(self, text):
        self.calls.append(("show_update", text))

    def open_url(self, url):
        self.calls.append(("open_url", url))

    def set_clipboard(self, text):
        self.calls.append(("set_clipboard", text))

    def __getattr__(self, name):                       # the hooks without arguments
        plain = ("config_reloaded", "show_state", "show_windows", "update_status", "update_settings",
                 "refresh_soon")
        if name not in plain:
            raise AttributeError(name)
        return lambda: self.calls.append((name,))


REAL_SPAWN = tm.TrayController.__dict__["spawn"]


@pytest.fixture(autouse=True)
def work_runs_at_once(monkeypatch):
    """The controller's background work (the update check) runs in place, so a test sees its result at once."""
    monkeypatch.setattr(tm.TrayController, "spawn", staticmethod(lambda work: work()))


@pytest.fixture
def ctl(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("VEROSCUDO_HOME", str(tmp_path / "run"))
    monkeypatch.setenv("VEROSCUDO_STATE", str(tmp_path / "lib"))
    conf = tmp_path / "config.json"
    conf.write_text(CONFIG)
    monkeypatch.setenv("VEROSCUDO_CONFIG", str(conf))
    fake = types.SimpleNamespace(
        connected=set(), owners={}, kinds={"wg-home": "wireguard"},
        kind=lambda n: fake.kinds.get(n, "vpn"), is_connected=lambda n: n in fake.connected,
        iface=lambda n: "ppp0",
        other_tunnels=lambda own: [], tunnel_owners=lambda: dict(fake.owners),
        down_argv=lambda name: ["nmcli", "connection", "down", "id", name], discover=list)
    monkeypatch.setattr(tm, "guard_running", lambda: True)
    monkeypatch.setattr(tm, "read_events", lambda n=40: ["2026-11-05 09:12:01,114 [INFO] ARMED"])
    started = []
    monkeypatch.setattr(tm.Runner, "start", lambda self, tag, *argvs: started.append((tag, argvs)))
    monkeypatch.setattr(tm.exitinfo.ExitFetch, "start", lambda self, profile, now=None: False)
    c = tm.TrayController(fake, FakeUi())
    c.fake, c.started, c.conf = fake, started, conf
    return c


def arm(c, up=True, profile="CorporateVPN"):
    """The guard's files as it leaves them: armed, and (up) the tunnel it let through."""
    c.store.armed_flag.write_text("1")
    if up:
        c.fake.connected = {profile}
        c.store.applied_file.write_text(json.dumps({"profile": profile, "tunnel": "ppp0"}))
    else:
        c.fake.connected = set()


def test_the_controller_calls_only_the_backend_contract():
    used = set(re.findall(r"\bnm\.([A-Za-z_]\w*)\s*\(", (SRC / "traymodel.py").read_text()))
    assert used and used <= set(backend.VPN_API), sorted(used - set(backend.VPN_API))


def test_is_up_means_connected_and_let_through_while_armed(ctl):
    nm, store = ctl.fake, ctl.store
    assert not tm.is_up(nm, store, "CorporateVPN")
    nm.connected = {"CorporateVPN"}
    assert tm.is_up(nm, store, "CorporateVPN")                      # not armed: connected is enough
    store.armed_flag.write_text("1")
    assert not tm.is_up(nm, store, "CorporateVPN")                  # armed: only what the guard let through
    store.applied_file.write_text(json.dumps({"profile": "CorporateVPN", "tunnel": "ppp0"}))
    assert tm.is_up(nm, store, "CorporateVPN")
    assert not tm.is_up(nm, store, "wg-home", armed=False)           # another profile: not connected at all
    nm.connected.add("wg-home")
    assert tm.is_up(nm, store, "wg-home", armed=False) and not tm.is_up(nm, store, "wg-home", armed=True)


def test_the_first_look_is_quiet_and_draws_in_order(ctl):
    ctl.refresh()
    assert ctl.view.state == "off" and ctl.last == "off" and ctl.facts.name == "CorporateVPN"
    assert ctl.ui.notices() == []
    assert ctl.ui.names() == ["config_reloaded", "show_state", "show_windows"]   # config.json was read
    ctl.ui.calls.clear()
    ctl.refresh()
    assert ctl.ui.calls == [("show_state",), ("show_windows",)]


def test_state_changes_send_their_notices(ctl):
    ctl.refresh()
    arm(ctl)
    ctl.refresh()
    assert ctl.view.state == "protected" and ctl.tunnel == "ppp0" and ctl.protected_since > 0
    assert ctl.ui.notices() == [("VPN protected", "Tunnel up, kill-switch on.", "normal", "protected")]
    ctl.ui.calls.clear()
    arm(ctl, up=False)                                                # a drop nobody asked for
    ctl.refresh()
    assert ctl.view.title == "Blocked - reconnecting" and ctl.tunnel is None
    (title, _body, urgency, state), = ctl.ui.notices()
    assert (title, urgency, state) == ("VPN connection lost - traffic blocked", "critical", "blocked")
    order = ctl.ui.names()
    assert order.index("show_state") < order.index("notice") < order.index("show_windows")
    ctl.ui.calls.clear()
    ctl.store.armed_flag.unlink()
    ctl.refresh()
    assert ctl.ui.notices()[0][0] == "VPN turned off"


def test_turned_on_elsewhere_reads_as_connecting_and_expires_once(ctl, monkeypatch):
    ctl.refresh()
    arm(ctl, up=False)                                                # `sudo veroscudo on` in a terminal
    ctl.refresh()
    assert ctl.view.title == "Connecting" and ctl.expect.kind == "connect"
    assert ctl.ui.notices()[0][0] == "VeroScudo on - connecting"
    ctl.ui.calls.clear()
    ctl.expect.since -= tm.EXPECT_SECONDS + 1                         # still not connected two minutes later
    ctl.refresh()
    assert ctl.expect.kind is None and ctl.view.title == "Blocked - reconnecting"
    assert ctl.ui.notices() == [(*tm.expired_notice("CorporateVPN"), "blocked")]
    ctl.ui.calls.clear()
    ctl.refresh()
    assert ctl.ui.notices() == []                                     # said once


def test_a_reconnect_the_user_started_is_not_called_a_drop(ctl):
    arm(ctl)
    ctl.refresh()
    ctl.ui.calls.clear()
    ctl.act("reconnect")
    assert ctl.expect.kind == "reconnect" and ctl.started[-1][0] == "reconnect"
    assert ctl.started[-1][1] == (["sudo", "-n", "/opt/veroscudo/bin/veroscudo", "reconnect"],)
    assert [n[0] for n in ctl.ui.notices()] == ["VeroScudo - reconnecting"]
    assert ctl.ui.names()[-1] == "refresh_soon"
    ctl.ui.calls.clear()
    arm(ctl, up=False)
    ctl.refresh()
    assert ctl.view.title == "Reconnecting" and ctl.ui.notices() == []


def test_reconnect_is_refused_while_off_and_for_hiddify(ctl):
    ctl.refresh()
    ctl.act("reconnect")
    assert ctl.started == []
    assert ctl.ui.notices() == [("VeroScudo", "The VPN is off - use Turn VPN on.", "normal", "off")]
    assert "refresh_soon" not in ctl.ui.names()
    ctl.fake.kinds["CorporateVPN"] = "hiddify"
    ctl._kinds.clear()
    arm(ctl)
    ctl.refresh()
    ctl.ui.calls.clear()
    ctl.act("reconnect")
    assert ctl.started == []
    assert ctl.ui.notices() == [("VeroScudo", tm.RECONNECT_HIDDIFY, "normal", "blocked")]


def test_a_switch_says_so_and_a_wireguard_profile_gets_its_word(ctl):
    ctl.refresh()
    ctl.ui.calls.clear()
    ctl.act("use", "wg-home")
    assert ctl.expect.kind == "switch" and ctl.started[-1][1][-1][-2:] == ["use", "wg-home"]
    assert ctl.ui.notices() == [("VeroScudo", "Switching to 'wg-home'", "normal", "off")]
    ctl.store.active_file.write_text("wg-home")                       # the guard switched
    ctl.ui.calls.clear()
    ctl.refresh()
    assert ctl.cfg.profile == "wg-home" and ctl.facts.kind == "wireguard"
    assert [n[0] for n in ctl.ui.notices()] == ["VeroScudo - WireGuard profile"]
    ctl.ui.calls.clear()
    ctl.refresh()
    assert ctl.ui.notices() == []                                     # every switch, once
    arm(ctl, profile="wg-home")
    ctl.act("use", "CorporateVPN")
    body = "Switching to 'CorporateVPN' - traffic stays blocked until it is connected"
    assert ctl.ui.notices()[-1] == ("VeroScudo", body, "normal", "blocked")


def test_another_vpn_is_announced_once_while_on(ctl):
    ctl.fake.owners = {"wg1": "example-wireguard"}
    ctl.refresh()
    assert [x.name for x in ctl.foreign] == ["example-wireguard"]
    assert ctl.ui.notices() == []                                     # off: not its business
    arm(ctl)
    ctl.refresh()
    assert ctl.facts.others == ("example-wireguard",) and ctl.view.state == "attention"
    (title, body, urgency, state), = ctl.ui.notices()                 # instead of the state's own notice
    assert title == "VeroScudo - another VPN" and "example-wireguard" in body
    assert (urgency, state) == ("critical", "attention")
    ctl.ui.calls.clear()
    ctl.refresh()
    assert ctl.ui.notices() == []


def test_other_vpns_are_asked_for_at_most_every_10_seconds(ctl):
    ctl.refresh()
    ctl.fake.owners = {"wg1": "example-wireguard"}
    ctl.refresh()
    assert ctl.foreign == []                                          # the answer of a moment ago
    assert [x.iface for x in ctl.find_foreign(force=True)] == ["wg1"]
    ctl.fake.tunnel_owners = lambda: (_ for _ in ()).throw(OSError("nmcli"))
    assert ctl.find_foreign(force=True) == []                         # the backend failed: none known


def test_turn_on_without_another_vpn_just_turns_on(ctl):
    ctl.refresh()
    ctl.request_on()
    assert ctl.started == [("on", (["sudo", "-n", "/opt/veroscudo/bin/veroscudo", "on"],))]
    assert ctl.expect.kind == "connect" and "choose_foreign" not in ctl.ui.names()


def test_turn_on_next_to_another_vpn_asks_first(ctl):
    ctl.refresh()
    ctl.fake.owners = {"wg1": "example-wireguard"}
    ctl.fake.other_tunnels = lambda own: ["tun7"]                     # and a VPN app's own tunnel
    ctl.request_on()                                                  # the answer: cancel
    prompt = ctl.ui.calls[-1][1]
    assert ctl.ui.names()[-1] == "choose_foreign"
    assert [b[0] for b in prompt.buttons] == ["cancel", "anyway", "disconnect"]
    assert ctl.started == [] and ctl.expect.kind is None
    assert ctl._foreign_shown == {"tun7", "wg1"}                      # seen in the question: no notice again
    ctl.ui.answer = "disconnect"
    ctl.request_on()
    tag, argvs = ctl.started[-1]
    assert tag == "on" and argvs == (["nmcli", "connection", "down", "id", "example-wireguard"],
                                     ["sudo", "-n", "/opt/veroscudo/bin/veroscudo", "on"])
    ctl.ui.answer = "anyway"
    ctl.request_on()
    assert len(ctl.started[-1][1]) == 1 and ctl.started[-1][1][0][-1] == "on"
    arm(ctl)
    ctl.ui.calls.clear()
    ctl.refresh()
    assert "VeroScudo - another VPN" not in [n[0] for n in ctl.ui.notices()]


def test_the_on_off_button_follows_the_state(ctl):
    ctl.refresh()
    ctl.toggle_on_off()
    assert ctl.started[-1][0] == "on"
    arm(ctl)
    ctl.refresh()
    ctl.toggle_on_off()
    assert ctl.started[-1][0] == "off"


def test_a_failed_action_is_reported_and_ends_the_wait(ctl):
    ctl.refresh()
    ctl.act("on")
    ctl.ui.calls.clear()
    ctl.runner.done.put(("on", tm.action_argv("on"), 1, "", "sudo: a password is required\n"))
    ctl.drain()
    assert ctl.expect.kind is None
    why = "VeroScudo's sudo rule is missing or outdated - run the installer again."
    assert ctl.ui.calls == [("notice", "VeroScudo - on failed", why, "critical", "attention")]
    ctl.runner.done.put(("off", tm.action_argv("off"), 0, "", ""))    # a success says nothing: the state will
    ctl.ui.calls.clear()
    ctl.drain()
    assert ctl.ui.calls == []


def test_admin_results_applied_cancelled_and_failed(ctl, monkeypatch):
    ctl.refresh()
    ctl.admin(["set", "vm", "false"])
    assert ctl.started[-1][0] == "admin:set" and ctl.started[-1][1][0][-4:] == ["set", "--", "vm", "false"]
    argv = ctl.started[-1][1][0]
    ctl.conf.write_text(CONFIG.replace('"updateCheck":true', '"updateCheck":false'))
    os.utime(ctl.conf, (1, 1))                                        # a time stamp that differs for certain
    ctl.ui.calls.clear()
    ctl.runner.done.put(("admin:set", argv, 0, "", ""))
    ctl.drain()
    assert ctl.cfg.update_check is False and ctl.ui.names() == ["config_reloaded"]
    ctl.refresh_after_admin = True                                    # macOS: one more pass at once
    ctl.conf.write_text(CONFIG)
    os.utime(ctl.conf, (2, 2))
    ctl.ui.calls.clear()
    ctl.runner.done.put(("admin:set", argv, 0, "", ""))
    ctl.drain()
    assert ctl.cfg.update_check is True and ctl.ui.names() == ["config_reloaded", "show_state", "show_windows"]
    ctl.runner.done.put(("admin:set", argv, 0, "", ""))               # config.json already read: no refill
    ctl.ui.calls.clear()
    ctl.drain()
    assert ctl.ui.names() == ["show_state", "show_windows"]
    ctl.ui.calls.clear()
    monkeypatch.setattr(tm, "cancelled", lambda rc, err: rc == 126)
    ctl.runner.done.put(("admin:set", argv, 126, "", ""))             # the password dialog was dismissed
    ctl.drain()
    assert ctl.ui.calls == [("update_settings",)]
    ctl.ui.calls.clear()
    ctl.runner.done.put(("admin:remove", argv, 2, "", "veroscudo: 'CorporateVPN' is the active profile\n"))
    ctl.drain()
    assert ctl.ui.calls == [("update_settings",), ("message", "The change was not made",
                                                   "'CorporateVPN' is the active profile", True)]


def test_without_a_config_the_tunnel_is_forgotten(ctl):
    arm(ctl)
    ctl.refresh()
    assert ctl.tunnel == "ppp0"
    ctl.conf.write_text("not json")
    os.utime(ctl.conf, (2, 2))
    ctl.refresh()
    assert not ctl.facts.configured and ctl.view.title == "Not configured" and ctl.tunnel is None


def test_update_check_outcomes(ctl, monkeypatch):
    url = update.RELEASES + "tag/v99.0"
    asked = []
    monkeypatch.setattr(update, "fetch_latest", lambda: asked.append(1) or update.Release("v99.0", url))
    ctl.refresh()
    ctl.check_updates()
    assert ctl.update_tag == "v99.0" and ctl.update_url == url
    assert ctl.ui.calls[-2] == ("show_update", "Update available: v99.0…")
    title, body, _urgency, state = ctl.ui.notices()[-1]
    assert title == "VeroScudo v99.0 is available" and "Open the tray menu" in body and state == "protected"
    saved = json.loads((keepawake.pref_file().parent / "update.json").read_text())
    assert saved["notified"] == "v99.0" and saved["checked"] > 0
    ctl.ui.calls.clear()
    ctl.update_clicked()                                              # opens the release, no second notice
    assert ctl.ui.calls == [("show_update", "Update available: v99.0…"), ("open_url", url)]
    # nothing newer, or no answer
    old = update.Release("v0.0.1", update.RELEASES + "tag/v0.0.1")
    monkeypatch.setattr(update, "fetch_latest", lambda: old)
    ctl.ui.calls.clear()
    ctl.update_clicked()
    assert ctl.update_url == "" and ctl.update_tag is None
    assert ctl.ui.calls[0] == ("show_update", "Check for updates")
    assert ctl.ui.notices()[0][1].startswith("You have the latest version (")
    monkeypatch.setattr(update, "fetch_latest", lambda: None)
    ctl.check_updates(force=True)
    assert ctl.ui.calls[-1] == ("show_update", "Check for updates")
    ctl.ui.calls.clear()
    ctl.update_clicked()                                              # asked for, and no answer: said so
    assert ctl.ui.notices()[-1][1] == "The update check got no answer - try again later."


def test_the_update_check_never_runs_on_the_ui_thread(ctl, monkeypatch):
    seen, go = [], threading.Event()
    monkeypatch.setattr(update, "fetch_latest", lambda: (go.wait(5), seen.append(threading.current_thread().name))[0] and None)
    monkeypatch.setattr(tm.TrayController, "spawn", REAL_SPAWN)
    started = []
    real = threading.Thread

    def thread(*a, **k):
        t = real(*a, **k)
        started.append(t)
        return t
    monkeypatch.setattr(tm.threading, "Thread", thread)
    ctl.refresh()
    ctl.check_updates(force=True)
    ctl.check_updates(force=True)                                     # one at a time
    assert len(started) == 1 and seen == []                           # still asking; the caller did not wait
    go.set()
    started[0].join(5)
    assert seen == ["veroscudo-tray-work"]
    ctl.ui.calls.clear()
    ctl.drain()                                                       # the answer is taken on the UI thread's timer
    assert ctl.ui.calls[-1] == ("show_update", "Check for updates")


def test_update_check_never_while_blocked_and_only_when_wanted(ctl, monkeypatch):
    asked = []
    monkeypatch.setattr(update, "fetch_latest", lambda: asked.append(1))
    ctl.refresh()
    arm(ctl, up=False)
    ctl.refresh()
    ctl.ui.calls.clear()
    ctl.update_clicked()
    blocked = "Traffic is blocked right now - check again once the VPN is connected."
    assert asked == [] and ctl.ui.notices() == [("VeroScudo", blocked, "normal", "blocked")]
    ctl.store.armed_flag.unlink()
    ctl.refresh()
    ctl.conf.write_text(CONFIG.replace('"updateCheck":true', '"updateCheck":false'))
    os.utime(ctl.conf, (3, 3))
    ctl.refresh()
    ctl.check_updates()                                               # the automatic check is switched off
    assert asked == []
    ctl.check_updates(force=True)
    assert asked == [1]
    other = tm.TrayController(ctl.fake, FakeUi(), menu_name="menu-bar menu")
    newer = update.Release("v98.0", update.RELEASES + "tag/v98.0")
    monkeypatch.setattr(update, "fetch_latest", lambda: newer)
    other.check_updates(force=True)
    assert "Open the menu-bar menu" in other.ui.notices()[-1][1]


def test_the_report_goes_to_the_clipboard(ctl):
    arm(ctl)
    ctl.refresh()
    text = ctl.copy_report()
    assert ctl.ui.calls[-1] == ("set_clipboard", text)
    assert text.splitlines()[0].endswith("- Protected") and "VPN profile  CorporateVPN (VPN)" in text
    assert "Tunnel       ppp0" in text
    assert text.endswith("--- last events\n2026-11-05 09:12:01,114 [INFO] ARMED")


def test_connection_form_is_checked_before_the_password_is_asked(ctl):
    assert ctl.save_check(True, 10, 2, [("not a host!", "tcp", 443)]).startswith("Address 1:")
    assert ctl.started == []
    assert ctl.save_check(True, 10, 2, [("api.example.com", "https", 443), ("", "tcp", 443)]) == ""
    tag, argvs = ctl.started[-1]
    assert tag == "admin:set" and argvs[0][-2] == "connectionCheck"
    assert '{"host": "api.example.com", "method": "https", "port": 443}' in argvs[0][-1]


def test_status_page_address_unchanged_saved_or_refused(ctl):
    from veroscudo import statuspage
    assert ctl.save_status_url(f"  {statuspage.DEFAULT_URL} ") is None
    assert ctl.save_status_url("http://status.example.com") == "The status page must be an https:// address"
    assert ctl.status_page_url() == statuspage.DEFAULT_URL
    assert ctl.save_status_url("https://status.example.com") == ""
    assert ctl.status_page_url() == "https://status.example.com"


def test_own_settings_are_saved_at_once_and_the_window_redrawn(ctl):
    ctl.set_exit_enabled(False)
    assert ctl.exit_enabled() is False and ctl.ui.calls[-1] == ("update_status",)
    ctl.clear_events()
    assert keepawake.get_pref("eventsClearedAt") and ctl.events(view=True) == []
    assert ctl.events() == ["2026-11-05 09:12:01,114 [INFO] ARMED"]
