"""The Linux tray (tray.py) against stand-in GTK modules: TrayApp is built, refreshed and driven through the
hooks traymodel.TrayController calls, so a wrong name or argument shows here and not first on a desktop. Both
front ends are also checked for every hook the controller uses."""
import ast
import re
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

from veroscudo import traymodel as tm

SRC = Path(__file__).resolve().parent.parent / "veroscudo"
HOOKS = {"notice", "message", "choose_foreign", "config_reloaded", "show_state", "show_windows",
         "update_status", "update_settings", "refresh_soon", "show_update", "open_url",
         "set_clipboard"}


def test_the_controller_uses_the_documented_hooks_and_both_trays_have_them():
    text = (SRC / "traymodel.py").read_text()
    assert set(re.findall(r"\bself\.ui\.([a-z_]+)\(", text)) == HOOKS
    doc = tm.TrayController.__doc__
    assert all(re.search(rf"^\s+{h}\(", doc, re.MULTILINE) for h in HOOKS)
    for name, cls in (("tray.py", "TrayApp"), ("tray_macos.py", "Tray")):
        tree = ast.parse((SRC / name).read_text())
        body = next(c for c in ast.walk(tree) if isinstance(c, ast.ClassDef) and c.name == cls).body
        have = {n.name for n in body if isinstance(n, ast.FunctionDef)}
        assert HOOKS <= have, f"{name}: {sorted(HOOKS - have)}"
    assert not HOOKS & set(vars(tm.TrayController)), "a hook's name is taken by the controller itself"


@pytest.fixture
def app(monkeypatch, tmp_path):
    gi = types.ModuleType("gi")
    gi.require_version = lambda *a: None
    repo = types.ModuleType("gi.repository")
    for name in ("Gdk", "GdkPixbuf", "GLib", "Gtk", "Pango", "AyatanaAppIndicator3"):
        setattr(repo, name, mock.MagicMock(name=name))
    white = types.SimpleNamespace(red=1.0, green=1.0, blue=1.0)      # the text colour of a dark theme
    repo.Gtk.Label.return_value.get_style_context.return_value.get_color.return_value = white
    gi.repository = repo
    monkeypatch.setitem(sys.modules, "gi", gi)
    monkeypatch.setitem(sys.modules, "gi.repository", repo)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("VEROSCUDO_HOME", str(tmp_path / "run"))
    monkeypatch.setenv("VEROSCUDO_STATE", str(tmp_path / "lib"))
    conf = tmp_path / "config.json"
    conf.write_text('{"profiles":[{"profile":"CorporateVPN","server":"vpn.example.com","vpnType":"sstp"},'
                    '{"profile":"Backup","server":"203.0.113.9","vpnType":"l2tp"}],'
                    '"activeProfile":"CorporateVPN"}')
    monkeypatch.setenv("VEROSCUDO_CONFIG", str(conf))
    from veroscudo import tray
    fake = types.SimpleNamespace(
        connected=set(), owners={"wg1": "example-wireguard"},
        kind=lambda n: "vpn", is_connected=lambda n: n in fake.connected, iface=lambda n: "ppp0",
        other_tunnels=lambda own: [], tunnel_owners=lambda: dict(fake.owners),
        down_argv=lambda name: ["nmcli", "connection", "down", "id", name], discover=list)
    monkeypatch.setattr(tray, "nm", fake)
    monkeypatch.setattr(tm, "guard_running", lambda: True)
    monkeypatch.setattr(tm, "read_events", lambda n=40: ["2026-11-05 09:12:01,114 [INFO] ARMED"])
    sent, started = [], []
    monkeypatch.setattr(tray, "notify", lambda *a, **k: sent.append(a))
    monkeypatch.setattr(tray, "_popen", lambda argv: sent.append(tuple(argv)))
    monkeypatch.setattr(tm.Runner, "start", lambda self, tag, *argvs: started.append((tag, argvs)))
    monkeypatch.setattr(tm.exitinfo.ExitFetch, "start", lambda self, profile, now=None: False)
    a = tray.TrayApp()
    a.sent, a.started, a.fake, a.mod = sent, started, fake, tray
    return a


def test_gtk_tray_is_its_own_ui_and_refreshes(app):
    assert app.ui is app and isinstance(app, tm.TrayController)
    assert app.facts.configured and app.view.state == "off" and app.last == "off"
    app.ind.set_icon_full.assert_called_with(str(app.mod.icon_path("off")), "Off")
    app.head.set_label.assert_any_call("VeroScudo - Off")          # every menu item is the same stand-in
    assert app._shown_profiles == (("CorporateVPN", "Backup"), "CorporateVPN")
    app.store.armed_flag.write_text("1")
    assert app._tick() is True
    assert app.view.title == "Connecting"                           # turned on elsewhere
    body = tm.foreign_notice(app.foreign[0])[1]
    assert app.sent[-1] == ("VeroScudo - another VPN", body, "critical", "attention")
    app.win.show_status()
    app.win.show_settings()
    assert app._tick() is True


def test_gtk_turn_on_asks_and_disconnects_the_other_vpn(app):
    app.win.choose_foreign = lambda prompt: prompt.buttons[-1][0]    # the primary: Disconnect ... and turn on
    app.request_on()
    tag, argvs = app.started[-1]
    assert tag == "on" and argvs[0] == ["nmcli", "connection", "down", "id", "example-wireguard"]
    assert argvs[-1] == ["sudo", "-n", "/opt/veroscudo/bin/veroscudo", "on"]
    app.GLib.timeout_add.assert_called()                             # refresh_soon
    assert app.win.choose_foreign(tm.foreign_prompt(app.foreign, "CorporateVPN")) == "disconnect"


def test_gtk_drain_reports_failures_and_its_timer_survives_an_error(app):
    shown = []
    app.win.message = lambda text, secondary="", error=False: shown.append((text, secondary, error))
    app.runner.done.put(("admin:set", ["pkexec", "x"], 2, "", "veroscudo: no such key\n"))
    app.runner.done.put(("on", tm.action_argv("on"), 1, "", "sudo: a password is required\n"))
    assert app._drain_tick() is True
    assert shown == [("The change was not made", "no such key", True)]
    why = "VeroScudo's sudo rule is missing or outdated - run the installer again."
    assert app.sent[-1][:3] == ("VeroScudo - on failed", why, "critical")
    app.drain = mock.Mock(side_effect=RuntimeError("boom"))
    assert app._drain_tick() is True                                 # logged; the timer goes on


def test_gtk_forms_save_through_the_controller(app):
    shown = []
    app.win.show_settings()
    app.win.message = lambda text, secondary="", error=False: shown.append((text, secondary, error))
    se = app.win._se
    se["busy"] = False
    se["sp_url"].get_text.return_value = "http://status.example.com"
    assert app.win._save_status_url() is False
    assert shown == [("Not saved", "The status page must be an https:// address", True)]
    se["sp_url"].set_text.assert_called_with(app.status_page_url())
    row = tuple(mock.MagicMock() for _ in range(3))
    row[0].get_text.return_value, row[1].get_active_id.return_value = "api.example.com", "https"
    row[2].get_value_as_int.return_value = 443
    se["rows"] = [row]
    se["en"].get_active.return_value = True
    se["every"].get_value_as_int.return_value, se["over"].get_value_as_int.return_value = 10, 2
    app.win._save_check()
    tag, argvs = app.started[-1]
    assert tag == "admin:set" and argvs[0][0] == "pkexec"
    assert '{"host": "api.example.com", "method": "https", "port": 443}' in argvs[0][-1]
    row[0].get_text.return_value = "not a host!"
    app.win._save_check()
    assert shown[-1][0] == "Not saved" and shown[-1][1].startswith("Address 1:")


def test_gtk_copy_and_update_item(app, monkeypatch):
    from veroscudo import update
    text = app.copy_report()
    app.Gtk.Clipboard.get.return_value.set_text.assert_called_with(text, -1)
    url = update.RELEASES + "tag/v99.0"
    monkeypatch.setattr(update, "fetch_latest", lambda: update.Release("v99.0", url))
    app.update_clicked()
    app.upd_item.set_label.assert_any_call("Update available: v99.0…")
    assert app.sent[-1] == ("xdg-open", url)
