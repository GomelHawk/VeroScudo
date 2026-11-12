"""The macOS menu-bar app (alpha, not yet run on a real Mac): the scutil parts it needs, the shared chart/badge geometry,
and a smoke run of tray_macos.py against stand-in AppKit modules - every window is built and refreshed, so a Python
mistake (a wrong name, a wrong argument) shows here and not first on a Mac."""
import ast
import subprocess
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

from veroscudo import scutil, stats
from veroscudo import traymodel as tm

SRC = Path(__file__).resolve().parent.parent / "veroscudo"

# ---------------------------------------------------------------- scutil: other VPNs on macOS
LISTING = ('Available network connection services in the current set (*=enabled):\n'
           '* (Connected)      0A3E4F6B-1111-2222-3333-444455556666 IPSec              "CorporateVPN"   [IPSec]\n'
           '* (Connected)      0A3E4F6B-1111-2222-3333-444455556667 PPP --> L2TP       "Office L2TP"    [PPP/L2TP]\n'
           '* (Disconnected)   0A3E4F6B-1111-2222-3333-444455556668 VPN (com.x.app)    "App VPN"        [VPN/com.x.app]\n'
           '* (Connected)      0A3E4F6B-1111-2222-3333-444455556669 VPN (com.y.app)    "Odd VPN"        [VPN/com.y.app]\n')
STATUS = {"CorporateVPN": "Connected\nExtended Status <dictionary> {\n  IPv4 : <dictionary> {\n    InterfaceName : ipsec0\n  }\n}\n",
          "Office L2TP": "Connected\nExtended Status <dictionary> {\n  PPP : <dictionary> {\n    InterfaceName : ppp0\n  }\n}\n",
          "Odd VPN": "Connected\nExtended Status <dictionary> {\n  InterfaceName : en0\n}\n"}


def test_scutil_connected_services_and_their_tunnels(monkeypatch):
    assert scutil.connected_services(LISTING) == ["CorporateVPN", "Office L2TP", "Odd VPN"]
    assert scutil.parse_iface(STATUS["Office L2TP"]) == "ppp0" and scutil.parse_iface(STATUS["Odd VPN"]) is None
    monkeypatch.setattr(scutil.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, LISTING, ""))
    monkeypatch.setattr(scutil, "_status", lambda name: STATUS.get(name, "Disconnected\n"))
    # a physical interface is never a tunnel: the service that reports en0 is left out
    assert scutil.tunnel_owners() == {"ipsec0": "CorporateVPN", "ppp0": "Office L2TP"}
    owners = scutil.tunnel_owners()
    fl = tm.foreign_list(scutil.other_tunnels("ipsec0"), owners, "ipsec0", "CorporateVPN", ("CorporateVPN",))
    assert [(x.name, x.kind, x.can_disconnect) for x in fl] == [("Office L2TP", "not imported", True)]
    assert scutil.down_argv(fl[0].connection) == ["scutil", "--nc", "stop", "Office L2TP"]


def test_scutil_tunnel_owners_without_scutil_is_empty(monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError("scutil")
    monkeypatch.setattr(scutil.subprocess, "run", missing)
    assert scutil.tunnel_owners() == {}


# ---------------------------------------------------------------- shared geometry
def test_stats_hit_follows_the_windows_hover_rule():
    g = tm.STATS_GEOMETRY
    y = g["top"] + g["label_h"] + 5                       # in today's strip
    assert tm.stats_hit(g["x"], y) == (0, 0)
    assert tm.stats_hit(g["x"] + 143 * g["bar_w"] + 1, y + 2 * g["row_h"]) == (2, 143)
    assert tm.stats_hit(g["x"] + 10, g["top"] + 3) is None             # on the day's label, not a bar
    assert tm.stats_hit(g["x"] + 144 * g["bar_w"], y) is None          # right of the strip
    assert tm.stats_hit(g["x"], y + 7 * g["row_h"]) is None            # below the last day
    assert tm.stats_hit(g["x"], y + 3 * g["row_h"], rows=3) is None
    assert [lab for _x, lab in tm.stats_grid()] == ["00", "03", "06", "09", "12", "15", "18", "21", "24"]
    assert tm.stats_grid()[-1][0] == g["x"] + 144 * g["bar_w"]


def test_stats_colours_match_the_linux_and_windows_charts():
    assert tm.stats_colour("good", True) == tm.stats_colour("up", False) == tm.hex_rgb("#30c84f")
    assert tm.stats_colour("unstable", False) == tm.hex_rgb("#e8a33d")
    assert tm.stats_colour("bad", True) == tm.hex_rgb("#9a4a2a")
    assert tm.stats_colour("off", True) == tm.hex_rgb("#464646") and tm.stats_colour("off", False) == tm.hex_rgb("#cdcdcd")
    assert tm.stats_colour("future", True) is None


def test_awake_rings_sit_in_the_bottom_right_corner():
    rings = tm.awake_rings(16)
    assert [r[0] for r in rings] == [(20, 20, 20), (46, 204, 64), (20, 20, 20)]
    (_, cx, cy, r0), (_, _, _, r1), (_, _, _, r2) = rings
    assert cx == cy == 12.5 and r0 == 3.5 and r0 > r1 > r2 > 0 and cx + r0 == 16


# ---------------------------------------------------------------- the source: PyObjC rules and parity with tray.py
def _tree():
    return ast.parse((SRC / "tray_macos.py").read_text())


def test_every_menu_and_button_action_has_its_method():
    tree = _tree()
    methods = {n.name for c in ast.walk(tree) if isinstance(c, ast.ClassDef) for n in c.body if isinstance(n, ast.FunctionDef)}
    selectors = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and n.value.endswith(":") and n.value[:-1].isidentifier() and n.value[0].islower()}
    assert selectors, "no actions found"
    missing = sorted(s for s in selectors - {"admin:"} if s.replace(":", "_") not in methods)     # admin: is a tag
    assert not missing, missing


def test_python_helpers_are_hidden_from_objective_c():
    """A method of an NSObject subclass without @objc.python_method becomes a selector; one with a name like `fill_menus`
    and the wrong number of arguments stops the class from loading (on a Mac only)."""
    allowed = {"init", "isFlipped"}
    for c in ast.walk(_tree()):
        if not isinstance(c, ast.ClassDef):
            continue
        for n in c.body:
            if not isinstance(n, ast.FunctionDef) or n.name in allowed or n.name.endswith("_"):
                continue
            decorated = any(isinstance(d, ast.Attribute) and d.attr == "python_method" for d in n.decorator_list)
            assert decorated, f"{c.name}.{n.name} needs @objc.python_method"
        for n in c.body:
            if isinstance(n, ast.FunctionDef) and n.name.endswith("_") and n.name not in allowed:
                assert len(n.args.args) - 1 == n.name.count("_"), f"{c.name}.{n.name}: arguments do not match the selector"


def test_texts_match_the_linux_tray():
    mac, lin = (SRC / "tray_macos.py").read_text(), (SRC / "tray.py").read_text()
    for text in ("unless \"\n                   \"lanAllow lets it through", "Save connection settings", "Recent events",
                 "VeroScudo - WireGuard profile", "it flows again once", "Statistics…", "\"Copy\"", "\"Statistics\"", "Open log",
                 "traymodel.BEHAVIOUR_NOTE", "traymodel.EXIT_ABOUT", "traymodel.remove_question", "traymodel.foreign_prompt",
                 "traymodel.turned_on_elsewhere", "Another VPN is connected"):
        probe = text.replace('"\n                   "', "")
        assert probe in mac.replace('"\n                   "', "").replace('"\n                                    "', ""), text
    assert "lanAllow lets it through" in lin
    order = [ln.strip() for ln in mac.splitlines() if "self.add(\"" in ln]
    titles = [ln.split('"')[1] for ln in order]
    assert titles.index("Statistics…") + 1 == titles.index("Settings…")


# ---------------------------------------------------------------- smoke run against stand-in AppKit modules
class _NS:
    """Stands in for NSObject / NSView: alloc().init...() returns the object, any other call is a mock."""

    def __init__(self):
        self._m = mock.MagicMock()

    @classmethod
    def alloc(cls):
        return cls.__new__(cls)

    def init(self):
        return self

    def initWithFrame_(self, _frame):
        self._m = mock.MagicMock()
        return self

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return getattr(self.__dict__.setdefault("_m", mock.MagicMock()), name)


_INTS = {"NSAlertFirstButtonReturn": 1000, "NSAlertSecondButtonReturn": 1001, "NSAlertThirdButtonReturn": 1002,
         "NSOnState": 1, "NSOffState": 0}


class _AppKit(types.ModuleType):
    def __getattr__(self, name):
        if name in ("NSObject", "NSView"):
            return _NS
        if name in _INTS:
            return _INTS[name]
        if name.startswith(("NSWindowStyleMask", "NSEventMask", "NSEventModifierFlag", "NSTrackingMouse", "NSTrackingActive", "NSTrackingInVisible", "NSEventType")):
            return 1 << (len(name) % 16)
        m = mock.MagicMock(name=name)
        setattr(self, name, m)
        return m


@pytest.fixture
def mac(monkeypatch, tmp_path):
    objc = types.ModuleType("objc")
    objc.python_method = lambda f: f
    objc.super = super
    appkit, foundation = _AppKit("AppKit"), _AppKit("Foundation")
    helper = types.ModuleType("PyObjCTools")
    helper.AppHelper = mock.MagicMock()
    for name, mod in (("objc", objc), ("AppKit", appkit), ("Foundation", foundation), ("PyObjCTools", helper)):
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.delitem(sys.modules, "veroscudo.tray_macos", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("VEROSCUDO_HOME", str(tmp_path / "run"))
    monkeypatch.setenv("VEROSCUDO_STATE", str(tmp_path / "lib"))
    conf = tmp_path / "config.json"
    conf.write_text('{"profiles":[{"profile":"CorporateVPN","server":"vpn.example.com","vpnType":"ikev2"},'
                    '{"profile":"Backup","server":"203.0.113.9","vpnType":"l2tp"}],"activeProfile":"CorporateVPN",'
                    '"connectionCheck":{"enabled":true,"intervalSeconds":10,"windowMinutes":2,'
                    '"targets":[{"host":"1.1.1.1","method":"tcp","port":443}]}}')
    monkeypatch.setenv("VEROSCUDO_CONFIG", str(conf))
    import veroscudo.tray_macos as tmac
    fake = types.SimpleNamespace(
        connected={"CorporateVPN": True}, owners={"ppp0": "Office L2TP"},
        kind=lambda n: "vpn", is_connected=lambda n: fake.connected.get(n, False), iface=lambda n: "ipsec0",
        other_tunnels=lambda own: [], tunnel_owners=lambda: dict(fake.owners), down_argv=scutil.down_argv,
        discover=lambda: [{"name": "Office L2TP", "vpn_type": "l2tp", "server": "l2tp.example.com", "protocol": "udp",
                           "note": ""}])
    monkeypatch.setattr(tmac, "nm", fake)
    monkeypatch.setattr(tmac.traymodel, "guard_running", lambda: True)
    monkeypatch.setattr(tmac.traymodel, "read_events", lambda n=40: ["2026-11-05 09:12:01,114 [INFO] ARMED"])
    sent = []
    monkeypatch.setattr(tmac, "notify", lambda title, body: sent.append((title, body)))
    monkeypatch.setattr(tmac, "_popen", lambda argv: sent.append(tuple(argv)))
    started = []
    monkeypatch.setattr(tmac.traymodel.Runner, "start", lambda self, tag, *argvs: started.append((tag, argvs)))
    monkeypatch.setattr(tmac.exitinfo.ExitFetch, "start", lambda self, profile, now=None: False)
    tray = tmac.Tray.alloc().init()
    tray.sent, tray.started, tray.fake, tray.mod = sent, started, fake, tmac
    return tray


def test_mac_tray_builds_every_window_and_refreshes(mac):
    assert mac.facts.configured and mac.facts.name == "CorporateVPN"
    mac.store.armed_flag.write_text("1")
    mac.refresh()
    assert mac.view.state in ("protected", "blocked")
    assert [x.name for x in mac.foreign] == ["Office L2TP"]
    assert any(t == "VeroScudo - another VPN" for t, *_ in mac.sent)            # announced once
    n = len(mac.sent)
    mac.refresh()
    assert len(mac.sent) == n
    mac.status_(None)
    mac.st_win.isVisible.return_value = True
    mac.update_status()
    assert mac.st["rows"] is not None
    text = mac.copy_report()
    assert "Other VPNs   Office L2TP (not imported)" in text and "Exit" in text and "--- last events" in text
    mac.statusClear_(None)
    mac.statusRefreshExit_(None)
    mac.settings_(None)
    mac.statistics_(None)
    chart = mac.stats_ui["chart"]
    assert len(chart.days) == 7 and chart.days[0][0].startswith("Today")
    chart.draw()
    g = tm.STATS_GEOMETRY
    chart.hover(g["x"], g["top"] + g["label_h"] + 5)
    assert chart.hovered.startswith("Today") and "00:00-00:10" in chart.hovered
    mac.statsTick_(None)
    assert mac.icon("protected", True) is not None


def test_mac_turn_on_asks_about_another_vpn_and_disconnects_it(mac):
    mac.choose_foreign = lambda prompt: (prompt.buttons[-1][0])            # the primary: Disconnect ... and turn on
    mac.turnOn_(None)
    tag, argvs = mac.started[-1]
    assert tag == "on" and argvs[0] == ["scutil", "--nc", "stop", "Office L2TP"] and argvs[-1][-1] == "on"
    mac.fake.owners = {}
    mac.turnOn_(None)
    assert len(mac.started[-1][1]) == 1


def test_mac_foreign_question_maps_the_buttons(mac):
    prompt = tm.foreign_prompt([tm.Foreign("Office L2TP", "ppp0", "Office L2TP", False)], "CorporateVPN")
    alert = mac.mod.NSAlert.alloc.return_value.init.return_value
    for code, answer in ((1000, "disconnect"), (1001, "cancel"), (1005, "cancel")):
        alert.runModal.return_value = code
        assert mac.choose_foreign(prompt) == answer


def test_mac_turned_on_elsewhere_reads_as_connecting(mac):
    mac.fake.connected, mac.fake.owners = {}, {}
    mac.refresh()
    assert mac.view.state == "off"
    mac.store.armed_flag.write_text("1")
    mac.refresh()
    assert mac.view.title == "Connecting"


def test_mac_exit_location_is_your_own_setting(mac):
    btn = mock.MagicMock()
    btn.state.return_value = 0
    mac.settingsExit_(btn)
    assert mac.exit.enabled() is False
    btn.state.return_value = 1
    mac.settingsExit_(btn)
    assert mac.exit.enabled() is True


def test_stats_week_reads_the_guards_folder_per_profile(mac):
    assert mac.stats_week("w")[0][1].vpn_minutes == 0
    d = stats.stats_dir(mac.store.state)
    d.mkdir(parents=True, exist_ok=True)
    from datetime import datetime
    (d / f"{datetime.now().date().isoformat()}.jsonl").write_text('{"m":0,"id":"w","p":"Work"}\n'
                                                                  '{"m":1,"id":"w","p":"Work","sent":3,"lost":0}\n'
                                                                  '{"m":2,"id":"h","p":"Home"}\n')
    assert mac.stats_week("w")[0][1].vpn_minutes == 2 and mac.stats_week("h")[0][1].vpn_minutes == 1
    assert ("h", "Home (removed)") in mac.stats_choices()


def test_mac_status_page_https_method_and_exit_refresh(mac, monkeypatch):
    from veroscudo import exitinfo, statuspage
    mac.settings_(None)
    ui = mac.win_ui
    assert mac.mod.METHOD_TITLES == ("Ping", "TCP port", "HTTPS") and mac.mod.method_of(2) == "https"
    # HTTPS chosen in the first row: saved with its port (own stand-ins: the fake AppKit gives every field the same mock)
    ui["rows"] = [tuple(mock.MagicMock() for _ in range(3)) for _ in range(3)]
    ui["en"], ui["every"], ui["over"] = mock.MagicMock(), mock.MagicMock(), mock.MagicMock()
    ui["rows"][0][0].stringValue.return_value = "api.example.com"
    ui["rows"][0][1].indexOfSelectedItem.return_value = 2
    ui["rows"][0][2].stringValue.return_value = "443"
    for h, m, p in ui["rows"][1:]:
        h.stringValue.return_value = ""
        m.indexOfSelectedItem.return_value = 1
        p.stringValue.return_value = "443"
    ui["en"].state.return_value = 1
    ui["every"].stringValue.return_value = "10"
    ui["over"].stringValue.return_value = "1"
    mac.settingsMethod_(None)
    ui["rows"][0][2].setEnabled_.assert_called_with(True)
    mac.settingsSave_(None)
    tag, argvs = mac.started[-1]
    assert tag == "admin:set" and '{"host": "api.example.com", "method": "https", "port": 443}' in argvs[0][-1]
    # the status page: your own setting, saved at once; a non-https address is refused
    monkeypatch.setattr(statuspage, "_get", lambda u, t: b'{"page":{"name":"Example Service"},'
                                                         b'"status":{"indicator":"minor","description":"Degraded"}}')
    mac.status_page._get = statuspage._get
    btn = mock.MagicMock()
    btn.state.return_value = 1
    mac.settingsStatusPage_(btn)
    assert mac.status_page.enabled()
    mac.status_page._job["thread"].join(5)
    mac.refresh()
    alerts = []
    mac.alert = lambda title, text, *a: alerts.append((title, text))
    field = mock.MagicMock()
    field.stringValue.return_value = "http://status.example.com"
    mac.settingsStatusUrl_(field)
    assert alerts == [("Not saved", "The status page must be an https:// address")]
    mac.status_(None)
    mac.st_win.isVisible.return_value = True
    assert not mac.status_page.checking                          # opening the window fetches nothing (after each connect / Refresh)
    mac.refresh()
    mac.update_status()
    assert "Service      Example Service: Degraded" in mac.copy_report()
    # the status window: the service card under the exit line ("!" on amber), no Service row in the table
    st = mac.st
    st["svc"].setHidden_.assert_called_with(False)
    st["sbadge"].setStringValue_.assert_any_call("!")
    st["sname"].setStringValue_.assert_any_call("Example Service")
    assert any(str(c.args[0]).startswith("Degraded · ") for c in st["sright"].setStringValue_.call_args_list)
    assert "Service" not in [k for k, *_ in st["rows"][0]]
    # its Refresh: a fetch now, "checking..." until it ends
    mac.statusRefreshService_(None)
    assert mac.status_page.checking and mac.status_page.view().right == "checking..."
    st["sright"].setStringValue_.assert_called_with("checking...")
    mac.status_page._job["thread"].join(5)
    mac.refresh()
    assert not mac.status_page.checking and mac.status_page.view().right.startswith("Degraded · ")
    # turned off: the card goes away
    btn.state.return_value = 0
    mac.settingsStatusPage_(btn)
    mac.update_status()
    st["svc"].setHidden_.assert_called_with(True)
    # Refresh without a tunnel: refused, with the reason on screen
    mac.fake.connected = {}
    mac.refresh()
    mac.statusRefreshExit_(None)
    assert mac.exit.refused == exitinfo.NO_TUNNEL
