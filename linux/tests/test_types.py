"""Reserve VPN kinds on NetworkManager: WireGuard handshake health, OpenVPN data parsing, other tunnels, notices."""
from veroscudo import keepawake, nm
from veroscudo.config import Config
from veroscudo.state import kind_label, switch_notice


def test_wireguard_state_from_handshakes():
    assert nm.wg_state([1000], now=1120, first_seen=900) == "up"            # 2 min old: a live link re-handshakes every 2
    assert nm.wg_state([1000], now=1240, first_seen=900) == "stale"         # 4 min: dead link, interface still up
    assert nm.wg_state([0], now=1000, first_seen=990) == "starting"         # just activated, no handshake yet
    assert nm.wg_state([0], now=1000, first_seen=900) == "stale"            # never handshook within the grace time
    assert nm.wg_state([10, 990], now=1000, first_seen=0) == "up"           # one fresh peer is enough


def test_a_silent_wireguard_link_counts_as_down(monkeypatch):
    monkeypatch.setattr(nm, "_kinds", {"wg": "wireguard"})
    monkeypatch.setattr(nm, "_nmcli", lambda *a: "activated" if "GENERAL.STATE" in a else "wg0")
    monkeypatch.setattr(nm, "is_virtual", lambda n: True)
    monkeypatch.setattr(nm, "wg_handshakes", lambda i: [1])               # last handshake in 1970
    monkeypatch.setattr(nm, "_wg_first_seen", {"wg": 0.0})
    assert not nm.is_connected("wg") and nm.is_stale("wg")


def test_wireguard_without_wg_tool_falls_back_to_the_activation_state(monkeypatch):
    monkeypatch.setattr(nm, "_kinds", {"wg": "wireguard"})
    monkeypatch.setattr(nm, "_nmcli", lambda *a: "activated" if "GENERAL.STATE" in a else "wg0")
    monkeypatch.setattr(nm, "is_virtual", lambda n: True)
    monkeypatch.setattr(nm, "wg_handshakes", lambda i: None)              # the tray runs without root
    assert nm.is_connected("wg") and not nm.is_stale("wg")


def test_kind_reads_the_connection_type(monkeypatch):
    answers = {"connection.type": "vpn", "vpn.service-type": "org.freedesktop.NetworkManager.openvpn"}
    monkeypatch.setattr(nm, "_kinds", {})
    monkeypatch.setattr(nm, "_nmcli", lambda *a: answers[a[1]])
    assert nm.kind("Reserve") == "openvpn"


def test_parse_openvpn_vpn_data():
    d = nm.parse_openvpn_data("remote = vpn.example.com:443, vpn2.example.com:443, proto-tcp = yes, connection-type = password, username = jdoe")
    assert d == {"hosts": ["vpn.example.com", "vpn2.example.com"], "port": 443, "proto": "tcp"}
    assert nm.parse_openvpn_data("remote = vpn.example.com, connection-type = tls")["port"] == 1194


def test_check_reports_a_protocol_mismatch(monkeypatch):
    cfg = Config.from_text('{"profiles":[{"profile":"R","server":"vpn.example.com","port":1194,"protocol":"tcp"},'
                           '{"profile":"W","server":"wg.example.com","port":51820,"protocol":"tcp"},{"profile":"Gone","server":"x.example.com"}]}')
    kinds = {"R": "openvpn", "W": "wireguard", "Gone": None}
    monkeypatch.setattr(nm, "kind", lambda p: kinds[p])
    monkeypatch.setattr(nm, "_nmcli", lambda *a: "remote = vpn.example.com:1194, connection-type = password")
    out = "\n".join(nm.check(cfg))
    assert "R: OpenVPN uses UDP but the profile says TCP" in out
    assert 'W: WireGuard uses UDP' in out and "PersistentKeepalive" in out
    assert "Gone: no NetworkManager connection" in out


def test_other_tunnels_are_found_but_not_ours(tmp_path):
    for name, state, physical in (("tun0", "unknown", False), ("wg1", "up", False), ("tun9", "down", False), ("eth0", "up", True), ("wg0", "up", False)):
        d = tmp_path / name
        d.mkdir()
        (d / "operstate").write_text(state)
        if physical:
            (d / "device").mkdir()
    assert nm.other_tunnels("wg0", tmp_path) == ["tun0", "wg1"]


def test_switch_notice_only_for_wireguard():
    assert "1-3 minutes" in switch_notice("wireguard", "home")
    assert switch_notice("openvpn", "r") is None and switch_notice("vpn", "w") is None
    assert kind_label("wireguard") == "WireGuard" and kind_label(None) == "VPN"


def test_tray_prefs_keep_each_other(tmp_path):
    f = tmp_path / "tray.json"
    keepawake.save_pref(True, f)
    keepawake.set_pref("lastProfile", "home", f)
    assert keepawake.load_pref(f) is True and keepawake.get_pref("lastProfile", path=f) == "home"
