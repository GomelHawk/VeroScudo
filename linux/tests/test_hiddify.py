"""Hiddify (VPN/TUN mode) profiles: the parsers and validators of hiddify.py, the config/import entry, the backends'
dispatch, the rulesets (nftables and pf) and the guard - permits from the live config, never a dial, blocked on a drop,
statistics and the connection check while connected. Example addresses only (203.0.113.x, vpn.example.com)."""
import json
import os
from datetime import datetime

import pytest

from veroscudo import daemon, firewall, hiddify, importer, nm, pf, quality, scutil
from veroscudo import traymodel as tm
from veroscudo.config import Config
from veroscudo.state import StateStore, kind_label

SAMPLE = {
    "log": {"level": "warn"},
    "experimental": {"clash_api": {"external_controller": "127.0.0.1:16756", "secret": "not-a-real-secret"}},
    "inbounds": [
        {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/28", "fdfe:dcba:9876::1/126"], "auto_route": True,
         "strict_route": True},
        {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 12334},
        {"type": "direct", "tag": "dns-in", "listen": "::1", "listen_port": 16450},
    ],
    "outbounds": [
        {"type": "selector", "tag": "select", "outbounds": ["auto", "p1"]},
        {"type": "urltest", "tag": "auto", "outbounds": ["p1", "p2"]},
        {"type": "direct", "tag": "direct"},
        {"type": "direct", "tag": "bypass"},
        {"type": "block", "tag": "block"},
        {"type": "vless", "tag": "p1", "server": "203.0.113.7", "server_port": 443, "tls": {"enabled": True},
         "transport": {"type": "ws"}},
        {"type": "hysteria2", "tag": "p2", "server": "203.0.113.7.sslip.io", "server_port": 36099},
        {"type": "trojan", "tag": "p3", "server": "vpn.example.com", "server_port": 13013, "transport": {"type": "xhttp"}},
        {"type": "vmess", "tag": "p4", "server": "203.0.113.7", "server_port": 443},           # same as p1: merged
        {"type": "shadowsocks", "tag": "lan", "server": "192.168.1.10", "server_port": 8388},   # private: dropped
        {"type": "tuic", "tag": "lo", "server": "127.0.0.1", "server_port": 443},               # loopback: dropped
        {"type": "vless", "tag": "badport", "server": "203.0.113.8", "server_port": 70000},     # dropped
        {"type": "wireguard", "tag": "wg", "server": "2001:db8::7", "server_port": 51820},
    ],
    "dns": {"servers": [
        {"type": "udp", "tag": "dns-direct", "server": "1.1.1.1"},
        {"type": "https", "tag": "dns-doh", "server": "dns.example.com", "detour": "direct"},
        {"type": "tls", "tag": "dns-dot", "server": "203.0.113.53", "detour": "bypass"},
        {"type": "https", "tag": "dns-remote", "server": "8.8.8.8", "detour": "select"},        # through the tunnel
        {"type": "local", "tag": "dns-local"},
        {"type": "fakeip", "tag": "dns-fake"},
        {"type": "hosts", "tag": "dns-hosts"},
    ]},
}


def eps_of(conf):
    return {(h, p): pr for h, p, pr in hiddify.endpoints(conf)[0]}


# ---------------------------------------------------------------- parsers and validators
def test_config_path_validation():
    ok = "/home/u/.local/share/app.hiddify.com/data/current-config.json"
    assert hiddify.valid_config_path(ok)
    for bad in ("relative/data/current-config.json", "/home/u/data/config.json", "/home/u/x\n/current-config.json",
                "/home/u/../etc/current-config.json", "", None, 7, "/" + "a" * 1100 + "/current-config.json"):
        assert not hiddify.valid_config_path(bad), bad


def test_endpoints_from_the_live_config():
    eps, dropped = hiddify.endpoints(SAMPLE)
    got = eps_of(SAMPLE)
    both = ("tcp", "udp")
    assert got == {("203.0.113.7", 443): both, ("203.0.113.7.sslip.io", 36099): both, ("vpn.example.com", 13013): both,
                   ("2001:db8::7", 51820): both,
                   ("1.1.1.1", 53): both,                       # direct udp DNS: udp + tcp 53
                   ("dns.example.com", 443): ("tcp",),          # https through a "direct" detour
                   ("203.0.113.53", 853): ("tcp",)}             # tls through another direct outbound
    assert ("8.8.8.8", 443) not in got                          # its detour is a proxy: inside the tunnel
    assert len(dropped) == 3 and any("192.168.1.10" in d for d in dropped) and any("127.0.0.1" in d for d in dropped)
    assert "not-a-real-secret" not in json.dumps(eps) + " ".join(dropped)


def test_endpoints_never_allow_local_addresses_and_are_capped():
    for addr in ("10.1.2.3", "172.19.0.1", "100.64.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1", "fe80::1",
                 "fd00::1", "ff02::1", "255.255.255.255", "::ffff:192.168.1.1"):
        assert hiddify.forbidden(addr), addr
    for addr in ("203.0.113.7", "198.51.100.1", "2001:db8::1", "1.1.1.1"):
        assert not hiddify.forbidden(addr), addr
    many = {"outbounds": [{"type": "vless", "server": f"203.0.113.{i}", "server_port": 443} for i in range(1, 101)]}
    eps, dropped = hiddify.endpoints(many)
    assert len(eps) == hiddify.MAX_ENDPOINTS and len(dropped) == 100 - hiddify.MAX_ENDPOINTS
    junk = {"outbounds": [{"type": "vless", "server": "bad host!", "server_port": 443}, {"type": "vless", "server": 5},
                          {"type": "vless", "server": "203.0.113.9", "server_port": True}, "x"], "dns": "nope"}
    assert hiddify.endpoints(junk)[0] == []


def test_legacy_formats_wireguard_peers_and_dns_addresses():
    conf = {"inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30", "interface_name": "tun7"}],
            "outbounds": [{"type": "direct", "tag": "direct"},
                          {"type": "wireguard", "tag": "w", "peers": [{"server": "203.0.113.20", "server_port": 51820}]}],
            "endpoints": [{"type": "wireguard", "tag": "w2", "peers": [{"address": "203.0.113.21", "port": 51821}]}],
            "dns": {"servers": [{"address": "tls://dns.example.com"}, {"address": "https://203.0.113.53/dns-query"},
                                {"address": "198.51.100.53"}, {"address": "tcp://[2001:db8::53]:5353"},
                                {"address": "local"}, {"address": "fakeip"}, {"address": "rcode://success"},
                                {"address": "udp://203.0.113.54", "detour": "proxy"}]}}
    assert hiddify.tun_settings(conf) == (["172.19.0.1"], "tun7")
    assert eps_of(conf) == {("203.0.113.20", 51820): ("udp",), ("203.0.113.21", 51821): ("udp",),
                            ("dns.example.com", 853): ("tcp",), ("203.0.113.53", 443): ("tcp",),
                            ("198.51.100.53", 53): ("tcp", "udp"), ("2001:db8::53", 5353): ("tcp", "udp")}


def test_tun_settings_current_format_and_missing():
    assert hiddify.tun_settings(SAMPLE) == (["172.19.0.1"], None)
    assert hiddify.tun_settings({"inbounds": [{"type": "mixed"}]}) == ([], None)
    assert hiddify.tun_settings({"inbounds": [{"type": "tun", "interface_name": "bad name;"}]}) == ([], None)


def test_resolution_merges_caches_and_survives_a_failed_lookup():
    eps = [("vpn.example.com", 443, ("tcp", "udp")), ("203.0.113.7", 443, ("tcp",))]
    hosts, asked = {}, []

    def res(name):
        asked.append(name)
        return ["203.0.113.7", "192.168.0.5", "2001:db8::9"]
    out = hiddify.resolve_endpoints(eps, res, hosts, now=1000)
    assert sorted(out) == [("2001:db8::9", 443, ("tcp", "udp")), ("203.0.113.7", 443, ("tcp", "udp"))]  # private dropped
    hiddify.resolve_endpoints(eps, res, hosts, now=1100)
    assert asked == ["vpn.example.com"]                          # cached within the TTL
    out = hiddify.resolve_endpoints(eps, lambda n: [], hosts, now=2000)
    assert ("2001:db8::9", 443, ("tcp", "udp")) in out           # lookup failed: last good addresses kept


def test_cache_round_trip_and_rejection():
    eps = [("203.0.113.7", 443, ("tcp", "udp")), ("2001:db8::7", 853, ("tcp",))]
    assert hiddify.parse_cache(hiddify.dump_cache(eps)) == eps
    bad = json.dumps({"endpoints": [["10.0.0.1", 443, ["tcp"]], ["203.0.113.7", 0, ["tcp"]], ["203.0.113.7", 1, ["icmp"]],
                                    ["vpn.example.com", 443, ["tcp"]], "x"]})
    assert hiddify.parse_cache(bad) == [] and hiddify.parse_cache("{") == []


def test_service_mode():
    assert hiddify.service_mode('{"flutter.service-mode":"vpn","flutter.x":1}') == "vpn"
    assert hiddify.service_mode('{"flutter.service-mode":"system-proxy"}') == "system-proxy"
    assert hiddify.service_mode("[]") is None and hiddify.service_mode("{") is None


IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: wlp2s0    inet 192.168.1.20/24 brd 192.168.1.255 scope global dynamic wlp2s0\\       valid_lft 1000sec
5: br-1a2b3c    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-1a2b3c\\       valid_lft forever
9: tun0    inet 172.19.0.1/28 brd 172.19.0.15 scope global tun0\\       valid_lft forever preferred_lft forever
"""
IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
utun3: flags=8050<POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 172.19.0.1 --> 172.19.0.1 netmask 0xfffffff0
utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000
\tinet 172.19.0.1 --> 172.19.0.1 netmask 0xfffffff0
"""


def test_interface_parsers_and_only_a_tunnel_device_counts():
    a = hiddify.parse_ip_addr(IP_ADDR)
    assert a["tun0"] == ["172.19.0.1"] and a["br-1a2b3c"] == ["172.19.0.1"]
    # a docker bridge holding the same address is never "Hiddify's tunnel"
    assert hiddify.pick_iface(a, ["172.19.0.1"], None, "linux", lambda i: i.startswith("tun")) == "tun0"
    assert hiddify.pick_iface(a, ["172.19.0.1"], None, "linux", lambda i: False) is None
    assert hiddify.pick_iface(a, ["172.19.0.9"], "tun0", "linux", lambda i: True) == "tun0"     # interface_name fallback
    m = hiddify.parse_ifconfig(IFCONFIG)
    assert "utun3" not in m and m["utun5"] == ["172.19.0.1"]                                     # down: not listed
    assert hiddify.pick_iface(m, ["172.19.0.1"], None, "darwin") == "utun5"
    assert hiddify.pick_iface({"en0": ["172.19.0.1"]}, ["172.19.0.1"], None, "darwin") is None


def test_process_detection_reads_comm_and_exe(tmp_path):
    proc = tmp_path / "proc"
    (proc / "12").mkdir(parents=True)
    (proc / "12" / "comm").write_text("bash\n")
    (proc / "self").mkdir()
    assert not hiddify.running("linux", proc)
    (proc / "77").mkdir()
    (proc / "77" / "comm").write_text("HiddifyCli\n")
    assert hiddify.running("linux", proc)
    (proc / "77" / "comm").write_text("worker\n")
    (proc / "77" / "exe").symlink_to("/opt/hiddify/hiddify")
    assert hiddify.running("linux", proc)


def write_conf(dirpath, conf=SAMPLE, mode="vpn"):
    data = dirpath / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "current-config.json").write_text(json.dumps(conf))
    if mode is not None:
        (dirpath / "shared_preferences.json").write_text(json.dumps({"flutter.service-mode": mode}))
    return data / "current-config.json"


def test_read_config_refuses_symlinks_big_files_and_garbage(tmp_path, monkeypatch):
    monkeypatch.setattr(hiddify, "allowed_owners", lambda p: {0, os.getuid()})
    path = write_conf(tmp_path / "h")
    assert hiddify.read_config(str(path))["inbounds"][0]["type"] == "tun"
    link = tmp_path / "l" / "data" / "current-config.json"
    link.parent.mkdir(parents=True)
    link.symlink_to(path)
    with pytest.raises(OSError):
        hiddify.read_config(str(link))
    path.write_text("[1]")
    with pytest.raises(ValueError):
        hiddify.read_config(str(path))
    path.write_text("{")
    with pytest.raises(ValueError):
        hiddify.read_config(str(path))
    monkeypatch.setattr(hiddify, "MAX_BYTES", 10)
    path.write_text('{"a": "0123456789"}')
    with pytest.raises(ValueError, match="larger"):
        hiddify.read_config(str(path))
    monkeypatch.setattr(hiddify, "MAX_BYTES", 2 * 1024 * 1024)
    monkeypatch.setattr(hiddify, "allowed_owners", lambda p: {0})
    path.write_text("{}")
    if os.getuid() != 0:
        with pytest.raises(ValueError, match="another user"):
            hiddify.read_config(str(path))


def test_allowed_owners_are_root_and_the_home_owner():
    import pwd
    me = pwd.getpwuid(os.getuid())
    assert hiddify.allowed_owners(me.pw_dir.rstrip("/") + "/x/data/current-config.json") >= {0, os.getuid()}
    assert hiddify.allowed_owners("/nonexistent-root/x/current-config.json") == {0}


def test_user_home_follows_sudo_and_pkexec():
    import pwd
    me = pwd.getpwuid(os.getuid())
    assert str(hiddify.user_home({"SUDO_USER": me.pw_name}, "linux")) == me.pw_dir
    assert str(hiddify.user_home({"PKEXEC_UID": str(os.getuid())}, "linux")) == me.pw_dir


def test_discover_vpn_mode_proxy_mode_and_nothing(tmp_path):
    assert hiddify.discover(tmp_path, "linux") == []
    write_conf(tmp_path / ".local/share/app.hiddify.com/hiddify")       # the nested folder, as on Windows
    [d] = hiddify.discover(tmp_path, "linux")
    assert d["name"] == "Hiddify" and d["vpn_type"] == "hiddify" and not d.get("unsupported")
    assert d["config_path"].endswith(".local/share/app.hiddify.com/hiddify/data/current-config.json")
    assert importer.importable(d) and "Hiddify (VPN mode)" in importer.summary(d)
    write_conf(tmp_path / "Library/Application Support/Hiddify", mode="system-proxy")
    [m] = hiddify.discover(tmp_path, "darwin")
    assert m.get("unsupported") and m["note"] == hiddify.PROXY_MODE_NOTE and not importer.importable(m)


def test_the_guard_shares_only_the_tun_settings_of_a_root_only_config(tmp_path, monkeypatch):
    shared = tmp_path / hiddify.SHARED_NAME
    path = "/var/lib/hiddify-admin-bgservice/core/work/data/current-config.json"
    hiddify.share_tun(path, SAMPLE, shared)
    text = shared.read_text()
    assert json.loads(text)["path"] == path and "203.0.113" not in text and "secret" not in text   # no server, no secret
    assert oct(shared.stat().st_mode & 0o777) == "0o644"
    v4, name = hiddify.tun_settings(SAMPLE)
    assert hiddify.shared_tun(path, shared, owner=os.getuid()) == (v4, name) and v4
    assert hiddify.shared_tun("/other/data/current-config.json", shared, owner=os.getuid()) == ([], None)
    if os.getuid() != 0:
        assert hiddify.shared_tun(path, shared) == ([], None)                       # not root's: ignored
    shared.write_text(json.dumps({"path": path, "v4": ["10.0.0.1", "x", "2001:db8::1"], "name": "tun0; drop"}))
    assert hiddify.shared_tun(path, shared, owner=os.getuid()) == (["10.0.0.1"], None)
    # the user's status and tray: the config is root-only -> what the guard shared
    monkeypatch.setattr(hiddify, "shared_tun", lambda p: (["172.19.0.1"], None))
    monkeypatch.setattr(hiddify.os, "stat", lambda p: (_ for _ in ()).throw(PermissionError(13, "denied")))
    assert hiddify.tun_of(path) == (["172.19.0.1"], None)


def test_discover_finds_the_live_config_of_hiddifys_root_service(tmp_path, monkeypatch):
    service = tmp_path / "var/lib/hiddify-admin-bgservice/core/work"
    monkeypatch.setitem(hiddify.SYSTEM_DIRS, "linux", (str(service),))
    home = tmp_path / "home"
    stale = write_conf(home / ".local/share/hiddify", mode="vpn")        # the app's own folder: settings + an old config
    os.utime(stale, (1_000_000, 1_000_000))
    write_conf(service, mode=None)                                      # the root service: the live config, no settings
    [d] = hiddify.discover(home, "linux")
    assert d["config_path"] == str(service / "data/current-config.json") and not d.get("unsupported")
    (home / ".local/share/hiddify/shared_preferences.json").write_text(json.dumps({"flutter.service-mode": "proxy"}))
    [p] = hiddify.discover(home, "linux")                               # the mode comes from the user's folder
    assert p.get("unsupported") and p["note"] == hiddify.PROXY_MODE_NOTE
    os.utime(stale, None)                                               # the user's folder written last: it wins
    os.utime(service / "data/current-config.json", (1_000_000, 1_000_000))
    assert hiddify.find(home, "linux") == home / ".local/share/hiddify"
    assert hiddify.candidates(home, "darwin")[0] == home / "Library/Application Support/app.hiddify.com"


# ---------------------------------------------------------------- config.json and import
HPATH = "/home/u/.local/share/app.hiddify.com/data/current-config.json"


def test_config_entry_needs_no_server_and_validates_the_path():
    cfg = Config.from_text(json.dumps({"profiles": [{"profile": "Hiddify", "vpnType": "hiddify", "configPath": HPATH}]}))
    p = cfg.current
    assert p.vpn_type == "hiddify" and p.config_path == HPATH and p.server == "" and len(p.id) == 12
    for bad in ("relative/current-config.json", "/x/other.json", None, "/x\x07/current-config.json"):
        with pytest.raises(ValueError, match="configPath"):
            Config.from_text(json.dumps({"profiles": [{"profile": "H", "vpnType": "hiddify", "configPath": bad}]}))


def test_import_writes_the_documented_entry():
    found = hiddify_found = [{"name": "Hiddify", "vpn_type": "hiddify", "server": "", "port": 0, "protocol": "tcp",
                              "username": "", "note": "", "config_path": HPATH}]
    text, msgs = importer.add_profiles("", found, ["Hiddify"])
    [p] = json.loads(text)["profiles"]
    assert p == {"profile": "Hiddify", "vpnType": "hiddify", "configPath": HPATH, "id": p["id"]}
    assert "Hiddify (VPN mode)" in msgs[0]
    proxy = [dict(hiddify_found[0], unsupported=True, note=hiddify.PROXY_MODE_NOTE)]
    with pytest.raises(ValueError, match="proxy mode"):
        importer.add_profiles("", proxy, ["Hiddify"])


# ---------------------------------------------------------------- rulesets
EPS = (("203.0.113.7", 443, ("tcp", "udp")), ("203.0.113.8", 443, ("tcp", "udp")), ("2001:db8::7", 51820, ("tcp", "udp")),
       ("203.0.113.53", 853, ("tcp",)))


def hcfg():
    return Config.from_text(json.dumps({"profiles": [{"profile": "Hiddify", "vpnType": "hiddify", "configPath": HPATH}]}))


def test_nft_permits_each_endpoint_for_its_protocols():
    rs = firewall.render_ruleset(hcfg(), [], "tun0", vm_allowed=True, endpoints=EPS)
    assert "ip daddr { 203.0.113.7, 203.0.113.8 } meta l4proto { tcp, udp } th dport 443 ct mark set 0x5653 accept" in rs
    assert "ip6 daddr { 2001:db8::7 } meta l4proto { tcp, udp } th dport 51820 ct mark set 0x5653 accept" in rs
    assert "ip daddr { 203.0.113.53 } tcp dport 853 ct mark set 0x5653 accept" in rs
    assert 'oifname "tun0" accept' in rs
    down = firewall.render_ruleset(hcfg(), [], None, vm_allowed=False, endpoints=EPS)
    assert "203.0.113.7" in down and "tun0" not in down                        # blocked: Hiddify may still reach its servers


def test_pf_permits_each_endpoint_for_its_protocols():
    rs = pf.render_ruleset(hcfg(), [], "utun5", vm_allowed=True, endpoints=EPS)
    assert "pass out quick inet proto { tcp udp } to { 203.0.113.7, 203.0.113.8 } port 443 keep state (if-bound)" in rs
    assert "pass out quick inet proto tcp to { 203.0.113.53 } port 853 keep state (if-bound)" in rs
    assert "pass quick on utun5 all" in rs


@pytest.mark.parametrize("bad", [("vpn.example.com", 443, ("tcp",)), ("203.0.113.7", 0, ("tcp",)),
                                 ("203.0.113.7", 443, ("icmp",)), ("203.0.113.7", 443, ())])
def test_renderers_refuse_bad_endpoints(bad):
    for mod in (firewall, pf):
        with pytest.raises(ValueError):
            mod.render_ruleset(hcfg(), [], None, vm_allowed=False, endpoints=(bad,))


# ---------------------------------------------------------------- tray model
def test_reconnect_is_disabled_for_hiddify_and_its_tunnel_is_named():
    v = tm.tray_state(tm.Facts(name="Hiddify", kind="hiddify", armed=True, up=False))
    assert tm.menu_state(v, "hiddify").reconnect is False and tm.menu_state(v, "vpn").reconnect is True
    assert tm.RECONNECT_HIDDIFY == hiddify.RECONNECT_HINT and tm.HIDDIFY_OWNER == hiddify.LABEL
    assert kind_label("hiddify") == "Hiddify VPN mode"
    for profiles in ((), ("Work", "Hiddify")):                                 # configured or not: the same
        [f] = tm.foreign_list(["tun0"], {"tun0": hiddify.LABEL}, "ppp0", "Work", profiles)
        assert f.name == "Hiddify (VPN mode)" and not f.can_disconnect and f.kind == "app"
        assert "Hiddify (VPN mode) (tun0)" in tm.foreign_notice(f)[1]
    assert tm.foreign_list(["tun0"], {"tun0": hiddify.LABEL}, "tun0", "Hiddify", ("Hiddify",)) == []   # its own tunnel


# ---------------------------------------------------------------- backends and the guard
@pytest.fixture(params=["nftables", "pf"])
def hid(request, tmp_path, monkeypatch):
    fw, vpn = (firewall, nm) if request.param == "nftables" else (pf, scutil)
    monkeypatch.setattr(daemon, "firewall", fw)
    monkeypatch.setattr(daemon, "nm", vpn)
    calls = {"apply": [], "clear": 0, "resolve": [], "nmcli": []}
    monkeypatch.setattr(fw, "apply", calls["apply"].append)
    monkeypatch.setattr(fw, "clear", lambda: calls.__setitem__("clear", calls["clear"] + 1))
    monkeypatch.setattr(fw, "is_active", lambda: bool(calls["apply"]))
    monkeypatch.setattr(vpn, "resolve", lambda s: calls["resolve"].append(s) or ["203.0.113.40"])
    monkeypatch.setattr(vpn, "resolver_uid", lambda: 101)
    monkeypatch.setattr(vpn, "nameservers", list)
    monkeypatch.setattr(vpn, "nm_dns", list)
    monkeypatch.setattr(vpn, "vm_bridges", list)
    monkeypatch.setattr(nm, "_nmcli", lambda *a: calls["nmcli"].append(a) or "")
    monkeypatch.setattr(nm.subprocess, "run", lambda *a, **k: pytest.fail(f"ran {a}"))       # never nmcli up/down, never scutil
    state = {"running": True, "ifaces": {"tun0": ["172.19.0.1"], "wlp2s0": ["203.0.113.99"]}}
    monkeypatch.setattr(hiddify, "running", lambda platform=None: state["running"])
    monkeypatch.setattr(hiddify, "interfaces", lambda platform=None: dict(state["ifaces"]))
    monkeypatch.setattr(hiddify, "_is_tun", lambda i: i.startswith("tun"))
    monkeypatch.setattr(hiddify, "allowed_owners", lambda p: {0, os.getuid()})
    monkeypatch.setattr(hiddify.sys, "platform", "linux")
    hiddify._tun_cache.clear()
    path = write_conf(tmp_path / "hiddify")
    cfg = Config.from_text(json.dumps({"profiles": [{"profile": "Work", "server": "vpn.example.com"},
                                                    {"profile": "Hiddify", "vpnType": "hiddify", "configPath": str(path)}],
                                       "activeProfile": "Hiddify", "retrySeconds": 3,
                                       "connectionCheck": {"enabled": True, "intervalSeconds": 15}}))
    g = daemon.Guard(cfg, StateStore(tmp_path / "run", tmp_path / "lib"))
    yield g, calls, state, vpn, path
    hiddify.register([])


def test_backend_dispatch(hid):
    _g, _calls, state, vpn, _ = hid
    assert vpn.kind("Hiddify") == "hiddify" and vpn.is_connected("Hiddify") and vpn.iface("Hiddify") == "tun0"
    assert vpn.up("Hiddify") is True and vpn.down("Hiddify") is True                   # no-ops: nothing was run
    state["running"] = False
    assert not vpn.is_connected("Hiddify") and vpn.iface("Hiddify") is None and vpn.up("Hiddify") is False
    state["running"] = True
    state["ifaces"] = {"tun0": ["172.19.0.2"]}
    assert not vpn.is_connected("Hiddify")                                            # another tunnel's address


def test_tunnel_owners_name_hiddify(hid, monkeypatch):
    _g, _calls, _state, vpn, _path = hid
    monkeypatch.setattr(hiddify, "find", lambda home, platform=None: None)
    monkeypatch.setattr(scutil.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("no scutil")))
    owners = vpn.tunnel_owners()
    assert owners.get("tun0") == hiddify.LABEL


def test_guard_permits_the_live_servers_and_the_tunnel(hid):
    g, calls, _state, _vpn, _ = hid
    g.arm()
    rs = calls["apply"][-1]
    for addr in ("203.0.113.7", "203.0.113.40", "1.1.1.1", "203.0.113.53", "2001:db8::7"):
        assert addr in rs, addr
    assert "192.168.1.10" not in rs and "127.0.0.1 " not in rs and "8.8.8.8" not in rs
    assert "not-a-real-secret" not in rs
    assert ("tun0" in rs) and g.store.allowed_tunnel("Hiddify") == "tun0"
    assert sorted(calls["resolve"]) == ["203.0.113.7.sslip.io", "dns.example.com", "vpn.example.com"]
    assert hiddify.parse_cache(g.store.server_cache("Hiddify").read_text())              # kept for the next boot


def test_guard_never_dials_and_stays_blocked_on_a_drop(hid, monkeypatch, caplog):
    g, calls, state, _vpn, _ = hid
    g.arm()
    state["running"] = False                                                         # Hiddify quit / disconnected
    monkeypatch.setattr(daemon.time, "sleep", lambda s: None)
    g.attempts = 2
    with caplog.at_level("INFO", logger="veroscudo"):
        g.on_event_down("Hiddify", user_requested=False)
        g._loop_thread and g._loop_thread.join(5)
        g.reconnect()
    assert g.store.armed and calls["clear"] == 0
    rs = calls["apply"][-1]
    assert "tun0" not in rs and "203.0.113.7" in rs                                  # blocked; Hiddify may still reach its server
    assert caplog.text.count(hiddify.NOT_CONNECTED) == 1                            # told once per drop
    assert g.store.allowed_tunnel("Hiddify") is None
    state["running"] = True
    g.watchdog()
    assert "tun0" in calls["apply"][-1] and g.store.allowed_tunnel("Hiddify") == "tun0"


def test_reconnect_does_nothing_and_off_only_disarms(hid):
    g, calls, _state, _vpn, _ = hid
    g.arm()
    n = len(calls["apply"])
    g.renew()
    assert len(calls["apply"]) == n                                                  # not even a block
    g.off()
    assert not g.store.armed and calls["clear"] == 1 and not g.off_marker.exists()


def test_a_broken_file_keeps_the_last_good_permits(hid):
    g, calls, _state, _vpn, path = hid
    g.arm()
    good = calls["apply"][-1]
    path.write_text("{ not json")
    g.enable_killswitch(True, force=True)
    assert "203.0.113.7" in calls["apply"][-1] and calls["apply"][-1].count("203.0.113.53") == good.count("203.0.113.53")
    g2 = daemon.Guard(g.base, g.store)                                               # after a restart: the cached set
    g2.boot()
    assert "203.0.113.7" in calls["apply"][-1]


def test_statistics_and_the_connection_check_while_connected(hid, monkeypatch):
    g, _calls, state, _vpn, _ = hid
    rounds = []
    monkeypatch.setattr(quality, "run_round", lambda t, tls=False: rounds.append((t, tls)) or [(True, 20)] * len(t))
    g.arm()
    g.watchdog()
    g.stats.tick(True, g.cfg.current.id, "Hiddify", datetime(2099, 1, 1))           # next minute: the previous one is written
    g.stats.flush()
    lines = "".join(p.read_text() for p in (g.store.state / "stats").glob("*.jsonl"))
    assert f'"id":"{g.cfg.current.id}","p":"Hiddify"' in lines
    assert g.quality_tick() == 15.0 and len(rounds) == 1 and rounds[0][1] is True   # TLS: Hiddify answers TCP itself
    state["running"] = False
    g.quality_tick()
    assert len(rounds) == 1                                                          # blocked: no checks


def test_with_hiddify_connected_and_veroscudo_off_the_button_says_turn_on():
    """Regression: the status button said Turn VPN off (Hiddify connected, VeroScudo off) and Off did nothing."""
    from veroscudo import traymodel as tm
    v = tm.tray_state(tm.Facts(name="Hiddify", kind="hiddify", armed=False, up=True))
    assert not tm.offers_off(v, "hiddify") and tm.menu_state(v, "hiddify").on
    assert tm.offers_off(v, "vpn")                                   # another VPN: Off hangs it up, so it is offered
    armed = tm.tray_state(tm.Facts(name="Hiddify", kind="hiddify", armed=True, up=True))
    assert tm.offers_off(armed, "hiddify") and not tm.menu_state(armed, "hiddify").reconnect


def test_tls_check_fails_when_the_connection_is_accepted_and_dropped():
    """What Hiddify's TUN does when none of its servers answers: TCP succeeds, TLS must not."""
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(2):
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                return
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        t = quality.Target("127.0.0.1", "tcp", port)
        assert quality.check(t)[0] is True
        assert quality.check(t, tls=True)[0] is False
    finally:
        srv.close()
