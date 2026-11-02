"""`veroscudo import`: NetworkManager / macOS connections -> config.json profiles with their type's settings, and the
kill-switch rules each VPN type gets."""
import json

import pytest

from veroscudo import firewall, importer, nm, pf, scutil
from veroscudo.config import Config, server_rules


@pytest.mark.parametrize("value,expected", [
    ("vpn.example.com", ("vpn.example.com", 0)), ("vpn.example.com:4443", ("vpn.example.com", 4443)),
    ("[2001:db8::1]:443", ("2001:db8::1", 443)), ("https://oc.example.com:8443/group", ("oc.example.com", 8443)),
])
def test_split_address(value, expected):
    assert nm.split_address(value) == expected


@pytest.mark.parametrize("kind,data,want", [
    ("openvpn", "remote = ovpn.example.com:443, proto-tcp = yes, username = jdoe, connection-type = password",
     {"vpn_type": "openvpn", "server": "ovpn.example.com", "port": 443, "protocol": "tcp", "username": "jdoe"}),
    ("l2tp", "gateway = l2tp.example.com, user = jdoe, ipsec-enabled = yes",
     {"vpn_type": "l2tp", "server": "l2tp.example.com", "protocol": "udp", "username": "jdoe"}),
    ("pptp", "gateway = pptp.example.com, user = jdoe", {"vpn_type": "pptp", "server": "pptp.example.com", "protocol": "tcp"}),
    ("sstp", "gateway = sstp.example.com:4443, user = jdoe", {"vpn_type": "sstp", "server": "sstp.example.com", "port": 4443}),
    ("ikev2", "address = ike.example.com, method = eap, user = jdoe", {"vpn_type": "ikev2", "server": "ike.example.com", "protocol": "udp"}),
    ("openconnect", "gateway = https://oc.example.com/, protocol = anyconnect", {"vpn_type": "openconnect", "server": "oc.example.com", "port": 443}),
])
def test_describe_each_networkmanager_vpn_type(kind, data, want):
    d = nm.describe_vpn("X", kind, data)
    for k, v in want.items():
        assert d[k] == v, k
    assert d["note"] == ""


def test_unsupported_plugin_cannot_be_imported():
    assert nm.describe_vpn("X", "", "gateway = x")["note"]


def test_wireguard_endpoint_from_keyfile():
    text = "[connection]\nid=wg\ntype=wireguard\n[wireguard]\nprivate-key=x\n[wireguard-peer.ABC=]\nendpoint=wg.example.com:51821\nallowed-ips=0.0.0.0/0;\n"
    assert nm.wireguard_endpoint(text) == ("wg.example.com", 51821)


def test_macos_list_and_server():
    listing = ('Available network connection services in the current set (*=enabled):\n'
               '* (Disconnected)   0A3E4F6B-1111-2222-3333-444455556666 PPP --> L2TP       "Office L2TP"    [PPP/L2TP]\n'
               '* (Connected)      0A3E4F6B-1111-2222-3333-444455556667 IPSec              "Cisco"          [IPSec]\n'
               '* (Disconnected)   0A3E4F6B-1111-2222-3333-444455556668 VPN (com.x.app)    "App VPN"        [VPN/com.x.app]\n')
    got = scutil.parse_list(listing)
    assert [(g["name"], g["kind"]) for g in got] == [("Office L2TP", "l2tp"), ("Cisco", "ipsec"), ("App VPN", "")]
    assert scutil.parse_server("  RemoteAddress : l2tp.example.com\n") == "l2tp.example.com"


FOUND = [nm.describe_vpn("Office L2TP", "l2tp", "gateway = l2tp.example.com, user = jdoe"),
         nm.describe_vpn("Reserve", "openvpn", "remote = ovpn.example.com:1194"),
         nm.describe_vpn("Weird", "", "")]
BASE = '{"profiles":[{"profile":"Work","server":"vpn.example.com","port":443}],"activeProfile":"Work","retrySeconds":10}'


def test_import_adds_profiles_with_their_type_and_keeps_the_rest():
    text, msgs = importer.add_profiles(BASE, FOUND, ["Office L2TP", "Reserve"])
    j = json.loads(text)
    assert [p["profile"] for p in j["profiles"]] == ["Work", "Office L2TP", "Reserve"]
    assert j["profiles"][1] == {"profile": "Office L2TP", "server": "l2tp.example.com", "port": 443, "protocol": "udp", "vpnType": "l2tp", "username": "jdoe"}
    assert j["activeProfile"] == "Work" and j["retrySeconds"] == 10 and len(msgs) == 2
    cfg = Config.from_text(text, active="Office L2TP")
    assert server_rules(cfg.current) == [("udp", (500, 4500, 1701)), ("esp", ())]


def test_import_into_an_empty_config():
    text, _ = importer.add_profiles("", FOUND, ["Reserve"])
    assert Config.from_text(text).profile == "Reserve"


@pytest.mark.parametrize("name,msg", [("Nope", "no VPN connection"), ("Work", "already"), ("Weird", "cannot be imported")])
def test_import_refuses(name, msg):
    found = FOUND + [nm.describe_vpn("Work", "l2tp", "gateway = x.example.com")]
    with pytest.raises(ValueError, match=msg):
        importer.add_profiles(BASE, found, [name])


def test_config_rejects_an_unknown_vpn_type():
    with pytest.raises(ValueError, match="vpnType"):
        Config.from_text('{"profiles":[{"profile":"X","server":"s","vpnType":"tor"}]}')


@pytest.mark.parametrize("vtype,nft,pfl", [
    ("l2tp", ["udp dport { 500, 4500, 1701 } accept", "meta l4proto esp accept"], ["proto udp to { 203.0.113.5 } port { 500 4500 1701 }", "proto esp to { 203.0.113.5 }"]),
    ("ikev2", ["udp dport { 500, 4500 } accept", "meta l4proto esp accept"], ["port { 500 4500 }", "proto esp"]),
    ("pptp", ["tcp dport 1723 accept", "meta l4proto gre accept"], ["proto tcp to { 203.0.113.5 } port 1723", "proto gre"]),
    ("sstp", ["tcp dport 4443 accept"], ["proto tcp to { 203.0.113.5 } port 4443"]),
    ("openconnect", ["tcp dport 4443 accept", "udp dport 4443 accept"], ["proto udp to { 203.0.113.5 } port 4443"]),
])
def test_each_vpn_type_gets_its_own_server_rules(vtype, nft, pfl):
    cfg = Config.from_text(json.dumps({"profiles": [{"profile": "X", "server": "s.example.com", "port": 4443, "vpnType": vtype}]}))
    rs = firewall.render_ruleset(cfg, ["203.0.113.5"], None, vm_allowed=False)
    for frag in nft:
        assert any(frag in ln and "203.0.113.5" in ln for ln in rs.splitlines()), frag
    prs = pf.render_ruleset(cfg, ["203.0.113.5"], None, vm_allowed=False)
    for frag in pfl:
        assert frag in prs, frag
