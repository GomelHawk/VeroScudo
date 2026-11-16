"""The helpers both VPN backends share (issue #5, 14): one copy, used by nm and scutil alike."""
from veroscudo import netutil, nm, scutil


def test_both_backends_use_the_shared_helpers():
    assert nm.resolve is netutil.resolve and scutil.resolve is netutil.resolve
    assert nm.nameservers is netutil.nameservers and scutil.nameservers is netutil.nameservers


def test_nameservers_skip_loopback_stubs_and_junk(tmp_path):
    f = tmp_path / "resolv.conf"
    f.write_text("nameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver fe80::1%wlp2s0\nnameserver not-an-ip\nsearch lan\n")
    assert netutil.nameservers(f) == ["192.168.1.1", "fe80::1"]
    assert netutil.nameservers(tmp_path / "missing") == []


def test_a_resolver_the_rules_would_refuse_is_left_out_instead_of_stopping_the_ruleset(tmp_path):
    from veroscudo.config import Config
    from veroscudo.firewall import DnsPolicy, render_ruleset
    f = tmp_path / "resolv.conf"
    f.write_text("nameserver ::ffff:192.0.2.53\nnameserver 192.168.1.1\nnameserver ::1\nnameserver 192.168.1.1/24\n")
    assert netutil.nameservers(f) == ["192.168.1.1"]
    assert netutil.resolver_address("fe80::1%wlp2s0") == "fe80::1" and netutil.resolver_address("::ffff:127.0.0.1") == ""
    cfg = Config.from_text('{"vpn":{"profile":"Work","server":"vpn.example.com","port":443,"username":"jdoe"}}')
    render_ruleset(cfg, ["203.0.113.5"], None, vm_allowed=False, dns=DnsPolicy(servers=tuple(netutil.nameservers(f))))


def test_resolve_returns_nothing_when_the_lookup_fails(monkeypatch):
    import socket

    def boom(*a, **k):
        raise OSError("no network")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert netutil.resolve("vpn.example.com") == []


def test_a_server_address_is_never_a_fake_dns_answer_or_loopback():
    from veroscudo.netutil import usable_server_ip
    for bad in ("198.18.0.81", "198.19.255.1", "fc00::44", "127.0.0.1", "::1", "0.0.0.0", "fe80::1", "224.0.0.1", "x"):
        assert not usable_server_ip(bad), bad
    for good in ("203.0.113.5", "185.72.199.130", "10.0.0.5", "192.168.1.10", "2001:db8::1", "fd00::5"):
        assert usable_server_ip(good), good


def test_the_trays_lookups_follow_no_redirect_and_ask_https_only():
    import urllib.error

    import pytest

    with pytest.raises(urllib.error.HTTPError):
        netutil._NoRedirect().redirect_request(type("R", (), {"full_url": "https://a.example.com/"})(), None, 302, "Found", {},
                                               "https://b.example.com/")
    with pytest.raises(ValueError):
        netutil.fetch_https("http://a.example.com/", 1, 10)
