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


def test_resolve_returns_nothing_when_the_lookup_fails(monkeypatch):
    import socket

    def boom(*a, **k):
        raise OSError("no network")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert netutil.resolve("vpn.example.com") == []
