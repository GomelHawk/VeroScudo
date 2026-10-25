"""macOS backend (alpha): the pf ruleset and the scutil parsing are pure and tested here; pfctl/scutil are not run."""
import pytest

from veroscudo import pf, scutil
from veroscudo.config import Config
from veroscudo.firewall import DnsPolicy

CFG = Config.from_text('{"vpn":{"profile":"Work","server":"vpn.example.com","port":4500,"protocol":"udp"},"lanAllow":["192.168.1.0/24"]}')


def test_pf_ends_with_a_quick_block_and_scopes_every_pass():
    rs = pf.render_ruleset(CFG, ["203.0.113.5"], "ipsec0", vm_allowed=False)
    lines = [ln for ln in rs.splitlines() if ln]
    assert lines[-1] == "block drop quick all"
    assert "pass quick on ipsec0 all" in lines
    assert "pass out quick inet proto udp to { 203.0.113.5 } port 4500" in lines
    assert "pass quick inet to 192.168.1.0/24" in lines
    for ln in lines:
        if ln.startswith("pass"):
            assert "quick" in ln and ln not in ("pass quick all", "pass out quick all")


def test_pf_dns_only_while_blocked_and_only_to_the_resolvers():
    up = pf.render_ruleset(CFG, ["203.0.113.5"], "ipsec0", vm_allowed=False, dns=DnsPolicy(servers=("192.168.1.1",)))
    down = pf.render_ruleset(CFG, ["203.0.113.5"], None, vm_allowed=False, dns=DnsPolicy(servers=("192.168.1.1",)))
    assert "port 53" not in up
    assert "pass out quick inet proto { udp tcp } to { 192.168.1.1 } port 53" in down


@pytest.mark.parametrize("bad", ["en0 all; pass", "x" * 16])
def test_pf_refuses_a_strange_interface(bad):
    with pytest.raises(ValueError):
        pf.render_ruleset(CFG, [], bad, vm_allowed=False)


def test_scutil_status_and_interface(monkeypatch):
    out = "Connected\nExtended Status <dictionary> {\n  IPv4 : <dictionary> {\n    InterfaceName : ipsec0\n  }\n}\n"
    monkeypatch.setattr(scutil, "_status", lambda p: out)
    assert scutil.is_connected("Work") and scutil.iface("Work") == "ipsec0"
    monkeypatch.setattr(scutil, "_status", lambda p: out.replace("ipsec0", "en0"))
    assert scutil.iface("Work") is None                       # a physical interface is never "the tunnel"
    monkeypatch.setattr(scutil, "_status", lambda p: "Disconnected\n")
    assert not scutil.is_connected("Work") and scutil.iface("Work") is None
