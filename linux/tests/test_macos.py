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
    assert "pass quick on ipsec0 all keep state (if-bound)" in lines
    assert "pass out quick inet proto udp to { 203.0.113.5 } port 4500 keep state (if-bound)" in lines
    assert "pass quick inet to 192.168.1.0/24 keep state (if-bound)" in lines
    assert "pass in quick inet from 192.168.1.0/24 keep state (if-bound)" in lines
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


def test_pf_lockdown_is_loopback_dhcp_and_neighbour_discovery_only():
    rs = pf.render_lockdown()
    lines = [ln for ln in rs.splitlines() if ln]
    assert lines[-1] == "block drop quick all"
    assert all(ln.startswith("pass quick on lo0") or "port 67" in ln or "port 68" in ln or "port 547" in ln
               or "icmp6" in ln for ln in lines[:-1])
    assert "port 53" not in rs and "port 4500" not in rs


class _Pfctl:
    """A fake pfctl: remembers the anchor's rules, whether pf is enabled and the tokens handed out."""

    def __init__(self, enabled=True, rules=""):
        self.enabled, self.rules, self.tokens, self.calls = enabled, rules, 0, []

    def __call__(self, args, **kw):
        import subprocess
        self.calls.append(args[1:])
        out = ""
        if args[1:] == ["-s", "info"]:
            out = "Status: Enabled for 0 days 00:01:00\n" if self.enabled else "Status: Disabled\n"
        elif args[1:] == ["-E"]:
            self.enabled, self.tokens = True, self.tokens + 1
            out = f"pf enabled\nToken : {1000 + self.tokens}\n"
        elif args[1:4] == ["-a", pf.ANCHOR, "-s"]:
            out = self.rules
        elif args[1:4] == ["-a", pf.ANCHOR, "-f"]:
            self.rules = kw.get("input", "")
        return subprocess.CompletedProcess(args, 0, out, "")


def test_pf_disabled_with_pfctl_d_is_not_active(monkeypatch, tmp_path):
    """`pfctl -d` leaves the anchor's rules listed but enforces nothing: that must read as inactive, so the watchdog
    re-applies (and re-enables) within 15 s instead of reporting 'active' until the next reboot."""
    fake = _Pfctl(enabled=True, rules=pf.render_lockdown())
    monkeypatch.setattr(pf.subprocess, "run", fake)
    monkeypatch.setattr(pf, "TOKEN", tmp_path / "token")
    assert pf.is_active()
    fake.enabled = False
    assert not pf.is_active()


def test_pf_apply_enables_pf_again_after_pfctl_d(monkeypatch, tmp_path):
    fake = _Pfctl(enabled=True)
    monkeypatch.setattr(pf.subprocess, "run", fake)
    monkeypatch.setattr(pf, "TOKEN", tmp_path / "token")
    pf.apply(pf.render_lockdown())
    assert fake.tokens == 1 and (tmp_path / "token").read_text() == "1001"
    pf.apply(pf.render_lockdown())
    assert fake.tokens == 1                                       # a token and pf still on: no second -E
    fake.enabled = False                                          # someone ran pfctl -d
    pf.apply(pf.render_lockdown())
    assert fake.enabled and fake.tokens == 2 and (tmp_path / "token").read_text() == "1002"
    assert pf.is_active()


def test_guard_runs_on_the_pf_backend(monkeypatch, tmp_path):
    """The shared guard with the macOS backend swapped in (as backend.py does on darwin): the pf ruleset is applied and
    the log names the tunnel state from what was applied."""
    import logging

    from veroscudo import daemon
    from veroscudo.state import StateStore
    applied = []
    monkeypatch.setattr(daemon, "firewall", pf)
    monkeypatch.setattr(daemon, "nm", scutil)
    monkeypatch.setattr(pf, "apply", applied.append)
    monkeypatch.setattr(pf, "is_active", lambda: bool(applied))
    status = {"out": "Connected\nExtended Status <dictionary> {\n  IPv4 : <dictionary> {\n    InterfaceName : ipsec0\n  }\n}\n"}
    monkeypatch.setattr(scutil, "_status", lambda p: status["out"])
    monkeypatch.setattr(scutil, "resolve", lambda s: ["203.0.113.5"])
    monkeypatch.setattr(scutil, "nameservers", list)
    g = daemon.Guard(CFG, StateStore(tmp_path / "run", tmp_path / "lib"))
    records = []
    monkeypatch.setattr(daemon.log, "info", lambda msg, *a: records.append(msg % a))
    g.arm()
    assert len(applied) == 1 and "pass quick on ipsec0 all" in applied[0] and "block drop quick all" in applied[0]
    assert any(r.endswith("tunnel=up)") for r in records), records
    status["out"] = "Disconnected\n"
    g.enable_killswitch(scutil.is_connected("Work"))
    assert len(applied) == 2 and "ipsec0" not in applied[1]
    assert records[-1].endswith("tunnel=DOWN)"), records
    assert isinstance(logging.getLogger("veroscudo"), logging.Logger)
