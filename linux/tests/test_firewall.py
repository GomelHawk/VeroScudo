import pytest

from veroscudo.config import Config
from veroscudo.firewall import DnsPolicy, render_ruleset

CFG = Config.from_text('{"vpn":{"profile":"Work","server":"vpn.example.com","port":443,"username":"jdoe"}}')


def test_output_policy_is_drop_with_scoped_allows():
    rs = render_ruleset(CFG, ["203.0.113.5"], "tun0", vm_allowed=True)
    assert "policy drop" in rs
    assert 'oifname "tun0" accept' in rs
    assert "ip daddr { 203.0.113.5 } tcp dport 443 accept" in rs
    assert "udp sport 68 udp dport 67 accept" in rs
    assert "oifname lo accept" in rs


def test_no_dns_outside_the_tunnel_while_protected():
    rs = render_ruleset(CFG, ["203.0.113.5"], "tun0", vm_allowed=True, dns=DnsPolicy(uid=101))
    assert "dport 53" not in rs                          # DNS goes through the tunnel like everything else


def test_dns_while_blocked_only_from_the_system_resolver():
    rs = render_ruleset(CFG, ["203.0.113.5"], None, vm_allowed=False, dns=DnsPolicy(uid=101, servers=("192.168.1.1",)))
    assert "meta skuid 101 udp dport 53 accept" in rs and "meta skuid 101 tcp dport 53 accept" in rs
    assert "\n    udp dport 53 accept" not in rs


def test_dns_while_blocked_only_to_the_resolvers_without_systemd_resolved():
    rs = render_ruleset(CFG, ["203.0.113.5"], None, vm_allowed=False, dns=DnsPolicy(servers=("192.168.1.1", "fd00::1")))
    assert "ip daddr { 192.168.1.1 } udp dport 53 accept" in rs
    assert "ip6 daddr { fd00::1 } udp dport 53 accept" in rs
    assert "\n    udp dport 53 accept" not in rs


def test_no_server_rule_without_resolved_ips():
    rs = render_ruleset(CFG, [], None, vm_allowed=False)
    assert "dport 443" not in rs
    assert "oifname \"" not in rs                       # no tunnel yet -> nothing but DHCP/DNS/server leaves


def test_ipv6_server_addresses_use_ip6():
    rs = render_ruleset(CFG, ["203.0.113.5", "2001:db8::5"], None, vm_allowed=False)
    assert "ip daddr { 203.0.113.5 } tcp dport 443 accept" in rs
    assert "ip6 daddr { 2001:db8::5 } tcp dport 443 accept" in rs


def test_forward_chain_blocks_containers_while_down():
    down = render_ruleset(CFG, ["203.0.113.5"], None, vm_allowed=False)
    up = render_ruleset(CFG, ["203.0.113.5"], "wg0", vm_allowed=True)
    fwd_down = down.split("chain forward")[1]
    fwd_up = up.split("chain forward")[1]
    assert "accept" not in fwd_down
    assert 'oifname "wg0" accept' in fwd_up


def test_udp_vpn_and_lan_allow():
    c = Config.from_text('{"vpn":{"profile":"W","server":"s","port":51820,"protocol":"udp"},"lanAllow":["192.168.1.0/24","fd00::/64"]}')
    rs = render_ruleset(c, ["198.51.100.7"], None, vm_allowed=False)
    assert "ip daddr { 198.51.100.7 } udp dport 51820 accept" in rs
    assert "ip daddr 192.168.1.0/24 accept" in rs
    assert "ip6 daddr fd00::/64 accept" in rs


@pytest.mark.parametrize("bad", ['tun0" accept; #', "eth0 accept", "x" * 16, ""])
def test_refuses_a_strange_interface_name(bad):
    with pytest.raises(ValueError):
        render_ruleset(CFG, ["203.0.113.5"], bad, vm_allowed=True)


def test_refuses_a_non_address_server_ip():
    with pytest.raises(ValueError):
        render_ruleset(CFG, ["203.0.113.5 } accept"], None, vm_allowed=False)


def test_never_a_blanket_accept():
    for tun in ("tun0", None):
        rs = render_ruleset(CFG, ["203.0.113.5"], tun, vm_allowed=True)
        for line in rs.splitlines():
            line = line.strip()
            if line.endswith("accept"):
                assert line != "accept", "a bare 'accept' would defeat the kill-switch"
