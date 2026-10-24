from veroscudo.config import Config
from veroscudo.firewall import render_ruleset

CFG = Config.from_text('{"vpn":{"profile":"Work","server":"vpn.example.com","port":443,"username":"jdoe"}}')


def test_output_policy_is_drop_with_scoped_allows():
    rs = render_ruleset(CFG, ["203.0.113.5"], "tun0", vm_allowed=True)
    assert "policy drop" in rs
    assert 'oifname "tun0" accept' in rs
    assert "ip daddr { 203.0.113.5 } tcp dport 443 accept" in rs
    assert "udp dport 53 accept" in rs and "udp sport 68 udp dport 67 accept" in rs
    assert "oifname lo accept" in rs


def test_no_server_rule_without_resolved_ips():
    rs = render_ruleset(CFG, [], None, vm_allowed=False)
    assert "dport 443" not in rs
    assert "oifname \"" not in rs                       # no tunnel yet -> nothing but DHCP/DNS/server leaves


def test_forward_chain_blocks_containers_while_down():
    down = render_ruleset(CFG, ["203.0.113.5"], None, vm_allowed=False)
    up = render_ruleset(CFG, ["203.0.113.5"], "wg0", vm_allowed=True)
    fwd_down = down.split("chain forward")[1]
    fwd_up = up.split("chain forward")[1]
    assert "accept" not in fwd_down
    assert 'oifname "wg0" accept' in fwd_up


def test_udp_vpn_and_lan_allow():
    c = Config.from_text('{"vpn":{"profile":"W","server":"s","port":51820,"protocol":"udp"},"lanAllow":["192.168.1.0/24"]}')
    rs = render_ruleset(c, ["198.51.100.7"], None, vm_allowed=False)
    assert "ip daddr { 198.51.100.7 } udp dport 51820 accept" in rs
    assert "ip daddr 192.168.1.0/24 accept" in rs


def test_never_a_blanket_accept():
    rs = render_ruleset(CFG, ["203.0.113.5"], "tun0", vm_allowed=True)
    for line in rs.splitlines():
        line = line.strip()
        if line.endswith("accept"):
            assert line != "accept", "a bare 'accept' would defeat the kill-switch"
