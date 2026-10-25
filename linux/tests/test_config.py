import pytest

from veroscudo.config import Config, is_lan_range

RAW = '{"vpn":{"profile":"Work","server":"vpn.example.com","port":443,"username":"jdoe"},"retrySeconds":7,"vm":"auto","lanAllow":[]}'
MULTI = ('{"profiles":[{"profile":"Work","server":"vpn.example.com","username":"jdoe"},'
         '{"profile":"Backup","server":"vpn2.example.com","port":8443,"protocol":"udp"}],"activeProfile":"Work"}')


def test_defaults_and_values():
    c = Config.from_text(RAW)
    assert (c.profile, c.server, c.port, c.protocol, c.retry_seconds, c.vm, c.lan_allow) == ("Work", "vpn.example.com", 443, "tcp", 7, "auto", ())


def test_minimal():
    c = Config.from_text('{"vpn":{"profile":"X","server":"s"}}')
    assert c.port == 443 and c.retry_seconds == 10 and c.vm == "auto"


def test_several_profiles_and_the_default():
    c = Config.from_text(MULTI)
    assert c.names == ["Work", "Backup"] and c.profile == "Work"


def test_active_selection_and_fallback():
    c = Config.from_text(MULTI, active="Backup")
    assert (c.profile, c.server, c.port, c.protocol) == ("Backup", "vpn2.example.com", 8443, "udp")
    assert Config.from_text(MULTI, active="Planted").profile == "Work"     # an unknown runtime selection is ignored
    with pytest.raises(ValueError, match="unknown VPN profile"):
        Config.from_text(MULTI).with_active("Nope")


@pytest.mark.parametrize("raw,msg", [
    ('{"vpn":{"server":"s"}}', "vpn.profile"),
    ('{"vpn":{"profile":"X"}}', "vpn.server"),
    ('{"vpn":{"profile":"X","server":"s"},"vm":"maybe"}', "vm must be"),
    ('{"vpn":{"profile":"X","server":"s","protocol":"icmp"}}', "protocol"),
    ('{"vpn":{"profile":"X","server":"s; rm -rf /"}}', "invalid server"),
    ('{"vpn":{"profile":"X","server":"s","port":0}}', "port must be"),
    ('{"vpn":{"profile":"X\\n","server":"s"}}', "invalid VPN profile name"),
    ('{"vpn":{"profile":"X","server":"s","serverIps":["1.2.3"]}}', "serverIps"),
    ('{"vpn":{"profile":"X","server":"s"},"retrySeconds":1}', "retrySeconds"),
    ('{"vpn":{"profile":"X","server":"s"},"lanAllow":["0.0.0.0/0"]}', "lanAllow"),
    ('{"vpn":{"profile":"X","server":"s"},"lanAllow":["::/0"]}', "lanAllow"),
    ('{"vpn":{"profile":"X","server":"s"},"lanAllow":["10.0.0.0/4"]}', "lanAllow"),
    ('{"vpn":{"profile":"X","server":"s"},"lanAllow":["192.168.1.0/24 accept"]}', "lanAllow"),
    ('{"profiles":[{"profile":"A","server":"s"},{"profile":"A","server":"t"}]}', "listed twice"),
    ('{"profiles":[{"profile":"A","server":"s"}],"activeProfile":"B"}', "activeProfile"),
])
def test_rejects(raw, msg):
    with pytest.raises(ValueError, match=msg):
        Config.from_text(raw)


@pytest.mark.parametrize("v,ok", [("192.168.1.0/24", True), ("10.0.0.5", True), ("fd00::/64", True),
                                  ("0.0.0.0/0", False), ("Any", False), ("", False), ("::/0", False)])
def test_is_lan_range(v, ok):
    assert is_lan_range(v) is ok
