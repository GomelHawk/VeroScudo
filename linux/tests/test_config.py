import pytest

from veroscudo.config import Config

RAW = '{"vpn":{"profile":"Work","server":"vpn.example.com","port":443,"username":"jdoe"},"retrySeconds":7,"vm":"auto","lanAllow":[]}'


def test_defaults_and_values():
    c = Config.from_text(RAW)
    assert (c.profile, c.server, c.port, c.protocol, c.retry_seconds, c.vm, c.lan_allow) == ("Work", "vpn.example.com", 443, "tcp", 7, "auto", ())


def test_minimal():
    c = Config.from_text('{"vpn":{"profile":"X","server":"s"}}')
    assert c.port == 443 and c.retry_seconds == 10 and c.vm == "auto"


@pytest.mark.parametrize("raw,msg", [
    ('{"vpn":{"server":"s"}}', "vpn.profile"),
    ('{"vpn":{"profile":"X"}}', "vpn.server"),
    ('{"vpn":{"profile":"X","server":"s"},"vm":"maybe"}', "vm must be"),
    ('{"vpn":{"profile":"X","server":"s","protocol":"icmp"}}', "protocol"),
])
def test_rejects(raw, msg):
    with pytest.raises(ValueError, match=msg):
        Config.from_text(raw)
