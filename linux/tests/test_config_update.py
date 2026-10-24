from veroscudo.config import Config


def test_update_check_default_and_off():
    assert Config.from_text('{"vpn":{"profile":"X","server":"s"}}').update_check is True
    assert Config.from_text('{"vpn":{"profile":"X","server":"s"},"updateCheck":false}').update_check is False
