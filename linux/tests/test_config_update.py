from veroscudo.config import Config


def test_update_check_default_and_off():
    assert Config.from_text('{"vpn":{"profile":"X","server":"s"}}').update_check is True
    assert Config.from_text('{"vpn":{"profile":"X","server":"s"},"updateCheck":false}').update_check is False


def test_daemon_picks_up_a_changed_config_and_keeps_the_old_one_on_a_broken_file(tmp_path, monkeypatch):
    import os

    from veroscudo.daemon import Guard
    from veroscudo.state import StateStore
    p = tmp_path / "config.json"
    p.write_text('{"profiles":[{"profile":"Work","server":"vpn.example.com"}]}')
    monkeypatch.setenv("VEROSCUDO_CONFIG", str(p))
    g = Guard(Config.load(), StateStore(tmp_path / "home"))
    assert not g.reload_config()
    p.write_text('{"profiles":[{"profile":"Work","server":"vpn.example.com"},{"profile":"Backup","server":"b.example.com"}]}')
    os.utime(p, (1, 1))
    assert g.reload_config() and g.base.names == ["Work", "Backup"]
    p.write_text('{"profiles":[]}')
    os.utime(p, (2, 2))
    assert not g.reload_config() and g.base.names == ["Work", "Backup"]       # broken: the running config stays
