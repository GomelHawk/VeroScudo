from veroscudo import daemon, firewall
from veroscudo.config import Config
from veroscudo.state import StateStore


def _guard(tmp_path, monkeypatch):
    applied = []
    monkeypatch.setattr(firewall, "apply", applied.append)
    cfg = Config.from_text('{"vpn": {"profile": "X", "server": "vpn.example.com"}}')
    return daemon.Guard(cfg, StateStore(tmp_path / "run", tmp_path / "lib")), applied


def test_armed_flag_survives_a_reboot(tmp_path):
    StateStore(tmp_path / "run", tmp_path / "lib").set_armed(True)
    (tmp_path / "run" / "reconnect.lock").write_text("1")
    for f in (tmp_path / "run").iterdir():      # reboot: /run is a tmpfs
        f.unlink()
    s = StateStore(tmp_path / "run", tmp_path / "lib")
    assert s.armed and not s.lock.exists()


def test_boot_blocks_when_armed_with_cached_server(tmp_path, monkeypatch):
    g, applied = _guard(tmp_path, monkeypatch)
    g.store.set_armed(True)
    g.store.server_ip.write_text("203.0.113.5")
    g.boot()
    assert len(applied) == 1
    assert "policy drop" in applied[0] and "203.0.113.5" in applied[0]


def test_boot_does_nothing_when_disarmed(tmp_path, monkeypatch):
    g, applied = _guard(tmp_path, monkeypatch)
    g.boot()
    assert applied == []


def test_log_file_is_size_limited(tmp_path, monkeypatch):
    import logging
    import logging.handlers

    from veroscudo import cli
    monkeypatch.setenv("VEROSCUDO_LOG", str(tmp_path / "v.log"))
    root = logging.getLogger()
    saved = root.handlers[:]
    root.handlers.clear()
    try:
        cli._setup_logging()
        fh = [h for h in root.handlers if isinstance(h, logging.handlers.RotatingFileHandler)]
        assert fh and fh[0].maxBytes == 2 * 1024 * 1024 and fh[0].backupCount == 1
    finally:
        for h in root.handlers:
            h.close()
        root.handlers[:] = saved
