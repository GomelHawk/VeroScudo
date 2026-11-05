import pytest

from veroscudo import daemon
from veroscudo.backend import firewall  # the platform's kill-switch (nftables / pf): what boot applies
from veroscudo.config import Config
from veroscudo.state import StateStore

NFT = firewall.__name__.endswith(".firewall")              # else pf (macOS)
BLOCKS = "policy drop" if NFT else "block drop quick all"   # what a blocking ruleset of this backend says


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
    assert BLOCKS in applied[0] and "203.0.113.5" in applied[0]


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


def _cli_env(tmp_path, monkeypatch, config_text):
    """The CLI as the boot unit runs it: state in tmp, config.json as given (None: missing)."""
    from veroscudo import cli
    monkeypatch.setenv("VEROSCUDO_HOME", str(tmp_path / "run"))
    monkeypatch.setenv("VEROSCUDO_STATE", str(tmp_path / "lib"))
    monkeypatch.setenv("VEROSCUDO_LOG", str(tmp_path / "v.log"))
    monkeypatch.setenv("VEROSCUDO_CONFIG", str(tmp_path / "config.json"))
    if config_text is not None:
        (tmp_path / "config.json").write_text(config_text)
    applied = []
    monkeypatch.setattr(cli.firewall, "apply", applied.append)
    return cli, applied


@pytest.mark.parametrize("broken", ["{not json", '{"profiles": []}', None])
def test_boot_fails_closed_when_armed_and_config_is_unusable(tmp_path, monkeypatch, broken):
    """A broken or missing config.json used to abort `veroscudo boot` before any filter was applied: an armed machine
    started open. Now it starts locked down (loopback, DHCP, neighbour discovery only)."""
    cli, applied = _cli_env(tmp_path, monkeypatch, broken)
    StateStore(tmp_path / "run", tmp_path / "lib").set_armed(True)
    assert cli.main(["boot"]) == 2
    assert len(applied) == 1
    rs = applied[0]
    assert rs == firewall.render_lockdown()
    if not NFT:
        return                                              # the pf lockdown is checked line by line in test_macos.py
    assert rs.count("policy drop") == 3
    for line in rs.splitlines():
        if "accept" in line:
            assert "lo " in line or "dport 67" in line or "dport 547" in line or "dport 68" in line or "dport 546" in line or "icmpv6" in line, line


def test_daemon_fails_closed_too(tmp_path, monkeypatch):
    cli, applied = _cli_env(tmp_path, monkeypatch, "{not json")
    StateStore(tmp_path / "run", tmp_path / "lib").set_armed(True)
    assert cli.main(["daemon"]) == 2
    assert applied == [firewall.render_lockdown()]


def test_unusable_config_while_disarmed_applies_nothing(tmp_path, monkeypatch):
    cli, applied = _cli_env(tmp_path, monkeypatch, "{not json")
    assert cli.main(["boot"]) == 2
    assert applied == []


def test_boot_with_a_good_config_is_unchanged(tmp_path, monkeypatch):
    cli, applied = _cli_env(tmp_path, monkeypatch, '{"vpn": {"profile": "X", "server": "vpn.example.com", "serverIps": ["203.0.113.5"]}}')
    StateStore(tmp_path / "run", tmp_path / "lib").set_armed(True)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    assert cli.main(["boot"]) == 0
    assert len(applied) == 1 and "203.0.113.5" in applied[0] and applied[0] != firewall.render_lockdown()
