"""The CLI's config changes (the tray's Settings, the installer's setup): root only, validated, the in-use profile kept."""
import json

import pytest

from veroscudo import cli, importer
from veroscudo.state import StateStore

TWO = '{"profiles":[{"profile":"Work","server":"vpn.example.com"},{"profile":"Backup","server":"vpn2.example.com"}],"activeProfile":"Work"}'


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text(TWO)
    monkeypatch.setenv("VEROSCUDO_CONFIG", str(p))
    monkeypatch.setenv("VEROSCUDO_LOG", str(tmp_path / "v.log"))
    return p


def test_changes_need_root(cfg, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    assert cli.main(["set", "updateCheck", "false"]) == 2
    assert cli.main(["setup"]) == 2
    assert json.loads(cfg.read_text()) == json.loads(TWO)


def test_root_changes_are_written(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    assert cli.do_edit("set", ["updateCheck", "false"], store) == 0
    assert cli.do_edit("default", ["Backup"], store) == 2              # gone: the tray menu's selection is what is used
    j = json.loads(cfg.read_text())
    assert j["updateCheck"] is False
    assert cli.do_edit("set", ["retrySeconds"], store) == 2              # wrong arity
    assert cli.do_edit("set", ["strict", "false"], store) == 2           # no such setting


def test_the_profile_in_use_cannot_be_removed_while_armed(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    store.set_armed(True)
    store.set_active("Work")
    assert cli.do_edit("remove", ["Work"], store) == 2
    assert cli.do_edit("remove", ["Backup"], store) == 0
    assert [p["profile"] for p in json.loads(cfg.read_text())["profiles"]] == ["Work"]


def test_removing_the_selected_profile_while_off_clears_the_selection(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    store.set_active("Backup")
    assert cli.do_edit("remove", ["Backup"], store) == 0
    assert store.active is None


def test_setup_keeps_a_valid_config_and_imports_by_name(cfg, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    found = [{"name": "Office", "vpn_type": "l2tp", "server": "l2tp.example.com", "port": 1701, "protocol": "udp",
              "username": "", "note": ""}]
    monkeypatch.setattr(cli.nm, "discover", lambda: found)
    assert cli.do_setup([]) == 0 and json.loads(cfg.read_text()) == json.loads(TWO)       # kept, nothing asked
    assert cli.do_setup(["Office"]) == 0
    assert [p["profile"] for p in json.loads(cfg.read_text())["profiles"]] == ["Work", "Backup", "Office"]
    assert cli.do_setup(["Office"]) == 0                                                  # again: already there, kept


def test_setup_without_a_terminal_and_without_a_name_refuses(tmp_path, monkeypatch):
    monkeypatch.setenv("VEROSCUDO_CONFIG", str(tmp_path / "none.json"))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.nm, "discover", list)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.do_setup([]) == 2 and not (tmp_path / "none.json").exists()


def test_choose_offers_only_usable_connections(monkeypatch):
    found = [{"name": "Bad", "vpn_type": "ikev2", "server": "", "port": 4500, "protocol": "udp", "unsupported": True, "note": "no"},
             {"name": "Good", "vpn_type": "l2tp", "server": "l2tp.example.com", "port": 1701, "protocol": "udp", "note": ""}]
    answers = iter(["1", "9", "2"])                                   # unusable, out of range, then the good one
    monkeypatch.setattr("builtins.input", lambda _p: next(answers))
    assert cli.choose(found) == ["Good"]
    monkeypatch.setattr("builtins.input", lambda _p: "0")
    assert cli.choose(found) is None


def test_written_config_is_what_the_guard_loads(cfg):
    text = importer.set_option(cfg.read_text(), "vm", "false")
    importer.write_config(text, cfg)
    assert json.loads(cfg.read_text())["vm"] is False


def test_removing_the_profile_in_use_falls_back_to_the_first_remaining(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    store.set_active("Work")
    assert cli.do_edit("remove", ["Work"], store) == 0
    assert store.active is None and json.loads(cfg.read_text())["activeProfile"] == "Backup"
