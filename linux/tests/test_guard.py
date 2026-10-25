"""The guard's event handling and profile switching, with NetworkManager and nft replaced by fakes."""
import pytest

from veroscudo import daemon, firewall, nm
from veroscudo.config import Config
from veroscudo.state import StateStore

MULTI = ('{"profiles":[{"profile":"Work","server":"vpn.example.com"},'
         '{"profile":"Backup","server":"vpn2.example.com","serverIps":["198.51.100.9"]}],"activeProfile":"Work"}')


@pytest.fixture
def env(tmp_path, monkeypatch):
    calls = {"apply": [], "up": [], "down": [], "clear": 0}
    connected = set()
    monkeypatch.setattr(firewall, "apply", calls["apply"].append)
    monkeypatch.setattr(firewall, "clear", lambda: calls.__setitem__("clear", calls["clear"] + 1))
    monkeypatch.setattr(firewall, "is_active", lambda: bool(calls["apply"]))
    monkeypatch.setattr(nm, "is_connected", lambda p: p in connected)
    monkeypatch.setattr(nm, "iface", lambda p: "tun0" if p in connected else None)
    monkeypatch.setattr(nm, "resolve", lambda s: ["203.0.113.5"])
    monkeypatch.setattr(nm, "resolver_uid", lambda: 101)
    monkeypatch.setattr(nm, "nameservers", list)

    def up(p):
        calls["up"].append(p)
        connected.add(p)
        return True

    def down(p):
        calls["down"].append(p)
        connected.discard(p)
        return True
    monkeypatch.setattr(nm, "up", up)
    monkeypatch.setattr(nm, "down", down)
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    g = daemon.Guard(Config.from_text(MULTI), store)
    return g, calls, connected


def test_reported_down_but_still_connected_is_ignored(env):
    g, calls, connected = env
    connected.add("Work")
    g.arm()
    g.on_event_down("Work", user_requested=True)
    assert g.store.armed and calls["clear"] == 0


def test_down_of_a_profile_that_is_not_active_is_ignored(env):
    g, calls, _ = env
    g.arm()
    g.on_event_down("Backup", user_requested=True)
    assert g.store.armed and calls["clear"] == 0


def test_user_hang_up_of_the_active_profile_disarms(env):
    g, calls, _ = env
    g.arm()
    g.on_event_down("Work", user_requested=True)
    assert not g.store.armed and calls["clear"] == 1


def test_switch_while_armed_stays_blocked_and_dials_the_new_profile(env):
    g, calls, connected = env
    connected.add("Work")
    g.arm()
    g.use("Backup")
    assert g.store.active == "Backup" and g.cfg.profile == "Backup"
    assert calls["down"] == ["Work"] and calls["up"] == ["Backup"]
    blocked = [rs for rs in calls["apply"] if 'oifname "tun0"' not in rs.split("chain forward")[0]]
    assert blocked, "a blocked ruleset must be in force between the two tunnels"
    assert "198.51.100.9" in calls["apply"][-1]            # pinned server address of the new profile
    assert g.store.armed


def test_switch_while_off_only_selects(env):
    g, calls, _ = env
    g.use("Backup")
    assert g.store.active == "Backup" and calls["up"] == [] and calls["apply"] == []


def test_switch_to_an_unknown_profile_is_refused(env):
    g, _, _ = env
    with pytest.raises(ValueError):
        g.use("Planted")


def test_connecting_another_configured_profile_makes_it_active(env):
    g, _, connected = env
    connected.add("Backup")
    g.on_event_up("Backup")
    assert g.store.active == "Backup" and g.store.armed


def test_connecting_an_unconfigured_vpn_is_ignored(env):
    g, calls, _ = env
    g.on_event_up("Someone-else")
    assert not g.store.armed and calls["apply"] == []


def test_watchdog_reapplies_a_flushed_table(env, monkeypatch):
    g, calls, connected = env
    connected.add("Work")
    g.arm()
    n = len(calls["apply"])
    g.watchdog()
    assert len(calls["apply"]) == n                        # unchanged and present -> nothing to do
    monkeypatch.setattr(firewall, "is_active", lambda: False)
    g.watchdog()
    assert len(calls["apply"]) == n + 1                    # `nft flush ruleset` by another tool -> back within one tick


def test_server_cache_merges_and_survives_a_failed_lookup(env, monkeypatch):
    g, _, _ = env
    assert g.server_ips(g.cfg) == ["203.0.113.5"]
    monkeypatch.setattr(nm, "resolve", lambda s: [])
    assert g.server_ips(g.cfg) == ["203.0.113.5"]           # blocked + DNS failing: the last known address still works
    monkeypatch.setattr(nm, "resolve", lambda s: ["203.0.113.77"])
    assert g.server_ips(g.cfg) == ["203.0.113.77", "203.0.113.5"]


def test_lock_is_exclusive(env):
    g, _, _ = env
    assert g.store.take_lock()
    assert not g.store.take_lock()
    g.store.release_lock()
    assert g.store.take_lock()
