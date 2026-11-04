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
    monkeypatch.setattr(nm, "kind", lambda p: "vpn")
    monkeypatch.setattr(nm, "nm_dns", list)
    monkeypatch.setattr(nm, "vm_bridges", list)

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


# ---- Reconnect (the user action)
def test_reconnect_blocks_before_taking_down_and_dials_again(env):
    g, calls, connected = env
    connected.add("Work")
    g.arm()
    order = []
    import veroscudo.firewall as fw
    real_apply = fw.apply

    def apply(rs):
        order.append("block" if 'oifname "tun0"' not in rs.split("chain forward")[0] else "allow-tunnel")
        real_apply(rs)
    fw.apply = apply
    real_down = nm.down

    def down(p):
        order.append("down")
        return real_down(p)
    nm.down = down
    try:
        g.renew()
    finally:
        fw.apply, nm.down = real_apply, real_down
    assert order[:2] == ["block", "down"]          # the tunnel stops being allowed before it is taken down
    assert order[-1] == "allow-tunnel"             # traffic flows again only once it is back
    assert g.store.armed and "Work" in connected and calls["up"] == ["Work"]


def test_reconnect_does_nothing_while_off(env):
    g, calls, _ = env
    g.renew()
    assert calls["apply"] == [] and calls["down"] == [] and calls["up"] == []


def test_own_take_down_during_reconnect_is_not_your_off(env):
    g, calls, _ = env
    g.arm()
    redials = []
    g.reconnect_async = lambda: redials.append(1)         # no background thread outliving the fakes
    g.renew_marker.write_text(str(__import__("time").time()))
    g.on_event_down("Work", user_requested=True)          # NetworkManager reports our nmcli down as user-requested
    assert g.store.armed and calls["clear"] == 0 and redials == [1]
    assert not g.renew_marker.exists()                    # consumed: the next real disconnect counts again


def test_a_real_disconnect_after_a_reconnect_still_disarms(env):
    g, calls, _ = env
    g.arm()
    g.renew_marker.write_text(str(__import__("time").time() - 600))   # stale marker
    g.on_event_down("Work", user_requested=True)
    assert not g.store.armed and calls["clear"] == 1


def test_off_wins_over_a_pending_reconnect(env):
    g, _, _ = env
    g.arm()
    g.renew_marker.write_text(str(__import__("time").time()))
    g.off()
    assert not g.store.armed and not g.renew_marker.exists()



def test_off_while_already_down_leaves_no_marker_that_could_disarm_a_later_drop(env):
    g, calls, connected = env
    g.arm()                                   # armed, tunnel down
    g.off()                                   # no down-event follows: no marker may stay behind
    assert not g.off_marker.exists()
    g.arm()
    connected.add("Work")
    connected.discard("Work")
    g.reconnect_async = lambda: None
    g.on_event_down("Work", user_requested=False)   # a real failure later
    assert g.store.armed and calls["clear"] == 1    # the one clear is from the Off above, not from this drop


def test_a_stale_off_marker_is_ignored(env):
    g, calls, _ = env
    g.arm()
    g.off_marker.write_text(str(__import__("time").time() - 3600))
    g.reconnect_async = lambda: None
    g.on_event_down("Work", user_requested=False)
    assert g.store.armed and calls["clear"] == 0


def test_bridges_are_in_the_ruleset_when_vm_is_wanted(env, monkeypatch):
    g, calls, connected = env
    monkeypatch.setattr(nm, "vm_bridges", lambda: ["docker0"])
    monkeypatch.setattr(g, "vm_wanted", lambda: True)
    connected.add("Work")
    g.arm()
    assert 'iifname { "docker0" } oifname { "docker0" } accept' in calls["apply"][-1]
    assert 'oifname "tun0" accept' in calls["apply"][-1].split("chain forward")[1]
    monkeypatch.setattr(g, "vm_wanted", lambda: False)                 # "vm": false - containers get nothing
    g.enable_killswitch(True)
    assert "docker0" not in calls["apply"][-1]


def test_watchdog_never_removes_a_table_another_process_just_armed(env, monkeypatch):
    """Issue #5 (4): the watchdog read 'disarmed', then cleared the table; a `veroscudo on` in another process that armed in
    between lost its filters - armed but open for up to 15 s. The clear now re-checks the flag under the cross-process lock."""
    import contextlib
    g, calls, connected = env
    calls["apply"].append("a table left behind")                 # is_active() -> True while disarmed: the watchdog wants to tidy up
    real_lock = g.store.firewall_lock

    @contextlib.contextmanager
    def other_process_armed_first():
        with real_lock():
            g.store.set_armed(True)                              # the other process held the lock before us and armed
            yield
    monkeypatch.setattr(g.store, "firewall_lock", other_process_armed_first)
    g.watchdog()
    assert calls["clear"] == 0 and g.store.armed


def test_firewall_lock_is_exclusive_across_processes_and_reentrant_within(env):
    import fcntl
    import os
    g, calls, connected = env
    with g.store.firewall_lock():
        with g.store.firewall_lock():                            # re-entrant: arm() holds it and enable_killswitch() takes it again
            fd = os.open(g.store.fw_lock_file, os.O_RDWR)        # a second open file description, as another process would have
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
    fd = os.open(g.store.fw_lock_file, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)           # released once the outermost block ends
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def test_user_off_still_clears_even_if_a_stale_table_exists(env):
    g, calls, connected = env
    g.arm()
    g.disarm()
    assert calls["clear"] == 1 and not g.store.armed
