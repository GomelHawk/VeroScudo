"""The guard's event handling and profile switching, with the VPN control and the firewall replaced by fakes - run once per
backend pair: nftables + NetworkManager (Linux) and pf + scutil (macOS). The tests read the applied rulesets only through
`calls["allows_tunnel"]`, so they know nothing about either syntax."""
import threading

import pytest

from veroscudo import daemon, firewall, nm, pf, scutil
from veroscudo.config import Config
from veroscudo.state import StateStore

MULTI = ('{"profiles":[{"profile":"Work","server":"vpn.example.com"},'
         '{"profile":"Backup","server":"vpn2.example.com","serverIps":["198.51.100.9"]}],"activeProfile":"Work"}')
BACKENDS = {
    "nftables": (firewall, nm, lambda rs: 'oifname "tun0"' in rs.split("chain forward")[0]),
    "pf":       (pf, scutil, lambda rs: "pass quick on tun0 all" in rs),
}


@pytest.fixture(params=list(BACKENDS))
def env(request, tmp_path, monkeypatch):
    fw, vpn, allows_tunnel = BACKENDS[request.param]
    monkeypatch.setattr(daemon, "firewall", fw)
    monkeypatch.setattr(daemon, "nm", vpn)
    calls = {"apply": [], "up": [], "down": [], "clear": 0, "backend": request.param, "fw": fw, "nm": vpn, "allows_tunnel": allows_tunnel}
    connected = set()
    monkeypatch.setattr(fw, "apply", calls["apply"].append)
    monkeypatch.setattr(fw, "clear", lambda: calls.__setitem__("clear", calls["clear"] + 1))
    monkeypatch.setattr(fw, "is_active", lambda: bool(calls["apply"]))
    nm = vpn                                                   # the rest of the fixture fakes the chosen VPN backend
    monkeypatch.setattr(nm, "is_connected", lambda p: p in connected)
    monkeypatch.setattr(nm, "iface", lambda p: "tun0" if p in connected else None)
    monkeypatch.setattr(nm, "resolve", lambda s: ["203.0.113.5"])
    monkeypatch.setattr(nm, "resolver_uid", lambda: 101)
    monkeypatch.setattr(nm, "nameservers", list)
    monkeypatch.setattr(nm, "kind", lambda p: "vpn")
    monkeypatch.setattr(nm, "nm_dns", list)
    monkeypatch.setattr(nm, "vm_bridges", list)
    monkeypatch.setattr(nm, "reset_resolver", lambda: None)          # never the real resolvectl in a unit test

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
    blocked = [rs for rs in calls["apply"] if not calls["allows_tunnel"](rs)]
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
    monkeypatch.setattr(calls["fw"], "is_active", lambda: False)
    g.watchdog()
    assert len(calls["apply"]) == n + 1                    # `nft flush ruleset` / `pfctl -d` by another tool -> back within one tick


def test_server_cache_merges_and_survives_a_failed_lookup(env, monkeypatch):
    g, calls, _ = env
    assert g.lookup_server_ips(g.cfg) == ["203.0.113.5"]
    monkeypatch.setattr(calls["nm"], "resolve", lambda s: [])
    assert g.lookup_server_ips(g.cfg) == ["203.0.113.5"]    # blocked + DNS failing: the last known address still works
    monkeypatch.setattr(calls["nm"], "resolve", lambda s: ["203.0.113.77"])
    assert g.lookup_server_ips(g.cfg) == ["203.0.113.77", "203.0.113.5"]


def test_blocking_never_waits_for_dns(env, monkeypatch):
    """A VPN that died abruptly leaves the resolver on its DNS behind the dead tunnel - a lookup hangs. Blocked, the rules
    come from the cache and nothing is looked up; the first rules of all (nothing cached) still resolve."""
    g, calls, _ = env
    looked = []
    me = threading.get_ident()                              # a redial thread left by another test calls the same fake
    monkeypatch.setattr(calls["nm"], "resolve", lambda s: (threading.get_ident() == me and looked.append(s)) or ["203.0.113.5"])
    g.arm()
    assert looked == ["vpn.example.com"] and "203.0.113.5" in calls["apply"][-1]     # first arm: nothing cached yet
    looked.clear()
    g.reconnect_async = lambda: None                        # no background thread outliving the fakes
    g.enable_killswitch(tunnel_up=False, force=True)
    g.watchdog()
    assert looked == []                                                               # blocked: the cache only


def test_on_from_off_looks_up_before_the_first_block(env, monkeypatch):
    """The name may answer with changing addresses: turned on from off (nothing blocked yet), it is looked up first, so the
    address the VPN client dials is allowed. Already armed (a restart, a second On) it is not - DNS may hang then."""
    g, calls, _ = env
    g.lookup_server_ips(g.cfg)                                                       # an old address in the cache
    order = []
    me = threading.get_ident()
    monkeypatch.setattr(calls["nm"], "resolve", lambda s: (threading.get_ident() == me and order.append("lookup")) or ["203.0.113.88"])
    monkeypatch.setattr(calls["fw"], "apply", lambda rs: order.append("apply") or calls["apply"].append(rs))
    g.arm()
    assert order[:2] == ["lookup", "apply"] and "203.0.113.88" in calls["apply"][0]
    order.clear()
    g.arm()
    assert "lookup" not in order


def test_lookup_after_the_tunnel_is_allowed_and_after_a_failed_redial(env, monkeypatch):
    g, calls, connected = env
    g.arm()
    looked = []
    me = threading.get_ident()
    monkeypatch.setattr(calls["nm"], "resolve", lambda s: (threading.get_ident() == me and looked.append(s)) or ["203.0.113.77"])
    connected.add("Work")
    g.enable_killswitch(tunnel_up=True)
    assert looked == ["vpn.example.com"]                                              # through the tunnel, after it is allowed
    assert "203.0.113.77" in calls["apply"][-1] and calls["allows_tunnel"](calls["apply"][-1])   # moved: applied again
    connected.clear()
    looked.clear()
    monkeypatch.setattr(calls["nm"], "up", lambda p: False)                           # the redial fails
    monkeypatch.setattr(daemon.time, "sleep", lambda s: None)
    g.attempts = 2
    if calls["backend"] == "pf":
        # pf: blocked, the server is looked up only right before each dial, in its short DNS window (another thread)
        monkeypatch.setattr(calls["nm"], "resolve", lambda s: looked.append(s) or ["203.0.113.77"])
        g.reconnect()
        assert looked == ["vpn.example.com"] * 2
        return
    g.reconnect()
    assert looked == ["vpn.example.com"]                    # only once: with the block after the failed attempt


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
    fw, nm = calls["fw"], calls["nm"]
    real_apply = fw.apply

    def apply(rs):
        order.append("allow-tunnel" if calls["allows_tunnel"](rs) else "block")
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
    if calls["backend"] != "nftables":
        pytest.skip("VMs and containers are not filtered on macOS (alpha)")
    monkeypatch.setattr(calls["nm"], "vm_bridges", lambda: ["docker0"])
    monkeypatch.setattr(g, "vm_wanted", lambda: True)
    connected.add("Work")
    g.arm()
    assert 'iifname { "docker0" } oifname { "docker0" } accept' in calls["apply"][-1]
    assert 'oifname "tun0" accept' in calls["apply"][-1].split("chain forward")[1]
    monkeypatch.setattr(g, "vm_wanted", lambda: False)                 # "vm": false - VeroScudo leaves them alone
    g.enable_killswitch(True)
    fwd = calls["apply"][-1].split("chain forward")[1]
    assert "policy accept;" in fwd and 'oifname "tun0"' not in fwd       # forwarding not filtered at all
    assert 'iifname { "docker0" } accept' in calls["apply"][-1]          # their DHCP/DNS from the host still works
    g.enable_killswitch(False)                                          # blocked: still left alone
    assert "policy accept;" in calls["apply"][-1].split("chain forward")[1]


def test_watchdog_never_removes_a_table_another_process_just_armed(env, monkeypatch):
    """Issue #5 (4): the watchdog read 'disarmed', then cleared the table; a `veroscudo on` in another process that armed in
    between lost its filters - armed but open for up to 15 s. The clear now re-checks the flag under the cross-process lock."""
    import contextlib
    g, calls, _ = env
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
    g, _, _ = env
    with g.store.firewall_lock(), g.store.firewall_lock():       # re-entrant: arm() holds it and enable_killswitch() takes it again
        fd = os.open(g.store.fw_lock_file, os.O_RDWR)            # a second open file description, as another process would have
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
    g, calls, _ = env
    g.arm()
    g.disarm()
    assert calls["clear"] == 1 and not g.store.armed


def test_a_command_dials_once_and_hands_the_redial_to_the_daemon(env, monkeypatch):
    g, calls, _connected = env
    monkeypatch.setattr(daemon.nm, "up", lambda p: calls["up"].append(p) or False)          # never connects
    monkeypatch.setattr(daemon.time, "sleep", lambda s: (_ for _ in ()).throw(AssertionError("must not wait for a retry")))
    g.attempts = 1
    g.on()
    assert calls["up"] == ["Work"] and g.store.armed               # one dial, still armed (blocked)
    assert not g.store.lock_alive()                                # the daemon's watchdog can take the loop over
    assert not calls["allows_tunnel"](calls["apply"][-1])


def test_the_guard_records_what_the_kill_switch_lets_through(env):
    g, _calls, connected = env
    g.arm()
    assert g.store.allowed_tunnel("Work") is None                    # armed, tunnel down: blocked
    connected.add("Work")
    g.enable_killswitch(tunnel_up=True)
    assert g.store.allowed_tunnel("Work") == "tun0" and g.store.allowed_tunnel("Backup") is None
    g.disarm()
    assert g.store.allowed_tunnel("Work") is None


def test_drops_are_recorded_with_their_reason_for_the_tray(env):
    g, _, _ = env
    g.arm()
    g.reconnect_async = lambda: None                      # no background thread outliving the fakes
    g.on_event_down("Work", user_requested=False)                  # a real drop: redials
    assert g.store.last_drop()["why"] == "connection lost" and g.store.last_drop()["profile"] == "Work"
    g.renew_marker.write_text(str(__import__("time").time()))      # your Reconnect took it down itself
    g.on_event_down("Work", user_requested=True)
    assert g.store.last_drop()["why"] == "Reconnect"
    g.renew_marker.write_text(str(__import__("time").time()))      # the guard's own Reconnect of a dead tunnel
    g.dead_marker.write_text(str(__import__("time").time()))
    g.on_event_down("Work", user_requested=True)
    assert g.store.last_drop()["why"] == "no traffic through the tunnel" and g.store.armed
    g.on_event_down("Work", user_requested=True)                   # you hung up
    assert g.store.last_drop()["why"] == "you disconnected"


# ---------------------------------------------------------------- password refused: redial paused (Windows: Set-VeroAuthFailed)
def test_refused_password_pauses_redial_until_you_ask_again(env):
    g, calls, _ = env
    g.arm()
    g.on_event_auth("Work", "rejected")
    assert g.store.auth_failed("Work") == "rejected"
    g.reconnect()                                          # the watchdog / a drop: no dial, the account is not locked
    assert calls["up"] == [] and g.store.armed
    g.renew()                                              # your Reconnect after storing the right password
    assert calls["up"] == ["Work"] and g.store.auth_failed("Work") is None


def test_password_event_for_another_profile_or_while_off_is_ignored(env):
    g, _, _ = env
    g.on_event_auth("Work", "missing")                     # off
    g.arm()
    g.on_event_auth("Backup", "missing")                   # not the active profile
    assert g.store.auth_failed("Work") is None


def test_connected_clears_the_password_pause(env):
    g, _, _ = env
    g.arm()
    g.on_event_auth("Work", "missing")
    g.on_event_up("Work")
    assert g.store.auth_failed("Work") is None


def test_nm_reason_names():
    assert nm.auth_reason("NO_SECRETS") == "missing" and nm.auth_reason("LOGIN_FAILED") == "rejected"
    assert nm.auth_reason("USER_DISCONNECTED") is None


def test_restarting_a_silent_wireguard_is_not_your_off(env, monkeypatch):
    """The guard takes a silent WireGuard down itself; NetworkManager reports that down as user-requested. It must not
    disarm."""
    g, calls, _ = env
    nm = calls["nm"]
    g.arm()
    stale = {"once": True}

    def is_stale(p):
        s, stale["once"] = stale["once"], False
        return s
    monkeypatch.setattr(nm, "is_stale", is_stale)
    real_down = nm.down

    def down(p):
        real_down(p)
        g.on_event_down(p, user_requested=True)            # what NetworkManager says about our own take-down
        return True
    monkeypatch.setattr(nm, "down", down)
    g.reconnect()
    assert g.store.armed and calls["up"] == ["Work"]


def test_wireguard_endpoint_it_really_uses_is_allowed_and_cached(env, monkeypatch):
    """A server name with changing addresses: WireGuard looks it up itself and may get another address than VeroScudo. The
    address the tunnel really uses is allowed and cached."""
    g, calls, connected = env
    nm = calls["nm"]
    connected.add("Work")
    monkeypatch.setattr(nm, "live_endpoints", lambda p: ["198.51.100.77"] if p == "Work" else [])
    g.arm()
    assert "198.51.100.77" in calls["apply"][-1]
    assert "198.51.100.77" in g.cached_server_ips(g.cfg)                     # also for the next redial, before the interface exists


def test_wg_show_endpoints_parsing():
    from veroscudo import nm as realnm
    text = "W31EZNwNi1bhP+Y1L+8QU6Q5snHFJWg+neN7J7934wQ=\t203.0.113.30:3389\nAbc=\t(none)\nDef=\t[2001:db8::7]:51820\n"
    assert realnm.parse_wg_endpoints(text) == ["203.0.113.30", "2001:db8::7"]
    assert realnm.parse_wg_endpoints("") == []


def test_record_minute_passes_up_and_down_to_the_statistics_and_logs_a_write_error(env, caplog):
    g, _, _ = env
    ticks = []

    class Recorder:
        fail = False

        def tick(self, up, pid, name, down=False):
            if self.fail:
                raise OSError("disk full")
            ticks.append((up, pid, name, down))
    g.stats = Recorder()
    g.record_minute(True)
    g.record_minute(False, down=True)
    pid = g.cfg.current.id
    assert ticks == [(True, pid, "Work", False), (False, pid, "Work", True)]
    g.stats.fail = True
    with caplog.at_level("ERROR", logger="veroscudo"):
        g.record_minute(True)                                      # logged, not raised: the guard's pass goes on
    assert [(r.message, r.exc_info[0]) for r in caplog.records] == [("statistics", OSError)]


def test_rules_another_process_applied_are_put_back(env):
    """A CLI call (Reconnect, a switch) applied other rules and ended before it put these back: the daemon sees it by the
    shared note in applied.json, not by its own memory, and applies its rules again."""
    g, calls, connected = env
    connected.add("Work")
    g.arm()
    n = len(calls["apply"])
    g.watchdog()
    assert len(calls["apply"]) == n                                   # its rules are in force: nothing to do
    g.store.set_applied("Work", None, "the blocked rules of a CLI call that ended early")
    g.watchdog()
    assert len(calls["apply"]) == n + 1 and calls["allows_tunnel"](calls["apply"][-1])


# ---------------------------------------------------------------- DNS while blocked: the VPN server's name only
def test_the_redial_may_look_up_the_server_name_only(env, monkeypatch):
    g, calls, connected = env
    monkeypatch.setattr(calls["nm"], "nameservers", lambda: ["192.168.1.1"])
    order = []
    def last():
        return calls["apply"][-1] if calls["apply"] else ""
    monkeypatch.setattr(calls["nm"], "resolve", lambda s: order.append(("lookup", last())) or ["203.0.113.5"])
    real_up = calls["nm"].up

    def up(p):
        order.append(("dial", last()))
        return real_up(p)
    monkeypatch.setattr(calls["nm"], "up", up)
    g.arm()
    g.reconnect()
    assert "Work" in connected
    dial = [rs for what, rs in order if what == "dial"][-1]
    if calls["backend"] == "nftables":
        # nftables: only a query for vpn.example.com gets out, in every blocked ruleset; no other DNS
        blocked = [rs for rs in calls["apply"] if not calls["allows_tunnel"](rs)]
        assert blocked and all("@th,160,128 0x0376706e076578616d706c6503636f6d" in rs for rs in blocked)
        assert not any("dport 53 ct mark" in rs or "tcp dport 53" in rs for rs in blocked)
    else:
        # pf: the resolver's cache answered the redial's lookup with DNS closed - no ruleset ever opened DNS
        assert [what for what, _ in order].count("lookup") >= 1
        assert not any("port 53" in rs for rs in calls["apply"])
        assert "port 53" not in dial


def test_pf_closes_dns_again_even_when_the_lookup_hangs(env, monkeypatch):
    g, calls, _ = env
    if calls["backend"] != "pf":
        pytest.skip("nftables lets the name out by itself")
    monkeypatch.setattr(calls["nm"], "nameservers", lambda: ["192.168.1.1"])
    gate = threading.Event()
    g.store.server_cache("Work").parent.mkdir(parents=True, exist_ok=True)
    g.store.server_cache("Work").write_text("203.0.113.5")      # the rules never wait for this lookup
    monkeypatch.setattr(calls["nm"], "resolve", lambda s: (gate.wait(5), [])[1])
    monkeypatch.setattr(daemon, "DNS_FIRST_SECONDS", 0.2)
    g.store.set_armed(True)
    g.prime_dns()
    gate.set()
    assert "port 53" not in calls["apply"][-1]


def test_pf_answered_from_the_cache_never_opens_dns(env, monkeypatch):
    g, calls, _ = env
    if calls["backend"] != "pf":
        pytest.skip("nftables lets the name out by itself")
    monkeypatch.setattr(calls["nm"], "nameservers", lambda: ["192.168.1.1"])
    monkeypatch.setattr(calls["nm"], "resolve", lambda s: ["203.0.113.5"])           # the resolver's cache answers
    g.store.set_armed(True)
    g.prime_dns()
    assert not any("port 53" in rs for rs in calls["apply"])


def test_dns_names_skip_hiddify_and_servers_given_as_addresses():
    assert daemon.Guard.dns_names(Config.from_text(MULTI)) == ("vpn.example.com",)
    ip = Config.from_text('{"profiles":[{"profile":"W","server":"203.0.113.5"}]}')
    assert daemon.Guard.dns_names(ip) == ()


def test_pf_blocked_the_servers_name_is_answered_locally_and_the_file_goes_when_up(env, monkeypatch):
    g, calls, connected = env
    if calls["backend"] != "pf":
        pytest.skip("nftables lets the name out by itself")
    from veroscudo import localdns
    monkeypatch.setattr(localdns, "PORTS", (0,))
    g.store.set_armed(True)
    g.store.server_cache("Work").parent.mkdir(parents=True, exist_ok=True)
    g.store.server_cache("Work").write_text("203.0.113.5")
    try:
        g.update_local_dns()
        assert g.local.names == {"vpn.example.com": ["203.0.113.5"]}
        g.enable_killswitch(tunnel_up=False)
        f = localdns.RESOLVER_DIR / "vpn.example.com"
        assert localdns.ours(f)
        connected.add("Work")
        g.enable_killswitch(tunnel_up=True)
        assert not f.exists()                                   # up: lookups go through the tunnel again
        connected.clear()
        g.enable_killswitch(tunnel_up=False)
        assert f.exists()
        g.store.set_armed(False)
        g.disable_killswitch()
        assert not f.exists()                                   # Off: gone
    finally:
        g.local.stop()
