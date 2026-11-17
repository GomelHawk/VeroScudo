"""Inputs that must never reach a ruleset, failures that must never leave an armed machine open, and an Off that works
without a usable config."""
import os
import stat
import subprocess
import time

import pytest

from veroscudo import cli, daemon, firewall, hiddify, netutil, nm, pf, scutil
from veroscudo.config import Config
from veroscudo.state import StateStore

ONE = '{"profiles":[{"profile":"Work","server":"vpn.example.com"%s}]%s}'
ZONE = '2001:db8::1%x }\\n include \\"y\\"\\n ip6 daddr { ::2'


# ---- addresses
@pytest.mark.parametrize("bad", ["fe80::1%eth0", "2001:db8::1%x } accept", "1.2.3.4 ", "1.2.3.4;", ""])
def test_rule_token_and_plain_ip_refuse_anything_but_an_address(bad):
    with pytest.raises(ValueError):
        netutil.rule_token(netutil.plain_ip(bad) if bad.strip() == bad and bad else bad)


def test_an_address_with_a_zone_is_not_a_server_address():
    assert not netutil.usable_server_ip("2001:db8::1%x")
    assert hiddify.forbidden("2001:db8::1%x")


@pytest.mark.parametrize("extra, tail", [
    (f', "serverIps": ["{ZONE}"]', ""),
    ("", ', "lanAllow": ["fe80::1%x } accept"]'),
    ("", ', "lanAllow": "10.0.0.0/8"'),
    (', "port": 1e999', ""),
    (', "port": true', ""),
    ("", ', "vm": 1'),
    ("", ', "retrySeconds": [5]'),
])
def test_config_refuses_values_that_are_not_what_they_claim(extra, tail):
    with pytest.raises(ValueError):
        Config.from_text(ONE % (extra, tail))


@pytest.mark.parametrize("text", ["[]", "null", "5", '{"profiles": ["Work"]}', '{"profiles": {"profile": "Work"}}'])
def test_config_of_the_wrong_shape_is_a_value_error(text):
    with pytest.raises(ValueError):
        Config.from_text(text)


def test_a_server_with_a_zone_is_refused():
    with pytest.raises(ValueError):
        Config.from_text('{"profiles":[{"profile":"Work","server":"fe80::1%eth0"}]}')


def test_lan_allow_is_stored_in_canonical_form():
    cfg = Config.from_text(ONE % ("", ', "lanAllow": ["192.168.1.5/24", "2001:DB8::/32", "10.1.2.3"]'))
    assert cfg.lan_allow == ("192.168.1.0/24", "2001:db8::/32", "10.1.2.3/32")
    with pytest.raises(ValueError):                              # a netmask is not a prefix length (nft would refuse it)
        Config.from_text(ONE % ("", ', "lanAllow": ["10.0.0.0/255.0.0.0"]'))


@pytest.mark.parametrize("render", [firewall.render_ruleset, pf.render_ruleset])
def test_renderers_refuse_a_zone_in_any_address(render):
    cfg = Config.from_text(ONE % ("", ""))
    with pytest.raises(ValueError):
        render(cfg, ["2001:db8::1%x } accept"], None, vm_allowed=False)
    with pytest.raises(ValueError):
        render(cfg, [], None, vm_allowed=False, endpoints=(("2001:db8::1%x }", 443, ("tcp",)),))
    with pytest.raises(ValueError):
        render(cfg, [], None, vm_allowed=False, dns=firewall.DnsPolicy(None, ("2001:db8::53%x",)))


def test_hiddify_drops_a_server_with_a_zone_and_logs_it_on_one_line():
    eps, dropped = hiddify.endpoints({"outbounds": [
        {"type": "vless", "server": "2606:4700:4700::1111%x }\n include \"y\"", "server_port": 443},
        {"type": "vless", "server": "203.0.113.7", "server_port": 1e999},
        {"type": "vless", "server": "203.0.113.8", "server_port": 443}]})
    assert [e[0] for e in eps] == ["203.0.113.8"]
    assert len(dropped) == 2 and all("\n" not in d and len(d) <= 70 for d in dropped)
    assert hiddify.parse_cache('{"endpoints": [["2001:db8::1%x", 443, ["tcp"]]]}') == []


# ---- bridges and tunnels
def test_a_bridge_over_a_bond_or_a_vlan_is_not_a_vm_bridge(tmp_path, monkeypatch):
    monkeypatch.setattr(nm, "SYS_NET", tmp_path)
    for br, port in (("br0", "bond0"), ("br1", "eth0.100"), ("docker0", "veth1a2b")):
        (tmp_path / br / "bridge").mkdir(parents=True)
        (tmp_path / br / "brif" / port).mkdir(parents=True)
        (tmp_path / port).mkdir()
    (tmp_path / "bond0" / "lower_eth0").mkdir()                  # a bond of physical cards: no device of its own
    (tmp_path / "eth0.100" / "lower_eth0").mkdir()               # a VLAN on a physical card
    assert nm.vm_bridges() == ["docker0"]


def test_a_bridge_or_a_bond_is_never_the_tunnel(tmp_path, monkeypatch):
    monkeypatch.setattr(nm, "SYS_NET", tmp_path)
    (tmp_path / "br0" / "bridge").mkdir(parents=True)
    (tmp_path / "bond0" / "bonding").mkdir(parents=True)
    (tmp_path / "eth0.100" / "lower_eth0").mkdir(parents=True)
    (tmp_path / "wg0").mkdir()
    assert [nm.is_virtual(n) for n in ("br0", "bond0", "eth0.100", "wg0")] == [False, False, False, True]


def test_macos_bridge_with_a_vlan_or_bond_member_is_not_a_vm_bridge():
    text = ("bridge100: flags=8a63<UP> mtu 1500\n\tmember: vmenet0 flags=3<LEARNING>\n"
            "bridge101: flags=8a63<UP> mtu 1500\n\tmember: vlan0 flags=3<LEARNING>\n"
            "bridge102: flags=8a63<UP> mtu 1500\n\tmember: bond0 flags=3<LEARNING>\n")
    assert scutil.parse_bridges(text) == ["bridge100"]


# ---- fail closed
@pytest.fixture(params=["nftables", "pf"])
def guard(request, tmp_path, monkeypatch):
    fw, vpn = {"nftables": (firewall, nm), "pf": (pf, scutil)}[request.param]
    monkeypatch.setattr(daemon, "firewall", fw)
    monkeypatch.setattr(daemon, "nm", vpn)
    st = {"applied": [], "fail": True, "connected": set(), "down": [], "cleared": 0}

    def apply(rs):
        if st["fail"] and rs != fw.render_lockdown():
            raise subprocess.CalledProcessError(1, "fw")
        st["applied"].append(rs)
    monkeypatch.setattr(fw, "apply", apply)
    monkeypatch.setattr(fw, "is_active", lambda: bool(st["applied"]))
    monkeypatch.setattr(fw, "clear", lambda: (st["applied"].clear(), st.__setitem__("cleared", st["cleared"] + 1)))
    monkeypatch.setattr(vpn, "is_connected", lambda p: p in st["connected"])
    monkeypatch.setattr(vpn, "iface", lambda p: "tun0" if p in st["connected"] else None)
    monkeypatch.setattr(vpn, "resolve", lambda s: ["203.0.113.5"])
    monkeypatch.setattr(vpn, "resolver_uid", lambda: None)
    monkeypatch.setattr(vpn, "nameservers", list)
    monkeypatch.setattr(vpn, "nm_dns", list)
    monkeypatch.setattr(vpn, "kind", lambda p: "vpn")
    monkeypatch.setattr(vpn, "vm_bridges", list)
    monkeypatch.setattr(vpn, "live_endpoints", lambda p: [])
    monkeypatch.setattr(vpn, "down", lambda p: (st["down"].append(p), st["connected"].discard(p), True)[2])
    g = daemon.Guard(Config.from_text(ONE % ("", "")), StateStore(tmp_path / "run", tmp_path / "lib"))
    return g, st, fw


def test_arming_with_rules_that_cannot_be_applied_locks_down(guard):
    g, st, fw = guard
    with pytest.raises(subprocess.CalledProcessError):
        g.arm()
    assert g.store.armed and st["applied"] == [fw.render_lockdown()]
    st["fail"] = False                                           # the next watchdog pass gets the real rules in
    g.enable_killswitch(False)
    assert len(st["applied"]) == 2 and st["applied"][1] != fw.render_lockdown()


def test_a_failed_change_keeps_the_rules_in_force(guard):
    g, st, fw = guard
    st["fail"] = False
    g.arm()
    st["fail"] = True
    st["connected"].add("Work")
    with pytest.raises(subprocess.CalledProcessError):
        g.enable_killswitch(True)
    assert len(st["applied"]) == 1 and st["applied"][0] != fw.render_lockdown()


def test_boot_with_rules_that_cannot_be_applied_locks_down(guard):
    g, st, fw = guard
    g.store.set_armed(True)
    g.boot()
    assert st["applied"] == [fw.render_lockdown()]


# ---- Off
def _broken(tmp_path, monkeypatch, text):
    cfg = tmp_path / "config.json"
    cfg.write_text(text)
    monkeypatch.setenv("VEROSCUDO_CONFIG", str(cfg))
    monkeypatch.setenv("VEROSCUDO_HOME", str(tmp_path / "run"))
    monkeypatch.setenv("VEROSCUDO_STATE", str(tmp_path / "lib"))
    monkeypatch.setenv("VEROSCUDO_LOG", str(tmp_path / "log"))
    seen = {"clear": 0, "apply": []}
    monkeypatch.setattr(cli.firewall, "clear", lambda: seen.__setitem__("clear", seen["clear"] + 1))
    monkeypatch.setattr(cli.firewall, "apply", seen["apply"].append)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    return seen


@pytest.mark.parametrize("text", ["{not json", "[]", '{"profiles": ["Work"]}'])
@pytest.mark.parametrize("action", ["off", "disarm"])
def test_off_works_without_a_usable_config(tmp_path, monkeypatch, text, action):
    seen = _broken(tmp_path, monkeypatch, text)
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    store.set_armed(True)
    assert cli.main([action]) == 0
    assert not store.armed and seen["clear"] == 1 and seen["apply"] == []


@pytest.mark.parametrize("text", ["[]", '{"profiles": ["Work"]}', '{"profiles":[{"profile":"a","server":"h.example.com","port":1e999}]}'])
def test_boot_locks_down_on_every_kind_of_broken_config(tmp_path, monkeypatch, text):
    seen = _broken(tmp_path, monkeypatch, text)
    StateStore(tmp_path / "run", tmp_path / "lib").set_armed(True)
    assert cli.main(["boot"]) == 2
    assert seen["apply"] == [cli.firewall.render_lockdown()]


def test_a_dial_that_succeeds_after_off_is_taken_down_not_armed(guard):
    g, st, _ = guard
    st["fail"] = False
    g.arm()
    assert g.store.take_lock()                                   # a redial is in flight (this process holds its lock)
    g.off()
    st["connected"].add("Work")                                  # ... and its dial succeeds now
    g.on_event_up("Work")
    assert not g.store.armed and st["down"] == ["Work"]
    g.on_event_down("Work", user_requested=True)                 # the take-down's own event: still off
    assert not g.store.armed
    g.store.release_lock()
    st["connected"].add("Work")                                  # connected by hand afterwards: arms as always
    g.on_event_up("Work")
    assert g.store.armed


def test_a_dial_that_succeeds_long_after_off_is_still_taken_down(guard):
    g, st, _ = guard
    st["fail"] = False
    g.arm()
    assert g.store.take_lock()
    g.off()
    os.utime(g.off_stamp, (time.time() - 90, time.time() - 90))  # NetworkManager may take up to ~60 s to connect a VPN
    st["connected"].add("Work")
    g.on_event_up("Work")
    assert not g.store.armed and st["down"] == ["Work"]
    g.store.release_lock()


def test_on_after_off_is_not_held_back(guard):
    g, st, _ = guard
    st["fail"] = False
    g.off()
    assert g.store.take_lock()
    g.arm()                                                      # your On: the note about the Off is gone
    assert not g.off_stamp.exists()


def test_an_empty_marker_counts_by_its_own_time(tmp_path):
    m = tmp_path / "renew.marker"
    m.write_text("")
    assert daemon.Guard._take_marker(m, 120) and not m.exists()
    m.write_text("")
    old = time.time() - 500
    os.utime(m, (old, old))
    assert not daemon.Guard._take_marker(m, 120)


# ---- root's environment and files
def test_root_takes_nothing_from_the_callers_environment():
    env = {"PATH": "/tmp/x:/usr/bin", "VEROSCUDO_CONFIG": "/tmp/c.json", "VEROSCUDO_HOME": "/tmp/h", "LANG": "C"}
    cli.root_environment(env)
    assert env == {"PATH": cli.SYSTEM_PATH, "LANG": "C"}


def test_the_firewall_lock_is_for_its_owner_only(tmp_path):
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    with store.firewall_lock():
        assert stat.S_IMODE(os.stat(store.fw_lock_file).st_mode) == 0o600
    os.chmod(store.fw_lock_file, 0o644)                          # loosened by somebody: tightened again at the next use
    with store.firewall_lock():
        assert stat.S_IMODE(os.stat(store.fw_lock_file).st_mode) == 0o600


def test_a_refused_ruleset_is_an_error_with_nfts_words_in_the_log(monkeypatch, caplog):
    monkeypatch.setattr(firewall.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "syntax error, line 3\n"))
    with pytest.raises(subprocess.CalledProcessError):
        firewall.apply("table x")
    assert "syntax error, line 3" in caplog.text


# ---- the redial lock names one process, not just a number
def test_a_lock_whose_process_id_went_to_another_process_is_stale(tmp_path, monkeypatch):
    from veroscudo import state
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    monkeypatch.setattr(state, "proc_started", lambda pid, proc=None: "4242")     # the start time is read on Linux only
    assert store.take_lock() and store.lock_alive()
    pid, started = store.lock.read_text().split()
    assert int(pid) == os.getpid() and started == "4242"
    store.lock.write_text(f"{pid} 1")                             # the same id, started at another time
    assert not store.lock_alive() and not store.lock.exists()
    store.lock.write_text(pid)                                    # a lock from an earlier version: the id alone
    assert store.lock_alive()
    store.lock.write_text("")                                     # just made, its owner has not written its id yet
    assert store.lock_alive()
    old = time.time() - 60
    os.utime(store.lock, (old, old))                              # empty for a minute: nobody is going to
    assert not store.lock_alive()


def test_a_lock_without_a_start_time_goes_by_the_process_id(tmp_path, monkeypatch):
    from veroscudo import state
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    monkeypatch.setattr(state, "proc_started", lambda pid, proc=None: None)       # macOS: no /proc
    assert store.take_lock() and store.lock.read_text() == str(os.getpid())
    assert store.lock_alive() and not store.take_lock()
    store.lock.write_text("999999999")
    assert not store.lock_alive()


def test_proc_started_reads_past_a_command_name_with_spaces(tmp_path):
    from veroscudo import state
    (tmp_path / "42").mkdir()
    (tmp_path / "42" / "stat").write_text("42 (a b) c) S " + " ".join(str(i) for i in range(4, 30)))
    assert state.proc_started(42, tmp_path) == "22"
    assert state.proc_started(43, tmp_path) is None


def test_nothing_is_applied_once_the_machine_is_off(guard):
    g, st, _fw = guard
    st["fail"] = False
    g.enable_killswitch(False)                                   # never armed: no rules
    assert st["applied"] == []
    g.arm()
    assert len(st["applied"]) == 1
    g.store.set_armed(False)                                     # Off landed between a caller's look and its apply
    g.enable_killswitch(False, force=True)
    assert len(st["applied"]) == 1


def test_rules_are_worked_out_before_the_lock_is_taken(guard, monkeypatch):
    g, st, _fw = guard
    st["fail"] = False
    g.store.set_armed(True)
    depth = []
    real = g.desired_ruleset
    monkeypatch.setattr(g, "desired_ruleset", lambda up: (depth.append(g.store._fw_depth), real(up))[1])
    g.enable_killswitch(False)
    assert depth and depth[0] == 0


def test_a_lock_somebody_holds_on_the_old_lock_file_does_not_stop_the_guard(tmp_path):
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    legacy = store.home / "firewall.lock"                        # up to 1.3: readable by everyone
    legacy.write_text("")
    os.chmod(legacy, 0o644)
    held = os.open(legacy, os.O_RDONLY)                          # somebody who opened it then and holds a lock on it
    import fcntl
    fcntl.flock(held, fcntl.LOCK_EX)
    try:
        assert store.fw_lock_file.name != legacy.name
        with store.firewall_lock():                              # another file: nobody else has it open
            assert stat.S_IMODE(os.stat(store.fw_lock_file).st_mode) == 0o600
    finally:
        os.close(held)


def test_state_files_are_replaced_whole(tmp_path):
    from veroscudo import state
    f = tmp_path / "active-profile"
    state.write_atomic(f, "Work")
    state.write_atomic(f, "Backup")
    assert f.read_text() == "Backup" and [p.name for p in tmp_path.iterdir()] == ["active-profile"]


def test_a_hiddify_config_of_the_wrong_shape_is_no_tunnel_not_an_error():
    assert hiddify.tun_settings({"inbounds": 5}) == ([], None)
    assert hiddify.tun_settings({"inbounds": {"type": "tun"}}) == ([], None)


def test_a_server_written_as_a_number_shorthand_is_refused():
    for bad in ("10.1", "1", "1.2.3", "999.1.1.1", "1.2.3.4.5"):
        with pytest.raises(ValueError):
            Config.from_text(f'{{"profiles":[{{"profile":"W","server":"{bad}"}}]}}')
    assert Config.from_text('{"profiles":[{"profile":"W","server":"203.0.113.5"}]}').server == "203.0.113.5"
