"""Connection quality (Settings > Connection): the config key, the form, the rating, the file the tray reads, the guard's
rounds and what the tray shows. The same rules are tested on Windows (tests/VeroScudo.Core.Tests.ps1, "Connection check")."""
from __future__ import annotations

import json

import pytest

from veroscudo import daemon, importer, quality, scutil
from veroscudo import traymodel as tm
from veroscudo.backend import nm
from veroscudo.config import Config, is_host
from veroscudo.quality import CheckConfig, Quality, Target
from veroscudo.state import StateStore

ONE = '{"profiles":[{"profile":"Work","server":"vpn.example.com"}]'


def cfg(check: str | None = None) -> Config:
    return Config.from_text(ONE + (f',"connectionCheck":{check}' if check is not None else "") + "}")


# ---------------------------------------------------------------- config.json
def test_missing_key_means_off_with_the_defaults():
    c = cfg().check
    assert c == CheckConfig(False, 10, 1, (Target("1.1.1.1", "tcp", 443),))


def test_a_full_setting_is_read():
    c = cfg('{"enabled":true,"intervalSeconds":30,"windowMinutes":5,"targets":['
            '{"host":"10.0.0.1","method":"ping"},{"host":"intranet.example.com","method":"tcp","port":8443}]}').check
    assert c.enabled and c.interval_seconds == 30 and c.window_minutes == 5
    assert c.targets == (Target("10.0.0.1", "ping", 443), Target("intranet.example.com", "tcp", 8443))


def test_an_empty_target_list_still_checks_one_address():
    assert cfg('{"enabled":true,"targets":[]}').check.targets == (quality.DEFAULT_TARGET,)


@pytest.mark.parametrize("bad", [
    '{"intervalSeconds":9}', '{"intervalSeconds":101}', '{"windowMinutes":0}', '{"windowMinutes":11}',
    '{"enabled":"yes"}', '{"targets":[{"host":"bad host"}]}', '{"targets":[{"host":"a.example","method":"udp"}]}',
    '{"targets":[{"host":"a.example","method":"tcp","port":0}]}', '{"targets":[{"host":"a.example","method":"tcp","port":70000}]}',
    '{"targets":[{"host":"a"},{"host":"b"},{"host":"c"},{"host":"d"}]}', '[]',
])
def test_invalid_settings_are_refused(bad):
    with pytest.raises(ValueError):
        cfg(bad)


def test_round_trip_through_json():
    c = CheckConfig(True, 20, 3, (Target("1.1.1.1", "tcp", 443), Target("10.1.2.3", "ping", 443)))
    assert cfg(json.dumps(c.to_json())).check == c
    assert "port" not in c.to_json()["targets"][1]


def test_the_cli_set_saves_it_and_validates_the_whole_file():
    text = importer.set_option(ONE + "}", "connectionCheck", '{"enabled":true,"intervalSeconds":15}')
    assert Config.from_text(text).check.interval_seconds == 15
    with pytest.raises(ValueError):
        importer.set_option(ONE + "}", "connectionCheck", '{"intervalSeconds":5}')
    with pytest.raises(ValueError):
        importer.set_option(ONE + "}", "connectionCheck", "not json")


# ---------------------------------------------------------------- the Settings form
@pytest.mark.parametrize("text,host,port", [
    ("1.1.1.1", "1.1.1.1", None), ("example.com:8443", "example.com", 8443), ("https://example.com/path", "example.com", 443),
    ("http://example.com", "example.com", 80), ("https://example.com:9443/x", "example.com", 9443),
    ("[2001:db8::1]:443", "2001:db8::1", 443), ("2001:db8::1", "2001:db8::1", None), ("  ", "", None),
])
def test_split_address(text, host, port):
    assert quality.split_address(text) == (host, port)


def test_form_first_address_is_never_empty_and_empty_others_are_dropped():
    c = quality.from_form(True, 10, 1, [("", "tcp", 443), ("", "ping", 443), ("10.0.0.1", "ping", 443)], is_host)
    assert c.targets == (Target("1.1.1.1", "tcp", 443), Target("10.0.0.1", "ping", 443))


def test_form_takes_the_port_of_a_url_and_clamps_the_numbers():
    c = quality.from_form(True, 5, 99, [("https://intranet.example.com:8443/health", "tcp", 443)], is_host)
    assert c.interval_seconds == 10 and c.window_minutes == 10
    assert c.targets == (Target("intranet.example.com", "tcp", 8443),)
    c = quality.from_form(True, 500, 0, [("intranet.example.com:8443", "tcp", 22)], is_host)
    assert c.interval_seconds == 100 and c.window_minutes == 1 and c.targets[0].port == 22   # the port field wins when changed


def test_form_refuses_a_bad_address_with_its_row_number():
    with pytest.raises(ValueError, match="Address 2"):
        quality.from_form(True, 10, 1, [("1.1.1.1", "tcp", 443), ("not a host!", "ping", 443)], is_host)


# ---------------------------------------------------------------- the rating
def samples(oks, t0=1000.0, step=10.0):
    return [(t0 + i * step, ok, 40 if ok else None) for i, ok in enumerate(oks)]


@pytest.mark.parametrize("oks,state", [
    ([True] * 10, "good"),
    ([True] * 9 + [False], "unstable"),                    # 10 % is not "under 10 %"
    ([True] * 19 + [False], "good"),                       # 5 %
    ([True] * 5 + [False] * 5, "unstable"),                # 50 % is not "over 50 %"
    ([True] * 4 + [False] * 6, "bad"),
    ([False] * 10, "bad"),
])
def test_thresholds(oks, state):
    s = samples(oks)
    assert quality.rate(s, s[-1][0], 3600).state == state


def test_fewer_than_three_checks_is_checking():
    s = samples([True, True])
    assert quality.rate(s, s[-1][0], 3600).state == "checking"


def test_only_the_window_counts():
    s = samples([False] * 10 + [True] * 10)                # the failures are older than the window
    q = quality.rate(s, s[-1][0], 95)
    assert q.state == "good" and q.checks == 10 and q.rtt_ms == 40


def test_the_window_holds_at_least_three_rounds():
    assert quality.window_seconds(CheckConfig(True, 100, 1)) == 300
    assert quality.window_seconds(CheckConfig(True, 20, 1)) == 60          # 20 s / 1 min: rounds at 0, 20, 40, 60 s
    assert quality.window_seconds(CheckConfig(True, 10, 2)) == 120


def test_describe():
    assert quality.describe(Quality("good", 0, 45, 6, 0)) == "good · 45 ms"
    assert quality.describe(Quality("unstable", 22.5, 300, 40, 9)) == "unstable · 22.5% lost"
    assert quality.describe(Quality("bad", 60.0, None, 10, 6)) == "bad · 60% lost"
    assert quality.describe(Quality("checking")) == "checking…"


# ---------------------------------------------------------------- quality.json
def test_monitor_writes_what_the_tray_reads_and_a_new_profile_starts_over(tmp_path):
    m = quality.Monitor(tmp_path / "quality.json")
    c = CheckConfig(True, 10, 1)
    for i in range(7):                                                   # 0 s .. 60 s: one full minute
        q = m.add_round(c, "Work", [(True, 30)], now=1000.0 + i * 10)
    assert q.state == "good"
    assert quality.read(m.path, "Work", now=1065.0) == q
    assert quality.read(m.path, "Backup", now=1065.0) is None          # another profile's rating is not shown
    assert quality.read(m.path, "Work", now=1200.0) is None            # too old: the guard stopped checking
    m.add_round(c, "Backup", [(False, None)], now=1070.0)
    assert len(m.samples) == 1
    m.reset()
    assert not m.path.exists() and not m.samples


def test_no_rating_before_one_full_period_even_with_enough_checks(tmp_path):
    m = quality.Monitor(tmp_path / "quality.json")
    c = CheckConfig(True, 10, 1, (Target("1.1.1.1"), Target("9.9.9.9"), Target("8.8.8.8")))
    states = [m.add_round(c, "Work", [(True, 20)] * 3, now=1000.0 + i * 10).state for i in range(7)]
    assert states == ["checking"] * 6 + ["good"]                        # 18 checks after 50 s are still not a rating


def test_a_change_of_the_check_settings_starts_the_rating_over(tmp_path):
    m = quality.Monitor(tmp_path / "quality.json")
    c = CheckConfig(True, 10, 1)
    for i in range(7):
        q = m.add_round(c, "Work", [(True, 20)], now=1000.0 + i * 10)
    assert q.state == "good"
    for changed in (CheckConfig(True, 20, 1), CheckConfig(True, 10, 2), CheckConfig(True, 10, 1, (Target("9.9.9.9", "ping"),))):
        assert m.add_round(changed, "Work", [(True, 20)], now=2000.0).state == "checking"
        assert len(m.samples) == 1
    assert m.add_round(CheckConfig(False, 10, 1, (Target("9.9.9.9", "ping"),)), "Work", [(True, 20)], now=2010.0).state == "checking"


def test_after_a_reset_the_next_connection_waits_a_full_period_again(tmp_path):
    m = quality.Monitor(tmp_path / "quality.json")
    c = CheckConfig(True, 10, 1)
    for i in range(7):
        m.add_round(c, "Work", [(True, 20)], now=1000.0 + i * 10)
    m.reset()                                                            # blocked / off
    assert m.add_round(c, "Work", [(True, 20)] * 5, now=1500.0).state == "checking"


def test_read_ignores_a_broken_file(tmp_path):
    p = tmp_path / "quality.json"
    p.write_text("{nope")
    assert quality.read(p, "Work") is None


def test_ping_command_has_a_timeout_and_no_name_lookup_of_answers(monkeypatch):
    monkeypatch.setattr(quality.sys, "platform", "linux")
    assert quality._ping_argv("1.1.1.1") == ["ping", "-4", "-n", "-c", "1", "-W", "3", "1.1.1.1"]
    monkeypatch.setattr(quality.sys, "platform", "darwin")
    assert quality._ping_argv("1.1.1.1") == ["ping", "-n", "-c", "1", "-t", "3", "1.1.1.1"]


def test_tcp_check_against_a_local_listener():
    import socket
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        ok, rtt = quality.check(Target("127.0.0.1", "tcp", port))
        assert ok and rtt is not None
    finally:
        srv.close()
    assert quality.check(Target("127.0.0.1", "tcp", port))[0] is False


# ---------------------------------------------------------------- the guard: checks only while armed and connected
@pytest.fixture(params=["nm", "scutil"])
def guard(request, tmp_path, monkeypatch):
    vpn = nm if request.param == "nm" else scutil
    monkeypatch.setattr(daemon, "nm", vpn)
    connected = {"up": True}
    monkeypatch.setattr(vpn, "is_connected", lambda p: connected["up"])
    monkeypatch.setattr(vpn, "resolve", lambda s: ["203.0.113.5"])       # never the real DNS in a unit test
    rounds = []
    monkeypatch.setattr(quality, "run_round", lambda targets, tls=False: rounds.append(targets) or [(True, 20)] * len(targets))
    store = StateStore(tmp_path / "run", tmp_path / "lib")
    g = daemon.Guard(cfg('{"enabled":true,"intervalSeconds":15}'), store)
    return g, connected, rounds


def test_guard_checks_while_protected_and_waits_the_interval(guard):
    g, _, rounds = guard
    g.store.set_armed(True)
    assert g.quality_tick() == 15.0 and len(rounds) == 1
    assert g.quality.path.exists()


def test_guard_does_not_check_while_off_or_blocked_and_drops_the_rating(guard):
    g, connected, rounds = guard
    g.store.set_armed(True)
    g.quality_tick()
    connected["up"] = False                                # blocked: nothing goes out, no rating
    g.quality_tick()
    assert len(rounds) == 1 and not g.quality.path.exists()
    connected["up"] = True
    g.store.set_armed(False)                               # off
    g.quality_tick()
    assert len(rounds) == 1


def test_guard_counts_each_round_in_the_statistics(guard):
    g, _, _ = guard
    g.store.set_armed(True)
    g.quality_tick()
    g.stats.flush()
    lines = [ln for f in (g.store.state / "stats").glob("*.jsonl") for ln in f.read_text().splitlines()]
    assert len(lines) == 1 and '"p":"' in lines[0] and '"sent":1,"lost":0' in lines[0]


def test_guard_does_nothing_when_the_check_is_off(tmp_path, monkeypatch):
    monkeypatch.setattr(quality, "run_round", lambda t, tls=False: pytest.fail("checked while disabled"))
    g = daemon.Guard(cfg(), StateStore(tmp_path / "run", tmp_path / "lib"))
    g.store.set_armed(True)
    assert g.quality_tick() == 5.0


# ---------------------------------------------------------------- what the tray shows
P = tm.Facts(name="Work", kind="vpn", armed=True, up=True)


def view(f):
    return tm.tray_state(f)


def with_q(state, loss=0.0, rtt=45):
    return tm.Facts(name="Work", kind="vpn", armed=True, up=True, check_enabled=True, quality=Quality(state, loss, rtt, 12, 0))


def test_tooltip_and_menu_head_carry_the_rating_only_while_protected():
    f = with_q("unstable", 20.0)
    assert tm.tooltip(view(f), False, f) == "VeroScudo - Protected, connection unstable"
    assert tm.menu_head(view(f), f) == "VeroScudo - Protected - Unstable"
    assert tm.tooltip(view(P), False, P) == "VeroScudo - Protected"            # check off: as before
    checking = with_q("checking")
    assert tm.menu_head(view(checking), checking) == "VeroScudo - Protected"
    blocked = tm.Facts(name="Work", kind="vpn", armed=True, up=False, check_enabled=True, quality=Quality("good", 0, 30, 9, 0))
    assert tm.menu_head(view(blocked), blocked) == "VeroScudo - Blocked - reconnecting"


@pytest.mark.parametrize("facts,text", [
    (with_q("good"), "good · 45 ms"),
    (with_q("bad", 70.0), "bad · 70% lost"),
    (tm.Facts(name="Work", armed=True, up=True, check_enabled=True), "checking…"),
    (P, "connected (check off)"),
    (tm.Facts(name="Work", armed=True, up=False), "redialing"),
    (tm.Facts(name="Work", armed=True, up=False, expect="switch"), "switching"),
    (tm.Facts(name="Work"), "-"),
    (tm.Facts(name="Work", up=True), "connected (VPN off)"),
    (tm.Facts(configured=False), "-"),
])
def test_connection_row(facts, text):
    assert tm.connection_text(facts, view(facts)) == text
    assert ("Connection", text) in tm.status_rows(facts, view(facts), False, None)


def test_a_reconnect_between_two_rounds_starts_the_rating_over(tmp_path):
    """Regression: "unstable" one second after a Reconnect - the tunnel was down for ~6 s between two 10 s rounds, so no
    round saw it, and the old period went on with the check that failed during the Reconnect."""
    m = quality.Monitor(tmp_path / "quality.json")
    c = CheckConfig(True, 10, 1)
    for i in range(7):
        q = m.add_round(c, "Work", [(True, 20)], now=1000.0 + i * 10)
    assert q.state == "good"
    q = m.add_round(c, "Work", [(False, None)], now=1070.0, down_at=1065.0)      # blocked at 1065, back before 1070
    assert q.state == "checking" and len(m.samples) == 1
    q = m.add_round(c, "Work", [(True, 20)], now=1080.0, down_at=1065.0)         # the same down moment: no second restart
    assert len(m.samples) == 2


def test_the_guard_records_every_blocked_moment(guard, monkeypatch):
    g, _, _ = guard
    applied = []
    monkeypatch.setattr(daemon.firewall, "apply", applied.append)
    monkeypatch.setattr(daemon.firewall, "is_active", lambda: True)
    monkeypatch.setattr(g, "desired_ruleset", lambda up: (f"ruleset up={up}", "tun0" if up else None))
    g.store.set_armed(True)
    g.enable_killswitch(False)                                                # blocked: a new connection will follow
    first = g.store.last_down()
    assert first > 0
    g.enable_killswitch(True)                                                 # up: not a blocked moment
    assert g.store.last_down() == first and len(applied) == 2


def test_first_rating_exactly_after_the_set_period_with_20_s_rounds(tmp_path):
    m = quality.Monitor(tmp_path / "quality.json")
    c = CheckConfig(True, 20, 1)
    states = [m.add_round(c, "Work", [(True, 20)], now=1000.0 + i * 20).state for i in range(4)]
    assert states == ["checking", "checking", "checking", "good"]          # rounds at 0, 20, 40 s; rated at 60 s


# ---------------------------------------------------------------- HTTPS: the real way to a web service
def test_https_target_in_config_form_and_labels():
    c = cfg('{"enabled":true,"targets":[{"host":"api.example.com","method":"https"},'
            '{"host":"web.example.com","method":"https","port":8443},{"host":"10.0.0.1","method":"ping"}]}').check
    assert c.targets == (Target("api.example.com", "https", 443), Target("web.example.com", "https", 8443),
                         Target("10.0.0.1", "ping", 443))
    assert c.to_json()["targets"] == [{"host": "api.example.com", "method": "https", "port": 443},
                                      {"host": "web.example.com", "method": "https", "port": 8443},
                                      {"host": "10.0.0.1", "method": "ping"}]
    assert [t.label() for t in c.targets] == ["api.example.com (HTTPS)", "web.example.com:8443 (HTTPS)", "10.0.0.1 (ping)"]
    assert Target("1.1.1.1", "tcp", 443).label() == "1.1.1.1:443"
    f = quality.from_form(True, 10, 1, [("https://api.example.com/v1", "https", 443), ("https://x.example.com:9443", "https", 443),
                                        ("y.example.com", "https", 8443)], is_host)
    assert f.targets == (Target("api.example.com", "https", 443), Target("x.example.com", "https", 9443),
                         Target("y.example.com", "https", 8443))
    with pytest.raises(ValueError, match="Ping, TCP port or HTTPS"):
        quality.from_form(True, 10, 1, [("a.example.com", "udp", 1)], is_host)
    with pytest.raises(ValueError, match="'https'"):
        cfg('{"enabled":true,"targets":[{"host":"a.example.com","method":"http"}]}')


class _PlainContext:
    """Stands in for ssl's context: no TLS, so a local plain socket plays the web server (no certificate, no network)."""

    def __init__(self, error=None):
        self.error, self.names = error, []

    def wrap_socket(self, raw, server_hostname=None):
        self.names.append(server_hostname)
        if self.error:
            raise self.error
        return raw


def _server(answer: bytes):
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got = []

    def run():
        conn, _ = srv.accept()
        with conn:
            got.append(conn.recv(4096))
            if answer:
                conn.sendall(answer)
    threading.Thread(target=run, daemon=True).start()
    return srv, srv.getsockname()[1], got


@pytest.mark.parametrize(("answer", "ok"), [(b"HTTP/1.1 403 Forbidden\r\nServer: x\r\n\r\n", True),
                                            (b"SSH-2.0-OpenSSH\r\n", False), (b"", False)])
def test_https_check_sends_a_bare_head_request_and_any_http_answer_counts(monkeypatch, answer, ok):
    ctx = _PlainContext()
    monkeypatch.setattr(quality.ssl, "create_default_context", lambda: ctx)
    srv, port, got = _server(answer)
    try:
        res = quality.check(Target("127.0.0.1", "https", port))
    finally:
        srv.close()
    assert res[0] is ok and (res[1] is not None) is ok
    assert ctx.names == ["127.0.0.1"]
    assert got == [b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: VeroScudo\r\nConnection: close\r\n\r\n"]


def test_https_certificate_error_still_means_the_server_answered(monkeypatch):
    import ssl
    monkeypatch.setattr(quality.ssl, "create_default_context", lambda: _PlainContext(ssl.SSLCertVerificationError("bad cert")))
    srv, port, _ = _server(b"")
    try:
        assert quality.check(Target("127.0.0.1", "https", port))[0] is True
        assert quality.check(Target("127.0.0.1", "https", port), tls=True)[0] is True       # Hiddify: HTTPS stays HTTPS
    finally:
        srv.close()
    monkeypatch.setattr(quality.ssl, "create_default_context", lambda: _PlainContext(ssl.SSLError("reset")))
    srv, port, _ = _server(b"")
    try:
        assert quality.check(Target("127.0.0.1", "https", port))[0] is False
    finally:
        srv.close()


def test_per_target_counts_reach_the_tray_tooltip(tmp_path):
    m = quality.Monitor(tmp_path / "quality.json")
    c = CheckConfig(True, 10, 1, (Target("1.1.1.1"), Target("api.example.com", "https")))
    for i in range(7):
        q = m.add_round(c, "Work", [(True, 30), (i % 2 == 0, 40 if i % 2 == 0 else None)], now=1000.0 + i * 10)
    assert q.targets == (("1.1.1.1:443", 7, 0), ("api.example.com (HTTPS)", 7, 3))
    data = json.loads(m.path.read_text())
    assert data["targets"] == [{"label": "1.1.1.1:443", "checks": 7, "lost": 0},
                               {"label": "api.example.com (HTTPS)", "checks": 7, "lost": 3}]
    r = quality.read(m.path, "Work", now=1065.0)
    assert r == q
    f = tm.Facts(name="Work", kind="vpn", armed=True, up=True, check_enabled=True, quality=r)
    tip = tm.connection_view(f, tm.tray_state(f), c).tip.splitlines()
    assert tip[1:] == ["1.1.1.1:443: 0 of 7 lost", "api.example.com (HTTPS): 3 of 7 lost",
                       "Every 10 s: 1.1.1.1:443, api.example.com (HTTPS)"]


def test_the_guard_writes_down_minutes_while_on_and_not_connected(guard, monkeypatch):
    g, connected, _ = guard
    connected["up"] = False
    g.store.set_armed(True)
    monkeypatch.setattr(g, "enable_killswitch", lambda up: None)
    monkeypatch.setattr(g, "reconnect_async", lambda: None)
    g.watchdog()                                                         # armed, not connected: a down pass
    g.stats.flush()
    lines = [ln for f in (g.store.state / "stats").glob("*.jsonl") for ln in f.read_text().splitlines()]
    assert any(ln.endswith('"p":"Work","down":1}') for ln in lines)
