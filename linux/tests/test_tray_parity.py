"""What the Linux and macOS trays took over from the Windows tray: exit location, other-VPN notices and the Turn-on
question, the status window's details, the keep-awake badge and Remove - all decided in shared modules."""
import time
from datetime import datetime, timedelta

import pytest

from veroscudo import badge, countries, exitinfo, keepawake, nm, scutil
from veroscudo import traymodel as tm
from veroscudo.quality import CheckConfig, Quality, Target
from veroscudo.state import StateStore
from veroscudo.traymodel import Facts, Foreign

# ---------------------------------------------------------------- exit location
IPINFO = '{"ip":"203.0.113.25","city":"Łódź","country":"PL","org":"AS64500 Example Net"}'.encode()
TRACE = b"fl=1\nh=www.cloudflare.com\nip=198.51.100.7\nts=1\nloc=DE\n"


def test_ipinfo_is_read_as_utf8_and_the_trace_page_as_key_value():
    assert exitinfo.parse_ipinfo(IPINFO) == {"ip": "203.0.113.25", "city": "Łódź", "country": "PL",
                                             "org": "AS64500 Example Net", "source": "ipinfo.io"}
    assert exitinfo.parse_ipinfo(b'{"bogon":true}') is None and exitinfo.parse_ipinfo(b"<html>") is None
    assert exitinfo.parse_trace(TRACE) == {"ip": "198.51.100.7", "city": "", "country": "DE", "org": "",
                                           "source": "cloudflare.com"}
    assert exitinfo.parse_trace(b"nothing here") is None


def test_lookup_falls_back_to_cloudflare_and_names_both_failures():
    asked = []

    def get(url, timeout):
        asked.append((url, timeout))
        if "ipinfo" in url:
            raise OSError("timed out")
        return TRACE
    assert exitinfo.lookup(get)["source"] == "cloudflare.com"
    assert asked == [(exitinfo.IPINFO_URL, 6.0), (exitinfo.TRACE_URL, 6.0)]

    def dead(url, timeout):
        raise OSError("network unreachable")
    err = exitinfo.lookup(dead)["error"]
    assert "ipinfo.io: network unreachable" in err and "cloudflare.com: network unreachable" in err
    assert exitinfo.lookup(lambda u, t: IPINFO)["source"] == "ipinfo.io"


def test_exit_view_fresh_only_through_the_tunnel_that_is_up_now():
    t = datetime(2026, 11, 5, 10, 33).astimezone()
    info = {"ip": "203.0.113.25", "city": "Example City", "country": "pl", "org": "AS64500 Example Net",
            "source": "ipinfo.io", "profile": "Work", "time": t.isoformat()}
    since = t.timestamp() - 5
    v = exitinfo.exit_view(info, "protected", "Work", since)
    assert v.has and v.fresh and (v.code, v.place, v.right) == ("PL", "Poland / Example City", "203.0.113.25")
    assert "AS64500 Example Net" in v.tip and "profile Work" in v.tip and "2026-11-05 10:33" in v.tip
    old = exitinfo.exit_view(info, "protected", "Work", t.timestamp() + 60)        # looked up before this connect
    assert not old.fresh and old.right == "203.0.113.25 - 10:33"
    assert not exitinfo.exit_view(info, "off", "Work", since).fresh
    assert not exitinfo.exit_view(info, "protected", "Backup", since).fresh       # another profile's tunnel
    assert exitinfo.exit_view(info, "protected", "Work", t.timestamp() + 60, preview=True).fresh
    assert exitinfo.exit_view(info, "protected", "Work", since, checking=True).right == "checking..."
    assert exitinfo.report_line(v) == "PL Poland / Example City 203.0.113.25"


def test_exit_view_without_a_location_says_why():
    assert exitinfo.exit_view(None, "off", "W").text == "Location: shown once the VPN is connected"
    assert exitinfo.exit_view({}, "protected", "W", checking=True).text == "Checking where your traffic leaves..."
    v = exitinfo.exit_view(None, "protected", "W", failure="no answer within 20 s")
    assert not v.has and v.text == "Location not available - no answer within 20 s" and exitinfo.report_line(v) == v.text
    # Cloudflare gives no city: the country alone; an unknown code stays a code
    v = exitinfo.exit_view({"ip": "198.51.100.7", "country": "XX", "time": "garbage"}, "off", "W")
    assert v.place == "XX" and v.right == "198.51.100.7 - ?"


def test_country_names():
    assert countries.country_name("PL") == "Poland" and countries.country_name("gb") == "United Kingdom"
    assert countries.country_name("ZZ") == "ZZ" and countries.country_name("") == ""
    assert len(countries.NAMES) == 249


def test_exit_fetch_saves_the_answer_for_the_profile_it_was_asked_for(tmp_path):
    pref = tmp_path / "tray.json"
    f = exitinfo.ExitFetch(pref, get=lambda u, t: IPINFO)
    assert f.enabled()                                     # on unless switched off
    assert f.start("Work")
    assert f.checking and not f.start("Work")              # one at a time
    f._job["thread"].join(5)
    assert f.poll() and not f.checking
    c = f.info()
    assert c["ip"] == "203.0.113.25" and c["profile"] == "Work" and c["city"] == "Łódź"
    assert datetime.fromisoformat(c["time"]).tzinfo is not None
    keepawake.set_pref("showExit", False, pref)
    assert not f.enabled() and not f.start("Work")         # switched off: never asks


def test_exit_fetch_gives_up_after_20_seconds_and_reports_failures(tmp_path):
    f = exitinfo.ExitFetch(tmp_path / "tray.json", get=lambda u, t: time.sleep(1) or IPINFO)
    f.start("Work", now=1000.0)
    assert not f.poll(now=1010.0)                           # still waiting
    assert f.poll(now=1021.0) and not f.checking and f.failure == "no answer within 20 s"
    assert f.info() is None
    g = exitinfo.ExitFetch(tmp_path / "t2.json", get=lambda u, t: b"")
    g.start("Work")
    g._job["thread"].join(5)
    assert g.poll() and "ipinfo.io" in g.failure and g.info() is None


# ---------------------------------------------------------------- keep-awake badge
def test_the_badge_is_drawn_in_the_bottom_right_corner_only():
    size = 64                                   # badge 28 px wide, centre (50, 50): dark disc, green ring r 8.4, dark hole r 2
    out = badge.awake_badge(bytes(size * size * 4), size)

    def px(x, y):
        return out[(y * size + x) * 4:(y * size + x) * 4 + 4]
    assert px(0, 0) == px(30, 30) == px(10, 60) == b"\0\0\0\0"         # the icon itself is untouched
    assert px(49, 49) == bytes(badge.DARK) + b"\xff"                     # dark centre
    assert px(50, 45) == bytes(badge.GREEN) + b"\xff"                    # the ring
    assert px(50, 38) == bytes(badge.DARK) + b"\xff"                     # the dark border around it
    with pytest.raises(ValueError):
        badge.awake_badge(b"\0" * 10, size)


# ---------------------------------------------------------------- status window
def view(f):
    return tm.tray_state(f)


CHK = CheckConfig(True, 10, 2, (Target("1.1.1.1", "tcp", 443), Target("10.0.0.1", "ping")))


def test_connection_view_matches_the_windows_card():
    P = Facts(name="W", armed=True, up=True, check_enabled=True, quality=Quality("unstable", 22.2, 310, 18, 4))
    cv = tm.connection_view(P, view(P), CHK)
    assert (cv.text, cv.tone, cv.word) == ("unstable · 22.2% lost", "warn", "Unstable")
    assert cv.tip == "18 checks in the last 2 min: 4 lost (22.2%), median 310 ms\nEvery 10 s: 1.1.1.1:443, 10.0.0.1 (ping)"
    good = Facts(name="W", armed=True, up=True, check_enabled=True, quality=Quality("good", 0.0, 45, 18, 0))
    assert tm.connection_view(good, view(good), CHK).tone == "good"
    bad = Facts(name="W", armed=True, up=True, check_enabled=True, quality=Quality("bad", 61.1, None, 18, 11))
    assert tm.connection_view(bad, view(bad), CHK).tip.startswith("18 checks in the last 2 min: 11 lost (61.1%)\n")
    checking = Facts(name="W", armed=True, up=True, check_enabled=True)
    cv = tm.connection_view(checking, view(checking), CHK)
    assert cv.tone == "normal" and cv.word is None and cv.tip.startswith("Every 10 s")
    down = Facts(name="W", armed=True, up=False, expect="reconnect")
    assert tm.connection_view(down, view(down), CHK) == tm.ConnView("reconnecting", "warn", None, "")
    off = Facts(name="W", up=True)
    assert tm.connection_view(off, view(off), CHK) == tm.ConnView("connected (VPN off)", "normal", None, "")
    nochk = Facts(name="W", armed=True, up=True)
    assert tm.connection_view(nochk, view(nochk)).text == "connected (check off)"


def test_title_and_firewall_colours():
    lost, wait = Facts(name="W", armed=True), Facts(name="W", armed=True, expect="connect")
    assert tm.title_tone(lost, view(lost)) == "bad" and tm.title_tone(wait, view(wait)) == "warn"
    assert tm.firewall_tone(lost, view(lost)) == "bad" and tm.firewall_tone(wait, view(wait)) == "warn"
    prot = Facts(name="W", armed=True, up=True)
    assert tm.title_tone(prot, view(prot)) == "good" and tm.firewall_tone(prot, view(prot)) == "normal"
    assert tm.title_tone(Facts(name="W"), view(Facts(name="W"))) == "normal"
    assert tm.tone_colour("good", True) == "#30c84f" and tm.tone_colour("warn", False) == "#9d5d00"
    assert tm.tone_colour("normal", True) is None


def test_tooltip_wording_and_length_match_windows():
    v = view(Facts(name="W", armed=True, up=True))
    assert tm.tooltip(v, True) == "VeroScudo - Protected, keeping PC awake"
    long = view(Facts(name="W", armed=True, up=False, guard_running=False))
    assert len(tm.tooltip(long, True)) <= 63


def test_last_drop_line():
    now = time.mktime((2026, 11, 5, 15, 0, 0, 0, 0, -1))
    rec = {"profile": "W", "why": "connection lost", "time": now - 3600}
    assert tm.last_drop_text(rec, "W", now) == "14:00 - connection lost"
    assert tm.last_drop_text(rec, "Other", now) == "-" and tm.last_drop_text(None, "W", now) == "-"
    assert tm.last_drop_text({**rec, "time": now - 86400}, "W", now) == "04 Nov 15:00 - connection lost"
    assert tm.last_drop_text({**rec, "time": "x"}, "W", now) == "-"


def test_recent_events_clear_and_short_lines():
    lines = ["2026-11-05 09:12:01,114 [INFO] ARMED", "2026-11-05 10:40:13,031 [INFO] VPN 'W' terminated",
             "2026-11-05 10:40:23 [INFO] no milliseconds", "Traceback (most recent call last):"]
    assert tm.filter_events(lines) == ["09:12:01 [INFO] ARMED", "10:40:13 [INFO] VPN 'W' terminated",
                                       "10:40:23 [INFO] no milliseconds", "Traceback (most recent call last):"]
    assert tm.filter_events(lines, "2026-11-05 10:40:13")[0] == "10:40:23 [INFO] no milliseconds"
    assert tm.clear_stamp(time.mktime((2026, 11, 5, 10, 40, 13, 0, 0, -1))) == "2026-11-05 10:40:13"


def test_status_rows_carry_last_drop_other_vpns_and_the_exit_line():
    f = Facts(name="W", kind="vpn", armed=True, up=True, others=("tun9",))
    rows = dict(tm.status_rows(f, view(f), False, "ppp0"))
    assert rows["Other VPNs"] == "tun9" and "Last drop" not in rows and "Exit" not in rows
    fl = [Foreign("wg-x", "wg1", "wg-x", False)]
    rows = dict(tm.status_rows(f, view(f), True, "ppp0", last_drop="14:00 - connection lost", foreign=fl, exit_line="PL x"))
    assert rows["Last drop"] == "14:00 - connection lost" and rows["Other VPNs"] == "wg-x (not imported)"
    assert rows["Exit"] == "PL x" and rows["Keep awake"] == "on"
    assert "Other VPNs" not in dict(tm.status_rows(f, view(f), False, None, foreign=()))


# ---------------------------------------------------------------- other VPNs
def test_foreign_list_names_connections_and_leaves_out_your_own():
    owners = {"wg0": "wg-home", "tun0": "CorporateVPN", "wg1": "example-wireguard"}
    fl = tm.foreign_list(["tun0", "tun5", "wg0"], owners, "tun0", "CorporateVPN", ("CorporateVPN", "wg-home"))
    assert fl == [Foreign("tun5", "tun5", None, False), Foreign("wg-home", "wg0", "wg-home", True),
                  Foreign("example-wireguard", "wg1", "example-wireguard", False)]
    assert [x.kind for x in fl] == ["app", "profile", "not imported"]
    assert [x.can_disconnect for x in fl] == [False, True, True]
    # your own profile's connection while VeroScudo has not let it through yet (no own interface known)
    assert tm.foreign_list(["tun0"], {"tun0": "CorporateVPN"}, None, "CorporateVPN") == []
    assert tm.foreign_text(fl) == "tun5 (VPN app), wg-home (another profile), example-wireguard (not imported)"


def test_foreign_notices_once_per_detection():
    a, b = Foreign("a", "wg1", "a", False), Foreign("tun3", "tun3", None, False)
    new, shown = tm.new_foreign(set(), [a])
    assert new == [a]
    new, shown = tm.new_foreign(shown, [a, b])
    assert new == [b]
    new, shown = tm.new_foreign(shown, [b])                       # a went away ...
    new, shown = tm.new_foreign(shown, [a, b])                    # ... and came back: announced again
    assert new == [a]
    assert tm.foreign_notice(a)[1] == ('"a" connected, but it is not a VeroScudo profile.\nIts traffic is blocked. '
                                       "Disconnect it, or import it in Settings.")
    assert "Disconnect it in that app" in tm.foreign_notice(b)[1] and "tun3" in tm.foreign_notice(b)[1]
    assert "another VeroScudo profile" in tm.foreign_notice(Foreign("p", "wg0", "p", True))[1]
    assert tm.foreign_notice(a)[0] == "VeroScudo - another VPN"


def test_turn_on_question_like_windows():
    wg = Foreign("example-wireguard", "wg1", "example-wireguard", False)
    app = Foreign("tun1", "tun1", None, False)
    prof = Foreign("wg-home", "wg0", "wg-home", True)
    p = tm.foreign_prompt([wg], "CorporateVPN")
    assert p.text == ('"example-wireguard" is connected. It is not a VeroScudo profile.\nVeroScudo will connect '
                      '"CorporateVPN" and block everything else, including its traffic.')
    assert p.buttons == (("cancel", "Cancel", False), ("disconnect", "Disconnect example-wireguard and turn on", True))
    assert "It is another VeroScudo profile." in tm.foreign_prompt([prof], "C").text
    p = tm.foreign_prompt([app], "C")
    assert p.buttons == (("cancel", "Cancel", False), ("anyway", "Turn on anyway", True))
    assert "cannot disconnect a VPN app's own tunnel (tun1)" in p.text
    p = tm.foreign_prompt([wg, app], "C")
    assert [b[0] for b in p.buttons] == ["cancel", "anyway", "disconnect"]
    assert p.buttons[2][1] == "Disconnect what it can and turn on" and not p.buttons[1][2]
    assert '"example-wireguard", "tun1" are connected.' in p.text and "their traffic" in p.text
    assert tm.foreign_prompt([wg, prof], "C").buttons[1][1] == "Disconnect all and turn on"


# ---------------------------------------------------------------- Settings
def test_remove_asks_first_with_this_platforms_wording():
    title, text = tm.remove_question("wg-home", "linux")
    assert title == "Remove 'wg-home' from VeroScudo?" and "NetworkManager" in text and "tray menu (VPN profile)" in text
    assert "System Settings > VPN" in tm.remove_question("x", "darwin")[1]


def test_runner_runs_a_chain_and_stops_at_the_first_failure():
    r = tm.Runner()
    r.start("on", ["true"], ["false"], ["echo", "never"])
    for _ in range(100):
        res = r.results()
        if res:
            break
        time.sleep(0.05)
    assert res[0][:3] == ("on", ["false"], 1)
    r.start("on", ["true"], ["echo", "done"])
    for _ in range(100):
        res = r.results()
        if res:
            break
        time.sleep(0.05)
    assert res[0][1] == ["echo", "done"] and res[0][2] == 0 and res[0][3].strip() == "done"


# ---------------------------------------------------------------- backends and the guard's record
def test_nm_names_the_connection_behind_each_tunnel(monkeypatch):
    text = "wg-home:wireguard:wg0\nCorporate\\:VPN:vpn:wlp2s0\nWi-Fi:802-11-wireless:wlp2s0\nopen:tun:tun7\n"
    assert nm.parse_active(text)[1] == ("Corporate:VPN", "vpn", "wlp2s0")
    monkeypatch.setattr(nm, "_nmcli", lambda *a: text)
    monkeypatch.setattr(nm, "iface", lambda name: "ppp0" if name == "Corporate:VPN" else None)
    assert nm.tunnel_owners() == {"wg0": "wg-home", "ppp0": "Corporate:VPN", "tun7": "open"}
    assert nm.down_argv("-odd name") == ["nmcli", "connection", "down", "id", "-odd name"]
    assert scutil.tunnel_owners() == {} and scutil.down_argv("Work") == ["scutil", "--nc", "stop", "Work"]


def test_the_newest_drop_is_kept_for_the_tray(tmp_path):
    s = StateStore(tmp_path)
    assert s.last_drop() is None
    s.record_drop("Work", "connection lost", now=100.0)
    s.record_drop("Work", "you disconnected", now=200.0)
    assert s.last_drop() == {"profile": "Work", "why": "you disconnected", "time": 200.0}
    assert (s.drop_file.stat().st_mode & 0o777) == 0o644


def test_exit_times_keep_their_offset():
    """The exit lookup's time stamp is local with its offset - comparable with the tray's protected_since."""
    t = datetime.now().astimezone() - timedelta(seconds=1)
    assert exitinfo._parse_time(t.isoformat()).timestamp() == pytest.approx(t.timestamp())


def test_turned_on_elsewhere_reads_as_connecting():
    blocked = view(Facts(name="W", armed=True))
    assert tm.turned_on_elsewhere("off", blocked, None)
    assert not tm.turned_on_elsewhere("protected", blocked, None)            # a real drop
    assert not tm.turned_on_elsewhere("off", blocked, "connect")             # the tray started it itself
    assert not tm.turned_on_elsewhere(None, blocked, None)                   # the first look
