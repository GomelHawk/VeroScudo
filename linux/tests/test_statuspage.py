"""Service status page (Settings > Connection): the address rule, the Statuspage answer, the status window's line and the
background fetch - the same texts as the Windows tray. No network: the fetch gets a stand-in."""
import time

from veroscudo import keepawake, statuspage
from veroscudo import traymodel as tm
from veroscudo.traymodel import Facts

OK = b'{"page":{"id":"x","name":"Example Service","url":"https://status.example.com"},' \
     b'"status":{"indicator":"none","description":"All Systems Operational"}}'


def test_only_https_addresses_up_to_300_characters_are_saved():
    assert statuspage.url_error(statuspage.DEFAULT_URL) == ""
    assert statuspage.DEFAULT_URL == "https://status.anthropic.com/api/v2/status.json"
    for bad in ("http://status.example.com/api/v2/status.json", "status.example.com", "", "https://", "ftp://x.example.com",
                "https://status.example.com/" + "a" * 300, "https://status example.com/"):
        assert statuspage.url_error(bad) == "The status page must be an https:// address", bad
    assert statuspage.url_error("HTTPS://status.example.com/api/v2/status.json") == ""


def test_the_statuspage_answer_and_its_colours():
    assert statuspage.parse(OK) == {"name": "Example Service", "indicator": "none", "description": "All Systems Operational"}
    assert statuspage.parse(b"<html>") is None and statuspage.parse(b'{"status":{}}') is None
    url = "https://status.example.com/api/v2/status.json"
    at = time.mktime((2026, 11, 9, 14, 5, 0, 0, 0, -1))
    v = statuspage.service_view(statuspage.parse(OK), url, at)
    assert (v.text, v.tone, v.tip) == ("Example Service: All Systems Operational", "good", f"checked 14:05 from {url}")
    for ind, tone in (("minor", "warn"), ("major", "bad"), ("critical", "bad")):
        assert statuspage.service_view({"name": "S", "indicator": ind, "description": "d"}, url, at).tone == tone
    bad = statuspage.service_view({"error": "timed out"}, url, at)
    assert bad.text == "status.example.com: not reachable" and bad.tip.startswith(f"checked 14:05 from {url}")
    assert "timed out" in bad.tip
    assert tm.tone_colour(v.tone, True) == "#30c84f"


def test_the_service_card_looks_like_the_exit_line():
    url = "https://status.example.com/api/v2/status.json"
    at = time.mktime((2026, 11, 9, 14, 5, 0, 0, 0, -1))
    v = statuspage.service_view(statuspage.parse(OK), url, at)
    assert (v.badge, v.tone, v.name, v.right) == ("OK", "good", "Example Service", "All Systems Operational · 14:05")
    for ind, badge, tone in (("minor", "!", "warn"), ("major", "!!", "bad"), ("critical", "!!", "bad"), ("odd", "?", "normal"),
                             ("", "?", "normal")):
        v = statuspage.service_view({"name": "S", "indicator": ind, "description": "d"}, url, at)
        assert (v.badge, v.tone, v.right) == (badge, tone, "d · 14:05"), ind
    nameless = statuspage.service_view({"name": "", "indicator": "none", "description": "d"}, url, at)
    assert nameless.name == "status.example.com" and nameless.text == "status.example.com: d"
    gone = statuspage.service_view({"error": "timed out"}, url, at)
    assert (gone.badge, gone.tone, gone.name, gone.right) == ("?", "normal", "status.example.com", "not reachable · 14:05")
    assert gone.tip == f"checked 14:05 from {url}\ntimed out" and gone.text == "status.example.com: not reachable"
    first = statuspage.service_view(None, url)
    assert (first.badge, first.tone, first.name, first.right, first.text) == ("?", "normal", "status.example.com",
                                                                              "not checked yet", "status.example.com: not checked yet")
    assert statuspage.service_view(None, url, checking=True).right == "checking..."
    # Refresh: the last answer stays, the right-hand text says a check runs; the report line does not change
    again = statuspage.service_view(statuspage.parse(OK), url, at, checking=True)
    assert (again.badge, again.right, again.text) == ("OK", "checking...", "Example Service: All Systems Operational")
    assert statuspage.service_view({"error": "x"}, url, at, checking=True).right == "checking..."


def test_the_badge_is_always_neutral():
    """Secondary information: the badge looks like the exit line's country code, never coloured (the user's call)."""
    for tone in ("good", "warn", "bad", "normal"):
        for dark in (True, False):
            assert statuspage.badge_colours(tone, dark) == (None, None)


def test_refresh_fetches_now_and_shows_checking(tmp_path):
    sp = statuspage.StatusFetch(tmp_path / "tray.json", get=lambda u, t: OK)
    assert not sp.refresh()                                      # off: nothing is fetched
    sp.set_enabled(True)
    sp._job["thread"].join(5)
    sp.poll(now=1000.0)
    assert sp.view().badge == "OK" and "·" in sp.view().right
    assert sp.refresh() and sp.checking and sp.view().right == "checking..." and sp.view().badge == "OK"
    assert not sp.refresh()                                      # one at a time
    sp._job["thread"].join(5)
    assert sp.poll(now=1010.0) and sp.view().right.startswith("All Systems Operational · ")


def test_the_service_line_in_the_status_table_and_the_report():
    f = Facts(name="Work", kind="vpn", armed=True, up=True)
    rows = tm.status_rows(f, tm.tray_state(f), False, "ppp0", service="Example Service: All Systems Operational")
    assert rows[-1] == ("Service", "Example Service: All Systems Operational")
    assert ("Service" not in dict(tm.status_rows(f, tm.tray_state(f), False, "ppp0")))


def test_fetch_is_opt_in_per_user_and_runs_in_the_background(tmp_path):
    pref = tmp_path / "tray.json"
    asked = []
    sp = statuspage.StatusFetch(pref, get=lambda u, t: asked.append((u, t)) or OK)
    assert not sp.enabled() and sp.view() is None and not sp.start() and not sp.tick()
    assert sp.url() == statuspage.DEFAULT_URL
    sp.set_enabled(True)                                         # turned on: fetched once at once
    assert keepawake.get_pref("statusPage", None, pref) is True and sp.checking
    assert sp.view().right == "checking..."
    sp._job["thread"].join(5)
    assert sp.tick(now=1000.0) and not sp.checking
    assert sp.view().text == "Example Service: All Systems Operational"
    assert asked == [(statuspage.DEFAULT_URL, 6.0)]
    assert not sp.tick(now=1000.0 + 3600) and not sp.checking    # no timer of its own: after each connect and on Refresh
    assert sp.on_connected() and sp.checking
    sp._job["thread"].join(5)
    sp.poll()
    assert sp.set_url("http://status.example.com") == statuspage.BAD_URL
    assert keepawake.get_pref("statusPageUrl", None, pref) is None          # not saved
    assert sp.set_url("https://status.example.com/api/v2/status.json") == ""
    assert sp.url() == "https://status.example.com/api/v2/status.json"
    assert sp.view().right == "checking..."                                  # the old answer was for the old address


def test_fetch_failures_say_not_reachable(tmp_path):
    def dead(u, t):
        raise OSError("network unreachable")
    assert statuspage.fetch(statuspage.DEFAULT_URL, dead) == {"error": "network unreachable"}
    assert statuspage.fetch(statuspage.DEFAULT_URL, lambda u, t: b"{}") == {"error": "not a Statuspage answer"}
    assert statuspage.fetch("http://x.example.com", lambda u, t: OK) == {"error": statuspage.BAD_URL}
    sp = statuspage.StatusFetch(tmp_path / "tray.json", get=lambda u, t: time.sleep(1) or OK)
    sp.set_enabled(True)
    started = sp._job["started"]
    assert not sp.poll(now=started + 5)
    assert sp.poll(now=started + 19) and sp.view().text == "status.anthropic.com: not reachable"
