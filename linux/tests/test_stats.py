"""Statistics: the same format and rules as the Windows tests (windows/tests, 'Statistics: ...')."""
from datetime import date, datetime

from veroscudo import stats


def test_one_line_per_up_minute_and_profile_with_its_checks(tmp_path):
    r = stats.Recorder(tmp_path)
    t = datetime(2026, 11, 7, 10, 5, 10)
    r.tick(True, "aaa", "Work", t)
    r.checks(3, 1, "aaa", "Work", t.replace(second=30))
    r.tick(True, "bbb", "Home", t.replace(second=50))   # switched within the minute: both are recorded
    r.tick(False, "bbb", "Home", t.replace(minute=6))   # 10:05 written; 10:06 (down) not
    r.tick(False, "bbb", "Home", t.replace(minute=7))
    assert (tmp_path / "stats" / "2026-11-07.jsonl").read_text() == \
        '{"m":605,"id":"aaa","p":"Work","sent":3,"lost":1}\n{"m":605,"id":"bbb","p":"Home"}\n'


def test_up_minute_without_checks_and_flush(tmp_path):
    r = stats.Recorder(tmp_path)
    r.tick(True, "aaa", "Work", datetime(2026, 11, 7, 23, 59, 30))
    r.flush()
    assert (tmp_path / "stats" / "2026-11-07.jsonl").read_text() == '{"m":1439,"id":"aaa","p":"Work"}\n'


def test_profile_names_are_escaped_as_ascii_json():
    line = stats.format_line(5, "aaa", 'Офис "VPN"', 2, 0)
    assert line == '{"m":5,"id":"aaa","p":"\\u041e\\u0444\\u0438\\u0441 \\"VPN\\"","sent":2,"lost":0}'
    assert stats.parse(line) == ({"aaa": {5: (2, 0, False, 0)}}, {"aaa": 'Офис "VPN"'})


def test_parse_adds_repeats_skips_garbage_caps_lost_and_keeps_the_last_name():
    d, names = stats.parse('{"m":605,"id":"w","p":"W","sent":3,"lost":1}\n{"m":605,"id":"w","p":"W2","sent":2,"lost":0}\n'
                           'garbage\n{"m":606,"id":"w","p":"W2"}\n{"m":1500,"id":"w","p":"W"}\n'
                           '{"m":7,"id":"w","p":"W2","sent":1,"lost":9}\n{"m":8,"p":"old build"}\n{"m":9,"id":"h","p":"H"}\n')
    assert d == {"w": {605: (5, 1, False, 0), 606: (0, 0, False, 0), 7: (1, 1, False, 0)}, "h": {9: (0, 0, False, 0)}}
    assert names == {"w": "W2", "h": "H"}


def test_bars_use_the_check_thresholds_and_unrated_time_counts_as_good():
    m = {i: (6, 0) for i in range(10)}
    m.update({i: (6, 2) for i in range(10, 20)})
    m.update({i: (6, 4) for i in range(20, 30)})
    m.update({i: (0, 0) for i in range(30, 35)})
    day = stats.day_row(m)
    assert len(day.bars) == 144
    assert [b.state for b in day.bars[:5]] == ["good", "unstable", "bad", "up", "off"]
    assert day.vpn_minutes == 35 and day.good_pct == 43
    assert stats.bar_state(10, 10, 1) == "unstable"


def test_future_and_no_vpn():
    day = stats.day_row({}, until=600)
    assert day.bars[59].state == "off" and day.bars[60].state == "future"
    assert day.good_pct is None and stats.total_text(day) == "not used"


def test_texts_match_windows():
    bar = stats.Bar(860, "unstable", 10, 60, 11)
    assert stats.bar_text(bar) == "14:20-14:30  unstable – 18 % lost (11 of 60 checks), connected 10 of 10 min"
    assert stats.bar_text(stats.Bar(0, "off", 0, 0, 0)) == "00:00-00:10  not connected"
    assert stats.total_text(stats.Day([], 580, 87)) == "connected 9 h 40 min · good 87 %"
    assert stats.day_label(date(2026, 11, 7), date(2026, 11, 7)) == "Today, 7 Nov"
    assert stats.day_label(date(2026, 11, 5), date(2026, 11, 7)) == "Thursday, 5 Nov"


def test_prune_removes_only_old_day_files(tmp_path):
    d = tmp_path / "stats"
    d.mkdir()
    for n in ("2026-10-30.jsonl", "2026-10-31.jsonl", "2026-11-07.jsonl", "notes.jsonl", "keep.txt"):
        (d / n).write_text("")
    stats.Recorder(tmp_path).prune(datetime(2026, 11, 7, 12))
    assert sorted(p.name for p in d.iterdir()) == ["2026-10-31.jsonl", "2026-11-07.jsonl", "keep.txt", "notes.jsonl"]


def test_week_reads_seven_days_of_one_profile_today_first(tmp_path):
    (tmp_path / "stats").mkdir()
    (tmp_path / "stats" / "2026-11-06.jsonl").write_text('{"m":60,"id":"w","p":"Work"}\n{"m":61,"id":"h","p":"Home"}\n'
                                                       '{"m":62,"id":"h","p":"Home"}\n')
    rows = stats.week(tmp_path, "h", datetime(2026, 11, 7, 9, 0))
    assert len(rows) == 7 and rows[0][0].startswith("Today") and rows[1][1].vpn_minutes == 2
    assert rows[0][1].bars[60].state == "future"
    assert stats.week(tmp_path, "w", datetime(2026, 11, 7, 9, 0))[1][1].vpn_minutes == 1


def test_renamed_profile_keeps_its_history_and_a_removed_one_its_last_name(tmp_path):
    (tmp_path / "stats").mkdir()
    (tmp_path / "stats" / "2026-11-05.jsonl").write_text('{"m":900,"id":"o","p":"Old office"}\n{"m":100,"id":"w","p":"Work"}\n')
    (tmp_path / "stats" / "2026-11-07.jsonl").write_text('{"m":60,"id":"w","p":"Corporate"}\n{"m":500,"id":"h","p":"Home"}\n')
    seen = stats.profiles_seen(tmp_path, datetime(2026, 11, 7, 12, 0))
    assert seen == [("h", "Home"), ("w", "Corporate"), ("o", "Old office")]      # most recent first, the latest name
    config = [("w", "Corporate VPN"), ("h", "Home"), ("n", "New")]             # renamed again since; "Old office" removed
    assert stats.choices(seen, config, "w") == [("w", "Corporate VPN"), ("h", "Home"), ("o", "Old office (removed)")]
    assert stats.choices([], config, "n") == [("n", "New")]                    # the active one even before it has data
    week = stats.week(tmp_path, "w", datetime(2026, 11, 7, 12, 0))
    assert week[0][1].vpn_minutes == 1 and week[2][1].vpn_minutes == 1        # both names, one history


# ---------------------------------------------------------------- VeroScudo on, but not connected: "down" minutes
def test_recorder_writes_a_down_minute_only_without_an_up_pass(tmp_path):
    r = stats.Recorder(tmp_path)
    t = datetime(2026, 11, 7, 10, 5, 0)
    r.tick(False, "aaa", "Work", t, down=True)
    r.tick(False, "aaa", "Work", t.replace(second=15), down=True)
    r.tick(False, "aaa", "Work", t.replace(minute=6), down=True)
    r.tick(True, "aaa", "Work", t.replace(minute=6, second=30))           # reconnected within the minute: up wins
    r.tick(False, "aaa", "Work", t.replace(minute=7))                     # off: nothing
    r.flush()
    assert (tmp_path / "stats" / "2026-11-07.jsonl").read_text() == \
        '{"m":605,"id":"aaa","p":"Work","down":1}\n{"m":606,"id":"aaa","p":"Work"}\n'
    assert stats.format_line(605, "aaa", "Work", down=True) == '{"m":605,"id":"aaa","p":"Work","down":1}'


def test_parse_up_line_wins_over_a_down_line():
    d, _ = stats.parse('{"m":5,"id":"w","p":"W","down":1}\n{"m":5,"id":"w","p":"W","sent":3,"lost":0}\n'
                       '{"m":6,"id":"w","p":"W","down":1}\n{"m":6,"id":"w","p":"W","down":1}\n'
                       '{"m":7,"id":"w","p":"W"}\n{"m":7,"id":"w","p":"W","down":1}\n')
    assert d == {"w": {5: (3, 0, False, 0), 6: (0, 0, True, 0), 7: (0, 0, False, 0)}}


def test_two_down_minutes_make_a_bar_bad_and_count_against_good():
    m = {i: (0, 0, True) for i in range(3)}                            # bar 0: 3 down
    m.update({i: (6, 0, False) for i in range(10, 20)})                   # bar 1: 10 good
    m[20], m[21] = (0, 0, True), (6, 0, False)                            # bar 2: 1 down, 1 good: not bad
    m.update({30: (0, 0, True, 0), 31: (0, 0, True, 0), 32: (6, 0, False, 0)})     # bar 3: 2 down + 1 connected
    day = stats.day_row(m, until=40)
    assert [b.state for b in day.bars[:5]] == ["bad", "good", "good", "bad", "future"]
    assert day.vpn_minutes == 12 and day.down_minutes == 6
    assert day.good_pct == round(100 * 11 / 18)                           # bar 3's minute is in a bad bar
    assert stats.bar_text(day.bars[0]) == "00:00-00:10  could not connect 3 of 10 min (VeroScudo on)"
    assert stats.bar_text(day.bars[3]) == "00:30-00:40  could not connect 2 of 10 min (VeroScudo on); connected 1 of 10 min"
    assert stats.bar_text(stats.Bar(860, "bad", 0, 0, 0, 4), 15) == "14:20-14:35  could not connect 4 of 15 min (VeroScudo on)"


def test_total_texts_with_down_minutes():
    assert stats.total_text(stats.Day([], 566, 93, 12)) == "connected 9 h 26 min · good 93 % · no connection 12 min"
    assert stats.total_text(stats.Day([], 0, 0, 65)) == "no connection 1 h 5 min · good 0 %"
    assert stats.total_text(stats.Day([], 0, None, 0)) == "not used"
    only_down = stats.day_row({i: (0, 0, True) for i in range(12)})
    assert only_down.good_pct == 0 and stats.total_text(only_down) == "no connection 12 min · good 0 %"


def test_slow_answers_are_recorded_and_make_a_bar_unstable_never_bad():
    """slow = answered, but over 1 s per round trip: written only when any, parsed, capped at sent - lost; a bar with
    10 % or more lost or slow is unstable, but slow answers alone never make it bad (the same as quality.rating)."""
    assert stats.format_line(5, "w", "W", 6, 0, slow=6) == '{"m":5,"id":"w","p":"W","sent":6,"lost":0,"slow":6}'
    assert stats.format_line(5, "w", "W", 6, 1) == '{"m":5,"id":"w","p":"W","sent":6,"lost":1}'
    data, _ = stats.parse('{"m":5,"id":"w","p":"W","sent":6,"lost":2,"slow":9}\n{"m":5,"id":"w","p":"W","sent":6,"lost":0,"slow":1}')
    assert data["w"][5] == (12, 2, False, 5)                 # 9 capped at 6 - 2
    assert stats.bar_state(10, 60, 0, 60) == "unstable"
    assert stats.bar_state(10, 60, 0, 5) == "good"
    assert stats.bar_state(10, 60, 2, 4) == "unstable"
    assert stats.bar_state(10, 60, 40, 20) == "bad"
    day = stats.day_row({m: (6, 0, False, 6) for m in range(10)})
    assert day.bars[0].state == "unstable" and day.bars[0].slow == 60
    assert stats.bar_text(day.bars[0]) == "00:00-00:10  unstable – 0 % lost (0 of 60 checks), 60 slow (over 1 s), connected 10 of 10 min"


def test_recorder_writes_slow(tmp_path):
    from datetime import datetime
    r = stats.Recorder(tmp_path)
    t = datetime(2026, 1, 5, 10, 5)
    r.checks(3, 0, "w", "W", now=t, slow=2)
    r.flush()
    assert (tmp_path / "stats" / "2026-01-05.jsonl").read_text() == '{"m":605,"id":"w","p":"W","sent":3,"lost":0,"slow":2}\n'
