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
    assert stats.parse(line) == ({"aaa": {5: (2, 0)}}, {"aaa": 'Офис "VPN"'})


def test_parse_adds_repeats_skips_garbage_caps_lost_and_keeps_the_last_name():
    d, names = stats.parse('{"m":605,"id":"w","p":"W","sent":3,"lost":1}\n{"m":605,"id":"w","p":"W2","sent":2,"lost":0}\n'
                           'garbage\n{"m":606,"id":"w","p":"W2"}\n{"m":1500,"id":"w","p":"W"}\n'
                           '{"m":7,"id":"w","p":"W2","sent":1,"lost":9}\n{"m":8,"p":"old build"}\n{"m":9,"id":"h","p":"H"}\n')
    assert d == {"w": {605: (5, 1), 606: (0, 0), 7: (1, 1)}, "h": {9: (0, 0)}}
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
