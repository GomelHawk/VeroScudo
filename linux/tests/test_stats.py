"""Statistics: the same format and rules as the Windows tests (windows/tests, 'Statistics: ...')."""
from datetime import date, datetime

from veroscudo import stats


def test_one_line_per_up_minute_with_its_checks(tmp_path):
    r = stats.Recorder(tmp_path)
    t = datetime(2026, 11, 7, 10, 5, 10)
    r.tick(True, t)
    r.checks(3, 1, t.replace(second=30))
    r.tick(False, t.replace(minute=6))                  # 10:05 written; 10:06 (down) not
    r.tick(False, t.replace(minute=7))
    assert (tmp_path / "stats" / "2026-11-07.jsonl").read_text() == '{"m":605,"sent":3,"lost":1}\n'


def test_up_minute_without_checks_and_flush(tmp_path):
    r = stats.Recorder(tmp_path)
    r.tick(True, datetime(2026, 11, 7, 23, 59, 30))
    r.flush()
    assert (tmp_path / "stats" / "2026-11-07.jsonl").read_text() == '{"m":1439}\n'


def test_parse_adds_repeats_skips_garbage_caps_lost():
    d = stats.parse('{"m":605,"sent":3,"lost":1}\n{"m":605,"sent":2,"lost":0}\ngarbage\n{"m":606}\n{"m":1500}\n'
                    '{"m":7,"sent":1,"lost":9}\n')
    assert d == {605: (5, 1), 606: (0, 0), 7: (1, 1)}


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
    assert day.good_pct is None and stats.total_text(day) == "no VPN"


def test_texts_match_windows():
    bar = stats.Bar(860, "unstable", 10, 60, 11)
    assert stats.bar_text(bar) == "14:20-14:30  unstable – 18 % lost (11 of 60 checks), VPN on 10 of 10 min"
    assert stats.bar_text(stats.Bar(0, "off", 0, 0, 0)) == "00:00-00:10  VPN off"
    assert stats.total_text(stats.Day([], 580, 87)) == "VPN 9 h 40 min · good 87 %"
    assert stats.day_label(date(2026, 11, 7), date(2026, 11, 7)) == "Today, 7 Nov"
    assert stats.day_label(date(2026, 11, 5), date(2026, 11, 7)) == "Thursday, 5 Nov"


def test_prune_removes_only_old_day_files(tmp_path):
    d = tmp_path / "stats"
    d.mkdir()
    for n in ("2026-10-30.jsonl", "2026-10-31.jsonl", "2026-11-07.jsonl", "notes.jsonl", "keep.txt"):
        (d / n).write_text("")
    stats.Recorder(tmp_path).prune(datetime(2026, 11, 7, 12))
    assert sorted(p.name for p in d.iterdir()) == ["2026-10-31.jsonl", "2026-11-07.jsonl", "keep.txt", "notes.jsonl"]


def test_week_reads_seven_days_today_first(tmp_path):
    (tmp_path / "stats").mkdir()
    (tmp_path / "stats" / "2026-11-06.jsonl").write_text('{"m":60}\n')
    rows = stats.week(tmp_path, datetime(2026, 11, 7, 9, 0))
    assert len(rows) == 7 and rows[0][0].startswith("Today") and rows[1][1].vpn_minutes == 1
    assert rows[0][1].bars[60].state == "future"
