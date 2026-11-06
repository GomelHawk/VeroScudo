"""Statistics: 7 days of VPN time and connection quality - the same format and rules as windows/Core/67-Stats.ps1.

The daemon notes, minute by minute, whether VeroScudo's VPN was up and - when the connection check is on - how many of its
checks were sent and lost in that minute. One file per local day, <state>/stats/yyyy-mm-dd.jsonl, one line per minute
with the VPN up: {"m":605} (up, check off) or {"m":605,"sent":3,"lost":1}. A minute without a line = VPN off, the computer
asleep or VeroScudo off. Raw counts, not colours: the window groups them into bars, and a later change of the thresholds
re-rates old days. Files older than KEEP_DAYS are removed by the recorder. The trays read them with read_day()/day_row()."""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

KEEP_DAYS = 8                                    # 7 full days + today
BUCKET_MINUTES = 10
_LINE = re.compile(r'^\s*\{"m":(\d{1,4})(?:,"sent":(\d+),"lost":(\d+))?\}\s*$')
_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")


def format_line(minute: int, sent: int = 0, lost: int = 0) -> str:
    return f'{{"m":{minute},"sent":{sent},"lost":{lost}}}' if sent > 0 else f'{{"m":{minute}}}'


def parse(text: str) -> dict[int, tuple[int, int]]:
    """A day file -> {minute: (sent, lost)}. Repeated minutes (the daemon restarted) are added up; broken lines skipped."""
    out: dict[int, tuple[int, int]] = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        minute = int(m.group(1))
        if minute >= 1440:
            continue
        sent = int(m.group(2) or 0)
        lost = min(int(m.group(3) or 0), sent)
        s0, l0 = out.get(minute, (0, 0))
        out[minute] = (s0 + sent, l0 + lost)
    return out


def bar_state(up_minutes: int, sent: int, lost: int) -> str:
    """off (no VPN), up (VPN on, not rated), good / unstable / bad - the connection check's thresholds."""
    if up_minutes <= 0:
        return "off"
    if sent <= 0:
        return "up"
    loss = 100.0 * lost / sent
    return "good" if loss < 10 else "bad" if loss > 50 else "unstable"


@dataclass(frozen=True)
class Bar:
    start: int
    state: str
    up_minutes: int
    sent: int
    lost: int


@dataclass(frozen=True)
class Day:
    bars: list[Bar] = field(default_factory=list)
    vpn_minutes: int = 0
    good_pct: int | None = None


def day_row(minutes: dict[int, tuple[int, int]], bucket: int = BUCKET_MINUTES, until: int = 1440) -> Day:
    """A day's minutes -> its bars and totals. good_pct: the share of VPN time in good bars ('up' counts as good: the VPN
    worked and nothing was measured). until: today - later empty bars are 'future'."""
    bars, vpn, good = [], 0, 0
    for start in range(0, 1440, bucket):
        up = sent = lost = 0
        for m in range(start, min(start + bucket, 1440)):
            if m in minutes:
                up += 1
                sent += minutes[m][0]
                lost += minutes[m][1]
        state = "future" if start >= until and up == 0 else bar_state(up, sent, lost)
        vpn += up
        if state in ("good", "up"):
            good += up
        bars.append(Bar(start, state, up, sent, lost))
    return Day(bars, vpn, round(100.0 * good / vpn) if vpn else None)


def _hm(m: int) -> str:
    return f"{m // 60:02d}:{m % 60:02d}"


def bar_text(bar: Bar, bucket: int = BUCKET_MINUTES) -> str:
    span = f"{_hm(bar.start)}-{_hm(min(bar.start + bucket, 1440))}"
    if bar.state == "future":
        return span
    if bar.state == "off":
        return f"{span}  VPN off"
    if bar.state == "up":
        return f"{span}  VPN on {bar.up_minutes} of {bucket} min – not rated (connection check off)"
    pct = round(100.0 * bar.lost / bar.sent)
    return (f"{span}  {bar.state} – {pct} % lost ({bar.lost} of {bar.sent} checks), "
            f"VPN on {bar.up_minutes} of {bucket} min")


def total_text(day: Day) -> str:
    if day.vpn_minutes <= 0:
        return "no VPN"
    h, m = divmod(day.vpn_minutes, 60)
    dur = f"{h} h {m} min" if h else f"{m} min"
    return f"VPN {dur} · good {day.good_pct} %"


def day_label(d: date, today: date) -> str:
    name = "Today" if d == today else "Yesterday" if d == today - timedelta(days=1) else d.strftime("%A")
    return f"{name}, {d.day} {d.strftime('%b')}"


def stats_dir(state_dir: Path) -> Path:
    return state_dir / "stats"


def read_day(state_dir: Path, d: date) -> dict[int, tuple[int, int]]:
    try:
        return parse((stats_dir(state_dir) / f"{d.isoformat()}.jsonl").read_text())
    except (OSError, UnicodeDecodeError):
        return {}


def week(state_dir: Path, now: datetime | None = None) -> list[tuple[str, Day]]:
    """The window's 7 rows, today first."""
    now = now or datetime.now()
    out = []
    for i in range(7):
        d = now.date() - timedelta(days=i)
        until = now.hour * 60 + now.minute + 1 if i == 0 else 1440
        out.append((day_label(d, now.date()), day_row(read_day(state_dir, d), until=until)))
    return out


class Recorder:
    """The daemon's side: tick(up) every pass, checks(sent, lost) after each connection-check round. Thread-safe (the
    watchdog and the quality thread both call it)."""

    def __init__(self, state_dir: Path) -> None:
        self.dir = stats_dir(state_dir)
        self._lock = threading.Lock()
        self._cur: dict | None = None            # {date, m, up, sent, lost}
        self._pruned = ""

    def _select(self, now: datetime) -> dict:
        d, m = now.date().isoformat(), now.hour * 60 + now.minute
        if not self._cur or self._cur["date"] != d or self._cur["m"] != m:
            self._save()
            self._cur = {"date": d, "m": m, "up": False, "sent": 0, "lost": 0}
        return self._cur

    def _save(self) -> None:
        c = self._cur
        if not c or not c["up"]:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        with open(self.dir / f"{c['date']}.jsonl", "a") as f:
            f.write(format_line(c["m"], c["sent"], c["lost"]) + "\n")

    def tick(self, up: bool, now: datetime | None = None) -> None:
        now = now or datetime.now()
        with self._lock:
            c = self._select(now)
            c["up"] = c["up"] or up
            if self._pruned != c["date"]:
                self.prune(now)
                self._pruned = c["date"]

    def checks(self, sent: int, lost: int, now: datetime | None = None) -> None:
        with self._lock:
            c = self._select(now or datetime.now())
            c["up"] = True
            c["sent"] += sent
            c["lost"] += lost

    def flush(self) -> None:
        """The daemon stops: the minute so far (a restart adds to it)."""
        with self._lock:
            self._save()
            self._cur = None

    def prune(self, now: datetime | None = None) -> None:
        """Only our own day files, only those older than the kept days."""
        oldest = (now or datetime.now()).date() - timedelta(days=KEEP_DAYS - 1)
        try:
            files = list(self.dir.iterdir())
        except OSError:
            return
        for f in files:
            m = _FILE.match(f.name)
            if not m or not f.is_file():
                continue
            try:
                d = date.fromisoformat(m.group(1))
            except ValueError:
                continue
            if d < oldest:
                f.unlink(missing_ok=True)
