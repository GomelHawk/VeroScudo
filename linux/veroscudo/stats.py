"""Statistics: 7 days of VPN time and connection quality - the same format and rules as windows/Core/67-Stats.ps1.

The daemon notes, minute by minute, which VeroScudo profile was up and - when the connection check is on - how many of its
checks were sent and lost in that minute. One file per local day, <state>/stats/yyyy-mm-dd.jsonl, one line per minute and
profile with the VPN up: {"m":605,"id":"3f2a9c0d1e2b","p":"Work"} (up, check off) or the same with "sent":3,"lost":1;
a minute VeroScudo was on but could not connect: the same with "down":1 (shown as bad - a redial that keeps failing).
Per profile: a corporate VPN and a home one are different connections - their problems must not be mixed. "id" is the
profile's lasting id (config.profile_id), so a renamed profile keeps its history; "p" is its name at that minute, so a
removed profile is still shown by its last name. A minute without a line = VPN off, the computer asleep or VeroScudo
off. JSON with ASCII escapes (the same on Windows). Raw counts, not colours: the window groups them into bars, and a
later change of the thresholds re-rates old days. Files older than KEEP_DAYS are removed by the recorder. The trays read them with read_day()/day_row()."""
from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

KEEP_DAYS = 8                                    # 7 full days + today
BUCKET_MINUTES = 10
_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")


def format_line(minute: int, pid: str, name: str, sent: int = 0, lost: int = 0, down: bool = False) -> str:
    head = f'{{"m":{minute},"id":{json.dumps(pid)},"p":{json.dumps(name, ensure_ascii=True)}'
    if down:
        return head + ',"down":1}'
    return f'{head},"sent":{sent},"lost":{lost}}}' if sent > 0 else head + "}"


Minutes = dict[int, tuple[int, int, bool]]      # minute -> (sent, lost, down); down: on, but not connected all minute


def parse(text: str) -> tuple[dict[str, Minutes], dict[str, str]]:
    """A day file -> ({id: {minute: (sent, lost, down)}}, {id: its last name in the file}). Repeated minutes (the daemon
    restarted) are added up - an up line for a minute wins over a down line; broken lines and lines without an id (an
    early test build) are skipped."""
    out: dict[str, Minutes] = {}
    names: dict[str, str] = {}
    for line in text.splitlines():
        try:
            j = json.loads(line)
            minute, pid, name = int(j["m"]), j["id"], j["p"]
            sent = int(j.get("sent", 0))
            lost = min(int(j.get("lost", 0)), sent)
            down = j.get("down") == 1
        except (ValueError, KeyError, TypeError):
            continue
        if not (isinstance(pid, str) and pid and isinstance(name, str) and 0 <= minute < 1440 and sent >= 0 and lost >= 0):
            continue
        day = out.setdefault(pid, {})
        s0, l0, d0 = day.get(minute, (0, 0, True))
        day[minute] = (s0 + sent, l0 + lost, d0 and down)
        names[pid] = name
    return out, names


def bar_state(up_minutes: int, sent: int, lost: int) -> str:
    """off (this profile not connected), up (connected, not rated), good / unstable / bad - the connection check's thresholds."""
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
    down_minutes: int = 0             # VeroScudo on, the profile not connected


DOWN_BAD = 2                          # a bar with this many minutes on-but-not-connected is bad (a redial that keeps failing)


@dataclass(frozen=True)
class Day:
    bars: list[Bar] = field(default_factory=list)
    vpn_minutes: int = 0              # connected
    good_pct: int | None = None       # good connected minutes out of connected + down minutes
    down_minutes: int = 0             # on, but not connected


def day_row(minutes: Minutes, bucket: int = BUCKET_MINUTES, until: int = 1440) -> Day:
    """A day's minutes -> its bars and totals. good_pct: the share of good minutes ('up' counts as good: the VPN worked
    and nothing was measured) out of the connected and the could-not-connect minutes. A bar with DOWN_BAD or more
    could-not-connect minutes is bad. until: today - later empty bars are 'future'. Pure."""
    bars, vpn, good, down_all = [], 0, 0, 0
    for start in range(0, 1440, bucket):
        up = down = sent = lost = 0
        for m in range(start, min(start + bucket, 1440)):
            v = minutes.get(m)
            if v is None:
                continue
            if len(v) > 2 and v[2]:
                down += 1
            else:
                up += 1
                sent += v[0]
                lost += v[1]
        state = ("future" if start >= until and up == 0 and down == 0 else "bad" if down >= DOWN_BAD
                 else bar_state(up, sent, lost))
        vpn += up
        down_all += down
        if state in ("good", "up"):
            good += up
        bars.append(Bar(start, state, up, sent, lost, down))
    total = vpn + down_all
    return Day(bars, vpn, round(100.0 * good / total) if total else None, down_all)


def _hm(m: int) -> str:
    return f"{m // 60:02d}:{m % 60:02d}"


def bar_text(bar: Bar, bucket: int = BUCKET_MINUTES) -> str:
    span = f"{_hm(bar.start)}-{_hm(min(bar.start + bucket, 1440))}"
    if bar.down_minutes >= DOWN_BAD:
        text = f"{span}  could not connect {bar.down_minutes} of {bucket} min (VeroScudo on)"
        return text + (f"; connected {bar.up_minutes} of {bucket} min" if bar.up_minutes > 0 else "")
    if bar.state == "future":
        return span
    if bar.state == "off":
        return f"{span}  not connected"
    if bar.state == "up":
        return f"{span}  connected {bar.up_minutes} of {bucket} min – not rated (connection check off)"
    pct = round(100.0 * bar.lost / bar.sent)
    return (f"{span}  {bar.state} – {pct} % lost ({bar.lost} of {bar.sent} checks), "
            f"connected {bar.up_minutes} of {bucket} min")


def _dur(minutes: int) -> str:
    h, m = divmod(minutes, 60)
    return f"{h} h {m} min" if h else f"{m} min"


def total_text(day: Day) -> str:
    """'connected 9 h 26 min · good 93 % · no connection 12 min', 'no connection 12 min · good 0 %' or 'not used'. Pure."""
    if day.vpn_minutes <= 0 and day.down_minutes <= 0:
        return "not used"
    if day.vpn_minutes <= 0:
        return f"no connection {_dur(day.down_minutes)} · good 0 %"
    text = f"connected {_dur(day.vpn_minutes)} · good {day.good_pct} %"
    return text + (f" · no connection {_dur(day.down_minutes)}" if day.down_minutes > 0 else "")


def day_label(d: date, today: date) -> str:
    name = "Today" if d == today else "Yesterday" if d == today - timedelta(days=1) else d.strftime("%A")
    return f"{name}, {d.day} {d.strftime('%b')}"


def stats_dir(state_dir: Path) -> Path:
    return state_dir / "stats"


def read_day(state_dir: Path, d: date) -> tuple[dict[str, Minutes], dict[str, str]]:
    try:
        return parse((stats_dir(state_dir) / f"{d.isoformat()}.jsonl").read_text())
    except (OSError, UnicodeDecodeError):
        return {}, {}


def profiles_seen(state_dir: Path, now: datetime | None = None) -> list[tuple[str, str]]:
    """(id, last name) of the profiles with VPN time in the last 7 days, the most recently used first."""
    now = now or datetime.now()
    last: dict[str, tuple[int, int]] = {}
    names: dict[str, str] = {}
    for i in range(6, -1, -1):                                    # oldest day first: a later name wins
        data, nm = read_day(state_dir, now.date() - timedelta(days=i))
        names.update(nm)
        for pid, mins in data.items():
            key = (-i, max(mins))
            if pid not in last or key > last[pid]:
                last[pid] = key
    return [(pid, names[pid]) for pid in sorted(last, key=lambda n: last[n], reverse=True)]


def week(state_dir: Path, pid: str, now: datetime | None = None) -> list[tuple[str, Day]]:
    """The window's 7 rows for one profile (by id), today first."""
    now = now or datetime.now()
    out = []
    for i in range(7):
        d = now.date() - timedelta(days=i)
        until = now.hour * 60 + now.minute + 1 if i == 0 else 1440
        out.append((day_label(d, now.date()), day_row(read_day(state_dir, d)[0].get(pid, {}), until=until)))
    return out


def choices(seen: list[tuple[str, str]], profiles: list[tuple[str, str]], active: str | None) -> list[tuple[str, str]]:
    """The drop-down as (id, label): the active profile first (also before it has data), then the others with data. A
    profile's label is its current name (renamed: the history stays); a removed one keeps its last name, marked. Pure.
    profiles: (id, name) of config.json; active: the active profile's id."""
    now = dict(profiles)
    order = ([active] if active else []) + [pid for pid, _ in seen if pid != active]
    last = dict(seen)
    return [(pid, now[pid] if pid in now else f"{last.get(pid, pid)} (removed)") for pid in order]


class Recorder:
    """The daemon's side: tick(up, id, name, down=...) every pass, checks(sent, lost, id, name) after each connection-check
    round. A minute with any up pass is up; a minute with only down passes (on, the active profile not connected) is
    written as down. Thread-safe (the watchdog and the quality thread both call it)."""

    def __init__(self, state_dir: Path) -> None:
        self.dir = stats_dir(state_dir)
        self._lock = threading.Lock()
        self._cur: dict | None = None            # {date, m, p: {id: [up, sent, lost, name, down]}}
        self._pruned = ""

    def _select(self, now: datetime) -> dict:
        d, m = now.date().isoformat(), now.hour * 60 + now.minute
        if not self._cur or self._cur["date"] != d or self._cur["m"] != m:
            self._save()
            self._cur = {"date": d, "m": m, "p": {}}
        return self._cur

    def _save(self) -> None:
        c = self._cur
        lines = [format_line(c["m"], pid, v[3], v[1], v[2], down=not v[0]) for pid, v in c["p"].items() if v[0] or v[4]] \
            if c else []
        if not lines:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        with open(self.dir / f"{c['date']}.jsonl", "a") as f:
            f.write("".join(ln + "\n" for ln in lines))

    def tick(self, up: bool, pid: str, name: str, now: datetime | None = None, down: bool = False) -> None:
        """up: the profile is connected (and VeroScudo on); down: VeroScudo is on, but the profile is not connected."""
        now = now or datetime.now()
        with self._lock:
            c = self._select(now)
            if (up or down) and pid:
                v = c["p"].setdefault(pid, [False, 0, 0, name, False])
                v[3] = name
                if up:
                    v[0] = True
                else:
                    v[4] = True
            if self._pruned != c["date"]:
                self.prune(now)
                self._pruned = c["date"]

    def checks(self, sent: int, lost: int, pid: str, name: str, now: datetime | None = None) -> None:
        if not pid:
            return
        with self._lock:
            v = self._select(now or datetime.now())["p"].setdefault(pid, [False, 0, 0, name, False])
            v[0], v[3] = True, name
            v[1] += sent
            v[2] += lost

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
