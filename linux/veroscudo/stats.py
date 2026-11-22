"""Statistics: 7 days of VPN time and connection quality - the same format and rules as windows/Core/67-Stats.ps1.

The daemon notes, minute by minute, which VeroScudo profile was up and - when the connection check is on - how many of its
checks were sent, lost and slow (answered, but over 1 s per round trip) in that minute. One file per local day, <state>/stats/yyyy-mm-dd.jsonl, one line per minute and
profile with the VPN up: {"m":605,"id":"3f2a9c0d1e2b","p":"Work"} (up, check off) or the same with "sent":3,"lost":1 (+ ,"slow":2 when any;
+ ,"rated":"bad" or "unstable" when the live rating - the status window's, over the last minutes - showed that in this minute);
a minute VeroScudo was on but could not connect: the same with "down":1 (shown as bad - a redial that keeps failing);
a minute the connected profile was lost (VeroScudo on, the same profile, then redialed): + ,"drop":1 (its bar is bad).
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

from . import quality

KEEP_DAYS = 8                                    # 7 full days + today
BUCKET_MINUTES = 10
_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl\Z")


def format_line(minute: int, pid: str, name: str, sent: int = 0, lost: int = 0, down: bool = False, slow: int = 0,
                drop: bool = False, rated: int = 0) -> str:
    head = f'{{"m":{minute},"id":{json.dumps(pid)},"p":{json.dumps(name, ensure_ascii=True)}'
    tail = ',"drop":1}' if drop else "}"
    if down:
        return head + ',"down":1' + tail
    if sent <= 0:
        return head + tail
    return (f'{head},"sent":{sent},"lost":{lost}' + (f',"slow":{slow}' if slow > 0 else "")
            + (f',"rated":"{_NAME[rated]}"' if rated in (1, 2) else "") + tail)


Minutes = dict[int, tuple]  # minute -> (sent, lost, down, slow, drop, rated); down: on, but not connected all minute; drop: the
#                             connection was lost; rated: the worst live rating shown in the minute (0 good/none, 1 unstable, 2 bad)
_RANK = {"good": 0, "unstable": 1, "bad": 2}
_NAME = {v: k for k, v in _RANK.items()}


def parse(text: str) -> tuple[dict[str, Minutes], dict[str, str]]:
    """A day file -> ({id: {minute: (sent, lost, down, slow)}}, {id: its last name in the file}). Repeated minutes (the daemon
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
            slow = min(int(j.get("slow", 0)), sent - lost)
            down = j.get("down") == 1
            drop = j.get("drop") == 1
            rated = _RANK.get(j.get("rated"), 0) if isinstance(j.get("rated"), str) else 0
        except (ValueError, KeyError, TypeError):
            continue
        if not (isinstance(pid, str) and pid and isinstance(name, str) and 0 <= minute < 1440 and sent >= 0 and lost >= 0
                and slow >= 0):
            continue
        day = out.setdefault(pid, {})
        s0, l0, d0, w0, x0, r0 = day.get(minute, (0, 0, True, 0, False, 0))
        day[minute] = (s0 + sent, l0 + lost, d0 and down, w0 + slow, x0 or drop, max(r0, rated))
        names[pid] = name
    return out, names


def bar_state(up_minutes: int, sent: int, lost: int, slow: int = 0) -> str:
    """off (this profile not connected), up (connected, not rated), good / unstable / bad - the connection check's rating
    (quality.rating: slow answers make a bar unstable, never bad)."""
    if up_minutes <= 0:
        return "off"
    if sent <= 0:
        return "up"
    return quality.rating(lost, slow, sent)


@dataclass(frozen=True)
class Bar:
    start: int
    state: str
    up_minutes: int
    sent: int
    lost: int
    down_minutes: int = 0             # VeroScudo on, the profile not connected
    slow: int = 0                     # answered, but over 1 s per round trip
    worst_start: int = 0              # the worst rating window in the bar (worst_end 0: none had checks)
    worst_end: int = 0
    worst_sent: int = 0
    worst_lost: int = 0
    worst_slow: int = 0
    drop_at: int = -1                 # the bar's first minute the connection was lost (VeroScudo redialed); -1: none
    rated_at: int = -1                # the live rating made the bar worse: its first minute with that rating; -1: it did not


DOWN_BAD = 2                          # a bar with this many minutes on-but-not-connected is bad (a redial that keeps failing)


@dataclass(frozen=True)
class Day:
    bars: list[Bar] = field(default_factory=list)
    vpn_minutes: int = 0              # connected
    good_pct: int | None = None       # good connected minutes out of connected + down minutes
    down_minutes: int = 0             # on, but not connected



def _worst_window(minutes: Minutes, start: int, end: int, window: int) -> tuple[int, int, int, int, int] | None:
    """The bar start..end cut into rating windows of `window` minutes (Settings > "Rate the last"; a shorter rest joins the
    last one) -> (start, end, sent, lost, slow) of the worst rated one (the earliest of equals), None: no checks. Pure."""
    w = max(1, min(window, end - start))
    n = (end - start) // w
    worst, best_key = None, None
    for k in range(n):
        a, b = start + k * w, start + (k + 1) * w if k < n - 1 else end
        sent = lost = slow = 0
        for m in range(a, b):
            v = minutes.get(m)
            if v is None or (len(v) > 2 and v[2]):
                continue
            sent += v[0]
            lost += v[1]
            slow += v[3] if len(v) > 3 else 0
        if sent > 0:
            key = (_RANK[quality.rating(lost, slow, sent)], lost / sent, (lost + slow) / sent)
            if best_key is None or key > best_key:
                worst, best_key = (a, b, sent, lost, slow), key
    return worst


def day_row(minutes: Minutes, bucket: int = BUCKET_MINUTES, until: int = 1440, window: int = 1) -> Day:
    """A day's minutes -> its bars and totals. A bar is as good as its worst rating window of `window` minutes (Settings >
    "Rate the last"): one bad minute in ten makes the bar bad. good_pct: the share of good minutes ('up' counts as good:
    the VPN worked and nothing was measured) out of the connected and the could-not-connect minutes. A bar with DOWN_BAD
    or more could-not-connect minutes is bad. Never better than the worst live rating shown in it (the status window rates the
    last minutes, which can straddle two windows here). until: today - later empty bars are 'future'. Pure."""
    bars, vpn, good, down_all = [], 0, 0, 0
    for start in range(0, 1440, bucket):
        up = down = sent = lost = slow = rated = 0
        drop_at = rated_first = -1
        for m in range(start, min(start + bucket, 1440)):
            v = minutes.get(m)
            if v is None:
                continue
            if len(v) > 5 and v[5] > rated:
                rated, rated_first = v[5], m
            if len(v) > 4 and v[4] and drop_at < 0:
                drop_at = m
            if len(v) > 2 and v[2]:
                down += 1
            else:
                up += 1
                sent += v[0]
                lost += v[1]
                slow += v[3] if len(v) > 3 else 0
        worst = _worst_window(minutes, start, min(start + bucket, 1440), window)
        state = ("future" if start >= until and up == 0 and down == 0 else "bad" if down >= DOWN_BAD or drop_at >= 0
                 else bar_state(up, *worst[2:]) if worst else bar_state(up, sent, lost, slow))
        rated_at = -1
        if state in ("up", "good", "unstable") and up and rated > _RANK.get(state, 0):
            state, rated_at = _NAME[rated], rated_first
        vpn += up
        down_all += down
        if state in ("good", "up"):
            good += up
        bars.append(Bar(start, state, up, sent, lost, down, slow, *(worst or (0, 0, 0, 0, 0)), drop_at, rated_at))
    total = vpn + down_all
    return Day(bars, vpn, round(100.0 * good / total) if total else None, down_all)


def _hm(m: int) -> str:
    return f"{m // 60:02d}:{m % 60:02d}"


def bar_text(bar: Bar, bucket: int = BUCKET_MINUTES) -> str:
    span = f"{_hm(bar.start)}-{_hm(min(bar.start + bucket, 1440))}"
    if bar.down_minutes >= DOWN_BAD:
        text = f"{span}  could not connect {bar.down_minutes} of {bucket} min (VeroScudo on)"
        text += f"; connection lost at {_hm(bar.drop_at)}" if bar.drop_at >= 0 else ""
        return text + (f"; connected {bar.up_minutes} of {bucket} min" if bar.up_minutes > 0 else "")
    if bar.state == "future":
        return span
    if bar.drop_at >= 0:
        text = f"{span}  bad – connection lost at {_hm(bar.drop_at)}, VeroScudo redialed; connected {bar.up_minutes} of {bucket} min"
        return text + (f"; {round(100.0 * bar.lost / bar.sent)} % of checks lost ({bar.lost} of {bar.sent})" if bar.sent else "")
    if bar.state == "off":
        return f"{span}  not connected"
    if bar.state == "up":
        return f"{span}  connected {bar.up_minutes} of {bucket} min – not rated (connection check off)"
    if bar.rated_at >= 0:
        whole = (f"{round(100.0 * bar.lost / bar.sent)} % lost ({bar.lost} of {bar.sent} checks), " if bar.sent else "") \
            + f"connected {bar.up_minutes} of {bucket} min"
        return f"{span}  {bar.state} – the connection check rated it {bar.state} at {_hm(bar.rated_at)}; all {bucket} min: {whole}"
    pct = round(100.0 * bar.lost / bar.sent)
    whole = (f"{pct} % lost ({bar.lost} of {bar.sent} checks), " + (f"{bar.slow} slow (over 1 s), " if bar.slow else "")
             + f"connected {bar.up_minutes} of {bucket} min")
    if bar.state in ("unstable", "bad") and bar.worst_end and bar.worst_end - bar.worst_start < min(bar.start + bucket, 1440) - bar.start:
        return (f"{span}  {bar.state} – {_hm(bar.worst_start)}-{_hm(bar.worst_end)}: {bar.worst_lost} of {bar.worst_sent} checks lost"
                + (f", {bar.worst_slow} slow (over 1 s)" if bar.worst_slow else "") + f"; all {bucket} min: {whole}")
    return f"{span}  {bar.state} – {whole}"


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


def week(state_dir: Path, pid: str, now: datetime | None = None, window: int = 1) -> list[tuple[str, Day]]:
    """The window's 7 rows for one profile (by id), today first. window: Settings > "Rate the last" (minutes)."""
    now = now or datetime.now()
    out = []
    for i in range(7):
        d = now.date() - timedelta(days=i)
        until = now.hour * 60 + now.minute + 1 if i == 0 else 1440
        out.append((day_label(d, now.date()), day_row(read_day(state_dir, d)[0].get(pid, {}), until=until, window=window)))
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
    """The daemon's side: tick(up, id, name, down=...) every pass, checks(sent, lost, id, name, slow=...) after each connection-check
    round. A minute with any up pass is up; a minute with only down passes (on, the active profile not connected) is
    written as down. Thread-safe (the watchdog and the quality thread both call it)."""

    def __init__(self, state_dir: Path) -> None:
        self.dir = stats_dir(state_dir)
        self._lock = threading.Lock()
        self._cur: dict | None = None            # {date, m, p: {id: [up, sent, lost, name, down, slow, drop, rated]}}
        self._pruned = ""
        self._was_up = ""                        # the profile seen connected since VeroScudo was last off: a down pass for it = a drop

    def _select(self, now: datetime) -> dict:
        d, m = now.date().isoformat(), now.hour * 60 + now.minute
        if not self._cur or self._cur["date"] != d or self._cur["m"] != m:
            self._save()
            self._cur = {"date": d, "m": m, "p": {}}
        return self._cur

    def _save(self) -> None:
        c = self._cur
        lines = [format_line(c["m"], pid, v[3], v[1], v[2], down=not v[0], slow=v[5], drop=v[6], rated=v[7]) for pid, v in c["p"].items() if v[0] or v[4]] \
            if c else []
        if not lines:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        with open(self.dir / f"{c['date']}.jsonl", "a") as f:
            f.write("".join(ln + "\n" for ln in lines))

    def tick(self, up: bool, pid: str, name: str, now: datetime | None = None, down: bool = False) -> None:
        """up: the profile is connected (and VeroScudo on); down: VeroScudo is on, but the profile is not connected - after it
        was connected (the same profile, VeroScudo not off in between) that is a drop. Neither: VeroScudo off."""
        now = now or datetime.now()
        with self._lock:
            c = self._select(now)
            if (up or down) and pid:
                v = c["p"].setdefault(pid, [False, 0, 0, name, False, 0, False, 0])
                v[3] = name
                if up:
                    v[0] = True
                else:
                    v[4] = True
                    v[6] = v[6] or self._was_up == pid
            self._was_up = pid if up else self._was_up if down else ""
            if self._pruned != c["date"]:
                self.prune(now)
                self._pruned = c["date"]

    def checks(self, sent: int, lost: int, pid: str, name: str, now: datetime | None = None, slow: int = 0) -> None:
        if not pid:
            return
        with self._lock:
            v = self._select(now or datetime.now())["p"].setdefault(pid, [False, 0, 0, name, False, 0, False, 0])
            v[0], v[3] = True, name
            v[1] += sent
            v[2] += lost
            v[5] += slow

    def rated(self, state: str, pid: str, name: str, now: datetime | None = None) -> None:
        """The live rating after a round (quality: over the last minutes): the minute keeps the worst one shown."""
        if not pid or state not in ("unstable", "bad"):
            return
        with self._lock:
            v = self._select(now or datetime.now())["p"].setdefault(pid, [False, 0, 0, name, False, 0, False, 0])
            v[7] = max(v[7], _RANK[state])

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
