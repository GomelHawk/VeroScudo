"""Connection quality: optional checks through the tunnel while protected (Settings > Connection, config `connectionCheck`).

Same rules on every platform (Windows: Core/66-Quality.ps1, docs/ARCHITECTURE.md "Connection check"):
- every `intervalSeconds` (10-100) the guard checks each address once: ping, or a TCP connection to a port;
- every check counts: loss = failed checks / all checks in the last `windowMinutes` (1-10), never fewer than 3 rounds;
- below 10 % lost: good; 10-50 %: unstable; above 50 %: bad;
- no rating ("checking") until one full window has passed since the rating started: it starts over on every connect,
  profile switch and change of the check settings (interval, window, addresses) - an early rating of a connection that
  has just come up is not one to trust.
The checks run only while the VPN is on and connected, so they go through the tunnel like all other traffic; nothing in
the kill-switch is opened for them. The guard writes the result to quality.json; the tray only reads it."""
from __future__ import annotations

import json
import os
import re
import socket
import statistics
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

INTERVAL_RANGE = (10, 100)            # seconds between two rounds
WINDOW_RANGE = (1, 10)                # minutes the rating looks back
MAX_TARGETS = 3
MIN_CHECKS = 3                        # fewer: "checking"
METHODS = ("ping", "tcp")
TIMEOUT = 3.0                         # one check; a round runs its checks in parallel
GOOD_BELOW, BAD_ABOVE = 10.0, 50.0    # loss %, see the module doc
DEFAULT_HOST = "1.1.1.1"


@dataclass(frozen=True)
class Target:
    host: str
    method: str = "tcp"               # ping | tcp
    port: int = 443                   # tcp only

    def label(self) -> str:
        return f"{self.host} (ping)" if self.method == "ping" else f"{self.host}:{self.port}"


DEFAULT_TARGET = Target(DEFAULT_HOST, "tcp", 443)


@dataclass(frozen=True)
class CheckConfig:
    enabled: bool = False
    interval_seconds: int = 10
    window_minutes: int = 1
    targets: tuple[Target, ...] = (DEFAULT_TARGET,)

    def to_json(self) -> dict:
        return {"enabled": self.enabled, "intervalSeconds": self.interval_seconds, "windowMinutes": self.window_minutes,
                "targets": [{"host": t.host, "method": t.method} | ({"port": t.port} if t.method == "tcp" else {})
                            for t in self.targets]}


def split_address(text: str) -> tuple[str, int | None]:
    """What the user typed (IP, host name, host:port or URL) -> (host, port or None). Pure; no validation of the host."""
    s = (text or "").strip()
    if not s:
        return "", None
    if "://" in s:
        u = urlsplit(s)
        try:
            port = u.port
        except ValueError:
            port = None
        if port is None:
            port = {"https": 443, "http": 80}.get(u.scheme.lower())
        return (u.hostname or ""), port
    if s.startswith("[") and "]" in s:                      # [IPv6]:port
        host, _, rest = s[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    if s.count(":") == 1:
        host, _, port = s.partition(":")
        return host, int(port) if port.isdigit() else None
    return s.split("/")[0], None


def parse(raw: object, is_host) -> CheckConfig:
    """config.json's `connectionCheck` -> CheckConfig. Missing = off with the defaults. Raises ValueError. `is_host` is
    config.py's host check (passed in: no import cycle). An empty target list falls back to 1.1.1.1 - there is always one."""
    if raw is None:
        return CheckConfig()
    if not isinstance(raw, dict):
        raise ValueError("config.json: connectionCheck must be an object")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("config.json: connectionCheck.enabled must be true or false")
    try:
        interval = int(raw.get("intervalSeconds", 10))
        window = int(raw.get("windowMinutes", 1))
    except (TypeError, ValueError):
        raise ValueError("config.json: connectionCheck.intervalSeconds / windowMinutes must be numbers") from None
    if not INTERVAL_RANGE[0] <= interval <= INTERVAL_RANGE[1]:
        raise ValueError(f"config.json: connectionCheck.intervalSeconds must be {INTERVAL_RANGE[0]}-{INTERVAL_RANGE[1]}")
    if not WINDOW_RANGE[0] <= window <= WINDOW_RANGE[1]:
        raise ValueError(f"config.json: connectionCheck.windowMinutes must be {WINDOW_RANGE[0]}-{WINDOW_RANGE[1]}")
    raw_targets = raw.get("targets") or []
    if not isinstance(raw_targets, list) or len(raw_targets) > MAX_TARGETS:
        raise ValueError(f"config.json: connectionCheck.targets must be a list of at most {MAX_TARGETS}")
    targets = []
    for t in raw_targets:
        if not isinstance(t, dict):
            raise ValueError("config.json: each connectionCheck target must be an object {host, method, port}")
        host = str(t.get("host") or "").strip()
        if not host or not is_host(host):
            raise ValueError(f"config.json: invalid connectionCheck host {host!r}")
        method = str(t.get("method", "tcp")).lower()
        if method not in METHODS:
            raise ValueError("config.json: connectionCheck method must be 'ping' or 'tcp'")
        port = 0
        if method == "tcp":
            try:
                port = int(t.get("port", 443))
            except (TypeError, ValueError):
                port = 0
            if not 1 <= port <= 65535:
                raise ValueError(f"config.json: connectionCheck port must be 1-65535 ({host})")
        targets.append(Target(host, method, port or 443))
    return CheckConfig(enabled, interval, window, tuple(targets) or (DEFAULT_TARGET,))


def from_form(enabled: bool, interval: int, window: int, rows, is_host) -> CheckConfig:
    """Settings > Connection -> CheckConfig. rows: up to 3 (text, method, port). An empty first address becomes 1.1.1.1;
    empty others are dropped; a URL or host:port gives its host (and, for TCP, its port when the port field was left at
    its default). Raises ValueError with a message for the user. Pure (the same rules as Windows' ConvertFrom-VeroCheckForm)."""
    interval = min(max(int(interval), INTERVAL_RANGE[0]), INTERVAL_RANGE[1])
    window = min(max(int(window), WINDOW_RANGE[0]), WINDOW_RANGE[1])
    targets = []
    for i, (text, method, port) in enumerate(list(rows)[:MAX_TARGETS]):
        host, url_port = split_address(text)
        if not host:
            if i == 0:
                host = DEFAULT_HOST
            else:
                continue
        if not is_host(host):
            raise ValueError(f"Address {i + 1}: '{text.strip()}' is not an IP address, host name or URL.")
        method = (method or "tcp").lower()
        if method not in METHODS:
            raise ValueError(f"Address {i + 1}: choose Ping or TCP.")
        p = int(port or 443)
        if method == "tcp" and url_port and p == 443:
            p = url_port
        if method == "tcp" and not 1 <= p <= 65535:
            raise ValueError(f"Address {i + 1}: the port must be 1-65535.")
        targets.append(Target(host, method, p if method == "tcp" else 443))
    return CheckConfig(bool(enabled), interval, window, tuple(targets) or (DEFAULT_TARGET,))


# ---------------------------------------------------------------- the rating (pure)
@dataclass(frozen=True)
class Quality:
    state: str                        # checking | good | unstable | bad
    loss_pct: float = 0.0
    rtt_ms: int | None = None
    checks: int = 0
    lost: int = 0


def window_seconds(cfg: CheckConfig) -> float:
    """The look-back: windowMinutes, but never fewer than MIN_CHECKS rounds (100 s rounds in a 1 minute window)."""
    return max(cfg.window_minutes * 60.0, MIN_CHECKS * cfg.interval_seconds + 1.0)


def rate(samples, now: float, window_s: float, since: float | None = None) -> Quality:
    """samples: (time, ok, rtt_ms or None), one per check. since: when the rating started - until a full window has passed
    the answer is "checking". Pure."""
    recent = [s for s in samples if now - s[0] <= window_s]
    n = len(recent)
    if n < MIN_CHECKS or (since is not None and now - since < window_s):
        return Quality("checking", checks=n, lost=sum(1 for s in recent if not s[1]))
    lost = sum(1 for s in recent if not s[1])
    loss = 100.0 * lost / n
    rtts = [s[2] for s in recent if s[1] and s[2] is not None]
    rtt = round(statistics.median(rtts)) if rtts else None
    state = "good" if loss < GOOD_BELOW else ("bad" if loss > BAD_ABOVE else "unstable")
    return Quality(state, round(loss, 1), rtt, n, lost)


def describe(q: Quality) -> str:
    """'good · 45 ms', 'unstable · 23% lost', 'checking…' - the short text of the tray. Pure."""
    if q.state == "checking":
        return "checking…"
    if q.state == "good":
        return f"good · {q.rtt_ms} ms" if q.rtt_ms is not None else "good"
    return f"{q.state} · {q.loss_pct:g}% lost"


# ---------------------------------------------------------------- the checks (impure)
_PING_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


def _ping_argv(host: str) -> list[str]:
    six = ":" in host
    if sys.platform == "darwin":
        return ["ping6" if six else "ping", "-n", "-c", "1", *([] if six else ["-t", str(int(TIMEOUT))]), host]
    return ["ping", "-6" if six else "-4", "-n", "-c", "1", "-W", str(int(TIMEOUT)), host]


def check(t: Target) -> tuple[bool, int | None]:
    """One check: (answered, round trip in ms)."""
    start = time.monotonic()
    if t.method == "ping":
        try:
            r = subprocess.run(_ping_argv(t.host), capture_output=True, text=True, timeout=TIMEOUT + 2, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return False, None
        if r.returncode != 0:
            return False, None
        m = _PING_TIME.search(r.stdout)
        return True, round(float(m.group(1))) if m else round((time.monotonic() - start) * 1000)
    try:
        with socket.create_connection((t.host, t.port), timeout=TIMEOUT):
            return True, round((time.monotonic() - start) * 1000)
    except OSError:
        return False, None


def run_round(targets) -> list[tuple[bool, int | None]]:
    """Every address once, in parallel (a round takes at most TIMEOUT, not TIMEOUT per address)."""
    out: list = [(False, None)] * len(targets)

    def one(i: int, t: Target) -> None:
        out[i] = check(t)

    threads = [threading.Thread(target=one, args=(i, t), daemon=True) for i, t in enumerate(targets)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(TIMEOUT + 3)
    return out


@dataclass
class Monitor:
    """The guard's side: keeps the samples of the current connection, rates them, writes quality.json for the tray."""
    path: Path
    samples: deque = field(default_factory=lambda: deque(maxlen=10 * 60 // INTERVAL_RANGE[0] * MAX_TARGETS + 10))
    key: tuple | None = None          # (profile, the check settings) the samples belong to
    started: float = 0.0              # when this rating started (first round after a connect / switch / settings change)
    last_state: str = ""

    def reset(self) -> None:
        self.samples.clear()
        self.key, self.last_state = None, ""
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass

    def add_round(self, cfg: CheckConfig, profile: str, results, now: float | None = None) -> Quality:
        now = time.time() if now is None else now
        key = (profile, cfg.interval_seconds, cfg.window_minutes, cfg.targets)
        if key != self.key:                                  # new connection, other profile or other rules: start over
            self.samples.clear()
            self.key, self.started, self.last_state = key, now, ""
        for ok, rtt in results:
            self.samples.append((now, ok, rtt))
        q = rate(self.samples, now, window_seconds(cfg), since=self.started)
        write(self.path, q, cfg, profile, now)
        return q


def write(path: Path, q: Quality, cfg: CheckConfig, profile: str, now: float) -> None:
    data = {"profile": profile, "state": q.state, "lossPct": q.loss_pct, "rttMs": q.rtt_ms, "checks": q.checks, "lost": q.lost,
            "intervalSeconds": cfg.interval_seconds, "windowMinutes": cfg.window_minutes, "updated": now}
    tmp = path.with_suffix(".json.new")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(data))
        os.chmod(tmp, 0o644)                                 # the tray (the user) reads it
        os.replace(tmp, path)
    except OSError:
        pass


def read(path: Path, profile: str, now: float | None = None) -> Quality | None:
    """The tray's side: the last rating of `profile`, or None (no file, another profile, or too old to trust)."""
    now = time.time() if now is None else now
    try:
        j = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(j, dict) or j.get("profile") != profile:
        return None
    try:
        age = now - float(j.get("updated", 0))
        if age > max(3 * int(j.get("intervalSeconds", 10)), 30) or age < -60:
            return None
        rtt = j.get("rttMs")
        return Quality(str(j.get("state", "checking")), float(j.get("lossPct", 0)), int(rtt) if rtt is not None else None,
                       int(j.get("checks", 0)), int(j.get("lost", 0)))
    except (TypeError, ValueError):
        return None
