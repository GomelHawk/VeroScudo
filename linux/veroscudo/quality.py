"""Connection quality: optional checks through the tunnel while protected (Settings > Connection, config `connectionCheck`).

Same rules on every platform (Windows: Core/66-Quality.ps1, docs/ARCHITECTURE.md "Connection check"):
- every `intervalSeconds` (10-100) the guard checks each address once: ping, a TCP connection to a port, or HTTPS (a TLS
  handshake and a HEAD request - any HTTP answer counts; no account or key is ever sent);
- an answer slower than 1000 ms per round trip is "slow" (ping and TCP: 1 round trip, a TLS handshake 2, HTTPS 3);
- every check counts: loss = failed checks / all checks in the last `windowMinutes` (1-10), never fewer than 3 rounds;
- below 10 % lost: good; 10-50 %: unstable; above 50 %: bad. Slow answers count like partial loss: 10 % or more lost or
  slow together makes a good connection unstable - never bad (it still answers);
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
import ssl
import statistics
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

INTERVAL_RANGE = (10, 100)            # seconds between two rounds
WINDOW_RANGE = (1, 10)                # minutes the rating looks back
MAX_TARGETS = 3
MIN_CHECKS = 3                        # fewer: "checking"
METHODS = ("ping", "tcp", "https")
PORT_METHODS = ("tcp", "https")       # the methods with a port
TIMEOUT = 3.0                         # one check; a round runs its checks in parallel
TLS_TIMEOUT = 5.0                     # a TLS check through a proxy (Hiddify) needs a few round trips more
GOOD_BELOW, BAD_ABOVE = 10.0, 50.0    # loss %, see the module doc
SLOW_MS = 1000                        # per round trip: a slower answer is "slow" (see the module doc)
DEFAULT_HOST = "1.1.1.1"


@dataclass(frozen=True)
class Target:
    host: str
    method: str = "tcp"               # ping | tcp | https
    port: int = 443                   # tcp and https

    def label(self) -> str:
        if self.method == "ping":
            return f"{self.host} (ping)"
        if self.method == "https":
            return f"{self.host} (HTTPS)" if self.port == 443 else f"{self.host}:{self.port} (HTTPS)"
        return f"{self.host}:{self.port}"


DEFAULT_TARGET = Target(DEFAULT_HOST, "tcp", 443)


@dataclass(frozen=True)
class CheckConfig:
    enabled: bool = False
    interval_seconds: int = 10
    window_minutes: int = 1
    targets: tuple[Target, ...] = (DEFAULT_TARGET,)

    def to_json(self) -> dict:
        return {"enabled": self.enabled, "intervalSeconds": self.interval_seconds, "windowMinutes": self.window_minutes,
                "targets": [{"host": t.host, "method": t.method} | ({"port": t.port} if t.method in PORT_METHODS else {})
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
        raise ValueError("config.json: connectionCheck must be an object")  # noqa: TRY004 - a config error is a ValueError everywhere (`veroscudo set` and the loaders catch ValueError)
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("config.json: connectionCheck.enabled must be true or false")  # noqa: TRY004 - a config error is a ValueError everywhere (`veroscudo set` and the loaders catch ValueError)
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
            raise ValueError("config.json: each connectionCheck target must be an object {host, method, port}")  # noqa: TRY004 - a config error is a ValueError everywhere (`veroscudo set` and the loaders catch ValueError)
        host = str(t.get("host") or "").strip()
        if not host or not is_host(host):
            raise ValueError(f"config.json: invalid connectionCheck host {host!r}")
        method = str(t.get("method", "tcp")).lower()
        if method not in METHODS:
            raise ValueError("config.json: connectionCheck method must be 'ping', 'tcp' or 'https'")
        port = 0
        if method in PORT_METHODS:
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
    empty others are dropped; a URL or host:port gives its host (and, for TCP and HTTPS, its port when the port field was
    left at its default). Raises ValueError with a message for the user. Pure (the same rules as Windows' ConvertFrom-VeroCheckForm)."""
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
            raise ValueError(f"Address {i + 1}: choose Ping, TCP port or HTTPS.")
        p = int(port or 443)
        if method in PORT_METHODS and url_port and p == 443:
            p = url_port
        if method in PORT_METHODS and not 1 <= p <= 65535:
            raise ValueError(f"Address {i + 1}: the port must be 1-65535.")
        targets.append(Target(host, method, p if method in PORT_METHODS else 443))
    return CheckConfig(bool(enabled), interval, window, tuple(targets) or (DEFAULT_TARGET,))


# ---------------------------------------------------------------- the rating (pure)
@dataclass(frozen=True)
class Quality:
    state: str                        # checking | good | unstable | bad
    loss_pct: float = 0.0
    rtt_ms: int | None = None
    checks: int = 0
    lost: int = 0
    targets: tuple[tuple[str, int, int], ...] = ()     # per address in the window: (label, checks, lost)
    slow: int = 0                     # answered, but slower than SLOW_MS per round trip

    def slow_pct(self) -> float:
        return round(100.0 * self.slow / self.checks, 1) if self.checks else 0.0


def window_seconds(cfg: CheckConfig) -> float:
    """The look-back: windowMinutes, but never fewer than MIN_CHECKS rounds (100 s rounds in a 1 minute window)."""
    # no "+1": with 20 s rounds and 1 minute it made 61 s, and the first rating came only with the round at 80 s
    return max(cfg.window_minutes * 60.0, MIN_CHECKS * cfg.interval_seconds * 1.0)


def rating(lost: int, slow: int, checks: int) -> str:
    """good / unstable / bad from the counts (checks > 0): see the module doc. Pure; the statistics' bars use it too."""
    loss = 100.0 * lost / checks
    if loss > BAD_ABOVE:
        return "bad"
    return "unstable" if loss >= GOOD_BELOW or 100.0 * (lost + slow) / checks >= GOOD_BELOW else "good"


def rate(samples, now: float, window_s: float, since: float | None = None) -> Quality:
    """samples: (time, ok, rtt_ms or None[, target index[, slow]]), one per check. since: when the rating started - until a full window has passed
    the answer is "checking". Pure."""
    recent = [s for s in samples if now - s[0] <= window_s]
    n = len(recent)
    if n < MIN_CHECKS or (since is not None and now - since < window_s):
        return Quality("checking", checks=n, lost=sum(1 for s in recent if not s[1]))
    lost = sum(1 for s in recent if not s[1])
    slow = sum(1 for s in recent if s[1] and len(s) > 4 and s[4])
    loss = 100.0 * lost / n
    rtts = [s[2] for s in recent if s[1] and s[2] is not None]
    rtt = round(statistics.median(rtts)) if rtts else None
    return Quality(rating(lost, slow, n), round(loss, 1), rtt, n, lost, slow=slow)


def per_target(samples, targets, now: float, window_s: float) -> tuple[tuple[str, int, int], ...]:
    """The rating window per address: ((label, checks, lost), ...) in the order of `targets` (samples carry the address's
    index as their 4th item). Pure."""
    counts = [[0, 0] for _ in targets]
    for s in samples:
        if len(s) > 3 and 0 <= s[3] < len(counts) and now - s[0] <= window_s:
            counts[s[3]][0] += 1
            counts[s[3]][1] += 0 if s[1] else 1
    return tuple((t.label(), c[0], c[1]) for t, c in zip(targets, counts))


def describe(q: Quality) -> str:
    """'good · 45 ms', 'unstable · 23% lost', 'unstable · 40% slow, 1450 ms', 'unstable · 12% lost, 30% slow',
    'checking…' - the short text of the tray. Pure."""
    if q.state == "checking":
        return "checking…"
    if q.state == "good":
        return f"good · {q.rtt_ms} ms" if q.rtt_ms is not None else "good"
    if q.slow and not q.lost:
        return f"{q.state} · {q.slow_pct():g}% slow" + (f", {q.rtt_ms} ms" if q.rtt_ms is not None else "")
    return f"{q.state} · {q.loss_pct:g}% lost" + (f", {q.slow_pct():g}% slow" if q.slow else "")


# ---------------------------------------------------------------- the checks (impure)
_PING_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


def _ping_argv(host: str) -> list[str]:
    six = ":" in host
    if sys.platform == "darwin":
        return ["ping6" if six else "ping", "-n", "-c", "1", *([] if six else ["-t", str(int(TIMEOUT))]), host]
    return ["ping", "-6" if six else "-4", "-n", "-c", "1", "-W", str(int(TIMEOUT)), host]


HEAD_REQUEST = "HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: VeroScudo\r\nConnection: close\r\n\r\n"


def _first_line(sock, limit: int = 1024) -> bytes:
    data = b""
    while b"\n" not in data and len(data) < limit:
        chunk = sock.recv(limit - len(data))
        if not chunk:
            break
        data += chunk
    return data.split(b"\n", 1)[0]


def _https(t: Target, start: float) -> bool:
    """TCP connect, TLS handshake (the system's trust store, the host's name) and a HEAD request: answered when the first
    line of the answer starts with HTTP/ - any status counts (a 403 or 404 still proves the way to the service works).
    A certificate that fails verification proves the server answered too (then without the HTTP part). Never sends
    credentials: no cookies, no Authorization header, no body."""
    ctx = ssl.create_default_context()
    host = t.host.strip("[]")
    try:
        with socket.create_connection((host, t.port), timeout=TLS_TIMEOUT) as raw:
            raw.settimeout(max(0.5, TLS_TIMEOUT - (time.monotonic() - start)))
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                name = f"[{host}]" if ":" in host else host
                s.sendall(HEAD_REQUEST.format(host=name).encode("ascii", errors="replace"))
                return _first_line(s).startswith(b"HTTP/")
    except ssl.SSLCertVerificationError:
        return True                                               # the server answered with its certificate
    except (OSError, ValueError):                                 # ssl.SSLError is an OSError: closed, reset, garbage
        return False


def round_trips(t: Target, tls: bool = False) -> int:
    """How many round trips a check takes: ping and TCP 1, a TLS handshake 2 (TCP + TLS 1.3), HTTPS 3 (+ the request). Pure."""
    if t.method == "https":
        return 3
    return 2 if tls else 1


def judge(t: Target, result: tuple[bool, int | None], tls: bool = False) -> tuple[bool, int | None, bool]:
    """(answered, ms) -> (answered, ms, slow): slow = answered, but slower than SLOW_MS per round trip. Pure."""
    ok, ms = result
    return ok, ms, bool(ok and ms is not None and ms > SLOW_MS * round_trips(t, tls))


def check(t: Target, tls: bool = False) -> tuple[bool, int | None, bool]:
    """One check, judged: (answered, its time in ms, slow) - see _check and judge."""
    return judge(t, _check(t, tls), tls)


def _check(t: Target, tls: bool = False) -> tuple[bool, int | None]:
    """One check: (answered, round trip in ms). https: see _https. tls (Hiddify profiles): a TLS handshake on the target's
    TCP port (443 for a ping target) instead of ping/TCP - Hiddify's TUN answers pings and completes TCP handshakes itself,
    locally, also when none of its servers works (<1 ms to a fake-DNS address); only a real server
    answers a TLS handshake. HTTPS targets stay HTTPS. A certificate that does not match still proves the server
    answered; a closed or reset connection does not."""
    start = time.monotonic()
    if t.method == "https":
        ok = _https(t, start)
        return (True, round((time.monotonic() - start) * 1000)) if ok else (False, None)
    if tls:
        port = 443 if t.method == "ping" else t.port
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((t.host, port), timeout=TLS_TIMEOUT) as raw:
                raw.settimeout(max(0.5, TLS_TIMEOUT - (time.monotonic() - start)))
                with ctx.wrap_socket(raw, server_hostname=t.host):
                    pass
        except ssl.SSLCertVerificationError:
            pass                                                  # the server answered with its certificate
        except (OSError, ValueError):                             # ssl.SSLError is an OSError: closed, reset, garbage
            return False, None
        return True, round((time.monotonic() - start) * 1000)
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


def run_round(targets, tls: bool = False) -> list[tuple[bool, int | None, bool]]:
    """Every address once, in parallel (a round takes at most TIMEOUT, not TIMEOUT per address). tls: see check()."""
    out: list = [(False, None, False)] * len(targets)
    slow = tls or any(t.method == "https" for t in targets)    # a TLS handshake needs a few round trips more

    def one(i: int, t: Target) -> None:
        out[i] = check(t, tls)

    threads = [threading.Thread(target=one, args=(i, t), daemon=True) for i, t in enumerate(targets)]
    for th in threads:
        th.start()
    for th in threads:
        th.join((TLS_TIMEOUT if slow else TIMEOUT) + 3)
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

    def add_round(self, cfg: CheckConfig, profile: str, results, now: float | None = None, down_at: float = 0.0) -> Quality:
        """down_at: when the kill-switch last blocked (StateStore.last_down): a Reconnect between two rounds is a new
        connection too, although no round saw it down (otherwise "unstable" one second after a Reconnect)."""
        now = time.time() if now is None else now
        key = (profile, cfg.interval_seconds, cfg.window_minutes, cfg.targets)
        if key != self.key or down_at > self.started:        # new connection, other profile or other rules: start over
            self.samples.clear()
            self.key, self.started, self.last_state = key, now, ""
        for i, (ok, rtt, *rest) in enumerate(results):         # (ok, rtt[, slow])
            self.samples.append((now, ok, rtt, i, bool(rest and rest[0])))   # i: the address (per-address counts in quality.json)
        q = replace(rate(self.samples, now, window_seconds(cfg), since=self.started),
                    targets=per_target(self.samples, cfg.targets, now, window_seconds(cfg)))
        write(self.path, q, cfg, profile, now)
        return q


def write(path: Path, q: Quality, cfg: CheckConfig, profile: str, now: float) -> None:
    data = {"profile": profile, "state": q.state, "lossPct": q.loss_pct, "rttMs": q.rtt_ms, "checks": q.checks, "lost": q.lost,
            "slow": q.slow, "intervalSeconds": cfg.interval_seconds, "windowMinutes": cfg.window_minutes, "updated": now,
            "targets": [{"label": label, "checks": n, "lost": k} for label, n, k in q.targets]}
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
        raw = j.get("targets")
        targets = tuple((str(t.get("label", "")), int(t.get("checks", 0)), int(t.get("lost", 0)))
                        for t in (raw if isinstance(raw, list) else []) if isinstance(t, dict))
        return Quality(str(j.get("state", "checking")), float(j.get("lossPct", 0)), int(rtt) if rtt is not None else None,
                       int(j.get("checks", 0)), int(j.get("lost", 0)), targets, int(j.get("slow", 0)))
    except (TypeError, ValueError):
        return None
