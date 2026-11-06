"""Exit location: where your traffic leaves the tunnel (Settings > Behaviour, "Show exit location") - shared by the Linux
and the macOS tray, the same rules as the Windows tray (VeroScudoTray.ps1, ConvertTo-VeroExitView in VeroScudo.Tray.psm1).

Asked only right after VeroScudo reaches Protected (connect, reconnect, switch) or when you click Refresh - so the request
goes through the tunnel and never shows your real address. ipinfo.io first (city, country, IP, provider), Cloudflare's
trace page as the fallback (IP and country only); 6 s per request, given up after 20 s. In a background thread: the
window never waits for the network. Cached per user in tray.json (`exitInfo`); shown grey with its time while not
protected or for another profile."""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import keepawake
from .countries import country_name

IPINFO_URL = "https://ipinfo.io/json"
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
TIMEOUT = 6.0               # one request
GIVE_UP = 20.0              # the whole lookup
NOT_PROTECTED = "checked only while the VPN is connected (Protected)"


# ---------------------------------------------------------------- the lookup
def parse_ipinfo(raw: bytes) -> dict | None:
    """ipinfo.io/json -> {ip, city, country, org, source}, or None without an IP. Decoded as UTF-8 (city names are not
    ASCII: the Windows tray once showed a Polish city garbled when the answer was read as Latin-1). Pure."""
    try:
        j = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if not isinstance(j, dict) or not j.get("ip"):
        return None
    return {"ip": str(j["ip"]), "city": str(j.get("city") or ""), "country": str(j.get("country") or ""),
            "org": str(j.get("org") or ""), "source": "ipinfo.io"}


def parse_trace(raw: bytes) -> dict | None:
    """Cloudflare's trace page (key=value lines) -> {ip, city '', country (loc), org '', source}, or None. Pure."""
    kv = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        k, sep, v = line.partition("=")
        if sep and v.strip():
            kv[k.strip()] = v.strip()
    if not kv.get("ip"):
        return None
    return {"ip": kv["ip"], "city": "", "country": kv.get("loc", ""), "org": "", "source": "cloudflare.com"}


def _get(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "VeroScudo"})
    with urllib.request.urlopen(req, timeout=timeout) as r:      # fixed https URLs only
        return r.read(65536)


def lookup(get=_get, timeout: float = TIMEOUT) -> dict:
    """ipinfo.io, then Cloudflare: {ip, city, country, org, source}, or {error} naming why both failed."""
    errors = []
    for url, parse, name in ((IPINFO_URL, parse_ipinfo, "ipinfo.io"), (TRACE_URL, parse_trace, "cloudflare.com")):
        try:
            got = parse(get(url, timeout))
            if got:
                return got
            errors.append(f"{name}: no address in the answer")
        except Exception as e:  # noqa: BLE001 - any network or TLS failure only means "not available"
            errors.append(f"{name}: {e}")
    return {"error": " / ".join(errors)}


class ExitFetch:
    """One lookup at a time, in a daemon thread. The front end calls `start` (on reaching Protected, on Refresh) and `poll`
    from its timer; a finished lookup is saved to tray.json (`exitInfo`). A lookup that takes over GIVE_UP seconds is
    abandoned: its thread may still finish, but its answer is ignored (it could come from a tunnel that is gone)."""

    def __init__(self, pref: Path | None = None, get=_get) -> None:
        self.pref, self._get = pref, get
        self.failure = ""
        self._job: dict | None = None

    @property
    def checking(self) -> bool:
        return self._job is not None

    def enabled(self) -> bool:
        return bool(keepawake.get_pref("showExit", True, self.pref))

    def info(self) -> dict | None:
        c = keepawake.get_pref("exitInfo", None, self.pref)
        return c if isinstance(c, dict) else None

    def start(self, profile: str, now: float | None = None) -> bool:
        if not self.enabled() or self._job is not None or not profile:
            return False
        job: dict = {"profile": profile, "started": time.time() if now is None else now, "result": None}
        self.failure = ""

        def run() -> None:
            job["result"] = lookup(self._get)
        job["thread"] = threading.Thread(target=run, daemon=True, name="exit-location")
        self._job = job
        job["thread"].start()
        return True

    def poll(self, now: float | None = None) -> bool:
        """Collects a finished lookup (or gives up); True when something changed that the window should show."""
        job = self._job
        if job is None:
            return False
        now = time.time() if now is None else now
        r = job["result"]
        if r is None:
            if now - job["started"] > GIVE_UP:
                self._job, self.failure = None, f"no answer within {GIVE_UP:g} s"
                return True
            return False
        self._job = None
        if r.get("ip"):
            keepawake.set_pref("exitInfo", {**{k: r.get(k, "") for k in ("ip", "city", "country", "org", "source")},
                                            "profile": job["profile"],
                                            "time": datetime.fromtimestamp(now).astimezone().isoformat(timespec="seconds")},
                               self.pref)
        else:
            self.failure = str(r.get("error") or "no answer")
        return True


# ---------------------------------------------------------------- what the line shows
@dataclass(frozen=True)
class ExitView:
    has: bool                 # a location to show (else `text` says why not)
    text: str = ""
    code: str = ""            # 'PL' - the badge
    place: str = ""           # 'Poland / Example City'
    right: str = ""           # the IP, or 'IP - HH:MM' when not fresh, or 'checking...'
    fresh: bool = False       # looked up through the tunnel that is up now: normal colour; else grey
    tip: str = ""


def _parse_time(text: str) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(text))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.astimezone()


def exit_view(info: dict | None, state: str, profile: str, protected_since: float = 0.0, checking: bool = False,
              failure: str = "", preview: bool = False) -> ExitView:
    """The exit-location line - ConvertTo-VeroExitView of the Windows tray. Fresh = looked up through the tunnel that is
    up now (protected, same profile, after it came up); otherwise grey with its time. `preview`: screenshots (always
    fresh). Pure."""
    c = info if isinstance(info, dict) else {}
    if not c.get("ip"):
        if checking:
            msg = "Checking where your traffic leaves..."
        elif failure:
            msg = f"Location not available - {failure}"
        else:
            msg = "Location: shown once the VPN is connected"
        return ExitView(False, msg)
    t = _parse_time(c.get("time", ""))
    ts = t.timestamp() if t else 0.0
    fresh = state == "protected" and bool(profile) and str(c.get("profile", "")) == profile and (preview or ts >= protected_since)
    code = str(c.get("country", ""))
    place = " / ".join(x for x in (country_name(code), str(c.get("city", ""))) if x)
    hhmm = t.astimezone().strftime("%H:%M") if t else "?"
    right = "checking..." if checking else (str(c["ip"]) if fresh else f"{c['ip']} - {hhmm}")
    when = t.astimezone().strftime("%Y-%m-%d %H:%M") if t else "?"
    tip = f"{c['ip']}  {c.get('org', '')}".rstrip() + f"\nfrom {c.get('source', '')}, {when}, profile {c.get('profile', '')}"
    return ExitView(True, "", code.upper(), place, right, fresh, tip)


def report_line(xv: ExitView) -> str:
    """The Copy report's Exit line: 'PL Poland / Example City 203.0.113.25', or why there is none. Pure."""
    return f"{xv.code} {xv.place} {xv.right}" if xv.has else xv.text
