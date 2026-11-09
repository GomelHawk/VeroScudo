"""Service status page (Settings > Connection, "Show a service status page in the status window") - shared by the Linux
and the macOS tray, the same rules as the Windows tray.

Opt-in, per user (tray.json: `statusPage`, `statusPageUrl` - saved at once, no administrator's password). An Atlassian
Statuspage summary (…/api/v2/status.json; Anthropic's by default) is fetched in a background thread every 5 minutes while
the option is on, once when it is turned on and once when the status window opens; 6 s per request. Nothing is sent but a
plain GET (no account, no key, no cookies). The status window shows it as a card under the exit location - a badge (OK, !,
!!, ?) coloured by the page's indicator, the page's name, "{description} · {HH:MM}" and a Refresh link; the Copy report gets a
Service line."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import keepawake

PREF_ON, PREF_URL = "statusPage", "statusPageUrl"
DEFAULT_URL = "https://status.anthropic.com/api/v2/status.json"
MAX_URL = 300
INTERVAL = 300.0            # seconds between two fetches while on
TIMEOUT = 6.0
BAD_URL = "The status page must be an https:// address"
ABOUT = "Atlassian Statuspage format (…/api/v2/status.json) - Anthropic's by default."
LABEL = "Show a service status page in the status window"
TONES = {"none": "good", "minor": "warn", "major": "bad", "critical": "bad"}


def url_error(url: str) -> str:
    """'' for an address that may be saved, else BAD_URL: https only, a host, at most MAX_URL characters. Pure."""
    u = (url or "").strip()
    if not u or len(u) > MAX_URL or any(c.isspace() for c in u):
        return BAD_URL
    try:
        parts = urlsplit(u)
    except ValueError:
        return BAD_URL
    return "" if parts.scheme.lower() == "https" and parts.hostname else BAD_URL


def parse(raw: bytes) -> dict | None:
    """status.json -> {name, indicator, description}, or None when it is not a Statuspage answer. Pure."""
    try:
        j = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if not isinstance(j, dict) or not isinstance(j.get("status"), dict):
        return None
    st, page = j["status"], j.get("page") if isinstance(j.get("page"), dict) else {}
    desc = str(st.get("description") or "").strip()
    if not desc:
        return None
    return {"name": str(page.get("name") or "").strip(), "indicator": str(st.get("indicator") or "").strip().lower(),
            "description": desc}


def host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url


BADGES = {"good": "OK", "warn": "!", "bad": "!!"}
BADGE_DARK_TEXT = "#141414"


@dataclass(frozen=True)
class ServiceView:
    """The status window's service card (a line like the exit location's: badge, name, grey text on the right, Refresh) and
    the Copy report's Service line (`text`)."""
    text: str
    tone: str                 # good | warn | bad | normal (traymodel.tone_colour)
    tip: str = ""
    badge: str = "?"          # OK | ! | !! | ?
    name: str = ""
    right: str = ""


def service_view(result: dict | None, url: str, checked: float | None = None, checking: bool = False) -> ServiceView:
    """The status window's service card. result: parse()'s answer, {'error': why} or None (not fetched yet); checking: a fetch
    runs right now (Refresh) - the right-hand text says so. Pure (apart from the local time zone)."""
    hhmm = time.strftime("%H:%M", time.localtime(checked)) if checked else "?"
    tip = f"checked {hhmm} from {url}"
    host = host_of(url)
    if result is None:                                    # checked after each connect and on Refresh (as the exit location)
        word = "checking..." if checking else "not checked yet"
        return ServiceView(f"{host}: {word}", "normal", f"from {url}", "?", host, word)
    if result.get("error") or not result.get("description"):
        why = str(result.get("error") or "no answer")
        return ServiceView(f"{host}: not reachable", "normal", f"{tip}\n{why}", "?", host,
                           "checking..." if checking else f"not reachable · {hhmm}")
    name = result.get("name") or host
    tone = TONES.get(str(result.get("indicator")), "normal")
    return ServiceView(f"{name}: {result['description']}", tone, tip, BADGES.get(tone, "?"), name,
                       "checking..." if checking else f"{result['description']} · {hhmm}")


def badge_colours(tone: str, dark: bool) -> tuple[str | None, str | None]:
    """The badge's (background, text) colours: the tone's colour (traymodel.tone_colour) with dark text on the bright green and
    amber of a dark theme, white on red and on the deeper colours of a light theme (dark text on them is hard to read);
    (None, None) for "?" - the exit badge's neutral background and the theme's text colour. Pure."""
    del tone, dark                                        # secondary information: always the neutral badge (as Windows)
    return None, None


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    """A redirect may lead to another https address only."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if url_error(newurl):
            raise urllib.error.HTTPError(newurl, code, "redirected to a non-https address", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "VeroScudo"})
    with urllib.request.build_opener(_HttpsOnly).open(req, timeout=timeout) as r:      # https only (url_error)
        return r.read(262144)


def fetch(url: str, get=_get, timeout: float = TIMEOUT) -> dict:
    """parse()'s answer, or {'error': why}."""
    if url_error(url):
        return {"error": BAD_URL}
    try:
        got = parse(get(url, timeout))
    except Exception as e:  # noqa: BLE001 - any network or TLS failure only means "not reachable"
        return {"error": str(e) or type(e).__name__}
    return got or {"error": "not a Statuspage answer"}


class StatusFetch:
    """One fetch at a time, in a daemon thread. The front end calls `tick` from its timer (fetches when due) and `start` when
    the status window opens or the option is turned on; `view` says what to show (None while the option is off)."""

    def __init__(self, pref=None, get=_get) -> None:
        self.pref, self._get = pref, get
        self.result: dict | None = None
        self.checked: float | None = None
        self.url_checked = ""
        self._job: dict | None = None

    def enabled(self) -> bool:
        return bool(keepawake.get_pref(PREF_ON, False, self.pref))

    def url(self) -> str:
        u = keepawake.get_pref(PREF_URL, DEFAULT_URL, self.pref)
        return u if isinstance(u, str) and not url_error(u) else DEFAULT_URL

    def set_enabled(self, on: bool) -> None:
        keepawake.set_pref(PREF_ON, bool(on), self.pref)
        if on:
            self.start()

    def set_url(self, url: str) -> str:
        """Saves the address when it is valid ('' back) - else BAD_URL and nothing is saved."""
        err = url_error(url)
        if err:
            return err
        url = url.strip()
        if url != self.url():
            keepawake.set_pref(PREF_URL, url, self.pref)
            self.result = self.checked = None
            if self.enabled():
                self.start()
        return ""

    @property
    def checking(self) -> bool:
        return self._job is not None

    def start(self, now: float | None = None) -> bool:
        if not self.enabled() or self._job is not None:
            return False
        url = self.url()
        job: dict = {"url": url, "started": time.time() if now is None else now, "result": None}

        def run() -> None:
            job["result"] = fetch(url, self._get)
        job["thread"] = threading.Thread(target=run, daemon=True, name="status-page")
        self._job = job
        job["thread"].start()
        return True

    def due(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.enabled() and self._job is None and (self.checked is None or now - self.checked >= INTERVAL)

    def poll(self, now: float | None = None) -> bool:
        """Collects a finished fetch; True when there is something new to show."""
        job = self._job
        if job is None or job["result"] is None:
            if job is not None and (time.time() if now is None else now) - job["started"] > 3 * TIMEOUT:
                self._job, self.result, self.checked = None, {"error": f"no answer within {TIMEOUT:g} s"}, job["started"]
                self.url_checked = job["url"]
                return True
            return False
        self._job = None
        self.result, self.url_checked = job["result"], job["url"]
        self.checked = time.time() if now is None else now
        return True

    def tick(self, now: float | None = None) -> bool:
        """The tray's timer: collects a finished fetch. No fetch of its own: the same rules as the exit location - once after
        each connect (on_connected) and on Refresh. True when the view changed."""
        return self.poll(now)

    def on_connected(self) -> bool:
        """VeroScudo reached Protected (a connect, a reconnect, a switch): look again, through the new tunnel."""
        return self.start()

    def view(self) -> ServiceView | None:
        if not self.enabled():
            return None
        url = self.url()
        if self.result is None or self.url_checked != url:
            return service_view(None, url, checking=self.checking)
        return service_view(self.result, url, self.checked, self.checking)

    def refresh(self) -> bool:
        """The card's Refresh link: a fetch now (unless one already runs or the option is off)."""
        return self.start()
