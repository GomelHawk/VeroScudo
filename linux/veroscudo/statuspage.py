"""Service status page (Settings > Connection, "Show a service status page in the status window") - shared by the Linux
and the macOS tray, the same rules as the Windows tray.

Opt-in, per user (tray.json: `statusPage`, `statusPageUrl` - saved at once, no administrator's password). An Atlassian
Statuspage summary (…/api/v2/status.json; Claude's by default) is fetched in a background thread once after each connect,
when the option is turned on and on Refresh; 6 s per request. A fetch after a connect that fails is retried after 10 s and
30 s ("checking..." meanwhile) - a tunnel that has just come up may not carry traffic yet; when the retries fail too, the
last good answer stays shown with its time (the failure in the tooltip), like the exit location. A failed Refresh shows
"not reachable" - you asked for a fresh answer. Nothing is sent but a
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
DEFAULT_URL = "https://status.claude.com/api/v2/status.json"
OLD_DEFAULT = "https://status.anthropic.com/api/v2/status.json"   # redirects to DEFAULT_URL (an extra round trip): read as it
RETRY_AFTER = (10.0, 30.0)  # a failed fetch after a connect: tried again after these seconds
MAX_URL = 300
INTERVAL = 300.0            # seconds between two fetches while on
TIMEOUT = 6.0
BAD_URL = "The status page must be an https:// address"
ABOUT = "Atlassian Statuspage format (…/api/v2/status.json) - Claude's by default."
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


def service_view(result: dict | None, url: str, checked: float | None = None, checking: bool = False,
                 failed: str = "") -> ServiceView:
    """The status window's service card. result: parse()'s answer, {'error': why} or None (not fetched yet); checking: a fetch
    runs right now or a retry is due - the right-hand text says so; failed: a later check failed while `result` (an older
    good answer) stays shown - it goes into the tooltip. Pure (apart from the local time zone)."""
    hhmm = time.strftime("%H:%M", time.localtime(checked)) if checked else "?"
    tip = f"checked {hhmm} from {url}" + (f"\nlater check failed: {failed}" if failed else "")
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
        self.failed = ""                  # an automatic check failed while an older good answer stays shown
        self._good: tuple[dict, float, str] | None = None     # the last good answer: (result, time, url)
        self._retry: list[float] = []     # the retries left of the current automatic check
        self._retry_at: float | None = None
        self._job: dict | None = None

    def enabled(self) -> bool:
        return bool(keepawake.get_pref(PREF_ON, False, self.pref))

    def url(self) -> str:
        u = keepawake.get_pref(PREF_URL, DEFAULT_URL, self.pref)
        return u if isinstance(u, str) and not url_error(u) and u != OLD_DEFAULT else DEFAULT_URL

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
        return self._job is not None or self._retry_at is not None

    def start(self, now: float | None = None, auto: bool = False) -> bool:
        """A fetch now. auto: after a connect - retried on failure (RETRY_AFTER), else a fresh request (Refresh)."""
        if not self.enabled() or self._job is not None:
            return False
        if not auto:
            self._retry, self._retry_at = [], None
        url = self.url()
        job: dict = {"url": url, "started": time.time() if now is None else now, "result": None, "auto": auto}

        def run() -> None:
            job["result"] = fetch(url, self._get)
        job["thread"] = threading.Thread(target=run, daemon=True, name="status-page")
        self._job = job
        job["thread"].start()
        return True

    def due(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.enabled() and self._job is None and (self.checked is None or now - self.checked >= INTERVAL)

    def _finish(self, job: dict, result: dict, now: float) -> None:
        self._job = None
        if not result.get("error"):
            self.result, self.checked, self.url_checked, self.failed = result, now, job["url"], ""
            self._good, self._retry = (result, now, job["url"]), []
            return
        if job.get("auto") and self._retry:                   # a fresh tunnel may not carry traffic yet: try again
            self._retry_at = now + self._retry.pop(0)
            return
        good = self._good
        if job.get("auto") and good and good[2] == job["url"]:   # keep the last good answer, like the exit location
            self.result, self.checked, self.url_checked = good
            self.failed = str(result["error"])
            return
        self.result, self.checked, self.url_checked, self.failed = result, now, job["url"], ""

    def poll(self, now: float | None = None) -> bool:
        """Collects a finished fetch; True when there is something new to show."""
        now = time.time() if now is None else now
        job = self._job
        if job is None or job["result"] is None:
            if job is not None and now - job["started"] > 3 * TIMEOUT:
                self._finish(job, {"error": f"no answer within {TIMEOUT:g} s"}, now)
                return True
            return False
        self._finish(job, job["result"], now)
        return True

    def tick(self, now: float | None = None) -> bool:
        """The tray's timer: collects a finished fetch and starts a retry that is due. No fetch of its own otherwise: the
        same rules as the exit location - once after each connect (on_connected) and on Refresh. True when the view changed."""
        now = time.time() if now is None else now
        changed = self.poll(now)
        if self._retry_at is not None and now >= self._retry_at:
            self._retry_at = None
            changed = self.start(now, auto=True) or changed
        return changed

    def on_connected(self, now: float | None = None) -> bool:
        """VeroScudo reached Protected (a connect, a reconnect, a switch): look again, through the new tunnel - retried."""
        self._retry, self._retry_at = list(RETRY_AFTER), None
        return self.start(now, auto=True)

    def view(self) -> ServiceView | None:
        if not self.enabled():
            return None
        url = self.url()
        if self.result is None or self.url_checked != url:
            return service_view(None, url, checking=self.checking)
        return service_view(self.result, url, self.checked, self.checking, self.failed)

    def refresh(self) -> bool:
        """The card's Refresh link: a fetch now (unless one already runs or the option is off)."""
        return self.start()
