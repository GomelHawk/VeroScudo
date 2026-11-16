"""Update notice: compare the running version with the latest GitHub release. Never called while blocked."""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass

from . import __version__
from .netutil import fetch_https

REPO = "GomelHawk/VeroScudo"
RELEASES = f"https://github.com/{REPO}/releases/"
_TAG = re.compile(r"^[vV]?(\d+(?:\.\d+){1,3})\Z")


def is_release_url(url: str) -> bool:
    """Only this project's GitHub release pages may be opened from an update notice."""
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return u.scheme == "https" and u.netloc == "github.com" and url.startswith(RELEASES) and "@" not in u.netloc


def _tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def is_newer(tag: str, current: str = __version__) -> bool:
    """True when a release tag (v1.2.3) is newer than the running version; garbage tags are never 'newer'."""
    m = _TAG.match(tag.strip())
    if not m:
        return False
    a, b = _tuple(m.group(1)), _tuple(current)
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) > b + (0,) * (n - len(b))


@dataclass(frozen=True)
class Release:
    tag: str
    url: str


def fetch_latest(repo: str = REPO, timeout: float = 10.0) -> Release | None:
    try:
        raw = fetch_https(f"https://api.github.com/repos/{repo}/releases/latest", timeout, 262144,
                          {"User-Agent": f"VeroScudo/{__version__}", "Accept": "application/vnd.github+json"})
        tag = str(json.loads(raw)["tag_name"])
        if not _TAG.match(tag):
            return None
        # the link is built here from the tag (digits and dots only), not taken from the answer: what is opened is what
        # was checked (the Windows tray does the same)
        rel = Release(tag=tag, url=RELEASES + "tag/" + tag)
        return rel if is_release_url(rel.url) else None
    except Exception:  # noqa: BLE001 - any network/parse problem just means "no notice this time"
        return None
