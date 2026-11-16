"""The rules Windows and Linux/macOS must agree on, from one file both test suites read (shared/vectors.json; the
Windows side is windows/tests/VeroScudo.Shared.Tests.ps1). A change of such a rule on one platform fails here or there."""
import json
import os
from pathlib import Path

import pytest

from veroscudo import statuspage, update
from veroscudo.config import Config, is_lan_range, profile_id
from veroscudo.netutil import usable_server_ip

FILE = Path(__file__).resolve().parents[2] / "shared" / "vectors.json"
V = json.loads(FILE.read_text(encoding="utf-8")) if FILE.exists() else {}


def test_the_shared_file_is_there_in_ci():
    """A packaged copy of linux/ alone has no shared folder: the rules below then have no cases and are skipped. In CI
    the whole repository is there, and a missing file would mean nothing here was checked."""
    if os.environ.get("CI"):
        assert V, f"{FILE} is missing"


def cases(key, label):
    """The cases of one rule as pytest parameters, each named by `label` (an empty list when the file is not there)."""
    return [pytest.param(c, id=str(label(c))[:60] or "empty") for c in V.get(key, [])]


@pytest.mark.parametrize("c", cases("version_newer", lambda c: f"{c['tag']}>{c['current']}"))
def test_version_newer(c):
    assert update.is_newer(c["tag"], c["current"]) is c["newer"]


@pytest.mark.parametrize("c", cases("release_url", lambda c: c["url"][:50] or "empty"))
def test_release_url(c):
    assert update.is_release_url(c["url"]) is c["ok"]


@pytest.mark.parametrize("c", cases("profile_id", lambda c: c["name"]))
def test_profile_id(c):
    assert profile_id(c["name"]) == c["id"]


@pytest.mark.parametrize("c", cases("lan_allow", lambda c: c["value"] or "empty"))
def test_lan_allow(c):
    assert is_lan_range(c["value"]) is c["ok"]


def config_text(top: dict, profile: dict) -> str:
    return json.dumps({"profiles": [{"profile": "X", "server": "vpn.example.com", "username": "u", **profile}], **top})


def loads(top: dict, profile: dict) -> bool:
    try:
        Config.from_text(config_text(top, profile))
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("c", cases("server_ips", lambda c: c["value"] or "empty"))
def test_server_ips(c):
    assert loads({}, {"serverIps": [c["value"]]}) is c["ok"]


@pytest.mark.parametrize("c", cases("config", lambda c: c["what"]))
def test_config(c):
    assert loads(c["top"], c["profile"]) is c["ok"]


@pytest.mark.parametrize("c", cases("status_url", lambda c: c["url"][:50] or "empty"))
def test_status_url(c):
    assert (statuspage.url_error(c["url"]) == "") is c["ok"]


@pytest.mark.parametrize("c", cases("usable_server_ip", lambda c: c["value"] or "empty"))
def test_usable_server_ip(c):
    assert usable_server_ip(c["value"]) is c["ok"]
