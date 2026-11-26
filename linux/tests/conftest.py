"""Shared by every test file."""
import threading

import pytest

from veroscudo import daemon, localdns


@pytest.fixture(autouse=True)
def no_redial_thread_outlives_its_test(monkeypatch):
    """A redial a test started in the background (Guard.reconnect_async) is waited for before the test's stand-ins are
    taken away: left running, it would go on in the next test - with that test's stand-ins, against its own guard."""
    yield
    for t in threading.enumerate():
        if getattr(getattr(t, "_target", None), "__func__", None) is daemon.Guard.reconnect:
            t.join(10)
            assert not t.is_alive(), "a redial loop started by this test is still running"


@pytest.fixture(autouse=True)
def never_the_real_resolver_dir(monkeypatch, tmp_path):
    """No test may write /etc/resolver: VeroScudo's resolver files go to the test's own folder."""
    monkeypatch.setattr(localdns, "RESOLVER_DIR", tmp_path / "etc-resolver")


@pytest.fixture(autouse=True)
def never_the_real_config(monkeypatch, tmp_path):
    """A guard under test reads no config.json of this machine (every VPN event looks whether the file changed)."""
    monkeypatch.setenv("VEROSCUDO_CONFIG", str(tmp_path / "no-config.json"))
