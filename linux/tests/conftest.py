"""Shared by every test file."""
import threading

import pytest

from veroscudo import daemon


@pytest.fixture(autouse=True)
def no_redial_thread_outlives_its_test(monkeypatch):
    """A redial a test started in the background (Guard.reconnect_async) is waited for before the test's stand-ins are
    taken away: left running, it would go on in the next test - with that test's stand-ins, against its own guard."""
    yield
    for t in threading.enumerate():
        if getattr(getattr(t, "_target", None), "__func__", None) is daemon.Guard.reconnect:
            t.join(10)
            assert not t.is_alive(), "a redial loop started by this test is still running"
