from veroscudo.state import Decision, StateStore, decide


def test_user_requested_always_disarms():
    assert decide(user_requested=True, armed=True) is Decision.DISARM
    assert decide(user_requested=True, armed=False) is Decision.DISARM


def test_failure_while_armed_reconnects():
    assert decide(user_requested=False, armed=True) is Decision.RECONNECT


def test_failure_while_disarmed_does_nothing():
    assert decide(user_requested=False, armed=False) is Decision.NONE


def test_no_unblock_decision_exists():
    assert {d.value for d in Decision} == {"disarm", "reconnect", "none"}


def test_flag_and_lock(tmp_path):
    s = StateStore(tmp_path)
    assert not s.armed
    assert s.set_armed(True) and s.armed
    assert not s.set_armed(True)          # idempotent
    assert s.set_armed(False) and not s.armed
    s.take_lock(); assert s.lock_alive(); s.release_lock(); assert not s.lock_alive()
    s.lock.write_text("999999"); assert not s.lock_alive()    # stale lock is cleaned
