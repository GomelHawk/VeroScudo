from veroscudo import tray


def test_second_tray_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    first = tray._single_instance()
    assert first is not None
    assert tray._single_instance() is None      # a second tray in the same session exits
    first.close()
    again = tray._single_instance()             # the lock is freed when the first tray exits
    assert again is not None
    again.close()
