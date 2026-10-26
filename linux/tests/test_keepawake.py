import sys

from veroscudo import keepawake


def test_pref_roundtrip(tmp_path):
    f = tmp_path / "sub" / "tray.json"
    assert keepawake.load_pref(f) is False          # missing file
    keepawake.save_pref(True, f)
    assert keepawake.load_pref(f) is True
    keepawake.save_pref(False, f)
    assert keepawake.load_pref(f) is False
    f.write_text("not json")
    assert keepawake.load_pref(f) is False


def test_commands_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "ubuntu:GNOME")
    monkeypatch.setattr(keepawake.shutil, "which", lambda n: f"/usr/bin/{n}")
    cmds = keepawake._commands()
    assert cmds[0][0] == "gnome-session-inhibit" and "suspend" in cmds[0] and "idle" not in cmds[0]
    assert cmds[1][0] == "systemd-inhibit" and "--what=sleep" in cmds[1]      # never idle: the screen may blank
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "KDE")
    assert [c[0] for c in keepawake._commands()] == ["systemd-inhibit"]
    monkeypatch.setattr(keepawake.shutil, "which", lambda n: None)
    assert keepawake._commands() == [] and keepawake.backend() is None


def test_commands_macos_never_keeps_display_on(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(keepawake.shutil, "which", lambda n: "/usr/bin/caffeinate")
    (cmd,) = keepawake._commands()
    assert cmd[0] == "caffeinate" and "-d" not in cmd and "-w" in cmd


def test_acquire_release_with_a_fake_inhibitor(monkeypatch):
    monkeypatch.setattr(keepawake, "_SPAWN_SETTLE_S", 0.05)
    monkeypatch.setattr(keepawake, "_commands", lambda: [[sys.executable, "-c", "import sys; sys.stdin.read()"]])
    ka = keepawake.KeepAwake()
    assert ka.acquire() and ka.active
    assert ka.set(True)                    # idempotent
    ka.release()
    assert not ka.active
    assert ka.set(False) is False


def test_acquire_fails_cleanly(monkeypatch):
    monkeypatch.setattr(keepawake, "_commands", list)
    ka = keepawake.KeepAwake()
    assert ka.acquire() is False and not ka.active


def test_dead_inhibitor_is_noticed(monkeypatch):
    monkeypatch.setattr(keepawake, "_SPAWN_SETTLE_S", 0.05)
    monkeypatch.setattr(keepawake, "_commands", lambda: [[sys.executable, "-c", "import time; time.sleep(0.3)"]])
    ka = keepawake.KeepAwake()
    assert ka.acquire()
    keepawake.time.sleep(0.6)
    assert not ka.active
