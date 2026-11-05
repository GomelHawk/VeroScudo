"""The tray's decisions (traymodel.py), shared by the Linux and the macOS tray - the same wording as the Windows tray."""
import pytest

from veroscudo import traymodel as tm
from veroscudo.traymodel import Facts


def test_states_and_their_texts():
    assert tm.tray_state(Facts(configured=False)).state == "attention"
    assert tm.tray_state(Facts(name="W", armed=False, up=True)).title == "Off"
    v = tm.tray_state(Facts(name="W", kind="vpn", armed=True, up=True))
    assert (v.state, v.title) == ("protected", "Protected") and "W (VPN) is connected" in v.text
    assert tm.tray_state(Facts(name="W", armed=True, up=False)).title == "Blocked - reconnecting"
    assert tm.tray_state(Facts(name="W", armed=True, expect="connect")).title == "Connecting"
    assert tm.tray_state(Facts(name="W", armed=True, expect="switch")).title == "Switching"
    assert tm.tray_state(Facts(name="W", armed=True, expect="reconnect")).title == "Reconnecting"


def test_a_stopped_guard_is_attention_whatever_else():
    v = tm.tray_state(Facts(name="W", armed=True, up=True, guard_running=False))
    assert v.state == "attention" and v.title == "Guard not running"


def test_another_tunnel_while_protected_is_a_note_not_a_loss_of_protection():
    v = tm.tray_state(Facts(name="W", armed=True, up=True, others=("tun1",)))
    assert v.state == "protected" and "tun1" in v.text


def test_menu_enabling_matches_windows():
    off = tm.menu_state(tm.tray_state(Facts(name="W")))
    assert off == tm.MenuState(on=True, off=False, reconnect=False)
    prot = tm.menu_state(tm.tray_state(Facts(name="W", armed=True, up=True)))
    assert prot == tm.MenuState(on=False, off=True, reconnect=True)
    stray = tm.menu_state(tm.tray_state(Facts(name="W", armed=False, up=True)))     # VPN up, VeroScudo off: Off still works
    assert stray.off and stray.on


def test_notifications_on_state_changes_only():
    prot = tm.tray_state(Facts(name="W", armed=True, up=True))
    lost = tm.tray_state(Facts(name="W", armed=True, up=False))
    assert tm.transition_notice(None, prot, None, "W") is None               # first look: quiet
    assert tm.transition_notice("protected", prot, None, "W") is None
    title, _, urgency = tm.transition_notice("protected", lost, None, "W")
    assert title == "VPN connection lost - traffic blocked" and urgency == "critical"
    assert tm.transition_notice("off", lost, "connect", "W")[0] == "VeroScudo on - connecting"
    assert tm.transition_notice("protected", lost, "reconnect", "W") is None   # the user's own Reconnect already said it
    assert tm.transition_notice("protected", lost, "switch", "W") is None
    assert tm.transition_notice("blocked", prot, None, "W")[0] == "VPN protected"
    assert tm.transition_notice("protected", tm.tray_state(Facts(name="W")), None, "W")[0] == "VPN turned off"


def test_expect_clears_when_protected_and_expires_once():
    e = tm.Expect()
    e.start("connect", now=0)
    blocked = tm.tray_state(Facts(name="W", armed=True))
    assert not e.update(blocked, now=60) and e.kind == "connect"
    assert e.update(blocked, now=tm.EXPECT_SECONDS + 1) and e.kind is None
    assert not e.update(blocked, now=500)                                     # once
    e.start("connect", now=0)
    e.update(tm.tray_state(Facts(name="W", armed=True, up=True)), now=5)
    assert e.kind is None
    e.start("connect", now=0)
    e.update(tm.tray_state(Facts(name="W")), now=30)                          # turned off again / cancelled
    assert e.kind is None


def test_tray_actions_go_through_sudo_n_by_full_path():
    assert tm.action_argv("on") == ["sudo", "-n", "/opt/veroscudo/bin/veroscudo", "on"]
    assert tm.action_argv("use", "Backup")[-2:] == ["use", "Backup"]
    with pytest.raises(ValueError):
        tm.action_argv("daemon")


def test_admin_actions_ask_for_a_password_and_pass_arguments_as_data():
    assert tm.admin_argv(["import", "Office; rm -rf /"], platform="linux") == \
        ["pkexec", "/opt/veroscudo/bin/veroscudo", "import", "Office; rm -rf /"]
    assert tm.admin_argv(["uninstall"], platform="linux") == ["pkexec", "/opt/veroscudo/uninstall.sh"]
    mac = tm.admin_argv(["remove", 'x" & do shell script "evil'], platform="darwin")
    assert mac[0] == "osascript" and mac[-1] == 'x" & do shell script "evil'           # an argv item, quoted by AppleScript
    assert "with administrator privileges" in " ".join(mac)
    with pytest.raises(ValueError):
        tm.admin_argv(["on"])


def test_cancel_and_failure_messages():
    assert tm.cancelled(126, "", platform="linux") and not tm.cancelled(1, "", platform="linux")
    assert tm.cancelled(1, "execution error: User canceled. (-128)", platform="darwin")
    argv = tm.action_argv("on")
    assert "sudo rule" in tm.explain_failure(argv, 1, "sudo: a password is required\n")
    assert tm.explain_failure(["pkexec", "x"], 2, "veroscudo: 'W' is the only profile\n") == "'W' is the only profile"


def test_update_notice_once_per_tag():
    info = tm.UpdateInfo()
    assert tm.update_notice(info, "v9.0.0", True) == ("Update available: v9.0.0…", True)
    assert tm.update_notice(info, "v9.0.0", True) == ("Update available: v9.0.0…", False)
    assert tm.update_notice(info, None, False) == ("Check for updates", False)


def test_events_are_none_when_the_log_is_not_readable(tmp_path):
    log = tmp_path / "v.log"
    assert tm.read_events(log) == []
    log.write_text("".join(f"line {i}\n" for i in range(40)))
    assert tm.read_events(log, n=3) == ["line 37", "line 38", "line 39"]
    assert tm.read_events(tmp_path) is None                      # a directory: cannot be read as a file -> None


def test_runner_reports_results(tmp_path):
    import time
    r = tm.Runner()
    r.start("x", ["sh", "-c", "echo no >&2; exit 3"])
    for _ in range(50):
        res = r.results()
        if res:
            break
        time.sleep(0.05)
    assert res and res[0][0] == "x" and res[0][2] == 3 and "no" in res[0][4]
