"""Keep the machine awake: the Linux tray's "Keep awake" toggle and `veroscudo awake` (the only way on macOS).

While held, the *system* must not sleep, including behind a locked screen. The display is left alone: it may
still turn off. Same idea as the Windows tray (a power request, never a display request).

One backend per platform, stdlib only; each is a child process that dies with us, so a crash can never leave
the machine unable to sleep:

- macOS: `caffeinate -i -s -w <our pid>` (no `-d`), which exits when we do.
- Linux: `gnome-session-inhibit` (GNOME) or `systemd-inhibit` wrapping `cat` on a pipe we hold: if we die the
  pipe closes, `cat` exits and the inhibitor goes with it.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

log = logging.getLogger(__name__)

REASON = "VeroScudo: Keep awake is on"
_SPAWN_SETTLE_S = 0.3        # how long a fresh inhibitor child gets to fail before it counts as holding


def pref_file() -> Path:
    """Per-user tray choices (the guard's own files are root-owned)."""
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "veroscudo" / "tray.json"


def load_pref(path: Path | None = None) -> bool:
    try:
        return bool(json.loads((path or pref_file()).read_text()).get("keepAwake"))
    except (OSError, ValueError, AttributeError):
        return False


def save_pref(on: bool, path: Path | None = None) -> None:
    path = path or pref_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"keepAwake": on}))
    except OSError:
        log.debug("could not save %s", path, exc_info=True)


class KeepAwake:
    """Holds (or not) one inhibitor. Call it from one thread only (the GUI thread)."""

    def __init__(self) -> None:
        self._child: subprocess.Popen[bytes] | None = None

    @property
    def active(self) -> bool:
        if self._child is not None and self._child.poll() is not None:
            log.warning("keep-awake inhibitor exited (code %s)", self._child.returncode)
            self._child = None
        return self._child is not None

    def set(self, on: bool) -> bool:
        """Acquire or release; returns whether the request is now held."""
        if on:
            return self.acquire()
        self.release()
        return False

    def acquire(self) -> bool:
        if self.active:
            return True
        for cmd in _commands():
            self._child = _spawn(cmd)
            if self._child is not None:
                log.info("keep-awake acquired (%s)", cmd[0])
                return True
        log.warning("keep-awake is not available on this system")
        return False

    def release(self) -> None:
        if self._child is None:
            return
        child, self._child = self._child, None
        try:
            if child.stdin is not None:
                child.stdin.close()
            child.terminate()
            child.wait(timeout=2)
        except Exception:
            log.debug("keep-awake child did not exit cleanly", exc_info=True)
            child.kill()
        log.info("keep-awake released")


def backend() -> str | None:
    """What `acquire()` would try first, or None when nothing can keep this machine awake."""
    commands = _commands()
    return commands[0][0] if commands else None


def _commands() -> list[list[str]]:
    """Inhibitor commands to try, best first."""
    if sys.platform == "darwin":
        return [["caffeinate", "-i", "-s", "-w", str(os.getpid())]] if shutil.which("caffeinate") else []
    commands = []
    # GNOME's automatic suspend is driven by its own session manager, not by logind's inhibitors. `suspend` only:
    # `idle` would also stop the screen blanking, which should keep working.
    if "GNOME" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper() and shutil.which("gnome-session-inhibit"):
        commands.append(["gnome-session-inhibit", "--inhibit", "suspend", "--reason", REASON, "cat"])
    if shutil.which("systemd-inhibit"):
        commands.append(["systemd-inhibit", "--what=sleep", "--who=VeroScudo", f"--why={REASON}", "--mode=block", "cat"])
    return commands


def _spawn(cmd: list[str]) -> subprocess.Popen[bytes] | None:
    """Start an inhibitor child; None if it is missing or exits straight away."""
    try:
        child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        log.debug("keep-awake: %s unavailable: %s", cmd[0], exc)
        return None
    time.sleep(_SPAWN_SETTLE_S)
    if child.poll() is not None:
        log.debug("keep-awake: %s exited with %s", cmd[0], child.returncode)
        return None
    return child


def hold() -> int:
    """`veroscudo awake`: keep the system awake until Ctrl-C or SIGTERM. Works on Linux and macOS."""
    import signal
    ka = KeepAwake()
    if not ka.acquire():
        print("veroscudo: nothing available to keep this machine awake (needs systemd-inhibit, "
              "gnome-session-inhibit or caffeinate)", file=sys.stderr)
        return 1
    print("Keeping the system awake (the screen may still turn off). Ctrl-C to stop.")
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        while ka.active:
            time.sleep(1)
        print("veroscudo: the inhibitor exited", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        ka.release()
