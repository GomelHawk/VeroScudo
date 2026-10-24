"""The state machine shared with the other platforms. Pure except for the flag files."""
from __future__ import annotations

import os
from enum import Enum
from pathlib import Path


class Decision(str, Enum):
    DISARM = "disarm"          # the user hung up -> firewall restored
    RECONNECT = "reconnect"    # the tunnel failed while armed -> stay blocked, redial forever
    NONE = "none"


def decide(user_requested: bool, armed: bool) -> Decision:
    """The one judgement the guard makes. Never yields an 'unblock' - strict by design."""
    if user_requested:
        return Decision.DISARM
    return Decision.RECONNECT if armed else Decision.NONE


class StateStore:
    """The armed flag + cached server IP must survive a reboot (strict from boot, like Windows), so they live in
    $VEROSCUDO_STATE (default /var/lib/veroscudo). The reconnect lock must not: it lives in $VEROSCUDO_HOME
    (default /run/veroscudo). Passing `home` (tests) puts everything there."""

    def __init__(self, home: Path | None = None, state: Path | None = None) -> None:
        self.home = home or Path(os.environ.get("VEROSCUDO_HOME", "/run/veroscudo"))
        self.state = state or home or Path(os.environ.get("VEROSCUDO_STATE", "/var/lib/veroscudo"))
        for d in (self.home, self.state):
            try:
                d.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass        # the tray runs as the user and only reads
        self.armed_flag = self.state / "armed.flag"
        self.lock = self.home / "reconnect.lock"
        self.server_ip = self.state / "server.ip"

    @property
    def armed(self) -> bool:
        return self.armed_flag.exists()

    def set_armed(self, value: bool) -> bool:
        """Returns True when the state changed."""
        if value and not self.armed_flag.exists():
            self.armed_flag.touch()
            return True
        if not value and self.armed_flag.exists():
            self.armed_flag.unlink()
            return True
        return False

    def lock_alive(self) -> bool:
        if not self.lock.exists():
            return False
        try:
            pid = int(self.lock.read_text().strip() or 0)
            os.kill(pid, 0)
            return True
        except (ValueError, ProcessLookupError, PermissionError):
            self.lock.unlink(missing_ok=True)
            return False

    def take_lock(self) -> None:
        self.lock.write_text(str(os.getpid()))

    def release_lock(self) -> None:
        self.lock.unlink(missing_ok=True)
