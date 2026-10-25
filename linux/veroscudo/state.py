"""The state machine shared with the other platforms. Pure except for the flag files."""
from __future__ import annotations

import hashlib
import os
import re
import sys
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


def safe_name(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:40]
    return f"{clean}-{hashlib.sha256(name.encode()).hexdigest()[:8]}"


RUN_DIR = "/var/run/veroscudo" if sys.platform == "darwin" else "/run/veroscudo"     # macOS has no /run


class StateStore:
    """The armed flag, the active profile and the cached server IPs must survive a reboot (strict from boot, like
    Windows), so they live in $VEROSCUDO_STATE (default /var/lib/veroscudo). The reconnect lock must not: it lives in
    $VEROSCUDO_HOME (default /run/veroscudo). Passing `home` (tests) puts everything there."""

    def __init__(self, home: Path | None = None, state: Path | None = None) -> None:
        self.home = home or Path(os.environ.get("VEROSCUDO_HOME", RUN_DIR))
        self.state = state or home or Path(os.environ.get("VEROSCUDO_STATE", "/var/lib/veroscudo"))
        for d in (self.home, self.state):
            try:
                d.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass        # the tray runs as the user and only reads
        self.armed_flag = self.state / "armed.flag"
        self.active_file = self.state / "active-profile"
        self.lock = self.home / "reconnect.lock"
        self.server_ip = self.state / "server.ip"           # 1.0 single-profile cache, read as a fallback

    def server_cache(self, profile: str) -> Path:
        return self.state / f"server-{safe_name(profile)}.ip"

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

    @property
    def active(self) -> str | None:
        try:
            return self.active_file.read_text().strip() or None
        except OSError:
            return None

    def set_active(self, name: str) -> bool:
        if self.active == name:
            return False
        self.active_file.write_text(name)
        return True

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

    def take_lock(self) -> bool:
        """Atomic (O_EXCL): two processes can never both run the redial loop. False when a live loop holds it."""
        for _ in range(2):
            try:
                fd = os.open(self.lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            except FileExistsError:
                if self.lock_alive():
                    return False
                continue                         # stale lock was removed: retry once
            with os.fdopen(fd, "w") as f:
                f.write(str(os.getpid()))
            return True
        return False

    def release_lock(self) -> None:
        self.lock.unlink(missing_ok=True)
