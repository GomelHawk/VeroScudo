"""The state machine shared with the other platforms. Pure except for the flag files."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sys
import threading
import time
from contextlib import contextmanager
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


KIND_LABELS = {"wireguard": "WireGuard", "openvpn": "OpenVPN"}


def kind_label(kind: str | None) -> str:
    """Human name of a NetworkManager connection kind (nm.kind)."""
    return KIND_LABELS.get(kind or "", "VPN")


def switch_notice(kind: str | None, name: str) -> str | None:
    """Shown on every switch to a profile whose drops are noticed late. NetworkManager reports OpenVPN's and WireGuard's
    "user disconnected" like any VPN, so only WireGuard's slower drop detection needs a word. Pure."""
    if kind == "wireguard":
        return (f"'{name}' is a WireGuard connection. A dead WireGuard link is noticed after 1-3 minutes, not seconds; "
                "you stay blocked until it reconnects.")
    return None


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
        self.fw_lock_file = self.home / "firewall.lock"     # see firewall_lock()
        self.applied_file = self.home / "applied.json"     # what the kill-switch allows right now (read by tray and status)
        self.down_file = self.home / "last-down"            # when the kill-switch last went to "blocked" (connection check)
        self.drop_file = self.home / "last-drop.json"       # the newest tunnel drop and why (the tray's "Last drop")
        self.auth_file = self.state / "auth-failed.json"    # the password was missing/rejected: redial paused (survives a reboot)
        self._fw_rlock = threading.RLock()
        self._fw_depth = 0
        self._fw_fd: int | None = None

    @contextmanager
    def firewall_lock(self):
        """Around every 'read the armed flag, then change the firewall': an flock in /run/veroscudo (every root process of
        VeroScudo - the daemon's watchdog, `veroscudo on` in another shell, the boot unit) plus a re-entrant thread lock.
        Without it the watchdog could read 'disarmed', a concurrent `on` arm and apply its table, and the watchdog then
        remove that table: armed but open until the next pass."""
        with self._fw_rlock:
            if self._fw_depth == 0:
                self._fw_fd = os.open(self.fw_lock_file, os.O_RDWR | os.O_CREAT, 0o644)
                fcntl.flock(self._fw_fd, fcntl.LOCK_EX)
            self._fw_depth += 1
            try:
                yield
            finally:
                self._fw_depth -= 1
                if self._fw_depth == 0 and self._fw_fd is not None:
                    fcntl.flock(self._fw_fd, fcntl.LOCK_UN)
                    os.close(self._fw_fd)
                    self._fw_fd = None

    def set_applied(self, profile: str | None, tunnel: str | None) -> None:
        """Written by the guard each time it applies or removes the kill-switch: the profile and the tunnel interface the
        rules let through (None: everything blocked). Atomic replace; readable by the signed-in user."""
        try:
            tmp = self.applied_file.with_suffix(".new")
            tmp.write_text(json.dumps({"profile": profile, "tunnel": tunnel}))
            os.replace(tmp, self.applied_file)
        except OSError:
            pass

    def mark_down(self, now: float | None = None) -> None:
        """The kill-switch was just applied without a tunnel (a drop, a Reconnect, a switch): the connection check starts
        its rating over from here, however short the gap was - its own rounds can miss a Reconnect of a few seconds."""
        try:
            self.down_file.write_text(repr(time.time() if now is None else now))
        except OSError:
            pass

    def last_down(self) -> float:
        try:
            return float(self.down_file.read_text())
        except (OSError, ValueError):
            return 0.0

    def record_drop(self, profile: str, why: str, now: float | None = None) -> None:
        """The tunnel of `profile` went down (a drop, your disconnect, a Reconnect) - the status window's "Last drop", like
        the Windows tray's RAS event. Only the newest one is kept; it is gone after a reboot (it lives in /run)."""
        try:
            tmp = self.drop_file.with_suffix(".new")
            tmp.write_text(json.dumps({"profile": profile, "why": why, "time": time.time() if now is None else now}))
            os.chmod(tmp, 0o644)                                 # the tray (the user) reads it
            os.replace(tmp, self.drop_file)
        except OSError:
            pass

    def set_auth_failed(self, profile: str, which: str) -> bool:
        """The VPN refused `profile` for its password: which = 'missing' (none stored) or 'rejected'. The guard stops
        redialing it so the account is not locked on the server (Windows: Set-VeroAuthFailed). True = newly set."""
        first = self.auth_failed(profile) is None
        try:
            tmp = self.auth_file.with_suffix(".new")
            tmp.write_text(json.dumps({"profile": profile, "which": which, "time": time.time()}))
            os.chmod(tmp, 0o644)                                 # the tray (the user) reads it
            os.replace(tmp, self.auth_file)
        except OSError:
            pass
        return first

    def auth_failed(self, profile: str) -> str | None:
        """'missing' / 'rejected' while `profile`'s password problem stands, else None."""
        try:
            j = json.loads(self.auth_file.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(j, dict) or j.get("profile") != profile or j.get("which") not in ("missing", "rejected"):
            return None
        return j["which"]

    def clear_auth_failed(self) -> bool:
        """You stored a password and asked again (On, Reconnect, a profile switch) or the VPN connected: redial resumes."""
        try:
            self.auth_file.unlink()
            return True
        except OSError:
            return False

    def last_drop(self) -> dict | None:
        """{profile, why, time} of the newest drop, or None."""
        try:
            j = json.loads(self.drop_file.read_text())
        except (OSError, ValueError):
            return None
        return j if isinstance(j, dict) else None

    def allowed_tunnel(self, profile: str) -> str | None:
        """The tunnel the kill-switch lets through for `profile`, as the guard last applied it - None while blocked. This,
        not "NetworkManager says activated", is what "protected" means: a dead WireGuard link stays activated."""
        try:
            j = json.loads(self.applied_file.read_text())
        except (OSError, ValueError):
            return None
        return j.get("tunnel") if isinstance(j, dict) and j.get("profile") == profile else None

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
        except PermissionError:
            return True             # the process exists but belongs to root: a non-root `status` may not signal it (nor unlink)
        except (ValueError, ProcessLookupError):
            try:
                self.lock.unlink(missing_ok=True)
            except OSError:
                pass                # read-only caller (tray, status): the daemon cleans it up
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
