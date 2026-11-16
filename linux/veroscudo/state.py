"""The state machine shared with the other platforms. Pure except for the flag files."""
from __future__ import annotations

import fcntl
import hashlib
import json
import logging
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


KIND_LABELS = {"wireguard": "WireGuard", "openvpn": "OpenVPN", "hiddify": "Hiddify VPN mode"}


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


LOG = "/var/log/veroscudo.log"       # the guard's log (written by the root command, read by the trays and `status`)
# who may read the log besides root: the administrators' group (Debian/Ubuntu 'adm' also reads the journal, where the
# daemon's output goes anyway; macOS 'admin'). The tray's Status and Open log read it as the signed-in user.
LOG_GROUP = "admin" if sys.platform == "darwin" else "adm"


def is_up(nm, store: StateStore, profile: str, armed: bool | None = None) -> bool:
    """Connected - and, while armed, let through by the kill-switch as the guard last applied it. A dead WireGuard link
    stays 'activated' and only root can read its handshakes; the guard's own verdict (applied.json) is what counts.
    The one rule for `veroscudo status` and both trays. `nm`: the platform's VPN backend; `armed`: store.armed when the
    caller has read it already."""
    if not nm.is_connected(profile):
        return False
    armed = store.armed if armed is None else armed
    return not armed or store.allowed_tunnel(profile) is not None


def proc_started(pid: int, proc: Path = Path("/proc")) -> str | None:
    """When the process started, as the kernel counts it (Linux: field 22 of /proc/<pid>/stat) - with the process id it
    names one process for good. None where that cannot be read (macOS, a process of another user in a hardened /proc):
    the caller then goes by the process id alone. Pure apart from the read."""
    try:
        stat = (proc / str(pid) / "stat").read_text()
    except OSError:
        return None
    fields = stat.rpartition(")")[2].split()                # the command name (in brackets) may hold spaces
    return fields[19] if len(fields) > 19 else None


def write_atomic(path: Path, text: str, mode: int | None = None) -> None:
    """A state file other processes read: written whole or not at all - to a temporary file of this process beside it,
    then renamed over the old one. A reader never meets an empty or half-written file."""
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.new")   # one per writer: the daemon has threads
    try:
        tmp.write_text(text)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)                          # only when the replace did not happen


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
        # see firewall_lock(). Not "firewall.lock": up to 1.3 that file was readable by everyone, and whoever opened it then
        # could still hold a lock on it - a name of its own has no such past
        self.fw_lock_file = self.home / "fw.lock"
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
                # 0600: flock works on a read-only handle too - a file others can open is a lock others can hold
                self._fw_fd = os.open(self.fw_lock_file, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                try:
                    if os.fstat(self._fw_fd).st_mode & 0o077:
                        os.fchmod(self._fw_fd, 0o600)
                    fcntl.flock(self._fw_fd, fcntl.LOCK_EX)
                except BaseException:                            # not locked: the file is closed again, nothing is left open
                    os.close(self._fw_fd)
                    self._fw_fd = None
                    raise
            self._fw_depth += 1
            try:
                yield
            finally:
                self._fw_depth -= 1
                if self._fw_depth == 0 and self._fw_fd is not None:
                    fcntl.flock(self._fw_fd, fcntl.LOCK_UN)
                    os.close(self._fw_fd)
                    self._fw_fd = None

    @staticmethod
    def _note(path: Path, what: dict, mode: int | None = None) -> None:
        """One of the small notes the tray and `status` read (mode 0644: the signed-in user reads it). A note that cannot
        be written is said in the log and nothing more: the guard's own decisions never wait on it."""
        try:
            write_atomic(path, json.dumps(what), mode)
        except OSError as e:
            logging.getLogger("veroscudo").warning("could not write %s: %s", path.name, e)

    def set_applied(self, profile: str | None, tunnel: str | None) -> None:
        """Written by the guard each time it applies or removes the kill-switch: the profile and the tunnel interface the
        rules let through (None: everything blocked). Atomic replace; readable by the signed-in user."""
        self._note(self.applied_file, {"profile": profile, "tunnel": tunnel})

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
        self._note(self.drop_file, {"profile": profile, "why": why, "time": time.time() if now is None else now}, 0o644)

    def set_auth_failed(self, profile: str, which: str) -> bool:
        """The VPN refused `profile` for its password: which = 'missing' (none stored) or 'rejected'. The guard stops
        redialing it so the account is not locked on the server (Windows: Set-VeroAuthFailed). True = newly set."""
        first = self.auth_failed(profile) is None
        self._note(self.auth_file, {"profile": profile, "which": which, "time": time.time()}, 0o644)
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
        write_atomic(self.active_file, name)                     # read on every look at the config, by every process
        return True

    def lock_alive(self) -> bool:
        """A redial loop holds the lock: its process exists and is the one that took it - the lock names the process id
        and when that process started, so an id the system has given to another process since does not count."""
        if not self.lock.exists():
            return False
        parts: list[str] | None = None
        try:
            parts = self.lock.read_text().split()
            if not parts and time.time() - self.lock.stat().st_mtime < 5:
                return True                                      # just created, its owner is about to write its id
            pid = int(parts[0]) if parts else 0
            if pid <= 0:
                raise ValueError("no process id")
            started = parts[1] if len(parts) > 1 else None
            now = proc_started(pid)
            if started is not None and now is not None and started != now:
                raise ProcessLookupError                         # the id belongs to another process now
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True             # the process exists but belongs to root: a non-root `status` may not signal it (nor unlink)
        except FileNotFoundError:
            return False                                         # released between the looks
        except (ValueError, ProcessLookupError):
            try:
                # only the lock that was just judged: another process may have removed it and taken a fresh one meanwhile
                if self.lock.read_text().split() == parts:
                    self.lock.unlink(missing_ok=True)
            except (OSError, ValueError):
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
                f.write(f"{os.getpid()} {proc_started(os.getpid()) or ''}".strip())
            return True
        return False

    def release_lock(self) -> None:
        self.lock.unlink(missing_ok=True)
