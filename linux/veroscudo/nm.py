"""NetworkManager backend via nmcli (control) and, when available, libnm over GObject introspection (events + reason)."""
from __future__ import annotations

import socket
import subprocess


def _nmcli(*args: str) -> str:
    return subprocess.run(["nmcli", "-t", *args], check=False, capture_output=True, text=True).stdout.strip()


def is_connected(profile: str) -> bool:
    return _nmcli("-g", "GENERAL.STATE", "connection", "show", profile) == "activated"


def iface(profile: str) -> str | None:
    """The tunnel interface of an active VPN connection (tun0, wg0, ppp0 ...)."""
    for key in ("GENERAL.IP-IFACE", "GENERAL.DEVICES"):
        v = _nmcli("-g", key, "connection", "show", profile)
        if v and v != "--":
            return v
    return None


def up(profile: str) -> bool:
    r = subprocess.run(["nmcli", "connection", "up", "id", profile], check=False, capture_output=True, text=True)
    return r.returncode == 0


def down(profile: str) -> bool:
    r = subprocess.run(["nmcli", "connection", "down", "id", profile], check=False, capture_output=True, text=True)
    return r.returncode == 0


def resolve(server: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(server, None, socket.AF_INET)})
    except OSError:
        return []


USER_REQUESTED_REASONS = {"user-requested", "user-disconnected"}


def watch(profile: str, on_up, on_down) -> None:
    """Blocks. Calls on_up() when the profile activates, on_down(user_requested: bool) when it deactivates.
    Uses libnm (python3-gi + gir1.2-nm-1.0) for the deactivation reason; falls back to polling without reasons."""
    try:
        import gi  # type: ignore
        gi.require_version("NM", "1.0")
        from gi.repository import NM, GLib  # type: ignore
    except (ImportError, ValueError):
        _watch_polling(profile, on_up, on_down)
        return

    client = NM.Client.new(None)
    tracked: dict[str, bool] = {}

    def hook(ac):
        if ac.get_id() != profile or ac.get_path() in tracked:
            return
        tracked[ac.get_path()] = True

        def changed(active, state, reason):
            st = NM.ActiveConnectionState(state)
            if st == NM.ActiveConnectionState.ACTIVATED:
                on_up()
            elif st == NM.ActiveConnectionState.DEACTIVATED:
                tracked.pop(ac.get_path(), None)
                rs = NM.ActiveConnectionStateReason(reason)
                on_down(rs == NM.ActiveConnectionStateReason.USER_DISCONNECTED)

        ac.connect("state-changed", changed)

    for ac in client.get_active_connections():
        hook(ac)
    client.connect("active-connection-added", lambda c, ac: hook(ac))
    GLib.MainLoop().run()


def _watch_polling(profile: str, on_up, on_down, interval: float = 2.0) -> None:
    import time

    last = is_connected(profile)
    while True:
        time.sleep(interval)
        now = is_connected(profile)
        if now and not last:
            on_up()
        elif last and not now:
            on_down(False)      # no reason available: treat as failure; `veroscudo off` sets its own marker first
        last = now
