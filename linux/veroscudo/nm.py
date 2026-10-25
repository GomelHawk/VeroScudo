"""NetworkManager backend via nmcli (control) and, when available, libnm over GObject introspection (events + reason)."""
from __future__ import annotations

import ipaddress
import pwd
import re
import socket
import subprocess
from pathlib import Path

_IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
SYS_NET = Path("/sys/class/net")


def _nmcli(*args: str) -> str:
    return subprocess.run(["nmcli", "-t", *args], check=False, capture_output=True, text=True).stdout.strip()


def is_connected(profile: str) -> bool:
    return _nmcli("-g", "GENERAL.STATE", "connection", "show", profile) == "activated"


def is_virtual(name: str) -> bool:
    """A tunnel interface has no backing device in sysfs; a physical NIC (eth0, wlp2s0) does."""
    return _IFNAME.match(name) is not None and not (SYS_NET / name / "device").exists()


def iface(profile: str) -> str | None:
    """The tunnel interface of an active VPN connection (tun0, wg0, ppp0 ...). Only GENERAL.IP-IFACE: for a 'vpn'
    connection GENERAL.DEVICES is the *underlying* card, and allowing that would open the kill-switch completely.
    Anything that is not a virtual interface is refused (None = stay blocked)."""
    v = _nmcli("-g", "GENERAL.IP-IFACE", "connection", "show", profile)
    if v and v != "--" and is_virtual(v):
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
        return sorted({ai[4][0] for ai in socket.getaddrinfo(server, None, socket.AF_UNSPEC)
                       if not ipaddress.ip_address(ai[4][0].split("%")[0]).is_link_local})
    except OSError:
        return []


def resolver_uid() -> int | None:
    """uid of systemd-resolved when it is the system resolver: then only it may send DNS while blocked."""
    if not Path("/run/systemd/resolve/io.systemd.Resolve").exists():
        return None
    try:
        return pwd.getpwnam("systemd-resolve").pw_uid
    except KeyError:
        return None


def nameservers(path: Path = Path("/etc/resolv.conf")) -> list[str]:
    """Upstream resolvers (no loopback stubs) - the only DNS destinations while blocked when systemd-resolved is absent."""
    out = []
    try:
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                try:
                    a = ipaddress.ip_address(parts[1].split("%")[0])
                except ValueError:
                    continue
                if not a.is_loopback:
                    out.append(str(a))
    except OSError:
        pass
    return sorted(set(out))


USER_REQUESTED_REASONS = {"user-requested", "user-disconnected"}


def watch(profiles, on_up, on_down) -> None:
    """Blocks. Calls on_up(profile) when a watched profile activates, on_down(profile, user_requested) when it deactivates.
    `profiles` is a callable returning the current set of names (config can change while running).
    Uses libnm (python3-gi + gir1.2-nm-1.0) for the deactivation reason; falls back to polling without reasons."""
    try:
        import gi  # type: ignore
        gi.require_version("NM", "1.0")
        from gi.repository import NM, GLib  # type: ignore
    except (ImportError, ValueError):
        _watch_polling(profiles, on_up, on_down)
        return

    client = NM.Client.new(None)
    tracked: dict[str, bool] = {}

    def hook(ac):
        name = ac.get_id()
        if name not in profiles() or ac.get_path() in tracked:
            return
        tracked[ac.get_path()] = True

        def changed(active, state, reason):
            st = NM.ActiveConnectionState(state)
            if st == NM.ActiveConnectionState.ACTIVATED:
                on_up(name)
            elif st == NM.ActiveConnectionState.DEACTIVATED:
                tracked.pop(ac.get_path(), None)
                rs = NM.ActiveConnectionStateReason(reason)
                on_down(name, rs == NM.ActiveConnectionStateReason.USER_DISCONNECTED)

        ac.connect("state-changed", changed)

    for ac in client.get_active_connections():
        hook(ac)
    client.connect("active-connection-added", lambda c, ac: hook(ac))
    GLib.MainLoop().run()


def _watch_polling(profiles, on_up, on_down, interval: float = 2.0) -> None:
    import time

    last = {p: is_connected(p) for p in profiles()}
    while True:
        time.sleep(interval)
        for p in profiles():
            now = is_connected(p)
            if now and not last.get(p, False):
                on_up(p)
            elif last.get(p, False) and not now:
                on_down(p, False)      # no reason available: treat as failure; `veroscudo off` sets its own marker first
            last[p] = now
