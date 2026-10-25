"""macOS VPN control through `scutil --nc` (ALPHA - not yet run on a real Mac). Same interface as nm.py.

Works with the VPN services macOS itself manages (System Settings > VPN: IKEv2, L2TP, Cisco IPSec); the password stays in
the macOS keychain. macOS reports no "user hung up" reason, so every drop is treated as a failure: the machine stays
blocked and redials until `sudo veroscudo off` - strict, never open."""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
from pathlib import Path

_IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def _status(profile: str) -> str:
    return subprocess.run(["scutil", "--nc", "status", profile], check=False, capture_output=True, text=True).stdout


def is_connected(profile: str) -> bool:
    out = _status(profile)
    return bool(out) and out.splitlines()[0].strip() == "Connected"


def iface(profile: str) -> str | None:
    """The tunnel interface (ipsec0, ppp0, utunN) from the extended status; only virtual interfaces are accepted."""
    m = re.search(r"InterfaceName\s*:\s*(\S+)", _status(profile))
    if m and _IFNAME.match(m.group(1)) and re.match(r"^(ipsec|ppp|utun|tun)\d+$", m.group(1)):
        return m.group(1)
    return None


def up(profile: str) -> bool:
    subprocess.run(["scutil", "--nc", "start", profile], check=False, capture_output=True, text=True)
    for _ in range(30):                       # scutil returns at once; wait for the outcome like nmcli does
        time.sleep(1)
        out = _status(profile)
        first = out.splitlines()[0].strip() if out else ""
        if first == "Connected":
            return True
        if first == "Disconnected":
            return False
    return False


def down(profile: str) -> bool:
    r = subprocess.run(["scutil", "--nc", "stop", profile], check=False, capture_output=True, text=True)
    return r.returncode == 0


def resolve(server: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(server, None, socket.AF_UNSPEC)
                       if not ipaddress.ip_address(ai[4][0].split("%")[0]).is_link_local})
    except OSError:
        return []


def resolver_uid() -> int | None:
    return None                               # pf matches users only on local sockets; DNS is scoped by destination instead


def nameservers(path: Path = Path("/etc/resolv.conf")) -> list[str]:
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


def watch(profiles, on_up, on_down, interval: float = 2.0) -> None:
    """Polling: macOS has no reason code, so a drop is reported as a failure (`veroscudo off` sets its own marker)."""
    last = {p: is_connected(p) for p in profiles()}
    while True:
        time.sleep(interval)
        for p in profiles():
            now = is_connected(p)
            if now and not last.get(p, False):
                on_up(p)
            elif last.get(p, False) and not now:
                on_down(p, False)
            last[p] = now
