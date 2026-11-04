"""Helpers shared by the VPN-control backends (nm.py, scutil.py) and the firewall backends (firewall.py, pf.py)."""
from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path

IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")         # a Linux/BSD interface name, and nothing that could end a rule line


def resolve(server: str) -> list[str]:
    """Every address of the VPN host (both families), link-local left out; [] when the lookup fails (blocked, offline)."""
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(server, None, socket.AF_UNSPEC)
                       if not ipaddress.ip_address(ai[4][0].split("%")[0]).is_link_local})
    except OSError:
        return []


def nameservers(path: Path = Path("/etc/resolv.conf")) -> list[str]:
    """Upstream resolvers from resolv.conf (no loopback stubs): the only DNS destinations while blocked."""
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
