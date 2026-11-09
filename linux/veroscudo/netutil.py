"""Helpers shared by the VPN-control backends (nm.py, scutil.py) and the firewall backends (firewall.py, pf.py)."""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
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


def parse_ip_addr(text: str) -> dict[str, list[str]]:
    """`ip -o -4 addr show up` -> {interface: [IPv4 addresses]}. A point-to-point link (ppp0 of an SSTP, L2TP or PPTP VPN)
    prints `inet 192.0.2.7 peer 192.0.2.1/32` - the local address has no /prefix there. Pure."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = re.match(r"^\d+:\s+(\S+?)(?:@\S+)?\s+inet\s+([0-9.]+)(?:/\d+|\s+peer\s)", line)
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    return out


def ipv4_by_iface() -> dict[str, list[str]]:
    """Linux: interfaces that are up -> their IPv4 addresses ({} when `ip` cannot be run)."""
    try:
        r = subprocess.run(["ip", "-o", "-4", "addr", "show", "up"], check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_ip_addr(r.stdout)
