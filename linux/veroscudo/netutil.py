"""Helpers shared by the VPN-control backends (nm.py, scutil.py) and the firewall backends (firewall.py, pf.py)."""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}\Z")         # a Linux/BSD interface name, and nothing that could end a rule line

_ADDR = re.compile(r"^[0-9A-Fa-f:.]{2,45}(/\d{1,3})?\Z")     # all an address or network in a rule may consist of


def plain_ip(value: object) -> str:
    """The address in its canonical form. ValueError for anything else - also for an IPv6 zone ("fe80::1%eth0"): the
    text after the % is free-form, and these strings end up in firewall rules. Pure."""
    s = str(value)
    if "%" in s:
        raise ValueError(f"an address with a zone is not accepted: {s[:60]!r}")
    a = ipaddress.ip_address(s)
    if getattr(a, "ipv4_mapped", None) is not None:
        raise ValueError(f"an IPv4 address written as IPv6 is not accepted (write it as IPv4): {s[:60]!r}")
    return str(a)


def plain_net(value: object) -> str:
    """An address or network in its canonical form (192.168.1.5/24 -> 192.168.1.0/24, a netmask -> a prefix length).
    ValueError for anything else, also for a zone. Pure."""
    s = str(value)
    if "%" in s:
        raise ValueError(f"a network with a zone is not accepted: {s[:60]!r}")
    net = ipaddress.ip_network(s, strict=False)
    if getattr(net.network_address, "ipv4_mapped", None) is not None:
        raise ValueError(f"an IPv4 network written as IPv6 is not accepted (write it as IPv4): {s[:60]!r}")
    return str(net)


def rule_token(value: str) -> str:
    """Last check before an address or network is written into a ruleset: digits, hex, dots, colons and one /prefix -
    nothing that could end a rule or start another one. Returns it unchanged; ValueError otherwise. Pure."""
    if not isinstance(value, str) or not _ADDR.match(value):
        raise ValueError(f"refusing {str(value)[:60]!r} in a firewall rule")
    return value


# fake-DNS ranges of sing-box / Hiddify (an answer from such a proxy, never a real server)
FAKE_IP_NETS = (ipaddress.ip_network("198.18.0.0/15"), ipaddress.ip_network("fc00::/18"))


def usable_server_ip(addr: str) -> bool:
    """An address a VPN server can really have: not link-local, loopback, unspecified, multicast, or a fake-DNS answer.
    Private ranges stay allowed - a company VPN server can sit in the local network. Pure."""
    try:
        ip = ipaddress.ip_address(plain_ip(addr))
    except ValueError:
        return False
    if ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return False
    if ip.version == 4 and (ip.packed[0] == 0 or ip.packed[0] >= 224):       # "this network", class E, broadcast
        return False
    return not any(ip.version == n.version and ip in n for n in FAKE_IP_NETS)


def resolve(server: str) -> list[str]:
    """Every usable address of the VPN host (both families); [] when the lookup fails (blocked, offline)."""
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(server, None, socket.AF_UNSPEC) if usable_server_ip(ai[4][0])})
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """An answer comes from the address that was asked, or not at all (as in the Windows tray's lookups)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirected - not followed", headers, fp)


def fetch_https(url: str, timeout: float, limit: int, headers: dict | None = None) -> bytes:
    """One https GET for the trays' lookups (exit location, service status page, update check): https only, no redirect
    followed, at most `limit` bytes read, `timeout` seconds per step. Raises OSError / ValueError on anything else."""
    if not url.lower().startswith("https://"):
        raise ValueError("https only")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "VeroScudo", **(headers or {})})
    with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as r:
        return r.read(limit)
