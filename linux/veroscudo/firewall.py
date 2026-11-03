"""nftables kill-switch. render_ruleset() is pure; apply()/clear() shell out to nft.

A separate table with `policy drop` base chains: in nftables a packet must be accepted by every base chain on a hook, so
a drop here is final whatever other tables (ufw, docker, firewalld) accept."""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field

from .config import Config, server_rules

TABLE = "inet veroscudo"
_IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


@dataclass(frozen=True)
class DnsPolicy:
    """Who may send DNS while blocked (redial needs to resolve the server): the system resolver's uid, else only the
    configured upstream resolvers, else (logged) any destination."""
    uid: int | None = None
    servers: tuple[str, ...] = field(default_factory=tuple)


def _split(addrs) -> tuple[list[str], list[str]]:
    v4, v6 = [], []
    for a in addrs:
        net = ipaddress.ip_network(str(a), strict=False)          # raises on anything that is not an address/network
        (v4 if net.version == 4 else v6).append(str(a))
    return v4, v6


MARK = "0x5653"          # conntrack mark of flows VeroScudo allowed outside the tunnel ("VS")


def render_ruleset(cfg: Config, server_ips: list[str], tun_iface: str | None, vm_allowed: bool,
                   dns: DnsPolicy | None = None) -> str:
    """Default-drop output, input and forward (containers/VMs) with the documented allow-list. DNS is allowed only while
    the tunnel is down: while it is up, name resolution goes through the tunnel like everything else (no DNS leak).

    Every explicit permit outside the tunnel marks its connection; established traffic is accepted only with that mark. So a
    flow that used the tunnel (a connected UDP socket, a TCP socket bound to the tunnel address) cannot carry on over the
    physical NIC once the tunnel is gone - it was never marked. Inbound: nothing but replies to marked flows, the tunnel,
    DHCP replies and neighbour discovery: the host is not reachable over the physical network while armed."""
    if tun_iface is not None and not _IFNAME.match(tun_iface):
        raise ValueError(f"refusing interface name {tun_iface!r}")
    dns = dns or DnsPolicy()
    srv4, srv6 = _split(server_ips)
    lan4, lan6 = _split(cfg.lan_allow)
    keep = f"ct mark set {MARK} accept"
    lines = [
        f"table {TABLE}",
        f"delete table {TABLE}",
        f"table {TABLE} {{",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        "    oifname lo accept",
    ]
    if tun_iface:
        lines.append(f'    oifname "{tun_iface}" accept')
    lines += [
        f"    ct state established,related ct mark {MARK} accept",      # only flows VeroScudo allowed itself
        f"    udp sport 68 udp dport 67 {keep}",                         # DHCP
        f"    udp sport 546 udp dport 547 {keep}",                       # DHCPv6
        "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report } accept",
    ]
    if not tun_iface:
        # DNS only while down (to find the VPN server): the system resolver's user, else only the known resolvers -
        # with neither known there is NO DNS permit (never "port 53 to anywhere"); the redial then uses cached addresses
        if dns.uid is not None:
            lines += [f"    meta skuid {dns.uid} udp dport 53 {keep}", f"    meta skuid {dns.uid} tcp dport 53 {keep}"]
        elif dns.servers:
            d4, d6 = _split(dns.servers)
            for fam, lst in (("ip", d4), ("ip6", d6)):
                if lst:
                    lines += [f"    {fam} daddr {{ {', '.join(lst)} }} udp dport 53 {keep}",
                              f"    {fam} daddr {{ {', '.join(lst)} }} tcp dport 53 {keep}"]
    for fam, lst in (("ip", srv4), ("ip6", srv6)):
        if not lst:
            continue
        for proto, ports in server_rules(cfg.current):                  # VPN control/data channel + redialing, per VPN type
            if ports:
                plist = str(ports[0]) if len(ports) == 1 else "{ " + ", ".join(str(x) for x in ports) + " }"
                lines.append(f"    {fam} daddr {{ {', '.join(lst)} }} {proto} dport {plist} {keep}")
            else:
                lines.append(f"    {fam} daddr {{ {', '.join(lst)} }} meta l4proto {proto} {keep}")
    for fam, lst in (("ip", lan4), ("ip6", lan6)):
        for cidr in lst:
            lines.append(f"    {fam} daddr {cidr} {keep}")
    lines += [
        "  }",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    iifname lo accept",
    ]
    if tun_iface:
        lines.append(f'    iifname "{tun_iface}" accept')
    lines += [
        f"    ct state established,related ct mark {MARK} accept",      # replies to the flows allowed above
        "    udp sport 67 udp dport 68 accept",                           # DHCP replies (often broadcast, not tracked)
        "    udp sport 547 udp dport 546 accept",                         # DHCPv6 replies
        "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-redirect } accept",
    ]
    for fam, lst in (("ip", srv4), ("ip6", srv6)):                       # IPsec ESP / PPTP GRE from the server itself
        if lst:
            for proto, ports in server_rules(cfg.current):
                if not ports:
                    lines.append(f"    {fam} saddr {{ {', '.join(lst)} }} meta l4proto {proto} accept")
    for fam, lst in (("ip", lan4), ("ip6", lan6)):                       # lanAllow: both directions
        for cidr in lst:
            lines.append(f"    {fam} saddr {cidr} accept")
    lines += [
        "  }",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
    ]
    if tun_iface and vm_allowed:
        lines.append(f'    oifname "{tun_iface}" accept')                 # containers/VMs out through the tunnel only
        lines.append(f'    iifname "{tun_iface}" ct state established,related accept')
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def apply(ruleset: str) -> None:
    subprocess.run(["nft", "-f", "-"], input=ruleset, text=True, check=True)


def clear() -> None:
    subprocess.run(["nft", "delete", "table", *TABLE.split()], check=False, capture_output=True)


def is_active() -> bool:
    r = subprocess.run(["nft", "list", "table", *TABLE.split()], check=False, capture_output=True, text=True)
    return r.returncode == 0
