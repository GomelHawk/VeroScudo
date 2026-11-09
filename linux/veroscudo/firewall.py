"""nftables kill-switch. render_ruleset() is pure; apply()/clear() shell out to nft.

A separate table with `policy drop` base chains: in nftables a packet must be accepted by every base chain on a hook, so
a drop here is final whatever other tables (ufw, docker, firewalld) accept."""
from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass, field

from .config import Config, server_rules
from .netutil import IFNAME  # also re-exported for the pf backend

TABLE = "inet veroscudo"


@dataclass(frozen=True)
class DnsPolicy:
    """Who may send DNS while blocked (redial needs to resolve the server): the system resolver's uid, else only the
    configured upstream resolvers, else (logged) any destination."""
    uid: int | None = None
    servers: tuple[str, ...] = field(default_factory=tuple)


def split_families(addrs) -> tuple[list[str], list[str]]:
    """IPv4 and IPv6 entries apart (shared with the pf backend)."""
    v4, v6 = [], []
    for a in addrs:
        net = ipaddress.ip_network(str(a), strict=False)          # raises on anything that is not an address/network
        (v4 if net.version == 4 else v6).append(str(a))
    return v4, v6


MARK = "0x5653"          # conntrack mark of flows VeroScudo allowed outside the tunnel ("VS")


def group_endpoints(endpoints) -> list[tuple[int, int, tuple[str, ...], list[str]]]:
    """Per-endpoint permits (a Hiddify profile: (address, port, protocols) from its live config) grouped into
    (family, port, protocols, addresses) - one rule each. Every address is checked again here. Pure; shared with pf."""
    groups: dict[tuple[int, int, tuple[str, ...]], list[str]] = {}
    for addr, port, protos in endpoints:
        a = ipaddress.ip_address(str(addr))                       # raises on anything that is not an address
        port = int(port)
        if not 1 <= port <= 65535 or not protos or any(x not in ("tcp", "udp") for x in protos):
            raise ValueError(f"refusing endpoint {addr!r} {port!r} {protos!r}")
        lst = groups.setdefault((a.version, port, tuple(sorted(protos))), [])
        if str(a) not in lst:
            lst.append(str(a))
    return [(fam, port, protos, addrs) for (fam, port, protos), addrs in sorted(groups.items())]


def render_ruleset(cfg: Config, server_ips: list[str], tun_iface: str | None, vm_allowed: bool,
                   dns: DnsPolicy | None = None, bridges: tuple[str, ...] = (), vms_free: bool = False,
                   endpoints: tuple = ()) -> str:
    """Default-drop output, input and forward (containers/VMs) with the documented allow-list. DNS is allowed only while
    the tunnel is down: while it is up, name resolution goes through the tunnel like everything else (no DNS leak).

    `bridges` (nm.vm_bridges: host-only bridges such as docker0, virbr0) carry traffic that never leaves the machine -
    host <-> container, container <-> container on one bridge (br_netfilter sends those frames through the forward
    hook too), a VM's DHCP/DNS from libvirt's dnsmasq. That is allowed in every state, like loopback. Their way out
    stays the tunnel only (`vm_allowed`, up only): a bridge is never forwarded to the physical card. `vms_free` (Settings:
    VMs and containers not protected): VeroScudo leaves them alone - forwarding is not filtered at all.

    Every explicit permit outside the tunnel marks its connection; established traffic is accepted only with that mark. So a
    flow that used the tunnel (a connected UDP socket, a TCP socket bound to the tunnel address) cannot carry on over the
    physical NIC once the tunnel is gone - it was never marked. Inbound: nothing but replies to marked flows, the tunnel,
    DHCP replies and neighbour discovery: the host is not reachable over the physical network while armed.

    `endpoints` (a Hiddify profile): (address, port, protocols) the VPN app itself must reach outside the tunnel - its
    servers and its direct DNS servers - allowed in every state, like a server permit."""
    if tun_iface is not None and not IFNAME.match(tun_iface):
        raise ValueError(f"refusing interface name {tun_iface!r}")
    for b in bridges:
        if not IFNAME.match(b):
            raise ValueError(f"refusing bridge name {b!r}")
    dns = dns or DnsPolicy()
    srv4, srv6 = split_families(server_ips)
    lan4, lan6 = split_families(cfg.lan_allow)
    keep = f"ct mark set {MARK} accept"
    brset = "{ " + ", ".join(f'"{b}"' for b in bridges) + " }" if bridges else None
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
    if brset:
        lines.append(f"    oifname {brset} accept")                      # host -> containers/VMs (stays on this machine)
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
            d4, d6 = split_families(dns.servers)
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
    for ver, port, protos, addrs in group_endpoints(endpoints):        # Hiddify: its servers and direct DNS servers
        fam = "ip" if ver == 4 else "ip6"
        l4 = f"{protos[0]} dport {port}" if len(protos) == 1 else f"meta l4proto {{ {', '.join(protos)} }} th dport {port}"
        lines.append(f"    {fam} daddr {{ {', '.join(addrs)} }} {l4} {keep}")
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
    if brset:
        lines.append(f"    iifname {brset} accept")                      # containers/VMs -> host (DHCP/DNS from dnsmasq, services)
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
        f"    type filter hook forward priority 0; policy {'accept' if vms_free else 'drop'};",
    ]
    if brset and not vms_free:
        lines.append(f"    iifname {brset} oifname {brset} accept")       # container <-> container, bridge <-> bridge: on this machine
    if tun_iface and vm_allowed and not vms_free:
        lines.append(f'    oifname "{tun_iface}" accept')                 # containers/VMs out through the tunnel only
        lines.append(f'    iifname "{tun_iface}" ct state established,related accept')
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def render_lockdown() -> str:
    """Fail closed without a usable config.json: loopback, DHCP and neighbour discovery only (the machine can get an
    address, nothing else leaves it). Applied by `boot`/`daemon` when the machine is armed but the config cannot be read."""
    return "\n".join([
        f"table {TABLE}",
        f"delete table {TABLE}",
        f"table {TABLE} {{",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        "    oifname lo accept",
        "    udp sport 68 udp dport 67 accept",
        "    udp sport 546 udp dport 547 accept",
        "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept",
        "  }",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    iifname lo accept",
        "    udp sport 67 udp dport 68 accept",
        "    udp sport 547 udp dport 546 accept",
        "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-redirect } accept",
        "  }",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        "  }",
        "}",
        "",
    ])


def apply(ruleset: str) -> None:
    subprocess.run(["nft", "-f", "-"], input=ruleset, text=True, check=True)


def clear() -> None:
    subprocess.run(["nft", "delete", "table", *TABLE.split()], check=False, capture_output=True)


def is_active() -> bool:
    r = subprocess.run(["nft", "list", "table", *TABLE.split()], check=False, capture_output=True, text=True)
    return r.returncode == 0
