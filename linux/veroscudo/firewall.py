"""nftables kill-switch. render_ruleset() is pure; apply()/clear() shell out to nft.

A separate table with `policy drop` base chains: in nftables a packet must be accepted by every base chain on a hook, so
a drop here is final whatever other tables (ufw, docker, firewalld) accept."""
from __future__ import annotations

import ipaddress
import logging
import pwd
import re
import subprocess
from dataclasses import dataclass, field

from .config import Config, server_rules
from .netutil import IFNAME, plain_ip, plain_net, rule_token

log = logging.getLogger("veroscudo")

_CGROUP = re.compile(r"^[A-Za-z0-9_.@-]+(/[A-Za-z0-9_.@-]+){0,7}\Z")   # a cgroup path: nothing that could end a rule

TABLE = "inet veroscudo"


@dataclass(frozen=True)
class DnsPolicy:
    """Who may send DNS while blocked (redial needs to resolve the server): the system resolver's uid, else only the
    configured upstream resolvers; with neither known there is no DNS permit.
    names: the VPN server's host names - then only a UDP query for exactly one of them gets out (qname_match): the names of
    the sites you visit stay inside while the VPN redials. () = no DNS at all (a server given as an address; Hiddify, which
    VeroScudo does not dial). None = not narrowed."""
    uid: int | None = None
    servers: tuple[str, ...] = field(default_factory=tuple)
    names: tuple[str, ...] | None = None
    window: bool = False           # pf only: the redial's own lookup of the server is running (daemon.prime_dns)


def matches_dns_names() -> bool:
    """nftables can let out a DNS query for one name only (qname_match); pf cannot - there DNS is open only for the
    redial's own lookup of the server, right before each dial (daemon.prime_dns)."""
    return True


_LABEL = re.compile(r"^[A-Za-z0-9_-]{1,63}\Z")


def qname_match(name: str) -> str:
    """An nft match for a DNS query of exactly `name`: over UDP the question's name starts 20 bytes into the transport header
    (8 of UDP, 12 of the DNS header), in the wire form (length-prefixed labels, ending in a zero byte - so "vpn.example.com"
    never matches "vpn.example.com.other"). Compared in pieces of at most 16 bytes, nft's widest raw-payload match."""
    labels = name.rstrip(".").split(".")
    if not all(_LABEL.match(x) for x in labels) or len(name) > 253:
        raise ValueError(f"refusing DNS name {name!r}")
    wire = b"".join(bytes([len(x)]) + x.encode("ascii") for x in labels) + b"\0"
    parts, bit = [], 160
    for i in range(0, len(wire), 16):
        chunk = wire[i:i + 16]
        parts.append(f"@th,{bit},{len(chunk) * 8} 0x{chunk.hex()}")
        bit += len(chunk) * 8
    return " ".join(parts)


def split_families(addrs) -> tuple[list[str], list[str]]:
    """IPv4 and IPv6 entries apart, each in its canonical form (shared with the pf backend). Raises ValueError on anything
    that is not a plain address or network - these strings are written into the ruleset."""
    v4, v6 = [], []
    for a in addrs:
        s = str(a)
        text = rule_token(plain_net(s) if "/" in s else plain_ip(s))
        (v4 if ipaddress.ip_network(text, strict=False).version == 4 else v6).append(text)
    return v4, v6


MARK = "0x5653"          # conntrack mark of flows VeroScudo allowed outside the tunnel ("VS")
# DNS while blocked has a mark of its own, and flows with it are accepted only in the rulesets without a tunnel: a
# connection to the network's resolver that was opened while blocked ends when the tunnel comes up, instead of going
# on outside it for as long as it lives
MARK_DNS = "0x5654"


def group_endpoints(endpoints) -> list[tuple[int, int, tuple[str, ...], list[str]]]:
    """Per-endpoint permits (a Hiddify profile: (address, port, protocols) from its live config) grouped into
    (family, port, protocols, addresses) - one rule each. Every address is checked again here. Pure; shared with pf."""
    groups: dict[tuple[int, int, tuple[str, ...]], list[str]] = {}
    for addr, port, protos in endpoints:
        a = ipaddress.ip_address(rule_token(plain_ip(addr)))      # raises on anything that is not a plain address
        port = int(port)
        if not 1 <= port <= 65535 or not protos or any(x not in ("tcp", "udp") for x in protos):
            raise ValueError(f"refusing endpoint {addr!r} {port!r} {protos!r}")
        lst = groups.setdefault((a.version, port, tuple(sorted(protos))), [])
        if str(a) not in lst:
            lst.append(str(a))
    return [(fam, port, protos, addrs) for (fam, port, protos), addrs in sorted(groups.items())]


def render_ruleset(cfg: Config, server_ips: list[str], tun_iface: str | None, vm_allowed: bool,
                   dns: DnsPolicy | None = None, bridges: tuple[str, ...] = (), vms_free: bool = False,
                   endpoints: tuple = (), cgroup: tuple[str, int] | None = None) -> str:
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
    keep_dns = f"ct mark set {MARK_DNS} accept"
    brset = "{ " + ", ".join(f'"{b}"' for b in bridges) + " }" if bridges else None
    lines = [
        f"table {TABLE}",
        f"delete table {TABLE}",
        f"table {TABLE} {{",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        "    oifname lo accept",
        "    fib daddr type local accept",                               # to this machine's own addresses: never leaves it
    ]
    if tun_iface:
        lines.append(f'    oifname "{tun_iface}" accept')
    if brset:
        lines.append(f"    oifname {brset} accept")                      # host -> containers/VMs (stays on this machine)
    lines += [
        f"    ct state established,related ct mark {MARK} accept",      # only flows VeroScudo allowed itself
        *([] if tun_iface else [f"    ct state established,related ct mark {MARK_DNS} accept"]),   # DNS: only while down
        f"    meta skuid {dhcp_uids()} udp sport 68 udp dport 67 {keep}",      # DHCP: only the DHCP clients
        f"    meta skuid {dhcp_uids()} udp sport 546 udp dport 547 {keep}",    # DHCPv6
        "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report } accept",
    ]
    if not tun_iface:
        # DNS only while down (to find the VPN server): the system resolver's user, else only the known resolvers -
        # with neither known there is NO DNS permit (never "port 53 to anywhere"); the redial then uses cached addresses
        who = [f"meta skuid {dns.uid}"] if dns.uid is not None else [
            f"{fam} daddr {{ {', '.join(lst)} }}" for fam, lst in zip(("ip", "ip6"), split_families(dns.servers)) if lst]
        if dns.names is not None:
            # only the VPN server's own name, UDP, in the case it is written and in lower case (the resolver passes the
            # name on as it got it)
            for n in sorted({n.rstrip(".") for n in dns.names} | {n.rstrip(".").lower() for n in dns.names}):
                lines += [f"    {w} udp dport 53 {qname_match(n)} {keep_dns}" for w in who]
        elif dns.uid is not None:
            lines += [f"    meta skuid {dns.uid} udp dport 53 {keep_dns}", f"    meta skuid {dns.uid} tcp dport 53 {keep_dns}"]
        elif dns.servers:
            d4, d6 = split_families(dns.servers)
            for fam, lst in (("ip", d4), ("ip6", d6)):
                if lst:
                    lines += [f"    {fam} daddr {{ {', '.join(lst)} }} udp dport 53 {keep_dns}",
                              f"    {fam} daddr {{ {', '.join(lst)} }} tcp dport 53 {keep_dns}"]
    # WireGuard (NetworkManager): its packets carry fwmark 0xcafd, which NetworkManager saves into the conntrack mark
    # (mangle OUTPUT, before this chain) and restores on the server's replies so they are routed outside the tunnel.
    # Setting VeroScudo's ct mark here would overwrite it: the replies would be routed wrongly and dropped. So the
    # WireGuard server's own address and port are allowed without our mark, and its replies explicitly in input.
    wg = cfg.current.vpn_type == "wireguard"
    for fam, lst in (("ip", srv4), ("ip6", srv6)):
        if not lst:
            continue
        for proto, ports in server_rules(cfg.current):                  # VPN control/data channel + redialing, per VPN type
            if ports:
                plist = str(ports[0]) if len(ports) == 1 else "{ " + ", ".join(str(x) for x in ports) + " }"
                lines.append(f"    {fam} daddr {{ {', '.join(lst)} }} {proto} dport {plist} {'accept' if wg else keep}")
            else:
                lines.append(f"    {fam} daddr {{ {', '.join(lst)} }} meta l4proto {proto} {keep}")
    # Hiddify: its core (sing-box, auto_redirect) keeps its own conntrack mark on its connections and routes their replies
    # by it - VeroScudo's mark would overwrite it (as with WireGuard above), so these permits leave the mark alone and the
    # replies are let in explicitly (input chain)
    cg_match = None
    if cgroup:                                                          # Hiddify's root service, to any address (hiddify.py)
        path, cid = cgroup
        if not _CGROUP.match(path) or {".", ".."} & set(path.split("/")) or not isinstance(cid, int):
            raise ValueError(f"unsafe cgroup path {path!r}")
        cg_match = f'socket cgroupv2 level {path.count("/") + 1} "{path}"'
        lines.append(f'    {cg_match} accept comment "Hiddify core, cgroup {cid}"')
    groups = group_endpoints(endpoints)
    for ver, port, protos, addrs in groups:                             # Hiddify: its servers and direct DNS servers
        fam = "ip" if ver == 4 else "ip6"
        l4 = f"{protos[0]} dport {port}" if len(protos) == 1 else f"meta l4proto {{ {', '.join(protos)} }} th dport {port}"
        lines.append(f"    {fam} daddr {{ {', '.join(addrs)} }} {l4} accept")
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
        *([] if tun_iface else [f"    ct state established,related ct mark {MARK_DNS} accept"]),   # DNS answers: only while down
        "    udp sport 67 udp dport 68 accept",                           # DHCP replies (often broadcast, not tracked)
        "    udp sport 547 udp dport 546 accept",                         # DHCPv6 replies
        "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-redirect } accept",
    ]
    for fam, lst in (("ip", srv4), ("ip6", srv6)):                       # IPsec ESP / PPTP GRE from the server itself
        if lst:
            for proto, ports in server_rules(cfg.current):
                if not ports:
                    lines.append(f"    {fam} saddr {{ {', '.join(lst)} }} meta l4proto {proto} accept")
                elif wg:                                                 # WireGuard: the server's replies (see output) -
                    # replies only: a forged sender address must not reach the host's own UDP services
                    plist = str(ports[0]) if len(ports) == 1 else "{ " + ", ".join(str(x) for x in ports) + " }"
                    lines.append(f"    {fam} saddr {{ {', '.join(lst)} }} {proto} sport {plist} ct state established,related accept")
    if cg_match:                                                        # Hiddify: replies to its core's own sockets
        lines.append(f"    {cg_match} ct state established,related accept")
    for ver, port, protos, addrs in groups:                             # Hiddify: replies from its servers (see output)
        fam = "ip" if ver == 4 else "ip6"
        l4 = f"{protos[0]} sport {port}" if len(protos) == 1 else f"meta l4proto {{ {', '.join(protos)} }} th sport {port}"
        lines.append(f"    {fam} saddr {{ {', '.join(addrs)} }} {l4} ct state established,related accept")
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


def dhcp_uids() -> str:
    """Who may send DHCP: root (NetworkManager, dhclient) and the users DHCP clients drop to where they exist
    (systemd-networkd, dhcpcd) - no other program may use the DHCP permit to reach a server outside the tunnel."""
    uids = [0]
    for name in ("systemd-network", "dhcpcd", "_dhcpcd"):
        try:
            uids.append(pwd.getpwnam(name).pw_uid)
        except KeyError:
            pass
    return "{ " + ", ".join(str(u) for u in sorted(set(uids))) + " }"


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
        f"    meta skuid {dhcp_uids()} udp sport 68 udp dport 67 accept",
        f"    meta skuid {dhcp_uids()} udp sport 546 udp dport 547 accept",
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
    """One transaction: all of it or nothing. A refused ruleset raises CalledProcessError; what nft said goes to the log
    (not to the terminal of whoever ran the command)."""
    r = subprocess.run(["nft", "-f", "-"], input=ruleset, text=True, check=False, capture_output=True)
    if r.returncode != 0:
        said = " | ".join((r.stderr or "").strip().splitlines()[:4])[:400]
        log.error("nft refused the ruleset (exit %s): %s", r.returncode, said or "no message")
        raise subprocess.CalledProcessError(r.returncode, "nft", r.stdout, r.stderr)


def clear() -> None:
    subprocess.run(["nft", "delete", "table", *TABLE.split()], check=False, capture_output=True)


def is_active() -> bool:
    r = subprocess.run(["nft", "list", "table", *TABLE.split()], check=False, capture_output=True, text=True)
    return r.returncode == 0
