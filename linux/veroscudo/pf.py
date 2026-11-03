"""macOS kill-switch with pf (ALPHA - not yet run on a real Mac). render_ruleset() is pure; apply()/clear() call pfctl.

The rules live in the anchor com.apple/250.VeroScudo: the stock /etc/pf.conf evaluates `anchor "com.apple/*"`, so no
system file is edited. Every rule is `quick`, and the anchor ends with `block drop quick all`: once armed, a packet that
does not match an allow rule stops here, whatever later rules would say. pf is enabled with a reference token
(pfctl -E) that is released on clear, so a pf the user or another app enabled stays enabled."""
from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

from .config import Config, server_rules
from .firewall import DnsPolicy

ANCHOR = "com.apple/250.VeroScudo"
TOKEN = Path("/var/run/veroscudo-pf.token")
_IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def _split(addrs) -> tuple[list[str], list[str]]:
    v4, v6 = [], []
    for a in addrs:
        net = ipaddress.ip_network(str(a), strict=False)
        (v4 if net.version == 4 else v6).append(str(a))
    return v4, v6


def render_ruleset(cfg: Config, server_ips: list[str], tun_iface: str | None, vm_allowed: bool,
                   dns: DnsPolicy | None = None) -> str:
    if tun_iface is not None and not _IFNAME.match(tun_iface):
        raise ValueError(f"refusing interface name {tun_iface!r}")
    dns = dns or DnsPolicy()
    srv4, srv6 = _split(server_ips)
    lan4, lan6 = _split(cfg.lan_allow)
    # states bound to the interface they were created on (if-bound): a flow that used the tunnel cannot continue over the
    # physical NIC once the tunnel is gone (pf's default floating states would let it)
    kb = "keep state (if-bound)"
    lines = ["pass quick on lo0 all"]
    if tun_iface:
        lines.append(f"pass quick on {tun_iface} all {kb}")
    lines += [
        f"pass out quick inet proto udp from any port 68 to any port 67 {kb}",
        "pass in quick inet proto udp from any port 67 to any port 68",
        f"pass out quick inet6 proto udp from any port 546 to any port 547 {kb}",
        "pass quick inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv, routersol, routeradv }",
    ]
    if not tun_iface:
        # macOS resolves through mDNSResponder; DNS only while blocked (redial), only to the network's resolvers
        # none known: no DNS permit at all (never "port 53 to anywhere")
        d4, d6 = _split(dns.servers)
        for fam, lst in (("inet", d4), ("inet6", d6)):
            if lst:
                lines.append(f"pass out quick {fam} proto {{ udp tcp }} to {{ {', '.join(lst)} }} port 53 {kb}")
    for fam, lst in (("inet", srv4), ("inet6", srv6)):
        if not lst:
            continue
        for proto, ports in server_rules(cfg.current):
            if ports:
                plist = str(ports[0]) if len(ports) == 1 else "{ " + " ".join(str(x) for x in ports) + " }"
                lines.append(f"pass out quick {fam} proto {proto} to {{ {', '.join(lst)} }} port {plist} {kb}")
            else:
                lines.append(f"pass out quick {fam} proto {proto} to {{ {', '.join(lst)} }} {kb}")
    for fam, lst in (("inet", lan4), ("inet6", lan6)):
        for cidr in lst:
            lines.append(f"pass quick {fam} to {cidr} {kb}")
            lines.append(f"pass in quick {fam} from {cidr} {kb}")
    lines += ["block drop quick all", ""]
    return "\n".join(lines)


def apply(ruleset: str) -> None:
    if not TOKEN.exists():
        r = subprocess.run(["pfctl", "-E"], check=False, capture_output=True, text=True)
        m = re.search(r"Token\s*:\s*(\d+)", r.stdout + r.stderr)
        if m:
            TOKEN.write_text(m.group(1))
    subprocess.run(["pfctl", "-a", ANCHOR, "-f", "-"], input=ruleset, text=True, check=True, capture_output=True)


def clear() -> None:
    subprocess.run(["pfctl", "-a", ANCHOR, "-F", "all"], check=False, capture_output=True)
    if TOKEN.exists():
        subprocess.run(["pfctl", "-X", TOKEN.read_text().strip()], check=False, capture_output=True)
        TOKEN.unlink(missing_ok=True)


def is_active() -> bool:
    r = subprocess.run(["pfctl", "-a", ANCHOR, "-s", "rules"], check=False, capture_output=True, text=True)
    return r.returncode == 0 and "block drop quick all" in r.stdout.replace("  ", " ")
