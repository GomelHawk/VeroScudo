"""nftables kill-switch. render_ruleset() is pure; apply()/clear() shell out to nft."""
from __future__ import annotations

import subprocess

from .config import Config

TABLE = "inet veroscudo"


def render_ruleset(cfg: Config, server_ips: list[str], tun_iface: str | None, vm_allowed: bool) -> str:
    """Default-drop output (and forward, for containers/VMs) with the documented allow-list."""
    srv = ", ".join(server_ips)
    lines = [
        f"table {TABLE}",
        f"delete table {TABLE}",
        f"table {TABLE} {{",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        "    oifname lo accept",
        "    ct state established,related accept",      # replies to allowed flows only; new flows still hit the rules below
    ]
    if tun_iface:
        lines.append(f'    oifname "{tun_iface}" accept')
    lines += [
        "    udp sport 68 udp dport 67 accept",                           # DHCP
        "    udp dport 53 accept",                                        # DNS (needed to resolve the VPN server)
        "    tcp dport 53 accept",
        "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report } accept",
    ]
    if srv:
        lines.append(f"    ip daddr {{ {srv} }} {cfg.protocol} dport {cfg.port} accept")   # VPN control channel + redialing
    for cidr in cfg.lan_allow:
        lines.append(f"    ip daddr {cidr} accept")
    lines += [
        "  }",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
    ]
    if tun_iface and vm_allowed:
        lines.append(f'    oifname "{tun_iface}" accept')                 # containers/VMs out through the tunnel only
        lines.append("    ct state established,related accept")
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def apply(ruleset: str) -> None:
    subprocess.run(["nft", "-f", "-"], input=ruleset, text=True, check=True)


def clear() -> None:
    subprocess.run(["nft", "delete", "table", *TABLE.split()], check=False, capture_output=True)


def is_active() -> bool:
    r = subprocess.run(["nft", "list", "table", *TABLE.split()], check=False, capture_output=True, text=True)
    return r.returncode == 0
