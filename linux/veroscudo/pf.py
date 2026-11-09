"""macOS kill-switch with pf (ALPHA - not yet run on a real Mac). render_ruleset() is pure; apply()/clear() call pfctl.

The rules live in the anchor com.apple/250.VeroScudo: the stock /etc/pf.conf evaluates `anchor "com.apple/*"`, so no
system file is edited. Every rule is `quick`, and the anchor ends with `block drop quick all`: once armed, a packet that
does not match an allow rule stops here, whatever later rules would say. pf is enabled with a reference token
(pfctl -E) that is released on clear, so a pf the user or another app enabled stays enabled."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .config import Config, server_rules
from .firewall import IFNAME, DnsPolicy, group_endpoints, split_families

ANCHOR = "com.apple/250.VeroScudo"
TOKEN = Path("/var/run/veroscudo-pf.token")
VM_TAG = "VEROSCUDO_VM"

# the one rule every VeroScudo anchor ends with; is_active() looks for it
_FINAL = "block drop quick all"
_BASE = [
    "pass quick on lo0 all",
    "pass out quick inet proto udp from any port 68 to any port 67 keep state (if-bound)",
    "pass in quick inet proto udp from any port 67 to any port 68",
    "pass out quick inet6 proto udp from any port 546 to any port 547 keep state (if-bound)",
    "pass quick inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv, routersol, routeradv }",
]


def render_ruleset(cfg: Config, server_ips: list[str], tun_iface: str | None, vm_allowed: bool,
                   dns: DnsPolicy | None = None, bridges: tuple[str, ...] = (), vms_free: bool = False,
                   endpoints: tuple = ()) -> str:
    """`endpoints` (a Hiddify profile): (address, port, protocols) Hiddify itself must reach outside the tunnel, in every
    state - firewall.render_ruleset says the same. `bridges` (scutil.vm_bridges: the host side of NAT/host-only VMs, e.g. bridge100) are passed in every state, both
    ways: VM <-> host (DHCP and DNS from the vmnet service) stays on this machine. With the VM setting on, a VM's way out is
    then judged like the host's own traffic on the interface it leaves by - the tunnel while it is up, nothing else while it
    is down (the forwarded packet meets the rules below on en0/utun). `vms_free` (Settings: VMs not protected): packets that
    came in from a VM are tagged and passed out on any interface - VeroScudo leaves them alone."""
    if tun_iface is not None and not IFNAME.match(tun_iface):
        raise ValueError(f"refusing interface name {tun_iface!r}")
    for b in bridges:
        if not IFNAME.match(b):
            raise ValueError(f"refusing bridge name {b!r}")
    dns = dns or DnsPolicy()
    srv4, srv6 = split_families(server_ips)
    lan4, lan6 = split_families(cfg.lan_allow)
    # states bound to the interface they were created on (if-bound): a flow that used the tunnel cannot continue over the
    # physical NIC once the tunnel is gone (pf's default floating states would let it)
    kb = "keep state (if-bound)"
    lines = _BASE[:1]
    if tun_iface:
        lines.append(f"pass quick on {tun_iface} all {kb}")
    lines += _BASE[1:]
    if bridges:
        bl = "{ " + " ".join(bridges) + " }"
        if vms_free:
            lines.append(f"pass in quick on {bl} all tag {VM_TAG} {kb}")
            lines.append(f"pass out quick on {bl} all {kb}")
            lines.append(f"pass out quick tagged {VM_TAG} {kb}")        # a VM's traffic, whichever way it leaves
        else:
            lines.append(f"pass quick on {bl} all {kb}")
    if not tun_iface:
        # macOS resolves through mDNSResponder; DNS only while blocked (redial), only to the network's resolvers
        # none known: no DNS permit at all (never "port 53 to anywhere")
        d4, d6 = split_families(dns.servers)
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
    for ver, port, protos, addrs in group_endpoints(endpoints):
        fam = "inet" if ver == 4 else "inet6"
        proto = protos[0] if len(protos) == 1 else "{ " + " ".join(protos) + " }"
        lines.append(f"pass out quick {fam} proto {proto} to {{ {', '.join(addrs)} }} port {port} {kb}")
    for fam, lst in (("inet", lan4), ("inet6", lan6)):
        for cidr in lst:
            lines.append(f"pass quick {fam} to {cidr} {kb}")
            lines.append(f"pass in quick {fam} from {cidr} {kb}")
    lines += [_FINAL, ""]
    return "\n".join(lines)


def render_lockdown() -> str:
    """Fail closed without a usable config.json: loopback, DHCP and neighbour discovery only."""
    return "\n".join(_BASE + [_FINAL, ""])


def _run(args: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["pfctl", *args], check=False, capture_output=True, text=True, **kw)


def enabled() -> bool:
    """pf itself is on. `pfctl -d` (by anyone as root, or another tool) turns it off with the anchor still listed."""
    r = _run(["-s", "info"])
    return r.returncode == 0 and re.search(r"^Status:\s*Enabled", r.stdout, re.MULTILINE) is not None


def _enable() -> None:
    r = _run(["-E"])
    m = re.search(r"Token\s*:\s*(\d+)", r.stdout + r.stderr)
    if m:
        TOKEN.write_text(m.group(1))


def apply(ruleset: str) -> None:
    # a token alone is not proof: pf may have been disabled since (pfctl -d) - then enable it again (a fresh token)
    if not TOKEN.exists() or not enabled():
        _enable()
    r = _run(["-a", ANCHOR, "-f", "-"], input=ruleset)
    if r.returncode != 0:
        raise subprocess.CalledProcessError(r.returncode, "pfctl", r.stdout, r.stderr)


def clear() -> None:
    _run(["-a", ANCHOR, "-F", "all"])
    if TOKEN.exists():
        _run(["-X", TOKEN.read_text().strip()])
        TOKEN.unlink(missing_ok=True)


def is_active() -> bool:
    """The anchor ends with the final block AND pf is enabled - listed rules in a disabled pf protect nothing. The daemon's
    watchdog re-applies (and re-enables) within 15 s when this turns false, as the Linux backend does after `nft flush`."""
    r = _run(["-a", ANCHOR, "-s", "rules"])
    return r.returncode == 0 and _FINAL in r.stdout.replace("  ", " ") and enabled()
