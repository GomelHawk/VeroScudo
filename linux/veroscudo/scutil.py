"""macOS VPN control through `scutil --nc` (ALPHA - not yet run on a real Mac). Same interface as nm.py.

Works with the VPN services macOS itself manages (System Settings > VPN: IKEv2, L2TP, Cisco IPSec); the password stays in
the macOS keychain. macOS reports no "user hung up" reason, so every drop is treated as a failure: the machine stays
blocked and redials until `sudo veroscudo off` - strict, never open."""
from __future__ import annotations

import re
import subprocess
import time

from . import hiddify
from .netutil import IFNAME as _IFNAME
from .netutil import nameservers, resolve  # noqa: F401  (part of this backend's contract)


def _status(profile: str) -> str:
    return subprocess.run(["scutil", "--nc", "status", profile], check=False, capture_output=True, text=True).stdout


def is_connected(profile: str) -> bool:
    if hiddify.is_profile(profile):
        return hiddify.connected(profile)       # Hiddify runs and a utun holds its tun address
    out = _status(profile)
    return bool(out) and out.splitlines()[0].strip() == "Connected"


def parse_iface(text: str) -> str | None:
    """The tunnel interface (ipsec0, ppp0, utunN) in `scutil --nc status` output; only virtual interfaces are accepted
    (a physical one is never "the tunnel"). Pure."""
    m = re.search(r"InterfaceName\s*:\s*(\S+)", text)
    if m and _IFNAME.match(m.group(1)) and re.match(r"^(ipsec|ppp|utun|tun)\d+$", m.group(1)):
        return m.group(1)
    return None


def iface(profile: str) -> str | None:
    """The tunnel interface from the extended status (a Hiddify profile: the utun holding Hiddify's tun address)."""
    if hiddify.is_profile(profile):
        return hiddify.iface(profile)
    return parse_iface(_status(profile))


def up(profile: str) -> bool:
    if hiddify.is_profile(profile):
        return is_connected(profile)            # connected in Hiddify only - VeroScudo never starts it
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
    if hiddify.is_profile(profile):
        return True                             # VeroScudo never stops Hiddify
    r = subprocess.run(["scutil", "--nc", "stop", profile], check=False, capture_output=True, text=True)
    return r.returncode == 0


def resolver_uid() -> int | None:
    return None                               # pf matches users only on local sockets; DNS is scoped by destination instead


def nm_dns() -> list[str]:
    return []                                 # resolvers come from resolv.conf on macOS


def watch(profiles, on_up, on_down, interval: float = 2.0, on_auth=None) -> None:
    """Polling: macOS has no reason code, so a drop is reported as a failure (`veroscudo off` sets its own marker).
    on_auth is never called: `scutil --nc status` gives no reason for a failed connect (to be checked on a real Mac)."""
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


def kind(profile: str) -> str | None:
    """macOS VPN services here are the built-in kinds (IKEv2, L2TP, Cisco IPSec); a Hiddify profile is 'hiddify'."""
    return hiddify.KIND if hiddify.is_profile(profile) else "vpn"


def is_stale(profile: str) -> bool:
    return False


def wait_connected(profile: str, seconds: float = 10.0) -> bool:
    return is_connected(profile)          # `up` already waits for the outcome


def other_tunnels(own: str | None) -> list[str]:
    """Bare tunnel interfaces are not reported on macOS: the system keeps utun0-utun3 up for itself (iCloud, Handoff), so
    an up utunN says nothing. Other VPNs are found by their service instead (tunnel_owners)."""
    return []


def connected_services(listing: str) -> list[str]:
    """`scutil --nc list` -> the names of the services that are connected right now. Pure."""
    return [s["name"] for s in parse_list(listing) if s["status"] == "Connected"]


def tunnel_owners() -> dict[str, str]:
    """Tunnel interface -> the connected VPN service that owns it (System Settings > VPN, and app VPNs listed there), so
    the tray can name another VPN and offer to disconnect it. {} when scutil cannot be asked."""
    try:
        listing = subprocess.run(["scutil", "--nc", "list"], check=False, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        listing = ""
    out = {}
    for name in connected_services(listing):
        try:
            ifc = parse_iface(_status(name))
        except (OSError, subprocess.SubprocessError):
            continue
        if ifc:
            out[ifc] = name
    out.update(hiddify.owners())                # Hiddify's utun, imported or not (its own service name, if any, is replaced)
    return out


def down_argv(name: str) -> list[str]:
    """Disconnects a VPN service as the signed-in user (System Settings > VPN services may be stopped by their user)."""
    return ["scutil", "--nc", "stop", name]


_VMIF = re.compile(r"^(bridge\d+|vmnet\d+|vnic\d+)$")
_PHYS = re.compile(r"^en\d+$")


def parse_bridges(text: str) -> list[str]:
    """`ifconfig` -> the host-side interfaces of VMs on NAT or host-only networks. Pure.

    bridgeN: the vmnet framework (Parallels, VMware Fusion, UTM, Lima, Docker Desktop's VM) - qualifies only while none of
    its members is a physical port (enN): a bridged-mode VM (bridge + en0) or the Thunderbolt Bridge (bridge0 + en1, en2)
    puts frames straight onto the wire, past pf - allowing it would open the kill-switch to the LAN, the same rule as
    nm.vm_bridges on Linux. vmnetN (older VMware Fusion) and vnicN (older Parallels) are host-side interfaces, always NAT
    or host-only."""
    out, name, phys = [], None, False
    for line in text.splitlines() + [""]:
        m = re.match(r"^(\S+?):\s+flags=", line)
        if m or line == "":
            if name and _VMIF.match(name) and _IFNAME.match(name) and not phys:
                out.append(name)
            name, phys = (m.group(1), False) if m else (None, False)
            continue
        mm = re.match(r"^\s+member:\s+(\S+)", line)
        if mm and _PHYS.match(mm.group(1)):
            phys = True
    return out


def live_endpoints(profile: str) -> list[str]:
    return []                             # the macOS VPN services here are IKEv2/L2TP/IPSec: their server is the profile's


def vm_bridges() -> list[str]:
    try:
        r = subprocess.run(["ifconfig"], check=False, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return parse_bridges(r.stdout)


def check(cfg) -> list[str]:
    out = []
    for p in cfg.profiles:
        if p.vpn_type == hiddify.KIND:
            out += hiddify.check_profile(p.name, p.config_path)
        elif not _status(p.name):
            out.append(f"{p.name}: no VPN service with this name (System Settings > VPN)")
    return out


# ---- import from macOS (veroscudo import)
_LIST = re.compile(r'^\*?\s*\((?P<status>[^)]*)\)\s+(?P<id>[0-9A-Fa-f-]{36})\s+(?P<what>.*?)\s+"(?P<name>[^"]+)"\s+\[(?P<kind>[^\]]+)\]\s*$')
_KINDS = {"PPP/L2TP": "l2tp", "PPP/PPTP": "pptp", "IPSec": "ipsec", "VPN/IKEv2": "ikev2", "IKEv2": "ikev2"}


def parse_list(text: str) -> list[dict]:
    """`scutil --nc list` -> [{name, id, kind, status}]; kind '' = a VPN type VeroScudo does not handle (an app's own VPN);
    status: Connected, Disconnected, Connecting ... Pure."""
    out = []
    for line in text.splitlines():
        m = _LIST.match(line.strip())
        if m:
            k = m.group("kind")
            out.append({"name": m.group("name"), "id": m.group("id"), "kind": _KINDS.get(k, "ikev2" if "IKEv2" in k else ""),
                        "status": m.group("status").strip()})
    return out


def parse_server(text: str) -> str:
    """The server address from `scutil --nc show <id>` (RemoteAddress / CommRemoteAddress / ServerAddress). Pure."""
    for key in ("RemoteAddress", "CommRemoteAddress", "ServerAddress"):
        m = re.search(rf"\b{key}\s*:\s*(\S+)", text)
        if m:
            return m.group(1)
    return ""


def discover() -> list[dict]:
    out = hiddify.discover()
    for s in parse_list(subprocess.run(["scutil", "--nc", "list"], check=False, capture_output=True, text=True).stdout):
        if out and "hiddify" in s["name"].lower():
            continue                           # Hiddify's own network extension: imported from its config file instead
        d = {"name": s["name"], "vpn_type": s["kind"], "server": "", "port": 4500, "protocol": "udp", "username": "", "note": ""}
        if not s["kind"]:
            d["note"] = "VPN type not supported by VeroScudo (an app's own VPN)"
        else:
            d["server"] = parse_server(subprocess.run(["scutil", "--nc", "show", s["id"]], check=False, capture_output=True, text=True).stdout)
            if s["kind"] == "pptp":
                d.update(port=1723, protocol="tcp")
            if not d["server"]:
                d["note"] = "no server found in the service"
        out.append(d)
    return out
