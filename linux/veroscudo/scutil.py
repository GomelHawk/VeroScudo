"""macOS VPN control through `scutil --nc` (ALPHA - not yet run on a real Mac). Same interface as nm.py.

Works with the VPN services macOS itself manages (System Settings > VPN: IKEv2, L2TP, Cisco IPSec); the password stays in
the macOS keychain. macOS reports no "user hung up" reason, so every drop is treated as a failure: the machine stays
blocked and redials until `sudo veroscudo off` - strict, never open."""
from __future__ import annotations

import re
import subprocess
import time

from .netutil import IFNAME as _IFNAME  # noqa: F401  (part of this backend's contract)
from .netutil import nameservers, resolve  # noqa: F401


def _status(profile: str) -> str:
    return subprocess.run(["scutil", "--nc", "status", profile], check=False, capture_output=True, text=True).stdout


def is_connected(profile: str) -> bool:
    out = _status(profile)
    return bool(out) and out.splitlines()[0].strip() == "Connected"


def iface(profile: str) -> str | None:
    """The tunnel interface (ipsec0, ppp0, utunN) from the extended status; only virtual interfaces are accepted."""
    m = re.search(r"InterfaceName\s*:\s*(\S+)", _status(profile))
    if m and _IFNAME.match(m.group(1)) and re.match(r"^(ipsec|ppp|utun|tun)\d+$", m.group(1)):
        return m.group(1)
    return None


def up(profile: str) -> bool:
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
    r = subprocess.run(["scutil", "--nc", "stop", profile], check=False, capture_output=True, text=True)
    return r.returncode == 0


def resolver_uid() -> int | None:
    return None                               # pf matches users only on local sockets; DNS is scoped by destination instead


def nm_dns() -> list[str]:
    return []                                 # resolvers come from resolv.conf on macOS


def watch(profiles, on_up, on_down, interval: float = 2.0) -> None:
    """Polling: macOS has no reason code, so a drop is reported as a failure (`veroscudo off` sets its own marker)."""
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
    """macOS VPN services here are the built-in kinds (IKEv2, L2TP, Cisco IPSec)."""
    return "vpn"


def is_stale(profile: str) -> bool:
    return False


def wait_connected(profile: str, seconds: float = 10.0) -> bool:
    return is_connected(profile)          # `up` already waits for the outcome


def other_tunnels(own: str | None) -> list[str]:
    return []


def vm_bridges() -> list[str]:
    return []                             # VMs/containers are not filtered on macOS (alpha)


def check(cfg) -> list[str]:
    return [f"{p.name}: no VPN service with this name (System Settings > VPN)" for p in cfg.profiles if not _status(p.name)]


# ---- import from macOS (veroscudo import)
_LIST = re.compile(r'^\*?\s*\((?P<status>[^)]*)\)\s+(?P<id>[0-9A-Fa-f-]{36})\s+(?P<what>.*?)\s+"(?P<name>[^"]+)"\s+\[(?P<kind>[^\]]+)\]\s*$')
_KINDS = {"PPP/L2TP": "l2tp", "PPP/PPTP": "pptp", "IPSec": "ipsec", "VPN/IKEv2": "ikev2", "IKEv2": "ikev2"}


def parse_list(text: str) -> list[dict]:
    """`scutil --nc list` -> [{name, id, kind}]; kind '' = a VPN type VeroScudo does not handle (an app's own VPN). Pure."""
    out = []
    for line in text.splitlines():
        m = _LIST.match(line.strip())
        if m:
            k = m.group("kind")
            out.append({"name": m.group("name"), "id": m.group("id"), "kind": _KINDS.get(k, "ikev2" if "IKEv2" in k else "")})
    return out


def parse_server(text: str) -> str:
    """The server address from `scutil --nc show <id>` (RemoteAddress / CommRemoteAddress / ServerAddress). Pure."""
    for key in ("RemoteAddress", "CommRemoteAddress", "ServerAddress"):
        m = re.search(rf"\b{key}\s*:\s*(\S+)", text)
        if m:
            return m.group(1)
    return ""


def discover() -> list[dict]:
    out = []
    for s in parse_list(subprocess.run(["scutil", "--nc", "list"], check=False, capture_output=True, text=True).stdout):
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
