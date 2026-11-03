"""NetworkManager backend via nmcli (control) and, when available, libnm over GObject introspection (events + reason)."""
from __future__ import annotations

import ipaddress
import pwd
import re
import socket
import subprocess
import time
from pathlib import Path

_IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
SYS_NET = Path("/sys/class/net")


def _nmcli(*args: str) -> str:
    return subprocess.run(["nmcli", "-t", *args], check=False, capture_output=True, text=True).stdout.strip()




def is_virtual(name: str) -> bool:
    """A tunnel interface has no backing device in sysfs; a physical NIC (eth0, wlp2s0) does."""
    return _IFNAME.match(name) is not None and not (SYS_NET / name / "device").exists()


def iface(profile: str) -> str | None:
    """The tunnel interface of an active VPN connection (tun0, wg0, ppp0 ...). Only GENERAL.IP-IFACE: for a 'vpn'
    connection GENERAL.DEVICES is the *underlying* card, and allowing that would open the kill-switch completely.
    Anything that is not a virtual interface is refused (None = stay blocked)."""
    v = _nmcli("-g", "GENERAL.IP-IFACE", "connection", "show", profile)
    if v and v != "--" and is_virtual(v):
        return v
    return None


WG_STALE_SECONDS = 180          # a live WireGuard link re-handshakes every 2 minutes
WG_GRACE_SECONDS = 30           # a just-activated tunnel has not handshaken yet
_kinds: dict[str, str | None] = {}
_wg_first_seen: dict[str, float] = {}


def kind(profile: str) -> str | None:
    """'wireguard', 'openvpn', 'vpn' (another VPN plugin) or the connection type; None when there is no such connection.
    Cached per process: a connection's type does not change."""
    if profile not in _kinds:
        t = _nmcli("-g", "connection.type", "connection", "show", profile)
        if t == "vpn":
            st = _nmcli("-g", "vpn.service-type", "connection", "show", profile)
            t = "openvpn" if "openvpn" in st else "vpn"
        _kinds[profile] = t or None
    return _kinds[profile]


def wg_state(handshakes: list[int], now: float, first_seen: float | None,
             stale: int = WG_STALE_SECONDS, grace: int = WG_GRACE_SECONDS) -> str:
    """'up' (a handshake within `stale` s), 'starting' (no fresh handshake yet, seen for less than `grace` s) or 'stale'
    (activated but silent - a dead link keeps its interface up). Pure."""
    last = max(handshakes, default=0)
    if last > 0 and now - last <= stale:
        return "up"
    if first_seen is None or now - first_seen < grace:
        return "starting"
    return "stale"


def wg_handshakes(ifname: str) -> list[int] | None:
    """Latest handshake per peer (unix time, 0 = never), or None when `wg` is unavailable or not allowed (non-root)."""
    if not _IFNAME.match(ifname):
        return None
    try:
        r = subprocess.run(["wg", "show", ifname, "latest-handshakes"], check=False, capture_output=True, text=True)
    except OSError:
        return None
    if r.returncode != 0:
        return None
    out = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            out.append(int(parts[1]))
    return out


def wg_health(profile: str) -> str:
    """WireGuard: 'up' | 'starting' | 'stale'; 'unknown' when the handshakes cannot be read (then the activation state rules)."""
    ifname = iface(profile)
    hs = wg_handshakes(ifname) if ifname else None
    if hs is None:
        return "unknown"
    now = time.time()
    st = wg_state(hs, now, _wg_first_seen.setdefault(profile, now))
    if st == "up":
        _wg_first_seen.pop(profile, None)
    return st


def is_connected(profile: str) -> bool:
    """Activated - and for WireGuard also handshaking: a dead WireGuard link stays 'activated' in NetworkManager."""
    if _nmcli("-g", "GENERAL.STATE", "connection", "show", profile) != "activated":
        _wg_first_seen.pop(profile, None)
        return False
    if kind(profile) == "wireguard":
        return wg_health(profile) in ("up", "starting", "unknown")
    return True


def is_stale(profile: str) -> bool:
    """WireGuard activated but silent for over 3 minutes (the redial takes it down and brings it up again)."""
    return kind(profile) == "wireguard" and wg_health(profile) == "stale"


_TUNNEL_NAME = re.compile(r"^(tun|tap|wg|ppp|nordlynx|proton|ipsec|vti)\d*$|^(tun|wg)-")


def other_tunnels(own: str | None, net: Path = SYS_NET) -> list[str]:
    """Up tunnel interfaces that are not the active profile's: another VPN next to VeroScudo."""
    out = []
    try:
        names = sorted(p.name for p in net.iterdir())
    except OSError:
        return out
    for n in names:
        if n == own or not _TUNNEL_NAME.match(n) or (net / n / "device").exists():
            continue
        try:
            state = (net / n / "operstate").read_text().strip()
        except OSError:
            continue
        if state != "down":
            out.append(n)
    return out


def parse_openvpn_data(data: str) -> dict:
    """NetworkManager's vpn.data of an OpenVPN connection -> {'hosts': [...], 'port': int|None, 'proto': 'tcp'|'udp'}. Pure."""
    items = {}
    for part in re.split(r",\s*(?=[a-z0-9-]+\s*=)", data.strip()):
        if "=" in part:
            k, v = part.split("=", 1)
            items[k.strip()] = v.strip()
    hosts, port = [], None
    for r in re.split(r"[,\s]+", items.get("remote", "")):
        if not r:
            continue
        host, _, p = r.partition(":")
        hosts.append(host)
        if p.isdigit() and port is None:
            port = int(p)
    if items.get("port", "").isdigit():
        port = int(items["port"])
    return {"hosts": hosts, "port": port or (1194 if hosts else None), "proto": "tcp" if items.get("proto-tcp") == "yes" else "udp"}


def check(cfg) -> list[str]:
    """Problems with the configured profiles (veroscudo check): a missing connection, or a protocol/port that does not match
    what NetworkManager will use (the kill-switch would then block the VPN itself)."""
    out = []
    for p in cfg.profiles:
        k = kind(p.name)
        if k is None:
            out.append(f"{p.name}: no NetworkManager connection with this name")
            continue
        if k == "wireguard":
            if p.protocol != "udp":
                out.append(f'{p.name}: WireGuard uses UDP - set "protocol": "udp" and "port": the endpoint\'s port')
            out.append(f"{p.name}: WireGuard - make sure the peer has PersistentKeepalive (e.g. 25): VeroScudo judges the link by its handshakes")
        elif k == "openvpn":
            d = parse_openvpn_data(unescape(_nmcli("-g", "vpn.data", "connection", "show", p.name)))
            if d["proto"] != p.protocol:
                out.append(f"{p.name}: OpenVPN uses {d['proto'].upper()} but the profile says {p.protocol.upper()}")
            if d["port"] and d["port"] != p.port:
                out.append(f"{p.name}: OpenVPN uses port {d['port']} but the profile says {p.port}")
            if d["hosts"] and p.server not in d["hosts"] and not p.server_ips:
                out.append(f"{p.name}: the server '{p.server}' is not among the connection's remotes ({', '.join(d['hosts'])})")
    return out


def up(profile: str) -> bool:
    r = subprocess.run(["nmcli", "connection", "up", "id", profile], check=False, capture_output=True, text=True)
    return r.returncode == 0


def wait_connected(profile: str, seconds: float = 10.0) -> bool:
    """After `up`: WireGuard is 'activated' before its first handshake - give it a moment."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if is_connected(profile) and not (kind(profile) == "wireguard" and wg_health(profile) == "starting"):
            return True
        time.sleep(1)
    return is_connected(profile)


def down(profile: str) -> bool:
    r = subprocess.run(["nmcli", "connection", "down", "id", profile], check=False, capture_output=True, text=True)
    return r.returncode == 0


def resolve(server: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(server, None, socket.AF_UNSPEC)
                       if not ipaddress.ip_address(ai[4][0].split("%")[0]).is_link_local})
    except OSError:
        return []


def resolver_uid() -> int | None:
    """uid of systemd-resolved when it is the system resolver: then only it may send DNS while blocked."""
    if not Path("/run/systemd/resolve/io.systemd.Resolve").exists():
        return None
    try:
        return pwd.getpwnam("systemd-resolve").pw_uid
    except KeyError:
        return None


def nameservers(path: Path = Path("/etc/resolv.conf")) -> list[str]:
    """Upstream resolvers (no loopback stubs) - the only DNS destinations while blocked when systemd-resolved is absent."""
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


def nm_dns() -> list[str]:
    """The DNS servers NetworkManager handed out on the physical links (when resolv.conf only names a local stub such as
    dnsmasq, unbound or Pi-hole): the only DNS destinations while blocked. No loopback."""
    out = []
    for line in _nmcli("-f", "IP4.DNS,IP6.DNS", "device", "show").splitlines():
        if ":" not in line:
            continue
        v = unescape(line.split(":", 1)[1]).strip()
        try:
            a = ipaddress.ip_address(v.split("%")[0])
        except ValueError:
            continue
        if not a.is_loopback:
            out.append(str(a))
    return sorted(set(out))


USER_REQUESTED_REASONS = {"user-requested", "user-disconnected"}


def watch(profiles, on_up, on_down) -> None:
    """Blocks. Calls on_up(profile) when a watched profile activates, on_down(profile, user_requested) when it deactivates.
    `profiles` is a callable returning the current set of names (config can change while running).
    Uses libnm (python3-gi + gir1.2-nm-1.0) for the deactivation reason; falls back to polling without reasons."""
    try:
        import gi  # type: ignore
        gi.require_version("NM", "1.0")
        from gi.repository import NM, GLib  # type: ignore
    except (ImportError, ValueError):
        _watch_polling(profiles, on_up, on_down)
        return

    client = NM.Client.new(None)
    tracked: dict[str, bool] = {}

    def hook(ac):
        name = ac.get_id()
        if name not in profiles() or ac.get_path() in tracked:
            return
        tracked[ac.get_path()] = True

        def changed(active, state, reason):
            st = NM.ActiveConnectionState(state)
            if st == NM.ActiveConnectionState.ACTIVATED:
                on_up(name)
            elif st == NM.ActiveConnectionState.DEACTIVATED:
                tracked.pop(ac.get_path(), None)
                rs = NM.ActiveConnectionStateReason(reason)
                on_down(name, rs == NM.ActiveConnectionStateReason.USER_DISCONNECTED)

        ac.connect("state-changed", changed)

    for ac in client.get_active_connections():
        hook(ac)
    client.connect("active-connection-added", lambda c, ac: hook(ac))
    GLib.MainLoop().run()


def _watch_polling(profiles, on_up, on_down, interval: float = 2.0) -> None:
    import time

    last = {p: is_connected(p) for p in profiles()}
    while True:
        time.sleep(interval)
        for p in profiles():
            now = is_connected(p)
            if now and not last.get(p, False):
                on_up(p)
            elif last.get(p, False) and not now:
                on_down(p, False)      # no reason available: treat as failure; `veroscudo off` sets its own marker first
            last[p] = now


# ---- import from NetworkManager (veroscudo import)
_SERVICE_TYPES = {"openvpn": "openvpn", "l2tp": "l2tp", "pptp": "pptp", "sstp": "sstp", "strongswan": "ikev2",
                  "libreswan": "ipsec", "openconnect": "openconnect"}


def unescape(value: str) -> str:
    """nmcli's terse output (-t / -g) escapes ':' and '\\' with a backslash. Pure."""
    return re.sub(r"\\(.)", r"\1", value or "")


def split_address(value: str) -> tuple[str, int]:
    """'host', 'host:4443', '[2001:db8::1]:443', 'https://host:8443/x' -> (host, port or 0). Pure."""
    v = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", (value or "").strip()).split("/")[0]
    m = re.match(r"^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$", v)
    if m:
        return m.group(1), int(m.group(2) or 0)
    m = re.match(r"^([^:]+):(\d{1,5})$", v)
    if m:
        return m.group(1), int(m.group(2))
    return v, 0


def parse_vpn_data(data: str) -> dict:
    """NetworkManager's vpn.data ('key = value, key = value') -> dict. Values may contain ', ' (OpenVPN remotes). Pure."""
    items = {}
    for part in re.split(r",\s*(?=[A-Za-z0-9_-]+\s*=)", (data or "").strip()):
        if "=" in part:
            k, v = part.split("=", 1)
            items[k.strip()] = v.strip()
    return items


def describe_vpn(name: str, kind_: str, data: str) -> dict:
    """One NetworkManager VPN connection -> what VeroScudo imports. Pure. server '' = cannot import (see note)."""
    d = parse_vpn_data(data)
    out = {"name": name, "vpn_type": "", "server": "", "port": 443, "protocol": "tcp", "username": "", "note": ""}
    if kind_ == "openvpn":
        o = parse_openvpn_data(data)
        out.update(vpn_type="openvpn", server=(o["hosts"] or [""])[0], port=o["port"] or 1194, protocol=o["proto"], username=d.get("username", ""))
        if len(o["hosts"]) > 1:
            out["note"] = f"{len(o['hosts'])} remotes - only the first is allowed; pin the others with serverIps"
    elif kind_ in ("l2tp", "pptp", "sstp"):
        host, port = split_address(d.get("gateway", ""))
        out.update(vpn_type=kind_, server=host, username=d.get("user", ""),
                   port=port or 443, protocol="tcp" if kind_ in ("pptp", "sstp") else "udp")
    elif kind_ in ("ikev2", "ipsec"):
        host, _ = split_address(d.get("address") or d.get("right", ""))
        out.update(vpn_type=kind_, server=host, protocol="udp", port=4500, username=d.get("user") or d.get("leftxauthusername", ""))
        # strongSwan / libreswan in NetworkManager are policy-based: no tunnel interface, so the kill-switch could never tell
        # the tunnel's traffic apart - connected but blocked forever. Refused until a route-based (vti/xfrm) setup is handled.
        out["unsupported"] = True
        out["note"] = "policy-based IPsec has no tunnel interface - not supported by VeroScudo on Linux yet"
    elif kind_ == "openconnect":
        host, port = split_address(d.get("gateway", ""))
        out.update(vpn_type="openconnect", server=host, port=port or 443)
    else:
        out["note"] = "VPN plugin not supported by VeroScudo"
    if not out["server"] and not out["note"]:
        out["note"] = "no server found in the connection"
    return out


def wireguard_endpoint(keyfile_text: str) -> tuple[str, int]:
    """The first peer endpoint of a NetworkManager WireGuard keyfile ([wireguard-peer.<key>] endpoint=host:port). Pure."""
    in_peer = False
    for line in keyfile_text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_peer = s.startswith("[wireguard-peer.")
        elif in_peer and s.startswith("endpoint="):
            return split_address(s.split("=", 1)[1])
    return "", 0


def discover() -> list[dict]:
    """Every VPN / WireGuard connection NetworkManager knows, described for import (needs root for WireGuard endpoints)."""
    out = []
    for line in _nmcli("-f", "NAME,TYPE", "connection", "show").splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) < 2:
            continue
        name, ctype = parts[0].replace("\\:", ":"), parts[1]
        if ctype == "wireguard":
            d = {"name": name, "vpn_type": "wireguard", "server": "", "port": 51820, "protocol": "udp", "username": "", "note": ""}
            path = unescape(_nmcli("-g", "GENERAL.FILENAME", "connection", "show", name))
            try:
                host, port = wireguard_endpoint(Path(path).read_text()) if path else ("", 0)
            except OSError:
                host, port = "", 0
                d["note"] = "run as root to read the WireGuard endpoint"
            d.update(server=host, port=port or 51820)
            if not host and not d["note"]:
                d["note"] = "no peer endpoint in the connection"
            out.append(d)
        elif ctype == "vpn":
            st = _nmcli("-g", "vpn.service-type", "connection", "show", name)
            k = next((v for key, v in _SERVICE_TYPES.items() if key in st), "")
            out.append(describe_vpn(name, k, unescape(_nmcli("-g", "vpn.data", "connection", "show", name))))
    return out
