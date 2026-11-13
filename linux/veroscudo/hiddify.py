"""Hiddify in VPN (TUN) mode as a VeroScudo profile - Linux and macOS (the Windows guard does the same).

Hiddify is a GUI around hiddify-core (a sing-box fork) running inside the app. In VPN mode it creates a TUN interface with
the address from its live sing-box config (<data dir>/data/current-config.json) and routes everything through it.
VeroScudo never starts or stops Hiddify: it watches whether Hiddify's tunnel is up, lets that tunnel through, and lets
Hiddify reach its own servers (and its direct DNS servers) outside the tunnel - parsed from the live config on every pass.
Proxy and system-proxy modes are not supported: they have no tunnel interface to hold the traffic to.

The config file belongs to the signed-in user (or to root, when Hiddify's own root service runs the core), and the guard
(root) reads it. That is acceptable: the file only decides
which server addresses and ports are allowed out (at most MAX_ENDPOINTS, public unicast only - never loopback, private,
link-local or multicast), and the same user can already turn the kill-switch off without a password
(`sudo veroscudo off`, the sudoers rule install.sh writes). The file must be a regular file (no symlink), owned by root or
by the user whose home folder holds it, at most MAX_BYTES; a file that cannot be read or parsed keeps the last good set.
The clash_api secret in the file is never logged or stored: only server addresses, ports and the tun address are used."""
from __future__ import annotations

import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .netutil import IFNAME, parse_ip_addr

KIND = "hiddify"
LABEL = "Hiddify (VPN mode)"                         # how another (not active) Hiddify tunnel is named in the tray
NAME = "Hiddify"                                     # the profile name `veroscudo import` offers
CONFIG_NAME = "current-config.json"
MAX_BYTES = 2 * 1024 * 1024
MAX_ENDPOINTS = 64
RESOLVE_SECONDS = 300                                # a host name's addresses are looked up again after this long

PROXY_MODE_NOTE = "Hiddify is in proxy mode - switch it to VPN mode (only VPN mode is supported)"
NOT_CONNECTED = "Hiddify is not connected - connect it in Hiddify (VPN mode); traffic stays blocked meanwhile"
RECONNECT_HINT = "Connect and reconnect in Hiddify"

# Hiddify's data folder, relative to the user's home; each entry is also tried with a nested "hiddify/". Windows:
# %APPDATA%\Hiddify\hiddify\data\current-config.json. The macOS entries are unverified.
DATA_DIRS = {
    "linux": (".local/share/hiddify", ".local/share/app.hiddify.com", ".local/share/Hiddify"),
    "darwin": ("Library/Application Support/app.hiddify.com", "Library/Application Support/Hiddify"),
}
# Hiddify's own root service (VPN mode in Hiddify 5 on Linux: HiddifyAdminBG.service runs the core as root and keeps the
# live config here, owned by root). The user's data folder above then still holds the app's settings.
SYSTEM_DIRS = {
    "linux": ("/var/lib/hiddify-admin-bgservice/core/work",),
    "darwin": (),
}

_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_GROUPS = {"direct", "block", "dns", "selector", "urltest", "balancer", "loadbalance"}   # outbounds without a server of their own
# direct DNS server type -> (protocols, default port)
_DNS_PORTS = {"udp": (("udp", "tcp"), 53), "tcp": (("udp", "tcp"), 53), "": (("udp", "tcp"), 53),
              "https": (("tcp",), 443), "tls": (("tcp",), 853), "quic": (("udp",), 853), "h3": (("udp",), 443)}
# RFC 1918, unique-local and carrier-grade NAT: never a Hiddify server reached from outside (documentation ranges such as
# 203.0.113.0/24 are allowed - Python counts them as "private", VeroScudo does not)
_PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                    "fc00::/7"))

Endpoint = tuple  # (address or host name, port, protocols) - e.g. ("203.0.113.7", 443, ("tcp", "udp"))


# ---------------------------------------------------------------- config.json: the profile's path
def valid_config_path(value: object) -> bool:
    """configPath of a hiddify profile: absolute, ends with /current-config.json, no control characters. Pure."""
    return (isinstance(value, str) and 0 < len(value) <= 1024 and value.startswith("/") and not _CTRL.search(value)
            and value.endswith("/" + CONFIG_NAME) and "/../" not in value)


_profiles: dict[str, str] = {}                       # profile name -> configPath, for the backends (they get names only)


def register(profiles) -> None:
    """Called whenever config.json is loaded: which profile names are Hiddify profiles, and their config files."""
    _profiles.clear()
    _profiles.update({p.name: p.config_path for p in profiles if getattr(p, "vpn_type", "") == KIND and p.config_path})


def path_for(name: str) -> str | None:
    return _profiles.get(name)


def is_profile(name: str) -> bool:
    return name in _profiles


# ---------------------------------------------------------------- pure parsers
def forbidden(addr: str) -> bool:
    """An address Hiddify's servers can never have: loopback, private, link-local, multicast, unspecified, reserved. Pure."""
    try:
        a = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return True
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved
            or any(a in n for n in _PRIVATE if n.version == a.version)
            or (a.version == 4 and str(a) == "255.255.255.255"))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        p = int(value)                                  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None


def tun_settings(conf: dict) -> tuple[list[str], str | None]:
    """The tun inbound's IPv4 addresses and its interface_name (None when not set). Handles the current sing-box format
    ("address": [...]) and the older one ("inet4_address"). Pure."""
    addrs, name = [], None
    for ib in conf.get("inbounds") or []:
        if not isinstance(ib, dict) or ib.get("type") != "tun":
            continue
        raw = ib.get("address") or ib.get("inet4_address") or []
        for a in [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []:
            if isinstance(a, str):
                try:
                    ip = ipaddress.ip_interface(a.strip()).ip
                except ValueError:
                    continue
                if ip.version == 4:
                    addrs.append(str(ip))
        n = ib.get("interface_name")
        if isinstance(n, str) and IFNAME.match(n):
            name = n
        break
    return addrs, name


def _dns_address(value: str) -> tuple[str, str, int | None]:
    """Legacy sing-box DNS "address" -> (type, host, port): 'udp://1.1.1.1', 'tls://dns.example.com:853',
    'https://dns.example.com/dns-query', '1.1.1.1' (= udp), 'local', 'fakeip'. Pure."""
    v = value.strip()
    m = re.match(r"^([a-z0-9]+)://(.*)$", v)
    if m:
        scheme, rest = m.group(1), m.group(2)
    elif not v or v in ("local", "fakeip"):
        return v, "", None
    else:
        scheme, rest = "udp", v
    rest = rest.split("/")[0]
    mm = re.match(r"^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$", rest)
    if mm:
        return scheme, mm.group(1), _port(mm.group(2)) if mm.group(2) else None
    host, _, port = rest.partition(":") if rest.count(":") == 1 else (rest, "", "")
    return scheme, host, _port(port) if port else None


def endpoints(conf: dict) -> tuple[list[Endpoint], list[str]]:
    """What Hiddify must reach outside its tunnel: every proxy outbound's server:server_port (TCP and UDP - QUIC/hysteria
    use UDP, xhttp either) and the DNS servers it asks directly (no detour, or a detour to a "direct" outbound).
    Returns (endpoints, dropped): hosts are IP addresses or host names (resolved later), forbidden addresses and invalid
    entries are dropped and named in `dropped`, at most MAX_ENDPOINTS. Pure."""
    found: dict[tuple[str, int], set] = {}
    dropped: list[str] = []

    def add(host: object, port: object, protos) -> None:
        p = _port(port)
        if not isinstance(host, str) or not host or p is None:
            dropped.append(f"{host}:{port}")
            return
        h = host.strip().strip("[]").lower()
        if _is_ip(h):
            if forbidden(h):
                dropped.append(f"{h}:{p}")
                return
            h = str(ipaddress.ip_address(h))
        elif not _HOST.match(h):
            dropped.append(f"{h[:60]}:{p}")
            return
        found.setdefault((h, p), set()).update(protos)

    outs = [o for o in conf.get("outbounds") or [] if isinstance(o, dict)]
    direct = {o.get("tag") for o in outs if o.get("type") == "direct"}
    both = ("tcp", "udp")
    for o in outs + [e for e in conf.get("endpoints") or [] if isinstance(e, dict)]:
        if o.get("type") in _GROUPS:
            continue
        if "server" in o:
            add(o.get("server"), o.get("server_port"), both)
        for peer in o.get("peers") or []:                       # WireGuard (old outbound and new endpoint format)
            if isinstance(peer, dict):
                add(peer.get("server") or peer.get("address"), peer.get("server_port") or peer.get("port"), ("udp",))
    dns = conf.get("dns") if isinstance(conf.get("dns"), dict) else {}
    for s in dns.get("servers") or []:
        if not isinstance(s, dict):
            continue
        detour = s.get("detour")
        if detour and detour not in direct:
            continue                                            # asked through the tunnel
        if "type" in s:
            kind, host, port = str(s.get("type")), s.get("server"), s.get("server_port")
        elif isinstance(s.get("address"), str):
            kind, host, port = _dns_address(s["address"])
        else:
            continue
        if kind not in _DNS_PORTS:
            continue                                            # hosts, local (the system resolver), fakeip, dhcp, rcode
        protos, default = _DNS_PORTS[kind]
        add(host, port if port is not None else default, protos)
    eps = [(h, p, tuple(x for x in ("tcp", "udp") if x in pr)) for (h, p), pr in found.items()]
    if len(eps) > MAX_ENDPOINTS:
        dropped += [f"{h}:{p}" for h, p, _ in eps[MAX_ENDPOINTS:]]
        eps = eps[:MAX_ENDPOINTS]
    return eps, dropped


def resolve_endpoints(eps: list[Endpoint], resolve, hosts: dict, now: float | None = None,
                      ttl: float = RESOLVE_SECONDS) -> list[Endpoint]:
    """Host names -> addresses (forbidden ones dropped), merged per address and port. `hosts` is the caller's cache
    {name: (addresses, when)}: a name is looked up again only after `ttl`, and a failed lookup keeps its last good addresses.
    Lookups run in parallel (a blocked DNS must not stall the guard for a minute per name)."""
    now = time.time() if now is None else now
    names = sorted({h for h, _, _ in eps if not _is_ip(h) and (h not in hosts or now - hosts[h][1] >= ttl)})
    if names:
        with ThreadPoolExecutor(max_workers=min(8, len(names))) as ex:
            for n, ips in zip(names, ex.map(resolve, names)):
                good = [a for a in ips if not forbidden(a)]
                if good:
                    hosts[n] = (good, now)
    out: dict[tuple[str, int], set] = {}
    for h, p, pr in eps:
        for a in [h] if _is_ip(h) else hosts.get(h, ((), 0))[0]:
            out.setdefault((a, p), set()).update(pr)
    return [(a, p, tuple(x for x in ("tcp", "udp") if x in pr)) for (a, p), pr in out.items()][:MAX_ENDPOINTS * 4]


def dump_cache(eps: list[Endpoint]) -> str:
    return json.dumps({"endpoints": [[a, p, list(pr)] for a, p, pr in eps]})


def parse_cache(text: str) -> list[Endpoint]:
    """The guard's last good permit set (for boot, before any DNS) - checked again like the live config. Pure."""
    try:
        j = json.loads(text)
    except ValueError:
        return []
    out = []
    for e in (j.get("endpoints") if isinstance(j, dict) else None) or []:
        if (isinstance(e, list) and len(e) == 3 and isinstance(e[0], str) and _is_ip(e[0]) and not forbidden(e[0])
                and _port(e[1]) and isinstance(e[2], list) and e[2] and all(x in ("tcp", "udp") for x in e[2])):
            out.append((str(ipaddress.ip_address(e[0])), int(e[1]), tuple(x for x in ("tcp", "udp") if x in e[2])))
    return out[:MAX_ENDPOINTS * 4]


def service_mode(prefs_text: str) -> str | None:
    """shared_preferences.json -> "vpn" | "proxy" | "system-proxy" | ... (None when not set). Pure."""
    try:
        j = json.loads(prefs_text)
    except ValueError:
        return None
    v = j.get("flutter.service-mode") if isinstance(j, dict) else None
    return v if isinstance(v, str) else None


def parse_ifconfig(text: str) -> dict[str, list[str]]:
    """macOS `ifconfig` -> {interface that is UP: [IPv4 addresses]}. Pure."""
    out: dict[str, list[str]] = {}
    name, up = None, False
    for line in text.splitlines():
        m = re.match(r"^(\S+?):\s+flags=[0-9a-fA-F]+<([^>]*)>", line)
        if m:
            name, up = m.group(1), "UP" in m.group(2).split(",")
            if up:
                out.setdefault(name, [])
            continue
        mm = re.match(r"^\s+inet\s+([0-9.]+)", line)
        if mm and name and up:
            out[name].append(mm.group(1))
    return out


def pick_iface(addrs: dict[str, list[str]], tun_v4: list[str], name: str | None, platform: str | None = None,
               is_tun=None) -> str | None:
    """The interface that holds the tun inbound's IPv4 address (fallback: the configured interface_name, if it is up).
    Only a tunnel device counts: on Linux a docker bridge may well hold 172.19.0.1 too (is_tun: /sys/.../tun_flags), on
    macOS only utunN. Pure apart from is_tun."""
    platform = platform or sys.platform        # at call time, not import time (tests switch it)
    def ok(ifc: str) -> bool:
        if not IFNAME.match(ifc):
            return False
        if platform == "darwin":
            return re.match(r"^utun\d+$", ifc) is not None
        return is_tun(ifc) if is_tun else True
    for ifc in sorted(addrs):
        if any(a in tun_v4 for a in addrs[ifc]) and ok(ifc):
            return ifc
    if name and name in addrs and ok(name):
        return name
    return None


# ---------------------------------------------------------------- small I/O helpers
def allowed_owners(path: str) -> set[int]:
    """root, and the user whose home folder holds the file (the user who imported it)."""
    out = {0}
    try:
        for pw in pwd.getpwall():
            home = pw.pw_dir.rstrip("/")
            if home and path.startswith(home + "/"):
                out.add(pw.pw_uid)
    except OSError:
        pass
    return out


def read_config(path: str) -> dict:
    """The live sing-box config, read defensively (the guard runs as root): a regular file, not a symlink, owned by root or
    the importing user, at most MAX_BYTES, a JSON object. Raises OSError / ValueError."""
    if not valid_config_path(path):
        raise ValueError("not a Hiddify current-config.json path")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("not a regular file")
        if st.st_uid not in allowed_owners(path):
            raise ValueError("owned by another user")
        if st.st_size > MAX_BYTES:
            raise ValueError(f"larger than {MAX_BYTES // 1024 // 1024} MB")
        with os.fdopen(os.dup(fd), "rb") as f:
            data = f.read(MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_BYTES:
        raise ValueError("file grew while reading")
    j = json.loads(data.decode("utf-8"))
    if not isinstance(j, dict):
        raise ValueError("not a JSON object")  # noqa: TRY004  (callers treat every bad file alike)
    return j


_tun_cache: dict[str, tuple[tuple, tuple[list[str], str | None]]] = {}


SHARED_NAME = "hiddify-tun.json"


def shared_file() -> Path:
    """Where the guard shares the tun settings of a root-only config: its run folder ($VEROSCUDO_HOME in tests)."""
    return Path(os.environ.get("VEROSCUDO_HOME") or ("/var/run/veroscudo" if sys.platform == "darwin" else "/run/veroscudo")
                ) / SHARED_NAME


def share_tun(path: str, conf: dict, file: Path | None = None) -> None:
    """The guard (root), after reading Hiddify's config: its tun address and interface name, readable by the user's status
    and tray - Hiddify's root service keeps its config where only root can read it. Nothing else of the file (no server,
    no secret). Written only when it changed."""
    file = file or shared_file()
    v4, name = tun_settings(conf)
    data = json.dumps({"path": path, "v4": v4, "name": name}, sort_keys=True)
    try:
        if file.read_text(encoding="utf-8") == data:
            return
    except OSError:
        pass
    try:
        tmp = file.with_suffix(".new")
        tmp.write_text(data, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, file)
    except OSError:
        pass


def shared_tun(path: str, file: Path | None = None, owner: int = 0) -> tuple[list[str], str | None]:
    """The tun settings the guard shared for this config file - only from a regular file owned by root, only well-formed
    IPv4 addresses and an interface name. ([], None) when there is none."""
    file = file or shared_file()
    try:
        st = os.lstat(file)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_size > 4096:
            return [], None
        j = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], None
    if not isinstance(j, dict) or j.get("path") != path:
        return [], None
    v4 = [a for a in j.get("v4") or [] if isinstance(a, str) and _is_ip(a) and ":" not in a][:8]
    name = j.get("name")
    return v4, (name if isinstance(name, str) and IFNAME.match(name) else None)


def tun_of(path: str) -> tuple[list[str], str | None]:
    """tun_settings of the file, re-read only when it changed (the tray asks every 3 s). A file the user may not read
    (Hiddify's root service): what the guard shared. ([], None) when neither is there."""
    try:
        st = os.stat(path)
        key = (st.st_mtime_ns, st.st_size, st.st_ino)
    except PermissionError:
        return shared_tun(path)
    except OSError:
        return [], None
    hit = _tun_cache.get(path)
    if hit and hit[0] == key:
        return hit[1]
    try:
        val = tun_settings(read_config(path))
    except PermissionError:
        return shared_tun(path)
    except (OSError, ValueError):
        val = ([], None)
    _tun_cache[path] = (key, val)
    return val


_PROC_NAME = re.compile(r"hiddify", re.IGNORECASE)


def running(platform: str | None = None, proc: Path = Path("/proc")) -> bool:
    """A Hiddify process (Hiddify, hiddify, HiddifyCli ...) is running. Linux: /proc/*/comm or the exe's name; macOS:
    pgrep -i."""
    platform = platform or sys.platform        # at call time, not import time (tests switch it)
    if platform == "darwin":
        try:
            r = subprocess.run(["pgrep", "-i", "hiddify"], check=False, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
        return r.returncode == 0 and bool(r.stdout.strip())
    try:
        pids = [d for d in os.listdir(proc) if d.isdigit()]
    except OSError:
        return False
    for pid in pids:
        try:
            if _PROC_NAME.search((proc / pid / "comm").read_text()):
                return True
        except OSError:
            pass
        try:
            if _PROC_NAME.search(os.path.basename(os.readlink(proc / pid / "exe"))):
                return True
        except OSError:
            pass
    return False


def interfaces(platform: str | None = None) -> dict[str, list[str]]:
    """Interfaces that are up -> their IPv4 addresses."""
    platform = platform or sys.platform        # at call time, not import time (tests switch it)
    argv = ["ifconfig"] if platform == "darwin" else ["ip", "-o", "-4", "addr", "show", "up"]
    try:
        r = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_ifconfig(r.stdout) if platform == "darwin" else parse_ip_addr(r.stdout)


def _is_tun(ifc: str) -> bool:
    return (Path("/sys/class/net") / ifc / "tun_flags").exists()


def tunnel(path: str, platform: str | None = None) -> str | None:
    """Hiddify's tunnel interface for this config file - None unless a Hiddify process runs AND an up tunnel interface
    holds the tun inbound's IPv4 address (or has its interface_name)."""
    platform = platform or sys.platform        # at call time, not import time (tests switch it)
    v4, name = tun_of(path)
    if not v4 and not name:
        return None
    if not running(platform):
        return None
    return pick_iface(interfaces(platform), v4, name, platform, _is_tun)


def iface(profile: str) -> str | None:
    p = path_for(profile)
    return tunnel(p) if p else None


def connected(profile: str) -> bool:
    return iface(profile) is not None


# ---------------------------------------------------------------- import / other-VPN detection / check
def user_home(env=None, platform: str | None = None) -> Path:
    """The invoking user's home: SUDO_USER's with sudo (`sudo veroscudo import`), PKEXEC_UID's with pkexec (the Linux tray's
    Import), the console user's when root on macOS (the macOS tray's Import runs through osascript), else the current
    user's."""
    platform = platform or sys.platform        # at call time, not import time (tests switch it)
    env = os.environ if env is None else env
    try:
        who = env.get("SUDO_USER")
        if who and who != "root":
            return Path(pwd.getpwnam(who).pw_dir)
        uid = env.get("PKEXEC_UID", "")
        if uid.isdigit() and uid != "0":
            return Path(pwd.getpwuid(int(uid)).pw_dir)
        if platform == "darwin" and os.getuid() == 0:
            owner = os.stat("/dev/console").st_uid
            if owner != 0:
                return Path(pwd.getpwuid(owner).pw_dir)
        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError):
        return Path.home()


def candidates(home: Path, platform: str | None = None) -> list[Path]:
    """Hiddify data folders to look in: Hiddify's root service (SYSTEM_DIRS), then the user's (DATA_DIRS, each also with a
    nested hiddify/). Pure."""
    platform = platform or sys.platform        # at call time, not import time (tests switch it)
    key = "darwin" if platform == "darwin" else "linux"
    out = [Path(d) for d in SYSTEM_DIRS.get(key, ())]
    for rel in DATA_DIRS.get(key, ()):
        out += [home / rel, home / rel / "hiddify"]
    return out


def find(home: Path, platform: str | None = None) -> Path | None:
    """The data folder whose data/current-config.json exists - the most recently written one when there are several (a
    folder an older Hiddify left behind keeps a stale file)."""
    platform = platform or sys.platform        # at call time, not import time (tests switch it)
    best, best_t = None, -1.0
    for d in candidates(home, platform):
        f = d / "data" / CONFIG_NAME
        try:
            st = os.stat(f)
            t = st.st_mtime if stat.S_ISREG(st.st_mode) else None
        except PermissionError:
            # Hiddify's root service folder, looked at as the user (the trays list importable VPNs before the password
            # prompt): it is there, only not readable. The import itself runs as root and finds the real file.
            t = 0.0
        except OSError:
            t = None
        if t is not None and t > best_t:
            best, best_t = d, t
    return best


# Hiddify 5's root service on Linux runs the core - the process that talks to Hiddify's servers and its own DNS. Like the
# Windows guard's program permit (Hiddify.exe / HiddifyCli.exe to any address), the kill-switch lets this service out by
# its cgroup: its servers change with each subscription update and sit behind CDNs that answer Hiddify's own DNS with
# other addresses than the system's, so an address list alone cannot keep up.
SERVICE_CGROUP = "system.slice/HiddifyAdminBG.service"


def service_cgroup(root: Path = Path("/sys/fs/cgroup"), platform: str | None = None) -> tuple[str, int] | None:
    """Hiddify's root service as nftables matches it: its cgroup path and the cgroup's id (its inode - a restarted service
    gets a new cgroup, and the rule must be loaded again). None when the service is not running, or not on Linux."""
    if (platform or sys.platform) == "darwin":
        return None
    try:
        st = os.stat(root / SERVICE_CGROUP)
    except OSError:
        return None
    return (SERVICE_CGROUP, st.st_ino) if stat.S_ISDIR(st.st_mode) else None


def mode_of(folder: Path, home: Path, platform: str | None = None) -> str | None:
    """Hiddify's service mode from shared_preferences.json: in the config's own data folder, else (the root service's
    folder has none) in the user's data folders. None when not found."""
    for d in [folder] + [c for c in candidates(home, platform) if c != folder]:
        try:
            return service_mode((d / "shared_preferences.json").read_text(encoding="utf-8"))
        except OSError:
            continue
    return None


def discover(home: Path | None = None, platform: str | None = None) -> list[dict]:
    """Hiddify for `veroscudo import` (the import entry of the trays): one entry when its live config exists."""
    platform = platform or sys.platform        # at call time, not import time (tests switch it)
    home = home or user_home()
    d = find(home, platform)
    if d is None:
        return []
    path = str(d / "data" / CONFIG_NAME)
    out = {"name": NAME, "vpn_type": KIND, "server": "", "port": 0, "protocol": "tcp", "username": "", "note": "",
           "config_path": path}
    mode = mode_of(d, home, platform)
    if mode not in (None, "vpn"):
        out.update(unsupported=True, note=PROXY_MODE_NOTE)
    elif not valid_config_path(path):
        out.update(unsupported=True, note="the path of its config file cannot be used")
    return [out]


def owners(configured: list[str] | None = None, platform: str | None = None) -> dict[str, str]:
    """Up Hiddify tunnels -> LABEL, for the configured Hiddify profiles and the current user's Hiddify (imported or not),
    so another VPN check names it instead of showing an anonymous tun."""
    platform = platform or sys.platform        # at call time, not import time (tests switch it)
    paths = list(configured if configured is not None else _profiles.values())
    d = find(user_home(), platform)
    if d is not None:
        paths.append(str(d / "data" / CONFIG_NAME))
    out = {}
    for p in dict.fromkeys(paths):
        t = tunnel(p, platform) if valid_config_path(p) else None
        if t:
            out[t] = LABEL
    return out


def check_profile(name: str, path: str) -> list[str]:
    """`veroscudo check` for a Hiddify profile."""
    try:
        conf = read_config(path)
    except (OSError, ValueError) as e:
        return [f"{name}: cannot read Hiddify's config {path} ({e}) - is Hiddify installed and connected once in VPN mode?"]
    out = []
    v4, ifname = tun_settings(conf)
    if not v4 and not ifname:
        out.append(f"{name}: Hiddify's config has no tun inbound - switch Hiddify to VPN mode (only VPN mode is supported)")
    eps, dropped = endpoints(conf)
    if not eps:
        out.append(f"{name}: no server found in Hiddify's config - the kill-switch would block Hiddify itself")
    if dropped:
        out.append(f"{name}: {len(dropped)} server entr{'y' if len(dropped) == 1 else 'ies'} not allowed (private, local or "
                   "invalid address, or over the limit of 64)")
    mode = mode_of(Path(path).parent.parent, user_home())
    if mode not in (None, "vpn"):
        out.append(f"{name}: {PROXY_MODE_NOTE}")
    return out
