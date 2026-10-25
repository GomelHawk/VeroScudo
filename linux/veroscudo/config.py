"""config.json loading - same keys on every platform (docs/ARCHITECTURE.md). Every value is validated: it ends up in
nftables rules and nmcli arguments run as root."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

DEFAULT_CONFIG = Path("/etc/veroscudo/config.json")
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_BAD_NAME = re.compile(r'[\x00-\x1f"\\]')


def is_lan_range(value: str) -> bool:
    """A single address or a network narrow enough to be a LAN - never 'everything' (IPv4 /8+, IPv6 /16+)."""
    try:
        net = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return False
    return net.prefixlen >= (8 if net.version == 4 else 16)


def _is_host(value: str) -> bool:
    if _HOST.match(value):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class Profile:
    name: str                      # NetworkManager connection id
    server: str
    username: str = ""
    port: int = 443
    protocol: str = "tcp"          # transport of the VPN control channel: tcp (SSTP/OpenVPN-tcp) or udp (WireGuard, OpenVPN-udp, IKEv2)
    server_ips: tuple[str, ...] = ()   # pinned addresses: when set, nothing is resolved


@dataclass(frozen=True)
class Config:
    profiles: tuple[Profile, ...]
    default_profile: str
    active: str
    retry_seconds: int = 10
    vm: object = "auto"            # "auto" | True | False  (Docker / libvirt forward chain)
    lan_allow: tuple[str, ...] = field(default_factory=tuple)
    update_check: bool = True

    # the active profile's fields, so most code reads cfg.profile / cfg.server / cfg.port
    @property
    def current(self) -> Profile:
        return next(p for p in self.profiles if p.name == self.active)

    @property
    def profile(self) -> str:
        return self.active

    @property
    def server(self) -> str:
        return self.current.server

    @property
    def port(self) -> int:
        return self.current.port

    @property
    def protocol(self) -> str:
        return self.current.protocol

    @property
    def username(self) -> str:
        return self.current.username

    @property
    def server_ips(self) -> tuple[str, ...]:
        return self.current.server_ips

    @property
    def names(self) -> list[str]:
        return [p.name for p in self.profiles]

    def with_active(self, name: str) -> Config:
        if name not in self.names:
            raise ValueError(f"unknown VPN profile '{name}' (configured: {', '.join(self.names)})")
        return replace(self, active=name)

    @staticmethod
    def _profile(p: dict) -> Profile:
        name = str(p.get("profile") or "")
        if not name:
            raise ValueError("config.json: vpn.profile is required")
        if len(name) > 255 or _BAD_NAME.search(name):
            raise ValueError(f"config.json: invalid VPN profile name {name!r}")
        server = str(p.get("server") or "")
        if not server:
            raise ValueError(f"config.json: vpn.server is required (profile '{name}')")
        if not _is_host(server):
            raise ValueError(f"config.json: invalid server {server!r} (profile '{name}')")
        port = int(p.get("port", 443))
        if not 1 <= port <= 65535:
            raise ValueError(f"config.json: port must be 1-65535 (profile '{name}')")
        proto = str(p.get("protocol", "tcp")).lower()
        if proto not in ("tcp", "udp"):
            raise ValueError("config.json: vpn.protocol must be 'tcp' or 'udp'")
        pins = []
        for ip in p.get("serverIps") or []:
            try:
                pins.append(str(ipaddress.ip_address(str(ip))))
            except ValueError:
                raise ValueError(f"config.json: invalid serverIps entry {ip!r} (profile '{name}')") from None
        return Profile(name, server, str(p.get("username", "")), port, proto, tuple(pins))

    @staticmethod
    def from_text(raw: str, active: str | None = None) -> Config:
        j = json.loads(raw)
        raw_profiles = j.get("profiles") or ([j["vpn"]] if j.get("vpn") else [])
        if not raw_profiles:
            raise ValueError("config.json: vpn.profile is required (add a \"profiles\" list)")
        profiles = tuple(Config._profile(p or {}) for p in raw_profiles)
        names = [p.name for p in profiles]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(f"config.json: profile '{sorted(dupes)[0]}' is listed twice")
        vm = j.get("vm", "auto")
        if vm not in ("auto", True, False):
            raise ValueError("config.json: vm must be 'auto', true or false")
        retry = int(j.get("retrySeconds", 10))
        if not 3 <= retry <= 3600:
            raise ValueError("config.json: retrySeconds must be 3-3600")
        lan = tuple(str(c) for c in (j.get("lanAllow") or ()))
        for c in lan:
            if not is_lan_range(c):
                raise ValueError(f"config.json: lanAllow {c!r} is not a LAN range (IPv4 /8 or narrower, IPv6 /16 or narrower)")
        default = str(j.get("activeProfile") or names[0])
        if default not in names:
            raise ValueError(f"config.json: activeProfile '{default}' is not in profiles")
        cfg = Config(profiles=profiles, default_profile=default, active=default, retry_seconds=retry, vm=vm,
                     lan_allow=lan, update_check=bool(j.get("updateCheck", True)))
        if active and active in names:
            cfg = replace(cfg, active=active)
        return cfg

    @staticmethod
    def load(path: Path | None = None, active: str | None = None) -> Config:
        """active: the runtime selection (StateStore.active); an unknown name falls back to the configured default."""
        p = path or Path(os.environ.get("VEROSCUDO_CONFIG", DEFAULT_CONFIG))
        if not p.exists():
            raise FileNotFoundError(f"VeroScudo config not found: {p} (run install.sh)")
        return Config.from_text(p.read_text(), active)
