"""config.json loading - same keys on every platform (docs/ARCHITECTURE.md)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG = Path("/etc/veroscudo/config.json")


@dataclass(frozen=True)
class Config:
    profile: str
    server: str
    username: str = ""
    port: int = 443
    protocol: str = "tcp"          # transport of the VPN control channel: tcp (SSTP/OpenVPN-tcp) or udp (WireGuard, OpenVPN-udp, IKEv2)
    retry_seconds: int = 10
    vm: object = "auto"            # "auto" | True | False  (Docker / libvirt forward chain)
    lan_allow: tuple[str, ...] = field(default_factory=tuple)
    update_check: bool = True

    @staticmethod
    def from_text(raw: str) -> Config:
        j = json.loads(raw)
        vpn = j.get("vpn") or {}
        for key in ("profile", "server"):
            if not vpn.get(key):
                raise ValueError(f"config.json: vpn.{key} is required")
        vm = j.get("vm", "auto")
        if vm not in ("auto", True, False):
            raise ValueError("config.json: vm must be 'auto', true or false")
        proto = str(vpn.get("protocol", "tcp")).lower()
        if proto not in ("tcp", "udp"):
            raise ValueError("config.json: vpn.protocol must be 'tcp' or 'udp'")
        return Config(
            profile=str(vpn["profile"]),
            server=str(vpn["server"]),
            username=str(vpn.get("username", "")),
            port=int(vpn.get("port", 443)),
            protocol=proto,
            retry_seconds=int(j.get("retrySeconds", 10)),
            vm=vm,
            lan_allow=tuple(j.get("lanAllow", []) or ()),
            update_check=bool(j.get("updateCheck", True)),
        )

    @staticmethod
    def load(path: Path | None = None) -> Config:
        p = path or Path(os.environ.get("VEROSCUDO_CONFIG", DEFAULT_CONFIG))
        if not p.exists():
            raise FileNotFoundError(f"VeroScudo config not found: {p} (run install.sh)")
        return Config.from_text(p.read_text())
