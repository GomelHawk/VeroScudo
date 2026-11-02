"""`veroscudo import`: adds VPN connections the OS already has (NetworkManager / macOS VPN services) to config.json with
the right settings for their type - server, port, protocol and vpnType - so the kill-switch allows exactly that VPN."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .config import DEFAULT_CONFIG, Config


def to_profile(d: dict) -> dict:
    """A discovered connection -> its config.json entry. Pure."""
    p = {"profile": d["name"], "server": d["server"], "port": int(d["port"]), "protocol": d["protocol"]}
    if d.get("vpn_type"):
        p["vpnType"] = d["vpn_type"]
    if d.get("username"):
        p["username"] = d["username"]
    return p


def add_profiles(raw: str, found: list[dict], names: list[str]) -> tuple[str, list[str]]:
    """Adds the named, importable connections to the config text (validated). Returns (new text, messages). Pure.
    Raises ValueError for a name that is unknown, not importable or already configured."""
    j = json.loads(raw) if raw.strip() else {}
    profiles = list(j.get("profiles") or ([j["vpn"]] if j.get("vpn") else []))
    have = {str(p.get("profile")) for p in profiles}
    by_name = {d["name"]: d for d in found}
    msgs = []
    for n in names:
        d = by_name.get(n)
        if d is None:
            raise ValueError(f"no VPN connection named '{n}' (see: veroscudo import)")
        if n in have:
            raise ValueError(f"'{n}' is already configured")
        if not d["server"] or d.get("unsupported"):
            raise ValueError(f"'{n}' cannot be imported: {d['note']}")
        profiles.append(to_profile(d))
        have.add(n)
        msgs.append(f"imported '{n}': {d['vpn_type'] or d['protocol']} to {d['server']} port {d['port']}" + (f" ({d['note']})" if d["note"] else ""))
    j.pop("vpn", None)
    j["profiles"] = profiles
    j.setdefault("activeProfile", profiles[0]["profile"])
    text = json.dumps(j, indent=2) + "\n"
    Config.from_text(text)                                   # the same validation as at load time
    return text, msgs


def write_config(text: str, path: Path | None = None) -> Path:
    p = path or Path(os.environ.get("VEROSCUDO_CONFIG", DEFAULT_CONFIG))
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.new")
    tmp.write_text(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, p)                                       # atomic
    return p
