"""`veroscudo import`: adds VPN connections the OS already has (NetworkManager / macOS VPN services) to config.json with
the right settings for their type - server, port, protocol and vpnType - so the kill-switch allows exactly that VPN."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .config import Config, config_path, profile_id


def importable(d: dict) -> bool:
    """A discovered connection VeroScudo can protect: a server (or, for Hiddify, its config file) and nothing against it.
    Pure."""
    if d.get("unsupported"):
        return False
    return bool(d.get("config_path")) if d.get("vpn_type") == "hiddify" else bool(d.get("server"))


def summary(d: dict) -> str:
    """'openvpn  vpn.example.com:1194' / 'Hiddify (VPN mode)  /home/.../current-config.json' for the import lists. Pure."""
    if d.get("vpn_type") == "hiddify":
        return f"Hiddify (VPN mode)  {d.get('config_path', '')}"
    return f"{d['vpn_type'] or d['protocol']}  {d['server'] or '-'}:{d['port']}"


def to_profile(d: dict) -> dict:
    """A discovered connection -> its config.json entry. Pure."""
    if d.get("vpn_type") == "hiddify":                     # no server/port/username: its servers come from its live config
        return {"profile": d["name"], "vpnType": "hiddify", "configPath": d["config_path"]}
    p = {"profile": d["name"], "server": d["server"], "port": int(d["port"]), "protocol": d["protocol"]}
    if d.get("vpn_type"):
        p["vpnType"] = d["vpn_type"]
    if d.get("username"):
        p["username"] = d["username"]
    return p


def add_profiles(raw: str, found: list[dict], names: list[str]) -> tuple[str, list[str]]:
    """Adds the named, importable connections to the config text (validated). Returns (new text, messages). Pure.
    Raises ValueError for a name that is unknown, not importable or already configured."""
    j, profiles = _load(raw)
    have = {str(p.get("profile")) for p in profiles}
    by_name = {d["name"]: d for d in found}
    msgs = []
    for n in names:
        d = by_name.get(n)
        if d is None:
            raise ValueError(f"no VPN connection named '{n}' (see: veroscudo import)")
        if n in have:
            raise ValueError(f"'{n}' is already configured")
        if not importable(d):
            raise ValueError(f"'{n}' cannot be imported: {d['note'] or 'no server found'}")
        profiles.append(to_profile(d))
        have.add(n)
        what = (f"Hiddify (VPN mode), servers from {d['config_path']}" if d.get("vpn_type") == "hiddify"
                else f"{d['vpn_type'] or d['protocol']} to {d['server']} port {d['port']}")
        msgs.append(f"imported '{n}': {what}" + (f" ({d['note']})" if d["note"] else ""))
    j.setdefault("activeProfile", profiles[0]["profile"])
    return _dump(j, profiles), msgs


def _load(raw: str) -> tuple[dict, list[dict]]:
    j = json.loads(raw) if raw.strip() else {}
    profiles = list(j.get("profiles") or ([j["vpn"]] if j.get("vpn") else []))
    j.pop("vpn", None)
    return j, profiles


def _dump(j: dict, profiles: list[dict]) -> str:
    j["profiles"] = with_ids(profiles)
    text = json.dumps(j, indent=2) + "\n"
    Config.from_text(text)                                   # the same validation as at load time
    return text


def with_ids(profiles: list[dict]) -> list[dict]:
    """Every profile gets its lasting "id" written down (statistics follow it across a rename): a profile without one gets
    the id its name gives (what the guard has used for it so far), or a random one when another profile holds that id
    already (a new profile named like one renamed earlier). Pure apart from the random fallback."""
    taken = {p["id"] for p in profiles if isinstance(p.get("id"), str) and profile_id("", p["id"]) == p["id"]}
    out = []
    for p in profiles:
        q = dict(p)
        if q.get("id") not in taken or profile_id("", q.get("id")) != q.get("id"):
            want = profile_id(str(q.get("profile", "")))
            q["id"] = want if want not in taken else os.urandom(6).hex()
        taken.add(q["id"])
        out.append(q)
    return out


def remove_profile(raw: str, name: str) -> str:
    """config.json without profile `name`. The last profile cannot go (the guard needs one); when the default goes, the
    first remaining profile becomes the default. Pure; raises ValueError."""
    j, profiles = _load(raw)
    keep = [p for p in profiles if str(p.get("profile")) != name]
    if len(keep) == len(profiles):
        raise ValueError(f"no profile named '{name}' in config.json")
    if not keep:
        raise ValueError(f"'{name}' is the only profile - add another one first (or uninstall)")
    if j.get("activeProfile") == name:
        j["activeProfile"] = keep[0]["profile"]
    return _dump(j, keep)


def set_default(raw: str, name: str) -> str:
    """activeProfile = `name`: the fallback used only when nothing is selected (first start, the selected profile removed) -
    there is no "default" to choose in the UI; the tray menu's selection is what is used. Pure; raises ValueError."""
    j, profiles = _load(raw)
    if name not in {str(p.get("profile")) for p in profiles}:
        raise ValueError(f"no profile named '{name}' in config.json")
    j["activeProfile"] = name
    return _dump(j, profiles)


# the settings the tray may change, and the values each accepts (the CLI's `set`, run as root)
OPTIONS = {"updateCheck": {"true": True, "false": False},
           "vm": {"true": True, "false": False, "auto": True}}       # "auto": the pre-1.4 value, = true


def set_option(raw: str, key: str, value: str) -> str:
    """updateCheck true|false, vm auto|true|false, connectionCheck <JSON object> - nothing else (the strict rule has no
    setting). Pure; raises ValueError (the whole file is validated again before anything is written)."""
    if key == "connectionCheck":
        try:
            obj = json.loads(value)
        except ValueError:
            raise ValueError("connectionCheck must be a JSON object") from None
        j, profiles = _load(raw)
        j[key] = obj
        return _dump(j, profiles)
    if key not in OPTIONS:
        raise ValueError(f"'{key}' cannot be set here (only: {', '.join([*OPTIONS, 'connectionCheck'])})")
    allowed = OPTIONS[key]
    if value not in allowed:
        raise ValueError(f"{key} must be one of {', '.join(allowed)}")
    j, profiles = _load(raw)
    j[key] = allowed[value]
    return _dump(j, profiles)


def write_config(text: str, path: Path | None = None) -> Path:
    p = path or config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.new")
    tmp.write_text(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, p)                                       # atomic
    return p
