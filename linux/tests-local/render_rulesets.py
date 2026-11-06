"""Writes every kill-switch ruleset VeroScudo can produce - each VPN type, tunnel up and down, DNS policies, LAN ranges,
container bridges, the lockdown - so CI can feed them to the real parser: `nft -c -f` (Linux) and `pfctl -n -f` (macOS).
Unit tests check what the rules say; this checks that the system accepts them.

    python3 render_rulesets.py nft|pf OUTDIR"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from veroscudo import firewall, pf
from veroscudo.config import VPN_TYPES, Config
from veroscudo.firewall import DnsPolicy


def configs():
    for vt in sorted(VPN_TYPES):
        yield vt or "plain", Config.from_text(json.dumps({
            "profiles": [{"profile": "P", "server": "vpn.example.com", "port": 4443, "protocol": "udp" if vt in ("wireguard", "") else "tcp",
                          "vpnType": vt}],
            "lanAllow": ["192.168.1.0/24", "fd00::/64"]}))


def main(kind: str, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    mod = firewall if kind == "nft" else pf
    tun = "wg0" if kind == "nft" else "utun4"
    n = 0
    for name, cfg in configs():
        for state, t in (("up", tun), ("down", None)):
            for dname, dns in (("uid", DnsPolicy(uid=101)), ("servers", DnsPolicy(servers=("192.0.2.53", "2001:db8::53"))), ("none", DnsPolicy())):
                if kind == "pf" and dname == "uid":
                    continue                       # pf scopes DNS by destination only
                rs = mod.render_ruleset(cfg, ["203.0.113.5", "2001:db8::5"], t, vm_allowed=bool(t), dns=dns,
                                        bridges=("docker0", "virbr0") if kind == "nft" else ())
                (out / f"{name}-{state}-{dname}.rules").write_text(rs)
                n += 1
            if kind == "nft":                          # VMs and containers not protected: forwarding left alone
                rs = mod.render_ruleset(cfg, ["203.0.113.5"], t, vm_allowed=False, bridges=("docker0",), vms_free=True)
                (out / f"{name}-{state}-vms-free.rules").write_text(rs)
                n += 1
    (out / "lockdown.rules").write_text(mod.render_lockdown())
    print(f"{n + 1} rulesets in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], Path(sys.argv[2])))
