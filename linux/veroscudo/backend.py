"""Platform backends. The guard (daemon.py), the CLI and the tray are shared; the firewall and the VPN control differ:
Linux = nftables + NetworkManager (beta), macOS = pf + scutil (alpha).

The contract both backends implement is spelled out below and checked when this module loads: a function missing on
one platform fails at startup, not in the middle of a redial. tests/test_backend.py checks that the shared code calls
nothing outside it."""
from __future__ import annotations

import sys
from types import ModuleType

# VPN control (nm.py / scutil.py): names the shared code may call
VPN_API = ("check", "discover", "down", "iface", "is_connected", "is_stale", "kind", "nameservers", "nm_dns",
           "other_tunnels", "resolve", "resolver_uid", "up", "vm_bridges", "wait_connected", "watch")
# kill-switch (firewall.py / pf.py)
FIREWALL_API = ("DnsPolicy", "apply", "clear", "is_active", "render_lockdown", "render_ruleset")


def check_contract(module: ModuleType, api: tuple[str, ...]) -> None:
    missing = [n for n in api if not callable(getattr(module, n, None))]
    if missing:
        raise ImportError(f"backend {module.__name__} lacks {', '.join(missing)}")


if sys.platform == "darwin":
    from . import pf as firewall
    from . import scutil as nm
else:
    from . import firewall, nm

check_contract(nm, VPN_API)
check_contract(firewall, FIREWALL_API)

__all__ = ["firewall", "nm", "VPN_API", "FIREWALL_API", "check_contract"]
