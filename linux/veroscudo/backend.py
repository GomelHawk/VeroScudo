"""Platform backends. The guard (daemon.py) is shared; the firewall and the VPN control differ:
Linux = nftables + NetworkManager (beta), macOS = pf + scutil (alpha)."""
from __future__ import annotations

import sys

if sys.platform == "darwin":
    from . import pf as firewall
    from . import scutil as nm
else:
    from . import firewall, nm

__all__ = ["firewall", "nm"]          # re-exported: daemon.py and cli.py import them from here
