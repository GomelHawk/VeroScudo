"""Platform backends. The guard (daemon.py) is shared; the firewall and the VPN control differ:
Linux = nftables + NetworkManager (beta), macOS = pf + scutil (alpha)."""
from __future__ import annotations

import sys

if sys.platform == "darwin":
    from . import pf as firewall  # noqa: F401
    from . import scutil as nm  # noqa: F401
else:
    from . import firewall  # noqa: F401
    from . import nm  # noqa: F401
