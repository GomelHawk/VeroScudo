"""The two platform backends implement one contract (backend.py), and the shared code uses nothing beyond it."""
import re
from pathlib import Path

import pytest

from veroscudo import backend, firewall, nm, pf, scutil

SRC = Path(__file__).resolve().parent.parent / "veroscudo"
SHARED = ("daemon.py", "cli.py", "tray.py", "importer.py")


@pytest.mark.parametrize("module", [nm, scutil])
def test_vpn_backends_implement_the_contract(module):
    backend.check_contract(module, backend.VPN_API)


@pytest.mark.parametrize("module", [firewall, pf])
def test_firewall_backends_implement_the_contract(module):
    backend.check_contract(module, backend.FIREWALL_API)


def test_a_missing_function_fails_at_import_time():
    class Half:
        __name__ = "half"
        up = staticmethod(lambda p: True)
    with pytest.raises(ImportError, match="lacks"):
        backend.check_contract(Half, backend.VPN_API)


def test_shared_code_calls_only_the_contract():
    """A call like nm.foo() in the shared modules must be in VPN_API (and firewall.foo in FIREWALL_API): otherwise it
    works on the platform it was written on and fails on the other."""
    for name in SHARED:
        text = (SRC / name).read_text()
        for mod, api in (("nm", backend.VPN_API), ("firewall", backend.FIREWALL_API)):
            used = set(re.findall(rf"\b{mod}\.([A-Za-z_]\w*)\s*\(", text))
            assert used <= set(api), f"{name}: {sorted(used - set(api))} not in the {mod} contract"
