# VeroScudo for Linux (NetworkManager + nftables) — beta

Same rule as on Windows: **VPN on + connection lost ⇒ no network until the VPN is back or you
turn it off.** See `../docs/ARCHITECTURE.md`.

Works with any VPN that NetworkManager manages (OpenVPN, WireGuard, IKEv2/strongSwan, L2TP,
SSTP via `network-manager-sstp`). Not for vendor VPN apps that bypass NetworkManager.

Requirements (Ubuntu 22.04+): `nftables`, `network-manager`, `python3-gi`, `gir1.2-nm-1.0`
(for the deactivation *reason*; without it the daemon falls back to polling and treats every
drop as a failure unless it came from `veroscudo off`). Tray: `gir1.2-ayatanaappindicator3-0.1`.

```bash
sudo ./install.sh            # asks for the NetworkManager connection name, installs the service
veroscudo on                 # connect + protect     (sudoers drop-in lets your user run on/off)
veroscudo status
veroscudo off                # deliberately off -> raw internet
```

**Status: beta.** The state machine and the nftables ruleset are unit-tested; the daemon has
not yet been through the real-machine tests on Ubuntu (see `tests-local/`). Treat it as a
preview until that log is in the repo.
