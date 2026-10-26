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
veroscudo profiles           # configured profiles, * = active
veroscudo awake              # keep the system from sleeping until Ctrl-C (the tray has a Keep awake toggle too)
sudo veroscudo use Backup    # switch: stays blocked until the new tunnel is up
```

More profiles: add entries to the `"profiles"` list in `/etc/veroscudo/config.json` (see
`../docs/ARCHITECTURE.md`); the tray shows them under *VPN profile*.

What it guarantees: an nftables table with `policy drop` output and forward chains - a drop
there is final whatever ufw/docker/firewalld accept. DNS only while the tunnel is down and only
from `systemd-resolved` (or only to the resolvers in `resolv.conf`); the tunnel is allowed only by
its own virtual interface, never the Wi-Fi/Ethernet card; the ruleset is re-checked every 15 s.

**Status: beta.** The state machine and the nftables ruleset are unit-tested; the daemon has
not yet been through the real-machine tests on Ubuntu (see `tests-local/`). Treat it as a
preview until that log is in the repo.
