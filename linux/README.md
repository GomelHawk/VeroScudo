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
veroscudo reconnect          # block, take the VPN down, redial; traffic again once the tunnel is back
veroscudo profiles           # configured profiles with their type, * = active
veroscudo check              # does each profile's protocol/port match its NetworkManager connection?
veroscudo import             # list NetworkManager's VPN connections and what would be imported
sudo veroscudo import "Office L2TP"   # add it with its type's server ports (L2TP, PPTP, SSTP, OpenVPN, WireGuard, OpenConnect;
                                      # strongSwan/libreswan IPsec is refused: no tunnel interface to allow)
veroscudo awake              # keep the system from sleeping until Ctrl-C (the tray has a Keep awake toggle too)
sudo veroscudo use Backup    # switch: stays blocked until the new tunnel is up
```

More profiles: add entries to the `"profiles"` list in `/etc/veroscudo/config.json` (see
`../docs/ARCHITECTURE.md`); the tray shows them under *VPN profile*.

What it guarantees: an nftables table with `policy drop` output and forward chains - a drop
there is final whatever ufw/docker/firewalld accept. DNS only while the tunnel is down and only
from `systemd-resolved` (or only to the resolvers in `resolv.conf`); the tunnel is allowed only by
its own virtual interface, never the Wi-Fi/Ethernet card; the ruleset is re-checked every 15 s.

Containers and VMs (Docker, libvirt, LXD, podman - `"vm": "auto"` detects them) follow the same rule: while armed they
reach the network **through the tunnel only**. Everything that stays on the machine keeps working in every state:
host <-> container (published ports on localhost), container <-> container (docker-compose), a VM's DHCP and DNS
from libvirt's dnsmasq. Qualifying bridges are those whose ports are all virtual (veth, tap); a bridge with your
Wi-Fi/Ethernet card enslaved is never allowed. Traffic from the LAN to a published port is blocked while armed, as is
all other inbound traffic. `"vm": false` leaves containers and VMs without any network while armed.

**OpenVPN and WireGuard** connections work as ordinary profiles: NetworkManager reports their "user
disconnected" like any VPN. Set `"protocol"` and `"port"` to what the connection uses (`veroscudo check`
tells you when they differ - the kill-switch would block the VPN itself). WireGuard stays *activated*
in NetworkManager when the link is dead, so VeroScudo reads its handshakes (`wg`, from `wireguard-tools`):
no handshake for 3 minutes counts as a drop and the connection is restarted. Give the peer a
`PersistentKeepalive` (e.g. 25). Every switch to a WireGuard profile shows a notice.

**Status: beta.** The state machine and the nftables ruleset are unit-tested; the daemon has
not yet been through the real-machine tests on Ubuntu (see `tests-local/`). Treat it as a
preview until that log is in the repo.
