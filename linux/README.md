# VeroScudo for Linux (NetworkManager + nftables) — beta

Same rule as on Windows: **VPN on + connection lost ⇒ no network until the VPN is back or you
turn it off.** See `../docs/ARCHITECTURE.md`.

Works with any VPN that NetworkManager manages (OpenVPN, WireGuard, IKEv2/strongSwan, L2TP,
SSTP via `network-manager-sstp`). Not for vendor VPN apps that bypass NetworkManager.

## Install, use, uninstall

```bash
sudo ./install.sh                         # installs missing packages (asks), lets you pick the VPN connection, starts it all
sudo ./install.sh --profile "Office VPN"  # no questions about the profile;  --yes: no question about packages
```

The installer needs Ubuntu 22.04+ (or another apt-based distribution; elsewhere it names the missing packages): nftables,
NetworkManager, `python3-gi` + `gir1.2-nm-1.0` (the "you hung up" reason), `gir1.2-gtk-3.0` +
`gir1.2-ayatanaappindicator3-0.1` + `libnotify-bin` (tray), `pkexec` (Settings), `wireguard-tools`. Plain GNOME (not Ubuntu)
also gets `gnome-shell-extension-appindicator` - enable it once in the Extensions app.

What goes where: the program in `/opt/veroscudo` (root's; run by `/usr/bin/python3 -I`), `veroscudo` on the PATH through
`/usr/local/bin`, the services `veroscudo.service` (guard) and `veroscudo-boot.service` (kill-switch before the network at
boot), the tray autostart `/etc/xdg/autostart/veroscudo-tray.desktop` and the menu entry *VeroScudo*, the sudoers rule
`/etc/sudoers.d/veroscudo` (your user: `on`, `off`, `reconnect`, `use` without a password - nothing else), the config
`/etc/veroscudo/config.json`, the log `/var/log/veroscudo.log` (readable by the `adm` group).

**Tray** (top bar): Turn VPN on / off, Reconnect VPN, VPN profile ▸, Status… (middle-click too), Open log, Statistics… (7
days of VPN time and connection quality, one bar per 10 minutes on a 24-hour grid), Settings…
(import a NetworkManager connection, remove, default, update check, containers/VMs - each change asks for your password;
*Show exit location* is your own setting and is saved at once), Keep awake (a green ring on the icon while on), Check for
updates, About (Uninstall…), Exit tray. Exit leaves the guard running; *VeroScudo* in the applications menu brings the
icon back.

**Status window**: the state, where your traffic leaves the tunnel (country, city, IP - asked from ipinfo.io right after
each connect and on *Refresh*, never while not protected), the profile, firewall, last drop and connection rating, other
VPNs next to VeroScudo, the recent events (*Clear* empties the view, not the log), Turn VPN on/off, Reconnect, Open log
and Copy report. **Another VPN**: Turn VPN on asks first when another VPN is connected (disconnect it and turn on, turn on
anyway, or cancel); a VPN that connects while VeroScudo is on is announced once - its traffic is blocked.

**Uninstall**: tray > About > *Uninstall…*, or `sudo /opt/veroscudo/uninstall.sh` (`--purge`: also config, state, log).

Command line:

```bash
veroscudo status
sudo veroscudo on            # arm + dial once; the service keeps redialing until it is up
sudo veroscudo off           # deliberately off -> raw internet
sudo veroscudo reconnect     # block, take the VPN down, redial; traffic again once the tunnel is back
veroscudo profiles           # configured profiles with their type, * = active
sudo veroscudo use Backup    # switch: stays blocked until the new tunnel is up
veroscudo check              # does each profile's protocol/port match its NetworkManager connection?
veroscudo import             # list NetworkManager's VPN connections and what would be imported
sudo veroscudo import "Office L2TP"   # add it with its type's server ports (L2TP, PPTP, SSTP, OpenVPN, WireGuard, OpenConnect;
                                      # strongSwan/libreswan IPsec is refused: no tunnel interface to allow)
sudo veroscudo remove <profile>               # what Settings does
sudo veroscudo set updateCheck true|false     # also: vm true|false
veroscudo awake              # keep the system from sleeping until Ctrl-C (the tray has a Keep awake toggle too)
```

More profiles: tray > Settings > *Import…*, `sudo veroscudo import <connection>`, or entries in the `"profiles"` list of
`/etc/veroscudo/config.json` (see `../docs/ARCHITECTURE.md`); the guard picks a change up within 15 s.

What it guarantees: an nftables table with `policy drop` output and forward chains - a drop
there is final whatever ufw/docker/firewalld accept. DNS only while the tunnel is down and only
from `systemd-resolved` (or only to the resolvers in `resolv.conf`); the tunnel is allowed only by
its own virtual interface, never the Wi-Fi/Ethernet card; the ruleset is re-checked every 15 s.

Containers and VMs (Docker, libvirt, LXD, podman) follow the same rule when *Protect VMs and containers* is on (`"vm": true`,
the default): while armed they
reach the network **through the tunnel only**. Everything that stays on the machine keeps working in every state:
host <-> container (published ports on localhost), container <-> container (docker-compose), a VM's DHCP and DNS
from libvirt's dnsmasq. Qualifying bridges are those whose ports are all virtual (veth, tap); a bridge with your
Wi-Fi/Ethernet card enslaved is never allowed. Traffic from the LAN to a published port is blocked while armed, as is
all other inbound traffic. Off (`"vm": false`): VeroScudo leaves containers and VMs alone - their forwarding is not
filtered at all (to cut a VM off, turn its network off inside the VM).

**OpenVPN and WireGuard** connections work as ordinary profiles: NetworkManager reports their "user
disconnected" like any VPN. Set `"protocol"` and `"port"` to what the connection uses (`veroscudo check`
tells you when they differ - the kill-switch would block the VPN itself). WireGuard stays *activated*
in NetworkManager when the link is dead, so VeroScudo reads its handshakes (`wg`, from `wireguard-tools`):
no handshake for 3 minutes counts as a drop and the connection is restarted. Give the peer a
`PersistentKeepalive` (e.g. 25). Every switch to a WireGuard profile shows a notice.

**Status: beta.** The state machine and the nftables ruleset are unit-tested, every ruleset passes `nft -c`, and
`tests-local/container-test.sh` installs, turns on, upgrades, turns off and uninstalls in a systemd container on Ubuntu
22.04, 24.04 and 26.04 (CI). The real-machine leak tests with a real VPN are still open - see `tests-local/README.md` for the
VM recipe. Treat it as a preview until that log is in the repo.
