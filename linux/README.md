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
days of VPN time and connection quality, one bar per 10 minutes on a 24-hour grid; minutes VeroScudo was on but could
not connect count as bad), Settings…
(import a NetworkManager connection, remove, default, update check, containers/VMs - each change asks for your password;
*Show exit location* and the service status page are your own settings and are saved at once; the connection check
can use ping, a TCP port or HTTPS - a TLS handshake and a HEAD request, any answer counts, no account or key), Keep awake (a green ring on the icon while on), Check for
updates, About (Uninstall…), Exit tray. Exit leaves the guard running; *VeroScudo* in the applications menu brings the
icon back.

**Status window**: the state, where your traffic leaves the tunnel (country, city, IP - asked from ipinfo.io right after
each connect and on *Refresh* whenever a VPN tunnel is up - never without one), the profile, firewall, last drop and
connection rating (its tooltip: lost checks per address), the service status page when it is on (an Atlassian Statuspage,
Anthropic's by default, fetched every 5 minutes), other VPNs next to VeroScudo, the recent events (*Clear* empties the view, not the log), Turn VPN on/off, Reconnect, Open log
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

**Hiddify (VPN mode)** can be a profile too: `veroscudo import` (and tray > Settings > *Import…*) lists *Hiddify* when your
Hiddify has its live config (`<data folder>/data/current-config.json`; looked for in `~/.local/share/app.hiddify.com`,
`~/.local/share/hiddify` or `~/.local/share/Hiddify`, each also with a nested `hiddify/` - these Linux paths are not yet
confirmed on a real install). The entry is `{"profile": "Hiddify", "vpnType": "hiddify", "configPath": "<that file>"}` - no
server or port. Only VPN (TUN) mode is supported; in proxy mode the import says so. VeroScudo never starts or stops
Hiddify: connect and reconnect it in Hiddify (Reconnect in the tray is disabled for it). Protected = a Hiddify process runs
and its tun device holds the address from the config; any drop keeps traffic blocked until Hiddify's tunnel is back or
you turn VeroScudo off. While armed the kill-switch also lets Hiddify reach, outside the tunnel, every proxy server in its
live config (server and port, TCP and UDP) and the DNS servers it asks directly - re-read every 15 s, at most 64 entries,
public addresses only. The guard (root) reads that file in your home folder: it only decides which servers may be
reached, and you can already turn the kill-switch off without a password (`sudo veroscudo off`).

**OpenVPN and WireGuard** connections work as ordinary profiles: NetworkManager reports their "user
disconnected" like any VPN. Set `"protocol"` and `"port"` to what the connection uses (`veroscudo check`
tells you when they differ - the kill-switch would block the VPN itself). WireGuard stays *activated*
in NetworkManager when the link is dead, so VeroScudo reads its handshakes (`wg`, from `wireguard-tools`):
no handshake for 3 minutes counts as a drop and the connection is restarted. Give the peer a
`PersistentKeepalive` (e.g. 25). Every switch to a WireGuard profile shows a notice.

**Status: beta.** The state machine and the nftables ruleset are unit-tested, every ruleset passes `nft -c`, and
`tests-local/container-test.sh` installs, turns on, upgrades, turns off and uninstalls in a systemd container on Ubuntu
22.04, 24.04 and 26.04 (CI). On a real machine with a real VPN (SSTP) `tests-local/live.sh` passed with no leak: On,
Reconnect, the VPN dying, a network drop, your own hang-up, Off (`../docs/TESTING.md`). Not yet checked on a real
machine: the tray, a reboot while armed, uninstall, and the other VPN types.
