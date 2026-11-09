<p align="center">
  <img src="https://raw.githubusercontent.com/GomelHawk/VeroScudo/main/assets/horizontal-logo.png"
       alt="VeroScudo - Master the switch."
       width="600">
</p>

<p align="center">
  <a href="https://github.com/GomelHawk/VeroScudo/actions/workflows/ci.yml"><img src="https://github.com/GomelHawk/VeroScudo/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/GomelHawk/VeroScudo/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT licence"></a>
  <img src="https://img.shields.io/badge/Windows-10%2F11-0078d4.svg" alt="Windows 10/11">
  <img src="https://img.shields.io/badge/Linux-NetworkManager%20(beta)-e95420.svg" alt="Linux beta">
  <img src="https://img.shields.io/badge/macOS-pf%20(alpha)-999.svg" alt="macOS alpha">
</p>

Your company says the VPN must be on. Then the tunnel drops for a second - a flaky Wi-Fi, a
server hiccup - and your laptop quietly carries on over the plain network until you notice.
VeroScudo is the switch that makes "VPN on" mean it: **with the VPN on, a lost connection
leaves you with no network at all until the tunnel is back**, and it redials for you in the
meantime. Turn the VPN off yourself and the laptop is a normal laptop again. That is the whole
rule, and there is no setting that weakens it.

It works with the VPN client your OS already has - Windows built-in profiles (SSTP, IKEv2,
L2TP, PPTP), NetworkManager on Linux, the built-in VPN services on macOS - so there is nothing
new to log in to. On Windows a reserve VPN can also be **OpenVPN** (VeroScudo runs your `.ovpn`
itself) or a **WireGuard** tunnel from the WireGuard app - see [Profile types](#profile-types).

| Platform | Status |
| :-- | :-- |
| Windows 10/11 | **stable** - verified with the live leak tests |
| Linux (Ubuntu 22.04+, NetworkManager) | **beta** - unit-tested, install/on/off/uninstall tested in a container in CI, no real-machine leak log yet |
| macOS (pf + scutil) | **alpha** - unit-tested, install/uninstall checked in CI, never run with a real VPN |

## What you get

- **A real kill-switch.** Default-block with a short, scoped allow-list (the tunnel, the VPN
  server, DHCP; DNS only while redialing). On Windows these are WFP filters in VeroScudo's own
  sublayer, so no app's firewall *allow* rule can punch through. Covers TCP, UDP/QUIC, ICMP,
  IPv4 and IPv6, inbound and outbound, and traffic from WSL, Docker or NAT-mode VMs.
- **No DNS leak.** While the VPN is up, names are resolved through the tunnel only.
- **Several VPN profiles.** Pick the active one from the tray menu (*VPN profile ▸*) or
  `veroscudo use <name>`; the switch keeps you blocked until the new tunnel is up.
- **Reconnect.** A slow or stuck tunnel? *Reconnect VPN* (tray) or `veroscudo reconnect` blocks
  traffic, hangs the tunnel up and dials it again; traffic flows once the new tunnel is up.
- **Reserve VPN types (Windows, beta).** Besides Windows' own client: OpenVPN (your `.ovpn`, run
  and controlled by VeroScudo) and WireGuard (a tunnel of the WireGuard app). Each switch to one
  of them shows what it guarantees, and the tray tells you when another VPN or kill-switch runs
  next to VeroScudo.
- **A rejected password stops the redial.** Retrying a wrong password every 10 s can lock your VPN
  account; VeroScudo pauses (still blocked) and asks you to store the right one.
- **VPN off means a normal network.** Turn the VPN off yourself (tray, shortcut, Windows UI or
  `veroscudo off`) and the kill-switch is lifted completely: a regular, non-VPN connection with
  your usual firewall, until you turn the VPN on again. Protection is tied to your choice, not forced.
- **Auto-reconnect, forever.** Every 10 seconds until the tunnel is back - never gives up,
  never "falls back" to raw internet.
- **It knows why the VPN ended.** The OS reports whether *you* hung up or the link failed.
  You hung up: firewall restored. Link failed: stay blocked, redial. A "you hung up" while the
  tunnel is still up, or two different reasons for one connection, is ignored as forged.
- **Self-healing.** A watchdog re-checks the filters every 15 s and re-applies them when anything
  changed or went missing (a new tunnel interface, the WSL adapter recreated at boot, a firewall reset).
- **A tray icon** that shows the state at a glance - Protected, Blocked, Off, Attention -
  with *Turn on* / *Turn off*, status and log one click away.
- **Keep awake** (tray). A menu toggle that keeps the PC from sleeping, locked screen included, so a
  long download or job finishes while you are away. The screen can still turn off. Same toggle on Linux and macOS;
  also `veroscudo awake` there (until Ctrl-C).
- **Update notice.** The tray tells you when a newer release exists (one check of the GitHub
  release after sign-in, only while traffic is allowed; `updateCheck: false` turns it off). Installing stays manual.
- **Two actions, nothing else.** On and Off. No "unblock" button, no timer, no backdoor -
  because a security policy with a backdoor is a suggestion.
- **Verified the hard way.** A live test harness that makes the VPN server unreachable,
  bounces the link and probes for leaks every 12 seconds for three minutes - including from a
  program that has its own firewall allow rule, over IPv6 and to port 53 (see [Testing](#testing)).
  Threat model and reporting: [`docs/SECURITY.md`](docs/SECURITY.md).

## Install

### Windows

1. Create your VPN profile in **Settings > Network & Internet > VPN** (or let IT do it) and
   connect once by hand, so you know it works.
2. Download the [latest release](https://github.com/GomelHawk/VeroScudo/releases) (or clone)
   and run the installer from an **elevated** PowerShell:

   ```powershell
   cd VeroScudo\windows
   .\Install.ps1 -ProfileName "MyCompanyVPN" -Server vpn.example.com -UserName jdoe
   ```

   It first checks that this Windows' filtering platform (WFP) offers everything the kill-switch
   needs (and changes nothing if not), copies the program to `C:\Program Files\VeroScudo`, writes
   `%ProgramData%\VeroScudo\config.json` (folder writable by administrators only), registers the
   scheduled tasks and the tray autostart, puts **VeroScudo On** / **VeroScudo Off** on your Desktop and a
   **VeroScudo** entry in the Start menu that brings the tray icon back after *Exit tray*.

   Run it from the account you sign in with, and that account must be an administrator: the guard tasks run
   elevated for the signed-in user. When a different account elevated (a standard user typing an administrator's
   password), the installer stops and says so - the tasks, the tray and the stored VPN password would otherwise
   belong to two different accounts.
   More profiles: run it again with another `-ProfileName/-Server/-UserName`, or use tray > Settings.
3. Store your VPN password for the automatic redial (once per profile, as your normal user - no
   admin): tray > **Settings** > *Set password...*, or

   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\Program Files\VeroScudo\Set-VpnCredential.ps1"
   ```

   It is kept DPAPI-encrypted for your Windows account only and handed to the `RasDial` API - it
   never appears on a command line. Windows' own saved password is not available to unattended
   redials, which is why this step exists.
4. Connect the VPN - from Windows, or with the **VeroScudo On** shortcut. The shield in the
   tray turns green. Done.

**IKEv2 on a PC with several user accounts:** Windows logs an IKEv2 connect only in the Application log, which every
local account can write. VeroScudo's defence against a forged "you hung up" record is therefore weaker for IKEv2 than for
SSTP, L2TP or PPTP: another local user could make a real drop look like your Off. On a single-user PC this does not
apply; on a shared one prefer SSTP or L2TP (see docs/SECURITY.md).

**More Windows VPN profiles:** tray > **Settings** > **Import from Windows...** lists every VPN of Windows Settings >
VPN (also those created for all users) with the type, server and sign-in VeroScudo found - Automatic, IKEv2, SSTP,
L2TP/IPsec with certificate or pre-shared key, PPTP - and adds the one you choose (one per import: not every VPN
on a PC is for work) with those settings (the port of an
SSTP server address such as `host:4443` included; a username Windows saved is filled in). Nothing is imported
automatically. From the command line: `Install.ps1 -ProfileName "<name as in Windows>"`.

A reserve profile (see [Profile types](#profile-types)):

```powershell
.\Install.ps1 -ProfileName "Reserve" -Type openvpn -OpenVpnConfig C:\Users\me\reserve.ovpn -UserName jdoe
.\Install.ps1 -ProfileName "wg-home" -Type wireguard -WireGuardConfig C:\Users\me\wg-home.conf
```

or tray > **Settings** > *Add...* and pick the type.

To update, run `Install.ps1` again; it keeps your config (a 1.0 single-profile config is converted, and the
1.0 firewall rules are replaced by WFP filters - new filters first, so an armed PC is never open). To remove everything:
`Uninstall.ps1` (add `-Purge` to also delete config and credential).

### Linux (Ubuntu 22.04+, NetworkManager) - beta

1. Create the VPN connection in **Settings > Network > VPN** (or let IT do it) and connect once by hand.
2. Download the [latest release](https://github.com/GomelHawk/VeroScudo/releases) (`VeroScudo-<version>-linux.tar.gz`),
   unpack it and run the installer as your own user:

   ```bash
   cd VeroScudo-linux && sudo ./install.sh
   ```

   It installs what is missing (nftables, NetworkManager's GObject bindings, the tray's GTK/AppIndicator packages,
   `wireguard-tools` - it asks first), lists your NetworkManager VPN connections to pick the one to protect, copies the
   program to `/opt/veroscudo`, starts the guard service and the **tray icon** (top bar; also at every login and from the
   applications menu as *VeroScudo*). `sudo ./install.sh --profile "Office VPN"` skips the question.
3. Connect the VPN - as usual, or with the tray's **Turn VPN on**. The shield turns green. Done.

Uninstall: tray > **About** > *Uninstall…*, or `sudo /opt/veroscudo/uninstall.sh` (add `--purge` to also delete the
config). See [`linux/README.md`](linux/README.md). CI installs, uses and uninstalls it in a container; it has not yet
been through the real-machine leak tests - treat it as a preview.

### macOS - alpha

1. Create the VPN service in **System Settings > VPN** (IKEv2, L2TP or Cisco IPSec) and connect once by hand.
2. Unpack `VeroScudo-<version>-macos-alpha.tar.gz` and run:

   ```bash
   cd VeroScudo-macos/macos && sudo ./install.sh
   ```

   It lists your VPN services to pick from, installs to `/opt/veroscudo` (Apple's own `python3`; the Command Line Tools
   are needed - `xcode-select --install`), starts the guard (launchd) and the **menu-bar icon** (also at every login and as
   `/Applications/VeroScudo.app`), and puts `veroscudo` on the PATH.
3. Turn the VPN on from the menu bar. macOS reports no "you hung up" reason, so **turn it off with VeroScudo** too - a
   disconnect in System Settings counts as a drop (you stay blocked until *Turn VPN off*).

Uninstall: menu bar > **About VeroScudo** > *Uninstall…*, or `sudo /opt/veroscudo/uninstall.sh [--purge]`. `pf` anchor +
`scutil --nc`; never run on a real Mac yet - see [`macos/README.md`](macos/README.md).

## Using it

| You do | VeroScudo does |
| :-- | :-- |
| Connect the VPN (Windows UI, tray, shortcut) | arms: kill-switch on, traffic only through the tunnel |
| Nothing - the tunnel drops by itself | stays blocked, redials every 10 s, icon turns red; green again when it's back |
| Disconnect the VPN yourself (Windows UI, tray, shortcut) | disarms: firewall back to normal, icon grey |
| Sit in a cafe with a captive portal | turn the VPN **off**, log in to the portal, turn it **on** |
| Pick another profile in tray > *VPN profile* (or `veroscudo use <name>`) | stays blocked, hangs up the old tunnel, dials the new one |
| Turn on while another VPN is connected (Windows) | the tray asks first: *Disconnect it and turn on*, or *Cancel* (a VPN app's own tunnel: *Turn on anyway*). Nothing is disconnected or imported without your click. The *On* shortcut / `-Action on` refuses and the tray says why; `-DisconnectOthers` / `-Force` decide on the command line |
| A VPN that is not a VeroScudo profile connects while VeroScudo is on | a notification: its traffic is blocked - disconnect it or import it; the status window lists it under *Other VPNs* |
| *Reconnect VPN* (tray, status window, `-Action reconnect`, `veroscudo reconnect`) | blocks, hangs up, redials; traffic again once the tunnel is back |
| The VPN rejects your password | stays blocked, stops redialing, icon *Attention*; store the right password, then *Reconnect* |

Tray menu (the same on Windows, Linux and macOS): **Turn VPN on** / **Turn VPN off** / **Reconnect VPN** /
**VPN profile ▸** / Status / Open log / **Statistics** (7 days, one bar per 10 minutes) / Settings / Keep awake / Check for updates / About / Exit (the guard keeps running
without the tray). Windows: left-click shows the status window; Linux: middle-click. The tray runs without administrator
rights; changing Settings asks for an administrator's password. Settings has three tabs: **VPN profiles**, **Behaviour**
and **Connection**.

**Connection check** (optional, off by default; Settings > *Connection*): while protected, VeroScudo checks up to three
addresses through the tunnel every 10-100 s - ping, or a TCP connection to a port (default: 1.1.1.1, TCP 443) - and rates
the last 1-10 minutes: under 10 % lost **good**, 10-50 % **unstable**, over 50 % **bad**. The first rating comes one full
period after each connect or settings change (*checking…* until then). The rating shows in the tooltip
(*VeroScudo - Protected, connection good*), the menu header and the status window's **CONNECTION** card, which shows the
redial instead while the VPN is not connected. It only reports - it never reconnects or switches profiles by itself.

Command line (Windows): `powershell -File "C:\Program Files\VeroScudo\VeroScudo.ps1" -Action status`
(also `on`, `off`, and elevated `switch -VpnProfile <name>`). Log: `%ProgramData%\VeroScudo\state\veroscudo.log`.

### How it decides

VeroScudo does not guess. Windows logs every VPN termination with a reason code; **631** means
"the user disconnected", everything else is a failure. NetworkManager reports
`user-requested` the same way. That single fact selects *disarm* or *reconnect* - see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the state machine, the exact allow-list and
the platform details.

### What is allowed while blocked

Only: the tunnel itself, the VPN server's address on the profile's protocol and port (on Windows
only from the VPN service), DHCP (on Windows only from the DHCP client service), and - only while
redialing - DNS from the system resolver to the network's DNS servers (none known: no DNS at all).
On Windows, the SSTP certificate-revocation check (HTTP) is allowed for 2 minutes only after a
dial failed on exactly that check. On Linux nothing reaches the machine from outside either: only
replies to the flows above, the tunnel, DHCP replies and neighbour discovery. DNS while redialing is the one documented side-channel - it is needed to resolve the
VPN server. Nothing else leaves the machine: no LAN, no printers over the network, no QUIC, no
ping, no IPv6, and no app gets through on the strength of its own firewall rule.

## Profile types

| Type | Client | "You turned it off" comes from | Drop noticed | Status |
| :-- | :-- | :-- | :-- | :-- |
| Windows VPN (`ras`, default) | Windows' built-in client | the RAS reason code (631) | seconds | **stable** - preferred |
| OpenVPN (`openvpn`) | `openvpn.exe` of the OpenVPN community installer, started and owned by VeroScudo through its management interface | VeroScudo's own stop - nothing else can claim it | seconds | beta |
| WireGuard (`wireguard`) | a tunnel of the WireGuard for Windows app | the tunnel was deactivated in the WireGuard app (its service removed) | 1-3 minutes (handshake age) | beta |

- **OpenVPN**: your `.ovpn` is checked and imported (key files inlined) into an administrators-only folder. Only known
  client options are accepted - nothing that runs scripts, loads plugins or modules, or brings its own management -
  because VeroScudo runs OpenVPN as administrator.
  Connect and disconnect it with VeroScudo only - **not from OpenVPN GUI**, which would compete for the same connection.
  By default the data channel offload (DCO) is turned off so only `openvpn.exe` may reach the server (`"dco": true` keeps it).
  A config with a one-time code (`static-challenge`) asks for the code in the tray on every connect.
- **WireGuard**: import the tunnel in the WireGuard app first, then add it to VeroScudo under exactly the same name. A
  dead WireGuard link keeps its adapter up, so VeroScudo judges it by its handshakes: set `PersistentKeepalive = 25`.
  Until a drop is noticed, traffic runs into the dead tunnel and is lost - it never leaks.
- Every switch to an OpenVPN or WireGuard profile shows a notice (once per switch, not again while it stays active).

Linux / macOS: `veroscudo import` lists the VPN connections NetworkManager (or macOS) has - OpenVPN, WireGuard, L2TP,
PPTP, SSTP, OpenConnect, and on macOS IKEv2/IPsec - and `sudo veroscudo import <name>` adds one with its type's server
ports. NetworkManager's strongSwan/libreswan IPsec is refused for now: it has no tunnel interface to allow.

Linux: NetworkManager already runs OpenVPN and WireGuard connections and reports "user disconnected" for them, so they
work as ordinary profiles; WireGuard is judged by its handshakes there too. `veroscudo check` compares each profile's
protocol and port with the NetworkManager connection.

## Testing

Unit tests run in CI on every change (Pester for the Windows core, pytest for Linux and macOS)
and pin what must never regress: the decision table (631 ⇒ disarm, anything else ⇒ reconnect,
never "unblock"), the allow-list (every rule scoped, never a blanket accept, DNS only while
down), forged-event handling, profile switching and config validation.

The real proof is local: `windows/tests-local/Test-Live.ps1` drives the installed guard through
its scheduled tasks - DNS-leak and forged-event checks while protected; server made unreachable,
link bounced, three minutes of leak probes (TCP 443/80/53, IPv6, ICMP, WSL - from a program with
its own firewall allow rule) with a firewall reset and a watchdog run in the middle; filters
deleted and self-healed; auto-recovery; profile switch; Off/On; a manual disconnect - and prints
a PASS/FAIL verdict. Run it before trusting a change, and
paste the verdict into your pull request. [`docs/TESTING.md`](docs/TESTING.md) has the details
and the record of the last full run.

## Good to know

- **Wi-Fi reset fix (Windows).** Windows Connection Manager marks a Wi-Fi link "bad" when it
  has no direct internet and resets the adapter ~15 s after a tunnel is dialed under the
  kill-switch, killing it. The installer sets `EnableBadStateTracking=0`; the uninstaller
  reverts it. Without it, every third reconnect dies young. Details in the architecture doc.
- **Only two states exist on purpose.** If you need raw internet, turn the VPN off. There is
  deliberately no "unblock while the VPN is down" action.
- **Hiddify** is supported in **VPN mode** as a kill-switch-only profile (Settings > Import): you connect,
  disconnect and reconnect in Hiddify; VeroScudo blocks everything else while its tunnel is down and records its
  statistics. Proxy modes are not supported.
- **Other vendor VPN apps** (PrivateVPN's app, NordVPN and similar) are not supported: VeroScudo
  cannot tell their "you hung up" from a failure. Most providers also offer IKEv2/L2TP for the Windows
  client, an `.ovpn` or a WireGuard config - use one of those as a profile. VeroScudo shows *Attention*
  when such an app's tunnel or kill-switch runs next to it.
- **It protects you from network failures, not from malware.** Turning the VPN off is your right,
  so a program running as you can do it too. See the threat model in [`docs/SECURITY.md`](docs/SECURITY.md).
- **Locked out?** From an elevated PowerShell: `& "C:\Program Files\VeroScudo\VeroScudo.ps1" -Action off`
  (or `Uninstall.ps1`). Linux/macOS: `sudo veroscudo off`.

## Contributing

Issues and pull requests are welcome - see [`CONTRIBUTING.md`](CONTRIBUTING.md). Anything that
touches the guard logic needs the local test log attached.

## Licence

[MIT](LICENSE). VeroScudo is one of the Vero tools by [GomelHawk](https://github.com/GomelHawk).
