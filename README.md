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
new to log in to.

| Platform | Status |
| :-- | :-- |
| Windows 10/11 | **stable** - verified with the live leak tests |
| Linux (Ubuntu 22.04+, NetworkManager) | **beta** - unit-tested, no real-machine log yet |
| macOS (pf + scutil) | **alpha** - unit-tested, never run on a Mac |

## What you get

- **A real kill-switch.** Default-block with a short, scoped allow-list (the tunnel, the VPN
  server, DHCP; DNS only while redialing). On Windows these are WFP filters in VeroScudo's own
  sublayer, so no app's firewall *allow* rule can punch through. Covers TCP, UDP/QUIC, ICMP,
  IPv4 and IPv6, inbound and outbound, and traffic from WSL, Docker or NAT-mode VMs.
- **No DNS leak.** While the VPN is up, names are resolved through the tunnel only.
- **Several VPN profiles.** Pick the active one from the tray menu (*VPN profile ▸*) or
  `veroscudo use <name>`; the switch keeps you blocked until the new tunnel is up.
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
  long download or job finishes while you are away. The screen can still turn off. Linux: tray toggle too;
  Linux and macOS: `veroscudo awake` (until Ctrl-C).
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
   scheduled tasks and the tray autostart, and puts **VeroScudo On** / **VeroScudo Off** on your Desktop.
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

To update, run `Install.ps1` again; it keeps your config (a 1.0 single-profile config is converted, and the
1.0 firewall rules are replaced by WFP filters - new filters first, so an armed PC is never open). To remove everything:
`Uninstall.ps1` (add `-Purge` to also delete config and credential).

### Linux (Ubuntu 22.04+, NetworkManager) - beta

```bash
sudo apt install nftables network-manager python3-gi gir1.2-nm-1.0
cd VeroScudo/linux && sudo ./install.sh
sudo veroscudo on
```

See [`linux/README.md`](linux/README.md). The Linux backend is unit-tested but has not yet
been through the real-machine tests; treat it as a preview.

### macOS - alpha

```bash
cd VeroScudo/macos && sudo ./install.sh
sudo veroscudo on
```

`pf` anchor + `scutil --nc`, CLI only, never run on a real Mac yet. See [`macos/README.md`](macos/README.md).

## Using it

| You do | VeroScudo does |
| :-- | :-- |
| Connect the VPN (Windows UI, tray, shortcut) | arms: kill-switch on, traffic only through the tunnel |
| Nothing - the tunnel drops by itself | stays blocked, redials every 10 s, icon turns red; green again when it's back |
| Disconnect the VPN yourself (Windows UI, tray, shortcut) | disarms: firewall back to normal, icon grey |
| Sit in a cafe with a captive portal | turn the VPN **off**, log in to the portal, turn it **on** |
| Pick another profile in tray > *VPN profile* (or `veroscudo use <name>`) | stays blocked, hangs up the old tunnel, dials the new one |

Tray menu: **Turn VPN on** / **Turn VPN off** / **VPN profile ▸** / Status / Open log / Settings /
About / Exit (the guard keeps running without the tray). Left-click shows the status window.
The tray runs without administrator rights.

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
only from the VPN service), DHCP, and - only while redialing - DNS from the system resolver to
the network's DNS servers and, on Windows, the certificate-revocation check the VPN service
performs. DNS while redialing is the one documented side-channel - it is needed to resolve the
VPN server. Nothing else leaves the machine: no LAN, no printers over the network, no QUIC, no
ping, no IPv6, and no app gets through on the strength of its own firewall rule.

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
- **Not for third-party VPN apps** (OpenVPN GUI, WireGuard app, Hiddify, vendor clients that
  bypass the OS): VeroScudo cannot tell their "you hung up" from a failure, and their many
  servers and helper processes cannot be put on a short allow-list. Import the profile into
  Windows/NetworkManager/macOS instead.
- **It protects you from network failures, not from malware.** Turning the VPN off is your right,
  so a program running as you can do it too. See the threat model in [`docs/SECURITY.md`](docs/SECURITY.md).
- **Locked out?** From an elevated PowerShell: `& "C:\Program Files\VeroScudo\VeroScudo.ps1" -Action off`
  (or `Uninstall.ps1`). Linux/macOS: `sudo veroscudo off`.

## Contributing

Issues and pull requests are welcome - see [`CONTRIBUTING.md`](CONTRIBUTING.md). Anything that
touches the guard logic needs the local test log attached.

## Licence

[MIT](LICENSE). VeroScudo is one of the Vero tools by [GomelHawk](https://github.com/GomelHawk).
