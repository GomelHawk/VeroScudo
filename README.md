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
  <img src="https://img.shields.io/badge/macOS-planned-999.svg" alt="macOS planned">
</p>

Your company says the VPN must be on. Then the tunnel drops for a second - a flaky Wi-Fi, a
server hiccup - and your laptop quietly carries on over the plain network until you notice.
VeroScudo is the switch that makes "VPN on" mean it: **with the VPN on, a lost connection
leaves you with no network at all until the tunnel is back**, and it redials for you in the
meantime. Turn the VPN off yourself and the laptop is a normal laptop again. That is the whole
rule, and there is no setting that weakens it.

It works with the VPN client your OS already has - Windows built-in profiles (SSTP, IKEv2,
L2TP, PPTP) and NetworkManager on Linux - so there is nothing new to log in to.

## What you get

- **A real kill-switch.** Firewall default-drop with a short allow-list (the tunnel, the VPN
  server, DHCP, DNS). Covers TCP, UDP/QUIC, ICMP, and traffic from WSL, Docker or VMs.
- **Auto-reconnect, forever.** Every 10 seconds until the tunnel is back - never gives up,
  never "falls back" to raw internet.
- **It knows why the VPN ended.** The OS reports whether *you* hung up or the link failed.
  You hung up: firewall restored. Link failed: stay blocked, redial.
- **A tray icon** that shows the state at a glance - Protected, Blocked, Off, Attention -
  with *Turn on* / *Turn off*, status and log one click away.
- **Update notice.** The tray tells you when a newer release exists (one check of the GitHub
  release after sign-in, only while traffic is allowed; `updateCheck: false` turns it off). Installing stays manual.
- **Two actions, nothing else.** On and Off. No "unblock" button, no timer, no backdoor -
  because a security policy with a backdoor is a suggestion.
- **Verified the hard way.** A live test harness that makes the VPN server unreachable,
  bounces the link and probes for leaks every 12 seconds for three minutes (see
  [Testing](#testing)).

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

   It copies the program to `C:\Program Files\VeroScudo`, writes
   `%ProgramData%\VeroScudo\config.json`, registers the scheduled tasks and the tray autostart,
   and puts **VeroScudo On** / **VeroScudo Off** on your Desktop.
3. Store your VPN password for the automatic redial (once, as your normal user - no admin):

   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\Program Files\VeroScudo\Set-VpnCredential.ps1"
   ```

   It is kept DPAPI-encrypted for your Windows account only. Windows' own saved password is
   not available to unattended redials, which is why this step exists.
4. Connect the VPN - from Windows, or with the **VeroScudo On** shortcut. The shield in the
   tray turns green. Done.

To update, run `Install.ps1` again; it keeps your config. To remove everything:
`Uninstall.ps1` (add `-Purge` to also delete config and credential).

### Linux (Ubuntu 22.04+, NetworkManager) - beta

```bash
sudo apt install nftables network-manager python3-gi gir1.2-nm-1.0
cd VeroScudo/linux && sudo ./install.sh
sudo veroscudo on
```

See [`linux/README.md`](linux/README.md). The Linux backend is unit-tested but has not yet
been through the real-machine tests; treat it as a preview.

### macOS

Planned (`pf` firewall + `scutil`). See [`macos/README.md`](macos/README.md).

## Using it

| You do | VeroScudo does |
| :-- | :-- |
| Connect the VPN (Windows UI, tray, shortcut) | arms: kill-switch on, traffic only through the tunnel |
| Nothing - the tunnel drops by itself | stays blocked, redials every 10 s, icon turns red; green again when it's back |
| Disconnect the VPN yourself (Windows UI, tray, shortcut) | disarms: firewall back to normal, icon grey |
| Sit in a cafe with a captive portal | turn the VPN **off**, log in to the portal, turn it **on** |

Tray menu: **Turn VPN on** / **Turn VPN off** / Status / Open log / Open config / About /
Exit (the guard keeps running without the tray). Left-click shows the status window.

Command line (Windows): `powershell -File "C:\Program Files\VeroScudo\VeroScudo.ps1" -Action status`
(also `on`, `off`). Log: `%ProgramData%\VeroScudo\state\veroscudo.log`.

### How it decides

VeroScudo does not guess. Windows logs every VPN termination with a reason code; **631** means
"the user disconnected", everything else is a failure. NetworkManager reports
`user-requested` the same way. That single fact selects *disarm* or *reconnect* - see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the state machine, the exact allow-list and
the platform details.

### What is allowed while blocked

Only: the tunnel itself, TCP to the VPN server's address and port (to redial), DHCP, DNS, and
on Windows the certificate-revocation check the VPN service performs (two system services,
port 80). DNS is the one documented side-channel - it is needed to resolve the VPN server.
Nothing else leaves the machine: no LAN, no printers over the network, no QUIC, no ping.

## Testing

Unit tests run in CI on every change (Pester for the Windows core, pytest for Linux) and
pin the two things that must never regress: the decision table (631 ⇒ disarm, anything else
⇒ reconnect, never "unblock") and the allow-list (every rule scoped, never a blanket accept).

The real proof is local: `windows/tests-local/Test-Live.ps1` drives the installed guard through
its scheduled tasks - server made unreachable, link bounced, three minutes of leak probes
(TCP 443/80, ICMP, WSL, DNS) with a watchdog run in the middle, auto-recovery, Off/On, a
manual disconnect - and prints a PASS/FAIL verdict. Run it before trusting a change, and
paste the verdict into your pull request. [`docs/TESTING.md`](docs/TESTING.md) has the details
and the record of the last full run.

## Good to know

- **Wi-Fi reset fix (Windows).** Windows Connection Manager marks a Wi-Fi link "bad" when it
  has no direct internet and resets the adapter ~15 s after a tunnel is dialed under the
  kill-switch, killing it. The installer sets `EnableBadStateTracking=0`; the uninstaller
  reverts it. Without it, every third reconnect dies young. Details in the architecture doc.
- **Only two states exist on purpose.** If you need raw internet, turn the VPN off. There is
  deliberately no "unblock while the VPN is down" action.
- **Password on the command line.** On Windows the redial passes the password to `rasdial`
  as an argument (visible to administrators of the same machine for a second). A RasDial API
  call is on the roadmap.
- **Not for third-party VPN apps** (OpenVPN GUI, WireGuard app, vendor clients that bypass the
  OS). Import the profile into Windows/NetworkManager instead.

## Contributing

Issues and pull requests are welcome - see [`CONTRIBUTING.md`](CONTRIBUTING.md). Anything that
touches the guard logic needs the local test log attached.

## Licence

[MIT](LICENSE). VeroScudo is one of the Vero tools by [GomelHawk](https://github.com/GomelHawk).
