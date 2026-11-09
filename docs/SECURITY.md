# VeroScudo security

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private reporting:
*Security* tab → *Report a vulnerability* on [GomelHawk/VeroScudo](https://github.com/GomelHawk/VeroScudo/security/advisories/new).
Include the platform, version (`veroscudo status` / tray *Copy report*) and steps to reproduce.
You will get an answer within a week; fixes for confirmed leaks are released as soon as they are
verified with the live tests.

## Threat model

VeroScudo is a **network kill-switch for the VPN client your OS already has**. What it promises:

> With the VPN on, nothing leaves the machine except through the tunnel - also while the tunnel is
> down, also after a reboot, until the tunnel is back or **you** turn the VPN off.

### In scope - what it protects against

| Threat | How |
|---|---|
| The tunnel drops (Wi-Fi, server, sleep, reboot) and apps carry on over the plain network | default-block filters stay in force; redial forever |
| Apps that have their own firewall allow rules (Store apps, installers, GPO), QUIC, ICMP, IPv6 | Windows: WFP filters in an own sublayer - a block there is final; Linux: a `policy drop` table; all protocols, both IP versions, inbound and outbound |
| DNS leaking to the local network while protected | no DNS permit outside the tunnel while it is up |
| DNS / port 53 used as a side door while blocked | only the OS resolver service, only to the network's resolvers |
| A hostile network spoofing the VPN server's address | server permit limited to the VPN's protocol/port and (Windows) to `svchost.exe`; the server's certificate is still validated by the VPN |
| Something resets the firewall (GPO refresh, `nft flush ruleset`) | Windows filters are independent of the firewall policy; the watchdog re-checks every 15 s |
| A forged "user disconnected" event | acted on only for the active profile, only if the tunnel is really down, never when two records conflict, only for the connection id seen connecting (SSTP/L2TP/PPTP: System log; IKEv2 logs its connect only in the user-writable Application log, so for IKEv2 this last check is weaker) |
| Non-admin code redirecting the elevated guard | no environment overrides - system folders (Program Files, ProgramData, System32) come from the OS and HKLM, never from `%ProgramFiles%`-style variables a user can plant in `HKCU\Environment`; executables by full System32 path (never the user's App Paths key); `PSModulePath` pinned to the system module folders in every script that runs elevated (a module planted in `Documents\WindowsPowerShell\Modules` would otherwise auto-load as administrator); state folder and program folder (also a custom `-InstallDir`) writable by administrators only; config validated. macOS: the program is under root-owned `/opt`, never Homebrew's user-writable `/usr/local` |
| The config file is missing or broken when an armed Linux/macOS machine boots | the boot step and the daemon fail closed: a lockdown ruleset (loopback, DHCP, neighbour discovery) until the file is fixed |
| Two VeroScudo processes changing the firewall at once (Linux/macOS: the daemon's watchdog and a `veroscudo on`) | every "read the armed flag, then apply or clear" runs under one cross-process lock (`flock` in `/run/veroscudo`); a tidy-up that finds the machine armed meanwhile keeps the table |
| The Windows installer run by a different account than the one signed in (over-the-shoulder UAC) | refused: tasks, tray and the DPAPI credential must belong to the signed-in administrator |
| The VPN password leaking via process lists / EDR logs | `RasDial` API, never on a command line; DPAPI-encrypted per user |
| A tampered update link | only this project's GitHub release pages are opened; nothing is installed automatically |
| An imported OpenVPN config running code as administrator | only an allow-list of client options is accepted (no scripts, plugins, PKCS#11/OpenSSL modules, management, includes, logs, proxies; no quoted or escaped option names); key files inlined only when they hold no tag lines; checked again by the elevated import, the stored text once more as a whole; administrators-only; `--script-security 1` on the command line |
| A local program taking over VeroScudo's OpenVPN | management on 127.0.0.1, a random port, a one-time password in an administrators-only file (deleted after login), and VeroScudo connects first while OpenVPN waits in hold |
| Retrying a rejected password until the VPN account is locked | the redial pauses (still blocked) until a newer password is stored |
| A dead WireGuard link that keeps its adapter up | judged by handshake age and restarted; meanwhile traffic goes into the dead tunnel and is lost, never out of the physical NIC |

### Out of scope - what it does **not** protect against

- **Anything running as you that wants the VPN off.** Turning the VPN off is a right VeroScudo gives
  its user (the *Off* task, `rasdial /disconnect`, `sudo veroscudo off`), so a program running under
  your account can do the same. VeroScudo is not anti-malware.
- **Administrators / root** can remove any filter.
- **Traffic inside the tunnel** - that is the VPN's job.
- **Hyper-V Default Switch VMs - covered, with a short window when only the VPN dies.** Windows translates their
  traffic inside the Hyper-V switch, below WFP (WFP's forwarding layers never see it), so VeroScudo stops it there with
  Hyper-V port ACLs while the tunnel is down, and blocks them as soon as Windows logs "network disconnected" until the
  tunnel is proven again (docs/ARCHITECTURE.md, *VMs and containers*). Live test 2026-11-06: before the fix a Default
  Switch VM left through the ISP for 2-7 s per Reconnect or Wi-Fi drop; after it, two Reconnects and a 30 s Wi-Fi outage
  showed only the VPN's exit address (VMs blocked 1 s after the Wi-Fi went away). Remaining: a VPN that dies while the
  network itself stays up is caught when Windows reports it (~1-2 s, like WSL). Not tested: Windows Sandbox and Docker in
  Hyper-V mode. Without the Hyper-V PowerShell tools VeroScudo logs that these VMs are not covered.
- **Bridged virtual machines** (Hyper-V external switch, VirtualBox/VMware/Parallels/libvirt bridged mode) and **Docker
  macvlan/ipvlan networks** - their frames bypass the host's IP stack, so no host firewall can see them. VeroScudo does
  not detect or report them (Settings > Behaviour says so under *Protect VMs and containers*); to protect such a VM,
  switch it to NAT mode or run a VPN with a kill-switch inside it. NAT-mode VMs, WSL and bridge-mode Docker/libvirt
  are covered (with a ~1–2 s window after a drop).
- **Hiddify (VPN mode)** - supported as a kill-switch-only profile. Windows: `Hiddify.exe`/`HiddifyCli.exe` may reach
  any address (by program, from an administrators-only folder), so whatever the app itself sends outside its tunnel
  (its update check, error reports) is not covered. Linux/macOS: only the servers in its live config (see ARCHITECTURE).
  Any drop - also your own disconnect in Hiddify - keeps everything blocked until its tunnel is back or VeroScudo is off.
  Live test 2026-11-09 (Windows, Hiddify 4.1.1, `windows/tests-local/Test-Hiddify.ps1`): disconnect in Hiddify, quit
  Hiddify -> only BLOCKED; reconnect, restart and server changes while VeroScudo stayed on -> through Hiddify at once;
  0 of 61 samples showed the real address.
- **Vendor VPN apps** with their own tunnel drivers and kill-switches (PrivateVPN's app, NordVPN ...) -
  VeroScudo cannot tell their "you hung up" from a failure. It detects their tunnels and filter layers and shows
  *Attention*. OpenVPN (run by VeroScudo itself) and the WireGuard app's tunnels are supported profile types (beta).
- **WireGuard: the first 1-3 minutes of a silent drop** - traffic goes into the dead tunnel and is lost (not leaked)
  until the handshake age shows the drop; then the redial starts.
- **DNS while blocked** is the one documented side channel: the OS resolver may query the
  network's DNS servers (needed to find the VPN server).
- **macOS (alpha)**: the boot window before launchd starts the daemon; VM filtering (pf, vmnet bridges) written but not yet seen on a real Mac.

## Hardening checklist for changes

Every pull request that touches the guard, the installers or the tray answers these:

1. **Fail closed?** If this throws halfway, is the machine blocked or open? (Apply new filters before
   removing old ones; never leave an armed machine without a block.)
2. **Who can influence it?** Can a non-admin process change an input (file, registry, environment,
   event log, command line) that the elevated guard acts on? Validate, or move the input out of reach.
3. **Is every permit scoped?** No rule without an interface, address, port or program. The unit tests
   enforce this - keep them.
4. **Strict stays strict.** No timers, no fallbacks to raw internet, no "unblock" action.
5. **Tested where it matters.** The live tests (`windows/tests-local/Test-Live.ps1`) probe the real leak
   paths; paste the verdict into the PR.

## Release integrity

- Release archives carry **build provenance** (Sigstore): `gh attestation verify <file> --repo GomelHawk/VeroScudo`.
- Windows scripts are **Authenticode-signed** when the repository has a signing certificate
  configured (`SIGNING_PFX_BASE64`); check with `Get-AuthenticodeSignature .\Install.ps1`.
- `SHA256SUMS.txt` detects corrupted downloads (not tampering - use the attestation for that).
- CI pins every action to a commit SHA and runs with a read-only token; Pester and PSScriptAnalyzer are installed at
  exact versions. The release tag reaches the release scripts only as environment data and must look like a version
  (`v1.2.3`); it is never pasted into script text.
