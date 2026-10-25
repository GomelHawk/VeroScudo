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
| A forged "user disconnected" event | acted on only for the active profile, only if the tunnel is really down, never when two records conflict |
| Non-admin code redirecting the elevated guard | no environment overrides; state folder writable by administrators only; config validated |
| The VPN password leaking via process lists / EDR logs | `RasDial` API, never on a command line; DPAPI-encrypted per user |
| A tampered update link | only this project's GitHub release pages are opened; nothing is installed automatically |

### Out of scope - what it does **not** protect against

- **Anything running as you that wants the VPN off.** Turning the VPN off is a right VeroScudo gives
  its user (the *Off* task, `rasdial /disconnect`, `sudo veroscudo off`), so a program running under
  your account can do the same. VeroScudo is not anti-malware.
- **Administrators / root** can remove any filter.
- **Traffic inside the tunnel** - that is the VPN's job.
- **Bridged virtual machines** (Hyper-V external switch, VirtualBox/VMware/libvirt bridged mode) - their
  frames bypass the host's IP stack. NAT-mode VMs, WSL and Docker are covered (with a ~1–2 s window after a drop).
- **Third-party VPN apps** with their own tunnel drivers (OpenVPN GUI, WireGuard app, Hiddify, vendor
  clients) - VeroScudo cannot tell their "you hung up" from a failure.
- **DNS while blocked** is the one documented side channel: the OS resolver may query the
  network's DNS servers (needed to find the VPN server).
- **macOS (alpha)**: the boot window before launchd starts the daemon; no VM filtering.

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
- CI pins every action to a commit SHA and runs with a read-only token.
