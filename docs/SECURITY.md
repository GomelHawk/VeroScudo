# VeroScudo security

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private reporting:
*Security* tab → *Report a vulnerability* on [GomelHawk/VeroScudo](https://github.com/GomelHawk/VeroScudo/security/advisories/new).
Include the platform, version (`veroscudo status` / the status window's *Copy* link) and steps to reproduce.
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
| Apps that have their own firewall allow rules (Store apps, installers, GPO), QUIC, ICMP, IPv6 | Windows: WFP filters in an own top-priority sublayer - firewall rules cannot override its block (see *Out of scope* for another layer of the same priority); Linux: a `policy drop` table; all protocols, both IP versions, inbound and outbound |
| DNS leaking to the local network while protected | no DNS permit outside the tunnel while it is up |
| DNS / port 53 used as a side door while blocked | Windows: only the DNS Client service, only to the network's resolvers; Linux with systemd-resolved: only that service's user; otherwise only the network's resolvers; none known: no DNS permit |
| A hostile network spoofing the VPN server's address | server permit limited to the VPN's protocol/port (Windows: SSTP also to `svchost.exe`; the IKEv2/L2TP/PPTP ports to traffic sent as Local System or by an elevated administrator, so no ordinary program of the signed-in user can use them - with UAC switched off, or signed in as the built-in Administrator, every program is elevated and this limit does not apply); the server's certificate is still validated by the VPN |
| Something resets the firewall (GPO refresh, `nft flush ruleset`) | Windows filters are independent of the firewall policy; the watchdog re-checks every 15 s |
| A forged "user disconnected" event | acted on only for the active profile, only if the tunnel is really down, never when two records conflict, only for the connection id seen connecting (SSTP/L2TP/PPTP: System log; IKEv2 logs its connect only in the user-writable Application log, so for IKEv2 this last check is weaker) |
| Non-admin code redirecting the elevated guard | no environment overrides - system folders (Program Files, ProgramData, System32) come from the OS and HKLM, never from `%ProgramFiles%`-style variables a user can plant in `HKCU\Environment`; executables by full System32 path (never the user's App Paths key); `PSModulePath` pinned to the system module folders in every script that runs elevated (a module planted in `Documents\WindowsPowerShell\Modules` would otherwise auto-load as administrator); state folder and program folder (also a custom `-InstallDir`) writable by administrators only - a state folder or program folder that exists before the install and is not the administrators' is refused, and both are created with their protection; config validated; the tray's Save is bound to the approved command by its SHA-256. Three inputs of the signed-in user remain, each validated: their own VeroScudo folder (`%LOCALAPPDATA%`: the stored password and key passphrase - two values picked from the file, never deserialized; a switch request - only a configured profile name; a one-time code - one short line; the tray's Save payload - only the one whose SHA-256 was approved). The guard reads there and never deletes or writes, their OpenVPN GUI folders (read for the conflict list) and the all-users phonebook path. Linux/macOS: the `veroscudo` command, as root, takes nothing from the caller's environment - a fixed `PATH` for `nft`, `nmcli`, `pfctl`, `scutil`..., no `VEROSCUDO_*` variable - and the sudo rule sets `secure_path` itself; the lock file in `/run/veroscudo` is root's alone. macOS: the program is under root-owned `/opt`, never Homebrew's user-writable `/usr/local` |
| The config file is missing or broken when an armed Linux/macOS machine boots | the boot step and the daemon fail closed, whatever is wrong with the file: a lockdown ruleset (loopback, DHCP, neighbour discovery) until it is fixed. *Off* still works |
| The kill-switch rules cannot be worked out or applied (a kernel without a needed feature, a refused ruleset, a helper that does not load) | Windows falls back to the firewall's outbound block (profiles switched on for it) and blocks the VMs and WSL, Linux/macOS fall back to the lockdown ruleset, both logged as `EMERGENCY`; only when that fallback fails too is the machine armed without rules, and the log says `NOT PROTECTED` |
| Text from a file a user owns ending up in the firewall rules (Hiddify's config, Linux/macOS) | addresses only in canonical form, no IPv6 zone, checked again where the ruleset is written |
| A bridge that leads to the physical network taken for a VM bridge (Linux) | a bridge counts as host-only only when none of its ports is a card or sits on one (a bond, team or VLAN) |
| Two VeroScudo processes changing the firewall at once (Linux/macOS: the daemon's watchdog and a `veroscudo on`) | every "read the armed flag, then apply or clear" runs under one cross-process lock (`flock` in `/run/veroscudo`); a tidy-up that finds the machine armed meanwhile keeps the table |
| The Windows installer run by a different account than the one signed in (over-the-shoulder UAC) | refused: tasks, tray and the DPAPI credential must belong to the signed-in administrator |
| The VPN password leaking via process lists / EDR logs | `RasDial` API, never on a command line; DPAPI-encrypted per user |
| A tampered update link | only this project's GitHub release pages are opened; nothing is installed automatically |
| An imported OpenVPN config running code as administrator | only an allow-list of client options is accepted, lines and tags read the way OpenVPN reads them - its own white space only, tags letter for letter (no scripts, plugins, PKCS#11/OpenSSL modules, management, includes, logs, proxies; no quoted or escaped option names; `setenv` only for a few fixed names, so `setenv opt` cannot carry another option in; no line long enough for OpenVPN to cut); key files inlined only when they hold no tag lines; checked again by the elevated import, the stored text once more as a whole and again at every start; administrators-only; `--script-security 1` on the command line |
| A local program taking over VeroScudo's OpenVPN | management on 127.0.0.1, a random port, a one-time password in a file created administrators-only (deleted after login), VeroScudo connects first while OpenVPN waits in hold, and sends nothing unless the port is held by the OpenVPN it started |
| Retrying a rejected password until the VPN account is locked | the redial pauses (still blocked) until a newer password is stored |
| A dead WireGuard link that keeps its adapter up | judged by handshake age and restarted; meanwhile traffic goes into the dead tunnel and is lost, never out of the physical NIC |

### Out of scope - what it does **not** protect against

- **Anything running as you that wants the VPN off.** Turning the VPN off is a right VeroScudo gives
  its user (the *Off* task, `rasdial /disconnect`, `sudo veroscudo off`), so a program running under
  your account can do the same. VeroScudo is not anti-malware.
- **Administrators / root** can remove any filter.
- **Another local account stopping the guard (Windows).** The state folder is readable by every user (the tray shows
  state and log from it), and a file held open by somebody cannot be replaced: the guard then cannot turn on, switch or
  turn off until that program ends. It never opens anything - what is blocked stays blocked, the VMs and WSL included -
  and the lock files are administrators-only. A PC shared with accounts you do not trust is outside what the tray's
  design covers.
- **Traffic inside the tunnel** - that is the VPN's job.
- **Hyper-V Default Switch VMs - covered, with a short window when only the VPN dies.** Windows translates their
  traffic inside the Hyper-V switch, below WFP (WFP's forwarding layers never see it), so VeroScudo stops it there with
  Hyper-V port ACLs while the tunnel is down, and blocks them as soon as Windows logs "network disconnected" until the
  tunnel is proven again (docs/ARCHITECTURE.md, *VMs and containers*). Measured: before the fix a Default
  Switch VM left through the ISP for 2-7 s per Reconnect or Wi-Fi drop; after it, two Reconnects and a 30 s Wi-Fi outage
  showed only the VPN's exit address (VMs blocked 1 s after the Wi-Fi went away). Remaining: a VPN that dies while the
  network itself stays up is caught when the route to the internet leaves the tunnel (the watchdog looks every second).
- **WSL in its default (NAT) network mode.** WSL is blocked within about a second of the route leaving the tunnel (a
  ready Hyper-V block rule, switched on first). That firewall judges only new connections, and Windows moves the
  translated ones WSL had already opened to the new route (ksbench measured up to 25 s of them before). So while the
  tunnel is down the internet is also routed to nowhere - routes on the loopback adapter, more specific than the
  default route, for everything but the VPN server and the networks the adapters are on: an open connection then has
  no way out (tested: a kept-alive connection from WSL stalled until the routes were gone). They come the moment the
  watchdog sees the route leave the tunnel, also while Windows' VPN client still says "connected" (at most 30 s that
  way); should the tunnel prove alive after all, they go again - Windows programs wait for that proof too. Not used for Hiddify
  (VeroScudo does not dial it) or during the SSTP revocation window; a route Windows refuses is logged, and WSL is then
  covered by the Hyper-V firewall alone. Not tested: Windows Sandbox and Docker in
  Hyper-V mode. Without the Hyper-V PowerShell tools VeroScudo logs that these VMs are not covered.
- **Bridged virtual machines** (Hyper-V external switch, VirtualBox/VMware/Parallels/libvirt bridged mode) and **Docker
  macvlan/ipvlan networks** - their frames bypass the host's IP stack, so no host firewall can see them. VeroScudo does
  not detect or report them (Settings > Behaviour says so under *Protect VMs and containers*); to protect such a VM,
  switch it to NAT mode or run a VPN with a kill-switch inside it. NAT-mode VMs, WSL and bridge-mode Docker/libvirt
  are covered (with a ~1–2 s window after a drop).
- **Hiddify (VPN mode)** - supported as a kill-switch-only profile. Windows: `Hiddify.exe`/`HiddifyCli.exe` may reach
  any address (by program, from an administrators-only folder), so whatever the app itself sends outside its tunnel
  (its update check, error reports, whatever its own routing rules send direct) is not covered. Linux with Hiddify 5:
  the same, by its root service's cgroup (`HiddifyAdminBG`), to any address. Otherwise, and on macOS: only the servers in
  its live config (see ARCHITECTURE).
  Any drop - also your own disconnect in Hiddify - keeps everything blocked until its tunnel is back or VeroScudo is off.
  Measured with `windows/tests-local/Test-Hiddify.ps1`: disconnect in Hiddify, quit
  Hiddify -> only BLOCKED; reconnect, restart and server changes while VeroScudo stayed on -> through Hiddify at once;
  0 of 61 samples showed the real address.
- **Vendor VPN apps** with their own tunnel drivers and kill-switches (PrivateVPN's app, NordVPN ...) -
  VeroScudo cannot tell their "you hung up" from a failure. It detects their tunnels and filter layers and shows
  *Attention*. OpenVPN (run by VeroScudo itself) and the WireGuard app's tunnels are supported profile types (beta).
- **WireGuard: the first 1-3 minutes of a silent drop** - traffic goes into the dead tunnel and is lost (not leaked)
  until the handshake age shows the drop; then the redial starts.
- **DNS while blocked** is the one documented side channel: the redial looks up the VPN server's name. Linux lets out
  only a query for exactly that name (nftables matches the name in the packet). Windows and macOS cannot filter by name:
  while the tunnel is down the server's name is answered on the computer itself - a responder on a loopback address that
  knows only that name (the addresses VeroScudo cached through the tunnel), reached through one NRPT rule (Windows) or a
  resolver file (macOS) for exactly that name, present only while the tunnel is down. No DNS packet leaves for it.
  Fallback when the rule is refused or there is no cached address yet: the system resolver may query the network's DNS
  servers for that lookup (3 s at most) - another app's lookup in those seconds can get out too. Not used: a hosts-file
  entry (security software commonly blocks it) or a signed driver.
- **macOS (alpha)**: the boot window before launchd starts the daemon; VM filtering (pf, vmnet bridges) written but not yet seen on a real Mac.
  A DNS connection opened while blocked can go on after the tunnel is up for as long as pf keeps its state (Linux ends
  such connections; the pf of macOS has no way to pick them out).
  Another program that loads a pf ruleset of its own (some VPN clients do) cuts VeroScudo's anchor off: that is detected
  (*not active*, logged as `EMERGENCY`, the tray shows it) but not repaired - VeroScudo never rewrites the main ruleset.
- **The environment of an elevation you approve (Windows).** The guard's own tasks start through a launcher that removes
  the variables the .NET runtime and OpenSSL act on before any script line runs (a profiler or a library to load), and
  `openvpn.exe` is started with the system's environment only. The administrator
  prompt of the tray's *Save* and of `Install.ps1` is Windows' own: what it starts gets the signed-in user's environment,
  which a program running as that user can add to beforehand. Use a separate administrator account for the prompt if
  programs you do not trust run under your own.
- **Another filter layer of VeroScudo's own top priority (Windows).** WFP evaluates sublayers of equal weight in no
  defined order; a *hard permit* there (another program's, installed with administrator rights) can win before
  VeroScudo's block is seen - only a kernel callout could veto it. VeroScudo detects such layers and shows *Attention*.
- **VMs/WSL and the local network (Windows).** Their traffic is translated below WFP and follows Windows' routing table:
  while the tunnel is up, the local network is reached directly. With a split-tunnel profile (the route to the internet
  does not lead into the tunnel) VeroScudo keeps VMs and WSL blocked even while it is up, and logs why; if the route
  cannot be looked up it lets them through as before.
- **IKEv2: disconnecting in Windows Settings can be undone (Windows).** Windows logs an IKEv2 hang-up about 20 s late;
  VeroScudo sees the tunnel go down first, takes it for a failure and dials again. Turn the VPN off in VeroScudo's tray
  instead. Not a leak: traffic stays blocked or goes through the tunnel throughout.
- **Mobile Hotspot, Internet Connection Sharing and custom NAT (Windows).** What Windows forwards for other devices is
  not filtered.
- **Another local account turning it off (Linux).** NetworkManager lets local users disconnect a VPN by default
  (polkit); VeroScudo reads that as your hang-up and turns off.
- **What is let out is let out for every local program.** The VPN server's ports, Hiddify's servers and direct DNS
  servers, and while blocked the DNS and DHCP permits are not tied to the VPN client (Linux: DNS only for
  `systemd-resolved`, DHCP needs root to bind port 68; macOS: any process).
- **Linux: checked every 15 s.** A bridge that gets a network card added counts as host-only until the next check, and
  a `nft flush ruleset` (reloading `nftables.service`, for one) removes VeroScudo's table until then.
- **Windows: before the filtering service starts.** The filters are persistent, not boot-time: they act from the moment
  Windows' Base Filtering Engine starts during boot, not in the instants before it.

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
