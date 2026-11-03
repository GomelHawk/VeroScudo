# Changelog

All notable changes to VeroScudo are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

Reserve VPN types, Reconnect, and a pause on rejected passwords.

### Windows
- **Profile types** (beta): besides Windows' built-in client (`ras`, still the stable default), a profile can be
  **OpenVPN** - VeroScudo imports your `.ovpn` (checked, key files inlined, administrators-only), runs `openvpn.exe`
  itself and controls it over the management interface, so "you turned it off" is only ever VeroScudo's own stop - or
  **WireGuard** - a tunnel of the WireGuard app, judged by its handshakes; deactivating it in the app counts as your Off.
  The kill-switch allows each type's own server endpoints only (OpenVPN: only from `openvpn.exe`). Install with
  `Install.ps1 -Type openvpn -OpenVpnConfig <file>` / `-Type wireguard -WireGuardConfig <file>`, or tray > Settings.
- **Reconnect** (tray menu, status window, `-Action reconnect`): blocks traffic, hangs up, redials; traffic flows again
  once the new tunnel is up. VeroScudo's own hang-up is not read as your Off.
- **Keep awake on the tray icon**: while Keep awake is on, the tray shield carries a small green ring in its
  bottom-right corner (tray only; windows and shortcuts keep the plain icon).
- **Start menu entry** *VeroScudo*: starts the tray again after *Exit tray*; removed by `Uninstall.ps1`.
- **Notice on every switch** to an OpenVPN or WireGuard profile (once per switch), and the type shown in the tray.
- **Checks when a profile is added**: OpenVPN configs that would run programs are refused; missing `redirect-gateway`,
  DNS, a plain password file or a one-time code are reported; WireGuard without `PersistentKeepalive`, a split tunnel or
  missing DNS too.
- **Conflict detection**: another `openvpn.exe`, the same `.ovpn` in OpenVPN GUI or the OpenVPN service, other WireGuard
  tunnels, other tunnel adapters and other VPN apps' kill-switch filter layers -> tray *Attention*.
- **Rejected password**: the redial pauses (still blocked) until a newer password is stored or you press On/Reconnect.
- OpenVPN: private-key passphrase and one-time codes (static challenge) from the tray; `Set-VpnCredential.ps1 -KeyPassphrase`.
- **Import from Windows** (tray Settings): every Windows VPN profile - also those for all users - with its detected type
  (Automatic, IKEv2, SSTP, L2TP/IPsec certificate or pre-shared key, PPTP), server, port and sign-in; the one you choose
  (one per import) is added with those settings. Certificate sign-in needs no username or password. `Install.ps1 -ProfileName` alone
  imports from Windows too. The profile editor fills in the server and shows the detected protocol.
- **Another VPN connected at Turn on**: the tray asks - *Disconnect it and turn on* or *Cancel* (*Turn on anyway* for a
  VPN app's own tunnel). The *On* shortcut and `-Action on` refuse with a tray message instead of silently blocking the
  other VPN; `-DisconnectOthers` / `-Force` on the command line. A VPN that is not a profile connecting while VeroScudo is
  on gets a notification; the status window lists *Other VPNs*. Nothing is disconnected or imported automatically.
- **Helper blocked by Windows** (Smart App Control / App Control refusing `VeroScudo.Native.dll`): the watchdog no longer
  fails every 15 s for hours in one stuck process - it logs the block and exits, and a fresh one retries after 1, then 5,
  then every 10 minutes. The tray shows *Attention* with the next retry time; status shows *Helper: BLOCKED*. The
  kill-switch filters stay in place meanwhile.
- New local test `tests-local/Test-Types.ps1`.

### Linux / macOS
- `veroscudo import`: NetworkManager's (macOS: System Settings') VPN connections - OpenVPN, WireGuard, L2TP, IKEv2/IPsec,
  PPTP, SSTP, OpenConnect - added with the right server ports per type (new `vpnType` key; L2TP/IKEv2 also allow ESP,
  PPTP GRE).
- `veroscudo reconnect` is now the user's Reconnect (block, take down, redial); the tray has *Reconnect VPN*.
- WireGuard connections are judged by their handshakes (a silent link is restarted); `veroscudo check` compares each
  profile's protocol/port with NetworkManager; the profile type is shown in status, `profiles` and the tray; a notice
  on every switch to a WireGuard profile; `veroscudo status` reports other tunnels next to VeroScudo.

### Fixed (review of the import / other-VPN changes)
- Windows: the elevated guard took Program Files / ProgramData / System32 from environment variables a non-admin process
  can plant; they now come from the OS and HKLM.
- Windows: Teredo, IP-HTTPS, 6to4 and ISATAP no longer count as "another VPN" (On refused every time).
- Windows: On while already on no longer says "not turned on"; a VPN app's tunnel is no longer logged as disconnected;
  the prompt offers "Disconnect what it can" next to "Turn on anyway".
- Windows: a short task that could not load the helper no longer leaves a false *Helper blocked* until reboot, nor delays
  the watchdog's retry.
- Linux: `veroscudo import` undoes nmcli's escaping (`host\:4443`, URLs, IPv6); policy-based IPsec (strongSwan,
  libreswan) is refused - it has no tunnel interface, so it could only stay blocked.

### Security (review 2026-11-02)
- Windows: TCP 80 from `svchost.exe` is no longer open to anywhere while blocked (BITS / Delivery Optimization could send
  through it); it opens for 2 minutes only after an SSTP dial failed on the certificate revocation check.
- Windows: a "you hung up" (631) counts only for the connection id VeroScudo saw connect in the System log, and the
  Terminated task waits 3 s so a forged record meets the real one; a 631 raced in with a fresh id no longer disarms.
- Windows: no DNS permit at all when no resolver is known (was: svchost to any address); DHCP only from svchost.
- Windows: `powershell.exe`, `schtasks.exe`, `rasdial.exe` and `wscript.exe` always by full System32 path (a bare name is
  resolved through the user's App Paths key); the installer and uninstaller take Program Files / ProgramData from the OS.
- Windows: the OpenVPN log moved to the administrators-only folder; the OpenVPN folder check no longer recurses or
  follows junctions; a filter layer with VeroScudo's top priority is reported; missing Hyper-V firewall is logged.
- Linux: an `input` chain (the host was reachable while blocked); established traffic only for flows VeroScudo allowed
  (conntrack mark), so a tunnel flow cannot continue over the NIC; no DNS-to-anywhere fallback (NetworkManager's resolvers
  are used); a stale Off marker can no longer turn a later drop into a disarm; systemd hardening for the daemon; the tray's
  update file now persists. macOS: pf states bound to their interface; no DNS-to-anywhere fallback.

## [1.2.1] - 2026-10-26

### Windows
- Fixed: the ticked *Keep awake* item showed the stock light-blue check box in the tray menu. A ticked item now
  just shows its icon in the accent colour.

## [1.2.0] - 2026-10-26

Keep awake on every platform; a roomier Windows tray menu.

### Windows
- **Keep awake** in the tray menu: stops the PC from sleeping (also behind a locked screen) while ticked; the
  screen may still turn off. One power request, visible in `powercfg /requests`, released on *Exit tray* or
  if the tray dies. The choice is remembered per user. Menu spacing now follows display scaling and the
  header shows the logo.

### Linux / macOS
- **Keep awake**: a tray toggle on Linux (remembered in `~/.config/veroscudo/tray.json`) and
  `veroscudo awake` on Linux and macOS (holds until Ctrl-C, no root). Linux uses `gnome-session-inhibit` or
  `systemd-inhibit`, macOS `caffeinate -i -s` (never `-d`); the child dies with the process, so a crash cannot
  leave the machine unable to sleep.

## [1.1.0] - 2026-10-26

Security hardening (an audit found real leak paths in 1.0), several VPN profiles, macOS alpha.

### Windows
- **Kill-switch engine moved to WFP.** 1.0 set the Windows Firewall default outbound to Block, but
  every enabled outbound *allow* rule (Store apps, Core Networking, installer and GPO rules - 170 on the
  test PC) still let traffic out. Now: own WFP provider + sublayer, persistent filters at ALE connect and
  recv-accept (IPv4 + IPv6), one transaction per change, catch-all block. Upgrade migrates the 1.0 rules
  (new filters first). Fail closed: if WFP cannot be used, the firewall default-block is used instead.
- **No DNS leak while protected**: DNS is allowed outside the tunnel only while redialing, only from the
  DNS Client service and only to the network's resolvers. Certificate-revocation fetches likewise.
- VPN server allowed only on the profile's tunnel-type ports, TCP/UDP only from `svchost.exe`; the tunnel
  only by its own interface (not "any dial-up connection").
- **Fixed: after a reboot WSL networking broke until a manual Off/On** - the WSL adapter gets a new id at
  every boot and the 1.0 rule stayed bound to the old one. The watchdog now re-binds tunnel and WSL
  interfaces every 15 s (was: every 5 min, never re-bound); it runs as one long-lived loop restarted within
  a minute if it stops.
- Forged/stale "user disconnected" events are ignored (tunnel still up, conflicting codes for one
  connection, other profile). The connected event is read from the System log.
- Password handed to the `RasDial` API - never on a command line (process lists, EDR, event 4688).
- `%ProgramData%\VeroScudo` locked to Administrators/SYSTEM (users read only); no environment-variable
  override of the state location; tray runs without admin rights; Settings saves through a re-validating
  elevated process without a temp file; config fully validated (`lanAllow` no wider than /8, no `Any`).
- Update notice opens only this project's release pages.
- Several VPN profiles: tray *VPN profile ▸* menu, Settings profile list, per-profile passwords,
  `Install.ps1 -ProfileName` adds a profile, elevated `switch` action. Switching stays blocked between tunnels.
- WFP self-test in `Install.ps1` before anything is changed; `Uninstall.ps1` removes provider and sublayer.
- Found and fixed in the real-machine run before release: VPN drop during the 1.0 migration (firewall steps in the
  wrong order); filters waiting for a DNS lookup they blocked (up to 35 s without network around a drop); crash with no
  DNS server known; one extra watchdog per minute; a disarm racing a re-arm (armed without filters for up to 15 s);
  WSL left offline while VeroScudo was off. Unit tests guard against a test ever touching paths outside its temp folder.
- Tests: 90 Pester tests; `Test-Offline`/`Test-Reconnect` drive the real tasks; `Test-Live.ps1` now probes from a program with its own allow rule, TCP 53, IPv6,
  DNS leak while protected, forged 631, firewall reset, filter self-heal, profile switch.

### Linux (beta)
- The tunnel is allowed only by its virtual interface - 1.0 could fall back to the physical card
  (`GENERAL.DEVICES`) and open the kill-switch completely.
- DNS only while the tunnel is down, only from `systemd-resolved` (else only to the resolvers); IPv6 server
  addresses; validated config; ruleset re-checked every 15 s and re-applied after a `nft flush ruleset`.
- Forged/stale down events ignored; atomic reconnect lock; several profiles (`veroscudo profiles`,
  `veroscudo use <name>`, tray submenu); installer writes the user's files as the user and validates sudoers.

### macOS (alpha, new)
- pf anchor kill-switch + `scutil --nc` control on the shared Python guard, launchd daemon, CLI.
  Unit-tested only.

### Project
- `docs/SECURITY.md` (threat model, reporting, hardening checklist). CI: actions pinned to SHAs, read-only
  token. Releases: build provenance attestation, optional Authenticode signing, macOS archive.

## [1.0.0] - 2026-10-24

First public release.

### Windows
- Strict kill-switch: Windows Defender Firewall default-outbound Block with a scoped allow-list
  (tunnel, VPN server, DHCP, DNS, certificate revocation for the VPN service, host-WSL switch).
  Stays strict across reboots; uninstall restores the firewall exactly as it was before.
- WSL / Docker Desktop traffic blocked while the tunnel is down, allowed through the tunnel while up
  (Hyper-V firewall rule).
- Auto-reconnect every 10 s, forever, with a DPAPI-stored credential (`rasdial` ignores the
  password saved by the Settings app). A stale reconnect lock (crash, reboot, reused PID) is detected.
- Manual-vs-failure detection from the RAS reason code (631 = user disconnected).
- Scheduled tasks for the connect/terminate events, a 5-minute watchdog, On/Off tasks and
  Desktop shortcuts; windowless launcher; every task failure is logged.
- Tray app: Protected / Blocked / Off / Attention icons (plain or shield-badge by taskbar theme),
  Windows-11-style menu, Status window (state, VPN/firewall/last-drop cards, recent events, Copy report),
  Settings window, About box, notifications on state changes. DPI-aware, dark/light theme following
  Windows, one instance per sign-in.
- Update notice: one check of the latest GitHub release after sign-in, only while traffic is allowed
  (`updateCheck: false` turns it off). Installing stays manual.
- Wi-Fi recovery fix (`WcmSvc EnableBadStateTracking=0`) - prevents Windows from resetting the
  Wi-Fi adapter ~15 s after a tunnel is dialed under the kill-switch.
- Installer / uninstaller: idempotent, upgrade-safe (stops the running tray, replaces files and icons
  in place, keeps config). Log capped at 2 MB + one old copy.
- Tests: Pester unit tests, PSScriptAnalyzer, real-machine scripts (`tests-local`: offline, reconnect,
  live end-to-end, upgrade).

### Linux (beta)
- NetworkManager backend (libnm events with deactivation reason, polling fallback), nftables
  ruleset with output + forward default-drop, CLI, AppIndicator tray (one per session), installer.
- systemd service plus a boot unit that re-applies the kill-switch before the network starts, so the
  guard stays strict across reboots and service restarts. Log capped at 2 MB + one old copy.
- Unit tests (pytest). Not yet verified on a real machine.

### Docs
- `docs/ARCHITECTURE.md` (the contract), `docs/TESTING.md` (procedure + live-run record),
  `CONTRIBUTING.md` (development and release checklist), README.
