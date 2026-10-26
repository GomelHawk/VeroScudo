# Changelog

All notable changes to VeroScudo are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

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
