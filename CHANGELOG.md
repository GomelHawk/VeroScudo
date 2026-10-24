# Changelog

All notable changes to VeroScudo are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

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
