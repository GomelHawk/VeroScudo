# Changelog

All notable changes to VeroScudo are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

### Security (review 2026-11-05 of 1.3.0, read-only; the install surface this time)
- Windows: **`PSModulePath` pinned to the system module folders** in every script that runs elevated (`VeroScudo.ps1`,
  `Install.ps1`, `Uninstall.ps1`, `Set-VpnCredential.ps1`, the tray's elevated save). The guard tasks run elevated as
  the signed-in user, and PowerShell auto-loads modules such as VpnClient from the user's writable
  `Documents\WindowsPowerShell\Modules` first: a module planted there by any program running as that user ran as
  administrator the moment `schtasks /run \VeroScudo\Off` fired. `-NoProfile` never covered this.
- Windows: a custom `-InstallDir` gets the same administrators-only ACL as the state folder, and the installer refuses a
  folder with a weak ancestor - one that lets a non-administrator rename or replace folders (a data drive's root, the
  user profile): the folder itself could be renamed away and a planted one put in its place, and the elevated tasks
  run the scripts from there. Program Files gave all of that by default.
- macOS: the daemon's venv is built from Apple's `/usr/bin/python3` only (Homebrew's is user-owned on Intel Macs), and
  the installer refuses to continue when `/opt` or the program folder is not root's and closed to others.
- macOS: the program moved from `/usr/local/lib/veroscudo` to **`/opt/veroscudo`**. On Intel Macs Homebrew makes
  `/usr/local/lib` and `/usr/local/bin` writable by the user, so the folder the root daemon and the passwordless sudo
  rule ran from could be swapped by a user-level process; the installer also chowned `/usr/local/bin` to root, which
  broke Homebrew. The sudo rule names root-owned paths only; `/usr/local/bin` is never created or chowned.
- Linux, macOS: **boot fails closed without a usable `config.json`**. The CLI read the config before the boot step, so a
  missing or broken file aborted `veroscudo boot` (and the daemon) before any filter was applied: an armed machine
  started open. Now a lockdown ruleset (loopback, DHCP, neighbour discovery only) is applied and stays until the file
  is fixed.
- macOS: `pfctl -d` was not noticed - the anchor's rules stayed listed, status said *active*, nothing was enforced until
  reboot. `is_active` now requires pf to be enabled, and the watchdog enables it again within 15 s.

### Fixed
- Linux: **Docker and libvirt networking broke while armed, even with the tunnel up** (B5 of the review). The forward
  chain let containers out through the tunnel, but policy drop in all three chains cut everything that stays on the
  machine: host <-> container (a published port on localhost), container <-> container on one Docker bridge
  (br_netfilter sends those frames through the forward hook), a VM's DHCP and DNS from libvirt's dnsmasq. Host-only
  bridges (every port virtual: docker0, br-*, virbr0, lxdbr0, podman0) are now allowed in input, output and
  bridge-to-bridge forward in every state; their way out is still the tunnel only, and a bridge with a physical card
  enslaved is never allowed. `"vm": "auto"` also detects such bridges.
- Linux, macOS: `veroscudo status` (and the tray) crashed while the daemon's reconnect was running: the user may not
  signal root's process, that was read as "dead", and deleting the root-owned lock then threw. A process that cannot
  be signalled is alive.
- Linux: the tray icons were never installed from the release archive (the installer looked one folder up, which is
  right for a git checkout only); a missing icon folder is reported instead of silently skipped.
- macOS: the log said `tunnel=DOWN` for every change (the up/down word was derived from an nftables-only pattern);
  the daemon now logs the interface it actually allowed.

### Changed
- Windows: **one handler per profile type.** Everything that differs between the built-in client, OpenVPN and WireGuard
  (label, defaults, connected check, tunnel adapter, server permits, dial, hang-up, status and failure text, foreign
  tunnels) lives in one table at the end of the core module; the dispatching `if type -eq ...` chains at 14 call sites
  are gone (45 type comparisons -> 27, the rest are type-specific code, not dispatch). No behaviour change: the full unit
  suite passes unchanged.
- Windows: `Invoke-VeroAction` is a 25-line dispatcher; each action (arm, on, off, on-event, watchdog, switch, status) is
  its own function with the body it had. `Sync-VeroKillSwitchCore` is split into `Get-VeroSyncPlan` (what the filters
  must look like now) and the apply/log/refresh step. No behaviour change.
- Windows: the core module is split by topic into `windows/Core/NN-<topic>.ps1` (13 files, 40-540 lines each);
  `VeroScudo.Core.psm1` is the loader that dot-sources them in a fixed order and exports the public functions. One
  module, one scope: callers, tests and the installed layout see the same module name as before. The installer copies
  the parts; the release archive and the signing step include them.
- Windows: **the tray has unit tests.** What the tray decides - state, title and text from the guard's facts, the exit
  location line, "a state file changed", the per-user preferences, the update-notice rule - moved from the WinForms
  script into `VeroScudo.Tray.psm1` as functions with explicit inputs, tested in `tests/VeroScudo.Tray.Tests.ps1`
  (6 groups). `VeroScudoTray.ps1` calls them with its globals and only draws.
- CI: PSScriptAnalyzer now fails on parse errors too (the settings listed Error and Warning only, so a script that no
  test imports - installer, tray - could have shipped unparseable).
- Linux, macOS: the backend contract (the VPN-control and firewall functions the shared code may call) is declared in
  `backend.py` and checked at startup on both platforms, and a test keeps the shared code inside it; the pf backend
  reuses the nftables backend's address helpers (one copy); the tray takes its VPN backend from `backend.py` like the
  daemon; the guard is now tested with the pf backend swapped in; two Windows test
  groups named after a commit are named after what they check.
- Windows: the watchdog's single-instance mutex is named per home folder, so the unit tests (temp home) no longer meet
  the installed watchdog's mutex - one test failed on a machine with VeroScudo running, passed on a clean CI runner.

## [1.3.0] - 2026-11-04

Reserve VPN types (OpenVPN, WireGuard - beta), every Windows VPN type armed, Reconnect, import from Windows, a working
IKEv2 kill-switch, profile switching you can rely on, and the exit location in the tray.

Tested live on Windows 11 (Windows VPN: SSTP and IKEv2; OpenVPN; WireGuard). Linux (beta) and macOS (alpha) changes are
covered by unit tests only.

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

### Fixed (live tests 2026-11-03)
- **IKEv2 profiles carried no traffic while armed** (and *Automatic* profiles that chose IKEv2): Windows hands IKEv2
  tunnel data to the firewall as an IP-in-IP flow (protocol 4, 41 for IPv6 inside) to the VPN server, which the
  kill-switch dropped - the tunnel connected and nothing went through. Now allowed to the profile's server addresses only.
- Status *Server* showed `name -> , , ,`: the cached server addresses were written into `wfp.json` as objects.
- The *other VPN* warning stayed up to a minute after the other VPN stopped: re-checked every 15 s while one is reported.
- Tray, checked in every state with `-Preview` (dark and light):
  - the status header grows with its text (nothing cut off);
  - *Protected* + note when another VPN runs next to a working tunnel;
  - dark scroll bars;
  - event lines wrap after commas, not inside an address;
  - disabled buttons drawn readable and visibly disabled;
  - drop-down lists in the theme's colours, also when locked while editing;
  - VeroScudo's own message boxes instead of the white Windows ones; *No* is the default of every Yes/No question;
  - a darker warning colour on the light theme;
  - wider Settings buttons.
- **Settings > Save switched the connection**: with the WireGuard app's tunnel up, saving any edit switched to the
  default Windows VPN. Save now never touches a connection: a new default (*Set as default*) is saved and you stay on
  the tunnel you are on; it is selected right away only when VeroScudo is off and nothing is connected.
- **No "connection lost" when you start something yourself**: after Turn on (tray, shortcut), a profile switch or
  Reconnect, the blocked phase until the tunnel is up is shown as *Connecting* / *Switching* / *Reconnecting* (amber),
  with one notice "kill-switch on, traffic blocked until ... is connected". A real drop while protected keeps the red
  *connection lost*; a start still not connected after 2 minutes says so once.
- **Exit location** in the status window (under the header): country, city and the IP your traffic leaves from. Asked
  once after each connect/reconnect/switch - only while Protected, so it goes through the tunnel - from ipinfo.io, with
  Cloudflare's trace page as fallback (IP and country). Shown grey with its time while not protected; *Refresh* asks again;
  off in Settings (*Show exit location*, your own setting). Also in *Copy report*. Shown as "[PL] Poland / city"; the answer is decoded as UTF-8 (Windows PowerShell garbled non-English city names).
- **OpenVPN profiles use VeroScudo's own adapter** *VeroScudo OpenVPN* (created with OpenVPN's `tapctl.exe` by the
  installer, or by the OpenVPN runner when missing; removed by `Uninstall.ps1`). Without DCO, OpenVPN used to take any
  free TAP adapter - e.g. one another VPN app installed under its own name, which also clashes when that app runs.
  When the adapter cannot be created (no `tapctl.exe`, no TAP driver) OpenVPN keeps choosing one itself, noted once in the log.
- **A profile chosen in the tray menu was ignored while another one was being redialed**: the redial loop kept the
  Switch task busy, and Windows does not start a busy task again. The loop now checks for your choice on every attempt
  (and while waiting for OpenVPN / WireGuard) and switches to it; the watchdog picks up a request nobody took within 15 s.
- **OpenVPN start that never finishes**: twice OpenVPN sat in STARTING and never asked for the password, until Off. A start
  that makes no progress for 45 s is now restarted, and the log names the last messages from OpenVPN; the previous run's
  OpenVPN log is kept as `.prev.log` (it used to be overwritten by the next start).
- The tray listed VeroScudo's **own OpenVPN adapter** as "Other VPNs: ... (VPN app)": it is now recognised by the
  address OpenVPN reported, which works from the tray's session too.
- Status: the third card of an OpenVPN / WireGuard profile is titled with the client (*OPENVPN* / *WIREGUARD*): it shows
  the client's state, not the last drop.
- Status *Server* of an OpenVPN profile shows its `remote` servers (it showed ` -> addresses` without a name).
- Status window: **Clear** empties *Recent events* from now on. The log file is not touched: it is admin-owned and
  rotates by itself at 2 MB, and *Open log* still shows everything.
- `-Preview` now captures every status state, every dialog and message (each answers Cancel/No, nothing is saved) and
  lists the balloon texts.

### Security (review 2026-11-02)
- Windows: TCP 80 from `svchost.exe` is no longer open to anywhere while blocked (BITS / Delivery Optimization could send
  through it); it opens for 2 minutes only after an SSTP dial failed on the certificate revocation check.
- Windows: a "you hung up" (631) counts only for the connection id VeroScudo saw connect in the System log, and the
  Terminated task waits 3 s so a forged record meets the real one; a 631 raced in with a fresh id no longer disarms.
- Windows: **IKEv2 profiles never armed** - an IKEv2 connect logs no RasMan 20267, only RasClient 20225. The Connected task
  now fires on both; it arms only when that profile really is connected. And for every Windows VPN type (Automatic,
  IKEv2, SSTP, L2TP, PPTP) the watchdog arms within 15 s when a configured profile's tunnel comes up, whatever was logged. SSTP redial under the kill-switch failed with
  `0x8007271D` (the blocked revocation fetch): that code now opens the 2-minute window too, and a freshly connected SSTP
  tunnel gets the window as well. Settings: editing a profile no longer lets you turn it into another one; "Make default"
  is now "Set as default" and never switches a running connection (see below).
- Windows: **a VPN server that moved was blocked forever** (since 1.0): while down VeroScudo used only cached addresses.
  It now looks the server up before arming (no filters yet) and again after a failed redial (DNS is allowed then), and
  lets a new address through. Seen live: vpn.corp.example.com moved, the tunnel was cut 5 s after arming, every redial refused.
- Windows: the native helper is loaded from its bytes instead of as a file: Smart App Control blocked the locally
  compiled, unsigned DLL (Code Integrity 3077) and with it On/Off/redial in the affected process. A signed release DLL
  remains the proper fix. Side effect: the DLL is no longer locked, so reinstalling never hits "file in use".
- Windows: the status window's events scroll vertically and wrap long lines; a password is asked every time a profile is
  imported or added (leave it empty to keep one stored before); status shows the server name and the addresses allowed.
- Windows: switching profiles always hangs the old tunnel up and waits until it is gone before dialing the new one (the
  new dial failed for about a minute otherwise); after Off nothing re-arms for 30 s, and a redial that still connects
  after Off is hung up - Off always ends disconnected. Failed attempts log the RasDial result.
- Windows: the CRL window opens on the RasDial result only - a forged Application-log record can no longer keep it open.
- Windows: a 631 may name the recorded connection id or the newest System-log connect (two quick connects no longer
  turn a real Off into a failure); every Hyper-V firewall call is gated, so Off and Status work without it (Windows 10);
  the "no DNS server known" line is logged once per change, not every 15 s.
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
