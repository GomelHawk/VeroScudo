# Changelog

All notable changes to VeroScudo are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

### Fixed: Linux, macOS - restarting a silent WireGuard turned protection off
- When a WireGuard tunnel had no handshake for 3 minutes, the guard took it down to start it fresh - and NetworkManager
  reports that take-down as user-requested, so the guard read it as your Off and disarmed. Its own restart now carries
  the same marker as Reconnect: it stays armed and blocked until the tunnel is back.

### Fixed: Linux - a WireGuard connection could not be imported
- **"no peer endpoint in the connection"**, in the tray and with `sudo veroscudo import`, for a WireGuard connection that
  was not connected: its file was looked up with `nmcli connection show <name>`, which names the file only while the
  connection is active. The endpoint now comes from NetworkManager itself (libnm) - which also works in the tray, where
  the root-only connection file cannot be read - and otherwise from the file the connection list names.

### Fixed: Linux - SSTP, L2TP and PPTP connections stayed blocked
- **The VPN connected, but VeroScudo kept blocking everything.** For pppd-based NetworkManager plugins (SSTP, L2TP,
  PPTP) NetworkManager reports the card underneath (`eth0`) as the connection's interface, not the tunnel (`ppp0`).
  VeroScudo rightly refused the card and stayed blocked. Now, when that happens, the tunnel is the virtual interface that
  holds the connection's own IPv4 address - exactly one, never a physical card; otherwise it stays blocked as before.
- The address reader now understands point-to-point links (`inet 192.0.2.7 peer 192.0.2.1/32`).
- Linux, macOS: **after a VPN died abruptly, the redial started ~20 s late.** Every rebuild of the rules looked the server
  name up first, and the resolver still asked the dead tunnel's DNS. The rules are now built from the cached server
  addresses; the name is looked up before arming (nothing blocked yet - a name with changing addresses gets the one the
  VPN client dials), while the tunnel is up, and after a failed redial (a server that moved is still picked up) - as on
  Windows.
- Linux installer: on Ubuntu 26.04 the tray-icon extension is part of `gnome-shell-ubuntu-extensions`; the installer
  asked for `gnome-shell-extension-appindicator` on every run and told you to enable it.
- `linux/tests-local/live.sh`: the real-machine test runs by itself - On, Reconnect, the VPN dying, a network drop, your
  own hang-up, On and Off, with a leak probe every 2 s; ends with PASS or FAIL. SSTP/L2TP/PPTP, OpenVPN and WireGuard need
  nothing from you; for Hiddify it tells you when to connect or disconnect in Hiddify.

### Security: Hyper-V Default Switch VMs
- **A Default Switch VM leaked while VeroScudo was blocked.** Windows translates its traffic inside the Hyper-V switch,
  below WFP: while the tunnel was up it went through it, but during a Reconnect or an outage the VM went out through the
  ISP. A block on WFP's forwarding layers was tried and did not catch it. Now, while armed and the tunnel is
  down, every VM on the Default Switch gets Hyper-V port ACLs (deny outbound except Windows itself); removed when the
  tunnel is back - exactly the rules VeroScudo added (also the broadcast rule, which Hyper-V stores without its /32).
  Because RAS reports a dead VPN only seconds after the network is back, a new `\VeroScudo\NetDown` task reacts to
  Windows' "network disconnected" event at once: the VMs are blocked right then and stay blocked until the tunnel is
  proven to carry traffic again (a redial, or a check through the tunnel).
- **Default Switch VMs had no network while VeroScudo was on** (no DHCP, no DNS: both come from Windows itself, and the
  kill-switch blocked them). The Default Switch's adapter is now allowed while the tunnel is up.
- **WireGuard profiles:** the WireGuard app's own kill-switch (*Block untunneled traffic*) also blocks Windows' DHCP and
  DNS for Hyper-V VMs - turn it off in the WireGuard app if you use VMs; VeroScudo's kill-switch covers the traffic.

### One meaning for the VM setting (Windows, Linux, macOS)
- **`vm` is now one on/off setting everywhere** - Settings > Behaviour, *Protect VMs and containers with the kill-switch*.
  On (default): their traffic follows the kill-switch. Off: VeroScudo leaves them alone. Before, `false` meant "left
  alone" on Windows but "no network while on" on Linux, and Linux had a third value; `"auto"` is now read as on. Linux:
  the drop-down became the check box, and `false` no longer cuts containers and VMs off - turn a VM's network off inside
  the VM for that.
- **macOS: the VM setting now works too** (alpha - not yet seen on a real Mac). pf passes the host side of NAT and
  host-only VMs (vmnet `bridgeN`: Parallels, VMware Fusion, UTM; older `vmnetN`/`vnicN`) both ways, and a VM's way out
  meets the same rules as the Mac's own traffic - the tunnel while it is up, nothing while it is down. Off: VM traffic is
  tagged and passed. A bridge with a physical port (bridged-mode VM, Thunderbolt Bridge) is never opened. The check box
  is now in the macOS Settings too, and `veroscudo setup` writes `"vm": true` on macOS as well.
- **Bridged VMs are named as not covered** in the description under the check box on every platform (their frames
  bypass the host firewall; switch them to NAT). Behaviour on macOS got the same labels and descriptions as Windows and Linux.

### Linux and macOS trays catch up with Windows
- **Show exit location** (Linux; macOS next): the status window shows where your traffic leaves the tunnel - country
  code, country / city and IP - looked up only right after VeroScudo reaches Protected and on *Refresh* (ipinfo.io,
  Cloudflare's trace page as the fallback; 6 s per request, given up after 20 s), so the request always goes through the
  tunnel. Grey with its time while not protected or for another profile; in the Copy report as *Exit*. Settings >
  Behaviour > *Show exit location* (on by default) is your own setting: saved at once, no password.
- **Other VPNs**: a notice once per detection when another VPN connects while VeroScudo is on (not a VeroScudo profile /
  another profile / a VPN app's own tunnel - each with what to do), and an *Other VPNs: ...* line in the status window.
  **Turn VPN on asks first** when another VPN is connected: disconnect it and turn on (NetworkManager connections,
  as you), turn on anyway (its traffic stays blocked) or cancel - the Windows question and buttons.
- **Status window like the Windows one**: the title and the *Connection* line in the rating's colour (details as a
  tooltip), *kill-switch ON* red while blocked, a **Last drop** line (the guard now records each drop and why:
  connection lost, you disconnected, Reconnect, turned off, silent WireGuard), *Recent events* without dates and with a
  **Clear** link (the log itself stays), and **Open log** next to Reconnect and Copy report (*Copied* after a click).
- **Keep-awake badge** on the tray icon while Keep awake is on (the green ring of the Windows icon, drawn from the icon
  itself); the tooltip says *keeping PC awake* like on Windows.
- **No more "default profile"** (Windows, Linux, macOS): *Make default* / *Set as default* and the *(default)* tag are
  gone from Settings, and `veroscudo default` from the CLI. The profile you select in the tray menu is what is used - the
  guard keeps it across reboots - so a default only ever mattered on the first start or after removing the selected
  profile, and it looked like a switch that it was not. `activeProfile` in config.json stays as that fallback (no
  visible setting; existing configs keep working); removing the profile in use falls back to the first remaining one.
- **Remove asks first** (Linux): *Remove 'X' from VeroScudo?* with the Windows wording.
- Turned on outside the tray (`sudo veroscudo on`) now reads as *Connecting*, not *connection lost* - as on Windows.
- **macOS menu-bar app (alpha) has all of the above too**: a live Status window (Option-click on the icon opens it),
  exit location, other VPNs found by their VPN service (`scutil --nc`; *Disconnect ... and turn on* stops it), the
  keep-awake badge and Remove as on Windows, and the Statistics window - with the Linux tray's texts.
- **Another tunnel next to a protected one** shows the amber icon with the title *Protected* and a note (Linux, macOS) -
  as on Windows, which already did.
- **Password missing / rejected** (Linux; macOS once a real Mac shows what scutil reports): when NetworkManager says the
  VPN failed for its password (no secrets, or the login was refused), the guard stops redialing so the server does not
  lock the account - traffic stays blocked - and the tray shows *Password missing* / *Password rejected* with the
  Windows wording. Turn on, Reconnect or a profile switch (after you stored the right password) resumes; so does any
  successful connect.
- **Windows gets "Guard not running"** (Linux had it): the watchdog writes a heartbeat on every pass; while VeroScudo is on
  and it is older than 3 minutes, the tray says the guard has stopped and how to fix it.

### Checks for the services you depend on (Windows, Linux, macOS)
- **HTTPS check method** (Settings > Connection, next to Ping and TCP port): TLS handshake plus one `HEAD /` without
  credentials, any HTTP answer counts - e.g. `api.anthropic.com`; no account or key is used. The CONNECTION tooltip lists
  each address's losses, so you see whether one service or the whole connection fails.
- **Hiddify profiles are checked with TLS:** Hiddify answers pings and TCP handshakes itself (also when its servers are
  dead), so those checks proved nothing; a TLS handshake needs a real server.
- **Service status page** (opt-in, per user): a card under the exit location, in its style - a neutral badge OK / ! / !!
  / ?, the service's name, its state and the time of the check, Refresh - from an Atlassian Statuspage (Anthropic's by
  default), checked like the exit location: after each connect and on Refresh. It tells a service's outage from your
  connection.
- **Hiddify, blocked:** the window says *Blocked - waiting for Hiddify* and CONNECTION *waiting for Hiddify* (not
  "reconnecting"/"redialing" - VeroScudo never dials Hiddify); the log says *Hiddify connected again* when it is back.
- **Statistics: "VeroScudo on, but no connection" is bad,** not grey - a bar with 2+ such minutes reads "could not
  connect", and the day says how long ("· no connection 42 min").
- **Exit location Refresh always answers:** it works whenever a tunnel is up (also with VeroScudo off, and in "Protected +
  note"), shows *checking...*, and a failed or refused refresh is shown next to the old values instead of nothing.
  With Hiddify the tooltip notes that the exit IP can differ per connection.
- **Windows: WSL never loses its network for a moment** when VeroScudo turns on with the tunnel already up, or turns off
  (the allow rule now comes before the default Block, and goes after the default is restored).
- **Hiddify fixes from the first live test:** with Hiddify connected and VeroScudo off, the button says *Turn VPN on*
  (it said *Turn VPN off*, and Off did nothing); Off no longer logs "disconnected 'Hiddify'"; connecting Hiddify turns
  VeroScudo on for it, like any VPN you connect yourself.

### Hiddify in VPN mode (Windows, Linux, macOS)
- **New profile type "Hiddify" - kill-switch only.** Connect, disconnect and reconnect in Hiddify (VPN/TUN mode);
  VeroScudo keeps everything else blocked while its tunnel is down, records its statistics and runs the connection
  check through it. Reconnect in VeroScudo is greyed out ("reconnect in Hiddify"); Off only disarms. Windows: the
  `Hiddify.exe`/`HiddifyCli.exe` programs from the administrators-only install folder may reach any address (its servers
  are many and change with each subscription). Linux/macOS: the servers and direct DNS of Hiddify's live config. Import:
  Settings > Import (proxy mode is refused with a note).
- **Fix: a running Hiddify was not detected at all on Windows** - its adapter is described `sing-tun Tunnel`, which matched
  none of the known tunnel names. It now shows as *Hiddify (VPN mode)*.

### Statistics (Windows, Linux, macOS)
- **Tray menu > Statistics:** the last 7 days of one VPN profile at a time (drop-down, the active profile first - a
  corporate and a home VPN are different connections, their problems are never mixed): one row per day on a 24-hour time
  grid, one bar per 10 minutes (green good, amber unstable, brown bad, grey not connected; hover for the numbers), with
  each day's connected time and the share of it that was good. Only VeroScudo's own VPN counts. With the connection
  check off, connected time shows green. Recorded by the guard per minute and profile in `stats/<date>.jsonl` (kept
  8 days).
- **Profiles get a lasting `id`** in config.json: a renamed profile keeps its statistics (shown by its new name), a
  removed one stays visible for its 7 days with its last name, marked *(removed)*. Configs from before get the id their
  names give, so nothing is lost.

### Connection check (Windows, Linux, macOS)
- **Optional connection quality check** (Settings > *Connection*, off by default): while protected, the guard checks up to
  three addresses through the tunnel every 10-100 s (ping, or TCP to a port; 1.1.1.1 TCP 443 by default - an emptied
  first address becomes 1.1.1.1 again) and rates the last 1-10 minutes: under 10 % of the checks lost *good*, 10-50 %
  *unstable*, over 50 % *bad*. The first rating comes only after one full period - after every connect, profile switch
  and change of the check settings (*checking…* until then), also after a Reconnect shorter than one round (every time
  the kill-switch blocks, the rating starts over). Shown in the tooltip (*VeroScudo - Protected, connection good*), the menu header
  (*VeroScudo - Protected - Unstable*), the status window (the *Redial* card is now **CONNECTION**: the quality while
  protected, the redial while not; Linux/macOS: a *Connection* row) and `status`. Only reports: it never reconnects or
  switches profiles. Nothing in the kill-switch is opened for it. New key `connectionCheck` (docs/ARCHITECTURE.md,
  *Connection check*); `veroscudo set connectionCheck '<json>'` on Linux/macOS.
- **Settings in three tabs** on every platform: VPN profiles, Behaviour, Connection. macOS: Settings is now a window
  (it was a submenu).

### Linux and macOS: install and use like on Windows
- **Tray on Linux, menu-bar app on macOS** with the Windows tray's menu: Turn VPN on / off, Reconnect VPN, VPN profile ▸,
  Status…, Open log, Settings, Keep awake, Check for updates, About (with *Uninstall…*), Exit. Same icons, same state
  texts and notifications (connection lost, protected again, not connected after 2 minutes, turned off). The decisions
  live in one tested module (`traymodel.py`); GTK (Linux) and AppKit through PyObjC (macOS) only draw them. Linux:
  `python3 -m veroscudo.tray --preview DIR` renders every window into PNGs.
- **Settings** (Linux window, macOS submenu): import one of the system's VPN connections, remove a profile, choose the
  default, update check, containers/VMs (Linux). Each change asks for an administrator's password (pkexec / the macOS
  password dialog) - the passwordless sudo rule still covers only on, off, reconnect and use. New root actions
  `veroscudo remove|default|set`; the daemon picks a changed `config.json` up within 15 s (a broken file keeps the running
  configuration). There is no setting that weakens the rule.
- **Installers** (`sudo ./install.sh [--profile <connection>]`): Linux installs the missing packages (asks, or `--yes`),
  both list the system's VPN connections to pick from instead of asking for server, port and protocol (`veroscudo setup`),
  start the tray at once and at every login (Linux: XDG autostart + an applications-menu entry; macOS: a login item and
  `/Applications/VeroScudo.app`), and put `veroscudo` on the PATH (macOS: `/etc/paths.d`). The program lives in
  `/opt/veroscudo` on both, run by the system's own `python3 -I` - no pip and no venv on Linux, PyObjC only for the
  macOS menu-bar app in its own folder. An older pip / venv install is removed.
- **Uninstall**: `sudo /opt/veroscudo/uninstall.sh [--purge]` on both (also from About > Uninstall…) removes the service,
  the kill-switch, the tray, the sudo rule and the program; `--purge` also the config, state and log.
- macOS: runs on Apple's python3 3.9 (the package required 3.10, so the alpha could not be installed at all).
- The log `/var/log/veroscudo.log` is root:adm (Linux) / root:admin (macOS) 0640, so an administrator's tray can show it;
  Debian's `adm` reads the journal, where the same lines went anyway.

### Fixed
- Linux, macOS: **"protected" means what the kill-switch lets through.** The guard records the tunnel it allows
  (`/run/veroscudo/applied.json`); the tray and `veroscudo status` show *Protected* only when that matches. A dead
  WireGuard link stays "activated" in NetworkManager and only root can read its handshakes, so the tray showed it as
  protected while the guard kept it blocked.
- Linux: the installer installs `wireguard-tools` - without `wg` a dead WireGuard link was never noticed.
- Linux, macOS: `veroscudo on` / `reconnect` / `use` dial once and return (still armed and blocked); the daemon keeps
  redialing. They used to redial in the foreground until connected - forever for a dead VPN, which a tray click cannot wait for.
- Windows tests: the locks-folder repair test used the shared test folder, which an earlier test had already locked down
  when CI ran elevated - it failed in CI only.

### Tests
- CI: every nftables and pf ruleset is fed to the real parser (`nft -c`, `pfctl -n`); `linux/tests-local/container-test.sh`
  installs, turns on (blocked: nothing leaves), upgrades while armed, turns off and uninstalls in a systemd + NetworkManager
  container on Ubuntu 22.04, 24.04 and 26.04; a macOS job runs the unit tests on Apple's python3, installs, checks the guard and the
  menu-bar app, and uninstalls (it never turns the VPN on - that would cut the runner off).

### Security
- Windows: **the lock files were open to every program of the account again after a reinstall.** `Install.ps1` resets
  everything under the state folder to its rules ("Users: read"), `state\locks` included, and the folder was locked down
  only when it was created. Read is enough to open `watchdog.lock` with no sharing while the watchdog restarts and keep it:
  every later watchdog start then ends at once and self-repair stops - reproduced live from a non-elevated window. The
  installer locks the folder down again after the reset, and every elevated caller checks it and repairs it.

### Security: the install surface
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

### Security (issue #5)
- Linux, macOS: **a `veroscudo on` racing the daemon's watchdog could lose its filters.** The watchdog read "disarmed",
  then cleared the table; an `on` in another process that armed in between was undone - armed but open until the next
  pass (15 s). Every "read the armed flag, then apply or clear" now runs under one cross-process `flock` in
  `/run/veroscudo`, and the watchdog's tidy-up re-checks the flag under it.
- Windows: the installer refuses to continue when the account that elevated is not the signed-in one (over-the-shoulder
  UAC): the tasks, the tray and the DPAPI credential would belong to two accounts, and the real user would get no redial
  and no tray. The signed-in user must be an administrator; README says so.
- Linux: the installer checks for pip up front, puts the command pip actually installed (`/usr/local/bin` on Debian,
  `/usr/bin` on Arch) into the units and the sudoers rule, and refuses a command or interpreter that is not root's and
  closed to others.
- Release: the tag name reaches the workflows only as environment data and must look like a version; CI installs
  Pester and PSScriptAnalyzer at exact versions.

- Windows: **the elevated save reads text, never a path the tray chose.** The tray inlines an OpenVPN config's key files
  as the user and hands the complete text to the elevated side, which checks it as a whole and stores it; an elevated
  process no longer opens files a non-elevated one picked. The config and the imports travel in one payload file in
  the user's own folder instead of the elevated process's command line (visible to every local process and to audit
  logs, and too short for inlined keys).
- Windows: the guard's single-instance locks (watchdog, filter sync, OpenVPN runner) are exclusive file handles in an
  administrators-only folder instead of named mutexes, which any process of the account could have created first and
  so stalled self-repair and redial for good.
- Windows: `Uninstall.ps1` refuses over-the-shoulder UAC like the installer (it removes the signed-in user's folders).
- Linux: `veroscudo status` without root says the kill-switch state is unknown instead of "inactive"; the log file is
  created readable by root only.
- Documented: IKEv2's "you hung up" defence is weaker on a PC with several accounts (README, SECURITY.md).

### Fixed
- Windows: **an OpenVPN start sometimes hung after the username** until the 45 s guard restarted it. OpenVPN 2.7.8's
  management interface ran the first of two commands that arrived together twice and dropped the second - once that was
  the password (its own log: `username` twice, no `password`). VeroScudo now sends one command at a time and waits for
  OpenVPN's answer; a command nobody answers is sent once more after 5 s. A restart by that guard is logged as VeroScudo's
  own, no longer as "OpenVPN exited on its own".
- Windows: deleting an OpenVPN profile in Settings left its stored config (with the keys inlined) and its logs in the
  administrators-only OpenVPN folder; the save now removes them.
- Windows (tray): the drop-down buttons were light grey with a tiny arrow and the check boxes white on the dark theme -
  the boxes did not read as drop-downs. Both are drawn in the theme's colours now, with a clear chevron and outline.
- Windows (tray): the tray menu is styled like the windows - the window colour behind, the items grouped in rounded cards
  (one per group, equal margins on every side and between them), the header as a heading, a chevron for the profile
  submenu, Windows 11's rounded frame. `VeroScudoTray.ps1 -Preview <folder> -PreviewOnly 'menu,editor-*'` renders only the
  named shots.
- Windows (tray): No on the UAC prompt of a save said "Not saved:" plus Windows' sentence in the system language; it now
  says that administrator approval was cancelled and nothing was changed.
- Windows (`tests-local/Test-Live.ps1`): the profile-switch phase counted traffic through the OLD tunnel, which stays
  allowed until the new profile's filters are in, as a leak. A leak now needs neither tunnel up, before and after the
  probe, and is logged with its time and route.
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
- Windows: the tray's C# helpers (DPI, dark title bars, keep-awake badge, theme, menu renderer, themed message box) are
  one file, `VeroScudo.Tray.cs`, loaded by the tray exactly as before and compiled by the unit suite, so a broken helper
  fails the tests rather than the tray at sign-in.
- Linux, macOS: every guard test runs against both backend pairs (nftables + NetworkManager, pf + scutil) through one
  parametrized fixture that reads rulesets only through a backend-neutral check.
- Windows: **the tray has unit tests.** What the tray decides - state, title and text from the guard's facts, the exit
  location line, "a state file changed", the per-user preferences, the update-notice rule - moved from the WinForms
  script into `VeroScudo.Tray.psm1` as functions with explicit inputs, tested in `tests/VeroScudo.Tray.Tests.ps1`
  (6 groups). `VeroScudoTray.ps1` calls them with its globals and only draws.
- CI: PSScriptAnalyzer now fails on parse errors too (the settings listed Error and Warning only, so a script that no
  test imports - installer, tray - could have shipped unparseable).
- Windows: the anti-forgery rule for a "you hung up" record is one pure function, `Resolve-VeroTerminationCode`
  (conflicting records, VeroScudo's own hang-up, a connection id never seen connecting), tested on its own; the filter
  spec takes the permit kind explicitly (`server` / `endpoints`) instead of reading it from `$null` vs `@()`; the
  type's config rules (name shape, server, username) and its on-disk keys live in the handler table, used by config.json
  validation and the tray's profile editor alike; the status line's server text is its own function.
- Linux, macOS: the DNS and resolver helpers both VPN backends copied are one module (`netutil.py`); the daemon's two
  marker readers and two cache readers are one each; the timing windows are named constants, documented next to the
  Windows ones (docs/ARCHITECTURE.md, "Timing windows").
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

### Fixed: import and other-VPN detection
- Windows: the elevated guard took Program Files / ProgramData / System32 from environment variables a non-admin process
  can plant; they now come from the OS and HKLM.
- Windows: Teredo, IP-HTTPS, 6to4 and ISATAP no longer count as "another VPN" (On refused every time).
- Windows: On while already on no longer says "not turned on"; a VPN app's tunnel is no longer logged as disconnected;
  the prompt offers "Disconnect what it can" next to "Turn on anyway".
- Windows: a short task that could not load the helper no longer leaves a false *Helper blocked* until reboot, nor delays
  the watchdog's retry.
- Linux: `veroscudo import` undoes nmcli's escaping (`host\:4443`, URLs, IPv6); policy-based IPsec (strongSwan,
  libreswan) is refused - it has no tunnel interface, so it could only stay blocked.

### Fixed
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

### Security
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
  lets a new address through. Before, a server that moved had its tunnel cut 5 s after arming, and every redial was refused.
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
