# VeroScudo for macOS - alpha

**Alpha: unit-tested, installed and uninstalled in CI on a macOS runner, never run with a real VPN yet.** Same rule as Windows and Linux; the guard is the shared
Python package in [`../linux`](../linux) with two macOS backends:

| Concern | macOS |
|---|---|
| VPN control | `scutil --nc start/stop/status` for VPN services macOS manages (System Settings > VPN: IKEv2, L2TP, Cisco IPSec); the password stays in the keychain |
| Connect / terminate | `scutil --nc status` polling every 2 s |
| User-requested vs failure | **not available** - every drop is treated as a failure (strict: stays blocked and redials). Turn off from the menu bar (or `sudo veroscudo off`) |
| Kill-switch | `pf` anchor `com.apple/250.VeroScudo` (evaluated by the stock `/etc/pf.conf`, no system file edited): `quick` allow-list, ends with `block drop quick all`. pf enabled with a reference token, released on off |
| Service | launchd daemon `com.gomelhawk.veroscudo` (root, `RunAtLoad` + `KeepAlive`): re-applies the kill-switch at boot and every 15 s |
| Profiles | `veroscudo profiles`, `sudo veroscudo use <name>` - same switching rules as Linux |

## Install, use, uninstall

```bash
cd VeroScudo-macos/macos && sudo ./install.sh           # pick the VPN service from the list
sudo ./install.sh --profile "Office IKEv2"               # or name it
```

Needs Apple's `python3` (Command Line Tools: `xcode-select --install`) and, once, internet access to fetch PyObjC for the
menu-bar app (pinned, wheels only, into `/opt/veroscudo/tray-lib` - the root daemon never loads it).

What goes where: the program in `/opt/veroscudo` (root's; run by `/usr/bin/python3 -I`), on the PATH through
`/etc/paths.d/veroscudo` (new terminal windows), the launchd daemon `com.gomelhawk.veroscudo`, the login item
`/Library/LaunchAgents/com.gomelhawk.veroscudo.tray.plist`, `/Applications/VeroScudo.app` (shows the menu-bar icon again
after *Exit*), the sudoers rule (your user: `on`, `off`, `reconnect`, `use` - nothing else), the config
`/etc/veroscudo/config.json`, the log `/var/log/veroscudo.log` (readable by administrators).

**Menu bar**: Turn VPN on / off, Reconnect VPN, VPN profile ▸, Status…, Open log, Settings ▸ (import a VPN service,
remove, default profile, update check - each asks for your password), Keep awake, Check for updates, About (Uninstall…),
Exit. **Turn the VPN off from here**, not in System Settings: macOS gives no "you hung up" reason, so a disconnect there
counts as a drop and you stay blocked until *Turn VPN off*.

**Uninstall**: menu bar > About VeroScudo > *Uninstall…*, or `sudo /opt/veroscudo/uninstall.sh` (`--purge`: also config,
state, log).

## Known gaps (why it is alpha)

- Not yet run on a Mac with a real VPN: the pf rules pass `pfctl -n` and install / uninstall run in CI on a macOS runner,
  but arming (which would cut the runner off) and the `scutil` output parsing are unit-tested only.
- The menu-bar app's windows are standard alerts; it has not been looked at on a real screen beyond the CI screenshot.
- Boot window: pf rules do not persist across a reboot; they are back as soon as launchd starts the daemon, which is
  early but not before the network.
- `pfctl -d` (root) turns pf off with the anchor still listed; the daemon notices within 15 s and enables it again,
  but those seconds are open. On Linux the same holds for `nft flush ruleset`.
- A missing or broken `config.json` while armed: the daemon applies a lockdown (loopback, DHCP, neighbour discovery
  only) and exits; fix the file and run `sudo veroscudo on`.
- Keep awake (menu bar, or `veroscudo awake`) runs `caffeinate -i -s`; unit-tested, not yet run on a Mac.
- Virtual machines and containers (`vm`) are not filtered.
- Third-party VPN apps (their own tunnels) are not supported - same as on the other platforms.

Before calling it beta: a `macos/tests-local/` script and a real-machine log, as for Windows.
