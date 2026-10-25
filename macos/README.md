# VeroScudo for macOS - alpha

**Alpha: written and unit-tested, never run on a real Mac yet.** Same rule as Windows and Linux; the guard is the shared
Python package in [`../linux`](../linux) with two macOS backends:

| Concern | macOS |
|---|---|
| VPN control | `scutil --nc start/stop/status` for VPN services macOS manages (System Settings > VPN: IKEv2, L2TP, Cisco IPSec); the password stays in the keychain |
| Connect / terminate | `scutil --nc status` polling every 2 s |
| User-requested vs failure | **not available** - every drop is treated as a failure (strict: stays blocked and redials). Turn off with `sudo veroscudo off` |
| Kill-switch | `pf` anchor `com.apple/250.VeroScudo` (evaluated by the stock `/etc/pf.conf`, no system file edited): `quick` allow-list, ends with `block drop quick all`. pf enabled with a reference token, released on off |
| Service | launchd daemon `com.gomelhawk.veroscudo` (root, `RunAtLoad` + `KeepAlive`): re-applies the kill-switch at boot and every 15 s |
| Profiles | `veroscudo profiles`, `sudo veroscudo use <name>` - same switching rules as Linux |

```bash
cd VeroScudo/macos && sudo ./install.sh
sudo veroscudo on
```

## Known gaps (why it is alpha)

- Not yet run on a Mac: the pf rules and the `scutil` output parsing are unit-tested only.
- Boot window: pf rules do not persist across a reboot; they are back as soon as launchd starts the daemon, which is
  early but not before the network.
- No tray / menu-bar app yet (CLI only).
- Virtual machines and containers (`vm`) are not filtered.
- Third-party VPN apps (their own tunnels) are not supported - same as on the other platforms.

Before calling it beta: a `macos/tests-local/` script and a real-machine log, as for Windows.
