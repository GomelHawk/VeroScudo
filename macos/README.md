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
echo 'export PATH="/opt/veroscudo/bin:$PATH"' >> ~/.zprofile   # new shell afterwards
sudo veroscudo on
```

The program lives in `/opt/veroscudo` (root-owned on every Mac). It is deliberately **not** under `/usr/local`: on
Intel Macs Homebrew makes `/usr/local/lib` and `/usr/local/bin` writable by you, and anything the root daemon and the
passwordless `sudo` rule run from must not be replaceable by a user-level process. Where `/usr/local/bin` already
exists and is root's, the installer adds a link there too; it never creates that folder or changes its owner.

## Known gaps (why it is alpha)

- Not yet run on a Mac: the pf rules and the `scutil` output parsing are unit-tested only.
- Boot window: pf rules do not persist across a reboot; they are back as soon as launchd starts the daemon, which is
  early but not before the network.
- `pfctl -d` (root) turns pf off with the anchor still listed; the daemon notices within 15 s and enables it again,
  but those seconds are open. On Linux the same holds for `nft flush ruleset`.
- A missing or broken `config.json` while armed: the daemon applies a lockdown (loopback, DHCP, neighbour discovery
  only) and exits; fix the file and run `sudo veroscudo on`.
- No tray / menu-bar app yet (CLI only). Keep awake is `veroscudo awake` (runs `caffeinate -i -s`, Ctrl-C to
  stop; unit-tested, not yet run on a Mac).
- Virtual machines and containers (`vm`) are not filtered.
- Third-party VPN apps (their own tunnels) are not supported - same as on the other platforms.

Before calling it beta: a `macos/tests-local/` script and a real-machine log, as for Windows.
