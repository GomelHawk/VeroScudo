# VeroScudo for macOS - planned

Same rule, native pieces:

| Concern | macOS |
|---|---|
| VPN control | `scutil --nc start/stop` for built-in profiles (IKEv2, L2TP); `networksetup -connectpppoeservice` |
| Connect / terminate events | `scutil --nc status` polling or `NEVPNStatusDidChange` via a small Swift helper |
| User-requested vs failure | `scutil --nc statistics` + the helper's disconnect-reason |
| Kill-switch | `pf` anchor with `block drop out`, pass on `utun*`, DHCP/DNS, the server address |
| Service | `launchd` daemon (root) + agent (tray via `NSStatusItem`) |

Not started. Contributions welcome - follow `docs/ARCHITECTURE.md` and add `macos/tests-local/`
with a real-machine log before marking it supported.
