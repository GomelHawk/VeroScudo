# VeroScudo architecture

One behaviour, implemented natively per platform. This document is the contract every
backend must honour; the platform notes below say how each one does it. The threat model -
what this protects against and what it does not - is in [`SECURITY.md`](SECURITY.md).

| Platform | Status | Kill-switch | VPN control |
|---|---|---|---|
| Windows 10/11 | stable | WFP filters (own provider + sublayer) | RAS (`RasDial` API, `rasdial`) |
| Linux (Ubuntu 22.04+) | beta - unit-tested, no real-machine log yet | nftables table `inet veroscudo` | NetworkManager (`nmcli`, libnm) |
| macOS | alpha - unit-tested, never run on a Mac | pf anchor `com.apple/250.VeroScudo` | `scutil --nc` |

## The rule

> **VPN on + connection lost ⇒ no network at all, until the VPN is back or the user turns
> the VPN off.** A deliberate "off" is the only way to raw internet.

No timers, no automatic unblock, no rescue action. "Strict" is not a setting.

## States

```
             user connects VPN                      tunnel drops (not by user)
 DISARMED ───────────────────────► ARMED/UP ───────────────────────────► ARMED/DOWN
    ▲        filters: none            filters: kill-switch                 filters: kill-switch
    │                                 traffic: via tunnel only             traffic: none
    │                                                                      action: redial every N s
    │  user disconnects VPN (any way)                                           │
    └────────────────────────────────────────────◄──────────────────────────────┘
                                                  redial succeeds ⇒ ARMED/UP
```

| Transition | Trigger (what the OS tells us) | Guard does |
|---|---|---|
| → ARMED | VPN connected event for a configured profile | write `armed` flag, make that profile active, apply the kill-switch |
| ARMED/UP → ARMED/DOWN | VPN terminated event with a *failure* reason, for the active profile, and the tunnel really is down | keep blocking, block the VM/WSL path, start the redial loop |
| ARMED/DOWN → ARMED/UP | redial succeeded (connected event) | re-bind the tunnel interface in the filters, re-allow the VM/WSL path |
| ARMED → DISARMED | VPN terminated event with the *user-requested* reason, or the guard's own `off` | remove `armed` flag, remove every filter |
| profile switch | tray / `veroscudo use` | see *Profiles* - stays blocked throughout |
| watchdog (every 15 s) | timer | armed ⇒ recompute the filter set and re-apply it if it differs or went missing, redial if down; disarmed but filters present ⇒ remove |

"Failure" vs "user-requested" is the only judgement the guard makes and it comes from the
platform's VPN subsystem, never from heuristics:

| Platform | Connected event | Terminated event | User-requested reason |
|---|---|---|---|
| Windows | System log, RasMan 20267 (profile = field 2) | Application log, RasClient 20226 | reason code 631 |
| Linux (NetworkManager) | `ActiveConnection.StateChanged` → activated | → deactivated | reason `user-requested` (2) |
| macOS (alpha) | `scutil --nc status` polling | idem | **none available** - every drop counts as a failure; `veroscudo off` to stop |

### Event checks (anti-spoofing)

The Application log accepts events from ordinary users, so a terminated event is only acted on when:

1. it is for the **active** profile (the old profile's hang-up during a switch is ignored);
2. the tunnel is **really down** (`Get-VpnConnection` / `nmcli`) - a "you hung up" while the tunnel
   is up is stale or forged and ignored;
3. on Windows, its connection id (CoID) has **no other termination record with a different code**
   - RAS writes exactly one per connection, so a 631 next to the real 829 is treated as a failure.

The connected event on Windows comes from the System log (RasMan), which ordinary users cannot write.

## The kill-switch

Default **block**, plus an allow-list. Everything not listed is blocked: TCP, UDP/QUIC, ICMP,
IPv4 and IPv6, outbound and unsolicited inbound, and on Linux anything forwarded for VMs and containers.

| Allowed while armed | Scope | When |
|---|---|---|
| loopback | - | always |
| the tunnel | its interface (Windows: LUID, Linux: `oifname`, macOS: `on ipsecN`) - only the **active** profile's | while up |
| the VPN server | its addresses + the profile's protocol/ports (Windows: per tunnel type - SSTP TCP 443, IKEv2/L2TP UDP 500/4500/1701 + ESP, PPTP TCP 1723 + GRE); on Windows TCP/UDP only from `svchost.exe` (SstpSvc, IKEEXT, RasMan) | always (keeps the tunnel and lets it redial) |
| DHCP / DHCPv6, IPv6 neighbour discovery (link-local only) | ports / ICMPv6 types | always |
| DNS | UDP/TCP 53, Windows: only `svchost.exe` (DNS Client) and only to the resolvers of the up physical links; Linux: only the `systemd-resolve` user, else only the resolvers in `resolv.conf`; macOS: only those resolvers | **only while the tunnel is down** (to resolve the server) |
| certificate revocation (Windows) | TCP 80 from `svchost.exe` (SstpSvc/CryptSvc) | only while the tunnel is down (SSTP checks it on every dial) |
| host ↔ WSL switch (Windows) | the WSL vEthernet interface (LUID, re-bound every 15 s - it changes at every boot) | always |
| `lanAllow` ranges | each CIDR, IPv4 `/8`+ / IPv6 `/16`+ only | always |

While the tunnel is up there is no DNS permit outside it: name resolution goes through the tunnel,
so nothing is resolved by the local network's DNS server (no DNS leak).

### Windows: WFP, not firewall rules

Windows Defender Firewall's default-outbound Block still lets through every *enabled outbound
allow rule* - Store apps, "Core Networking", rules installers add, GPO rules (a typical PC has
150+). That is not a kill-switch. VeroScudo instead adds **its own WFP provider and sublayer**
(weight 0xFFFF) with persistent filters at `ALE_AUTH_CONNECT_V4/V6` and `ALE_AUTH_RECV_ACCEPT_V4/V6`:
scoped PERMIT filters (weight 8) and one catch-all BLOCK per layer (weight 0). WFP arbitration
makes a BLOCK in any sublayer final, so no firewall rule can override it; the PERMITs are soft
(they do not clear the action right), so the user's own firewall blocks still apply.

- **Atomic**: the whole set is replaced in one WFP transaction - no gap, no half state.
- **Persistent**: filters survive reboots and BFE restarts, so an armed PC is strict from boot.
- **Self-checking**: `Install.ps1` verifies every layer/field id against the running WFP before it
  changes anything; filter keys are derived from an index so the watchdog can count them.
- **Fail closed**: if applying filters fails, the guard falls back to the firewall's default-outbound
  Block (weaker, never open) and logs `EMERGENCY`; the next successful sync removes it.
- **Uninstall / Off** delete every filter; `Uninstall.ps1` also removes the provider and sublayer.
  1.0.x firewall rules and profile defaults are migrated away on upgrade (filters first).

### VMs and containers

Their packets are forwarded, not sent by the host, so they need their own control:

- **Windows (WSL)**: the Hyper-V firewall - the WSL VM's default outbound is set to Block while
  armed (restored on disarm), and an allow rule is enabled only while the tunnel is up.
- **Linux**: the `forward` chain - accept only out through the tunnel, only while it is up.
- **macOS**: not filtered (alpha).

The toggle happens on the terminated/connected events, so VM traffic has a ~1–2 s exposure
window after a drop; the host itself has none. Bridged VMs (Hyper-V external switch, VirtualBox/
VMware/libvirt bridged mode) send frames below the host's IP stack and are **not** covered.

## Reconnecting

Every `retrySeconds` (10), forever, in a single loop guarded by an atomic lock file (`CreateNew` /
`O_EXCL`). Each attempt re-reads the config (it follows a profile switch) and re-syncs the
filters. The loop ends only when the tunnel is up or the state becomes DISARMED.

- **Windows**: the `RasDial` API with the DPAPI-stored credential - the password is never on a
  command line (process lists, EDR, event 4688). Without a stored credential, `rasdial <profile>`.
- **Linux**: `nmcli connection up`; NetworkManager keeps the secrets (keyring / `psk-flags`).
- **macOS**: `scutil --nc start`; the keychain keeps the secrets.

Server addresses: `serverIps` in the profile pins them (nothing resolved). Otherwise each sync
resolves the name and merges the result with the cache (newest first, at most 8), so a host
that moves keeps working and a lookup that fails while blocked still leaves the last known
addresses.

## Profiles

Several VPN profiles can be configured; one is **active**. The runtime selection is kept in the
admin-owned state folder (`active-profile`), the configured default in `activeProfile`.

Switching (tray menu *VPN profile*, `veroscudo use <name>`):

1. the name is checked against `config.json` (the tray only *requests*: Windows writes the name
   to the user's own folder and runs the elevated `Switch` task; Linux/macOS run `sudo veroscudo use`);
2. the new profile becomes active **first**, so the old profile's hang-up is ignored;
3. while armed: the filters are re-applied for the new profile with no tunnel (blocked), the old
   tunnel is hung up, the new one is dialed by the normal redial loop - nothing leaves the
   machine between the two tunnels;
4. while off: only the selection changes.

Connecting a configured profile by hand (Windows Settings, nmcli) makes it the active one;
connecting a VPN that is not configured is ignored.

## Files and layout (per platform)

| | Windows | Linux | macOS (alpha) |
|---|---|---|---|
| program | `C:\Program Files\VeroScudo\` (+ `VeroScudo.Native.dll`, compiled at install) | python package (pip) | venv in `/usr/local/lib/veroscudo` |
| config | `%ProgramData%\VeroScudo\config.json` | `/etc/veroscudo/config.json` | `/etc/veroscudo/config.json` |
| state + log | `%ProgramData%\VeroScudo\state\` - Administrators/SYSTEM full, Users read only | `/var/lib/veroscudo/` (armed flag, active profile, server cache - survive reboot), `/run/veroscudo/` (lock), `/var/log/veroscudo.log` | `/var/lib/veroscudo/`, `/var/run/veroscudo/`, `/var/log/veroscudo.log` |
| per-user | `%LOCALAPPDATA%\VeroScudo\` - `cred-<profile>.xml`, `switch.request`, `update.json` | – | – |
| scheduler | Task Scheduler `\VeroScudo\{Connected,Terminated,Watchdog,On,Off,Switch}` (highest) + `Tray` (limited) | `veroscudo.service` + `veroscudo-boot.service` (root) + `veroscudo-tray.service` (user) | launchd `com.gomelhawk.veroscudo` |
| kill-switch | WFP provider/sublayer "VeroScudo" + Hyper-V rule `VeroScudo-WSL` | nftables table `inet veroscudo` | pf anchor `com.apple/250.VeroScudo` |

The Windows state location is fixed: it is never taken from an environment variable (a value a
non-admin process can plant in `HKCU\Environment` must not redirect an elevated guard).

`config.json` (same keys everywhere; the 1.0 single `"vpn": {...}` object is still accepted):

```json
{
  "profiles": [
    { "profile": "Work",   "server": "vpn.example.com",  "port": 443,  "username": "jdoe" },
    { "profile": "Backup", "server": "vpn2.example.com", "port": 4500, "username": "jdoe", "protocol": "udp", "serverIps": ["198.51.100.9"] }
  ],
  "activeProfile":   "Work",
  "retrySeconds":    10,
  "vm":              "auto",
  "wifiRecoveryFix": true,
  "updateCheck":     true,
  "lanAllow":        []
}
```

Every value is validated (it ends up in filters, nft rules and command arguments run as root):
profile names without control/wildcard characters, host names or IPs, ports 1-65535,
`retrySeconds` 3-3600, `serverIps` real addresses, `lanAllow` real ranges no wider than IPv4 /8
or IPv6 /16 (never `0.0.0.0/0`, `Any`).

- `profile`: the OS's name for the VPN (Windows Settings > VPN, NetworkManager connection id, macOS VPN service).
- `protocol` (Linux/macOS): `tcp` or `udp` - the VPN control channel. On Windows it follows the profile's tunnel type.
- `serverIps`: pin the server addresses (nothing is resolved for that profile).
- `vm`: `"auto"` (detect WSL/Docker), `true`, `false`.
- `wifiRecoveryFix` (Windows only): sets `HKLM\SOFTWARE\Microsoft\WcmSvc\EnableBadStateTracking=0`.
  Without it Windows resets the Wi-Fi adapter ~15 s after a tunnel is dialed under the
  kill-switch (WLAN AutoConfig event 4003) and kills the fresh tunnel. Reverted on uninstall.
- `lanAllow`: ranges allowed while armed, both directions. Empty = strict (recommended).
- `updateCheck`: the tray asks GitHub for the latest release once, two minutes after it starts, and shows a notice
  when it is newer. Only while the state is *protected* or *off* - never while blocked. HTTPS to `api.github.com`,
  nothing sent but the version in the User-Agent. Only links to this project's release pages are opened.
  `false` disables it. No automatic installation.

## Tray app

Runs **without administrator rights** (Windows: `Limited` task; Linux: user service). Reads state
only (flag files, active profile, the OS's VPN status); every action runs the same scheduled
task / `sudo veroscudo` command the shortcuts use, so the guard logic lives in one place.
Icon = state (Protected / Blocked / Off / Attention), menu = Turn on / Turn off / **VPN profile ▸** /
Status / Log / Settings / About / Exit. Settings (Windows) edits the profiles list; it writes
`config.json` through an elevated, re-validating PowerShell (UAC prompt), passing the JSON inside
`-EncodedCommand` - no temp file. Passwords are stored per profile for the signed-in user only.
