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
| Reconnect (user) | tray *Reconnect VPN*, `-Action reconnect`, `veroscudo reconnect` | while armed: apply the filters **without** the tunnel, hang it up, redial; ARMED/DOWN until the new tunnel is up. Our own hang-up is marked (`renew.json` / `renew.marker`) so its "user-requested" reason is read as a failure, not as your Off |
| password rejected | RAS 691, OpenVPN `Verification Failed: 'Auth'` | stay blocked, stop redialing (`authfail-*.flag`) until a newer password is stored or you press On / Reconnect - retrying could lock the account |
| watchdog (every 15 s) | timer | armed ⇒ recompute the filter set and re-apply it if it differs or went missing, redial if down; disarmed but filters present ⇒ remove |

"Failure" vs "user-requested" is the only judgement the guard makes and it comes from the
platform's VPN subsystem, never from heuristics:

| Platform | Connected event | Terminated event | User-requested reason |
|---|---|---|---|
| Windows | System log, RasMan 20267 (profile = field 2) | Application log, RasClient 20226 | reason code 631 |
| Linux (NetworkManager) | `ActiveConnection.StateChanged` → activated | → deactivated | reason `user-requested` (2) |
| macOS (alpha) | `scutil --nc status` polling | idem | **none available** - every drop counts as a failure; `veroscudo off` to stop |
| Windows, OpenVPN profile | the runner reads `>STATE:...,CONNECTED` on the management interface | `>STATE:...,EXITING` / the process ends | only VeroScudo's own `signal SIGTERM` (Off, switch, Reconnect) - any other end is a failure |
| Windows, WireGuard profile | watchdog: the tunnel service started (WireGuard app) | service stopped / crashed, or no handshake for 3 min | the service was **removed** (deactivated in the WireGuard app) while VeroScudo was not reconnecting it |

## Profile types (Windows)

Every profile has a `type`; the guard, the filters, the watchdog and the tray are shared, and each type supplies five
things: how to tell the tunnel is up, its adapter, its server endpoints, how to dial and how to hang up.

| | `ras` (default, stable) | `openvpn` (beta) | `wireguard` (beta) |
|---|---|---|---|
| client | Windows built-in (RAS) | `openvpn.exe` (OpenVPN community), run by VeroScudo | WireGuard for Windows (tunnel service `WireGuardTunnel$<name>`) |
| up = | the RAS adapter is up | the runner saw `CONNECTED` and that tunnel address sits on an up tunnel adapter (TAP/Wintun/DCO) | the service runs **and** the last handshake is < 3 min old (the adapter itself is allowed while the service runs) |
| adapter (LUID) | the `Ppp` adapter named like the profile | the tunnel adapter holding the CONNECTED address | the `WireGuard` adapter named like the tunnel |
| server permit | per tunnel type (SSTP/IKEv2/L2TP/PPTP ports), TCP from `svchost.exe` | every `remote` of the `.ovpn` on its protocol/port, only from `openvpn.exe` (DCO off by default; `"dco": true` drops the program condition) | UDP to the endpoint (no program: the kernel driver sends it); the address the tunnel really uses is learned while it runs |
| dial | `RasDial` with the stored credential | start the runner task, wait for CONNECTED | start / install the tunnel service; a silent tunnel is removed and installed again (fresh name lookup) |
| hang up | `rasdial /disconnect` | stop request -> the runner sends `signal SIGTERM` | `wireguard.exe /uninstalltunnelservice` (what the app's *Deactivate* does) |
| password | DPAPI per user, `RasDial` | the same store, sent over the management connection | none (keys in the WireGuard app) |

**OpenVPN runner.** The elevated task `\VeroScudo\OpenVPN` (one per session, mutex) runs `openvpn.exe` for the active
profile while armed: your file first, then VeroScudo's options so they win - `--management 127.0.0.1 <random port>
<one-time password file>` (administrators only, deleted after login), `--management-hold`, `--management-query-passwords`,
`--auth-retry interact`, `--auth-nocache`, `--script-security 1`, its own `--log`, `--auth-user-pass` (no file) and
`--disable-dco` (2.6+). It answers password / key-passphrase / static-challenge prompts, follows `>STATE:` (re-syncing the
filters on CONNECTED / RECONNECTING / EXITING) and restarts OpenVPN every `retrySeconds` when it ends on its own. It stops on
Off, on a switch to another profile, on a rejected password and on VeroScudo's stop request. Imported configs may use only an
**allow-list** of known client options (no `up`/`down`/`plugin`/`pkcs11-providers`/`providers`/`engine`/`management`/`config`/
`log`/proxies, no `script-security` above 1, no option names with quotes or escapes); inline blocks end where OpenVPN ends them;
referenced key files are inlined at import and refused if they contain tag lines; the stored result is checked again as a whole.

**WireGuard watch.** Only the long-running watchdog keeps the previous state of each WireGuard tunnel service, so it alone
sees the edges: *not running -> running* while not the armed active profile = activated in the WireGuard app -> arm and
make it active (like connecting a Windows VPN by hand); *running -> removed* while armed, active and no reconnect running =
deactivated in the app -> your Off. *running -> stopped* (still installed: a crash, `services.msc`) is a failure. All starts
are handled before any removal in a pass, so switching tunnels in the app ends armed on the new one. The adapter is allowed
while the service runs (app traffic is what starts a handshake when no keepalive is set; a dead tunnel only loses it - its
routes point into it). A tunnel without a handshake for 3 minutes counts as down and the redial restarts it.

**Other VPNs at Turn on (Windows).** `Get-VeroForeignVpn` lists every connected VPN that is not the active profile's tunnel:
another Windows VPN (also another configured profile), a WireGuard tunnel, an `openvpn.exe` VeroScudo did not start, or a
vendor app's tunnel adapter. The tray asks before *On*; the guard's `on` refuses while any is connected (writes
`state\on-refused.json`, the tray shows why), `on-disconnect` (tasks `OnDisconnect`, `-DisconnectOthers`) ends them first,
each the way its own client does, and `on-force` (`OnForce`, `-Force`) turns on next to them. A vendor app's tunnel cannot be
ended by VeroScudo. A Windows VPN that is not a profile connecting while armed is written to `state\foreign.json` (tray
notification). Nothing is ever disconnected or imported without the user's choice.

**Helper blocked by Windows.** Smart App Control (or an App Control policy) can refuse the locally compiled, unsigned
`VeroScudo.Native.dll`. A process that failed to load it keeps failing for its whole life, so the watchdog records the block
(`state\native-blocked.json`) and exits; its task starts a fresh one, which retries only when due - 1, then 5, then every
10 minutes - and clears the record on the first successful pass. The filters already applied stay in force; while blocked,
self-repair and the watchdog's redial are paused and the tray shows *Attention*. A signed release DLL is the real fix.

**Conflicts.** About once a minute the watchdog lists what else tunnels or filters next to VeroScudo (`state\conflicts.json`):
`openvpn.exe` it did not start, an `.ovpn` with the same server in OpenVPN GUI's or the OpenVPN service's folders, other
active WireGuard tunnels, any other up tunnel adapter (vendor VPN apps), and WFP providers of known VPN apps. Read-only;
the tray shows *Attention* while armed and protected.

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
| DHCP / DHCPv6, IPv6 neighbour discovery (link-local only) | ports / ICMPv6 types; Windows: DHCP only from `svchost.exe` (DHCP client) | always |
| DNS | UDP/TCP 53, Windows: only `svchost.exe` (DNS Client) and only to the resolvers of the up physical links; Linux: only the `systemd-resolve` user, else only the resolvers in `resolv.conf` or, when that names only a local stub, NetworkManager's; macOS: only those resolvers. **No resolver known: no DNS permit** (never port 53 to anywhere) | **only while the tunnel is down** (to resolve the server) |
| certificate revocation (Windows, SSTP) | TCP 80 from `svchost.exe` | **only for 2 minutes after a dial failed on the revocation check** (`state\crl-window.json`). Not open by default: BITS, Delivery Optimization and WPAD share `svchost.exe`, so a standing permit would be a side door |
| host ↔ WSL switch (Windows) | the WSL vEthernet interface (LUID, re-bound every 15 s - it changes at every boot) | always |
| `lanAllow` ranges | each CIDR, IPv4 `/8`+ / IPv6 `/16`+ only | always |

While the tunnel is up there is no DNS permit outside it: name resolution goes through the tunnel,
so nothing is resolved by the local network's DNS server (no DNS leak).

**Linux (nftables).** Every explicit permit outside the tunnel sets a conntrack mark; established traffic is accepted only
with that mark, so a flow that used the tunnel cannot continue over the physical NIC after a drop. An `input` chain with
policy drop admits only loopback, the tunnel, replies to marked flows, DHCP replies, neighbour discovery, ESP/GRE from the
VPN server and `lanAllow`. **macOS (pf)**: every pass keeps its state bound to its interface (`if-bound`).

**Windows: "you hung up" must name the right connection.** At arm the guard records the connection id (CoID) of the RasMan
20267 it saw in the System log (users cannot write that log). A RasClient 20226 with code 631 counts only if it names that
same CoID; any other id - a forged record with a fresh GUID raced in after a real failure - is a failure. The `Terminated`
task also waits 3 s first, so a forged 631 for the real CoID meets the real record and the conflict check sees both.

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
| per-user | `%LOCALAPPDATA%\VeroScudo\` - `cred-<profile>.xml`, `keypass-<profile>.xml` (OpenVPN key), `otp-<profile>.txt` (one-time code, read once), `switch.request`, `update.json`, `tray.json` (keep awake, last profile for the switch notice) | `~/.config/veroscudo/tray.json` | – |
| OpenVPN (Windows) | `%ProgramData%\VeroScudo\openvpn\<profile>.ovpn` (administrators/SYSTEM only); `state\ovpn-<profile>.json/.log` | – | – |
| scheduler | Task Scheduler `\VeroScudo\{Connected,Terminated,Watchdog,On,OnDisconnect,OnForce,Off,Switch,Reconnect,OpenVPN}` (highest) + `Tray` (limited) | `veroscudo.service` + `veroscudo-boot.service` (root) + `veroscudo-tray.service` (user) | launchd `com.gomelhawk.veroscudo` |
| kill-switch | WFP provider/sublayer "VeroScudo" + Hyper-V rule `VeroScudo-WSL` | nftables table `inet veroscudo` | pf anchor `com.apple/250.VeroScudo` |

The Windows state location is fixed: it is never taken from an environment variable (a value a
non-admin process can plant in `HKCU\Environment` must not redirect an elevated guard).

`config.json` (same keys everywhere; the 1.0 single `"vpn": {...}` object is still accepted):

```json
{
  "profiles": [
    { "profile": "Work",   "server": "vpn.example.com",  "port": 443,  "username": "jdoe" },
    { "profile": "Backup", "server": "vpn2.example.com", "port": 4500, "username": "jdoe", "protocol": "udp", "serverIps": ["198.51.100.9"] },
    { "profile": "Reserve", "type": "openvpn", "username": "jdoe", "auth": true },
    { "profile": "wg-home", "type": "wireguard", "server": "wg.example.com", "port": 51820 }
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

- `profile`: the OS's name for the VPN (Windows Settings > VPN, NetworkManager connection id, macOS VPN service; the
  WireGuard app's tunnel name - 1-32 of `A-Z a-z 0-9 _ = + . -`).
- `vpnType` (Linux/macOS): what the server permit allows - `l2tp` (UDP 500/4500/1701 + ESP), `ikev2`/`ipsec` (UDP 500/4500
  + ESP), `pptp` (TCP 1723 + GRE), `sstp` (TCP port), `openconnect` (TCP+UDP port), `openvpn`/`wireguard`/empty (protocol +
  port). Written by `veroscudo import`. On Windows the protocol is read from the Windows profile itself.
- `auth` (Windows, `ras`): `false` for a certificate sign-in (no username, no stored password).
- `type` (Windows): `ras` (default), `openvpn` or `wireguard` - see *Profile types*. `openvpn` needs no `server`
  (the imported `.ovpn`'s `remote` lines are used), `auth` says whether it asks for a password, `dco: true` keeps the
  kernel data channel. `wireguard` needs `server` + `port` (its endpoint) and no username.
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
