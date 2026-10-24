# VeroScudo architecture

One behaviour, implemented natively per platform. This document is the contract every
backend must honour; the platform notes below say how each one does it.

## The rule

> **VPN on + connection lost ⇒ no network at all, until the VPN is back or the user turns
> the VPN off.** A deliberate "off" is the only way to raw internet.

No timers, no automatic unblock, no rescue action. "Strict" is not a setting.

## States

```
             user connects VPN                      tunnel drops (not by user)
 DISARMED ───────────────────────► ARMED/UP ───────────────────────────► ARMED/DOWN
    ▲        firewall: default        firewall: kill-switch                firewall: kill-switch
    │                                 traffic: via tunnel only             traffic: none
    │                                                                      action: redial every N s
    │  user disconnects VPN (any way)                                           │
    └────────────────────────────────────────────◄──────────────────────────────┘
                                                  redial succeeds ⇒ ARMED/UP
```

| Transition | Trigger (what the OS tells us) | Guard does |
|---|---|---|
| → ARMED | VPN connected event | write `armed` flag, enable kill-switch |
| ARMED/UP → ARMED/DOWN | VPN terminated event with a *failure* reason | keep kill-switch, block the VM/WSL path, start the redial loop |
| ARMED/DOWN → ARMED/UP | redial succeeded (connected event) | re-allow the VM/WSL path, keep kill-switch |
| ARMED → DISARMED | VPN terminated event with the *user-requested* reason, or the guard's own `off` | remove `armed` flag, restore firewall |
| watchdog (periodic + at logon) | timer | armed+down ⇒ ensure blocked, (re)start loop; disarmed but still blocked ⇒ restore |

"Failure" vs "user-requested" is the only judgement the guard makes and it comes from the
platform's VPN subsystem, never from heuristics:

| Platform | Connected event | Terminated event | User-requested reason |
|---|---|---|---|
| Windows | System log, RasMan 20267 | Application log, RasClient 20226 | reason code 631 |
| Linux (NetworkManager) | `ActiveConnection.StateChanged` → activated | → deactivated | reason `user-requested` (2) |
| macOS (planned) | `scutil`/`networksetup` + `ne` notifications | idem | user-initiated flag |

## The kill-switch

Default outbound policy = **drop**, plus an allow-list. Everything not listed is blocked,
including UDP/QUIC, ICMP and anything a VM or container sends through the host.

| Allowed while armed | Why |
|---|---|
| any traffic on the tunnel interface | the point of the VPN |
| TCP 443 (or the profile's port) to the VPN server's resolved IPs | the tunnel's own control channel + redialing |
| DHCP (UDP 67/68) | keep the link's lease |
| DNS (UDP/TCP 53) | resolve the VPN server; documented as the one allowed side-channel |
| platform-specific: certificate revocation fetch for the VPN service only (Windows: `SstpSvc`/`CryptSvc` on TCP 80) | SSTP validates the server certificate on every connect |
| host ↔ VM switch (Windows: `vEthernet (WSL*)`) | local only, never leaves the laptop |

Nothing else: no LAN, no printers over the network, no captive portals. (Captive portal: turn
the VPN off, log in, turn it on.)

The VM/WSL/Docker path is handled explicitly because those packets are filtered at a
different hook (Hyper-V vSwitch on Windows, `forward` chain on Linux): allowed while the
tunnel is up, blocked while it is down. That toggle happens on the terminated/connected
events, so VM traffic has a ~1–2 s exposure window after a drop; the host itself has none
(its default-drop is already in force).

## Reconnecting

`rasdial`/`nmcli` with the stored credential, every `retrySeconds` (10), forever, in a
single loop guarded by a lock file. Each attempt refreshes the server IP allow-rule (the
VPN host may change address). The loop ends only when the tunnel is up or the state becomes
DISARMED.

Credentials: Windows keeps the password DPAPI-encrypted for the user (`%LOCALAPPDATA%`);
NetworkManager stores VPN secrets itself (keyring / `psk-flags`).

## Files and layout (per platform)

| | Windows | Linux |
|---|---|---|
| program | `C:\Program Files\VeroScudo\` | `/usr/lib/veroscudo/` (python package) |
| config | `%ProgramData%\VeroScudo\config.json` | `/etc/veroscudo/config.json` |
| state + log | `%ProgramData%\VeroScudo\state\` | `/var/lib/veroscudo/` (armed flag, server IP - survive reboot), `/run/veroscudo/` (reconnect lock), `/var/log/veroscudo.log` |
| per-user | `%LOCALAPPDATA%\VeroScudo\cred.xml` | – |
| scheduler | Task Scheduler `\VeroScudo\{Connected,Terminated,Watchdog,On,Off,Tray}` | `veroscudo.service` (root) + `veroscudo-boot.service` (root, kill-switch before the network at boot) + `veroscudo-tray.service` (user) |
| firewall | Windows Defender Firewall, group `VeroScudo` + Hyper-V rule `VeroScudo-WSL` | nftables table `inet veroscudo` |

`config.json` (same keys everywhere):

```json
{
  "vpn":          { "profile": "MyVPN", "server": "vpn.example.com", "port": 443, "username": "jdoe" },
  "retrySeconds": 10,
  "vm":           "auto",
  "wifiRecoveryFix": true,
  "updateCheck":  true,
  "lanAllow":     []
}
```

- `vm`: `"auto"` (detect WSL/Docker), `true`, `false`.
- `wifiRecoveryFix` (Windows only): sets `HKLM\SOFTWARE\Microsoft\WcmSvc\EnableBadStateTracking=0`.
  Without it Windows resets the Wi-Fi adapter ~15 s after a tunnel is dialed under the
  kill-switch (WLAN AutoConfig event 4003) and kills the fresh tunnel. Reverted on uninstall.
- `lanAllow`: CIDRs allowed while armed. Empty = strict (recommended).
- `updateCheck`: the tray app asks GitHub for the latest release once, two minutes after it starts, and shows a notice when it is
  newer. Only while the state is *protected* or *off* - never while blocked. HTTPS to `api.github.com`,
  nothing sent but the version in the User-Agent. `false` disables it. No automatic installation.

## Tray app

Reads state only (flag files + the OS's VPN status); every action it offers runs the same
scheduled task / service command the shortcuts use, so the guard logic lives in one place.
Icon = state (Protected / Blocked / Off / Attention), menu = Turn on / Turn off / Status /
Log / Settings / About / Exit. Notifications on state changes only.
