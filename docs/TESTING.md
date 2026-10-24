# Testing VeroScudo

## Layers

| Layer | Where | Runs in CI | What it pins |
|---|---|---|---|
| Unit (Windows) | `windows/tests/` (Pester 5) | yes | config defaults/validation, the decision table, the allow-list shape, flag/log plumbing |
| Unit (Linux) | `linux/tests/` (pytest) | yes | same, plus the rendered nftables ruleset (policy drop, scoped accepts, forward chain) |
| Lint | PSScriptAnalyzer, ruff, shellcheck | yes | |
| Real machine | `windows/tests-local/` | **no** | the actual firewall, VPN and scheduled tasks |

CI cannot dial a VPN or change a firewall. The real-machine scripts are the proof; run them
on your laptop with the guard installed and paste the verdict into your PR.

## Real-machine scripts (Windows)

Run from an elevated PowerShell with the VPN connected and the credential stored.

1. **`Test-Offline.ps1`** (~1 min) - arm → hang up → redial under the kill-switch → disarm.
   First thing to run after any change: proves the redial itself works while blocked.
2. **`Test-Reconnect.ps1`** (~2 min) - adds a 60 s watch of the fresh tunnel (Windows + WSL
   traffic) and reports WLAN 4003 events (Wi-Fi resets).
3. **`Test-Live.ps1`** (~7 min) - end-to-end through the real scheduled tasks:
   - server made unreachable by a temporary block rule + Wi-Fi bounce → RAS 829 →
     `Terminated` task → redial loop; **3 minutes** of probes every 12 s (TCP 443, TCP 80,
     ICMP, WSL, DNS) with the `Watchdog` task triggered half-way;
   - server unblocked → must reconnect by itself with the kill-switch still on;
   - `Off` task → raw internet; `On` task → protected;
   - `rasdial /disconnect` (same as the Settings UI, RAS 631) → disarmed; `On` → protected.

Expected: every leak probe `False` while blocked, `dns=True` (documented), `outbound=Block`
throughout, all phases `PASS`.

## Record of the last full run

2026-10-23, Windows 11 25H2, SSTP profile, strict mode, through the real tasks:

```
=== VERDICT
   1 strict outage        PASS   (3 min, 12 failed redials, tcp443/tcp80/ping/wsl all False every 12 s, watchdog x2 no-op)
   1 auto-recover         PASS   (reconnected on attempt 13, ~10 s after the server came back; kill-switch stayed on)
   2 off / 2 on           PASS
   3 manual disconnect    PASS   (RAS 631 -> disarmed)   3 on  PASS
   WLAN 4003 events: none
```

(Phase numbering in the current script differs slightly from that run; the content is the same.)

## Things that bit us, so you don't have to

- A 5-second `netsh wlan` reconnect does **not** drop an SSTP tunnel; to produce a real drop,
  block the server first.
- `rasdial <profile>` without credentials fails with RAS 628 after the link is up - the
  password saved by the Settings app is not used. Hence `Set-VpnCredential.ps1`.
- Disabling the Wi-Fi adapter to simulate a failure took 40 s to come back; don't.
- Never run a live test before the offline test passes: in the first attempt the whole laptop
  stayed blocked because the redial could not succeed under the kill-switch.
