# Testing VeroScudo

## Layers

| Layer | Where | Runs in CI | What it pins |
|---|---|---|---|
| Unit (Windows) | `windows/tests/` (Pester 5, on Windows PowerShell 5.1) | yes | config defaults/validation, the decision table, forged-event handling, the WFP filter set (every permit scoped, DNS only while down, per-tunnel-type server ports), struct layout of the native helper, sync/fail-closed, profile switching, lock, update URLs |
| Unit (Linux/macOS) | `linux/tests/` (pytest) | yes | same, plus the rendered nftables and pf rulesets, tunnel-interface checks, the guard's event handling and switching with fakes |
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
   - new in 1.1: a firewall *allow* rule for the probing PowerShell (1.0 leaked through rules like it),
     TCP 53 and IPv6 probes, a DNS query to the LAN resolver while protected (must fail), a forged
     RAS 631 while up (must be ignored), the firewall default forced to Allow mid-outage, all filters
     deleted mid-outage (watchdog must restore them within 30 s), a profile switch when 2+ are configured.

Expected: every leak probe `False` while blocked, `dns=True` (documented), filters present
throughout, all phases `PASS`.

## Record of the last full run

2026-10-26, Windows 11 (26200), SSTP profile, 1.1.0 (WFP engine) installed over 1.0.0, through the real tasks:

```
Pester (Windows PowerShell 5.1)                  90 passed
Test-Offline  1 hang-up disarms                  PASS  (2.1 s)
              2 redial under kill-switch         PASS  (77 leak probes while down, 0 leaks; up in 2.8 s)
Test-Live     0 no DNS leak while protected      PASS
              0 forged 631 ignored               PASS
              1 strict outage                    PASS  (3 min; tcp443/80/53, ping, WSL all False every 15 s - from a
                                                        PowerShell with its own firewall allow rule; firewall default
                                                        forced to Allow mid-outage; watchdog triggered)
              2 self-heal                        PASS  (all filters deleted -> restored in 2 s)
              1 auto-recover                     PASS  (tunnel back 6 s after the server was reachable)
              4 off / 4 on / 5 manual disconnect / 5 on   PASS
WSL while off                                    301 (internet) - after the fix below
Test-Upgrade  v1.0.0 (GitHub) -> 1.1.0, twice    PASS  (49 checks; no VPN drop; config converted and restored)
```

The IPv6 probe was `False` even while off: that network has no IPv6, so IPv6 blocking is covered by the
unit tests only.

Bugs this run found (all fixed before the record above): the 1.0 -> 1.1 migration removed the old allow
rules before restoring the firewall default (the VPN dropped once, RAS 829); the filters waited for a DNS
lookup that the filters in force blocked (23 s idle after a drop, 12 s after a reconnect); a crash when no DNS
server was known yet; one watchdog started per minute because the launcher returned at once; a disarm could
finish after a parallel re-arm and leave it without filters; the saved "original" WSL setting could be
VeroScudo's own Block, leaving WSL offline while VeroScudo was off. `Test-Offline`/`Test-Reconnect` raced the
always-on watchdog and were rewritten to drive the scheduled tasks.

### 1.0.0 run

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
