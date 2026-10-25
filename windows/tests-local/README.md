# Local (real-machine) tests — Windows

These scripts exercise the real thing: your VPN, your firewall, your Wi-Fi. They cannot run in
CI. Each restores the machine in a `finally` block, but expect the VPN (and, while the
kill-switch is on, all network traffic) to be interrupted for the stated time.

Run from an **elevated** PowerShell, with the VPN connected and the guard installed
(`Install.ps1`, credential stored with `Set-VpnCredential.ps1`):

| Script | What it proves | Disruption |
|---|---|---|
| `Test-Offline.ps1` | through the real tasks: manual hang-up (RAS 631) disarms; the On task redials **under the kill-switch** with the stored credential - leak probes every second until the tunnel is up. Ends protected. Run this first after any change to the core. | ~30 s |
| `Test-Reconnect.ps1` | `Test-Offline.ps1`, then watches the fresh tunnel for 60 s (Windows + WSL traffic). Catches the Wi-Fi reset problem (`docs/ARCHITECTURE.md`, `wifiRecoveryFix`). | ~2 min |
| `Test-Upgrade.ps1` | installs the previous GitHub release, then this checkout over it twice: one tray running (the new one), installed files and icons match the checkout (no stale or nested folders), tasks registered, VPN on/off state untouched, no missing-asset warnings. **Required before every release.** | none (tray restarts) — ends with this checkout installed |
| `Test-Live.ps1` | **end-to-end through the real scheduled tasks**: no DNS leak while protected, forged RAS 631 ignored, link failure, 3-minute strict outage with the VPN server unreachable (+ a firewall-default reset + a watchdog run), filters deleted and self-healed, auto-recovery, profile switch (2+ profiles), Off/On, manual disconnect (RAS 631). Leak probes every 12 s: TCP 443/80/53, IPv6, ICMP, WSL - from a PowerShell that has its own firewall *allow* rule. | ~10 min |

Logs land in `%ProgramData%\VeroScudo\state\*.log`. Paste the `VERDICT` block into your PR.

Never test a reconnect path by breaking the live link before `Test-Offline.ps1` passes.

The scripts drive the **installed** guard through its scheduled tasks and never call the module's actions next to it: the
watchdog loop and the event tasks run all the time and would race a script that arms, disarms or redials by itself.
