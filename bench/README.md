# ksbench - test your VPN kill-switch

One file, nothing to install. It checks whether a VPN kill-switch - any app, any VPN - really stops your
traffic when the VPN fails, and gives a score from 0 to 100 with a plain verdict:

- **STRONG** (90-100) - keep it.
- **FAIR** (70-89) - acceptable for everyday use, with gaps.
- **POOR** (below 70) - your real traffic got out; change your kill-switch.

It takes about 2-3 minutes. Every step is printed as it happens, and every result as PASS or FAIL.

## How it works

The bench watches your **physical network adapter** (Wi-Fi or Ethernet) and counts every packet that
leaves it to anywhere but the VPN server. The VPN app's own connections are listed but not counted. Meanwhile it:

1. sends test traffic while the VPN is up (DNS, IPv6, UDP, a program bound to the adapter) - **S1-S4**;
2. breaks the VPN on purpose - blocks the VPN server, takes the tunnel down, unplugs the adapter for up
   to 10 s, kills the VPN client - and waits for it to come back - **D1-D5**;
3. tries to get around the kill-switch - a firewall allow rule, killing the kill-switch app - **T1-T2**.

The test traffic goes to documentation addresses (`198.51.100.x`, `2001:db8::x`) that belong to nobody,
so nothing reaches a third party. The exact rules, weights and scoring are in [SCENARIOS.md](SCENARIOS.md).

## Is it safe?

- Nothing is installed, nothing is rebooted, no file of yours is deleted.
- The steady tests (S1-S4) change nothing. The outage and tamper tests run only after you say yes
  (they cut your network for a few seconds at a time). Killing a process always asks first; the bench never
  kills system processes.
- Every change - a firewall rule, a disabled adapter - is written down **before** it is made and undone
  right after the test, also on Ctrl-C. If the window was closed in the middle, run the bench with
  `--restore` (Linux, macOS) or `-Restore` (Windows). A later run refuses to start until that is done.
- Over SSH or Remote Desktop it asks separately before taking the network adapter down.

## Run it

Connect your VPN and its kill-switch first. Turn off split tunnelling for the test.

Both files are attached to every [release](https://github.com/GomelHawk/VeroScudo/releases/latest) on their own -
no VeroScudo needed - with their checksums in `SHA256SUMS.txt`.

**Windows 10 (21H2+) / 11** - download [`ksbench.ps1`](ksbench.ps1), then in PowerShell **as administrator**:

```powershell
powershell -ExecutionPolicy Bypass -File .\ksbench.ps1
```

**Linux** (Python 3.9+, iproute2, iptables or nft) and **macOS** (built-in tools) - download
[`ksbench.py`](ksbench.py), then:

```bash
sudo python3 ksbench.py
```

It asks for the app's name (for the report), whether to run the optional online check, and whether to run
the outage tests. Useful options (Windows names in brackets):

| Option | What it does |
|---|---|
| `--list` (`-List`) | show the scenarios and what each one changes, then exit |
| `--only S1,S2,S3,S4` (`-Only S1,S2,S3,S4`) | run only some tests - these four change nothing |
| `--yes` (`-Yes`) | run the outage tests without asking |
| `--online` / `--no-online` (`-Online` / `-NoOnline`) | answer the online-check question in advance |
| `--app-process NAME` (`-AppProcess NAME`) | experts: the kill-switch app's process for T2 (otherwise T2 is N/A - the bench never asks) |
| `--server ADDR` / `--iface NAME` (`-Server` / `-Iface`) | when the bench cannot find the VPN server or adapter itself |
| `--restore` (`-Restore`) | undo the changes of a run that was interrupted |

The report is also saved as JSON (path printed at the end; on Windows next to the capture files in
`%TEMP%\ksbench\run-<time>`).

## The online check

Optional, on by default, and the bench asks first. Every 2 s it asks Cloudflare (`https://1.1.1.1`) which
address it sees you coming from. If it ever sees your real address instead of the VPN's, the report shows
it. If a leak happens, Cloudflare sees your real address too - say no if you mind. It never changes the score.
