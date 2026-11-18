# ksbench scenarios and scoring

Every test watches the **physical network adapter** (Wi-Fi, Ethernet) for outbound packets. A packet
counts as a **leak** when it goes to a public address that is not the VPN server. Not counted: the VPN
server itself, DHCP, IPv6 neighbour discovery and router solicitation, and the local network (private
ranges, link-local, multicast, CGNAT). A packet to port 53 or 853 (DNS, DNS over TLS) is a **DNS leak**,
whatever its address, including a router on the local network.

The bench's own probe targets are documentation addresses (`198.51.100.0/24`, `2001:db8::/32`). They
belong to nobody, so no probe ever reaches a third party, and a probe on the physical adapter is a leak
by definition. The DNS probes look up random names under `example.com`.

## Scenarios

| ID | Group | Weight | Scenario | Pass when |
|---|---|---|---|---|
| S1 | steady | 15 | DNS stays in the tunnel | No DNS packet on the physical adapter during 2 look-ups via the system resolver and direct DNS queries (UDP, TCP, IPv6). |
| S2 | steady | 10 | IPv6 stays in the tunnel | No IPv6 leak during UDP, TCP and ping over IPv6. N/A when the network has no IPv6. |
| S3 | steady | 15 | A program bound to the physical adapter cannot get out | No leak from UDP/TCP sockets bound to the physical adapter (`SO_BINDTODEVICE`, `IP_BOUND_IF`, `IP_UNICAST_IF`). Route-only kill-switches fail this. |
| S4 | steady | 5 | UDP/QUIC, STUN and ping stay in the tunnel | No leak of a QUIC-sized UDP packet, a STUN request or a ping. |
| D1 | outage | 20 | VPN server unreachable | A firewall rule blocks the VPN server for the hold time; no leak until the VPN is back. |
| D2 | outage | 15 | VPN client process killed | The process that owns the VPN connection is killed; no leak until the VPN is back. N/A when the VPN runs in the kernel or inside the OS. |
| D3 | outage | 15 | Tunnel adapter goes down | The tunnel adapter is taken down; no leak until the VPN is back. N/A for Windows' own VPN client. |
| D4 | outage | 20 | Physical link drops and comes back | The physical adapter is taken down for up to 10 s and brought back; no leak until the VPN is back. |
| D5 | outage | 10 | No DNS leak during any outage | No DNS packet on the physical adapter during any of D1-D4, T1, T2. |
| T1 | tamper | 15 | Another program adds a firewall allow rule | A firewall allow rule for the probe addresses is added, then the VPN server is blocked; no leak. |
| T2 | tamper | 10 | The kill-switch app is killed | The process you name is killed, then the VPN server is blocked; no leak. Skipped when you name no process. |

During every outage test the bench sends, every 250 ms, UDP and TCP to `198.51.100.7:443` (and
`2001:db8::7` with IPv6), and every 2 s a DNS look-up of a random name. Background traffic of any app
counts the same way. The window runs from the fault until the VPN is back (plus 1.5 s), so a leak while
reconnecting counts.

A fault that never takes the tunnel down (for example a WireGuard tunnel that keeps its routes while the
server is unreachable) makes the test **N/A**: nothing could leak, so the kill-switch was not tested.

## Score

- Score = points of passed tests / points of tests that ran x 100. N/A, skipped, not run and invalid
  tests do not count either way. The report always shows how many points ran.
- A leak in a critical test (S1, S2, S3, D1, D2, D3, D4, T1, T2) **caps the score at 40**: a
  kill-switch that leaks when the VPN fails has failed its one job.
- Verdict: **STRONG** 90-100, **FAIR** 70-89, **POOR** below 70, **UNCLEAR** when less than half of all
  points ran.
- **Invalid**: the online check saw your real IP address but the capture saw no leak. Traffic left
  through an adapter the bench does not watch; name it with `--iface` / `-Iface`.

## Time

The steady tests take about 15 s. The outage and tamper tests have a 150 s budget together; a test that
would not fit is reported as *not run*. They run in this order, most important first: D1, D3, D4, T1,
D2, T2. A typical run takes about 2 minutes.

## Online check (optional)

On by default, but the bench asks first (`--online` / `--no-online` skip the question; without a
terminal it is skipped). Every 2 s the bench asks `https://1.1.1.1/cdn-cgi/trace` (and the IPv6
address) which address it sees. An answer while the VPN is up records a VPN exit address; an answer with
another address while the VPN is down is your real address - it is shown in the report. It never adds
or removes points.
