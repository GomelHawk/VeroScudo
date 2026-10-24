# Local (real-machine) tests — Linux

Not yet written: the Linux backend is a beta that has only been unit-tested. The plan mirrors
`windows/tests-local/`:

1. `offline.sh` — `veroscudo arm` → `nmcli connection down` → `veroscudo on` must redial under the
   kill-switch → `veroscudo disarm`.
2. `live.sh` — block the VPN server with a temporary nft rule, bounce the link, verify 3 minutes of
   total blocking (curl/ping/dns probes, a container probe), then recovery; `off`/`on`; manual
   `nmcli connection down` must disarm (reason user-requested).

Contributions with a log from a real Ubuntu machine are very welcome.
