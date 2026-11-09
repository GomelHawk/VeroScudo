# Local tests - Linux

## In a container (no VM, no VPN; CI runs it on every change)

```bash
linux/tests-local/container-test.sh ubuntu:24.04      # or ubuntu:22.04 / ubuntu:26.04; needs Docker
```

A privileged Ubuntu container with systemd and NetworkManager: `install.sh --yes --profile …`, status as the user,
On through the sudo rule (armed, the table in force, nothing leaves), the daemon taking the redial over, a Settings change
picked up without a restart, an upgrade while armed, Off (network back), uninstall and `--purge`. The kill-switch lives
in the container's own network namespace - the host is not touched. What it cannot show: the tray on a real desktop and
a real VPN dropping and coming back.

`render_rulesets.py nft|pf DIR` writes every ruleset VeroScudo can produce; CI feeds them to `nft -c` and `pfctl -n`.

## On a real desktop: an Ubuntu VM (the end-to-end test)

A VM keeps the kill-switch away from the machine you work on: blocking the VM blocks nothing else.

1. **VM**: Ubuntu 24.04 Desktop in Hyper-V (*Quick Create* offers it), VirtualBox or VMware; NAT networking is fine.
2. **VPN**: create the connection in Settings > Network > VPN and connect once by hand. An SSTP server works with
   `sudo apt install network-manager-sstp-gnome`; OpenVPN / WireGuard configs import there too.
3. **Install**: copy the release archive (or the repo) into the VM, `cd VeroScudo-linux && sudo ./install.sh`, pick the
   connection. The shield appears in the top bar.
4. **Run the automated test** for the active profile (`sudo veroscudo use <profile>` first): `sudo linux/tests-local/live.sh`
   in the VM's own window (while armed, inbound SSH is blocked; over SSH use `sudo -b linux/tests-local/live.sh` and read
   `~/veroscudo-live.log` afterwards). About 6 minutes: On, Reconnect, the VPN dying (its process killed; WireGuard: its
   interface removed), the network card down for 30 s (`DROP_SECONDS`), your own hang-up, On and Off - with a probe every
   2 s (exit address, direct ping and DNS to an address the kill-switch does not allow). NetworkManager VPNs need nothing
   from you. A Hiddify profile needs you in Hiddify: the script says `>>> DO NOW: ...` (connect, disconnect, start it
   again) and waits until it sees the result - run that one in the VM's window. It ends with PASS or FAIL and the leaks.
5. **By hand** (what the script cannot see; each line: what you do -> what you must see):
   - tray > Turn VPN on -> *Connecting* notification, then green shield, *VPN protected*; red while blocked, grey when off
   - tray > VPN profile > another profile (if you have two) -> stays red until the new one is up
   - tray > Status… / Open log / Statistics… / Settings… (import, make default - asks for your password) / About
   - reboot while on with the VPN server unreachable -> blocked from the first second (`sudo nft list table inet veroscudo`)
   - tray > About > Uninstall… -> everything gone, network normal
6. Paste the end of `~/veroscudo-live.log`, the end of `/var/log/veroscudo.log` and what you saw into the pull request.
