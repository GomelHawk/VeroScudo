# Local tests - Linux

## In a container (no VM, no VPN; CI runs it on every change)

```bash
linux/tests-local/container-test.sh ubuntu:24.04      # or ubuntu:22.04; needs Docker
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
4. **Walk through it** (each line: what you do -> what you must see):
   - tray > Turn VPN on -> *Connecting* notification, then green shield, *VPN protected*
   - `curl -s https://ifconfig.me` -> the VPN's address
   - pull the VM's network cable (VM settings) for a minute -> red shield, *VPN connection lost - traffic blocked*;
     `curl --max-time 5 https://example.com`, `ping -c2 1.1.1.1`, `dig @1.1.1.1 example.com` all fail; plug it back -> green
   - tray > Reconnect VPN -> red while it redials, green again
   - tray > VPN profile > another profile (if you have two) -> stays red until the new one is up
   - disconnect the VPN in Settings > Network -> grey shield, *VPN turned off*, normal network (the "you hung up" reason)
   - tray > Status… / Open log / Settings… (import, make default - asks for your password) / About
   - reboot while on with the VPN server unreachable -> blocked from the first second (`sudo nft list table inet veroscudo`)
   - tray > About > Uninstall… -> everything gone, network normal
5. Paste `veroscudo status`, the end of `/var/log/veroscudo.log` and what you saw into the pull request.

Still to write: a `live.sh` that automates the leak probes of step 4, as `windows/tests-local/Test-Live.ps1` does.
