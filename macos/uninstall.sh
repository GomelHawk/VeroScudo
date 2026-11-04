#!/usr/bin/env bash
# Removes the launchd daemon, the pf anchor, the sudoers rule and the program. Keeps /etc/veroscudo unless --purge.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
launchctl bootout system/com.gomelhawk.veroscudo 2>/dev/null
rm -f /Library/LaunchDaemons/com.gomelhawk.veroscudo.plist /etc/sudoers.d/veroscudo
pfctl -a com.apple/250.VeroScudo -F all 2>/dev/null
[ -f /var/run/veroscudo-pf.token ] && pfctl -X "$(cat /var/run/veroscudo-pf.token)" 2>/dev/null && rm -f /var/run/veroscudo-pf.token
rm -rf /var/run/veroscudo
rm -f /var/lib/veroscudo/armed.flag      # a later reinstall must not start armed
[ "${1:-}" = "--purge" ] && rm -rf /etc/veroscudo /var/lib/veroscudo
# the program: /opt/veroscudo (1.3.1+), /usr/local/lib/veroscudo (1.3.0 alpha); the /usr/local/bin link only if it is ours
case "$(readlink /usr/local/bin/veroscudo 2>/dev/null)" in */veroscudo/*) rm -f /usr/local/bin/veroscudo ;; esac
rm -rf /opt/veroscudo /usr/local/lib/veroscudo
echo "UNINSTALL OK"
