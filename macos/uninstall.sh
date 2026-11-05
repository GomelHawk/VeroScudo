#!/usr/bin/env bash
# Removes VeroScudo from this Mac: the launchd guard, the pf anchor, the menu-bar app (login item and /Applications), the
# sudo rule and the program.
#     sudo /opt/veroscudo/uninstall.sh            keeps /etc/veroscudo/config.json for a later install
#     sudo /opt/veroscudo/uninstall.sh --purge    also the config, the state and the log
# Also run by menu bar > About VeroScudo > Uninstall…. Your VPN services are not touched; a connected VPN stays up.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run it with sudo: sudo $0"; exit 1; }
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

launchctl bootout system/com.gomelhawk.veroscudo 2>/dev/null
rm -f /Library/LaunchDaemons/com.gomelhawk.veroscudo.plist /etc/sudoers.d/veroscudo
pfctl -a com.apple/250.VeroScudo -F all 2>/dev/null      # the kill-switch: the network is normal from here on
[ -f /var/run/veroscudo-pf.token ] && pfctl -X "$(cat /var/run/veroscudo-pf.token)" 2>/dev/null
rm -f /var/run/veroscudo-pf.token /var/run/veroscudo/*.lock /var/run/veroscudo/*.marker
rmdir /var/run/veroscudo 2>/dev/null
rm -f /var/lib/veroscudo/armed.flag                       # a later install must not start armed

# the menu-bar app: every signed-in user's copy, the login item, the app
for uid in $(ps -axo uid=,comm= | awk '$2 ~ /loginwindow$/ {print $1}' | sort -u); do
  launchctl bootout "gui/$uid/com.gomelhawk.veroscudo.tray" 2>/dev/null
done
pkill -f 'bin/veroscudo-tray' 2>/dev/null
rm -f /Library/LaunchAgents/com.gomelhawk.veroscudo.tray.plist /etc/paths.d/veroscudo
[ -d /Applications/VeroScudo.app ] && rm -rf -- /Applications/VeroScudo.app

# the program: /opt/veroscudo (1.3.1+), /usr/local/lib/veroscudo (1.3.0 alpha); the /usr/local/bin link only if it is ours
case "$(readlink /usr/local/bin/veroscudo 2>/dev/null)" in */veroscudo/*) rm -f /usr/local/bin/veroscudo ;; esac
rm -rf -- /opt/veroscudo /usr/local/lib/veroscudo
if [ "$PURGE" -eq 1 ]; then
  rm -rf -- /etc/veroscudo /var/lib/veroscudo
  rm -f /var/log/veroscudo.log /var/log/veroscudo.log.1 /var/log/veroscudo.out
fi
echo "UNINSTALL OK$([ "$PURGE" -eq 1 ] && echo ' (config, state and log removed too)' || echo ' - /etc/veroscudo/config.json kept (--purge removes it)')"
echo "Your own menu-bar choices stay in ~/.config/veroscudo (a few bytes) - delete that folder if you like."
