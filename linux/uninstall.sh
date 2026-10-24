#!/usr/bin/env bash
# Removes the service, the tray autostart, the sudoers rule and the nftables table. Keeps /etc/veroscudo unless --purge.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
USER_NAME="${SUDO_USER:-$(logname 2>/dev/null)}"
if [ -n "$USER_NAME" ]; then
  sudo -u "$USER_NAME" XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" systemctl --user disable --now veroscudo-tray.service 2>/dev/null
  rm -f "/home/$USER_NAME/.config/systemd/user/veroscudo-tray.service"
fi
systemctl disable --now veroscudo.service veroscudo-boot.service 2>/dev/null
rm -f /etc/systemd/system/veroscudo.service /etc/systemd/system/veroscudo-boot.service /etc/sudoers.d/veroscudo
nft delete table inet veroscudo 2>/dev/null
rm -rf /run/veroscudo
rm -f /var/lib/veroscudo/armed.flag      # a later reinstall must not start armed
[ "${1:-}" = "--purge" ] && rm -rf /etc/veroscudo /usr/share/veroscudo /var/lib/veroscudo
python3 -m pip uninstall -y --break-system-packages veroscudo 2>/dev/null || python3 -m pip uninstall -y veroscudo
systemctl daemon-reload
echo "UNINSTALL OK"
