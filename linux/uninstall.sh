#!/usr/bin/env bash
# Removes VeroScudo: the service, the kill-switch table, the tray (autostart and menu entry), the sudo rule and the program.
#     sudo /opt/veroscudo/uninstall.sh            keeps /etc/veroscudo/config.json for a later install
#     sudo /opt/veroscudo/uninstall.sh --purge    also the config, the state and the log
# Also run by tray > About > Uninstall… (through pkexec). Your VPN connections are not touched; a connected VPN stays up.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run it with sudo: sudo $0"; exit 1; }
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
PREFIX=/opt/veroscudo

systemctl disable --now veroscudo.service veroscudo-boot.service >/dev/null 2>&1
rm -f /etc/systemd/system/veroscudo.service /etc/systemd/system/veroscudo-boot.service /etc/sudoers.d/veroscudo
nft delete table inet veroscudo 2>/dev/null        # the kill-switch: the network is normal from here on
rm -f /run/veroscudo/*.lock /run/veroscudo/*.marker
rmdir /run/veroscudo 2>/dev/null
rm -f /var/lib/veroscudo/armed.flag                # a later install must not start armed

# the tray: autostart, menu entry, every running copy (and the per-user unit of 1.3 and older)
rm -f /etc/xdg/autostart/veroscudo-tray.desktop /usr/share/applications/veroscudo.desktop
pkill -f 'bin/veroscudo-tray|-m veroscudo\.tray' 2>/dev/null
USER_NAME="${SUDO_USER:-}"
[ -z "$USER_NAME" ] && [ -n "${PKEXEC_UID:-}" ] && USER_NAME="$(getent passwd "$PKEXEC_UID" | cut -d: -f1)"
if [ -n "$USER_NAME" ] && [ "$USER_NAME" != root ]; then
  uid="$(id -u "$USER_NAME")"
  sudo -u "$USER_NAME" env "XDG_RUNTIME_DIR=/run/user/$uid" systemctl --user disable veroscudo-tray.service >/dev/null 2>&1
  home="$(getent passwd "$USER_NAME" | cut -d: -f6)"
  [ -f "$home/.config/systemd/user/veroscudo-tray.service" ] && sudo -u "$USER_NAME" rm -f "$home/.config/systemd/user/veroscudo-tray.service"
fi

# the program (and the pip copy of 1.3 and older)
case "$(readlink /usr/local/bin/veroscudo 2>/dev/null)" in "$PREFIX"/*) rm -f /usr/local/bin/veroscudo ;; esac
if python3 -m pip show veroscudo >/dev/null 2>&1; then
  python3 -m pip uninstall -y -q --break-system-packages veroscudo 2>/dev/null || python3 -m pip uninstall -y -q veroscudo
fi
rm -rf -- /opt/veroscudo /usr/share/veroscudo
if [ "$PURGE" -eq 1 ]; then
  rm -rf -- /etc/veroscudo /var/lib/veroscudo
  rm -f /var/log/veroscudo.log /var/log/veroscudo.log.1
fi
systemctl daemon-reload
echo "UNINSTALL OK$([ "$PURGE" -eq 1 ] && echo ' (config, state and log removed too)' || echo ' - /etc/veroscudo/config.json kept (--purge removes it)')"
echo "Your own tray choices stay in ~/.config/veroscudo (a few bytes) - delete that folder if you like."
