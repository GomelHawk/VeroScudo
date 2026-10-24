#!/usr/bin/env bash
# VeroScudo installer for Linux (NetworkManager + nftables). Run with sudo from the linux/ folder.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="${SUDO_USER:-$(logname)}"
for bin in nft nmcli python3; do command -v "$bin" >/dev/null || { echo "missing: $bin (apt install nftables network-manager python3)"; exit 1; }; done

python3 -m pip install --quiet --break-system-packages "$HERE" 2>/dev/null || python3 -m pip install --quiet "$HERE"
install -d /etc/veroscudo /usr/share/veroscudo/icons
if [ ! -f /etc/veroscudo/config.json ]; then
  echo "NetworkManager connections:"; nmcli -t -f NAME,TYPE connection show | sed 's/^/  /'
  read -r -p "VPN connection name: " PROFILE
  read -r -p "VPN server host name: " SERVER
  read -r -p "VPN port [443]: " PORT; PORT="${PORT:-443}"
  read -r -p "VPN transport, tcp or udp [tcp]: " PROTO; PROTO="${PROTO:-tcp}"
  cat > /etc/veroscudo/config.json <<JSON
{
  "vpn": { "profile": "$PROFILE", "server": "$SERVER", "port": $PORT, "protocol": "$PROTO" },
  "retrySeconds": 10,
  "vm": "auto",
  "lanAllow": []
}
JSON
  echo "config written: /etc/veroscudo/config.json"
fi
for s in protected blocked off attention; do
  src="$HERE/../assets/icons/png/$s-48.png"
  [ -f "$src" ] && install -m 644 "$src" "/usr/share/veroscudo/icons/$s.png"
done
install -m 644 "$HERE/systemd/veroscudo.service" /etc/systemd/system/veroscudo.service
install -m 644 "$HERE/systemd/veroscudo-boot.service" /etc/systemd/system/veroscudo-boot.service
# an armed flag left in /run by an older layout (lost on reboot): move it, or the upgrade would silently disarm
install -d /var/lib/veroscudo
for f in armed.flag server.ip; do
  [ -f "/run/veroscudo/$f" ] && [ ! -f "/var/lib/veroscudo/$f" ] && mv "/run/veroscudo/$f" "/var/lib/veroscudo/$f"
done
install -d "/home/$USER_NAME/.config/systemd/user"
install -m 644 -o "$USER_NAME" "$HERE/systemd/veroscudo-tray.service" "/home/$USER_NAME/.config/systemd/user/veroscudo-tray.service"
echo "$USER_NAME ALL=(root) NOPASSWD: /usr/local/bin/veroscudo on, /usr/local/bin/veroscudo off" > /etc/sudoers.d/veroscudo
chmod 440 /etc/sudoers.d/veroscudo
systemctl daemon-reload
systemctl enable veroscudo.service veroscudo-boot.service
systemctl restart veroscudo.service     # an upgrade must run the new code; the armed flag survives (RuntimeDirectoryPreserve)
# a running tray keeps the old code too: restart it if it is running (no-op otherwise)
sudo -u "$USER_NAME" XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" systemctl --user daemon-reload 2>/dev/null || true
sudo -u "$USER_NAME" XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" systemctl --user try-restart veroscudo-tray.service 2>/dev/null || true
echo
echo "INSTALL OK. Tray: systemctl --user enable --now veroscudo-tray   (needs gir1.2-ayatanaappindicator3-0.1)"
echo "Turn on:   sudo veroscudo on      Turn off:   sudo veroscudo off      Status: veroscudo status"
