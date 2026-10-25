#!/usr/bin/env bash
# VeroScudo installer for Linux (NetworkManager + nftables). Run with sudo from the linux/ folder.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="${SUDO_USER:-$(logname)}"
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
for bin in nft nmcli python3; do command -v "$bin" >/dev/null || { echo "missing: $bin (apt install nftables network-manager python3)"; exit 1; }; done

python3 -m pip install --quiet --break-system-packages "$HERE" 2>/dev/null || python3 -m pip install --quiet "$HERE"
install -d -m 755 -o root -g root /etc/veroscudo /usr/share/veroscudo/icons /var/lib/veroscudo
if [ ! -f /etc/veroscudo/config.json ]; then
  echo "NetworkManager connections:"; nmcli -t -f NAME,TYPE connection show | sed 's/^/  /'
  read -r -p "VPN connection name: " PROFILE
  read -r -p "VPN server host name: " SERVER
  read -r -p "VPN port [443]: " PORT; PORT="${PORT:-443}"
  read -r -p "VPN transport, tcp or udp [tcp]: " PROTO; PROTO="${PROTO:-tcp}"
  # built by Python so the answers are JSON-escaped, then validated with the guard's own rules before it is written
  PROFILE="$PROFILE" SERVER="$SERVER" PORT="$PORT" PROTO="$PROTO" python3 - <<'PY'
import json, os
from veroscudo.config import Config
cfg = {"profiles": [{"profile": os.environ["PROFILE"], "server": os.environ["SERVER"], "port": int(os.environ["PORT"]),
                     "protocol": os.environ["PROTO"]}],
       "activeProfile": os.environ["PROFILE"], "retrySeconds": 10, "vm": "auto", "updateCheck": True, "lanAllow": []}
text = json.dumps(cfg, indent=2)
Config.from_text(text)
open("/etc/veroscudo/config.json", "w").write(text + "\n")
PY
  chmod 644 /etc/veroscudo/config.json
  echo "config written: /etc/veroscudo/config.json  (add more profiles to its \"profiles\" list)"
else
  python3 -c 'from veroscudo.config import Config; Config.load()' || { echo "config.json is not valid - fix it first"; exit 1; }
fi
for s in protected blocked off attention; do
  src="$HERE/../assets/icons/png/$s-48.png"
  [ -f "$src" ] && install -m 644 "$src" "/usr/share/veroscudo/icons/$s.png"
done
install -m 644 "$HERE/systemd/veroscudo.service" /etc/systemd/system/veroscudo.service
install -m 644 "$HERE/systemd/veroscudo-boot.service" /etc/systemd/system/veroscudo-boot.service
# an armed flag left in /run by an older layout (lost on reboot): move it, or the upgrade would silently disarm
for f in armed.flag server.ip; do
  [ -f "/run/veroscudo/$f" ] && [ ! -f "/var/lib/veroscudo/$f" ] && mv "/run/veroscudo/$f" "/var/lib/veroscudo/$f"
done
# the user's own unit: written by the user, not by root (root following a symlink planted in a home folder could be
# steered into writing anywhere)
sudo -u "$USER_NAME" install -d "$USER_HOME/.config/systemd/user"
sudo -u "$USER_NAME" install -m 644 "$HERE/systemd/veroscudo-tray.service" "$USER_HOME/.config/systemd/user/veroscudo-tray.service"
cat > /etc/sudoers.d/veroscudo.tmp <<EOF
$USER_NAME ALL=(root) NOPASSWD: /usr/local/bin/veroscudo on, /usr/local/bin/veroscudo off, /usr/local/bin/veroscudo use *
EOF
visudo -cf /etc/sudoers.d/veroscudo.tmp >/dev/null && mv /etc/sudoers.d/veroscudo.tmp /etc/sudoers.d/veroscudo
chmod 440 /etc/sudoers.d/veroscudo
systemctl daemon-reload
systemctl enable veroscudo.service veroscudo-boot.service
systemctl restart veroscudo.service     # an upgrade must run the new code; the armed flag survives (StateDirectory)
# a running tray keeps the old code too: restart it if it is running (no-op otherwise)
sudo -u "$USER_NAME" XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" systemctl --user daemon-reload 2>/dev/null || true
sudo -u "$USER_NAME" XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" systemctl --user try-restart veroscudo-tray.service 2>/dev/null || true
echo
echo "INSTALL OK. Tray: systemctl --user enable --now veroscudo-tray   (needs gir1.2-ayatanaappindicator3-0.1)"
echo "Turn on:   sudo veroscudo on      Turn off:   sudo veroscudo off      Status: veroscudo status"
echo "Profiles:  veroscudo profiles     Switch:     sudo veroscudo use <profile>"
