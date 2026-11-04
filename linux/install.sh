#!/usr/bin/env bash
# VeroScudo installer for Linux (NetworkManager + nftables). Run with sudo from the linux/ folder.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="${SUDO_USER:-$(logname)}"
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
for bin in nft nmcli python3; do command -v "$bin" >/dev/null || { echo "missing: $bin (apt install nftables network-manager python3)"; exit 1; }; done
python3 -m pip --version >/dev/null 2>&1 || { echo "missing: pip for python3 (apt install python3-pip)"; exit 1; }

python3 -m pip install --quiet --break-system-packages "$HERE" 2>/dev/null || python3 -m pip install --quiet "$HERE"
# where pip put the command: /usr/local/bin on Debian/Ubuntu, /usr/bin on Arch - the units and the sudoers rule name it.
# It runs as root from there, so the file and its folder must be root's and closed to others (same rule as macOS).
BIN="$(command -v veroscudo || true)"
case "$BIN" in /*) ;; *) echo "veroscudo installed, but no 'veroscudo' command on root's PATH - is pip's bin folder on PATH?"; exit 1 ;; esac
PY3="$(command -v python3)"
for f in "$BIN" "$(dirname "$BIN")" "$PY3"; do
  if [ "$(stat -L -c %u "$f")" != "0" ] || [ -n "$(find -L "$f" -maxdepth 0 -perm /022)" ]; then
    echo "$f is not root-owned and closed to others - refusing (root would run a program others can replace)"; exit 1
  fi
done
case "$BIN$PY3" in *[!A-Za-z0-9/._-]*) echo "unexpected characters in '$BIN' / '$PY3' - refusing"; exit 1 ;; esac
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
# icons: next to this script in the release archive (VeroScudo-linux/assets), one level up in a git checkout
ICONS=""
for d in "$HERE/assets/icons/png" "$HERE/../assets/icons/png"; do [ -f "$d/protected-48.png" ] && { ICONS="$d"; break; }; done
[ -n "$ICONS" ] || echo "WARNING: tray icons not found (assets/icons/png) - the tray will use a generic icon"
for s in protected blocked off attention; do
  [ -n "$ICONS" ] && install -m 644 "$ICONS/$s-48.png" "/usr/share/veroscudo/icons/$s.png"
done
# the units name the resolved command (the files in systemd/ carry the Debian/Ubuntu path)
sed "s#^ExecStart=/usr/local/bin/veroscudo #ExecStart=$BIN #" "$HERE/systemd/veroscudo.service" > /etc/systemd/system/veroscudo.service
sed "s#^ExecStart=/usr/local/bin/veroscudo #ExecStart=$BIN #" "$HERE/systemd/veroscudo-boot.service" > /etc/systemd/system/veroscudo-boot.service
chmod 644 /etc/systemd/system/veroscudo.service /etc/systemd/system/veroscudo-boot.service
grep -q "^ExecStart=$BIN " /etc/systemd/system/veroscudo.service || { echo "unit template did not take the resolved path"; exit 1; }
# an armed flag left in /run by an older layout (lost on reboot): move it, or the upgrade would silently disarm
for f in armed.flag server.ip; do
  [ -f "/run/veroscudo/$f" ] && [ ! -f "/var/lib/veroscudo/$f" ] && mv "/run/veroscudo/$f" "/var/lib/veroscudo/$f"
done
# the user's own unit: written by the user, not by root (root following a symlink planted in a home folder could be
# steered into writing anywhere)
sudo -u "$USER_NAME" install -d "$USER_HOME/.config/systemd/user"
sed "s#^ExecStart=/usr/bin/python3 #ExecStart=$PY3 #" "$HERE/systemd/veroscudo-tray.service" | sudo -u "$USER_NAME" tee "$USER_HOME/.config/systemd/user/veroscudo-tray.service" > /dev/null
cat > /etc/sudoers.d/veroscudo.tmp <<EOF
$USER_NAME ALL=(root) NOPASSWD: $BIN on, $BIN off, $BIN reconnect, $BIN use *
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
