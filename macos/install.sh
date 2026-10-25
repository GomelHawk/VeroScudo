#!/usr/bin/env bash
# VeroScudo installer for macOS - ALPHA (pf + scutil). Run with sudo from the macos/ folder.
# Uses the shared Python guard from ../linux in its own venv; the launchd daemon keeps the kill-switch and redials.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ "$(uname -s)" = "Darwin" ] || { echo "this installer is for macOS"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="${SUDO_USER:-$(stat -f %Su /dev/console)}"
PREFIX=/usr/local/lib/veroscudo
command -v python3 >/dev/null || { echo "missing: python3 (xcode-select --install)"; exit 1; }

install -d -m 755 -o root -g wheel "$PREFIX" /etc/veroscudo /var/lib/veroscudo /usr/local/bin
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --quiet --upgrade "$HERE/../linux"
ln -sf "$PREFIX/venv/bin/veroscudo" /usr/local/bin/veroscudo

if [ ! -f /etc/veroscudo/config.json ]; then
  echo "macOS VPN services:"; scutil --nc list | sed 's/^/  /'
  read -r -p "VPN service name (as in System Settings > VPN): " PROFILE
  read -r -p "VPN server host name: " SERVER
  read -r -p "VPN port [4500 for IKEv2]: " PORT; PORT="${PORT:-4500}"
  read -r -p "VPN transport, tcp or udp [udp]: " PROTO; PROTO="${PROTO:-udp}"
  PROFILE="$PROFILE" SERVER="$SERVER" PORT="$PORT" PROTO="$PROTO" "$PREFIX/venv/bin/python" - <<'PY'
import json, os
from veroscudo.config import Config
cfg = {"profiles": [{"profile": os.environ["PROFILE"], "server": os.environ["SERVER"], "port": int(os.environ["PORT"]),
                     "protocol": os.environ["PROTO"]}],
       "activeProfile": os.environ["PROFILE"], "retrySeconds": 10, "vm": False, "updateCheck": True, "lanAllow": []}
text = json.dumps(cfg, indent=2)
Config.from_text(text)
open("/etc/veroscudo/config.json", "w").write(text + "\n")
PY
  chmod 644 /etc/veroscudo/config.json
  echo "config written: /etc/veroscudo/config.json"
fi

install -m 644 -o root -g wheel "$HERE/com.gomelhawk.veroscudo.plist" /Library/LaunchDaemons/com.gomelhawk.veroscudo.plist
launchctl bootout system/com.gomelhawk.veroscudo 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.gomelhawk.veroscudo.plist

cat > /etc/sudoers.d/veroscudo.tmp <<EOF
$USER_NAME ALL=(root) NOPASSWD: /usr/local/bin/veroscudo on, /usr/local/bin/veroscudo off, /usr/local/bin/veroscudo use *
EOF
visudo -cf /etc/sudoers.d/veroscudo.tmp >/dev/null && mv /etc/sudoers.d/veroscudo.tmp /etc/sudoers.d/veroscudo
chmod 440 /etc/sudoers.d/veroscudo
echo
echo "INSTALL OK (alpha). Turn on: sudo veroscudo on   Off: sudo veroscudo off   Status: veroscudo status"
echo "Profiles: veroscudo profiles   Switch: sudo veroscudo use <profile>"
echo "macOS reports no 'you hung up' reason: after disconnecting in System Settings, run 'sudo veroscudo off'."
