#!/usr/bin/env bash
# VeroScudo installer for macOS - ALPHA (pf + scutil). Run with sudo from the macos/ folder.
# Uses the shared Python guard from ../linux in its own venv; the launchd daemon keeps the kill-switch and redials.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ "$(uname -s)" = "Darwin" ] || { echo "this installer is for macOS"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="${SUDO_USER:-$(stat -f %Su /dev/console)}"
# /opt is root-owned on every Mac. /usr/local is Homebrew's: on Intel Macs the user owns /usr/local/lib and /usr/local/bin,
# so a program there could be swapped by any user-level process - and this one runs as root (launchd, sudoers).
PREFIX=/opt/veroscudo
BIN="$PREFIX/bin/veroscudo"
# Apple's python3 only (root-owned): the venv's interpreter is what the root daemon runs. `command -v python3` could find
# Homebrew's, which the user owns on Intel Macs - the same swap problem as /usr/local, one level down.
PYTHON=/usr/bin/python3
if ! { [ -x "$PYTHON" ] && "$PYTHON" -c 'import venv' 2>/dev/null; }; then echo "missing: Apple's python3 - run: xcode-select --install"; exit 1; fi

install -d -m 755 -o root -g wheel /opt "$PREFIX" "$PREFIX/bin" /etc/veroscudo /var/lib/veroscudo
# every folder the daemon and the sudo rule run from must be root's and not writable by others - refuse otherwise
for d in /opt "$PREFIX" "$PREFIX/bin"; do
  if [ "$(stat -f %u "$d")" != "0" ] || [ -n "$(find "$d" -maxdepth 0 -perm +022)" ]; then
    echo "$d is not root-owned and closed to others - refusing (an owner could swap the program the root daemon runs)"; exit 1
  fi
done
"$PYTHON" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --quiet --upgrade "$HERE/../linux"
ln -sfh "$PREFIX/venv/bin/veroscudo" "$BIN"
chown -R root:wheel "$PREFIX"
# 1.3.0 alpha installed under /usr/local: remove that copy (nothing of yours lives there)
rm -rf /usr/local/lib/veroscudo
[ -L /usr/local/bin/veroscudo ] && rm -f /usr/local/bin/veroscudo
# a convenience link only where /usr/local/bin already exists and is root's: the installer never creates or chowns it
RULE_PATHS=("$BIN")
if [ -d /usr/local/bin ] && [ "$(stat -f %u /usr/local/bin)" = "0" ]; then
  ln -sfh "$BIN" /usr/local/bin/veroscudo
  RULE_PATHS+=(/usr/local/bin/veroscudo)
fi

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

# passwordless only for the four user actions, only by root-owned paths
RULE=""
for b in "${RULE_PATHS[@]}"; do
  for a in on off reconnect "use *"; do RULE="$RULE${RULE:+, }$b $a"; done
done
cat > /etc/sudoers.d/veroscudo.tmp <<EOF
$USER_NAME ALL=(root) NOPASSWD: $RULE
EOF
visudo -cf /etc/sudoers.d/veroscudo.tmp >/dev/null && mv /etc/sudoers.d/veroscudo.tmp /etc/sudoers.d/veroscudo
chmod 440 /etc/sudoers.d/veroscudo
echo
echo "INSTALL OK (alpha). The program is $BIN - put $PREFIX/bin on your PATH (new shell afterwards):"
echo "    echo 'export PATH=\"$PREFIX/bin:\$PATH\"' >> ~/.zprofile"
echo "Turn on: sudo veroscudo on   Off: sudo veroscudo off   Status: veroscudo status"
echo "Profiles: veroscudo profiles   Switch: sudo veroscudo use <profile>"
echo "macOS reports no 'you hung up' reason: after disconnecting in System Settings, run 'sudo veroscudo off'."
