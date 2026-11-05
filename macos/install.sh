#!/usr/bin/env bash
# VeroScudo installer for macOS - ALPHA (pf + scutil). From the macos/ folder, as your own user:
#     sudo ./install.sh                             asks which VPN service to protect
#     sudo ./install.sh --profile "Office IKEv2"    that service (System Settings > VPN), no questions
# Run it again to update: config.json and the armed state are kept. Remove: sudo /opt/veroscudo/uninstall.sh
# The guard is the shared Python package in ../linux, run by Apple's python3; the launchd daemon keeps the kill-switch
# and redials; the menu-bar app (PyObjC) runs as you.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run it with sudo: sudo ./install.sh"; exit 1; }
[ "$(uname -s)" = "Darwin" ] || { echo "this installer is for macOS"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../linux"
PROFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    *) echo "unknown option: $1  (see the top of this file)"; exit 1 ;;
  esac
done
USER_NAME="${SUDO_USER:-}"
if [ -z "$USER_NAME" ] || [ "$USER_NAME" = root ]; then
  echo "run it with sudo from the account you sign in with (the menu-bar app and the passwordless On/Off are set up for it)"; exit 1
fi
USER_ID="$(id -u "$USER_NAME")"
# /opt is root-owned on every Mac. /usr/local is Homebrew's: on Intel Macs the user owns /usr/local/lib and /usr/local/bin,
# so a program there could be swapped by any user-level process - and this one runs as root (launchd, sudoers).
PREFIX=/opt/veroscudo
BIN="$PREFIX/bin/veroscudo"
TRAY="$PREFIX/bin/veroscudo-tray"
APP=/Applications/VeroScudo.app
AGENT=/Library/LaunchAgents/com.gomelhawk.veroscudo.tray.plist
# Apple's python3 only (root-owned). `command -v python3` could find Homebrew's, which the user owns on Intel Macs.
PYTHON=/usr/bin/python3
if ! "$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
  echo "missing: Apple's python3 (3.9 or newer) - run: xcode-select --install   then this installer again"; exit 1
fi

echo "== 1/5 program -> $PREFIX"
install -d -m 755 -o root -g wheel /opt "$PREFIX" "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/icons" /etc/veroscudo /var/lib/veroscudo
for d in /opt "$PREFIX" "$PREFIX/bin"; do
  if [ "$(stat -f %u "$d")" != "0" ] || [ -n "$(find "$d" -maxdepth 0 -perm +022)" ]; then
    echo "$d is not root-owned and closed to others - refusing (an owner could swap the program the root daemon runs)"; exit 1
  fi
done
"$PYTHON" -I - "$SRC/veroscudo" "$PREFIX/lib/veroscudo.new" <<'PY'
import shutil, sys
shutil.rmtree(sys.argv[2], ignore_errors=True)
shutil.copytree(sys.argv[1], sys.argv[2], ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
PY
[ -d "$PREFIX/lib/veroscudo" ] && mv "$PREFIX/lib/veroscudo" "$PREFIX/lib/veroscudo.old"
mv "$PREFIX/lib/veroscudo.new" "$PREFIX/lib/veroscudo"
[ -d "$PREFIX/lib/veroscudo.old" ] && rm -rf -- "$PREFIX/lib/veroscudo.old"
# 1.3.x: a venv with a symlink at bin/veroscudo - writing through that link would land in the venv
rm -f "$BIN" "$TRAY"
[ -d "$PREFIX/venv" ] && rm -rf -- "$PREFIX/venv"
# -I: no PYTHONPATH, no user site-packages, not the current folder - only Apple's Python and this copy
printf '#!%s -I\nimport sys\nsys.path.insert(0, "%s/lib")\nfrom veroscudo.cli import main\nsys.exit(main())\n' "$PYTHON" "$PREFIX" > "$BIN"
printf '#!%s -I\nimport sys\nsys.path[:0] = ["%s/lib", "%s/tray-lib"]\nfrom veroscudo.tray_macos import main\nsys.exit(main())\n' \
  "$PYTHON" "$PREFIX" "$PREFIX" > "$TRAY"
install -m 755 "$HERE/uninstall.sh" "$PREFIX/uninstall.sh"
# the menu-bar app's only dependency: PyObjC (AppKit), pinned, wheels only, in its own folder - the root daemon never loads it
TRAY_OK=1
[ -d "$PREFIX/tray-lib.new" ] && rm -rf -- "$PREFIX/tray-lib.new"
if "$PYTHON" -m pip install --quiet --disable-pip-version-check --no-cache-dir --only-binary=:all: \
     --target "$PREFIX/tray-lib.new" "pyobjc-core==10.3.1" "pyobjc-framework-Cocoa==10.3.1"; then
  [ -d "$PREFIX/tray-lib" ] && mv "$PREFIX/tray-lib" "$PREFIX/tray-lib.old"
  mv "$PREFIX/tray-lib.new" "$PREFIX/tray-lib"
  [ -d "$PREFIX/tray-lib.old" ] && rm -rf -- "$PREFIX/tray-lib.old"
else
  [ -d "$PREFIX/tray-lib.new" ] && rm -rf -- "$PREFIX/tray-lib.new"
  [ -d "$PREFIX/tray-lib" ] || TRAY_OK=0
  echo "WARNING: PyObjC could not be downloaded - the menu-bar app needs it (run the installer again when online)"
fi
chown -R root:wheel "$PREFIX"
chmod -R go-w "$PREFIX"
chmod 755 "$BIN" "$TRAY"
# 1.3.0 alpha installed under /usr/local: remove that copy (nothing of yours lives there)
[ -d /usr/local/lib/veroscudo ] && rm -rf -- /usr/local/lib/veroscudo
# on PATH for every shell (path_helper reads /etc/paths.d); a /usr/local/bin link only where that folder is root's
echo "$PREFIX/bin" > /etc/paths.d/veroscudo
chmod 644 /etc/paths.d/veroscudo
RULE_PATHS=("$BIN")
if [ -d /usr/local/bin ] && [ "$(stat -f %u /usr/local/bin)" = "0" ]; then
  ln -sfh "$BIN" /usr/local/bin/veroscudo
  RULE_PATHS+=(/usr/local/bin/veroscudo)
elif [ -L /usr/local/bin/veroscudo ]; then
  rm -f /usr/local/bin/veroscudo
fi
VERSION="$("$BIN" --version | awk '{print $2}')"
echo "veroscudo $VERSION"

echo "== 2/5 VPN profile"
if [ -n "$PROFILE" ]; then "$BIN" setup "$PROFILE"; else "$BIN" setup; fi

echo "== 3/5 guard (launchd) and the sudo rule"
touch /var/log/veroscudo.log && chgrp admin /var/log/veroscudo.log && chmod 640 /var/log/veroscudo.log   # admins' tray shows it
install -m 644 -o root -g wheel "$HERE/com.gomelhawk.veroscudo.plist" /Library/LaunchDaemons/com.gomelhawk.veroscudo.plist
launchctl bootout system/com.gomelhawk.veroscudo 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.gomelhawk.veroscudo.plist
RULE=""
for b in "${RULE_PATHS[@]}"; do
  for a in on off reconnect "use *"; do RULE="$RULE${RULE:+, }$b $a"; done
done
echo "$USER_NAME ALL=(root) NOPASSWD: $RULE" > /etc/sudoers.d/veroscudo.tmp
chmod 440 /etc/sudoers.d/veroscudo.tmp
visudo -cf /etc/sudoers.d/veroscudo.tmp >/dev/null && mv /etc/sudoers.d/veroscudo.tmp /etc/sudoers.d/veroscudo

echo "== 4/5 icons and the app"
ICONS=""
for d in "$HERE/../assets/icons" "$HERE/assets/icons"; do [ -f "$d/png/protected-128.png" ] && { ICONS="$d"; break; }; done
if [ -n "$ICONS" ]; then
  for s in protected blocked off attention; do install -m 644 "$ICONS/png/$s-64.png" "$PREFIX/icons/$s.png"; done
  install -m 644 "$ICONS/app/app-128.png" "$PREFIX/icons/app.png"
else
  echo "WARNING: icons not found (assets/icons) - the menu bar shows 'VS' instead of the shield"
fi
# /Applications/VeroScudo.app: opens the menu-bar icon again after "Exit"; no Dock icon (LSUIElement)
[ -d "$APP" ] && rm -rf -- "$APP"
install -d -m 755 "$APP/Contents/MacOS" "$APP/Contents/Resources"
printf '#!/bin/sh\nexec %s\n' "$TRAY" > "$APP/Contents/MacOS/VeroScudo"
chmod 755 "$APP/Contents/MacOS/VeroScudo"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>VeroScudo</string>
    <key>CFBundleDisplayName</key><string>VeroScudo</string>
    <key>CFBundleIdentifier</key><string>com.gomelhawk.veroscudo.tray</string>
    <key>CFBundleExecutable</key><string>VeroScudo</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleIconFile</key><string>VeroScudo</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
EOF
if [ -n "$ICONS" ]; then        # best effort: the app works without its icon
  tmp_root="$(mktemp -d)"
  set_dir="$tmp_root/VeroScudo.iconset"
  mkdir -p "$set_dir"
  for s in 16 32 128 256; do cp "$ICONS/app/app-$s.png" "$set_dir/icon_${s}x${s}.png"; done
  cp "$ICONS/app/app-32.png" "$set_dir/icon_16x16@2x.png"
  cp "$ICONS/app/app-64.png" "$set_dir/icon_32x32@2x.png"
  cp "$ICONS/app/app-256.png" "$set_dir/icon_128x128@2x.png"
  iconutil -c icns "$set_dir" -o "$APP/Contents/Resources/VeroScudo.icns" 2>/dev/null || echo "note: app icon not built"
  case "$tmp_root" in /var/folders/*|/tmp/*|/private/*) rm -rf -- "$tmp_root" ;; esac
fi
chown -R root:wheel "$APP"

echo "== 5/5 menu-bar app at login"
cat > "$AGENT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.gomelhawk.veroscudo.tray</string>
    <key>ProgramArguments</key><array><string>$TRAY</string></array>
    <key>RunAtLoad</key><true/>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
    <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
EOF
chown root:wheel "$AGENT"
chmod 644 "$AGENT"
pkill -f 'bin/veroscudo-tray' 2>/dev/null || true
launchctl bootout "gui/$USER_ID/com.gomelhawk.veroscudo.tray" 2>/dev/null || true
started=0
if [ "$TRAY_OK" -eq 1 ] && launchctl bootstrap "gui/$USER_ID" "$AGENT" 2>/dev/null; then started=1; fi
echo
echo "INSTALL OK (alpha)."
if [ "$started" -eq 1 ]; then
  echo "The VeroScudo shield is in the menu bar. Turn the VPN on there."
else
  echo "Open VeroScudo from Applications to show the menu-bar icon (it starts by itself at your next login)."
fi
echo "macOS reports no 'you hung up' reason: turn the VPN off with VeroScudo (menu bar > Turn VPN off), not in System Settings."
echo "Command line (new terminal window): veroscudo status | sudo veroscudo on | sudo veroscudo off | sudo veroscudo use <profile>"
echo "Uninstall: sudo $PREFIX/uninstall.sh   (or menu bar > About VeroScudo > Uninstall…)"
