#!/usr/bin/env bash
# VeroScudo installer for Linux (NetworkManager + nftables). From the linux/ folder, as your own user:
#     sudo ./install.sh                         asks which VPN connection to protect
#     sudo ./install.sh --profile "Office VPN"  that NetworkManager connection, no questions
#     sudo ./install.sh --yes                   install missing packages without asking
# Run it again to update: config.json and the armed state are kept. Remove: sudo /opt/veroscudo/uninstall.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run it with sudo: sudo ./install.sh"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX=/opt/veroscudo
BIN="$PREFIX/bin/veroscudo"
TRAY="$PREFIX/bin/veroscudo-tray"
PY3=/usr/bin/python3
PROFILE=""
YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    *) echo "unknown option: $1  (see the top of this file)"; exit 1 ;;
  esac
done
USER_NAME="${SUDO_USER:-}"
if [ -z "$USER_NAME" ] || [ "$USER_NAME" = root ]; then
  echo "run it with sudo from the account you sign in with (the tray and the passwordless On/Off are set up for that user)"; exit 1
fi
USER_ID="$(id -u "$USER_NAME")"

echo "== 1/6 packages"
need=()
have_gi() { "$PY3" -c "import gi; gi.require_version('$1', '$2'); from gi.repository import $1" 2>/dev/null; }
command -v nft >/dev/null || need+=(nftables)
command -v nmcli >/dev/null || need+=(network-manager)
[ -x "$PY3" ] || need+=(python3)
"$PY3" -c 'import gi' 2>/dev/null || need+=(python3-gi)
have_gi NM 1.0 || need+=(gir1.2-nm-1.0)                                 # the "you hung up" reason
have_gi Gtk 3.0 || need+=(gir1.2-gtk-3.0)                                 # tray windows
have_gi AyatanaAppIndicator3 0.1 || need+=(gir1.2-ayatanaappindicator3-0.1)   # tray icon
command -v notify-send >/dev/null || need+=(libnotify-bin)                # tray notifications
command -v pkexec >/dev/null || need+=(pkexec)                            # Settings / Uninstall ask for the admin password
command -v pgrep >/dev/null || need+=(procps)
command -v wg >/dev/null || need+=(wireguard-tools)                     # WireGuard: a dead link is judged by its handshakes
# GNOME shows tray icons only with the AppIndicator extension (Ubuntu ships it; plain GNOME does not)
if command -v gnome-shell >/dev/null && command -v dpkg >/dev/null \
   && ! dpkg -s gnome-shell-extension-appindicator >/dev/null 2>&1 && ! dpkg -s gnome-shell-extension-ubuntu-appindicators >/dev/null 2>&1 \
   && ! dpkg -s gnome-shell-ubuntu-extensions >/dev/null 2>&1; then      # Ubuntu 26.04: part of gnome-shell-ubuntu-extensions
  need+=(gnome-shell-extension-appindicator)
fi
if [ ${#need[@]} -gt 0 ]; then
  if ! command -v apt-get >/dev/null; then
    echo "missing (install them with your package manager, then run this again): ${need[*]}"; exit 1
  fi
  # 22.04 calls pkexec's package policykit-1
  if [[ " ${need[*]} " == *" pkexec "* ]] && ! apt-cache show pkexec >/dev/null 2>&1; then need=("${need[@]/pkexec/policykit-1}"); fi
  echo "needed: ${need[*]}"
  if [ "$YES" -ne 1 ]; then
    read -r -p "Install them now with apt? [Y/n] " a
    case "${a:-y}" in y|Y|yes) ;; *) echo "nothing changed"; exit 1 ;; esac
  fi
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${need[@]}"
fi
if ! command -v nft >/dev/null || ! command -v nmcli >/dev/null; then echo "nftables / NetworkManager still missing"; exit 1; fi

echo "== 2/6 program -> $PREFIX"
# root runs it (the service, the sudo rule): the interpreter and every folder on the way must be root's and closed to others
for f in "$PY3" /opt /usr/local/bin; do
  [ -e "$f" ] || continue
  if [ "$(stat -L -c %u "$f")" != "0" ] || [ -n "$(find -L "$f" -maxdepth 0 -perm /022)" ]; then
    echo "$f is not root-owned and closed to others - refusing (root would run a program others can replace)"; exit 1
  fi
done
install -d -m 755 -o root -g root "$PREFIX" "$PREFIX/bin" "$PREFIX/lib" /etc/veroscudo /usr/share/veroscudo/icons /var/lib/veroscudo
# a fresh copy of the package (no __pycache__ from a checkout), swapped in whole
"$PY3" -I - "$HERE/veroscudo" "$PREFIX/lib/veroscudo.new" <<'PY'
import shutil, sys
shutil.rmtree(sys.argv[2], ignore_errors=True)
shutil.copytree(sys.argv[1], sys.argv[2], ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
PY
[ -d "$PREFIX/lib/veroscudo" ] && mv "$PREFIX/lib/veroscudo" "$PREFIX/lib/veroscudo.old"
mv "$PREFIX/lib/veroscudo.new" "$PREFIX/lib/veroscudo"
[ -d "$PREFIX/lib/veroscudo.old" ] && rm -rf -- "$PREFIX/lib/veroscudo.old"
# -I: no PYTHONPATH, no user site-packages, not the current folder - only the system's packages and this copy
for pair in "veroscudo:veroscudo.cli" "veroscudo-tray:veroscudo.tray"; do
  name="${pair%%:*}"; mod="${pair#*:}"
  printf '#!%s -I\nimport sys\nsys.path.insert(0, "%s/lib")\nfrom %s import main\nsys.exit(main())\n' "$PY3" "$PREFIX" "$mod" > "$PREFIX/bin/$name"
done
install -m 755 "$HERE/uninstall.sh" "$PREFIX/uninstall.sh"
chown -R root:root "$PREFIX"
chmod -R go-w "$PREFIX"
chmod 755 "$BIN" "$TRAY"
# up to 1.3: installed with pip into the system Python - remove that copy so only one exists
if "$PY3" -m pip show veroscudo >/dev/null 2>&1; then
  "$PY3" -m pip uninstall -y -q --break-system-packages veroscudo 2>/dev/null || "$PY3" -m pip uninstall -y -q veroscudo || true
fi
RULE_PATHS=("$BIN")
if [ -d /usr/local/bin ]; then
  ln -sfn "$BIN" /usr/local/bin/veroscudo
  RULE_PATHS+=(/usr/local/bin/veroscudo)
fi
"$BIN" --version

echo "== 3/6 VPN profile"
if [ -n "$PROFILE" ]; then "$BIN" setup "$PROFILE"; else "$BIN" setup; fi

echo "== 4/6 icons, menu entry, tray autostart"
ICONS=""
for d in "$HERE/assets/icons" "$HERE/../assets/icons"; do [ -f "$d/png/protected-128.png" ] && { ICONS="$d"; break; }; done
if [ -n "$ICONS" ]; then
  for s in protected blocked off attention; do install -m 644 "$ICONS/png/$s-128.png" "/usr/share/veroscudo/icons/$s.png"; done
  install -m 644 "$ICONS/app/app-128.png" /usr/share/veroscudo/icons/app.png
else
  echo "WARNING: icons not found (assets/icons) - the tray will show a generic icon"
fi
desktop() {   # $1 file, $2 extra lines
  cat > "$1" <<EOF
[Desktop Entry]
Type=Application
Name=VeroScudo
GenericName=VPN kill-switch
Comment=Show the VeroScudo tray icon
Exec=$TRAY
Icon=/usr/share/veroscudo/icons/app.png
Terminal=false
Categories=Network;Security;
$2
EOF
  chmod 644 "$1"
}
desktop /usr/share/applications/veroscudo.desktop ""                       # the way back after "Exit tray"
desktop /etc/xdg/autostart/veroscudo-tray.desktop "X-GNOME-Autostart-enabled=true
NoDisplay=true"                                                             # every desktop session, every user

echo "== 5/6 services and the sudo rule"
for u in veroscudo.service veroscudo-boot.service; do
  sed "s#^ExecStart=/opt/veroscudo/bin/veroscudo #ExecStart=$BIN #" "$HERE/systemd/$u" > "/etc/systemd/system/$u"
  chmod 644 "/etc/systemd/system/$u"
done
grep -q "^ExecStart=$BIN daemon" /etc/systemd/system/veroscudo.service || { echo "unit template did not take the program path"; exit 1; }
# the log: root:adm 0640, so an administrator's tray can show it (adm reads the journal, where the same lines go anyway)
if getent group adm >/dev/null; then
  sed -i 's/^#SupplementaryGroups=adm$/SupplementaryGroups=adm/' /etc/systemd/system/veroscudo.service
  touch /var/log/veroscudo.log && chgrp adm /var/log/veroscudo.log && chmod 640 /var/log/veroscudo.log
fi
# an armed flag left in /run by an older layout (lost on reboot): move it, or the upgrade would silently disarm
for f in armed.flag server.ip; do
  [ -f "/run/veroscudo/$f" ] && [ ! -f "/var/lib/veroscudo/$f" ] && mv "/run/veroscudo/$f" "/var/lib/veroscudo/$f"
done
RULE=""
for b in "${RULE_PATHS[@]}"; do
  for a in on off reconnect "use *"; do RULE="$RULE${RULE:+, }$b $a"; done
done
echo "$USER_NAME ALL=(root) NOPASSWD: $RULE" > /etc/sudoers.d/veroscudo.tmp
chmod 440 /etc/sudoers.d/veroscudo.tmp
visudo -cf /etc/sudoers.d/veroscudo.tmp >/dev/null && mv /etc/sudoers.d/veroscudo.tmp /etc/sudoers.d/veroscudo
systemctl daemon-reload
systemctl enable --quiet veroscudo.service veroscudo-boot.service
systemctl restart veroscudo.service     # an upgrade must run the new code; the armed flag survives (StateDirectory)

echo "== 6/6 tray"
RUN_AS=(sudo -u "$USER_NAME" env "XDG_RUNTIME_DIR=/run/user/$USER_ID" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$USER_ID/bus")
# up to 1.3 the tray was a per-user systemd unit: replaced by the autostart entry above
"${RUN_AS[@]}" systemctl --user disable --now veroscudo-tray.service >/dev/null 2>&1 || true
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
[ -f "$USER_HOME/.config/systemd/user/veroscudo-tray.service" ] && sudo -u "$USER_NAME" rm -f "$USER_HOME/.config/systemd/user/veroscudo-tray.service"
pkill -u "$USER_ID" -f 'bin/veroscudo-tray|-m veroscudo\.tray' 2>/dev/null || true
started=0
if [ -S "/run/user/$USER_ID/bus" ] && "${RUN_AS[@]}" systemctl --user show-environment 2>/dev/null | grep -qE '^(WAYLAND_)?DISPLAY='; then
  "${RUN_AS[@]}" systemd-run --user --quiet --collect "--unit=veroscudo-tray-$$" "$TRAY" && started=1
fi
echo
echo "INSTALL OK."
if [ "$started" -eq 1 ]; then
  echo "The VeroScudo shield is in the top bar. Turn the VPN on there, or connect it as usual - VeroScudo arms by itself."
else
  echo "The tray starts at your next sign-in - or now: open 'VeroScudo' from the applications menu."
fi
if [[ " ${need[*]} " == *" gnome-shell-extension-appindicator "* ]]; then
  echo "GNOME: sign out and in once, then enable 'AppIndicator and KStatusNotifierItem Support' in the Extensions app."
fi
echo "Command line: veroscudo status | sudo veroscudo on | sudo veroscudo off | veroscudo profiles | sudo veroscudo use <profile>"
echo "Uninstall:    sudo $PREFIX/uninstall.sh   (or tray > About > Uninstall…)"
