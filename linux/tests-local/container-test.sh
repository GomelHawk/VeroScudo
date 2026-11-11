#!/usr/bin/env bash
# shellcheck disable=SC2016  # the single-quoted snippets passed to ct_sh expand inside the container, on purpose
# Installs, uses and uninstalls VeroScudo for real in a throwaway Ubuntu container that runs systemd and NetworkManager:
# install.sh (packages, program, service, sudo rule, tray autostart), status as the user, On/Off through the sudo rule, the
# kill-switch table, the daemon picking up a Settings change, an upgrade over an armed install, uninstall and --purge.
#
# The kill-switch lives in the container's own network namespace: the host's network is never touched. No real VPN: an
# OpenVPN connection whose plugin is not installed - NetworkManager knows it, every dial fails, so the container stays armed
# and blocked, which is exactly what is checked.
#
#     linux/tests-local/container-test.sh [ubuntu:24.04|ubuntu:22.04|ubuntu:26.04]   (needs Docker; CI runs all three)
set -euo pipefail
IMAGE="${1:-ubuntu:24.04}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TAG="veroscudo-ct:$(echo "$IMAGE" | tr ':/' '--')"
NAME="veroscudo-ct-$$"
LOGS="$(mktemp -d)"
pass=0
fail=0
ok() { echo "PASS  $*"; pass=$((pass + 1)); }
bad() { echo "FAIL  $*"; fail=$((fail + 1)); }
check() { local what="$1"; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
in_ct() { docker exec "$NAME" "$@"; }
as_user() { docker exec -u tester "$NAME" "$@"; }
# a shell snippet inside the container ($ and quotes are meant for that shell, not this one)
ct_sh() { docker exec "$NAME" sh -c "$1"; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# systemd-binfmt is masked: binfmt_misc is shared with the host kernel, and the container's systemd would clear the host's
# registrations (on WSL that removes WSLInterop - no Windows program starts any more until it is registered again).
# the Ubuntu mirrors sometimes fail a download from CI runners (apt exit 100): apt retries each download, and the whole
# build is tried up to 3 times - a build that fails every time still fails the test
# the build uses the host's network (its DNS and routes - Docker's own build DNS can fail on CI runner images); on a
# failure apt's own error lines are shown (docker build -q hid them)
build() {
  local out
  out=$(docker build --network=host --progress=plain -t "$TAG" - 2>&1 <<EOF
FROM $IMAGE
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -o Acquire::Retries=5 update -q \
    && apt-get -o Acquire::Retries=5 install -y -q systemd systemd-sysv dbus sudo python3 iproute2 procps network-manager \
    && systemctl mask systemd-binfmt.service proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.mount \
    && useradd -m -s /bin/bash tester \
    && printf '[keyfile]\nunmanaged-devices=interface-name:eth0\n' > /etc/NetworkManager/conf.d/10-ct.conf
CMD ["/sbin/init"]
EOF
) && return 0
  echo "$out" | grep -E "(^| )(E:|Err:|W:)|Could not|Temporary failure|Unable to|ERROR" | tail -15
  return 1
}
for try in 1 2 3; do
  build && break
  [ "$try" -lt 3 ] || { echo "the test image could not be built (package download failed 3 times)"; exit 1; }
  echo "image build failed (attempt $try) - retrying in 20 s"; sleep 20
done
docker run -d --name "$NAME" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock -v "$ROOT:/src:ro" "$TAG" >/dev/null
for _ in $(seq 60); do in_ct systemctl is-active -q NetworkManager 2>/dev/null && break; sleep 1; done

docker exec -i "$NAME" sh -c 'umask 077; cat > /etc/NetworkManager/system-connections/ovpn-ct.nmconnection' <<'NM'
[connection]
id=ovpn-ct
type=vpn
autoconnect=false

[vpn]
service-type=org.freedesktop.NetworkManager.openvpn
connection-type=password
remote=192.0.2.1:1194
username=tester

[ipv4]
method=auto
NM
in_ct nmcli connection reload

echo "== install ($IMAGE)"
if in_ct env SUDO_USER=tester /src/linux/install.sh --yes --profile ovpn-ct > "$LOGS/install.log" 2>&1; then
  ok "install.sh --yes --profile ovpn-ct"
else
  bad "install.sh"; cat "$LOGS/install.log"; exit 1
fi
check "service active" in_ct systemctl is-active -q veroscudo.service
check "boot unit enabled" in_ct systemctl is-enabled -q veroscudo-boot.service
check "profile imported as OpenVPN to its remote" ct_sh 'grep -q "\"server\": \"192.0.2.1\"" /etc/veroscudo/config.json && grep -q "\"vpnType\": \"openvpn\"" /etc/veroscudo/config.json'
check "tray autostart + menu entry" in_ct test -f /etc/xdg/autostart/veroscudo-tray.desktop -a -f /usr/share/applications/veroscudo.desktop
check "icons" in_ct test -f /usr/share/veroscudo/icons/protected.png -a -f /usr/share/veroscudo/icons/app.png
check "program is root's and closed to others" ct_sh '[ "$(stat -c %U%a /opt/veroscudo/bin/veroscudo)" = root755 ] && ! find /opt/veroscudo -perm /022 | grep -q .'
check "command on PATH" as_user sh -c 'command -v veroscudo'
check "status as the user: off" as_user sh -c 'veroscudo status | grep -q "state      : off"'
check "tray module loads with its GTK/AppIndicator packages" as_user /usr/bin/python3 -I -c \
  'import sys; sys.path.insert(0, "/opt/veroscudo/lib"); import veroscudo.tray as t, gi; gi.require_version("AyatanaAppIndicator3", "0.1"); t._gtk()'

echo "== on / off through the sudo rule"
check "network works before On (TCP to 1.1.1.1:443)" in_ct timeout 10 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'
check "on (dials once, returns)" as_user timeout 90 sudo -n /opt/veroscudo/bin/veroscudo on
check "armed" in_ct test -f /var/lib/veroscudo/armed.flag
check "kill-switch table in force" in_ct nft list table inet veroscudo
check "nothing leaves while blocked (TCP to 1.1.1.1:443)" ct_sh '! timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null'
sleep 35
# the command's own single dial logs "attempt 1 failed" once; a second loop (and its "attempt 2") is the daemon's
check "the daemon took the redial over" ct_sh '[ "$(grep -c "attempt 1 failed" /var/log/veroscudo.log)" -ge 2 ] || grep -q "attempt 2 failed" /var/log/veroscudo.log'
check "status as the user: blocked" as_user sh -c 'veroscudo status | grep -q "state      : blocked"'
check "log readable by administrators (root:adm 0640)" ct_sh '[ "$(stat -c %U:%G:%a /var/log/veroscudo.log)" = root:adm:640 ]'
check "the sudo rule allows nothing else (daemon refused)" as_user sh -c '! sudo -n /opt/veroscudo/bin/veroscudo daemon 2>/dev/null'
check "the sudo rule allows no config change (import refused)" as_user sh -c '! sudo -n /opt/veroscudo/bin/veroscudo import x 2>/dev/null'

echo "== a Settings change is picked up without a restart"
in_ct /opt/veroscudo/bin/veroscudo set updateCheck false >/dev/null
sleep 20
check "daemon reloaded config.json" in_ct grep -q "config.json changed" /var/log/veroscudo.log

echo "== upgrade while armed"
if in_ct env SUDO_USER=tester /src/linux/install.sh --yes > "$LOGS/upgrade.log" 2>&1; then
  ok "install.sh again"
else
  bad "install.sh again"; cat "$LOGS/upgrade.log"
fi
check "still armed after the upgrade" in_ct test -f /var/lib/veroscudo/armed.flag
check "config kept" in_ct grep -q '"updateCheck": false' /etc/veroscudo/config.json
sleep 5
check "table in force after the upgrade" in_ct nft list table inet veroscudo
check "nothing leaves after the upgrade" ct_sh '! timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null'

check "off" as_user sudo -n /opt/veroscudo/bin/veroscudo off
check "disarmed, table gone" ct_sh '[ ! -f /var/lib/veroscudo/armed.flag ] && ! nft list table inet veroscudo 2>/dev/null'
check "network works after Off" in_ct timeout 10 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'

echo "== uninstall"
check "uninstall.sh" in_ct /opt/veroscudo/uninstall.sh
for f in /opt/veroscudo /etc/systemd/system/veroscudo.service /etc/sudoers.d/veroscudo /etc/xdg/autostart/veroscudo-tray.desktop \
         /usr/share/applications/veroscudo.desktop /usr/local/bin/veroscudo /usr/share/veroscudo; do
  check "removed: $f" in_ct sh -c "[ ! -e $f ] && [ ! -L $f ]"
done
check "config kept without --purge" in_ct test -f /etc/veroscudo/config.json
check "--purge removes config and state" ct_sh '/src/linux/uninstall.sh --purge >/dev/null && [ ! -e /etc/veroscudo ] && [ ! -e /var/lib/veroscudo ]'

echo
echo "$IMAGE: $pass passed, $fail failed   (installer output: $LOGS)"
[ "$fail" -eq 0 ]
