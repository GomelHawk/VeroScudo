#!/usr/bin/env bash
# Short commands for testing in a VM without a clipboard. Each run first updates the repo (git pull as you), so a new
# check only needs a commit on the other side - never a long command typed by hand.
#   once:   sudo linux/tests-local/vt.sh install      -> afterwards just: vt <command>
#   vt live            the kill-switch live test (live.sh)
#   vt wgcycle [N]     VeroScudo stopped; the active WireGuard profile restarted N times (6) - does its handshake answer?
#   vt fail            the network state saved at each failure of the last live test
#   vt log [N]         VeroScudo's last N log lines (40)
#   vt status          VeroScudo's status
#   vt profiles        the profiles (* = active);   vt use <profile>   switch to it
#   vt boot            after a reboot while on: did the kill-switch come up before the network? protected now?
#   vt gone            after an uninstall: is anything of VeroScudo left?
#   vt hdiag           Hiddify: its service, tunnel, config as VeroScudo reads it, the kill-switch's permits, the exit
#   vt cgtest          can nftables match Hiddify's service by its cgroup? (counts only, blocks nothing, 5 s)
#   vt hfix            Hiddify 5.5 "exit status 127": (re)install its service from the right folder, link its lib, restart
set -u
SELF="$(readlink -f "$0")"
REPO="$(cd "$(dirname "$SELF")/../.." && pwd)"
[ "$(id -u)" -eq 0 ] || exec sudo "$SELF" "$@"
OWNER="${SUDO_USER:-root}"
HOME_DIR="$(getent passwd "$OWNER" | cut -d: -f6)"

if [ -z "${VT_PULLED:-}" ]; then          # update, then run the updated script
  sudo -u "$OWNER" git -C "$REPO" pull --ff-only -q || echo "(git pull failed - running the version on disk)"
  VT_PULLED=1 exec "$SELF" "$@"
fi

profile() { veroscudo status 2>/dev/null | awk -F' *: ' '$1 == "profile" {sub(/ \(.*$/, "", $2); print $2; exit}'; }

case "${1:-}" in
  install)
    ln -sf "$SELF" /usr/local/bin/vt && echo "done - from now on: vt <command> (vt help)" ;;
  live)
    shift; exec "$REPO/linux/tests-local/live.sh" "$@" ;;
  wgcycle)
    n="${2:-6}"; p="$(profile)"
    [ -n "$p" ] || { echo "no active profile"; exit 1; }
    trap 'systemctl start veroscudo; echo "VeroScudo service started again"' EXIT
    veroscudo off >/dev/null 2>&1; systemctl stop veroscudo
    echo "VeroScudo stopped; restarting '$p' $n times (10 s each)"
    ok=0
    for i in $(seq "$n"); do
      nmcli con down "$p" >/dev/null 2>&1; nmcli con up "$p" >/dev/null 2>&1; sleep 10
      t="$(wg show "$p" transfer 2>/dev/null | awk '{print $2, $3}')"
      if [ -n "$t" ] && [ "${t%% *}" != 0 ]; then r=answers; ok=$((ok + 1)); else r="NO ANSWER"; fi
      echo "$i: $r  (received: ${t:-no interface})"
    done
    echo "=== $ok of $n restarts got an answer from the server"
    nmcli con down "$p" >/dev/null 2>&1 ;;
  fail)
    awk '/^--- state at the failure/{on=1} on{print} /^---$/{on=0}' "$HOME_DIR/veroscudo-live.log" ;;
  log)
    tail -n "${2:-40}" /var/log/veroscudo.log ;;
  status)
    veroscudo status ;;
  profiles)
    veroscudo profiles ;;
  use)
    shift; [ $# -gt 0 ] || { echo "vt use <profile>   (vt profiles lists them)"; exit 1; }
    veroscudo use "$*" && veroscudo status | head -3 ;;
  hdiag)
    cfgp=/var/lib/hiddify-admin-bgservice/core/work/data/current-config.json
    echo "Hiddify service: $(systemctl is-active HiddifyAdminBG 2>&1)   processes: $(pgrep -il hiddify | awk '{print $2}' | sort | uniq -c | xargs)"
    echo "tun interfaces: $(ip -br addr | awk '$1 ~ /^tun/ {print $1, $2, $3}' | paste -sd';')"
    echo "config: $(stat -c '%A %U changed %y' "$cfgp" 2>&1 | cut -c1-60)"
    PYTHONPATH=/opt/veroscudo/lib python3 -I -c '
import sys; sys.path.insert(0, "/opt/veroscudo/lib")
from veroscudo import hiddify
p = sys.argv[1]
try:
    c = hiddify.read_config(p)
except Exception as e:
    print("VeroScudo cannot read it:", type(e).__name__, str(e)[:80]); raise SystemExit
eps, dropped = hiddify.endpoints(c)
print("tun from config:", hiddify.tun_settings(c), "| servers:", len(eps), [str(h) + ":" + str(pt) + "/" + "+".join(pr) for h, pt, pr in eps][:4], "| dropped:", len(dropped))
print("Hiddify running:", hiddify.running(), "| its tunnel now:", hiddify.tunnel(p))' "$cfgp"
    echo "shared for the tray: $(cat /run/veroscudo/hiddify-tun.json 2>&1)"
    veroscudo status | grep -E "^(armed|connected|state|tunnel) "
    echo "guard log:"; tail -n 10 /var/log/veroscudo.log | cut -c12-150
    echo "kill-switch permits:"; nft list table inet veroscudo 2>/dev/null | grep -E "daddr|ifname" | grep -v -E "dport 53 |/(8|10|12|16|24) " | head -8 | cut -c1-110
    echo "Hiddify's own connections (peer):"; ss -tunpH 2>/dev/null | grep -i hiddify | awk '{print $1, $6}' | sort | uniq -c | head -8
    echo "exit address now: $(curl -s --max-time 6 https://ifconfig.me || echo none)" ;;
  cgtest)
    cg="system.slice/HiddifyAdminBG.service"
    [ -d "/sys/fs/cgroup/$cg" ] || { echo "no cgroup /sys/fs/cgroup/$cg - is Hiddify's service running?"; exit 1; }
    nft delete table inet vscgtest 2>/dev/null
    if ! printf 'table inet vscgtest {\n chain o {\n  type filter hook output priority 10; policy accept;\n  socket cgroupv2 level 2 "%s" counter\n }\n}\n' "$cg" | nft -f -; then
      echo "RESULT: nftables cannot match a cgroup here (kernel: $(uname -r))"; exit 1
    fi
    sleep 5
    n="$(nft list table inet vscgtest | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+')"
    nft delete table inet vscgtest
    echo "RESULT: the rule works; Hiddify's service sent ${n:-0} packets in 5 s (more than 0 = it matches its traffic)" ;;
  hfix)
    owner_name="$OWNER"; [ "$owner_name" = root ] && { echo "run it as your user: vt hfix"; exit 1; }
    (cd /opt/hiddify && ./HiddifyCli admin_bgservice install "$owner_name")
    [ -e /var/lib/hiddify-admin-bgservice/lib ] || ln -s /opt/hiddify/lib /var/lib/hiddify-admin-bgservice/lib
    systemctl restart HiddifyAdminBG; sleep 2
    echo "Hiddify service: $(systemctl is-active HiddifyAdminBG)" ;;
  boot)
    # monotonic microseconds since boot: the kill-switch unit has to finish before NetworkManager starts
    show() { systemctl show -p "$2" --value "$1" 2>/dev/null; }
    ks_end="$(show veroscudo-boot.service ExecMainExitTimestampMonotonic)"; ks_rc="$(show veroscudo-boot.service ExecMainStatus)"
    nm_start="$(show NetworkManager.service ExecMainStartTimestampMonotonic)"
    echo "kill-switch at boot: exit code ${ks_rc:-?}, done at ${ks_end:-?} us; NetworkManager started at ${nm_start:-?} us"
    if [ "${ks_rc:-1}" = 0 ] && [ "${ks_end:-0}" -gt 0 ] && [ "${nm_start:-0}" -gt "$ks_end" ]; then
      echo "OK - the kill-switch was in place before the network started"
    else
      echo "PROBLEM - not before the network (or it failed):"; journalctl -b -u veroscudo-boot --no-pager | tail -5
    fi
    nft list table inet veroscudo >/dev/null 2>&1 && echo "kill-switch table: present" || echo "kill-switch table: MISSING"
    veroscudo status | head -4
    echo "exit address now: $(curl -s --max-time 5 https://ifconfig.me || echo none)" ;;
  gone)
    left=()
    for f in /opt/veroscudo /usr/share/veroscudo /usr/local/bin/veroscudo /etc/systemd/system/veroscudo.service \
             /etc/systemd/system/veroscudo-boot.service /etc/sudoers.d/veroscudo /etc/xdg/autostart/veroscudo-tray.desktop \
             /usr/share/applications/veroscudo.desktop /run/veroscudo /var/lib/veroscudo/armed.flag; do
      [ -e "$f" ] && left+=("$f")
    done
    nft list table inet veroscudo >/dev/null 2>&1 && left+=("nftables table inet veroscudo")
    procs="$(pgrep -af 'bin/veroscudo|-m veroscudo' | cut -c1-70 | paste -sd';')"
    [ -n "$procs" ] && left+=("processes: $procs")
    if [ "${#left[@]}" -eq 0 ]; then echo "OK - nothing of VeroScudo left"; else echo "LEFT:"; printf '  %s\n' "${left[@]}"; fi
    for f in /etc/veroscudo/config.json /var/log/veroscudo.log; do [ -e "$f" ] && echo "kept (removed only by --purge): $f"; done
    echo "network: $(curl -s --max-time 5 https://ifconfig.me || echo NONE)" ;;
  *)
    sed -n '2,15p' "$SELF" | sed 's/^# \{0,1\}//' ;;
esac
