#!/usr/bin/env bash
# Short commands for testing in a VM without a clipboard. Each run first updates the repo (git pull as you), so a new
# check only needs a commit on the other side - never a long command typed by hand.
#   once:   sudo linux/tests-local/vt.sh install      -> afterwards just: vt <command>
#   vt live            the kill-switch live test (live.sh)
#   vt wgcycle [N]     VeroScudo stopped; the active WireGuard profile restarted N times (6) - does its handshake answer?
#   vt fail            the network state saved at each failure of the last live test
#   vt log [N]         VeroScudo's last N log lines (40)
#   vt status          VeroScudo's status
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
  *)
    sed -n '2,9p' "$SELF" | sed 's/^# \{0,1\}//' ;;
esac
