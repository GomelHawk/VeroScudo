#!/usr/bin/env bash
# Automated kill-switch test on a real Linux machine with a real VPN (best in a VM: blocking it blocks nothing else).
# Needs VeroScudo installed with a NetworkManager VPN profile that connects. Runs everything itself, about 6 minutes:
#   1 On          -> protected; the exit address must be the VPN's, not your real one
#   2 Reconnect   -> blocked while it redials, protected again
#   3 The VPN dies (its process is killed) -> blocked within 10 s, redialed, protected again
#   4 Network drop: the network card goes down for DROP_SECONDS -> nothing gets out; afterwards the tunnel carries again
#     (a VPN over TCP may survive a short drop - then VeroScudo rightly stays protected)
#   5 You hang up the VPN (nmcli connection down) -> VeroScudo turns off, network normal
#   6 On, then Off -> the kill-switch table is gone, network normal
# A probe runs every 2 s the whole time: the exit address (https://ifconfig.me), a direct ping and a direct DNS query to
# 1.1.1.1. LEAK = while protected, an address seen while VeroScudo was off (behind NAT or another VPN there can be
# several); while blocked, anything at all getting out.
#     sudo linux/tests-local/live.sh             in the machine's own window (armed, inbound SSH is blocked)
#     sudo -b linux/tests-local/live.sh          over SSH: runs on when SSH drops; read the log afterwards
# Log: ~/veroscudo-live.log of the user who ran sudo, with VeroScudo's own log lines of the test. Exit code 0 = PASS.
set -u
DROP_SECONDS="${DROP_SECONDS:-30}"
[ "$(id -u)" -eq 0 ] || { echo "run it with sudo: sudo $0"; exit 2; }
command -v veroscudo >/dev/null || { echo "VeroScudo is not installed (linux/install.sh)"; exit 2; }
command -v dig >/dev/null || { echo "dig is missing: sudo apt install dnsutils"; exit 2; }
OWNER="${SUDO_USER:-root}"
LOG="$(getent passwd "$OWNER" | cut -d: -f6)/veroscudo-live.log"
SAMPLES="$(mktemp)"
: > "$LOG"; chown "$OWNER" "$LOG" 2>/dev/null
PHASE=prep
FAILS=()
NIC=""
PROBE_PID=""

say() { echo "$(date +%T) $*" | tee -a "$LOG"; }
field() { veroscudo status 2>/dev/null | awk -F' *: ' -v k="$1" '$1 == k {print $2; exit}'; }   # one line of the status
state() { field state; }
exit_ip() { curl -s --max-time 3 https://ifconfig.me || true; }
off_addr() {     # $1 was seen as the exit address while VeroScudo was off
  { echo "$REAL_IP"; awk '$3 == "off" && $4 == "off" && $5 != "BLOCKED" {print $5}' "$SAMPLES"; } | grep -Fxq -- "$1"
}
carries() {      # the tunnel carries traffic: an exit address not seen while off, within 20 s
  local i x
  for i in 1 2 3 4 5 6 7 8 9 10; do
    x=$(exit_ip); [ -n "$x" ] && ! off_addr "$x" && return 0
    sleep 1; : "$i"
  done
  return 1
}
off_list() { { echo "$REAL_IP"; awk '$3 == "off" && $4 == "off" && $5 != "BLOCKED" {print $5}' "$SAMPLES"; } | sort -u | paste -sd' '; }
fail() { FAILS+=("$PHASE: $*"); say "FAIL $PHASE: $*"; }

wait_state() {   # $1 wanted state, $2 timeout s -> prints the seconds it took; 1 = timeout
  local t0=$SECONDS
  while [ $((SECONDS - t0)) -lt "$2" ]; do
    [ "$(state)" = "$1" ] && { echo $((SECONDS - t0)); return 0; }
    sleep 1
  done
  return 1
}

probe_loop() {   # one line per probe: phase state-before state-after ip ping dns
  while true; do
    local s1 ip p d s2
    s1=$(state); s1=${s1:-none}; ip=$(exit_ip); [ -n "$ip" ] || ip=BLOCKED
    if ping -c1 -W1 1.1.1.1 >/dev/null 2>&1; then p=ping-ok; else p=ping-blocked; fi
    if dig +time=1 +tries=1 @1.1.1.1 example.com >/dev/null 2>&1; then d=dns-ok; else d=dns-blocked; fi
    s2=$(state); s2=${s2:-none}
    echo "$(date +%T) $(cat "$SAMPLES.phase" 2>/dev/null || echo prep) $s1 $s2 $ip $p $d" >> "$SAMPLES"
    sleep 1
  done
}
phase() { PHASE=$1; echo "$1" > "$SAMPLES.phase"; say "=== $1"; }

# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
  [ -n "$PROBE_PID" ] && kill "$PROBE_PID" 2>/dev/null
  if [ -n "$NIC" ] && ! ip link show dev "$NIC" | grep -q '[<,]UP[,>]'; then ip link set dev "$NIC" up; say "network card $NIC brought back up"; fi
  rm -f "$SAMPLES" "$SAMPLES.phase"
}
trap cleanup EXIT
trap 'say "interrupted - VeroScudo is left as it is (sudo veroscudo off for normal network)"; exit 3' INT TERM

PROFILE=$(field profile | sed 's/ ([^)]*)$//')
[ -n "$PROFILE" ] || { echo "no VeroScudo profile configured"; exit 2; }
nmcli -g NAME connection show | grep -Fxq "$PROFILE" || { echo "NetworkManager has no connection '$PROFILE'"; exit 2; }
START=$(date '+%F %T')
say "VeroScudo live test - profile '$PROFILE', network drop ${DROP_SECONDS} s"

# ---- prep: off, VPN down, learn the network card and the real address
phase prep
veroscudo off >/dev/null 2>&1
nmcli connection down "$PROFILE" >/dev/null 2>&1
sleep 3
NIC=$(ip -o route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
[ -n "$NIC" ] || { say "no default route - is the network up?"; NIC=""; exit 2; }
case "$NIC" in ppp*|tun*|wg*) say "the default route is still on $NIC - turn the VPN off first"; NIC=""; exit 2 ;; esac
say "network card: $NIC"
REAL_IP=$(exit_ip)
[ -n "$REAL_IP" ] || { say "no internet without the VPN - nothing to test"; exit 2; }
say "real address (without VPN): $REAL_IP"
probe_loop & PROBE_PID=$!

# ---- 1 On
phase 1-on
veroscudo on >/dev/null 2>&1
if t=$(wait_state protected 90); then say "protected after $t s"; else fail "not protected within 90 s"; fi
sleep 15
VPN_IP=$(exit_ip)
say "exit address while protected: ${VPN_IP:-none}"
[ -n "$VPN_IP" ] || fail "no answer through the tunnel"
[ -z "$VPN_IP" ] || ! off_addr "$VPN_IP" || fail "exit address is the real one - traffic does not go through the VPN"

# ---- 2 Reconnect
phase 2-reconnect
t0=$SECONDS
veroscudo reconnect >/dev/null 2>&1                               # blocks, hangs up, dials once, returns
if wait_state protected 120 >/dev/null; then say "protected again after $((SECONDS - t0)) s"; else fail "not protected again within 120 s"; fi
sleep 10

# ---- 3 The VPN dies
phase 3-vpn-dies
TUN=$(field tunnel)
case "$TUN" in
  ppp*) VPNPROC=pppd ;;
  tun*) VPNPROC=$(pgrep -x openvpn >/dev/null && echo openvpn || echo openconnect) ;;
  *) VPNPROC="" ;;
esac
if [ -z "$VPNPROC" ]; then
  say "tunnel '${TUN:-none}': no VPN process to kill for this type - step skipped"
else
  pkill -KILL -x "$VPNPROC"
  say "killed $VPNPROC (tunnel $TUN)"
  if t=$(wait_state blocked 10); then say "blocked $t s after the VPN died"; else fail "not blocked within 10 s after the VPN died (state '$(state)')"; fi
  if t=$(wait_state protected 120); then say "protected again after $t s"; else fail "not protected again within 120 s"; fi
  carries || fail "protected, but the tunnel carries nothing"
fi
sleep 10

# ---- 4 Network drop
phase 4-drop
ip link set dev "$NIC" down
say "network card $NIC down"
seen=""
for _ in $(seq 1 "$DROP_SECONDS"); do
  [ -z "$seen" ] && [ "$(state)" = blocked ] && seen=$((SECONDS))
  sleep 1
done
ip link set dev "$NIC" up
say "network card $NIC up"
if [ -n "$seen" ]; then say "VeroScudo saw the drop (blocked during it)"; else say "VeroScudo stayed protected: the VPN survived the drop"; fi
sleep 10
if ! ip -o -4 addr show dev "$NIC" | grep -q inet; then              # NetworkManager did not reconnect the card by itself
  say "no address on $NIC after 10 s - asking NetworkManager to connect it"
  nmcli device connect "$NIC" >/dev/null 2>&1
fi
if t=$(wait_state protected 180); then say "protected $t s after the network came back"; else fail "not protected within 180 s after the network came back"; fi
carries || fail "protected, but the tunnel carries nothing"
sleep 10

# ---- 5 You hang up
phase 5-hangup
nmcli connection down "$PROFILE" >/dev/null 2>&1
if t=$(wait_state off 30); then say "VeroScudo off $t s after you hung up"; else fail "still '$(state)' 30 s after you hung up (expected off)"; fi
sleep 5
[ -n "$(exit_ip)" ] || fail "no network after hanging up"

# ---- 6 On, then Off
phase 6-off
veroscudo on >/dev/null 2>&1
if ! wait_state protected 90 >/dev/null; then fail "not protected within 90 s"; fi
veroscudo off >/dev/null 2>&1
sleep 3
[ "$(state)" = off ] || fail "state '$(state)' after Off"
nft list table inet veroscudo >/dev/null 2>&1 && fail "kill-switch table still present after Off"
[ -n "$(exit_ip)" ] || fail "no network after Off"
kill "$PROBE_PID" 2>/dev/null; PROBE_PID=""

# ---- verdict from the probes
leaks=0; n=0; blocked=0
while read -r tm ph s1 s2 ipx p d; do
  n=$((n + 1))
  [ "$s1" = "$s2" ] || continue                                    # the state changed during this probe
  why=""
  case "$s1" in
    blocked) blocked=$((blocked + 1))
             if [ "$ipx" != BLOCKED ] || [ "$p" = ping-ok ] || [ "$d" = dns-ok ]; then why="got out while blocked"; fi ;;
    protected) [ "$ipx" != BLOCKED ] && off_addr "$ipx" && why="an address seen while off, while protected" ;;
  esac
  if [ -n "$why" ]; then leaks=$((leaks + 1)); say "LEAK $tm [$ph] $why: ip=$ipx $p $d"; fi
done < "$SAMPLES"
[ "$blocked" -gt 0 ] || fail "no probe ran while blocked"
say "=== VeroScudo log during the test"
awk -v s="$START" '($1 " " substr($2, 1, 8)) >= s' /var/log/veroscudo.log 2>/dev/null | tee -a "$LOG"
say "=== Result"
say "probes $n (blocked $blocked), leaks $leaks, VPN ${VPN_IP:-none}, without VPN: $(off_list)"
[ "$leaks" -eq 0 ] || FAILS+=("leaks: $leaks")
if [ ${#FAILS[@]} -eq 0 ]; then say "PASS"; exit 0; fi
for f in "${FAILS[@]}"; do say "  - $f"; done
say "FAIL - send the whole log: cat $LOG"
exit 1
