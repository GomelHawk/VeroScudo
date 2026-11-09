#!/usr/bin/env bash
# Leak probe for the real-machine test (README.md in this folder): run it in a terminal on the machine with VeroScudo,
# as your own user, and leave it running while you go through the walk-through. Stop it with Ctrl-C for the summary.
#     linux/tests-local/probe.sh                 the VPN's exit address is learned from the first "protected" reading
#     linux/tests-local/probe.sh 203.0.113.7     or given
# Every 3 s: VeroScudo's state, the exit address (https://ifconfig.me), a direct ping and a direct DNS query to 1.1.1.1
# (past systemd-resolved). LEAK = while armed, an address other than the VPN's answered, or - while blocked - a ping or
# DNS query got through. A reading during which the state changed is marked "changing" and never counted as a leak.
# Log: ~/veroscudo-probe.log (appended). Read-only: changes nothing.
set -u
VPN_IP="${1:-}"
LOG="$HOME/veroscudo-probe.log"
n=0; leaks=0; blocked=0; protected=0; off=0
state() { veroscudo status 2>/dev/null | awk '/^state/{print $3}'; }
summary() {
  echo "--- $(date '+%F %T') readings $n: protected $protected, blocked $blocked, off $off; LEAKS $leaks; VPN address ${VPN_IP:-unknown}" | tee -a "$LOG"
  exit 0
}
trap summary INT TERM
command -v dig >/dev/null || echo "note: dig not found (sudo apt install dnsutils) - the DNS probe is skipped" | tee -a "$LOG"
echo "--- $(date '+%F %T') probe started; VPN address ${VPN_IP:-to be learned}" | tee -a "$LOG"
while true; do
  s1=$(state)
  ip=$(curl -s --max-time 4 https://ifconfig.me) || ip=""
  [ -n "$ip" ] || ip=BLOCKED
  if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then p=ping-ok; else p=ping-blocked; fi
  if ! command -v dig >/dev/null; then d=dns-n/a
  elif dig +time=2 +tries=1 @1.1.1.1 example.com >/dev/null 2>&1; then d=dns-ok; else d=dns-blocked; fi
  s2=$(state)
  n=$((n + 1))
  flag=""
  if [ "$s1" != "$s2" ]; then
    flag="  (changing: $s1 -> $s2)"
  else
    case "$s1" in
      protected)
        protected=$((protected + 1))
        if [ -z "$VPN_IP" ] && [ "$ip" != BLOCKED ]; then VPN_IP=$ip; flag="  (VPN address learned)"; fi
        if [ -n "$VPN_IP" ] && [ "$ip" != BLOCKED ] && [ "$ip" != "$VPN_IP" ]; then flag="  <<< LEAK: not the VPN address"; fi ;;
      blocked)
        blocked=$((blocked + 1))
        if { [ "$ip" != BLOCKED ] && [ "$ip" != "$VPN_IP" ]; } || [ $p = ping-ok ] || [ $d = dns-ok ]; then
          flag="  <<< LEAK while blocked"
        fi ;;
      off) off=$((off + 1)) ;;
    esac
  fi
  case "$flag" in *LEAK*) leaks=$((leaks + 1)) ;; esac
  echo "$(date +%T) state=${s2:-?} ip=$ip $p $d$flag" | tee -a "$LOG"
  sleep 3
done
