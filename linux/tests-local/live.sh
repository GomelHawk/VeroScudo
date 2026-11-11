#!/usr/bin/env bash
# Kill-switch test on a real Linux machine with a real VPN (best in a VM: blocking it blocks nothing else). Tests the
# ACTIVE profile - switch first with `sudo veroscudo use <profile>`. About 6 minutes:
#   1 On          -> protected; the exit address must be the VPN's
#   2 Reconnect   -> protected again                      (Hiddify: you disconnect in Hiddify -> stays blocked; you connect)
#   3 The VPN dies (its process killed; WireGuard: its interface removed) -> blocked within 10 s, protected again
#                                                          (Hiddify: Hiddify is killed -> blocked; you start it again)
#   4 Network drop: the network card goes down for DROP_SECONDS -> nothing gets out; afterwards the tunnel carries again
#     (a VPN may survive a short drop - then VeroScudo rightly stays protected)
#   5 You hang up the VPN (nmcli connection down) -> VeroScudo turns off, network normal        (Hiddify: step 2)
#   6 On, then Off -> the kill-switch table is gone, the network answers
# NetworkManager VPNs (SSTP, L2TP, PPTP, OpenVPN, WireGuard) run without you. VeroScudo never connects Hiddify, so for a
# Hiddify profile the script says ">>> DO NOW: ..." when you have to act in Hiddify, and waits until it sees the result.
# A probe runs every 2 s the whole time: the exit address (https://ifconfig.me), a direct ping and a direct DNS query to
# an address the kill-switch does not allow. LEAK = while protected, an address seen without any VPN; while blocked,
# anything at all getting out.
#     sudo linux/tests-local/live.sh             in the machine's own window (armed, inbound SSH is blocked)
#     sudo -b linux/tests-local/live.sh          over SSH (not for Hiddify): runs on when SSH drops; read the log afterwards
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
todo() { printf '\a'; say ">>> DO NOW: $*"; }                    # Hiddify: what you do in Hiddify
field() { veroscudo status 2>/dev/null | awk -F' *: ' -v k="$1" '$1 == k {print $2; exit}'; }   # one line of the status
state() { field state; }
exit_ip() { curl -s --max-time 3 https://ifconfig.me || true; }
fail() { FAILS+=("$PHASE: $*"); say "FAIL $PHASE: $*"; diag; }
diag() {   # the network state at a failure, into the log - before anything changes it (no clipboard in a VM)
  {
    echo "--- state at the failure ($PHASE)"
    veroscudo status 2>&1 | head -6
    echo "ip rule:"; ip rule 2>&1
    echo "routes:"; ip route show table all 2>&1 | grep -v -E "^(local|broadcast|multicast) |table local" | head -20
    echo "WireGuard:"; wg show 2>&1 | grep -E "interface|endpoint|handshake|transfer" || echo "(none)"
    echo "marks (NetworkManager 0xcafd / VeroScudo 0x5653):"; nft list ruleset 2>/dev/null | grep -c -E "cafd|0x5653"
    echo "ping 1.1.1.1 (whatever is in force now):"; ping -c 2 -W 2 1.1.1.1 2>&1 | tail -2
    echo "---"
  } >> "$LOG" 2>&1
}
phase() { PHASE=$1; echo "$1" > "$SAMPLES.phase"; say "=== $1"; }

wait_state() {   # $1 wanted state, $2 timeout s -> prints the seconds it took; 1 = timeout
  local t0=$SECONDS
  while [ $((SECONDS - t0)) -lt "$2" ]; do
    [ "$(state)" = "$1" ] && { echo $((SECONDS - t0)); return 0; }
    sleep 1
  done
  return 1
}
wait_connected() {   # $1 True|False (the active profile's tunnel), $2 timeout s
  local t0=$SECONDS
  while [ $((SECONDS - t0)) -lt "$2" ]; do
    [ "$(field connected)" = "$1" ] && return 0
    sleep 1
  done
  return 1
}

# addresses seen with no VPN at all: in prep, and - NetworkManager VPNs only - while off after the hang-up and after Off
# (with Hiddify, VeroScudo off still leaves Hiddify's tunnel up)
off_addrs() {
  cat "$SAMPLES.real"
  [ "$TYPE" = hiddify ] || awk '($2 == "5-hangup" || $2 == "6-off") && $3 == "off" && $4 == "off" && $5 != "BLOCKED" {print $5}' "$SAMPLES"
}
off_addr() { off_addrs | grep -Fxq -- "$1"; }
off_list() { off_addrs | sort -u | paste -sd' '; }
carries() {      # the tunnel carries traffic: an exit address not seen without VPN, within ~45 s
  local i x
  for i in $(seq 15); do
    x=$(exit_ip); [ -n "$x" ] && ! off_addr "$x" && return 0
    sleep 1; : "$i"
  done
  return 1
}

kill_vpn() {     # the VPN dies: its process killed (WireGuard: its interface removed); TUN = the tunnel, "" when skipped
  TUN=$(field tunnel)
  case "$TYPE:$TUN" in
    hiddify:*) pkill -KILL -i hiddify; say "killed Hiddify (tunnel $TUN)" ;;
    wireguard:*) ip link delete dev "$TUN"; say "removed the WireGuard interface $TUN" ;;
    openvpn:?*) pkill -KILL -x openvpn; say "killed openvpn (tunnel $TUN)" ;;
    *:ppp*) pkill -KILL -x pppd; say "killed pppd (tunnel $TUN)" ;;
    *:tun*|*:vpn*) pkill -KILL -x openconnect; say "killed openconnect (tunnel $TUN)" ;;
    *) say "tunnel '${TUN:-none}': no VPN process to kill for this type - step skipped"; TUN="" ;;
  esac
}

probe_loop() {   # one line per probe: time phase state-before state-after ip ping dns
  local tgt s1 ip p d s2
  tgt=$(cat "$SAMPLES.target")
  while true; do
    s1=$(state); s1=${s1:-none}; ip=$(exit_ip); [ -n "$ip" ] || ip=BLOCKED
    if ping -c1 -W1 "$tgt" >/dev/null 2>&1; then p=ping-ok; else p=ping-blocked; fi
    if dig +time=1 +tries=1 "@$tgt" example.com >/dev/null 2>&1; then d=dns-ok; else d=dns-blocked; fi
    s2=$(state); s2=${s2:-none}
    echo "$(date +%T) $(cat "$SAMPLES.phase") $s1 $s2 $ip $p $d" >> "$SAMPLES"
    sleep 1
  done
}

probe_now() {   # one quick probe right now (the loop may miss a short blocked window: a fast redial)
  local tgt s1 ip p d s2
  tgt=$(cat "$SAMPLES.target")
  s1=$(state); s1=${s1:-none}
  ip=$(curl -s --max-time 2 https://ifconfig.me || true); [ -n "$ip" ] || ip=BLOCKED
  if ping -c1 -W1 "$tgt" >/dev/null 2>&1; then p=ping-ok; else p=ping-blocked; fi
  if dig +time=1 +tries=1 "@$tgt" example.com >/dev/null 2>&1; then d=dns-ok; else d=dns-blocked; fi
  s2=$(state); s2=${s2:-none}
  echo "$(date +%T) $(cat "$SAMPLES.phase") $s1 $s2 $ip $p $d" >> "$SAMPLES"
}

# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
  [ -n "$PROBE_PID" ] && kill "$PROBE_PID" 2>/dev/null
  nft delete table inet vstest 2>/dev/null && say "the test's own block of the VPN server removed"
  if [ -n "$NIC" ] && ! ip link show dev "$NIC" | grep -q '[<,]UP[,>]'; then ip link set dev "$NIC" up; say "network card $NIC brought back up"; fi
  rm -f "$SAMPLES" "$SAMPLES.phase" "$SAMPLES.target" "$SAMPLES.real"
}
trap cleanup EXIT
trap 'say "interrupted - VeroScudo is left as it is (sudo veroscudo off for normal network)"; exit 3' INT TERM

P=$(field profile)                                               # "Work (WireGuard)"
PROFILE=${P% (*}
case "${P##* (}" in
  "Hiddify VPN mode)") TYPE=hiddify ;;
  "WireGuard)") TYPE=wireguard ;;
  "OpenVPN)") TYPE=openvpn ;;
  *) TYPE=vpn ;;
esac
[ -n "$PROFILE" ] || { echo "no VeroScudo profile configured"; exit 2; }
if [ "$TYPE" != hiddify ]; then
  nmcli -g NAME connection show | grep -Fxq "$PROFILE" || { echo "NetworkManager has no connection '$PROFILE'"; exit 2; }
fi
START=$(date '+%F %T')
: > "$SAMPLES.real"
say "VeroScudo live test - profile '$PROFILE' ($TYPE), network drop ${DROP_SECONDS} s"

# ---- prep: off, VPN down, learn the network card and the address without VPN
phase prep
veroscudo off >/dev/null 2>&1
if [ "$TYPE" = hiddify ]; then
  if [ "$(field connected)" = True ]; then
    todo "disconnect Hiddify (the test needs the address without any VPN first)"
    wait_connected False 180 || { say "Hiddify is still connected - stopped"; exit 2; }
  fi
else
  nmcli connection down "$PROFILE" >/dev/null 2>&1
fi
sleep 3
NIC=$(ip -o route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
[ -n "$NIC" ] || { say "no default route - is the network up?"; NIC=""; exit 2; }
case "$NIC" in ppp*|tun*|wg*) say "the default route is still on $NIC - turn the VPN off first"; NIC=""; exit 2 ;; esac
say "network card: $NIC"
for _ in 1 2 3; do exit_ip >> "$SAMPLES.real"; echo >> "$SAMPLES.real"; done   # it can change (NAT, another VPN outside)
sed -i '/^$/d' "$SAMPLES.real"
REAL_IP=$(head -n1 "$SAMPLES.real")
[ -n "$REAL_IP" ] || { say "no internet without the VPN - nothing to test"; exit 2; }
say "address without VPN: $(off_list)"

# ---- 1 On
phase 1-on
veroscudo on >/dev/null 2>&1
TARGET=""
for t in 1.1.1.1 9.9.9.9 208.67.222.222 8.8.4.4; do              # a probe target the kill-switch does not allow
  nft list table inet veroscudo 2>/dev/null | grep -Fq -- "$t" || { TARGET=$t; break; }
done
[ -n "$TARGET" ] || { fail "every probe address is allowed by the kill-switch"; TARGET=1.1.1.1; }
echo "$TARGET" > "$SAMPLES.target"
say "probe target for ping and DNS: $TARGET"
probe_loop & PROBE_PID=$!
if [ "$TYPE" = hiddify ]; then
  todo "connect Hiddify (VPN mode)"
  if t=$(wait_state protected 180); then say "protected $t s after the request"; else fail "not protected within 180 s"; fi
else
  if t=$(wait_state protected 90); then say "protected after $t s"; else fail "not protected within 90 s"; fi
fi
VPN_IP=""
for _ in $(seq 15); do VPN_IP=$(exit_ip); [ -n "$VPN_IP" ] && break; sleep 2; done   # up to ~45 s for the first answer
say "exit address while protected: ${VPN_IP:-none}"
[ -n "$VPN_IP" ] || fail "no answer through the tunnel"
[ -z "$VPN_IP" ] || ! off_addr "$VPN_IP" || fail "exit address is the one without VPN - traffic does not go through the VPN"

# ---- 2 Reconnect (Hiddify: you disconnect and connect in Hiddify)
if [ "$TYPE" = hiddify ]; then
  phase 2-disconnect
  todo "disconnect in Hiddify"
  if t=$(wait_state blocked 120); then say "blocked $t s after the request"; else fail "not blocked within 120 s (state '$(state)')"; fi
  sleep 10
  [ "$(state)" = blocked ] || fail "state '$(state)' 10 s after you disconnected Hiddify (expected: stays blocked)"
  todo "connect Hiddify again"
  if t=$(wait_state protected 180); then say "protected $t s after the request"; else fail "not protected within 180 s"; fi
else
  phase 2-reconnect
  t0=$SECONDS
  veroscudo reconnect >/dev/null 2>&1                             # blocks, hangs up, dials once, returns
  if wait_state protected 120 >/dev/null; then say "protected again after $((SECONDS - t0)) s"; else fail "not protected again within 120 s"; fi
fi
carries || fail "protected, but the tunnel carries nothing"
sleep 10

# ---- 3 The VPN dies
phase 3-vpn-dies
kill_vpn
if [ -n "$TUN" ]; then
  if t=$(wait_state blocked 10); then say "blocked $t s after the VPN died"; probe_now; else fail "not blocked within 10 s after the VPN died (state '$(state)')"; fi
  if [ "$TYPE" = hiddify ]; then
    todo "start Hiddify again and connect (VPN mode)"
    if t=$(wait_state protected 240); then say "protected $t s after the request"; else fail "not protected within 240 s"; fi
  else
    if t=$(wait_state protected 120); then say "protected again after $t s"; else fail "not protected again within 120 s"; fi
  fi
  carries || fail "protected, but the tunnel carries nothing"
fi
sleep 10

# ---- 4 Network drop
phase 4-drop
ip link set dev "$NIC" down
say "network card $NIC down"
seen=""
for _ in $(seq 1 "$DROP_SECONDS"); do
  [ -z "$seen" ] && [ "$(state)" = blocked ] && seen=yes
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
if [ "$TYPE" = hiddify ] && ! wait_state protected 60 >/dev/null; then
  todo "connect Hiddify again if it dropped"
fi
if t=$(wait_state protected 180); then say "protected $t s later"; else fail "not protected within 180 s after the network came back"; fi
carries || fail "protected, but the tunnel carries nothing"
sleep 10

# ---- 5 You hang up
# ---- 4b The VPN server goes away while the network stays up: VeroScudo must stay blocked the whole time, nothing gets out
if [ "$TYPE" != hiddify ]; then
  phase 4b-unreachable
  srv=$(nft list table inet veroscudo 2>/dev/null | grep -E 'daddr \{.*\} (udp|tcp) dport' | grep -v 'dport 53 ' \
        | grep -oE '\{[^}]*\}' | tr -d '{},' | xargs)
  if [ -z "$srv" ]; then
    fail "no VPN server address found in the kill-switch"
  else
    v4=$(tr ' ' '\n' <<<"$srv" | grep -v : | paste -sd, -); v6=$(tr ' ' '\n' <<<"$srv" | grep : | paste -sd, -)
    {
      echo "table inet vstest {"
      echo "  chain out { type filter hook output priority -50; policy accept;"
      [ -n "$v4" ] && echo "    ip daddr { $v4 } drop"
      [ -n "$v6" ] && echo "    ip6 daddr { $v6 } drop"
      echo "  }"
      echo "}"
    } | nft -f - && say "VPN server unreachable (the test drops $srv)"
    kill_vpn
    if [ -n "$TUN" ]; then
      if t=$(wait_state blocked 60); then
        say "blocked $t s after the VPN died with its server unreachable"
        for _ in 1 2 3; do probe_now; sleep 5; done                  # VeroScudo redials in vain meanwhile
        [ "$(state)" = blocked ] || say "note: state '$(state)' while the server is unreachable"
      else
        fail "not blocked within 60 s with the VPN server unreachable (state '$(state)')"
      fi
    fi
    nft delete table inet vstest && say "VPN server reachable again"
    if t=$(wait_state protected 150); then say "protected again after $t s"; else fail "not protected again within 150 s"; fi
    carries || fail "protected, but the tunnel carries nothing"
  fi
  sleep 10
fi

phase 5-hangup
if [ "$TYPE" = hiddify ]; then
  say "Hiddify: your own disconnect keeps the block (step 2) - nothing more to do here"
else
  nmcli connection down "$PROFILE" >/dev/null 2>&1
  if t=$(wait_state off 30); then say "VeroScudo off $t s after you hung up"; else fail "still '$(state)' 30 s after you hung up (expected off)"; fi
  sleep 5
  [ -n "$(exit_ip)" ] || fail "no network after hanging up"
fi

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
[ "$TYPE" = hiddify ] && say "Hiddify stays connected - VeroScudo never disconnects it"

# ---- verdict from the probes
leaks=0; n=0; blocked=0
while read -r tm ph s1 s2 ipx p d; do
  n=$((n + 1))
  [ "$s1" = "$s2" ] || continue                                    # the state changed during this probe
  why=""
  case "$s1" in
    blocked) blocked=$((blocked + 1))
             if [ "$ipx" != BLOCKED ] || [ "$p" = ping-ok ] || [ "$d" = dns-ok ]; then why="got out while blocked"; fi ;;
    protected) [ "$ipx" != BLOCKED ] && off_addr "$ipx" && why="an address without VPN, while protected" ;;
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
