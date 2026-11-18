#!/bin/sh
# Lab for ksbench.py: two network namespaces in a throwaway privileged container - a "physical" LAN, a real
# WireGuard tunnel, a mock VPN client that brings the tunnel back after 5 s, and optionally a mock nft kill-switch.
# Runs the bench against "no kill-switch" and "nft kill-switch" and checks the per-scenario results.
#   docker run --rm --privileged -v "$PWD/bench":/b python:3.12-slim sh /b/tests/lab.sh
set -eu
umask 077
apt-get -qq update >/dev/null
apt-get -qq install -y iproute2 iptables nftables wireguard-tools procps iputils-ping >/dev/null 2>&1

setup() {
    ip netns add srv
    ip netns add cli
    ip link add eth0 netns cli type veth peer name lan netns srv
    ip -n srv addr add 203.0.113.1/24 dev lan
    ip -n srv addr add 3fff:1::1/64 dev lan nodad
    ip -n srv link set lan up
    ip -n cli addr add 203.0.113.2/24 dev eth0
    ip -n cli addr add 3fff:1::2/64 dev eth0 nodad
    ip -n cli link set eth0 up
    ip -n cli link set lo up
    ip -n cli route add default via 203.0.113.1
    ip -n cli -6 route add default via 3fff:1::1
    wg genkey > /tmp/s.key
    wg genkey > /tmp/c.key
    ip -n srv link add wg0 type wireguard
    ip netns exec srv wg set wg0 listen-port 51820 private-key /tmp/s.key \
        peer "$(wg pubkey < /tmp/c.key)" allowed-ips 10.66.0.2/32,fd66::2/128
    ip -n srv addr add 10.66.0.1/24 dev wg0
    ip -n srv link set wg0 up
    mkdir -p /etc/netns/cli
    echo "nameserver 192.0.2.53" > /etc/netns/cli/resolv.conf
}

# mock VPN client: (re)creates the tunnel and its routes, 5 s after it finds it missing
cat > /tmp/vpnclient.sh <<EOF
#!/bin/sh
up() {
    ip link add wg0 type wireguard 2>/dev/null || true
    wg set wg0 private-key /tmp/c.key peer "\$(wg pubkey < /tmp/s.key)" endpoint 203.0.113.1:51820 \
        allowed-ips 0.0.0.0/0,::/0 persistent-keepalive 1
    ip addr replace 10.66.0.2/32 dev wg0
    ip addr replace fd66::2/128 dev wg0 nodad
    ip link set wg0 up
    for r in 0.0.0.0/1 128.0.0.0/1; do ip route replace \$r dev wg0; done
    for r in ::/1 8000::/1; do ip -6 route replace \$r dev wg0; done
}
up
miss=0
while true; do
    ip route replace default via 203.0.113.1 2>/dev/null; ip -6 route replace default via 3fff:1::1 2>/dev/null  # "DHCP"
    if ! ip route get 198.51.100.7 2>/dev/null | grep -q wg0 && ip route show default | grep -q eth0; then
        sleep 5; up; miss=-10  # reconnect only once the network is back; 10 s grace for the handshake
    fi
    if ping -c1 -W1 10.66.0.1 >/dev/null 2>&1; then miss=0; else miss=\$((miss+1)); fi
    if [ \$miss -ge 3 ]; then ip link del wg0; miss=0; fi    # server gone: tear down, reconnect later
    sleep 1
done
EOF

KS='table inet ks {
  chain out { type filter hook output priority 0; policy drop;
    oif lo accept
    oifname "wg0" accept
    ip daddr 203.0.113.1 udp dport 51820 accept
    udp dport { 67, 68, 546, 547 } accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept
  }
}'

result() {   # result <report> <id>
    python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(next(s['status'] for s in d['scenarios'] if s['id']==sys.argv[2]))" "$1" "$2"
}

expect() {   # expect <report> <id> <status>
    got=$(result "$1" "$2")
    if [ "$got" = "$3" ]; then echo "  ok   $2 = $got"; else echo "  FAIL $2 = $got (expected $3)"; FAILED=1; fi
}

FAILED=0
for mode in none ks; do
    echo "=== lab: $mode ==="
    setup
    ip netns exec cli sh /tmp/vpnclient.sh & VPN=$!
    cp /bin/sleep /tmp/ksapp
    ip netns exec cli /tmp/ksapp 100000 &
    [ "$mode" = ks ] && echo "$KS" | ip netns exec cli nft -f -
    sleep 3
    T0=$(date +%s)
    ip netns exec cli python3 /b/ksbench.py --product "lab-$mode" --no-online --yes  \
        --app-process ksapp --out /tmp/r-$mode.json < /dev/null || true
    echo "  run time: $(( $(date +%s) - T0 )) s (limit 180)"
    [ $(( $(date +%s) - T0 )) -le 180 ] || { echo "  FAIL longer than 3 minutes"; FAILED=1; }
    kill $VPN 2>/dev/null || true
    pkill -x ksapp 2>/dev/null || true
    # every change must be undone: no bench rules left, adapters up
    if ip netns exec cli iptables -S | grep -q 198.51.100 || ip netns exec cli nft list tables | grep -q ksbench; then
        echo "  FAIL rules left behind"; FAILED=1
    else echo "  ok   no rules left behind"; fi
    ip -n cli link show eth0 | grep -q "state UP" && echo "  ok   eth0 is up" || { echo "  FAIL eth0 down"; FAILED=1; }
    R=/tmp/r-$mode.json
    if [ "$mode" = none ]; then
        expect $R S1 pass; expect $R S2 pass; expect $R S3 fail; expect $R S4 pass
        expect $R D1 fail; expect $R D2 n/a; expect $R D3 fail; expect $R D4 fail; expect $R D5 fail
        expect $R T1 fail; expect $R T2 fail
    else
        for s in S1 S2 S3 S4 D1 D3 D4 D5 T1 T2; do expect $R $s pass; done
        expect $R D2 n/a
    fi
    python3 -c "import json; print('  score', json.load(open('$R'))['score'])"
    ip netns del cli
    ip netns del srv
done

echo "=== lab: --restore after a killed run ==="
setup
ip netns exec cli sh /tmp/vpnclient.sh & VPN=$!
sleep 3
ip netns exec cli python3 /b/ksbench.py --no-online --yes --only D1 --hold 60 --product x < /dev/null > /tmp/k.log 2>&1 &
B=$!
for _ in $(seq 1 40); do ip netns exec cli iptables -S | grep -q "203.0.113.1" && break; sleep 0.5; done
kill -9 $B
ip netns exec cli iptables -S | grep -q "203.0.113.1" && echo "  ok   rule present after kill -9" || { echo "  FAIL no rule"; FAILED=1; }
ip netns exec cli python3 /b/ksbench.py --restore
ip netns exec cli iptables -S | grep -q "203.0.113.1" && { echo "  FAIL rule left"; FAILED=1; } || echo "  ok   --restore removed it"
kill $VPN 2>/dev/null || true

[ $FAILED = 0 ] && echo "LAB PASSED" || { echo "LAB FAILED"; exit 1; }
