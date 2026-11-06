#!/bin/bash
# 30.07 VPS-only test network (run as root). Namespaces only: nothing on the host network changes.
#   fwc (client + finalwisp)  10.88.0.1 / fd88::1  <-- veth, netem 25 ms each way -->  fwt (targets) 10.88.0.2 / fd88::2
#   dead addresses (silently dropped by a dummy device in fwc): 10.99.0.5, 2a00:dead::5
set -e
ip netns del fwc 2>/dev/null || true; ip netns del fwt 2>/dev/null || true
ip netns add fwc; ip netns add fwt
ip -n fwc link set lo up; ip -n fwt link set lo up
ip link add vc netns fwc type veth peer name vt netns fwt
ip -n fwc addr add 10.88.0.1/24 dev vc; ip -n fwt addr add 10.88.0.2/24 dev vt
ip -n fwc addr add fd88::1/64 dev vc nodad; ip -n fwt addr add fd88::2/64 dev vt nodad
ip -n fwc link set vc up; ip -n fwt link set vt up
ip netns exec fwc tc qdisc add dev vc root netem delay 25ms limit 100000
ip netns exec fwt tc qdisc add dev vt root netem delay 25ms limit 100000
ip -n fwc link add d0 type dummy; ip -n fwc link set d0 up
ip -n fwc addr add 10.99.0.1/24 dev d0; ip -n fwc addr add 2a00:dead::1/64 dev d0 nodad
ip netns exec fwc sysctl -qw net.ipv4.tcp_fastopen=1
ip netns exec fwt sysctl -qw net.ipv4.tcp_fastopen=3
mkdir -p /etc/netns/fwc
cat > /etc/netns/fwc/hosts <<EOF
127.0.0.1 localhost
::1 localhost
10.99.0.5 dead4first
fd88::2 dead4first
2a00:dead::5 dead6first
10.88.0.2 dead6first
10.88.0.2 tgt4
10.99.0.5 deadpair4
10.88.0.2 deadpair4
EOF
ip netns exec fwc ping -c 2 -q 10.88.0.2 | tail -1
echo ok
