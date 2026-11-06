#!/bin/bash
# 30.09 (20.19) VPS-only rate-limited link for head-of-line / fairness tests (root; namespaces only).
#   fwa (wbench client) 10.77.0.1  <-- veth, netem delay $DELAY each way, rate $RATE, limit $LIMIT pkts -->  fws (finalwisp + targets) 10.77.0.2
# usage: netns_hol.sh [RATE=100mbit] [DELAY=10ms] [LIMIT=200]   |   netns_hol.sh down
set -e
if [ "$1" = down ]; then ip netns del fwa 2>/dev/null; ip netns del fws 2>/dev/null; echo down; exit 0; fi
RATE=${1:-100mbit}; DELAY=${2:-10ms}; LIMIT=${3:-200}
ip netns del fwa 2>/dev/null || true; ip netns del fws 2>/dev/null || true
ip netns add fwa; ip netns add fws
ip -n fwa link set lo up; ip -n fws link set lo up
ip link add va netns fwa type veth peer name vs netns fws
ip -n fwa addr add 10.77.0.1/24 dev va; ip -n fws addr add 10.77.0.2/24 dev vs
ip -n fwa link set va up; ip -n fws link set vs up
ip netns exec fwa tc qdisc add dev va root netem delay $DELAY rate $RATE limit $LIMIT
ip netns exec fws tc qdisc add dev vs root netem delay $DELAY rate $RATE limit $LIMIT
ip netns exec fwa ping -c 2 -q 10.77.0.2 | tail -1
echo "ok rate=$RATE delay=$DELAY limit=$LIMIT"
