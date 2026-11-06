#!/bin/sh
# 40.14 (70.02) root-only helper for keepalive_dead.py, modelled on soak-nft.sh (30.11): a client sets IP_TOS 0x28
# (DSCP AF11) on its connection to the test server port and sends one packet; the output rule marks the conntrack
# entry, the input rule then drops every packet of that connection in both directions (a peer that vanished:
# no FIN, no RST). Only lo, only the given ports (default 8130-8131).
# usage (root): ka-nft.sh up [PORTLO PORTHI] | down
set -eu
case "${1:-}" in
up)
  lo=${2:-8130}; hi=${3:-8131}
  nft -f - <<EOF
table inet ka {
  chain out {
    type filter hook output priority 0; policy accept;
    oif "lo" tcp dport $lo-$hi ip dscp af11 ct mark set 0x6b61
  }
  chain in {
    type filter hook input priority 0; policy accept;
    iif "lo" ct mark 0x6b61 counter drop
  }
}
EOF
  ;;
down)
  nft delete table inet ka
  if command -v conntrack >/dev/null; then conntrack -D --mark 0x6b61 >/dev/null 2>&1 || true; fi
  ;;
*) echo "usage: $0 up [PORTLO PORTHI] | down" >&2; exit 2 ;;
esac
