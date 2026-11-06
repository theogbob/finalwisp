#!/bin/sh
# 30.11 soak: root-only setup for half-open clients (halfopen.py). A client sets IP_TOS 0x28 (DSCP AF11) on
# its connection to the soak servers (7001/7002) and sends one packet: the output rule marks the conntrack
# entry, the input rule drops every packet of a marked connection in both directions. Second rule (base-1.2
# re-soak): the dead-target helper (deadtarget.py, port 7120) marks its own side of a target connection the same way.
# usage (root): soak-nft.sh up | down
set -eu
case "${1:-}" in
up)
  nft -f - <<'EOF'
table inet soak {
  chain out {
    type filter hook output priority 0; policy accept;
    oif "lo" tcp dport { 7001, 7002 } ip dscp af11 ct mark set 0x50a1
    oif "lo" tcp sport 7120 ip dscp af11 ct mark set 0x50a1
  }
  chain in {
    type filter hook input priority 0; policy accept;
    iif "lo" ct mark 0x50a1 counter drop
  }
}
EOF
  ;;
down)
  nft delete table inet soak
  if command -v conntrack >/dev/null; then conntrack -D --mark 0x50a1 >/dev/null 2>&1 || true; fi
  ;;
*) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
