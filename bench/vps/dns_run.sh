#!/bin/bash
# 30.09 (20.19) DNS resolver-pool experiment (VPS, root). Needs the netns from netns_hol.sh (server side = fws).
# A stub resolver (slowdns.py, DELAY ms per query) answers inside fws; finalwisp variants run against it:
# page bursts (dns_burst.py), pool head-of-line behind a 3 s name and NXDOMAIN fan-out (dns_hol.py).
# env: FW_DIR (binaries + scripts, default: this dir), DELAY (20), REPS ("1 2 3"), PORT (6901), TPORT (6902)
# Variants: --no-dns-coalesce / --dns-threads 4 (old behaviour) vs defaults.
# Historical (60.18): --no-dns-coalesce was removed in base-4; the base* variants need a base-3 or older binary.
cd "${FW_DIR:-$(dirname "$0")}"
PORT=${PORT:-6901}; TPORT=${TPORT:-6902}
mkdir -p /etc/netns/fws; echo "nameserver 127.0.0.1" > /etc/netns/fws/resolv.conf
X="ip netns exec fws"
$X python3 slowdns.py 127.0.0.1 53 ${DELAY:-20} 127.0.0.1 2>slowdns.err & DNSPID=$!
$X ./wbench target --port $TPORT --mode reply >/dev/null 2>&1 & TPID=$!
sleep 0.5
for rep in ${REPS:-1 2 3}; do
for v in "base4:--no-dns-coalesce --dns-threads 4" "coalesce4:--dns-threads 4" "base16:--no-dns-coalesce --dns-threads 16" "coalesce16:"; do
  name=${v%%:*}; flags=${v#*:}
  $X ./finalwisp --port $PORT --allow-loopback $flags >/dev/null 2>&1 & SPID=$!
  sleep 0.3
  for case in "1 6" "3 6" "6 1" "6 6"; do
    set -- $case
    r=$($X python3 dns_burst.py 127.0.0.1:$PORT $TPORT 15 $1 $2 slow)
    echo "{\"variant\": \"$name\", \"rep\": $rep, \"res\": $r}"
  done
  r=$($X python3 dns_hol.py 127.0.0.1:$PORT $TPORT 2 6 slow3 slow); echo "{\"variant\": \"$name\", \"rep\": $rep, \"hol\": $r}"
  r=$($X python3 dns_hol.py 127.0.0.1:$PORT $TPORT 3 6 nx slow); echo "{\"variant\": \"$name\", \"rep\": $rep, \"nx\": $r}"
  kill $SPID; wait $SPID 2>/dev/null
done
done
kill $DNSPID $TPID; wait 2>/dev/null
rm -f /etc/netns/fws/resolv.conf
