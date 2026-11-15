#!/bin/bash
# 20.13 / 40.04 TLS test runner: wss:// wisp-js suite (incl. 2x64 MiB download = splice through kTLS),
# 40.03 adversarial suite over TLS, 40.04 TLS adversarial + openssl s_client matrix, 40.05 nonces, 40.09 extras.
# usage: tests/compat/run_tls.sh [FINALWISP_BINARY] [PORT]   (needs: `tls` kernel module loaded, node, python3, openssl)
set -u
cd "$(dirname "$0")/../.."
BIN=${1:-server/target/release/finalwisp}; PORT=${2:-7650}; NODE=${NODE:-node}
# 80.03: WST_TLS_PART=k/5 runs one part of the sections on a server of its own (wst compat --shards tls=5): 1 = wisp-js over
# wss (3 runs) + tls_nonce, 2..4 = adversarial.py --tls with WST_CASES=1/3..3/3, 5 = tls_adversarial + tls_extras.
# Unset: every section, as before.
PART=${WST_TLS_PART:-}
case "$PART" in ""|1/5|2/5|3/5|4/5|5/5) ;; *) echo "FAIL run_tls: WST_TLS_PART=$PART (k/5 or unset)"; exit 2 ;; esac
part() { [ -z "$PART" ] || [ "$PART" = "$1" ]; }
ADV=""; case "$PART" in 2/5) ADV=1/3 ;; 3/5) ADV=2/3 ;; 4/5) ADV=3/3 ;; esac
mkdir -p tests/certs
(  # 80.02: under a lock, so that two gates in a fresh clone do not write the pair at the same moment (pcompat.py takes it too)
  flock 9
  if [ ! -f tests/certs/cert.pem ]; then  # test-only self-signed cert (gitignored)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=localhost \
      -keyout tests/certs/key.pem -out tests/certs/cert.pem 2>/dev/null
  fi
) 9> tests/certs/.lock
"$BIN" --port "$PORT" --allow-loopback --tls-cert tests/certs/cert.pem --tls-key tests/certs/key.pem > "/tmp/fw-tls-$PORT.log" 2>&1 &
SRV=$!; trap 'kill $SRV 2>/dev/null' EXIT; sleep 0.5
kill -0 $SRV 2>/dev/null || { cat "/tmp/fw-tls-$PORT.log"; exit 1; }
rc=0
# 80.02: every section prints "passed: N" (its number of PASS lines), so that the assertion count of this step can be
# compared between two runs (the PASS lines themselves are not printed, as before)
if part 1/5; then
for opt in "" "--tls-max-v1.2" "--tls-cipher-list=TLS_CHACHA20_POLY1305_SHA256"; do
  echo "== wisp-js over wss ${opt:-(default)}"
  (cd tests/compat && NODE_TLS_REJECT_UNAUTHORIZED=0 NODE_NO_WARNINGS=1 timeout 300 "$NODE" $opt wispjs.mjs "wss://127.0.0.1:$PORT/") | awk '/^PASS/{n++} {l=$0} END{print "passed: " n+0; print l}' || rc=1
  [ "${PIPESTATUS[0]}" = 0 ] || rc=1
done
fi
if [ -z "$PART" ] || [ -n "$ADV" ]; then
# the section line is printed by the first part only, so that the parts together print it once
if [ -z "$ADV" ] || [ "$ADV" = 1/3 ]; then echo "== adversarial.py --tls"; else echo "#### adversarial.py --tls, cases $ADV"; fi
env ${ADV:+WST_CASES=$ADV} timeout 300 python3 tests/compat/adversarial.py "$PORT" --tls | awk '/^PASS/{n++; next} {print} END{print "passed: " n+0}'  # no `|| true`: it would reset PIPESTATUS (review r1)
[ "${PIPESTATUS[0]}" = 0 ] || rc=1
fi
if part 5/5; then
echo "== tls_adversarial.py"; timeout 300 python3 tests/compat/tls_adversarial.py "$PORT" | awk '/^PASS/{n++; next} {print} END{print "passed: " n+0}'  # no `|| true`: it would reset PIPESTATUS (review r1)
[ "${PIPESTATUS[0]}" = 0 ] || rc=1
fi
if part 1/5; then
echo "== tls_nonce.py (40.05)"; timeout 60 python3 tests/compat/tls_nonce.py "$PORT" | awk '/^PASS/{n++} {l=$0} END{print "passed: " n+0; print l}'
[ "${PIPESTATUS[0]}" = 0 ] || rc=1
fi
if part 5/5; then
echo "== tls_extras.py (40.09: SNI, SIGHUP reload, close_notify, KeyUpdate, cipher order; ports PORT+1..PORT+3)"
timeout 200 python3 tests/compat/tls_extras.py "$BIN" $((PORT + 1)) | awk '/^PASS/{n++; next} {print} END{print "passed: " n+0}'  # no `|| true`: it would reset PIPESTATUS (review r1)
[ "${PIPESTATUS[0]}" = 0 ] || rc=1
fi
echo "run_tls: $([ $rc = 0 ] && echo ALL PASS || echo FAILURES)"; exit $rc
