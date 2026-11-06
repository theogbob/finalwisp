#!/bin/bash
# 20.13 / 40.04 TLS test runner: wss:// wisp-js suite (incl. 2x64 MiB download = splice through kTLS),
# 40.03 adversarial suite over TLS, 40.04 TLS adversarial + openssl s_client matrix, 40.05 nonces, 40.09 extras.
# usage: tests/compat/run_tls.sh [FINALWISP_BINARY] [PORT]   (needs: `tls` kernel module loaded, node, python3, openssl)
set -u
cd "$(dirname "$0")/../.."
BIN=${1:-server/target/release/finalwisp}; PORT=${2:-7650}; NODE=${NODE:-node}
mkdir -p tests/certs
if [ ! -f tests/certs/cert.pem ]; then  # test-only self-signed cert (gitignored)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=localhost \
    -keyout tests/certs/key.pem -out tests/certs/cert.pem 2>/dev/null
fi
"$BIN" --port "$PORT" --allow-loopback --tls-cert tests/certs/cert.pem --tls-key tests/certs/key.pem > "/tmp/fw-tls-$PORT.log" 2>&1 &
SRV=$!; trap 'kill $SRV 2>/dev/null' EXIT; sleep 0.5
kill -0 $SRV 2>/dev/null || { cat "/tmp/fw-tls-$PORT.log"; exit 1; }
rc=0
for opt in "" "--tls-max-v1.2" "--tls-cipher-list=TLS_CHACHA20_POLY1305_SHA256"; do
  echo "== wisp-js over wss ${opt:-(default)}"
  (cd tests/compat && NODE_TLS_REJECT_UNAUTHORIZED=0 NODE_NO_WARNINGS=1 timeout 300 "$NODE" $opt wispjs.mjs "wss://127.0.0.1:$PORT/") | tail -1 || rc=1
  [ "${PIPESTATUS[0]}" = 0 ] || rc=1
done
echo "== adversarial.py --tls"; timeout 300 python3 tests/compat/adversarial.py "$PORT" --tls | grep -v '^PASS'  # no `|| true`: it would reset PIPESTATUS (review r1)
[ "${PIPESTATUS[0]}" = 0 ] || rc=1
echo "== tls_adversarial.py"; timeout 300 python3 tests/compat/tls_adversarial.py "$PORT" | grep -v '^PASS'  # no `|| true`: it would reset PIPESTATUS (review r1)
[ "${PIPESTATUS[0]}" = 0 ] || rc=1
echo "== tls_nonce.py (40.05)"; timeout 60 python3 tests/compat/tls_nonce.py "$PORT" | tail -1
[ "${PIPESTATUS[0]}" = 0 ] || rc=1
echo "== tls_extras.py (40.09: SNI, SIGHUP reload, close_notify, KeyUpdate, cipher order; ports PORT+1..PORT+3)"
timeout 200 python3 tests/compat/tls_extras.py "$BIN" $((PORT + 1)) | grep -v '^PASS'  # no `|| true`: it would reset PIPESTATUS (review r1)
[ "${PIPESTATUS[0]}" = 0 ] || rc=1
echo "run_tls: $([ $rc = 0 ] && echo ALL PASS || echo FAILURES)"; exit $rc
