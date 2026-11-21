#!/bin/bash
# 60.78 G10 + G59: every check of the two rows in ONE ephemeral VM, in order. usage: g10g59.sh DIR
# DIR: finalwisp (candidate), finalwisp130 (v1.3.0, the keepalive control), the scripts of bench/vmcheck, ka-nft.sh,
# keepalive_dead.py, Dockerfile, BUILDINFO. Output: DIR/out/.
set -u
D=$1; O=$D/out; mkdir -p $O; cd $D
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null 2>&1; apt-get install -y -q nftables openssl iproute2 >/dev/null 2>&1
modprobe tls; ulimit -n 200000
echo "CHECK INFO $(uname -r) $(nproc) CPUs $(awk '/MemTotal/{print $2}' /proc/meminfo) kB; candidate $(md5sum finalwisp | cut -c1-8) $(./finalwisp --version); control $(md5sum finalwisp130 | cut -c1-8) $(./finalwisp130 --version)" | tee $O/info.txt
echo "== G10"; timeout 1500 python3 portshare.py ./finalwisp $O/g10 2>&1 | tail -40
echo "== E3"; timeout 900 python3 e3five.py ./finalwisp $O/e3 2>&1 | tail -20
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=localhost -keyout $D/key.pem -out $D/cert.pem >/dev/null 2>&1
echo "== keepalive_dead --tls"
./ka-nft.sh up 8130 8131
python3 -c "
import socket, threading
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(('127.0.0.1', 7690)); ls.listen(64)
def f(c):
    try:
        while True: c.sendall(b'x' * 65536)
    except OSError: pass
while True:
    c, _ = ls.accept(); threading.Thread(target=f, args=(c,), daemon=True).start()
" & FEED=$!
mkdir -p $O/kad; ./finalwisp --port 8130 --allow-loopback --log-conns --tls-cert $D/cert.pem --tls-key $D/key.pem > $O/kad/server.log 2>&1 & SP=$!
sleep 1
timeout 600 python3 keepalive_dead.py 8130 7690 --tls --pid $SP 2>&1 | tee $O/kad/keepalive_dead.txt
kill $SP; wait $SP; echo "server exit $?" >> $O/kad/keepalive_dead.txt
kill $FEED; ./ka-nft.sh down
echo "== keepalive burst"
for arm in "cand-ws ./finalwisp" "v130-ws ./finalwisp130" "cand-wss ./finalwisp --tls" "v130-wss ./finalwisp130 --tls"; do
  set -- $arm
  if [ "${3:-}" = --tls ]; then timeout 500 python3 kaburst.py $2 8140 $O/ka $1 --tls $D/cert.pem $D/key.pem 2>&1 | tail -2
  else timeout 500 python3 kaburst.py $2 8140 $O/ka $1 2>&1 | tail -2; fi
  sleep 70  # TIME_WAIT of the last arm
done
echo "== T6"; timeout 900 bash t6docker.sh $D 2>&1 | tail -12
echo "== DONE"
