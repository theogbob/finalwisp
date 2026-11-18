#!/bin/bash
# 60.78 G03 old-kernel functional check of one release binary (no timing). Runs as root inside an ephemeral VM.
# usage: vmcheck.sh DIR   (DIR holds finalwisp and wbench, both static); writes DIR/out/checks.txt (CHECK name PASS|FAIL|INFO detail)
D=$(cd "$1" && pwd); R=$D/out; mkdir -p $R; cd $D
FW=$D/finalwisp; WB=$D/wbench
: > $R/checks.txt
res() { echo "CHECK $1 $2 ${3:-}" | tee -a $R/checks.txt; }
uname -r > $R/uname.txt; . /etc/os-release; echo "$PRETTY_NAME" > $R/os.txt
CG=$(stat -fc %T /sys/fs/cgroup); echo "$CG" > $R/cgroupfs.txt
res system INFO "kernel $(uname -r) | $PRETTY_NAME | /sys/fs/cgroup $CG | nproc $(nproc) | mem $(awk '/MemTotal/{print $2}' /proc/meminfo) kB"
md5sum $FW $WB > $R/md5.txt
res md5 INFO "$(md5sum $FW | cut -c1-8) finalwisp, $(md5sum $WB | cut -c1-8) wbench"
ulimit -Sn 1024   # the soft limit only (the hard one stays): the start raises it
PIDS=()
spawn() { local n=$1; shift; "$@" > $R/$n.log 2>&1 & PIDS+=($!); echo $! > $R/$n.pid; }
spawn t_echo $WB target --port 7101 --mode echo --threads 1
spawn t_source $WB target --port 7103 --mode source --verify --threads 1
spawn t_sink $WB target --port 7102 --mode sink --verify --threads 1
spawn t_udp $WB target --port 7105 --mode udp-echo --threads 1
sleep 1
# start NAME PORT ARGS...: a server; PASS if it listens within 5 s
start() {
  local n=$1 port=$2; shift 2
  "$@" > $R/$n.log 2>&1 & echo $! > $R/$n.pid
  for i in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && return 0; kill -0 $(cat $R/$n.pid) 2>/dev/null || break; sleep 0.1; done
  return 1
}
# stop NAME CHECK: SIGTERM, then PASS if the exit status is 0 (not in a $(...) subshell: wait needs this shell)
stop() { local p=$(cat $R/$1.pid); kill -TERM $p 2>/dev/null; wait $p 2>/dev/null; local rc=$?
  [ $rc = 0 ] && res $2 PASS "exit status 0 on SIGTERM" || res $2 FAIL "exit status $rc on SIGTERM"; }
# idle_stream PORT SECS: one Wisp v1 stream to the echo target that sends nothing for SECS (bash only: a masked WS frame
# with the zero mask key holding CONNECT type 1, stream 1, TCP, port 7101, host 127.0.0.1)
idle_stream() {
  exec 5<>/dev/tcp/127.0.0.1/$1
  printf 'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' >&5
  sleep 0.5
  printf '\x82\x91\x00\x00\x00\x00\x01\x01\x00\x00\x00\x01\xbd\x1b127.0.0.1' >&5
  sleep $2
}
# wb NAME URL TEST TARGET CONNS STREAMS [extra]: PASS if exit 0, errors 0 and every connection ok
wb() {
  local n=$1 url=$2 t=$3 tg=$4 c=$5 s=$6; shift 6
  $WB run --url $url --target $tg --test $t --conns $c --streams $s --duration 3 --warmup 0.5 --threads 1 --json "$@" > $R/wb-$n.log 2>&1
  local rc=$? j=$(grep '^{' $R/wb-$n.log | tail -1)
  local e=$(echo "$j" | grep -oE '"errors":[0-9]+' | cut -d: -f2) ok=$(echo "$j" | grep -oE '"conns_ok":[0-9]+' | cut -d: -f2)
  if [ $rc -eq 0 ] && [ "$e" = 0 ] && [ "$ok" = "$c" ]; then res wb-$n PASS "rc 0, errors 0, conns_ok $ok/$c"; else res wb-$n FAIL "rc $rc errors ${e:-?} conns_ok ${ok:-?}/$c"; fi
}
traffic() {  # PREFIX URL [wbench args]
  local p=$1 u=$2; shift 2
  wb $p-echo $u echo 127.0.0.1:7101 2 4 "$@"
  wb $p-download $u download 127.0.0.1:7103 2 2 --verify "$@"
  wb $p-upload $u upload 127.0.0.1:7102 2 2 --verify "$@"
  wb $p-churn-name $u churn localhost:7101 2 2 "$@"
}
caps() { grep -m1 'capabilities:' $R/$1.log | cut -c1-900; }

# A: bare (the release defaults)
if start bare 6001 $FW --port 6001 --allow-loopback --log-level debug; then
  res bare-start PASS "$(grep -m1 'open files' $R/bare.log | sed 's/  */ /g')"
  res bare-caps INFO "$(caps bare)"
  traffic bare ws://127.0.0.1:6001/
  wb bare-udp ws://127.0.0.1:6001/ udp-rr 127.0.0.1:7105 1 2
  # keepalive while a stream is idle: the server's target socket to the echo target has a keepalive timer
  idle_stream 6001 3 &
  IDP=$!; sleep 2.5
  ss -tnoH state established '( dport = :7101 )' > $R/ss-ka.txt
  wait $IDP; exec 5>&- 2>/dev/null
  if grep -q 'keepalive' $R/ss-ka.txt; then res target-keepalive PASS "$(grep -m1 -oE 'timer:\(keepalive[^)]*\)' $R/ss-ka.txt) on the idle stream's target socket"; else res target-keepalive FAIL "$(head -2 $R/ss-ka.txt | tr '\n' ' ')"; fi
  res bare-vsz INFO "idle VmSize $(awk '/VmSize/{print $2, $3}' /proc/$(cat $R/bare.pid)/status), threads $(ls /proc/$(cat $R/bare.pid)/task | wc -l)"
  if grep -q 'splice' $R/bare.log; then res splice INFO "$(grep -m1 -oE '[^,]*splice[^,]*' $R/bare.log | head -1)"; fi
  stop bare bare-stop
else res bare-start FAIL "$(tail -3 $R/bare.log)"; fi
# fd raise: the soft limit was 1024
if grep -qE 'open files +up to (1024|[0-9]{1,3})$' $R/bare.log; then res fd-raise FAIL "$(grep -m1 'open files' $R/bare.log)"; else res fd-raise PASS "soft limit 1024 before; $(grep -m1 'open files' $R/bare.log | sed 's/  */ /g')"; fi

# B: --preset public (+ --unread-close, --auto-balance)
if start preset 6002 $FW --preset public --unread-close --auto-balance --port 6002 --allow-loopback --log-level debug; then
  res preset-start PASS
  grep -iE 'not in effect|warning' $R/preset.log | cut -c1-300 | while read -r l; do res preset-note INFO "$l"; done
  for g in 'TCP memory guard' 'source port guard' 'dead destination guard' 'network watch' 'unread'; do
    grep -q "$g" $R/preset.log && res "preset-line" INFO "$g: on" || res "preset-line" INFO "$g: no line"; done
  traffic preset ws://127.0.0.1:6002/
  stop preset preset-stop
else res preset-start FAIL "$(tail -3 $R/preset.log)"; fi

# C: wss (kTLS); a kernel without it must stop at start with the reason
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=localhost -keyout $R/key.pem -out $R/cert.pem 2>/dev/null
if start tls 6003 $FW --port 6003 --allow-loopback --log-level debug --tls-cert $R/cert.pem --tls-key $R/key.pem; then
  res tls-start PASS "$(grep -m1 -oE 'kTLS [^ ,]+' $R/tls.log | cut -c1-200)"
  traffic tls wss://127.0.0.1:6003/ --insecure
  stop tls tls-stop
else
  sleep 1; kill -0 $(cat $R/tls.pid) 2>/dev/null && { res tls-start FAIL "running but not listening"; stop tls tls-stop; } || res tls-start INFO "stopped at start: $(grep -v '^ ' $R/tls.log | tail -1 | cut -c1-250)"
fi

# D: cgroup memory budget (systemd scope with a 300 MiB limit; v1: MemoryLimit, v2: MemoryMax)
if [ "$CG" = cgroup2fs ]; then PROP="-p MemoryMax=300M"; else PROP="-p MemoryLimit=300M"; fi
if start cg 6004 systemd-run --scope --quiet --unit=fwcheck-cg $PROP $FW --port 6004 --allow-loopback --log-level debug; then
  b=$(grep -m1 -oE 'memory budget [0-9]+ MiB \([^;)]*' $R/cg.log)
  case "$b" in *"memory budget 300 MiB"*|*"memory budget 299 MiB"*) res cgroup-budget PASS "$b";; *) res cgroup-budget FAIL "$b";; esac
  traffic cg ws://127.0.0.1:6004/
  systemctl stop fwcheck-cg.scope 2>/dev/null; sleep 1
else res cgroup-budget FAIL "$(tail -3 $R/cg.log)"; fi

# E: vm.overcommit_memory=2 (this VM only; restored)
OC=$(cat /proc/sys/vm/overcommit_memory)
sysctl -qw vm.overcommit_memory=2
if start oc 6005 $FW --port 6005 --allow-loopback --log-level debug; then
  res overcommit2-start PASS; traffic oc ws://127.0.0.1:6005/; stop oc oc-stop
else res overcommit2-start FAIL "$(tail -3 $R/oc.log)"; fi
sysctl -qw vm.overcommit_memory=$OC

# F: low RLIMIT_AS. 70.25's spec: 2-4 GiB runs the load with the pool falling back to glibc, no abort (PASS rule for
# 2048 MiB); 1024 and 512 MiB are recorded (INFO) to show where it ends
for AS in 2048 1024 512; do
  port=$((6006 + AS / 512))
  if start as$AS $port bash -c "ulimit -v $((AS * 1024)); exec $FW --port $port --allow-loopback --log-level debug"; then
    res rlimit-as$AS-start PASS "$(grep -m1 -oE 'pool on: [^,]*' $R/as$AS.log)"
    traffic as$AS ws://127.0.0.1:$port/
    if kill -0 $(cat $R/as$AS.pid) 2>/dev/null; then stop as$AS as$AS-stop; else wait $(cat $R/as$AS.pid) 2>/dev/null; res as$AS-alive $([ $AS = 2048 ] && echo FAIL || echo INFO) "died during the load: $(grep -m1 -E 'memory allocation|panicked|abort' $R/as$AS.log)"; fi
  else res rlimit-as$AS-start $([ $AS = 2048 ] && echo FAIL || echo INFO) "$(tail -2 $R/as$AS.log | tr '\n' ' ')"; fi
done

# G: hostile nsswitch.conf (hosts without files/dns: the static binary must ignore it)
cp /etc/nsswitch.conf $R/nsswitch.orig
printf 'passwd: files nis sss\ngroup: files nis\nhosts: mdns4_minimal [NOTFOUND=return] nis ldap\n' > /etc/nsswitch.conf
if start ns 6007 $FW --port 6007 --allow-loopback --log-level debug; then
  res nsswitch-start PASS "$(grep -m1 -oE 'static: [^,]*' $R/ns.log)"
  wb ns-churn-name ws://127.0.0.1:6007/ churn localhost:7101 2 2
  stop ns ns-stop
else res nsswitch-start FAIL "$(tail -3 $R/ns.log)"; fi
cp $R/nsswitch.orig /etc/nsswitch.conf

for p in "${PIDS[@]}"; do kill $p 2>/dev/null; done; wait 2>/dev/null
res summary INFO "PASS $(grep -c ' PASS' $R/checks.txt) FAIL $(grep -c ' FAIL' $R/checks.txt)"
