#!/bin/bash
# 60.78 G59 T6: "IPv4 clients keep their address through a published port" (shown on v1.2.1 only) on
# the candidate's image, in ONE VM (root). contrib/docker/Dockerfile, context = DIR with finalwisp + BUILDINFO. A client
# in a network namespace (veth 10.77.0.2 / fd77::2 -> the VM 10.77.0.1 / fd77::1) plays the remote host.
# usage: t6docker.sh DIR (DIR/finalwisp, DIR/BUILDINFO, DIR/Dockerfile, DIR/wispa.py) -> DIR/out/t6.txt
set -u
D=$1; O=$D/out; mkdir -p $O; T=$O/t6.txt
say() { echo "$*" | tee -a $T; }
export DEBIAN_FRONTEND=noninteractive
command -v docker >/dev/null || { apt-get update -q >/dev/null && apt-get install -y -q docker.io docker-buildx >/dev/null 2>&1; }
C=$(mktemp -d); cp $D/finalwisp $D/BUILDINFO $C/  # the build context: the binary and BUILDINFO only (the Dockerfile's header)
say "CHECK INFO docker $(docker version --format '{{.Server.Version}}' 2>&1), kernel $(uname -r)"
DOCKER_BUILDKIT=1 docker build -q -f $D/Dockerfile --build-arg REVISION=$(awk '/^git:/{print $2}' $D/BUILDINFO) -t finalwisp:cand $C > $O/build.txt 2>&1
say "CHECK INFO image $(docker image inspect finalwisp:cand --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' 2>&1)"
docker run -d --name fwt6 -p 6001:6001 --stop-timeout 35 finalwisp:cand --host 0.0.0.0 --port 6001 --log-conns >/dev/null
ip netns add cl; ip link add v-h type veth peer name v-c; ip link set v-c netns cl
ip addr add 10.77.0.1/24 dev v-h; ip -6 addr add fd77::1/64 dev v-h nodad; ip link set v-h up
ip netns exec cl ip addr add 10.77.0.2/24 dev v-c; ip netns exec cl ip -6 addr add fd77::2/64 dev v-c nodad
ip netns exec cl ip link set v-c up; ip netns exec cl ip link set lo up
sleep 3
HOSTIP=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')
probe() {  # $1 label, $2 ns prefix, $3 host
  r=$($2 python3 -c "
import asyncio, sys; sys.path.insert(0, '$D')
from wispa import Wisp
async def m():
    w = await Wisp().open('$3', 6001, timeout=5); await asyncio.sleep(1); w.close(); await asyncio.sleep(0.3)
try: asyncio.run(m()); print('connected')
except Exception as e: print('no connection:', type(e).__name__, e)
" 2>&1); sleep 1.5
  ip=$(docker logs fwt6 2>&1 | grep -o ' ip=[^ ]*' | tail -1); say "CHECK INFO T6 $1 -> $3: client $r; server's last ip=: ${ip# ip=}"
}
probe "remote IPv4 client 10.77.0.2 (netns)" "ip netns exec cl" 10.77.0.1
c1=$(docker logs fwt6 2>&1 | grep -c ' ip=10.77.0.2'); [ "$c1" -ge 1 ] && say "CHECK PASS T6: the remote IPv4 client keeps its address through the published port (ip=10.77.0.2)" || say "CHECK FAIL T6: no ip=10.77.0.2 in the server's log"
probe "remote IPv6 client fd77::2 (netns)" "ip netns exec cl" fd77::1
probe "client on the Docker host via its own IPv4 $HOSTIP" "" $HOSTIP
probe "client on the Docker host via 127.0.0.1" "" 127.0.0.1
docker logs fwt6 > $O/t6-server.log 2>&1
docker exec fwt6 /finalwisp --version >> $T 2>&1 || true
docker rm -f fwt6 >/dev/null; ip netns del cl; ip link del v-h 2>/dev/null
say "CHECK INFO cleaned (container removed, netns removed)"
