# 40.06 UDP stream tests (20.16) for a Wisp server: v1 + v2, adversarial cases. Stdlib only.
# usage: python3 udp.py PORT [--no-udp-port P] [--ref]
#   PORT          server with UDP enabled and --allow-loopback (private addresses blocked)
#   --no-udp-port a second server started with --no-udp
#   --ref         reference-server mode: only report what happens (no finalwisp-specific asserts)
import os, socket, struct, sys, time, base64, threading

args = sys.argv[1:]
PORT = int(args[0])
NOUDP = int(args[args.index("--no-udp-port") + 1]) if "--no-udp-port" in args else None
REF = "--ref" in args
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

def frame(op, payload):
    n = len(payload)
    if n < 126: hdr = bytes([0x80 | op, 0x80 | n])
    elif n < 65536: hdr = bytes([0x80 | op, 0x80 | 126]) + struct.pack(">H", n)
    else: hdr = bytes([0x80 | op, 0x80 | 127]) + struct.pack(">Q", n)
    m = os.urandom(4)
    # fast XOR mask for big payloads
    k = int.from_bytes(m * ((n + 3) // 4), "little") if n else 0
    body = (int.from_bytes(payload, "little") ^ k).to_bytes(len(m * ((n + 3) // 4)), "little")[:n] if n else b""
    return hdr + m + body

class Wisp:
    def __init__(self, port=PORT, v2=False, exts=b"\x01\x00\x00\x00\x00"):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=3)
        key = base64.b64encode(os.urandom(16)).decode()
        proto = "Sec-WebSocket-Protocol: wisp-v2\r\n" if v2 else ""
        self.s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{proto}\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = self.s.recv(4096)
            if not d: raise RuntimeError("no upgrade")
            buf += d
        head, _, self.buf = buf.partition(b"\r\n\r\n")
        self.buf = bytearray(self.buf)
        self.closed = False
        self.info = None
        if v2:
            p = self.packet(3)
            assert p and p[0] == 5, f"expected INFO, got {p}"
            self.info = p[2][2:]
            self.send(5, 0, bytes([2, 0]) + exts)
        p = self.packet(3)
        assert p and p[0] == 3 and p[1] == 0, f"expected CONTINUE 0, got {p}"
    def send(self, ty, sid, body):
        self.s.sendall(frame(2, struct.pack("<BI", ty, sid) + body))
    def raw(self, data): self.s.sendall(data)
    def pkt(self, ty, sid, body): return frame(2, struct.pack("<BI", ty, sid) + body)
    def connect(self, sid, port, host=b"127.0.0.1", stype=2):
        self.send(1, sid, struct.pack("<BH", stype, port) + host)
    def _parse(self):
        b = self.buf
        if len(b) < 2: return None
        ln = b[1] & 0x7f; hl = 2
        if ln == 126:
            if len(b) < 4: return None
            ln = struct.unpack(">H", b[2:4])[0]; hl = 4
        elif ln == 127:
            if len(b) < 10: return None
            ln = struct.unpack(">Q", b[2:10])[0]; hl = 10
        if len(b) < hl + ln: return None
        op = b[0] & 0x0f; p = bytes(b[hl:hl + ln]); del b[:hl + ln]
        if op == 8: self.closed = True; return ("wsclose", p)
        if op != 2: return ("op", op)
        return (p[0], struct.unpack("<I", p[1:5])[0], p[5:])
    def packet(self, t=1.0):
        end = time.time() + t
        while True:
            r = self._parse()
            if r is not None:
                if r[0] == "op": continue
                return r
            left = end - time.time()
            if left <= 0 or self.closed: return None
            self.s.settimeout(left)
            try:
                d = self.s.recv(1 << 20)
            except socket.timeout:
                return None
            except ConnectionResetError:
                d = b""
            if not d: self.closed = True; return None
            self.buf += d
    def packets(self, t=1.0, until=None):
        out = []; end = time.time() + t
        while time.time() < end:
            p = self.packet(max(0.01, end - time.time()))
            if p is None: break
            out.append(p)
            if until and until(out): break
        return out
    def close(self): self.s.close()

def udp_echo(port=0):
    """UDP echo server thread; returns (socket, port). b'FLOOD n' -> sends n 1000-byte datagrams back fast.
    Also on ::1 at the same port (best effort): "localhost" resolves to ::1 first on some hosts (Debian 12)."""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    u.bind(("127.0.0.1", port))
    socks = [u]
    try:
        u6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        u6.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        u6.bind(("::1", u.getsockname()[1]))
        socks.append(u6)
    except OSError as e:
        print(f"note: no UDP echo on [::1]:{u.getsockname()[1]} ({e}); 'localhost' must resolve to 127.0.0.1", flush=True)
    def run(s):
        while True:
            try: d, a = s.recvfrom(70000)
            except OSError: return
            if d.startswith(b"FLOOD "):
                for i in range(int(d[6:])):
                    try: s.sendto(struct.pack("<I", i) + b"f" * 996, a)
                    except OSError: pass
                continue
            try: s.sendto(d, a)
            except OSError: pass
    for s in socks:
        threading.Thread(target=run, args=(s,), daemon=True).start()
    return u, u.getsockname()[1]

def free_udp_port():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 0))
    p = u.getsockname()[1]; u.close(); return p

def server_pid(port):
    inode = None
    for line in open("/proc/net/tcp").readlines()[1:]:
        f = line.split()
        if f[3] == "0A" and int(f[1].split(":")[1], 16) == port:
            inode = f[9]; break
    if not inode: return None
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            if any(os.readlink(f"/proc/{pid}/fd/{fd}") == f"socket:[{inode}]" for fd in os.listdir(f"/proc/{pid}/fd")):
                return int(pid)
        except OSError:
            continue
def nfds(pid): return len(os.listdir(f"/proc/{pid}/fd")) if pid else -1
def rss_mib(pid): return next(int(l.split()[1]) // 1024 for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")) if pid else -1

echo, EPORT = udp_echo()
PID = server_pid(PORT)

for v2 in (False, True):
    tag = "v2" if v2 else "v1"
    w = Wisp(v2=v2)
    if v2:
        ok(b"\x01\x00\x00\x00\x00" in (w.info or b""), f"{tag}: server INFO advertises UDP extension 0x01 (exts {w.info.hex() if w.info else None})")
    # boundaries: 3 datagrams in one WS write -> 3 DATA packets of the same sizes, plus an empty datagram
    w.connect(1, EPORT)
    sizes = [1, 1400, 9000, 0]
    w.raw(b"".join(w.pkt(2, 1, bytes([65 + i]) * n) for i, n in enumerate(sizes)))
    got = [p for p in w.packets(2, until=lambda o: len([x for x in o if x[0] == 2]) >= 4)]
    data = [p[2] for p in got if p[0] == 2 and p[1] == 1]
    ok(sorted(map(len, data)) == sorted(sizes) and all(d == bytes([d[0]]) * len(d) for d in data if d),
       f"{tag}: datagram boundaries kept, empty datagram forwarded (sizes {[len(d) for d in data]})")
    ok(not any(p[0] in (3, 4) and p[1] == 1 for p in got), f"{tag}: no CONTINUE/CLOSE on the UDP stream")
    # 200 datagrams: never a CONTINUE (spec: CONTINUE must not be sent for UDP)
    w.raw(b"".join(w.pkt(2, 1, struct.pack("<I", i)) for i in range(200)))
    got = w.packets(3, until=lambda o: len(o) >= 200)
    ok(len([p for p in got if p[0] == 2]) >= 190 and not any(p[0] == 3 for p in got),
       f"{tag}: 200 datagrams echoed ({len([p for p in got if p[0] == 2])}), no CONTINUE")
    # max and oversized datagrams
    w.send(2, 1, b"M" * 65507)
    p = w.packet(2)
    ok(p is not None and p[0] == 2 and len(p[2]) == 65507, f"{tag}: 65507-byte datagram round trip ({len(p[2]) if p else None})")
    w.send(2, 1, b"X" * 65508); w.send(2, 1, b"after")
    p = w.packet(2)
    ok(p is not None and p[2] == b"after", f"{tag}: 65508-byte DATA dropped, stream still works (next={p[2][:8] if p else None})")
    # hostname path (DNS) + DATA sent right behind the CONNECT (queued while resolving)
    w.raw(w.pkt(1, 2, struct.pack("<BH", 2, EPORT) + b"localhost") + w.pkt(2, 2, b"early1") + w.pkt(2, 2, b"early2"))
    got = w.packets(2, until=lambda o: len(o) >= 2)
    ok([p[2] for p in got if p[1] == 2] == [b"early1", b"early2"], f"{tag}: DATA before resolve queued + delivered in order ({[p[2] for p in got]})")
    w.close()

# closed port: ICMP port unreachable must not kill the stream; when the port opens, traffic flows
w = Wisp()
cp = free_udp_port()
w.connect(5, cp)
w.send(2, 5, b"ping1"); time.sleep(0.3); w.send(2, 5, b"ping2"); time.sleep(0.3)
got = w.packets(0.5)
closed = [p for p in got if p[0] == 4 and p[1] == 5]
if REF:
    print(f"INFO ref: closed port -> {['CLOSE 0x%02x' % p[2][0] for p in closed] or 'no CLOSE'}")
else:
    ok(not closed, f"closed port: ICMP refusals do not close the stream ({got})")
    late, _ = udp_echo(cp)
    w.send(2, 5, b"hello")
    p = w.packet(2)
    ok(p is not None and p[:2] == (2, 5) and p[2] == b"hello", f"closed port: after the port opens the same stream works ({p})")
    late.close()
w.close()

# blocked / invalid / unresolvable
w = Wisp()
w.connect(6, 53, b"10.0.0.1"); w.connect(7, 53, b"169.254.169.254"); w.connect(8, 53, b"no-such-host.invalid")
w.connect(9, 0, b"127.0.0.1"); w.connect(10, EPORT, b"")
# 30 s: the unresolvable name goes to the host's resolver (this server is started by compat.py, default getaddrinfo);
# glibc's worst case with one nameserver is timeout 5 s x attempts 2 (60.33: a stall during a Wi-Fi drop)
got = {p[1]: p[2][0] for p in w.packets(30, until=lambda o: len(o) >= 5) if p[0] == 4}
print(f"INFO close reasons: {got}")
if not REF:
    ok(got.get(6) == 0x48 and got.get(7) == 0x48, f"private/metadata address blocked -> 0x48")
    ok(got.get(8) == 0x42, f"unresolvable host -> 0x42")
    ok(got.get(9) == 0x41 and got.get(10) == 0x41, f"port 0 / empty host -> 0x41")
w.close()

# flood from the target while the client does not read: bounded server memory, then still usable
w = Wisp()
w.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
w.connect(11, EPORT)
rss0 = rss_mib(PID)
w.send(2, 11, b"FLOOD 200000")
time.sleep(4)
rss1 = rss_mib(PID)
cnt = 0; end = time.time() + 20; last = None
while time.time() < end:
    p = w.packet(1.0)
    if p is None: break
    if p[0] == 2 and p[1] == 11: cnt += 1; last = p
ok(0 < cnt < 200000 and (REF or rss1 - rss0 < 64), f"target flood (200k x 1000 B) with a stalled client: {cnt} delivered, rest dropped, RSS {rss0} -> {rss1} MiB")
w.send(2, 11, b"still")
p = w.packets(2, until=lambda o: any(x[2] == b"still" for x in o))
ok(any(x[2] == b"still" for x in p), "flooded stream still works afterwards")
w.close()

# many UDP streams on one connection, then close them all: fds released
time.sleep(0.3)
fd0 = nfds(PID)
w = Wisp(v2=True)
N = 1000
w.raw(b"".join(w.pkt(1, 100 + i, struct.pack("<BH", 2, EPORT) + b"127.0.0.1") for i in range(N)))
# DATA in batches of 100: one burst of 1000 datagrams overflows the test's own echo socket on hosts with a small
# net.core.rmem_max (SO_RCVBUF is capped by it: 212992 on stock Ubuntu -> ~90% echoed on a 2 vCPU box)
got = []
for b in range(0, N, 100):
    w.raw(b"".join(w.pkt(2, 100 + i, struct.pack("<I", i)) for i in range(b, b + 100)))
    got += w.packets(5, until=lambda o: len(o) >= 100)
ids = {p[1] for p in got if p[0] == 2 and p[2] == struct.pack("<I", p[1] - 100)}
fd1 = nfds(PID)
ok(len(ids) >= N * 0.98, f"{N} UDP streams on one connection: {len(ids)} echoed (server fds {fd0} -> {fd1})")
w.raw(b"".join(w.pkt(4, 100 + i, b"\x02") for i in range(N)))
time.sleep(0.5)
fd2 = nfds(PID)
ok(REF or fd2 - fd0 < 20, f"client CLOSE of {N} UDP streams releases the sockets (fds {fd1} -> {fd2})")
w.send(2, 100, b"after-close")
p = w.packets(0.7)
ok(not any(x[0] == 2 and x[1] == 100 for x in p), "DATA on a closed UDP stream is ignored")
w.close()

# v2 client that did not list UDP: still allowed (like wisp-js/epoxy/wispurr)
w = Wisp(v2=True, exts=b"")
w.connect(1, EPORT); w.send(2, 1, b"nolist")
p = w.packet(2)
ok(p is not None and p[2] == b"nolist", f"v2 client without UDP extension can still open UDP ({p})")
w.close()

if NOUDP:
    w = Wisp(NOUDP, v2=True)
    ok(b"\x01\x00\x00\x00\x00" not in (w.info or b""), f"--no-udp: INFO without UDP extension ({w.info.hex()})")
    w.connect(1, EPORT); w.send(2, 1, b"x")
    p = w.packet(2)
    ok(p is not None and p[0] == 4 and p[2] == b"\x48", f"--no-udp: UDP CONNECT -> CLOSE 0x48 (60.20 Q7; {p})")
    w.close()
    w = Wisp(NOUDP)
    w.connect(1, EPORT)
    p = w.packet(2)
    ok(p is not None and p[0] == 4 and p[2] == b"\x48", f"--no-udp v1: UDP CONNECT -> CLOSE 0x48 (60.20 Q7; {p})")
    w.close()

print(f"{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
sys.exit(1 if fails else 0)
