# 40.11 (20.18) Wisp v2 extensions: password auth (0x02), key auth (0x03), MOTD (0x04).
# Starts its own finalwisp servers and a TCP echo target; raw sockets + openssl CLI (ed25519 signing).
# usage: python3 v2ext.py BIN BASEPORT     (uses BASEPORT .. BASEPORT+9)
import base64, hashlib, os, socket, statistics, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = sys.argv[1], int(sys.argv[2])
P_AUTH, P_KEY, P_BOTH, P_NONE, P_MOTD, P_NOUDP, ECHO = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5, BASE + 9
MOTD = "hello from finalwisp \u2713"
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

tmp = tempfile.mkdtemp(prefix="v2ext-")
def path(n): return os.path.join(tmp, n)
for k in ("a", "b"):
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", path(k + ".key")], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", path(k + ".key"), "-pubout", "-out", path(k + ".pub")], check=True, capture_output=True)
with open(path("users"), "w") as f:
    f.write("# user:password\nalice:s3cret\nbob:pa:ss\n")
os.chmod(path("users"), 0o600)

def raw_pub(k):  # last 32 bytes of the SPKI DER
    der = base64.b64decode("".join(open(path(k + ".pub")).read().split("\n")[1:-2]))
    return der[-32:]
def sign(k, msg):
    open(path("msg"), "wb").write(msg)
    return subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", path(k + ".key"), "-in", path("msg")],
                          check=True, capture_output=True).stdout

# ---- servers
procs = []
def serve(port, *args):
    p = subprocess.Popen([BIN, str(port), "--allow-loopback", "--threads", "2", *args], stderr=subprocess.PIPE, text=True)
    procs.append(p)
    return p
class Echo(threading.Thread):
    daemon = True
    def run(self):
        ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", ECHO)); ls.listen(128)
        self.accepted = 0
        while True:
            c, _ = ls.accept(); self.accepted += 1; c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # no Nagle in the test itself: it added ~40 ms (delayed ACK) to the brute-force p99
            threading.Thread(target=self.pump, args=(c,), daemon=True).start()
    def pump(self, c):
        try:
            while (d := c.recv(65536)):
                c.sendall(d)
        except OSError:
            pass  # the server reset the stream (refused handshakes): expected in this test
        finally:
            c.close()
echo = Echo(); echo.start()
serve(P_AUTH, "--auth-file", path("users"), "--motd", MOTD)
serve(P_KEY, "--cert-auth-key", path("a.pub"))
serve(P_BOTH, "--auth-file", path("users"), "--cert-auth-key", path("a.pub"), "--cert-auth-key", path("b.pub"))
serve(P_NONE)
serve(P_MOTD, "--motd", MOTD)
serve(P_NOUDP, "--no-udp", "--auth-file", path("users"))
time.sleep(0.4)
for p in procs:
    if p.poll() is not None:
        print("server failed to start:", p.stderr.read()); sys.exit(1)

# ---- websocket helpers
def frame(op, payload, fin=True):
    n = len(payload)
    if n < 126: hdr = bytes([0x80 * fin | op, 0x80 | n])
    elif n < 65536: hdr = bytes([0x80 * fin | op, 0x80 | 126]) + struct.pack(">H", n)
    else: hdr = bytes([0x80 * fin | op, 0x80 | 127]) + struct.pack(">Q", n)
    m = os.urandom(4)
    mm = (m * (n // 4 + 1))[:n]
    return hdr + m + (int.from_bytes(payload, "big") ^ int.from_bytes(mm, "big")).to_bytes(n, "big") if n else hdr + m

class WS:
    def __init__(self, port, proto="wisp-v2", path_="/"):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=3); self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        key = base64.b64encode(os.urandom(16)).decode()
        extra = f"Sec-WebSocket-Protocol: {proto}\r\n" if proto else ""
        self.s.sendall((f"GET {path_} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = self.s.recv(4096)
            if not d: break
            buf += d
        self.head, _, self.buf = buf.partition(b"\r\n\r\n")
        self.closed = False
    def _fill(self, t):
        self.s.settimeout(t)
        try:
            d = self.s.recv(65536)
        except (socket.timeout, ConnectionResetError):
            d = None if isinstance(sys.exc_info()[1], socket.timeout) else b""
        if d == b"": self.closed = True
        if d: self.buf += d
        return d
    def msg(self, t=2.0):
        """next server frame as (opcode, payload) or None"""
        end = time.time() + t
        while True:
            b = self.buf
            if len(b) >= 2:
                n, hl = b[1] & 0x7f, 2
                if n == 126 and len(b) >= 4: n, hl = struct.unpack(">H", b[2:4])[0], 4
                elif n == 127 and len(b) >= 10: n, hl = struct.unpack(">Q", b[2:10])[0], 10
                if n < 126 or hl > 2:
                    if len(b) >= hl + n:
                        self.buf = b[hl + n:]
                        return b[0] & 0x0f, b[hl:hl + n]
            if self.closed or time.time() > end or self._fill(max(0.01, end - time.time())) is None and time.time() > end:
                return None
    def send(self, payload): self.s.sendall(frame(0x2, payload))
    def wisp(self, ty, sid, body=b""): self.send(bytes([ty]) + struct.pack("<I", sid) + body)
    def eof(self, t=2.0):
        end = time.time() + t
        while not self.closed and time.time() < end:
            self._fill(end - time.time())
        return self.closed

def rec(i, meta): return bytes([i]) + struct.pack("<I", len(meta)) + meta
def pw(u, p): u, p = u.encode(), p.encode(); return bytes([len(u)]) + u + p
def info(*records): return b"\x05\x00\x00\x00\x00\x02\x00" + b"".join(records)
def parse_info(p):
    assert p[0] == 5 and p[1:5] == b"\0\0\0\0", p[:8]
    out, d = {}, p[7:]
    while d:
        i, n = d[0], struct.unpack("<I", d[1:5])[0]
        out[i] = d[5:5 + n]; d = d[5 + n:]
    return p[5:7], out
CONT = b"\x03\x00\x00\x00\x00" + struct.pack("<I", 128)
def close0(reason): return b"\x04\x00\x00\x00\x00" + bytes([reason])

def handshake(port, *records, proto="wisp-v2"):
    w = WS(port, proto)
    m = w.msg()
    w.server_info = m[1] if m else None
    w.send(info(*records))
    return w
def expect_close(w, reason, what):
    m = w.msg()
    m2 = w.msg()
    ok(m == (2, close0(reason)) and m2 == (8, b"\x03\xe8") and w.eof(), f"{what} -> CLOSE(0, {reason:#04x}) + WS close 1000 + EOF")
def expect_open(w, what, echo_check=True):
    m = w.msg()
    good = m == (2, CONT)
    if good and echo_check:
        w.wisp(0x01, 1, b"\x01" + struct.pack("<H", ECHO) + b"127.0.0.1")
        w.wisp(0x02, 1, b"ping-" + what.encode())
        got = b""
        for _ in range(5):
            m = w.msg()
            if m and m[1][:1] == b"\x02": got += m[1][5:]
            if b"ping-" in got: break
        good = got == b"ping-" + what.encode()
    ok(good, f"{what} -> CONTINUE(0, 128)" + (" + echo stream works" if echo_check else ""))
    w.s.close()

# ---- 1. no flags: byte-identical to pre-20.18 (INFO 2.0, no extensions; v1 gets CONTINUE)
w = WS(P_NONE); ok(w.msg() == (2, b"\x05\x00\x00\x00\x00\x02\x00\x01\x00\x00\x00\x00"), "no flags: v2 INFO is exactly 05 00000000 02 00 + UDP record 01 00000000 (pre-20.18 bytes)")
w.send(info(rec(0x02, b"\xff"))); expect_open(w, "no flags: malformed records ignored (not inspected)", False)
w = WS(P_NONE, None); ok(w.msg() == (2, CONT), "no flags: header-less client gets CONTINUE (v1)")
w = WS(P_NOUDP); ok(parse_info(w.msg()[1])[1] == {2: b"\x01"}, "--no-udp + auth: INFO = password only (no 0x01)"); w.s.close()

# ---- 2. MOTD only
w = WS(P_MOTD); ver, ex = parse_info(w.msg()[1])
ok(ver == b"\x02\x00" and ex == {1: b"", 4: MOTD.encode()}, "motd: INFO carries UDP 0x01 + record 0x04 with the UTF-8 text")
w.send(info()); expect_open(w, "motd: client INFO without records")
w = WS(P_MOTD, None); ok(w.msg() == (2, CONT), "motd: header-less client still v1 (CONTINUE)")

# ---- 3. password auth
w = WS(P_AUTH); ver, ex = parse_info(w.msg()[1])
ok(ex == {1: b"", 2: b"\x01", 4: MOTD.encode()}, "auth: INFO = udp + password(required=1) + motd")
expect_open(handshake(P_AUTH, rec(2, pw("alice", "s3cret"))), "right password")
expect_open(handshake(P_AUTH, rec(2, pw("bob", "pa:ss")), rec(4, b"")), "right password with ':' + motd record")
expect_open(handshake(P_AUTH, rec(0x99, os.urandom(300)), rec(1, b""), rec(2, pw("alice", "s3cret")), rec(5, b"")), "unknown/other ids around a valid password")
expect_close(handshake(P_AUTH, rec(2, pw("alice", "wrong"))), 0xc0, "wrong password")
expect_close(handshake(P_AUTH, rec(2, pw("alice", "s3cret "))), 0xc0, "password with extra byte")
expect_close(handshake(P_AUTH, rec(2, pw("mallory", "s3cret"))), 0xc0, "unknown user")
expect_close(handshake(P_AUTH, rec(2, pw("alic", "es3cret"))), 0xc0, "shifted user/password split")
expect_close(handshake(P_AUTH, rec(2, b"")), 0xc0, "empty password record")
expect_close(handshake(P_AUTH, rec(2, b"\x40alice")), 0xc0, "user length beyond the record")
expect_close(handshake(P_AUTH), 0xc2, "INFO without credentials")
expect_close(handshake(P_AUTH, rec(1, b""), rec(4, b"")), 0xc2, "INFO with only udp/motd")
expect_close(handshake(P_AUTH, rec(3, b"\x01" + bytes(96))), 0xc2, "key auth record to a password-only server")
w = WS(P_AUTH, None); m = w.msg()
ok(m and m[1][:1] == b"\x05", "auth: header-less client also gets the v2 INFO")
before = echo.accepted
w.wisp(0x01, 1, b"\x01" + struct.pack("<H", ECHO) + b"127.0.0.1")
expect_close(w, 0xc2, "v1 client (CONNECT first) on an auth server")
time.sleep(0.2); ok(echo.accepted == before, "v1 client's CONNECT never reached the target")
w = WS(P_AUTH); w.msg(); w.wisp(0x02, 0, b"x"); expect_close(w, 0xc2, "DATA before INFO")
w = WS(P_AUTH, path_="/127.0.0.1:%d" % ECHO)
ok(w.head.startswith(b"HTTP/1.1 403") and w.eof(), "auth: wsproxy path refused with 403 (no way to authenticate)")
w = WS(P_AUTH); w.msg()
p = info(rec(2, pw("alice", "s3cret"))); w.s.sendall(frame(0x2, p[:4], fin=False) + frame(0x0, p[4:]))
expect_open(w, "INFO split over WS continuation frames")
w = handshake(P_AUTH, rec(2, pw("alice", "s3cret"))); w.msg()
w.send(info(rec(2, pw("x", "y")))); w.wisp(0x01, 1, b"\x01" + struct.pack("<H", ECHO) + b"127.0.0.1")
w.wisp(0x02, 1, b"after")
m = w.msg(); m2 = w.msg()
ok(any(x and x[1] == b"\x02\x01\x00\x00\x00after" for x in (m, m2)) and not w.closed, "second INFO after the handshake is ignored")
w.s.close()

# ---- 4. malformed client INFO -> CLOSE 0x04
for name, body in [
    ("truncated record header", rec(2, pw("alice", "s3cret")) + b"\x02\x00"),
    ("truncated record payload", b"\x02\x10\x00\x00\x00\x05alice"),
    ("length 0xffffffff", b"\x02\xff\xff\xff\xff" + pw("alice", "s3cret")),
    ("duplicate password records", rec(2, pw("alice", "s3cret")) + rec(2, pw("alice", "s3cret"))),
    ("duplicate unknown ids", rec(0x77, b"") + rec(0x77, b"") + rec(2, pw("alice", "s3cret"))),
]:
    expect_close(handshake(P_AUTH, body), 0x04, "malformed: " + name)
w = WS(P_AUTH); w.msg(); w.send(b"\x05\x00\x00\x00\x00\x09\x00"); expect_close(w, 0x04, "major version 9")
big = rec(0x99, bytes(1 << 20)) + rec(2, pw("alice", "s3cret"))
expect_open(handshake(P_AUTH, big), "1 MiB unknown record + valid password")
# header only (declares 17 MiB, no payload sent): the server must refuse from the length alone, without
# buffering up to MAX_FRAME first
w = WS(P_AUTH); w.msg(); w.s.sendall(bytes([0x82, 0x80 | 127]) + struct.pack(">Q", 17 << 20) + os.urandom(4))
m = w.msg(t=5)
ok(m == (8, b"\x03\xf1") and w.eof(), "17 MiB INFO frame header -> WS close 1009 (MAX_FRAME) before any payload")

# ---- 5. key auth
def key_handshake(port, key, fmt="epoxy", user=b"", alg=1, replay=None):
    w = WS(port); ver, ex = parse_info(w.msg()[1]); w.ex = ex
    meta = ex[3]
    ch = meta[2:]
    sig = replay if replay is not None else sign(key, ch)
    body = bytes([alg]) + hashlib.sha256(raw_pub(key)).digest() + sig
    if fmt == "spec": body = bytes([len(user)]) + user + body
    w.ch, w.sig = ch, sig
    w.send(info(rec(3, body)))
    return w
w = key_handshake(P_KEY, "a")
ok(w.ex[3][:2] == b"\x01\x01" and len(w.ch) == 64 and 2 not in w.ex, "key: INFO = key auth(required=1, ed25519) + 64-byte challenge")
expect_open(w, "valid ed25519 signature (epoxy format)")
expect_open(key_handshake(P_KEY, "a", "spec", b"alice"), "valid signature (spec format with username)")
w1 = WS(P_KEY); w2 = WS(P_KEY)
c1, c2 = parse_info(w1.msg()[1])[1][3][2:], parse_info(w2.msg()[1])[1][3][2:]
ok(c1 != c2, "challenges differ per connection"); w1.s.close(); w2.s.close()
expect_close(key_handshake(P_KEY, "b"), 0xc1, "key not in the allowed list")
expect_close(key_handshake(P_KEY, "a", alg=2), 0xc1, "unsupported algorithm bit")
old = key_handshake(P_KEY, "a"); old.msg(); old.s.close()
expect_close(key_handshake(P_KEY, "a", replay=old.sig), 0xc1, "replayed signature from another connection")
expect_close(key_handshake(P_KEY, "a", replay=old.sig[:63]), 0xc1, "63-byte signature")
expect_close(handshake(P_KEY, rec(3, b"")), 0xc1, "empty key record")
expect_close(handshake(P_KEY), 0xc2, "key server, no credentials")
expect_close(handshake(P_KEY, rec(2, pw("alice", "s3cret"))), 0xc2, "password to a key-only server")

# ---- 6. both methods (password file + two key files)
w = WS(P_BOTH); ex = parse_info(w.msg()[1])[1]; w.s.close()
ok(set(ex) == {1, 2, 3}, "both: INFO advertises 0x01, 0x02 and 0x03")
expect_open(handshake(P_BOTH, rec(2, pw("alice", "s3cret"))), "both: password alone")
expect_open(key_handshake(P_BOTH, "b"), "both: second key file")
expect_close(handshake(P_BOTH, rec(2, pw("alice", "nope"))), 0xc0, "both: wrong password")

# ---- 7. brute force does not block the event loop; timing
N, THREADS = 1500, 16
lat, stop = [], threading.Event()
def legit():
    w = handshake(P_AUTH, rec(2, pw("alice", "s3cret"))); w.msg()
    w.wisp(0x01, 1, b"\x01" + struct.pack("<H", ECHO) + b"127.0.0.1")
    while not stop.is_set():
        t = time.perf_counter(); w.wisp(0x02, 1, b"x")
        m = w.msg()
        if not m: break
        lat.append(time.perf_counter() - t); time.sleep(0.005)
def brute(n, out):
    for i in range(n):
        w = handshake(P_AUTH, rec(2, pw("alice", f"guess{i}")))
        out.append(w.msg() == (2, close0(0xc0))); w.s.close()
lt = threading.Thread(target=legit); lt.start(); time.sleep(0.2)
res = []; t0 = time.perf_counter()
ts = [threading.Thread(target=brute, args=(N // THREADS, res)) for _ in range(THREADS)]
[t.start() for t in ts]; [t.join() for t in ts]
dt = time.perf_counter() - t0; stop.set(); lt.join()
lat.sort()
p99 = lat[int(len(lat) * 0.99)] * 1e3 if lat else 1e9
print(f"     brute force: {len(res)} wrong guesses in {dt:.2f}s ({len(res)/dt:.0f}/s), legit echo p50 {lat[len(lat)//2]*1e3:.2f} ms p99 {p99:.2f} ms over {len(lat)} pings")
ok(all(res) and len(res) == N // THREADS * THREADS, "brute force: every guess rejected with 0xc0")
ok(p99 < 50, "brute force: an authenticated stream keeps answering (p99 < 50 ms)")

def timed(user, pwd, n=300):
    out = []
    for _ in range(n):
        w = WS(P_AUTH); w.msg()
        p = info(rec(2, pw(user, pwd)))
        t = time.perf_counter(); w.send(p); w.msg(); out.append(time.perf_counter() - t); w.s.close()
    return statistics.median(out) * 1e6
for _ in range(2): timed("alice", "x", 50)  # warm up
a = timed("alice", "s3cret"); b = timed("alice", "s3cres"); c = timed("zzzzz", "s3cret"); d = timed("alice", "x" * 200)
print(f"     handshake medians (us): right {a:.0f}, wrong last byte {b:.0f}, unknown user {c:.0f}, long password {d:.0f}")
ok(max(a, b, c, d) - min(a, b, c, d) < 100, "timing: medians within 100 us (loopback noise; compare is constant-time by construction)")

for p in procs: p.terminate()
for p in procs: p.wait()
print(f"\n{fails} failed")
sys.exit(1 if fails else 0)
