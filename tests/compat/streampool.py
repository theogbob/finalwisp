#!/usr/bin/env python3
"""60.72 --stream-pool against a real finalwisp. Stdlib only. usage: streampool.py FINALWISP_BINARY BASEPORT
(BASEPORT, +1 = the test's echo target). The server runs in a user systemd scope with MemoryMax=128M (a budget under
256 MiB: memory level 1 from the start, with its stream limit per worker thread) and 2 threads. Exit 77 = SKIP (no
user systemd or no delegated memory controller), as membudget.py.
Cases, each on a fresh server:
- off (bare): one connection asks for 1.5 x the per-thread limit (it lives on one thread): the streams above the
  limit get CLOSE 0x49 (refuse_streams) although the other thread has room.
- on (--stream-pool): the same connection gets all of its streams (refuse_streams 0); a second connection then asks
  for more than the rest of the shared limit: in all, the open streams reach the shared limit (2 x the per-thread
  limit, less what the other thread keeps unused: at most 2 blocks) and never pass it; every refusal is CLOSE 0x49.
  The level stays 1 (no level 2: the bound is the same), and the open streams echo.
The per-thread limit is read from the log's first refusal of the off case (its streams gauge).
A timeout is a failure everywhere."""
import base64, os, resource, socket, struct, subprocess, sys, tempfile, threading, time

fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

def echo(c):
    with c:
        try:
            d = c.recv(65536)
            while d:
                c.sendall(d); d = c.recv(65536)
        except OSError: pass
def acceptor(ls):
    while True:
        try: c, _ = ls.accept()
        except OSError: return
        threading.Thread(target=echo, args=(c,), daemon=True).start()
def target(port):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", port)); ls.listen(4096)
    threading.Thread(target=acceptor, args=(ls,), daemon=True).start()
    return ls

def srvlog(p):
    with open(p.logf.name) as f:
        return f.read()
def stop(p, port):
    p.terminate()
    try: p.wait(15)
    except subprocess.TimeoutExpired: p.kill(); p.wait()
    for _ in range(100):
        try: t = socket.socket(); t.bind(("127.0.0.1", port)); t.close(); break
        except OSError: time.sleep(0.05)
def metric(p, key):
    """the value in a metrics line written after the call (None: no line in 3 s, or no such key)"""
    n0, end = srvlog(p).count("ev=metrics"), time.time() + 3
    while srvlog(p).count("ev=metrics") <= n0 and time.time() < end:
        time.sleep(0.1)
    vals = [l for l in srvlog(p).splitlines() if "ev=metrics" in l]
    if len(vals) <= n0: return None
    for kv in vals[-1].split():
        if kv.startswith(key + "="): return int(kv.split("=", 1)[1])
    return None
def metrics(p, keys):
    """the values of `keys` in one metrics line written after the call ({} if none came in 3 s)"""
    n0, end = srvlog(p).count("ev=metrics"), time.time() + 3
    while srvlog(p).count("ev=metrics") <= n0 and time.time() < end:
        time.sleep(0.1)
    vals = [l for l in srvlog(p).splitlines() if "ev=metrics" in l]
    if len(vals) <= n0: return {}
    kv = dict(x.split("=", 1) for x in vals[-1].split() if "=" in x)
    return {k: int(kv[k]) for k in keys if k in kv and kv[k].isdigit()}
def settle(p, keys, total, secs=15):
    """the metrics once sum(keys) == total (None: not within secs)"""
    end = time.time() + secs
    while time.time() < end:
        m = metrics(p, keys)
        if len(m) == len(keys) and sum(m.values()) == total: return m
    return None

def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

class Wisp:
    """a Wisp v1 client"""
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.s.settimeout(3)
        self.s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
                       + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d: raise ConnectionResetError("closed before 101")
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]: raise ConnectionResetError(head[:40])
        self.seen = []
    def send(self, ty, sid, body):
        self.s.sendall(frame(bytes([ty]) + struct.pack("<I", sid) + body))
    def connect(self, sid, port):
        self.send(1, sid, b"\x01" + struct.pack("<H", port) + b"127.0.0.1")
    def packets(self, t=1.0, until=None):
        """every Wisp packet (type, sid, body) so far, after at most t seconds (or once `until(all)` holds)"""
        end = time.time() + t
        self.s.settimeout(0.05)
        while True:
            while len(self.buf) >= 2:
                ln = self.buf[1] & 0x7f; h = 2
                if ln == 126:
                    if len(self.buf) < 4: break
                    ln = struct.unpack(">H", self.buf[2:4])[0]; h = 4
                elif ln == 127:
                    if len(self.buf) < 10: break
                    ln = struct.unpack(">Q", self.buf[2:10])[0]; h = 10
                if len(self.buf) < h + ln: break
                p, self.buf = self.buf[h:h + ln], self.buf[h + ln:]
                if len(p) >= 5: self.seen.append((p[0], struct.unpack("<I", p[1:5])[0], p[5:]))
            if (until and until(self.seen)) or time.time() >= end: break
            try:
                d = self.s.recv(1 << 20)
                if not d: break
                self.buf += d
            except socket.timeout:
                pass
        return self.seen
    def closed(self, t=0.5):
        """{sid: reason} of every CLOSE so far"""
        return {s: b[0] for ty, s, b in self.packets(t) if ty == 4 and b}
    def echo(self, sid, data=b"ping"):
        self.send(2, sid, data)
        got = lambda out: b"".join(b for ty, s, b in out if ty == 2 and s == sid)
        return got(self.packets(3.0, lambda out: got(out).endswith(data))).endswith(data)
    def alive(self):
        try:
            self.s.settimeout(0.05); d = self.s.recv(1, socket.MSG_PEEK)
            return d != b""
        except socket.timeout: return True
        except OSError: return False

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
TGT = BASE + 1
target(TGT)
D = tempfile.mkdtemp(prefix="fw-streampool-")
UNIT = f"fw-streampool-{os.getpid()}"
if subprocess.run(["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=128M", "true"], capture_output=True, timeout=30).returncode != 0:
    print("SKIP no user systemd scope with a memory limit", flush=True)
    sys.exit(77)

def start(n, *args):
    log = open(os.path.join(D, f"srv{n}.log"), "w+")
    p = subprocess.Popen(["systemd-run", "--user", "--scope", "-q", f"--unit={UNIT}-{n}", "-p", "MemoryMax=128M", "-p", "MemorySwapMax=0",
                          BIN, str(BASE), "--allow-loopback", "--metrics-interval", "1", "--threads", "2", *args],
                         stdout=log, stderr=subprocess.STDOUT)
    p.logf = log
    for _ in range(200):
        if "listening on" in srvlog(p) or p.poll() is not None: break
        time.sleep(0.05)
    time.sleep(0.2)
    return p

KEYS = ("streams", "refuse_streams")
def ask(c, sids):
    for s in sids:
        c.connect(s, TGT)

# --- off: the per-thread limit, measured
p = start("off")
c = Wisp(BASE)
ask(c, range(1, 401))
m = settle(p, KEYS, 400)
ok(m is not None and m["refuse_streams"] > 0, f"off: one connection of 400 streams meets the per-thread limit ({m})")
per = (m or {}).get("streams", 0)
ok(150 <= per <= 300, f"off: the per-thread limit at 128 MiB and 2 threads is {per} streams (227 computed)")
why = c.closed(1.0)
ok(len(why) == (m or {}).get("refuse_streams") and set(why.values()) == {0x49}, f"off: each refusal is CLOSE 0x49 ({len(why)})")
lvl = metric(p, "level")
ok(lvl == 1, f"off: memory level {lvl} (1: the budget is under 256 MiB)")
c.s.close()
stop(p, BASE)
if per == 0:
    print("streampool: no limit measured", flush=True)
    sys.exit(1)

# --- on: one shared limit of 2 x per
p = start("on", "--stream-pool")
a = Wisp(BASE)
want = per + per // 2
ask(a, range(1, want + 1))
m = settle(p, KEYS, want)
ok(m is not None and m["refuse_streams"] == 0 and m["streams"] == want, f"on: one connection gets {want} streams, nothing refused ({m})")
ok(all(a.echo(s) for s in (1, per, want)), "on: they echo")
b = Wisp(BASE)
more = per
ask(b, range(1, more + 1))
m = settle(p, KEYS, want + more) or {}
total = 2 * per
ok(total - 8 <= m.get("streams", 0) <= total, f"on: in all {m.get('streams')} streams open, the shared limit is {total} (less at most 2 unused blocks)")
why = b.closed(1.0)
ok(len(why) == m.get("refuse_streams") and set(why.values()) <= {0x49}, f"on: each refusal is CLOSE 0x49 ({len(why)} of {m.get('refuse_streams')})")
lvl = metric(p, "level")
ok(lvl == 1, f"on: memory level {lvl} (the bound did not move)")
open_b = [s for s in range(1, more + 1) if s not in why][:3]
ok(open_b and all(b.echo(s) for s in open_b), "on: the second connection's open streams echo")
# streams that close give their units back: the second connection gets them
for s in range(1, 51):
    a.send(4, s, b"\x02")
m2 = settle(p, ("streams",), m.get("streams", 0) - 50) or {}
ask(b, range(more + 1, more + 41))
m3 = settle(p, KEYS, m.get("streams", 0) - 50 + 40 + m.get("refuse_streams", 0)) or {}
ok(m3.get("refuse_streams") == m.get("refuse_streams"), f"on: after 50 closes, 40 new streams of the other connection open ({m3})")
ok(a.alive() and b.alive(), "on: nobody is disconnected")
stop(p, BASE)
print("streampool:", "OK" if fails == 0 else f"{fails} FAIL", flush=True)
sys.exit(1 if fails else 0)
