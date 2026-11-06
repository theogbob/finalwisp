#!/usr/bin/env python3
"""60.25 C10b upload caps against a real finalwisp, loopback, no root. Stdlib only.
usage: uplimit.py FINALWISP_BINARY BASEPORT   (server BASEPORT, TCP + UDP targets BASEPORT+1)
The server stops reading a client over its allowance (TCP flow control holds the sender), so a target receives at
the cap. Rates = target bytes over 4 s after a 2 s warm-up (the burst, default B = R, is spent by then); band
0.8..1.25 x the cap (the 100 ms resume tick and the 2 s sample grid).
- --upload-rate 256K: one connection with two streams shares the cap; two connections each get it (per connection);
  600 KB sent on one stream arrive intact and complete while limited; metrics rx_bytes and upl_pauses count
- --upload-rate-per-ip 512K: two connections from one address share it, neither starved (each >= 15 %)
- --upload-rate 64K: a UDP stream's datagrams count against the cap
- wss (kTLS, if this kernel has it): --upload-rate 256K holds; a clamped read can end inside a TLS record
- startup line, bad values refused, --config form"""
import base64, hashlib, os, socket, ssl, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
TPORT = BASE + 1
WARM, DUR = 2.0, 4.0
LO, HI = 0.8, 1.25
CERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "server", "fuzz", "certs")
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

SINKS = []  # per accepted TCP target connection: [bytes list of (t, n), sha256]
def serve(c):
    rec = [[], hashlib.sha256()]; SINKS.append(rec)
    with c:
        try:
            while (d := c.recv(1 << 20)):
                rec[0].append((time.monotonic(), len(d))); rec[1].update(d)
        except OSError:
            pass
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", TPORT)); ls.listen(64)
threading.Thread(target=lambda: [threading.Thread(target=serve, args=(ls.accept()[0],), daemon=True).start() for _ in iter(int, 1)],
                 daemon=True).start()
UDP = []  # (t, n) of every datagram at the UDP target
us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); us.bind(("127.0.0.1", TPORT))
us.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
threading.Thread(target=lambda: [UDP.append((time.monotonic(), len(us.recv(65536)))) for _ in iter(int, 1)], daemon=True).start()

D = tempfile.mkdtemp(prefix="fw-uplimit-")
def srvlog(p):
    with open(p.logf.name) as f:
        return f.read()
def start(*args, tls=False):
    log = open(os.path.join(D, "srv.log"), "w+")
    extra = ["--tls-cert", os.path.join(CERTS, "cert.pem"), "--tls-key", os.path.join(CERTS, "key.pem")] if tls else []
    p = subprocess.Popen([BIN, str(BASE), "--allow-loopback", "--metrics-interval", "1", *extra, *args],
                         stdout=log, stderr=subprocess.STDOUT)
    p.logf = log
    for _ in range(100):
        if "capabilities:" in srvlog(p) or p.poll() is not None: break
        time.sleep(0.05)
    time.sleep(0.2)
    return p
def stop(p):
    p.terminate()
    try: p.wait(10)
    except subprocess.TimeoutExpired: p.kill(); p.wait()

class Wisp:
    def __init__(self, tls=False):
        s = socket.create_connection(("127.0.0.1", BASE), timeout=10)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname="localhost")
        self.s = s
        self.s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
                       + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(65536)
            if not d: raise ConnectionError("closed before 101")
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        assert b" 101 " in head.split(b"\r\n")[0], head[:60]
        self.credit = {}
    def ws(self, op, p):
        n = len(p)
        h = bytes([0x80 | op, 0x80 | n]) if n < 126 else (bytes([0x80 | op, 0xFE]) + struct.pack(">H", n) if n < 65536
                                                         else bytes([0x80 | op, 0xFF]) + struct.pack(">Q", n))
        self.s.sendall(h + b"\0\0\0\0" + p)  # zero mask key: the XOR is a no-op
    def send(self, ty, sid, body):
        self.ws(2, bytes([ty]) + struct.pack("<I", sid) + body)
    def connect(self, sid, udp=False):
        self.send(1, sid, (b"\x02" if udp else b"\x01") + struct.pack("<H", TPORT) + b"127.0.0.1")
    def poll(self, timeout):
        self.s.settimeout(timeout)
        try:
            d = self.s.recv(1 << 20)
            if not d: raise ConnectionError("closed")
            self.buf += d
        except (socket.timeout, ssl.SSLWantReadError):
            pass
        finally:
            self.s.settimeout(None)  # sends block while the server does not read us (that is the cap working)
        while len(self.buf) >= 2:
            ln = self.buf[1] & 0x7f; h = 2
            if ln == 126:
                if len(self.buf) < 4: break
                ln = struct.unpack(">H", self.buf[2:4])[0]; h = 4
            elif ln == 127:
                if len(self.buf) < 10: break
                ln = struct.unpack(">Q", self.buf[2:10])[0]; h = 10
            if len(self.buf) < h + ln: break
            op = self.buf[0] & 0x0f; p = self.buf[h:h + ln]; self.buf = self.buf[h + ln:]
            if op == 2 and len(p) >= 9 and p[0] == 3: self.credit[struct.unpack("<I", p[1:5])[0]] = struct.unpack("<I", p[5:9])[0]
            elif op == 9: self.ws(10, p)
    def pump(self, sids, until, chunk=b"u" * 16384, total=None, udp=False):
        """send DATA on `sids` as credit allows (UDP streams have no credit) until `until` (monotonic) or `total` bytes
        per stream are sent"""
        sent = {s: 0 for s in sids}
        while time.monotonic() < until:
            self.poll(0.001)
            moved = False
            for s in sids:
                if total is not None and sent[s] >= total: continue
                c = 1 if udp else self.credit.get(s, self.credit.get(0, 0))
                if c > 0:
                    part = chunk if total is None else chunk[: total - sent[s]]
                    self.credit[s] = c - 1; self.send(2, s, part); sent[s] += len(part); moved = True
            if total is not None and all(v >= total for v in sent.values()): break
            if not moved: self.poll(0.05)
        return sent

def rate(rec, t0):
    return sum(n for t, n in rec if t0 + WARM <= t < t0 + WARM + DUR) / DUR
def band(r, cap, lo=LO):
    return lo * cap <= r <= HI * cap
def run_conns(nconn, nstreams, tls=False):
    """nconn connections in threads, nstreams each; returns per-connection target rates"""
    SINKS.clear(); ws = [Wisp(tls) for _ in range(nconn)]; out = [0.0] * nconn
    for w in ws:
        for s in range(1, nstreams + 1): w.connect(s)
    time.sleep(0.2)
    t0 = time.monotonic()
    errs = []
    def go(w):
        try:
            w.pump(range(1, nstreams + 1), t0 + WARM + DUR + 0.3)
        except Exception as e:  # (review) an uploader that died must fail the case, not vanish from it
            errs.append(repr(e))
    th = [threading.Thread(target=go, args=(w,)) for w in ws]
    [t.start() for t in th]; [t.join() for t in th]
    for w in ws: w.s.close()
    if errs:
        raise RuntimeError(f"uploader failed: {errs}")
    # one target connection per stream: per connection only when nstreams or nconn is 1
    if len(SINKS) != nconn * nstreams:
        raise RuntimeError(f"{len(SINKS)} target connections, expected {nconn * nstreams}")
    rates = [rate(r[0], t0) for r in SINKS]
    return [sum(rates)] if nconn == 1 else rates
def metric(p, key):
    v = [int(x.split("=")[1]) for x in srvlog(p).split() if x.startswith(key + "=")]
    return v[-1] if v else None

K = 1024
def case(name, f):
    try:
        return f()
    except (RuntimeError, OSError, ssl.SSLError, AssertionError, ConnectionError) as e:
        ok(False, f"{name}: {e}")
        return None
p = start("--upload-rate", "256K")
ok("upload cap: 262144 B/s burst 262144 per connection" in srvlog(p), "startup line names the per-connection cap")
r = case("1 conn 2 streams", lambda: run_conns(1, 2))
if r: ok(band(r[0], 256 * K), f"--upload-rate 256K, one connection, two streams share it: {r[0] / (256 * K):.3f} x cap")
r = case("2 conns", lambda: run_conns(2, 1))
if r: ok(len(r) == 2 and all(band(x, 256 * K) for x in r), f"two connections each at the cap (per connection): {[round(x / (256 * K), 3) for x in r]}")
time.sleep(2.5)  # the earlier runs' bytes are published (close + sweep): the 600 KB check below is a delta
rx0 = metric(p, "rx_bytes") or 0
# 600 KB on one stream: complete and intact at the target while limited
SINKS.clear(); w = Wisp(); w.connect(1); time.sleep(0.2)
data = bytes(range(256)) * (600_000 // 256)
w.pump([1], time.monotonic() + 20, chunk=data, total=len(data))
deadline = time.monotonic() + 10
while time.monotonic() < deadline and (not SINKS or sum(n for _, n in SINKS[0][0]) < len(data)):
    w.poll(0.1)
got = sum(n for _, n in SINKS[0][0]) if SINKS else 0
ok(got == len(data) and SINKS[0][1].hexdigest() == hashlib.sha256(data).hexdigest(), f"600 KB on a limited stream arrive intact: {got} B")
w.s.close()
time.sleep(2.5)  # the close publishes rx_bytes; the next metrics line (1 s) shows it
rx, up = metric(p, "rx_bytes"), metric(p, "upl_pauses")
ok(rx is not None and rx - rx0 >= len(data) and up is not None and up > 0,
   f"metrics: rx_bytes grew by {None if rx is None else rx - rx0} (>= {len(data)}), upl_pauses={up}")
stop(p)

p = start("--upload-rate-per-ip", "512K")
ok("per-ip: upload 524288 B/s burst 524288" in srvlog(p), "startup line names the per-IP cap")
r = case("per-ip 2 conns", lambda: run_conns(2, 1))
if r:
    tot = sum(r)
    # no starvation, not equal shares: on one worker the split is ~0.5 / 0.5; across workers (connections on two
    # threads race on the table lock) 0.25-0.5 was measured (60.25 as built)
    ok(len(r) == 2 and band(tot, 512 * K) and min(r) >= 0.15 * tot,
       f"--upload-rate-per-ip 512K, two connections share it: {tot / (512 * K):.3f} x cap, split {[round(x / max(tot, 1), 2) for x in r]}")
ip_waits = metric(p, "upl_ip_waits")
stop(p)
ok(ip_waits is not None, f"metrics upl_ip_waits present ({ip_waits})")

p = start("--upload-rate", "64K")
w = Wisp(); w.connect(1, udp=True); time.sleep(0.2); UDP.clear()
t0 = time.monotonic()
w.pump([1], t0 + WARM + DUR + 0.3, chunk=b"d" * 1000, udp=True)
w.s.close()
ur = sum(n for t, n in UDP if t0 + WARM <= t < t0 + WARM + DUR) / DUR
ok(band(ur, 64 * K, 0.7), f"--upload-rate 64K, a UDP stream's datagrams: {ur / (64 * K):.3f} x cap (payload only)")
stop(p)

p = start("--upload-rate", "256K", tls=True)
if p.poll() is not None or "capabilities:" not in srvlog(p):
    print("SKIP wss: the server did not start with TLS (kTLS missing?)")
    stop(p)
else:
    r = case("wss", lambda: run_conns(1, 1, tls=True))
    if r: ok(band(r[0], 256 * K), f"wss (kTLS) --upload-rate 256K: {r[0] / (256 * K):.3f} x cap")
    stop(p)

for bad, why in [(["--upload-rate", "4K"], "8K..1T"), (["--upload-rate", "1M/16K"], "below 100 ms"), (["--upload-rate", "163841/16384"], "below 100 ms"), (["--upload-rate-per-ip", "x"], "R or R/B")]:
    q = subprocess.run([BIN, str(BASE), *bad], capture_output=True, text=True, timeout=10)
    ok(q.returncode != 0 and why in q.stderr, f"refused: {' '.join(bad)} ({q.stderr.strip()[:90]})")
cf = os.path.join(D, "fw.conf")
open(cf, "w").write("upload-rate 1M/512K\nupload-rate-per-ip 2M\n")
p = start("--config", cf)
log = srvlog(p)
ok("upload cap: 1048576 B/s burst 524288 per connection" in log and "upload 2097152 B/s burst 2097152" in log, "--config form")
stop(p)
print(f"uplimit: {'OK' if not fails else f'{fails} FAILED'}")
sys.exit(1 if fails else 0)
