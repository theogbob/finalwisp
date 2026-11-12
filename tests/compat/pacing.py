#!/usr/bin/env python3
"""60.30 C10a bandwidth caps against a real finalwisp, loopback, no root. Stdlib only.
usage: pacing.py FINALWISP_BINARY BASEPORT   (server BASEPORT, targets BASEPORT+1)
Cases (CAP = 1 MiB/s, rates over 4 s after a 1 s warm-up; loopback sends 64 KiB skbs and the first 10 segments
are unpaced, so the band is wide: 0.8..1.25 x CAP; the netns/veth matrix in 60.26 is the precise check):
- --download-rate 1M: one bulk download stream; with --threads 2 --balance three clients, each capped
- uncapped: the same download is > 5 x CAP (the cap is the feature, not the harness)
- --upload-rate-per-stream 1M: two upload streams on one connection, each at the cap (per stream, not shared)
- startup line: `pacing: download/conn ... (splice off)`, `upload/stream ...`; bad values refused; --config form."""
import base64, os, socket, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
TPORT = BASE + 1
CAP, WARM, DUR = 1 << 20, 1.0, 4.0
LO, HI = 0.8, 1.25
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

# one target port: a client that sends "S" gets an endless stream (download source); "U" = a sink that counts bytes
SINKS = []
def serve(c):
    with c:
        try:
            kind = c.recv(1)
            if kind == b"S":
                d = b"x" * 65536
                while True: c.sendall(d)
            rec = [0, []]; SINKS.append(rec)
            while (d := c.recv(1 << 20)):
                rec[1].append((time.monotonic(), len(d)))
        except OSError:
            pass
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", TPORT)); ls.listen(64)
threading.Thread(target=lambda: [threading.Thread(target=serve, args=(ls.accept()[0],), daemon=True).start() for _ in iter(int, 1)],
                 daemon=True).start()

D = tempfile.mkdtemp(prefix="fw-pacing-")
def start(*args):
    log = open(os.path.join(D, "srv.log"), "w+")
    p = subprocess.Popen([BIN, str(BASE), "--allow-loopback", "--log-level", "debug", *args], stdout=log, stderr=subprocess.STDOUT)
    p.logf = log
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", BASE), timeout=1).close(); break
        except OSError:
            if p.poll() is not None: break
            time.sleep(0.05)
    for _ in range(100):  # review: the capability line comes after the listeners are up
        if "capabilities:" in srvlog(p) or p.poll() is not None: break
        time.sleep(0.05)
    time.sleep(0.2)
    return p
def srvlog(p):
    with open(p.logf.name) as f:
        return f.read()
def stop(p):
    p.terminate()
    try: p.wait(10)
    except subprocess.TimeoutExpired: p.kill(); p.wait()

class Wisp:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", BASE), timeout=10)
        self.s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
                       + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(65536)
            if not d: raise ConnectionError("closed before 101")
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        assert b" 101 " in head.split(b"\r\n")[0], head[:60]
    def ws(self, op, p):
        n = len(p)
        h = bytes([0x80 | op, 0x80 | n]) if n < 126 else (bytes([0x80 | op, 0xFE]) + struct.pack(">H", n) if n < 65536
                                                         else bytes([0x80 | op, 0xFF]) + struct.pack(">Q", n))
        self.s.sendall(h + b"\0\0\0\0" + p)  # zero mask key: the XOR is a no-op
    def send(self, ty, sid, body):
        self.ws(2, bytes([ty]) + struct.pack("<I", sid) + body)
    def connect(self, sid, first):
        self.send(1, sid, b"\x01" + struct.pack("<H", TPORT) + b"127.0.0.1")
        self.send(2, sid, first)
    def frames(self, timeout):
        """(type, sid, body) of the Wisp packets that arrive within `timeout` (a ping is answered)"""
        self.s.settimeout(timeout)
        try:
            d = self.s.recv(1 << 20)
            if not d: raise ConnectionError("closed")
            self.buf += d
        except socket.timeout:
            pass
        out = []
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
            if op == 2 and len(p) >= 5: out.append((p[0], struct.unpack("<I", p[1:5])[0], p[5:]))
            elif op == 9: self.ws(10, p)
        return out

def download_rate():
    w = Wisp(); w.connect(1, b"S"); t0 = time.monotonic(); got = 0
    while (t := time.monotonic() - t0) < WARM + DUR:
        for ty, sid, body in w.frames(0.2):
            if ty == 2 and WARM <= time.monotonic() - t0 < WARM + DUR: got += len(body)
    w.s.close()
    return got / DUR

def upload_rates(n):
    w = Wisp(); SINKS.clear(); credit = {}
    for sid in range(1, n + 1): w.connect(sid, b"U")
    chunk = b"u" * 16384; t0 = time.monotonic()
    while time.monotonic() - t0 < WARM + DUR + 0.3:
        for ty, sid, body in w.frames(0.001):
            if ty == 3: credit[sid] = struct.unpack("<I", body[:4])[0]
        sent = False
        for sid in range(1, n + 1):
            c = credit.get(sid, credit.get(0, 0))
            if c > 0:
                credit[sid] = c - 1; w.send(2, sid, chunk); sent = True
        if not sent:
            for ty, sid, body in w.frames(0.05):
                if ty == 3: credit[sid] = struct.unpack("<I", body[:4])[0]
    w.s.close()
    return [sum(b for t, b in r[1] if t0 + WARM <= t < t0 + WARM + DUR) / DUR for r in SINKS]

band = lambda r: LO * CAP <= r <= HI * CAP

p = start("--download-rate", "1M", "--upload-rate-per-stream", "1M")
log = srvlog(p)
ok("pacing: download/conn 1048576 B/s = 8.4 Mbit/s (splice off) upload/stream 1048576 B/s = 8.4 Mbit/s (TCP streams only)" in log,
   "startup line names both caps, splice off")
r = download_rate()
ok(band(r), f"download 1 stream at --download-rate 1M: {r / CAP:.3f} x cap")
rs = upload_rates(2)
ok(len(rs) == 2 and all(band(x) for x in rs), f"upload 2 streams at --upload-rate-per-stream 1M: {[round(x / CAP, 3) for x in rs]} x cap each")
stop(p)

p = start("--threads", "2", "--balance", "--download-rate", "1M")
res = []
ths = [threading.Thread(target=lambda: res.append(download_rate())) for _ in range(3)]
[t.start() for t in ths]; [t.join() for t in ths]
ok(len(res) == 3 and all(band(x) for x in res), f"--balance, 3 clients: {[round(x / CAP, 3) for x in res]} x cap each")
stop(p)

p = start()
r = download_rate()
ok(r > 5 * CAP and "pacing:" not in srvlog(p), f"uncapped: {r / CAP:.1f} x cap, no pacing in the startup line")
stop(p)

for bad in ["16383", "4G", "1.5M", "x"]:
    q = subprocess.run([BIN, str(BASE), "--download-rate", bad], capture_output=True, text=True, timeout=10)
    ok(q.returncode != 0 and "16K..4095M" in q.stderr, f"--download-rate {bad} refused")

cf = os.path.join(D, "fw.conf")
open(cf, "w").write("allow-loopback\ndownload-rate 2M\n")
os.chmod(cf, 0o600)
p = subprocess.Popen([BIN, str(BASE), "--log-level", "debug", "--config", cf], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(1.0); stop(p)
out = p.stdout.read()
ok("download/conn 2097152 B/s" in out, "--config download-rate 2M")

if fails:
    print(f"server logs: {D}")
print(f"{'FAIL' if fails else 'PASS'} pacing: {fails} failed")
sys.exit(1 if fails else 0)
