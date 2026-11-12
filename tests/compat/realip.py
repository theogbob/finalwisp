#!/usr/bin/env python3
"""60.20 C2 real client IP + C3b per-IP limits against a real finalwisp. Stdlib only.
usage: realip.py FINALWISP_BINARY BASEPORT (BASEPORT = server, BASEPORT+1 = TCP echo)
Cases: --max-conns-per-ip across --threads 4, with and without --balance: exactly N connections per source address
(127.0.0.2 / 127.0.0.3), the rest reset at accept; a close makes room. Behind a trusted proxy (--trusted-proxy
127.0.0.1): keyed by the rightmost untrusted X-Forwarded-For entry, over the limit 429; no header: not limited; a
spoofed header from an untrusted peer (127.0.0.2) is ignored (its own address is the key); wsproxy counts as a
connection; --stream-rate-per-ip: burst, then 0x49, refill. Metrics refuse_ip_conns / refuse_ip_rate /
realip_missing."""
import base64, os, socket, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
P, E = BASE, BASE + 1
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", E)); ls.listen(64)
def pump(c):
    with c:
        try:
            while (d := c.recv(65536)): c.sendall(d)
        except OSError: pass
def acc():
    while True:
        c, _ = ls.accept(); threading.Thread(target=pump, args=(c,), daemon=True).start()
threading.Thread(target=acc, daemon=True).start()

D = tempfile.mkdtemp(prefix="fw-realip-")
def start(*args):
    log = open(os.path.join(D, f"srv{time.monotonic_ns()}.log"), "w+")
    p = subprocess.Popen([BIN, str(P), "--allow-loopback", "--log-level", "debug", "--threads", "4", "--metrics-interval", "1", *args],
                         stdout=log, stderr=subprocess.STDOUT)
    p.logf = log
    for _ in range(100):
        if "capabilities:" in srvlog(p) or p.poll() is not None: break
        time.sleep(0.05)
    return p
def srvlog(p):
    with open(p.logf.name) as f: return f.read()
def stop(p):
    p.terminate()
    try: p.wait(10)
    except subprocess.TimeoutExpired: p.kill(); p.wait()
def metric(p, key):
    time.sleep(1.2)
    vals = [l for l in srvlog(p).splitlines() if "ev=metrics" in l]
    for kv in (vals[-1].split() if vals else []):
        if kv.startswith(key + "="): return int(kv.split("=", 1)[1])
    return None

def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

class Refused(Exception): pass

class Conn:
    """an upgrade from source address `src`, optional X-Forwarded-For; raises Refused(status or 'reset')"""
    def __init__(self, src, xff=None, path="/"):
        self.s = socket.socket(); self.s.bind((src, 0)); self.s.settimeout(3)
        try:
            self.s.connect(("127.0.0.1", P))
            h = f"X-Forwarded-For: {xff}\r\n" if xff is not None else ""
            self.s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n{h}Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ".encode()
                           + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
            self.buf = b""
            while b"\r\n\r\n" not in self.buf:
                d = self.s.recv(4096)
                if not d: raise Refused("closed")
                self.buf += d
        except (ConnectionResetError, BrokenPipeError):
            self.s.close(); raise Refused("reset")
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        status = head.split(b"\r\n")[0]
        if b" 101 " not in status:
            self.s.close(); raise Refused(status.split(b" ")[1].decode())
    def send(self, ty, sid, body): self.s.sendall(frame(bytes([ty]) + struct.pack("<I", sid) + body))
    def connect(self, sid): self.send(1, sid, b"\x01" + struct.pack("<H", E) + b"127.0.0.1")
    def close_reason(self, sid, t=0.5):
        """the CLOSE reason for sid (None: none within t); CLOSEs for other streams are kept for later calls"""
        self.closes = getattr(self, "closes", {})
        end = time.time() + t; self.s.settimeout(0.05)
        while time.time() < end:
            if sid in self.closes: return self.closes[sid]
            try:
                d = self.s.recv(65536)
                if not d: return "eof"
                self.buf += d
            except socket.timeout: pass
            while len(self.buf) >= 2:
                ln = self.buf[1] & 0x7f; h = 2
                if ln == 126:
                    if len(self.buf) < 4: break
                    ln = struct.unpack(">H", self.buf[2:4])[0]; h = 4
                if len(self.buf) < h + ln: break
                p, self.buf = self.buf[h:h + ln], self.buf[h + ln:]
                if len(p) >= 6 and p[0] == 4: self.closes[struct.unpack("<I", p[1:5])[0]] = p[5]
        return self.closes.get(sid)
    def close(self): self.s.close()

def attempt(src, xff=None, path="/"):
    try: return Conn(src, xff, path), "101"
    except Refused as e: return None, str(e)

# 1. direct peers: exactly N per source address across 4 threads, with and without --balance
for extra in ([], ["--balance"]):
    tag = "balance" if extra else "reuseport"
    p = start("--max-conns-per-ip", "3", *extra)
    ok("per-ip: conns 3" in srvlog(p), f"{tag}: capability line")
    res = [attempt("127.0.0.2") for _ in range(6)]
    ok(sum(1 for c, _ in res if c) == 3 and all(s == "reset" for c, s in res if not c), f"{tag}: exactly 3 of 6 from 127.0.0.2, the rest reset ({[s for _, s in res]})")
    other = [attempt("127.0.0.3") for _ in range(3)]
    ok(all(c for c, _ in other), f"{tag}: 127.0.0.3 has its own 3")
    next(c for c, _ in res if c).close(); time.sleep(0.2)
    again = attempt("127.0.0.2")  # kept: a dropped Conn closes its socket
    ok(again[0] is not None, f"{tag}: a close makes room")
    ok(attempt("127.0.0.2")[1] == "reset", f"{tag}: and only one")
    ok(metric(p, "refuse_ip_conns") == 4, f"{tag}: refuse_ip_conns = 4")
    stop(p)

# 2. behind a trusted proxy (127.0.0.1)
p = start("--trusted-proxy", "127.0.0.1", "--max-conns-per-ip", "2", "--stream-rate-per-ip", "2/3")
ok("client ip: 1 trusted proxies (header x-forwarded-for)" in srvlog(p) and "streams 2/s burst 3" in srvlog(p), "capability line")
a = [attempt("127.0.0.1", "5.5.5.5") for _ in range(3)]
ok([s for _, s in a] == ["101", "101", "429"], f"XFF 5.5.5.5: 2 admitted, the 3rd 429 ({[s for _, s in a]})")
b = [attempt("127.0.0.1", "5.5.5.5, 6.6.6.6") for _ in range(2)]
ok(all(c for c, _ in b), "keyed by the rightmost untrusted entry (6.6.6.6, not the client-written 5.5.5.5)")
ok(attempt("127.0.0.1", "1.2.3.4, 6.6.6.6, 127.0.0.1")[1] == "429", "trusted hops skipped: 6.6.6.6 again -> 429")
n = [attempt("127.0.0.1") for _ in range(4)]
ok(all(c for c, _ in n), "no header from the proxy: not limited (fail open)")
s = [attempt("127.0.0.2", "9.9.9.9") for _ in range(3)]
ok([x for _, x in s] == ["101", "101", "reset"], f"untrusted peer: its header is ignored, its own address is limited at accept ({[x for _, x in s]})")
ok(attempt("127.0.0.1", "9.9.9.9")[0] is not None, "so 9.9.9.9 behind the proxy is still free")
ok(attempt("127.0.0.1", "5.5.5.5", "/p/127.0.0.1:%d" % E)[1] == "429", "wsproxy counts as a connection (5.5.5.5 is full: 429)")
a[0][0].close(); time.sleep(0.2)
w, st = attempt("127.0.0.1", "5.5.5.5", "/p/127.0.0.1:%d" % E)
ok(w is not None, f"wsproxy admitted after a close ({st})")
# stream rate 2/s burst 3 on 6.6.6.6 (one key for both connections)
c1, c2 = b[0][0], b[1][0]
c1.connect(1); c2.connect(2); c1.connect(3); c2.connect(4)  # at once: the bucket refills 2/s
r = [c1.close_reason(1, 0.3), c2.close_reason(2, 0.3), c1.close_reason(3, 0.3), c2.close_reason(4, 0.3)]
ok(sorted(r, key=str) == [73, None, None, None], f"burst 3 across the key's two connections (on two threads), one 0x49 ({r})")
time.sleep(0.6)
c1.connect(5)
ok(c1.close_reason(5) is None, "refilled after 0.5 s")
rr, rm = metric(p, "refuse_ip_rate"), metric(p, "realip_missing")
ok((rr, rm) == (1, 4), f"refuse_ip_rate 1 / realip_missing 4 ({rr}, {rm})")
ok(metric(p, "refuse_ip_conns") == 4, f"refuse_ip_conns = 4 ({metric(p, 'refuse_ip_conns')})")
stop(p)

print(f"{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
sys.exit(1 if fails else 0)
