#!/usr/bin/env python3
"""60.27 / 60.32 C6 --upstream against REAL proxies in a throwaway Debian 13 container (not a compat step: it needs the
proxies, set up by tests/compat/upstream_real_setup.sh as root; 60.32 "Real proxies" has the recipe).
usage: upstream_real.py FINALWISP BASEPORT. Proxies must already listen: microsocks :1080 (no auth), :1081 (user u / pass p),
openssh `ssh -D 1082` (no auth; dante is not in Debian 13), tinyproxy :8888 (BasicAuth u p), squid :3128 (no auth, denies 192.0.2.9).
Prints one observation line per case; PASS/FAIL against the 60.27 mapping."""
import base64, hashlib, os, socket, struct, subprocess, sys, tempfile, threading, time
BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
P, E, BAN, BULK = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True); fails += 0 if c else 1
def serve(port, handler, host="0.0.0.0", fam=socket.AF_INET):
    ls = socket.socket(fam); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6: ls.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    ls.bind((host, port)); ls.listen(128)
    def acc():
        while True:
            c, _ = ls.accept(); threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=acc, daemon=True).start()
def pump(c):
    with c:
        try:
            while (d := c.recv(65536)): c.sendall(d)
        except OSError: pass
def banner(c): c.sendall(b"220 hello\r\n"); pump(c)
BULK_DATA = os.urandom(1 << 20) * 32
def bulk(c):
    with c:
        try: c.sendall(BULK_DATA)
        except OSError: pass
for port, h in ((E, pump), (BAN, banner), (BULK, bulk)):
    serve(port, h)
V6ONLY = BASE + 5
serve(V6ONLY, pump, "::1", socket.AF_INET6)  # retry case: only ::1 listens, so the IPv4-first attempt is refused
D = tempfile.mkdtemp(prefix="fw-real-")
def start(*args):
    log = open(os.path.join(D, f"srv{time.monotonic_ns()}.log"), "w+")
    p = subprocess.Popen([BIN, str(P), "--host", "127.0.0.1", "--log-level", "debug", "--metrics-interval", "1", "--allow-loopback", *args], stdout=log, stderr=subprocess.STDOUT)
    p.logf = log
    for _ in range(100):
        if "capabilities:" in open(log.name).read() or p.poll() is not None: break
        time.sleep(0.05)
    return p
def stop(p):
    p.terminate()
    try: p.wait(10)
    except subprocess.TimeoutExpired: p.kill(); p.wait()
def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))
UPGRADE = (b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
           + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
class Wisp:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", P), timeout=3); self.s.sendall(UPGRADE); self.buf = b""
        while b"\r\n\r\n" not in self.buf: self.buf += self.s.recv(4096)
        head, self.buf = self.buf.split(b"\r\n\r\n", 1); self.sid = 0
    def send(self, ty, sid, body): self.s.sendall(frame(bytes([ty]) + struct.pack("<I", sid) + body))
    def connect(self, host, port=E, data=None):
        self.sid += 1; self.send(1, self.sid, b"\x01" + struct.pack("<H", port) + host.encode())
        if data: self.send(2, self.sid, data)
        return self.sid
    def packets(self, t, until):
        out, end = [], time.time() + t; self.s.settimeout(0.05)
        while time.time() < end:
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
                if len(p) >= 5: out.append((p[0], struct.unpack("<I", p[1:5])[0], p[5:]))
            if until(out): return out
            try:
                d = self.s.recv(1 << 20)
                if not d: break
                self.buf += d
            except socket.timeout: pass
        return out
    def result(self, sid, t=8):
        pk = self.packets(t, lambda o: any(s == sid and ty in (2, 4) for ty, s, _ in o))
        for ty, s, b in pk:
            if s == sid and ty == 4: return ("close", hex(b[0]))
            if s == sid and ty == 2: return ("data", b)
        return ("none", None)
    def data(self, sid, n, t=10):
        pk = self.packets(t, lambda o: sum(len(b) for ty, s, b in o if s == sid and ty == 2) >= n
                          or any(s == sid and ty == 4 for ty, s, _ in o))
        self.last_close = next((hex(b[0]) for ty, s, b in pk if s == sid and ty == 4), None)
        return b"".join(b for ty, s, b in pk if s == sid and ty == 2)
def closed_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); return s, s.getsockname()[1]
keep, dead = closed_port()
PROXIES = [
    ("microsocks", "socks5://127.0.0.1:1080", None),
    ("microsocks-auth", "socks5://u:p@127.0.0.1:1081", "socks5://u:bad@127.0.0.1:1081"),
    ("openssh-D", "socks5://127.0.0.1:1082", None),
    ("tinyproxy-auth", "http://u:p@127.0.0.1:8888", "http://u:bad@127.0.0.1:8888"),
    ("squid", "http://127.0.0.1:3128", None),
]
for name, url, badurl in PROXIES:
    print(f"==== {name} {url.split('@')[-1]}", flush=True)
    p = start("--upstream", url, "--connect-timeout", "4", "--allow-dest", "192.0.2.9", "--allow-dest", "203.0.113.0/24")
    w = Wisp()
    sid = w.connect("127.0.0.1", data=b"ping"); ok(w.data(sid, 4) == b"ping", f"{name}: echo, IP literal")
    sid = w.connect("localhost", data=b"pong"); ok(w.data(sid, 4) == b"pong", f"{name}: echo, name resolved locally")
    sid = w.connect("127.0.0.1", BAN); got = w.data(sid, 11); ok(got == b"220 hello\r\n", f"{name}: server-first banner {got!r}")
    sid = w.connect("127.0.0.1", dead); r = w.result(sid); print(f"OBS {name}: closed target port -> {r}")
    sid = w.connect("192.0.2.9", 80); t0 = time.time(); r = w.result(sid); print(f"OBS {name}: blackhole/denied 192.0.2.9 -> {r} after {time.time()-t0:.1f}s")
    sid = w.connect("localhost", V6ONLY, data=b"v6"); got = w.data(sid, 2); r = "echo" if got == b"v6" else ("close", w.last_close)
    print(f"OBS {name}: localhost:{V6ONLY} listening on ::1 only (127.0.0.1 refused first) -> {r}")
    sid = w.connect("127.0.0.1", BULK); t0 = time.time(); got = w.data(sid, len(BULK_DATA), 60)
    ok(hashlib.sha256(got).digest() == hashlib.sha256(BULK_DATA).digest(), f"{name}: 32 MiB download intact ({len(got)} B)")
    stop(p)
    if badurl:
        p = start("--upstream", badurl); w = Wisp(); sid = w.connect("127.0.0.1")
        r = w.result(sid); ok(r == ("close", "0x3"), f"{name}: wrong password -> {r} (want 0x3)"); stop(p)
# socks5h via microsocks: the proxy resolves
p = start("--upstream", "socks5h://127.0.0.1:1080", "--upstream-trust-dns")
w = Wisp(); sid = w.connect("localhost", data=b"h"); got = w.data(sid, 1)
print(f"OBS microsocks socks5h localhost -> v4-only echo: {'echo' if got == b'h' else ('close', w.last_close)}")
sid = w.connect("localhost", V6ONLY, data=b"h"); got = w.data(sid, 1)
ok(got == b"h", f"microsocks socks5h: name resolved by the proxy (::1-only listener: {'echo' if got == b'h' else w.last_close})")
sid = w.connect("no-such-name.invalid"); r = w.result(sid); print(f"OBS microsocks socks5h: NXDOMAIN at the proxy -> {r}")
sid = w.connect("127.1"); r = w.result(sid); ok(r == ("close", "0x48"), f"socks5h 127.1 refused locally -> {r}")
stop(p)
# localhost through microsocks: 127.0.0.1 first (IPv4 first, wispurr parity), the v4-only banner target
p = start("--upstream", "socks5://127.0.0.1:1080")
w = Wisp(); sid = w.connect("localhost", BAN); got = w.data(sid, 11)
ok(got == b"220 hello\r\n", f"microsocks: localhost (127.0.0.1 first) banner {got!r}")
stop(p)
print("real:", "ALL PASS" if fails == 0 else f"{fails} FAIL", flush=True)
sys.exit(1 if fails else 0)  # (review)
