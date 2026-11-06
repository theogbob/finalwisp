#!/usr/bin/env python3
"""60.20 C1 destination policy against a real finalwisp. Stdlib only. usage: policy.py FINALWISP_BINARY BASEPORT
Ports: BASEPORT (each server in turn), BASEPORT+1 (TCP echo on 127.0.0.1 and 127.0.0.2, UDP echo on 127.0.0.1).
Cases: port rules per protocol (tcp: blocks TCP, UDP passes), --block-smtp, --block-host (subdomain, case, trailing dot:
0x48 at once, before DNS; a sibling name goes to DNS), wsproxy 403 before the 101, the capability line and the SMTP
hint; --no-direct-ip (inet_aton forms) and an allow list (default deny; a name allow does not lift the loopback class);
--no-ipv6-targets (getaddrinfo and --dns-own: localhost connects over IPv4, ::1 refused); --allow-dest beats the
loopback class for one address only; recursion: a CONNECT to the server's own non-loopback address (and to 0.0.0.0, ::)
is refused even with --allow-private, and with --allow-self a nested Wisp handshake runs through it (skipped when the
box has no non-loopback IPv4 address); metrics refuse_policy."""
import base64, os, socket, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
P, E = BASE, BASE + 1
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

def pump(c):
    with c:
        try:
            while (d := c.recv(65536)): c.sendall(d)
        except OSError: pass
def tcp_echo(addr):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind((addr, E)); ls.listen(64)
    def acc():
        while True:
            c, _ = ls.accept(); threading.Thread(target=pump, args=(c,), daemon=True).start()
    threading.Thread(target=acc, daemon=True).start()
for a in ("127.0.0.1", "127.0.0.2"):
    tcp_echo(a)
us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); us.bind(("127.0.0.1", E))
def uecho():
    while True:
        d, f = us.recvfrom(65536); us.sendto(d, f)
threading.Thread(target=uecho, daemon=True).start()

D = tempfile.mkdtemp(prefix="fw-policy-")
def start(*args, host="127.0.0.1"):
    log = open(os.path.join(D, f"srv{time.monotonic_ns()}.log"), "w+")
    p = subprocess.Popen([BIN, str(P), "--host", host, "--metrics-interval", "1", *args], stdout=log, stderr=subprocess.STDOUT)
    p.logf, p.host = log, host
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
UPGRADE = (b"GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
           + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")

class Wisp:
    def __init__(self, host="127.0.0.1"):
        self.s = socket.create_connection((host, P), timeout=3)
        self.s.sendall(UPGRADE.replace(b"{path}", b"/"))
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d: raise ConnectionResetError("closed before 101")
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        assert b" 101 " in head.split(b"\r\n")[0], head[:60]
        self.sid = 0
    def send(self, ty, sid, body):
        self.s.sendall(frame(bytes([ty]) + struct.pack("<I", sid) + body))
    def connect(self, host, port=E, udp=False):
        self.sid += 1
        self.send(1, self.sid, (b"\x02" if udp else b"\x01") + struct.pack("<H", port) + host.encode())
        return self.sid
    def packets(self, t):
        out, end = [], time.time() + t
        self.s.settimeout(0.05)
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
            try:
                d = self.s.recv(65536)
                if not d: break
                self.buf += d
            except socket.timeout:
                pass
        return out
    def close_reason(self, sid, t=0.5):
        """the CLOSE reason for sid within t seconds (None = no CLOSE: the stream is up)"""
        end = time.time() + t
        while time.time() < end:
            for ty, s, body in self.packets(0.1):
                if ty == 4 and s == sid: return body[0]
        return None
    def echo(self, sid, data=b"policy-echo"):
        self.send(2, sid, data)
        got = b""
        for ty, s, body in self.packets(1.0):
            if ty == 2 and s == sid: got += body
        return got == data
    def close(self): self.s.close()

def reason(w, host, port=E, udp=False, t=0.5):
    sid = w.connect(host, port, udp)
    return sid, w.close_reason(sid, t)
def connects(w, host, port=E, udp=False):
    sid = w.connect(host, port, udp)
    return w.echo(sid) and w.close_reason(sid, 0.1) is None

# 1. port / host / smtp rules, wsproxy, capability line, hint
p = start("--allow-loopback", "--block-ports", f"tcp:{E}", "--block-host", "blocked.test", "--block-smtp")
log = srvlog(p)
ok("policy: hosts +0 -1, ports +0 -1, no smtp, own addresses blocked" in log, "capability line names the rules")
ok("hint: mail ports" not in log, "no SMTP hint with --block-smtp")
w = Wisp()
ok(reason(w, "127.0.0.1")[1] == 0x48, "tcp: port rule -> 0x48")
ok(connects(w, "127.0.0.1", udp=True), "the tcp: rule leaves UDP to the same port open")
ok(reason(w, "127.0.0.1", 25)[1] == 0x48 and reason(w, "127.0.0.1", 587)[1] == 0x48, "--block-smtp: 25, 587 -> 0x48")
for h in ["blocked.test", "x.BLOCKED.TEST.", "a.b.blocked.test"]:
    t0 = time.time(); r = reason(w, h, 80)[1]
    ok(r == 0x48 and time.time() - t0 < 0.4, f"--block-host: {h} -> 0x48 at once (before DNS)")
ok(reason(w, "notblocked.test", 80, t=8)[1] == 0x42, "notblocked.test is not matched (goes to DNS: 0x42)")
ok(connects(w, "127.0.0.1", udp=True), "the connection stays up after the refusals")
s = socket.create_connection(("127.0.0.1", P), timeout=3)
s.sendall(UPGRADE.replace(b"{path}", b"/p/x.blocked.test:80"))
resp = s.recv(4096); s.close()
ok(resp.startswith(b"HTTP/1.1 403") and b" 101 " not in resp, f"wsproxy: refused before the 101 ({resp[:40]!r})")
n = metric(p, "refuse_policy")
ok(n == 7, f"metrics refuse_policy counts them: 7 ({n})")
w.close(); stop(p)

# 2. --no-direct-ip and an allow list (no --allow-loopback)
p = start("--no-direct-ip", "--allow-host", "localhost")
ok("hint: mail ports 25/465/587 are open to clients; --block-smtp closes them" in srvlog(p), "SMTP hint without --block-smtp")
w = Wisp()
for h in ["127.0.0.1", "127.1", "2130706433", "0x7f000001", "0177.0.0.1", "::ffff:127.0.0.1", "8.8.8.8", "::1%1", "::ffff:127.0.0.1%1"]:
    ok(reason(w, h)[1] == 0x48, f"--no-direct-ip: {h} -> 0x48")
ok(reason(w, "example.com", 80)[1] == 0x48, "allow list: another name -> 0x48 at once")
ok(reason(w, "localhost", t=3)[1] == 0x48, "an allowed name does not lift the loopback class (address stage 0x48)")
w.close(); stop(p)

# 3. --no-ipv6-targets, with getaddrinfo and with the own resolver
for extra in ([], ["--dns-own"]):
    p = start("--allow-loopback", "--no-ipv6-targets", *extra)
    tag = "dns-own" if extra else "getaddrinfo"
    w = Wisp()
    ok(reason(w, "::1")[1] == 0x48, f"{tag}: --no-ipv6-targets: ::1 -> 0x48")
    ok(connects(w, "localhost"), f"{tag}: localhost connects over IPv4")
    ok(connects(w, "::ffff:127.0.0.1"), f"{tag}: an IPv4-mapped literal counts as IPv4")
    w.close(); stop(p)

# 4. --allow-dest beats the loopback class for that CIDR only
p = start("--allow-dest", "127.0.0.2/32")
w = Wisp()
ok(connects(w, "127.0.0.2"), "--allow-dest 127.0.0.2/32: connects without --allow-loopback")
ok(reason(w, "127.0.0.1")[1] == 0x48, "127.0.0.1 still refused")
w.close(); stop(p)

# 5. recursion: our own addresses
def own_v4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9)); a = s.getsockname()[0]  # no packet is sent: the route's source address
        return None if a.startswith("127.") else a
    except OSError:
        return None
    finally:
        s.close()
me = own_v4()
p = start("--allow-private", "--allow-embedded-v4", "--allow-self")
w = Wisp()
for h in ["0.0.0.0", "0.1.2.3", "::", "::ffff:0.0.0.0"]:
    ok(reason(w, h, P, t=2)[1] == 0x48, f"unspecified {h}:{P} -> 0x48 without --allow-loopback (also with the other allow flags)")
w.close(); stop(p)
if me is None:
    print("SKIP recursion via an own address: no non-loopback IPv4 address", flush=True)
else:
    p = start("--allow-private")
    ok("own addresses blocked (" in srvlog(p) and "own addresses blocked (0)" not in srvlog(p), "own addresses in the capability line")
    w = Wisp()
    for h in [me, f"::ffff:{me}"]:
        ok(reason(w, h, P, t=2)[1] == 0x48, f"recursion to our own address {h}:{P} -> 0x48 with --allow-private")
    w.close(); stop(p)
    # --allow-self: a nested Wisp handshake through the server to itself. The server listens on that address for a few
    # seconds, so it can reach port P only (--allow-ports) and no UDP.
    p = start("--allow-self", "--allow-private", "--allow-ports", f"tcp:{P}", "--no-udp", host=me)
    w = Wisp(me)
    sid = w.connect(me, P)
    w.send(2, sid, UPGRADE.replace(b"{path}", b"/"))
    got = b"".join(b for ty, s, b in w.packets(1.5) if ty == 2 and s == sid)
    ok(b" 101 " in got.split(b"\r\n")[0], f"--allow-self: nested Wisp handshake through our own address ({got[:30]!r})")
    w.close(); stop(p)

print(f"{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
sys.exit(1 if fails else 0)
