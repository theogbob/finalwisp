#!/usr/bin/env python3
"""60.63 section E against a real finalwisp. Stdlib only. usage: bounds.py FINALWISP_BINARY BASEPORT
(BASEPORT, +1 = the test's echo target). A client gets a public address from a PROXY protocol v1 header: the rules of
section E never apply to a loopback client.
Cases:
- off: no guard thread, no row in --show-config; the counters are in the metrics line.
- on (--tcpmem-share --port-share --dest-failfast --net-watch): the guard thread runs, --show-config has the rows of
  the four parts; 200 streams of one address beside another client open and echo, and nothing is refused.
- E3 end to end. A destination whose accept queue is full drops every SYN. 10 connects of one address hang. After the
  4th SYN of each (3 s) and the worker's sweep it is a suspect (gauge dest_dead 1, one warning that names it). New
  streams to it get CLOSE 0x43 within a second, except one probe per second (refuse_dest_dead moves, connect_timeout
  does not); a stream to another destination opens. The destination answers again: the suspect goes and a new stream
  to it opens.
- E3 a destination that was dead and then refuses the connection: the suspect goes, a new stream gets 0x44.
E1 and E2 act on a host at 3/4 of its TCP memory or of its source ports toward one destination: the unit tests
(bounds::tests, worker::tests::bd) and the box cells of note 60.63 cover them.
A timeout is a failure everywhere."""
import base64, os, socket, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
TGT = BASE + 1
A, B = "203.0.113.1", "198.51.100.7"
ON = ("--tcpmem-share", "--port-share", "--dest-failfast", "--net-watch")
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
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", TGT)); ls.listen(1024)
threading.Thread(target=acceptor, args=(ls,), daemon=True).start()

class Dead:
    """a listener whose accept queue is full: the kernel drops every further SYN"""
    def __init__(self):
        self.s = socket.socket(); self.s.bind(("127.0.0.1", 0)); self.s.listen(0)
        self.port = self.s.getsockname()[1]
        self.fill = []
        for _ in range(3):
            c = socket.socket(); c.settimeout(0.3)
            try: c.connect(("127.0.0.1", self.port)); self.fill.append(c)
            except OSError: c.close()
    def revive(self):
        self.s.listen(4096)
        threading.Thread(target=acceptor, args=(self.s,), daemon=True).start()
    def refuse(self):
        for c in self.fill: c.close()
        self.s.close()

D = tempfile.mkdtemp(prefix="fw-bounds-")
def start(*args):
    log = open(os.path.join(D, f"srv{time.monotonic_ns()}.log"), "w+")
    p = subprocess.Popen([BIN, str(BASE), "--allow-loopback", "--metrics-interval", "1", "--threads", "1", "--connect-timeout", "40",
                          "--proxy-protocol", "tcp", "--proxy-protocol-from", "127.0.0.0/8", *args], stdout=log, stderr=subprocess.STDOUT)
    p.logf = log
    for _ in range(200):
        if "listening on" in srvlog(p) or p.poll() is not None: break
        time.sleep(0.05)
    time.sleep(0.2)
    return p
def srvlog(p):
    with open(p.logf.name) as f:
        return f.read()
def stop(p):
    p.terminate()
    try: p.wait(15)
    except subprocess.TimeoutExpired: p.kill(); p.wait()
    for _ in range(100):
        try: t = socket.socket(); t.bind(("127.0.0.1", BASE)); t.close(); break
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
def until(p, key, want, secs):
    end = time.time() + secs
    while time.time() < end:
        if metric(p, key) == want: return True
    return False
def threads(p):
    out = []
    for t in os.listdir(f"/proc/{p.pid}/task"):
        try: out.append(open(f"/proc/{p.pid}/task/{t}/comm").read().strip())
        except OSError: pass
    return out

def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

class Wisp:
    """a Wisp client whose address is `src` (PROXY protocol v1)"""
    def __init__(self, src):
        self.s = socket.create_connection(("127.0.0.1", BASE), timeout=3)
        self.s.settimeout(3)
        self.s.sendall(f"PROXY TCP4 {src} 192.0.2.1 40000 443\r\n".encode()
                       + b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
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
    def connect(self, sid, port=TGT):
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
    def echo(self, sid, data=b"ping"):
        self.send(2, sid, data)
        got = lambda out: b"".join(b for ty, s, b in out if ty == 2 and s == sid)
        return got(self.packets(3.0, lambda out: got(out).endswith(data))).endswith(data)
    def reason(self, sid, t=3.0):
        """the CLOSE reason of stream sid, or None if none came in t seconds"""
        for ty, s, body in self.packets(t, lambda out: any(ty == 4 and s == sid for ty, s, _ in out)):
            if ty == 4 and s == sid: return body[0]
        return None
    def close(self):
        self.s.close()

REFUSALS = ("refuse_tcpmem_share", "refuse_port_share", "refuse_port_full", "refuse_dest_dead")

# --- off
p = start()
ok("guard" not in threads(p), "off: no guard thread")
ok(all(metric(p, k) == 0 for k in REFUSALS + ("tcpmem_unread", "port_dest_max", "dest_dead")), "off: the counters of section E are in the metrics line, at 0")
stop(p)
cfg = subprocess.run([BIN, "--show-config"], capture_output=True, text=True, timeout=10).stdout
ok("TCP memory guard" not in cfg and "dead destination guard" not in cfg, "off: --show-config has no row of section E")
cfg = subprocess.run([BIN, "--show-config", *ON], capture_output=True, text=True, timeout=10).stdout
ok(all(r in cfg for r in ("TCP memory guard", "source port guard", "dead destination guard", "network watch")), "on: --show-config has the four rows")

# --- on: honest streams
p = start(*ON)
ok("guard" in threads(p), "on: the guard thread runs")
a, b = Wisp(A), Wisp(B)
for sid in range(1, 201):
    a.connect(sid)
ok(all(a.echo(sid) for sid in (1, 100, 200)) and not any(ty == 4 for ty, _, _ in a.packets(0.3)), "on: 200 streams of one address open and echo, no CLOSE")
b.connect(1)
ok(b.echo(1), "on: the other client's stream")
ok(all(metric(p, k) == 0 for k in REFUSALS), "on: nothing refused")
for sid in range(1, 201):
    a.send(4, sid, b"\x02")

# --- E3: a destination that does not answer
dead = Dead()
t0 = time.time()
for sid in range(300, 310):
    a.connect(sid, dead.port)
ok(until(p, "dest_dead", 1, 12), f"E3: 10 connects without an answer: the destination is a suspect ({time.time() - t0:.1f} s after the connects)")
ok(time.time() - t0 >= 2.9, "E3: not before the 4th SYN (3 s)")
ok(f"127.0.0.1:{dead.port} does not answer" in srvlog(p), "E3: one warning names the destination")
time.sleep(1.1)  # (a probe second is over: the first of the next streams is the probe)
t1 = time.time()
for sid in (320, 321, 322):
    a.connect(sid, dead.port)
b.connect(5, dead.port)  # (within the same second: the probe of this second is taken)
other = b.reason(5, 1.5)
got = [a.reason(sid, 0.5) for sid in (321, 322, 320)]
# (which of the three is the probe depends on how the server read them: one is, the two others are refused)
ok(sorted(got, key=str) == [0x43, 0x43, None] and time.time() - t1 < 3, f"E3: of 3 new streams one is the probe, two get CLOSE 0x43 at once ({got})")
ok(other == 0x43, "E3: the other address is refused too")
a.connect(330)
ok(a.echo(330), "E3: a stream to another destination opens")
ok(metric(p, "refuse_dest_dead") == 3 and metric(p, "connect_timeout") == 0, "E3: refuse_dest_dead 3, no connect timeout")
ok("refused with 0x43 at once" in srvlog(p), "E3: the refusal's warning")
dead.revive()
ok(until(p, "dest_dead", 0, 15), "E3: the destination answers again: no suspect")
a.connect(340, dead.port)
ok(a.echo(340), "E3: a new stream to it opens")
ok(metric(p, "refuse_dest_dead") == 3, "E3: nothing more refused")
a.close(); b.close()
stop(p)

# --- E3: a destination that was dead and then refuses
p = start(*ON)
a, b = Wisp(A), Wisp(B)
dead = Dead()
for sid in range(1, 11):
    a.connect(sid, dead.port)
ok(until(p, "dest_dead", 1, 12), "E3 refusing: a suspect first")
dead.refuse()
ok(until(p, "dest_dead", 0, 15), "E3 refusing: the connects in flight are refused, none is left: no suspect")
n = metric(p, "refuse_dest_dead")
a.connect(20, dead.port)
ok(a.reason(20, 3) == 0x44, "E3 refusing: a new stream gets the kernel's answer, CLOSE 0x44")
ok(metric(p, "refuse_dest_dead") == n, "E3 refusing: not counted as refused")
a.close(); b.close()
stop(p)

print(f"{'FAILED' if fails else 'ok'}: {fails} failure(s); logs in {D}", flush=True)
sys.exit(1 if fails else 0)
