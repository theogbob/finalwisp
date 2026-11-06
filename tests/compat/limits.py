#!/usr/bin/env python3
"""60.20 C3a policy limits against a real finalwisp. Stdlib only. usage: limits.py FINALWISP_BINARY BASEPORT (BASEPORT..+3)
Cases: --max-conns 3 on --threads 4 (with and without --balance): 3 upgraded connections stay up, a 4th is reset at
accept; closing one makes room; 50 rounds of open/close leave no reservation behind (the 4th is still refused when 3
are open). --max-streams-per-conn 2: the 3rd CONNECT gets CLOSE 0x49, the connection and both streams keep working,
and a stream end (client CLOSE, target close) frees the slot. The metrics line shows refuse_conns / refuse_limit /
conns_reserved."""
import base64, os, socket, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
ECHO = BASE + 3
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", ECHO)); ls.listen(64)
def pump(c):
    with c:
        try:
            while (d := c.recv(65536)): c.sendall(d)
        except OSError: pass
def acceptor():
    while True:
        c, _ = ls.accept(); threading.Thread(target=pump, args=(c,), daemon=True).start()
threading.Thread(target=acceptor, daemon=True).start()

D = tempfile.mkdtemp(prefix="fw-limits-")
def start(port, *args):
    log = open(os.path.join(D, f"srv{port}.log"), "w+")
    p = subprocess.Popen([BIN, str(port), "--allow-loopback", "--metrics-interval", "1", *args], stdout=log, stderr=subprocess.STDOUT)
    p.logf = log
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close(); break
        except OSError:
            if p.poll() is not None: break
            time.sleep(0.05)
    time.sleep(0.2)  # the probe connection above is closed again
    return p
def srvlog(p):
    with open(p.logf.name) as f:  # own handle: the server writes through the inherited one (no shared offset)
        return f.read()
def stop(p):
    p.terminate()
    try: p.wait(10)
    except subprocess.TimeoutExpired: p.kill(); p.wait()

def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

class Wisp:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
                       + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d: raise ConnectionResetError("closed before 101")
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]: raise ConnectionResetError(head[:40])
    def send(self, ty, sid, body):
        self.s.sendall(frame(bytes([ty]) + struct.pack("<I", sid) + body))
    def connect(self, sid, port=ECHO):
        self.send(1, sid, b"\x01" + struct.pack("<H", port) + b"127.0.0.1")
    def packets(self, t=1.0):
        """Wisp packets (type, sid, body) that arrive within t seconds"""
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
    def echo(self, sid, data):
        self.send(2, sid, data)
        got = b""
        for ty, s, body in self.packets(1.0):
            if ty == 2 and s == sid: got += body
        return got == data
    def close(self):
        self.s.close()

def alive(w):
    """the server still serves this connection (a WS ping gets an answer, or at least no reset)"""
    try:
        w.s.sendall(bytes([0x89, 0x80, 0, 0, 0, 0]))
        w.s.settimeout(1); d = w.s.recv(64)
        return bool(d)
    except (socket.timeout,):
        return True
    except OSError:
        return False

def refused(port):
    """True when a new connection is reset / closed without a 101"""
    try:
        w = Wisp(port); w.close(); return False
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        return True  # a timeout (a server that accepted and hung) is not a refusal: it propagates and fails the test

def metric(p, key):
    vals = [l for l in srvlog(p).splitlines() if "ev=metrics" in l]
    if not vals: return None
    for kv in vals[-1].split():
        if kv.startswith(key + "="): return kv.split("=", 1)[1]
    return None

# --max-conns 3, with and without --balance
for i, extra in enumerate([[], ["--balance"]]):
    port = BASE + i
    p = start(port, "--threads", "4", "--max-conns", "3", *extra)
    tag = "balance" if extra else "plain"
    ok("limits: conns 3" in srvlog(p), f"{tag}: capability line shows the limit")
    ws = [Wisp(port) for _ in range(3)]
    ok(refused(port), f"{tag}: 4th connection reset at --max-conns 3")
    ok(all(alive(w) for w in ws), f"{tag}: the 3 admitted connections stay up")
    ws.pop().close(); time.sleep(0.1)
    try:
        ws.append(Wisp(port)); ok(True, f"{tag}: room again after one closed")
    except OSError as e:
        ok(False, f"{tag}: room again after one closed ({e})")
    leak = False
    for _ in range(50):
        ws.pop().close()
        for _ in range(20):  # the release follows the server's close of the old connection (retry up to ~400 ms)
            time.sleep(0.02)
            try: ws.append(Wisp(port)); break
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError): pass
        else:
            leak = True; break
    ok(not leak and refused(port), f"{tag}: 50 open/close rounds leave no reservation behind (still 3 + refused)")
    for w in ws: w.close()
    time.sleep(1.3)
    ok(metric(p, "conns_reserved") == "0" and metric(p, "conns_max") == "3" and int(metric(p, "refuse_conns") or 0) >= 2,
       f"{tag}: metrics conns_reserved=0 conns_max=3 refuse_conns>=2 ({metric(p, 'conns_reserved')}, {metric(p, 'refuse_conns')})")
    stop(p)

# --max-streams-per-conn 2
port = BASE + 2
p = start(port, "--threads", "2", "--max-streams-per-conn", "2")
w = Wisp(port)
w.packets(0.3)  # v1: nothing, v2: INFO
w.connect(1); w.connect(2); w.connect(3)
pk = w.packets(0.5)
ok(any(ty == 4 and s == 3 and body[:1] == b"\x49" for ty, s, body in pk), "3rd CONNECT on one connection gets CLOSE 0x49")
ok(not any(ty == 4 and s in (1, 2) for ty, s, body in pk), "streams 1 and 2 are not closed")
ok(w.echo(1, b"one") and w.echo(2, b"two"), "both admitted streams carry data")
w.send(4, 1, b"\x02"); time.sleep(0.1)  # client CLOSE frees a slot
w.connect(4)
pk = w.packets(0.4)
ok(not any(ty == 4 and s == 4 for ty, s, body in pk) and w.echo(4, b"four"), "after a client CLOSE a new stream fits")
w.connect(5)
pk = w.packets(0.4)
ok(any(ty == 4 and s == 5 and body[:1] == b"\x49" for ty, s, body in pk), "and the cap holds again (5th refused)")
dead = socket.socket(); dead.bind(("127.0.0.1", 0)); dport = dead.getsockname()[1]; dead.close()
w.send(4, 2, b"\x02"); time.sleep(0.1)
w.connect(6, dport)  # refused by the target host: the stream ends by itself
pk = w.packets(0.6)
ok(any(ty == 4 and s == 6 for ty, s, body in pk), "a refused connect closes its stream")
w.connect(7)
pk = w.packets(0.4)
ok(not any(ty == 4 and s == 7 for ty, s, body in pk) and w.echo(7, b"seven"), "the refused stream's slot was freed")
ok(alive(w), "the connection stays up through the refusals")
time.sleep(1.3)
ok(int(metric(p, "refuse_limit") or 0) == 2, f"metrics refuse_limit=2 ({metric(p, 'refuse_limit')})")
w.close(); stop(p)
print(f"limits: {fails} failures")
sys.exit(1 if fails else 0)
