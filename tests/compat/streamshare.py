#!/usr/bin/env python3
"""60.72 --stream-share against a real finalwisp. Stdlib only. usage: streamshare.py FINALWISP_BINARY BASEPORT
(BASEPORT, +1 = the test's echo target). The server runs with RLIMIT_NOFILE 400 (set before exec) and 1 thread.
Cases, each on a fresh server, with 20 light connections (no stream) and one heavy connection that asks for as many
streams as there are usable fds (metrics fd_limit = F):
- on (--stream-share): from 7/8 of F the heavy connection gets CLOSE 0x49 (refuse_stream_share), well before F;
  then every light connection opens a stream that echoes (nothing refused for them, refuse_fd 0); the heavy
  connection's open streams echo; nobody is disconnected; one warning line and the mark's line. --show-config names
  the mark.
- off (bare): the heavy connection takes the fds up to F (refuse_fd), and the light connections' new streams get
  CLOSE 0x49 (the case the option is for); refuse_stream_share stays 0 and no line of the option.
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
LIGHT = 20
target(TGT)
D = tempfile.mkdtemp(prefix="fw-streamshare-")

def start(*args):
    log = open(os.path.join(D, f"srv{time.monotonic_ns()}.log"), "w+")
    p = subprocess.Popen([BIN, str(BASE), "--allow-loopback", "--metrics-interval", "1", "--threads", "1", *args], stdout=log,
                         stderr=subprocess.STDOUT, preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (400, 400)))
    p.logf = log
    for _ in range(200):
        if "listening on" in srvlog(p) or p.poll() is not None: break
        time.sleep(0.05)
    time.sleep(0.2)
    return p

KEYS = ("streams", "refuse_stream_share", "refuse_fd")
def run(on):
    tag = "on" if on else "off"
    p = start(*(["--stream-share"] if on else []))
    f = metric(p, "fd_limit")
    ok(f is not None and 200 < f < 400, f"{tag}: usable fds F = {f}")
    light = [Wisp(BASE) for _ in range(LIGHT)]
    heavy = Wisp(BASE)
    for sid in range(1, f + 1):
        heavy.connect(sid, TGT)
    m = settle(p, KEYS, f)
    ok(m is not None, f"{tag}: every CONNECT of the heavy connection is open or refused ({m})")
    m = m or {}
    mark = (f * 14 + 15) // 16
    if on:
        ok(m.get("refuse_stream_share", 0) > 0 and m.get("refuse_fd") == 0,
           f"{tag}: the heavy connection is refused by the rule, not by the fd limit ({m})")
        ok(mark - LIGHT - 70 <= m.get("streams", 0) <= mark - LIGHT, f"{tag}: it stops at the mark (7/8 of F = {mark} fds, {LIGHT + 1} of them connections): {m.get('streams')} streams")
        why = heavy.closed(1.0)
        ok(len(why) == m.get("refuse_stream_share") and set(why.values()) == {0x49}, f"{tag}: each refusal is CLOSE 0x49 ({len(why)})")
    else:
        ok(m.get("refuse_fd", 0) > 0 and m.get("refuse_stream_share") == 0, f"{tag}: the heavy connection runs into the fd limit ({m})")
    # the light connections each ask for one stream
    for c in light:
        c.connect(1, TGT)
    lm = settle(p, KEYS, f + LIGHT)
    ok(lm is not None, f"{tag}: every light CONNECT is open or refused ({lm})")
    got = [c.closed(0.3).get(1) for c in light]
    if on:
        ok(got.count(None) == LIGHT and all(c.echo(1) for c in light), f"{tag}: every light connection's stream opens and echoes ({got.count(None)} of {LIGHT})")
        ok((lm or {}).get("refuse_fd") == 0, f"{tag}: refuse_fd 0 ({lm})")
        open_sids = [s for s in (1, 2, 50, 100) if s not in heavy.closed(0.1)]
        ok(open_sids and all(heavy.echo(s) for s in open_sids), f"{tag}: the heavy connection's open streams go on")
        log = srvlog(p)
        ok("--stream-share is armed" in log and log.count("finalwisp: --stream-share: a connection with") == 1,
           f"{tag}: the mark's line and one refusal line (10 s)")
    else:
        ok(got.count(0x49) >= LIGHT // 2, f"{tag}: the light connections' streams get CLOSE 0x49 ({got.count(0x49)} of {LIGHT})")
        ok("--stream-share" not in srvlog(p), f"{tag}: no line of the option")
    ok(heavy.alive() and all(c.alive() for c in light), f"{tag}: nobody is disconnected")
    stop(p, BASE)

run(True)
run(False)
cfg = subprocess.run([BIN, "--show-config", "--stream-share"], capture_output=True, text=True, timeout=10,
                     preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (400, 400))).stdout
ok("--stream-share: from" in cfg, "--show-config names the mark of --stream-share")
cfg = subprocess.run([BIN, "--show-config"], capture_output=True, text=True, timeout=10).stdout
ok("stream-share" in cfg and "--stream-share: from" not in cfg, "--show-config off: the setting, no mark")
print("streamshare:", "OK" if fails == 0 else f"{fails} FAIL", flush=True)
sys.exit(1 if fails else 0)
