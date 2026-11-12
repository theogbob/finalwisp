#!/usr/bin/env python3
"""60.57 the fd count and the fd limit against a real finalwisp. Stdlib only. usage: fds.py FINALWISP_BINARY BASEPORT
(BASEPORT..+3; +3 = the test's own target). The server runs with a small RLIMIT_NOFILE (set before exec).
Cases:
- A1 the soft limit is raised to the hard one at startup (and not with --no-nofile-raise); the startup line.
- A2 the server's count (metrics `fds`) equals its real fds (/proc/PID/fd minus the idle process) at rest, with
  connections, with streams, after failed connects, after a spliced download, and after everything closed.
- A3 / T8 at the limit a new client gets a reset at once (no hang), refuse_fd_conns moves, one warning line names the
  fix without --log-conns; the open connections go on.
- A4 at the limit a new stream gets CLOSE 0x49, refuse_fd moves, the open streams go on; A6 connect_fail.
- the reserve: the process never reaches its open-file limit (accept_err_fd stays 0).
A timeout is a failure everywhere: the point of A3 is that nobody waits."""
import base64, os, resource, socket, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
TGT, DEAD = BASE + 3, BASE + 2  # DEAD: nothing listens (refused connects)
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

BULK = 8 << 20
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", TGT)); ls.listen(256)
def serve(c):
    """first byte 'B': send BULK bytes and close; else echo"""
    with c:
        try:
            d = c.recv(65536)
            if d[:1] == b"B":
                c.sendall(b"\xa5" * BULK); return
            while d:
                c.sendall(d); d = c.recv(65536)
        except OSError: pass
def acceptor():
    while True:
        c, _ = ls.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
threading.Thread(target=acceptor, daemon=True).start()

D = tempfile.mkdtemp(prefix="fw-fds-")
def start(port, soft, hard, *args, threads=2):
    log = open(os.path.join(D, f"srv{port}.log"), "w+")
    # (60.60: the `fds:` detail line is a debug line; the start block's `open files` row is at the default level)
    p = subprocess.Popen([BIN, str(port), "--allow-loopback", "--metrics-interval", "1", "--threads", str(threads), "--log-level", "debug",
                          *args], stdout=log,
                         stderr=subprocess.STDOUT, preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard)))
    p.logf = log
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close(); break
        except OSError:
            if p.poll() is not None: break
            time.sleep(0.05)
    time.sleep(0.3)  # the probe connection above is closed again
    return p
def srvlog(p):
    with open(p.logf.name) as f:
        return f.read()
def stop(p):
    p.terminate()
    try: p.wait(10)
    except subprocess.TimeoutExpired: p.kill(); p.wait()
def nfd(p):
    return len(os.listdir(f"/proc/{p.pid}/fd"))
def pipes(p):
    n = 0
    for f in os.listdir(f"/proc/{p.pid}/fd"):
        try: n += os.readlink(f"/proc/{p.pid}/fd/{f}").startswith("pipe:")
        except OSError: pass
    return n
def metric(p, key, fresh=True):
    """the value in the newest metrics line; fresh: wait for a line written after the call"""
    n0 = srvlog(p).count("ev=metrics")
    end = time.time() + 3
    while fresh and srvlog(p).count("ev=metrics") <= n0 + 0 and time.time() < end:
        time.sleep(0.1)
    vals = [l for l in srvlog(p).splitlines() if "ev=metrics" in l]
    if not vals: return None
    for kv in vals[-1].split():
        if kv.startswith(key + "="): return int(kv.split("=", 1)[1])
    return None
def startup(p, key):
    """a number of the startup line `fds: ... fixed X, reserve Y, usable Z`"""
    for l in srvlog(p).splitlines():
        if " fds: " in l or l.startswith("fds: "):
            w = l.replace(",", " ").replace(";", " ").split()
            if key in w: return int(w[w.index(key) + 1])
    return None

def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

class Wisp:
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
    def send(self, ty, sid, body):
        self.s.sendall(frame(bytes([ty]) + struct.pack("<I", sid) + body))
    def connect(self, sid, port=TGT):
        self.send(1, sid, b"\x01" + struct.pack("<H", port) + b"127.0.0.1")
    def packets(self, t=1.0, until=None):
        """Wisp packets (type, sid, body) that arrive within t seconds (or until `until(out)` holds)"""
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
            if until and until(out): break
            try:
                d = self.s.recv(1 << 20)
                if not d: break
                self.buf += d
            except socket.timeout:
                pass
        return out
    def echo(self, sid, data=b"ping"):
        self.send(2, sid, data)
        got = lambda out: b"".join(b for ty, s, b in out if ty == 2 and s == sid)
        return got(self.packets(2.0, lambda out: got(out) == data)) == data
    def closed(self, sid, t=3.0):
        """the CLOSE reason of stream sid, or None if none came in t seconds (a hang)"""
        for ty, s, body in self.packets(t, lambda out: any(ty == 4 and s == sid for ty, s, _ in out)):
            if ty == 4 and s == sid: return body[0]
        return None
    def close(self):
        self.s.close()

def attempt(port):
    """'ok' (a Wisp), 'reset', or 'hang' for one new client"""
    try:
        return Wisp(port)
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        return "reset"
    except socket.timeout:
        return "hang"

# --- A1 the raise
p = start(BASE, 200, 300)
ok("nofile soft 200 -> 300, hard 300" in srvlog(p), "A1: soft limit 200 raised to the hard limit 300 (startup line)")
lim = resource.prlimit(p.pid, resource.RLIMIT_NOFILE)
ok(lim == (300, 300), f"A1: the process runs with {lim}")
row = [l.split(None, 2)[2] for l in srvlog(p).splitlines() if l.strip().startswith("open files")]
ok(row == ["up to 300 (raised from 200)"], f"A1: the start block's row: open files {row}")
stop(p)
p = start(BASE, 200, 300, "--no-nofile-raise")
lim = resource.prlimit(p.pid, resource.RLIMIT_NOFILE)
ok(lim == (200, 300) and "nofile soft 200, hard 300" in srvlog(p), f"A1: --no-nofile-raise keeps {lim}")
row = [l.split(None, 2)[2] for l in srvlog(p).splitlines() if l.strip().startswith("open files")]
warned = [l for l in srvlog(p).splitlines() if "warning: open-file limit 200:" in l]
ok(row == ["up to 200"] and len(warned) == 1 and "Fix: LimitNOFILE=65536" in warned[0],
   f"A1: --no-nofile-raise, hard limit 300: open files {row}, the fix is a higher limit (the option's raise would stop at 300)")
stop(p)
own_hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
if own_hard == resource.RLIM_INFINITY or own_hard >= 65536:
    p = start(BASE, 200, 65536, "--no-nofile-raise")
    warned = [l for l in srvlog(p).splitlines() if "warning: open-file limit 200:" in l]
    ok(len(warned) == 1 and "Fix: start without --no-nofile-raise (the hard limit is 65536)" in warned[0],
       "A1: --no-nofile-raise, hard limit 65536: the warning names the option as the fix")
    stop(p)
else:
    print(f"SKIP A1: --no-nofile-raise with a hard limit of 65536 (the hard limit here is {own_hard}; covered by the unit tests)")
try:  # T5 a hard limit above fs.nr_open (root only: an unprivileged process cannot raise its hard limit)
    nr_open = int(open("/proc/sys/fs/nr_open").read())
    cur = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (cur[0], resource.RLIM_INFINITY))
    resource.setrlimit(resource.RLIMIT_NOFILE, cur)
    big = True
except (ValueError, OSError):
    big = False
if big:
    for hard, name in ((resource.RLIM_INFINITY, "infinity"), (1073741816, "1073741816")):
        if hard != resource.RLIM_INFINITY and hard <= nr_open:
            print(f"SKIP A1: hard {name} is not above fs.nr_open {nr_open} here"); continue
        p = start(BASE, 1024, hard)
        lim = resource.prlimit(p.pid, resource.RLIMIT_NOFILE)
        ok(lim[0] == min(nr_open, 1048576) and p.poll() is None, f"A1: hard {name}: soft {lim[0]} (fs.nr_open {nr_open}), hard now {lim[1]}")
        stop(p)
else:
    print("SKIP A1: hard limit infinity / 1073741816 (needs root; covered by the unit tests and on the test boxes)")

# --- A2 the count follows the real fds
p = start(BASE, 256, 256)
F, fixed, reserve = startup(p, "usable"), startup(p, "fixed"), startup(p, "reserve")
ok(F is not None and F + fixed + reserve == 256, f"startup line: fixed {fixed} + reserve {reserve} + usable {F} = 256")
base = nfd(p)
ok(metric(p, "fds") == 0 and metric(p, "fd_limit", False) == F, f"at rest: fds=0, fd_limit={F}, {base} real fds")
def same(what):
    time.sleep(0.2)
    m, real = metric(p, "fds"), nfd(p) - base
    ok(m == real, f"A2 {what}: fds={m}, real {real}")
ws = [Wisp(BASE) for _ in range(20)]
same("20 connections")
for i, w in enumerate(ws):
    for sid in (1, 2, 3): w.connect(sid)
ok(all(w.echo(1) and w.echo(3) for w in ws), "60 streams echo")
same("20 connections x 3 streams")
for w in ws[:10]:
    for sid in range(10, 14): w.connect(sid, DEAD)
got = [w.closed(13) for w in ws[:10]]
ok(all(g == 0x44 for g in got), f"refused connects close with 0x44 ({got[:3]})")
same("after 40 refused connects")
ok(metric(p, "connect_fail", False) == 40, f"A6 connect_fail={metric(p, 'connect_fail', False)} (40)")
w = ws[0]
w.connect(20); w.send(2, 20, b"B")
n = 0
def full(out):
    return sum(len(b) for ty, s, b in out if ty == 2 and s == 20) >= BULK or any(ty == 4 and s == 20 for ty, s, _ in out)
n = sum(len(b) for ty, s, b in w.packets(30, full) if ty == 2 and s == 20)
ok(n == BULK, f"spliced download: {n} bytes")
np_ = pipes(p)
ok(np_ == 2, f"the client's splice pipe is open ({np_} pipe fds)")
same("with a splice pipe")
for sid in (1, 2, 3): ws[1].send(4, sid, b"\x02")
same("after 3 streams closed by the client")
for w in ws: w.close()
time.sleep(0.5)
same("after every connection closed")
ok(nfd(p) == base, f"real fds back to {base}")

stop(p)

# --- A3 / T8 at the limit: new clients are reset at once (one worker: the numbers are exact; with more, a worker keeps
# up to one unused block of its allowance, so the last few fds can be on the wrong worker)
p = start(BASE + 1, 256, 256, threads=1)
F, base = startup(p, "usable"), nfd(p)
ws, res, t0 = [], {"reset": 0, "hang": 0}, time.time()
for _ in range(F + 30):
    r = attempt(BASE + 1)
    if isinstance(r, Wisp): ws.append(r)
    else: res[r] += 1
dt = time.time() - t0
ok(res["hang"] == 0, f"A3: no client hangs ({len(ws)} upgraded, {res['reset']} reset, {dt:.1f} s for {F + 30} clients)")
ok(len(ws) == F and res["reset"] == 30, f"A3: exactly the usable {F} fds are given out; the other 30 clients are reset")
ok(nfd(p) - base == F, f"real fds = base + {F}; {256 - nfd(p)} below the open-file limit")
m = {k: metric(p, k, k == "fds") for k in ("fds", "refuse_fd_conns", "accept_err_fd", "fd_granted")}
ok(m["fds"] == F and m["refuse_fd_conns"] == 30 and m["accept_err_fd"] == 0, f"A3: metrics {m}")
warn = [l for l in srvlog(p).splitlines() if "out of file descriptors" in l]
ok(1 <= len(warn) <= 2 and "Fix:" in warn[0] and "nofile" in warn[0], f"A3: {len(warn)} warning line(s) with the fix, without --log-conns")
# --- A4 a new stream at the limit
w = ws[0]
w.connect(1)
r = w.closed(1)
ok(r == 0x49, f"A4: a stream at the limit closes with {r if r is None else hex(r)} (0x49)")
ws.pop().close(); ws.pop().close(); time.sleep(0.3)
w.connect(2); ok(w.echo(2), "A4: after two connections closed a stream opens and echoes")
w.connect(3); w.connect(4)
cl = {s: b[0] for ty, s, b in w.packets(2, lambda out: any(ty == 4 and s == 4 for ty, s, _ in out)) if ty == 4}
r3, r4 = cl.get(3), cl.get(4)
ok(r3 is None and r4 == 0x49 and w.echo(2) and w.echo(3), f"A4: the 2nd fd goes to stream 3, stream 4 is refused ({r4}); streams 2 and 3 go on")
ok(metric(p, "refuse_fd") == 2, f"A4: refuse_fd={metric(p, 'refuse_fd', False)} (2)")
warn = [l for l in srvlog(p).splitlines() if "new streams are refused" in l]
ok(len(warn) == 1 and "Fix:" in warn[0], f"A4: {len(warn)} warning line for the refused streams, without --log-streams")
for w in ws: w.close()
time.sleep(0.5)
ok(nfd(p) == base and metric(p, "fds") == 0, f"all closed: real fds {nfd(p)} = {base}, fds=0")
ok(p.poll() is None, "the server is alive")
stop(p)

# --- 60.57 C: --fd-admission and --conn-share (off by default). Clients get their address from X-Forwarded-For
# behind --trusted-proxy 127.0.0.1 (a loopback address itself is never gated).
def xff_client(port, ip):
    """a Wisp client with a forwarded address: the Wisp, or the HTTP status line of the refusal"""
    s = socket.create_connection(("127.0.0.1", port), timeout=3); s.settimeout(3)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: " + ip.encode() + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: " + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d: return "closed"
            buf += d
    except socket.timeout:
        return "hang"
    except OSError:
        return "reset"
    head = buf.split(b"\r\n")[0].decode()
    if " 101 " not in head:
        s.close(); return head
    w = Wisp.__new__(Wisp); w.s, w.buf = s, buf.split(b"\r\n\r\n", 1)[1]
    return w

resource.setrlimit(resource.RLIMIT_NOFILE, (min(8192, resource.getrlimit(resource.RLIMIT_NOFILE)[1]),) + resource.getrlimit(resource.RLIMIT_NOFILE)[1:])
us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); us.bind(("127.0.0.1", 0)); UDP = us.getsockname()[1]
def udp_streams(w, first, n):
    for sid in range(first, first + n):
        w.send(1, sid, b"\x02" + struct.pack("<H", UDP) + b"127.0.0.1")  # a UDP stream: one fd, no peer needed
NOFILE = 1200
p = start(BASE + 1, NOFILE, NOFILE, "--conn-share", "--fd-admission", "--trusted-proxy", "127.0.0.1", threads=1)
F = startup(p, "usable")
line = [l for l in srvlog(p).splitlines() if " fds: " in l][0]
ok("--conn-share: from" in line and "--fd-admission: from" in line, "C: the startup line prints both marks")
half, floor, m34, m78 = F // 2, max(F // 64, 256), -(-F * 12 // 16), -(-F * 14 // 16)  # (the marks round up)
idle_fds = nfd(p)
ok(F > 2 * floor + 100, f"C: usable {F}: a key above {half}, others from {floor}, share mark {m34}, host mark {m78}")
BIG, SMALL = "203.0.113.1", "198.51.100.7"
big = xff_client(BASE + 1, BIG)
udp_streams(big, 1, half + 40)
ok(metric(p, "fds") == half + 41, f"C: the big address holds {half + 41} fds (fds={metric(p, 'fds', False)})")
# (i) a probe from a second address while the share mark is not even set, then with it set
small = xff_client(BASE + 1, SMALL)
udp_streams(small, 1, 3)
b2 = xff_client(BASE + 1, BIG)
ok(isinstance(b2, Wisp), "C: below the share mark the big address connects")
need = m34 - (half + 41 + 4 + 1) + 8
udp_streams(big, 5000, need)  # the big address alone takes the count over the share mark
time.sleep(2.5)  # (an idle sweep publishes exact per-address numbers)
ok(metric(p, "fds") >= m34, f"C: {metric(p, 'fds', False)} fds in use: the share mark ({m34}) is set")
b3 = xff_client(BASE + 1, BIG)
ok(isinstance(b3, Wisp), "C (i): one probe connection with 3 streams from a second address does not arm the rule")
for w in (b2, b3):
    if isinstance(w, Wisp): w.close()
# (ii) the second address grows to the floor: the big address gets no new connection, everyone else does
for sid in range(5000, 5000 + need): big.send(4, sid, b"\x02")
time.sleep(0.5)
udp_streams(small, 10, floor)
time.sleep(2.5)
used = metric(p, "fds")
ok(used >= m34 and used < m78, f"C: {used} fds: between the share mark and the host mark")
r = xff_client(BASE + 1, BIG)
ok(isinstance(r, str) and " 429 " in r, f"C (ii): the big address is refused with 429 ({r if isinstance(r, str) else 'connected'})")
s2 = xff_client(BASE + 1, SMALL)
n1 = xff_client(BASE + 1, "192.0.2.99")
ok(isinstance(s2, Wisp) and isinstance(n1, Wisp), "C (ii): the small address and a new address still connect")
udp_streams(big, 9000, 2); time.sleep(0.3)
ok(metric(p, "fds") == used + 2 + 2, "C: the big address's open connection still opens streams")
ok(metric(p, "refuse_share_conns", False) == 1, f"C: refuse_share_conns={metric(p, 'refuse_share_conns', False)} (1)")
warn = [l for l in srvlog(p).splitlines() if "--conn-share: one address holds" in l]
ok(len(warn) == 1 and "Fix:" in warn[0] and BIG not in warn[0], f"C: {len(warn)} warning line with the fix and without the address")
arm = [l for l in srvlog(p).splitlines() if "--conn-share is armed" in l]
ok(len(arm) >= 1, f"C: the mark crossing is logged ({len(arm)} line)")
# the host mark: more fds from the small addresses up to 7/8: every new connection is reset at accept
udp_streams(n1, 1, m78 - metric(p, "fds") + 4); time.sleep(0.5)
ok(metric(p, "fds") >= m78, f"C: {metric(p, 'fds', False)} fds: the host mark ({m78}) is set")
res = [attempt(BASE + 1) for _ in range(5)]
ok(res == ["reset"] * 5, f"C: --fd-admission resets new connections at the host mark ({res})")
ok(metric(p, "refuse_mark_conns") == 5, f"C: refuse_mark_conns={metric(p, 'refuse_mark_conns', False)} (5)")
ok(small.echo(1, b"x") is not None and big.closed(9001, 0.3) is None, "C: open connections go on")
warn = [l for l in srvlog(p).splitlines() if "--fd-admission: new connections are reset" in l]
ok(len(warn) == 1 and "Fix:" in warn[0], f"C: {len(warn)} warning line for the host mark")
for w in (big, small, s2, n1): w.close()
time.sleep(0.6)
ok(metric(p, "fds") == 0 and nfd(p) == idle_fds, f"C: all closed: fds={metric(p, 'fds', False)}, real fds {nfd(p)} = {idle_fds} at the start")
w = attempt(BASE + 1)
ok(isinstance(w, Wisp), "C: below the marks again connections are taken")
if isinstance(w, Wisp): w.close()
stop(p)
# off (the default): the same shape, nothing refused before the limit itself
p = start(BASE + 1, NOFILE, NOFILE, "--trusted-proxy", "127.0.0.1", "--max-conns-per-ip", "100000", threads=1)
ok("--conn-share" not in srvlog(p) and "--fd-admission" not in srvlog(p), "off: the startup line has no marks")
big = xff_client(BASE + 1, BIG); udp_streams(big, 1, half + 40)
small = xff_client(BASE + 1, SMALL); udp_streams(small, 1, m78 - (half + 41) + 10)
time.sleep(2.5)
ok(metric(p, "fds") >= m78, f"off: {metric(p, 'fds', False)} fds in use (over 7/8)")
r1, r2 = xff_client(BASE + 1, BIG), attempt(BASE + 1)
ok(isinstance(r1, Wisp) and isinstance(r2, Wisp), "off: the big address and a plain client still connect")
ok(metric(p, "refuse_share_conns") == 0 and metric(p, "refuse_mark_conns", False) == 0, "off: no share or mark refusal")
stop(p)

print("ALL PASS" if fails == 0 else f"{fails} FAILED")
sys.exit(1 if fails else 0)
