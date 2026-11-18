#!/usr/bin/env python3
"""60.27 / 60.32 C6 --upstream against fake proxies. Stdlib only.
usage: upstream.py FINALWISP_BINARY BASEPORT
Fake proxies in this process (SOCKS5 RFC 1928/1929, HTTP CONNECT) record what they receive and answer per case.
Ports: BASEPORT server, +1 echo, +2 banner target (sends 220 first), +3 bulk source, +4 bye target; the fake proxies
and the fake DNS server take ephemeral ports. The real-proxy matrix is upstream_real.py (60.32)."""
import base64, hashlib, os, shutil, signal, socket, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
P, E, BAN, BULK = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

def serve(port, handler, host="127.0.0.1"):
    """port 0: an ephemeral port (ls.getsockname())"""
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind((host, port)); ls.listen(128)
    def acc():
        while True:
            c, _ = ls.accept(); threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=acc, daemon=True).start()
    return ls
def pump(c):
    with c:
        try:
            while (d := c.recv(65536)): c.sendall(d)
        except OSError: pass
def banner(c):
    c.sendall(b"220 hello\r\n"); pump(c)
BULK_DATA = os.urandom(1 << 20) * 32  # 32 MiB
def bulk(c):
    with c:
        try: c.sendall(BULK_DATA)
        except OSError: pass
BYE = BASE + 4
def bye(c):
    c.sendall(b"221 bye\r\n"); c.close()
serve(E, pump); serve(BAN, banner); serve(BULK, bulk); serve(BYE, bye)

def relay(a, b):
    def one(x, y):
        try:
            while (d := x.recv(65536)): y.sendall(d)
        except OSError: pass
        try: y.shutdown(socket.SHUT_WR)
        except OSError: pass
    threading.Thread(target=one, args=(a, b), daemon=True).start(); one(b, a)

def rx(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d: raise EOFError
        b += d
    return b

class Socks:
    """mode keys: auth=(u,p) required; noauth_pick: answer 00 even if 02 offered; rep: f(dest)->code; delay; stall;
    close_after_greeting; combine: read the target's first bytes and send them with the reply in one segment"""
    def __init__(self, **mode):
        self.mode, self.log = mode, []
        self.port = serve(0, self.h).getsockname()[1]
    def h(self, c):
        m = self.mode
        try:
            v, n = rx(c, 2); meths = rx(c, n); self.log.append(("greet", meths))
            if m.get("stall"): time.sleep(30); return
            if m.get("close_after_greeting"): c.close(); return
            if m.get("auth") and not m.get("noauth_pick"):
                if 2 not in meths: c.sendall(b"\x05\xff"); return
                c.sendall(b"\x05\x02")
                _, ul = rx(c, 2); u = rx(c, ul); pl = rx(c, 1)[0]; p = rx(c, pl)
                self.log.append(("auth", u, p))
                if (u, p) != m["auth"]: c.sendall(b"\x01\x01"); return
                c.sendall(b"\x01\x00")
            else:
                c.sendall(b"\x05\x00")
            ver, cmd, rsv, atyp = rx(c, 4)
            if atyp == 1: dest = socket.inet_ntop(socket.AF_INET, rx(c, 4))
            elif atyp == 4: dest = socket.inet_ntop(socket.AF_INET6, rx(c, 16))
            else: dest = rx(c, rx(c, 1)[0]).decode()
            port = struct.unpack(">H", rx(c, 2))[0]
            self.log.append(("connect", atyp, dest, port))
            time.sleep(m.get("delay", 0))
            rep = m.get("rep", lambda d: 0)(dest)
            if rep: c.sendall(bytes([5, rep, 0, 1, 0, 0, 0, 0, 0, 0])); return
            t = socket.create_connection(("127.0.0.1", port))
            reply = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00"
            if m.get("combine"):
                time.sleep(0.2); first = t.recv(65536); c.sendall(reply + first)
            else:
                c.sendall(reply)
            relay(c, t)
        except (OSError, EOFError): pass
        finally:
            try: c.close()
            except OSError: pass

class Http:
    """auth=(u,p); status=f(dest)->code; dribble: send the head byte by byte; combine; bighead"""
    def __init__(self, **mode):
        self.mode, self.log = mode, []
        self.port = serve(0, self.h).getsockname()[1]
    def h(self, c):
        m = self.mode
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                d = c.recv(4096)
                if not d: return
                head += d
            self.log.append(head)
            line = head.split(b"\r\n")[0].decode(); dest = line.split()[1]
            hostpart, port = dest.rsplit(":", 1)
            code = m.get("status", lambda d: 200)(dest)
            if m.get("auth"):
                want = b"Proxy-Authorization: Basic " + base64.b64encode(b"%s:%s" % m["auth"])
                if want not in head: code = 407
            if code != 200:
                c.sendall(b"HTTP/1.1 %d X\r\nContent-Length: 0\r\n\r\n" % code); return
            t = socket.create_connection(("127.0.0.1", int(port)))
            resp = b"HTTP/1.1 200 Connection established\r\n" + (b"X-Pad: " + b"a" * 9000 + b"\r\n" if m.get("bighead") else b"") + b"\r\n"
            if m.get("dribble"):
                for i in range(len(resp)): c.sendall(resp[i:i + 1]); time.sleep(0.005)
            elif m.get("combine"):
                time.sleep(0.2); resp += t.recv(65536)
                c.sendall(resp)
            else:
                c.sendall(resp)
            relay(c, t)
        except (OSError, EOFError): pass
        finally:
            try: c.close()
            except OSError: pass

D = tempfile.mkdtemp(prefix="fw-upstream-")
def start(*args, wrap=()):
    log = open(os.path.join(D, f"srv{time.monotonic_ns()}.log"), "w+")
    p = subprocess.Popen([*wrap, BIN, str(P), "--host", "127.0.0.1", "--log-level", "debug", "--metrics-interval", "1", "--allow-loopback", *args],
                         stdout=log, stderr=subprocess.STDOUT, start_new_session=bool(wrap))
    p.logf = log
    p.group = bool(wrap)  # a wrapper (bwrap) does not pass SIGTERM on: the signals go to the whole group
    for _ in range(100):
        if "capabilities:" in srvlog(p) or p.poll() is not None: break
        time.sleep(0.05)
    return p
def srvlog(p):
    with open(p.logf.name) as f: return f.read()
TRIM = bool(os.environ.get("WST_TRIM"))  # wst compat --trim (80.01)
def stop(p):
    def term(s=signal.SIGTERM):
        if not getattr(p, "group", False): return p.terminate() if s == signal.SIGTERM else p.kill()
        try: os.killpg(p.pid, s)
        except ProcessLookupError: pass
    term()
    if TRIM:  # a second SIGTERM = exit now (60.12). Without it a server that still has this test's connections drains (30 s), and the wait below ends in SIGKILL after 10 s
        try: p.wait(0.5)
        except subprocess.TimeoutExpired: term()
    try: p.wait(10)
    except subprocess.TimeoutExpired: term(signal.SIGKILL); p.wait()
    if getattr(p, "group", False):  # the wrapper is gone; the server in its group may still drain: wait for the whole group
        t = time.time()
        while True:
            try: os.killpg(p.pid, 0)
            except ProcessLookupError: break
            if time.time() - t > 10: term(signal.SIGKILL)
            if time.time() - t > 20: ok(False, f"the server group {p.pid} is still there 20 s after SIGTERM (SIGKILL sent)"); break
            time.sleep(0.05)
def metric(p, key):
    time.sleep(1.3)
    vals = [l for l in srvlog(p).splitlines() if "ev=metrics " in l]
    for kv in (vals[-1].split() if vals else []):
        if kv.startswith(key + "="): return int(kv.split("=", 1)[1])
    return None

def frame(payload):
    n = len(payload); m = os.urandom(4)
    if n < 126: hdr = bytes([0x82, 0x80 | n])
    elif n < 65536: hdr = bytes([0x82, 0xFE]) + struct.pack(">H", n)
    else: hdr = bytes([0x82, 0xFF]) + struct.pack(">Q", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))
UPGRADE = (b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
           + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
class Wisp:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", P), timeout=3)
        self.s.sendall(UPGRADE); self.buf = b""
        while b"\r\n\r\n" not in self.buf: self.buf += self.s.recv(4096)
        head, self.buf = self.buf.split(b"\r\n\r\n", 1); assert b" 101 " in head.split(b"\r\n")[0]
        self.sid = 0
    def send(self, ty, sid, body): self.s.sendall(frame(bytes([ty]) + struct.pack("<I", sid) + body))
    def connect(self, host, port=E, udp=False, data=None):
        self.sid += 1
        self.send(1, self.sid, (b"\x02" if udp else b"\x01") + struct.pack("<H", port) + host.encode())
        if data: self.send(2, self.sid, data)
        return self.sid
    def packets(self, t, until=None):
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
            if until and until(out): return out
            try:
                d = self.s.recv(1 << 20)
                if not d: break
                self.buf += d
            except socket.timeout: pass
        return out
    def result(self, sid, t=4):
        """('close', reason) or ('data', bytes) for the first event of sid"""
        pk = self.packets(t, until=lambda o: any(s == sid and ty in (2, 4) for ty, s, _ in o))
        for ty, s, b in pk:
            if s == sid and ty == 4: return ("close", b[0])
            if s == sid and ty == 2:
                return ("data", b + b"".join(x for t2, s2, x in pk if s2 == sid and t2 == 2 and x is not b))
        return ("none", None)
    def data(self, sid, n, t=5):
        got = b""
        pk = self.packets(t, until=lambda o: sum(len(b) for ty, s, b in o if s == sid and ty == 2) >= n)
        for ty, s, b in pk:
            if s == sid and ty == 2: got += b
        return got

def case_close(w, host, want, port=E, msg=""):
    sid = w.connect(host, port)
    r = w.result(sid)
    ok(r == ("close", want), f"{msg or host}: CLOSE {want:#x} (got {r[0]} {r[1] if r[0]=='close' else ''})")

def echo_ok(w, host, msg, port=E, payload=b"ping-123"):
    sid = w.connect(host, port, data=payload)
    got = w.data(sid, len(payload))
    ok(got == payload, f"{msg}: echo through the proxy ({got[:20]!r})")
    return sid

# ---- WST_CASES="k/n" runs only shard k of n (k = 1..n). Unset: nothing changes. From here on the file is a list of
# sections. "#@seg NAME SECONDS" starts a case group (one unit; SECONDS = its measured time alone without WST_TRIM, used
# only to balance the shards; a later "#@seg NAME" continues the group), "#@seg NAME SECONDSxCOUNT" a group whose loop
# over each(NAME, [...]) is COUNT units of SECONDS each, "#@all" the lines that every shard runs (objects that several
# groups use, and the summary line; they print no PASS line). With WST_CASES this file is compiled again with the groups
# of the other shards blanked (the line numbers stay) and run here: each unit is in exactly one shard.
SHARD = None  # or the set of (NAME, item index or None) of this shard
def each(name, items):
    if SHARD is None: return items
    if [u[1] for u in UNITS if u[0] == name] != list(range(len(items))): between(); shard_error(f"each({name!r}): {len(items)} items, the #@seg line does not say x{len(items)}")
    return [x for i, x in enumerate(items) if (name, i) in SHARD]
def shard_error(msg):
    print("upstream.py: " + msg, file=sys.stderr); sys.exit(2)
def between():  # a group of another shard was here: stop the server that the group before it left running
    if p.poll() is None: stop(p)
class NoServer:  # "p" before the first group of a shard: stop(p) does nothing
    def terminate(self): pass
    def wait(self, timeout=None): return 0
    def poll(self): return 0
if "WST_CASES" in os.environ:
    import re
    LINES, UNITS, MARKS = open(__file__, encoding="utf-8").read().split("\n"), [], {}  # MARKS: line index -> NAME, None for "#@all"
    for i, l in enumerate(LINES):
        if not l.startswith("#@"): continue
        m = re.fullmatch(r"#@all|#@seg ([\w-]+)(?: (\d+(?:\.\d+)?)(?:x([1-9]\d*))?)?", l)
        if not m or (m[1] is not None and (m[2] is None) != any(u[0] == m[1] for u in UNITS)) or (m[2] and float(m[2]) <= 0):
            shard_error(f"line {i + 1}: bad section line {l!r}")
        MARKS[i] = m[1]
        if m[2]: UNITS += [(m[1], j if m[3] else None, float(m[2])) for j in range(int(m[3] or 1))]
    m = re.fullmatch(r"([1-9][0-9]*)/([1-9][0-9]*)", os.environ["WST_CASES"])
    if not m or not int(m[1]) <= int(m[2]) <= len(UNITS):
        shard_error(f"WST_CASES={os.environ['WST_CASES']!r}: want k/n with 1 <= k <= n <= {len(UNITS)}")
    # the longest unit first, each to the shard with the smallest sum so far (ties: file order, then the lowest shard)
    load, SHARD = [0.0] * int(m[2]), set()
    for name, item, sec in sorted(UNITS, key=lambda u: -u[2]):
        j = load.index(min(load)); load[j] += sec
        if j == int(m[1]) - 1: SHARD.add((name, item))
    keep = False  # the lines above ran already
    for i, l in enumerate(LINES):
        if i in MARKS:
            keep = MARKS[i] is None or any(u[0] == MARKS[i] for u in SHARD)
            if not keep: LINES[i] = "between()"
        elif not keep: LINES[i] = ""
    p = NoServer()
    exec(compile("\n".join(LINES), __file__, "exec"))
    shard_error("the last section did not end the script")
# ---- SOCKS5, no auth, local DNS
#@all
s1 = Socks()
#@seg socks5-basic 12.8
p = start("--upstream", f"socks5://127.0.0.1:{s1.port}")
ok("upstream socks5://127.0.0.1:%d" % s1.port in srvlog(p) and "UDP off" in srvlog(p), "capability line: upstream + UDP off")
ok(metric(p, "upstream_ok") == 0 and metric(p, "upstream_dns_age_s") is None, "an IP-literal proxy: no refresh fields in the line")
w = Wisp()
echo_ok(w, "127.0.0.1", "socks5 IP literal")
ok(s1.log[-1] == ("connect", 1, "127.0.0.1", E), f"socks5: proxy got ATYP 1 127.0.0.1 ({s1.log[-1]})")
ok(s1.log[0] == ("greet", b"\x00"), "socks5 no creds: greeting offers 00 only")
echo_ok(w, "localhost", "socks5 name (local DNS)")
ok(s1.log[-1][:3] == ("connect", 1, "127.0.0.1"), f"socks5 name: resolved locally, IPv4 first ({s1.log[-1]})")
n0 = len(s1.log)
case_close(w, "10.1.2.3", 0x48, msg="C1 private address before the proxy")
ok(len(s1.log) == n0, "C1 refusal: the proxy saw nothing")
sid = w.connect("127.0.0.1", E, udp=True)
ok(w.result(sid) == ("close", 0x48), "UDP with an upstream: 0x48")
#@seg socks5-combine 10.6
# banner in the same segment as the reply (no over-read)
s2 = Socks(combine=True)
stop(p); p = start("--upstream", f"socks5://127.0.0.1:{s2.port}")
w = Wisp(); sid = w.connect("127.0.0.1", BAN)
got = w.data(sid, 11)
ok(got == b"220 hello\r\n", f"socks5: banner sent with the reply arrives as first DATA ({got!r})")
# review P1: reply + tunnel bytes + FIN in one event: the EOF must not be lost
sid = w.connect("127.0.0.1", BYE)
pk = w.packets(4, until=lambda o: any(s == sid and ty == 4 for ty, s, _ in o))
gotd = b"".join(b for ty, s, b in pk if s == sid and ty == 2); cl = [b[0] for ty, s, b in pk if s == sid and ty == 4]
ok(gotd == b"221 bye\r\n" and cl != [], f"socks5: banner + FIN with the reply: DATA then CLOSE ({gotd!r}, close {cl})")
#@seg socks5-early-data 10.4
# DATA before the reply, proxy delays 300 ms
s3 = Socks(delay=0.3)
stop(p); p = start("--upstream", f"socks5://127.0.0.1:{s3.port}")
w = Wisp(); sid = w.connect("127.0.0.1", E, data=b"early-1")
w.send(2, sid, b"early-2")
got = w.data(sid, 14)
ok(got == b"early-1early-2", f"DATA sent during the handshake arrives in order after it ({got!r})")
#@all
# retry: REP 04 for 127.0.0.1, OK for ::1 (fake proxy routes both to the echo)
s4 = Socks(rep=lambda d: 4 if d == "127.0.0.1" else 0)
#@seg socks5-retry 0.5
has_v6 = any(a[0] == socket.AF_INET6 for a in socket.getaddrinfo("localhost", E))
BWRAP = shutil.which("bwrap")
wrap = ()
if not has_v6 and BWRAP:
    # 60.78 G20: a host whose /etc/hosts has no ::1 for localhost (the laptop) runs the same case with a server that sees a
    # private /etc/hosts (bwrap bind mount, no root; the host's file is not touched). The fake proxy answers both names.
    hosts = os.path.join(D, "hosts")
    with open(hosts, "w") as f: f.write("127.0.0.1 localhost\n::1 localhost\n")
    wrap = (BWRAP, "--die-with-parent", "--dev-bind", "/", "/", "--ro-bind", hosts, "/etc/hosts")
stop(p); p = start("--upstream", f"socks5://127.0.0.1:{s4.port}", wrap=wrap)
w = Wisp()
if has_v6 or BWRAP:
    echo_ok(w, "localhost", "REP 04 on 127.0.0.1, retry on ::1" + ("" if has_v6 else " (a private /etc/hosts with ::1 localhost)"))
    ok([x[2] for x in s4.log if x[0] == "connect"][-2:] == ["127.0.0.1", "::1"], f"retry order v4 then v6 ({s4.log[-2:]})")
else:
    print("SKIP retry (localhost has no ::1, and no bwrap for a private /etc/hosts)")
#@seg socks5-rep 1.6x8
# REP codes
for rep, want in each("socks5-rep", [(1, 0x03), (2, 0x48), (3, 0x42), (4, 0x42), (5, 0x44), (6, 0x43), (7, 0x03), (8, 0x03)]):
    s = Socks(rep=lambda d, r=rep: r)
    stop(p); p = start("--upstream", f"socks5://127.0.0.1:{s.port}")
    w = Wisp(); case_close(w, "127.0.0.1", want, msg=f"SOCKS REP {rep:#04x}")
    n = metric(p, "upstream_fail")
    ok(n == (0 if rep in (3, 4, 5, 6) else 1), f"REP {rep:#04x}: upstream_fail {n} (a refusal about the target is not the proxy's failure)")
#@all
# auth
sa = Socks(auth=(b"us er", b"p@ss"))
#@seg socks5-auth 10.2
stop(p); p = start("--upstream", f"socks5://us%20er:p%40ss@127.0.0.1:{sa.port}")
w = Wisp(); echo_ok(w, "127.0.0.1", "socks5 user/pass (percent-decoded)")
ok(("auth", b"us er", b"p@ss") in sa.log and sa.log[0] == ("greet", b"\x00\x02"), f"RFC 1929 bytes; greeting offers 00+02 ({sa.log[:2]})")
ok("p@ss" not in srvlog(p) and "p%40ss" not in srvlog(p) and "us%20er" not in srvlog(p) and "us er" not in srvlog(p) and "***@" in srvlog(p), "user and password not in the server log")
#@seg socks5-auth-wrong 1.5
stop(p); p = start("--upstream", f"socks5://us%20er:wrong@127.0.0.1:{sa.port}")
w = Wisp(); case_close(w, "127.0.0.1", 0x03, msg="socks5 wrong password")
ok(metric(p, "upstream_fail") >= 1, "upstream_fail counted")
#@seg socks5-auth-unused 10.2
sn = Socks(auth=(b"x", b"y"), noauth_pick=True)
stop(p); p = start("--upstream", f"socks5://x:y@127.0.0.1:{sn.port}")
w = Wisp(); echo_ok(w, "127.0.0.1", "creds set, proxy picks no-auth (wispurr parity)")
#@seg proxy-dead 0.2
# failures of the proxy itself
dead = socket.socket(); dead.bind(("127.0.0.1", 0)); dport = dead.getsockname()[1]
stop(p); p = start("--upstream", f"socks5://127.0.0.1:{dport}")
w = Wisp(); case_close(w, "127.0.0.1", 0x44, msg="proxy port closed (parity: 0x44)")
#@seg proxy-stall 3.9
ss = Socks(stall=True)
stop(p); p = start("--upstream", f"socks5://127.0.0.1:{ss.port}", "--connect-timeout", "2")
w = Wisp(); t0 = time.time(); sid = w.connect("127.0.0.1"); r = w.result(sid, 6); dt = time.time() - t0
ok(r == ("close", 0x43) and 1.5 < dt < 3.5, f"stalled proxy: 0x43 at the deadline ({r}, {dt:.1f}s)")
# close mid-handshake: no leak
for _ in range(20): w.connect("127.0.0.1")
time.sleep(0.3)
for sid in range(2, w.sid + 1): w.send(4, sid, b"\x02")
ok(metric(p, "streams") == 0, "client CLOSE during the handshake: streams gauge back to 0")
#@seg proxy-closes 0.2
sc = Socks(close_after_greeting=True)
stop(p); p = start("--upstream", f"socks5://127.0.0.1:{sc.port}")
w = Wisp(); case_close(w, "127.0.0.1", 0x03, msg="proxy closes after the greeting")
#@seg socks5h 10.6
# socks5h
stop(p); p = start("--upstream", f"socks5h://127.0.0.1:{s1.port}")
ok(p.poll() is not None and "--upstream-trust-dns" in srvlog(p), "socks5h without --upstream-trust-dns: refuses to start")
p = start("--upstream", f"socks5h://127.0.0.1:{s1.port}", "--upstream-trust-dns")
w = Wisp(); n0 = len(s1.log)
echo_ok(w, "localhost", "socks5h localhost with --allow-loopback")
ok(s1.log[-1][:3] == ("connect", 3, "localhost."), f"socks5h: the proxy got the absolute name, ATYP 3 ({s1.log[-1]})")
# 60.32 #9: RFC 7686 .onion names go without the added dot (Tor refuses `x.onion.`); any case; a client's dot is removed
for host, want in (("expyuzz4wqqyqhjn.onion", "expyuzz4wqqyqhjn.onion"), ("EXPYUZZ4WQQYQHJN.Onion.", "EXPYUZZ4WQQYQHJN.Onion"),
                   ("onion.example.com", "onion.example.com.")):
    echo_ok(w, host, f"socks5h {host}")
    ok(s1.log[-1][:3] == ("connect", 3, want), f"socks5h {host}: the proxy got {want!r} ({s1.log[-1]})")
for bad in ("127.1", "0x7f000001", "2130706433"):
    case_close(w, bad, 0x48, msg=f"socks5h inet_aton form {bad}")
ok(all(x[0] != "connect" or x[2] not in ("127.1", "0x7f000001", "2130706433") for x in s1.log), "inet_aton forms never reach the proxy")
echo_ok(w, "127.0.0.1", "socks5h IP literal (address rules apply)")
case_close(w, "10.0.0.1", 0x48, msg="socks5h private literal refused locally")
stop(p); p = start("--upstream", f"socks5h://127.0.0.1:{s1.port}", "--upstream-trust-dns", "--allow-private")
p2log = srvlog(p)
stop(p)
#@seg socks5h-no-loopback 0.7
# no --allow-loopback: localhost names refused under socks5h
pp = subprocess.Popen([BIN, str(P), "--host", "127.0.0.1", "--upstream", f"socks5h://127.0.0.1:{s1.port}", "--upstream-trust-dns"],
                      stdout=open(os.path.join(D, "nl.log"), "w+"), stderr=subprocess.STDOUT); time.sleep(0.5)
w = Wisp(); case_close(w, "localhost", 0x48, msg="socks5h: localhost refused without --allow-loopback")
case_close(w, "a.localhost", 0x48, msg="socks5h: *.localhost refused")
pp.terminate(); pp.wait()
#@seg http-auth 10.4
# ---- HTTP CONNECT
h1 = Http(auth=(b"a", b"b:c"))
p = start("--upstream", f"http://a:b%3Ac@127.0.0.1:{h1.port}")
w = Wisp(); echo_ok(w, "127.0.0.1", "http CONNECT with Basic auth")
ok(h1.log[-1].startswith(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nProxy-Authorization: Basic " % (E, E)), f"request bytes ({h1.log[-1][:80]!r})")
stop(p); p = start("--upstream", f"http://a:bad@127.0.0.1:{h1.port}")
w = Wisp(); case_close(w, "127.0.0.1", 0x03, msg="http 407")
#@seg http-status 0.3x5
for code, want in each("http-status", [(403, 0x48), (502, 0x03), (503, 0x03), (504, 0x43), (500, 0x03)]):
    h = Http(status=lambda d, c=code: c)
    stop(p); p = start("--upstream", f"http://127.0.0.1:{h.port}")
    w = Wisp(); case_close(w, "127.0.0.1", want, msg=f"http {code}")
#@seg http-dribble 10.3
hd = Http(dribble=True)
stop(p); p = start("--upstream", f"http://127.0.0.1:{hd.port}")
w = Wisp(); echo_ok(w, "127.0.0.1", "http reply head dribbled byte by byte")
#@all
hc = Http(combine=True)
#@seg http-combine 10.3
stop(p); p = start("--upstream", f"http://127.0.0.1:{hc.port}")
w = Wisp(); sid = w.connect("127.0.0.1", BAN); got = w.data(sid, 11)
ok(got == b"220 hello\r\n", f"http: banner in the same segment as the 200 arrives as first DATA ({got!r})")
#@seg http-bighead 0.3
hb = Http(bighead=True)
stop(p); p = start("--upstream", f"http://127.0.0.1:{hb.port}")
w = Wisp(); case_close(w, "127.0.0.1", 0x03, msg="http head over 8 KiB")
#@seg http-bulk 6.8
# bulk download through the proxy: integrity (+ splice checked by strace in the doc run)
stop(p); p = start("--upstream", f"http://127.0.0.1:{hc.port}")
w = Wisp(); sid = w.connect("127.0.0.1", BULK)
got = w.data(sid, len(BULK_DATA), t=30)
ok(hashlib.sha256(got).digest() == hashlib.sha256(BULK_DATA).digest(), f"32 MiB download through the HTTP proxy intact ({len(got)} bytes)")
ok(metric(p, "upstream_ok") is not None, "upstream_ok metric present")
#@all
# ---- 60.32: the try cap (PROXY_TRIES 4) and no early DNS answers, with a fake DNS server (--dns-server)
def dns_server():
    d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); d.bind(("127.0.0.1", 0))
    def answer(q):
        off, labels = 12, []
        while q[off]: labels.append(q[off + 1:off + 1 + q[off]].decode().lower()); off += 1 + q[off]
        n, qt = ".".join(labels), struct.unpack(">H", q[off + 1:off + 3])[0]
        ips = []
        if n == "many.test" and qt == 1: ips = [socket.inet_aton(f"127.0.0.{i}") for i in range(1, 7)]
        if n == "late6.test": ips = [socket.inet_aton("127.0.0.1")] if qt == 1 else [socket.inet_pton(socket.AF_INET6, "::1")]
        if n == "late6.test" and qt == 28: time.sleep(0.3)  # 70.10: without an upstream the A answer would go first
        hdr = q[:2] + struct.pack(">HHHHH", 0x8180, 1, len(ips), 0, 0)
        return hdr + q[12:off + 5] + b"".join(b"\xc0\x0c" + struct.pack(">HHIH", qt, 1, 60, len(ip)) + ip for ip in ips)
    def loop():
        while True:
            q, a = d.recvfrom(4096)
            threading.Thread(target=lambda q=q, a=a: d.sendto(answer(q), a), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return d.getsockname()[1]
DNSP = dns_server()
#@seg dns-try-cap 0.3
sall = Socks(rep=lambda d: 4)
stop(p); p = start("--upstream", f"socks5://127.0.0.1:{sall.port}", "--dns-server", f"127.0.0.1:{DNSP}")
w = Wisp(); case_close(w, "many.test", 0x42, msg="6 target addresses, REP 04 for each")
tried = [x[2] for x in sall.log if x[0] == "connect"]
ok(tried == ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"], f"at most 4 target addresses tried through the proxy ({tried})")
#@seg dns-retry 12.8
stop(p); p = start("--upstream", f"socks5://127.0.0.1:{s4.port}", "--dns-server", f"127.0.0.1:{DNSP}")
w = Wisp(); n0 = len(s4.log); echo_ok(w, "many.test", "REP 04 on 127.0.0.1, the retry on 127.0.0.2 succeeds")
ok([x[2] for x in s4.log[n0:] if x[0] == "connect"] == ["127.0.0.1", "127.0.0.2"], f"retry: the next target address over a new proxy connection ({s4.log[n0:]})")
ok(metric(p, "upstream_fail") == 0 and metric(p, "upstream_ok") == 1, "a retried open: upstream_ok 1, upstream_fail 0")
#@seg dns-late6 10.5
stop(p); p = start("--upstream", f"socks5://127.0.0.1:{s1.port}", "--dns-server", f"127.0.0.1:{DNSP}")
w = Wisp(); n0 = len(s1.log); t0 = time.time()
echo_ok(w, "late6.test", "--dns-own: the final answer (A now, AAAA 300 ms later)")
ok(time.time() - t0 >= 0.25 and [x for x in s1.log[n0:] if x[0] == "connect"] == [("connect", 1, "127.0.0.1", E)],
   f"no early answer with an upstream: one CONNECT after the final answer, IPv4 first ({s1.log[n0:]})")
#@seg loopback-names 30.8
# ---- 60.32: loopback names under socks5h (the /etc/hosts aliases), refused without --allow-loopback
stop(p)
pp = subprocess.Popen([BIN, str(P), "--host", "127.0.0.1", "--upstream", f"socks5h://127.0.0.1:{s1.port}", "--upstream-trust-dns"],
                      stdout=open(os.path.join(D, "nl2.log"), "w+"), stderr=subprocess.STDOUT); time.sleep(0.5)
w = Wisp(); n0 = len(s1.log)
for name in ("localhost.localdomain", "LOCALHOST6", "ip6-localhost", "ip6-loopback", "localhost6.localdomain6"):
    case_close(w, name, 0x48, msg=f"socks5h: {name} refused")
ok(len(s1.log) == n0, "loopback names never reach the proxy")
echo_ok(w, "93.184.216.34", "a proxy on 127.0.0.1 without --allow-loopback (the proxy address is the operator's choice)")
#@all
# the refresh thread: only for a proxy given by name
tasks = lambda pid: [open(f"/proc/{pid}/task/{t}/comm").read().strip() for t in os.listdir(f"/proc/{pid}/task")]
#@seg loopback-names
ok("upstream-dns" not in tasks(pp.pid), "an IP-literal proxy: no upstream-dns thread")
stop(pp) if TRIM else (pp.terminate(), pp.wait())  # w is still open: without --trim this is the 30 s drain
#@seg proxy-by-name 12.8
p = start("--upstream", f"socks5://localhost:{s1.port}")
ok("upstream-dns" in tasks(p.pid), "a proxy given by name: the upstream-dns thread runs")
w = Wisp(); echo_ok(w, "127.0.0.1", "proxy given by name (localhost)")
ok(metric(p, "upstream_dns_fail") == 0 and metric(p, "upstream_dns_age_s") is not None, "a proxy by name: upstream_dns_fail / upstream_dns_age_s in the line")
stop(p)
#@seg no-upstream 0.2
p0 = start(); ok("upstream-dns" not in tasks(p0.pid) and "upstream" not in srvlog(p0), "no --upstream: no thread, no capability note"); stop(p0)
#@seg startup-refusals 0.4
# ---- 60.32: startup refusals (every unsupported form fails loudly; no message quotes the credentials)
for args, want in [(["--upstream", "https://u:hunter2@127.0.0.1:1"], "not supported"),
                   (["--upstream", "socks5h://u:hunter2@127.0.0.1:1"], "--upstream-trust-dns"),
                   (["--upstream-trust-dns"], "only with"),
                   (["--upstream", "socks5://u:hunter2@::1:1080"], "brackets"),
                   (["--upstream", "socks5://u:hunter2@no-such-host.invalid"], "no address")]:
    q = start(*args); q.wait(30); out = srvlog(q)  # 30 s: no-such-host.invalid goes to the host's resolver at startup (60.33)
    ok(q.returncode not in (None, 0) and want in out and "hunter2" not in out, f"refused at startup: {args[-1]} ({out.strip()[-90:]!r})")
#@seg config-secret 10.2
# ---- 60.32: --upstream with credentials in a group-readable --config: the C8 secret warning (and no password shown)
cf = os.path.join(D, "fw.conf")
with open(cf, "w") as f: f.write(f"upstream socks5://us%20er:p%40ss@127.0.0.1:{sa.port}\n")
os.chmod(cf, 0o644)
p = start("--config", cf)
ok("holds a secret" in srvlog(p) and "p%40ss" not in srvlog(p) and "/proc/PID/cmdline" not in srvlog(p), "--config 0644 with --upstream: secret warning; no cmdline warning")
w = Wisp(); echo_ok(w, "127.0.0.1", "--upstream from --config")
#@seg cmdline-secret 0.2
stop(p); p = start("--upstream", f"socks5://us%20er:p%40ss@127.0.0.1:{sa.port}")
ok("/proc/PID/cmdline" in srvlog(p) and "clear text" in srvlog(p), "credentials on the command line: both warnings")
stop(p)
#@all
print("upstream:", "ALL PASS" if fails == 0 else f"{fails} FAIL", flush=True)
sys.exit(1 if fails else 0)
