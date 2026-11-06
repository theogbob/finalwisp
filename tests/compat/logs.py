#!/usr/bin/env python3
"""60.24 (60.20 C4 step 1) logging against a real finalwisp. Stdlib only.
usage: logs.py FINALWISP_BINARY BASEPORT (BASEPORT = server, BASEPORT+1 = TCP echo)
Cases: the default prints no connection lines; --log-conns: one ev=conn_close per connection with exact wire bytes
(rx = what the client sent, tx = what it received), the reason for a client close, a WebSocket error, a handshake
timeout, streams / refused; 500 quick connections with a reader give 500 lines and no drops; --log-level warn hides
info lines and keeps warnings (also the connection lines with --log-conns), error hides both; a line queued just before
exit is written; a 1000-connection refusal flood (--max-conns 1) gives at most 20
conn_refused lines per second plus ev=refused_suppressed, adding up to the refusals; a stalled stderr: echo still
works, lines are dropped and counted (ev=log_dropped, metric log_dropped).
60.35 --log-streams (without --log-conns): a TCP echo stream with exact up/down and dst, a request-rule refusal
(stream_refused rule=ports), an escaped host, an address-class refusal after DNS (rule=private), 0x42 dns_fail, a UDP
stream's datagram and byte counts, a long refused host cut (host_len), wsproxy lines (sid=0: connect_fail, target_close),
no conn_close lines; with --log-level warn no stream lines."""
import base64, os, re, socket, struct, subprocess, sys, tempfile, threading, time

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

D = tempfile.mkdtemp(prefix="fw-logs-")
def start(*args, stderr=None, probe=False):
    """ready at the capabilities line; `probe`: at the first accepted connection instead (a level that hides that
    line; it would be a connection line itself with --log-conns), or after a fixed wait (stderr not in the log)"""
    log = open(os.path.join(D, f"srv{time.monotonic_ns()}.log"), "w+")
    p = subprocess.Popen([BIN, str(P), "--allow-loopback", *args], stdout=log,
                         stderr=stderr if stderr is not None else subprocess.STDOUT)
    p.logf = log
    for _ in range(200):
        if p.poll() is not None: break
        if probe:
            try:
                socket.create_connection(("127.0.0.1", P), timeout=1).close(); break
            except OSError: pass
        elif stderr is None and "capabilities:" in srvlog(p): break
        time.sleep(0.05)
    if stderr is not None: time.sleep(0.5)
    return p
def srvlog(p):
    with open(p.logf.name) as f: return f.read()
def stop(p):
    p.terminate()
    try: p.wait(10)
    except subprocess.TimeoutExpired: p.kill(); p.wait()
def lines(p, ev): return [l for l in srvlog(p).splitlines() if f" ev={ev} " in l + " "]
def fields(l): return dict(kv.split("=", 1) for kv in l.split()[1:] if "=" in kv)

def frame(payload, mask=True):
    n = len(payload); m = os.urandom(4) if mask else b""
    b1 = 0x80 if mask else 0
    hdr = bytes([0x82, b1 | n]) if n < 126 else (bytes([0x82, b1 | 126]) + struct.pack(">H", n) if n < 65536 else bytes([0x82, b1 | 127]) + struct.pack(">Q", n))
    return hdr + m + (bytes(b ^ m[i & 3] for i, b in enumerate(payload)) if mask else payload)

UP = (b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
      + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")

class Conn:
    """a v1 Wisp connection that counts the bytes it sent and received"""
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", P), timeout=5)
        self.sent = self.got = 0
        self.tx(UP)
        self.buf = b""
        while b"\r\n\r\n" not in self.buf: self.rx()
        self.buf = self.buf.split(b"\r\n\r\n", 1)[1]
    def tx(self, b): self.s.sendall(b); self.sent += len(b)
    def rx(self):
        d = self.s.recv(1 << 20)
        if not d: raise EOFError
        self.got += len(d); self.buf += d
    def wisp(self, ty, sid, body): self.tx(frame(bytes([ty]) + struct.pack("<I", sid) + body))
    def frames(self):
        """whole frames from buf (payloads)"""
        out = []
        while len(self.buf) >= 2:
            ln, h = self.buf[1] & 0x7f, 2
            if ln == 126:
                if len(self.buf) < 4: break
                ln, h = struct.unpack(">H", self.buf[2:4])[0], 4
            elif ln == 127:
                if len(self.buf) < 10: break
                ln, h = struct.unpack(">Q", self.buf[2:10])[0], 10
            if len(self.buf) < h + ln: break
            out.append(self.buf[h:h + ln]); self.buf = self.buf[h + ln:]
        return out
    def echo(self, n):
        """one stream to the echo server: n bytes up and back"""
        self.wisp(1, 1, b"\x01" + struct.pack("<H", E) + b"127.0.0.1")
        data = os.urandom(n); back = b""
        for i in range(0, n, 16000): self.wisp(2, 1, data[i:i + 16000])
        end = time.time() + 10
        while len(back) < n and time.time() < end:
            self.rx()
            for f in self.frames():
                if f[0] == 2: back += f[5:]
        return back == data

def wait_for(p, ev, n, t=3.0):
    end = time.time() + t
    while time.time() < end and len(lines(p, ev)) < n: time.sleep(0.05)
    return lines(p, ev)

# 1. default: no connection lines, the info lines are there
p = start("--threads", "2")
c = Conn(); ok(c.echo(1000), "default: echo"); c.s.close(); time.sleep(0.3)
stop(p); t = srvlog(p)
ok("ev=conn_" not in t and "ev=stream_" not in t and "listening on" in t and "capabilities:" in t, "default: info lines, no connection lines")

# 2. --log-conns
p = start("--threads", "2", "--log-conns", "--max-streams-per-conn", "1")
hs = socket.create_connection(("127.0.0.1", P))  # sends nothing: handshake timeout (5 idle sweeps of 2 s)
c = Conn(); ok(c.echo(300_000), "conns: echo 300 KB")
c.wisp(1, 2, b"\x01" + struct.pack("<H", E) + b"127.0.0.1")  # over --max-streams-per-conn 1: refused
time.sleep(0.2); c.rx(); c.frames()
c.s.shutdown(socket.SHUT_WR)
try:
    while True: c.rx()
except (EOFError, OSError): pass
c.s.close()
bad = Conn(); bad.tx(frame(b"\x02\x01\x00\x00\x00x", mask=False)); time.sleep(0.3); bad.s.close()
got = wait_for(p, "conn_close", 2)
by = {f.get("why"): f for f in map(fields, got)}
f = by.get("client_close", {})
ok(f.get("rx") == str(c.sent) and f.get("tx") == str(c.got), f"conns: rx/tx = wire bytes ({f.get('rx')}/{c.sent}, {f.get('tx')}/{c.got})")
ok((f.get("proto"), f.get("streams"), f.get("refused"), f.get("ip"), f.get("auth"), f.get("tls")) == ("v1", "1", "1", "127.0.0.1", "none", "0"),
   f"conns: fields {f}")
ok(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", f.get("ts", "")) is not None and re.fullmatch(r"\d+:\d+", f.get("cid", "")) is not None,
   "conns: ts and cid")
ok("ws_error" in by, f"conns: unmasked frame -> ws_error ({list(by)})")
t0 = time.time(); got = wait_for(p, "conn_close", 3, 15)
ok(any(fields(l).get("why") == "hs_timeout" for l in got), f"conns: silent connection -> hs_timeout after {time.time() - t0:.1f} s")
hs.close()
ok(not lines(p, "conn_open"), "conns: no conn_open at info")
# 500 quick connections, stderr read: every line, none dropped
n0 = len(lines(p, "conn_close"))
def quick(k):
    for _ in range(k):
        s = socket.create_connection(("127.0.0.1", P)); s.sendall(UP); s.recv(4096); s.close()
ths = [threading.Thread(target=quick, args=(100,)) for _ in range(5)]
[t.start() for t in ths]; [t.join() for t in ths]
got = wait_for(p, "conn_close", n0 + 500, 5)
ok(len(got) - n0 == 500 and not lines(p, "log_dropped"), f"conns: 500 quick connections -> {len(got) - n0} lines, no drops")
stop(p)

# 3. --log-level
p = start("--log-level", "warn", "--real-ip-header", "x-real-ip", probe=True); stop(p); t = srvlog(p)
ok("warning: --real-ip-header" in t and "listening on" not in t and "capabilities:" not in t, "warn: warnings only")
p = start("--log-level", "error", "--real-ip-header", "x-real-ip", probe=True); stop(p); t = srvlog(p)
ok(t.strip() == "", f"error: nothing ({t[:200]!r})")
p = start("--log-level", "warn", "--log-conns", probe=True); c = Conn(); c.s.close(); time.sleep(0.5); stop(p)
ok("ev=conn_" not in srvlog(p), "warn + --log-conns: connection lines are info, not shown")
p = start("--log-conns", "--drain-timeout", "5"); c = Conn(); c.s.close(); time.sleep(0.03); stop(p)
ok(len(lines(p, "conn_close")) == 1, "exit right after a close: the queued line is written (writer flush)")
p = start("--log-level", "debug", "--log-conns"); c = Conn(); c.s.close(); got = wait_for(p, "conn_close", 1); stop(p)
ok(len(lines(p, "conn_open")) == 1 and len(got) == 1, "debug: conn_open + conn_close")

# 4. refusal flood: --max-conns 1, one held, 1000 more reset at accept
p = start("--threads", "1", "--log-conns", "--max-conns", "1", "--metrics-interval", "1")
held = Conn(); t0 = time.time()
for _ in range(1000):
    try:
        s = socket.create_connection(("127.0.0.1", P)); s.close()
    except OSError: pass
time.sleep(2.5); dt = time.time() - t0
ref = lines(p, "conn_refused"); sup = sum(int(fields(l)["n"]) for l in lines(p, "refused_suppressed"))
m = [fields(l) for l in lines(p, "metrics")]
nref = int(m[-1].get("refuse_conns", -1)) if m else -1
ok(len(ref) <= 20 * (int(dt) + 2) and len(ref) + sup == nref and nref > 900,
   f"flood: {len(ref)} lines + {sup} suppressed = {nref} refusals in {dt:.1f} s")
held.s.close(); stop(p)

# 5. a stalled stderr (a pipe nobody reads): echo still works, lines dropped and counted
p = start("--threads", "1", "--log-conns", "--metrics-interval", "1", stderr=subprocess.PIPE)
def churn(k):
    for _ in range(k):
        s = socket.create_connection(("127.0.0.1", P)); s.sendall(UP); s.recv(4096); s.close()
ths = [threading.Thread(target=churn, args=(800,)) for _ in range(5)]
[t.start() for t in ths]; [t.join() for t in ths]
c = Conn(); ok(c.echo(100_000), "stalled stderr: echo still works"); c.s.close()
out = []
rd = threading.Thread(target=lambda: out.append(p.stderr.read()), daemon=True); rd.start()
time.sleep(2.5)
stop(p); rd.join(5)
t = (out[0] if out else b"").decode(errors="replace")
dropped = sum(int(fields(l)["n"]) for l in t.splitlines() if " ev=log_dropped " in l)
mets = [fields(l) for l in t.splitlines() if " ev=metrics" in l]
ok(dropped > 0 and mets and int(mets[-1].get("log_dropped", 0)) == dropped,
   f"stalled stderr: ev=log_dropped n={dropped}, metric {mets[-1].get('log_dropped') if mets else None}")
ok(dropped + t.count(" ev=conn_close ") == 4001, f"stalled stderr: lines + dropped = 4001 connections ({t.count(' ev=conn_close ')} + {dropped})")


# 6. 60.35 --log-streams (without --log-conns): one ev=stream_close per stream, ev=stream_refused per refused CONNECT
us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); us.bind(("127.0.0.1", E))
def uecho():
    while True:
        d, a = us.recvfrom(65536); us.sendto(d, a)
threading.Thread(target=uecho, daemon=True).start()
p = start("--threads", "1", "--log-streams", "--block-ports", "22")
c = Conn(); ok(c.echo(300_000), "streams: echo 300 KB")
c.wisp(4, 1, b"\x02"); time.sleep(0.2)
c.wisp(1, 3, b"\x01" + struct.pack("<H", 22) + b"example.com")       # request rule: refused before a target
c.wisp(1, 5, b"\x01" + struct.pack("<H", 22) + b'q"x=y.example')     # the same, a host that needs escaping
c.wisp(1, 7, b"\x01" + struct.pack("<H", 80) + b"10.0.0.1")          # address class after "DNS": private
c.wisp(1, 9, b"\x01" + struct.pack("<H", 80) + b"a..")               # 0x42 at once: dns_fail
c.wisp(1, 13, b"\x01" + struct.pack("<H", 80) + b"a" * 1000)         # an invalid host: logged cut, with its length
c.wisp(1, 11, b"\x02" + struct.pack("<H", E) + b"127.0.0.1")         # UDP: 3 datagrams there and back
for n in (100, 200, 300): c.wisp(2, 11, os.urandom(n))
got_u, end = 0, time.time() + 5
while got_u < 3 and time.time() < end:
    c.rx(); got_u += sum(1 for f in c.frames() if f[0] == 2 and struct.unpack("<I", f[1:5])[0] == 11)
c.wisp(4, 11, b"\x02")
got = wait_for(p, "stream_close", 4)
by = {fields(l).get("sid"): fields(l) for l in got}
f = by.get("1", {})
ok((f.get("t"), f.get("host"), f.get("port"), f.get("up"), f.get("down"), f.get("reason"), f.get("why"), f.get("dst"))
   == ("tcp", "127.0.0.1", str(E), "300000", "300000", "none", "client_close", "127.0.0.1"), f"streams: tcp line {f}")
ok(re.fullmatch(r"\d+:\d+", f.get("cid", "")) is not None and f.get("ip") == "127.0.0.1" and f.get("dur_ms", "").isdigit(),
   "streams: cid, ip, dur_ms without --log-conns")
f = by.get("7", {}); ok((f.get("reason"), f.get("why"), f.get("rule")) == ("0x48", "policy", "private"), f"streams: address rule {f}")
f = by.get("9", {}); ok((f.get("reason"), f.get("why"), f.get("host")) == ("0x42", "dns_fail", "a.."), f"streams: dns_fail {f}")
f = by.get("11", {})
ok((f.get("t"), f.get("up"), f.get("down"), f.get("dgrams_up"), f.get("dgrams_down")) == ("udp", "600", "600", "3", "3"),
   f"streams: udp counts {f} ({got_u} back)")
ref = {fields(l).get("sid"): l for l in lines(p, "stream_refused")}
r3 = ref.get("3", "")
ok(r3.endswith(" sid=3 t=tcp host=example.com port=22 reason=0x48 why=policy rule=ports"), f"streams: refused line {r3!r}")
ok(' host="q\\"x=y.example" port=22 ' in ref.get("5", ""), f"streams: host escaped {ref.get('5')!r}")
r13 = ref.get("13", "")
ok(f" host={'a' * 255} host_len=1000 port=80 reason=0x41 why=invalid" in r13, f"streams: a long host is cut ({len(r13)} bytes)")
c.s.close(); time.sleep(0.3)
# wsproxy: one line with sid=0; a refused connect is connect_fail, a target that closes is target_close (no Wisp code)
dead = socket.socket(); dead.bind(("127.0.0.1", 0)); dport = dead.getsockname()[1]; dead.close()
shut = socket.socket(); shut.bind(("127.0.0.1", 0)); shut.listen(4); sport = shut.getsockname()[1]
def shut_acc():
    while True:
        a, _ = shut.accept(); a.close()
threading.Thread(target=shut_acc, daemon=True).start()
for port in (dport, sport):
    s = socket.create_connection(("127.0.0.1", P), timeout=5)
    s.sendall(UP.replace(b"GET / ", f"GET /127.0.0.1:{port} ".encode()))
    try:
        while s.recv(65536): pass
    except OSError: pass
    s.close()
got = wait_for(p, "stream_close", len(got) + 2)
wsp = {fields(l).get("port"): fields(l) for l in got if fields(l).get("t") == "wsproxy"}
f = wsp.get(str(dport), {})
ok((f.get("sid"), f.get("reason"), f.get("why")) == ("0", "none", "connect_fail"), f"streams: wsproxy refused connect {f}")
f = wsp.get(str(sport), {})
ok((f.get("sid"), f.get("reason"), f.get("why"), f.get("dst")) == ("0", "none", "target_close", "127.0.0.1"), f"streams: wsproxy target closed {f}")
stop(p)
ok(not lines(p, "conn_close"), "streams: no conn_close without --log-conns")
p = start("--log-streams", "--drain-timeout", "5"); c = Conn(); ok(c.echo(1000), "streams: echo before exit"); c.s.close()
time.sleep(0.03); stop(p)
ok(len(lines(p, "stream_close")) == 1, "streams: exit right after a close: the stream line is written (flushed with the connection)")
p = start("--log-level", "warn", "--log-streams", probe=True); c = Conn(); ok(c.echo(1000), "warn + --log-streams: echo"); c.s.close()
time.sleep(0.5); stop(p)
ok("ev=stream_" not in srvlog(p), "warn + --log-streams: stream lines are info, not shown")

print("DONE" if fails == 0 else f"FAILED {fails}", flush=True)
sys.exit(1 if fails else 0)
