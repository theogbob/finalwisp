#!/usr/bin/env python3
"""60.78 G11 + G12: the TCP pressure warn line, E1 (--tcpmem-share) and E2 (--port-share) end to end with --preset public,
in a VM of its own (it writes net.ipv4.tcp_mem and ip_local_port_range of THAT VM and puts them back). Counts and
pass/fail only, no timing. Stdlib only; run as root. usage: pressure.py FINALWISP BASEPORT  (BASEPORT+1 echo, +2 source)
Clients get public addresses from a PROXY protocol v1 header (no rule of section E applies to a loopback client).
- G11: tcp_mem 4096 6144 8192 pages; one client opens 64 downloads and never reads: TcpExt TCPMemoryPressures rises,
  the server prints its warning line once.
- G12 E1: in the same state that client (A) holds more than half of the unread target sockets (floor = 8192 pages x
  4096 / 16 / tcp_rmem[1]); another client (B) is connected: A's new stream gets CLOSE 0x49, refuse_tcpmem_share
  moves, B's new stream opens.
- G12 E2: ip_local_port_range 40000 40255 (256 ports): A holds 200 streams to the echo target, B one: A's new stream
  to it gets CLOSE 0x49 (refuse_port_share), B's new stream opens, a stream of A to another destination opens."""
import base64, os, socket, struct, subprocess, sys, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
TGT, SRC = BASE + 1, BASE + 2
A, B = "203.0.113.1", "198.51.100.7"
OUT = os.path.join(os.path.dirname(BIN), "out"); os.makedirs(OUT, exist_ok=True)
fails = 0
def ok(c, m):
    global fails
    line = ("CHECK " + ("PASS " if c else "FAIL ") + m)
    print(line, flush=True); open(os.path.join(OUT, "pressure.txt"), "a").write(line + "\n")
    fails += 0 if c else 1
def info(m):
    print("CHECK INFO " + m, flush=True); open(os.path.join(OUT, "pressure.txt"), "a").write("CHECK INFO " + m + "\n")
def rd(p): return open(p).read().strip()
def wr(p, v): open(p, "w").write(v)
def netstat(key):
    t = open("/proc/net/netstat").read().split("\n")
    for i in range(0, len(t) - 1, 2):
        h, v = t[i].split(), t[i + 1].split()
        if h and h[0] == "TcpExt:" and key in h: return int(v[h.index(key)])
def tcp_pages():
    for l in open("/proc/net/sockstat"):
        if l.startswith("TCP:"): f = l.split(); return int(f[f.index("mem") + 1])

def echo(c):
    with c:
        try:
            d = c.recv(65536)
            while d: c.sendall(d); d = c.recv(65536)
        except OSError: pass
def feed(c):
    blob = b"x" * 65536
    try:
        while True: c.sendall(blob)
    except OSError: c.close()
def serve(port, fn):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", port)); ls.listen(4096)
    def run():
        while True:
            try: c, _ = ls.accept()
            except OSError: return
            threading.Thread(target=fn, args=(c,), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
serve(TGT, echo); serve(SRC, feed)

LOGS = []
def start(name):
    log = open(os.path.join(OUT, f"pressure-{name}.log"), "w+")
    p = subprocess.Popen([BIN, "--preset", "public", "--port", str(BASE), "--allow-loopback", "--metrics-interval", "1",
                          "--threads", "1", "--log-level", "debug", "--proxy-protocol", "tcp", "--proxy-protocol-from", "127.0.0.0/8"],
                         stdout=log, stderr=subprocess.STDOUT)
    p.logf = log
    for _ in range(200):
        if "listening on" in srvlog(p) or p.poll() is not None: break
        time.sleep(0.05)
    time.sleep(0.3)
    return p
def srvlog(p):
    with open(p.logf.name) as f: return f.read()
def stop(p):
    p.terminate()
    try: rc = p.wait(15)
    except subprocess.TimeoutExpired: p.kill(); rc = p.wait()
    return rc
def metric(p, key):
    n0, end = srvlog(p).count("ev=metrics"), time.time() + 3
    while srvlog(p).count("ev=metrics") <= n0 and time.time() < end: time.sleep(0.1)
    vals = [l for l in srvlog(p).splitlines() if "ev=metrics" in l]
    for kv in (vals[-1].split() if vals else []):
        if kv.startswith(key + "="): return int(kv.split("=", 1)[1])

def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))
class Wisp:
    def __init__(self, src, rcvbuf=None):
        self.s = socket.socket()
        if rcvbuf: self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        self.s.settimeout(5); self.s.connect(("127.0.0.1", BASE))
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
    def send(self, ty, sid, body): self.s.sendall(frame(bytes([ty]) + struct.pack("<I", sid) + body))
    def connect(self, sid, port=TGT): self.send(1, sid, b"\x01" + struct.pack("<H", port) + b"127.0.0.1")
    def packets(self, t=1.0, until=None):
        end = time.time() + t; self.s.settimeout(0.05)
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
                if len(p) >= 5 and p[0] != 2: self.seen.append((p[0], struct.unpack("<I", p[1:5])[0], p[5:]))
                elif len(p) >= 5: self.seen.append((2, struct.unpack("<I", p[1:5])[0], p[5:]))
            if (until and until(self.seen)) or time.time() >= end: break
            try:
                d = self.s.recv(1 << 20)
                if not d: break
                self.buf += d
            except socket.timeout: pass
        return self.seen
    def echo(self, sid, data=b"ping"):
        self.send(2, sid, data)
        got = lambda out: b"".join(b for ty, s, b in out if ty == 2 and s == sid)
        return got(self.packets(4.0, lambda out: got(out).endswith(data))).endswith(data)
    def reason(self, sid, t=3.0):
        for ty, s, body in self.packets(t, lambda out: any(ty == 4 and s == sid for ty, s, _ in out)):
            if ty == 4 and s == sid: return body[0]
    def close(self): self.s.close()

TM, PR = "/proc/sys/net/ipv4/tcp_mem", "/proc/sys/net/ipv4/ip_local_port_range"
tm0, pr0 = rd(TM), rd(PR)
info(f"kernel {os.uname().release}; tcp_mem {tm0}; ip_local_port_range {pr0}; tcp_rmem {rd('/proc/sys/net/ipv4/tcp_rmem')}")
try:
    # ---------------- G11 + E1
    wr(TM, "4096 6144 8192")
    p = start("e1")
    log0 = srvlog(p)
    ok("TCP memory guard" in log0, "E1: the preset's TCP memory guard line at start: " + next((l.strip()[:200] for l in log0.splitlines() if "TCP memory guard" in l), "none"))
    pres0 = netstat("TCPMemoryPressures")
    a = Wisp(A, rcvbuf=4096); b = Wisp(B)
    b.connect(1); ok(b.echo(1), "E1: B's stream opens before the load")
    for sid in range(1, 65): a.connect(sid, SRC)
    peak, end = 0, time.time() + 30
    while time.time() < end:
        peak = max(peak, tcp_pages()); time.sleep(0.2)
        if netstat("TCPMemoryPressures") > pres0 and "kernel TCP memory pressure" in srvlog(p): break
    pres1 = netstat("TCPMemoryPressures")
    info(f"G11: host TCP pages peak {peak} (tcp_mem {rd(TM)}); TCPMemoryPressures {pres0} -> {pres1}")
    ok(pres1 > pres0, "G11: the host entered TCP memory pressure (TcpExt TCPMemoryPressures rose)")
    time.sleep(2.5)  # (the sampler reads once a second)
    lines = [l for l in srvlog(p).splitlines() if "the host entered kernel TCP memory pressure" in l]
    ok(len(lines) >= 1, "G11: the server's warning line: " + (lines[0][:160] if lines else "none"))
    ok(len(lines) <= 2, f"G11: rate limited ({len(lines)} line(s) in this run)")
    time.sleep(1.5)
    info(f"E1: tcpmem_unread {metric(p, 'tcpmem_unread')}, host TCP pages {tcp_pages()}")
    r0 = metric(p, "refuse_tcpmem_share")
    a.connect(100, SRC)
    ra = a.reason(100, 4)
    ok(ra == 0x49, f"E1: A (holds the unread downloads) gets CLOSE 0x49 for a new stream (got {ra})")
    ok((metric(p, "refuse_tcpmem_share") or 0) > (r0 or 0), f"E1: refuse_tcpmem_share {r0} -> {metric(p, 'refuse_tcpmem_share')}")
    b.connect(2); ok(b.echo(2), "E1: B's new stream opens while A is refused")
    ok("--tcpmem-share: new streams of one client address are refused" in srvlog(p), "E1: the refusal's warning line")
    a.close(); b.close()
    rc = stop(p); ok(rc == 0, f"E1: exit status {rc} on SIGTERM")
    wr(TM, tm0); time.sleep(2)
    # ---------------- E2
    wr(PR, "40000 40255")
    p = start("e2")
    ok("source port guard" in srvlog(p), "E2: the preset's source port guard line: " + next((l.strip()[:200] for l in srvlog(p).splitlines() if "source port guard" in l), "none"))
    a = Wisp(A); b = Wisp(B)
    b.connect(1); ok(b.echo(1), "E2: B uses the destination (one stream)")
    for sid in range(1, 201): a.connect(sid)
    ok(all(a.echo(s) for s in (1, 100, 200)), "E2: A's 200 streams to the destination open")
    time.sleep(1.0)  # (the guard thread sums the ports every 250 ms)
    info(f"E2: port_dest_max {metric(p, 'port_dest_max')}")
    r0 = metric(p, "refuse_port_share")
    a.connect(300); ra = a.reason(300, 4)
    ok(ra == 0x49, f"E2: A's new stream to the destination gets CLOSE 0x49 (got {ra})")
    ok((metric(p, "refuse_port_share") or 0) > (r0 or 0), f"E2: refuse_port_share {r0} -> {metric(p, 'refuse_port_share')}")
    b.connect(2); ok(b.echo(2), "E2: B's new stream to the destination opens")
    a.connect(301, SRC); ok(a.reason(301, 1.5) is None, "E2: A's stream to another destination opens (no CLOSE)")
    ok("--port-share" in srvlog(p) and "refused" in srvlog(p), "E2: a refusal line of --port-share")
    a.close(); b.close()
    rc = stop(p); ok(rc == 0, f"E2: exit status {rc} on SIGTERM")
finally:
    wr(TM, tm0); wr(PR, pr0)
    info(f"restored tcp_mem {rd(TM)}; ip_local_port_range {rd(PR)}")
print(f"{'FAILED' if fails else 'ok'}: {fails} failure(s)", flush=True)
sys.exit(1 if fails else 0)
