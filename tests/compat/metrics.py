#!/usr/bin/env python3
"""60.12 C5-lite metrics, functional (stdlib only; laptop-safe: a few connections, no load).

usage: metrics.py BIN [--port P]

1. --metrics-interval 1: one `ev=metrics` line per second on stderr, logfmt key=value; the counters match
   what the test did: 3 connections accepted, CONNECTs admitted, CLOSE 0x41 (bad stream type), 0x44 (refused
   port), 0x42 + dns_fail (a name that does not resolve; --dns-own against a local NXDOMAIN server, not the host's) and dns_neg_hit (the same name again), the streams
   gauge back to 0 after the client closed its stream; no secret-looking strings.
2. SIGTERM: graceful shutdown (60.12 drain), one `ev=metrics_final` line, exit 0.
3. Off (no flag): no metrics line, no `metrics` thread, SIGTERM exits 0.
5. A full stderr pipe nobody reads: SIGTERM still ends it within 3 s.
4. --mem-budget 32M (starts at level 1): level=1, the accepted sockets counted in cap_apply, time at level 1.
Exit 0 = all passed, 1 = a failure.
"""
import os, signal, socket, struct, subprocess, sys, threading, time

args = sys.argv[1:]
if not args or args[0].startswith("-"):
    print(__doc__)
    sys.exit(2)
BIN = os.path.abspath(args[0])
PORT = int(args[args.index("--port") + 1]) if "--port" in args else 7990
fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail else ""), flush=True)
    if not ok:
        fails.append(name)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def echo_target():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)

    def serve(c):
        try:
            while (d := c.recv(65536)):
                c.sendall(d)
        except OSError:
            pass  # a stream closed by the server's RST (client CLOSE 0x02 = reset)
        c.close()

    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=serve, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


def ws_frame(payload):  # masked binary frame
    n = len(payload)
    hdr = bytes([0x82]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
    m = os.urandom(4)
    return hdr + m + bytes(c ^ m[i & 3] for i, c in enumerate(payload))


class Wisp:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        self.s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            self.buf += self.s.recv(4096)
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 101"), head

    def send(self, ty, sid, payload):
        self.s.sendall(ws_frame(struct.pack("<BI", ty, sid) + payload))

    def packet(self):
        """next Wisp packet (type, stream id, payload) from an unmasked server frame"""
        while True:
            if len(self.buf) >= 2:
                n, off = self.buf[1] & 0x7F, 2
                if n == 126:
                    n, off = struct.unpack(">H", self.buf[2:4])[0], 4
                elif n == 127:
                    n, off = struct.unpack(">Q", self.buf[2:10])[0], 10
                if len(self.buf) >= off + n:
                    p, self.buf = self.buf[off:off + n], self.buf[off + n:]
                    return p[0], struct.unpack("<I", p[1:5])[0], p[5:]
            d = self.s.recv(65536)
            if not d:
                raise EOFError
            self.buf += d

    def close_reason(self, sid):
        while True:
            ty, s, p = self.packet()
            if ty == 0x04 and s == sid:
                return p[0]


def connect(w, sid, port, host, stype=1):
    w.send(0x01, sid, struct.pack("<BH", stype, port) + host.encode())


servers = []  # every finalwisp this test starts: killed in main()'s finally, also when a check raises


def start(extra):
    p = subprocess.Popen([BIN, "--port", str(PORT), "--threads", "2", "--allow-loopback", "--log-level", "debug", *extra],
                         stderr=subprocess.PIPE, text=True)
    servers.append(p)
    return p


def nxdomain_server():
    """A local DNS server that answers every query NXDOMAIN at once (rcode 3: definitive, so the server's negative
    cache applies). The 0x42 checks use it through --dns-own --dns-server: independent of the host's resolver
    (the RC1 compat run once timed out here while the laptop's resolver stalled during a Wi-Fi drop, 60.33)."""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 0))

    def loop():
        while True:
            q, peer = u.recvfrom(4096)
            if len(q) < 12:
                continue
            end = 12
            while end < len(q) and q[end]:
                end += 1 + q[end]
            question = q[12:end + 5]  # QNAME + its 0 byte + QTYPE + QCLASS
            u.sendto(q[:2] + struct.pack(">HHHHH", 0x8183, 1, 0, 0, 0) + question, peer)  # QR RD RA, NXDOMAIN

    threading.Thread(target=loop, daemon=True).start()
    return u.getsockname()[1]


def lines_until(p, pred, timeout):
    got, end = [], time.time() + timeout
    while time.time() < end:
        l = p.stderr.readline()
        if not l:
            break
        got.append(l.rstrip("\n"))
        if pred(l):
            break
    return got


def kv(line):
    return dict(f.split("=", 1) for f in line.split()[1:] if "=" in f)


def main():
    tgt = echo_target()
    dns_port = nxdomain_server()
    closed_port = free_port()

    # 1 + 2: metrics on
    p = start(["--metrics-interval", "1", "--dns-own", "--dns-server", f"127.0.0.1:{dns_port}"])
    t0 = time.time()
    lines_until(p, lambda l: "capabilities" in l, 10)
    ws = [Wisp() for _ in range(3)]
    for w in ws:
        w.packet()  # the handshake CONTINUE (v1)
    a = ws[0]
    connect(a, 1, tgt, "127.0.0.1")
    a.send(0x02, 1, b"ping")
    ty, sid, data = a.packet()
    while ty != 0x02:
        ty, sid, data = a.packet()
    check("echo through a stream", data == b"ping", repr(data))
    a.send(0x04, 1, b"\x02")  # client close: the server sends no CLOSE for it
    connect(ws[1], 3, tgt, "127.0.0.1", stype=9)
    check("bad stream type -> CLOSE 0x41", ws[1].close_reason(3) == 0x41)
    connect(ws[1], 5, closed_port, "127.0.0.1")
    check("closed port -> CLOSE 0x44", ws[1].close_reason(5) == 0x44)
    connect(ws[2], 7, 80, "no-such-name.invalid")
    check("unresolvable name -> CLOSE 0x42", ws[2].close_reason(7) == 0x42)
    connect(ws[2], 9, 80, "no-such-name.invalid")
    check("same name again -> CLOSE 0x42 (negative cache)", ws[2].close_reason(9) == 0x42)
    # a line written after an idle sweep (2 s, publishes the streams gauge) that followed this test's events
    after = time.time() - t0 + 3
    got = lines_until(p, lambda l: "ev=metrics " in l and int(kv(l).get("up", 0)) >= after, after + 5)
    m = [l for l in got if "ev=metrics " in l]
    ups = [int(kv(l)["up"]) for l in m]
    check("a metrics line per interval", len(m) >= 3 and ups == sorted(ups) and ups[-1] - ups[0] <= len(m), f"up {ups}")
    last = kv(m[-1]) if m else {}
    print("   ", m[-1] if m else "(none)")
    want = {"keyupdate_closes": 0, "accepted": 3, "close_41": 1, "close_44": 1, "close_42": 2, "dns_fail": 1, "dns_neg_hit": 1, "dns_miss": 1,
            "streams": 0, "level": 0, "refuse_admit": 0, "shed_holder": 0, "dead_peers": 0}
    for k, v in want.items():
        check(f"{k}={v}", last.get(k) == str(v), f"got {last.get(k)}")
    check("connects >= 4", int(last.get("connects", 0)) >= 4, last.get("connects"))
    check("conns gauge = 3", last.get("conns") == "3", last.get("conns"))
    check("logfmt: every field key=value", all("=" in f for f in m[-1].split()[1:]) if m else False)
    check("no secret-looking keys", not any(s in m[-1].lower() for s in ("pass", "auth", "secret", "token", "cert")) if m else False)
    p.send_signal(signal.SIGTERM)
    fin = lines_until(p, lambda l: "ev=metrics_final" in l, 5)
    rc = p.wait(5)
    check("SIGTERM -> final line", any("ev=metrics_final" in l for l in fin), fin[-1] if fin else "")
    check("SIGTERM: graceful shutdown exits 0 (60.12 drain)", rc == 0, f"rc {rc}")
    for w in ws:
        w.s.close()

    # 3: metrics off (default)
    p = start([])
    lines_until(p, lambda l: "capabilities" in l, 10)
    time.sleep(1.5)
    threads = sorted(open(f"/proc/{p.pid}/task/{t}/comm").read().strip() for t in os.listdir(f"/proc/{p.pid}/task"))
    check("off: no metrics thread", "metrics" not in threads, ",".join(threads))
    p.send_signal(signal.SIGTERM)
    rc = p.wait(5)
    rest = p.stderr.read()
    check("off: no metrics line", "ev=metrics" not in rest)
    check("off: SIGTERM exits 0 as without metrics", rc == 0, f"rc {rc}")
    # 5: a stderr pipe that fills up and is never read: the metrics thread blocks in its write (holding the std stderr
    # lock); SIGTERM still ends the server at once (the final line is skipped)
    rfd, wfd = os.pipe()
    p = subprocess.Popen([BIN, "--port", str(PORT), "--threads", "2", "--metrics-interval", "1"], stderr=wfd)
    servers.append(p)
    time.sleep(1.0)  # startup lines written (they block on a full pipe, before and without this change)
    os.set_blocking(wfd, False)
    try:
        while True:
            os.write(wfd, b"x" * 4096)
    except BlockingIOError:
        pass
    os.set_blocking(wfd, True)  # review: the child's fd 2 shares these flags; its writes must block, not get EAGAIN
    time.sleep(2.5)  # the next metrics lines block (the metrics thread holds the std stderr lock)
    t1 = time.time()
    p.send_signal(signal.SIGTERM)
    try:
        rc = p.wait(5)
    except subprocess.TimeoutExpired:
        p.kill(); rc = p.wait(5)
    # (each shutdown log line and the final metrics line wait at most 500 ms: log_bounded)
    check("full stderr pipe: SIGTERM ends it within 3 s", rc == 0 and time.time() - t1 < 3, f"rc {rc}, {time.time() - t1:.2f} s")
    os.close(wfd); os.close(rfd)

    # 7: --drain-timeout 0: SIGTERM exits at once (another exit path of the signal loop), still with the final line
    p = start(["--metrics-interval", "1", "--drain-timeout", "0"])
    lines_until(p, lambda l: "capabilities" in l, 10)
    w = Wisp()
    p.send_signal(signal.SIGTERM)
    fin = lines_until(p, lambda l: "ev=metrics_final" in l, 5)
    rc = p.wait(5)
    check("--drain-timeout 0: 'exiting now', then the final line, exit 0",
          any("exiting now" in l for l in fin) and "ev=metrics_final" in fin[-1] and rc == 0, f"rc {rc}, {fin[-2:]}")
    w.s.close()

    # 4: a small budget starts at level 1 (mem::SMALL_BUDGET): accepted sockets are capped, time is at level 1
    p = start(["--metrics-interval", "1", "--mem-budget", "32M"])
    lines_until(p, lambda l: "capabilities" in l, 10)
    ws = [Wisp() for _ in range(2)]
    got = lines_until(p, lambda l: "ev=metrics " in l and int(kv(l).get("up", 0)) >= 2, 8)
    last = kv(got[-1]) if got else {}
    lv = [l for l in got if "memory level" in l]
    if lv:  # review: show why the level moved (host mode: other programs' TCP memory counts too)
        print("    level lines:", lv)
    # (host mode counts the host's TCP memory above its startup value: other programs' traffic can raise the level on a
    # busy laptop, so only the floor is checked: never level 0, the 2 accepted sockets capped at least once)
    check("small budget: never level 0, sockets capped",
          last.get("level") in ("1", "2", "3") and last.get("t_l0") == "0" and int(last.get("cap_apply", 0)) >= 2,
          got[-1] if got else "")
    p.send_signal(signal.SIGTERM)
    p.wait(5)
    for w in ws:
        w.s.close()


try:
    main()
finally:
    for s in servers:  # a check that raised leaves its server running: stop every one (they hold our stdout)
        if s.poll() is None:
            s.kill()
            s.wait(5)
print("FAILED: " + ", ".join(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
