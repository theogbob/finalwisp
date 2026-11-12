# 70.09 --dns-own / --dns-server functional test: a fake DNS server (UDP + TCP, IPv4 + IPv6) behind real finalwisp
# servers, driven by Wisp CONNECTs to a local echo target. Stdlib only.
# usage: python3 dns_own.py BIN BASEPORT [preset]     (uses BASEPORT .. BASEPORT+9)
# `preset` (60.58, the compat step dns-preset): every server also gets --preset public, which sets dns-own and
# dns-reserve; the same cases must pass, and the last case shows the reserve.
# Cases: A, A SERVFAIL + AAAA ok, TC -> TCP, NXDOMAIN (+ negative cache), NODATA, SERVFAIL, timeout (deadline),
# garbage / wrong-ID / wrong-question packets, a reply from another source port, CNAME chain, FORMERR on EDNS,
# 70.10 RFC 8305 early family (one family never answered or late: connect on the other at ~50 ms; late family after the
# early address failed; connect deadline while the late family is due),
# a refused first server, an IPv6 nameserver, cancellation (a closed stream stops the retries).
# 60.18 #16 absolute names: a server under bwrap with a resolv.conf `search corp.internal` + `options ndots:5` asks
# only the client's name (never wiki.corp.internal), so --block-host wiki.corp.internal cannot be bypassed with "wiki".
import base64, os, socket, struct, subprocess, sys, threading, time

BIN, BASE = sys.argv[1], int(sys.argv[2])
PRESET = ["--preset", "public"] if sys.argv[3:4] == ["preset"] else []
P_A, P_B, P_C, P_D, BH, DNS, DEAD, P_E, ECHO6, ECHO = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5, BASE + 6, BASE + 7, BASE + 8, BASE + 9
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

def has_v6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.bind(("::1", 0)); s.close(); return True
    except OSError:
        return False
V6 = has_v6()

# ---- fake DNS
log = []  # (name, qtype, transport, edns)
lock = threading.Lock()
def qname(m, off=12):
    labels = []
    while m[off]:
        n = m[off]; labels.append(m[off + 1:off + 1 + n].decode().lower()); off += 1 + n
    return ".".join(labels), off + 1
def rr(owner, ty, data): return owner + struct.pack(">HHIH", ty, 1, 60, len(data)) + data
def name(s): return b"".join(bytes([len(l)]) + l.encode() for l in s.split(".")) + b"\0"
def reply(q, rcode=0, tc=False, ans=(), qid=None, question=None):
    _, end = qname(q)
    hdr = struct.pack(">HHHHHH", struct.unpack(">H", q[:2])[0] if qid is None else qid, 0x8180 | rcode | (0x200 if tc else 0), 1, len(ans), 0, 0)
    return hdr + (question if question is not None else q[12:end + 4]) + b"".join(ans)
P = b"\xc0\x0c"
LOOP4 = socket.inet_aton("127.0.0.1")
LOOP6 = socket.inet_pton(socket.AF_INET6, "::1")

def answer(q, tcp):
    """-> list of (datagram, via_other_socket)"""
    n, end = qname(q)
    qt = struct.unpack(">H", q[end:end + 2])[0]
    edns = struct.unpack(">H", q[10:12])[0] > 0
    with lock:
        log.append((n, qt, "tcp" if tcp else "udp", edns))
    a = qt == 1
    good = reply(q, ans=[rr(P, 1, LOOP4)] if a else [])
    if n in ("ok.test", "okb.test", "wiki.corp.internal"): return [(good, False)]
    if n.startswith("dead"): return []  # 60.58 names that never answer (the reserve case)
    if n == "afail.test": return [(reply(q, 2) if a else reply(q, ans=[rr(P, 28, LOOP6)]), False)]
    if n == "tc.test": return [(reply(q, tc=True) if not tcp else good, False)]
    if n == "servfail.test": return [(reply(q, 2), False)]
    if n == "nodata.test": return [(reply(q), False)]
    if n in ("slow.test", "hang.test"): return []
    if n == "v4only.test": return [(good, False)] if a else []  # like dnsmasq for a local v4-only name: AAAA never answered
    six = reply(q, ans=[rr(P, 28, LOOP6)] if not a else [])
    if n == "v6only.test": return [] if a else [(six, False)]  # 70.10 A never answered
    if n in ("late6.test", "late6b.test"): return [(good, False)] if a else [(six, "late")]  # 70.10 AAAA 300 ms after A
    if n == "blackhole.test": return [(good, False)] if a else []  # 70.10 A -> 127.0.0.1 (port BH: SYNs dropped)
    if n == "garbage.test":
        wrong_q = name("other.test") + q[end:end + 4]
        return [(b"\xff\xfe\x00garbage", False), (reply(q, ans=[rr(P, 1, b"\x0a\x06\x06\x06")] if a else [], qid=(struct.unpack(">H", q[:2])[0] ^ 0x5555)), False),
                (reply(q, ans=[rr(b"\xc0\x0c", 1, b"\x0a\x06\x06\x06")] if a else [], question=wrong_q), False), (good, False)]
    if n == "spoof.test":  # a well-formed reply with the right ID, but from another port: must be ignored
        return [(reply(q, ans=[rr(P, 1, b"\x0a\x06\x06\x06")] if a else []), True), (good, False)]
    if n == "cname.test":
        c1, c2 = name("c1.test"), name("c2.test")
        return [(reply(q, ans=[rr(P, 5, c1), rr(c1, 5, c2)] + ([rr(c2, 1, LOOP4)] if a else [])), False)]
    if n == "formerr.test":
        return [(reply(q, 1) if edns else good, False)]
    return [(reply(q, 3), False)]  # NXDOMAIN

def udp_server(fam, host):
    u = socket.socket(fam, socket.SOCK_DGRAM); u.bind((host, DNS))
    other = socket.socket(fam, socket.SOCK_DGRAM); other.bind((host, 0))
    def run():
        while True:
            q, frm = u.recvfrom(4096)
            for d, alt in answer(q, False):
                if alt == "late":
                    threading.Timer(0.3, u.sendto, (d, frm)).start()
                else:
                    (other if alt else u).sendto(d, frm)
    threading.Thread(target=run, daemon=True).start()
def tcp_server(fam, host):
    t = socket.socket(fam, socket.SOCK_STREAM); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind((host, DNS)); t.listen(16)
    def conn(c):
        with c:
            l = c.recv(2, socket.MSG_WAITALL)
            q = c.recv(struct.unpack(">H", l)[0], socket.MSG_WAITALL)
            for d, _ in answer(q, True):
                c.sendall(struct.pack(">H", len(d)) + d)
    def run():
        while True:
            c, _ = t.accept()
            threading.Thread(target=conn, args=(c,), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
udp_server(socket.AF_INET, "127.0.0.1"); tcp_server(socket.AF_INET, "127.0.0.1")
if V6:
    udp_server(socket.AF_INET6, "::1")

# ---- echo target (both families)
accepts = {}  # (host, port) -> connections accepted
def echo(fam, host, port=ECHO):
    ls = socket.socket(fam, socket.SOCK_STREAM); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, port)); ls.listen(64)
    def pump(c):
        with c:
            try:
                while (d := c.recv(65536)): c.sendall(d)
            except OSError: pass
    def run():
        while True:
            c, _ = ls.accept(); threading.Thread(target=pump, args=(c,), daemon=True).start()
            with lock: accepts[(host, port)] = accepts.get((host, port), 0) + 1
    threading.Thread(target=run, daemon=True).start()
echo(socket.AF_INET, "127.0.0.1")
if V6:
    echo(socket.AF_INET6, "::1")
    echo(socket.AF_INET6, "::1", ECHO6)  # 70.10 nothing listens on 127.0.0.1:ECHO6

# ---- servers
procs, errs = [], {}
def serve(port, *args):
    p = subprocess.Popen([BIN, str(port), *PRESET, "--allow-loopback", "--threads", "2", "--log-level", "debug", *args], stderr=subprocess.PIPE, text=True)
    procs.append(p); errs[port] = p
serve(P_A, "--dns-server", f"127.0.0.1:{DNS}")
serve(P_B, "--dns-server", f"127.0.0.1:{DEAD}", "--dns-server", f"127.0.0.1:{DNS}")
if V6:
    serve(P_C, "--dns-own", "--dns-server", f"[::1]:{DNS}")
serve(P_D, "--dns-server", f"127.0.0.1:{DNS}", "--connect-timeout", "1")
# 60.18 #16: its own /etc/resolv.conf (bwrap bind mount; servers from --dns-server, search + ndots from the file)
import shutil, tempfile
BWRAP = shutil.which("bwrap")
if BWRAP:
    rc = tempfile.NamedTemporaryFile("w", prefix="fw-resolv-", suffix=".conf", delete=False)
    rc.write("nameserver 127.0.0.1\nsearch corp.internal\noptions ndots:5\n"); rc.close()
    p = subprocess.Popen([BWRAP, "--die-with-parent", "--dev-bind", "/", "/", "--ro-bind", rc.name, "/etc/resolv.conf", BIN, str(P_E), *PRESET,
                          "--allow-loopback", "--threads", "2", "--log-level", "debug", "--dns-own", "--dns-server", f"127.0.0.1:{DNS}",
                          "--block-host", "wiki.corp.internal"], stderr=subprocess.PIPE, text=True, start_new_session=True)
    p.group = True  # terminate the whole group: a SIGTERM to bwrap alone leaves finalwisp running
    procs.append(p); errs[P_E] = p
time.sleep(0.5)
for p in procs:
    if p.poll() is not None:
        print("server failed to start:", p.stderr.read()); sys.exit(1)

# ---- Wisp v1 client
def frame(op, payload):
    n = len(payload)
    hdr = bytes([0x80 | op, 0x80 | n]) if n < 126 else bytes([0x80 | op, 0xFE]) + struct.pack(">H", n)
    m = os.urandom(4)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))
class Wisp:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=3)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.s.recv(4096)
        self.buf = bytearray(buf.partition(b"\r\n\r\n")[2])
    def send(self, ty, sid, body): self.s.sendall(frame(2, struct.pack("<BI", ty, sid) + body))
    def packet(self, t):
        end = time.time() + t
        while True:
            b = self.buf
            if len(b) >= 2:
                ln, hl = b[1] & 0x7F, 2
                if ln == 126 and len(b) >= 4: ln, hl = struct.unpack(">H", b[2:4])[0], 4
                if ln < 126 or hl == 4:
                    if len(b) >= hl + ln:
                        p = bytes(b[hl:hl + ln]); del b[:hl + ln]
                        return (p[0], struct.unpack("<I", p[1:5])[0], p[5:])
            left = end - time.time()
            if left <= 0: return None
            self.s.settimeout(left)
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                return None
            if not d: return None
            self.buf += d
    def attempt(self, sid, host, t=8.0, port=ECHO):
        """CONNECT + DATA b'ping': ('data', bytes) | ('close', reason) | None; and the seconds it took."""
        t0 = time.time()
        self.send(1, sid, struct.pack("<BH", 1, port) + host.encode())
        self.send(2, sid, b"ping")
        while (p := self.packet(max(0.01, t0 + t - time.time()))) is not None:
            if p[1] != sid: continue
            if p[0] == 2: return ("data", p[2]), time.time() - t0
            if p[0] == 4: return ("close", p[2][0]), time.time() - t0
        return None, time.time() - t0

def count(n):
    with lock:
        return sum(1 for x in log if x[0] == n)

w = Wisp(P_A)
sid = [0]
def go(host, t=8.0, wsock=None, port=ECHO):
    sid[0] += 1
    return (wsock or w).attempt(sid[0], host, t, port)

r, dt = go("ok.test.")
ok(r == ("data", b"ping"), f"A record: connected and echoed ({r}, {dt*1000:.0f} ms)")
if V6:
    r, dt = go("afail.test.")
    ok(r == ("data", b"ping"), f"A SERVFAIL + AAAA ::1: the AAAA answer is used ({r})")
r, dt = go("tc.test.")
tcp = [x for x in log if x[0] == "tc.test" and x[2] == "tcp"]
ok(r == ("data", b"ping") and len(tcp) >= 1, f"TC=1 over UDP -> retried over TCP ({r}, {len(tcp)} TCP queries)")
r, dt = go("nx.test.")
c1 = count("nx.test")
r2, _ = go("nx.test.")
ok(r == ("close", 0x42) and r2 == ("close", 0x42) and count("nx.test") == c1 == 2,
   f"NXDOMAIN: CLOSE 0x42 ({r}, {dt*1000:.0f} ms); the repeat is answered from the negative cache ({count('nx.test')} queries)")
r, dt = go("nodata.test.")
c1 = count("nodata.test")
r2, _ = go("nodata.test.")
ok(r == ("close", 0x42) and r2 == ("close", 0x42) and count("nodata.test") == c1, f"NODATA in both families: definitive, cached ({r})")
r, dt = go("servfail.test.")
c1 = count("servfail.test")
r2, _ = go("servfail.test.")
ok(r == ("close", 0x42) and dt < 1.0 and count("servfail.test") > c1, f"SERVFAIL: CLOSE 0x42 at once ({dt*1000:.0f} ms), not cached (asked again)")
r, dt = go("garbage.test.")
ok(r == ("data", b"ping"), f"garbage, wrong ID and wrong question ignored, then the real reply ({r})")
r, dt = go("spoof.test.")
ok(r == ("data", b"ping"), f"a reply from another source port is ignored ({r}; accepting it would give 10.6.6.6)")
r, dt = go("cname.test.")
ok(r == ("data", b"ping"), f"CNAME chain cname -> c1 -> c2 -> A ({r})")
r, dt = go("formerr.test.")
fe = [x[3] for x in log if x[0] == "formerr.test" and x[1] == 1]
ok(r == ("data", b"ping") and fe[:2] == [True, False], f"FORMERR on EDNS -> resent without EDNS ({r}, edns per A query {fe})")
# 70.10 RFC 8305 s3: a family that is never answered no longer holds the connect until the deadline (was 4 s, 70.09)
r, dt = go("v4only.test.", t=10)
ok(r == ("data", b"ping") and dt < 0.5, f"AAAA never answered -> connects via A after the 50 ms resolution delay ({dt*1000:.0f} ms)")
if V6:
    r, dt = go("v6only.test.", t=10)
    ok(r == ("data", b"ping") and dt < 0.5, f"A never answered -> connects via AAAA ::1 at once ({dt*1000:.0f} ms)")
    with lock: n4 = accepts.get(("127.0.0.1", ECHO), 0); n6 = accepts.get(("::1", ECHO), 0)
    r, dt = go("late6.test.", t=10)
    time.sleep(0.6)  # the late AAAA (300 ms) must not start a second connection
    with lock: d4 = accepts.get(("127.0.0.1", ECHO), 0) - n4; d6 = accepts.get(("::1", ECHO), 0) - n6
    ok(r == ("data", b"ping") and dt < 0.25 and (d4, d6) == (1, 0),
       f"AAAA 300 ms late: connected via A at {dt*1000:.0f} ms, one connection (v4 +{d4}, v6 +{d6})")
    # the early address refuses (nothing on 127.0.0.1:ECHO6): the stream waits for the late AAAA and connects via ::1
    r, dt = go("late6b.test.", t=10, port=ECHO6)
    ok(r == ("data", b"ping") and 0.25 <= dt < 1.5, f"A refused, AAAA 300 ms late: connected via ::1 at {dt*1000:.0f} ms")
# the early address times out (--connect-timeout 1) while the other family is due: CLOSE 0x43 once the lookup ends
# at its deadline (4 s), not 0x42 and not a stall. Local blackhole: a listener with backlog 0 whose accept queue is
# full (one connection never accepted) drops every further SYN (192.0.2.1 is not one everywhere: proxies answer it).
bh = socket.socket(); bh.bind(("127.0.0.1", BH)); bh.listen(0)
bh_fill = socket.create_connection(("127.0.0.1", BH))
# The lookup deadline = window x tries from /etc/resolv.conf options (--dns-server keeps them; 70.09: window = timeout
# clamped to 1..2 s, tries = min(1 server x attempts, 3)); unparked, the close would come at the 1 s connect timeout.
def resolv_opt(k, d):
    try:
        for l in open("/etc/resolv.conf"):
            if l.split()[:1] == ["options"]:
                for o in l.split()[1:]:
                    if o.startswith(k + ":"): d = int(o.split(":")[1])
    except (OSError, ValueError): pass
    return d
LOOKUP_DEADLINE = min(max(resolv_opt("timeout", 5), 1), 2) * min(max(resolv_opt("attempts", 2), 1), 3)
wd = Wisp(P_D)
r, dt = go("blackhole.test.", t=10, wsock=wd, port=BH)
ok(r == ("close", 0x43) and LOOKUP_DEADLINE - 0.3 <= dt <= LOOKUP_DEADLINE + 1.5,
   f"early address timed out, AAAA never answered: {r} at {dt:.1f} s (lookup deadline {LOOKUP_DEADLINE} s"
   + ("; equals the connect timeout here, so parking is not visible" if LOOKUP_DEADLINE <= 1 else "") + ")")

# timeout: resolv.conf window (timeout clamped to 1..2 s) x tries (1 server x attempts, at most 3)
r, dt = go("slow.test.", t=10)
q = count("slow.test")
ok(r == ("close", 0x42) and 0.9 <= dt <= 6.5 and q % 2 == 0, f"dead name: CLOSE 0x42 after the deadline ({dt:.1f} s, {q} queries)")
# cancellation: close the stream while the lookup waits; no retry after the first window
w2 = Wisp(P_A)
w2.send(1, 1, struct.pack("<BH", 1, ECHO) + b"hang.test.")
time.sleep(0.3)
w2.send(4, 1, b"\x02")
time.sleep(4.5)
ok(count("hang.test") == 2, f"cancelled lookup: no retry after the close ({count('hang.test')} queries, 2 = first try only)")
w2.s.close()
# a refused first server: every family moves to the second at once
wb = Wisp(P_B)
r, dt = go("ok.test.", wsock=wb)
ok(r == ("data", b"ping") and dt < 0.5, f"first server refused (ICMP): second server answers ({dt*1000:.0f} ms)")
if V6:
    wc = Wisp(P_C)
    n0 = len(log)
    r, dt = go("cname.test.", wsock=wc)
    ok(r == ("data", b"ping") and len(log) > n0, f"IPv6 nameserver [::1]:{DNS} ({r})")
else:
    print("SKIP no ::1 (IPv6 cases)")
# 60.18 #16 absolute names (the search list and ndots of the server's resolv.conf are never used)
r, dt = go("wiki.corp.internal.")
ok(r == ("data", b"ping"), f"control: wiki.corp.internal resolves and connects on a server without the rule ({r})")
if BWRAP:
    we = Wisp(P_E)
    n0 = len(log)
    r1, _ = go("wiki", wsock=we)
    r2, _ = go("wiki.", wsock=we)
    r3, _ = go("wiki.corp.internal", wsock=we)
    r4, _ = go("example.com", wsock=we)
    with lock: asked = sorted({x[0] for x in log[n0:]})
    ok(r1 == ("close", 0x42) and r2 == ("close", 0x42), f"'wiki' / 'wiki.' asked as absolute names: NXDOMAIN 0x42, not wiki.corp.internal ({r1}, {r2})")
    ok(r3 == ("close", 0x48), f"--block-host wiki.corp.internal still refuses the full name ({r3})")
    ok(r4 == ("close", 0x42) and asked == ["example.com", "wiki"], f"names asked: {asked} (no search-list completion, ndots:5 ignored)")
else:
    print("SKIP no bwrap (absolute-name cases need a private /etc/resolv.conf)")
# 60.58 --dns-reserve (in the preset). Connection A asks for a name that never answers; after 1 s A is slow. Then A
# asks for 16 more: with the reserve the slow connection gets 12 of the 16 threads, and a new name of connection B
# starts at once. Without it (plain --dns-own: arrival order) A's 17 names hold every thread until the first gives up
# (4 s after its start), and B's name waits for that.
wa, wb2 = Wisp(P_A), Wisp(P_A)
wa.send(1, 1, struct.pack("<BH", 1, ECHO) + b"dead0.test.")
time.sleep(1.3)
for i in range(1, 17):
    wa.send(1, 1 + i, struct.pack("<BH", 1, ECHO) + f"dead{i}.test.".encode())
time.sleep(0.2)
r, dt = wb2.attempt(1, "okb.test.", t=9)
if PRESET:
    ok(r == ("data", b"ping") and dt < 1.0, f"preset (dns-reserve): another connection's name starts at once while a slow one holds its threads ({r}, {dt*1000:.0f} ms)")
else:
    ok(r == ("data", b"ping") and dt > 1.5, f"no reserve: another connection's name waits for a thread ({r}, {dt*1000:.0f} ms)")
wa.s.close(); wb2.s.close()
for p in procs:
    if getattr(p, "group", False):
        os.killpg(p.pid, 15)
    else:
        p.terminate()
for port, p in errs.items():
    err = p.stderr.read()
    ok("DNS own resolver" in err, f"server :{port} capability line names the own resolver")
    if PRESET:
        ok("DNS share (reserve: 4 of 16 threads)" in err, f"server :{port} capability line names the reserve of the preset")
    ok("panicked" not in err, f"server :{port} stderr has no panic")
print(f"dns_own: {fails} failures")
sys.exit(1 if fails else 0)
