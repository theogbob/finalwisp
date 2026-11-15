#!/usr/bin/env python3
"""80.02 explicit cases for observations that older tests made only by waiting (each waits ONCE per gate, here):
 A. late reset: after the last CLOSE of a download the server must leave the connection alone (no byte, no FIN, no
    reset), and the connection must still work. Two shapes with the sizes and the windows that adversarial.py had:
    case 8 (one stream, 32 MiB, 20 s) and case 15 (a 4 MiB bulk stream beside open echo streams, 10 s).
    adversarial.py saw this by a read that ran 20 s / 10 s into its timeout in each of its 9 runs; since 80.02 that
    read waits 0.5 s.
 B. long drain: SIGTERM while clients hold an open, idle stream; the server must stay up for the whole drain
    (--drain-timeout, default 30 s), then send 1001, exit 0, log the drain timeout, and its stderr must hold no
    panic. Two servers at once: defaults, and --dns-own (the stderr read of dns_own.py saw this by waiting for
    the 30 s drain of its servers, and stop() of upstream.py / fds.py / realip.py / uplimit.py by waiting 10 s).
usage: late.py FINALWISP_BINARY PORT   (ports PORT, PORT+1, PORT+2; targets on ephemeral ports; stdlib only)"""
import base64, os, shutil, signal, socket, struct, subprocess, sys, tempfile, threading, time

BIN, PORT = os.path.abspath(sys.argv[1]), int(sys.argv[2])
DRAIN = 30     # B: the server's default --drain-timeout
VERDICTS = 7   # the lines this script must print; fewer = a case died without a verdict = FAIL
fails = said = 0
_out = threading.Lock()
def ok(c, m):
    global fails, said
    with _out:
        print(("PASS " if c else "FAIL ") + m, flush=True)
        fails += 0 if c else 1
        said += 1

def listen():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0)); ls.listen(64)
    return ls, ls.getsockname()[1]

def echo_server():
    ls, port = listen()
    def pump(c):
        with c:
            try:
                while (d := c.recv(65536)): c.sendall(d)
            except OSError: pass
    def run():
        while True:
            c, _ = ls.accept(); threading.Thread(target=pump, args=(c,), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
    return port

def source_server(n):
    """sends n bytes to every client, then closes (the target's EOF = Wisp CLOSE reason 0x02)"""
    ls, port = listen()
    def feed(c):
        with c:
            try: c.sendall(bytes(range(256)) * (n // 256))
            except OSError: pass
    def run():
        while True:
            c, _ = ls.accept(); threading.Thread(target=feed, args=(c,), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
    return port

D = tempfile.mkdtemp(prefix="fw-late-")
def serve(port, *args):
    with open(f"{D}/srv{port}.log", "w") as log:
        p = subprocess.Popen([BIN, "--port", str(port), "--allow-loopback", "--threads", "2", *args], stdout=log, stderr=subprocess.STDOUT)
    p.logpath = log.name
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close(); return p
        except OSError:
            if p.poll() is not None: break
            time.sleep(0.05)
    raise SystemExit(f"late: server on {port} did not start: {open(f'{D}/srv{port}.log').read()}")
def srvlog(p):
    with open(p.logpath, errors="replace") as f:   # a handle of its own: the server's write offset is not touched
        return f.read()

def frame(op, payload):
    n = len(payload)
    hdr = bytes([0x80 | op, 0x80 | n]) if n < 126 else bytes([0x80 | op, 0xFE]) + struct.pack(">H", n)
    m = os.urandom(4)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))
UPGRADE = (b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           b"Sec-WebSocket-Key: " + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")

class Wisp:
    """a Wisp v1 client on a raw socket; frame() returns (opcode, payload) or ("eof", how)"""
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.s.sendall(UPGRADE); self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d: raise OSError("closed during the upgrade")
            self.buf += d
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        if not head.startswith(b"HTTP/1.1 101"): raise OSError(f"no 101: {head[:40]!r}")
    def frame(self, t):
        end = time.time() + t
        while True:
            b = self.buf
            if len(b) >= 2:
                n, hl = b[1] & 0x7f, 2
                if n == 126 and len(b) >= 4: n, hl = struct.unpack(">H", b[2:4])[0], 4
                elif n == 127 and len(b) >= 10: n, hl = struct.unpack(">Q", b[2:10])[0], 10
                elif n >= 126: n = None
                if n is not None and len(b) >= hl + n:
                    self.buf = b[hl + n:]
                    return b[0] & 0x0f, b[hl:hl + n]
            left = end - time.time()
            if left <= 0: return "eof", "timeout"
            self.s.settimeout(left)
            try: d = self.s.recv(65536)
            except socket.timeout: return "eof", "timeout"
            except ConnectionResetError: return "eof", "RST"
            if not d: return "eof", "FIN"
            self.buf += d
    def wisp(self, ty, sid, body): self.s.sendall(frame(2, struct.pack("<BI", ty, sid) + body))
    def connect(self, sid, port, host=b"127.0.0.1"): self.wisp(1, sid, struct.pack("<BH", 1, port) + host)
    def echo(self, sid, data, t=3.0):
        self.wisp(2, sid, data)
        end, got = time.time() + t, b""
        while time.time() < end and len(got) < len(data):
            op, p = self.frame(max(0.05, end - time.time()))
            if op == "eof": return False
            if op == 2 and p[0] == 2 and struct.unpack("<I", p[1:5])[0] == sid: got += p[5:]
        return got == data
    def download(self, sid, t=30.0):
        """(bytes of DATA on sid, CLOSE reason or None) until the CLOSE of sid"""
        end, got = time.time() + t, 0
        while time.time() < end:
            op, p = self.frame(max(0.05, end - time.time()))
            if op == "eof": return got, None
            if op == 2 and len(p) >= 5 and struct.unpack("<I", p[1:5])[0] == sid:
                if p[0] == 2: got += len(p) - 5
                elif p[0] == 4: return got, p[5]
        return got, None
    def close_code(self, t):
        """(the first WS close code the server sent or None, seconds until that frame, how the connection ended, seconds until then,
        frames other than that close)"""
        t0, code, at, other = time.time(), None, None, 0
        while True:
            op, p = self.frame(max(0.05, t - (time.time() - t0)))
            if op == "eof": return code, at, p, time.time() - t0, other
            if op == 8 and code is None: code, at = (struct.unpack(">H", p[:2])[0] if len(p) >= 2 else 0), time.time() - t0
            else: other += 1

ECHO = echo_server()

# ---------------------------------------------------------------- A: late reset
def case_a(name, echoes, size, quiet_s):
    try:
        src = source_server(size)
        w = Wisp(PORT)
        for sid in range(2, 2 + echoes): w.connect(sid, ECHO)
        pre = all(w.echo(sid, b"before%d" % sid) for sid in range(2, 2 + echoes))
        w.connect(1, src)
        got, reason = w.download(1, 60.0)
        t0 = time.time()
        op, how = w.frame(quiet_s)  # nothing may arrive: no frame, no FIN, no reset
        quiet = (op, how) == ("eof", "timeout") and not w.buf   # not one byte, also not a part of a frame
        dt = time.time() - t0
        after = False
        if quiet:
            w.connect(9, ECHO)
            after = w.echo(9, b"after") and all(w.echo(sid, b"again%d" % sid) for sid in range(2, 2 + echoes))
        w.s.close()
        ok(got == size and reason == 2 and pre and quiet and after,
           f"late reset ({name}): {quiet_s:.0f} s after the CLOSE of a {size >> 20} MiB download the connection is untouched and works "
           f"(got {got}, close {reason}, before={pre}, in the window: {op} {how} at {dt:.1f} s, {len(w.buf)} loose byte(s), after={after})")
    except Exception as e:   # every way out of a case is a verdict line
        ok(False, f"late reset ({name}): {e.__class__.__name__} {e}")

# ---------------------------------------------------------------- B: long drain with open idle streams
def case_b(name, port, *args):
    try:
        p = serve(port, *args)
        ws = [Wisp(port), Wisp(port)]
        for w in ws: w.connect(1, ECHO)
        live = all(w.echo(1, b"live") for w in ws)
        if "--dns-own" in args:  # the resolver has been used once before the drain (the answer is not judged)
            ws[0].connect(5, 80, b"late-drain.invalid"); ws[0].download(5, 3.0)
        t0 = time.time(); p.send_signal(signal.SIGTERM)
        res = [(None, None, "no result", 0.0, 0)] * 2
        def watch(i):
            try: res[i] = ws[i].close_code(DRAIN + 8)
            except Exception as e: res[i] = (None, None, f"{e.__class__.__name__} {e}", time.time() - t0, 0)
        th = [threading.Thread(target=watch, args=(i,)) for i in (0, 1)]
        for t in th: t.start()
        time.sleep(10); up10 = p.poll() is None   # what stop() of four tests saw: 10 s into a drain the server runs
        for t in th: t.join()
        try: rc = p.wait(8)
        except subprocess.TimeoutExpired: p.kill(); p.wait(); rc = None
        dt = time.time() - t0; log = srvlog(p)
        codes = [r[0] for r in res]; at = [r[1] for r in res]; ends = [r[2] for r in res]; eof = [r[3] for r in res]
        # the 1001 itself must come at the drain timeout (not before, with the connection held open), the end of the
        # connection after it; nothing else may arrive on the idle connections during the drain
        timed = all(x is not None and DRAIN - 2 <= x <= DRAIN + 5 for x in at) and all(DRAIN - 2 <= x <= DRAIN + 6 for x in eof)
        ok(live and up10 and codes == [1001, 1001] and timed and ends == ["FIN", "FIN"] and not any(r[4] for r in res) and rc == 0,
           f"long drain ({name}): 2 clients with an open idle stream: server up at 10 s ({up10}), 1001 at the drain timeout "
           f"({codes} at {' / '.join('none' if x is None else f'{x:.1f}' for x in at)} s, then {' / '.join(ends)} at {eof[0]:.1f} / {eof[1]:.1f} s, "
           f"other frames {[r[4] for r in res]}), exit rc={rc} at {dt:.1f} s")
        ok("drain timeout" in log and "panicked" not in log, f"long drain ({name}): log has the drain timeout and no panic")
        for w in ws: w.s.close()
    except (Exception, SystemExit) as e:   # every way out of a case is a verdict line
        ok(False, f"long drain ({name}): {e.__class__.__name__} {e}")

try:
    srv = serve(PORT)
    th = [threading.Thread(target=case_a, args=("one stream", 0, 32 << 20, 20.0)), threading.Thread(target=case_a, args=("bulk beside 3 echo streams", 3, 4 << 20, 10.0)),
          threading.Thread(target=case_b, args=("defaults", PORT + 1)), threading.Thread(target=case_b, args=("--dns-own", PORT + 2, "--dns-own"))]
    for t in th: t.start()
    for t in th: t.join()
    ok(srv.poll() is None and "panicked" not in srvlog(srv), "late reset: server alive at the end, no panic in its log")
    srv.kill(); srv.wait()
finally:
    shutil.rmtree(D, ignore_errors=True)
if said != VERDICTS:
    ok(False, f"late: {said} verdict lines, not {VERDICTS}: a case ended without one")
print("ALL PASS" if not fails else f"{fails} FAILURES"); sys.exit(1 if fails else 0)
