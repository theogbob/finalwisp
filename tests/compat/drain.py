#!/usr/bin/env python3
"""60.12 graceful shutdown (SIGTERM/SIGINT, --drain-timeout) against a real finalwisp. Stdlib + openssl CLI (for the
wss case). usage: drain.py FINALWISP_BINARY BASEPORT   (uses BASEPORT .. BASEPORT+9)
Cases: idle Wisp connection (v1, or v2 before its INFO) -> WS close 1001 at once; new connections refused; a live stream keeps working and the
server exits 0 when it ends; drain timeout -> 1001 to all, exit 0; second signal -> exit at once; no clients -> exit
at once (SIGINT); SIGINT ignored at startup stays ignored, SIGTERM drains; --drain-timeout 0; connections queued in the listen backlog (server stopped) are served (101,
then 1001), not reset; wss: 1001 + close_notify."""
import base64, os, signal, socket, ssl, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
ECHO = BASE + 9
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

def echo_server():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", ECHO)); ls.listen(64)
    def pump(c):
        with c:
            try:
                while (d := c.recv(65536)): c.sendall(d)
            except OSError: pass
    def run():
        while True:
            c, _ = ls.accept(); threading.Thread(target=pump, args=(c,), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
echo_server()

D = tempfile.mkdtemp(prefix="fw-drain-")
def serve(port, *args):
    log = open(f"{D}/srv{port}.log", "w+")
    p = subprocess.Popen([BIN, str(port), "--allow-loopback", "--threads", "2", *args], stdout=log, stderr=subprocess.STDOUT)
    p.logf = log
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close(); return p
        except OSError:
            if p.poll() is not None: break
            time.sleep(0.05)
    raise SystemExit(f"server on {port} did not start: {open(f'{D}/srv{port}.log').read()}")
def srvlog(p):
    p.logf.flush(); p.logf.seek(0); return p.logf.read()
def wait_exit(p, t):
    t0 = time.time()
    try:
        return p.wait(t), time.time() - t0
    except subprocess.TimeoutExpired:
        p.kill(); p.wait(); return None, time.time() - t0

def frame(op, payload):
    n = len(payload)
    hdr = bytes([0x80 | op, 0x80 | n]) if n < 126 else bytes([0x80 | op, 0xFE]) + struct.pack(">H", n)
    m = os.urandom(4)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))
UPGRADE = (b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           b"Sec-WebSocket-Key: " + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")

class Wisp:
    """Wisp v1 client. frames() yields (opcode, payload); `end` records how the connection ended."""
    def __init__(self, port, sock=None, tls=False):
        s = sock or socket.create_connection(("127.0.0.1", port), timeout=5)
        if tls:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
            s = c.wrap_socket(s, server_hostname="localhost", suppress_ragged_eofs=False)
        self.s, self.buf = s, b""
        if sock is None:
            self.upgrade()
    def upgrade(self):
        self.s.sendall(UPGRADE)
        return self.head()
    def head(self):
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d: raise EOFError("closed before the 101")
            self.buf += d
        h, self.buf = self.buf.split(b"\r\n\r\n", 1)
        self.status = h.split(b"\r\n", 1)[0].decode()
        return self.status
    def frame(self, t=5.0):
        """(opcode, payload), or ("eof", how) when the connection ends"""
        self.s.settimeout(t)
        while True:
            b = self.buf
            if len(b) >= 2:
                ln, hl = b[1] & 0x7F, 2
                if ln == 126 and len(b) >= 4: ln, hl = struct.unpack(">H", b[2:4])[0], 4
                if (ln < 126 or hl == 4) and len(b) >= hl + ln:
                    self.buf = b[hl + ln:]
                    return b[0] & 15, b[hl:hl + ln]
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                return "eof", "timeout"
            except ssl.SSLEOFError:
                return "eof", "no close_notify"
            except ConnectionResetError:
                return "eof", "RST"
            if not d: return "eof", "close_notify" if isinstance(self.s, ssl.SSLSocket) else "FIN"
            self.buf += d
    def close_code(self, t=5.0):
        """the WS close code the server sent (skipping Wisp frames) and how the connection then ended"""
        code = None
        while True:
            op, p = self.frame(t)
            if op == "eof": return code, p
            if op == 8: code = struct.unpack(">H", p[:2])[0] if len(p) >= 2 else 0
    def wisp(self, ty, sid, body): self.s.sendall(frame(2, struct.pack("<BI", ty, sid) + body))
    def connect(self, sid): self.wisp(1, sid, struct.pack("<BH", 1, ECHO) + b"127.0.0.1")
    def echo(self, sid, data, t=3.0):
        self.wisp(2, sid, data)
        end, got = time.time() + t, b""
        while time.time() < end and len(got) < len(data):
            op, p = self.frame(max(0.05, end - time.time()))
            if op == "eof": return False
            if op == 2 and p[0] == 2 and struct.unpack("<I", p[1:5])[0] == sid: got += p[5:]
        return got == data

def refused(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close(); return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False

# ---- 1: idle -> 1001 at once, new connections refused, live stream served, exit 0 when it ends
p = serve(BASE, "--drain-timeout", "10")
idle, live = Wisp(BASE), Wisp(BASE)
live.connect(1)
ok(live.echo(1, b"before"), "live stream echoes before the signal")
t0 = time.time(); p.send_signal(signal.SIGTERM)
code, how = idle.close_code(3)
ok(code == 1001 and how == "FIN" and time.time() - t0 < 1.0, f"idle connection: WS close {code} then {how} at {time.time() - t0:.2f} s")
time.sleep(0.3)
ok(refused(BASE), "new connection after SIGTERM: refused (listeners closed)")
ok(live.echo(1, b"during") and p.poll() is None, "live stream still echoes during the drain; server running")
time.sleep(1.0)
ok(live.echo(1, b"later") and p.poll() is None, "live stream echoes 1.3 s into the drain")
live.wisp(4, 1, b"\x02")  # CLOSE the stream: the connection becomes idle -> 1001 -> no connection left -> exit
code, how = live.close_code(3)
rc, dt = wait_exit(p, 3)
log = srvlog(p)
ok(code == 1001 and rc == 0 and dt < 1.0, f"stream closed -> 1001 ({code}, {how}); server exited rc={rc} {dt:.2f} s later")
ok("SIGTERM: shutting down" in log and "no connection left, exiting" in log, "log: shutdown start + drained")

# ---- 1b: a Wisp v2 client that has not answered the server's INFO yet (WaitInfo) has no stream: 1001 at once too
p = serve(BASE + 7, "--drain-timeout", "10")
s = socket.create_connection(("127.0.0.1", BASE + 7), timeout=5)
s.sendall(UPGRADE.replace(b"\r\n\r\n", b"\r\nSec-WebSocket-Protocol: wisp-v2\r\n\r\n"))
v2 = Wisp(BASE + 7, sock=s); v2.head()
t0 = time.time(); p.send_signal(signal.SIGTERM)
code, how = v2.close_code(3)
rc, _ = wait_exit(p, 3)
ok(code == 1001 and rc == 0 and time.time() - t0 < 1.0, f"v2 client before its INFO: WS close {code} ({how}), rc={rc}")

# ---- 2: drain timeout -> 1001 to the live one, exit 0
p = serve(BASE + 1, "--drain-timeout", "1")
live = Wisp(BASE + 1); live.connect(1); live.echo(1, b"x")
t0 = time.time(); p.send_signal(signal.SIGTERM)
code, how = live.close_code(4)
rc, _ = wait_exit(p, 4)
dt = time.time() - t0
ok(code == 1001 and rc == 0 and 0.9 <= dt < 3.5, f"drain timeout 1 s: live connection gets 1001 ({how}), rc={rc} at {dt:.2f} s")
ok("drain timeout" in srvlog(p), "log: drain timeout")

# ---- 3: second signal exits at once
p = serve(BASE + 2, "--drain-timeout", "30")
live = Wisp(BASE + 2); live.connect(1); live.echo(1, b"x")
p.send_signal(signal.SIGTERM); time.sleep(0.3)
t0 = time.time(); p.send_signal(signal.SIGTERM)
rc, dt = wait_exit(p, 3)
ok(rc == 0 and dt < 0.5 and "exiting now" in srvlog(p), f"second SIGTERM: exit rc={rc} in {dt:.2f} s")

# ---- 4: no clients, SIGINT: exit at once; --drain-timeout 0 with a live client: exit at once
p = serve(BASE + 3)
t0 = time.time(); p.send_signal(signal.SIGINT)
rc, dt = wait_exit(p, 3)
ok(rc == 0 and dt < 0.6 and "SIGINT: shutting down" in srvlog(p), f"SIGINT, no clients: exit rc={rc} in {dt:.2f} s")
p = serve(BASE + 4, "--drain-timeout", "0")
live = Wisp(BASE + 4); live.connect(1); live.echo(1, b"x")
p.send_signal(signal.SIGTERM)
rc, dt = wait_exit(p, 3)
ok(rc == 0 and dt < 0.5 and "exiting now" in srvlog(p), f"--drain-timeout 0: exit rc={rc} in {dt:.2f} s with a live client")

# ---- 4b: SIGINT ignored at startup (`cmd &` in a non-interactive shell, nohup-style): stays ignored; SIGTERM drains
log8 = open(f"{D}/srv{BASE + 8}.log", "w+")
p = subprocess.Popen([BIN, str(BASE + 8), "--allow-loopback", "--threads", "2"], stdout=log8, stderr=subprocess.STDOUT,
                     preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
p.logf = log8
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", BASE + 8), timeout=1).close(); break
    except OSError:
        time.sleep(0.05)
p.send_signal(signal.SIGINT); time.sleep(0.5)
alive = p.poll() is None
try:
    socket.create_connection(("127.0.0.1", BASE + 8), timeout=1).close(); serving = True
except OSError:
    serving = False
ok(alive and serving and "SIGINT" not in srvlog(p), f"inherited SIG_IGN: SIGINT ignored (alive {alive}, serving {serving})")
p.send_signal(signal.SIGTERM)
rc, dt = wait_exit(p, 3)
ok(rc == 0 and "SIGTERM: shutting down" in srvlog(p), f"inherited SIG_IGN for SIGINT: SIGTERM still drains, rc={rc}")

# ---- 5: connections queued in the listen backlog while the server is stopped: served (101), then 1001; none reset
p = serve(BASE + 5, "--drain-timeout", "10")
p.send_signal(signal.SIGSTOP); time.sleep(0.1)
queued = [socket.create_connection(("127.0.0.1", BASE + 5), timeout=5) for _ in range(8)]  # the kernel completes them
for s in queued: s.sendall(UPGRADE)
p.send_signal(signal.SIGTERM); p.send_signal(signal.SIGCONT)
res = []
for s in queued:
    w = Wisp(BASE + 5, sock=s)
    try:
        st = w.head()
    except (EOFError, OSError) as e:
        res.append((f"no 101: {e.__class__.__name__}", None, None)); continue
    res.append((st.split(" ")[1],) + w.close_code(3))
rc, dt = wait_exit(p, 3)
good = all(r == ("101", 1001, "FIN") for r in res)
ok(good and rc == 0, f"8 connections queued during SIGTERM: {sorted(set(res))}; rc={rc}")

# ---- 6: wss: idle connection gets 1001 and close_notify
cert, key = f"{D}/c.pem", f"{D}/k.pem"
if subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                   "-subj", "/CN=localhost", "-keyout", key, "-out", cert], capture_output=True).returncode == 0:
    try:
        p = serve(BASE + 6, "--tls-cert", cert, "--tls-key", key)
    except SystemExit as e:
        p = None; print(f"SKIP wss: {str(e)[:200]}")
    if p:
        w = Wisp(BASE + 6, tls=True)
        p.send_signal(signal.SIGTERM)
        code, how = w.close_code(3)
        rc, _ = wait_exit(p, 3)
        ok(code == 1001 and how == "close_notify" and rc == 0, f"wss idle: WS close {code}, then {how}; rc={rc}")
else:
    print("SKIP wss: openssl missing")
print(f"drain: {fails} failures")
sys.exit(1 if fails else 0)
