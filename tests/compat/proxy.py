#!/usr/bin/env python3
"""40.02 reverse-proxy compat (60.12): finalwisp (ws://, 127.0.0.1) behind nginx and Caddy (TLS at the proxy), with the
configurations of docs/summaries/40.01-deployment.md, in docker (--network host). Per proxy: the real wisp-js client
(wispjs.mjs over wss://, incl. a 2x64 MiB download), a 32 MiB upload to a target that stops reading for 6 s (the client must
run out of credit: backpressure through the proxy; every byte must arrive in order: digest), and a connection idle for 125 s (longer than finalwisp's 120 s keepalive
idle) that must still work. The same checks run direct (no proxy) as the reference.
usage: proxy.py FINALWISP_BINARY BASEPORT   (BASEPORT .. BASEPORT+9). Needs docker + images nginx:1.27-alpine,
caddy:2.8-alpine (pulled if missing), node + tests/compat/node_modules. Exit 77 = SKIP (any of them missing)."""
import base64, hashlib, os, signal, shutil, socket, ssl, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
FW, NGINX, CADDY, SINK, ECHO = BASE, BASE + 1, BASE + 2, BASE + 8, BASE + 9
HERE = os.path.dirname(os.path.abspath(__file__))
IDLE = float(os.environ.get("PROXY_IDLE", "125"))
IMAGES = {"nginx": "nginx:1.27-alpine", "caddy": "caddy:2.8-alpine"}
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1
def run(cmd, t=120):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=t)
    return p.returncode, p.stdout + p.stderr

if not shutil.which("docker") or run(["docker", "info"], 30)[0] != 0:
    print("SKIP proxy: docker not usable"); sys.exit(77)
NODE = shutil.which("node")
if not NODE or not os.path.isdir(os.path.join(HERE, "node_modules")):
    print("SKIP proxy: node or tests/compat/node_modules missing"); sys.exit(77)
for img in IMAGES.values():
    if run(["docker", "image", "inspect", img], 30)[0] != 0 and run(["docker", "pull", "-q", img], 600)[0] != 0:
        print(f"SKIP proxy: cannot pull {img}"); sys.exit(77)

# ---- targets: echo, and a sink that stops reading for 6 s after 4 MiB, then answers "OK <bytes>" after N bytes
def listener(port, handler):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", port)); ls.listen(64)
    def loop():
        while True:
            c, _ = ls.accept(); threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
def echo(c):
    with c:
        try:
            while (d := c.recv(65536)): c.sendall(d)
        except OSError: pass
UP = 32 << 20
def sink(c):
    with c:
        n, paused, h = 0, False, hashlib.sha256()
        try:
            while n < UP:
                d = c.recv(min(1 << 20, UP - n))
                if not d: return
                n += len(d); h.update(d)
                if n >= 4 << 20 and not paused:
                    paused = True; time.sleep(6)
            c.sendall(f"OK {n} {h.hexdigest()[:16]}".encode())
            c.recv(1)
        except OSError: pass
listener(ECHO, echo); listener(SINK, sink)

# ---- finalwisp + proxies
D = tempfile.mkdtemp(prefix="fw-proxy-")
os.chmod(D, 0o755)
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                "-subj", "/CN=localhost", "-keyout", f"{D}/key.pem", "-out", f"{D}/cert.pem"], check=True, capture_output=True)
for f in ("key.pem", "cert.pem"): os.chmod(f"{D}/{f}", 0o644)
log = open(f"{D}/fw.log", "w")
srv = None
names = {"nginx": f"fw-proxy-nginx-{BASE}", "caddy": f"fw-proxy-caddy-{BASE}"}
def cleanup():
    for name in names.values():
        run(["docker", "rm", "-f", name], 30)
    if srv is not None and srv.poll() is None:
        srv.terminate()
        try: srv.wait(5)
        except subprocess.TimeoutExpired: srv.kill(); srv.wait(5)
def on_term(sig, _frame): raise SystemExit(f"FAIL proxy: signal {sig}")
signal.signal(signal.SIGTERM, on_term)
open(f"{D}/nginx.conf", "w").write(f"""map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
server {{
    listen 127.0.0.1:{NGINX} ssl;
    ssl_certificate     /certs/cert.pem;
    ssl_certificate_key /certs/key.pem;
    location / {{
        proxy_pass http://127.0.0.1:{FW};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }}
}}
""")
open(f"{D}/Caddyfile", "w").write(f"""{{
    admin off
    auto_https off
}}
:{CADDY} {{
    bind 127.0.0.1
    tls /certs/cert.pem /certs/key.pem
    reverse_proxy 127.0.0.1:{FW} {{
        stream_close_delay 5m
    }}
}}
""")
mounts = {"nginx": ["-v", f"{D}/nginx.conf:/etc/nginx/conf.d/default.conf:ro"], "caddy": ["-v", f"{D}/Caddyfile:/etc/caddy/Caddyfile:ro"]}
try:
    srv = subprocess.Popen([BIN, str(FW), "--allow-loopback", "--threads", "2", "--drain-timeout", "0"], stdout=log, stderr=subprocess.STDOUT)
    for k, name in names.items():
        run(["docker", "rm", "-f", name], 30)
        rc, o = run(["docker", "run", "-d", "--rm", "--network", "host", "--name", name, "-v", f"{D}:/certs:ro", *mounts[k], IMAGES[k]], 120)
        if rc: print(f"FAIL {k}: docker run: {o.strip()[:300]}"); fails += 1
    def up(port, tls):
        for _ in range(100):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=1)
                if tls: ssl._create_unverified_context().wrap_socket(s, server_hostname="localhost").close()
                else: s.close()
                return True
            except OSError:
                time.sleep(0.1)
        return False
    for port, tls, what in ((FW, False, "finalwisp"), (NGINX, True, "nginx"), (CADDY, True, "caddy")):
        if not up(port, tls):
            logs = run(["docker", "logs", names.get(what, "x")], 30)[1][-600:] if what in names else open(f"{D}/fw.log").read()
            raise SystemExit(f"FAIL {what} did not come up on :{port}: {logs}")
    PATHS = [("direct", FW, False), ("nginx", NGINX, True), ("caddy", CADDY, True)]

    def frame(op, p):
        n, m = len(p), os.urandom(4)
        hdr = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0xFE]) + struct.pack(">H", n) if n < 65536
                                   else bytes([0xFF]) + struct.pack(">Q", n))
        return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(p)) if n < 4096 else hdr + m + mask(p, m)
    def mask(p, m):
        k = int.from_bytes(m * (len(p) // 4 + 1), "little")
        return (int.from_bytes(p, "little") ^ (k & ((1 << (8 * len(p))) - 1))).to_bytes(len(p), "little")
    class W:
        def __init__(self, port, tls):
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            if tls: s = ssl._create_unverified_context().wrap_socket(s, server_hostname="localhost")
            self.s, self.b, self.credit = s, b"", {}
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
                      + base64.b64encode(os.urandom(16)) + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
            while b"\r\n\r\n" not in self.b:
                d = s.recv(4096)
                if not d: raise EOFError("no 101")
                self.b += d
            head, self.b = self.b.split(b"\r\n\r\n", 1)
            self.status = head.split(b"\r\n", 1)[0].decode()
            if " 101 " not in self.status + " ": raise EOFError(f"handshake: {self.status!r}")
        def packet(self, t=10):
            """next Wisp packet (type, sid, body); None on EOF/timeout; WS Close -> ("close", code)"""
            self.s.settimeout(t)
            while True:
                b = self.b
                if len(b) >= 2:
                    ln, h = b[1] & 127, 2
                    if ln == 126 and len(b) >= 4: ln, h = struct.unpack(">H", b[2:4])[0], 4
                    elif ln == 127 and len(b) >= 10: ln, h = struct.unpack(">Q", b[2:10])[0], 10
                    if ln < 126 or h > 2:
                        if len(b) >= h + ln:
                            op, p = b[0] & 15, b[h:h + ln]; self.b = b[h + ln:]
                            if op == 8: return ("close", struct.unpack(">H", p[:2])[0] if len(p) >= 2 else 0, b"")
                            if op == 2 and len(p) >= 5:
                                ty, sid = p[0], struct.unpack("<I", p[1:5])[0]
                                if ty == 3: self.credit[sid] = struct.unpack("<I", p[5:9])[0]
                                return (ty, sid, p[5:])
                            continue
                try: d = self.s.recv(1 << 20)
                except (socket.timeout, OSError): return None
                if not d: return None
                self.b += d
        def send(self, ty, sid, body):
            self.s.settimeout(30)  # packet(0) leaves the socket non-blocking
            self.s.sendall(frame(2, struct.pack("<BI", ty, sid) + body))
        def connect(self, sid, port):
            self.send(1, sid, struct.pack("<BH", 1, port) + b"127.0.0.1")
            return True  # v1: no confirmation; a failure arrives as CLOSE
        def echo(self, sid, data):
            self.send(2, sid, data); got = b""
            while len(got) < len(data):
                p = self.packet()
                if p is None or p[0] in ("close", 4): return False
                if p[0] == 2 and p[1] == sid: got += p[2]
            return got == data

    def upload(port, tls):
        """32 MiB in 16 KiB DATA packets within the server's credit (v1: CONTINUE on stream 0 = the initial credit of
        every stream, then CONTINUE on the stream = packets it may send from then on); the sink stalls 6 s at 4 MiB and
        answers "OK <bytes> <sha256>"; each chunk starts with its index (loss, reorder, duplication change the digest).
        Returns ("ok", answer, expected answer, longest credit wait s, secs) or an error string."""
        w = W(port, tls)
        sent, used, base, h, answer, longest = 0, 0, os.urandom(16 << 10), hashlib.sha256(), b"", 0.0
        while 0 not in w.credit:
            p = w.packet(10)
            if p is None or p[0] == "close": return f"no initial CONTINUE: {p}"
        allowed = w.credit[0]
        w.connect(1, SINK)
        t0 = time.time()
        def take(p):
            nonlocal used, allowed, answer
            if p and p[0] == 3 and p[1] == 1: used, allowed = 0, w.credit[1]
            if p and p[0] == 2 and p[1] == 1: answer += p[2]
            return p is not None and p[0] in ("close", 4)
        i = 0
        while sent < UP:
            t1 = time.time()
            while used >= allowed:
                p = w.packet(30)
                if p is None or take(p): return f"stopped at {sent >> 20} MiB: {p}"
            longest = max(longest, time.time() - t1)
            chunk = struct.pack("<Q", i) + base[8:]; i += 1; h.update(chunk)
            w.send(2, 1, chunk); sent += len(chunk); used += 1
            while (p := w.packet(0)) is not None:  # CONTINUEs already here (non-blocking)
                if take(p): return f"closed at {sent >> 20} MiB: {p}"
        want = f"OK {UP} {h.hexdigest()[:16]}"
        while len(answer) < len(want):
            p = w.packet(30)
            if p is None or take(p): return f"no answer: {p} after {answer!r}"
        return ("ok", answer.decode(), want, round(longest, 1), round(time.time() - t0, 1))

    # 1: wisp-js through each path
    for what, port, tls in PATHS:
        url = f"{'wss' if tls else 'ws'}://127.0.0.1:{port}/"
        env = dict(os.environ, NODE_TLS_REJECT_UNAUTHORIZED="0", NODE_NO_WARNINGS="1")
        try:
            p = subprocess.run([NODE, "wispjs.mjs", url], cwd=HERE, capture_output=True, text=True, timeout=300, env=env)
            rc, bad = p.returncode, [l for l in p.stdout.splitlines() if l.startswith("FAIL")]
        except subprocess.TimeoutExpired:
            rc, bad = "timeout 300 s", []
        ok(rc == 0 and not bad, f"{what}: wisp-js client (v1 + v2, 2x64 MiB download) rc={rc} {bad[:3]}")
    # 2: upload with a stalling target
    for what, port, tls in PATHS:
        try: r = upload(port, tls)
        except Exception as e: r = f"{e.__class__.__name__} {e}"
        # the stall must reach the client as backpressure (no credit for >= 2 s), and every byte must arrive in order
        ok(isinstance(r, tuple) and r[1] == r[2] and r[3] >= 2,
           f"{what}: 32 MiB upload, target stalls 6 s at 4 MiB (answer, expected, longest credit wait s, secs): {r}")
    # 3: idle longer than the keepalive idle (all paths at once)
    res = {}
    def idle(what, port, tls):
        try:
            w = W(port, tls)
            a = w.connect(1, ECHO) and w.echo(1, b"before")
            time.sleep(IDLE)
            res[what] = (a, w.echo(1, b"after-idle"))
        except Exception as e:
            res[what] = (False, f"{e.__class__.__name__} {e}")
    ts = [threading.Thread(target=idle, args=x) for x in PATHS]
    for t in ts: t.start()
    for t in ts: t.join(IDLE + 60)
    for what, _, _ in PATHS:
        ok(res.get(what) == (True, True), f"{what}: connection idle {IDLE:.0f} s, then the stream echoes: {res.get(what)}")
    ok(srv.poll() is None, "finalwisp alive at the end")
finally:
    cleanup()
print(f"proxy: {fails} failures")
sys.exit(1 if fails else 0)
