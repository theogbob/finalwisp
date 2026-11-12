#!/usr/bin/env python3
"""60.31 C7 --listen-unix against a real finalwisp, no root. Stdlib only (strace and caddy optional: missing = SKIP lines).
usage: unix.py FINALWISP_BINARY BASEPORT   (the TCP listener BASEPORT; targets on ephemeral ports; a throwaway cert)
Cases: socket mode (default 660, --unix-mode), Wisp over the unix socket and TCP at once, a 64 MiB download, unix plain
ws:// beside a TLS TCP listener, --max-conns and the unix peer's X-Forwarded-For (per-IP key; no header = not charged),
the forced hand-over (clients per worker epoll from /proc fdinfo), --log-conns ip=unix, the stale / live / crashed /
regular-file / second-instance (flock) cases, the file removed at SIGTERM, refusals (--unix-mode alone, bad paths),
splice into the unix socket (strace), and Caddy reverse_proxy unix/ (the use case)."""
import base64, os, re, shutil, signal, socket, ssl, stat, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
D = tempfile.mkdtemp(prefix="fw-unix-")
CERT, KEY = os.path.join(D, "cert.pem"), os.path.join(D, "key.pem")  # test-only self-signed (as run_tls.sh)
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                "-subj", "/CN=localhost", "-keyout", KEY, "-out", CERT], check=True, capture_output=True)
U = os.path.join(D, "fw.sock")
fails = 0
def ok(c, m, detail=""):
    global fails
    print(("PASS " if c else "FAIL ") + m + (f"  ({detail})" if detail else ""), flush=True)
    fails += 0 if c else 1
def skip(m, why): print(f"SKIP {m}  ({why})", flush=True)

BLAST = 64 << 20
def serve(fn):
    ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(64)
    threading.Thread(target=lambda: [threading.Thread(target=fn, args=(ls.accept()[0],), daemon=True).start() for _ in iter(int, 1)],
                     daemon=True).start()
    return ls.getsockname()[1]
def echo(c):
    with c:
        try:
            while (d := c.recv(65536)): c.sendall(d)
        except OSError: pass
def blast(c):
    with c:
        try:
            b = b"x" * (1 << 20)
            for _ in range(BLAST >> 20): c.sendall(b)
        except OSError: pass
ECHO, BL = serve(echo), serve(blast)

class Srv:
    def __init__(self, *args, wrap=()):
        self.logf = open(os.path.join(D, f"srv{time.monotonic_ns()}.log"), "w+")
        self.p = subprocess.Popen([*wrap, BIN, str(BASE), "--allow-loopback", "--log-level", "debug", *args], stdout=self.logf, stderr=subprocess.STDOUT)
        for _ in range(200):
            if "capabilities:" in self.log() or self.p.poll() is not None: break
            time.sleep(0.05)
    def log(self):
        with open(self.logf.name) as f: return f.read()
    def pid(self):
        if self.p.args[0] != "strace": return self.p.pid
        return int(subprocess.run(["pgrep", "-P", str(self.p.pid)], capture_output=True, text=True).stdout.split()[0])
    def stop(self, sig=signal.SIGTERM):
        os.kill(self.pid(), sig)  # under strace: finalwisp itself, so strace sees it exit and writes its summary
        try: rc = self.p.wait(15)
        except subprocess.TimeoutExpired: self.p.kill(); rc = self.p.wait()
        for _ in range(100):  # the port is free again before the next server
            try: t = socket.socket(); t.bind(("127.0.0.1", BASE)); t.close(); break
            except OSError: time.sleep(0.05)
        return rc
def refused(*args):
    return subprocess.run([BIN, str(BASE), *args], capture_output=True, text=True, timeout=10)

def ws_frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n) if n < 65536 else bytes([0x82, 0xFF]) + struct.pack(">Q", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

class Refused(Exception): pass

class Wisp:
    """a Wisp v1 client on the connected socket `s`"""
    def __init__(self, s, xff=None, tls=False):
        self.s = s; s.settimeout(5)
        try:
            if tls:
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                self.s = s = ctx.wrap_socket(s, server_hostname="localhost")
            h = f"X-Forwarded-For: {xff}\r\n" if xff else ""
            s.sendall(f"GET / HTTP/1.1\r\nHost: x\r\n{h}Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ".encode()
                      + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
            self.buf = b""
            while b"\r\n\r\n" not in self.buf:
                d = s.recv(4096)
                if not d: raise Refused("closed")
                self.buf += d
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            s.close(); raise Refused("reset")
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        st = head.split(b"\r\n")[0]
        if b" 101 " not in st:
            s.close(); raise Refused(st.split(b" ")[1].decode())
        self.packet()  # CONTINUE 0
    def need(self, n):
        while len(self.buf) < n:
            d = self.s.recv(1 << 20)
            if not d: raise EOFError
            self.buf += d
        b, self.buf = self.buf[:n], self.buf[n:]; return b
    def packet(self):
        h = self.need(2); n = h[1] & 0x7f
        if n == 126: n = struct.unpack(">H", self.need(2))[0]
        elif n == 127: n = struct.unpack(">Q", self.need(8))[0]
        p = self.need(n); return p[0], struct.unpack("<I", p[1:5])[0], p[5:]
    def send(self, t, sid, pl): self.s.sendall(ws_frame(bytes([t]) + struct.pack("<I", sid) + pl))
    def connect(self, sid, port): self.send(1, sid, b"\x01" + struct.pack("<H", port) + b"127.0.0.1")
    def echo_ok(self, msg=b"hello wisp"):
        self.connect(1, ECHO); self.send(2, 1, msg); got = b""
        while len(got) < len(msg):
            t, sid, p = self.packet()
            if t == 2 and sid == 1: got += p
            elif t == 4: return False
        return got == msg
    def download(self):
        self.connect(1, BL); got = 0
        while got < BLAST:
            t, sid, p = self.packet()
            if t == 2: got += len(p)
            elif t == 4: break
        return got
    def close(self): self.s.close()

def unix_sock(path=U):
    s = socket.socket(socket.AF_UNIX); s.connect(path); return s
def tcp_sock():
    return socket.create_connection(("127.0.0.1", BASE))
def outcome(fn):
    try: w = fn(); w.close(); return "ok"
    except Refused as e: return str(e)
    except (ConnectionResetError, BrokenPipeError, EOFError): return "reset"
    except socket.timeout: return "timeout"
def metric(srv, key):
    time.sleep(1.2)
    vals = [l for l in srv.log().splitlines() if "ev=metrics" in l]
    for kv in (vals[-1].split() if vals else []):
        if kv.startswith(key + "="): return int(kv.split("=", 1)[1])
def epoll_tfds(pid):
    """registered fds per epoll instance (one per worker), from /proc/PID/fdinfo"""
    out = {}
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            if os.readlink(f"/proc/{pid}/fd/{fd}") != "anon_inode:[eventpoll]": continue
            out[fd] = set(re.findall(r"^tfd:\s+(\d+)", open(f"/proc/{pid}/fdinfo/{fd}").read(), re.M))
        except OSError: pass
    return out

# ---- basics, mode, both listeners, download, counters, shutdown
s = Srv("--threads", "4", "--listen-unix", U, "--metrics-interval", "1")
m = os.stat(U).st_mode
ok(stat.S_ISSOCK(m) and stat.S_IMODE(m) == 0o660, "socket created with mode 660 (default)", oct(m))
ok("listening on unix:" + U in s.log() and "mode 660" in s.log(), "startup line names the unix listener")
w = Wisp(unix_sock()); ok(w.echo_ok(), "Wisp echo over the unix socket"); w.close()
w = Wisp(tcp_sock()); ok(w.echo_ok(), "the TCP listener still serves"); w.close()
w = Wisp(unix_sock()); got = w.download(); ok(got == BLAST, "64 MiB download over the unix socket", got); w.close()
ok((metric(s, "accepted_unix") or 0) == 2, "accepted_unix counts the unix clients only")
r = refused("--listen-unix", U)
ok(r.returncode == 1 and "another finalwisp holds this path" in r.stderr, "a second server on the path refuses to start (flock)", r.stderr.strip()[-120:])
ok(s.stop() == 0, "SIGTERM exits 0")
ok(not os.path.exists(U), "the socket file is removed at shutdown")
ok(os.path.exists(U + ".lock"), "the .lock file stays (never removed: no lock race)")

# ---- stale file, crash, a live foreign server, a regular file, --unix-mode
st_ = socket.socket(socket.AF_UNIX); st_.bind(U); st_.close()
s = Srv("--listen-unix", U, "--unix-mode", "600")
ok(s.p.poll() is None and stat.S_IMODE(os.stat(U).st_mode) == 0o600, "a stale socket file is replaced; --unix-mode 600")
w = Wisp(unix_sock()); ok(w.echo_ok(), "works after replacing the stale file"); w.close()
s.stop(signal.SIGKILL)  # leaves the file behind (a crash)
s = Srv("--listen-unix", U); ok(s.p.poll() is None, "restart after a crash (stale file left by SIGKILL)"); s.stop()
L2 = os.path.join(D, "foreign.sock"); fl = socket.socket(socket.AF_UNIX); fl.bind(L2); fl.listen(1)
r = refused("--listen-unix", L2)
ok(r.returncode == 1 and "a server is accepting on it" in r.stderr and os.path.exists(L2), "a live socket of another program is left alone", r.stderr.strip()[-100:])
fl.close(); os.unlink(L2)
open(U, "w").close()
r = refused("--listen-unix", U)
ok(r.returncode == 1 and "not a socket" in r.stderr and os.path.exists(U), "a regular file at the path is refused, not removed", r.stderr.strip()[-100:]); os.unlink(U)
r = refused("--unix-mode", "600")
ok(r.returncode == 2 and "--unix-mode needs --listen-unix" in r.stderr, "--unix-mode without --listen-unix refuses to start", r.stderr.strip()[:100])
r = refused("--listen-unix", U, "--unix-mode", "999")
ok(r.returncode == 2 and "octal" in r.stderr, "--unix-mode 999 refused", r.stderr.strip()[:100])
r = refused("--listen-unix", os.path.join(D, "x" * 120))
ok(r.returncode == 1 and "not a usable socket path" in r.stderr, "a path over sun_path is refused", r.stderr.strip()[-100:])
r = refused("--listen-unix", os.path.join(D, "nodir", "w.sock"))
ok(r.returncode == 1 and "--listen-unix" in r.stderr, "a missing directory is a startup error", r.stderr.strip()[-100:])

# ---- unix stays plain ws:// beside TLS on TCP; --download-rate warning
s = Srv("--listen-unix", U, "--tls-cert", CERT, "--tls-key", KEY, "--download-rate", "10M")
w = Wisp(unix_sock()); ok(w.echo_ok(), "with --tls-cert: the unix socket stays plain ws://"); w.close()
w = Wisp(tcp_sock(), tls=True); ok(w.echo_ok(), "with --tls-cert: TCP is TLS"); w.close()
ok("--download-rate does not cap --listen-unix clients" in s.log(), "--download-rate warns that unix clients are not paced")
s.stop()

# ---- --max-conns covers unix; the unix peer's XFF is believed (per-IP key); no header = not charged; ip=unix
s = Srv("--threads", "4", "--listen-unix", U, "--max-conns", "3", "--max-conns-per-ip", "1", "--metrics-interval", "1", "--log-conns")
a = Wisp(unix_sock(), xff="9.9.9.9")
ok(outcome(lambda: Wisp(unix_sock(), xff="9.9.9.9")) == "429", "per-ip: the same X-Forwarded-For again gets 429")
b = Wisp(unix_sock(), xff="8.8.8.8"); c_ = Wisp(unix_sock())
ok(outcome(lambda: Wisp(unix_sock())) in ("reset", "closed"), "--max-conns 3: the 4th unix client is reset")
ok((metric(s, "realip_missing") or 0) >= 1, "realip_missing for the client without a header")
for x in (a, b, c_): x.close()
time.sleep(0.5)
log = s.log()
ok(re.search(r"ev=conn_close .* ip=9\.9\.9\.9 via=unix ", log) is not None, "--log-conns: a unix client with XFF: ip=9.9.9.9 via=unix")
ok(re.search(r"ev=conn_close .* ip=unix .*why=", log) is not None, "--log-conns: a unix client without a header: ip=unix")
ok(re.search(r"ev=conn_refused .* ip=unix why=limit", log) is not None, "--log-conns: the --max-conns refusal: ip=unix")
s.stop()

# ---- the forced hand-over: 40 unix clients spread over 4 workers (EPOLLEXCLUSIVE alone puts them on one)
s = Srv("--threads", "4", "--listen-unix", U)
pid = s.pid(); before = epoll_tfds(pid)
held = []
for i in range(40):
    held.append(Wisp(unix_sock())); time.sleep(0.01)
time.sleep(0.3)
after = epoll_tfds(pid)
per = sorted((len(after[k] - before.get(k, set())) for k in after), reverse=True)
ok(len(per) >= 4 and sum(per) == 40 and per[0] <= 12, "40 unix clients spread over the 4 workers", f"clients per worker epoll {per}")
for x in held: x.close()
s.stop()

# ---- splice into the unix client (download path)
if shutil.which("strace"):
    trace = os.path.join(D, "splice.trace")
    s = Srv("--listen-unix", U, "--threads", "1", wrap=("strace", "-f", "-qq", "-c", "-e", "trace=splice", "-o", trace))
    if s.p.poll() is None and os.path.exists(U):
        w = Wisp(unix_sock()); got = w.download(); w.close(); s.stop(); time.sleep(0.3)
        calls = [int(l.split()[3]) for l in open(trace).read().splitlines() if l.split()[-1:] == ["splice"]]
        ok(got == BLAST and calls and calls[0] > 100, "the download uses splice into the unix socket", f"splice calls {calls}")
    else:
        s.p.kill(); skip("splice into the unix socket", "strace could not run the server")
else:
    skip("splice into the unix socket", "no strace")

# ---- Caddy -> unix socket -> finalwisp (the C7 use case)
CADDY = shutil.which("caddy")
if CADDY:
    s = Srv("--listen-unix", U)
    t = socket.socket(); t.bind(("127.0.0.1", 0)); cp = t.getsockname()[1]; t.close()
    cf = os.path.join(D, "Caddyfile")
    open(cf, "w").write(f"{{\n  admin off\n  auto_https off\n  storage file_system {D}/caddy\n}}\n:{cp} {{\n  reverse_proxy unix/{U}\n}}\n")
    cad = subprocess.Popen([CADDY, "run", "--config", cf, "--adapter", "caddyfile"], stdout=subprocess.DEVNULL,
                           stderr=open(os.path.join(D, "caddy.log"), "w"), env={**os.environ, "HOME": D, "XDG_DATA_HOME": D, "XDG_CONFIG_HOME": D})
    for _ in range(100):
        try: socket.create_connection(("127.0.0.1", cp), timeout=0.2).close(); break
        except OSError: time.sleep(0.1)
    try:
        w = Wisp(socket.create_connection(("127.0.0.1", cp))); ok(w.echo_ok(b"z" * 300000), "caddy reverse_proxy unix/ -> Wisp echo"); w.close()
    except Exception as e:
        ok(False, "caddy reverse_proxy unix/ -> Wisp echo", repr(e))
    cad.terminate(); cad.wait(10); s.stop()
else:
    skip("caddy reverse_proxy unix/", "no caddy in PATH")

print(f"unix: {fails} failure(s) (logs {D})")
sys.exit(1 if fails else 0)
