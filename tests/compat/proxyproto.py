#!/usr/bin/env python3
"""60.34 PROXY protocol v1/v2 (--proxy-protocol tcp|unix, --proxy-protocol-from) against a real finalwisp, no root.
Stdlib only. usage: proxyproto.py FINALWISP_BINARY BASEPORT   (the TCP listener BASEPORT; targets on ephemeral ports)
Cases: v1 TCP4 / TCP6 / UNKNOWN, v2 with a TLV, LOCAL (the real peer), per-IP charge by the header's source, a source
outside --proxy-protocol-from reset at accept, no header / junk reset, a header in two segments, a partial header reset
after 4-6 s, PROXY then TLS, the unix listener with PROXY, a header source in --trusted-proxy (its X-Forwarded-For is
walked), --balance, --log-conns names the header's client, counters and conns=0 after, SIGTERM with a header still
missing, the startup refusals, the 0.0.0.0/0 warning and the capability line."""
import base64, os, re, signal, socket, ssl, struct, subprocess, sys, tempfile, threading, time

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
D = tempfile.mkdtemp(prefix="fw-pp-")
U = os.path.join(D, "fw.sock")
CERT, KEY = os.path.join(D, "cert.pem"), os.path.join(D, "key.pem")  # test-only self-signed (as run_tls.sh)
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                "-subj", "/CN=localhost", "-keyout", KEY, "-out", CERT], check=True, capture_output=True)
fails = 0
def ok(c, m, detail=""):
    global fails
    print(("PASS " if c else "FAIL ") + m + (f"  ({detail})" if detail else ""), flush=True)
    fails += 0 if c else 1

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

def ws_frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n) if n < 65536 else bytes([0x82, 0xFF]) + struct.pack(">Q", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

class Refused(Exception): pass

class Wisp:
    """a Wisp v1 client on the connected socket `s`; `pre` = bytes sent first (a PROXY header)"""
    def __init__(self, s, pre=b"", xff=None, tls=False):
        self.s = s; s.settimeout(5)
        try:
            if pre: s.sendall(pre)
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

def unix_sock():
    s = socket.socket(socket.AF_UNIX); s.connect(U); return s
def tcp_sock(src="127.0.0.1"):
    s = socket.socket(); s.bind((src, 0)); s.connect(("127.0.0.1", BASE)); return s
def outcome(fn):
    try: w = fn(); w.close(); return "ok"
    except Refused as e: return str(e)
    except (ConnectionResetError, BrokenPipeError, EOFError): return "reset"
    except socket.timeout: return "timeout"
def kv(srv):
    time.sleep(1.2)
    last = [l for l in srv.log().splitlines() if "ev=metrics" in l][-1]
    return dict(p.split("=", 1) for p in last.split()[2:] if "=" in p)
def pp1(src, fam="TCP4", dst="127.0.0.1"): return f"PROXY {fam} {src} {dst} 40000 443\r\n".encode()
SIG = b"\r\n\r\n\x00\r\nQUIT\n"
def pp2(src=None, local=False):
    if local: return SIG + b"\x20\x00\x00\x00"
    a = socket.inet_aton(src) + socket.inet_aton("127.0.0.1") + struct.pack(">HH", 40000, 443)
    tlv = b"\xEA\x00\x05\x01vpce"  # an AWS TLV, skipped
    return SIG + b"\x21\x11" + struct.pack(">H", len(a) + len(tlv)) + a + tlv

FROM = ["--proxy-protocol", "tcp", "--proxy-protocol-from", "127.0.0.1/32"]

# ---- the TCP listener: versions, LOCAL, per-IP by source, refusals, split / partial headers, counters
s = Srv("--threads", "2", *FROM, "--max-conns-per-ip", "1", "--metrics-interval", "1", "--log-conns")
ok("proxy protocol: tcp (from 1 ranges)" in s.log(), "capability line names the PROXY listener")
a = Wisp(tcp_sock(), pre=pp1("1.1.1.1")); ok(a.echo_ok(), "v1 TCP4 header, then Wisp")
ok(outcome(lambda: Wisp(tcp_sock(), pre=pp1("1.1.1.1"))) in ("reset", "closed"), "the same header source again: over --max-conns-per-ip 1, reset")
b = Wisp(tcp_sock(), pre=pp2("2.2.2.2")); ok(b.echo_ok(), "v2 header with a TLV")
c_ = Wisp(tcp_sock(), pre=pp1("2001:db8::1", "TCP6", "::1")); ok(c_.echo_ok(), "v1 TCP6")
d = Wisp(tcp_sock(), pre=pp2(local=True)); ok(d.echo_ok(), "v2 LOCAL (a health check): the real peer")
ok(outcome(lambda: Wisp(tcp_sock(), pre=b"PROXY UNKNOWN\r\n")) in ("reset", "closed"), "v1 UNKNOWN = the real peer, already at its limit: reset")
for x in (a, b, c_, d): x.close()
for _ in range(3):  # a load balancer's TCP health check: connect, close
    tcp_sock().close()
ok(outcome(lambda: Wisp(tcp_sock())) in ("reset", "closed"), "no header (plain HTTP): reset")
ok(outcome(lambda: Wisp(tcp_sock(), pre=b"\x16\x03\x01\x00\x05hello")) in ("reset", "closed"), "a TLS ClientHello instead of the header: reset")
ok(outcome(lambda: Wisp(tcp_sock("127.0.0.2"), pre=pp1("5.5.5.5"))) in ("reset", "closed"), "a peer outside --proxy-protocol-from: reset at accept")
x = tcp_sock(); h = pp1("3.3.3.3"); x.sendall(h[:9]); time.sleep(0.3)
w = Wisp(x, pre=h[9:]); ok(w.echo_ok(), "a header in two segments"); w.close()
x = tcp_sock(); x.sendall(b"PROXY TCP4"); x.settimeout(12); t0 = time.time()
try: r = x.recv(10)
except ConnectionResetError: r = b"reset"
el = time.time() - t0
ok(r in (b"", b"reset") and 3.5 <= el <= 8.5, "a partial header is reset after the timeout (4-6 s; 8 s after an idle gap)", f"{el:.1f}s {r!r}")
x.close(); time.sleep(0.5)
m = kv(s)
ok(int(m["pp_ok"]) >= 5 and int(m["pp_local"]) == 1 and int(m["pp_bad"]) >= 2 and int(m["pp_refused"]) >= 1 and int(m["pp_timeout"]) >= 1
   and int(m["refuse_ip_conns"]) >= 2, "counters (pp_local: the admitted LOCAL only; the refused UNKNOWN is not in pp_ok)", " ".join(f"{k}={m[k]}" for k in ("pp_ok", "pp_local", "pp_bad", "pp_timeout", "pp_refused", "refuse_ip_conns")))
ok(m["conns"] == "0", "nothing left counted after the clients closed", m["conns"])
log = s.log()
ok(re.search(r"ev=conn_close .* ip=1\.1\.1\.1 ", log) is not None, "--log-conns: the header's client is the ip")
ok(re.search(r"ev=conn_refused .* ip=127\.0\.0\.2 why=protocol_error", log) is not None, "--log-conns: the refused source")
ok(re.search(r"ev=conn_refused .* why=hs_timeout", log) is not None, "--log-conns: the header timeout")
ok(re.search(r"ev=conn_refused .* ip=1\.1\.1\.1 why=limit", log) is not None, "--log-conns: a per-IP refusal after the header names the header's client")
ok(not re.search(r"ev=conn_refused .* why=client_close", log), "--log-conns: no line for a connection closed before its header (health checks)")
s.stop()

# ---- PROXY then TLS: the header is consumed exactly, the ClientHello stays for rustls / kTLS
s = Srv(*FROM, "--tls-cert", CERT, "--tls-key", KEY)
w = Wisp(tcp_sock(), pre=pp2("4.4.4.4"), tls=True); ok(w.echo_ok(b"y" * 100000), "v2 header, then TLS, then Wisp (100 KB echo)"); w.close()
s.stop()

# ---- a header source in --trusted-proxy (a CDN edge behind the load balancer): its X-Forwarded-For is walked
s = Srv(*FROM, "--trusted-proxy", "10.0.0.0/8", "--max-conns-per-ip", "1", "--log-conns")
a = Wisp(tcp_sock(), pre=pp1("10.1.1.1"), xff="9.9.9.9"); ok(a.echo_ok(), "header source 10.1.1.1 (trusted) with X-Forwarded-For")
ok(outcome(lambda: Wisp(tcp_sock(), pre=pp1("10.1.1.2"), xff="9.9.9.9")) == "429", "the XFF client again through another edge: 429")
b = Wisp(tcp_sock(), pre=pp1("6.6.6.6"), xff="7.7.7.7")
ok(outcome(lambda: Wisp(tcp_sock(), pre=pp1("6.6.6.6"), xff="8.8.8.8")) in ("reset", "closed"), "an untrusted header source: its XFF ignored, charged as itself")
a.close(); b.close(); time.sleep(0.5)
ok(re.search(r"ev=conn_close .* ip=9\.9\.9\.9 via=10\.1\.1\.1 ", s.log()) is not None, "--log-conns: ip=9.9.9.9 via=10.1.1.1")
s.stop()

# ---- --balance: the hand-over happens at accept, the owner waits for the header
s = Srv("--threads", "4", "--balance", *FROM, "--metrics-interval", "1")
ws_ = []
for i in range(8):
    ws_.append(Wisp(tcp_sock(), pre=pp1(f"20.0.0.{i + 1}")))
ok(all(w.echo_ok() for w in ws_), "--balance: 8 PROXY clients served")
for w in ws_: w.close()
ok(kv(s)["conns"] == "0", "--balance: conns back to 0")
s.stop()

# ---- the unix listener with PROXY (HAProxy send-proxy-v2 to unix@): the header's source is the client
s = Srv("--listen-unix", U, "--proxy-protocol", "unix", "--max-conns-per-ip", "1", "--log-conns")
a = Wisp(unix_sock(), pre=pp1("6.6.6.6"), xff="7.7.7.7"); ok(a.echo_ok(), "unix: v1 over the unix socket")
ok(outcome(lambda: Wisp(unix_sock(), pre=pp1("6.6.6.6"), xff="1.2.3.4")) in ("reset", "closed"), "unix: the same source again: reset (XFF from an untrusted source ignored)")
ok(outcome(lambda: Wisp(unix_sock())) in ("reset", "closed"), "unix: no header: reset")
w = Wisp(unix_sock(), pre=pp2(local=True), xff="5.5.5.5"); ok(w.echo_ok(), "unix: LOCAL = the unix peer (trusted: XFF read)"); w.close()
w = Wisp(tcp_sock()); ok(w.echo_ok(), "unix PROXY only: the TCP listener needs no header"); w.close()
a.close(); time.sleep(0.5)
ok(re.search(r"ev=conn_close .* ip=5\.5\.5\.5 via=unix ", s.log()) is not None, "--log-conns: LOCAL on unix: ip=5.5.5.5 via=unix")
s.stop()

# ---- SIGTERM with a header still missing: the drain closes it (STOP_CLOSE), exit 0
s = Srv(*FROM, "--drain-timeout", "1")
x = tcp_sock(); x.sendall(b"PROXY "); time.sleep(0.2)
t0 = time.time(); s.p.send_signal(signal.SIGTERM); rc = s.p.wait(15); el = time.time() - t0  # (stop() also waits for the port)
ok(rc == 0 and el < 4, "SIGTERM with a header still missing: exit 0 without waiting for its timeout", f"rc={rc} {el:.1f}s")
x.close()
for _ in range(200):  # the port is free again before the next server (TIME_WAIT of the closed pending connection)
    try: t = socket.socket(); t.bind(("127.0.0.1", BASE)); t.close(); break
    except OSError: time.sleep(0.05)

# ---- startup
def refused(*args): return subprocess.run([BIN, str(BASE), *args], capture_output=True, text=True, timeout=10)
r = refused("--proxy-protocol", "tcp")
ok(r.returncode == 2 and "needs --proxy-protocol-from" in r.stderr, "--proxy-protocol tcp without --proxy-protocol-from: exit 2", r.stderr.strip()[:90])
r = refused("--proxy-protocol", "unix")
ok(r.returncode == 2 and "needs --listen-unix" in r.stderr, "--proxy-protocol unix without --listen-unix: exit 2")
r = refused("--proxy-protocol-from", "10.0.0.1")
ok(r.returncode == 2 and "needs --proxy-protocol tcp" in r.stderr, "--proxy-protocol-from alone: exit 2")
r = refused("--proxy-protocol", "udp", "--proxy-protocol-from", "10.0.0.1")
ok(r.returncode == 2 and "tcp or unix" in r.stderr, "--proxy-protocol udp: exit 2")
s = Srv("--proxy-protocol", "tcp", "--proxy-protocol-from", "0.0.0.0/0,::/0")
ok("--proxy-protocol-from accepts every address" in s.log(), "0.0.0.0/0 in --proxy-protocol-from: a warning")
s.stop()
cf = os.path.join(D, "fw.conf"); open(cf, "w").write("proxy-protocol tcp\nproxy-protocol-from 127.0.0.1\n")
s = Srv("--config", cf)
w = Wisp(tcp_sock(), pre=pp1("1.2.3.4")); ok(w.echo_ok(), "--config form"); w.close()
s.stop()

print(f"proxyproto: {fails} failure(s) (logs {D})")
sys.exit(1 if fails else 0)
