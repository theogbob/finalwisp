#!/usr/bin/env python3
"""40.09 (20.17) TLS extras for finalwisp kTLS mode: SNI with several certificates, SIGHUP certificate
reload, close_notify both ways, TLS 1.3 KeyUpdate (client-initiated via openssl s_client, and the
server's proactive KeyUpdate via --tls-rekey-records), --tls-cipher-order, startup errors.
Starts its own servers on PORT, PORT+1, PORT+2.  usage: tls_extras.py FINALWISP_BINARY PORT
Needs: `tls` kernel module, openssl, python3 (stdlib only)."""
import base64, hashlib, os, shutil, signal, socket, ssl, subprocess, sys, tempfile, threading, time

BIN, PORT = os.path.abspath(sys.argv[1]), int(sys.argv[2])
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

D = tempfile.mkdtemp(prefix="fw-tlsx-")
def mkcert(name, cn, san):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-days", "30", "-subj", f"/CN={cn}", "-addext", f"subjectAltName={san}",
                    "-keyout", f"{D}/{name}.key", "-out", f"{D}/{name}.pem"], check=True, capture_output=True)
    return f"{D}/{name}.pem", f"{D}/{name}.key"
A = mkcert("a", "a.test", "DNS:a.test,DNS:*.wild.test")
B = mkcert("b", "b.test", "DNS:b.test")
C = mkcert("c", "a-new.test", "DNS:a.test")
def fp_file(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(pem).read())).hexdigest()[:16]
FA, FB, FC = fp_file(A[0]), fp_file(B[0]), fp_file(C[0])

procs = []
def start(port, *args):
    log = open(f"{D}/srv{port}.log", "w")
    p = subprocess.Popen([BIN, "--port", str(port), "--allow-loopback", *args], stdout=log, stderr=subprocess.STDOUT)
    procs.append(p)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close(); return p
        except OSError:
            if p.poll() is not None: break
            time.sleep(0.05)
    raise SystemExit(f"server on {port} did not start: {open(f'{D}/srv{port}.log').read()}")

def ctx(maxv=None, ragged=True):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    if maxv: c.maximum_version = maxv
    return c

def tls_conn(port, sni="localhost", maxv=None, ragged=True):
    return ctx(maxv).wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname=sni,
                                 suppress_ragged_eofs=ragged)

def fp(port, sni):
    s = tls_conn(port, sni); d = s.getpeercert(binary_form=True); s.close()
    return hashlib.sha256(d).hexdigest()[:16]

def upgrade_req():
    key = base64.b64encode(os.urandom(16)).decode()
    return (f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()

def frame(op, payload):
    m = os.urandom(4)
    return bytes([0x80 | op, 0x80 | len(payload)]) + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

class Ws:
    """wss client over an ssl socket: upgrade, then read server frames."""
    def __init__(self, port, sni="localhost", maxv=None, ragged=True):
        self.s = tls_conn(port, sni, maxv, ragged); self.buf = b""
        self.s.sendall(upgrade_req())
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(65536)
            if not d: raise OSError("closed before 101")
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        self.status = head.split(b"\r\n", 1)[0].decode()
    def need(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d: raise EOFError
            self.buf += d
    def frame(self):
        self.need(2); op, ln = self.buf[0] & 15, self.buf[1] & 127; h = 2
        if ln == 126: self.need(4); ln = int.from_bytes(self.buf[2:4], "big"); h = 4
        elif ln == 127: self.need(10); ln = int.from_bytes(self.buf[2:10], "big"); h = 10
        self.need(h + ln); p = self.buf[h:h + ln]; self.buf = self.buf[h + ln:]
        return op, p
    def ping(self, payload):
        """send a ping, return True when its pong arrives (skips Wisp frames)"""
        self.s.sendall(frame(9, payload))
        while True:
            op, p = self.frame()
            if op == 10: return p == payload

def tls_stat():
    """/proc/net/tls_stat counters; {} where the kernel has none (e.g. 5.4): then "stat n/a"."""
    try:
        return {l.split()[0]: int(l.split()[1]) for l in open("/proc/net/tls_stat")}
    except FileNotFoundError:
        return {}
STAT = bool(tls_stat())
if not STAT:
    print("note: /proc/net/tls_stat missing (old kernel): stat n/a; the functional checks still run", flush=True)
REKEY = "TlsRxRekeyOk" in tls_stat()  # kTLS rekey (Linux 6.14+); absent on 6.8 and where tls_stat is missing
CLOSE_NOTIFY_IN = b"<<< TLS 1.3, Alert [length 0002], warning close_notify"  # s_client -msg

class SClient:
    """openssl s_client with stdin commands (k = KeyUpdate, K = KeyUpdate + update_requested)."""
    def __init__(self, port, *extra):
        self.p = subprocess.Popen(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "localhost",
                                   "-alpn", "http/1.1", *extra], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        self.out = b""; self.lock = threading.Lock()
        threading.Thread(target=self._rd, daemon=True).start()
    def _rd(self):
        while True:
            d = self.p.stdout.read1(65536)
            if not d: return
            with self.lock: self.out += d
    def send(self, b):
        try: self.p.stdin.write(b); self.p.stdin.flush()
        except BrokenPipeError: pass  # s_client exited (server closed): the checks below fail
    def wait_for(self, marker, t=3):
        end = time.time() + t
        while time.time() < end:
            with self.lock:
                if marker in self.out: return True
            if self.p.poll() is not None: break
            time.sleep(0.02)
        with self.lock: return marker in self.out
    def gone(self, t=3):
        """True when s_client exits within t seconds (the server closed the connection)"""
        try: self.p.wait(t); return True
        except subprocess.TimeoutExpired: return False
    def close(self):
        try: self.p.kill()
        except OSError: pass
        self.p.wait()

class HoldProxy:
    """40.09 KeyUpdate-behind-data: a one-connection TCP relay between s_client and the server. Server->client
    is relayed at once. Client->server is relayed at once until hold(); then the client's bytes are kept until
    flush(n) sees n complete TLS records, which go to the server in ONE send (one TCP segment on loopback)."""
    def __init__(self, port):
        self.ls = socket.socket(); self.ls.bind(("127.0.0.1", 0)); self.ls.listen(1)
        self.port = self.ls.getsockname()[1]; self.up = port
        self.held = None; self.cv = threading.Condition()
        threading.Thread(target=self._run, daemon=True).start()
    def _run(self):
        c, _ = self.ls.accept(); self.ls.close()
        s = socket.create_connection(("127.0.0.1", self.up))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.c, self.s = c, s
        threading.Thread(target=self._pipe, args=(s, c, False), daemon=True).start()
        self._pipe(c, s, True)
    def _pipe(self, a, b, up):
        try:
            while d := a.recv(65536):
                with self.cv:
                    if up and self.held is not None:
                        self.held += d; self.cv.notify_all(); continue
                b.sendall(d)
        except OSError:
            pass
    def hold(self):
        with self.cv: self.held = b""
    def records(self):
        n, off, h = 0, 0, self.held
        while off + 5 <= len(h) and off + 5 + int.from_bytes(h[off + 3:off + 5], "big") <= len(h):
            off += 5 + int.from_bytes(h[off + 3:off + 5], "big"); n += 1
        return n
    def wait_records(self, n, t=3):
        with self.cv: return self.cv.wait_for(lambda: self.records() >= n, t)
    def flush(self):
        with self.cv:
            d, self.held = self.held, None
            self.s.sendall(d)
        return len(d)

try:
    # ---------------------------------------------------------------- startup errors
    def startup(*args):
        p = subprocess.run([BIN, "--port", str(PORT), *args], capture_output=True, timeout=5)
        return p.returncode, p.stderr.decode(errors="replace").strip()
    rc, err = startup("--tls-cert", A[0], "--tls-key", A[1], "--tls-cert", B[0])
    ok(rc == 2, f"startup: 2 certs, 1 key -> exit {rc}")
    rc, err = startup("--tls-cert", A[0], "--tls-key", A[1], "--tls-cert", f"{D}/missing.pem", "--tls-key", B[1])
    ok(rc == 1 and "missing.pem" in err, f"startup: second pair unreadable -> exit {rc} ({err[:70]})")
    rc, err = startup("--tls-cert", A[0], "--tls-key", A[1], "--tls-cert", B[0], "--tls-key", A[1])
    ok(rc == 1, f"startup: second pair cert/key mismatch -> exit {rc} ({err[:70]})")

    # ---------------------------------------------------------------- SNI: two certificates on one port
    start(PORT, "--tls-cert", A[0], "--tls-key", A[1], "--tls-cert", B[0], "--tls-key", B[1])
    for sni, want, what in (("b.test", FB, "B"), ("a.test", FA, "A"), ("x.wild.test", FA, "A (wildcard)"),
                            ("B.TEST", FB, "B (case)"), ("nomatch.test", FA, "A (no match -> first)"),
                            (None, FA, "A (no SNI -> first)")):
        got = fp(PORT, sni)
        ok(got == want, f"SNI {sni}: cert {what} [{got}]")
    p = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", "-servername", "b.test"], input=b"",
                       capture_output=True, timeout=5).stdout.decode(errors="replace").replace("CN = ", "CN=")  # OpenSSL 3.0 prints "CN = x"
    ok("CN=b.test" in p, "openssl s_client -servername b.test -> subject CN=b.test")
    p = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", "-noservername"], input=b"",
                       capture_output=True, timeout=5).stdout.decode(errors="replace").replace("CN = ", "CN=")
    ok("CN=a.test" in p, "openssl s_client -noservername -> subject CN=a.test (first pair)")
    for v in (ssl.TLSVersion.TLSv1_2, None):
        w = Ws(PORT, "b.test", v); okp = w.ping(b"sni1"); vv = w.s.version(); w.s.close()
        ok(w.status.startswith("HTTP/1.1 101") and okp, f"wss via cert B ({vv}): upgrade + ping/pong")

    # ---------------------------------------------------------------- close_notify
    for v in (ssl.TLSVersion.TLSv1_2, None):
        w = Ws(PORT, maxv=v, ragged=False)
        w.s.sendall(frame(8, b"\x03\xe8"))  # WS close -> server echoes Close and closes the connection
        try:
            while True:
                op, _ = w.frame()
            r = "?"
        except EOFError:
            r = "clean close_notify"  # SSLSocket.recv returns b"" only after close_notify (ragged EOF raises)
        except ssl.SSLEOFError as e:
            r = f"EOF without close_notify ({e.__class__.__name__})"
        except OSError as e:
            r = f"{e.__class__.__name__} {e}"
        ok(r == "clean close_notify", f"server close sends close_notify ({w.s.version()}): {r}")
        w.s.close()
    # incoming close_notify: the server closes and answers with its own close_notify
    w = Ws(PORT)
    try:
        w.s.settimeout(3); w.s.unwrap(); r = "answered"
    except (ssl.SSLError, OSError) as e:
        r = f"{e.__class__.__name__} {e}"
    ok(r == "answered", f"client close_notify -> server close_notify back: {r}")

    # ---------------------------------------------------------------- client KeyUpdate (openssl s_client k / K)
    # Kernels before 6.14 (e.g. 6.8) have no kTLS rekey (no TlsRxRekeyOk in tls_stat): the new RX key
    # cannot be installed, so the documented behaviour there is a prompt close (no stall), server alive.
    ku_t0 = time.monotonic()  # 60.12: the rate-limit check below needs all refusals inside one 60 s window
    for cmd, req in ((b"k\n", False), (b"K\n", True)):
        st0 = tls_stat()
        sc = SClient(PORT, "-tls1_3", "-msg")
        sc.send(upgrade_req())
        got101 = sc.wait_for(b"101 Switching Protocols")
        sc.send(frame(9, b"pre1")); pre = sc.wait_for(b"\x8a\x04pre1")
        sc.send(cmd); time.sleep(0.3)
        what = f"client KeyUpdate {'update_requested' if req else 'update_not_requested'}: 101={got101} ping before={pre}"
        if not REKEY:
            closed = sc.gone(); cn = sc.wait_for(CLOSE_NOTIFY_IN, 1)
            sc.close()
            ok(got101 and pre and closed and cn, f"{what}, no kernel rekey -> connection closed={closed} with close_notify={cn}")
            continue
        sc.send(frame(9, b"aft1")); aft = sc.wait_for(b"\x8a\x04aft1")
        sc.send(frame(9, b"aft2")); aft2 = sc.wait_for(b"\x8a\x04aft2")
        alive = sc.p.poll() is None
        sc.close(); st1 = tls_stat()
        drx = st1["TlsRxRekeyOk"] - st0["TlsRxRekeyOk"]; dtx = st1["TlsTxRekeyOk"] - st0["TlsTxRekeyOk"]
        ok(got101 and pre and aft and aft2 and alive and drx >= 1 and (dtx >= 1) == req,
           f"{what} after={aft},{aft2} alive={alive} kernel RX rekeys +{drx} TX rekeys +{dtx}")

    # ---------------------------------------------------------------- 40.09 KeyUpdate right behind application data
    # Records [ping A][KeyUpdate][ping B (new key)] arrive in ONE TCP segment and nothing follows. kTLS
    # read() returns ping A short (a record of another type ends a read) with the KeyUpdate already decrypted
    # and queued; Linux 6.14+ then polls not-readable until the new RX key is set (tls_sk_poll,
    # key_update_pending). A server that takes the short read as "drained" (EPOLLET) never sees the KeyUpdate:
    # pong B never comes, the connection stalls. Only the record count makes this deterministic, no timing.
    # Variant "2 records": [ping A][KeyUpdate] in one segment, then ping C in a later segment: pong C must come
    # (on Linux 7.2+ the kernel sends no wakeup for the queued KeyUpdate, so the server sees it only with C).
    for cmd, req in ((b"k\n", False), (b"K\n", True)):
        for tail in (True, False):
            st0 = tls_stat()
            px = HoldProxy(PORT); sc = SClient(px.port, "-tls1_3", "-msg")
            sc.send(upgrade_req())
            got101 = sc.wait_for(b"101 Switching Protocols")
            px.hold()
            sc.send(frame(9, b"kuA1")); r1 = px.wait_records(1)
            sc.send(cmd); r2 = px.wait_records(2)
            want = 3 if tail else 2
            if tail:
                sc.send(frame(9, b"kuB1")); r2 = r2 and px.wait_records(3)
            nrec = px.records(); px.flush()
            pa = sc.wait_for(b"\x8a\x04kuA1")
            what = (f"KeyUpdate {'update_requested' if req else 'update_not_requested'} behind data, one segment "
                    f"({nrec} records{'' if tail else ', then a ping in a later segment'})")
            if not REKEY:
                closed = sc.gone(); cn = sc.wait_for(CLOSE_NOTIFY_IN, 1)
                sc.close()
                ok(got101 and r1 and r2 and nrec == want and pa and closed and cn,
                   f"{what}: pong before={pa}, no kernel rekey -> connection closed={closed} with close_notify={cn} (no stall)")
                continue
            if tail:
                pb = sc.wait_for(b"\x8a\x04kuB1", 3)
            else:
                time.sleep(0.2); sc.send(frame(9, b"kuC1")); pb = sc.wait_for(b"\x8a\x04kuC1", 3)
            sku = sc.wait_for(b"<<< TLS 1.3, Handshake [length 0005], KeyUpdate", 1) if req else None
            alive = sc.p.poll() is None
            sc.close(); st1 = tls_stat()
            drx = st1["TlsRxRekeyOk"] - st0["TlsRxRekeyOk"]
            ok(got101 and r1 and r2 and nrec == want and pa and pb and sku in (None, True) and alive and drx >= 1,
               f"{what}: pong before={pa} after={pb} server KeyUpdate={sku} alive={alive} RX rekeys +{drx}")

    # 60.12: a refused client KeyUpdate (no kernel rekey) logs ONE line per 60 s with the reason and the way out
    # (TLS at a reverse proxy, or Linux 6.14+); with kernel rekey nothing is logged
    kul = [l for l in open(f"{D}/srv{PORT}.log").read().splitlines() if "client sent a TLS 1.3 KeyUpdate" in l]
    if REKEY:
        ok(not kul, f"KeyUpdate with kernel rekey: no refusal log line ({len(kul)})")
    else:
        took = time.monotonic() - ku_t0
        want = len(kul) == 1 if took < 55 else 1 <= len(kul) <= 2
        ok(want and "6.14" in kul[0] and "reverse proxy" in kul[0] and "1 such close(s)" in kul[0],
           f"KeyUpdate refused 6x in {took:.0f} s: {len(kul)} log line(s) (rate-limited, 1 per 60 s): {kul[:1]}")

    # ---------------------------------------------------------------- SIGHUP reload
    d2 = f"{D}/live"; os.mkdir(d2); shutil.copy(A[0], f"{d2}/c.pem"); shutil.copy(A[1], f"{d2}/k.pem")
    srv = start(PORT + 1, "--tls-cert", f"{d2}/c.pem", "--tls-key", f"{d2}/k.pem")
    old = Ws(PORT + 1); ok(old.ping(b"old0") and fp(PORT + 1, "a.test") == FA, "reload: before SIGHUP cert A")
    shutil.copy(C[0], f"{d2}/c.pem"); shutil.copy(C[1], f"{d2}/k.pem")
    ok(fp(PORT + 1, "a.test") == FA, "reload: files replaced, no SIGHUP yet -> still cert A")
    srv.send_signal(signal.SIGHUP); time.sleep(0.3)
    got = fp(PORT + 1, "a.test")
    ok(got == FC, f"reload: after SIGHUP new connections get cert C [{got}]")
    ok(old.ping(b"old1"), "reload: connection from before the reload still works")
    open(f"{d2}/c.pem", "w").write("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n")
    srv.send_signal(signal.SIGHUP); time.sleep(0.3)
    got = fp(PORT + 1, "a.test"); log = open(f"{D}/srv{PORT + 1}.log").read()
    ok(got == FC and "reload failed" in log and srv.poll() is None,
       f"reload: bad cert file -> old config kept [{got}], error logged, server alive")
    shutil.copy(C[0], f"{d2}/c.pem"); shutil.copy(B[1], f"{d2}/k.pem")
    srv.send_signal(signal.SIGHUP); time.sleep(0.3)
    ok(fp(PORT + 1, "a.test") == FC, "reload: cert/key mismatch -> old config kept")
    ok(old.ping(b"old2"), "reload: old connection still works after failed reloads")
    old.s.close()

    # ---------------------------------------------------------------- server KeyUpdate + cipher order
    start(PORT + 2, "--tls-cert", A[0], "--tls-key", A[1], "--tls-rekey-records", "64", "--tls-cipher-order", "server")
    st0 = tls_stat()
    w = Ws(PORT + 2); good = 0
    try:
        for i in range(600):
            good += w.ping(b"r%05d" % i)
    except (OSError, EOFError) as e:  # e.g. a KeyUpdate the kernel could not follow: bad record mac
        print(f"rekey-64 connection broke after {good} pings: {e.__class__.__name__} {e}", flush=True)
    w.s.close(); st1 = tls_stat()
    if REKEY:
        drx = st1["TlsRxRekeyOk"] - st0["TlsRxRekeyOk"]; dtx = st1["TlsTxRekeyOk"] - st0["TlsTxRekeyOk"]
        ok(good == 600 and dtx >= 5 and drx >= 5,
           f"--tls-rekey-records 64: 600 ping/pong ok={good}, server TX rekeys +{dtx}, client RX rekeys (update_requested) +{drx}")
    else:  # the startup probe found no kernel rekey: no KeyUpdate at all (one would break the connection here)
        log = open(f"{D}/srv{PORT + 2}.log").read()
        ok(good == 600 and "no kTLS rekey" in log,
           f"--tls-rekey-records 64, no kernel rekey: 600 ping/pong ok={good}, startup log says no kTLS rekey="
           f"{'no kTLS rekey' in log}")
    def neg(port, suites, extra=()):
        out = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", *extra, "-ciphersuites", suites, "-tls1_3"],
                             input=b"", capture_output=True, timeout=5).stdout.decode(errors="replace")
        return next((l.split("Cipher is")[1].strip() for l in out.splitlines() if "Cipher is" in l), "?")
    pref = "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
    ok(neg(PORT, pref) == "TLS_CHACHA20_POLY1305_SHA256", f"cipher order client (default): client prefers ChaCha20 -> {neg(PORT, pref)}")
    ok(neg(PORT + 2, pref) == "TLS_AES_256_GCM_SHA384", f"cipher order server: client prefers ChaCha20 -> {neg(PORT + 2, pref)}")
    pref2 = "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
    ok(neg(PORT + 2, pref2) == "TLS_AES_128_GCM_SHA256", f"cipher order server: client offers ChaCha20, AES-128 -> {neg(PORT + 2, pref2)}")
    ok(neg(PORT + 2, "TLS_CHACHA20_POLY1305_SHA256") == "TLS_CHACHA20_POLY1305_SHA256", "cipher order server: ChaCha20-only client still served")
    c12 = ctx(ssl.TLSVersion.TLSv1_2); c12.set_ciphers("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")
    s = c12.wrap_socket(socket.create_connection(("127.0.0.1", PORT + 2)), server_hostname="x"); c = s.cipher()[0]; s.close()
    ok(c == "ECDHE-ECDSA-AES256-GCM-SHA384", f"cipher order server, TLS 1.2: -> {c}")
    w = Ws(PORT + 2, maxv=ssl.TLSVersion.TLSv1_2); good = sum(w.ping(b"t%04d" % i) for i in range(200)); w.s.close()
    ok(good == 200, "TLS 1.2 with --tls-rekey-records 64: no KeyUpdate (1.3 only), 200 ping/pong ok")
    for p in procs:
        ok(p.poll() is None, f"server pid {p.pid} alive at the end")
finally:
    for p in procs:
        p.kill(); p.wait()
    shutil.rmtree(D, ignore_errors=True)
print("ALL PASS" if not fails else f"{fails} FAILURES"); sys.exit(1 if fails else 0)
