# 40.04 (20.13) TLS-specific adversarial tests for finalwisp --tls-cert/--tls-key (kTLS after handshake).
# usage: python3 tls_adversarial.py PORT        (server: finalwisp --port PORT --tls-cert C --tls-key K)
# Needs `openssl` on PATH for the s_client matrix. Stdlib only otherwise.
import base64, os, socket, ssl, struct, subprocess, sys, threading, time, warnings
from concurrent.futures import ThreadPoolExecutor

PORT = int(sys.argv[1])
warnings.filterwarnings("ignore", category=DeprecationWarning)  # TLSVersion.TLSv1_1 (used on purpose)
HS_TIMEOUT = 10  # server constant TLS_HANDSHAKE_TIMEOUT
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

def ctx(maxv=None, minv=None, ciphers=None, alpn=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if maxv: c.maximum_version = maxv
    if minv: c.minimum_version = minv
    if ciphers: c.set_ciphers(ciphers)
    if alpn: c.set_alpn_protocols(alpn)
    return c

def upgrade_req():
    key = base64.b64encode(os.urandom(16)).decode()
    return (f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()

def ws_close_frame():
    m = os.urandom(4); p = b"\x03\xe8"
    return bytes([0x88, 0x82]) + m + bytes(b ^ m[i & 3] for i, b in enumerate(p))

def raw():
    return socket.create_connection(("127.0.0.1", PORT), timeout=3)

def closed_within(s, t):
    """True if the server closes (EOF/RST) within t seconds; returns (closed, bytes_seen, seconds)."""
    s.settimeout(t); t0 = time.time(); seen = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: return True, seen, time.time() - t0
            seen += d
            if time.time() - t0 > t: return False, seen, time.time() - t0
    except socket.timeout:
        return False, seen, time.time() - t0
    except (ConnectionResetError, ssl.SSLError, OSError):
        return True, seen, time.time() - t0

def wss_101(c=None, extra=b""):
    """Full TLS handshake + WS upgrade; returns the HTTP status line ("" on failure) and the socket."""
    s = (c or ctx()).wrap_socket(raw(), server_hostname="localhost")
    s.sendall(upgrade_req() + extra)
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: break
        buf += d
    return buf.split(b"\r\n", 1)[0].decode(errors="replace"), s, buf

def server_pid():
    inode = None
    for line in open("/proc/net/tcp").readlines()[1:]:
        f = line.split()
        if f[3] == "0A" and int(f[1].split(":")[1], 16) == PORT:
            inode = f[9]; break
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            if any(os.readlink(f"/proc/{pid}/fd/{fd}") == f"socket:[{inode}]" for fd in os.listdir(f"/proc/{pid}/fd")):
                return pid
        except OSError:
            continue

def nfds(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))

def client_hello():
    """Bytes of a real TLS ClientHello (via MemoryBIO; nothing is sent)."""
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    o = ctx().wrap_bio(inc, out, server_hostname="localhost")
    try: o.do_handshake()
    except ssl.SSLWantReadError: pass
    return out.read()

def alive():
    try:
        st, s, _ = wss_101(); s.close(); return st.startswith("HTTP/1.1 101")
    except OSError:
        return False

pid = server_pid()
fd0 = nfds(pid) if pid else None

# stalled clients run in the background while the other tests go on (they take HS_TIMEOUT)
stall_res = {}
def stall(name, payload):
    s = raw()
    if payload: s.sendall(payload)
    stall_res[name] = closed_within(s, HS_TIMEOUT + 5)
    s.close()
ch = client_hello()
stalls = [threading.Thread(target=stall, args=(n, p)) for n, p in
          (("silent", b""), ("half ClientHello", ch[:len(ch) // 2]), ("header only", ch[:5]))]
for t in stalls: t.start()

# 1. baseline: TLS 1.3 and 1.2 upgrade
st, s, _ = wss_101(ctx(minv=ssl.TLSVersion.TLSv1_3)); v = s.version(); s.close()
ok(st.startswith("HTTP/1.1 101") and v == "TLSv1.3", f"TLS 1.3 wss upgrade -> {st!r} ({v})")
st, s, _ = wss_101(ctx(maxv=ssl.TLSVersion.TLSv1_2)); v = s.version(); s.close()
ok(st.startswith("HTTP/1.1 101") and v == "TLSv1.2", f"TLS 1.2 wss upgrade -> {st!r} ({v})")

# 2. plain HTTP to the TLS port -> closed at once, no crash
s = raw(); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
c, seen, dt = closed_within(s, 2); s.close()
ok(c and dt < 1.5, f"plain HTTP to TLS port -> closed in {dt:.2f}s ({len(seen)} bytes back)")

# 3. garbage bytes
s = raw(); s.sendall(b"\x00" + os.urandom(4000))
c, seen, dt = closed_within(s, 2); s.close()
ok(c and dt < 1.5, f"random garbage -> closed in {dt:.2f}s")

# 4. TLS-looking records with garbage inside -> closed (rustls sends a decode_error alert when it can)
s = raw(); s.sendall(bytes([22, 3, 1, 0, 200]) + os.urandom(200))
c, seen, dt = closed_within(s, 2); s.close()
ok(c and dt < 1.5, f"handshake record with random body -> closed (alert {seen[:7].hex() or 'none'})")
s = raw(); s.sendall(bytes([22, 3, 1, 0, 200, 1, 0, 0, 196]) + os.urandom(196))
c, seen, dt = closed_within(s, 2); s.close()
ok(c and dt < 1.5 and seen[:1] == b"\x15", f"ClientHello with garbage body -> alert {seen[:7].hex()} + closed")

# 5. oversized record length
s = raw(); s.sendall(bytes([22, 3, 1, 0xff, 0xff]))
c, seen, dt = closed_within(s, 2); s.close()
ok(c and dt < 1.5, "record length 65535 -> closed")

# 6. close mid-handshake, many times (after ClientHello, and after a partial ClientHello)
for i in range(60):
    s = raw(); s.sendall(ch if i % 2 else ch[:37])
    if i % 3 == 0:
        try: s.recv(100)
        except OSError: pass
    if i % 4 == 0:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # RST
    s.close()
ok(alive(), "server alive after 60 clients closed mid-handshake (FIN and RST)")

# 7. TLS 1.1 client and ALPN without http/1.1 -> refused, server alive
try:
    s = ctx(maxv=ssl.TLSVersion.TLSv1_1, minv=ssl.TLSVersion.TLSv1_1).wrap_socket(raw(), server_hostname="localhost")
    s.close(); r = "accepted"
except (ssl.SSLError, OSError) as e:
    r = type(e).__name__
ok(r != "accepted", f"TLS 1.1 client refused ({r})")
try:
    s = ctx(alpn=["h2"]).wrap_socket(raw(), server_hostname="localhost"); s.close(); r = "accepted"
except (ssl.SSLError, OSError) as e:
    r = type(e).__name__
ok(r != "accepted", f"ALPN h2-only refused ({r})")
st, s, _ = wss_101(ctx(alpn=["h2", "http/1.1"])); a = s.selected_alpn_protocol(); s.close()
ok(st.startswith("HTTP/1.1 101") and a == "http/1.1", f"ALPN h2,http/1.1 -> {a}")

# 8. app data in the same TCP segment as the client Finished (TLS 1.3): the server must not read
#    past Finished into rustls; the request must arrive through kTLS RX.
def bio_handshake(maxv=None):
    """Handshake through MemoryBIO so the test controls exactly which bytes go out in which write."""
    sock = raw()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    o = ctx(maxv=maxv).wrap_bio(inc, out, server_hostname="localhost")
    while True:
        try:
            o.do_handshake(); return sock, o, inc, out
        except ssl.SSLWantReadError:
            if out.pending: sock.sendall(out.read())
            d = sock.recv(65536)
            if not d: raise OSError("eof during handshake")
            inc.write(d)

def bio_read_until(sock, o, inc, marker):
    buf = b""; sock.settimeout(3)
    while marker not in buf:
        d = sock.recv(65536)
        if not d: break
        inc.write(d)
        try:
            while True: buf += o.read(65536)
        except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
            pass
    return buf

def coalesced(maxv):
    sock, o, inc, out = bio_handshake(maxv)
    o.write(upgrade_req())
    sock.sendall(out.read())  # TLS 1.3: client Finished + request in one write
    buf = bio_read_until(sock, o, inc, b"\r\n\r\n")
    sock.close()
    return buf.split(b"\r\n", 1)[0].decode(errors="replace")
for i in range(20):
    st = coalesced(None)
    if not st.startswith("HTTP/1.1 101"): break
ok(st.startswith("HTTP/1.1 101"), f"TLS 1.3 Finished + request in one segment (20x) -> {st!r}")
st = coalesced(ssl.TLSVersion.TLSv1_2)
ok(st.startswith("HTTP/1.1 101"), f"TLS 1.2 request right after handshake -> {st!r}")

# 9. close_notify alert after the upgrade: kTLS read() fails with EIO -> server closes the client
sock, o, inc, out = bio_handshake()
o.write(upgrade_req()); sock.sendall(out.read())
buf = bio_read_until(sock, o, inc, b"\r\n\r\n")
try: o.unwrap()
except ssl.SSLWantReadError: pass
sock.sendall(out.read())
c, _, dt = closed_within(sock, 3); sock.close()
ok(buf.startswith(b"HTTP/1.1 101") and c and dt < 1, f"close_notify after upgrade -> server closed in {dt:.2f}s")
ok(alive(), "server alive after close_notify")

# 10. many handshakes in parallel
def one(_):
    try:
        st, s, _ = wss_101(); s.close(); return st.startswith("HTTP/1.1 101")
    except OSError:
        return False
with ThreadPoolExecutor(128) as ex:
    res = list(ex.map(one, range(600)))
ok(all(res), f"600 parallel handshakes (128 at a time): {sum(res)}/600 got 101")

# 11. openssl s_client matrix: TLS 1.2 + 1.3 x AES-128-GCM / AES-256-GCM / CHACHA20-POLY1305
cert_kind = "ECDSA"
try:
    pem = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", "-showcerts"], input=b"",
                         capture_output=True, timeout=5).stdout
    if b"rsaEncryption" in subprocess.run(["openssl", "x509", "-noout", "-text"], input=pem, capture_output=True).stdout:
        cert_kind = "RSA"
except Exception:
    pass
matrix = [("-tls1_3", "-ciphersuites", s) for s in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")]
matrix += [("-tls1_2", "-cipher", f"ECDHE-{cert_kind}-{s}") for s in ("AES128-GCM-SHA256", "AES256-GCM-SHA384", "CHACHA20-POLY1305")]
for ver, flag, suite in matrix:
    try:
        p = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", ver, flag, suite, "-ign_eof", "-alpn", "http/1.1"],
                           input=upgrade_req() + ws_close_frame(), capture_output=True, timeout=8)
        out = p.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode(errors="replace") + " TIMEOUT"
    got101 = "HTTP/1.1 101 Switching Protocols" in out
    neg = next((l.strip() for l in out.splitlines() if "Cipher is" in l), "?")
    ok(got101 and suite in neg, f"s_client {ver} {suite}: 101={got101} [{neg}]")

# 12. stalled handshakes are closed by the server timeout
for t in stalls: t.join()
for name, (c, _, dt) in sorted(stall_res.items()):
    ok(c and HS_TIMEOUT - 1 <= dt <= HS_TIMEOUT + 4, f"stalled handshake ({name}) closed by server after {dt:.1f}s")

# 13. no fd leak
if pid:
    time.sleep(0.5)
    ok(nfds(pid) <= fd0 + 2, f"server fds before {fd0}, after {nfds(pid)}")
ok(alive(), "server alive at the end")
print("ALL PASS" if not fails else f"{fails} FAILURES"); sys.exit(1 if fails else 0)
