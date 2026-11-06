# 40.03 adversarial tests for finalwisp hardening (raw sockets, stdlib only).
# usage: python3 adversarial.py PORT [--tls]   (--tls: 20.13, the server runs with --tls-cert/--tls-key)
import itertools, os, socket, ssl, struct, sys, time, base64

PORT = int([a for a in sys.argv[1:] if not a.startswith("--")][0])
TLS = "--tls" in sys.argv
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE

def client_sock(rcvbuf=None):
    # rcvbuf: SO_RCVBUF set BEFORE connect, as a real small-buffer client does. Set after connect on loopback
    # (MSS 32-64 KiB) the window stays below one MSS: any sender then moves data only on zero-window probes
    # (~200 ms each; a plain Python sender took 27 s for 4 MiB, the same as finalwisp; vmtest finding 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.settimeout(3); s.connect(("127.0.0.1", PORT))
    return _ctx.wrap_socket(s, server_hostname="localhost") if TLS else s
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m)
    fails += 0 if c else 1

def ws_connect(path="/", proto=None):
    s = client_sock()
    key = base64.b64encode(os.urandom(16)).decode()
    extra = f"Sec-WebSocket-Protocol: {proto}\r\n" if proto else ""
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: break
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    return s, head, rest

def frame(op, payload, mask=True, fin=True):
    b0 = (0x80 if fin else 0) | op
    n = len(payload)
    hdr = bytes([b0]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
    if not mask:
        hdr = bytes([hdr[0], hdr[1] & 0x7f]) + hdr[2:]
        return hdr + payload
    m = os.urandom(4)
    return hdr + m + bytes(c ^ m[i & 3] for i, c in enumerate(payload))

def read_all(s, t=1.0):
    s.settimeout(t); out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: return out, True
            out += d
    except socket.timeout:
        return out, False
    except ConnectionResetError:
        return out, True

def alive():
    s, head, _ = ws_connect()
    r = head.startswith(b"HTTP/1.1 101"); s.close(); return r

# 1. unmasked client frame -> close 1002
s, h, rest = ws_connect()
s.sendall(frame(0x2, b"\x02\x01\x00\x00\x00hi", mask=False))
data, closed = read_all(s)
ok(b"\x88\x02\x03\xea" in rest + data and closed, "unmasked frame -> WS close 1002 + disconnect")

# 2. new data frame during fragmented message -> 1002
s, h, rest = ws_connect()
s.sendall(frame(0x2, b"\x02\x01\x00", fin=False) + frame(0x2, b"\x02\x01\x00\x00\x00x"))
data, closed = read_all(s)
ok(b"\x88\x02\x03\xea" in rest + data and closed, "interleaved fragment -> WS close 1002")

# 3. v2 INFO with bad major version -> Wisp CLOSE(0, 0x04)
s, h, rest = ws_connect(proto="wisp-v2")
s.sendall(frame(0x2, b"\x05\x00\x00\x00\x00\x09\x00"))
data, closed = read_all(s)
ok(b"\x04\x00\x00\x00\x00\x04" in rest + data and closed, "v2 INFO major=9 -> CLOSE(0, 0x04)")

# 4. v2 INFO too short -> rejected
s, h, rest = ws_connect(proto="wisp-v2")
s.sendall(frame(0x2, b"\x05\x00\x00\x00\x00"))
data, closed = read_all(s)
ok(closed and b"\x03\x00\x00\x00\x00" not in data, "v2 INFO without version -> no CONTINUE, closed")

# 5. non-ASCII percent path in wsproxy must not crash the server
s, h, rest = ws_connect(path="/%a\xc3\xa9:80".encode("latin-1").decode("utf-8", "surrogateescape") if False else "/%a%C3%A9:80")
s.close()
raw = client_sock()
raw.sendall(b"GET /%a\xc3\xa9:80 HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
read_all(raw, 0.5); raw.close()
time.sleep(0.2)
ok(alive(), "non-ASCII wsproxy path did not crash server")

# 6. ping flood, never read -> server stops reading us (bounded memory), stays alive
s, h, rest = ws_connect()
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
ping = frame(0x9, b"x" * 125)
sent = 0; s.settimeout(0.5)
t0 = time.time()
try:
    while time.time() - t0 < 6:
        s.sendall(ping * 64); sent += 64 * len(ping)
except (socket.timeout, BlockingIOError):
    pass
# server RSS: find the process listening on PORT via /proc (no pid file needed)
rss = None
inode = None
for line in open("/proc/net/tcp").readlines()[1:]:
    f = line.split()
    if f[3] == "0A" and int(f[1].split(":")[1], 16) == PORT:
        inode = f[9]; break
if inode:
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            if any(os.readlink(f"/proc/{pid}/fd/{fd}") == f"socket:[{inode}]" for fd in os.listdir(f"/proc/{pid}/fd")):
                rss = next(int(l.split()[1]) // 1024 for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS"))
                break
        except OSError:
            continue
ok(sent < 64 << 20 and (rss is None or rss < 200), f"ping flood blocked after {sent >> 20} MiB sent, server RSS {rss} MiB")
s.close()
ok(alive(), "server alive after ping flood")

# 7. HTTP/1.0 upgrade -> 400
raw = client_sock()
raw.sendall(b"GET / HTTP/1.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
d, _ = read_all(raw, 0.5)
ok(d.startswith(b"HTTP/1.1 400"), "HTTP/1.0 upgrade -> 400")

# 8. slow-reading client during a big verified download (client socket fills up again and again;
#    catches lost wakeups when the server stops reading a target because the client is full)
import threading, hashlib
SRC_N = 32 << 20
pattern = hashlib.sha256(b"seed").digest() * 32768  # 1 MiB
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0)); srv.listen(4); SRC_PORT = srv.getsockname()[1]
def source():
    c, _ = srv.accept()
    for _ in range(SRC_N // len(pattern)):
        c.sendall(pattern)
    c.close()
threading.Thread(target=source, daemon=True).start()
s, h, rest = ws_connect()
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)  # tiny windows make loopback TCP crawl; 64K + pauses still fill the server
host = b"127.0.0.1"
s.sendall(frame(0x2, b"\x01\x07\x00\x00\x00" + b"\x01" + struct.pack("<H", SRC_PORT) + host))
buf = bytearray(rest); got = 0; digest = hashlib.sha256(); closed_reason = None
s.settimeout(20); deadline = time.time() + 60
try:
    while closed_reason is None and time.time() < deadline:
        # parse whole server frames from buf
        while True:
            if len(buf) < 2: break
            ln = buf[1] & 0x7f; hl = 2
            if ln == 126:
                if len(buf) < 4: break
                ln = struct.unpack(">H", buf[2:4])[0]; hl = 4
            elif ln == 127:
                if len(buf) < 10: break
                ln = struct.unpack(">Q", buf[2:10])[0]; hl = 10
            if len(buf) < hl + ln: break
            p = bytes(buf[hl:hl + ln]); del buf[:hl + ln]
            if buf and False: pass
            if p[0] == 0x02 and p[1:5] == b"\x07\x00\x00\x00":
                digest.update(p[5:]); got += len(p) - 5
            elif p[0] == 0x04 and p[1:5] == b"\x07\x00\x00\x00":
                closed_reason = p[5]
        d = s.recv(65536)
        if not d: break
        buf += d
        if got < (16 << 20): time.sleep(0.002)  # pause between reads: server's socket fills every time
except socket.timeout:
    pass
expect = hashlib.sha256(pattern * (SRC_N // len(pattern))).hexdigest()
ok(got == SRC_N and closed_reason == 2 and digest.hexdigest() == expect,
   f"slow-reader 32 MiB download intact, no stall (got {got >> 20} MiB, close {closed_reason})")
s.close(); srv.close()

# 9. target finishes (data + FIN all buffered) while the client is not reading at all:
#    no new target event will ever arrive, so the server must resume on client EPOLLOUT by itself.
def frozen_reader_download(total, freeze):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(4); port = srv.getsockname()[1]
    def src():
        c, _ = srv.accept()
        try:
            for _ in range(total // len(pattern)):
                c.sendall(pattern)
        finally:
            c.close()
    threading.Thread(target=src, daemon=True).start()
    s, h, rest = ws_connect()
    s.sendall(frame(0x2, b"\x01\x09\x00\x00\x00\x01" + struct.pack("<H", port) + b"127.0.0.1"))
    time.sleep(freeze)
    buf = bytearray(rest); got = 0; dg = hashlib.sha256(); reason = None
    s.settimeout(10); end = time.time() + 30
    try:
        while reason is None and time.time() < end:
            while len(buf) >= 2:
                ln = buf[1] & 0x7f; hl = 2
                if ln == 126:
                    if len(buf) < 4: break
                    ln = struct.unpack(">H", buf[2:4])[0]; hl = 4
                elif ln == 127:
                    if len(buf) < 10: break
                    ln = struct.unpack(">Q", buf[2:10])[0]; hl = 10
                if len(buf) < hl + ln: break
                p = bytes(buf[hl:hl + ln]); del buf[:hl + ln]
                if p[0] == 0x02: dg.update(p[5:]); got += len(p) - 5
                elif p[0] == 0x04: reason = p[5]
            if reason is not None: break
            d = s.recv(1 << 20)
            if not d: break
            buf += d
    except socket.timeout:
        pass
    s.close(); srv.close()
    return got, reason, dg.hexdigest() == hashlib.sha256(pattern * (total // len(pattern))).hexdigest()

# 10. target sends TCP urgent (OOB) data mid-stream: splice() stops at the urgent mark (returns 0/EAGAIN
#     with data still queued); the server must not treat that as EOF or as drained.
def oob_download(total, marks=(2, 5)):
    """marks: an urgent byte after these 1 MiB blocks (20.25 stall regression: urgent_behind_bulk)."""
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(4); port = srv.getsockname()[1]
    def src():
        c, _ = srv.accept()
        try:
            for i in range(total // len(pattern)):
                c.sendall(pattern)
                if i in marks:
                    c.send(b"!", socket.MSG_OOB)  # urgent byte: out of band, not part of the normal stream
        finally:
            c.close()
    threading.Thread(target=src, daemon=True).start()
    s, h, rest = ws_connect()
    s.sendall(frame(0x2, b"\x01\x0b\x00\x00\x00\x01" + struct.pack("<H", port) + b"127.0.0.1"))
    buf = bytearray(rest); got = 0; dg = hashlib.sha256(); reason = None
    s.settimeout(10); end = time.time() + 30
    try:
        while reason is None and time.time() < end:
            while len(buf) >= 2:
                ln = buf[1] & 0x7f; hl = 2
                if ln == 126:
                    if len(buf) < 4: break
                    ln = struct.unpack(">H", buf[2:4])[0]; hl = 4
                elif ln == 127:
                    if len(buf) < 10: break
                    ln = struct.unpack(">Q", buf[2:10])[0]; hl = 10
                if len(buf) < hl + ln: break
                p = bytes(buf[hl:hl + ln]); del buf[:hl + ln]
                if p[0] == 0x02: dg.update(p[5:]); got += len(p) - 5
                elif p[0] == 0x04: reason = p[5]
            if reason is not None: break
            d = s.recv(1 << 20)
            if not d: break
            buf += d
    except socket.timeout:
        pass
    s.close(); srv.close()
    blocks = total // len(pattern)
    # TCP keeps one urgent mark: if the next mark arrives before the reader reached this one, this urgent
    # byte becomes ordinary data (RFC 6093). So each earlier mark may show up inline, the last never does.
    ok_digests = set()
    for inl in itertools.product((False, True), repeat=len(marks) - 1):
        data = b""
        for i in range(blocks):
            data += pattern
            if i in marks[:-1] and inl[marks.index(i)]:
                data += b"!"
        ok_digests.add(hashlib.sha256(data).hexdigest())
    return got, reason, dg.hexdigest() in ok_digests

got, reason, same = oob_download(8 << 20)
ok((8 << 20) <= got <= (8 << 20) + 1 and reason == 2 and same, f"target urgent/OOB data: full 8 MiB delivered, not cut (got {got}, close {reason}, intact {same})")
def urgent_behind_bulk(window=5.0):
    """20.25: stream 1 = 16 MiB download to a client that reads nothing for 1 s (the connection's output fills,
    so the server stops reading targets). Stream 2's target meanwhile sends 32 KiB, an urgent byte, 32 KiB, all
    of it queued in the server's socket, then holds the connection open until the client is done (no FIN can
    rescue an old server inside the window). When the server resumes stream 2,
    read() stops short at the urgent mark; an old server took that for "drained" and the second 32 KiB waited
    for the FIN. Returns seconds until stream 2 had all 64 KiB, and whether its bytes are intact."""
    part = bytes(range(256)) * 128  # 32 KiB
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(4); port = srv.getsockname()[1]
    bulk = socket.socket(); bulk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bulk.bind(("127.0.0.1", 0)); bulk.listen(4); bport = bulk.getsockname()[1]
    started, done = threading.Event(), threading.Event()
    def src_bulk():
        c, _ = bulk.accept()
        try:
            for i in range(16):
                c.sendall(pattern)
                if i == 1: started.set()  # 2 MiB in: the frozen client's output is full by now
        except OSError: pass
        finally: started.set(); c.close()
    def src_urg():
        c, _ = srv.accept()
        try:
            started.wait(3); time.sleep(0.3)  # let the server stop reading targets (output full)
            c.sendall(part); c.send(b"!", socket.MSG_OOB); c.sendall(part)
            done.wait(window + 5)
        finally:
            c.close()
    threading.Thread(target=src_bulk, daemon=True).start(); threading.Thread(target=src_urg, daemon=True).start()
    s, h, rest = ws_connect()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    s.sendall(frame(0x2, b"\x01" + struct.pack("<I", 1) + b"\x01" + struct.pack("<H", bport) + b"127.0.0.1"))
    s.sendall(frame(0x2, b"\x01" + struct.pack("<I", 2) + b"\x01" + struct.pack("<H", port) + b"127.0.0.1"))
    time.sleep(1.0)
    t0 = time.time(); buf = bytearray(rest); got2 = bytearray(); t_full = None
    s.settimeout(window); end = t0 + window
    try:
        while t_full is None and time.time() < end:
            while len(buf) >= 2:
                ln = buf[1] & 0x7f; hl = 2
                if ln == 126:
                    if len(buf) < 4: break
                    ln = struct.unpack(">H", buf[2:4])[0]; hl = 4
                elif ln == 127:
                    if len(buf) < 10: break
                    ln = struct.unpack(">Q", buf[2:10])[0]; hl = 10
                if len(buf) < hl + ln: break
                p = bytes(buf[hl:hl + ln]); del buf[:hl + ln]
                if p[0] == 0x02 and struct.unpack("<I", p[1:5])[0] == 2:
                    got2 += p[5:]
                    if len(got2) >= 2 * len(part) and t_full is None: t_full = time.time()
            if t_full is not None: break
            d = s.recv(1 << 20)
            if not d: break
            buf += d
    except socket.timeout:
        pass
    done.set(); s.close(); srv.close(); bulk.close()
    return (round(t_full - t0, 2) if t_full else None), bytes(got2) == part * 2, len(got2)

dt, intact, n2 = urgent_behind_bulk()
ok(dt is not None and dt < 3 and intact, f"20.25 urgent mark on a resumed target held open: all 64 KiB before the FIN (after {dt} s, got {n2}, intact {intact})")

for total in (8 << 20, 24 << 20):
    got, reason, same = frozen_reader_download(total, 1.0)
    ok(got == total and reason == 2 and same, f"frozen-reader {total >> 20} MiB download completes (got {got >> 20} MiB, close {reason})")

# 11. fragmented DATA messages back to back in one write (upload batching must not keep pointers
#     into the reassembly buffer, which is freed and reused by the next fragmented message)
def recv_wisp_data(s, sid, want, timeout=5):
    buf = bytearray(); got = bytearray(); s.settimeout(timeout); end = time.time() + timeout
    try:
        while len(got) < want and time.time() < end:
            while len(buf) >= 2:
                ln = buf[1] & 0x7f; hl = 2
                if ln == 126:
                    if len(buf) < 4: break
                    ln = struct.unpack(">H", buf[2:4])[0]; hl = 4
                elif ln == 127:
                    if len(buf) < 10: break
                    ln = struct.unpack(">Q", buf[2:10])[0]; hl = 10
                if len(buf) < hl + ln: break
                p = bytes(buf[hl:hl + ln]); del buf[:hl + ln]
                if p[0] == 0x02 and struct.unpack("<I", p[1:5])[0] == sid: got += p[5:]
            if len(got) >= want: break
            d = s.recv(1 << 16)
            if not d: break
            buf += d
    except socket.timeout:
        pass
    return bytes(got)

echo_srv = socket.socket(); echo_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
echo_srv.bind(("127.0.0.1", 0)); echo_srv.listen(16); ECHO_PORT = echo_srv.getsockname()[1]
def echo_loop():
    while True:
        try:
            c, _ = echo_srv.accept()
        except OSError:
            return
        def serve(c=c):
            try:
                while (d := c.recv(1 << 16)):
                    c.sendall(d)
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
threading.Thread(target=echo_loop, daemon=True).start()

bad = 0
for trial in range(20):
    s, h, rest = ws_connect()
    sid = 0x21
    s.sendall(frame(0x2, b"\x01" + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", ECHO_PORT) + b"127.0.0.1"))
    time.sleep(0.05)  # target connected, so DATA takes the batched path
    msgs = [os.urandom(3000) for _ in range(4)]
    wire = b""
    for m in msgs:
        pkt = b"\x02" + struct.pack("<I", sid) + m
        wire += frame(0x2, pkt[:1500], fin=False) + frame(0x0, pkt[1500:])
    wire += frame(0x2, b"\x02" + struct.pack("<I", sid) + b"tail")  # unfragmented DATA, same stream, same read
    s.sendall(wire)
    want = b"".join(msgs) + b"tail"
    got = recv_wisp_data(s, sid, len(want))
    bad += got != want
    s.close()
ok(bad == 0, f"fragmented DATA + batching: echo intact in {20 - bad}/20 trials")

# 12. DATA + WS close in one write while the target has just reset the connection (write error during
#     teardown must not re-enter close_target and kill the worker)
rst_srv = socket.socket(); rst_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rst_srv.bind(("127.0.0.1", 0)); rst_srv.listen(64); RST_PORT = rst_srv.getsockname()[1]
def rst_loop():
    while True:
        try:
            c, _ = rst_srv.accept()
        except OSError:
            return
        c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        time.sleep(0.02)
        c.close()  # RST
threading.Thread(target=rst_loop, daemon=True).start()
for trial in range(40):
    try:
        s, h, rest = ws_connect()
        s.sendall(frame(0x2, b"\x01\x31\x00\x00\x00\x01" + struct.pack("<H", RST_PORT) + b"127.0.0.1"))
        time.sleep(0.015 + (trial % 8) * 0.001)
        s.sendall(b"".join(frame(0x2, b"\x02\x31\x00\x00\x00" + os.urandom(20000)) for _ in range(3))
                  + frame(0x8, b"\x03\xe8"))
        read_all(s, 0.05)
        s.close()
    except OSError:
        pass
time.sleep(0.3)
ok(alive(), "server survives DATA+close racing a target reset (40 trials)")
# 13. 20.11 idle sweep: a client idle past two sweeps (buffers freed) must work again, both directions,
#     including a frame larger than the initial 16 KiB read buffer
s, h, rest = ws_connect()
sid = 0x41
s.sendall(frame(0x2, b"\x01" + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", ECHO_PORT) + b"127.0.0.1"))
first = os.urandom(60000)  # > 16 KiB initial rbuf; frame() caps at 64 KiB
s.sendall(frame(0x2, b"\x02" + struct.pack("<I", sid) + first))
got1 = recv_wisp_data(s, sid, len(first))
time.sleep(4.5)
second = os.urandom(200000)
s.sendall(b"".join(frame(0x2, b"\x02" + struct.pack("<I", sid) + second[i:i + 50000]) for i in range(0, len(second), 50000)))
got2 = recv_wisp_data(s, sid, len(second))
s.close()
ok(got1 == first and got2 == second, f"echo intact before and after idle buffer release ({len(got1)}+{len(got2)} bytes)")

# 14. 30.09: a client idle past two sweeps after a bulk download (splice pipe closed) downloads intact again
src_srv = socket.socket(); src_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
src_srv.bind(("127.0.0.1", 0)); src_srv.listen(4); SRC_PORT = src_srv.getsockname()[1]
pattern = bytes(range(256)) * 4096  # 1 MiB
def src_loop():
    while True:
        try:
            c, _ = src_srv.accept()
        except OSError:
            return
        try:
            c.sendall(pattern * 8); c.close()
        except OSError:
            pass
threading.Thread(target=src_loop, daemon=True).start()
s, h, rest = ws_connect()
oks = []
for sid in (0x51, 0x52):
    s.sendall(frame(0x2, b"\x01" + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", SRC_PORT) + b"127.0.0.1"))
    got = recv_wisp_data(s, sid, len(pattern) * 8, timeout=10)
    oks.append(got == pattern * 8)
    if sid == 0x51:
        time.sleep(4.5)
s.close(); src_srv.close()
ok(all(oks), f"8 MiB download intact before and after idle pipe release ({oks})")

# 15. 20.19 two-lane output (the default since 20.22; also valid with --no-prio): a throttled client (small SO_RCVBUF, reads in
#     4 KiB sips) takes a 4 MiB bulk download while 40 short echo streams run on the same connection; every
#     stream's bytes must arrive intact and in order (a bulk frame split across send() calls must never be
#     interleaved with another frame), and the bulk stream's CLOSE must come after its last DATA byte.
src2 = socket.socket(); src2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
src2.bind(("127.0.0.1", 0)); src2.listen(4); SRC2_PORT = src2.getsockname()[1]
BULK = pattern * 4  # 4 MiB
def src2_loop():
    while True:
        try:
            c, _ = src2.accept()
        except OSError:
            return
        try:
            c.sendall(BULK); c.close()
        except OSError:
            pass
threading.Thread(target=src2_loop, daemon=True).start()
s = client_sock(rcvbuf=16384)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
buf = bytearray()
while b"\r\n\r\n" not in buf:
    buf += s.recv(4096)
buf = bytearray(buf.split(b"\r\n\r\n", 1)[1])
BSID = 0x61
s.sendall(frame(0x2, b"\x01" + struct.pack("<I", BSID) + b"\x01" + struct.pack("<H", SRC2_PORT) + b"127.0.0.1"))
small = {}
for k in range(40):
    sid = 0x100 + k
    small[sid] = os.urandom(1000 + k * 37)
    s.sendall(frame(0x2, b"\x01" + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", ECHO_PORT) + b"127.0.0.1")
              + frame(0x2, b"\x02" + struct.pack("<I", sid) + small[sid]))
got = {sid: bytearray() for sid in small}; bulk_got = bytearray(); bulk_close = None; order_ok = True
s.settimeout(10); end = time.time() + 30
while time.time() < end and (bulk_close is None or any(len(got[k]) < len(small[k]) for k in small)):
    while len(buf) >= 2:
        ln = buf[1] & 0x7f; hl = 2
        if ln == 126:
            if len(buf) < 4: break
            ln = struct.unpack(">H", buf[2:4])[0]; hl = 4
        elif ln == 127:
            if len(buf) < 10: break
            ln = struct.unpack(">Q", buf[2:10])[0]; hl = 10
        if len(buf) < hl + ln: break
        op = buf[0] & 0x0f; p = bytes(buf[hl:hl + ln]); del buf[:hl + ln]
        if op != 0x2 or len(p) < 5:
            order_ok = False; continue
        sid = struct.unpack("<I", p[1:5])[0]
        if p[0] == 0x02:
            if sid == BSID:
                if bulk_close is not None: order_ok = False  # DATA after CLOSE
                bulk_got += p[5:]
            elif sid in got: got[sid] += p[5:]
        elif p[0] == 0x04:
            if sid == BSID: bulk_close = p[5]
        elif p[0] != 0x03:
            order_ok = False
    try:
        d = s.recv(4096)  # small sips: the server's send() calls are split often
    except socket.timeout:
        break
    if not d: break
    buf += d
    time.sleep(0.0005)
s.close(); src2.close()
small_ok = all(bytes(got[k]) == small[k] for k in small)
ok(small_ok and bytes(bulk_got) == BULK and bulk_close == 2 and order_ok,
   f"throttled client: 40 small echoes intact ({sum(bytes(got[k]) == small[k] for k in small)}/40), 4 MiB bulk intact ({len(bulk_got)}), CLOSE after data ({bulk_close}), frames well-formed ({order_ok})")

# 16. 20.19 close during a lane frame (the default since 20.22; also valid with --no-prio): a throttled client pulls an endless bulk
#     download, then sends a WS Close while the server is part-way through a bulk frame. Everything the server
#     sends afterwards must still parse as whole frames and end with the server's Close (review r1 P2: the lane
#     drop used to cut the in-progress frame, so the Close landed inside its payload).
src3 = socket.socket(); src3.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
src3.bind(("127.0.0.1", 0)); src3.listen(8); SRC3_PORT = src3.getsockname()[1]
def src3_loop():
    while True:
        try:
            c, _ = src3.accept()
        except OSError:
            return
        def feed(c=c):
            try:
                while True: c.sendall(pattern)
            except OSError:
                pass
        threading.Thread(target=feed, daemon=True).start()
threading.Thread(target=src3_loop, daemon=True).start()
def close_mid_bulk(attempt):
    s = client_sock(); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    buf = bytearray(buf.split(b"\r\n\r\n", 1)[1])
    s.sendall(frame(0x2, b"\x01" + struct.pack("<I", 7) + b"\x01" + struct.pack("<H", SRC3_PORT) + b"127.0.0.1"))
    s.settimeout(5); pulled = 0; target = (1 << 20) + attempt * 12345  # stop at a different offset each time
    while pulled < target:
        d = s.recv(4096)
        if not d: break
        buf += d; pulled += len(d); time.sleep(0.0003)
    s.sendall(frame(0x8, struct.pack(">H", 1000)))
    while True:
        try:
            d = s.recv(65536)
        except (socket.timeout, ConnectionResetError):
            break
        if not d: break
        buf += d
    s.close()
    ops = []; bad = False
    while len(buf) >= 2:
        ln = buf[1] & 0x7f; hl = 2
        if ln == 126:
            if len(buf) < 4: break
            ln = struct.unpack(">H", buf[2:4])[0]; hl = 4
        elif ln == 127:
            if len(buf) < 10: break
            ln = struct.unpack(">Q", buf[2:10])[0]; hl = 10
        if len(buf) < hl + ln: break
        op = buf[0] & 0x0f; p = bytes(buf[hl:hl + ln]); del buf[:hl + ln]
        if op == 0x2:
            if len(p) < 5 or p[0] not in (0x02, 0x03, 0x04): bad = True
        elif op != 0x8: bad = True
        ops.append(op)
    return (not bad and not buf and ops[-1:] == [0x8]), len(buf), ops[-1:] if ops else None
r16 = [close_mid_bulk(a) for a in range(5)]
src3.close()
ok(all(r[0] for r in r16), f"WS Close during a throttled bulk download: whole frames then the server's Close, 5/5 ({r16})")

# 17. handshake deadline (review r1): a client that never finishes the HTTP upgrade (1 byte/s drip) and a v2
#     client that never sends its INFO are both closed within ~12 s; an established idle connection stays.
def drip():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=1)
    if TLS: s = _ctx.wrap_socket(s, server_hostname="localhost")
    s.sendall(b"GET / HTTP/1.1\r\n"); t0 = time.time()
    while time.time() - t0 < 16:
        try:
            s.sendall(b"X")
        except OSError:
            return time.time() - t0
        try:
            if s.recv(4096) == b"": return time.time() - t0
        except socket.timeout:
            pass
        except OSError:
            return time.time() - t0
    return None
def no_info():
    s = client_sock(); key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: wisp-v2\r\n\r\n").encode())
    t0 = time.time(); s.settimeout(1)
    while time.time() - t0 < 16:
        try:
            if s.recv(4096) == b"": return time.time() - t0
        except socket.timeout:
            pass
        except OSError:
            return time.time() - t0
    return None
idle_ok = []
def idle_v1():
    s = client_sock(); key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    s.settimeout(3); s.recv(4096); time.sleep(14)
    s.sendall(frame(0x9, b"hi")); s.settimeout(3)
    try:
        idle_ok.append(b"\x8a\x02hi" in s.recv(4096))
    except OSError:
        idle_ok.append(False)
res17 = {}
ths = [threading.Thread(target=lambda: res17.__setitem__("drip", drip())),
       threading.Thread(target=lambda: res17.__setitem__("noinfo", no_info())),
       threading.Thread(target=idle_v1)]
[t.start() for t in ths]; [t.join() for t in ths]
ok(res17.get("drip") is not None and res17["drip"] < 13 and res17.get("noinfo") is not None and res17["noinfo"] < 13
   and idle_ok == [True],
   f"handshake deadline: HTTP drip closed after {res17.get('drip')}, v2 without INFO closed after {res17.get('noinfo')}, idle open connection alive {idle_ok}")

# 18. oh256 per-stream fairness: 6 endless downloads on one connection, throttled reader (so the server's output cap
#     engages all the time). Every stream must keep advancing; a park/resume order bug starves streams silently
#     (aggregate throughput looks fine). Counted over the second half of a 3 s window.
fair_srv = socket.socket(); fair_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
fair_srv.bind(("127.0.0.1", 0)); fair_srv.listen(16); FAIR_PORT = fair_srv.getsockname()[1]
def fair_feed(c):
    blk = os.urandom(65536)
    try:
        while True:
            c.sendall(blk)
    except OSError:
        pass
    finally:
        c.close()
def fair_accept():
    while True:
        try:
            c, _ = fair_srv.accept()
        except OSError:
            return
        threading.Thread(target=fair_feed, args=(c,), daemon=True).start()
threading.Thread(target=fair_accept, daemon=True).start()
def fairness(n=6, window=3.0):
    s, h, rest = ws_connect()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    for sid in range(1, n + 1):
        s.sendall(frame(0x2, b"\x01" + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", FAIR_PORT) + b"127.0.0.1"))
    buf = bytearray(rest); late = {sid: 0 for sid in range(1, n + 1)}; total = dict(late)
    t0 = time.time(); s.settimeout(3)
    try:
        while time.time() - t0 < window:
            d = s.recv(65536)
            if not d: break
            buf += d
            while len(buf) >= 2:
                ln = buf[1] & 0x7f; hl = 2
                if ln == 126:
                    if len(buf) < 4: break
                    ln = struct.unpack(">H", buf[2:4])[0]; hl = 4
                elif ln == 127:
                    if len(buf) < 10: break
                    ln = struct.unpack(">Q", buf[2:10])[0]; hl = 10
                if len(buf) < hl + ln: break
                p = bytes(buf[hl:hl + 5]); del buf[:hl + ln]
                if len(p) == 5 and p[0] == 0x02:
                    sid = struct.unpack("<I", p[1:5])[0]
                    if sid in total:
                        total[sid] += ln - 5
                        if time.time() - t0 >= window / 2: late[sid] += ln - 5
            time.sleep(0.0005)
    except socket.timeout:
        pass
    s.close()
    return late, total
late18, total18 = fairness()
mean18 = sum(late18.values()) / len(late18)
ok(mean18 > 0 and min(late18.values()) >= 0.05 * mean18,  # stall detector (master's spread: min 0.3-0.9 x mean)
   f"6 parallel downloads on one throttled connection all advance (second-half KiB per stream {[v >> 10 for v in late18.values()]})")
fair_srv.close()

# 19. 60.05 H2: a frame header claiming 16 MiB must not allocate 16 MiB before the bytes arrive (base-1 resized rbuf
#     to the frame size at the next read: 100 connections x 14 bytes = 1.6 GiB RSS, pre-auth). A legitimate 10 MiB frame
#     (larger than rbuf at every level) still goes through intact at level 0.
def server_rss_kib():
    inode = None
    for line in open("/proc/net/tcp").readlines()[1:]:
        f = line.split()
        if f[3] == "0A" and int(f[1].split(":")[1], 16) == PORT:
            inode = f[9]; break
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            if any(os.readlink(f"/proc/{pid}/fd/{fd}") == f"socket:[{inode}]" for fd in os.listdir(f"/proc/{pid}/fd")):
                return next(int(l.split()[1]) for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS"))
        except OSError:
            continue
    return None
def big_frame(payload, claim=None):
    n = len(payload) if claim is None else claim
    m = os.urandom(4)
    mask = (m * (len(payload) // 4 + 1))[:len(payload)]
    masked = (int.from_bytes(payload, "little") ^ int.from_bytes(mask, "little")).to_bytes(len(payload), "little")
    return bytes([0x82, 0x80 | 127]) + struct.pack(">Q", n) + m + masked
rss0 = server_rss_kib(); hold = []
for _ in range(100):
    s, h, rest = ws_connect()
    s.sendall(big_frame(b"\x02", claim=16 << 20))
    hold.append(s)
time.sleep(0.3)
for s in hold: s.sendall(b"\0")  # the next read is the one that grew rbuf to the frame size in base-1
time.sleep(1.0)
rss1 = server_rss_kib()
grew = (rss1 - rss0) >> 10 if rss0 and rss1 else None
for s in hold: s.close()
ok(grew is not None and grew < 64 and alive(), f"100 x 16 MiB frame headers + 1 byte: server RSS +{grew} MiB (base-1: +1600)")
s, h, rest = ws_connect()
sid = 0x31
s.sendall(frame(0x2, b"\x01" + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", ECHO_PORT) + b"127.0.0.1"))
time.sleep(0.05)
body = os.urandom(10 << 20)
threading.Thread(target=lambda: s.sendall(big_frame(b"\x02" + struct.pack("<I", sid) + body)), daemon=True).start()
got = recv_wisp_data(s, sid, len(body), timeout=20)
s.close()
ok(got == body, f"one 10 MiB DATA frame (bigger than rbuf) echoed intact ({len(got)} bytes)")

# 20. 60.05 H6: a v2 client that rejects the server's INFO sends CLOSE(0, reason) and closes the WebSocket
#     (protocol.md handshake): the server answers with a clean WS close 1000, not 1002 (base-1).
s, h, rest = ws_connect(proto="wisp-v2")
s.sendall(frame(0x2, b"\x04\x00\x00\x00\x00\x04"))
data, closed = read_all(s)
ok(b"\x88\x02\x03\xe8" in rest + data and b"\x88\x02\x03\xea" not in rest + data and closed,
   "v2 client CLOSE(0) during the handshake -> WS close 1000")

rst_srv.close(); echo_srv.close()

print("ALL PASS" if not fails else f"{fails} FAILURES"); sys.exit(1 if fails else 0)
