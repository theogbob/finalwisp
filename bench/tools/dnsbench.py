#!/usr/bin/env python3
"""60.41 DNS-thread bench (stdlib only; bench-only, never shipped): unique-name CONNECT churn through finalwisp against a
local stub DNS server that answers after a fixed delay, so the --dns-threads pool size matters.

  stub   --addr 127.0.0.77 --port 53 --delay-ms D     A 127.0.0.1 for *.pos.test, AAAA NODATA, NXDOMAIN otherwise
  client --url ws://127.0.0.1:P/ --target-port E --conc C --dur S --warm W --tag X [--procs K]
         closed loop: C streams in flight (split over K processes, one WebSocket each), every CONNECT a new name
         <tag>-<proc>-<n>.pos.test. (no cache hit, no coalescing), DATA "ping", wait for the echo, CLOSE.
         Prints one JSON line: ops/s, p50/p99/max CONNECT->echo latency (ms), errors.

The getaddrinfo lane needs finalwisp to read a resolv.conf naming the stub. The bench boxes' /etc/resolv.conf is never
touched: a COPY of the static binary has the string /etc/resolv.conf replaced by /tmp/b61dns.conf (same length;
`patch BIN OUT`). That copy is a bench artifact only and must never be shipped.
"""
import base64, heapq, json, os, select, socket, struct, sys, time


def arg(name, default=None, conv=str):
    a = sys.argv
    if name in a:
        return conv(a[a.index(name) + 1])
    return default


# ---- stub DNS
def qname(m, off=12):
    labels = []
    while m[off]:
        n = m[off]
        labels.append(m[off + 1:off + 1 + n].decode(errors="replace").lower())
        off += 1 + n
    return ".".join(labels), off + 1


def stub():
    addr, port, delay = arg("--addr", "127.0.0.77"), arg("--port", 53, int), arg("--delay-ms", 20.0, float) / 1000
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind((addr, port))
    s.setblocking(False)
    due = []  # (time, seq, datagram, peer)
    seq = 0
    n = 0
    while True:
        now = time.monotonic()
        while due and due[0][0] <= now:
            _, _, d, peer = heapq.heappop(due)
            try:
                s.sendto(d, peer)
            except OSError:
                pass
        tmo = max(0.0, due[0][0] - now) if due else 1.0
        r, _, _ = select.select([s], [], [], tmo)
        if not r:
            continue
        for _ in range(64):
            try:
                q, peer = s.recvfrom(4096)
            except BlockingIOError:
                break
            try:
                name, end = qname(q)
                qt = struct.unpack(">H", q[end:end + 2])[0]
            except (IndexError, struct.error):
                continue
            qd = q[12:end + 4]
            if name.endswith("pos.test"):
                ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1") if qt == 1 else b""
                rc = 0
            else:
                ans, rc = b"", 3
            hdr = struct.pack(">HHHHHH", struct.unpack(">H", q[:2])[0], 0x8180 | rc, 1, 1 if ans else 0, 0, 0)
            seq += 1
            n += 1
            heapq.heappush(due, (time.monotonic() + delay, seq, hdr + qd + ans, peer))


# ---- Wisp v1 client
def frame(payload):
    n = len(payload)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + b"\0\0\0\0" + payload  # zero mask: XOR is a no-op


def one_client(url, eport, conc, dur, warm, tag, wfd):
    host, port = url.split("//")[1].rstrip("/").rsplit(":", 1)
    s = socket.create_connection((host, int(port)))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    buf = bytearray(buf.partition(b"\r\n\r\n")[2])
    s.setblocking(False)
    out = bytearray()
    t_start = time.monotonic()
    t0, t1 = t_start + warm, t_start + warm + dur
    live = {}  # sid -> send time
    nxt = [1]
    lat, errs = [], 0

    def open_one(now):
        sid = nxt[0]
        nxt[0] += 1
        live[sid] = now
        out.extend(frame(struct.pack("<BIBH", 1, sid, 1, eport) + f"{tag}-{sid}.pos.test.".encode()))
        out.extend(frame(struct.pack("<BI", 2, sid) + b"ping"))

    now = time.monotonic()
    for _ in range(conc):
        open_one(now)
    while True:
        now = time.monotonic()
        if now >= t1:
            break
        if out:
            try:
                k = s.send(out)
                del out[:k]
            except BlockingIOError:
                pass
        r, w, _ = select.select([s], [s] if out else [], [], 0.05)
        if not r:
            continue
        try:
            d = s.recv(1 << 20)
        except BlockingIOError:
            continue
        if not d:
            raise SystemExit("server closed the WebSocket")
        buf += d
        now = time.monotonic()
        while len(buf) >= 2:
            ln, hl = buf[1] & 0x7F, 2
            if ln == 126:
                if len(buf) < 4:
                    break
                ln, hl = struct.unpack(">H", buf[2:4])[0], 4
            elif ln == 127:
                if len(buf) < 10:
                    break
                ln, hl = struct.unpack(">Q", buf[2:10])[0], 10
            if len(buf) < hl + ln:
                break
            op = buf[0] & 0x0F
            p = bytes(buf[hl:hl + ln])
            del buf[:hl + ln]
            if op != 2 or len(p) < 5:
                continue
            ty, sid = p[0], struct.unpack("<I", p[1:5])[0]
            if sid not in live:
                continue
            if ty == 2 or ty == 4:  # echo DATA (done) or a CLOSE from the server (error)
                st = live.pop(sid)
                if ty == 2:
                    if st >= t0:
                        lat.append(now - st)
                    out.extend(frame(struct.pack("<BIB", 4, sid, 2)))
                else:
                    if st >= t0:
                        errs += 1
                open_one(now)
    os.write(wfd, json.dumps({"lat": lat, "errs": errs, "dur": dur}).encode())
    os.close(wfd)


def client():
    url, eport = arg("--url"), arg("--target-port", type(0), int) if False else arg("--target-port", None, int)
    conc, dur, warm = arg("--conc", 8, int), arg("--dur", 5.0, float), arg("--warm", 1.0, float)
    tag, procs = arg("--tag", "x"), arg("--procs", 1, int)
    kids = []
    for i in range(procs):
        c = conc // procs + (1 if i < conc % procs else 0)
        rfd, wfd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(rfd)
            try:
                one_client(url, eport, c, dur, warm, f"{tag}-{i}", wfd)
            finally:
                os._exit(0)
        os.close(wfd)
        kids.append((pid, rfd))
    lat, errs = [], 0
    for pid, rfd in kids:
        data = b""
        while (d := os.read(rfd, 1 << 20)):
            data += d
        os.waitpid(pid, 0)
        if not data:
            raise SystemExit("a client process failed")
        j = json.loads(data)
        lat += j["lat"]
        errs += j["errs"]
    lat.sort()
    q = lambda f: round(lat[min(len(lat) - 1, int(f * len(lat)))] * 1000, 2) if lat else None
    print(json.dumps({"tag": tag, "conc": conc, "ops": len(lat), "rps": round(len(lat) / dur, 1), "p50": q(0.5),
                      "p99": q(0.99), "max": q(1.0), "errs": errs}), flush=True)


def patch():
    src, dst = sys.argv[2], sys.argv[3]
    b = open(src, "rb").read()
    old, new = b"/etc/resolv.conf\0", b"/tmp/b61dns.conf\0"
    n = b.count(old)
    if n == 0:
        raise SystemExit("no /etc/resolv.conf string")
    open(dst, "wb").write(b.replace(old, new))
    os.chmod(dst, 0o755)
    print(f"patched {n} occurrence(s) -> {dst}")


if __name__ == "__main__":
    {"stub": stub, "client": client, "patch": patch}[sys.argv[1]]()
