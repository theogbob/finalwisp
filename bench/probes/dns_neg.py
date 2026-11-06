#!/usr/bin/env python3
"""20.23 negative DNS cache check: one Wisp v1 connection; for each name kind, REPS sequential CONNECT + DATA to
the SAME fresh name, GAP_MS apart; time until the stream answers (DATA back) or gets CLOSE (reason recorded).
Kinds (bench/vps/slowdns.py suffixes): nxd = NXDOMAIN after the resolver delay (cacheable), sf = SERVFAIL
(EAI_AGAIN: must NOT be cached), ok = resolves (positive cache sanity), nxexp = NXDOMAIN, then again after
EXPIRE_S (the negative entry must have expired: a fresh lookup), long = a 304-byte name (refused at once, 0x42).
usage: dns_neg.py WS_HOST:PORT TARGET_PORT REPS GAP_MS EXPIRE_S -> JSON line"""
import json, socket, struct, sys, time
wh, wp = sys.argv[1].rsplit(":", 1); tp = int(sys.argv[2]); reps = int(sys.argv[3]); gap = float(sys.argv[4]) / 1000; expire = float(sys.argv[5])
def frame(p):
    n = len(p); h = bytes([0x82])
    h += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n)
    return h + b"\0\0\0\0" + p
s = socket.create_connection((wh, int(wp))); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf: buf += s.recv(4096)
buf = buf.split(b"\r\n\r\n", 1)[1]
def read_msg(timeout=30.0):
    global buf
    s.settimeout(timeout)
    while True:
        if len(buf) >= 2:
            ln, hl = buf[1] & 0x7f, 2  # 30.10: 16- and 64-bit lengths (was: 127 read as a 127-byte frame)
            if ln == 126: ln, hl = (struct.unpack(">H", buf[2:4])[0], 4) if len(buf) >= 4 else (None, 4)
            elif ln == 127: ln, hl = (struct.unpack(">Q", buf[2:10])[0], 10) if len(buf) >= 10 else (None, 10)
            if ln is not None and len(buf) >= hl + ln:
                op, p = buf[0] & 0x0f, buf[hl:hl + ln]; buf = buf[hl + ln:]
                return op, p
        d = s.recv(65536)
        if not d: raise EOFError
        buf += d
sid = 1
def one(host):
    global sid
    me = sid; sid += 1
    t0 = time.perf_counter()
    s.sendall(frame(b"\x01" + struct.pack("<I", me) + b"\x01" + struct.pack("<H", tp) + host.encode()) + frame(b"\x02" + struct.pack("<I", me) + b"ping"))
    while True:
        op, p = read_msg()
        if op != 2 or len(p) < 5 or struct.unpack("<I", p[1:5])[0] != me: continue
        if p[0] == 2:
            s.sendall(frame(b"\x04" + struct.pack("<I", me) + b"\x02")); return round((time.perf_counter() - t0) * 1000, 2), "data"
        if p[0] == 4: return round((time.perf_counter() - t0) * 1000, 2), hex(p[5])
rid = int(time.time() * 1000) % 10_000_000
out = {}
for kind, suf in (("nxd", "nxd"), ("sf", "sf"), ("ok", "slow")):
    host = f"n{rid}.{suf}"; r = []
    for _ in range(reps):
        r.append(one(host)); time.sleep(gap)
    out[kind] = r
host = f"e{rid}.nxd"; first = one(host); time.sleep(expire); out["nxexp"] = [first, one(host)]
out["long"] = [one("a" * 300 + ".nxd") for _ in range(3)]  # review 20.23: over 255 bytes, refused before DNS
print(json.dumps(out))
