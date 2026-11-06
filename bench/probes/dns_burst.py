#!/usr/bin/env python3
"""30.09 (20.19) DNS burst latency: one Wisp v1 connection; per round, H fresh host names x S streams each
(CONNECT + one request in a single write, like a page load), time until every stream answered.
Names: h{round}-{k}-{run id}.SUFFIX (never repeated, so every round misses the server's cache).
usage: dns_burst.py WS_HOST:PORT TARGET_PORT ROUNDS HOSTS STREAMS SUFFIX  -> JSON line"""
import json, socket, statistics as st, struct, sys, time
wh, wp = sys.argv[1].rsplit(":", 1); tp = int(sys.argv[2]); rounds, H, S = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
suffix = sys.argv[6]
def frame(p):
    n = len(p); h = bytes([0x82])
    h += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n)
    return h + b"\0\0\0\0" + p
s = socket.create_connection((wh, int(wp))); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf: buf += s.recv(4096)
buf = buf.split(b"\r\n\r\n", 1)[1]
def read_msg():
    global buf
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
run_id = int(time.time() * 1000) % 10_000_000
req = struct.pack("<II", 64, 64) + b"x" * 56  # reply target: 64-byte request -> 64-byte response
lat, fails, first = [], 0, []
sid = 1
for r in range(rounds):
    out = b""; ids = set()
    for k in range(H):
        host = f"h{r}-{k}-{run_id}.{suffix}".encode()
        for _ in range(S):
            out += frame(b"\x01" + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", tp) + host) + frame(b"\x02" + struct.pack("<I", sid) + req)
            ids.add(sid); sid += 1
    t0 = time.perf_counter(); s.sendall(out); t1 = None
    while ids:
        op, p = read_msg()
        if op != 2 or len(p) < 5: continue
        i = struct.unpack("<I", p[1:5])[0]
        if i not in ids: continue
        if p[0] == 2:
            ids.discard(i)
            if t1 is None: t1 = time.perf_counter()
        elif p[0] == 4: ids.discard(i); fails += 1
    lat.append((time.perf_counter() - t0) * 1000); first.append((t1 - t0) * 1000 if t1 else None)
    for i in range(sid - H * S, sid): s.sendall(frame(b"\x04" + struct.pack("<I", i) + b"\x02"))
    time.sleep(0.05)
q = sorted(lat); f = sorted(x for x in first if x is not None)
print(json.dumps({"rounds": rounds, "hosts": H, "streams": S, "fails": fails, "all_p50_ms": round(st.median(q), 1),
                  "all_max_ms": round(q[-1], 1), "first_p50_ms": round(st.median(f), 1) if f else None}))
