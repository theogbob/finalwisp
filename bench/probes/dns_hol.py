#!/usr/bin/env python3
"""30.09 (20.19) DNS pool head-of-line: one Wisp v1 connection; per round, S CONNECTs to a fresh name whose
lookup stalls (SUFFIX_SLOW, e.g. .slow3 = 3 s in slowdns.py), then one CONNECT + request to a fresh fast name
(.slow); reports the fast stream's latency (how long the stalled lookups block the resolver pool) and, for
SUFFIX_SLOW=.nx, that every stalled stream gets its own CLOSE (failure fan-out).
usage: dns_hol.py WS_HOST:PORT TARGET_PORT ROUNDS S SUFFIX_SLOW SUFFIX_FAST -> JSON line"""
import json, socket, statistics as st, struct, sys, time
wh, wp = sys.argv[1].rsplit(":", 1); tp = int(sys.argv[2]); rounds, S = int(sys.argv[3]), int(sys.argv[4])
slow, fast = sys.argv[5], sys.argv[6]
def frame(p):
    n = len(p); h = bytes([0x82])
    h += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n)
    return h + b"\0\0\0\0" + p
s = socket.create_connection((wh, int(wp))); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf: buf += s.recv(4096)
buf = buf.split(b"\r\n\r\n", 1)[1]
def read_msg(timeout=20.0):
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
run_id = int(time.time() * 1000) % 10_000_000
req = struct.pack("<II", 64, 64) + b"x" * 56
fast_lat, closes, sid = [], 0, 1
for r in range(rounds):
    out = b""; slow_ids = set()
    host = f"s{r}-{run_id}.{slow}".encode()
    for _ in range(S):
        out += frame(b"\x01" + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", tp) + host) + frame(b"\x02" + struct.pack("<I", sid) + req)
        slow_ids.add(sid); sid += 1
    fid = sid; sid += 1
    out += frame(b"\x01" + struct.pack("<I", fid) + b"\x01" + struct.pack("<H", tp) + f"f{r}-{run_id}.{fast}".encode()) + frame(b"\x02" + struct.pack("<I", fid) + req)
    t0 = time.perf_counter(); s.sendall(out); got_fast = False
    while slow_ids or not got_fast:
        try:
            op, p = read_msg()
        except socket.timeout:
            break
        if op != 2 or len(p) < 5: continue
        i = struct.unpack("<I", p[1:5])[0]
        if i == fid and p[0] in (2, 4):
            if not got_fast: fast_lat.append((time.perf_counter() - t0) * 1000); got_fast = True
        elif i in slow_ids and p[0] in (2, 4):
            slow_ids.discard(i)
            if p[0] == 4: closes += 1
    for i in range(fid - S, fid + 1): s.sendall(frame(b"\x04" + struct.pack("<I", i) + b"\x02"))
print(json.dumps({"rounds": rounds, "stalled_per_round": S, "fast_p50_ms": round(st.median(fast_lat), 1) if fast_lat else None,
                  "fast_max_ms": round(max(fast_lat), 1) if fast_lat else None, "stalled_closes": closes}))
