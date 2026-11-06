#!/usr/bin/env python3
"""30.07 connect latency: time from CONNECT+first DATA (sent in one write) to the first echoed byte, one new
target connection per sample, sequential. What happy eyeballs (20.14) and TCP Fast Open (20.15) change.
Usage: connect_latency.py WS_HOST:PORT TARGET_HOST TARGET_PORT N [tls|plain]  -> JSON line"""
import json, os, socket, statistics as st, struct, sys, time
wh, wp = sys.argv[1].rsplit(":", 1); th, tp, n = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
kind = sys.argv[5] if len(sys.argv) > 5 else "tls"
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
payload = (b"\x16\x03\x01\x01\xfc\x01" + os.urandom(507)) if kind == "tls" else (b"GET / HTTP/1.1\r\n" + b"x" * 496)
lat, fails = [], 0
for i in range(n):
    sid = 100 + i
    t0 = time.perf_counter()
    s.sendall(frame(b"\x01" + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", tp) + th.encode())
              + frame(b"\x02" + struct.pack("<I", sid) + payload))
    while True:
        op, p = read_msg()
        if op != 2 or len(p) < 5 or struct.unpack("<I", p[1:5])[0] != sid: continue
        if p[0] == 2: lat.append((time.perf_counter() - t0) * 1000); break
        if p[0] == 4: fails += 1; break
    s.sendall(frame(b"\x04" + struct.pack("<I", sid) + b"\x02"))
    time.sleep(0.02)
q = sorted(lat)
print(json.dumps({"kind": kind, "n": len(lat), "fails": fails, "p50_ms": round(st.median(q), 1) if q else None,
                  "min_ms": round(q[0], 1) if q else None, "p90_ms": round(q[int(len(q) * 0.9) - 1], 1) if q else None}))
