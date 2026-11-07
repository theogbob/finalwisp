#!/usr/bin/env python3
"""60.42 write-all-then-read client (deadlock check for credit pacing). One Wisp v1 stream to an echo target: the app
writes N bytes (within credit), then reads N back. The Wisp "library" reads the socket only while its buffered,
unread DATA is < Q bytes (a bounded stream queue: backpressure by not reading the socket; Q=0 = unbounded).
usage: writeall.py WSPORT ECHOPORT N Q [TIMEOUT]   prints OK secs / STALL got_up got_down"""
import os, select, socket, struct, sys, time
wsport, eport, N, Q = (int(x) for x in sys.argv[1:5]); TO = float(sys.argv[5]) if len(sys.argv) > 5 else 20
s = socket.create_connection(("127.0.0.1", wsport))
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf:
    buf += s.recv(4096)
buf = buf.split(b"\r\n\r\n", 1)[1]
def frame(p):
    n = len(p); h = bytes([0x82])
    h += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else bytes([0x80 | 127]) + struct.pack(">Q", n)
    return h + b"\0\0\0\0" + p  # zero mask key: payload unchanged
s.setblocking(False)
credit = None; sid = 1
out = bytearray(); up = down = 0; rxq = 0; chunk = os.urandom(16384)
def parse():
    global buf, credit, down, rxq
    while len(buf) >= 2:
        n = buf[1] & 0x7F; o = 2
        if n == 126:
            if len(buf) < 4: return
            n = struct.unpack(">H", buf[2:4])[0]; o = 4
        elif n == 127:
            if len(buf) < 10: return
            n = struct.unpack(">Q", buf[2:10])[0]; o = 10
        if len(buf) < o + n: return
        op, p = buf[0] & 0x0F, buf[o:o + n]; buf = buf[o + n:]
        if op == 9:
            out.extend(bytes([0x8A, 0x80 | len(p)]) + b"\0\0\0\0" + p)
        if op != 2: continue
        t, st = p[0], struct.unpack("<I", p[1:5])[0]
        if t == 3:
            credit = struct.unpack("<I", p[5:9])[0] if st == 0 and credit is None else (struct.unpack("<I", p[5:9])[0] if st == sid else credit)
        elif t == 2 and st == sid:
            down += len(p) - 5; rxq += len(p) - 5
        elif t == 4:
            print("CLOSED", p[5]); sys.exit(2)
parse()
t0 = time.time(); connected = False; app_reading = False
while down < N:
    if time.time() - t0 > TO:
        print(f"STALL up={up} down={down} credit={credit} rxq={rxq}"); sys.exit(1)
    if credit is not None and not connected:
        out.extend(frame(bytes([1]) + struct.pack("<I", sid) + bytes([1]) + struct.pack("<H", eport) + b"127.0.0.1")); connected = True
    while connected and up < N and credit and len(out) < 65536:
        k = min(16384, N - up); out.extend(frame(bytes([2]) + struct.pack("<I", sid) + chunk[:k])); up += k; credit -= 1
    if up >= N:
        app_reading = True; rxq = 0
    want_r = Q == 0 or app_reading or rxq < Q
    r, w, _ = select.select([s] if want_r else [], [s] if out else [], [], 0.05)
    if w:
        try:
            k = s.send(out); del out[:k]
        except BlockingIOError: pass
    if r:
        d = s.recv(1 << 20)
        if not d: print("EOF"); sys.exit(2)
        buf += d; parse()
print(f"OK {time.time() - t0:.2f}s")
