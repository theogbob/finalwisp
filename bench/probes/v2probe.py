#!/usr/bin/env python3
"""v2probe (showdown 60.71): does a Wisp server answer a client that asks for Wisp v2 the way the spec says?
Sends a WebSocket upgrade with `Sec-WebSocket-Protocol: wisp-v2` (what the wisp-js client sends), prints the
response status, the Sec-WebSocket-Protocol answer header, and the first packet on stream 0 (v2: INFO type 0x05;
v1: CONTINUE 0x03). A WebSocket client that asked for a subprotocol must fail the handshake when the server does
not echo one (RFC 6455 4.1); wisp-js then retries as v1.
usage: v2probe.py PORT [--host 127.0.0.1] [--path /]   (loopback fixture only)"""
import argparse, base64, json, os, socket, struct

ap = argparse.ArgumentParser()
ap.add_argument("port", type=int)
ap.add_argument("--host", default="127.0.0.1")
ap.add_argument("--path", default="/")
a = ap.parse_args()
s = socket.create_connection((a.host, a.port), timeout=5)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((f"GET {a.path} HTTP/1.1\r\nHost: {a.host}:{a.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: wisp-v2\r\n\r\n").encode())
buf = b""
while b"\r\n\r\n" not in buf:
    d = s.recv(4096)
    if not d:
        break
    buf += d
head, _, rest = buf.partition(b"\r\n\r\n")
lines = head.decode(errors="replace").split("\r\n")
hdrs = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
out = {"status": lines[0], "sec_websocket_protocol": hdrs.get("sec-websocket-protocol")}
def frame():
    global rest
    while len(rest) < 2:
        rest += s.recv(4096)
    b1, b2 = rest[0], rest[1]
    n, off = b2 & 0x7f, 2
    if n == 126:
        while len(rest) < 4: rest += s.recv(4096)
        n, off = struct.unpack(">H", rest[2:4])[0], 4
    elif n == 127:
        while len(rest) < 10: rest += s.recv(4096)
        n, off = struct.unpack(">Q", rest[2:10])[0], 10
    while len(rest) < off + n:
        rest += s.recv(65536)
    p, rest = rest[off:off + n], rest[off + n:]
    return b1 & 0x0f, p
try:
    op, p = frame()
    out["first_ws_opcode"] = op
    if op == 2 and len(p) >= 5:
        t, sid = p[0], struct.unpack("<I", p[1:5])[0]
        out["first_packet"] = {3: "CONTINUE", 5: "INFO"}.get(t, hex(t))
        out["first_packet_stream"] = sid
        if t == 5 and len(p) >= 7:
            out["info_version"] = f"{p[5]}.{p[6]}"
except (socket.timeout, OSError) as e:
    out["first_packet"] = f"none ({e.__class__.__name__})"
out["v2_per_spec"] = bool(out.get("sec_websocket_protocol")) and out.get("first_packet") == "INFO"
print(json.dumps(out))
