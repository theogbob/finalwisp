#!/usr/bin/env python3
# 40.14 (70.02) dead-peer detection, the dead side. Needs the root nft table from ka-nft.sh (up) for the server port.
# Opens --idle idle Wisp connections and --dl connections with an unread download (SOURCE_PORT: a target that sends
# without end), lets the downloads fill the queues, then marks every connection (IP_TOS 0x28 + one WS ping): nft drops
# all its later packets both ways. The client sockets stay open (a close would send FIN/RST). Polls `ss` for the
# server-side sockets (sport = WS_PORT) and reports when each one disappears.
# Expect (default keepalive): idle gone at ~180 s (120 s + 4 x 15 s), download gone at ~150-155 s (TCP_INFO check).
# 70.07 --tls: the connections use TLS (server with --tls-cert/--tls-key; kTLS needs the `tls` module): checks that
# every server socket is kTLS (ss: tcp-ulp-tls) before the cut; --pid: the server's open fds are back at their
# count before the test once all are gone (a reset socket is closed, not kept by the TLS ULP).
# usage: keepalive_dead.py WS_PORT SOURCE_PORT [--idle 3] [--dl 3] [--limit 400] [--tls] [--pid PID]
import argparse, os, socket, ssl, struct, subprocess, sys, time
ap = argparse.ArgumentParser(); ap.add_argument("port", type=int); ap.add_argument("source", type=int)
ap.add_argument("--idle", type=int, default=3); ap.add_argument("--dl", type=int, default=3)
ap.add_argument("--limit", type=float, default=400); ap.add_argument("--expect", default="on", choices=["on", "off"])
ap.add_argument("--tls", action="store_true"); ap.add_argument("--pid", type=int)
a = ap.parse_args()
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
fds = lambda: len(os.listdir(f"/proc/{a.pid}/fd"))
fd0 = fds() if a.pid else None

def frame(p, op=0x2):
    n = len(p); h = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
    return h + b"\0\0\0\0" + p

def conn(dl):
    s = socket.create_connection(("127.0.0.1", a.port), timeout=10); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
    if a.tls:
        s = ctx.wrap_socket(s, server_hostname="localhost")
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    b = b""
    while b"\r\n\r\n" not in b:
        d = s.recv(4096)
        if not d: raise OSError("closed during the handshake")
        b += d
    if dl:
        s.sendall(frame(b"\x01" + struct.pack("<I", 1) + b"\x01" + struct.pack("<H", a.source) + b"127.0.0.1"))
    return s

def server_ports():
    out = subprocess.run(["ss", "-tnH", "state", "all", f"( sport = :{a.port} )"], capture_output=True, text=True).stdout
    return {int(l.split()[-1].rsplit(":", 1)[1]) for l in out.splitlines() if l.strip() and "LISTEN" not in l.split()[0]}

socks = {"idle": [conn(False) for _ in range(a.idle)], "dl": [conn(True) for _ in range(a.dl)]}
time.sleep(3)  # downloads fill the server's queues; the clients never read
ports = {k: [s.getsockname()[1] for s in v] for k, v in socks.items()}
if a.tls:
    out = subprocess.run(["ss", "-tniH", "state", "established", f"( sport = :{a.port} )"], capture_output=True, text=True).stdout
    nk = out.count("tcp-ulp-tls")
    print(f"server sockets with the kTLS ULP: {nk} of {sum(len(v) for v in ports.values())}")
    if nk != sum(len(v) for v in ports.values()):
        print("FAILURES (not kTLS)"); sys.exit(1)
for v in socks.values():
    for s in v:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x28)
        s.sendall(frame(b"bye", 0x9))  # marks the connection: this packet and everything after is dropped
t0 = time.time(); gone = {}
while time.time() - t0 < a.limit:
    live = server_ports()
    for k, ps in ports.items():
        for p in ps:
            if p not in live and p not in gone: gone[p] = round(time.time() - t0)
    if len(gone) == sum(len(v) for v in ports.values()): break
    time.sleep(2)
res = {k: [gone.get(p) for p in ps] for k, ps in ports.items()}
print(f"seconds until the server dropped each connection (None = still open after {a.limit:.0f} s): {res}")
if a.expect == "on":
    ok = all(t is not None and 170 <= t <= 200 for t in res["idle"]) and all(t is not None and 145 <= t <= 200 for t in res["dl"])
else:
    ok = all(t is None for v in res.values() for t in v)
if a.pid and a.expect == "on":
    time.sleep(1)
    n = fds(); print(f"server fds: {fd0} before, {n} after"); ok = ok and n <= fd0
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
