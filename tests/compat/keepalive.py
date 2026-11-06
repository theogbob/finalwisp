#!/usr/bin/env python3
# 40.14 (70.02) dead-peer detection, the live side: a client that stops reading a download (zero window)
# for --hold seconds must NOT be closed by the server (TCP keepalive does not run with data queued, and the
# server's TCP_INFO check needs unanswered probes: a live client ACKs every zero-window probe). Afterwards the
# client reads again and must get more DATA on the stream, then closes cleanly.
# usage: keepalive.py WS_PORT SOURCE_PORT [--hold SECS (default 600)] [--clients N (default 2)]
# SOURCE_PORT: a TCP target that sends without end (wbench target --mode source). Stdlib only.
import argparse, socket, struct, sys, threading, time
ap = argparse.ArgumentParser(); ap.add_argument("port", type=int); ap.add_argument("source", type=int)
ap.add_argument("--hold", type=float, default=600); ap.add_argument("--clients", type=int, default=2)
a = ap.parse_args()

def frame(p, op=0x2):
    n = len(p); h = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
    return h + b"\0\0\0\0" + p

class C:
    def __init__(s):
        s.s = socket.create_connection(("127.0.0.1", a.port), timeout=10); s.buf = b""
        s.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
        s.s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        while b"\r\n\r\n" not in s.buf:
            d = s.s.recv(4096)
            if not d: raise OSError("closed during the handshake")
            s.buf += d
        s.buf = s.buf.split(b"\r\n\r\n", 1)[1]
        s.s.sendall(frame(b"\x01" + struct.pack("<I", 1) + b"\x01" + struct.pack("<H", a.source) + b"127.0.0.1"))
    def read(s, nbytes, timeout):
        """DATA bytes of stream 1 until nbytes; returns (bytes, event) event = None | 'close' | 'eof' | 'timeout'"""
        s.s.settimeout(timeout); got = 0
        try:
            while got < nbytes:
                while len(s.buf) >= 2:
                    ln = s.buf[1] & 0x7f; hl = 2
                    if ln == 126:
                        if len(s.buf) < 4: break
                        ln = struct.unpack(">H", s.buf[2:4])[0]; hl = 4
                    elif ln == 127:
                        if len(s.buf) < 10: break
                        ln = struct.unpack(">Q", s.buf[2:10])[0]; hl = 10
                    if len(s.buf) < hl + ln: break
                    p = s.buf[hl:hl + ln]; op = s.buf[0] & 0xf; s.buf = s.buf[hl + ln:]
                    if op == 0x8: return got, "ws-close"
                    if op == 0x2 and p[:1] == b"\x02": got += len(p) - 5
                    elif op == 0x2 and p[:1] == b"\x04": return got, f"wisp-close {p[5] if len(p) > 5 else '?'}"
                    if got >= nbytes: return got, None
                d = s.s.recv(1 << 16)
                if not d: return got, "eof"
                s.buf += d
        except socket.timeout:
            return got, "timeout"
        except OSError as e:
            return got, f"error {e}"
        return got, None

res = []
def one(i):
    try:
        one_(i)
    except Exception as e:  # a failed client is a FAIL, not a missing row (review)
        res.append((i, (0, f"error {e}"), (0, "not run"), 0))
def one_(i):
    c = C()
    before = c.read(1 << 20, 10)
    t0 = time.time(); time.sleep(a.hold)  # zero window: the process is alive, the kernel ACKs the probes
    after = c.read(4 << 20, 30)
    res.append((i, before, after, round(time.time() - t0)))
    c.s.close()
ths = [threading.Thread(target=one, args=(i,)) for i in range(a.clients)]
[t.start() for t in ths]; [t.join() for t in ths]
ok = len(res) == a.clients and all(b[0] >= 1 << 20 and b[1] is None and af[0] >= 4 << 20 and af[1] is None for _, b, af, _ in res)
for r in res: print(("PASS" if r[1][1] is None and r[2][1] is None and r[2][0] >= 4 << 20 else "FAIL"), f"client {r[0]}: before {r[1]}, held {r[3]} s, after {r[2]}")
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
