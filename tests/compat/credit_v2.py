#!/usr/bin/env python3
"""20.30 credit v2 compat: Wisp v1 upload clients of every ping behaviour against a finalwisp with credit v2 (the default since 60.13).
Each case uploads N packets of 16 KiB on 2 streams to a local counting sink, strictly within its credit (absolute
CONTINUE: credit = value), and checks: every byte arrives, no CLOSE, no WS close.
Cases: pong (answers pings at once), nopong (never answers: base-2 rule), eager (sends its credit inside the CONTINUE
handler, before it answers the ping that follows: wisp-js 0.5.0 does this; it deadlocked an early v2), foreign (also
sends unsolicited pongs with junk payloads). Stdlib only.
usage: credit_v2.py FINALWISP_BIN PORT"""
import json, os, select, socket, struct, subprocess, sys, threading, time

BIN, PORT = sys.argv[1], int(sys.argv[2])
N_ALL, N_EAGER, SZ = 3000, 9000, 16384  # eager: long enough to run mostly under v2 grants
PONG_DELAY = 0.04  # eager client: on loopback a prompt pong makes the server's in-flight estimate ~0, which hides a
                   # missing liveness probe (review P2: the case passed with the probe compiled out)
fails = 0


def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += not c


got = {}


def sink(ls):
    while True:
        try:
            c, _ = ls.accept()
        except OSError:
            return
        def rd(c=c):
            port = c.getpeername()[1]
            n = 0
            while True:
                try:
                    d = c.recv(1 << 20)
                except OSError:  # (the server resets targets at stream close: Wisp CLOSE 0x02)
                    break
                if not d:
                    break
                n += len(d)
                got[port] = n
            c.close()
        threading.Thread(target=rd, daemon=True).start()


def frame(op, payload):
    n = len(payload)
    h = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
    return h + b"\0\0\0\0" + payload


def wisp(ty, sid, body=b""):
    return frame(2, bytes([ty]) + struct.pack("<I", sid) + body)


def run(case, sink_port):
    N = N_EAGER if case == "eager" else N_ALL
    s = socket.create_connection(("127.0.0.1", PORT))
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    buf = buf.split(b"\r\n\r\n", 1)[1]
    s.setblocking(False)
    out = bytearray()
    credit, sent, closed, pings, pongs_sent = {}, {1: 0, 2: 0}, {}, 0, 0
    data = b"\x07" * SZ
    state = {"init": False, "wsclosed": False}
    late = []  # eager: (due, payload) pongs answered PONG_DELAY late

    def send_some():
        for st in (1, 2):
            while credit.get(st, 0) > 0 and sent[st] < N:
                out.extend(wisp(2, st, data))
                credit[st] -= 1
                sent[st] += 1

    def parse():
        nonlocal buf, pings, pongs_sent
        while len(buf) >= 2:
            n, o = buf[1] & 0x7F, 2
            if n == 126:
                if len(buf) < 4:
                    return
                n, o = struct.unpack(">H", buf[2:4])[0], 4
            elif n == 127:
                if len(buf) < 10:
                    return
                n, o = struct.unpack(">Q", buf[2:10])[0], 10
            if len(buf) < o + n:
                return
            op, p, buf = buf[0] & 0x0F, buf[o:o + n], buf[o + n:]
            if op == 9:
                pings += 1
                if case == "eager":
                    late.append((time.time() + PONG_DELAY, p))  # (a slow event loop: the RTT seen by the server is real)
                elif case != "nopong":
                    out.extend(frame(10, p))
                    pongs_sent += 1
                if case == "foreign":
                    out.extend(frame(10, b"junk")); out.extend(frame(10, struct.pack("<Q", 99999)))
            elif op == 8:
                state["wsclosed"] = True
            elif op == 2 and len(p) >= 5:
                ty, sid = p[0], struct.unpack("<I", p[1:5])[0]
                if ty == 3:
                    v = struct.unpack("<I", p[5:9])[0]
                    if sid == 0 and not state["init"]:
                        state["init"] = True
                        for st in (1, 2):
                            out.extend(wisp(1, st, b"\x01" + struct.pack("<H", sink_port) + b"127.0.0.1"))
                            credit[st] = v
                    else:
                        credit[sid] = v
                    if case == "eager":
                        send_some()  # inside the CONTINUE handler, before the ping after it is read (wisp-js)
                elif ty == 4:
                    closed[sid] = p[5] if len(p) > 5 else -1
    parse()  # the stream-0 CONTINUE can arrive in the same read as the 101 response
    end = time.time() + 60
    while time.time() < end and not state["wsclosed"] and (sent[1] < N or sent[2] < N or out):
        while late and late[0][0] <= time.time():
            out.extend(frame(10, late.pop(0)[1]))
            pongs_sent += 1
        if state["init"]:
            send_some()
        r, w, _ = select.select([s], [s] if out else [], [], 0.05)
        if r:
            try:
                d = s.recv(1 << 20)
                if not d:
                    break
                buf += d
                parse()
            except BlockingIOError:
                pass
        if w and out:
            try:
                del out[:s.send(out)]
            except BlockingIOError:
                pass
    time.sleep(1.0)
    total = sum(got.get(p, 0) for p in list(got))
    s.close()
    return sent, closed, pings, pongs_sent, state["wsclosed"], total


ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", 0)); ls.listen(16)
threading.Thread(target=sink, args=(ls,), daemon=True).start()
srv = subprocess.Popen([BIN, "--port", str(PORT), "--allow-loopback", "--threads", "2"],  # credit v2 is the default (60.13)
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
try:
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", PORT), 0.2).close(); break
        except OSError:
            time.sleep(0.05)
    for case in ("pong", "nopong", "eager", "foreign"):
        got.clear()
        sent, closed, pings, pongs, wsc, total = run(case, ls.getsockname()[1])
        N = N_EAGER if case == "eager" else N_ALL
        want = 2 * N * SZ
        ok(sent == {1: N, 2: N} and total == want and not closed and not wsc,
           f"{case}: sent {sent[1] + sent[2]}/{2 * N} packets, sink got {total}/{want} bytes, closes {closed}, ws closed {wsc}, pings {pings}, pongs {pongs}")
        if case == "pong":
            ok(pings > 0, f"{case}: the server pings after CONTINUE ({pings})")
finally:
    srv.terminate()
    err = srv.communicate(timeout=10)[1]
ok("upload credit v2" in err, "the startup line names upload credit v2")
print("ALL PASS" if not fails else f"{fails} FAILURES")
sys.exit(1 if fails else 0)
