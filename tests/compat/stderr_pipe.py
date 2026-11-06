#!/usr/bin/env python3
# 40.13 runtime log write to a dead stderr pipe (60.05 H3): the server logs memory level changes at runtime. With
# its stderr a pipe whose reader is gone, base-1's eprintln! panicked on EPIPE (panic = abort: the whole server).
# usage: stderr_pipe.py BIN PORT
import os, socket, struct, subprocess, sys, time, base64
BIN, PORT = sys.argv[1], int(sys.argv[2])
p = subprocess.Popen([BIN, "--port", str(PORT), "--allow-loopback", "--threads", "1", "--mem-budget", "32M"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
line = p.stderr.readline()  # startup line(s) are written before the pipe dies
time.sleep(0.3)
p.stderr.close()  # the log reader is gone: the next write gets EPIPE (SIGPIPE is ignored by the server)
def ws():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=3)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    return s
hold = []
blk = os.urandom(1 << 20)
for i in range(24):  # 24 x ~3 MiB of unfinished frames > 32 MiB budget: the level rises and is logged
    try:
        s = ws(); s.settimeout(0.5)
        s.sendall(bytes([0x82, 0xff]) + struct.pack(">Q", 4 << 20) + b"\0\0\0\0")
        for _ in range(3): s.sendall(blk)
        hold.append(s)
    except OSError:
        pass
time.sleep(2)
for s in hold: s.close()  # end the pressure first: at level 2+ a new connection is not admitted
time.sleep(0.5)
alive = p.poll() is None
try:
    s = ws(); s.settimeout(3); alive = alive and s.recv(4096).startswith(b"HTTP/1.1 101"); s.close()
except OSError:
    pass  # not admitted yet (pressure): liveness is p.poll(); the panic this test is about aborts the process
alive = alive and p.poll() is None
print(("PASS" if alive else "FAIL") + f" server survives a runtime log line to a dead stderr pipe (exit {p.poll()}, held {len(hold)})")
if p.poll() is None:
    p.terminate()
p.wait()
sys.exit(0 if alive else 1)
