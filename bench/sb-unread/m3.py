#!/usr/bin/env python3
"""60.78 T2 (sb-unread) M3: the abuse shapes (fill F then stop, S streams unread, trickle): what each costs the server host and the client. Stdlib only.
usage: m1.py FINALWISP_BINARY BASEPORT SECS OUTFILE
One finalwisp per shape (port BASEPORT+2+i, --threads 1), one endless TCP source on BASEPORT+1 (each accepted socket
gets 64 KiB blocks without end). Shape = (name, streams, client SO_RCVBUF (0 = autotuned), bytes read per s after
the 101 (0 = never), seconds read at full speed first). Every 10 s: for each server, `ss -tmi` of its process: per
socket rmem_alloc (r), wmem_queued (w), notsent bytes; summed for the client sockets and the target sockets. Raw lines:
'S t shape cli_r cli_w cli_notsent tgt_r tgt_w nsock' and the client side 'C t shape taken client_rcvq'."""
import base64, fcntl, termios, os, re, socket, struct, subprocess, sys, threading, time
BIN, BASE, SECS, OUT = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
SRC = BASE + 1
# M3: the 5th field is the bytes read at full speed first (not seconds); rate 0 = nothing after it
SHAPES = [("fill1m", 1, 0, 0, 1 << 20), ("fill8m", 1, 0, 0, 8 << 20), ("fill16m", 1, 0, 0, 16 << 20), ("fill64m", 1, 0, 0, 64 << 20),
          ("noread_s1", 1, 0, 0, 0), ("noread_s16", 16, 0, 0, 0), ("noread_s64", 64, 0, 0, 0), ("trickle_rcv4k", 1, 4096, 8, 0)]
out = open(OUT, "w")
def log(s):
    out.write(s + "\n"); out.flush()
blob = b"x" * 65536
def feed(c):
    try:
        while True: c.sendall(blob)
    except OSError: pass
src = socket.socket(); src.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); src.bind(("127.0.0.1", SRC)); src.listen(256)
def acc():
    while True:
        c, _ = src.accept(); threading.Thread(target=feed, args=(c,), daemon=True).start()
threading.Thread(target=acc, daemon=True).start()
procs = []
for i, sh in enumerate(SHAPES):
    p = subprocess.Popen([BIN, str(BASE + 2 + i), "--allow-loopback", "--threads", "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
time.sleep(1.0)
def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))
taken = {}
inq = {}
def client(i, name, streams, rcv, rate, fast):
    s = socket.socket()
    if rcv: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcv)
    s.connect(("127.0.0.1", BASE + 2 + i))
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
              + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(1)
    for sid in range(1, streams + 1):
        s.sendall(frame(bytes([1]) + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", SRC) + b"127.0.0.1"))
    t0 = time.time(); got = 0; s.settimeout(0.2)
    while time.time() - t0 < SECS + 5:
        el = time.time() - t0
        want = (fast - got) if got < fast else (int(el * rate) - (got - fast) if rate else 0)
        if want > 0:
            try:
                d = s.recv(min(want, 1 << 20))
                if not d: break
                got += len(d)
            except socket.timeout: pass
        else: time.sleep(0.05)
        taken[name] = got
        inq[name] = struct.unpack("i", fcntl.ioctl(s.fileno(), termios.FIONREAD, b"\0\0\0\0"))[0]
    s.close()
for i, sh in enumerate(SHAPES):
    threading.Thread(target=client, args=(i, *sh), daemon=True).start()
def ss(pid):
    o = subprocess.run(["ss", "-tmipnH"], capture_output=True, text=True).stdout
    # one socket = a line with users:(...pid=PID...) and the indented lines after it
    socks, cur = [], None
    for line in o.splitlines():
        if not line.startswith((" ", "\t")):
            cur = line; socks.append([line, ""])
        elif socks: socks[-1][1] += line
    res = []
    for head, det in socks:
        if f"pid={pid}," not in head: continue
        f = head.split()
        m = re.search(r"skmem:\(r(\d+),rb\d+,t\d+,tb\d+,f\d+,w(\d+)", det)
        ns = re.search(r"notsent:(\d+)", det)
        if m: res.append((f[3], f[4], int(m.group(1)), int(m.group(2)), int(ns.group(1)) if ns else 0))
    return res
t0 = time.time(); nxt = 10
while time.time() - t0 < SECS:
    time.sleep(0.5)
    if time.time() - t0 < nxt: continue
    nxt += 10
    for i, sh in enumerate(SHAPES):
        cr = cw = cn = tr = tw = n = 0
        for loc, peer, r, w, ns in ss(procs[i].pid):
            if loc.endswith(f":{BASE + 2 + i}"): cr += r; cw += w; cn += ns; n += 1
            elif peer.endswith(f":{SRC}"): tr += r; tw += w; n += 1
        log(f"S {time.time() - t0:.0f} {sh[0]} {cr} {cw} {cn} {tr} {tw} {n}")
        log(f"C {time.time() - t0:.0f} {sh[0]} {taken.get(sh[0], 0)} {inq.get(sh[0], 0)}")
for p in procs: p.terminate()
for p in procs: p.wait(10)
log("end")
