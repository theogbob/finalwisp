#!/usr/bin/env python3
# 40.12 big-frame hold stress (60.05 H2 follow-up; functional, laptop, not a benchmark).
# N WebSocket clients finish the Wisp v1 handshake (101 + CONTINUE(0)), then each starts a frame of FRAME bytes and
# streams all but the last ~100 KiB as fast as loopback allows, then stalls forever (never finishes it).
#   mode "frame": one 10 MiB DATA frame (rbuf path);  mode "frag": a non-FIN BIN frame + 64 KiB continuation
#   fragments (reassembly path, Client::frag).
# Reports: peak server VmRSS (sampled every 20 ms) vs the budget, levels the server logged (with times), holders shed,
# an honest client that downloads 64 MiB every 2 s during the push + stall (5 s handshake timeout), and one after it.
# usage: bigframe_stress.py BIN PORT MODE OUTLOG [--mem-budget 256M | --cgroup 256M] [--n 1000]
import os, socket, struct, sys, time, base64, selectors, subprocess, threading, errno, json
BIN, PORT, MODE, OUTLOG = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
args = sys.argv[5:]
N = int(args[args.index("--n") + 1]) if "--n" in args else 1000
BUDGET = args[args.index("--mem-budget") + 1] if "--mem-budget" in args else None
FRAME = 10 << 20
SEND = FRAME - (100 << 10)
DL = 64 << 20
CGROUP = args[args.index("--cgroup") + 1] if "--cgroup" in args else None  # MemoryMax of a user scope (no --mem-budget)
srv_args = [BIN, "--port", str(PORT), "--allow-loopback"] + (["--mem-budget", BUDGET] if BUDGET else [])
if CGROUP:
    srv_args = ["systemd-run", "--user", "--scope", "-q", f"--unit=fw-bigframe-{PORT}-{os.getpid()}", "-p", f"MemoryMax={CGROUP}",
                "-p", "MemorySwapMax=0"] + srv_args
srv = subprocess.Popen(srv_args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
T0 = time.time(); levels = []
def errlog():
    for l in srv.stderr:
        levels.append(f"{time.time() - T0:6.2f}s {l.strip()}")
threading.Thread(target=errlog, daemon=True).start()
time.sleep(0.7)

peak = [0]; samples = []; stop = threading.Event()
def rss_kib():
    try:
        return next(int(l.split()[1]) for l in open(f"/proc/{srv.pid}/status") if l.startswith("VmRSS"))
    except (OSError, StopIteration):
        return None
def sampler():
    while not stop.is_set():
        r = rss_kib()
        if r is None: break
        peak[0] = max(peak[0], r); samples.append((round(time.time() - T0, 2), r >> 10))
        time.sleep(0.02)
threading.Thread(target=sampler, daemon=True).start()

# 64 MiB source for the honest client
src = socket.socket(); src.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
src.bind(("127.0.0.1", 0)); src.listen(16); SRC_PORT = src.getsockname()[1]
blk = os.urandom(1 << 20)
def src_loop():
    while True:
        try: c, _ = src.accept()
        except OSError: return
        def feed(c=c):
            try:
                for _ in range(DL >> 20): c.sendall(blk)
            except OSError: pass
            c.close()
        threading.Thread(target=feed, daemon=True).start()
threading.Thread(target=src_loop, daemon=True).start()

def upgrade(s):
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf or len(buf.partition(b"\r\n\r\n")[2]) < 11:  # 101 + CONTINUE(0) frame (2 + 9)
        d = s.recv(4096)
        if not d: raise OSError("closed during handshake")
        buf += d
    return buf.startswith(b"HTTP/1.1 101")
def hdr(op, n, fin=True):
    b0 = (0x80 if fin else 0) | op
    if n < 126: h = bytes([b0, 0x80 | n])
    elif n < 65536: h = bytes([b0, 0x80 | 126]) + struct.pack(">H", n)
    else: h = bytes([b0, 0x80 | 127]) + struct.pack(">Q", n)
    return h + b"\0\0\0\0"  # mask key 0: payload sent as is
def honest(tag, res, hs_timeout=10):
    t0 = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=hs_timeout)
        if not upgrade(s): res[tag] = ("no 101", time.time() - t0); return
        t_hs = time.time() - t0
        p = b"\x01" + struct.pack("<I", 1) + b"\x01" + struct.pack("<H", SRC_PORT) + b"127.0.0.1"
        s.sendall(hdr(0x2, len(p)) + p)
        got = 0; buf = bytearray(); s.settimeout(30)
        while got < DL:
            d = s.recv(1 << 20)
            if not d: break
            buf += d
            while len(buf) >= 2:
                ln = buf[1] & 0x7f; hl = 2
                if ln == 126:
                    if len(buf) < 4: break
                    ln = struct.unpack(">H", buf[2:4])[0]; hl = 4
                elif ln == 127:
                    if len(buf) < 10: break
                    ln = struct.unpack(">Q", buf[2:10])[0]; hl = 10
                if len(buf) < hl + ln: break
                if buf[hl] == 0x02: got += ln - 5
                del buf[:hl + ln]
        s.close()
        res[tag] = (round(t0 - T0, 1), got == DL, got, round(t_hs, 2), round(time.time() - t0, 2))
    except OSError as e:
        res[tag] = (round(t0 - T0, 1), False, f"error {e}", round(time.time() - t0, 2))
probes = {}; probing = threading.Event()
PROBE_GAP = 0.5
def prober():  # an honest client every 0.5 s while the holders push and stall (2 s handshake timeout)
    k = 0
    while not probing.is_set():
        honest(k, probes, hs_timeout=2); k += 1
        time.sleep(PROBE_GAP)

# rr probe (--rr): one connection opened before the holders, a stream to a local echo; 64 B DATA, wait for the
# echo, every 2 ms; (t, rtt ms) samples (at level 3 clients are not read: the probe stalls by design)
rr = []; rr_stop = threading.Event()
if "--rr" in args:
    esrv = socket.socket(); esrv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    esrv.bind(("127.0.0.1", 0)); esrv.listen(4); EPORT = esrv.getsockname()[1]
    def echo_one():
        c, _ = esrv.accept()
        try:
            while (d := c.recv(65536)): c.sendall(d)
        except OSError: pass
    threading.Thread(target=echo_one, daemon=True).start()
    rs = socket.create_connection(("127.0.0.1", PORT), timeout=10); upgrade(rs)
    p = b"\x01" + struct.pack("<I", 9) + b"\x01" + struct.pack("<H", EPORT) + b"127.0.0.1"
    rs.sendall(hdr(0x2, len(p)) + p); time.sleep(0.2)
    def rr_loop():
        buf = bytearray(); rs.settimeout(60)
        while not rr_stop.is_set():
            pl = b"\x02" + struct.pack("<I", 9) + os.urandom(64)
            t1 = time.time()
            try:
                rs.sendall(hdr(0x2, len(pl)) + pl); got = 0
                while got < 64:
                    d = rs.recv(65536)
                    if not d: return
                    buf += d
                    while len(buf) >= 2 and len(buf) >= 2 + (buf[1] & 0x7f):
                        ln = buf[1] & 0x7f; f = bytes(buf[2:2 + ln]); del buf[:2 + ln]
                        if f[:1] == b"\x02": got += ln - 5
            except OSError:
                return
            rr.append((round(t1 - T0, 3), round((time.time() - t1) * 1000, 2)))
            time.sleep(0.002)
    threading.Thread(target=rr_loop, daemon=True).start()

# holders: handshake in threads (blocking, short), then one selector loop pushes the bytes
holders = []; hs_fail = 0
def connect_one():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    upgrade(s); s.setblocking(False); return s
t0 = time.time()
for i in range(N):
    try: holders.append(connect_one())
    except OSError: hs_fail += 1
t_hs = time.time() - t0
chunk = memoryview(os.urandom(1 << 20))
frag = 64 << 10
plan = {}
for s in holders:
    if MODE == "frame":
        pre = hdr(0x2, FRAME) + b"\x02" + struct.pack("<I", 7)
        plan[s.fileno()] = [pre, SEND, None]  # pending prefix, payload bytes left, current fragment left
    else:
        plan[s.fileno()] = [hdr(0x2, frag, fin=False), SEND - frag, frag]
sel = selectors.DefaultSelector()
for s in holders: sel.register(s, selectors.EVENT_WRITE, s)
res = {}; shed = 0
threading.Thread(target=prober, daemon=True).start(); t_send = time.time(); done = 0; sent_total = 0
t_last_err = None
def drop(s):
    global shed, t_last_err
    sel.unregister(s); shed += 1; t_last_err = time.time() - T0
while time.time() - t_send < 60 and len(sel.get_map()) > 0:
    for key, _ in sel.select(timeout=0.5):
        s = key.data; st = plan[s.fileno()]
        try:
            if st[0]:
                n = s.send(st[0]); st[0] = st[0][n:]; continue
            if MODE == "frame":
                if st[1] <= 0: sel.unregister(s); done += 1; continue
                n = s.send(chunk[:min(st[1], len(chunk))]); st[1] -= n; sent_total += n
            else:
                if st[2] == 0:
                    if st[1] <= 0: sel.unregister(s); done += 1; continue
                    st[0] = hdr(0x0, frag, fin=False); st[2] = frag; st[1] -= frag; continue
                n = s.send(chunk[:st[2]]); st[2] -= n; sent_total += n
        except BlockingIOError:
            pass
        except OSError:
            drop(s)
t_push = time.time() - t_send
# stall phase: count holders the server closed (EOF/RST) over 20 s
def alive_count():
    a = 0
    for s in holders:
        try:
            d = s.recv(65536, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            if d == b"": continue
            # data (e.g. WS Close 1013) may sit before the EOF; check with a 0-byte probe below
            a += not (len(d) >= 2 and d[0] == 0x88)
        except BlockingIOError:
            a += 1
        except OSError:
            pass
    return a
alive_t = []; t_stall = time.time()
for k in range(10):
    time.sleep(2); alive_t.append(alive_count())
probing.set(); rr_stop.set(); time.sleep(3)
honest("after", res)
rss_end = rss_kib()
cg_peak = None  # cgroup mode: the scope's memory.peak (incl. kernel socket memory), review
if CGROUP:
    try:
        rel = open(f"/proc/{srv.pid}/cgroup").read().strip().split("::")[1]
        cg_peak = int(open(f"/sys/fs/cgroup{rel}/memory.peak").read()) >> 20
    except (OSError, IndexError, ValueError):
        pass
stop.set(); time.sleep(0.05)
survived = srv.poll() is None
for s in holders: s.close()
time.sleep(1); rss_closed = rss_kib()
if srv.poll() is None:
    honest("after_close", res)
srv.terminate(); srv.wait()
other = [l for l in levels if "memory level" not in l]
levels = [l for l in levels if "memory level" in l]
out = dict(mode=MODE, n=N, budget=BUDGET, cgroup=CGROUP, hs_fail=hs_fail, t_handshakes=round(t_hs, 1), push_s=round(t_push, 1),
           sent_gib=round(sent_total / 2**30, 2), finished_sending=done, send_errors=shed,
           peak_rss_mib=peak[0] >> 10, cgroup_memory_peak_mib=cg_peak, rss_end_mib=(rss_end or 0) >> 10, rss_after_close_mib=(rss_closed or 0) >> 10,
           alive_holders_every_2s=alive_t, t_stall_start=round(t_stall - T0, 1), honest_after=res.get("after"), honest_after_close=res.get("after_close"),
           probes=[probes[k] for k in sorted(probes)], t_last_shed=t_last_err, survived=survived, stderr_other=other[:200], rr=rr, levels=levels[:16], n_level_lines=len(levels))
json.dump(dict(out, samples=samples[::10]), open(OUTLOG, "w"))
print(json.dumps(out, indent=1))
