# 30.11 soak: one abuse burst; prints one JSON line.
#   partial:   --conns (200) connections to A, each sends a WS frame header claiming 10 MiB and 0-1 MiB of it, holds
#              15-30 s, then closes (half RST).
#   blackhole: 3 connections x 100 streams to B (--allow-private) CONNECT 10.255.255.1:80; every stream
#              must get a CLOSE (expected 0x43 after the 10 s connect timeout).
import argparse, json, os, random, socket, struct, sys, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from wispc import Wisp, Closed, CLOSE, DATA

ap = argparse.ArgumentParser()
ap.add_argument("mode", choices=("partial", "blackhole"))
ap.add_argument("--a", type=int, default=7001)
ap.add_argument("--b", type=int, default=7002)
ap.add_argument("--conns", type=int, default=200, help="30.16: partial-frame connections (heavy soak: more)")
a = ap.parse_args()
rng = random.Random()
res = {"t": time.time(), "mode": a.mode, "fail": []}
t0 = time.monotonic()

if a.mode == "partial":
    conns = []; sent = 0; errs = 0
    junk = os.urandom(1 << 20)
    for i in range(a.conns):
        try:
            w = Wisp(a.a, timeout=5)
            m = os.urandom(4)
            w.s.sendall(bytes([0x82, 0x80 | 127]) + struct.pack(">Q", 10 << 20) + m)
            conns.append((w, rng.randint(0, 1 << 20)))
        except (Closed, OSError):
            errs += 1
    for w, n in conns:  # second pass so all 200 hold partial frames at the same time
        try:
            w.s.settimeout(2)
            w.s.sendall(junk[:n]); sent += n
        except OSError:
            errs += 1
    hold = rng.uniform(15, 30)
    time.sleep(hold)
    for i, (w, _) in enumerate(conns):
        w.close(rst=i % 2 == 0)
    res.update(conns=len(conns), connect_or_send_errors=errs, sent_mib=round(sent / 2**20, 1), hold_s=round(hold, 1))
    if len(conns) < 0.9 * a.conns:  # review: a burst that could not be built is not a passed burst
        res["fail"].append(f"only {len(conns)} of {a.conns} partial-frame connections opened")
else:
    hist = {}; missing = 0; ws = []
    for c in range(3):
        w = Wisp(a.b, tls=True, timeout=5)
        for s in range(1, 101):
            w.connect(s, 80, b"10.255.255.1")
        ws.append(w)
    for w in ws:
        pend = set(range(1, 101)); end = time.monotonic() + 25
        while pend and time.monotonic() < end:
            try:
                p = w.recv_pkt(end - time.monotonic())
            except Closed as e:
                res["fail"].append(f"connection closed: {e}"); break
            if p is None:
                break
            if p[0] == CLOSE and p[1] in pend:
                pend.discard(p[1]); r = p[2][:1].hex()
                hist[r] = hist.get(r, 0) + 1
            elif p[0] == DATA and p[1] in pend:
                res["fail"].append(f"DATA from a blackholed target on stream {p[1]}")
        missing += len(pend)
        w.close()
    res.update(reasons=hist, missing=missing)
    if missing:
        res["fail"].append(f"{missing} of 300 streams got no CLOSE in 25 s")
res["s"] = round(time.monotonic() - t0, 1)
res["ok"] = not res["fail"]
print(json.dumps(res), flush=True)
