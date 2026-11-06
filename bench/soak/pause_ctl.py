# 30.11 control: kernel-only path. A plain TCP client reads from the source target directly (no Wisp server),
# pauses P s, then reads again. Optional rcvbuf (0 = kernel default). Prints JSON per client.
import json, os, socket, sys, threading, time
port = int(sys.argv[1]); RCVBUF = int(os.environ.get("RCVBUF", "16384")); WAIT = float(os.environ.get("WAIT", "150"))
res = {}
def one(P):
    s = socket.socket()
    if RCVBUF: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
    s.connect(("127.0.0.1", port)); s.settimeout(1)
    got = 0; t0 = time.monotonic()
    while time.monotonic() - t0 < 5:
        try: got += len(s.recv(65536))
        except socket.timeout: pass
    time.sleep(P)
    g2 = 0; first = None; t1 = time.monotonic()
    while time.monotonic() - t1 < WAIT and g2 < (1 << 20):
        try:
            d = s.recv(65536)
            if d: g2 += len(d); first = first or round(time.monotonic() - t1, 2)
        except socket.timeout: pass
    res[P] = {"path": "plain-tcp", "pause": P, "rcvbuf": RCVBUF, "before": got, "after": g2, "first_data_s": first,
              "lport": s.getsockname()[1]}
    s.close()
ts = [threading.Thread(target=one, args=(float(P),)) for P in sys.argv[2:]]
[t.start() for t in ts]; [t.join() for t in ts]
for P in sorted(res): print(json.dumps(res[P]))
