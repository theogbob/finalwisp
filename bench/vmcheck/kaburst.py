#!/usr/bin/env python3
"""60.78 G59 keepalive TLS arm (sb-robust): 60.67's keepalive finding (a burst of idle connections accepted together;
the server's TCP keepalive probes leave in one instant, some are dropped, live idle clients are reset at ~182 s) and
the v1.3.1 K1 fix (spread of the idle time), with a TLS arm. N idle Wisp connections opened at once (THREADS threads),
never read or written after the handshake; held HOLD s; a connection the server closed shows POLLRDHUP/POLLHUP/POLLERR.
usage: kaburst.py FINALWISP PORT OUTDIR NAME [--tls CERT KEY] [--n 10000] [--hold 290] [--threads 16]
The server runs with --log-conns (why=dead_peer counts the keepalive closes). Root raises RLIMIT_NOFILE."""
import json, os, resource, select, socket, ssl, subprocess, sys, threading, time
a = sys.argv[1:]
def opt(k, d): return a[a.index(k) + 1] if k in a else d
BIN, PORT, OUT, NAME = os.path.abspath(a[0]), int(a[1]), a[2], a[3]; os.makedirs(OUT, exist_ok=True)
N, HOLD, TH = int(opt("--n", "10000")), float(opt("--hold", "290")), int(opt("--threads", "16"))
TLS = (a[a.index("--tls") + 1], a[a.index("--tls") + 2]) if "--tls" in a else None
try: resource.setrlimit(resource.RLIMIT_NOFILE, (200000, 200000))
except (ValueError, OSError): resource.setrlimit(resource.RLIMIT_NOFILE, (resource.getrlimit(resource.RLIMIT_NOFILE)[1],) * 2)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
log = open(os.path.join(OUT, f"kaburst-{NAME}.log"), "w+")
args = [BIN, "--port", str(PORT), "--log-conns", "--metrics-interval", "5"] + (["--tls-cert", TLS[0], "--tls-key", TLS[1]] if TLS else [])
srv = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
for _ in range(100):
    if "listening on" in open(log.name).read(): break
    time.sleep(0.1)
time.sleep(0.5)
socks, fails, lock = [], [], threading.Lock()
def opener(k):
    for i in range(k, N, TH):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
            if TLS: s = ctx.wrap_socket(s, server_hostname="localhost")
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            b = b""
            while b"\r\n\r\n" not in b:
                d = s.recv(4096)
                if not d: raise OSError("closed during the handshake")
                b += d
            with lock: socks.append(s)
        except OSError as e:
            with lock: fails.append(str(e)[:80])
t0 = time.time()
ths = [threading.Thread(target=opener, args=(k,)) for k in range(TH)]
[t.start() for t in ths]; [t.join() for t in ths]
t_open = time.time() - t0
p = select.poll(); fdmap = {}
for s in socks:
    p.register(s.fileno(), select.POLLRDHUP | select.POLLHUP | select.POLLERR); fdmap[s.fileno()] = s
closed = {}
while time.time() - t0 < HOLD and len(closed) < len(socks):
    for fd, ev in p.poll(1000):
        if fd not in closed:
            closed[fd] = round(time.time() - t0, 1); p.unregister(fd)
kt = None
if TLS:
    o = subprocess.run(["ss", "-tniH", "state", "established", f"( sport = :{PORT} )"], capture_output=True, text=True).stdout
    kt = o.count("tcp-ulp-tls")
m = [l for l in open(log.name) if "ev=metrics" in l][-1:]
srv.terminate(); rc = srv.wait(60)
txt = open(log.name).read()
ages = sorted(closed.values())
s = {"name": NAME, "bin": BIN, "tls": bool(TLS), "opened": len(socks), "open_fail": len(fails), "open_s": round(t_open, 1), "hold_s": HOLD,
     "closed_by_server": len(closed), "closed_at_s_min_max": [ages[0], ages[-1]] if ages else None,
     "server_log_dead_peer": txt.count("why=dead_peer"), "ktls_sockets_at_end": kt, "rc": rc, "last_metrics": m[0].strip()[:600] if m else None}
open(os.path.join(OUT, "kaburst.jsonl"), "a").write(json.dumps(s) + "\n")
print("CHECK INFO kaburst " + json.dumps(s), flush=True)
open(os.path.join(OUT, "kaburst.txt"), "a").write("CHECK INFO kaburst " + json.dumps(s) + "\n")
