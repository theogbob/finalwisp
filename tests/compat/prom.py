#!/usr/bin/env python3
"""60.29 C5 --metrics-listen against a real finalwisp (stdlib only; laptop-safe: a few connections, no load).
usage: prom.py FINALWISP_BINARY BASEPORT (the Wisp port BASEPORT, the metrics port BASEPORT+1)
Cases: GET /metrics 200 with the 0.0.4 content type and Connection: close, every sample after its HELP/TYPE, counters
end in _total, accepted_total counts our connections, metrics_scrapes_total counts scrapes, no MOTD text; 404 / 405 /
400 (junk, over 8 KiB); a client that holds the socket idle delays the next scrape by at most ~2 s and the Wisp port
answers meanwhile; a client that drips bytes is closed at ~2 s; off (no flag): no metrics-http thread, no listener;
the --config form; refused at startup (exit 2): the Wisp port, a port in use; a non-loopback address warns."""
import os, re, socket, subprocess, sys, tempfile, time, base64

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
MP = BASE + 1
D = tempfile.mkdtemp(prefix="fw-prom-")
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

def up(port, p, t=5):
    end = time.time() + t
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close(); return True
        except OSError:
            if p.poll() is not None: return False
            time.sleep(0.05)
    return False

def start(args, wait=(BASE, MP)):
    log = open(os.path.join(D, f"srv{len(os.listdir(D))}.log"), "w+")
    p = subprocess.Popen([BIN, *args], stdout=log, stderr=subprocess.STDOUT)
    for port in wait:
        up(port, p)
    return p, log

def text(log):
    log.flush(); log.seek(0); return log.read()

def wait_text(log, needle, t=3.0):
    """main prints the metrics lines after the workers start, so after the ports listen: poll (50 ms steps)"""
    end = time.time() + t
    while True:
        if needle in text(log): return True
        if time.time() >= end: return False
        time.sleep(0.05)

def stop(p):
    p.terminate()
    try: p.wait(5)
    except subprocess.TimeoutExpired: p.kill(); p.wait()
    for _ in range(100):  # both ports free again
        try:
            for port in (BASE, MP):
                s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.close()
            return
        except OSError: time.sleep(0.05)

def req(raw, port=MP, timeout=5):
    """(head, body) of one answer. Strict (review): a reset, a timeout, no clean EOF, no head or a body that is not
    exactly Content-Length bytes gives head "ERROR ...", so every status check on it fails."""
    got = b""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        with s:
            s.sendall(raw)
            while (d := s.recv(65536)): got += d  # b"" = the server's FIN (clean EOF)
    except OSError as e:
        return f"ERROR {type(e).__name__}: {e} after {len(got)} bytes", ""
    head, sep, body = got.partition(b"\r\n\r\n")
    cl = re.search(rb"\r\nContent-Length: (\d+)", head, re.I)
    if not sep or not cl or int(cl.group(1)) != len(body):
        return f"ERROR truncated or bad length: head {head[:60]!r}, Content-Length {cl and cl.group(1)}, body {len(body)} bytes", ""
    return head.decode(errors="replace"), body.decode(errors="replace")


def scrape(port=MP):
    return req(b"GET /metrics HTTP/1.1\r\nHost: x\r\nAccept: text/plain\r\n\r\n", port)

def val(body, name):
    m = re.search(rf"^{name} (\S+)$", body, re.M)
    return float(m.group(1)) if m else None

def wisp_upgrade(port=BASE):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
              + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: break
        buf += d
    s.close()
    return buf.startswith(b"HTTP/1.1 101")

# 1. the page
p, log = start(["--port", str(BASE), "--metrics-listen", str(MP), "--threads", "2", "--motd", "promsecretmotd"])
ok(wait_text(log, "metrics on http://127.0.0.1:%d/metrics" % MP), "startup line names the endpoint")
for _ in range(3):
    wisp_upgrade()
h, b = scrape()
ok(h.startswith("HTTP/1.1 200 "), f"200: {h.splitlines()[:1]}")
ok("Content-Type: text/plain; version=0.0.4; charset=utf-8" in h and "Connection: close" in h, "content type 0.0.4, Connection: close")
cl = re.search(r"Content-Length: (\d+)", h)
ok(cl is not None and int(cl.group(1)) == len(b.encode()), "Content-Length matches the body")
typed, helped, bad = {}, set(), []
for l in b.splitlines():
    if l.startswith("# HELP "): helped.add(l.split()[2])
    elif l.startswith("# TYPE "): typed[l.split()[2]] = l.split()[3]
    else:
        m = re.match(r"^(finalwisp_[a-z0-9_]+)(\{[a-z]+=\"[^\"]*\"\})? (-?[0-9.e+]+)$", l)
        if not m or m.group(1) not in typed or m.group(1) not in helped: bad.append(l)
ok(not bad and len(typed) > 50, f"format: {len(typed)} families, bad lines {bad[:3]}")
ok(all((t == "counter") == n.endswith("_total") for n, t in typed.items()), "counters and only counters end in _total")
ok(not any(re.search(r"_(kib|mib|ms|us)($|_)", n) for n in typed), "base units only")
ok((val(b, "finalwisp_accepted_total") or 0) >= 3, f"accepted_total {val(b, 'finalwisp_accepted_total')} >= 3")
ok(val(b, "finalwisp_metrics_scrapes_total") == 0 and val(scrape()[1], "finalwisp_metrics_scrapes_total") == 1, "metrics_scrapes_total counts completed scrapes")
ok("promsecretmotd" not in b, "no configuration (MOTD) on the page")
ok('finalwisp_build_info{version="' in b, "build_info")

# 2. other requests
ok(req(b"GET / HTTP/1.1\r\n\r\n")[0].startswith("HTTP/1.1 404 "), "404 other path")
h, _ = req(b"POST /metrics HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
ok(h.startswith("HTTP/1.1 405 ") and "Allow: GET" in h, "405 other method")
h, _ = req(b"POST /metrics HTTP/1.1\r\nContent-Length: 20000\r\n\r\n" + b"x" * 20000)
ok(h.startswith("HTTP/1.1 405 "), "405 with an unread 20 KB body (no RST)")
h, _ = req(b"GET /metrics HTTP/1.1\r\n\r\nGET /metrics HTTP/1.1\r\n\r\n")
ok(h.startswith("HTTP/1.1 200 "), "200 with a pipelined second request (no RST)")
ok(req(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\r\n\r\n")[0].startswith("HTTP/1.1 400 "), "400 junk")
ok(req(b"GET /metrics HTTP/1.1\r\nX: " + b"a" * 9000 + b"\r\n\r\n")[0].startswith("HTTP/1.1 400 "), "400 over 8 KiB")

# 3. a stuck scraper delays the next scrape by <= ~2 s; the Wisp port is not affected
stuck = socket.create_connection(("127.0.0.1", MP)); time.sleep(0.1)
t0 = time.time(); w_ok = wisp_upgrade(); tw = time.time() - t0
ok(w_ok and tw < 0.5, f"Wisp upgrade during a stuck scrape in {tw:.3f} s")
h, b = scrape(); dt = time.time() - t0
ok(h.startswith("HTTP/1.1 200 ") and 1.0 < dt < 3.5, f"next scrape after a stuck client: {dt:.2f} s (deadline 2 s)")
stuck.close()

# 4. a dripping client cannot extend the deadline
s = socket.create_connection(("127.0.0.1", MP), timeout=6); t0 = time.time(); closed = None
try:
    for ch in b"GET /metrics HTTP/1.1\r\nX: " + b"a" * 40:
        s.send(bytes([ch])); time.sleep(0.25)
        s.settimeout(0.01)
        try:
            if s.recv(1) == b"": closed = time.time() - t0; break
        except socket.timeout: pass
except OSError: closed = time.time() - t0
s.close()
ok(closed is not None and closed < 3.0, f"dripping client closed at {closed}")
stop(p)

# 5. off: no thread, no listener
p, log = start(["--port", str(BASE), "--threads", "2"], wait=(BASE,))
time.sleep(0.2)
comms = [open(f"/proc/{p.pid}/task/{t}/comm").read().strip() for t in os.listdir(f"/proc/{p.pid}/task")]
ok("metrics-http" not in comms, f"off: no metrics-http thread ({sorted(set(comms))})")
try: socket.create_connection(("127.0.0.1", MP), timeout=1).close(); listening = True
except OSError: listening = False
ok(not listening, "off: nothing listens on the metrics port")
stop(p)

# 6. --config form
cf = os.path.join(D, "m.conf")
with open(cf, "w") as f: f.write(f"port {BASE}\nthreads 2\nmetrics-listen 127.0.0.1:{MP}\n")
os.chmod(cf, 0o600)
p, log = start(["--config", cf])
ok(scrape()[0].startswith("HTTP/1.1 200 "), "--config metrics-listen")
stop(p)

# 7. startup refusals (exit 2 before listening)
r = subprocess.run([BIN, "--port", str(BASE), "--metrics-listen", f"0.0.0.0:{BASE}"], capture_output=True, text=True, timeout=10)
ok(r.returncode == 2 and "is the Wisp port" in r.stderr, f"Wisp port refused: rc {r.returncode} {r.stderr.splitlines()[:1]}")
with open(cf, "w") as f: f.write(f"port {BASE}\nmetrics-listen 0.0.0.0:{BASE}\n")
r = subprocess.run([BIN, "--config", cf], capture_output=True, text=True, timeout=10)
ok(r.returncode == 2 and "is the Wisp port" in r.stderr, f"Wisp port refused (--config): rc {r.returncode} {r.stderr.splitlines()[:1]}")
blk = socket.socket(); blk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); blk.bind(("127.0.0.1", MP)); blk.listen(1)
r = subprocess.run([BIN, "--port", str(BASE), "--metrics-listen", str(MP)], capture_output=True, text=True, timeout=10)
ok(r.returncode == 2 and f"--metrics-listen 127.0.0.1:{MP}: cannot listen" in r.stderr, f"port in use: rc {r.returncode} {r.stderr.splitlines()[:1]}")
ok("listening on" not in r.stderr, "no Wisp listener opened before the refusal")
blk.close()

# 8. a non-loopback address warns
p, log = start(["--port", str(BASE), "--threads", "2", "--metrics-listen", f"0.0.0.0:{MP}"])
ok(wait_text(log, "is not a loopback address and /metrics has no auth"), "non-loopback warning")
stop(p)

print(f"prom: {fails} failure(s)")
sys.exit(1 if fails else 0)
