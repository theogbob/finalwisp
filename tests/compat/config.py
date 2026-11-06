#!/usr/bin/env python3
"""60.20 C8 --config FILE against a real finalwisp. Stdlib only. usage: config.py FINALWISP_BINARY BASEPORT (BASEPORT, +1)
Cases: a server started from a config file only (port, allow-loopback, threads, motd) serves a Wisp v1 stream to a local
echo server and names the file in its capability line; a flag after --config overrides the file (port); a refused
CONNECT to loopback without allow-loopback in the file (the file decides); bad files exit 2 before listening, with
FILE:LINE and without the value (bad value, unknown flag, --config inside the file, missing file, too big)."""
import os, socket, struct, subprocess, sys, tempfile, threading, time, base64

BIN, BASE = os.path.abspath(sys.argv[1]), int(sys.argv[2])
ECHO = BASE + 1
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1

ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", ECHO)); ls.listen(16)
def pump(c):
    with c:
        try:
            while (d := c.recv(65536)): c.sendall(d)
        except OSError: pass
threading.Thread(target=lambda: [threading.Thread(target=pump, args=(ls.accept()[0],), daemon=True).start() for _ in iter(int, 1)], daemon=True).start()

D = tempfile.mkdtemp(prefix="fw-config-")
def conf(name, text, mode=0o600):
    p = os.path.join(D, name)
    with open(p, "wb") as f:
        f.write(text.encode() if isinstance(text, str) else text)
    os.chmod(p, mode)
    return p

def start(args, port):
    log = open(os.path.join(D, f"srv{port}.log"), "w+")
    p = subprocess.Popen([BIN, *args], stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close(); break
        except OSError:
            if p.poll() is not None: break
            time.sleep(0.05)
    for _ in range(40):  # the capability line comes after the listeners (main.rs)
        log.flush(); log.seek(0); text = log.read()
        if "capabilities:" in text or p.poll() is not None: break
        time.sleep(0.05)
    return p, text

def stop(p):
    p.terminate()
    try: p.wait(5)
    except subprocess.TimeoutExpired: p.kill(); p.wait()

def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

def wisp_echo(port, data=b"config-file-echo"):
    """v1: CONNECT stream 1 to 127.0.0.1:ECHO, send data, return the echoed bytes (or a CLOSE reason int)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
              + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(4096)
    buf = buf.split(b"\r\n\r\n", 1)[1]
    s.sendall(frame(b"\x01" + struct.pack("<I", 1) + b"\x01" + struct.pack("<H", ECHO) + b"127.0.0.1"))
    s.sendall(frame(b"\x02" + struct.pack("<I", 1) + data))
    got = b""
    t0 = time.time()
    while len(got) < len(data) and time.time() - t0 < 5:
        while len(buf) >= 2:
            ln = buf[1] & 0x7f; h = 2
            if ln == 126: ln = struct.unpack(">H", buf[2:4])[0]; h = 4
            if len(buf) < h + ln: break
            p, buf = buf[h:h + ln], buf[h + ln:]
            if p[:1] == b"\x02": got += p[5:]
            if p[:1] == b"\x04": s.close(); return p[5]
        if len(got) >= len(data): break
        d = s.recv(65536)
        if not d: break
        buf += d
    s.close()
    return got

# 1. everything from the file
good = conf("good.conf", f"# finalwisp test config\nport {BASE}\nallow-loopback\nthreads 2\nmotd from a config file\n")
p, log = start(["--config", good], BASE)
ok(f"config {good}" in log, "capability line names the config file")
ok(wisp_echo(BASE) == b"config-file-echo", "server started from a config file serves a stream (allow-loopback from the file)")
stop(p)
# 2. a flag after --config overrides the file
other = conf("other.conf", f"port {BASE + 50}\nallow-loopback\nthreads 2\n")
p, log = start(["--config", other, "--port", str(BASE)], BASE)
ok(wisp_echo(BASE) == b"config-file-echo", "--port after --config overrides the file's port")
stop(p)
# 3. the file decides the SSRF guard: no allow-loopback in it -> CONNECT to 127.0.0.1 refused (0x48)
noloop = conf("noloop.conf", f"port {BASE}\nthreads 2\n")
p, log = start(["--config", noloop], BASE)
ok(wisp_echo(BASE) == 0x48, "without allow-loopback in the file the loopback CONNECT is refused with 0x48")
stop(p)
# 4. bad files: exit 2, FILE:LINE, value not shown, nothing listens
SECRET = "s3cretVALUE"
for name, text, want in [
    ("badval.conf", f"port {BASE}\nthreads {SECRET}\n", "badval.conf:2: --threads: bad value (value not shown)"),
    ("unknown.conf", f"port {BASE}\n\nbogus-flag 1\n", 'unknown.conf:3: unknown flag "bogus-flag"'),
    ("include.conf", "config other.conf\n", "include.conf:1: --config inside a config file (no includes)"),
    ("big.conf", "#" * ((1 << 20) + 10), "big.conf: larger than 1024 KiB"),
    ("utf8.conf", b"motd \xff\n", "utf8.conf:1: not valid UTF-8"),
]:
    path = conf(name, text)
    r = subprocess.run([BIN, "--config", path], capture_output=True, text=True, timeout=10, errors="replace")
    ok(r.returncode == 2 and want in r.stderr and SECRET not in r.stderr, f"{name}: exit 2 with {want!r}" + ("" if r.returncode == 2 and want in r.stderr else f" (rc {r.returncode}: {r.stderr[:200]!r})"))
r = subprocess.run([BIN, "--config", os.path.join(D, "missing.conf")], capture_output=True, text=True, timeout=10)
ok(r.returncode == 2 and "missing.conf: No such file" in r.stderr, "missing file: exit 2")
try:
    socket.create_connection(("127.0.0.1", BASE), timeout=0.5).close(); ok(False, "nothing listens after the bad configs")
except OSError:
    ok(True, "nothing listens after the bad configs")
print(f"config: {fails} failures")
sys.exit(1 if fails else 0)
