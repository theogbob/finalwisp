#!/usr/bin/env python3
"""60.74 step 3 forced-move compatibility: real clients through connections that move between workers.
usage: forced_move.py POOLTEST_BIN|--build CARGO_DIR BASEPORT [--release-bin BIN]   (ports BASE .. BASE+9)
--build CARGO_DIR: `cargo build --release --locked --features pooltest` there first, in the target directory of
bench/tools/gate.py's pooltest lane (CARGO_DIR/target/gate-pooltest: after a gate's lanes it is built already).

POOLTEST_BIN: a build with cargo feature pooltest (the test hook FW_FORCE_MOVE=N: every worker moves one connection at
rest to the next worker every N loop turns, at the turn's end and where a request is handled; 60.64). The release
build has no hook: --release-bin is checked for its absence.
Per N in (1, 7), --threads 2:
  wispjs   tests/compat/wispjs.mjs (wisp-js 0.5.3, v1 + v2: echo byte compare, 2x64 MiB pattern downloads during echo,
           target EOF 0x02, refused 0x44, unresolvable 0x42) against a server with the hook on
  conn     a stdlib v1 client: 3 streams (--max-streams-per-conn 3) echo random data 30 rounds (byte compare); the
           4th CONNECT gets 0x49; a client CLOSE frees a slot (new stream echoes; the next is 0x49 again); an upload
           of 40 x the initial credit to a counting sink strictly within CONTINUE credit (the credit goes on);
           target EOF -> 0x02 after its data; refused -> 0x44; a WS close at the end and the server's close back
           (no reset). The --log-conns line of the connection: why=client_close, streams= / refused= as counted
           by the client, rx = the wire bytes the client sent.
  credit2  tests/compat/credit_v2.py (credit v2 clients: pong / nopong / eager / foreign) on the hooked build
Every server's last metrics line: moved_conns > 0 (the moves happened; printed), moved_reset = 0.
A reference run of `conn` with the hook at 0 (no move) must give the same per-connection fields."""
import base64, os, shlex, socket, struct, subprocess, sys, tempfile, threading, time

args = sys.argv[1:]
REL = None
if "--release-bin" in args:
    i = args.index("--release-bin")
    REL = os.path.abspath(args[i + 1])
    del args[i:i + 2]
if args[0] == "--build":
    cdir = os.path.abspath(args[1])
    tdir = os.path.join(cdir, "target", "gate-pooltest")
    r = subprocess.run(["cargo", "build", "--release", "-q", "--locked", "--features", "pooltest"], cwd=cdir, capture_output=True, text=True,
                       env={**os.environ, "CARGO_TARGET_DIR": tdir, "CARGO_BUILD_BUILD_DIR": os.path.join(tdir, "build")})
    if r.returncode != 0:
        print(f"FAIL the pooltest build in {cdir} (exit {r.returncode}): {r.stderr[-500:]}")
        sys.exit(1)
    args = [os.path.join(tdir, "release", "finalwisp")] + args[2:]
BIN, BASE = os.path.abspath(args[0]), int(args[1])
HERE = os.path.dirname(os.path.abspath(__file__))
ECHO, SINK, DEAD = BASE + 7, BASE + 8, BASE + 9  # DEAD: nothing listens there (the refused check; below the ephemeral range)
fails = 0


def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True)
    fails += 0 if c else 1


# targets: echo ("BYE" at the end of a read: the target ends the socket after echoing), counting sink
def echo_pump(c):
    with c:
        try:
            while (d := c.recv(65536)):
                c.sendall(d)
                if d.endswith(b"BYE"):
                    c.shutdown(socket.SHUT_WR)
                    return
        except OSError:
            pass


sunk = {"bytes": 0}
sunk_mu = threading.Lock()


def sink_pump(c):
    with c:
        try:
            while (d := c.recv(1 << 20)):
                with sunk_mu:
                    sunk["bytes"] += len(d)
        except OSError:
            pass


def serve(port, pump):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(64)

    def acceptor():
        while True:
            c, _ = ls.accept()
            threading.Thread(target=pump, args=(c,), daemon=True).start()
    threading.Thread(target=acceptor, daemon=True).start()


serve(ECHO, echo_pump)
serve(SINK, sink_pump)
D = tempfile.mkdtemp(prefix="fw-forced-move-")


def start(port, every, *extra):
    log = open(os.path.join(D, f"srv{port}-{every}.log"), "w+")
    env = {**os.environ, "FW_FORCE_MOVE": str(every)}
    p = subprocess.Popen([BIN, str(port), "--allow-loopback", "--threads", "2", "--log-level", "debug", "--metrics-interval", "1", *extra],
                         stdout=log, stderr=subprocess.STDOUT, env=env)
    p.logf = log
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            if p.poll() is not None:
                break
            time.sleep(0.05)
    return p


def srvlog(p):
    with open(p.logf.name) as f:
        return f.read()


def stop(p):
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def last_metrics(text):
    # ev=metrics (each interval) or ev=metrics_final (at exit: the only one with --metrics-interval 600); the counters
    # are cumulative, so the last line of either kind holds them
    lines = [l for l in text.splitlines() if "ev=metrics " in l or "ev=metrics_final" in l]
    if not lines:
        return {}
    return dict(kv.split("=", 1) for kv in lines[-1].split() if "=" in kv)


def frame(payload, op=0x2):
    n = len(payload)
    m = os.urandom(4)
    if n < 126:
        hdr = bytes([0x80 | op, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x80 | op, 0xFE]) + struct.pack(">H", n)
    else:
        hdr = bytes([0x80 | op, 0xFF]) + struct.pack(">Q", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))


class Wisp:
    """a v1 client that counts its wire bytes both ways"""

    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sent = self.recvd = 0
        self.buf = b""
        self.pk = []  # packets read but not taken yet
        self.ws_closed = False
        self.raw(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
                 + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
        while b"\r\n\r\n" not in self.buf:
            self.fill(5)
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise ConnectionResetError(head[:40])

    def raw(self, b):
        self.s.sendall(b)
        self.sent += len(b)

    def fill(self, t):
        self.s.settimeout(t)
        d = self.s.recv(1 << 20)
        if not d:
            raise ConnectionResetError("EOF")
        self.recvd += len(d)
        self.buf += d

    def parse(self):
        while len(self.buf) >= 2:
            op, ln, h = self.buf[0] & 0x0f, self.buf[1] & 0x7f, 2
            if ln == 126:
                if len(self.buf) < 4:
                    return
                ln, h = struct.unpack(">H", self.buf[2:4])[0], 4
            elif ln == 127:
                if len(self.buf) < 10:
                    return
                ln, h = struct.unpack(">Q", self.buf[2:10])[0], 10
            if len(self.buf) < h + ln:
                return
            p, self.buf = self.buf[h:h + ln], self.buf[h + ln:]
            if op == 0x8:
                self.ws_closed = True
            elif op == 0x2 and len(p) >= 5:
                self.pk.append((p[0], struct.unpack("<I", p[1:5])[0], p[5:]))

    def send(self, ty, sid, body):
        self.raw(frame(bytes([ty]) + struct.pack("<I", sid) + body))

    def connect(self, sid, port):
        self.send(1, sid, b"\x01" + struct.pack("<H", port) + b"127.0.0.1")

    def take(self, pred, t=5.0):
        """the first packet that matches pred, waiting up to t seconds (None: none came)"""
        end = time.time() + t
        while True:
            self.parse()
            for i, x in enumerate(self.pk):
                if pred(x):
                    return self.pk.pop(i)
            left = end - time.time()
            if left <= 0:
                return None
            try:
                self.fill(min(left, 0.5))
            except socket.timeout:
                pass

    def echo(self, sid, data, t=10.0):
        self.send(2, sid, data)
        got = b""
        while len(got) < len(data):
            x = self.take(lambda x: x[1] == sid and x[0] in (2, 4), t)
            if x is None or x[0] == 4:
                return False
            got += x[2]
        return got == data


def moves_of(p):
    m = last_metrics(srvlog(p))
    return int(m.get("moved_conns", -1)), int(m.get("moved_reset", -1))


def conn_case(port, every):
    """-> the per-connection fields (why, streams, refused) of the server's conn_close line, or None"""
    tag = f"N={every} conn"
    p = start(port, every, "--max-streams-per-conn", "3", "--log-conns")
    try:
        w = Wisp(port)
        c0 = w.take(lambda x: x[0] == 3 and x[1] == 0)
        credit = struct.unpack("<I", c0[2][:4])[0] if c0 else 0
        ok(credit > 0, f"{tag}: initial CONTINUE credit {credit}")
        opened, refused = 0, 0
        for sid in (1, 2, 3):
            w.connect(sid, ECHO)
            opened += 1
        good = all(w.echo(sid, os.urandom(4096 + 37 * r)) for r in range(30) for sid in (1, 2, 3))
        ok(good, f"{tag}: 3 streams x 30 rounds of echo, byte compare")
        w.connect(4, ECHO)
        x = w.take(lambda x: x[1] == 4 and x[0] == 4)
        refused += 1
        ok(x is not None and x[2][:1] == b"\x49", f"{tag}: the 4th CONNECT gets CLOSE 0x49 ({x})")
        w.send(4, 3, b"\x02")  # client CLOSE of stream 3: its slot is free
        w.connect(5, ECHO)
        opened += 1
        ok(w.echo(5, os.urandom(10000)), f"{tag}: a client CLOSE frees a slot (stream 5 echoes)")
        w.connect(6, ECHO)
        x = w.take(lambda x: x[1] == 6 and x[0] == 4)
        refused += 1
        ok(x is not None and x[2][:1] == b"\x49", f"{tag}: and the limit holds again (0x49: {x})")
        # upload to the sink strictly within credit (v1: CONTINUE carries the absolute buffer count)
        w.send(4, 2, b"\x02")
        before = sunk["bytes"]
        w.connect(7, SINK)
        opened += 1
        n_up, cred, chunk, stalled = 40 * credit, credit, b"u" * 1024, False
        for _ in range(n_up):
            while cred == 0:
                x = w.take(lambda x: x[1] == 7 and x[0] in (3, 4), 10.0)
                if x is None or x[0] == 4:
                    stalled = True
                    break
                cred = struct.unpack("<I", x[2][:4])[0]
            if stalled:
                break
            w.send(2, 7, chunk)
            cred -= 1
        end = time.time() + 10
        while sunk["bytes"] - before < n_up * 1024 and time.time() < end:
            time.sleep(0.02)
        ok(not stalled and sunk["bytes"] - before == n_up * 1024,
           f"{tag}: upload of {n_up} packets within credit, sink got {sunk['bytes'] - before}/{n_up * 1024} (stalled {stalled})")
        # target EOF and refused (slots: 1, 5, 7 open -> close 1 and 7 first)
        w.send(4, 1, b"\x02")
        w.send(4, 7, b"\x02")
        w.connect(8, ECHO)
        opened += 1
        w.send(2, 8, b"hello BYE")
        got, x = b"", None
        while True:
            x = w.take(lambda x: x[1] == 8, 10.0)
            if x is None or x[0] == 4:
                break
            if x[0] == 2:
                got += x[2]
        ok(x is not None and x[2][:1] == b"\x02" and got == b"hello BYE", f"{tag}: target EOF -> CLOSE 0x02 after its data ({got!r}, {x})")
        w.connect(9, DEAD)
        opened += 1
        x = w.take(lambda x: x[1] == 9 and x[0] == 4, 10.0)
        ok(x is not None and x[2][:1] == b"\x44", f"{tag}: refused -> CLOSE 0x44 ({x})")
        # the end: a WS close; the server answers with its close and ends the socket (no reset)
        w.raw(frame(b"\x03\xe8", op=0x8))
        reset, end = False, time.time() + 5
        while time.time() < end:
            try:
                w.fill(1)
            except ConnectionResetError as e:
                reset = "EOF" not in str(e)
                break
            except socket.timeout:
                pass
            except OSError:
                reset = True
                break
        w.parse()
        ok(w.ws_closed and not reset, f"{tag}: WS close answered, socket ended without a reset (closed {w.ws_closed}, reset {reset})")
        w.s.close()
        time.sleep(1.5)  # the next metrics line
        text = srvlog(p)
        lines = [l for l in text.splitlines() if "ev=conn_close" in l and "proto=v1" in l]
        f = dict(kv.split("=", 1) for kv in lines[-1].split() if "=" in kv) if lines else {}
        ok(len(lines) == 1, f"{tag}: one conn_close line for the connection ({len(lines)})")
        ok(f.get("why") == "client_close" and f.get("streams") == str(opened) and f.get("refused") == str(refused),
           f"{tag}: per-connection counters kept: why={f.get('why')} streams={f.get('streams')} (client: {opened}) refused={f.get('refused')} (client: {refused})")
        ok(f.get("rx") == str(w.sent), f"{tag}: rx {f.get('rx')} = the client's wire bytes {w.sent}")
        moved, mreset = moves_of(p)
        print(f"INFO {tag}: moved_conns={moved} moved_reset={mreset} worker at close w={f.get('w')}", flush=True)
        if every:
            ok(moved > 0 and mreset == 0, f"{tag}: the connection moved ({moved} moves), moved_reset {mreset}")
        else:
            ok(moved == 0, f"{tag}: no move with the hook at 0 ({moved})")
        return (f.get("why"), f.get("streams"), f.get("refused")), moved
    finally:
        stop(p)


def wispjs_case(port, every):
    tag = f"N={every} wispjs"
    p = start(port, every)
    try:
        r = subprocess.run(["node", "wispjs.mjs", f"ws://127.0.0.1:{port}/"], cwd=HERE, capture_output=True, text=True, timeout=280,
                           env={**os.environ, "WISPJS_DEAD": str(DEAD)})
        for l in r.stdout.splitlines():
            if l.startswith(("PASS", "FAIL")):
                print(l.split(" ", 1)[0] + f" {tag}: " + l.split(" ", 1)[1], flush=True)
        ok(r.returncode == 0 and "ALL PASS" in r.stdout, f"{tag}: exit {r.returncode} {r.stdout.strip().splitlines()[-1:] if r.stdout.strip() else r.stderr[-200:]}")
        stop(p)
        moved, mreset = moves_of(p)
        print(f"INFO {tag}: moved_conns={moved} moved_reset={mreset}", flush=True)
        ok(moved > 0 and mreset == 0, f"{tag}: connections moved ({moved}), moved_reset {mreset}")
        return moved
    finally:
        stop(p)


def credit2_case(port, every):
    tag = f"N={every} credit2"
    log = os.path.join(D, f"credit2-{every}.log")
    wrap = os.path.join(D, f"wrap-{every}.sh")
    # the script starts its own server: a wrapper adds the hook and a metrics line at exit, and keeps a copy of stderr
    open(wrap, "w").write(f"#!/bin/bash\nexport FW_FORCE_MOVE={every}\nexec {shlex.quote(BIN)} \"$@\" --metrics-interval 600 2> >(tee -a {shlex.quote(log)} >&2)\n")
    os.chmod(wrap, 0o755)
    r = subprocess.run([sys.executable, os.path.join(HERE, "credit_v2.py"), wrap, str(port)], capture_output=True, text=True, timeout=280)
    for l in r.stdout.splitlines():
        if l.startswith(("PASS", "FAIL")):
            print(l.split(" ", 1)[0] + f" {tag}: " + l.split(" ", 1)[1], flush=True)
    ok(r.returncode == 0 and "ALL PASS" in r.stdout, f"{tag}: exit {r.returncode}")
    time.sleep(0.5)  # tee ends after the server
    moved, mreset = (int(last_metrics(open(log).read()).get(k, -1)) for k in ("moved_conns", "moved_reset"))
    print(f"INFO {tag}: moved_conns={moved} moved_reset={mreset}", flush=True)
    ok(moved > 0 and mreset == 0, f"{tag}: connections moved ({moved}), moved_reset {mreset}")
    return moved


hook = open(BIN, "rb").read().find(b"FW_FORCE_MOVE") >= 0
ok(hook, f"{os.path.basename(BIN)} has the test hook (a pooltest build)")
if REL:
    ok(open(REL, "rb").read().find(b"FW_FORCE_MOVE") < 0, f"the release binary {os.path.basename(REL)} has no test hook")
if not hook:
    print("1 FAILURES")
    sys.exit(1)
ref, _ = conn_case(BASE, 0)
moves = {}
for k, every in enumerate((1, 7)):
    moves[f"wispjs N={every}"] = wispjs_case(BASE + 1 + 3 * k, every)
    got, moves[f"conn N={every}"] = conn_case(BASE + 2 + 3 * k, every)
    ok(got == ref, f"N={every} conn: the per-connection fields equal the run without moves ({got} vs {ref})")
    moves[f"credit2 N={every}"] = credit2_case(BASE + 3 + 3 * k, every)
print("MOVES " + " ".join(f"{k.replace(' ', ':')}={v}" for k, v in moves.items()), flush=True)
print("ALL PASS" if not fails else f"{fails} FAILURES")
sys.exit(1 if fails else 0)
