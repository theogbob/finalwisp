#!/usr/bin/env python3
"""v13-form functional tests of the preset form and the runtime hints (note 60.59), on loopback only.

Usage: python3 bench/v13-form-fn.py --bin PATH --out DIR [--base-port 9780] [--caddy PATH] [--docker] [--only A,B,...]
Writes DIR/fn.json (one record per case: argv, exit code, the lines it looked at, pass) and DIR/logs/<case>.err.
Every listener is on 127.0.0.1 (the Docker cases use --network none: nothing is published). Stdlib only.
Groups: A print-preset and errors, B startup line and layers, C the preset's settings act, D hints, E Docker.
"""
import argparse, base64, hashlib, json, os, resource, shutil, signal, socket, struct, subprocess, sys, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRESET = os.path.join(ROOT, "contrib", "public.conf")
RESULTS = []


def record(case, ok, **kw):
    RESULTS.append({"case": case, "pass": bool(ok), **kw})
    print(("PASS " if ok else "FAIL ") + case + ("" if ok else "  " + json.dumps(kw)[:600]), flush=True)


def run(binary, args, timeout=10):
    p = subprocess.run([binary] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")


class Server:
    """finalwisp on 127.0.0.1:port; stderr to a file; stopped by its own handle (SIGTERM, then SIGKILL)."""

    def __init__(self, binary, port, args, log, pre=()):
        self.log = log
        self.f = open(log, "wb")
        # 60.60: --log-level debug: the lines these tests read (`finalwisp: preset ...`, `capabilities:`) are debug lines
        self.argv = list(pre) + ["--host", "127.0.0.1", "--port", str(port), "--drain-timeout", "0", "--log-level", "debug"] + list(args)
        self.p = subprocess.Popen([binary] + self.argv, stdout=subprocess.DEVNULL, stderr=self.f)
        self.wait_for("finalwisp listening on", 8)

    def text(self):
        with open(self.log, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def lines(self, needle):
        return [l for l in self.text().splitlines() if needle in l]

    def wait_for(self, needle, secs):
        end = time.time() + secs
        while time.time() < end:
            if needle in self.text():
                return True
            if self.p.poll() is not None:
                break
            time.sleep(0.05)
        return needle in self.text()

    def metric(self, name, secs=4):
        """the value of `name` in the newest ev=metrics line that is newer than this call"""
        n0 = len(self.lines("ev=metrics"))
        end = time.time() + secs
        while time.time() < end:
            ls = self.lines("ev=metrics")
            if len(ls) > n0 and ls[-1].endswith(tuple("0123456789")):
                for kv in ls[-1].split():
                    if kv.startswith(name + "="):
                        return int(kv.split("=")[1])
                return None
            time.sleep(0.1)
        return None

    def stop(self):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(5)
        self.f.close()


KEY = base64.b64encode(b"0123456789abcdef").decode()


def upgrade(port, headers="", src="127.0.0.1", timeout=3.0):
    """a WebSocket upgrade on / ; returns (socket, status line, bytes after the response head)"""
    s = socket.socket()
    s.settimeout(timeout)
    s.bind((src, 0))
    s.connect(("127.0.0.1", port))
    s.sendall(("GET / HTTP/1.1\r\nHost: t\r\n%sUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n" % (headers, KEY)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    return s, head.split(b"\r\n")[0].decode("latin1"), rest


def ws_frame(payload):
    """one masked binary frame (client to server; mask key 0)"""
    n = len(payload)
    if n < 126:
        h = bytes([0x82, 0x80 | n])
    else:
        h = bytes([0x82, 0x80 | 126]) + struct.pack(">H", n)
    return h + b"\0\0\0\0" + payload


def ws_parse(buf):
    """(payloads of the complete server frames, the rest)"""
    out = []
    while len(buf) >= 2:
        n, off = buf[1] & 0x7F, 2
        if n == 126:
            if len(buf) < 4:
                break
            n, off = struct.unpack(">H", buf[2:4])[0], 4
        elif n == 127:
            if len(buf) < 10:
                break
            n, off = struct.unpack(">Q", buf[2:10])[0], 10
        if len(buf) < off + n:
            break
        if buf[0] & 0x0F == 2:
            out.append(buf[off:off + n])
        buf = buf[off + n:]
    return out, buf


def wisp_connects(port, targets, budget=10.0, quiet=1.5):
    """Wisp v1: open one TCP stream per (host, port) in `targets` (stream ids from 1) on one connection. Returns
    {stream id: close reason} for the streams the server closed, read until `quiet` s pass without a packet or the
    total `budget` is used (probe rule: handles CLOSE, per-read timeout, total budget)."""
    s, status, rest = upgrade(port)
    if " 101 " not in status + " ":
        s.close()
        return None
    out = b"".join(ws_frame(bytes([1]) + struct.pack("<I", i + 1) + bytes([1]) + struct.pack("<H", p) + h.encode())
                   for i, (h, p) in enumerate(targets))
    s.sendall(out)
    closes, buf, end, last = {}, rest, time.time() + budget, time.time()
    s.settimeout(0.2)
    while time.time() < end and time.time() - last < quiet:
        try:
            d = s.recv(65536)
        except socket.timeout:
            d = None
        if d == b"":
            break
        if d:
            buf += d
            last = time.time()
        frames, buf = ws_parse(buf)
        for f in frames:
            if len(f) >= 6 and f[0] == 4:
                closes[struct.unpack("<I", f[1:5])[0]] = f[5]
    s.close()
    return closes


class Sink:
    """a TCP target on 127.0.0.1 that accepts and holds every connection"""

    def __init__(self):
        self.l = socket.socket()
        self.l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l.bind(("127.0.0.1", 0))
        self.l.listen(4096)
        self.port = self.l.getsockname()[1]
        self.conns, self.on = [], True
        self.l.settimeout(0.2)
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        while self.on:
            try:
                self.conns.append(self.l.accept()[0])
            except socket.timeout:
                pass
            except OSError:
                break

    def close(self):
        self.on = False
        self.t.join(2)
        for c in self.conns:
            c.close()
        self.l.close()


def group_a(a):
    shipped = open(PRESET, "rb").read()
    for name, args in [("A1 print-preset public", ["--print-preset", "public"]),
                       ("A2 print-preset beside the image's arguments",
                        ["--preset", "public", "--host", "0.0.0.0", "--port", "6001", "--print-preset", "public"])]:
        rc, out, err = run(a.bin, args)
        record(name, rc == 0 and out == shipped and err == "", argv=args, exit=rc, stdout_bytes=len(out),
               stdout_md5=hashlib.md5(out).hexdigest(), shipped_bytes=len(shipped), shipped_md5=hashlib.md5(shipped).hexdigest(),
               stderr=err[:300])
    rc, out, err = run(a.bin, ["--print-preset", "none"])
    record("A3 print-preset none", rc == 0 and out == b"" and err == "", exit=rc, stdout_bytes=len(out), stderr=err[:300])
    for name, args, want in [
        ("A4 print-preset of an unknown name", ["--print-preset", "pubic"], 'finalwisp: --print-preset: unknown preset "pubic" (the presets: public, none)'),
        ("A5 preset of an unknown name", ["--preset", "pubic"], 'finalwisp: --preset: unknown preset "pubic" (the presets: public, none)'),
        ("A6 preset without a name", ["--preset"], "finalwisp: --preset needs a value: --preset NAME"),
    ]:
        rc, out, err = run(a.bin, args)
        first = err.splitlines()[0] if err else ""
        record(name, rc == 2 and out == b"" and first == want, argv=args, exit=rc, first_line=first)
    conf = os.path.join(a.tmp, "bad.conf")
    open(conf, "w").write("port 1\npreset s3cretVALUE\n")
    rc, out, err = run(a.bin, ["--config", conf])
    first = err.splitlines()[0] if err else ""
    record("A7 unknown preset in a config file: line named, value hidden",
           rc == 2 and first == "finalwisp: %s:2: --preset needs the name of a preset (public, none)" % conf and "s3cret" not in err,
           exit=rc, first_line=first.replace(conf, "FILE"))
    # 60.60: --help is a short page on stdout (exit 0); the options are on the topic pages
    rc, out, err = run(a.bin, ["--help"])
    rc2, out2, _ = run(a.bin, ["--help", "config"])
    rc3, out3, _ = run(a.bin, ["--help", "destinations"])
    record("A8 --help lists --preset, --print-preset and --no-block-smtp", rc == 0 and rc2 == 0 and rc3 == 0 and err == ""
           and b"\n  --preset NAME " in out and b"--print-preset public" in out and b"\n  --preset NAME " in out2
           and b"\n  --print-preset NAME\n" in out2 and b"\n  --no-block-smtp\n" in out3, exit=rc)


def group_b(a):
    conf_off = os.path.join(a.tmp, "off.conf")
    open(conf_off, "w").write("max-streams-per-conn 64\nno-block-smtp\n")
    conf_named = os.path.join(a.tmp, "named.conf")
    open(conf_named, "w").write("preset public\nmax-streams-per-conn 2000\n")
    conf_off3 = os.path.join(a.tmp, "off3.conf")
    P = "finalwisp: preset "
    # v1.3.0: the preset has ten settings; T = the four switches of 60.57 / 60.58 and the four of 60.63 with one layer
    SW = ("fd-admission", "conn-share", "dns-own", "dns-reserve", "tcpmem-share", "port-share", "dest-failfast", "net-watch")
    open(conf_off3, "w").write("".join("no-%s\n" % k for k in SW))
    T = lambda layer, on="on": "".join(", %s %s (%s)" % (k, on, layer) for k in SW)
    off3 = ["--no-" + k for k in SW]
    cases = [
        ("B1 plain finalwisp: no preset line", [], None),
        ("B2 --preset public", ["--preset", "public"],
         P + "public (command line): block-smtp on (preset), max-streams-per-conn 1024 (preset)" + T("preset")),
        ("B3 every setting off on the command line", ["--preset", "public", "--no-block-smtp", "--max-streams-per-conn", "0"] + off3,
         P + "public (command line): block-smtp off (command line), max-streams-per-conn off (command line)" + T("command line", "off")),
        ("B4 a config file over the preset", ["--preset", "public", "--config", conf_off],
         P + "public (command line): block-smtp off (file), max-streams-per-conn 64 (file)" + T("preset")),
        ("B5 the command line over the file over the preset", ["--preset", "public", "--config", conf_off, "--block-smtp", "--max-streams-per-conn", "512"],
         P + "public (command line): block-smtp on (command line), max-streams-per-conn 512 (command line)" + T("preset")),
        ("B6 the preset named in the config file", ["--config", conf_named],
         P + "public (file): block-smtp on (preset), max-streams-per-conn 2000 (file)" + T("preset")),
        ("B7 --preset none after --preset public", ["--preset", "public", "--preset", "none"],
         P + "none (command line): block-smtp off (default), max-streams-per-conn off (default)" + T("default", "off")),
        ("B8 the command line's preset over the file's", ["--config", conf_named, "--preset", "none"],
         P + "none (command line): block-smtp off (default), max-streams-per-conn 2000 (file)" + T("default", "off")),
        ("B9 a config file turns the eight switches off", ["--preset", "public", "--config", conf_off3],
         P + "public (command line): block-smtp on (preset), max-streams-per-conn 1024 (preset)" + T("file", "off")),
    ]
    for i, (name, args, want) in enumerate(cases):
        s = Server(a.bin, a.port + i, args, os.path.join(a.logs, name.split()[0] + ".err"), pre=())
        time.sleep(0.3)
        got = s.lines("finalwisp: preset ")
        caps = s.lines("capabilities:")
        s.stop()
        limits = "limits:" + caps[0].split("limits:")[1].split(",")[0] if caps and "limits:" in caps[0] else ""
        ok = (got == [] if want is None else got == [want]) and s.p.returncode == 0
        record(name, ok, argv=[x.replace(a.tmp, "TMP") for x in args], preset_line=got, capability_limits=limits, exit=s.p.returncode)
    # B10 / B11 (60.58): a setting that another one needs cannot be turned off by name while that one is on
    for name, args, want, fix in [
        ("B10 --preset public --no-dns-share: refused, the reason names --no-dns-reserve",
         ["--preset", "public", "--no-dns-share"], "--no-dns-share and --dns-reserve together", "--no-dns-reserve turns the reserve off"),
        ("B11 --preset public --dns-server 192.0.2.1 --no-dns-own: refused",
         ["--preset", "public", "--dns-server", "192.0.2.1", "--no-dns-own"], "--no-dns-own and --dns-server together", "Remove one of the two"),
    ]:
        p = subprocess.run([a.bin] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        err = p.stderr.decode("utf-8", "replace")
        record(name, p.returncode == 2 and want in err and fix in err and "Try: finalwisp --help" in err,
               exit=p.returncode, stderr=err[:300])
    # B12 (60.58): --show-config names the two DNS settings of the preset, and the thread sharing that dns-reserve turns on
    p = subprocess.run([a.bin, "--preset", "public", "--show-config"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    rows = {l.split()[0]: " ".join(l.split()[1:]) for l in p.stdout.decode("utf-8", "replace").splitlines() if l.startswith("  dns-")}
    want = {"dns-own": "on (preset)", "dns-reserve": "on (preset)", "dns-share": "on (set by dns-reserve)"}
    record("B12 --preset public --show-config: dns-own, dns-reserve from the preset, dns-share set by dns-reserve",
           p.returncode == 0 and all(rows.get(k) == v for k, v in want.items()), exit=p.returncode, rows={k: rows.get(k) for k in want})


def group_c(a):
    sink = Sink()
    n = 1030
    targets = [("127.0.0.1", sink.port)] * n
    cases = [
        ("C1 --preset public: stream 1025 and later get 0x49", ["--preset", "public"], 6),
        ("C2 plain finalwisp: 1030 streams, none refused", [], 0),
        ("C3 --preset public --max-streams-per-conn 0: none refused", ["--preset", "public", "--max-streams-per-conn", "0"], 0),
        ("C4 --preset public --preset none: none refused", ["--preset", "public", "--preset", "none"], 0),
    ]
    for i, (name, args, want) in enumerate(cases):
        s = Server(a.bin, a.port + 20 + i, args + ["--allow-loopback", "--metrics-interval", "1"], os.path.join(a.logs, name.split()[0] + ".err"))
        closes = wisp_connects(a.port + 20 + i, targets)
        refused = sorted(k for k, v in (closes or {}).items() if v == 0x49)
        m = s.metric("refuse_limit")
        s.stop()
        ok = closes is not None and len(refused) == want and (want == 0 or refused == list(range(n - want + 1, n + 1))) and m == want \
            and len(closes) == want
        record(name, ok, streams_sent=n, closed_0x49=len(refused), first_refused=refused[:1], other_closes=len(closes or {}) - len(refused),
               refuse_limit=m)
    sink.close()
    for i, (name, args, want48) in enumerate([
        ("C5 --preset public: CONNECT to port 25, 465, 587 gets 0x48", ["--preset", "public"], True),
        ("C6 plain finalwisp: port 25, 465, 587 not refused by policy", [], False),
        ("C7 --preset public --no-block-smtp: not refused by policy", ["--preset", "public", "--no-block-smtp"], False),
    ]):
        s = Server(a.bin, a.port + 30 + i, args + ["--allow-loopback", "--metrics-interval", "1"], os.path.join(a.logs, name.split()[0] + ".err"))
        closes = wisp_connects(a.port + 30 + i, [("127.0.0.1", 25), ("127.0.0.1", 465), ("127.0.0.1", 587)], quiet=1.0)
        m = s.metric("refuse_policy")
        hint = s.lines("hint: mail ports 25, 465 and 587 are open")  # (60.60 wording)
        s.stop()
        reasons = [closes.get(k) for k in (1, 2, 3)] if closes is not None else None
        ok = reasons is not None and ((reasons == [0x48] * 3 and m == 3 and not hint) if want48 else (0x48 not in reasons and m == 0 and len(hint) == 1))
        record(name, ok, close_reasons=[("0x%02x" % r if r is not None else "open") for r in (reasons or [])], refuse_policy=m,
               smtp_startup_hint=len(hint))


def group_d(a):
    xff = "X-Forwarded-For: 198.51.100.7\r\n"
    HA = "finalwisp: hint: a request from 127.0.0.1 carries the header x-forwarded-for, but 127.0.0.1 is not a trusted proxy"
    HB = "finalwisp: hint: the trusted proxy 127.0.0.1 sent a request without the header x-forwarded-for"
    port = a.port + 40

    def hints(s):
        """the runtime hint lines (the startup hint about the mail ports is not one)"""
        return [l for l in s.lines("finalwisp: hint: ") if "mail ports" not in l]

    def conns(port, n, headers):
        socks = []
        for _ in range(n):
            s, status, _ = upgrade(port, headers)
            socks.append(s)
            if " 101 " not in status + " ":
                return socks, False
        return socks, True

    # D1 hint (a): a per-address limit is on (the server keeps peer addresses), the loopback peer is not trusted
    s = Server(a.bin, port, ["--max-conns-per-ip", "100000", "--metrics-interval", "1"], os.path.join(a.logs, "D1.err"))
    socks, ok101 = conns(port, 1, "")
    none_yet = s.metric("hint_fwd_untrusted") == 0 and not hints(s)
    more, ok2 = conns(port, 6, xff)
    socks += more
    m = s.metric("hint_fwd_untrusted")
    time.sleep(0.3)
    got = s.lines(HA)
    for c in socks:
        c.close()
    s.stop()
    record("D1 hint (a): untrusted loopback peer with X-Forwarded-For: one line, counter counts each request, all upgrades still 101",
           ok101 and ok2 and none_yet and len(got) == 1 and m == 6 and "--trusted-proxy 127.0.0.1" in got[0],
           requests_with_header=6, upgrades_101=ok101 and ok2, hint_lines=len(got), hint_fwd_untrusted=m, line=got[:1])
    # D2 the same requests against a plain finalwisp: it keeps no peer address, so no hint (documented limit)
    s = Server(a.bin, port + 1, ["--metrics-interval", "1"], os.path.join(a.logs, "D2.err"))
    socks, ok101 = conns(port + 1, 6, xff)
    m = s.metric("hint_fwd_untrusted")
    got = s.lines("finalwisp: hint: a request")
    for c in socks:
        c.close()
    s.stop()
    record("D2 plain finalwisp: the same requests, no hint and no count (no peer address is kept)", ok101 and m == 0 and not got,
           requests_with_header=6, hint_lines=len(got), hint_fwd_untrusted=m)
    # D3 hint (b): the peer is a trusted proxy and sends no header
    s = Server(a.bin, port + 2, ["--trusted-proxy", "127.0.0.1", "--metrics-interval", "1"], os.path.join(a.logs, "D3.err"))
    socks, ok101 = conns(port + 2, 1, xff)
    before = len(s.lines(HB)) == 0 and s.metric("realip_missing") == 0
    more, ok2 = conns(port + 2, 5, "")
    socks += more
    m, fa = s.metric("realip_missing"), s.metric("hint_fwd_untrusted")
    time.sleep(0.3)
    got = s.lines(HB)
    for c in socks:
        c.close()
    s.stop()
    record("D3 hint (b): trusted proxy without the header: one line, realip_missing counts each request",
           ok101 and ok2 and before and len(got) == 1 and m == 5 and fa == 0, requests_without_header=5, hint_lines=len(got),
           realip_missing=m, hint_fwd_untrusted=fa, line=got[:1])
    # D4 hint (c): 70 connections from one loopback address, a per-address limit on; the idle sweep finds it
    s = Server(a.bin, port + 3, ["--max-conns-per-ip", "100000", "--metrics-interval", "1", "--threads", "2"], os.path.join(a.logs, "D4.err"))
    socks, ok101 = conns(port + 3, 70, "")
    t0 = time.time()
    seen = s.wait_for("connections come from 127.0.0.1, a loopback or private address", 75)
    waited = round(time.time() - t0, 1)
    m = s.metric("one_key_conns_max")
    got = hints(s)
    for c in socks:
        c.close()
    s.stop()
    record("D4 hint (c): 70 connections from 127.0.0.1 with a per-address limit on: one line, gauge 70",
           ok101 and seen and m == 70 and len(got) == 1 and got[0].startswith("finalwisp: hint: 70 of 70 connections come from 127.0.0.1"),
           connections=70, hint_lines=len(got), one_key_conns_max=m, waited_s=waited, line=got[:1])
    # D5 below the floor of 64: no line
    s = Server(a.bin, port + 4, ["--max-conns-per-ip", "100000", "--metrics-interval", "1", "--threads", "2"], os.path.join(a.logs, "D5.err"))
    socks, ok101 = conns(port + 4, 60, "")
    time.sleep(40)
    m = s.metric("one_key_conns_max")
    got = hints(s)
    for c in socks:
        c.close()
    s.stop()
    record("D5 60 connections from 127.0.0.1 (below the floor of 64), 40 s: no line", ok101 and m == 0 and not got, connections=60,
           hint_lines=len(got), one_key_conns_max=m, waited_s=40)
    # D9 / D10 (v1.3.0 merge): the preset's conn-share builds the per-address table, so hints (a) and (c) fire with
    # --preset public alone
    s = Server(a.bin, port + 5, ["--preset", "public", "--metrics-interval", "1"], os.path.join(a.logs, "D9.err"))
    socks, ok101 = conns(port + 5, 6, xff)
    m = s.metric("hint_fwd_untrusted")
    time.sleep(0.3)
    got = s.lines(HA)
    for c in socks:
        c.close()
    s.stop()
    record("D9 hint (a) with --preset public alone: one line, the counter counts each request", ok101 and len(got) == 1 and m == 6,
           requests_with_header=6, hint_lines=len(got), hint_fwd_untrusted=m, line=got[:1])
    s = Server(a.bin, port + 6, ["--preset", "public", "--metrics-interval", "1", "--threads", "2"], os.path.join(a.logs, "D10.err"))
    socks, ok101 = conns(port + 6, 70, "")
    t0 = time.time()
    seen = s.wait_for("connections come from 127.0.0.1, a loopback or private address", 75)
    waited = round(time.time() - t0, 1)
    m = s.metric("one_key_conns_max")
    got = hints(s)
    for c in socks:
        c.close()
    s.stop()
    record("D10 hint (c) with --preset public alone: 70 connections from 127.0.0.1: one line, gauge 70",
           ok101 and seen and m == 70 and len(got) == 1 and got[0].startswith("finalwisp: hint: 70 of 70 connections come from 127.0.0.1"),
           connections=70, hint_lines=len(got), one_key_conns_max=m, waited_s=waited, line=got[:1])
    if a.caddy:
        group_d_caddy(a, port + 10, HA, HB)


def group_d_caddy(a, port, HA, HB):
    """a real reverse proxy on loopback: Caddy adds X-Forwarded-For by default"""
    for i, (name, args, want_hint) in enumerate([
        ("D7 Caddy in front, not trusted: hint (a), every client keyed as 127.0.0.1", ["--max-conns-per-ip", "100000"], True),
        ("D8 Caddy in front, --trusted-proxy 127.0.0.1: no hint", ["--max-conns-per-ip", "100000", "--trusted-proxy", "127.0.0.1"], False),
    ]):
        fw, cp = port + 2 * i, port + 2 * i + 1
        cf = os.path.join(a.tmp, "Caddyfile%d" % i)
        open(cf, "w").write("{\n\tadmin off\n\tauto_https off\n}\nhttp://:%d {\n\tbind 127.0.0.1\n\treverse_proxy 127.0.0.1:%d\n}\n" % (cp, fw))
        s = Server(a.bin, fw, args + ["--metrics-interval", "1", "--log-conns"], os.path.join(a.logs, name.split()[0] + ".err"))
        clog = open(os.path.join(a.logs, name.split()[0] + ".caddy.log"), "wb")
        c = subprocess.Popen([a.caddy, "run", "--config", cf, "--adapter", "caddyfile"], stdout=clog, stderr=clog,
                             env={**os.environ, "XDG_DATA_HOME": a.tmp, "XDG_CONFIG_HOME": a.tmp})
        ok101, socks = False, []
        end = time.time() + 8
        while time.time() < end and not ok101:
            try:
                so, status, _ = upgrade(cp, "", timeout=2.0)
                ok101 = " 101 " in status + " "
                if ok101:
                    socks.append(so)
                else:
                    so.close()
                    time.sleep(0.2)
            except OSError:
                time.sleep(0.2)
        for _ in range(2):
            so, status, _ = upgrade(cp, "X-Forwarded-For: 198.18.0.9\r\n")
            ok101 = ok101 and " 101 " in status + " "
            socks.append(so)
        m, miss = s.metric("hint_fwd_untrusted"), s.metric("realip_missing")
        for so in socks:
            so.close()
        time.sleep(0.5)
        got = s.lines(HA)
        ips = sorted(set(kv[3:] for l in s.lines("ev=conn_close") for kv in l.split() if kv.startswith("ip=")))
        c.terminate()
        try:
            c.wait(5)
        except subprocess.TimeoutExpired:
            c.kill()
        clog.close()
        s.stop()
        ok = ok101 and ((len(got) == 1 and m == 3 and ips == ["127.0.0.1"]) if want_hint else (not got and m == 0 and miss == 0 and ips == ["127.0.0.1"]))
        record(name, ok, upgrades_through_caddy=len(socks), upgrades_101=ok101, hint_lines=len(got), hint_fwd_untrusted=m, realip_missing=miss,
               logged_client_ips=ips)


def group_e(a):
    """the image: contrib/docker/Dockerfile with this binary; --network none (nothing reachable, nothing published)"""
    ctx = os.path.join(a.tmp, "ctx")
    os.makedirs(ctx, exist_ok=True)
    shutil.copy(a.bin, os.path.join(ctx, "finalwisp"))
    bi = os.path.join(os.path.dirname(a.bin), "BUILDINFO")
    open(os.path.join(ctx, "BUILDINFO"), "w").write(open(bi).read() if os.path.exists(bi) else "test build\n")
    tag = "v13form-fn:test"
    b = subprocess.run(["docker", "build", "-q", "-f", os.path.join(ROOT, "contrib", "docker", "Dockerfile"), "-t", tag, ctx],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    record("E0 docker build of contrib/docker/Dockerfile", b.returncode == 0, exit=b.returncode, out=b.stdout.decode()[-300:])
    if b.returncode != 0:
        return
    insp = subprocess.run(["docker", "inspect", "-f", "{{json .Config.Entrypoint}} {{json .Config.Cmd}}", tag], stdout=subprocess.PIPE, timeout=60)
    got = insp.stdout.decode().strip()
    record("E1 image ENTRYPOINT and CMD", got == '["/finalwisp","--preset","public"] ["--host","0.0.0.0","--port","6001"]', entrypoint_cmd=got)
    shipped = open(PRESET, "rb").read()
    p = subprocess.run(["docker", "run", "--rm", "--network", "none", tag, "--print-preset", "public"], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=120)
    record("E2 docker run IMAGE --print-preset public", p.returncode == 0 and p.stdout == shipped, exit=p.returncode,
           stdout_bytes=len(p.stdout), stdout_md5=hashlib.md5(p.stdout).hexdigest(), shipped_md5=hashlib.md5(shipped).hexdigest(),
           stderr=p.stderr.decode("utf-8", "replace")[:300])
    # 60.60: at the default log level the start block's `preset` row says it (the image's CMD cannot carry --log-level debug)
    P = "  preset        "
    # (v1.3.0: the four switches of 60.57 / 60.58 and the four of 60.63)
    T = ", fd-admission on, conn-share on, dns-own on, dns-reserve on, tcpmem-share on, port-share on, dest-failfast on, net-watch on"
    for name, extra, want, listen in [
        ("E3 docker run IMAGE", [], P + "public: block-smtp on, max-streams-per-conn 1024" + T, "0.0.0.0:6001"),
        ("E4 docker run IMAGE --host 0.0.0.0 --port 6001 --motd hi (arguments replace CMD, the preset stays)",
         ["--host", "0.0.0.0", "--port", "6001", "--motd", "hi"], P + "public: block-smtp on, max-streams-per-conn 1024" + T, "0.0.0.0:6001"),
        ("E5 docker run IMAGE --host 0.0.0.0 --port 6001 --preset none",
         ["--host", "0.0.0.0", "--port", "6001", "--preset", "none"], P + "none", "0.0.0.0:6001"),
        ("E6 docker run IMAGE --host 0.0.0.0 --port 6001 --no-block-smtp",
         ["--host", "0.0.0.0", "--port", "6001", "--no-block-smtp"], P + "public: block-smtp off (command line), max-streams-per-conn 1024" + T,
         "0.0.0.0:6001"),
        ("E7 docker run IMAGE --port 7000 (CMD replaced: the default host again, the preset stays)",
         ["--port", "7000"], P + "public: block-smtp on, max-streams-per-conn 1024" + T, "127.0.0.1:7000"),
    ]:
        cname = "v13form-fn-" + name.split()[0].lower()
        subprocess.run(["docker", "run", "-d", "--rm", "--name", cname, "--network", "none", "--stop-timeout", "2", tag] + (extra + ["--drain-timeout", "0"] if extra else []),  # E3: no argument at all, so the image's CMD applies
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        time.sleep(2.0)
        logs = subprocess.run(["docker", "logs", cname], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60).stdout.decode("utf-8", "replace")
        subprocess.run(["docker", "stop", "-t", "2", cname], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        open(os.path.join(a.logs, name.split()[0] + ".err"), "w").write(logs)
        # the row with its continuation lines (the block wraps a long value under its column)
        pl, ls = [], logs.splitlines()
        for i, l in enumerate(ls):
            if l.startswith(P):
                j = i + 1
                while j < len(ls) and ls[j].startswith(" " * len(P)):
                    l, j = l + " " + ls[j].strip(), j + 1
                pl.append(l)
        li = [l for l in logs.splitlines() if "finalwisp listening on" in l]
        nofile = [l.split("up to ")[1] for l in logs.splitlines() if l.startswith("  open files ") and "up to " in l]
        record(name, pl == [want] and len(li) == 1 and ("//%s/" % listen) in li[0] and "--trusted-proxy" not in logs, preset_line=pl,
               listening=[l.split(" (")[0] for l in li], nofile=nofile[:1])
    subprocess.run(["docker", "image", "rm", tag], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base-port", type=int, default=9780)
    ap.add_argument("--caddy", default=shutil.which("caddy"))
    ap.add_argument("--docker", action="store_true")
    ap.add_argument("--only", default="A,B,C,D,E")
    a = ap.parse_args()
    a.bin, a.port = os.path.abspath(a.bin), a.base_port
    a.logs = os.path.join(a.out, "logs")
    os.makedirs(a.logs, exist_ok=True)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 65536) if hard != resource.RLIM_INFINITY else 65536, hard))
    md5 = hashlib.md5(open(a.bin, "rb").read()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="v13form-") as tmp:
        a.tmp = tmp
        for g, f in [("A", group_a), ("B", group_b), ("C", group_c), ("D", group_d), ("E", group_e)]:
            if g in a.only.split(",") and (g != "E" or a.docker):
                f(a)
    out = {"binary_md5": md5, "date": time.strftime("%Y-%m-%d %H:%M:%S"), "host": os.uname().nodename, "kernel": os.uname().release,
           "groups": a.only, "caddy": bool(a.caddy), "docker": a.docker, "cases": RESULTS}
    path = os.path.join(a.out, "fn.json")
    json.dump(out, open(path, "w"), indent=1)
    bad = [r["case"] for r in RESULTS if not r["pass"]]
    print("v13-form-fn: %d cases, %d passed, %d FAILED -> %s" % (len(RESULTS), len(RESULTS) - len(bad), len(bad), path))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
