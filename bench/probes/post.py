#!/usr/bin/env python3
"""60.44 POST-like upload latency probe (v11x-kmem; stdlib). Measures what a fresh stream's first credit costs a short
upload: one warm WebSocket connection (Wisp v1; answers pings, so credit v2 is active), then per request a NEW stream:
CONNECT, an 8-byte length + N bytes of DATA in --pkt packets (respecting the stream's credit: the handshake CONTINUE,
then CONTINUE(sid)), and the time until the ack target's 1-byte reply arrives (= the whole body reached the target).
Also records how long the sender waited on credit per request.

  post.py target --port P [--bind ADDR]        ack target: per TCP connection read 8-byte LE length + that many bytes, send b"k"
  post.py run --url ws://H:P/ --target H:P --sizes 65536,262144,1048576,4194304 --reps R [--pkt 16384] [--fresh]
      --fresh: a new WebSocket connection per request (cold path: TCP + upgrade included in the latency)
  Output: one JSON line per request ({size, ms, credit_wait_ms, rep}) and a summary line per size (median, p90).
"""
import argparse, base64, json, os, select, socket, struct, sys, threading, time

DATA, CONNECT, CONT, CLOSE = 2, 1, 3, 4


def target(a):
    srv = socket.socket(socket.AF_INET6 if ":" in a.bind else socket.AF_INET)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port)); srv.listen(512)

    def serve(c):
        try:
            while True:
                h = b""
                while len(h) < 8:
                    x = c.recv(8 - len(h))
                    if not x:
                        return
                    h += x
                n = struct.unpack("<Q", h)[0]
                while n > 0:
                    x = c.recv(min(n, 1 << 20))
                    if not x:
                        return
                    n -= len(x)
                c.sendall(b"k")
        except OSError:
            pass
        finally:
            c.close()
    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


class WS:
    def __init__(self, url):
        hp = url.split("//", 1)[1].split("/", 1)
        host, port = hp[0].rsplit(":", 1)
        path = "/" + (hp[1] if len(hp) > 1 else "")
        self.s = socket.create_connection((host.strip("[]"), int(port)), timeout=30)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            x = self.s.recv(4096)
            if not x:
                raise OSError("upgrade: closed")
            buf += x
        head, self.rb = buf.split(b"\r\n\r\n", 1)
        self.s.settimeout(None)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise OSError("upgrade refused: " + head[:80].decode(errors="replace"))
        self.hs_credit = None
        self.credit = {}
        self.acked = set()
        self.closed = {}
        self.wb = bytearray()

    def frame(self, op, payload):
        n = len(payload)
        h = bytes([0x80 | op])
        if n < 126:
            h += bytes([0x80 | n])
        elif n < 65536:
            h += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            h += bytes([0x80 | 127]) + struct.pack(">Q", n)
        # zero mask key: masking is a no-op (allowed: the key is the client's choice)
        self.wb += h + b"\0\0\0\0" + payload

    def wisp(self, ty, sid, body=b""):
        self.frame(2, struct.pack("<BI", ty, sid) + body)

    def flush(self, block=True):
        while self.wb:
            try:
                n = self.s.send(self.wb, 0 if block else socket.MSG_DONTWAIT)
            except BlockingIOError:
                return
            del self.wb[:n]

    def pump(self, timeout):
        """read and handle what is there (wait up to timeout for the first bytes)"""
        if not self.parse():
            r, w, _ = select.select([self.s], [self.s] if self.wb else [], [], timeout)
            if w:
                self.flush(block=False)
            if not r:
                return
            x = self.s.recv(1 << 20)
            if not x:
                raise OSError("server closed")
            self.rb += x
            self.parse()

    def parse(self):
        """handle every complete frame in rb; True if any"""
        got = False
        while True:
            b = self.rb
            if len(b) < 2:
                return got
            op, ln, o = b[0] & 0x0F, b[1] & 0x7F, 2
            if ln == 126:
                if len(b) < 4: return got
                ln, o = struct.unpack(">H", b[2:4])[0], 4
            elif ln == 127:
                if len(b) < 10: return got
                ln, o = struct.unpack(">Q", b[2:10])[0], 10
            if len(b) < o + ln:
                return got
            p = bytes(b[o:o + ln]); self.rb = b[o + ln:]
            got = True
            if op == 9:
                self.frame(10, p)  # flushed by the next pump (select on writable)
            elif op == 2 and len(p) >= 5:
                ty, sid = struct.unpack("<BI", p[:5])
                if ty == CONT:
                    v = struct.unpack("<I", p[5:9])[0]
                    if sid == 0:
                        self.hs_credit = v
                    else:
                        self.credit[sid] = v
                elif ty == DATA and p[5:6] == b"k":
                    self.acked.add(sid)
                elif ty == CLOSE:
                    self.closed[sid] = p[5] if len(p) > 5 else -1  # refused or reset: an error, never an ack
            elif op == 8:
                raise OSError("ws close")


class Stall(Exception):
    pass


def request(ws, sid, host, port, size, pkt, limit=30.0):
    """one POST on a new stream; Stall(state) when it does not finish within `limit` s (review 60.44: an 8 h chain of
    600 s driver timeouts; every wait now has a deadline)"""
    t0 = time.perf_counter()
    end = t0 + limit
    st = {"phase": "hs", "left": size, "credit": None}

    def pump():
        if sid in ws.closed:
            raise Stall(json.dumps({**st, "closed_reason": ws.closed[sid]}))
        if time.perf_counter() > end:
            st["credit"] = ws.credit.get(sid)
            raise Stall(json.dumps(st))
        ws.pump(min(1.0, max(0.01, end - time.perf_counter())))
    while ws.hs_credit is None:
        pump()
    ws.credit[sid] = ws.hs_credit
    ws.wisp(CONNECT, sid, struct.pack("<BH", 1, port) + host.encode())
    body = struct.pack("<Q", size)
    left, wait = size, 0.0
    first = True
    while left > 0 or first:
        if ws.credit[sid] <= 0:
            st["phase"], st["left"] = "credit", left
            tw = time.perf_counter()
            while ws.credit[sid] <= 0:
                pump()
            wait += time.perf_counter() - tw
        n = min(pkt - (8 if first else 0), left)
        ws.wisp(DATA, sid, (body if first else b"") + b"x" * n)
        ws.credit[sid] -= 1
        left -= n; first = False
        if len(ws.wb) > (1 << 20):
            st["phase"], st["left"] = "send", left
            while len(ws.wb) > (256 << 10):  # non-blocking: keep reading (pings, CONTINUEs) while the buffer drains
                pump()
    st["phase"], st["left"] = "drain", 0
    while ws.wb:
        pump()
    st["phase"] = "ack"
    while sid not in ws.acked:
        pump()
    ms = (time.perf_counter() - t0) * 1000
    ws.wisp(CLOSE, sid, b"\x02")  # flushed by the next pump
    ws.credit.pop(sid, None)
    return ms, wait * 1000


def run(a):
    host, port = a.target.rsplit(":", 1)
    sizes = [int(x) for x in a.sizes.split(",")]
    res = {s: [] for s in sizes}
    ws = None  # connected at the first request (inside the try: a failed connect is an error row)
    sid = 0
    start = time.time()
    for rep in range(a.warm + a.reps):
        for s in sizes:
            t0 = time.perf_counter()
            sid += 1
            if time.time() - start > a.budget:
                print(json.dumps({"error": "budget", "budget_s": a.budget}), flush=True)
                return summary(res, sizes)
            try:
                if a.fresh or ws is None:
                    ws = WS(a.url)
                ms, w = request(ws, sid, host, int(port), s, a.pkt, a.limit)
            except (Stall, OSError) as e:
                print(json.dumps({"size": s, "error": type(e).__name__, "state": str(e), "rep": rep - a.warm}), flush=True)
                try:
                    if ws is not None:
                        ws.s.close()
                except OSError:
                    pass
                ws = None  # reconnect at the next request (a failed connect is an error row too)
                continue
            if a.fresh:
                ms = (time.perf_counter() - t0) * 1000
                ws.s.close()
            if rep >= a.warm:
                res[s].append(ms)
                print(json.dumps({"size": s, "ms": round(ms, 2), "credit_wait_ms": round(w, 2), "rep": rep - a.warm}), flush=True)
            if a.gap:
                time.sleep(a.gap)
    summary(res, sizes)


def summary(res, sizes):
    for s in sizes:
        v = sorted(res[s])
        if not v:
            print(json.dumps({"summary": True, "size": s, "n": 0}), flush=True)
            continue
        print(json.dumps({"summary": True, "size": s, "n": len(v), "median_ms": round(v[len(v) // 2], 2),
                          "p90_ms": round(v[int(len(v) * 0.9)], 2), "min_ms": round(v[0], 2),
                          "mib_s_median": round(s / 2**20 / (v[len(v) // 2] / 1000), 2)}), flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    t = sp.add_parser("target"); t.add_argument("--port", type=int, required=True); t.add_argument("--bind", default="127.0.0.1")
    r = sp.add_parser("run")
    r.add_argument("--url", required=True); r.add_argument("--target", required=True)
    r.add_argument("--sizes", default="65536,262144,1048576,4194304"); r.add_argument("--reps", type=int, default=10)
    r.add_argument("--warm", type=int, default=1); r.add_argument("--pkt", type=int, default=16384)
    r.add_argument("--fresh", action="store_true"); r.add_argument("--gap", type=float, default=0.0)
    r.add_argument("--limit", type=float, default=30.0, help="per request (s): a stall is recorded and the connection replaced")
    r.add_argument("--budget", type=float, default=600.0, help="whole run (s)")
    a = ap.parse_args()
    target(a) if a.cmd == "target" else run(a)
