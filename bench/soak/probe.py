# 30.11 soak: one correctness probe against one server (fresh client). Prints one JSON line.
# usage: probe.py --port P [--tls] [--dl-mib N] [--expect-private REASON]
import argparse, hashlib, json, os, struct, sys, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import random
from wispc import Wisp, Closed, CONNECT, DATA, CONTINUE, CLOSE, mask_frame, pattern_base, pattern_chunk

PATTERN, ECHO, UDP, REFUSED = 7106, 7101, 7105, 7199

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--tls", action="store_true")
ap.add_argument("--dl-mib", type=int, default=32)
ap.add_argument("--ul-mib", type=int, default=4)
ap.add_argument("--expect-private", default="0x48")
a = ap.parse_args()

# 30.11 fix (soak12 h6.3): recv_pkt leaves the socket timeout at its leftover (<= 50 ms in the upload loop), so
# a sendall during a CPU burst raised TimeoutError (harness, not server). Sends get a fixed 10 s timeout.
_send = Wisp.send_pkt
def _send_pkt(self, ty, sid, body=b""):
    self.s.settimeout(10)
    return _send(self, ty, sid, body)
Wisp.send_pkt = _send_pkt

res = {"t": time.time(), "port": a.port, "tls": a.tls, "fail": [], "ms": {}}
def fail(step, msg):
    res["fail"].append(f"{step}: {msg}")

def timed(step):
    class T:
        def __enter__(s): s.t0 = time.monotonic()
        def __exit__(s, *e): res["ms"][step] = round((time.monotonic() - s.t0) * 1000, 1)
    return T()


def stream_close_reason(w, sid, t):
    end = time.monotonic() + t
    while time.monotonic() < end:
        p = w.recv_pkt(end - time.monotonic())
        if p is None:
            return None
        if p[1] == sid and p[0] == CLOSE:
            return p[2][0] if p[2] else -1
    return None


def download(w, sid):
    n = a.dl_mib << 20
    seed = int.from_bytes(os.urandom(8), "little")
    base = pattern_base(seed)
    w.connect(sid, PATTERN)
    w.send_pkt(DATA, sid, struct.pack("<QQ", n, seed))
    got = bytearray(); pos = 0; idx = 0; reason = None
    t0 = time.monotonic()
    while True:
        p = w.recv_pkt(20)
        if p is None:
            return fail("download", f"stalled at {pos + len(got)} of {n} bytes (20 s without a packet)")
        ty, s, body = p
        if s != sid:
            continue
        if ty == DATA:
            got += body
            while len(got) >= 65536:
                if got[:65536] != pattern_chunk(seed, idx, base):
                    return fail("download", f"pattern mismatch in chunk {idx} (offset {pos})")
                del got[:65536]; pos += 65536; idx += 1
        elif ty == CLOSE:
            reason = body[0] if body else -1
            break
    if got:
        if bytes(got) != pattern_chunk(seed, idx, base)[:len(got)]:
            return fail("download", f"pattern mismatch in last chunk {idx}")
        pos += len(got)
    dt = time.monotonic() - t0
    res["dl_mib_s"] = round(n / dt / 2**20, 1)
    if pos != n:
        fail("download", f"got {pos} bytes, expected {n}")
    if reason != 0x02:
        fail("download", f"CLOSE reason {reason:#x}, expected 0x02")


def upload_echo(w, sid):
    total = a.ul_mib << 20
    data = os.urandom(total)
    w.connect(sid, ECHO)
    remaining = w.credit; sent = 0; echo = bytearray(); t0 = time.monotonic(); last = t0
    while len(echo) < total:
        while remaining > 0 and sent < total:
            w.send_pkt(DATA, sid, data[sent:sent + 16384]); sent += 16384; remaining -= 1
        p = w.recv_pkt(0.05 if sent < total else 1.0)
        if p is None:
            if time.monotonic() - last > 20:
                return fail("upload", f"stalled: sent {sent}, echoed {len(echo)}, credit left {remaining}")
            continue
        last = time.monotonic()
        ty, s, body = p
        if s != sid:
            continue
        if ty == CONTINUE:
            remaining = struct.unpack("<I", body[:4])[0]
        elif ty == DATA:
            echo += body
        elif ty == CLOSE:
            return fail("upload", f"unexpected CLOSE {body[:1].hex()} after {len(echo)} echoed bytes")
    res["ul_mib_s"] = round(total / (time.monotonic() - t0) / 2**20, 1)
    if hashlib.sha256(echo).digest() != hashlib.sha256(data).digest():
        fail("upload", "echoed bytes differ")
    w.close_stream(sid)


def upmux(w, base_sid, n=8, per=256 << 10):
    """30.14 (20.33 upload batching): n echo streams, DATA of 1-4 KiB interleaved across the streams and sent in
    batches of many frames per sendall (one client read batch holds frames of several targets). Credit per stream
    is respected (CONTINUE sets the stream's credit); every stream's echo must equal its bytes, in order."""
    sids = list(range(base_sid, base_sid + n))
    data = {s: os.urandom(per) for s in sids}
    sent = {s: 0 for s in sids}; credit = {s: w.credit for s in sids}; echo = {s: bytearray() for s in sids}
    for s in sids:
        w.connect(s, ECHO)
    rnd = random.Random(); last = time.monotonic()
    while any(len(echo[s]) < per for s in sids):
        batch = []
        for _ in range(64):  # one round robin pass per frame slot: interleaved like epoxy / wisp-js / wbench
            for s in sids:
                if sent[s] < per and credit[s] > 0:
                    k = rnd.randint(1024, 4096)
                    batch.append(mask_frame(2, struct.pack("<BI", DATA, s) + data[s][sent[s]:sent[s] + k]))
                    sent[s] += min(k, per - sent[s]); credit[s] -= 1
        if batch:
            w.s.settimeout(10)
            w.s.sendall(b"".join(batch))
        p = w.recv_pkt(0.05 if any(sent[s] < per and credit[s] > 0 for s in sids) else 1.0)
        if p is None:
            if time.monotonic() - last > 20:
                return fail("upmux", f"stalled: sent {sum(sent.values())}, echoed {sum(map(len, echo.values()))}")
            continue
        last = time.monotonic()
        ty, s, body = p
        if s not in echo:
            continue
        if ty == CONTINUE:  # absolute, like wisp-js / epoxy (frames in flight can exceed it: credit v2 tolerates)
            credit[s] = struct.unpack("<I", body[:4])[0]
        elif ty == DATA:
            echo[s] += body
        elif ty == CLOSE:
            return fail("upmux", f"stream {s}: unexpected CLOSE {body[:1].hex()} after {len(echo[s])} echoed bytes")
    bad = [s for s in sids if bytes(echo[s]) != data[s]]
    if bad:
        fail("upmux", f"{len(bad)} of {n} streams echoed wrong bytes (first {bad[0]})")
    for s in sids:
        w.close_stream(s)


def streams100(w, base_sid):
    sids = list(range(base_sid, base_sid + 100))
    want = {s: os.urandom(512) for s in sids}
    for s in sids:
        w.connect(s, ECHO)
        w.send_pkt(DATA, s, want[s])
    got = {s: bytearray() for s in sids}
    pending = set(sids); end = time.monotonic() + 20
    while pending and time.monotonic() < end:
        p = w.recv_pkt(end - time.monotonic())
        if p is None:
            break
        ty, s, body = p
        if s not in got:
            continue
        if ty == DATA:
            got[s] += body
            if len(got[s]) >= 512:
                pending.discard(s)
        elif ty == CLOSE:
            fail("streams100", f"stream {s} closed by server, reason {body[:1].hex()}")
            pending.discard(s)
    if pending:
        fail("streams100", f"{len(pending)} of 100 streams got no full echo in 20 s")
    bad = [s for s in sids if s not in pending and got[s] and bytes(got[s]) != want[s]]
    if bad:
        fail("streams100", f"{len(bad)} streams echoed wrong bytes")
    for s in sids:
        w.close_stream(s)


def expect_close(w, step, sid, port, host, want, t=15):
    w.connect(sid, port, host)
    with timed(step):
        r = stream_close_reason(w, sid, t)
    if r is None:
        fail(step, f"no CLOSE in {t} s (expected {want:#x})")
    elif r != want:
        fail(step, f"CLOSE {r:#x}, expected {want:#x}")
    res.setdefault("reasons", {})[step] = r


def udp(w, sid):
    w.connect(sid, UDP, b"127.0.0.1", stype=2)
    for i in range(3):
        w.send_pkt(DATA, sid, b"soak-udp-%d" % i)
        end = time.monotonic() + 1.0
        while time.monotonic() < end:
            p = w.recv_pkt(end - time.monotonic())
            if p and p[1] == sid and p[0] == DATA and p[2].startswith(b"soak-udp-"):
                res["udp_tries"] = i + 1
                w.close_stream(sid)
                return
            if p and p[1] == sid and p[0] == CLOSE:
                return fail("udp", f"CLOSE {p[2][:1].hex()}")
    fail("udp", "no datagram echoed after 3 tries")


def main():
    t0 = time.monotonic()
    try:
        with timed("handshake"):
            w = Wisp(a.port, tls=a.tls)
        res["credit"] = w.credit
        with timed("download"):
            download(w, 1)
        with timed("upload"):
            upload_echo(w, 3)
        with timed("streams100"):
            streams100(w, 100)
        with timed("upmux"):
            upmux(w, 300)
        expect_close(w, "refused", 5, REFUSED, b"127.0.0.1", 0x44)
        expect_close(w, "dns_invalid", 7, 80, b"soak-%s.invalid" % os.urandom(4).hex().encode(), 0x42)
        if a.expect_private != "skip":
            expect_close(w, "private", 9, 80, b"10.255.255.1", int(a.expect_private, 16))
        with timed("udp"):
            udp(w, 11)
        w.close()
    except (Closed, OSError) as e:
        fail("conn", f"{type(e).__name__}: {e}")
    res["ms"]["total"] = round((time.monotonic() - t0) * 1000, 1)
    res["ok"] = not res["fail"]
    print(json.dumps(res), flush=True)


main()
