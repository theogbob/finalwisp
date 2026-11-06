#!/usr/bin/env python3
"""70.01 seed corpora for the cargo-fuzz targets (server/fuzz). Deterministic; writes corpus/<target>/seed-*.
Cases follow tests/compat/adversarial.py (#1-#7, #11, #12, #19, #20), the v2 auth tests and real client flows
(wisp-js / epoxy: v2 INFO, CONNECT tcp+udp, DATA, CLOSE; wsproxy). usage: python3 seeds.py"""
import os, ssl, struct, hashlib

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")
KEY = "dGhlIHNhbXBsZSBub25jZQ=="
MASK = b"\x37\xfa\x21\x3d"

def frame(op, payload, mask=True, fin=True, rsv=0):
    b0 = (0x80 if fin else 0) | rsv | op
    n = len(payload)
    mb = 0x80 if mask else 0
    if n < 126:
        hdr = bytes([b0, mb | n])
    elif n <= 0xFFFF:
        hdr = bytes([b0, mb | 126]) + struct.pack(">H", n)
    else:
        hdr = bytes([b0, mb | 127]) + struct.pack(">Q", n)
    if not mask:
        return hdr + payload
    return hdr + MASK + bytes(c ^ MASK[i & 3] for i, c in enumerate(payload))

def upgrade(path="/", proto=None, ver="1.1", key=KEY, extra=""):
    p = f"Sec-WebSocket-Protocol: {proto}\r\n" if proto else ""
    return (f"GET {path} HTTP/{ver}\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{p}{extra}\r\n").encode()

def wisp(ty, sid, body=b""):
    return bytes([ty]) + struct.pack("<I", sid) + body

def connect(sid, host=b"127.0.0.1", port=4444, stype=1):
    return wisp(1, sid, bytes([stype]) + struct.pack("<H", port) + host)

def record(i, meta):
    return bytes([i]) + struct.pack("<I", len(meta)) + meta

INFO_PW = wisp(5, 0, b"\x02\x00" + record(2, b"\x01up"))
INFO_BARE = wisp(5, 0, b"\x02\x00")
INFO_UDP = wisp(5, 0, b"\x02\x00" + record(1, b""))

def client_hello():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    i, o = ssl.MemoryBIO(), ssl.MemoryBIO()
    s = ctx.wrap_bio(i, o, server_hostname="localhost")
    try:
        s.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return o.read()

def write(target, name, data):
    d = os.path.join(ROOT, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "seed-" + name), "wb") as f:
        f.write(data)

def main():
    # ---- ws-parse: [max selector] frame header (+payload)
    ws = {
        "bin-small": frame(2, b"\x02\x01\x00\x00\x00hi"), "bin-126": frame(2, b"a" * 126), "bin-64k": frame(2, b"a" * 65536)[:20],
        "unmasked": frame(2, b"x", mask=False), "ping125": frame(9, b"p" * 125), "ping126": frame(9, b"p" * 126)[:8],
        "close": frame(8, b"\x03\xe8"), "cont": frame(0, b"x", fin=False), "rsv": frame(2, b"x", rsv=0x40),
        "len64-16m": bytes([0x82, 0xFF]) + struct.pack(">Q", 16 << 20) + MASK, "len64-huge": bytes([0x82, 0xFF]) + b"\x80" + b"\x00" * 7 + MASK,
        "len64-max+1": bytes([0x82, 0xFF]) + struct.pack(">Q", (16 << 20) + 1) + MASK, "op3": frame(3, b"x"), "text": frame(1, b"hello"),
    }
    for k, v in ws.items():
        write("ws-parse", k, b"\x00" + v)
    # ---- http-parse
    http = {
        "v1": upgrade(), "v2": upgrade(proto="wisp-v2"), "v2-multi": upgrade(proto="wisp-v2, other"),
        "wsproxy": upgrade("/p/127.0.0.1:4444"), "wsproxy-pct": upgrade("/%5B%3A%3A1%5D:443?x=1"), "wsproxy-v6": upgrade("/[::1]:80"),
        "http10": upgrade(ver="1.0"), "shortkey": upgrade(key="short"), "plain": b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        "split-conn": b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + KEY.encode() + b"\r\nSec-WebSocket-Version: 13\r\n\r\n",
        "lf-only": upgrade().replace(b"\r\n", b"\n"), "nonascii-path": b"GET /%a\xc3\xa9:80 HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + KEY.encode() + b"\r\nSec-WebSocket-Version: 13\r\n\r\n",
        "partial": upgrade()[:40], "post": upgrade().replace(b"GET", b"POST"), "obs-text-proto": upgrade(extra="Sec-WebSocket-Protocol: \xe9t\xe9\r\n".encode("latin-1").decode("latin-1")),
    }
    for k, v in http.items():
        write("http-parse", k, v)
    # ---- ext-records: [mode] records ; mode 2 = signed (user), mode 3 = auth file / PEM
    ex = {
        "pw-ok": b"\x00" + record(2, b"\x01up"), "pw-bad": b"\x00" + record(2, b"\x01uX"), "pw-alice": b"\x00" + record(2, b"\x05alices3cr:et"),
        "udp-pw": b"\x00" + record(1, b"") + record(2, b"\x01up"), "dup": b"\x00" + record(2, b"\x01up") * 2, "trunc": b"\x00\x02\x05\x00",
        "cert-97": b"\x00" + record(3, b"\x01" + b"\x00" * 96), "cert-user": b"\x00" + record(3, b"\x03bob\x01" + b"\x00" * 96),
        "unknown": b"\x00" + record(0x99, b"x" * 10) + record(4, b"motd"), "pw-empty": b"\x00" + record(2, b""), "ulen-big": b"\x00" + record(2, b"\x09a"),
        "signed": b"\x02bob", "signed-nouser": b"\x02", "authfile": b"\x03# c\n\nalice:s3cr:et\r\nbob:\n",
        "pem": b"\x03-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n",
    }
    for k, v in ex.items():
        write("ext-records", k, v)
    # ---- tls-framing
    ch = client_hello()
    tl = {"clienthello": ch, "ch-trunc": ch[:40], "ku0": bytes([24, 0, 0, 1, 0]), "ku1": bytes([24, 0, 0, 1, 1]),
          "rec-empty": b"\x16\x03\x01\x00\x00\x01", "alert": b"\x15\x03\x03\x00\x02\x01\x00", "http": b"GET / HTTP/1.1\r\n"}
    for k, v in tl.items():
        write("tls-framing", k, v)
    # ---- worker-stream: [variant|level] [split seed] client bytes
    v1 = upgrade()
    flows = {
        "v1-connect-data": (0, v1 + frame(2, connect(1)) + frame(2, wisp(2, 1, b"hello")) + frame(2, wisp(4, 1, b"\x02"))),
        "v1-dns": (0, v1 + frame(2, connect(1, b"example.com", 80)) + frame(2, connect(3, b"nx.example", 80)) + frame(2, connect(5, b"host6", 443)) + frame(2, wisp(2, 1, b"GET /"))),
        "v1-udp": (0, v1 + frame(2, connect(7, b"127.0.0.1", 4444, 2)) + frame(2, wisp(2, 7, b"dgram"))),
        "v1-late": (0, v1 + frame(2, connect(1, b"late.test")) + frame(2, wisp(2, 1, b"GET /")) + frame(2, connect(3, b"late.x"))
                    + frame(2, wisp(4, 3, b"\x02")) + frame(2, connect(5, b"late.u", 4444, 2))),  # 70.10 early + late answers
        "v1-public": (0, v1 + frame(2, connect(1, b"1.1.1.1", 80)) + frame(2, connect(2, b"10.0.0.1", 80))),
        "v2-pw": (1, upgrade(proto="wisp-v2") + frame(2, INFO_PW) + frame(2, connect(1)) + frame(2, wisp(2, 1, b"x" * 300))),
        "v2-noauth": (0, upgrade(proto="wisp-v2") + frame(2, INFO_UDP) + frame(2, connect(1)) + frame(2, wisp(2, 1, b"data"))),
        "v2-badver": (0, upgrade(proto="wisp-v2") + frame(2, wisp(5, 0, b"\x09\x00"))),
        "v2-short-info": (0, upgrade(proto="wisp-v2") + frame(2, wisp(5, 0))),
        "v2-reject": (0, upgrade(proto="wisp-v2") + frame(2, wisp(4, 0, b"\x04"))),
        "v2-authreq-v1": (1, upgrade(proto="wisp-v2") + frame(2, connect(1))),
        "unmasked": (0, v1 + frame(2, wisp(2, 1, b"hi"), mask=False)),
        "interleaved-frag": (0, v1 + frame(2, b"\x02\x01\x00", fin=False) + frame(2, wisp(2, 1, b"x"))),
        "frag-data": (0, v1 + frame(2, connect(1)) + frame(2, wisp(2, 1, b"ab")[:4], fin=False) + frame(9, b"ping") + frame(0, wisp(2, 1, b"ab")[4:])),
        "frag-batch": (0, v1 + frame(2, connect(1)) + b"".join(frame(2, wisp(2, 1, bytes([65 + i]) * 100)[:50], fin=False) + frame(0, wisp(2, 1, bytes([65 + i]) * 100)[50:]) for i in range(4))),
        "data-close": (0, v1 + frame(2, connect(1)) + frame(2, wisp(2, 1, b"q" * 1000)) + frame(8, b"\x03\xe8")),
        "close-1": (0, v1 + frame(8, b"\x03")),
        "ping-flood": (0, v1 + frame(9, b"x" * 125) * 50),
        "h2-16m-header": (0, v1 + bytes([0x82, 0xFF]) + struct.pack(">Q", 16 << 20) + MASK + b"z" * 3000),
        "h2-frag-big": (0, v1 + frame(2, b"a" * 60000, fin=False) + frame(0, b"b" * 60000, fin=False)),
        "too-big": (0, v1 + bytes([0x82, 0xFF]) + struct.pack(">Q", (16 << 20) + 1) + MASK),
        "wsproxy": (0, upgrade("/p/127.0.0.1:4444") + frame(2, b"proxied bytes") + frame(1, b"text")),
        "wsproxy-pct": (0, upgrade("/%31%32%37.0.0.1:4444")),
        "wsproxy-bad": (0, upgrade("/p/host:0")),
        "wsproxy-auth": (1, upgrade("/p/127.0.0.1:4444")),
        "http10": (0, upgrade(ver="1.0")),
        "plain-get": (0, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        "huge-header": (0, b"GET / HTTP/1.1\r\n" + b"X: " + b"a" * 17000 + b"\r\n\r\n"),
        "pressure-l2": (6 << 2, v1 + frame(2, connect(1)) + frame(2, wisp(2, 1, b"p" * 20000))),
        "pressure-l3": (7 << 2, v1 + frame(2, connect(1)) + frame(2, wisp(2, 1, b"p" * 2000))),
        "noudp": (2, v1 + frame(2, connect(1, b"127.0.0.1", 4444, 2)) + frame(2, connect(2))),
        "tls-hello": (3, ch), "tls-garbage": (3, b"GET / HTTP/1.1\r\n\r\n"),
        "tls-split-hello": (3, ch[:5] + ch[5:]),
    }
    # 20.33 interleaved streams in one read batch
    flows["interleaved"] = (0, v1 + b"".join(frame(2, connect(s)) for s in (1, 2, 3))
                            + b"".join(frame(2, wisp(2, s, bytes([48 + s]) * (100 + r))) for r in range(12) for s in (1, 2, 3))
                            + frame(2, wisp(4, 2, b"\x02")) + frame(9, b"p")
                            + b"".join(frame(2, wisp(2, s, bytes([48 + s]) * 300)) for r in range(6) for s in (1, 3)))
    for k, (sel, v) in flows.items():
        write("worker-stream", k, bytes([sel, 0x5A]) + v)
    # ---- worker-wisp: [variant|level] [mode] ops   (mode: bits0-1 path/proto, bits2-3 auto INFO)
    def op_pkt(ty, sid, body):
        assert len(body) < 256
        return bytes([0, ty, sid, len(body)]) + body
    def op_raw(p):
        return bytes([2, len(p)]) + p
    c1 = op_pkt(1, 1, b"\x01\x5c\x11127.0.0.1")
    d1 = op_pkt(2, 1, b"hello world")
    cl1 = op_pkt(4, 1, b"\x02")
    flush = b"\x06"
    sweep = b"\x46"
    conn3 = b"".join(op_pkt(1, s, b"\x01\x5c\x11127.0.0.1") for s in (1, 2, 3))
    def inter(sids, rounds):  # 20.33 one DATA per stream in turn, `rounds` times
        sids = list(sids)
        return b"".join(op_pkt(2, s, bytes([48 + s]) * (40 + 13 * r)) for r in range(rounds) for s in sids)
    ww = {
        "v1-echo": (0, 0, c1 + flush + d1 + flush + d1 + cl1 + flush),
        "v1-udp": (0, 0, op_pkt(1, 3, b"\x02\x5c\x11127.0.0.1") + op_pkt(2, 3, b"dgram") + flush),
        "v1-long-data": (0, 0, c1 + flush + bytes([1, 2, 1, 0x40]) + flush),
        "v2-bare": (0, 1 | 1 << 2, c1 + d1 + flush),
        "v2-pw": (1, 1 | 2 << 2, c1 + d1 + flush + sweep),
        "v2-key": (1, 1 | 3 << 2, c1 + d1 + flush),
        "v2-noinfo": (1, 1, c1 + flush),
        "v2-raw-info": (0, 1, op_raw(INFO_PW) + flush),
        "frag": (0, 0, c1 + flush + bytes([3, 3, 4]) + wisp(2, 1)[:4] + b"\x05" + wisp(2, 1)[4:] + b"a" + b"\x03abc" + flush),
        "control": (0, 0, bytes([4, 0x89, 3]) + b"abc" + bytes([4, 0x88, 2]) + b"\x03\xe8" + flush),
        "rawbytes": (0, 0, bytes([5, 4]) + b"\x82\x85\x00\x00" + flush),
        "levels": (0, 0, c1 + flush + bytes([7 | 6 << 3]) + d1 + flush + sweep + bytes([7]) + d1 + flush),
        "late": (0, 0, op_pkt(1, 2, b"\x01\x5c\x11late.a") + op_pkt(2, 2, b"x") + flush
                 + op_pkt(1, 4, b"\x01\x5c\x11late.b") + op_pkt(4, 4, b"\x02") + flush + sweep + flush),  # 70.10
        "dns": (0, 0, op_pkt(1, 2, b"\x01\x50\x00example.com") + op_pkt(1, 4, b"\x01\x50\x00nx.ex") + op_pkt(1, 6, b"\x01\x50\x00a6") + flush + sweep),
        "wsproxy": (0, 2, op_raw(b"raw proxied") + flush),
        "wsproxy-pct": (0, 3, op_raw(b"raw") + flush),
        "noudp": (2, 0, op_pkt(1, 3, b"\x02\x5c\x11127.0.0.1") + c1 + flush),
        # 20.33 interleaved streams in one read batch (per-target staging): 3 streams round robin, a CLOSE for one and a
        # PING in the middle, a fragmented DATA for another, a level change, then more interleaved DATA
        "interleaved": (0, 0, conn3 + flush + inter(range(1, 4), 6) + cl1 + bytes([4, 0x89, 1]) + b"p" + inter(range(2, 4), 3)
                        + bytes([3, 2, 30]) + wisp(2, 2, b"f" * 25) + bytes([10]) + b"g" * 10 + inter(range(2, 4), 4) + flush
                        + bytes([7 | 1 << 3]) + inter(range(2, 4), 8) + flush + sweep),
        "interleaved-v2": (0, 1 | 1 << 2, conn3 + flush + inter(range(1, 4), 10) + flush + inter(range(1, 4), 5) + flush),
    }
    for k, (sel, mode, v) in ww.items():
        write("worker-wisp", k, bytes([sel, mode]) + v)

def tls_seeds():
    # ---- worker-tls: [sel: bit0 TLS1.2, bits1-2 cipher, bit3 no ALPN, bits4-5=11 corrupt] [off/4] [xor] ops
    def wf(p):
        return bytes([2, len(p)]) + p
    up1, up2, upx = b"\x01\x00", b"\x01\x01", b"\x01\x02"
    flush = b"\x06\x00"
    info = wisp(5, 0, b"\x02\x00")
    c1 = connect(1)
    flows = {
        "v1-echo": up1 + flush + wf(c1) + wf(wisp(2, 1, b"hello")) + flush + flush,
        "v2": up2 + flush + wf(info) + wf(c1) + wf(wisp(2, 1, b"x" * 100)) + flush,
        "wsproxy": upx + flush + wf(b"raw") + flush,
        "ku-req": up1 + flush + b"\x04\x01" + flush + wf(c1) + flush,
        "ku-noreq": b"\x04\x00" + up1 + flush,
        "close-notify": up1 + b"\x05\x00",
        "alert-fatal": up1 + b"\x03\x15\x02\x02\x28",
        "junk-handshake": b"\x03\x16\x05\x18\x00\x00\x01\x05",
        "renego-hello": b"\x03\x16\x04\x01\x00\x00\x00",
        "ccs": b"\x03\x14\x01\x01",
        "raw-data": b"\x00\x10GET / HTTP/1.1\r\n\r\n",
        "levels": up1 + flush + b"\x07\x06" + wf(c1) + b"\x06\x01" + b"\x07\x00" + flush,
    }
    for sel in (0x00, 0x01, 0x02, 0x04, 0x03, 0x05, 0x08):
        for k, v in flows.items():
            write("worker-tls", f"{sel:02x}-{k}", bytes([sel, 0, 0]) + v)
    for off in (0, 3, 10, 40, 80, 120):
        write("worker-tls", f"corrupt-{off}", bytes([0x30, off, 0x41]) + up1 + flush)
        write("worker-tls", f"corrupt12-{off}", bytes([0x31, off, 0x80]) + up1 + flush)

def cli_seeds():
    # ---- cli-parse: arguments separated by NUL
    for k, v in {"defaults": b"", "help": b"--help", "tls": b"--tls-cert\0a\0--tls-key\0b\0--tls-cipher-order\0server",
                 "values": b"7000\0--host\0::\0--threads\0" + b"2\0--connect-timeout\0" + b"86400\0--no-prio\0--mem-budget\0" + b"64M",
                 "bad-timeout": b"--connect-timeout\0" + b"18446744073709551615", "size": b"--mem-budget\0" + b"99999999999G"}.items():
        write("cli-parse", k, v)

def dns_seeds():
    # ---- dns-parse: [selector: bit0 = AAAA, bits1.. = read_name offset] DNS reply for www.example.com
    q = b"\x03www\x07example\x03com\x00"
    def rep(qt, rcode=0, tc=False, ans=(), qd=1, extra=b""):
        flags = 0x8180 | rcode | (0x200 if tc else 0)
        m = struct.pack(">HHHHHH", 0xBEEF, flags, qd, len(ans), 0, 0) + (q + struct.pack(">HH", qt, 1) if qd else b"")
        for owner, ty, data in ans:
            m += owner + struct.pack(">HHIH", ty, 1, 60, len(data)) + data
        return m + extra
    P = b"\xc0\x0c"
    v6 = bytes.fromhex("20010db8000000000000000000000001")
    cases = {
        "a": (0, rep(1, ans=[(P, 1, b"\x5d\xb8\xd8\x22"), (P, 1, b"\x01\x02\x03\x04")])),
        "aaaa": (1, rep(28, ans=[(P, 28, v6)])),
        "cname": (0, rep(1, ans=[(P, 5, b"\x01x\xc0\x10"), (b"\x01x\xc0\x10", 1, b"\x0a\x00\x00\x01")])),
        "cname-loop": (1, rep(28, ans=[(P, 5, P)])),
        "nx": (0, rep(1, rcode=3)), "servfail": (0, rep(1, rcode=2)), "formerr-bare": (0, rep(1, rcode=1, qd=0)),
        "tc": (1, rep(28, tc=True)), "nodata": (0, rep(1)),
        "fwd-ptr": (0x18, rep(1, ans=[(b"\xc0\xff", 1, b"\x01\x02\x03\x04")])),
        "resolv": (0, b"nameserver 127.0.0.53\nnameserver fe80::1%lo\nsearch a.example b\noptions ndots:2 timeout:1 attempts:3 rotate\n"),
        "hosts": (0, b"127.0.0.1 localhost\n::1 localhost ip6-localhost\n"),
        "server": (0, b"[::1]:5353\n1.2.3.4:53\nfe80::1%1\n"),
    }
    for k, (sel, m) in cases.items():
        write("dns-parse", k, bytes([sel]) + m)

if __name__ == "__main__":
    tls_seeds()
    cli_seeds()
    dns_seeds()
    main()
