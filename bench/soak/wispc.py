# 30.11 soak: minimal Wisp v1 client over WebSocket (stdlib only; optional TLS).
import base64, os, socket, ssl, struct, time

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE

CONNECT, DATA, CONTINUE, CLOSE = 1, 2, 3, 4
PLAIN_ONLY = os.environ.get("SOAK_PLAIN") == "1"


def mask_frame(op, payload, fin=True):
    n = len(payload)
    b0 = (0x80 if fin else 0) | op
    if n < 126:
        hdr = bytes([b0, 0x80 | n])
    elif n < 65536:
        hdr = bytes([b0, 0x80 | 126]) + struct.pack(">H", n)
    else:
        hdr = bytes([b0, 0x80 | 127]) + struct.pack(">Q", n)
    m = os.urandom(4)
    if not n:
        return hdr + m
    w = (n + 3) // 4
    k = int.from_bytes(m * w, "little")
    body = (int.from_bytes(payload, "little") ^ k).to_bytes(4 * w, "little")[:n]
    return hdr + m + body


class Closed(Exception):
    pass


class Wisp:
    """One Wisp v1 connection. recv_pkt returns (type, sid, payload) or None on timeout."""

    def __init__(self, port, tls=False, host="127.0.0.1", timeout=10.0, bind_port=None, handshake=True, rcvbuf=None,
                 src=None):
        if PLAIN_ONLY:
            tls = False  # 30.16: SOAK_PLAIN=1 (box without kTLS): server B is plain too, every helper speaks ws
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if rcvbuf:
            # 30.11: before connect, like a real client. Set after connect on loopback (wscale and the 32 KiB MSS already
            # negotiated) the window ends up below one MSS: the sender then moves data only on persist probes (backoff
            # up to 120 s after a long zero window). Measured 2026-10-25, same on every server: a harness artifact.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        if bind_port:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", bind_port))
        elif src:
            # 30.16 heavy soak: another loopback source address = another ~28k ephemeral ports to the same server port
            s.bind((src, 0))
        s.connect((host, port))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # wrap_socket detaches s: socket options and close() go to the SSLSocket (same fd)
        self.s = _ctx.wrap_socket(s, server_hostname="localhost") if tls else s
        self.raw = self.s
        self.rbuf = bytearray()
        self.closed = False
        self.credit = None
        if handshake:
            self.upgrade()

    def upgrade(self):
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = self.s.recv(4096)
            if not d:
                raise Closed("no upgrade response")
            buf += d
        head, _, rest = buf.partition(b"\r\n\r\n")
        if not head.startswith(b"HTTP/1.1 101"):
            raise Closed("upgrade refused: " + head.split(b"\r\n")[0].decode("latin-1"))
        self.rbuf += rest
        p = self.recv_pkt(10)
        if not p or p[0] != CONTINUE or p[1] != 0:
            raise Closed(f"expected CONTINUE 0, got {p!r:.80}")
        self.credit = struct.unpack("<I", p[2][:4])[0]

    def send_pkt(self, ty, sid, body=b""):
        # 30.11: recv_pkt leaves the socket timeout at its leftover (can be ~0); a send under CPU contention then
        # raised TimeoutError (probe h6.3 in soak12, one deadtarget cycle in soak24). Sends get a fixed 10 s.
        self.s.settimeout(10)
        self.s.sendall(mask_frame(2, struct.pack("<BI", ty, sid) + body))

    def connect(self, sid, port, host=b"127.0.0.1", stype=1):
        if isinstance(host, str):
            host = host.encode()
        self.send_pkt(CONNECT, sid, struct.pack("<BH", stype, port) + host)

    def close_stream(self, sid, reason=0x02):
        self.send_pkt(CLOSE, sid, bytes([reason]))

    def ping(self, payload=b"p"):
        self.s.sendall(mask_frame(0x9, payload))

    def _parse(self):
        b = self.rbuf
        if len(b) < 2:
            return None
        ln = b[1] & 0x7F
        hl = 2
        if ln == 126:
            if len(b) < 4:
                return None
            ln = struct.unpack_from(">H", b, 2)[0]
            hl = 4
        elif ln == 127:
            if len(b) < 10:
                return None
            ln = struct.unpack_from(">Q", b, 2)[0]
            hl = 10
        if len(b) < hl + ln:
            return None
        op = b[0] & 0x0F
        p = bytes(b[hl:hl + ln])
        del b[:hl + ln]
        if op == 8:
            self.closed = True
            return ("wsclose", 0, p)
        if op == 9:
            self.s.sendall(mask_frame(0xA, p))
            return ("op", 0, b"")
        if op != 2:
            return ("op", 0, b"")
        return (p[0], struct.unpack_from("<I", p, 1)[0], p[5:])

    def recv_pkt(self, t=10.0):
        end = time.monotonic() + t
        while True:
            r = self._parse()
            if r is not None:
                if r[0] == "op":
                    continue
                return r
            left = end - time.monotonic()
            if left <= 0:
                return None
            if self.closed:
                raise Closed("connection closed")
            self.s.settimeout(left)
            try:
                d = self.s.recv(1 << 20)
            except (socket.timeout, TimeoutError):
                return None
            except (ConnectionResetError, ssl.SSLError, OSError) as e:
                self.closed = True
                raise Closed(f"recv: {e}")
            if not d:
                self.closed = True
                raise Closed("EOF")
            self.rbuf += d

    def close(self, rst=False):
        try:
            if rst:
                self.raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            self.raw.close()
        except OSError:
            pass


def pattern_chunk(seed, i, base):
    """Chunk i (64 KiB) of the pattern stream: [seed u64][index u64] + base[16:]."""
    return struct.pack("<QQ", seed, i) + base[16:]


def pattern_base(seed):
    import random
    return random.Random(seed).randbytes(65536)
