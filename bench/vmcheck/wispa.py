"""60.78 (sb-robust) small asyncio Wisp v1 client for the VM checks (bench/vmcheck): stdlib only.
Wisp(host, port, src=None, tls=False): src = a client address sent in a PROXY v1 header (the server needs
--proxy-protocol tcp --proxy-protocol-from 127.0.0.0/8), so the rules of section E see a public client.
stream(port, host) -> sid; data(sid, bytes); await w.first(sid, timeout) -> ("d", bytes) | ("c", reason) | ("x", None)."""
import asyncio, base64, os, ssl, struct


def frame(payload, op=0x2):
    n = len(payload); m = os.urandom(4)
    if n < 126: hdr = bytes([0x80 | op, 0x80 | n])
    elif n < 65536: hdr = bytes([0x80 | op, 0xFE]) + struct.pack(">H", n)
    else: hdr = bytes([0x80 | op, 0xFF]) + struct.pack(">Q", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))


class Wisp:
    def __init__(self):
        self.q, self.next, self.closed = {}, 1, False

    async def open(self, host, port, src=None, tls=False, timeout=10):
        ctx = None
        if tls:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        self.r, self.w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout)
        pre = f"PROXY TCP4 {src} 192.0.2.1 40000 443\r\n".encode() if src else b""
        self.w.write(pre + b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
                     + base64.b64encode(os.urandom(16)) + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
        head = await asyncio.wait_for(self.r.readuntil(b"\r\n\r\n"), timeout)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise ConnectionError(head[:60])
        self.task = asyncio.get_running_loop().create_task(self._read())
        return self

    async def _read(self):
        try:
            while True:
                h = await self.r.readexactly(2); n = h[1] & 0x7F
                if n == 126: n = struct.unpack(">H", await self.r.readexactly(2))[0]
                elif n == 127: n = struct.unpack(">Q", await self.r.readexactly(8))[0]
                p = await self.r.readexactly(n)
                if h[0] & 0x0F != 0x2 or len(p) < 5: continue
                ty, sid = p[0], struct.unpack("<I", p[1:5])[0]
                if sid == 0 or sid not in self.q: continue
                if ty == 2: self.q[sid].put_nowait(("d", p[5:]))
                elif ty == 4: self.q[sid].put_nowait(("c", p[5] if len(p) > 5 else -1))
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        self.closed = True
        for q in self.q.values(): q.put_nowait(("x", None))

    def stream(self, port, host="127.0.0.1"):
        sid = self.next; self.next += 1; self.q[sid] = asyncio.Queue()
        self.w.write(frame(bytes([1]) + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", port) + host.encode()))
        return sid

    def data(self, sid, b):
        self.w.write(frame(bytes([2]) + struct.pack("<I", sid) + b))

    def close_stream(self, sid):
        self.w.write(frame(bytes([4]) + struct.pack("<I", sid) + b"\x02"))

    async def first(self, sid, timeout):
        try: return await asyncio.wait_for(self.q[sid].get(), timeout)
        except asyncio.TimeoutError: return ("t", None)

    def close(self):
        try: self.w.close()
        except Exception: pass
