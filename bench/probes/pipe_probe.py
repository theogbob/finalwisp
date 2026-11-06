#!/usr/bin/env python3
"""30.09 splice-pipe probe: N clients each download `size` bytes once (bulk -> splice pipe), then stay idle.
Reports server fds, whether this user can still get a 256 KiB pipe, and MiB/s of one fresh client's download.
Usage: pipe_probe.py WS_PORT SOURCE_PORT SERVER_PID N [size] [settle]"""
import asyncio, fcntl, json, os, struct, sys, time
port, sport, spid, n = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
size = int(sys.argv[5]) if len(sys.argv) > 5 else 4 << 20
settle = float(sys.argv[6]) if len(sys.argv) > 6 else 5
F_SETPIPE_SZ = 1031
def frame(p):
    n = len(p); h = bytes([0x82])
    h += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n)
    return h + b"\0\0\0\0" + p
async def client(hold, want, t_out):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    await r.readuntil(b"\r\n\r\n")
    w.write(frame(b"\x01" + struct.pack("<I", 1) + b"\x01" + struct.pack("<H", sport) + b"127.0.0.1")); await w.drain()
    got, t0, cont = 0, time.perf_counter(), 0
    while got < want:
        b0 = await r.readexactly(2); ln = b0[1] & 0x7f
        if ln == 126: ln = struct.unpack(">H", await r.readexactly(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", await r.readexactly(8))[0]
        p = await r.readexactly(ln)
        if p and p[0] == 2: got += len(p) - 5
    t_out.append(time.perf_counter() - t0)
    w.write(frame(b"\x04" + struct.pack("<I", 1) + b"\x02")); await w.drain()  # close the stream, keep the WS
    DONE[0] += 1
    async def drain():  # a real client keeps reading: the server can flush what was in flight
        try:
            while True:
                if not await r.read(65536): return
        except Exception: return
    dt = asyncio.create_task(drain())
    await hold.wait(); dt.cancel(); w.close()
DONE = [0]
def fds(): return len(os.listdir(f"/proc/{spid}/fd"))
def can_big_pipe():
    a, b = os.pipe()
    try:
        fcntl.fcntl(b, F_SETPIPE_SZ, 256 * 1024); return True
    except OSError: return False
    finally: os.close(a); os.close(b)
async def main():
    hold = asyncio.Event(); ts = []
    f0 = fds()
    tasks = []
    for i in range(n):  # 16 at a time
        tasks.append(asyncio.create_task(client(hold, size, ts)))
        if len(tasks) % 16 == 0:
            while DONE[0] < len(tasks) - 0: await asyncio.sleep(0.01)
    while DONE[0] < n: await asyncio.sleep(0.05)
    await asyncio.sleep(settle)
    res = {"n": n, "fds_before": f0, "fds_idle": fds(), "user_can_get_256k_pipe": can_big_pipe()}
    ts2 = []; h2 = asyncio.Event(); h2.set()
    await client(h2, 64 << 20, ts2)
    res["fresh_client_64MiB_MiB_s"] = round(64 / ts2[0], 1)
    res["first_clients_MiB_s_median"] = round(sorted(size / 2**20 / t for t in ts)[len(ts) // 2], 1)
    hold.set(); await asyncio.gather(*tasks, return_exceptions=True)
    print(json.dumps(res))
asyncio.run(main())
