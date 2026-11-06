"""Idle memory per connection (30.10; was idle_rss.py, 30.06 / 20.11).

wst idle SERVER... [--n 2000] [--reps 6] [--port 8390] [--echo-port 8391] [--size 65536] [--settle 30]
  SERVER: registry name, fw:PATH [args], or NAME='command --port {port}'. Each rep starts every server fresh
  (rotated order), opens N Wisp connections that echo `size` bytes once and then sit idle, and reads the server's
  RSS before, right after, and then once a second until it is stable (4 samples, 3 s, within 2% of the idle memory or
  0.1 KiB/conn) or `settle` s (default 30) have passed. Result: KiB per idle connection (settled), median over
  reps; each record has settle_s (start of the stable window; None = not stable by `settle`), kib_per_conn_3s
  (the old fixed reading) and the RSS samples. A slow box frees later (2 vCPU: 20-129 KiB/conn at 3 s, 4.7 at 33 s).
  With two servers: ratio second/first and the exact paired Wilcoxon p.
probe only (the old idle_rss.py CLI): python3 -m wispsuite.idle WS_PORT ECHO_PORT SERVER_PID N [size] [settle] [--group]
"""
import argparse, asyncio, json, math, os, resource, struct, sys, time

DONE = [0]


def rss(pid, group=False):
    if group:
        from .sample import group_usage
        value = group_usage(pid)[1]
        if value <= 0:
            raise ProcessLookupError(f"server session {pid} has no readable live RSS")
        return value
    for l in open(f"/proc/{pid}/status"):
        if l.startswith("VmRSS"): return int(l.split()[1]) / 1024


def frame(p):
    n = len(p); h = bytes([0x82])
    h += bytes([0x80 | n]) if n < 126 else (bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else bytes([0x80 | 127]) + struct.pack(">Q", n))
    return h + b"\0\0\0\0" + p  # zero mask key: payload unchanged


async def one(port, eport, size, hold):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    await r.readuntil(b"\r\n\r\n")
    w.write(frame(b"\x01" + struct.pack("<I", 1) + b"\x01" + struct.pack("<H", eport) + b"127.0.0.1"))
    chunk = 16384; sent = 0
    while sent < size:
        k = min(chunk, size - sent); w.write(frame(b"\x02" + struct.pack("<I", 1) + bytes(k))); sent += k
    w.write(b"\x89\x80\0\0\0\0")  # WS ping: epoxy only flushes its output when something else wakes it
    await w.drain()
    got = 0
    while got < size:  # count DATA payload bytes for stream 1
        b0 = await r.readexactly(2); ln = b0[1] & 0x7f
        if ln == 126: ln = struct.unpack(">H", await r.readexactly(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", await r.readexactly(8))[0]
        p = await r.readexactly(ln)
        if (b0[0] & 0x0f) == 0x2 and p and p[0] == 2: got += len(p) - 5  # skip pong / non-DATA
    DONE[0] += 1
    await hold.wait()
    w.close()


async def probe_async(port, eport, spid, n, size, settle, group=False):
    DONE[0] = 0
    before = rss(spid, group); hold = asyncio.Event(); t0 = time.time()
    tasks = [asyncio.create_task(one(port, eport, size, hold)) for i in range(n)]
    # wait until every client finished its echo (they then block on hold)
    for _ in range(600):
        await asyncio.sleep(0.05)
        if DONE[0] >= n or any(t.done() and t.exception() for t in tasks): break
    await asyncio.sleep(0.3)
    after = rss(spid, group); t_idle = time.monotonic()
    samples = []  # (seconds since idle, RSS MiB): on whole seconds (a late wakeup skips ticks), up to `settle` s
    while True:
        el = time.monotonic() - t_idle
        await asyncio.sleep(min(math.floor(el) + 1, max(settle, el)) - el)
        samples.append((time.monotonic() - t_idle, rss(spid, group)))
        if stable(samples, before, n) or samples[-1][0] >= settle - 0.01:
            break
    settled = samples[-1][1]
    hold.set(); await asyncio.gather(*tasks, return_exceptions=True)
    ok = stable(samples, before, n)
    s3 = next((m for s, m in samples if s >= 2.99), None)  # the old fixed 3 s reading (None: settle < 3)
    return {"n": n, "size": size, "rss_before_mib": round(before, 1), "rss_idle_mib": round(after, 1),
            "rss_settled_mib": round(settled, 1), "kib_per_conn_settled": round((settled - before) * 1024 / n, 1),
            "kib_per_conn_3s": round((s3 - before) * 1024 / n, 1) if s3 is not None else None,
            "settle_s": round(samples[-STABLE_N][0], 1) if ok else None, "settled_ok": ok,
            "rss_samples_mib": [round(m, 1) for _, m in samples],
            "echoed": DONE[0], "secs": round(time.time() - t0, 1)}


STABLE_N = 4  # samples 1 s apart: the window spans 3 s, longer than finalwisp's 2 s idle sweep, so a plateau between two sweeps never reads as stable


def stable(samples, before, n):
    """True when the last STABLE_N RSS samples differ by < 2% of the idle memory (RSS above the pre-test level),
    or by < 0.1 KiB per connection (RSS is read in KiB; small idle footprints would never meet 2%)."""
    if len(samples) < STABLE_N or samples[-1][0] - samples[-STABLE_N][0] < STABLE_N - 1.5:
        return False  # the window must really span ~3 s (no back-to-back samples after a stall)
    last = [m for _, m in samples[-STABLE_N:]]
    tol = max(0.02 * (last[-1] - before), 0.1 * n / 1024)
    return max(last) - min(last) < tol


def probe_main(argv):
    group = "--group" in argv
    argv = [a for a in argv if a != "--group"]
    port, eport, spid, n = int(argv[0]), int(argv[1]), int(argv[2]), int(argv[3])
    size = int(argv[4]) if len(argv) > 4 else 65536
    settle = float(argv[5]) if len(argv) > 5 else 30.0
    print(json.dumps(asyncio.run(probe_async(port, eport, spid, n, size, settle, group=group))))


def probe_cmd(port, eport, pid, n, size=65536, settle=30.0, *, group=False):
    """Probe in its own process. group=True samples the suite-owned server session (30.13),
    not one listener PID. Standalone probes retain their single-PID default."""
    return [sys.executable, "-m", "wispsuite.idle", str(port), str(eport), str(pid), str(n), str(size), str(settle)] + (["--group"] if group else [])


def main(argv):
    from . import proc, report, servers, wbench
    from .stats import compare, median
    ap = argparse.ArgumentParser(prog="wst idle", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("servers", nargs="+"); ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--reps", type=int, default=6); ap.add_argument("--port", type=int, default=8390)
    ap.add_argument("--echo-port", type=int, default=8391); ap.add_argument("--size", type=int, default=65536)
    ap.add_argument("--settle", type=float, default=30.0, help="max seconds to wait for a stable RSS"); ap.add_argument("--wbench")
    ap.add_argument("--out", default=os.path.join(report.BENCH, "results", f"idle-{report.stamp()}.json"))
    a = ap.parse_args(argv)
    srvs = [servers.resolve(s) for s in a.servers]
    bad = proc.strays([a.port, a.echo_port])
    if bad:
        sys.exit("idle: " + "; ".join(bad))
    proc.install_handlers()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    scratch = servers.SCRATCH
    tg = wbench.start_target(wbench.find(a.wbench), a.echo_port, "echo")
    res = {s.name: [] for s in srvs}
    raw = []
    try:
        for rep in range(a.reps):
            k = rep % len(srvs)
            for s in srvs[k:] + srvs[:k]:
                try:
                    p = s.start(a.port, scratch)
                except RuntimeError as e:
                    print(f"idle: {e}", file=sys.stderr); res[s.name].append(None); continue
                time.sleep(0.5)
                rc, out, err = proc.run(probe_cmd(a.port, a.echo_port, p.pid, a.n, a.size, a.settle, group=True), timeout=90 + a.settle,
                                        cwd=report.BENCH, env={"PYTHONPATH": report.BENCH})
                proc.stop(p)
                proc.wait_free(a.port)
                j = wbench.parse_last_json(out) or {"error": (err or "")[-300:]}
                j.update(server=s.name, rep=rep)
                raw.append(j)
                res[s.name].append(j.get("kib_per_conn_settled"))
                print(f"  {s.name} rep {rep}: {json.dumps(j)}", file=sys.stderr, flush=True)
    finally:
        proc.stop(tg, 0)
    rows = [(n, median(v), v) for n, v in res.items()]
    print(report.md_table(["server", f"KiB per idle conn ({a.n} conns, median)", "all"], rows))
    cmp_ = None
    if len(srvs) == 2:
        cmp_ = compare(res[srvs[0].name], res[srvs[1].name], higher_better=False)
        print(f"\n{srvs[1].name} / {srvs[0].name}: {cmp_}")
    report.write(a.out, "idle", binaries=[], results=raw, summary={"medians": {n: m for n, m, _ in rows}, "compare": cmp_})
    print(f"saved {a.out}", file=sys.stderr)


if __name__ == "__main__":
    probe_main(sys.argv[1:])
