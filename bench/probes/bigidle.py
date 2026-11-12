#!/usr/bin/env python3
"""Big idle probe (60.12 scale tests; extends wst idle, 30.06/30.10, to 100k+ connections on one box).

usage: bigidle.py --server 'CMD (gets --port P)' --n 100000 [--per-proc 10000] [--size 65536] [--settle 60] [--fixed]
                 [--port 8390] [--echo-port 8400] [--probe-rr] [--probe-max N] [--ct-wait-below 40000]
Starts the server (nofile raised to the hard limit, inherited), K = ceil(n / per-proc) wbench echo targets on
echo-port..echo-port+K-1 (bound 127.0.0.1; one target port per <= per-proc server-side upstream connections, so the
server's loopback source ports never run out) and K client processes; client k uses source 127.0.0.(2+k) with
IP_BIND_ADDRESS_NO_PORT (port chosen at connect, shared with other destinations), opens per-proc Wisp connections that echo `size` bytes once on stream 1 to its target and
then sit idle. Reads, before / right after / then each second until stable (4 samples within 2% or 0.1 KiB/conn,
as wst idle) or `settle` s: the server's VmRSS + RssAnon, and the container cgroup memory.current + memory.stat
(anon, sock, kernel, slab). Also counts the server's fds. One JSON line on stdout.
Server-attributable cgroup estimate = cgroup delta - client RSS delta - target RSS delta (still includes the kernel
socket memory of all 4 socket ends per connection; the same connections for every variant, so the paired difference
between variants is the server's).
Waits first for the conntrack table to drain (2 flows per idle connection, max 262144 in the test containers).
--probe-rr / --probe-max (imply --fixed): a wbench rr 1x1, or N python connections doing sequential 64 B echoes that record
the MAX latency, through the server during the idle window (70.23: a malloc_trim stall shows as one huge sample).
Exit status 1 if the run failed (the JSON line still has "error").
The JSON's "capabilities" is the server's detail line: finalwisp 1.3.0 and later print it only with --log-level debug
(put it into --server; without --log-conns it adds no line per connection).
"""
import argparse, asyncio, json, math, os, resource, signal, socket, struct, subprocess, sys, time

IP_BIND_ADDRESS_NO_PORT = 24  # linux/in.h

CG = "/sys/fs/cgroup" + open("/proc/self/cgroup").read().strip().split("::", 1)[-1].rstrip("/")  # "0::/" in a container


def status(pid):
    d = {}
    for l in open(f"/proc/{pid}/status"):
        k, _, v = l.partition(":")
        if k in ("VmRSS", "RssAnon", "VmHWM", "Threads"):
            d[k] = int(v.split()[0])
    return d  # KiB (Threads: count)


def cgroup():
    d = {"current": int(open(f"{CG}/memory.current").read())}
    for l in open(f"{CG}/memory.stat"):
        k, v = l.split()
        if k in ("anon", "sock", "kernel", "slab", "file", "percpu", "kernel_stack", "pagetables"):
            d[k] = int(v)
    return d  # bytes


def maps_summary(pid):
    """Where the idle server's resident memory sits (smaps): mapping count, Rss (KiB) of [heap], of anonymous
    mappings by size (< 1 MiB = glibc mmapped chunks / thread caches, >= 1 MiB = arenas, stacks, allocator regions)."""
    d = {"maps": 0, "heap_rss": 0, "anon_small_n": 0, "anon_small_rss": 0, "anon_big_n": 0, "anon_big_rss": 0, "other_rss": 0,
         "big": []}  # big: [size KiB, Rss KiB, perms] per anonymous mapping >= 1 MiB (glibc arenas = 64 MiB reservations)
    cur = None
    try:
        for l in open(f"/proc/{pid}/smaps"):
            f = l.split()
            if "-" in f[0] and ":" not in f[0]:
                a, b = (int(x, 16) for x in f[0].split("-"))
                name = f[5] if len(f) > 5 else ""
                d["maps"] += 1
                cur = "heap" if name == "[heap]" else ("other" if name else ("anon_small" if (b - a) < (1 << 20) else "anon_big"))
                if cur.startswith("anon"):
                    d[cur + "_n"] += 1
                if cur == "anon_big":
                    d["big"].append([(b - a) >> 10, 0, f[1]])
            elif f[0] == "Rss:" and cur:
                d[cur + "_rss"] += int(f[1])
                if cur == "anon_big":
                    d["big"][-1][1] = int(f[1])
    except OSError:
        pass
    return d


def nfds(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def frame(p):
    n = len(p); h = bytes([0x82])
    h += bytes([0x80 | n]) if n < 126 else (bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else bytes([0x80 | 127]) + struct.pack(">Q", n))
    return h + b"\0\0\0\0" + p


async def one(port, eport, size, src, sem, done, fail):
    try:
        async with sem:
            return await asyncio.wait_for(one_inner(port, eport, size, src, done), 60)
    except Exception as e:
        fail[0] += 1
        fail.append(repr(e)[:120]) if len(fail) < 6 else None
        return None


async def one_inner(port, eport, size, src, done):
    if True:
        if True:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # source address only: the port is picked at connect() and shared with connections to other destinations.
            # A plain bind(src, 0) reserves the port for every address and blocked the server's own upstream connect()s
            # (20k bound client ports left the server ~14k source ports: 60.12 scale, e5)
            s.setsockopt(socket.IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1)
            s.bind((src, 0)); s.setblocking(False)
            try:
                await asyncio.get_running_loop().sock_connect(s, ("127.0.0.1", port))
            except BaseException:
                s.close(); raise
            r, w = await asyncio.open_connection(sock=s)
            w.write(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            await r.readuntil(b"\r\n\r\n")
            w.write(frame(b"\x01" + struct.pack("<I", 1) + b"\x01" + struct.pack("<H", eport) + b"127.0.0.1"))
            sent = 0
            while sent < size:
                k = min(16384, size - sent); w.write(frame(b"\x02" + struct.pack("<I", 1) + bytes(k))); sent += k
            await w.drain()
            got = 0
            while got < size:
                b0 = await r.readexactly(2); ln = b0[1] & 0x7f
                if ln == 126: ln = struct.unpack(">H", await r.readexactly(2))[0]
                elif ln == 127: ln = struct.unpack(">Q", await r.readexactly(8))[0]
                p = await r.readexactly(ln)
                if (b0[0] & 0x0f) == 0x2 and p and p[0] == 2: got += len(p) - 5
        done[0] += 1
        return w


async def client_async(port, eport, n, size, src, conc):
    sem = asyncio.Semaphore(conc); done = [0]; fail = [0]
    async def progress():
        t0 = time.time()
        while True:
            await asyncio.sleep(5)
            print(f"client {src}: {done[0]} done {fail[0]} failed after {time.time() - t0:.0f}s", file=sys.stderr, flush=True)
    pt = asyncio.create_task(progress())
    ws = await asyncio.gather(*[one(port, eport, size, src, sem, done, fail) for _ in range(n)])
    pt.cancel()
    print(json.dumps({"done": done[0], "fail": fail[0], "errs": fail[1:]}), flush=True)
    sys.stdin.readline()  # hold until the parent closes stdin
    for w in ws:
        if w: w.close()


def client_main(argv):
    port, eport, n, size, src, conc = int(argv[0]), int(argv[1]), int(argv[2]), int(argv[3]), argv[4], int(argv[5])
    asyncio.run(client_async(port, eport, n, size, src, conc))


async def lat_async(port, eport, conns, dur):
    """--probe-max: `conns` Wisp connections, each a sequential 64 B echo loop on one stream; returns the max and the top
    latencies (a worker stall shows as one huge sample on the connections of that worker; wbench reports only p999)."""
    lats, errs = [], []
    async def one_conn():
        try:
            await one_conn_inner()
        except Exception as e:  # keep the other connections' samples (the max is the signal)
            errs.append(repr(e)[:120])
    async def one_conn_inner():
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        await r.readuntil(b"\r\n\r\n")
        w.write(frame(b"\x01" + struct.pack("<I", 1) + b"\x01" + struct.pack("<H", eport) + b"127.0.0.1"))
        end = time.monotonic() + dur; mine = []
        while time.monotonic() < end:
            t0 = time.monotonic()
            w.write(frame(b"\x02" + struct.pack("<I", 1) + bytes(64))); await w.drain()
            got = 0
            while got < 64:
                b0 = await r.readexactly(2); ln = b0[1] & 0x7f
                if ln == 126: ln = struct.unpack(">H", await r.readexactly(2))[0]
                elif ln == 127: ln = struct.unpack(">Q", await r.readexactly(8))[0]
                pl = await r.readexactly(ln)
                if (b0[0] & 0x0f) == 0x2 and pl and pl[0] == 2: got += len(pl) - 5
            mine.append(time.monotonic() - t0)
        lats.extend(mine); w.close()
    await asyncio.gather(*[one_conn() for _ in range(conns)])
    lats.sort()
    n = len(lats)
    if not n:
        return {"n": 0, "errors": len(errs), "errs": errs[:3]}
    return {"n": n, "errors": len(errs), "errs": errs[:3], "max_ms": round(lats[-1] * 1000, 2), "top5_ms": [round(x * 1000, 2) for x in lats[-5:]],
            "p99_ms": round(lats[int(0.99 * n)] * 1000, 3), "p9999_ms": round(lats[min(n - 1, int(0.9999 * n))] * 1000, 2),
            "over_50ms": sum(1 for x in lats if x > 0.05)}


def lat_main(argv):
    print(json.dumps(asyncio.run(lat_async(int(argv[0]), int(argv[1]), int(argv[2]), float(argv[3])))), flush=True)


def stable(samples, before, n):
    if len(samples) < 4 or samples[-1][0] - samples[-4][0] < 2.5:
        return False
    last = [m for _, m in samples[-4:]]
    return max(last) - min(last) < max(0.02 * (last[-1] - before), 0.1 * n)  # KiB


def wait_port(port, t):
    import socket
    end = time.time() + t
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close(); return True
        except OSError:
            time.sleep(0.1)
    return False


def rss_of(pids):
    tot = 0
    for p in pids:
        try: tot += status(p)["VmRSS"]
        except (OSError, KeyError): pass
    return tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True); ap.add_argument("--n", type=int, default=100000)
    ap.add_argument("--per-proc", type=int, default=10000); ap.add_argument("--size", type=int, default=65536)
    ap.add_argument("--settle", type=float, default=60); ap.add_argument("--port", type=int, default=8390)
    ap.add_argument("--echo-port", type=int, default=8400); ap.add_argument("--conc", type=int, default=1000)
    ap.add_argument("--wbench", default="/root/fw/wbench"); ap.add_argument("--label", default="")
    ap.add_argument("--ct-wait-below", type=int, default=40000)
    ap.add_argument("--probe-max", type=int, default=0, help="N python rr connections during the idle window: max latency")
    ap.add_argument("--probe-rr", action="store_true", help="run a 1x1 wbench rr through the server during the idle window")
    ap.add_argument("--fixed", action="store_true", help="always sample for --settle s (no early stop): at 100k conns glibc's\n"
                    "RSS still fell slowly after the 2%%/3 s window had called it stable")
    a = ap.parse_args()
    if a.probe_rr or a.probe_max:
        a.fixed = True  # the probes run for settle - 8 s: an early stop would cut them off and sample while they run
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))  # run the finally below (children are in their own sessions)
    # conntrack is on in these containers (max 262144 flows, 2 per idle connection): wait for the previous run's
    # TIME_WAIT/CLOSE entries to expire so 100k connections fit
    ct = "/proc/sys/net/netfilter/nf_conntrack_count"
    t_ct = time.time()
    while os.path.exists(ct) and int(open(ct).read()) > a.ct_wait_below and time.time() - t_ct < 400:
        time.sleep(5)
    ct0 = int(open(ct).read()) if os.path.exists(ct) else None
    K = math.ceil(a.n / a.per_proc)
    # after the conntrack wait: another run may have started meanwhile; server and wbench targets use SO_REUSEPORT,
    # so a leftover would silently share the port
    busy = [pt for pt in [a.port] + [a.echo_port + k for k in range(K)] if wait_port(pt, 0.3)]
    if busy:
        print(json.dumps({"label": a.label, "error": f"port(s) {busy} busy before start"})); sys.exit(1)
    per = [a.n // K + (1 if i < a.n % K else 0) for i in range(K)]
    procs = []
    out = {"label": a.label, "n": a.n, "K": K, "size": a.size, "nofile": hard, "conntrack_before": ct0, "ct_wait_s": round(time.time() - t_ct)}
    try:
        tg = []
        for k in range(K):  # registered one by one: a failed spawn must not leak the ones already started
            tg.append(subprocess.Popen([a.wbench, "target", "--port", str(a.echo_port + k), "--mode", "echo"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True))
            procs.append(tg[-1])
        srv = subprocess.Popen(f"exec {a.server} --port {a.port}", shell=True, stdout=subprocess.DEVNULL,
                               stderr=open(f"/tmp/bigidle-srv-{a.port}.log", "w"), start_new_session=True)
        procs.append(srv)
        if not wait_port(a.port, 15) or not all(wait_port(a.echo_port + k, 5) for k in range(K)):
            raise RuntimeError("server or target did not listen")
        time.sleep(1.0)
        s0, c0, t0rss = status(srv.pid), cgroup(), rss_of([p.pid for p in tg])
        out.update(srv_before=s0, cg_before=c0, srv_fds_before=nfds(srv.pid))
        t0 = time.time()
        cl = []
        for k in range(K):
            cl.append(subprocess.Popen([sys.executable, os.path.abspath(__file__), "--client", str(a.port), str(a.echo_port + k),
                                        str(per[k]), str(a.size), f"127.0.0.{2 + k}", str(max(1, a.conc // K))], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, text=True, start_new_session=True))
            procs.append(cl[-1])
        # the clients did not exist at c0, so cg_minus_clients below subtracts their full RSS (not a delta)
        res = [json.loads(c.stdout.readline() or '{"done": 0, "fail": -1}') for c in cl]  # each client: <= n/conc * 60 s
        out["setup_s"] = round(time.time() - t0, 1)
        out["echoed"] = sum(r["done"] for r in res); out["failed"] = sum(r["fail"] for r in res)
        out["errs"] = [e for r in res for e in r.get("errs", [])][:6]
        time.sleep(0.3)
        out["srv_idle0"] = status(srv.pid)
        out["maps_peak"] = maps_summary(srv.pid)  # all connections echoed, before the idle sweep
        rr = None
        if a.probe_rr:  # 70.23 trim stall check: request/response latency through the server while the idle sweeps run
            rr = subprocess.Popen([a.wbench, "run", "--url", f"ws://127.0.0.1:{a.port}/", "--target", f"127.0.0.1:{a.echo_port}",
                                   "--test", "rr", "--conns", "1", "--streams", "1", "--duration", str(max(5, a.settle - 8)),
                                   "--warmup", "0", "--threads", "1", "--json"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, start_new_session=True)
            procs.append(rr)
        lp = None
        if a.probe_max:
            lp = subprocess.Popen([sys.executable, os.path.abspath(__file__), "--lat", str(a.port), str(a.echo_port), str(a.probe_max),
                                   str(max(5, a.settle - 8))], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True)
            procs.append(lp)
        t_idle = time.monotonic(); samples = []
        while True:
            el = time.monotonic() - t_idle
            time.sleep(max(0, min(math.floor(el) + 1, a.settle) - el))
            samples.append((round(time.monotonic() - t_idle, 1), status(srv.pid)["VmRSS"]))
            if (not a.fixed and stable(samples, s0["VmRSS"], a.n)) or samples[-1][0] >= a.settle - 0.01:
                break
        s1, c1 = status(srv.pid), cgroup()
        if lp is not None:
            try:
                o, _ = lp.communicate(timeout=60)
                out["probe_max"] = json.loads(o.strip().splitlines()[-1])
            except Exception as e:
                out["probe_max"] = {"error": repr(e)}
        if rr is not None:
            try:
                o, _ = rr.communicate(timeout=30)
                out["probe_rr"] = json.loads([l for l in o.splitlines() if l.startswith("{")][-1])
            except Exception as e:
                out["probe_rr"] = {"error": repr(e)}
        s_30 = next((m for t_, m in samples if t_ >= 29.9), None)
        out["kib_per_conn_rss_30s"] = round((s_30 - s0["VmRSS"]) / max(1, out["echoed"]), 2) if s_30 is not None else None
        out["maps_idle"] = maps_summary(srv.pid)
        out["conntrack_idle"] = int(open(ct).read()) if os.path.exists(ct) else None
        out.update(srv_settled=s1, cg_settled=c1, settle_s=samples[-4][0] if stable(samples, s0["VmRSS"], a.n) else None,
                   rss_samples_kib=[m for _, m in samples], srv_fds_idle=nfds(srv.pid), srv_alive=srv.poll() is None)
        cl_rss = rss_of([c.pid for c in cl]); t1rss = rss_of([p.pid for p in tg])
        try:
            out["capabilities"] = next((l.strip()[:600] for l in open(f"/tmp/bigidle-srv-{a.port}.log") if "capabilities" in l), None)
            out["metrics_last"] = ([l.strip()[:1500] for l in open(f"/tmp/bigidle-srv-{a.port}.log") if "ev=metrics" in l] or [None])[-1]
        except OSError:
            pass
        out.update(client_rss_kib=cl_rss, target_rss_delta_kib=t1rss - t0rss)
        n = max(1, out["echoed"])
        out["kib_per_conn"] = {
            "rss": round((s1["VmRSS"] - s0["VmRSS"]) / n, 2), "anon": round((s1["RssAnon"] - s0["RssAnon"]) / n, 2),
            "cg_current": round((c1["current"] - c0["current"]) / 1024 / n, 2),
            "cg_sock": round((c1.get("sock", 0) - c0.get("sock", 0)) / 1024 / n, 2),
            "cg_kernel": round((c1.get("kernel", 0) - c0.get("kernel", 0)) / 1024 / n, 2),
            "cg_minus_clients": round(((c1["current"] - c0["current"]) / 1024 - cl_rss - (t1rss - t0rss)) / n, 2),
            "fds": round((out["srv_fds_idle"] - out["srv_fds_before"]) / n, 3)}
        for c in cl:
            c.stdin.close()
        for c in cl:
            try: c.wait(60)
            except subprocess.TimeoutExpired: pass
    except BaseException as e:  # incl. SystemExit(143) from SIGTERM: record it, clean up, exit non-zero below
        out["error"] = repr(e)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)  # a second SIGTERM must not abort the cleanup
        for p in procs:
            if p.poll() is None:
                try: os.killpg(p.pid, signal.SIGTERM)
                except OSError: pass
        for p in procs:
            try: p.wait(20)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
    try:  # ev=metrics_final is written at the server's SIGTERM (above)
        out["metrics_final"] = ([l.strip()[:2000] for l in open(f"/tmp/bigidle-srv-{a.port}.log") if "ev=metrics_final" in l] or [None])[-1]
    except OSError:
        pass
    print(json.dumps(out), flush=True)
    sys.exit(1 if "error" in out else 0)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--client":
        client_main(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == "--lat":
        lat_main(sys.argv[2:])
    else:
        main()
