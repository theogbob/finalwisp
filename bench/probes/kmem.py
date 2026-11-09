#!/usr/bin/env python3
"""60.44 host TCP memory accounting by socket role (v11x-kmem, 2026-11). stdlib only, no `ss` needed (containers
without iproute2): one NETLINK_SOCK_DIAG dump per sample gives every TCP socket's skmem.

Roles (loopback bench, one host): ws-cli = the client's WebSocket (peer port = server port), ws-srv = the server's
WebSocket (local port = server port), tgt-srv = the server's socket to a target (peer port in the target ports),
tgt = the target process's socket (local port in the target ports). Per role per sample, MiB: r = rmem_alloc,
w = wmem_queued, f = fwd_alloc (charged to the protocol's memory, not yet used), rq / wq = unread / unacked+unsent
payload bytes (the kernel's rqueue / wqueue). "mem" = r + w + f ~= what the socket charges to tcp_mem (pages).

usage (driver): kmem.py OUT.json --reps N --server SPEC ... --case test:conns:streams[:"wbench args"] ...
  SPEC = registry name (bench/servers.json), fw:PATH [args], or NAME=CMD {port}.
Per cell: TcpExt TCPMemoryPressures / Chrono deltas, tcp_press_frac (0.05 s samples of the global flag), sockstat TCP
mem peak (0.05 s), server VmRSS peak (0.1 s), and the role series (every --every s): role sums at the sample with the
largest host total ("at_peak"), per-role maxima ("role_max"), the median over the measured window ("steady").
"""
import argparse, json, os, socket, struct, sys, threading, time

MIB = 1 << 20
NETLINK_SOCK_DIAG, SOCK_DIAG_BY_FAMILY = 4, 20
NLM_F_REQUEST, NLM_F_DUMP = 1, 0x300
NLMSG_DONE, NLMSG_ERROR = 3, 2
INET_DIAG_SKMEMINFO = 7
ROLES = ("ws-cli", "ws-srv", "tgt-srv", "tgt", "other")


def diag_dump(families=(socket.AF_INET, socket.AF_INET6)):
    """[(sport, dport, state, rq, wq, meminfo tuple)] for every TCP socket in this netns."""
    out = []
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
    try:
        for fam in families:
            # inet_diag_req_v2: family, protocol, ext, pad, states, id (sport, dport, src[16], dst[16], if, cookie[2])
            req = struct.pack("=BBBBI", fam, socket.IPPROTO_TCP, 1 << (INET_DIAG_SKMEMINFO - 1), 0, 0xFFF & ~(1 << 10))
            req += b"\0" * 48
            hdr = struct.pack("=IHHII", 16 + len(req), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, 1, 0)
            s.send(hdr + req)
            done = False
            while not done:
                buf = s.recv(1 << 20)
                off = 0
                while off + 16 <= len(buf):
                    ln, typ, _, _, _ = struct.unpack_from("=IHHII", buf, off)
                    if typ == NLMSG_DONE or typ == NLMSG_ERROR:
                        done = True
                        break
                    m = off + 16
                    state = buf[m + 1]
                    sport, dport = struct.unpack_from(">HH", buf, m + 4)
                    # inet_diag_msg: family,state,timer,retrans (4) id (48) expires,rqueue,wqueue,uid,inode (20)
                    _exp, rq, wq = struct.unpack_from("=III", buf, m + 52)
                    mi = None
                    a = m + 72
                    end = off + ln
                    while a + 4 <= end:
                        alen, atyp = struct.unpack_from("=HH", buf, a)
                        if alen < 4:
                            break
                        if atyp == INET_DIAG_SKMEMINFO:
                            n = (alen - 4) // 4
                            mi = struct.unpack_from(f"={n}i", buf, a + 4)  # signed: fwd_alloc can be < 0
                        a += (alen + 3) & ~3
                    if mi:
                        out.append((sport, dport, state, rq, wq, mi))
                    off += (ln + 3) & ~3
    finally:
        s.close()
    return out


def role_of(sport, dport, port, tports):
    if dport == port:
        return "ws-cli"
    if sport == port:
        return "ws-srv"
    if dport in tports:
        return "tgt-srv"
    if sport in tports:
        return "tgt"
    return "other"


def role_sums(port, tports):
    """{role: {n, r, w, f, rq, wq, mem (MiB), rb_max, tb_max, rb_avg, tb_avg (KiB)}} for established-ish sockets."""
    acc = {}
    for sport, dport, state, rq, wq, mi in diag_dump():
        if state == 10:  # LISTEN
            continue
        rl = role_of(sport, dport, port, tports)
        d = acc.setdefault(rl, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        r, rb, t, tb, f, w = mi[0], mi[1], mi[2], mi[3], mi[4], mi[5]
        d[0] += 1; d[1] += r; d[2] += w; d[3] += f; d[4] += rq; d[5] += wq
        d[6] = max(d[6], rb); d[7] = max(d[7], tb); d[8] += rb; d[9] += tb
    res = {}
    for rl, d in acc.items():
        n = d[0]
        res[rl] = {"n": n, "r": d[1] / MIB, "w": d[2] / MIB, "f": d[3] / MIB, "rq": d[4] / MIB, "wq": d[5] / MIB,
                   "mem": (d[1] + d[2] + d[3]) / MIB, "rb_max": d[6] >> 10, "tb_max": d[7] >> 10,
                   "rb_avg": (d[8] // n) >> 10, "tb_avg": (d[9] // n) >> 10}
    return res


def sockstat_pages():
    for l in open("/proc/net/sockstat"):
        if l.startswith("TCP:"):
            f = l.split()
            return int(f[f.index("mem") + 1])
    return None


class RoleSampler:
    """Thread: every `every` s a diag dump by role + sockstat pages + the server's VmRSS."""

    def __init__(self, port, tports, pid, every=0.1):
        self.port, self.tports, self.pid, self.every = port, set(tports), pid, every
        self.series, self._stop = [], threading.Event()
        self.rss_peak = 0.0
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        t0 = time.time()
        while True:
            try:
                rs = role_sums(self.port, self.tports)
                pg = sockstat_pages()
            except OSError:
                rs, pg = {}, None
            try:
                with open(f"/proc/{self.pid}/status") as f:
                    st = f.read()
                rss = int(st.split("VmRSS:")[1].split()[0]) / 1024
                self.rss_peak = max(self.rss_peak, rss)
            except (OSError, IndexError, ValueError):
                rss = None
            now = time.time() - t0
            self.series.append({"t": round(now, 3), "pages": pg, "rss": rss, "roles": rs})
            # the start transient (first credit window in flight) is short: 20 ms samples for the first 2.5 s
            if self._stop.wait(min(self.every, 0.02) if now < 2.5 else self.every):
                return

    def __enter__(self):
        import signal  # as sample.TcpMemPeak: the thread inherits the blocked termination signals (proc.spawn relies on it)
        sigs = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
        old = signal.pthread_sigmask(signal.SIG_BLOCK, sigs)
        try:
            self._t.start()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)
        return self

    def __exit__(self, *e):
        self._stop.set()
        self._t.join(5)

    def summary(self, t_lo, t_hi):
        """at_peak: role mem at the sample with the most total role memory; role_max: per role max of mem; steady:
        per-role median mem over samples in [t_lo, t_hi]; also per-role details at the peak."""
        tot = lambda s: sum(v["mem"] for v in s["roles"].values())
        if not self.series:
            return {}
        pk = max(self.series, key=tot)
        rmax = {}
        for s in self.series:
            for rl, v in s["roles"].items():
                rmax[rl] = max(rmax.get(rl, 0), v["mem"])
        # review: the first 2.5 s are sampled every 20 ms; thin them to `every` so the median is not weighted
        # toward the start of the window
        win, last = [], -1e9
        for s in self.series:
            if t_lo <= s["t"] <= t_hi and s["t"] - last >= self.every * 0.9:
                win.append(s)
                last = s["t"]
        win = win or self.series
        steady, steady_d = {}, {}
        for rl in ROLES:
            vals = sorted(s["roles"].get(rl, {}).get("mem", 0) for s in win)
            if any(vals):
                steady[rl] = round(vals[len(vals) // 2], 1)
                med = lambda k: round(sorted(s["roles"].get(rl, {}).get(k, 0) for s in win)[len(win) // 2], 2)
                steady_d[rl] = {k: med(k) for k in ("r", "w", "f", "rq", "wq", "rb_avg", "tb_avg", "rb_max", "tb_max")}
        r1 = lambda d: {k: (round(v, 2) if isinstance(v, float) else v) for k, v in d.items()}
        return {"peak_t": pk["t"], "peak_total": round(tot(pk), 1), "peak_pages": pk["pages"],
                "at_peak": {rl: r1(v) for rl, v in pk["roles"].items()}, "role_max": {k: round(v, 1) for k, v in rmax.items()},
                "steady": steady, "steady_detail": steady_d, "steady_total": round(sum(steady.values()), 1), "samples": len(self.series)}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    bench = os.path.dirname(here)
    sys.path.insert(0, bench)
    from wispsuite import proc, report, sample, servers as srvmod, wbench
    from wispsuite.matrix import run_case, MODES

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--reps", type=int, default=2)
    ap.add_argument("--server", action="append", default=[])
    ap.add_argument("--case", action="append", default=[])
    ap.add_argument("--duration", type=float, default=5)
    ap.add_argument("--warmup", type=float, default=1)
    ap.add_argument("--port", type=int, default=27700)
    ap.add_argument("--every", type=float, default=0.1)
    ap.add_argument("--settle", type=float, default=20)
    ap.add_argument("--keep-series", action="store_true", help="store the full role series per cell (large)")
    a = ap.parse_args()
    cases = []
    for c in a.case:
        t, cn, st, *rest = c.split(":", 3)
        d = {"test": t, "conns": int(cn), "streams": int(st)}
        if rest:
            d["extra"] = rest[0].split()
        cases.append(d)
    port = a.port
    tports = {m: port + 1 + i for i, m in enumerate(MODES)}
    wb = wbench.find()
    reg = srvmod.load()
    srvs = [srvmod.resolve(s, reg) for s in a.server]
    logdir = os.path.splitext(os.path.abspath(a.out))[0] + "-logs"
    os.makedirs(logdir, exist_ok=True)
    bad = proc.strays([port, *tports.values()])
    if bad:
        sys.exit("strays: " + "; ".join(bad))
    proc.install_handlers()
    rows = []
    host = {"tcp_mem": open("/proc/sys/net/ipv4/tcp_mem").read().split() if os.path.exists("/proc/sys/net/ipv4/tcp_mem") else None,
            "tcp_rmem": open("/proc/sys/net/ipv4/tcp_rmem").read().split(), "tcp_wmem": open("/proc/sys/net/ipv4/tcp_wmem").read().split(),
            "nproc": os.cpu_count(), "uname": os.uname().release}

    def save():
        report.write(a.out, "kmem-roles", binaries=[wb, os.environ.get("FINALWISP_BIN", "")],
                     config={"cases": cases, "servers": [s.name for s in srvs], "cmds": a.server, "reps": a.reps,
                             "duration": a.duration, "warmup": a.warmup, "host": host}, results=rows)

    def log(m):
        print(m, file=sys.stderr, flush=True)

    try:
        for mode, tport in tports.items():
            wbench.start_target(wb, tport, mode, log=os.path.join(logdir, f"target-{mode}.log"))
        for rep in range(a.reps):
            k = rep % len(srvs)
            for srv in srvs[k:] + srvs[:k]:
                for case in cases:  # one server process per cell: no state carried between cells
                    slog = os.path.join(logdir, f"server-{srv.name}-r{rep}.log")
                    t_s = time.time()
                    lim = sample.tcp_mem_max() or (1 << 30)
                    while (sample.tcp_mem_pages() or 0) > max(lim * 0.01, 256) and time.time() - t_s < a.settle:
                        time.sleep(0.2)
                    try:
                        p = srv.start(port, srvmod.SCRATCH, log=slog)
                    except RuntimeError as e:
                        rows.append({"server": srv.name, **case, "rep": rep, "error": str(e)}); save(); continue
                    time.sleep(0.3)
                    pr0 = sample.tcp_pressure_both()
                    mem0 = sample.tcp_mem_pages()
                    with sample.TcpMemPeak() as tpk, RoleSampler(port, tports.values(), p.pid, a.every) as rsmp:
                        res = run_case(wb, port, tports, case, srv, a.duration, a.warmup, p)
                    proc.stop(p)
                    proc.wait_free(port)
                    pr1 = sample.tcp_pressure_both()
                    pd = sample.pressure_delta(pr0, pr1)
                    res.update(server=srv.name, rep=rep, conns=case["conns"], streams=case["streams"], case_extra=case.get("extra"))
                    res.update(tcp_mem_pages_before=mem0, tcp_mem_peak_mib=round((tpk.max_seen or 0) * 4096 / MIB, 1),
                               tcp_press_frac=round(tpk.press_samples / tpk.samples, 3) if tpk.samples else None,
                               tcp_press=pd[0] if pd else None, tcp_press_ms=pd[1] if pd else None,
                               rss_peak_sampled=round(rsmp.rss_peak, 1),
                               roles=rsmp.summary(a.warmup + 0.5, a.warmup + a.duration - 0.2))
                    if a.keep_series:
                        res["series"] = rsmp.series
                    rows.append(res); save()
                    rl = res["roles"]
                    log(f"{srv.name} {case['test']} {case['conns']}x{case['streams']} {case.get('extra','')} r{rep}: "
                        f"up {res.get('mib_s_up')} down {res.get('mib_s_down')} err {res.get('errors')} rss {res.get('server_peak_mib')} "
                        f"tcp_peak {res['tcp_mem_peak_mib']} press {res['tcp_press_frac']} | steady {rl.get('steady')} | peak {rl.get('peak_total')} "
                        f"{ {k: round(v['mem'], 1) for k, v in rl.get('at_peak', {}).items()} } {res.get('error', '')}")
    finally:
        proc.stop_all()
        save()
    log(f"results: {a.out}")


if __name__ == "__main__":
    main()
