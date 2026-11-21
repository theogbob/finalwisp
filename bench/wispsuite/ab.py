"""Rotated, interleaved A/B of server variants with wbench (30.10; was bench/ab.py, 30.09 / 20.19).

usage: wst ab VARIANTS.json REPS [suite options] WBENCH-RUN-ARGS...   (e.g. --test download --conns 10 --streams 10)
  VARIANTS.json: {"name": "server command (gets --port PORT appended)", ...}
  suite options (default from the env var in brackets):
    --port P (PORT, 6901)  --tport P (TPORT, 6902)  --tmode M (TMODE; default by test)  --dur S (DUR, 4)
    --warmup S (WARMUP, 1)  --raw FILE (RAW: one JSON record per run)  --link LABEL (LINK, lo)  --tls (AB_TLS=1)
    --fixed-order (FW_AB_ROTATE=0)
    --order rotate|random|balanced|chain (AB_ORDER, rotate): the slot order of the arms in a round. rotate = the start
      arm moves one place per round (as always). random = a shuffle per round (seeded with the round number: the same
      command gives the same orders). balanced = all orders of the arms in turn (2 to 4 arms; 3 arms = 6 orders).
      chain (80.04, 2 to 7 arms) = carry-balanced: each round starts with the arm the round before ended with, and over a
      whole cycle (2k rounds for k arms; 2 arms: 2) every arm follows every arm (itself included) equally often and is in
      every slot equally often (80.04); 8 or more arms: an error.
    --order-seed N (AB_ORDER_SEED, chain only; 0 = the arms as listed, from the first row of the table): another seed
      relabels the arms and picks the start row; the same seed gives the same orders. --fixed-order with chain: an error.
    --settle S (AB_SETTLE, 0 = off): before each run wait until the host's TCP memory is back at its value before
      the first run (+ 64 pages), at most S seconds; the record gets settle_s.
    --cmap all|ARM,ARM (AB_CMAP, off): 80.04 post-stratification: for those arms read which server worker holds each
      client connection right after set-up, BEFORE the window (Cmap0: /proc only, no server change); the record gets
      cmap0 (client ports per worker used; None when incomplete), cmap0_n, cmap0_ms, cmap0_end_ms, cmap0_read_ms; a read
      that ran into the window makes the run an error record. Cells with >= 2 connections, not connchurn / burstidle.
    --client-ssh [USER@]HOST [--server-ip IP] [--force-clean]: cross-host (root; bench/wispsuite/xhost.py): server +
      target on this box bound to its address facing HOST (variants get --host IP), wbench on HOST via ssh, iptables
      lets only HOST reach the ports during the run
  netns runs (root): SRV_PREFIX / CLI_PREFIX (e.g. "ip netns exec fws"), SRV_HOST, SRV_BIND env vars.
Every rep runs every variant once; the start variant rotates per rep (position bias). The server and the wbench
client each run in their own process group; a SIGTERM/SIGINT stops both (no strays). A stray process or listener
on PORT/TPORT stops the run before it starts (a leftover reuseport target silently takes half the streams).
Every raw record has t0 / tw0 / win_s / t1 (unix times: server start, client start, client wall, record written),
steal (host steal ticks during the client's run), slot (place in the round) and tcp_mem0 (host TCP pages before the run).
Prints one JSON line per variant: median + all values of the key metric (rps for rr/churn/connchurn/browse/udp-rr,
mib_s_up for upload, else mib_s_down), median server CPU% and RSS; browse adds latency and bulk.
--test connchurn: a new WebSocket connection per request (wbench; rps = connections/s).
--test burstidle: per run, 3 x (5 s download burst on new connections, 3 s idle) against one server process
  (suite-side, --dur/--warmup not used); mib_s_down = median burst, plus per-burst MiB/s and server CPU% for
  every burst and idle gap.
"""
import collections, contextlib, itertools, json, os, random, signal, sys, threading, time
from . import proc, sample, wbench
from .stats import median


class AbError(Exception):
    pass


# 80.04 --order chain: row r = the slot order of round r over the arms 0..k-1, as listed; a search script made
# these (odd k: Williams sequences + reverses, all translates, in Euler-circuit order; even k: searched) and checks them
CHAIN = {
    2: "01, 10",
    3: "012, 201, 120, 021, 102, 210",
    4: "0123, 3012, 2031, 1302, 2103, 3210, 0231, 1320",
    5: "01234, 42301, 13042, 20413, 34120, 02143, 31402, 24031, 10324, 43210",
    6: "012345, 501234, 402135, 531420, 024513, 315042, 240351, 153204, 430521, 143052, 254103, 325410",
    7: "0123456, 6452301, 1305264, 4260513, 3516042, 2041635, 5634120, 0214365, 5361402, 2406153, 3150624, 4625031, 1032546, 6543210",
}


def chain_rows(k):
    return [[int(c) for c in r] for r in CHAIN[k].split(", ")]


def chain_ok(rows, k):
    """a whole chain cycle read cyclically (the last round's last arm comes before the first round): every row is an
    order of 0..k-1, each row starts with the arm the row before it ended with, every ordered pair (self included)
    follows equally often, and every arm is in every slot equally often"""
    n = len(rows)
    if not n or n % k or any(sorted(r) != list(range(k)) for r in rows):
        return False
    stream = [x for r in rows for x in r] + [rows[0][0]]
    pairs = collections.Counter(zip(stream, stream[1:]))
    slots = collections.Counter((s, x) for r in rows for s, x in enumerate(r))
    return (all(rows[i][-1] == rows[(i + 1) % n][0] for i in range(n)) and len(pairs) == k * k and len(set(pairs.values())) == 1
            and len(slots) == k * k and len(set(slots.values())) == 1)


def schedule(names, reps, order="rotate", seed=None, rotate=True):
    """80.04: the slot order of every round, made before anything starts -> [[arm, ...] per round]; AbError for an
    order that cannot run. rotate / random / balanced: as before (rotate=False: the arms as listed in every round)."""
    names = list(names)
    if order not in ("rotate", "random", "balanced", "chain"):
        raise AbError(f"--order {order}: rotate, random, balanced or chain")
    if seed is not None and order != "chain":
        raise AbError(f"--order-seed is for --order chain (here --order {order})")
    if order == "balanced" and not 2 <= len(names) <= 4:
        raise AbError("--order balanced is for 2 to 4 arms")
    if order == "chain":
        k = len(names)
        if not rotate:
            raise AbError("--fixed-order and --order chain exclude each other")
        if k not in CHAIN:
            raise AbError(f"--order chain: no chain table for {k} arm{'' if k == 1 else 's'} (2 to {max(CHAIN)}); use --order random")
        if seed is None:
            seed = 0
        if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
            raise AbError(f"--order-seed {seed!r}: a whole number >= 0")
        rows = chain_rows(k)
        if not chain_ok(rows, k):
            raise AbError(f"--order chain: the table for {k} arms fails its self-check")
        perm, start = list(range(k)), 0
        if seed:
            rng = random.Random(seed)
            rng.shuffle(perm)
            start = rng.randrange(len(rows))
        return [[names[perm[x]] for x in rows[(start + rep) % len(rows)]] for rep in range(reps)]
    perms = list(itertools.permutations(names)) if order == "balanced" else None
    out = []
    for rep in range(reps):
        k = rep % len(names) if rotate else 0
        round_order = names[k:] + names[:k]
        if rotate and order == "random":
            round_order = list(names)
            random.Random(rep).shuffle(round_order)
        elif rotate and order == "balanced":
            round_order = list(perms[rep % len(perms)])
        out.append(round_order)
    return out


def run_ab(variants, reps, wb_args, *, wb, port="6901", tport="6902", tmode=None, dur="4", warmup="1", tls=False,
           raw=None, link="lo", srv_prefix=(), cli_prefix=(), srv_host="127.0.0.1", srv_bind="", rotate=True,
           verbose=True, client_ssh=None, tgt_host="127.0.0.1", order="rotate", settle=0.0, cmap=(), order_seed=None):
    """Returns {variant: [record per rep]}. Raises AbError before starting anything if a port is taken or the order
    cannot run (schedule).
    client_ssh (cross-host): wbench run executes on that host over ssh; the target binds tgt_host and the server
    is reached at srv_host (both this box's address facing the client; the caller sets the firewall)."""
    test = wb_args[wb_args.index("--test") + 1]
    tmode = tmode or wbench.target_mode(test)
    if client_ssh and tmode == "udp-echo":
        raise AbError("cross-host mode is TCP only (the firewall rules cover TCP; a public UDP echo would be a reflector)")
    netns = bool(srv_prefix)
    rounds = schedule(variants, reps, order, order_seed, rotate)  # 80.04: every round's order before anything starts
    cmap = set(cmap)
    if cmap:  # 80.04 --cmap: checked before anything starts
        names = list(variants)
        cmap = set(names) if "all" in cmap else cmap
        if cmap - set(names):
            raise AbError(f"--cmap {','.join(sorted(cmap - set(names)))}: not an arm")
        cv = [a.split("=", 1)[1] for a in wb_args if a.startswith("--conns=")] + [wb_args[i + 1] if i + 1 < len(wb_args) else "" for i, a in enumerate(wb_args) if a == "--conns"]
        if len(cv) > 1 or (cv and not cv[0].isdigit()) or (cv and int(cv[0]) < 1):
            raise AbError(f"--cmap: --conns must be given once as a positive number (got {cv})")
        conns = int(cv[0]) if cv else 1
        if test in ("connchurn", "burstidle") or conns < 2:
            cmap = set()  # brief connections / one connection: no map to read
    # netns: the servers live in another namespace, so a host listener with the same number does not matter
    bad = proc.strays([int(port), int(tport)], listeners=not netns)
    if bad:
        raise AbError("; ".join(bad))
    rawf = open(raw, "a") if raw else None
    tg = wbench.start_target(wb, tport, tmode, prefix=srv_prefix, wait=not netns,
                             extra=["--bind", tgt_host] if tgt_host != "127.0.0.1" else [])
    res = {k: [] for k in variants}
    names = list(variants)
    timeout = float(dur) + float(warmup) + 60
    tcp_max = sample.tcp_mem_max()  # 50.02 D
    pre = [*srv_prefix, *cli_prefix]
    nss = sorted({pre[i + 2] for i in range(len(pre) - 2) if pre[i] == "netns" and pre[i + 1] == "exec"})
    mem_idle = sample.tcp_mem_pages()
    try:
        for rep in range(reps):
            for slot, name in enumerate(rounds[rep]):
                cmd = " ".join(srv_prefix) + " " + variants[name] + f" --port {port} {srv_bind}"
                settle_s = None
                if settle > 0 and mem_idle is not None:  # 80.03: TCP memory of the run before must not be this run's start state
                    ts = time.time()
                    while (sample.tcp_mem_pages() or 0) > mem_idle + 64 and time.time() - ts < settle:
                        time.sleep(0.1)
                    settle_s = round(time.time() - ts, 2)
                mem0 = sample.tcp_mem_pages()
                t_start = time.time()
                p = proc.spawn(cmd, shell=True)
                try:
                    ready = True
                    if not netns:
                        ready = proc.wait_port(int(port), 15, p, host=srv_host)
                    time.sleep(max(0.0, 0.5 - (time.time() - t_start)))  # >= 0.5 s as before: every worker has bound
                    if p.poll() is not None:
                        ready = False
                    srv_pids = sample.group_pids(p.pid) if ready else ()  # 60.78 G22: the server's pids for the VmRSS samples (a /proc scan, before the CPU window)
                    pr0 = sample.tcp_pressure_both(nss)  # 60.42 verify: before the CPU window (review: subprocesses)
                    cpu0, _, _ = sample.group_usage(p.pid)
                    cg0 = cgroup_usage_s()
                    st0 = sample.steal_ticks()
                    t0 = time.time()
                    # 50.02 D: host TCP memory peak during the rep (this box: the server's; review: also cross-host)
                    mempk = sample.TcpMemPeak(pids=srv_pids)
                    with mempk:
                        if ready and test == "burstidle":
                            j = burst_idle(wb, [*(["--insecure"] if tls else []), "--url", f"{'wss' if tls else 'ws'}://{srv_host}:{port}/",
                                                "--target", f"{tgt_host}:{tport}"] + list(wb_args), p, cli_prefix, client_ssh)
                        elif ready:
                            args = [*(["--insecure"] if tls else []), "--url", f"{'wss' if tls else 'ws'}://{srv_host}:{port}/",
                                    "--target", f"{tgt_host}:{tport}", "--duration", dur, "--warmup", warmup] + list(wb_args)
                            c0m = Cmap0(srv_pids, int(port), conns, float(warmup)) if name in cmap else None  # its clock starts here, before the client
                            if c0m:
                                c0m.start()
                            try:
                                j = wbench.run(wb, args, timeout, prefix=cli_prefix, ssh=client_ssh)
                            finally:
                                if c0m:
                                    c0m.stop.set()  # a client that ended early (failed launch): no read goes on into the next run
                                    c0m.join(5)
                            if c0m and isinstance(j, dict):
                                alive = c0m.is_alive()  # latched once: a still-running sampler counts as late
                                j.update(c0m.result(j.get("conns_ok"), alive))
                                if alive or c0m.late:  # the read may have overlapped the window: no timing of this run is used
                                    j["cmap0_late_values"] = {x: j.pop(x) for x in ("rps", "mib_s_up", "mib_s_down", "bulk_mib_s", "pages_s", "page_p50_us", "page_p99_us",
                                                                                    "p50_us", "p90_us", "p99_us", "p999_us", "timer_late_ms") if x in j}
                                    j.setdefault("error", "cmap0: the map read ran into the window (this run is not a measurement)")
                        else:
                            j = {"error": f"server did not start on :{port}"}
                    if mempk.samples:  # share of 0.05 s samples with the global pressure flag set (the robust metric)
                        j["tcp_press_frac"] = round(mempk.press_samples / mempk.samples, 3)
                    if mempk.max_seen is not None:
                        j["tcp_mem_peak"] = mempk.max_seen
                        j["at_tcp_mem_max"] = sample.at_tcp_mem_max(mempk.max_seen, tcp_max)
                    wall = time.time() - t0
                    st1 = sample.steal_ticks()
                    cg1 = cgroup_usage_s()  # before the /proc scan below, so its CPU stays outside the window
                    cpu1, rss, hwm = sample.group_usage(p.pid)
                finally:
                    proc.stop(p, 0)
                # 60.42 verify: entries / ms (TcpExt) read after the server is gone: the kernel credits
                # TCPMemoryPressuresChrono when pressure ends, usually at this rep's teardown (review P2);
                # a lower bound for pressure that outlives the rep (tcp_press_frac does not have that gap)
                time.sleep(0.2)
                pd = sample.pressure_delta(pr0, sample.tcp_pressure_both(nss))
                if pd is not None and isinstance(j, dict):
                    j["tcp_press"], j["tcp_press_ms"] = pd
                if not netns and not proc.wait_free(int(port), 30):
                    # 60.12 scale: the reaped server's sockets close asynchronously (gold t36 echo 100x10: 36 listeners +
                    # CLOSE_WAITs for > 0.3 s), and the next server's bind then failed with EADDRINUSE in every other rep
                    raise AbError(f"port {port} still has a listener 30 s after the server stopped")
                time.sleep(0.3)
                if "cpu_pct" not in j:  # burstidle sets its own (bursts only)
                    j["cpu_pct"] = round(100 * (cpu1 - cpu0) / wall, 1) if wall > 0 else 0
                if cg0 is not None and cg1 is not None and wall > 0 and not client_ssh and test != "burstidle":
                    # 60.12 scale tests: the whole cgroup (server + wbench client + target + suite) over the same window;
                    # client side CPU% ~= cg_cpu_pct - cpu_pct (shared boxes: server and client share the CPUs; not for
                    # burstidle, whose cpu_pct is the median burst; not valid if SRV_/CLI_PREFIX moves a process to another cgroup)
                    j["cg_cpu_pct"] = round(100 * (cg1 - cg0) / wall, 1)
                j["loadavg"] = [float(x) for x in open("/proc/loadavg").read().split()[:3]]  # host-wide inside a container
                j["rss_mib"] = round(rss, 1)
                j["hwm_mib"] = round(hwm, 1)
                if mempk.rss_max is not None:  # 60.78 G22: per-sample VmRSS max of the server over the run (sampled every 0.05 s)
                    j["rss_peak_mib"] = round(mempk.rss_max, 1)
                # 80.03 (P6 of the performance audit): when the run was, so that the time budget of a round is a table and
                # a noisy run can be seen. t0 = the server's start, tw0 = the client's start (the window is inside
                # tw0..tw0+win_s), t1 = this record (after the stop and the settle); steal = host steal ticks over the
                # client's time (None where /proc/stat has no such column)
                # slot = the place of this run in its round (0 = first); tcp_mem0 = host TCP memory pages before the server start
                j.update(t0=round(t_start, 3), tw0=round(t0, 3), win_s=round(wall, 3), t1=round(time.time(), 3),
                         steal=None if st0 is None or st1 is None else st1 - st0, slot=slot, tcp_mem0=mem0)
                if settle_s is not None:
                    j["settle_s"] = settle_s
                if rawf:
                    rawf.write(json.dumps({"rep": rep, "v": name, "extra": " ".join(wb_args), "tls": tls, "link": link, **j}) + "\n")
                    rawf.flush()
                res[name].append(j)
                if verbose:
                    print(f"  {name}: {json.dumps(j)}", file=sys.stderr, flush=True)
    finally:
        proc.stop(tg, 0)
        if rawf:
            rawf.close()
    return res


def conn_map(pids, port, want=0):
    """80.04: which server epoll instance (= worker: fw has one epoll per worker thread) holds
    each client connection -> ([sorted client ports per epoll that holds any], connections seen). Server sockets =
    ESTABLISHED with local port `port`, read from the server's own /proc/<pid>/net (its network namespace); epoll members
    from /proc/<pid>/fdinfo/<epoll fd> "tfd:" lines. The epoll scan runs only when >= want connections are up.
    (None, n) when it cannot be read."""
    if not pids:
        return None, 0
    try:
        peer = {}
        for fn in ("tcp", "tcp6"):
            try:
                with open(f"/proc/{pids[0]}/net/{fn}") as f:
                    lines = f.read().splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                x = line.split()
                if len(x) > 9 and x[3] == "01" and int(x[1].rsplit(":", 1)[1], 16) == port:
                    peer[x[9]] = int(x[2].rsplit(":", 1)[1], 16)
        if len(peer) < want:
            return None, len(peer)
        out = []
        for pid in pids:
            fds, eps = {}, []
            for fd in os.listdir(f"/proc/{pid}/fd"):
                try:
                    t = os.readlink(f"/proc/{pid}/fd/{fd}")
                except OSError:
                    continue
                if t.startswith("socket:["):
                    fds[fd] = t[8:-1]
                elif t == "anon_inode:[eventpoll]":
                    eps.append(fd)
            for ep in eps:
                try:
                    with open(f"/proc/{pid}/fdinfo/{ep}") as f:
                        info = f.read()
                except OSError:
                    continue
                ports = sorted(peer[fds[x]] for x in (l.split()[1] for l in info.splitlines() if l.startswith("tfd:")) if x in fds and fds[x] in peer)
                if ports:
                    out.append(ports)
        return sorted(out), len(peer)
    except (OSError, ValueError, IndexError):
        return None, 0


class Cmap0(threading.Thread):
    """80.04: the connection -> worker map right after the client set up its connections, before the window
    (the kernel's SO_REUSEPORT choice: random per server start, exogenous to the build). Built just before the client
    starts (its monotonic clock starts then); polls until the map holds `want` connections. No read starts after 0.8 x
    warm-up; a read that ended after the warm-up (it may have overlapped the window, which opens after set-up + warm-up)
    drops the map and marks the run cmap0_late, and run_ab makes that run an error record (not a round: its timing is
    never used; the cell then needs a re-run). A map is also dropped when the client set up fewer connections than asked
    (wbench conns_ok: fw registers a socket before its handshake). result(): cmap0 (None when incomplete, late or short),
    cmap0_n (connections in the map / seen), cmap0_ms (-> complete map), cmap0_end_ms (-> end of the last read),
    cmap0_read_ms (time in reads)."""

    def __init__(self, pids, port, want, warmup):
        super().__init__(daemon=True)
        self.t0 = time.monotonic()
        self.pids, self.port, self.want, self.warmup = list(pids), port, want, warmup
        self.m, self.n, self.ms, self.end_ms, self.read_s, self.late = None, 0, None, None, 0.0, False
        self.stop = threading.Event()

    def start(self):
        # as sample.TcpMemPeak: the thread inherits blocked termination signals, so they reach the main thread only
        # (proc.spawn blocks them there between fork and registration)
        old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        try:
            super().start()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)

    def run(self):
        while time.monotonic() - self.t0 < 0.8 * self.warmup and not self.stop.is_set():
            r0 = time.monotonic()
            m, n = conn_map(self.pids, self.port, self.want)
            r1 = time.monotonic()
            self.read_s += r1 - r0
            self.end_ms = round((r1 - self.t0) * 1000, 1)
            self.n = sum(len(x) for x in m) if m else n
            if r1 - self.t0 >= self.warmup:
                self.late = True
                return
            if m and self.n >= self.want:
                self.m, self.ms = m, self.end_ms
                return
            self.stop.wait(0.005)

    def result(self, conns_ok=None, alive=False):
        short = self.m is not None and conns_ok is not None and conns_ok < self.want
        return {"cmap0": None if (short or alive) else self.m, "cmap0_n": self.n, "cmap0_ms": self.ms, "cmap0_end_ms": self.end_ms,
                "cmap0_read_ms": round(self.read_s * 1000, 1), **({"cmap0_late": True} if self.late else {}),
                **({"cmap0_short": f"conns_ok {conns_ok} of {self.want}"} if short else {}), **({"cmap0_alive": True} if alive else {})}


def cgroup_usage_s():
    """CPU seconds used by this process's cgroup (v2 cpu.stat usage_usec), None if unreadable."""
    try:
        cg = open("/proc/self/cgroup").read().strip().split("::", 1)[-1]
        for l in open(f"/sys/fs/cgroup{cg.rstrip('/')}/cpu.stat"):
            k, v = l.split()
            if k == "usage_usec":
                return int(v) / 1e6
    except (OSError, ValueError):
        return None
    return None


BURSTS, BURST_S, IDLE_S = 3, 5, 3.0  # burstidle (30.10 design): 3 x (5 s download burst, 3 s idle)


def burst_idle(wb, args, p, cli_prefix=(), client_ssh=None):
    """burstidle: BURSTS x (one `wbench run --test download` of BURST_S s, no warmup, new connections each time;
    then IDLE_S s with no clients) against the SAME server process. Catches costs that appear only after the
    server went idle (memory returned to the OS and faulted back in, idle sweeps, timers). Record: mib_s_down =
    median burst; bursts_mib_s, burst_cpu_pct (server CPU% during each burst), idle_cpu_pct (during each idle
    gap); cpu_pct = median burst CPU%."""
    args = list(args)
    args[args.index("--test") + 1] = "download"
    args += ["--duration", str(BURST_S), "--warmup", "0"]
    bursts, cpus, idles, errors, j = [], [], [], 0, {}
    for k in range(BURSTS):
        c0, _, _ = sample.group_usage(p.pid)
        t0 = time.time()
        j = wbench.run(wb, args, BURST_S + 60, prefix=cli_prefix, ssh=client_ssh)
        c1, _, _ = sample.group_usage(p.pid)
        t1 = time.time()
        if "error" in j:
            return {"error": f"burst {k + 1}: {j['error']}"}
        if p.poll() is not None:
            return {"error": f"server exited during burst {k + 1}"}
        bursts.append(j.get("mib_s_down"))
        cpus.append(round(100 * (c1 - c0) / (t1 - t0), 1))
        errors += int(j.get("errors") or 0)
        time.sleep(IDLE_S)
        if p.poll() is not None:  # an idle-path crash (sweeps, timers, memory return) must not pass
            return {"error": f"server exited in the idle gap after burst {k + 1}"}
        c2, _, _ = sample.group_usage(p.pid)
        idles.append(round(100 * (c2 - c1) / (time.time() - t1), 2))
    return {**j, "test": "burstidle", "mib_s_down": median(bursts), "errors": errors, "bursts_mib_s": bursts,
            "burst_cpu_pct": cpus, "idle_cpu_pct": idles, "cpu_pct": median(cpus)}


def summarize(test, res):
    key = wbench.key_metric(test)
    lines = []
    for name, rs in res.items():
        ok = [r for r in rs if r.get(key) is not None]
        med = lambda f: median([r.get(f) for r in ok])
        line = {"variant": name, "test": test, "n": len(ok), key: med(key), "all": [r.get(key) for r in rs],
                "cpu_pct": med("cpu_pct"), "cg_cpu_pct": med("cg_cpu_pct"), "rss_mib": med("rss_mib"), "errors": sum(r.get("errors", 0) or 0 for r in ok)}
        if test in ("rr", "churn", "connchurn", "browse"):
            line.update(p50_us=med("p50_us"), p99_us=med("p99_us"))
        if test == "burstidle":
            line.update(bursts_mib_s=[r.get("bursts_mib_s") for r in rs], burst_cpu_pct=[r.get("burst_cpu_pct") for r in rs],
                        idle_cpu_pct=[r.get("idle_cpu_pct") for r in rs])
        if test == "browse":
            line.update(page_p50_us=med("page_p50_us"), page_p99_us=med("page_p99_us"), bulk_mib_s=med("bulk_mib_s"),
                        p50_all=[r.get("p50_us") for r in rs])
        lines.append(line)
    return lines


def main(argv):
    if len(argv) < 2 or argv[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if argv and argv[0] in ("-h", "--help") else 2)
    env = os.environ
    o = {"--port": env.get("PORT", "6901"), "--tport": env.get("TPORT", "6902"), "--tmode": env.get("TMODE") or None,
         "--dur": env.get("DUR", "4"), "--warmup": env.get("WARMUP", "1"), "--raw": env.get("RAW") or None,
         "--link": env.get("LINK", "lo"), "--client-ssh": None, "--server-ip": None,
         "--order": env.get("AB_ORDER", "rotate"), "--settle": env.get("AB_SETTLE", "0"), "--cmap": env.get("AB_CMAP", ""),
         "--order-seed": env.get("AB_ORDER_SEED") or None}
    flags = {"--tls": env.get("AB_TLS", "0") == "1", "--fixed-order": env.get("FW_AB_ROTATE", "1") == "0", "--force-clean": False}
    variants = json.load(open(argv[0]))
    reps = int(argv[1])
    rest, extra, i = argv[2:], [], 0
    while i < len(rest):
        if rest[i] in o and i + 1 < len(rest):
            o[rest[i]] = rest[i + 1]; i += 2
        elif rest[i] in flags:
            flags[rest[i]] = True; i += 1
        else:
            extra.append(rest[i]); i += 1
    if "--test" not in extra:
        sys.exit("wst ab: --test is required")
    if "--order-seed" in extra:  # a trailing --order-seed without its number would go to wbench
        sys.exit("ab: --order-seed needs a number")
    seed = o["--order-seed"]
    if seed is not None:
        if not (seed.isascii() and seed.isdigit()):
            sys.exit(f"ab: --order-seed {seed}: a whole number >= 0")
        seed = int(seed)
    proc.install_handlers()
    wb = wbench.find()
    kw = dict(srv_prefix=env.get("SRV_PREFIX", "").split(), cli_prefix=env.get("CLI_PREFIX", "").split(),
              srv_host=env.get("SRV_HOST", "127.0.0.1"), srv_bind=env.get("SRV_BIND", ""), link=o["--link"])
    fw = contextlib.nullcontext()
    if o["--client-ssh"]:
        from . import xhost
        try:
            xh = xhost.Xhost(o["--client-ssh"], wb, o["--server-ip"])
            fw = xhost.firewall([int(o["--port"]), int(o["--tport"])], xh.client_ip, flags["--force-clean"])
        except xhost.XhostError as e:
            sys.exit(f"ab: {e}")
        if xh.md5_problem():
            print(f"ab: WARNING {xh.md5_problem()}", file=sys.stderr)
        print(f"ab: cross-host {xh.describe()}", file=sys.stderr)
        kw = dict(srv_host=xh.server_ip, srv_bind=f"--host {xh.server_ip}", tgt_host=xh.server_ip, client_ssh=xh.ssh,
                  link=xh.label if o["--link"] == "lo" else o["--link"])
    try:
        with fw:
            res = run_ab(variants, reps, extra, wb=wb, port=o["--port"], tport=o["--tport"], tmode=o["--tmode"],
                         dur=o["--dur"], warmup=o["--warmup"], tls=flags["--tls"], raw=o["--raw"],
                         rotate=not flags["--fixed-order"], order=o["--order"], settle=float(o["--settle"]),
                         cmap=tuple(x for x in o["--cmap"].split(",") if x), order_seed=seed, **kw)
    except AbError as e:
        sys.exit(f"ab: {e}")
    except Exception as e:  # xhost.XhostError from the firewall setup
        if type(e).__name__ != "XhostError":
            raise
        sys.exit(f"ab: {e}")
    for line in summarize(extra[extra.index("--test") + 1], res):
        print(json.dumps(line), flush=True)
    if o["--client-ssh"] and xhost.cleanup_errors:
        sys.exit("ab: " + "; ".join(xhost.cleanup_errors))
