"""80.04: timed single-box runs, box side (latency distributions, saturation curves, CPU per unit of work).

usage: python3 -m wispsuite.timed run JOB.json     (cwd = the job root; bench/wispsuite importable)
       python3 -m wispsuite.timed check JOB.json   one JSON line {"clean": bool, "why": [...]}; status 0 clean, 3 dirty
The laptop side is bench/tools/timebox.py (lock, ship, start as a transient unit, pull, tables). Files in the job root:
out/raw.jsonl (one line per wbench run: the whole wbench JSON with the latency buckets and the window-edge counters,
host-state tags, the run's part times), out/probe.json, PROGRESS, DONE | FAILED | REFUSED. A file STOP ends the
session at the next round (lat) or sweep (curve) boundary, so every round on file has every arm.

Job keys: arms {name: {"label", "cmd" (gets {port}), "extra": [wbench args]}}, mode "lat" | "curve", cell
"test:conns:streams[:size]", port, tport (< 32768), wbench (path), unit ("scope": each server in its own transient
systemd scope, its cgroup read at the window edges; "none": its pids), src_port (null or BASE: connection i binds
BASE + i, the same server worker in every arm), dur, warmup, rounds (lat), rate (lat: null = closed loop, or messages
per second), curve {"axis": "rate" | "conns", "fracs" | "rates" | "conns", "dur", "warmup", "sweeps", "drain",
"calib_dur", "refine" (3: bisection points between the last served and the first unserved step)}, seed, deadline (unix time: no run starts after it), marks (hoststate.BAD_MARKS overrides).

The run loop ("fast loop", 80.03, waits on conditions instead of fixed sleeps):
  start: the server's port accepts, and the server shows as many listeners on the port and threads as its probe
         start did (one probe per arm at the session start: 0.5 s after the port accepted); at most 1 s
  run:   one `wbench run --json --lat --edges` (CPU, host state and TCP pressure read at the window's two edges)
  stop:  SIGKILL to the server's group, the port free (5 ms poll), host TCP memory no longer falling (3 reads 10 ms
         apart, at most 0.5 s)
Every record has d_start / d_run / d_stop (seconds), so the fixed cost per run is a table.
lat mode: `rounds` rounds; every round runs every arm once (fresh server each), in a random order per round
(seeded). curve mode: per sweep (random arm order), one fresh server per arm runs every step in rising order
(axis rate: open loop at each offered rate; axis conns: closed loop with that many connections); the rates come
from fracs x the highest closed-loop rate of a calibration run per arm (or from "rates")."""
import json, math, os, random, re, shlex, sys, threading, time
from . import hoststate, proc, sample, wbench

HZ = os.sysconf("SC_CLK_TCK")


def utc(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def listeners(port):
    hexport, n = f"{port:04X}", 0
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(fn) as f:
                next(f)
                for line in f:
                    x = line.split()
                    if x[3] == "0A" and x[1].rsplit(":", 1)[1] == hexport:
                        n += 1
        except (OSError, StopIteration, IndexError):
            continue
    return n


def udp_bound(port):
    """UDP sockets bound to the port (the udp-echo target's)"""
    hexport, n = f"{port:04X}", 0
    for fn in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(fn) as f:
                next(f)
                n += sum(1 for line in f if line.split()[1].rsplit(":", 1)[1] == hexport)
        except (OSError, StopIteration, IndexError):
            continue
    return n


def threads(pids):
    n = 0
    for pid in pids:
        try:
            with open(f"/proc/{pid}/status") as f:
                for l in f:
                    if l.startswith("Threads:"):
                        n += int(l.split()[1])
                        break
        except OSError:
            pass
    return n


def thread_sched(pids):
    """{tid: [comm, on-CPU ns, run-queue wait ns, timeslices, voluntary switches, involuntary switches]} of every thread
    of `pids` (/proc/<pid>/task/<tid>/schedstat + status): 80.04 where a message's time goes besides CPU"""
    out = {}
    for pid in pids:
        try:
            tids = os.listdir(f"/proc/{pid}/task")
        except OSError:
            continue
        for tid in tids:
            try:
                b = f"/proc/{pid}/task/{tid}/"
                comm = open(b + "comm").read().strip()
                run, wait, slices = (int(x) for x in open(b + "schedstat").read().split()[:3])
                vcs = ncs = 0
                with open(b + "status") as f:
                    for l in f:
                        if l.startswith("voluntary_ctxt_switches:"):
                            vcs = int(l.split()[1])
                        elif l.startswith("nonvoluntary_ctxt_switches:"):
                            ncs = int(l.split()[1])
                out[tid] = [comm, run, wait, slices, vcs, ncs]
            except (OSError, ValueError, IndexError):
                pass
    return out


def sched_delta(a, b):
    """per thread present at both reads: [comm, d run ns, d wait ns, d slices, d voluntary, d involuntary]"""
    return {f"{v[0]}/{t}": [v[1] - a[t][1], v[2] - a[t][2], v[3] - a[t][3], v[4] - a[t][4], v[5] - a[t][5]]
            for t, v in b.items() if t in a and (v[1] > a[t][1] or v[4] > a[t][4] or v[5] > a[t][5])}


def thread_ns(pids):
    """{tid: [comm, on-CPU ns]} of every thread of the server (schedstat), for the worker split of a run"""
    out = {}
    for pid in pids:
        try:
            for tid in os.listdir(f"/proc/{pid}/task"):
                try:
                    comm = open(f"/proc/{pid}/task/{tid}/comm").read().strip()
                    out[tid] = [comm, int(open(f"/proc/{pid}/task/{tid}/schedstat").read().split()[0])]
                except (OSError, ValueError, IndexError):
                    pass
        except OSError:
            pass
    return out


def client_pids(exclude, comm_prefix="wbench"):
    """pids of this driver's client children (the running client; targets excluded), from /proc/*/stat ppid and the
    command name (an arm's own client copy is named after its file: comm_prefix = its first 15 characters)"""
    me, out = os.getpid(), []
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) in exclude:
            continue
        try:
            st_ = open(f"/proc/{d}/stat").read()
            comm, rest = st_[st_.index("(") + 1:st_.rindex(")")], st_[st_.rindex(")") + 2:].split()
            if int(rest[1]) == me and comm.startswith(comm_prefix):
                out.append(int(d))
        except (OSError, ValueError, IndexError):
            continue
    return out


def cgroup_dir(pid):
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            for l in f:
                if l.startswith("0::"):
                    d = "/sys/fs/cgroup" + l[3:].strip()
                    return d if os.path.exists(os.path.join(d, "cpu.stat")) else None
    except OSError:
        pass
    return None


def proc_cpu_s(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            x = f.read().rsplit(")", 1)[1].split()
        return (int(x[11]) + int(x[12])) / HZ
    except (OSError, IndexError, ValueError):
        return None


def settle_tcp(limit=0.5):
    """host TCP memory has stopped falling: 3 reads 10 ms apart without a fall, at most `limit` s"""
    t0, last, still = time.time(), sample.tcp_mem_pages(), 0
    while time.time() - t0 < limit and still < 3:
        time.sleep(0.01)
        cur = sample.tcp_mem_pages()
        still = still + 1 if cur is None or last is None or cur >= last else 0
        last = cur
    return round(time.time() - t0, 3)


def split_rate(cell):
    """"echo:1:1:16384@r=20000" -> ("echo:1:1:16384", 20000.0); no "@r=" -> (cell, None); "@f=X" -> (base, None)"""
    base, _, r = cell.partition("@r=")
    return base.partition("@f=")[0], float(r) if r else None


def rate_frac(cell):
    """"rr:1:1@f=0.5" -> 0.5 (open loop at 0.5 x arm a's median closed-loop rate of rr:1:1 earlier in this session)"""
    _, _, f = cell.partition("@f=")
    return float(f) if f else None


def rate_problems(job):
    """80.04 (2026-11-20): every offered rate the job states must be a finite number > 0: a cell's "@r=R" and
    "@f=F", the job's "rate", a rate curve's "rates" (or its "fracs" when it has none). A rate of 0 would not run open
    loop at all (wb_args passes --rate only for a true rate): a closed-loop run under an open-loop name. The mode must be
    lat or curve (run() sends any other mode to curve(), past the curve check here). -> [problem], empty when valid. The rate an "@f=" cell resolves to is checked where it is known (Session.lat)"""
    pos = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v > 0
    bad = [] if job.get("mode") in ("lat", "curve") else [f"mode {job.get('mode')!r}: lat or curve"]  # run() sends any other mode to curve()
    for cell in dict.fromkeys([job["cell"], *(job.get("cells") or [])]):  # curve() runs job["cell"], lat() the cells
        for key in ("@r=", "@f="):
            _, sep, v = cell.partition(key)
            if sep:
                try:
                    x = float(v)
                except ValueError:
                    x = None
                if x is None or not pos(x):
                    bad.append(f"{cell}: {key[1:-1]}={v} must be a number > 0")
    if job.get("rate") is not None and not pos(job["rate"]):
        bad.append(f"rate {job['rate']!r} must be a number > 0 (none: closed loop)")
    c = job.get("curve") or {}
    if job.get("mode") == "curve" and c.get("axis", "rate") == "rate":
        if c.get("rates"):
            bad += [f"curve rate {r!r} must be a number > 0" for r in c["rates"] if not pos(r)]
        else:
            bad += [f"curve frac {f!r} must be a number > 0" for f in c.get("fracs") or [] if not pos(f)]
    return bad


def parse_cell(cell):
    f = split_rate(cell)[0].split(":")
    test, conns, streams = f[0], int(f[1]), int(f[2])
    size = int(f[3]) if len(f) > 3 else None
    return test, conns, streams, size


def ab_notes(path, off):
    """fw --auto-balance's own lines of one server (balance.rs, printed at --log-level debug only): the verdict of every
    judged trial (Keep / Noisy / Fell / Moved / Flat / Empty / NoMeasure) and the trials dropped or sent back before a
    verdict. -> None when the server printed none (any other arm, or no trial)"""
    try:
        with open(path, "rb") as f:
            f.seek(off)
            lines = [l for l in f.read().decode(errors="replace").splitlines() if "auto-balance: " in l]
    except OSError:
        return None
    if not lines:
        return None
    verdicts = [m.group(1) for m in (re.search(r" verdict=(\w+)", l) for l in lines) if m]
    return {"verdicts": verdicts, "kept": verdicts.count("Keep"), "dropped": sum(": dropped:" in l for l in lines),
            "back": sum(l.endswith(": back") or "back on the source" in l for l in lines),
            "naps": sum(" nap " in l for l in lines), "lines": len(lines)}


class Server:
    """one fresh server process of an arm (a transient scope with unit "scope")"""
    seq = 0

    def __init__(self, job, name, probe=None):
        self.job, self.name, self.probe = job, name, probe or {}
        self.p, self.pids, self.cg = None, [], None

    def start(self):
        job, arm = self.job, self.job["arms"][self.name]
        argv = pin_prefix(job, "server") + shlex.split(arm["cmd"].format(port=job["port"]))
        if job.get("unit", "scope") == "scope":
            Server.seq += 1
            unit = f"fw-mst-{job['sid'][:8]}-{Server.seq}"
            argv = ["systemd-run", "--scope", "--quiet", "--collect", "--unit", unit, "-p", "MemoryMax=3G", "--", *argv]
        t0 = time.time()
        self.p = proc.spawn(argv, log=os.path.join("out", "server.log"))
        if not proc.wait_port(int(job["port"]), 15, self.p):
            return f"server {self.name} did not accept on :{job['port']}"
        L, T = self.probe.get("listeners", 1), self.probe.get("threads", 1)
        while time.time() - t0 < 1.0:  # fast loop: every listener and thread of the probe start is there
            self.pids = sample.group_pids(self.p.pid)
            if listeners(int(job["port"])) >= L and threads(self.pids) >= T:
                break
            time.sleep(0.002)
        self.pids = sample.group_pids(self.p.pid)
        if self.p.poll() is not None or not self.pids:
            return f"server {self.name} exited at start"
        if job.get("unit", "scope") == "scope":
            self.cg = cgroup_dir(self.pids[0])
            if not self.cg:
                return f"server {self.name}: no cgroup with cpu.stat for pid {self.pids[0]}"
        return None

    def alive(self):
        return self.p is not None and self.p.poll() is None

    def stop(self):
        t0 = time.time()
        proc.stop(self.p, 0)
        if not proc.wait_free(int(self.job["port"]), 30):
            raise RuntimeError(f"port {self.job['port']} still has a listener 30 s after the server stopped")
        settle_tcp()
        return round(time.time() - t0, 3)

    def stop_old(self):
        """wispsuite/ab.py's stop: SIGKILL, 0.2 s, the port free (50 ms poll), 0.3 s"""
        t0 = time.time()
        proc.stop(self.p, 0)
        time.sleep(0.2)
        if not proc.wait_free(int(self.job["port"]), 30):
            raise RuntimeError(f"port {self.job['port']} still has a listener 30 s after the server stopped")
        time.sleep(0.3)
        return round(time.time() - t0, 3)


def probe(job, name):
    """start once, 0.5 s after the port accepts: the number of listeners on the port and of threads (the fast loop's
    readiness counts for this arm)"""
    s = Server(job, name)
    err = s.start()
    if err:
        proc.stop(s.p, 0)
        raise RuntimeError(err)
    time.sleep(0.5)
    pids = sample.group_pids(s.p.pid)
    out = {"listeners": listeners(int(job["port"])), "threads": threads(pids), "pids": len(pids), "cg": bool(s.cg)}
    s.stop()
    return out


def wb_args(job, name, cell, srv, dur, warmup, rate=None, drain=None):
    """wbench run arguments. An arm with "plain": true runs without any 80.04 flag (an old client can run it); one with
    "flags": [...] uses only those of lat / edges / src_port (the client-overhead check)"""
    test, conns, streams, size = parse_cell(cell)
    arm = job["arms"][name]
    flags = [] if arm.get("plain") else arm.get("flags", ["lat", "edges", "src_port"])
    tport = (job.get("tports") or {}).get(wbench.target_mode(test), job["tport"])
    a = ["--url", f"ws://127.0.0.1:{job['port']}/", "--target", f"127.0.0.1:{tport}", "--test", test,
         "--conns", conns, "--streams", streams, "--duration", dur, "--warmup", warmup]
    if size:
        a += ["--size", size]
    if "lat" in flags and test in ("echo", "rr", "churn"):
        a += ["--lat"]
    if "edges" in flags and test != "connchurn":  # connchurn refuses --edges / --src-port (a new connection per request)
        a += ["--edges"] + (["--cpu-cgroup", srv.cg] if srv.cg else ["--cpu-pids", ",".join(map(str, srv.pids))])
    if job.get("src_port") and "src_port" in flags and test != "connchurn":
        a += ["--src-port", job["src_port"]]
    if rate:
        a += ["--rate", rate, "--drain", drain if drain is not None else 1.0]
    if job.get("counts") and not arm.get("plain") and not arm.get("no_counts"):  # 80.04 --counts (a wbench that has it; timebox checks its --help)
        a += ["--counts"]
    return a + list(job["arms"][name].get("extra", []))


def conn_map(pids, port):
    """80.04 which server epoll instance (= worker, one epoll per worker thread) holds each client connection, read once
    from /proc while the run is in its window: [sorted client ports per epoll that holds any] (one entry per worker
    used). Server-side sockets = ESTABLISHED with local port `port` (/proc/net/tcp, tcp6); epoll members from
    /proc/<pid>/fdinfo/<epoll fd> "tfd:" lines. None when nothing could be read."""
    try:
        peer = {}
        for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                lines = open(fn).read().splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                f = line.split()
                if len(f) > 9 and f[3] == "01" and int(f[1].rsplit(":", 1)[1], 16) == port:
                    peer[f[9]] = int(f[2].rsplit(":", 1)[1], 16)
        out = []
        for pid in pids:
            fds = {}
            eps = []
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
                    info = open(f"/proc/{pid}/fdinfo/{ep}").read()
                except OSError:
                    continue
                ports = sorted(peer[fds[x]] for x in (l.split()[1] for l in info.splitlines() if l.startswith("tfd:"))
                               if x in fds and fds[x] in peer)
                if ports:
                    out.append(ports)
        return sorted(out)
    except (OSError, ValueError, IndexError):
        return None


class Session:
    def __init__(self, job):
        self.job = job
        self.wb = os.path.abspath(job["wbench"])
        self.raw = open(os.path.join("out", "raw.jsonl"), "a")
        self.tgts = {}
        self.n = 0

    def progress(self, msg):
        with open("PROGRESS", "a") as f:
            f.write(f"{utc()} {msg}\n")

    def stopped(self):
        dl = self.job.get("deadline")
        return os.path.exists("STOP") or (dl is not None and time.time() > dl)

    def run_one(self, name, cell, srv, dur, warmup, rate=None, drain=None, meta=None):
        """one wbench run against a started server -> the record (also written to raw.jsonl)"""
        job = self.job
        args = wb_args(job, name, cell, srv, dur, warmup, rate, drain)
        tgt = self.tgts[wbench.target_mode(parse_cell(cell)[0])]
        tc0 = proc_cpu_s(tgt.pid)
        wb = os.path.abspath(job["arms"][name].get("client") or self.wb)
        th0 = thread_ns(srv.pids)
        cmap = {}
        test = parse_cell(cell)[0]
        tm = None
        tm0 = None
        if test != "connchurn":  # which worker holds which connection (connchurn's connections are brief): "cmap0" early
            # in the warm-up (right after the connections are set up: the kernel's SO_REUSEPORT choice, exogenous to the
            # build), "cmap" mid-window (after any rebalancing, e.g. --auto-balance)
            want = int(parse_cell(cell)[1])

            def first_full():  # poll from the client's start: the FIRST map that holds every connection (set-up done,
                # load just starting; --auto-balance moves connections only after it saw load), with its time
                t_end, m = time.time() + min(2.0, float(warmup)), None
                while time.time() < t_end:
                    m = conn_map(srv.pids, int(job["port"]))
                    if m and sum(len(x) for x in m) >= want:
                        cmap.update(m0=m, t0_ms=round((time.time() - tw0) * 1000, 1))
                        return
                    time.sleep(0.002)
                cmap.update(m0_incomplete=m)
            tm0 = threading.Timer(0, first_full)
            every = float(job.get("cmap_every_ms") or 0) / 1000

            def mid_and_series():  # mid-window map; with cmap_every_ms also a series [[ms since the client start, map]]
                # from the set-up to the window's end (when each collision is resolved, e.g. --auto-balance)
                t_mid, t_end = tw0 + float(warmup) + float(dur) / 2, tw0 + float(warmup) + float(dur)
                # the client's own threads over the window (80.04: a saturated client thread limits a load point even
                # on its own cores): schedstat 50 ms after the window opens and 50 ms before it closes
                def cli_threads():
                    # wbench opens its window after the connection set-up: shift by the set-up time first_full saw
                    # (cmap0_ms; none for connchurn, or a set-up longer than the warm-up: then from the client start)
                    t0c = tw0 + float(warmup) + 0.05
                    stop_series.wait(max(0.0, t0c - time.time()))
                    shift = (cmap.get("t0_ms") or 0) / 1000
                    stop_series.wait(max(0.0, t0c + shift - time.time()))
                    tg = {p.pid for p in self.tgts.values()}
                    cp = client_pids(tg, os.path.basename(wb)[:15])
                    a0, ta = thread_ns(cp), time.time()
                    # 80.04: run-queue wait and context switches per thread of server, client and target over the window
                    s0 = {k: thread_sched(p) for k, p in (("srv", srv.pids), ("cli", cp), ("tgt", sorted(tg)))} if job.get("sched") else None
                    stop_series.wait(max(0.0, t_end + shift - 0.05 - time.time()))
                    b0, tb = thread_ns(client_pids(tg, os.path.basename(wb)[:15])), time.time()
                    if s0 is not None:
                        s1 = {k: thread_sched(p) for k, p in (("srv", srv.pids), ("cli", cp), ("tgt", sorted(tg)))}
                        cmap["sched"] = {"s": round(time.time() - ta, 4), **{k: sched_delta(s0[k], s1[k]) for k in s0}}
                    if tb > ta and a0:
                        cmap["cli_thr"] = {f"{v[0]}/{t}": round((v[1] - a0[t][1]) / 1e9 / (tb - ta), 3) for t, v in b0.items() if t in a0}
                tcli = threading.Thread(target=cli_threads, daemon=True)
                tcli.start()
                subs.append(tcli)
                ser = []
                while every and time.time() < t_end and not stop_series.is_set():
                    ser.append([round((time.time() - tw0) * 1000), conn_map(srv.pids, int(job["port"]))])
                    if "m" not in cmap and time.time() >= t_mid:
                        cmap["m"] = ser[-1][1]
                    stop_series.wait(every)
                if ser:
                    cmap["series"] = ser
                if "m" not in cmap and not stop_series.is_set():
                    stop_series.wait(max(0.0, t_mid - time.time()))
                    if not stop_series.is_set():
                        cmap["m"] = conn_map(srv.pids, int(job["port"]))
            stop_series = threading.Event()
            subs = []  # threads started by mid_and_series: joined before the record is written
            tm = threading.Thread(target=mid_and_series, daemon=True)
            tm0.daemon = True
        tw0 = time.time()
        if tm:
            tm0.start()
            tm.start()
        j = wbench.run(wb, args, float(dur) + float(warmup) + float(drain or 0) + 60, prefix=pin_prefix(job, "client"))
        d_run = round(time.time() - tw0, 3)
        if tm:
            tm0.cancel()
            stop_series.set()
            for x in (tm0, tm):
                x.join(5)
            for x in subs:
                x.join(5)
        tc1 = proc_cpu_s(tgt.pid)
        th1 = thread_ns(srv.pids)
        # per server thread: CPU ms over the whole client run (set-up and warm-up included): the worker split = the
        # SO_REUSEPORT hash mode of this run, for every arm (also a plain one or an old client)
        thr = {v[0] + "/" + t: round((v[1] - th0[t][1]) / 1e6, 1) for t, v in th1.items() if t in th0 and v[1] > th0[t][1]}
        win = float(dur) + float(warmup)
        # the target's CPU over the whole client run, scaled to the window (an estimate: the target is idle outside)
        tgt = (tc1 - tc0) * float(dur) / win if tc0 is not None and tc1 is not None and win > 0 else 0.0
        t = hoststate.tags(j.get("edges"), tgt, hoststate.cpu_mhz())
        rec = {"n": self.n, "arm": name, "label": job["arms"][name]["label"], "cell": cell, "rate": rate,
               "tw0": round(tw0, 3), "d_run": d_run, "client_fixed_s": round(d_run - win, 3),  # beyond the window (an open-loop run: its drain included)
               "srv_alive": srv.alive(), "thr": thr, "cmap0": cmap.get("m0"), "cmap0_ms": cmap.get("t0_ms"), "cmap": cmap.get("m"),
               "cmap_n": [sum(len(x) for x in (cmap.get(k) or [])) for k in ("m0", "m")],
               **({"cmap0_incomplete": cmap["m0_incomplete"]} if "m0_incomplete" in cmap else {}),
               **({"cmap_series": cmap["series"]} if "series" in cmap else {}),
               **({"sched": cmap["sched"]} if "sched" in cmap else {}),
               "cli_thr": cmap.get("cli_thr"), "tgt_cpu_s": round(tgt, 4), "tags": t, "bad": hoststate.bad(t, job.get("marks")), **(meta or {}), "j": j}
        self.n += 1
        self.raw.write(json.dumps(rec) + "\n")
        self.raw.flush()
        return rec

    def fresh_run(self, name, cell, dur, warmup, rate=None, meta=None):
        old = self.job["arms"][name].get("loop") == "old"
        slog = os.path.join("out", "server.log")
        off = os.path.getsize(slog) if os.path.exists(slog) else 0  # this server's lines start here (the log is appended)
        t0 = time.time()
        srv = Server(self.job, name, self.job["probe"][name])
        err = srv.start()
        if old and not err:  # 80.04: wispsuite/ab.py's loop: at least 0.5 s after the spawn before the client starts
            time.sleep(max(0.0, 0.5 - (time.time() - t0)))
        d_start = round(time.time() - t0, 3)
        try:
            if err:
                rec = {"n": self.n, "arm": name, "cell": cell, "rate": rate, "j": {"error": err}, **(meta or {})}
                self.n += 1
                self.raw.write(json.dumps(rec) + "\n")
                self.raw.flush()
                return rec
            rec = self.run_one(name, cell, srv, dur, warmup, rate, self.job.get("drain"), dict(meta or {}, t0=round(t0, 3), d_start=d_start))
        finally:
            d_stop = srv.stop_old() if old else srv.stop()
        st = {"n": self.n - 1, "d_stop": d_stop, "t1": round(time.time(), 3)}
        ab = ab_notes(slog, off)
        if ab:
            st["ab"] = ab
        try:  # every line this server printed (80.04: arms at --log-level debug; bare and --balance must print none extra)
            with open(slog, "rb") as f:
                f.seek(off)
                st["log_lines"] = f.read().count(b"\n")
        except OSError:
            pass
        with open(os.path.join("out", "stops.jsonl"), "a") as f:
            f.write(json.dumps(st) + "\n")
        return rec

    def lat(self):
        """every cell of job["cells"] (or job["cell"]) in turn: `rounds` rounds of every arm (random order per round)"""
        job, names = self.job, list(self.job["arms"])
        closed = {}  # base cell -> arm a's median closed-loop rps in this session (for "@f=X" cells)
        seen = set()  # (base cell, rate): the pairing key of the summary; a repeat would mix two cells' rounds
        for cell in job.get("cells") or [job["cell"]]:
            base, rate = split_rate(cell)
            rate = rate or job.get("rate")
            if rate_frac(cell):
                if base not in closed:
                    raise RuntimeError(f"{cell}: needs the closed-loop cell {base} earlier in the session")
                rate = round(rate_frac(cell) * closed[base])
                if rate < 1:  # 80.04: a rate of 0 would run closed loop (wb_args) under an open-loop name
                    raise RuntimeError(f"{cell}: {rate_frac(cell)} x the closed-loop {closed[base]:.1f}/s of {base} rounds to "
                                       f"{rate}/s: an open-loop rate must be at least 1/s")
                self.progress(f"{cell}: open loop at {rate}/s ({rate_frac(cell)} x {closed[base]:.0f})")
            if (base, rate) in seen:
                raise RuntimeError(f"{cell}: the same cell and rate ({base} at {rate}) as an earlier cell of the session")
            seen.add((base, rate))
            got = []
            for rnd in range(job.get("rounds", 8)):
                order = list(names)
                random.Random(f"{job.get('seed', 1)}-{cell}-{rnd}").shuffle(order)
                if self.stopped():  # only at a round boundary: every round on file is complete (all arms)
                    return False
                for slot, name in enumerate(order):
                    r = self.fresh_run(name, base, job["dur"], job["warmup"], rate, {"rnd": rnd, "slot": slot})
                    self.progress(f"lat {cell} rnd {rnd} {name} {short(r)}")
                    if name == names[0] and not rate and (r.get("j") or {}).get("rps"):
                        got.append(r["j"]["rps"])
            if got:
                closed[base] = sorted(got)[len(got) // 2]
        return True

    def curve(self):
        job, names, c = self.job, list(self.job["arms"]), self.job["curve"]
        axis = c.get("axis", "rate")
        test, conns, streams, size = parse_cell(job["cell"])
        if axis == "rate":
            rates = c.get("rates")
            if not rates:  # calibration: the closed-loop rate of every arm; steps = fracs x the highest
                best = []
                for name in names:
                    if self.stopped():  # the deadline counts for calibration runs too
                        return False
                    r = self.fresh_run(name, job["cell"], c.get("calib_dur", 2), c.get("warmup", 0.5), None, {"calib": True})
                    best.append(r["j"].get("rps") or 0)
                    self.progress(f"calib {name} {short(r)}")
                ref = max(best)
                if ref <= 0:
                    raise RuntimeError("calibration: no arm has a closed-loop rate")
                rates = [max(1, round(f * ref)) for f in c.get("fracs", [0.1, 0.25, 0.5, 0.7, 0.8, 0.9, 1.0, 1.15])]
                with open(os.path.join("out", "rates.json"), "w") as f:
                    json.dump({"ref_rps": ref, "calib": dict(zip(names, best)), "rates": rates}, f)
            steps = [(job["cell"], r) for r in rates]
            if len(set(rates)) != len(rates):  # two fracs that round to one rate: two steps under one name
                raise RuntimeError(f"curve: rates {rates} repeat a value")
        else:
            steps = [(f"{test}:{k}:{streams}" + (f":{size}" if size else ""), None) for k in c["conns"]]
        for sw in range(c.get("sweeps", 3)):
            order = list(names)
            random.Random(f"{job.get('seed', 1)}-sweep-{sw}").shuffle(order)
            if self.stopped():  # only at a sweep boundary
                return False
            for slot, name in enumerate(order):
                t0 = time.time()
                srv = Server(job, name, job["probe"][name])
                err = srv.start()
                d_start = round(time.time() - t0, 3)
                try:
                    if err:
                        raise RuntimeError(err)
                    res = []
                    for k, (cell, rate) in enumerate(steps):
                        r = self.run_one(name, cell, srv, c.get("dur", 3), c.get("warmup", 0.5), rate, c.get("drain", 1.0),
                                         {"sweep": sw, "slot": slot, "step": k, "d_start": d_start if k == 0 else 0})
                        self.progress(f"curve sw {sw} {name} step {k} {short(r)}")
                        res.append((rate, served(r)))
                        if not srv.alive():
                            break
                    # refine (axis rate): bisect between the last served step below the first unserved one and that
                    # one, on the same server; the knee of this sweep = the highest served rate below the lowest unserved
                    if axis == "rate" and srv.alive():
                        bad = [x for x, g in res if not g]
                        hi = min(bad) if bad else None
                        good = [x for x, g in res if g and (hi is None or x < hi)]
                        lo = max(good) if good else None
                        for i in range(c.get("refine", 3) if lo and hi else 0):
                            mid = round((lo + hi) / 2)
                            if not lo < mid < hi:  # (integer rates: the same as mid in (lo, hi)); a rate below 1 never rounds to 0
                                break
                            r = self.run_one(name, job["cell"], srv, c.get("dur", 3), c.get("warmup", 0.5), mid, c.get("drain", 1.0),
                                             {"sweep": sw, "slot": slot, "refine": i})
                            self.progress(f"curve sw {sw} {name} refine {i} {short(r)}")
                            lo, hi = (mid, hi) if served(r) else (lo, mid)
                            if not srv.alive():
                                break
                finally:
                    srv.stop()
        return True


def served(r):
    """an open-loop step is served: no error, nothing censored or dropped, achieved >= 98 % of the offered rate"""
    j = r.get("j") or {}
    o = j.get("ol") or {}
    rate = r.get("rate")
    return ("error" not in j and (j.get("errors") or 0) == 0 and "ol" in j and r.get("srv_alive", True) and rate is not None
            and not o.get("censored") and not o.get("dropped") and (j.get("rps") or 0) >= 0.98 * rate)


def short(r):
    j = r.get("j", {})
    if "error" in j:
        return "ERROR " + j["error"][:120]
    l = j.get("lat") or {}
    return f"rps={j.get('rps')} mib_down={j.get('mib_s_down')} p50={l.get('p50')} p99={l.get('p99')} bad={r.get('bad')}"


def check(job, sample_s=2.0):
    """the box at rest: no stray fw / finalwisp / wbench process, the job's ports free, CPU busy <= 10 % and steal
    <= 5 % over sample_s, TCP memory pressure not moving"""
    why = []
    mine = set(proc._ancestors()) | {os.getpid()}
    for d in filter(str.isdigit, os.listdir("/proc")):
        try:
            comm = open(f"/proc/{d}/comm").read().strip()
        except OSError:
            continue
        if int(d) not in mine and comm.startswith(tuple(job.get("stray_prefixes") or ("fw-", "finalwisp", "wbench"))):
            why.append(f"stray process {d} {comm}")
    n_tgt = len({wbench.target_mode(parse_cell(c)[0]) for c in job.get("cells") or [job["cell"]]})  # run(): one target per mode
    for p in (job["port"], *range(int(job["tport"]), int(job["tport"]) + n_tgt)):
        if listeners(int(p)) or udp_bound(int(p)):
            why.append(f"port {p} has a listener or a bound UDP socket")
    def st():
        x = [int(v) for v in open("/proc/stat").readline().split()[1:9]]
        return sum(x), x[3] + x[4], x[7]
    a, pa = st(), sample.tcp_pressure()
    time.sleep(sample_s)
    b, pb = st(), sample.tcp_pressure()
    tot = max(1, b[0] - a[0])
    busy, steal = 1 - (b[1] - a[1]) / tot, (b[2] - a[2]) / tot
    if busy > 0.10:
        why.append(f"CPU busy {busy:.2f}")
    if steal > 0.05:
        why.append(f"steal {steal:.2f}")
    if pa is not None and pb is not None and pa != pb:
        why.append("TCP memory pressure counter moving")
    return {"clean": not why, "why": why, "busy": round(busy, 3), "steal": round(steal, 4), "t": utc()}


PIDS = os.path.abspath("PIDS")


def pin_sets():
    """80.04 --pin split: separate CPUs for client, target and server on a many-core box (no sysctl, only affinity):
    the client gets the last physical core (all its hardware threads), the target the one before, the server every
    other allowed CPU. -> {"client": "a,b", "target": "c,d", "server": "list"} or None when fewer than 4 cores"""
    allowed = sorted(os.sched_getaffinity(0))
    groups = []
    for c in allowed:
        try:
            sib = open(f"/sys/devices/system/cpu/cpu{c}/topology/thread_siblings_list").read().strip()
        except OSError:
            sib = str(c)
        ids = set()
        for part in sib.split(","):
            lo, _, hi = part.partition("-")
            ids |= set(range(int(lo), int(hi or lo) + 1))
        g = tuple(sorted(ids & set(allowed)))
        if g not in groups:
            groups.append(g)
    groups.sort()
    if len(groups) < 4:
        return None
    cli, tgt = groups[-1], groups[-2]
    srv = [c for c in allowed if c not in cli and c not in tgt]
    j = lambda xs: ",".join(map(str, xs))
    return {"client": j(cli), "target": j(tgt), "server": j(srv)}


def pin_prefix(job, who):
    s = (job.get("pin_sets") or {}).get(who)
    return ["taskset", "-c", s] if s else []


def run(job):
    os.makedirs("out", exist_ok=True)
    for m in ("DONE", "FAILED", "REFUSED"):
        if os.path.exists(m):
            os.replace(m, f"{m}.old-{int(time.time())}")
    with open("PID", "w") as f:
        f.write(f"{os.getpid()}\n")
    # every process this session starts (servers, targets, clients) goes to PIDS: on a box without systemd (unit
    # "none": a container without systemd) the laptop side stops the session by these pidfiles and checks none of them is left
    _spawn = proc.spawn

    def spawn_rec(*a, **k):
        p = _spawn(*a, **k)
        with open(PIDS, "a") as f:
            f.write(f"{p.pid}\n")
        return p
    proc.spawn = spawn_rec
    proc.install_handlers()
    try:  # a preflight error (a malformed job) ends with a marker too, never silently
        bad = rate_problems(job)
        if bad:
            raise ValueError("; ".join(bad))
        c = check(job)
    except Exception as e:
        with open("FAILED", "w") as f:
            f.write(json.dumps({"t": utc(), "why": f"preflight {type(e).__name__}: {e}", "runs": 0}) + "\n")
        return 2
    with open(os.path.join("out", "check.json"), "w") as f:
        json.dump(c, f)
    if not c["clean"] and not job.get("force"):
        with open("REFUSED", "w") as f:
            f.write(json.dumps(c) + "\n")
        return 3
    s = Session(job)
    t0 = time.time()
    try:
        # one wbench target per mode the cells need, on tport, tport + 1, ... (job["tports"] = {mode: port})
        if job.get("pin") == "split":
            job["pin_sets"] = pin_sets()
            s.progress(f"pin {job['pin_sets']}")
            with open(os.path.join("out", "pin.json"), "w") as f:
                json.dump(job["pin_sets"], f)
        modes = sorted({wbench.target_mode(parse_cell(c)[0]) for c in job.get("cells") or [job["cell"]]})
        job["tports"] = {m: int(job["tport"]) + i for i, m in enumerate(modes)}
        for m, p in job["tports"].items():
            s.tgts[m] = wbench.start_target(s.wb, p, m, prefix=pin_prefix(job, "target"), log=os.path.join("out", f"target-{m}.log"))
        job["probe"] = {name: probe(job, name) for name in job["arms"]}
        with open(os.path.join("out", "probe.json"), "w") as f:
            json.dump(job["probe"], f)
        s.progress(f"probe {job['probe']}")
        full = s.lat() if job["mode"] == "lat" else s.curve()
        with open("DONE" if full else "FAILED", "w") as f:
            f.write(json.dumps({"t": utc(), "wall_s": round(time.time() - t0, 1), "runs": s.n, "full": full,
                                "why": None if full else "stopped (STOP file or deadline)"}) + "\n")
        return 0 if full else 2
    except Exception as e:  # the session ends with FAILED and the reason; the servers are stopped by proc's handlers
        with open("FAILED", "w") as f:
            f.write(json.dumps({"t": utc(), "why": f"{type(e).__name__}: {e}", "runs": s.n}) + "\n")
        return 2
    finally:
        for t in s.tgts.values():
            proc.stop(t, 0)
        proc.stop_all(0)


def main(argv):
    if len(argv) != 2 or argv[0] not in ("run", "check"):
        print(__doc__)
        return 2
    with open(argv[1]) as f:
        job = json.load(f)
    if argv[0] == "check":
        c = check(job)
        print(json.dumps(c))
        return 0 if c["clean"] else 3
    return run(job)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
