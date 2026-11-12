#!/usr/bin/env python3
# 30.11 soak driver: starts targets, two finalwisp instances (own scopes, MemoryMax=1G), the client
# helpers and the wbench workloads; samples every 10 s to samples.csv; probes every minute; stops
# everything at the end. Stdlib only. usage: soak.py RUN_DIR --minutes M --fw BINARY [--ho-offset K]
# 30.14 (pre-soak of master): servers log --metrics-interval lines (parsed into samples.csv, m_* columns), upmux
# workload + probe step (20.33), connchurn workload; half-open / dead-target helpers need the nft table
# (soak-nft.sh; checked at start; --no-halfopen / --no-deadtarget without it).
import argparse, contextlib, csv, json, os, random, resource, shutil, signal, socket, struct, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import common  # noqa: E402  (30.16: spawn_logged, smaps_breakdown)
ap = argparse.ArgumentParser()
ap.add_argument("run_dir")
ap.add_argument("--minutes", type=float, required=True)
ap.add_argument("--fw", required=True)
ap.add_argument("--wbench", default=os.path.join(HERE, "wbench"))
ap.add_argument("--certs", default=os.path.join(HERE, "certs"))
ap.add_argument("--ho-offset", type=int, default=0)
ap.add_argument("--abuse-every", type=float, default=30.0, help="minutes (randomized +-5)")
ap.add_argument("--first-abuse", type=float, default=5.0, help="minutes")
ap.add_argument("--quiet-every", type=float, default=60.0, help="minutes between quiet windows (0 = none)")
ap.add_argument("--quiet-len", type=float, default=5.0, help="minutes; only idle/slow/half-open/probes/canary run")
# 30.11 base-1.2 re-soak additions
ap.add_argument("--no-bench", action="store_true", help="no bench window after each quiet window")
ap.add_argument("--bench-every", type=int, default=1, help="bench window after every Nth quiet window")
ap.add_argument("--bench-reps", type=int, default=2, help="rounds of the 8 cells per bench window (each round shuffled)")
ap.add_argument("--bench-dur", type=float, default=8.0)
ap.add_argument("--fresh-fw", default=None, help="binary for the fresh server F (default: --fw)")
ap.add_argument("--cohort", type=int, default=200, help="idle connections kept for the whole run")
ap.add_argument("--no-deadtarget", action="store_true")
ap.add_argument("--no-halfopen", action="store_true", help="no half-open clients (needs the root nft table)")
ap.add_argument("--no-scope", action="store_true",
                help="30.16: no systemd user scope per server (Docker: no user manager); memory from /proc only. "
                     "Without MemoryMax the server's budget is the container limit or MemTotal/2 (memory levels rarely move)")
ap.add_argument("--plain", action="store_true",
                help="30.16: no kTLS on the box: B is a plain ws server too (SOAK_PLAIN=1 for every helper)")
ap.add_argument("--scale", type=int, default=1,
                help="30.16 heavy soak: connection counts x K (bulk cells up to 10 streams), idle holder 500K..min(3000K, "
                     "50k), slow readers 12 x min(K, 5), partial-frame burst 200K conns")
ap.add_argument("--mem-budget-b", default=None,
                help="30.16 heavy lane: --mem-budget for server B only (A stays the unbudgeted control), sized so B's memory "
                     "levels move under the scaled peaks; B's runs/probes that fail during a level episode are then "
                     "judged by the analyzer as degraded (0x49 / connection resets allowed), not as errors")
ap.add_argument("--wb-threads", type=int, default=2, help="30.16: wbench --threads per run")
ap.add_argument("--gap-scale", type=float, default=1.0, help="30.16: multiply every workload gap (light soak: 2-3)")
ap.add_argument("--tcp-safe", action="store_true",
                help="30.17 shared box: bulk workloads (dl, ul, kill, upmux, browse with bulk) in one lane, at most 1 conn x "
                     "2 streams; every wbench run waits while sockstat TCP mem > --tcp-gate x tcp_mem[1]; bench cells 1x1 "
                     "and 1x2; a 0.5 s monitor records the TCP peak and TcpExt TCPMemoryPressures and stops the soak at "
                     "--tcp-abort new pressure events")
ap.add_argument("--tcp-gate", type=float, default=0.3, help="30.17 --tcp-safe: share of tcp_mem[1] above which no run starts")
ap.add_argument("--tcp-abort", type=int, default=3, help="30.17 --tcp-safe: stop the soak after this many new pressure events")
ap.add_argument("--metrics-interval", type=int, default=10, help="server --metrics-interval (s); 0 = off")
ap.add_argument("--ho-every", type=float, nargs=2, default=None, help="30.17 half-open cycle gap s (helper default 480 720)")
ap.add_argument("--slow-n", type=int, default=None, help="30.17 slow readers (default 12 x min(K, 5))")
ap.add_argument("--slow-pause-share", type=float, default=None, help="30.17 share of slow readers that pause 3-10 min")
ap.add_argument("--dt-first", type=float, default=300, help="s before the first dead-target cycle")
ap.add_argument("--dt-hold", type=float, default=1500, help="s after the cut before the client closes open streams")
ap.add_argument("--dt-every", type=float, nargs=2, default=(600, 900))
a = ap.parse_args()

RUN = os.path.abspath(a.run_dir)
if not 1 <= a.scale <= 100:
    raise SystemExit("--scale must be 1..100")  # review: the idle range is capped at 50k connections
if a.plain:
    os.environ["SOAK_PLAIN"] = "1"  # inherited by every helper (wispc.PLAIN_ONLY)
os.makedirs(RUN, exist_ok=True)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))  # like systemd LimitNOFILE; not a sysctl
PY = sys.executable
STOP = threading.Event()
QUIET = threading.Event()  # set during a quiet window: no new wbench runs (canary excepted), no abuse
BENCH = threading.Event()  # set during a bench window: also no canary, no probes; idle/slow helpers SIGSTOPped
PAUSE_FILE = os.path.join(RUN, "pause")  # exists during a bench window: halfopen/deadtarget start no new cycle
inflight = [0]  # wbench runs + probe runs in progress (the bench window waits for 0)
T0 = time.time()
END = T0 + a.minutes * 60
rng = random.Random()
lock = threading.Lock()


def jlog(name, **kv):
    kv.setdefault("t", round(time.time(), 3))
    with lock:
        with open(os.path.join(RUN, name), "a") as f:
            f.write(json.dumps(kv) + "\n")


def event(kind, **kv):
    jlog("events.jsonl", kind=kind, **kv)
    print(time.strftime("%H:%M:%S"), kind, json.dumps(kv)[:300], flush=True)


# ---------------------------------------------------------------- processes
procs = {}  # name -> Popen (long-running)


def spawn(name, argv, log=None):
    out = open(os.path.join(RUN, log or f"{name}.log"), "ab")
    p = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         start_new_session=True, cwd=HERE)
    procs[name] = p
    return p


def wait_port(port, t=10, udp=False, host="127.0.0.1"):
    end = time.time() + t
    while time.time() < end:
        try:
            socket.create_connection((host, port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def kill_group(p, sig=signal.SIGTERM, wait=10):
    if p.poll() is not None:
        return p.returncode
    try:
        os.killpg(p.pid, sig)
    except ProcessLookupError:
        pass
    try:
        return p.wait(wait)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return p.wait(5)


TARGETS = {"echo": 7101, "sink": 7102, "source": 7103, "reply": 7104}
# 30.16 (gold smoke, K 25): every server->target connection to 127.0.0.1:7101 comes from 127.0.0.1, so they share one
# 4-tuple space of ~28k ephemeral ports (ip_local_port_range); churn's TIME_WAIT + the idle streams filled it and
# connect() failed (CLOSE 0x42 to rr/churn/probes). At scale the echo target also listens on 127.0.0.2..8 and the
# small-request workloads and idle streams spread over them (the servers allow all of 127/8 with --allow-loopback).
ECHO_HOSTS = ["127.0.0.1"] + ([f"127.0.0.{i}" for i in range(2, 9)] if a.scale > 1 else [])


def echo_target():
    return f"{rng.choice(ECHO_HOSTS)}:7101"
SERVERS = {
    "A": {"port": 7001, "args": ["--allow-loopback"], "tls": False},
    "B": {"port": 7002, "tls": True, "args": ["--allow-loopback", "--allow-private",
          "--tls-cert", os.path.join(a.certs, "cert.pem"), "--tls-key", os.path.join(a.certs, "key.pem")]},
}
if a.plain:  # 30.16: same flags as B without the certificate (CONNECTs to private addresses still allowed on B)
    SERVERS["B"].update(tls=False, args=["--allow-loopback", "--allow-private"])
if a.tcp_safe and a.scale != 1:
    sys.exit("--tcp-safe is for the light lane (--scale 1)")  # review: the caps assume K = 1
if a.mem_budget_b:
    if not a.no_scope:
        # review: the scope's MemoryMax=1G would OOM B before a larger budget's level 1; the light lane's
        # levels come from the scope limit itself
        sys.exit("--mem-budget-b needs --no-scope (scoped servers already have a 1G budget from MemoryMax)")
    SERVERS["B"]["args"] = SERVERS["B"]["args"] + ["--mem-budget", a.mem_budget_b]
server_gen = {"A": 0, "B": 0}


def scoped(argv, unit):
    """30.16: the server command in its own user scope (MemoryMax=1G), or bare with --no-scope"""
    if a.no_scope:
        return argv
    return ["systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}", "-p", "MemoryMax=1G",
            "-p", "MemorySwapMax=0"] + argv


def start_server(name):
    s = SERVERS[name]
    gen = server_gen[name]
    unit = f"soak-{name}-{int(time.time())}"
    # 60.60: the capabilities line (recorded below, read by analyze.py) is a debug line since v1.3.0; without
    # --log-conns debug adds no line per connection
    argv = scoped([a.fw, "--port", str(s["port"]), "--log-level", "debug"] + s["args"], unit)
    if a.metrics_interval > 0:
        argv += ["--metrics-interval", str(a.metrics_interval)]  # 30.14: counters + pool gauges (metrics.rs)
    s["log"] = os.path.join(RUN, f"server{name}.{gen}.log")
    s["log_off"] = 0
    s["level"] = 0
    s["metrics"] = {}  # 30.14: the last ev=metrics line of this generation (cumulative since its start)
    # 30.16: the log goes through a pipe to this process (its page cache is not charged to the server's scope)
    p = common.spawn_logged(argv, s["log"], start_new_session=True, cwd=HERE)
    procs[f"server{name}"] = p
    # review: pid and cgroup of the new generation are published together with the process (other threads read them)
    s["cg"] = None; s["pid"] = p.pid  # systemd-run --scope execs the command: same pid
    s["proc"] = p; s["unit"] = unit
    ok = wait_port(s["port"], 15)
    try:
        rel = open(f"/proc/{p.pid}/cgroup").read().strip().split("::", 1)[1]
        s["cg"] = None if a.no_scope else "/sys/fs/cgroup" + rel  # --no-scope: the cgroup is shared, not the server's
    except (OSError, IndexError):
        pass
    s["cpu_prev"] = None
    time.sleep(0.5)
    cap = [l.strip() for l in open(s["log"], errors="replace") if "capabilities" in l]
    event("server_start", server=name, gen=gen, pid=p.pid, unit=unit, cgroup=s["cg"], listening=ok,
          comm=open(f"/proc/{p.pid}/comm").read().strip() if ok else None, capability=cap[:1])
    return ok


def nft_active():
    """30.14: is the root nft table of soak-nft.sh loaded? A DSCP AF11 packet to port 7001 must be dropped (the
    helpers would otherwise make live, not dead, peers and every reap/dead-target result would be wrong)."""
    l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(("127.0.0.1", 7001)); l.listen()
    c = socket.create_connection(("127.0.0.1", 7001), timeout=5); s, _ = l.accept()
    try:
        c.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x28); c.send(b"x")
        s.settimeout(1.0)
        try:
            return not s.recv(1)
        except (socket.timeout, TimeoutError):
            return True  # dropped
    finally:
        # review: RST-close both ends (SO_LINGER 0): a FIN would be dropped by the table and leave a FIN_WAIT
        # socket on 127.0.0.1:7001 right before server A binds it
        for x in (c, s):
            x.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            x.close()
        l.close()


def start_all():
    for mode, port in TARGETS.items():
        spawn(f"t_{mode}", [a.wbench, "target", "--port", str(port), "--mode", mode, "--threads", "2"])
    for h in ECHO_HOSTS[1:]:  # 30.16 --scale: more echo targets on other loopback addresses (see ECHO_HOSTS)
        spawn(f"t_echo_{h}", [a.wbench, "target", "--bind", h, "--port", "7101", "--mode", "echo", "--threads", "2"])
    spawn("t_udp", [a.wbench, "target", "--port", "7105", "--mode", "udp-echo"])
    spawn("t_pattern", [PY, os.path.join(HERE, "pattern_target.py"), "7106"])
    for port in list(TARGETS.values()) + [7106]:
        if not wait_port(port):
            raise SystemExit(f"target {port} did not start")
    for h in ECHO_HOSTS[1:]:
        if not wait_port(7101, host=h):  # review (all): polled like the others (ECONNREFUSED returns at once)
            raise SystemExit(f"echo target {h}:7101 did not start")
    for n in SERVERS:
        if not start_server(n):
            raise SystemExit(f"server {n} did not start")


HELPERS = {
    "idle": lambda: [PY, os.path.join(HERE, "idle.py"), os.path.join(RUN, "idle.jsonl"), "--cohort", str(a.cohort)]
    + ([] if a.scale == 1 else  # 30.16: > 28k conns need more loopback source addresses; few streams (target ports)
       ["--min", str(min(500 * a.scale, 50000)), "--max", str(min(3000 * a.scale, 50000)), "--src-ips", "8",
        "--echo-hosts", ",".join(ECHO_HOSTS),
        "--streams", "0,0,0,1", "--max-arrivals", str(300 * min(a.scale, 10))]),
    "slow": lambda: [PY, os.path.join(HERE, "slow.py"), os.path.join(RUN, "slow.jsonl"),
                     "--n", str(a.slow_n if a.slow_n is not None else 12 * min(a.scale, 5))]
    + ([] if a.slow_pause_share is None else ["--pause-share", str(a.slow_pause_share)]),
    "halfopen": lambda: [PY, os.path.join(HERE, "halfopen.py"), os.path.join(RUN, "halfopen.jsonl"),
                         "--offset", str(a.ho_offset), "--pause-file", PAUSE_FILE,
                         "--reaps", os.path.join(RUN, "reaps.jsonl")]
    + ([] if a.ho_every is None else ["--every", str(a.ho_every[0]), str(a.ho_every[1])]),
}
if a.no_halfopen:
    del HELPERS["halfopen"]
if not a.no_deadtarget:
    HELPERS["deadtarget"] = lambda: [PY, os.path.join(HERE, "deadtarget.py"), os.path.join(RUN, "deadtarget.jsonl"),
                                     "--pause-file", PAUSE_FILE, "--first", str(a.dt_first), "--hold", str(a.dt_hold),
                                     "--every", str(a.dt_every[0]), str(a.dt_every[1])]


# ---------------------------------------------------------------- wbench workloads
counts = {}  # workload -> {"runs","ok","err","timeout","killed"}
last_lat = {}  # workload -> (p50_us, p99_us)
R = rng.randint
U = rng.uniform


def pick_server():
    return "A" if rng.random() < 0.75 else "B"


def wb_argv(test, server, target, conns, streams, dur, extra=()):
    s = SERVERS[server]
    url = f"{'wss' if s['tls'] else 'ws'}://127.0.0.1:{s['port']}/"
    return [a.wbench, "run", "--url", url, "--target", target, "--test", test, "--conns", str(conns),
            "--streams", str(streams), "--duration", f"{dur:.1f}", "--warmup", "0.5", "--json",
            "--threads", str(a.wb_threads)] + (["--insecure"] if s["tls"] else []) + list(extra)


def run_wbench(wl, argv, dur, kill_after=None):
    c = counts.setdefault(wl, {"runs": 0, "ok": 0, "err": 0, "timeout": 0, "killed": 0})
    if a.tcp_safe and wl in BULK_WL and not (wl == "browse" and "--bulk" in argv and argv[argv.index("--bulk") + 1] == "0"):
        with BULK_LANE:  # 30.17: one bulk run at a time
            tcp_gate()
            return _admitted(wl, argv, dur, kill_after, c)
    tcp_gate()
    return _admitted(wl, argv, dur, kill_after, c)


def _admitted(wl, argv, dur, kill_after, c):
    if STOP.is_set():
        return  # review: a pressure abort released the waiters
    if a.tcp_safe and QUIET.is_set() and wl != "canary":
        return  # 30.17: a quiet window opened while this run waited at the TCP gate / bulk lane
    if not admit():
        return  # a bench window opened between the loop's check and here: skip this run
    c["runs"] += 1
    try:
        _run_wbench(wl, argv, dur, kill_after, c)
    finally:
        release()


def _run_wbench(wl, argv, dur, kill_after, c):
    t0 = time.time()
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, text=True)
    try:
        out, _ = p.communicate(timeout=kill_after if kill_after else dur + 40)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        if kill_after:
            c["killed"] += 1
            jlog("wbench.jsonl", wl=wl, argv=argv[2:], rc="killed", s=round(time.time() - t0, 2))
            return
        c["timeout"] += 1
        jlog("wbench.jsonl", wl=wl, argv=argv[2:], rc="timeout", s=round(time.time() - t0, 2), out=out[-2000:])
        event("wbench_timeout", wl=wl, argv=argv[2:])
        return
    js = None
    for line in out.splitlines():
        if line.startswith("{"):
            try:
                js = json.loads(line)
            except ValueError:
                pass
    bad = p.returncode != 0 or js is None or js.get("errors", 0) > 0 or js.get("conns_ok", 0) < js.get("conns", 0)
    c["err" if bad else "ok"] += 1
    if js and js.get("p50_us"):
        last_lat[wl] = (js["p50_us"], js["p99_us"])
    rec = dict(wl=wl, argv=argv[2:], rc=p.returncode, s=round(time.time() - t0, 2), r=js)
    if bad:
        rec["out"] = out[-2000:]
    jlog("wbench.jsonl", **rec)


def wl_loop(wl, make, gap):
    time.sleep(U(0, 10))
    while not STOP.is_set() and time.time() < END:
        while ((QUIET.is_set() and wl != "canary") or BENCH.is_set()) and not STOP.is_set():
            STOP.wait(1)
        try:
            argv, dur, kill_after = make()  # review: inside the try, a bad make() must not end the thread
            run_wbench(wl, argv, dur, kill_after)
        except Exception as e:  # harness bug: record, keep going
            event("harness_error", wl=wl, err=repr(e))
        STOP.wait(U(*gap) * a.gap_scale)


def quiet_loop():
    """Every --quiet-every minutes a --quiet-len window: in-flight runs finish (<= ~70 s), then only the
    background clients run. The analyzer reads the floor (RSS, CPU, latency) from the last 3 min of each."""
    if a.quiet_every <= 0:
        return
    n = 0
    while not STOP.wait(max(0, T0 + (n + 1) * a.quiet_every * 60 - a.quiet_len * 60 - time.time())):
        if time.time() > END - a.quiet_len * 60:
            return
        n += 1
        QUIET.set(); event("quiet_start", n=n)
        STOP.wait(a.quiet_len * 60)
        if not STOP.is_set():
            floor_snapshot(n)
        if not a.no_bench and n % a.bench_every == 0 and not STOP.is_set():
            try:
                bench_window(n)
            except Exception as e:
                event("harness_error", where="bench", err=repr(e))
        QUIET.clear(); event("quiet_end", n=n)


def floor_snapshot(n):
    """30.16: at the end of each quiet window (the floor): smaps breakdown ([heap] = glibc main arena, other anon maps)
    + cgroup anon/kernel/file + pool gauges per server, to floors.jsonl. Reads /proc only (no server change)."""
    for name, s in SERVERS.items():
        if s["proc"].poll() is not None:
            continue
        rec = dict(n=n, h=round((time.time() - T0) / 3600, 3), server=name, gen=server_gen[name],
                   **common.smaps_breakdown(s["pid"]))
        if s["cg"]:
            ms = read_kv(s["cg"] + "/memory.stat")
            for k in ("anon", "kernel", "sock", "file"):
                rec["cg_" + k + "_kib"] = int(ms.get(k, 0)) >> 10
        for k in ("conns", "streams", "pool_dirty_kib", "pool_chunks"):
            rec["m_" + k] = s["metrics"].get(k)
        jlog("floors.jsonl", **rec)


BENCH_HELPERS = ("idle", "slow")  # SIGSTOPped during a bench window (the kernel still ACKs for them: live peers)


def signal_helpers(sig):
    for name in BENCH_HELPERS:
        p = procs.get(name)
        if p is not None and p.poll() is None:
            try:
                os.killpg(p.pid, sig)
            except ProcessLookupError:
                pass


def proc_cpu(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / CLK
    except (OSError, IndexError):
        return None


def bench_window(n):
    """30.11 re-soak: factorial {aged A, fresh F} x {aged target 7103, fresh target 7113} x {download 3x3, 4x4},
    --bench-reps rounds, each round in a new random order, everything else paused. F and the fresh target
    start for this window and stop after it (F in its own scope, same flags as A). Every cell is logged
    (rc "timeout"/"error" included); the analyzer checks the coverage."""
    fresh = []
    try:
        with lock:
            BENCH.set()  # under lock: run_wbench / probes admit only while BENCH is clear (admit())
        event("bench_start", n=n)
        end = time.time() + 120
        while inflight[0] > 0 and time.time() < end and not STOP.is_set():
            STOP.wait(0.5)
        waited_inflight = inflight[0]
        if waited_inflight:
            event("harness_error", where="bench", err=f"{waited_inflight} runs still in flight after 120 s: window skipped")
            return
        open(PAUSE_FILE, "w").close()
        signal_helpers(signal.SIGSTOP)
        fw = a.fresh_fw or a.fw
        unit = f"soak-F-{int(time.time())}"
        fresh.append(common.spawn_logged(scoped([fw, "--port", "7011", "--allow-loopback"], unit),
                                         os.path.join(RUN, f"serverF.{n}.log"), start_new_session=True))
        fresh.append(subprocess.Popen([a.wbench, "target", "--port", "7113", "--mode", "source", "--threads", "2"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True))
        fp = fresh[0]
        if not (wait_port(7011, 15) and wait_port(7113, 15)):
            event("harness_error", where="bench", err="fresh server/target did not listen")
            return
        STOP.wait(10)  # settle: SIGSTOPped helpers, drained queues
        pids = {"A": SERVERS["A"]["pid"], "F": fp.pid}
        sizes = (1, 2) if a.tcp_safe else (3, 4)  # 30.17 tcp-safe: cells 1x1 / 1x2 (conns 1, streams cs below)
        cells = [(srv, tgt, cs) for srv in ("A", "F") for tgt in ("aged", "fresh") for cs in sizes]
        est = None
        try:
            est = len(os.listdir(f"/proc/{pids['A']}/fd"))
        except OSError:
            pass
        for rnd in range(a.bench_reps):
            rng.shuffle(cells)
            for srv, tgt, cs in cells:
                if STOP.is_set():
                    return
                port = 7001 if srv == "A" else 7011
                target = "127.0.0.1:7103" if tgt == "aged" else "127.0.0.1:7113"
                # deliberate: --threads 2 here, not --wb-threads (the A/F cells stay comparable across runs and boxes)
                argv = [a.wbench, "run", "--url", f"ws://127.0.0.1:{port}/", "--target", target, "--test", "download",
                        "--conns", str(1 if a.tcp_safe else cs), "--streams", str(cs), "--duration", str(a.bench_dur), "--warmup", "1",
                        "--json", "--threads", "2"]
                tcp_gate()  # 30.17 (a no-op without --tcp-safe)
                if STOP.is_set():
                    return
                c0 = proc_cpu(pids[srv]); t0 = time.monotonic()
                js = None
                try:
                    p = subprocess.run(argv, capture_output=True, text=True, timeout=a.bench_dur + 40)
                    rc = p.returncode
                    js = next((json.loads(l) for l in p.stdout.splitlines() if l.startswith("{")), None)
                except subprocess.TimeoutExpired:
                    rc = "timeout"
                except (OSError, ValueError) as e:
                    rc = f"error: {e!r}"
                c1 = proc_cpu(pids[srv]); dt = time.monotonic() - t0
                jlog("bench.jsonl", n=n, h=round((time.time() - T0) / 3600, 3), round=rnd, server=srv, target=tgt,
                     cs=cs, conns=1 if a.tcp_safe else cs, rc=rc, mib_s=js and js.get("mib_s_down"), errors=js and js.get("errors"),
                     srv_cpu_pct=None if c0 is None or c1 is None else round(100 * (c1 - c0) / dt, 1),
                     a_fds=est, waited_inflight=waited_inflight)
    finally:
        for p in fresh:
            kill_group(p)
        signal_helpers(signal.SIGCONT)
        try:
            os.remove(PAUSE_FILE)
        except FileNotFoundError:
            pass
        BENCH.clear(); event("bench_end", n=n)


def admit():
    """30.11 re-soak: count a run as in flight only if no bench window is open (atomic with BENCH.set)."""
    with lock:
        if BENCH.is_set():
            return False
        inflight[0] += 1
        return True


def release():
    with lock:
        inflight[0] -= 1


# 30.17 --tcp-safe (shared box, VPS3: tcp_rmem max 32 MiB, one loopback download stream reached ~12k pages)
TCP_MEM1 = int(open("/proc/sys/net/ipv4/tcp_mem").read().split()[1]) if a.tcp_safe else 0  # review
STOP_REASON = [None]  # review: why STOP was set, if not a signal
MON_STOP = threading.Event()  # review: the monitor outlives STOP until the clients are gone
BULK_LANE = threading.Semaphore(1)
BULK_WL = {"dl", "ul", "kill", "upmux", "browse"}
tcp_state = {"peak": 0, "pressures0": None, "pressures": 0, "gated": 0}


def tcp_mem_pages():
    for line in open("/proc/net/sockstat"):
        if line.startswith("TCP:"):
            p = line.split()
            return int(p[p.index("mem") + 1])
    raise ValueError("sockstat: no TCP: line")  # review: never a silent 0 (the gate would open)


def tcp_pressures():
    l = [x for x in open("/proc/net/netstat") if x.startswith("TcpExt:")]
    return int(dict(zip(l[0].split(), l[1].split())).get("TCPMemoryPressures", 0))


def tcp_monitor():
    """30.17: every 0.5 s: the host TCP peak and new TcpExt pressure events; stop the soak at --tcp-abort events"""
    while not MON_STOP.is_set():
        try:
            m = tcp_mem_pages()
            if m > tcp_state["peak"]:
                tcp_state["peak"] = m
            if m > 0.4 * TCP_MEM1 and time.time() - tcp_state.get("high_t", 0) >= 10:
                tcp_state["high_t"] = time.time()  # 30.17 attribution: when host TCP was high (<= 1 per 10 s)
                event("tcp_high", tcp_mem=m, tcp_mem1=TCP_MEM1)
            n = tcp_pressures() - tcp_state["pressures0"]
            if n > tcp_state["pressures"]:
                tcp_state["pressures"] = n
                event("tcp_pressure", count=n, tcp_mem=m, tcp_mem1=TCP_MEM1)
                if n >= a.tcp_abort:
                    event("tcp_pressure_abort", count=n)
                    STOP_REASON[0] = "tcp_pressure_abort"
                    STOP.set()
        except (OSError, ValueError, IndexError) as e:
            event("harness_error", where="tcp_monitor", err=repr(e))  # the analyzer FAILs on harness errors
            STOP_REASON[0] = "tcp_monitor"
            STOP.set()  # review: an unmonitored shared box is not allowed: stop
            return
        MON_STOP.wait(0.5)


def tcp_gate():
    """30.17: wait (up to 10 min) while host TCP memory is above the gate; True = a wait happened"""
    if not a.tcp_safe:
        return False
    waited, end = False, time.time() + 600
    while tcp_mem_pages() > a.tcp_gate * TCP_MEM1 and time.time() < end and not STOP.is_set():
        waited = True
        STOP.wait(1)
    if waited:
        with lock:
            tcp_state["gated"] += 1
    return waited


def C(lo, hi, cap=None):
    """30.16 --scale K: a connection count R(lo, hi) x K (x min(K, cap) where a big K would only add client CPU)."""
    k = a.scale if cap is None else min(a.scale, cap)
    return R(lo, hi) * k


BULK_STREAMS = (1, 2) if a.tcp_safe else (1, 4) if a.scale == 1 else (1, 10)  # 30.17 tcp-safe: <= 2x2
BULK_CONNS = (1, 1) if a.tcp_safe else (1, 4)  # 30.17 smoke2: one 2x2 download alone reached ~60k pages  # 30.16: at scale the 10-stream cells (up to 100x10 at K 25)


def mk_dl():
    d = U(5, 30); s = pick_server()
    return wb_argv("download", s, "127.0.0.1:7103", C(*BULK_CONNS), R(*BULK_STREAMS), d), d, None


def mk_ul():
    d = U(5, 30); s = pick_server()
    return wb_argv("upload", s, "127.0.0.1:7102", C(*BULK_CONNS), R(*BULK_STREAMS), d), d, None


def mk_rr():
    d = U(5, 20)
    return wb_argv("rr", pick_server(), echo_target(), C(1, 16), R(1, 8), d), d, None


def mk_churn():
    d = U(5, 20)
    # review (all): the DNS branch (localhost = 127.0.0.1 only) keeps 1/2 of churn at K 1 and its share of one host at
    # scale, so the single 4-tuple space carries no more than the others
    tgt = "localhost:7101" if rng.random() < 0.5 / len(ECHO_HOSTS) else echo_target()
    # 30.16: x min(K, 8): each stream is a new target connection (TIME_WAIT on the target port space)
    return wb_argv("churn", pick_server(), tgt, C(1, 8, 8), R(1, 8), d), d, None


def mk_browse():
    d = U(10, 40)
    bulk = int(rng.random() < 0.3)
    extra = ["--page-gap-ms", str(R(0, 500)), "--bulk", str(bulk), "--bulk-size", str(8 << 20)]
    conns = 1 if a.tcp_safe and bulk else C(2, 12, 10)  # 30.17 review: <= 2 bulk streams
    return wb_argv("browse", pick_server(), "127.0.0.1:7104", conns, R(4, 20), d, extra), d, None


def mk_udp():
    d = U(5, 20)
    return wb_argv("udp-rr", pick_server(), "127.0.0.1:7105", C(1, 4), R(1, 8), d), d, None


def mk_upmux():
    """30.14 (20.33): interleaved small-packet uploads, 1 conn x 4-10 streams x 1-4 KiB DATA (per-target buckets)."""
    d = U(5, 20); s = pick_server()
    return wb_argv("upload", s, "127.0.0.1:7102", C(1, 1), R(4, 4) if a.tcp_safe else R(4, 10), d,
                   ["--size", str(rng.choice((1024, 2048, 4096)))]), d, None


def mk_connchurn():
    """30.14: a new WebSocket connection (TLS handshake on B) per request. (30.16: x min(K, 4): every loop uses a new
    client port per request)"""
    d = U(5, 15)
    return wb_argv("connchurn", pick_server(), echo_target(), C(1, 4, 4), R(1, 4), d), d, None


def mk_canary():
    return wb_argv("rr", "A", "127.0.0.1:7101", 1, 1, 5.0), 5.0, None


def mk_kill():
    test, tgt = rng.choice((("download", "127.0.0.1:7103"), ("upload", "127.0.0.1:7102"),
                            ("echo", "127.0.0.1:7101"), ("browse", "127.0.0.1:7104")))
    cs = (C(*BULK_CONNS), R(*BULK_STREAMS)) if a.tcp_safe else (C(1, 8), R(1, 8))  # 30.17
    return wb_argv(test, pick_server(), tgt, cs[0], cs[1], 60.0), 60.0, U(0.8, 8)


# gaps tuned in pilot1 (host CPU 88% mean with the first set) to leave headroom: mean ~60% busy
WORKLOADS = [("dl", mk_dl, (20, 120)), ("ul", mk_ul, (20, 120)), ("rr", mk_rr, (5, 45)), ("churn", mk_churn, (10, 60)),
             ("browse", mk_browse, (20, 90)), ("udp", mk_udp, (10, 60)), ("canary", mk_canary, (55, 55)),
             ("kill", mk_kill, (20, 90)), ("upmux", mk_upmux, (40, 150)), ("connchurn", mk_connchurn, (60, 180))]  # 30.14 (smoke: host CPU 73 % mean busy)


# ---------------------------------------------------------------- probes, abuse, DNS
probe_counts = {"A": [0, 0], "B": [0, 0]}  # runs, failures
last_probe = {}


def probe_loop():
    time.sleep(20)
    while not STOP.is_set() and time.time() < END:
        t_next = time.time() + 60
        while BENCH.is_set() and not STOP.is_set():
            STOP.wait(1)
        for n, s in SERVERS.items():
            argv = [PY, os.path.join(HERE, "probe.py"), "--port", str(s["port"])]
            argv += ["--tls"] if s["tls"] else []
            # B allows private targets (--allow-private): no 0x48 check there (30.16: B may be plain with --plain)
            argv += ["--expect-private", "skip" if "--allow-private" in s["args"] else "0x48"]
            if not admit():
                continue  # bench window: no probe now (the next minute's round runs after it)
            try:
                out = subprocess.run(argv, capture_output=True, text=True, timeout=150).stdout  # 30.14: + upmux 20 s
                r = json.loads(out.strip().splitlines()[-1])
            except Exception as e:
                r = {"ok": False, "fail": [f"probe harness: {e!r}"], "t": time.time()}
            finally:
                release()
            r["server"] = n
            probe_counts[n][0] += 1
            if not r.get("ok"):
                probe_counts[n][1] += 1
                event("probe_fail", server=n, fail=r.get("fail"))
            last_probe[n] = r
            jlog("probes.jsonl", **r)
        STOP.wait(max(1, t_next - time.time()))


abuse_counts = [0, 0]


def abuse_loop():
    STOP.wait(a.first_abuse * 60)
    i = 0
    while not STOP.is_set() and time.time() < END - 120:
        while (QUIET.is_set() or (a.tcp_safe and BENCH.is_set())) and not STOP.is_set():
            STOP.wait(1)
        mode = ("partial", "blackhole")[i % 2]
        lane = BULK_LANE if a.tcp_safe else contextlib.nullcontext()
        # 30.17 tcp-safe: the partial-frame burst parks ~100 MiB in socket buffers: not next to a bulk run
        with lane:
            tcp_gate()
            if STOP.is_set():
                break
            if QUIET.is_set() or BENCH.is_set():
                # review: a quiet/bench window opened while this burst waited for the lane or the gate: the
                # window must not see it; try again after the window
                continue
            i += 1
            try:
                out = subprocess.run([PY, os.path.join(HERE, "abuse.py"), mode, "--conns", str(200 * a.scale)],
                                     capture_output=True, text=True, timeout=180 + a.scale * 10)
                r = json.loads(out.stdout.strip().splitlines()[-1])
            except Exception as e:
                r = {"mode": mode, "ok": False, "fail": [f"abuse harness: {e!r}"]}
        abuse_counts[0] += 1
        if not r.get("ok"):
            abuse_counts[1] += 1
        jlog("abuse.jsonl", **r)
        event("abuse", **{k: r.get(k) for k in ("mode", "ok", "reasons", "missing", "conns", "sent_mib", "fail")})
        STOP.wait(a.abuse_every * 60 + U(-300, 300))


# ---------------------------------------------------------------- sampler
TCP_STATES = {"01": "estab", "02": "synsent", "03": "synrecv", "04": "finwait1", "05": "finwait2",
              "06": "timewait", "07": "close", "08": "closewait", "09": "lastack", "0A": "listen", "0B": "closing"}
CLK = os.sysconf("SC_CLK_TCK")
COLS = None


def read_kv(path, sep=None):
    out = {}
    try:
        for line in open(path):
            p = line.split(sep) if sep else line.split()
            if len(p) >= 2:
                out[p[0].rstrip(":")] = p[1]
    except OSError:
        pass
    return out


def proc_net_tcp():
    """inode -> (state, local port, remote port, txq, rxq)"""
    m = {}
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(f) as fh:
                next(fh)
                for line in fh:
                    p = line.split()
                    tx, rx = p[4].split(":")
                    m[p[9]] = (p[3], int(p[1].rsplit(":", 1)[1], 16), int(p[2].rsplit(":", 1)[1], 16),
                               int(tx, 16), int(rx, 16))
        except OSError:
            pass
    return m


def server_level(s):
    try:
        with open(s["log"], "rb") as f:
            f.seek(s["log_off"])
            data = f.read()
            data = data[:data.rfind(b"\n") + 1]  # 30.14: whole lines only (a half-written metrics line waits)
            s["log_off"] += len(data)
    except OSError:
        return s["level"]
    for line in data.decode("utf-8", "replace").splitlines():
        if " ev=metrics" in line:
            # 30.14: logfmt key=value (metrics.rs line()); numbers only, "na"/"unknown" kept as text
            s["metrics"] = dict(kv.split("=", 1) for kv in line.split()[1:] if "=" in kv)
            g = s["metrics"].get("level", "")
            if g.isdigit() and int(g) != s["level"]:
                # 30.16 review (all): the level gauge of the metrics line (every 10 s), in log order with the
                # "memory level" lines: changes that the server did not log (rate limit) still show here
                s["level"] = int(g)
                jlog("events.jsonl", kind="level_gauge", server=s.get("name"), level=int(g))
            continue
        if "memory level" in line:
            try:
                s["level"] = int(line.split("memory level", 1)[1].split("->")[1].split()[0])
            except (IndexError, ValueError):
                pass
            jlog("events.jsonl", kind="mem_level", server=s.get("name"), line=line.strip())
    return s["level"]


cpu_prev_host = None
try:
    HCG = "/sys/fs/cgroup" + open("/proc/self/cgroup").read().strip().split("::", 1)[1].rstrip("/")
    HCG = HCG if os.path.exists(HCG + "/memory.current") else None
except (OSError, IndexError):
    HCG = None
# 30.14: metrics.rs keys sampled per server (cumulative counters since the server's start, gauges at the last sweep)
METRIC_KEYS = ("up", "conns", "streams", "used_mib", "level_changes", "accepted", "connects", "dead_peers",
               "refuse_admit", "refuse_streams", "refuse_dns", "holds", "shed_pend", "shed_hold", "shed_over_credit",
               "shed_holder", "shed_client", "hs_expired", "tls_expired", "cap_apply", "accept_err_fd", "accept_err_mem",
               "cache_hit", "cache_miss", "pool_fallback", "pool_remote", "pool_madvise", "pool_munmap",
               "pool_madvise_fail", "pool_munmap_fail", "pool_capped", "pool_chunks", "pool_dirty_kib",
               "pool_release_max_us", "pool_release_cpu_max_us", "ktls_starve", "ktls_starve_end", "ktls_starve_read", "ktls_starve_slices",
               "ktls_starve_ms_max", "ktls_starve_conn_max", "host_tcp_pressures", "host_tcp_pressure_ms",
               "keyupdate_closes", "close_03", "close_41", "close_42", "close_43", "close_44", "close_48", "close_49")


def sample():
    global cpu_prev_host
    row = {"t": round(time.time(), 1), "min": round((time.time() - T0) / 60, 2), "quiet": int(QUIET.is_set()),
           "bench": int(BENCH.is_set())}
    tcp = proc_net_tcp()
    ho = {k: 0 for k in ("A_ho_idle", "A_ho_dl", "B_ho_idle", "B_ho_dl")}
    for st, lp, rp, _, _ in tcp.values():
        if st == "01" and lp in (7001, 7002) and 61000 <= rp < 63000:
            ho[("A" if lp == 7001 else "B") + ("_ho_idle" if rp < 62000 else "_ho_dl")] += 1
    row.update(ho)
    for n, s in SERVERS.items():
        s["name"] = n
        pid = s["pid"]; pre = n + "_"
        alive = s["proc"].poll() is None
        row[pre + "alive"] = int(alive)
        row[pre + "gen"] = server_gen[n]
        if not alive:
            continue
        st = read_kv(f"/proc/{pid}/status")
        row[pre + "rss_kib"] = int(st.get("VmRSS", "0"))
        row[pre + "hwm_kib"] = int(st.get("VmHWM", "0"))
        row[pre + "anon_kib"] = int(st.get("RssAnon", "0"))
        row[pre + "threads"] = int(st.get("Threads", "0"))
        try:
            f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
            cpu = (int(f[11]) + int(f[12])) / CLK
            now = time.monotonic()
            if s["cpu_prev"]:
                row[pre + "cpu_pct"] = round(100 * (cpu - s["cpu_prev"][0]) / (now - s["cpu_prev"][1]), 1)
            s["cpu_prev"] = (cpu, now)
            row[pre + "cpu_s"] = round(cpu, 1)
        except (OSError, IndexError):
            pass
        kinds = {"sock": 0, "pipe": 0, "eventfd": 0, "epoll": 0, "other": 0}
        states = {}
        txq = rxq = 0
        dt_socks = 0
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            fds = []
        for fd in fds:
            try:
                l = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if l.startswith("socket:["):
                kinds["sock"] += 1
                e = tcp.get(l[8:-1])
                if e:
                    dt_socks += e[2] == 7120
                    k = TCP_STATES.get(e[0], e[0])
                    states[k] = states.get(k, 0) + 1
                    txq += e[3]; rxq += e[4]
            elif l.startswith("pipe:"):
                kinds["pipe"] += 1
            elif "eventfd" in l:
                kinds["eventfd"] += 1
            elif "eventpoll" in l:
                kinds["epoll"] += 1
            else:
                kinds["other"] += 1
        row[pre + "fds"] = len(fds)
        for k, v in kinds.items():
            row[pre + "fd_" + k] = v
        for k in ("estab", "synsent", "closewait", "finwait1", "finwait2", "lastack", "timewait", "close"):
            row[pre + "tcp_" + k] = states.get(k, 0)
        row[pre + "txq_kib"] = txq >> 10; row[pre + "rxq_kib"] = rxq >> 10
        row[pre + "dt_socks"] = dt_socks  # 30.11 re-soak: server-owned target sockets to the dead-target helper
        if s["cg"]:
            try:
                row[pre + "cg_cur_kib"] = int(open(s["cg"] + "/memory.current").read()) >> 10
                ms = read_kv(s["cg"] + "/memory.stat")
                for k in ("anon", "file", "sock", "kernel", "slab", "inactive_file"):
                    row[pre + "cg_" + k + "_kib"] = int(ms.get(k, 0)) >> 10
                me = read_kv(s["cg"] + "/memory.events")
                if "oom_kill" in me:  # review: an unreadable file is a missing value, not a 0
                    row[pre + "cg_oom_kill"] = int(me["oom_kill"])
                    row[pre + "cg_max_ev"] = int(me.get("max", 0))
                row[pre + "cg_peak_kib"] = int(open(s["cg"] + "/memory.peak").read()) >> 10
            except (OSError, ValueError):
                pass
        row[pre + "level"] = server_level(s)
        m = s["metrics"]  # 30.14: fixed key list, so the first row (COLS) has every column even before a line came
        for k in METRIC_KEYS:
            row[pre + "m_" + k] = m.get(k, "")
    # host
    ss = {}
    for line in open("/proc/net/sockstat"):
        p = line.split()
        if p[0] in ("TCP:", "UDP:"):
            for k, v in zip(p[1::2], p[2::2]):
                ss[p[0][:-1].lower() + "_" + k] = int(v)
    for k in ("tcp_inuse", "tcp_orphan", "tcp_tw", "tcp_alloc", "tcp_mem", "udp_inuse", "udp_mem"):
        row["h_" + k] = ss.get(k, 0)
    mi = read_kv("/proc/meminfo")
    for k in ("MemAvailable", "Slab", "SUnreclaim", "AnonPages", "PageTables"):
        row["h_" + k] = int(mi.get(k, 0))
    row["h_files"] = int(open("/proc/sys/fs/file-nr").read().split()[0])
    # 30.16: the harness's own cgroup (with --no-scope also the servers'; in Docker the container): memory, OOM kills
    if HCG:
        try:
            row["h_cg_cur_kib"] = int(open(HCG + "/memory.current").read()) >> 10
            me = read_kv(HCG + "/memory.events")
            if "oom_kill" in me:
                row["h_cg_oom_kill"] = int(me["oom_kill"])
        except (OSError, ValueError):
            pass
    row["h_load1"] = float(open("/proc/loadavg").read().split()[0])
    c = [int(x) for x in open("/proc/stat").readline().split()[1:]]
    busy, total = sum(c) - c[3] - c[4], sum(c)
    if cpu_prev_host:
        row["h_cpu_pct"] = round(100 * (busy - cpu_prev_host[0]) / max(1, total - cpu_prev_host[1]), 1)
    cpu_prev_host = (busy, total)
    # workloads
    for wl, _, _ in WORKLOADS:
        cc = counts.get(wl, {})
        row[f"w_{wl}_ok"] = cc.get("ok", 0)
        row[f"w_{wl}_bad"] = cc.get("err", 0) + cc.get("timeout", 0)
    row["w_kill_killed"] = counts.get("kill", {}).get("killed", 0)
    for wl in ("canary", "rr", "churn", "browse", "udp"):
        row[f"{wl}_p50_us"], row[f"{wl}_p99_us"] = last_lat.get(wl, ("", ""))
    for n in SERVERS:
        row[f"probe_{n}_runs"], row[f"probe_{n}_fail"] = probe_counts[n]
        lp = last_probe.get(n, {})
        row[f"probe_{n}_ms"] = lp.get("ms", {}).get("total", "")
        row[f"probe_{n}_dl_mib_s"] = lp.get("dl_mib_s", "")
    row["abuse_runs"], row["abuse_fail"] = abuse_counts
    return row


def sampler_loop():
    global COLS
    path = os.path.join(RUN, "samples.csv")
    f = open(path, "a", newline="")
    w = None
    sample()  # primes the CPU deltas so the first row has every column (COLS comes from it)
    time.sleep(1)
    while not STOP.is_set():
        t_next = time.time() + 10
        try:
            row = sample()
            if COLS is None:
                COLS = list(row.keys()) + ["note"]
                w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
                w.writeheader()
            w.writerow(row); f.flush()
            st = {k: row.get(k) for k in ("min", "A_rss_kib", "A_fds", "A_cpu_pct", "A_level", "B_rss_kib", "B_fds",
                                          "B_level", "A_ho_idle", "A_ho_dl", "B_ho_idle", "B_ho_dl", "h_cpu_pct",
                                          "h_MemAvailable")}
            st.update(counts=counts, probes=probe_counts, abuse=abuse_counts, end_in_min=round((END - time.time()) / 60, 1))
            with open(os.path.join(RUN, "status.json.tmp"), "w") as sf:
                json.dump(st, sf)
            os.replace(os.path.join(RUN, "status.json.tmp"), os.path.join(RUN, "status.json"))
        except Exception as e:
            event("harness_error", where="sampler", err=repr(e))
        supervise()
        STOP.wait(max(0.5, t_next - time.time()))


def supervise():
    for n, s in SERVERS.items():
        rc = s["proc"].poll()
        if rc is not None and not STOP.is_set():
            s["proc"].pump.join(5)  # review: the piped log has the last lines (a panic message) before the tail is read
            tail = open(s["log"], "rb").read()[-3000:].decode("utf-8", "replace")
            event("server_died", server=n, gen=server_gen[n], rc=rc, log_tail=tail)
            server_gen[n] += 1
            start_server(n)
        if s["proc"].pump_err and not s.get("pump_err_logged"):
            s["pump_err_logged"] = True  # 30.16: the log is no longer written (the pipe is still drained)
            event("harness_error", where="log pump", server=n, err=s["proc"].pump_err)
    for name, mk in HELPERS.items():
        p = procs.get(name)
        if p is not None and p.poll() is not None and not STOP.is_set():
            event("helper_died", helper=name, rc=p.returncode)
            spawn(name, mk())


# ---------------------------------------------------------------- main
def stop_all(*_):
    STOP.set()


import atexit
atexit.register(lambda: signal_helpers(signal.SIGCONT))  # never leave a SIGSTOPped helper behind


signal.signal(signal.SIGTERM, stop_all)
signal.signal(signal.SIGINT, stop_all)
signal.signal(signal.SIGHUP, stop_all)
event("start", minutes=a.minutes, fw=a.fw, ho_offset=a.ho_offset, argv=sys.argv)


def net_admin():
    """30.16: CAP_NET_ADMIN (bit 12) in this process's effective set (a container without it cannot load nft)"""
    for line in open("/proc/self/status"):
        if line.startswith("CapEff:"):
            return bool(int(line.split()[1], 16) >> 12 & 1)
    return False


if ("halfopen" in HELPERS or "deadtarget" in HELPERS) and not nft_active():
    raise SystemExit("soak: the nft table is not loaded (as root: soak-nft.sh up), or pass --no-halfopen --no-deadtarget"
                     + ("" if net_admin() or os.geteuid() != 0 else
                        "; this process is root without CAP_NET_ADMIN (a container?): nft cannot be loaded here"))


def scope_ok():
    try:
        return subprocess.run(["systemd-run", "--user", "--scope", "--quiet", "true"], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


if not a.no_scope and not scope_ok():
    raise SystemExit("soak: systemd-run --user --scope failed (no user manager, e.g. Docker): pass --no-scope")
if a.tcp_safe:
    try:  # review: the pressure baseline before the servers and helpers start, or no run
        tcp_state["pressures0"] = tcp_pressures()
        tcp_mem_pages()
    except (OSError, ValueError, IndexError) as e:
        raise SystemExit(f"soak: --tcp-safe cannot read /proc/net/netstat or sockstat: {e!r}")
# review: the harness cgroup's OOM count before anything starts (the --no-scope OOM check compares against it)
event("hcg_oom_start", oom_kill=(read_kv(HCG + "/memory.events").get("oom_kill") if HCG else None))
try:
    start_all()
except SystemExit:
    for p in procs.values():  # review: no orphaned targets/servers after a failed start (own sessions)
        kill_group(p, wait=5)
    raise
for name, mk in HELPERS.items():
    spawn(name, mk())
threads = [threading.Thread(target=sampler_loop, daemon=True), threading.Thread(target=probe_loop, daemon=True),
           threading.Thread(target=abuse_loop, daemon=True), threading.Thread(target=quiet_loop, daemon=True)]
threads += [threading.Thread(target=wl_loop, args=w, daemon=True) for w in WORKLOADS]
if a.tcp_safe:
    mon = threading.Thread(target=tcp_monitor, daemon=True)
    mon.start()  # 30.17, before the workload threads
for t in threads:
    t.start()
while not STOP.is_set() and time.time() < END:
    STOP.wait(1)
event("stopping", reason=(STOP_REASON[0] or "signal") if STOP.is_set() else "time")
STOP.set()
signal_helpers(signal.SIGCONT)  # a stopped process would not act on SIGTERM
for name in HELPERS:
    if name in procs:
        kill_group(procs[name])
time.sleep(5)  # in-flight wbench runs end on their own (max ~70 s); probes finish
for t in threads:
    t.join(timeout=90)
sample()  # CPU deltas of the final sample cover only the quiet period below
time.sleep(30)  # idle: the idle sweep frees buffers
final = sample()  # last sample after the clients are gone (half-open ones stay)
jlog("final_sample.jsonl", **final)
for n, s in SERVERS.items():
    rc = kill_group(s["proc"], signal.SIGTERM, 45)  # 30.14: master drains up to 30 s, then logs ev=metrics_final
    s["proc"].pump.join(5)  # 30.16: the piped log has its last line
    event("server_stop", server=n, rc=rc)
for name, p in procs.items():
    if p.poll() is None:
        kill_group(p)
if a.tcp_safe:
    MON_STOP.wait(2)  # review: the last readings after the clients stopped, then the summary
    MON_STOP.set(); mon.join(5)
    event("tcp_summary", peak=tcp_state["peak"], tcp_mem1=TCP_MEM1, pressures=tcp_state["pressures"],
          gated=tcp_state["gated"])  # 30.17
event("done")
