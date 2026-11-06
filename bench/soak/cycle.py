#!/usr/bin/env python3
# 30.15 cycle test (30.14 watch 1): is the slow rise of the non-pool heap a leak or retained heap? A fresh A (plain) +
# B (wss) pair, then N identical cycles: a fixed mix for --mix-s seconds (bulk lane, small-request lane, idle holder,
# one partial-frame burst, one probe per server), then --idle-s seconds with no client. Per cycle the idle floor
# (cgroup anon, RSS, memory.current, pool gauges; median of the last --floor-s seconds) goes to cycles.jsonl; a
# linear rise per cycle = leak, a plateau = retention. Host TCP memory is kept low on purpose (shared box): the mix is
# small and no run starts while sockstat TCP mem > --tcp-gate x tcp_mem[1]; the peak and TcpExt TCPMemoryPressures
# are recorded per cycle. Uses the soak ports, targets and helpers (probe.py, abuse.py, wispc.py); stdlib only.
# 30.16: server logs go through a pipe (not charged to the scope); smaps breakdown per floor (sm_* keys).
# usage: cycle.py RUN_DIR --fw BINARY [--cycles 20] ; cycle.py RUN_DIR --analyze
import argparse, csv, json, os, random, resource, signal, socket, statistics, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ap = argparse.ArgumentParser()
ap.add_argument("run_dir")
ap.add_argument("--fw")
ap.add_argument("--wbench", default=os.path.join(HERE, "wbench"))
ap.add_argument("--certs", default=os.path.join(HERE, "certs"))
ap.add_argument("--cycles", type=int, default=20)
ap.add_argument("--mix-s", type=float, default=300)
ap.add_argument("--idle-s", type=float, default=60)
ap.add_argument("--floor-s", type=float, default=30)
ap.add_argument("--idle-a", type=int, default=400, help="idle connections held on A during the mix")
ap.add_argument("--idle-b", type=int, default=150)
ap.add_argument("--tcp-gate", type=float, default=0.5, help="no run starts above this share of tcp_mem[1]")
ap.add_argument("--analyze", action="store_true")
ap.add_argument("--floor-hook", default=None,
                help="30.17: command run at each floor after the floor sample, with args: CYCLE A=PID B=PID (e.g. "
                     "'python3 heapsnap.py DIR'; servers idle; timeout 150 s)")
a = ap.parse_args()
RUN = os.path.abspath(a.run_dir)


def theil_sen(xs, ys):
    sl = [(ys[j] - ys[i]) / (xs[j] - xs[i]) for i in range(len(xs)) for j in range(i + 1, len(xs)) if xs[j] != xs[i]]
    return statistics.median(sl) if sl else None


def analyze():
    cy = [json.loads(l) for l in open(os.path.join(RUN, "cycles.jsonl"))]
    rng = random.Random(1)
    out = ["# cycle test: idle floor per cycle (cycle 1 = warm-up, excluded from the fits)", ""]
    keys = [k for k in cy[0] if k[:2] in ("A_", "B_") and isinstance(cy[0][k], (int, float))]
    out.append("| cycle | " + " | ".join(keys) + " | tcp_mem_peak | pressures |")
    out.append("|---|" + "---|" * (len(keys) + 2))
    for c in cy:
        out.append(f"| {c['cycle']} | " + " | ".join(f"{c[k]:,.0f}" if k in c else "" for k in keys) + f" | {c['tcp_mem_peak']} | {c['pressures']} |")
    out += ["", "Theil-Sen slope per cycle (cycles 2..N), 95 % bootstrap over cycles; halves = median of cycles 2..k vs k+1..N"]
    for k in keys:
        fit = [c for c in cy if c["cycle"] >= 2 and k in c]  # review: a cycle without the key is skipped
        xs = [c["cycle"] for c in fit]; ys = [c[k] for c in fit]
        if len(xs) < 4:
            continue
        s = theil_sen(xs, ys); bs = []
        for _ in range(2000):
            idx = [rng.randrange(len(xs)) for _ in xs]
            if len(set(xs[i] for i in idx)) >= 3:
                bs.append(theil_sen([xs[i] for i in idx], [ys[i] for i in idx]))
        bs.sort(); h = len(ys) // 2
        s1 = theil_sen(xs[:h], ys[:h]); s2 = theil_sen(xs[h:], ys[h:])
        out.append(f"- {k}: {s:+,.1f}/cycle [{bs[int(.025 * len(bs))]:+,.1f}, {bs[int(.975 * len(bs))]:+,.1f}]; first half "
                   f"{s1:+,.1f}/cycle, second half {s2:+,.1f}/cycle; median {statistics.median(ys[:h]):,.0f} -> "
                   f"{statistics.median(ys[h:]):,.0f}; first {ys[0]:,.0f} last {ys[-1]:,.0f}")
    bad = sum(c["wb_bad"] for c in cy); pf = sum(c["probe_fail"] for c in cy)
    out += ["", f"wbench runs {sum(c['wb_runs'] for c in cy)}, bad {bad}; probes failed {pf}; idle opened "
            f"{sum(c['idle_opened'] for c in cy)}, idle open failures {sum(c['idle_fail'] for c in cy)}; abuse not ok "
            f"{sum(1 for c in cy if not c['abuse_ok'])}; host TCP mem peak {max(c['tcp_mem_peak'] for c in cy)} pages "
            f"(tcp_mem[1] {cy[0]['tcp_mem1']}); TcpExt pressures during the test {sum(c['pressures'] for c in cy)}; "
            f"runs delayed by the TCP gate {sum(c['gated'] for c in cy)}"]
    open(os.path.join(RUN, "cycles.md"), "w").write("\n".join(out) + "\n")
    print("\n".join(out))


if a.analyze:
    analyze(); sys.exit(0)
if not a.fw:
    sys.exit("--fw is required")
os.makedirs(RUN, exist_ok=True)
if os.path.exists(os.path.join(RUN, "cycles.jsonl")):
    sys.exit(f"{RUN} has a cycles.jsonl: use a new run dir (review: two runs must not be fitted as one)")
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
from wispc import Wisp, Closed  # noqa: E402
import common  # noqa: E402

PY = sys.executable
STOP = threading.Event()
lock = threading.Lock()
procs = []
TCP_MEM = [int(x) for x in open("/proc/sys/net/ipv4/tcp_mem").read().split()]


def jlog(fname, **kv):
    kv.setdefault("t", round(time.time(), 3))
    with lock:
        with open(os.path.join(RUN, fname), "a") as f:
            f.write(json.dumps(kv) + "\n")


def event(kind, **kv):
    jlog("events.jsonl", kind=kind, **kv)
    print(time.strftime("%H:%M:%S"), kind, json.dumps(kv)[:300], flush=True)


def spawn(argv, log):
    p = subprocess.Popen(argv, stdout=open(os.path.join(RUN, log), "ab"), stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True, cwd=HERE)
    procs.append(p)
    return p


def wait_port(port, t=15):
    end = time.time() + t
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def kill_group(p, sig=signal.SIGTERM, wait=45):
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


SERVERS = {"A": {"port": 7001, "tls": False, "args": ["--allow-loopback"]},
           "B": {"port": 7002, "tls": True, "args": ["--allow-loopback", "--allow-private", "--tls-cert",
                                                     os.path.join(a.certs, "cert.pem"), "--tls-key",
                                                     os.path.join(a.certs, "key.pem")]}}


def fail_start(msg):
    for p in procs:  # review: no orphans that a later run would find listening
        kill_group(p, wait=5)
    sys.exit(msg)


def start():
    for mode, port in (("echo", 7101), ("sink", 7102), ("source", 7103), ("reply", 7104)):
        spawn([a.wbench, "target", "--port", str(port), "--mode", mode, "--threads", "2"], f"t_{mode}.log")
    spawn([a.wbench, "target", "--port", "7105", "--mode", "udp-echo"], "t_udp.log")
    spawn([PY, os.path.join(HERE, "pattern_target.py"), "7106"], "t_pattern.log")
    for port in (7101, 7102, 7103, 7104, 7106):
        if not wait_port(port):
            fail_start(f"target {port} did not start")
    for n, s in SERVERS.items():
        argv = ["systemd-run", "--user", "--scope", "--quiet", f"--unit=cycle-{n}-{int(time.time())}", "-p",
                "MemoryMax=1G", "-p", "MemorySwapMax=0", a.fw, "--port", str(s["port"]), "--metrics-interval", "5"]
        s["log"] = os.path.join(RUN, f"server{n}.log"); s["off"] = 0; s["m"] = {}
        # 30.16: log through a pipe to this process: its page cache is not charged to the server's scope
        s["proc"] = common.spawn_logged(argv + s["args"], s["log"], start_new_session=True, cwd=HERE)
        procs.append(s["proc"])
        if not wait_port(s["port"]):
            fail_start(f"server {n} did not start")
        s["cg"] = "/sys/fs/cgroup" + open(f"/proc/{s['proc'].pid}/cgroup").read().strip().split("::", 1)[1]
        time.sleep(0.5)  # review: the capability line comes after listen, through the log pipe
        cap = [l.strip() for l in open(s["log"], errors="replace") if "capabilities" in l]
        event("server_start", server=n, pid=s["proc"].pid, cgroup=s["cg"], capability=cap[:1])


def kv(path):
    out = {}
    try:
        for line in open(path):
            p = line.split()
            if len(p) >= 2:
                out[p[0].rstrip(":")] = p[1]
    except OSError:
        pass
    return out


def metrics(s):
    with open(s["log"], "rb") as f:
        f.seek(s["off"]); d = f.read()
    d = d[:d.rfind(b"\n") + 1]; s["off"] += len(d)
    for line in d.decode("utf-8", "replace").splitlines():
        if " ev=metrics" in line:
            s["m"] = dict(x.split("=", 1) for x in line.split()[1:] if "=" in x)
    return s["m"]


def tcp_mem_pages():
    for line in open("/proc/net/sockstat"):
        if line.startswith("TCP:"):
            p = line.split()
            return int(p[p.index("mem") + 1])
    return 0


def pressures():
    l = [x for x in open("/proc/net/netstat") if x.startswith("TcpExt:")]
    d = dict(zip(l[0].split(), l[1].split()))
    return int(d.get("TCPMemoryPressures", 0))


MK = ("conns", "streams", "pool_dirty_kib", "pool_chunks", "pool_release_max_us", "pool_release_cpu_max_us",
      "pool_fallback", "pool_capped",
      "dead_peers", "level", "ktls_starve")
COLS = None
cyc_state = {"cycle": 0, "phase": "start", "tcp_peak": 0}


def sample():
    row = {"t": round(time.time(), 1), "cycle": cyc_state["cycle"], "phase": cyc_state["phase"]}
    for n, s in SERVERS.items():
        if s["proc"].poll() is not None:
            continue  # review: a dead server's scope is gone; the other one is still sampled
        pid = s["proc"].pid
        st = kv(f"/proc/{pid}/status")
        row[n + "_rss_kib"] = int(st.get("VmRSS", 0)); row[n + "_threads"] = int(st.get("Threads", 0))
        try:
            row[n + "_fds"] = len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            row[n + "_fds"] = ""
        ms = kv(s["cg"] + "/memory.stat")
        row[n + "_cg_cur_kib"] = int(open(s["cg"] + "/memory.current").read()) >> 10
        for k in ("anon", "sock", "kernel", "file"):
            row[n + "_cg_" + k + "_kib"] = int(ms.get(k, 0)) >> 10
        me = kv(s["cg"] + "/memory.events")
        row[n + "_oom"] = int(me.get("oom_kill", 0)); row[n + "_max_ev"] = int(me.get("max", 0))
        m = metrics(s)
        for k in MK:
            row[n + "_m_" + k] = m.get(k, "")
    for n, s in SERVERS.items():
        if s["proc"].pump_err and not s.get("pump_err_logged"):
            s["pump_err_logged"] = True  # 30.16: the log is no longer written (the pipe is still drained)
            event("harness_error", where="log pump", server=n, err=s["proc"].pump_err)
    row["h_tcp_mem"] = tcp_mem_pages(); row["h_pressures"] = pressures()
    row["h_load1"] = float(open("/proc/loadavg").read().split()[0])
    cyc_state["tcp_peak"] = max(cyc_state["tcp_peak"], row["h_tcp_mem"])
    return row


samples = []


def sampler():
    global COLS
    f = open(os.path.join(RUN, "samples.csv"), "a", newline="")
    w = None
    while not STOP.is_set():
        t1 = time.time() + 2
        try:
            r = sample()
            if w is None:
                COLS = list(r); w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore"); w.writeheader()
            w.writerow(r); f.flush()
            with lock:
                samples.append(r)
        except Exception as e:  # the main loop checks liveness separately
            event("harness_error", where="sampler", err=repr(e))
        STOP.wait(max(0.2, t1 - time.time()))


# ---------------------------------------------------------------- the fixed mix
def wb(test, srv, target, conns, streams, dur, extra=()):
    s = SERVERS[srv]
    url = f"{'wss' if s['tls'] else 'ws'}://127.0.0.1:{s['port']}/"
    return [a.wbench, "run", "--url", url, "--target", target, "--test", test, "--conns", str(conns), "--streams",
            str(streams), "--duration", str(dur), "--warmup", "0.5", "--json", "--threads", "2"] + \
           (["--insecure"] if s["tls"] else []) + list(extra)


# (name, argv, kill_after or None). Same list every cycle; durations sum to < mix-s per lane.
BULK = [("dl_A", wb("download", "A", "127.0.0.1:7103", 2, 2, 20), None),
        ("ul_A", wb("upload", "A", "127.0.0.1:7102", 2, 2, 20), None),
        ("upmux_A", wb("upload", "A", "127.0.0.1:7102", 1, 8, 20, ["--size", "1024"]), None),
        ("dl_B", wb("download", "B", "127.0.0.1:7103", 2, 2, 20), None),
        ("ul_B", wb("upload", "B", "127.0.0.1:7102", 2, 2, 20), None),
        ("upmux_B", wb("upload", "B", "127.0.0.1:7102", 1, 6, 20, ["--size", "4096"]), None),
        ("browse_A", wb("browse", "A", "127.0.0.1:7104", 4, 8, 25, ["--page-gap-ms", "100", "--bulk", "1",
                                                                      "--bulk-size", str(8 << 20)]), None),
        ("browse_B", wb("browse", "B", "127.0.0.1:7104", 2, 8, 20, ["--page-gap-ms", "100"]), None),
        ("kill_dl_A", wb("download", "A", "127.0.0.1:7103", 2, 2, 60), 3.0),
        ("kill_ul_B", wb("upload", "B", "127.0.0.1:7102", 2, 2, 60), 3.0)]
SMALL = [("rr_A", wb("rr", "A", "127.0.0.1:7101", 8, 4, 15), None),
         ("churn_A", wb("churn", "A", "localhost:7101", 4, 4, 15), None),
         ("connchurn_A", wb("connchurn", "A", "127.0.0.1:7101", 2, 2, 15), None),
         ("udp_A", wb("udp-rr", "A", "127.0.0.1:7105", 2, 4, 15), None),
         ("rr_B", wb("rr", "B", "127.0.0.1:7101", 4, 4, 15), None),
         ("churn_B", wb("churn", "B", "127.0.0.1:7101", 2, 4, 15), None),
         ("connchurn_B", wb("connchurn", "B", "127.0.0.1:7101", 2, 2, 15), None),
         ("udp_B", wb("udp-rr", "B", "127.0.0.1:7105", 2, 2, 15), None)]


def gate(c):
    """wait while the host is above the TCP gate (bounded: 60 s, then run anyway and count it)"""
    end = time.time() + 60
    waited = False
    while tcp_mem_pages() > a.tcp_gate * TCP_MEM[1] and time.time() < end and not STOP.is_set():
        waited = True; STOP.wait(0.5)
    if waited:
        c["gated"] += 1


def run_one(c, name, argv, kill_after):
    gate(c)
    t0 = time.time()
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=kill_after or 80)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL); out, _ = p.communicate()
        if kill_after:
            jlog("wbench.jsonl", cycle=c["cycle"], name=name, rc="killed"); return
        out = out or ""; rc = "timeout"
    else:
        rc = p.returncode
    js = next((json.loads(l) for l in out.splitlines() if l.startswith("{")), None)
    bad = rc != 0 or js is None or js.get("errors", 0) > 0 or js.get("conns_ok", 0) < js.get("conns", 0)
    with lock:
        c["wb_runs"] += 1; c["wb_bad"] += bad
    jlog("wbench.jsonl", cycle=c["cycle"], name=name, rc=rc, s=round(time.time() - t0, 1), r=js,
         **({"out": out[-1500:]} if bad else {}))
    if bad:
        event("wbench_bad", cycle=c["cycle"], name=name, rc=rc)


def lane(c, runs, extra=None):
    for name, argv, k in runs:
        if STOP.is_set():
            return  # review: a stop ends the mix (no new runs)
        try:
            run_one(c, name, argv, k)
        except Exception as e:  # a harness bug must show up, not end the lane silently
            c["wb_bad"] += 1; event("harness_error", cycle=c["cycle"], name=name, err=repr(e))
    if extra:
        try:
            extra(c)
        except Exception as e:
            c["probe_fail"] += 1; event("harness_error", cycle=c["cycle"], where="extra", err=repr(e))


def probes(c):
    for n, s in SERVERS.items():
        argv = [PY, os.path.join(HERE, "probe.py"), "--port", str(s["port"])]
        argv += ["--tls", "--expect-private", "skip"] if s["tls"] else ["--expect-private", "0x48"]
        try:
            r = json.loads(subprocess.run(argv, capture_output=True, text=True, timeout=150).stdout.strip().splitlines()[-1])
        except Exception as e:
            r = {"ok": False, "fail": [f"probe harness: {e!r}"]}
        r.update(cycle=c["cycle"], server=n); jlog("probes.jsonl", **r)
        if not r.get("ok"):
            c["probe_fail"] += 1; event("probe_fail", cycle=c["cycle"], server=n, fail=r.get("fail"))


def abuse(c):
    try:
        r = json.loads(subprocess.run([PY, os.path.join(HERE, "abuse.py"), "partial"], capture_output=True, text=True,
                                      timeout=120).stdout.strip().splitlines()[-1])
    except Exception as e:
        r = {"ok": False, "fail": [repr(e)]}
    r["cycle"] = c["cycle"]; jlog("abuse.jsonl", **r); c["abuse_ok"] = bool(r.get("ok"))


def idle_hold(c, done):
    """--idle-a / --idle-b connections, each with one echo stream (one echo checked), held until `done`; then closed
    (half FIN, half RST)."""
    held = []
    for n, cnt in (("A", a.idle_a), ("B", a.idle_b)):
        for i in range(cnt):
            if done.is_set():
                break
            try:
                w = Wisp(SERVERS[n]["port"], tls=SERVERS[n]["tls"], timeout=10)
                w.connect(1, 7101); w.send_pkt(2, 1, b"x")
                p = w.recv_pkt(10)
                if not p or p[0] != 2:
                    raise Closed(f"no echo: {p!r:.60}")
                held.append(w); c["idle_opened"] += 1
            except (Closed, OSError) as e:
                c["idle_fail"] += 1
                if c["idle_fail"] <= 3:
                    event("idle_fail", cycle=c["cycle"], server=n, err=repr(e))
    done.wait()
    for i, w in enumerate(held):
        w.close(rst=i % 2 == 0)


def floor(cycle, t_from):
    with lock:
        rs = [r for r in samples if r["cycle"] == cycle and r["phase"] == "idle" and r["t"] >= t_from]
    out = {}
    for n in SERVERS:
        for k in ("cg_anon_kib", "cg_kernel_kib", "rss_kib", "cg_cur_kib", "cg_sock_kib", "fds", "m_pool_dirty_kib", "m_pool_chunks",
                  "m_conns"):
            v = [float(r[n + "_" + k]) for r in rs if r.get(n + "_" + k) not in ("", None)]
            if v:
                out[f"{n}_{k}"] = statistics.median(v)
        v = [float(r[n + "_cg_anon_kib"]) for r in rs]
        if v:
            out[f"{n}_cg_anon_min_kib"] = min(v)
    return out


def main():
    event("start", argv=sys.argv, tcp_mem=TCP_MEM)
    start()
    threading.Thread(target=sampler, daemon=True).start()
    time.sleep(3)
    for i in range(1, a.cycles + 1):
        if STOP.is_set():
            break
        c = {"cycle": i, "wb_runs": 0, "wb_bad": 0, "probe_fail": 0, "idle_opened": 0, "idle_fail": 0, "abuse_ok": True,
             "gated": 0}
        cyc_state.update(cycle=i, phase="mix", tcp_peak=0)
        p0 = pressures(); t0 = time.time()
        event("cycle_start", cycle=i)
        done = threading.Event()
        th = [threading.Thread(target=idle_hold, args=(c, done)),
              threading.Thread(target=lane, args=(c, BULK)),
              threading.Thread(target=lane, args=(c, SMALL, lambda c: (time.sleep(20), abuse(c), probes(c))))]
        for t in th:
            t.start()
        for t in th[1:]:
            t.join()
        STOP.wait(max(0, t0 + a.mix_s - time.time()))
        done.set(); th[0].join(60)
        if th[0].is_alive():  # review: the floor needs every holder connection closed
            event("harness_error", cycle=i, err="idle holder still running 60 s after the mix: cycle not recorded")
            break
        mix_s = round(time.time() - t0, 1)
        cyc_state["phase"] = "idle"; t_idle = time.time()
        if STOP.wait(a.idle_s):
            break  # review: a stop cut the idle phase: no floor, the cycle is not recorded
        rec = dict(c, mix_s=mix_s, tcp_mem_peak=cyc_state["tcp_peak"], tcp_mem1=TCP_MEM[1], pressures=pressures() - p0)
        rec.update(floor(i, t_idle + a.idle_s - a.floor_s))
        for n, s in SERVERS.items():  # 30.16: heap breakdown at the floor ([heap] = main arena; other anon maps)
            rec.update({f"{n}_{k}": v for k, v in common.smaps_breakdown(s["proc"].pid).items()})
        alive = {n: s["proc"].poll() is None for n, s in SERVERS.items()}
        rec["alive"] = alive
        if a.floor_hook and all(alive.values()):
            th0 = time.time()
            try:
                hp = subprocess.run(a.floor_hook.split() + [str(i)] + [f"{n}={s['proc'].pid}" for n, s in SERVERS.items()],
                                    capture_output=True, text=True, timeout=150)
                rec["hook"] = {"rc": hp.returncode, "s": round(time.time() - th0, 2), "out": hp.stdout[-600:] + hp.stderr[-300:]}
            except Exception as e:
                rec["hook"] = {"rc": "error", "err": repr(e)}
        jlog("cycles.jsonl", **rec)
        event("cycle_end", **{k: rec.get(k) for k in ("cycle", "mix_s", "wb_runs", "wb_bad", "probe_fail", "A_cg_anon_kib",
                                                       "B_cg_anon_kib", "A_m_conns", "B_m_conns", "tcp_mem_peak",
                                                       "pressures", "gated")})
        if not all(alive.values()):
            event("server_died", alive=alive); break
    STOP.set()
    for n, s in SERVERS.items():
        event("server_stop", server=n, rc=kill_group(s["proc"]))
        s["proc"].pump.join(5)
    for p in procs:
        kill_group(p, wait=10)
    event("done")
    analyze()


# review: Event.set() takes a lock that an interrupted STOP.wait() may hold: set it from a thread instead
signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=STOP.set).start())
signal.signal(signal.SIGINT, lambda *_: threading.Thread(target=STOP.set).start())
main()
