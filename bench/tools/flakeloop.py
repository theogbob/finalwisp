#!/usr/bin/env python3
"""60.74 4.5 flake loop: the unit test suite (and optionally compat steps) N times in a row beside a second copy of the suite
that runs in a loop (the load: "two suites at once", the condition under which the 60.74 4.5 list fails). Counts and
pass/fail only: no timing claim (wall seconds are how long the pipeline took).

usage: bench/tools/flakeloop.py run OUT --runs N [--tree DIR] [--load suite|none] [--load-copies K] [--burn B] [--test-threads T] [--stall MS:EVERY] [--port-churn N] [--features F]
                                [--compat STEPS --bin FINALWISP|auto --base-port P] [--filter "WORDS"]
       bench/tools/flakeloop.py table OUT [--check FILE]

run    builds the suite (`cargo test --release --locked --no-run`, + --features), then N runs of its test binary, one
       after another; beside them K copies of the same binary loop (each in its own process group, killed at the end;
       their results are counted in OUT/load.jsonl, never judged). --burn B: B more processes that only spin on a CPU
       (bash busy loops, nice 0), so the host has about twice as many runnable threads as CPUs (2x load: B = nproc).
       --stall MS:EVERY: every EVERY ms on average (0.5x..1.5x, seeded per run) the test binary (and the compat run)
       with every process below it is stopped for MS ms (SIGSTOP / SIGCONT): a host stall of a known size.
       --port-churn N: N UDP and N TCP loopback sockets bound to port 0 and rotated all the time (other processes taking
       ephemeral ports, as parallel suites do); its loop also keeps up to one CPU busy.
       --test-threads T: the test harness's thread count for the runs and the load copies (default: the harness's own,
       = CPUs; the laptop's 16 on a small VM gives the interleaving of the laptop's two-suite runs). --compat: after each suite run, `wst compat --only
       STEPS --no-cargo` on --bin (ports --base-port + 0..99), beside the same load.
       OUT/runs.jsonl: one line per run (i, rc, failed tests with the first line of each panic message, compat step
       statuses, load1 at start and end, UTC stamp). OUT/DONE at the end.
table  the per-test failure counts of OUT/runs.jsonl as a markdown table; --check FILE: exit 1 unless FILE contains it.
"""
import argparse, json, os, re, shlex, signal, subprocess, sys, threading, time


class LagProbe:
    """60.74 4.5: the host's scheduling lag during a run: a thread sleeps 1 ms in a loop; per run the largest
    overshoot, its 99th percentile and the count above 50 ms (ms). What the timing tests see, measured beside them."""

    def __init__(self):
        self.mu, self.over, self.stop = threading.Lock(), [], False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self.stop:
            t = time.monotonic()
            time.sleep(0.001)
            o = (time.monotonic() - t - 0.001) * 1000
            with self.mu:
                self.over.append(o)

    def take(self):
        with self.mu:
            v, self.over = sorted(self.over), []
        if not v:
            return {}
        return {"lag_max_ms": round(v[-1], 1), "lag_p99_ms": round(v[int(len(v) * 0.99)], 2), "lag_over50": sum(1 for x in v if x > 50), "lag_n": len(v)}


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load1():
    return float(open("/proc/loadavg").read().split()[0])


def build(tree, features):
    cmd = ["cargo", "test", "--release", "--locked", "--no-run", "--message-format=json-render-diagnostics"] + (["--features", features] if features else [])
    p = subprocess.run(cmd, cwd=os.path.join(tree, "server"), capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"flakeloop: build failed (exit {p.returncode}):\n{p.stderr[-3000:]}")
    exes = [m["executable"] for m in map(json.loads, filter(None, p.stdout.splitlines()))
            if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("profile", {}).get("test")]
    if not exes:
        sys.exit("flakeloop: no test executable in the build output")
    return exes


def parse(out):
    """-> ({test: first panic line}, passed count)"""
    failed = {l.split()[1]: "" for l in out.splitlines() if re.match(r"^test \S+ \.\.\. FAILED$", l)}
    for name in failed:
        m = re.search(r"^---- " + re.escape(name) + r" stdout ----\n(.*?)(?=^---- |\Z|^failures:)", out, re.M | re.S)
        if m:
            pm = re.search(r"panicked at ([^\n]*)\n([^\n]*)", m.group(1))
            failed[name] = (pm.group(1) + " " + pm.group(2)).strip()[:300] if pm else m.group(1).strip()[:300]
    passed = sum(int(n) for n in re.findall(r"test result: \w+\. (\d+) passed", out))
    return failed, passed


def descendants(root):
    """root and every process below it (from /proc: the ppid of each)"""
    kids = {}
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                st = open(f"/proc/{d}/stat").read()
            except OSError:
                continue
            ppid = int(st[st.rindex(")") + 2:].split()[1])
            kids.setdefault(ppid, []).append(int(d))
    out, todo = [], [root]
    while todo:
        p = todo.pop()
        out.append(p)
        todo += kids.get(p, [])
    return out


def signal_all(pids, sig):
    for p in pids:
        try:
            os.kill(p, sig)
        except ProcessLookupError:
            pass


class Stall:
    """--stall MS:EVERY: a host stall of a known size, injected: every EVERY ms on average (uniform 0.5x..1.5x, seeded
    by the run) the command and every process below it are stopped (SIGSTOP) for MS ms, then continued. What a host
    that does not schedule the tests for MS ms looks like to them (their own lag meters see it); the 60.74 4.5
    records saw stalls above 400 ms on the laptop under two gates at once."""

    def __init__(self, spec, seed):
        self.ms, self.every = (int(x) for x in spec.split(":"))
        self.rnd, self.n, self.done = __import__("random").Random(seed), 0, threading.Event()

    def watch(self, root):
        def run():
            while not self.done.wait(self.every * self.rnd.uniform(0.5, 1.5) / 1000):
                pids = descendants(root)
                signal_all(pids, signal.SIGSTOP)
                time.sleep(self.ms / 1000)
                signal_all(set(pids) | set(descendants(root)), signal.SIGCONT)
                self.n += 1
        t = threading.Thread(target=run, daemon=True)
        t.start()
        return t


# --port-churn N: N UDP and N TCP sockets on 127.0.0.1 bound to port 0, the oldest closed and a new one bound all the
# time: other processes that take ports from the ephemeral range (what parallel suites do); a test that frees a port
# and binds it again later loses it with a chance that grows with N
PORT_CHURN = r"""
import collections, resource, socket, sys, time
n = int(sys.argv[1])
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, max(soft, 2 * n + 256)), hard))
q = collections.deque()
while True:
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        s = socket.socket(socket.AF_INET, kind)
        try:
            s.bind(("127.0.0.1", 0))
        except OSError:
            s.close()
            continue
        q.append(s)
    while len(q) > 2 * n:
        q.popleft().close()
    time.sleep(0.0002)
"""

CURRENT = {"p": None}  # the command under way (a signal kills its session)
STOP = {"now": False}  # a signal came: no further command starts


def kill_session(p):
    """p's session and every process below it (review: wispsuite starts steps and servers in sessions of their own,
    which a group kill misses; their pids are taken before any is killed)"""
    pids = descendants(p.pid)
    signal_all(pids, signal.SIGCONT)
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    signal_all(pids, signal.SIGKILL)


def run_cmd(cmd, timeout, stall=None, seed=0, **kw):
    """(output, exit status or "timeout", stalls injected): cmd in its own session; a timeout kills the session"""
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True, **kw)
    CURRENT["p"] = p
    if STOP["now"]:  # (the signal came between Popen and the line above)
        kill_session(p)
    st = Stall(stall, seed) if stall else None
    th = st.watch(p.pid) if st else None
    try:
        o, _ = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        if st:
            st.done.set()
            th.join()
        kill_session(p)
        o, _ = p.communicate()
        rc = "timeout"
    CURRENT["p"] = None
    if st:
        st.done.set()
        th.join()
    return o.decode(errors="replace"), rc, (st.n if st else 0)


def cmd_run(a):
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    if os.listdir(out):
        sys.exit(f"flakeloop: {out} is not empty")
    tree = os.path.abspath(a.tree)
    exes = build(tree, a.features)
    if a.bin == "auto":  # the release binary of this tree (plain cargo build; compat steps need any finalwisp of the tree)
        p = subprocess.run(["cargo", "build", "--release", "--locked", "--message-format=json-render-diagnostics"], cwd=os.path.join(tree, "server"), capture_output=True, text=True)
        bins = [m["executable"] for m in map(json.loads, filter(None, p.stdout.splitlines())) if m.get("reason") == "compiler-artifact" and m.get("executable")]
        if p.returncode != 0 or not bins:
            sys.exit(f"flakeloop: release build failed (exit {p.returncode})")
        a.bin = bins[0]
    meta = {"utc": utc(), "tree": tree, "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=tree, capture_output=True, text=True).stdout.strip(),
            "exes": exes, "runs": a.runs, "load": a.load, "load_copies": a.load_copies, "burn": a.burn, "test_threads": a.test_threads, "features": a.features, "compat": a.compat, "stall": a.stall, "port_churn": a.port_churn,
            "filter": a.filter, "nproc": os.cpu_count()}
    json.dump(meta, open(os.path.join(out, "META.json"), "w"), indent=1)
    loads = []
    stop = STOP

    def on_sig(*_):
        # the run under way ends now (its command's session is killed) and is not recorded (60.78 T1: a farm.py signal
        # drains the loop: it should not wait up to an hour for the compat run)
        stop["now"] = True
        p = CURRENT["p"]
        if p is not None and p.poll() is None:
            kill_session(p)
    signal.signal(signal.SIGTERM, on_sig)
    signal.signal(signal.SIGINT, on_sig)
    if a.load == "suite":
        for k in range(a.load_copies):
            # a shell loop in its own process group; each pass appends one line (exit status) to load.jsonl
            tt = f" --test-threads={a.test_threads}" if a.test_threads else ""
            script = (f"while :; do for e in {' '.join(shlex.quote(x) for x in exes)}; do \"$e\" -q{tt} > /dev/null 2>&1; "
                      f"echo \"{{\\\"copy\\\": {k}, \\\"rc\\\": $?}}\" >> {shlex.quote(out + '/load.jsonl')}; done; done")
            loads.append(subprocess.Popen(["bash", "-c", script], start_new_session=True, stdin=subprocess.DEVNULL))
    if a.port_churn:
        loads.append(subprocess.Popen([sys.executable, "-c", PORT_CHURN, str(a.port_churn)], start_new_session=True, stdin=subprocess.DEVNULL))
    for k in range(a.burn):
        loads.append(subprocess.Popen(["bash", "-c", "while :; do :; done"], start_new_session=True, stdin=subprocess.DEVNULL))
    if loads:
        time.sleep(5)  # the load is under way before the first run
    probe = LagProbe()
    try:
        for i in range(a.runs):
            if stop["now"]:
                break
            probe.take()  # (the lag of this run only)
            rec = {"i": i, "utc": utc(), "load1_start": load1(), "failed": {}, "passed": 0, "rc": []}
            for e in exes:
                if stop["now"]:
                    break
                # (a hang is a result of the run: counted as "timeout", the loop goes on)
                text, rc, ns = run_cmd([e, *a.filter.split(), *([f"--test-threads={a.test_threads}"] if a.test_threads else [])], 1800, a.stall, i,
                                       env={**os.environ, "RUST_BACKTRACE": "0"})
                rec["stalls"] = rec.get("stalls", 0) + ns
                if rc == "timeout":
                    rec["failed"]["(timeout 1800 s)"] = os.path.basename(e)
                f, n = parse(text)
                rec["failed"].update(f)
                rec["passed"] += n
                rec["rc"].append(rc)
                if rc != 0:
                    open(os.path.join(out, f"fail-{i}.log"), "a").write(text)
            if a.compat and not stop["now"]:
                cdir = os.path.join(out, "compat", str(i))
                _, crc, ns = run_cmd([sys.executable, "-m", "wispsuite", "compat", "--bin", a.bin, "--only", a.compat, "--no-cargo", "--out", cdir,
                                      "--base-port", str(a.base_port)], 3600, a.stall, 10000 + i, cwd=os.path.join(tree, "bench"))
                rec["compat_stalls"] = ns
                try:
                    res = json.load(open(os.path.join(cdir, "results.json")))
                    rec["compat"] = {s["step"]: s["status"] for s in res.get("steps", [])}
                    rec["compat_fail_lines"] = {s["step"]: s.get("fail_lines", [])[:3] for s in res.get("steps", []) if s["status"] != "PASS"}
                except Exception as ex:
                    rec["compat"] = {"(results)": f"not read: {type(ex).__name__}"}
                rec["compat_rc"] = crc
            if stop["now"]:
                print(f"run {i}: interrupted by a signal, not recorded", flush=True)
                break
            rec["load1_end"] = load1()
            rec.update(probe.take())
            open(os.path.join(out, "runs.jsonl"), "a").write(json.dumps(rec) + "\n")
            print(f"run {i}: rc {rec['rc']} passed {rec['passed']} failed {list(rec['failed'])} compat {rec.get('compat', '-')} load1 {rec['load1_end']} "
                  f"lag max {rec.get('lag_max_ms')} ms p99 {rec.get('lag_p99_ms')} ms", flush=True)
    finally:
        for p in loads:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
    open(os.path.join(out, "DONE"), "w").write(utc() + "\n")


def lagq(k, runs):
    v = sorted(r[k] for r in runs if k in r)
    return f"{v[0]} / {v[len(v) // 2]} / {v[-1]}" if v else "-"


def table(out):
    runs = [json.loads(l) for l in open(os.path.join(out, "runs.jsonl"))]
    meta = json.load(open(os.path.join(out, "META.json")))
    lj = os.path.join(out, "load.jsonl")
    lrc = [json.loads(l)["rc"] for l in open(lj)] if os.path.exists(lj) else []
    fails, comp = {}, {}
    for r in runs:
        for t in r["failed"]:
            fails[t] = fails.get(t, 0) + 1
        for s, st in (r.get("compat") or {}).items():
            comp.setdefault(s, [0, 0])[st != "PASS"] += 1
    clean = sum(1 for r in runs if not r["failed"] and all(x == 0 for x in r["rc"]) and all(v == "PASS" for v in (r.get("compat") or {}).values()))
    l1 = [x for r in runs for x in (r["load1_start"], r["load1_end"])]
    rows = [f"<!-- table flakeloop {os.path.basename(out.rstrip('/'))} -->",
            "| what | value |", "|---|---|",
            f"| head | {meta['head'][:8]} |", f"| runs | {len(runs)} of {meta['runs']} |",
            f"| load | {meta['load']} x{meta['load_copies']} + {meta.get('burn', 0)} spinners on {meta['nproc']} CPUs, test threads {meta.get('test_threads') or 'default'}{'; port churn ' + str(meta['port_churn']) + ' x2 sockets' if meta.get('port_churn') else ''}{'; stalls ' + meta['stall'] + ' ms (MS:EVERY), injected ' + str(sum(r.get('stalls', 0) + r.get('compat_stalls', 0) for r in runs)) if meta.get('stall') else ''}; load passes {len(lrc)} ({sum(1 for x in lrc if x != 0)} not 0) |",
            f"| load1 min / max | {min(l1) if l1 else '-'} / {max(l1) if l1 else '-'} |",
            f"| clean runs | {clean} |",
            f"| host lag per run: max ms (min / median / max over runs) | {lagq('lag_max_ms', runs)} |",
            f"| host lag per run: p99 ms (min / median / max over runs) | {lagq('lag_p99_ms', runs)} |",
            f"| tests passed per run (min / max) | {min(r['passed'] for r in runs) if runs else '-'} / {max(r['passed'] for r in runs) if runs else '-'} |"]
    for t, n in sorted(fails.items(), key=lambda x: (-x[1], x[0])):
        lags = sorted(r.get("lag_max_ms", -1) for r in runs if t in r["failed"])
        rows.append(f"| FAILED {t} | {n} (host lag max in those runs: {lags[0]} to {lags[-1]} ms) |")
    for s, (ok, bad) in sorted(comp.items()):
        rows.append(f"| compat {s} PASS / not PASS | {ok} / {bad} |")
    rows.append("<!-- /table -->")
    return "\n".join(rows)


def cmd_table(a):
    t = table(os.path.abspath(a.out))
    if a.check:
        if t not in open(a.check).read():
            print(t)
            sys.exit(f"flakeloop table: {a.check} does not contain this table")
        print("table check OK")
    else:
        print(t)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run")
    p.add_argument("out")
    p.add_argument("--runs", type=int, required=True)
    p.add_argument("--tree", default=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    p.add_argument("--load", choices=("suite", "none"), default="suite")
    p.add_argument("--load-copies", type=int, default=1)
    p.add_argument("--burn", type=int, default=0)
    p.add_argument("--port-churn", type=int, default=0, help="N: N UDP + N TCP loopback sockets bound to port 0, rotated all the time")
    p.add_argument("--stall", default="", help="MS:EVERY: stop the tests (and compat) for MS ms every EVERY ms on average")
    p.add_argument("--test-threads", type=int, default=0)
    p.add_argument("--features", default="")
    p.add_argument("--filter", default="")
    p.add_argument("--compat", default="")
    p.add_argument("--bin", default="")
    p.add_argument("--base-port", type=int, default=22000)
    p = sub.add_parser("table")
    p.add_argument("out")
    p.add_argument("--check")
    a = ap.parse_args()
    if a.cmd == "run" and a.compat and not a.bin:
        ap.error("--compat needs --bin")
    {"run": cmd_run, "table": cmd_table}[a.cmd](a)
