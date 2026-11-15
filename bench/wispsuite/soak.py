"""Soak kit for the parallel compat gate (80.02): run the gate N times in one mode and keep one line per run and one
line per failed step, so that "0 failures in N runs" is a file, not a claim.

usage: python3 -m wispsuite.soak --bin FINALWISP --out DIR --runs N [--jobs 12] [--base-port 14500]
           [--pair [--pair-base-port P]]   every run = TWO gates started at the same moment (their own port ranges)
           [--cpu-load K]                  K busy processes beside every run (induced CPU load)
           [--gate-lock FILE]              flock FILE (LOCK_EX) around every run: "one gate per kernel" with other drivers
           [--no-cargo] [--no-fuzz] [--cargo DIR] [--wbench PATH] [-- extra arguments for `wst compat`]
The mode is `wst compat --bin X --matrix --fuzz-replay --jobs J` (the merge gate's compat part) unless changed above.
Files in DIR: runs.jsonl (one line per gate run), failed.jsonl (one line per step that is not PASS, with its unit, its
reason, its first FAIL lines and the path of its log), hoststate.jsonl (wispsuite.hoststate, every 2 s), PROGRESS, DONE,
run-NNN[a|b]/ (the whole output of every run: nothing is deleted). A file DIR/STOP ends the soak after the current run.
A second call with the same DIR goes on after the last run on file. Exit status: 0 if every run exited 0."""
import collections, argparse, fcntl, json, os, signal, subprocess, sys, time
from . import report


def _load():
    with open("/proc/loadavg") as f:
        return f.read().split()[:3]


def _gate(a, d, port, extra):
    cmd = [sys.executable, "-m", "wispsuite", "compat", "--bin", a.bin, "--matrix", "--jobs", str(a.jobs), "--base-port", str(port),
           "--out", os.path.join(d, "compat")] + ([] if a.no_fuzz else ["--fuzz-replay"]) + (["--no-cargo"] if a.no_cargo else ["--cargo", a.cargo])
    if a.wbench:
        cmd += ["--wbench", a.wbench]
    os.makedirs(d, exist_ok=True)
    log = open(os.path.join(d, "compat.log"), "w")
    return subprocess.Popen(cmd + extra, cwd=report.BENCH, stdout=log, stderr=subprocess.STDOUT, start_new_session=True), log


def _record(a, d, run, gate, rc, t0, t1, l0, out):
    line = {"run": run, "gate": gate, "start": round(t0, 1), "wall": round(t1 - t0, 1), "exit": rc, "load_start": l0, "load_end": _load(),
            "jobs": a.jobs, "pair": bool(a.pair), "cpu_load": a.cpu_load, "dir": os.path.relpath(d, out)}
    steps, failed = [], []
    try:
        with open(os.path.join(d, "compat", "results.json")) as f:
            res = json.load(f)
        steps = res["steps"]
        line.update(t_par=res.get("t_par"), t_late=res.get("t_late"), kept_back=res.get("kept_back"),
                    killed=[u["unit"] for u in res.get("units", []) if u.get("killed")])
    except (OSError, ValueError, KeyError) as e:
        line["no_results"] = repr(e)[:200]
    for k in ("PASS", "FAIL", "SKIP"):
        line[k.lower()] = sum(s["status"] == k for s in steps)
    try:  # how long the tls step waited for the host-wide kTLS counter lock (tests/compat/tls_extras.py prints it)
        with open(os.path.join(d, "compat", "tls.log")) as f:
            line["ktls_lock_wait"] = round(sum(float(l.split("waited ")[1].split()[0]) for l in f if l.startswith("note: kTLS counter lock")), 1)
    except (OSError, IndexError, ValueError):
        pass
    for s in steps:
        if s["status"] != "PASS":
            failed.append({"run": run, "gate": gate, "step": s["step"], "status": s["status"], "unit": s.get("unit"), "why": s.get("why", ""),
                           "fail_lines": s.get("fail_lines", [])[:5],
                           "log": os.path.join(line["dir"], "compat", s["step"].replace(" ", "_").replace("/", "_") + ".log")})
    if not steps:
        failed.append({"run": run, "gate": gate, "step": "(the gate)", "status": "FAIL", "why": f"no results.json, exit {rc}", "fail_lines": [],
                       "log": os.path.join(line["dir"], "compat.log")})
    return line, failed


def main(argv):
    extra = []
    if "--" in argv:
        i = argv.index("--")
        argv, extra = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(prog="wispsuite.soak", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", type=int, required=True)
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--base-port", type=int, default=14500)
    ap.add_argument("--pair", action="store_true")
    ap.add_argument("--pair-base-port", type=int, default=None)
    ap.add_argument("--cpu-load", type=int, default=0)
    ap.add_argument("--gate-lock", default="")
    ap.add_argument("--no-cargo", action="store_true")
    ap.add_argument("--no-fuzz", action="store_true")
    ap.add_argument("--cargo", default=os.path.join(os.path.dirname(report.BENCH), "server"))
    ap.add_argument("--wbench", default="")
    ap.add_argument("--run-timeout", type=int, default=3600, help="seconds one gate run may take; then SIGTERM, 30 s later SIGKILL, and the run counts as failed")
    a = ap.parse_args(argv)
    a.bin, out = os.path.abspath(a.bin), os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    span = 100 * (a.jobs + 1)
    ports = [a.base_port] + ([a.pair_base_port if a.pair_base_port is not None else a.base_port + span] if a.pair else [])
    if a.pair and abs(ports[1] - ports[0]) < span:
        sys.exit(f"soak: the two gates need {span} ports each; --base-port {ports[0]} and --pair-base-port {ports[1]} overlap")

    def say(s):
        with open(os.path.join(out, "PROGRESS"), "a") as f:
            f.write(time.strftime("%H:%M:%S ") + s + "\n")
    done = 0
    try:  # a run counts as done when each of its gates has its line (a pair: a and b)
        with open(os.path.join(out, "runs.jsonl")) as f:
            seen = collections.Counter(json.loads(l)["run"] for l in f if l.strip())
        done = max(seen, default=0)
        cut = sorted(r for r, n in seen.items() if n < len(ports))
    except OSError:
        cut = []
    for r in cut:  # a run with fewer lines than gates: the driver was cut between the lines of a pair. It is not run again
        # (its directories and the lines that exist stay as they are); the missing gate is one FAIL line, written once
        why = f"run {r}: fewer lines in runs.jsonl than gates: the driver was cut; the missing gate has no verdict"
        try:
            with open(os.path.join(out, "failed.jsonl")) as f:
                known = why in f.read()
        except OSError:
            known = False
        if not known:
            with open(os.path.join(out, "failed.jsonl"), "a") as f:
                f.write(json.dumps({"run": r, "gate": "?", "step": "(the gate)", "status": "FAIL", "why": why, "fail_lines": [], "log": ""}) + "\n")
            say(why)
    live, stop = [], [False]

    def kill_gates(sig):
        for p in list(live):
            try:
                os.killpg(p.pid, sig)
            except ProcessLookupError:
                pass

    def on_sig(*_):  # end the gates (they stop their own units); the wait loop then records them and the driver ends
        stop[0] = True
        kill_gates(signal.SIGTERM)
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, on_sig)
    sampler = subprocess.Popen([sys.executable, "-m", "wispsuite.hoststate", os.path.join(out, "hoststate.jsonl"), "2"], cwd=report.BENCH,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    say(f"START runs {done + 1}..{done + a.runs}: jobs {a.jobs}, ports {ports}, pair {a.pair}, cpu-load {a.cpu_load}, extra {extra}")
    bad, burn = 0, []
    try:
        for run in range(done + 1, done + a.runs + 1):
            if stop[0] or os.path.exists(os.path.join(out, "STOP")):
                say("STOP")
                break
            lock, waited = None, 0.0
            if a.gate_lock:
                t = time.time()
                lock = open(a.gate_lock, "a")
                while not stop[0]:  # a wait that a signal can end
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        time.sleep(0.5)
                waited = time.time() - t
            if stop[0]:
                say("STOP (signal)")
                break
            t0, l0 = time.time(), _load()
            gates, timed_out = [], False
            try:
                burn.extend(subprocess.Popen([sys.executable, "-c", "while True: pass"]) for _ in range(a.cpu_load))
                for i, port in enumerate(ports):
                    if stop[0]:
                        break
                    name = "ab"[i] if a.pair else ""
                    d = os.path.join(out, f"run-{run:03d}{name}")
                    p, log = _gate(a, d, port, extra)
                    live.append(p)
                    gates.append((name, d, p, log))
                ends, term_at = {}, None
                while len(ends) < len(gates):  # each gate's own end time
                    for name, d, p, log in gates:
                        if name not in ends and p.poll() is not None:
                            ends[name] = time.time()
                    now = time.time()
                    if term_at is None and (stop[0] or now - t0 > a.run_timeout):
                        timed_out = not stop[0]
                        term_at = now
                        kill_gates(signal.SIGTERM)
                    elif term_at is not None and now - term_at > 30:  # a gate that did not end on SIGTERM
                        kill_gates(signal.SIGKILL)
                    time.sleep(0.2)
            finally:
                while burn:
                    b = burn.pop()
                    b.kill()
                    b.wait()
                if lock:
                    lock.close()
            for name, d, p, log in gates:
                log.close()
                live.remove(p)
                line, failed = _record(a, d, run, name, p.returncode, t0, ends[name], l0, out)
                line["gate_lock_wait"] = round(waited, 1)
                if timed_out:
                    line["timed_out"] = a.run_timeout
                    failed.append({"run": run, "gate": name, "step": "(the gate)", "status": "FAIL", "why": f"over --run-timeout {a.run_timeout} s: ended by the soak driver",
                                   "fail_lines": [], "log": os.path.join(line["dir"], "compat.log")})
                with open(os.path.join(out, "runs.jsonl"), "a") as f:
                    f.write(json.dumps(line) + "\n")
                with open(os.path.join(out, "failed.jsonl"), "a") as f:
                    for x in failed:
                        f.write(json.dumps(x) + "\n")
                bad += p.returncode != 0 or timed_out
                say(f"run {run}{name}: exit {p.returncode}, {line['wall']:.0f} s, {line['pass']} PASS {line['fail']} FAIL {line['skip']} SKIP, "
                    f"load {l0[0]} -> {line['load_end'][0]}" + (f"; not PASS: {', '.join(x['step'] for x in failed)}" if failed else ""))
    finally:
        sampler.terminate()
        sampler.wait()
    with open(os.path.join(out, "DONE"), "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')} runs to {run if a.runs else done}: {bad} gate run(s) with a non-zero exit\n")
    say("DONE")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
