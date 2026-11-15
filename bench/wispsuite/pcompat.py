"""Parallel scheduler for the functional gates (`wst compat --bin X --jobs N`; prototype of the 80.01 pipeline work).

It does not know any test. The step list, the commands, the judges and the timeouts are those of compat.py:
1. PLAN: gate_finalwisp() runs once "dry" (no server, no command): every step it would run is recorded, with the
   servers that are alive at that moment. Steps that share a server form one UNIT (udp + wispjs-udp + wispjs;
   wispjs-v2c + adv-v2c; each matrix pair), the fuzz replay is one unit; every other step is a unit of its own.
2. RUN: each unit is one child `wst compat --only <its steps> --base-port <its block>`: the serial runner itself,
   restricted to that unit, in the order of the serial run. A unit has its own block of 100 ports (base-port +
   100 * k, k < jobs), so two units never share a port; every other resource of a step is already private (temp
   directories from mkdtemp, log names with the port, systemd scope and docker names with the port).
3. LANES: the steps named in --serial-lane (default SERIAL_LANE: CPU-bound builds and the steps that judge a rate or a
   latency) are the QUIET steps: their units run first, one at a time, with nothing else of the gate running. A unit
   that also has other steps after its quiet ones (fuzz-build + the replays; wispjs-v2c + adv-v2c) goes last in that
   lane, and the very last one RELEASES the lane when its quiet steps are reported: its other steps then run beside
   the parallel lane. All other units run on --jobs workers, the longest first (HINT_SECS: the order only, never a
   verdict). The serial lane has its own port block (base-port + 100 * jobs).
4. MERGE: the step records and logs of the units go into OUT/ in the order of the serial run: the same summary.txt,
   results.json (plus "units": lane, block, start, end) and the same exit rule. A planned step that no unit
   reported is a FAIL; a reported step that was not planned is a FAIL (the plan and the run must agree).

Before any unit starts (80.02): the port blocks must lie outside the kernel's range for outgoing connections and
hold no TCP listener and no bound UDP socket; tests/certs is made once. After a unit ends, every process that still
carries the unit's tag (WST_UNIT in its environment) is killed, and its port block goes back to the pool only when
nothing is bound in it (else it is kept back: fail closed).
EXPERIMENTS (default off): --late-lane STEPS runs those units after the parallel lane (--late-jobs at a time).

Not isolated by this scheduler: CPU and memory of the host (a step that judges a rate or a latency must be in the
serial lane), the kernel's global TCP memory, the per-user systemd manager, docker. The host-wide kTLS counters are
guarded by a lock inside tests/compat/tls_extras.py (every entry point takes it), not here.
"""
import errno, fcntl, json, os, shutil, signal, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from . import compat, proc, report

BLOCK = 100  # ports per unit: compat.py uses base+0 .. base+99
# Units that run alone (one step name selects its whole unit). Why each is here: see the 80.01 report, table "lanes".
SERIAL_LANE = ("cargo", "fuzz-build", "pacing", "uplimit", "v2ext", "udp", "wispjs-udp", "wispjs", "wispjs-v2c", "membudget")
# Typical seconds (serial run of 2026-11-12, v13-final/glibc27): used to start the long units first. No verdict use.
HINT_SECS = {"upstream": 199, "tls": 155, "adv-noprio": 136, "adv-lane": 108, "adv-v2c": 105, "uplimit": 61, "dns-own": 50,
             "proxyproto": 49, "dns-preset": 47, "fds": 41, "membudget": 35, "bounds": 33, "logs": 31, "limits": 23,
             "pacing": 23, "realip": 20, "cargo": 18, "policy": 15, "metrics": 13, "late": 31, "form": 120}
# 80.03 --quiet-par: the units that only burn CPU (no server of theirs is judged). They are bound to the heavy CPUs with
# taskset. No other unit is bound: a server without --threads takes its thread count from the CPUs it may use
# (available_parallelism), so a bound unit would test another server shape than today.
HEAVY_UNITS = ("fuzz",)
# 80.03 --quiet-par: these stay in the serial lane (alone, first), also in the fast mode.
# v2ext judges medians of handshake times within 100 us: it failed once beside the fast gate on a host at load1 36
# (medians 36 to 155 us; 15 to 47 us in every run alone). cargo: the unit tests listen on ports that the kernel
# chooses, as the helper listeners of the compat tests do; three unit-test runs side by side gave a false FAIL in 3 of
# 27 rounds (pf-unit3), so the unit tests keep the host to themselves. pacing, uplimit (the parent's decision B,
# 2026-11-13): the rate faults failed beside the lane, but the judged rates spread wider there than alone (pacing up
# to 1.045 against 1.006, uplimit up to 1.094 against 1.016) and pacing failed once there with no fault to explain it
# (a client send timed out, load1 32): a rate step leaves the serial lane only on a clean proof (REPORT-T, X5b, X15).
ALONE_FIRST = ("cargo", "v2ext", "pacing", "uplimit")
# 80.03 --shards: which variable tells the test which part of its cases to run (k/n), per step.
FAST_SHARDS = "upstream=4,adv=3,tls=5,form=3"


def shard_of(step, shards):
    """(n, variable) for a step that runs as n parts, else None."""
    if step == "upstream":
        n, var = shards.get("upstream", 1), "WST_CASES"
    elif step.startswith("adv-"):  # adv-lane, adv-noprio, adv-v2c, adv--<flag>
        n, var = shards.get("adv", 1), "WST_CASES"
    elif step == "tls":
        n, var = shards.get("tls", 1), "WST_TLS_PART"
    elif step == "form":
        n, var = shards.get("form", 1), "WST_FORM_PART"
    else:
        return None
    return (n, var) if n > 1 else None


def heavy_cpus(a):
    """The CPU list for the heavy units, or "" when this host has too few CPUs for --quiet-par (the caller says so)."""
    if getattr(a, "heavy_cpus", ""):
        return a.heavy_cpus
    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 8 or not shutil.which("taskset"):
        return ""
    return ",".join(str(x) for x in cpus[-(len(cpus) // 4):])


# 80.03: seconds of the parts of a sharded step (measured alone, laptop), for the start order only. No verdict use.
PART_SECS = {("adv", 2): (45, 40), ("adv", 3): (45, 20, 20), ("upstream", 2): (100, 100), ("upstream", 3): (67, 67, 64),
             ("upstream", 4): (52, 52, 52, 52), ("tls", 5): (6, 42, 23, 27, 37), ("form", 2): (78, 13), ("form", 3): (18, 73, 13)}
# 80.03: the mount table of the host is shared. `bwrap --dev-bind / /` (the fuzz replays, dns_own.py) binds every mount
# under / and fails when one of them goes away meanwhile; docker makes and removes mounts under /tmp while it builds and
# starts containers (seen: "bwrap: Can't bind mount ... /tmp/containerd-mount...: Invalid argument", a fuzz replay
# FAIL beside the docker group of the form checks). So a unit that uses docker runs under an exclusive host lock and a
# unit that uses bwrap under a shared one (flock, also between two gates of one user on one kernel).
MOUNT_LOCK = f"/tmp/wst-{os.getuid()}-mounts.lock"
BWRAP_STEPS = ("dns-own", "dns-preset")  # + the unit "fuzz"


def mount_mode(u):
    """fcntl.LOCK_EX for a unit that uses docker, LOCK_SH for one that uses bwrap, None for the others."""
    if "proxy" in u["steps"]:
        return fcntl.LOCK_EX
    if "form" in u["steps"]:
        part = u.get("env", {}).get("WST_FORM_PART")
        groups = compat.FORM_PARTS[int(part.split("/")[1])][int(part.split("/")[0]) - 1] if part else "E"
        return fcntl.LOCK_EX if "E" in groups else None
    if u["unit"] == "fuzz" or set(u["steps"]) & set(BWRAP_STEPS):
        return fcntl.LOCK_SH
    return None


_spawn_lock = threading.RLock()  # a child is registered in proc._live before the signal handler may run stop_all
_cancel = threading.Event()  # set at SIGTERM / SIGINT / an error in run(): no unit starts after it (review)


class _Dry(compat.Gate):
    """Records what gate_finalwisp would run: (step name, timeout, servers alive, group)."""

    dry = True

    def __init__(self):
        self.steps, self.seen, self.live, self.group = [], [], set(), None

    def say(self, s):
        pass

    def step(self, name, cmd, cwd=None, timeout=900, shell=False, judge=None, env=None):
        self.seen.append({"step": name, "timeout": timeout, "live": frozenset(self.live), "group": self.group})
        return "PASS"

    def broken(self, name, why):
        # review: a step that is "broken" in the dry run (a fuzz target that is not built yet) runs for real later:
        # it keeps the default step timeout in the unit's budget
        self.seen.append({"step": name, "timeout": 900, "live": frozenset(self.live), "group": self.group})


def plan(a):
    """The units of this run, in the order of the serial run: [{"unit", "steps", "flags", "timeout", "lane"}]."""
    g = _Dry()
    saved = (compat.fw, proc.stop, proc.wait_free, compat.fuzz_replay)
    count = [0]

    def fw(binp, port, args=""):
        count[0] += 1
        g.live.add(count[0])
        return count[0]

    def fuzz(a_, g_):
        g_.group = "fuzz"
        try:
            saved[3](a_, g_)
        finally:
            g_.group = None
    compat.fw, proc.stop, proc.wait_free, compat.fuzz_replay = fw, (lambda p, grace=3.0: g.live.discard(p)), (lambda port, timeout=5.0: True), fuzz
    try:
        compat.gate_finalwisp(a, g)
    finally:
        compat.fw, proc.stop, proc.wait_free, compat.fuzz_replay = saved
    for s in g.steps:  # records written without step(): fuzz-replay SKIP (missing tools)
        g.seen.append({"step": s["step"], "timeout": 0, "live": frozenset(), "group": "fuzz", "fixed": s})
    matrix = {f"{p}{f}" for f in compat.MATRIX_FLAGS for p in ("adv", "wispjs")}
    units = []
    for s in g.seen:
        key = ("group", s["group"]) if s["group"] else None
        u = next((u for u in units if (key and u["key"] == key) or (s["live"] and u["live"] & s["live"])), None)
        if u is None:
            u = {"unit": s["step"], "steps": [], "key": key, "live": set(), "timeout": 60, "flags": [], "fixed": []}
            units.append(u)
        u["steps"].append(s["step"])
        u["live"] |= s["live"]
        u["timeout"] += s["timeout"]
        if "fixed" in s:
            u["fixed"].append(s["fixed"])
    serial, late = set(a.serial_lane), set(getattr(a, "late_lane", ()) or ())
    for u in units:
        if u["key"] == ("group", "fuzz"):
            u["unit"], u["flags"] = "fuzz", ["--no-cargo", "--fuzz-replay", "--only", "~fuzz"]
        elif u["steps"] == ["proxy"]:
            u["flags"] = ["--no-cargo", "--proxy", "--only", "~proxy"]
        elif u["steps"] == ["form"]:
            u["flags"] = ["--no-cargo", "--form", "--only", "~form"]
        elif u["steps"] == ["cargo"]:
            u["flags"] = ["--only", "cargo"]
        else:
            u["flags"] = ["--no-cargo", "--only", ",".join(u["steps"])] + (["--matrix"] if set(u["steps"]) & matrix else [])
        if set(u["steps"]) & late:  # experiment: this unit runs after the parallel lane (it is not a quiet unit then)
            quiet = [False] * len(u["steps"])
            u["lane"] = "late"
        else:
            quiet = [s in serial for s in u["steps"]]
            u["lane"] = "serial" if any(quiet) else "par"
        u["quiet"] = [s for s, q in zip(u["steps"], quiet) if q]
        # the steps after the last quiet one need no quiet host: seconds that may run beside the parallel lane
        last = max((i for i, q in enumerate(quiet) if q), default=-1)
        u["tail"] = sum(HINT_SECS.get(s, 5) for s in u["steps"][last + 1:]) if any(quiet) else 0
        u["hint"] = sum(HINT_SECS.get(s, 5) for s in u["steps"])
        del u["key"], u["live"]
    return _shard(units, getattr(a, "shards", None) or {}, matrix)


def _shard(units, shards, matrix):
    """80.03: a unit with a step that runs in n parts becomes n units. Part 1 keeps every step of the unit (the steps
    that share its server); parts 2..n run only the sharded step, on a server of their own. Each part gets the variable
    of shard_of() = k/n in its environment; the test runs the cases of that part and nothing else."""
    out = []
    for u in units:
        cut = [(s, shard_of(s, shards)) for s in u["steps"] if shard_of(s, shards)]
        if not cut or u["fixed"]:
            out.append(u)
            continue
        if len(cut) > 1:
            raise SystemExit(f"compat: unit {u['unit']} has two sharded steps")
        step, (n, var) = cut[0]
        for k in range(1, n + 1):
            kind = "adv" if step.startswith("adv-") else step
            secs = PART_SECS.get((kind, n))
            hint = secs[k - 1] if secs else u["hint"] / n
            if step == "adv-noprio" and k == 1:
                hint = 72  # the part with case 16, which takes longer with --no-prio
            v = dict(u, unit=f"{u['unit']}.{k}of{n}", shard={"step": step, "k": k, "n": n}, env={var: f"{k}/{n}"}, hint=hint)
            if k > 1:  # only the sharded step; not a quiet unit (the quiet step of the unit, if any, ran in part 1)
                flags = ["--no-cargo", "--form", "--only", "~form"] if step == "form" else \
                        ["--no-cargo", "--only", step] + (["--matrix"] if step in matrix else [])
                v.update(steps=[step], flags=flags, quiet=[], tail=0, lane="par" if u["lane"] == "serial" else u["lane"])
            out.append(v)
    return out


def _bound(ports):
    """TCP listeners and bound UDP sockets on these ports, with ONE read of each socket table (1,300 ports took 12 s
    port by port). UDP: wispjs-udp, udp.py and the servers' UDP streams (80.02: the check was TCP only)."""
    want, out = set(ports), set()
    for fn, kind in (("/proc/net/tcp", "listener"), ("/proc/net/tcp6", "listener"), ("/proc/net/udp", "UDP socket"), ("/proc/net/udp6", "UDP socket")):
        try:
            with open(fn) as f:
                next(f)
                for line in f:
                    x = line.split()
                    port = int(x[1].rsplit(":", 1)[1], 16)
                    if port in want and (kind == "UDP socket" or x[3] == "0A"):
                        out.add((port, kind))
        except (OSError, StopIteration, ValueError, IndexError):
            continue
    return [f"port {p} already has a {k}" for p, k in sorted(out)]


def ensure_certs():
    """tests/certs/cert.pem + key.pem: the self-signed test certificate, made by run_tls.sh on first use. Made here
    once before any unit starts, under the lock that run_tls.sh takes too (two gates in a fresh clone)."""
    d = os.path.join(compat.ROOT, "tests", "certs")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, ".lock"), "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        if os.path.exists(os.path.join(d, "cert.pem")):
            return
        try:  # the command of run_tls.sh
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "30",
                            "-subj", "/CN=localhost", "-keyout", os.path.join(d, "key.pem"), "-out", os.path.join(d, "cert.pem")],
                           check=True, capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            pass  # no openssl: the tls step says so itself


def _kill_strays(tag):
    """SIGKILL every process that still carries WST_UNIT=tag in its environment: the tests and servers of a unit whose
    runner died (they are in sessions of their own, so stopping the runner's group does not reach them). Called after
    every unit; in a normal run it finds nothing. Returns what it killed."""
    needle, hit = f"WST_UNIT={tag}".encode(), []
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) == os.getpid():
            continue
        try:
            fd = os.pidfd_open(int(d))  # the handle first: if the pid is used again after this, the signal goes nowhere
        except OSError:
            continue
        try:
            with open(f"/proc/{d}/environ", "rb") as f:
                if needle not in f.read().split(b"\0"):
                    continue
            with open(f"/proc/{d}/comm") as f:
                name = f.read().strip()
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            hit.append(f"{name}({d})")
        except OSError:  # gone, or another user's process
            continue
        finally:
            os.close(fd)
    return hit


class _Blocks:
    """The port blocks. take() waits for a free one; None only when every block is kept back or the run is cancelled."""

    def __init__(self, blocks):
        self.free, self.out, self.held, self.cv = list(blocks), 0, [], threading.Condition()

    def take(self):
        with self.cv:
            while not self.free:
                if self.out == 0 or _cancel.is_set():
                    return None
                self.cv.wait(0.5)
            self.out += 1
            return self.free.pop(0)

    def give(self, block, kept=None):
        with self.cv:
            self.out -= 1
            if kept:
                self.held.append(kept)
            else:
                self.free.insert(0, block)
            self.cv.notify_all()


def _cpu_list(text):
    """taskset's list form ("12-15", "0,2,4-6") as a list of CPU numbers."""
    out = []
    for part in text.split(","):
        lo, _, hi = part.partition("-")
        out += range(int(lo), int(hi or lo) + 1)
    return out


def _unit(a, u, pool, out):
    """Run one unit on a block of the pool; clean up after it (80.02). Returns its step records."""
    if u["fixed"]:
        return u["fixed"]
    mode, lock = mount_mode(u), None
    if mode is not None and not a.netns:
        lock = open(MOUNT_LOCK, "a")  # one open file per unit: flock then also excludes the threads of this process
        t0 = time.time()
        while True:  # in steps, so that a cancelled gate does not wait here
            try:
                fcntl.flock(lock, mode | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES) or _cancel.is_set():  # review: only "taken" is waited for
                    lock.close()
                    if not _cancel.is_set():
                        u["rc"] = f"mount lock {MOUNT_LOCK}: {e}"  # fail closed: the steps of u become FAIL in the merge
                    return []
                time.sleep(0.2)
        u["mount_wait"] = round(time.time() - t0, 1)
    block = pool.take()
    if block is None:  # every block is kept back: fail closed, the steps of u become FAIL in the merge
        u["rc"] = "no free port block"
        if lock:
            lock.close()
        return []
    kept = None
    try:
        return _run_unit(a, u, block, out)
    finally:
        killed = _kill_strays(f"{os.getpid()}.{u['unit']}")
        if killed:
            u["killed"] = killed
        left, end = [], time.time() + 5
        while not a.netns and (left := _bound(range(block, block + BLOCK))) and time.time() < end:
            time.sleep(0.2)
        if left:
            kept = f"block {block} kept back after unit {u['unit']}: {left[0]}"
        pool.give(block, kept)
        if lock:
            lock.close()  # releases the flock: after the unit's strays are gone (review)


def _run_unit(a, u, block, out):
    """One unit = one child of the serial runner. Returns its step records (results.json of the child)."""
    d = os.path.join(out, "units", u["unit"])
    os.makedirs(d)  # fresh: run() moved an old units/ directory aside, so no result of an earlier run can be read
    cmd = [sys.executable, "-m", "wispsuite", "compat", "--bin", a.bin, "--base-port", str(block), "--out", d,
           "--cargo", a.cargo, "--wbench", a.wbench, "--allow-skip"] + u["flags"]
    if a.skip:
        cmd += ["--skip", ",".join(a.skip)]
    if a.membudget_master:
        cmd += ["--membudget-master", a.membudget_master]
    if a.netns:  # experiment (80.01 report, table "netns"): the unit in its own network namespace (loopback only)
        cmd = ["bwrap", "--unshare-net", "--unshare-pid", "--die-with-parent", "--dev-bind", "/", "/", "--proc", "/proc"] + cmd
    if u["unit"] == "fuzz" and getattr(a, "fuzz_jobs", 1) > 1:  # experiment
        cmd += ["--fuzz-jobs", str(a.fuzz_jobs)]
    elif u["unit"] == "fuzz" and u.get("cpus"):  # 80.03: the replays side by side, one per heavy CPU
        cmd += ["--fuzz-jobs", str(len(_cpu_list(u["cpus"])))]
    return _run_unit_child(a, u, block, d, cmd)


def _run_unit_child(a, u, block, d, cmd):
    u.update(block=block, start=round(time.time() - a.t0, 1), load1=round(os.getloadavg()[0], 2))
    env = {"WST_UNIT": f"{os.getpid()}.{u['unit']}", **u.get("env", {})}  # the tag of everything this unit starts (see _kill_strays)
    if u.get("cpus"):  # 80.03 --quiet-par: a heavy unit, bound to its CPUs (inherited by everything it starts)
        cmd = ["taskset", "-c", u["cpus"]] + cmd
    if os.environ.get("WST_COV_DIR"):  # a binary built with -C instrument-coverage: one profile directory per unit (test selection, 80.01)
        env["LLVM_PROFILE_FILE"] = os.path.join(os.environ["WST_COV_DIR"], u["unit"], "%p-%m.profraw")
    with _spawn_lock:
        if _cancel.is_set():
            return []
        p = proc.spawn(cmd, cwd=report.BENCH, env=env, log=os.path.join(d, "unit.log"))
    try:
        rc = p.wait(timeout=u["timeout"])
    except subprocess.TimeoutExpired:
        rc = None
    proc.stop(p, 5.0)
    u.update(end=round(time.time() - a.t0, 1), rc=rc)
    try:
        with open(os.path.join(d, "results.json")) as f:
            steps = json.load(f)["steps"]
    except (OSError, ValueError, KeyError):
        return []  # every planned step of the unit becomes a FAIL in the merge
    # review: the unit's exit status must agree with its records (children run with --allow-skip: 0 = no FAIL)
    want = 1 if (not steps or any(s["status"] == "FAIL" for s in steps)) else 0
    if rc != want:
        steps.append({"step": f"unit {u['unit']}", "status": "FAIL", "rc": rc, "secs": 0, "fail_lines": [],
                      "why": f"the unit exited {rc}, its records say {want}"})
    return steps


def _merged(a, name, parts, got):
    """80.03: the record and the log of a step that ran as parts (shards). FAIL if any part failed, did not report, or
    the parts do not agree; the log is the logs of the parts one after the other, each under a `#### part` line."""
    fname = name.replace(" ", "_").replace("/", "_") + ".log"
    recs, texts = [], []
    for v in sorted(parts, key=lambda v: v["shard"]["k"]):
        r = next((x for x in got.get(v["unit"], []) if x["step"] == name), None)
        if r is None:
            r = {"step": name, "status": "FAIL", "rc": None, "secs": 0, "fail_lines": [],
                 "why": f"unit {v['unit']} did not report this step (rc {v.get('rc')}; see units/{v['unit']}/unit.log)"}
        try:
            with open(os.path.join(a.out, "units", v["unit"], fname), errors="replace") as f:
                text = f.read()
        except OSError:
            text = ""
        recs.append((v, r))
        texts.append(f"#### part {v['shard']['k']}/{v['shard']['n']} (unit {v['unit']}): {r['status']} rc={r['rc']} {r['secs']}s\n"
                     + text + ("" if text.endswith("\n") or not text else "\n"))
    with open(os.path.join(a.out, fname), "w") as f:
        f.write("".join(texts))
    seen = {r["status"] for _, r in recs}
    n = parts[0]["shard"]["n"]
    why = [f"part {v['shard']['k']}/{n}: {r['why']}" for v, r in recs if r["why"]]
    if len(recs) != n or sorted(v["shard"]["k"] for v, _ in recs) != list(range(1, n + 1)):
        seen.add("FAIL")
        why.append(f"{len(recs)} parts planned, {n} wanted")
    if len(seen) > 1 and "FAIL" not in seen:
        why.append("the parts do not agree: " + ", ".join(r["status"] for _, r in recs))
    status = seen.pop() if len(seen) == 1 else "FAIL"
    rcs = [r["rc"] for _, r in recs]
    rec = {"step": name, "status": status, "rc": next((x for x in rcs if x != 0), 0), "secs": max(r["secs"] for _, r in recs),
           "fail_lines": [l for _, r in recs for l in r["fail_lines"]][:50], "why": "; ".join(why),
           "cpu_s": round(sum(r.get("cpu_s", 0) for _, r in recs), 1),
           "parts": [{"k": v["shard"]["k"], "unit": v["unit"], "status": r["status"], "rc": r["rc"], "secs": r["secs"]} for v, r in recs]}
    return rec, "\n".join("".join(texts).strip().splitlines()[-2:])


def run(a):
    """The parallel gate. Returns the exit status (the rule of compat.main)."""
    units = plan(a)
    if a.plan:
        for u in units:
            print(f"{u['lane']:6} {u['unit']:22} {' '.join(u['steps'])}" + "".join(f" {k}={v}" for k, v in u.get("env", {}).items()))
        return 0
    jobs = max(1, a.jobs)
    ports = range(a.base_port, a.base_port + BLOCK * (1 if a.netns else jobs + 1))
    if not a.netns:
        compat.check_port_range(ports.start, ports.stop - 1)
    bad = [] if a.netns else _bound(ports)
    if bad:
        sys.exit("compat: " + "; ".join(bad[:5]) + f" (ports {ports.start}-{ports.stop - 1} must be free; use --base-port)")
    ensure_certs()
    proc.install_handlers()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):  # first no new unit, then proc's handler (stop every group, exit)
        prev = signal.getsignal(sig)
        # review 2: _spawn_lock is taken once after the flag is set, so a spawn that is under way in a worker thread is
        # registered before stop_all runs (RLock: the main thread may hold it itself when the signal comes)
        signal.signal(sig, lambda s, f, prev=prev: (_cancel.set(), _spawn_lock.acquire(), _spawn_lock.release(), prev(s, f)))
    a.cargo, a.wbench = os.path.abspath(a.cargo), os.path.abspath(a.wbench)  # the units run with cwd = bench/ (review)
    if a.membudget_master:
        a.membudget_master = os.path.abspath(a.membudget_master)
    old = os.path.join(a.out, "units")
    if os.path.isdir(old):  # --out used again: stale unit results must not be read (review); moved, not deleted
        os.rename(old, f"{old}.old-{int(time.time())}")
    g = compat.Gate(a.out)
    a.t0 = time.time()
    g.say(f"compat gates for {a.bin} md5 {report.md5(a.bin)}")
    if getattr(a, "quiet_par", False):  # 80.03: no serial lane; the heavy units on CPUs of their own
        heavy = heavy_cpus(a)
        if heavy:
            for u in units:
                if u["lane"] == "serial" and not set(u["steps"]) & set(ALONE_FIRST):
                    u["lane"] = "quiet"
                    if u["unit"] in HEAVY_UNITS:
                        u["cpus"] = heavy
            g.say(f"--quiet-par: the quiet units run beside the parallel lane ({', '.join(u['unit'] for u in units if u['lane'] == 'quiet')}); "
                  f"bound to CPUs {heavy}: {', '.join(u['unit'] for u in units if u.get('cpus')) or '-'}; "
                  f"still alone, first: {', '.join(u['unit'] for u in units if u['lane'] == 'serial') or '-'}")
        else:
            g.say("--quiet-par is OFF for this run: fewer than 8 CPUs or no taskset, the serial lane stays")
    lanes = {k: [u for u in units if u["lane"] in v] for k, v in (("serial", ("serial",)), ("par", ("par", "quiet")), ("late", ("late",)))}
    g.say(f"parallel: {len(units)} units, --jobs {jobs}, serial lane: {', '.join(u['unit'] for u in lanes['serial']) or '-'}; "
          + (f"late lane (experiment, {a.late_jobs} at a time): {', '.join(u['unit'] for u in lanes['late'])}; " if lanes["late"] else "")
          + f"load1 {os.getloadavg()[0]:.2f}")
    got = {}
    # one pool for all lanes: jobs blocks for the parallel lane + 1 (the serial lane, and its last unit beside the parallel lane)
    pool = _Blocks([a.base_port + (0 if a.netns else BLOCK * k) for k in ([jobs] + list(range(jobs)))])
    ser = sorted(lanes["serial"], key=lambda u: u["tail"])  # stable: the order of the serial run
    tail_thread = None
    t_par = t_late = None
    ex = ex2 = None
    try:
        for i, u in enumerate(ser):  # the serial lane: one unit at a time, nothing else of the gate runs
            if i == len(ser) - 1 and u["tail"] and not u["fixed"]:
                # the last unit: the lane is released when its quiet steps are reported; the rest runs beside the parallel lane
                summary = os.path.join(a.out, "units", u["unit"], "summary.txt")
                tail_thread = threading.Thread(target=lambda u=u: got.__setitem__(u["unit"], _unit(a, u, pool, a.out)), daemon=True)
                tail_thread.start()
                while tail_thread.is_alive():
                    try:
                        with open(summary) as f:
                            seen = {l[3:].split(":")[0] for l in f if l.startswith("== ")}
                    except OSError:
                        seen = set()
                    if set(u["quiet"]) <= seen:
                        break
                    time.sleep(0.2)
                u["released"] = round(time.time() - a.t0, 1)
            else:
                got[u["unit"]] = _unit(a, u, pool, a.out)
        par = sorted(lanes["par"], key=lambda u: (not u.get("cpus"), -u["hint"]))  # a CPU-bound unit first (80.03), then the longest
        t_par = time.time() - a.t0
        ex = ThreadPoolExecutor(max_workers=jobs)
        for u, steps in zip(par, ex.map(lambda u: _unit(a, u, pool, a.out), par)):
            got[u["unit"]] = steps
        if tail_thread is not None:
            tail_thread.join()
        t_late = time.time() - a.t0
        if lanes["late"]:  # experiment: the CPU-bound units after everything that judges a time
            ex2 = ThreadPoolExecutor(max_workers=max(1, a.late_jobs))
            for u, steps in zip(lanes["late"], ex2.map(lambda u: _unit(a, u, pool, a.out), lanes["late"])):
                got[u["unit"]] = steps
            ex2.shutdown()
    except BaseException:  # SIGTERM / SIGINT (proc's handler raised SystemExit) or an error: stop, do not run the queue
        _cancel.set()
        with _spawn_lock:
            pass
        proc.stop_all()
        for e in (ex, ex2):
            if e is not None:
                e.shutdown(wait=True, cancel_futures=True)
        if tail_thread is not None:  # its unit ends with its runner (stopped above); then _unit kills what it left behind
            tail_thread.join(60)
        raise
    ex.shutdown()
    for h in pool.held:
        g.say(h)
    for u in units:
        if u.get("killed"):
            g.say(f"unit {u['unit']}: killed what it left behind: {', '.join(u['killed'][:8])}")
    # merge, in the order of the serial run
    for u in units:
        d = os.path.join(a.out, "units", u["unit"])
        by = {s["step"]: s for s in got.get(u["unit"], [])}
        for name in u["steps"]:
            s = by.pop(name, None)
            if u.get("shard") and u["shard"]["step"] == name:  # 80.03: one record and one log for the parts of this step
                if u["shard"]["k"] != 1:
                    continue  # reported with part 1
                s, tail = _merged(a, name, [v for v in units if v.get("shard") and v["shard"]["step"] == name], got)
                g.say(f"== {name}: {s['status']} rc={s['rc']} {s['secs']:.0f}s FAIL-lines={len(s['fail_lines'])}" + (f" ({s['why']})" if s["why"] else "")
                      + (f"\n{tail}" if tail else "") + ("\n" + "\n".join(s["fail_lines"][:10]) if s["fail_lines"] else ""))
                g.steps.append(dict(s, unit=u["unit"]))
                continue
            if s is None:
                why = f"unit {u['unit']} did not report this step (rc {u.get('rc')}; see units/{u['unit']}/unit.log)"
                s = {"step": name, "status": "FAIL", "rc": None, "secs": 0, "fail_lines": [], "why": why}
            log = os.path.join(d, name.replace(" ", "_").replace("/", "_") + ".log")
            tail = ""
            if os.path.exists(log):
                shutil.copy(log, a.out)
                with open(log, errors="replace") as f:
                    tail = "\n".join(f.read().strip().splitlines()[-2:])
            g.say(f"== {name}: {s['status']} rc={s['rc']} {s['secs']:.0f}s FAIL-lines={len(s['fail_lines'])}" + (f" ({s['why']})" if s["why"] else "")
                  + (f"\n{tail}" if tail else "") + ("\n" + "\n".join(s["fail_lines"][:10]) if s["fail_lines"] else ""))
            g.steps.append(dict(s, unit=u["unit"]))
        for name, s in by.items():  # the plan and the run must agree
            g.say(f"== {name}: FAIL (reported by unit {u['unit']} but not planned)")
            g.steps.append(dict(s, status="FAIL", why="not in the plan", unit=u["unit"]))
    n = {s: sum(x["status"] == s for x in g.steps) for s in ("PASS", "FAIL", "SKIP")}
    wall = time.time() - a.t0
    g.say(f"compat done: {n['PASS']} PASS, {n['FAIL']} FAIL, {n['SKIP']} SKIP" + (f" (FAIL: {', '.join(x['step'] for x in g.steps if x['status'] == 'FAIL')})" if n["FAIL"] else ""))
    g.say(f"wall {wall:.0f}s (serial lane {t_par:.0f}s, parallel lane {t_late - t_par:.0f}s" + (f", late lane {wall - t_late:.0f}s" if lanes["late"] else "")
          + f"), sum of the steps {sum(x['secs'] for x in g.steps):.0f}s, load1 {os.getloadavg()[0]:.2f}")
    keep = ("unit", "steps", "lane", "block", "start", "end", "rc", "load1", "released", "killed", "shard", "cpus", "mount_wait")
    report.write(os.path.join(a.out, "results.json"), "compat", binaries=[a.bin], mode="gate", server=None, steps=g.steps,
                 jobs=jobs, wall=round(wall, 1), t_par=round(t_par, 1), t_late=round(t_late, 1), kept_back=pool.held, units=[{k: u.get(k) for k in keep} for u in units])
    left_out = [x for x in a.skip] + (["cargo"] if a.no_cargo else []) + (["(--only " + ",".join(a.only) + ")"] if a.only else [])
    if left_out:
        g.say("not run on request: " + ", ".join(left_out))
    return 1 if n["FAIL"] or (n["SKIP"] and not a.allow_skip) or not g.steps else 0
