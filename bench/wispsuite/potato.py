"""Potato curve (30.10; was potato_curve.py + potato_ab.py, 20.26): each server build under a systemd scope with
MemoryMax = N MiB (no swap, one CPU), four workloads; survival (alive, no OOM kill) and throughput.

usage: wst potato --bin NAME=PATH[@K=V,K=V] ... [--mbs 16,32,64,128] [--tests download,upload,rr,churn]
                  [--reps 1] [--dur 3] [--cpu 1] [--pin CPUS] [--port 6610] [--out FILE.jsonl]
  @K=V: environment for that build's server. --pin: taskset wbench + targets to CPUS (keep them off the server's
  CPU). regress: server on the 2nd-lowest allowed CPU, peers on the lowest (pin_pair()). As root: system scopes, else user scopes (needs a delegated memory controller).
Rows (JSON lines): mb, test, bin, rep, value (MiB/s or req/s), errors, alive, peak_mib, oom_kill, lvl_changes,
lvl_max (from the server's "memory level a -> b" log lines), steal_ticks, cpu_us (the scope's CPU time).
Loop order: mb, test, rep, builds (start build rotated per rep).
"""
import argparse, json, os, re, subprocess, sys, time
from . import proc, report, sample, wbench
from .stats import median

CASES = {"download": ("10", 1, "16384"), "upload": ("10", 2, "16384"), "rr": ("10", 3, "64"), "churn": ("10", 3, "64")}
MODES = {1: "source", 2: "sink", 3: "echo"}


def _cpus(spec):
    out = []
    for part in str(spec).split(","):
        a, _, b = part.partition("-")
        out += list(range(int(a), int(b or a) + 1))
    return out


def _fmt(s):
    return ",".join(str(x) for x in sorted(s))


def pin_pair():
    """(server cpu, peers cpu) = the 2nd-lowest and lowest CPUs this process may use (sched_getaffinity), so the
    pinning works inside cpusets/sandboxes that exclude CPU 0; None if fewer than 2 are allowed."""
    allowed = sorted(os.sched_getaffinity(0))
    return (str(allowed[1]), str(allowed[0])) if len(allowed) >= 2 else None


def scopes_available():
    user = [] if os.geteuid() == 0 else ["--user"]
    return subprocess.run(["systemd-run", *user, "--scope", "-q", "-p", "MemoryMax=16M", "true"],
                          capture_output=True).returncode == 0


def run_curve(wb, out_path, bins, mbs=(16, 32, 64, 128), tests=("download", "upload", "rr", "churn"), reps=1, dur="3",
              cpu="1", pin="", port=6610, logdir=None, rotate=True, verbose=True):
    """bins: [(name, path, ["K=V", ...])]. Appends rows to out_path; returns them."""
    user = [] if os.geteuid() == 0 else ["--user"]
    allowed = os.sched_getaffinity(0)
    for what, cpus in (("--pin", pin), ("--cpu", cpu)):
        if cpus and not set(_cpus(cpus)) <= allowed:
            raise RuntimeError(f"potato: {what} {cpus} is outside this process's CPUs {_fmt(allowed)}")
    pin_cmd = ["taskset", "-c", pin] if pin else []
    logdir = logdir or os.path.join(os.path.dirname(os.path.abspath(out_path)), "potato-logs")
    os.makedirs(logdir, exist_ok=True)
    bad = proc.strays([port] + [port + k for k in MODES])
    if bad:
        raise RuntimeError("; ".join(bad))
    tg = {k: wbench.start_target(wb, port + k, m, prefix=pin_cmd) for k, m in MODES.items()}
    rows = []
    out = open(out_path, "a")
    try:
        for mb in mbs:
            for test in tests:
                cs, toff, size = CASES[test]
                for rep in range(reps):
                    k = rep % len(bins) if rotate else 0
                    for name, path, env in bins[k:] + bins[:k]:
                        unit = f"pc-{name}-{mb}-{test}-{int(time.time() * 1000) % 100000}"
                        log = os.path.join(logdir, unit + ".log")
                        srv = proc.spawn(["systemd-run", *user, "--scope", "-q", "--unit", unit, "-p", f"MemoryMax={mb}M",
                                          "-p", "MemorySwapMax=0", "-p", f"AllowedCPUs={cpu}", *[f"--setenv={e}" for e in env],
                                          path, "--port", str(port), "--allow-loopback", "--threads", "1"], log=log)
                        time.sleep(0.6)
                        proc.wait_port(port, 5, srv)
                        st0 = sample.steal_ticks()
                        j = wbench.run(wb, ["--url", f"ws://127.0.0.1:{port}/", "--target", f"127.0.0.1:{port + toff}",
                                            "--conns", cs, "--streams", cs, "--duration", dur, "--warmup", "1", "--test", test,
                                            "--size", size, "--stall-ping-ms", "1"], float(dur) + 31, prefix=pin_cmd)
                        st1 = sample.steal_ticks()
                        alive = srv.poll() is None
                        peak, oom, cpu_us = sample.scope_stats(unit, bool(user))
                        proc.stop(srv, 0)
                        time.sleep(0.4)
                        try:
                            txt = open(log, errors="replace").read()
                            os.unlink(log)
                        except OSError:
                            txt = ""
                        lv = [int(m.group(1)) for m in re.finditer(r"memory level \d -> (\d)", txt)]
                        row = {"mb": mb, "test": test, "bin": name, "rep": rep, "value": j.get(wbench.key_metric(test)),
                               "errors": j.get("errors"), "alive": alive, "peak_mib": peak, "oom_kill": oom,
                               "lvl_changes": len(lv), "lvl_max": max(lv) if lv else None,
                               "steal_ticks": None if st0 is None or st1 is None else st1 - st0, "cpu_us": cpu_us}
                        if "error" in j:
                            row["error"] = j["error"][:200]
                        rows.append(row)
                        out.write(json.dumps(row) + "\n")
                        out.flush()
                        if verbose:
                            print(json.dumps(row), flush=True)
    finally:
        out.close()
        for p in tg.values():
            proc.stop(p, 0)
    return rows


def parse_bin(spec):
    name, rest = spec.split("=", 1)
    path, _, env = rest.partition("@")
    return name, os.path.abspath(path), [e for e in env.replace(";", ",").split(",") if e]


def main(argv):
    ap = argparse.ArgumentParser(prog="wst potato", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", action="append", required=True, help="NAME=PATH[@K=V,K=V] (repeat)")
    ap.add_argument("--mbs", default="16,32,64,128"); ap.add_argument("--tests", default="download,upload,rr,churn")
    ap.add_argument("--reps", type=int, default=1); ap.add_argument("--dur", default="3")
    ap.add_argument("--cpu", default=os.environ.get("CPU") or (pin_pair() or ("",))[0] or str(min(os.sched_getaffinity(0))),
                    help="server CPU (default: 2nd-lowest allowed)")
    ap.add_argument("--pin", default=os.environ.get("PEERS_CPU", ""), help="peers' CPUs (default: unpinned)")
    ap.add_argument("--port", type=int, default=6610); ap.add_argument("--wbench")
    ap.add_argument("--out", default=os.path.join(report.BENCH, "results", f"potato-{report.stamp()}.jsonl"))
    a = ap.parse_args(argv)
    if not scopes_available():
        sys.exit("potato: systemd-run memory scopes are not available (user systemd + delegated memory controller)")
    proc.install_handlers()
    bins = [parse_bin(b) for b in a.bin]
    rows = run_curve(wbench.find(a.wbench), a.out, bins, [int(x) for x in a.mbs.split(",")], a.tests.split(","), a.reps,
                     a.dur, a.cpu, a.pin, a.port)
    cells = {}
    for r in rows:
        cells.setdefault((r["mb"], r["test"], r["bin"]), []).append(r)
    table = [(f"{mb}M", t, b, f"{sum(bool(x['alive']) and not x['oom_kill'] for x in rs)}/{len(rs)}",
              median([x["value"] for x in rs if x["alive"] and not x["oom_kill"]]), median([x["peak_mib"] for x in rs]))
             for (mb, t, b), rs in sorted(cells.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2]))]
    print(report.md_table(["MemoryMax", "test", "build", "alive", "median value", "median peak MiB"], table))
    print(f"rows: {a.out}", file=sys.stderr)


def legacy_curve(argv):
    """potato_curve.py WBENCH OUT NAME=PATH ...   (env CPU, PEERS_CPU): one pass, builds in the given order."""
    if len(argv) < 3:
        sys.exit("usage: potato_curve.py WBENCH OUT BIN_NAME=PATH ... (env CPU, PEERS_CPU)")
    proc.install_handlers()
    run_curve(os.path.abspath(argv[0]), argv[1], [parse_bin(b) for b in argv[2:]], cpu=os.environ.get("CPU", "1"),
              pin=os.environ.get("PEERS_CPU", ""), rotate=False)
