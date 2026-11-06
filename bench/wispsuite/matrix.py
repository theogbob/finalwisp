"""Server x case matrix with wbench (30.10; was run_matrix.py + median_runs.py, pointer 30.01).

usage: wst matrix CONFIG.json [--only NAME ...] [--reps N] [--out-dir DIR]
Config (JSON):
{
  "wbench": "target/release/wbench",      # optional; relative to the config file's directory
  "duration": 3, "warmup": 1, "port": 6001, "target_port": 6002,
  "servers": ["finalwisp", "epoxy",       # registry names (bench/servers.json), "fw:PATH args", or full entries:
              {"name": "x", "cmd": "exec ./x --port {port}", "cwd": "...", "env": {}, "extra": [], "ready_timeout": 20}],
  "cases": [{"test": "upload", "conns": 1, "streams": 1, "size": 16384, "extra": ["--stall-ping-ms", "1"]}]
}
A server's "extra" (wbench args) is appended to every case for that server. Targets: target_port .. +3 = echo,
sink, source, reply (started once, shared by all servers). browse: {"test": "browse", "conns": 1, "streams": 6,
"bulk": 1} = page bursts (rps = requests/s, p50/p99 = request latency). --reps N runs the whole matrix N times
(servers rotated per rep) and adds a median table (was median_runs.py).
"""
import argparse, json, os, sys, time
from . import proc, report, sample, servers as srvmod, wbench
from .stats import median

MODES = ("echo", "sink", "source", "reply")
TEST_MODE = {"upload": "sink", "download": "source", "echo": "echo", "rr": "echo", "churn": "echo", "connchurn": "echo", "browse": "reply"}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def run_case(wb, port, tports, case, srv, duration, warmup, server_proc):
    test = case["test"]
    args = ["--url", f"ws://127.0.0.1:{port}/", "--target", f"127.0.0.1:{tports[TEST_MODE[test]]}",
            "--conns", case.get("conns", 1), "--streams", case.get("streams", 1),
            "--duration", case.get("duration", duration), "--warmup", case.get("warmup", warmup), "--test", test]
    if case.get("size"):
        args += ["--size", case["size"]]
    if case.get("bulk"):
        args += ["--bulk", case["bulk"]]  # 20.19 browse: bulk download streams per connection
    args += case.get("extra", []) + srv.extra
    budget = float(case.get("duration", duration)) + float(case.get("warmup", warmup)) + 30
    cpu0, _, _ = sample.group_usage(server_proc.pid)
    t0 = time.time()
    res = wbench.run(wb, args, budget)
    wall = time.time() - t0
    cpu1, rss, hwm = sample.group_usage(server_proc.pid)
    if "error" in res:
        return {"test": test, "error": res["error"], "server_alive": server_proc.poll() is None}
    res["server_cpu_s"] = round(cpu1 - cpu0, 3)
    res["server_cpu_pct"] = round(100 * (cpu1 - cpu0) / wall, 1) if wall > 0 else 0
    res["server_rss_mib"] = round(rss, 1)
    res["server_peak_mib"] = round(hwm, 1)
    res["server_alive"] = server_proc.poll() is None
    return res


HEAD = ["server", "test", "conns", "streams", "size", "MiB/s up", "MiB/s down", "rps", "p50 us", "p99 us", "p999 us",
        "errors", "srv CPU%", "srv RSS MiB"]


def markdown(rows):
    out = []
    for r in rows:
        if "error" in r:
            out.append([r["server"], r["test"], "", "", "", f"ERROR: {r['error'][:80]}"] + [""] * (len(HEAD) - 6))
        else:
            out.append([r["server"], r["test"], r["conns"], r["streams"], r["size"], r["mib_s_up"], r["mib_s_down"], r["rps"],
                        r["p50_us"], r["p99_us"], r["p999_us"], r["errors"], r["server_cpu_pct"], r["server_rss_mib"]])
    return report.md_table(HEAD, out)


def median_table(rows):
    groups = {}
    for r in rows:
        if "error" not in r:
            groups.setdefault((r["server"], r["test"], r["conns"], r["streams"], r["size"]), []).append(r)
    out = []
    for k, rs in groups.items():
        g = lambda f: median([r.get(f) for r in rs], 1)
        out.append([*k[:2], f"{k[2]}x{k[3]}", k[4], len(rs), g("mib_s_up"), g("mib_s_down"), g("rps"), g("p50_us"), g("p99_us"),
                    sum(r.get("errors", 0) for r in rs), g("server_cpu_pct"), g("server_rss_mib")])
    return report.md_table(["server", "test", "CxS", "size", "n", "up MiB/s", "down MiB/s", "rps", "p50 us", "p99 us", "errors",
                            "CPU%", "RSS MiB"], out)


def main(argv):
    ap = argparse.ArgumentParser(prog="wst matrix", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config")
    ap.add_argument("--only", nargs="*", help="only these server names")
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--out-dir", default=os.path.join(report.BENCH, "results"))
    a = ap.parse_args(argv)
    cfg_path = os.path.abspath(a.config)
    cfg = json.load(open(cfg_path))
    wb = cfg.get("wbench")
    if wb and not os.path.isabs(wb):
        wb = os.path.normpath(os.path.join(os.path.dirname(cfg_path), wb))
    wb = wbench.find(wb)
    if not os.access(wb, os.X_OK):
        sys.exit(f"wbench binary not found: {wb} (cd bench && cargo build --release)")
    port = int(cfg.get("port", 6001))
    tbase = int(cfg.get("target_port", port + 1))
    tports = {m: tbase + i for i, m in enumerate(MODES)}
    duration, warmup = cfg.get("duration", 3), cfg.get("warmup", 1)
    reg = srvmod.load()
    srvs = [srvmod.resolve(s, reg) for s in cfg["servers"]]
    srvs = [s for s in srvs if not a.only or s.name in a.only]
    stamp = report.stamp()
    logdir = os.path.join(a.out_dir, f"{stamp}-logs")
    os.makedirs(logdir, exist_ok=True)
    bad = proc.strays([port, *tports.values()])
    if bad:
        sys.exit("matrix: " + "; ".join(bad))
    proc.install_handlers()
    rows = []
    try:
        for mode, tport in tports.items():
            wbench.start_target(wb, tport, mode, log=os.path.join(logdir, f"target-{mode}.log"))
        for rep in range(a.reps):
            k = rep % len(srvs) if srvs else 0
            for srv in srvs[k:] + srvs[:k]:
                log(f"== {srv.name}: starting" + (f" (rep {rep + 1}/{a.reps})" if a.reps > 1 else ""))
                try:
                    p = srv.start(port, srvmod.SCRATCH, log=os.path.join(logdir, f"server-{srv.name}.log"))
                except RuntimeError as e:
                    rows.append({"server": srv.name, "test": "-", "rep": rep, "error": str(e)})
                    continue
                time.sleep(0.3)
                for case in cfg["cases"]:
                    if p.poll() is not None:
                        rows.append({"server": srv.name, "test": case["test"], "rep": rep, "error": "server exited"})
                        continue
                    res = run_case(wb, port, tports, case, srv, duration, warmup, p)
                    res.update(server=srv.name, rep=rep)
                    rows.append(res)
                    log(f"   {srv.name} {case}: " + json.dumps({k: v for k, v in res.items() if k != 'stderr'}))
                proc.stop(p)
                proc.wait_free(port)
    finally:
        proc.stop_all()
    path = report.write(os.path.join(a.out_dir, f"{stamp}.json"), "matrix", binaries=[wb], config=cfg, results=rows)
    print(markdown(rows))
    if a.reps > 1:
        print("\nMedians over reps:\n" + median_table(rows))
    log(f"results: {path}")
