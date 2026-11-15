#!/usr/bin/env python3
"""60.71 memory step: RSS and VmHWM of finalwisp release builds, counted (no timing claim), on one host.
For each run, thread count and binary (binary order rotated per run): start the binary bare (bench defaults:
--allow-loopback --allow-private) with --threads N, read RSS / VmHWM 1 s after start (idle), then after each of
upload 10x10, download 10x10, echo 10x10 (wbench, 16 KiB, 5 s + 1 s warm-up, the 30.19 cases; one server process for
all three, as in the method). One JSON line per sample.
usage: v131-memstep.py OUT.jsonl --base-port P [--wbench PATH] [--runs 3] [--threads 2,8,16,80] NAME=BINARY ..."""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispsuite import proc, sample, servers as srvmod, wbench
from wispsuite.matrix import run_case, MODES

ap = argparse.ArgumentParser()
ap.add_argument("out")
ap.add_argument("--base-port", type=int, required=True)
ap.add_argument("--runs", type=int, default=3)
ap.add_argument("--threads", default="2,8,16,80")
ap.add_argument("--wbench", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "target/release/wbench"))
ap.add_argument("bins", nargs="+")
a = ap.parse_args()
bins = [b.split("=", 1) for b in a.bins]
port = a.base_port
tports = {m: port + 1 + i for i, m in enumerate(MODES)}
CASES = [{"test": "upload", "conns": 10, "streams": 10, "size": 16384}, {"test": "download", "conns": 10, "streams": 10},
         {"test": "echo", "conns": 10, "streams": 10, "size": 16384}]
wb = wbench.find(a.wbench)
bad = proc.strays([port, *tports.values()])
if bad:
    sys.exit("strays: " + "; ".join(bad))
proc.install_handlers()
out = open(a.out, "a")
def rec(**k):
    out.write(json.dumps({"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **k}) + "\n"); out.flush()
try:
    for m, tp in tports.items():
        wbench.start_target(wb, tp, m)
    for run in range(a.runs):
        for th in [int(x) for x in a.threads.split(",")]:
            k = (run * 7 + th) % len(bins)
            for name, path in bins[k:] + bins[:k]:
                srv = srvmod.finalwisp(path, f"--threads {th}", name=name)
                p = srv.start(port, srvmod.SCRATCH)
                time.sleep(1.0)
                _, rss, hwm = sample.group_usage(p.pid)
                rec(bin=name, threads=th, run=run, step="idle", rss_mib=round(rss, 2), hwm_mib=round(hwm, 2))
                for c in CASES:
                    r = run_case(wb, port, tports, c, srv, 5, 1, p)
                    rec(bin=name, threads=th, run=run, step=f"{c['test']}:10:10", rss_mib=r.get("server_rss_mib"),
                        hwm_mib=r.get("server_peak_mib"), errors=r.get("errors"), error=r.get("error"),
                        alive=r.get("server_alive"))
                proc.stop(p)
                proc.wait_free(port)
                print(f"run {run} threads {th} {name} done", file=sys.stderr, flush=True)
finally:
    proc.stop_all()
