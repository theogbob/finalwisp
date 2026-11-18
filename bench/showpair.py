#!/usr/bin/env python3
"""60.78 G02 showpair: the showdown (60.71 cells) as PAIRED rounds: finalwisp against every competitor.

usage: bench/showpair.py OUT_DIR --servers finalwisp,epoxy,... [--cells upload:1:1:16384,...] [--rounds 16]
       [--dur 5] [--warmup 1] [--port 21700] [--settle S] [--ref finalwisp]

Per cell (cells run one after the other), ROUNDS rounds; a round runs every server once, a fresh server process per
run, wbench 5 s + 1 s warm-up against a wbench target on this box (loopback), the server's own wbench extras from
bench/servers.json (as the showdown and run_v110.py). Slot order: a Williams design (base sequence 0, 1, K-1, 2, K-2, ...,
round r = base + r mod K; K arms, K even): over a multiple of K rounds every arm has every slot equally often and every
arm follows every other arm equally often (16 rounds, 8 arms: twice each; 2 arms: the slots swap every round), so a
run's leftovers (TIME_WAIT sockets, TCP memory) do not land on one competitor more than on another.
Each competitor X is paired with the reference (finalwisp) of the SAME round; tables: bench/showpair-tables.py.
--settle S: before each run wait (max S s) until the host's TCP memory is below 2 % of tcp_mem[2] (as run_v110.py).
Raw: OUT_DIR/raw.jsonl, one record per run (cell, round, slot, server, value or error, server_alive, errors, RSS/HWM,
server CPU, TCP pressure share, TIME_WAIT count before the run (tw_count0), unix times, run_id = the driver's start). The
same OUT_DIR resumes with the same settings only (checked against the first meta.jsonl line): a round that one attempt
(run_id) completed is skipped, any other round is redone whole (the tables pair within the latest complete attempt). OUT_DIR/PAUSE (a file) makes the
driver wait at the next cell boundary (box hand-over); OUT_DIR/DONE is written at the end.
A run counts as failed (pair dropped, never a win for either side) when the server did not start, exited during the
run, wbench gave no result, or the value is not > 0; the record says which."""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispsuite import proc, sample, servers as srvmod, wbench  # noqa: E402

MODE = {"upload": "sink", "download": "source", "echo": "echo", "rr": "echo", "churn": "echo"}
CELLS = "upload:1:1:16384,upload:10:10:16384,download:10:10,echo:1:1:16384,echo:10:10:16384,rr:1:1:64,rr:10:10:64,churn:10:10:64"


def time_wait():
    for line in open("/proc/net/sockstat"):
        if line.startswith("TCP:"):
            p = line.split()
            return int(p[p.index("tw") + 1])
    return None


def parse_cell(c):
    f = c.split(":")
    if len(f) not in (3, 4) or f[0] not in MODE:
        raise SystemExit(f"cell {c}: TEST:CONNS:STREAMS[:SIZE], TEST one of {', '.join(MODE)}")
    return {"cell": c, "test": f[0], "conns": int(f[1]), "streams": int(f[2]), "size": int(f[3]) if len(f) == 4 else 0}


def one_run(wb, srv, cell, port, tports, a, logdir):
    rec = {}
    settle_s = None
    if a.settle:
        lim, t_s = sample.tcp_mem_max() or 0, time.time()
        while (sample.tcp_mem_pages() or 0) > lim * 0.02 and time.time() - t_s < a.settle:
            time.sleep(0.2)
        settle_s = round(time.time() - t_s, 1)
    rec.update(settle_s=settle_s, tw_count0=time_wait(), tcp_mem0=sample.tcp_mem_pages(), load1=os.getloadavg()[0])
    if not proc.wait_free(port, 30):
        return {**rec, "error": f"port {port} still has a listener", "fatal": True}
    t0 = time.time()
    try:
        p = srv.start(port, srvmod.SCRATCH, log=os.path.join(logdir, f"server-{srv.name}.log"))
    except RuntimeError as e:
        return {**rec, "t0": round(t0, 3), "error": f"server did not start: {e}", "server_alive": False}
    try:
        time.sleep(max(0.0, 0.5 - (time.time() - t0)))  # every worker has bound (as wst ab)
        args = ["--url", f"ws://127.0.0.1:{port}/", "--target", f"127.0.0.1:{tports[MODE[cell['test']]]}",
                "--conns", cell["conns"], "--streams", cell["streams"], "--duration", a.dur, "--warmup", a.warmup,
                "--test", cell["test"]]
        if cell["size"]:
            args += ["--size", cell["size"]]
        args += srv.extra
        pr0 = sample.tcp_pressure_both()
        cpu0, _, _ = sample.group_usage(p.pid)
        tw = time.time()
        pk = sample.TcpMemPeak()
        with pk:
            j = wbench.run(wb, args, float(a.dur) + float(a.warmup) + 40)
        wall = time.time() - tw
        alive = p.poll() is None
        cpu1, rss, hwm = sample.group_usage(p.pid) if alive else (cpu0, None, None)
    finally:
        proc.stop(p)
    time.sleep(0.2)
    pd = sample.pressure_delta(pr0, sample.tcp_pressure_both())
    key = wbench.key_metric(cell["test"])
    rec.update(t0=round(t0, 3), tw_start=round(tw, 3), win_s=round(wall, 3), t1=round(time.time(), 3), server_alive=alive,
               cpu_pct=round(100 * (cpu1 - cpu0) / wall, 1) if alive and wall > 0 else None, rss_mib=rss, hwm_mib=hwm,
               tcp_press_frac=round(pk.press_samples / pk.samples, 3) if pk.samples else None,
               tcp_press=pd[0] if pd else None, tcp_mem_peak=pk.max_seen)
    if "error" in j:
        rec["error"] = ("server exited during the run; " if not alive else "") + "wbench: " + j["error"][:300]
    else:
        rec.update(value=j.get(key), metric=key, errors=j.get("errors"), p50_us=j.get("p50_us"), p99_us=j.get("p99_us"),
                   stall_pings=j.get("stall_pings"))
        if not alive:
            rec["error"] = "server exited during the run"
        elif not (rec["value"] or 0) > 0:
            rec["error"] = "value not > 0 (moved nothing)"
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--servers", required=True)
    ap.add_argument("--ref", default="finalwisp")
    ap.add_argument("--cells", default=CELLS)
    ap.add_argument("--rounds", type=int, default=16)
    ap.add_argument("--dur", default="5")
    ap.add_argument("--warmup", default="1")
    ap.add_argument("--port", type=int, default=21700, help="server port; targets port+1..+3 (keep below 32768)")
    ap.add_argument("--settle", type=float, default=0)
    ap.add_argument("--wbench", default=None)
    a = ap.parse_args()
    if not 1024 <= a.port <= 32760:
        sys.exit("--port: 1024..32760 (test ports stay below 32768)")
    names = [n for n in a.servers.split(",") if n]
    if a.ref not in names:
        sys.exit(f"--ref {a.ref} is not in --servers")
    if len(set(names)) != len(names):
        sys.exit("--servers: a name is listed twice")
    if len(names) % 2 or a.rounds % len(names):
        sys.exit(f"{len(names)} arms, {a.rounds} rounds: the balanced order needs an even number of arms and rounds a multiple of it")
    reg = srvmod.load()
    srvs = {n: srvmod.resolve(n, reg) for n in names}
    cells = [parse_cell(c) for c in a.cells.split(",") if c]
    wb = wbench.find(a.wbench)
    os.makedirs(a.out, exist_ok=True)
    logdir = os.path.join(a.out, "logs")
    os.makedirs(logdir, exist_ok=True)
    rawp = os.path.join(a.out, "raw.jsonl")
    have = {}  # (cell, round) -> {run_id: set of servers}
    if os.path.exists(rawp):
        for line in open(rawp):
            r = json.loads(line)
            have.setdefault((r["cell"], r["round"]), {}).setdefault(r["run_id"], set()).add(r["server"])
    tports = {m: a.port + 1 + i for i, m in enumerate(("echo", "sink", "source"))}
    bad = proc.strays([a.port, *tports.values()])
    if bad:
        sys.exit("; ".join(bad))
    proc.install_handlers()
    meta = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "argv": sys.argv, "servers": names, "ref": a.ref,
            "cells": [c["cell"] for c in cells], "rounds": a.rounds, "dur": a.dur, "warmup": a.warmup, "settle": a.settle,
            "cmds": {n: srvs[n].cmd for n in names}, "extra": {n: srvs[n].extra for n in names},
            "fw": os.environ.get("FINALWISP_BIN"), "nproc": os.cpu_count(), "kernel": os.uname().release,
            "cpu": next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")}
    metap = os.path.join(a.out, "meta.jsonl")
    if os.path.exists(metap):
        first = json.loads(open(metap).readline())
        same = ("servers", "ref", "cells", "rounds", "dur", "warmup", "settle")
        if any(first[k] != meta[k] for k in same):
            sys.exit(f"{metap}: an earlier run of this OUT_DIR had other settings ({', '.join(same)} must match)")
    if os.path.exists(os.path.join(a.out, "DONE")):
        os.replace(os.path.join(a.out, "DONE"), os.path.join(a.out, "DONE.old"))
    with open(metap, "a") as f:
        f.write(json.dumps(meta) + "\n")
    targets = [wbench.start_target(wb, p, m, log=os.path.join(logdir, f"target-{m}.log")) for m, p in tports.items()]
    k_arms = len(names)
    base = [0]
    for i in range(1, k_arms):
        base.append((i + 1) // 2 if i % 2 else k_arms - i // 2)
    try:
        with open(rawp, "a") as raw:
            for cell in cells:
                while os.path.exists(os.path.join(a.out, "PAUSE")):
                    time.sleep(5)
                for rnd in range(a.rounds):
                    if any(set(names) <= s for s in have.get((cell["cell"], rnd), {}).values()):
                        continue
                    order = [names[(b + rnd) % k_arms] for b in base]
                    for slot, n in enumerate(order):
                        if any(t.poll() is not None for t in targets):
                            sys.exit("a wbench target exited: stop")
                        rec = one_run(wb, srvs[n], cell, a.port, tports, a, logdir)
                        if rec.pop("fatal", False):
                            sys.exit(rec["error"])
                        if any(t.poll() is not None for t in targets):  # the run is not the server's fault: not written
                            sys.exit("a wbench target exited during a run: stop (the round is redone on resume)")
                        rec = {"cell": cell["cell"], "round": rnd, "slot": slot, "server": n, "run_id": meta["started"], **rec}
                        raw.write(json.dumps(rec) + "\n")
                        raw.flush()
                        print(f"{cell['cell']} r{rnd} s{slot} {n}: {rec.get('value')} {rec.get('error', '')}", file=sys.stderr, flush=True)
                        time.sleep(0.3)
    finally:
        for t in targets:
            proc.stop(t, 0)
    with open(os.path.join(a.out, "DONE"), "w") as f:
        f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ\n", time.gmtime()))


if __name__ == "__main__":
    main()
