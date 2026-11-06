"""30.02 showdown (30.10: `wst showdown`): live, visual head-to-head of Wisp servers on this machine.

usage:  wst showdown                                   # finalwisp vs epoxy vs wisp-js vs python vs wispurr, 4 key tests
        wst showdown --all                             # all 8 cases
        wst showdown --servers finalwisp,epoxy --duration 8
        wst showdown --servers fw:path/to/finalwisp,epoxy   # any build; or NAME='cmd --port {port}'
Servers come from bench/servers.json (or --config MATRIX.json with a "servers" list).

Shows, per server and test: result, server cores used (summed over the server's session),
client cores used (to prove the load generator is not the limit), peak RSS. Results saved to
bench/results/showdown-<timestamp>.json (schema wispsuite/1). Stdlib only, no sudo.
"""
import argparse, json, os, subprocess, sys, time
from . import proc, report, servers as srvmod, wbench
from .sample import group_usage as _gu

HERE = report.BENCH
COLORS = {"finalwisp": "\033[1;32m", "epoxy": "\033[1;33m", "wisp-js": "\033[1;36m", "python": "\033[1;35m",
          "wispurr": "\033[1;34m", "wispx": "\033[1;31m", "wispx-nodelay": "\033[1;31m"}
B, DIM, R = "\033[1m", "\033[2m", "\033[0m"

KEY_CASES = [  # (test, conns, streams, size, metric, unit, higher_is_better)
    ("download", 10, 10, 0, "mib_s_down", "MiB/s", True),
    ("upload", 1, 1, 16384, "mib_s_up", "MiB/s", True),
    ("rr", 10, 10, 64, "rps", "req/s", True),
    ("churn", 10, 10, 64, "rps", "streams/s", True),
]
ALL_CASES = [
    ("upload", 1, 1, 16384, "mib_s_up", "MiB/s", True),
    ("upload", 10, 10, 16384, "mib_s_up", "MiB/s", True),
    ("download", 10, 10, 0, "mib_s_down", "MiB/s", True),
    ("echo", 1, 1, 16384, "mib_s_down", "MiB/s", True),
    ("echo", 10, 10, 16384, "mib_s_down", "MiB/s", True),
    ("rr", 1, 1, 64, "rps", "req/s", True),
    ("rr", 10, 10, 64, "rps", "req/s", True),
    ("churn", 10, 10, 64, "rps", "streams/s", True),
]
MODE = {"upload": "sink", "download": "source", "echo": "echo", "rr": "echo", "churn": "echo"}


def group_usage(pgid):
    """(cpu_seconds, rss_bytes) summed over live processes in a group or session."""
    cpu, rss, _ = _gu(pgid)
    return cpu, rss * 2**20


def time_wait():
    for line in open("/proc/net/sockstat"):
        if line.startswith("TCP:"):
            p = line.split()
            return int(p[p.index("tw") + 1])
    return 0


def bar(frac, width=28):
    frac = max(0.0, min(1.0, frac))
    full = int(frac * width)
    part = " ▏▎▍▌▋▊▉"[int((frac * width - full) * 8)]
    return ("█" * full + (part if full < width else "")).ljust(width)


def fmt(v, unit):
    if unit == "MiB/s" and v >= 1024:
        return f"{v / 1024:6.2f} GiB/s"
    if v >= 1e6:
        return f"{v / 1e6:6.2f}M {unit}"
    if v >= 1e4:
        return f"{v / 1e3:6.1f}k {unit}"
    return f"{v:7.0f} {unit}"


def run_case(srv, case, port, tports, args):
    test, conns, streams, size, metric, unit, _ = case
    if not proc.wait_free(port):
        return {"error": f"port {port} busy"}
    try:
        sp = srv.start(port, srvmod.SCRATCH)
    except RuntimeError:
        return {"error": "server did not start"}
    target = f"127.0.0.1:{tports[MODE[test]]}"
    wargs = [args.wbench, "run", "--url", f"ws://127.0.0.1:{port}/", "--target", target, "--conns", str(conns),
             "--streams", str(streams), "--duration", str(args.duration), "--warmup", "1", "--test", test, "--json"]
    if size:
        wargs += ["--size", str(size)]
    wargs += srv.extra
    cp = proc.spawn(wargs, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    t0 = time.monotonic()
    total = 1 + args.duration
    s_cpu0 = c_cpu0 = None
    last = (t0, group_usage(sp.pid)[0], group_usage(cp.pid)[0])
    peak_rss = 0
    color = COLORS.get(srv.name, B)
    while cp.poll() is None:
        time.sleep(0.25)
        if cp.poll() is not None:
            break
        now = time.monotonic()
        scpu, srss = group_usage(sp.pid)
        ccpu, _ = group_usage(cp.pid)
        # 30.13: /proc returns zero after exit. Never replace the last live sample,
        # including when the client exits DURING the scan (not only during sleep).
        if cp.poll() is not None:
            break
        peak_rss = max(peak_rss, srss)
        if s_cpu0 is None and now - t0 >= 1.0:  # end of warmup
            s_cpu0, c_cpu0, tm0 = scpu, ccpu, now
        dt = max(now - last[0], 1e-3)
        s_live, c_live = (scpu - last[1]) / dt, (ccpu - last[2]) / dt
        last = (now, scpu, ccpu)
        el = now - t0
        phase = "warmup " if el < 1 else "measure"
        sys.stdout.write(f"\r  {color}{srv.name:<10}{R} {DIM}{phase}{R} [{bar(el / total, 20)}] {el:4.1f}s  "
                         f"server {B}{s_live:5.1f}{R} cores  client {s_fmt(c_live)} cores  RSS {srss / 2**20:6.1f} MiB   ")
        sys.stdout.flush()
    end = time.monotonic()
    scpu1, _ = group_usage(sp.pid)
    ccpu1, c_end = last[2], last[0]  # client is gone now: use its last live sample
    out = cp.stdout.read()
    alive = sp.poll() is None
    proc.stop(sp)
    proc.stop(cp, 0)
    sys.stdout.write("\r\033[K")
    line = next((l for l in reversed(out.splitlines()) if l.startswith("{")), None)
    if not line:
        return {"error": "no result (client failed)", "server_alive": alive}
    r = json.loads(line)
    win = max(end - (tm0 if s_cpu0 is not None else t0), 1e-3)
    r["server_cores"] = (scpu1 - (s_cpu0 or 0)) / win
    r["client_cores"] = max(0.0, (ccpu1 - (c_cpu0 or 0)) / max(c_end - (tm0 if s_cpu0 is not None else t0), 1e-3))
    r["server_peak_rss_mib"] = peak_rss / 2**20
    r["server_alive"] = alive
    r["value"] = r.get(metric, 0)
    return r


def s_fmt(x):
    return f"{x:4.1f}"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wst showdown", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=None, help="a matrix JSON whose \"servers\" list is used instead of the registry")
    ap.add_argument("--wbench", default=None)
    ap.add_argument("--servers", default="finalwisp,epoxy,wisp-js,python,wispurr")
    ap.add_argument("--duration", type=int, default=5)
    ap.add_argument("--all", action="store_true", help="run all 8 cases instead of the 4 key ones")
    ap.add_argument("--case", action="append", default=[], metavar="TEST:CONNS:STREAMS[:SIZE]",
                    help="run this case (repeatable) instead of the default list, e.g. download:100:10")
    ap.add_argument("--port", type=int, default=6301, help="server port; targets use port+1..+3")
    ap.add_argument("--tw-wait", type=int, default=65, help="max seconds to wait for TIME_WAIT to drain before churn")
    args = ap.parse_args(argv)
    args.wbench = wbench.find(args.wbench)
    if not os.path.exists(args.wbench):
        sys.exit(f"build the load generator first: (cd {HERE} && cargo build --release)")
    reg = srvmod.load()
    if args.config:
        reg = {}
        for e in json.load(open(args.config))["servers"]:
            sv = srvmod.resolve(e, srvmod.load())
            reg[sv.name] = sv
    servers, names = {}, []
    for spec in [n for n in args.servers.split(",") if n]:
        sv = reg[spec] if isinstance(reg.get(spec), srvmod.Server) else srvmod.resolve(spec, reg)
        servers[sv.name] = sv
        names.append(sv.name)
    proc.install_handlers()
    cases = ALL_CASES if args.all else KEY_CASES
    if args.case:
        if args.all:
            sys.exit("wst showdown: --case and --all exclude each other")
        cases = []
        for c in args.case:
            f = c.split(":")
            try:
                if len(f) not in (3, 4) or f[0] not in MODE:
                    raise ValueError
                test, conns, streams = f[0], int(f[1]), int(f[2])
                size = int(f[3]) if len(f) == 4 else (16384 if test in ("upload", "echo") else 64 if test in ("rr", "churn") else 0)
                if conns < 1 or streams < 1 or (test != "download" and size < 1):
                    raise ValueError
            except ValueError:
                sys.exit(f"--case {c}: expected TEST:CONNS:STREAMS[:SIZE] (positive numbers), TEST one of {', '.join(MODE)}")
            metric, unit = {"upload": ("mib_s_up", "MiB/s"), "download": ("mib_s_down", "MiB/s"), "echo": ("mib_s_down", "MiB/s"),
                            "rr": ("rps", "req/s"), "churn": ("rps", "streams/s")}[test]
            cases.append((test, conns, streams, size, metric, unit, True))

    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
    load = os.getloadavg()[0]
    print(f"\n{B}Wisp server showdown{R}  {cpu}  ×{os.cpu_count()} cpus  kernel {os.uname().release}")
    print(f"load avg {load:.1f}" + (f"  {B}\033[31m(busy machine: results will be noisy){R}" if load > 2 else "")
          + f"  duration {args.duration}s + 1s warmup per run\n")

    tports = {"echo": args.port + 1, "sink": args.port + 2, "source": args.port + 3}
    bad = proc.strays([args.port] + list(tports.values()))
    if bad:
        sys.exit("; ".join(bad) + ". Use --port N.")
    results = []
    targets = []
    try:
        for m, p in tports.items():
            targets.append(wbench.start_target(args.wbench, p, m))
        for case in cases:
            test, conns, streams, size, metric, unit, hib = case
            print(f"{B}▶ {test}{R}  {conns} conn × {streams} streams" + (f", {size} B packets" if size else "")
                  + f"   {DIM}(metric: {unit}){R}")
            rows = []
            for n in names:
                if test == "churn":
                    t_end = time.time() + args.tw_wait
                    while time_wait() > 2000 and time.time() < t_end:
                        sys.stdout.write(f"\r  {DIM}waiting for TIME_WAIT to drain ({time_wait()} sockets, "
                                         f"{t_end - time.time():3.0f}s max) so every server starts clean{R}   ")
                        sys.stdout.flush()
                        time.sleep(1)
                    sys.stdout.write("\r\033[K")
                r = run_case(servers[n], case, args.port, tports, args)
                r.update(server=n, test=test, conns=conns, streams=streams, size=size, metric=metric, unit=unit)
                rows.append(r)
                results.append(r)
            best = max((r.get("value", 0) for r in rows), default=0) or 1
            for r in sorted(rows, key=lambda r: -r.get("value", 0)):
                color = COLORS.get(r["server"], B)
                if "error" in r:
                    print(f"  {color}{r['server']:<10}{R} \033[31mERROR: {r['error']}{R}")
                    continue
                lat = f"  p50 {r['p50_us']}µs p99 {r['p99_us']}µs" if test in ("rr", "churn") else ""
                err = f"  \033[31merrors {r['errors']}{R}" if r.get("errors") else ""
                print(f"  {color}{r['server']:<10}{R} {color}{bar(r['value'] / best)}{R} {B}{fmt(r['value'], unit)}{R}"
                      f"  {DIM}server{R} {r['server_cores']:4.1f} cores  {DIM}client{R} {r['client_cores']:4.1f}"
                      f"  {DIM}RSS{R} {r['server_peak_rss_mib']:6.1f} MiB{lat}{err}")
            print()
    finally:
        for t in targets:
            proc.stop(t)

    # summary
    print(f"{B}Summary{R} (higher is better; × = how many times the best other server)")
    hdr = f"  {'test':<16}" + "".join(f"{n:>19}" for n in names) + "   winner"
    print(hdr)
    for case in cases:
        test, conns, streams, size, metric, unit, _ = case
        rows = {r["server"]: r for r in results if r["test"] == test and r["conns"] == conns and r["streams"] == streams and r["size"] == size}
        vals = {n: rows[n].get("value", 0) for n in names if n in rows and "error" not in rows[n]}
        if not vals:
            continue
        win = max(vals, key=vals.get)
        others = [v for n, v in vals.items() if n != win]
        ratio = f"  ×{vals[win] / max(others):.2f}" if others and max(others) > 0 else ""
        label = f"{test} {conns}x{streams}"
        cells = "".join(f"{fmt(vals[n], unit).strip():>19}" if n in vals else f"{'ERR':>19}" for n in names)
        print(f"  {label:<16}{cells}   {COLORS.get(win, B)}{win}{R}{ratio}")
    eff = [r for r in results if "error" not in r and r.get("server_cores", 0) > 0.05]
    if eff:
        print(f"\n{B}Efficiency{R} (result per server core used)")
        for case in cases:
            test, conns, streams, size, metric, unit, _ = case
            rs = [r for r in eff if r["test"] == test and r["conns"] == conns and r["streams"] == streams and r["size"] == size]
            if rs:
                cells = "  ".join(f"{r['server']} {fmt(r['value'] / r['server_cores'], unit).strip()}/core" for r in rs)
                print(f"  {test} {conns}x{streams}: {cells}")
    path = report.write(os.path.join(HERE, "results", time.strftime("showdown-%Y%m%d-%H%M%S.json")), "showdown",
                        binaries=[args.wbench], cpu=cpu, nproc=os.cpu_count(), load=load, duration=args.duration, results=results)
    print(f"\n{DIM}saved {path}{R}")

