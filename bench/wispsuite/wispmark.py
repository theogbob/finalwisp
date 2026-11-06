"""30.03 wispmark (30.10: `wst wispmark`): WispMark-style benchmark (same clients, same methodology) with extra metrics.

What is the same as WispMark (github.com/MercuryWorkshop/WispMark):
  - every Wisp server is paired with every real Wisp client:
      wisp-js (10), wisp-js (5x10)   = WispMark's own client.mjs (wisp-js client, 10 streams of 50 KiB sends)
      wisp-mux (10), wisp-mux (5x10) = epoxy-tls simple-wisp-client -s 10 -p 50
  - all streams go to a TCP echo server; the score is the traffic through the echo port
    (in + out, like WispMark's iftop "Cumulative total"), after 1 s of warmup, over --duration seconds
  - the server is restarted for every cell; the same server configs WispMark uses
What is extra:
  - in/out split, server cores, client cores (summed over process groups), server peak RSS,
    MiB/s per server core, stalls (a cell is flagged if traffic stops)
  - no sudo/iftop: the echo server counts bytes itself (wbench target cumulative counters)

Profiles (what WispMark's numbers mean depends on the versions; INVENTORY/README "WispMark comparison"):
  current   wisp-js 0.5.0 client + server at the library's default log level (project policy 2026-10-22)
  upstream  WispMark's own pins: wisp-js 0.4.1 client + server with DEBUG logging (baselines/legacy/)
Both: epoxy-server single/multithread with WispMark's TOML, wisp-server-python as WispMark runs it, wispurr
(= mrrowisp) with WispMark's settings, and finalwisp ($FINALWISP_BIN, $FINALWISP_ARGS). WispMark also sets
websocketTcpNoDelay for mrrowisp; wispurr has no such key (ignored), so it is not set here.
Remaining differences to WispMark: the echo target is wbench (tokio) instead of tokio's echo-tcp example, and the
score counts TCP payload at the echo server over the exact window (WispMark: sudo iftop IP bytes / wall time
around iftop, which reads a few % lower). Ranking only changes for servers within ~5% of each other.

usage: wst wispmark [--profile current|upstream] [--duration 10] [--servers a,b] [--clients a,b] [--print-md]
  --servers: display names (default all), registry names, or fw:PATH for another finalwisp build
"""
import argparse, json, os, re, subprocess, sys, threading, time
from . import proc, report, servers as srvmod, wbench
from .sample import group_usage

HERE = report.BENCH
ROOT = srvmod.ROOT
WBENCH = None  # set in main (wbench.find)
SWC = os.path.join(ROOT, "ref/epoxy-tls/target/release/simple-wisp-client")
B, DIM, R, RED = "\033[1m", "\033[2m", "\033[0m", "\033[31m"
COL = {"finalwisp": "\033[1;32m", "epoxy": "\033[1;33m", "wisp-js": "\033[1;36m", "wisp-server": "\033[1;35m",
       "wispurr": "\033[1;34m"}


def color(name):
    return next((c for k, c in COL.items() if name.startswith(k)), B)


# ---------------------------------------------------------------- servers (WispMark configs, from bench/servers.json)
SERVERS = {  # display name -> registry name, per profile
    "current": {"finalwisp": "finalwisp", "epoxy-server (singlethread)": "epoxy-single", "epoxy-server (multithread)": "epoxy-multi",
                "wisp-js": "wisp-js", "wisp-server-python": "python-wispmark", "wispurr (wispmark cfg)": "wispurr-wispmark",
                "wispurr (speed cfg)": "wispurr"},
    "upstream": {"finalwisp": "finalwisp", "epoxy-server (singlethread)": "epoxy-single", "epoxy-server (multithread)": "epoxy-multi",
                 "wisp-js 0.4.1": "wisp-js-0.4.1", "wisp-server-python": "python-wispmark", "mrrowisp (wispurr, wispmark cfg)": "wispurr-wispmark"},
}
JS_CLIENT = {"current": "baselines/js-client", "upstream": "baselines/legacy/js-client-0.4.1"}


def server_for(display, profile):
    reg = srvmod.load()
    spec = SERVERS[profile].get(display, display)
    s = srvmod.resolve(spec, reg)
    if spec == "finalwisp" and os.environ.get("FINALWISP_ARGS"):
        s.cmd += " " + os.environ["FINALWISP_ARGS"]
    s.name = display
    return s


# ---------------------------------------------------------------- clients (WispMark set)
CLIENTS = {
    "wisp-js (10)": ("js", 1),
    "wisp-js (5x10)": ("js", 5),
    "wisp-mux (10)": ("mux", 1),
    "wisp-mux (5x10)": ("mux", 5),
}


def client_cmds(kind, n, port, echo_port, profile="current"):
    if kind == "js":
        return [(f"exec node client.mjs {port} {echo_port} 10", os.path.join(ROOT, JS_CLIENT[profile]))] * n
    return [(f"exec {SWC} -w ws://127.0.0.1:{port}/ -t 127.0.0.1:{echo_port} -s 10 -p 50", None)] * n


# ---------------------------------------------------------------- process helpers
def start(cmd, cwd=None, stderr=None):
    return proc.spawn(cmd, shell=True, cwd=cwd, stderr=stderr)


def usage(pgids):
    """(cpu seconds, rss bytes) summed over all processes of the given process groups."""
    cpu, rss, _ = group_usage(pgids)
    return cpu, rss * 2**20


def stop(p):
    proc.stop(p)


class Echo:
    """wbench echo target; a thread keeps the latest cumulative byte counters with arrival time."""
    LINE = re.compile(r"cum_in=(\d+) cum_out=(\d+)")

    def __init__(self, port):
        self.p = start(f"exec {WBENCH} target --port {port} --mode echo --report 100", stderr=subprocess.PIPE)
        self.samples = []  # (t, in, out)
        self.lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stderr:
            m = self.LINE.search(line)
            if m:
                with self.lock:
                    self.samples.append((time.time(), int(m.group(1)), int(m.group(2))))
                    del self.samples[:-600]

    def at(self, t):
        """counters at the first sample at or after time t (None if not yet available)."""
        with self.lock:
            for s in self.samples:
                if s[0] >= t:
                    return s
        return None

    def latest(self):
        with self.lock:
            return self.samples[-1] if self.samples else None


# ---------------------------------------------------------------- table (WispMark's own format)
def get_table(table, print_md):
    corner = "-|-" if print_md else "-+-"
    widths = [max(len(table[y][x]) for y in range(len(table))) for x in range(len(table[0]))]
    rows = []
    for row in table:
        line = " | ".join(c.ljust(widths[x]) for x, c in enumerate(row))
        rows.append(f"| {line} |" if print_md else line)
    sep = corner.join("-" * w for w in widths) + "-"
    if print_md:
        sep = f"|-{sep}|"
        return f"\n{sep}\n".join(rows[:2]) + "\n" + "\n".join(rows[2:])
    return f"\n{sep}\n".join(rows)


def fmt_mib(v):
    return f"{round(v, 2)} MiB/s"


def bar(frac, width=24):
    frac = max(0.0, min(1.0, frac))
    full = int(frac * width)
    part = " ▏▎▍▌▋▊▉"[int((frac * width - full) * 8)]
    return ("█" * full + (part if full < width else "")).ljust(width)


# ---------------------------------------------------------------- one cell
def run_cell(sname, cname, args, echo):
    port, eport = args.port, args.echo_port
    if not proc.wait_free(port):
        return {"error": f"port {port} busy"}
    try:
        sp = server_for(sname, args.profile).start(port, srvmod.SCRATCH)
    except RuntimeError:
        return {"error": "server did not start"}
    time.sleep(0.3)
    kind, n = CLIENTS[cname]
    cps = [start(c, d) for c, d in client_cmds(kind, n, port, eport, args.profile)]
    t_start = time.time()
    t_meas = t_start + 1.0  # WispMark: sleep 1 s, then measure
    t_end = t_meas + args.duration
    s0 = c0 = None
    e0 = None
    peak_rss = 0
    stalled_ticks = 0
    last_e, last_t = None, None
    col = color(sname)
    while time.time() < t_end:
        time.sleep(0.25)
        now = time.time()
        scpu, srss = usage([sp.pid])
        ccpu, _ = usage([c.pid for c in cps])
        peak_rss = max(peak_rss, srss)
        e = echo.latest()
        if s0 is None and now >= t_meas:
            s0, c0, ts0 = scpu, ccpu, now
        if e0 is None and now >= t_meas:
            e0 = echo.at(t_meas)  # may arrive a tick later; retried every loop
        live = 0.0
        if e and last_e and e[0] > last_e[0]:
            live = ((e[1] + e[2]) - (last_e[1] + last_e[2])) / (e[0] - last_e[0]) / 2**20
            if now >= t_meas and live < 1.0:
                stalled_ticks += 1
        if e:
            last_e = e
        phase = "warmup " if now < t_meas else "measure"
        frac = (now - t_start) / (t_end - t_start)
        ds = scpu - last_t[0] if last_t else 0.0
        dc = ccpu - last_t[1] if last_t else 0.0
        dt_s = now - last_t[2] if last_t else 1.0
        last_t = (scpu, ccpu, now)
        sys.stdout.write(f"\r  {col}{sname[:27]:<27}{R} × {cname:<15} {DIM}{phase}{R} [{bar(frac, 16)}] "
                         f"{B}{live:8.1f}{R} MiB/s  srv {ds / dt_s:4.1f} cores  cli {dc / dt_s:4.1f}  "
                         f"RSS {srss / 2**20:6.1f} MiB   ")
        sys.stdout.flush()
        if sp.poll() is not None:
            break
    # final sample: first echo sample at/after t_end
    wait_end = time.time() + 1.0
    if e0 is None:
        e0 = echo.at(t_meas)
    e1 = echo.at(t_end)
    while e1 is None and time.time() < wait_end:
        time.sleep(0.05)
        e1 = echo.at(t_end)
    scpu1, _ = usage([sp.pid])
    ccpu1, _ = usage([c.pid for c in cps])
    t1 = time.time()
    alive = sp.poll() is None
    for c in cps:
        stop(c)
    stop(sp)
    sys.stdout.write("\r\033[K")
    if not alive:
        return {"error": "server crashed"}
    if not (e0 and e1) or e1[0] <= e0[0]:
        return {"error": "no echo samples"}
    dt = e1[0] - e0[0]
    bin_ = (e1[1] - e0[1]) / dt / 2**20
    bout = (e1[2] - e0[2]) / dt / 2**20
    win = max(t1 - ts0, 1e-3)
    srv_cores = (scpu1 - s0) / win
    return {"mib_s": bin_ + bout, "mib_s_in": bin_, "mib_s_out": bout, "server_cores": srv_cores,
            "client_cores": (ccpu1 - c0) / win, "server_peak_rss_mib": peak_rss / 2**20,
            "mib_s_per_core": (bin_ + bout) / srv_cores if srv_cores > 0.05 else 0.0,
            "stalled_s": stalled_ticks * 0.25}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wst wispmark", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=sorted(SERVERS), default="current")
    ap.add_argument("--duration", type=int, default=10, help="seconds per test (WispMark default 10)")
    ap.add_argument("--servers", default=None, help="comma list; default all of the profile")
    ap.add_argument("--clients", default=",".join(CLIENTS), help="comma list; default all four")
    ap.add_argument("--port", type=int, default=6001)
    ap.add_argument("--echo-port", type=int, default=6002)
    ap.add_argument("--print-md", action="store_true", help="print markdown tables (like WispMark --print-md)")
    ap.add_argument("--output", default=None, help="markdown output file (default bench/results/wispmark-<ts>.md)")
    args = ap.parse_args(argv)
    global WBENCH
    WBENCH = wbench.find()
    servers = [s.strip() for s in (args.servers or ",".join(SERVERS[args.profile])).split(",") if s.strip()]
    clients = [c.strip() for c in args.clients.split(",") if c.strip()]
    for s in servers:
        server_for(s, args.profile)  # exits with the list of known names if unknown
    for c in clients:
        if c not in CLIENTS:
            sys.exit(f"unknown client '{c}'. known: {', '.join(CLIENTS)}")
    for need in (WBENCH, SWC):
        if not os.path.exists(need):
            sys.exit(f"missing {need}; build it first (see bench/README or ref/epoxy-tls)")
    bad = proc.strays([args.port, args.echo_port])
    if bad:
        sys.exit("; ".join(bad) + " (another server/benchmark running?). Use --port/--echo-port.")
    proc.install_handlers()

    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
    cpu_s = f"{cpu} (x{os.cpu_count()})"
    load = os.getloadavg()[0]
    n_cells = len(servers) * len(clients)
    print(f"\n{B}WispMark (finalwisp edition, profile {args.profile}){R}  {len(servers)} servers × {len(clients)} clients = {n_cells} tests, "
          f"~{n_cells * (args.duration + 3) / 60:.1f} min")
    print(f"CPU: {cpu_s}   load avg {load:.1f}" + (f"  {RED}(busy machine: noisy results){R}" if load > 2 else ""))
    print(f"{DIM}score = traffic through the echo port (in+out), like WispMark's iftop total{R}\n")

    echo = Echo(args.echo_port)
    if not proc.wait_port(args.echo_port, 10, echo.p):
        sys.exit("echo server failed to start")
    results = {}
    try:
        for s in servers:
            for c in clients:
                r = run_cell(s, c, args, echo)
                results[(s, c)] = r
                col = color(s)
                if "error" in r:
                    print(f"  {col}{s:<27}{R} × {c:<15} {RED}DNF ({r['error']}){R}")
                else:
                    stall = f"  {RED}stalled {r['stalled_s']:.1f}s{R}" if r["stalled_s"] >= 1 else ""
                    print(f"  {col}{s:<27}{R} × {c:<15} {B}{r['mib_s']:9.1f} MiB/s{R}  "
                          f"{DIM}srv{R} {r['server_cores']:4.1f} cores  {DIM}cli{R} {r['client_cores']:4.1f}  "
                          f"{DIM}RSS{R} {r['server_peak_rss_mib']:6.1f} MiB{stall}")
            print()
    finally:
        stop(echo.p)

    # ---- WispMark's table, exactly its format
    table = [[""] + clients]
    for s in servers:
        row = [s]
        for c in clients:
            r = results[(s, c)]
            if "error" in r:
                row.append("DNF")
            else:  # WispMark prints whatever it measured; we also flag cells where traffic stopped
                row.append(fmt_mib(r["mib_s"]) + (" (stall)" if r["stalled_s"] >= 1 else ""))
        table.append(row)
    header = f"CPU: {cpu_s}\nTest duration: {args.duration}s\nProfile: {args.profile}"
    print(f"{B}WispMark has finished.{R}\n\n{header}\n")
    print(get_table(table, args.print_md))

    # ---- extra: per-client ranking bars
    print(f"\n{B}Ranking per client{R} (bar = share of the best)")
    for c in clients:
        ok = sorted(((s, results[(s, c)]) for s in servers if "error" not in results[(s, c)]), key=lambda x: -x[1]["mib_s"])
        if not ok:
            continue
        best = ok[0][1]["mib_s"] or 1
        print(f"  {B}{c}{R}")
        for s, r in ok:
            lead = f"  ×{best / r['mib_s']:.2f} slower" if r is not ok[0][1] and r["mib_s"] > 0 else ""
            print(f"    {color(s)}{s:<27}{R} {color(s)}{bar(r['mib_s'] / best)}{R} {r['mib_s']:9.1f} MiB/s{DIM}{lead}{R}")

    # ---- extra: detail table
    det = [["server", "client", "total MiB/s", "in", "out", "srv cores", "cli cores", "MiB/s per srv core", "srv RSS MiB", "stall s"]]
    for s in servers:
        for c in clients:
            r = results[(s, c)]
            if "error" in r:
                det.append([s, c, "DNF", "", "", "", "", "", "", r["error"]])
            else:
                det.append([s, c, f"{r['mib_s']:.1f}", f"{r['mib_s_in']:.1f}", f"{r['mib_s_out']:.1f}",
                            f"{r['server_cores']:.2f}", f"{r['client_cores']:.2f}", f"{r['mib_s_per_core']:.0f}",
                            f"{r['server_peak_rss_mib']:.1f}", f"{r['stalled_s']:.1f}"])
    print(f"\n{B}Details{R}\n")
    print(get_table(det, args.print_md))
    notes = [f"- {s}: {server_for(s, args.profile).note}" for s in servers if server_for(s, args.profile).note]
    if notes:
        print("\nNotes:\n" + "\n".join(notes))

    out = args.output or os.path.join(HERE, "results", time.strftime("wispmark-%Y%m%d-%H%M%S.md"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write(f"```\n{header}\nload avg: {load:.1f}\n```\n\n{get_table(table, True)}\n\n## Details\n\n{get_table(det, True)}\n")
        if notes:
            f.write("\n" + "\n".join(notes) + "\n")
    report.write(out.replace(".md", ".json"), "wispmark", binaries=[WBENCH, SWC], profile=args.profile, cpu=cpu_s,
                 duration=args.duration, load=load,
                 results=[{"server": s, "client": c, **results[(s, c)]} for s in servers for c in clients])
    print(f"\n{DIM}saved {out} (+ .json){R}")

