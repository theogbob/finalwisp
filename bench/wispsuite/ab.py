"""Rotated, interleaved A/B of server variants with wbench (30.10; was bench/ab.py, 30.09 / 20.19).

usage: wst ab VARIANTS.json REPS [suite options] WBENCH-RUN-ARGS...   (e.g. --test download --conns 10 --streams 10)
  VARIANTS.json: {"name": "server command (gets --port PORT appended)", ...}
  suite options (default from the env var in brackets):
    --port P (PORT, 6901)  --tport P (TPORT, 6902)  --tmode M (TMODE; default by test)  --dur S (DUR, 4)
    --warmup S (WARMUP, 1)  --raw FILE (RAW: one JSON record per run)  --link LABEL (LINK, lo)  --tls (AB_TLS=1)
    --fixed-order (FW_AB_ROTATE=0)
    --order rotate|random|balanced (AB_ORDER, rotate): the slot order of the arms in a round. rotate = the start arm
      moves one place per round (as always). random = a shuffle per round (seeded with the round number: the same
      command gives the same orders). balanced = all orders of the arms in turn (2 to 4 arms; 3 arms = 6 orders).
    --settle S (AB_SETTLE, 0 = off): before each run wait until the host's TCP memory is back at its value before
      the first run (+ 64 pages), at most S seconds; the record gets settle_s.
    --client-ssh [USER@]HOST [--server-ip IP] [--force-clean]: cross-host (root; bench/wispsuite/xhost.py): server +
      target on this box bound to its address facing HOST (variants get --host IP), wbench on HOST via ssh, iptables
      lets only HOST reach the ports during the run
  netns runs (root): SRV_PREFIX / CLI_PREFIX (e.g. "ip netns exec fws"), SRV_HOST, SRV_BIND env vars.
Every rep runs every variant once; the start variant rotates per rep (position bias). The server and the wbench
client each run in their own process group; a SIGTERM/SIGINT stops both (no strays). A stray process or listener
on PORT/TPORT stops the run before it starts (a leftover reuseport target silently takes half the streams).
Every raw record has t0 / tw0 / win_s / t1 (unix times: server start, client start, client wall, record written),
steal (host steal ticks during the client's run), slot (place in the round) and tcp_mem0 (host TCP pages before the run).
Prints one JSON line per variant: median + all values of the key metric (rps for rr/churn/connchurn/browse/udp-rr,
mib_s_up for upload, else mib_s_down), median server CPU% and RSS; browse adds latency and bulk.
--test connchurn: a new WebSocket connection per request (wbench; rps = connections/s).
--test burstidle: per run, 3 x (5 s download burst on new connections, 3 s idle) against one server process
  (suite-side, --dur/--warmup not used); mib_s_down = median burst, plus per-burst MiB/s and server CPU% for
  every burst and idle gap.
"""
import contextlib, itertools, json, os, random, sys, time
from . import proc, sample, wbench
from .stats import median


class AbError(Exception):
    pass


def run_ab(variants, reps, wb_args, *, wb, port="6901", tport="6902", tmode=None, dur="4", warmup="1", tls=False,
           raw=None, link="lo", srv_prefix=(), cli_prefix=(), srv_host="127.0.0.1", srv_bind="", rotate=True,
           verbose=True, client_ssh=None, tgt_host="127.0.0.1", order="rotate", settle=0.0):
    """Returns {variant: [record per rep]}. Raises AbError before starting anything if a port is taken.
    client_ssh (cross-host): wbench run executes on that host over ssh; the target binds tgt_host and the server
    is reached at srv_host (both this box's address facing the client; the caller sets the firewall)."""
    test = wb_args[wb_args.index("--test") + 1]
    tmode = tmode or wbench.target_mode(test)
    if client_ssh and tmode == "udp-echo":
        raise AbError("cross-host mode is TCP only (the firewall rules cover TCP; a public UDP echo would be a reflector)")
    netns = bool(srv_prefix)
    # netns: the servers live in another namespace, so a host listener with the same number does not matter
    bad = proc.strays([int(port), int(tport)], listeners=not netns)
    if bad:
        raise AbError("; ".join(bad))
    rawf = open(raw, "a") if raw else None
    tg = wbench.start_target(wb, tport, tmode, prefix=srv_prefix, wait=not netns,
                             extra=["--bind", tgt_host] if tgt_host != "127.0.0.1" else [])
    res = {k: [] for k in variants}
    names = list(variants)
    timeout = float(dur) + float(warmup) + 60
    tcp_max = sample.tcp_mem_max()  # 50.02 D
    pre = [*srv_prefix, *cli_prefix]
    nss = sorted({pre[i + 2] for i in range(len(pre) - 2) if pre[i] == "netns" and pre[i + 1] == "exec"})
    if order not in ("rotate", "random", "balanced"):
        raise AbError(f"--order {order}: rotate, random or balanced")
    if order == "balanced" and not 2 <= len(names) <= 4:
        raise AbError("--order balanced is for 2 to 4 arms")
    perms = list(itertools.permutations(names)) if order == "balanced" else None
    mem_idle = sample.tcp_mem_pages()
    try:
        for rep in range(reps):
            k = rep % len(names) if rotate else 0
            round_order = names[k:] + names[:k]
            if rotate and order == "random":
                round_order = list(names)
                random.Random(rep).shuffle(round_order)
            elif rotate and order == "balanced":
                round_order = list(perms[rep % len(perms)])
            for slot, name in enumerate(round_order):
                cmd = " ".join(srv_prefix) + " " + variants[name] + f" --port {port} {srv_bind}"
                settle_s = None
                if settle > 0 and mem_idle is not None:  # 80.03: TCP memory of the run before must not be this run's start state
                    ts = time.time()
                    while (sample.tcp_mem_pages() or 0) > mem_idle + 64 and time.time() - ts < settle:
                        time.sleep(0.1)
                    settle_s = round(time.time() - ts, 2)
                mem0 = sample.tcp_mem_pages()
                t_start = time.time()
                p = proc.spawn(cmd, shell=True)
                try:
                    ready = True
                    if not netns:
                        ready = proc.wait_port(int(port), 15, p, host=srv_host)
                    time.sleep(max(0.0, 0.5 - (time.time() - t_start)))  # >= 0.5 s as before: every worker has bound
                    if p.poll() is not None:
                        ready = False
                    pr0 = sample.tcp_pressure_both(nss)  # 60.42 verify: before the CPU window (review: subprocesses)
                    cpu0, _, _ = sample.group_usage(p.pid)
                    cg0 = cgroup_usage_s()
                    st0 = sample.steal_ticks()
                    t0 = time.time()
                    # 50.02 D: host TCP memory peak during the rep (this box: the server's; review: also cross-host)
                    mempk = sample.TcpMemPeak()
                    with mempk:
                        if ready and test == "burstidle":
                            j = burst_idle(wb, [*(["--insecure"] if tls else []), "--url", f"{'wss' if tls else 'ws'}://{srv_host}:{port}/",
                                                "--target", f"{tgt_host}:{tport}"] + list(wb_args), p, cli_prefix, client_ssh)
                        elif ready:
                            args = [*(["--insecure"] if tls else []), "--url", f"{'wss' if tls else 'ws'}://{srv_host}:{port}/",
                                    "--target", f"{tgt_host}:{tport}", "--duration", dur, "--warmup", warmup] + list(wb_args)
                            j = wbench.run(wb, args, timeout, prefix=cli_prefix, ssh=client_ssh)
                        else:
                            j = {"error": f"server did not start on :{port}"}
                    if mempk.samples:  # share of 0.05 s samples with the global pressure flag set (the robust metric)
                        j["tcp_press_frac"] = round(mempk.press_samples / mempk.samples, 3)
                    if mempk.max_seen is not None:
                        j["tcp_mem_peak"] = mempk.max_seen
                        j["at_tcp_mem_max"] = sample.at_tcp_mem_max(mempk.max_seen, tcp_max)
                    wall = time.time() - t0
                    st1 = sample.steal_ticks()
                    cg1 = cgroup_usage_s()  # before the /proc scan below, so its CPU stays outside the window
                    cpu1, rss, hwm = sample.group_usage(p.pid)
                finally:
                    proc.stop(p, 0)
                # 60.42 verify: entries / ms (TcpExt) read after the server is gone: the kernel credits
                # TCPMemoryPressuresChrono when pressure ends, usually at this rep's teardown (review P2);
                # a lower bound for pressure that outlives the rep (tcp_press_frac does not have that gap)
                time.sleep(0.2)
                pd = sample.pressure_delta(pr0, sample.tcp_pressure_both(nss))
                if pd is not None and isinstance(j, dict):
                    j["tcp_press"], j["tcp_press_ms"] = pd
                if not netns and not proc.wait_free(int(port), 30):
                    # 60.12 scale: the reaped server's sockets close asynchronously (gold t36 echo 100x10: 36 listeners +
                    # CLOSE_WAITs for > 0.3 s), and the next server's bind then failed with EADDRINUSE in every other rep
                    raise AbError(f"port {port} still has a listener 30 s after the server stopped")
                time.sleep(0.3)
                if "cpu_pct" not in j:  # burstidle sets its own (bursts only)
                    j["cpu_pct"] = round(100 * (cpu1 - cpu0) / wall, 1) if wall > 0 else 0
                if cg0 is not None and cg1 is not None and wall > 0 and not client_ssh and test != "burstidle":
                    # 60.12 scale tests: the whole cgroup (server + wbench client + target + suite) over the same window;
                    # client side CPU% ~= cg_cpu_pct - cpu_pct (shared boxes: server and client share the CPUs; not for
                    # burstidle, whose cpu_pct is the median burst; not valid if SRV_/CLI_PREFIX moves a process to another cgroup)
                    j["cg_cpu_pct"] = round(100 * (cg1 - cg0) / wall, 1)
                j["loadavg"] = [float(x) for x in open("/proc/loadavg").read().split()[:3]]  # host-wide inside a container
                j["rss_mib"] = round(rss, 1)
                j["hwm_mib"] = round(hwm, 1)
                # 80.03 (P6 of the performance audit): when the run was, so that the time budget of a round is a table and
                # a noisy run can be seen. t0 = the server's start, tw0 = the client's start (the window is inside
                # tw0..tw0+win_s), t1 = this record (after the stop and the settle); steal = host steal ticks over the
                # client's time (None where /proc/stat has no such column)
                # slot = the place of this run in its round (0 = first); tcp_mem0 = host TCP memory pages before the server start
                j.update(t0=round(t_start, 3), tw0=round(t0, 3), win_s=round(wall, 3), t1=round(time.time(), 3),
                         steal=None if st0 is None or st1 is None else st1 - st0, slot=slot, tcp_mem0=mem0)
                if settle_s is not None:
                    j["settle_s"] = settle_s
                if rawf:
                    rawf.write(json.dumps({"rep": rep, "v": name, "extra": " ".join(wb_args), "tls": tls, "link": link, **j}) + "\n")
                    rawf.flush()
                res[name].append(j)
                if verbose:
                    print(f"  {name}: {json.dumps(j)}", file=sys.stderr, flush=True)
    finally:
        proc.stop(tg, 0)
        if rawf:
            rawf.close()
    return res


def cgroup_usage_s():
    """CPU seconds used by this process's cgroup (v2 cpu.stat usage_usec), None if unreadable."""
    try:
        cg = open("/proc/self/cgroup").read().strip().split("::", 1)[-1]
        for l in open(f"/sys/fs/cgroup{cg.rstrip('/')}/cpu.stat"):
            k, v = l.split()
            if k == "usage_usec":
                return int(v) / 1e6
    except (OSError, ValueError):
        return None
    return None


BURSTS, BURST_S, IDLE_S = 3, 5, 3.0  # burstidle (30.10, parent design): 3 x (5 s download burst, 3 s idle)


def burst_idle(wb, args, p, cli_prefix=(), client_ssh=None):
    """burstidle: BURSTS x (one `wbench run --test download` of BURST_S s, no warmup, new connections each time;
    then IDLE_S s with no clients) against the SAME server process. Catches costs that appear only after the
    server went idle (memory returned to the OS and faulted back in, idle sweeps, timers). Record: mib_s_down =
    median burst; bursts_mib_s, burst_cpu_pct (server CPU% during each burst), idle_cpu_pct (during each idle
    gap); cpu_pct = median burst CPU%."""
    args = list(args)
    args[args.index("--test") + 1] = "download"
    args += ["--duration", str(BURST_S), "--warmup", "0"]
    bursts, cpus, idles, errors, j = [], [], [], 0, {}
    for k in range(BURSTS):
        c0, _, _ = sample.group_usage(p.pid)
        t0 = time.time()
        j = wbench.run(wb, args, BURST_S + 60, prefix=cli_prefix, ssh=client_ssh)
        c1, _, _ = sample.group_usage(p.pid)
        t1 = time.time()
        if "error" in j:
            return {"error": f"burst {k + 1}: {j['error']}"}
        if p.poll() is not None:
            return {"error": f"server exited during burst {k + 1}"}
        bursts.append(j.get("mib_s_down"))
        cpus.append(round(100 * (c1 - c0) / (t1 - t0), 1))
        errors += int(j.get("errors") or 0)
        time.sleep(IDLE_S)
        if p.poll() is not None:  # an idle-path crash (sweeps, timers, memory return) must not pass
            return {"error": f"server exited in the idle gap after burst {k + 1}"}
        c2, _, _ = sample.group_usage(p.pid)
        idles.append(round(100 * (c2 - c1) / (time.time() - t1), 2))
    return {**j, "test": "burstidle", "mib_s_down": median(bursts), "errors": errors, "bursts_mib_s": bursts,
            "burst_cpu_pct": cpus, "idle_cpu_pct": idles, "cpu_pct": median(cpus)}


def summarize(test, res):
    key = wbench.key_metric(test)
    lines = []
    for name, rs in res.items():
        ok = [r for r in rs if r.get(key) is not None]
        med = lambda f: median([r.get(f) for r in ok])
        line = {"variant": name, "test": test, "n": len(ok), key: med(key), "all": [r.get(key) for r in rs],
                "cpu_pct": med("cpu_pct"), "cg_cpu_pct": med("cg_cpu_pct"), "rss_mib": med("rss_mib"), "errors": sum(r.get("errors", 0) or 0 for r in ok)}
        if test in ("rr", "churn", "connchurn", "browse"):
            line.update(p50_us=med("p50_us"), p99_us=med("p99_us"))
        if test == "burstidle":
            line.update(bursts_mib_s=[r.get("bursts_mib_s") for r in rs], burst_cpu_pct=[r.get("burst_cpu_pct") for r in rs],
                        idle_cpu_pct=[r.get("idle_cpu_pct") for r in rs])
        if test == "browse":
            line.update(page_p50_us=med("page_p50_us"), page_p99_us=med("page_p99_us"), bulk_mib_s=med("bulk_mib_s"),
                        p50_all=[r.get("p50_us") for r in rs])
        lines.append(line)
    return lines


def main(argv):
    if len(argv) < 2 or argv[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if argv and argv[0] in ("-h", "--help") else 2)
    env = os.environ
    o = {"--port": env.get("PORT", "6901"), "--tport": env.get("TPORT", "6902"), "--tmode": env.get("TMODE") or None,
         "--dur": env.get("DUR", "4"), "--warmup": env.get("WARMUP", "1"), "--raw": env.get("RAW") or None,
         "--link": env.get("LINK", "lo"), "--client-ssh": None, "--server-ip": None,
         "--order": env.get("AB_ORDER", "rotate"), "--settle": env.get("AB_SETTLE", "0")}
    flags = {"--tls": env.get("AB_TLS", "0") == "1", "--fixed-order": env.get("FW_AB_ROTATE", "1") == "0", "--force-clean": False}
    variants = json.load(open(argv[0]))
    reps = int(argv[1])
    rest, extra, i = argv[2:], [], 0
    while i < len(rest):
        if rest[i] in o and i + 1 < len(rest):
            o[rest[i]] = rest[i + 1]; i += 2
        elif rest[i] in flags:
            flags[rest[i]] = True; i += 1
        else:
            extra.append(rest[i]); i += 1
    if "--test" not in extra:
        sys.exit("wst ab: --test is required")
    proc.install_handlers()
    wb = wbench.find()
    kw = dict(srv_prefix=env.get("SRV_PREFIX", "").split(), cli_prefix=env.get("CLI_PREFIX", "").split(),
              srv_host=env.get("SRV_HOST", "127.0.0.1"), srv_bind=env.get("SRV_BIND", ""), link=o["--link"])
    fw = contextlib.nullcontext()
    if o["--client-ssh"]:
        from . import xhost
        try:
            xh = xhost.Xhost(o["--client-ssh"], wb, o["--server-ip"])
            fw = xhost.firewall([int(o["--port"]), int(o["--tport"])], xh.client_ip, flags["--force-clean"])
        except xhost.XhostError as e:
            sys.exit(f"ab: {e}")
        if xh.md5_problem():
            print(f"ab: WARNING {xh.md5_problem()}", file=sys.stderr)
        print(f"ab: cross-host {xh.describe()}", file=sys.stderr)
        kw = dict(srv_host=xh.server_ip, srv_bind=f"--host {xh.server_ip}", tgt_host=xh.server_ip, client_ssh=xh.ssh,
                  link=xh.label if o["--link"] == "lo" else o["--link"])
    try:
        with fw:
            res = run_ab(variants, reps, extra, wb=wb, port=o["--port"], tport=o["--tport"], tmode=o["--tmode"],
                         dur=o["--dur"], warmup=o["--warmup"], tls=flags["--tls"], raw=o["--raw"],
                         rotate=not flags["--fixed-order"], order=o["--order"], settle=float(o["--settle"]), **kw)
    except AbError as e:
        sys.exit(f"ab: {e}")
    except Exception as e:  # xhost.XhostError from the firewall setup
        if type(e).__name__ != "XhostError":
            raise
        sys.exit(f"ab: {e}")
    for line in summarize(extra[extra.index("--test") + 1], res):
        print(json.dumps(line), flush=True)
    if o["--client-ssh"] and xhost.cleanup_errors:
        sys.exit("ab: " + "; ".join(xhost.cleanup_errors))
