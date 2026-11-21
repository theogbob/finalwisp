"""80.04: tables of timed single-box sessions (bench/wispsuite/timed.py raw.jsonl), pure functions.

Used by bench/tools/timebox.py (OUT/summary.json + OUT/TABLE.md, the 80.04 result contract) and by anyone who replays
the raw runs (statistics tools). Every number comes from the raw records:
- per run: the metrics of metrics() (latency percentiles from the run's own HDR buckets, CPU per unit of work from
  the window-edge counters over the same window as the rates);
- per arm: merged distributions (the buckets of all its runs added: exact, no samples) -> percentiles of pct();
- per pair (same round, or same sweep and step): wispsuite.stats.compare (HL ratio b/a, exact Wilcoxon, 90 % CI)
  per metric; "watch" (stats.py) is reported as "unclear" (the contract's four words).
Latency unit: microseconds (the raw buckets are ns)."""
import json, math, re, statistics as st
from collections import defaultdict
from . import stats

# metric -> (unit, higher is better)
METRICS = {
    "rate_mib_s": ("MiB/s", True), "rps": ("1/s", True),
    "p50": ("us", False), "p90": ("us", False), "p99": ("us", False), "p999": ("us", False),
    "mean": ("us", False), "max": ("us", False),
    "srv_us_per_msg": ("us CPU/msg", False), "srv_s_per_gib": ("s CPU/GiB", False), "srv_cpu": ("CPU s/s", False),
    "srv_sys_share": ("share", False), "cli_us_per_msg": ("us CPU/msg", False),
    "censored": ("share", False), "svc_p99": ("us", False), "lag_p50": ("us", False), "lag_p99": ("us", False),
}


def load(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def pct(buckets, q):
    """value (us) at quantile q of {ns: count}: the smallest bucket value whose cumulative count reaches q * n
    (n >= 1; q * n rounded up, at least 1)"""
    n = sum(buckets.values())
    if n == 0:
        return None
    want, cum = max(1, math.ceil(q * n - 1e-9)), 0
    for v in sorted(buckets):
        cum += buckets[v]
        if cum >= want:
            return v / 1000
    return max(buckets) / 1000


def buckets(d):
    return {int(v): int(c) for v, c in (d or {}).get("b", [])}


def merge(dists):
    out = defaultdict(int)
    for d in dists:
        for v, c in buckets(d).items():
            out[v] += c
    return dict(out)


def ok(rec):
    j = rec.get("j") or {}
    return "error" not in j and (j.get("errors") or 0) == 0 and rec.get("srv_alive", True)


def metrics(rec):
    """per-run metrics of one raw record (None where the run has no such number)"""
    j = rec.get("j") or {}
    test = rec["cell"].split(":")[0]
    l, e, o = j.get("lat") or {}, j.get("edges") or {}, j.get("ol")
    c = j.get("counts")  # 80.04 --counts: exact over the window (echo messages fully back, DATA packets each way)
    if c and c.get("msgs") is not None and c.get("window_s"):
        m = {"rps": c["msgs"] / c["window_s"]}
    elif test in ("rr", "churn", "connchurn", "browse", "udp-rr") or "ol" in j:  # wbench.RATE_TESTS + open loop: rps is measured
        m = {"rps": j.get("rps")}  # a measured 0 stays 0 (reported; ratios need both sides > 0)
    else:  # echo / byte tests without --counts: an older wbench prints rps 0 there = not counted
        m = {"rps": j.get("rps") or None}
    if c and c.get("window_s"):
        m["frames_up_s"] = c["frames_up"] / c["window_s"]
        m["frames_down_s"] = c["frames_down"] / c["window_s"] if c.get("frames_down") is not None else None
    m["rate_mib_s"] = j.get("mib_s_up") if test == "upload" else j.get("mib_s_down") if test in ("echo", "download") else None
    if m["rate_mib_s"] is not None and c and c.get("window_s") and c.get("bytes_down") is not None:  # exact bytes (the JSON MiB/s has 2 decimals)
        m["rate_mib_s"] = (c["bytes_up"] if test == "upload" else c["bytes_down"]) / c["window_s"] / 2 ** 20
    b = buckets(l)
    for k, q in (("p50", .5), ("p90", .9), ("p99", .99), ("p999", .999)):
        m[k] = pct(b, q) if b else None
    m["mean"] = l.get("mean") / 1000 if l.get("n") else None
    m["max"] = l.get("max") / 1000 if l.get("n") else None
    dt = e.get("dt_s")
    srv = srv_cpu_s(e)
    # CPU is read at the edge thread's actual edges (late0_us / late1_us after the scheduled ones), the work over the
    # scheduled window: per-unit efficiency only when the two windows agree within EDGE_SKEW of the window (80.04,
    # 5278 runs: late0 + late1 median 0.09 %, 8 runs above 1 %)
    win = (c or {}).get("window_s") or j.get("duration")
    m["edge_skew"] = max(abs(dt / win - 1), (e.get("late0_us", 0) + e.get("late1_us", 0)) / 1e6 / win) if dt and win else None
    aligned = m["edge_skew"] is not None and m["edge_skew"] <= EDGE_SKEW
    if srv is not None and dt:
        rate = srv / dt
        m["srv_cpu"] = rate
        m["srv_us_per_msg"] = rate / m["rps"] * 1e6 if m["rps"] and aligned else None
        m["srv_s_per_gib"] = rate / (m["rate_mib_s"] / 1024) if m["rate_mib_s"] and aligned else None
        if "srv_cg_us" in e and e["srv_cg_us"] > 0:
            m["srv_sys_share"] = e["srv_cg_sys_us"] / max(1, e["srv_cg_user_us"] + e["srv_cg_sys_us"])
    if dt and m["rps"] and aligned:
        m["cli_us_per_msg"] = (e.get("cli_user_us", 0) + e.get("cli_sys_us", 0)) / 1e6 / dt / m["rps"] * 1e6
    ct = rec.get("cli_thr")
    if ct:
        m["cli_thr_max"] = max(ct.values())  # the client's busiest thread, cores over the window
    if o:
        # a run that censored or dropped arrivals: its percentiles hold censored ages and miss the dropped ones (bounds,
        # not distributions): pair_rows leaves such pairs out of the latency rows
        m["ol_incomplete"] = bool(o.get("censored") or o.get("dropped"))
        m["censored"] = o["censored"] / o["sched"] if o.get("sched") else None
        m["done_share"] = o["done"] / o["sched"] if o.get("sched") else None
        m["svc_p99"] = pct(buckets(o.get("svc")), .99)
        m["lag_p50"] = (o.get("lag") or {}).get("p50", 0) / 1000
        m["lag_p99"] = (o.get("lag") or {}).get("p99", 0) / 1000
    return m


HELPER_THREADS = ("fw-dns", "lastlog", "mem")
EDGE_SKEW = 0.01
LAT_METRICS = ("mean", "max", "p50", "p90", "p99", "p999", "svc_p99")


def workers(rec):
    """(distinct workers holding the run's connections from the mid-window connection map or None, busy server threads
    = threads with >= 25 % of the busiest one's CPU, the busiest thread's name)"""
    thr = {k: v for k, v in (rec.get("thr") or {}).items() if not k.split("/")[0].startswith(HELPER_THREADS)}
    top = max(thr.values(), default=0)
    busy = sum(1 for v in thr.values() if top and v >= 0.25 * top) if thr else None
    name = max(thr, key=thr.get).split("/")[0] if thr else None
    conns = int(rec["cell"].split(":")[1])
    n0 = (rec.get("cmap_n") or [None])[0]
    # the set-up map (exogenous) when it holds every connection; else the mid-window one
    cm = rec.get("cmap0") if rec.get("cmap0") and (n0 is None or n0 == conns) else rec.get("cmap")
    return (len(cm) if cm else None), busy, name


def distinct(rec):
    """(distinct workers at set-up from a complete cmap0 or None, distinct workers mid-window from cmap or None)"""
    conns = int(rec["cell"].split(":")[1])
    n0 = (rec.get("cmap_n") or [None])[0]
    c0, cm = rec.get("cmap0"), rec.get("cmap")
    return (len(c0) if c0 and (n0 is None or n0 == conns) else None), (len(cm) if cm else None)


def cpu_split(rec):
    """cores over the window: server total, its busiest thread, client (wbench), target"""
    e = (rec.get("j") or {}).get("edges") or {}
    dt = e.get("dt_s")
    if not dt:
        return None
    srv = srv_cpu_s(e)
    thr = {k: v for k, v in (rec.get("thr") or {}).items() if not k.split("/")[0].startswith(HELPER_THREADS)}
    win = rec.get("d_run") or 0
    return {"srv": srv / dt if srv is not None else None, "srv_top": max(thr.values()) / 1000 / win if thr and win else None,
            "cli": (e.get("cli_user_us", 0) + e.get("cli_sys_us", 0)) / 1e6 / dt, "tgt": (rec.get("tgt_cpu_s") or 0) / dt,
            "cli_top": max((rec.get("cli_thr") or {}).values(), default=None)}


def workers_table(recs, names, labels):
    """markdown lines: per cell and arm, distinct workers per run (connection map; busy threads as a cross-check), the
    rate by distinct-worker count, and the CPU split (median cores)"""
    L = ["| cell | arm | runs | distinct workers at set-up (cmap0): runs | distinct workers mid-window (cmap): runs | busy threads: runs | rps by distinct workers mid-window (mean) | busiest thread | CPU cores srv / srv top thread / client / client top thread / target (median) |",
         "|---|---|---|---|---|---|---|---|---|"]
    groups = []
    for r in recs:
        g = (r["cell"], r.get("rate"))
        if not r.get("calib") and r.get("step") is None and g not in groups:
            groups.append(g)
    med = lambda xs: round(st.median(xs), 3) if xs else None
    for g in groups:
        for n in names:
            rs = [r for r in recs if (r["cell"], r.get("rate")) == g and r["arm"] == n and ok(r)]
            if not rs:
                continue
            w = [workers(r) for r in rs]
            dd = [distinct(r) for r in rs]
            d0m = defaultdict(int)
            dmm = defaultdict(int)
            for a0, a1 in dd:
                d0m[a0] += 1
                dmm[a1] += 1
            dm = defaultdict(int)
            bm = defaultdict(int)
            byd = defaultdict(list)
            tops = defaultdict(int)
            for r, (d, b, nm), (_, dmid) in zip(rs, w, dd):
                dm[d] += 1
                bm[b] += 1
                tops[nm] += 1
                if dmid is not None and metrics(r).get("rps"):
                    byd[dmid].append(metrics(r)["rps"])
            sp = [cpu_split(r) for r in rs]
            sp = [x for x in sp if x]
            cs = " / ".join(str(med([x[k] for x in sp if x[k] is not None])) for k in ("srv", "srv_top", "cli", "cli_top", "tgt"))
            name = group_name(g[0], g[1])
            fm = lambda m: ", ".join(f"{k}: {v}" for k, v in sorted(m.items(), key=str))
            L.append(f"| {name} | {labels.get(n, n)} | {len(rs)} | {fm(d0m)} | {fm(dmm)} | "
                     f"{', '.join(f'{k}: {v}' for k, v in sorted(bm.items(), key=str))} | "
                     f"{', '.join(f'{k}: {st.mean(v):.0f}' for k, v in sorted(byd.items()))} | "
                     f"{', '.join(f'{k} x{v}' for k, v in sorted(tops.items(), key=lambda kv: -kv[1])[:3])} | {cs} |")
    return L


def srv_top(r):
    """the server's busiest thread in cores: over the window from --sched (exact), else from the per-thread CPU over the
    whole client run ("thr", set-up and warm-up included: a lower bound)"""
    s = r.get("sched")
    if s and s.get("srv") and s.get("s"):
        return max(v[0] for v in s["srv"].values()) / 1e9 / s["s"]
    thr = [v for k, v in (r.get("thr") or {}).items() if not k.startswith(("fw-dns", "lastlog"))]
    return max(thr) / 1000 / r["d_run"] if thr and r.get("d_run") else None


def loadpoint_table(recs, names, labels):
    """80.04 rule for fixed-rate (open-loop) cells: did the CLIENT sustain the schedule, and was the TARGET not the
    limit? Per cell and arm (medians over runs): done / scheduled, lag p99 against the per-connection interval, client
    CPU (process and busiest thread), target CPU, the server's busiest thread; flag = 'client near limit' (client or
    its busiest thread >= 0.9 core, or lag p99 > 2 x interval), 'target near limit' (>= 0.9 core), 'server thread near
    limit' (its busiest thread >= 0.9 core: one connection = one worker, so a saturated worker queues its own
    messages), 'not served' (done < 0.999 x scheduled)"""
    L = ["| cell | arm | runs | done / sched | lag p99 us | interval us | client cores | client top thread | target cores | server top thread | flag |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
    groups = []
    for r in recs:
        g = (r["cell"], r.get("rate"))
        if r.get("rate") and not r.get("calib") and r.get("step") is None and g not in groups:
            groups.append(g)
    med = lambda xs: st.median(xs) if xs else None
    for g in groups:
        conns = int(g[0].split(":")[1])
        iv = conns / g[1] * 1e6
        for n in names:
            rs = [r for r in recs if (r["cell"], r.get("rate")) == g and r["arm"] == n and ok(r)]
            if not rs:
                continue
            ms = [metrics(r) for r in rs]
            sp = [x for x in (cpu_split(r) for r in rs) if x]
            done = med([m["done_share"] for m in ms if m.get("done_share") is not None])
            lag = med([m["lag_p99"] for m in ms if m.get("lag_p99") is not None])
            cli = med([x["cli"] for x in sp])
            top = med([x["cli_top"] for x in sp if x.get("cli_top") is not None])
            tgt = med([x["tgt"] for x in sp])
            stop = med([x for x in (srv_top(r) for r in rs) if x is not None])
            flag = []
            if (cli or 0) >= 0.9 or (top or 0) >= 0.9 or (lag or 0) > 2 * iv:
                flag.append("client near limit")
            if (tgt or 0) >= 0.9:
                flag.append("target near limit")
            if (stop or 0) >= 0.9:
                flag.append("server thread near limit")
            if done is not None and done < 0.999:
                flag.append("not served")
            f3 = lambda v: "-" if v is None else f"{v:.3f}"
            L.append(f"| {group_name(g[0], g[1])} | {labels.get(n, n)} | {len(rs)} | {f3(done)} | {f3(lag)} | {iv:.1f} | {f3(cli)} | {f3(top)} | {f3(tgt)} | {f3(stop)} | {', '.join(flag) or 'ok'} |")
    return L


def srv_cpu_s(e, hz=100):
    """server CPU seconds in the window: the unit's cgroup, else the threads' schedstat when no thread exited in the
    window, else the processes' stat ticks (they keep the time of exited threads; 10 ms steps)"""
    if "srv_cg_us" in e:
        return e["srv_cg_us"] / 1e6
    if "srv_sched_ns" in e and not e.get("srv_sched_lost_threads"):
        return e["srv_sched_ns"] / 1e9
    if "srv_utime" in e:
        return (e["srv_utime"] + e["srv_stime"]) / hz
    return None


def word(v):
    return "unclear" if v == "watch" else v


def pair_rows(recs, a, b, key, cell_name, names=None, keep_bad=False):
    """contract rows for arms a (base) and b over the pairs keyed by key(rec) (both arms present and valid; a pair
    with a run marked BAD by hoststate is left out unless keep_bad, and counted in the note)"""
    by, badk = defaultdict(dict), set()
    for r in recs:
        if ok(r):
            by[key(r)][r["arm"]] = metrics(r)
            if r.get("bad") and r["arm"] in (a, b):
                badk.add(key(r))
    allp = [k for k, v in sorted(by.items(), key=lambda kv: str(kv[0])) if a in v and b in v]
    nbad = sum(1 for k in allp if k in badk)
    pairs = [(by[k][a], by[k][b]) for k in allp if keep_bad or k not in badk]
    rows = []
    for name in names or METRICS:
        unit, hb = METRICS[name]
        use = [p for p in pairs if not (name in LAT_METRICS and (p[0].get("ol_incomplete") or p[1].get("ol_incomplete")))]
        n_inc = len(pairs) - len(use)
        both = [(p[0].get(name), p[1].get(name)) for p in use]
        both = [(x, y) for x, y in both if x is not None and y is not None]  # medians and n: zeros included
        if not both:
            continue
        valid = [(x, y) for x, y in both if x > 0 and y > 0]  # the ratio: pairs with both sides > 0
        n_zero = len(both) - len(valid) if valid else 0  # a metric that is 0 throughout (a share) has no ratio anyway
        # a pair with a zero on ONE side only (e.g. one arm served nothing): the ratio over the other pairs would ignore
        # that failure, so the verdict is withheld (the ratio stays, for reading)
        n_one = sum(1 for x, y in both if (x > 0) != (y > 0))
        c = stats.compare([x for x, _ in valid], [y for _, y in valid], higher_better=hb) if valid else None
        va, vb = [x for x, _ in both], [y for _, y in both]
        cv = lambda v: st.pstdev(v) / st.mean(v) if len(v) > 1 and st.mean(v) else None
        logs = [math.log(y / x) for x, y in valid]
        note = (f"cv a {fmt(cv(va))} b {fmt(cv(vb))}; sd log(b/a) {fmt(st.stdev(logs) if len(logs) > 1 else None)}"
                + (f"; {nbad} BAD pairs out" if nbad and not keep_bad else "")
                + (f"; {n_inc} pairs out: censored or dropped arrivals (latency is a bound there)" if n_inc else "")
                + (f"; {n_zero} pairs with a zero: not in the ratio" if n_zero else "")
                + (f"; {n_one} pairs zero on one side only: no verdict" if n_one else ""))
        rows.append({"cell": cell_name, "metric": name, "unit": unit, "a": rnd(st.median(va)), "b": rnd(st.median(vb)),
                     "ratio": c["ratio"] if c else None, "ci_lo": c["ci90"][0] if c and c["ci90"] else None,
                     "ci_hi": c["ci90"][1] if c and c["ci90"] else None, "verdict": word(c["verdict"]) if c and not n_one else "unclear",
                     "n": len(both), "note": note})
    return rows


def fmt(x, nd=4):
    return "-" if x is None else f"{x:.{nd}f}"


def rnd(x):
    return None if x is None else float(f"{x:.6g}")


def arm_dist(recs, arm, filt=lambda r: True):
    """merged latency distribution of an arm: {n, censored, p50, p90, p99, p999, max (us), mean (us)}"""
    rs = [r for r in recs if r["arm"] == arm and ok(r) and filt(r)]
    ls = [r["j"].get("lat") for r in rs if r["j"].get("lat")]
    b = merge(ls)
    n = sum(b.values())
    if not n:
        return None
    s = sum((l.get("mean", 0) * l.get("n", 0)) for l in ls)
    cens = sum((r["j"].get("ol") or {}).get("censored", 0) for r in rs)
    drop = sum((r["j"].get("ol") or {}).get("dropped", 0) for r in rs)
    # censored > 0 or dropped > 0: the tail percentiles are bounds (censored ages in, dropped arrivals absent)
    return {"runs": len(rs), "n": n, "censored": cens, "dropped": drop, "bound": bool(cens or drop), "mean": round(s / n / 1000, 2), "p50": pct(b, .5), "p90": pct(b, .9),
            "p99": pct(b, .99), "p999": pct(b, .999), "p9999": pct(b, .9999), "max": max(l.get("max", 0) for l in ls) / 1000}


def knee(steps):
    """steps: [(offered, achieved, censored share, dropped)] rising -> the highest offered rate still served
    (achieved >= 0.98 x offered, nothing censored or dropped), None if not even the first"""
    best = None
    for off, ach, cen, drop in steps:
        if ach is not None and off and ach >= 0.98 * off and not cen and not drop:
            best = off
        else:
            break
    return best


def served(r):
    j = r.get("j") or {}
    o = j.get("ol") or {}
    rate = r.get("rate")
    return (ok(r) and "ol" in j and rate is not None and not o.get("censored") and not o.get("dropped")
            and (j.get("rps") or 0) >= 0.98 * rate)


def point_diag(r):
    """one open-loop load point: what limited it (80.04 rule: a missed rate is a failed load point, not proof of server
    saturation). CPU shares in cores over the window (server: total and its busiest thread; client: wbench; target:
    estimate scaled to the window; host busy: share of all CPUs). Limits (all that apply):
      server = its busiest thread >= 0.9 core (a 1x1 cell lives on one worker thread)
      client = wbench or its busiest thread >= 0.9 core, or lag p99 > 2 x the per-connection interval with the box not
               busy (< 0.85) and no server thread >= 0.9 (lag includes credit and run-queue waits)
      target = the target >= 0.9 core
      host   = the box busy (>= 0.85 of all CPUs) and none of the above (2-vCPU box: client, server, target, softirq share)
      drain  = the rate was met but messages were still open at the drain's end (censored)
      unknown otherwise. served points get "-"."""
    j = r.get("j") or {}
    o, e, t = j.get("ol") or {}, j.get("edges") or {}, r.get("tags") or {}
    dt = e.get("dt_s") or 0
    rate = r.get("rate") or 0
    conns = int(r["cell"].split(":")[1])
    srv = srv_cpu_s(e)
    win = max(1e-9, r.get("d_run") or 0)
    thr_max = max((v for k, v in (r.get("thr") or {}).items() if not k.startswith(("fw-dns", "lastlog"))), default=None)
    d = {"rate": rate, "achieved": j.get("rps"), "censored": o.get("censored"), "unsent": o.get("unsent"), "dropped": o.get("dropped"),
         "max_backlog": o.get("max_backlog"), "lag_p50_us": (o.get("lag") or {}).get("p50", 0) / 1000, "lag_p99_us": (o.get("lag") or {}).get("p99", 0) / 1000,
         "interval_us": conns / rate * 1e6 if rate else None,
         "srv_cpu": round(srv / dt, 3) if srv is not None and dt else None,
         "srv_thread_max": round(thr_max / 1000 / win, 3) if thr_max is not None else None,
         "cli_cpu": round((e.get("cli_user_us", 0) + e.get("cli_sys_us", 0)) / 1e6 / dt, 3) if dt else None,
         "tgt_cpu": round(r.get("tgt_cpu_s", 0) / dt, 3) if dt else None, "softirq": t.get("softirq"), "busy": t.get("busy"),
         "cli_thr_max": max((r.get("cli_thr") or {}).values(), default=None)}
    if served(r):
        d["limit"] = "-"
        return d
    lim = []
    if (d["srv_thread_max"] or 0) >= 0.9:
        lim.append("server")
    # lag = intended -> queued for the socket: it includes waits for the server's credit, so a late client counts as
    # the limit only when it had spare CPU (box not busy) and no server thread was saturated
    late = d["interval_us"] and d["lag_p99_us"] > 2 * d["interval_us"]
    # a late client counts only when the box had clear spare CPU (< 0.85 busy): on a 2-vCPU box at ~0.9 busy the lag is
    # run-queue wait shared by every component (labelled "host" below), not the client's own limit
    if (d["cli_cpu"] or 0) >= 0.9 or (d["cli_thr_max"] or 0) >= 0.9 or (late and (d["busy"] or 1) < 0.85 and d["srv_thread_max"] is not None and d["srv_thread_max"] < 0.9):
        lim.append("client")
    if (d["tgt_cpu"] or 0) >= 0.9:
        lim.append("target")
    if not lim and (d["busy"] or 0) >= 0.85:
        lim.append("host")
    if not lim and d["achieved"] and d["achieved"] >= 0.98 * rate and d["censored"] and not d["dropped"]:
        lim.append("drain")
    d["limit"] = "+".join(lim) or "unknown"
    return d


def knees(recs, arm):
    """per sweep of an arm (open-loop curve, steps + refine points): the highest served offered rate below the lowest
    unserved one (None if the first point is not served; the highest step if every point is served: a lower bound)"""
    out = {}
    for sw in sorted({r.get("sweep") for r in recs if r["arm"] == arm and r.get("sweep") is not None}):
        pts = [(r["rate"], served(r)) for r in recs if r["arm"] == arm and r.get("sweep") == sw and r.get("rate") and not r.get("calib")]
        bad = [x for x, g in pts if not g]
        hi = min(bad) if bad else None
        good = [x for x, g in pts if g and (hi is None or x < hi)]
        first = next((r for r in recs if r["arm"] == arm and r.get("sweep") == sw and r.get("rate") == hi and not r.get("calib")), None)
        bracket = [r for r in recs if r["arm"] == arm and r.get("sweep") == sw and r.get("rate") in (hi, max(good) if good else None)]
        out[sw] = {"knee": max(good) if good else None, "first_unserved": hi, "lower_bound": hi is None,
                   "below_range": hi is not None and not good,  # not even the lowest point served: an upper bound only
                   "bad_in_bracket": any(r.get("bad") for r in bracket),
                   # runs with errors or a dead server count as unserved (the overload symptom); how many there were:
                   "invalid": sum(1 for r in recs if r["arm"] == arm and r.get("sweep") == sw and r.get("rate") and not r.get("calib") and not ok(r)),
                   "at_unserved": point_diag(first) if first else None}
    return out


def curve_table(recs, arm):
    """per step of an arm (open-loop rate or conns): medians over sweeps of achieved rps, merged latency, CPU/msg"""
    rows = []
    steps = sorted({r.get("step") for r in recs if r["arm"] == arm and r.get("step") is not None})
    for k in steps:
        rs = [r for r in recs if r["arm"] == arm and r.get("step") == k and ok(r)]
        if not rs:
            rows.append({"step": k, "runs": 0})
            continue
        ms = [metrics(r) for r in rs]
        med = lambda f: rnd(st.median([m[f] for m in ms if m.get(f) is not None])) if any(m.get(f) is not None for m in ms) else None
        d = arm_dist(recs, arm, lambda r, k=k: r.get("step") == k)
        ol = [r["j"].get("ol") or {} for r in rs]
        rows.append({"step": k, "cell": rs[0]["cell"], "offered": rs[0].get("rate"), "runs": len(rs), "rps": med("rps"),
                     "mib_s": med("rate_mib_s"), "p50": d and d["p50"], "p99": d and d["p99"], "p999": d and d["p999"],
                     "max": d and d["max"], "censored": sum(o.get("censored", 0) for o in ol), "dropped": sum(o.get("dropped", 0) for o in ol),
                     "srv_us_per_msg": med("srv_us_per_msg"), "srv_s_per_gib": med("srv_s_per_gib"), "srv_cpu": med("srv_cpu"), "lag_p99": med("lag_p99")})
    return rows


def fixed_costs(recs, stops=()):
    """the run loop's own time per run (s): start (spawn -> ready), client beyond its window, stop (kill -> free)"""
    f = lambda xs: {"n": len(xs), "median": rnd(st.median(xs)), "max": rnd(max(xs))} if xs else None
    return {"d_start": f([r["d_start"] for r in recs if r.get("d_start")]),
            "client_fixed_s": f([r["client_fixed_s"] for r in recs if r.get("client_fixed_s") is not None]),
            "d_stop": f([s["d_stop"] for s in stops if s.get("d_stop") is not None])}


def host_summary(recs):
    """the worst and the median of each host-state tag over the session's runs, and how many runs were marked BAD"""
    out = {"runs": len(recs), "bad_runs": sum(1 for r in recs if r.get("bad"))}
    for k in ("steal", "softirq", "other", "busy", "tcp_press", "late_ms", "mhz"):
        v = [r["tags"][k] for r in recs if r.get("tags") and r["tags"].get(k) is not None]
        if v:
            out[k] = {"median": rnd(st.median(v)), "max": rnd(max(v))}
    return out


def _epoch(s):
    import calendar
    import time as _t
    return calendar.timegm(_t.strptime(s[:19], "%Y-%m-%dT%H:%M:%S"))


def rate_label(rate):
    """lossless text of a rate for row and cell names (80.04, 2026-11-20): :g where it prints the rate exactly, else the
    exact integer or float text; float(rate_label(x)) == x, so two different rates never share a label"""
    s = f"{rate:g}"
    if float(s) == rate:
        return s
    return str(int(rate)) if float(rate).is_integer() else repr(float(rate))


def group_name(cell, rate):
    """the name of a latency group (cell, rate): "cell" (rate None) or "cell@rate=LABEL" (one rule for paired rows, tables,
    tick lines); a rate of 0 (an "@f=" cell rounded to 0) keeps its own name, apart from the closed-loop group"""
    return cell + (f"@rate={rate_label(rate)}" if rate is not None else "")


def names_session(w, session):
    """True when a window names `session`: its "session" field, else a "session NAME" token in its what / why text
    (exact token, never a prefix: "...-client2" does not name "...-client2b")"""
    if w.get("session") is not None:
        return w["session"] == session
    # per field (no token across them); "session" starts the field or follows a blank or ";" (the archived form "...; session
    # NAME"): "(session killed)" is a status note and "post-session x" a word, neither names a session
    return any(session in re.findall(r"(?:^|(?<=[\s;]))session ([^\s;()]+)", w.get(k) or "") for k in ("what", "why"))


def exclusions(paths, box, me=None, session=None):
    """foreign-activity windows of a box (80.04 measurement rule: a measured round that ran during a foreign unit or
    process is excluded and rerun): lines {"box", "start", "end" (UTC), "why" | "who" + "what" [+ "session"]} of the
    jsonl files (a session's own list and a shared log of foreign windows). A window of `me` (the caller's worker name)
    that names `session` (the caller's session) is the session's own and not foreign; every other window counts, also
    other windows of `me` (80.04 audit 2026-11-20: a kit ship of another session of the same worker, made before its
    own lock while this session held the box, is foreign to this session). session None: no window is the caller's own."""
    out = []
    for path in ([paths] if isinstance(paths, str) else paths):
        try:
            lines = open(path).read().splitlines()
        except FileNotFoundError:  # an optional list that does not exist yet
            continue  # any other read error (permissions, I/O) raises: an unreadable configured source is not "no windows"
        for line in lines:
            if not line.strip():
                continue
            w = json.loads(line)
            if w.get("box") != box:
                continue
            if me is not None and session is not None and w.get("who") == me and names_session(w, session):
                continue
            why = w.get("why") or f"{w.get('who')}: {w.get('what')} (shared log)"
            out.append((_epoch(w["start"]), _epoch(w["end"]), why))
    return out


TICK_S = 2.0  # 80.04 tick check (2026-11-20): on the VPS boxes the first ~2 s of each minute run slower


def tick_exposure(recs, warmup, unit, units=(), arms=()):
    """80.04 (2026-11-20): {unit: {arm: [runs whose measured window overlaps [:00, :00 + TICK_S) of the box clock,
    valid runs, valid runs without a window estimate]}} over valid non-calibration runs; unit(rec) -> name (None: skip);
    units x arms are listed even with no valid run (a cell whose rounds were all excluded, an arm whose runs all failed).
    Descriptive only: no threshold, no flag, no verdict effect (a small session can still be misread: read it beside the rows).
    Window start = ESTIMATE (wbench does not log it): tw0 (box clock at client launch) + set-up + warmup; set-up = cmap0_ms
    (connections at the server's epoll: a few ms before the window opens); a run whose map poll timed out (cmap0_incomplete)
    max(the (cell, arm) median, min(2, warmup)); else the (cell, arm) median; else 0.02 s. End = start + j.duration."""
    med = defaultdict(list)
    for r in recs:
        if r.get("cmap0_ms") is not None:
            med[(r["cell"], r["arm"])].append(r["cmap0_ms"] / 1000)
    out = {u: {a: [0, 0, 0] for a in arms} for u in units}
    for r in recs:
        u = unit(r)
        if u is None or r.get("calib") or not ok(r):
            continue
        c = out.setdefault(u, {}).setdefault(r["arm"], [0, 0, 0])
        c[1] += 1
        try:  # a record without usable timing is counted as "without a window estimate", never an error
            dur, tw0 = float((r.get("j") or {}).get("duration")), float(r.get("tw0"))
        except (TypeError, ValueError):
            dur = tw0 = None
        if dur is None or not (math.isfinite(dur) and math.isfinite(tw0)) or dur <= 0:
            c[2] += 1
            continue
        m = st.median(med[(r["cell"], r["arm"])]) if med.get((r["cell"], r["arm"])) else None
        if r.get("cmap0_ms") is not None:
            su = r["cmap0_ms"] / 1000
        elif r.get("cmap0_incomplete") is not None:
            su = max(m or 0.0, min(2.0, warmup))
        else:
            su = m if m is not None else 0.02
        ws = tw0 + su + warmup
        we = ws + dur
        c[0] += any(ws < 60 * k + TICK_S and we > 60 * k for k in range(int(ws // 60), int(we // 60) + 1))
    return out


def apply_exclusions(recs, windows, margin=2.0):
    """-> (kept recs, excluded [{cell, rate, rnd, sweep, why}]): every latency round (cell, rate, rnd: all arms) or curve
    sweep (all its steps and arms) with a run whose span [server start - margin, client end + margin] intersects a
    foreign window is dropped whole. Span: t0 = before the server's start (latency runs) or tw0 - d_start (curves:
    tw0 = client start), end = tw0 + d_run"""
    if not windows:
        return recs, []
    unit = lambda r: ("sweep", r["sweep"]) if r.get("sweep") is not None else (r["cell"], r.get("rate"), r.get("rnd"))
    bad = {}
    for r in recs:
        tw0 = r.get("tw0")
        start = r.get("t0") if r.get("t0") is not None else (tw0 - (r.get("d_start") or 0) if tw0 is not None else None)
        if start is None:
            continue
        end = (tw0 if tw0 is not None else start) + (r.get("d_run") or 0)
        lo, hi = start - margin, end + margin
        for s, e, why in windows:
            if lo <= e and s <= hi:
                bad.setdefault(unit(r), why)
    kept = [r for r in recs if unit(r) not in bad]
    exc = [({"sweep": k[1]} if k[0] == "sweep" else {"cell": k[0], "rate": k[1], "rnd": k[2]}) | {"why": why}
           for k, why in sorted(bad.items(), key=str)]
    return kept, exc
