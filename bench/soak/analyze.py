#!/usr/bin/env python3
# 30.11 soak analysis (30.14: server metrics table, run-wide expectations): slopes after warm-up, event/probe/workload summaries, optional plots.
# usage: analyze.py RUN_DIR [--warmup-min 60] [--out DIR]   (plots need matplotlib:
#        uv run --with matplotlib python bench/soak/analyze.py RUN_DIR)
import argparse, csv, json, os, statistics, sys
from collections import Counter

ap = argparse.ArgumentParser()
ap.add_argument("run")
ap.add_argument("--warmup-min", type=float, default=60)
ap.add_argument("--out")
a = ap.parse_args()
OUT = a.out or a.run
os.makedirs(OUT, exist_ok=True)


def jl(name):
    p = os.path.join(a.run, name)
    if not os.path.exists(p):
        return []
    out = []
    for line in open(p):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


rows = list(csv.DictReader(open(os.path.join(a.run, "samples.csv"))))
for r in rows:
    for s in "AB":
        hi, hd = num(r.get(f"{s}_ho_idle")), num(r.get(f"{s}_ho_dl"))
        f = num(r.get(f"{s}_fds"))
        if f is not None and hi is not None:
            # a half-open download connection also holds its target socket
            r[f"{s}_fds_adj"] = f - hi - 2 * (hd or 0)
        # 30.16: cgroup memory without page cache (anon + kernel + sock): a log or file written in the scope cannot move it
        ak = [num(r.get(f"{s}_cg_{k}_kib")) for k in ("anon", "kernel", "sock")]
        if None not in ak:
            r[f"{s}_cg_aks_kib"] = sum(ak)
t_end = num(rows[-1]["min"])
post = [r for r in rows if num(r["min"]) >= a.warmup_min]


def ols(xs, ys):
    n = len(xs)
    if n < 3:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx if sxx else None


def theil_sen(xs, ys):
    sl = [(ys[j] - ys[i]) / (xs[j] - xs[i]) for i in range(len(xs)) for j in range(i + 1, len(xs)) if xs[j] != xs[i]]
    return statistics.median(sl) if sl else None


def series(key, rs=None):
    out = []
    for r in rs if rs is not None else post:
        v = num(r.get(key))
        if v is not None:
            out.append((num(r["min"]) / 60, v))
    return out


def buckets(pts, width_h=0.5, agg=statistics.median):
    b = {}
    for h, v in pts:
        b.setdefault(int(h / width_h), []).append(v)
    return [((k + 0.5) * width_h, agg(v)) for k, v in sorted(b.items()) if len(v) >= 3]


METRICS = [("A_rss_kib", "A RSS KiB"), ("B_rss_kib", "B RSS KiB"), ("A_cg_cur_kib", "A cgroup KiB"),
           ("B_cg_cur_kib", "B cgroup KiB"), ("A_cg_aks_kib", "A cgroup anon+kernel+sock KiB"),
           ("B_cg_aks_kib", "B cgroup anon+kernel+sock KiB"), ("A_cg_anon_kib", "A cgroup anon KiB"), ("B_cg_anon_kib", "B cgroup anon KiB"),
           ("A_fds", "A fds"), ("B_fds", "B fds"), ("A_fds_adj", "A fds - half-open"), ("B_fds_adj", "B fds - half-open"),
           ("A_fd_pipe", "A pipe fds"), ("B_fd_pipe", "B pipe fds"), ("A_threads", "A threads"), ("B_threads", "B threads"),
           ("A_cpu_pct", "A CPU %"), ("B_cpu_pct", "B CPU %"), ("h_SUnreclaim", "host SUnreclaim KiB"),
           ("h_Slab", "host Slab KiB"), ("h_files", "host open files"), ("h_tcp_inuse", "host TCP in use"),
           ("canary_p50_us", "canary rr p50 us"), ("canary_p99_us", "canary rr p99 us"),
           ("probe_A_ms", "probe A total ms"), ("probe_B_ms", "probe B total ms"),
           # 30.14: metrics.rs gauges (the pool at the last idle sweep; live conns/streams)
           ("A_m_pool_dirty_kib", "A pool dirty KiB"), ("B_m_pool_dirty_kib", "B pool dirty KiB"),
           ("A_m_pool_chunks", "A pool chunks"), ("B_m_pool_chunks", "B pool chunks"),
           ("A_m_conns", "A conns (metrics)"), ("B_m_conns", "B conns (metrics)")]

lines = []
P = lines.append
P(f"# Soak analysis: {os.path.basename(os.path.abspath(a.run))}")
P(f"samples {len(rows)} over {t_end / 60:.2f} h; warm-up excluded: first {a.warmup_min:.0f} min ({len(post)} samples after)")
P("")
P("## Slopes after warm-up (per hour; % of the post-warm-up mean)")
P("Floor = Theil-Sen slope of 30-min bucket minima (the level the server returns to between bursts);")
P("median = same on 30-min medians; all = OLS on every 10 s sample. Flat = |floor| and |median| < 1 %/h.")
P("")
P("| metric | mean | first 30 min med | last 30 min med | all %/h | median %/h | floor %/h | verdict |")
P("|---|---|---|---|---|---|---|---|")
slopes = {}
for key, label in METRICS:
    pts = series(key)
    if len(pts) < 10:
        continue
    mean = statistics.fmean(v for _, v in pts)
    if mean == 0:
        continue
    o = ols([h for h, _ in pts], [v for _, v in pts])
    med = buckets(pts)
    flo = buckets(pts, agg=min)
    sm = theil_sen([h for h, _ in med], [v for _, v in med]) if len(med) >= 3 else None
    sf = theil_sen([h for h, _ in flo], [v for _, v in flo]) if len(flo) >= 3 else None
    pc = lambda s: None if s is None else 100 * s / mean
    vals = [pc(s) for s in (o, sm, sf)]
    flat = all(v is not None and abs(v) < 1 for v in vals[1:])
    slopes[key] = vals
    f30 = statistics.median([v for h, v in pts if h < pts[0][0] + 0.5])
    l30 = statistics.median([v for h, v in pts if h > pts[-1][0] - 0.5])
    fmt = lambda v: "-" if v is None else f"{v:+.2f}"
    P(f"| {label} | {mean:,.1f} | {f30:,.1f} | {l30:,.1f} | {fmt(vals[0])} | {fmt(vals[1])} | {fmt(vals[2])} | "
      f"{'flat' if flat else 'CHECK'} |")


# ---- quiet windows: the floor once the bursts are over (idle/slow/half-open clients still connected)
def solve3(A, b):
    import copy
    M = [r[:] + [v] for r, v in zip(copy.deepcopy(A), b)]
    for c in range(3):
        p = max(range(c, 3), key=lambda r: abs(M[r][c]))
        if abs(M[p][c]) < 1e-12:
            return None
        M[c], M[p] = M[p], M[c]
        for r in range(3):
            if r != c:
                f = M[r][c] / M[c][c]
                M[r] = [x - f * y for x, y in zip(M[r], M[c])]
    return [M[i][3] / M[i][i] for i in range(3)]


def ols2(h, e, y):
    """y = b0 + b1*h + b2*e; returns (b1, b2)."""
    n = len(y)
    if n < 4:
        return None
    X = [[1, hh, ee] for hh, ee in zip(h, e)]
    A = [[sum(X[k][i] * X[k][j] for k in range(n)) for j in range(3)] for i in range(3)]
    bv = [sum(X[k][i] * y[k] for k in range(n)) for i in range(3)]
    s = solve3(A, bv)
    return None if s is None else (s[1], s[2])


wins = []
cur = []
for r in rows:
    if r.get("quiet") == "1" and r.get("bench") == "1":
        continue  # 30.11 re-soak: the bench window runs inside the quiet window; its rows are not the floor
    if r.get("quiet") == "1":
        cur.append(r)
    elif cur:
        wins.append(cur); cur = []
if cur:
    wins.append(cur)
wins = [[r for r in w if num(r["min"]) >= num(w[0]["min"]) + 2] for w in wins]
wins = [w for w in wins if len(w) >= 6]
QK = ["A_rss_kib", "B_rss_kib", "A_anon_kib", "B_anon_kib", "A_cg_anon_kib", "B_cg_anon_kib", "A_cg_cur_kib", "B_cg_cur_kib", "A_cg_aks_kib", "B_cg_aks_kib", "A_fds_adj", "B_fds_adj",
      "A_fd_pipe", "B_fd_pipe", "A_tcp_closewait", "B_tcp_closewait", "A_tcp_estab", "B_tcp_estab", "A_cpu_pct",
      "B_cpu_pct", "canary_p50_us", "canary_p99_us", "probe_A_ms", "probe_B_ms", "h_SUnreclaim", "h_tcp_inuse",
      "A_m_pool_dirty_kib", "B_m_pool_dirty_kib", "A_m_pool_chunks", "B_m_pool_chunks"]
if wins:
    P("")
    P("## Quiet windows (median of the last 3 min of each; no wbench except the canary, no abuse)")
    P("| hour | " + " | ".join(k for k in QK) + " |")
    P("|---|" + "---|" * len(QK))
    wmed = []
    for w in wins:
        m = {"h": num(w[-1]["min"]) / 60}
        for k in QK:
            v = [num(r.get(k)) for r in w if num(r.get(k)) is not None]
            m[k] = statistics.median(v) if v else None
        wmed.append(m)
        P(f"| {m['h']:.2f} | " + " | ".join("-" if m[k] is None else f"{m[k]:,.0f}" for k in QK) + " |")
    if len(wmed) >= 3:
        P("")
        P("Slopes over the quiet windows (Theil-Sen, per hour, % of mean); RSS/anon also with the server's ESTAB")
        P("count as a covariate (idle connection count varies; per-connection cost = the fitted KiB/conn).")
        for k in QK:
            pts = [(m["h"], m[k]) for m in wmed if m[k] is not None]
            if len(pts) < 3:
                continue
            mean = statistics.fmean(v for _, v in pts)
            sl = theil_sen([h for h, _ in pts], [v for _, v in pts])
            pct = 100 * sl / mean if mean else 0
            extra = ""
            if k[2:] in ("rss_kib", "anon_kib", "cg_anon_kib", "cg_cur_kib", "cg_aks_kib", "fds_adj"):
                est = k[0] + "_tcp_estab"
                tri = [(m["h"], m[est], m[k]) for m in wmed if m[k] is not None and m[est] is not None]
                fit = ols2([t[0] for t in tri], [t[1] for t in tri], [t[2] for t in tri])
                if fit:
                    extra = f"; with ESTAB covariate {fit[0]:+,.1f}/h ({100 * fit[0] / mean:+.2f} %/h), {fit[1]:.2f} per ESTAB socket"
            P(f"- {k}: mean {mean:,.1f}, {sl:+,.2f}/h ({pct:+.2f} %/h){extra}")

ev = jl("events.jsonl")
kinds = Counter(e["kind"] for e in ev)
_argv = next((e.get("argv") or [] for e in ev if e["kind"] == "start"), [])
NO_SCOPE = "--no-scope" in _argv  # 30.16
SCALE = int(_argv[_argv.index("--scale") + 1]) if "--scale" in _argv else 1
P("")
P("## Events")
P(", ".join(f"{k} {v}" for k, v in sorted(kinds.items())))
for e in ev:
    if e["kind"] in ("server_died", "helper_died", "harness_error", "wbench_timeout", "probe_fail", "server_stop"):
        P(f"- {e['kind']}: {json.dumps({k: v for k, v in e.items() if k != 'kind'})[:600]}")
levels = [e for e in ev if e["kind"] == "mem_level"]
if levels:
    P(f"- memory level changes: {len(levels)}; first: {levels[0]['line'][:200]}")
last = rows[-1]
for s in "AB":
    P(f"- {s}: oom_kill {last.get(f'{s}_cg_oom_kill')}, memory.max events {last.get(f'{s}_cg_max_ev')}, "
      f"cgroup peak {num(last.get(f'{s}_cg_peak_kib') or 0) / 1024:.0f} MiB, VmHWM {num(last.get(f'{s}_hwm_kib') or 0) / 1024:.0f} MiB, "
      f"restarts (gen) {last.get(f'{s}_gen')}")
fin = jl("final_sample.jsonl")
if fin:
    f = fin[-1]
    P(f"- final quiet sample (all clients stopped 30+ s, half-open held): " + ", ".join(
        f"{s}: RSS {f.get(f'{s}_rss_kib', 0) / 1024:.1f} MiB, fds {f.get(f'{s}_fds')}, CPU {f.get(f'{s}_cpu_pct')}%, "
        f"estab {f.get(f'{s}_tcp_estab')}, half-open idle/dl {f.get(f'{s}_ho_idle')}/{f.get(f'{s}_ho_dl')}" for s in "AB"))

pr = jl("probes.jsonl")
P("")
P("## Probes (every minute per server)")
for s in "AB":
    ps = [p for p in pr if p.get("server") == s]
    bad = [p for p in ps if not p.get("ok")]
    dl = [p["dl_mib_s"] for p in ps if "dl_mib_s" in p]
    tot = [p["ms"]["total"] for p in ps if "total" in p.get("ms", {})]
    reasons = Counter((k, v) for p in ps for k, v in p.get("reasons", {}).items())
    P(f"- {s}: {len(ps)} runs, {len(bad)} failed; download MiB/s median {statistics.median(dl) if dl else '-'}, "
      f"total ms median {statistics.median(tot) if tot else '-'} p99 {sorted(tot)[int(0.99 * (len(tot) - 1))] if tot else '-'}; "
      f"CLOSE reasons seen: {', '.join(f'{k}={v:#x} x{n}' if isinstance(v, int) else f'{k}={v} x{n}' for (k, v), n in sorted(reasons.items(), key=str))}")
    for p in bad[:20]:
        P(f"  - FAIL min {(p['t'] - num(rows[0]['t'])) / 60:.1f}: {p.get('fail')}")

wb = jl("wbench.jsonl")
P("")
P("## wbench workloads")
P("| workload | runs | ok | bad | timeout | killed | median p50 us | median p99 us | MiB moved (up+down) |")
P("|---|---|---|---|---|---|---|---|---|")
by = {}
for r in wb:
    by.setdefault(r["wl"], []).append(r)
for wl, rs in sorted(by.items()):
    ok = [r for r in rs if isinstance(r.get("rc"), int) and r["rc"] == 0 and r.get("r") and r["r"]["errors"] == 0
          and r["r"]["conns_ok"] >= r["r"]["conns"]]
    to = sum(1 for r in rs if r.get("rc") == "timeout")
    kl = sum(1 for r in rs if r.get("rc") == "killed")
    bad = len(rs) - len(ok) - to - kl
    p50 = [r["r"]["p50_us"] for r in ok if r["r"].get("p50_us")]
    p99 = [r["r"]["p99_us"] for r in ok if r["r"].get("p99_us")]
    mib = sum((r["r"]["mib_s_up"] + r["r"]["mib_s_down"]) * r["r"]["duration"] for r in ok)
    P(f"| {wl} | {len(rs)} | {len(ok)} | {bad} | {to} | {kl} | {statistics.median(p50) if p50 else '-'} | "
      f"{statistics.median(p99) if p99 else '-'} | {mib:,.0f} |")
badruns = [r for r in wb if r.get("out")]
for r in badruns[:15]:
    P(f"- bad {r['wl']} rc={r.get('rc')} {' '.join(map(str, r['argv']))[:160]}: {r.get('r')} {r['out'][-300:]!r}")

ab = jl("abuse.jsonl")
P("")
P("## Abuse bursts")
for r in ab:
    P(f"- min {(r.get('t', 0) - num(rows[0]['t'])) / 60:.0f} {r.get('mode')}: ok={r.get('ok')} "
      + json.dumps({k: r.get(k) for k in ("conns", "sent_mib", "hold_s", "reasons", "missing", "fail", "s") if k in r}))

idle = [r for r in jl("idle.jsonl") if "n" in r and "event" not in r]
if idle:
    lf = [x for r in idle for x in r.get("live_fail", [])]
    P("")
    P("## Idle connections")
    P(f"- ticks {len(idle)}, count min/median/max {min(r['n'] for r in idle)}/{statistics.median(r['n'] for r in idle):.0f}/"
      f"{max(r['n'] for r in idle)}; opened {sum(r['opened'] for r in idle)}, closed by client {sum(r['closed'] for r in idle)}, "
      f"open failures {sum(r['open_fail'] for r in idle)}, closed by server {sum(r['server_closed'] for r in idle)}, "
      f"liveness failures {len(lf)}")
    for x in lf[:10]:
        P(f"  - {x}")
    errs = Counter(r["err"] for r in idle if r.get("err"))
    for e, n in errs.most_common(5):
        P(f"  - open error x{n}: {e}")

sl = [r for r in jl("slow.jsonl") if "event" not in r]
if sl:
    P("")
    P("## Slow readers")
    stuck = [r for r in sl if "stuck_at" in r]
    err = [r for r in sl if "err" in r]
    sc = Counter(r.get("server_close") for r in sl if r.get("server_close"))
    P(f"- readers {len(sl)}, MiB read {sum(r.get('bytes', 0) for r in sl) / 2**20:,.0f}, stuck (no byte 30 s) {len(stuck)}, "
      f"errors {len(err)}, server CLOSE reasons {dict(sc)}; worst max gap {max((r.get('max_gap_s', 0) for r in sl), default=0)} s")
    for r in (stuck + err)[:10]:
        P(f"  - {r}")

ho = [r for r in jl("halfopen.jsonl") if "cycle" in r]
if ho:
    P("")
    P("## Half-open clients")
    P(f"- cycles {len(ho)}, idle made {sum(len(r['idle_ports']) for r in ho)}, download made {sum(len(r['dl_ports']) for r in ho)}, "
      f"errors {sum(len(r['errs']) for r in ho)}")
    P(f"- server-side half-open at end: " + ", ".join(f"{k}={last.get(k)}" for k in ("A_ho_idle", "A_ho_dl", "B_ho_idle", "B_ho_dl")))

# ---------------------------------------------------------------- 30.11 base-1.2 re-soak sections
EXP = []  # (PASS/FAIL/INFO, text)


def expect(ok, text):
    EXP.append(("PASS" if ok else "FAIL", text))


caps = [e for e in ev if e["kind"] == "server_start"]
if caps:
    P("")
    P("## Capability lines")
    for e in caps:
        P(f"- {e['server']} gen {e['gen']}: {(e.get('capability') or ['(not recorded)'])[0][:400]}")
keepalive_on = any("dead peers" in (e.get("capability") or [""])[0] and "dead peers off" not in (e.get("capability") or [""])[0]
                   for e in caps)

rp = jl("reaps.jsonl")
if rp:
    P("")
    P("## Dead-peer reaping (half-open clients; base-1.2 expects idle ~180 s, with a queued download ~150-155 s)")
    # bands: idle = keepalive 120 + 4 x 15 s (+ a 2 s poll); dl = PEER_GONE_MS 150 s + 2 sweeps (2 s each) + poll.
    # A peer that dies at full probe backoff takes ~360 s (60.17: 3 unanswered probes); here it dies right after its download started.
    for kind, lo, hi in (("idle", 175, 200), ("dl", 145, 170)):
        for tls in (False, True):
            g = [r for r in rp if r["kind"] == kind and r["tls"] == tls]
            if not g:
                continue
            ok = [r["s"] for r in g if r["reaped"]]
            nr = [r for r in g if r["reaped"] is False]
            cen = [r for r in g if r.get("censored")]
            overdue = [r for r in cen if r["s"] > hi]
            orphan = [r for r in g if r.get("left_estab_s") is not None and r["reaped"] and r["s"] - r["left_estab_s"] > 4]
            q = (lambda v: f"min {min(v)} / median {statistics.median(v)} / max {max(v)} s") if ok else (lambda v: "-")
            P(f"- {kind} {'TLS' if tls else 'plain'}: {len(g)} marked, {len(ok)} reaped ({q(ok)}), {len(nr)} not reaped "
              f"within the limit, {len(cen)} still pending at the stop ({len(overdue)} overdue), {len(orphan)} left "
              f"ESTABLISHED > 4 s before the socket was gone (states {sorted(set(s for r in orphan for s in r['states']))})")
            text = f"reap {kind} {'TLS' if tls else 'plain'}: all {len(g) - len(cen) + len(overdue)} reaped in {lo}-{hi} s"
            if keepalive_on:
                expect(not nr and not overdue and all(lo <= s <= hi for s in ok), text)
            else:
                EXP.append(("INFO", text + ": not checked (capability line does not say dead peers are on)"))

idle_rows = [r for r in jl("idle.jsonl") if "n" in r and "event" not in r]
if idle_rows:
    sc = sum(r["server_closed"] for r in idle_rows)
    lf = sum(len(r.get("live_fail", [])) for r in idle_rows)
    last_i = idle_rows[-1]
    coh_sc = last_i.get("cohort_server_closed", 0)
    coh_lf = sum(len(r.get("cohort_live_fail", [])) for r in idle_rows)
    P("")
    P("## Live peers must stay (no false dead-peer resets)")
    P(f"- idle holder: closed by the server {sc}, liveness failures {lf}; cohort {last_i.get('cohort_n')}/"
      f"{last_i.get('cohort_opened')} alive at the end, closed by the server {coh_sc}, cohort liveness failures {coh_lf}")
    expect(sc == 0 and lf == 0, "idle holder: 0 server closes, 0 liveness failures")
    of = sum(r.get("open_fail", 0) for r in idle_rows)  # review: port/fd exhaustion would underfill the holder
    expect(of == 0, f"idle holder: 0 open failures ({of}; max held {max(r['n'] for r in idle_rows)})")
    if last_i.get("cohort_opened"):
        expect(coh_sc == 0 and coh_lf == 0, f"long-lived cohort ({last_i.get('cohort_opened')} conns, whole run): 0 server closes")
sl2 = [r for r in jl("slow.jsonl") if "event" not in r]
if sl2:
    pz = [r for r in sl2 if r.get("end") == "pause"]
    fr = [r for r in sl2 if r.get("false_reset")]
    stuck2 = [r for r in sl2 if "stuck_at" in r]
    P(f"- slow readers: {len(sl2)}, of them {len(pz)} paused 3-10 min mid-stream (zero window); false resets {len(fr)}, "
      f"stuck {len(stuck2)}, SIGSTOP time absorbed {sum(r.get('stopped_s', 0) for r in sl2)} s")
    for r in fr[:10]:
        P(f"  - {r}")
    live_err = [r for r in sl2 if (r.get("err") or r.get("server_close")) and not r.get("stopping")]
    for r in live_err[:10]:
        P(f"  - error/close: {r}")
    done_pz = sum(1 for r in pz if r.get("paused_s") is not None)
    expect(not fr and not stuck2 and not live_err,
           f"slow readers ({len(sl2)}, {done_pz} completed a 3-10 min zero-window pause): 0 false resets, 0 stuck, "
           f"0 server closes/errors")

dts = [r for r in jl("deadtarget.jsonl") if "cycle" in r]
if dts:
    P("")
    P("## Dead target sockets (blackholed website mid-stream; measured, not asserted. base-1.2 had no target-side timer;")
    P("master closes an idle/download stream with 0x47 once target keepalive (70.13) gives up, an upload when the kernel")
    P("stops retransmitting)")
    by = {}
    for r in dts:
        for sid, s in r["streams"].items():
            k = (s["kind"], r["tls"])
            by.setdefault(k, []).append((s, r))
    names = {"I": "idle stream", "D": "download", "U": "upload"}
    for (kind, tls), g in sorted(by.items()):
        cl = [s["close"] for s, _ in g if s["close"]]
        reasons = Counter(c["reason"] for c in cl)
        times = [c["s_after_cut"] for c in cl if c["s_after_cut"] is not None]
        cc = sum(1 for s, r in g if s["close"] is None)
        after = sum(s["down_after"] for s, _ in g)
        P(f"- {names[kind]} {'TLS' if tls else 'plain'}: {len(g)} streams; server CLOSE {len(cl)} {dict(reasons)}"
          + (f" at {min(times)}-{max(times)} s after the cut (median {statistics.median(times)})" if times else "")
          + f"; still open at the hold limit (client closed) {cc}; bytes received after the cut {after}")
    ef = sum(len(r["echo_fail"]) for r in dts)
    errs = [r["err"] for r in dts if r.get("err")]
    P(f"- cycles {len(dts)}; echo checks on the same connection failed {ef}; cycle errors {len(errs)} {errs[:3]}")
    unconf = sum(1 for r in dts for k in r.get("marked", []) if k.endswith("?"))
    P(f"- marking packets not confirmed at the cut (send buffer full; marked by the next transmission): {unconf}")
    expect(ef == 0 and not errs, "dead targets: the client connection stays usable (echo every 60 s), no cycle errors")
    fin2 = jl("final_sample.jsonl")
    if fin2:
        left = {s: fin2[-1].get(f"{s}_dt_socks") for s in "AB"}
        P(f"- server-owned sockets to the dead-target port in the final sample: {left} (open cycles at the stop excluded)")

bw = jl("bench.jsonl")
if bw:
    P("")
    P("## Bench windows: {aged A, fresh F} x {aged, fresh target} x download 3x3 / 4x4 (tcp-safe: 1x1 / 1x2) (MiB/s, median per window)")
    wins_b = sorted(set(r["n"] for r in bw))
    cells = sorted(set((r["server"], r["target"], r["cs"]) for r in bw))
    BCONNS = {r["cs"]: r.get("conns", r["cs"]) for r in bw}  # 30.17 review: tcp-safe cells are 1 x cs
    P("| window | hour | " + " | ".join(f"{s}/{t}/{BCONNS[c]}x{c}" for s, t, c in cells) + " |")
    P("|---|---|" + "---|" * len(cells))
    med = {}
    for n in wins_b:
        rs = [r for r in bw if r["n"] == n]
        row_ = []
        for cell in cells:
            v = [r["mib_s"] for r in rs if (r["server"], r["target"], r["cs"]) == cell and r["mib_s"]]
            med[(n, cell)] = statistics.median(v) if v else None
            row_.append("-" if not v else f"{med[(n, cell)]:,.0f}")
        P(f"| {n} | {rs[0]['h']:.2f} | " + " | ".join(row_) + " |")
    P("")
    P("Drift per hour (Theil-Sen over windows, % of mean) of the ratios; aging of the server = aged/fresh server")
    P("with the same target; aging of the target = aged/fresh target on the fresh server.")
    hours = {n: [r for r in bw if r["n"] == n][0]["h"] for n in wins_b}
    for label, num_, den in [("server A/F, aged target", ("A", "aged"), ("F", "aged")),
                             ("server A/F, fresh target", ("A", "fresh"), ("F", "fresh")),
                             ("target aged/fresh, server F", ("F", "aged"), ("F", "fresh")),
                             ("target aged/fresh, server A", ("A", "aged"), ("A", "fresh"))]:
        for cs in sorted(set(r["cs"] for r in bw)):  # 30.17 (tcp-safe cells 1 / 2)
            pts = [(hours[n], med[(n, num_ + (cs,))] / med[(n, den + (cs,))]) for n in wins_b
                   if med.get((n, num_ + (cs,))) and med.get((n, den + (cs,)))]
            if len(pts) >= 3:
                m = statistics.fmean(v for _, v in pts)
                sl = theil_sen([h for h, _ in pts], [v for _, v in pts])
                P(f"- {label}, {BCONNS[cs]}x{cs}: mean ratio {m:.3f}, {100 * sl / m:+.2f} %/h ({len(pts)} windows)")
    bad = [r for r in bw if r["rc"] != 0 or (r["errors"] or 0) > 0 or not r["mib_s"]]
    reps_ = max(r["round"] for r in bw) + 1
    short = [n for n in wins_b if sum(1 for r in bw if r["n"] == n) < 8 * reps_]
    bstart = sum(1 for e in ev if e["kind"] == "bench_start")
    skipped = [e for e in ev if e["kind"] == "harness_error" and e.get("where") == "bench"]
    expect(not bad and not short and not skipped,
           f"bench windows: {len(wins_b)} of {bstart} with results, {len(bw)} runs, 0 errors, every window "
           f"{8 * reps_} cells (short: {short}, skipped/failed windows: {len(skipped)})")

if ab:
    P("")
    P("## Heap after abuse bursts (cgroup anon; median of 60 s before the burst vs 60-180 s after it ended)")
    for s in "AB":
        out = []
        for r in ab:
            t1 = r.get("t", 0); t2 = t1 + (r.get("s") or 0)
            before = [num(x.get(f"{s}_cg_anon_kib")) for x in rows if t1 - 60 <= num(x["t"]) < t1]
            after = [num(x.get(f"{s}_cg_anon_kib")) for x in rows if t2 + 60 <= num(x["t"]) < t2 + 180]
            before = [v for v in before if v is not None]; after = [v for v in after if v is not None]
            if before and after:
                out.append((r["mode"], statistics.median(before) / 1024, statistics.median(after) / 1024))
        if out:
            d = [x[2] - x[1] for x in out]
            P(f"- {s}: {len(out)} bursts, anon after - before: median {statistics.median(d):+.1f} MiB, max {max(d):+.1f} MiB")

# ---------------------------------------------------------------- 30.14 server metrics (--metrics-interval)
MK_ZERO = ("pool_fallback", "pool_capped", "pool_madvise_fail", "pool_munmap_fail", "accept_err_fd", "accept_err_mem")
MK_SHOW = ("accepted", "connects", "dead_peers", "refuse_admit", "refuse_streams", "refuse_dns", "holds", "shed_pend",
           "shed_hold", "shed_over_credit", "shed_holder", "shed_client", "hs_expired", "tls_expired", "cap_apply",
           "level_changes", "cache_hit", "cache_miss", "pool_remote", "pool_madvise", "pool_munmap", "ktls_starve",
           "ktls_starve_slices", "ktls_starve_ms_max", "keyupdate_closes", "close_03", "close_41", "close_42",
           "close_43", "close_44", "close_48", "close_49") + MK_ZERO


def final_metrics(s, gen):
    """last ev=metrics_final (or ev=metrics) line of server s, generation gen (the server log)."""
    p = os.path.join(a.run, f"server{s}.{gen}.log")
    last = None
    if os.path.exists(p):
        for line in open(p, errors="replace"):
            if " ev=metrics" in line:
                last = dict(kv.split("=", 1) for kv in line.split()[1:] if "=" in kv)
    return last


gens = {s: int(num(last.get(f"{s}_gen")) or 0) for s in "AB"}
mf = {(s, g): final_metrics(s, g) for s in "AB" for g in range(gens[s] + 1)}
if any(mf.values()):
    P("")
    P("## Server metrics (last metrics line of each server generation; counters cumulative since its start)")
    P("| key | " + " | ".join(f"{s}.{g}" for s, g in mf) + " |")
    P("|---|" + "---|" * len(mf))
    for k in ("up", "ev") + MK_SHOW + ("pool_chunks", "pool_dirty_kib", "pool_release_max_us", "pool_release_cpu_max_us"):
        P(f"| {k} | " + " | ".join((m or {}).get(k, "-") for m in mf.values()) + " |")
    for s in "AB":
        rel = [num(r.get(f"{s}_m_pool_release_max_us")) for r in rows if num(r.get(f"{s}_m_pool_release_max_us")) is not None]
        # 60.16: its thread CPU time (missing on older binaries)
        rcpu = [num(r.get(f"{s}_m_pool_release_cpu_max_us")) for r in rows if num(r.get(f"{s}_m_pool_release_cpu_max_us")) is not None]
        dirty = [num(r.get(f"{s}_m_pool_dirty_kib")) for r in rows if num(r.get(f"{s}_m_pool_dirty_kib")) is not None]
        ch = [num(r.get(f"{s}_m_pool_chunks")) for r in rows if num(r.get(f"{s}_m_pool_chunks")) is not None]
        if dirty:
            P(f"- {s}: pool dirty KiB median {statistics.median(dirty):,.0f} max {max(dirty):,.0f}; chunks median "
              f"{statistics.median(ch):,.0f} max {max(ch):,.0f}; release max {max(rel) if rel else '-'} us"
              f" (cpu {max(rcpu) if rcpu else '-'} us)")
    for s, g in mf:
        m = mf[(s, g)] or {}
        # review (all): a key that is missing is not a 0; pool_* exist only in pool builds (every build since 60.18 #11;
        # older runs of a base-4 NOFEAT or pre-70.25 binary lack them: then INFO, not PASS)
        keys = MK_ZERO if "pool_chunks" in m else tuple(k for k in MK_ZERO if not k.startswith("pool_"))
        if m and "pool_chunks" not in m:
            EXP.append(("INFO", f"{s}.{g} metrics: no pool_* keys (a pre-pool / NOFEAT binary?)"))
        bad = {k: m.get(k) for k in keys if m.get(k) != "0"}
        expect(bool(m) and not bad, f"{s}.{g} metrics: {', '.join(keys)} all 0 {bad if bad else ''}".rstrip())
        if g == gens[s]:  # the last generation must have logged its final line at SIGTERM (drained, not SIGKILLed)
            expect(m.get("ev") == "metrics_final", f"{s}.{g}: last metrics line is ev=metrics_final (got {m.get('ev')})")
    if rp:
        dp = sum(int((mf[(s, g)] or {}).get("dead_peers", 0)) for s, g in mf)
        EXP.append(("INFO", f"dead_peers counter (sum over servers) {dp} vs reaps.jsonl reaped "
                    f"{sum(1 for r in rp if r.get('reaped'))} (dead_peers counts only the TCP_INFO reset with output "
                    f"queued; keepalive reaps are the kernel's)"))

# ---------------------------------------------------------------- 30.16 memory minima (the 30.14 estimator)
P("")
P("## Memory minima (30-min bucket minima after warm-up; Theil-Sen; 95 % bucket bootstrap, seed 1)")
P("Pass rule (30.16): the CI lower bound of RSS and anon must be < 1 %/h of the mean (a slope that is surely")
P("above 1 %/h fails); the KiB/h values are what a drift would cost. At --scale > 1 the idle count random-walks over")
P("12-50k connections: the rule then uses the series adjusted for the server's ESTAB count (y - b * estab, b from an")
P("OLS of every post-warm-up sample on hour and ESTAB), shown as *_adj.")
_rng = __import__("random").Random(1)
RAW_MEAN = {}
for s in "AB":
    est = f"{s}_tcp_estab"
    for k in ("rss_kib", "anon_kib", "cg_anon_kib", "cg_aks_kib", "rss_kib_adj", "anon_kib_adj"):
        base_k = k[:-4] if k.endswith("_adj") else k
        coef = 0.0
        if k.endswith("_adj"):
            tri = [(num(r["min"]) / 60, num(r.get(est)), num(r.get(f"{s}_{base_k}"))) for r in post]
            tri = [t for t in tri if None not in t]
            fit = ols2([t[0] for t in tri], [t[1] for t in tri], [t[2] for t in tri]) if len(tri) > 10 else None
            if not fit:
                continue
            coef = fit[1]
        b = {}
        for r in post:
            v = num(r.get(f"{s}_{base_k}")); e = num(r.get(est)) or 0
            if v is not None:
                b.setdefault(int(num(r["min"]) / 30), []).append(v - coef * e)
        # review: >= 90 samples (half a bucket at 10 s): a short trailing bucket must not set a minimum
        pts = [((kk + 0.5) / 2, min(v)) for kk, v in sorted(b.items()) if len(v) >= 90]
        if len(pts) < 4:
            continue
        mean = statistics.fmean(v for _, v in pts)
        if k.endswith("_adj"):
            # 30.18 review of the RC1 12 h data: the adjusted series is shifted by b x ESTAB (B at K 25: mean below 0, so
            # its %/h flipped sign and order); a percentage is taken of the raw series' mean (same KiB/h unit)
            mean = RAW_MEAN.get((s, base_k), mean)
        else:
            RAW_MEAN[(s, k)] = mean
        sl = theil_sen([h for h, _ in pts], [v for _, v in pts])
        bs = []
        for _ in range(2000):
            smp = [pts[_rng.randrange(len(pts))] for _ in pts]
            if len(set(h for h, _ in smp)) >= 3:
                bs.append(theil_sen([h for h, _ in smp], [v for _, v in smp]))
        bs.sort()
        lo, hi = bs[int(0.025 * len(bs))], bs[int(0.975 * len(bs))]
        P(f"- {s} {k}: {sl:+,.0f} KiB/h [{lo:+,.0f}, {hi:+,.0f}] = {100 * sl / mean:+.2f} %/h [{100 * lo / mean:+.2f}, "
          f"{100 * hi / mean:+.2f}] ({len(pts)} buckets, {pts[0][1]:,.0f} -> {pts[-1][1]:,.0f} KiB"
          + (f"; {coef:.2f} KiB per ESTAB" if coef else "") + ")")
        if k in (("rss_kib_adj", "anon_kib_adj") if SCALE > 1 else ("rss_kib", "anon_kib")):
            expect(100 * lo / mean < 1.0, f"{s} {k} minima: CI lower bound {100 * lo / mean:+.2f} %/h < 1 %/h")

# ---------------------------------------------------------------- 30.16 floor snapshots (smaps at each quiet window end)
fl = jl("floors.jsonl")
if fl:
    P("")
    P("## Heap at the floors (smaps: [heap] = glibc main arena; anon maps = thread arenas, pool chunks, stacks)")
    for s in "AB":
        g = [r for r in fl if r["server"] == s and r.get("h", 0) * 60 >= a.warmup_min]
        if len(g) < 3:
            continue
        for k in ("sm_anonymous_kib", "sm_heap_kib", "sm_anon_maps_kib", "sm_anon_maps", "cg_anon_kib", "cg_kernel_kib"):
            pts = [(r["h"], r[k]) for r in g if r.get(k) is not None]  # review: one failed read drops one point only
            if len(pts) < 3:
                continue
            P(f"- {s} {k}: {pts[0][1]:,} -> {pts[-1][1]:,} ({len(pts)} floors), Theil-Sen "
              f"{theil_sen([h for h, _ in pts], [v for _, v in pts]):+,.1f}/h")

# ---------------------------------------------------------------- 30.14 run-wide expectations
expect(kinds.get("server_died", 0) == 0, f"no server died (server_died events {kinds.get('server_died', 0)})")
stops = [e for e in ev if e["kind"] == "server_stop"]
expect(len(stops) == 2 and all(e.get("rc") == 0 for e in stops),
       f"both servers exited 0 on SIGTERM (server_stop: {[(e.get('server'), e.get('rc')) for e in stops]})")
for s in "AB" if not NO_SCOPE else ():
    # review: every sample (each generation has its own scope), and a never-recorded field is not a 0
    oom = [num(r.get(f"{s}_cg_oom_kill")) for r in rows]; mx = [num(r.get(f"{s}_cg_max_ev")) for r in rows]
    oom = [v for v in oom if v is not None]; mx = [v for v in mx if v is not None]
    if True:
        expect(bool(oom) and bool(mx) and max(oom) == 0 and max(mx) == 0,
               f"{s}: 0 OOM kills, 0 memory.max events in every sample ({len(oom)} samples with the field)")
if NO_SCOPE:  # 30.16 --no-scope (from the start event): no per-server cgroup; the harness's cgroup instead
    st = [e.get("oom_kill") for e in ev if e["kind"] == "hcg_oom_start"]
    hoom = [num(r.get("h_cg_oom_kill")) for r in rows] + [num(f.get("h_cg_oom_kill")) for f in jl("final_sample.jsonl")]
    hoom = [v for v in hoom if v is not None]
    base = num(st[0]) if st else None
    if hoom and base is not None:
        expect(max(hoom) == base, f"no scopes (--no-scope): harness/container cgroup oom_kill {base:.0f} at the start, "
                                  f"max {max(hoom):.0f} over {len(hoom)} samples incl. the final one")
    else:
        expect(False, "no scopes (--no-scope): harness cgroup oom_kill not recorded (OOM kills not measurable)")
# 30.16 heavy lane --mem-budget-b: B's memory-level episodes. Sources, in log order: both ends of every logged
# "memory level a -> b" line, the metrics line's level gauge (level_gauge events, newer runs) and level 0 at every B
# start. The server always logs a change to 0 and every change to or from 3; others within 5 s of the last logged one
# are only counted ("k changes not logged"), so an episode can begin unlogged: it then starts at the previous point
# (conservative). A B run or probe that fails while an episode of peak >= 2 overlaps it (+- LEVEL_GRACE: lines are
# read <= 10 s late) is "degraded" when EVERY printed error is an allowed shed (below); at peak 1 nothing may fail.
import re  # noqa: E402


def _budget_b(argv):
    for i, x in enumerate(argv):
        if x == "--mem-budget-b" and i + 1 < len(argv):
            return argv[i + 1]
        if x.startswith("--mem-budget-b="):  # review
            return x.split("=", 1)[1]
    return None


BUDGET_B = _budget_b(_argv)  # deliberate: assumes B's level floor is 0 (budget >= 256 MiB, mem.rs floor)
LEVEL_GRACE = 30
_LV = re.compile(r"memory level (\d) -> (\d)\b(?:.*?(\d+) changes not logged)?")


def level_points(s):
    pts = []  # (t, level, kind); events.jsonl is in log order (ts equal within one read)
    for e in ev:
        if e.get("server") != s:
            continue
        if e["kind"] == "server_start":
            pts.append((e["t"], 0, "start"))  # review: a restart has no "-> 0" line
        elif e["kind"] == "level_gauge":
            pts.append((e["t"], int(e["level"]), "gauge"))
        elif e["kind"] == "mem_level":
            m = _LV.search(e.get("line", ""))
            if m:
                frm, to, quiet = int(m[1]), int(m[2]), int(m[3] or 0)
                # unlogged changes only go to 1 or 2 and never leave 3: reaching a from-level 1 through >= 2 of them
                # passed level 2
                pts.append((e["t"], 2 if frm == 1 and quiet >= 2 else frm, "from"))
                pts.append((e["t"], to, "to"))
    return pts


def level_episodes(s):
    pts = level_points(s)
    eps, start, peak, last_t = [], None, 0, None
    for t, lvl, kind in pts:
        if lvl >= 1:
            if start is None:
                # review 2 (review): a gauge can precede its own "0 -> n" line (published before the logger writes):
                # its change happened within one metrics interval (10 s) + read lag, not back to the last point
                start, peak = (last_t if last_t is not None else t), lvl
                if kind == "gauge":
                    start = max(start, t - 20)
            peak = max(peak, lvl)
        elif start is not None:
            eps.append((start, t, peak))
            start = None
        last_t = t
    if start is not None:
        eps.append((start, float("inf"), peak))
    return sum(1 for p in pts if p[2] == "to"), eps


B_EPS = level_episodes("B")[1] if BUDGET_B else []


def ep_peak(t0, t1):
    return max((p for a_, b_, p in B_EPS if t0 <= b_ + LEVEL_GRACE and t1 >= a_ - LEVEL_GRACE), default=0)


# wbench error lines (bench/src/run.rs, connchurn.rs) allowed inside a peak >= 2 episode: 0x49 closes, the shed
# WebSocket close 1013, connection loss, and (admission paused at 2+, no client reads at 3) setup / iteration timeouts
# review 2 (review): plus connchurn's forms (connchurn.rs one()) and run.rs setup-phase losses (ws::connect)
_LOSS = r"(eof|eof during ws handshake|Connection reset by peer \(os error 104\)|Broken pipe \(os error 32\))"
WB_OK = re.compile(r"(server closed stream \d+ \(reason 0x49\)|server sent connection CLOSE \(reason 0x49\)"
                   r"|websocket closed by server \(code 1013\)|websocket TCP connection closed by server"
                   r"|(read|write): (Connection reset by peer \(os error 104\)|Broken pipe \(os error 32\))"
                   r"|setup timeout|timeout \(10 s\)|timeout waiting for Wisp CONTINUE handshake"
                   r"|stream closed by the server \(reason 0x49\)|server closed before CONTINUE"
                   r"|server closed the WebSocket before the echo"
                   r"|((connect/upgrade|waiting for CONTINUE|send CONNECT\+DATA|waiting for the echo): )?" + _LOSS + ")")
# the same allowlist as error_kinds keys (bench/src/errkind.rs classify); errno 104 = ECONNRESET, 32 = EPIPE
WB_OK_KINDS = {"stream_0x49", "conn_close_0x49", "ws_1013", "errno_104", "errno_32", "eof", "setup_timeout",
               "handshake_timeout", "timeout"}
WB_PREFIX = re.compile(r"^wbench error: (?:conn \d+: |connchurn loop \d+: )?")


def wb_server(r):
    return "B" if any(":7002/" in str(x) for x in r.get("argv", [])) else "A"


def wb_degraded(r):
    """None = not degraded; else True / "tail" (older wbench, more errors than it prints (8): the rest unverified)"""
    if not B_EPS or wb_server(r) != "B" or r.get("rc") not in (0, 3) or not r.get("r"):
        return None
    if any((r["r"].get(k) or 0) > 0 for k in ("verify_content_errors", "verify_count_errors", "verify_missing")):
        return None
    t1 = r.get("t", 0); t0 = t1 - (r.get("s") or 0)
    if ep_peak(t0, t1) < 2:
        return None
    errors = r["r"].get("errors") or 0
    ek = r["r"].get("error_kinds")
    if ek is not None:
        # 30.16 wbench error_kinds (errkind.rs): every counted error has a key, so the whole run is checked; the
        # printed text is not (review: connchurn's close lines now carry "(code N)", the counters decide)
        return True if errors > 0 and sum(ek.values()) == errors and set(ek) <= WB_OK_KINDS else None
    lines = [WB_PREFIX.sub("", x) for x in r.get("out", "").splitlines() if x.startswith("wbench error: ")]
    if not lines or not all(WB_OK.fullmatch(x) for x in lines):
        return None  # review (all): a run with no printed reason, or any other line, stays a failure
    return "tail" if errors > len(lines) else True  # older wbench: text only


# 30.16 smoke8: with a budget, B also sheds at level 0: pend_sweep (worker/sweep.rs, "at every level") closes the largest
# upload backlogs with 0x49 once the worker's total is over pend_cap (the budget's share). A B run whose only errors
# are stream 0x49 closes counts as degraded ("budget shed") when B's shed counters rose by at least that many over
# the run (+ one sample on each side), in the same server generation.
# review 3 (review): only the budget's own stream sheds; shed_holder counts client resets, shed_over_credit a client
# over its credit (not a budget consequence)
SHED_KEYS = ("B_m_shed_pend", "B_m_shed_hold")


def budget_shed(r):
    if not BUDGET_B or wb_server(r) != "B" or r.get("rc") != 0 or not r.get("r"):
        return False
    ek, errors = r["r"].get("error_kinds"), r["r"].get("errors") or 0
    if not ek or set(ek) != {"stream_0x49"} or ek["stream_0x49"] != errors:
        return False
    if any((r["r"].get(k) or 0) > 0 for k in ("verify_content_errors", "verify_count_errors", "verify_missing")):
        return False
    if not r.get("s"):
        return False  # review 3 (review): no duration, no window
    t1 = r.get("t", 0); t0 = t1 - r["s"]
    before = [x for x in rows if num(x.get("t")) is not None and num(x["t"]) <= t0 - 1]
    after_ = [x for x in rows if num(x.get("t")) is not None and num(x["t"]) >= t1 + 1]
    if not before or not after_ or before[-1].get("B_gen") != after_[min(1, len(after_) - 1)].get("B_gen"):
        return False
    lo, hi = before[-1], after_[min(1, len(after_) - 1)]  # metrics lines lag the sample by <= 10 s: one more
    if any(num(x.get(k)) is None for x in (lo, hi) for k in SHED_KEYS):
        return False  # review 3 (review): a blank (no metrics line yet) is not a zero baseline
    d = sum(num(hi[k]) - num(lo[k]) for k in SHED_KEYS)
    return d >= errors


# probe fail lines (probe.py) allowed inside a peak >= 2 episode; COMPANION only next to a 0x49 line of the same
# probe (the bytes a shed stream did not deliver); STALL (no client reads) only at peak 3
P_SHED = re.compile(r"[a-z0-9_]+: (stream \d+ closed by server, reason 49|CLOSE reason 0x49, expected 0x[0-9a-f]+"
                    r"|(stream \d+: )?unexpected CLOSE 49 after \d+ echoed bytes|CLOSE 49|CLOSE 0x49, expected 0x[0-9a-f]+)")
P_COMPANION = re.compile(r"download: got \d+ bytes, expected \d+|streams100: \d+ of 100 streams got no full echo in 20 s")
P_CONN = re.compile(r"conn: (TimeoutError: .*|ConnectionResetError: .*|BrokenPipeError: .*|Closed: EOF"
                    r"|Closed: connection closed|Closed: no upgrade response"
                    r"|Closed: recv: \[Errno (104|32)\] .*"  # review 2 (review): resets only, not ssl.SSLError
                    r"|Closed: expected CONTINUE 0, got \(4, 0, b'I.*)")  # review: 'I' = 0x49 only
P_STALL = re.compile(r"(upload|upmux): stalled: .*")


def probe_degraded(p):
    if not B_EPS or p.get("server") != "B" or p.get("ok") or not p.get("fail"):
        return False
    t0 = p.get("t", 0); t1 = t0 + (p.get("ms", {}).get("total") or 0) / 1000
    peak = ep_peak(t0, t1)
    if peak < 2:
        return False
    fl = p["fail"]
    shed_steps = {f.split(":", 1)[0] for f in fl if P_SHED.fullmatch(f)}  # review 2 (review): same step only
    return all(P_SHED.fullmatch(f) or P_CONN.fullmatch(f)
               or (f.split(":", 1)[0] in shed_steps and P_COMPANION.fullmatch(f))
               or (peak >= 3 and P_STALL.fullmatch(f)) for f in fl)


if BUDGET_B:
    nchg, _ = level_episodes("B")
    P("")
    P(f"## Server B memory levels (--mem-budget-b {BUDGET_B}; A is the unbudgeted control)")
    fin_eps = [e for e in B_EPS if e[1] != float("inf")]
    dur = [e[1] - e[0] for e in fin_eps]
    peaks = Counter(e[2] for e in B_EPS)
    P(f"- logged level changes {nchg}; episodes {len(B_EPS)} (peak level: {dict(sorted(peaks.items()))}); time at >= 1 "
      f"(conservative bounds): {sum(dur):,.0f} s; longest {max(dur, default=0):,.0f} s; median "
      f"{statistics.median(dur) if dur else 0:,.0f} s")
    expect(nchg > 0, f"B level transitions exercised under scale ({nchg} logged changes, {len(B_EPS)} episodes)")
    # review: the final level from the last metrics line of B's last generation (the gauge), not
    # from the rate-limited log lines
    fl_b = (mf.get(("B", gens["B"])) or {}).get("level")
    expect(fl_b == "0", f"B at level 0 at the end (last metrics line level={fl_b}; open episodes "
                        f"{len(B_EPS) - len(fin_eps)})")
    EXP.append(("INFO", f"A (control, no budget) level changes: {level_episodes('A')[0]}"))
for s_ in "AB":
    # 30.16 wbench error_kinds summed over the runs against each server (newer wbench; empty with an older one)
    ek_tot = Counter()
    for r in wb:
        if wb_server(r) == s_ and r.get("r") and r["r"].get("error_kinds"):
            ek_tot.update(r["r"]["error_kinds"])
    if ek_tot:
        P(f"- wbench error kinds vs {s_}: " + ", ".join(f"{k} {v:,}" for k, v in ek_tot.most_common()))
TCPS = next((e for e in ev if e["kind"] == "tcp_summary"), None)  # 30.17 --tcp-safe
if "--tcp-safe" in _argv:
    expect(TCPS is not None, "tcp-safe: tcp_summary recorded")
    if TCPS:
        expect(TCPS["pressures"] == 0, f"tcp-safe: TcpExt TCPMemoryPressures during the run {TCPS['pressures']}")
        expect(TCPS["peak"] < 0.5 * TCPS["tcp_mem1"], f"tcp-safe: host TCP peak {TCPS['peak']:,} pages < 0.5 x "
                                                       f"tcp_mem[1] {TCPS['tcp_mem1']:,} (0.5 s monitor)")
        EXP.append(("INFO", f"tcp-safe: runs delayed by the TCP gate {TCPS['gated']}"))
    expect(not any(e["kind"] == "tcp_pressure_abort" for e in ev), "tcp-safe: no pressure abort")
pdeg = [p for p in pr if probe_degraded(p)]
pfail = sum(1 for p in pr if not p.get("ok")) - len(pdeg)
expect(pfail == 0, f"probes: {len(pr)} runs, {pfail} failed" + (f" ({len(pdeg)} B probes degraded inside a level >= 2 "
                                                                    f"episode: 0x49 shed / connection loss only)" if pdeg else ""))
wbby = {}
for r in wb:
    wbby.setdefault(r["wl"], []).append(r)
for wl, rs in sorted(wbby.items()):
    # review (all): the same predicate as the workload table (a timeout or a crash can have empty output)
    badr = [r for r in rs if r.get("rc") != "killed" and not (
        r.get("rc") == 0 and r.get("r") and r["r"].get("errors") == 0 and r["r"].get("conns_ok", 0) >= r["r"].get("conns", 1))]
    dg = [wb_degraded(r) or ("shed" if budget_shed(r) else None) for r in badr]
    deg = sum(1 for x in dg if x and x != "shed")
    tail = sum(1 for x in dg if x == "tail")
    bshed = sum(1 for x in dg if x == "shed")
    nb = len(badr) - deg - bshed
    expect(nb == 0, f"wbench {wl}: {len(rs)} runs, {nb} bad/timeout"
           + (f" ({bshed} B runs with 0x49 closes outside a level >= 2 episode, all matched by B's own shed counters "
              f"(pend_cap / hold sheds))" if bshed else "")
           + (f" ({deg} B runs degraded inside a level >= 2 episode, every error an allowed shed"
              + (f"; {tail} of them from an older wbench without error_kinds: only the first 8 printed errors "
                 f"checked" if tail else "") + ")" if deg else ""))
expect(kinds.get("harness_error", 0) == 0, f"harness errors {kinds.get('harness_error', 0)}")

if EXP:
    P("")
    P("## Expectations")
    for k, t in EXP:
        P(f"- {k} {t}")
    open(os.path.join(OUT, "analysis.md"), "w").write("\n".join(lines) + "\n")

open(os.path.join(OUT, "analysis.md"), "w").write("\n".join(lines) + "\n")
print("\n".join(lines))

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("(matplotlib not available: no plots)")
    sys.exit(0)

panels = [("RSS MiB", [("A_rss_kib", 1 / 1024), ("B_rss_kib", 1 / 1024)]),
          ("cgroup memory.current MiB", [("A_cg_cur_kib", 1 / 1024), ("B_cg_cur_kib", 1 / 1024)]),
          ("fds (minus half-open)", [("A_fds_adj", 1), ("B_fds_adj", 1)]),
          ("half-open server sockets", [("A_ho_idle", 1), ("A_ho_dl", 1), ("B_ho_idle", 1), ("B_ho_dl", 1)]),
          ("server CPU % (5 min mean)", [("A_cpu_pct", 1), ("B_cpu_pct", 1)]),
          ("canary rr latency ms", [("canary_p50_us", 1e-3), ("canary_p99_us", 1e-3)]),
          ("host slab MiB", [("h_Slab", 1 / 1024), ("h_SUnreclaim", 1 / 1024)]),
          ("memory level", [("A_level", 1), ("B_level", 1)]),
          ("server ESTAB sockets", [("A_tcp_estab", 1), ("B_tcp_estab", 1)]),
          ("pool dirty MiB (30.14 metrics)", [("A_m_pool_dirty_kib", 1 / 1024), ("B_m_pool_dirty_kib", 1 / 1024)])]
fig, axes = plt.subplots(len(panels), 1, figsize=(12, 2.4 * len(panels)), sharex=True)
for ax, (title, keys) in zip(axes, panels):
    for key, k in keys:
        pts = series(key, rows)
        if not pts:
            continue
        xs, ys = [h for h, _ in pts], [v * k for _, v in pts]
        if "cpu" in key:
            w = 30
            ys = [statistics.fmean(ys[max(0, i - w + 1):i + 1]) for i in range(len(ys))]
        ax.plot(xs, ys, lw=0.7, label=key)
    if not ax.lines:
        continue
    ax.axvline(a.warmup_min / 60, color="gray", ls=":", lw=0.8)
    for w in wins:
        ax.axvspan(num(w[0]["min"]) / 60, num(w[-1]["min"]) / 60, color="green", alpha=0.12, lw=0)
    ax.set_title(title, fontsize=9)
    ax.legend(fontsize=7, loc="upper left")
    ax.grid(alpha=0.3)
axes[-1].set_xlabel("hours")
fig.tight_layout()
fig.savefig(os.path.join(OUT, "soak.png"), dpi=110)
print(f"plot: {os.path.join(OUT, 'soak.png')}")
