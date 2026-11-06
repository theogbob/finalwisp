"""60.01 Phase B regression harness: one command, one table, new build vs the base build (30.10: `wst regress`).

usage: wst regress (or bench/regress.py) --base BIN --new BIN [--suite lo,tls,idle,link,potato] [--reps N] [--out DIR]
                  [--args "extra server args"] [--new-args=--flag ...] [--cert C --key K] [--wbench PATH] [--quick]
       (args that start with "-" need the --new-args=VALUE form)

Runs the A/B runner (wispsuite.ab: interleaved, start variant rotated per rep) for every case, with one record per run, then
pairs the runs by rep. The paired Hodges-Lehmann (HL) ratio, exact two-sided Wilcoxon signed-rank p,
and 90% CI all use log(new/base). Marginal medians and their ratio are descriptive only. Verdicts:
  LOSS  paired HL worse with p < 0.05          WIN  paired HL better with p < 0.05
  watch >= 3% worse, not significant
  tie   not significant and the 90% CI of the ratio is within 5% on the worse side (non-inferior, 60.12); idle row
        also: a WIN / LOSS / watch whose paired difference is below the RSS resolution (30.10; verdict_raw, note)
  unclear  significant but paired HL is neutral; or not significant, < 3% worse, and CI permits a > 5% cost
Server CPU per unit of work and peak RSS are reported next to the main metric (they are less noisy than
throughput and catch a feature that costs CPU or memory without moving the headline number yet).
Suites:
  lo      8 loopback cases, plain ws://
  tls     wss:// download 10x10 + rr 10x10 (needs --cert/--key; kTLS)
  idle    KiB per idle connection (idle_rss.py, 2000 clients)
  link    root only: netns links (netns_hol.sh): 100 Mbit / 10 ms each way page test (browse 1x6 + 1 bulk),
          1 Gbit / 20 ms each way download 1x1 + 10x10
  potato  systemd-run scopes: potato_curve.py at 16/32/64/128 MiB, survival + ratio where both survive
Exit status 1 if any case is a LOSS or anything is incomplete: a runner that exited non-zero, fewer paired reps
than asked, a metric with no data, any benchmark error in either build (the case is then `invalid`, 60.15 T08), or a
requested suite that could not run (all listed as PROBLEM lines). Stdlib only (the test boxes have python3 and nothing else).
"""
import argparse, contextlib, json, os, resource, statistics as st, subprocess, sys, time
from collections import defaultdict
from . import ab as abmod, idle as idlemod, potato as potatomod, proc, report, wbench, xhost as xhostmod
from .sample import tcp_pressure
from .stats import ALPHA, WATCH, BIG, NI_MARGIN, compare

HERE = report.BENCH

def find(name):
    for p in (os.path.join(HERE, name), os.path.join(HERE, "vps", name), os.path.join(HERE, "..", name)):
        if os.path.exists(p):
            return os.path.abspath(p)
    sys.exit(f"regress.py: {name} not found next to {HERE}")

# case: id, ab.py args, [(metric, higher_better)]
LO = [("download 1x1", "--test download --conns 1 --streams 1", [("mib_s_down", True)]),
      ("download 10x10", "--test download --conns 10 --streams 10", [("mib_s_down", True)]),
      ("upload 1x1", "--test upload --conns 1 --streams 1", [("mib_s_up", True)]),
      ("upload 10x10", "--test upload --conns 10 --streams 10", [("mib_s_up", True)]),
      ("echo 1x1", "--test echo --conns 1 --streams 1", [("mib_s_down", True)]),
      ("echo 10x10", "--test echo --conns 10 --streams 10", [("mib_s_down", True)]),
      ("rr 10x10", "--test rr --conns 10 --streams 10", [("rps", True)]),
      ("churn 10x10", "--test churn --conns 10 --streams 10", [("rps", True)]),
      # 30.10: a new WebSocket connection per request (churn reuses its connections)
      ("connchurn 10x10", "--test connchurn --conns 10 --streams 10", [("rps", True), ("p99_us", False)]),
      # 30.10: 3 x (5 s download, 3 s idle) on one server process; ~24 s per run, independent of --dur
      ("burstidle 10x10", "--test burstidle --conns 10 --streams 10", [("mib_s_down", True)])]
TLS = [("wss download 10x10", "--test download --conns 10 --streams 10", [("mib_s_down", True)]),
       ("wss rr 10x10", "--test rr --conns 10 --streams 10", [("rps", True)]),
       ("connchurn-tls 10x10", "--test connchurn --conns 10 --streams 10", [("rps", True), ("p99_us", False)])]
PAGE = [("page 100M/20ms", "--test browse --conns 1 --streams 6 --bulk 1",
         [("p50_us", False), ("p99_us", False), ("page_p50_us", False), ("page_p99_us", False), ("rps", True), ("bulk_mib_s", True)])]
GIG = [("1G/40ms download 1x1", "--test download --conns 1 --streams 1", [("mib_s_down", True)]),
       ("1G/40ms download 10x10", "--test download --conns 10 --streams 10", [("mib_s_down", True)])]

IDLE_SETTLE = 30  # idle probe: max seconds to wait for a stable RSS (wispsuite.idle)
IDLE_N = 2000  # idle probe: connections
# 30.10 idle resolution floor: settled RSS moves in 0.1-0.25 MiB steps (page / arena granularity; kib_per_conn is
# rounded to 0.1 KiB = 0.2 MiB at 2000 conns), so an A/A run (rc1 vs a copy, rcq3) scored a 1.06 "LOSS" on one step.
# A directional verdict (WIN / LOSS / watch) needs |median paired difference| >= max(this, the measured step), else tie.
IDLE_FLOOR_MIB = 0.25

class Run:
    def __init__(s, a):
        a.xh = getattr(a, "xh", None)
        s.a, s.rows, s.out, s.problems = a, [], a.out, []
        os.makedirs(os.path.join(s.out, "raw"), exist_ok=True)
        # cross-host: the target is on this box's public address, so no --allow-* flag (closest to production)
        srv = a.args.strip() if a.xh else f"--allow-loopback {a.args}".strip()
        # B (20.31 redesign, D4): --own-scope runs each server in its own systemd scope (cgroup), as tcpmem_bench does: the
        # --tcpmem-adapt guard then sees the server's own socket memory, not the client's and targets' too (one session
        # cgroup reads ~100%). Off by default: the old mode stays the comparable baseline. lo/tls suites only.
        scope = "systemd-run --quiet --scope -p MemoryAccounting=yes " if getattr(a, "own_scope", False) else ""
        s.variants = {"base": f"exec {scope}{a.base} {srv} {a.base_args}".rstrip(), "new": f"exec {scope}{a.new} {srv} {a.new_args}".rstrip()}
        s.env = dict(os.environ, WBENCH=a.wbench, DUR=str(a.dur), WARMUP="1")
        if a.port_base:  # 30.10: all ports from one base (default: the historical fixed ports)
            s.env.update(PORT=str(a.port_base), TPORT=str(a.port_base + 1))

    def ab(self, cid, args, metrics, tls=False, link="lo", extra_env=None):
        if self.a.only and self.a.only not in cid:
            return
        if self.a.xh:
            link = self.a.xh.label  # RAW records and the LOSS re-run (confirm) carry "xhost:HOST"
        vfile = os.path.join(self.out, "variants.json")
        v = {k: c + (f" --tls-cert {self.a.cert} --tls-key {self.a.key}" if tls else "") for k, c in self.variants.items()}
        if extra_env and "SRV_BIND" in extra_env:
            # netns: ab.py runs "ip netns exec NS <cmd>", which cannot run the shell builtin `exec`
            v = {k: c.removeprefix("exec ").replace("--allow-loopback", "--allow-loopback --allow-private") for k, c in v.items()}
        json.dump(v, open(vfile, "w"))
        raw = os.path.join(self.out, "raw", cid.replace(" ", "_").replace("/", "-") + ".jsonl")
        if os.path.exists(raw):
            os.replace(raw, raw + ".old")
        env = dict(self.env, RAW=raw, LINK=link, AB_TLS="1" if tls else "0", **(extra_env or {}))
        print(f"[regress] {cid} ({self.a.reps} reps)", file=sys.stderr, flush=True)
        nss = ["fws", "fwa"] if extra_env and "SRV_BIND" in extra_env else [None]
        mp0 = [tcp_pressure(ns) for ns in nss]
        rp0 = xhostmod.remote_tcp_pressure(self.a.xh.ssh) if self.a.xh else None
        try:  # in-process (30.10): one process registry, so a SIGTERM stops the server, target and client at once
            xh = self.a.xh
            where = (dict(srv_host=xh.server_ip, srv_bind=f"--host {xh.server_ip}", tgt_host=xh.server_ip, client_ssh=xh.ssh)
                     if xh else dict(srv_prefix=env.get("SRV_PREFIX", "").split(), cli_prefix=env.get("CLI_PREFIX", "").split(),
                                     srv_host=env.get("SRV_HOST", "127.0.0.1"), srv_bind=env.get("SRV_BIND", "")))
            abmod.run_ab(v, self.a.reps, args.split(), wb=self.a.wbench, port=env.get("PORT", "6901"), tport=env.get("TPORT", "6902"),
                         tmode=env.get("TMODE") or None, dur=env["DUR"], warmup=env["WARMUP"], tls=tls, raw=raw, link=link,
                         rotate=env.get("FW_AB_ROTATE", "1") != "0", verbose=self.a.verbose, **where)
        except Exception as e:  # what used to be "ab.py exited N"
            print(f"[regress] {cid}: {e}", file=sys.stderr)
            self.problems.append(f"{cid}: ab failed: {e}")
        mp = sum((b or 0) - (a or 0) for a, b in zip(mp0, (tcp_pressure(ns) for ns in nss)))
        if self.a.xh:  # cross-host: the client box can be the one under pressure too
            rp1 = xhostmod.remote_tcp_pressure(self.a.xh.ssh)
            if rp0 is None or rp1 is None:
                self.problems.append(f"{cid}: TCP memory pressure on the client {self.a.xh.ssh} could not be read")
            else:
                mp += rp1 - rp0
        invalid = []  # reasons this case gives no verdict (the computed one stays visible as verdict_raw)
        if mp > 0:  # the kernel throttled every TCP socket on the box: the numbers measure the box, not finalwisp
            invalid.append("host TCP memory pressure")
            self.problems.append(f"{cid}: host TCP memory pressure ({mp}x, net.ipv4.tcp_mem) during the case; results not valid")
        recs = [json.loads(l) for l in open(raw)] if os.path.exists(raw) else []
        by = {k: {} for k in ("base", "new")}
        for x in recs:
            by[x["v"]][x["rep"]] = x
        reps = sorted(set(by["base"]) & set(by["new"]))
        get = lambda v, f: [by[v][i].get(f) for i in reps]
        # 50.02 D: reps during which host TCP memory reached tcp_mem[2] (ab.py samples sockstat): at the hard limit the
        # kernel refuses socket memory outright (a kTLS sender with nothing in flight can stall a whole rep); invalid
        atmax = {k: sum(1 for x in by[k].values() if x.get("at_tcp_mem_max")) for k in by}
        if atmax["base"] or atmax["new"]:
            self.problems.append(f"{cid}: at tcp_mem max (net.ipv4.tcp_mem[2]) in {atmax['base']} base / {atmax['new']} new "
                                 f"reps; results not valid")
            invalid.append("tcp_mem max")
        errs = {k: sum(int(x.get("errors") or 0) + (1 if "error" in x else 0) for x in by[k].values()) for k in by}
        if len(reps) < self.a.reps:
            self.problems.append(f"{cid}: only {len(reps)} of {self.a.reps} paired reps")
        # 60.15 T08: a run with benchmark errors measured something other than the clean workload (failed streams, short
        # runs), on either side; symmetric errors do not cancel out, so no verdict at all
        if errs["base"] or errs["new"]:
            self.problems.append(f"{cid}: benchmark errors {errs['base']} base / {errs['new']} new; results not valid")
            invalid.append("benchmark errors")
        for m, hb in metrics:
            c = compare(get("base", m), get("new", m), hb)
            if c is None:
                row = {"case": cid, "metric": m, "verdict": "NO DATA", "errors": errs}
                if invalid:  # same rule as below: an invalid case is labelled invalid even with too few pairs to compare
                    row.update(verdict="invalid", verdict_raw="NO DATA", invalid=invalid)
                self.rows.append(row)
                self.problems.append(f"{cid}: no data for {m}")
                continue
            if any(x is None for x in get("base", m) + get("new", m)):
                self.problems.append(f"{cid}: {m} missing in some runs")
            unit = lambda v: [(x.get("cpu_pct") or 0) / x[m] if x.get(m) else None for x in (by[v][i] for i in reps)]
            cpu = compare(unit("base"), unit("new"), False) if m == metrics[0][0] else None
            hwm = compare(get("base", "hwm_mib"), get("new", "hwm_mib"), False) if m == metrics[0][0] else None
            if not invalid and ((c["ratio"] <= 1 - BIG) if hb else (c["ratio"] >= 1 + BIG)):  # no claims from invalid numbers
                self.problems.append(f"{cid}: {m} paired HL ratio {c['ratio']} of base (>= {BIG:.0%} worse)")
            if invalid:  # no WIN/LOSS/watch from an invalid case (fix2, T08); the computed verdict stays visible
                c = dict(c, verdict="invalid", verdict_raw=c["verdict"], invalid=invalid)
            self.rows.append({"case": cid, "metric": m, **c, "errors": errs, "_call": (args, metrics, tls, link, extra_env),
                              "cpu_per_unit": cpu and {"ratio": cpu["ratio"], "p": cpu["p"]},
                              "peak_mib": hwm and {"base": hwm["base"], "new": hwm["new"], "p": hwm["p"]}})

    def idle(self):
        wb, port, eport = self.a.wbench, 6911, 6912
        if self.a.port_base:
            port, eport = self.a.port_base + 2, self.a.port_base + 3
        bad = proc.strays([port, eport])
        if bad:
            self.problems.append("idle: " + "; ".join(bad) + ": not run")
            return
        res = {"base": [], "new": []}
        used = {"base": [], "new": []}  # settled - before RSS per probe (MiB; None = failed or not reported), by rep
        settled = {"base": [], "new": []}  # rss_settled_mib per probe (the measured RSS step, per variant)
        settle = {"base": [], "new": []}  # settle_s per probe (None = not stable by IDLE_SETTLE s, "failed" = no record)
        # 60.15 T09: every probe's full record (RSS samples, 3 s reading, settle) goes to raw/idle.jsonl, one line per
        # probe, so an idle verdict can be re-scored later (pairs = same rep); a failed probe gets a line with "error"
        raw = os.path.join(self.out, "raw", "idle.jsonl")
        if os.path.exists(raw):
            os.replace(raw, raw + ".old")
        rawf = open(raw, "w")
        tg = None
        try:
            tg = wbench.start_target(wb, eport, "echo")
            # one base + one new probe per rep, n pairs at --reps n (was n/2: 8 pairs at 16); >= 6 (3 pairs: min p 0.25)
            for rep in range(max(6, self.a.reps)):
                for pos, name in enumerate(["base", "new"] if rep % 2 == 0 else ["new", "base"]):
                    binp = getattr(self.a, name)
                    s = proc.spawn([binp, "--port", str(port), "--allow-loopback", *self.a.args.split(),
                                    *getattr(self.a, name + "_args").split()])  # own group, registered: a SIGTERM stops it
                    try:
                        time.sleep(0.5)
                        rc, out, err = proc.run(idlemod.probe_cmd(port, eport, s.pid, IDLE_N, settle=IDLE_SETTLE, group=True), timeout=120 + IDLE_SETTLE, cwd=HERE,
                                              env={"PYTHONPATH": HERE})
                    finally:
                        proc.stop(s, 0)
                    time.sleep(0.3)
                    rec = {"v": name, "rep": rep, "pos": pos, "n": IDLE_N, "settle_max_s": IDLE_SETTLE, "rc": rc}
                    try:
                        j = json.loads(out.strip().splitlines()[-1])
                        res[name].append(j["kib_per_conn_settled"])
                        settle[name].append(j.get("settle_s"))
                        sm, bm = j.get("rss_settled_mib"), j.get("rss_before_mib")
                        settled[name].append(sm)
                        # (older probes without the RSS fields: kib_per_conn back to MiB)
                        used[name].append(sm - bm if sm is not None and bm is not None else j["kib_per_conn_settled"] * IDLE_N / 1024)
                        rec.update(j)
                    except Exception as e:
                        res[name].append(None)
                        settle[name].append("failed")
                        used[name].append(None)
                        rec["error"] = f"{type(e).__name__}: {e}; stderr tail {(err or '').strip()[-300:]!r}"
                    rawf.write(json.dumps(rec) + "\n")
                    rawf.flush()
        finally:
            rawf.close()
            proc.stop(tg, 0)
        c = compare(res["base"], res["new"], False)
        if any(x is None for x in res["base"] + res["new"]):
            self.problems.append(f"idle: {sum(x is None for x in res['base'] + res['new'])} failed probes")
        if c is None:
            self.problems.append("idle: no data")
        notes = []
        if c:
            c, res_note = idle_floor(c, used, settled)
            notes += [res_note] if res_note else []
        row = {"case": f"idle {IDLE_N} conns", "metric": "kib_per_conn", **(c or {"verdict": "NO DATA"}), "errors": {},
               "settle_s": settle}
        late = {k: sum(x is None for x in v) for k, v in settle.items()}
        if any(late.values()):  # the last value is used; still freeing then = the number is an upper bound
            notes.append(f"RSS not stable within {IDLE_SETTLE} s in {late['base']} base / {late['new']} new probes "
                         f"(value at {IDLE_SETTLE} s used)")
        if notes:
            row["note"] = "; ".join(notes)
        self.rows.append(row)

    def link(self):
        if os.geteuid() != 0:
            self.problems.append("link suite requested but not root: not run")
            return
        nh = find("netns_hol.sh")
        env = {"SRV_PREFIX": "ip netns exec fws", "CLI_PREFIX": "ip netns exec fwa", "SRV_HOST": "10.77.0.2",
               "SRV_BIND": "--host 10.77.0.2"}
        try:
            # netem queue (packets): 1 Gbit x 40 ms RTT is ~3500 full-size packets in flight; 1000 dropped and collapsed
            for (rate, delay), cases in (((("100mbit", "10ms")), PAGE), ((("1gbit", "20ms")), GIG)):
                subprocess.run(["bash", nh, rate, delay, "10000" if rate == "1gbit" else "200"], check=True, capture_output=True)
                for cid, args, metrics in cases:
                    self.ab(cid, args, metrics, link=f"{rate}/{delay}", extra_env=env)
                    if self.a.tls_ok and cid.startswith("page"):
                        self.ab("wss " + cid, args, metrics, tls=True, link=f"{rate}/{delay}", extra_env=env)
        finally:
            subprocess.run(["bash", nh, "down"], capture_output=True)

    def potato(self):
        if not potatomod.scopes_available():
            self.problems.append("potato suite requested but systemd-run memory scopes are not available: not run")
            return
        pport = self.a.port_base + 4 if self.a.port_base else 6610
        bad = proc.strays([pport, pport + 1, pport + 2, pport + 3])
        if bad:
            self.problems.append("potato: " + "; ".join(bad) + ": not run")
            return
        # (bench-cpu: server/peers on the two lowest CPUs this process may use, not 0/1: cpusets may exclude 0)
        cpus = potatomod.pin_pair()
        if cpus is None:
            self.problems.append("potato: fewer than 2 CPUs allowed (sched_getaffinity): cannot keep peers off the server's CPU; not run")
            return
        out = os.path.join(self.out, "raw", "potato.jsonl")
        if os.path.exists(out):
            os.replace(out, out + ".old")
        for rep in range(max(6, self.a.reps // 2)):  # >= 6 per cell, else p can never reach 0.05 (3 reps: min p 0.25)
            order = ["base", "new"] if rep % 2 == 0 else ["new", "base"]
            print(f"[regress] potato rep {rep + 1}", file=sys.stderr, flush=True)
            # server on one cpu, wbench + targets on another: unpinned peers share the server's cpu part of the time and
            # favour whichever build splices (r5: master's 128M download read 1785-2200 unpinned vs 1192-1602 pinned)
            try:
                potatomod.run_curve(self.a.wbench, out, [(k, getattr(self.a, k), []) for k in order], cpu=cpus[0], pin=cpus[1],
                                    rotate=False, verbose=False,
                                    logdir=os.path.join(self.out, "raw", "potato-logs"),
                                    port=pport)
            except Exception as e:
                self.problems.append(f"potato rep {rep + 1}: {e}")
        if not os.path.exists(out):
            self.problems.append("potato: no rows")
            return
        cells = defaultdict(lambda: {"base": [], "new": []})
        for x in (json.loads(l) for l in open(out)):
            dead = bool(x.get("oom_kill")) or not x.get("alive")
            cells[(x["test"], x["mb"])][x["bin"]].append(None if dead else x.get("value"))
        if not cells:
            self.problems.append("potato: no rows")
        for (test, mb), v in sorted(cells.items()):
            alive = {k: sum(y is not None for y in v[k]) for k in v}
            c = compare(v["base"], v["new"], True)
            row = {"case": f"potato {test} {mb}M", "metric": "alive/value", "alive": alive, "errors": {}}
            if alive["new"] < len(v["new"]):
                row["verdict"] = "LOSS"  # the new build died where it must not
            elif c:
                row.update(c)
            else:
                row["verdict"] = "base dies" if alive["base"] < len(v["base"]) else "NO DATA"
            if row["verdict"] == "NO DATA" or len(v["base"]) != len(v["new"]):
                self.problems.append(f"potato {test} {mb}M: incomplete ({len(v['base'])} base / {len(v['new'])} new rows)")
            self.rows.append(row)

def rss_step(values):
    """30.10 smallest nonzero gap between one variant's settled RSS values (MiB), the measured RSS granularity; None with
    fewer than 3 distinct values (2 values = a bimodal build or one outlier, not a granularity estimate)"""
    v = sorted(set(round(x, 3) for x in values if x is not None))
    gaps = [b - a for a, b in zip(v, v[1:]) if b - a > 1e-9]
    return round(min(gaps), 3) if len(v) >= 3 else None


def idle_floor(c, used, settled):
    """30.10 resolution floor for the idle row: (compare() result, note or None).
    used = {variant: [settled - before RSS per probe, MiB, or None]} paired by rep (the RSS behind kib_per_conn, on the
    same 0.1 MiB grid as the step); settled = {variant: [settled RSS, MiB]}. Effect = Hodges-Lehmann estimate of the
    paired differences new - base (the verdict's HL ratio is the same estimator on logs; a plain median would ignore a
    minority of large increases). Floor = max(IDLE_FLOOR_MIB, the larger per-variant step: never a between-build gap).
    A WIN / LOSS / watch whose |effect| is below the floor becomes tie (verdict_raw keeps the computed one)."""
    d = [y - x for x, y in zip(used["base"], used["new"]) if x is not None and y is not None]
    steps = [s for s in (rss_step(settled["base"]), rss_step(settled["new"])) if s is not None]
    step = max(steps) if steps else None
    floor = max(IDLE_FLOOR_MIB, step or 0)
    eff = round(st.median([(d[i] + d[j]) / 2 for i in range(len(d)) for j in range(i, len(d))]), 3) if d else None
    c = dict(c, resolution={"effect_mib": eff, "floor_mib": floor, "step_mib": step})
    if eff is not None and c["verdict"] in ("WIN", "LOSS", "watch") and abs(eff) < floor - 1e-9:
        return (dict(c, verdict="tie", verdict_raw=c["verdict"]),
                f"{c['verdict']} below the RSS resolution (paired HL difference {eff:+.2f} MiB, floor {floor} MiB): tie")
    return c, None


def confirm(r):
    # 11-17 metrics at p < 0.05: an A/A run has ~40% odds of one false LOSS. A LOSS counts only if the case,
    # re-run on its own, loses again (false alarm ~0.1% per case).
    for row in [x for x in r.rows if x["verdict"] == "LOSS" and "_call" in x]:
        if "confirmed" in row:
            continue
        args, metrics, tls, link, env = row["_call"]
        if link != "lo" and env:
            r.problems.append(f"{row['case']}: LOSS on a link case; re-run it with --suite link --only to confirm")
            continue
        n0, p0 = len(r.rows), len(r.problems)
        r.ab(row["case"], args, metrics, tls=tls, link=link, extra_env=env)
        again = {x["metric"]: x for x in r.rows[n0:]}
        del r.rows[n0:]
        # keep every re-run problem (a crash or missing data there must not vanish); drop only exact repeats
        rerun = [p for p in r.problems[p0:] if p not in r.problems[:p0]]
        del r.problems[p0:]
        r.problems += [f"re-run: {p}" for p in rerun]
        for x in [y for y in r.rows if y["case"] == row["case"] and y["verdict"] == "LOSS"]:
            y2 = again.get(x["metric"])
            if not y2 or "ratio" not in y2:  # the re-run produced nothing usable: the LOSS stands
                x["confirmed"] = None
                x["note"] = "re-run gave no data; LOSS kept"
                continue
            if y2["verdict"] == "invalid":  # the re-run is invalid (pressure, tcp_mem max, errors): it says nothing either way
                x["confirmed"] = None
                x["note"] = f"re-run invalid ({', '.join(y2.get('invalid', []))}); LOSS kept"
                continue
            x["confirmed"] = y2["verdict"] == "LOSS"
            if not x["confirmed"]:
                x["verdict"] = "watch"
                x["note"] = f"LOSS not reproduced (re-run paired HL ratio {y2 and y2.get('ratio')}, p {y2 and y2.get('p')})"
    for x in r.rows:
        x.pop("_call", None)

def table(rows):
    lines = ["| case | metric | base median | new median | paired HL ratio | marginal median ratio | 90% CI | p | verdict | cpu/unit HL ratio | peak MiB base->new | errors b/n |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    def f(x):
        if x is None:
            return ""
        if isinstance(x, float):
            return f"{x:.0f}" if abs(x) >= 100 else f"{x:.3g}"
        return str(x)
    for r in rows:
        cpu = r.get("cpu_per_unit") or {}
        pk = r.get("peak_mib") or {}
        al = r.get("alive")
        e = r.get("errors") or {}
        lines.append(f"| {r['case']} | {r['metric']} | {f(r.get('base'))} | {f(r.get('new'))} | {f(r.get('ratio'))} | {f(r.get('ratio_medians'))} | "
                     f"{(f(r['ci90'][0]) + '-' + f(r['ci90'][1])) if r.get('ci90') else ''} | {f(r.get('p'))} | **{r['verdict']}** | {f(cpu.get('ratio'))} | "
                     f"{(f(pk.get('base')) + ' -> ' + f(pk.get('new'))) if pk else ('alive ' + str(al) if al else '')} | "
                     f"{e.get('base', '')}/{e.get('new', '')} |")
    return "\n".join(lines)

def run_suites(r, a, suites):
    if "lo" in suites:
        for case in LO:
            r.ab(*case)
    if "tls" in suites:
        if a.tls_ok:
            for case in TLS:
                r.ab(*case, tls=True)
        else:
            r.problems.append("tls suite requested without --cert/--key: not run")
    if "idle" in suites:
        r.idle()
    if "link" in suites:
        r.link()
    if "potato" in suites:
        r.potato()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wst regress", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True); ap.add_argument("--new", required=True)
    ap.add_argument("--suite", default=None, help="default lo,tls,idle (cross-host: lo,tls)"); ap.add_argument("--reps", type=int, default=12)
    ap.add_argument("--dur", type=int, default=4); ap.add_argument("--out", default="regress-out")
    ap.add_argument("--args", default="", help="extra server args for both builds")
    ap.add_argument("--new-args", default="", help="extra server args for the new build only (cost of a feature while ON)")
    ap.add_argument("--base-args", default="", help="extra server args for the base build only")
    ap.add_argument("--cert"); ap.add_argument("--key")
    ap.add_argument("--wbench", default=None, help="default: $WBENCH or bench/target/release/wbench")
    ap.add_argument("--verbose", action="store_true", help="print every run (A/B records) to stderr")
    ap.add_argument("--quick", action="store_true", help="4 reps x 2 s: a smoke test, not a verdict")
    ap.add_argument("--own-scope", action="store_true", help="lo/tls: each server in its own systemd scope (20.31 D4; root or user systemd)")
    ap.add_argument("--only", default="", help="run only cases whose id contains this text (lo/tls/link suites)")
    ap.add_argument("--port-base", type=int, default=0, help="use ports P..P+7 (default: A/B 6901/6902, idle 6911/6912, potato 6610-6613)")
    ap.add_argument("--client-ssh", default=None, help="cross-host: run wbench on [USER@]HOST over ssh (root here: iptables); suites lo,tls")
    ap.add_argument("--server-ip", default=None, help="cross-host: this box's address the client connects to (default: the route to HOST)")
    ap.add_argument("--force-clean", action="store_true", help="cross-host: remove leftover wst-xhost iptables rules first")
    a = ap.parse_args(argv)
    if a.suite is None:
        a.suite = "lo,tls" if a.client_ssh else "lo,tls,idle"
    if a.client_ssh and set(a.suite.split(",")) - {"lo", "tls"}:
        sys.exit("regress: cross-host mode supports the lo and tls suites only (idle/link/potato need the client on this box)")
    if a.quick:
        a.reps, a.dur = 4, 2
    a.wbench = wbench.find(a.wbench)
    a.base, a.new, a.wbench = (os.path.abspath(x) for x in (a.base, a.new, a.wbench))
    a.tls_ok = bool(a.cert and a.key)
    if a.tls_ok:
        a.cert, a.key = os.path.abspath(a.cert), os.path.abspath(a.key)
    for p in (a.base, a.new, a.wbench):
        if not os.access(p, os.X_OK):
            sys.exit(f"regress.py: not executable: {p}")
    proc.install_handlers()  # SIGTERM/SIGINT: stop every server, target and client we started, then exit
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))  # idle suite: 2000 clients + server fds
    a.xh, fw = None, contextlib.nullcontext()
    if a.client_ssh:
        try:
            a.xh = xhostmod.Xhost(a.client_ssh, a.wbench, a.server_ip)
        except xhostmod.XhostError as e:
            sys.exit(f"regress: {e}")
        print(f"[regress] cross-host {a.xh.describe()}", file=sys.stderr, flush=True)
    r = Run(a)
    if a.xh:  # exactly the ports the A/B cases use (PORT/TPORT env or --port-base)
        fw = xhostmod.firewall([int(r.env.get("PORT", "6901")), int(r.env.get("TPORT", "6902"))], a.xh.client_ip, a.force_clean)
    if a.xh and a.xh.md5_problem():
        r.problems.append(a.xh.md5_problem())
    suites = a.suite.split(",")
    t0 = time.time()
    try:
        with fw:  # cross-host: iptables rules for exactly this block (removed on exit, error or signal)
            run_suites(r, a, suites)
            confirm(r)
    except xhostmod.XhostError as e:  # setup only (teardown never raises; its problems are below)
        sys.exit(f"regress: {e}")
    r.problems += [f"cross-host teardown: {m}" for m in xhostmod.cleanup_errors]
    md = table(r.rows)
    notes = [f"- {x['case']} {x['metric']}: {x['note']}" for x in r.rows if x.get("note")]
    if notes:
        md += "\n\n" + "\n".join(notes)
    weak = sorted({x["case"] for x in r.rows if 0 < x.get("n", 99) < 6})
    if weak:  # with fewer than 6 pairs the exact test cannot give p < 0.05: no verdict either way
        r.problems.append(f"fewer than 6 paired runs (no verdict possible): {', '.join(weak)}")
    p_end = report.power_state()
    p_diff = report.power_changed(report.POWER_START, p_end)
    if p_diff:  # absolute numbers before and after are not comparable (laptop profile/AC change); pairs may still be
        r.problems.append("host power state changed during the run (" + ", ".join(
            f"{k} {report.POWER_START.get(k)} -> {p_end.get(k)}" for k in p_diff) + ")")
    losses = [x for x in r.rows if x["verdict"] == "LOSS"]
    head = (f"# regress: new {a.new} {a.new_args} vs base {a.base} {a.base_args}\n\nreps {a.reps}, {a.dur} s runs, suites {a.suite}, "
            + (f"link {a.xh.describe()}, " if a.xh else "")
            + f"{(time.time() - t0) / 60:.0f} min. LOSS = worse with p < {ALPHA}, reproduced in a re-run of that case; "
            f"watch = >= {WATCH:.0%} worse, not significant; tie = not significant and the 90% CI is within "
            f"{NI_MARGIN:.0%} on the worse side; unclear = significant but paired HL is neutral, or not significant "
            f"with a CI too wide to call a tie; idle: a WIN/LOSS/watch below the RSS resolution floor is tie (row note; "
            f"its ratio, p and CI stay unadjusted).\n"
            f"Paired HL ratio, p and 90% CI use log(new/base); marginal medians and their ratio are descriptive only.\n"
            f"power: start {report.power_fmt(report.POWER_START)}; end {report.power_fmt(p_end)}.\n"
            + ("**Fewer than 6 reps: p cannot reach 0.05. Smoke test only, not a verdict.**\n" if a.reps < 6 else "")
            + f"**{len(losses)} LOSS**, {sum(x['verdict'] == 'watch' for x in r.rows)} watch, "
            f"{sum(x['verdict'] == 'unclear' for x in r.rows)} unclear, "
            f"{sum(x['verdict'] == 'WIN' for x in r.rows)} WIN, "
            + (f"**{n_inv} invalid** (host TCP memory pressure, tcp_mem max or benchmark errors), "
               if (n_inv := sum(x['verdict'] == 'invalid' for x in r.rows)) else "")
            + f"**{len(r.problems)} PROBLEMS**.\n\n"
            + "".join(f"- PROBLEM: {p}\n" for p in r.problems) + ("\n" if r.problems else ""))
    open(os.path.join(a.out, "summary.md"), "w").write(head + md + "\n")
    report.write(os.path.join(a.out, "results.json"), "regress", binaries=[a.base, a.new, a.wbench], rows=r.rows, problems=r.problems)
    print(head + md)
    sys.exit(1 if losses or r.problems else 0)  # a broken or incomplete run never passes

