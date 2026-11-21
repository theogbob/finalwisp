#!/usr/bin/env python3
"""80.04 L8 report tables from e2e.py session directories (raw.jsonl + meta.json; nothing else is read).

usage: bench/e2e/report_tables.py [--vis LABEL=DIR] [--faults LABEL=DIR] [--close LABEL=DIR] [--check REPORT.md]
       bench/e2e/report_tables.py --close-json DIR   (counts of the closefail family as JSON, for scripts)
  --vis     a session with arms REF, an A/A copy (label ending in 'aa') and competitors: per client/workload key metric, the
            A/A ratio, finalwisp / X for each competitor (paired HL ratio, 90 % CI, verdict seen from finalwisp: WIN =
            finalwisp better), the direct floor, the client main-thread and server CPU per wall second (arm REF)
  --faults  a session with arms v140, fk-off and faults: per fault and client/workload key metric, fault / v140 with the
            verdict for the fault (LOSS = the fault made it worse = detected), and fault / fk-off
  --close   a closefail session: per arm and client the responses lost, pooled over rounds, with a Wilson 95 % interval,
            and the paired verdict of the per-round loss share against the first arm
  --check   every table printed must appear byte for byte in REPORT.md (exit 1 if not)
Several --vis / --faults / --close may be given (one table each)."""
import json, math, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
from wispsuite import stats  # noqa: E402
import e2e  # noqa: E402


def cmp(base, new, metric):
    """paired over the rounds both have; returns (ratio new/base, ci, verdict for new, n) or None"""
    rounds = sorted(set(base) & set(new))
    A, B = [base[r] for r in rounds], [new[r] for r in rounds]
    if len(rounds) < 2:
        return None
    c = stats.compare(A, B, e2e.higher_better(metric))
    if c is None:
        if all(x == y for x, y in zip(A, B)):
            return ("=", None, "tie", len(rounds))
        p = stats.wilcoxon(B, A)
        d = st.median([y - x for x, y in zip(A, B)])
        v = ("WIN" if (d > 0) == e2e.higher_better(metric) else "LOSS") if p < stats.ALPHA else "unclear"
        return (f"d {d:+.3g}", None, v, len(rounds))
    return (c["ratio"], c["ci90"], c["verdict"], c["n"])


def cell(c):
    if c is None:
        return "-"
    r, ci, v, n = c
    rs = f"{r:.3f}" if isinstance(r, float) else str(r)
    return f"{rs} {('[' + format(ci[0], '.3f') + ', ' + format(ci[1], '.3f') + ']') if ci else ''} {v}".replace("  ", " ")


def keyrows(meta, vals):
    out = []
    for c in meta["clients"]:
        if c == "direct":
            continue
        for w in meta["workloads"]:
            for m in e2e.KEY.get(w, ()):
                out.append((c, w, m))
    return out


def med(d):
    return e2e.fmt(st.median(d.values())) if d else "-"


def excl_txt(meta):
    """', N excluded (k foreign activity, m OVERLAP.jsonl)' for a table header; '' when none"""
    ex = meta.get("excluded_rounds") or {}
    if not ex:
        return ""
    ov = sum("OVERLAP" in v for v in ex.values())
    return f", {len(ex)} excluded ({len(ex) - ov} foreign activity / incomplete, {ov} overlapping OVERLAP.jsonl windows: rounds {', '.join(sorted(ex, key=int))})"


def vis_table(label, d):
    meta, vals, share, fails, wall = e2e.collect(d)
    arms = [x["label"] for x in meta["arms"]]
    ref = arms[0]
    aa = [a for a in arms[1:] if a.endswith("aa")]
    comp = [a for a in arms[1:] if a not in aa]
    L = [f"### {label}: {meta.get('box')} {meta['started_utc']}, {meta['rounds']} rounds{excl_txt(meta)}, wall {meta.get('wall_s')} s ({d.split('/stale/')[-1]})", "",
         f"| client/workload | metric | {ref} median | A/A {', '.join(aa) or '-'} / {ref} | " + " | ".join(f"{ref} / {x}" for x in comp)
         + " | direct floor | client CPU | server CPU | failed runs |",
         "|---|---|---|---|" + "---|" * len(comp) + "---|---|---|---|"]
    aa_n = aa_flag = 0
    for c, w, m in keyrows(meta, vals):
        rv = vals.get((ref, c, w), {}).get(m, {})
        if not rv and not any(vals.get((x, c, w)) for x in arms):
            continue
        aac = cell(cmp(rv, vals.get((aa[0], c, w), {}).get(m, {}), m)) if aa else "-"
        cc = []
        for x in comp:
            cc.append(cell(cmp(vals.get((x, c, w), {}).get(m, {}), rv, m)))  # verdict for finalwisp (ref) against x
        fl = vals.get(("direct", "direct", w), {}).get(m, {})
        sh = share.get((ref, c, w))
        cl = f"{st.median(s[0] for s in sh):.2f}" if sh else "-"
        sv = f"{st.median(s[1] for s in sh):.2f}" if sh else "-"
        nf = ", ".join(f"{a} {len(fails[(a, c, w)])}" for a in arms if (a, c, w) in fails) or "-"
        L.append(f"| {c}/{w} | {m} | {med(rv)} | {aac} | " + " | ".join(cc) + f" | {med(fl)} | {cl} | {sv} | {nf} |")
        if aa and m != "busy_censored":
            aa_n += 1
            aa_flag += aac.endswith(("WIN", "LOSS"))
    if aa:
        a_ = stats.ALPHA
        tail = sum(math.comb(aa_n, j) * a_ ** j * (1 - a_) ** (aa_n - j) for j in range(aa_flag, aa_n + 1))
        L += ["", f"A/A ({aa[0]} = the same binary as {ref}): {aa_flag} of {aa_n} key rows flagged WIN/LOSS (Wilcoxon p < {a_}: "
                  f"{a_ * aa_n:.1f} expected by chance; P(>= {aa_flag}) = {tail:.2f} if the rows were independent, and they are not: "
                  "a lone flag in one row is weak evidence)."]
    return "\n".join(L) + "\n"


def fault_table(label, d):
    meta, vals, share, fails, wall = e2e.collect(d)
    arms = [x["label"] for x in meta["arms"]]
    ref = arms[0]
    ctrl = "fk-off" if "fk-off" in arms else None
    rows = keyrows(meta, vals)
    rows = [(c, w, m) for c, w, m in rows if vals.get((ref, c, w), {}).get(m)]
    L = [f"### {label}: {meta.get('box')} {meta['started_utc']}, {meta['rounds']} rounds{excl_txt(meta)}, wall {meta.get('wall_s')} s ({d.split('/stale/')[-1]})", "",
         "Cell: fault / " + ref + " ratio [90 % CI] verdict for the fault (LOSS = worse = detected)" + (f"; second line: against {ctrl}" if ctrl else ""), "",
         "| fault | " + " | ".join(f"{c}/{w} {m}" for c, w, m in rows) + " |", "|---|" + "---|" * len(rows)]
    L.append(f"| {ref} (median) | " + " | ".join(med(vals[(ref, c, w)][m]) for c, w, m in rows) + " |")
    for x in arms[1:]:
        cs = [cell(cmp(vals.get((ref, c, w), {}).get(m, {}), vals.get((x, c, w), {}).get(m, {}), m)) for c, w, m in rows]
        L.append(f"| {x} | " + " | ".join(cs) + " |")
        if ctrl and x != ctrl:
            cs = [cell(cmp(vals.get((ctrl, c, w), {}).get(m, {}), vals.get((x, c, w), {}).get(m, {}), m)) for c, w, m in rows]
            L.append(f"| {x} vs {ctrl} | " + " | ".join(cs) + " |")
    return "\n".join(L) + "\n"


def wilson(k, n, z=1.96):
    if n == 0:
        return (None, None)
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, c - h), min(1.0, c + h))


def is_browser(client):
    return client.split("-")[0] in ("chromium", "firefox", "webkit")


def resp_in_close_read(x):
    """the R test of one s.resp entry. Node (client.mjs --wslog): did the response-bearing DATA (not a lone 24-byte TLS 1.3
    close_notify) arrive in the same socket read as the server's CLOSE? Chromium (browser/closefail.mjs): was the body still
    not fully read by the page when the CLOSE message arrived (pending_at_close)? None if the entry has no tap data"""
    if "pending_at_close" in x:
        return x["pending_at_close"]
    d = x.get("data")
    if not d:
        return None
    rd_ = [y for y in d if y[0] != 24] or d
    return any(y[1] == 0 for y in rd_)


def pct(k, n):
    if not n:
        return "-"
    lo, hi = wilson(k, n)
    return f"{100 * k / n:.1f} [{100 * lo:.1f}, {100 * hi:.1f}]"


def boot_runs(pairs, reps=2000, seed=8004):
    """95 % percentile interval of sum(k) / sum(n) resampling whole runs (rounds): responses within a run are not
    independent, so this is the interval to trust; the Wilson one assumes independent responses"""
    import random
    if len(pairs) < 10:  # with few runs the run bootstrap only replays the observed run rates: no interval shown
        return None
    rng, out = random.Random(seed), []
    for _ in range(reps):
        s = [pairs[rng.randrange(len(pairs))] for _ in pairs]
        n = sum(p[1] for p in s)
        out.append(100 * sum(p[0] for p in s) / n if n else 0.0)
    out.sort()
    return round(out[int(0.025 * reps)], 2), round(out[int(0.975 * reps) - 1], 2)


def bpct(pairs):
    b = boot_runs(pairs)
    return f"[{b[0]:.1f}, {b[1]:.1f}]" if b else "-"


def close_counts(d):
    """counts per (workload, arm, client) of the closefail family, excluded and tcpdump rounds left out: a list of dicts"""
    meta, vals, share, fails, wall = e2e.collect(d)
    arms = [x["label"] for x in meta["arms"]]
    excl = meta.get("excluded_rounds", {})
    raw_all = e2e.load_raw(d)
    pcap_rounds = sorted({r.get("round") for r in raw_all if r.get("pcap")})  # diagnostic rounds, failed runs included
    fails_of = lambda a, c, w: [r for r in raw_all if r.get("arm") == a and r.get("client") == c and r.get("w") == w
                                and not e2e.good(r) and str(r.get("round")) not in excl and r.get("round") not in pcap_rounds]
    allr = [r for r in raw_all if str(r.get("w", "")).startswith("closefail") and e2e.good(r) and str(r.get("round")) not in excl]
    recs = [r for r in allr if r.get("round") not in pcap_rounds]
    vals = {k: {m: {rr: v for rr, v in d_.items() if rr not in pcap_rounds} for m, d_ in mv.items()} for k, mv in vals.items()}
    out = []
    for w in [x for x in meta["workloads"] if x.startswith("closefail")]:
        for c in meta["clients"]:
            if c == "direct":
                continue
            for a in arms:
                mine = [r for r in recs if r["arm"] == a and r["client"] == c and r["w"] == w]
                per_run = [((r["res"].get("s") or {}).get("outcomes", []), [x for x in ((r["res"].get("s") or {}).get("resp") or []) if isinstance(x, dict)]) for r in mine]
                oc = [o for o_, _ in per_run for o in o_]
                rs = [x for _, rr in per_run for x in rr]
                n, k = len(oc), oc.count(0)
                if is_browser(c) and not any("pending_at_close" in x for x in rs):
                    rs_tap = []  # the first page tap grouped by microtask checkpoint: 0 by construction, so not a measurement
                else:
                    rs_tap = rs
                R = [x for x in rs_tap if resp_in_close_read(x)]
                nR = [x for x in rs_tap if resp_in_close_read(x) is False]
                row = {"workload": w, "arm": a, "client": c, "runs": len(mine), "responses": n, "lost": k,
                       "lost_pct": round(100 * k / n, 2) if n else None,
                       "lost_wilson95": [round(100 * v, 2) for v in wilson(k, n)] if n else None,
                       "lost_runboot95": boot_runs([(o.count(0), len(o)) for o, _ in per_run]),
                       "tapped": len(R) + len(nR), "R": len(R), "lost_when_R": sum(not x["ok"] for x in R),
                       "lost_when_not_R": sum(not x["ok"] for x in nR),
                       "R_runboot95": boot_runs([(sum(bool(resp_in_close_read(x)) for x in rr), sum(resp_in_close_read(x) is not None for x in rr)) for _, rr in per_run])
                                      if rs_tap else None,
                       "R_kind": ("pending_at_close" if any("pending_at_close" in x for x in rs) else "none (old page tap: not measured)")
                                 if is_browser(c) else "same_socket_read",
                       "failed_runs": len(fails_of(a, c, w)), "truncated": sum((r["res"].get("s") or {}).get("truncated", 0) for r in mine),
                       "timeouts": sum(1 for x in rs if str(x.get("err") or "").startswith("timeout")),
                       "packets_sharing_a_timer_turn": sum((r["res"].get("s") or {}).get("packets_sharing_a_timer_turn", 0) for r in mine) if is_browser(c) else None,
                       "packets": sum((r["res"].get("s") or {}).get("packets", 0) for r in mine) if is_browser(c) else None,
                       "errors": sorted({(x.get("err") or "")[:70] for x in rs if not x["ok"]})[:4]}
                if a != arms[0]:
                    pc = cmp(vals.get((arms[0], c, w), {}).get("close_lost_pct", {}), vals.get((a, c, w), {}).get("close_lost_pct", {}), "close_lost_pct")
                    row["paired_vs_first_arm"] = cell(pc)
                out.append(row)
    return meta, pcap_rounds, out


def close_table(label, d):
    meta, pcap_rounds, rows = close_counts(d)
    arms = [x["label"] for x in meta["arms"]]
    L = [f"### {label}: {meta.get('box')} {meta['started_utc']}, {meta['rounds']} rounds"
         + (f" (pcap round {', '.join(map(str, pcap_rounds))} left out)" if pcap_rounds else "")
         + (f", {len(meta.get('excluded_rounds', {}))} excluded" if meta.get("excluded_rounds") else "") + f" ({d.split('/stale/')[-1]})", "",
         "Responses pooled over rounds. R, Node clients: the response-bearing DATA arrived in the same socket read as the server's CLOSE.",
         "R, browsers (chromium/firefox/webkit): the page had not yet read the whole body when the CLOSE message arrived (pending_at_close; a browser runs a",
         "microtask checkpoint after every event callback, so the Node read grouping is always 0 there). '-' = not measured.",
         "[W] = Wilson (independent responses), [B] = bootstrap over runs (from 10 runs). Paired: per-round loss share against " + arms[0] + ".",
         "Failed runs (workload error or timeout) are not in the counts: see the last column.", "",
         "| workload | arm | client | runs | responses | lost | lost % [W] | [B] | R share % [W] | [B] | lost when R | lost when not R | paired vs " + arms[0] + " | failed runs / truncated / timeouts |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    fb = lambda b: f"[{b[0]:.1f}, {b[1]:.1f}]" if b else "-"
    for x in rows:
        if not x["responses"]:
            L.append(f"| {x['workload']} | {x['arm']} | {x['client']} | {x['runs']} | 0 | - | - | - | - | - | - | - | - | {x['failed_runs']} / {x['truncated']} / {x['timeouts']} |")
            continue
        t = x["tapped"]
        L.append(f"| {x['workload']} | {x['arm']} | {x['client']} | {x['runs']} | {x['responses']} | {x['lost']} | {pct(x['lost'], x['responses'])} | "
                 f"{fb(x['lost_runboot95'])} | {pct(x['R'], t) if t else '-'} | {fb(x['R_runboot95']) if t else '-'} | "
                 f"{str(x['lost_when_R']) + '/' + str(x['R']) if t else '-'} | {str(x['lost_when_not_R']) + '/' + str(t - x['R']) if t else '-'} | "
                 f"{x.get('paired_vs_first_arm', '-')} | {x['failed_runs']} / {x['truncated']} / {x['timeouts']} |")
    return "\n".join(L) + "\n"


def size_table(label, d):
    """closefail family per body size: kept responses per arm and the completion time (t1 - t0) of kept responses, per-round
    median, paired against the first arm. Kept sets differ between arms (a server that loses more keeps a biased subset),
    so read a time ratio together with both kept counts; the matched rows use only the requests (round, index) the first
    arm kept and the other arm kept too. Last block: server CPU per response and per delivered byte."""
    meta = json.load(open(os.path.join(d, "meta.json")))
    meta2, *_ = e2e.collect(d)
    excl = meta2.get("excluded_rounds", {})
    arms = [x["label"] for x in meta["arms"]]
    raw_all = e2e.load_raw(d)
    pcap_rounds = sorted({r.get("round") for r in raw_all if r.get("pcap")})
    recs = [r for r in raw_all if str(r.get("w", "")).startswith("closefail") and e2e.good(r) and str(r.get("round")) not in excl
            and r.get("round") not in pcap_rounds]
    kept, times, per_req, cpu = {}, {}, {}, {}
    failed, trunc = {}, {}
    for r in raw_all:
        if str(r.get("w", "")).startswith("closefail") and r.get("arm") and str(r.get("round")) not in excl \
                and r.get("round") not in pcap_rounds and not e2e.good(r):
            failed[(r["w"], r["client"], r["arm"])] = failed.get((r["w"], r["client"], r["arm"]), 0) + 1
    incomplete = sorted(r["round"] for r in raw_all if r.get("event") == "round" and r.get("incomplete") and str(r.get("round")) not in excl)
    for r in recs:
        trunc[(r["w"], r["client"], r["arm"])] = trunc.get((r["w"], r["client"], r["arm"]), 0) + ((r["res"].get("s") or {}).get("truncated") or 0)
        by = {}
        rs = [q for q in (r["res"].get("s") or {}).get("resp") or [] if isinstance(q, dict) and q.get("size") is not None]
        for q in rs:
            k = (r["w"], r["client"], q["size"], r["arm"])
            n_ok = kept.setdefault(k, [0, 0])
            n_ok[0] += 1
            ok = bool(q.get("ok")) and q.get("t1") is not None and q.get("t0") is not None
            if ok:
                n_ok[1] += 1
                by.setdefault(k, []).append(q["t1"] - q["t0"])
            per_req.setdefault((r["w"], r["client"], r["arm"], r["round"]), {})[q["i"]] = (q["size"], q["t1"] - q["t0"] if ok else None)
        for k, v in by.items():
            times.setdefault(k, {})[r["round"]] = st.median(v)
        sv = (r["res"].get("cpu") or {}).get("server_ms")
        tapped = any("bytes" in q for q in rs)  # epoxy tap: stream bytes of every response; a run with an unjoined one is left out
        nb = (sum(q["bytes"] for q in rs) if all(q.get("bytes") is not None for q in rs) else None) if tapped \
            else sum(q.get("got") or 0 for q in rs)  # no tap (wisp-js): body bytes
        if sv is not None and rs:
            c_ = cpu.setdefault((r["w"], r["client"], r["arm"]), {"per_resp": {}, "per_kept": {}, "per_mib": {}})
            c_["per_resp"][r["round"]] = sv / len(rs)
            nk = sum(1 for q in rs if q.get("ok"))
            if nk:
                c_["per_kept"][r["round"]] = sv / nk
            if nb:
                c_["per_mib"][r["round"]] = sv / (nb / 2**20)
    combos = sorted({k[:3] for k in kept}, key=lambda k: (meta["workloads"].index(k[0]), meta["clients"].index(k[1]), k[2]))
    L = [f"### {label}: per body size, {meta.get('box')} {meta['started_utc']}" + (f" ({excl_txt(meta2).lstrip(', ')})" if excl else "")
         + f" ({d.split('/stale/')[-1]})", "",
         "Kept = complete responses / responses issued in good runs. Failed runs and requests a limited run never issued (truncated) are",
         "not in the counts: " + ("; ".join(f"{w}/{c}/{a}: {failed.get((w, c, a), 0)} failed runs, {trunc.get((w, c, a), 0)} truncated"
                                           for (w, c, a) in sorted(set(failed) | {k for k, v in trunc.items() if v}))
                                  or "none in this session") + "."
         + (f" Incomplete rounds (good runs counted): {incomplete}." if incomplete else ""),
         "Time = t1 - t0 of kept responses (ms), median per round, then median over rounds; ratio = paired",
         f"against {arms[0]} over rounds where both kept at least one (HL ratio, 90 % CI, verdict). Different kept sets: read with the counts.", "",
         "| workload | client | size B | " + " | ".join(f"{a} kept | {a} ms" for a in arms) + " | " + " | ".join(f"{a}/{arms[0]}" for a in arms[1:]) + " |",
         "|" + "---|" * (3 + 2 * len(arms) + len(arms) - 1)]
    for w, c, sz in combos:
        cells = []
        for a in arms:
            n, ok = kept.get((w, c, sz, a), [0, 0])
            t = times.get((w, c, sz, a))
            cells += [f"{ok}/{n}", f"{st.median(t.values()):.2f}" if t else "-"]
        base = times.get((w, c, sz, arms[0])) or {}
        rat = [cell(cmp(base, times.get((w, c, sz, a)) or {}, "close_ok_p50_ms")) for a in arms[1:]]
        L.append(f"| {w} | {c} | {sz} | " + " | ".join(cells) + " | " + " | ".join(rat) + " |")
    # matched: only requests (same round, same index) that the first arm kept AND the other arm kept; the per-round medians
    # of both arms over exactly those requests, paired over rounds
    L += ["", f"Matched requests: per round, only the request indices that {arms[0]} kept and the compared arm kept too; median time of",
          "both over exactly those requests, paired over rounds. Rows where the first arm lost some responses of that size only.", "",
          "| workload | client | size B | arm | matched requests | rounds | " + arms[0] + " ms | arm ms | arm/" + arms[0] + " |", "|---|---|---|---|---|---|---|---|---|"]
    for w, c, sz in combos:
        n0, ok0 = kept.get((w, c, sz, arms[0]), [0, 0])
        if not ok0 or ok0 == n0:
            continue
        for a in arms[1:]:
            mb, ma, nm = {}, {}, 0
            for rnd in sorted({k[3] for k in per_req if k[:3] == (w, c, arms[0])}):
                p0, p1 = per_req.get((w, c, arms[0], rnd), {}), per_req.get((w, c, a, rnd), {})
                idx = [i for i, (s0, t0) in p0.items() if s0 == sz and t0 is not None and i in p1 and p1[i][1] is not None]
                if idx:
                    mb[rnd], ma[rnd] = st.median(p0[i][1] for i in idx), st.median(p1[i][1] for i in idx)
                    nm += len(idx)
            if mb:
                L.append(f"| {w} | {c} | {sz} | {a} | {nm} | {len(mb)} | {st.median(mb.values()):.2f} | {st.median(ma.values()):.2f} | "
                         f"{cell(cmp(mb, ma, 'close_ok_p50_ms'))} |")
    # server CPU: the server process CPU of the whole run (warm-up included) per response, per kept response, per MiB of
    # stream bytes the client received (kept and lost responses)
    L += ["", "Server CPU of the run (server process, warm-up request included): per response, per kept response, per MiB the client",
          "received on the response streams (kept and lost; epoxy: stream bytes from the tap, headers included; wisp-js: body bytes of",
          f"kept responses, it loses none). Median over rounds; ratio paired against {arms[0]}.", "",
          "| workload | client | arm | ms / response | ms / kept response | ms / MiB received (rounds) | ratio / response | ratio / kept | ratio / MiB |",
          "|---|---|---|---|---|---|---|---|---|"]
    for w in [x for x in meta["workloads"] if x.startswith("closefail")]:
        for c in meta["clients"]:
            b0 = cpu.get((w, c, arms[0]))
            if not b0:
                continue
            for a in arms:
                x = cpu.get((w, c, a))
                if not x:
                    continue
                f = lambda v: f"{st.median(v.values()):.3f}" if v else "-"
                rr = ["-", "-", "-"] if a == arms[0] else [cell(cmp(b0[m], x[m], "server_cpu_ms")) for m in ("per_resp", "per_kept", "per_mib")]
                L.append(f"| {w} | {c} | {a} | {f(x['per_resp'])} | {f(x['per_kept'])} | {f(x['per_mib'])} ({len(x['per_mib'])}) | " + " | ".join(rr) + " |")
    return "\n".join(L) + "\n"


GATE_KEYS = ("browser", "held", "released", "capped", "dropped", "nopong", "full", "pings")


def gate_rows(d):
    """close_counts rows plus, per (workload, arm, client), the server's metric deltas summed over the good runs (e2e.py scrapes
    GET /metrics before / after each client process of an arm with --metrics-listen), console errors of browser runs,
    request streams the page's tap saw without a CLOSE, and the checks a verdict needs (expected runs, valid scrapes)"""
    meta, pcap_rounds, rows = close_counts(d)
    excl = meta.get("excluded_rounds", {})
    raw_all = e2e.load_raw(d)
    rounds = sorted({r["round"] for r in raw_all if r.get("event") == "round" and str(r["round"]) not in excl
                     and r["round"] not in pcap_rounds})
    good = [r for r in raw_all if r.get("arm") and r.get("client") and e2e.good(r) and str(r.get("round")) not in excl
            and r.get("round") not in pcap_rounds]
    gated_arms = {r["arm"] for r in good if (r.get("metrics") or {}).get("gate_counters")}
    for row in rows:
        mine = [r for r in good if (r["arm"], r["client"], r["w"]) == (row["arm"], row["client"], row["workload"])]
        row["expected_runs"] = len(rounds)
        row["missing_runs"] = max(0, len(rounds) - row["runs"] - row["failed_runs"])
        ms = [r.get("metrics") for r in mine]
        row["metrics_runs"] = sum(1 for m in ms if m and "delta" in m)
        row["metrics_missing"] = sum(1 for m in ms if not m or "delta" not in m)
        # a run's scrape pair is invalid: a counter went down, a gate counter in one snapshot only, or (gated arm) the gate
        # counters missing in either snapshot; records of the first smoke have no 'invalid' / 'gate_counters_before' keys
        row["metrics_invalid"] = sum(1 for m in ms if m and "delta" in m and (m.get("invalid") or (
            row["arm"] in gated_arms and not (m.get("gate_counters") and m.get("gate_counters_before", True)))))
        row["unsettled"] = sum(1 for m in ms if m and (m.get("settled") is False or m.get("quiet_before") is False))
        tot = {}
        for m in ms:
            for k, v in ((m or {}).get("delta") or {}).items():
                tot[k] = tot.get(k, 0) + v
        row["has_gate_counters"] = row["arm"] in gated_arms
        row["gate"] = {g: tot.get(f"finalwisp_ping_gate_{g}_total", 0) for g in GATE_KEYS}
        row["close_sent"] = sum(v for k, v in tot.items() if k.startswith("finalwisp_close_total"))
        row["accepted"] = tot.get("finalwisp_accepted_total", 0)
        cons = [x for r in mine for x in ((r["res"].get("s") or {}).get("browser") or {}).get("console", [])]
        row["console_errors"] = sum(1 for x in cons if x.startswith(("error:", "pageerror:")))
        row["console_other"] = sum(1 for x in cons if not x.startswith(("error:", "pageerror:")))
        row["console_sample"] = sorted(set(x[:120] for x in cons))[:5]
        # request streams without a CLOSE: the page's own count (warm-up stream left out unless a request reused it), else
        # (first smoke) from the tap's streams; None for a run whose tap saw no message
        swc = []
        for r in mine:
            s_ = r["res"].get("s") or {}
            if "streams_without_close" in s_:
                swc.append(s_["streams_without_close"])
            elif s_.get("packets") and s_.get("streams"):
                swc.append(sum(1 for x in s_["streams"][1 if s_.get("joined") else 0:] if x.get("reason") is None))
            else:
                swc.append(None)
        row["untapped_runs"] = sum(1 for x in swc if x is None) if is_browser(row["client"]) else 0
        row["streams_without_close"] = None if not swc or all(x is None for x in swc) else sum(x or 0 for x in swc)
        row["engine"] = sorted({f"{b.get('engine')} {b.get('version')}" for r in mine for b in [((r["res"].get("s") or {}).get("browser") or {})] if b})
    return meta, rows


def gate_verdict(row):
    """PASS / FAIL per the smoke's criteria (counts only)"""
    fn_ok = (row["responses"] > 0 and row["lost"] == 0 and row["failed_runs"] == 0 and row["missing_runs"] == 0
             and row["truncated"] == 0 and row["timeouts"] == 0 and row["console_errors"] == 0
             and row["metrics_missing"] == 0 and row["metrics_invalid"] == 0 and row["unsettled"] == 0)
    g = row["gate"]
    if is_browser(row["client"]):  # skipped as a browser: CLOSEs at once, nothing held, no gate PING; every run tapped
        return "PASS" if (fn_ok and row["untapped_runs"] == 0 and row["streams_without_close"] == 0
                          and g["browser"] > 0 and g["held"] == 0 and g["pings"] == 0) else "FAIL"
    # a native client: held, released by the PONG, no nopong, (almost) no cap
    return "PASS" if fn_ok and g["held"] > 0 and g["nopong"] == 0 and g["full"] == 0 and g["capped"] <= 0.01 * g["held"] else "FAIL"


def gate_table(label, d):
    meta, rows = gate_rows(d)
    arms = [x["label"] for x in meta["arms"]]
    gated = sorted({r["arm"] for r in rows if r["has_gate_counters"]})
    L = [f"### {label}: {meta.get('box')} {meta['started_utc']}, {meta['rounds']} rounds ({d.split('/stale/')[-1]})", "",
         "Counts only. Gate counters = the server's finalwisp_ping_gate_*_total, GET /metrics before and after each client process,",
         "summed over the runs ('-': the build has no such counter). close sent = finalwisp_close_total (all reasons). console err =",
         "browser console messages of type error and page errors. no-CLOSE = request streams the page's tap saw without a CLOSE (the",
         "keep-alive warm-up's own stream excluded; '-': not a browser, or the tap saw no message). Verdict (arms with gate counters): browser rows PASS = no loss / failure / truncation / timeout /",
         "console error, browser > 0, held = 0, pings = 0; native rows PASS = the same function checks, held > 0, nopong = 0,",
         "full = 0, capped <= 1 % of held. Every verdict also needs all expected runs, a valid and settled scrape pair per run",
         "(quiet server before and after: no connection, stream or held CLOSE; no counter going down), and (browsers) a tap",
         "that saw every run. Control rows: '-' (reference).", "",
         "| workload | client | arm | runs | responses | lost | failed / trunc / timeouts | console err | no-CLOSE | close sent | "
         + " | ".join(GATE_KEYS) + " | missing / invalid / unsettled scrapes | verdict |",
         "|" + "---|" * (11 + len(GATE_KEYS) + 1)]
    for x in rows:
        g = x["gate"]
        gc = [str(g[k]) if x["has_gate_counters"] else "-" for k in GATE_KEYS]
        v = gate_verdict(x) if x["arm"] in gated else "-"
        L.append(f"| {x['workload']} | {x['client']} | {x['arm']} | {x['runs']}" + (f" of {x['expected_runs']}" if x['missing_runs'] else "") + f" | {x['responses']} | {x['lost']} | "
                 f"{x['failed_runs']} / {x['truncated']} / {x['timeouts']} | {x['console_errors']} | "
                 f"{'-' if x['streams_without_close'] is None else x['streams_without_close']} | {x['close_sent']} | "
                 + " | ".join(gc) + f" | {x['metrics_missing']} / {x['metrics_invalid']} / {x['unsettled']} | {v} |")
    eng = sorted({e for x in rows for e in x["engine"]})
    if eng:
        L += ["", "Engines: " + "; ".join(eng) + "."]
    samp = sorted({s for x in rows for s in x["console_sample"]})
    L += ["", "Console messages (distinct, first 120 characters): " + ("; ".join(samp[:12]) if samp else "none") + "."]
    return "\n".join(L) + "\n"


def main(argv):
    if "--close-json" in argv:  # counts JSON for scripts: report_tables.py --close-json DIR
        meta, pcap_rounds, rows = close_counts(argv[argv.index("--close-json") + 1])
        print(json.dumps({"box": meta.get("box"), "started_utc": meta["started_utc"], "rounds": meta["rounds"],
                          "excluded_rounds": meta.get("excluded_rounds", {}), "pcap_rounds": pcap_rounds, "rows": rows}, indent=1))
        return
    check = None
    if "--check" in argv:
        i = argv.index("--check")
        check = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    tables = []
    for i in range(0, len(argv), 2):
        kind, spec = argv[i], argv[i + 1]
        label, _, d = spec.partition("=")
        tables.append({"--vis": vis_table, "--faults": fault_table, "--close": close_table, "--size": size_table, "--gate": gate_table}[kind](label, d))
    if check:
        rep = open(check).read()
        bad = [t.splitlines()[0] for t in tables if t not in rep]
        n = sum(len(t.splitlines()) for t in tables)
        if bad:
            print("CHECK FAILED: not byte for byte in " + check + ": " + "; ".join(bad))
            sys.exit(1)
        print(f"CHECK OK: {len(tables)} tables, {n} lines in {check}")
        return
    print("\n".join(tables), end="")


if __name__ == "__main__":
    main(sys.argv[1:])
