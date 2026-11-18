#!/usr/bin/env python3
"""60.78 G02: tables of bench/showpair.py runs: finalwisp against each competitor, paired by round.

usage: bench/showpair-tables.py LABEL=DIR[@ARM] [LABEL=DIR[@ARM] ...] [--check REPORT.md]
DIR = a showpair OUT_DIR pulled from a box (raw.jsonl, meta.jsonl; md5.txt of the kit beside them). @ARM pairs every
other arm against ARM instead of the run's --ref (the ratios are then ARM / X).
Per box and cell, for each competitor X: the rounds where finalwisp and X both have a valid run in the latest complete
attempt of the round (all arms with the same run_id) are the pairs; wispsuite.stats.compare(X, finalwisp) gives the
paired Hodges-Lehmann ratio finalwisp / X, its 90 % CI, p and the verdict seen from finalwisp (WIN = finalwisp faster,
LOSS = slower, tie = not significant and finalwisp not more than 5 % slower, watch / unclear as stats.py).
A failed run of X (did not start, exited, no result, moved nothing) drops its pair and is counted in "X failed";
it is never a win. --check: every table printed must appear byte for byte in REPORT.md (exit 1 if not)."""
import json, os, sys
from collections import defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from wispsuite import stats  # noqa: E402

LABEL = {"upload:1:1:16384": "upload 1x1", "upload:10:10:16384": "upload 10x10", "upload:10:2:16384": "upload 10x2",
         "download:10:10": "download 10x10", "download:10:2": "download 10x2", "echo:1:1:16384": "echo 1x1",
         "echo:10:10:16384": "echo 10x10", "echo:10:2:16384": "echo 10x2", "rr:1:1:64": "rr 1x1", "rr:10:10:64": "rr 10x10",
         "churn:10:10:64": "churn 10x10"}


def load(d):
    raw = [json.loads(l) for l in open(os.path.join(d, "raw.jsonl"))]
    meta = [json.loads(l) for l in open(os.path.join(d, "meta.jsonl"))]
    md5 = {}
    p = os.path.join(d, "md5.txt")
    if os.path.exists(p):
        for l in open(p):
            h, f = l.split()
            md5[f] = h[:8]
    return raw, meta, md5


def pairs(raw, servers, ref):
    """{cell: {X: (x_vals, fw_vals, x_fail_kinds, fw_fail, n_rounds, press)}} over the latest complete attempt per round"""
    by = defaultdict(lambda: defaultdict(dict))  # (cell, round) -> run_id -> server -> rec
    for r in raw:
        by[(r["cell"], r["round"])][r["run_id"]][r["server"]] = r
    out = defaultdict(dict)
    rounds = defaultdict(list)
    for (cell, rnd), att in sorted(by.items()):
        done = [rid for rid, s in att.items() if all(n in s for n in servers)]
        if done:
            rounds[cell].append(att[max(done)])
    for cell, rs in rounds.items():
        for x in servers:
            if x == ref:
                continue
            xv, fv, xf, ff, pr, xe, fe = [], [], defaultdict(int), 0, 0, 0, 0
            for s in rs:
                a, b = s[x], s[ref]
                if "error" in a:
                    xf[a["error"].split(":")[0]] += 1
                if "error" in b:
                    ff += 1
                pr += bool(a.get("tcp_press") or a.get("tcp_press_frac")) + bool(b.get("tcp_press") or b.get("tcp_press_frac"))
                if "error" in a or "error" in b:
                    continue
                xe += a.get("errors") or 0
                fe += b.get("errors") or 0
                xv.append(a["value"])
                fv.append(b["value"])
            out[cell][x] = (xv, fv, dict(xf), ff, len(rs), pr, xe, fe)
    return out


def fmt_ci(c):
    return f"[{c[0]:.3f}, {c[1]:.3f}]" if c else "-"


def box_table(label, d):
    d, _, ref_over = d.partition("@")  # DIR@NAME: pair against arm NAME instead of the run's reference
    raw, meta, md5 = load(d)
    m = dict(meta[0])
    if ref_over:
        if ref_over not in m["servers"]:
            sys.exit(f"{label}: @{ref_over} is not an arm of {d}")
        m["ref"] = ref_over
    incomplete = []
    fwname = os.path.basename(m.get("fw") or "") or "finalwisp"
    servers, ref = m["servers"], m["ref"]
    pp = pairs(raw, servers, ref)
    others = [s for s in servers if s != ref]
    lines = [f"### {label}: {m['cpu']}, {m['nproc']} CPUs, Linux {m['kernel']}",
             (f"reference arm here: {m['ref']} (ratios {m['ref']} / X); " if m["ref"] != meta[0]["ref"] else "") +
             f"finalwisp = {fwname} md5 {md5.get(fwname, '?')}; {m['rounds']} rounds per cell, {m['dur']} s + {m['warmup']} s,"
             f" settle {m['settle']} s; slot order balanced (Williams). Cell entries: {m['ref'].split('=')[0]} / X (paired HL), 90 % CI,"
             f" verdict (from {m['ref'].split('=')[0]}'s side), pairs; 'X failed k' = runs of X that failed (pair dropped); 'X wbench errors' = stream"
             " errors wbench counted in X's valid runs; 'P k' = runs of the pair (both arms) with kernel TCP memory pressure.", ""]
    show = {x: x.split("=", 1)[0] for x in others}  # NAME=COMMAND specs: the name
    lines.append("| cell | " + " | ".join(show[x] for x in others) + " |")
    lines.append("|---|" + "---|" * len(others))
    summ = []
    for cell in m["cells"]:
        if cell not in pp:
            lines.append(f"| {LABEL.get(cell, cell)} | " + " | ".join("not run" for _ in others) + " |")
            continue
        row, verdicts = [], {}
        nr = next(iter(pp[cell].values()))[4]
        ffail = max(v[3] for v in pp[cell].values())
        if nr < m["rounds"]:
            incomplete.append(f"{LABEL.get(cell, cell)} {nr}/{m['rounds']} rounds")
        for x in others:
            xv, fv, xf, ff, nr, pr, xe, fe = pp[cell][x]
            c = stats.compare(xv, fv) if len(xv) >= 2 else None
            fail = "; ".join(f"X failed {k} ({e})" for e, k in sorted(xf.items()))
            ffs = (f"; finalwisp failed {ff}" if ff else "") + (f"; X wbench errors {xe}" if xe else "") + (
                f"; finalwisp wbench errors {fe}" if fe else "") + (f"; P {pr}" if pr else "")
            if c is None:
                row.append(f"no verdict ({len(xv)} pairs{'; ' + fail if fail else ''}{ffs})")
                verdicts[x] = "none"
            else:
                row.append(f"{c['ratio']:.2f} {fmt_ci(c['ci90'])} {c['verdict']} n={c['n']}{'; ' + fail if fail else ''}{ffs}")
                verdicts[x] = c["verdict"]
        lines.append(f"| {LABEL.get(cell, cell)} ({nr} rounds) | " + " | ".join(row) + " |")
        summ.append((cell, verdicts, ffail))
    lines.append("")
    rn = m["ref"].split("=")[0]
    lines.append(f"| cell ({label}) | {rn} WIN against | tie | LOSS | watch / unclear | no verdict (X failed) | {rn} failed runs |")
    lines.append("|---|---|---|---|---|---|---|")
    for cell, v, ffail in summ:
        g = lambda k: ", ".join(show[x] for x in others if v[x] in k) or "-"
        lines.append(f"| {LABEL.get(cell, cell)} | {g(('WIN',))} | {g(('tie',))} | {g(('LOSS',))} | {g(('watch', 'unclear'))} | {g(('none',))} | {ffail} |")
    missing = [LABEL.get(c, c) for c in m["cells"] if c not in pp]
    if incomplete or missing or not os.path.exists(os.path.join(d, "DONE")):
        lines.append("")
        lines.append("INCOMPLETE: " + "; ".join(incomplete + [f"{c} not run" for c in missing]
                                               + ([] if os.path.exists(os.path.join(d, "DONE")) else ["no DONE file"])))
    return "\n".join(lines) + "\n"


def main(argv):
    check = None
    if "--check" in argv:
        i = argv.index("--check")
        check = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if not argv:
        sys.exit(__doc__)
    tables = [box_table(*a.split("=", 1)) for a in argv]
    text = "\n".join(tables)
    if check:
        rep = open(check).read()
        bad = [t.splitlines()[0] for t in tables if t not in rep]
        if bad:
            print("CHECK FAILED: not byte for byte in " + check + ": " + "; ".join(bad))
            sys.exit(1)
        print(f"CHECK OK: {len(tables)} tables in {check}")
        return
    print(text, end="")


if __name__ == "__main__":
    main(sys.argv[1:])
