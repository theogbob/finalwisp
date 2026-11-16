#!/usr/bin/env python3
"""60.74 (auto-balance2) tables, printed from raw files in an internal note (not published) (main checkout).
usage: python3 bench/auto-balance2-tables.py [--check note 60.74]
--check: every <!-- table NAME --> block of the note must equal the table printed here (exit 1 if not)."""
import glob, json, os, re, statistics, sys

ROOT = os.environ.get("AB2_RAW", "an internal note (not published)")
TABLES = {}


def table(name):
    def deco(f):
        TABLES[name] = f
        return f
    return deco


def md(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(x) for x in r) + " |" for r in rows]
    return "\n".join(out)


FNS = ["<finalwisp::worker::Worker>::run", "<finalwisp::worker::Worker>::close_client", "<finalwisp::worker::Worker>::take",
       "<finalwisp::worker::Worker>::adopt", "<finalwisp::worker::Worker>::accept_on"]
ARMS = [("base", "v1.3.1 (26793d35)"), ("base2", "v1.3.1, copy"), ("new", "this build, flag off"), ("new2", "this build, copy")]


ARMS3 = [("base", "v1.3.2 (0eb36d76)"), ("base2", "v1.3.2, copy"), ("new", "this build, flag off"), ("new2", "this build, copy")]


def cg_rows(d, cell, unit, arms=ARMS):
    rows = []
    for arm, label in arms:
        for f in sorted(glob.glob(f"{d}/{cell}.{arm}.*.cg.json")):
            j = json.load(open(f))
            fn = j["fn"]
            rows.append([label, j["rep"], j["md5"][:8], f"{j['units']:,}", f"{j['el']['Ir']:,.1f}"] + [f"{fn.get(x, 0):.2f}" for x in FNS])
    return md(["arm", "rep", "md5", f"{unit}s", f"all user Ir per {unit}", "run", "close_client", "take", "adopt", "accept_on"], rows)


@table("cg-connchurn")
def _():
    return cg_rows(f"{ROOT}/proof/costfp-79597662", "connchurn", "connection")


@table("cg-rr1")
def _():
    return cg_rows(f"{ROOT}/proof/costfp-79597662", "rr1", "request")


def disasm_rows(f):
    rows = []
    for l in open(f):
        m = re.match(r"^(worker|finalwisp|other)\s+(OFFSET-ONLY|RENAME-ONLY|LOGIC)\s+(\d+)", l)
        if m:
            rows.append(list(m.groups()))
    return md(["group", "class", "functions"], rows)


def logic_rows(f, base):
    j = json.load(open(f))
    rows = [[f"`{r['fn'][:70]}`", r["only_base"], r["only_new"], ", ".join(c.split("::")[-1][:30] for c in r["new_calls"])] for r in j["rows"]]
    return md(["function (LOGIC in disasm_cls)", f"instructions only in {base}", "only in this build", "new calls"], rows)


@table("disasm")
def _():
    return disasm_rows(f"{ROOT}/proof/disasm-cls-79597662.txt")


@table("disasm-logic")
def _():
    return logic_rows(f"{ROOT}/proof/disasm-logic-79597662.json", "v1.3.1")


# 60.74 the v1.3.3 round (the observer naps): against v1.3.2
@table("cg-connchurn-133")
def _():
    return cg_rows(f"{ROOT}/proof/costfp-f71248e8", "connchurn", "connection", ARMS3)


@table("cg-rr1-133")
def _():
    return cg_rows(f"{ROOT}/proof/costfp-f71248e8", "rr1", "request", ARMS3)


@table("disasm-133")
def _():
    return disasm_rows(f"{ROOT}/proof/disasm-cls-f71248e8.txt")


@table("disasm-logic-133")
def _():
    return logic_rows(f"{ROOT}/proof/disasm-logic-f71248e8.json", "v1.3.2")


def smoke_rows(files):
    rows = []
    for f in files:
        for l in open(f):
            r = json.loads(l)
            v = [t.get("verdict") or ("dropped" if "dropped" in (t.get("text") or "") else None) for t in r["trials"]]
            v = [x for x in v if x]
            rows.append([os.path.basename(f), r["case"], r["run"], r["threads"], r.get("dry") or "0", r.get("ticks") or "5", len(v),
                         " ".join(v) or "-", f"{r['moved_conns']}/{r['moved_back']}", r["errors"]])
    return md(["file", "cell", "run", "threads", "dry", "window ticks", "trials", "verdicts", "moved / moved back", "errors"], rows)


@table("smoke")
def _():
    return smoke_rows(sorted(glob.glob(f"{ROOT}/raw/laptop/smoke[0-9].jsonl")))


BOXES = ["gold3", "v187", "v194"]
VERDICTS = ["Keep", "Flat", "Fell", "Noisy", "Moved", "Empty", "NoMeasure"]


def trials_of(row):
    """(verdict or 'dropped', |A2/A1 - 1| of the bytes or None) per trial line of one run."""
    out = []
    for t in row["trials"]:
        v = t.get("verdict") or ("dropped" if "dropped" in (t.get("text") or "") else None)
        if not v:
            continue
        try:
            a1, a2 = float(t["a1_bytes"]), float(t["a2_bytes"])
            n = abs(a2 / a1 - 1) if a1 > 0 and a2 > 0 else None
        except (KeyError, ValueError):
            n = None
        out.append((v, n))
    return out


def counts(ts):
    c = {}
    for v, _ in ts:
        c[v] = c.get(v, 0) + 1
    return " ".join(f"{k} {c[k]}" for k in VERDICTS + ["dropped"] if k in c) or "-"


@table("null")
def _():
    rows = []
    for box in BOXES:
        for ticks in (2, 5, 10):
            by = {}
            # (null-t: the jobN cells; its download cell ran against an echo target, no traffic: left out, run again
            # with a source target as jobD, null-dl-t)
            for f in (f"{ROOT}/raw/{box}/null-t{ticks}.jsonl", f"{ROOT}/raw/{box}/null-dl-t{ticks}.jsonl"):
                if not os.path.exists(f):
                    continue
                for l in open(f):
                    r = json.loads(l)
                    if r["case"].startswith("download") and "/null-t" in f:
                        continue
                    by.setdefault(r["case"], []).extend(trials_of(r))
            for case, ts in by.items():
                n = sorted(x for _, x in ts if x is not None)
                judged = [v for v, _ in ts if v not in ("Empty", "dropped")]
                keep = sum(v == "Keep" for v, _ in ts)
                rows.append([box, ticks * 100, case, len(ts), counts(ts), f"{keep}/{len(judged)}",
                             f"{100 * statistics.median(n):.1f}" if n else "-", f"{100 * n[int(0.9 * (len(n) - 1))]:.1f}" if n else "-"])
    return md(["box", "window ms", "cell", "trials", "verdicts", "dry Keep / judged", "median abs(A2/A1-1) %", "p90 %"], rows)


@table("explore")
def _():
    rows = []
    for box in BOXES:
        f = f"{ROOT}/raw/{box}/explore.jsonl"
        if not os.path.exists(f):
            continue
        by = {}
        for l in open(f):
            r = json.loads(l)
            b = by.setdefault(r["case"], {"runs": 0, "ts": [], "mv": 0, "bk": 0, "rs": 0, "err": 0})
            b["runs"] += 1
            b["ts"] += trials_of(r)
            b["mv"] += r["moved_conns"] or 0
            b["bk"] += r["moved_back"] or 0
            b["rs"] += r["moved_reset"] or 0
            b["err"] += r["errors"] or 0
        for case, b in by.items():
            rows.append([box, case, b["runs"], len(b["ts"]), counts(b["ts"]), f"{b['mv']}/{b['bk']}/{b['rs']}", b["err"]])
    return md(["box", "cell", "runs of 20 s", "trials", "verdicts", "moved / moved back / reset", "errors"], rows)


def paired(f, metric):
    """{variant: {rep: value}} of one wst ab raw file."""
    out = {}
    for l in open(f):
        r = json.loads(l)
        out.setdefault(r["v"], {})[r["rep"]] = r[metric]
    return out


def ratio_ci(a, b, seed=7):
    """median of the per-rep ratios a/b, and a 95% bootstrap interval of that median (2000 resamples)."""
    import random
    reps = sorted(set(a) & set(b))
    rs = [a[k] / b[k] for k in reps if b[k] > 0]
    if not rs:
        return None
    rnd = random.Random(seed)
    meds = sorted(statistics.median(rnd.choices(rs, k=len(rs))) for _ in range(2000))
    return statistics.median(rs), meds[50], meds[1949], len(rs)


def ab_rows(box, job, pairs):
    """wispsuite.stats.compare per pair (the project's paired verdict: HL ratio, Wilcoxon p, 90% interval), paired by
    round."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
    from wispsuite.stats import compare
    rows = []
    for f in sorted(glob.glob(f"{ROOT}/raw/{box}/{job}/*.jsonl")):
        if f.endswith("summary.jsonl"):
            continue
        case = os.path.basename(f)[:-6]
        metric = "mib_s_down" if case.startswith(("download", "echo")) else "rps"
        p = paired(f, metric)
        err = sum(json.loads(l).get("errors", 0) for l in open(f))
        for x, y in pairs:
            if x not in p or y not in p:
                continue
            reps = sorted(set(p[x]) & set(p[y]))
            c = compare([p[y][k] for k in reps], [p[x][k] for k in reps])
            if c:
                ci = c["ci90"] and f"[{c['ci90'][0]:.3f}, {c['ci90'][1]:.3f}]"
                rows.append([box, case, metric, f"{x} / {y}", c["n"], f"{c['ratio']:.3f}", ci or "-", f"{c['p']:.3f}",
                             c["verdict"], f"{c['new']:,.1f}", err])
    return rows


AB_HEAD = ["box", "cell", "metric", "pair", "n", "HL ratio", "90% interval", "p", "verdict (stats.py)", "median of the first", "errors (all arms)"]


@table("gold3")
def _():
    return md(AB_HEAD, ab_rows("gold3", "G", [("bas2", "base"), ("on", "base"), ("on", "bas2"), ("bal", "base")]))


@table("vps")
def _():
    rows = []
    for box in ("v187", "v194"):
        rows += ab_rows(box, "V", [("bas2", "base"), ("off", "base"), ("on", "base"), ("on", "bas2"), ("on", "off")])
    return md(AB_HEAD, rows)



@table("vps32")
def _():
    return md(AB_HEAD, ab_rows("v187", "W", [("bas2", "base"), ("off", "base"), ("on", "base"), ("on", "bas2"), ("on", "off")]))



# 60.74 the v1.3.3 round: base / bas2 = v1.3.2, off / on = this build (the observer naps), n=32, raw/<box>-133/W
@table("vps133")
def _():
    rows = []
    for box in ("v187", "v194"):
        rows += ab_rows(f"{box}-133", "W", [("bas2", "base"), ("off", "base"), ("on", "base"), ("on", "bas2"), ("on", "off")])
    return md(AB_HEAD, rows)


@table("nap133")
def _():
    rows = []
    for box in ("v187", "v194"):
        f = f"{ROOT}/raw/{box}-133/stderr-on.log"
        if not os.path.exists(f):
            continue
        lines = [l for l in open(f) if "balance_naps=" in l]
        get = lambda l, k: int(re.search(rf"\b{k}=(\d+)", l).group(1))
        napping = sum(get(l, "balance_nap_s") > 0 for l in lines)
        rows.append([box, len(lines), max(get(l, "moved_conns") for l in lines), max(get(l, "balance_naps") for l in lines),
                     f"{napping} ({100 * napping / len(lines):.0f}%)", max(get(l, "balance_nap_s") for l in lines)])
    return md(["box", "metrics lines of the on arm (5 s apart)", "moved_conns (max per server)", "balance_naps (max per server)",
               "lines in a nap", "longest nap s"], rows)



def vm_rows(f):
    rows = []
    for l in open(f):
        r = json.loads(l)
        tl, te = r["load_start"], r["load_end"]
        trials = [(t - tl, x) for t, x in r["lines"] if "auto-balance: trial" in x]
        naps = [(t - tl, x) for t, x in r["lines"] if "auto-balance: nap" in x and 0 <= t - tl <= te - tl]
        judged = [(t, x) for t, x in trials if "verdict=" in x]
        first = judged[0][0] if judged else None
        verdicts = {}
        for _, x in judged:
            v = re.search(r"verdict=(\w+)", x).group(1)
            verdicts[v] = verdicts.get(v, 0) + 1
        last = [x for _, x in r["lines"] if "balance_naps=" in x][-1]
        get = lambda k: int(re.search(rf"\b{k}=(\d+)", last).group(1))
        after = sum(1 for t, _ in naps if first is not None and t > first)
        rows.append([r["case"], f"{first:.1f}" if first is not None else "none", " ".join(f"{k} {v}" for k, v in sorted(verdicts.items())) or "-",
                     len(naps), " ".join(f"{t:.0f}" for t, _ in naps) or "-", after, get("moved_conns"), get("moved_back"), r["errors"]])
    return md(["cell", "first judged trial, s after the load started", "verdicts", "naps under load", "nap starts, s", "naps after the first judged trial",
               "moved_conns", "moved_back", "client errors"], rows)


# 60.74 4.3 the 16-vCPU function check (one VM on the build host, counts only): the nap build, then decision C
@table("vm16-nap")
def _():
    return vm_rows(f"{ROOT}/vm16/out-c959e40c.jsonl")


@table("vm16-c")
def _():
    return vm_rows(f"{ROOT}/vm16/out.jsonl")


def main():
    out = {n: f() for n, f in TABLES.items()}
    if len(sys.argv) > 2 and sys.argv[1] == "--check":
        note = open(sys.argv[2]).read()
        bad = 0
        for n, t in out.items():
            m = re.search(rf"<!-- table {re.escape(n)} -->\n(.*?)\n<!-- /table -->", note, re.S)
            if not m:
                print(f"{n}: not in the note"); bad += 1
            elif m.group(1).strip() != t.strip():
                print(f"{n}: DIFFERS"); bad += 1
        print(f"check: {len(out)} tables, {bad} problem(s): {'OK' if not bad else 'BROKEN'}")
        sys.exit(1 if bad else 0)
    for n, t in out.items():
        print(f"<!-- table {n} -->\n{t}\n<!-- /table -->\n")


main()
