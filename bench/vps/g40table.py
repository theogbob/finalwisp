#!/usr/bin/env python3
"""60.78 G40 (sb-robust): fd-admission off / on / off copy (A/A), churn 1x10, one `wst ab` on VPS1 (rotated arms, 100
rounds, dur 4 s, warmup 1 s). Pairs by round; verdicts of bench/wispsuite/stats.py compare (rules unchanged), key rps.
usage: bench/vps/g40table.py RAW.jsonl [--check NOTE.md]"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from wispsuite import stats

by = {}
for l in open(sys.argv[1]):
    r = json.loads(l)
    by.setdefault(r["v"], {})[r["rep"]] = r
def ok(r): return r is not None and "error" not in r and isinstance(r.get("rps"), (int, float)) and r["rps"] > 0
rows = ["| pair (base -> new) | rounds | ratio new/base | ci90 | verdict | errors (base / new) | runs in TCP pressure |", "|---|---|---|---|---|---|---|"]
for a, b, label in (("off", "on", "fd-admission off -> on"), ("off", "off2", "A/A: off -> off (second copy of the binary)"), ("off2", "on", "off (copy) -> on")):
    reps = sorted(i for i in set(by[a]) & set(by[b]) if ok(by[a][i]) and ok(by[b][i]))
    c = stats.compare([by[a][i]["rps"] for i in reps], [by[b][i]["rps"] for i in reps], higher_better=True)
    ci = c.get("ci90") or c.get("ci")
    err = (sum(by[a][i].get("errors", 0) for i in reps), sum(by[b][i].get("errors", 0) for i in reps))
    pr = sum(by[x][i].get("tcp_press", 0) > 0 for i in reps for x in (a, b))
    rows.append(f"| {label} | {len(reps)} | {c['ratio']} | {ci[0]} to {ci[1]} | {c['verdict']} | {err[0]} / {err[1]} | {pr} |" if ci else f"| {label} | {len(reps)} | {c} |")
med = {v: stats.median([r["rps"] for r in by[v].values() if ok(r)]) for v in by}
rows.append("")
rows.append("median rps: " + ", ".join(f"{v} {m}" for v, m in sorted(med.items())))
print("\n".join(rows))
if "--check" in sys.argv:
    note = open(sys.argv[sys.argv.index("--check") + 1]).read()
    miss = [r for r in rows if r and r not in note]
    print(f"g40table --check: {len(rows)} rows, {len(miss)} not in the note"); sys.exit(1 if miss else 0)
