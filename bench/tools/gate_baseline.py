#!/usr/bin/env python3
"""G20 (60.78): the compat inventory of a gate against a stored baseline of the round, every gate.

A SKIP line inside a step that passed was silent before: the gate counted only step statuses. Now the gate compares
(1) the inventory of its compat run (python3 -m wispsuite.inventory; a step that passed only on the rerun counts with its
rerun's entry, as gate.py's rerun rule does) with the baseline inventory: a LOSS of `inventory --diff` (a step missing, a
status not the same, fewer PASS lines or tests, more SKIP lines or ignored tests) is BROKEN; and
(2) every SKIP line of a compat log with the baseline's list of expected SKIP lines (step, exact text, why): a SKIP line
that is not on the list is BROKEN, also when the counts are equal (another case skips). An expected line that did not
appear is reported (more was run), not an error.
The baseline is per host class and compat mode ("laptop-fast", "farm-vm-fast", ...): the class is $GATE_HOST_CLASS (default
"laptop"; bench/tools/farm.py sets farm-vm) + "-" + the gate's --compat-mode. No baseline for the class: BROKEN.
More PASS lines than the baseline (a branch added tests) are listed as "more"; refresh the baseline at the merge.

usage: bench/tools/gate_baseline.py write GATE_OUT --class CLASS [--file F] [--why STEP=TEXT ...] [--allow-broken G,...]
                                                                                                  (from an OK gate)
       bench/tools/gate_baseline.py check GATE_OUT --class CLASS [--file F]
F default: bench/tools/gate-baseline.json. `write` keeps the "why" of a SKIP line that the file had already."""
import argparse, json, os, re, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # bench/: the wispsuite package
from wispsuite import inventory as INV  # noqa: E402

FILE = os.path.join(HERE, "gate-baseline.json")


def safe(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def log_name(step):
    return step.replace(" ", "_").replace("/", "_") + ".log"  # the file name wispsuite gives a step's log


def collect(out, reruns):
    """(inventory, [(step, SKIP line)]) of the compat run in OUT; a rerun that passed stands for its step"""
    inv = INV.inventory(os.path.join(out, "compat"))
    logs = {s: os.path.join(out, "compat", log_name(s)) for s in inv["steps"]}
    for r in reruns or []:
        if r.get("rerun_status") != "PASS":
            continue
        d = os.path.join(out, "compat-rerun", safe(r["step"]))
        one = INV.inventory(d)["steps"].get(r["step"])
        if one is None:
            raise ValueError(f"the rerun of {r['step']} has no record of the step")
        inv["steps"][r["step"]] = one
        logs[r["step"]] = os.path.join(d, log_name(r["step"]))
    skips = []
    for s in sorted(logs):
        try:
            with open(logs[s], errors="replace") as f:
                skips += [(s, l.rstrip("\n").strip()) for l in f if l.startswith("SKIP")]
        except OSError:
            pass
    return inv, skips


def reruns_of(out):
    try:
        return json.load(open(os.path.join(out, "VERDICT.json"))).get("reruns") or []
    except (OSError, ValueError):
        return []


def check(base, cls, inv, skips):
    """-> (ok, detail, report lines)"""
    b = (base.get("classes") or {}).get(cls)
    if b is None:
        return False, f"no baseline for host class {cls} in the baseline file (classes: {', '.join(sorted(base.get('classes') or {})) or 'none'})", []
    loss, more = INV.diff({"steps": b["inventory"]}, inv)
    want = {(x["step"], x["line"]) for x in b["skip_lines"]}
    seen = set(skips)
    new = [x for x in skips if x not in want]
    gone = sorted(want - seen)
    lines = [f"LOSS {s}: {w}" for s, w in loss] + [f"NEW SKIP {s}: {l}" for s, l in new] + [f"expected SKIP not seen (more ran) {s}: {l}" for s, l in gone] \
        + [f"more {s}: {w}" for s, w in more]
    detail = (f"class {cls}: {len(loss)} inventory loss(es), {len(new)} SKIP line(s) not in the baseline, {len(skips) - len(new)} expected SKIP line(s), "
              f"{len(gone)} expected not seen, {len(more)} more")
    if loss or new:
        detail += ": " + "; ".join(lines[:4])[:400]
    return not loss and not new, detail, lines


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=("write", "check"))
    ap.add_argument("out")
    ap.add_argument("--class", dest="cls", required=True)
    ap.add_argument("--file", default=FILE)
    ap.add_argument("--why", action="append", default=[], help="STEP=TEXT: why the SKIP lines of STEP are expected (write)")
    ap.add_argument("--allow-broken", default="", help="write: gates of GATE_OUT that may be BROKEN (comma list; the first baseline: baseline)")
    a = ap.parse_args()
    out = os.path.abspath(a.out)
    inv, skips = collect(out, reruns_of(out))
    try:
        base = json.load(open(a.file))
    except FileNotFoundError:
        base = {"classes": {}}
    if a.what == "check":
        ok, detail, lines = check(base, a.cls, inv, skips)
        print("\n".join(lines))
        print(("OK " if ok else "BROKEN ") + detail)
        sys.exit(0 if ok else 1)
    v = json.load(open(os.path.join(out, "VERDICT.json")))
    if not a.cls.endswith("-" + str(v.get("compat_mode"))) or a.cls.rsplit("-", 1)[0] != v.get("host_class", "laptop"):
        sys.exit(f"gate_baseline: --class {a.cls} is not the class of this gate (host class {v.get('host_class', 'laptop')}, compat mode {v.get('compat_mode')})")
    broken = sorted(g["gate"] for g in v.get("gates", []) if g["status"] != "OK")
    allowed = [x for x in a.allow_broken.split(",") if x]
    if any(b not in allowed for b in broken) or not v.get("complete") or v.get("experiment") or "compat" in broken:
        sys.exit(f"gate_baseline: {out} is not a complete OK merge gate (verdict {v.get('verdict')}, complete {v.get('complete')}, broken {broken}); "
                 "no baseline from it (--allow-broken names gates that may be BROKEN, e.g. baseline for the first one; never compat)")
    old = {(x["step"], x["line"]): x.get("why") for x in ((base.get("classes") or {}).get(a.cls) or {}).get("skip_lines", [])}
    why = dict(w.split("=", 1) for w in a.why)
    miss = [f"{s}: {l}" for s, l in skips if not (old.get((s, l)) or why.get(s))]
    if miss:
        sys.exit("gate_baseline: every expected SKIP line needs a reason (--why STEP=TEXT): " + "; ".join(miss))
    base.setdefault("classes", {})[a.cls] = {
        "from": out, "head": v["head"], "binary_md5": v["binary_md5"], "gate_broken": broken, "written": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "skip_lines": [{"step": s, "line": l, "why": old.get((s, l)) or why[s]} for s, l in skips],
        "inventory": {k: {kk: vv for kk, vv in st.items()} for k, st in sorted(inv["steps"].items())}}
    with open(a.file, "w") as f:
        json.dump(base, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"gate_baseline: class {a.cls}: {len(inv['steps'])} steps, {len(skips)} expected SKIP line(s) -> {a.file}")


if __name__ == "__main__":
    main()
