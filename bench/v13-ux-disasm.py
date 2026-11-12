#!/usr/bin/env python3
"""60.60 the full per-function compare lists of bench/tools/disasm_norm.py (which prints the first 20 of each) as JSON.

usage: v13-ux-disasm.py OUT.json NAME=BINARY NAME=BINARY [NAME=BINARY ...]
Compares every later binary with every earlier one (--fold finalwisp::worker, as the project rule says) and writes
{"A vs B": {"functions": [nA, nB], "only_a": [...], "only_b": [...], "differs": [...], "collisions": n}, ...,
 "md5": {NAME: md5}}."""
import hashlib, itertools, json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools"))
import disasm_norm  # noqa: E402

out, pairs = sys.argv[1], [a.split("=", 1) for a in sys.argv[2:]]
fold = disasm_norm.make_fold(["finalwisp::worker"])
fs = {name: disasm_norm.funcs(path, fold) for name, path in pairs}
res = {"md5": {name: hashlib.md5(open(path, "rb").read()).hexdigest() for name, path in pairs}}
for (na, _), (nb, _) in itertools.combinations(pairs, 2):
    (a, ca), (b, cb) = fs[na], fs[nb]
    res[f"{na} vs {nb}"] = {
        "functions": [len(a), len(b)],
        "only_a": sorted(set(a) - set(b)),
        "only_b": sorted(set(b) - set(a)),
        "differs": [k for k in sorted(set(a) & set(b)) if a[k] != b[k]],
        "collisions": len(set(ca) | set(cb)),
    }
    r = res[f"{na} vs {nb}"]
    print(f"{na} vs {nb}: functions {len(a)} / {len(b)}, only in {na} {len(r['only_a'])}, only in {nb} {len(r['only_b'])}, "
          f"bodies differ {len(r['differs'])}, fold collisions {r['collisions']}")
json.dump(res, open(out, "w"), indent=1)
