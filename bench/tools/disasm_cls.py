#!/usr/bin/env python3
"""Classify the functions that differ between two release binaries (60.58; uses disasm_norm.py).
usage: bench/tools/disasm_cls.py BASE NEW [--show NAME]
A differing function is OFFSET-ONLY when the two bodies are equal after every number (immediates, displacements,
+offsets of jump / call targets) is replaced by one token; RENAME-ONLY when they are equal after that and after the
names of call / jump targets outside the function are replaced too (identical code folding gives one body several
names: the pairs are printed, check that they are the same generic function over types of one size); else LOGIC. Prints the counts and every LOGIC function and
every function only in one binary, grouped: finalwisp::worker (the per-byte paths live here), other finalwisp, the rest
(std / libc: ICF renames and PLT shifts)."""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import disasm_norm as D

a_path, b_path = sys.argv[1], sys.argv[2]
show = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--show" else None
fold = D.make_fold(["finalwisp::worker"])
(a, _), (b, _) = D.funcs(a_path, fold), D.funcs(b_path, fold)
NUM = re.compile(r"-?0x[0-9a-f]+|\$-?[0-9]+|\+0x[0-9a-f]+>")


def loose(bodies):
    return [NUM.sub("N", x) for x in bodies]


TARGET = re.compile(r"^(call|jmp|j[a-z]+) <(.*)>$")


def renamed(k, xa, xb):
    """the (base, new) target-name pairs if the bodies differ only in call / jump target names, else None"""
    pairs = set()
    if len(xa) != len(xb):
        return None
    for ba, bb in zip(loose(xa), loose(xb)):
        la, lb = ba.splitlines(), bb.splitlines()
        if len(la) != len(lb):
            return None
        for x, y in zip(la, lb):
            if x == y:
                continue
            ma, mb = TARGET.match(x), TARGET.match(y)
            if not (ma and mb and ma.group(1) == mb.group(1)):
                return None
            pairs.add((ma.group(2), mb.group(2)))
    return pairs


def group(name):
    if "finalwisp::worker" in name:
        return "worker"
    if "finalwisp::" in name:
        return "finalwisp"
    return "other"


diff = [k for k in sorted(set(a) & set(b)) if a[k] != b[k]]
out = {}
RENAMES = {}
for k in diff:
    kind = "OFFSET-ONLY" if loose(a[k]) == loose(b[k]) else "LOGIC"
    if kind == "LOGIC":
        pairs = renamed(k, a[k], b[k])
        if pairs:
            kind = "RENAME-ONLY"
            RENAMES.setdefault(k, pairs)
    out.setdefault((group(k), kind), []).append(k)
print(f"functions base {len(a)} new {len(b)}; differ {len(diff)}; only in base {len(set(a) - set(b))}; only in new {len(set(b) - set(a))}")
for g in ("worker", "finalwisp", "other"):
    for kind in ("OFFSET-ONLY", "RENAME-ONLY", "LOGIC"):
        v = out.get((g, kind), [])
        print(f"{g:9s} {kind:11s} {len(v)}")
        if kind == "LOGIC" or g == "worker":
            for k in v:
                print("    ", k[:200])
                for x, y in sorted(RENAMES.get(k, ())):
                    print("         target", x[:120], "->", y[:120])
for side, s in (("only in base", set(a) - set(b)), ("only in new", set(b) - set(a))):
    for g in ("worker", "finalwisp"):
        v = sorted(k for k in s if group(k) == g)
        print(f"{side}, {g}: {len(v)}")
        for k in v:
            print("    ", k[:200])
if show:
    import difflib
    for k in diff:
        if show in k:
            print("---", k)
            for l in difflib.unified_diff("\n=====\n".join(a[k]).splitlines(), "\n=====\n".join(b[k]).splitlines(), "base", "new", lineterm="", n=3):
                print(l)
