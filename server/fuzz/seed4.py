#!/usr/bin/env python3
# 60.78 G04: a variant-4 copy of every worker-stream / worker-wisp seed (first byte: sel % 5 == 4, same level bits)
import os, sys
root = sys.argv[1]
for t in ("worker-stream", "worker-wisp"):
    d = os.path.join(root, t)
    n = 0
    for f in sorted(os.listdir(d)):
        if f.startswith("v4-"):
            continue
        b = open(os.path.join(d, f), "rb").read()
        if len(b) < 2 or b[0] % 5 == 4:
            continue
        cand = [x for x in range(256) if x % 5 == 4 and (x >> 2) & 7 == (b[0] >> 2) & 7]
        if not cand:
            continue
        open(os.path.join(d, "v4-" + f), "wb").write(bytes([cand[0]]) + b[1:])
        n += 1
    print(t, n, "variant-4 copies")
