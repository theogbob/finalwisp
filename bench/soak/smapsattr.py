#!/usr/bin/env python3
"""60.78 G05 attribution: which anonymous mappings of a soak server grew, from smapsmon.py's samples.
usage: smapsattr.py RUN.smaps.jsonl [--samples RUN/samples.csv] [--block 12] [--check NOTE.md]
--samples adds the block tables (and the per-arena state from --judge-from H, default 24): per-arena high-water per --block hours (60.78 G05 48 h: does each arena stop growing?).
Mapping classes (by perms, name and the neighbour mapping): [heap]; glibc thread arena (a rw-p map followed by its ---p
reserve, 64 MiB together); sigaltstack / thread stack (rw-p after a 4 KiB guard); 4 MiB multiples (pool chunks);
other rw anon (large malloc mmaps above the 16 KiB mmap threshold, and maps the kernel merged); [stack].
Per server and class: the minimum Anonymous KiB of each 3-h bucket after the first hour, its Theil-Sen slope (KiB/h),
and for the arenas the slope of the first and the second half. Samples every 600 s are not at the quiet floors of the
soak's 10-s samples: this names the class that grows, the soak's analyze.py keeps the pass rule."""
import json, sys
from collections import defaultdict

def classify(maps):
    ms = sorted(maps, key=lambda m: int(m[0], 16)); out = []
    for i, m in enumerate(ms):
        a, b, perm, name, size, rss, anon = m
        prev = ms[i - 1] if i else None; nxt = ms[i + 1] if i + 1 < len(ms) else None
        if name: c = name
        elif perm != "rw-p": c = "reserve " + perm
        elif nxt and nxt[2] == "---p" and nxt[0] == b and size + nxt[4] == 65536: c = "glibc thread arena"
        elif prev and prev[2] == "---p" and prev[1] == a and prev[4] == 4: c = "sigaltstack" if size <= 16 else "thread stack"
        elif size % 4096 == 0 and size >= 4096: c = "4 MiB multiples (pool chunks)"
        else: c = "other rw anon (large malloc mmaps, merged maps)"
        out.append((c, m))
    return out

def theil(x, y):
    s = sorted((y[j] - y[i]) / (x[j] - x[i]) for i in range(len(x)) for j in range(i + 1, len(x)) if x[j] != x[i])
    return s[len(s) // 2] if s else float("nan")


def arena_blocks(S, samples_csv=None, block_h=12):
    """per server: each arena's high-water (max Anonymous KiB) per BLOCK_H block, how many arenas still grew in each
    block, the summed arena growth per hour, and (with the soak's samples.csv) the Theil-Sen slope of its 30-min anon
    floors per block. An arena is keyed by its start address (glibc does not move an arena)."""
    out = []
    floors = {}
    if samples_csv:
        import csv
        for r in csv.DictReader(open(samples_csv)):
            m = float(r["min"])
            if m < 60: continue
            for s in ("A", "B"):
                v = r.get(f"{s}_anon_kib")
                if v not in (None, ""):
                    k = (s, int(m // 30)); floors[k] = min(floors.get(k, 1e18), float(v))
    t0 = min(s["t"] for s in S)
    for srv in sorted({s["server"] for s in S}):
        hw = defaultdict(lambda: defaultdict(int))  # arena -> block -> high-water
        ns = defaultdict(int)
        for s in S:
            if s["server"] != srv: continue
            blk = int((s["t"] - t0) / 3600 // block_h); ns[blk] += 1
            for c, m in classify(s["maps"]):
                if c == "glibc thread arena":
                    hw[m[0]][blk] = max(hw[m[0]][blk], m[6])
        blocks = sorted({b for a in hw.values() for b in a})
        for b in blocks:
            grew = [a for a in hw if b - 1 in hw[a] and hw[a].get(b, 0) > hw[a][b - 1]] if b else []
            gsum = sum(hw[a].get(b, 0) - hw[a].get(b - 1, 0) for a in hw if b - 1 in hw[a]) if b else None
            total = sum(a.get(b, 0) for a in hw.values())
            fl = sorted((k[1], v) for k, v in floors.items() if k[0] == srv and b * block_h * 2 <= k[1] < (b + 1) * block_h * 2)
            fs = theil([k / 2 + 0.25 for k, _ in fl], [v for _, v in fl]) if len(fl) > 2 else None
            out.append(f"| {srv} | {b * block_h}-{(b + 1) * block_h} h | {ns[b]} | {len(hw)} | {total} | "
                       f"{'-' if not b else f'{len(grew)} of {len(hw)}'} | {'-' if gsum is None else f'{gsum:+d} ({gsum / block_h:+.1f}/h)'} | "
                       f"{'-' if fs is None else f'{fs:+.0f}'} |")
    head = ["| server | block | samples (600 s) | arenas | sum of arena high-waters KiB | arenas whose high-water rose over the block before | arena growth over the block before KiB | anon floor slope in the block KiB/h (30-min minima, Theil-Sen) |",
            "|---|---|---|---|---|---|---|---|"]
    return head + out


def arena_states(S, block_h=12, judge_from_h=24):
    """per server and arena: the high-water per BLOCK_H block (full blocks only: a block with fewer than
    3/4 of its 600-s samples is left out), and the state from JUDGE_FROM_H on: "flat" = no block from there on has a
    higher high-water than the block before it, else "still growing (+KiB)". G05 rule (owner, 2026-11-17): CLOSED if
    every arena is flat in the second 24 h."""
    t0 = min(s["t"] for s in S); per_block = block_h * 6
    rows = []
    for srv in sorted({s["server"] for s in S}):
        hw = defaultdict(lambda: defaultdict(int)); ns = defaultdict(int)
        for s in S:
            if s["server"] != srv: continue
            b = int((s["t"] - t0) / 3600 // block_h); ns[b] += 1
            for c, m in classify(s["maps"]):
                if c == "glibc thread arena": hw[m[0]][b] = max(hw[m[0]][b], m[6])
        full = [b for b in sorted(ns) if ns[b] >= 0.75 * per_block]
        jb = [b for b in full if b * block_h >= judge_from_h]
        head = f"| server | arena (start) | high-water KiB per {block_h} h block: " + " / ".join(f"{b * block_h}-{(b + 1) * block_h} h" for b in full) + f" | from {judge_from_h} h |"
        rows += ["", head, "|---|---|---|---|"]
        nflat = 0
        for a in sorted(hw):
            v = [hw[a].get(b, 0) for b in full]
            rise = sum(max(0, hw[a].get(b, 0) - hw[a].get(b - 1, 0)) for b in jb if b - 1 in full)
            st = "flat" if rise == 0 else f"still growing (+{rise})"
            nflat += rise == 0
            rows.append(f"| {srv} | {a} | {' / '.join(map(str, v))} | {st if jb else 'n/a (no full block yet)'} |")
        rows.append(f"| {srv} | all {len(hw)} arenas | sum " + " / ".join(str(sum(hw[a].get(b, 0) for a in hw)) for b in full) + f" | {nflat} of {len(hw)} flat |" if jb else f"| {srv} | all {len(hw)} arenas | sum " + " / ".join(str(sum(hw[a].get(b, 0) for a in hw)) for b in full) + " | n/a |")
    return rows

S = [json.loads(l) for l in open(sys.argv[1])]
S = [s for s in S if "maps" in s]
t0 = min(s["t"] for s in S)
rows = ["| server | class | maps (first / last sample) | Anonymous KiB, minimum per 3-h bucket after hour 1 | Theil-Sen KiB/h | first half / second half KiB/h |",
        "|---|---|---|---|---|---|"]
for srv in sorted({s["server"] for s in S}):
    ss = [s for s in S if s["server"] == srv]
    per = []
    for s in ss:
        t = defaultdict(int); n = defaultdict(int)
        for c, m in classify(s["maps"]):
            t[c] += m[6]; n[c] += 1
        t["all (smaps_rollup Anonymous)"] = s["rollup"]["Anonymous"]
        per.append(((s["t"] - t0) / 3600, t, n))
    for c in sorted({c for _, t, _ in per for c in t}):
        pts = [(h, t.get(c, 0)) for h, t, _ in per if h >= 1]
        if not any(v for _, v in pts): continue
        b = defaultdict(list)
        for h, v in pts: b[int(h // 3)].append(v)
        ks = sorted(b); mins = [min(b[k]) for k in ks]
        sl = theil([k * 3 + 1.5 for k in ks], mins)
        half = max(h for h, _ in pts) / 2
        f = [(h, v) for h, v in pts if h < half]; s2 = [(h, v) for h, v in pts if h >= half]
        hs = f"{theil(*zip(*f[::3])):.0f} / {theil(*zip(*s2[::3])):.0f}" if c == "glibc thread arena" else "-"
        rows.append(f"| {srv} | {c} | {per[0][2].get(c, '-')} / {per[-1][2].get(c, '-')} | {' '.join(map(str, mins))} | {sl:+.0f} | {hs} |")
if "--samples" in sys.argv:
    blk = int(sys.argv[sys.argv.index("--block") + 1]) if "--block" in sys.argv else 12
    rows += [""] + arena_blocks(S, sys.argv[sys.argv.index("--samples") + 1], blk) + arena_states(S, blk, int(sys.argv[sys.argv.index("--judge-from") + 1]) if "--judge-from" in sys.argv else 24)
print("\n".join(rows))
if "--check" in sys.argv:
    note = open(sys.argv[sys.argv.index("--check") + 1]).read(); miss = [r for r in rows if r and r not in note]
    print(f"smapsattr --check: {len(rows)} rows, {len(miss)} not in the note"); sys.exit(1 if miss else 0)
