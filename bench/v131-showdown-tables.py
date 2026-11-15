#!/usr/bin/env python3
"""60.71 (showdown: finalwisp v1.3.1 vs the latest competitors): every table of note 60.71
(internal set) and of the proposed docs/benchmarks.md text (public set), from the raw files. Method = 30.19 (v110-bench):
median of 3 reps; (P k/n) = kernel TCP memory pressure in k of n reps; on the 3.8 GB VPSes the 10x10 bulk rows are
replaced by the 10x2 re-run and shown apart ("dropped").
usage: v131-showdown-tables.py [RAW_DIR] [--check NOTE.md] [--check-public PROPOSAL.md]
RAW_DIR default: an internal note (not published) in the main checkout. Per box dir:
  main.json            the main run (3 reps, servers rotated, one server process per rep)
  main-r3.json         one rep that replaces rep 3 of its servers (the first unit stopped at an OOM kill)
  rerun.json           re-run cells (10x2, echo 1x1, --settle 20): replace the same cells of main
  epx/main.json, epx/rerun.json   part 3: epoxy 9cde724 with tokio-websockets 0.12.3, finalwisp as the anchor
  credit.json          wispurr with 256 credits (WispMark settings), both builds
  oom*.txt, epx/oom.txt   kernel OOM lines of the runs
A case missing from a run that exists = the server died before it (crash or OOM kill): a failed run of that case.
The published run's cells: an internal note (not published)
--check / --check-public: every table block of that set must be in the file, byte for byte; exit 1 otherwise."""
import json, os, re, statistics, sys

argv = sys.argv[1:]
opt = lambda k: argv[argv.index(k) + 1] if k in argv else None
CHECK, CHECKP = opt("--check"), opt("--check-public")
pos = [a for i, a in enumerate(argv) if not a.startswith("--") and (i == 0 or not argv[i - 1].startswith("--"))]
RAW = pos[0] if pos else "an internal note (not published)"
PUB = os.path.join(RAW, "../v110-bench")
BOXES = {"194": ("VPS A (VPS2, EPYC Milan, distribution TCP defaults, cubic)", True),
         "187": ("VPS B (VPS1, EPYC Rome, 16 MiB TCP buffers, BBR)", True),
         "gold3": ("gold3 (2 x Xeon Gold 6138, 80 threads, container)", False)}
EPX = "epoxy-9cde724-lock0123"
ORDER = ["finalwisp", "epoxy", EPX, "wispurr", "wisp-js", "python", "wispurr-2afbad2", "fw110"]
NAMES = {"finalwisp": "finalwisp", "epoxy": "epoxy-server", EPX: "epoxy-server, tokio-websockets 0.12.3",
         "wispurr": "wispurr", "wisp-js": "wisp-js", "python": "wisp-server-python", "wispurr-2afbad2": "wispurr 2afbad2 (old)", "fw110": "finalwisp 1.1.0 (ref)"}
OTHERS = ["epoxy", EPX, "wispurr", "wisp-js", "python"]  # the old wispurr build and finalwisp 1.1.0 are reference columns, never an "other"
CASE_ORDER = {"upload": 0, "download": 1, "echo": 2, "rr": 3, "churn": 4}
DROP = {("upload", 10, 10), ("download", 10, 10), ("echo", 10, 10)}
LABEL = {"upload": "upload", "download": "download", "echo": "echo", "rr": "request/response", "churn": "new stream per request"}
UNIT = {"upload": "MiB/s", "download": "MiB/s", "echo": "MiB/s each way", "rr": "req/s", "churn": "streams/s"}
DIED = ("server exited", "server died before this case")


def metric(t):
    return "rps" if t in ("rr", "churn") else ("mib_s_up" if t == "upload" else "mib_s_down")


def fmt(v):
    return f"{v:,.0f}" if v >= 100 else f"{v:,.1f}"


def ratio(a, b):
    if a is None or b is None:
        return "-"
    if b == 0:
        return "∞" if a > 0 else "-"
    return f"{a / b:.2f}"


def korder(k):
    return (CASE_ORDER[k[0]], k[1] * k[2])


def by_cell(rows):
    out = {}
    for r in rows:
        if "conns" in r:
            out.setdefault((r["server"], (r["test"], r["conns"], r["streams"])), []).append(r)
    return out


def load_run(d, main="main.json", r3=None, rerun="rerun.json"):
    p = os.path.join(d, main)
    if not os.path.exists(p):
        return None, {}
    m = json.load(open(p))
    rows = m["results"]
    if r3 and os.path.exists(os.path.join(d, r3)):  # one rep that replaces rep 3 (index 2) of its servers
        x = json.load(open(os.path.join(d, r3)))["results"]
        srv = {r["server"] for r in x}
        rows = [r for r in rows if not (r["server"] in srv and r["rep"] == 2)] + [{**r, "rep": 2} for r in x]
    cells = by_cell(rows)
    cases = {k for _, k in cells}
    reps = {}
    for r in rows:
        reps.setdefault(r["server"], set()).add(r["rep"])
    for s, rs in reps.items():
        for k in cases:
            have = {r["rep"] for r in cells.get((s, k), [])}
            for rep in sorted(rs - have):
                cells.setdefault((s, k), []).append({"server": s, "rep": rep, "error": "server died before this case"})
    rp = os.path.join(d, rerun)
    if os.path.exists(rp):
        cells.update(by_cell(json.load(open(rp))["results"]))  # replace, not merge
    return m["meta"], cells


def cell(cells, s, key):
    rs = cells.get((s, key), [])
    if not rs:
        return None
    ok = [r for r in rs if "error" not in r]
    died = sum(1 for r in rs if r.get("error") in DIED or (r.get("error") is None and r.get("server_alive") is False))
    base = {"n": len(ok), "failed": len(rs) - len(ok), "died": died, "runs": len(rs)}
    if not ok:
        return {**base, "v": None}
    m = metric(key[0])
    fr = [r.get("tcp_press_frac") for r in ok if r.get("tcp_press_frac") is not None]
    return {**base, "v": statistics.median(r[m] for r in ok), "vals": [r[m] for r in ok],
            "errors": sum(r.get("errors", 0) for r in ok), "invalid": sum(bool(r.get("invalid_tcp_mem")) for r in ok),
            "rss": statistics.median(r["server_rss_mib"] for r in ok), "peak": max(r["server_peak_mib"] for r in ok),
            "frac_max": max(fr) if fr else None, "press_ms": sum(r.get("tcp_press_ms") or 0 for r in ok),
            "tcp_peak": max((r.get("tcp_mem_pages_peak") or 0) for r in ok)}


def show(c, public):
    if c is None:
        return "-"
    word = "crashed" if public else "failed"
    if c["v"] is None:
        return f"{word} ({c['failed']}/{c['runs']} runs)"
    x = fmt(c["v"])
    if c["errors"]:
        x += f" ({c['errors']} err)"
    if c["invalid"]:
        x += f" (P {c['invalid']}/{c['n']})"
    if c["failed"]:
        x += f" ({c['failed']} run{'s' if c['failed'] > 1 else ''} {word})"
    elif c["died"]:  # the cell ran, but the server was dead at its end
        x += f" (server {'crashed' if public else 'died'} in {c['died']} run{'s' if c['died'] > 1 else ''})"
    return x


def kills(d):
    out = []
    for root, _, files in os.walk(d):
        for f in files:
            if re.fullmatch(r"oom\d?\.txt", f):
                for line in open(os.path.join(root, f)):
                    m = re.search(r"Killed process \d+ \(([^)]+)\).*anon-rss:(\d+)kB", line)
                    if m:
                        out.append((m.group(1), int(m.group(2)) / 1024))
    return out


def block(head, rows):
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(r) + " |" for r in rows]


def box_tables(box, public):
    label, drop = BOXES[box]
    d = os.path.join(RAW, box)
    meta, cells = load_run(d, r3="main-r3.json")
    _, ecells = load_run(os.path.join(d, "epx"))
    for (s, k), rs in ecells.items():
        if s == EPX:
            cells[(s, k)] = rs
    cases = sorted({k for _, k in cells}, key=korder)
    main = [k for k in cases if not (drop and k in DROP)]
    dropped = [k for k in cases if drop and k in DROP]
    servers = [s for s in ORDER if any(x == s for x, _ in cells) and (not public or s not in ("wispurr-2afbad2", "fw110"))]
    oth = [s for s in OTHERS if s in servers]
    kl = kills(d)

    def name(k, unit=True):
        t, c, s = k
        sh = "1 stream" if c * s == 1 else f"{c} conns x {s} streams"
        return f"{LABEL[t]}, {sh}" + (f" ({UNIT[t]})" if unit else "")

    def mem(s, f):
        v = [cell(cells, s, k)[f] for k in main if cell(cells, s, k) and cell(cells, s, k)["v"] is not None]
        return max(v) if v else None

    def died(s):  # a server that died in a run: its memory rows miss the rest of that run, so they are no comparison
        return any(c["failed"] or c["died"] for k in main + dropped for c in [cell(cells, s, k)] if c)

    def values(keys, with_mem):
        rows = [[name(k)] + [show(cell(cells, s, k), public) for s in servers] for k in keys]
        if with_mem:
            for f, lab in (("rss", "RSS after the case, largest (MiB, median)"), ("peak", "peak RSS, VmHWM (MiB, max)")):
                row = [lab]
                for s in servers:
                    m = mem(s, f)
                    x = fmt(m) if m else "-"
                    k_ = [mib for p, mib in kl if p == s]
                    if f == "peak" and k_:
                        x += f" (OOM-killed at {fmt(max(k_))})"
                    elif m and s != "finalwisp" and died(s):
                        x += f" (runs {'crashed' if public else 'died'})"
                    row.append(x)
                rows.append(row)
        return block(["case"] + [NAMES[s] for s in servers], rows)

    def ratios(keys, with_mem):
        rows = []
        for k in keys:
            fw = cell(cells, "finalwisp", k)
            fwv = fw["v"] if fw else None
            nums = {s: cell(cells, s, k)["v"] for s in oth if cell(cells, s, k) and cell(cells, s, k)["v"] is not None}
            best = max(nums.values()) if nums else None
            rows.append([name(k, False), ratio(fwv, best)] + [ratio(fwv, nums.get(s)) for s in oth])
        if with_mem:
            for f, lab in (("rss", "RSS after the case, largest"), ("peak", "peak RSS, VmHWM")):
                o = {s: mem(s, f) for s in oth if mem(s, f) and not died(s)}
                rows.append([lab, ratio(min(o.values()), mem("finalwisp", f)) if o else "-"] + [ratio(o.get(s), mem("finalwisp", f)) for s in oth])
        return block(["case", "vs best other"] + [f"vs {NAMES[s]}" for s in oth], rows)

    out = [values(main, True), ratios(main, True)]
    if dropped:
        out += [values(dropped, False), ratios(dropped, False)]
    if public:
        return label, meta, out
    # kernel TCP memory per cell
    rows = []
    for k in main + dropped:
        row = [f"{k[0]} {k[1]}x{k[2]}"]
        for s in servers:
            c = cell(cells, s, k)
            row.append("-" if c is None or c["v"] is None else f"{c['frac_max'] if c['frac_max'] is not None else '-'} / {c['tcp_peak']:,} / {c['press_ms']}")
        rows.append(row)
    out.append(block(["case"] + [NAMES[s] for s in servers], rows))
    # finalwisp 1.1.0 as a reference column of the same rotated run (median of 3, not a verdict)
    if "fw110" in servers:
        rows = []
        for k in main + dropped:
            a, b = cell(cells, "finalwisp", k), cell(cells, "fw110", k)
            if a and b and a["v"] is not None and b["v"] is not None:
                rows.append([f"{k[0]} {k[1]}x{k[2]}", show(a, False), show(b, False), ratio(a["v"], b["v"])])
        for f, lab in (("rss", "RSS after the case, largest (MiB)"), ("peak", "peak RSS, VmHWM (MiB)")):
            a, b = mem("finalwisp", f), mem("fw110", f)
            rows.append([lab, fmt(a) if a else "-", fmt(b) if b else "-", ratio(a, b)])
        out.append(block(["case", "finalwisp 1.3.1", "finalwisp 1.1.0 (same run)", "1.3.1 / 1.1.0"], rows))
    # the epoxy part-3 run: finalwisp there / finalwisp in the main run (same box, 25-40 min later)
    fe = {k: cell(ecells, "finalwisp", k) for k in cases}
    if any(fe.values()):
        rows = []
        for k in main + dropped:
            a, b = fe.get(k), cell(cells, "finalwisp", k)
            if a and b and a["v"] is not None and b["v"] is not None:
                rows.append([f"{k[0]} {k[1]}x{k[2]}", show(a, False), show(b, False), ratio(a["v"], b["v"])])
        out.append(block(["case", "finalwisp, part 3", "finalwisp, main run", "part 3 / main"], rows))
    # against the published run (30.19: finalwisp v1.1.0 and the competitor builds of that day)
    pp = os.path.join(PUB, box, "cells.json")
    if os.path.exists(pp):
        pub = json.load(open(pp))
        pairs = [("finalwisp", "finalwisp"), ("epoxy", "epoxy"), ("epoxy", EPX), ("wispurr", "wispurr"),
                 ("wisp-js", "wisp-js"), ("python", "python"), ("wispurr", "wispurr-2afbad2")]
        rows = []
        for k in main + dropped:
            ck = f"{k[0]}:{k[1]}:{k[2]}"
            row = [f"{k[0]} {k[1]}x{k[2]}"]
            for ps, ns in pairs:
                p, c = pub["cells"].get(f"{ps}|{ck}"), cell(cells, ns, k)
                if not p or c is None or c["v"] is None:
                    row.append("-")
                    continue
                flag = "" if (not c["invalid"] and not p["invalid"]) else " (P)"
                row.append(f"{fmt(c['v'])} / {fmt(p['v'])} = {ratio(c['v'], p['v'])}{flag}")
            rows.append(row)
        out.append(block(["case", "finalwisp 1.3.1 / 1.1.0", "epoxy 9cde724 / 0c11678-lock0123", "epoxy 9cde724-lock0123 / 0c11678-lock0123",
                          "wispurr 0e0fdb1 / 2afbad2", "wisp-js 0.5.3 / 0.5.0", "python 0.11.0 / 0.9.0", "wispurr 2afbad2 / 2afbad2"], rows))
    # wispurr credit-stall check (256 credits, WispMark settings)
    cp = os.path.join(d, "credit.json")
    if os.path.exists(cp):
        cr = by_cell(json.load(open(cp))["results"])
        rows = []
        for k in sorted({k for _, k in cr}, key=korder):
            row = [f"{k[0]} {k[1]}x{k[2]}"]
            for s in ("wispurr-wispmark", "wispurr-2afbad2-wispmark"):
                rs = cr.get((s, k), [])
                vals = [r[metric(k[0])] for r in rs if "error" not in r]
                row += [", ".join(fmt(v) for v in vals) + (f" ({len(rs) - len(vals)} failed)" if len(rs) > len(vals) else ""), show(cell(cr, s, k), False)]
            rows.append(row)
        out.append(block(["case (256 credits)", "wispurr 0e0fdb1: runs", "median", "wispurr 2afbad2: runs", "median"], rows))
    return label, meta, out


def extra_tables():
    """compat report mode per server (laptop, wisp-js client 0.5.0) and the v2 handshake probe"""
    out = []
    # every server's compat dir (labels = registry names), then the parent's wispurr runs of 2026-11-15
    cdir = os.path.join(RAW, "compat")
    comp = [(n, os.path.join("compat", n)) for n in sorted(os.listdir(cdir)) if os.path.isdir(os.path.join(cdir, n))]
    comp += [("wispurr", "../pipeline/parent/wispurr-0e0fdb1/new"), ("wispurr-2afbad2", "../pipeline/parent/wispurr-0e0fdb1/old")]
    steps = ["wispjs", "wispjs-udp", "udp", "adversarial", "epoxy-udp-burst"]
    rows = []
    for lab, p in comp:
        f = os.path.join(RAW, p, "results.json")
        if not os.path.exists(f):
            continue
        st = {s["step"]: s for s in json.load(open(f))["steps"]}
        row = [lab]
        for s in steps:
            x = st.get(s)
            row.append("-" if x is None else x["status"] + (f" ({len(x.get('fail_lines') or [])} FAIL lines)" if x["status"] != "PASS" and x.get("fail_lines") else ""))
        rows.append(row)
    out.append(block(["server (compat report mode)"] + steps, rows))
    vp = os.path.join(RAW, "v2probe.jsonl")
    if os.path.exists(vp):
        rows = []
        for line in open(vp):
            d = json.loads(line)
            rows.append([d["server"], d.get("status", "-").replace("HTTP/1.1 ", ""), str(d.get("sec_websocket_protocol")),
                         d.get("first_packet", "-") + (f" {d['info_version']}" if d.get("info_version") else ""), "yes" if d.get("v2_per_spec") else "NO"])
        out.append(block(["server", "status", "Sec-WebSocket-Protocol answer", "first packet", "v2 as the spec says"], rows))
    return out


def memstep_tables():
    """memstep.jsonl (bench/v131-memstep.py, laptop, counted): per release and --threads, median of the runs"""
    p = os.path.join(RAW, "memstep.jsonl")
    if not os.path.exists(p):
        return []
    by = {}
    for line in open(p):
        d = json.loads(line)
        by.setdefault((d["bin"], d["threads"]), {}).setdefault(d["run"], {})[d["step"]] = d
    rel = sorted({b for b, _ in by}, key=lambda b: [int(x) for x in b.split("-")[1].split(".")])
    ths = sorted({t for _, t in by})
    med = lambda xs: statistics.median(xs) if xs else None
    f = lambda v: "-" if v is None else f"{v:.1f}"
    rows = []
    for b in rel:
        for t in ths:
            runs = by.get((b, t), {})
            idle = [r["idle"]["rss_mib"] for r in runs.values() if "idle" in r]
            last = [r["echo:10:10"] for r in runs.values() if "echo:10:10" in r and r["echo:10:10"].get("hwm_mib") is not None]
            bad = sum(1 for r in runs.values() for s in r.values() if s.get("error") or s.get("errors") or s.get("alive") is False)
            hw = [x["hwm_mib"] for x in last]
            rows.append([b, str(t), str(len(runs)), f(med(idle)), f(med([x["rss_mib"] for x in last])), f(med(hw)),
                         (f"{min(hw):.1f}-{max(hw):.1f}" if hw else "-"), str(bad)])
    out = []
    sp = os.path.join(RAW, "smaps_idle.jsonl")
    if os.path.exists(sp):  # one idle sample per release and thread count: /proc/PID/smaps_rollup 1 s after start
        rows = [[d["bin"], str(d["threads"]), str(d["rss_kb"]), str(d["anon_kb"]), str(d["file_kb"]), str(d["size_kb"])]
                for d in map(json.loads, open(sp))]
        out.append(block(["release", "--threads", "Rss kB", "Anonymous kB", "file-backed kB", "binary size kB"], rows))
    return [block(["release", "--threads", "runs", "RSS idle (MiB, median)", "RSS after echo 10x10 (MiB, median)",
                   "VmHWM at the end (MiB, median)", "VmHWM min-max", "runs with errors"], rows)] + out


def main():
    sets = {False: [], True: []}
    for box in BOXES:
        if os.path.exists(os.path.join(RAW, box, "main.json")):
            for pub in (False, True):
                sets[pub].append(box_tables(box, pub))
    for title, pub in (("INTERNAL (note 60.71)", False), ("PUBLIC (proposal)", True)):
        print(f"===== {title}")
        for lab, meta, ts in sets[pub]:
            print(f"\n## {lab}: {meta['cpu']}, nproc {meta['nproc']}, kernel {meta['kernel']}, main run file written {meta['time']}\n")
            for t in ts:
                print("\n".join(t) + "\n")
        if not pub:
            ex = extra_tables() + memstep_tables()
            sets[False].append(("compat and v2 probe (laptop)", None, ex))
            print("## compat and v2 probe (laptop, functional)\n")
            for t in ex:
                print("\n".join(t) + "\n")
    bad = 0
    for f, pub in ((CHECK, False), (CHECKP, True)):
        if f:
            text = open(f).read()
            blocks = ["\n".join(t) for _, _, ts in sets[pub] for t in ts]
            miss = [b.split("\n")[0][:90] + " / " + b.split("\n")[2][:40] for b in blocks if b not in text]
            print(f"check {f}: {len(blocks)} tables, {len(miss)} missing" + "".join("\n  " + m for m in miss))
            bad += len(miss)
    sys.exit(1 if bad else 0)


main()
