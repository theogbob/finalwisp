"""Browser A/B of finalwisp builds (bench/browser): a base build twice (A/A) vs variants.

  python3 bench/browser/ab_splice.py --base PATH --new PATH [--reps 8] [--out DIR/results.json]   (splice64 set)
  python3 bench/browser/ab_splice.py --base PATH --variant NAME=fw:PATH [args] ... [--compat-downloads]
  python3 bench/browser/ab_splice.py --analyze DIR/results.json

Servers: base-a, base-b (= the same base build twice: the A/A noise floor), base-nosplice (base --no-splice),
new (the new build, default flags). 4 servers x 8 rotated reps (balanced: each goes first twice), transports
epoxy + libcurl, timing mode with --trace. Cases: m-busy (page load + small fetches under an endless download),
m-big100 (100 MiB download), plain pages m-wikipedia, m-hn, m-mdn, m-assets200. ~25 min; needs the machine lock.

Analysis: per transport, every variant paired with base-a in the same rep (the same position in the rotation):
n, how often the variant is better, the median difference; A/A (base-b) gives the noise. Metrics: m-busy load_ms
and the median of its 5 small fetches, m-big100 MiB/s, plain-page load_ms. Writes DIR/ab.md.
"""
import argparse, json, math, os, statistics, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SITES = ["m-busy", "m-big100", "m-wikipedia", "m-hn", "m-mdn", "m-assets200"]
PAGES = ["m-wikipedia", "m-hn", "m-mdn", "m-assets200"]


def sign_p(k, n):
    """Two-sided exact sign test p for k of n pairs on one side."""
    if n == 0:
        return None
    t = min(k, n - k)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(t + 1)) / 2 ** n)


def metric(r, key):
    if not r.get("ok"):
        return None
    if key == "small":
        return statistics.median(r["small_ms"]) if r.get("small_ms") else None
    return r.get(key)


def frame_table(d):
    """Download frame sizes per server/transport (needs --trace): is an adaptive cap active during a download?"""
    rows = {}
    for r in d["results"]:
        f = r.get("frames")
        if r.get("case") != "download" or not f:
            continue
        rows.setdefault((r["site"], r["server"], r["transport"]), []).append((r, f))
    if not rows:
        return ""
    med = lambda xs: statistics.median(xs) if xs else None
    out = ["\n## Download Wisp frames (medians over reps)\n",
           "| site | server (transport) | MiB/s | frames <=16K / <=64K / >64K | bytes in >64K frames | max frame | client DATA frames (same stream) | longest client-DATA gap ms |",
           "|---|---|---|---|---|---|---|---|"]
    for (site, sv, tr), lst in sorted(rows.items()):
        fs = [f for _, f in lst]
        out.append(f"| {site} | {sv} ({tr}) | {med([r['mib_s'] for r, _ in lst if r.get('mib_s')])} | "
                   f"{med([f['hist']['le16k'] for f in fs])} / {med([f['hist']['le64k'] for f in fs])} / {med([f['hist']['gt64k'] for f in fs])} | "
                   f"{med([f['share_bytes_gt64k'] for f in fs]):.0%} | {max(f['max'] for f in fs)} | "
                   f"{med([f['client_data_frames'] for f in fs])} ({med([f['client_data_frames_same_stream'] for f in fs])}) | "
                   f"{med([f['client_data_max_gap_ms'] for f in fs])} |")
    return "\n".join(out) + "\n"


def analyze(path):
    """Every variant paired, per rep, with the mean of base-a and base-b (base-b alone vs base-a = the A/A row)."""
    d = json.load(open(path))
    res = d["results"]
    idx = {(r["server"], r["transport"], r["site"], r["rep"]): r for r in res}
    names = [s["name"] for s in d["servers"]]
    variants = [n for n in names if n not in ("base-a", "base-b")]
    have_b = "base-b" in names
    sites = sorted({r["site"] for r in res})
    checks = [("m-busy", "load_ms", "busy page load ms", -1), ("m-busy", "small", "busy small fetch ms", -1),
              ("m-big100", "mib_s", "100 MiB download MiB/s", +1)] + [(p, "load_ms", f"{p} load ms", -1) for p in PAGES]
    checks = [c for c in checks if c[0] in sites]
    rows = []
    for tr in d["transports"] + ["both"]:
        for site, key, label, better in checks:
            comps = ([("base-b (A/A vs base-a)", "base-b", ["base-a"])] if have_b else []) + \
                    [(v, v, ["base-a", "base-b"] if have_b else ["base-a"]) for v in variants]
            for label_v, v, bases in comps:
                diffs, bvals = [], []
                for (sv, t, st, rep), r in idx.items():
                    if sv != v or st != site or (tr != "both" and t != tr):
                        continue
                    x = metric(r, key)
                    bs = [metric(idx.get((b, t, st, rep)) or {}, key) for b in bases]
                    if x is None or any(b is None for b in bs):
                        continue
                    b = statistics.mean(bs)
                    diffs.append(x - b)
                    bvals.append(b)
                n = len(diffs)
                wins = sum(1 for x in diffs if x * better > 0)
                rows.append([tr, label, label_v, "-" if not bvals else f"{statistics.median(bvals):.1f}", n, f"{wins}/{n}",
                             "-" if not n else f"{statistics.median(diffs):+.1f}", "-" if not n else f"{sign_p(wins, n):.3f}"])
    fails = [f'{r["server"]}/{r["transport"]}/{r["site"]} rep {r["rep"]}: {r.get("error")}' for r in res if not r.get("ok")]
    head = ["transport", "metric", "variant", "base median", "pairs", "variant better", "median diff", "sign p"]
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    text = (f"# browser A/B: {path}\n\npower: {d.get('power')}\n\n" + "\n".join(out) +
            "\n\nbase = mean of base-a and base-b in the same rep; variant better = pairs where the variant beats it "
            "(lower ms / higher MiB/s). The base-b row (vs base-a alone) is the A/A noise floor.\n" + frame_table(d) +
            ("\nfailed reps:\n" + "\n".join(f"- {f}" for f in fails) + "\n" if fails else ""))
    with open(os.path.join(os.path.dirname(os.path.abspath(path)), "ab.md"), "w") as f:
        f.write(text)
    print(text)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base")
    ap.add_argument("--new", help="shorthand for --variant new=fw:PATH plus base --no-splice (the splice64 A/B)")
    ap.add_argument("--variant", action="append", default=[], help="NAME=fw:PATH [args] (repeatable)")
    ap.add_argument("--compat-downloads", action="store_true",
                    help="afterwards: real-internet HTTPS downloads (cloudflare 25 MiB, kernel.org 50 MiB range) with --trace, "
                         "2 reps, for the Wisp frame sizes a real TLS download produces")
    ap.add_argument("--reps", type=int, default=8)
    ap.add_argument("--out", default=None)
    ap.add_argument("--port-base", type=int, default=8400)
    ap.add_argument("--analyze", default=None, help="only analyze an existing results.json")
    a = ap.parse_args(argv)
    if a.analyze:
        return analyze(a.analyze)
    if not a.base or not (a.new or a.variant):
        sys.exit("--base and (--new or --variant) are required")
    base = os.path.abspath(a.base)
    variants = list(a.variant)
    if a.new:
        variants = [f"base-nosplice=fw:{base} --no-splice", f"new=fw:{os.path.abspath(a.new)}"] + variants
    for p in [base] + [v.split("=fw:", 1)[1].split(" ")[0] for v in variants]:
        if not os.access(p, os.X_OK):
            sys.exit(f"not an executable: {p}")
    out = a.out or os.path.join(os.path.dirname(HERE), "results", "browser-splice-ab", "results.json")
    servers = [f"base-a=fw:{base}", f"base-b=fw:{base}"] + variants
    if (len(servers) and a.reps % len(servers)):
        print(f"warning: {a.reps} reps over {len(servers)} servers: rotation unbalanced", file=sys.stderr)
    cmd = [sys.executable, os.path.join(HERE, "browser.py"), "--mode", "timing", "--trace", "--reps", str(a.reps),
           "--sites", ",".join(SITES), "--transport", "epoxy", "--transport", "libcurl", "--port-base", str(a.port_base), "--out", out]
    for s in servers:
        cmd += ["--server", s]
    print(" ".join(cmd), flush=True)
    rc = subprocess.call(cmd)
    if os.path.exists(out):
        analyze(out)
    if a.compat_downloads:
        cout = os.path.join(os.path.dirname(os.path.abspath(out)), "compat-downloads", "results.json")
        ccmd = [sys.executable, os.path.join(HERE, "browser.py"), "--mode", "compat", "--trace", "--reps", "2",
                "--sites", "cloudflare-25MiB,kernel-50MiB-range", "--transport", "epoxy", "--transport", "libcurl",
                "--port-base", str(a.port_base), "--out", cout]
        for s in servers:
            if not s.startswith("base-b="):
                ccmd += ["--server", s]
        print(" ".join(ccmd), flush=True)
        rc2 = subprocess.call(ccmd)
        if os.path.exists(cout):
            analyze(cout)
        rc = rc or rc2
    sys.exit(rc)


if __name__ == "__main__":
    main()
