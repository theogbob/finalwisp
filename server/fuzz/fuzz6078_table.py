#!/usr/bin/env python3
"""60.78 G15 campaign table from the raw files of one campaign directory (campaign.py output + the end replays).
usage: fuzz6078_table.py DIR [--check NOTE.md]
DIR holds logs/ (campaign.jsonl, <target>-lane<i>-<n>.<run>.log), artifacts/, sanlogs/, end/ (replay-{regress,corpus,merged}-<t>.log,
merge-<t>.log). execs = sum of the last status line of every lane log (a restarted lane counts both segments);
crash/timeout/oom = the last status line of each segment, the n=0 worker segments (02:35-02:50Z, finding F1, harness)
apart. --check: exit 1 if a generated row is not in NOTE.md."""
import glob, json, os, re, sys
from collections import defaultdict

D = sys.argv[1]
secs, ex, bad, bad_f1 = defaultdict(int), defaultdict(int), defaultdict(lambda: [0, 0, 0]), defaultdict(int)
for l in open(os.path.join(D, "logs/campaign.jsonl")):
    e = json.loads(l)
    if e.get("ev") == "start" and e["n"] == 0:
        secs[e["target"]] += e["secs"]
restarted = {(json.loads(l)["target"], json.loads(l)["lane"]) for l in open(os.path.join(D, "logs/campaign.jsonl")) if '"n": 1' in l}
for f in sorted(glob.glob(os.path.join(D, "logs/*-lane*.log"))):
    m = re.search(r"/([a-z-]+)-lane(\d+)-(\d+)\.", f)
    t, lane, n = m.group(1), int(m.group(2)), int(m.group(3))
    last = None
    for line in open(f, errors="replace"):
        s = re.match(r"#(\d+): cov: \d+ .*oom/timeout/crash: (\d+)/(\d+)/(\d+)", line)
        if s: last = s
    if not last: continue
    ex[t] += int(last.group(1))
    if (t, lane) in restarted and n == 0:
        bad_f1[t] += int(last.group(4))
    else:
        for i in range(3): bad[t][i] += int(last.group(2 + i))
def cov(kind, t):
    p = os.path.join(D, "end", f"replay-{kind}-{t}.log")
    if not os.path.isfile(p): return "?"
    m = re.findall(r"DONE +cov: (\d+)", open(p, errors="replace").read())
    return m[-1] if m else "?"
def merged(t):
    p = os.path.join(D, "end", f"merge-{t}.log")
    return os.path.isdir(os.path.join(D, "regress-merged", t)) and len(os.listdir(os.path.join(D, "regress-merged", t)))
rows = ["| target | lane h | execs | crash / timeout / oom (after F1) | F1 crashes (harness, 02:35-02:50Z) | artifacts | sanitizer logs | cov replay regress -> final corpus -> merged | regress-merged files |",
        "|---|---|---|---|---|---|---|---|---|"]
for t in sorted(secs):
    arts = len(os.listdir(os.path.join(D, "artifacts", t))) if os.path.isdir(os.path.join(D, "artifacts", t)) else 0
    b = bad[t]
    rows.append(f"| {t} | {secs[t] / 3600:g} | {ex[t]:,} | {b[2]} / {b[1]} / {b[0]} | {bad_f1[t]} | {arts} | {len(os.listdir(os.path.join(D, 'sanlogs')))} | "
                f"{cov('regress', t)} -> {cov('corpus', t)} -> {cov('merged', t)} | {merged(t)} |")
print("\n".join(rows))
if "--check" in sys.argv:
    note = open(sys.argv[sys.argv.index("--check") + 1]).read()
    missing = [r for r in rows if r not in note]
    print(f"fuzz6078_table --check: {len(rows)} rows, {len(missing)} not in the note")
    sys.exit(1 if missing else 0)
