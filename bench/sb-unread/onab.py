#!/usr/bin/env python3
"""60.78 T2 (sb-unread): the on-cost of --unread-close with the public preset, one box. Runs detached (transient unit).
usage: onab.py ROOT PAIRS CELLS PORT
ROOT holds bench/wispsuite (the suite), wbench, fw-pre, fw-uc, fw-pre2 (three copies of one binary; step D: fw-uc the
new build, fw-pre / fw-pre2 two copies of the base) and gets out/. $ONAB_UC: the uc arm's switches (--unread-close).
Arms (rotated per round by `wst ab`; every arm also gets --allow-loopback --allow-private): pre = fw-pre --preset public, uc = fw-uc --preset public --unread-close,
pre2 = fw-pre2 --preset public (the A/A copy). CELLS: test:conns:streams,... One `python3 -m wispsuite ab` per cell,
loopback, ports PORT / PORT+1. Files: out/<cell>.jsonl (raw), .stdout, .stderr; PROGRESS; DONE or FAILED; REST (the
box before the start: stray processes, load, TCP memory)."""
import json, os, re, subprocess, sys, time
root, pairs, cells, port = sys.argv[1], int(sys.argv[2]), sys.argv[3].split(","), int(sys.argv[4])
os.chdir(root); os.makedirs("out", exist_ok=True)
def say(m):
    with open("PROGRESS", "a") as f: f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {m}\n")
stray = [l for l in subprocess.run(["ps", "-eo", "pid,comm"], capture_output=True, text=True).stdout.splitlines()[1:]
         if re.match(r"^(fw-|finalwisp|wbench)", l.split()[1])]
rest = {"stray": stray, "load": open("/proc/loadavg").read().split()[:3],
        "tcp": [l for l in open("/proc/net/sockstat") if l.startswith("TCP:")][0].strip()}
json.dump(rest, open("REST", "w")); open("REST", "a").write("\n")
if stray:
    say(f"REFUSED: stray processes {stray}"); open("FAILED", "w").write("stray\n"); sys.exit(3)
AP = "--allow-loopback --allow-private --preset public"  # as abfan: the target is on loopback
UC = os.environ.get("ONAB_UC", "--unread-close")  # the uc arm's own switches (step D: --unread-relief; fw-uc another binary)
arms = {"pre": f"{root}/fw-pre {AP}", "uc": f"{root}/fw-uc {AP} {UC}", "pre2": f"{root}/fw-pre2 {AP}"}
json.dump(arms, open("out/arms.json", "w"))
env = dict(os.environ, WBENCH=os.path.join(root, "wbench"))
bad = 0
for cell in cells:
    t, c, s = cell.split(":"); tag = cell.replace(":", "-")
    if os.path.exists(f"out/{tag}.done"): continue
    say(f"start {cell}")
    cmd = [sys.executable, "-m", "wispsuite", "ab", f"{root}/out/arms.json", str(pairs), "--raw", f"{root}/out/{tag}.jsonl",
           "--port", str(port), "--tport", str(port + 1), "--test", t, "--conns", c, "--streams", s]
    with open(f"out/{tag}.stdout", "w") as fo, open(f"out/{tag}.stderr", "w") as fe:
        rc = subprocess.run(cmd, cwd=os.path.join(root, "bench"), env=env, stdout=fo, stderr=fe, timeout=pairs * 3 * 30 + 300).returncode
    say(f"end {cell} rc={rc}")
    if rc == 0: open(f"out/{tag}.done", "w").write("ok\n")
    else: bad += 1
open("DONE" if not bad else "FAILED", "w").write(f"{bad} failed\n")
say("DONE" if not bad else f"FAILED {bad}")
