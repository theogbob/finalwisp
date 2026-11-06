#!/usr/bin/env python3
"""70.01 fuzz campaign driver: runs lanes of libFuzzer processes, each in its own network namespace
(bwrap --unshare-net), sharing one corpus dir per target. libFuzzer fork mode (-fork=1 -ignore_crashes=1): a
crash is saved to artifacts/ and fuzzing goes on. SIGTERM/SIGINT stop every lane. usage: python3 campaign.py PLAN.json   (writes logs/campaign.jsonl)
Lane logs: logs/<target>-lane<i>-<n>.<run>.log, <run> = this driver start (UTC time + pid), opened for append: a restarted
driver never overwrites an earlier start's logs (70.27: the 04:11Z restart lost the 03:42-04:11 tail of segment 1)."""
import json, os, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "target/x86_64-unknown-linux-gnu/release")
MAX_RESTARTS = 25
plan = json.load(open(sys.argv[1]))  # {"lanes": [[{"target","secs","max_len"}...], ...]}
RUN = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{os.getpid()}"  # one id per driver start (lane log names)
log = open(os.path.join(HERE, "logs/campaign.jsonl"), "a")

def note(**k):
    k["t"] = time.strftime("%H:%M:%S")
    log.write(json.dumps(k) + "\n")
    log.flush()

def start(lane, step, left, n):
    t = step["target"]
    for d in (f"corpus/{t}", f"artifacts/{t}"):
        os.makedirs(os.path.join(HERE, d), exist_ok=True)
    name = f"logs/{t}-lane{lane}-{n}.{RUN}.log"
    out = open(os.path.join(HERE, name), "a")
    cmd = ["nice", "-n", "10", "bwrap", "--unshare-net", "--die-with-parent", "--dev-bind", "/", "/",
           os.path.join(BIN, t), f"corpus/{t}", f"-artifact_prefix=artifacts/{t}/", f"-max_len={step['max_len']}",
           f"-max_total_time={int(left)}", "-timeout=30", "-rss_limit_mb=3072", "-print_final_stats=1",
           "-fork=1", "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1"]
    p = subprocess.Popen(cmd, cwd=HERE, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    procs.append(p)
    note(ev="start", lane=lane, target=t, pid=p.pid, secs=int(left), n=n, log=name)
    return p

procs = []
def stop(sig, _f):
    for p in procs:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGTERM)
    note(ev="stopped", sig=sig)
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

note(ev="driver", run=RUN, plan=os.path.abspath(sys.argv[1]))
lanes = [{"steps": l, "i": 0, "p": None, "end": 0, "n": 0} for l in plan["lanes"]]
restarts = {}
while True:
    busy = False
    for li, L in enumerate(lanes):
        if L["p"] is not None:
            rc = L["p"].poll()
            if rc is None:
                busy = True
                continue
            t = L["steps"][L["i"]]["target"]
            left = L["end"] - time.time()
            note(ev="exit", lane=li, target=t, rc=rc, left=int(left))
            L["p"] = None
            if rc != 0 and left > 30 and restarts.get(t, 0) < MAX_RESTARTS:
                restarts[t] = restarts.get(t, 0) + 1
                L["n"] += 1
                L["p"] = start(li, L["steps"][L["i"]], left, L["n"])
                busy = True
                continue
            L["i"] += 1
        if L["p"] is None and L["i"] < len(L["steps"]):
            step = L["steps"][L["i"]]
            L["end"] = time.time() + step["secs"]
            L["n"] = 0
            L["p"] = start(li, step, step["secs"], 0)
            busy = True
    if not busy:
        note(ev="done")
        break
    time.sleep(5)
