#!/usr/bin/env python3
# 30.11 follow-up: is memory freed (or reused) after clients holding unread downloads go away?
# Fresh server per transport; 3 batches x N connections each with a download stream that is never read;
# then every client is aborted (RST). Samples at +3/+10/+30/+60 s after each batch. Functional, not a benchmark.
# usage: retain.py OUT.jsonl [--n 200]
import argparse, json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispc import Wisp
HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser(); ap.add_argument("out"); ap.add_argument("--n", type=int, default=200)
a = ap.parse_args()
out = open(a.out, "a", buffering=1)

def snap(pid, cg):
    st = {l.split(":")[0]: l.split()[1] for l in open(f"/proc/{pid}/status") if ":" in l and len(l.split()) > 1}
    ms = dict(l.split() for l in open(cg + "/memory.stat"))
    return {"rss_kib": int(st["VmRSS"]), "fds": len(os.listdir(f"/proc/{pid}/fd")), "anon_kib": int(ms["anon"]) // 1024,
            "sock_kib": int(ms["sock"]) // 1024, "cg_kib": int(open(cg + "/memory.current").read()) // 1024}

for tls in (True, False):
    port = 7002 if tls else 7001
    args = [os.path.join(HERE, "fw-base1.1"), "--port", str(port), "--allow-loopback"]
    if tls:
        args += ["--tls-cert", os.path.join(HERE, "certs/cert.pem"), "--tls-key", os.path.join(HERE, "certs/key.pem")]
    srv = subprocess.Popen(["systemd-run", "--user", "--scope", "--quiet", f"--unit=soak-rt-{port}-{int(time.time())}",
                            "-p", "MemoryMax=1G", "-p", "MemorySwapMax=0"] + args, stderr=subprocess.DEVNULL, start_new_session=True)
    src = subprocess.Popen([os.path.join(HERE, "wbench"), "target", "--port", "7103", "--mode", "source"],
                           stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(1.5)
    cg = "/sys/fs/cgroup" + open(f"/proc/{srv.pid}/cgroup").read().strip().split("::", 1)[1]
    rec = lambda **kv: out.write(json.dumps(dict(t=time.time(), tls=tls, **kv, **snap(srv.pid, cg))) + "\n")
    try:
        time.sleep(3); rec(phase="base", batch=0)
        for b in range(1, 4):
            ws = []
            for i in range(a.n):
                w = Wisp(port, tls=tls); w.connect(1, 7103); ws.append(w)
            time.sleep(5); rec(phase="held", batch=b)
            for w in ws:
                w.close(rst=True)
            t0 = time.time()
            for s in (3, 10, 30, 60):
                time.sleep(max(0, t0 + s - time.time())); rec(phase="after", batch=b, s=s)
    finally:
        for p in (srv, src):
            p.terminate(); p.wait(10)
    time.sleep(3)
