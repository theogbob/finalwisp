#!/usr/bin/env python3
# 30.11 soak follow-up: cost of dead-peer (half-open) connections on a fresh finalwisp, measured in its own
# scope. Needs the root nft table from soak-nft.sh (ports 7001/7002). Run only when the soak is not running.
# Phases per transport (plain :7001, TLS :7002): baseline -> N idle conns (healthy) -> marked dead ->
# N conns with an unread download, marked dead -> watched until the kernel reaps them (or --watch-min).
# usage: halfcost.py OUT.jsonl [--n 200] [--watch-min 30]
import argparse, json, os, re, socket, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispc import Wisp

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("out")
ap.add_argument("--n", type=int, default=200)
ap.add_argument("--watch-min", type=float, default=30)
a = ap.parse_args()
import resource
resource.setrlimit(resource.RLIMIT_NOFILE, (resource.getrlimit(resource.RLIMIT_NOFILE)[1],) * 2)
out = open(a.out, "a", buffering=1)


def snap(pid, cg, port):
    st = {l.split(":")[0]: l.split()[1] for l in open(f"/proc/{pid}/status") if ":" in l and len(l.split()) > 1}
    ms = dict(l.split() for l in open(cg + "/memory.stat"))
    ss = subprocess.run(["ss", "-tmnH", "state", "established", f"( sport = :{port} )"], capture_output=True,
                        text=True).stdout
    # skmem:(r<rmem_alloc>,rb..,t<wmem_alloc>,tb..,f<fwd_alloc>,w<wmem_queued>,...): r + w = queued bytes
    skmem = sum(int(m.group(1)) + int(m.group(2)) for m in re.finditer(r"skmem:\(r(\d+),rb\d+,t\d+,tb\d+,f\d+,w(\d+)", ss))
    return {"rss_kib": int(st["VmRSS"]), "fds": len(os.listdir(f"/proc/{pid}/fd")),
            "cg_kib": int(open(cg + "/memory.current").read()) >> 10, "anon_kib": int(ms["anon"]) >> 10,
            "sock_kib": int(ms["sock"]) >> 10, "kernel_kib": int(ms.get("kernel", 0)) >> 10,
            "skmem_rw_kib": skmem >> 10, "estab": ss.count("skmem:(")}


def run(tls):
    port = 7002 if tls else 7001
    args = [os.path.join(HERE, "fw-base1.1"), "--port", str(port), "--allow-loopback"]
    if tls:
        args += ["--tls-cert", os.path.join(HERE, "certs/cert.pem"), "--tls-key", os.path.join(HERE, "certs/key.pem")]
    unit = f"soak-hc-{port}-{int(time.time())}"
    srv = subprocess.Popen(["systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}", "-p", "MemoryMax=1G",
                            "-p", "MemorySwapMax=0"] + args, stderr=subprocess.DEVNULL, start_new_session=True)
    src = subprocess.Popen([os.path.join(HERE, "wbench"), "target", "--port", "7103", "--mode", "source"],
                           stderr=subprocess.DEVNULL, start_new_session=True)
    idle, dl = [], []
    time.sleep(1.5)
    cg = "/sys/fs/cgroup" + open(f"/proc/{srv.pid}/cgroup").read().strip().split("::", 1)[1]
    rec = lambda phase, **kv: out.write(json.dumps(dict(t=time.time(), tls=tls, n=a.n, phase=phase,
                                                         **snap(srv.pid, cg, port), **kv)) + "\n")
    try:
        time.sleep(3); rec("base")
        idle.extend(Wisp(port, tls=tls, bind_port=61500 + i) for i in range(a.n))
        time.sleep(5); rec("idle_healthy")
        for w in idle:
            w.raw.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x28); w.ping(b"bye")
        time.sleep(5); rec("idle_dead")
        for i in range(a.n):
            w = Wisp(port, tls=tls, bind_port=62500 + i)
            w.connect(1, 7103); dl.append(w)
        time.sleep(5); rec("dl_unread")
        for w in dl:
            w.raw.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x28); w.ping(b"bye")
        t0 = time.time()
        while time.time() - t0 < a.watch_min * 60:
            time.sleep(30); rec("dl_dead", s=round(time.time() - t0))
            ss = subprocess.run(["ss", "-tn", "state", "established", f"( sport = :{port} and dport >= :62500 and dport < :63000 )"],
                                capture_output=True, text=True).stdout
            if len(ss.splitlines()) <= 1:
                break
        time.sleep(5); rec("end")
    finally:
        for p in (srv, src):
            p.terminate(); p.wait(10)
        for w in idle + dl:
            w.close()


run(False)
time.sleep(5)
run(True)
