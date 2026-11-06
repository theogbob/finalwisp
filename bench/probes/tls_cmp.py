#!/usr/bin/env python3
"""30.08 TLS deployment comparison (interleaved): each variant = list of server processes; the client is
wbench over wss:// (--insecure). Reports throughput / req/s and the summed CPU of ALL server-side processes
(e.g. Caddy + finalwisp) per run. Usage: tls_cmp.py VARIANTS.json REPS OUT.jsonl  (env WBENCH, CASES)
VARIANTS.json: {"name": {"url": "wss://127.0.0.1:7801/", "cmds": ["exec ...", ...]}}"""
import json, os, signal, subprocess, sys, time
variants = json.load(open(sys.argv[1])); reps = int(sys.argv[2]); out = open(sys.argv[3], "w")
WB = os.environ.get("WBENCH", "./wbench"); HZ = os.sysconf("SC_CLK_TCK")
CASES = os.environ.get("CASES", "download:1x1 download:10x10 upload:1x1 upload:10x10 echo:10x10 rr:10x10 churn:10x10").split()
TP = {"download": 7890, "upload": 7891}
tg = [subprocess.Popen([WB, "target", "--port", str(p), "--mode", m], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
      for p, m in [(7890, "source"), (7891, "sink"), (7892, "echo")]]
time.sleep(0.3)
def cpu(pids):
    t = 0
    for p in pids:
        for tid in os.listdir(f"/proc/{p}/task") if os.path.exists(f"/proc/{p}/task") else []:
            try:
                f = open(f"/proc/{p}/task/{tid}/stat").read().rsplit(")", 1)[1].split()
                t += int(f[11]) + int(f[12])
            except OSError:
                pass
    return t / HZ
try:
    for case in CASES:
        test, cs = case.split(":"); c, s = cs.split("x")
        for rep in range(reps):
            for name, v in variants.items():
                ps = [subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True) for cmd in v["cmds"]]
                time.sleep(v.get("ready", 0.7))
                pids = [p.pid for p in ps]
                c0 = cpu(pids); t0 = time.time()
                r = subprocess.run([WB, "run", "--url", v["url"], "--insecure", "--target", f"127.0.0.1:{TP.get(test, 7892)}", "--conns", c, "--streams", s,
                                    "--duration", "4", "--warmup", "1", "--test", test, "--json"] + v.get("extra", []), capture_output=True, text=True)
                used = cpu(pids) - c0; wall = time.time() - t0
                for p in ps:
                    try: os.killpg(p.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    p.wait()
                time.sleep(0.3)
                try: j = json.loads(r.stdout.strip().splitlines()[-1])
                except Exception: j = {"error": (r.stdout + r.stderr)[-300:]}
                rec = {"case": case, "variant": name, "rep": rep, "cpu_cores": round(used / wall, 2), **j}
                out.write(json.dumps(rec) + "\n"); out.flush()
finally:
    for p in tg: os.killpg(p.pid, signal.SIGKILL)
print("done")
