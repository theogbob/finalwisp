# 30.11 pause confirmation (base-1.2 candidate): Wisp client, 16 KiB rcvbuf set BEFORE connect (fixed harness) vs
# AFTER connect (the artifact), pauses 60 and 250 s, 30 s to resume. usage: pause_confirm.py FW
import subprocess, sys, time, os, json
os.chdir(os.path.dirname(os.path.abspath(__file__)))
procs = []
def sp(argv): p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True); procs.append(p); return p
sp(["./wbench", "target", "--port", "7103", "--mode", "source", "--threads", "2"])
sp([sys.argv[1], "--port", "7002", "--allow-loopback"])
time.sleep(1.5)
runs = [{"RCVBUF": "16384", "WAIT": "30", "BEFORE": "1"}, {"RCVBUF": "16384", "WAIT": "30", "BEFORE": "0"}]
outs = [subprocess.Popen([sys.executable, "pause_repro.py", "7002", "7103", "60", "250"], stdout=subprocess.PIPE, text=True,
                         env=dict(os.environ, **e)) for e in runs]
for o in outs:
    for line in o.communicate()[0].splitlines():
        d = json.loads(line); print(json.dumps({k: d.get(k) for k in ("pause", "rcvbuf", "before_connect", "before", "after", "first_data_s", "close", "err")}))
for p in procs:
    os.killpg(p.pid, 15); p.wait()
