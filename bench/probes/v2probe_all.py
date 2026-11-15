#!/usr/bin/env python3
"""showdown 60.71: v2probe.py against registry servers, a fresh server per probe (loopback). usage: v2probe_all.py PORT NAME..."""
import json, os, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from wispsuite import proc, servers as srvmod
port = int(sys.argv[1])
reg = srvmod.load()
for name in sys.argv[2:]:
    srv = srvmod.resolve(name, reg)
    p = srv.start(port, srvmod.SCRATCH)
    time.sleep(0.3)
    try:
        out = subprocess.run([sys.executable, os.path.join(HERE, "v2probe.py"), str(port)], capture_output=True, text=True, timeout=20)
        print(json.dumps({"server": name, **json.loads(out.stdout or "{}")}) if out.stdout else json.dumps({"server": name, "error": out.stderr[-300:]}))
    finally:
        proc.stop(p)
        proc.wait_free(port)
