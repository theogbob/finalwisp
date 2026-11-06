#!/usr/bin/env python3
"""30.17 heap check (parent, 2026-10-31): cycle.py --floor-hook. At a floor (servers idle, after the floor sample),
dump glibc malloc_info XML of each server via gdb (brief stop): OUTDIR/<cycle>-<S>.xml.
usage: heapsnap.py OUTDIR CYCLE A=PID B=PID"""
import os, subprocess, sys, time
out, cyc = sys.argv[1], int(sys.argv[2])
os.makedirs(out, exist_ok=True)
for kv in sys.argv[3:]:
    s, pid = kv.split("=")
    f = os.path.join(out, f"{cyc:03d}-{s}.xml")
    t0 = time.time()
    cmd = ["gdb", "-batch", "-nx", "-p", pid,
           "-ex", f'set $f = (void*)fopen("{f}", "w")',
           "-ex", "call (int)malloc_info(0, $f)",
           "-ex", "call (int)fclose($f)"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        rc = p.returncode
        err = "" if os.path.getsize(f) > 0 else (p.stdout + p.stderr)[-400:]
    except Exception as e:  # recorded; the next floor tries again
        rc, err = "error", repr(e)
    print(f"{s} pid {pid} cycle {cyc}: rc {rc} {time.time() - t0:.2f} s {err}", flush=True)
