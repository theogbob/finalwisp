#!/usr/bin/env python3
"""60.78 T2: sample the server side of every client connection on PORT (ss -tinH sport = :PORT) every 0.5 s until the
file STOP exists: 'Z t sockets zero_window_sockets' lines. A connection is in an --unread-close stall only with the
client's receive window at 0 (snd_wnd:0 on the server's socket). usage: zwnd_sample.py PORT OUT STOP"""
import os, re, subprocess, sys, time
port, out, stop = sys.argv[1], open(sys.argv[2], "a"), sys.argv[3]
t0 = time.time()
while not os.path.exists(stop):
    o = subprocess.run(["ss", "-tinH", "sport", "=", f":{port}"], capture_output=True, text=True).stdout
    w = re.findall(r"snd_wnd:(\d+)", o)
    out.write(f"Z {time.time() - t0:.1f} {len(w)} {sum(1 for x in w if x == '0')}\n"); out.flush()
    time.sleep(0.5)
