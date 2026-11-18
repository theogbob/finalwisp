#!/usr/bin/env python3
"""60.78 T2: on the client VM, every 10 s for SECS: each TCP socket to SRV:PORT as 'P t local_port bytes_received recv_q'
(ss -tin). bytes_received is the client's TCP-level take (the server's tcpi_bytes_acked); recv_q what its application
has not read yet. usage: ss_sample.py SRV PORT SECS OUT"""
import re, subprocess, sys, time
srv, port, secs, out = sys.argv[1], sys.argv[2], float(sys.argv[3]), open(sys.argv[4], "a")
t0 = time.time()
while time.time() - t0 < secs:
    o = subprocess.run(["ss", "-tinH", "dst", f"{srv}:{port}"], capture_output=True, text=True).stdout
    head = None
    for line in o.splitlines():
        if not line.startswith((" ", "\t")):
            head = line.split()
        elif head:
            m = re.search(r"bytes_received:(\d+)", line)
            out.write(f"P {time.time() - t0:.0f} {head[3].rsplit(':', 1)[1]} {m.group(1) if m else 0} {head[1]}\n")
            head = None
    out.flush()
    time.sleep(10)
