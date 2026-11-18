#!/usr/bin/env python3
"""60.78 T2 (sb-unread): the server's target sockets toward one destination, every PERIOD s, from `ss -tmpiHn`:
'G t pid lport rmem rcvbuf drops rcv_space bytes_received' per socket (skmem r / rb / d, the owner pid from users:).
usage: tgt_sample.py DST_IP DST_PORT DUR OUT [PERIOD=30]"""
import re, subprocess, sys, time
ip, port, dur, out = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
per = float(sys.argv[5]) if len(sys.argv) > 5 else 30
f = open(out, "a"); t0 = time.time()
while time.time() - t0 < dur:
    el = time.time() - t0
    o = subprocess.run(["ss", "-tmpiHn", "state", "established", "dst", f"{ip}:{port}"], capture_output=True, text=True).stdout
    for blk in re.split(r"\n(?=\S)", o.strip()):
        if not blk: continue
        lp = re.search(r"\s\S+:(\d+)\s+" + re.escape(ip), blk); pid = re.search(r"pid=(\d+)", blk)
        sk = re.search(r"skmem:\(r(\d+),rb(\d+),.*?d(\d+)\)", blk)
        rs = re.search(r"rcv_space:(\d+)", blk); br = re.search(r"bytes_received:(\d+)", blk)
        if lp and pid and sk:
            f.write(f"G {el:.0f} {pid.group(1)} {lp.group(1)} {sk.group(1)} {sk.group(2)} {sk.group(3)} "
                    f"{rs.group(1) if rs else 0} {br.group(1) if br else 0}\n")
    f.flush(); time.sleep(per)
