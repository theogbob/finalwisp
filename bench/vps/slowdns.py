#!/usr/bin/env python3
"""30.09 (20.19) slow stub DNS resolver for the DNS-coalescing experiment (VPS netns). Answers every A query
for *.slow with 10.77.0.2 (or ADDR) after DELAY_MS (*.slow3: after 3000 ms, a stalled upstream), NXDOMAIN for
*.nx at once and for *.nxd after DELAY_MS, SERVFAIL for *.sf after DELAY_MS (20.23 negative cache test); counts queries to stderr every 2 s.
usage: slowdns.py BIND_IP PORT DELAY_MS [ADDR]"""
import socket, struct, sys, threading, time
bind, port, delay = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]) / 1000.0
addr = sys.argv[4] if len(sys.argv) > 4 else "10.77.0.2"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((bind, port))
n = 0
def answer(pkt, peer):
    global n
    qid = pkt[:2]; q = pkt[12:]
    i = 0; labels = []
    while q[i]:
        labels.append(q[i + 1:i + 1 + q[i]].decode()); i += 1 + q[i]
    qname = q[:i + 1]; qtype, qclass = struct.unpack(">HH", q[i + 1:i + 5])
    name = ".".join(labels)
    if name.endswith(".slow3"):
        time.sleep(3.0)
    elif not name.endswith(".nx"):
        time.sleep(delay)
    if name.endswith(".sf"):
        hdr = qid + b"\x81\x82" + struct.pack(">HHHH", 1, 0, 0, 0)
        s.sendto(hdr + qname + struct.pack(">HH", qtype, qclass), peer); return
    if name.endswith(".nx") or name.endswith(".nxd"):
        hdr = qid + b"\x81\x83" + struct.pack(">HHHH", 1, 0, 0, 0)
        s.sendto(hdr + qname + struct.pack(">HH", qtype, qclass), peer); return
    if qtype == 1:
        hdr = qid + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0)
        rr = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + socket.inet_aton(addr)
        s.sendto(hdr + qname + struct.pack(">HH", qtype, qclass) + rr, peer)
    else:  # AAAA etc: empty answer
        hdr = qid + b"\x81\x80" + struct.pack(">HHHH", 1, 0, 0, 0)
        s.sendto(hdr + qname + struct.pack(">HH", qtype, qclass), peer)
def report():
    last = 0
    while True:
        time.sleep(2)
        if n != last:
            print(f"slowdns: {n} queries", file=sys.stderr, flush=True); last = n
threading.Thread(target=report, daemon=True).start()
print(f"slowdns on {bind}:{port} delay {delay*1000:.0f} ms -> {addr}", file=sys.stderr, flush=True)
while True:
    pkt, peer = s.recvfrom(512); n += 1
    threading.Thread(target=answer, args=(pkt, peer), daemon=True).start()
