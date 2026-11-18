#!/usr/bin/env python3
"""60.78 T2 (sb-unread) pressure run of --unread-close's credit rule: honest slow readers and abusive shapes under real
host TCP memory pressure. Root, on a VPS (VPS1: rmem_max 16 MiB, so a client SO_RCVBUF of 16 MiB is a 32 MiB buffer).
usage: vps_unread.py run BIN PORT DUR OUTDIR [HOLD_16THS]   (the driver; start it in a transient systemd unit)
       vps_unread.py hostlog DUR FILE                          (this host's TCP memory + TcpExt counters)
       vps_unread.py source PORT [BIND [LOG]]                 (an endless TCP source, 64 KiB blocks; LOG: its ends)
       vps_unread.py clients SRV PORT TGT DUR OUTDIR [TGT_IP]  (in the netns: the client shapes, one thread each)
       vps_unread.py serve BIN PORT DUR OUTDIR HOLD_16THS IP [MORE_JSON [FIRST_ARGS]] (two-VM form: finalwisp on IP + the holder; clients and
                                                              `source PORT IP` run on another VM, behind netem there)
Link: netns fwsb (10.78.9.1: clients and source) <-> veth vfwsb/vsb <-> host netns (10.78.9.2: finalwisp), netem 20 ms
and 100 Mbit each way. Nothing listens on a public address. Holder: unread loopback queues in the host netns until the
host's TCP memory (sockstat) reaches HOLD_16THS/16 of tcp_mem's maximum (default 13: above the 3/4 mark of
--unread-close, below the maximum), from 60 s after the clients start; topped up every 10 s. Files in OUTDIR: srv.log (finalwisp, --log-conns, metrics every
10 s), host.txt ('H t sockstat_pages tcp_mem_max holder_pairs' every 10 s), clients.txt ('T t name taken' every 10 s,
'R t name why' at a reset or error, 'E t name alive taken' at the end), run.txt (setup, cleanup)."""
import os, signal, socket, struct, subprocess, sys, threading, time, base64

# a SIGTERM (systemctl stop) ends the driver through its finally (link, netns and holder removed)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))

SRV, CLI = "10.78.9.2", "10.78.9.1"
NS = ["ip", "netns", "exec", "fwsb"]
# (name, streams, SO_RCVBUF (0 = autotuned), bytes per s after the start (0: none), bytes read at full speed first,
#  pause s before reading, trickle: (bytes, every s) or None)
SHAPES = [
    ("H1_2k_auto", 1, 0, 2048, 0, 0, None),
    ("H2_1k_32m", 1, 16 << 20, 1024, 0, 0, None),
    ("H3_2k_32m", 1, 16 << 20, 2048, 0, 0, None),
    ("H4_8k_32m", 1, 16 << 20, 8192, 0, 0, None),
    ("H5_1k_fast", 1, 0, 1024, 32 << 20, 0, None),
    ("H6_2k_pause300", 1, 0, 2048, 0, 300, None),
    ("H7_1k_32m_fast", 1, 16 << 20, 1024, 32 << 20, 0, None),
    ("A1_noread", 1, 0, 0, 0, 0, None),
    ("A2_noread_s16", 16, 0, 0, 0, 0, None),
    ("A3_trickle", 1, 4096, 0, 0, 0, (4096, 500)),
    ("A4_fill16m", 1, 0, 0, 16 << 20, 0, None),
    ("A5_noread_s64", 64, 0, 0, 0, 0, None),
    # a frozen tab / an app in the background: (8th field) a window (from, to) in s with no read at all
    ("H8_2k_stop300to1500", 1, 0, 2048, 0, 0, None, (300, 1500)),
    ("H9_2k_stop300to2100", 1, 0, 2048, 0, 0, None, (300, 2100)),
    ("H10_2k_stop0to1200", 1, 0, 2048, 0, 0, None, (0, 1200)),
]

def frame(payload):
    n = len(payload); m = os.urandom(4)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))

def source(port, bind=CLI, log=None):
    """`log`: a file for one line per connection that ends: 'X t peer_port error' (the source saw the end)"""
    blob = b"x" * 65536; t0 = time.time(); lf = open(log, "a") if log else None
    def feed(c):
        peer = c.getpeername()[1]
        try:
            while True: c.sendall(blob)
        except OSError as e:
            if lf: lf.write(f"X {time.time() - t0:.0f} {peer} {type(e).__name__}:{e}\n"); lf.flush()
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((bind, port)); s.listen(512)
    while True:
        c, _ = s.accept(); threading.Thread(target=feed, args=(c,), daemon=True).start()

def clients(srv, port, tgt, dur, outdir, tgt_ip=CLI):
    out = open(os.path.join(outdir, "clients.txt"), "a"); lk = threading.Lock(); t0 = time.time()
    def log(s):
        with lk: out.write(f"{s}\n"); out.flush()
    def one(name, streams, rcv, rate, fast, pause, trickle, stop=None):
        got = 0
        try:
            s = socket.socket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1448)
            if rcv: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcv)
            s.connect((srv, port))
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
                      + base64.b64encode(b"0123456789abcdef") + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf: buf += s.recv(1)
            for sid in range(1, streams + 1):
                s.sendall(frame(bytes([1]) + struct.pack("<I", sid) + b"\x01" + struct.pack("<H", tgt) + tgt_ip.encode()))
            log(f"S {time.time() - t0:.0f} {name} rcvbuf={s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)} port={s.getsockname()[1]}")
            s.settimeout(0.2); last = 0; fast_end = None; tk_at = 0
            while time.time() - t0 < dur:
                el = time.time() - t0
                if got < fast:
                    want = fast - got
                elif trickle:
                    want = trickle[0] if el - tk_at >= trickle[1] else 0
                    if want: tk_at = el
                elif stop and stop[0] <= el < stop[1]:
                    want = 0
                elif rate and el >= pause:
                    if fast_end is None: fast_end = (el, got)
                    off = max(0, min(el, stop[1]) - max(stop[0], fast_end[0])) if stop else 0
                    want = int((el - fast_end[0] - off) * rate) - (got - fast_end[1])
                else:
                    want = 0
                while want > 0:
                    try:
                        d = s.recv(min(want, 1 << 20))
                    except socket.timeout:
                        break
                    if not d: raise ConnectionResetError("EOF")
                    got += len(d); want -= len(d)
                if want <= 0: time.sleep(0.05)
                if el - last >= 10:
                    last = el; log(f"T {el:.0f} {name} {got}")
                    # a client that does not read sees a reset only here: TCP_INFO's state (7 = closed)
                    if s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 8)[0] == 7: raise ConnectionResetError("state closed")
            log(f"E {time.time() - t0:.0f} {name} alive {got}")
        except OSError as e:
            log(f"R {time.time() - t0:.0f} {name} {type(e).__name__}:{e} taken={got}")
    ths = [threading.Thread(target=one, args=sh, daemon=True) for sh in SHAPES]
    for t in ths: t.start(); time.sleep(0.2)
    for t in ths: t.join(dur + 60)

def sh(*c):
    subprocess.run(list(c), check=True, capture_output=True, timeout=20)

def pages():
    for l in open("/proc/net/sockstat"):
        if l.startswith("TCP:"): f = l.split(); return int(f[f.index("mem") + 1])
    return 0

def run(binp, port, dur, outdir, hold16):
    os.makedirs(outdir, exist_ok=True)
    rl = open(os.path.join(outdir, "run.txt"), "a")
    def note(s): rl.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {s}\n"); rl.flush()
    tmax = int(open("/proc/sys/net/ipv4/tcp_mem").read().split()[2])
    if subprocess.run(["ip", "link", "show", "vfwsb"], capture_output=True).returncode == 0:
        sys.exit("vfwsb exists: another run?")
    procs, socks = [], []
    try:
        sh("ip", "netns", "add", "fwsb"); sh("ip", "-n", "fwsb", "link", "set", "lo", "up")
        sh("ip", "link", "add", "vfwsb", "type", "veth", "peer", "name", "vsb", "netns", "fwsb")
        sh("ip", "addr", "add", f"{SRV}/24", "dev", "vfwsb"); sh("ip", "link", "set", "vfwsb", "up")
        sh("ip", "-n", "fwsb", "addr", "add", f"{CLI}/24", "dev", "vsb"); sh("ip", "-n", "fwsb", "link", "set", "vsb", "up")
        sh("tc", "qdisc", "add", "dev", "vfwsb", "root", "netem", "delay", "20ms", "rate", "100mbit", "limit", "10000")
        sh(*NS, "tc", "qdisc", "add", "dev", "vsb", "root", "netem", "delay", "20ms", "rate", "100mbit", "limit", "10000")
        note(f"link up; tcp_mem max {tmax} pages; target {hold16}/16; bin {binp}")
        me = os.path.abspath(__file__)
        procs.append(subprocess.Popen([*NS, sys.executable, me, "source", str(port + 1)], stderr=subprocess.DEVNULL))
        srvlog = open(os.path.join(outdir, "srv.log"), "a")
        procs.append(subprocess.Popen([binp, "--port", str(port), "--host", SRV, "--allow-private", "--unread-close",
                                       "--metrics-interval", "10", "--log-conns"], stdout=srvlog, stderr=srvlog))
        time.sleep(2)
        procs.append(subprocess.Popen([*NS, sys.executable, me, "clients", SRV, str(port), str(port + 1), str(dur), outdir],
                                      stderr=open(os.path.join(outdir, "clients.err"), "a")))
        # the holder (after the clients' memory settled, so the sum stays at the target): unread loopback pairs
        time.sleep(60)
        hs = socket.socket(); hs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        hs.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20); hs.bind(("127.0.0.1", 0)); hs.listen(256)
        want = tmax * hold16 // 16
        def top_up():
            chunk = b"h" * 65536
            while pages() < want and len(socks) < 2 * 1500:
                c = socket.socket(); c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
                c.connect(hs.getsockname()); s, _ = hs.accept(); c.setblocking(False)
                try:
                    while pages() < want: c.send(chunk)
                except BlockingIOError:
                    pass
                socks.extend([c, s])
        top_up()
        note(f"holder {len(socks) // 2} pairs, sockstat {pages()} pages")
        host = open(os.path.join(outdir, "host.txt"), "a"); t0 = time.time()
        while time.time() - t0 < dur + 30 and procs[-1].poll() is None:
            top_up()
            host.write(f"H {time.time() - t0:.0f} {pages()} {tmax} {len(socks) // 2}\n"); host.flush()
            time.sleep(10)
        note("clients done")
    finally:
        for p in reversed(procs):
            if p.poll() is None:
                p.terminate()
                try: p.wait(10)
                except subprocess.TimeoutExpired: p.kill()
        for s in socks:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00"); s.close()
        subprocess.run(["ip", "link", "del", "vfwsb"], capture_output=True)
        subprocess.run(["ip", "netns", "del", "fwsb"], capture_output=True)
        note("cleanup done")

def netstat():
    """TcpExt counters of this namespace (/proc/net/netstat) as {name: value}"""
    ls = open("/proc/net/netstat").read().splitlines()
    for a, b in zip(ls[::2], ls[1::2]):
        if a.startswith("TcpExt:"):
            return dict(zip(a.split()[1:], map(int, b.split()[1:])))
    return {}


def hostlog(dur, path):
    """the client VM's own TCP memory, so a run can show its client side was not short: 'H t pages tcp_mem_max' every
    10 s and 'N t name=delta ...' (TcpExt counters that moved since the start) every 60 s, in one file"""
    tmax = int(open("/proc/sys/net/ipv4/tcp_mem").read().split()[2])
    f = open(path, "a"); t0, n0, nt = time.time(), netstat(), 0
    while time.time() - t0 < dur:
        el = time.time() - t0
        f.write(f"H {el:.0f} {pages()} {tmax}\n")
        if el >= nt:
            nt += 60; n1 = netstat()
            f.write(f"N {el:.0f} " + " ".join(f"{k}={n1[k] - n0.get(k, 0)}" for k in n1 if n1[k] != n0.get(k, 0)) + "\n")
        f.flush(); time.sleep(10)


def serve(binp, port, dur, outdir, hold16, ip, more="[]", first="--unread-close"):
    """two-VM form: the server VM runs finalwisp on `ip` and the holder; the clients and the source run on another VM
    (their buffers are then not in this kernel's TCP memory). `more`: JSON list of [binary, port, "args"] for more
    servers beside the first (whose args are `first`, default --unread-close). Files: srv.log (the first), srv-PORT.log (the others),
    host.txt, netstat.txt ('N t name=delta ...': TcpExt counters that moved since the start, every 60 s), run.txt."""
    import json
    os.makedirs(outdir, exist_ok=True)
    rl = open(os.path.join(outdir, "run.txt"), "a")
    def note(s): rl.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {s}\n"); rl.flush()
    tmax = int(open("/proc/sys/net/ipv4/tcp_mem").read().split()[2])
    procs, socks = [], []
    common = ["--allow-private", "--metrics-interval", "10", "--log-conns"]
    specs = [(binp, port, first + (" --log-streams" if json.loads(more) else ""), "srv.log")]
    specs += [(b, int(p), a, f"srv-{p}.log") for b, p, a in json.loads(more)]
    try:
        for b, p, a, lg in specs:
            f = open(os.path.join(outdir, lg), "a")
            cmd = [b, "--port", str(p), "--host", ip, *common, *a.split()]
            procs.append(subprocess.Popen(cmd, stdout=f, stderr=f))
            note(f"server pid {procs[-1].pid}: " + " ".join(cmd))
        note(f"tcp_mem max {tmax} pages; target {hold16}/16; holder from 90 s")
        hs = socket.socket(); hs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        hs.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20); hs.bind(("127.0.0.1", 0)); hs.listen(256)
        want = tmax * hold16 // 16
        def top_up():
            chunk = b"h" * 65536
            while pages() < want and len(socks) < 2 * 1500:
                c = socket.socket(); c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
                c.connect(hs.getsockname()); s, _ = hs.accept(); c.setblocking(False)
                try:
                    while pages() < want: c.send(chunk)
                except BlockingIOError:
                    pass
                socks.extend([c, s])
        host = open(os.path.join(outdir, "host.txt"), "a"); nf = open(os.path.join(outdir, "netstat.txt"), "a")
        t0, said, n0, nt = time.time(), False, netstat(), 0
        while time.time() - t0 < dur and all(p.poll() is None for p in procs):
            el = time.time() - t0
            if el >= 90:
                top_up()
                if not said: note(f"holder {len(socks) // 2} pairs, sockstat {pages()} pages"); said = True
            host.write(f"H {el:.0f} {pages()} {tmax} {len(socks) // 2}\n"); host.flush()
            if el >= nt:
                nt += 60; n1 = netstat()
                nf.write(f"N {el:.0f} " + " ".join(f"{k}={n1[k] - n0.get(k, 0)}" for k in n1 if n1[k] != n0.get(k, 0)) + "\n"); nf.flush()
            time.sleep(10)
        note("serve done" + ("" if all(p.poll() is None for p in procs) else ": a server ended early"))
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try: p.wait(10)
                except subprocess.TimeoutExpired: p.kill()
        for s in socks:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00"); s.close()
        note("cleanup done")

if __name__ == "__main__":
    m = sys.argv[1]
    if m == "hostlog": hostlog(float(sys.argv[2]), sys.argv[3])
    elif m == "source": source(int(sys.argv[2]), *sys.argv[3:5])
    elif m == "clients": clients(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]), sys.argv[6], *sys.argv[7:8])
    elif m == "serve": serve(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), sys.argv[5], int(sys.argv[6]), sys.argv[7], *sys.argv[8:10])
    else: run(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), sys.argv[5], int(sys.argv[6]) if len(sys.argv) > 6 else 13)
