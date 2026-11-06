#!/usr/bin/env python3
"""20.31 B3 premise probe: host TCP memory (/proc/net/sockstat "TCP ... mem", pages) vs net.ipv4.tcp_mem
during loopback bulk cases, sampled every 50 ms, plus TcpExt TCPMemoryPressures / TCPMemoryPressuresChrono deltas
and the server's own memory-level log lines. stdlib only; every child has a hard timeout.

usage: tcpmem_premise.py --bin FW --wbench WB [--cases download:10x10,upload:10x10,echo:10x10] [--dur 6] [--reps 2]
       [--port 6931] [--tport 6932] [--args "..."] [--out FILE.jsonl]
"""
import argparse, json, os, signal, subprocess, sys, threading, time

ap = argparse.ArgumentParser()
ap.add_argument("--bin", required=True); ap.add_argument("--wbench", required=True)
ap.add_argument("--cases", default="download:10x10,upload:10x10,echo:10x10,download:1x1")
ap.add_argument("--dur", type=float, default=6); ap.add_argument("--reps", type=int, default=2)
ap.add_argument("--port", type=int, default=6931); ap.add_argument("--tport", type=int, default=6932)
ap.add_argument("--args", default=""); ap.add_argument("--out", default="")
ap.add_argument("--netns", action="store_true", help="server + target in netns fws (10.77.0.2), client in fwa (bench/vps/netns_hol.sh)")
ap.add_argument("--target-in-client-ns", action="store_true", help="--netns: the target in fwa (10.77.0.1) too, behind the link: "
                "only the server's sockets are in fws (a remote client and a remote site)")
a = ap.parse_args()
PAGE = os.sysconf("SC_PAGE_SIZE")
TCP_MEM = [int(x) for x in open("/proc/sys/net/ipv4/tcp_mem").read().split()]
TMODE = {"download": "source", "upload": "sink", "echo": "echo"}


def tcp_pages():
    for l in open("/proc/net/sockstat"):
        if l.startswith("TCP:"):
            f = l.split()
            return int(f[f.index("mem") + 1])
    return None


def tcpext():
    # (TcpExt counters are per network namespace: the netns variant adds the server's and the client's)
    if a.netns:
        tot = [0, 0]
        for ns in ("fws", "fwa"):
            t = subprocess.run(["ip", "netns", "exec", ns, "cat", "/proc/net/netstat"], capture_output=True, text=True, timeout=10).stdout
            lines = [l.split() for l in t.splitlines() if l.startswith("TcpExt:")]
            d = dict(zip(lines[0][1:], map(int, lines[1][1:])))
            tot[0] += d.get("TCPMemoryPressures", 0); tot[1] += d.get("TCPMemoryPressuresChrono", 0)
        return tuple(tot)
    lines = [l.split() for l in open("/proc/net/netstat") if l.startswith("TcpExt:")]
    d = dict(zip(lines[0][1:], map(int, lines[1][1:])))
    return d.get("TCPMemoryPressures", 0), d.get("TCPMemoryPressuresChrono", 0)


def ss_by_proc():
    """socket memory (skmem r + w + f: receive alloc, write queued, forward alloc; bytes) per owning process name"""
    import re
    pre = ["ip", "netns", "exec", "fws"] if a.netns else []
    out = {}
    for tag, ns_pre in ([("fws:", pre), ("fwa:", ["ip", "netns", "exec", "fwa"])] if a.netns else [("", pre)]):
        t = subprocess.run([*ns_pre, "ss", "-tmnpH"], capture_output=True, text=True, timeout=10).stdout
        for line in re.split(r"\n(?=\S)", t):
            m = re.search(r"skmem:\(r(\d+),rb\d+,t\d+,tb\d+,f(\d+),w(\d+)", line)
            n = re.search(r'users:\(\("([^"]+)"', line)
            if m:
                k = tag + (n.group(1) if n else "orphan/none")
                out[k] = out.get(k, 0) + int(m.group(1)) + int(m.group(2)) + int(m.group(3))
    return {k: round(v / 2**20, 1) for k, v in out.items()}


def run_case(test, cs, rep):
    conns, streams = cs.split("x")
    sp, cp, host = (["ip", "netns", "exec", "fws"], ["ip", "netns", "exec", "fwa"], "10.77.0.2") if a.netns else ([], [], "127.0.0.1")
    thost, tp = ("10.77.0.1", cp) if a.target_in_client_ns else (host, sp)
    tg = subprocess.Popen([*tp, a.wbench, "target", "--port", str(a.tport), "--mode", TMODE[test], "--bind", thost], stderr=subprocess.DEVNULL)
    srv = subprocess.Popen([*sp, a.bin, "--port", str(a.port), "--host", host, "--allow-loopback", "--allow-private", *a.args.split()],
                           stderr=subprocess.PIPE, text=True)
    log = []
    threading.Thread(target=lambda: [log.append(l.rstrip()) for l in srv.stderr], daemon=True).start()
    time.sleep(1.0)
    p0, c0 = tcpext()
    base_pages = tcp_pages()
    samples, stop = [], threading.Event()

    def sampler():
        t0 = time.time()
        while not stop.is_set():
            samples.append((round(time.time() - t0, 3), tcp_pages()))
            time.sleep(0.05)

    th = threading.Thread(target=sampler, daemon=True); th.start()
    snap = {}
    threading.Timer(1.0 + a.dur / 2, lambda: snap.update(ss_by_proc())).start()  # mid-run: who holds the TCP memory
    try:
        wb = subprocess.run([*cp, "timeout", str(int(a.dur) + 40), a.wbench, "run", "--url", f"ws://{host}:{a.port}/",
                             "--target", f"{thost}:{a.tport}", "--test", test, "--conns", conns, "--streams", streams,
                             "--duration", str(a.dur), "--warmup", "1", "--json"], capture_output=True, text=True, timeout=a.dur + 60)
        js = next((json.loads(l) for l in wb.stdout.splitlines() if l.startswith("{")), {})
    finally:
        time.sleep(1.0)  # recovery tail
        stop.set(); th.join(2)
        p1, c1 = tcpext()
        for p in (srv, tg):
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill(); p.wait(5)
    pages = [s[1] for s in samples if s[1] is not None]
    dt = 0.05
    above = lambda th: round(sum(dt for x in pages if x >= th), 2)
    mx = max(pages) if pages else None
    t_last_over1 = max((t for t, x in samples if x is not None and x >= TCP_MEM[1]), default=None)
    t_end = samples[-1][0] if samples else None
    r = dict(case=f"{test} {cs}", rep=rep, tcp_mem=TCP_MEM, base_pages=base_pages, max_pages=mx,
             max_mib=round(mx * PAGE / 2**20, 1) if mx else None, s_above_mem0=above(TCP_MEM[0]), s_above_mem1=above(TCP_MEM[1]),
             pressures=p1 - p0, pressure_chrono_ms=c1 - c0, last_over_mem1_s=t_last_over1, sampled_s=t_end,
             mib_s_down=js.get("mib_s_down"), mib_s_up=js.get("mib_s_up"), errors=js.get("errors"),
             server_mem_lines=[l for l in log if "memory level" in l], ss_mib_by_proc=snap, series=samples[::4])
    return r


out = open(a.out, "a") if a.out else None
for rep in range(a.reps):
    for c in a.cases.split(","):
        test, cs = c.split(":")
        r = run_case(test, cs, rep)
        s = {k: v for k, v in r.items() if k != "series"}
        print(json.dumps(s), flush=True)
        if out:
            out.write(json.dumps(r) + "\n"); out.flush()
