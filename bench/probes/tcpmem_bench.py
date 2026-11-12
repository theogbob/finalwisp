#!/usr/bin/env python3
"""20.31 B3 pressure benchmark (root; VPS1/VPS2 shape). The normal regress marks host-TCP-pressure cases invalid; this
one measures them on purpose: base vs new (--tcpmem-adapt) under real kernel TCP memory pressure.

Link (set up and removed here): netns fwb (10.78.0.1) <-> veth <-> the host netns (10.78.0.2), netem 20 ms + 1 Gbit
each way. The client AND the target run in fwb behind the link (a remote client and a remote site). The server runs in
the HOST netns (review: only the initial netns shows net.ipv4.tcp_mem, so a server in another netns has the adaptation
off) in its own systemd-run scope (its cgroup's memory.stat `sock` is then only its own: 20.31 guard (a)). The new
variant must report "tcpmem adapt on" at startup, else the run aborts. Optional holder: another
process on the host keeping --holder-pm per mille of tcp_mem[1] in unread loopback socket queues (someone else's TCP
memory). Per run: main MiB/s, errors, side rr 1x1 p99 (an interactive stream next to the bulk load), kernel pressure
(TcpExt TCPMemoryPressures/Chrono deltas, all three namespaces), peak sockstat pages, recovery (s from load end until
sockstat < tcp_mem[0]), server level lines. Rotated, interleaved, paired; Wilcoxon per case (wispsuite.stats).

usage: tcpmem_bench.py --base BIN --new BIN [--new-args "--tcpmem-adapt"] --wbench WB [--reps 16] [--dur 10]
       [--cases download:10x10,echo:10x10,upload:10x10] [--holder none,600] [--out FILE.jsonl] [--suite DIR (wispsuite)]
"""
import argparse, json, os, signal, socket, subprocess, sys, threading, time

ap = argparse.ArgumentParser()
ap.add_argument("--base", required=True); ap.add_argument("--new", required=True)
ap.add_argument("--new-args", default="--tcpmem-adapt"); ap.add_argument("--wbench", required=True)
ap.add_argument("--base-args", default="", help="extra server args for the base (20.30 x 20.31 joint: B3 alone vs B3 + credit v2)")
ap.add_argument("--reps", type=int, default=16); ap.add_argument("--dur", type=float, default=10)
ap.add_argument("--cases", default="download:10x10,echo:10x10,upload:10x10")
ap.add_argument("--holder", default="none,600", help="comma list: none or per mille of tcp_mem[1] held by another process")
ap.add_argument("--out", default="tcpmem_bench.jsonl"); ap.add_argument("--suite", default="")
ap.add_argument("--port", type=int, default=6941)
ap.add_argument("--peer-bufs", action="store_true", help="small TCP buffers for the peers (fwb)")
ap.add_argument("--main-rate", type=float, default=0, help="Mbit/s cap on the main target's replies (equal-throughput runs)")
ap.add_argument("--srv-rate", type=float, default=0, help="Mbit/s of the host -> fwb direction (default 1000)")
a = ap.parse_args()
# a SIGTERM/SIGHUP ends the run through the finally below (link removed, children stopped)
for _s in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(_s, lambda *_: sys.exit(143))
CHILDREN = []
if a.suite:
    sys.path.insert(0, a.suite)
PAGE = os.sysconf("SC_PAGE_SIZE")
TCP_MEM = [int(x) for x in open("/proc/sys/net/ipv4/tcp_mem").read().split()]
TMODE = {"download": "source", "upload": "sink", "echo": "echo"}
FWA, FWS = ["ip", "netns", "exec", "fwb"], []
SRV, CLI = "10.78.0.2", "10.78.0.1"


def sh(*c):
    subprocess.run(list(c), check=True, capture_output=True, timeout=20)


def link_up():
    if subprocess.run(["ip", "link", "show", "vfwb"], capture_output=True).returncode == 0:
        sys.exit("vfwb exists: another run? (ip link del vfwb; ip netns del fwb)")
    sh("ip", "netns", "add", "fwb")
    sh("ip", "-n", "fwb", "link", "set", "lo", "up")
    sh("ip", "link", "add", "vfwb", "type", "veth", "peer", "name", "vb", "netns", "fwb")
    sh("ip", "addr", "add", f"{SRV}/24", "dev", "vfwb"); sh("ip", "link", "set", "vfwb", "up")
    sh("ip", "-n", "fwb", "addr", "add", f"{CLI}/24", "dev", "vb"); sh("ip", "-n", "fwb", "link", "set", "vb", "up")
    # --srv-rate: the host -> fwb direction (server -> client, server -> target) at this rate instead of 1 Gbit: the
    # bottleneck stays at the server's egress (its sockets hold the queue, as in the pressure runs), for every flow alike
    sh("tc", "qdisc", "add", "dev", "vfwb", "root", "netem", "delay", "20ms", "rate", f"{a.srv_rate:g}mbit" if a.srv_rate else "1gbit",
       "limit", "10000")
    if a.main_rate:
        # parent 2026-10-27: equal main throughput off vs on. The main target's replies (source port a.port + 1, fwb -> host:
        # download data, echo replies) get their own HTB class capped at --main-rate; the side rr and everything else
        # keep 1 Gbit. 20 ms netem under each class.
        tcf = ["ip", "netns", "exec", "fwb", "tc"]
        sh(*tcf, "qdisc", "add", "dev", "vb", "root", "handle", "1:", "htb", "default", "20")
        sh(*tcf, "class", "add", "dev", "vb", "parent", "1:", "classid", "1:1", "htb", "rate", "1gbit", "ceil", "1gbit")
        sh(*tcf, "class", "add", "dev", "vb", "parent", "1:1", "classid", "1:10", "htb", "rate", f"{a.main_rate}mbit",
           "ceil", f"{a.main_rate}mbit")
        sh(*tcf, "class", "add", "dev", "vb", "parent", "1:1", "classid", "1:20", "htb", "rate", "1gbit", "ceil", "1gbit")
        for c in ("10", "20"):
            sh(*tcf, "qdisc", "add", "dev", "vb", "parent", f"1:{c}", "netem", "delay", "20ms", "limit", "10000")
        sh(*tcf, "filter", "add", "dev", "vb", "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "sport",
           str(a.port + 1), "0xffff", "flowid", "1:10")
    else:
        sh("ip", "netns", "exec", "fwb", "tc", "qdisc", "add", "dev", "vb", "root", "netem", "delay", "20ms", "rate", "1gbit", "limit", "10000")
    # the peers share this host's global TCP memory (sockstat counts every netns); on their own machines they would not.
    # --peer-bufs: smaller buffers in fwb (per-netns sysctls). Smoke on VPS1: with them echo 10x10 peaked at 23 MiB and
    # never reached pressure, so the default keeps the kernel defaults (the peers then hold about half of the memory).
    if a.peer_bufs:
        sh("ip", "netns", "exec", "fwb", "sysctl", "-q", "-w", "net.ipv4.tcp_rmem=4096 131072 1048576",
           "net.ipv4.tcp_wmem=4096 16384 524288")


def link_down():
    subprocess.run(["ip", "link", "del", "vfwb"], capture_output=True, timeout=20)
    subprocess.run(["ip", "netns", "del", "fwb"], capture_output=True, timeout=20)


def tcp_pages():
    for l in open("/proc/net/sockstat"):
        if l.startswith("TCP:"):
            f = l.split()
            return int(f[f.index("mem") + 1])


def pressure():
    tot = [0, 0]
    for pre in ([], FWA):
        t = subprocess.run([*pre, "cat", "/proc/net/netstat"], capture_output=True, text=True, timeout=10).stdout
        ls = [l.split() for l in t.splitlines() if l.startswith("TcpExt:")]
        d = dict(zip(ls[0][1:], map(int, ls[1][1:])))
        tot[0] += d.get("TCPMemoryPressures", 0); tot[1] += d.get("TCPMemoryPressuresChrono", 0)
    return tot


class Holder:
    """Unread loopback queues in the host netns until sockstat shows `pages` more than at the start (or 64 pairs)."""
    def __init__(self, pages):
        self.socks, start = [], tcp_pages()
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0)); srv.listen(128)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        chunk = b"h" * 65536
        while tcp_pages() - start < pages and len(self.socks) < 128:
            c = socket.socket(); c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
            c.connect(srv.getsockname()); s, _ = srv.accept()
            c.setblocking(False)
            try:
                while tcp_pages() - start < pages:
                    c.send(chunk)
            except BlockingIOError:
                pass
            self.socks += [c, s]
        self.pages = tcp_pages() - start
        srv.close()

    def close(self):
        for s in self.socks:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            s.close()


def spawn(*args, **kw):
    p = subprocess.Popen(*args, **kw)
    CHILDREN.append(p)
    return p


def stop(p):
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(5)


def wb_json(out):
    return next((json.loads(l) for l in out.splitlines() if l.startswith("{")), {})


def run(v, binp, extra, test, cs, rep, holder):
    conns, streams = cs.split("x")
    tport, rport = a.port + 1, a.port + 2
    tg = spawn([*FWA, a.wbench, "target", "--port", str(tport), "--mode", TMODE[test], "--bind", CLI], stderr=subprocess.DEVNULL)
    rt = spawn([*FWA, a.wbench, "target", "--port", str(rport), "--mode", "echo", "--bind", CLI], stderr=subprocess.DEVNULL)
    unit = f"fwbench-{os.getpid()}-{rep}-{v}"
    srv = spawn(["systemd-run", "--quiet", "--scope", "--unit", unit, "-p", "MemoryAccounting=yes", binp,
                            "--port", str(a.port), "--host", SRV, "--allow-private", "--log-level", "debug", *extra],  # (60.60: "tcpmem adapt on" is in the debug detail line)
                           stderr=subprocess.PIPE, text=True)
    log, t0 = [], time.time()
    threading.Thread(target=lambda: [log.append((round(time.time() - t0, 3), l.rstrip())) for l in srv.stderr], daemon=True).start()
    hold = Holder(TCP_MEM[1] * holder // 1000) if holder else None
    time.sleep(1.0)
    if "--tcpmem-adapt" in extra and not any("tcpmem adapt on" in l for _, l in log):
        stop(srv); stop(tg); stop(rt)
        hold and hold.close()
        raise SystemExit("new variant: tcpmem adapt is not on: " + " | ".join(l for _, l in log if "tcpmem" in l)[:400])
    if hold and hold.pages < TCP_MEM[1] * holder // 1000 * 9 // 10:
        print(f"warning: holder reached {hold.pages} of {TCP_MEM[1] * holder // 1000} pages", file=sys.stderr)
    p0, peak, stop_s = pressure(), [0], threading.Event()

    def sampler():
        while not stop_s.is_set():
            peak[0] = max(peak[0], tcp_pages()); time.sleep(0.05)
    threading.Thread(target=sampler, daemon=True).start()
    url = f"ws://{SRV}:{a.port}/"
    side = spawn([*FWA, "timeout", str(int(a.dur) + 40), a.wbench, "run", "--url", url, "--target", f"{CLI}:{rport}",
                             "--test", "rr", "--conns", "1", "--streams", "1", "--duration", str(a.dur), "--warmup", "1", "--json"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    main = subprocess.run([*FWA, "timeout", str(int(a.dur) + 40), a.wbench, "run", "--url", url, "--target", f"{CLI}:{tport}",
                           "--test", test, "--conns", conns, "--streams", streams, "--duration", str(a.dur), "--warmup", "1", "--json"],
                          capture_output=True, text=True, timeout=a.dur + 60)
    t_end = time.time()
    side_out = side.communicate(timeout=a.dur + 60)[0]
    # recovery: until the host's TCP memory is under tcp_mem[0] (the kernel's exit), the holder still in place;
    # review: a run that does not recover in 30 s is recorded as 30 (censored), not dropped
    rec, censored = None, False
    while time.time() - t_end < 30:
        if tcp_pages() < TCP_MEM[0]:
            rec = round(time.time() - t_end, 2); break
        time.sleep(0.05)
    if rec is None:
        rec, censored = 30.0, True
    stop_s.set()
    # 20.30 joint: the server's peak heap (VmHWM; systemd-run --scope execs it in place) and its scope's memory.peak
    hwm = mpeak = None
    try:
        hwm = int(next(l for l in open(f"/proc/{srv.pid}/status") if l.startswith("VmHWM")).split()[1]) // 1024
    except (OSError, StopIteration):
        pass
    try:
        mpeak = int(open(f"/sys/fs/cgroup/system.slice/{unit}.scope/memory.peak").read()) >> 20
    except (OSError, ValueError):
        pass
    for p in (srv, tg, rt):
        stop(p)
    if hold:
        hold.close()
    # review: the kernel credits TCPMemoryPressuresChrono when it LEAVES pressure: read it after the run's memory is gone
    for _ in range(100):
        if tcp_pages() < TCP_MEM[0]:
            break
        time.sleep(0.1)
    p1 = pressure()
    js, sj = wb_json(main.stdout), wb_json(side_out)
    # review: a side stream that failed (no JSON, errors, no requests) has no latency, not a 0 one
    side_ok = side.returncode == 0 and sj and not sj.get("errors") and (sj.get("rps") or 0) > 0
    lv = [l for _, l in log if "memory level" in l or "tcp level" in l]
    return dict(v=v, rep=rep, case=f"{test} {cs}", holder=holder, main_rate=a.main_rate, srv_rate=a.srv_rate, holder_pages=hold.pages if hold else 0,
                mib_s=js.get("mib_s_down" if test == "download" else "mib_s_up" if test == "upload" else "mib_s_down"),
                mib_s_up=js.get("mib_s_up"), errors=(js.get("errors") or 0) + (0 if js else 1),
                rr_p99_us=sj.get("p99_us") if side_ok else None, rr_rps=sj.get("rps") if side_ok else 0, side_failed=not side_ok,
                pressures=p1[0] - p0[0], pressure_ms=p1[1] - p0[1], peak_pages=peak[0], recovery_s=rec, recovery_censored=censored,
                tcp_level_lines=sum("tcp level 0 -> 1" in l for l in lv), level_lines=lv[:6], hwm_mib=hwm, mem_peak_mib=mpeak)


out = open(a.out, "a")
variants = [("base", a.base, a.base_args.split()), ("new", a.new, a.new_args.split())]
link_up()
try:
  for rep in range(a.reps):
      for holder in [0 if h == "none" else int(h) for h in a.holder.split(",")]:
          for c in a.cases.split(","):
              test, cs = c.split(":")
              order = variants if rep % 2 == 0 else variants[::-1]
              for v, b, extra in order:
                  r = run(v, b, extra, test, cs, rep, holder)
                  print(json.dumps({k: x for k, x in r.items() if k != "level_lines"}), flush=True)
                  out.write(json.dumps(r) + "\n"); out.flush()
finally:
    for p in CHILDREN:
        stop(p)
    link_down()

# summary
try:
    from wispsuite.stats import compare
except ImportError:
    compare = None
recs = [json.loads(l) for l in open(a.out)]
keys = sorted({(r["case"], r["holder"]) for r in recs})
print("| case | holder | metric | base | new | ratio | p | verdict |")
for case, h in keys:
    by = {v: {r["rep"]: r for r in recs if r["case"] == case and r["holder"] == h and r["v"] == v} for v in ("base", "new")}
    reps = sorted(set(by["base"]) & set(by["new"]))
    cens = {v: sum(by[v][i].get("recovery_censored", False) for i in reps) for v in by}
    sidef = {v: sum(by[v][i].get("side_failed", False) for i in reps) for v in by}
    print(f"| {case} | {h} | censored recoveries / failed side streams | {cens['base']}/{sidef['base']} | {cens['new']}/{sidef['new']} | | | |")
    for m, hb in (("mib_s", True), ("rr_p99_us", False), ("rr_rps", True), ("pressure_ms", False), ("peak_pages", False),
                  ("recovery_s", False), ("errors", False)):
        b = [by["base"][i][m] for i in reps]; n = [by["new"][i][m] for i in reps]
        c = compare(b, n, hb) if compare else None
        if c:
            print(f"| {case} | {h} | {m} | {c['base']} | {c['new']} | {c['ratio']} | {c['p']} | {c['verdict']} |")
        else:
            print(f"| {case} | {h} | {m} | {b} | {n} | | | |")
