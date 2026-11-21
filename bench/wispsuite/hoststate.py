"""Host state sampler (80.02): one JSON line every INTERVAL seconds, so that interference between the units of a
parallel gate (or between two gates) is measured, not assumed.  usage: python3 -m wispsuite.hoststate OUT.jsonl [INTERVAL=2]
Stops at SIGTERM / SIGINT, or when the file OUT.jsonl.stop exists. Reads /proc only (no root, no tool).
Fields: t (unix), load1, cpu_busy (share of all cores since the last sample), psi_cpu / psi_mem / psi_io (some avg10),
mem_avail_mb, tcp_inuse, tcp_orphan, tcp_tw, tcp_alloc, tcp_mem_pages (sockstat), udp_inuse, udp_mem_pages,
tcp_mem_limit (the three limits, pages), eph_tcp / eph_udp (sockets with a local port in ip_local_port_range),
eph_range, listeners, and the counters of /proc/net/netstat and /proc/net/snmp named in COUNTERS (absolute values:
take differences), tls_rx_rekey / tls_tx_rekey (/proc/net/tls_stat), procs (processes of this uid)."""
import json, os, signal, sys, time

COUNTERS = ("TCPMemoryPressures", "TCPMemoryPressuresChrono", "PruneCalled", "RcvPruned", "OfoPruned", "TCPAbortOnMemory", "ListenOverflows",
            "ListenDrops", "TCPTimeouts", "TCPSynRetrans", "TCPBacklogDrop", "TCPRcvQDrop", "TCPReqQFullDrop", "TCPOrphanQueued",
            "RetransSegs", "AttemptFails", "EstabResets", "OutRsts", "InErrors", "RcvbufErrors", "SndbufErrors")


def _kv(path):
    """the 'Name: k1 k2' / 'Name: v1 v2' line pairs of /proc/net/netstat and snmp -> {k: v}"""
    out = {}
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    for a, b in zip(lines[::2], lines[1::2]):
        pre = a.split(":")[0]
        if pre not in ("TcpExt", "Tcp", "Udp"):  # UdpLite, Icmp, Ip: the same key names as Udp, not recorded
            continue
        for k, v in zip(a.split()[1:], b.split()[1:]):
            out[k if pre != "Udp" else "Udp" + k] = int(v)
    return out


def _cpu():
    with open("/proc/stat") as f:
        x = [int(v) for v in f.readline().split()[1:9]]
    return sum(x), x[3] + x[4]


def _psi(name):
    try:
        with open(f"/proc/pressure/{name}") as f:
            return float(f.readline().split("avg10=")[1].split()[0])
    except (OSError, IndexError, ValueError):
        return None


def sample(prev_cpu, eph):
    d = {"t": round(time.time(), 2), "load1": os.getloadavg()[0]}
    tot, idle = _cpu()
    if prev_cpu and tot > prev_cpu[0]:
        d["cpu_busy"] = round(1 - (idle - prev_cpu[1]) / (tot - prev_cpu[0]), 3)
    d.update(psi_cpu=_psi("cpu"), psi_mem=_psi("memory"), psi_io=_psi("io"))
    try:
        with open("/proc/meminfo") as f:
            d["mem_avail_mb"] = next(int(l.split()[1]) // 1024 for l in f if l.startswith("MemAvailable"))
    except (OSError, StopIteration):
        pass
    try:
        with open("/proc/net/sockstat") as f:
            for l in f:
                x = l.split()
                kv = dict(zip(x[1::2], x[2::2]))
                if x[0] == "TCP:":
                    d.update(tcp_inuse=int(kv["inuse"]), tcp_orphan=int(kv["orphan"]), tcp_tw=int(kv["tw"]), tcp_alloc=int(kv["alloc"]), tcp_mem_pages=int(kv["mem"]))
                elif x[0] == "UDP:":
                    d.update(udp_inuse=int(kv["inuse"]), udp_mem_pages=int(kv["mem"]))
    except (OSError, KeyError, ValueError):
        pass
    n = {"tcp": 0, "udp": 0, "listen": 0}
    for fn, kind in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp"), ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp")):
        try:
            with open(fn) as f:
                next(f)
                for line in f:
                    x = line.split()
                    port = int(x[1].rsplit(":", 1)[1], 16)
                    if eph[0] <= port <= eph[1]:
                        n[kind] += 1
                    if kind == "tcp" and x[3] == "0A":
                        n["listen"] += 1
        except (OSError, StopIteration, ValueError, IndexError):
            continue
    d.update(eph_tcp=n["tcp"], eph_udp=n["udp"], listeners=n["listen"])
    c = {**_kv("/proc/net/netstat"), **_kv("/proc/net/snmp")}
    for k in COUNTERS:
        for name in (k, "Udp" + k):
            if name in c:
                d[name] = c[name]
    try:
        with open("/proc/net/tls_stat") as f:
            ts = {l.split()[0]: int(l.split()[1]) for l in f}
        d.update(tls_rx_rekey=ts.get("TlsRxRekeyOk"), tls_tx_rekey=ts.get("TlsTxRekeyOk"))
    except OSError:
        pass
    uid, procs = os.getuid(), 0
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                procs += os.stat(f"/proc/{p}").st_uid == uid
            except OSError:
                pass
    d["procs"] = procs
    return d, (tot, idle)


# 80.04: host-state tags of ONE timed run, from the counters wbench --edges read at the two edges of its
# measured window (bench/src/edges.rs). Shares of all CPU ticks of the window (ncpu x dt): steal (hypervisor),
# softirq, irq, iowait; other = user + nice + system ticks NOT used by the server, the wbench client or the target,
# per CPU (another process on the box). tcp_press = TCPMemoryPressures entries in the window. BAD marks: BAD_MARKS
# (see bad()); thresholds from archived runs: bench/tools/timemarks.py (5104 A/A pairs of `wst ab` on two 2-vCPU VPS boxes: the
# pair spread is 1.9 x the clean spread at steal 1-2 %, 1.4 x at 0.5-1 %, 2.5 x with TCP memory pressure; BAD = 1.5 x
# or more). "other" has no archived counterpart: 5 % is PROVISIONAL until timebox A/A runs give the same table for it.
CLK_TCK = os.sysconf("SC_CLK_TCK")
BAD_MARKS = {"steal": 0.01, "other": 0.05, "tcp_press": 0}


def cpu_mhz():
    """mean "cpu MHz" of /proc/cpuinfo (a VM often shows a fixed value; None if absent)"""
    try:
        v = [float(l.split(":")[1]) for l in open("/proc/cpuinfo") if l.startswith("cpu MHz")]
        return round(sum(v) / len(v), 1) if v else None
    except (OSError, ValueError, IndexError):
        return None


def tags(edges, tgt_cpu_s=0.0, mhz=None):
    """-> dict of host-state tags of one run (None values where wbench had no such counter)."""
    e = edges or {}
    h = e.get("host") or {}
    tot = sum(h.values()) if h else 0
    from .timedsum import srv_cpu_s
    srv = srv_cpu_s(e, CLK_TCK)
    cli = (e.get("cli_user_us", 0) + e.get("cli_sys_us", 0)) / 1e6
    out = {"dt_s": e.get("dt_s"), "mhz": mhz, "tcp_press": e.get("tcp_press"), "tcp_press_ms": e.get("tcp_press_ms"),
           "tcp_mem": e.get("tcp_mem"), "late_ms": round(max(e.get("late0_us", 0), e.get("late1_us", 0)) / 1000, 2)}
    if tot > 0:
        for k in ("steal", "softirq", "irq", "iowait"):
            out[k] = round(h.get(k, 0) / tot, 4)
        ncpu = tot / CLK_TCK / e["dt_s"] if e.get("dt_s") else None  # CPUs seen in the window's ticks
        used = (h.get("user", 0) + h.get("nice", 0) + h.get("system", 0)) / CLK_TCK
        if srv is not None and ncpu:
            out["other"] = round(max(0.0, used - srv - cli - (tgt_cpu_s or 0)) / (ncpu * e["dt_s"]), 4)
        out["busy"] = round(1 - (h.get("idle", 0) + h.get("iowait", 0)) / tot, 4)
    return out


def bad(t, marks=None):
    """-> list of the marks one run's tags pass (empty = a clean run)"""
    m = {**BAD_MARKS, **(marks or {})}
    out = []
    for k in ("steal", "other"):
        if t.get(k) is not None and t[k] > m[k]:
            out.append(f"{k} {t[k]} > {m[k]}")
    if t.get("tcp_press") is not None and t["tcp_press"] > m["tcp_press"]:
        out.append(f"tcp_press {t['tcp_press']}")
    return out


def main(argv):
    out, interval = argv[0], float(argv[1]) if len(argv) > 1 else 2.0
    stop = [False]
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.__setitem__(0, True))
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
            eph = tuple(int(x) for x in f.read().split())
    except (OSError, ValueError):
        eph = (32768, 60999)
    head = {"t": round(time.time(), 2), "start": True, "interval": interval, "eph_range": eph, "nproc": os.cpu_count()}
    try:
        with open("/proc/sys/net/ipv4/tcp_mem") as f:
            head["tcp_mem_limit"] = [int(x) for x in f.read().split()]
    except (OSError, ValueError):
        pass
    prev = None
    with open(out, "a") as f:
        f.write(json.dumps(head) + "\n")
        while not stop[0] and not os.path.exists(out + ".stop"):
            t0 = time.time()
            d, prev = sample(prev, eph)
            f.write(json.dumps(d) + "\n")
            f.flush()
            time.sleep(max(0.05, interval - (time.time() - t0)))


if __name__ == "__main__":
    main(sys.argv[1:])
