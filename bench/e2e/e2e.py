#!/usr/bin/env python3
"""80.04 layer L8: real Wisp clients end to end. Paired rounds of real client libraries (epoxy-tls WASM,
wisp-js + Node TLS, libcurl.js plain HTTP, and 'direct' = no Wisp server: the floor of the client stack) against our own
HTTPS target on the same host, through each server arm. Details, workloads and blind spots: bench/e2e/README.md.

usage: bench/e2e/e2e.py OUT --arm LABEL=SPEC --arm LABEL=SPEC [--arm ...] [--clients epoxy,wispjs,direct]
                        [--workloads page,bulk,rr,tls,busy] [--rounds 16] [--port-base 16100] [--quick]
                        [--timeout-s 60] [--order rotate|random] [--seed N] [--pcap-round R]
       bench/e2e/e2e.py OUT --table [--check]          (recompute summary.json + TABLE.md from OUT/raw.jsonl)
  OUT/STOP ends the session after the current round; OUT/PAUSE holds it at the next round boundary (OUT/PAUSED says so).
  SPEC: a bench/servers.json name, fw:PATH [args], or NAME=COMMAND with {port}. The first arm is the reference (a);
        every other arm is paired with it round by round (b / a ratios; 2 arms: summary "b" is the second arm).
  A/A: two labels with the same SPEC (--arm a1=fw:PATH --arm a2=fw:PATH).
  Ports: server port-base+1, target port-base+10 .. +69 (all below 32768, 127.0.0.1 only).
Per round: each arm once (rotated order), a fresh server per arm, then for every client and workload ONE client process
(a new Wisp connection; epoxy-tls cannot close its raw streams, so a process per workload bounds what it leaves open).
'direct' runs once per round, in its own rotated slot, with no server. Hard timeout per client process.
Output: OUT/raw.jsonl (one record per client process), OUT/meta.json, OUT/summary.json (80.04 result contract),
OUT/TABLE.md; prints its wall time. Verdicts: wispsuite.stats.compare (paired HL ratio, 90 % CI, Wilcoxon). A run whose server did not start or died drops that arm's records of the round (never a win for either side)."""
import argparse, datetime, hashlib, json, os, random, re, shutil, signal, statistics as st, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
sys.path.insert(0, BENCH)
from wispsuite import proc, servers as srvmod, stats  # noqa: E402

LAYER, TOOL = "L8-e2e", "bench/e2e/e2e.py"
HIGHER = ("_mib_s", "_per_s")  # metric suffixes where more is better; everything else (ms, pct, slowdown) less is better
CLIENT_BOUND = 0.85            # client MAIN-THREAD CPU per wall second at or above this: the client is the bottleneck
KEY = {"page": ("page_warm_ms", "page_cold_ms", "page_req_p99_ms"), "page1": ("page1_warm_ms", "page1_cold_ms"),
       "bulk": ("bulk_mib_s",), "rr": ("rr_p50_ms", "rr_p99_ms"), "tls": ("tls_p50_ms", "tls_p99_ms"), "closefail": ("close_lost_pct",),
       "closefail3": ("close_lost_pct",), "closefail3busy": ("close_lost_pct",), "closefailslow5": ("close_lost_pct",),
       "closefailslow20": ("close_lost_pct",), "churn": ("churn_per_s", "churn_p99_ms"), "busy": ("busy_page_ms", "busy_small_p50_ms", "busy_bulk_mib_s_page", "busy_censored")}
NODE = os.environ.get("E2E_NODE") or shutil.which("node") or "/root/node/bin/node"


def utc(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t if t is not None else time.time()))


def md5(path):
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        return h.hexdigest()
    except OSError:
        return None


def cpu_steal():
    with open("/proc/stat") as f:
        x = [int(v) for v in f.readline().split()[1:9]]
    return sum(x), x[7]


# ---- foreign activity on the box (measurement rule 80.04: a round that overlapped a foreign unit or process is excluded
# and rerun). At each round start / end every process OUTSIDE our own cgroup (the transient unit: driver, servers, target,
# clients) is read from /proc: CPU ticks, name, kernel thread or not, and whether it is our own polling (its command line
# names the kit or out dir). Categories: own-poll, sshd, kthread, other. A round is flagged when "other" used more than
# FOREIGN_OTHER_CORES, sshd more than FOREIGN_SSHD_CORES, or a process of a known benchmark runner ran (FOREIGN_PATTERNS).
# The thresholds are provisional; every round's numbers are in raw.jsonl (event "round"), so a reader can recompute.
FOREIGN_OTHER_CORES, FOREIGN_SSHD_CORES = 0.01, 0.02
FOREIGN_PATTERNS = ("abbox", "wbench", "timebox", "prof.py", "abfan", "finalwisp", "epoxy-server", "perf ", "bpftrace",
                    "tcpdump", "iperf", "wrk", "node ")


def registry_binaries():
    """distinctive names of the servers in bench/servers.json (a foreign run of any registered server also counts): the
    binary's basename, or for an interpreter (python, node, ...) the module after -m / the script after it"""
    try:
        reg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "servers.json")))["servers"]
    except (OSError, ValueError, KeyError):
        return ()
    interp = re.compile(r"(python|node|sh|bash|java|deno|bun)[\d.]*$")
    names = set()
    for x in reg.values():
        toks = [t for t in str(x.get("cmd", "")).split() if t]
        # the program: the first {root}/ token, else the first token that is a path or a bare command
        j = next((k for k, t in enumerate(toks) if t.startswith("{root}/")), 0 if toks and "{" not in toks[0] else None)
        if j is None:
            continue
        base = os.path.basename(toks[j])
        if not interp.match(base):
            names.add(base)
        elif j + 1 < len(toks):
            nxt = toks[j + 2] if toks[j + 1] == "-m" and j + 2 < len(toks) else toks[j + 1]
            if not nxt.startswith("-") and "{" not in nxt:
                names.add(os.path.basename(nxt))
    return tuple(sorted(n for n in names if len(n) >= 4))  # a 1-3 letter name would match anything


FOREIGN_PATTERNS += registry_binaries()
CLK = os.sysconf("SC_CLK_TCK")

# cumulative CPU by cgroup (cgroup v2; includes processes that started and ended inside the round, review P1): the top-level
# groups system.slice / user.slice / init.scope / machine.slice minus our own unit and our own ssh session scope(s)
# (E2E_OWN_SCOPES, set by e2ebox: its multiplexed connection). Kernel threads and softirq sit in the root group: not counted.
CG = "/sys/fs/cgroup"
CG_TOP = ("system.slice", "user.slice", "init.scope", "machine.slice")
FOREIGN_USER_CORES, FOREIGN_SYSTEM_CORES = 0.003, 0.02  # provisional (any foreign ssh session costs > 3 ms/s)


def cg_usage(path):
    try:
        with open(os.path.join(CG, path.lstrip("/"), "cpu.stat")) as f:
            for line in f:
                if line.startswith("usage_usec"):
                    return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


def cg_snapshot(own_cg, out_dir=None):
    """cumulative usage of the top-level groups and of our own groups: our unit, E2E_OWN_SCOPES, and every scope e2ebox's
    polls recorded in OUT/own-scopes (its ssh master can be replaced mid-run: the new session scope is ours too)"""
    own = {own_cg} | {s for s in os.environ.get("E2E_OWN_SCOPES", "").split(",") if s}
    try:
        with open(os.path.join(out_dir, "own-scopes")) as f:
            own |= {x.strip() for x in f if x.strip().startswith("/")}
    except (OSError, TypeError):
        pass
    return {"top": {g: cg_usage(g) for g in CG_TOP}, "own": {p: cg_usage(p) for p in own if p}}


def cg_delta(c0, c1, wall_s):
    """foreign cores per top-level group (group delta minus our own groups under it). None for a group whose counter is
    missing, or where one of our own groups vanished during the round (its CPU cannot be split off: unknown)"""
    if wall_s <= 0:
        return {}
    out = {}
    under = lambda p, g: p.strip("/") == g or p.strip("/").startswith(g + "/")
    for g in CG_TOP:
        a, b = c0["top"].get(g), c1["top"].get(g)
        if a is None or b is None:
            out[g] = None
            continue
        mine, unknown = 0, False
        for p in set(c0["own"]) | set(c1["own"]):
            if not under(p, g):
                continue
            u0, u1 = c0["own"].get(p), c1["own"].get(p)
            if u1 is None and u0 is not None:
                unknown = True  # present at the start, gone at the end
            elif u1 is not None:
                mine += u1 - (u0 or 0)  # new during the round: all of it is ours
        out[g] = None if unknown else round((b - a - mine) / 1e6 / wall_s, 4)
    return out



def own_cgroup():
    try:
        with open("/proc/self/cgroup") as f:
            return f.read().strip().split("::")[-1]
    except OSError:
        return None


def foreign_snapshot(own_cg, own_marks):
    snap = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/cgroup") as f:
                cg = f.read().strip().split("::")[-1]
            if own_cg and cg.startswith(own_cg):
                continue
            with open(f"/proc/{d}/stat") as f:
                s = f.read()
            rp = s.rindex(")")
            comm, fields = s[s.index("(") + 1:rp], s[rp + 2:].split()
            ppid, ticks, start = int(fields[1]), int(fields[11]) + int(fields[12]), int(fields[19])
            with open(f"/proc/{d}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace")[:300]
        except (OSError, ValueError, IndexError):
            continue
        kind = ("kthread" if (ppid == 2 or int(d) == 2) and not cmd else "own-poll" if any(m in cmd for m in own_marks)
                else "sshd" if comm == "sshd" or cmd.startswith("sshd") else "other")
        snap[(int(d), start)] = (ticks, comm, kind, cmd)
    return snap


def foreign_delta(s0, s1, wall_s, cg0=None, cg1=None):
    """per category cores used between two snapshots (new processes count with all their ticks), top 'other' processes"""
    use, top = {"own-poll": 0, "sshd": 0, "kthread": 0, "other": 0}, []
    for k, (t1, comm, kind, cmd) in s1.items():
        dt = t1 - (s0[k][0] if k in s0 else 0)
        if dt <= 0:
            continue
        use[kind] += dt
        if kind in ("other", "sshd"):
            top.append((dt, comm, cmd[:80]))
    cores = {k: round(v / CLK / wall_s, 4) for k, v in use.items()} if wall_s > 0 else {}
    top.sort(reverse=True)
    pat = [c for _, comm, c in top if any(p in (comm + " " + c) for p in FOREIGN_PATTERNS)]
    cgd = cg_delta(cg0, cg1, wall_s) if cg0 and cg1 else {}
    if cgd.get("user.slice") is not None and cgd.get("system.slice") is not None:
        # the cgroup counters see every process, also short-lived ones; the /proc scan names the long-lived ones
        flag = (cgd["user.slice"] > FOREIGN_USER_CORES or (cgd.get("machine.slice") or 0) > FOREIGN_USER_CORES
                or cgd["system.slice"] + (cgd.get("init.scope") or 0) > FOREIGN_SYSTEM_CORES or bool(pat))
    else:  # a needed counter is missing or unknown: the /proc rule decides
        flag = (cores.get("other", 0) > FOREIGN_OTHER_CORES or cores.get("sshd", 0) > FOREIGN_SSHD_CORES or bool(pat))
    flag = flag and bool(os.environ.get("E2E_BOX"))  # box mode only (e2ebox sets E2E_BOX); a laptop smoke records, never flags
    return {"foreign_cgroup_cores": cgd, "foreign_cores": cores, "foreign_top": [[c, round(1000 * t / CLK), x] for t, c, x in top[:5]],
            "foreign_runner": pat[:3], "flag": flag}


# OVERLAP check (optional): E2E_OVERLAP = a JSONL file of {box, start, end, who[, what]} windows in which someone touched a
# box outside its lock; E2E_OVERLAP_SELF = our own "who" (our windows are outside our sessions by construction). Unset: no check.
OVERLAP = os.environ.get("E2E_OVERLAP")
OWNER_NAME = os.environ.get("E2E_OVERLAP_SELF", "")


def overlap_exclusions(meta, raw):
    """measurement rule (2026-11-19): rounds whose time span overlaps a FOREIGN window of OVERLAP.jsonl on the session's box
    (someone touched the box outside its lock) are excluded. Span of a round: its 'round' event (t0, t1), else the
    first client start to the last client end of that round. Read at analysis time, so a rerun of --table picks up windows
    reported later. Our own windows (who = E2E_OVERLAP_SELF) happened outside our sessions by construction and are skipped."""
    box = meta.get("box")
    if not OVERLAP:
        return {}
    try:
        lines = open(OVERLAP).read().splitlines()
    except OSError:
        return {}
    ts_ = lambda s: datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    wins = []
    for n_, l in enumerate(lines, 1):  # one bad or half-written line is skipped (with a warning), not fatal
        if not l.strip():
            continue
        try:
            w = json.loads(l)
            if not all(isinstance(w.get(k), str) for k in ("box", "start", "end", "who")):
                raise ValueError("box / start / end / who missing")
            if w["box"] == box and w["who"] != OWNER_NAME:
                wins.append((ts_(w["start"]), ts_(w["end"]) + 1, w))
        except (ValueError, KeyError, TypeError, AttributeError) as e_:
            print(f"warning: {OVERLAP}:{n_} skipped: {e_}", file=sys.stderr)
    if not wins:
        return {}
    span = {}
    for r in raw:
        if r.get("event") == "round":
            span[r["round"]] = (r["t0"], r["t1"])
    for r in raw:
        if "client" in r and r.get("round") not in span and r.get("t0") is not None:
            a_, b_ = span.get(("c", r["round"]), (r["t0"], r.get("t1") or r["t0"]))
            span[("c", r["round"])] = (min(a_, r["t0"]), max(b_, r.get("t1") or r["t0"]))
    out = {}
    for k, (a_, b_) in span.items():
        rnd = k[1] if isinstance(k, tuple) else k
        hit = [w for s, e_, w in wins if s < b_ and e_ > a_]
        if hit:
            out[str(rnd)] = "overlaps OVERLAP.jsonl: " + "; ".join(f"{w['who']} {w['start'][11:]}-{w['end'][11:]} {str(w.get('what', ''))[:50]}" for w in hit[:3])
    return out


def isolation(out, raw, meta):
    """what the session unit was limited to (OUT/kit.json unit_limits, written by e2ebox from systemctl show) and the foreign
    load the per-round check saw (cgroup cores outside our unit, clean rounds), so a box run is not read as isolated.
    e2ebox caps memory and tasks only; CPU and I/O are shared with the other units on the box."""
    try:
        lim = json.load(open(os.path.join(out, "kit.json"))).get("unit_limits")
    except (OSError, ValueError):
        lim = None
    cpu_io = None  # a ceiling only: CPU quota, a CPU set or an I/O bandwidth max (CPUWeight / IOWeight are relative priorities)
    if lim:
        cpu_io = (lim.get("CPUQuotaPerSecUSec", "infinity") != "infinity" or bool(lim.get("AllowedCPUs"))
                  or bool(lim.get("IOReadBandwidthMax")) or bool(lim.get("IOWriteBandwidthMax")))
    excl = meta.get("excluded_rounds", {})
    fc = [r.get("foreign_cgroup_cores") or {} for r in raw
          if r.get("event") == "round" and not r.get("incomplete") and str(r.get("round")) not in excl]
    load = {}
    for g in ("system.slice", "user.slice", "init.scope", "machine.slice"):
        xs = [x[g] for x in fc if isinstance(x.get(g), (int, float))]
        if xs:
            load[g] = {"median": round(st.median(xs), 4), "max": round(max(xs), 4), "rounds": len(xs)}
    return {"unit_limits": lim, "cpu_io_capped": cpu_io, "foreign_cores_clean_rounds": load or None}


def isolation_line(iso):
    if not iso:
        return ""
    lim = iso.get("unit_limits")
    if lim:
        mm = lim.get("MemoryMax", "?")
        mm = f"{int(mm) // 2**20} MiB" if str(mm).isdigit() else mm
        s = (f"unit limits: MemoryMax {mm}, MemorySwapMax {lim.get('MemorySwapMax', '?')}, TasksMax {lim.get('TasksMax', '?')}; "
             f"CPUQuota {lim.get('CPUQuotaPerSecUSec', '?')}, CPUWeight {lim.get('CPUWeight', '?')}, IOWeight {lim.get('IOWeight', '?')}"
             + (": CPU and I/O NOT capped" if not iso.get("cpu_io_capped") else "")
             + "; the run is not isolated from other units on the box (shared cores, disk and network)")
    else:
        s = "unit limits: not recorded (no memory cap known; CPU and I/O not capped): not isolated"
    fl = iso.get("foreign_cores_clean_rounds")
    if fl:
        s += ". Foreign load in clean rounds (cores, median / max): " + ", ".join(f"{g} {v['median']} / {v['max']}" for g, v in fl.items())
    return s


def host_snapshot():
    d = {"t": round(time.time(), 1), "load1": os.getloadavg()[0], "nproc": os.cpu_count(), "kernel": os.uname().release}
    try:
        from wispsuite import hoststate
        try:
            with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
                eph = tuple(int(x) for x in f.read().split())
        except (OSError, ValueError):
            eph = (32768, 60999)
        s, _ = hoststate.sample(None, eph)
        for k in ("psi_cpu", "psi_mem", "mem_avail_mb", "tcp_inuse", "tcp_tw", "tcp_mem_pages", "TCPMemoryPressures", "procs"):
            if k in s:
                d[k] = s[k]
    except Exception as e:  # the sampler is optional; its absence is recorded, not fatal
        d["hoststate_error"] = str(e)[:200]
    return d


def server_binary(spec, srv):
    """the executable of an arm (for the md5 in the summary): fw:PATH, or the first word of the registry command"""
    if spec.startswith("fw:"):
        return os.path.abspath(spec[3:].split(" ", 1)[0])
    cmd, _ = srv.command(1, srvmod.SCRATCH)
    words = cmd.split()
    w = words[1] if words and words[0] == "exec" and len(words) > 1 else (words[0] if words else "")
    return w if os.path.isabs(w) else None


class Target:
    def __init__(self, out, base):
        self.out, self.base, self.p = out, base, None
        self.certs = os.path.join(out, "certs")
        if not os.path.exists(os.path.join(self.certs, "ca.pem")):
            r = subprocess.run(["bash", os.path.join(HERE, "mkcerts.sh"), self.certs], capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                raise SystemExit(f"mkcerts failed: {r.stderr[-400:]}")

    def alive(self):
        return self.p is not None and self.p.poll() is None

    def start(self):
        for port in range(self.base, self.base + 60):
            if not proc.wait_free(port, 10):
                raise SystemExit(f"target port {port} has a listener (not ours?): refusing")
        log = open(os.path.join(self.out, "target.log"), "ab")
        self.p = subprocess.Popen([NODE, os.path.join(HERE, "target.mjs"), self.certs, str(self.base), "--watch-stdin"], cwd=HERE,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, start_new_session=True, text=True)
        line = self.p.stdout.readline()
        if not line.startswith("READY"):
            raise SystemExit(f"target did not start: {line!r} (see target.log)")
        return self.p.pid

    def stop(self):
        if self.alive():
            try:
                os.killpg(self.p.pid, signal.SIGTERM)
                self.p.wait(5)
            except Exception:
                try:
                    os.killpg(self.p.pid, signal.SIGKILL)
                except OSError:
                    pass


def start_pcap(path, port):
    """tcpdump of the Wisp port on lo (diagnostic rounds only: --pcap-round); None if tcpdump is not there"""
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return None
    p = subprocess.Popen([tcpdump, "-i", "lo", "-s", "0", "-U", "-n", "-w", path, f"tcp port {port}"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    t0 = time.time()
    while not os.path.exists(path) and time.time() - t0 < 5:
        time.sleep(0.05)
    time.sleep(0.5)
    return p


def stop_pcap(p):
    if p is not None:
        try:
            os.killpg(p.pid, signal.SIGINT)
            p.wait(5)
        except Exception:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass


# ---- server metrics (optional): an arm 'fw:PATH ... --metrics-listen PORT' is scraped (GET /metrics) before and after each
# client process; the record keeps the counters that changed (ping gate, close codes, ...). Counts only, no timing.
def metrics_addr(spec):
    """(host, port) of the --metrics-listen option in an arm's server spec, else None"""
    toks = spec.split()
    for k, t in enumerate(toks):
        v = toks[k + 1] if t == "--metrics-listen" and k + 1 < len(toks) else t.split("=", 1)[1] if t.startswith("--metrics-listen=") else None
        if v is not None:
            host, _, port = v.rpartition(":")
            return (host or "127.0.0.1", int(port))
    return None


def scrape(addr, tries=1):
    """{sample name with labels: value} of every *_total counter and the finalwisp_connections / finalwisp_streams gauges at
    GET /metrics; None when it cannot be read or holds no counter"""
    import urllib.request
    text = None
    for k in range(tries):
        try:
            with urllib.request.urlopen(f"http://{addr[0]}:{addr[1]}/metrics", timeout=3) as r:
                text = r.read().decode()
            break
        except OSError:
            if k + 1 < tries:
                time.sleep(0.1)
    if text is None:
        return None
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, val = line.rpartition(" ")
        base = name.split("{")[0]
        if base.endswith("_total") or base in ("finalwisp_connections", "finalwisp_streams"):
            try:
                out[name] = float(val)
            except ValueError:
                pass
    return out if any(k.endswith("_total") for k in out) else None


GATE_NAMES = tuple(f"finalwisp_ping_gate_{g}_total" for g in ("held", "released", "capped", "dropped", "full", "nopong", "browser", "pings"))


def gate_live(m):
    """CLOSEs the ping gate still holds (each held one ends as released, capped or dropped)"""
    return m.get("finalwisp_ping_gate_held_total", 0) - sum(m.get(f"finalwisp_ping_gate_{k}_total", 0) for k in ("released", "capped", "dropped"))


def quiet(m):
    """the server holds nothing for the run that just ended: no connection, no stream, no held CLOSE"""
    return m.get("finalwisp_connections", 0) == 0 and m.get("finalwisp_streams", 0) == 0 and gate_live(m) == 0


def stable_view(m):
    """the counters that only work moves (time-driven ones and the scrape counter itself left out)"""
    return {k: v for k, v in m.items() if "seconds" not in k and "metrics_scrapes" not in k}


def settle(addr, settle_s=4.0):
    """the first of two consecutive scrapes (0.1 s apart) that are quiet and equal in every counter, within settle_s
    (monotonic; scrape retries included). -> (snapshot or None, settled)"""
    t_end, prev = time.monotonic() + settle_s, None
    while True:
        cur = scrape(addr)
        if cur is not None and prev is not None and quiet(cur) and stable_view(cur) == stable_view(prev):
            return cur, True
        if time.monotonic() > t_end:
            return cur, False
        prev = cur
        time.sleep(0.1)


def metrics_delta(addr, before, settle_s=4.0):
    """after a client process: settle (see settle), then the counters that changed since 'before'. A counter that went down
    (a restart or a reset) or a gate counter present in only one snapshot makes the record invalid."""
    after, settled = settle(addr, settle_s)
    if before is None or after is None:
        return {"error": "metrics endpoint not readable", "settled": settled}
    d, bad = {}, []
    for k in set(after) | set(before):
        if k in ("finalwisp_connections", "finalwisp_streams") or k.startswith("finalwisp_memory_level_seconds_total"):
            continue
        x = after.get(k, 0) - before.get(k, 0)
        if x < 0 or (k in GATE_NAMES and (k in before) != (k in after)):
            bad.append(k)
        if x:
            d[k] = int(x) if float(x).is_integer() else round(x, 6)
    gate_before, gate_after = all(k in before for k in GATE_NAMES), all(k in after for k in GATE_NAMES)
    return {"delta": d, "settled": settled, "gate_counters": gate_after, "gate_counters_before": gate_before,
            "invalid": sorted(bad), "quiet_before": quiet(before)}

def run_client(a, client, workload, wisp_port, target, server_pgid, epoxy_pkg=None):
    cmd = [NODE, os.path.join(HERE, "client.mjs"), "--client", client, "--wisp", f"ws://127.0.0.1:{wisp_port}/",
           "--base", str(a.port_base + 10), "--ca", os.path.join(target.certs, "ca.pem"), "--workloads", workload,
           "--target-pid", str(target.p.pid), "--timeout-s", str(a.timeout_s)]
    if server_pgid:
        cmd += ["--server-pgid", str(server_pgid)]
    if a.quick:
        cmd.append("--quick")
    if workload.startswith("closefail") and client.startswith("epoxy"):  # the chromium clients tap inside the page
        cmd.append("--wslog")
    if epoxy_pkg and client.startswith("epoxy"):  # --epoxy-pkg: this arm's Node epoxy clients load another epoxy-tls build
        cmd += ["--epoxy-pkg", epoxy_pkg]
    t0 = time.time()
    c0, s0 = cpu_steal()
    try:
        r = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True, timeout=a.timeout_s + 30, start_new_session=True)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = None, (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), "hard timeout"
    c1, s1 = cpu_steal()
    rec = {"t0": round(t0, 3), "t1": round(time.time(), 3), "proc_wall_ms": round(1000 * (time.time() - t0)), "rc": rc,
           "steal_share": round((s1 - s0) / (c1 - c0), 4) if c1 > c0 else None, "load1": os.getloadavg()[0]}
    res = None
    for line in out.splitlines():
        if line.startswith("{"):
            try:
                res = json.loads(line)
            except ValueError:
                pass
    if res is None:
        rec["error"] = f"no result (rc {rc}): {err.strip()[-300:]}"
    else:
        rec["res"] = res
    return rec


def run(a):
    os.makedirs(a.out, exist_ok=True)
    arms = []
    for x in a.arm:
        label, _, spec = x.partition("=")
        if not spec or "=" in label:
            raise SystemExit(f"--arm {x}: LABEL=SPEC")
        arms.append((label, spec))
    if len(arms) < 1 or len({l for l, _ in arms}) != len(arms):
        raise SystemExit("arms need unique labels")
    reg = srvmod.load()
    srvs = {l: srvmod.resolve(s, reg) for l, s in arms}
    maddr = {l: metrics_addr(s) for l, s in arms if s.startswith("fw:") and metrics_addr(s)}
    for l, (_, mp) in maddr.items():  # not a port of the server, the target or the browser page
        if mp == a.port_base + 1 or a.port_base + 10 <= mp <= a.port_base + 80:  # +80: the browser clients' page server
            raise SystemExit(f"arm {l}: --metrics-listen {mp} collides with the run's ports (base+1, base+10..+80)")
    clients = a.clients.split(",")
    srv_clients = [c for c in clients if c != "direct"]
    workloads = a.workloads.split(",")
    meta_path = os.path.join(a.out, "meta.json")
    meta = {"layer": LAYER, "tool": TOOL, "started_utc": utc(), "box": os.environ.get("E2E_BOX") or os.uname().nodename, "t_start": time.time(), "arms": [], "clients": clients,
            "workloads": workloads, "rounds": a.rounds, "quick": a.quick, "port_base": a.port_base, "order": a.order,
            "node": subprocess.run([NODE, "--version"], capture_output=True, text=True).stdout.strip(), "argv": sys.argv[1:],
            "host_start": host_snapshot(), "client_md5": md5(os.path.join(HERE, "client.mjs")), "target_md5": md5(os.path.join(HERE, "target.mjs"))}
    # --epoxy-pkg LABEL=DIR: the Node epoxy clients of arm LABEL load DIR/epoxy.js + DIR/epoxy.wasm instead of the npm build
    # (a client-side variant against the same server: label the arm accordingly); other clients are unchanged
    # The pair is copied once into OUT/epoxy-pkg-LABEL/ (epoxy.js as epoxy.mjs: ES module whatever package scope the source
    # sits in) and every round loads that copy, so the recorded md5s are the bytes every client ran.
    epkg, epkg_md5 = {}, {}
    if os.path.exists(meta_path):
        raise SystemExit(f"{meta_path} exists: use a new OUT (resume is not supported)")
    for x in a.epoxy_pkg:
        l, _, d = x.partition("=")
        d = os.path.realpath(d) if d else ""
        if l not in {l_ for l_, _ in arms} or l in epkg or not all(os.path.isfile(os.path.join(d, f)) for f in ("epoxy.js", "epoxy.wasm")):
            raise SystemExit(f"--epoxy-pkg {x}: LABEL of an arm (once) = a DIR with epoxy.js and epoxy.wasm")
        snap = os.path.join(a.out, f"epoxy-pkg-{re.sub(r'[^A-Za-z0-9_.-]', '_', l)}")
        os.makedirs(snap)
        shutil.copyfile(os.path.join(d, "epoxy.js"), os.path.join(snap, "epoxy.mjs"))
        shutil.copyfile(os.path.join(d, "epoxy.wasm"), os.path.join(snap, "epoxy.wasm"))
        epkg[l] = snap
        epkg_md5[l] = {"source": d, "dir": snap, "epoxy.js": md5(os.path.join(snap, "epoxy.mjs")), "epoxy.wasm": md5(os.path.join(snap, "epoxy.wasm"))}
    npm_dir = os.path.join(HERE, "node_modules", "@mercuryworkshop", "epoxy-tls", "full")
    meta["epoxy_npm"] = {f: md5(os.path.join(npm_dir, f)) for f in ("epoxy.js", "epoxy.wasm") if os.path.isfile(os.path.join(npm_dir, f))}
    for l, s in arms:
        b = server_binary(s, srvs[l])
        meta["arms"].append({"label": l, "spec": s, "path": b, "md5": md5(b) if b else None,
                             **({"epoxy_pkg": epkg_md5[l]} if l in epkg else {})})
    if os.path.exists(meta_path):
        raise SystemExit(f"{meta_path} exists: use a new OUT (resume is not supported)")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=1)
    target = Target(a.out, a.port_base + 10)
    target.start()
    port = a.port_base + 1
    rng = random.Random(a.seed)
    slots = [l for l, _ in arms] + (["direct"] if "direct" in clients else [])
    raw = open(os.path.join(a.out, "raw.jsonl"), "a")
    t_start = time.time()
    own_cg, own_marks = own_cgroup(), (os.path.abspath(a.out), HERE)
    max_rounds = a.rounds + (max(2, a.rounds // 4) if a.replace_flagged else 0)
    clean = rnd = 0
    try:
        while clean < a.rounds and rnd < max_rounds:
            if os.path.exists(os.path.join(a.out, "STOP")):
                print(f"STOP file: ending before round {rnd} (0-based)", flush=True)
                break
            if os.path.exists(os.path.join(a.out, "PAUSE")):  # box hand-over at a ROUND boundary (both arms of a pair on one side)
                target.stop()
                with open(os.path.join(a.out, "PAUSED"), "w") as f:
                    f.write(utc() + "\n")
                print(f"PAUSE before round {rnd} at {utc()}", flush=True)
                while os.path.exists(os.path.join(a.out, "PAUSE")):
                    time.sleep(2)
                os.remove(os.path.join(a.out, "PAUSED"))
                raw.write(json.dumps({"event": "paused", "round": rnd, "t": time.time()}) + "\n")
                target.start()
            # rotation by the CLEAN round count: kept rounds stay balanced, and a replacement repeats the order it replaces
            order = slots[clean % len(slots):] + slots[:clean % len(slots)] if a.order == "rotate" else rng.sample(slots, len(slots))
            fs0, cg0, ft0 = foreign_snapshot(own_cg, own_marks), cg_snapshot(own_cg, a.out), time.time()
            incomplete = False  # a server that did not start or died: the round does not count as clean (replaced)
            for slot, label in enumerate(order):
                if not target.alive():
                    target.start()
                    raw.write(json.dumps({"event": "target restarted", "round": rnd, "t": time.time()}) + "\n")
                base = {"round": rnd, "slot": slot, "arm": label}
                if label == "direct":
                    for w in workloads:
                        rec = run_client(a, "direct", w, port, target, 0)
                        raw.write(json.dumps({**base, "client": "direct", "w": w, **rec}) + "\n")
                    raw.flush()
                    continue
                if not proc.wait_free(port, 30):
                    raise SystemExit(f"server port {port} still has a listener")
                try:
                    p = srvs[label].start(port, srvmod.SCRATCH, log=os.path.join(a.out, f"server-{label}.log"))
                except RuntimeError as e:
                    raw.write(json.dumps({**base, "event": "server did not start", "error": str(e)}) + "\n")
                    raw.flush()
                    incomplete = True
                    continue
                time.sleep(0.5)  # every worker has bound (as wst ab / showpair)
                recs = []
                try:
                    for c in srv_clients:
                        for w in workloads:
                            pc = None
                            if clean == a.pcap_round and w.startswith("closefail"):  # re-armed if the carrying round gets excluded
                                pc = start_pcap(os.path.join(a.out, f"pcap-{label}-{c}-r{rnd}.pcap"), port)
                            try:
                                mb = settle(maddr[label])[0] if maddr.get(label) else None  # a clean boundary (quiet_before)
                                rec = run_client(a, c, w, port, target, p.pid, epkg.get(label))
                                if maddr.get(label):
                                    rec["metrics"] = metrics_delta(maddr[label], mb)
                            finally:
                                stop_pcap(pc)
                            if pc is not None:
                                rec["pcap"] = f"pcap-{label}-{c}-r{rnd}.pcap"
                            rec["server_alive"] = p.poll() is None
                            recs.append({**base, "client": c, "w": w, **rec})
                            if not rec["server_alive"]:
                                break
                        if p.poll() is not None:
                            break
                finally:
                    alive = p.poll() is None
                    proc.stop(p)
                for r in recs:
                    if not alive or not r["server_alive"]:
                        r["server_died"] = True
                        incomplete = True
                    raw.write(json.dumps(r) + "\n")
                raw.flush()
            fr = foreign_delta(fs0, foreign_snapshot(own_cg, own_marks), time.time() - ft0, cg0, cg_snapshot(own_cg, a.out))
            raw.write(json.dumps({"event": "round", "round": rnd, "t0": round(ft0, 3), "t1": round(time.time(), 3), "incomplete": incomplete, **fr}) + "\n")
            raw.flush()
            clean += 0 if fr["flag"] or incomplete else 1
            print(f"round {rnd} (0-based) done at {round(time.time() - t_start)} s ({clean}/{a.rounds} clean)"
                  + (f"; FOREIGN activity, excluded: {fr['foreign_cores']} {fr['foreign_top'][:2]}" if fr["flag"] else ""), flush=True)
            rnd += 1
    finally:
        raw.close()
        target.stop()
    meta["host_end"] = host_snapshot()
    meta["wall_s"] = round(time.time() - t_start, 1)
    meta["rounds_attempted"], meta["rounds_clean"] = rnd, clean
    if clean < a.rounds:
        print(f"ONLY {clean} CLEAN ROUNDS of {a.rounds} wanted ({rnd} attempted): STOP, cap or replacement budget", flush=True)
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=1)
    summary, table = analyse(a.out)
    write(a.out, summary, table)
    print(table)
    print(f"wall time: {meta['wall_s']} s")
    with open(os.path.join(a.out, "DONE"), "w") as f:
        f.write(utc() + "\n")


# ---------------- analysis (pure: raw.jsonl + meta.json -> summary, table) ----------------
def higher_better(metric):
    return metric.endswith(HIGHER) or "_mib_s_" in metric  # busy_bulk_mib_s_page / _all are throughputs too


def load_raw(out):
    recs = []
    with open(os.path.join(out, "raw.jsonl")) as f:
        for line in f:
            if line.strip():
                recs.append(json.loads(line))
    return recs


def good(r):
    return "res" in r and r["res"].get("ok") and not r.get("server_died") and r.get("rc") == 0


def fmt(x):
    if x is None:
        return "-"
    return f"{x:.3g}" if abs(x) < 1000 else f"{x:.0f}"


def collect(out):
    """raw.jsonl -> (meta, vals[(arm, client, w)][metric][round], share[(arm, client, w)] = [(client main, server, target,
    client process) CPU per wall second, ...], fails[(arm, client, w)] = [error, ...], wall[(client, w)] = seconds)"""
    meta = json.load(open(os.path.join(out, "meta.json")))
    raw = load_raw(out)
    # excluded rounds (measurement rule): flagged by the foreign-activity check, or listed by hand in OUT/excluded.json
    # {"<round>": "why", ...} (an incident found another way); their runs count in no comparison
    excl = {str(r["round"]): f"foreign activity on the box: cgroup {r.get('foreign_cgroup_cores')} procs {r.get('foreign_cores')} {r.get('foreign_top', [])[:2]}"
            for r in raw if r.get("event") == "round" and r.get("flag")}
    if os.path.exists(os.path.join(out, "excluded.json")):
        excl.update({str(k): v for k, v in json.load(open(os.path.join(out, "excluded.json"))).items()})
    excl.update(overlap_exclusions(meta, raw))
    meta["excluded_rounds"] = excl
    recs = [r for r in raw if "client" in r and str(r.get("round")) not in excl]
    vals, share, fails, wall = {}, {}, {}, {}
    for r in recs:
        key = (r["arm"], r["client"], r["w"])
        wall[(r["client"], r["w"])] = wall.get((r["client"], r["w"]), 0) + r.get("proc_wall_ms", 0) / 1000
        if not good(r):
            fails.setdefault(key, []).append(r.get("error") or r.get("res", {}).get("error") or ("server died" if r.get("server_died") else f"rc {r.get('rc')}"))
            continue
        res = r["res"]
        m = dict(res.get("m") or {})
        cpu = res.get("cpu") or {}
        m["client_cpu_ms"] = cpu.get("client_ms")
        if r["client"] != "direct":
            m["server_cpu_ms"] = cpu.get("server_ms")
        for k, v in m.items():
            if v is not None:
                vals.setdefault(key, {}).setdefault(k, {})[r["round"]] = v
        if res.get("wall_ms"):
            main = cpu.get("client_main_ms")
            share.setdefault(key, []).append(((main if main is not None else cpu.get("client_ms", 0)) / res["wall_ms"],
                                              (cpu.get("server_ms") or 0) / res["wall_ms"], (cpu.get("target_ms") or 0) / res["wall_ms"],
                                              cpu.get("client_ms", 0) / res["wall_ms"]))
    return meta, vals, share, fails, wall


def analyse(out):
    meta, vals, share, fails, wall = collect(out)
    labels = [x["label"] for x in meta["arms"]]
    ref = labels[0]
    rows = []
    pairs_ws = sorted({(c, w) for (_, c, w) in vals if c != "direct"}, key=lambda x: (meta["clients"].index(x[0]), meta["workloads"].index(x[1])))

    def note_for(c, w, arm):
        s = share.get((arm, c, w))
        if not s:
            return ""
        cl, sv, tg, cp = (st.median(x[i] for x in s) for i in range(4))
        txt = f"cpu/wall: client main thread {cl:.2f} (process {cp:.2f}), server {sv:.2f}, target {tg:.2f}"
        if cl >= CLIENT_BOUND:
            txt = "client-bound (client main thread >= 0.85 of a core): a tie here means this benchmark did not establish a server effect for this client, not that the servers are equal (the fault-kit rows say how large a server change it can still detect); " + txt
        return txt

    for other in labels[1:]:
        for c, w in pairs_ws:
            ka, kb = (ref, c, w), (other, c, w)
            for metric in sorted(set(vals.get(ka, {})) | set(vals.get(kb, {}))):
                av, bv = vals.get(ka, {}).get(metric, {}), vals.get(kb, {}).get(metric, {})
                rounds = sorted(set(av) & set(bv))
                A, B = [av[i] for i in rounds], [bv[i] for i in rounds]
                hb = higher_better(metric)
                cmp = stats.compare(A, B, hb) if len(rounds) >= 2 else None
                row = {"cell": f"{c}/{w}" + (f" [{other}]" if len(labels) > 2 else ""), "metric": metric,
                       "unit": "MiB/s" if "_mib_s" in metric else "1/s" if metric.endswith("_per_s") else "%" if metric.endswith("_pct") else "x" if metric.endswith("slowdown") else "ms",
                       "a": stats.median(A, 3) if A else None, "b": stats.median(B, 3) if B else None, "n": len(rounds),
                       "ratio": None, "ci_lo": None, "ci_hi": None, "verdict": None, "higher_better": hb}
                if cmp:
                    row.update(ratio=cmp["ratio"], verdict=cmp["verdict"], p=cmp["p"])
                    if cmp["ci90"]:
                        row["ci_lo"], row["ci_hi"] = cmp["ci90"]
                elif len(rounds) >= 2:  # zeros (e.g. a loss share of 0): a paired signed-rank test on the differences, no ratio
                    p = stats.wilcoxon(B, A)
                    d = st.median([y - x for x, y in zip(A, B)])
                    if all(x == y for x, y in zip(A, B)):
                        row["verdict"] = "tie"
                    elif p < stats.ALPHA:
                        row["verdict"] = "WIN" if (d > 0) == hb else "LOSS"
                    else:
                        row["verdict"] = "unclear"
                    row.update(p=round(p, 3), diff_median=d)
                    row["note"] = "values <= 0: paired difference test, no ratio"
                sh = share.get(ka)
                if sh:
                    row["client_cpu_share"] = round(st.median(x[0] for x in sh), 2)
                    row["server_cpu_share"] = round(st.median(x[1] for x in sh), 2)
                if metric not in ("client_cpu_ms", "server_cpu_ms"):
                    nb = note_for(c, w, ref)
                    if nb:
                        row["note"] = (row.get("note", "") + "; " if row.get("note") else "") + nb
                fl = vals.get(("direct", "direct", w), {}).get(metric) if metric not in ("server_cpu_ms",) else None
                if fl and c != "direct":
                    row["floor_direct"] = stats.median(list(fl.values()), 3)
                fa, fb = len(fails.get(ka, [])), len(fails.get(kb, []))
                if fa or fb:
                    row["failed_runs"] = [fa, fb]
                rows.append(row)
    try:  # e2ebox.py: shipped binaries are debug-stripped copies; map them back to the originals by their kit path
        ship = json.load(open(os.path.join(out, "ship.json")))
    except (OSError, ValueError):
        ship = {}
    for x in meta["arms"]:
        p = x.get("path") or ""
        kp = p.split("/kit/", 1)[1] if "/kit/" in p else None
        if kp in ship and ship[kp].get("ship_md5") == x.get("md5"):
            x["md5_original"] = ship[kp]["md5"]
    summary = {"layer": LAYER, "tool": TOOL,
               "a": {"label": ref, "path": meta["arms"][0]["path"], "md5": meta["arms"][0].get("md5_original") or meta["arms"][0]["md5"],
                     "md5_shipped": meta["arms"][0]["md5"]},
               "b": ({"label": labels[1], "path": meta["arms"][1]["path"], "md5": meta["arms"][1].get("md5_original") or meta["arms"][1]["md5"],
                      "md5_shipped": meta["arms"][1]["md5"]} if len(labels) == 2 else None),
               "arms": meta["arms"], "box": meta.get("box") or os.uname().nodename, "started_utc": meta["started_utc"],
               "wall_s": meta.get("wall_s"), "host_state": {"start": meta.get("host_start"), "end": meta.get("host_end")},
               "clients": meta["clients"], "workloads": meta["workloads"], "rounds": meta["rounds"], "quick": meta["quick"],
               "rounds_attempted": meta.get("rounds_attempted"), "rounds_clean": meta.get("rounds_clean"),
               "wall_by_client_workload_s": {f"{c}/{w}": round(v, 1) for (c, w), v in sorted(wall.items())},
               "failures": {f"{a_}/{c}/{w}": e[:5] + ([f"... {len(e) - 5} more"] if len(e) > 5 else []) for (a_, c, w), e in sorted(fails.items())},
               "excluded_rounds": meta.get("excluded_rounds", {}),
               "isolation": isolation(out, load_raw(out), meta),
               "rows": rows}
    if summary["excluded_rounds"]:  # the note key of every row says which rounds were left out and why
        ex = "excluded rounds " + "; ".join(f"{k}: {v}" for k, v in sorted(summary["excluded_rounds"].items(), key=lambda kv: int(kv[0])))
        for r in rows:
            r["note"] = (r.get("note", "") + ("; " if r.get("note") else "") + ex)[:2000]
    return summary, table_md(summary, meta)


def table_md(s, meta):
    L = [f"# e2e {', '.join(x['label'] for x in s['arms'])} on {s['box']} ({s['started_utc']}, {s['rounds']} rounds wanted"
         + (f", {s['rounds_clean']} clean of {s['rounds_attempted']} attempted" if s.get("rounds_clean") is not None else "")
         + f"{', quick' if s['quick'] else ''}; wall {s['wall_s']} s)", "",
         "arms: " + "; ".join(f"{x['label']} = {x['spec']} (md5 {(x.get('md5_original') or x['md5'] or '-')[:8]}"
                              f"{', shipped stripped ' + x['md5'][:8] if x.get('md5_original') else ''})"
                              + (f" + epoxy clients from {os.path.basename(x['epoxy_pkg'].get('source') or x['epoxy_pkg']['dir'])} (epoxy.wasm {x['epoxy_pkg']['epoxy.wasm'][:8]},"
                                 f" epoxy.js {x['epoxy_pkg']['epoxy.js'][:8]})" if x.get("epoxy_pkg") else "") for x in s["arms"]),
         f"node {meta.get('node')}, client.mjs {(meta.get('client_md5') or '-')[:8]}, target.mjs {(meta.get('target_md5') or '-')[:8]}", "",
         *([isolation_line(s.get("isolation")), ""] if s.get("isolation") else []),
         "## Headline (key metrics; client CPU = the client's main thread busy share over the workload, from arm a; at >= 0.85 the client is",
         "saturated and server effects can hide behind it; a tie does not prove the server is invisible: the fault-kit runs say how much it can see)", "",
         "| cell | metric | a | b | b/a | 90% CI | verdict | n | direct floor | client CPU |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in s["rows"]:
        w = r["cell"].split("/", 1)[1].split(" ")[0]
        if r["metric"] in KEY.get(w, ()):
            ci = f"[{r['ci_lo']}, {r['ci_hi']}]" if r.get("ci_lo") is not None else "-"
            L.append(f"| {r['cell']} | {r['metric']} | {fmt(r['a'])} | {fmt(r['b'])} | {r['ratio'] if r['ratio'] is not None else '-'} | {ci} | "
                     f"{r['verdict'] or '-'} | {r['n']} | {fmt(r.get('floor_direct'))} | {r.get('client_cpu_share', '-')} |")
    L += ["", "## All rows", "", "| cell | metric | a | b | b/a | 90% CI | verdict | n | direct floor | note |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in s["rows"]:
        ci = f"[{r['ci_lo']}, {r['ci_hi']}]" if r.get("ci_lo") is not None else "-"
        L.append(f"| {r['cell']} | {r['metric']} | {fmt(r['a'])} | {fmt(r['b'])} | {r['ratio'] if r['ratio'] is not None else '-'} | {ci} | "
                 f"{r['verdict'] or '-'} | {r['n']} | {fmt(r.get('floor_direct'))} | {r.get('note', '')}{' failed runs ' + str(r['failed_runs']) if r.get('failed_runs') else ''} |")
    if s["failures"]:
        L += ["", "Failed client runs (arm/client/workload: first errors):"]
        L += [f"- {k}: {v}" for k, v in s["failures"].items()]
    if s.get("excluded_rounds"):
        L += ["", "Excluded rounds (measurement rule: foreign activity on the box, or listed in excluded.json):"]
        L += [f"- round {k}: {v}" for k, v in sorted(s["excluded_rounds"].items(), key=lambda kv: int(kv[0]))]
    L += ["", "Wall time per client/workload (both arms, all rounds, client processes only): " +
          ", ".join(f"{k} {v} s" for k, v in s["wall_by_client_workload_s"].items())]
    return "\n".join(L) + "\n"


def write(out, summary, table):
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    with open(os.path.join(out, "TABLE.md"), "w") as f:
        f.write(table)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--arm", action="append", default=[])
    ap.add_argument("--epoxy-pkg", action="append", default=[], metavar="LABEL=DIR",
                    help="arm LABEL's Node epoxy clients load DIR/epoxy.js + DIR/epoxy.wasm (another epoxy-tls build) instead of the npm one")
    ap.add_argument("--clients", default="epoxy,wispjs,direct")
    ap.add_argument("--workloads", default="page,bulk,rr,tls,busy")
    ap.add_argument("--rounds", type=int, default=16)
    ap.add_argument("--port-base", type=int, default=16100)
    ap.add_argument("--timeout-s", type=int, default=60)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--order", choices=("rotate", "random"), default="rotate")
    ap.add_argument("--seed", type=int, default=8004)
    ap.add_argument("--pcap-round", type=int, default=-1, help="tcpdump the closefail runs of this round (diagnostic; adds load)")
    ap.add_argument("--no-replace", dest="replace_flagged", action="store_false",
                    help="do not add replacement rounds for rounds excluded by the foreign-activity check (default: add, up to max(2, N/4))")
    ap.add_argument("--table", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if not (1024 < a.port_base and a.port_base + 70 < 32768):
        raise SystemExit("--port-base: the ports must stay below 32768")
    if a.table:
        t0 = time.time()
        s, t = analyse(a.out)
        if a.check:
            old_s = json.load(open(os.path.join(a.out, "summary.json")))
            old_t = open(os.path.join(a.out, "TABLE.md")).read()
            bad = [k for k in ("rows", "failures") if old_s.get(k) != json.loads(json.dumps(s[k]))] + (["TABLE.md"] if old_t != t else [])
            print(f"check: {'OK' if not bad else 'DIFFERS: ' + ', '.join(bad)} ({len(s['rows'])} rows, {round(time.time() - t0, 2)} s)")
            sys.exit(1 if bad else 0)
        write(a.out, s, t)
        print(t)
        return
    if not a.arm:
        raise SystemExit("at least one --arm LABEL=SPEC")
    run(a)


if __name__ == "__main__":
    main()
