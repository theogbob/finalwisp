"""Resource sampling (30.10): process-group CPU / RSS / peak RSS, cgroup v2 scopes, kernel TCP memory pressure.
Units: MiB = 2^20 bytes everywhere."""
import os, signal, subprocess, threading

HZ = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")
MIB = 1 << 20
_WRAPPERS = ("Name:\tsh\n", "Name:\tbash\n", "Name:\tip\n", "Name:\tsystemd-run\n")


def group_usage(pgids):
    """(cpu seconds, RSS MiB, peak RSS MiB) summed over live processes in the groups or sessions.
    Suite children lead both; nested groups (e.g. timeout) stay in the same session (30.13).
    RSS = VmRSS from /proc/PID/status (the stat field as fallback; 60.17). Peak RSS (VmHWM) skips shell /
    `ip netns exec` / systemd-run wrappers; the kernel still feeds VmHWM from the approximate counter. RSS is not cgroup memory;
    shared pages may be counted more than once, and exited processes are not included."""
    want = {pgids} if isinstance(pgids, int) else set(pgids)
    cpu, rss, hwm = 0.0, 0, 0
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as fh:
                f = fh.read().rsplit(")", 1)[1].split()
            if (int(f[2]) not in want and int(f[3]) not in want) or f[0] == "Z":
                continue
            cpu += (int(f[11]) + int(f[12])) / HZ
            stat_rss = int(f[21]) * PAGE
            try:
                with open(f"/proc/{d}/status") as fh:
                    st = fh.read()
            except OSError:  # exited between the two reads: keep its stat RSS
                rss += stat_rss
                continue
            # VmRSS, not the stat field: on kernels with per-CPU RSS counters, stat skips the per-CPU deltas, so
            # many threads freeing on many CPUs leave it high (gold, 72 CPUs: 7-18 MiB over VmRSS at idle; 60.17)
            rss += int(st.split("VmRSS:")[1].split()[0]) * 1024 if "VmRSS:" in st else stat_rss
            if not st.startswith(_WRAPPERS) and "VmHWM:" in st:
                hwm += int(st.split("VmHWM:")[1].split()[0]) * 1024
        except (OSError, IndexError, ValueError):
            pass
    return cpu, rss / MIB, hwm / MIB


def rss_mib(pid):
    """VmRSS of one process in MiB (None if gone)."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS"):
                    return int(line.split()[1]) / 1024
    except OSError:
        return None
    return None


def scope_dir(unit, user):
    uid = os.getuid()
    base = f"user.slice/user-{uid}.slice/user@{uid}.service/app.slice/" if user else "system.slice/"
    return f"/sys/fs/cgroup/{base}{unit}.scope"


def scope_stats(unit, user):
    """(memory.peak MiB, oom_kill count, cpu usage_usec) of a systemd scope; None for what cannot be read."""
    d = scope_dir(unit, user)
    peak = oom = cpu = None
    try:
        peak = int(open(f"{d}/memory.peak").read()) >> 20
        oom = int(dict(l.split() for l in open(f"{d}/memory.events"))["oom_kill"])
        cpu = int(dict(l.split() for l in open(f"{d}/cpu.stat"))["usage_usec"])
    except (OSError, KeyError, ValueError):
        pass
    return peak, oom, cpu


def tcp_pressure(ns=None):
    """TcpExt TCPMemoryPressures (kernel entered global tcp_mem pressure) in the host or a netns; None if unreadable."""
    try:
        cmd = (["ip", "netns", "exec", ns] if ns else []) + ["cat", "/proc/net/netstat"]
        lines = [l.split() for l in subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()
                 if l.startswith("TcpExt:")]
        return int(dict(zip(lines[0][1:], lines[1][1:]))["TCPMemoryPressures"])
    except Exception:
        return None


def tcp_pressure_both(nss=()):
    """60.42 verify: {ns or "": (TCPMemoryPressures, TCPMemoryPressuresChrono ms)} for the host and the netns `nss` (the
    kernel counts an entry / exit in the netns of the socket that crossed tcp_mem[1]); None if the host is unreadable.
    Subtract with pressure_delta (only namespaces read at both ends)."""
    out = {}
    for ns in (None, *nss):
        try:
            cmd = (["ip", "netns", "exec", ns] if ns else []) + ["cat", "/proc/net/netstat"]
            lines = [l.split() for l in subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()
                     if l.startswith("TcpExt:")]
            d = dict(zip(lines[0][1:], lines[1][1:]))
            v = (int(d["TCPMemoryPressures"]), int(d["TCPMemoryPressuresChrono"]))
        except Exception:
            if ns is None:
                return None
            continue
        out[ns or ""] = v
    return out


def pressure_delta(a, b):
    """(entries, ms) from two tcp_pressure_both readings, over the namespaces present in both; None if either is None."""
    if a is None or b is None:
        return None
    ks = a.keys() & b.keys()
    return sum(b[k][0] - a[k][0] for k in ks), sum(b[k][1] - a[k][1] for k in ks)


def tcp_press_flag():
    """60.42 verify: the kernel's global TCP memory pressure flag now (/proc/net/protocols, TCP row, "press" column:
    yes / no; the flag is host-wide, visible from any netns); None if unreadable. Unlike the TcpExt counters it also
    shows pressure that started before the window (the entry counter only counts 0 -> 1 transitions) and pressure still
    on at the end (TCPMemoryPressuresChrono is credited only when pressure ends)."""
    try:
        with open("/proc/net/protocols") as f:
            head = f.readline().split()
            col = head.index("press")
            for l in f:
                x = l.split()
                if x and x[0] == "TCP":
                    return {"yes": 1, "no": 0}.get(x[col])
    except (OSError, ValueError, IndexError):
        pass
    return None


def tcp_mem_pages():
    """Host TCP memory in pages (/proc/net/sockstat "TCP: ... mem N"); None if unreadable."""
    try:
        for l in open("/proc/net/sockstat"):
            if l.startswith("TCP:"):
                f = l.split()
                return int(f[f.index("mem") + 1])
    except (OSError, ValueError):
        pass
    return None


def tcp_mem_max():
    """net.ipv4.tcp_mem[2] (the hard limit, pages); None if unreadable."""
    try:
        return int(open("/proc/sys/net/ipv4/tcp_mem").read().split()[2])
    except (OSError, ValueError, IndexError):
        return None


class TcpMemPeak:
    """50.02 D: sample host TCP memory every `every` s in a thread while a rep runs. max_seen = the highest sockstat
    value seen (TCP memory is accounted host-wide, so this process's view covers netns runs too). At the hard limit (tcp_mem[2]) the kernel refuses socket memory outright and a kTLS
    sender with nothing in flight can stall the whole run (50.02): such reps are "at tcp_mem max". sockstat lags the
    real total by up to the per-CPU reserves (1 MiB per CPU), so the flag counts within that margin."""

    def __init__(self, every=0.05):
        self.every, self.max_seen, self._stop = every, None, threading.Event()
        self.press_samples = self.samples = 0  # 60.42 verify: samples with the global TCP pressure flag set
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while True:
            v = tcp_mem_pages()
            if v is not None and (self.max_seen is None or v > self.max_seen):
                self.max_seen = v
            pf = tcp_press_flag()
            if pf is not None:
                self.samples += 1
                self.press_samples += pf
            if self._stop.wait(self.every):
                return

    def __enter__(self):
        # review: start with the termination signals blocked, so the thread inherits the mask and they reach
        # the main thread only (proc.spawn relies on blocking them there between fork and registration)
        sigs = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
        old = signal.pthread_sigmask(signal.SIG_BLOCK, sigs)
        try:
            self._t.start()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._t.join()


def at_tcp_mem_max(peak, limit, ncpu=None):
    """50.02 D: True if a sockstat peak reached the hard limit within the per-CPU reserves (256 pages per CPU)."""
    if peak is None or limit is None:
        return False
    return peak >= limit - 256 * (ncpu or os.cpu_count() or 1)


def steal_ticks():
    """Cumulative CPU steal ticks of the host (/proc/stat)."""
    try:
        return int(open("/proc/stat").readline().split()[8])
    except (OSError, IndexError, ValueError):
        return None
