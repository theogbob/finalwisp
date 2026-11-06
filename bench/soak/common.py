# 30.11 soak: helpers shared by the long-running client processes.
import json, os, resource, signal, subprocess, sys, threading, time

STOP = False


def _stop(*_):
    global STOP
    STOP = True


def setup():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))


def stopped():
    return STOP


def sleep(t):
    end = time.monotonic() + t
    while not STOP and time.monotonic() < end:
        time.sleep(min(0.5, max(0.0, end - time.monotonic())))


class Log:
    def __init__(self, path):
        self.f = open(path, "a", buffering=1)

    def __call__(self, **kv):
        kv.setdefault("t", round(time.time(), 3))
        self.f.write(json.dumps(kv) + "\n")


def wait_unpaused(path):
    """30.11 re-soak: the driver creates PATH during a bench window; helpers wait before starting a new cycle."""
    while path and os.path.exists(path) and not STOP:
        time.sleep(1)


class GapClock:
    """Detects a stopped process (SIGSTOP during a bench window): tick() returns the seconds this loop was
    not running beyond `slack` since the last tick (0 normally)."""

    def __init__(self, slack=5.0):
        self.slack = slack
        self.last = time.monotonic()

    def tick(self):
        now = time.monotonic()
        gap = now - self.last
        self.last = now
        return gap if gap > self.slack else 0.0


def spawn_logged(argv, path, **kw):
    """30.16: start a server with stdout/stderr on a pipe; a thread of THIS process appends it to `path`. The log's
    page cache is then charged to the harness's cgroup, not to the server's scope (30.15: a file written by the server
    itself grew the scope's memory.current by 64 KiB per 5 min of metrics lines). Line-buffered; the thread ends at EOF."""
    sink = open(path, "ab")  # review: opened before the start (a bad path fails here, not silently in the thread)
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kw)
    p.pump_err = None

    def pump():
        # review (review P1): a failed write must not stop the reading: the pipe would fill and block the server's
        # metrics thread. Keep draining, record the first error (the driver reports it as a harness error).
        for line in p.stdout:
            if p.pump_err is None:
                try:
                    sink.write(line); sink.flush()
                except OSError as e:
                    p.pump_err = repr(e)
        sink.close()
    p.pump = threading.Thread(target=pump, daemon=True, name="log-" + os.path.basename(path))
    p.pump.start()  # join it after the process exited: the last lines (ev=metrics_final) are then on disk
    return p


def smaps_breakdown(pid):
    """30.16 heap snapshot without touching the server: /proc/PID/smaps_rollup (Rss, Anonymous) and, from
    /proc/PID/smaps, the resident anon KiB of [heap] (glibc main arena, brk), of the other anonymous mappings (thread
    arenas, pool chunks, stacks) and their count. KiB; {} if the process is gone."""
    out = {}
    try:
        for line in open(f"/proc/{pid}/smaps_rollup"):
            k, _, v = line.partition(":")
            if k in ("Rss", "Anonymous", "Private_Dirty"):
                out["sm_" + k.lower() + "_kib"] = int(v.split()[0])
        heap = other = n = 0; name = None
        for line in open(f"/proc/{pid}/smaps"):
            f = line.split()
            if f and "-" in f[0] and not f[0].endswith(":"):  # mapping header: addr perms off dev inode [name]
                name = f[5] if len(f) > 5 else ""
                if name == "":
                    n += 1
            elif f and f[0] == "Anonymous:":
                kib = int(f[1])
                if name == "[heap]":
                    heap += kib
                elif name == "":
                    other += kib
        out.update(sm_heap_kib=heap, sm_anon_maps_kib=other, sm_anon_maps=n)
    except (OSError, ValueError, IndexError):
        pass
    return out
