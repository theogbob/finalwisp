# 30.11 soak: many idle Wisp connections that come and go (random walk of the target count).
# usage: idle.py LOG --min N --max N [--src-ips N --streams 0,0,0,1 --max-arrivals N] ; 80% to server A (plain), 20% to B (TLS)
import argparse, os, random, select, socket, struct, sys, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import common
from wispc import Wisp, Closed, DATA, CLOSE, PLAIN_ONLY

ap = argparse.ArgumentParser()
ap.add_argument("log")
ap.add_argument("--min", type=int, default=500)
ap.add_argument("--max", type=int, default=3000)
ap.add_argument("--a", type=int, default=7001)
ap.add_argument("--b", type=int, default=7002)
ap.add_argument("--echo", type=int, default=7101)
ap.add_argument("--echo-hosts", default="127.0.0.1", help="30.16: echo target addresses (comma list) for the streams")
ap.add_argument("--src-ips", type=int, default=1, help="30.16: spread client source addresses over 127.0.0.2..N+1 (>28k conns)")
ap.add_argument("--streams", default="0,0,1,2", help="30.16: choices for the streams per connection")
ap.add_argument("--max-arrivals", type=int, default=300, help="30.16: connections opened per 10 s tick at most")
ap.add_argument("--cohort", type=int, default=0, help="30.11 re-soak: connections kept for the whole run (never closed by us)")
a = ap.parse_args()
common.setup()
log = common.Log(a.log)
rng = random.Random()

conns = []  # [Wisp, opened_at, next_sid]


STREAMS = [int(x) for x in a.streams.split(",")]
ECHO_HOSTS = a.echo_hosts.split(",")
n_open = [0]


def open_one():
    tls = rng.random() < 0.2 and not PLAIN_ONLY  # 30.16 --plain: record what the connection really is
    n_open[0] += 1
    src = f"127.0.0.{2 + n_open[0] % a.src_ips}" if a.src_ips > 1 else None
    w = Wisp(a.b if tls else a.a, tls=tls, timeout=5, src=src)
    sid = 1
    for _ in range(rng.choice(STREAMS)):
        w.connect(sid, a.echo, rng.choice(ECHO_HOSTS))
        w.send_pkt(DATA, sid, b"idle-hello")
        sid += 1
    w.raw.setblocking(False) if not tls else None
    return [w, time.time(), sid, tls]


def drain(c):
    """Read what is queued (echoes, CONTINUEs); a server close is an event."""
    w = c[0]
    try:
        while True:
            d = w.s.recv(65536) if not c[3] else _tls_recv(w)
            if d is None:
                return True
            if not d:
                return False
            w.rbuf += d
            while w._parse() is not None:
                pass
    except (BlockingIOError, InterruptedError):
        return True
    except OSError:
        return False


def _tls_recv(w):
    w.s.settimeout(0)
    try:
        return w.s.recv(65536)
    except (BlockingIOError, socket.timeout):
        return None
    except Exception as e:
        if "WantRead" in type(e).__name__ or "read operation timed out" in str(e):
            return None
        raise


def liveness(c, tries=2):
    """New stream on an old idle connection: the echo must come back. A wait that took far longer than its
    5 s (this process was SIGSTOPped in a bench window) is retried once on a new stream instead of failing."""
    w = c[0]
    for attempt in range(tries):
        sid = c[2]; c[2] += 1
        w.raw.setblocking(True); w.s.settimeout(5)
        t_start = time.monotonic()
        try:
            w.connect(sid, a.echo, rng.choice(ECHO_HOSTS))
            w.send_pkt(DATA, sid, b"alive?")
            end = time.monotonic() + 5
            while time.monotonic() < end:
                p = w.recv_pkt(end - time.monotonic())
                if p and p[1] == sid and p[0] == DATA:
                    w.close_stream(sid)
                    return None
                if p and p[1] == sid and p[0] == CLOSE:
                    return f"CLOSE {p[2][:1].hex()}"
            w.close_stream(sid)  # do not leave the unanswered stream open on the server
            if time.monotonic() - t_start > 15 and attempt + 1 < tries:
                continue  # suspended mid-wait: retry
            return "no echo in 5 s"
        except (Closed, OSError) as e:
            return f"{type(e).__name__}: {e}"
        finally:
            if not c[3]:
                w.raw.setblocking(False)
    return "no echo in 5 s"


# 30.11 re-soak: a long-lived cohort (hours idle: TCP keepalive probes them every 2 min; a live peer must never
# be reset). Never closed by us; one closed by the server is counted and not replaced.
cohort = []
for _ in range(a.cohort):
    try:
        cohort.append(open_one())
    except (Closed, OSError):
        pass
cohort_opened = len(cohort)
cohort_server_closed = 0
next_cohort_live = time.monotonic() + 600

target = rng.randint(a.min, a.max)
next_target = time.monotonic() + 300
next_live = time.monotonic() + 60
while not common.stopped():
    t0 = time.monotonic()
    opened = closed = open_fail = server_closed = 0
    first_err = None
    if t0 >= next_target:
        target = rng.randint(a.min, a.max)
        next_target = t0 + rng.uniform(120, 600)
    # drain + detect server-side closes
    keep = []
    for c in conns:
        if drain(c):
            keep.append(c)
        else:
            server_closed += 1
            c[0].close()
    conns = keep
    # random departures: 2-8% per tick (clean FIN, RST, or stream CLOSE first)
    rng.shuffle(conns)
    k = int(len(conns) * rng.uniform(0.02, 0.08))
    for c in conns[:k]:
        mode = rng.random()
        if mode < 0.25:
            try:
                for sid in range(1, c[2]):
                    c[0].close_stream(sid)
            except OSError:
                pass
        c[0].close(rst=0.25 <= mode < 0.5)
        closed += 1
    conns = conns[k:]
    # arrivals toward the target, at most 300 per tick
    want = min(a.max_arrivals, max(0, target - len(conns)) + rng.randint(0, 20))
    for _ in range(want):
        try:
            conns.append(open_one()); opened += 1
        except (Closed, OSError) as e:
            open_fail += 1
            first_err = first_err or f"{type(e).__name__}: {e}"
    keepc = []
    for c in cohort:
        if drain(c):
            keepc.append(c)
        else:
            cohort_server_closed += 1
            c[0].close()
    cohort = keepc
    cohort_live_fail = []
    if t0 >= next_cohort_live and cohort:
        next_cohort_live = t0 + 600
        for c in rng.sample(cohort, min(5, len(cohort))):
            err = liveness(c)
            if err:
                cohort_live_fail.append({"age_s": round(time.time() - c[1]), "tls": c[3], "err": err})
    live_fail = []
    if t0 >= next_live and conns:
        next_live = t0 + 60
        old = sorted(conns, key=lambda c: c[1])[: max(1, len(conns) // 4)]
        for c in rng.sample(old, min(10, len(old))):
            err = liveness(c)
            if err:
                live_fail.append({"age_s": round(time.time() - c[1]), "tls": c[3], "err": err})
    log(n=len(conns), target=target, opened=opened, closed=closed, open_fail=open_fail, server_closed=server_closed,
        live_fail=live_fail, err=first_err, tick_s=round(time.monotonic() - t0, 2), cohort_n=len(cohort),
        cohort_opened=cohort_opened, cohort_server_closed=cohort_server_closed, cohort_live_fail=cohort_live_fail)
    common.sleep(max(0.5, 10 - (time.monotonic() - t0)))
for c in conns + cohort:
    c[0].close()
log(event="stop", n=len(conns))
