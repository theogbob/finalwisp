# 30.11 soak: half-open clients. Every 8-12 min: 10 idle connections (client port 61000-61999) and 10
# with a download stream that is never read (62000-62999). Then IP_TOS 0x28 is set and one ping is sent: the
# root nft table "soak" (soak-nft.sh) marks the conntrack entry and drops every later packet of the connection
# in both directions, so the server sees a peer that vanished (no FIN, no RST), like a dead client/NAT.
# The client sockets stay open in this process (see below).
import argparse, random, socket, sys, threading, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import common
from wispc import Wisp, Closed

ap = argparse.ArgumentParser()
ap.add_argument("log")
ap.add_argument("--a", type=int, default=7001)
ap.add_argument("--b", type=int, default=7002)
ap.add_argument("--source", type=int, default=7103)
ap.add_argument("--offset", type=int, default=0, help="first port index (0-999) so runs do not reuse 4-tuples")
ap.add_argument("--first", type=float, default=120)
ap.add_argument("--pause-file", default=None)
ap.add_argument("--reaps", default=None, help="JSONL: one line per marked connection (reaped after s, or not)")
ap.add_argument("--reap-limit", type=float, default=900, help="s after the mark: still there = not reaped")
ap.add_argument("--every", type=float, nargs=2, default=(480, 720), help="30.17 s between cycles (uniform)")
a = ap.parse_args()
common.setup()
log = common.Log(a.log)
rng = random.Random()
idx = a.offset
cycle = 0
held = []
pending = {}  # client port -> dict(kind, tls, server port, t_mark) of marked connections not yet reaped
clients = {}  # client port -> Wisp of a marked connection (closed once its server side is gone)
plock = threading.Lock()
rlog = common.Log(a.reaps) if a.reaps else None


def server_side(ports):
    """client port -> TCP state (hex, /proc/net/tcp) of its server-side socket (local 7001/7002), if it exists."""
    alive = {}
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(f) as fh:
                next(fh)
                for line in fh:
                    p = line.split()
                    lp = int(p[1].rsplit(":", 1)[1], 16); rp = int(p[2].rsplit(":", 1)[1], 16)
                    if lp in (a.a, a.b) and rp in ports:
                        alive[rp] = p[3]
        except OSError:
            pass
    return alive


def reap_watch():
    """30.11 re-soak: base-1.2 reaps dead peers (keepalive ~180 s idle; TCP_INFO check ~150 s with data queued).
    `reaped` = the server-side socket is gone; `left_estab_s` = when it left ESTABLISHED (a server that closed
    instead of resetting leaves a FIN_WAIT orphan: then the two differ and `states` says which)."""
    while not common.stopped():
        time.sleep(2)
        with plock:
            ports = set(pending)
        if not ports:
            continue
        alive = server_side(ports)
        now = time.time()
        for p in ports:
            e = pending[p]
            st = alive.get(p)
            if st is not None and st != "01":
                e.setdefault("left_estab_s", round(now - e["t_mark"], 1))
                if st not in e["states"]:
                    e["states"].append(st)
            if st is None:
                rlog and rlog(port=p, kind=e["kind"], tls=e["tls"], reaped=True, s=round(now - e["t_mark"], 1),
                              left_estab_s=e.get("left_estab_s"), states=e["states"])
            elif now - e["t_mark"] > a.reap_limit:
                rlog and rlog(port=p, kind=e["kind"], tls=e["tls"], reaped=False, s=round(now - e["t_mark"], 1),
                              left_estab_s=e.get("left_estab_s"), states=e["states"])
            else:
                continue
            with plock:
                pending.pop(p, None)
                w = clients.pop(p, None)
            if w is not None and st is None:
                # server side gone: free the client port (RST; the conntrack mark still drops it), so a 24 h run can
                # reuse the 1000-port ranges. Not reaped -> kept (never closed while the server still holds it).
                w.close(rst=True)


threading.Thread(target=reap_watch, daemon=True).start()
common.sleep(a.first)
while not common.stopped():
    common.wait_unpaused(a.pause_file)
    tls = cycle % 2 == 1
    port = a.b if tls else a.a
    made = {"idle": [], "dl": []}; errs = []
    socks = []
    for i in range(10):
        for kind, base in (("idle", 61000), ("dl", 62000)):
            p = base + (idx + i) % 1000
            try:
                w = Wisp(port, tls=tls, timeout=5, bind_port=p)
                if kind == "dl":
                    w.connect(1, a.source)
                socks.append(w); made[kind].append(p)
            except (Closed, OSError) as e:
                errs.append(f"{kind} {p}: {type(e).__name__}: {e}")
    idx += 10
    time.sleep(2)  # let downloads fill the queues
    t_mark = time.time()
    for w in socks:
        try:
            w.raw.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x28)
            w.ping(b"bye")  # this packet marks the connection; it and everything after is dropped
            cp = w.raw.getsockname()[1]
            with plock:
                pending[cp] = {"kind": "idle" if cp < 62000 else "dl", "tls": tls, "t_mark": t_mark, "states": []}
                clients[cp] = w
        except OSError as e:
            errs.append(f"tos/ping: {e}")
    # never closed: a close() would send FIN/RST, and an RST conntrack calls invalid carries no mark and
    # would reach the server. Held until the helper stops.
    held.extend(w for w in socks if w.raw.fileno() >= 0)
    log(cycle=cycle, tls=tls, idle_ports=made["idle"], dl_ports=made["dl"], errs=errs, next_index=idx % 1000)
    cycle += 1
    common.sleep(rng.uniform(*a.every))
# censored: marked connections still pending at the stop (younger than --reap-limit); logged so the
# analysis can tell them from the reaped ones (overdue ones = still there after the expected reap time)
with plock:
    for p, e in pending.items():
        rlog and rlog(port=p, kind=e["kind"], tls=e["tls"], reaped=None, s=round(time.time() - e["t_mark"], 1),
                      censored=True, left_estab_s=e.get("left_estab_s"), states=e["states"])
for w in held:
    w.close()
log(event="stop", next_index=idx % 1000)
