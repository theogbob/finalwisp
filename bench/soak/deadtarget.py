# 30.11 soak (base-1.2 re-soak): dead TARGET sockets. One process is both a TCP target on --port (7120) and a
# Wisp client. Every 10-15 min a cycle (alternately server A and B) opens one Wisp connection with 2 idle, 2
# download and 2 upload streams to the target, lets data flow for 5 s, then the target blackholes its side of
# every stream: IP_TOS 0x28 + one packet; the root nft table (soak-nft.sh, rule `tcp sport 7120`) marks the
# conntrack entry and drops all later packets both ways: the server's target socket sees a website that vanished
# (no FIN, no RST). The client then keeps reading downloads and offering upload data (within credit) and records
# for each stream whether / when / with which reason the server CLOSEs it. A stream still open after --hold s is
# closed by the client (CLOSE 0x02). Every 60 s an echo stream on the same connection checks it stays usable.
# Target-side sockets are never closed (a close could send an unmarked RST); held until the helper stops.
# Log: one JSON line per cycle. usage: deadtarget.py LOG [--hold 1500] [--first 300]
import argparse, os, random, socket, struct, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common
from wispc import Wisp, Closed, DATA, CONTINUE, CLOSE

ap = argparse.ArgumentParser()
ap.add_argument("log")
ap.add_argument("--port", type=int, default=7120)
ap.add_argument("--a", type=int, default=7001)
ap.add_argument("--b", type=int, default=7002)
ap.add_argument("--echo", type=int, default=7101)
ap.add_argument("--hold", type=float, default=1500, help="s after the cut before the client closes open streams")
ap.add_argument("--first", type=float, default=300)
ap.add_argument("--every", type=float, nargs=2, default=(600, 900))
ap.add_argument("--pause-file", default=None)
a = ap.parse_args()
common.setup()
log = common.Log(a.log)
rng = random.Random()
held = []  # target-side sockets, never closed
lock = threading.Lock()
cuts = {}  # cycle id -> threading.Event (set = blackhole now)
marked = {}  # cycle id -> list of stream kinds whose marking packet was sent ("D?" = not confirmed)


def target_conn(c):
    """First 9 bytes from the stream: kind (I/D/U) + u64 cycle id."""
    try:
        c.settimeout(30)
        hdr = b""
        while len(hdr) < 9:
            d = c.recv(9 - len(hdr))
            if not d:
                return
            hdr += d
        kind, cyc = chr(hdr[0]), struct.unpack("<Q", hdr[1:])[0]
        with lock:
            held.append(c)
            ev = cuts.setdefault(cyc, threading.Event())
            marked.setdefault(cyc, [])
        chunk = os.urandom(65536)
        c.settimeout(1)
        while not ev.is_set() and not common.stopped():
            if kind == "D":
                try:
                    c.send(chunk)
                except (socket.timeout, BlockingIOError):
                    pass
            elif kind == "U":
                try:
                    if not c.recv(1 << 20):
                        return  # the server closed the stream before the cut (cycle failed early): stop, no busy loop
                except socket.timeout:
                    pass
            else:
                ev.wait(1)
        c.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x28)
        # The marking packet: one byte. If the send buffer is full (download kind) the send times out, but the queued
        # data goes out later with the new TOS (set per transmission), which marks it then. Recorded per stream
        # ("D?" = not confirmed at the cut) so the analysis can tell them apart.
        c.settimeout(2)
        try:
            c.send(b"x")
            marked[cyc].append(kind)
        except OSError:
            marked[cyc].append(kind + "?")  # send buffer full: marked by the next (re)transmission, not confirmed
    except OSError:
        pass


def listener():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", a.port))
    ls.listen(256)
    ls.settimeout(1)
    while not common.stopped():
        try:
            c, _ = ls.accept()
        except socket.timeout:
            continue
        threading.Thread(target=target_conn, args=(c,), daemon=True).start()


def cycle(cyc, tls):
    rec = {"cycle": cyc, "tls": tls, "streams": {}, "echo_fail": [], "err": None}
    kinds = {1: "I", 2: "I", 3: "D", 4: "D", 5: "U", 6: "U"}
    st = {sid: {"kind": k, "down_before": 0, "down_after": 0, "up_before": 0, "up_after": 0, "close": None}
          for sid, k in kinds.items()}
    with lock:
        ev = cuts.setdefault(cyc, threading.Event())
        marked.setdefault(cyc, [])
    gc = common.GapClock()
    stopped = 0.0
    try:
        w = Wisp(a.b if tls else a.a, tls=tls, timeout=10)
        credit = {sid: w.credit for sid in kinds}
        for sid, k in kinds.items():
            w.connect(sid, a.port)
            w.send_pkt(DATA, sid, k.encode() + struct.pack("<Q", cyc))
            credit[sid] -= 1
        payload = os.urandom(16384)
        t0 = time.monotonic(); t_cut = None; next_echo = t0 + 60; echo_sid = 100
        while not common.stopped():
            stopped += gc.tick()
            now = time.monotonic()
            quiet = a.pause_file and os.path.exists(a.pause_file)  # bench window: receive only, send nothing
            if t_cut is None and now - t0 >= 5:
                ev.set(); t_cut = now; rec["t_cut"] = time.time()
            phase = "after" if t_cut else "before"
            if t_cut and now - t_cut >= a.hold:
                break
            if all(s["close"] for s in st.values()) and t_cut:
                break
            for sid in (5, 6) if not quiet else ():
                if st[sid]["close"] is None and credit[sid] > 0:
                    w.send_pkt(DATA, sid, payload); credit[sid] -= 1; st[sid]["up_" + phase] += len(payload)
            if now >= next_echo and not quiet:
                next_echo = now + 60; echo_sid += 1
                w.connect(echo_sid, a.echo); w.send_pkt(DATA, echo_sid, b"dt-alive")
                end = time.monotonic() + 10; ok = False
                while time.monotonic() < end and not ok:
                    p = w.recv_pkt(end - time.monotonic())
                    if p is None:
                        break
                    if p[1] == echo_sid and p[0] == DATA:
                        ok = True
                    elif p[1] in st:
                        handle(p, st, credit, t_cut)
                if not ok and time.monotonic() - now < 20:  # a much longer wait = suspended, not a failure
                    rec["echo_fail"].append(round(now - t0))
                w.close_stream(echo_sid)
                continue
            p = w.recv_pkt(0.2)
            if p is not None:
                handle(p, st, credit, t_cut)
        open_at_end = [sid for sid, s in st.items() if s["close"] is None]
        rec["client_closed"] = open_at_end
        for sid in open_at_end:
            w.close_stream(sid)
        time.sleep(5)
        w.close()
    except (Closed, OSError) as e:
        rec["err"] = f"{type(e).__name__}: {e}"
    rec["streams"] = st
    rec["marked"] = marked.get(cyc, [])
    rec["stopped_s"] = round(stopped)
    log(**rec)


def handle(p, st, credit, t_cut):
    ty, sid, body = p
    if sid not in st:
        return
    s = st[sid]
    phase = "after" if t_cut else "before"
    if ty == DATA:
        s["down_" + phase] += len(body)
    elif ty == CONTINUE:
        credit[sid] = struct.unpack("<I", body[:4])[0]
    elif ty == CLOSE:
        s["close"] = {"reason": body[:1].hex(), "s_after_cut": None if t_cut is None else round(time.monotonic() - t_cut, 1)}


threading.Thread(target=listener, daemon=True).start()
common.sleep(a.first)
cyc = int(time.time()) * 10
n = 0
while not common.stopped():
    common.wait_unpaused(a.pause_file)
    threading.Thread(target=cycle, args=(cyc + n, n % 2 == 1), daemon=True).start()
    n += 1
    common.sleep(rng.uniform(*a.every))
log(event="stop", cycles=n, held=len(held))
