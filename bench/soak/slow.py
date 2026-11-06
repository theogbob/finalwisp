# 30.11 soak: slow readers. Each worker thread runs one download at a time from the source target,
# reading at 8-256 KiB/s with a small receive buffer, for 1-10 min, then ends it (clean CLOSE, RST, or a
# 2-min full stall then close). Logs one line per reader; "stuck" = no byte in 30 s while reading.
import argparse, random, socket, sys, threading, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import common
from wispc import Wisp, Closed, DATA, CLOSE, PLAIN_ONLY

ap = argparse.ArgumentParser()
ap.add_argument("log")
ap.add_argument("--n", type=int, default=12)
ap.add_argument("--a", type=int, default=7001)
ap.add_argument("--b", type=int, default=7002)
ap.add_argument("--source", type=int, default=7103)
ap.add_argument("--pause-share", type=float, default=None,
                help="30.17 share of readers that pause 3-10 min (default: 2 of 6 end modes)")
a = ap.parse_args()
common.setup()
log = common.Log(a.log)
lock = threading.Lock()


def reader(rng):
    tls = rng.random() < 0.3 and not PLAIN_ONLY  # 30.16 --plain: record what the connection really is
    rate = rng.choice((8, 16, 32, 64, 128, 256)) * 1024
    life = rng.uniform(60, 600)
    end_mode = rng.choice(("close", "close", "rst", "stall", "pause", "pause"))
    if a.pause_share is not None:  # 30.17 re-check: more zero-window pauses (the peer_gone false-reset case)
        end_mode = "pause" if rng.random() < a.pause_share else rng.choice(("close", "close", "rst", "stall"))
    # 30.11 re-soak "pause": a live reader stops reading for 3-10 min mid-stream (zero window; the kernel
    # still ACKs probes), then reads again for 60 s. base-1.2 must not reset it (false dead-peer reset).
    pause_at = pause_len = None
    if end_mode == "pause":
        pause_len = rng.uniform(180, 600)
        pause_at = rng.uniform(20, 60)
        life = pause_at + pause_len + 60
    rec = {"tls": tls, "rate_kib": rate >> 10, "life_s": round(life), "end": end_mode}
    gc = common.GapClock()
    stopped_s = 0.0
    paused = False
    got_at_resume = 0
    try:
        w = Wisp(a.b if tls else a.a, tls=tls, timeout=10, rcvbuf=16384)
        w.connect(1, a.source)
        t0 = time.monotonic(); got = 0; last_byte = t0; max_gap = 0.0
        # life and the 30 s stuck test count only time this process ran (SIGSTOP in a bench window excluded:
        # GapClock is ticked after every blocking call, before any deadline is evaluated)
        active = lambda: time.monotonic() - t0 - stopped_s
        while not common.stopped() and active() < life:
            if pause_at is not None and not paused and active() >= pause_at:
                paused = True; rec["bytes_before_pause"] = got
                common.sleep(pause_len)
                gc.tick(); last_byte = time.monotonic(); rec["paused_s"] = round(pause_len)
                got_at_resume = got
            p = w.recv_pkt(1.0)
            g = gc.tick()
            if g:  # SIGSTOPped by the driver (bench window): not our stall
                stopped_s += g; last_byte = time.monotonic()
            now = time.monotonic()
            if p is None:
                if now - last_byte > 30:
                    rec["stuck_at"] = got
                    break
                continue
            if p[1] == 1 and p[0] == DATA:
                got += len(p[2]); max_gap = max(max_gap, now - last_byte); last_byte = now
                ahead = got / rate - (now - t0 - stopped_s - (pause_len if paused else 0))
                if ahead > 0:
                    time.sleep(min(ahead, 2.0))
            elif p[1] == 1 and p[0] == CLOSE:
                # the source target never ends: any server CLOSE of a live reader is unexpected
                rec["server_close"] = p[2][:1].hex()
                break
        run_s = time.monotonic() - t0 - stopped_s - (pause_len if paused else 0)
        rec.update(bytes=got, kib_s=round(got / 1024 / max(0.001, run_s), 1), max_gap_s=round(max_gap, 2),
                   stopped_s=round(stopped_s))
        if pause_at is not None and not paused:
            rec["pause_not_reached"] = True  # ended (stuck/closed/stopped) before the pause point
        if paused:
            rec["bytes_after_resume"] = got - got_at_resume
            if not common.stopped():
                if "server_close" in rec:
                    rec["false_reset"] = "CLOSE " + rec["server_close"]
                elif got - got_at_resume == 0:
                    rec["false_reset"] = "no data after resume"
        if end_mode == "stall" and not common.stopped():
            common.sleep(120)
        if end_mode == "close":
            w.close_stream(1)
        w.close(rst=end_mode == "rst")
    except (Closed, OSError) as e:
        rec["err"] = f"{type(e).__name__}: {e}"
        rec["stopped_s"] = round(stopped_s)
        if paused and not common.stopped():
            rec["false_reset"] = rec["err"]
    rec["stopping"] = common.stopped()
    with lock:
        log(**rec)


def worker(i):
    rng = random.Random()
    common.sleep(rng.uniform(0, 30))
    while not common.stopped():
        reader(rng)
        common.sleep(rng.uniform(1, 20))


ts = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(a.n)]
for t in ts:
    t.start()
while not common.stopped():
    common.sleep(1)
log(event="stop")
