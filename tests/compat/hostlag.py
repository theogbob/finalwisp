"""60.74 4.5: the host's scheduling lag while a compat case runs (the Python side of server/src/testlag.rs).
A probe thread sleeps 1 ms in a loop and keeps the largest overshoot (it also sees the GIL hand-over, at most the
interpreter's switch interval, so it reads a little high). An upper bound of a case is then `base + hops x lag` (a chain
of `hops` thread wakeups: client, server worker, DNS thread, fake server, target ...), and a case whose outcome depends
on a deadline is judged only on a run whose lag stayed at or below what it tolerates (judged). Stdlib only."""
import threading, time


class Lag:
    def __init__(self):
        self.mx, self._stop, self.cur = 0.0, False, time.monotonic()
        threading.Thread(target=self._run, daemon=True).start()
        time.sleep(0.002)

    def _run(self):
        while not self._stop:
            t = self.cur = time.monotonic()
            time.sleep(0.001)
            o = time.monotonic() - t - 0.001
            if o > self.mx:
                self.mx = o

    def max(self):
        """the largest overshoot since start / reset, the probe's current sleep included (a case that wakes from the same
        stall reads it before the probe has run again), plus the probe's own period (s)"""
        cur = self.cur  # (first: a sleep that ends between the two reads has set mx before the next start)
        return max(self.mx, time.monotonic() - cur - 0.001) + 0.001

    def reset(self):
        self.mx = 0.0

    def bound(self, base, hops):
        return base + hops * self.max()

    def stop(self):
        self._stop = True


def judged(what, tol, tries, case):
    """case(lag, run) -> (cond, msg). A run that fails with the lag above `tol` (s) is no judgement of the case: an INFO
    line, and it runs again (at most `tries` runs; `run` lets the case use fresh names). Returns (cond, msg + the lag)
    of the first run that passed, failed within the tolerance, or was the last (a host too busy to judge fails)."""
    for i in range(1, tries + 1):
        lag = Lag()
        try:
            c, m = case(lag, i)
            mx = lag.max()  # (read while the probe runs: after stop its current-sleep start goes stale)
        finally:
            lag.stop()
        if c or mx <= tol or i == tries:
            return c, f"{m} (host lag {mx * 1000:.0f} ms" + (f", run {i}" if i > 1 else "") + ")"
        print(f"INFO {what}: run {i} failed with a host lag of {mx * 1000:.0f} ms, above {tol * 1000:.0f} ms: "
              f"not a judgement, again ({m})", flush=True)
