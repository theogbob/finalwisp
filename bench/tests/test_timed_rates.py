"""80.04 (2026-11-20): an offered rate must be > 0 (a rate of 0 ran closed loop under an open-loop name:
timed.wb_args passes --rate only for a true rate). timed.rate_problems (job spec; timed.run preflight; timebox calls it
before it claims OUT: tests/test_timebox_who.py), Session.lat (the rate an "@f=" cell resolves to). Synthetic jobs only;
no box, no network."""
import json, os, shutil, sys, tempfile, unittest
from unittest import mock

BENCH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BENCH)
from wispsuite import timed  # noqa: E402

LAT = {"mode": "lat", "cell": "rr:1:1", "cells": ["rr:1:1"], "rate": None, "arms": {"a": {}, "b": {}}}


def lat(*cells, rate=None):
    return dict(LAT, cell=cells[0], cells=list(cells), rate=rate)


def curve(rates=None, fracs=(0.5, 1.0), axis="rate"):
    return {"mode": "curve", "cell": "rr:1:1", "cells": ["rr:1:1"], "rate": None,
            "curve": {"axis": axis, "rates": rates, "fracs": list(fracs) if fracs is not None else None, "conns": [1, 2]}}


class RateProblems(unittest.TestCase):
    def test_valid(self):
        for job in (lat("rr:1:1"), lat("rr:1:1", "rr:1:1@f=0.5", "echo:1:1:16384@r=25000"), lat("rr:1:1", rate=4000),
                    lat("rr:1:1@r=0.5"), curve(), curve(rates=[100, 200]), curve(rates=[100], fracs=[0]),
                    curve(fracs=[0], axis="conns"), {"mode": "lat", "cell": "rr:1:1@f=0.001", "rate": None}):
            with self.subTest(job=job):
                self.assertEqual(timed.rate_problems(job), [])

    def test_refused(self):
        cases = [(lat("rr:1:1", "rr:1:1@r=0"), "rr:1:1@r=0: r=0 must be a number > 0"),
                 (lat("rr:1:1", "rr:1:1@f=0"), "rr:1:1@f=0: f=0 must be a number > 0"),
                 (lat("rr:1:1@f=-0.5"), "f=-0.5 must be"), (lat("rr:1:1@r=x"), "r=x must be"),
                 (lat("rr:1:1@r=nan"), "r=nan must be"), (lat("rr:1:1@f=inf"), "f=inf must be"),
                 (lat("rr:1:1", rate=0), "rate 0 must be"), (lat("rr:1:1", rate=-4000.0), "rate -4000.0 must be"),
                 (lat("rr:1:1", rate=True), "rate True must be"), (lat("rr:1:1", rate="4000"), "rate '4000' must be"),
                 (curve(rates=[100, 0]), "curve rate 0 must be"), (curve(fracs=[0.5, 0]), "curve frac 0 must be"),
                 (curve(fracs=[-1]), "curve frac -1 must be"), (dict(curve(), mode="curv"), "mode 'curv': lat or curve")]
        for job, want in cases:
            with self.subTest(want=want):
                bad = timed.rate_problems(job)
                self.assertEqual(len(bad), 1, bad)
                self.assertIn(want, bad[0])


class ResolvedFrac(unittest.TestCase):
    """Session.lat: "@f=F" resolves to round(F x arm a's closed-loop rps); below 1/s it raises before any run of that cell"""

    def run_lat(self, cells, rps):
        d = tempfile.mkdtemp(prefix="tdrate")
        self.addCleanup(shutil.rmtree, d, True)
        cwd = os.getcwd()
        os.chdir(d)
        self.addCleanup(os.chdir, cwd)
        os.makedirs("out")
        job = dict(lat(*cells), wbench="wb", rounds=3, dur=1, warmup=0.1, seed=1)
        s = timed.Session(job)
        self.addCleanup(s.raw.close)
        runs = []

        def fresh_run(name, cell, dur, warmup, rate=None, meta=None):
            runs.append((cell, rate))
            return {"j": {"rps": rps}}
        s.fresh_run = fresh_run
        return s, runs

    def test_rounds_to_zero_refused(self):
        s, runs = self.run_lat(["rr:1:1", "rr:1:1@f=0.001"], 400.0)  # 0.001 x 400 = 0.4 -> 0
        with self.assertRaises(RuntimeError) as e:
            s.lat()
        self.assertIn("rr:1:1@f=0.001: 0.001 x the closed-loop 400.0/s of rr:1:1 rounds to 0/s", str(e.exception))
        self.assertEqual({r for _, r in runs}, {None})  # only the closed-loop rounds ran

    def test_one_per_second_runs(self):
        s, runs = self.run_lat(["rr:1:1", "rr:1:1@f=0.002"], 400.0)  # 0.8 -> 1
        self.assertTrue(s.lat())
        self.assertEqual(sorted({r for _, r in runs}, key=str), [1, None])


class CurveRefine(unittest.TestCase):
    """the curve's bisection never runs a midpoint that rounds to a load step (or to 0): rates [0.2, 0.4], 0.2 served,
    0.4 not: round(0.3) = 0 would run closed loop (review)"""

    def test_no_zero_midpoint(self):
        d = tempfile.mkdtemp(prefix="tdcurve")
        self.addCleanup(shutil.rmtree, d, True)
        cwd = os.getcwd()
        os.chdir(d)
        self.addCleanup(os.chdir, cwd)
        os.makedirs("out")
        job = dict(curve(rates=[0.2, 0.4]), wbench="wb", seed=1, arms={"a": {}}, probe={"a": None})
        job["curve"].update(sweeps=1, refine=3)

        class Srv:
            def __init__(self, *a):
                pass
            start = stop = lambda self: None
            alive = lambda self: True
        s = timed.Session(job)
        self.addCleanup(s.raw.close)
        rates = []

        def run_one(name, cell, srv, dur, warmup, rate=None, drain=None, meta=None):
            rates.append(rate)
            return {"rate": rate, "j": {"ol": {}, "rps": rate if rate == 0.2 else 0}}
        s.run_one = run_one
        with mock.patch.object(timed, "Server", Srv):
            self.assertTrue(s.curve())
        self.assertEqual(rates, [0.2, 0.4])


class PreflightMarker(unittest.TestCase):
    """timed.run: a job with a rate <= 0 ends with FAILED "preflight ValueError: ..." (rc 2) before the box check"""

    def test_failed_marker(self):
        d = tempfile.mkdtemp(prefix="tdpre")
        self.addCleanup(shutil.rmtree, d, True)
        cwd = os.getcwd()
        os.chdir(d)
        self.addCleanup(os.chdir, cwd)
        job = dict(lat("rr:1:1", rate=0), wbench="wb", port=1, tport=2)
        with mock.patch.object(timed.proc, "install_handlers"), mock.patch.object(timed.proc, "spawn"), \
             mock.patch.object(timed, "check", side_effect=AssertionError("box check ran")):
            rc = timed.run(job)
        self.assertEqual(rc, 2)
        with open("FAILED") as f:
            why = json.loads(f.read())["why"]
        self.assertTrue(why.startswith("preflight ValueError: rate 0 must be a number > 0"), why)


if __name__ == "__main__":
    unittest.main()
