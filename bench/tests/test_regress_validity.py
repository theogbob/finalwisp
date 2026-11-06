"""60.15 T08 (any benchmark error -> invalid) and T09 (raw idle samples) in wst regress. Run: cd bench && python3 -m unittest discover -s tests -v."""
import json, os, tempfile, types, unittest
from unittest import mock

from wispsuite import regress


def args(out, reps=8):
    return types.SimpleNamespace(out=out, args="", base="/b", new="/n", base_args="", new_args="", wbench="/wb", dur=1,
                                 port_base=0, reps=reps, only="", verbose=False, own_scope=False, xh=None, cert=None, key=None,
                                 tls_ok=False)


def fake_ab(values, errors):
    """run_ab stand-in: writes RAW records like ab.py; values/errors = {variant: [per-rep]}"""
    def run_ab(v, reps, argv, raw, **kw):
        with open(raw, "w") as f:
            for rep in range(reps):
                for name in ("base", "new"):
                    f.write(json.dumps({"v": name, "rep": rep, "mib_s_down": values[name][rep],
                                        "errors": errors[name][rep], "cpu_pct": 100}) + "\n")
    return run_ab


class ErrorsInvalidTests(unittest.TestCase):
    def case(self, eb, en, new_vals=None):
        with tempfile.TemporaryDirectory() as d:
            r = regress.Run(args(d))
            vals = {"base": [100.0 + i for i in range(8)], "new": new_vals or [80.0 + i for i in range(8)]}
            with mock.patch.object(regress.abmod, "run_ab", fake_ab(vals, {"base": eb, "new": en})), \
                 mock.patch.object(regress, "tcp_pressure", lambda ns: 0):
                r.ab("download 1x1", "--test download", [("mib_s_down", True)])
            return r

    def test_symmetric_errors_make_the_case_invalid(self):
        r = self.case([1] + [0] * 7, [1] + [0] * 7)
        row = r.rows[0]
        self.assertEqual(row["verdict"], "invalid")
        self.assertEqual(row["verdict_raw"], "LOSS")  # the computed verdict stays visible
        self.assertEqual(row["invalid"], ["benchmark errors"])
        self.assertTrue(any("benchmark errors 1 base / 1 new" in p for p in r.problems))
        self.assertFalse(any(">= " in p and "worse" in p for p in r.problems))  # no >= 5% claim from invalid numbers

    def test_errors_in_base_only_make_the_case_invalid(self):
        r = self.case([0] * 7 + [3], [0] * 8)
        self.assertEqual(r.rows[0]["verdict"], "invalid")

    def test_errors_with_too_few_pairs_are_invalid_not_just_no_data(self):
        with tempfile.TemporaryDirectory() as d:
            r = regress.Run(args(d))
            def run_ab(v, reps, argv, raw, **kw):  # every run failed: error records only, no metric
                with open(raw, "w") as f:
                    for rep in range(reps):
                        for name in ("base", "new"):
                            f.write(json.dumps({"v": name, "rep": rep, "error": "timeout"}) + "\n")
            with mock.patch.object(regress.abmod, "run_ab", run_ab), mock.patch.object(regress, "tcp_pressure", lambda ns: 0):
                r.ab("download 1x1", "--test download", [("mib_s_down", True)])
        self.assertEqual(r.rows[0]["verdict"], "invalid")
        self.assertEqual(r.rows[0]["verdict_raw"], "NO DATA")
        self.assertEqual(r.rows[0]["invalid"], ["benchmark errors"])

    def test_no_errors_gives_an_ordinary_verdict(self):
        r = self.case([0] * 8, [0] * 8)
        self.assertEqual(r.rows[0]["verdict"], "LOSS")
        self.assertNotIn("invalid", r.rows[0])
        self.assertFalse(any("benchmark errors" in p for p in r.problems))

    def test_invalid_rerun_keeps_the_loss_and_names_the_reason(self):
        r = self.case([0] * 8, [0] * 8)
        calls = []
        def rerun(cid, a, m, **kw):
            calls.append(cid)
            r.rows.append({"case": cid, "metric": "mib_s_down", "verdict": "invalid", "ratio": 0.8, "invalid": ["benchmark errors"]})
        with mock.patch.object(r, "ab", rerun):
            regress.confirm(r)
        self.assertEqual(calls, ["download 1x1"])
        self.assertEqual(r.rows[0]["verdict"], "LOSS")
        self.assertEqual(r.rows[0]["note"], "re-run invalid (benchmark errors); LOSS kept")


class IdleRawTests(unittest.TestCase):
    def test_every_probe_is_saved_including_failures(self):
        n = [0]
        def run(cmd, **kw):
            n[0] += 1
            if n[0] == 3:
                return None, None, ""  # a probe that timed out
            return 0, "log line\n" + json.dumps({"kib_per_conn_settled": 10.0 + n[0], "settle_s": 4.0,
                                                 "rss_samples_mib": [50.0, 49.0, 49.0, 49.0, 49.0]}) + "\n", ""
        with tempfile.TemporaryDirectory() as d:
            r = regress.Run(args(d, reps=12))
            with mock.patch.object(regress.proc, "strays", lambda ports: []), \
                 mock.patch.object(regress.wbench, "start_target", lambda *a, **k: None), \
                 mock.patch.object(regress.proc, "spawn", lambda *a, **k: types.SimpleNamespace(pid=1)), \
                 mock.patch.object(regress.proc, "stop", lambda *a, **k: None), \
                 mock.patch.object(regress.proc, "run", run), mock.patch.object(regress.time, "sleep", lambda s: None):
                r.idle()
            recs = [json.loads(l) for l in open(os.path.join(d, "raw", "idle.jsonl"))]
        self.assertEqual(len(recs), 24)  # max(6, reps) = 12 reps x 2 builds (one pair per rep)
        self.assertEqual([(x["rep"], x["v"]) for x in recs[:4]], [(0, "base"), (0, "new"), (1, "new"), (1, "base")])
        self.assertIn("error", recs[2])
        self.assertIsNone(recs[2]["rc"])
        self.assertEqual(recs[0]["rss_samples_mib"], [50.0, 49.0, 49.0, 49.0, 49.0])
        self.assertEqual(recs[1]["kib_per_conn_settled"], 12.0)
        self.assertTrue(any("1 failed probes" in p for p in r.problems))


def idle_run(d, reps, values):
    """r.idle() with probes that return values[variant][rep] KiB/conn (rss_settled_mib from it: 2.3 MiB before)"""
    r = regress.Run(args(d, reps=reps))
    def run(cmd, **kw):
        k = run.k; run.k += 1
        rep, pos = divmod(k, 2)
        v = (["base", "new"] if rep % 2 == 0 else ["new", "base"])[pos]
        kib = values[v][rep]
        return 0, json.dumps({"kib_per_conn_settled": kib, "settle_s": 4.0, "rss_before_mib": 2.3,
                              "rss_settled_mib": round(2.3 + kib * 2000 / 1024, 1)}) + "\n", ""
    run.k = 0
    with mock.patch.object(regress.proc, "strays", lambda ports: []), \
         mock.patch.object(regress.wbench, "start_target", lambda *a, **k: None), \
         mock.patch.object(regress.proc, "spawn", lambda *a, **k: types.SimpleNamespace(pid=1)), \
         mock.patch.object(regress.proc, "stop", lambda *a, **k: None), \
         mock.patch.object(regress.proc, "run", run), mock.patch.object(regress.time, "sleep", lambda s: None):
        r.idle()
    return r.rows[0]


class IdlePairsAndFloorTests(unittest.TestCase):
    """30.10 idle: n pairs at --reps n, and the RSS resolution floor (the flow branch's A/A, rcq3: 1.062 "LOSS", p 0.031)"""
    # A/A shape from rcq3: identical builds, settled RSS one 0.1 KiB/conn step (0.2 MiB) apart in most pairs
    AA_BASE = [1.5, 1.5, 1.6, 1.5, 1.5, 1.5, 1.6, 1.5] * 2
    AA_NEW = [1.6] * 16

    def test_reps_16_gives_16_pairs(self):
        with tempfile.TemporaryDirectory() as d:
            row = idle_run(d, 16, {"base": [1.0 + i / 10 for i in range(16)], "new": [1.0 + i / 10 for i in range(16)]})
        self.assertEqual(row["n"], 16)

    def test_synthetic_aa_one_step_apart_is_tie(self):
        with tempfile.TemporaryDirectory() as d:
            row = idle_run(d, 16, {"base": self.AA_BASE, "new": self.AA_NEW})
        self.assertEqual(row["verdict"], "tie")  # below the 0.25 MiB floor (before 30.10's floor: LOSS)
        self.assertEqual(row["verdict_raw"], "LOSS")  # the test alone calls it (p < 0.05)
        self.assertAlmostEqual(row["resolution"]["effect_mib"], 0.2, places=3)
        self.assertIn("below the RSS resolution", row["note"])

    def test_real_differences_keep_their_verdict(self):
        cases = [  # (base, new, verdict) in KiB/conn; settled RSS = 2.3 MiB + kib x 2000 / 1024 (0.1 MiB grid)
            ([1.5] * 16, [1.8] * 16, "LOSS"),  # constant 0.6 MiB shift, each build constant (review: step must not be it)
            ([1.5] * 15 + [1.6], [1.8] * 15 + [1.9], "LOSS"),
            ([1.5] * 16, [1.5] * 10 + [3.0] * 6, "LOSS"),  # zero-heavy: 6 of 16 pairs +3 MiB (a plain median says 0)
            ([4.9 + (i % 3) / 10 for i in range(16)], [1.6] * 16, "WIN"),  # base-3 vs own-alloc sized
        ]
        for b, n, want in cases:
            with tempfile.TemporaryDirectory() as d:
                row = idle_run(d, 16, {"base": b, "new": n})
            self.assertEqual(row["verdict"], want, (b, n, row.get("resolution")))
            self.assertNotIn("verdict_raw", row)

    def test_measured_step_per_variant(self):
        self.assertIsNone(regress.rss_step([5.2, 5.8, 5.8]))  # 2 distinct values: no granularity estimate
        self.assertEqual(regress.rss_step([5.1, 5.6, 6.1, 5.1]), 0.5)
        c = {"verdict": "LOSS", "ratio": 1.1, "p": 0.01}
        settled = {"base": [5.0, 5.5, 6.0] * 3, "new": [5.4, 5.9, 6.4] * 3}  # each build moves in 0.5 MiB steps
        used = {"base": [3.0] * 9, "new": [3.4] * 9}  # +0.4 MiB: below that step
        c2, note = regress.idle_floor(c, used, settled)
        self.assertEqual((c2["verdict"], c2["resolution"]["floor_mib"]), ("tie", 0.5))
        # one build constant, the other two-valued: no step, the 0.25 floor applies
        c3, _ = regress.idle_floor(c, used, {"base": [5.2] * 9, "new": [5.6] * 8 + [6.8]})
        self.assertEqual((c3["verdict"], c3["resolution"]["floor_mib"]), ("LOSS", 0.25))


if __name__ == "__main__":
    unittest.main()
