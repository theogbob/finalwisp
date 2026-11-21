"""80.04 (2026-11-20): timedsum.exclusions with the session-aware owner rule, and timedsum.tick_exposure.
A window of the caller's worker (me) is the session's own only when it names this session; any other window counts
(a kit ship of another session of the same worker, before its own lock, is foreign). Run from bench:
python3 -m unittest tests.test_timed_exclusions -v."""
import json, os, tempfile, unittest

from wispsuite import timedsum as TS

T0 = "2026-01-01T00:00:00Z"


def win(**kw):
    w = {"box": "b1", "start": "2026-01-01T00:00:10Z", "end": "2026-01-01T00:00:20Z"}
    w.update(kw)
    return w


class Exclusions(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)

    def tearDown(self):
        os.unlink(self.path)

    def whys(self, lines, **kw):
        with open(self.path, "w") as f:
            f.write("\n".join(json.dumps(x) for x in lines) + "\n")
        return [w for _, _, w in TS.exclusions([self.path, self.path + ".missing"], "b1", **kw)]

    def test_own_window_is_skipped_only_when_it_names_the_session(self):
        lines = [win(who="w", what="kit ship before the lock (upload 2 s; session S-1)"),
                 win(who="w", what="kit ship before the lock (upload 2 s; session S-2)"),
                 win(who="w", what="manual ssh probes (no session named)"),
                 win(who="other", what="unit (session S-1)"),
                 win(why="a session's own list"),
                 win(box="b2", who="other", what="another box")]
        got = self.whys(lines, me="w", session="S-1")
        self.assertEqual(len(got), 4)
        self.assertFalse(any("session S-1)" in g and g.startswith("w:") for g in got))  # its own window: skipped
        self.assertTrue(any("session S-2" in g for g in got))  # another session of the same worker: foreign
        self.assertTrue(any("manual ssh" in g for g in got))  # names no session: foreign
        self.assertTrue(any(g.startswith("other:") for g in got))  # another worker naming this session: foreign

    def test_exact_token_never_a_prefix(self):
        lines = [win(who="w", what="kit ship (session S-client2b)"), win(who="w", what="kit ship (upload time unknown (session killed); session S-client2)")]
        got = self.whys(lines, me="w", session="S-client2")
        self.assertEqual(len(got), 1)
        self.assertIn("S-client2b", got[0])
        self.assertTrue(TS.names_session({"what": lines[1]["what"]}, "S-client2"))  # the real name after the status note
        self.assertEqual(len(self.whys(lines, me="w", session="killed")), 2)  # "(session killed)" is a status note: names no session
        self.assertFalse(TS.names_session({"what": "upload time unknown (session killed)"}, "killed"))

    def test_session_field_wins_over_the_text(self):
        lines = [win(who="w", session="S-1", what="text naming session S-2"), win(who="w", session="S-2", what="text naming session S-1")]
        got = self.whys(lines, me="w", session="S-1")
        self.assertEqual(len(got), 1)
        self.assertIn("naming session S-1", got[0])

    def test_without_me_or_session_every_window_counts(self):
        lines = [win(who="w", what="kit ship (session S-1)"), win(why="own list")]
        self.assertEqual(len(self.whys(lines, me="w")), 2)
        self.assertEqual(len(self.whys(lines, session="S-1")), 2)
        self.assertEqual(len(self.whys(lines)), 2)

    def test_session_must_start_a_word_after_a_blank_or_semicolon(self):
        lines = [win(who="w", what="post-session cleanup"), win(who="w", what="kit ship (upload 2 s;session cleanup)"),
                 win(who="w", what="session cleanup at the start")]
        got = self.whys(lines, me="w", session="cleanup")
        self.assertEqual(got, ["w: post-session cleanup (shared log)"])

    def test_no_token_across_fields(self):
        lines = [win(who="w", what="manual probe after session", why="alpha restart")]
        self.assertEqual(len(self.whys(lines, me="w", session="alpha")), 1)

    def test_why_text_can_name_the_session(self):
        lines = [win(who="w", why="kit ship before the lock; session S-1")]
        self.assertEqual(self.whys(lines, me="w", session="S-1"), [])


def run(tw0, dur=2.0, arm="a", cell="rr:1:1", **kw):
    r = {"cell": cell, "arm": arm, "tw0": tw0, "j": {"duration": dur}}
    r.update(kw)
    return r


class TickExposure(unittest.TestCase):
    def exp(self, recs, warmup=0.5):
        return TS.tick_exposure(recs, warmup, lambda r: r["cell"])

    def test_window_bounds(self):
        base = 1800000000.0  # a whole minute (divisible by 60)
        self.assertEqual(base % 60, 0)
        cases = [(base - 1.0, 2.0, 1),         # window (set-up 0, warmup 0.5) [base - 0.5, base + 1.5): crosses :00
                 (base - 2.5, 2.0, 0),         # [base - 2, base): ends at :00 exactly, no overlap
                 (base - 2.4, 2.0, 1),         # [base - 1.9, base + 0.1): ends just after :00
                 (base + 1.4, 2.0, 1),         # [base + 1.9, ...): starts inside [:00, :02)
                 (base + 1.5, 2.0, 0),         # [base + 2.0, ...): starts at :02
                 (base + 10.0, 2.0, 0),        # mid-minute
                 (base + 10.0, 120.0, 1)]      # a long window spans the next :00
        for tw0, dur, want in cases:
            got = self.exp([run(tw0, dur, cmap0_ms=0)])
            self.assertEqual(got["rr:1:1"]["a"][:2], [want, 1], (tw0 - base, dur))

    def test_setup_estimate(self):
        base = 1800000000.0
        # measured set-up: 0 s -> window [:59.5, :01.5) (hit); 2.6 s -> [:02.1, :04.1) (no hit)
        self.assertEqual(self.exp([run(base - 1.0, cmap0_ms=0)])["rr:1:1"]["a"][0], 1)
        self.assertEqual(self.exp([run(base - 1.0, cmap0_ms=2600)])["rr:1:1"]["a"][0], 0)
        # no cmap0: the (cell, arm) median of the others (2.6 s) is used, not 0.02 s (which would hit)
        recs = [run(base + 30, cmap0_ms=2600), run(base + 31, cmap0_ms=2600), run(base - 1.0)]
        self.assertEqual(self.exp(recs)["rr:1:1"]["a"], [0, 3, 0])
        # poll timed out, no median: max(0, min(2, warmup 2)) = 2 s -> start base + 3 (no hit; 0.02 s would give base + 1.02)
        self.assertEqual(self.exp([run(base - 1.0, cmap0_incomplete=True)], warmup=2.0)["rr:1:1"]["a"], [0, 1, 0])
        # nothing known: 0.02 s -> start base exactly (hit)
        self.assertEqual(self.exp([run(base - 0.52)])["rr:1:1"]["a"], [1, 1, 0])

    def test_counted_runs(self):
        base = 1800000000.0
        recs = [run(base - 1.0, cmap0_ms=0), run(base - 1.0, arm="b", cmap0_ms=0, calib=True),
                run(base - 1.0, arm="b", cmap0_ms=0, j={"error": "x"}), run(None, arm="b"), run(base + 10, arm="b", dur=0)]
        self.assertEqual(self.exp(recs), {"rr:1:1": {"a": [1, 1, 0], "b": [0, 2, 2]}})
        self.assertEqual(TS.tick_exposure(recs, 0.5, lambda r: None), {})
        bad = [run(base, dur="unknown"), run(base, dur=float("inf")), run(float("nan")), run("x"), run(base, dur=-1)]
        self.assertEqual(self.exp(bad), {"rr:1:1": {"a": [0, 5, 5]}})  # unusable timing: counted, never an error
        self.assertEqual(self.exp([]), {})

    def test_seeded_units_and_arms(self):
        """a cell whose rounds were all excluded and an arm whose runs all failed still get their line (0/0)"""
        base = 1800000000.0
        recs = [run(base - 1.0, cmap0_ms=0), run(base - 1.0, arm="b", j={"error": "x"})]
        got = TS.tick_exposure(recs, 0.5, lambda r: r["cell"], units=["rr:1:1", "echo:1:1"], arms=["a", "b"])
        self.assertEqual(got, {"rr:1:1": {"a": [1, 1, 0], "b": [0, 0, 0]}, "echo:1:1": {"a": [0, 0, 0], "b": [0, 0, 0]}})


class RateLabel(unittest.TestCase):
    RATES = [1, 4000, 25000, 61428, 126400, 999999, 1000000, 1000001, 1234567, 123456789, 2.5, 0.1, 1e-7, 4000.001, 4000.002,
             1e6 + 0.5, 3.0, 1e21, 2 ** 53 + 2]

    def test_lossless_and_short_where_g_is_exact(self):
        labels = [TS.rate_label(r) for r in self.RATES]
        for r, s in zip(self.RATES, labels):
            self.assertEqual(float(s), float(r), s)  # round trip: the label is the rate
            if float(f"{r:g}") == r:
                self.assertEqual(s, f"{r:g}")  # unchanged wherever :g was exact (archived names stay byte-identical)
        self.assertEqual(len(set(labels)), len(labels))
        self.assertEqual((TS.rate_label(1000000), TS.rate_label(1000001)), ("1e+06", "1000001"))
        self.assertEqual(TS.rate_label(4000.001), "4000.001")

    def test_group_name(self):
        self.assertEqual(TS.group_name("rr:1:1", None), "rr:1:1")
        self.assertEqual(TS.group_name("rr:1:1", 0), "rr:1:1@rate=0")
        self.assertEqual(TS.group_name("rr:1:1", 4000), "rr:1:1@rate=4000")
        self.assertEqual(TS.group_name("rr:1:1", 1000001), "rr:1:1@rate=1000001")


if __name__ == "__main__":
    unittest.main()
