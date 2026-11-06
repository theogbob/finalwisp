"""30.10 / 60.12 paired inference. Run from bench: python3 -m unittest discover -s tests -v."""
import itertools
import math
import statistics
import unittest

from wispsuite import stats


def exact_sign_p(differences):
    """Independent brute-force sign assignment, using rank definitions directly."""
    values = [d for d in differences if d != 0]
    ranks = [2 * sum(abs(x) < abs(d) for x in values)
             + sum(abs(x) == abs(d) for x in values) + 1 for d in values]
    observed = sum(r for r, d in zip(ranks, values) if d > 0)
    cutoff = min(observed, sum(ranks) - observed)
    count = sum(sum(r for r, positive in zip(ranks, signs) if positive) <= cutoff
                for signs in itertools.product((False, True), repeat=len(values)))
    return min(1.0, 2 * count / 2 ** len(values))


class WilcoxonTests(unittest.TestCase):
    def test_exact_ties_and_zeros_n8_n16(self):
        for n in (8, 16):
            for pattern in ([1, -1, 2, -2, 2, 0, 1, 0], [1, 1, 1, 2, 2, 2, -3, -3]):
                differences = pattern * (n // 8)
                with self.subTest(n=n, pattern=pattern):
                    self.assertEqual(stats.wilcoxon(differences, [0] * n), exact_sign_p(differences))

    def test_exact_all_tied_n32_against_binomial(self):
        for positives in (0, 8, 16, 24, 32):
            differences = [1] * positives + [-1] * (32 - positives)
            tail = sum(math.comb(32, k) for k in range(min(positives, 32 - positives) + 1))
            self.assertEqual(stats.wilcoxon(differences, [0] * 32), min(1, 2 * tail / 2 ** 32))

    def test_all_zero(self):
        self.assertEqual(stats.wilcoxon([0] * 32, [0] * 32), 1)


class RatioIntervalTests(unittest.TestCase):
    def test_walsh_endpoints_n8_n16_n32(self):
        # Critical indices independently enumerated from the exact null sign sums.
        for n, k in ((8, 6), (16, 36), (32, 176)):
            exponents = [-3, -1, 0, 0, 1, 2, 2, 3] * (n // 8)
            logs = [math.log(2.0 ** exponent) for exponent in exponents]
            walsh = sorted((x + y) / 2 for i, x in enumerate(logs) for y in logs[i:])
            expected = (math.exp(walsh[k - 1]), math.exp(walsh[-k]))
            with self.subTest(n=n):
                self.assertEqual(stats.ratio_ci([1] * n, [2.0 ** x for x in exponents]), expected)

    def test_critical_indices_against_null_enumeration(self):
        for n, k in ((8, 6), (16, 36)):
            sums = [sum(rank for rank, sign in enumerate(signs, 1) if sign)
                    for signs in itertools.product((False, True), repeat=n)]
            self.assertLessEqual(sum(s < k for s in sums) / 2 ** n, .05)
            self.assertGreater(sum(s <= k for s in sums) / 2 ** n, .05)

    def test_small_n_and_equal_samples(self):
        for n in (0, 1, 2, 3, 4):
            self.assertIsNone(stats.ratio_ci([1] * n, [1] * n))
        for n in (5, 8, 16, 32):
            self.assertEqual(stats.ratio_ci([1] * n, [1] * n), (1, 1))

    def test_swapped_pair_interval_is_reciprocal(self):
        base = [1, 2, 3, 4, 5, 6, 7, 8]
        new = [1, 4, 3, 2, 10, 12, 3.5, 16]
        lo, hi = stats.ratio_ci(base, new)
        swapped_lo, swapped_hi = stats.ratio_ci(new, base)
        self.assertAlmostEqual(swapped_lo, 1 / hi)
        self.assertAlmostEqual(swapped_hi, 1 / lo)

    def test_invalid_confidence(self):
        for conf in (0, 1, -1, 2, float("nan"), float("inf")):
            with self.subTest(conf=conf), self.assertRaises(ValueError):
                stats.ratio_ci([1] * 8, [1] * 8, conf)


class CompareTests(unittest.TestCase):
    def test_inverted_marginal_direction(self):
        base = [5, 1, 2, 2, 100, 20, 50, 1]
        new = [5.5, .8, 1.6, 1, 90, 16, 25, .5]
        result = stats.compare(base, new)
        self.assertEqual(result["ratio_medians"], 1.014)
        self.assertLess(result["ratio"], 1)
        self.assertLess(result["ci90"][1], 1)
        self.assertEqual(result["verdict"], "LOSS")
        self.assertEqual(stats.compare(base, new, False)["verdict"], "WIN")
        logs = [math.log(y / x) for x, y in zip(base, new)]
        self.assertEqual(result["p"], round(exact_sign_p(logs), 3))
        self.assertNotEqual(result["p"], round(stats.wilcoxon(new, base), 3))

    def test_equal_marginal_medians_do_not_force_loss(self):
        base = [1] * 7 + [10] * 2 + [100] * 7
        new = [1.1] * 7 + [10] * 2 + [101] * 7
        result = stats.compare(base, new)
        self.assertEqual(result["ratio_medians"], 1)
        self.assertEqual(result["base"], result["new"])
        self.assertGreater(result["ratio"], 1)
        self.assertEqual(result["verdict"], "WIN")
        self.assertEqual(stats.compare(base, new, False)["verdict"], "LOSS")

    def test_constant_improvement_agrees(self):
        result = stats.compare([100] * 8, [110] * 8)
        self.assertEqual(result, {"base": 100.0, "new": 110.0, "ratio": 1.1, "ratio_medians": 1.1,
                                  "p": .008, "n": 8, "ci90": [1.1, 1.1], "verdict": "WIN"})

    def test_hl_is_median_of_walsh_logs(self):
        base = [1] * 8
        new = [1, 1, 1, 1, 2, 4, 8, 16]
        logs = [math.log(x) for x in new]
        walsh = [(x + y) / 2 for i, x in enumerate(logs) for y in logs[i:]]
        result = stats.compare(base, new)
        self.assertEqual(result["ratio"], round(math.exp(statistics.median(walsh)), 3))
        self.assertEqual(result["p"], round(exact_sign_p(logs), 3))

    def test_neutral_hl_with_significant_zero_dropped_test_is_unclear(self):
        for new in ([1] * 24 + [2] * 8, [1] * 24 + [.5] * 8):
            for higher_better in (True, False):
                result = stats.compare([1] * 32, new, higher_better)
                self.assertEqual(result["ratio"], 1)
                self.assertLess(result["p"], .05)
                self.assertEqual(result["verdict"], "unclear")

    def test_identical_positive_samples(self):
        result = stats.compare([10] * 8, [10] * 8)
        self.assertEqual(result["p"], 1)
        self.assertEqual(result["ci90"], [1, 1])
        self.assertEqual(result["verdict"], "tie")

    def test_missing_pairs_are_dropped_and_zip_pairing_preserved(self):
        self.assertIsNone(stats.compare([], []))
        self.assertIsNone(stats.compare([1, None], [2, 3]))
        result = stats.compare([None, 1, 2, 3], [0, 2, 4])
        self.assertEqual(result["n"], 2)
        self.assertEqual(result["ratio"], 2)
        self.assertEqual(result["ratio_medians"], 2)
        self.assertIsNone(result["ci90"])

    def test_nonpositive_and_nonfinite_pairs_fail_closed(self):
        for invalid in (0, -1, float("nan"), float("inf"), float("-inf")):
            for sample in ([invalid] * 8, [1] * 7 + [invalid]):
                with self.subTest(invalid=invalid, sample=sample):
                    self.assertIsNone(stats.compare([1] * 8, sample))
                    self.assertIsNone(stats.compare(sample, [1] * 8))
                    self.assertIsNone(stats.ratio_ci([1] * 8, sample))
                    self.assertIsNone(stats.ratio_ci(sample, [1] * 8))
        self.assertIsNone(stats.compare([0] * 8, [0] * 8))

    def test_nonrepresentable_pair_ratio_fails_closed(self):
        for base, new in (([1e-300] * 8, [1e300] * 8), ([1e300] * 8, [1e-300] * 8)):
            self.assertIsNone(stats.compare(base, new))
            self.assertIsNone(stats.ratio_ci(base, new))

    def test_verdict_boundaries(self):
        cases = [(1, .05, True, (.95, 1.05), "tie"), (1, .05, False, (.95, 1.05), "tie"),
                 (1, .05, True, (.949, 1.05), "unclear"), (1, .05, False, (.95, 1.051), "unclear"),
                 (.97, .05, True, (.96, .98), "watch"), (1.03, .05, False, (1.02, 1.04), "watch"),
                 (1, .05, True, None, "unclear")]
        for ratio, p, higher_better, ci, expected in cases:
            with self.subTest(ratio=ratio, p=p, higher_better=higher_better, ci=ci):
                self.assertEqual(stats.verdict(ratio, p, higher_better, ci), expected)


if __name__ == "__main__":
    unittest.main()
