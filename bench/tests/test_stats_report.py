"""30.10 regression-table labels distinguish paired inference from marginal summaries."""
import unittest

from wispsuite.regress import table


class StatsReportTests(unittest.TestCase):
    def test_paired_and_marginal_columns_are_separate_and_missing_values_stay_blank(self):
        rows = [{"case": "opposite", "metric": "rate", "base": 3.5, "new": 3.55,
                 "ratio": .75, "ratio_medians": 1.014, "ci90": [.5, .9], "p": .023,
                 "verdict": "LOSS", "cpu_per_unit": {"ratio": .92},
                 "peak_mib": {"base": 100, "new": 90}, "errors": {"base": 0, "new": 1}},
                {"case": "missing", "metric": "rate", "verdict": "no-data"}]
        lines = table(rows).splitlines()
        cells = [[cell.strip() for cell in line.strip("|").split("|")] for line in lines]
        self.assertEqual(cells[0], ["case", "metric", "base median", "new median", "paired HL ratio",
                                   "marginal median ratio", "90% CI", "p", "verdict", "cpu/unit HL ratio",
                                   "peak MiB base->new", "errors b/n"])
        self.assertTrue(all(len(row) == len(cells[0]) for row in cells))
        self.assertEqual(cells[2], ["opposite", "rate", "3.5", "3.55", "0.75", "1.01", "0.5-0.9",
                                   "0.023", "**LOSS**", "0.92", "100 -> 90", "0/1"])
        self.assertEqual(cells[3], ["missing", "rate", "", "", "", "", "", "", "**no-data**", "", "", "/"])


if __name__ == "__main__":
    unittest.main()
