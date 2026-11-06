"""Paired statistics for A/B runs (30.10; moved verbatim from regress.py, 60.01 Phase B)."""
import math
import statistics as st
from collections import defaultdict

ALPHA, WATCH, BIG = 0.05, 0.03, 0.20
NI_MARGIN = 0.05  # 60.12 non-inferiority margin for "tie" (see verdict)


def wilcoxon(a, b):
    """Exact two-sided Wilcoxon signed-rank p for paired samples (zero differences dropped, midranks for ties)."""
    d = [x - y for x, y in zip(a, b) if x != y]
    n = len(d)
    if n == 0:
        return 1.0
    order = sorted(range(n), key=lambda i: abs(d[i]))
    r2 = [0] * n  # doubled ranks keep midranks integral
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(d[order[j + 1]]) == abs(d[order[i]]):
            j += 1
        for k in range(i, j + 1):
            r2[order[k]] = i + j + 2
        i = j + 1
    wplus = sum(r for r, x in zip(r2, d) if x > 0)
    lo = min(wplus, sum(r2) - wplus)
    dist = {0: 1}
    for r in r2:
        nd = defaultdict(int)
        for s, c in dist.items():
            nd[s] += c
            nd[s + r] += c
        dist = nd
    return min(1.0, 2 * sum(c for s, c in dist.items() if s <= lo) / 2 ** n)


def _log_ratios(base, new):
    """Return paired log ratios, or None if any pair cannot support ratio inference."""
    logs = []
    for x, y in zip(base, new):
        if not (math.isfinite(x) and math.isfinite(y)) or x <= 0 or y <= 0:
            return None
        ratio = y / x
        if not math.isfinite(ratio) or ratio <= 0:
            return None
        logs.append(math.log(ratio))
    return logs


def _walsh(logs):
    return sorted((x + y) / 2 for i, x in enumerate(logs) for y in logs[i:])


def _ratio_ci(n, walsh, conf):
    """Walsh order-statistic interval, with the exact no-tie signed-rank cutoff."""
    if not 0 < conf < 1:
        raise ValueError("confidence must be between 0 and 1")
    m = n * (n + 1) // 2
    dist = [1] + [0] * m  # counts of W+ over the 2^n sign patterns for ranks 1..n
    for r in range(1, n + 1):
        for s in range(m, r - 1, -1):
            dist[s] += dist[s - r]
    tail, k, total = 0, 0, 2 ** n
    while (tail + dist[k]) / total <= (1 - conf) / 2:
        tail += dist[k]
        k += 1
    if k == 0:
        return None
    return math.exp(walsh[k - 1]), math.exp(walsh[m - k])


def ratio_ci(base, new, conf=0.90):
    """60.12 paired HL ratio CI: Walsh averages of log(new/base), exact no-tie cutoff.

    Pair by zip, as compare does. Return None for nonpositive/nonfinite measurements,
    nonrepresentable pair ratios, or too few pairs (n < 5 at 90%). Tied-data intervals
    use the no-tie cutoff, not a tie-adjusted inversion. Invalid confidence raises ValueError.
    """
    if not 0 < conf < 1:
        raise ValueError("confidence must be between 0 and 1")
    logs = _log_ratios(base, new)
    return _ratio_ci(len(logs), _walsh(logs), conf) if logs is not None else None


def verdict(ratio, p, higher_better, ci=None):
    """LOSS/WIN: p < ALPHA with a nonneutral paired HL ratio. watch: >= WATCH worse, not significant.
    tie: not significant AND the CI's worse-side bound is within NI_MARGIN (non-inferior).
    unclear: significant but HL-neutral, or not significant and a > NI_MARGIN cost is not excluded (60.12).
    """
    better = ratio > 1 if higher_better else ratio < 1
    worse_by = (1 - ratio) if higher_better else (ratio - 1)
    if p < ALPHA:
        # Many unchanged pairs can make HL neutral while the zero-dropped test rejects.
        if ratio == 1:
            return "unclear"
        return "WIN" if better else "LOSS"
    if worse_by >= WATCH:
        return "watch"
    if ci is None:
        return "unclear"
    worst = ci[0] if higher_better else ci[1]
    ok = worst >= 1 - NI_MARGIN if higher_better else worst <= 1 + NI_MARGIN
    return "tie" if ok else "unclear"


def compare(base, new, higher_better=True):
    """Pair by zip, dropping None pairs; return None for fewer than two valid pairs.

    30.10 / 60.12: ratio is the paired Hodges-Lehmann estimate exp(median(Walsh
    log-ratios)); p and ci90 use those same log-ratios. base/new are descriptive
    marginal medians, and ratio_medians is their ratio, not an inferential effect.
    Any retained nonpositive/nonfinite measurement or nonrepresentable pair ratio
    makes the comparison unavailable (None), rather than mixing inference scales.
    """
    pairs = [(b, n) for b, n in zip(base, new) if b is not None and n is not None]
    if len(pairs) < 2:
        return None
    b, n = zip(*pairs)
    logs = _log_ratios(b, n)
    if logs is None:
        return None
    walsh = _walsh(logs)
    ratio = math.exp(st.median(walsh))
    mb, mn = st.median(b), st.median(n)
    p = wilcoxon(logs, [0.0] * len(logs))
    ci = _ratio_ci(len(logs), walsh, 0.90)
    return {"base": mb, "new": mn, "ratio": round(ratio, 3), "ratio_medians": round(mn / mb, 3),
            "p": round(p, 3), "n": len(pairs),
            "ci90": [round(ci[0], 3), round(ci[1], 3)] if ci else None,
            "verdict": verdict(ratio, p, higher_better, ci)}


def median(xs, nd=1):
    """Median of the non-None values, rounded; None if there are none (never a -1 placeholder)."""
    v = [x for x in xs if x is not None]
    return round(st.median(v), nd) if v else None
