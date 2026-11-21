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


def compare(base, new, higher_better=True, care=None, mde=False):
    """Pair by zip, dropping None pairs; return None for fewer than two valid pairs.

    80.04: mde=True or care adds "mde" (the run's minimum detectable effect, percent, see mde()) and "bound" (the worst
    effect the 90 % interval does not exclude, percent worse). care (a fraction, e.g. 0.02): verdict becomes one of the
    four contract words by verdict_care (tie only when a loss > care is excluded), "verdict_today" keeps today's word and
    "note" says watch. Without both, the result is exactly today's.

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
    out = {"base": mb, "new": mn, "ratio": round(ratio, 3), "ratio_medians": round(mn / mb, 3),
           "p": round(p, 3), "n": len(pairs),
           "ci90": [round(ci[0], 3), round(ci[1], 3)] if ci else None,
           "verdict": verdict(ratio, p, higher_better, ci)}
    if mde or care is not None:
        out["mde"] = globals()["mde"](logs, higher_better)
        out["bound"] = bound(ci, higher_better)
    if care is not None:
        out["verdict_today"] = out["verdict"]
        out["verdict"], out["note"] = verdict_care(ratio, p, higher_better, ci, care)
    return out


# ---- 80.04 L6: minimum detectable effect, the observed loss bound, a "care" tie rule, contract rows.
# compare() without care/mde returns exactly what it returned before (gate tables and tests compare whole dicts).
MDE_POWER = 0.80   # MDE = the smallest loss that the full rule (p < ALPHA, HL on the loss side) reads LOSS in 80 % of tries
MDE_SIMS = 400     # sign-flip tries per run (fixed seed: the same data give the same MDE)
MDE_CAL = 1.1      # calibration factor on the log scale: fitted on archived A/A sessions (held out: 1.05-1.25; 80.04)
_CRIT = {}


def crit_w(n, alpha=ALPHA):
    """largest W+ whose exact two-sided Wilcoxon p (no ties) is < alpha; -1 when no W+ is (n < 6 at 0.05)"""
    if (n, alpha) not in _CRIT:
        m = n * (n + 1) // 2
        dist = [1] + [0] * m
        for r in range(1, n + 1):
            for s in range(m, r - 1, -1):
                dist[s] += dist[s - r]
        cum, c, tot = 0, -1, 2 ** n
        for w in range(m + 1):
            cum += dist[w]
            if 2 * cum / tot >= alpha:
                break
            c = w
        _CRIT[(n, alpha)] = c
    return _CRIT[(n, alpha)]


def loss_shift(z):
    """z = paired log ratios oriented so that a loss is negative. -> the smallest downward shift s (log scale) at which
    the rule reads LOSS: W+ = the number of positive Walsh averages, so W+ <= crit_w(n) once the shift moves the (c+1)-th
    largest Walsh average below 0. Exact for data without ties or zeros (continuous rates); with ties (repeated values)
    the rule's midrank test can need a larger shift, so it is an approximation there. None when n is too small for any
    p < ALPHA."""
    c = crit_w(len(z))
    if c < 0:
        return None
    w = sorted(((x + y) / 2 for i, x in enumerate(z) for y in z[i:]), reverse=True)
    return w[c]


def mde(logs, higher_better=True, power=MDE_POWER, sims=MDE_SIMS, seed=8004):
    """80.04: the run's minimum detectable effect in percent: the loss that the full rule would read LOSS in `power` of
    the tries, a try being this run's own centred residuals (log ratios minus their HL) with random signs, so the noise
    is the run's and the true effect is removed. Loss = rate x (1 - d) for higher_better, latency x (1 + d) otherwise.
    None for fewer than 6 pairs. Calibrated on archived A/A sessions by MDE_CAL (80.04)."""
    z = [x if higher_better else -x for x in logs]
    if crit_w(len(z)) < 0:
        return None
    h = st.median(_walsh(z))
    e = [x - h for x in z]
    rng = __import__("random").Random(seed)
    th = sorted(loss_shift([x if rng.random() < 0.5 else -x for x in e]) for _ in range(sims))
    s = max(0.0, th[min(sims - 1, int(math.ceil(power * sims)) - 1)]) * MDE_CAL
    d = (1 - math.exp(-s)) if higher_better else (math.exp(s) - 1)
    return round(100 * d, 2)


def bound(ci, higher_better=True):
    """the worst effect the 90 % interval does not exclude, in percent worse (negative: the interval excludes any loss)"""
    if not ci:
        return None
    return round(100 * ((1 - ci[0]) if higher_better else (ci[1] - 1)), 2)


def verdict_care(ratio, p, higher_better, ci, care):
    """80.04 four words: LOSS / WIN as today's rule; tie only when the 90 % interval excludes a loss larger than `care`
    (a fraction, e.g. 0.02) and the HL is not a watch; everything else unclear. -> (word, note); note "watch" when today's
    rule says watch."""
    v = verdict(ratio, p, higher_better, ci)
    if v in ("LOSS", "WIN"):
        return v, ""
    if v == "watch":
        return "unclear", "watch"
    if p < ALPHA or ci is None:
        return "unclear", ""
    worst = ci[0] if higher_better else ci[1]
    return ("tie" if (worst >= 1 - care if higher_better else worst <= 1 + care) else "unclear"), ""


def contract_row(cell, metric, unit, c, higher_better=True, care=None):
    """80.04 result contract row from a compare() result c (None -> verdict unclear, n 0). Verdict words: WIN / tie / LOSS /
    unclear; today's watch -> unclear with note "watch"; a floored link-cell tie (wbench.floored) -> tie with its note."""
    row = {"cell": cell, "metric": metric, "unit": unit, "a": None, "b": None, "ratio": None, "ci_lo": None, "ci_hi": None,
           "verdict": "unclear", "n": 0, "mde": None, "note": "no valid pairs"}
    if not c:
        return row
    v, note = c["verdict"], c.get("note", "")
    if v.startswith("tie ("):
        v, note = "tie", v[5:-1]
    elif v == "watch":
        v, note = "unclear", "watch"
    if care is not None and "verdict_today" not in c and v == "tie" and c.get("ci90"):
        lo, hi = c["ci90"]
        if (lo < 1 - care) if higher_better else (hi > 1 + care):
            v, note = "unclear", f"a loss above {100 * care:g} % is not excluded"
    if v == "unclear" and c.get("mde") is not None and "MDE" not in note:
        note = (note + "; " if note else "") + f"MDE {c['mde']:g} %"
    row.update(a=c["base"], b=c["new"], ratio=c["ratio"], ci_lo=c["ci90"][0] if c.get("ci90") else None,
               ci_hi=c["ci90"][1] if c.get("ci90") else None, verdict=v, n=c["n"], mde=c.get("mde"), note=note)
    return row


# ---- 80.04 L6: a verdict rule for COUNTED metrics (instructions, system calls, wakeups per unit; a few reps per arm)
COUNT_K = 4.0   # flag at |d| > 4 standard errors; chosen post hoc on 19 archived A/A sessions of counted metrics: the false-flag
                # rate is known only after a fresh A/A set is scored with k fixed (80.04)
Z80 = 0.8416    # one-sided normal quantile of 80 % power


def counted(base, new, sigma=None, k=COUNT_K, layout=0.0, higher_better=False, care=None, min_df=6):
    """80.04 counted rule. base / new: per-rep values of ONE element per unit of work (one session, both arms in it).
    d = median(log new) - median(log base); se = max(sigma, pooled sd of the logs) x sqrt(1/nb + 1/nn), sigma = the
    element's A/A spread from a reference set of sessions (80.04: the 75th percentile of the within-session sd);
    without sigma the pooled sd alone needs min_df degrees of freedom. LOSS / WIN when |d| > max(k x se, layout) (layout =
    the element's code-layout floor, e.g. |log(fk-off / v140)|); tie when care is given and |d| + k x se <= log(1 + care);
    else unclear. mde = the change seen at 80 % power, max(k x se, layout) + 0.84 x se, in percent. One side all zero and
    the other not: LOSS / WIN by direction (a new or vanished count). Negative or non-finite values: no verdict. Counts:
    lower is better (higher_better=False)."""
    if not (sigma is None or (math.isfinite(sigma) and sigma >= 0)) or not (math.isfinite(k) and k > 0) or not (math.isfinite(layout) and layout >= 0) \
            or not (care is None or (math.isfinite(care) and care > 0)):
        raise ValueError(f"counted: sigma {sigma}, k {k}, layout {layout}, care {care}: need finite values, sigma / layout >= 0, k / care > 0")
    b = [x for x in base if x is not None]
    n = [x for x in new if x is not None]
    out = {"base": None, "new": None, "ratio": None, "n": min(len(b), len(n)), "ci90": None, "verdict": "unclear", "mde": None, "note": ""}
    if any(not math.isfinite(x) or x < 0 for x in b + n):
        out["note"] = "negative or non-finite values"
        return out
    if len(b) < 2 or len(n) < 2:
        out["note"] = "fewer than 2 reps per arm"
        return out
    out["base"], out["new"] = st.median(b), st.median(n)
    if min(b + n) <= 0:
        if max(b) == 0 and min(n) > 0 or max(n) == 0 and min(b) > 0:
            up = max(b) == 0
            out["verdict"], out["note"] = ("WIN" if up == higher_better else "LOSS"), ("only new has it" if up else "only base has it")
        else:
            out["note"] = "zero values in " + " and ".join(s for s, v in (("base", b), ("new", n)) if min(v) <= 0) + " (no side all zero against a count)"
        return out
    lb, ln = [math.log(x) for x in b], [math.log(x) for x in n]
    df = len(lb) + len(ln) - 2
    pooled = math.sqrt(((len(lb) - 1) * st.variance(lb) + (len(ln) - 1) * st.variance(ln)) / df) if df > 0 else 0.0
    if sigma is None and df < min_df:
        out["note"] = f"no A/A spread for this element and only {df} degrees of freedom"
        sig = None
    else:
        sig = max(sigma or 0.0, pooled)
    d = st.median(ln) - st.median(lb)
    out["ratio"] = round(math.exp(d), 5)
    if sig is None:
        return out
    se = sig * math.sqrt(1 / len(lb) + 1 / len(ln))
    out["ci90"] = [round(math.exp(d - 1.645 * se), 5), round(math.exp(d + 1.645 * se), 5)]
    out["mde"] = round(100 * (math.exp(max(k * se, layout) + Z80 * se) - 1), 3)
    if abs(d) > max(k * se, layout):
        worse = (d < 0) if higher_better else (d > 0)
        out["verdict"] = "LOSS" if worse else "WIN"
    elif care is not None and abs(d) + k * se <= math.log(1 + care):
        out["verdict"] = "tie"
    elif abs(d) > k * se:
        out["note"] = f"inside the layout floor {100 * layout:.3g}%"
    return out


def counted_reps(sigma, floor, k=COUNT_K, layout=0.0):
    """reps per arm for the counted rule to see a change of `floor` (a fraction) at 80 % power (normal approximation);
    None when the change is not above the layout floor (the rule can never flag it)"""
    if not (math.isfinite(sigma) and sigma >= 0 and math.isfinite(floor) and floor > 0 and math.isfinite(k) and k > 0 and math.isfinite(layout) and layout >= 0):
        raise ValueError(f"counted_reps: sigma {sigma}, floor {floor}, k {k}, layout {layout}: need finite values, sigma / layout >= 0, floor / k > 0")
    if math.log(1 + floor) <= layout:
        return None
    if sigma <= 0:
        return 2
    # se = sigma x sqrt(2 / r); needed: log(1 + floor) >= max(k x se, layout) + Z80 x se, i.e. se <= min(L / (k + Z80), (L - layout) / Z80)
    L = math.log(1 + floor)
    se = min(L / (k + Z80), (L - layout) / Z80)
    return max(2, math.ceil(2 * (sigma / se) ** 2))


def median(xs, nd=1):
    """Median of the non-None values, rounded; None if there are none (never a -1 placeholder)."""
    v = [x for x in xs if x is not None]
    return round(st.median(v), nd) if v else None
