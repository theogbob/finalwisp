#!/usr/bin/env python3
"""60.76: the "## Performance" block of README.public.md, computed from docs/benchmarks.md (v1.3.2 release text).

usage: python3 bench/v132-readme-perf.py [--bench docs/benchmarks.md]            # prints the block
       python3 bench/v132-readme-perf.py --check README.public.md                 # exit 1 unless the README has it

Rules (as 30.19's ranges.py): per machine the MAIN value table only (on the VPSes the 10 x 2 bulk rows; the dropped
10 x 10 rows are not used). A multiplier is the page's ratio table entry of the cell, so the README and the page say
the same numbers; it is checked against finalwisp / other of the value cells (1.5 %: both are rounded). It counts only
where both value cells are valid: a value above 0, no "(P n/3)" (kernel TCP memory pressure), no "err" (60.76,
2026-11-15: also when the cell moved data, so no multiplier rests on a run where a server failed), no crash mark.
epoxy-server = the "tokio-websockets 0.12.3" column. Range ends are rounded down, never up (60.76, 2026-11-15):
below 2 with two decimals, from 2 on with one. The memory bullets use the same four columns (a server whose runs
crashed is not compared, as on the page).
"""
import argparse, math, re, sys, textwrap

MACHINES = [("80-thread server", "## 80-thread server"), ("VPS A", "## 2-core VPS A"), ("VPS B", "## 2-core VPS B")]
OTHERS = [  # README row, the page's column, link, footnote mark
    ("epoxy-server", "epoxy-server, tokio-websockets 0.12.3", "https://github.com/MercuryWorkshop/epoxy-tls", "²"),
    ("wisp-server-python", "wisp-server-python", "https://github.com/MercuryWorkshop/wisp-server-python", ""),
    ("wisp-js", "wisp-js", "https://github.com/MercuryWorkshop/wisp-js", ""),
    ("wispurr", "wispurr", "https://github.com/sylvieisnton/wispurr", "³"),
]
CATS = ["Throughput", "Requests/s", "New streams/s"]


def cat(case):
    for pre, c in (("upload", 0), ("download", 0), ("echo", 0), ("request/response", 1), ("new stream per request", 2)):
        if case.startswith(pre):
            return CATS[c]
    return None  # memory rows


def tables(text):
    """[(header, rows)] of every markdown table in text, rows = list of cell lists."""
    out, cur = [], None
    for line in text.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cur is None:
                cur = (cells, [])
                out.append(cur)
            elif not all(re.fullmatch(r"-+", c) for c in cells):
                cur[1].append(cells)
        else:
            cur = None
    return out


def section(text, head):
    i = text.index("\n" + head + "\n")
    j = text.find("\n## ", i + 1)
    return text[i: j if j > 0 else len(text)]


def value(cell):
    """(number or None, valid)"""
    m = re.match(r"([\d,]+(?:\.\d+)?)", cell)
    v = float(m.group(1).replace(",", "")) if m else None
    return v, v is not None and v > 0 and "(P " not in cell and "crash" not in cell and " err)" not in cell


def load(path):
    text = open(path, encoding="utf-8").read()
    data = {}
    for name, head in MACHINES:
        ts = tables(section(text, head))
        vt = next(t for t in ts if t[0][:2] == ["case", "finalwisp"])        # the first value table = main rows
        rt = next(t for t in ts if t[0][:2] == ["case", "vs best other"])    # its ratio table
        rows = {r[0]: dict(zip(vt[0], r)) for r in vt[1]}
        ratios = {r[0]: dict(zip(rt[0], r)) for r in rt[1]}
        data[name] = (rows, ratios)
    return data


def fmt_x(x):
    """rounded DOWN, never up (60.76, 2026-11-15): below 2 with two decimals (1.051 -> 1.05), from 2 on with one
    (4.19 -> 4.1, 15.19 -> 15.1); the page's ratio tables have two decimals, so a README end never says more"""
    x = round(x, 9)  # a quotient such as 1.3 / 1.0 must not floor to 1.29
    return f"{math.floor(x * 100) / 100:.2f}" if x < 2 else f"{math.floor(x * 10) / 10:.1f}"


def wrap(text, **kw):
    """textwrap.fill that does not break between a number and its unit"""
    t = re.sub(r"(\d) (MiB|GiB)", "\\1\u00a0\\2", text)
    return textwrap.fill(t, 118, break_on_hyphens=False, **kw).replace("\u00a0", " ")


def fmt_mib(v):
    return f"{v / 1024:.1f} GiB" if v >= 1024 else f"{v:,.0f} MiB" if v >= 100 else f"{v:g} MiB"


def build(data):
    ranges = {}
    for name, (rows, ratios) in data.items():
        for case, row in rows.items():
            c = cat(case)
            if c is None:
                continue
            fw, ok = value(row["finalwisp"])
            if not ok:
                continue
            short = case.split(" (")[0]
            for s, col, _, _ in OTHERS:
                o, ok = value(row[col])
                if not ok:
                    continue
                x = fw / o
                page = float(ratios[short]["vs " + col])
                if abs(x - page) > 0.015 * page:
                    sys.exit(f"{name} {short} vs {col}: {x:.3f} from the values, {page} in the ratio table")
                ranges.setdefault((s, c), []).append(page)  # the page's own ratio: README and page say the same
    lines = ["## Performance", "", "How many times faster finalwisp is than each server (valid cells only¹):", "",
             "| finalwisp vs | " + " | ".join(CATS) + " |", "|---|---|---|---|"]
    for s, _, link, mark in OTHERS:
        cells = [f"{fmt_x(min(ranges[(s, c)]))}–{fmt_x(max(ranges[(s, c)]))}×" for c in CATS]
        lines.append(f"| [{s}]({link}){mark} | " + " | ".join(cells) + " |")

    big_rows = data["80-thread server"][0]
    vps = [data["VPS A"][0], data["VPS B"][0]]

    def best_bulk(rowsets):
        best = None
        for rows in rowsets:
            for case, row in rows.items():
                v, ok = value(row["finalwisp"])
                if cat(case) == "Throughput" and ok and (best is None or v > best[0]):
                    best = (v, case.split(",")[0])
        return best
    kind = {"upload": "uploads", "download": "downloads", "echo": "echo"}
    big_bulk, vps_bulk = best_bulk([big_rows]), best_bulk(vps)
    rr = "request/response, 10 conns x 10 streams (req/s)"
    big_rr = value(big_rows[rr]["finalwisp"])
    vps_rr = [value(r[rr]["finalwisp"]) for r in vps]
    assert big_rr[1] and all(ok for _, ok in vps_rr), "an rr 10x10 cell of finalwisp is not valid"
    vps_rr = sorted(v for v, _ in vps_rr)

    rss, peak = "RSS after the case, largest (MiB, median)", "peak RSS, VmHWM (MiB, max)"

    def mem(rows, row):
        fw = value(rows[row]["finalwisp"])[0]
        others = [(value(rows[row][col])[0], s) for s, col, _, _ in OTHERS if value(rows[row][col])[1]]
        return fw, others
    big_rss, vps_rss = mem(big_rows, rss), [mem(r, rss) for r in vps]
    vps_others = [v for _, o in vps_rss for v, _ in o]
    peaks = [mem(r, peak) for r in [big_rows] + vps]
    for fw, others in peaks:
        assert fw < min(v for v, _ in others), "finalwisp's peak is not the lowest on every machine: rewrite the bullet"
    near = [min(o) for _, o in peaks[1:]]

    bullets = [
        "Ranges cover an 80-thread Intel Xeon Gold server and two 2-core VPSes: finalwisp 1.3.1 and the newest version "
        "of every other server on 2026-11-15, each at its default or documented settings. A value is the median of 3 "
        "runs, one session per machine.",
        "These are loopback tests without TLS: they show what each server can push when the network is not the limit. "
        "Over a real link, the link usually runs out first.",
        f"On the big server finalwisp moved {big_bulk[0] / 1024:.1f} GiB/s of {kind[big_bulk[1]]} and "
        f"{big_rr[0] / 1000:.0f}k requests/s; on a 2-core VPS, up to {vps_bulk[0] / 1024:.1f} GiB/s "
        f"({kind[vps_bulk[1]]}: there the download tests ran short of TCP memory) and "
        f"{vps_rr[0] / 1000:.0f}–{vps_rr[-1] / 1000:.0f}k requests/s.",
        "finalwisp also hands memory back when the load stops: right after the heaviest test its resident memory was "
        f"{big_rss[0]:.0f} MiB on the big server and {min(fw for fw, _ in vps_rss):g}–{max(fw for fw, _ in vps_rss):g} "
        f"MiB on the 2-core VPSes; the others held {fmt_mib(min(v for v, _ in big_rss[1]))} to "
        f"{fmt_mib(max(v for v, _ in big_rss[1]))} on the big server and {fmt_mib(min(vps_others))} to "
        f"{fmt_mib(max(vps_others))} on the VPSes.",
        "Its peak memory under load (VmHWM) was the lowest of the servers whose runs did not crash, on all three "
        "machines. On the VPSes the "
        f"next lowest was {near[0][1]} with {near[0][0]:g} MiB against {peaks[1][0]:g} on one, and {near[1][1]} with "
        f"{near[1][0]:g} MiB against {peaks[2][0]:g} on the other.",
    ]
    lines.append("")
    lines += [wrap(b, initial_indent="- ", subsequent_indent="  ") for b in bullets]
    foot = [
        "¹ Valid cells only: a test is left out of a range where the kernel ran short of TCP memory during it (some bulk "
        "tests on the VPSes), and where either server moved no data, reported errors or had crashed.",
        "² Built from its repository as its README says, epoxy-server crashed under load on both VPSes (a panic in its "
        "tokio-websockets 0.12.0), and the tests after a crash had no server, so they have no value. Its numbers here "
        "are for the same commit with tokio-websockets 0.12.3, which did not crash. Details: "
        "[benchmarks](docs/benchmarks.md#notes).",
        "³ The tested version fixed the data-loss and flow-control bugs of the version tested before. It does not "
        "answer the Wisp v2 subprotocol, so a Wisp v2 client falls back to Wisp v1 with it.",
    ]
    lines += ["", "Full tables and method: [benchmarks](docs/benchmarks.md).", ""]
    for f in foot:
        lines += [wrap(f), ""]
    return "\n".join(lines) + "\n"


def block_of(readme):
    i = readme.index("## Performance\n")
    j = readme.index("\n## ", i + 1)
    return readme[i: j + 1]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bench", default="docs/benchmarks.md")
    ap.add_argument("--check", metavar="README", help="fail unless README's Performance block is the printed one")
    a = ap.parse_args()
    block = build(load(a.bench))
    if not a.check:
        sys.stdout.write(block)
        return
    have = block_of(open(a.check, encoding="utf-8").read())
    if have == block:
        print(f"OK: the Performance block of {a.check} follows {a.bench}")
        return
    import difflib
    sys.stdout.writelines(difflib.unified_diff(have.splitlines(True), block.splitlines(True), a.check, "computed"))
    sys.exit(f"BROKEN: the Performance block of {a.check} does not follow {a.bench}")


if __name__ == "__main__":
    main()
