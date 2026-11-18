#!/usr/bin/env python3
"""60.78 G16: which Stats counters (server/src/metrics.rs, the stats! block) does no test assert?
usage: bench/tools/counter_cover.py [--check]
A counter is covered when its name appears as a word in test code (comments removed): worker/*tests.rs, the `#[cfg(test)] mod tests` part of
any other server/src file, or tests/compat/*.py|*.mjs (the compat tests read the metrics line by key). Prints one row per
counter (covered / EXCEPTION reason / UNCOVERED) and the totals. --check: exit 1 when a counter is UNCOVERED (an exception
needs its reason in EXCEPTIONS below), or when an exception is covered after all (stale entry)."""
import os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "server", "src")

# counters no test can move, with the reason (60.78 G16)
EXCEPTIONS = {
    "accept_err_mem": "accept4 failing with ENOBUFS / ENOMEM needs kernel memory exhaustion (no sysctl writes, no hook); "
    "the branch only picks this counter or accept_err_fd (EMFILE / ENFILE; tests/compat/fds.py reads it)",
}


def counters():
    t = open(os.path.join(SRC, "metrics.rs")).read()
    block = t[t.index("stats! {\n"):]
    block = block[: block.index("\n}\n")]
    return re.findall(r"^    ([a-z][a-z0-9_]*),$", block, re.M)


RS_COMMENT = re.compile(r"//.*$", re.M)  # (a `//` inside a string literal is cut too: only shortens the text searched)
PY_COMMENT = re.compile(r"(^|\s)#.*$", re.M)


def test_text():
    """the test code, comments removed (a counter named in a comment is not asserted)"""
    parts = []
    for dp, _, fs in os.walk(SRC):
        for f in fs:
            if not f.endswith(".rs"):
                continue
            t = open(os.path.join(dp, f)).read()
            if f.endswith("tests.rs"):
                parts.append(RS_COMMENT.sub("", t))
            else:
                m = re.search(r"^#\[cfg\(test\)\]\nmod tests", t, re.M)
                if m:
                    parts.append(RS_COMMENT.sub("", t[m.start():]))
    cd = os.path.join(ROOT, "tests", "compat")
    for f in sorted(os.listdir(cd)):
        if f.endswith(".py"):
            parts.append(PY_COMMENT.sub("", open(os.path.join(cd, f)).read()))
        elif f.endswith(".mjs"):
            parts.append(RS_COMMENT.sub("", open(os.path.join(cd, f)).read()))
    return "\n".join(parts)


def main():
    names, text = counters(), test_text()
    assert len(names) > 100 and len(set(names)) == len(names), len(names)
    bad = 0
    rows = {"covered": 0, "exception": 0, "uncovered": 0}
    for n in names:
        hit = re.search(r"\b%s\b" % re.escape(n), text) is not None
        if n in EXCEPTIONS:
            if hit:
                print(f"STALE      {n}: covered, remove it from EXCEPTIONS")
                bad += 1
            else:
                print(f"EXCEPTION  {n}: {EXCEPTIONS[n]}")
                rows["exception"] += 1
        elif hit:
            rows["covered"] += 1
        else:
            print(f"UNCOVERED  {n}")
            rows["uncovered"] += 1
            bad += 1
    print(f"counters {len(names)}: covered {rows['covered']}, exceptions {rows['exception']}, uncovered {rows['uncovered']}")
    if "--check" in sys.argv[1:]:
        print("OK" if bad == 0 else "BROKEN")
        sys.exit(1 if bad else 0)


main()
