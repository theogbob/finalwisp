"""Inventory of a compat gate run (80.02): for every step, how many assertions it printed, as a machine-readable
file, so that "every assertion still runs" is a diff of two files and not a claim.

usage: python3 -m wispsuite.inventory COMPAT_OUT_DIR [-o FILE]        write the inventory (JSON) of one run
       python3 -m wispsuite.inventory --diff A.json B.json           print what differs; exit 1 if B has less than A
Per step: status, kind and counts.
  kind "lines":   pass / fail / skip = the lines that start with PASS / FAIL / SKIP (tests/compat scripts, wisp-js)
  kind "cargo":   tests_passed / tests_failed / tests_ignored from the `test result:` lines
  kind "fuzz":    corpus_files = the files libFuzzer loaded ("seed corpus: files: N"), runs = "Done N runs"
  kind "tls":     sections = the section verdicts of run_tls.sh; pass = the sum of its "passed: N" lines (since 80.02;
                  null for a log of an older tree, where the PASS lines of this step were not counted)
  kind "none":    the step prints nothing countable (fuzz-build)
--diff: a step of A that B does not have, or a count of A that is larger than in B, is a LOSS (exit 1); more in B is
listed as "more". Numbers that a step measures (bytes, seconds) are not part of the inventory."""
import json, os, re, sys


def step_inventory(name, status, text):
    if name == "cargo":
        res = [re.search(r"(\d+) passed; (\d+) failed; (\d+) ignored", l) for l in text.splitlines() if l.startswith("test result:")]
        res = [m for m in res if m]
        return {"kind": "cargo", "tests_passed": sum(int(m.group(1)) for m in res), "tests_failed": sum(int(m.group(2)) for m in res),
                "tests_ignored": sum(int(m.group(3)) for m in res), "test_binaries": len(res)}
    if name == "fuzz-build":
        return {"kind": "none"}
    if name.startswith("fuzz-"):
        files = re.search(r"seed corpus: files: (\d+)", text)
        runs = re.search(r"Done (\d+) runs", text)
        return {"kind": "fuzz", "corpus_files": int(files.group(1)) if files else None, "runs": int(runs.group(1)) if runs else None}
    lines = text.splitlines()
    d = {"kind": "lines", "pass": sum(l.startswith("PASS") for l in lines), "fail": sum(l.startswith("FAIL") for l in lines),
         "skip": sum(l.startswith("SKIP") for l in lines)}
    if name == "tls":
        counted = [int(l.split()[1]) for l in lines if re.match(r"passed: \d+$", l)]
        d.update(kind="tls", sections=sum(l.startswith("== ") for l in lines), sections_all_pass=sum(l.strip() == "ALL PASS" for l in lines),
                 **{"pass": sum(counted) if counted else None})
    return d


def inventory(compat_dir):
    with open(os.path.join(compat_dir, "results.json")) as f:
        res = json.load(f)
    steps = {}
    for s in res["steps"]:
        log = os.path.join(compat_dir, s["step"].replace(" ", "_").replace("/", "_") + ".log")
        try:
            with open(log, errors="replace") as f:
                text = f.read()
        except OSError:
            text = ""
        steps[s["step"]] = {"status": s["status"], **step_inventory(s["step"], s["status"], text)}
    return {"dir": os.path.abspath(compat_dir), "binaries": res.get("binaries"), "jobs": res.get("jobs", 0), "steps": steps}


COUNTS = ("pass", "tests_passed", "test_binaries", "corpus_files", "sections", "sections_all_pass")   # fewer in B = LOSS
# "runs" of a fuzz replay is recorded and not compared: libFuzzer's "Done N runs" is not the same from run to run for the
# same corpus files (seen: 2303 files, 2639 and 2637 runs)
NOT_RUN = ("skip", "tests_ignored")   # more in B = LOSS (something that ran in A did not run in B)
BAD = ("fail", "tests_failed")        # any difference is reported; it is a LOSS only together with the rules above


def diff(a, b):
    """[(step, what)] losses, [(step, what)] more. A loss: a step is missing, a status is not the same (in any direction:
    a FAIL that became PASS means B did not see what A saw), a count of COUNTS went down or is no longer known, or a
    count of NOT_RUN went up. A count that A did not know (None) cannot be compared: reported as `more` when B knows it."""
    loss, more = [], []
    for name, sa in a["steps"].items():
        sb = b["steps"].get(name)
        if sb is None:
            loss.append((name, "step missing"))
            continue
        if sa["status"] != sb["status"]:
            loss.append((name, f"status {sa['status']} -> {sb['status']}"))
        if sa["kind"] != sb["kind"]:
            loss.append((name, f"kind {sa['kind']} -> {sb['kind']}"))
        for k in COUNTS + NOT_RUN + BAD:
            va, vb = sa.get(k), sb.get(k)
            if va is None and vb is None:
                continue
            if va is None:
                more.append((name, f"{k} not counted -> {vb}"))
            elif vb is None:
                loss.append((name, f"{k} {va} -> not counted"))
            elif vb != va:
                down = vb < va if k in COUNTS else vb > va if k in NOT_RUN else False
                (loss if down else more).append((name, f"{k} {va} -> {vb}"))
    for name in b["steps"]:
        if name not in a["steps"]:
            more.append((name, "new step"))
    return loss, more


def main(argv):
    if argv and argv[0] == "--diff":
        with open(argv[1]) as f:
            a = json.load(f)
        with open(argv[2]) as f:
            b = json.load(f)
        loss, more = diff(a, b)
        for name, what in loss:
            print(f"LOSS {name}: {what}")
        for name, what in more:
            print(f"more {name}: {what}")
        print(f"inventory diff: {len(a['steps'])} steps in A, {len(b['steps'])} in B, {len(loss)} losses, {len(more)} more")
        sys.exit(1 if loss else 0)
    inv = inventory(argv[0])
    text = json.dumps(inv, indent=1, sort_keys=True) + "\n"
    if "-o" in argv:
        with open(argv[argv.index("-o") + 1], "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main(sys.argv[1:])
