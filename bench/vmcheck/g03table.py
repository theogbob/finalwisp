#!/usr/bin/env python3
"""60.78 G03 table from the raw check files of bench/vmcheck/vmcheck.sh (and pressure.py). usage:
  g03table.py DIR [--check NOTE.md]   DIR/<vm>/out/checks.txt (+ pressure.txt). --check: exit 1 if a generated row is
  not in NOTE.md (stale or edited by hand). The 512 MiB RLIMIT_AS probe is its own column (below the idle VmSize: not
  a pass rule); every other PASS/FAIL line counts."""
import os, re, sys

D = sys.argv[1]
rows = ["| VM | kernel | system | cgroup | wss (kTLS) | checks PASS / FAIL (without the 512 MiB probe) | 512 MiB RLIMIT_AS probe | idle VmSize | G11/G12 pressure.py PASS / FAIL |",
        "|---|---|---|---|---|---|---|---|---|"]
for vm in sorted(os.listdir(D)):
    f = os.path.join(D, vm, "out", "checks.txt")
    if not os.path.isfile(f):
        continue
    L = open(f).read().splitlines()
    sysl = next(l for l in L if l.startswith("CHECK system INFO"))
    kern = re.search(r"kernel (\S+)", sysl).group(1)
    distro = sysl.split(" | ")[1]
    caps = next((l for l in L if l.startswith("CHECK bare-caps")), "")
    cg = re.search(r"cgroup: (v\d)", caps)
    cg = cg.group(1) if cg else ("v1" if "cgroup v1 limit" in "".join(L) else "?")
    tls = next(l for l in L if "tls-start" in l)
    tls = "yes" if " PASS" in tls else ("no: stops at start with the reason" if "stopped at start" in tls else "FAIL")
    verdict = lambda l: (re.match(r"CHECK \S+ (PASS|FAIL)\b", l) or [None, None])[1]
    main = [verdict(l) for l in L if verdict(l) and "as512" not in l]
    p = main.count("PASS"); fl = main.count("FAIL")
    a5 = [l for l in L if "as512" in l]
    a5s = "ran the load" if a5 and not any(verdict(l) == "FAIL" or "died" in l for l in a5) else ("aborted: " + next((l.split("died during the load: ")[1] for l in a5 if "died" in l), "load failed"))
    vsz = re.search(r"idle VmSize (\d+) kB", "".join(L))
    vsz = f"{int(vsz.group(1)) / 1024:.0f} MiB" if vsz else "?"
    pf = os.path.join(D, vm, "out", "pressure.txt")
    pr = "-"
    if os.path.isfile(pf):
        P = open(pf).read().splitlines()
        pr = f"{sum(l.startswith('CHECK PASS') for l in P)} / {sum(l.startswith('CHECK FAIL') for l in P)}"
    rows.append(f"| {vm} | {kern} | {distro} | {cg} | {tls} | {p} / {fl} | {a5s} | {vsz} | {pr} |")
print("\n".join(rows))
if "--check" in sys.argv:
    note = open(sys.argv[sys.argv.index("--check") + 1]).read()
    missing = [r for r in rows if r not in note]
    print(f"g03table --check: {len(rows)} rows, {len(missing)} not in the note")
    sys.exit(1 if missing else 0)
