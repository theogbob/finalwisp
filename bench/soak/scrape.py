#!/usr/bin/env python3
"""b6rc1 soak (60.33): scrape a finalwisp --metrics-listen page every N s into a jsonl (one record per scrape: t,
ok, the counter and gauge samples), then check every counter is monotonic. Stdlib only.
usage: scrape.py URL OUT.jsonl SECONDS [--until EPOCH]   |   scrape.py --check OUT.jsonl"""
import json, sys, time, urllib.request


def parse(text):
    kinds, vals = {}, {}
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(None, 3)
            kinds[name] = kind
        elif line and not line.startswith("#"):
            name, v = line.rsplit(" ", 1)
            vals[name] = float(v)
    return kinds, vals


def check(path):
    prev, kinds, n, bad, gaps, fails = {}, {}, 0, [], 0, 0
    for line in open(path):
        r = json.loads(line)
        n += 1
        if not r["ok"]:
            fails += 1
            continue
        kinds.update(r["kinds"])
        for k, v in r["vals"].items():
            fam = k.split("{")[0]
            if kinds.get(fam) == "counter" and k in prev and v < prev[k]:
                bad.append((r["t"], k, prev[k], v))
            prev[k] = v
    print(f"scrapes {n}, failed {fails}, counters {sum(1 for k in prev if kinds.get(k.split('{')[0]) == 'counter')}, "
          f"non-monotonic {len(bad)}")
    for b in bad[:20]:
        print("  BAD", b)
    return 0 if not bad else 1


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        sys.exit(check(sys.argv[2]))
    url, out, every = sys.argv[1], sys.argv[2], float(sys.argv[3])
    until = float(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[4] == "--until" else float("inf")
    with open(out, "a") as f:
        while time.time() < until:
            t0 = time.time()
            rec = {"t": round(t0, 1), "ok": False}
            try:
                body = urllib.request.urlopen(url, timeout=5).read().decode()
                kinds, vals = parse(body)
                rec.update(ok=True, kinds=kinds, vals=vals, bytes=len(body))
            except Exception as e:  # recorded, not fatal: a failed scrape is a finding
                rec["err"] = repr(e)
            f.write(json.dumps(rec) + "\n")
            f.flush()
            time.sleep(max(0.0, every - (time.time() - t0)))
