#!/usr/bin/env python3
"""60.78 G05 attribution: every EVERY s, the anonymous mappings of a soak server from /proc/PID/smaps, so a
step in anon memory can be named (which mapping grew: glibc arena, pool chunk, thread stack, [heap]).
usage: smapsmon.py RUNDIR OUT.jsonl [--server A,B] [--every 600] [--until EPOCH]
The PID is the newest server_start of each server in RUNDIR/events.jsonl (written by soak.py), so a restart is
followed. One JSON line per server per sample: t, server, pid, gen, threads, rollup {Rss, Anonymous, ...} KiB, and
maps = [[start, end, perms, name, size_kib, rss_kib, anon_kib], ...] for every mapping without a file (name "" or
[heap]/[stack]/[anon:...]), the ---p reserves included (size only). Reads /proc only; never signals the server."""
import json, os, sys, time

def arg(k, d):
    return sys.argv[sys.argv.index(k) + 1] if k in sys.argv else d

RUN, OUT = sys.argv[1], sys.argv[2]
SERVERS = arg("--server", "A,B").split(",")
EVERY = float(arg("--every", "600"))
UNTIL = float(arg("--until", "0")) or float("inf")

def newest():
    pids = {}
    try:
        for l in open(os.path.join(RUN, "events.jsonl")):
            e = json.loads(l)
            if e.get("kind") == "server_start" and e.get("server") in SERVERS:
                pids[e["server"]] = (e["pid"], e.get("gen"))
    except (OSError, ValueError):
        pass
    return pids

def snap(pid):
    maps, cur, roll = [], None, {}
    with open(f"/proc/{pid}/smaps") as f:
        for line in f:
            p = line.split()
            if p and "-" in p[0] and not p[0].endswith(":"):
                name = " ".join(p[5:]) if len(p) > 5 else ""
                a, b = p[0].split("-")
                cur = [a, b, p[1], name, 0, 0, 0] if (name == "" or name.startswith("[")) else None
                if cur is not None:
                    maps.append(cur)
            elif cur is not None and p and p[0] in ("Size:", "Rss:", "Anonymous:"):
                cur[{"Size:": 4, "Rss:": 5, "Anonymous:": 6}[p[0]]] = int(p[1])
    for line in open(f"/proc/{pid}/smaps_rollup"):
        k, _, v = line.partition(":")
        if v.strip().endswith("kB"):
            roll[k] = int(v.split()[0])
    return maps, roll, len(os.listdir(f"/proc/{pid}/task"))

with open(OUT, "a") as out:
    while time.time() < UNTIL:
        t = time.time()
        for s, (pid, gen) in sorted(newest().items()):
            try:
                maps, roll, thr = snap(pid)
            except (OSError, ValueError) as e:
                out.write(json.dumps({"t": round(t, 1), "server": s, "pid": pid, "gen": gen, "error": str(e)}) + "\n")
                continue
            out.write(json.dumps({"t": round(t, 1), "server": s, "pid": pid, "gen": gen, "threads": thr, "rollup": roll, "maps": maps}) + "\n")
        out.flush()
        time.sleep(max(1.0, EVERY - (time.time() - t)))
