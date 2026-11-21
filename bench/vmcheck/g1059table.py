#!/usr/bin/env python3
"""60.78 G10 + G59 tables from the raw files of bench/vmcheck/g10g59.sh (OUT = its out/ directory):
g10/portshare.jsonl, e3/e3five.jsonl, ka/kaburst.jsonl, kad/keepalive_dead.txt, t6.txt. usage: g1059table.py OUT [--check NOTE.md]"""
import json, os, sys
O = sys.argv[1]; rows = []
J = lambda p: [json.loads(l) for l in open(os.path.join(O, p))]
rows += ["G10: --port-share off / on, 8192 ports, 7168 target sockets toward one destination, 300 streams/s", "",
         "| round | server | streams of the ramp | failed | server CPU ms per 1000 streams | p50 ms (INFO) | p99 ms (INFO) | odd / even source ports at the end |", "|---|---|---|---|---|---|---|---|"]
for s in J("g10/portshare.jsonl"):
    for p in s["phases"]:
        rows.append(f"| {s['round']} | {'--port-share' if s['mode'] == 'on' else 'off'} | {p['from']}-{p['to']} | {p['fail']} | {p['cpu_ms_per_1000']} | {p['p50_ms']} | {p['p99_ms']} | {p['odd_at_end']} / {p['even_at_end']} |")
rows += ["", "G59 E3: a page of 70 streams (30 at once + 40, one per 200 ms) from a host that answers only the 5th SYN", "",
         "| run | server | answered | CLOSE 0x43 | refuse_dest_dead | seconds to the answer min / p50 / max |", "|---|---|---|---|---|---|"]
for s in J("e3/e3five.jsonl"):
    rows.append(f"| {s['run']} | {'--dest-failfast' if s['mode'] == 'on' else 'off'} | {s['results'].get('answer', 0)} | {s['results'].get('close_0x43', 0)} | {s['refuse_dest_dead']} | {' / '.join(map(str, s['answer_s']))} |")
rows += ["", "G59 keepalive: 10,000 idle connections opened at once, held 290 s, never read or written", "",
         "| arm | binary | TLS | opened | closed by the server | at s | why=dead_peer in the log | kTLS sockets at the end |", "|---|---|---|---|---|---|---|---|"]
for s in J("ka/kaburst.jsonl"):
    rows.append(f"| {s['name']} | {os.path.basename(s['bin'])} | {'wss' if s['tls'] else 'ws'} | {s['opened']} | {s['closed_by_server']} | {s['closed_at_s_min_max'] or '-'} | {s['server_log_dead_peer']} | {s['ktls_sockets_at_end'] if s['ktls_sockets_at_end'] is not None else '-'} |")
rows += ["", "keepalive_dead.py --tls (candidate): " + " | ".join(l.strip() for l in open(os.path.join(O, "kad/keepalive_dead.txt")) if l.strip())]
rows += ["", "G59 T6: " + " | ".join(l.strip()[len("CHECK "):] for l in open(os.path.join(O, "t6.txt")) if l.startswith("CHECK"))]
print("\n".join(rows))
if "--check" in sys.argv:
    note = open(sys.argv[sys.argv.index("--check") + 1]).read(); miss = [r for r in rows if r and r not in note]
    print(f"g1059table --check: {len(rows)} rows, {len(miss)} not in the note"); sys.exit(1 if miss else 0)
