#!/usr/bin/env python3
"""60.78 T2 (sb-unread) tables from raw files (not in the repository).
usage: bench/sb-unread-tables.py [--m1 FILE] [--big DIR] [--check NOTE]
--m1 FILE: the output of bench/sb-unread/m1.py: lines 'S t shape cli_r cli_w cli_notsent tgt_r tgt_w nsock'
  (sums over one finalwisp's sockets, from ss -tmi) every 10 s. Table T-M1: per shape the median of the samples
  from 30 s on.
--big DIR: the wnd2.py files of 60.73 T-wnd-big (DIR/rcvB-rateR-fastF.txt; lines 'T taken=N acked=N step=N wnd=N
  rcvbuf=N' at each change of the server socket's tcpi_bytes_acked). Events less than 1 s apart are one take; a
  cycle = a take and the gap after it. Table T-M2: per run the first take (the fill), the first gap, its drain
  (gap x rate) against the fill; then over the later cycles the largest drain against the bytes of the take before
  the gap (P1) and against the larger of the two takes before it (max(P1, P2)).
--m3 FILE: the output of bench/sb-unread/m3.py (also 'C t shape taken client_rcvq'). Table T-ABUSE: per abuse shape the
  client's own download, our bytes held, and the hold time by today's rule and the credit rule (constants R, L_LO, L_HI,
  FILL_DIV below: a model of the rule, the bytes measured).
--vm DIR: the two-VM pressure run of --unread-close (bench/sb-unread/vps_unread.py): T-VM per client, and the host.
--browser DIR: Chromium + Scramjet (epoxy, epoxy-v2) against finalwisp --unread-close, local mirror (T-BROWSER).
--brw4 DIR: FINAL-4, Chromium under TCP memory pressure with --preset public, with and without --unread-relief (T-BRW4).
--g71 DIR: G71, the same-tab busy case: where the page load waits (T-G71).
--check NOTE: every table line printed here must be a line of NOTE (exit 1 and the missing lines otherwise)."""
import glob, os, re, statistics, sys

def arg(k):
    return sys.argv[sys.argv.index(k) + 1] if k in sys.argv else None

def m1_rows(fn):
    by = {}
    for line in open(fn):
        f = line.split()
        if f and f[0] == "S" and int(f[1]) >= 30:
            by.setdefault(f[2], []).append([int(x) for x in f[3:]])
    rows = ["| shape | samples | client socket: send queue (wmem_queued), bytes | of it not sent | target sockets: receive queues, bytes | sum, bytes |",
            "|---|---|---|---|---|---|"]
    for sh, v in by.items():
        med = lambda i: int(statistics.median(x[i] for x in v))
        rows.append(f"| {sh} | {len(v)} | {med(1)} | {med(2)} | {med(3)} | {med(1) + med(3)} |")
    return rows

def takes(fn):
    ev = [(float(t), int(a)) for t, a in re.findall(r"^\s*([\d.]+) taken=\d+ acked=(\d+)", open(fn).read(), re.M)]
    out = []  # (start, end, acked at end)
    for t, a in ev:
        if out and t - out[-1][1] < 1.0: out[-1] = (out[-1][0], t, a)
        else: out.append((t, t, a))
    return out

def big_rows(d):
    rows = ["| SO_RCVBUF set | s at full speed first | bytes read per s | fill, bytes | first gap, s | first drain / fill | later gaps | largest later drain / P1 | largest later drain / max(P1, P2) |",
            "|---|---|---|---|---|---|---|---|---|"]
    for fn in sorted(glob.glob(os.path.join(d, "rcv*-rate*-fast*.txt"))):
        rcv, rate, fast = (int(x) for x in re.match(r"rcv(\d+)-rate(\d+)-fast(\d+)\.txt$", os.path.basename(fn)).groups())
        tk = takes(fn)
        # the fill: every take that ends before the first gap of 5 s or more
        i = next(k for k in range(len(tk) - 1) if tk[k + 1][0] - tk[k][1] >= 5.0)
        fill = tk[i][2]
        gap0 = tk[i + 1][0] - tk[i][1]
        p = [fill] + [tk[k][2] - tk[k - 1][2] for k in range(i + 1, len(tk))]
        r1, r2 = [], []
        for k in range(i + 1, len(tk) - 1):
            drain = (tk[k + 1][0] - tk[k][1]) * rate
            p1, p2 = p[k - i], p[k - i - 1]
            r1.append(drain / p1); r2.append(drain / max(p1, p2))
        rows.append(f"| {'autotuned' if rcv == 0 else rcv} | {fast} | {rate} | {fill} | {gap0:.1f} | {gap0 * rate / fill:.3f} | "
                    f"{len(r1)} | {max(r1):.2f} | {max(r2):.2f} |" if r1 else
                    f"| {'autotuned' if rcv == 0 else rcv} | {fast} | {rate} | {fill} | {gap0:.1f} | {gap0 * rate / fill:.3f} | 0 | | |")
    return rows

# T-ABUSE: hold time per abuse strategy, today's rule and the credit rule; model constants (labelled: a model, not a run)
R, L_LO, L_HI, FILL_DIV = 512, 600, 3600, 8
# byte-second form: one connection may hold M0 = one full stream (tcp_rmem max, Linux default 6 MiB, + notsent-lowat
# 128 KiB) for its whole credit; holding M > M0 shortens the hold by M0 / M
M0 = (6 << 20) + (128 << 10)

def m3_held(fn):
    """per shape from bench/sb-unread/m3.py: (our bytes: client send queue + target receive queues, the client's own
    download: bytes it read + its receive queue), medians of the samples from 30 s on"""
    s, c = {}, {}
    for line in open(fn):
        f = line.split()
        if not f or f[0] not in "SC" or len(f) < 4 or not f[1].isdigit() or int(f[1]) < 30: continue
        if f[0] == "S": s.setdefault(f[2], []).append(int(f[4]) + int(f[6]))
        else: c.setdefault(f[2], []).append(int(f[3]) + int(f[4]))
    return {k: (int(statistics.median(s[k])), int(statistics.median(c.get(k, [0])))) for k in s}

def trickle_hold(gap, take):
    """the credit rule against a client that takes `take` bytes after every `gap` s of stall: s until the reset"""
    credit, t = L_LO, 0
    while credit > gap:
        credit, t = min(credit - gap + take / R, L_HI), t + gap
        if t > 10 * 86400: return "unbounded"
    return round(t + credit)

def abuse_rows(fn):
    h = m3_held(fn)
    rows = ["| strategy (one connection) | the client's download, bytes | our bytes held (loopback) | hold today, s | hold, credit rule, s | hold, byte-second form, s | ours held at K = 100, MB | at K = 1000, MB |",
            "|---|---|---|---|---|---|---|---|"]
    def credit(paid_fill):
        return min(L_LO + paid_fill // (FILL_DIV * R), L_HI)
    for k in ("noread_s1", "noread_s16", "noread_s64", "fill1m", "fill8m", "fill16m", "fill64m"):
        if k not in h: continue
        ours, cost = h[k]
        hold = credit(cost)
        rows.append(f"| {k} | {cost} | {ours} | {L_LO} | {hold} | {round(hold * min(1, M0 / ours))} | {ours * 100 / 1e6:.0f} | {ours * 1000 / 1e6:.0f} |")
    if "trickle_rcv4k" in h:
        ours, _ = h["trickle_rcv4k"]
        rows.append(f"| trickle: one take of 4 KiB per 599 s (rcvbuf 4 KiB) | 24.6 KB per hour | {ours} | unbounded | "
                    f"{trickle_hold(599, 4096)} | {trickle_hold(599, 4096)} | {ours * 100 / 1e6:.0f} | {ours * 1000 / 1e6:.0f} |")
        rows.append(f"| re-buy: stall, then take {L_HI * R} bytes fast, repeat | {L_HI * R} per {L_HI} s ({R} B/s) | {ours} | unbounded | "
                    f"unbounded (the price of an honest {R} B/s reader) | unbounded | {ours * 100 / 1e6:.0f} | {ours * 1000 / 1e6:.0f} |")
    return rows

def vm_rows(d):
    """the two-VM pressure run (bench/sb-unread/vps_unread.py serve / clients): DIR/clients.txt, DIR/srv.log, DIR/host.txt.
    A reset of a client that reads shows in its own 'R' line; one of a client that never reads is matched to the
    server's conn_close line with why=unread by its stream count (16: A2, 64: A5) or, with one stream, by the bytes
    the server sent (below 20000: A3, whose buffer is 8 KiB; 16 MiB or more: A4; else A1). Its time = the connection's
    lifetime (dur_ms; the clients start within 3 s)."""
    cl = open(os.path.join(d, "clients.txt")).read().splitlines()
    names, rcv, taken, flat, first, ends = [], {}, {}, {}, {}, {}
    last_change = {}
    for l in cl:
        f = l.split()
        if f[0] == "S":
            names.append(f[2]); rcv[f[2]] = f[3].split("=")[1]
        elif f[0] == "T":
            t, n, v = int(f[1]), f[2], int(f[3])
            if v != taken.get(n, 0):
                if n in last_change: flat[n] = max(flat.get(n, 0), t - last_change[n])
                first.setdefault(n, t); last_change[n] = t
            taken[n] = v
        elif f[0] in "RE":
            ends[f[2]] = (f[0], int(f[1]))
    srv = open(os.path.join(d, "srv.log")).read()
    closes = [dict(kv.split("=", 1) for kv in l.split()[1:] if "=" in kv) for l in srv.splitlines() if "ev=conn_close" in l and "why=unread" in l]
    reset = {}
    for c in closes:
        s, tx, t = int(c["streams"]), int(c["tx"]), int(c["dur_ms"]) // 1000
        n = {16: "A2_noread_s16", 64: "A5_noread_s64"}.get(s) or ("A3_trickle" if tx < 20000 else "A4_fill16m" if tx >= 16 << 20 else "A1_noread")
        reset[n] = t
    for n, (k, t) in ends.items():
        if k == "R" and n not in reset: reset[n] = f"{t} (seen by the client)"
    rows = ["| client | SO_RCVBUF (kernel) | bytes taken | longest time without a take after its first, s (10-s steps) | reset by --unread-close at, s |",
            "|---|---|---|---|---|"]
    for n in names:
        rows.append(f"| {n} | {rcv[n]} | {taken.get(n, 0)} | {flat.get(n, '')} | {reset.get(n, 'kept')} |")
    hl = [l.split() for l in open(os.path.join(d, "host.txt")) if l.startswith("H ")]
    on = [int(f[2]) for f in hl if int(f[1]) >= 100]
    mx = int(hl[-1][3]) if hl else 0
    mark = sum(p >= mx * 12 // 16 for p in on)
    cu = re.findall(r"close_unread=(\d+)", srv)
    rows += ["", "| host samples from 100 s | at or above the 3/4 mark | host TCP pages min / max | tcp_mem max | close_unread at the end |",
             "|---|---|---|---|---|",
             f"| {len(on)} | {mark} | {min(on) if on else ''} / {max(on) if on else ''} | {mx} | {cu[-1] if cu else ''} |"]
    if os.path.exists(os.path.join(d, "ss.txt")):
        rows += [""] + ss_rows(d, {n: taken.get(n, 0) for n in names if n not in reset})
    return rows

def ss_rows(d, names_taken):
    """DIR/ss.txt (bench/sb-unread/ss_sample.py on the client VM, started later than the clients): per socket the TCP
    take (bytes_received) every 10 s. A socket is named by matching its application take (bytes_received - recv_q)
    at its last sample with the clients' last 'T' values (the closest; the readers' rates differ)."""
    by = {}
    for l in open(os.path.join(d, "ss.txt")):
        f = l.split()
        by.setdefault(f[2], []).append((int(f[1]), int(f[3]), int(f[4])))
    rows = ["| client | sampled, s | longest time with no TCP byte taken, s (10-s steps; >=: until the end) | bytes in its receive queue at the end |",
            "|---|---|---|---|"]
    pf = os.path.join(d, "ports.txt")  # optional: 'port name' lines (the rules of the naming in its comments)
    ports = dict(l.split() for l in open(pf) if l.strip() and not l.startswith("#")) if os.path.exists(pf) else {}
    for port, v in sorted(by.items(), key=lambda kv: ports.get(kv[0], kv[0])):
        app = v[-1][1] - v[-1][2]
        name = ports.get(port) or min(names_taken, key=lambda n: abs(names_taken[n] - app))
        longest, start = 0, v[0][0]
        for (t0, b0, _), (t1, b1, _) in zip(v, v[1:]):
            if b1 != b0:
                longest = max(longest, t1 - start); start = t1
        tail = v[-1][0] - start
        rows.append(f"| {name} | {v[-1][0] - v[0][0]} | {max(longest, tail) if longest >= tail else '>= ' + str(tail)} | {v[-1][2]} |")
    return rows

def browser_rows(d):
    """DIR/zwnd.txt (zwnd_sample.py on the server's Wisp port during bench/browser/browser.py --mode timing) and
    DIR/results.json: the cases that passed, and how often a client connection showed a zero receive window."""
    import json
    z = [l.split() for l in open(os.path.join(d, "zwnd.txt")) if l.startswith("Z ")]
    res = json.load(open(os.path.join(d, "results.json")))
    rs = res.get("results", [])
    ok = sum(1 for r in rs if r.get("ok"))
    return ["| browser cases passed | samples (0.5 s) | samples with a client connection | zero-window socket samples |",
            "|---|---|---|---|",
            f"| {ok} of {len(rs)} | {len(z)} | {sum(1 for f in z if int(f[2]) > 0)} | {sum(int(f[3]) for f in z)} |"]
def onab_rows(d, box):
    """DIR/out/<cell>.jsonl of bench/sb-unread/onab.py (arms pre, uc = pre + --unread-close, pre2 = a copy of pre;
    `wst ab` raw records): per cell the paired verdict of wispsuite.stats.compare on mib_s_down, rounds paired by rep;
    also DIR/out/<cell>.jsonl of a follow-up with arms uc, uc2 (any arms: every pair below that exists is shown)."""
    import json
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
    from wispsuite import stats
    rows = []
    for fn in sorted(os.listdir(os.path.join(d, "out"))):
        if not fn.endswith(".jsonl"): continue
        recs = [json.loads(l) for l in open(os.path.join(d, "out", fn))]
        by = {}
        for x in recs: by.setdefault(x["v"], {})[x["rep"]] = x
        errs = sum(x.get("errors", 0) for x in recs); press = sum(x.get("tcp_press") or 0 for x in recs)
        for a, b in [("pre", "uc"), ("pre", "pre2"), ("pre2", "uc"), ("pre2", "uc2"), ("uc", "uc2")]:
            if a not in by or b not in by: continue
            reps = sorted(set(by[a]) & set(by[b]))
            c = stats.compare([by[a][i]["mib_s_down"] for i in reps], [by[b][i]["mib_s_down"] for i in reps])
            rows.append(f"| {box} | {fn[:-6]} | {b} / {a} | {len(reps)} | {c['base']:.0f} | {c['new']:.0f} | {c['ratio']:.3f} | "
                        f"[{c['ci90'][0]:.3f}, {c['ci90'][1]:.3f}] | {c['p']:.3f} | {c['verdict']} | {errs} | {press} |")
    return rows


def arms_of(d):
    """[(client set name, server log)]: DIR/arms.txt ('NAME PORT' per line; port 18850 = srv.log, others srv-PORT.log),
    else the r6 layout (new = srv.log, pre = srv-18860.log, bare = srv-18870.log)"""
    p = os.path.join(d, "arms.txt")
    if not os.path.exists(p):
        return [("new", "srv.log"), ("pre", "srv-18860.log"), ("bare", "srv-18870.log")]
    return [(n, "srv.log" if p_ == "18850" else f"srv-{p_}.log") for n, p_ in (l.split() for l in open(p) if l.strip())]


def tgt_rows(d):
    """DIR/srv/tgt.txt (tgt_sample.py: the server VM's target sockets toward the source, every 30 s) with the server pids
    of DIR/srv/run.txt and DIR/arms.txt: per server, the target sockets seen, how many dropped segments (skmem d,
    the last value per socket), and the receive buffer (rb) and memory held (r) at the median / max sample."""
    import re
    port_of = {}
    for l in open(os.path.join(d, "srv", "run.txt")):
        m = re.search(r"server pid (\d+): .* --port (\d+)", l)
        if m: port_of[m.group(1)] = m.group(2)
    name_of = {p: n for n, p in (l.split() for l in open(os.path.join(d, "arms.txt")) if l.strip())}
    last, rbs, rs = {}, {}, {}
    for l in open(os.path.join(d, "srv", "tgt.txt")):
        f = l.split()
        if f[0] != "G" or f[2] not in port_of: continue
        n = name_of[port_of[f[2]]]
        last[(n, f[3])] = int(f[6]); rbs.setdefault(n, []).append(int(f[5])); rs.setdefault(n, []).append(int(f[4]))
    rows = ["| server | target sockets seen | sockets that dropped segments | dropped segments (sum) | rb median / max KiB | r (held) median / max KiB |",
            "|---|---|---|---|---|---|"]
    for n, _ in arms_of(d):
        dr = [v for (a, _), v in last.items() if a == n]
        rb, r = sorted(rbs.get(n, [0])), sorted(rs.get(n, [0]))
        rows.append(f"| {n} | {len(dr)} | {sum(1 for v in dr if v)} | {sum(dr)} | {rb[len(rb) // 2] >> 10} / {rb[-1] >> 10} | "
                    f"{r[len(r) // 2] >> 10} / {r[-1] >> 10} |")
    return rows


def timeout_rows(d, share_kib=370):
    """each source connection that ended with TimeoutError, joined to the server's target socket by port (the source's
    peer port = the target socket's local port in DIR/srv/tgt.txt; the server from its pid, DIR/srv/run.txt): bytes held
    (skmem r) and its receive buffer (rb) at the sample about 900 s (tcp_retries2 = 15) before the timeout and at the
    last sample before it, the drops (skmem d) between them, and the samples in that window above share_kib (the kernel's
    per-socket share under pressure, tcp_mem max / sockets allocated: r7 = 89040 pages / ~961 sockets = ~370 KiB, the
    socket count estimated as 2 x holder pairs + 3 x 93 targets + 45 clients + 3 listeners)."""
    import datetime, re
    def utc(s): return datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp()
    port_of = {}
    for l in open(os.path.join(d, "srv", "run.txt")):
        m = re.search(r"server pid (\d+): .* --port (\d+)", l)
        if m: port_of[m.group(1)] = m.group(2)
    name_of = {p: n for n, p in (l.split() for l in open(os.path.join(d, "arms.txt")) if l.strip())}
    t_srv = utc(open(os.path.join(d, "srv", "run.txt")).readline()[:19])
    t_src = None
    for l in open(os.path.join(d, "starts.txt")):
        m = re.match(r"fwsb-src-\S+ \w+ (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC", l)
        if m: t_src = utc(m.group(1).replace(" ", "T"))
    ser = {}
    for l in open(os.path.join(d, "srv", "tgt.txt")):
        f = l.split()
        if f[0] == "G": ser.setdefault(f[3], []).append((int(f[1]), f[2], int(f[4]), int(f[5]), int(f[6])))
    rows = ["| source timeout at (s, server clock) | server | held / buffer KiB ~900 s before | held / buffer KiB last before | drops between | samples above the share / all |",
            "|---|---|---|---|---|---|"]
    for l in open(os.path.join(d, "cli", "src.txt")):
        f = l.split()
        if f[0] != "X" or "TimeoutError" not in l: continue
        t = float(f[1]) + t_src - t_srv
        s = [x for x in ser.get(f[2], []) if x[0] <= t]
        if not s:
            rows.append(f"| {t:.0f} | (port {f[2]} not sampled) | | | | |"); continue
        w = [x for x in s if x[0] >= t - 900] or s[-1:]
        a, b = w[0], w[-1]
        rows.append(f"| {t:.0f} | {name_of.get(port_of.get(b[1]), '?')} | {a[2] >> 10} / {a[3] >> 10} | {b[2] >> 10} / {b[3] >> 10} | "
                    f"{b[4] - a[4]} | {sum(1 for x in w if x[2] > share_kib << 10)} / {len(w)} |")
    return rows



def relief_rows(d):
    """per server of DIR/arms.txt, from its log (DIR/srv/srv*.log): the last metrics line's --unread-relief counters
    (relief_bytes, relief_streams, relief_capped; '-' for a binary without them), close_unread, the memory level
    changes and cap_apply, and used_mib (the server's own memory count) at its median and max over the metrics lines"""
    rows = ["| server | relief_bytes (MiB) | relief_streams | relief_capped | close_unread | level_changes | cap_apply | used_mib median / max |",
            "|---|---|---|---|---|---|---|---|"]
    for n, log in arms_of(d):
        ms = [dict(x.split("=", 1) for x in l.split()[1:] if "=" in x) for l in open(os.path.join(d, "srv", log)) if "ev=metrics " in l]
        if not ms:
            rows.append(f"| {n} | (no metrics line) | | | | | | |"); continue
        m, u = ms[-1], sorted(int(x.get("used_mib", 0)) for x in ms)
        rb = f"{int(m['relief_bytes']) / 1048576:.1f}" if "relief_bytes" in m else "-"
        rows.append(f"| {n} | {rb} | {m.get('relief_streams', '-')} | {m.get('relief_capped', '-')} | {m.get('close_unread', 0)} | "
                    f"{m.get('level_changes', 0)} | {m.get('cap_apply', 0)} | {u[len(u) // 2]} / {u[-1]} |")
    return rows


def closed_rows(d):
    """per target stream that closed with why=target_close (DIR/srv/srv*.log): its connection (cid), that connection's
    bytes sent (conn_close tx), and the client whose socket received that many bytes (DIR/cli/NAME/ss.txt 'P t port
    received queued': the largest 'received' of the port, within 64 bytes of tx; the port's client from the 'S' lines
    of clients.txt), with how that client ended. A kept client whose stream closed reads on from its own buffer, so
    'ran short' (T-CAUSE) misses it when its buffer is large; this join does not."""
    import re
    rows = ["| server | closed at (UTC) | cid | conn tx bytes | client (bytes received = tx) | client's end | its unread bytes then |",
            "|---|---|---|---|---|---|---|"]
    for n, log in arms_of(d):
        lines = open(os.path.join(d, "srv", log)).read().splitlines()
        tx = {}
        for l in lines:
            if "ev=conn_close" in l:
                f = dict(x.split("=", 1) for x in l.split()[1:] if "=" in x)
                tx[f["cid"]] = int(f["tx"])
        name, end = {}, {}
        for l in open(os.path.join(d, "cli", n, "clients.txt")):
            f = l.split()
            if f[0] == "S": name[re.search(r"port=(\d+)", l).group(1)] = f[2]
            elif f[0] == "E": end[f[2]] = "kept"
            elif f[0] == "R": end[f[2]] = f"reset at {f[1]} s"
        best = {}
        for l in open(os.path.join(d, "cli", n, "ss.txt")):
            f = l.split()
            if f[0] == "P" and int(f[3]) > best.get(f[2], (0, 0))[0]: best[f[2]] = (int(f[3]), int(f[4]))
        for l in lines:
            if "ev=stream_close" in l and "why=target_close" in l:
                f = dict(x.split("=", 1) for x in l.split()[1:] if "=" in x)
                t = tx.get(f["cid"])
                who = [(p, q) for p, (r, q) in best.items() if t is not None and abs(r - t) <= 64]
                c = name.get(who[0][0], "?") if len(who) == 1 else ("none" if not who else "ambiguous")
                rows.append(f"| {n} | {f['ts'][11:19]} | {f['cid']} | {t} | {c} | {end.get(c, '-')} | {who[0][1] if len(who) == 1 else '-'} |")
    return rows

def cause_rows(d):
    """a two-VM rerun with three servers side by side (vps_unread.py serve with MORE_JSON): DIR/srv/srv.log (the new
    binary, --unread-close), srv-18860.log (v1.3.3 --preset public), srv-18870.log (v1.3.3 bare), DIR/srv/netstat.txt;
    DIR/cli/{new,pre,bare}/clients.txt, DIR/cli/src.txt (the source's ends), DIR/cli/clihost.txt, DIR/starts.txt
    (the units' start times: client and source times are seconds from their unit's start).
    Rows 1: per client, how it ended, the bytes it took and the last 10-s sample in which it took a byte ('ran short'
    = an honest reader that took nothing in its last 300 s of reading). Rows 2: per target stream that closed during
    the run (why=target_close), the client whose bytes taken equal the stream's down bytes within 0.2% (the stream
    ran dry, so the client got exactly what was sent), else none. Rows 3: the counts, the source's ends by kind and
    the host counters (the server VM's TcpExt deltas; the client VM's TCP memory peak and pressure entries)."""
    import datetime, re
    def utc(s): return datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp() + float("0" + s[19:23])
    st = {}
    for l in open(os.path.join(d, "starts.txt")):
        m = re.match(r"(fwsb-\S+) \w+ (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC", l)
        if m: st[m.group(1)] = utc(m.group(2).replace(" ", "T"))
    t_src = [v for k, v in st.items() if k.startswith("fwsb-src")][0]
    src = [l.split(" ", 3) for l in open(os.path.join(d, "cli", "src.txt")) if l.startswith("X ")]
    dur = max(float(l.split()[1]) for l in open(os.path.join(d, "cli", arms_of(d)[0][0], "clients.txt")) if l.startswith("E "))
    r1, r2, r3 = [], [], []
    for sn, log in arms_of(d):
        t_cli = [v for k, v in st.items() if k.endswith("-" + sn) and "-cli-" in k][0]
        ser, end = {}, {}
        for l in open(os.path.join(d, "cli", sn, "clients.txt")):
            f = l.split()
            if f[0] == "T": ser.setdefault(f[2], []).append((float(f[1]), int(f[3])))
            elif f[0] == "E": end[f[2]] = ("kept", int(f[4]))
            elif f[0] == "R": end[f[2]] = (f"reset at {f[1]} s", int(l.rsplit("taken=", 1)[1]))
        def key(n): return (n[0], int(re.match(r"[A-Z](\d+)", n).group(1)))
        short = 0
        for n in sorted(end, key=key):
            s = ser.get(n, [])
            gr = [t for (t, g), (_, g0) in zip(s[1:], s[:-1]) if g > g0]
            last = max(gr) if gr else 0
            ran_short = n.startswith("H") and end[n][0] == "kept" and last < dur - 300
            short += ran_short
            r1.append(f"| {sn} | {n} | {end[n][0]} | {end[n][1]} | {last:.0f} | {'yes' if ran_short else 'no'} |")
        streams = [dict(x.split("=", 1) for x in l.split()[1:] if "=" in x) for l in open(os.path.join(d, "srv", log))
                   if "ev=stream_close" in l and "why=target_close" in l]
        for s in streams:
            down = int(s["down"])
            who = [n for n in end if end[n][0] == "kept" and abs(end[n][1] - down) <= 0.002 * down]
            r2.append(f"| {sn} | {utc(s['ts']) - t_cli:.0f} | {s['reason']} | {down} | {', '.join(who) or 'none (no client ran short on it)'} |")
        r3.append(f"| {sn} | {sum(1 for n in end if end[n][0] != 'kept')} of {len(end)} | {len(streams)} | {short} |")
    kinds = {}
    for f in src: kinds.setdefault(f[3].split(":")[0], []).append(float(f[1]))
    to = sorted(kinds.get("TimeoutError", []))
    ns = [l.split() for l in open(os.path.join(d, "srv", "netstat.txt"))][-1]
    nk = dict(x.split("=") for x in ns[2:])
    ch = [l.split() for l in open(os.path.join(d, "cli", "clihost.txt"))]
    chp = max(int(f[2]) for f in ch if f[0] == "H"); chmax = [int(f[3]) for f in ch if f[0] == "H"][0]
    chn = dict(x.split("=") for x in [f for f in ch if f[0] == "N"][-1][2:])
    rows = ["| server | client | client's end | bytes taken | last sample with a byte taken (s) | ran short |", "|---|---|---|---|---|---|"] + r1
    rows += ["", "| server | target stream closed at (s) | reason | down bytes | client whose bytes taken = down (within 0.2%) |", "|---|---|---|---|---|"] + r2
    rows += ["", "| server | clients reset | target streams closed (0x03 target_close) | honest readers that ran short |", "|---|---|---|---|"] + r3
    rows += ["", "| source ends: TimeoutError (ETIMEDOUT) | first .. last (s) | ConnectionResetError | server VM TCPRcvQDrop | TCPZeroWindowDrop | TCPMemoryPressures | client VM TCP pages peak / max | client VM TCPMemoryPressures |",
             "|---|---|---|---|---|---|---|---|",
             f"| {len(to)} | {to[0]:.0f} .. {to[-1]:.0f} | {len(kinds.get('ConnectionResetError', []))} | {nk.get('TCPRcvQDrop', 0)} | {nk.get('TCPZeroWindowDrop', 0)} | "
             f"{nk.get('TCPMemoryPressures', 0)} | {chp} / {chmax} | {chn.get('TCPMemoryPressures', 0)} |"]
    return rows


def brw4_rows(d):
    """FINAL-4: Chromium + Scramjet (epoxy) in a netns behind netem (8 Mbit/s, 20 ms) against finalwisp --preset public
    in one VM with tcp_mem lowered and held at 13/16 (vps_unread.py serve); a 64 MiB download (scenario.mjs case
    download, every byte hashed in the page, SHA-256 against cfg-dl.json) and, during it, 6 page loads from a second
    Chromium. DIR/<arm>/: dl*.out, pg*.out, srv.log (metrics every 10 s), tgt.txt (tgt_sample.py on the mirror port)."""
    import datetime, json
    def utc(s): return datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp()
    exp = json.load(open(os.path.join(d, "cfg-dl.json")))["cases"][0]["expect_sha256"]
    rows = ["| arm | download ok | bytes | SHA-256 = expected | s | page loads ok | relief_streams (at its end) | relief_bytes (at its end) | download's target socket: rcvbuf first / last | max rmem | streams closed 0x03 (whole run) |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]
    for arm in sorted(os.listdir(d)):
        p = os.path.join(d, arm)
        if not os.path.isdir(p): continue
        res = lambda pat: [json.loads(l[7:]) for f in glob.glob(os.path.join(p, pat)) for l in open(f) if l.startswith("RESULT ")]
        dl, pg = res("dl*.out")[0], res("pg*.out")
        ms = [dict(x.split("=", 1) for x in l.split() if "=" in x) for l in open(os.path.join(p, "srv.log")) if "ev=metrics" in l]
        # (the relief counters at the end of the download: later streams, such as the 1 MiB hash checks, are not its)
        t0 = utc(open(os.path.join(p, "run.txt")).readline().split()[0])
        sc = [dict(x.split("=", 1) for x in l.split() if "=" in x) for l in open(os.path.join(p, "srv.log")) if "ev=stream_close" in l]
        dls = max(sc, key=lambda s: int(s["down"]))
        ms = [m for m in ms if int(m["up"]) <= utc(dls["ts"]) - t0]
        g = [l.split() for l in open(os.path.join(p, "tgt.txt")) if l.startswith("G ")]
        big = max({f[3] for f in g}, key=lambda k: max(int(f[8]) for f in g if f[3] == k))
        gb = [f for f in g if f[3] == big]
        closes = [l for l in open(os.path.join(p, "srv.log")) if "ev=stream_close" in l and "why=target_close" in l and "reason=0x03" in l]
        ok_hash = "yes" if dl["ok"] and dl.get("sha256", exp) == exp else "no"
        rows.append(f"| {arm} | {dl['ok']} | {dl['bytes']} | {ok_hash} | {dl['secs']:.0f} | {sum(1 for r in pg if r['ok'])} of {len(pg)} | "
                    f"{ms[-1].get('relief_streams', '0')} | {ms[-1].get('relief_bytes', '0')} | {gb[0][5]} / {gb[-1][5]} | {max(int(f[4]) for f in gb)} | {len(closes)} |")
    return rows


def g71_rows(d):
    """G71: Chromium + Scramjet (epoxy) in a netns behind netem 8 Mbit/s against one Wisp server, case busy (scenario.mjs
    copy in DIR, req_log): origin page, frame 2, a background download (64 MiB or 1 MiB), 5 small fetches, a wait
    (page_wait), then a page load in the same tab, all on one Wisp connection. The mirror closes an idle keep-alive
    connection after MIRROR_KA_MS. DIR/arms.txt: 'tag server keepalive_s wait_s bulk pressure'; DIR/<tag>/brw.out
    (RESULT, 'REQ t event url' from the page-load start, 'BG t bytes'), samp.txt (g71samp.py: ss of the Wisp
    connection from both ends every 1 s), srv.log."""
    import json
    rows = ["| arm | server | origin keep-alive (s) | wait before page load (s) | bulk | TCP memory held | page-load requests done | page load: first request to last done (s) | case result | largest client send in 1 s after the first 20 s (bytes) |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for l in open(os.path.join(d, "arms.txt")):
        tag, srv, ka, wait, bulk, pr = l.split()
        p = os.path.join(d, tag)
        lines = open(os.path.join(p, "brw.out")).read().splitlines()
        req = [x.split() for x in lines if x.startswith("REQ ")]
        page = [r for r in req if "__gen" not in r[3]]
        done = [float(r[1]) for r in page if r[2] == "done"]
        t0 = min(float(r[1]) for r in page if r[2] == "start") if page else None
        span = f"{max(done) - t0:.2f}" if done else "none done"
        res = [json.loads(x[7:]) for x in lines if x.startswith("RESULT ")]
        if res:
            r = res[0]
            why = "ok" if r["ok"] else r["error"].split("\n")[0][:70]
        else:
            why = "stopped (page loaded; bulk still running)"
        # the client's sends after setup (the first 20 s of samples: page loads, frame 2, the small fetches): the
        # largest step of bytes_sent between two samples (a request is hundreds of bytes; a WebSocket pong is 6)
        c = [x.split() for x in open(os.path.join(p, "samp.txt")) if x.startswith("C ") and "bytes_sent:" in x]
        bs = [(float(x[1]), int([f for f in x if f.startswith("bytes_sent:")][0].split(":")[1])) for x in c]
        late = [b for t, b in bs if t >= 20]
        last = str(max((b - a for a, b in zip(late, late[1:])), default=0)) if len(late) > 1 else "-"
        rows.append(f"| {tag} | {srv} | {ka} | {wait} | {bulk} | {pr} | {len(done)} | {span} | {why} | {last} |")
    return rows


def g71_srv_rows(d, tags=("A-fw", "I-ka120-busy-fw", "J-ka120-busy-fw-noprio", "L-ka120-busy-fw-press")):
    """G71: the server's side of the Wisp connection (g71samp.py S lines) while the bulk ran (Send-Q > 0): the
    medians of Send-Q, notsent (the part not yet handed to the network) and the smoothed RTT."""
    rows = ["| arm | samples with Send-Q > 0 | median Send-Q (bytes) | median notsent (bytes) | median RTT (ms) | median cwnd |", "|---|---|---|---|---|---|"]
    for tag in tags:
        s = [x.split() for x in open(os.path.join(d, tag, "samp.txt")) if x.startswith("S ") and "rtt:" in x]
        f = lambda x, k: next((v.split(":", 1)[1] for v in x if v.startswith(k + ":")), "0")
        s = [x for x in s if int(x[3]) > 0]
        med = lambda v: statistics.median(v) if v else 0
        rows.append(f"| {tag} | {len(s)} | {med([int(x[3]) for x in s]):.0f} | {med([int(f(x, 'notsent')) for x in s]):.0f} | "
                    f"{med([float(f(x, 'rtt').split('/')[0]) for x in s]):.0f} | {med([int(f(x, 'cwnd')) for x in s]):.0f} |")
    return rows


out = []
if arg("--m1"): out += ["T-M1"] + m1_rows(arg("--m1")) + [""]
if arg("--m3"): out += ["T-ABUSE"] + abuse_rows(arg("--m3")) + [""]
if arg("--vm"): out += ["T-VM"] + vm_rows(arg("--vm")) + [""]
if arg("--browser"): out += ["T-BROWSER"] + browser_rows(arg("--browser")) + [""]
for spec in [a for a in sys.argv if a.startswith("--onab=")]:
    box, d = spec[len("--onab="):].split(":", 1)
    out += [f"T-ONAB {box}", "| box | cell | arm / base | rounds | base MiB/s | arm MiB/s | ratio | ci90 | p | verdict | stream errors | pressure events |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|"] + onab_rows(d, box) + [""]
if arg("--cause"):
    out += ["T-CAUSE"] + cause_rows(arg("--cause")) + [""]
    if os.path.exists(os.path.join(arg("--cause"), "srv", "tgt.txt")):
        out += ["T-TGT"] + tgt_rows(arg("--cause")) + ["", "T-TIMEOUT"] + timeout_rows(arg("--cause")) + [""]
if arg("--relief"): out += ["T-RELIEF"] + relief_rows(arg("--relief")) + ["", "T-CLOSED"] + closed_rows(arg("--relief")) + [""]
if arg("--brw4"): out += ["T-BRW4"] + brw4_rows(arg("--brw4")) + [""]
if arg("--g71"): out += ["T-G71"] + g71_rows(arg("--g71")) + ["", "T-G71-SRV"] + g71_srv_rows(arg("--g71")) + [""]
if arg("--big"): out += ["T-M2"] + big_rows(arg("--big")) + [""]
print("\n".join(out))
if arg("--check"):
    note = set(open(arg("--check")).read().splitlines())
    miss = [l for l in out if l.startswith("|") and l not in note]
    for l in miss: print("MISSING", l)
    print("check:", "OK" if not miss else f"BROKEN ({len(miss)} lines)")
    sys.exit(1 if miss else 0)
