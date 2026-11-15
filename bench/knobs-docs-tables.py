#!/usr/bin/env python3
"""60.75 tables (knobs-docs, the flush-first study of 60.70 9.5 B): counts from the raw files of one ephemeral the build host VM
(AMD Ryzen 7 9700X host, 4 vCPU guest, Ubuntu kernel 7.0). No timing: MiB/s only scales counts to "per MiB".

usage: bench/knobs-docs-tables.py RAW [--check NOTE.md]
RAW = the directory with k1-e1.jsonl, k1-e2.jsonl, k1-rec1/, k1-rec2/ (four arms, 64 KiB frames), k1b-e4.jsonl (queue
samples of ss every 0.1 s, credit pacing off as two more arms) and k1c-e1.jsonl (63 KiB frames). Main checkout:
an internal note (not published) (the drivers: ../kit).
Without --check the tables are printed as Markdown, each between <!-- table NAME --> and <!-- /table -->. With --check
every table must equal the block of the same name in NOTE.md: prints "check: OK (N tables)" or the differences, exit 1.
Per MiB: echo moves the same bytes both ways; the denominator is wbench's MiB/s x the perf window (as vps_row of bench/lane-cost-tables.py on branch lane-cost), the
lpt counters (whole run) are per MiB of download (t_read_b + t_spl_b). Cells: median [min, max] of the runs."""
import json, os, re, statistics, sys

K, M = 1024, 1024 * 1024
ARMS = ["pt", "pt-ff", "pt-1m", "pt-ff1m"]
ARM_NAME = {"pt": "default (256 KiB bulk mark)", "pt-ff": "flush-first", "pt-1m": "1 MiB bulk mark", "pt-ff1m": "flush-first + 1 MiB mark"}
CELLS = ["echo-1x10", "echo-1x1"]


def load(path):
    if not os.path.exists(path):
        return []
    rows = [json.loads(l) for l in open(path) if l.strip()]
    bad = [r for r in rows if "error" in r]
    if bad:
        sys.exit(f"{path}: {len(bad)} run(s) with an error: {bad[0]['error']}")
    return rows


def mmm(xs, nd):
    xs = [x for x in xs if x is not None]
    if not xs:
        return "-"
    f = lambda v: f"{v:,.{nd}f}"
    return f"{f(statistics.median(xs))} [{f(min(xs))}, {f(max(xs))}]"


def perf_mib(r):
    return r["mib_s"] * r["window_s"]


def lpt_row(l):
    down = l["t_read_b"] + l["t_spl_b"]
    if down <= 0:
        return None
    mib = down / M
    return {
        "parks": (l["park_bulk"] + l["park_high"]) / mib,
        "ff": l["ff_flush"] / mib,
        "ep": l["ep_ret"] / mib,
        "copy": 100.0 * l["t_read_b"] / down,
        "csend": (l["c_send"] + l["b_send"] + l["c_spl"]) / mib,
        "kib_csend": (l["c_send_b"] + l["b_send_b"] + l["c_spl_b"]) / K / max(l["c_send"] + l["b_send"] + l["c_spl"], 1),
        "tread": (l["t_read"] + l["t_spl"]) / mib,
        "kib_tread": down / K / max(l["t_read"] + l["t_spl"], 1),
        "creads": l["c_read"] / mib,
        "uwv": l["u_writev"] / mib,
        "kib_uwv": l["u_writev_b"] / K / max(l["u_writev"], 1),
        "ts_seg": l["ts_data_out"] / mib,
        "kib_ts_seg": l["u_writev_b"] / K / max(l["ts_data_out"], 1),
        "cs_seg": l["cs_data_out"] / mib,
        "cont": l["cont"] / mib,
        "pace": l["pace_hold"] / mib,
        "tpr": l["u_writev"] / max(l["c_read"], 1),
        "t_acks": (l["ts_segs_in"] - l["ts_data_in"]) / mib,
        "segs": (l["ts_segs_in"] + l["ts_segs_out"] + l["cs_segs_in"] + l["cs_segs_out"]) / mib,
    }


def e1_row(r):
    p, t, mib = r["perf"], r["thr"], perf_mib(r)
    d = {"cyc": (p["cycles:k"] + p["cycles:u"]) / mib / 1e6, "cyc_k": p["cycles:k"] / mib / 1e6, "cyc_u": p["cycles:u"] / mib / 1e6,
         "ins_k": p["instructions:k"] / mib / 1e6, "ins_u": p["instructions:u"] / mib / 1e6,
         "ipc_k": p["instructions:k"] / p["cycles:k"], "core": (t["u"] + t["s"]) / t["tck"] / r["window_s"]}
    d.update(lpt_row(r["lpt"]) or {})
    return d


def e2_row(r):
    p, mib = r["perf"], perf_mib(r)
    g = lambda k: p[k] / mib / 1e3
    return {"cyc": p["cycles"] / mib / 1e6, "l2": g("ls_any_fills_from_sys.local_l2"), "ccx": g("ls_any_fills_from_sys.local_ccx"),
            "dram": g("ls_any_fills_from_sys.dram_io_all"), "l2miss": g("l2_cache_req_stat.ic_dc_miss_in_l2")}


def pct_ok(rows):
    for r in rows:
        for k, v in r["perf"].items():
            if k.endswith("@pct") and v < 99.0:
                sys.exit(f"perf event {k[:-4]} ran {v}% of the window (run {r['cell']} {r['arm']} rep {r.get('rep')}): multiplexed")


def table(name, head, lines):
    out = [f"<!-- table {name} -->", "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(x) for x in l) + " |" for l in lines]
    return name, "\n".join(out + ["<!-- /table -->"])


E1_COLS = [("cyc", "server thread cycles per MiB, M", 2), ("cyc_k", "kernel", 2), ("cyc_u", "user", 2),
           ("ins_k", "kernel instructions per MiB, M", 2), ("ipc_k", "kernel instructions per cycle", 2), ("core", "server thread, cores", 2)]
LPT_COLS = [("parks", "target parks", 2), ("ff", "early flushes", 2), ("ep", "epoll_wait returns", 2), ("copy", "download copied, %", 0),
            ("csend", "sends + splices to the client", 1), ("kib_csend", "KiB each", 0), ("creads", "client reads", 1),
            ("uwv", "upload writev to the targets", 1), ("kib_uwv", "KiB each", 0), ("ts_seg", "data segments to the targets", 1),
            ("kib_ts_seg", "KiB each", 1), ("t_acks", "ACKs from the targets", 1), ("segs", "all segments of the server's sockets", 1),
            ("tpr", "targets written per client read", 2), ("pace", "credit pace holds", 2), ("cont", "CONTINUE frames", 2)]
E2_COLS = [("cyc", "cycles per MiB, M", 2), ("l2", "fills from the own L2, thousand per MiB", 1), ("ccx", "fills from L3 or another core's L2", 1),
           ("dram", "fills from DRAM", 2), ("l2miss", "L2 misses (demand data + instruction)", 1)]


def by(rows, f):
    g = {}
    for r in rows:
        g.setdefault((r["cell"], r["arm"]), []).append(f(r))
    return g


def stat_tables(raw, tag):
    out = []
    e1 = load(f"{raw}/{tag}-e1.jsonl")
    if not e1:
        return out
    pct_ok(e1)
    g = by(e1, e1_row)
    lines = [[c, ARM_NAME[a], len(g[(c, a)])] + [mmm([d.get(k) for d in g[(c, a)]], nd) for k, _, nd in E1_COLS]
             for c in CELLS for a in ARMS if (c, a) in g]
    out.append(table(f"{tag}-cycles", ["cell", "arm", "n"] + [h for _, h, _ in E1_COLS], lines))
    lines = [[c, ARM_NAME[a], len(g[(c, a)])] + [mmm([d.get(k) for d in g[(c, a)]], nd) for k, _, nd in LPT_COLS]
             for c in CELLS for a in ARMS if (c, a) in g]
    out.append(table(f"{tag}-counts", ["cell", "arm", "n"] + [h + (" per MiB" if not h.startswith(("KiB", "download")) else "") for _, h, _ in LPT_COLS], lines))
    e2 = load(f"{raw}/{tag}-e2.jsonl")
    if e2:
        pct_ok(e2)
        g2 = by(e2, e2_row)
        lines = [[c, ARM_NAME[a], len(g2[(c, a)])] + [mmm([d.get(k) for d in g2[(c, a)]], nd) for k, _, nd in E2_COLS]
                 for c in CELLS for a in ARMS if (c, a) in g2]
        out.append(table(f"{tag}-cache", ["cell", "arm", "n"] + [h for _, h, _ in E2_COLS], lines))
    out += profile_tables(raw, tag, g)
    return out


def q_row(r):
    """k1b runs: the e4 events + the ss queue samples of the perf window (means over the samples, KiB)"""
    p, mib, q = r["perf"], perf_mib(r), r["q"]
    if len(q) < 20:
        sys.exit(f"run {r['cell']} {r['arm']} rep {r.get('rep')}: only {len(q)} queue samples")
    m = lambda i: statistics.mean(x[i] for x in q) / K
    d = {"cyc": (p["cycles:k"] + p["cycles:u"]) / mib / 1e6, "ins_k": p["instructions:k"] / mib / 1e6,
         "ccx": p["ls_any_fills_from_sys.local_ccx"] / mib / 1e3, "dram": p["ls_any_fills_from_sys.dram_io_all"] / mib / 1e3,
         "c_rq": m(0), "c_sq": m(1), "t_rq": m(2), "t_sq": m(3), "nq": len(q)}
    d.update(lpt_row(r["lpt"]))
    return d


Q_ARMS = ["pt", "pt-ff", "pt-np", "pt-ff-np"]
Q_NAME = {"pt-np": "default, --no-credit-pace", "pt-ff-np": "flush-first, --no-credit-pace"}
Q_COLS = [("cyc", "cycles per MiB, M", 2), ("ins_k", "kernel instructions per MiB, M", 2), ("ccx", "fills from L3 or another core's L2, thousand per MiB", 1),
          ("dram", "fills from DRAM, thousand per MiB", 2), ("c_rq", "client socket: upload not read yet, KiB", 0), ("c_sq", "client socket: download not acked, KiB", 0),
          ("t_rq", "target sockets: download not read yet, KiB", 0), ("t_sq", "target sockets: upload not acked, KiB", 0),
          ("pace", "credit pace holds per MiB", 2), ("cont", "CONTINUE frames per MiB", 2), ("parks", "target parks per MiB", 2), ("kib_uwv", "KiB per upload writev", 0)]


def q_tables(raw):
    rows = load(f"{raw}/k1b-e4.jsonl")
    if not rows:
        return []
    pct_ok(rows)
    g = by(rows, q_row)
    name = lambda a: Q_NAME.get(a) or ARM_NAME[a]
    lines = [[c, name(a), len(g[(c, a)]), min(d["nq"] for d in g[(c, a)])] + [mmm([d[k] for d in g[(c, a)]], nd) for k, _, nd in Q_COLS]
             for c in CELLS for a in Q_ARMS if (c, a) in g]
    return [table("k1b-queues", ["cell", "arm", "n", "queue samples per run, at least"] + [h for _, h, _ in Q_COLS], lines)]


F_CELLS = ["echo-1x10-f63k", "echo-1x1-f63k"]
F_COLS = [("cyc", "cycles per MiB, M", 2), ("ins_k", "kernel instructions per MiB, M", 2), ("ipc_k", "kernel instructions per cycle", 2),
          ("uwv", "upload writev per MiB", 1), ("kib_uwv", "KiB each", 0), ("tpr", "targets written per client read", 2),
          ("ts_seg", "data segments to the targets per MiB", 1), ("t_acks", "ACKs from the targets per MiB", 1),
          ("segs", "all segments per MiB", 1), ("parks", "target parks per MiB", 2), ("copy", "download copied, %", 0)]


def f_tables(raw):
    rows = load(f"{raw}/k1c-e1.jsonl")
    if not rows:
        return []
    pct_ok(rows)
    g = by(rows, e1_row)
    lines = [[c, ARM_NAME[a], len(g[(c, a)])] + [mmm([d[k] for d in g[(c, a)]], nd) for k, _, nd in F_COLS] for c in F_CELLS for a in ARMS if (c, a) in g]
    return [table("k1c-frames-63k", ["cell (63 KiB frames)", "arm", "n"] + [h for _, h, _ in F_COLS], lines)]


GROUPS = [  # the GROUPS of bench/lane-cost-tables.py (branch lane-cost) (symbol -> what the cycles are spent on), plus the kernel 7.0 names of this VM
    # (kernel_init_pages = zeroing at allocation, the paravirtual spinlock, conntrack, fdget)
    ("kernel copy to user space (reads of the client and copied target reads)", r"^k:(_copy_to_iter|__skb_datagram_iter|skb_copy_datagram_iter|simple_copy_to_iter)"),
    ("kernel copy from user space (sends, upload writev)", r"^k:(_copy_from_iter|copy_iovec_from_user)"),
    ("copy checks", r"^k:(rep_movs_alternative|copy_user|check_heap_object|__check_object_size|__virt_addr_valid|check_stack_object|is_vmalloc_addr)"),
    ("page allocation and zeroing", r"^k:(clear_page_rep|clear_page|post_alloc_hook|get_page_from_freelist|__rmqueue_pcplist|rmqueue|__alloc_pages|alloc_pages|skb_page_frag_refill|free_unref_page|__free_one_page|free_tail_page_prepare|free_unref_page_prepare|free_unref_page_commit|__free_pages|free_pcppages_bulk|page_frag|__page_frag|kmem_cache|__kmalloc|kfree|kmalloc|memset_orig|__alloc_skb|__build_skb|skb_release|__kfree_skb|kfree_skb|consume_skb|skb_free|napi_consume|__put_page|__folio_put|mod_memcg|__mod_memcg|memcg|try_charge|refill_stock|obj_cgroup|__sk_mem|sk_mem|tcp_wmem|mem_cgroup|free_frozen|__free_frozen|free_unref_folio|folio|kernel_init_pages|prep_compound_page|page_counter|__pi_memset|__next_zones_zonelist|__nr_to_section)"),
    ("splice and pipe", r"^k:(splice|skb_splice|pipe_|__splice|do_splice|tcp_splice|skb_splice_bits|__skb_splice|generic_pipe|page_cache_pipe|iov_iter_extract|vmsplice|anon_pipe|wakeup_pipe|__skb_to_sgvec|spd_|tcp_read_sock)"),
    ("TCP send, receive, loopback, netfilter", r"^k:(tcp_|__tcp_|ip_|__ip_|net_rx|__netif|netif|dev_|__dev_|loopback|process_backlog|enqueue_to_backlog|nf_|nft_|ipv4_|inet_|__inet|sk_|__sk_|sock_|skb_|__skb|validate_xmit|eth_|napi|__napi|raw_|__local_bh|do_softirq|__do_softirq|handle_softirq|release_sock|lock_sock|__release_sock|__lock_sock|bpf_|ktime|read_tsc|pvclock|kvm_clock|__mod_timer|mod_timer|lock_timer|detach_if_pending|__qdisc|sch_|fq_|rb_|tcp_rbtree|__rcu|rcu_|csum|__copy_skb|pskb|ipv6|import_iovec|__import|__nf_|nf_conntrack|resolve_normal_ct|hash_conntrack|__siphash|expr_call|cubictcp|dst_|__smp_call)"),
    ("wake-ups, scheduler, epoll, locks", r"^k:(__raw_callee_save___pv_queued_spin|__pv_queued_spin|ep_|__ep_|epoll|do_epoll|try_to_wake|ttwu|__wake_up|wake_up|select_task|enqueue_|dequeue_|update_|pick_next|__schedule|schedule|finish_task|switch_|__switch|native_queued_spin|_raw_spin|__raw_spin|raw_spin|sched_|resched|available_idle|cpuacct|psi_|__update|set_next|put_prev|check_preempt|wakeup_|default_wake|autoremove|pollwake|__pollwait|sock_def_readable|sock_def_write|native_send_call|smp_call|native_write_msr|x2apic|kvm_|pv_|native_sched|record_times|place_entity|reweight|avg_vruntime|newidle|idle_cpu|irq)"),
    ("syscall entry and exit, mitigations", r"^k:(entry_|syscall_|do_syscall|__x64_sys|__sys_|x64_sys|srso|__x86_|retbleed|ret_from|fpregs|restore_fpregs|switch_fpu|exit_to_user|__fget|fget|fput|__fdget|sockfd|security_|apparmor|aa_|common_file|rw_verify|vfs_|ksys_|__audit|audit|native_irq|asm_|error_entry|sync_regs|amd_clear|__get_user|__put_user|copy_msghdr|___sys|____sys|sock_sendmsg|sock_recvmsg|sock_read_iter|sock_write_iter|do_iter|new_sync|__cond_resched|mutex|__mutex|fsnotify|touch_atime|atime|current_time|file_|iov_iter|aio_|fdget)"),
    ("server: unmask the client's upload (user)", r"^u:.*(unmask|hw_ws_mask)"),
    ("server: memmove / memcpy (user)", r"^u:.*(memmove|memcpy)"),
    ("server: other user code", r"^u:"),
]
OTHER = "other kernel symbols"


def flat(path):
    d = {}
    for l in open(path):
        m = re.match(r"\s+([\d.]+)%\s+\[(.)\]\s+(\S+)", l)
        if m:
            d[("k:" if m.group(2) == "k" else "u:") + m.group(3)] = d.get(("k:" if m.group(2) == "k" else "u:") + m.group(3), 0) + float(m.group(1))
    return d


def shares(fl):
    g = {}
    for s, pct in fl.items():
        for name, rx in GROUPS:
            if re.search(rx, s):
                g[name] = g.get(name, 0) + pct
                break
        else:
            g[OTHER] = g.get(OTHER, 0) + pct
    tot = sum(g.values())
    return {k: 100.0 * v / tot for k, v in g.items()}


def profile_tables(raw, tag, g1):
    out = []
    names = [n for n, _ in GROUPS] + [OTHER]
    for cell in CELLS:
        cols, heads = [], []
        for a in ARMS:
            recs = [f"{raw}/{tag}-rec{i}/perf-{cell}-{a}.flat.txt" for i in (1, 2)]
            recs = [p for p in recs if os.path.exists(p)]
            if not recs or (cell, a) not in g1:
                continue
            cyc = statistics.median(d["cyc"] for d in g1[(cell, a)]) * 1000  # thousand cycles per MiB
            sh = [shares(flat(p)) for p in recs]
            cols.append({n: [s.get(n, 0) * cyc / 100 for s in sh] for n in names} | {"all": cyc})
            heads.append(f"{ARM_NAME[a]} ({len(recs)} profiles)")
        if not cols:
            continue
        f = lambda xs: f"{statistics.mean(xs):,.0f}" + (f" ({min(xs):,.0f}-{max(xs):,.0f})" if len(xs) > 1 else "")
        lines = [[n] + [f(c[n]) for c in cols] for n in names]
        lines.append(["all: median cycles per MiB of the stat runs"] + [f"{c['all']:,.0f}" for c in cols])
        out.append(table(f"{tag}-profile-{cell}", ["thousand cycles per MiB spent on"] + heads, lines))
    return out


G3_ARMS = [("ptdef", "pooltest default (256 KiB bulk mark)"), ("ptdef2", "the same binary again (A/A copy)"), ("ptff", "flush-first")]


def g3_tables(raw):
    """gold3 timed cells (`wst ab`, n=12, rotated; RAW/../gold3-raw/out/raw): paired ratio to the default by
    bench/wispsuite/stats.py (verdict words from it), also flush-first against the A/A copy"""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
    from wispsuite import stats
    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(raw))), "gold3-raw", "out", "raw")
    lines = []
    for cell, frame in (("echo-1x10-f63k", "63 KiB"), ("echo-1x10-f64k", "64 KiB")):
        rows = load(os.path.join(d, cell + ".jsonl"))
        if not rows:
            continue
        by_v = {}
        for r in rows:
            if r.get("errors"):
                sys.exit(f"{cell}: a run with errors ({r['v']} rep {r['rep']})")
            by_v.setdefault(r["v"], {})[r["rep"]] = r["mib_s_down"]
        reps = sorted(set.intersection(*(set(x) for x in by_v.values())))
        col = lambda v: [by_v[v][i] for i in reps]
        fmt = lambda c: f"{c['ratio']:.3f} [{c['ci90'][0]:.3f}, {c['ci90'][1]:.3f}] {c['verdict']}"
        for v, name in G3_ARMS:
            xs = col(v)
            base = "base" if v == "ptdef" else fmt(stats.compare(col("ptdef"), xs))
            vs_copy = fmt(stats.compare(col("ptdef2"), xs)) if v == "ptff" else "-"
            cpu = statistics.median(r["cpu_pct"] for r in rows if r["v"] == v)
            lines.append([f"echo 1x10, {frame} frames", name, len(xs), f"{statistics.median(xs):,.0f}", f"{min(xs):,.0f}", f"{max(xs):,.0f}",
                          f"{cpu:.0f}", base, vs_copy])
    if not lines:
        return []
    return [table("g3-timed", ["cell", "arm", "n", "median MiB/s", "min", "max", "server CPU %", "paired ratio to the default [90% CI]",
                               "to the A/A copy"], lines)]

def main():
    raw = sys.argv[1]
    tabs = []
    tabs += stat_tables(raw, "k1")
    tabs += q_tables(raw)
    tabs += f_tables(raw)
    tabs += g3_tables(raw)
    if "--check" in sys.argv:
        note = open(sys.argv[sys.argv.index("--check") + 1]).read()
        bad = 0
        for name, t in tabs:
            m = re.search(rf"<!-- table {re.escape(name)} -->.*?<!-- /table -->", note, re.S)
            if not m or m.group(0) != t:
                bad += 1
                print(f"check: table {name} differs or is missing")
        names = set(re.findall(r"<!-- table (\S+) -->", note))
        for n in names - {n for n, _ in tabs}:
            if n.startswith(("k1-", "k1b-", "k1c-", "g3-")):
                bad += 1
                print(f"check: the note has table {n}, the raw files do not")
        print(f"check: OK ({len(tabs)} tables)" if not bad else f"check: {bad} problem(s)")
        sys.exit(1 if bad else 0)
    print("\n\n".join(t for _, t in tabs))


if __name__ == "__main__":
    main()
