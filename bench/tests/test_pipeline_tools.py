"""60.78 (worker sb-pipe): the pipeline tools close what they claim. Run: cd bench && python3 -m unittest discover -s tests -v.
G18 disasm gate, G20 compat baseline, G22 per-sample peak RSS, G23 relocation-aware data sections, G24 abfan / evalall,
G50 farm signal + rerun-aware parity, doccheck --rewritten-group. No network, no box; gcc for the G23 case."""
import json, os, shutil, signal, subprocess, sys, tempfile, threading, time, types, unittest
from unittest import mock

BENCH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BENCH, "tools"))
import gate, gate_baseline, costfp, route, abfan, farm, doccheck, disasm_cls  # noqa: E402
from wispsuite import sample, regress  # noqa: E402

DIS = """functions base 10 new 11; differ 2; only in base 0; only in new 1
worker    OFFSET-ONLY 1
     finalwisp::worker::a
worker    RENAME-ONLY 0
worker    LOGIC       1
     finalwisp::worker::Worker::run
         target x -> y
finalwisp OFFSET-ONLY 0
finalwisp RENAME-ONLY 0
finalwisp LOGIC       1
     finalwisp::cli::parse
other     OFFSET-ONLY 0
other     RENAME-ONLY 0
other     LOGIC       0
only in base, worker: 0
only in base, finalwisp: 0
only in new, worker: 1
     finalwisp::worker::new_fn
only in new, finalwisp: 0
"""


class DisasmGate(unittest.TestCase):
    def test_parse(self):
        f = gate.disasm_parse(DIS)
        self.assertEqual(f, {"LOGIC": ["finalwisp::worker::Worker::run"], "only in new": ["finalwisp::worker::new_fn"], "only in base": []})

    def test_unlisted_worker_logic_is_broken(self):
        ok, detail, _ = gate.disasm_verdict(DIS, [{"fn": "finalwisp::worker::new_fn", "kind": "only in new", "proof": "x"}])
        self.assertFalse(ok)
        self.assertIn("NOT on the allow list", detail)
        self.assertIn("Worker::run", detail)

    def test_all_listed_with_proof_is_ok_and_stale_is_named(self):
        allow = [{"fn": "finalwisp::worker::Worker::run", "kind": "LOGIC", "proof": "60.xx T1"},
                 {"fn": "finalwisp::worker::new_fn", "kind": "only in new", "proof": "60.xx T2"},
                 {"fn": "finalwisp::worker::gone", "kind": "LOGIC", "proof": "old"}]
        ok, detail, _ = gate.disasm_verdict(DIS, allow)
        self.assertTrue(ok, detail)
        self.assertIn("1 allow entr(ies) not in the report (stale)", detail)

    def test_entry_without_proof_is_broken(self):
        ok, detail, _ = gate.disasm_verdict(DIS, [{"fn": "finalwisp::worker::Worker::run", "kind": "LOGIC", "proof": ""},
                                                  {"fn": "finalwisp::worker::new_fn", "kind": "only in new", "proof": "p"}])
        self.assertFalse(ok)

    def test_unknown_format_is_an_error(self):
        with self.assertRaises(ValueError):
            gate.disasm_parse(DIS.replace("     finalwisp::worker::Worker::run", "\tfinalwisp::worker::Worker::run"))

    def test_identical_binaries_report(self):
        clean = DIS.replace("worker    LOGIC       1\n     finalwisp::worker::Worker::run\n         target x -> y\n", "worker    LOGIC       0\n") \
                   .replace("only in new, worker: 1\n     finalwisp::worker::new_fn\n", "only in new, worker: 0\n")
        self.assertTrue(gate.disasm_verdict(clean, [])[0])


def fake_gate(d, steps, rerun=None):
    """a gate output directory: compat/results.json + logs; rerun = (step, log text) of a rerun that passed"""
    os.makedirs(os.path.join(d, "compat"))
    json.dump({"steps": [{"step": s, "status": st} for s, (st, _) in steps.items()]}, open(os.path.join(d, "compat/results.json"), "w"))
    for s, (_, text) in steps.items():
        open(os.path.join(d, "compat", s + ".log"), "w").write(text)
    reruns = []
    if rerun:
        rd = os.path.join(d, "compat-rerun", rerun[0])
        os.makedirs(rd)
        json.dump({"steps": [{"step": rerun[0], "status": "PASS"}]}, open(os.path.join(rd, "results.json"), "w"))
        open(os.path.join(rd, rerun[0] + ".log"), "w").write(rerun[1])
        reruns = [{"step": rerun[0], "rerun_status": "PASS", "rerun_dir": "/vm/path/elsewhere"}]
    json.dump({"verdict": "OK", "complete": True, "head": "h", "binary_md5": "m", "reruns": reruns}, open(os.path.join(d, "VERDICT.json"), "w"))
    return reruns


class DisasmCls(unittest.TestCase):
    """the number pattern: "$0x4e0" is one token (it was "$0" + "x4e0": a changed hexadecimal immediate kept its digits)"""

    def test_hex_immediate_is_one_token(self):
        self.assertEqual(disasm_cls.loose(["add $0x4e0,%rdi"]), ["add N,%rdi"])
        self.assertEqual(disasm_cls.loose(["mov $-0x8,%rax\nmov 0x10(%rsp),%rax\nmov -0x8(%rbp),%rax\ncall <f+0x1f>\nmov $5,%eax"]),
                         ["mov N,%rax\nmov N(%rsp),%rax\nmov N(%rbp),%rax\ncall <fN\nmov N,%eax"])

    def test_offset_only_body(self):
        a = {"finalwisp::worker::level_refused_conn": ["lea 0x10(%rdi),%rax\nadd $0x4e0,%rdi"], "finalwisp::worker::x": ["cmp $0x1,%eax\nje <g>"]}
        b = {"finalwisp::worker::level_refused_conn": ["lea 0x18(%rdi),%rax\nadd $0x4f0,%rdi"], "finalwisp::worker::x": ["cmp $0x1,%eax\njne <g>"]}
        diff, out, _ = disasm_cls.classify(a, b)
        self.assertEqual(out[("worker", "OFFSET-ONLY")], ["finalwisp::worker::level_refused_conn"])
        self.assertEqual(out[("worker", "LOGIC")], ["finalwisp::worker::x"])


class Baseline(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)
        ref = os.path.join(self.t, "ref")
        fake_gate(ref, {"up": ("PASS", "PASS a\nPASS b\nSKIP retry (x)\n"), "fds": ("PASS", "PASS c\n")})
        inv, sk = gate_baseline.collect(ref, [])
        self.base = {"classes": {"laptop-fast": {"inventory": inv["steps"], "skip_lines": [{"step": s, "line": l, "why": "w"} for s, l in sk]}}}

    def run_case(self, steps, rerun=None):
        d = os.path.join(self.t, "g%d" % len(os.listdir(self.t)))
        rr = fake_gate(d, steps, rerun)
        inv, sk = gate_baseline.collect(d, rr)
        return gate_baseline.check(self.base, "laptop-fast", inv, sk)

    def test_same_is_ok(self):
        self.assertTrue(self.run_case({"up": ("PASS", "PASS a\nPASS b\nSKIP retry (x)\n"), "fds": ("PASS", "PASS c\n")})[0])

    def test_new_skip_line_in_a_pass_step_is_broken(self):
        ok, detail, lines = self.run_case({"up": ("PASS", "PASS a\nPASS b\nSKIP retry (x)\n"), "fds": ("PASS", "PASS c\nSKIP A1: needs root\n")})
        self.assertFalse(ok)
        self.assertTrue(any(l.startswith("NEW SKIP fds") for l in lines), lines)

    def test_other_skip_with_equal_count_is_broken(self):
        ok, _, lines = self.run_case({"up": ("PASS", "PASS a\nPASS b\nSKIP other case\n"), "fds": ("PASS", "PASS c\n")})
        self.assertFalse(ok)

    def test_fewer_pass_lines_is_broken(self):
        self.assertFalse(self.run_case({"up": ("PASS", "PASS a\nSKIP retry (x)\n"), "fds": ("PASS", "PASS c\n")})[0])

    def test_expected_skip_gone_is_ok(self):
        ok, detail, _ = self.run_case({"up": ("PASS", "PASS a\nPASS b\nPASS retry\n"), "fds": ("PASS", "PASS c\n")})
        self.assertTrue(ok, detail)
        self.assertIn("1 expected not seen", detail)

    def test_rerun_counts_with_its_entry(self):
        steps = {"up": ("FAIL", "PASS a\nFAIL b\nSKIP retry (x)\n"), "fds": ("PASS", "PASS c\n")}
        self.assertTrue(self.run_case(steps, rerun=("up", "PASS a\nPASS b\nSKIP retry (x)\n"))[0])
        self.assertFalse(self.run_case(steps)[0])

    def test_no_class_is_broken(self):
        d = os.path.join(self.t, "x")
        fake_gate(d, {"up": ("PASS", "PASS a\n")})
        inv, sk = gate_baseline.collect(d, [])
        ok, detail, _ = gate_baseline.check(self.base, "farm-vm-fast", inv, sk)
        self.assertFalse(ok)
        self.assertIn("no baseline for host class farm-vm-fast", detail)


class FarmParityAndSignal(unittest.TestCase):
    def test_parity_counts_reruns(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t)
        fake_gate(os.path.join(t, "lap"), {"up": ("PASS", "PASS a\nPASS b\n")})
        fake_gate(os.path.join(t, "vm"), {"up": ("FAIL", "PASS a\nFAIL b\n")}, rerun=("up", "PASS a\nPASS b\n"))
        f = farm.Farm.__new__(farm.Farm)
        f.repo = os.path.dirname(BENCH)
        f.a = types.SimpleNamespace(ref_compat=os.path.join(t, "lap", "compat"))
        r = f.parity(os.path.join(t, "vm"))
        self.assertEqual(r.get("losses"), 0, r)

    def test_signal_stops_the_vms_and_kills_a_client_that_stays(self):
        f = farm.Farm.__new__(farm.Farm)
        f.KILL_GRACE_S = 0.3
        calls = []
        f.incus = lambda *a, **k: calls.append(a) or types.SimpleNamespace(returncode=0, stderr="")
        stubborn = subprocess.Popen([sys.executable, "-c", "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"])
        self.addCleanup(lambda: stubborn.poll() is None and stubborn.kill())
        time.sleep(0.3)
        f.procs, f.stopping = {stubborn}, False
        f.jobs = [{"vm": "fw-farm-t-0", "made": True}, {"vm": "fw-farm-t-1"}, {"vm": "fw-farm-t-2", "made": True, "deleted": True}]
        f.on_signal()
        self.assertTrue(f.stopping)
        deadline = time.time() + 10
        while stubborn.poll() is None and time.time() < deadline:
            time.sleep(0.1)
        self.assertEqual(stubborn.poll(), -signal.SIGKILL)
        self.assertEqual(calls, [("stop", "--force", "fw-farm-t-0")])

    def drain_farm(self):
        f = farm.Farm.__new__(farm.Farm)
        f.KILL_GRACE_S, f.LOOP_GRACE_S = 0.3, 0.6
        calls = []
        f.incus = lambda *a, **k: calls.append(a) or types.SimpleNamespace(returncode=0, stderr="")
        f.procs, f.stopping, f.draining = set(), False, False
        f.say = lambda m: None
        return f, calls

    def test_signal_drains_a_loop_first(self):
        # 60.78 T1: the loop's flakeloop is asked to end in the VM; the job then pulls and deletes its VM itself
        f, calls = self.drain_farm()
        job = {"vm": "fw-farm-t-0", "made": True, "in_loop": True}
        f.jobs = [job]
        f.on_signal()
        self.assertFalse(f.stopping)
        deadline = time.time() + 5
        while not calls and time.time() < deadline:
            time.sleep(0.05)
        job["deleted"] = True  # (what guarded() does after the pull)
        time.sleep(1.0)
        self.assertEqual(calls, [("exec", "fw-farm-t-0", "--", "pkill", "-TERM", "-f", farm.Farm.FLAKELOOP_PATTERN)])
        # the pattern hits flakeloop, not the systemd-run client that started it
        self.assertRegex("python3 /home/ubuntu/finalwisp/bench/tools/flakeloop.py run /home/ubuntu/loop --runs 5", f.FLAKELOOP_PATTERN)
        self.assertNotRegex("systemd-run --user --wait python3 /home/ubuntu/finalwisp/bench/tools/flakeloop.py run /home/ubuntu/loop", f.FLAKELOOP_PATTERN)
        self.assertFalse(f.stopping)

    def test_a_loop_that_does_not_end_is_stopped_by_force(self):
        f, calls = self.drain_farm()
        f.jobs = [{"vm": "fw-farm-t-0", "made": True, "in_loop": True}]
        f.on_signal()
        deadline = time.time() + 5
        while ("stop", "--force", "fw-farm-t-0") not in calls and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(f.stopping)
        self.assertEqual(calls[-1], ("stop", "--force", "fw-farm-t-0"))
        self.assertEqual(f.draining, "timeout")

    def test_a_second_signal_stops_a_draining_loop_by_force(self):
        f, calls = self.drain_farm()
        f.LOOP_GRACE_S = 30
        f.jobs = [{"vm": "fw-farm-t-0", "made": True, "in_loop": True}]
        f.on_signal()
        f.on_signal()
        self.assertTrue(f.stopping)
        deadline = time.time() + 5
        while ("stop", "--force", "fw-farm-t-0") not in calls and time.time() < deadline:
            time.sleep(0.05)
        self.assertIn(("stop", "--force", "fw-farm-t-0"), calls)


class Router(unittest.TestCase):
    def fp(self, dd):
        return {"meta": {"md5": {"base": "a", "new": "b"}, "cells": [], "failed": []}, "identity": {"differing_bodies": 1, "data_sections_differ": dd},
                "cells": {c: {"flagged": [], "code": {"changed": []}} for c in route.FP_CELLS}}

    def test_any_data_section_routes_the_full_core_set(self):
        self.assertEqual(route.route("CHANGED", self.fp([]))["decision"], "routed")  # (the canary)
        for s in (".data.rel.ro", ".init_array", ".got", "rodata.cst32", ".tdata"):
            r = route.route("CHANGED", self.fp([s]))
            self.assertEqual(r["decision"], "blind-full-core", s)
            self.assertEqual(r["order"], route.CORE)


class DataHashes(unittest.TestCase):
    """a static-pie binary whose only change is a pointer target in a const table: LLD (rustc's linker) leaves the slot 0
    in the file and puts the target in an R_X86_64_RELATIVE addend. GNU ld (here) writes the addend into the slot too, so
    the slots are zeroed by hand to get LLD's file bytes; the bodies stay the same."""

    def test_pointer_target_change_is_seen(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t)
        src = "int a = 7, b = 7;\nint *const tbl[] = {&%s, &a};\nint main(int c, char **v) { (void)v; return *tbl[c & 1]; }\n"
        def sect(p):  # (addr, offset, size) of .data.rel.ro
            for l in subprocess.run(["readelf", "-S", "-W", p], capture_output=True, text=True, check=True).stdout.splitlines():
                x = l.split("]", 1)[1].split() if "]" in l else []
                if x and x[0] == ".data.rel.ro":
                    return int(x[2], 16), int(x[3], 16), int(x[4], 16)
            raise AssertionError("no .data.rel.ro")
        bins = []
        for n in "ab":
            open(f"{t}/{n}.c", "w").write(src % n)
            subprocess.run(["gcc", "-O1", "-static-pie", "-fPIE", "-o", f"{t}/{n}", f"{t}/{n}.c"], check=True)
            raw = bytearray(open(f"{t}/{n}", "rb").read())
            addr, off, size = sect(f"{t}/{n}")
            for l in subprocess.run(["readelf", "-r", "-W", f"{t}/{n}"], capture_output=True, text=True, check=True).stdout.splitlines():
                x = l.split()
                if len(x) >= 4 and x[2] == "R_X86_64_RELATIVE" and addr <= int(x[0], 16) < addr + size:
                    at = off + int(x[0], 16) - addr
                    raw[at:at + 8] = bytes(8)
            open(f"{t}/{n}", "wb").write(raw)
            bins.append(f"{t}/{n}")
        rd = lambda p: (lambda a, o, s: open(p, "rb").read()[o:o + s])(*sect(p))
        self.assertEqual(rd(bins[0]), rd(bins[1]), "the file bytes of .data.rel.ro are the same (the blind spot)")
        ha, hb = costfp.data_hashes(bins[0]), costfp.data_hashes(bins[1])
        self.assertEqual([k for k in ha if ha[k] != hb.get(k)], [".data.rel.ro"])


class PeakRss(unittest.TestCase):
    def test_per_sample_vmrss_max(self):
        p = subprocess.Popen([sys.executable, "-c", "import time; b = bytearray(64 << 20); time.sleep(0.6); del b; time.sleep(1.5)"])
        self.addCleanup(lambda: p.poll() is None and p.kill())
        pk = sample.TcpMemPeak(pids=[p.pid])
        with pk:
            p.wait()
        self.assertIsNotNone(pk.rss_max)
        self.assertGreater(pk.rss_max, 60)

    def test_group_pids_skips_wrappers(self):
        p = subprocess.Popen(["sh", "-c", "sleep 3 & wait"], start_new_session=True)
        self.addCleanup(lambda: (os.killpg(p.pid, signal.SIGKILL), p.wait()))
        time.sleep(0.3)
        pids = sample.group_pids(p.pid)
        names = []
        for x in pids:
            with open(f"/proc/{x}/comm") as f:
                names.append(f.read().strip())
        self.assertEqual(names, ["sleep"])

    def test_regress_peak_uses_the_samples(self):
        with tempfile.TemporaryDirectory() as d:
            r = regress.Run(types.SimpleNamespace(out=d, args="", base="/b", new="/n", base_args="", new_args="", wbench="/wb", dur=1, port_base=0,
                                                  reps=8, only="", verbose=False, own_scope=False, xh=None, cert=None, key=None, tls_ok=False))

            def run_ab(v, reps, argv, raw, **kw):
                with open(raw, "w") as f:
                    for rep in range(reps):
                        for name in ("base", "new"):
                            f.write(json.dumps({"v": name, "rep": rep, "mib_s_down": 100.0 + rep, "errors": 0, "cpu_pct": 100,
                                                "hwm_mib": 50.0, "rss_peak_mib": 10.0 + (rep if name == "new" else 0)}) + "\n")
            with mock.patch.object(regress.abmod, "run_ab", run_ab), mock.patch.object(regress, "tcp_pressure", lambda ns: 0):
                r.ab("download 1x1", "--test download", [("mib_s_down", True)])
            pk = r.rows[0]["peak_mib"]
            self.assertEqual(pk["source"], "rss_peak_mib")
            self.assertLess(pk["base"], 20)
            self.assertNotIn("(VmHWM)", regress.table(r.rows))


class Abfan(unittest.TestCase):
    def sess(self, sid, tmp=None):
        s = abfan.Session.__new__(abfan.Session)
        s.a = types.SimpleNamespace(owner="w", cells=None, exact_cells=False, set="core", followup="LOSS", followup_pairs=32, srv_args="", pairs=16,
                                    port=21500, tport=21501, dur="4", warmup="1", order=None, settle=None)
        s.name, s.sid, s.cands, s.bins, s.cells = "sess", sid, ["new1"], {}, abfan.SETS["core"]
        s.boxes, s.ids, s.dir = {"b1": {}}, {"base": "aaa", "new1": "bbb"}, tmp
        return s

    def test_lock_of_the_same_name_in_another_sessions_directory_is_not_adopted(self):
        a, b = self.sess("1111"), self.sess("2222")
        text = a.lock_text("b1", {"cells": ["x"], "pairs": 1})
        self.assertTrue(a.mine(text))
        self.assertFalse(b.mine(text))

    def test_table_only_compares_the_job(self):
        with tempfile.TemporaryDirectory() as t:
            s = self.sess("1111", t)
            os.makedirs(os.path.join(t, "b1"))
            json.dump(s.job("b1"), open(os.path.join(t, "b1", "job.local.json"), "w"))
            self.assertEqual(s.table_only_diff("b1"), [])
            s.a.pairs = 32
            s.ids = {"base": "aaa", "new1": "ccc"}
            self.assertEqual(s.table_only_diff("b1"), ["pairs", "ids"])


class RewrittenGroup(unittest.TestCase):
    def test_only_the_group(self):
        with tempfile.TemporaryDirectory() as t:
            f = os.path.join(t, "rw.txt")
            with open(f, "w") as fh:
                fh.write("# 60.77: old\nOld sentence one.\n#   comment\n# 60.78 G01: new\nNew sentence.\n")
            os.makedirs(os.path.join(t, "docs"))
            for group, want in ((None, 2), ("60.78", 1), ("60.76", 0)):
                probs = []
                doccheck.check_lost(t, [], None, [], f, probs, group)
                self.assertEqual(len(probs), want, (group, probs))



class LinkCell(unittest.TestCase):
    """60.78 G27: the hol cell of the full set: lower p99 latency is better, in abbox and in abfan's table."""
    def data(self, new):
        by = {}
        for i in range(16):
            w = 1 + 0.01 * (i % 5)
            by.setdefault("base", {})[i] = {"p99_us": 1000 * w}
            by.setdefault("bas2", {})[i] = {"p99_us": 1002 * w}
            by.setdefault("new1", {})[i] = {"p99_us": new * w}
        return by

    def test_sets_and_key(self):
        from wispsuite import wbench
        self.assertIn("hol:1:1", abfan.SETS["full"])
        self.assertNotIn("hol:1:1", abfan.SETS["core"])
        self.assertEqual([c for c in abfan.SETS["full"] if c.split(":")[0] not in wbench.LINK_CELLS], route.FULL)
        self.assertEqual([c for c in abfan.SETS["full"] if c.split(":")[0] in wbench.LINK_CELLS], route.LINK)
        self.assertIn("hol:1:1", route.route("CHANGED", Router().fp([".rodata"]))["skipped"])
        self.assertEqual(wbench.cell_key("hol"), ("p99_us", False))
        self.assertEqual(wbench.cell_key("rr"), ("rps", True))
        self.assertEqual(wbench.cell_key("upload"), ("mib_s_up", True))

    def test_lower_latency_reads_win_higher_reads_loss(self):
        job = {"base": "base", "copy": "bas2", "pairs": 16, "followup": None, "cand_copy": {"new1": "cpy1"}}
        self.assertEqual(abfan.read_cell(self.data(800), {}, "new1", job, "p99_us", False)["reading"], "WIN")
        self.assertEqual(abfan.read_cell(self.data(1250), {}, "new1", job, "p99_us", False)["reading"], "LOSS")
        self.assertEqual(abfan.read_cell(self.data(1250), {}, "new1", job, "p99_us")["reading"], "WIN")  # the old direction

    def test_abbox_verdicts_direction(self):
        import importlib.util
        from wispsuite import stats
        spec = importlib.util.spec_from_file_location("abbox", os.path.join(BENCH, "vps", "abbox.py"))
        abbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(abbox)
        v = abbox.verdicts(self.data(1250), [("new1/base", "base", "new1")], "p99_us", stats, False)
        self.assertEqual(v["new1/base"]["verdict"], "LOSS")

    def test_lock_minutes_use_the_link_cell_window(self):
        s = Abfan().sess("1111")
        self.assertEqual(s.lock_text("b1", {"cells": ["hol:1:1"], "pairs": 16}).split(" | ")[2], "33")  # 3 arms x 16 x (30 + 2 + 1.91) s

    def test_box_without_netns_reads_skipped_not_failed(self):
        """abbox: a link cell on a box without netns writes <tag>.skipped and the session ends DONE; abfan's table shows
        SKIPPED outside the verdict (status 0) and names the box."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("abbox", os.path.join(BENCH, "vps", "abbox.py"))
        abbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(abbox)
        self.assertEqual(abbox.netns_probe({"netns": False}), (False, "the boxes file says netns false"))
        with tempfile.TemporaryDirectory() as t:
            root = os.path.join(t, "sess")
            shutil.copytree(os.path.join(BENCH, "wispsuite"), os.path.join(root, "bench", "wispsuite"))
            for n in ("fw-base", "fw-bas2", "fw-new1", "wbench"):
                with open(os.path.join(root, n), "w") as f:
                    f.write("#!/bin/sh\n")
                os.chmod(os.path.join(root, n), 0o755)
            job = {"session": "s", "box": "b1", "root": root, "arms": {"base": "fw-base", "bas2": "fw-bas2", "new1": "fw-new1"},
                   "md5": {}, "args": "", "base": "base", "copy": "bas2", "cands": ["new1"], "cand_copy": {"new1": "cpy1"},
                   "cells": ["hol:1:1"], "pairs": 2, "port": 21590, "tport": 21591, "followup": None, "netns": False,
                   "marks": {"busy": 1.0, "steal": 1.0, "mem_avail_mb": 0, "tcp_mem_pages": 1 << 40, "strays": False}}
            abbox.check = lambda job, sample_s=0: {"clean": True, "why": []}
            cwd, path = os.getcwd(), list(sys.path)
            try:
                with mock.patch.object(abbox.resource, "setrlimit"):  # run() raises the open-file limit: not in this process
                    self.assertEqual(abbox.run(job), 0)
            finally:
                os.chdir(cwd)
                sys.path[:] = path
            self.assertTrue(os.path.exists(os.path.join(root, "DONE")))
            self.assertEqual(json.load(open(os.path.join(root, "DONE")))["skipped"], ["hol-1x1"])
            self.assertFalse(os.path.exists(os.path.join(root, "out", "hol-1x1.done")))
            # abfan's table of that box
            s = Abfan().sess("1111", t)
            s.cells, s.status = ["hol:1:1"], {"boxes": {"b1": {"state": "done"}}}
            s.mismatch = set()
            os.makedirs(os.path.join(t, "b1"))
            shutil.copytree(os.path.join(root, "out"), os.path.join(t, "b1", "out"))
            json.dump(dict(job, cells=["hol:1:1"]), open(os.path.join(t, "b1", "job.local.json"), "w"))
            rows, text, worst = s.table()
            self.assertEqual((rows, worst), ([], 0))
            self.assertIn("SKIPPED (no netns: the boxes file says netns false)", text)
            self.assertEqual(s.skipped, [("b1", "hol-1x1", "no netns: the boxes file says netns false")])
            # a later try that failed (the box fixed, then netns_hol.sh failed) is a fault, not SKIPPED
            fl = os.path.join(t, "b1", "out", "hol-1x1.failed")
            open(fl, "w").write("{}")
            st = os.stat(os.path.join(t, "b1", "out", "hol-1x1.skipped"))
            os.utime(fl, (st.st_mtime + 5, st.st_mtime + 5))
            rows, text, worst = s.table()
            self.assertEqual((s.skipped, worst), ([], 2))

    def test_hol_floor_turns_the_aa_win_into_a_tie(self):
        """the 30 s A/A on VPS1 (v1.3.3 vs itself): copy/base 0.996 WIN [0.992, 0.998] -> tie below hol's 1 % floor"""
        from wispsuite import wbench
        aa = {"ratio": 0.996, "ci90": [0.992, 0.998], "verdict": "WIN"}
        self.assertEqual(wbench.floored(aa, "hol")["verdict"], "tie (below the 1 % floor of hol)")
        self.assertEqual(wbench.floored(aa, "rr"), aa)  # every other cell unchanged
        self.assertEqual(wbench.floored(dict(aa, ratio=1.03, ci90=[1.02, 1.04], verdict="LOSS"), "hol")["verdict"], "LOSS")
        self.assertEqual(wbench.floored(dict(aa, ci90=[0.97, 1.0], verdict="watch"), "hol")["verdict"], "watch")  # wide interval

    def test_hol_floor_reaches_read_cell_and_abbox(self):
        import importlib.util
        from wispsuite import stats
        by = self.data(1005)  # +0.5 % against base, narrow interval: a raw LOSS
        job = {"base": "base", "copy": "bas2", "pairs": 16, "followup": None, "cand_copy": {"new1": "cpy1"}}
        self.assertEqual(abfan.read_cell(by, {}, "new1", job, "p99_us", False)["reading"], "LOSS")
        self.assertEqual(abfan.read_cell(by, {}, "new1", job, "p99_us", False, "hol")["reading"], "tie (below the 1 % floor of hol)")
        spec = importlib.util.spec_from_file_location("abbox", os.path.join(BENCH, "vps", "abbox.py"))
        abbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(abbox)
        v = abbox.verdicts(by, [("new1/base", "base", "new1")], "p99_us", stats, False, "hol")
        self.assertEqual(v["new1/base"]["verdict"], "tie (below the 1 % floor of hol)")


if __name__ == "__main__":
    unittest.main()
