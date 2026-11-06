"""30.13 accounting regressions. Run: cd bench && python3 -m unittest discover -s tests -v."""
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wispsuite import idle, sample, showdown


class ShowdownCpuTests(unittest.TestCase):
    def run_case(self, exit_in_scan=False):
        clock = SimpleNamespace(now=0.0, ended=False)
        def sleep(dt):
            clock.now += dt
        cp = SimpleNamespace(pid=20, stdout=io.StringIO('{"mib_s_down": 1, "errors": 0}\n'))
        cp.poll = lambda: 0 if clock.ended or clock.now >= 2 else None
        sp = SimpleNamespace(pid=10, poll=lambda: None)
        def usage(pid):
            if pid == 20:
                if exit_in_scan and clock.now >= 1.75:
                    clock.ended = True
                return (0.0 if cp.poll() is not None else 2 * clock.now), 0
            return clock.now, 1048576
        srv = SimpleNamespace(name="fake", extra=[], start=lambda *a: sp)
        args = SimpleNamespace(wbench="fake-wbench", duration=1)
        output = io.StringIO()
        with patch.object(showdown.proc, "wait_free", return_value=True), \
             patch.object(showdown.proc, "spawn", return_value=cp), \
             patch.object(showdown.proc, "stop"), \
             patch.object(showdown, "group_usage", side_effect=usage), \
             patch.object(showdown.time, "sleep", side_effect=sleep), \
             patch.object(showdown.time, "time", side_effect=lambda: clock.now), \
             patch.object(showdown.time, "monotonic", side_effect=lambda: clock.now), \
             patch.object(showdown.sys, "stdout", output):
            result = showdown.run_case(srv, showdown.KEY_CASES[0], 6000, {"source": 6001}, args)
        return result, output.getvalue()

    def test_exit_during_sleep_keeps_last_live_cpu(self):
        result, output = self.run_case()
        self.assertAlmostEqual(result["client_cores"], 2.0)
        self.assertNotIn("-", output)

    def test_exit_during_proc_scan_keeps_last_live_cpu(self):
        result, output = self.run_case(exit_in_scan=True)
        self.assertAlmostEqual(result["client_cores"], 2.0)
        self.assertNotIn("-", output)


class SessionUsageTests(unittest.TestCase):
    def test_nested_process_groups_are_included_once(self):
        def stat(pgid, sid, state="S"):
            fields = ["0"] * 22
            fields[0], fields[2], fields[3] = state, str(pgid), str(sid)
            fields[11], fields[12], fields[21] = str(sample.HZ), "0", "1"
            return "1 (a name) " + " ".join(fields)
        stats = {"1": stat(10, 10), "2": stat(20, 10), "3": stat(30, 30), "4": stat(10, 10, "Z")}
        def read(path):
            pid = path.split("/")[2]
            return io.StringIO(stats[pid] if path.endswith("/stat") else "Name:\tserver\nVmHWM:\t4 kB\n")
        with patch.object(sample.os, "listdir", return_value=list(stats)), patch("builtins.open", side_effect=read):
            cpu, rss, hwm = sample.group_usage(10)
        self.assertEqual(cpu, 2.0)
        self.assertEqual(rss, 2 * sample.PAGE / sample.MIB)
        self.assertEqual(hwm, 8 / 1024)

    def test_rss_prefers_vmrss_over_stat(self):
        def stat(pgid):
            fields = ["0"] * 22
            fields[0], fields[2], fields[3], fields[21] = "S", str(pgid), str(pgid), "1000"
            return "1 (a name) " + " ".join(fields)
        stats = {"1": stat(10), "2": stat(10)}
        status = {"1": "Name:\tserver\nVmHWM:\t4 kB\nVmRSS:\t2048 kB\n", "2": "Name:\tkworker\n"}  # 2: no VmRSS
        def read(path):
            pid = path.split("/")[2]
            return io.StringIO(stats[pid] if path.endswith("/stat") else status[pid])
        with patch.object(sample.os, "listdir", return_value=list(stats)), patch("builtins.open", side_effect=read):
            _, rss, _ = sample.group_usage(10)
        self.assertEqual(rss, 2 + 1000 * sample.PAGE / sample.MIB)  # 1: VmRSS 2 MiB; 2: stat fallback

    def test_rss_keeps_stat_when_status_is_gone(self):
        def stat(pgid):
            fields = ["0"] * 22
            fields[0], fields[2], fields[3], fields[11], fields[21] = "S", str(pgid), str(pgid), str(sample.HZ), "1000"
            return "1 (a name) " + " ".join(fields)
        stats = {"1": stat(10), "2": stat(10)}
        def read(path):
            pid = path.split("/")[2]
            if path.endswith("/stat"):
                return io.StringIO(stats[pid])
            if pid == "2":
                raise FileNotFoundError(path)  # exited between the stat and status reads
            return io.StringIO("Name:\tserver\nVmRSS:\t2048 kB\n")
        with patch.object(sample.os, "listdir", return_value=list(stats)), patch("builtins.open", side_effect=read):
            cpu, rss, _ = sample.group_usage(10)
        self.assertEqual(cpu, 2.0)
        self.assertEqual(rss, 2 + 1000 * sample.PAGE / sample.MIB)


class IdleScopeTests(unittest.TestCase):
    def test_pid_probe_is_backwards_compatible(self):
        self.assertNotIn("--group", idle.probe_cmd(1, 2, 3, 4))

    def test_suite_can_request_session_sampling(self):
        self.assertIn("--group", idle.probe_cmd(1, 2, 3, 4, group=True))

    def test_dead_session_is_failure_not_memory_win(self):
        with patch("wispsuite.sample.group_usage", return_value=(0, 0, 0)):
            with self.assertRaises(ProcessLookupError):
                idle.rss(123, group=True)

    def test_session_rss_uses_all_processes(self):
        with patch("wispsuite.sample.group_usage", return_value=(1, 24, 30)) as usage:
            self.assertEqual(idle.rss(123, group=True), 24)
            usage.assert_called_once_with(123)


if __name__ == "__main__":
    unittest.main()
