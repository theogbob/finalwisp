#!/usr/bin/env python3
"""campaign.py: a restarted driver must not overwrite the lane logs of an earlier start (70.27 lesson).
Run: python3 -m unittest server/fuzz/test_campaign.py (needs bwrap with unprivileged user namespaces; else skipped)."""
import json, os, shutil, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE = "#!/bin/sh\necho fake-target pid $$\nexit 0\n"  # a "fuzz target" that runs once and exits 0


def bwrap_ok():
    if not shutil.which("bwrap"):
        return False
    try:
        r = subprocess.run(["bwrap", "--unshare-net", "--die-with-parent", "--dev-bind", "/", "/", "true"],
                           capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


@unittest.skipUnless(bwrap_ok(), "bwrap --unshare-net not available")
class RestartKeepsLogs(unittest.TestCase):
    def test_two_driver_starts_keep_both_lane_logs(self):
        d = tempfile.mkdtemp(prefix="campaign-test-")
        try:
            shutil.copy(os.path.join(HERE, "campaign.py"), d)
            bindir = os.path.join(d, "target/x86_64-unknown-linux-gnu/release")
            os.makedirs(bindir)
            os.makedirs(os.path.join(d, "logs"))
            fake = os.path.join(bindir, "fake")
            with open(fake, "w") as f:
                f.write(FAKE)
            os.chmod(fake, 0o755)
            plan = os.path.join(d, "plan.json")
            with open(plan, "w") as f:
                json.dump({"lanes": [[{"target": "fake", "secs": 5, "max_len": 64}]]}, f)
            for _ in range(2):  # the same plan twice, as the 04:11Z restart did
                r = subprocess.run([sys.executable, os.path.join(d, "campaign.py"), plan], cwd=d, timeout=60,
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
            logs = sorted(x for x in os.listdir(os.path.join(d, "logs")) if x.startswith("fake-lane0-0."))
            self.assertEqual(len(logs), 2, logs)
            for x in logs:
                with open(os.path.join(d, "logs", x)) as f:
                    self.assertIn("fake-target pid", f.read(), x)
            with open(os.path.join(d, "logs/campaign.jsonl")) as f:
                ev = [json.loads(l) for l in f]
            runs = [e["run"] for e in ev if e["ev"] == "driver"]
            self.assertEqual(len(set(runs)), 2, runs)
            self.assertEqual(sorted(e["log"] for e in ev if e["ev"] == "start"), ["logs/" + x for x in logs])
        finally:
            shutil.rmtree(d)  # (a temp dir this test created)


if __name__ == "__main__":
    unittest.main()
