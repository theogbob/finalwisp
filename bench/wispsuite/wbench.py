"""wbench (bench/src, pointer 30.01) helpers: binary lookup, targets, one run -> parsed JSON (30.10)."""
import json, os, time
from . import proc

BENCH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_MODE = {"upload": "sink", "download": "source", "burstidle": "source", "browse": "reply", "udp-rr": "udp-echo"}  # else echo
RATE_TESTS = ("rr", "churn", "connchurn", "browse", "udp-rr")


def find(explicit=None):
    """wbench path: explicit, else $WBENCH (both used as given, never replaced by another binary), else
    bench/target/release/wbench, else ./wbench next to the suite (VPS copies). Exits if it is not executable."""
    given = explicit or os.environ.get("WBENCH")
    cands = [given] if given else [os.path.join(BENCH, "target/release/wbench"), os.path.join(BENCH, "wbench")]
    for p in cands:
        if os.access(p, os.X_OK):
            return os.path.abspath(p)
    raise SystemExit(f"wbench not found or not executable: {cands[0]} (cd bench && cargo build --release, or --wbench / $WBENCH)")


def target_mode(test):
    return TARGET_MODE.get(test, "echo")


def key_metric(test):
    return "rps" if test in RATE_TESTS else ("mib_s_up" if test == "upload" else "mib_s_down")


def start_target(wb, port, mode, prefix=(), log=None, extra=(), wait=True):
    """Start `wbench target`; waits for the port (wait=True, TCP modes, host namespace) or 0.3 s otherwise."""
    p = proc.spawn([*prefix, wb, "target", "--port", str(port), "--mode", mode, *extra], log=log)
    if wait and mode != "udp-echo":
        bind = extra[list(extra).index("--bind") + 1] if "--bind" in extra else "127.0.0.1"
        if not proc.wait_port(port, 5, p, host=bind):
            proc.stop(p, 0)
            raise RuntimeError(f"wbench target {mode} did not start on :{port}")
    else:
        time.sleep(0.3)
    return p


def parse_last_json(text):
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                return None
    return None


STDERR_PREFIXES = ("wbench error:", "run:", "target:", "debug:")  # wbench eprintln! lines


def run(wb, args, timeout, prefix=(), ssh=None):
    """One `wbench run ... --json` in its own registered process group (on the host `ssh` when given, cross-host
    mode). Returns the result dict, or {"error": ...} (never raises for a failed run)."""
    if ssh:
        from . import xhost
        rc, out, err = proc.run(xhost.wbench_cmd(ssh, wb, args, timeout), timeout=timeout + 15)
    else:
        rc, out, err = proc.run([*prefix, wb, "run", *[str(a) for a in args], "--json"], timeout=timeout)
    if rc is None:
        return {"error": f"wbench timed out after {timeout:.0f}s"}
    j = parse_last_json(out)
    if j is None:
        return {"error": f"no JSON from wbench (exit {rc}): {((err or '') + (out or '')).strip()[-300:]}"}
    if ssh:  # the pty merges wbench's stderr into stdout: keep only its stderr lines (src/run.rs, src/main.rs
        # eprintln! prefixes), not the human summary on stdout ("... errors=0 ...")
        err = "\n".join(l for l in (out or "").splitlines() if l.strip().startswith(STDERR_PREFIXES))
    if err and err.strip():
        j["stderr"] = err.strip()[:500]
    return j
