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


# 60.78 G27: abfan / abbox cells that are not one plain wbench test on loopback. Cell "NAME:C:S" runs
# `wbench run --test TEST --conns C --streams S ARGS` from netns fwa to the servers in netns fws across the link of
# bench/vps/netns_hol.sh (RATE DELAY LIMIT; root, so VPS boxes only), with its own window (dur / warmup, seconds).
# A box that cannot make a network namespace (boxes file "netns": false, not root, or the probe NETNS_PROBE fails, e.g. a
# container without CAP_NET_ADMIN) reads the cell SKIPPED (no netns): never FAILED, never a loopback stand-in.
# Verdict on "key" (stats.py, "higher" = higher is better); "info" metrics are shown with their reading, no verdict.
# hol: head-of-line latency: one connection carries a bulk download and one small request/response stream; the
# requests' latency (p50 / p99) is what waits behind the bulk data (server write buffer, socket, link queue).
LINK_CELLS = {"hol": {"test": "browse", "args": ["--size", "64", "--resp", "64", "--reqs-per-stream", "1000000000", "--bulk", "1"],
                      "link": ["100mbit", "10ms", "200"], "dur": 30, "warmup": 2,  # 30 s: ~660 requests, so p99 is not the top 2-3 values
                      "key": "p99_us", "higher": False, "info": [["p50_us", False], ["bulk_mib_s", True]],
                      # p99 sits on the link ceiling (RTT + full netem queue, histogram steps ~0.2 %): the 30 s A/A on VPS1
                      # read copy/base 0.996 WIN [0.992, 0.998]; below 1 % a verdict of this cell means nothing
                      "min_effect": 0.01}}
NETNS_PROBE = ["unshare", "-n", "sh", "-c", "ip link set lo up && tc qdisc add dev lo root netem delay 1ms"]  # netns + netem
LINK_ENV = {"SRV_PREFIX": "ip netns exec fws", "CLI_PREFIX": "ip netns exec fwa", "SRV_HOST": "10.77.0.2", "SRV_BIND": "--host 10.77.0.2"}


def floored(c, test):
    """60.78 G27: the per-cell floor of a link cell (LINK_CELLS "min_effect" m) on one stats.compare result c: |ratio - 1| < m
    and the 90 % interval inside [1 - 2m, 1 + 2m] -> verdict "tie (below the 1 % floor of hol)". stats.py is unchanged;
    every other cell (no min_effect) gets c back as it is. On stats.compare's 3-decimal ratio: 0.990 / 1.010 are NOT below."""
    m = (LINK_CELLS.get(test) or {}).get("min_effect")
    if not m or not c or c.get("verdict") == "tie" or not c.get("ci90"):
        return c
    lo, hi = c["ci90"]
    if abs(c["ratio"] - 1) < m and 1 - 2 * m <= lo and hi <= 1 + 2 * m:
        return dict(c, verdict=f"tie (below the {m * 100:g} % floor of {test})", verdict_raw=c["verdict"])
    return c


def cell_key(test):
    """-> (key metric, higher is better) of an abfan cell's test name (a LINK_CELLS name or a wbench test)"""
    s = LINK_CELLS.get(test)
    return (s["key"], s["higher"]) if s else (key_metric(test), True)


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
