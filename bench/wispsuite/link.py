"""Rate/delay-limited netns link A/B (30.10; root only; the regress link suite uses the same pieces).

usage: wst link up [RATE=100mbit] [DELAY=10ms] [LIMIT=200]     (fwa 10.77.0.1 <-> fws 10.77.0.2, netem each way)
       wst link down
       wst link ab VARIANTS.json REPS --rate R --delay D [--limit L] WBENCH-RUN-ARGS...
  ab: brings the link up, runs `wst ab` with the server + target in fws and wbench in fwa (variants get
  --allow-private --host 10.77.0.2 appended), prints the per-variant summary, takes the link down again (also on
  SIGTERM / Ctrl-C). DELAY is one way (RTT = 2 x DELAY). LIMIT: netem queue in packets (1 Gbit x 40 ms RTT needs
  ~3500; the regress link suite uses 10000 at 1 Gbit, 200 at 100 Mbit).
Only network namespaces change: the host network is untouched.
"""
import contextlib, json, os, subprocess, sys
from . import ab as abmod, proc, wbench

BENCH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = {"SRV_PREFIX": "ip netns exec fws", "CLI_PREFIX": "ip netns exec fwa", "SRV_HOST": "10.77.0.2",
       "SRV_BIND": "--host 10.77.0.2"}


def script():
    for p in (os.path.join(BENCH, "vps", "netns_hol.sh"), os.path.join(BENCH, "netns_hol.sh")):
        if os.path.exists(p):
            return p
    sys.exit("link: netns_hol.sh not found (bench/vps/)")


@contextlib.contextmanager
def link(rate, delay, limit="200"):
    try:  # a setup that fails half-way (or is interrupted) is torn down too
        subprocess.run(["bash", script(), rate, delay, str(limit)], check=True, capture_output=True)
        yield ENV
    finally:
        subprocess.run(["bash", script(), "down"], capture_output=True)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__); sys.exit(0)
    if os.geteuid() != 0:
        sys.exit("link: needs root (network namespaces)")
    if argv[0] == "down":
        sys.exit(subprocess.run(["bash", script(), "down"]).returncode)
    if argv[0] == "up":
        sys.exit(subprocess.run(["bash", script(), *argv[1:]]).returncode)
    if argv[0] != "ab" or len(argv) < 3:
        sys.exit("usage: wst link up|down|ab ... (wst link --help)")
    variants = json.load(open(argv[1])); reps = int(argv[2]); rest = argv[3:]
    o = {"--rate": "100mbit", "--delay": "10ms", "--limit": "200", "--raw": None, "--dur": "4"}
    extra, i = [], 0
    while i < len(rest):
        if rest[i] in o and i + 1 < len(rest):
            o[rest[i]] = rest[i + 1]; i += 2
        else:
            extra.append(rest[i]); i += 1
    v = {k: c.removeprefix("exec ") + " --allow-private" for k, c in variants.items()}  # `ip netns exec` cannot run `exec`
    proc.install_handlers()
    with link(o["--rate"], o["--delay"], o["--limit"]) as env:
        res = abmod.run_ab(v, reps, extra, wb=wbench.find(), dur=o["--dur"], raw=o["--raw"], link=f"{o['--rate']}/{o['--delay']}",
                           srv_prefix=env["SRV_PREFIX"].split(), cli_prefix=env["CLI_PREFIX"].split(),
                           srv_host=env["SRV_HOST"], srv_bind=env["SRV_BIND"])
    for line in abmod.summarize(extra[extra.index("--test") + 1], res):
        print(json.dumps(line), flush=True)
