#!/usr/bin/env python3
"""60.44 POST probe driver over a netns link (root; bench/vps/netns_hol.sh): server + ack target in fws, post.py in fwa.
usage: post_drv.py OUT.jsonl VARIANTS.json ROUNDS DELAY_MS... [--rate 1gbit] [--reps 5] [--sizes ...] [--fresh]
The ack target listens on 127.0.0.1 inside fws (as `wst link ab`): the server's own address 10.77.0.2 is a blocked
destination (own addresses, --allow-self), which is what made the first version wait forever on credit of a refused
stream. Per delay: link up; ROUNDS rounds, variant order rotated per round; per (round, variant) one server process and
`post.py run --reps N --warm 1`; every request line is appended to OUT with variant/delay/round."""
import json, os, signal, subprocess, sys, time
here = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
def opt(name, default):
    if name in args:
        i = args.index(name); v = args[i + 1]; del args[i:i + 2]; return v
    return default
rate, reps, sizes = opt("--rate", "1gbit"), opt("--reps", "5"), opt("--sizes", "65536,262144,1048576,4194304")
fresh = "--fresh" in args
if fresh: args.remove("--fresh")
out, var, rounds, delays = args[0], json.load(open(args[1])), int(args[2]), args[3:]
NS = os.path.join(here, "..", "vps", "netns_hol.sh")
PORT, TPORT = 27791, 27790
names = list(var)


def stop(p):
    """SIGTERM, then SIGKILL after 3 s (finalwisp drains open connections for up to 30 s on SIGTERM)"""
    try:
        os.killpg(p.pid, signal.SIGTERM)
        time.sleep(3)  # the group, not only the shell: finalwisp itself may still drain after the shell exited
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    p.wait()
f = open(out, "a")
LIVE = []  # review: servers/targets run in their own sessions; stop them in the finally (SIGTERM -> SystemExit)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
try:
    for d in delays:
        subprocess.run(["bash", NS, rate, f"{d}ms", "10000"], check=True, capture_output=True)
        tg = subprocess.Popen(["ip", "netns", "exec", "fws", "python3", os.path.join(here, "post.py"), "target", "--port", str(TPORT), "--bind", "127.0.0.1"],
                              start_new_session=True)
        LIVE.append(tg)
        time.sleep(0.5)
        for r in range(rounds):
            k = r % len(names)
            for name in names[k:] + names[:k]:
                srv = subprocess.Popen(f"ip netns exec fws {var[name]} --port {PORT} --host 10.77.0.2 --allow-private",
                                       shell=True, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                LIVE.append(srv)
                time.sleep(0.6)
                cmd = ["ip", "netns", "exec", "fwa", "python3", os.path.join(here, "post.py"), "run", "--url", f"ws://10.77.0.2:{PORT}/",
                       "--target", f"127.0.0.1:{TPORT}", "--reps", reps, "--warm", "1", "--sizes", sizes, "--limit", "20", "--budget", "240"] + (["--fresh"] if fresh else [])
                try:
                    pr = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    o = pr.stdout
                    if pr.returncode != 0:
                        f.write(json.dumps({"variant": name, "delay_ms": int(d), "round": r, "error": f"rc {pr.returncode}", "stderr": pr.stderr[-300:]}) + "\n")
                except subprocess.TimeoutExpired as e:
                    o = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")  # keep what finished
                    f.write(json.dumps({"variant": name, "delay_ms": int(d), "round": r, "error": "timeout"}) + "\n")
                for line in o.splitlines():
                    try:
                        j = json.loads(line)
                    except ValueError:
                        continue
                    if j.get("error") or not j.get("summary"):
                        j.update(variant=name, delay_ms=int(d), round=r, fresh=fresh)
                        f.write(json.dumps(j) + "\n")
                f.flush()
                stop(srv)
                print(f"delay {d} round {r} {name} done", flush=True)
        stop(tg)
finally:
    for p in LIVE:
        if p.poll() is None:
            stop(p)
    subprocess.run(["bash", NS, "down"], capture_output=True)
