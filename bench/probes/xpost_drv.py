#!/usr/bin/env python3
"""60.44 real-path POST driver, run on the laptop (orchestration only, no timing here): per round and variant the
server variant starts on the server box (public address, port 27791; ack target on its 127.0.0.1:27790, started by
the caller), and post.py runs on the far client box over ssh. The caller opens the server port to the client IP only.
usage: xpost_drv.py OUT.jsonl "SRV_SSH" "CLI_SSH" SRV_IP VARIANTS.json ROUNDS [--reps 5] [--fresh] [--wbench "RUN ARGS" --tport P]
  --wbench: instead of post.py, one `wbench run --url ws://SRV_IP:27791/ --target 127.0.0.1:P RUN ARGS --json` per
  (round, variant) (wbench at /root/v11x-kmem/bench/target/release/wbench on the client; the caller starts the target)
  SSH args are whole ssh command prefixes, e.g. "ssh root@1.2.3.4" and "ssh -p 1280 root@host"; post.py must be at
  /root/v11x-kmem/bench/probes/post.py on the client."""
import json, shlex, subprocess, sys
a = sys.argv[1:]
fresh = "--fresh" in a
a = [x for x in a if x != "--fresh"]
reps = "5"
wb = tport = None
for o in ("--wbench", "--tport"):
    if o in a:
        i = a.index(o); v = a[i + 1]; del a[i:i + 2]
        wb, tport = (v, tport) if o == "--wbench" else (wb, v)
if "--reps" in a:
    i = a.index("--reps"); reps = a[i + 1]; del a[i:i + 2]
out, srv, cli, ip, var, rounds = a[0], shlex.split(a[1]), shlex.split(a[2]), a[3], json.load(open(a[4])), int(a[5])
names = list(var)
KILL = "pkill -f -- '[-]-port 27791 --host 0.0.0.0'; sleep 3; pkill -9 -f -- '[-]-port 27791 --host 0.0.0.0'; true"
f = open(out, "a")
for r in range(rounds):
    k = r % len(names)
    for name in names[k:] + names[:k]:
        # review: no leftover server may answer for this variant: kill first, then start, then require exactly
        # one listener process of this variant before measuring
        st = subprocess.run(srv + [f"{KILL}; cd /root/v11x-kmem && (setsid {var[name]} --port 27791 --host 0.0.0.0 > xsrv.log 2>&1 < /dev/null &) ; "
                                   f"sleep 0.8; pgrep -fc -- '[-]-port 27791 --host 0.0.0.0'"], capture_output=True, text=True)
        if st.stdout.strip().splitlines()[-1:] != ["1"]:
            f.write(json.dumps({"variant": name, "round": r, "error": f"server start: {st.stdout.strip()[-80:]}"}) + "\n"); f.flush()
            continue
        try:
            rc = (f"/root/v11x-kmem/bench/target/release/wbench run --url ws://{ip}:27791/ --target 127.0.0.1:{tport} {wb} --json" if wb else
                  f"python3 /root/v11x-kmem/bench/probes/post.py run --url ws://{ip}:27791/ --target 127.0.0.1:27790 --reps {reps} --warm 1 --limit 30 --budget 400" + (" --fresh" if fresh else ""))
            pr = subprocess.run(cli + [rc], capture_output=True, text=True, timeout=480)
            o = pr.stdout
            if pr.returncode != 0:
                f.write(json.dumps({"variant": name, "round": r, "error": f"rc {pr.returncode}", "stderr": pr.stderr[-300:]}) + "\n")
        except subprocess.TimeoutExpired as e:
            o = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")  # keep what finished
            f.write(json.dumps({"variant": name, "round": r, "error": "timeout"}) + "\n")
        for line in o.splitlines():
            try:
                j = json.loads(line)
            except ValueError:
                continue
            if wb and not isinstance(j, dict):
                continue
            if j.get("error") or not j.get("summary"):
                j.update(variant=name, round=r, fresh=fresh); f.write(json.dumps(j) + "\n")
        f.flush()
        subprocess.run(srv + [KILL])
        print(f"round {r} {name} done", flush=True)
