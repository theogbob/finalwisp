#!/usr/bin/env python3
"""60.78 G59 E3: 60.63 T-e3-slow's one open cell on the candidate: a page of 70 streams (30 at once + 40,
one per 200 ms) from a host that answers only the 5th SYN, --dest-failfast on (and off as the control), another client
connected. In ONE VM (root): an nft table on lo drops the first NTH SYNs of every connection to the sink port (per
source port), as kit/synfix.sh did on the sink host. 60.63: the first rule refused 1 of 70 (single run), not repeated
on the final build. usage: e3five.py FINALWISP OUTDIR [--on 10] [--off 3] [--nth 4]"""
import asyncio, json, os, socket, subprocess, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispa import Wisp
a = sys.argv[1:]
def opt(k, d): return a[a.index(k) + 1] if k in a else d
BIN, OUT = os.path.abspath(a[0]), a[1]; os.makedirs(OUT, exist_ok=True)
NON, NOFF, NTH = int(opt("--on", "10")), int(opt("--off", "3")), int(opt("--nth", "4"))
BASE = 7400; REQ = bytes(64)
TXT = open(os.path.join(OUT, "e3five.txt"), "a")
def say(s): print(s, flush=True); TXT.write(s + "\n"); TXT.flush()

def sink(port):  # reply sink: answer every read with 64 bytes, keep the socket
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", port)); ls.listen(4096)
    def h(c):
        try:
            while c.recv(4096): c.sendall(bytes(64))
        except OSError: pass
    def run():
        while True:
            c, _ = ls.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()

def nft(port, n):
    sets = "".join(f"  set s{i} {{ type ipv4_addr . inet_service . inet_service; flags dynamic,timeout; timeout 30s; size 65535; }}\n" for i in range(1, n + 1))
    slow = f"    ip saddr . tcp sport . tcp dport @s{n} return\n" + "".join(
        f"    ip saddr . tcp sport . tcp dport @s{i} add @s{i + 1} {{ ip saddr . tcp sport . tcp dport }} drop\n" for i in range(n - 1, 0, -1)) \
        + "    add @s1 { ip saddr . tcp sport . tcp dport } drop\n"
    rules = (f"table inet fwe3 {{\n{sets}  chain in {{\n    type filter hook input priority -5; policy accept;\n"
             f"    iif \"lo\" tcp dport {port} tcp flags & (syn | ack) == syn jump slow\n  }}\n  chain slow {{\n{slow}  }}\n}}\n")
    subprocess.run(["nft", "delete", "table", "inet", "fwe3"], capture_output=True)
    r = subprocess.run(["nft", "-f", "-"], input=rules, text=True, capture_output=True)
    if r.returncode: raise SystemExit("nft: " + r.stderr)

async def page(sp):
    other = await Wisp().open("127.0.0.1", BASE, src="198.51.100.7")
    w = await Wisp().open("127.0.0.1", BASE, src="203.0.113.1")
    out = []; T0 = time.monotonic()
    async def one():
        t0 = time.monotonic(); sid = w.stream(sp); w.data(sid, REQ)
        k, v = await w.first(sid, 16)
        out.append({"sid": sid, "start": round(t0 - T0, 3), "s": round(time.monotonic() - t0, 3), "r": "answer" if k == "d" else ("close_0x%02x" % v if k == "c" else {"t": "timeout", "x": "lost"}[k])})
    tasks = [asyncio.create_task(one()) for _ in range(30)]
    for j in range(40):
        await asyncio.sleep(max(0, T0 + 0.2 * (j + 1) - time.monotonic())); tasks.append(asyncio.create_task(one()))
    await asyncio.gather(*tasks); w.close(); other.close()
    return out

say(f"CHECK INFO kernel {os.uname().release}; tcp_syn_linear_timeouts {open('/proc/sys/net/ipv4/tcp_syn_linear_timeouts').read().strip() if os.path.exists('/proc/sys/net/ipv4/tcp_syn_linear_timeouts') else 'n/a'}; the host answers SYN {NTH + 1}")
plan = [("on", i) for i in range(NON)]
for i in range(NOFF): plan.insert(1 + 3 * i, ("off", i))  # the control runs between the on runs
try:
    for k, (mode, i) in enumerate(plan):
        sp = 31000 + k; sink(sp); nft(sp, NTH)
        log = open(os.path.join(OUT, f"server-{k}-{mode}.log"), "w+")
        srv = subprocess.Popen([BIN, "--port", str(BASE), "--allow-loopback", "--proxy-protocol", "tcp", "--proxy-protocol-from", "127.0.0.0/8",
                                "--metrics-interval", "1"] + (["--dest-failfast"] if mode == "on" else []), stdout=log, stderr=subprocess.STDOUT)
        for _ in range(100):
            if "listening on" in open(log.name).read(): break
            time.sleep(0.1)
        time.sleep(0.5)
        out = asyncio.run(page(sp)); time.sleep(1.5)
        ml = [l for l in open(log.name) if "ev=metrics" in l][-1:]
        mx = {kv.split("=")[0]: kv.split("=")[1] for kv in (ml[0].split() if ml else []) if "=" in kv}
        srv.terminate(); rc = srv.wait(30)
        res = {}
        for o in out: res[o["r"]] = res.get(o["r"], 0) + 1
        ans = sorted(o["s"] for o in out if o["r"] == "answer")
        s = {"run": k, "mode": mode, "streams": len(out), "results": res, "answer_s": [ans[0], ans[len(ans) // 2], ans[-1]] if ans else None,
             "refuse_dest_dead": mx.get("refuse_dest_dead"), "dest_dead": mx.get("dest_dead"), "connect_timeout": mx.get("connect_timeout"), "rc": rc}
        json.dump(out, open(os.path.join(OUT, f"page-{k}-{mode}.json"), "w"))
        open(os.path.join(OUT, "e3five.jsonl"), "a").write(json.dumps(s) + "\n")
        say(f"CHECK INFO run {k} {mode}: {res}, seconds to the answer min/p50/max {s['answer_s']}, refuse_dest_dead {s['refuse_dest_dead']}, rc {rc}")
finally:
    subprocess.run(["nft", "delete", "table", "inet", "fwe3"], capture_output=True)
