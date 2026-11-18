#!/usr/bin/env python3
"""60.78 G10 (sb-robust): the --port-share help sentence "without it connects slow down past half of the ports", as a
paired off/on cell in ONE VM (root; it writes net.ipv4.ip_local_port_range of THAT VM and puts it back).
usage: portshare.py FINALWISP OUTDIR [--rounds off,on,on,off] [--lo 40000] [--hi 48191] [--fill 7168] [--clients 16] [--rate 300]
Per round: a fresh server (bare + --allow-loopback + PROXY protocol from loopback; "on" adds --port-share), a holder
target on a fresh loopback port (accepts, answers the first bytes once, keeps the socket), CLIENTS Wisp connections with
public client addresses (PROXY v1; no client holds near half, so the share rules never refuse), streams opened at RATE
per second up to FILL target sockets toward that one destination. Per stream: seconds from CONNECT+DATA to the first
answer (or the failure). At 0, 1/4, 1/2, 3/4 of the range and at FILL: the server's CPU ticks (utime, stime) and the
parity of the source ports of its target sockets (without the option the kernel takes the even ports first; with
IP_LOCAL_PORT_RANGE it searches with step 1). Counts are the claim; seconds in a VM on a shared host are INFO."""
import asyncio, json, os, resource, signal, socket, subprocess, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wispa import Wisp

a = sys.argv[1:]
def opt(k, d): return a[a.index(k) + 1] if k in a else d
if a and a[0] == "--holder":  # the target: accept, answer once, keep; SIGUSR1 closes every socket (so TIME_WAIT is here)
    try: resource.setrlimit(resource.RLIMIT_NOFILE, (200000, 200000))
    except (ValueError, OSError): resource.setrlimit(resource.RLIMIT_NOFILE, (resource.getrlimit(resource.RLIMIT_NOFILE)[1],) * 2)
    port = int(a[1]); keep = []
    async def h(r, w):
        keep.append(w)
        try:
            await r.read(64); w.write(b"ok" * 4); await w.drain(); await r.read()  # until the peer closes
        except Exception: pass
    async def main():
        srv = await asyncio.start_server(h, "127.0.0.1", port, backlog=4096)
        ev = asyncio.Event(); asyncio.get_running_loop().add_signal_handler(signal.SIGUSR1, ev.set)
        await ev.wait()
        for w in keep: w.close()
        await asyncio.sleep(2)
    asyncio.run(main()); sys.exit(0)

BIN, OUT = os.path.abspath(a[0]), a[1]; os.makedirs(OUT, exist_ok=True)
ROUNDS = opt("--rounds", "off,on,on,off").split(","); LO, HI = int(opt("--lo", "40000")), int(opt("--hi", "48191"))
FILL, NCL, RATE = int(opt("--fill", "7168")), int(opt("--clients", "16")), float(opt("--rate", "300"))
RANGE = HI - LO + 1; BASE = 7300
try: resource.setrlimit(resource.RLIMIT_NOFILE, (200000, 200000))
except (ValueError, OSError): resource.setrlimit(resource.RLIMIT_NOFILE, (resource.getrlimit(resource.RLIMIT_NOFILE)[1],) * 2)
PR = "/proc/sys/net/ipv4/ip_local_port_range"; old_range = open(PR).read().split()
TXT = open(os.path.join(OUT, "portshare.txt"), "a")
def say(s): print(s, flush=True); TXT.write(s + "\n"); TXT.flush()

def ticks(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]), int(f[12])  # utime, stime (clock ticks)
def ports_to(tp):
    out = subprocess.run(["ss", "-tnH", "state", "established", f"( dport = :{tp} )"], capture_output=True, text=True).stdout
    ps = [int(l.split()[2].rsplit(":", 1)[1]) for l in out.splitlines() if l.strip()]
    return len(ps), sum(p % 2 == 0 for p in ps)
def tw():
    return len(subprocess.run(["ss", "-tanH", "state", "time-wait"], capture_output=True, text=True).stdout.splitlines())

async def ramp(srv_pid, tp, mode):
    ws = [await Wisp().open("127.0.0.1", BASE, src=f"203.0.113.{10 + k}") for k in range(NCL)]
    marks = sorted({0, RANGE // 4, RANGE // 2, 3 * RANGE // 4, FILL}); snaps = []; res = []; tasks = []
    async def one(i, w):
        t0 = time.monotonic(); sid = w.stream(tp); w.data(sid, b"hello123")
        k, v = await w.first(sid, 15)
        res.append({"i": i, "t": round(t0 - T0, 3), "s": round(time.monotonic() - t0, 5), "r": "ok" if k == "d" else f"{k}:{v}"})
    T0 = time.monotonic(); off = 0.0  # off: the time spent at the marks moves the schedule (no catch-up burst)
    for i in range(FILL + 1):
        if i in marks:
            m0 = time.monotonic()
            await asyncio.sleep(0.5 if i else 0)
            n, ev = await asyncio.get_running_loop().run_in_executor(None, ports_to, tp)
            snaps.append({"issued": i, "held": n, "even": ev, "odd": n - ev, "ticks": ticks(srv_pid), "t": round(time.monotonic() - T0, 2)})
            off += time.monotonic() - m0
        if i == FILL: break
        await asyncio.sleep(max(0, T0 + off + i / RATE - time.monotonic()))
        tasks.append(asyncio.create_task(one(i, ws[i % NCL])))
    await asyncio.gather(*tasks)
    n, ev = ports_to(tp); snaps.append({"issued": FILL, "held": n, "even": ev, "odd": n - ev, "ticks": ticks(srv_pid), "t": round(time.monotonic() - T0, 2), "end": True})
    return ws, snaps, sorted(res, key=lambda r: r["i"])

def pct(xs, q):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None

summary = []
try:
    open(PR, "w").write(f"{LO} {HI}")
    say(f"CHECK INFO kernel {os.uname().release}; ip_local_port_range {open(PR).read().strip()} ({RANGE} ports); fill {FILL}; {NCL} clients; {RATE:g} streams/s; rounds {ROUNDS}")
    for ri, mode in enumerate(ROUNDS):
        tp = 30100 + ri
        while tw() > 200: time.sleep(2)
        hold = subprocess.Popen([sys.executable, os.path.abspath(__file__), "--holder", str(tp)])
        log = open(os.path.join(OUT, f"server-{ri}-{mode}.log"), "w+")
        args = [BIN, "--port", str(BASE), "--allow-loopback", "--proxy-protocol", "tcp", "--proxy-protocol-from", "127.0.0.0/8",
                "--metrics-interval", "1"] + (["--port-share"] if mode == "on" else [])
        srv = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        for _ in range(100):
            if "listening on" in open(log.name).read(): break
            time.sleep(0.1)
        time.sleep(0.5)
        ws, snaps, res = asyncio.run(ramp(srv.pid, tp, mode))
        time.sleep(2.5)
        mline = [l for l in open(log.name) if "ev=metrics" in l][-1:]
        mx = {kv.split("=")[0]: kv.split("=")[1] for kv in (mline[0].split() if mline else []) if "=" in kv}
        hold.send_signal(signal.SIGUSR1); time.sleep(3)
        for w in ws: w.close()
        srv.terminate(); rc = srv.wait(30); hold.wait(30)
        json.dump(res, open(os.path.join(OUT, f"streams-{ri}-{mode}.json"), "w"))
        rows = []
        for (s0, s1) in zip(snaps, snaps[1:]):
            if s1["issued"] == s0["issued"]: continue
            seg = [r for r in res if s0["issued"] <= r["i"] < s1["issued"]]
            lat = [r["s"] for r in seg if r["r"] == "ok"]
            cpu = (s1["ticks"][0] + s1["ticks"][1] - s0["ticks"][0] - s0["ticks"][1]) * 1000 / os.sysconf("SC_CLK_TCK")
            rows.append({"from": s0["issued"], "to": s1["issued"], "streams": len(seg), "fail": len(seg) - len(lat),
                         "sys_ms": (s1["ticks"][1] - s0["ticks"][1]) * 1000 / os.sysconf("SC_CLK_TCK"), "cpu_ms_per_1000": round(cpu * 1000 / max(1, len(seg)), 1),
                         "p50_ms": round(1000 * pct(lat, .5), 2) if lat else None, "p99_ms": round(1000 * pct(lat, .99), 2) if lat else None,
                         "max_ms": round(1000 * max(lat), 2) if lat else None, "odd_at_end": s1["odd"], "even_at_end": s1["even"]})
        s = {"round": ri, "mode": mode, "rc": rc, "streams": len(res), "ok": sum(r["r"] == "ok" for r in res),
             "fail": {k: sum(r["r"] == k for r in res) for k in sorted({r["r"] for r in res}) if k != "ok"}, "phases": rows, "snaps": snaps,
             "metrics": {k: mx.get(k) for k in ("port_dest_max", "refuse_port_share", "refuse_port_full", "connect_fail", "connect_timeout")},
             "start_lines": [l.strip()[:300] for l in open(log.name) if "port" in l and "ev=metrics" not in l][:4]}
        summary.append(s); open(os.path.join(OUT, "portshare.jsonl"), "a").write(json.dumps(s) + "\n")
        say(f"CHECK INFO round {ri} {mode}: {s['ok']}/{s['streams']} ok, fail {s['fail']}, rc {rc}, metrics {s['metrics']}")
        for r in rows: say(f"CHECK INFO   {mode} streams {r['from']}-{r['to']}: cpu {r['cpu_ms_per_1000']} ms/1000 streams, p50 {r['p50_ms']} ms, p99 {r['p99_ms']} ms, fail {r['fail']}, ports odd/even at the end {r['odd_at_end']}/{r['even_at_end']}")
finally:
    open(PR, "w").write(" ".join(old_range))
    say(f"CHECK INFO restored ip_local_port_range {open(PR).read().strip()}")
