#!/usr/bin/env python3
"""40.10 20.26 memory budget, functional: under a cgroup v2 memory limit the server slows down
instead of being OOM-killed.

usage: membudget.py BIN [--base-port P (uses P..P+34 with up to 8 rounds)] [--wbench PATH] [--master BIN] [--mems 32M,64M]

Runs the server in a user systemd scope (systemd-run --user --scope, MemoryMax=M, MemorySwapMax=0,
CPUQuota=100%, --threads 1) and checks for every M:
  1 download 10x10 for 5 s from `wbench target --mode source`: server alive, memory.events
    oom_kill == 0, wbench errors == 0 and 10/10 connections ok (throughput may be lower);
  2 hostile upload on the same server: 10 connections x 20 upload streams to a sink that does not
    read for 4 s: server alive, oom_kill == 0 (streams may be refused or closed with 0x49);
  3 recovery on the same server: the sink drains, then download 10x10 for 2 s with no errors;
then once at 256M (level 0):
  4 backlog fairness: client X fills the upload backlog to a paused sink (2 streams, 384 KiB frames),
    client Y uploads to a draining sink at the same time: Y keeps flowing (> 50 MiB/s, no errors).
--master BIN runs check 1 also on another binary and reports (informational) whether it was
OOM-killed: the reproduction of the bug. Exit 0 = all checks passed, 1 = a failure, 77 = skipped
(no user systemd or no delegated memory controller).
"""
import json, os, socket, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
if not args or args[0].startswith("-"):
    print(__doc__)
    sys.exit(2)
BIN = os.path.abspath(args[0])
opt = {"--base-port": "7860", "--wbench": os.path.join(HERE, "../../bench/target/release/wbench"), "--master": "", "--mems": "32M,64M"}
i = 1
while i < len(args):
    if args[i] in opt and i + 1 < len(args):
        opt[args[i]] = args[i + 1]
        i += 2
    else:
        print("unknown argument", args[i])
        sys.exit(2)
BASE = int(opt["--base-port"])
WB = os.path.abspath(opt["--wbench"])
UID = os.getuid()
CG = f"/sys/fs/cgroup/user.slice/user-{UID}.slice/user@{UID}.service/app.slice/"
fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail else ""), flush=True)
    if not ok:
        fails.append(name)


def scope_files(unit):
    d = CG + unit + ".scope/"
    try:
        ev = dict(l.split() for l in open(d + "memory.events"))
        peak = int(open(d + "memory.peak").read()) >> 20 if os.path.exists(d + "memory.peak") else -1
        return {k: int(v) for k, v in ev.items()}, peak
    except OSError:
        return None, -1


class Server:
    def __init__(self, binary, port, mem, unit):
        self.unit, self.port = unit, port
        cmd = ["systemd-run", "--user", "--scope", "-q", f"--unit={unit}", "-p", f"MemoryMax={mem}", "-p", "MemorySwapMax=0",
               "-p", "CPUQuota=100%", binary, "--port", str(port), "--allow-loopback", "--threads", "1"]
        self.log = open(f"/tmp/membudget-{unit}.log", "w+")
        self.p = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"server on {port} did not start: {self.text()}")

    def alive(self):
        return self.p.poll() is None

    def text(self):
        self.log.flush()
        self.log.seek(0)
        return self.log.read()

    def stop(self):
        if self.alive():
            self.p.terminate()
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.kill()
        subprocess.run(["systemctl", "--user", "stop", self.unit + ".scope"], capture_output=True)


def wbench(port, tport, test, conns, streams, dur, size=0):
    cmd = [WB, "run", "--url", f"ws://127.0.0.1:{port}/", "--target", f"127.0.0.1:{tport}", "--conns", str(conns),
           "--streams", str(streams), "--test", test, "--duration", str(dur), "--warmup", "0", "--json"]
    if size:
        cmd += ["--size", str(size)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=dur + 60)
    for line in r.stdout.splitlines():
        if line.startswith("{"):
            return json.loads(line)
    return {"errors": -1, "conns_ok": 0, "mib_s_down": 0, "mib_s_up": 0, "raw": (r.stdout + r.stderr)[-300:]}


class PausedSink:
    """TCP sink that accepts but does not read until release(); then reads everything."""

    def __init__(self, port):
        self.go = threading.Event()
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", port))
        self.ls.listen(1024)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                s, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self.drain, args=(s,), daemon=True).start()

    def drain(self, s):
        self.go.wait()
        try:
            while s.recv(1 << 20):
                pass
        except OSError:
            pass
        s.close()

    def release(self):
        self.go.set()

    def close(self):
        try:
            self.ls.shutdown(socket.SHUT_RDWR)  # wakes the accept() thread; close() alone keeps the port
        except OSError:
            pass
        self.ls.close()


def preflight():
    if not os.path.exists(WB):
        print("SKIP: wbench not found at", WB)
        sys.exit(77)
    unit = f"fwmb-probe-{os.getpid()}"
    r = subprocess.run(["systemd-run", "--user", "--scope", "-q", f"--unit={unit}", "-p", "MemoryMax=64M", "sh", "-c",
                        f"cat {CG}{unit}.scope/memory.max"], capture_output=True, text=True)
    if r.returncode != 0 or r.stdout.strip() != str(64 << 20):
        print("SKIP: no user systemd scope with a memory limit:", (r.stdout + r.stderr).strip()[:200])
        sys.exit(77)


def main():
    preflight()
    global drain_port
    src_port, drain_port = BASE, BASE + 1
    src = subprocess.Popen([WB, "target", "--port", str(src_port), "--mode", "source", "--threads", "2"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    drain = subprocess.Popen([WB, "target", "--port", str(drain_port), "--mode", "sink", "--threads", "2"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    try:
        port = BASE + 2
        if opt["--master"]:
            for k, mem in enumerate(m for m in opt["--mems"].split(",") if m):
                unit = f"fwmb-master-{mem}-{k}-{os.getpid()}"
                s = Server(os.path.abspath(opt["--master"]), port, mem, unit)
                r = wbench(port, src_port, "download", 10, 10, 5)
                ev, peak = scope_files(unit)
                died = not s.alive()
                print(f"INFO master {mem}: {'OOM-killed (reproduced)' if died else 'survived'}; "
                      f"wbench errors={r['errors']} down={r['mib_s_down']} MiB/s peak={peak} MiB")
                s.stop()
                port += 1
        for k, mem in enumerate(m for m in opt["--mems"].split(",") if m):
            unit = f"fwmb-{mem}-{k}-{os.getpid()}"
            s = Server(BIN, port, mem, unit)
            try:
                r = wbench(port, src_port, "download", 10, 10, 5)
                ev, peak = scope_files(unit)
                ok = s.alive() and ev is not None and ev.get("oom_kill", 1) == 0
                check(f"{mem} download 10x10: server alive, no OOM kill", ok, f"events={ev} peak={peak} MiB")
                check(f"{mem} download 10x10: no errors, 10/10 connections", r["errors"] == 0 and r["conns_ok"] == 10 and r["mib_s_down"] > 0,
                      f"{r['mib_s_down']} MiB/s errors={r['errors']} conns_ok={r['conns_ok']}")
                sink_port = port + 16  # its own port per round (the old listener may linger)
                sink = PausedSink(sink_port)
                hostile = {}
                t = threading.Thread(target=lambda: hostile.update(wbench(port, sink_port, "upload", 10, 20, 4)))
                t.start()
                t.join(70)
                ev, peak = scope_files(unit)
                ok = s.alive() and ev is not None and ev.get("oom_kill", 1) == 0
                check(f"{mem} hostile upload 10x20 to a paused sink: server alive, no OOM kill", ok,
                      f"events={ev} peak={peak} MiB wbench errors={hostile.get('errors')} up={hostile.get('mib_s_up')} MiB/s")
                sink.release()
                sink.close()
                # pressure is gone once the sink has drained: wait for the cgroup to fall under 40%
                limit = int(open(CG + unit + ".scope/memory.max").read()) if s.alive() else 0
                t0 = time.time()
                while s.alive() and time.time() - t0 < 15:
                    if int(open(CG + unit + ".scope/memory.current").read()) < limit * 0.4:
                        break
                    time.sleep(0.1)
                print(f"INFO {mem}: memory under 40% {time.time() - t0:.1f} s after the sink resumed")
                time.sleep(1.5)  # sampler + hysteresis + the 250 ms dwell per level step down
                r = wbench(port, src_port, "download", 10, 10, 2)
                check(f"{mem} recovery: download 10x10 after the hostile load", s.alive() and r["errors"] == 0 and r["conns_ok"] == 10,
                      f"{r['mib_s_down']} MiB/s errors={r['errors']} conns_ok={r['conns_ok']}")
            finally:
                if fails:
                    print("server log tail:\n" + "\n".join(s.text().splitlines()[-8:]))
                s.stop()
                port += 1
        # 4 review B, at 256M (level 0: no socket caps, so only the backlog rule can slow Y down):
        # client X fills the upload backlog to a paused sink (2 streams, 128 credits x 384 KiB frames =
        # 96 MiB, over the 64 MiB backlog cap, under the 64 MiB per-stream PEND_HARD); client Y uploads to a draining sink at the same time. Y must keep
        # flowing: only the client holding the backlog is not read (and it is shed after ~4 s).
        mem, unit = "256M", f"fwmb-fair-{os.getpid()}"
        s = Server(BIN, port, mem, unit)
        try:
            xsink = PausedSink(port + 24)
            x = {}
            tx = threading.Thread(target=lambda: x.update(wbench(port, port + 24, "upload", 1, 2, 8, size=384 << 10)))
            tx.start()
            time.sleep(2.0)
            y = wbench(port, drain_port, "upload", 1, 1, 3)
            tx.join(70)
            xsink.release()
            xsink.close()
            ev, peak = scope_files(unit)
            check("256M backlog fairness: Y uploads at speed while X's target is stalled",
                  s.alive() and y["errors"] == 0 and y["mib_s_up"] > 50,
                  f"Y {y['mib_s_up']} MiB/s errors={y['errors']}; X {x.get('mib_s_up')} MiB/s errors={x.get('errors')} (shed streams); peak={peak} MiB")
            r = wbench(port, src_port, "download", 2, 2, 1)
            check("256M after the fairness check: download works", s.alive() and r["errors"] == 0, f"{r['mib_s_down']} MiB/s")
        finally:
            if fails:
                print("server log tail:\n" + "\n".join(s.text().splitlines()[-8:]))
            s.stop()
    finally:
        src.terminate()
        drain.terminate()
    print("membudget:", "FAILED " + ", ".join(fails) if fails else "all passed")
    sys.exit(1 if fails else 0)


main()
