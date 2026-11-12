#!/usr/bin/env python3
"""60.31 C7: a TCP peer at exactly 100:: is reset at accept with --listen-unix; ::1 and 100::1 are served. Needs root
(the address on lo): run it in a throwaway container or netns, not in the compat suite. usage: unix_sentinel.py BIN"""
import os, socket, subprocess, sys, time
BIN = sys.argv[1]
fails = 0
def ok(c, m):
    global fails
    print(("PASS " if c else "FAIL ") + m, flush=True); fails += 0 if c else 1
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
for a in ("100::/128", "100::1/128"):
    subprocess.run(["ip", "-6", "addr", "add", a, "dev", "lo"], check=True)
time.sleep(2)  # DAD
def up(src, port):
    s = socket.socket(socket.AF_INET6); s.bind((src, 0)); s.settimeout(3); s.connect(("::1", port))
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    try:
        d = s.recv(4096)
        return "101" if d.startswith(b"HTTP/1.1 101") else ("eof" if not d else d[:20].decode())
    except ConnectionResetError:
        return "reset"
    finally:
        s.close()
def run(args, port):
    log = open(f"/tmp/fw{port}.log", "w+")
    p = subprocess.Popen([BIN, "--host", "::", "--port", str(port), "--log-level", "debug", "--metrics-interval", "1", *args], stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        if "capabilities:" in open(log.name).read(): break
        time.sleep(0.05)
    return p, log
for name, args in (("--log-conns", ["--log-conns"]), ("--trusted-proxy", ["--trusted-proxy", "10.0.0.0/8"]),
                   ("--max-conns-per-ip", ["--max-conns-per-ip", "5"])):
    port = 7100 + len(name)
    p, log = run(["--listen-unix", f"/tmp/u{port}.sock", "--max-conns", "10", *args], port)
    r0, r1, r2 = up("100::", port), up("::1", port), up("100::1", port)
    time.sleep(1.3)
    p.terminate(); p.wait(10)
    text = open(log.name).read()
    last = [l for l in text.splitlines() if "ev=metrics" in l][-1]
    kv = dict(x.split("=", 1) for x in last.split() if "=" in x)
    ok(r0 == "reset", f"{name}: TCP peer 100:: reset at accept (got {r0})")
    ok(r1 == "101" and r2 == "101", f"{name}: ::1 and 100::1 served ({r1}, {r2})")
    ok(kv.get("refuse_sentinel") == "1" and kv.get("conns_reserved") == "0", f"{name}: refuse_sentinel={kv.get('refuse_sentinel')} conns_reserved={kv.get('conns_reserved')} (reservation released)")
    if name == "--log-conns":
        ok("ip=100::" not in text.replace("ip=100::1", ""), "--log-conns: no line for the reset sentinel peer as a client")
# without --listen-unix: 100:: is an ordinary peer (no sentinel, no reset)
p, log = run(["--log-conns"], 7200)
r = up("100::", 7200); time.sleep(1.3); p.terminate(); p.wait(10)
kv = dict(x.split("=", 1) for x in [l for l in open(log.name).read().splitlines() if "ev=metrics" in l][-1].split() if "=" in x)
ok(r == "101" and kv.get("refuse_sentinel") == "0", f"no --listen-unix: TCP peer 100:: served ({r}, refuse_sentinel={kv.get('refuse_sentinel')})")
# --listen-unix alone (no want_peer): no sockaddr read, so no check; 100:: is served but gets no Peer (untrusted)
p, log = run(["--listen-unix", "/tmp/u7300.sock"], 7300)
r = up("100::", 7300); time.sleep(1.3); p.terminate(); p.wait(10)
kv = dict(x.split("=", 1) for x in [l for l in open(log.name).read().splitlines() if "ev=metrics" in l][-1].split() if "=" in x)
ok(r == "101" and kv.get("refuse_sentinel") == "0", f"--listen-unix alone: no peer read, 100:: served as untrusted ({r})")
print(f"t100: {fails} failure(s)"); sys.exit(1 if fails else 0)
