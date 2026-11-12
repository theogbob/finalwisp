"""Functional gates (30.10; was bench/gates.py, 60.01): every compat test in tests/compat/ against one server.

usage: wst compat --bin FINALWISP [--base-port 8300] [--out DIR] [--matrix] [--skip a,b] [--only a,b]
                  [--cargo DIR | --no-cargo] [--membudget-master BIN] [--fuzz-replay]
       wst compat --server NAME|fw:PATH|NAME='cmd --port {port}' [--base-port 8300] [--out DIR]

--bin: the finalwisp gate. Steps (ports base+0 .. base+99):
  cargo         cargo test --release in --cargo DIR (default: <repo>/server; the source of --bin, not checked)
  adv-lane      tests/compat/adversarial.py on --threads 2 (two-lane output on, the default)      base+0
  adv-noprio    adversarial.py on --threads 2 --no-prio                                           base+1
  tls           tests/compat/run_tls.sh (wisp-js over wss, adversarial --tls, tls_adversarial,
                tls_nonce, tls_extras)                                                            base+2..+5
  v2ext         tests/compat/v2ext.py (password / key auth, MOTD)                                 base+10..+19
  udp           tests/compat/udp.py with a --no-udp twin                                          base+20, +21
  wispjs-udp    tests/compat/wispjs_udp.mjs (real wisp-js client over UDP streams)               base+20, +21
  wispjs        tests/compat/wispjs.mjs (real wisp-js client v1+v2, 2x64 MiB pattern download)
                + default SSRF guard on a server without --allow-loopback                         base+20, +21
  credit-v2     tests/compat/credit_v2.py (20.30 credit v2: pong / no-pong / eager / foreign-pong clients)  base+66
  wispjs-v2c    wispjs.mjs + adversarial.py (adv-v2c) with credit v2 (wisp-js sends inside its CONTINUE handler)  base+67
  limits        tests/compat/limits.py (60.20 C3a: --max-conns with/without --balance, --max-streams-per-conn;
                60.39 --stream-rate-per-dest / -minute)                                           base+24..+27
  fds           tests/compat/fds.py (60.57: the nofile raise, the fd count against /proc/PID/fd, resets and 0x49
                at the fd limit, the warning lines; 60.57 C: --conn-share, --fd-admission)        base+52..+55
  bounds        tests/compat/bounds.py (60.63 E: the four options off and on, honest streams, --dest-failfast end to
                end against a destination that does not answer, answers again, refuses)             base+97, +98
  policy        tests/compat/policy.py (60.20 C1: port/host/dest rules, --no-direct-ip, --no-ipv6-targets, recursion)  base+28, +29
  realip        tests/compat/realip.py (60.20 C2/C3b: per-IP limits direct and behind a trusted proxy, XFF, rates)  base+8, +9
  logs          tests/compat/logs.py (60.24 --log-level, --log-conns lines, refusal flood, stalled stderr)  base+22, +23
  pacing        tests/compat/pacing.py (60.30 C10a: --download-rate / --upload-rate-per-stream on loopback)  base+78, +79
  uplimit       tests/compat/uplimit.py (60.25 C10b: --upload-rate / --upload-rate-per-ip; plain, UDP, wss)  base+50, +51
  config        tests/compat/config.py (60.20 C8: a server started from --config FILE, override, bad files)  base+6, +7
  prom          tests/compat/prom.py (60.29 C5 --metrics-listen: /metrics page, 404/405/400, stuck and dripping
                scrapers, off = no thread, --config form, startup refusals)                       base+68, +69
  proxyproto    tests/compat/proxyproto.py (60.34 --proxy-protocol tcp|unix: v1/v2/LOCAL, source list, per-IP by
                source, bad / split / late headers, TLS after it, trusted source + XFF, --balance, unix, drain)  base+96
  unix          tests/compat/unix.py (60.31 C7 --listen-unix: mode, both listeners, TLS beside it, XFF from the unix
                peer, hand-over spread, stale/live/crash/flock cases; strace / caddy optional)    base+65
  drain         tests/compat/drain.py (60.12 SIGTERM/SIGINT graceful shutdown, --drain-timeout)       base+80..+89
  upstream      tests/compat/upstream.py (60.32 C6 --upstream against fake SOCKS5 / HTTP CONNECT proxies and a fake
                DNS server: codes, retries, the try cap, socks5h rules, startup refusals, redaction)   base+90..+94
  membudget     tests/compat/membudget.py (user systemd scopes; exit 77 = SKIP)                   base+30..+64
  --matrix      opt-in: adversarial.py + wispjs.mjs on each of --no-splice, --balance, --no-tfo,
                --graceful-close                                                                  base+70..+77
  --proxy       opt-in (40.02): tests/compat/proxy.py: finalwisp behind nginx and Caddy in docker (TLS at the
                proxy; wisp-js, 32 MiB upload with a stalling target, 125 s idle); no docker = SKIP      base+90..+99
  --fuzz-replay  opt-in (70.01): cargo fuzz build -O in --cargo DIR/fuzz, then every fuzz target replays its
                regression corpus server/fuzz/regress/<target> once (-runs=0, no fuzzing), each in
                bwrap --unshare-net. Steps fuzz-build, fuzz-<target>; like cargo it tests that source, not --bin.
                The binaries are left in fuzz/target (60.18 #11: one build; the nofeat lane is gone).
                Needs cargo-fuzz + bwrap (missing = SKIP); worker-tls needs kTLS (the tls module; missing = SKIP).
  Exit status: 0 only if every step ran and passed (rc 0 and no FAIL lines; cargo: no "FAILED"/"panicked",
  every "test result: ok"). A SKIP (membudget without a delegated memory controller) also fails the gate unless
  --allow-skip is given; steps left out with --only/--skip/--no-cargo are listed in the summary.
--server: any Wisp server (competitors). The protocol-generic tests in report mode, a fresh server per test:
  wisp-js client (wispjs.mjs), wisp-js UDP (wispjs_udp.mjs), udp.py --ref, adversarial.py (several checks assert
  finalwisp's own choices: read the FAIL lines, they are not all bugs), epoxy_udp_burst.py (server must survive).
  Prints a PASS/FAIL table; exit 0 unless the suite itself broke.
Logs: OUT/<step>.log, OUT/summary.txt, OUT/results.json (schema wispsuite/1).
"""
import argparse, glob, os, re, shlex, shutil, sys, time
from . import proc, report, servers as srvmod

ROOT = srvmod.ROOT
COMPAT = os.path.join(ROOT, "tests", "compat")
MATRIX_FLAGS = ["--no-splice", "--balance", "--no-tfo", "--graceful-close", "--dns-own"]  # 70.09 --dns-own: wispjs resolves "localhost" (hosts file)


class Gate:
    def __init__(self, out):
        self.out, self.steps = out, []
        os.makedirs(out, exist_ok=True)
        self.summary = open(os.path.join(out, "summary.txt"), "w")

    def say(self, s):
        print(s, flush=True)
        self.summary.write(s + "\n")
        self.summary.flush()

    def step(self, name, cmd, cwd=ROOT, timeout=900, shell=False, judge=None, env=None):
        """Run one test command (own process group, killed on timeout); record status PASS/FAIL/SKIP."""
        t0 = time.time()
        rc, out, err = proc.run(cmd, timeout=timeout, shell=shell, cwd=cwd, env=env)
        text = (out or "") + (err or "")
        with open(os.path.join(self.out, name.replace(" ", "_").replace("/", "_") + ".log"), "w") as f:
            f.write(text)
        fails = [l for l in text.splitlines() if l.startswith("FAIL")]
        status = "PASS" if rc == 0 and not fails else "FAIL"
        why = "" if rc is not None else f"timeout {timeout}s"
        if judge:
            status, why = judge(rc, text, fails)
        if proc.INCOMPLETE in text:  # review: lost output must not pass (a judge may not look at FAIL lines)
            status, why = "FAIL", proc.INCOMPLETE
        tail = "\n".join(text.strip().splitlines()[-2:])
        self.say(f"== {name}: {status} rc={rc} {time.time() - t0:.0f}s FAIL-lines={len(fails)}" + (f" ({why})" if why else "")
                 + (f"\n{tail}" if tail else "") + ("\n" + "\n".join(fails[:10]) if fails else ""))
        self.steps.append({"step": name, "status": status, "rc": rc, "secs": round(time.time() - t0, 1),
                           "fail_lines": fails[:50], "why": why})
        return status

    def broken(self, name, why):
        self.say(f"== {name}: FAIL ({why})")
        self.steps.append({"step": name, "status": "FAIL", "rc": None, "secs": 0, "fail_lines": [], "why": why})


def cargo_judge(rc, text, fails):
    results = [l for l in text.splitlines() if l.startswith("test result:")]
    bad = [l for l in text.splitlines() if "FAILED" in l or "panicked" in l]
    if rc != 0:
        return "FAIL", f"cargo exited {rc}"
    if bad:
        return "FAIL", bad[0][:120]
    if not results or any(not l.startswith("test result: ok") for l in results):
        return "FAIL", "no passing 'test result' line" if not results else "a test binary failed"
    total = sum(int(l.split("ok.")[1].split("passed")[0]) for l in results if "passed" in l)
    return "PASS", f"{total} tests passed"


def membudget_judge(rc, text, fails):
    if rc == 77:
        return "SKIP", "no user systemd / delegated memory controller"
    return ("PASS", "") if rc == 0 and not fails else ("FAIL", f"rc {rc}")


def proxy_judge(rc, text, fails):
    if rc == 77:
        return "SKIP", "docker or the proxy images not available"
    return ("PASS", "") if rc == 0 and not fails else ("FAIL", f"rc {rc}")


def fuzz_judge(rc, text, fails):
    if "kTLS unavailable" in text:
        return "SKIP", "kTLS not available (worker-tls)"
    bad = [l for l in text.splitlines() if "panicked at" in l or "ERROR: AddressSanitizer" in l or "ERROR: libFuzzer" in l]
    if rc != 0 or bad:
        return "FAIL", (bad[0][:120] if bad else f"rc {rc}")
    done = [l for l in text.splitlines() if " DONE " in l or l.startswith("Done ")]
    return ("PASS", done[-1].strip()[:80]) if done else ("FAIL", "no DONE line")


def fuzz_replay(a, g):
    """70.01: replay the committed regression corpora (server/fuzz/regress/<target>) through the fuzz targets."""
    fz = os.path.join(os.path.abspath(a.cargo), "fuzz")  # absolute: the replays run with cwd=fz
    missing = [t for t in ("cargo-fuzz", "bwrap") if not shutil.which(t)]
    if missing or not os.path.isdir(os.path.join(fz, "regress")):
        why = f"missing {', '.join(missing)}" if missing else f"no {fz}/regress"
        g.say(f"== fuzz-replay: SKIP ({why})")
        g.steps.append({"step": "fuzz-replay", "status": "SKIP", "rc": None, "secs": 0, "fail_lines": [], "why": why})
        return
    # 60.18 #11: one build (the pool is the only allocator path; the --no-default-features lane is gone)
    if g.step("fuzz-build", ["cargo", "fuzz", "build", "-O"], cwd=fz, timeout=1800) != "PASS":
        return
    for d in sorted(glob.glob(os.path.join(fz, "regress", "*"))):
        if not os.path.isdir(d):  # regress/README.md
            continue
        t = os.path.basename(d)
        bins = glob.glob(os.path.join(fz, "target", "*", "release", t))
        if not bins:
            g.broken(f"fuzz-{t}", "fuzz target binary not built")
            continue
        g.step(f"fuzz-{t}", ["bwrap", "--unshare-net", "--die-with-parent", "--dev-bind", "/", "/", bins[0], "-runs=0",
                             "-rss_limit_mb=4096", "-timeout=60", d], cwd=fz, timeout=900, judge=fuzz_judge)


def fw(binp, port, args=""):
    """finalwisp server on port (its own group); waits until it listens. None if it never does."""
    s = srvmod.Server("fw", f"exec {shlex.quote(binp)} --port {{port}} {args}".rstrip())
    try:
        return s.start(port, srvmod.SCRATCH, wait=True)
    except RuntimeError:
        return None


def gate_finalwisp(a, g):
    binp, B = a.bin, a.base_port
    wb = a.wbench
    want = lambda n: (not a.only or n in a.only) and n not in a.skip
    g.say(f"compat gates for {binp} md5 {report.md5(binp)}")
    if want("cargo") and not a.no_cargo:
        g.say(f"cargo test runs in {a.cargo} (git {report.git_rev_of(a.cargo)}): it tests that source, not necessarily the source of --bin")
        g.step("cargo", ["cargo", "test", "--release"], cwd=a.cargo, timeout=1800, judge=cargo_judge)
    adv = os.path.join(COMPAT, "adversarial.py")
    for name, port, args in (("adv-lane", B, "--allow-loopback --threads 2"), ("adv-noprio", B + 1, "--allow-loopback --threads 2 --no-prio")):
        if want(name):
            p = fw(binp, port, args)
            if p is None:
                g.broken(name, f"server did not listen on :{port}")
                continue
            g.step(name, [sys.executable, adv, str(port)])
            proc.stop(p)
    if want("tls"):
        g.step("tls", ["bash", os.path.join(COMPAT, "run_tls.sh"), binp, str(B + 2)], timeout=1500)
    if want("v2ext"):
        g.step("v2ext", [sys.executable, os.path.join(COMPAT, "v2ext.py"), binp, str(B + 10)])
    if want("dns-own"):  # 70.09 own resolver against a fake DNS server (ports B+40..B+49)
        g.step("dns-own", [sys.executable, os.path.join(COMPAT, "dns_own.py"), binp, str(B + 40)], timeout=300)
    if want("dns-preset"):  # 60.58 the same cases with --preset public (dns-own, dns-reserve); the same ports, after dns-own
        g.step("dns-preset", [sys.executable, os.path.join(COMPAT, "dns_own.py"), binp, str(B + 40), "preset"], timeout=300)
    if want("limits"):  # 60.20 C3a --max-conns / --max-streams-per-conn (ports B+24..B+27)
        g.step("limits", [sys.executable, os.path.join(COMPAT, "limits.py"), binp, str(B + 24)], timeout=180)
    if want("fds"):  # 60.57 fd count, fd limit, refusals at the limit (ports B+52..B+55)
        g.step("fds", [sys.executable, os.path.join(COMPAT, "fds.py"), binp, str(B + 52)], timeout=300)
    if want("bounds"):  # 60.63 E the bounds of section E (ports B+97, B+98)
        g.step("bounds", [sys.executable, os.path.join(COMPAT, "bounds.py"), binp, str(B + 97)], timeout=300)
    if want("policy"):  # 60.20 C1 destination policy (ports B+28, B+29)
        g.step("policy", [sys.executable, os.path.join(COMPAT, "policy.py"), binp, str(B + 28)], timeout=180)
    if want("realip"):  # 60.20 C2 / C3b (ports B+8, B+9)
        g.step("realip", [sys.executable, os.path.join(COMPAT, "realip.py"), binp, str(B + 8)], timeout=180)
    if want("logs"):  # 60.24 --log-level / --log-conns (ports B+22, B+23)
        g.step("logs", [sys.executable, os.path.join(COMPAT, "logs.py"), binp, str(B + 22)], timeout=240)
    if want("pacing"):  # 60.30 C10a bandwidth caps (ports B+78, B+79)
        g.step("pacing", [sys.executable, os.path.join(COMPAT, "pacing.py"), binp, str(B + 78)], timeout=180)
    if want("uplimit"):  # 60.25 C10b upload caps (ports B+50, B+51; between steps, membudget's range is free)
        g.step("uplimit", [sys.executable, os.path.join(COMPAT, "uplimit.py"), binp, str(B + 50)], timeout=240)
    if want("config"):  # 60.20 C8 --config FILE (ports B+6, B+7)
        g.step("config", [sys.executable, os.path.join(COMPAT, "config.py"), binp, str(B + 6)], timeout=120)
    if want("prom"):  # 60.29 C5 --metrics-listen (ports B+68, B+69)
        g.step("prom", [sys.executable, os.path.join(COMPAT, "prom.py"), binp, str(B + 68)], timeout=120)
    if want("proxyproto"):  # 60.34 PROXY protocol (port B+96; the opt-in proxy step's B+90..99 runs separately)
        g.step("proxyproto", [sys.executable, os.path.join(COMPAT, "proxyproto.py"), binp, str(B + 96)], timeout=300)
    if want("unix"):  # 60.31 C7 --listen-unix (port B+65; the socket in a temp dir)
        g.step("unix", [sys.executable, os.path.join(COMPAT, "unix.py"), binp, str(B + 65)], timeout=300)
    if want("drain"):  # 60.12 graceful shutdown (ports B+80..B+89)
        g.step("drain", [sys.executable, os.path.join(COMPAT, "drain.py"), binp, str(B + 80)], timeout=300)
    if want("upstream"):  # 60.32 C6 upstream proxy (ports B+90..B+94; the fake proxies take ephemeral ports)
        g.step("upstream", [sys.executable, os.path.join(COMPAT, "upstream.py"), binp, str(B + 90)], timeout=400)
    if want("udp") or want("wispjs-udp") or want("wispjs"):
        a1, b1 = fw(binp, B + 20, "--allow-loopback"), fw(binp, B + 21, "--allow-loopback --no-udp")
        if a1 is None or b1 is None:
            g.broken("udp", f"servers did not listen on :{B + 20}/:{B + 21}")
        else:
            if want("udp"):
                g.step("udp", [sys.executable, os.path.join(COMPAT, "udp.py"), str(B + 20), "--no-udp-port", str(B + 21)])
            if want("wispjs-udp"):
                g.step("wispjs-udp", ["node", "wispjs_udp.mjs", f"ws://127.0.0.1:{B + 20}/", f"ws://127.0.0.1:{B + 21}/"], cwd=COMPAT)
            proc.stop(b1)
            proc.wait_free(B + 21)
            b1 = fw(binp, B + 21)  # defaults: loopback/private targets refused (SSRF guard)
            if want("wispjs"):
                if b1 is None:
                    g.broken("wispjs", f"server did not listen on :{B + 21}")
                else:
                    g.step("wispjs", ["node", "wispjs.mjs", f"ws://127.0.0.1:{B + 20}/", f"ws://127.0.0.1:{B + 21}/"], cwd=COMPAT)
        proc.stop(a1)
        proc.stop(b1)
    if want("credit-v2"):  # 20.30 upload credit v2 (default on since 60.13): every ping behaviour of a client
        g.step("credit-v2", [sys.executable, os.path.join(COMPAT, "credit_v2.py"), binp, str(B + 66)], timeout=300)
    if want("wispjs-v2c") or want("adv-v2c"):
        p = fw(binp, B + 67, "--allow-loopback --threads 2")  # credit v2: the default (60.13; --credit-v2 removed in 60.18)
        if p is None:
            g.broken("wispjs-v2c", f"server did not listen on :{B + 67}")
        else:
            if want("wispjs-v2c"):
                g.step("wispjs-v2c", ["node", "wispjs.mjs", f"ws://127.0.0.1:{B + 67}/"], cwd=COMPAT)
            if want("adv-v2c"):
                g.step("adv-v2c", [sys.executable, adv, str(B + 67)])
            proc.stop(p)
    if want("membudget"):
        cmd = [sys.executable, os.path.join(COMPAT, "membudget.py"), binp, "--base-port", str(B + 30), "--wbench", wb]
        if a.membudget_master:
            cmd += ["--master", a.membudget_master]
        g.step("membudget", cmd, timeout=1800, judge=membudget_judge)
    if want("metrics"):  # 60.12 C5-lite: the metrics line, the final line at SIGTERM, off = absent
        g.step("metrics", [sys.executable, os.path.join(COMPAT, "metrics.py"), binp, "--port", str(B + 66)], timeout=120)
    if a.proxy:
        g.step("proxy", [sys.executable, os.path.join(COMPAT, "proxy.py"), binp, str(B + 90)], timeout=900, judge=proxy_judge)
    if a.fuzz_replay:
        fuzz_replay(a, g)
    if a.matrix:
        for i, flag in enumerate(MATRIX_FLAGS):
            port = B + 70 + 2 * i
            name = f"adv{flag}"
            jname = f"wispjs{flag}"
            group = "matrix" not in a.skip and (not a.only or "matrix" in a.only)
            run_adv = name not in a.skip and (group or name in a.only)
            run_js = jname not in a.skip and (group or jname in a.only)
            if not (run_adv or run_js):
                continue
            p = fw(binp, port, f"--allow-loopback --threads 2 {flag}")
            if p is None:
                g.broken(name, f"server did not listen on :{port}")
                continue
            if run_adv:
                g.step(name, [sys.executable, adv, str(port)])
            if run_js:
                g.step(jname, ["node", "wispjs.mjs", f"ws://127.0.0.1:{port}/"], cwd=COMPAT)
            proc.stop(p)


def gate_any(a, g):
    """Report mode for any server: a fresh server for every test."""
    srv = srvmod.resolve(a.server)
    port = a.base_port
    tests = [("wispjs", ["node", "wispjs.mjs", f"ws://127.0.0.1:{port}/"], COMPAT, 600),
             ("wispjs-udp", ["node", "wispjs_udp.mjs", f"ws://127.0.0.1:{port}/"], COMPAT, 300),
             ("udp", [sys.executable, os.path.join(COMPAT, "udp.py"), str(port), "--ref"], ROOT, 300),
             ("adversarial", [sys.executable, os.path.join(COMPAT, "adversarial.py"), str(port)], ROOT, 900),
             ("epoxy-udp-burst", [sys.executable, os.path.join(COMPAT, "epoxy_udp_burst.py"), str(port), "200"], ROOT, 60)]
    g.say(f"compat (report mode) for server '{srv.name}': {srv.cmd}")
    for name, cmd, cwd, timeout in tests:
        if (a.only and name not in a.only) or name in a.skip:
            continue
        proc.wait_free(port)
        log = os.path.join(a.out, f"server-{name}.log")
        try:
            p = srv.start(port, srvmod.SCRATCH, log=log)
        except RuntimeError as e:
            g.broken(name, str(e))
            continue
        judge = None
        if name == "epoxy-udp-burst":  # the script always exits 0: the verdict is whether the server survived
            judge = lambda rc, text, fails, p=p: (("PASS", "server alive") if p.poll() is None and proc.wait_port(port, 2)
                                                  else ("FAIL", "server died"))
        g.step(name, cmd, cwd=cwd, timeout=timeout, judge=judge)
        proc.stop(p)


def main(argv):
    from . import wbench
    ap = argparse.ArgumentParser(prog="wst compat", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    who = ap.add_mutually_exclusive_group(required=True)
    who.add_argument("--bin", help="a finalwisp binary: the full gate")
    who.add_argument("--server", help="any server (registry name, fw:PATH, NAME='cmd {port}'): report mode")
    ap.add_argument("--base-port", type=int, default=8300)
    ap.add_argument("--out", default=None)
    ap.add_argument("--matrix", action="store_true", help="also the option matrix (" + ", ".join(MATRIX_FLAGS) + ")")
    ap.add_argument("--only", default="", help="comma list of step names")
    ap.add_argument("--skip", default="", help="comma list of step names")
    ap.add_argument("--cargo", default=os.path.join(ROOT, "server"), help="crate dir for cargo test")
    ap.add_argument("--no-cargo", action="store_true")
    ap.add_argument("--allow-skip", action="store_true", help="--bin: a SKIP step (e.g. membudget without scopes) does not fail the gate")
    ap.add_argument("--membudget-master", default="", help="informational: also run membudget check 1 on this binary")
    ap.add_argument("--wbench", default=None)
    ap.add_argument("--proxy", action="store_true", help="--bin: also finalwisp behind nginx + Caddy (docker; 40.02)")
    ap.add_argument("--fuzz-replay", action="store_true", help="--bin: also replay the fuzz regression corpora (server/fuzz/regress)")
    a = ap.parse_args(argv)
    a.only = [x for x in a.only.split(",") if x]
    a.skip = [x for x in a.skip.split(",") if x]
    a.wbench = wbench.find(a.wbench)
    a.out = os.path.abspath(a.out or os.path.join(report.BENCH, "results", f"compat-{report.stamp()}"))
    ports = range(a.base_port, a.base_port + (80 if a.bin else 1))
    bad = proc.strays(ports, cmdline=False)
    if bad:
        sys.exit("compat: " + "; ".join(bad[:5]) + f" (ports {ports.start}-{ports.stop - 1} must be free; use --base-port)")
    proc.install_handlers()
    g = Gate(a.out)
    if a.bin:
        a.bin = os.path.abspath(a.bin)
        if not os.access(a.bin, os.X_OK):
            sys.exit(f"compat: not executable: {a.bin}")
        gate_finalwisp(a, g)
    else:
        gate_any(a, g)
    proc.stop_all()
    n = {s: sum(x["status"] == s for x in g.steps) for s in ("PASS", "FAIL", "SKIP")}
    g.say(f"compat done: {n['PASS']} PASS, {n['FAIL']} FAIL, {n['SKIP']} SKIP" + (f" (FAIL: {', '.join(x['step'] for x in g.steps if x['status'] == 'FAIL')})" if n["FAIL"] else ""))
    report.write(os.path.join(a.out, "results.json"), "compat", binaries=[a.bin] if a.bin else [],
                 mode="gate" if a.bin else "report", server=a.server, steps=g.steps)
    left_out = [x for x in a.skip] + (["cargo"] if a.no_cargo else []) + (["(--only " + ",".join(a.only) + ")"] if a.only else [])
    if a.bin and left_out:
        g.say("not run on request: " + ", ".join(left_out))
    if a.bin:
        sys.exit(1 if n["FAIL"] or (n["SKIP"] and not a.allow_skip) or not g.steps else 0)
