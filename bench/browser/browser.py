"""wst browser (bench/browser): a "real user" simulator for Wisp servers.

Headless Chromium (Playwright) runs a Scramjet web proxy whose Wisp transport (epoxy-transport or
libcurl-transport) points at the Wisp server under test, then loads real sites, a short user session,
a page WebSocket and downloads. Catches compat problems synthetic tests miss; gives a "does it feel the same" number.

  compat mode (default): real internet. Pass/fail matters; timings are informational (the internet is noisy).
  timing mode: a local static mirror (bench/browser/mirror, see mirror.py, served by its own node process) is the
               only origin; rotated server order, --reps reps, medians; any failed/5xx/external request fails the
               rep. Ask for the machine lock before timing runs.

usage: python3 bench/browser/browser.py [--mode compat|timing] [--server SPEC]... [--transport epoxy|libcurl]...
         [--reps N] [--sites a,b] [--out PATH] [--port-base 8400] [--tls]
--tls: Wisp over wss:// with a per-run self-signed cert (fw: servers only; default server list = fw only).
SPEC: [NAME=]fw:PATH [args] (a finalwisp binary; timing mode adds --allow-loopback), a registry name (epoxy, wisp-js;
      bench/servers.json when wispsuite is present), or NAME='command with {port}'.
Writes one wispsuite/1 JSON (kind "browser") + a markdown table next to it. Exit: compat -> 1 on any failure;
timing -> 1 only if the harness broke. Needs: node, `npm i` in bench/browser, Playwright Chromium
(`npx playwright install chromium`), a built Scramjet checkout ($SCRAMJET_DIR, see README.md).
"""
import argparse, base64, datetime as dt, hashlib, json, os, platform, shlex, signal, socket, statistics, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
sys.path.insert(0, BENCH)
try:  # bench-suite's shared modules (branch bench-suite); a small fallback keeps this runnable alone
    from wispsuite import report as _report, servers as _servers
except ImportError:
    _report = _servers = None


def main_root():
    """The main checkout (ref/ and baselines/ live there; a worktree may not have them)."""
    if os.environ.get("FINALWISP_ROOT"):
        return os.environ["FINALWISP_ROOT"]
    try:
        common = subprocess.run(["git", "-C", BENCH, "rev-parse", "--path-format=absolute", "--git-common-dir"],
                                capture_output=True, text=True, timeout=5).stdout.strip()
        if common:
            return os.path.dirname(common)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return os.path.dirname(BENCH)


ROOT = main_root()
SCRAMJET = os.path.abspath(os.environ.get("SCRAMJET_DIR", os.path.join(ROOT, "scramjet")))  # a scramjet build (README)
# fallback registry, same commands as bench/servers.json (bench-suite); used only when wispsuite is absent
BUILTIN = {
    "epoxy": ("{root}/ref/epoxy-tls/target/release/epoxy-server {cfg}", None,
              '[server]\nbind = ["tcp", "127.0.0.1:{port}"]\nruntime = "multithread"\n\n[stream]\nallow_loopback = true\nallow_non_global = true\n'),
    "wisp-js": ("node server.mjs {port}", "{root}/baselines/js-server", None),
}


class Srv:
    def __init__(self, name, binary, start):
        self.name, self.binary, self._start = name, binary, start  # start(port, log) -> (Popen, cmd string)


def spawn(cmd, cwd, log):
    out = open(log, "ab")
    p = subprocess.Popen(cmd, shell=True, cwd=cwd, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         start_new_session=True)
    out.close()
    return p


def resolve(spec, mode, scratch, tls=None):
    """tls = (cert, key): finalwisp serves wss:// with that pair (--tls); other servers are refused there."""
    label, fwspec = None, spec
    if "=fw:" in spec.split(" ", 1)[0]:  # NAME=fw:PATH [args]: a finalwisp build under a chosen name
        label, fwspec = spec.split("=", 1)
    if fwspec.startswith("fw:"):
        path, _, args = fwspec[3:].partition(" ")
        path = os.path.abspath(path)
        if mode == "timing" and "--allow-loopback" not in args:
            args = (args + " --allow-loopback").strip()  # the mirror is on 127.0.0.1
        if tls:
            if "--tls-cert" in args or "--tls-key" in args:  # finalwisp would pick that pair, Chromium trusts only ours
                sys.exit(f"--tls: server '{spec}' already has --tls-cert/--tls-key; --tls brings its own pair")
            args = f"{args} --tls-cert {shlex.quote(tls[0])} --tls-key {shlex.quote(tls[1])}".strip()
        name = label or os.path.basename(path)
        cmd = f"exec {shlex.quote(path)} --port {{port}} {args}".rstrip()
        return Srv(name, path, lambda port, log: (spawn(cmd.replace("{port}", str(port)), None, log), cmd.replace("{port}", str(port))))
    if tls:
        sys.exit(f"--tls: server '{spec}' is not a finalwisp build (fw:PATH); only those get the run's certificate")
    if "=" in spec:
        name, cmd = spec.split("=", 1)
        return Srv(name, None, lambda port, log: (spawn("exec " + cmd.replace("{port}", str(port)), None, log), cmd.replace("{port}", str(port))))
    if _servers is not None:
        s = _servers.resolve(spec)
        def start(port, log, s=s):
            cmd, cwd = s.command(port, os.path.join(scratch, f"{s.name}-{port}"))
            return spawn(cmd, cwd, log), cmd
        return Srv(spec, None, start)
    if spec in BUILTIN:
        cmd, cwd, cfgtext = BUILTIN[spec]
        def start(port, log, cmd=cmd, cwd=cwd, cfgtext=cfgtext):
            c = cmd.replace("{root}", ROOT).replace("{port}", str(port))
            if cfgtext:
                path = os.path.join(scratch, f"{spec}-{port}.toml")
                with open(path, "w") as f:
                    f.write(cfgtext.replace("{port}", str(port)))
                c = c.replace("{cfg}", path)
            return spawn("exec " + c, cwd and cwd.replace("{root}", ROOT), log), c
        return Srv(spec, None, start)
    sys.exit(f"unknown server '{spec}': use fw:PATH, {', '.join(BUILTIN)}, or NAME='cmd {{port}}'")


def tls_pair(scratch):
    """--tls: a self-signed P-256 cert for 127.0.0.1 in the run's scratch dir -> ((cert, key), base64 SHA-256 of its SPKI)."""
    cert, key = os.path.join(scratch, "wisp-cert.pem"), os.path.join(scratch, "wisp-key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", cert],
                   check=True, capture_output=True)
    pub = subprocess.run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"], check=True, capture_output=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pub, check=True, capture_output=True).stdout
    return (cert, key), base64.b64encode(hashlib.sha256(der).digest()).decode()


def stop(p):
    """SIGTERM the process group, SIGKILL after 3 s; returns when no process of the group is left."""
    for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 3.0)):
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            break
        end = time.time() + wait
        while time.time() < end:
            p.poll()
            try:
                os.killpg(p.pid, 0)  # raises once the group is empty
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            continue
        break
    try:
        p.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


def wait_port(port, p, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if p.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def load_sites(mode):
    with open(os.path.join(HERE, "sites.json")) as f:
        return json.load(f)[mode]


def run_scenario(cfg, path, timeout):
    """Run scenario.mjs; returns (results, stderr text, harness error or None, chromium version).
    On timeout: SIGTERM to node's group (scenario.mjs then closes Chromium, which Playwright starts in its own
    process group), SIGKILL after 8 s."""
    with open(path, "w") as f:
        json.dump(cfg, f)
    p = subprocess.Popen(["node", os.path.join(HERE, "scenario.mjs"), path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         stdin=subprocess.DEVNULL, cwd=HERE, start_new_session=True)
    harness = None
    try:
        out, err = p.communicate(timeout=timeout)
        if p.returncode != 0:
            harness = f"scenario exit {p.returncode}"
    except (SystemExit, KeyboardInterrupt):
        stop(p)  # this driver was stopped: take node (and through its SIGTERM handler, Chromium) down too
        raise
    except subprocess.TimeoutExpired:
        harness = f"scenario timeout {timeout}s"
        for sig, wait in ((signal.SIGTERM, 8), (signal.SIGKILL, 5)):
            try:
                os.killpg(p.pid, sig)
            except ProcessLookupError:
                break
            try:
                out, err = p.communicate(timeout=wait)
                break
            except subprocess.TimeoutExpired:
                out, err = b"", b""
    out, err = out.decode(errors="replace"), err.decode(errors="replace")
    res, chromium = [], None
    for line in out.splitlines():
        try:
            if line.startswith("RESULT "):
                res.append(json.loads(line[7:]))
            elif line.startswith("BROWSER "):
                chromium = json.loads(line[8:]).get("chromium")
        except ValueError:
            harness = harness or f"malformed scenario output: {line[:200]}"
    return res, err, harness, chromium


class PowerChanged(Exception):
    pass


def power_state():
    """Laptop power profile + EPP of policy0 (both change timing a lot; a run must not straddle a change)."""
    try:
        prof = subprocess.run(["powerprofilesctl", "get"], capture_output=True, text=True, timeout=5).stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        prof = None
    try:
        epp = open("/sys/devices/system/cpu/cpufreq/policy0/energy_performance_preference").read().strip()
    except OSError:
        epp = None
    return {"profile": prof, "epp": epp}


def port_busy(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
        return True
    except OSError:
        return False


def warm(root):
    """Read the whole mirror once so the first server measured does not pay for a cold page cache."""
    for d, _, fs in os.walk(root):
        for f in fs:
            with open(os.path.join(d, f), "rb") as fh:
                while fh.read(1 << 20):
                    pass


def tail(path, n=4096):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - n))
            return f.read().decode(errors="replace")
    except OSError:
        return ""


def metric_of(r):
    return ("mib_s", "MiB/s") if r["case"] == "download" else ("load_ms", "ms")


def summarize(results):
    groups = {}
    for r in results:
        groups.setdefault((r["server"], r["transport"], r["case"], r["site"]), []).append(r)
    out = []
    for (srv, tr, case, site), rs in groups.items():
        key, unit = metric_of(rs[0])
        vals = [r[key] for r in rs if r.get("ok") and r.get(key) is not None]
        out.append({"server": srv, "transport": tr, "case": case, "site": site, "metric": key, "unit": unit,
                    "n": len(rs), "ok": sum(1 for r in rs if r.get("ok")), "median": statistics.median(vals) if vals else None,
                    "min": min(vals) if vals else None, "max": max(vals) if vals else None,
                    "all": [r.get(key) if r.get("ok") else None for r in rs],
                    "init_ms_median": statistics.median([r["init_ms"] for r in rs if r.get("init_ms") is not None] or [None]),
                    "errors": sorted({r["error"] for r in rs if r.get("error")})[:3]})
    return out


def md(summary, servers, transports):
    sites = []
    for s in summary:
        if (s["case"], s["site"]) not in sites:
            sites.append((s["case"], s["site"]))
    cols = [(sv, tr) for tr in transports for sv in servers]
    head = ["case", "site", "metric"] + [f"{sv} ({tr})" for sv, tr in cols]
    idx = {(s["server"], s["transport"], s["case"], s["site"]): s for s in summary}
    rows = []
    for case, site in sites:
        cells, metric = [], ""
        for sv, tr in cols:
            s = idx.get((sv, tr, case, site))
            if not s:
                cells.append("")
                continue
            metric = f'{s["metric"]} ({s["unit"]})'
            fmt = lambda x: f"{x:.1f}" if isinstance(x, float) else str(x)
            v = "-" if s["median"] is None else fmt(s["median"]) + (f' [{fmt(s["min"])}-{fmt(s["max"])}]' if s["n"] > 1 else "")
            cells.append(f'{v} {s["ok"]}/{s["n"]}' + ("" if s["ok"] == s["n"] else " FAIL"))
        rows.append([case, site, metric] + cells)
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(lines) + "\n\ncell = median [min-max] of ok reps, ok/n; FAIL marks any failed rep (see results[].error).\n"


def trace_table(results, servers, transports):
    """Medians over reps of the busy-case trace summary (see scenario.mjs traceSummary) and download CPU."""
    med = lambda xs: statistics.median(xs) if xs else None
    def g(d, path):
        for k in path.split("."):
            d = d.get(k) if isinstance(d, dict) else None
        return d
    cols = [("load_ms", "load_ms"), ("small_ms_p50", "small fetch ms"), ("bg_mib_s", "bg MiB/s"),
            ("trace.bulk_js_mib_s", "bulk to JS MiB/s"), ("trace.bulk_bytes_in_window", "bulk KB in load"), ("trace.other_bytes_in_window", "other KB"),
            ("trace.page_streams.first_data_ms_p50", "stream 1st data p50"), ("trace.page_streams.first_data_ms_max", "1st data max"),
            ("trace.pipeline.first_data_split_p50.server_ms", "of it: server"), ("trace.pipeline.first_data_split_p50.client_ms", "of it: client"),
            ("trace.pipeline.backlog_kb_p50.server_q", "srv sock q KB"), ("trace.pipeline.backlog_kb_p50.kernel_rq", "cli RecvQ KB"),
            ("trace.pipeline.backlog_kb_p50.chromium", "in Chromium KB"), ("trace.pipeline.backlog_kb_p50.origin_rq", "origin RecvQ KB"),
            ("trace.main_thread_busy", "main busy"), ("trace.cpu.by_type.renderer", "renderer cores"),
            ("trace.cpu.by_type.utility:mojom", "utility cores"), ("trace.cpu.server_cores", "server cores")]
    lines = ["\n## busy-case trace (medians over ok reps)\n", "| server (transport) | " + " | ".join(c[1] for c in cols) + " |",
             "|" + "---|" * (len(cols) + 1)]
    for tr in transports:
        for sv in servers:
            rs = [r for r in results if r.get("server") == sv and r.get("transport") == tr and r.get("case") == "busy" and r.get("trace")]
            if not rs:
                continue
            for r in rs:
                if r.get("small_ms"):
                    r["small_ms_p50"] = statistics.median(r["small_ms"])
            cells = []
            for key, _ in cols:
                v = med([g(r, key) for r in rs if g(r, key) is not None])
                if v is not None and key.endswith("bytes_in_window"):
                    v = v / 1000
                cells.append("-" if v is None else (f"{v:.2f}" if isinstance(v, float) and v < 10 else f"{v:.0f}" if isinstance(v, float) else str(v)))
            lines.append(f"| {sv} ({tr}) | " + " | ".join(cells) + " |")
    dl = [r for r in results if r.get("case") == "download" and r.get("cpu")]
    if dl:
        lines += ["\n## download CPU (medians): MiB/s, chrome cores, renderer cores, top thread, server cores\n",
                  "| server (transport) | MiB/s | chrome | renderer | top thread | server |", "|---|---|---|---|---|---|"]
        for tr in transports:
            for sv in servers:
                rs = [r for r in dl if r["server"] == sv and r["transport"] == tr]
                if rs:
                    top = rs[0]["cpu"]["top_threads"][:1]
                    lines.append(f"| {sv} ({tr}) | {med([r['mib_s'] for r in rs if r.get('mib_s')])} | {med([r['cpu']['chrome_cores'] for r in rs])} | "
                                 f"{med([r['cpu']['by_type'].get('renderer', 0) for r in rs])} | {top} | {med([r['cpu']['server_cores'] for r in rs if r['cpu']['server_cores'] is not None])} |")
    return "\n".join(lines) + "\n"


def meta(binaries):
    if _report is not None:
        return None  # report.write fills it
    def md5(p):
        try:
            return hashlib.md5(open(p, "rb").read()).hexdigest()
        except OSError:
            return None
    git = subprocess.run(["git", "-C", BENCH, "describe", "--always", "--dirty", "--tags"], capture_output=True, text=True).stdout.strip()
    return {"time": dt.datetime.now().isoformat(timespec="seconds"), "host": platform.node(), "kernel": platform.release(),
            "nproc": os.cpu_count(), "load1": round(os.getloadavg()[0], 2), "git": git or None, "argv": sys.argv,
            "binaries": {b: md5(b) for b in binaries if b}}


def write(path, binaries, **body):
    if _report is not None:
        return _report.write(path, "browser", binaries=binaries, **body)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump({"schema": "wispsuite/1", "kind": "browser", "meta": meta(binaries), **body}, f, indent=1)
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wst browser", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["compat", "timing"], default="compat")
    ap.add_argument("--server", action="append", help="repeatable; default: fw:$FINALWISP_BIN, epoxy, wisp-js")
    ap.add_argument("--transport", action="append", choices=["epoxy", "epoxy-v2", "libcurl"], help="repeatable; default epoxy (epoxy-v2 = epoxy with wisp_v2 on)")
    ap.add_argument("--reps", type=int, default=None, help="default 1 (compat), 6 (timing); use a multiple of the server count")
    ap.add_argument("--sites", default="", help="comma list of site names from sites.json (default: all of the mode)")
    ap.add_argument("--out", default=None, help="result JSON (default bench/results/browser-<stamp>/results.json)")
    ap.add_argument("--port-base", type=int, default=8400, help="page :B, mirror :B+1, wisp :B+10")
    ap.add_argument("--mirror-delay-ms", type=int, default=0, help="timing mode: fixed delay per origin response")
    ap.add_argument("--headful", action="store_true")
    ap.add_argument("--tls", action="store_true", help="Wisp over wss:// (fw: servers only): a self-signed P-256 pair made "
                    "for this run; Chromium trusts only that key (--ignore-certificate-errors-spki-list)")
    ap.add_argument("--trace", action="store_true", help="busy/download cases: per-request + per-Wisp-frame timing, "
                    "Chromium thread CPU and server CPU; raw traces in <out dir>/traces/, summary in results[].trace")
    a = ap.parse_args(argv)
    reps = a.reps or (6 if a.mode == "timing" else 1)
    if reps < 1:
        sys.exit("--reps must be >= 1")
    transports = a.transport or ["epoxy"]
    fw_default = os.environ.get("FINALWISP_BIN", os.path.join(ROOT, "server/target/release/finalwisp"))
    specs = a.server or ([f"fw:{fw_default}"] if a.tls else [f"fw:{fw_default}", "epoxy", "wisp-js"])
    if a.tls and a.trace:  # the trace's pipeline split compares WS frame bytes with kernel socket counters (TLS records)
        sys.exit("--tls with --trace is not supported: the pipeline split assumes a plaintext socket")
    stampv = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = a.out or os.path.join(BENCH, "results", f"browser-{stampv}", "results.json")
    odir = os.path.dirname(os.path.abspath(out))
    os.makedirs(odir, exist_ok=True)
    scratch = tempfile.mkdtemp(prefix="wst-browser-")  # private per run (configs; removed by the OS tmp cleaner)
    try:
        tls, spki = (tls_pair(scratch) if a.tls else (None, None))
    except (OSError, subprocess.CalledProcessError) as e:
        sys.exit(f"--tls: openssl failed: {(getattr(e, 'stderr', None) or b'').decode().strip() or e}")
    servers = [resolve(s, a.mode, scratch, tls) for s in specs]
    names = [s.name for s in servers]
    if len(set(names)) != len(names):
        sys.exit(f"duplicate server names {names}: use NAME=fw:PATH or NAME='cmd' to rename")
    if a.mode == "timing" and reps % len(servers):
        print(f"[browser] warning: {reps} reps over {len(servers)} servers: first-position counts are unequal", file=sys.stderr)
    cases = load_sites(a.mode)
    if a.sites:
        want = a.sites.split(",")
        unknown = sorted(set(want) - {c["site"] for c in cases})
        if unknown:
            sys.exit(f"unknown {a.mode} sites {unknown}; known: {', '.join(c['site'] for c in cases)}")
        cases = [c for c in cases if c["site"] in want]
    base = {"scramjet_dir": SCRAMJET, "page_port": a.port_base, "timeout_ms": 60000, "settle_ms": 2000, "headful": a.headful,
            "spki": spki}
    wport, mport = a.port_base + 10, a.port_base + 1
    mirror_proc, manifest = None, None
    for port in (a.port_base, wport) + ((mport,) if a.mode == "timing" else ()):
        if port_busy(port):
            sys.exit(f"port {port} is already in use (a stale run?): pick another --port-base")
    if a.mode == "timing":
        mdir = os.path.join(HERE, "mirror")
        if not os.path.isfile(os.path.join(mdir, "MANIFEST.json")):
            sys.exit("timing mode needs bench/browser/mirror: run python3 bench/browser/mirror.py first")
        manifest = json.load(open(os.path.join(mdir, "MANIFEST.json")))
        base.update(mirror_dir=mdir, mirror_port=mport, mirror_delay_ms=a.mirror_delay_ms, settle_ms=500)
        for c in cases:  # mirror URLs are relative in sites.json
            for k in ("url", "origin_url", "big_url", "cancel_url", "small_url"):
                if k in c and c[k].startswith("/"):
                    c[k] = f"http://127.0.0.1:{mport}{c[k]}"
        warm(mdir)
        mirror_proc = spawn(f"exec node {shlex.quote(os.path.join(HERE, 'scenario.mjs'))} --mirror {shlex.quote(mdir)} {mport} {a.mirror_delay_ms}",
                            HERE, os.path.join(odir, "mirror.log"))
        if not wait_port(mport, mirror_proc):
            stop(mirror_proc)
            sys.exit(f"mirror did not start (log {odir}/mirror.log)")
    started = dt.datetime.now().isoformat(timespec="seconds")
    results, runs, harness_errors, chromium = [], [], [], None
    power0 = power_state()
    power_log = [dict(power0, at="start")]
    print(f"[browser] power: {power0}", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        for rep in range(reps):
            k = rep % len(servers)
            order = servers[k:] + servers[:k]  # rotated: over a multiple of len(servers) reps each server goes first equally often
            for srv in order:
                for tr in transports:
                    log = os.path.join(odir, f"{srv.name}.stderr.log")
                    with open(log, "ab") as f:
                        f.write(f"\n=== rep {rep} transport {tr} {dt.datetime.now().isoformat(timespec='seconds')} ===\n".encode())
                    if port_busy(wport):
                        sys.exit(f"port {wport} still in use before starting {srv.name}: a previous server did not exit")
                    pw = power_state()
                    if pw != power0:
                        power_log.append(dict(pw, at=f"rep {rep} before {srv.name}/{tr}"))
                        if a.mode == "timing":
                            harness_errors.append(f"POWER STATE CHANGED mid-run: {power0} -> {pw} (rep {rep}); run aborted, re-run it")
                            raise PowerChanged
                    p, cmd = srv._start(wport, log)
                    try:
                        if not wait_port(wport, p):
                            harness_errors.append(f"{srv.name}: did not listen on :{wport} (log {log})")
                            for c in cases:
                                results.append({"server": srv.name, "transport": tr, "case": c["case"], "site": c["site"], "rep": rep,
                                                "ok": False, "error": "server did not start"})
                            continue
                        cfg = dict(base, wisp_url=f"{'wss' if tls else 'ws'}://127.0.0.1:{wport}/", transport=tr,
                                   cases=[dict(c, rep=rep) for c in cases], server_pid=p.pid, trace=a.trace,
                                   trace_dir=os.path.join(odir, "traces"), trace_prefix=f"{srv.name}-{tr}-r{rep}")
                        t0 = time.time()
                        res, err, harness, chromium = run_scenario(cfg, os.path.join(scratch, "scenario.json"), 120 + 150 * len(cases))
                        alive = p.poll() is None
                        got = {(r["case"], r["site"]) for r in res}
                        for r in res:
                            results.append(dict(r, server=srv.name, transport=tr))
                            if str(r.get("error") or "").startswith(("harness:", "sim init")):
                                harness_errors.append(f"{srv.name}/{tr} rep {rep} {r['site']}: {r['error'][:300]}")
                        for c in cases:
                            if (c["case"], c["site"]) not in got:
                                results.append({"server": srv.name, "transport": tr, "case": c["case"], "site": c["site"], "rep": rep,
                                                "ok": False, "error": harness or "no result"})
                        if harness:
                            harness_errors.append(f"{srv.name}/{tr} rep {rep}: {harness}: {err[-500:]}")
                        if not alive:
                            harness_errors.append(f"{srv.name}/{tr} rep {rep}: SERVER EXITED during the run (rc {p.returncode})")
                        runs.append({"server": srv.name, "transport": tr, "rep": rep, "cmd": cmd, "secs": round(time.time() - t0, 1),
                                     "server_alive_after": alive, "scenario_stderr_tail": err[-2000:]})
                        print(f"[browser] rep {rep} {srv.name}/{tr}: {sum(bool(r.get('ok')) for r in res)}/{len(cases)} ok "
                              f"({time.time() - t0:.0f}s){'' if alive else ' SERVER DIED'}", flush=True)
                    finally:
                        stop(p)
    except PowerChanged:
        pass  # recorded in harness_errors; results so far are kept but the run is marked broken (exit 1)
    finally:
        if mirror_proc:
            stop(mirror_proc)
    power_log.append(dict(power_state(), at="end"))
    if a.mode == "timing" and {k: power_log[-1][k] for k in power0} != power0:
        if not any("POWER" in e for e in harness_errors):
            harness_errors.append(f"POWER STATE CHANGED by the end: {power0} -> {power_log[-1]}")
    summary = summarize(results)
    table = md(summary, names, transports)
    stderr_tails = {s.name: tail(os.path.join(odir, f"{s.name}.stderr.log")) for s in servers}
    write(out, [s.binary for s in servers], mode=a.mode, tls=bool(tls), servers=[{"name": s.name, "binary": s.binary} for s in servers],
          runs=runs, transports=transports, reps=reps, cases=cases,
          mirror={"delay_ms": a.mirror_delay_ms, "manifest": manifest} if a.mode == "timing" else None,
          scramjet={"dir": SCRAMJET, "commit": subprocess.run(["git", "-C", SCRAMJET, "rev-parse", "--short", "HEAD"],
                                                               capture_output=True, text=True).stdout.strip() or None},
          chromium=chromium, power=power_log, started=started, ended=dt.datetime.now().isoformat(timespec="seconds"), results=results,
          summary=summary, harness_errors=harness_errors, server_stderr_tail=stderr_tails)
    ttable = trace_table(results, names, transports) if a.trace else ""
    with open(os.path.splitext(out)[0] + ".md", "w") as f:
        f.write(f"# browser sim, {a.mode} mode{', Wisp over wss:// (--tls)' if tls else ''}, {started}\n\npower: {power_log}\n\n{table}{ttable}")
        if harness_errors:
            f.write("\nharness errors:\n" + "\n".join(f"- {e}" for e in harness_errors) + "\n")
    print(table + ttable)
    print(f"[browser] wrote {out}")
    failed = any(not r.get("ok") for r in results)
    sys.exit(1 if (harness_errors or (a.mode == "compat" and failed)) else 0)

if __name__ == "__main__":
    main()
