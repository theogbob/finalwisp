> **Benchmarking a Wisp server?** Start with [docs/benchmarking.md](../docs/benchmarking.md): setup, the commands
> that matter, the server and matrix formats, and the pitfalls. This file is the full reference for every command,
> including finalwisp's own release gates.

# bench/: the wisp test suite (pointer 30.10)

One entry point for every functional gate and benchmark of finalwisp, usable on any other Wisp server too:

```
bench/wst <command> [args]        # = cd bench && python3 -m wispsuite <command>
bench/wst <command> --help
```

Requirements: Linux, python3 (stdlib only), the `wbench` load generator (`cd bench && cargo build --release`).
`compat` also needs node (tests/compat: `npm ci`), openssl, cargo; `potato` needs user systemd scopes with a
delegated memory controller (or root); `link` needs root (network namespaces). No sudo otherwise.

| command | what | replaces |
|---|---|---|
| `compat --bin FW [--matrix]` | all functional gates on a finalwisp build; exit 1 on ANY failure (incl. cargo test) | gates.py |
| `compat --server NAME` | the protocol-generic tests on any server (report mode) | - |
| `ab VARIANTS.json REPS --test ...` | rotated interleaved A/B, RAW records | ab.py, vps/vps_ab.py, tls_sanity.py |
| `regress --base B --new N` | Phase B gate (60.01): lo/tls/idle/link/potato, exact paired Wilcoxon, LOSS re-run | regress.py |
| `matrix CONFIG.json [--reps N]` | servers x cases table (+ medians) | run_matrix.py, median_runs.py |
| `showdown` | live visual head-to-head | showdown.py |
| `wispmark [--profile current/upstream]` | WispMark grid with the real clients | wispmark.py |
| `potato --bin N=PATH ...` | survival + throughput under MemoryMax 16-128 MiB | potato_curve.py, potato_ab.py |
| `link up/down/ab` | root: rate/delay netns link, A/B over it | vps/netns_hol.sh by hand |
| `idle SERVER...` | KiB per idle connection | idle_rss.py by hand |
| `browser [--full]` | real-user simulator: headless Chromium + Scramjet over Wisp (bench/browser/README.md) | - |

The old commands (`ab.py`, `regress.py`, `run_matrix.py`, `showdown.py`, `wispmark.py`, `gates.py`,
`potato_curve.py`, `idle_rss.py`) still work with the same command lines; they are thin wrappers.

## browser (real-user simulator)
`wst browser` runs bench/browser/browser.py (setup: node, Playwright Chromium, a Scramjet build; see
bench/browser/README.md). Default = quick compat subset with the epoxy transport: wikipedia, hn,
wikipedia-session, ws-echo, cloudflare-25MiB, busy-user (real internet, about 1-2 min per server).
`--full` = every case x epoxy, epoxy-v2, libcurl. Explicit `--sites` / `--transport` win; other options pass
through (`--server`, `--reps`, `--mode timing`, `--port-base`, default 8400 / 8401 / 8410). Compat mode exits 1 on
any failure. Timing mode uses a local mirror and needs the machine lock.
```
bench/wst browser --server fw:server/target/release/finalwisp            # quick
bench/wst browser --full --server fw:FW --server epoxy --server wisp-js  # everything
```

## Servers
`bench/servers.json` is the one server registry (finalwisp, epoxy, epoxy-single/multi, wisp-js, wisp-js-0.4.1,
python, python-wispmark, wispurr, wispurr-wispmark; unofficial, for fun only: wispx, wispx-nodelay = WispX-Rust,
an epoxy-server fork, binary at ref/wispx-rust/epoxy-server: build it in a container from github.com/Redgale/WispX-Rust with
`cargo build --release -p epoxy-server`). Paths are relative to the repo root (`{root}`), generated
config files go to
`bench/results/stale/wst-scratch/` (gitignored). Anywhere a server is asked for you can also give
- `fw:PATH [args]`: any finalwisp build (adds `--allow-loopback --allow-private`);
- `NAME='command --port {port}'`: any other Wisp server.
`$FINALWISP_BIN` overrides the `finalwisp` entry's binary (default `server/target/release/finalwisp`).

## Shared library (bench/wispsuite/)
| module | contents |
|---|---|
| proc.py | spawn in a new session, process registry, stop a whole group (TERM, then KILL, wait until gone), SIGTERM/SIGINT/exit handlers, stray checks (listener in /proc/net/tcp* or `port N` in a command line), wait_port |
| sample.py | process-group CPU / RSS / peak RSS (VmHWM, wrappers skipped), cgroup scope stats, TcpExt memory pressure, steal |
| stats.py | exact Wilcoxon signed-rank, compare (ratio of medians), verdict (LOSS/WIN/watch/tie), median without placeholders |
| wbench.py | wbench lookup, targets, one run -> JSON |
| servers.py | the registry, `fw:` / custom servers |
| report.py | result JSON (`"schema": "wispsuite/1"`, `"kind"`, `"meta"`: time, host, kernel, cpu, nproc, load, git rev, argv, md5 of binaries, `power` at start and end: power-profiles-daemon profile, cpufreq policy0 EPP + governor, AC online, battery status, and which of profile/EPP/governor/AC changed) |

Units: MiB = 2^20 bytes, KiB = 2^10, GiB/s = 1024 MiB/s everywhere (wbench, RSS, cgroups). Counts (req/s, k, M)
are decimal.

Every child runs in its own process group and is registered: Ctrl-C or SIGTERM to any command stops every
server, target and client it started (no strays). A stray listener or `port N` process on a port the command
needs stops it before it starts (a leftover reuseport target takes half the streams silently).

## Typical use
```
bench/wst compat --bin server/target/release/finalwisp                    # before merging anything
bench/wst compat --bin FW --matrix                                         # + --no-splice/--balance/--no-tfo/--graceful-close
bench/wst regress --base BASE_BIN --new FW --cert C --key K --out bench/results/regress/NAME
bench/wst regress ... --new-args=--log-conns                               # cost of a feature while ON
bench/wst showdown --servers fw:FW,epoxy,wisp-js
bench/wst wispmark --profile upstream --duration 10
bench/wst compat --server epoxy                                            # a competitor, report mode
```
Laptops: the power profile and AC state change absolute numbers (one regress saw wss 2x higher for both builds
than 30 min later). `regress` prints the power state at start and end in its header and adds a PROBLEM if the
profile, EPP, governor or AC state changed during the run. Paired verdicts within one run stay valid; absolute
numbers are only comparable across runs with the same power state.
Connection-cost cases (30.10): `connchurn` (wbench test: a NEW WebSocket connection per request: connect,
upgrade, TLS with wss, CONNECT one stream, 64 B echo, close; rps = connections/s, p50/p99 per connection from
TCP connect to the echo; `churn` reuses its connections) and `burstidle` (suite-side, `ab`/`regress`: 3 x (5 s
download 10x10 on new connections, 3 s idle) against one server process; per-burst MiB/s, server CPU% per burst
and per idle gap). regress lo runs `connchurn 10x10` (rps, p99) and `burstidle 10x10` (~24 s per run whatever
--dur is), tls runs `connchurn-tls 10x10`.
Byte integrity at rate (60.15 T06, bench/src/verify.rs): `wbench target --mode source|sink --verify` with
`wbench run --test download|upload --verify`. Each stream carries a keyed, numbered nonzero pattern instead of
zeros; the receiver checks every byte; after the window an END handshake (up to 15 s, unmeasured) reconciles the
target's sent/received counts with the client's. Prints a `verify:` line and `verify_*` JSON fields (streams/ok,
content errors, count mismatches, missing END, bytes both ways); verify errors are not in `errors`; any of them:
exit 4. Off by default. Checker speed: `cd bench && cargo test --release -- --ignored --nocapture speed`
(laptop ~27 GiB/s per core). The suite (`ab`/`regress`) does not use it; run it by hand next to a number to prove it.
`regress` ports: A/B 6901/6902, idle 6911/6912, potato 6610-6613 (or `--port-base P` for P..P+7).
`compat` uses base-port .. base-port+79 (default 8300).

## Cross-host (real network between two boxes)
`wst regress ... --client-ssh root@HOST` and `wst ab ... --client-ssh root@HOST` (bench/wispsuite/xhost.py, root):
the servers and wbench targets run on this box bound to its address facing HOST (`--server-ip` overrides),
`wbench run` runs on HOST over `ssh -o BatchMode=yes` (JSON back on stdout). Public addresses: regress adds no
`--allow-*` flag (use `--args=--allow-private` on a private LAN). Suites: lo, tls (default lo,tls).
- Safety: during the run iptables INPUT rules (comment `wst-xhost`) accept the two ports only from HOST and lo and
  drop them from everyone else; removed on exit, error, SIGTERM/SIGINT/SIGHUP. A leftover rule (SIGKILLed run)
  stops the next run until `--force-clean`.
- HOST needs wbench at the same path (md5 compared; a mismatch is a PROBLEM). A `wbench run` already running on
  HOST stops the run. The remote run is wrapped in `timeout` and started with `ssh -tt`, so killing the local ssh
  ends it.
- TCP memory pressure is checked on both boxes; RAW records and the summary header carry `link xhost:HOST`.

## VPS
Copy `bench/wst`, `bench/wispsuite/`, `bench/servers.json`, `bench/vps/` and a `wbench` binary into one
directory; `wbench` next to `wst` is found automatically (or `$WBENCH`).

## Tools (bench/tools/)
- `disasm_norm.py A B [--fold PREFIX] [--show N]`: per-function normalized `objdump` compare of two release builds;
  exit 0 = every function identical after normalization (no raw bytes, no data sections; see its docstring). The evidence for pure refactors (module moves, renames, comments): build both
  commits with bench/release.sh and compare (before 60.18 #11 also the `NOFEAT=1` build); `--fold finalwisp::worker` for moves into
  worker/ submodules. Used for the 60.16 #10 worker.rs split (3276/3276 functions vs base-4-rc1). Data sections are
  not compared (line numbers move them).

## Probes (bench/probes/, bench/vps/)
Single-file tools for one question each; they run inside network namespaces on the VPS, so they stay standalone:
dns_burst.py, dns_hol.py, dns_neg.py (DNS pool), connect_latency.py (HE / TFO), pipe_probe.py (splice pipes),
tls_cmp.py (TLS deployments), vps/netns_hol.sh (rate/delay link), vps/netns_setup.sh (HE/TFO net),
vps/dns_run.sh, vps/slowdns.py, vps/tfo_echo.py.

## WispMark comparison
`wst wispmark` runs WispMark's grid (github.com/MercuryWorkshop/WispMark, checked at cc512c9): the same four
clients (wisp-js 10 / 5x10 streams of 50 KiB sends, epoxy simple-wisp-client `-s 10 -p 50` x1 / x5), the same
server configs, 1 s warm-up, then DURATION s, score = in+out bytes at the echo port in MiB/s (2^20).
- `--profile upstream`: WispMark's pins (wisp-js 0.4.1 client + server with DEBUG logging).
- `--profile current` (default): wisp-js 0.5.0 at its default log level (project policy since 2026-10-22).
- Echo target: wbench's tokio echo (counts bytes itself) instead of tokio's echo-tcp example.
- Counting: TCP payload at the echo server over the exact window, no sudo. WispMark uses `sudo iftop` (IP bytes,
  divided by wall time around iftop incl. its start-up, 3 significant digits): it reads a few % lower and can
  drop packets at multi-GiB/s. Rankings agree unless two servers are within ~5%.
- WispMark sets `websocketTcpNoDelay` for mrrowisp; wispurr (its successor) has no such key.

## Retired
`bench/legacy/` (README there) keeps one-off scripts that are no longer maintained.
