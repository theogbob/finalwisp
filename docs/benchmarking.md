# Benchmarking Wisp servers

This repository ships the tools behind the [benchmark results](benchmarks.md). They work with any Wisp server, not
only finalwisp, so you can check the numbers on your own hardware or compare a server of your own.

- **`wbench`** is the load generator, written in Rust. It opens Wisp connections and streams, pushes data through
  them, and also runs the plain TCP targets (echo, sink, source) that the streams connect to.
- **`bench/wst`** is the test suite, in Python (standard library only). It starts each server, runs `wbench` against
  it, samples the server's CPU and memory, and prints a table.

Requirements: Linux, Python 3, a Rust toolchain for `wbench`, and whatever each server you test needs (Node.js, Go,
Python). No root is needed for the commands on this page.

## Quick start

```sh
# build the load generator (once)
cd bench && cargo build --release && cd ..

# build finalwisp
cd server && cargo build --release && cd ..

# compare finalwisp with any other server you have
bench/wst showdown --servers finalwisp,'myserver=/path/to/myserver --port {port}'
```

`wst` finds `wbench` in `bench/target/release/wbench`. Set the `WBENCH` environment variable to use another copy (a
matrix file can also name one with its `wbench` key).

## The commands

`bench/wst --help` lists every command, and `bench/wst COMMAND --help` explains one. These are the ones you need for
comparing servers:

| command | what it does |
|---|---|
| `showdown` | A live, visual head-to-head of several servers on this machine. The easiest start. |
| `matrix CONFIG.json` | Every server against every test case from a JSON file, as a table. This is how the published results were made. |
| `ab VARIANTS.json REPS ...` | A rotated, interleaved A/B test of a few server commands on one test, with all raw values. |
| `idle SERVER...` | Memory per idle connection. |
| `compat --server NAME` | Protocol tests against any server (report mode): a real wisp-js client, UDP, malformed input. |

The other commands (`regress`, `potato`, `link`, `wispmark`, `browser`, `compat --bin`) are finalwisp's own release
gates and research tools; `bench/README.md` describes them.

Every server, target and client that `wst` starts runs in its own process group. Ctrl-C stops all of them. `wst` also
refuses to start if another process already listens on a port it needs, because a leftover target would silently take
half of the streams.

### showdown

```sh
bench/wst showdown                                   # finalwisp, epoxy, wisp-js, python, wispurr: 4 key tests
                                                     # (set up the other servers first, see below)
bench/wst showdown --all                             # all 8 test cases
bench/wst showdown --servers finalwisp,epoxy --duration 8
bench/wst showdown --servers fw:path/to/finalwisp,epoxy
bench/wst showdown --case download:100:10 --case rr:10:10:64
```

For each server and test it shows the result, the CPU cores the server used, the cores the client used (to prove that
the load generator was not the limit), and the server's peak memory. Results are also saved as JSON in the `results`
directory inside `bench/`.

### matrix

```sh
bench/wst matrix bench/matrix.main.json --reps 3
bench/wst matrix bench/matrix.main.json --only finalwisp epoxy
```

`--reps N` runs the whole matrix N times, changes the server order each time, and adds a table of medians. The
published results use the cases of `bench/matrix.main.json`, with the median of 3 reps.

### ab

```sh
cat > variants.json <<'EOF'
{
  "fw":         "server/target/release/finalwisp --allow-loopback --allow-private",
  "fw-balance": "server/target/release/finalwisp --allow-loopback --allow-private --balance"
}
EOF
bench/wst ab variants.json 6 --test download --conns 10 --streams 10
```

Run it from the repository root. Each value is a server command; `wst` appends `--port PORT`, so the server must take that option (wrap it in a
small script if it does not). Each rep runs every variant once, and the starting variant rotates. Everything after the
suite's own options goes to `wbench run` (`--test`, `--conns`, `--streams`, `--size`, ...). `--raw FILE` saves one JSON
record per run. The output is one JSON line per variant with the median and all values of the main metric, plus the
server's CPU and memory.

### idle

```sh
bench/wst idle finalwisp epoxy --n 2000 --reps 6
```

Opens N connections that each echo a little data once and then sit idle, waits until the server's memory is stable,
and reports KiB per idle connection. With two servers it adds their ratio and a paired significance test.

### compat --server

```sh
bench/wst compat --server epoxy
bench/wst compat --server 'myserver=/path/to/myserver --port {port}'
```

Runs the protocol-generic tests, a fresh server for each: the wisp-js client over TCP and UDP, UDP checks, a set of
malformed and adversarial inputs, and a UDP burst that the server must survive. It prints a PASS/FAIL table. Some
adversarial checks test finalwisp's own choices, so read the FAIL lines: not all of them are bugs. Needs Node.js
(`cd tests/compat && npm ci`) and openssl.

## Servers

Anywhere `wst` asks for a server you can give:

- a name from `bench/servers.json` (`finalwisp`, `epoxy`, `wisp-js`, `python`, `wispurr`, ...);
- `fw:PATH [args]`: any finalwisp binary (`wst` adds `--allow-loopback --allow-private`, because the targets are on
  127.0.0.1);
- `NAME='COMMAND'`: any other server. The command must contain `{port}`.

`FINALWISP_BIN=/path/to/finalwisp` changes the binary of the `finalwisp` entry (default:
`server/target/release/finalwisp`).

### Setting up the other servers

The registry expects the other servers at fixed paths under the repository. `ref/` is ignored by git, so clone them
there:

| entry | setup |
|---|---|
| `epoxy` | `git clone https://github.com/MercuryWorkshop/epoxy-tls ref/epoxy-tls && (cd ref/epoxy-tls && cargo build --release -p epoxy-server)` |
| `python` | `git clone https://github.com/MercuryWorkshop/wisp-server-python ref/wisp-server-python && python3 -m venv baselines/python/.venv && baselines/python/.venv/bin/pip install ./ref/wisp-server-python` |
| `wisp-js` | `(cd baselines/js-server && npm ci)` |
| `wispurr` | see below |

The published results used wisp-server-python 0.9.0 and wisp-js 0.5.0 (pinned in `baselines/js-server/package-lock.json`).
Newer versions may give other numbers; write down the commit you tested.

**wispurr** needs two steps:

1. Build it: clone https://github.com/sylvieisnton/wispurr into `ref/wispurr` (the results used commit `2afbad2`),
   then `cd ref/wispurr && go build -o ../../baselines/wispurr/wispurr main.go`.
2. Copy its speed configuration. The author's `speed.config.json` is not shipped in this repository (wispurr is
   AGPL-3.0 licensed). Copy it from the wispurr repository to `baselines/wispurr/speed.config.json`, then set
   `allowDirectIP`, `allowPrivateIPs` and `allowLoopbackIPs` to `true` (the targets are on 127.0.0.1), `allowUDP` to
   `false` and `logLevel` to `error`.

`baselines/wispurr/SOURCE.md` has the details and the bugs found in the tested version.

### Adding a server to the registry

`bench/servers.json` maps a name to the way to start the server:

```json
{
  "servers": {
    "myserver": {
      "cmd": "{root}/ref/myserver/target/release/myserver --config {dir}/myserver-{port}.toml",
      "files": {
        "myserver-{port}.toml": "listen = \"127.0.0.1:{port}\"\nallow_loopback = true\n"
      },
      "extra": ["--stall-ping-ms", "1"],
      "note": "what this entry is"
    }
  }
}
```

| key | meaning |
|---|---|
| `cmd` | Shell command that starts the server in the foreground. Placeholders: `{port}`, `{root}` (the repository), `{bench}`, `{dir}` (a scratch directory for generated files), `{fw}` (the finalwisp binary). `exec` is added in front when the command is a single program, so signals and CPU sampling reach the server itself. |
| `cwd` | Working directory (placeholders allowed). Optional. |
| `env` | Extra environment variables. Optional. |
| `files` | Config files to write into `{dir}` before the start: file name to text, or `{"json_base": PATH, "set": {...}}` to copy a JSON file with some keys changed. Optional. |
| `extra` | Extra `wbench run` arguments for every test of this server. Optional. |
| `ready_timeout` | Seconds to wait until the server accepts connections (default 20). |
| `note` | Free text. |

The server must listen on `127.0.0.1:{port}`, serve Wisp at `/`, and allow targets on loopback (the test targets
are on 127.0.0.1).

About `--stall-ping-ms 1`: some servers queue a Wisp CONTINUE packet without sending it until something else wakes
them up (epoxy-server's upload is one). This `wbench` option sends a WebSocket ping after 1 ms without traffic, which
unsticks them. The registry gives it to every server except finalwisp, which does not need it.

## Matrix files

A matrix file lists the servers and the test cases:

```json
{
  "duration": 5,
  "warmup": 1,
  "port": 6001,
  "servers": [
    "finalwisp",
    "epoxy",
    "fw:/opt/fw/finalwisp --balance",
    {"name": "myserver", "cmd": "exec /opt/myserver --port {port}", "extra": ["--stall-ping-ms", "1"]}
  ],
  "cases": [
    {"test": "upload",   "conns": 1,  "streams": 1,  "size": 16384},
    {"test": "download", "conns": 10, "streams": 10},
    {"test": "echo",     "conns": 10, "streams": 10, "size": 16384},
    {"test": "rr",       "conns": 10, "streams": 10, "size": 64},
    {"test": "churn",    "conns": 10, "streams": 10, "size": 64}
  ]
}
```

- `duration` and `warmup` are seconds per case. `port` is the server's port; the targets use the next four ports
  (`target_port` moves them).
- `servers` entries are registry names, `fw:PATH args`, or full entries with the keys from the table above plus `name`.
- `wbench` (optional) is the path to `wbench`, relative to the matrix file.
- Each case can also set its own `duration`, `warmup` and `extra` (`wbench run` arguments).

`bench/matrix.main.json` is the published comparison and `bench/matrix.example.json` a shorter one.

### Test cases

| `test` | what it measures | result |
|---|---|---|
| `upload` | the client sends as fast as it can; the target discards | MiB/s up |
| `download` | the target sends as fast as it can | MiB/s down |
| `echo` | the client sends; the target sends everything back | MiB/s each way |
| `rr` | request/response: one `size`-byte message, wait for the echo, repeat | requests/s, latency |
| `churn` | like `rr`, but every request opens a new stream | streams/s, latency |
| `connchurn` | every request opens a new WebSocket connection | connections/s, latency |
| `browse` | page-like bursts of short streams, optionally with bulk downloads beside them | requests/s, latency |

`conns` x `streams` is the load: 10 x 10 is 10 WebSocket connections with 10 streams each. `size` is the payload of
each Wisp DATA packet (default 16384 for upload and echo, 64 for `rr` and `churn`). `bench/target/release/wbench run
--help` lists every option.

## Reading the results

`matrix` prints one row per server and case:

| column | meaning |
|---|---|
| `MiB/s up`, `MiB/s down` | payload throughput (MiB = 2^20 bytes) |
| `rps` | requests (or streams, or connections) per second |
| `p50 us`, `p99 us`, `p999 us` | latency percentiles in microseconds |
| `errors` | failed streams or connections. A cell with errors is suspect. |
| `srv CPU%` | server CPU over the case; 100 = one core |
| `srv RSS MiB` | server resident memory right after the case |

Each run is also saved as JSON in the `results` directory inside `bench/` (`--out-dir` changes it), with the machine
(CPU, cores, kernel, load), the git commit and the md5 of `wbench`. Keep it with any number you publish, and note the
versions or checksums of the servers yourself.

Rules of thumb:

- Compare servers only within one run of one machine. Absolute numbers change with the CPU, the kernel and its
  settings, and on a laptop with the power profile and the charger.
- Use medians of several reps (`--reps 3` or more). A single run can be far off.
- Look at the client's CPU (`showdown` shows it). If the client is at its limit, you measured `wbench`, not the server.
- A server with `0` or errors in a cell did not work in that test; say so instead of averaging it in.

## Pitfalls

### TCP memory pressure

Linux has one TCP memory limit for the whole host (`net.ipv4.tcp_mem`). Fast bulk tests with many streams can reach
it on a machine with a few GB of RAM. The kernel then shrinks socket buffers, and throughput swings for every server.
Such a cell is invalid.

`wst matrix` and `wst showdown` do not check this, so check it yourself. Read the kernel counter before and after a
run:

```sh
nstat -az TcpExtTCPMemoryPressures
```

If the value grew, at least one cell ran under pressure. Run the bulk cases one at a time to find which, or use fewer
streams (the published VPS results use 10 x 2 instead of 10 x 10 for that reason). `wst ab` records the host's peak
TCP memory for every run in its raw records (`tcp_mem_peak`, and `at_tcp_mem_max` when it reached the hard limit).

### The load generator shares the machine

`wbench`, the targets and the server all run on one machine. On a small machine they compete for the same cores, so
every server looks slower than it would be on its own. That is fair between servers, but it is not the server's real
capacity. On machines with many cores, give the client enough threads (`wbench run --threads`, default: all CPUs).

### Ports and leftovers

`wst` needs its ports free (for example 6001 to 6005 for `matrix`). It stops before the run if something already
listens there. Before the stream churn test, `showdown` waits for old `TIME_WAIT` sockets to drain (`--tw-wait`).

### Loopback is not a network

All of this runs over loopback without TLS. It shows the most each server can move. Over a real link, the link and the
round-trip time usually set the limit long before the server does.
