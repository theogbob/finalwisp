# Changelog

## v1.6.0

A minor release because the way download streams move data changed: with the priority lane (the default), a download
stream can now wait for the splice pipe instead of copying its next bytes (below). This release adds no option.

Changed:

- **A download stream can wait for the splice pipe instead of copying.** With the priority lane (the default;
  `--no-prio` turns it off), a bulk download stream whose next read cannot use `splice()` can now pause instead of
  moving its next bytes at once with `read()` and `send()`: while the connection's pipe still holds data, while its own
  frames are queued in the bulk lane, or until the other streams' bulk frames queued at that moment have gone out. That
  last wait starts only when nothing waits in the priority queue and happens at most once between two reads (a
  connection moved to another thread starts afresh); after it the stream reads as before (by `splice()` when it can,
  else by copy). The new wait does not apply past the output caps, during a kTLS send-starvation episode, or without
  splicing. The caps are unchanged, but a paused download stream, also one paused at a cap, now resumes only once the
  pipe has drained, except during a kTLS send-starvation episode. On a 2-core VPS, a download test with 10 connections
  of two streams each moved about 11 % of its bytes by copy before and 0.1 % now (two connections of two streams: 10 %
  and 0.02 %). In VM page tests on a full 100 Mbit link, downloads gave up 1-2 % of their throughput to the page loads
  in two of five setups, and two downloads on one connection shared the link more evenly; with real Wisp clients on a
  similar link, no throughput loss was reproduced. No option.

## v1.5.0

A minor release because a default changed for connections without an `Origin` header (browsers send one): when a
destination ends an open TCP stream, its CLOSE now waits up to 1 second for the client's answer to a WebSocket ping
(below). This release adds no option.

Changed:

- **A stream's CLOSE waits for the client's answer to a WebSocket ping.** When a destination ends an open TCP
  stream, finalwisp sends a ping behind the stream's last data and sends the Wisp CLOSE when the pong comes back, at
  most 1 second later. A pong from the client shows that its WebSocket layer has read the stream's last data (not that
  the application has used it), so that data no longer arrives in the same read as the CLOSE. Connections whose upgrade
  request carried an `Origin` header (browsers send one), `0x49` and UDP streams are not affected. No option; it costs
  about one round trip at each such stream end. Details and known limits (a proxy that answers pings itself, the 1 s
  cap): [close codes](docs/logs-metrics.md#wisp-close-codes).
- `finalwisp_close_total` counts CLOSE packets sent: a held CLOSE that is never sent (the client closed the stream
  while it waited, or the connection ended) is not counted. New counters `finalwisp_ping_gate_*_total`
  ([metrics](docs/logs-metrics.md#metrics-and-prometheus)).
- Graceful shutdown: an idle connection whose CLOSEs wait for a pong gets its 1001 once they are sent, at most 1 s
  later.

Fixed:

- **Downloads move less data through user space when the client is slow.** A download that waits for its client
  pauses and is resumed when the client has taken data. A wake-up left over from before the pause could resume it
  early, while its last data was still on its way out; the server then moved that download's next bytes with
  `read()` and `send()` instead of `splice()`. Now a paused download resumes only when it is released (its client
  took data, or a retry of a stalled kTLS send). On a 2-core VPS, in a download test with 10 connections of one stream
  each, 17 % of the bytes went that way before and 4 % now (one stream on one connection: 13 % and 8 %; medians of
  3 runs each); with two streams per connection the share did not change. In a single-stream download test on the
  same VPS the download rate rose by 5 % (two sessions of 16 rounds each), and the server's CPU time per GiB fell by
  8 % (measured in the second session). No option.

## v1.4.0

A minor release because `--preset public` changed: it now turns on `--unread-close`. A plain `finalwisp` starts as
before. This release adds no option; it closes most of the gaps that 1.3.x left open (tests, documented limits, old
claims).

Changed in `--preset public` (the Docker image and `contrib/finalwisp.service` start with it):

- **The preset turns on `--unread-close`.** It acts only while the host's TCP memory is short (from 3/4 of
  `net.ipv4.tcp_mem`'s maximum). Then it resets a connection that has stopped taking data from its downloads, once
  that connection's stall time is used up, and it moves the bytes of waiting downloads into the server so their
  destinations do not time out (below). The preset start line lists `unread-close on`. `--no-unread-close` undoes it.
  - In tests with two VMs under held TCP memory pressure (90 minutes each, Linux 6.12 and 6.8): the clients that took
    nothing, or only a few bytes, were reset after 621 to 811 seconds; honest readers of 1 to 8 KiB per second, also
    with 32 MiB buffers, were kept and lost no stream. With 1.3.3's preset, 3 of those honest readers lost their
    download (CLOSE `0x03`) in each of the same runs.
  - A client that pauses for 10 minutes or more in all without taking data can be reset while the host's TCP memory is
    short. In the tests, a client that read for 5 minutes and then paused for 30 was reset; one that read for 5
    minutes and paused for 20 was kept (the data it took first had bought it the time). A reset client gets an error;
    a new connection starts with new time.
  - Timed on two 2-core VPSes, both with the preset, against 1.3.3 (20 cells, 16 runs each): 12 read the same, 7
    unclear or watch, and 1 first reading was lower (a download test where every run of every server ran short of TCP
    memory); its rerun (32 rounds per arm) showed no loss.

Changed:

- `--unread-close` has a new rule for how long a client may take no data. Before, each stall had 600 seconds, and any
  byte taken started them again, so a client that took a few bytes now and then was never reset. Now each connection
  starts with 600 seconds of stall time; data the client takes adds 1 second per 512 bytes, up to 3600 seconds (the
  first data, what filled the client's buffer, adds 1 second per 4 KiB); a connection that holds more of the host's
  TCP memory than one stream can uses its time up faster. So a slow reader with a large buffer, which takes no data
  for minutes while its buffer drains, has paid for that time, and a client that takes nothing gets 600 seconds in
  all. Details: [configuration](docs/configuration.md#--unread-close).
- `--unread-close` also relieves waiting downloads while the host's TCP memory is short (Linux 5.15 or later). A
  waiting download's target socket that holds more than half of its share of `tcp_mem` gets a receive buffer of half
  the share and is read out into its client's queue, so the socket can take the destination's data again and the
  destination does not time out the stream (CLOSE `0x03` after about 15 minutes; in the tests above, 0 such closes
  with relief against 3 to 4 without). The moved bytes use at most a quarter of the memory budget. Below 5.15, or
  without a readable `tcp_mem`, a start logs one line and the reset part works as before (it needs Linux 5.4 or
  later). Counters `relief_bytes`, `relief_streams` and `relief_capped`. `--no-unread-close` turns off both parts.
- `--dest-failfast`: a destination is taken for dead only from connects near their connect timeout (the last 2.5
  seconds: from 7.5 s of the default 10 s). A host that answers only a late SYN (in the test, the 5th, about 4 s after
  the first) no longer loses streams of a large page: before, 1 to 6 of 70 streams in about half of the page loads.
- `--dest-failfast`: one client address may have 64 connects in flight per worker thread that get no answer. Above
  that, its new connects to such destinations, or to destinations without an open stream, get CLOSE `0x43` at once
  (counter `refuse_dest_dead`). With 1,000 distinct dead destinations the server now holds about 250 to 600 file
  descriptors instead of up to 4,158 (without the option, about 20,000).
- A client that sends frames over 256 KiB within its credit can no longer push one stream's upload backlog past 64 MiB
  + 256 KiB: such a frame closes that stream with CLOSE `0x49` (counter `shed_hold`); the connection and its other
  streams go on. Clients with ordinary frames (64 KiB) are only paused, as before.
- `--port 0` (or a bare `0`) is refused at start with an error. Before, the kernel picked a random port that the start
  line did not show.
- A WebSocket Close from a client whose reason text is not valid UTF-8 is answered with close code 1007 (RFC 6455)
  instead of an echo of its code. Wisp clients send no reason text or a UTF-8 one, so they see no change.
- Adaptive splice reads a client's round trip only when it needs it (the first time the client has more than 4 streams
  and a backed-up socket), once per connection. Before, every accepted TCP connection paid one extra `getsockopt`; a
  connection that only opens one stream now makes one system call less. A connection that first needs it 4 to 4.5
  minutes or more after it connected keeps the 256 KiB reads. New counters `splice_near`, `splice_far` and
  `splice_old`.
- The kTLS cipher is picked by the cipher suite's code instead of its printed name, so a rename in a dependency update
  cannot turn off kTLS for every suite.

Fixed:

- When the server closes a connection whose client is still sending (after a protocol error, or a refused request with
  more data behind it), the client now gets every byte the server queued and a clean close, not a reset. The server
  ends its direction and reads and discards the client's input until the client closes, for at most 5 seconds (10 with
  the built-in TLS) or 1 MiB. New counter `linger_capped`: closes at one of these bounds.
- With `--stream-pool` (in `--preset public`), a WebSocket proxy (wsproxy) request over the shared stream limit now
  gets `503 Service Unavailable` (counted as `refuse_streams`) instead of a 101 and then the close of its stream.
- A client that times out (TCP keepalive or retransmission timeout) while it is not read under memory pressure, or
  while its connection is closing, now counts in `dead_peers`. A paused client's `--log-conns` line says `dead_peer`;
  a closing client's line keeps the reason it was closing for.

Deprecated:

- `--park-rcvlock` has no effect since 1.4.0 (`--unread-close` manages these receive buffers). It is still accepted on
  the command line and in config files, and a start logs one line. `rcvlock_locks` and `rcvlock_errors` stay in the
  metrics, always 0.

Documentation:

- The v1.1.0 entry is corrected (2026-11-16): on a second 2-core VPS with smaller socket buffers, server memory in the
  100-stream echo test went from 206 to 158 MiB (not 4-10x less), and the other machines read 4-7x, not 4-10x.
- The known limit on idle memory no longer gives a number ("under 2 MiB"): no test measured such a bound.
- Reproducible builds: the binary follows the `libc6-dev` package, not only the glibc version; `bench/release.sh
  --compare-ci` checks it.
- [Built-in TLS](docs/tls.md) lists the kernels tested in VMs: 4.18 to 6.8 (Rocky 8, Ubuntu 20.04, 22.04 and 24.04,
  Debian 11 and 12; Debian 11 has no `wss://` because its kernel has no kTLS).
- [Memory](docs/memory.md): do not set `ulimit -v` below 1 GiB (with 512 MiB the server stopped on a failed allocation
  under load).
- `--auto-balance`: its cost to a busy process on the same cores was about 0.1% of that process's work.
- Known limits: a UDP stream has no idle timeout; the TIME_WAIT table can fill when the server and its destinations
  share a host; the Docker form of the open-file limit; the kernel's connection-tracking log line.
- The start samples in the docs are the output of 1.4.0.

Tests:

- Old kernels: the 1.3.3 binary passed its functional checks in VMs with Linux 4.18 (cgroup v1), 5.4 (cgroup v1),
  5.10, 5.15, 6.1 and 6.8 (this release changes no kernel-dependent path except the relief of `--unread-close`, which
  logs that it is not in effect below 5.15). Kernel TCP memory pressure and a narrow source port range were tested end
  to end in a VM (19 of 19 checks).
- Fuzzing: the worker fuzz target got a variant with the preset's limits on; a 12-hour campaign on the 1.3.3 code (14
  targets, 5.4 billion runs) found no bug in the server.
- Timing tests that failed now and then on a loaded host measure the host's lag and allow for it, or wait for their
  event; 101 of 101 full runs were clean on 4-CPU VMs with 4 busy loops beside them.
- A compatibility step moves live connections between worker threads every loop turn (wisp-js 0.5.3 Wisp v1 and v2, a
  v1 client with stream limits and close codes, credit v2): none was reset.
- Every counter that no test checked has a test now (one exception: `accept_err_mem`); the WebSocket, HTTP and PROXY
  protocol parsers have table tests of their edge cases.
- A 24-hour soak of an earlier 1.4.0 candidate (before the `--dest-failfast`, close and stream-limit changes above;
  two servers with `--preset public`): no server close, no false reset, no error in 368 bench runs. Its idle memory
  floor rose about 1.5 to 2 MiB in 24 hours; up to half of that is glibc's per-thread memory (arenas), which grew more
  slowly in the second half.

## v1.3.3

New option, off by default (a plain `finalwisp` and `--preset public` do not change):

- `--auto-balance`: when one worker thread is fully busy with two or more busy connections while another is idle,
  it moves one of those connections to the idle thread for a trial of about 2.5 seconds (measure, move, measure,
  move back, measure). The move is kept only if the server as a whole carried more with it than before and after it.
  It helps a host with many cores and many short connections: with 8 clients of 32 short streams each on 16
  threads, 9% more connections per second (16 runs each, 90% interval 5.9% to 15.1%); echo and request/response traffic
  read the same with and without it. On two 2-core VPSes it found nothing to move and no difference was measured
  (32 runs each). On a host with up to 4 worker threads it checks less and less often while it finds nothing to do
  (every 5 seconds, doubling up to every 160 seconds); with more threads it keeps watching. Turned off, it costs
  nothing measurable: in 10 test cells of 32 runs each, all 10 read the same as 1.3.2. Counters `moved_conns`,
  `moved_back` and `moved_reset` (a connection the new thread could not take over, which is then closed; 0 in all
  our tests); with the option the metrics line also has `balance_naps` and `balance_nap_s`.

Tests:

- Some unit tests failed now and then on a loaded host: they waited a fixed number of rounds instead of for their
  event, or counted connections that other tests sent to a port they had freed. They now wait for the event and take
  only their own connections.

## v1.3.2

New options, all off by default (a plain `finalwisp` does not change):

- `--stream-share`: while 7/8 of the usable file descriptors are handed out (the mark where `--fd-admission` refuses
  new connections; it does not need `--fd-admission`), a connection that holds its share of streams or more gets no
  new stream (CLOSE `0x49`, counter `refuse_stream_share`). Connections with fewer streams go on, and open streams are
  not closed. The share is about twice the file descriptors per open connection at the mark, once that at the limit,
  and never below 32 streams. It counts connections, not addresses.
- `--stream-pool`: under memory pressure (memory level 1 and above, and always with a budget under 256 MiB) the
  worker threads share one stream limit of the same total instead of one limit each, so one busy connection is no
  longer refused while another thread has room. The memory bound does not change. In a test with 128 MiB and 2
  threads, one connection got 340 of 340 streams instead of 227.
- `--unread-close`: while the host's TCP memory is short (the mark of `--tcpmem-share`), a connection whose client has
  taken no data for 600 seconds (10 minutes) with its receive window at 0 is reset. That frees the kernel memory its
  downloads hold. Nothing is reset while the host has TCP memory to spare. An honest slow reader also takes no data
  for minutes while its buffer drains: in our tests up to 187 s at 2 KiB per second with the kernel's default buffer
  and 346 s with an 8 MiB buffer, so a reader that is slower or has a larger buffer can be reset under pressure.
  Counter `close_unread`, `why=unread` in `--log-conns`. Needs Linux 5.4 or later.

Changed in `--preset public` (the Docker image and `contrib/finalwisp.service` start with it):

- **The preset turns on the two stream options.** `--print-preset public` prints two more lines, and the `preset`
  line at startup lists `stream-share on, stream-pool on`. What a preset user can see change:
  - From 7/8 of the file descriptors on, a connection that holds its share of streams or more gets CLOSE `0x49` for
    new streams, so connections with fewer streams can still open theirs. Before, one busy connection could take the
    descriptors until none was left, and then the new streams of every connection were refused.
  - On a host with a small memory budget, one connection can open more streams than one thread's limit
    (`refuse_streams` counts fewer refusals); the total stays the same.
  - `--no-stream-share` and `--no-stream-pool` undo them.
- `--unread-close` is off unless asked for: the preset does not turn it on in this release. A later release may, once
  a rule that does not depend on the client's buffer size has been tested with real clients.
- What the two stream options cost: when a stream opens and closes, about 170 more instructions of the server's own
  (2.2% of the preset's count, counted with callgrind on loopback); per new connection 0.5%. Relayed bytes cost
  nothing extra that the counts could show. Timed on two 2-core VPSes, new connections per second with the preset
  read 2.1% to 2.7% below 1.3.1 in four readings (no reading is a confirmed loss); on an 80-thread server no
  difference. (`--unread-close`, when asked for, reads `TCP_INFO` once every 2 seconds
  for each connection that holds a download that waits for its client.)

Changed:

- **`--net-watch` also reads the host's connection-tracking table** (`nf_conntrack_count` and `nf_conntrack_max`, where
  the kernel has one and the files are readable; read only). It warns at the start and while it runs when the table is
  3/4 full (the next such warning only after the table was below half), and the metrics get `host_conntrack` and
  `host_conntrack_max`. When the table is full, the kernel drops the packets of new connections, and nothing in the
  server's other counters names the cause. The preset sets `--net-watch`.
- `--show-config` has a row `connection tracking` with `--net-watch`: the entries in use, the table's size, and whether
  the table has fewer entries than the file descriptors for connections and streams. It also names the mark of
  `--stream-share`.
- When the open-file limit cannot be read, the start warning names every option that needs it.

Tested with:

- The wisp-js client 0.5.3 (before: 0.5.0) in the compatibility tests.

Documentation:

- The [benchmarks](docs/benchmarks.md) page is renewed: finalwisp 1.3.1 against the newest version of every other server
  on 2026-11-15, on an 80-thread server and two 2-core VPSes, and the README's performance table follows it.
  epoxy-server built as its README says crashed under load on the VPSes; the page has that build and one with
  tokio-websockets 0.12.3. The epoxy-server numbers published before 2026-11-15 were for a build with
  tokio-websockets 0.12.3.

## v1.3.1

Fixed:

- A connection that is refused per client address with `429 Too Many Requests` (behind a trusted proxy or on
  `--listen-unix`: over `--max-conns-per-ip`, `--conn-rate-per-ip` or `conn-share`) now gives its `--max-conns` place
  back when the server refuses it. Before, it held the place until the 429 had been sent and the connection closed,
  so a new client that came in just then could be reset at accept although the limit was not really reached.
- Idle connections accepted together no longer send their keepalive probes in the same second. Each client gets its
  own idle time, 120 s plus up to 59 s, so a burst of idle clients is no longer cut by its own probe burst. In the
  test runs for this release (10,000 and 20,000 idle clients opened at once between two 2-core hosts), 1.3.0 closed
  1,139 and 2,411 of them (11 to 12%) and 1.3.1 none; the loss of 1.3.0 varies from run to run (its own tests, in the
  1.3.0 notes below, saw 887 of 10,000). Streams opened together get the same spread on their target sockets.
- `dead_peers` now counts a client whose read or write failed with a timeout (`ETIMEDOUT` or `EHOSTUNREACH`).
  Before, it stayed 0 although `--log-conns` said `why=dead_peer`.

Changed:

- An idle dead peer is now closed after 3 to 4 minutes (before: about 180 s).
- `--preset public` costs less per stream: a destination rule set made only of port rules (such as `--block-smtp`)
  no longer looks at the host name, and a worker in hold mode makes one guarded call per file descriptor it takes,
  with no extra clock read (about 300 fewer user instructions per stream opened and closed, counted).
- `BUILDINFO` records the `libc6-dev` package beside `glibc:` (the release binary links the static C library of that
  package, so the md5 follows it).
- Help texts: `--fd-admission` says that the room it keeps is not a guarantee (the open connections' own streams can
  use it up); `--dns-own` gives the time per try (1-2 s) and for a whole lookup (6 s at most, 4 to 6 s with the
  defaults of `/etc/resolv.conf`).

## v1.3.0

Changed defaults of the Docker image and the systemd unit (a plain `finalwisp` still starts with no preset and no
limits; what changed for it is in the next list):

- **The Docker image now starts `finalwisp --preset public`.** The image's entry point is
  `/finalwisp --preset public` and its default arguments are still `--host 0.0.0.0 --port 6001`. An image tag that you
  update from 1.2.x therefore changes behaviour: the mail ports 25, 465 and 587 are refused (CLOSE `0x48`), a
  connection can hold at most 1024 streams (the next CONNECT gets CLOSE `0x49`), new connections are refused when the
  file descriptors run short (`fd-admission`, `conn-share`), names are looked up by the built-in resolver
  (`dns-own`), a quarter of the resolver threads is kept for clients whose names answer fast (`dns-reserve`), and
  four guards for the host's TCP memory, source ports and dead destinations are on (`tcpmem-share`, `port-share`,
  `dest-failfast`, `net-watch`; see "Added"). Arguments after the image name replace only
  `--host 0.0.0.0 --port 6001` and keep the preset. To get
  the old behaviour, add `--preset none` to the arguments, for example
  `docker run ... finalwisp:1.3.0 --host 0.0.0.0 --port 6001 --preset none`; to undo one setting, add
  `--no-block-smtp`, `--max-streams-per-conn 0`, `--no-fd-admission`, `--no-conn-share`, `--no-dns-own`,
  `--no-dns-reserve`, `--no-tcpmem-share`, `--no-port-share`, `--no-dest-failfast` or `--no-net-watch`.
  `docker run --rm finalwisp:1.3.0 --print-preset public` prints what the preset sets.
- **`contrib/finalwisp.service` now starts `finalwisp --preset public ...`.** A unit file you installed earlier does
  not change by itself; this matters when you copy the new file. Remove `--preset public` from `ExecStart`, or write
  `--preset none`, to get the old behaviour.
- Neither passes `--trusted-proxy`. Behind a reverse proxy, add it yourself (see
  [behind a reverse proxy](docs/reverse-proxy.md)).
- What the preset costs: when a stream opens and closes, the server runs about 1,070 more instructions of its own
  (about 7,230 against 6,160; hardware counters, two 2-core hosts, a test that only opens and closes streams on
  loopback). The kernel's part of a stream (about 131,000 instructions there) and the system calls do not change, and
  the stream rate ties. Relayed bytes cost nothing extra. The parts: the destination rule about 300, `conn-share`
  340 to 420, `fd-admission` 80 to 110, and the four guards about 230 when `fd-admission` or `conn-share` is on
  (alone: no difference that the counters could show).

Changed in every start, with or without the preset:

- **The server raises its soft open-file limit to the hard limit at startup** (at most 1048576, never lower than it
  was) and the start output shows the result. If the hard limit is above the kernel's `fs.nr_open`, the hard limit is
  lowered to `fs.nr_open` with a warning, because the kernel accepts no other change then. `--no-nofile-raise` keeps the limit it was started with.
- **Out of file descriptors, a new connection is reset at once** instead of waiting without an answer, and a new
  stream is refused with CLOSE `0x49` instead of `0x03`. Both are counted (`refuse_fd_conns`, `refuse_fd`) and logged
  with the fix, at most one line per 10 s.
- At memory level 2 or 3, a new connection is reset at accept instead of waiting in the listen backlog (counter
  `refuse_level_conns`). `accept_paused` keeps its name and meaning.
- A name lookup that waited for a resolver thread for as long as `--connect-timeout` (at least 1 s) is given up: its
  stream closes like a failed lookup (CLOSE `0x42`, counter `dns_expired`). Before, with the system resolver and many
  names that do not resolve, lookups queued without limit.

Changed output (what the server prints; no option changed its meaning):

- **`finalwisp --help` is a short page on stdout and exits with status 0.** `finalwisp --help TOPIC` prints the options
  of one topic, `finalwisp --help all` every topic. Before, `--help` printed the full list on stderr with status 2.
- **A usage error is short**: the reason (with the nearest option name for a typo), then the line
  `Try: finalwisp --help TOPIC`. The full option list is no longer printed after an error. The status is still 2.
- **The start output is a short block** after `finalwisp listening on ws://HOST:PORT/`: version, threads, memory, open
  files, TLS, preset, and the settings from the config file and the command line. If you parse the old
  `finalwisp: capabilities: ...` line: it prints unchanged with `--log-level debug`, and `finalwisp --show-config`
  shows the same facts.
- The `finalwisp listening on` line no longer has a parenthesis after the address.
- The startup warning about `tcp_wmem` / `tcp_rmem` is now one line of the start block, shown under the same condition
  (a maximum below 16 MiB): `TCP buffer  4 MiB send, 6 MiB receive: below 16 MiB, see --show-config`.
  `finalwisp --show-config` has the explanation under Notes.
- The open-file warning names the fix for the hard limit (`LimitNOFILE=` in the systemd unit, `--ulimit nofile=` in
  Docker), because the server now raises the soft limit itself.
- The shutdown line is shorter: `SIGTERM: shutting down: no new connections; N open connection(s) get up to 30 s to
  finish (a second SIGTERM exits now)`.
- The Prometheus label `finalwisp_build_info{version="..."}` is now the release version (it was `0.1.0`).

Added:

- `--preset public`: one built-in set of settings for a server that anyone can reach (also `preset public` in a
  config file). `--print-preset public` prints it. The preset is read first, then the command line from left to
  right, with the config file at the place where `--config` stands; the later one wins, and every setting of the
  preset has an off value. `--preset none` drops a preset that a start
  command carries. The start block shows each setting of the preset with the value in effect.
  See [presets](docs/configuration.md#presets) and [a public server](docs/public-server.md), which says what the
  preset covers and what it does not.
- `--fd-admission` (off by default, on in the preset): while 7/8 of the file descriptors the server can use are
  handed out, new connections are reset at accept and open connections go on (counter `refuse_mark_conns`).
  `--no-fd-admission` turns it off again.
- `--conn-share` (off by default, on in the preset): from 3/4 of them, a client address that holds more than half
  gets no new connections while other addresses hold a real share (counter `refuse_share_conns`). It never applies
  to loopback, private and `--trusted-proxy` addresses. `--no-conn-share` turns it off again.
- `--dns-share` (off by default): a resolver thread that comes back goes to the client address
  with the fewest lookups running, so a new client does not wait behind the queue of a client that asks for many
  names. Nothing is refused and no thread is kept free. `--no-dns-share` turns it off again.
- `--dns-reserve` (off by default, on in the preset; it turns `--dns-share` on): a quarter of the resolver threads
  is kept for clients whose names answer fast. A client with a lookup that has run for 1 s is slow, for 60 s after
  it too, with every connection of its public address; all slow clients together get the other threads and no more.
  So a client that is slow already cannot make the names of other clients wait (a client's first names, before one
  of them has run for 1 s, still can, once). Its costs: the kept threads can stand
  free while slow lookups wait; a client on the same public address as a slow client is slow with it; a client that
  opens pages with dead names in quick succession waits about 1 s for the live names from its third page on.
  `--no-dns-reserve` turns it off again. See [slow names](docs/public-server.md#slow-names-and-the-resolver-threads).
- The preset uses the built-in resolver (`dns-own`), which gives up on a name that never answers after 6 s at most (4 to 6 s
  with the defaults of `/etc/resolv.conf`) instead of 10 s. From `/etc/resolv.conf` it reads the name servers and the options `timeout`, `attempts` and
  `rotate`, nothing else ([the list](docs/configuration.md#--dns-own)). `--no-dns-own` (new) goes back to the system
  resolver; it is refused together with `--dns-server`.
- `--tcpmem-share` (off by default, on in the preset): from 3/4 of the kernel's TCP memory limit
  (`net.ipv4.tcp_mem`), a client address that holds more than half of the downloads that their clients do not read
  gets no new streams (CLOSE `0x49`) while another client is connected. Counter `refuse_tcpmem_share`, gauge
  `tcpmem_unread`. It stops one address that keeps adding downloads it never reads and keeps the host off the
  kernel's limit; other clients can still be slowed. It does not cover many addresses that each hold a few, a burst
  of unread downloads within a second or two, or downloads that ran at full speed and were then paused.
  `--no-tcpmem-share` turns it off again.
- `--port-share` (off by default, on in the preset): the host's source ports toward one destination address and
  port. From 1/4 in use, new target sockets to it get the socket option `IP_LOCAL_PORT_RANGE` (Linux 6.3). From 3/4,
  a client address that holds more than half of the sockets to it gets no new streams to it while another client
  uses it; from 15/16, an address that is alone on it gets none while another client is connected (the same
  counter; the stream log names the rule `port_share` or `port_reserve`). With no port left the stream gets CLOSE
  `0x49`. Counters `refuse_port_share`, `refuse_port_full`; gauge `port_dest_max`.
  `--no-port-share` turns it off again.
- `--dest-failfast` (off by default, on in the preset): a destination where 8 connects of one worker thread have each
  got no answer to 4 SYNs gets no new connects from that thread but one probe per second; new streams to it get CLOSE `0x43` at once (counter
  `refuse_dest_dead`, gauge `dest_dead`). Not in effect with `--upstream`. `--no-dest-failfast` turns it off again.
- `--net-watch` (off by default, on in the preset): the metrics `host_syn_retrans`, `host_udp_out` and `connecting`,
  and a warning when the host sends very many SYN retransmits or UDP datagrams. It refuses nothing.
  `--no-net-watch` turns it off again.
- The share rules of `tcpmem-share` and `port-share` never apply to loopback, private and `--trusted-proxy`
  addresses and never to a client that is alone on the server. With no port left toward a destination, every
  client's stream to it is refused. None of the guards closes anything that is open.
- `--no-block-smtp`: turns `--block-smtp` off again (from a preset, a config file or earlier on the command line).
- `finalwisp --version` (also `-V`).
- `finalwisp [OPTIONS] --show-config`: checks the options, prints every setting in effect with where it came from
  (preset, config file, command line), what this host allows and the warnings a start would print, then exits. It
  opens no listener and reads no certificate or password file.
- `--name=value` is accepted for every option that takes a value.
- Colour on a terminal only (`NO_COLOR` turns it off).
- Runtime hints about the proxy chain, each printed once and then at most once per hour, each with a counter: a
  loopback or private peer that is not a trusted proxy sends a forwarding header (`hint_fwd_untrusted`); a trusted
  proxy sends no client address (`realip_missing`, the counter existed); one loopback or private address holds most
  connections (`one_key_conns_max`). They never change what the server does. The first two need a per-IP limit,
  `--conn-share` (so the preset is enough) or `--trusted-proxy`; the third a per-IP limit or `--conn-share`.
- One warning line when the host enters kernel TCP memory pressure (at most once per minute; needs the memory
  budget, which is on by default).
- Metrics: `fds` (a gauge: the file descriptors of connections and streams), `connect_fail` and `connect_timeout`
  (streams whose connect to the target failed or timed out), `dns_wait_us`, `dns_wait_ms_max` and `dns_expired`
  (`finalwisp_dns_wait_seconds_total`, `finalwisp_dns_wait_max_seconds`, `finalwisp_dns_expired_total`), and the
  counters named above. The metrics line also has `fd_limit=` and `fd_granted=`.

Known issue, not new in this release (it is in every release so far): when several thousand connections are accepted
within a second or two and then stay idle, the server can reset some of them after about 3 minutes although the
clients are alive, because their TCP keepalive probes go out as one burst and part of it is lost. Found in the
tests for this release: between two 2-core hosts, 10,000 idle connections opened at once lost 887, 5,000 lost none,
20,000 opened at once lost 545 and 638 (about 10,000 of them arrived in the first seconds), and 20,000 opened over
60 seconds lost none. Connections with traffic are not affected. `--no-keepalive` avoids it
(then an idle client that vanished is not found). Details and numbers:
[known limits](docs/troubleshooting.md#known-limits). A fix is planned for 1.3.1.

Docs: the deployment guide is now one page per task, with an index ([docs/README.md](docs/README.md)); the old page
keeps its headings and links to the new places. The "reasonable start" flags are gone. In our tests they refused
honest users (100 browsers behind one address open 5,560 streams within one second on a large page) and locked out
everyone who shared an address with an attacker. The guide now describes the preset, the proxy setups the server
cannot tell apart (with the nginx and Caddy lines), and how many file descriptors a user costs.

## v1.2.1

Changed:

- **Adaptive splice is on by default, for far clients only.** A client whose round trip was 10 ms or more when it
  connected, with more than 4 streams and a backed-up socket, gets 64 KiB zero-copy reads from its targets instead of
  256 KiB. Clients closer than 10 ms (same host, LAN), clients on `--listen-unix`, and every client behind a reverse
  proxy on the same host keep 256 KiB reads, exactly as before. On a 2-core VPS with one client 112 ms away running
  100 download streams, compared with 1.1.1: the download was 1.37x faster, the host stayed out of kernel TCP memory
  pressure (0 of 16 runs instead of 12), and another program on the same host kept receiving a plain TCP upload at
  full speed (22.2 MiB/s median instead of 0.1, 12 rounds). With clients on the same host, a 2-core VPS and a
  72-thread server showed no slowdown and no new memory pressure. In 1.2.0, `--adaptive-splice` also slowed clients on
  the same host of a 2-core VPS (a 100-stream download less than half as fast); the round-trip check removes that. If
  you used `--adaptive-splice` in 1.2.0 behind a reverse proxy or load balancer on the same host, it now does nothing
  there. `--no-adaptive-splice` turns it off; `--adaptive-splice` is still accepted.

## v1.2.0

No default changes. Two new options for small hosts that serve many slow downloads, and a guide for them.

Added (both off by default):

- `--adaptive-splice`: a client with more than 4 streams whose socket is backed up gets 64 KiB zero-copy reads from
  its targets instead of 256 KiB. On a 2-core VPS serving one client 112 ms away with 100 download streams, the
  download was 1.2-1.4x faster, the host stayed out of kernel TCP memory pressure (0 of 16 runs instead of 9-12), and
  another program on the same host kept receiving a plain TCP upload at full speed (22.5 MiB/s median instead of 1.9,
  12 rounds). Cost: on the same kind of VPS, clients on the same host with more than 4 streams were slower (echo
  10 x 5 streams 6-11%, a 100-stream download less than half as fast). Use it when clients are far away. Clients with
  1-4 streams are not affected.
- `--park-rcvlock`: while a download waits on a slow client, its target connection's kernel receive buffer stops
  growing (it is never made smaller, so no data is dropped). On an 80-thread server, peak host TCP memory with 100
  waiting downloads went from 952 to 613 MiB, with no throughput loss. It does nothing while the memory budget is
  below 256 MiB. Needs Linux 5.15 or later.
- Metrics: `rcvlock_locks`, `rcvlock_errors`.

Fixed:

- Credit pacing (on by default since 1.1.0): once one target slot of a worker thread had been reused about a billion
  times (2^30 streams), a stream whose upload credit was held while its download waited on the client could stay held
  after the client caught up. Its upload then paused for up to 2 seconds (with `--no-credit-v2`: until other traffic
  on the stream, so an echo stream could stall). A server that opens about 1000 short streams per second on one
  thread could reach that after about 12 days.

Docs: [small hosts and many slow downloads](docs/deployment.md#small-hosts-and-many-slow-downloads): how to tell if a
host is in kernel TCP memory pressure, and what `--no-splice`, per-IP limits, `--buffer 32` and the two new options
cost and gain.

## v1.1.1

Fixed:

- Per-IP limits (`--max-conns-per-ip`, `--stream-rate-per-ip`, `--conn-rate-per-ip`, `--upload-rate-per-ip`): the
  per-address table now keeps time in 64-bit milliseconds. Before, its 32-bit clock wrapped after 49.7 days: an
  address that had used up its rate limit and came back after 49.7 days or more, on a server that had no clients at all
  in between, could still find its limit used up (the idle time did not count) and be refused until the limit refilled
  at its normal rate, up to one minute longer.
- Per-IP rate limits count tokens exactly (integers). Before, `--stream-rate-per-ip` with `--upload-rate-per-ip`
  could refill inexactly (too slowly or too quickly) while the address was uploading (float rounding of the small refill
  of each read, most with a large burst).

Docs: benchmark numbers re-measured with 1.1.0 on the same three machines ([benchmarks](docs/benchmarks.md)).

## v1.1.0

Changed:

- **Credit pacing is on by default.** A stream gets no new upload credit while its download waits on the client.
  Echo-like traffic (full-duplex bulk) no longer fills the kernel socket buffers faster than the client reads: on a
  2-core VPS, 100 echo streams went from 236 to 24 MiB of server memory and 1.7x the throughput, and most echo cases no
  longer push the host into TCP memory pressure. On a second 2-core VPS with smaller socket buffer limits: 206 to
  158 MiB (1.3x less) and no clear change in throughput. Other machines: 1.06-1.10x the echo throughput, 4-7x less
  server memory. (Corrected 2026-11-16: this entry said "4-10x" for the other machines, which counted a cell of the
  first VPS, and did not name the second VPS.) Uploads, downloads and request/response traffic are not affected. Cost: a single echo stream on one 2-core
  VPS was 2-3% slower. `--no-credit-pace` turns it off.
- DNS cache entries now expire in the background (5 s for names with no address, 30 s otherwise) and the cache gives its
  memory back; before, they stayed in memory until a thread's cache reached 4096 entries.

Added (all off by default):

- `--stream-rate-per-dest R[/B]` and `--stream-rate-per-dest-minute N`: new streams per destination (target IP and
  port), all clients together. wispurr's defaults are `--stream-rate-per-dest 250/250 --stream-rate-per-dest-minute 6000`.
- `--conn-rate-per-ip R[/B]`: new connections per client address. "200 per 10 seconds" is `--conn-rate-per-ip 20/200`.
- Metrics: `refuse_ip_connrate`, `refuse_dest_rate`, `dest_untracked`, `dest_keys_max`, `cpace_holds`.

Other:

- `--help` and error messages no longer mention internal note numbers.
- `--dns-threads` stays 16: smaller pools were 2-10x slower at opening connections when DNS is slow.

## v1.0.0

The first public release.

- Wisp v1 and v2 over `ws://` and `wss://`, TCP and UDP streams, password and key authentication.
- One event loop per CPU thread, `splice` for downloads, TLS in the kernel (kTLS). One static binary.
- Safe defaults for a public server: private, loopback and own addresses blocked as targets; host, port and address
  rules; limits per server, per client IP and per connection; upload and download caps; a memory budget that
  follows the cgroup limit.
- Real client addresses from `X-Forwarded-For` or the PROXY protocol; a Unix socket listener.
- An outbound SOCKS5 or HTTP proxy for every stream, Tor and `.onion` included.
- Built-in DNS resolver, Prometheus metrics, connection and stream logs, graceful shutdown, certificate reload.
- Reproducible builds: the same commit and toolchain give the same binary, byte for byte.

Known limits: see [docs/deployment.md](docs/deployment.md#known-limits). Benchmarks: [docs/benchmarks.md](docs/benchmarks.md).
