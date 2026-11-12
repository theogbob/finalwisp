# Changelog

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
  longer push the host into TCP memory pressure. Other machines: 1.06-1.10x the echo throughput, 4-10x less server
  memory. Uploads, downloads and request/response traffic are not affected. Cost: a single echo stream on one 2-core
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
