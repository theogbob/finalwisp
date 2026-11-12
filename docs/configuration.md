# Configuration reference

Every option finalwisp accepts, grouped by topic, with its default. The source of truth is the binary itself:
`finalwisp --help` prints a short overview, `finalwisp --help TOPIC` the options of one topic and
`finalwisp --help all` every option (on stdout, with status 0).

All options are off or at a safe default unless you set them. A plain `finalwisp` serves `ws://127.0.0.1:6001/`.

The topic names are the ones that `finalwisp --help TOPIC` takes:

| topic | options for |
|---|---|
| [config](#config) | config file, presets, checking the settings |
| [listen](#listen) | address, port, threads, unix socket |
| [tls](#tls) | certificates for `wss://` |
| [client-ip](#client-ip) | the real client address behind a proxy or load balancer |
| [limits](#limits) | timeouts, connections, streams, rates and bandwidth |
| [destinations](#destinations) | where clients may connect: hosts, ports, address ranges |
| [auth](#auth) | passwords and keys for clients |
| [upstream](#upstream) | send every stream through a SOCKS5 or HTTP proxy |
| [dns](#dns) | resolver threads and name servers |
| [logs](#logs) | log level, connection and stream logs, metrics |
| [memory](#memory) | memory budget, kernel TCP memory |
| [advanced](#advanced) | tuning and diagnostic switches |

Before the topics: [how options are read](#how-options-are-read), the [config file](#config-file) and the
[presets](#presets).

## How options are read

- Options are read left to right. When an option is given twice, the last one wins (`--port 7000 --port 7001` listens
  on 7001).
- A switch such as `--no-splice` cannot be turned off again later on the same command line. (Exceptions:
  `--adaptive-splice` after `--no-adaptive-splice` turns it back on, and `--no-block-smtp` after `--block-smtp` turns it
  off. `--no-fd-admission`, `--no-conn-share` and `--no-dns-share` turn `--fd-admission`, `--conn-share` and
  `--dns-share` off again: of the two, the later one wins. `--no-dns-reserve` and `--no-dns-own` do the same for
  `--dns-reserve` and `--dns-own`, and `--no-tcpmem-share`, `--no-port-share`, `--no-dest-failfast` and
  `--no-net-watch` for the four guards.)
- Options come from up to three places: a [preset](#presets), a [config file](#config-file) and the command line. The
  preset is read first, then the command line from left to right, with the config file at the place where `--config`
  stands. The later one wins.
- A bare number is the port: `finalwisp 7000` is the same as `finalwisp --port 7000`.
- An option that takes a value takes it as the next word or after `=`: `--port 7000` or `--port=7000`.
- The policy, CIDR and `--proxy-protocol` lists take comma-separated values and can be repeated; repeated values add
  up. `--dns-server`, `--tls-cert` / `--tls-key` and `--cert-auth-key` take one value each: repeat the option.
- Sizes and rates (`--mem-budget`, `--download-rate`, `--upload-rate-per-stream`, `--upload-rate`,
  `--upload-rate-per-ip`) accept the suffixes `K`, `M` and `G` (powers of 1024: `1M` = 1048576). Every other number is
  a plain integer (`--notsent-lowat 131072`, not `128K`).
- An unknown option, a bad value or a removed option prints `finalwisp: <reason>` and exits with status 2. The
  message is 1 to 3 lines. It names the nearest option when there is one, and ends with `Try: finalwisp --help TOPIC`.

## Config

`finalwisp --help config` prints these options: config file, presets, checking the settings.

| option | value | default | what it does |
|---|---|---|---|
| `--config` | `FILE` | none | Read options from a file. See [config file](#config-file). |
| `--preset` | `public\|none` | `none` | Start from a built-in set of options. See [presets](#presets). |
| `--print-preset` | `NAME` |  | Print the preset's settings on stdout and exit with status 0. See [presets](#presets). |
| `--show-config` |  |  | Check the options, print every setting in effect with the layer that set it and what this host allows, then exit. Nothing is started. |
| `--help` | `[TOPIC]` |  | Print a short overview and exit with status 0. With a topic (the section names of this page, or `all`): the options of that topic. Short form: `-h`. |
| `--version` |  |  | Print the version (`finalwisp 1.3.0`) and exit. Short form: `-V`. |

## Config file

`--config FILE` reads options from a file. Use it for anything longer than a few flags, and for secrets such as an
`--upstream` URL with a password.

```text
# /etc/finalwisp.conf
# finalwisp behind nginx on the same host
preset public
host 127.0.0.1
port 6001
trusted-proxy 127.0.0.1
motd welcome
dns-server 10.0.0.53
dns-server 10.0.0.54
mem-budget 1G
```

```sh
finalwisp --config /etc/finalwisp.conf
```

Syntax:

- One option per line: the long option name without the leading dashes, then its value (`port 6001`), or the name
  alone for a switch (`block-smtp`).
- Blank lines and lines that start with `#` are skipped.
- The value is the rest of the line with the outer spaces trimmed. There is no quoting, and a `#` after a value is part
  of the value (`motd hi # x` sets the message to `hi # x`).
- A repeated name adds to a list (`dns-server`, `tls-cert` / `tls-key`, `cert-auth-key`, the policy lists).
- The bare port form is not accepted in a file: write `port 7000`.
- A file cannot include another file (`config` inside a file is an error), and `--config` can be given only once.
- `preset NAME` chooses a [preset](#presets). The file's other lines override the preset wherever the `preset` line
  stands.

How the file and the command line combine:

- The file's options take the place of `--config FILE` on the command line. An option after `--config` overrides
  the file; an option before it is overridden by the file.
- A list option given anywhere on the command line replaces the file's whole list. Lists are not merged.
  `--tls-cert` and `--tls-key` count as one list.
- A switch set in the file cannot be turned off on the command line. Remove the line instead. (Exceptions:
  `--adaptive-splice` on the command line undoes `no-adaptive-splice` in the file, and `--no-block-smtp` undoes
  `block-smtp`. `--no-fd-admission`, `--no-conn-share` and `--no-dns-share` undo `fd-admission`, `conn-share` and
  `dns-share`. `--no-dns-reserve` and `--no-dns-own` undo `dns-reserve` and `dns-own`, and `--no-tcpmem-share`,
  `--no-port-share`, `--no-dest-failfast` and `--no-net-watch` undo the four guards.)

Errors stop the server before it opens any socket, with status 2. The message names `FILE:LINE` and the option, but
never the value, because the file may hold secrets. Limits: the file must be at most 1 MiB, each line at most 16 KiB,
valid UTF-8 and free of control characters.

The lines printed at startup have a line `config file`, with the name of the file and the settings that it decides,
so you can see which file was used. If a file that holds a secret (`upstream` with a password) can be read by group or others, finalwisp prints a
warning. Use mode 0600 for such a file, owned by the service user.

The file is read once at startup. `SIGHUP` reloads TLS certificates only; restart the server to apply a changed config
file.

## Presets

A preset is a set of options that is built into the binary. There is one, `public`: the settings for a server that
anyone can reach. [Securing a public server](public-server.md) says what it protects against and what it does not.

```sh
finalwisp --preset public --host 0.0.0.0 --port 6001
```

| option | what it does |
|---|---|
| `--preset public` | Start from the `public` preset. A config file and the command line override single settings. In a config file: `preset public`. |
| `--preset none` | No preset. Use it to drop a preset that a start command already carries (the Docker image and the systemd unit start with `--preset public`). |
| `--print-preset NAME` | Print the preset's settings on stdout and exit with status 0. The output is the file that was built into the binary, byte for byte, in the config file format. Nothing else is checked or started. |

What `public` sets:

| setting | value | to turn it off |
|---|---|---|
| `block-smtp` | on | `--no-block-smtp` |
| `max-streams-per-conn` | `1024` | `--max-streams-per-conn 0` |
| `fd-admission` | on | `--no-fd-admission` |
| `conn-share` | on | `--no-conn-share` |
| `dns-own` | on | `--no-dns-own` |
| `dns-reserve` | on | `--no-dns-reserve` |
| `tcpmem-share` | on | `--no-tcpmem-share` |
| `port-share` | on | `--no-port-share` |
| `dest-failfast` | on | `--no-dest-failfast` |
| `net-watch` | on | `--no-net-watch` |

`finalwisp --print-preset public` shows the lines of the version you run.

How the layers combine:

- The order is preset, then config file, then command line. The later one wins, for every setting. `--preset` can
  stand anywhere on the command line: its settings always count as the first layer.
- Between the config file and the command line nothing changed: an option after `--config` overrides the file, an
  option before it is overridden by the file, and a list option on the command line replaces the file's whole list.
- Every setting of a preset has an off value (the table above), so a later layer can always undo it.
- A preset holds no list option (hosts, ports, address ranges, trusted proxies). Lists come only from your config file
  and command line.
- If `--preset` is given several times, the last one wins. The command line's `--preset` wins over the file's
  `preset` line.
- An unknown preset name is an error that lists the names.

The lines printed at startup show the layers. The `preset` line lists every setting of the preset with the value in
effect, and names the layer when another one overrides it. Every other setting that is not the default stands once,
under the layer that decides it (`config file` or `command line`). Here the file's `max-streams-per-conn 256` replaced
the preset's 1024:

<!-- sample: real output of the merged 1.3.0 build on a terminal (2026-11-11, a 15-thread machine; the file stood in /tmp for the run) -->
```text
$ finalwisp --config /etc/finalwisp.conf
finalwisp listening on ws://127.0.0.1:6001/
  version      1.3.0
  threads      15
  memory       up to 31410 MiB (half of this machine's memory)
  open files   up to 524288
  TCP buffer   4 MiB send: below 16 MiB, see --show-config
  TLS          off
  preset       public: block-smtp on, max-streams-per-conn 256 (config file),
               fd-admission on, conn-share on, dns-own on, dns-reserve on,
               tcpmem-share on, port-share on, dest-failfast on, net-watch on
  config file  /etc/finalwisp.conf: trusted-proxy 127.0.0.1, metrics-listen 9100
  metrics      http://127.0.0.1:9100/metrics
```

The file of this example:

```text
# /etc/finalwisp.conf
preset public
trusted-proxy 127.0.0.1
max-streams-per-conn 256
metrics-listen 9100
```

`finalwisp YOUR-OPTIONS --show-config` prints every setting with the layer that set it, and starts nothing.

A plain `finalwisp` uses no preset: its `preset` line says `none`.

<a id="listening-and-tls"></a>
## Listen

`finalwisp --help listen` prints these options: address, port, threads, unix socket.

| option | value | default | what it does |
|---|---|---|---|
| `--host` | `H` | `127.0.0.1` | Address to listen on. An IP address, not a name. Use `0.0.0.0` or `::` for direct clients; keep `127.0.0.1` behind a reverse proxy on the same host. |
| `--port` | `P` | `6001` | TCP port to listen on (0-65535; do not use 0). |
| `--threads` | `N` | number of CPUs | Event loop threads. Lower it to leave cores to other services. `0` counts as 1. |
| `--listen-unix` | `PATH` | off | A second listener on a Unix socket, next to the TCP one. Plain `ws://` only. Meant for a reverse proxy on the same host. Clients on it are trusted to send the client-IP header, like `--trusted-proxy`. |
| `--unix-mode` | `OCTAL` | `660` | Permissions of the Unix socket file. Whoever may write the file may connect. Needs `--listen-unix`. |

The server accepts Wisp on any path that ends with `/` (`ws://host:6001/` or `ws://host:6001/wisp/`). A WebSocket
on a path that ends with `host:port` (`ws://host:6001/proxy/example.com:443`) is a wsproxy connection: one TCP stream
over one WebSocket, under the same destination policy and limits. A plain HTTP request without a WebSocket upgrade
gets `200 OK` and the text `finalwisp: this is a Wisp server`, which is handy for health checks.

## TLS

`finalwisp --help tls` prints these options: certificates for `wss://`.

| option | value | default | what it does |
|---|---|---|---|
| `--tls-cert` | `FILE --tls-key FILE` | off | Serve `wss://` with kernel TLS. Both files are PEM. Repeat the pair for more names: the certificate is picked by SNI, and the first pair is used when nothing matches. Needs the `tls` kernel module (see [built-in TLS](tls.md)). |
| `--tls-key` | `FILE` | off | The private key (PEM) of a `--tls-cert`. Give the same number of each: they pair up in order. |
| `--tls-cipher-order` | `client\|server` | `client` | `server` prefers AES-GCM over ChaCha20 whatever the client prefers. Useful on CPUs with AES instructions. |
| `--tls-rekey-records` | `N` | `8388608` (2^23) | With built-in TLS 1.3, send a KeyUpdate after N records. `0` or 2^24 and above turns it off. Works only on Linux 6.14 or later. |

[Built-in TLS](tls.md) has the setup, the renewal and the kernel table.

<a id="client-ip-behind-proxies"></a>
## Client IP

`finalwisp --help client-ip` prints these options: the real client address behind a proxy or load balancer.

| option | value | default | what it does |
|---|---|---|---|
| `--trusted-proxy` | `CIDRS` | none | Peers whose client-IP header is believed. From any other peer the header is ignored. List only your proxies. |
| `--real-ip-header` | `NAME` | `x-forwarded-for` | The one header read from a trusted peer. `x-forwarded-for` is read right to left, skipping trusted hops. Any other name (`x-real-ip`, `cf-connecting-ip`) is read as one address. |
| `--proxy-protocol` | `tcp\|unix` | off | Every connection on that listener (`tcp`, `unix` or both, comma-separated) must start with a PROXY protocol v1 or v2 header. Use it behind a TCP load balancer that sends one. A connection without the header is reset. |
| `--proxy-protocol-from` | `CIDRS` | none | The load balancers allowed to send the PROXY header on TCP. Required with `--proxy-protocol tcp`. Any other peer is reset. |

The client address is used by the per-IP limits and by the connection and stream logs. The `Forwarded` header
(RFC 7239) is not supported.

When the server keeps client addresses (a per-IP limit, `--conn-share`, `--trusted-proxy` or `--listen-unix` is set), it also prints
[runtime hints](logs-metrics.md#runtime-hints-and-warnings) about a proxy setup that looks wrong, for example a proxy
that sends `X-Forwarded-For` but is not in `--trusted-proxy`.

## Limits

`finalwisp --help limits` prints these options: timeouts, connections, streams, rates and bandwidth.

All limits are off by default. The memory budget (below) protects the server even without them; these are policy
limits that you choose.

| option | value | default | what it does |
|---|---|---|---|
| `--connect-timeout` | `SECS` | `10` | How long a connect to a target may take (at most 86400). A timeout closes the stream with CLOSE `0x43`. |
| `--drain-timeout` | `SECS` | `30` | On SIGTERM or SIGINT, how long open connections may continue before they are closed (at most 86400; `0` exits at once). |
| `--max-conns` | `N` | off | At most N client connections in total. A new connection over the limit is reset right after accept. |
| `--max-streams-per-conn` | `N` | off | At most N streams on one connection. A CONNECT over it is refused with Wisp CLOSE `0x49` (throttled); the connection stays. `0` is off. The `public` preset sets 1024. |
| `--max-conns-per-ip` | `N` | off | At most N connections per client address (IPv4 address or IPv6 /64). A direct client over it is reset at accept; behind a trusted proxy it gets `429 Too Many Requests`. |
| `--stream-rate-per-ip` | `R[/B]` | off | New streams per second per client address, with a burst of B (default 2R). R is 1 to 1000000. Over it: CLOSE `0x49`. |
| `--conn-rate-per-ip` | `R[/B]` | off | New connections per second per client address, with a burst of B (default 2R). R is 1 to 1000000, B is 1 to 2000000. A direct client over it is reset at accept; behind a trusted proxy it gets `429 Too Many Requests`. "200 connections per 10 seconds" is `20/200`. |
| `--stream-rate-per-dest` | `R[/B]` | off | New streams per second to one destination (target IP and port), all clients together, with a burst of B (default 2R). R is 1 to 1000000. Over it: CLOSE `0x49`. See [per-destination limits](public-server.md#per-destination-limits). |
| `--stream-rate-per-dest-minute` | `N` | off | New streams per minute to one destination, all clients together (1 to 60000000). Over it: CLOSE `0x49`. |
| `--download-rate` | `RATE` | off | The most the server sends on one client connection per second, all its streams together. Uses kernel TCP pacing. Range 16K to 4095M bytes per second. Also turns off splice. |
| `--upload-rate-per-stream` | `RATE` | off | The most the server sends to one TCP target per second, per stream. Uses kernel TCP pacing. Range 16K to 4095M. |
| `--upload-rate` | `R[/B]` | off | The most finalwisp reads from one client connection per second (all its TCP and UDP streams). R is 8K to 1T. Burst B defaults to max(R, 16K) and must be at least 16K and at least R/10. Over the limit the client is not read until it is under again; nothing is dropped. |
| `--upload-rate-per-ip` | `R[/B]` | off | The same as `--upload-rate`, shared by all connections of one client address. |
| `--fd-admission` |  | off | Keep room for the connections that are already open. `--no-fd-admission` turns it off again. [Details](#--fd-admission). |
| `--no-fd-admission` |  |  | Turns `--fd-admission` off again. Of the two, the later one wins. |
| `--conn-share` |  | off | Stop one client address from taking the file descriptors that other clients use. `--no-conn-share` turns it off again. [Details](#--conn-share). |
| `--no-conn-share` |  |  | Turns `--conn-share` off again. Of the two, the later one wins. |
| `--no-nofile-raise` |  | raise on | Keep the soft open-file limit (`RLIMIT_NOFILE`) the server was started with. By default the server raises its soft limit to the hard limit at startup, but not above 1048576, and never lowers it. [Details](#--no-nofile-raise). |
| `--tcpmem-share` |  | off | While the host's TCP memory is short, one client address cannot keep adding downloads that it does not read. `--no-tcpmem-share` turns it off again. [Details](#--tcpmem-share). |
| `--no-tcpmem-share` |  |  | Turns `--tcpmem-share` off again. Of the two, the later one wins. |
| `--port-share` |  | off | Keep the host's source ports toward one destination for all clients: one client address cannot take them all. `--no-port-share` turns it off again. [Details](#--port-share). |
| `--no-port-share` |  |  | Turns `--port-share` off again. Of the two, the later one wins. |
| `--dest-failfast` |  | off | Stop sending connects to a destination that does not answer: new streams to it fail at once instead of after the connect timeout. `--no-dest-failfast` turns it off again. [Details](#--dest-failfast). |
| `--no-dest-failfast` |  |  | Turns `--dest-failfast` off again. Of the two, the later one wins. |
| `--net-watch` |  | off | Counters and a log line for two things that no option bounds: SYN retransmits (connects that get no answer) and UDP datagrams. Nothing is refused. `--no-net-watch` turns it off again. [Details](#--net-watch). |
| `--no-net-watch` |  |  | Turns `--net-watch` off again. Of the two, the later one wins. |

Rates are bytes per second of TCP payload. In network units: `1M` is about 8.4 Mbit/s, `10M` about 84 Mbit/s,
`100M` about 839 Mbit/s.

Per-IP limits need the real client address. Behind a reverse proxy, set `--trusted-proxy` (or use `--listen-unix`).
Without it every client has the proxy's address and they all share one limit.

### `--fd-admission`

A connection needs one file descriptor and each of its streams at least one, and the startup log prints how many the
server can use (`usable`). While 7/8 of them are handed out to the worker threads (in use, plus a small unused
allowance that each thread keeps), a new connection is reset right after accept; this ends when fewer than 13/16 are
handed out. Open connections and their new streams go on. Without it the server takes connections until the last file
descriptor, and then streams on open connections are refused (CLOSE `0x49`). Counter: `refuse_mark_conns`.

The 1/8 that is kept is room, not a guarantee: the open connections can use it up with their own streams, and then
their new streams are refused too. In a test with the `public` preset, which sets this option, a limit of 65,536 and 1,000 users arriving over 400
seconds (one run with the preset, one without), new connections were refused from 806 connected users on, and the streams of those users used up the
rest 50 seconds later. Over the whole run the connected users lost 60,269 requests with the preset and 168,096
without it; 194 of the 1,000 users never got in with it, 18 without it. A higher limit is the real fix.

### `--conn-share`

From 3/4 of the usable file descriptors handed out (until below 11/16), a client address (IPv4 address or IPv6 /64)
that holds more than half of them gets no new connection, if all other addresses together hold at least 1/64 of them
and at least 256. A direct client is reset at accept; behind a trusted proxy it gets `429 Too Many Requests`. Its open
connections go on. Never applies to addresses that are not public (loopback, private, link-local, carrier-grade NAT
`100.64.0.0/10` and the other reserved ranges), to `--trusted-proxy` addresses, and to a client without a client
address (a `--listen-unix` client that sends no client-address header; with the header it is judged by that address).
Behind a reverse proxy it needs `--trusted-proxy`, or every client has the proxy's address. Counter:
`refuse_share_conns`.

### `--no-nofile-raise`

Each connection and each stream needs one file descriptor, so the limit is the number of connections plus streams the
server can hold. The startup log shows the limit before and after. If the hard limit is unlimited or above the
kernel's `fs.nr_open`, the kernel accepts the raise only together with a hard limit of `fs.nr_open`: the server does
that and logs a warning.

### `--tcpmem-share`

The kernel keeps the data of every TCP socket of the host in one pool with a limit (`net.ipv4.tcp_mem`, the third
value, in pages). A download that its client does not read stays in that pool, in the target socket. When the pool is
full, every TCP connection of the host slows down or stops, also those of other clients and of other programs.

With `--tcpmem-share` the server reads the pool's use (`/proc/net/sockstat`) against the limit. From 3/4 of the limit
(until below 11/16), a client address (IPv4 address or IPv6 /64) that holds more than half of all unread downloads of
the server gets no new stream (CLOSE `0x49`) while another client is connected. The address must hold enough of them
to matter on this host: their number times the kernel's default receive buffer (`net.ipv4.tcp_rmem`, the second
value) is 1/16 of the limit or more. An unread download is a target socket that the server has stopped reading
because its client's output is full. Counter: `refuse_tcpmem_share`.

Open streams go on, and nothing is closed. A client that is alone on the server is never refused. The rule never
applies to addresses that are not public (loopback, private, link-local, carrier-grade NAT `100.64.0.0/10` and the
other reserved ranges), to `--trusted-proxy` addresses, and to a client without a client address; their unread
downloads still count in the total. Behind a reverse proxy it needs `--trusted-proxy`, or every client has the
proxy's address. UDP streams are not refused.

The server reads that file 4 times per second, up to 50 times per second near the mark, and changes no kernel setting. In a
container that cannot read `net.ipv4.tcp_mem`, the rule runs while the kernel reports TCP memory pressure
(`/proc/net/protocols`); `--show-config` says which form is in use. The gauge `tcpmem_unread` is the number of unread
downloads at the last count.

What it did in our test (a 2-vCPU VPS; one address opened unread downloads in steps of 500 to 1,000 while another
client used the server; three runs with the option): once the mark was passed, the address got no further stream
(1,000 of 1,000 refused), and the host's TCP memory stopped at 294 to 312 MiB of 350. Without the option it reached
the limit: the other client's upload stopped (0.00 to 0.11 MiB/s of 2.00) and its download fell to 0.03 MiB/s of
8.00. With the option the other client kept working, but not at full speed in every run: its upload was 0.72 to
2.00 MiB/s, its download 8.00 MiB/s in one run and 0.7 MiB/s in two. So the option keeps the host off the kernel's
maximum. Other clients can still be slowed.

What it does not cover:

- Many addresses that each hold a few unread downloads. No address holds more than half, so nobody is refused, and
  the result is the same as without the option: in a test with 250 client addresses on a 2-vCPU host, another
  client's download stopped when the pool was full (1,000 unread downloads), with and without it. The warning
  "the host entered kernel TCP memory pressure" names this case.
- A burst from one address. A new unread download fills its socket 1 to 2 seconds after it is opened, and the rule
  looks at the memory in use now, so the streams that open within that time are all let in. Streams that are open
  are not closed. In a test, 1,000 unread downloads opened at once from 28 MiB below the mark were all let in, and
  another client's download fell to a tenth (0.77 MiB/s of 8.00). The last step before the mark in the test above is
  the same case.
- Downloads that ran at full speed and were then paused, from honest clients or not. The kernel has grown their
  buffers, so each holds far more than a download that was never read (about 2.6 MiB each in a test, against 0.1
  MiB), and 100 of them fill the TCP memory of a 2-vCPU host. The rule counts sockets, and so few sockets are below
  its count.

In short: the option stops one address that keeps adding downloads it never reads, and it keeps the host off the
kernel's maximum. It does not stop a burst, and it does not keep other clients at full speed.

### `--port-share`

A TCP connection from the host to one destination address and port needs its own source port, and the host has a
fixed number of them (`net.ipv4.ip_local_port_range`, 28232 by default, minus `net.ipv4.ip_local_reserved_ports`). So
the server can hold at most that many target sockets to one destination, for all clients together. A busy site with
few addresses reaches a large part of it with honest users.

With `--port-share` the server counts its target sockets per destination (every 2 seconds, and every 250 ms while a mark is passed) and does four things:

- From 1/4 of the ports in use toward one destination: new target sockets to it get the socket option
  `IP_LOCAL_PORT_RANGE` (Linux 6.3 and later) with the host's own range. The kernel then looks at every port; without
  the option it tries the even ports first, and connects get slow once half of the ports are in use.
- From 3/4: a client address (IPv4 address or IPv6 /64) that holds more than half of the sockets to that destination
  gets no new stream to it (CLOSE `0x49`) while another client holds a socket to it. Counter: `refuse_port_share`.
- From 15/16: an address that is alone on the destination gets no new stream to it (CLOSE `0x49`) while another
  client is connected to the server. That leaves ports for a client that comes later, and from its first socket
  the rule before this one applies. The server counts a few times a second, so an address that opens streams fast
  stops a little above 15/16: in a test with 28,232 ports it held 27,000, and a client that came later got the
  1,232 that were left. The same counter; `--log-streams` names the rule
  (`port_share` or `port_reserve`), and each has its own warning. An address that is alone on the server can use
  every port.
- No port left (the kernel answers `EADDRNOTAVAIL`): the stream gets CLOSE `0x49` (without the option: `0x42`), and
  for 250 ms new streams to that destination are refused without asking the kernel again. Counter:
  `refuse_port_full`.

A rule judges one address of a name: when a name has more addresses, the stream goes on with the next one. Open
streams go on, and nothing is closed. The second and the third rule never apply to addresses that are not public (loopback,
private, link-local, carrier-grade NAT `100.64.0.0/10` and the other reserved ranges), to `--trusted-proxy` addresses,
and to a client without a client address; their sockets still count. Behind a reverse proxy it needs
`--trusted-proxy`, or every client has the proxy's address.

It covers TCP streams only (UDP sockets have their own ports). With `--upstream` the destination is the proxy's
address and port. It does not cover many addresses that each hold a few sockets to one destination: for those only the
last rule acts. On a kernel without the socket option the first rule is off; `--show-config` says so. The gauge
`port_dest_max` is the largest number of target sockets to one destination at the last count.

### `--dest-failfast`

A connect to a destination that does not answer holds a socket until `--connect-timeout` (10 seconds), and the
kernel sends a SYN packet for it again and again in that time. Many streams to one dead destination hold many sockets
and send many packets for nothing.

With `--dest-failfast` a worker thread takes a destination (target address and port) for dead when 8 or more of its
connects to it have each got no answer to 4 SYNs (about 3 seconds on a current kernel) and no stream to it has opened
since the last count. Until it answers:

- A new stream to it is refused at once with CLOSE `0x43`, the reason it would get at the connect timeout. Counter:
  `refuse_dest_dead`.
- One connect per second per worker thread still goes out as a probe. The first connect to it that opens ends it.
  It also ends when no connect to it is waiting any more: the destination refuses connections now (new streams then
  get `0x44`), or nobody asked for it and the waiting connects have timed out. For up to about 2.5 seconds after a
  dead destination starts refusing, new streams to it may still be answered `0x43` (no answer) and not `0x44`
  (refused): in a test, 22 of 137 streams.

A target that answers the second or the third SYN is never taken for dead. Only while another client is connected: a
client that is alone on the server is never refused. A name with more addresses goes on with the next one. Streams
that are already connecting go on until `--connect-timeout`. Never applies to addresses that are not public
(loopback, private, link-local, carrier-grade NAT `100.64.0.0/10` and the other reserved ranges), to
`--trusted-proxy` addresses, and to a client without a client address.

The cost is at a restart of the destination: streams that arrive between two probes are refused, also when the
destination has just come back. In a test with a destination that was down for 12 seconds and came back, 60 of 270
streams were refused at once; without the option 59 of them would have connected after a wait of up to 7 seconds. The
first answer came at the same time with and without it. A host that answers only the fifth SYN (after 4 seconds)
can lose a few streams of a large page: 1 of 70 in a test.

It covers TCP streams only, and it is not in effect with `--upstream` (every connect goes to the proxy). It does not
cover connects to many dead destinations with fewer than 8 at a time to each one. The gauge `dest_dead` is the
number of destinations that are taken for dead now.

### `--net-watch`

Two kinds of traffic use the host's packet rate out, and the host has no limit for it that finalwisp could read:

- Connects to many destinations that do not answer. The kernel sends the SYN packet of each one again and again
  until `--connect-timeout`. `--dest-failfast` stops this for one destination, not for many.
- UDP datagrams. finalwisp has no limit on datagrams per second.

`--net-watch` refuses nothing. It adds three values to the metrics:

- `host_syn_retrans` and `host_udp_out`: SYN retransmits and UDP datagrams sent by the whole host since boot (from
  `/proc/net/netstat` and `/proc/net/snmp`). They count every program on the host, not finalwisp alone.
- `connecting`: streams of this server with a connect in flight.

One thread reads the host's counters every 10 seconds and logs a warning when

- the host sent 30,000 or more SYN retransmits in the 10 seconds and 3 or more per connect attempt, or
- the host sent 75,000 or more UDP datagrams in the 10 seconds and they are half or more of all its packets.

The next warning of the same kind comes only at more than twice the value of the last one, so each kind is logged a
few times at most. The two numbers are thresholds for a log line, not limits. They come from measurements on a
2-vCPU host: other clients were not slowed at 3,000 SYN retransmits or 5,000 UDP datagrams per second, and were at
4,200 and 10,000. A host with a faster network path has more room. 100 browsers that load a page from a slow host
at the same time stay below both conditions.

<a id="destination-policy"></a>
## Destinations

`finalwisp --help destinations` prints these options: where clients may connect: hosts, ports, address ranges.

These options decide which targets clients may reach. A refused stream gets Wisp CLOSE `0x48` (blocked). List options
are comma-separated and repeatable.

| option | value | default | what it does |
|---|---|---|---|
| `--allow-loopback` |  | off | Let clients reach loopback targets (127.0.0.0/8, ::1, 0.0.0.0/8, `::`). Only for tests or a trusted service on the same host. |
| `--allow-private` |  | off | Let clients reach private, link-local, CGNAT and other reserved ranges. Only on a trusted network. It does not lift the two classes that `--allow-self` and `--allow-embedded-v4` open. |
| `--no-udp` |  | UDP on | Refuse Wisp UDP streams (CLOSE `0x48`). |
| `--allow-host` | `NAMES` | none | Only these host names and the names below them (`example.com` also allows `a.example.com`). Any other name is refused. IP addresses skip host rules. |
| `--block-host` | `NAMES` | none | Refuse these host names and the names below them. Wins over `--allow-host`. |
| `--allow-ports` | `[tcp:\|udp:]N[-M],...` | none | Only these ports (1-65535). Without `tcp:` or `udp:` an entry covers both. A list with only `tcp:` entries leaves UDP ports open. |
| `--block-ports` | `[tcp:\|udp:]N[-M],...` | none | Refuse these ports. Wins over `--allow-ports`. |
| `--allow-dest` | `CIDRS` | none | Let these addresses through every address class (loopback, private, own, embedded). Not through `--block-dest`. |
| `--block-dest` | `CIDRS` | none | Refuse these addresses. Checked first. |
| `--block-smtp` |  | off | Refuse the mail ports, the same as `--block-ports tcp:25,tcp:465,tcp:587`. Without it the server prints a hint at startup. The `public` preset sets it. |
| `--no-direct-ip` |  | off | Refuse a CONNECT to an IP address (including forms such as `127.1` or `2130706433`): clients must send a name. |
| `--no-ipv6-targets` |  | off | Use IPv4 targets only: no IPv6 addresses, no AAAA lookups. |
| `--allow-self` |  | off | Let clients reach the server's own interface addresses. Blocked by default even with `--allow-private`. |
| `--allow-embedded-v4` |  | off | Let clients reach IPv6 forms that carry an IPv4 address (`::/96`, 6to4, Teredo, local-use NAT64). Blocked by default. |
| `--no-block-smtp` |  |  | Undo `--block-smtp` from a preset, a config file or earlier on the command line. It does not remove the mail ports from a `--block-ports` list. |

Address rules run on every address a name resolves to, so a name that points at a blocked address is refused too. Host
rules compare the name exactly as the client sent it (internationalized names arrive as `xn--` punycode) and cannot see
DNS aliases (CNAME). Use `--block-dest` for anything that must never be reached.

<a id="authentication-and-wisp-v2"></a>
## Auth

`finalwisp --help auth` prints these options: passwords and keys for clients.

| option | value | default | what it does |
|---|---|---|---|
| `--auth-file` | `FILE` | off | Wisp v2 password authentication. One `user:password` per line; `#` lines and blank lines are skipped. The passwords are plain text: keep the file private (finalwisp warns if group or others can read it). |
| `--cert-auth-key` | `FILE` | off | Wisp v2 ed25519 key authentication. The file holds one or more PEM `PUBLIC KEY` blocks (for example from `openssl pkey -in key.pem -pubout`). Repeatable. |
| `--motd` | `TEXT` | off | A Wisp v2 message of the day. |

With any authentication option set, every client must authenticate. Wisp v1 clients cannot connect, and plain
WebSocket proxy (wsproxy) connections get `403 Forbidden`, because neither has a way to send credentials.

<a id="upstream-proxy"></a>
## Upstream

`finalwisp --help upstream` prints these options: send every stream through a SOCKS5 or HTTP proxy.

| option | value | default | what it does |
|---|---|---|---|
| `--upstream` | `URL` | off | Send every TCP stream through one proxy: `socks5://`, `socks5h://` or `http://` (HTTP CONNECT), then `[USER[:PASS]@]HOST[:PORT]`. Default ports: 1080 for SOCKS, 80 for HTTP. UDP streams are refused with CLOSE `0x48`. |
| `--upstream-trust-dns` |  | off | Required with `socks5h://`, refused otherwise. The proxy resolves the target names instead of finalwisp. |

`https://` proxies are not supported. Put a URL that holds a password in a config file with mode 0600; on the command
line it is visible to other users of the host. Logs show it as `scheme://***@host:port`. See
[upstream proxy and Tor](upstream-proxy.md).

## DNS

`finalwisp --help dns` prints these options: resolver threads and name servers.

| option | value | default | what it does |
|---|---|---|---|
| `--dns-threads` | `N` | `16` | Resolver threads (both resolvers). Each thread runs one lookup at a time, so at most N new names are looked up at once: with a 20 ms name server, 16 threads answer about 750 new names per second and further lookups wait. Identical names looked up at the same time share one lookup. `0` counts as 1. |
| `--dns-own` |  | off | Use the built-in resolver instead of the system's (`getaddrinfo`). It gives up on a dead name server after 1-2 s instead of about 10 s. The public preset sets it. [What it reads](#--dns-own). |
| `--dns-server` | `IP[:PORT]` | from `/etc/resolv.conf` | Name servers for the built-in resolver. At most 3, repeatable. Implies `--dns-own`. IPv6: `[addr]:port`. |
| `--dns-share` |  | off | Share the resolver threads between clients. Nothing is refused, no thread is kept free, and a client alone uses every thread. Best with `--dns-own`. [Details](#--dns-share). |
| `--no-dns-share` |  |  | Turns `--dns-share` off again. Of the two, the later one wins, also across a config file and the command line. Refused together with `--dns-reserve`, which needs it. |
| `--dns-reserve` |  | off | Keep a quarter of the resolver threads (at least one) for clients whose names answer fast, so that names that never answer cannot take every thread. Turns on `--dns-share`. The public preset sets it. [Details and costs](#--dns-reserve). |
| `--no-dns-reserve` |  |  | Turns `--dns-reserve` off again. Of the two, the later one wins. It leaves `--dns-share` as it was set. |
| `--no-dns-own` |  |  | Turns `--dns-own` off again: names are looked up with the system resolver. Of the two, the later one wins. Refused together with `--dns-server`. |

A lookup that waited for a resolver thread for as long as `--connect-timeout` (at least 1 s) is not started: its stream closes
like a failed lookup (CLOSE `0x42`), and the `dns_expired` counter counts it.

Each worker thread caches answers for 30 s (names with no address: 5 s); expired entries are dropped within about
2 s, also on a worker with no clients. Both resolvers read `/etc/hosts` first. Every name is looked up as a full name: the `search` and `domain` lines of
`/etc/resolv.conf` are not applied, so clients must send full names (`intranet.corp.example`, not `intranet`).

### `--dns-own`

The built-in resolver asks the name servers itself, over UDP, and over TCP when an answer is cut short.

- From `/etc/resolv.conf` it reads the `nameserver` lines (the first 3) and the options `timeout`, `attempts` and
  `rotate`. With `--dns-server` it asks those servers instead. It reads the file again when the file changes.
- It does not read the other lines and options of `/etc/resolv.conf`: `sortlist`, and the options `single-request`,
  `use-vc`, `no-aaaa`, `inet6` and `edns0` (it always sends EDNS0 with 1232 bytes, and asks again without it when
  a name server refuses that).
- It reads `/etc/hosts` first, as the system resolver does.
- Tested name servers: a systemd-resolved stub (`127.0.0.53`), Docker's embedded DNS (`127.0.0.11`), a local
  resolver, public resolvers.

The same with both resolvers: `nsswitch.conf` is not read (the binary is static: `/etc/hosts`, then DNS), so names
that only mDNS (`.local`), LDAP or NIS know are not found; there is no DNSSEC check and no DNS over TLS or HTTPS.

### `--dns-share`

A thread that comes back goes to the client address with the fewest lookups running, and for that address to its
connection with the fewest. So a new client waits for a thread to come back, not behind the queue of a client that
already has lookups running. Needs at least 2 resolver threads (with `--dns-threads 1` the order stays arrival order).
See [slow names](public-server.md#slow-names-and-the-resolver-threads).

### `--dns-reserve`

A quarter of the resolver threads (4 of 16; at least one, and none when there is only 1 thread) is kept for clients
that are not slow. A client is slow while one of its lookups has run for 1 s, and for 60 s after such a lookup is
back. Slow is the connection, and with it every connection of its client address when that address is public
(an IPv4 address, an IPv6 /64). All slow clients together use the other threads (12 of 16) and no more, also when
the kept threads are free. Among themselves, and among the clients that are not slow, the threads go by the rule of
`--dns-share`, which `--dns-reserve` turns on. A client is not slow in its first second, so its first names can
take every thread once.

What it costs is in [slow names](public-server.md#slow-names-and-the-resolver-threads). With `--log-level debug`
the start prints the number of kept threads (`DNS share (reserve: 4 of 16 threads)`).

<a id="logging-and-metrics"></a>
## Logs

`finalwisp --help logs` prints these options: log level, connection and stream logs, metrics.

| option | value | default | what it does |
|---|---|---|---|
| `--metrics-interval` | `SECS` | `0` (off) | Print one line with all counters on stderr every SECS seconds, and a last one at exit. |
| `--log-level` | `error\|warn\|info\|debug` | `info` | Which lines are printed on stderr. `error`: fatal startup errors only; `warn`: also warnings; `info`: also startup, shutdown and metrics lines; `debug`: also a line when a connection opens (with `--log-conns`). |
| `--log-conns` |  | off | One line per connection when it closes, with the client IP, duration, bytes and close reason. |
| `--log-streams` |  | off | One line per stream (client IP, target host and port, bytes, close reason) and one per refused CONNECT. This logs where your users go: a privacy decision. |
| `--metrics-listen` | `[ADDR:]PORT` | off | Serve Prometheus metrics at `GET /metrics` on their own port. A bare port listens on 127.0.0.1. No authentication: keep it on loopback or a private address. It cannot share the Wisp port. |

Log formats and the metric names are in [logs and metrics](logs-metrics.md).

<a id="performance-switches"></a>
## Memory

`finalwisp --help memory` prints these options: memory budget, kernel TCP memory.

The memory budget is on by default. `--tcpmem-adapt` and `--park-rcvlock` are off by default; credit pacing and adaptive
splice are on. [Memory](memory.md) explains when each one helps.

| option | value | default | what it does |
|---|---|---|---|
| `--mem-budget` | `BYTES` | automatic | The memory the server plans to stay under. Automatic means the cgroup memory limit, else half of the RAM. `0` turns the budget off, and with it the memory levels and the warning about kernel TCP memory pressure (see [runtime hints](logs-metrics.md#runtime-hints-and-warnings)). See [memory budget](memory.md#memory-budget). |
| `--tcpmem-adapt` |  | off | When the host is near its kernel TCP memory limit (`net.ipv4.tcp_mem`), shrink the buffers of this server's sockets to remote peers. For a small VPS that runs out of TCP memory under many fast streams. [Details](#--tcpmem-adapt). |
| `--no-credit-pace` |  | credit pace on | Turn off credit pacing. By default a stream gets no new upload credit while its download waits on the client (the client reads slower than the target answers), so echo-like traffic and other full-duplex bulk transfers cannot fill the kernel socket buffers faster than the client reads. [Details](#--no-credit-pace). |
| `--park-rcvlock` |  | off | Stop the kernel from growing the receive buffer of a download stream's target connection while the stream waits on a slow client. Needs Linux 5.15 or later (the server refuses to start otherwise). [Details](#--park-rcvlock). |
| `--adaptive-splice` |  | on | The default since 1.2.1. Still accepted, so that a 1.2.0 config keeps working. After `--no-adaptive-splice` it turns adaptive splice back on. |
| `--no-adaptive-splice` |  | adaptive splice on | Turn off adaptive splice (on by default since 1.2.1; `--adaptive-splice` is still accepted). Adaptive splice reads less from the targets of a busy far client at a time. [Details](#--no-adaptive-splice). |

### `--tcpmem-adapt`

Needs cgroup v2 socket accounting, Linux 5.15 or later, the host network namespace, credit v2 and the memory budget;
a warning at startup says why it is off otherwise, and so does `--show-config`.

### `--park-rcvlock`

Without it, each waiting download can hold up to `net.ipv4.tcp_rmem` max (6-32 MiB) of the target's data in kernel
memory, and many waiting downloads can push a small host into TCP memory pressure. The buffer keeps the size it has
(it is never made smaller, so no data is dropped; one below 512 KiB is raised to 512 KiB or to twice
`net.core.rmem_max`, whichever is smaller; finalwisp measures that limit with a test socket, so it also works in
containers that hide the net sysctls) and grows again once the client catches up. Streams whose client sent data in
the last 250 ms, or whose upload credit pacing holds, are not affected. It does nothing while the memory budget is
below 256 MiB (the memory caps already limit these buffers there; `rcvlock_locks` stays 0). After a period of memory
pressure, a target that the caps skipped can keep its lock until its stream next catches up, or until it closes. See
[memory](memory.md#memory-budget) for when it helps.

### `--no-credit-pace`

Measured (echo 10 x 10, pacing vs v1.0.0): 1.06-1.10x the throughput on a laptop and 24- and 72-thread servers and
1.7x on a 2-core VPS; server memory 4-10x lower (1.3x on a 2-core VPS with small socket buffer limits, which stays in
host TCP memory pressure with 100 echo streams in both builds; `--buffer 32` kept it out in most runs there); host TCP
memory up to 5x lower on the big machines but only about 10% lower on 2-core VPSes at 100 streams. On the VPSes it
takes most echo cases with fewer streams out of host TCP memory pressure. Cost: a single echo stream on one 2-core VPS
was about 2-3% slower (no change or faster on the other machines). Uploads, downloads and request/response traffic are
not affected. Turn it off only to compare or roll back.

### `--no-adaptive-splice`

When a client whose round trip was 10 ms or more at connect has more than 4 streams open (busy or idle) and its socket
is backed up, each zero-copy read from one of its targets takes at most 64 KiB instead of 256 KiB. This helps a small
host that serves many slow downloads to far clients: with one client 112 ms away running 100 download streams on a
2-core VPS, the download was 1.2-1.4x faster and the host stayed out of kernel TCP memory pressure (0 of 16 runs
instead of 9-12). Clients closer than 10 ms (same host, LAN), clients on `--listen-unix` and all clients behind a
reverse proxy on the same host keep the 256 KiB reads, so it changes nothing for them: no gain and no cost. On a
2-core VPS with clients on the same host, echo and download tests with 1 to 100 streams per client showed no
difference with it on. Turn it off only to compare or roll back. Clients with 1-4 streams are not affected. It does
nothing when splice is off (`--no-splice`, or a `--download-rate` cap). See [small
hosts](memory.md#small-hosts-and-many-slow-downloads).

<a id="advanced-and-diagnostic"></a>
## Advanced

`finalwisp --help advanced` prints these options: tuning and diagnostic switches.

Leave these at the default unless a problem points at one of them.

| option | value | default | what it does |
|---|---|---|---|
| `--buffer` | `N` | `128` | The first stream credit (packets) the server grants. `0` counts as 1. [Details](#--buffer). |
| `--graceful-close` |  | reset | Close a finished target connection with FIN instead of a TCP reset when the client closes the stream. The reset is much faster under connection churn and leaves no `TIME_WAIT` sockets behind. |
| `--no-splice` |  | splice on | Copy downloads through user space instead of the kernel's zero-copy `splice`. [Details](#--no-splice). |
| `--balance` |  | off | Hand each new connection to the least busy thread instead of letting the kernel choose. Helps a few busy long-lived connections on big machines (4-11 % on 36-72 threads) and costs 1-7 % when many short connections come and go. |
| `--no-tfo` |  | TFO on | Do not use TCP Fast Open to targets. Try it if a middlebox drops SYN packets that carry data. |
| `--no-keepalive` |  | on | Turn off dead-peer detection on clients and targets (TCP keepalive). With it on, an idle dead peer is closed after about 180 s. |
| `--no-credit-v2` |  | credit v2 on | Turn off the upload credit scheme that pings the client after a CONTINUE. A compatibility fallback; leave it on. |
| `--notsent-lowat` | `BYTES` | `131072` | `TCP_NOTSENT_LOWAT` on client sockets: how much unsent data the kernel holds per socket. `0` leaves it to the kernel. |
| `--no-prio` |  | two lanes | Use one output queue per client. By default data of bulk streams waits in a second lane, so small replies on other streams can go first. |

### `--buffer`

Leave it, except on a small host where echo-like traffic (streams that upload and download at once) causes kernel TCP
memory pressure and large uploads on open connections are rare: `--buffer 32` kept a 2-core VPS out of pressure in 15
of 16 loopback echo runs (10 x 10 streams) and cut server memory from 144 to 22 MiB, but an upload of 1-4 MiB on an
open connection waits one more round trip (at 115 ms: 1 MiB in 243 instead of 121 ms). It does not help with pressure
from downloads. See [small hosts](memory.md#small-hosts-and-many-slow-downloads).

### `--no-splice`

On a small host whose clients are far away it probably holds less kernel TCP memory: one client with 100 download
streams at 20 ms on a 2-core VPS got 1.2x the speed, the host left TCP memory pressure in most runs (13-14 of 16 runs
in pressure before, 0-2 after), and an upload next to it slowed far less (median 19 instead of 0.3 MiB/s). Cost: on
loopback on the same 2-core VPS, downloads were 12-31% slower and the host held more TCP memory, not less; keep splice
on where clients and targets are close and fast. See [small hosts](memory.md#small-hosts-and-many-slow-downloads).
