# Configuration reference

Every option finalwisp accepts, grouped by topic, with its default. The source of truth is the binary itself:
`finalwisp --help` prints the full list (to stderr) and exits with status 2.

All options are off or at a safe default unless you set them. A plain `finalwisp` serves `ws://127.0.0.1:6001/`.

## How options are read

- Options are read left to right. When an option is given twice, the last one wins (`--port 7000 --port 7001` listens
  on 7001).
- A switch such as `--no-splice` cannot be turned off again later on the same command line.
- A bare number is the port: `finalwisp 7000` is the same as `finalwisp --port 7000`.
- The policy, CIDR and `--proxy-protocol` lists take comma-separated values and can be repeated; repeated values add
  up. `--dns-server`, `--tls-cert` / `--tls-key` and `--cert-auth-key` take one value each: repeat the option.
- Sizes and rates (`--mem-budget`, `--download-rate`, `--upload-rate-per-stream`, `--upload-rate`,
  `--upload-rate-per-ip`) accept the suffixes `K`, `M` and `G` (powers of 1024: `1M` = 1048576). Every other number is
  a plain integer (`--notsent-lowat 131072`, not `128K`).
- An unknown option, a bad value or a removed option prints `finalwisp: <reason>` and exits with status 2.

## Config file

`--config FILE` reads options from a file. Use it for anything longer than a few flags, and for secrets such as an
`--upstream` URL with a password.

```text
# /etc/finalwisp.conf
# finalwisp behind nginx on the same host
host 127.0.0.1
port 6001
trusted-proxy 127.0.0.1
max-conns 10000
max-conns-per-ip 50
block-smtp
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

How the file and the command line combine:

- The file's options take the place of `--config FILE` on the command line. An option after `--config` overrides
  the file; an option before it is overridden by the file.
- A list option given anywhere on the command line replaces the file's whole list. Lists are not merged.
  `--tls-cert` and `--tls-key` count as one list.
- A switch set in the file cannot be turned off on the command line. Remove the line instead.

Errors stop the server before it opens any socket, with status 2. The message names `FILE:LINE` and the option, but
never the value, because the file may hold secrets. Limits: the file must be at most 1 MiB, each line at most 16 KiB,
valid UTF-8 and free of control characters.

The startup line `finalwisp: capabilities: ...` ends its first part with `config FILE`, so you can see which file was
used. If a file that holds a secret (`upstream` with a password) can be read by group or others, finalwisp prints a
warning. Use mode 0600 for such a file, owned by the service user.

The file is read once at startup. `SIGHUP` reloads TLS certificates only; restart the server to apply a changed config
file.

## Listening and TLS

| option | default | what it does |
|---|---|---|
| `PORT`, `--port P` | `6001` | TCP port to listen on (0-65535; do not use 0). |
| `--host H` | `127.0.0.1` | Address to listen on. An IP address, not a name. Use `0.0.0.0` or `::` for direct clients; keep `127.0.0.1` behind a reverse proxy on the same host. |
| `--threads N` | number of CPUs | Event loop threads. Lower it to leave cores to other services. `0` counts as 1. |
| `--tls-cert FILE --tls-key FILE` | off | Serve `wss://` with kernel TLS. Both files are PEM. Repeat the pair for more names: the certificate is picked by SNI, and the first pair is used when nothing matches. Needs the `tls` kernel module (see the [deployment guide](deployment.md#built-in-tls)). |
| `--tls-cipher-order client\|server` | `client` | `server` prefers AES-GCM over ChaCha20 whatever the client prefers. Useful on CPUs with AES instructions. |
| `--listen-unix PATH` | off | A second listener on a Unix socket, next to the TCP one. Plain `ws://` only. Meant for a reverse proxy on the same host. Clients on it are trusted to send the client-IP header, like `--trusted-proxy`. |
| `--unix-mode OCTAL` | `660` | Permissions of the Unix socket file. Whoever may write the file may connect. Needs `--listen-unix`. |
| `--proxy-protocol tcp\|unix` | off | Every connection on that listener (`tcp`, `unix` or both, comma-separated) must start with a PROXY protocol v1 or v2 header. Use it behind a TCP load balancer that sends one. A connection without the header is reset. |
| `--proxy-protocol-from CIDRS` | none | The load balancers allowed to send the PROXY header on TCP. Required with `--proxy-protocol tcp`. Any other peer is reset. |

The server accepts Wisp on any path that ends with `/` (`ws://host:6001/` or `ws://host:6001/wisp/`). A WebSocket
on a path that ends with `host:port` (`ws://host:6001/proxy/example.com:443`) is a wsproxy connection: one TCP stream
over one WebSocket, under the same destination policy and limits. A plain HTTP request without a WebSocket upgrade
gets `200 OK` and the text `finalwisp: this is a Wisp server`, which is handy for health checks.

## Authentication and Wisp v2

| option | default | what it does |
|---|---|---|
| `--auth-file FILE` | off | Wisp v2 password authentication. One `user:password` per line; `#` lines and blank lines are skipped. The passwords are plain text: keep the file private (finalwisp warns if group or others can read it). |
| `--cert-auth-key FILE` | off | Wisp v2 ed25519 key authentication. The file holds one or more PEM `PUBLIC KEY` blocks (for example from `openssl pkey -in key.pem -pubout`). Repeatable. |
| `--motd TEXT` | off | A Wisp v2 message of the day. |
| `--buffer N` | `128` | The first stream credit (packets) the server grants. `0` counts as 1. Leave it, except on a small host where echo-like traffic (streams that upload and download at once) causes kernel TCP memory pressure and large uploads on open connections are rare: `--buffer 32` kept a 2-core VPS out of pressure in 15 of 16 loopback echo runs (10 x 10 streams) and cut server memory from 144 to 22 MiB, but an upload of 1-4 MiB on an open connection waits one more round trip (at 115 ms: 1 MiB in 243 instead of 121 ms). It does not help with pressure from downloads. See [small hosts](deployment.md#small-hosts-and-many-slow-downloads). |
| `--no-credit-v2` | credit v2 on | Turn off the upload credit scheme that pings the client after a CONTINUE. A compatibility fallback; leave it on. |

With any authentication option set, every client must authenticate. Wisp v1 clients cannot connect, and plain
WebSocket proxy (wsproxy) connections get `403 Forbidden`, because neither has a way to send credentials.

## Limits

All limits are off by default. The memory budget (below) protects the server even without them; these are policy
limits that you choose.

| option | default | what it does |
|---|---|---|
| `--max-conns N` | off | At most N client connections in total. A new connection over the limit is reset right after accept. |
| `--max-streams-per-conn N` | off | At most N streams on one connection. A CONNECT over it is refused with Wisp CLOSE `0x49` (throttled); the connection stays. |
| `--max-conns-per-ip N` | off | At most N connections per client address (IPv4 address or IPv6 /64). A direct client over it is reset at accept; behind a trusted proxy it gets `429 Too Many Requests`. |
| `--stream-rate-per-ip R[/B]` | off | New streams per second per client address, with a burst of B (default 2R). R is 1 to 1000000. Over it: CLOSE `0x49`. |
| `--conn-rate-per-ip R[/B]` | off | New connections per second per client address, with a burst of B (default 2R). R is 1 to 1000000, B is 1 to 2000000. A direct client over it is reset at accept; behind a trusted proxy it gets `429 Too Many Requests`. "200 connections per 10 seconds" is `20/200`. |
| `--stream-rate-per-dest R[/B]` | off | New streams per second to one destination (target IP and port), all clients together, with a burst of B (default 2R). R is 1 to 1000000. Over it: CLOSE `0x49`. See [per-destination limits](deployment.md#per-destination-limits). |
| `--stream-rate-per-dest-minute N` | off | New streams per minute to one destination, all clients together (1 to 60000000). Over it: CLOSE `0x49`. |
| `--download-rate RATE` | off | The most the server sends on one client connection per second, all its streams together. Uses kernel TCP pacing. Range 16K to 4095M bytes per second. Also turns off splice. |
| `--upload-rate-per-stream RATE` | off | The most the server sends to one TCP target per second, per stream. Uses kernel TCP pacing. Range 16K to 4095M. |
| `--upload-rate R[/B]` | off | The most finalwisp reads from one client connection per second (all its TCP and UDP streams). R is 8K to 1T. Burst B defaults to max(R, 16K) and must be at least 16K and at least R/10. Over the limit the client is not read until it is under again; nothing is dropped. |
| `--upload-rate-per-ip R[/B]` | off | The same as `--upload-rate`, shared by all connections of one client address. |
| `--mem-budget BYTES` | automatic | The memory the server plans to stay under. Automatic means the cgroup memory limit, else half of the RAM. `0` turns the budget off. See [memory budget](deployment.md#memory-budget). |
| `--connect-timeout SECS` | `10` | How long a connect to a target may take (at most 86400). A timeout closes the stream with CLOSE `0x43`. |
| `--drain-timeout SECS` | `30` | On SIGTERM or SIGINT, how long open connections may continue before they are closed (at most 86400; `0` exits at once). |

Rates are bytes per second of TCP payload. In network units: `1M` is about 8.4 Mbit/s, `10M` about 84 Mbit/s,
`100M` about 839 Mbit/s.

Per-IP limits need the real client address. Behind a reverse proxy, set `--trusted-proxy` (or use `--listen-unix`).
Without it every client has the proxy's address and they all share one limit.

## Destination policy

These options decide which targets clients may reach. A refused stream gets Wisp CLOSE `0x48` (blocked). List options
are comma-separated and repeatable.

| option | default | what it does |
|---|---|---|
| `--allow-loopback` | off | Let clients reach loopback targets (127.0.0.0/8, ::1, 0.0.0.0/8, `::`). Only for tests or a trusted service on the same host. |
| `--allow-private` | off | Let clients reach private, link-local, CGNAT and other reserved ranges. Only on a trusted network. It does not lift the two classes below. |
| `--allow-self` | off | Let clients reach the server's own interface addresses. Blocked by default even with `--allow-private`. |
| `--allow-embedded-v4` | off | Let clients reach IPv6 forms that carry an IPv4 address (`::/96`, 6to4, Teredo, local-use NAT64). Blocked by default. |
| `--allow-host NAMES` | none | Only these host names and the names below them (`example.com` also allows `a.example.com`). Any other name is refused. IP addresses skip host rules. |
| `--block-host NAMES` | none | Refuse these host names and the names below them. Wins over `--allow-host`. |
| `--allow-ports [tcp:\|udp:]N[-M],...` | none | Only these ports (1-65535). Without `tcp:` or `udp:` an entry covers both. A list with only `tcp:` entries leaves UDP ports open. |
| `--block-ports [tcp:\|udp:]N[-M],...` | none | Refuse these ports. Wins over `--allow-ports`. |
| `--block-smtp` | off | Refuse the mail ports, the same as `--block-ports tcp:25,tcp:465,tcp:587`. Without it the server prints a hint at startup. |
| `--allow-dest CIDRS` | none | Let these addresses through every address class (loopback, private, own, embedded). Not through `--block-dest`. |
| `--block-dest CIDRS` | none | Refuse these addresses. Checked first. |
| `--no-direct-ip` | off | Refuse a CONNECT to an IP address (including forms such as `127.1` or `2130706433`): clients must send a name. |
| `--no-ipv6-targets` | off | Use IPv4 targets only: no IPv6 addresses, no AAAA lookups. |
| `--no-udp` | UDP on | Refuse Wisp UDP streams (CLOSE `0x48`). |

Address rules run on every address a name resolves to, so a name that points at a blocked address is refused too. Host
rules compare the name exactly as the client sent it (internationalized names arrive as `xn--` punycode) and cannot see
DNS aliases (CNAME). Use `--block-dest` for anything that must never be reached.

## Client IP behind proxies

| option | default | what it does |
|---|---|---|
| `--trusted-proxy CIDRS` | none | Peers whose client-IP header is believed. From any other peer the header is ignored. List only your proxies. |
| `--real-ip-header NAME` | `x-forwarded-for` | The one header read from a trusted peer. `x-forwarded-for` is read right to left, skipping trusted hops. Any other name (`x-real-ip`, `cf-connecting-ip`) is read as one address. |

The client address is used by the per-IP limits and by the connection and stream logs. The `Forwarded` header
(RFC 7239) is not supported.

## Upstream proxy

| option | default | what it does |
|---|---|---|
| `--upstream URL` | off | Send every TCP stream through one proxy: `socks5://`, `socks5h://` or `http://` (HTTP CONNECT), then `[USER[:PASS]@]HOST[:PORT]`. Default ports: 1080 for SOCKS, 80 for HTTP. UDP streams are refused with CLOSE `0x48`. |
| `--upstream-trust-dns` | off | Required with `socks5h://`, refused otherwise. The proxy resolves the target names instead of finalwisp. |

`https://` proxies are not supported. Put a URL that holds a password in a config file with mode 0600; on the command
line it is visible to other users of the host. Logs show it as `scheme://***@host:port`. See
[upstream proxy](deployment.md#upstream-proxy-and-tor) in the deployment guide.

## DNS

| option | default | what it does |
|---|---|---|
| `--dns-threads N` | `16` | Resolver threads (both resolvers). Each thread runs one lookup at a time, so at most N new names are looked up at once: with a 20 ms name server, 16 threads answer about 750 new names per second and further lookups wait. Identical names looked up at the same time share one lookup. `0` counts as 1. |
| `--dns-own` | off | Use the built-in resolver instead of the system's (`getaddrinfo`). It gives up on a dead name server after 1-2 s instead of about 10 s. |
| `--dns-server IP[:PORT]` | from `/etc/resolv.conf` | Name servers for the built-in resolver. At most 3, repeatable. Implies `--dns-own`. IPv6: `[addr]:port`. |

Each worker thread caches answers for 30 s (names with no address: 5 s); expired entries are dropped within about
2 s, also on a worker with no clients. Both resolvers read `/etc/hosts` first. Every name is looked up as a full name: the `search` and `domain` lines of
`/etc/resolv.conf` are not applied, so clients must send full names (`intranet.corp.example`, not `intranet`).

## Logging and metrics

| option | default | what it does |
|---|---|---|
| `--log-level error\|warn\|info\|debug` | `info` | Which lines are printed on stderr. `error`: fatal startup errors only; `warn`: also warnings; `info`: also startup, shutdown and metrics lines; `debug`: also a line when a connection opens (with `--log-conns`). |
| `--log-conns` | off | One line per connection when it closes, with the client IP, duration, bytes and close reason. |
| `--log-streams` | off | One line per stream (client IP, target host and port, bytes, close reason) and one per refused CONNECT. This logs where your users go: a privacy decision. |
| `--metrics-interval SECS` | `0` (off) | Print one line with all counters on stderr every SECS seconds, and a last one at exit. |
| `--metrics-listen [ADDR:]PORT` | off | Serve Prometheus metrics at `GET /metrics` on their own port. A bare port listens on 127.0.0.1. No authentication: keep it on loopback or a private address. It cannot share the Wisp port. |

Log formats and the metric names are in the [deployment guide](deployment.md#logging).

## Performance switches

All are off by default.

| option | default | what it does |
|---|---|---|
| `--balance` | off | Hand each new connection to the least busy thread instead of letting the kernel choose. Helps a few busy long-lived connections on big machines (4-11 % on 36-72 threads) and costs 1-7 % when many short connections come and go. |
| `--tcpmem-adapt` | off | When the host is near its kernel TCP memory limit (`net.ipv4.tcp_mem`), shrink the buffers of this server's sockets to remote peers. For a small VPS that runs out of TCP memory under many fast streams. Needs cgroup v2 socket accounting, Linux 5.15 or later, the host network namespace, credit v2 and the memory budget; the startup line says why it is off otherwise. |
| `--no-credit-pace` | credit pace on | Turn off credit pacing. By default a stream gets no new upload credit while its download waits on the client (the client reads slower than the target answers), so echo-like traffic and other full-duplex bulk transfers cannot fill the kernel socket buffers faster than the client reads. Measured (60.42, echo 10 x 10, pacing vs v1.0.0): 1.06-1.10x the throughput on a laptop and 24- and 72-thread servers and 1.7x on a 2-core VPS; server memory 4-10x lower (1.3x on a 2-core VPS with small socket buffer limits, which stays in host TCP memory pressure with 100 echo streams in both builds; `--buffer 32` kept it out in most runs there); host TCP memory up to 5x lower on the big machines but only about 10% lower on 2-core VPSes at 100 streams. On the VPSes it takes most echo cases with fewer streams out of host TCP memory pressure. Cost: a single echo stream on one 2-core VPS was about 2-3% slower (no change or faster on the other machines). Uploads, downloads and request/response traffic are not affected. Turn it off only to compare or roll back. |
| `--park-rcvlock` | off | Stop the kernel from growing the receive buffer of a download stream's target connection while the stream waits on a slow client. Without it, each waiting download can hold up to `net.ipv4.tcp_rmem` max (6-32 MiB) of the target's data in kernel memory, and many waiting downloads can push a small host into TCP memory pressure. The buffer keeps the size it has (it is never made smaller, so no data is dropped; one below 512 KiB is raised to 512 KiB or to twice `net.core.rmem_max`, whichever is smaller; finalwisp measures that limit with a test socket, so it also works in containers that hide the net sysctls) and grows again once the client catches up. Streams whose client sent data in the last 250 ms, or whose upload credit pacing holds, are not affected. It does nothing while the memory budget is below 256 MiB (the memory caps already limit these buffers there; `rcvlock_locks` stays 0). After a period of memory pressure, a target that the caps skipped can keep its lock until its stream next catches up, or until it closes. Needs Linux 5.15 or later (the server refuses to start otherwise). See the [deployment guide](deployment.md#memory-budget) for when it helps. |
| `--adaptive-splice` | off | Read less from the targets of a busy client at a time. When a client has more than 4 streams open (busy or idle) and its socket is backed up, each zero-copy read from one of its targets takes at most 64 KiB instead of 256 KiB. This helps a small host that serves many slow downloads to far clients: with one client 112 ms away running 100 download streams on a 2-core VPS, the download was 1.2-1.4x faster and the host stayed out of kernel TCP memory pressure (0 of 16 runs instead of 9-12). The cost is on clients close to the server: on the same kind of 2-core VPS, clients on the same host with more than 4 streams were slower (echo with 10 x 5 streams 6-11% slower, and the host now entered TCP memory pressure; a 100-stream download less than half as fast, with the host in TCP memory pressure with or without the flag). Clients with 1-4 streams are not affected. It does nothing when splice is off (`--no-splice`, or a `--download-rate` cap). See the [deployment guide](deployment.md#small-hosts-and-many-slow-downloads). |

## Advanced and diagnostic

Leave these at the default unless a problem points at one of them.

| option | default | what it does |
|---|---|---|
| `--graceful-close` | reset | Close a finished target connection with FIN instead of a TCP reset when the client closes the stream. The reset is much faster under connection churn and leaves no `TIME_WAIT` sockets behind. |
| `--no-splice` | splice on | Copy downloads through user space instead of the kernel's zero-copy `splice`. On a small host whose clients are far away it probably holds less kernel TCP memory: one client with 100 download streams at 20 ms on a 2-core VPS got 1.2x the speed, the host left TCP memory pressure in most runs (13-14 of 16 runs in pressure before, 0-2 after), and an upload next to it slowed far less (median 19 instead of 0.3 MiB/s). Cost: on loopback on the same 2-core VPS, downloads were 12-31% slower and the host held more TCP memory, not less; keep splice on where clients and targets are close and fast. See [small hosts](deployment.md#small-hosts-and-many-slow-downloads). |
| `--no-tfo` | TFO on | Do not use TCP Fast Open to targets. Try it if a middlebox drops SYN packets that carry data. |
| `--no-keepalive` | on | Turn off dead-peer detection on clients and targets (TCP keepalive). With it on, an idle dead peer is closed after about 180 s. |
| `--no-prio` | two lanes | Use one output queue per client. By default data of bulk streams waits in a second lane, so small replies on other streams can go first. |
| `--notsent-lowat BYTES` | `131072` | `TCP_NOTSENT_LOWAT` on client sockets: how much unsent data the kernel holds per socket. `0` leaves it to the kernel. |
| `--tls-rekey-records N` | `8388608` (2^23) | With built-in TLS 1.3, send a KeyUpdate after N records. `0` or 2^24 and above turns it off. Works only on Linux 6.14 or later. |
| `-h`, `--help` | | Print the usage and exit with status 2. |
