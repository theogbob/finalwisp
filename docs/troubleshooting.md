# Troubleshooting

Find a problem by what you see, with its cause and the fix. The last section lists the known limits.

First check that the server answers. With built-in TLS use `https://`:

```sh
curl http://HOST:PORT/
# finalwisp: this is a Wisp server
```

Then check the settings in effect. This starts nothing:

```sh
finalwisp YOUR-OPTIONS --show-config
```

## Problems

- [The client cannot connect at all](#the-client-cannot-connect-at-all)
- [The page cannot connect, and the browser console says "mixed content"](#the-page-cannot-connect-and-the-browser-console-says-mixed-content)
- [Connections drop after about 60 seconds of idle time](#connections-drop-after-about-60-seconds-of-idle-time)
- [All clients are limited together, or the logs show only `127.0.0.1`](#all-clients-are-limited-together-or-the-logs-show-only-127001)
- [`wss://` start fails with "modprobe tls"](#wss-start-fails-with-modprobe-tls)
- [Streams fail with `0x48` (blocked)](#streams-fail-with-0x48-blocked)
- [Streams fail with `0x42` for short internal names](#streams-fail-with-0x42-for-short-internal-names)
- [Streams fail with `0x49` (throttled)](#streams-fail-with-0x49-throttled)
- [Uploads slow down for everyone while one client downloads a lot](#uploads-slow-down-for-everyone-while-one-client-downloads-a-lot)
- [Name lookups are slow when a name server is down](#name-lookups-are-slow-when-a-name-server-is-down)
- [New names are slow, or fail with `0x42`, while other streams work](#new-names-are-slow-or-fail-with-0x42-while-other-streams-work)
- [Clients are reset with `why=unread`](#clients-are-reset-with-whyunread)
- [New connections and streams time out, and the host's connection-tracking table is full](#new-connections-and-streams-time-out-and-the-hosts-connection-tracking-table-is-full)
- [Startup warnings](#startup-warnings)
- [Known limits](#known-limits)

### The client cannot connect at all

- finalwisp listens on `127.0.0.1` by default. Use `--host 0.0.0.0` for direct clients, or connect through your proxy.
- `curl http://HOST:PORT/` (with built-in TLS: `curl https://HOST:PORT/`) should print
  `finalwisp: this is a Wisp server`. If it does, the network path is fine and
  the problem is in the WebSocket upgrade (check the proxy's `Upgrade` and `Connection` headers).

### The page cannot connect, and the browser console says "mixed content"

Browsers do not let a page that was loaded over `https://` open a `ws://` connection to another machine. That is a
rule of browsers, not of finalwisp. Give the page a `wss://` address: put a [reverse proxy](reverse-proxy.md) in
front of finalwisp, or use the [built-in TLS](tls.md).

### Connections drop after about 60 seconds of idle time

nginx's `proxy_read_timeout` defaults to 60 s. Raise it (see [nginx](reverse-proxy.md#nginx)). Behind Cloudflare, idle WebSockets
are closed after about 100 s.

### All clients are limited together, or the logs show only `127.0.0.1`

finalwisp sees the proxy, not the clients. Set `--trusted-proxy` to the proxy's address and make the proxy send
`X-Forwarded-For`. When finalwisp can see this case it prints a hint: see
[what the server can and cannot tell](reverse-proxy.md#what-the-server-can-and-cannot-tell).

### `wss://` start fails with "modprobe tls"

The `tls` kernel module is not loaded. Run `sudo modprobe tls` and add it to `/etc/modules-load.d/`. Under the
systemd unit, the service cannot load it itself (`ProtectKernelModules=yes`). In Docker, load it on the host. On a
kernel without kTLS, use a reverse proxy.

### Streams fail with `0x48` (blocked)

The destination policy refused them. Loopback, private and the server's own addresses are blocked by default. Run
with `--log-streams` to see the `rule=` that matched.

### Streams fail with `0x42` for short internal names

finalwisp looks up every name as a full name and ignores `search` in `/etc/resolv.conf`. Send the full name
(`intranet.corp.example`), or put the name in `/etc/hosts`. (Internal targets also need `--allow-private`.)

### Streams fail with `0x49` (throttled)

A stream limit was hit, or the server is under memory pressure. Check the `finalwisp_memory_level` metric and the
`refuse_*` counters. Under pressure, raise the memory limit or lower the load.

Three guards (`--tcpmem-share`, `--port-share`, `--dest-failfast`; see `--print-preset public` for the ones
your preset turns on) also refuse streams, each with a warning in the log that names the cause and the fix: `refuse_tcpmem_share` (one address holds most of the downloads that are not read while the host's TCP
memory is short), `refuse_port_share` and `refuse_port_full` (the source ports toward one destination), and
`refuse_dest_dead` (CLOSE `0x43`: a destination that does not answer). See the
[reference](configuration.md#--tcpmem-share).

### Uploads slow down for everyone while one client downloads a lot

On a small host this is often kernel TCP memory pressure. See
[small hosts and many slow downloads](memory.md#small-hosts-and-many-slow-downloads).

### Name lookups are slow when a name server is down

The system resolver waits about 10 s per dead server. `--dns-own` (or `--dns-server`) waits 1-2 s for each try, at most 3
tries, so it gives up on a name after 6 s at most (4 to 6 s with the defaults of `/etc/resolv.conf`).
The public preset sets `--dns-own`.

### A name resolves on the host but not through finalwisp

With `--preset public` (or `--dns-own`) the built-in resolver asks the name servers of `/etc/resolv.conf` itself.
It does not use the other options of that file, and neither resolver reads `nsswitch.conf`
([what the built-in resolver reads](configuration.md#--dns-own)). To compare, start with `--no-dns-own`: then the
system resolver is used. `finalwisp --show-config` shows which resolver is in effect and its name servers
(`name lookups`).

### New names are slow, or fail with `0x42`, while other streams work

The resolver threads are busy, most often with names whose name server does not answer. Check
`finalwisp_dns_wait_max_seconds` and `finalwisp_dns_expired_total`. See
[slow names](public-server.md#slow-names-and-the-resolver-threads).

### Clients are reset with `why=unread`

`--unread-close` is on (the public preset sets it), and the host's TCP memory was short. A connection with a download that its client did not
read (receive window 0, no data taken) used up its stall time (600 seconds, more for data it took) and was reset.
The counter is `close_unread`, the log has one warning per 10 s at most. A client that was paused for 10 minutes or
more in all (a phone app in the background, a frozen browser tab), or one that reads slower than 512 bytes per second,
can be one of them; it connects again. If honest clients are reset often, the host needs more TCP memory
(`net.ipv4.tcp_mem`, or more RAM), or turn the option off with `--no-unread-close` (that also turns off its relief of
waiting downloads). See the [reference](configuration.md#--unread-close).

### Slow downloads end with `0x03` while the host's TCP memory stays short

A download whose client reads slowly ends with `0x03` (`why=target_close` in `--log-streams`) after 25 minutes or more,
while the host's TCP memory has been short all that time. The destination ended the connection, not finalwisp. The
bytes that the slow client has not read yet wait in the kernel, in the receive buffer of the server's connection to the
destination. While TCP memory is short, the kernel accepts new data for a socket only while the socket holds less than
its share (about `net.ipv4.tcp_mem` maximum divided by the number of TCP sockets on the host). A socket with more than
that drops what the destination sends. The destination gets no acknowledgement, and its kernel ends the connection
after about 15 minutes (`net.ipv4.tcp_retries2`). The socket gets under its share again only as the client reads, and a
client that reads a few KiB per second needs longer than that for a few MiB. With `--unread-close` (the public preset
sets it) the server reads such a socket out into its own memory while TCP memory is short, so this happens only past
its cap (a quarter of the memory budget), with the option off, or on a kernel older than 5.15. See [Known limits](#known-limits) for what to do.

### New connections and streams time out, and the host's connection-tracking table is full

When the host has a firewall with connection tracking (`nf_conntrack`), each client connection and each stream takes
an entry, and a closed one keeps its entry for up to 2 minutes. When the table is full, the kernel drops the packets
of new connections: new clients and new streams time out, and `connect_timeout` goes up. With `--net-watch` (in the
public preset) the server warns at the start and while it runs when the table is 3/4 full; the gauges are
`host_conntrack` and `host_conntrack_max`, and `--show-config` says whether the table is smaller than the server's
open-file budget. Fix: a larger
`net.netfilter.nf_conntrack_max` on the host. In a container the table may belong to the host, and its files may not
be readable: then there is no warning. See the [reference](configuration.md#--net-watch).

## Startup warnings

finalwisp warns about host settings that limit it, but never changes them. `finalwisp --show-config` lists the same
values, with a note for each one that limits the server:

| warning about | why it matters | where to change it |
|---|---|---|
| `tcp_wmem` / `tcp_rmem` max below 16 MiB | one stream's speed is limited to about max / round-trip time | `net.ipv4.tcp_wmem`, `net.ipv4.tcp_rmem` |
| `tcp_mem` max below 512 MiB | the kernel runs out of TCP memory under many fast streams | `net.ipv4.tcp_mem` |
| `somaxconn` below 4096 | bursts of new connections are dropped | `net.core.somaxconn` |
| open files below 65536 | each connection and stream is one file descriptor | `LimitNOFILE=`, `ulimit -n`, `docker run --ulimit nofile=1048576:1048576` |
| memory budget off | `/proc/meminfo` could not be read | set `--mem-budget` |
| connection-tracking table (with `--net-watch`) | 3/4 full: new connections are dropped when it is full | `net.netfilter.nf_conntrack_max` |

The `tcp_wmem` / `tcp_rmem` line is not a warning: the kernel's default values are below 16 MiB, so nearly every host
has it. The start output has one line for it, for example
`TCP buffer  4 MiB send, 6 MiB receive: below 16 MiB, see --show-config` (only the side that is below 16 MiB is named).
`finalwisp --show-config` explains it under Notes, and `--log-level debug` prints the same explanation at startup.

## Known limits

- Linux on x86_64 only.
- `wss://` needs kTLS. TLS 1.3 key updates need Linux 6.14; on older kernels a KeyUpdate closes the connection.
- On a small host, one client with many parallel downloads that its own link cannot take can push the host into
  kernel TCP memory pressure, and uploads from other clients then slow down sharply. See
  [small hosts and many slow downloads](memory.md#small-hosts-and-many-slow-downloads).
- `--download-rate` is per connection. There is no per-IP download cap: a client with several connections gets the
  cap on each.
- UDP uploads are not paced by `--upload-rate-per-stream`; `--upload-rate` does cover them.
- A UDP stream has no idle timeout, and the usual ICMP errors (port, host or network unreachable) do not close it: it
  keeps its socket until the client closes the stream or the connection ends.
- The first few packets of each connection are not paced, so a capped connection can burst at its start.
- On a connection with a download cap, the upload slows down too, because control messages wait behind queued data.
- All streams of one connection share it: with `--upload-rate`, a small request waits behind a bulk upload on the
  same connection.
- Idle memory creeps up a little after load peaks (allocator retention, with no proven ceiling). It resets on
  restart. Long soak tests found no leak.
- A client that times out while its connection is already closing keeps the reason it was closing for in its
  `--log-conns` line (for example `client_close`); the timeout is counted in `dead_peers`.
- Slow readers lose their downloads when the host's TCP memory stays short for long. If the host stays above 3/4 of
  `net.ipv4.tcp_mem` for more than about 15 minutes while slow clients have MiBs of unread data waiting, the
  destinations of some of those downloads end their connections, and the streams end with `0x03` (see
  [above](#slow-downloads-end-with-0x03-while-the-hosts-tcp-memory-stays-short)). finalwisp leaves the bytes a client
  has not read in the kernel's receive buffer of the connection to the destination, so that a slow client slows the
  destination down; every proxy that does the same has this limit. `--unread-close` (in the public preset since
  1.4.0) moves those bytes into the server's memory while the host's TCP memory is short, up to a quarter of the
  memory budget. In our tests (a host held at 13/16 of `tcp_mem` for 90 minutes) some slow readers lost their
  downloads after 25 minutes or more without this relief, and none with it. What to do: size `tcp_mem` so that the
  host does not stay above 3/4 of it at its busiest (raise all three values, or add RAM; see
  [memory](memory.md#small-hosts-and-many-slow-downloads)). The resets of `--unread-close` shorten the time that
  clients which take no data at all keep the memory short (after their stall time, 600 seconds or more), and
  `--tcpmem-share` stops one address from adding more unread downloads. Neither of those two helps when honest slow
  readers alone fill the memory; the relief covers them up to its cap.
- A client that vanished without closing (power loss, a NAT that dropped it) is found by TCP keepalive after 3 to 4
  minutes of idle time. `--no-keepalive` turns this off; the price is that such a client is no longer found while its
  connection is idle.
