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

## Startup warnings

finalwisp warns about host settings that limit it, but never changes them. `finalwisp --show-config` lists the same
values, with a note for each one that limits the server:

| warning about | why it matters | where to change it |
|---|---|---|
| `tcp_wmem` / `tcp_rmem` max below 16 MiB | one stream's speed is limited to about max / round-trip time | `net.ipv4.tcp_wmem`, `net.ipv4.tcp_rmem` |
| `tcp_mem` max below 512 MiB | the kernel runs out of TCP memory under many fast streams | `net.ipv4.tcp_mem` |
| `somaxconn` below 4096 | bursts of new connections are dropped | `net.core.somaxconn` |
| open files below 65536 | each connection and stream is one file descriptor | `LimitNOFILE=`, `ulimit -n` |
| memory budget off | `/proc/meminfo` could not be read | set `--mem-budget` |

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
- The first few packets of each connection are not paced, so a capped connection can burst at its start.
- On a connection with a download cap, the upload slows down too, because control messages wait behind queued data.
- All streams of one connection share it: with `--upload-rate`, a small request waits behind a bulk upload on the
  same connection.
- Idle memory creeps up a little after load peaks (allocator retention, under 2 MiB in our longest tests). It resets
  on restart. Long soak tests found no leak.
- A client whose socket reports an error while it is paused or closing is logged as `client_close`; such a timeout
  is not counted in `dead_peers`.
- A client that vanished without closing (power loss, a NAT that dropped it) is found by TCP keepalive after 3 to 4
  minutes of idle time. `--no-keepalive` turns this off; the price is that such a client is no longer found while its
  connection is idle.
