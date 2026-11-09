# Deployment guide

This guide takes you from a downloaded binary to a public Wisp server. Each section stands on its own; skip what you
do not need. Every option is listed in the [configuration reference](configuration.md).

- [Install](#install)
- [First run](#first-run)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Built-in TLS](#built-in-tls)
- [systemd](#systemd)
- [Docker](#docker)
- [Config file](#config-file)
- [Signals: reload and graceful shutdown](#signals-reload-and-graceful-shutdown)
- [Securing a public server](#securing-a-public-server)
- [Upstream proxy and Tor](#upstream-proxy-and-tor)
- [Logging](#logging)
- [Metrics and Prometheus](#metrics-and-prometheus)
- [Memory budget](#memory-budget)
- [Kernel features](#kernel-features)
- [Troubleshooting](#troubleshooting)
- [Known limits](#known-limits)

## Install

finalwisp is one static binary for Linux on x86_64. It has no runtime dependencies and no minimum glibc version.

1. Download `finalwisp-VERSION-x86_64-linux.tar.gz` and `SHA256SUMS` from the Releases page.
2. Unpack and check. `SHA256SUMS` covers the tarball and the binary inside it:

   ```sh
   tar -xzf finalwisp-VERSION-x86_64-linux.tar.gz
   sha256sum -c SHA256SUMS
   ```

3. Install it:

   ```sh
   sudo install -m 0755 finalwisp-VERSION-x86_64-linux/finalwisp /usr/local/bin/finalwisp
   ```

The tarball also holds `BUILDINFO`: the commit, toolchain and checksum of the build.

### Build it yourself

```sh
bench/release.sh
# output: server/target/x86_64-unknown-linux-gnu/release/finalwisp and BUILDINFO
```

It needs rustup (the toolchain is pinned in `rust-toolchain.toml`), gcc, and a static glibc 2.34 or newer on the build
machine (Debian and Ubuntu: `libc6-dev`; Fedora: `glibc-static`). The build is reproducible: the same commit, the pinned
Rust toolchain and the same gcc, binutils and glibc versions give the same binary, byte for byte, wherever it is built.
`BUILDINFO` records those versions and the md5, so you can compare your build with the release.

Compiler options such as `-C target-cpu=native` or profile-guided optimization gave no measurable gain in our tests:
the kernel does most of the work (TCP, splice, TLS). They also make the binary stop running on older CPUs, so the
release does not use them.

## First run

```sh
finalwisp
```

```text
finalwisp listening on ws://127.0.0.1:6001/ (8 threads, buffer 128, upload credit v2, credit pace, adaptive splice)
finalwisp: capabilities: 8 threads, memory budget 7845 MiB (MemTotal/2; ...), TLS off, splice on, TFO on, ...
finalwisp: hint: mail ports 25/465/587 are open to clients; --block-smtp closes them
```

That serves `ws://127.0.0.1:6001/`. Point any Wisp client at it. Wisp works on any path that ends with `/`, so
`ws://127.0.0.1:6001/wisp/` works too.

The second line, the capability line, says what the server found on this host: threads, memory budget, TLS support
and more. Warnings may follow. finalwisp never changes system settings; it only tells you about values that limit
it (see [troubleshooting](#troubleshooting)).

To accept clients from other machines without a proxy:

```sh
finalwisp --host 0.0.0.0 --port 6001
```

No root is needed. A port below 1024 needs the `CAP_NET_BIND_SERVICE` capability (the systemd unit below shows how).

Open files: each connection and each stream use one file descriptor, and a connection that uses splice two more.
Raise the limit (`LimitNOFILE=` in systemd, `ulimit -n`, or `--ulimit nofile=` in Docker), for example to 1048576.
The server warns at startup below 65536.

## Behind a reverse proxy

The usual setup: nginx or Caddy terminates TLS on port 443 and forwards to finalwisp on `127.0.0.1:6001`. Use it to
share port 443 with a website, or when the kernel has no TLS support. The cost is speed: the proxy copies every byte
through user space, while finalwisp's own TLS path stays in the kernel.

Two things matter with any proxy:

1. **Idle timeouts.** finalwisp never closes an idle Wisp connection and sends no keepalive pings while a connection is idle. Proxies do close
   idle connections: nginx after `proxy_read_timeout` (60 s by default), even while the client is still sending.
   Raise the timeout.
2. **Client addresses.** Without help, finalwisp sees every client as the proxy's address, so per-IP limits would
   hit everyone at once and the logs show only the proxy. Start finalwisp with `--trusted-proxy 127.0.0.1` and have
   the proxy send `X-Forwarded-For`.

### nginx

```nginx
map $http_upgrade $connection_upgrade { default upgrade; '' close; }

server {
    listen 443 ssl;
    server_name wisp.example.com;
    ssl_certificate     /etc/letsencrypt/live/wisp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wisp.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:6001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;   # the 60 s default cuts idle Wisp connections
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
```

```sh
finalwisp --host 127.0.0.1 --port 6001 --trusted-proxy 127.0.0.1
```

To serve Wisp under a path next to a website, use `location /wisp/ { ... }` with the same lines, and give clients
`wss://wisp.example.com/wisp/`.

### Caddy

```caddy
wisp.example.com {
    reverse_proxy 127.0.0.1:6001
}
```

Caddy handles WebSocket upgrades, sets `X-Forwarded-For` and has no idle timeout by default. On a config reload Caddy
closes proxied WebSockets; `stream_close_delay` keeps them open longer:

```caddy
wisp.example.com {
    reverse_proxy 127.0.0.1:6001 {
        stream_close_delay 5m
    }
}
```

### Cloudflare

Cloudflare proxies WebSockets. It is commonly reported to close idle WebSockets after about 100 seconds (its
documentation gives no number). finalwisp cannot prevent that, because it sends nothing on an idle connection: clients should reconnect,
or send some traffic now and then. For the client address, set `--trusted-proxy` to Cloudflare's published address
ranges and either keep `X-Forwarded-For` or use `--real-ip-header cf-connecting-ip`. If another proxy sits between
Cloudflare and finalwisp, list that proxy too.

### How the client address is read

- Only a peer inside `--trusted-proxy` may name the client. From anyone else the header is ignored.
- Every address in `--trusted-proxy` can claim to be any client, so list only your proxies, never a range that also
  holds clients.
- `X-Forwarded-For` is read from right to left. Trusted hops are skipped, and the first other entry is the client. An
  entry the client wrote itself further left does not count.
- With `--real-ip-header x-real-ip` (nginx: `proxy_set_header X-Real-IP $remote_addr;`), the header holds one address.
- A trusted request without the header is not limited per IP. An unreadable header makes the proxy the client.
- Over `--max-conns-per-ip` or `--conn-rate-per-ip`, a client behind a proxy gets `429 Too Many Requests`; a direct
  client is reset at accept.

### Unix socket between the proxy and finalwisp

`--listen-unix PATH` adds a listener on a Unix socket, next to the TCP one. The proxy then talks to finalwisp
without a loopback TCP hop. The socket always speaks plain `ws://`.

```sh
finalwisp --host 127.0.0.1 --port 6001 --listen-unix /run/finalwisp/wisp.sock
```

```nginx
proxy_pass http://unix:/run/finalwisp/wisp.sock;   # the rest of the location block as above
```

```caddy
wisp.example.com {
    reverse_proxy unix//run/finalwisp/wisp.sock
}
```

- Who may connect is who may write the socket file. Its mode is 660 (`--unix-mode`). Give the directory the proxy's
  group. With systemd: `RuntimeDirectory=finalwisp`, `RuntimeDirectoryMode=2750` and `Group=www-data` in the unit.
  Without systemd: `install -d -m 2750 -o finalwisp -g www-data /run/finalwisp`.
- Clients on the socket are trusted like a `--trusted-proxy`: their `X-Forwarded-For` names the client. So only a
  proxy that sets the header itself may reach the socket. nginx with `$proxy_add_x_forwarded_for` and Caddy do.
- A second finalwisp on the same path refuses to start (a `PATH.lock` file beside the socket is locked). A socket left
  behind by a crash is replaced. A clean shutdown removes the socket.
- The TCP listener stays on. Keep it on `127.0.0.1` if only the proxy should reach finalwisp.
- Download caps, dead-peer detection and built-in TLS do not apply to Unix socket clients.

### PROXY protocol behind a TCP load balancer

A layer-4 load balancer (AWS NLB, HAProxy in `mode tcp`, an nginx `stream {}` block) can put the client's address in
a PROXY protocol header. Turn it on in finalwisp and in the balancer at the same time:

```sh
finalwisp --host 0.0.0.0 --port 6001 --proxy-protocol tcp --proxy-protocol-from 10.0.0.0/16
```

Balancer side: AWS NLB target group attribute `proxy_protocol_v2.enabled`, HAProxy `send-proxy-v2`, nginx stream
`proxy_protocol on`. For HAProxy to a Unix socket: `server fw unix@/run/finalwisp/wisp.sock send-proxy-v2` with
`--proxy-protocol unix`.

- Every connection on that listener must start with the header (v1 or v2). Without it, the connection is reset.
- Only peers in `--proxy-protocol-from` may send it. List only the balancers. An NLB that preserves client addresses
  connects from the client's own address; then the list must be `0.0.0.0/0,::/0` (finalwisp warns), and your
  firewall or security group must let nothing but the balancer reach the port.
- TLS still ends in finalwisp if you use `--tls-cert`: the header comes before the TLS handshake.
- Health checks work: a LOCAL header, or a plain TCP connect and close. A LOCAL check counts as a new connection
  from the balancer's own address, so with `--conn-rate-per-ip` keep R above the check rate of each balancer node.
- With an HTTP proxy or CDN in front of the balancer, also list that hop in `--trusted-proxy`, so its
  `X-Forwarded-For` names the client.

## Built-in TLS

finalwisp can serve `wss://` itself. The handshake runs in finalwisp; after it, the kernel encrypts and decrypts the
data (kernel TLS, kTLS). Data moves without copies through user space, which is the fastest path.

```sh
finalwisp --host 0.0.0.0 --port 443 \
  --tls-cert /etc/finalwisp/fullchain.pem --tls-key /etc/finalwisp/privkey.pem
```

- **Load the kernel module.** kTLS needs the `tls` module. Load it now and at every boot:

  ```sh
  sudo modprobe tls
  echo tls | sudo tee /etc/modules-load.d/tls.conf
  ```

  finalwisp loads the module itself only when it runs with `CAP_NET_ADMIN`, which is not recommended. Without the
  module, a `wss://` start stops with a message that says `sudo modprobe tls`. Plain `ws://` does not need it.
- **Several names.** Repeat the pair: `--tls-cert a.pem --tls-key a.key --tls-cert b.pem --tls-key b.key`. Each
  handshake gets the first certificate that is valid for the name the client asked for (SNI), else the first pair.
- **Renewal.** Send `SIGHUP` (`systemctl reload finalwisp`) after the files change. All pairs are read again; if any
  file is bad, the old set stays in use. Open connections keep their keys.
- **File access.** The service user must be able to read the key. With certbot, a deploy hook can copy the renewed
  files to `/etc/finalwisp` with the right owner and run `systemctl reload finalwisp`.
- **Versions and ciphers.** TLS 1.2 and 1.3, with the AES-GCM and ChaCha20-Poly1305 suites this kernel can offload.
  The capability line lists them (`kTLS ...`). `--tls-cipher-order server` prefers AES-GCM.
- **Key updates.** TLS 1.3 key updates need Linux 6.14 or later. On older kernels, a client that sends a KeyUpdate is
  disconnected, and finalwisp logs it at most once a minute. Use a reverse proxy if that matters to you.

See [kernel features](#kernel-features) for which kernel supports what.

## systemd

A hardened unit file is in [`contrib/finalwisp.service`](../contrib/finalwisp.service).

```sh
sudo cp contrib/finalwisp.service /etc/systemd/system/
sudoedit /etc/systemd/system/finalwisp.service   # adjust ExecStart
sudo systemctl daemon-reload
sudo systemctl enable --now finalwisp
```

What the unit does:

- Runs as a dynamic user (`DynamicUser=yes`), with no root and a read-only view of the system.
- `systemctl reload finalwisp` sends `SIGHUP` (reload certificates); `systemctl stop` sends `SIGTERM` (graceful
  drain). `TimeoutStopSec=40` is longer than the default drain of 30 s plus 2 s.
- `LimitNOFILE=1048576` for many connections and streams.
- `MemoryMax=` (commented out) sets the memory the server may use. finalwisp reads the limit and stays under it; see
  [memory budget](#memory-budget).

Changes you may need:

- **Files to read** (`--tls-key`, `--auth-file`, `--cert-auth-key`): a dynamic user cannot be given ownership of a
  file. Replace `DynamicUser=yes` with `User=finalwisp` (create it with `useradd --system finalwisp`), and keep the
  files in `/etc/finalwisp`, owned `root:finalwisp`, mode 640.
- **Ports below 1024**: uncomment `AmbientCapabilities=CAP_NET_BIND_SERVICE`.
- **A config file**: `ExecStart=/usr/local/bin/finalwisp --config /etc/finalwisp.conf`. The service user must be able
  to read it; with `DynamicUser=yes` that means mode 644, so keep secrets in the files it names.
- **Unix socket for the proxy**: add `RuntimeDirectory=finalwisp`, `RuntimeDirectoryMode=2750`, `Group=www-data`.

`ProtectKernelModules=yes` hides the kernel modules from the service, so the `tls` module must be loaded at boot
(see [built-in TLS](#built-in-tls)). Older systemd versions ignore the hardening keys they do not know, with a warning.
None of the hardening gets in the way: finalwisp only reads `/proc`, `/sys/fs/cgroup`, `/etc/resolv.conf`,
`/etc/hosts` and its own files.

Running finalwisp in a unit also gives it its own cgroup, which makes the memory budget more precise (see
[memory budget](#memory-budget)).

## Docker

[`contrib/docker/Dockerfile`](../contrib/docker/Dockerfile) builds a tiny image from the static binary: `FROM
scratch`, the binary and `BUILDINFO`, a non-root user (uid 65532).

```sh
# in the unpacked release directory (it holds finalwisp and BUILDINFO)
docker build -f /path/to/contrib/docker/Dockerfile -t finalwisp:VERSION .

docker run -d --name finalwisp -p 6001:6001 --stop-timeout 35 --memory 1g finalwisp:VERSION
```

- The image's default command is `--host 0.0.0.0 --port 6001`. Arguments after the image name replace it, so repeat
  `--host` and `--port` when you add options.
- `--stop-timeout 35`: Docker's default stop timeout is 10 s, shorter than the 30 s drain. Either raise it or set
  `--drain-timeout 7`.
- `--memory` sets the cgroup limit that finalwisp uses as its memory budget.
- For `wss://`, load the `tls` module on the host (a container cannot load it) and mount the certificate pair so uid
  65532 can read it:

  ```sh
  docker run -d -p 443:6001 --stop-timeout 35 -v /etc/finalwisp/tls:/tls:ro finalwisp:VERSION \
    --host 0.0.0.0 --port 6001 --tls-cert /tls/fullchain.pem --tls-key /tls/privkey.pem
  ```

- Names: finalwisp reads `/etc/hosts` and `/etc/resolv.conf`, which Docker provides in every container. Docker
  container names resolve as usual. `--add-host` entries work too.

In Kubernetes the same rules apply: `terminationGracePeriodSeconds` (30 s by default) must be longer than
`--drain-timeout` plus 2 s, so set it to 40 or lower the drain to 25.

## Config file

Every option can live in a file, one per line, without the dashes:

```text
# /etc/finalwisp.conf
host 127.0.0.1
port 6001
trusted-proxy 127.0.0.1
block-smtp
max-conns 10000
```

```sh
finalwisp --config /etc/finalwisp.conf
```

Options after `--config` on the command line override the file. The full syntax is in the
[configuration reference](configuration.md#config-file). The file is read only at startup: restart after a change.

## Signals: reload and graceful shutdown

| signal | effect |
|---|---|
| `SIGHUP` | Reload the TLS certificate files. All or nothing: a bad file keeps the old set. Nothing else is reloaded. |
| `SIGTERM`, `SIGINT` | Graceful shutdown (below). |
| a second `SIGTERM` or `SIGINT` | Exit at once. |

A graceful shutdown:

1. Stops accepting. Connections already waiting in the queue are accepted first, then the listeners close.
2. Closes idle Wisp connections at once with WebSocket close code 1001 ("going away").
3. Lets the other connections continue until they end or `--drain-timeout` (default 30 s) passes.
4. Sends 1001 to the rest and exits with status 0, at most 2 s later.

Clients see 1001 and can reconnect elsewhere. Make your supervisor wait longer than `--drain-timeout` plus 2 s before
it kills the process:

| supervisor | default kill timeout | what to do |
|---|---|---|
| systemd | `TimeoutStopSec=90s` | fine (the unit file sets 40) |
| Docker | 10 s | `docker run --stop-timeout 35`, `docker stop -t 35`, or `--drain-timeout 7` |
| Kubernetes | `terminationGracePeriodSeconds: 30` | set it to 40, or `--drain-timeout 25` |

## Securing a public server

By default finalwisp already refuses loopback, private and reserved targets, the server's own addresses, and IPv6
forms that hide an IPv4 address. Clients can reach the public internet on any port. For a public server, add limits
and decide what clients may reach.

A reasonable start:

```sh
finalwisp --host 127.0.0.1 --port 6001 --trusted-proxy 127.0.0.1 \
  --block-smtp \
  --max-conns 10000 --max-conns-per-ip 50 \
  --max-streams-per-conn 256 --stream-rate-per-ip 50
```

- **`--block-smtp`** closes the mail ports. An open Wisp server is otherwise a spam relay, and hosting providers
  react quickly to that.
- **Connection limits.** `--max-conns` caps the whole process (think of your file descriptor limit). `--max-conns-per-ip`
  stops one address from taking all of them. `--conn-rate-per-ip R/B` limits how fast one address opens new
  connections (a client that connects, closes and reconnects in a loop): `20/200` allows a burst of 200, then 20 per
  second, the same as "200 connections per 10 seconds". A closed connection does not give its token back.
- **Stream limits.** `--max-streams-per-conn` stops one WebSocket from opening thousands of streams (a port scan, for
  example); 64-256 is generous for browsers. `--stream-rate-per-ip` limits how fast one address opens streams.
- **Per destination.** `--stream-rate-per-dest` caps how fast all clients together open streams to one target, so
  your server cannot be used to flood one site (see [per-destination limits](#per-destination-limits)).
- **Bandwidth.** `--download-rate` and `--upload-rate` cap one connection; `--upload-rate-per-ip` caps one address.
  There is no per-IP download cap (see [known limits](#known-limits)).
- **Destinations.** `--allow-ports tcp:80,tcp:443 --no-udp` keeps clients on the web (an allow list for TCP alone leaves UDP
  open). `--block-dest` refuses address ranges,
  `--block-host` names. `--no-direct-ip` forces clients to send names. `--no-udp` refuses UDP streams.
- **Authentication.** `--auth-file` (passwords) or `--cert-auth-key` (ed25519 keys) restrict the server to your own
  clients. This uses Wisp v2; v1 clients cannot connect then.

Points to know about the destination policy:

- The server's own addresses are read once at startup. An address added later (DHCP, a cloud change) needs a restart.
- A public IP that is not on an interface (cloud 1:1 NAT, an EC2 elastic IP) is not in that set. Block it with
  `--block-dest`, or clients can reach your own services through it.
- Host rules match the name as the client sent it and cannot see DNS aliases. Use `--block-dest` for hard blocks.
- An allowed name never lifts an address block: a name that resolves to a private address is still refused.
- `--allow-private` opens your whole internal network to every client. Use it only on a trusted network.

Per-IP limits use IPv4 addresses and IPv6 /64 networks. The table holds up to 65,536 addresses; when it is full, new
addresses are not limited per IP (`--max-conns` still applies).

### Per-destination limits

Per-IP limits stop one client. They do not stop many clients that all open streams to the same site, and to that site
the flood comes from your server's address: abuse reports and IP bans then hit every user. Two options cap new
streams to one destination from all clients together:

```sh
finalwisp ... --stream-rate-per-dest 250/250 --stream-rate-per-dest-minute 6000
```

- `--stream-rate-per-dest R[/B]`: R new streams per second, burst B (default 2R).
- `--stream-rate-per-dest-minute N`: N new streams per minute (refilled evenly, N/60 per second).
- A stream needs room under both. Over either, the stream gets CLOSE `0x49` (throttled); the connection stays open.
  A refused stream uses up no per-destination budget. Open streams are not counted, only new ones.
- The destination is the target IP address and port, after DNS: a name and its address share one limit, and a site
  with several addresses gets the limit per address. With `--upstream socks5h://...` (the proxy resolves names) it is
  the host name and port instead (case-insensitive); a client can then spread its streams over other names of the site.
- The limit counts every client on the whole server (all threads share one table). The table holds 65,536
  destinations; a full table section first drops the entries that have refilled, and if none has, new destinations are
  not limited (counted in `dest_untracked`).
- Refusals are counted in `refuse_dest_rate`; with `--log-streams` they have `rule=dest_rate` (per second) or
  `rule=dest_rate_minute`.

Coming from wispurr: `maxConnectsPerDestPerSecond: 250` and `maxConnectsPerDestPerMinute: 6000` are
`--stream-rate-per-dest 250/250 --stream-rate-per-dest-minute 6000`. wispurr counts in fixed windows; finalwisp
uses token buckets, so the per-minute budget refills gradually instead of all at once at the window's end.

## Upstream proxy and Tor

`--upstream` sends every TCP stream through one SOCKS5 or HTTP CONNECT proxy. Use it to give all clients one exit
address, or to send them through Tor.

```sh
finalwisp --upstream socks5://127.0.0.1:1080
finalwisp --upstream http://user:secret@proxy.example.com:3128
```

- DNS, the destination policy, the limits and the memory budget still run in finalwisp. Only an allowed IP address is
  sent to the proxy.
- There is never a fallback to direct connections. If the proxy fails, the stream fails.
- The proxy's address is not checked against the policy: a proxy on `127.0.0.1` works without `--allow-loopback`.
  A proxy name is resolved at startup and again every 30 s.
- Credentials go to the proxy in clear text (SOCKS and HTTP Basic both do that). Put the URL in a config file with mode
  0600, not on the command line, where other users can read it.
- UDP streams are refused, because neither proxy type carries them here. TLS to the proxy (`https://`) is not
  supported.
- `--connect-timeout` covers the whole setup: the connect to the proxy, its handshake and its connect to the target.

Tested with microsocks, OpenSSH `ssh -D`, tinyproxy (with Basic auth), squid and Tor.

### Tor

```sh
sudo apt install tor     # listens on 127.0.0.1:9050 by default
finalwisp --upstream socks5h://127.0.0.1:9050 --upstream-trust-dns --connect-timeout 30
```

- Use `socks5h://` with `--upstream-trust-dns`. Tor then resolves every name at the exit, and finalwisp sends no DNS
  query at all. With plain `socks5://`, finalwisp resolves the names itself, so your resolver sees every site your
  users visit.
- `.onion` addresses work with `socks5h://` (not with `socks5://`).
- Set `--connect-timeout 30` (the default is 10). The timeout covers Tor's circuit setup and the target connect. A
  first stream after Tor starts can take several seconds, a `.onion` up to about 9 s in our tests, and Tor retries a
  stalled stream on a new circuit only after 10-15 s.
- With `socks5h://`, the address rules cannot see where a name points (the exit resolves it). Host and port rules still
  apply, IP addresses still go through the address rules, and loopback names are still refused locally. finalwisp warns about this at startup.
- If Tor stops, new streams fail at once and finalwisp keeps running. Once Tor is back, streams work again without a
  restart.
- All clients share Tor's circuits, because finalwisp sends one set of SOCKS credentials (none).
- UDP is refused (Tor carries no UDP).

## Logging

Everything goes to stderr. Under systemd, `journalctl -u finalwisp` shows it with timestamps.

`--log-level` chooses how much: `error` (fatal startup errors only), `warn` (and every warning), `info` (the
default: also startup, shutdown, memory level and metrics lines), `debug` (also a line when a connection opens, with
`--log-conns`).

### Connection log

`--log-conns` prints one line per connection when it closes:

```text
finalwisp: ev=conn_close ts=2026-11-01T12:00:00.123Z w=3 cid=3:1842 ip=203.0.113.9 via=10.0.0.2 tls=1 proto=v2 auth=none dur_ms=93812 streams=41 refused=2 rx=18234 tx=91823412 why=client_close
```

| field | meaning |
|---|---|
| `ts` | time (UTC) |
| `w`, `cid` | worker thread; connection id (`worker:sequence`, unique per run) |
| `ip`, `via` | the client; `via` is the trusted proxy it came through (`unix` for the Unix socket) |
| `tls`, `proto`, `auth` | built-in TLS used; `http` (no WebSocket), `v1`, `v2` or `wsproxy`; `none`, `ok` or `failed` |
| `streams`, `refused` | streams opened; CONNECTs refused (policy, limits, memory) |
| `rx`, `tx` | bytes on the wire, WebSocket and TLS framing included |
| `why` | why it closed (below) |

`why` is one of: `client_close`, `server_close` (shutdown, or a plain HTTP request answered), `ws_error`,
`protocol_error`, `hs_timeout` (no complete handshake in time), `auth_failed`, `tls_error`, `pressure_shed` (memory
pressure), `dead_peer` (the client vanished), `limit` (a per-IP limit or a policy refusal).

A connection refused right at accept (`--max-conns`, `--max-conns-per-ip`, `--conn-rate-per-ip`) gives `ev=conn_refused ... why=limit`, at
most 20 lines per second per thread, then one `ev=refused_suppressed n=` line per second.

### Stream log

`--log-streams` prints one line per stream and one per refused CONNECT. It works with or without `--log-conns`:

```text
finalwisp: ev=stream_close ts=2026-11-02T06:46:47.430Z w=0 cid=0:1 ip=203.0.113.9 sid=1 t=tcp host=example.com port=443 dst=93.184.215.14 dur_ms=41 up=517 down=6211 reason=0x02 why=target_close
finalwisp: ev=stream_refused ts=... w=0 cid=0:1 ip=203.0.113.9 sid=5 t=tcp host=example.com port=22 reason=0x48 why=policy rule=ports
```

- `sid` is the Wisp stream id, `t` is `tcp`, `udp` or `wsproxy`, `host` and `port` are what the client asked for, and
  `dst` is the address finalwisp connected to. With `--upstream`, the line has `upstream=1` and `dst` is the proxy.
- `up` and `down` are payload bytes to and from the target (UDP lines add `dgrams_up` and `dgrams_down`).
- `reason` is the Wisp close code sent (table below), or `none` if the client closed the stream.
- `why` is one of `target_close`, `client_close`, `conn_close`, `dns_fail`, `connect_fail`, `upstream_fail`,
  `policy`, `limit`, `pressure`, `invalid`; `rule` names the rule that refused it (`ports`, `private`, `block_dest`,
  `max_streams_per_conn`, `stream_rate`, `dest_rate`, `dest_rate_minute`, ...). A per-destination refusal comes after
  DNS, so it is an `ev=stream_close` line with `reason=0x49 why=limit`, not a `stream_refused` line.
- Expect one line per stream: size your log storage for the stream rate, not the connection rate.

### Privacy and safety of the logs

- Client IPs appear only with `--log-conns` or `--log-streams`. Target names appear only with `--log-streams`.
- User names, keys and passwords are never logged. An `--upstream` URL is shown as `scheme://***@host:port`.
- Values are escaped, so a client cannot fake a line or a field.
- A slow log reader never slows the server: one log thread writes the lines, and lines that do not fit its queue are
  dropped and counted (`ev=log_dropped n=`, metric `log_dropped`). With journald this does not happen at normal rates.

### Wisp close codes

What a client sees when finalwisp closes a stream:

| code | meaning |
|---|---|
| `0x02` | the target closed the connection (normal end) |
| `0x03` | network error on an open stream |
| `0x41` | invalid CONNECT (bad stream type, port 0, a bad host name) |
| `0x42` | unreachable: the name does not resolve, or no route |
| `0x43` | connect timeout (`--connect-timeout`) |
| `0x44` | the target refused the connection |
| `0x47` | an open target stopped answering (keepalive or retransmission timeout) |
| `0x48` | blocked by the destination policy, `--no-udp`, or UDP with `--upstream` |
| `0x49` | throttled: memory pressure, a stream limit, or too many DNS lookups in flight |
| `0x04`, `0xc0`-`0xc2` | (whole connection) incompatible version, bad password, bad signature, authentication required |

WebSocket close codes: 1000 normal, 1001 server shutdown, 1002 protocol error, 1009 message too big, 1013 try again
later (heavy memory pressure, plain `ws://` only).

## Metrics and Prometheus

The counters always run; reading them is off by default. Two ways, usable together:

- `--metrics-interval SECS` prints one `ev=metrics` line with every counter on stderr each interval, and an
  `ev=metrics_final` line at exit.
- `--metrics-listen [ADDR:]PORT` serves `GET /metrics` in the Prometheus text format on its own port. A bare port
  listens on `127.0.0.1`.

```sh
finalwisp --metrics-listen 9464
curl -s http://127.0.0.1:9464/metrics | head
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: finalwisp
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

The endpoint has **no authentication and no TLS**. Keep it on loopback or a private address (finalwisp warns about any
other address), or put your reverse proxy's authentication in front. It can never be the Wisp port, and a port already
in use stops the server at startup.

What you get:

- Counters as `finalwisp_<name>_total`, for example `finalwisp_accepted_total` and
  `finalwisp_refuse_policy_total`.
- Gauges such as `finalwisp_connections`, `finalwisp_streams`, `finalwisp_memory_level` and
  `finalwisp_process_resident_bytes`.
- Close codes sent: `finalwisp_close_total{reason="0x49"}` (a code appears once it was sent at least once). Time at each memory level:
  `finalwisp_memory_level_seconds_total{level="0"}` to `"3"`.
- `finalwisp_build_info{version="..."} 1`.
- Base units only (bytes, seconds). Every metric has `# HELP` and `# TYPE` lines.

No metric carries a client address, a destination or a secret.

Useful ones to watch: `finalwisp_memory_level` above 0 (memory pressure), `finalwisp_refuse_conns_total` and
`finalwisp_refuse_ip_conns_total` and `finalwisp_refuse_ip_connrate_total` (per-IP connection limits hit), `finalwisp_refuse_policy_total` (policy refusals),
`finalwisp_dead_peers_total`, `finalwisp_log_dropped_total` and `finalwisp_upstream_fail_total`.

## Memory budget

finalwisp keeps its memory under a budget instead of meeting the kernel's out-of-memory killer. As usage grows it
shrinks queues and buffers, then stops taking new connections and streams, and as a last step closes the clients that
hold the most memory.

Where the budget comes from (the capability line shows it):

1. `--mem-budget BYTES`, if set (`--mem-budget 0` turns the budget off).
2. Else the cgroup memory limit: systemd `MemoryMax=`, `docker --memory`, a Kubernetes memory limit.
3. Else half of the machine's RAM.

| level | starts at | what changes |
|---|---|---|
| 0 | | normal |
| 1 | 50 % of the budget | smaller queues, credit and socket buffers |
| 2 | 70 % | smaller still; no new connections (they wait in the queue) and no new streams (`0x49`) |
| 3 | 85 % | clients with a pending upload are not read; streams holding over 1 MiB of unsent upload are closed; if that does not help, the clients holding the most memory are closed |

A level goes up at once and comes down after usage stays 10 points lower for a short while, so it does not flap.
Budgets under 256 MiB start at level 1 and never go below it, because a download burst can grow memory faster than it can be
measured.

How usage is measured:

- With a cgroup limit: the cgroup's memory use, minus page cache that can be dropped.
- Without one: finalwisp's own memory plus its socket memory. It reads the socket memory from its own cgroup (cgroup
  v2 with socket accounting, the normal case). Otherwise it falls back to the host's total TCP memory, which counts
  every other program's sockets too.

So **run finalwisp in a cgroup of its own**: a systemd unit, `systemd-run --scope`, or its own container. In a cgroup
shared with other programs, their memory and sockets count against finalwisp's budget. A cgroup of its own also gives
it its own CPU share.

Sizing: an idle connection costs about 1-3 KiB in finalwisp plus about 8 KiB in the kernel. A busy stream can use up
to its socket buffers (`net.ipv4.tcp_rmem` and `tcp_wmem`). Set `MemoryMax=` (or `--mem-budget`) to what the server
may use.

Notes:

- The host's own TCP memory limit (`net.ipv4.tcp_mem`) is shared by every socket on the host and is not part of the
  budget. Credit pacing (on by default, `--no-credit-pace` turns it off) reduces how much of it full-duplex bulk traffic
  (echo-like streams) builds up. It does not always keep a small host out of TCP memory pressure: on a VPS with small
  socket buffer limits, echo with 100 streams still reaches it; `--buffer 32` (a smaller first upload window per stream)
  kept it out in most runs there (60.42). `--tcpmem-adapt` shrinks this server's socket buffers when the host gets close to it.
  Many downloads that wait on slow clients (one client with many streams, for example) keep the targets' data in this
  server's target connections, up to `net.ipv4.tcp_rmem` max each. `--park-rcvlock` (off by default) stops those buffers
  from growing while their streams wait. It catches a buffer before it grows only if the stream starts to wait early;
  a buffer that has already grown keeps its size.
  See [small hosts and many slow downloads](#small-hosts-and-many-slow-downloads) for the trade-offs.
- finalwisp's virtual size (VSZ) is larger than its resident memory, because it reserves memory in 4 MiB chunks. Only
  resident memory counts. If you set `ulimit -v`, size it from VSZ.
- After a big burst, resident memory can stay higher for about 10 seconds while freed buffers are returned in small
  batches.

### Small hosts and many slow downloads

On a small host, one client can push the whole host into kernel TCP memory pressure. Other clients then pay for it.

When it happens: a client runs many downloads at once (about 100 streams) and its own link cannot take them as fast
as the targets send. Each waiting stream keeps the target's data in the kernel's receive queue of its target socket.
The kernel grows those queues on its own, up to `tcp_rmem` max. finalwisp's own memory stays small (about 5 MiB in
these tests); the bytes sit in kernel socket memory.

What we measured on a 2-vCPU VPS with 3.8 GB of RAM and the kernel's default `tcp_mem` (pressure starts at 233 MiB),
with far clients on 20 ms and 112 ms paths and the targets on another host:

- One far client with one connection and 100 download streams. The target queues held 140-230 MiB, and the host was
  in TCP memory pressure in 13-14 of 16 runs, for about a third of the run (median). The downloading client itself
  still got 80-100 MiB/s at 20 ms round trip.
- While that download ran, a separate upload through the same server slowed down. At 20 ms round trip it fell from
  22-65 MiB/s to 0.3 MiB/s in all 4 runs. At 112 ms the median fell from 23 to 17.5 MiB/s, and one of 4 runs fell to
  3.4 MiB/s. These are small samples, with the upload sent from the same far machine as the download.
- With 10 connections of 10 streams each, the host stayed out of pressure at 20 ms but entered it at 112 ms.
- Why uploads suffer: while the host is in pressure, the kernel limits the receive window of every socket that
  receives data to about four packets. By the same kernel rule, uploads from any client and data sent to other
  programs on the host are affected too (not measured separately). Sending is hit less.
- Another Wisp server we tested held as much or more TCP memory in the same case. The base effect is the kernel's
  limit; how a server reads its targets changes how much it holds (see `--no-splice` below).

What helps, with the measured costs:

- **`--no-splice`.** The copy path reads less from each target socket at a time, so the kernel probably grows fewer of
  them to large sizes. In the 100-stream case at 20 ms the download was 1.2x faster (1.16-1.21x in three paired
  comparisons of 16 runs), the runs in pressure fell from 13-14 of 16 to 0-2 of 16, and the host TCP peak fell from
  233-234 to 178-180 MiB. The upload next to it kept 4-40 MiB/s at 20 ms (median 19) and 16-26 MiB/s at 112 ms
  (median 24). The cost is on fast local paths: on loopback on the same kind of VPS, downloads were 12-31% slower
  (1 stream 12%, 10 x 10 streams 31%), and the host held more TCP memory there, not less (10 x 10 streams: in
  pressure in all 16 runs instead of 8). An older test on another machine lost more on one loopback stream (3.5 to
  1.9 GiB/s). Use it on a small host whose clients are far away; leave splice on where clients and targets are close
  and fast.
- **Adaptive splice** (on by default since 1.2.1; `--no-adaptive-splice` turns it off). Keeps splice on, but a far
  client (round trip 10 ms or more when it connected) with more than 4 streams (busy or idle) whose socket is backed
  up gets 64 KiB reads from its targets instead of 256 KiB. In the 100-stream case at 112 ms the download was 1.2-1.4x
  faster (1.66x with the built-in TLS) and the host left TCP memory pressure (0 of 16 runs instead of 9-13). On a
  lossy 20-30 ms path, 100 streams on one connection also kept the host out of pressure (0 of 16 runs instead of 13),
  with no clear change in download speed. With 10 connections of 10 streams on that path the host was in pressure in
  about 9 of 32 runs instead of all 32, but the download was about 5% slower than with `--no-adaptive-splice`; turning
  it off gets that back, but on a small host it can put the kernel into TCP memory pressure, which slows every other
  TCP connection on that host. Clients closer than 10 ms (same host, LAN) and clients on `--listen-unix` keep 256 KiB
  reads, so on a 2-core VPS with clients on the same host nothing changed with it on. **Behind a reverse proxy on the
  same host (nginx or Caddy as in [Behind a reverse proxy](#behind-a-reverse-proxy), the usual setup) every client
  looks local to finalwisp, so it does nothing there: no gain, no cost.** It helps only when far clients connect to
  finalwisp directly, with plain ws:// or its own TLS (behind a TCP load balancer the round trip is the balancer's).
- **Per-IP and per-connection limits.** Fewer parallel streams per client means less waiting data. In the same test
  at 20 ms, one connection with 10 streams peaked at 58 MiB of host TCP memory, with 50 streams at 176-232 MiB, with
  100 at 231-244 MiB. `--max-streams-per-conn` caps the streams on one connection (the 256 in the example under
  [securing a public server](#securing-a-public-server) does not stop 100). `--max-conns-per-ip` caps how many
  connections one address can spread them over (10 x 10 streams still reached pressure at 112 ms).
  `--stream-rate-per-ip` only limits how fast new streams open, not how many run at once. Set the caps above what your
  normal clients use; we did not measure a particular value.
- **More RAM or a larger `tcp_mem`.** The kernel sets `tcp_mem` from the RAM size (pressure starts at the second
  value, about 6% of RAM), and finalwisp never changes it. The startup warning about `tcp_mem` below 512 MiB points at
  this case. Raise all three values of `net.ipv4.tcp_mem` yourself if the host has the memory, or move to a larger
  host.
- **`--buffer 32`.** A smaller first upload window per stream. It helps when the pressure comes from echo-like traffic
  (many streams that upload and download at once). In a loopback echo test with 10 x 10 streams on the same kind of
  VPS, the runs in pressure went from 16 of 16 to 1 of 16, the host TCP peak from 234 to 198 MiB, and server memory
  from 144 to 22 MiB. It does not target the many-downloads case above (downloads do not use upload credit). The
  cost: an upload of 1-4 MiB on an already open connection waits one more round trip. At 115 ms round trip a 1 MiB
  upload took 243 ms instead of 121 ms (median), a 4 MiB upload 494 ms instead of 358 ms. Uploads up to 256 KiB took
  2% longer or less, and uploads that open a new connection each time did not change. A new upload stream also
  started slower in its first second on a 150 ms test link (0.75x). Use it only where echo-like traffic causes the
  pressure and large uploads on open connections are rare.
- **Not a fix:** `--tcpmem-adapt` kept the host out of pressure but cost the many-stream downloads a quarter to a
  third of their speed. A low `--mem-budget` counts socket memory and slows everything: 256 MiB cut that download to
  about half.

How to tell:

1. Look at the host's TCP memory: `cat /proc/net/sockstat` (the `mem` value on the `TCP:` line, in 4 KiB pages)
   against `cat /proc/sys/net/ipv4/tcp_mem` (three values, also in pages). Pressure starts above the second value and
   ends below the first.
2. Check whether the host is in pressure now: the `press` column of the `TCP` line in `/proc/net/protocols` reads
   `yes`.
3. Count how often it entered pressure: `nstat -az TcpExtTCPMemoryPressures TcpExtTCPMemoryPressuresChrono`. The first
   counts entries (a host that stays in pressure counts once), the second the milliseconds spent in pressure, added
   only when a pressure period ends.
4. Find the cause: `finalwisp_streams` is high against `finalwisp_connections` (many streams per connection), and
   `--log-streams` shows which client addresses run them. Uploads from other clients slow down at the same time.
5. Check finalwisp's own memory (`finalwisp_process_resident_bytes`). If it is small but host TCP memory is near the
   limit, the bytes are in socket queues, and the options above apply.

## Kernel features

finalwisp checks the kernel at startup; there is nothing to configure. Plain `ws://`, splice, TCP Fast Open,
keepalive and the cgroup v1 and v2 memory budget work on every kernel listed here.

| kernel | `wss://` (kTLS) | TLS 1.3 | ChaCha20 | TLS 1.3 key update | example systems |
|---|---|---|---|---|---|
| before 4.13 | no: use a reverse proxy | | | | |
| 4.13-4.16 | no (transmit only): use a reverse proxy | | | | |
| 4.18 (RHEL 8) | yes | yes (backported) | no | no | RHEL / Rocky 8 |
| 5.4 | yes | yes | no | no | Ubuntu 20.04 |
| 5.10 | yes, if built with `CONFIG_TLS` | yes | no | no | Debian 11 (no `CONFIG_TLS`: no `wss://`) |
| 5.15 | yes | yes | yes | no | Ubuntu 22.04 |
| 6.1 | yes | yes | yes | no | Debian 12, Amazon Linux 2023 |
| 6.8 | yes | yes | yes | no | Ubuntu 24.04 |
| 6.14 and later | yes | yes | yes | yes | |

- Without kTLS, a `wss://` start stops with the reason. Use a reverse proxy for TLS there.
- Without key update support, a client's TLS 1.3 KeyUpdate closes its connection.
- `--tcpmem-adapt` needs 5.15 or later. The bandwidth caps (`--download-rate`, `--upload-rate-per-stream`) need 4.13
  or later.
- Kernels older than 5.15 are not tested.

## Troubleshooting

**The client cannot connect at all.**
- finalwisp listens on `127.0.0.1` by default. Use `--host 0.0.0.0` for direct clients, or connect through your proxy.
- `curl http://HOST:PORT/` (with built-in TLS: `curl https://HOST:PORT/`) should print
  `finalwisp: this is a Wisp server`. If it does, the network path is fine and
  the problem is in the WebSocket upgrade (check the proxy's `Upgrade` and `Connection` headers).

**Connections drop after about 60 seconds of idle time.**
nginx's `proxy_read_timeout` defaults to 60 s. Raise it (see [nginx](#nginx)). Behind Cloudflare, idle WebSockets
are closed after about 100 s.

**All clients are limited together, or the logs show only `127.0.0.1`.**
finalwisp sees the proxy, not the clients. Set `--trusted-proxy` to the proxy's address and make the proxy send
`X-Forwarded-For`.

**`wss://` start fails with "modprobe tls".**
The `tls` kernel module is not loaded. Run `sudo modprobe tls` and add it to `/etc/modules-load.d/`. Under the
systemd unit, the service cannot load it itself (`ProtectKernelModules=yes`). In Docker, load it on the host. On a
kernel without kTLS, use a reverse proxy.

**Streams fail with `0x48` (blocked).**
The destination policy refused them. Loopback, private and the server's own addresses are blocked by default. Run
with `--log-streams` to see the `rule=` that matched.

**Streams fail with `0x42` for short internal names.**
finalwisp looks up every name as a full name and ignores `search` in `/etc/resolv.conf`. Send the full name
(`intranet.corp.example`), or put the name in `/etc/hosts`. (Internal targets also need `--allow-private`.)

**Streams fail with `0x49` (throttled).**
A stream limit was hit, or the server is under memory pressure. Check the `finalwisp_memory_level` metric and the
`refuse_*` counters. Under pressure, raise the memory limit or lower the load.

**Uploads slow down for everyone while one client downloads a lot.**
On a small host this is often kernel TCP memory pressure. See
[small hosts and many slow downloads](#small-hosts-and-many-slow-downloads).

**Name lookups are slow when a name server is down.**
The system resolver waits about 10 s per dead server. `--dns-own` (or `--dns-server`) gives up after 1-2 s.

**Startup warnings.**
finalwisp warns about host settings that limit it, but never changes them:

| warning about | why it matters | where to change it |
|---|---|---|
| `tcp_wmem` / `tcp_rmem` max below 16 MiB | one stream's speed is limited to about max / round-trip time | `net.ipv4.tcp_wmem`, `net.ipv4.tcp_rmem` |
| `tcp_mem` max below 512 MiB | the kernel runs out of TCP memory under many fast streams | `net.ipv4.tcp_mem` |
| `somaxconn` below 4096 | bursts of new connections are dropped | `net.core.somaxconn` |
| open files below 65536 | each connection and stream is one file descriptor | `LimitNOFILE=`, `ulimit -n` |
| memory budget off | `/proc/meminfo` could not be read | set `--mem-budget` |

## Known limits

- Linux on x86_64 only.
- `wss://` needs kTLS. TLS 1.3 key updates need Linux 6.14; on older kernels a KeyUpdate closes the connection.
- On a small host, one client with many parallel downloads that its own link cannot take can push the host into
  kernel TCP memory pressure, and uploads from other clients then slow down sharply. See
  [small hosts and many slow downloads](#small-hosts-and-many-slow-downloads).
- `--download-rate` is per connection. There is no per-IP download cap: a client with several connections gets the
  cap on each.
- UDP uploads are not paced by `--upload-rate-per-stream`; `--upload-rate` does cover them.
- The first few packets of each connection are not paced, so a capped connection can burst at its start.
- On a connection with a download cap, the upload slows down too, because control messages wait behind queued data.
- All streams of one connection share it: with `--upload-rate`, a small request waits behind a bulk upload on the
  same connection.
- Idle memory creeps up a little after load peaks (allocator retention, under 2 MiB in our longest tests). It resets
  on restart. Long soak tests found no leak.
