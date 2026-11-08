# Changelog

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
