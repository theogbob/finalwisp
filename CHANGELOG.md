# Changelog

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
