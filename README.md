# finalwisp

The fastest [Wisp server](https://github.com/MercuryWorkshop/wisp-protocol) for Linux. Written in Rust, one static
binary, with every feature a public Wisp server is likely to need.

## Performance

How many times faster finalwisp is than each server:

| finalwisp vs | Throughput | Requests/s | New streams/s |
|---|---|---|---|
| [epoxy-server](https://github.com/MercuryWorkshop/epoxy-tls) | 1.5–5.4× | 1.0–1.4× | 1.9–5.9× |
| [wisp-server-python](https://github.com/MercuryWorkshop/wisp-server-python) | 2.7–7.2× | 2.0–4.2× | 3.3–7.3× |
| [wisp-js](https://github.com/MercuryWorkshop/wisp-client-js) | 3.7–37× | 1.8–18× | 3.3–17× |
| [wispurr](https://www.npmjs.com/package/wispurr) | 1.5–10×¹ | 2.1–6.0× | 2.4–5.1× |

Ranges cover a 72-thread Intel Xeon Gold server and two 2-core cloud VPSes, finalwisp 1.1.0, every server at its
default or documented settings. On the big server finalwisp moved 21.8 GiB/s of downloads and 445k requests/s; on a
2-core VPS, 2.4 GiB/s and 64–93k requests/s.

finalwisp also hands memory back when the load stops: its resident memory right after the heaviest test was 4 MiB on
the 2-core VPSes, where the others held 145 MiB to 3.3 GiB. Its peak memory under load (VmHWM) was the lowest of the
five servers on the big server and one VPS, and level with wisp-server-python's on the other VPS (156 vs 160 MiB). The
benchmarks page has both.

These are loopback tests without TLS: they show what each server can push when the network is not the limit. Over a real link,
the link usually runs out first. Full tables and method: [benchmarks](docs/benchmarks.md).

¹ Valid cells only: wispurr moved no data in most single-stream upload and echo runs, and failed the big server's
download test (known bugs in the tested version).

## Quick start

Latest version: **1.1.1**. Download it from the [Releases](../../releases) page, check its SHA-256 sum, then:

```sh
finalwisp --port 6001
```

That serves `ws://127.0.0.1:6001/`. Point any Wisp client at it.

For a public server, put it behind your reverse proxy and tell it where client addresses come from:

```sh
finalwisp --port 6001 --trusted-proxy 127.0.0.1 --max-conns 10000 --block-smtp
```

```nginx
location /wisp/ {
    proxy_pass http://127.0.0.1:6001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;   # nginx closes idle WebSockets after 60 s by default
}
```

Or let finalwisp do TLS itself: `finalwisp --host 0.0.0.0 --port 443 --tls-cert fullchain.pem --tls-key privkey.pem`
(needs the kernel's `tls` module).

A hardened systemd unit is in [`contrib/finalwisp.service`](contrib/finalwisp.service), and a container image recipe in
[`contrib/docker/`](contrib/docker/). Every flag can also live in a config file (`--config`).

## Features

- Wisp v1 and v2, TCP and UDP streams, password and key authentication
- `wss://` with kernel TLS (TLS 1.2 and 1.3)
- Host, port and address allow and block lists; private, loopback and SMTP blocking
- Limits: connections in total and per IP, streams per connection, new streams per second, upload and download caps
- A memory budget that follows the cgroup limit
- Real client IPs from `X-Forwarded-For` or the PROXY protocol, and a Unix socket listener
- An outbound SOCKS5 or HTTP proxy for every stream (works with Tor, `.onion` included)
- Built-in DNS resolver with short timeouts, or the system's
- Prometheus metrics and per-connection logs
- Graceful shutdown, certificate reload on SIGHUP

## Documentation

- [Deployment guide](docs/deployment.md): reverse proxies, TLS, systemd, Docker, Tor, logs, metrics, memory
- [Configuration reference](docs/configuration.md): every option with its default, and the config file
- [Benchmarks](docs/benchmarks.md): full results, method and caveats
- [Benchmarking](docs/benchmarking.md): run the same tests on your own hardware, against any Wisp server
- `finalwisp --help`

## Limits

- Linux on x86_64 only.
- Built-in `wss://` needs kTLS (the `tls` kernel module). Without it, use a reverse proxy for TLS.
- Download caps are per connection, not per client IP.
- Idle memory creeps up a little after load peaks (allocator retention: under 2 MiB in our longest tests, with no
  proven ceiling). It resets on restart. Long soak tests found no leak.

The deployment guide lists the rest.

## Building

```sh
bench/release.sh   # static, reproducible build; needs rustup, gcc and static glibc
```

Same commit, same toolchain: same binary, byte for byte. Details in the deployment guide.

## License

[Apache License 2.0](LICENSE)
