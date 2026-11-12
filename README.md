# finalwisp

The fastest [Wisp server](https://github.com/MercuryWorkshop/wisp-protocol) for Linux. Written in Rust, one static
binary, with every feature a public Wisp server is likely to need.

Wisp is a protocol that carries many TCP and UDP connections over one WebSocket. Web proxies that run in the browser
use it: the page opens a WebSocket to a Wisp server, and the server opens the real connections to the internet.
finalwisp is that server.

- [Install](#install)
- [Quick start](#quick-start): on your machine, behind nginx or Caddy, in Docker
- [Features](#features)
- [Performance](#performance)
- [Documentation](#documentation)

## Install

finalwisp is one file for Linux on x86_64. It needs nothing else on the machine.

```sh
V=v1.3.0
curl -LO https://github.com/theogbob/finalwisp/releases/download/$V/finalwisp-$V-x86_64-linux.tar.gz
curl -LO https://github.com/theogbob/finalwisp/releases/download/$V/SHA256SUMS
tar -xzf finalwisp-$V-x86_64-linux.tar.gz
sha256sum -c SHA256SUMS      # must print OK twice: the download, and the binary inside it
sudo install -m 0755 finalwisp-$V-x86_64-linux/finalwisp /usr/local/bin/finalwisp
finalwisp --version          # finalwisp 1.3.0
```

All versions are on the [Releases](https://github.com/theogbob/finalwisp/releases) page. To build it yourself, see
[Building](#building).

## Quick start

### 1. Try it on your machine

```sh
finalwisp
```

That serves `ws://127.0.0.1:6001/`. Point any Wisp client at it. Only programs on the same machine can reach it.

To check that it runs, in a second terminal:

```sh
curl http://127.0.0.1:6001/
# finalwisp: this is a Wisp server
```

### 2. A public server behind nginx or Caddy

Browsers do not let a page that was loaded over `https://` open a `ws://` connection to another machine. So a
public server needs `wss://`. The usual way: a reverse proxy holds the certificate and port 443, and finalwisp stays
on `127.0.0.1`.

```sh
finalwisp --preset public --trusted-proxy 127.0.0.1
```

- `--preset public` turns on the built-in settings for a server that anyone can reach.
- `--trusted-proxy 127.0.0.1` lets finalwisp read each client's real address from the proxy.

Caddy (it gets the certificate itself):

```caddy
wisp.example.com {
    reverse_proxy 127.0.0.1:6001
}
```

nginx: use the [server block](docs/reverse-proxy.md#nginx) of the reverse proxy page.

Clients then use `wss://wisp.example.com/`.

Next steps:

- [Reverse proxy](docs/reverse-proxy.md): full nginx and Caddy files, Cloudflare, client addresses.
- [Run it as a service](docs/service.md): the systemd unit in [`contrib/finalwisp.service`](contrib/finalwisp.service).
- [Securing a public server](docs/public-server.md): what the preset covers, and what it does not.
- No reverse proxy? finalwisp can do TLS itself:
  `finalwisp --preset public --host 0.0.0.0 --port 443 --tls-cert fullchain.pem --tls-key privkey.pem`
  (needs the kernel's `tls` module, see [built-in TLS](docs/tls.md)).

### 3. Docker

```sh
# open to everyone: plain ws:// on port 6001 of every address of the host, IPv4 and IPv6
docker run -d --name finalwisp -p 6001:6001 --stop-timeout 35 ghcr.io/theogbob/finalwisp:latest

# behind nginx or Caddy on the same host: only the host can reach it, and the Docker bridge gateway is trusted
docker run -d --name finalwisp -p 127.0.0.1:6001:6001 --stop-timeout 35 ghcr.io/theogbob/finalwisp:latest \
  --host 0.0.0.0 --port 6001 --trusted-proxy 172.17.0.1
```

Use one of the two. The image starts with `--preset public`. [Docker](docs/service.md#docker) explains both lines
and has the rest: options, memory, open files, TLS.

## Features

- Wisp v1 and v2, TCP and UDP streams, password and key authentication
- `wss://` with kernel TLS (TLS 1.2 and 1.3)
- One preset for a public server (`--preset public`)
- Host, port and address allow and block lists; private, loopback and SMTP blocking
- Limits: connections in total and per IP, streams per connection, new streams per second, upload and download caps
- A memory budget that follows the cgroup limit
- Real client IPs from `X-Forwarded-For` or the PROXY protocol, and a Unix socket listener
- An outbound SOCKS5 or HTTP proxy for every stream (works with Tor, `.onion` included)
- Built-in DNS resolver with short timeouts, or the system's
- Prometheus metrics and per-connection logs
- Graceful shutdown, certificate reload on SIGHUP
- Every option can also live in a config file (`--config`)

## Performance

How many times faster finalwisp is than each server:

| finalwisp vs | Throughput | Requests/s | New streams/s |
|---|---|---|---|
| [epoxy-server](https://github.com/MercuryWorkshop/epoxy-tls) | 1.5–5.4× | 1.0–1.4× | 1.9–5.9× |
| [wisp-server-python](https://github.com/MercuryWorkshop/wisp-server-python) | 2.7–7.2× | 2.0–4.2× | 3.3–7.3× |
| [wisp-js](https://github.com/MercuryWorkshop/wisp-client-js) | 3.7–37× | 1.8–18× | 3.3–17× |
| [wispurr](https://www.npmjs.com/package/wispurr) | 1.5–10×¹ | 2.1–6.0× | 2.4–5.1× |

- Ranges cover a 72-thread Intel Xeon Gold server and two 2-core cloud VPSes, finalwisp 1.1.0, every server at its
  default or documented settings.
- These are loopback tests without TLS: they show what each server can push when the network is not the limit. Over a
  real link, the link usually runs out first.
- On the big server finalwisp moved 21.8 GiB/s of downloads and 445k requests/s; on a 2-core VPS, 2.4 GiB/s and
  64–93k requests/s.
- finalwisp also hands memory back when the load stops: its resident memory right after the heaviest test was 4 MiB
  on the 2-core VPSes, where the others held 145 MiB to 3.3 GiB.
- Its peak memory under load (VmHWM) was the lowest of the five servers on the big server and one VPS, and level with
  wisp-server-python's on the other VPS (156 vs 160 MiB).

Full tables and method: [benchmarks](docs/benchmarks.md).

¹ Valid cells only: wispurr moved no data in most single-stream upload and echo runs, and failed the big server's
download test (known bugs in the tested version).

## Documentation

Start at the [documentation index](docs/README.md). The short list:

| I want to ... | page |
|---|---|
| install it and run it for the first time | [Getting started](docs/getting-started.md) |
| put it behind nginx, Caddy or Cloudflare | [Reverse proxy](docs/reverse-proxy.md) |
| serve `wss://` without a proxy | [Built-in TLS](docs/tls.md) |
| run it under systemd, Docker or Kubernetes | [Run it as a service](docs/service.md) |
| open it to the public | [Securing a public server](docs/public-server.md) |
| send all traffic through a proxy or Tor | [Upstream proxy and Tor](docs/upstream-proxy.md) |
| read the logs and the metrics | [Logs and metrics](docs/logs-metrics.md) |
| plan memory, or run on a small host | [Memory](docs/memory.md) |
| fix a problem | [Troubleshooting](docs/troubleshooting.md) |
| look up an option | [Configuration reference](docs/configuration.md), or `finalwisp --help` |
| see or repeat the benchmarks | [Benchmarks](docs/benchmarks.md), [Benchmarking](docs/benchmarking.md) |

## Limits

- Linux on x86_64 only.
- Built-in `wss://` needs kTLS (the `tls` kernel module). Without it, use a reverse proxy for TLS.
- Download caps are per connection, not per client IP.
- Idle memory creeps up a little after load peaks (allocator retention: under 2 MiB in our longest tests, with no
  proven ceiling). It resets on restart. Long soak tests found no leak.

[Known limits](docs/troubleshooting.md#known-limits) lists the rest.

## Building

```sh
bench/release.sh   # static, reproducible build; needs rustup, gcc and static glibc
```

Same commit, same toolchain: same binary, byte for byte. Details: [build it yourself](docs/getting-started.md#build-it-yourself).

## Help and security

Questions and bugs: open an [issue](https://github.com/theogbob/finalwisp/issues). Security problems: see
[SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
