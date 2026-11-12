# finalwisp documentation

Every page starts with one sentence on what it gets you and a block you can copy. The explanation comes after.

## I want to ...

**Run it for the first time**

| I want to ... | page |
|---|---|
| install finalwisp and start it | [Getting started](getting-started.md) |
| know what the lines at startup mean | [Getting started: first run](getting-started.md#first-run) |
| put my options in a file | [Configuration reference: config file](configuration.md#config-file) |
| build it from source | [Getting started: build it yourself](getting-started.md#build-it-yourself) |

**Put it on the internet**

| I want to ... | page |
|---|---|
| put it behind nginx, Caddy or Cloudflare | [Reverse proxy](reverse-proxy.md) |
| serve `wss://` without a proxy | [Built-in TLS](tls.md) |
| start it at boot with systemd | [Run it as a service: systemd](service.md#systemd) |
| run it in Docker or Kubernetes | [Run it as a service: Docker](service.md#docker) |
| open it to everyone | [Securing a public server](public-server.md) |
| decide where clients may connect | [Securing a public server: destination policy](public-server.md#destination-policy) |
| let only my own clients in | [Configuration reference: auth](configuration.md#auth) |
| send all traffic through a SOCKS or HTTP proxy, or Tor | [Upstream proxy and Tor](upstream-proxy.md) |

**Operate it**

| I want to ... | page |
|---|---|
| see the real client addresses behind my proxy | [Reverse proxy: how the client address is read](reverse-proxy.md#how-the-client-address-is-read) |
| check that my proxy setup is right | [Reverse proxy: what the server can and cannot tell](reverse-proxy.md#what-the-server-can-and-cannot-tell) |
| know how many users fit | [Securing a public server: what a user costs](public-server.md#what-a-user-costs) |
| set limits per connection, per address or per destination | [Securing a public server: more limits](public-server.md#more-limits-you-can-add) |
| read the logs | [Logs and metrics: logging](logs-metrics.md#logging) |
| understand a close code such as `0x49` | [Logs and metrics: Wisp close codes](logs-metrics.md#wisp-close-codes) |
| scrape metrics with Prometheus | [Logs and metrics: metrics](logs-metrics.md#metrics-and-prometheus) |
| give it a memory limit | [Memory: memory budget](memory.md#memory-budget) |
| run it on a small VPS | [Memory: small hosts](memory.md#small-hosts-and-many-slow-downloads) |
| reload certificates, stop it without cutting clients | [Run it as a service: signals](service.md#signals-reload-and-graceful-shutdown) |
| fix a problem | [Troubleshooting](troubleshooting.md) |
| look up an option | [Configuration reference](configuration.md) |

**Measure it, build it, change it**

| I want to ... | page |
|---|---|
| see how it compares with other Wisp servers | [Benchmarks](benchmarks.md) |
| run the same tests on my hardware, against any Wisp server | [Benchmarking](benchmarking.md) |
| know which kernel supports what | [Built-in TLS: kernel features](tls.md#kernel-features) |
| know what it cannot do | [Troubleshooting: known limits](troubleshooting.md#known-limits) |
| see what changed in a release | [Changelog](../CHANGELOG.md) |
| report a bug or a security problem | [Contributing](../CONTRIBUTING.md), [Security](../SECURITY.md) |

## All pages

| page | what is in it |
|---|---|
| [Getting started](getting-started.md) | Install, first run, clients from other machines, the config file in short, building. |
| [Reverse proxy](reverse-proxy.md) | nginx, Caddy, Cloudflare, client addresses, the Unix socket, the PROXY protocol. |
| [Built-in TLS](tls.md) | `wss://` with kernel TLS: the kernel module, several names, renewal, the kernel table. |
| [Run it as a service](service.md) | The systemd unit, the Docker image, Kubernetes, reload and graceful shutdown. |
| [Securing a public server](public-server.md) | The `public` preset, more limits, file descriptors per user, destination policy, slow names. |
| [Upstream proxy and Tor](upstream-proxy.md) | Every stream through one SOCKS5 or HTTP CONNECT proxy; Tor and `.onion`. |
| [Logs and metrics](logs-metrics.md) | Log levels, connection and stream logs, runtime hints, close codes, Prometheus. |
| [Memory](memory.md) | The memory budget and its levels, sizing, kernel TCP memory on small hosts. |
| [Troubleshooting](troubleshooting.md) | Problems by symptom, startup warnings, known limits. |
| [Configuration reference](configuration.md) | Every option by topic, the config file, the presets. |
| [Benchmarks](benchmarks.md) | Results, method and caveats. |
| [Benchmarking](benchmarking.md) | The test tools, for any Wisp server. |
| [Deployment guide](deployment.md) | The old single page: now a list of where each section went. |

The command line has the same structure: `finalwisp --help` is the overview, and `finalwisp --help TOPIC` lists the
options of one section of the configuration reference.
