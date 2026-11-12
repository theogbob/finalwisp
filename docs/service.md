# Run it as a service

Start finalwisp at boot and stop it cleanly: as a systemd unit, as a Docker container or in Kubernetes.

- [systemd](#systemd)
- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Signals: reload and graceful shutdown](#signals-reload-and-graceful-shutdown)

## systemd

A hardened unit file is in [`contrib/finalwisp.service`](../contrib/finalwisp.service).

```sh
sudo cp contrib/finalwisp.service /etc/systemd/system/
sudoedit /etc/systemd/system/finalwisp.service   # adjust ExecStart
sudo systemctl daemon-reload
sudo systemctl enable --now finalwisp
```

What the unit does:

- Starts finalwisp with `--preset public` (since 1.3.0): the built-in settings for a server that anyone can reach, see
  [securing a public server](public-server.md#securing-a-public-server). Options after it in `ExecStart` override it; remove it, or
  write `--preset none`, for a server without them. The unit does not pass `--trusted-proxy`: add it when a reverse
  proxy stands in front (see [behind a reverse proxy](reverse-proxy.md#what-matters-with-any-proxy)).
- Runs as a dynamic user (`DynamicUser=yes`), with no root and a read-only view of the system.
- `systemctl reload finalwisp` sends `SIGHUP` (reload certificates); `systemctl stop` sends `SIGTERM` (graceful
  drain). `TimeoutStopSec=40` is longer than the default drain of 30 s plus 2 s.
- `LimitNOFILE=1048576` for many connections and streams.
- `MemoryMax=` (commented out) sets the memory the server may use. finalwisp reads the limit and stays under it; see
  [memory budget](memory.md#memory-budget).

Changes you may need:

- **Files to read** (`--tls-key`, `--auth-file`, `--cert-auth-key`): a dynamic user cannot be given ownership of a
  file. Replace `DynamicUser=yes` with `User=finalwisp` (create it with `useradd --system finalwisp`), and keep the
  files in `/etc/finalwisp`, owned `root:finalwisp`, mode 640.
- **Ports below 1024**: uncomment `AmbientCapabilities=CAP_NET_BIND_SERVICE`.
- **A config file**: `ExecStart=/usr/local/bin/finalwisp --config /etc/finalwisp.conf`. The service user must be able
  to read it; with `DynamicUser=yes` that means mode 644, so keep secrets in the files it names.
- **Unix socket for the proxy**: add `RuntimeDirectory=finalwisp`, `RuntimeDirectoryMode=2750`, `Group=www-data`.

`ProtectKernelModules=yes` hides the kernel modules from the service, so the `tls` module must be loaded at boot
(see [built-in TLS](tls.md#built-in-tls)). Older systemd versions ignore the hardening keys they do not know, with a warning.
None of the hardening gets in the way: finalwisp only reads `/proc`, `/sys/fs/cgroup`, `/etc/resolv.conf`,
`/etc/hosts` and its own files.

Running finalwisp in a unit also gives it its own cgroup, which makes the memory budget more precise (see
[memory budget](memory.md#memory-budget)).

## Docker

The image is `ghcr.io/theogbob/finalwisp`. Each release has a tag (`v1.3.0`), and `latest` is the newest release.

```sh
docker run -d --name finalwisp -p 6001:6001 --stop-timeout 35 --memory 1g ghcr.io/theogbob/finalwisp:latest
```

That serves plain `ws://` on port 6001 of every address of the host, IPv4 and IPv6, to everyone who can reach it.

### Docker behind a reverse proxy on the same host

Publish the port on `127.0.0.1` only, and trust the gateway address of the Docker bridge:

```sh
docker run -d --name finalwisp -p 127.0.0.1:6001:6001 --stop-timeout 35 --memory 1g ghcr.io/theogbob/finalwisp:latest \
  --host 0.0.0.0 --port 6001 --trusted-proxy 172.17.0.1
```

- The proxy on the host forwards to `127.0.0.1:6001`, as in [reverse proxy](reverse-proxy.md). Machines other than
  the host cannot reach the port.
- Inside the container, a connection through the published port comes from the gateway address of the bridge network,
  not from `127.0.0.1`. So the gateway is the address to trust. `172.17.0.1` is the gateway of the default bridge of
  Docker; `docker network inspect bridge` prints yours as `Gateway`. We checked this line with Docker 29 and the
  default bridge.
- Every program on the host that connects to the port is then trusted to name the client, the same as with
  `--trusted-proxy 127.0.0.1` without Docker.

### Build the image yourself

[`contrib/docker/Dockerfile`](../contrib/docker/Dockerfile) builds a tiny image from the static binary: `FROM
scratch`, the binary and `BUILDINFO`, a non-root user (uid 65532).

```sh
# in the unpacked release directory (it holds finalwisp and BUILDINFO)
docker build -f /path/to/contrib/docker/Dockerfile -t finalwisp:VERSION .

docker run -d --name finalwisp -p 6001:6001 --stop-timeout 35 --memory 1g finalwisp:VERSION
```

### What to know about the image

- The image starts `finalwisp --preset public` (since 1.3.0) with the default arguments `--host 0.0.0.0 --port 6001`.
  Arguments after the image name replace only `--host 0.0.0.0 --port 6001`, so repeat those two when you add
  options. The preset stays: it is part of the image's entry point.
- To see the preset: `docker run --rm finalwisp:VERSION --print-preset public`. To run without it, add
  `--preset none` to the arguments (the last `--preset` wins), or turn one setting off (`--no-block-smtp`,
  `--max-streams-per-conn 0`):

  ```sh
  docker run -d -p 6001:6001 --stop-timeout 35 finalwisp:VERSION --host 0.0.0.0 --port 6001 --preset none
  ```

- The image does not pass `--trusted-proxy`. With a published port (`-p`), IPv4 clients arrive with their own address,
  but Docker's port forwarder passes every IPv6 client as the bridge gateway address (for example `172.17.0.1`), so
  all IPv6 users count as one address. See [what the server can and cannot tell](reverse-proxy.md#what-the-server-can-and-cannot-tell).
- File descriptors: Docker starts a container with a soft limit of 1024 open files and a much higher hard limit.
  finalwisp raises its soft limit to the hard limit at startup (but not above 1048576). To set both yourself: `--ulimit nofile=1048576:1048576`
  (see [what a user costs](public-server.md#what-a-user-costs)).
- Connection tracking: Docker's default network makes the host track every connection, and that table has a fixed
  size. On a busy server it can fill long before the file descriptors do (see
  [what a user costs](public-server.md#what-a-user-costs)).
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

## Kubernetes

In Kubernetes the same rules apply: `terminationGracePeriodSeconds` (30 s by default) must be longer than
`--drain-timeout` plus 2 s, so set it to 40 or lower the drain to 25.

The other rules of the Docker section apply too: the memory limit of the container is the memory budget, and the
`tls` kernel module must be loaded on the node for `wss://`.

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
