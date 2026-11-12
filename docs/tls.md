# Built-in TLS

Serve `wss://` from finalwisp itself, without a reverse proxy. It needs a certificate, its key and the kernel module
named `tls`.

Load the kernel module, now and at every boot:

```sh
sudo modprobe tls
echo tls | sudo tee /etc/modules-load.d/tls.conf
```

Start finalwisp with the certificate and the key (both PEM files):

```sh
finalwisp --host 0.0.0.0 --port 443 \
  --tls-cert /etc/finalwisp/fullchain.pem --tls-key /etc/finalwisp/privkey.pem
```

Clients then connect to `wss://YOUR-NAME/`. For a server that anyone can reach, add `--preset public` (see
[securing a public server](public-server.md)).

Port 443 is below 1024, so the server needs the `CAP_NET_BIND_SERVICE` capability for it: the
[systemd unit](service.md#systemd) shows how. A port from 1024 up needs no capability and no root.

- [How it works](#how-it-works)
- [Setup and renewal](#setup-and-renewal)
- [Kernel features](#kernel-features): which kernel supports what

## How it works

finalwisp can serve `wss://` itself. The handshake runs in finalwisp; after it, the kernel encrypts and decrypts the
data (kernel TLS, kTLS). Data moves without copies through user space, which is the fastest path.

Use a [reverse proxy](reverse-proxy.md) instead when port 443 is shared with a website, or when the kernel has no TLS
support.

## Setup and renewal

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
  The capability line lists them (`kTLS ...`); it is printed at `--log-level debug`. `--tls-cipher-order server` prefers AES-GCM.
- **Key updates.** TLS 1.3 key updates need Linux 6.14 or later. On older kernels, a client that sends a KeyUpdate is
  disconnected, and finalwisp logs it at most once a minute. Use a reverse proxy if that matters to you.

See [kernel features](#kernel-features) for which kernel supports what.

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
