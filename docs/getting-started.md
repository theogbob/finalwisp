# Getting started

This page takes you from nothing to a running Wisp server on one Linux machine, and explains what it prints.

```sh
finalwisp          # after the install below: serves ws://127.0.0.1:6001/
```

- [Install](#install)
- [First run](#first-run)
- [Clients from other machines](#clients-from-other-machines)
- [Options in a config file](#options-in-a-config-file)
- [Build it yourself](#build-it-yourself)
- [Next steps](#next-steps)

## Install

```sh
V=v1.3.0
curl -LO https://github.com/theogbob/finalwisp/releases/download/$V/finalwisp-$V-x86_64-linux.tar.gz
curl -LO https://github.com/theogbob/finalwisp/releases/download/$V/SHA256SUMS
tar -xzf finalwisp-$V-x86_64-linux.tar.gz
sha256sum -c SHA256SUMS      # must print OK twice: the download, and the binary inside it
sudo install -m 0755 finalwisp-$V-x86_64-linux/finalwisp /usr/local/bin/finalwisp
finalwisp --version          # finalwisp 1.3.0
```

finalwisp is one static binary for Linux on x86_64. It has no runtime dependencies and no minimum glibc version.

What the commands do:

1. Download `finalwisp-VERSION-x86_64-linux.tar.gz` and `SHA256SUMS` from the
   [Releases](https://github.com/theogbob/finalwisp/releases) page.
2. Unpack and check. `SHA256SUMS` covers the tarball and the binary inside it, so `sha256sum -c SHA256SUMS` prints
   `OK` twice. Stop if it does not.
3. Install it: copy the binary to `/usr/local/bin/finalwisp`. Any directory works; the binary needs no other file.

The tarball also holds `BUILDINFO`: the commit, toolchain and checksum of the build.

## First run

```sh
finalwisp
```

<!-- sample: real output of the merged 1.3.0 build on a terminal (2026-11-11, a 15-thread machine; raw data (not published)) -->
```text
finalwisp listening on ws://127.0.0.1:6001/
  version     1.3.0
  threads     15
  memory      up to 31410 MiB (half of this machine's memory)
  open files  up to 524288
  TCP buffer  4 MiB send: below 16 MiB, see --show-config
  TLS         off
  preset      none
finalwisp: hint: mail ports 25, 465 and 587 are open to clients.
  Fix: --block-smtp (part of --preset public).
```

That serves `ws://127.0.0.1:6001/`. Point any Wisp client at it. Wisp works on any path that ends with `/`, so
`ws://127.0.0.1:6001/wisp/` works too.

The lines under the first one say what the server found on this host and what is set: the version, the threads, the
memory budget, the open-file limit, TLS and the preset. The `TCP buffer` line is there only when the kernel's largest
TCP socket buffer is below 16 MiB, which is the kernel's default; it is not a warning. Warnings and hints may follow.
finalwisp never changes system settings; it only tells you about values that limit it (see
[troubleshooting](troubleshooting.md#startup-warnings)).

To see every setting and what the host allows without starting the server:

```sh
finalwisp --show-config
```

`finalwisp --help` prints a short overview of the options, and `finalwisp --help TOPIC` the options of one topic.

To check it from the same machine, in a second terminal:

```sh
curl http://127.0.0.1:6001/
# finalwisp: this is a Wisp server
```

Stop it with Ctrl-C. Open connections get up to 30 seconds to finish; a second Ctrl-C exits at once
(see [reload and graceful shutdown](service.md#signals-reload-and-graceful-shutdown)).

## Clients from other machines

By default finalwisp listens on `127.0.0.1`: only programs on the same machine can reach it. To accept clients from
other machines without a proxy:

```sh
finalwisp --host 0.0.0.0 --port 6001
```

No root is needed. A port below 1024 needs the `CAP_NET_BIND_SERVICE` capability (the [systemd unit](service.md#systemd) shows how).

Browsers do not let a page that was loaded over `https://` open a `ws://` connection to another machine (mixed
content). That is a rule of browsers, not of finalwisp. So a server for a public web page needs `wss://`: put a
[reverse proxy](reverse-proxy.md) in front, or use the [built-in TLS](tls.md). For a server that anyone can reach, also read
[securing a public server](public-server.md).

Open files: each connection and each stream use one file descriptor, and a connection that uses splice two more.
At startup finalwisp raises its own soft limit to the hard limit, but not above 1048576 (`--no-nofile-raise` keeps the
soft limit). If the hard limit is low, raise it (`LimitNOFILE=` in systemd, `ulimit -n`, or `--ulimit nofile=` in
Docker), for example to 1048576. The server warns at startup below 65536.
[What a user costs](public-server.md#what-a-user-costs) has the numbers.

## Options in a config file

Every option can live in a file, one per line, without the dashes:

```text
# /etc/finalwisp.conf
preset public
host 127.0.0.1
port 6001
trusted-proxy 127.0.0.1
```

```sh
finalwisp --config /etc/finalwisp.conf
```

Options after `--config` on the command line override the file, and the file overrides the preset. The full syntax is
in the [configuration reference](configuration.md#config-file). The file is read only at startup: restart after a change.

## Build it yourself

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

## Next steps

| I want to ... | page |
|---|---|
| put it behind nginx or Caddy | [Reverse proxy](reverse-proxy.md) |
| serve `wss://` without a proxy | [Built-in TLS](tls.md) |
| start it at boot, or run it in Docker | [Run it as a service](service.md) |
| open it to the public | [Securing a public server](public-server.md) |
| look up an option | [Configuration reference](configuration.md) |
| see everything else | [Documentation index](README.md) |
