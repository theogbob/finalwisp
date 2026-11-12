# Security

finalwisp is a network proxy: a bug can let clients reach places they should not, or take a server down. Please
report security problems privately, not in a public issue.

## Reporting

Use GitHub's private reporting: **Security** tab of this repository, then **Report a vulnerability**. Include the
finalwisp version (`finalwisp --version`, `BUILDINFO` in the release, or the commit), the command line or config
(without secrets), and the steps or the client that triggers it.

You will get an answer within a few days. Fixes ship as a new release; the advisory names you unless you prefer not.

## Scope

In scope: anything in this repository, for example a way around the destination rules (private, loopback or own
addresses, host and port rules), around authentication or the limits, a crash or memory exhaustion a client can
cause, or a wrong client address behind a trusted proxy.

Out of scope: what a correctly configured open proxy is meant to do (clients reaching public sites), settings that
the documentation marks as unsafe (`--allow-private`, `--allow-loopback`, `--upstream-trust-dns` with a proxy that
can reach your network), and problems in the kernel, glibc or other servers.

Supported versions: the latest release.
