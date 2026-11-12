# Deployment guide

The deployment guide is now a set of shorter pages, one per task. Start at the [documentation index](README.md).

This page keeps every heading of the old guide, so that old links still land. Each heading says where its text is
now. Nothing was removed.

| I want to ... | page |
|---|---|
| install it and run it for the first time | [Getting started](getting-started.md) |
| put it behind nginx, Caddy or Cloudflare | [Reverse proxy](reverse-proxy.md) |
| serve `wss://` without a proxy | [Built-in TLS](tls.md) |
| run it under systemd, Docker or Kubernetes | [Run it as a service](service.md) |
| open it to the public | [Securing a public server](public-server.md) |
| send all traffic through a proxy or Tor | [Upstream proxy and Tor](upstream-proxy.md) |
| read the logs and the metrics | [Logs and metrics](logs-metrics.md) |
| plan memory, or run on a small host | [Memory](memory.md) |
| fix a problem | [Troubleshooting](troubleshooting.md) |
| look up an option | [Configuration reference](configuration.md) |

## Install

Moved to [Getting started](getting-started.md#install).

### Build it yourself

Moved to [Getting started](getting-started.md#build-it-yourself).

## First run

Moved to [Getting started](getting-started.md#first-run).

## Behind a reverse proxy

Moved to [Reverse proxy](reverse-proxy.md#what-matters-with-any-proxy).

### nginx

Moved to [Reverse proxy](reverse-proxy.md#nginx).

### Caddy

Moved to [Reverse proxy](reverse-proxy.md#caddy).

### Cloudflare

Moved to [Reverse proxy](reverse-proxy.md#cloudflare).

### How the client address is read

Moved to [Reverse proxy](reverse-proxy.md#how-the-client-address-is-read).

### What the server can and cannot tell

Moved to [Reverse proxy](reverse-proxy.md#what-the-server-can-and-cannot-tell).

### Unix socket between the proxy and finalwisp

Moved to [Reverse proxy](reverse-proxy.md#unix-socket-between-the-proxy-and-finalwisp).

### PROXY protocol behind a TCP load balancer

Moved to [Reverse proxy](reverse-proxy.md#proxy-protocol-behind-a-tcp-load-balancer).

## Built-in TLS

Moved to [Built-in TLS](tls.md#built-in-tls).

## systemd

Moved to [Run it as a service](service.md#systemd).

## Docker

Moved to [Run it as a service](service.md#docker).

## Config file

Moved to [Configuration reference](configuration.md#config-file).

## Signals: reload and graceful shutdown

Moved to [Run it as a service](service.md#signals-reload-and-graceful-shutdown).

## Securing a public server

Moved to [Securing a public server](public-server.md#securing-a-public-server).

### What the preset does

Moved to [Securing a public server](public-server.md#what-the-preset-does).

### What the preset does not do

Moved to [Securing a public server](public-server.md#what-the-preset-does-not-do).

### More limits you can add

Moved to [Securing a public server](public-server.md#more-limits-you-can-add).

### What a user costs

Moved to [Securing a public server](public-server.md#what-a-user-costs).

### Destination policy

Moved to [Securing a public server](public-server.md#destination-policy).

### Per-destination limits

Moved to [Securing a public server](public-server.md#per-destination-limits).

### Slow names and the resolver threads

Moved to [Securing a public server](public-server.md#slow-names-and-the-resolver-threads) (added by the DNS work of 1.3.0).

## Upstream proxy and Tor

Moved to [Upstream proxy and Tor](upstream-proxy.md#upstream-proxy-and-tor).

### Tor

Moved to [Upstream proxy and Tor](upstream-proxy.md#tor).

## Logging

Moved to [Logs and metrics](logs-metrics.md#logging).

### Connection log

Moved to [Logs and metrics](logs-metrics.md#connection-log).

### Stream log

Moved to [Logs and metrics](logs-metrics.md#stream-log).

### Runtime hints and warnings

Moved to [Logs and metrics](logs-metrics.md#runtime-hints-and-warnings).

### Privacy and safety of the logs

Moved to [Logs and metrics](logs-metrics.md#privacy-and-safety-of-the-logs).

### Wisp close codes

Moved to [Logs and metrics](logs-metrics.md#wisp-close-codes).

## Metrics and Prometheus

Moved to [Logs and metrics](logs-metrics.md#metrics-and-prometheus).

## Memory budget

Moved to [Memory](memory.md#memory-budget).

### Small hosts and many slow downloads

Moved to [Memory](memory.md#small-hosts-and-many-slow-downloads).

## Kernel features

Moved to [Built-in TLS](tls.md#kernel-features).

## Troubleshooting

Moved to [Troubleshooting](troubleshooting.md#troubleshooting).

## Known limits

Moved to [Troubleshooting](troubleshooting.md#known-limits).
