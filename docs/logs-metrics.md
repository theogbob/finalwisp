# Logs and metrics

See who connects, why a stream failed and how the server is doing: the logs on stderr, and Prometheus metrics.

```sh
finalwisp --log-conns --metrics-listen 9464
```

In a second terminal:

```sh
curl -s http://127.0.0.1:9464/metrics | head
```

- [Logging](#logging): [connection log](#connection-log), [stream log](#stream-log),
  [runtime hints and warnings](#runtime-hints-and-warnings), [privacy](#privacy-and-safety-of-the-logs),
  [Wisp close codes](#wisp-close-codes)
- [Metrics and Prometheus](#metrics-and-prometheus)

## Logging

Everything goes to stderr. Under systemd, `journalctl -u finalwisp` shows it with timestamps.

`--log-level` chooses how much: `error` (fatal startup errors only), `warn` (and every warning), `info` (the
default: also startup, shutdown, memory level and metrics lines), `debug` (also the start details in one long line, and a line when a connection
opens, with `--log-conns`).

### Connection log

`--log-conns` prints one line per connection when it closes:

```text
finalwisp: ev=conn_close ts=2026-11-01T12:00:00.123Z w=3 cid=3:1842 ip=203.0.113.9 via=10.0.0.2 tls=1 proto=v2 auth=none dur_ms=93812 streams=41 refused=2 rx=18234 tx=91823412 why=client_close
```

| field | meaning |
|---|---|
| `ts` | time (UTC) |
| `w`, `cid` | worker thread; connection id (`worker:sequence`, unique per run) |
| `ip`, `via` | the client; `via` is the trusted proxy it came through (`unix` for the Unix socket) |
| `tls`, `proto`, `auth` | built-in TLS used; `http` (no WebSocket), `v1`, `v2` or `wsproxy`; `none`, `ok` or `failed` |
| `streams`, `refused` | streams opened; CONNECTs refused (policy, limits, memory) |
| `rx`, `tx` | bytes on the wire, WebSocket and TLS framing included |
| `why` | why it closed (below) |

`why` is one of: `client_close`, `server_close` (shutdown, or a plain HTTP request answered), `ws_error`,
`protocol_error`, `hs_timeout` (no complete handshake in time), `auth_failed`, `tls_error`, `pressure_shed` (memory
pressure), `dead_peer` (the client vanished), `limit` (a per-IP limit or a policy refusal).

A connection refused right at accept (`--max-conns`, `--max-conns-per-ip`, `--conn-rate-per-ip`) gives `ev=conn_refused ... why=limit`, at
most 20 lines per second per thread, then one `ev=refused_suppressed n=` line per second.

### Stream log

`--log-streams` prints one line per stream and one per refused CONNECT. It works with or without `--log-conns`:

```text
finalwisp: ev=stream_close ts=2026-11-02T06:46:47.430Z w=0 cid=0:1 ip=203.0.113.9 sid=1 t=tcp host=example.com port=443 dst=93.184.215.14 dur_ms=41 up=517 down=6211 reason=0x02 why=target_close
finalwisp: ev=stream_refused ts=... w=0 cid=0:1 ip=203.0.113.9 sid=5 t=tcp host=example.com port=22 reason=0x48 why=policy rule=ports
```

- `sid` is the Wisp stream id, `t` is `tcp`, `udp` or `wsproxy`, `host` and `port` are what the client asked for, and
  `dst` is the address finalwisp connected to. With `--upstream`, the line has `upstream=1` and `dst` is the proxy.
- `up` and `down` are payload bytes to and from the target (UDP lines add `dgrams_up` and `dgrams_down`).
- `reason` is the Wisp close code sent (table below), or `none` if the client closed the stream.
- `why` is one of `target_close`, `client_close`, `conn_close`, `dns_fail`, `connect_fail`, `upstream_fail`,
  `policy`, `limit`, `pressure`, `invalid`; `rule` names the rule that refused it (`ports`, `private`, `block_dest`,
  `max_streams_per_conn`, `stream_rate`, `dest_rate`, `dest_rate_minute`, `tcpmem_share`, `port_share`,
  `port_reserve`, `port_full`, `dest_dead`, ...). A per-destination refusal comes after
  DNS, so it is an `ev=stream_close` line with `reason=0x49 why=limit`, not a `stream_refused` line.
- Expect one line per stream: size your log storage for the stream rate, not the connection rate.

### Runtime hints and warnings

Four lines tell you about a setup or a host state that needs a look. They do not depend on `--log-conns`, they never
change what the server does, and each has a counter. They are printed at the `warn` level (so `--log-level error`
hides them): the first time at once, then at most once per hour (the TCP memory line: once per minute). Lines 1, 2
and 4 then give the number of times since the last line.

| # | line | when | counter | what to do |
|---|---|---|---|---|
| 1 | `hint: a request from ADDR carries the header NAME, but ADDR is not a trusted proxy` | A peer with a loopback or private address, not in `--trusted-proxy`, sends `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, `CF-Connecting-IP` or the `--real-ip-header` name. It is probably your reverse proxy. It can also be a client on your own network that sends such a header | `hint_fwd_untrusted` | `--trusted-proxy ADDR`, and the proxy's header line (see [reverse proxy](reverse-proxy.md#what-the-server-can-and-cannot-tell)) |
| 2 | `hint: the trusted proxy ADDR sent a request without the header NAME` | A peer in `--trusted-proxy` (or on `--listen-unix`) sends a request without the client-address header. That connection is not limited per address. A health check from the proxy's host looks the same | `realip_missing` | make the proxy set the header on every request |
| 3 | `hint: N of M connections come from ADDR, a loopback or private address` | One loopback or private address holds at least 64 connections and more than half of all. A proxy, a NAT or a container port forward in front of many users looks like this; so does one busy local client. Checked about every 30 seconds | `one_key_conns_max` (the largest N seen) | `--trusted-proxy` and the header line, or `--proxy-protocol` |
| 4 | `warning: the host entered kernel TCP memory pressure` | The kernel's count of TCP memory pressure periods went up (read once a second). While it lasts the kernel throttles every TCP socket on the host | `host_tcp_pressures` in the metrics line (`--metrics-interval`), `finalwisp_host_tcp_pressures_total` at `--metrics-listen` | [small hosts and many slow downloads](memory.md#small-hosts-and-many-slow-downloads) |

When they run:

- Hints 1 and 2 need the server to keep peer addresses: a per-IP limit, `--conn-share` or `--trusted-proxy` is set
  (hint 2 also works for `--listen-unix`). A plain `finalwisp` keeps no peer address and prints neither.
- Hint 3 needs the per-address table: a per-IP limit or `--conn-share` is set.
- The `public` preset sets `--conn-share`, so with the preset alone hints 1 and 3 can print.
- Line 4 comes from the memory sampler, so `--mem-budget 0` turns it off. In a container with its own network
  namespace the kernel counts only the pressure periods that this container's sockets started, so the line can miss
  some.

A hint names a loopback or private address, or the address of a trusted proxy. It never names a client on a public
address.

### Privacy and safety of the logs

- Client IPs appear only with `--log-conns` or `--log-streams`, except that a [runtime hint](#runtime-hints-and-warnings)
  can name a loopback or private peer or a trusted proxy. Target names appear only with `--log-streams`.
- User names, keys and passwords are never logged. An `--upstream` URL is shown as `scheme://***@host:port`.
- Values are escaped, so a client cannot fake a line or a field.
- A slow log reader never slows the server: one log thread writes the lines, and lines that do not fit its queue are
  dropped and counted (`ev=log_dropped n=`, metric `log_dropped`). With journald this does not happen at normal rates.

### Wisp close codes

What a client sees when finalwisp closes a stream:

| code | meaning |
|---|---|
| `0x02` | the target closed the connection (normal end) |
| `0x03` | network error on an open stream |
| `0x41` | invalid CONNECT (bad stream type, port 0, a bad host name) |
| `0x42` | unreachable: the name does not resolve, or no route |
| `0x43` | connect timeout (`--connect-timeout`), or a destination that does not answer (`--dest-failfast`: at once) |
| `0x44` | the target refused the connection |
| `0x47` | an open target stopped answering (keepalive or retransmission timeout) |
| `0x48` | blocked by the destination policy, `--no-udp`, or UDP with `--upstream` |
| `0x49` | throttled: memory pressure, a stream limit, too many DNS lookups in flight, no file descriptor left, or a guard (`--tcpmem-share`, `--port-share`) |
| `0x04`, `0xc0`-`0xc2` | (whole connection) incompatible version, bad password, bad signature, authentication required |

WebSocket close codes: 1000 normal, 1001 server shutdown, 1002 protocol error, 1009 message too big, 1013 try again
later (heavy memory pressure, plain `ws://` only).

## Metrics and Prometheus

The counters always run; reading them is off by default. Two ways, usable together:

- `--metrics-interval SECS` prints one `ev=metrics` line with every counter on stderr each interval, and an
  `ev=metrics_final` line at exit.
- `--metrics-listen [ADDR:]PORT` serves `GET /metrics` in the Prometheus text format on its own port. A bare port
  listens on `127.0.0.1`.

```sh
finalwisp --metrics-listen 9464
curl -s http://127.0.0.1:9464/metrics | head
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: finalwisp
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

The endpoint has **no authentication and no TLS**. Keep it on loopback or a private address (finalwisp warns about any
other address), or put your reverse proxy's authentication in front. It can never be the Wisp port, and a port already
in use stops the server at startup.

What you get:

- Counters as `finalwisp_<name>_total`, for example `finalwisp_accepted_total` and
  `finalwisp_refuse_policy_total`.
- Gauges such as `finalwisp_connections`, `finalwisp_streams`, `finalwisp_memory_level` and
  `finalwisp_process_resident_bytes`.
- Close codes sent: `finalwisp_close_total{reason="0x49"}` (a code appears once it was sent at least once). Time at each memory level:
  `finalwisp_memory_level_seconds_total{level="0"}` to `"3"`.
- `finalwisp_build_info{version="..."} 1`.
- Base units only (bytes, seconds). Every metric has `# HELP` and `# TYPE` lines.

No metric carries a client address, a destination or a secret.

Proxy setup: `finalwisp_hint_fwd_untrusted_total`, `finalwisp_realip_missing_total` and `finalwisp_one_key_conns_max`
above 0 mean a [runtime hint](#runtime-hints-and-warnings) was due.

Useful ones to watch: `finalwisp_memory_level` above 0 (memory pressure), `finalwisp_refuse_conns_total` and
`finalwisp_refuse_ip_conns_total` and `finalwisp_refuse_ip_connrate_total` (per-IP connection limits hit), `finalwisp_refuse_policy_total` (policy refusals),
`finalwisp_dead_peers_total`, `finalwisp_log_dropped_total` and `finalwisp_upstream_fail_total`.

Name lookups: `finalwisp_dns_wait_seconds_total` is the time lookups waited for a free resolver thread; divided by
`finalwisp_dns_miss_total` it is the mean wait of a new name (normally well under a millisecond).
`finalwisp_dns_wait_max_seconds` is the longest wait since the start. `finalwisp_dns_expired_total` counts lookups
that waited as long as `--connect-timeout` and were given up without a query. A wait that grows means the resolver
threads are all busy: see [slow names](public-server.md#slow-names-and-the-resolver-threads).
