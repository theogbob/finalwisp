# Memory

Give finalwisp a memory limit that it stays under, and keep a small host out of kernel TCP memory pressure.

```sh
finalwisp --mem-budget 1G        # or MemoryMax=1G in the systemd unit, or docker run --memory 1g
```

- [Memory budget](#memory-budget): where the limit comes from, the four levels, sizing
- [Small hosts and many slow downloads](#small-hosts-and-many-slow-downloads): kernel TCP memory pressure, what
  helps and what it costs

## Memory budget

finalwisp keeps its memory under a budget instead of meeting the kernel's out-of-memory killer. As usage grows it
shrinks queues and buffers, then stops taking new connections and streams, and as a last step closes the clients that
hold the most memory.

Where the budget comes from (the `memory` line at startup shows it):

1. `--mem-budget BYTES`, if set (`--mem-budget 0` turns the budget off).
2. Else the cgroup memory limit: systemd `MemoryMax=`, `docker --memory`, a Kubernetes memory limit.
3. Else half of the machine's RAM.

| level | starts at | what changes |
|---|---|---|
| 0 | | normal |
| 1 | 50 % of the budget | smaller queues, credit and socket buffers; each worker thread also gets a limit on its open streams, sized from the budget (a new stream over it gets `0x49`, counter `refuse_streams`) |
| 2 | 70 % | smaller still; no new connections (they are reset at accept) and no new streams (`0x49`) |
| 3 | 85 % | clients with a pending upload are not read; streams holding over 1 MiB of unsent upload are closed; if that does not help, the clients holding the most memory are closed |

A level goes up at once and comes down after usage stays 10 points lower for a short while, so it does not flap.
Budgets under 256 MiB start at level 1 and never go below it, because a download burst can grow memory faster than it can be
measured. So a small budget always has the stream limit of level 1: with 128 MiB and 2 threads it is 227 open
streams per thread (computed), and a few users with stream-heavy pages can reach it. In a test with 20 connections
of 20 streams each, some streams were refused at 128 MiB and none at 512 MiB.

How usage is measured:

- With a cgroup limit: the cgroup's memory use, minus page cache that can be dropped.
- Without one: finalwisp's own memory plus its socket memory. It reads the socket memory from its own cgroup (cgroup
  v2 with socket accounting, the normal case). Otherwise it falls back to the host's total TCP memory, which counts
  every other program's sockets too.

So **run finalwisp in a cgroup of its own**: a systemd unit, `systemd-run --scope`, or its own container. In a cgroup
shared with other programs, their memory and sockets count against finalwisp's budget. A cgroup of its own also gives
it its own CPU share.

Sizing: an idle connection costs about 1-3 KiB in finalwisp plus about 8 KiB in the kernel. A busy stream can use up
to its socket buffers (`net.ipv4.tcp_rmem` and `tcp_wmem`). Set `MemoryMax=` (or `--mem-budget`) to what the server
may use.

Notes:

- The host's own TCP memory limit (`net.ipv4.tcp_mem`) is shared by every socket on the host and is not part of the
  budget. Credit pacing (on by default, `--no-credit-pace` turns it off) reduces how much of it full-duplex bulk traffic
  (echo-like streams) builds up. It does not always keep a small host out of TCP memory pressure: on a VPS with small
  socket buffer limits, echo with 100 streams still reaches it; `--buffer 32` (a smaller first upload window per stream)
  kept it out in most runs there. `--tcpmem-adapt` shrinks this server's socket buffers when the host gets close to it.
  Many downloads that wait on slow clients (one client with many streams, for example) keep the targets' data in this
  server's target connections, up to `net.ipv4.tcp_rmem` max each. `--park-rcvlock` (off by default) stops those buffers
  from growing while their streams wait. It catches a buffer before it grows only if the stream starts to wait early;
  a buffer that has already grown keeps its size.
  See [small hosts and many slow downloads](#small-hosts-and-many-slow-downloads) for the trade-offs.
- finalwisp's virtual size (VSZ) is larger than its resident memory, because it reserves memory in 4 MiB chunks. Only
  resident memory counts. If you set `ulimit -v`, size it from VSZ.
- After a big burst, resident memory can stay higher for about 10 seconds while freed buffers are returned in small
  batches.

## Small hosts and many slow downloads

On a small host, one client can push the whole host into kernel TCP memory pressure. Other clients then pay for it.

When it happens: a client runs many downloads at once (about 100 streams) and its own link cannot take them as fast
as the targets send. Each waiting stream keeps the target's data in the kernel's receive queue of its target socket.
The kernel grows those queues on its own, up to `tcp_rmem` max. finalwisp's own memory stays small (about 5 MiB in
these tests); the bytes sit in kernel socket memory.

What we measured on a 2-vCPU VPS with 3.8 GB of RAM and the kernel's default `tcp_mem` (pressure starts at 233 MiB),
with far clients on 20 ms and 112 ms paths and the targets on another host:

- One far client with one connection and 100 download streams. The target queues held 140-230 MiB, and the host was
  in TCP memory pressure in 13-14 of 16 runs, for about a third of the run (median). The downloading client itself
  still got 80-100 MiB/s at 20 ms round trip.
- While that download ran, a separate upload through the same server slowed down. At 20 ms round trip it fell from
  22-65 MiB/s to 0.3 MiB/s in all 4 runs. At 112 ms the median fell from 23 to 17.5 MiB/s, and one of 4 runs fell to
  3.4 MiB/s. These are small samples, with the upload sent from the same far machine as the download.
- With 10 connections of 10 streams each, the host stayed out of pressure at 20 ms but entered it at 112 ms.
- Why uploads suffer: while the host is in pressure, the kernel limits the receive window of every socket that
  receives data to about four packets. By the same kernel rule, uploads from any client and data sent to other
  programs on the host are affected too (not measured separately). Sending is hit less.
- Another Wisp server we tested held as much or more TCP memory in the same case. The base effect is the kernel's
  limit; how a server reads its targets changes how much it holds (see `--no-splice` below).

What helps, with the measured costs:

- **`--no-splice`.** The copy path reads less from each target socket at a time, so the kernel probably grows fewer of
  them to large sizes. In the 100-stream case at 20 ms the download was 1.2x faster (1.16-1.21x in three paired
  comparisons of 16 runs), the runs in pressure fell from 13-14 of 16 to 0-2 of 16, and the host TCP peak fell from
  233-234 to 178-180 MiB. The upload next to it kept 4-40 MiB/s at 20 ms (median 19) and 16-26 MiB/s at 112 ms
  (median 24). The cost is on fast local paths: on loopback on the same kind of VPS, downloads were 12-31% slower
  (1 stream 12%, 10 x 10 streams 31%), and the host held more TCP memory there, not less (10 x 10 streams: in
  pressure in all 16 runs instead of 8). An older test on another machine lost more on one loopback stream (3.5 to
  1.9 GiB/s). Use it on a small host whose clients are far away; leave splice on where clients and targets are close
  and fast.
- **Adaptive splice** (on by default since 1.2.1; `--no-adaptive-splice` turns it off). Keeps splice on, but a far
  client (round trip 10 ms or more when it connected) with more than 4 streams (busy or idle) whose socket is backed
  up gets 64 KiB reads from its targets instead of 256 KiB. In the 100-stream case at 112 ms the download was 1.2-1.4x
  faster (1.66x with the built-in TLS) and the host left TCP memory pressure (0 of 16 runs instead of 9-13). On a
  lossy 20-30 ms path, 100 streams on one connection also kept the host out of pressure (0 of 16 runs instead of 13),
  with no clear change in download speed. With 10 connections of 10 streams on that path the host was in pressure in
  about 9 of 32 runs instead of all 32, but the download was about 5% slower than with `--no-adaptive-splice`; turning
  it off gets that back, but on a small host it can put the kernel into TCP memory pressure, which slows every other
  TCP connection on that host. Clients closer than 10 ms (same host, LAN) and clients on `--listen-unix` keep 256 KiB
  reads, so on a 2-core VPS with clients on the same host nothing changed with it on. **Behind a reverse proxy on the
  same host (nginx or Caddy as in [Behind a reverse proxy](reverse-proxy.md#what-matters-with-any-proxy), the usual setup) every client
  looks local to finalwisp, so it does nothing there: no gain, no cost.** It helps only when far clients connect to
  finalwisp directly, with plain ws:// or its own TLS (behind a TCP load balancer the round trip is the balancer's).
- **Per-IP and per-connection limits.** Fewer parallel streams per client means less waiting data. In the same test
  at 20 ms, one connection with 10 streams peaked at 58 MiB of host TCP memory, with 50 streams at 176-232 MiB, with
  100 at 231-244 MiB. `--max-streams-per-conn` caps the streams on one connection (the 1024 of the `public` preset is a backstop and does
  not stop 100). `--max-conns-per-ip` caps how many
  connections one address can spread them over (10 x 10 streams still reached pressure at 112 ms).
  `--stream-rate-per-ip` only limits how fast new streams open, not how many run at once. Set the caps above what your
  normal clients use; we did not measure a particular value.
- **More RAM or a larger `tcp_mem`.** The kernel sets `tcp_mem` from the RAM size (pressure starts at the second
  value, about 6% of RAM), and finalwisp never changes it. The startup warning about `tcp_mem` below 512 MiB points at
  this case. Raise all three values of `net.ipv4.tcp_mem` yourself if the host has the memory, or move to a larger
  host.
- **`--buffer 32`.** A smaller first upload window per stream. It helps when the pressure comes from echo-like traffic
  (many streams that upload and download at once). In a loopback echo test with 10 x 10 streams on the same kind of
  VPS, the runs in pressure went from 16 of 16 to 1 of 16, the host TCP peak from 234 to 198 MiB, and server memory
  from 144 to 22 MiB. It does not target the many-downloads case above (downloads do not use upload credit). The
  cost: an upload of 1-4 MiB on an already open connection waits one more round trip. At 115 ms round trip a 1 MiB
  upload took 243 ms instead of 121 ms (median), a 4 MiB upload 494 ms instead of 358 ms. Uploads up to 256 KiB took
  2% longer or less, and uploads that open a new connection each time did not change. A new upload stream also
  started slower in its first second on a 150 ms test link (0.75x). Use it only where echo-like traffic causes the
  pressure and large uploads on open connections are rare.
- **`--tcpmem-share`** is for another case: one client address that holds many
  downloads it never reads. From 3/4 of `tcp_mem` that address gets no new streams while another client is
  connected. It does not act in the case of this section: a download that ran at full speed before its client slowed
  down holds about 2.6 MiB of TCP memory, 100 of them fill a host of this size, and the rule does not count so few
  sockets as a share. See the [reference](configuration.md#--tcpmem-share).
- **Not a fix:** `--tcpmem-adapt` kept the host out of pressure but cost the many-stream downloads a quarter to a
  third of their speed. A low `--mem-budget` counts socket memory and slows everything: 256 MiB cut that download to
  about half.

How to tell:

0. finalwisp logs `warning: the host entered kernel TCP memory pressure` when it happens (see
   [runtime hints and warnings](logs-metrics.md#runtime-hints-and-warnings)).
1. Look at the host's TCP memory: `cat /proc/net/sockstat` (the `mem` value on the `TCP:` line, in 4 KiB pages)
   against `cat /proc/sys/net/ipv4/tcp_mem` (three values, also in pages). Pressure starts above the second value and
   ends below the first.
2. Check whether the host is in pressure now: the `press` column of the `TCP` line in `/proc/net/protocols` reads
   `yes`.
3. Count how often it entered pressure: `nstat -az TcpExtTCPMemoryPressures TcpExtTCPMemoryPressuresChrono`. The first
   counts entries (a host that stays in pressure counts once), the second the milliseconds spent in pressure, added
   only when a pressure period ends.
4. Find the cause: `finalwisp_streams` is high against `finalwisp_connections` (many streams per connection), and
   `--log-streams` shows which client addresses run them. Uploads from other clients slow down at the same time.
5. Check finalwisp's own memory (`finalwisp_process_resident_bytes`). If it is small but host TCP memory is near the
   limit, the bytes are in socket queues, and the options above apply.
