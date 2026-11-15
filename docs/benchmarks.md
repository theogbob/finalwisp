# Benchmarks

How finalwisp compares with the other Wisp servers on the same machine, under the same load. The short version is in
the [README](../README.md#performance). This page has every number, the method, and the caveats you need to read
them. To run the same tests yourself, see [benchmarking](benchmarking.md).

Measured with finalwisp 1.3.1 on 2026-11-15, against the newest version of every other server on that day.

## What these numbers are, and are not

- **Loopback, no TLS.** The load generator, the test targets and the server run on one machine, over plain `ws://`.
  This shows how much each server can move when the network is not the limit. Over a real network the link usually
  limits throughput long before the server does.
- **Defaults.** Every server ran at its default or documented settings. None was tuned for these tests.
- **Medians of 3 runs, one session per machine.** A value is the median of 3 runs. These are not paired statistical
  tests, and a machine's numbers move by up to about 20 % between two sessions of the same binary. Read small
  differences as no difference.
- **Shared cores on the small machines.** On the 2-core VPSes the load generator and the targets share the 2 cores with
  the server. That is the same for every server, but it lowers all numbers.
- **Small machines run out of kernel TCP memory.** On a 3.8 GB VPS, many fast streams can push the kernel into TCP
  memory pressure. Results under pressure are erratic for every server, so those cells are marked invalid.
  See [TCP memory pressure](#tcp-memory-pressure).
- **epoxy-server, two builds.** epoxy-server ships as source. Built the way its README says (`cargo b -r`), it uses the
  tokio-websockets 0.12.0 of its lock file, and under load it crashed: the whole server process exited on a panic
  inside tokio-websockets. The column "epoxy-server" is that build. The column "epoxy-server, tokio-websockets 0.12.3"
  is the same commit with one change, `cargo update -p tokio-websockets --precise 0.12.3`, which fixes the crash.
  **The epoxy-server numbers published here before 2026-11-15 were for a build with tokio-websockets 0.12.3 in its lock
  file**, not for the lock file of the epoxy repository.
- **Two kinds of memory.** "RSS after the case" is the resident memory right after a test: what a server keeps holding
  once the load is gone. "Peak" is the highest resident memory during the whole run (VmHWM).

## Method

- **Load generator:** `wbench`, from this repository. Each cell is 5 seconds of measurement after a 1 second warm-up.
  The value is the median of 3 runs, and the order of the servers changed between runs. One server process serves all
  tests of a run.
- **Targets:** an echo, a sink and a source server on the same machine.
- **Tests:**
  - upload, download and echo, with 1 stream, or with 10 connections of N streams each;
  - request/response with 64-byte messages, with 1 stream or 10 x 10 streams;
  - "new stream per request" (churn): every request opens a new stream.
- **Servers:**

  | server | version and settings |
  |---|---|
  | finalwisp | 1.3.1, default settings |
  | epoxy-server | 9cde724 (2026-10-22), multithreaded runtime; built from its repository as its README says, and once more with tokio-websockets 0.12.3 |
  | wisp-server-python | 0.11.0 on CPython 3.13, in its default multi-process mode (memory = the whole process group) |
  | wisp-js | 0.5.3 on Node 24 (one thread, by design) |
  | wispurr | 0e0fdb1 (2026-11-14), its author's speed configuration |

  Loopback and private targets were allowed in every server, because the targets are local.
- **Memory:** "RSS after the case" is the server's resident memory right after the case; the table shows the largest
  case. "Peak" is the process's lifetime high-water mark (VmHWM). A server whose process crashed in a run misses the
  rest of that run, so its memory rows are not compared.
- **Kernel TCP memory:** for every cell we also record whether the kernel was in TCP memory pressure: the TcpExt
  `TCPMemoryPressures` counter before and after, and the kernel's pressure flag sampled every 0.05 s during the cell.
  A run counts as under pressure if either shows it.
- **Crashes:** "crashed (k/3 runs)" = the server process had exited before this test in k runs, so the test has no
  value; "(server crashed in k runs)" = the test ran, but the process was gone at its end.
- **Units:** MiB/s = 2^20 bytes per second. "Each way" for echo means the rate in one direction. `k` = 1000.

## Summary

On the 80-thread server and on both 2-core VPSes, finalwisp had the highest median in every test of the main tables (median of 3 runs, one
session per machine, not a paired statistical test). The smallest margin was request/response with 1 stream, against
epoxy-server: 1.05x on the 80-thread server, 1.05x on VPS A and 1.14x on VPS B (tokio-websockets 0.12.3 build on the VPSes), which is inside the spread between two
sessions of one machine. finalwisp's own medians on the VPSes are 0.80-1.05 of those published for 1.1.0 on 2026-11-07, in the tests that were
valid in both sessions; the cause is not established. This page has no paired test of 1.3.1 against 1.1.0.

## 80-thread server

2 x Intel Xeon Gold 6138 (80 threads), Linux 6.6, a rented container. No cell was under TCP memory pressure. This is not
the 72-thread machine of the earlier version of this page, so its numbers do not compare with those.

| case | finalwisp | epoxy-server | epoxy-server, tokio-websockets 0.12.3 | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 1 stream (MiB/s) | 2,230 | 521 | 541 | 1,286 | 352 | 483 |
| upload, 10 conns x 10 streams (MiB/s) | 4,800 | 2,721 | 2,797 | 2,808 | 316 | 2,957 |
| download, 10 conns x 10 streams (MiB/s) | 5,965 | 2,928 | 2,803 | 2,397 | 540 | 3,282 |
| echo, 1 stream (MiB/s each way) | 1,345 | 291 | 321 | 738 | 0.0 (3 err) | 310 |
| echo, 10 conns x 10 streams (MiB/s each way) | 2,492 | 1,151 | 1,149 | 1,347 | 202 | 1,358 |
| request/response, 1 stream (req/s) | 13,986 | 13,270 | 12,779 | 10,271 | 8,743 | 6,855 |
| request/response, 10 conns x 10 streams (req/s) | 420,722 | 277,970 | 280,095 | 133,707 | 28,568 | 212,660 |
| new stream per request, 10 conns x 10 streams (streams/s) | 86,530 | 20,611 | 20,794 | 24,184 | 6,360 | 16,291 |
| RSS after the case, largest (MiB, median) | 25.2 | 1,549 | 1,484 | 1,414 | 872 | 2,279 |
| peak RSS, VmHWM (MiB, max) | 95.9 | 1,615 | 1,601 | 1,615 | 888 | 2,286 |

How many times faster finalwisp is (memory rows: how many times less memory it used):

| case | vs best other | vs epoxy-server | vs epoxy-server, tokio-websockets 0.12.3 | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 1 stream | 1.73 | 4.28 | 4.12 | 1.73 | 6.33 | 4.62 |
| upload, 10 conns x 10 streams | 1.62 | 1.76 | 1.72 | 1.71 | 15.21 | 1.62 |
| download, 10 conns x 10 streams | 1.82 | 2.04 | 2.13 | 2.49 | 11.04 | 1.82 |
| echo, 1 stream | 1.82 | 4.61 | 4.19 | 1.82 | ∞ | 4.34 |
| echo, 10 conns x 10 streams | 1.83 | 2.16 | 2.17 | 1.85 | 12.36 | 1.83 |
| request/response, 1 stream | 1.05 | 1.05 | 1.09 | 1.36 | 1.60 | 2.04 |
| request/response, 10 conns x 10 streams | 1.50 | 1.51 | 1.50 | 3.15 | 14.73 | 1.98 |
| new stream per request, 10 conns x 10 streams | 3.58 | 4.20 | 4.16 | 3.58 | 13.61 | 5.31 |
| RSS after the case, largest | 34.60 | 61.46 | 58.87 | 56.12 | 34.60 | 90.44 |
| peak RSS, VmHWM | 9.26 | 16.84 | 16.70 | 16.84 | 9.26 | 23.84 |

## 2-core VPS A

AMD EPYC Milan, 2 cores, 3.8 GB RAM, Linux 6.8, the distribution's default TCP settings.

On these 3.8 GB machines the 10 x 10 bulk tests can push the kernel into TCP memory pressure, so the bulk tests were run
again at 10 connections x 2 streams, for every server. Those are the rows below. Cells marked **(P n/3)** were under
pressure in n of the 3 runs: they are invalid.

| case | finalwisp | epoxy-server | epoxy-server, tokio-websockets 0.12.3 | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 1 stream (MiB/s) | 1,706 | 649 | 585 | 1,015 | 295 | 267 |
| upload, 10 conns x 2 streams (MiB/s) | 1,802 | 782 | 797 | 1,144 | 0.0 (29 err) | 407 |
| download, 10 conns x 2 streams (MiB/s) | 2,233 (P 1/3) | 703 | 677 | 1,529 | 442 | 688 |
| echo, 1 stream (MiB/s each way) | 938 | 247 | 275 | 592 | 168 | 179 |
| echo, 10 conns x 2 streams (MiB/s each way) | 1,039 | 97.5 (30 err) (server crashed in 3 runs) | 340 | 647 | 196 | 248 |
| request/response, 1 stream (req/s) | 10,420 | crashed (3/3 runs) | 9,911 | 6,435 | 6,228 | 5,382 |
| request/response, 10 conns x 10 streams (req/s) | 57,369 | crashed (3/3 runs) | 40,154 | 20,652 | 11,818 | 19,631 |
| new stream per request, 10 conns x 10 streams (streams/s) | 12,433 | crashed (3/3 runs) | 6,935 | 5,238 | 3,981 | 4,309 |
| RSS after the case, largest (MiB, median) | 4.5 | 76.8 (runs crashed) | 146 | 1,015 | 1,352 | 163 |
| peak RSS, VmHWM (MiB, max) | 154 | 111 (runs crashed) | 163 | 1,024 | 1,410 | 168 |

How many times faster finalwisp is (finalwisp ÷ other; above 1 = finalwisp is faster). For the two memory rows the
ratio is other ÷ finalwisp: how many times less memory finalwisp used; below 1 = finalwisp used more.

| case | vs best other | vs epoxy-server | vs epoxy-server, tokio-websockets 0.12.3 | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 1 stream | 1.68 | 2.63 | 2.92 | 1.68 | 5.78 | 6.40 |
| upload, 10 conns x 2 streams | 1.57 | 2.31 | 2.26 | 1.57 | ∞ | 4.43 |
| download, 10 conns x 2 streams | 1.46 | 3.18 | 3.30 | 1.46 | 5.05 | 3.25 |
| echo, 1 stream | 1.59 | 3.79 | 3.41 | 1.59 | 5.58 | 5.23 |
| echo, 10 conns x 2 streams | 1.61 | 10.66 | 3.05 | 1.61 | 5.30 | 4.18 |
| request/response, 1 stream | 1.05 | - | 1.05 | 1.62 | 1.67 | 1.94 |
| request/response, 10 conns x 10 streams | 1.43 | - | 1.43 | 2.78 | 4.85 | 2.92 |
| new stream per request, 10 conns x 10 streams | 1.79 | - | 1.79 | 2.37 | 3.12 | 2.89 |
| RSS after the case, largest | 32.44 | - | 32.44 | 225.53 | 300.53 | 36.29 |
| peak RSS, VmHWM | 1.06 | - | 1.06 | 6.65 | 9.16 | 1.09 |

The dropped 10 x 10 bulk rows, for completeness (replaced by the 10 x 2 rows above):

| case | finalwisp | epoxy-server | epoxy-server, tokio-websockets 0.12.3 | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 10 conns x 10 streams (MiB/s) | 1,406 (P 1/3) | 706 (10 err) (server crashed in 1 run) | 730 | 1,044 | 291 | 373 |
| download, 10 conns x 10 streams (MiB/s) | 1,929 (P 2/3) | 586 (P 2/2) (1 run crashed) | 639 (P 3/3) | 1,428 (P 3/3) | 209 (P 3/3) | 455 (P 3/3) |
| echo, 10 conns x 10 streams (MiB/s each way) | 692 (P 3/3) | 0.0 (20 err) (1 run crashed) | 325 | 529 (P 3/3) | 179 | 261 |

| case | vs best other | vs epoxy-server | vs epoxy-server, tokio-websockets 0.12.3 | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 10 conns x 10 streams | 1.35 | 1.99 | 1.93 | 1.35 | 4.82 | 3.77 |
| download, 10 conns x 10 streams | 1.35 | 3.29 | 3.02 | 1.35 | 9.25 | 4.23 |
| echo, 10 conns x 10 streams | 1.31 | ∞ | 2.13 | 1.31 | 3.88 | 2.66 |

## 2-core VPS B

AMD EPYC Rome, 2 cores, 3.8 GB RAM, Linux 6.8, with larger TCP buffers and BBR congestion control.

On these 3.8 GB machines the 10 x 10 bulk tests can push the kernel into TCP memory pressure, so the bulk tests were run
again at 10 connections x 2 streams, for every server. Those are the rows below. Cells marked **(P n/3)** were under
pressure in n of the 3 runs: they are invalid. The larger TCP buffers use more kernel TCP memory per test, so more bulk cells hit pressure here than on VPS A.

| case | finalwisp | epoxy-server | epoxy-server, tokio-websockets 0.12.3 | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 1 stream (MiB/s) | 1,281 | 845 | 842 | 999 | 308 | 323 |
| upload, 10 conns x 2 streams (MiB/s) | 1,422 | 850 (10 err) (server crashed in 1 run) | 930 (P 1/3) | 1,019 (P 3/3) | 282 (15 err) | 407 |
| download, 10 conns x 2 streams (MiB/s) | 1,758 (P 3/3) | 850 (P 1/2) (1 run crashed) | 723 (P 3/3) | 1,393 (P 3/3) | 473 (P 3/3) | 735 (P 3/3) |
| echo, 1 stream (MiB/s each way) | 724 | 358 (1 run crashed) | 349 | 529 | 194 | 220 |
| echo, 10 conns x 2 streams (MiB/s each way) | 848 | 294 (10 err) (1 run crashed) | 459 (P 2/3) | 489 (P 3/3) | 196 (13 err) | 303 |
| request/response, 1 stream (req/s) | 16,808 | crashed (3/3 runs) | 14,743 | 8,911 | 7,718 | 6,332 |
| request/response, 10 conns x 10 streams (req/s) | 97,494 | crashed (3/3 runs) | 55,120 | 36,622 | 17,226 | 19,061 |
| new stream per request, 10 conns x 10 streams (streams/s) | 17,984 | crashed (3/3 runs) | 10,047 | 7,331 | 4,324 | 4,899 |
| RSS after the case, largest (MiB, median) | 4.1 | 85.0 (runs crashed) | 172 | 1,237 | 1,320 | 166 |
| peak RSS, VmHWM (MiB, max) | 125 | 105 (runs crashed) | 228 | 1,322 | 1,866 | 168 |

How many times faster finalwisp is (finalwisp ÷ other; above 1 = finalwisp is faster). For the two memory rows the
ratio is other ÷ finalwisp: how many times less memory finalwisp used; below 1 = finalwisp used more.

| case | vs best other | vs epoxy-server | vs epoxy-server, tokio-websockets 0.12.3 | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 1 stream | 1.28 | 1.52 | 1.52 | 1.28 | 4.15 | 3.97 |
| upload, 10 conns x 2 streams | 1.40 | 1.67 | 1.53 | 1.40 | 5.05 | 3.49 |
| download, 10 conns x 2 streams | 1.26 | 2.07 | 2.43 | 1.26 | 3.72 | 2.39 |
| echo, 1 stream | 1.37 | 2.02 | 2.07 | 1.37 | 3.72 | 3.29 |
| echo, 10 conns x 2 streams | 1.74 | 2.89 | 1.85 | 1.74 | 4.32 | 2.80 |
| request/response, 1 stream | 1.14 | - | 1.14 | 1.89 | 2.18 | 2.65 |
| request/response, 10 conns x 10 streams | 1.77 | - | 1.77 | 2.66 | 5.66 | 5.11 |
| new stream per request, 10 conns x 10 streams | 1.79 | - | 1.79 | 2.45 | 4.16 | 3.67 |
| RSS after the case, largest | 40.37 | - | 41.90 | 301.68 | 322.00 | 40.37 |
| peak RSS, VmHWM | 1.34 | - | 1.82 | 10.56 | 14.90 | 1.34 |

The dropped 10 x 10 bulk rows, for completeness (replaced by the 10 x 2 rows above):

| case | finalwisp | epoxy-server | epoxy-server, tokio-websockets 0.12.3 | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 10 conns x 10 streams (MiB/s) | 1,303 | 0.0 (30 err) (server crashed in 3 runs) | 834 | 1,030 (P 3/3) | 262 (6 err) | 395 |
| download, 10 conns x 10 streams (MiB/s) | 1,685 (P 3/3) | crashed (3/3 runs) | 627 (P 3/3) | 1,425 (P 3/3) | 279 (P 3/3) | 724 (P 3/3) |
| echo, 10 conns x 10 streams (MiB/s each way) | 826 (P 1/3) | crashed (3/3 runs) | 395 | 498 (P 3/3) | 187 (1 err) | 258 |

| case | vs best other | vs epoxy-server | vs epoxy-server, tokio-websockets 0.12.3 | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|---|
| upload, 10 conns x 10 streams | 1.27 | ∞ | 1.56 | 1.27 | 4.97 | 3.30 |
| download, 10 conns x 10 streams | 1.18 | - | 2.69 | 1.18 | 6.04 | 2.33 |
| echo, 10 conns x 10 streams | 1.66 | - | 2.09 | 1.66 | 4.42 | 3.21 |

## TCP memory pressure

Linux has one limit for the TCP memory of all sockets on a host (`net.ipv4.tcp_mem`). When the sockets get close to
it, the kernel enters "memory pressure" and shrinks socket buffers. Throughput then swings widely, for every server. A
bulk cell during which the kernel entered pressure is therefore invalid. [Benchmarking](benchmarking.md#tcp-memory-pressure) shows how to check for it.

## Notes

- **epoxy-server:** built as its README says, the server process crashed (a panic in tokio-websockets 0.12.0) in the
  many-stream upload and echo tests on both VPSes (not on the 80-thread server); every later test of that run then had no server. Its
  request/response and new-stream rows therefore have no value. With tokio-websockets 0.12.3 it did not crash. The
  numbers published here before 2026-11-15 were for a build with 0.12.3 in its lock file.
- **wispurr:** the tested version (0e0fdb1) fixed the data-loss and flow-control bugs of the version published here
  before. It now moves data in every test, its peak memory stayed at 1.0-1.6 GiB, and it was not killed for running
  out of memory. It does not answer the `wisp-v2` WebSocket subprotocol a Wisp v2 client asks for, so a standard
  client (wisp-js) falls back to Wisp v1 with it.
- **wisp-js:** 0.5.3 reset connections in the 10 x 2 upload test on the VPSes and moved no data in the single-stream
  echo test on the 80-thread server (marked "err").
- **Loopback is not the internet:** over a real network the link usually limits throughput long before the server
  does.
