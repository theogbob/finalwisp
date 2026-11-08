# Benchmarks

How finalwisp compares with the other Wisp servers on the same machine, under the same load. The short version is in
the [README](../README.md#performance). This page has every number, the method, and the caveats you need to read
them. To run the same tests yourself, see [benchmarking](benchmarking.md).

Measured with finalwisp 1.1.0 on 2026-11-07, on all three machines in the same session.

## What these numbers are, and are not

- **Loopback, no TLS.** The load generator, the test targets and the server run on one machine, over plain `ws://`.
  This shows how much each server can move when the network is not the limit. Over a real network the link usually
  limits throughput long before the server does.
- **Defaults.** Every server ran at its default or documented settings. None was tuned for these tests.
- **Shared cores on the small machines.** On the 2-core VPSes the load generator and the targets share the 2 cores with
  the server. That is the same for every server, but it lowers all numbers.
- **Small machines run out of kernel TCP memory.** On a 3.8 GB VPS, many fast streams can push the kernel into TCP
  memory pressure. Results under pressure are erratic for every server, so those cells are marked invalid and left out
  of the README's ranges. See [TCP memory pressure](#tcp-memory-pressure).
- **wispurr has known bugs.** The tested wispurr moved no data in some tests and was killed for running out of memory
  in others. See [notes](#notes).
- **Two kinds of memory.** "RSS after the case" is the resident memory right after a test: what a server keeps holding
  once the load is gone. "Peak" is the highest resident memory during the whole run (VmHWM). In this run finalwisp had
  the lowest RSS after the case on all three machines, and the lowest peak on two; on VPS A its peak was level with
  wisp-server-python's (156 vs 160 MiB).

## Method

- **Load generator:** `wbench`, from this repository. Each cell is 5 seconds of measurement after a 1 second warm-up.
  The value is the median of 3 runs, and the order of the servers changed between runs.
- **Targets:** an echo, a sink and a source server on the same machine.
- **Tests:**
  - upload, download and echo, with 1 stream, or with 10 connections of N streams each;
  - request/response with 64-byte messages, with 1 stream or 10 x 10 streams;
  - "new stream per request" (churn): every request opens a new stream.
- **Servers:**

  | server | version and settings |
  |---|---|
  | finalwisp | 1.1.0, default settings |
  | epoxy-server | multithreaded runtime |
  | wisp-server-python | 0.9.0 on CPython 3.13, in its default multi-process mode (memory = the whole process group) |
  | wisp-js | 0.5.0 on Node 24 (one thread, by design) |
  | wispurr | its author's speed configuration |

  Loopback and private targets were allowed in every server, because the targets are local.
- **Memory:** "RSS after the case" is the server's resident memory right after the case; the table shows the largest
  case. "Peak" is the process's lifetime high-water mark (VmHWM).
- **Kernel TCP memory:** for every cell we also record whether the kernel was in TCP memory pressure: the TcpExt
  `TCPMemoryPressures` counter before and after, and the kernel's pressure flag sampled every 0.05 s during the cell.
  A run counts as under pressure if either shows it.
- **Units:** MiB/s = 2^20 bytes per second. "Each way" for echo means the rate in one direction. `k` = 1000.

## 72-thread server

2 x Intel Xeon Gold 6154 (72 threads), Linux 7.0, a rented container. No cell was under TCP memory pressure.

| test | finalwisp | epoxy-server | wisp-server-python | wisp-js | wispurr |
|---|---|---|---|---|---|
| upload, 1 stream (MiB/s) | 2,712 | 1,193 | 418 | 432 | 0.0 |
| upload, 10 conns x 10 streams (MiB/s) | 12,535 | 8,540 | 3,439 | 399 | 8,509 |
| download, 10 conns x 10 streams (MiB/s) | 22,313 | 5,609 | 6,685 | 601 | 0.0 (30 err) |
| echo, 1 stream (MiB/s each way) | 1,961 | 362 | 272 | 259 | 0.0 |
| echo, 10 conns x 10 streams (MiB/s each way) | 7,366 | 3,274 | 2,239 | 222 | 4,494 |
| request/response, 1 stream (req/s) | 24k | 23k | 9.1k | 12k | 4.0k |
| request/response, 10 conns x 10 streams (req/s) | 445k | 320k | 202k | 25k | 216k |
| new stream per request, 10 conns x 10 streams (streams/s) | 124k | 21k | 17k | 7.2k | 24k |
| RSS after the case, largest (MiB) | 8.7 | 1,318 | 2,134 | 419 | 6,255 |

Peak memory (VmHWM, MiB): finalwisp 60.0, epoxy-server 1,460, wisp-server-python 2,154, wisp-js 602, wispurr 6,799.

## 2-core VPS A

AMD EPYC Milan, 2 cores, 3.8 GB RAM, Linux 6.8, the distribution's default TCP settings.

On these 3.8 GB machines the 10 x 10 bulk tests can push the kernel into TCP memory pressure, so the bulk tests were run
again at 10 connections x 2 streams, for every server. Those are the rows below. Cells marked **(P n/3)** were under
pressure in n of the 3 runs: they are invalid and left out of the README. All 10 x 2 cells were valid on this machine.

| case | finalwisp | epoxy-server | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|
| upload, 1 stream (MiB/s) | 1,853 | 798 | 0.0 | 343 | 290 |
| upload, 10 conns x 2 streams (MiB/s) | 2,013 | 841 | 792 | 346 | 445 |
| download, 10 conns x 2 streams (MiB/s) | 2,437 | 756 | 240 | 505 | 744 |
| echo, 1 stream (MiB/s each way) | 1,033 | 273 | 337 (1 run failed) | 220 | 199 |
| echo, 10 conns x 2 streams (MiB/s each way) | 1,152 | 370 | 146 (10 err) (1 run failed) | 212 | 302 |
| request/response, 1 stream (req/s) | 11,710 | 9,525 | 5,031 | 6,561 | 5,743 |
| request/response, 10 conns x 10 streams (req/s) | 64,024 | 46,021 | 30,317 | 15,907 | 19,152 |
| new stream per request, 10 conns x 10 streams (streams/s) | 15,529 | 8,227 | 6,527 | 4,665 | 4,740 |
| RSS after the case, largest (MiB, median) | 4.2 | 145 | 3,372 | 1,498 | 150 |
| peak RSS, VmHWM (MiB, max) | 156 | 186 | 3,390 | 1,686 | 160 |

How many times faster finalwisp is (finalwisp ÷ other; above 1 = finalwisp is faster). For the two memory rows the
ratio is other ÷ finalwisp: how many times less memory finalwisp used; below 1 = finalwisp used more.

| case | vs best other | vs epoxy-server | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|
| upload, 1 stream | 2.32 | 2.32 | ∞ | 5.40 | 6.39 |
| upload, 10 conns x 2 streams | 2.39 | 2.39 | 2.54 | 5.81 | 4.52 |
| download, 10 conns x 2 streams | 3.22 | 3.22 | 10.14 | 4.83 | 3.28 |
| echo, 1 stream | 3.07 | 3.78 | 3.07 | 4.69 | 5.19 |
| echo, 10 conns x 2 streams | 3.11 | 3.11 | 7.91 | 5.44 | 3.81 |
| request/response, 1 stream | 1.23 | 1.23 | 2.33 | 1.78 | 2.04 |
| request/response, 10 conns x 10 streams | 1.39 | 1.39 | 2.11 | 4.02 | 3.34 |
| new stream per request, 10 conns x 10 streams | 1.89 | 1.89 | 2.38 | 3.33 | 3.28 |
| RSS after the case, largest | 34.62 | 34.62 | 802.85 | 356.76 | 35.60 |
| peak RSS, VmHWM | 1.03 | 1.19 | 21.72 | 10.80 | 1.03 |

The dropped 10 x 10 bulk rows, for completeness (replaced by the 10 x 2 rows above):

| case | finalwisp | epoxy-server | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|
| upload, 10 conns x 10 streams (MiB/s) | 1,398 | 770 | 1,133 | 348 | 389 |
| download, 10 conns x 10 streams (MiB/s) | 2,818 | 706 (P 3/3) | 44.1 (P 3/3) | 241 (P 3/3) | 537 (P 3/3) |
| echo, 10 conns x 10 streams (MiB/s each way) | 662 (P 3/3) | 347 | 105 | 193 | 257 |

| case | vs best other | vs epoxy-server | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|
| upload, 10 conns x 10 streams | 1.23 | 1.82 | 1.23 | 4.02 | 3.60 |
| download, 10 conns x 10 streams | 3.99 | 3.99 | 63.92 | 11.69 | 5.24 |
| echo, 10 conns x 10 streams | 1.90 | 1.90 | 6.28 | 3.42 | 2.58 |

## 2-core VPS B

AMD EPYC Rome, 2 cores, 3.8 GB RAM, Linux 6.8, with larger TCP buffers and BBR congestion control.

The larger TCP buffers use more kernel TCP memory per test, so more bulk cells hit pressure here than on VPS A. Download
10 x 2 stayed under pressure for every server. **(P n/3)** marks the same as above.

| case | finalwisp | epoxy-server | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|
| upload, 1 stream (MiB/s) | 1,283 | 867 | 0.0 | 325 | 304 |
| upload, 10 conns x 2 streams (MiB/s) | 1,487 | 1,007 | 1,196 (P 3/3) | 339 | 495 |
| download, 10 conns x 2 streams (MiB/s) | 2,077 (P 3/3) | 1,015 (P 3/3) | 1,409 (P 3/3) | 527 (P 3/3) | 774 (P 3/3) |
| echo, 1 stream (MiB/s each way) | 773 | 382 | 0.0 | 208 | 234 |
| echo, 10 conns x 2 streams (MiB/s each way) | 882 | 508 (P 1/3) | 602 (P 3/3) | 213 | 332 |
| request/response, 1 stream (req/s) | 16,695 | 14,124 | 4,650 (1 run failed) | 7,719 | 6,191 |
| request/response, 10 conns x 10 streams (req/s) | 92,852 | 64,370 | 40,098 (1 run failed) | 17,944 | 21,952 |
| new stream per request, 10 conns x 10 streams (streams/s) | 21,775 | 10,840 | 7,838 (1 run failed) | 4,868 | 5,285 |
| RSS after the case, largest (MiB, median) | 4.0 | 170 | 2,296 | 1,817 | 156 |
| peak RSS, VmHWM (MiB, max) | 20.1 | 237 | 3,040 | 1,866 | 159 |

How many times faster finalwisp is (memory rows: how many times less memory it used):

| case | vs best other | vs epoxy-server | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|
| upload, 1 stream | 1.48 | 1.48 | ∞ | 3.95 | 4.22 |
| upload, 10 conns x 2 streams | 1.24 | 1.48 | 1.24 | 4.38 | 3.01 |
| download, 10 conns x 2 streams | 1.47 | 2.05 | 1.47 | 3.94 | 2.68 |
| echo, 1 stream | 2.03 | 2.03 | ∞ | 3.71 | 3.31 |
| echo, 10 conns x 2 streams | 1.47 | 1.74 | 1.47 | 4.14 | 2.66 |
| request/response, 1 stream | 1.18 | 1.18 | 3.59 | 2.16 | 2.70 |
| request/response, 10 conns x 10 streams | 1.44 | 1.44 | 2.32 | 5.17 | 4.23 |
| new stream per request, 10 conns x 10 streams | 2.01 | 2.01 | 2.78 | 4.47 | 4.12 |
| RSS after the case, largest | 39.02 | 42.40 | 574.04 | 454.23 | 39.02 |
| peak RSS, VmHWM | 7.92 | 11.81 | 151.24 | 92.82 | 7.92 |

The dropped 10 x 10 bulk rows (replaced by the 10 x 2 rows above):

| case | finalwisp | epoxy-server | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|
| upload, 10 conns x 10 streams (MiB/s) | 1,322 | 881 | 1,172 (P 3/3) | 304 | 416 |
| download, 10 conns x 10 streams (MiB/s) | 1,538 (P 3/3) | 695 (P 3/3) | 757 (3 err) (P 3/3) | 221 (P 3/3) | 802 (P 3/3) |
| echo, 10 conns x 10 streams (MiB/s each way) | 827 | 446 | 581 (1 run failed) (P 2/2) | 192 | 275 |

| case | vs best other | vs epoxy-server | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|
| upload, 10 conns x 10 streams | 1.13 | 1.50 | 1.13 | 4.36 | 3.18 |
| download, 10 conns x 10 streams | 1.92 | 2.21 | 2.03 | 6.95 | 1.92 |
| echo, 10 conns x 10 streams | 1.42 | 1.85 | 1.42 | 4.30 | 3.01 |

## TCP memory pressure

Linux has one limit for the TCP memory of all sockets on a host (`net.ipv4.tcp_mem`). When the sockets get close to
it, the kernel enters "memory pressure" and shrinks socket buffers. Throughput then swings widely, for every server. A
bulk cell during which the kernel entered pressure is therefore invalid. [Benchmarking](benchmarking.md#tcp-memory-pressure) shows how to check for it.

The echo 10 x 10 cell on VPS A (dropped) is a case where finalwisp itself can cause the pressure: it takes uploads
faster than the clients read the echoed data, so the data waits in kernel socket buffers. Since 1.1.0, credit pacing
(on by default) stops refilling a stream's upload credit while its replies wait on the client. In this run finalwisp
moved 662 MiB/s in that cell against epoxy-server's 347, but the kernel was still under pressure for up to 58 % of the
cell, so the cell stays invalid. On VPS B, finalwisp's echo cells stayed out of pressure.

## Notes

- **wispurr:** on the big server and VPS B it moved no data in the single-stream upload and echo tests; on VPS A it moved
  data in some of those runs and not in others. It failed the big server's download test (0 MiB/s, 30 errors) and was
  killed by the kernel's out-of-memory killer on both VPSes (at 3.2-3.3 GiB). Its request/response and new-stream cells on
  VPS A come from a fresh server process: after its echo 10 x 10 growth it managed 27 requests/s. The tested version has
  known data-loss and flow-control bugs.
- **Peak memory (VmHWM):** finalwisp's peak was the lowest of the five servers on the big server, 60 MiB (others 602
  MiB to 6.6 GiB), and on VPS B, 20 MiB (others 159 MiB to 3.0 GiB). On VPS A it was 156 MiB, level with
  wisp-server-python's 160 MiB (epoxy-server 186 MiB); it comes from the echo 10 x 10 test, a cell under pressure.
- **Loopback is not the internet:** over a real network the link usually limits throughput long before the server
  does.
