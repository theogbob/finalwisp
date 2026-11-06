# Benchmarks

How finalwisp compares with the other Wisp servers on the same machine, under the same load. The short version is in
the [README](../README.md#performance). This page has every number, the method, and the caveats you need to read
them. To run the same tests yourself, see [benchmarking](benchmarking.md).

Measured with finalwisp base-6 on 2026-11-02 (the big server) and 2026-11-06 (the two VPSes).

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
  once the load is gone. "Peak" is the highest resident memory during the whole run (VmHWM). finalwisp is far ahead on
  the first; on the small machines its peak is about the same as epoxy-server's and above wisp-server-python's.

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
  | finalwisp | base-6 |
  | epoxy-server | multithreaded runtime |
  | wisp-server-python | 0.9.0, in its default multi-process mode (memory = the whole process group) |
  | wisp-js | 0.5.0 on Node 24 (one thread, by design) |
  | wispurr | its author's speed configuration |

  Loopback and private targets were allowed in every server, because the targets are local.
- **Memory:** "RSS after the case" is the server's resident memory right after the case; the table shows the largest
  case. "Peak" is the process's lifetime high-water mark (VmHWM).
- **Units:** MiB/s = 2^20 bytes per second. "Each way" for echo means the rate in one direction. `k` = 1000.

## 72-thread server

2 x Intel Xeon Gold 6154 (72 threads), Linux 7.0, a rented container.

| test | finalwisp | epoxy-server | wisp-server-python | wisp-js | wispurr |
|---|---|---|---|---|---|
| upload, 1 stream (MiB/s) | 2,695 | 1,246 | 400 | 433 | 0 |
| upload, 10 conns x 10 streams (MiB/s) | 12,672 | 8,441 | 3,190 | 406 | 8,545 |
| download, 10 conns x 10 streams (MiB/s) | 21,717 | 5,634 | 6,593 | 589 | 0 (30 errors) |
| echo, 1 stream (MiB/s each way) | 1,877 | 362 | 274 | 214 | 0 |
| echo, 10 conns x 10 streams (MiB/s each way) | 6,876 | 3,259 | 2,303 | 239 | 4,522 |
| request/response, 1 stream (req/s) | 24k | 23k | 9.2k | 13k | 3.7k |
| request/response, 10 conns x 10 streams (req/s) | 443k | 318k | 197k | 29k | 217k |
| new stream per request, 10 conns x 10 streams (streams/s) | 124k | 21k | 17k | 8.0k | 24k |
| RSS after the case, largest (MiB) | 96 | 1,324 | 2,127 | 499 | 5,204 |

Peak memory (VmHWM, MiB): finalwisp 300, epoxy-server 1,568, wisp-server-python 2,128, wisp-js 690, wispurr 6,900.

## 2-core VPS A

AMD EPYC Milan, 2 cores, 3.8 GB RAM, Linux 6.8, the distribution's default TCP settings.

On these 3.8 GB machines the 10 x 10 bulk tests hit kernel TCP memory pressure, so the bulk tests were run again at
10 connections x 2 streams. Those are the rows below. Cells marked **(P n/3)** were under pressure in n of the 3 runs:
they are invalid and left out of the README.

| case | finalwisp | epoxy-server | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|
| upload, 1 stream (MiB/s) | 1,766 | 558 | 0.0 | 301 | 274 |
| upload, 10 conns x 2 streams (MiB/s) | 1,796 | 861 | 800 | 296 | 425 |
| download, 10 conns x 2 streams (MiB/s) | 2,480 | 709 | 220 | 453 | 672 |
| echo, 1 stream (MiB/s each way) | 933 | 272 | 0.0 (1 err) | 190 | 194 |
| echo, 10 conns x 2 streams (MiB/s each way) | 991 | 336 | 174 (1 run failed) | 194 | 284 |
| request/response, 1 stream (req/s) | 10,730 | 9,243 | 5,321 | 5,939 | 5,367 |
| request/response, 10 conns x 10 streams (req/s) | 60,422 | 43,663 | 14,959 | 15,195 | 18,330 |
| new stream per request, 10 conns x 10 streams (streams/s) | 13,649 | 7,853 | 9.2 | 4,098 | 4,732 |
| RSS after the case, largest (MiB, median) | 4.2 | 153 | 3,395 | 1,433 | 162 |
| peak RSS, VmHWM (MiB, max) | 204 | 180 | 3,406 | 1,544 | 168 |

How many times faster finalwisp is (finalwisp ÷ other; above 1 = finalwisp is faster). For the two memory rows the
ratio is other ÷ finalwisp: how many times less memory finalwisp used; below 1 = finalwisp used more.

| case | vs best other | vs epoxy-server | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|
| upload, 1 stream | 3.16 | 3.16 | ∞ | 5.87 | 6.46 |
| upload, 10 conns x 2 streams | 2.09 | 2.09 | 2.24 | 6.07 | 4.23 |
| download, 10 conns x 2 streams | 3.50 | 3.50 | 11.27 | 5.48 | 3.69 |
| echo, 1 stream | 3.43 | 3.43 | ∞ | 4.92 | 4.81 |
| echo, 10 conns x 2 streams | 2.95 | 2.95 | 5.68 | 5.11 | 3.48 |
| request/response, 1 stream | 1.16 | 1.16 | 2.02 | 1.81 | 2.00 |
| request/response, 10 conns x 10 streams | 1.38 | 1.38 | 4.04 | 3.98 | 3.30 |
| new stream per request, 10 conns x 10 streams | 1.74 | 1.74 | 1483.61 | 3.33 | 2.88 |
| RSS after the case, largest | 36.36 | 36.36 | 808.38 | 341.21 | 38.45 |
| peak RSS, VmHWM | 0.82 | 0.88 | 16.66 | 7.55 | 0.82 |

The dropped 10 x 10 bulk rows, for completeness (replaced by the 10 x 2 rows above):

| case | finalwisp | epoxy-server | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|
| upload, 10 conns x 10 streams (MiB/s) | 1,433 (P 1/3) | 775 | 1,024 | 303 | 393 |
| download, 10 conns x 10 streams (MiB/s) | 2,470 | 666 (P 3/3) | 47.2 (P 3/3) | 181 (P 3/3) | 770 (P 3/3) |
| echo, 10 conns x 10 streams (MiB/s each way) | 159 (P 3/3) | 325 | 120 | 182 | 254 |

| case | vs best other | vs epoxy-server | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|
| upload, 10 conns x 10 streams | 1.40 | 1.85 | 1.40 | 4.73 | 3.65 |
| download, 10 conns x 10 streams | 3.21 | 3.71 | 52.38 | 13.62 | 3.21 |
| echo, 10 conns x 10 streams | 0.49 | 0.49 | 1.33 | 0.87 | 0.63 |

## 2-core VPS B

AMD EPYC Rome, 2 cores, 3.8 GB RAM, Linux 6.8, with larger TCP buffers and BBR congestion control.

The larger TCP buffers use 2 to 4 times as much kernel TCP memory per test, so more bulk cells hit pressure here than on
VPS A. **(P n/3)** marks the same as above.

| case | finalwisp | epoxy-server | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|
| upload, 1 stream (MiB/s) | 1,293 | 807 | 0.0 | 308 | 295 |
| upload, 10 conns x 2 streams (MiB/s) | 1,423 | 939 | 1,167 (P 3/3) | 274 | 439 |
| download, 10 conns x 2 streams (MiB/s) | 1,974 (P 3/3) | 702 (P 3/3) | 1,283 (P 3/3) | 446 (P 3/3) | 683 (P 3/3) |
| echo, 1 stream (MiB/s each way) | 744 | 361 | 0.0 (1 err) | 191 | 204 |
| echo, 10 conns x 2 streams (MiB/s each way) | 818 (P 3/3) | 441 (P 2/3) | 610 (P 3/3) | 188 | 295 |
| request/response, 1 stream (req/s) | 15,755 | 13,854 | 5,104 | 6,606 | 6,355 |
| request/response, 10 conns x 10 streams (req/s) | 95,403 | 67,309 | 38,476 | 16,484 | 20,502 |
| new stream per request, 10 conns x 10 streams (streams/s) | 18,212 | 9,909 | 7,091 | 4,570 | 4,678 |
| RSS after the case, largest (MiB, median) | 4.1 | 176 | 650 | 1,907 | 154 |
| peak RSS, VmHWM (MiB, max) | 231 | 234 | 662 | 2,036 | 156 |

How many times faster finalwisp is (memory rows: how many times less memory it used):

| case | vs best other | vs epoxy-server | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|
| upload, 1 stream | 1.60 | 1.60 | ∞ | 4.19 | 4.37 |
| upload, 10 conns x 2 streams | 1.22 | 1.52 | 1.22 | 5.19 | 3.24 |
| download, 10 conns x 2 streams | 1.54 | 2.81 | 1.54 | 4.43 | 2.89 |
| echo, 1 stream | 2.06 | 2.06 | ∞ | 3.89 | 3.64 |
| echo, 10 conns x 2 streams | 1.34 | 1.85 | 1.34 | 4.35 | 2.77 |
| request/response, 1 stream | 1.14 | 1.14 | 3.09 | 2.39 | 2.48 |
| request/response, 10 conns x 10 streams | 1.42 | 1.42 | 2.48 | 5.79 | 4.65 |
| new stream per request, 10 conns x 10 streams | 1.84 | 1.84 | 2.57 | 3.99 | 3.89 |
| RSS after the case, largest | 37.63 | 42.85 | 158.49 | 465.07 | 37.63 |
| peak RSS, VmHWM | 0.68 | 1.01 | 2.87 | 8.82 | 0.68 |

The dropped 10 x 10 bulk rows (replaced by the 10 x 2 rows above):

| case | finalwisp | epoxy-server | wispurr | wisp-js | wisp-server-python |
|---|---|---|---|---|---|
| upload, 10 conns x 10 streams (MiB/s) | 1,314 (P 2/3) | 856 | 1,022 (P 3/3) | 278 | 370 |
| download, 10 conns x 10 streams (MiB/s) | 1,697 (P 3/3) | 664 (P 3/3) | 640 (2 err) (P 2/3) | 221 (P 3/3) | 541 (P 3/3) |
| echo, 10 conns x 10 streams (MiB/s each way) | 452 (P 3/3) | 416 | 6.3 (11 err) (P 3/3) | 170 | 258 |

| case | vs best other | vs epoxy-server | vs wispurr | vs wisp-js | vs wisp-server-python |
|---|---|---|---|---|---|
| upload, 10 conns x 10 streams | 1.29 | 1.53 | 1.29 | 4.72 | 3.55 |
| download, 10 conns x 10 streams | 2.56 | 2.56 | 2.65 | 7.67 | 3.14 |
| echo, 10 conns x 10 streams | 1.09 | 1.09 | 71.39 | 2.66 | 1.75 |

## TCP memory pressure

Linux has one limit for the TCP memory of all sockets on a host (`net.ipv4.tcp_mem`). When the sockets get close to
it, the kernel enters "memory pressure" and shrinks socket buffers. Throughput then swings widely, for every server. A
bulk cell during which the kernel entered pressure is therefore invalid. [Benchmarking](benchmarking.md#tcp-memory-pressure) shows how to check for it.

The echo 10 x 10 cell on VPS A (dropped) is a case where finalwisp itself causes the pressure: finalwisp 154 vs
epoxy-server 332 MiB/s, over 8 paired runs. finalwisp takes uploads faster than the clients read the echoed data, so
the data waits in kernel socket buffers, and under pressure the kernel shrinks the clients' send buffers.
epoxy-server reaches its CPU limit earlier and stays out of pressure. When every server is under pressure (memory held
by another program), finalwisp is 3.3x epoxy-server; at 10 x 5 streams it is 2.5x. A fix is planned: stop refilling
a stream's upload credit while its replies wait on the client. Today `--tcpmem-adapt` helps this case (3.9x), but it
costs about 10 % at 10 x 5.

## Notes

- **wispurr:** it moved no data in the single-stream upload and echo tests. It was killed by the kernel's
  out-of-memory killer in echo 10 x 10 on VPS B (at 3.3-3.4 GB) and once on VPS A, and after that growth reached 9
  streams/s in VPS A's churn test; the README leaves that churn cell out. The tested version has known data-loss and
  flow-control bugs.
- **Peak memory:** on the 2-core VPSes finalwisp's peak (204-231 MiB) was about epoxy-server's (180-234) and 21-48 %
  above wisp-server-python's (156-168). On the big server it was the lowest, 2 to 23 times below the others.
- **Loopback is not the internet:** over a real network the link usually limits throughput long before the server
  does.
