# bench/e2e: real Wisp clients end to end (80.04 layer L8)

What a user feels: real client libraries, our own HTTPS target on the same host, one Wisp server per arm in between.
The question this layer answers: in which workloads does the server change the maintainer-visible time at all, and where is
the client stack the bottleneck?

## Files
- `target.mjs`: the target fixture, 127.0.0.1 only. BASE+0..3 TLS origins with h2 + http/1.1 (ALPN), BASE+4..7 TLS
  origins http/1.1 only, BASE+8 plain HTTP, BASE+9 TCP echo, BASE+20..59 forty more http/1.1 TLS origins. Routes
  `/o/<bytes>` (exact body) and `/bulk/<bytes>` (streamed). Certificates: `mkcerts.sh DIR` (a throwaway CA + leaf).
- `client.mjs`: one Node process per client and workload; prints one JSON line per workload.
- `e2e.py`: the paired driver (rounds, a fresh server per arm and round, rotated slot order, per-run CPU, summary.json
  per the 80.04 result contract, TABLE.md, `--table --check`).
- `report_tables.py`: report tables from session directories (`--vis`, `--faults`, `--close`, `--size`; `--check FILE`).
- `pcapclose.py`: wire timing of the closefail runs of an `e2e.py --pcap-round` round (diagnostic).
- `browser/`: the closefail workloads in headless Chromium / Firefox / WebKit (Playwright; clients `chromium-epoxy` etc.).

## Clients (`--clients`)
| client | stack | notes |
|---|---|---|
| `epoxy` / `epoxy-v2` | epoxy-tls 2.1.20-1 WASM (wisp-mux + rustls + hyper; h2 by ALPN), Wisp v1 / v2 | what epoxy-transport 3.0.2 (Scramjet's default) runs; WebSocket = Node's built-in (undici), not Chromium's |
| `wispjs` / `wispjs-v2` | wisp-js 0.5.3 mux (ws package) + Node's native TLS and HTTP (h2 sessions, keep-alive agent with 6 per origin) | separates Wisp-mux cost from TLS-in-WASM cost |
| `direct` | the same Node TLS/HTTP stack straight to the target | no Wisp server in the path: the floor of the client stack, once per round |
| `libcurl` | libcurl.js 0.7.5 (bundled) over its own Wisp client, plain HTTP only | it has no CA option, so no HTTPS to our own CA (the WASM is not patched) |

## Workloads (`--workloads`)
| workload | what | key metrics |
|---|---|---|
| `page` | HTML (40 KB) then 79 objects (1 KB to 500 KB, 2.44 MB in all, seeded) over 4 h2 origins; one cold load (new Wisp connection + TLS) then 5 warm loads | page_cold_ms, page_warm_ms, page_req_p50/p99_ms, page_ttfb_p50_ms |
| `page1` | the same page over 4 http/1.1 origins, 6 connections per origin (as a browser) | page1_cold_ms, page1_warm_ms |
| `bulk` | one 64 MiB HTTPS download | bulk_mib_s, bulk_ttfb_ms |
| `rr` | 200 sequential 64 B GETs on one warm keep-alive connection | rr_p50_ms, rr_p99_ms |
| `tls` | 40 GETs, each to a new origin: Wisp stream open + target connect + TLS handshake + request | tls_p50_ms, tls_p99_ms |
| `closefail` | 40 GETs with `Connection: close` (64 B / 20 KB): share of responses lost or cut short. `closefail3` adds 1 MiB bodies, `closefail3busy` a busy client main thread, `closefailslow5` / `slow20` a consumer that sleeps per chunk | close_lost_pct |
| `churn` | 200 raw TCP streams to the echo, 10 at a time (wisp-js and direct only: epoxy cannot close raw streams) | churn_per_s, churn_p99_ms |
| `busy` | the page loaded while a bulk download runs on the same Wisp connection, then 10 small fetches; the same without the bulk first | busy_page_ms, busy_small_p50_ms, busy_page_slowdown, busy_bulk_mib_s_page |
Every row also carries client_cpu_ms and server_cpu_ms (schedstat of every thread of the client process / the server's
process group), and a note with the CPU share per wall second of the client's main thread, the server and the target.
A client main thread at 0.85 or more is saturated: server effects can hide behind it (a tie there does not prove the
server is invisible; the seeded-fault runs say how much each workload can see).

## Run
```
# functional check (short, any machine):
python3 bench/e2e/e2e.py OUT --arm a=fw:PATH --arm b=NAME --rounds 2 --quick     # NAME: a server of bench/servers.json
# a timed comparison (a quiet machine). Per-round exclusion of foreign activity needs E2E_BOX=NAME (it turns flagging
# on, and is the box name OVERLAP windows match) and a run inside a transient systemd unit (its cgroup is "ours"):
systemd-run --unit e2e-ab --collect --working-directory=$PWD -E E2E_BOX=NAME -p MemoryMax=1536M \
  python3 bench/e2e/e2e.py OUT --arm a=fw:PATH --arm b=NAME --clients epoxy,wispjs,direct --workloads page,rr,busy --rounds 16
python3 bench/e2e/e2e.py OUT --table --check     # the numbers of TABLE.md / summary.json again from raw.jsonl
```
Setup once: `cd bench/e2e && npm ci` (Node 24). Ports: 16100-16199 (server base+1, target base+10..+69).
Optional: `E2E_OVERLAP=FILE` (JSONL windows {box, start, end, who} in which someone touched the machine outside the run)
and `E2E_OVERLAP_SELF=WHO` (your own windows, skipped): rounds that overlap a foreign window are excluded at table time.

## Blind spots
- Not a browser (except the `browser/` closefail clients, counts only): Node's WebSocket and event loop, not Chromium +
  Scramjet (no rewriting, no service worker, no renderer).
- Loopback: no RTT, no bandwidth limit. A server's latency shows only as CPU / scheduling time; the 10 ms / 100 Mbit
  link (netns) is not used yet.
- Small machines (2 vCPU): client, server and target share 2 cores; read the CPU shares in the notes.
- libcurl.js: plain HTTP only. epoxy raw streams: no churn. epoxy and wisp-js clients default to Wisp v1 (as the
  transports do); v2 only with the -v2 clients.
