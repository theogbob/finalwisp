# wispurr baseline (formerly "mrrowisp")
Source: https://github.com/sylvieisnton/wispurr. Benches use the LATEST upstream commit (owner, 2026-11-15): check
`git -C ref/wispurr fetch` before a bench round and rebuild when upstream moved.
- `wispurr` = **0e0fdb1** (2026-11-14, "fix: fix random crashing"; LICENSE now AGPL-3.0 text from 36de32e). md5 f6ecb5f1 (go 1.26.8).
- `wispurr-2afbad2` = 2afbad2 (2026-10-19), the build of every result before 2026-11-15. Its Go core `wisp/` is
  byte-identical to the last mrrowisp module (soap-phia/mrrowisp v0.0.0-20260916003350-55bb4b286ddf); main.go only adds --host. md5 475a4d46.
Build: cd ref/wispurr && git checkout COMMIT && go build -o ../../baselines/wispurr/wispurr-COMMIT main.go   (go 1.26.8);
`wispurr` is a copy of the newest one. Binaries are not in git.
Config (same for both commits; upstream speed.config.json unchanged by 0e0fdb1): author's speed.config.json (from the wispurr
repository; not shipped in the public tree, wispurr is AGPL-3.0: copy it here as baselines/wispurr/speed.config.json)
+ allowDirectIP/allowPrivateIPs/allowLoopbackIPs=true (bench targets 127.0.0.1), allowUDP=false, logLevel=error.
WispMark variant ("wispmark cfg"): same, with WispMark's tcpBufferSize=131072, bufferRemainingLength=256.

## Bugs found in 2afbad2 (40.01 compat test fails 4/20)
1. Data loss: wisp/wisp-stream.go:274 takes pendingData before connReadyDone is set (:392, signalConnReady).
   DATA arriving in that window (wisp-connection.go:308-320) is appended to a fresh pendingData that is never flushed.
   Symptom: small-packet streams sent right after CONNECT lose bytes (958/1000, 164000/200000).
2. Credit stall: pre-connect DATA (pending path, wisp-connection.go:308-322) returns before bufferRemaining--,
   so server and client credit counts diverge and the server never sends the next CONTINUE (upload stops at 0 MiB/s
   with 256 credits; 32768 credits mostly hides it).
3. wisp-js client asks for v2 (Sec-WebSocket-Protocol: wisp-v2) but the connection reports v1.

## 0e0fdb1 vs 2afbad2 (2026-11-15, `wst compat --server`, report mode, loopback, no timing;
raw data (not published))
What the diff changes: flushPending() writes the pending DATA under pendingMutex before connReady (bug 1); the credit
count is taken for every TCP DATA, also on the pending path, with an atomic counter (bug 2); full write and ingress
queues now wait (sync.Cond, 8 MiB hard cap) instead of closing the connection / stream (reason throttled).
| step | 2afbad2 | 0e0fdb1 |
|---|---|---|
| wispjs (v1 + v2 data integrity) | FAIL, 6 checks lose bytes (944/1000, 184000/200000, 49650/50000), 80 s | **PASS**, 1 s |
| wispjs-udp, udp | FAIL (allowUDP=false in the bench config: expected) | same |
| adversarial | 5 PASS, then reset at line 141 (ping flood), 2 s | 19 PASS, 2 FAIL (HTTP/1.0 upgrade not refused with 400; WS Close during a throttled bulk download 5/5), then reset at line 797 (held connections), 304 s |
| epoxy-udp-burst | PASS (server alive) | PASS (server alive) |
Not checked yet: bug 2 directly (an upload with 256 credits, the wispurr-wispmark entry), bug 3, memory under load
(2afbad2 was OOM-killed in the showdown, docs/benchmarks.md), speed. The published benchmark numbers are for 2afbad2.
