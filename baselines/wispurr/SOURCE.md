# wispurr baseline (formerly "mrrowisp")
Source: https://github.com/sylvieisnton/wispurr @ 2afbad2 (2026-10-19). Go core `wisp/` is byte-identical to the
last mrrowisp module (soap-phia/mrrowisp v0.0.0-20260916003350-55bb4b286ddf); main.go only adds --host.
Build: cd ref/wispurr && go build -o ../../baselines/wispurr/wispurr main.go   (go 1.26.8)
Config: author's speed.config.json (from the wispurr repository; not shipped in the public tree, wispurr is AGPL-3.0:
copy it here as baselines/wispurr/speed.config.json) + allowDirectIP/allowPrivateIPs/allowLoopbackIPs=true (bench targets 127.0.0.1), allowUDP=false, logLevel=error.
WispMark variant ("wispmark cfg"): same, with WispMark's tcpBufferSize=131072, bufferRemainingLength=256.

## Bugs found (present in 2afbad2), 40.01 compat test fails 4/20
1. Data loss: wisp/wisp-stream.go:274 takes pendingData before connReadyDone is set (:392, signalConnReady).
   DATA arriving in that window (wisp-connection.go:308-320) is appended to a fresh pendingData that is never flushed.
   Symptom: small-packet streams sent right after CONNECT lose bytes (958/1000, 164000/200000).
2. Credit stall: pre-connect DATA (pending path, wisp-connection.go:308-322) returns before bufferRemaining--,
   so server and client credit counts diverge and the server never sends the next CONTINUE (upload stops at 0 MiB/s
   with 256 credits; 32768 credits mostly hides it).
3. wisp-js client asks for v2 (Sec-WebSocket-Protocol: wisp-v2) but the connection reports v1.
