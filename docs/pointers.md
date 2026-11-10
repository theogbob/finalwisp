# Pointer index

Comments in the code cite design-note ids of the form `NN.NN`. The notes are internal and are not part of this
repository; the comments carry their reasoning inline. This index gives the topic of every id that the code cites.

| id | topic |
|---|---|
| 10.01 | Wisp protocol: what it is |
| 20.01 | the server itself |
| 20.02 | module ids from the 20.01 SPEC: ws.rs (RFC 6455 framing), http.rs (upgrade), net.rs (sockets, SSRF, DNS pool), worker.rs |
| 20.03 | module ids from the 20.01 SPEC: ws.rs (RFC 6455 framing), http.rs (upgrade), net.rs (sockets, SSRF, DNS pool), worker.rs |
| 20.04 | module ids from the 20.01 SPEC: ws.rs (RFC 6455 framing), http.rs (upgrade), net.rs (sockets, SSRF, DNS pool), worker.rs |
| 20.05 | module ids from the 20.01 SPEC: ws.rs (RFC 6455 framing), http.rs (upgrade), net.rs (sockets, SSRF, DNS pool), worker.rs |
| 20.06 | finalwisp performance findings |
| 20.08 | splice download path |
| 20.09 | upload batching |
| 20.10 | accept balancing |
| 20.11 | idle memory: rbuf grows on demand, 2 s idle sweep |
| 20.13 | built-in TLS via kTLS |
| 20.14 | happy eyeballs; TCP Fast Open to targets |
| 20.15 | happy eyeballs; TCP Fast Open to targets |
| 20.16 | UDP streams |
| 20.17 | TLS extras: SNI, SIGHUP reload, close_notify, KeyUpdate, cipher order |
| 20.18 | Wisp v2 extensions: password / key auth, MOTD |
| 20.19 | Performance levers, perf-reviewer A research |
| 20.21 | adaptive TCP_NOTSENT_LOWAT for kTLS clients |
| 20.22 | two-lane output default-on |
| 20.23 | negative DNS cache; Happy Eyeballs family memory |
| 20.24 | negative DNS cache; Happy Eyeballs family memory |
| 20.25 | copy-path stall at a TCP urgent mark |
| 20.26 | Memory budget: slow down instead of being OOM-killed |
| 20.27 | Upload backlog credit: echo memory and the absolute-credit loop |
| 20.30 | Upload credit v2: acceptance bar, interim, design, spike |
| 20.31 | Host TCP memory adaptation (B3): premise and design |
| 20.33 | Upload batching across interleaved streams |
| 30.01 | wbench load generator |
| 30.02 | bench/showdown.py |
| 30.03 | bench/wispmark.py |
| 30.06 | idle RSS probe |
| 30.07 | VPS netns test network, connect latency, TFO echo target |
| 30.08 | TLS deployments compared |
| 30.09 | idle splice-pipe reclaim |
| 30.10 | Wisp test suite |
| 30.11 | Soak test: base-1.1, 12 h of mixed traffic on VPS3 |
| 30.13 | bench audit (run log), not published |
| 30.14 | Pre-soak of the release candidate: 12 h |
| 30.15 | Cycle test: leak or retention? |
| 30.16 | RC battle soak: plan |
| 30.17 | RC1 light lane (VPS3): LIGHT 1 cycle test + LIGHT 2 12 h soak |
| 30.18 | RC1 heavy soak (run log), not published |
| 30.19 | Benchmarks: finalwisp vs other Wisp servers |
| 40.01 | Deployment |
| 40.02 | CI and the reference build |
| 40.03 | CLI reference |
| 40.04 | tls_adversarial.py |
| 40.05 | tls_nonce.py |
| 40.06 | udp.py; wispjs_udp.mjs |
| 40.07 | udp.py; wispjs_udp.mjs |
| 40.08 | epoxy_udp_burst.py |
| 40.09 | tls_extras.py; membudget.py; v2ext.py |
| 40.10 | tls_extras.py; membudget.py; v2ext.py |
| 40.11 | tls_extras.py; membudget.py; v2ext.py |
| 40.12 | bigframe_stress.py |
| 40.13 | stderr_pipe.py |
| 40.14 | keepalive tests |
| 50.02 | wss download zero reps under host TCP pressure |
| 60.01 | Roadmap: stable fast base, then production features |
| 60.02 | Feature designs: Phase C production features C1-C10 |
| 60.04 | finalwisp base-1: code-quality review |
| 60.05 | Full review of base-1 |
| 60.06 | base-1.1 release notes |
| 60.09 | Full review of the base-2 candidate |
| 60.12 | Post-base-2 design review (2026-10-27): backlog priorities |
| 60.13 | Decision: credit v2 + B3 on by default |
| 60.14 | base-3 release notes |
| 60.15 | base-4 triage: every open item that touches the base |
| 60.16 | base-4 tidy review and flag inventory |
| 60.17 | base-4 fixes: notes |
| 60.18 | base-4 decisions |
| 60.20 | Part 2 plan: order of the C features |
| 60.21 | C1 destination policy: as-built spec and decisions |
| 60.22 | C2 real client IP + C3b per-IP limits: as-built spec and decisions |
| 60.24 | C4 step 1 connection log: as built |
| 60.25 | Hot-path metering: C5 rx_bytes, C4 UDP counters, C10b upload caps |
| 60.26 | C10a bandwidth caps by kernel TCP pacing: research and pre-spec |
| 60.27 | C6 upstream proxy research (kept on a research branch) |
| 60.28 | C7 unix listener, C5 endpoint and PROXY protocol research (kept on a research branch) |
| 60.29 | C5 Prometheus endpoint: as built |
| 60.30 | C10a bandwidth caps by kernel TCP pacing: as built |
| 60.31 | C7 unix socket listener: as built |
| 60.32 | C6 upstream proxy: as built |
| 60.33 | base-6 release notes |
| 60.34 | PROXY protocol v1/v2: as built |
| 60.35 | C4 step 2 stream log (--log-streams) + C4 UDP counters: as built |
| 60.37 | public release scrub: what the public tree leaves out |
| 60.39 | 1a per-destination connect limits (wispurr maxConnectsPerDest*): design, as built, numbers |
| 60.40 | 1e --conn-rate-per-ip: per-IP rate of new connections |
| 60.41 | DNS cache expiry in the idle sweep + the --dns-threads default |
| 60.42 | --credit-pace: no upload credit while the stream's own download waits on the client |
| 60.43 | Long-link download collapse: test artifact or real? |
| 60.44 | Host TCP memory: who holds it, and what the server can lower |
| 60.45 | per-IP table clock: u64 ms |
| 60.46 | Adaptive splice length |
| 60.47 | --park-rcvlock: lock, don't shrink, the receive buffer of a parked download-only target |
| 60.50 | v1.2 combined measurement: v1.1.1 against the splice and receive-buffer changes |
| 60.51 | --adaptive-splice for far clients only |
| 70.01 | Fuzzing base-1.1 network parsers |
| 70.02 | dead-peer detection |
| 70.03 | glibc mmap threshold 16 KiB + M_MMAP_MAX |
| 70.04 | SSRF filter: IPv6 forms that carry an IPv4 address |
| 70.05 | sampler log lines through a bounded queue |
| 70.06 | peer_gone latch |
| 70.07 | RST paths through reset_client |
| 70.08 | level-2 drip: a stall is < STALL_MIN_BYTES per sweep |
| 70.09 | Own DNS resolver (C9, `--dns-own`): design |
| 70.10 | RFC 8305 resolution delay with late updates |
| 70.11 | Per-worker block cache |
| 70.12 | Static glibc build (crt-static) check |
| 70.13 | TCP keepalive on target sockets |
| 70.14 | Level-1 drained-lane flush fix |
| 70.20 | obuf / buffer growth under glibc: the "mmap churn" weak spot re-measured |
| 70.23 | malloc_trim at the idle sweep |
| 70.24 | malloc_trim on a low-priority trim thread |
| 70.25 | Own allocator for the big per-connection buffers ("option 2"): design spec |
| 70.27 | base-4 RC1 battle tests: long fuzz campaign + real-browser suite |
| 70.28 | base-6 fuzz campaign: the code added since base-4 |
| 80.01 | ops hardening round |
