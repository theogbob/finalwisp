# bench/browser: real-user simulator (wst browser)

Headless Chromium (Playwright) runs the Scramjet web proxy. Scramjet's transport (epoxy-transport 3.0.1 or
libcurl-transport 2.0.5) talks Wisp to the server under test. Both transports default to Wisp v1;
`--transport epoxy-v2` is epoxy-transport with `wisp_v2: true` (the only way a browser client exercises v2 here). The scenario loads real sites, does a short user
session (open, scroll, click a link, back), opens a page WebSocket, and downloads files with `fetch()` inside the
proxied page. Every case runs in a fresh browser context (cold service worker, new Wisp connection).

Files: `browser.py` (driver, `main(argv)` for `wst browser`), `scenario.mjs` (Playwright runner + page/mirror
HTTP servers), `page/` (host page + service worker), `sites.json` (case lists per mode), `mirror.py` (timing-mode
mirror builder).

## Setup (once)

```
cd bench/browser && npm i                      # playwright 1.64.1
npx playwright install chromium                # bundled Chromium (PLAYWRIGHT_BROWSERS_PATH honoured), no sudo
# Scramjet build (default SCRAMJET_DIR=<repo root>/scramjet, gitignored; tested at commit b14b709a):
git clone https://github.com/MercuryWorkshop/scramjet && cd scramjet && npx pnpm@10.12.1 install
cargo install --git https://github.com/r58Playz/wasm-snip --root ../tools   # the crates.io wasm-snip 0.4.0 fails on anyref
(cd packages/core && PATH=../../../tools/bin:$PATH RELEASE=1 npx pnpm@10.12.1 rewriter:build)  # needs nightly + wasm-bindgen 0.2.105 + wasm-opt
CI=1 npx pnpm@10.12.1 exec rspack build --mode production   # the types step fails; the bundles are fine
```

## Run

```
# compat (real internet; pass/fail matters, timing informational). Exit 1 on any failure.
python3 bench/browser/browser.py --server fw:BASE_BIN --server epoxy --server wisp-js \
    --transport epoxy --transport epoxy-v2 --transport libcurl --reps 2
# timing (local mirror; ask for the machine lock first). Rotated server order, medians.
python3 bench/browser/mirror.py                 # once: saved pages + synthetic pages + 100 MiB file
python3 bench/browser/browser.py --mode timing --reps 6 --server fw-a=fw:PATH --server fw-b=fw:PATH \\
    --server epoxy --server wisp-js [--mirror-delay-ms 20]      # fw-a/fw-b = A/A pair: the noise floor
```

Wisp over TLS (`--tls`, fw: servers only; validated in compat mode): browser.py makes a self-signed P-256 pair for 127.0.0.1 in
the run's scratch dir, starts finalwisp with `--tls-cert/--tls-key` (wss://, kTLS) and launches Chromium with
`--ignore-certificate-errors-spki-list` for that key only. Not with `--trace` (its pipeline split assumes plaintext).
```
python3 bench/browser/browser.py --tls --server fw-rc=fw:PATH --transport epoxy --transport epoxy-v2 --transport libcurl --reps 2
```

Ports: page `B`, mirror `B+1`, Wisp `B+10` (`--port-base`, default 8400). finalwisp runs with no `--allow-*`
flags in compat mode; timing mode adds `--allow-loopback` (the mirror is on 127.0.0.1). Output:
`bench/results/browser-<stamp>/results.json` (schema `wispsuite/1`, kind `browser`), `results.md`, and each
server's stderr log in the same directory.

## What is measured

- page: iframe load event time (`load_ms`), proxied requests, failed requests, 5xx, bytes received by the renderer,
  text length + title of the loaded document (a page with less than `min_text` characters fails).
- session: sum of open + click + back navigation times; per-step times in `steps`.
- websocket: `wss://echo.websocket.org`, 20 messages echoed; time to the last echo.
- download: `fetch()` streamed to the end inside the proxied page; `mib_s`, `ttfb_ms`, exact byte count check.
- timing mode is strict: any failed request, 5xx, request that leaves the mirror, or (busy) a background download
  that ended before the page load fails the rep. The mirror runs as its own node process and is read once first
  (warm page cache). Use a rep count that is a multiple of the server count (rotation).
- Compat timings are informational: Chromium + wasm TLS + Scramjet rewriting are CPU-bound, so other load on the
  machine moves them by 2x (seen during a parallel stress test). Compare servers only within one run.

Known upstream noise (same on every server): tracker 4xx/5xx and aborted requests on news sites; YouTube renders
blank under this Scramjet build (text check off); `unrewriteurl: unexpected url tel:` console errors on apple.com.

## Busy-case investigation (`--trace`)

`--trace` adds to the busy and download cases (raw data in `<out dir>/traces/*.json`, summary in `results[].trace`
and a second table in `results.md`):
- a tap on the Wisp WebSocket in the host page: every message `[JS dispatch time, Wisp type, stream id, bytes]`,
  every client frame sent (CONNECT/DATA/CLOSE). The bulk stream = the stream with the most DATA bytes.
- CDP: every proxied request (start, response headers, first/last body chunk, end) and every binary WS frame
  (CDP time). Same message in both = JS dispatch lag.
- CPU over the measured page load (busy) or the whole download: every thread of this run's Chromium
  (by process type + thread name) and the server process, from /proc (10 ms ticks); main-thread busy fraction from
  CDP Performance.getMetrics.
- `node bench/browser/scenario.mjs --selftest` checks the trace summary on synthetic data (no browser).

A/B of finalwisp flags (no server code change), A/A pair + wisp-js as reference:
```
FW=BASE_BIN
python3 bench/browser/browser.py --mode timing --trace --reps 12 --sites m-busy,m-big100,m-hn \
  --server fw-def=fw:$FW --server fw-def2=fw:$FW --server "fw-noprio=fw:$FW --no-prio" \
  --server "fw-low16k=fw:$FW --notsent-lowat 16384" --server "fw-low64k=fw:$FW --notsent-lowat 65536" \
  --server wisp-js --transport epoxy --transport libcurl
```

## Splice frame cap A/B (`ab_splice.py`)

```
python3 bench/browser/ab_splice.py --base PATH/base-1.1 --new PATH/new-build   # needs the lock, ~25 min
python3 bench/browser/ab_splice.py --analyze OUT_DIR/results.json
```
base-a/base-b (A/A), base --no-splice, new; epoxy + libcurl; m-busy, m-big100, 4 plain pages; 8 rotated reps,
--trace; paired sign tests per metric in `ab.md`.

## Leak check and known client issues (2026-10-24)
- Every case fails if the browser sends a request or opens a WebSocket to an origin other than the host page (it
  escaped Scramjet and went direct, not through Wisp). Known Scramjet leaks are allowed per site with `allow_leaks`
  regexes in `sites.json`; they are still counted in `leaks` / `leak_urls`.
- A case origin must be an HTML page: Scramjet does not instrument a non-HTML document, so its fetch/WebSocket go direct.
- epoxy and epoxy-v2 hold the last sent WebSocket frame until the next send. `ws-echo` sends one probe and records
  `held_last_frame: true` (see REPORT-s64a-2026-10-24.md).
