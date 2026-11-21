// 80.04 L8 client: real Wisp client libraries against target.mjs through a Wisp server (bench/e2e/README.md).
// usage: node client.mjs --client epoxy|epoxy-v2|wispjs|wispjs-v2|direct|libcurl|{chromium,firefox,webkit}-epoxy[-v2]|{chromium,firefox,webkit}-libcurl --wisp ws://127.0.0.1:P/ --base B
//                        --ca CA.pem --workloads page,bulk,rr,tls,churn,busy [--server-pgid N] [--target-pid N] [--quick]
//                        [--timeout-s S (per workload, 60)] [--wslog (epoxy: per-stream DATA/CLOSE timing in rec.s.streams)]
// One JSON line per workload on stdout: {w, client, ok, error?, wall_ms, cpu: {client_ms, server_ms, target_ms}, m: {metric: value},
// s: {raw samples}}. Every workload opens its own client (a new Wisp connection); nothing is shared between workloads.
// direct = the same Node TLS/HTTP stack straight to the target (no Wisp): the floor of the client stack, no server in the path.
import fs from "node:fs"; import net from "node:net"; import tls from "node:tls"; import https from "node:https";
import http from "node:http"; import http2 from "node:http2"; import { Duplex } from "node:stream";
import path from "node:path"; import { pathToFileURL } from "node:url";

const args = {};
for (let i = 2; i < process.argv.length; i++) {
  const k = process.argv[i];
  if (!k.startsWith("--")) throw new Error(`bad arg ${k}`);
  const name = k.slice(2);
  if (name === "quick" || name === "wslog") { args[name] = true; continue; }
  args[name] = process.argv[++i];
}
const CLIENT = args.client, WISP = args.wisp, BASE = Number(args.base);
const CA = args.ca ? fs.readFileSync(args.ca, "utf8") : null;
const QUICK = !!args.quick;
const TIMEOUT_MS = 1000 * Number(args["timeout-s"] || 60);
const SERVER_PGID = Number(args["server-pgid"] || 0), TARGET_PID = Number(args["target-pid"] || 0);
const H2_ORIGINS = [0, 1, 2, 3].map(i => BASE + i), H1_ORIGINS = [4, 5, 6, 7].map(i => BASE + i);
const PLAIN = BASE + 8, ECHO = BASE + 9, MANY = Array.from({ length: 40 }, (_, i) => BASE + 20 + i);
const now = () => performance.now();
let warns = 0;
console.warn = () => { warns++; };  // wisp-js warns per late packet of a stream it closed: counted (rec.warns), not printed

// --wslog: a tap on the client's WebSocket (epoxy uses the global one = undici; wisp-js uses the ws package: not tapped). It
// is registered in the constructor, so it runs before the client's own message handler, and records every Wisp packet:
// send/recv, type, stream id, payload bytes, time, the CLOSE reason, and two arrival groups:
//   read: a process.nextTick armed at the first packet of a group runs after the socket 'data' callback that delivered it
//         (Node drains ticks and microtasks after each stream read callback; undici parses and dispatches the frames of
//         one chunk synchronously), so packets with the same read id came out of ONE socket read; the client's WASM tasks
//         (woken through microtasks) cannot run between them
//   turn: the same with setImmediate: one event-loop I/O batch (several reads can share a turn)
const EPOXY_PKG = args["epoxy-pkg"] || null;  // e2e.py --epoxy-pkg
const WSLOG = args.wslog ? [] : null;
if (WSLOG && globalThis.WebSocket) {
  const WS = globalThis.WebSocket;
  let turn = 0, armed = false, read = 0, tickArmed = false, wsn = 0;
  globalThis.WebSocket = class extends WS {
    constructor(...a) {
      super(...a);
      const w = this._tapW = ++wsn;  // WebSocket instance: stream ids restart on a reconnect, so streams are keyed by (w, sid)
      this.addEventListener("message", ev => {
        if (!(ev.data instanceof ArrayBuffer) || ev.data.byteLength < 5) return;
        const v = new DataView(ev.data);
        const sameBatch = armed;
        if (!armed) { armed = true; setImmediate(() => { armed = false; turn++; }); }
        if (!tickArmed) { tickArmed = true; process.nextTick(() => { tickArmed = false; read++; }); }
        const type = v.getUint8(0);
        WSLOG.push({ d: "r", w, t: now(), type, sid: v.getUint32(1, true), n: ev.data.byteLength - 5, same: sameBatch, turn, read,
                     reason: type === 4 && ev.data.byteLength >= 6 ? v.getUint8(5) : null });
      });
    }
    send(x) {
      try { const b = x instanceof ArrayBuffer ? new Uint8Array(x) : new Uint8Array(x.buffer ?? x, x.byteOffset ?? 0, x.byteLength);
            if (b.byteLength >= 5) WSLOG.push({ d: "s", w: this._tapW, t: now(), type: b[0], sid: (b[1] | b[2] << 8 | b[3] << 16 | b[4] << 24) >>> 0, n: b.byteLength - 5 }); } catch {}
      return super.send(x);
    }
  };
}

// ---------- CPU accounting: /proc/<pid>/task/*/schedstat (ns on CPU per thread; threads that exited are not counted) ----------
function taskNs(pid) {
  let t = 0;
  try {
    for (const tid of fs.readdirSync(`/proc/${pid}/task`)) {
      try { t += Number(fs.readFileSync(`/proc/${pid}/task/${tid}/schedstat`, "utf8").split(" ")[0]); } catch {}
    }
  } catch { return null; }
  return t;
}
function groupNs(pgid) {  // every process of the server's process group (a forking server counts whole)
  if (!pgid) return null;
  let t = 0;
  for (const d of fs.readdirSync("/proc")) {
    if (d.charCodeAt(0) > 57) continue;
    try {
      const s = fs.readFileSync(`/proc/${d}/stat`, "utf8");
      if (Number(s.slice(s.lastIndexOf(")") + 2).split(" ")[2]) === pgid) t += taskNs(d) ?? 0;
    } catch {}
  }
  return t;
}
const mainNs = () => { try { return Number(fs.readFileSync(`/proc/self/task/${process.pid}/schedstat`, "utf8").split(" ")[0]); } catch { return null; } };
// the client's own counters are read right at the wall-clock marks (the /proc scans for the server and the target lie
// outside the measured interval), so client CPU / wall is the share of that interval
function cpuStart() {
  const s = groupNs(SERVER_PGID), t = TARGET_PID ? taskNs(TARGET_PID) : null;
  const u = process.cpuUsage(), cm = mainNs(), t0 = now();
  return { c: (u.user + u.system) / 1000, cm, s, t, t0 };
}
function cpuEnd(a) {
  const t1 = now(), cm = mainNs(), u = process.cpuUsage();
  const b = { c: (u.user + u.system) / 1000, cm, s: groupNs(SERVER_PGID), t: TARGET_PID ? taskNs(TARGET_PID) : null };
  const d = (x, y) => x == null || y == null ? null : Math.round((y - x) / 1e5) / 10;
  return { wall_ms: Math.round(t1 - a.t0), cpu: { client_ms: Math.round(b.c - a.c), client_main_ms: d(a.cm, b.cm), server_ms: d(a.s, b.s), target_ms: d(a.t, b.t) } };
}

// ---------- the page: deterministic manifest (seeded), HTML first, then 79 objects over 4 origins ----------
function mulberry32(a) { return () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a);
  t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function manifest(n = 79) {
  const r = mulberry32(8004), out = [];
  for (let i = 0; i < n; i++) {
    const u = r(), v = r();
    const size = u < 0.5 ? 1000 + Math.floor(v * 7000) : u < 0.8 ? 8000 + Math.floor(v * 32000)
      : u < 0.95 ? 40000 + Math.floor(v * 110000) : 150000 + Math.floor(v * 350000);
    const w = r(), origin = w < 0.4 ? 0 : w < 0.6 ? 1 : w < 0.8 ? 2 : 3;
    out.push({ size, origin, i });
  }
  return out;
}
const PAGE = manifest(), HTML_SIZE = 40000;
const PAGE_BYTES = HTML_SIZE + PAGE.reduce((s, o) => s + o.size, 0);

// ---------- adapters: each gives fetch(url, {close}) -> timing record, tcp(port) -> {send, recv, close}, close() ----------
function wrapSock(s) {  // a Node socket -> {send, recv, close}
  const q = [], waiters = [];
  let ended = false;
  const fin = () => { ended = true; while (waiters.length) waiters.shift()(null); };
  s.on("data", d => { const w = waiters.shift(); if (w) w(d); else q.push(d); });
  s.on("end", fin); s.on("close", fin);
  s.on("error", () => {});
  return { send: d => new Promise(r => s.write(d, r)), recv: () => q.length ? q.shift() : ended ? null : new Promise(r => waiters.push(r)),
           close: () => s.destroy() };
}

async function readBody(reader, t0, onChunk, sleepMs = 0) {
  let bytes = 0, first = null;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (first === null) first = now();
    bytes += value.byteLength;
    if (onChunk) onChunk(bytes);
    if (sleepMs) await new Promise(r => setTimeout(r, sleepMs));  // slow consumer (closefailslow*): backpressure
  }
  return { bytes, first };
}

let epoxyMod = null;
// epoxy-tls converts a stream write with `new Request("", {body})`: a browser resolves "" against the page URL, Node has no
// base URL and throws (epoxy then reports "Invalid payload"). The shim gives "" the base a page would; nothing else changes.
{ const R = globalThis.Request; globalThis.Request = class extends R { constructor(u, o) { super(u === "" ? "http://e2e.invalid/" : u, o); } }; }
async function epoxyClient(v2) {
  if (!epoxyMod) {
    if (EPOXY_PKG) {  // --epoxy-pkg DIR: another epoxy-tls build (same API), loaded as the npm one is
      const js = fs.existsSync(path.join(EPOXY_PKG, "epoxy.mjs")) ? "epoxy.mjs" : "epoxy.js";  // e2e.py's copy: .mjs
      epoxyMod = await import(pathToFileURL(path.join(EPOXY_PKG, js)).href);
      await epoxyMod.default({ module_or_path: fs.readFileSync(path.join(EPOXY_PKG, "epoxy.wasm")) });
    } else {
      epoxyMod = await import("@mercuryworkshop/epoxy-tls/epoxy");
      const wasm = fs.readFileSync(new URL("./node_modules/@mercuryworkshop/epoxy-tls/full/epoxy.wasm", import.meta.url));
      await epoxyMod.default({ module_or_path: wasm });
    }
  }
  const o = new epoxyMod.EpoxyClientOptions();
  o.wisp_v2 = v2; o.pem_files = [CA]; o.user_agent = "finalwisp-e2e";
  const c = new epoxyMod.EpoxyClient(WISP, o);
  return {
    async fetch(url, { close = false, onChunk, signalBox, sleepMs = 0 } = {}) {
      const t0 = now();
      const r = await c.fetch(url, close ? { headers: { Connection: "close" } } : {});
      const th = now();
      const reader = r.body.getReader();
      if (signalBox) signalBox.cancel = () => reader.cancel().catch(() => {});
      const { bytes, first } = await readBody(reader, t0, onChunk, sleepMs);
      return { status: r.status, t0, th, tfirst: first ?? now(), tend: now(), bytes };
    },
    tcp() { throw new Error("n/a for epoxy: its raw streams cannot be closed from the client side (writer close never resolves)"); },
    close() { try { c.free(); } catch {} },
  };
}

let wispjsMod = null;
class WispDuplex extends Duplex {  // a wisp-js TCP stream as a Node Duplex (TLS runs on top of it)
  constructor(conn, host, port) {
    super();
    this.s = conn.create_stream(host, port);
    this.s.onmessage = d => this.push(Buffer.from(d));
    this.s.onclose = r => { this.reason = r; this.push(null); };
  }
  _write(chunk, enc, cb) { try { this.s.send(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)); cb(); } catch (e) { cb(e); } }
  _read() {}
  _final(cb) { cb(); }
  _destroy(err, cb) { if (this.reason === undefined) { this.reason = -1; this.s.onclose = () => {}; try { this.s.close(0x02); } catch {} } cb(err); }
}
async function wispjsConn(version) {
  if (!wispjsMod) wispjsMod = await import("@mercuryworkshop/wisp-js/client");
  return await new Promise((ok, bad) => {
    const c = new wispjsMod.client.ClientConnection(WISP, { wisp_version: version });
    const t = setTimeout(() => bad(new Error("wisp-js connect timeout")), 10000);
    c.onopen = () => { clearTimeout(t); ok(c); };
    c.onclose = () => { clearTimeout(t); bad(new Error("wisp-js ws closed")); };
  });
}

// Node TLS + HTTP over a socket factory: h2 sessions for the h2 origins, a keep-alive agent (6 per origin) for h1
function nodeHttp(rawSocket) {
  const tlsTo = (port, alpn) => tls.connect({ socket: rawSocket(port), host: "127.0.0.1", ca: CA, ALPNProtocols: alpn });
  class A extends https.Agent { createConnection(opts) { return tlsTo(opts.port, ["http/1.1"]); } }
  const keep = new A({ keepAlive: true, maxSockets: 6 }), once = new A({ keepAlive: false, maxSockets: 6 });
  const plainAgent = new (class extends http.Agent { createConnection(opts) { return rawSocket(opts.port); } })({ keepAlive: true, maxSockets: 6 });
  const sessions = new Map();
  const h2 = port => {
    let s = sessions.get(port);
    if (!s || s.closed || s.destroyed) {
      s = http2.connect(`https://127.0.0.1:${port}`, { createConnection: () => tlsTo(port, ["h2"]) });
      s.on("error", () => {});
      sessions.set(port, s);
    }
    return s;
  };
  return {
    fetch(url, { close = false, onChunk, signalBox, sleepMs = 0 } = {}) {
      const u = new URL(url), port = Number(u.port), t0 = now();
      return new Promise((ok, bad) => {
        let th = null, first = null, bytes = 0;
        const done = status => ok({ status, t0, th, tfirst: first ?? now(), tend: now(), bytes });
        const data = d => { if (first === null) first = now(); bytes += d.length; if (onChunk) onChunk(bytes); };
        if (H2_ORIGINS.includes(port)) {
          const rq = h2(port).request({ ":path": u.pathname + u.search });
          let status = 0;
          rq.on("response", h => { th = now(); status = h[":status"]; });
          rq.on("data", data); rq.on("end", () => done(status)); rq.on("error", bad);
          if (signalBox) signalBox.cancel = () => rq.close(http2.constants.NGHTTP2_CANCEL);
          rq.end();
          return;
        }
        const mod = u.protocol === "http:" ? http : https;
        const agent = u.protocol === "http:" ? plainAgent : close ? once : keep;
        const rq = mod.request({ host: "127.0.0.1", port, path: u.pathname + u.search, agent,
                                 headers: close ? { Connection: "close" } : {} }, res => {
          th = now(); res.on("data", d => { data(d); if (sleepMs) { res.pause(); setTimeout(() => res.resume(), sleepMs); } });
          res.on("end", () => done(res.statusCode)); res.on("error", bad);
        });
        rq.on("error", bad);
        if (signalBox) signalBox.cancel = () => rq.destroy();
        rq.end();
      });
    },
    tcp(port) { return wrapSock(rawSocket(port)); },
    close() { for (const s of sessions.values()) try { s.destroy(); } catch {} keep.destroy(); once.destroy(); plainAgent.destroy(); },
  };
}

let curlMod = null;
async function libcurlClient() {
  if (!curlMod) {
    // libcurl.js is built for web / worker only: present the globals of a worker (its wasm is a data: URL in the bundle)
    if (typeof globalThis.importScripts !== "function") {
      globalThis.importScripts = () => {}; globalThis.self = globalThis;
      if (!globalThis.location) globalThis.location = new URL("http://e2e.invalid/");
    }
    // and hide process.versions.node while its module body runs (it asserts "node environment detected but not enabled")
    const pv = Object.getOwnPropertyDescriptor(process, "versions");
    Object.defineProperty(process, "versions", { value: { ...process.versions, node: undefined }, configurable: true });
    try { curlMod = (await import("libcurl.js/bundled")).libcurl; } finally { Object.defineProperty(process, "versions", pv); }
    await curlMod.load_wasm();
  }
  curlMod.set_websocket(WISP);
  const sess = new curlMod.HTTPSession();
  return {
    async fetch(url, { onChunk, signalBox, sleepMs = 0 } = {}) {
      const t0 = now();
      const ac = new AbortController();
      if (signalBox) signalBox.cancel = () => ac.abort();
      const r = await sess.fetch(url, { signal: ac.signal });
      const th = now();
      const { bytes, first } = await readBody(r.body.getReader(), t0, onChunk, sleepMs);
      return { status: r.status, t0, th, tfirst: first ?? now(), tend: now(), bytes };
    },
    tcp() { throw new Error("n/a for libcurl: no raw TCP stream in this harness"); },
    close() {},  // sess.close() with a cancelled download still in its event loop crashes the WASM (memory access out of
                 // bounds) after the result is out; one process per workload, so the session simply ends with the process
  };
}

async function openClient() {
  switch (CLIENT) {
    case "epoxy": return epoxyClient(false);
    case "epoxy-v2": return epoxyClient(true);
    case "wispjs": case "wispjs-v2": {
      const conn = await wispjsConn(CLIENT === "wispjs-v2" ? 2 : 1);
      const h = nodeHttp(port => new WispDuplex(conn, "127.0.0.1", port));
      const close = h.close;
      h.close = () => { close(); try { conn.ws.close(); } catch {} };
      return h;
    }
    case "direct": return nodeHttp(port => net.connect({ host: "127.0.0.1", port, noDelay: true }));
    case "libcurl": return libcurlClient();
    case "chromium-epoxy": case "chromium-epoxy-v2": case "firefox-epoxy": case "firefox-epoxy-v2": case "webkit-epoxy": case "webkit-epoxy-v2":
    case "chromium-libcurl": case "firefox-libcurl": case "webkit-libcurl":
      throw new Error("n/a for browser clients: closefail workloads only");
    default: throw new Error(`unknown client ${CLIENT}`);
  }
}
const PLAIN_ONLY = CLIENT === "libcurl";
const origin = (port, i) => PLAIN_ONLY ? `http://127.0.0.1:${PLAIN}` : `https://127.0.0.1:${port}`;

// ---------- helpers ----------
function q(xs, p) { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1))]; }
const r1 = x => x == null ? null : Math.round(x * 100) / 100;
function sem(n) { let a = 0; const w = []; return async f => { while (a >= n) await new Promise(r => w.push(r)); a++;
  try { return await f(); } finally { a--; const x = w.shift(); if (x) x(); } }; }
function check(rec, size, what) {
  if (rec.status !== 200 || rec.bytes !== size) throw new Error(`${what}: status ${rec.status} bytes ${rec.bytes} want ${size}`);
  return rec;
}

// a page load: HTML, then every object at once (h2 origins: no limit; h1 / plain: 6 per origin, as a browser)
async function loadPage(cl, h1 = false, tag = 0) {
  const ports = h1 ? H1_ORIGINS : H2_ORIGINS;
  const t0 = now();
  const html = check(await cl.fetch(`${origin(ports[0])}/o/${HTML_SIZE}?p=${tag}`), HTML_SIZE, "html");
  const lim = ports.map(() => sem(h1 || PLAIN_ONLY ? 6 : 1000));
  const recs = await Promise.all(PAGE.map(o => lim[o.origin](async () =>
    check(await cl.fetch(`${origin(ports[o.origin])}/o/${o.size}?p=${tag}&i=${o.i}`), o.size, `obj ${o.i}`))));
  const t1 = now();
  return { page_ms: t1 - t0, html_ttfb_ms: html.th - html.t0, req_ms: recs.map(r => r.tend - r.t0), ttfb_ms: recs.map(r => r.th - r.t0) };
}

// per stream (from the tap), in the order the client opened the streams (CONNECT sends): DATA packets and payload bytes
// received; the server's CLOSE: reason, time, gap after the last DATA, same turn / same socket read as the packet before
// it, and how many DATA packets (bytes) came in the CLOSE's read; whether the client sent a CLOSE first
function streamSummary() {
  if (!WSLOG) return null;
  const st = new Map(), order = [], key = e => `${e.w}:${e.sid}`;
  for (const e of WSLOG) {
    if (e.d === "s" && e.type === 1) {
      st.set(key(e), { sid: e.sid, ws: e.w, t_open: r1(e.t), nd: 0, bytes: 0, lastData: null, lastRead: null, gap_ms: null, same_batch: null,
                       same_read: null, reason: null, t_close: null, nd_close_read: 0, bytes_close_read: 0, client_close: false, reads: new Set() });
      order.push(key(e));
    }
    const s = st.get(key(e));
    if (!s) continue;
    if (e.d === "s" && e.type === 4) s.client_close = true;
    if (e.d !== "r") continue;
    if (e.type === 2) { s.nd++; s.bytes += e.n; s.lastData = e.t; s.lastRead = e.read; s.reads.add(e.read); }
    if (e.type === 4 && s.t_close == null) {
      s.t_close = r1(e.t); s.reason = e.reason; s.same_batch = e.same;
      s.gap_ms = s.lastData == null ? null : Math.round((e.t - s.lastData) * 1000) / 1000;
      s.same_read = s.lastRead == null ? null : s.lastRead === e.read;
      const mine = WSLOG.filter(x => x.d === "r" && x.type === 2 && x.w === e.w && x.sid === e.sid);
      for (const x of mine) if (x.read === e.read) { s.nd_close_read++; s.bytes_close_read += x.n; }
      // every DATA packet: [payload bytes, reads before the CLOSE's read (0 = in the CLOSE's read), ms before the CLOSE]
      s.data = mine.map(x => [x.n, e.read - x.read, Math.round((e.t - x.t) * 1000) / 1000]);
    }
  }
  return order.map(k => { const s = st.get(k); const { lastData, lastRead, reads, ...o } = s; o.n_reads = reads.size; return o; });
}
// self-check of the read grouping: packets with one read id must share one turn (a read cannot span two event-loop turns)
function readGroupingOk() {
  if (!WSLOG) return null;
  const m = new Map();
  for (const x of WSLOG) if (x.d === "r") { if (!m.has(x.read)) m.set(x.read, x.turn); else if (m.get(x.read) !== x.turn) return false; }
  return true;
}

// ---------- {chromium,firefox,webkit}-epoxy[-v2] / -libcurl: the closefail family in a headless browser (Playwright engines) ----------
// -libcurl: the page runs libcurl.js 0.7.5 (the bundled build) instead of epoxy-tls, against the plain HTTP origin.
// The page (browser/closefail.html + .mjs) runs the same epoxy-tls 2.1.20-1 WASM, served from node_modules by a small HTTP
// server on BASE+70; its tap groups packets by microtask checkpoint (the browser analogue of the Node socket-read groups).
// Playwright comes from bench/browser/node_modules (npm i there; npx playwright install chromium). CPU numbers are the Node
// driver's only (the browser's own CPU is not measured): function and loss counts, no timing.
const BMATCH = CLIENT.match(/^(chromium|firefox|webkit)-(epoxy(-v2)?|libcurl)$/);  // Playwright engine + the page's client library
const BROWSER = BMATCH ? BMATCH[1] : null, BLIB = BMATCH && BMATCH[2] === "libcurl" ? "libcurl" : "epoxy";
const CHROMIUM = BROWSER !== null;  // (name kept: any browser client)
async function chromiumRun(cfg) {
  const { createRequire } = await import("node:module");
  const pw = createRequire(new URL("../browser/package.json", import.meta.url))("playwright");
  const files = { "/closefail.html": ["browser/closefail.html", "text/html"], "/closefail.mjs": ["browser/closefail.mjs", "text/javascript"],
                  "/epoxy/epoxy.js": ["node_modules/@mercuryworkshop/epoxy-tls/full/epoxy.js", "text/javascript"],
                  "/epoxy/epoxy.wasm": ["node_modules/@mercuryworkshop/epoxy-tls/full/epoxy.wasm", "application/wasm"],
                  "/libcurl/libcurl_full.mjs": ["node_modules/libcurl.js/libcurl_full.mjs", "text/javascript"] };
  const srv = http.createServer((rq, rs) => {
    const p = new URL(rq.url, "http://x").pathname;
    if (p === "/ca.pem") { rs.writeHead(200, { "content-type": "text/plain" }); rs.end(CA); return; }
    const f = files[p];
    if (!f) { rs.writeHead(404); rs.end(); return; }
    rs.writeHead(200, { "content-type": f[1], "cache-control": "no-store" });
    rs.end(fs.readFileSync(new URL("./" + f[0], import.meta.url)));
  });
  const port = BASE + 70;
  await new Promise((ok, bad) => { srv.once("error", bad); srv.listen(port, "127.0.0.1", ok); });
  const browser = await pw[BROWSER].launch(BROWSER === "chromium" ? { headless: true, args: ["--no-sandbox"] } : { headless: true });
  try {
    const page = await browser.newPage();
    const logs = [];
    page.on("console", m => { if (logs.length < 20) logs.push(`${m.type()}: ${m.text()}`.slice(0, 200)); });
    page.on("pageerror", e => { if (logs.length < 20) logs.push(`pageerror: ${String(e).slice(0, 200)}`); });
    const n = QUICK ? Math.max(4, Math.round(cfg.n / 4)) : cfg.n;
    const qs = new URLSearchParams({ wisp: WISP, base: String(BASE), lib: BLIB, v2: CLIENT.endsWith("-v2") ? "1" : "0", busy: cfg.busy ? "1" : "0",
                                     n: String(n), sizes: cfg.sizes.join(","), sleep: String(cfg.sleep || 0),
                                     limit: String(cfg.limitMs || 0),
                                     deadline: String(cfg.limitMs ? Math.max(5000, TIMEOUT_MS - cfg.limitMs - 15000) : 0) });
    await page.goto(`http://127.0.0.1:${port}/closefail.html?${qs}`);
    await page.waitForFunction(() => window.__result, null, { timeout: TIMEOUT_MS - 5000, polling: 200 });
    const res = await page.evaluate(() => window.__result);
    if (!res.ok) throw new Error(`page: ${res.error}; console: ${logs.join(" | ")}`);
    const { ok, ...rest } = res;
    rest.s.browser = { engine: BROWSER, version: browser.version(), console: logs };
    return rest;
  } finally { await browser.close().catch(() => {}); srv.close(); }
}

// ---------- the closefail family: responses whose origin closes right after them (Connection: close) ----------
// closefail: 40 requests, 64 B / 20000 B alternating (the original workload, unchanged). closefail3: 60 requests, 64 B /
// 20000 B / 1 MiB. closefail3busy: the same while the client's main thread is ~80 % busy (8 ms of every 10 ms). closefailslow5
// / slow20: 1 MiB responses read by a consumer that sleeps 5 / 20 ms per chunk (backpressure). --quick: a quarter.
// A response counts as lost if it is short, fails, or is not done within limitMs. s.resp (with --wslog / the browser tap): one entry
// per request joined to its stream by the order of CONNECT sends (the warm-up is the first stream).
const CF = {  // limitMs: a response not done by then counts as lost (0 = none: the original closefail, unchanged)
  closefail: { sizes: [64, 20000], n: 40, limitMs: 0 },
  closefail3: { sizes: [64, 20000, 1048576], n: 60, limitMs: 15000 },
  closefail3busy: { sizes: [64, 20000, 1048576], n: 60, busy: true, limitMs: 15000 },
  closefailslow5: { sizes: [1048576], n: 16, sleep: 5, limitMs: 15000 },
  closefailslow20: { sizes: [1048576], n: 10, sleep: 20, limitMs: 15000 },
};
function withLimit(p, ms, onTimeout) {  // p, or a rejection after ms (0 = no limit; onTimeout() then tears the request down)
  if (!ms) return p;
  let t;
  return Promise.race([p, new Promise((_, bad) => { t = setTimeout(() => { try { onTimeout?.(); } catch {} bad(new Error(`timeout ${ms / 1000} s`)); }, ms); })])
    .finally(() => clearTimeout(t));
}
async function closefailRun(cfg) {
  if (CHROMIUM) return chromiumRun(cfg);
  const tStart = now();  // the run deadline counts from here (setup and warm-up included)
  const n = QUICK ? Math.max(4, Math.round(cfg.n / 4)) : cfg.n, cl = await openClient();
  const busy = cfg.busy ? setInterval(() => { const t = now(); while (now() - t < 8); }, 10) : null;
  try {
    check(await cl.fetch(`${origin(H1_ORIGINS[3])}/o/64?w=0`), 64, "closefail warm-up");
    // run deadline (workloads with a per-response limit): no new request after it, so a run with hangs still returns its
    // outcomes (s.truncated = requests not issued) instead of hitting the workload timeout and losing every count
    // a timed-out request ends the run too: its teardown cannot be confirmed (a fetch cancelled before its headers keeps
    // running), and the workload must stay sequential; the rest counts as truncated, not lost
    const deadline = cfg.limitMs ? Math.max(5000, TIMEOUT_MS - cfg.limitMs - 10000) : 0;
    let lost = 0, truncated = 0, timedOut = false; const xs = [], errs = {}, outcomes = [], resp = [];
    for (let i = 0; i < n; i++) {
      if (timedOut || (deadline && now() - tStart > deadline)) { truncated = n - i; break; }
      const size = cfg.sizes[i % cfg.sizes.length];
      let ok = false, got = null, err = null;
      const t0 = now();
      try {
        const sb = {};  // a timed-out request is cancelled before the next one starts (sequential workload)
        const r = await withLimit(cl.fetch(`${origin(H1_ORIGINS[2])}/o/${size}?c=${i}`, { close: true, sleepMs: cfg.sleep || 0, signalBox: sb }),
                                  cfg.limitMs, () => sb.cancel?.());
        got = r.bytes;
        if (r.status === 200 && r.bytes === size) { xs.push(r.tend - r.t0); ok = true; } else { lost++; errs.short = (errs.short || 0) + 1; err = `short: status ${r.status}`; }
      } catch (e) {
        lost++; const full = String(e?.message ?? e); err = full.slice(0, 240); const k = full.slice(0, 60); errs[k] = (errs[k] || 0) + 1;
        if (cfg.limitMs && full.startsWith("timeout")) timedOut = true;
      }
      outcomes.push(ok ? 1 : 0);
      resp.push({ i, size, ok, got, err, t0: r1(t0), t1: r1(now()) });
      await new Promise(r => setTimeout(r, 5));  // the stream's late packets land before the next request
    }
    const streams = streamSummary(), m = resp.length;
    let joined = resp, joinError = null;  // s.resp stays an array; an unjoined run keeps its outcomes (and timeouts)
    if (streams) { if (streams.length === m + 1) joined = resp.map((x, k) => ({ ...x, ...streams[k + 1] })); else joinError = `CONNECTs ${streams.length} != ${m + 1}: not joined`; }
    return { m: { close_lost_pct: m ? 100 * lost / m : null, close_ok_p50_ms: q(xs, 0.5) },
             s: { errs, outcomes, streams, resp: joined, ...(joinError ? { join_error: joinError } : {}), read_grouping_ok: readGroupingOk(),
                  ...(cfg.limitMs ? { truncated } : {}) } };
  } finally { if (busy) clearInterval(busy); cl.close(); }
}

// ---------- workloads ----------
const W = {
  async page() {  // one cold load (new Wisp connection + TLS) then REPS warm loads on the same client
    const reps = QUICK ? 2 : 5, cl = await openClient();
    try {
      const cold = await loadPage(cl, false, 0);
      const warm = [];
      for (let i = 1; i <= reps; i++) warm.push(await loadPage(cl, false, i));
      const req = warm.flatMap(x => x.req_ms), ttfb = warm.flatMap(x => x.ttfb_ms);
      return { m: { page_cold_ms: cold.page_ms, page_warm_ms: q(warm.map(x => x.page_ms), 0.5), page_req_p50_ms: q(req, 0.5),
                    page_req_p99_ms: q(req, 0.99), page_ttfb_p50_ms: q(ttfb, 0.5), page_html_ttfb_ms: q(warm.map(x => x.html_ttfb_ms), 0.5) },
               s: { warm_page_ms: warm.map(x => r1(x.page_ms)), page_bytes: PAGE_BYTES } };
    } finally { cl.close(); }
  },
  async page1() {  // the same page over HTTP/1.1 origins (6 connections per origin)
    const reps = QUICK ? 2 : 5, cl = await openClient();
    try {
      const cold = await loadPage(cl, true, 0);
      const warm = [];
      for (let i = 1; i <= reps; i++) warm.push(await loadPage(cl, true, i));
      const req = warm.flatMap(x => x.req_ms);
      return { m: { page1_cold_ms: cold.page_ms, page1_warm_ms: q(warm.map(x => x.page_ms), 0.5), page1_req_p50_ms: q(req, 0.5),
                    page1_req_p99_ms: q(req, 0.99) }, s: { warm_page_ms: warm.map(x => r1(x.page_ms)) } };
    } finally { cl.close(); }
  },
  async bulk() {
    const size = (QUICK ? 16 : 32) << 20, cl = await openClient();
    try {
      const r = check(await cl.fetch(`${origin(H1_ORIGINS[0])}/bulk/${size}`), size, "bulk");
      return { m: { bulk_mib_s: (size / 1048576) / ((r.tend - r.tfirst) / 1000), bulk_ttfb_ms: r.th - r.t0, bulk_total_ms: r.tend - r.t0 } };
    } finally { cl.close(); }
  },
  async rr() {  // sequential small requests on one warm keep-alive connection
    const n = QUICK ? 50 : 200, cl = await openClient();
    try {
      for (let i = 0; i < 5; i++) check(await cl.fetch(`${origin(H1_ORIGINS[1])}/o/64?w=${i}`), 64, "rr warm-up");
      const xs = [];
      const t0 = now();
      for (let i = 0; i < n; i++) { const r = check(await cl.fetch(`${origin(H1_ORIGINS[1])}/o/64?i=${i}`), 64, "rr"); xs.push(r.tend - r.t0); }
      const total = now() - t0;
      return { m: { rr_p50_ms: q(xs, 0.5), rr_p99_ms: q(xs, 0.99), rr_mean_ms: total / n }, s: { rr_ms: xs.map(r1) } };
    } finally { cl.close(); }
  },
  async tls() {  // a new origin per request (40 target ports): Wisp stream open + target connect + TLS handshake + one GET
    if (PLAIN_ONLY) throw new Error("n/a for libcurl (plain HTTP only)");
    const n = QUICK ? 10 : 40, cl = await openClient();
    try {
      check(await cl.fetch(`${origin(H1_ORIGINS[2])}/o/64?w=0`), 64, "tls warm-up");  // the Wisp connection is open
      const xs = [];
      for (let i = 0; i < n; i++) { const r = check(await cl.fetch(`${origin(MANY[i])}/o/64?i=${i}`), 64, "tls"); xs.push(r.tend - r.t0); }
      return { m: { tls_p50_ms: q(xs, 0.5), tls_p99_ms: q(xs, 0.99) }, s: { tls_ms: xs.map(r1) } };
    } finally { cl.close(); }
  },
  async closefail() { return closefailRun(CF.closefail); },
  async closefail3() { return closefailRun(CF.closefail3); },
  async closefail3busy() { return closefailRun(CF.closefail3busy); },
  async closefailslow5() { return closefailRun(CF.closefailslow5); },
  async closefailslow20() { return closefailRun(CF.closefailslow20); },
  async churn() {  // short TCP streams to the echo target, 10 at a time: open, 64 B there and back, close
    if (PLAIN_ONLY) throw new Error("n/a for libcurl");
    const n = QUICK ? 50 : 200, cl = await openClient();
    const payload = new Uint8Array(64).fill(7);
    try {
      const one = async () => {
        const t0 = now(), s = await cl.tcp(ECHO);
        await s.send(payload);
        let got = 0;
        while (got < 64) { const d = await s.recv(); if (!d) throw new Error(`echo closed after ${got} B`); got += d.byteLength; }
        const t = now() - t0;
        await s.close();
        return t;
      };
      await one();
      const lim = sem(10), t0 = now();
      const xs = await Promise.all(Array.from({ length: n }, () => lim(one)));
      const total = now() - t0;
      return { m: { churn_per_s: n / (total / 1000), churn_p50_ms: q(xs, 0.5), churn_p99_ms: q(xs, 0.99) }, s: { churn_ms: xs.map(r1) } };
    } finally { cl.close(); }
  },
  async busy() {  // a page load and small fetches while a bulk download runs on the same Wisp connection
    // Caps: a server that queues the page behind the bulk would hold it for the whole download. The page under the bulk
    // gets BUSY_CAP ms; past it the value is the cap (censored, busy_censored = 1), the bulk is cancelled and the page is
    // waited for (not measured). The 10 small fetches get the same cap together.
    const BUSY_CAP = 8000;
    const cl = await openClient();
    const startAt = 4 << 20;
    const capped = (p, ms) => Promise.race([p.then(x => ({ x }), e => ({ e })), new Promise(r => setTimeout(() => r({ cap: true }), ms))]);
    try {
      await loadPage(cl, false, 0);                        // TLS connections of the page origins exist (as a warm tab)
      const quiet = await loadPage(cl, false, 1);
      const quietSmall = [];
      for (let i = 0; i < 10; i++) { const r = check(await cl.fetch(`${origin(H1_ORIGINS[3])}/o/2000?q=${i}`), 2000, "small"); quietSmall.push(r.tend - r.t0); }
      let bulkBytes = 0, started;
      const reached = new Promise(r => { started = r; });
      const box = {};
      const tb = now();
      const bulk = cl.fetch(`${origin(H1_ORIGINS[0])}/inf`, { signalBox: box,
        onChunk: b => { bulkBytes = b; if (b >= startAt) started(); } }).then(r => ({ r }), e => ({ e }));
      const early = await Promise.race([reached.then(() => null), bulk, new Promise(r => setTimeout(() => r({ e: "no 4 MiB of bulk in 20 s" }), 20000))]);
      if (early) throw new Error(`bulk ended before ${startAt} B: ${early.e ?? "done"}`);
      const b0 = bulkBytes, tp = now();
      let censored = 0, busyPageMs, b1, tq, small = [];
      const pageP = loadPage(cl, false, 2);
      const pr = await capped(pageP, BUSY_CAP);
      if (pr.e) throw pr.e;
      if (pr.cap) {
        censored = 1; busyPageMs = BUSY_CAP; b1 = bulkBytes; tq = now();
        small = Array(10).fill(BUSY_CAP);
      } else {
        busyPageMs = pr.x.page_ms; b1 = bulkBytes; tq = now();
        const ts = now();
        for (let i = 0; i < 10; i++) {
          const left = BUSY_CAP - (now() - ts);
          const r = left > 0 ? await capped(cl.fetch(`${origin(H1_ORIGINS[3])}/o/2000?b=${i}`), left) : { cap: true };
          if (r.e) throw r.e;
          if (r.cap) { censored = 1; while (small.length < 10) small.push(BUSY_CAP); break; }
          small.push(check(r.x, 2000, "small").tend - r.x.t0);
        }
      }
      const b2 = bulkBytes, te = now();
      const ended = await Promise.race([bulk.then(() => true), new Promise(r => setTimeout(() => r(false), 0))]);
      if (ended) throw new Error("bulk ended during the measurement");
      if (box.cancel) box.cancel();
      await Promise.race([bulk, new Promise(r => setTimeout(r, 2000))]);
      if (censored) await Promise.race([pageP.catch(() => {}), new Promise(r => setTimeout(r, 3000))]);
      return { m: { busy_page_ms: busyPageMs, quiet_page_ms: quiet.page_ms, busy_page_slowdown: busyPageMs / quiet.page_ms,
                    busy_small_p50_ms: q(small, 0.5), quiet_small_p50_ms: q(quietSmall, 0.5), busy_small_max_ms: Math.max(...small),
                    busy_bulk_mib_s_page: ((b1 - b0) / 1048576) / ((tq - tp) / 1000), busy_bulk_mib_s_all: ((b2 - startAt) / 1048576) / ((te - tb) / 1000),
                    busy_censored: censored },
               s: { busy_req_ms: pr.x ? pr.x.req_ms.map(r1) : null, small_ms: small.map(r1), quiet_small_ms: quietSmall.map(r1), bulk_mib_page: r1((b1 - b0) / 1048576) } };
    } finally { cl.close(); }
  },
};

const list = (args.workloads || "page,bulk,rr,tls,busy").split(",");
for (const w of list) if (!W[w]) { console.error(`unknown workload ${w}; known: ${Object.keys(W).join(",")}`); process.exit(2); }
let failed = 0;
for (const w of list) {
  const c0 = cpuStart();
  let rec;
  let timer;
  try {
    const out = await Promise.race([W[w](), new Promise((_, bad) => { timer = setTimeout(() => bad(new Error(`timeout ${TIMEOUT_MS} ms`)), TIMEOUT_MS); })]);
    rec = { w, client: CLIENT, ok: true, ...out };
  } catch (e) {
    failed++;
    rec = { w, client: CLIENT, ok: false, error: String(e?.message ?? e).slice(0, 400) };
  } finally { clearTimeout(timer); }
  const ce = cpuEnd(c0);
  rec.wall_ms = ce.wall_ms;
  rec.warns = warns;
  rec.cpu = ce.cpu;
  if (rec.m) for (const k in rec.m) rec.m[k] = r1(rec.m[k]);
  process.stdout.write(JSON.stringify(rec) + "\n");
  await new Promise(r => setTimeout(r, 100));
}
process.exit(failed ? 1 : 0);
