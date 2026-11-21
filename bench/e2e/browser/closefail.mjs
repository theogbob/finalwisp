// 80.04 L8: the closefail workload in a real browser (Chromium via Playwright, driven by client.mjs --client chromium-*).
// Same epoxy-tls 2.1.20-1 WASM as the Node client. The tap logs every Wisp packet the page's WebSocket receives (type, stream,
// payload bytes, time). It cannot use the Node "same socket read" grouping: a browser runs a microtask checkpoint after every
// event-listener callback (HTML "clean up after running script"), so epoxy's wasm futures, and so the stream reader, always
// run between two WebSocket messages. The browser measure is instead pending_at_close per response: the body was not yet
// fully read by the page when the server's CLOSE message arrived (the tap's listener runs before epoxy's). turn (a
// setTimeout(0) task counter) is informational: two messages share a turn if no timer task ran between them.
// The per-response join (s.resp) has the same shape as client.mjs, so report_tables.py / pcapclose.py read it unchanged.
const P = new URLSearchParams(location.search);
const WISP = P.get("wisp"), BASE = Number(P.get("base")), V2 = P.get("v2") === "1";
const LIB = P.get("lib") || "epoxy";  // epoxy (epoxy-tls, HTTPS to our CA) or libcurl (libcurl.js 0.7.5 bundled: plain HTTP only)
const BUSY = P.get("busy") === "1", N = Number(P.get("n")), SIZES = P.get("sizes").split(",").map(Number), SLEEP = Number(P.get("sleep") || 0);
const LIMIT = Number(P.get("limit") || 0);
const DEADLINE = Number(P.get("deadline") || 0);  // ms after the start: no new request after it (partial run, s.truncated)  // ms; 0 = no limit (as client.mjs CF.limitMs)
const now = () => performance.now();
const r1 = x => x == null ? null : Math.round(x * 100) / 100;
const WSLOG = [];
let turn = 0, tarmed = false, wsn = 0;
const WS = window.WebSocket;
window.WebSocket = class extends WS {
  constructor(...a) {
    super(...a);
    const w = this._tapW = ++wsn;  // WebSocket instance: stream ids restart on a reconnect, so streams are keyed by (w, sid)
    this.addEventListener("message", ev => {
      if (!(ev.data instanceof ArrayBuffer) || ev.data.byteLength < 5) return;
      const v = new DataView(ev.data);
      if (!tarmed) { tarmed = true; setTimeout(() => { tarmed = false; turn++; }, 0); }
      const type = v.getUint8(0);
      WSLOG.push({ d: "r", w, k: WSLOG.length, t: now(), type, sid: v.getUint32(1, true), n: ev.data.byteLength - 5, turn,
                   reason: type === 4 && ev.data.byteLength >= 6 ? v.getUint8(5) : null });
    });
  }
  send(x) {
    try { const b = x instanceof ArrayBuffer ? new Uint8Array(x) : new Uint8Array(x.buffer ?? x, x.byteOffset ?? 0, x.byteLength);
          if (b.byteLength >= 5) WSLOG.push({ d: "s", w: this._tapW, t: now(), type: b[0], sid: (b[1] | b[2] << 8 | b[3] << 16 | b[4] << 24) >>> 0, n: b.byteLength - 5 }); } catch {}
    return super.send(x);
  }
};

function streamSummary() {  // per stream in CONNECT order: DATA packets / bytes, CLOSE reason, time, tap index, gap after the last DATA
  const st = new Map(), order = [], key = e => `${e.w}:${e.sid}`;
  for (const e of WSLOG) {
    if (e.d === "s" && e.type === 1) {
      st.set(key(e), { sid: e.sid, ws: e.w, nd: 0, bytes: 0, reason: null, t_close: null, k_close: null, gap_ms: null, lastData: null });
      order.push(key(e));
    }
    const s = st.get(key(e));
    if (!s || e.d !== "r") continue;
    if (e.type === 2) { s.nd++; s.bytes += e.n; s.lastData = e.t; }
    if (e.type === 4 && s.reason == null) {
      s.reason = e.reason; s.t_close = e.t; s.k_close = e.k;
      s.gap_ms = s.lastData == null ? null : Math.round((e.t - s.lastData) * 1000) / 1000;
    }
  }
  return order.map(k => { const { lastData, ...o } = st.get(k); return o; });
}

async function main() {
  const tStart = now();  // the run deadline counts from here (setup and warm-up included)
  const busy = BUSY ? setInterval(() => { const t = now(); while (now() - t < 8); }, 10) : null;  // main thread ~80 % busy
  let c, origin;
  if (LIB === "libcurl") {  // libcurl.js has no CA option: the plain HTTP origin (BASE + 8) for every request
    const lc = (await import("/libcurl/libcurl_full.mjs")).libcurl;
    lc.set_websocket(WISP);
    await lc.load_wasm();
    c = new lc.HTTPSession();
    origin = () => `http://127.0.0.1:${BASE + 8}`;
  } else {
    const ep = await import("/epoxy/epoxy.js");
    await ep.default({ module_or_path: "/epoxy/epoxy.wasm" });
    const ca = await (await fetch("/ca.pem")).text();
    const o = new ep.EpoxyClientOptions();
    o.wisp_v2 = V2; o.pem_files = [ca]; o.user_agent = "finalwisp-e2e-chromium";
    c = new ep.EpoxyClient(WISP, o);
    origin = port => `https://127.0.0.1:${port}`;
  }
  const sizes = SIZES, n = N;
  let timeouts = 0;
  const get = async (url, close, size) => {  // -> {ok, got, err, tFull}; not done within LIMIT ms counts as lost
    let tFull = null, kFull = null;  // when the page had read the whole body (time; WSLOG length)
    let rd = null, abandoned = false;  // on timeout: the reader is cancelled and the loop stops before the next request
    const run = (async () => {
      const r = await c.fetch(url, close ? { headers: { Connection: "close" } } : {});
      rd = r.body.getReader(); let got = 0;
      if (abandoned) { rd.cancel().catch(() => {}); throw new Error("abandoned after timeout"); }
      for (;;) {
        const { done, value } = await rd.read(); if (done || abandoned) break; got += value.byteLength;
        if (got >= size && tFull === null) { tFull = now(); kFull = WSLOG.length; }  // packets logged so far: exact order
        if (SLEEP) await new Promise(res => setTimeout(res, SLEEP));  // slow consumer: backpressure
      }
      return { ok: r.status === 200 && got === size, got, err: r.status === 200 && got === size ? null : `short: status ${r.status}` };
    })();
    const caught = run.catch(e => ({ ok: false, got: null, err: String(e?.message ?? e).slice(0, 240) }));
    let t;
    const out = !LIMIT ? await caught : await Promise.race([caught, new Promise(res => {
      t = setTimeout(() => { abandoned = true; if (rd) rd.cancel().catch(() => {}); timeouts++;
                             res({ ok: false, got: null, err: `timeout ${LIMIT / 1000} s` }); }, LIMIT); })]).finally(() => clearTimeout(t));
    return { ...out, tFull, kFull };
  };
  const w0 = await get(`${origin(BASE + 7)}/o/64?w=0`, false, 64);
  if (!w0.ok) throw new Error(`warm-up: ${w0.err}`);
  // a timed-out request ends the run: its teardown cannot be confirmed (cancel works only once the headers are in), and
  // the workload must stay sequential; the rest counts as truncated, not lost
  let lost = 0, truncated = 0; const outcomes = [], resp = [], errs = {};
  const kLoop = WSLOG.filter(e => e.d === "s" && e.type === 1).length;  // streams opened before the measured requests (warm-up)
  for (let i = 0; i < n; i++) {
    if (timeouts || (DEADLINE && now() - tStart > DEADLINE)) { truncated = n - i; break; }
    const size = sizes[i % sizes.length], t0 = now();
    const r = await get(`${origin(BASE + 6)}/o/${size}?c=${i}`, true, size);
    if (!r.ok) { lost++; const k = (r.err || "").slice(0, 60); errs[k] = (errs[k] || 0) + 1; }
    outcomes.push(r.ok ? 1 : 0);
    resp.push({ i, size, ok: r.ok, got: r.got, err: r.err, t0: r1(t0), t1: r1(now()), t_full: r.tFull, k_full: r.kFull });
    await new Promise(res => setTimeout(res, 5));
  }
  if (busy) clearInterval(busy);
  const streams = streamSummary(), m = resp.length;
  // pending_at_close: the server's CLOSE was logged before the page had read the whole body (or the body never completed).
  // Order by WSLOG index, not by time (performance.now is coarsened in a page): complete before CLOSE <=> k_full <= k_close.
  const joined = streams.length === m + 1 ? resp.map((x, k) => {
    const s = streams[k + 1];
    const pending = s.k_close == null ? null : (x.k_full == null || x.k_full > s.k_close);
    return { ...x, ...s, t_close: r1(s.t_close), t_full: r1(x.t_full), pending_at_close: pending };
  }) : resp;
  let sharedTurn = 0, total = 0, prevTurn = null;
  for (const e of WSLOG) if (e.d === "r") { total++; if (prevTurn !== null && e.turn === prevTurn) sharedTurn++; prevTurn = e.turn; }
  return { m: { close_lost_pct: m ? 100 * lost / m : null }, s: { errs, outcomes, streams, resp: joined, n_connect: streams.length, truncated, timeouts,
           joined: streams.length === m + 1, websockets: wsn, packets: total, packets_sharing_a_timer_turn: sharedTurn, ua: navigator.userAgent,
           lib: LIB,
           // request streams the tap saw without a CLOSE: the warm-up's stream only counts if a request reused it (fewer new
           // streams than requests); null when the tap saw no message
           streams_without_close: total ? (streams.length - kLoop < m ? streams : streams.slice(kLoop)).filter(s => s.reason == null).length : null } };
}
main().then(x => { window.__result = { ok: true, ...x }; }, e => { window.__result = { ok: false, error: String(e?.stack ?? e).slice(0, 600) }; });
