// Browser sim scenario runner (bench/browser, driven by browser.py). Node + Playwright.
// usage: node scenario.mjs CONFIG.json   -> prints one "RESULT {json}" line per case to stdout.
// CONFIG: {scramjet_dir, page_port, wisp_url, transport, mirror_dir?, mirror_port?, mirror_delay_ms?,
//          cases: [{case: "page"|"download"|"session", site, url, rep, ...}], timeout_ms, settle_ms, headful?,
//          spki? (wss:// Wisp with a self-signed cert: base64 SHA-256 of its SPKI)}
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { spawn } from "node:child_process";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// `node scenario.mjs --mirror DIR PORT DELAY_MS`: only the timing-mode origin, as its own process (browser.py
// starts it once per run, so origin serving never shares an event loop with the Playwright driver).
const MIRROR_ONLY = process.argv[2] === "--mirror";
const SELFTEST = process.argv[2] === "--selftest"; // trace summary on synthetic data + one /proc CPU sample, no browser
const cfg = SELFTEST ? { server_pid: process.pid } : MIRROR_ONLY
	? { mirror_dir: process.argv[3], mirror_port: +process.argv[4], mirror_delay_ms: +process.argv[5] }
	: JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const TIMEOUT = cfg.timeout_ms ?? 60000;
const SETTLE = cfg.settle_ms ?? 2000;
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".mjs": "text/javascript",
	".wasm": "application/wasm", ".json": "application/json", ".css": "text/css", ".png": "image/png",
	".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp",
	".woff2": "font/woff2", ".woff": "font/woff", ".ico": "image/x-icon", ".bin": "application/octet-stream" };

function sendFile(res, file, extraHeaders = {}) {
	fs.stat(file, (err, st) => {
		if (err || !st.isFile()) { res.writeHead(404, { "content-type": "text/plain" }); res.end("not found"); return; }
		res.writeHead(200, { "content-type": MIME[path.extname(file).toLowerCase()] ?? "application/octet-stream",
			"content-length": st.size, "cache-control": "no-store", ...extraHeaders });
		fs.createReadStream(file).pipe(res);
	});
}

// safe join: never serve outside root
function under(root, urlPath) {
	let dec;
	try { dec = decodeURIComponent(urlPath); } catch { return null; }
	const p = path.normalize(path.join(root, dec));
	return p.startsWith(path.resolve(root) + path.sep) || p === path.resolve(root) ? p : null;
}

function startPageServer() {
	const sj = cfg.scramjet_dir;
	const mounts = [
		["/scramjet/", path.join(sj, "packages/core/dist")],
		["/controller/", path.join(sj, "packages/controller/dist")],
	];
	const files = {
		"/": path.join(HERE, "page/index.html"),
		"/main.mjs": path.join(HERE, "page/main.mjs"),
		"/sw.js": path.join(HERE, "page/sw.js"),
		"/transports/epoxy.mjs": path.join(sj, "packages/demo/node_modules/@mercuryworkshop/epoxy-transport/dist/index.mjs"),
		"/transports/libcurl.mjs": path.join(sj, "packages/demo/node_modules/@mercuryworkshop/libcurl-transport/dist/index.mjs"),
	};
	const srv = http.createServer((req, res) => {
		const u = new URL(req.url, "http://x");
		if (files[u.pathname]) return sendFile(res, files[u.pathname]);
		for (const [pre, dir] of mounts) {
			if (u.pathname.startsWith(pre)) {
				const f = under(dir, u.pathname.slice(pre.length));
				if (f) return sendFile(res, f);
			}
		}
		res.writeHead(404); res.end();
	});
	return new Promise((r) => srv.listen(cfg.page_port, "127.0.0.1", () => r(srv)));
}

// Timing-mode origin: static files from mirror_dir, optional fixed per-response delay (a crude RTT stand-in).
// /__blocked/* answers 404 at once (external URLs left in saved pages are rewritten to it).
const GEN = Buffer.alloc(1 << 20);
for (let i = 0, x = 1; i < GEN.length; i++) { x = (x * 1103515245 + 12345) >>> 0; GEN[i] = x >>> 24; }
function startMirrorServer() {
	const root = cfg.mirror_dir;
	const delay = cfg.mirror_delay_ms ?? 0;
	const srv = http.createServer((req, res) => {
		const u = new URL(req.url, "http://x");
		const go = () => {
			if (u.pathname.startsWith("/__blocked/")) { res.writeHead(404); res.end(); return; }
			// /__gen/N: N bytes of a fixed 1 MiB pseudo-random block, streamed with backpressure (an "endless" download)
			if (u.pathname.startsWith("/__gen/")) {
				const n = Number(u.pathname.slice(7));
				if (!(n > 0)) { res.writeHead(400); res.end(); return; }
				res.writeHead(200, { "content-type": "application/octet-stream", "content-length": n, "cache-control": "no-store" });
				let left = n;
				const pump = () => {
					while (left > 0) {
						const k = Math.min(left, GEN.length);
						left -= k;
						if (!res.write(k === GEN.length ? GEN : GEN.subarray(0, k))) return res.once("drain", pump);
					}
					res.end();
				};
				res.on("close", () => { left = 0; });
				return pump();
			}
			let f = under(root, u.pathname);
			if (f && fs.existsSync(f) && fs.statSync(f).isDirectory()) f = path.join(f, "index.html");
			if (!f) { res.writeHead(404); res.end(); return; }
			sendFile(res, f);
		};
		delay ? setTimeout(go, delay) : go();
	});
	srv.keepAliveTimeout = 30000;
	return new Promise((r) => srv.listen(cfg.mirror_port, "127.0.0.1", () => r(srv)));
}

function emit(obj) { process.stdout.write("RESULT " + JSON.stringify(obj) + "\n"); }

// One fresh browser context per case: cold transport, new Wisp connection, no shared cache.
async function withSim(browser, fn) {
	const ctx = await browser.newContext({ viewport: { width: 1300, height: 800 }, serviceWorkers: "allow" });
	const page = await ctx.newPage();
	const st = { leaks: [], external: 0, external_urls: [], requests: 0, failed: 0, http5xx: 0, bytes: 0, failures: [], console_errors: [], websockets: 0, pending: new Set() };
	// proxied = goes through the transport; scramjet.wasm.js is served by the controller itself
	const proxied = (u) => u.includes("/~/sj/") && !u.endsWith("/scramjet.wasm.js");
	const mirror = cfg.mirror_port ? `http://127.0.0.1:${cfg.mirror_port}/` : null;
	ctx.on("request", (rq) => {
		if (!proxied(rq.url())) return;
		st.requests++; st.pending.add(rq);
		// timing mode: anything not from the mirror is noise from outside (should stay 0)
		if (mirror && !decodeSj(rq.url()).startsWith(mirror) && !decodeSj(rq.url()).startsWith("data:")) {
			st.external++; if (st.external_urls.length < 4) st.external_urls.push(decodeSj(rq.url()));
		}
	});
	ctx.on("requestfailed", (rq) => {
		if (!proxied(rq.url())) return;
		st.pending.delete(rq); st.failed++;
		if (st.failures.length < 8) st.failures.push(`${rq.failure()?.errorText} ${decodeSj(rq.url())}`);
	});
	ctx.on("requestfinished", async (rq) => {
		if (!proxied(rq.url())) return;
		try {
			const resp = await rq.response();
			if (resp && resp.status() >= 500) {
				st.http5xx++;
				if (st.failures.length < 8) st.failures.push(`HTTP ${resp.status()} ${decodeSj(rq.url())}`);
			}
		} catch {}
		st.pending.delete(rq); // after the status is counted, so settle() cannot return before it
	});
	page.on("websocket", (ws) => {
		st.websockets++;
		// the Wisp connection is the only WebSocket the browser itself may open; a page WebSocket must go through Wisp
		if (ws.url() !== cfg.wisp_url) st.leaks.push("websocket " + ws.url());
	});
	// proxy escape: any request the browser makes to an origin other than the host page (a frame whose document Scramjet
	// did not instrument, e.g. a text/plain origin, fetches directly) is a leak and fails the case
	const own = `http://127.0.0.1:${cfg.page_port}/`;
	ctx.on("request", (rq) => {
		const u = rq.url();
		if (!/^(https?|wss?):/.test(u) || u.startsWith(own)) return;
		if (st.leaks.length < 200) st.leaks.push("request " + u.slice(0, 160));
	});
	// body bytes as the renderer received them (SW-served responses report encodedDataLength <= 0 in sizes())
	const cdp = await ctx.newCDPSession(page);
	await cdp.send("Network.enable");
	const sjIds = new Set();
	cdp.on("Network.requestWillBeSent", (ev) => { if (proxied(ev.request.url)) sjIds.add(ev.requestId); });
	cdp.on("Network.dataReceived", (ev) => { if (sjIds.has(ev.requestId)) st.bytes += ev.dataLength; });
	st.cdp = cdp;
	if (cfg.trace) traceCdp(cdp, st, proxied);
	page.on("console", (m) => { if (m.type() === "error" && st.console_errors.length < 8) st.console_errors.push(m.text().slice(0, 300)); });
	page.on("pageerror", (e) => { if (st.console_errors.length < 8) st.console_errors.push("pageerror: " + String(e).slice(0, 300)); });
	try {
		const t0 = Date.now();
		await page.goto(`http://127.0.0.1:${cfg.page_port}/?transport=${cfg.transport}&wisp=${encodeURIComponent(cfg.wisp_url)}${cfg.trace ? "&trace=1" : ""}`);
		await page.waitForFunction(() => window.__sim && (window.__sim.ready || window.__sim.error), null, { timeout: 30000 });
		const err = await page.evaluate(() => window.__sim.error);
		if (err) throw new Error("sim init: " + err);
		const init_ms = Date.now() - t0;
		return await fn(page, st, init_ms);
	} finally {
		await ctx.close().catch(() => {});
	}
}

function decodeSj(u) {
	const i = u.indexOf("/~/sj/");
	if (i < 0) return u;
	const rest = u.slice(i + 6).split("/").slice(2).join("/"); // /~/sj/<ctrl>/<frame>/<encoded url>
	try { return decodeURIComponent(rest).slice(0, 200); } catch { return rest.slice(0, 200); }
}

const childFrame = (page) => page.frames().find((f) => f.parentFrame() === page.mainFrame());

async function snapshotDoc(page) {
	const fr = childFrame(page);
	if (!fr) return { title: null, text_len: 0, url: null };
	try {
		return await fr.evaluate(() => ({ title: document.title, text_len: (document.body?.innerText || "").length,
			doc_status: performance.getEntriesByType("navigation")[0]?.responseStatus ?? null }));
	} catch (e) { return { title: null, text_len: 0, eval_error: String(e).slice(0, 200) }; }
}

async function settle(st, ms) {
	// wait up to ms for in-flight proxied requests to finish (a person looks at the page for a moment)
	const end = Date.now() + ms;
	while (Date.now() < end && st.pending.size) await new Promise((r) => setTimeout(r, 100));
	return st.pending.size;
}

function counts(st) {
	return { leaks: st.leaks.length, leak_urls: st.leaks.slice(0, 4), leak_all: st.leaks.slice(0, 200), external_requests: st.external, external_urls: st.external_urls, requests: st.requests, failed_requests: st.failed, http_5xx: st.http5xx, bytes: st.bytes,
		websockets: st.websockets, failures: st.failures, console_errors: st.console_errors };
}

async function casePage(browser, c) {
	return withSim(browser, async (page, st, init_ms) => {
		let load_ms = null, error = null;
		try { load_ms = await page.evaluate(([u, t]) => window.__sim.go(u, t), [c.url, TIMEOUT]); }
		catch (e) { error = String(e.message || e).slice(0, 300); }
		const still_pending = await settle(st, SETTLE);
		const doc = await snapshotDoc(page);
		const min_text = c.min_text ?? 200;
		if (!error && doc.text_len < min_text) error = `page text ${doc.text_len} chars < ${min_text} (title ${JSON.stringify(doc.title)})`;
		return { ok: !error, error, init_ms, load_ms: load_ms == null ? null : Math.round(load_ms), still_pending, ...doc, ...counts(st) };
	});
}

// A download the way a page script does it: fetch() inside the proxied page, streamed to the end.
async function caseDownload(browser, c) {
	return withSim(browser, async (page, st, init_ms) => {
		let error = null, res = {};
		try {
			await page.evaluate(([u, t]) => window.__sim.go(u, t), [c.origin_url, TIMEOUT]);
			const fr = childFrame(page);
			const cpu0 = cfg.trace ? cpuSnap() : null;
			res = await fr.evaluate(async ([u, range, t]) => {
				const ac = new AbortController();
				const timer = setTimeout(() => ac.abort(), t);
				const t0 = performance.now();
				const e0 = performance.timeOrigin + t0; // epoch ms, comparable with the host page's WS tap
				const r = await fetch(u, { signal: ac.signal, headers: range ? { Range: range } : {} });
				const reader = r.body.getReader();
				let n = 0, tfirst = null;
				for (;;) {
					const { done, value } = await reader.read();
					if (done) break;
					if (tfirst === null) tfirst = performance.now();
					n += value.byteLength;
				}
				clearTimeout(timer);
				const t1 = performance.now();
				return { status: r.status, bytes: n, secs: (t1 - t0) / 1000, ttfb_ms: Math.round((tfirst ?? t1) - t0), e0, e1: performance.timeOrigin + t1 };
			}, [c.url, c.range ?? null, c.download_timeout_ms ?? 120000]);
			if (cpu0) res.cpu = cpuDelta(cpu0, cpuSnap()); // whole download: is the client or the server the bottleneck?
			if (cfg.trace) {
				try {
					const tap = await page.evaluate(() => window.__sim.tap);
					res.frames = frameStats(tap, res.e0, res.e1);
					res.trace_file = saveTrace(c.site, { e0: res.e0, e1: res.e1, tap, frames: res.frames });
				} catch (e) { res.trace_error = String(e).slice(0, 200); }
			}
			if (res.status >= 400) error = `HTTP ${res.status}`;
			else if (c.expect_bytes && res.bytes !== c.expect_bytes) error = `got ${res.bytes} bytes, expected ${c.expect_bytes}`;
		} catch (e) { error = String(e.message || e).slice(0, 300); }
		const mib_s = res.secs ? +(res.bytes / 1048576 / res.secs).toFixed(2) : null;
		return { ok: !error, error, init_ms, bytes: res.bytes ?? 0, secs: res.secs ?? null, ttfb_ms: res.ttfb_ms ?? null,
			mib_s: error ? null : mib_s, status: res.status ?? null, cpu: res.cpu ?? undefined,
			frames: res.frames ?? undefined, trace_file: res.trace_file ?? undefined, leaks: st.leaks.length, leak_urls: st.leaks.slice(0, 4), leak_all: st.leaks.slice(0, 200), websockets: st.websockets, console_errors: st.console_errors };
	});
}

// A short person-like session: open, scroll, click an in-page link, go back.
async function caseSession(browser, c) {
	return withSim(browser, async (page, st, init_ms) => {
		const steps = [];
		let error = null;
		const step = async (name, fn) => {
			const t0 = Date.now();
			try { await fn(); steps.push({ step: name, ms: Date.now() - t0, ok: true }); }
			catch (e) { steps.push({ step: name, ms: Date.now() - t0, ok: false, error: String(e.message || e).slice(0, 200) }); throw e; }
		};
		try {
			await step("open", () => page.evaluate(([u, t]) => window.__sim.go(u, t), [c.url, TIMEOUT]));
			await step("scroll", async () => {
				await page.mouse.move(600, 400);
				for (let i = 0; i < 6; i++) { await page.mouse.wheel(0, 700); await page.waitForTimeout(250); }
			});
			// navigation inside the proxied frame: wait for the next iframe load event (counted by main.mjs)
			const nav = async (action) => {
				const n = await page.evaluate(() => window.__sim.loads);
				await action();
				await page.waitForFunction((n) => window.__sim.loads > n, n, { timeout: TIMEOUT });
			};
			await step("click", () => nav(() => childFrame(page).locator(c.link_selector).first().click({ timeout: 10000 })));
			await step("back", () => nav(() => page.evaluate(() => window.__sim.frame.back())));
		} catch (e) { error = steps.find((s) => !s.ok)?.step + ": " + String(e.message || e).slice(0, 200); }
		await settle(st, SETTLE);
		const doc = await snapshotDoc(page);
		const total = steps.filter((s) => s.step !== "scroll").reduce((a, s) => a + s.ms, 0);
		return { ok: !error, error, init_ms, load_ms: error ? null : total, steps, ...doc, ...counts(st) };
	});
}

// A page script's WebSocket: open, send N text messages, expect each echoed back (the proxy carries it over Wisp).
async function caseWebsocket(browser, c) {
	return withSim(browser, async (page, st, init_ms) => {
		let error = null, res = {};
		try {
			await page.evaluate(([u, t]) => window.__sim.go(u, t), [c.origin_url, TIMEOUT]);
			res = await childFrame(page).evaluate(([u, n, t]) => new Promise((resolve) => {
				const t0 = performance.now(); let got = 0, opened = null;
				const ws = new WebSocket(u);
				const timer = setTimeout(() => { try { ws.close(); } catch {} resolve({ error: `timeout after ${got}/${n} echoes`, got }); }, t);
				const want = Array.from({ length: n }, (_, i) => "fw-sim-" + i + "-" + "x".repeat(i * 37));
				let bad = 0;
				// epoxy/epoxy-v2 (all servers) hold the LAST sent frame until the next send (2026-10-24: always 19/20, and a
				// probe sent 2 s later releases it). Probe once if exactly the last echo is missing after 3 s, and flag it
				// (held_last_frame) instead of failing: the case is about the Wisp server, which cannot see that frame.
				let held = false;
				ws.onopen = () => { opened = performance.now() - t0; for (const m of want) ws.send(m);
					setTimeout(() => { if (got === n - 1) { held = true; ws.send("probe-after-held-frame"); } }, 3000); };
				// echo.websocket.org sends a greeting first; count only our payloads, in order and byte-exact
				ws.onmessage = (ev) => { const d = String(ev.data); if (!d.startsWith("fw-sim-")) return;
					if (d === want[got]) got++; else { bad++; clearTimeout(timer); ws.close(); resolve({ error: `echo ${got} mismatch (${d.length} chars)`, got }); return; }
					if (got === n) { clearTimeout(timer); ws.close(); resolve({ got, held, open_ms: Math.round(opened), ms: Math.round(performance.now() - t0) }); } };
				ws.onerror = () => { clearTimeout(timer); resolve({ error: "websocket error", got }); };
			}), [c.url, c.messages ?? 20, 20000]);
			error = res.error ?? null;
		} catch (e) { error = String(e.message || e).slice(0, 300); }
		return { ok: !error, error, init_ms, load_ms: error ? null : res.ms, open_ms: res.open_ms ?? null, echoes: res.got ?? 0, held_last_frame: res.held ?? undefined,
			leaks: st.leaks.length, leak_urls: st.leaks.slice(0, 4), leak_all: st.leaks.slice(0, 200), console_errors: st.console_errors };
	});
}

// ---------------------------------------------------------------- trace (cfg.trace; busy + download cases)
// CDP side: per proxied request [start, response headers, first/last body chunk, end] (CDP monotonic seconds,
// converted with the wallTime of the first request). WS frames are NOT taken from CDP: webSocketFrameReceived
// base64-copies every payload on the renderer main thread (review), which would load the client more for the
// server that delivers more bulk bytes. The page's WS tap (main.mjs) and `ss` socket polling replace it.
function traceCdp(cdp, st, proxied) {
	const tr = (st.tr = { off: null, req: new Map() });
	const R = (id) => tr.req.get(id);
	cdp.on("Network.requestWillBeSent", (ev) => {
		if (tr.off === null && ev.wallTime) tr.off = ev.wallTime * 1000 - ev.timestamp * 1000;
		if (proxied(ev.request.url)) tr.req.set(ev.requestId, { url: decodeSj(ev.request.url), type: ev.type, t0: ev.timestamp, bytes: 0 });
	});
	cdp.on("Network.responseReceived", (ev) => { const r = R(ev.requestId); if (r) { r.tresp = ev.timestamp; r.status = ev.response.status; } });
	cdp.on("Network.dataReceived", (ev) => { const r = R(ev.requestId); if (r) { r.bytes += ev.dataLength; r.tfirst ??= ev.timestamp; r.tlast = ev.timestamp; } });
	cdp.on("Network.loadingFinished", (ev) => { const r = R(ev.requestId); if (r) r.tend = ev.timestamp; });
	cdp.on("Network.loadingFailed", (ev) => { const r = R(ev.requestId); if (r) { r.tend = ev.timestamp; r.failed = ev.errorText; } });

}

// CPU of every thread of this run's Chromium (descendants of this node process) and of the Wisp server, from /proc.
const HZ = 100; // USER_HZ on Linux
function procStat(path) {
	try {
		const t = fs.readFileSync(path, "utf8"), i = t.lastIndexOf(")");
		const f = t.slice(i + 2).split(" ");
		return { comm: t.slice(t.indexOf("(") + 1, i), ppid: +f[1], ticks: +f[11] + +f[12] };
	} catch { return null; }
}
function chromePids() {
	const kids = new Map();
	for (const d of fs.readdirSync("/proc")) {
		if (!/^\d+$/.test(d)) continue;
		const s = procStat(`/proc/${d}/stat`);
		if (s) (kids.get(s.ppid) ?? kids.set(s.ppid, []).get(s.ppid)).push(+d);
	}
	const out = [], todo = [process.pid];
	while (todo.length) for (const k of kids.get(todo.pop()) ?? []) { out.push(k); todo.push(k); }
	return out;
}
function procType(pid) {
	try {
		// zygote children (renderers) get a setproctitle-style cmdline: one string with spaces, not NUL-separated
		const a = fs.readFileSync(`/proc/${pid}/cmdline`, "utf8").split(/[\0 ]/);
		if (!a[0].includes("chrom")) return null; // e.g. our own ss processes
		const t = a.find((x) => x.startsWith("--type="));
		if (!t) return "browser";
		const sub = a.find((x) => x.startsWith("--utility-sub-type="));
		return t.slice(7) + (sub ? ":" + sub.split(".").pop() : "");
	} catch { return "?"; }
}
function cpuSnap() {
	const th = new Map();
	for (const pid of chromePids()) {
		const type = procType(pid);
		if (!type) continue;
		let tasks = [];
		try { tasks = fs.readdirSync(`/proc/${pid}/task`); } catch {}
		for (const tid of tasks) {
			const s = procStat(`/proc/${pid}/task/${tid}/stat`);
			if (!s) continue;
			const k = `${type}/${s.comm}`;
			th.set(k, (th.get(k) ?? 0) + s.ticks);
		}
	}
	const srv = cfg.server_pid ? procStat(`/proc/${cfg.server_pid}/stat`) : null;
	return { t: performance.now(), th, server: srv ? srv.ticks : null };
}
function cpuDelta(a, b) {
	const secs = (b.t - a.t) / 1000, cores = (x) => +(x / HZ / secs).toFixed(3);
	const threads = [...b.th].map(([k, v]) => [k, v - (a.th.get(k) ?? 0)]).filter(([, v]) => v > 0).sort((x, y) => y[1] - x[1]);
	const byType = {};
	for (const [k, v] of threads) { const t = k.split("/")[0]; byType[t] = (byType[t] ?? 0) + v; }
	return { secs: +secs.toFixed(3), server_cores: a.server == null || b.server == null ? null : cores(b.server - a.server),
		chrome_cores: cores(threads.reduce((s, [, v]) => s + v, 0)),
		by_type: Object.fromEntries(Object.entries(byType).map(([k, v]) => [k, cores(v)])),
		top_threads: threads.slice(0, 8).map(([k, v]) => [k, cores(v)]) };
}
async function mainThread(cdp) {
	const m = Object.fromEntries((await cdp.send("Performance.getMetrics")).metrics.map((x) => [x.name, x.value]));
	return { task: m.TaskDuration, script: m.ScriptDuration, layout: m.LayoutDuration, style: m.RecalcStyleDuration };
}
const q = (xs, p) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };
const r1 = (x) => (x == null ? null : Math.round(x * 10) / 10);

// Summary of one traced page load [w0, w1] (epoch ms) while a bulk download runs on the same Wisp connection.
function traceSummary(st, tap, w0, w1, cpu, mt0, mt1) {
	const tr = st.tr, ep = (ts) => ts * 1000 + tr.off;
	const total = new Map();
	for (const [, ty, sid, n] of tap.in) if (ty === 2) total.set(sid, (total.get(sid) ?? 0) + n);
	const bulk = [...total].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
	const win = tap.in.filter(([t]) => t >= w0 && t <= w1);
	const sizes = (rows) => rows.filter(([, ty, sid]) => ty === 2 && sid === bulk).map((x) => x[3]);
	const bulkAll = sizes(tap.in);
	// streams the page opened during its load: CONNECT (client) -> first DATA -> CLOSE (server)
	const streams = [];
	for (const [t, ty, sid] of tap.out) {
		if (ty !== 1 || t < w0 || t > w1) continue;
		const rows = tap.in.filter((x) => x[2] === sid && x[0] >= t);
		const fd = rows.find((x) => x[1] === 2), cl = rows.find((x) => x[1] === 4);
		streams.push({ sid, first_data_ms: fd ? fd[0] - t : null, close_ms: cl ? cl[0] - t : null, bytes: rows.filter((x) => x[1] === 2).reduce((s, x) => s + x[3], 0) });
	}
	const reqs = [...tr.req.values()].filter((r) => ep(r.t0) >= w0 - 5 && ep(r.t0) <= w1);
	const ttfb = reqs.filter((r) => r.tresp).map((r) => (r.tresp - r.t0) * 1000);
	const dur = reqs.filter((r) => r.tend).map((r) => (r.tend - r.t0) * 1000);
	const winMs = w1 - w0;
	return {
		window_ms: Math.round(winMs),
		bulk_sid: bulk,
		ws_in_msgs: win.length,
		bulk_js_mib_s: r1(win.filter((x) => x[1] === 2 && x[2] === bulk).reduce((s, x) => s + x[3], 0) / 1048576 / (winMs / 1000)),
		bulk_bytes_in_window: win.filter((x) => x[1] === 2 && x[2] === bulk).reduce((s, x) => s + x[3], 0),
		other_bytes_in_window: win.filter((x) => x[1] === 2 && x[2] !== bulk).reduce((s, x) => s + x[3], 0),
		bulk_msg_bytes: { p50: q(bulkAll, 0.5), max: q(bulkAll, 1), n: bulkAll.length },
		page_streams: { n: streams.length, first_data_ms_p50: r1(q(streams.map((x) => x.first_data_ms).filter((x) => x != null), 0.5)),
			first_data_ms_max: r1(q(streams.map((x) => x.first_data_ms).filter((x) => x != null), 1)),
			close_ms_max: r1(q(streams.map((x) => x.close_ms).filter((x) => x != null), 1)) },
		frames_js: tap.in.length,
		pipeline: pipelineSplit(st.ss, tap, w0, w1, streams),
		requests: { n: reqs.length, ttfb_ms_p50: r1(q(ttfb, 0.5)), ttfb_ms_max: r1(q(ttfb, 1)), dur_ms_p50: r1(q(dur, 0.5)), dur_ms_max: r1(q(dur, 1)) },
		cpu,
		main_thread_busy: mt0 && mt1 ? +((mt1.task - mt0.task) / (winMs / 1000)).toFixed(3) : null,
		main_thread_script: mt0 && mt1 ? +((mt1.script - mt0.script) / (winMs / 1000)).toFixed(3) : null,
	};
}

// Socket polling (no root, sockpoll.py): kernel view of the Wisp socket pair and of the server's origin sockets,
// ~2-3 ms apart. Per sample [epoch ms, server app bytes written (bytes_acked + Send-Q), server notsent,
// client kernel bytes received, client Recv-Q (received, not yet read by Chromium), origin Recv-Q sum (origin
// bytes the server has not read yet)]. With the WS tap this splits the delay of a page response into
// "server had not written it yet" and "written, but queued in the kernel / inside Chromium behind bulk bytes".
function startSs(wport, mport) {
	// sockpoll.py: exact sock_diag lookups every ~2 ms (ss costs ~70 ms per call here, too coarse)
	const samples = [];
	const ch = spawn("python3", [path.join(HERE, "sockpoll.py"), String(wport), String(mport ?? 0)], { stdio: ["pipe", "pipe", "inherit"] });
	let buf = "";
	ch.stdout.on("data", (d) => {
		buf += d;
		let k;
		while ((k = buf.indexOf("\n")) >= 0) { const l = buf.slice(0, k); buf = buf.slice(k + 1); try { samples.push(JSON.parse(l)); } catch {} }
	});
	const done = new Promise((r) => ch.on("close", r));
	// the first sample must be taken while the connection is idle (it anchors the byte offsets: hs_bytes)
	const first = new Promise((r) => { const t = setInterval(() => { if (samples.length) { clearInterval(t); r(); } }, 2); setTimeout(() => { clearInterval(t); r(); }, 3000); });
	return { samples, first, stop: async () => { ch.stdin.end(); ch.kill("SIGTERM"); await done; } };
}

// WS wire size of a server->client message (unmasked): 2-byte header, +2 for 126..65535, +8 above
const wsWire = (n) => n + 2 + (n > 125 ? 2 : 0) + (n > 65535 ? 6 : 0);

function pipelineSplit(ss, tap, w0, w1, streams) {
	if (!ss || ss.length < 3) return null;
	// cumulative wire offset (end) of every received message, aligned to the kernel byte count with the first sample
	// in which all bytes the client received were dispatched (no backlog): offset = bytes_received - dispatched.
	let cum = 0;
	const ends = tap.in.map((x) => (cum += wsWire(x[3])));
	const dispatchedBy = (t) => { let lo = 0, hi = tap.in.length; while (lo < hi) { const m = (lo + hi) >> 1; if (tap.in[m][0] <= t) lo = m + 1; else hi = m; } return lo ? ends[lo - 1] : 0; };
	const hs = ss[0][3] - ss[0][4] - dispatchedBy(ss[0][0]); // first sample taken while idle: = HTTP 101 response bytes
	const inWin = ss.filter((s) => s[0] >= w0 && s[0] <= w1);
	const gaps = inWin.slice(1).map((s, k) => s[0] - inWin[k][0]);
	const back = inWin.map((s) => ({ server_q: s[1] - s[3], kernel_rq: s[4], chromium: Math.max(0, s[3] - s[4] - hs - dispatchedBy(s[0])), origin_rq: s[5] }));
	const med = (k) => q(back.map((b) => b[k]), 0.5), mx = (k) => q(back.map((b) => b[k]), 1);
	// per page stream: when did the server have its first DATA written (first sample with written >= its wire end)
	const split = [];
	for (const st of streams) {
		const idx = tap.in.findIndex((x) => x[2] === st.sid && x[1] === 2);
		if (idx < 0 || st.first_data_ms == null) continue;
		const end = ends[idx] + hs, tjs = tap.in[idx][0], tsend = tjs - st.first_data_ms;
		const w = ss.find((s) => s[1] >= end);
		if (!w) continue;
		split.push({ sid: st.sid, server_ms: Math.max(0, w[0] - tsend), client_ms: Math.max(0, tjs - w[0]) });
	}
	return {
		samples: inWin.length, poll_ms_p50: r1(q(gaps, 0.5)), poll_ms_max: r1(q(gaps, 1)), hs_bytes: hs,
		backlog_kb_p50: { server_q: r1(med("server_q") / 1000), kernel_rq: r1(med("kernel_rq") / 1000), chromium: r1(med("chromium") / 1000), origin_rq: r1(med("origin_rq") / 1000) },
		backlog_kb_max: { server_q: r1(mx("server_q") / 1000), kernel_rq: r1(mx("kernel_rq") / 1000), chromium: r1(mx("chromium") / 1000), origin_rq: r1(mx("origin_rq") / 1000) },
		// first page DATA: time until the server had written it (server side) / from written to JS dispatch (client side);
		// resolution = poll interval
		first_data_split_p50: { server_ms: r1(q(split.map((x) => x.server_ms), 0.5)), client_ms: r1(q(split.map((x) => x.client_ms), 0.5)) },
		first_data_split_max: { server_ms: r1(q(split.map((x) => x.server_ms), 1)), client_ms: r1(q(split.map((x) => x.client_ms), 1)) },
		n_split: split.length,
	};
}

// Wisp frame sizes of a download (the stream with the most DATA in [e0, e1]) and the client DATA the transport sent
// meanwhile (TLS records / HTTP/2 WINDOW_UPDATEs of the request's stream, or other streams): an adaptive server cap that
// reacts to client DATA would see these.
function frameStats(tap, e0, e1) {
	const win = tap.in.filter((x) => x[0] >= e0 && x[0] <= e1 && x[1] === 2);
	const per = new Map();
	for (const x of win) per.set(x[2], (per.get(x[2]) ?? 0) + x[3]);
	const sid = [...per].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
	const sz = win.filter((x) => x[2] === sid).map((x) => x[3]);
	const hist = { le16k: 0, le64k: 0, gt64k: 0 };
	let bytesGt = 0;
	for (const n of sz) { if (n <= 16384) hist.le16k++; else if (n <= 65535) hist.le64k++; else { hist.gt64k++; bytesGt += n; } }
	const out = tap.out.filter((x) => x[0] >= e0 && x[0] <= e1 && x[1] === 2);
	const outSid = out.filter((x) => x[2] === sid);
	// longest gap between client DATA frames on the connection during the download (a 500 ms window cap expires in gaps)
	let gap = 0, last = e0;
	for (const x of out) { gap = Math.max(gap, x[0] - last); last = x[0]; }
	gap = Math.max(gap, e1 - last);
	return { sid, frames: sz.length, hist, max: sz.length ? Math.max(...sz) : 0, p50: q(sz, 0.5),
		share_bytes_gt64k: sz.length ? +(bytesGt / sz.reduce((a, b) => a + b, 0)).toFixed(3) : 0,
		client_data_frames: out.length, client_data_bytes: out.reduce((a, x) => a + x[3], 0),
		client_data_frames_same_stream: outSid.length, client_data_max_gap_ms: Math.round(gap) };
}

function saveTrace(name, obj) {
	if (!cfg.trace_dir) return null;
	fs.mkdirSync(cfg.trace_dir, { recursive: true });
	const f = path.join(cfg.trace_dir, `${cfg.trace_prefix ?? "trace"}-${name}.json`);
	fs.writeFileSync(f, JSON.stringify(obj));
	return f;
}

// A busy user on one Wisp connection: a big download runs in a second frame; meanwhile the user starts another
// download and cancels it after 1 s (client-side stream close mid-transfer), fetches small files on the same
// connection, then opens a page. Measures page load under load and checks the background download is intact.
async function caseBusy(browser, c) {
	return withSim(browser, async (page, st, init_ms) => {
		let error = null, ssPoll = null; const out = {};
		const frameOf = async (sel) => (await page.$(sel)).contentFrame();
		try {
			await page.evaluate(([u, t]) => window.__sim.go(u, t), [c.origin_url, TIMEOUT]);
			await page.evaluate(([u, t]) => window.__sim.frame2().go(u, t), [c.origin_url, TIMEOUT]);
			const f2 = await frameOf("#f2");
			const wport = +new URL(cfg.wisp_url).port;
			if (cfg.trace) { ssPoll = startSs(wport, cfg.mirror_port); await ssPoll.first; }
			// background download (not awaited here)
			await f2.evaluate((u) => {
				window.__bg = { bytes: 0, done: false, error: null, t0: performance.now(), ac: new AbortController() };
				(async () => {
					try {
						const r = await fetch(u, { signal: window.__bg.ac.signal });
						if (!r.ok) throw new Error("HTTP " + r.status);
						const rd = r.body.getReader();
						for (;;) { const { done, value } = await rd.read(); if (done) break; window.__bg.bytes += value.byteLength; }
					} catch (e) { if (!window.__bg.stopped) window.__bg.error = String(e); }
					window.__bg.done = true; window.__bg.secs = (performance.now() - window.__bg.t0) / 1000;
				})();
			}, c.big_url);
			const f1 = await frameOf("#f");
			// cancel a second download once cancel_after_bytes arrived (client closes the stream mid-transfer),
			// then use the connection for small fetches (each with its own timeout)
			Object.assign(out, await f1.evaluate(async ([big, small, n, limit]) => {
				const ac = new AbortController();
				let got = 0, aborted = false, err = null;
				try {
					const r = await fetch(big, { signal: ac.signal });
					const rd = r.body.getReader();
					for (;;) {
						const { done, value } = await rd.read(); if (done) break;
						got += value.byteLength;
						if (got >= limit) { ac.abort(); }
					}
				} catch (e) { if (e.name === "AbortError" && got >= limit) aborted = true; else err = String(e); }
				const small_ms = [];
				for (let i = 0; i < n; i++) {
					const t0 = performance.now();
					const r = await fetch(small + (small.includes("?") ? "&" : "?") + "fwsim=" + i, { cache: "no-store", signal: AbortSignal.timeout(15000) });
					await r.arrayBuffer();
					if (!r.ok) throw new Error("small fetch HTTP " + r.status);
					small_ms.push(Math.round(performance.now() - t0));
				}
				return { cancelled_after_bytes: got, cancel_ok: aborted, cancel_error: err, small_ms };
			}, [c.cancel_url ?? c.big_url, c.small_url, c.small_n ?? 5, c.cancel_after_bytes ?? 4194304]));
			if (!out.cancel_ok) throw new Error(`cancel: ${out.cancel_error ?? "download ended before the cancel"} (${out.cancelled_after_bytes} B)`);
			const bgBefore = await f2.evaluate(() => window.__bg.bytes);
			let cpu0, mt0;
			if (cfg.trace) { await st.cdp.send("Performance.enable").catch(() => {}); mt0 = await mainThread(st.cdp).catch(() => null); cpu0 = cpuSnap(); }
			out.load_ms = Math.round(await page.evaluate(([u, t]) => window.__sim.go(u, t), [c.url, TIMEOUT]));
			if (cfg.trace) {
				const cpu = cpuDelta(cpu0, cpuSnap()), mt1 = await mainThread(st.cdp).catch(() => null);
				await ssPoll.stop(); st.ss = ssPoll.samples; ssPoll = null;
				const win = await page.evaluate(() => window.__sim.lastGo);
				out.trace_window = { w0: win.t0, w1: win.t1, cpu, mt0, mt1 };
			}
			const bgAfter = await f2.evaluate(() => ({ bytes: window.__bg.bytes, done: window.__bg.done }));
			out.bg_bytes_at_page_load = bgAfter.bytes - bgBefore;
			out.bg_active_during_load = !bgAfter.done; // false: the page load was not measured under load
			// bg_stop_after_load: an "endless" background download is cancelled once the page loaded (timing mode)
			if (c.bg_stop_after_load) await f2.evaluate(() => { window.__bg.stopped = true; window.__bg.ac.abort(); });
			await f2.waitForFunction(() => window.__bg.done, null, { timeout: c.download_timeout_ms ?? 180000 });
			const bg = await f2.evaluate(() => { const { ac, ...rest } = window.__bg; return rest; });
			out.bg_bytes = bg.bytes; out.bg_mib_s = bg.secs ? +(bg.bytes / 1048576 / bg.secs).toFixed(2) : null;
			if (bg.error) throw new Error("background download: " + bg.error);
			if (c.expect_bytes && !c.bg_stop_after_load && bg.bytes !== c.expect_bytes) throw new Error(`background download: ${bg.bytes} bytes, expected ${c.expect_bytes}`);
			const doc = await snapshotDoc(page);
			out.title = doc.title; out.text_len = doc.text_len;
			if (doc.text_len < (c.min_text ?? 200)) throw new Error(`page text ${doc.text_len} chars`);
		} catch (e) { error = String(e.message || e).slice(0, 300); }
		if (ssPoll) await ssPoll.stop();
		if (out.trace_window) {
			const { w0, w1, cpu, mt0, mt1 } = out.trace_window;
			delete out.trace_window;
			try {
				const tap = await page.evaluate(() => window.__sim.tap);
				out.trace = traceSummary(st, tap, w0, w1, cpu, mt0, mt1);
				out.trace_file = saveTrace(`${c.site}`, { w0, w1, off: st.tr.off, tap, ss: st.ss, req: [...st.tr.req.values()], summary: out.trace });
			} catch (e) { out.trace_error = String(e).slice(0, 200); }
		}
		return { ok: !error, error, init_ms, ...out, load_ms: error ? null : out.load_ms, ...counts(st) };
	});
}

// Pass/fail rules applied to every case after it ran (adds an error only if the case had none).
// Compat: the right document (expect_title, main document status < 400). Timing (local mirror): also no request
// may fail, return 5xx or leave the mirror; session and busy cancel requests on purpose, so only 5xx/external count.
function judge(c, r) {
	if (r.error) return r;
	const bad = [];
	if (c.expect_title && !String(r.title ?? "").toLowerCase().includes(c.expect_title.toLowerCase()))
		bad.push(`title ${JSON.stringify(r.title)} lacks ${JSON.stringify(c.expect_title)}`);
	if (r.doc_status >= 400) bad.push(`document HTTP ${r.doc_status}`);
	if (r.leaks) {
		// known Scramjet leaks (sites.json allow_leaks, regexes) are recorded but do not fail the case: they are not the
		// Wisp server's fault, and the rest of the page still went through Wisp
		const allow = (c.allow_leaks ?? []).map((x) => new RegExp(x));
		const all = r.leak_all ?? r.leak_urls ?? [];
		const unknown = all.filter((u) => !allow.some((re) => re.test(u.replace(/^(request|websocket) /, ""))));
		if (unknown.length) bad.push(`${unknown.length} requests escaped the proxy (went direct, not through Wisp): ${unknown.slice(0, 3).join(" ")}`);
	}
	if (cfg.mirror_dir) {
		if (c.case === "busy" && r.bg_active_during_load === false) bad.push("background download ended before the page load: not measured under load");
		// the page reader can lag far behind the Wisp stream (the transport does not apply backpressure): with --trace,
		// "under load" means bulk DATA actually arrived at the Wisp level during the page load
		if (c.case === "busy" && r.trace && !r.trace.bulk_bytes_in_window) bad.push("no bulk DATA on the Wisp connection during the page load (the download had already been delivered): not measured under load");
		if (r.external_requests) bad.push(`${r.external_requests} requests left the mirror: ${r.external_urls?.join(" ")}`);
		if (r.http_5xx) bad.push(`${r.http_5xx} responses 5xx`);
		if ((c.case === "page" || c.case === "download") && r.failed_requests) bad.push(`${r.failed_requests} requests failed: ${r.failures?.slice(0, 2).join(" ")}`);
		if (c.case === "page" && r.still_pending) bad.push(`${r.still_pending} requests still pending`);
	}
	if (!bad.length) return r;
	const out = { ...r, ok: false, error: bad.join("; ").slice(0, 400) };
	for (const k of ["load_ms", "mib_s"]) if (k in out) out[k] = null; // medians never include failed reps
	return out;
}

process.on("unhandledRejection", (e) => process.stderr.write("unhandledRejection: " + String(e).slice(0, 300) + "\n"));

const RUN = { busy: caseBusy, websocket: caseWebsocket, page: casePage, download: caseDownload, session: caseSession };

if (SELFTEST) {
	// bulk stream 7 sends 64 KiB frames every 2 ms; the page opens streams 9, 11 at t=100/120 ms, data 30 ms later
	const T = 1_000_000, tap = { in: [], out: [] };
	for (let t = 0; t < 400; t += 2) tap.in.push([T + t, 2, 7, 65535]);
	tap.out.push([T + 100, 1, 9, 30], [T + 120, 1, 11, 30]);
	tap.in.push([T + 130, 2, 9, 5000], [T + 150, 2, 11, 7000], [T + 160, 4, 9, 6], [T + 170, 4, 11, 6]);
	tap.in.sort((a, b) => a[0] - b[0]);
	// server writes every message 3 ms before the page sees it; ss sampled every 1 ms; 150-byte HTTP 101 first
	const ss = [];
	for (let t = T - 5; t < T + 400; t += 1) {
		let w = 150;
		for (const x of tap.in) if (x[0] - 3 <= t) w += wsWire(x[3]);
		ss.push([t, w, 0, w, 0, 0]);
	}
	const st = { ss, tr: { off: 500, req: new Map([["r1", { url: "x", t0: (T + 90 - 500) / 1000, tresp: (T + 140 - 500) / 1000, tend: (T + 175 - 500) / 1000, bytes: 9 }]]) } };
	const a = cpuSnap(); let x = 0; for (let i = 0; i < 3e7; i++) x += i; const b = cpuSnap();
	const sum = traceSummary(st, tap, T + 90, T + 200, cpuDelta(a, b), { task: 1, script: 0.5 }, { task: 1.055, script: 0.6 });
	console.log(JSON.stringify(sum, null, 1));
	const ok = sum.bulk_sid === 7 && sum.page_streams.n === 2 && sum.page_streams.first_data_ms_p50 === 30
		&& sum.pipeline.hs_bytes === 150 && sum.pipeline.first_data_split_p50.server_ms === 27 && sum.pipeline.first_data_split_p50.client_ms === 3
		&& sum.other_bytes_in_window === 12000 && sum.requests.ttfb_ms_max === 50 && sum.main_thread_busy === 0.5;
	const fsx = frameStats({ in: [[10, 2, 5, 262149], [20, 2, 5, 65535], [30, 2, 5, 1000], [25, 2, 7, 500]], out: [[15, 2, 5, 40], [400, 2, 9, 10]] }, 0, 1000);
	console.log(JSON.stringify(fsx));
	const ok2 = fsx.sid === 5 && fsx.hist.gt64k === 1 && fsx.hist.le64k === 1 && fsx.hist.le16k === 1 && fsx.client_data_frames === 2
		&& fsx.client_data_frames_same_stream === 1 && fsx.client_data_max_gap_ms === 600;
	console.log(ok && ok2 ? "SELFTEST OK" : "SELFTEST FAIL");
	process.exit(ok && ok2 ? 0 : 1);
}
if (MIRROR_ONLY) {
	await startMirrorServer();
	process.stdout.write(`mirror on 127.0.0.1:${cfg.mirror_port}\n`);
	await new Promise(() => {}); // until killed
}
const servers = [await startPageServer()];
// --tls (browser.py): the Wisp server's self-signed key is the only one whose certificate errors are ignored
const browser = await chromium.launch({ headless: !cfg.headful, args: cfg.spki ? [`--ignore-certificate-errors-spki-list=${cfg.spki}`] : [] });
process.stdout.write("BROWSER " + JSON.stringify({ chromium: browser.version() }) + "\n");
// SIGTERM from browser.py on timeout: close Chromium (it runs in its own process group) before exiting
process.on("SIGTERM", () => { browser.close().finally(() => process.exit(143)); setTimeout(() => process.exit(143), 3000); });
try {
	for (const c of cfg.cases) {
		const t0 = Date.now();
		let r;
		try { r = judge(c, await RUN[c.case](browser, c)); }
		catch (e) { r = { ok: false, error: "harness: " + String(e.message || e).slice(0, 300) }; }
		emit({ case: c.case, site: c.site, rep: c.rep ?? 0, wall_ms: Date.now() - t0, ...r });
	}
} finally {
	await browser.close();
	for (const s of servers) s.close();
}
