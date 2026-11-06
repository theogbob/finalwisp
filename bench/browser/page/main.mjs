// Host page for the browser sim (bench/browser): Scramjet controller + one proxied iframe.
// Query: ?wisp=ws://127.0.0.1:PORT/&transport=epoxy|epoxy-v2|libcurl (epoxy-v2: epoxy with wisp_v2 on; the
// transports default to Wisp v1). Sets window.__sim = {ready, error, go, frame}.
const q = new URLSearchParams(location.search);
const wisp = q.get("wisp");
const transport = q.get("transport") || "epoxy";
window.__sim = { ready: false, error: null, loads: 0 };
// ?trace=1: tap the Wisp WebSocket (the transports create it with the global constructor in this page).
// Per message: [epoch ms at JS dispatch, Wisp type, stream id, bytes]. Cheap: one DataView read per message.
if (q.get("trace")) {
	const tap = (window.__sim.tap = { in: [], out: [] });
	const now = () => performance.timeOrigin + performance.now();
	const head = (d) => {
		const v = d instanceof ArrayBuffer ? new DataView(d) : ArrayBuffer.isView(d) ? new DataView(d.buffer, d.byteOffset, d.byteLength) : null;
		return v && v.byteLength >= 5 ? [v.getUint8(0), v.getUint32(1, true), v.byteLength] : [-1, -1, d?.size ?? d?.length ?? 0];
	};
	const WS = window.WebSocket;
	window.WebSocket = class extends WS {
		constructor(...a) {
			super(...a);
			this.addEventListener("message", (ev) => tap.in.push([now(), ...head(ev.data)]));
		}
		send(d) {
			try { tap.out.push([now(), ...head(d)]); } catch {}
			return super.send(d);
		}
	};
}
try {
	if (!wisp) throw new Error("missing ?wisp=");
	const mod = transport === "libcurl" ? await import("/transports/libcurl.mjs") : await import("/transports/epoxy.mjs");
	const Transport = mod.default;
	const reg = await navigator.serviceWorker.register("/sw.js");
	await navigator.serviceWorker.ready;
	const sw = navigator.serviceWorker.controller ?? reg.active;
	if (!sw) throw new Error("no active service worker");
	const controller = new $scramjetController.Controller({
		serviceworker: sw,
		transport: new Transport(transport === "epoxy-v2" ? { wisp, wisp_v2: true } : { wisp }),
		scramjetConfig: $scramjet.defaultConfig,
	});
	await controller.wait();
	const el = document.getElementById("f");
	const frame = controller.createFrame(el);
	el.addEventListener("load", () => window.__sim.loads++);
	Object.assign(window.__sim, {
		controller, frame, el,
		// navigate the proxied frame; resolves on the iframe load event (or rejects on timeout)
		go: (url, timeoutMs = 60000) => new Promise((resolve, reject) => {
			const t0 = performance.now();
			window.__sim.lastGo = { t0: performance.timeOrigin + t0, t1: null };
			const timer = setTimeout(() => { el.removeEventListener("load", onload); reject(new Error(`load timeout ${timeoutMs} ms`)); }, timeoutMs);
			const onload = () => { clearTimeout(timer); const t1 = performance.now(); window.__sim.lastGo.t1 = performance.timeOrigin + t1; resolve(t1 - t0); };
			el.addEventListener("load", onload, { once: true });
			frame.go(url);
		}),
		// a second proxied frame on the same controller (same transport, same Wisp connection)
		frame2: () => {
			if (window.__sim.f2) return window.__sim.f2;
			const el2 = document.createElement("iframe");
			el2.id = "f2"; el2.style.cssText = "width:400px;height:200px;border:0";
			document.body.append(el2);
			const fr2 = controller.createFrame(el2);
			window.__sim.f2 = {
				go: (url, timeoutMs = 60000) => new Promise((resolve, reject) => {
					const timer = setTimeout(() => reject(new Error(`frame2 load timeout ${timeoutMs} ms`)), timeoutMs);
					el2.addEventListener("load", () => { clearTimeout(timer); resolve(); }, { once: true });
					fr2.go(url);
				}),
			};
			return window.__sim.f2;
		},
		ready: true,
	});
} catch (e) {
	window.__sim.error = String(e && e.stack || e);
	console.error("sim init failed", e);
}
