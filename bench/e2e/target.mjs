// 80.04 L8 target fixture: HTTPS origins + plain HTTP + TCP echo on 127.0.0.1 only (bench/e2e/README.md).
// usage: node target.mjs CERTDIR BASEPORT [--watch-stdin]   (--watch-stdin: exit at stdin EOF, so it dies with its driver)
//   BASE+0..3  TLS origins, ALPN h2 + http/1.1 (http2.createSecureServer, allowHTTP1)
//   BASE+4..7  TLS origins, ALPN http/1.1 only (https.createServer)
//   BASE+8     plain HTTP/1.1 (libcurl.js: it has no CA option, so no HTTPS to our own CA)
//   BASE+9     TCP echo (churn); a client half-close ends the echo socket
//   BASE+20..59  40 more TLS origins, ALPN http/1.1 only (the TLS-heavy workload: a new origin = a new connection per request)
// Routes: GET /o/<bytes> -> exactly <bytes> of body (sliced from one 1 MiB random buffer), any query ignored;
//         GET /bulk/<bytes> -> <bytes> streamed in 256 KiB writes with backpressure;
//         GET /inf -> chunked (no content-length), streams until the client goes away (cap 64 GiB): the busy workload's
//         background download (a 4 GiB content-length overflows epoxy-tls's 32-bit WASM body length: IncompleteBody).
// Prints "READY <pid>" on stdout when every listener is up. Exits on SIGTERM / SIGINT (or stdin EOF with --watch-stdin).
import fs from "node:fs"; import http from "node:http"; import https from "node:https"; import http2 from "node:http2";
import net from "node:net"; import crypto from "node:crypto";

const [certDir, baseArg] = process.argv.slice(2);
const BASE = Number(baseArg);
if (!certDir || !(BASE > 1024 && BASE < 32000)) { console.error("usage: node target.mjs CERTDIR BASEPORT (BASE < 32000)"); process.exit(2); }
const cert = fs.readFileSync(`${certDir}/cert.pem`), key = fs.readFileSync(`${certDir}/key.pem`);
const POOL = crypto.randomBytes(1 << 20);
const CHUNK = 256 << 10;
const MAX = 4 * 2 ** 30;

function handler(req, res) {
  if ((req.url || "").startsWith("/inf")) {
    res.writeHead(200, { "content-type": "application/octet-stream", "cache-control": "no-store" });
    let sent = 0;
    const pump = () => {
      while (sent < 64 * 2 ** 30 && !res.destroyed) {
        sent += CHUNK;
        if (!res.write(POOL.subarray(0, CHUNK))) { res.once("drain", pump); return; }
      }
      res.end();
    };
    res.on("error", () => {}); res.on("close", () => { sent = Infinity; });
    pump();
    return;
  }
  const m = /^\/(o|bulk)\/(\d+)/.exec(req.url || "");
  const n = m ? Number(m[2]) : -1;
  if (!m || !(n >= 0 && n <= MAX)) { res.writeHead(404, { "content-length": "0" }); res.end(); return; }
  res.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(n), "cache-control": "no-store" });
  if (m[1] === "o" && n <= POOL.length) { res.end(POOL.subarray(0, n)); return; }
  let left = n;
  const pump = () => {
    while (left > 0) {
      const k = Math.min(CHUNK, left);
      left -= k;
      if (!res.write(POOL.subarray(0, k))) { res.once("drain", pump); return; }
    }
    res.end();
  };
  res.on("error", () => {});
  pump();
}

const servers = [];
const listen = (srv, port) => new Promise((ok, bad) => { srv.once("error", bad); srv.listen(port, "127.0.0.1", ok); servers.push(srv); });
for (let i = 0; i < 4; i++) {
  const s = http2.createSecureServer({ cert, key, allowHTTP1: true, settings: { maxConcurrentStreams: 256 } }, handler);
  s.on("sessionError", () => {}); s.on("tlsClientError", () => {});
  await listen(s, BASE + i);
}
for (let i = 4; i < 8; i++) {
  const s = https.createServer({ cert, key, ALPNProtocols: ["http/1.1"], keepAliveTimeout: 30000 }, handler);
  s.on("tlsClientError", () => {});
  await listen(s, BASE + i);
}
for (let i = 20; i < 60; i++) {
  const s = https.createServer({ cert, key, ALPNProtocols: ["http/1.1"], keepAliveTimeout: 30000 }, handler);
  s.on("tlsClientError", () => {});
  await listen(s, BASE + i);
}
{ const s = http.createServer({ keepAliveTimeout: 30000 }, handler); await listen(s, BASE + 8); }
{
  const s = net.createServer({ allowHalfOpen: true }, c => {
    c.setNoDelay(true); c.on("error", () => {});
    c.on("data", d => c.write(d)); c.on("end", () => c.end());
  });
  await listen(s, BASE + 9);
}
const quit = () => { for (const s of servers) try { s.close(); } catch {} process.exit(0); };
process.on("SIGTERM", quit); process.on("SIGINT", quit);
if (process.argv[4] === "--watch-stdin") { process.stdin.on("end", quit); process.stdin.resume(); }
console.log(`READY ${process.pid}`);
