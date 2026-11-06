// 40.01 compat test: real wisp-js client (v1 + v2) against a Wisp server.
// usage: node wispjs.mjs ws://127.0.0.1:PORT/ [blocked_url]
import { client } from "@mercuryworkshop/wisp-js/client";
import net from "node:net";
import crypto from "node:crypto";

const url = process.argv[2];
const blockedUrl = process.argv[3];
let failures = 0;
const ok = (c, m) => { console.log(`${c ? "PASS" : "FAIL"} ${m}`); if (!c) failures++; };

// local echo server; "BYE" makes it end the socket (target EOF path)
const echo = net.createServer(s => {
  s.setNoDelay(true);
  s.on("data", d => { if (d.toString().endsWith("BYE")) s.end(d); else s.write(d); });
  s.on("error", () => {});
});
await new Promise(r => echo.listen(0, "127.0.0.1", r));
const ECHO = echo.address().port;
// "source" target: streams TOTAL bytes where every u32 word = its own word offset (detects loss/reorder/dup)
const SRC_TOTAL = 64 << 20;
function patternChunk(wordOff, bytes) {
  const b = Buffer.allocUnsafe(bytes);
  const u = new Uint32Array(b.buffer, b.byteOffset, bytes / 4);
  for (let i = 0; i < u.length; i++) u[i] = wordOff + i;
  return b;
}
const source = net.createServer(s => {
  s.setNoDelay(true); s.on("error", () => {});
  let off = 0;
  const pump = () => {
    while (off < SRC_TOTAL) {
      const n = Math.min(1 << 20, SRC_TOTAL - off);
      const ok = s.write(patternChunk(off / 4, n)); off += n;
      if (!ok) { s.once("drain", pump); return; }
    }
    s.end();
  };
  pump();
});
await new Promise(r => source.listen(0, "127.0.0.1", r));
const SRC = source.address().port;

function streamDownload(conn, host) {
  return new Promise(res => {
    const s = conn.create_stream(host, SRC);
    let got = 0, bad = -1, carry = Buffer.alloc(0);
    const t = setTimeout(() => res({ ok: false, why: `timeout got ${got}/${SRC_TOTAL}` }), 60000);
    s.onmessage = d => {
      let b = carry.length ? Buffer.concat([carry, Buffer.from(d)]) : Buffer.from(d);
      const whole = b.length - (b.length % 4);
      for (let i = 0; i < whole && bad < 0; i += 4) if (b.readUInt32LE(i) !== (got + i) / 4) bad = got + i;
      got += whole; carry = b.subarray(whole);
    };
    s.onclose = r => { clearTimeout(t);
      const ok = r === 0x02 && got === SRC_TOTAL && bad < 0 && carry.length === 0;
      res({ ok, why: ok ? "" : `reason ${r} got ${got} first-bad ${bad}` }); };
  });
}
const closed = net.createServer(); await new Promise(r => closed.listen(0, "127.0.0.1", r));
const DEAD = closed.address().port; await new Promise(r => closed.close(r));

function connect(u, version) {
  return new Promise((res, rej) => {
    const c = new client.ClientConnection(u, { wisp_version: version });
    const t = setTimeout(() => rej(new Error("connect timeout")), 5000);
    c.onopen = () => { clearTimeout(t); res(c); };
    c.onclose = () => { clearTimeout(t); rej(new Error("ws closed")); };
  });
}

function streamEcho(conn, host, bytes, chunk) {
  return new Promise((res) => {
    const s = conn.create_stream(host, ECHO);
    const data = crypto.randomBytes(bytes);
    const got = [];
    let n = 0;
    const t = setTimeout(() => res({ ok: false, why: `timeout got ${n}/${bytes}` }), 20000);
    s.onmessage = d => { got.push(Buffer.from(d)); n += d.length;
      if (n >= bytes) { clearTimeout(t); s.close(0x02);
        const same = Buffer.concat(got).equals(data); res({ ok: same, why: same ? "" : "content mismatch" }); } };
    s.onclose = r => { clearTimeout(t); res({ ok: false, why: `closed early reason ${r}` }); };
    for (let i = 0; i < bytes; i += chunk) s.send(data.subarray(i, Math.min(bytes, i + chunk)));
  });
}

function streamClose(conn, host, port, payload, waitMs = 15000) {
  return new Promise(res => {
    const s = conn.create_stream(host, port);
    const t = setTimeout(() => res("timeout"), waitMs);
    let got = 0;
    s.onmessage = d => { got += d.length; };
    s.onclose = r => { clearTimeout(t); res({ reason: r, got }); };
    if (payload) s.send(new TextEncoder().encode(payload));
  });
}

for (const v of [1, 2]) {
  let conn;
  try { conn = await connect(url, v); } catch (e) { ok(false, `v${v} handshake: ${e.message}`); continue; }
  ok(true, `v${v} handshake (server ${conn.wisp_version ?? "?"}, buffer ${conn.max_buffer_size})`);
  ok(conn.max_buffer_size > 0, `v${v} initial CONTINUE credit = ${conn.max_buffer_size}`);
  const results = await Promise.all([
    streamEcho(conn, "127.0.0.1", 8 << 20, 16384),
    streamEcho(conn, "127.0.0.1", 3 << 20, 60000),
    streamEcho(conn, "127.0.0.1", 1000, 7),
    streamEcho(conn, "localhost", 200000, 1000),
  ]);
  results.forEach((r, i) => ok(r.ok, `v${v} echo stream ${i} ${r.why}`));
  // big verified downloads interleaved with echo traffic on the same connection (splice + copy frames)
  const mixed = await Promise.all([streamDownload(conn, "127.0.0.1"), streamDownload(conn, "127.0.0.1"),
    streamEcho(conn, "127.0.0.1", 2 << 20, 3000), streamEcho(conn, "127.0.0.1", 50000, 50)]);
  ok(mixed[0].ok && mixed[1].ok, `v${v} 2x64 MiB pattern download intact ${mixed[0].why} ${mixed[1].why}`);
  ok(mixed[2].ok && mixed[3].ok, `v${v} echo during bulk download intact ${mixed[2].why} ${mixed[3].why}`);
  const eof = await streamClose(conn, "127.0.0.1", ECHO, "hello BYE");
  ok(eof.reason === 0x02 && eof.got === 9, `v${v} target EOF -> CLOSE 0x02 after data (got ${JSON.stringify(eof)})`);
  const ref = await streamClose(conn, "127.0.0.1", DEAD);
  ok(ref.reason === 0x44, `v${v} refused -> 0x44 (got ${JSON.stringify(ref)})`);
  // 30 s: the host's resolver (the server under test uses getaddrinfo; glibc worst case 5 s x 2 attempts; 60.33)
  const nx = await streamClose(conn, "does-not-exist.invalid", 80, undefined, 30000);
  ok(nx.reason === 0x42, `v${v} unresolvable -> 0x42 (got ${JSON.stringify(nx)})`);
  conn.close();
}

if (blockedUrl) {
  const conn = await connect(blockedUrl, 1);
  const b = await streamClose(conn, "127.0.0.1", ECHO);
  ok(b.reason === 0x48, `default SSRF guard: loopback -> 0x48 (got ${JSON.stringify(b)})`);
  const b2 = await streamClose(conn, "10.0.0.1", 80);
  ok(b2.reason === 0x48, `default SSRF guard: private -> 0x48 (got ${JSON.stringify(b2)})`);
  conn.close();
}
echo.close(); source.close();
console.log(failures ? `${failures} FAILURES` : "ALL PASS");
process.exit(failures ? 1 : 0);
