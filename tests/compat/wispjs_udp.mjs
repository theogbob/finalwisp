// 40.07 (20.16) real wisp-js client over Wisp UDP streams, v1 and v2 (v2 refuses UDP unless the server
// INFO lists extension 0x01). usage: node wispjs_udp.mjs ws://127.0.0.1:PORT/ [no_udp_url]
import { client } from "@mercuryworkshop/wisp-js/client";
import dgram from "node:dgram";
import { readFileSync } from "node:fs";

const [url, noUdpUrl] = process.argv.slice(2);
let failures = 0;
const ok = (c, m) => { console.log(`${c ? "PASS" : "FAIL"} ${m}`); if (!c) failures++; };

// 4 MiB receive buffer: the client sends each burst at once; the default 208 KiB drops part of it here
const echo = dgram.createSocket({ type: "udp4", recvBufferSize: 4 << 20 });
echo.on("message", (m, r) => echo.send(m, r.port, r.address));
await new Promise(r => echo.bind(0, "127.0.0.1", r));
const ECHO = echo.address().port;
console.log(`note: echo socket receive buffer ${echo.getRecvBufferSize()} bytes (asked 4 MiB, the kernel reports double; net.core.rmem_max caps it)`);
// the same echo on [::1]:ECHO (best effort): "localhost" resolves to ::1 first on some hosts (Debian 12)
const echo6 = dgram.createSocket({ type: "udp6", ipv6Only: true, recvBufferSize: 4 << 20 });
echo6.on("message", (m, r) => echo6.send(m, r.port, r.address));
await new Promise(r => { echo6.once("error", e => { console.log(`note: no UDP echo on [::1]:${ECHO} (${e.message})`); r(); });
  echo6.bind(ECHO, "::1", r); });

function connect(u, version) {
  return new Promise((res, rej) => {
    const c = new client.ClientConnection(u, { wisp_version: version });
    const t = setTimeout(() => rej(new Error("connect timeout")), 5000);
    c.onopen = () => { clearTimeout(t); res(c); };
    c.onclose = () => { clearTimeout(t); rej(new Error("ws closed")); };
  });
}

// 60.15 T07: UDP may drop. Under CPU load the kernel drops part of a 300-datagram burst at a full socket
// receive buffer (on epyc2 the server's target socket at rmem_default 208 KiB: the echo's got 4 MiB, rmem_max
// allows it; the note line prints what the echo got): every lost datagram showed up as one Udp RcvbufErrors, and
// the old one-shot 5 s wait failed 6/12 epyc2 runs with 14 busy loops on 16 CPUs. So the echo now resends
// what is missing (up to RESEND_ROUNDS times, each after QUIET_MS without a reply) and every loss must be
// explained by the kernel's buffer-drop counters (dropAccount): a server that loses datagrams itself fails.
const QUIET_MS = 400, RESEND_ROUNDS = 5, DEADLINE_MS = 20000, GRACE_MS = 2000;

// N datagrams of distinct sizes; every reply must be one whole datagram that we sent
function udpEcho(conn, host, n) {
  return new Promise(res => {
    let s;
    try { s = conn.create_stream(host, ECHO, "udp"); } catch (e) { return res({ ok: false, why: e.message, sent: 0, replies: 0 }); }
    const sent = new Map(), seen = new Set();
    let replies = 0, bad = 0, xmit = 0, rounds = 0, lost1 = null, done = false, quiet, graceEnd = null;
    const send = i => { const b = Buffer.from(sent.get(i), "hex"); xmit++; s.send(new Uint8Array(b)); };
    const finish = (ok, why) => { if (done) return; done = true; clearTimeout(quiet); clearTimeout(dead);
      try { s.close(0x02); } catch {} res({ ok, why: `${why}; lost ${lost1 ?? n - seen.size} of ${n} first pass, ${rounds} resend rounds, bad ${bad}`, sent: xmit, replies }); };
    const dead = setTimeout(() => finish(false, `deadline ${seen.size}/${n}`), DEADLINE_MS);
    // QUIET_MS without a reply: everything in flight has arrived (or was dropped). Done, or resend the rest.
    const idle = () => {
      if (lost1 === null) lost1 = n - seen.size;
      if (seen.size === n) {
        // a resend whose original was only late still has a reply in flight: give it up to GRACE_MS, so that the
        // accounting (dropAccount) does not count a late duplicate as a loss the kernel never saw
        if (replies < xmit && (graceEnd ??= Date.now() + GRACE_MS) > Date.now()) return void (quiet = setTimeout(idle, QUIET_MS));
        return finish(bad === 0, bad ? "bad replies" : "all echoed");
      }
      if (replies === 0) return finish(false, "no reply at all");  // the server forwards nothing: no retry
      if (rounds === RESEND_ROUNDS) return finish(false, `missing ${n - seen.size} after ${rounds} resend rounds`);
      rounds++;
      for (let i = 0; i < n; i++) if (!seen.has(i)) send(i);
      quiet = setTimeout(idle, QUIET_MS);
    };
    s.onmessage = d => { const b = Buffer.from(d); const k = b.length >= 2 ? b.readUInt16LE(0) : -1; replies++;
      if (sent.get(k) !== b.toString("hex")) bad++; else seen.add(k);
      clearTimeout(quiet);
      if (seen.size === n && replies >= xmit) return finish(bad === 0, bad ? "bad replies" : "all echoed");  // balanced
      quiet = setTimeout(idle, QUIET_MS); };  // wait for stragglers (resend duplicates) too
    s.onclose = r => finish(false, `closed reason ${r}`);
    for (let i = 0; i < n; i++) {
      const b = Buffer.alloc(2 + (i * 37) % 1400, i & 0xff); b.writeUInt16LE(i, 0);
      sent.set(i, b.toString("hex"));
    }
    for (let i = 0; i < n; i++) send(i);
    quiet = setTimeout(idle, QUIET_MS * 5);  // the first reply may take a moment (DNS, connect)
  });
}

// kernel UDP receive/send drops in this network namespace: Udp InErrors (a superset of RcvbufErrors and
// MemErrors) + SndbufErrors, IPv4 and IPv6. null = /proc/net/snmp not readable; no snmp6 (IPv6 off) counts 0.
// Known residual: a loopback backlog overflow (netif_rx, softnet_stat) has no UDP counter; not seen so far.
function bufDrops() {
  const pick = (k, v) => ["InErrors", "SndbufErrors"].reduce((a, f) => a + Number(v[k.indexOf(f)] || 0), 0);
  let n;
  try {
    const l = readFileSync("/proc/net/snmp", "utf8").split("\n").filter(x => x.startsWith("Udp:"));
    n = pick(l[0].split(/\s+/), l[1].split(/\s+/));
  } catch { return null; }
  try {
    for (const x of readFileSync("/proc/net/snmp6", "utf8").split("\n")) {
      const [f, c] = x.trim().split(/\s+/);
      if (f === "Udp6InErrors" || f === "Udp6SndbufErrors") n += Number(c);
    }
  } catch {}
  return n;
}
// every datagram sent and not echoed was dropped once on one of the two legs; the kernel must have counted it
// (other traffic on the host can only raise the counters, so this never fails a correct server)
function dropAccount(v, rs, d0) {
  const d1 = bufDrops(), lost = rs.reduce((a, x) => a + Math.max(0, x.sent - x.replies), 0);
  // more replies than transmissions on a stream = the server duplicated datagrams: never a kernel drop
  rs.forEach((x, i) => ok(x.replies <= x.sent, `v${v} UDP stream ${i}: no duplicated replies (${x.replies} replies to ${x.sent} sent)`));
  if (d0 === null || d1 === null) {  // no counters: a loss cannot be told from a server bug
    ok(lost === 0, `v${v} UDP losses: ${lost} (/proc/net/snmp not readable, so a loss cannot be accounted)`); return; }
  ok(lost <= d1 - d0, `v${v} UDP losses explained by kernel drops (lost ${lost}, Udp InErrors+SndbufErrors +${d1 - d0})`);
}

for (const v of [1, 2]) {
  let conn;
  try { conn = await connect(url, v); } catch (e) { ok(false, `v${v} handshake: ${e.message}`); continue; }
  ok(conn.udp_enabled, `v${v} client sees UDP enabled (server exts ${Object.keys(conn.server_exts)})`);
  const d0 = bufDrops();
  const r = await Promise.all([udpEcho(conn, "127.0.0.1", 300), udpEcho(conn, "localhost", 100)]);
  r.forEach((x, i) => ok(x.ok, `v${v} UDP echo stream ${i}: ${x.why}`));
  dropAccount(v, r, d0);
  conn.close();
}
if (noUdpUrl) {
  const conn = await connect(noUdpUrl, 2);
  ok(!conn.udp_enabled, `--no-udp server: v2 client sees UDP disabled`);
  conn.close();
  const c1 = await connect(noUdpUrl, 1);
  const r = await new Promise(res => { const s = c1.create_stream("127.0.0.1", ECHO, "udp");
    s.onclose = reason => res(reason); setTimeout(() => res("timeout"), 3000); s.send(new Uint8Array([1])); });
  ok(r === 0x48, `--no-udp server: v1 UDP stream closed with 0x48 (60.20 Q7; got ${r})`);
  c1.close();
}
echo.close();
try { echo6.close(); } catch {}
console.log(failures ? `${failures} FAILED` : "ALL PASS");
process.exit(failures ? 1 : 0);
