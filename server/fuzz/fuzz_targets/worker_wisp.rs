#![no_main]
//! 70.01 stateful, structure-aware: a valid WebSocket upgrade (v1, v2, or wsproxy to the echo sink),
//! optionally a valid v2 INFO (no records / password / ed25519 signature over the server's challenge),
//! then input-chosen Wisp packets wrapped in masked WS frames (fragmented, with control frames, raw
//! bytes, idle sweeps and memory-pressure level changes in between) through the real Worker.
//! Input: [variant|level] [mode] ops...
use finalwisp_fuzz::ext;
use finalwisp_fuzz::worker::fuzz_hooks::{sign, Conn, Harness};
use libfuzzer_sys::fuzz_target;
#[path = "common.rs"]
mod common;
use common::*;

fn frame(out: &mut Vec<u8>, b0: u8, payload: &[u8], mask: Option<[u8; 4]>) {
    out.push(b0);
    let mb = if mask.is_some() { 0x80 } else { 0 };
    let n = payload.len();
    if n < 126 {
        out.push(mb | n as u8);
    } else if n <= 0xffff {
        out.push(mb | 126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(mb | 127);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    match mask {
        Some(m) => {
            out.extend_from_slice(&m);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ m[i & 3]));
        }
        None => out.extend_from_slice(payload),
    }
}

/// The server's key-auth challenge from its INFO packet (after the 101 response).
fn challenge(out: &[u8]) -> Option<Vec<u8>> {
    let p = out.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let f = &out[p..];
    if f.len() < 2 || f[0] != 0x82 {
        return None;
    }
    let (len, hl) = match f[1] {
        126 => (u16::from_be_bytes([*f.get(2)?, *f.get(3)?]) as usize, 4),
        n if n < 126 => (n as usize, 2),
        _ => return None,
    };
    let w = f.get(hl..hl + len)?; // 05 | sid 0 | 2 0 | records
    let ci = ext::parse_records(w.get(7..)?).ok()?;
    Some(ci.cert?.get(2..)?.to_vec())
}

struct In<'a>(&'a [u8]);
impl In<'_> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, r) = self.0.split_first()?;
        self.0 = r;
        Some(b)
    }
    fn take(&mut self, n: usize) -> &[u8] {
        let n = n.min(self.0.len());
        let (a, r) = self.0.split_at(n);
        self.0 = r;
        a
    }
}

fn wisp(ty: u8, sid: u32, body: &[u8]) -> Vec<u8> {
    let mut v = vec![ty];
    v.extend_from_slice(&sid.to_le_bytes());
    v.extend_from_slice(body);
    v
}

fn run(h: &mut Harness, sel: u8, mode: u8, mut inp: In) {
    let mut c: Conn = h.open();
    let path = match mode & 3 {
        2 => "/p/127.0.0.1:4444",
        3 => "/p/%31%32%37.0.0.1:4444?x=1",
        _ => "/",
    };
    let proto = if mode & 3 == 1 { "Sec-WebSocket-Protocol: wisp-v2\r\n" } else { "" };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{proto}\r\n"
    );
    let req = if h.tls { Vec::new() } else { req.into_bytes() }; // TLS: the ops carry the handshake bytes
    if !req.is_empty() && !h.feed(&mut c, &req, false) {
        return h.close(c);
    }
    let mut rng = Rng(u64::from(sel) << 8 | u64::from(mode) | 1 << 40);
    let mask = |rng: &mut Rng| Some((rng.next() as u32).to_ne_bytes());
    // auto INFO (v2): 0 none, 1 bare 2.0, 2 password u:p, 3 key signature over the server's challenge
    let info = match (mode >> 2) & 3 {
        1 => Some(wisp(5, 0, &[2, 0])),
        2 => {
            let mut b = vec![2, 0];
            ext::record(&mut b, ext::EXT_PASSWORD, b"\x01up");
            Some(wisp(5, 0, &b))
        }
        3 => challenge(&c.out).map(|ch| {
            let mut b = vec![2, 0];
            ext::record(&mut b, ext::EXT_CERT, &sign(&ch));
            wisp(5, 0, &b)
        }),
        _ => None,
    };
    if let Some(m) = info {
        let mut f = Vec::new();
        frame(&mut f, 0x82, &m, mask(&mut rng));
        if !h.feed(&mut c, &f, false) {
            return h.close(c);
        }
    }
    let mut pending = Vec::new();
    let mut ops = 0;
    while let Some(op) = inp.u8() {
        ops += 1;
        if ops > 256 {
            break;
        }
        let r = rng.next();
        let m = if r % 64 == 0 { None } else { mask(&mut rng) }; // rarely unmasked (protocol error)
        match op % 8 {
            0 | 1 => {
                // one Wisp packet, short or long body
                let ty = inp.u8().unwrap_or(2) % 8;
                let sid = inp.u8().unwrap_or(1) as u32;
                let n = if op % 8 == 0 { inp.u8().unwrap_or(0) as usize } else { (inp.u8().unwrap_or(0) as usize) << 8 };
                let mut body = inp.take(n).to_vec();
                body.resize(n, 0x61); // short input: pad (a long DATA body costs no input bytes)
                frame(&mut pending, 0x82, &wisp(ty, sid, &body), m);
            }
            2 => {
                // a raw WS payload (any bytes, may be a malformed Wisp packet), BIN or TEXT
                let b0 = if op & 0x80 != 0 { 0x81 } else { 0x82 };
                let n = inp.u8().unwrap_or(0) as usize;
                let p = inp.take(n).to_vec();
                frame(&mut pending, b0, &p, m);
            }
            3 => {
                // fragmented message: parts with control frames in between
                let parts = 1 + inp.u8().unwrap_or(0) as usize % 6;
                for i in 0..parts {
                    let n = inp.u8().unwrap_or(0) as usize;
                    let p = inp.take(n).to_vec();
                    let b0 = (if i + 1 == parts { 0x80 } else { 0 }) | if i == 0 { 2 } else { 0 };
                    frame(&mut pending, b0, &p, mask(&mut rng));
                    if rng.next() % 4 == 0 {
                        frame(&mut pending, 0x89, b"ping", mask(&mut rng));
                    }
                }
            }
            4 => {
                // control or reserved frame with any first byte
                let b0 = inp.u8().unwrap_or(0x89);
                let n = inp.u8().unwrap_or(0) as usize % 130;
                let p = inp.take(n).to_vec();
                frame(&mut pending, b0, &p, m);
            }
            5 => {
                let n = inp.u8().unwrap_or(0) as usize;
                pending.extend_from_slice(inp.take(n));
            }
            6 => {
                // flush what is pending, in input-chosen pieces, then maybe an idle sweep
                let sweep = op & 0x40 != 0;
                if !feed_split(h, &mut c, &mut pending, &mut rng, sweep) {
                    return h.close(c);
                }
            }
            _ => h.set_level(level(op >> 3)),
        }
        if pending.len() > 1 << 16 && !feed_split(h, &mut c, &mut pending, &mut rng, false) {
            return h.close(c);
        }
    }
    if feed_split(h, &mut c, &mut pending, &mut rng, false) {
        for _ in 0..4 {
            h.turn(false);
            h.drain(&mut c);
            h.check(&c);
        }
    }
    h.close(c);
}

fn feed_split(h: &mut Harness, c: &mut Conn, pending: &mut Vec<u8>, rng: &mut Rng, sweep: bool) -> bool {
    let mut rest = &pending[..];
    let mut ok = true;
    while !rest.is_empty() {
        let r = rng.next();
        let k = if r % 4 == 0 { 1 + (r >> 8) as usize % 64 } else { rest.len() }.min(rest.len());
        if !h.feed(c, &rest[..k], sweep && k == rest.len()) {
            ok = false;
            break;
        }
        rest = &rest[k..];
    }
    pending.clear();
    ok
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (sel, mode) = (data[0], data[1]);
    with_harness(sel, |h| {
        h.reset();
        h.set_level(level(sel >> 2));
        run(h, sel, mode, In(&data[2..]));
        h.set_level(0);
        h.turn(false);
    });
});
