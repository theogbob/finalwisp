#![no_main]
//! 70.01 stateful: a raw client byte stream, split at input-chosen points, through the real Worker
//! (HTTP upgrade or TLS handshake, WS framing + fragment reassembly, Wisp packets, wsproxy) on a
//! socketpair. Invariants after every turn: Harness::check (rbuf/need/frag bounds); after close: no
//! client or target slot left. Input: [variant|level] [split seed] stream...
use libfuzzer_sys::fuzz_target;
#[path = "common.rs"]
mod common;
use common::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (sel, seed, mut rest) = (data[0], data[1], &data[2..]);
    with_harness(sel, |h| {
        h.reset();
        h.set_level(level(sel >> 2));
        let mut c = h.open();
        let mut rng = Rng((seed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        while !rest.is_empty() {
            let r = rng.next();
            let k = match r % 8 {
                0 => 1,
                1 => 1 + (r >> 8) as usize % 16,
                2 | 3 => 1 + (r >> 8) as usize % 512,
                _ => rest.len(),
            }
            .min(rest.len());
            let sweep = (r >> 32) % 64 == 0;
            if !h.feed(&mut c, &rest[..k], sweep) {
                break;
            }
            rest = &rest[k..];
        }
        for _ in 0..4 {
            h.turn(false);
            h.drain(&mut c);
            h.check(&c);
        }
        h.close(c);
        h.set_level(0);
        h.turn(false);
    });
});
