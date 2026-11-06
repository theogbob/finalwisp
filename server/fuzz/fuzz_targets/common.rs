//! 70.01 shared by the worker targets: one Harness per config variant, built on first use.
use finalwisp_fuzz::worker::fuzz_hooks::{Harness, VARIANTS};
use std::cell::RefCell;

thread_local! {
    static HS: RefCell<Vec<Option<Option<Harness>>>> = RefCell::new((0..VARIANTS).map(|_| None).collect());
}

/// Run `f` on the harness of variant `v` (falls back to variant 0 when e.g. TLS is unavailable).
pub fn with_harness<R>(v: u8, f: impl FnOnce(&mut Harness) -> R) -> R {
    HS.with(|hs| {
        let mut hs = hs.borrow_mut();
        let v = (v % VARIANTS) as usize;
        if hs[v].is_none() {
            hs[v] = Some(Harness::new(v as u8));
        }
        let v = if hs[v].as_ref().unwrap().is_some() { v } else { 0 };
        if hs[v].is_none() {
            hs[v] = Some(Harness::new(v as u8));
        }
        f(hs[v].as_mut().unwrap().as_mut().expect("variant 0 always builds"))
    })
}

/// Memory pressure level from a selector byte: mostly 0, sometimes 1..3.
pub fn level(b: u8) -> usize {
    match b & 7 {
        5 => 1,
        6 => 2,
        7 => 3,
        _ => 0,
    }
}

#[allow(dead_code)] // not every target splits its input
pub struct Rng(pub u64);
#[allow(dead_code)]
impl Rng {
    pub fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}
