//! 60.72 two stream limits, off by default and free when off (the worker side: worker/slimits.rs). Both ride 60.57's
//! hold mode: with either on, the fd gate's mask has a bit of this file, so every CONNECT reaches the out-of-line
//! fd_more (before DNS), every fd put the out-of-line fd_trim; no inline path tests them.
//!
//! --stream-share: from the host mark of 60.57 C (7/8 of the usable fds handed out, until below 13/16; its own bit
//! MARK_STREAM, so it does not need --fd-admission), a connection that holds `n` streams gets no new stream when `n`
//! is at least `share_cap`: about twice its equal share of the fds at the mark, once its equal share at the limit.
//! A connection with few streams goes on, so the room that --fd-admission keeps is not used up by the heaviest
//! connections first. Not per address: users behind one address are not judged together.
//!
//! --stream-pool: the memory levels' stream limit (mem::max_streams, a limit per worker thread while socket buffers
//! are capped: level 1 and up, and always under a budget of 256 MiB) becomes one limit for the process with the same
//! total (the per-worker limit times the threads). A worker takes units of it in blocks and gives back what it does
//! not use, so a busy thread is not refused while another thread has room. The memory bound stays the same.
//!
//! The state is a global of this file (one cell per worker), not a field of the Worker or of the fd gate: a field
//! there would move the offsets of the fields that the event loop reads, and with both options off the loop must stay
//! as it was.
use crate::fdgate::Line;
use std::sync::atomic::{
    AtomicU32, AtomicU64, AtomicU8,
    Ordering::{Relaxed, SeqCst},
};
use std::sync::OnceLock;

/// --stream-share: a connection with fewer streams than this is never refused by the rule
pub const SHARE_MIN: u32 = 32;
/// --stream-share: a worker sums the connections of all workers at most this often
pub const CONNS_MS: u64 = 100;
/// --stream-pool: the largest block a worker takes at once
pub const POOL_BLOCK_MAX: u32 = 16;

/// why a new stream is refused (Cell::why: set by the rule in fd_more, taken by fd_short at once)
pub const WHY_SHARE: u8 = 1;
pub const WHY_POOL: u8 = 2;

/// --stream-share: the most streams a connection may hold before a new one is refused, for `limit` usable fds of which
/// `granted` are handed out and `conns` connections: its equal share F / conns, times 1 + (the fds left) / (F / 8),
/// that factor at most 2. So 2 x the share at the mark (7/8), 1 x at the limit; never below SHARE_MIN.
pub fn share_cap(limit: u32, granted: u32, conns: u32) -> u32 {
    let f = limit as u64;
    let share = f / conns.max(1) as u64;
    let eighth = (f / 8).max(1);
    let room = f.saturating_sub(granted as u64).min(eighth);
    (share + share * room / eighth).clamp(SHARE_MIN as u64, u32::MAX as u64) as u32
}

/// --stream-pool: the pool's size for a per-worker limit `per` (usize::MAX = no limit) and `threads` workers
pub fn pool_total(per: usize, threads: u32) -> u32 {
    if per == usize::MAX {
        u32::MAX
    } else {
        (per as u64).saturating_mul(threads.max(1) as u64).min(u32::MAX as u64 - 1) as u32
    }
}

/// --stream-pool: the block a worker takes or gives back at once: 1/64 of an even share, 1 to POOL_BLOCK_MAX
pub fn pool_block(total: u32, threads: u32) -> u32 {
    (total as u64 / (64 * threads.max(1) as u64)).clamp(1, POOL_BLOCK_MAX as u64) as u32
}

/// One worker's state (written by that worker only; atomics so that the table can be shared)
#[derive(Default)]
pub struct WCell {
    /// --stream-pool: the units this worker holds (its live streams plus what it does not use)
    pub have: AtomicU32,
    /// WHY_* of the stream refused last (0 = none)
    pub why: AtomicU8,
    /// --stream-share: the connections of all workers at the last sum, and when (ms, metrics::ms_at)
    pub conns: AtomicU32,
    pub conns_at: AtomicU64,
}

/// The process state of both limits (`install`)
pub struct Slimits {
    pub share: bool,
    pub pool: bool,
    /// --stream-pool: the pool's size and block at each memory level (from the budget, which main sets before)
    pub pool_at: [(u32, u32); crate::mem::STAGES.len()],
    /// --stream-pool: units handed to the workers in blocks (the sum of every worker's `have`)
    granted: Line<AtomicU32>,
    pub(crate) cells: Box<[Line<WCell>]>,
    /// tests: the per-worker limit of the memory levels (0: pool_at)
    #[cfg(test)]
    pub test_per: std::sync::atomic::AtomicUsize,
}

impl Slimits {
    pub fn new(share: bool, pool: bool, threads: usize) -> Slimits {
        let threads = threads.max(1);
        Slimits {
            share,
            pool,
            pool_at: std::array::from_fn(|l| {
                let total = pool_total(crate::mem::max_streams(&crate::mem::STAGES[l]), threads as u32);
                (total, pool_block(total, threads as u32))
            }),
            granted: Line(AtomicU32::new(0)),
            cells: (0..threads).map(|_| Line(WCell::default())).collect(),
            #[cfg(test)]
            test_per: Default::default(),
        }
    }
    /// worker `idx`'s cell (a worker index past the table, a test worker: the last cell)
    pub fn cell(&self, idx: usize) -> &WCell {
        &self.cells[idx.min(self.cells.len() - 1)].0
    }
    pub fn granted(&self) -> u32 {
        self.granted.0.load(Relaxed)
    }
    /// --stream-pool: take up to `want` (at least `need`, else nothing) of what is left under `total`. Exact (a CAS).
    pub fn grab(&self, want: u32, need: u32, total: u32) -> u32 {
        let mut g = self.granted.0.load(Relaxed);
        loop {
            let n = want.min(total.saturating_sub(g));
            if n == 0 || n < need {
                return 0;
            }
            match self.granted.0.compare_exchange_weak(g, g + n, SeqCst, Relaxed) {
                Ok(_) => return n,
                Err(now) => g = now,
            }
        }
    }
    pub fn give(&self, n: u32) {
        let prev = self.granted.0.fetch_sub(n, SeqCst);
        debug_assert!(prev >= n, "stream pool gave back more than was granted");
    }
}

static GLOBAL: OnceLock<Slimits> = OnceLock::new();

/// main, before the workers are built (only with --stream-share or --stream-pool)
pub fn install(s: Slimits) {
    let _ = GLOBAL.set(s);
}

/// the server's state (None: both options off; the fuzz harness)
#[cfg(not(test))]
#[inline]
pub fn global() -> Option<&'static Slimits> {
    GLOBAL.get()
}

#[cfg(test)]
thread_local! {
    /// tests: each test thread its own state (a worker test runs its workers on its own thread)
    static TEST: std::cell::Cell<Option<&'static Slimits>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub fn global() -> Option<&'static Slimits> {
    TEST.get()
}
/// tests: the state of this thread's workers (leaked: a test's state lives as long as its process)
#[cfg(test)]
pub fn set_test(s: Option<Slimits>) {
    TEST.set(s.map(|s| &*Box::leak(Box::new(s))));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_cap_tightens_from_the_mark_to_the_limit() {
        // T8 of 60.67: 65,435 usable fds, 806 connections: share 81; 2 x at the mark, 1 x at the limit
        let f = 65_435;
        assert_eq!(share_cap(f, f / 8 * 7, 806), 162);
        assert_eq!(share_cap(f, f, 806), 81);
        assert_eq!(share_cap(f, f - f / 16, 806), 121);
        // below the mark (the mark still set on the way down to 13/16): at most 2 x
        assert_eq!(share_cap(f, f / 16 * 13, 806), 162);
        // over the limit (granted runs ahead): 1 x
        assert_eq!(share_cap(f, u32::MAX, 806), 81);
        // the floor: many connections, or a tiny limit
        assert_eq!(share_cap(f, f, 20_000), SHARE_MIN);
        assert_eq!(share_cap(7, 7, 1), SHARE_MIN);
        // one connection alone, no connection counted
        assert_eq!(share_cap(f, f, 1), f);
        assert_eq!(share_cap(f, f, 0), f);
        assert_eq!(share_cap(u32::MAX, 0, 1), u32::MAX);
    }

    #[test]
    fn pool_sizes() {
        assert_eq!(pool_total(usize::MAX, 4), u32::MAX);
        assert_eq!(pool_total(227, 2), 454);
        assert_eq!(pool_total(usize::MAX - 1, 4), u32::MAX - 1);
        assert_eq!(pool_total(16, 0), 16);
        assert_eq!((pool_block(454, 2), pool_block(u32::MAX, 2), pool_block(0, 2), pool_block(8192, 2)), (3, 16, 1, 16));
    }

    #[test]
    fn pool_grab_is_exact() {
        let s = Slimits::new(false, true, 2);
        assert_eq!(s.grab(16, 1, 20), 16);
        assert_eq!(s.grab(16, 1, 20), 4);
        assert_eq!(s.grab(16, 1, 20), 0);
        s.give(10);
        assert_eq!(s.grab(16, 11, 20), 0, "less than `need` is nothing");
        assert_eq!(s.grab(16, 10, 20), 10);
        assert_eq!(s.granted(), 20);
        // a smaller total (a higher memory level) with more granted: nothing until enough comes back
        assert_eq!(s.grab(1, 1, 8), 0);
        s.give(20);
        assert_eq!(s.granted(), 0);
        assert_eq!(s.cell(5).have.load(Relaxed), 0);
    }
}
