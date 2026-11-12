//! 60.57 file descriptors. A1: the soft RLIMIT_NOFILE is raised at startup (`raise_nofile`).
//! The count of the workers' fds and its reserve (A2) and the marks of --fd-admission / --conn-share (C) follow below.

/// A1 the automatic raise never goes above this (the default fs.nr_open; an operator's own higher soft limit is kept)
pub const NOFILE_AUTO_MAX: u64 = 1_048_576;
/// RLIM_INFINITY in this module's u64 terms
pub const INF: u64 = u64::MAX;

/// RLIMIT_NOFILE (soft, hard); INF = unlimited
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Limits {
    pub soft: u64,
    pub hard: u64,
}

/// A1 the setrlimit calls to try, in order; empty = the soft limit stays (already at or above the target).
/// Target: min(hard, NOFILE_AUTO_MAX, fs.nr_open), never below the soft limit. The kernel refuses (EPERM) every
/// RLIMIT_NOFILE change whose hard limit is above fs.nr_open, also an unchanged one (kernel/sys.c do_prlimit): with
/// hard = unlimited or 1073741816 above a default nr_open of 1048576 the only call that works lowers the hard limit to
/// nr_open (no loss: no fd above nr_open can exist). nr_open unreadable (a container that hides /proc/sys): the hard
/// limit as it is first, then lowered to the target.
pub fn raise_plan(l: Limits, nr_open: Option<u64>) -> Vec<Limits> {
    let want = l.hard.min(NOFILE_AUTO_MAX).min(nr_open.unwrap_or(INF));
    if want <= l.soft {
        return Vec::new();
    }
    let mut plan = Vec::new();
    if nr_open.is_none_or(|n| l.hard <= n) {
        plan.push(Limits { soft: want, hard: l.hard });
    }
    let lower = nr_open.unwrap_or(want);
    if l.hard > lower {
        plan.push(Limits { soft: want, hard: lower });
    }
    plan
}

/// What the raise did: the limits before and after (read back), and the warning if it failed or lowered the hard limit
/// (a text for main's `warn`: at most 2 lines of 80 columns, main.rs open_file_rows_and_warnings)
pub struct Raise {
    pub before: Limits,
    pub after: Limits,
    pub warn: Option<String>,
}

impl Raise {
    /// `nofile soft 1024 -> 524288, hard 524288` for the startup line
    pub fn describe(&self) -> String {
        let n = |v: u64| if v == INF { "unlimited".to_string() } else { v.to_string() };
        let part = |name: &str, a: u64, b: u64| if a == b { format!("{name} {}", n(a)) } else { format!("{name} {} -> {}", n(a), n(b)) };
        format!("nofile {}, {}", part("soft", self.before.soft, self.after.soft), part("hard", self.before.hard, self.after.hard))
    }
}

/// A1 `raise_plan` applied through `set` (Err = errno) and read back through `get`. A failed call keeps the old limit
/// and warns; the second step of a plan runs only after EPERM.
pub fn raise_with(
    before: Limits,
    nr_open: Option<u64>,
    mut set: impl FnMut(Limits) -> Result<(), i32>,
    get: impl Fn() -> Option<Limits>,
) -> Raise {
    let mut warn = None;
    for (i, step) in raise_plan(before, nr_open).into_iter().enumerate() {
        match set(step) {
            Ok(()) => {
                // (the kernel refuses every change of the limit while the hard limit is above fs.nr_open, so the soft limit
                // could not be raised otherwise; no fd above fs.nr_open can exist, so nothing is lost)
                warn = (step.hard != before.hard).then(|| {
                    format!(
                        "hard open-file limit lowered to {} ({}): needed for the raise. --no-nofile-raise keeps both limits.",
                        step.hard,
                        if nr_open.is_some() { "fs.nr_open" } else { "fs.nr_open unreadable" }
                    )
                });
                break;
            }
            Err(e) => {
                warn = Some(format!(
                    "open-file limit: the raise from {} to {} failed ({}); the old limit stays.",
                    before.soft,
                    step.soft,
                    std::io::Error::from_raw_os_error(e)
                ));
                if e != libc::EPERM || i > 0 {
                    break;
                }
            }
        }
    }
    let after = get().unwrap_or(before);
    if after.soft < before.soft {
        // (cannot happen: no step lowers the soft limit; said, not assumed)
        warn = Some(format!("open-file limit: the soft limit went down from {} to {}.", before.soft, after.soft));
    }
    Raise { before, after, warn }
}

#[allow(clippy::unnecessary_cast)] // rlim_t is u32 on 32-bit GNU targets
fn from_rlim(v: libc::rlim_t) -> u64 {
    if v == libc::RLIM_INFINITY {
        INF
    } else {
        v as u64
    }
}

fn to_rlim(v: u64) -> libc::rlim_t {
    if v == INF {
        libc::RLIM_INFINITY
    } else {
        libc::rlim_t::try_from(v).unwrap_or(libc::RLIM_INFINITY)
    }
}

pub fn nofile() -> Option<Limits> {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: rl is a valid rlimit for the call to fill
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0)
        .then(|| Limits { soft: from_rlim(rl.rlim_cur), hard: from_rlim(rl.rlim_max) })
}

/// A1 at startup, before any worker exists: raise the soft RLIMIT_NOFILE to min(hard, NOFILE_AUTO_MAX) (`raise` false =
/// --no-nofile-raise: only read it). fs.nr_open is read, never written. None: getrlimit failed.
pub fn raise_nofile(raise: bool) -> Option<Raise> {
    let before = nofile()?;
    if !raise {
        return Some(Raise { before, after: before, warn: None });
    }
    let nr_open = std::fs::read_to_string("/proc/sys/fs/nr_open").ok().and_then(|s| s.trim().parse().ok());
    let set = |l: Limits| {
        let rl = libc::rlimit { rlim_cur: to_rlim(l.soft), rlim_max: to_rlim(l.hard) };
        // SAFETY: rl is a valid rlimit
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    };
    Some(raise_with(before, nr_open, set, nofile))
}

// ---- A2: the fds the workers hold, counted process-wide, with a reserve

use crate::metrics::Stats;
use std::sync::atomic::{
    AtomicU32, AtomicU64, AtomicU8,
    Ordering::{Relaxed, SeqCst},
};
use std::sync::{Arc, OnceLock};

/// One value alone on its cache lines (128 bytes: the adjacent-line prefetcher, as metrics::Stats)
#[repr(align(128))]
#[derive(Default)]
struct Line<T>(T);

/// A2 fds the process opens after the count at startup and keeps: the memory sampler's cgroup / proc files (at most 5),
/// with room for a file read now and then (the metrics line's /proc/net/netstat, a certificate reload)
pub const LATE_FILES: u64 = 8;
/// A2 the reserve, which no connection and no stream can use: a base (the metrics endpoint serves one connection at a
/// time, the upstream-proxy name refresh, a startup probe), RESERVE_PER_DNS per DNS thread (a lookup holds at most two
/// sockets at a time, three with the own resolver's route probe; glibc's are not ours to count), and one per worker
/// (accept4 creates the fd before the worker can refuse it). At most a quarter of the limit (a tiny nofile).
pub const RESERVE_BASE: u64 = 16;
pub const RESERVE_PER_DNS: u64 = 4;
/// A2 the most fds a worker takes from the process count at once (and the slack it keeps): see `block`
pub const BLOCK_MAX: u32 = 64;

/// A2 F = soft limit - fixed fds - reserve
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Budget {
    pub fixed: u64,
    pub reserve: u64,
    /// F: the fds connections and streams may hold in all
    pub usable: u32,
}

/// `open_now`: the fds open once every worker is built (listeners, epoll, eventfds, the spare fds, stdio, a unix or
/// metrics listener, the lock file)
pub fn budget(soft: u64, open_now: u64, dns_threads: usize, workers: usize) -> Budget {
    let fixed = open_now.saturating_add(LATE_FILES);
    let room = soft.saturating_sub(fixed);
    // (saturating: the parser has no upper bound for --dns-threads)
    let want = RESERVE_BASE.saturating_add(RESERVE_PER_DNS.saturating_mul(dns_threads as u64)).saturating_add(workers as u64);
    let reserve = want.min(room / 4);
    Budget { fixed, reserve, usable: (room - reserve).min(u32::MAX as u64) as u32 }
}

/// A2 the block a worker takes or returns at once: 1/64 of an even share, 1 to BLOCK_MAX. Every worker can hold up to
/// two blocks it does not use, so the process count runs ahead of the real use by at most F/32.
pub fn block(usable: u32, workers: usize) -> u32 {
    (usable / (64 * workers.max(1) as u32)).clamp(1, BLOCK_MAX)
}

/// `open_fds` when /proc is unreadable: stdio, and per worker a listener, an epoll, an event fd and a spare; a unix
/// listener with its lock file and a metrics listener on top
pub fn fixed_estimate(workers: usize) -> u64 {
    4u64.saturating_mul(workers as u64).saturating_add(6) // (saturating: as `budget`)
}

/// main warns when fewer fds than this are usable (a limit of 256 or below)
pub const USABLE_WARN: u64 = 128;

/// The fds open in this process (/proc/self/fd, without the directory's own fd). None: /proc is not readable.
pub fn open_fds() -> Option<u64> {
    Some((std::fs::read_dir("/proc/self/fd").ok()?.count() as u64).saturating_sub(1))
}

/// Rate-limited log lines (one slot each in FdGate::log_at)
#[derive(Clone, Copy)]
pub enum Line10 {
    ConnFd,
    ConnLevel,
    StreamFd,
    Emfile,
    /// C a connection reset at the host mark (--fd-admission)
    ConnMark,
    /// C a connection refused by the share rule (--conn-share)
    ConnShare,
    /// C the share mark was crossed (in or out)
    MarkShare,
    /// C the host mark was crossed
    MarkHost,
}
const LOG_KINDS: usize = 8;
/// at most one line per kind per this (process-wide)
pub const LOG_EVERY_MS: u64 = 10_000;

/// C the marks, as parts of F in 16ths: entry and exit (below its entry, as the memory levels have). The share mark
/// arms --conn-share; from the host mark --fd-admission resets every new connection. Starting values (60.57 C).
pub const SHARE_IN_16: u32 = 12;
pub const SHARE_OUT_16: u32 = 11;
pub const HOST_IN_16: u32 = 14;
pub const HOST_OUT_16: u32 = 13;
/// C bits of FdGate::marks
pub const MARK_SHARE: u8 = 1;
pub const MARK_HOST: u8 = 2;
/// C --conn-share: a key is gated when it holds more than F / SHARE_KEY_DIV fds ...
pub const SHARE_KEY_DIV: u32 = 2;
/// ... while the other keys together hold at least max(F / SHARE_FLOOR_DIV, SHARE_FLOOR_MIN) fds: "a real share", so
/// that one probe connection, or one connection with a few streams, from a second address does not arm the rule, and
/// a few dozen users on other addresses do (tests: one pair to move)
pub const SHARE_FLOOR_DIV: u32 = 64;
pub const SHARE_FLOOR_MIN: u32 = 256;

/// C `part`/16 of `limit`, rounded up (so `granted >= part16(..)` is exactly "at least part/16 of the limit", for
/// tiny limits too), without overflow
pub fn part16(limit: u32, part: u32) -> u32 {
    (limit as u64 * part as u64).div_ceil(16) as u32
}

/// C the share rule's two numbers for F = `limit`: (a key above this many fds, others at or above this many)
pub fn share_rule(limit: u32) -> (u32, u32) {
    (limit / SHARE_KEY_DIV, (limit / SHARE_FLOOR_DIV).max(SHARE_FLOOR_MIN))
}

/// A2 the process-wide count. `granted` = fds handed to the workers in blocks (the sum of every worker's allowance):
/// a worker counts its own fds in its Stats (`fds`, single writer) against its allowance and touches `granted` only
/// to take or return a block, so no shared cache line is written per connection or per stream. A connection handed to
/// another worker (--balance) takes its unit of allowance along: no shared write, and it cannot fail.
///
/// C `marks`: MARK_SHARE / MARK_HOST, moved only where `granted` moves (a block taken or returned), so they follow the
/// granted count: ahead of the real use by the workers' unused allowance (at most F/32), never behind it. Read at
/// accept when --fd-admission or --conn-share is on; written only at a crossing.
pub struct FdGate {
    granted: Line<AtomicU32>,
    marks: Line<AtomicU8>,
    log_at: Line<[AtomicU64; LOG_KINDS]>,
    limit: AtomicU32,
    block: AtomicU32,
    /// C which marks are in use (MARK_* bits; 0 = both flags off: `mark` returns at once)
    mask: AtomicU8,
    /// C the state of the marks that the log last told (MARK_* bits; written with a log line: at most one per 10 s)
    logged: AtomicU8,
    stats: OnceLock<Arc<Vec<Arc<Stats>>>>,
}

impl FdGate {
    pub fn new(limit: u32, block: u32) -> FdGate {
        FdGate {
            granted: Line(AtomicU32::new(0)),
            marks: Line(AtomicU8::new(0)),
            log_at: Line(Default::default()),
            limit: AtomicU32::new(limit),
            block: AtomicU32::new(block.max(1)),
            mask: AtomicU8::new(0),
            logged: AtomicU8::new(0),
            stats: OnceLock::new(),
        }
    }
    /// no limit (unit tests, the fuzz harness: no gate installed)
    pub fn unlimited() -> FdGate {
        FdGate::new(u32::MAX, BLOCK_MAX)
    }
    /// main, once, after the workers are built and before they run (the fixed fds are counted then)
    pub fn set_limit(&self, limit: u32, block: u32) {
        self.limit.store(limit, Relaxed);
        self.block.store(block.max(1), Relaxed);
    }
    /// the workers' counters, for `used`
    pub fn set_stats(&self, stats: Arc<Vec<Arc<Stats>>>) {
        let _ = self.stats.set(stats);
    }
    pub fn limit(&self) -> u32 {
        self.limit.load(Relaxed)
    }
    pub fn block(&self) -> u32 {
        self.block.load(Relaxed)
    }
    pub fn granted(&self) -> u32 {
        self.granted.0.load(Relaxed)
    }
    /// Take up to `want` (at least `need`, else nothing) from what is left under the limit. Exact (a CAS).
    pub fn grab(&self, want: u32, need: u32) -> u32 {
        let limit = self.limit();
        let mut g = self.granted.0.load(Relaxed);
        loop {
            let n = want.min(limit.saturating_sub(g));
            if n == 0 || n < need {
                return 0;
            }
            // (SeqCst: see mark; on x86 the same instruction)
            match self.granted.0.compare_exchange_weak(g, g + n, SeqCst, Relaxed) {
                Ok(_) => {
                    self.mark();
                    return n;
                }
                Err(now) => g = now,
            }
        }
    }
    pub fn give(&self, n: u32) {
        let prev = self.granted.0.fetch_sub(n, SeqCst);
        debug_assert!(prev >= n, "FdGate gave back more than was granted");
        self.mark();
    }
    /// C main, once, with set_limit: which marks are in use (--conn-share: MARK_SHARE, --fd-admission: MARK_HOST)
    pub fn set_marks(&self, mask: u8) {
        self.mask.store(mask, Relaxed);
        self.mark();
    }
    pub fn mask(&self) -> u8 {
        self.mask.load(Relaxed)
    }
    /// C the marks that are set now (MARK_* bits)
    #[inline]
    pub fn marks(&self) -> u8 {
        self.marks.0.load(Relaxed)
    }
    /// C the marks for `granted` fds when they were `m`: in at the entry part, out below the exit part
    pub fn marks_for(m: u8, granted: u32, limit: u32, mask: u8) -> u8 {
        let step = |m: u8, bit: u8, i: u32, o: u32| {
            if granted >= part16(limit, i).max(1) {
                m | bit
            } else if granted < part16(limit, o).max(1) {
                m & !bit
            } else {
                m
            }
        };
        step(step(m, MARK_SHARE, SHARE_IN_16, SHARE_OUT_16), MARK_HOST, HOST_IN_16, HOST_OUT_16) & mask
    }
    /// C move the marks to where `granted` is. Called after every change of `granted`. SeqCst here and on those changes
    /// (review): they are in one order for all threads, so of two workers that change `granted` at the same
    /// time at least one reads the other's change, and the marks cannot stay behind the last value. (With Relaxed that
    /// holds on x86, whose locked instructions order them anyway, and not on Arm.) A loser of the exchange reads both
    /// again.
    fn mark(&self) {
        let mask = self.mask.load(Relaxed);
        if mask == 0 {
            return;
        }
        let limit = self.limit();
        let (m, g) = loop {
            let m = self.marks.0.load(SeqCst);
            let g = self.granted.0.load(SeqCst);
            let n = Self::marks_for(m, g, limit, mask);
            if n == m {
                break (m, g);
            }
            let _ = self.marks.0.compare_exchange(m, n, SeqCst, SeqCst);
        };
        if self.logged.load(Relaxed) != m {
            self.crossed(m, g, limit);
        }
    }
    /// C the log follows the marks: one line when a mark's state is not the state last logged, at most one per
    /// LOG_EVERY_MS per mark. A state that came and went inside that time is not logged; if the mark then stays in
    /// the other state, the next change of `granted` after that time logs it (review: the last line is not
    /// left saying "armed" for a mark that is at rest). The line names the fix.
    #[cold]
    #[inline(never)]
    fn crossed(&self, now: u8, granted: u32, limit: u32) {
        const FIX: &str = "raise the open-file limit and restart (ulimit -n, systemd LimitNOFILE, docker --ulimit nofile)";
        let was = self.logged.load(Relaxed);
        let (key, floor) = share_rule(limit);
        for (bit, kind) in [(MARK_SHARE, Line10::MarkShare), (MARK_HOST, Line10::MarkHost)] {
            if (was ^ now) & bit == 0 || !self.log_due(kind) {
                continue;
            }
            if now & bit != 0 {
                self.logged.fetch_or(bit, Relaxed);
            } else {
                self.logged.fetch_and(!bit, Relaxed);
            }
            let line = match (bit, now & bit != 0) {
                (MARK_SHARE, true) => format!(
                    "finalwisp: fds: {granted} of {limit} usable fds are handed out: --conn-share is armed (from 3/4, until \
                     below 11/16): an address that holds more than {key} fds gets no new connections while other addresses \
                     hold {floor} or more. Fix: {FIX}; if that address is your reverse proxy, set --trusted-proxy so that \
                     clients are told apart; or --no-conn-share"
                ),
                (MARK_SHARE, false) => {
                    format!("finalwisp: fds: {granted} of {limit} usable fds are handed out: --conn-share is at rest (below 11/16)")
                }
                (_, true) => format!(
                    "finalwisp: fds: {granted} of {limit} usable fds are handed out: --fd-admission resets new connections \
                     (from 7/8, until below 13/16); open connections go on. Fix: {FIX}; or --no-fd-admission (then new \
                     connections go on until the limit itself, where new streams are refused)"
                ),
                (_, false) => {
                    format!("finalwisp: fds: {granted} of {limit} usable fds are handed out: --fd-admission takes new connections again (below 13/16)")
                }
            };
            crate::metrics::log_nowait(line);
        }
    }
    /// The fds the workers hold now: the sum of their own counts (each exact; the sum is not one instant). Without
    /// the workers' counters (a test gate): what is granted.
    pub fn used(&self) -> u32 {
        match self.stats.get() {
            Some(s) => s.iter().map(|w| w.fds.get()).sum::<u64>().min(u32::MAX as u64) as u32,
            None => self.granted(),
        }
    }
    /// true at most once per LOG_EVERY_MS per kind (the first call at once)
    pub fn log_due(&self, kind: Line10) -> bool {
        let now = crate::metrics::now_ms().max(1);
        let at = &self.log_at.0[kind as usize];
        let next = at.load(Relaxed);
        now >= next && at.compare_exchange(next, now + LOG_EVERY_MS, Relaxed, Relaxed).is_ok()
    }
}

static GLOBAL: OnceLock<Arc<FdGate>> = OnceLock::new();

/// main, before the workers are built
pub fn install(g: Arc<FdGate>) {
    let _ = GLOBAL.set(g);
}
/// the server's gate (None: not installed; unit tests, the fuzz harness)
pub fn global() -> Option<&'static Arc<FdGate>> {
    GLOBAL.get()
}
/// Worker::new: the server's gate, or a gate of its own without a limit
pub fn for_worker() -> Arc<FdGate> {
    GLOBAL.get().cloned().unwrap_or_else(|| Arc::new(FdGate::unlimited()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: fn(u64, u64) -> Limits = |soft, hard| Limits { soft, hard };

    #[test]
    fn raise_plan_covers_the_hard_limit_cases() {
        const M: u64 = NOFILE_AUTO_MAX;
        // systemd's hard limit (and its fs.nr_open) on recent distributions
        const SD: u64 = 1_073_741_816;
        // the Docker default: 1024 soft / 524288 hard
        assert_eq!(raise_plan(L(1024, 524_288), Some(M)), [L(524_288, 524_288)]);
        // hard 1024 cannot be raised by the server (T5)
        assert_eq!(raise_plan(L(1024, 1024), Some(M)), []);
        // the unit: both 1048576
        assert_eq!(raise_plan(L(M, M), Some(M)), []);
        // a hard limit above the cap: the soft limit goes to the cap, the hard limit stays
        assert_eq!(raise_plan(L(1024, 4 * M), Some(SD)), [L(M, 4 * M)]);
        // hard = 1073741816 with fs.nr_open = 1073741816 (systemd raised both)
        assert_eq!(raise_plan(L(1024, SD), Some(SD)), [L(M, SD)]);
        // hard = 1073741816 or unlimited above a default fs.nr_open: only a call that lowers the hard limit works
        assert_eq!(raise_plan(L(1024, SD), Some(M)), [L(M, M)]);
        assert_eq!(raise_plan(L(1024, INF), Some(M)), [L(M, M)]);
        assert_eq!(raise_plan(L(1024, INF), Some(SD)), [L(M, SD)]);
        // a small fs.nr_open bounds the target; a soft limit at it stays
        assert_eq!(raise_plan(L(1024, INF), Some(65_536)), [L(65_536, 65_536)]);
        assert_eq!(raise_plan(L(65_536, INF), Some(65_536)), []);
        // the operator's soft limit above the cap is kept (never lowered)
        assert_eq!(raise_plan(L(2 * M, 4 * M), Some(SD)), []);
        assert_eq!(raise_plan(L(INF, INF), Some(SD)), []);
        // fs.nr_open unreadable: the hard limit as it is, then lowered to the target
        assert_eq!(raise_plan(L(1024, 524_288), None), [L(524_288, 524_288)]);
        assert_eq!(raise_plan(L(1024, INF), None), [L(M, INF), L(M, M)]);
        assert_eq!(raise_plan(L(1024, SD), None), [L(M, SD), L(M, M)]);
        // never a step below the soft limit, never a hard limit above the old one
        for soft in [0, 1, 1024, 65_536, M, M + 1, SD, INF] {
            for hard in [soft, soft.saturating_add(1), M, SD, INF] {
                for nr in [None, Some(1024), Some(M), Some(SD)] {
                    for s in raise_plan(L(soft, hard.max(soft)), nr) {
                        assert!(
                            s.soft > soft && s.soft <= s.hard && s.hard <= hard.max(soft) && s.soft <= M,
                            "{soft} {hard} {nr:?}: {s:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn raise_keeps_the_old_limit_when_the_call_fails() {
        use std::cell::Cell;
        // a refused raise (seccomp, a kernel that says no): old limit, a warning that names both values
        let cur = Cell::new(L(1024, 524_288));
        let r = raise_with(cur.get(), Some(NOFILE_AUTO_MAX), |_| Err(libc::EINVAL), || Some(cur.get()));
        assert_eq!((r.before, r.after), (L(1024, 524_288), L(1024, 524_288)));
        let w = r.warn.clone().unwrap();
        assert!(w.contains("from 1024 to 524288 failed") && w.contains("the old limit stays"), "{w}");
        assert_eq!(r.describe(), "nofile soft 1024, hard 524288");
        // the plain case
        let r = raise_with(
            cur.get(),
            Some(NOFILE_AUTO_MAX),
            |l| {
                cur.set(l);
                Ok(())
            },
            || Some(cur.get()),
        );
        assert!(r.warn.is_none());
        assert_eq!(r.describe(), "nofile soft 1024 -> 524288, hard 524288");
        // unlimited hard, fs.nr_open unreadable: EPERM on the first step, the second lowers the hard limit and says so
        let cur = Cell::new(L(1024, INF));
        let calls = Cell::new(0);
        let r = raise_with(
            cur.get(),
            None,
            |l| {
                calls.set(calls.get() + 1);
                if l.hard > NOFILE_AUTO_MAX {
                    return Err(libc::EPERM);
                }
                cur.set(l);
                Ok(())
            },
            || Some(cur.get()),
        );
        assert_eq!((calls.get(), r.after), (2, L(NOFILE_AUTO_MAX, NOFILE_AUTO_MAX)));
        assert!(r.warn.as_deref().unwrap().starts_with("hard open-file limit lowered to 1048576 (fs.nr_open unreadable)"));
        assert_eq!(r.describe(), "nofile soft 1024 -> 1048576, hard unlimited -> 1048576");
        // a failure other than EPERM does not try the second step
        let calls = Cell::new(0);
        let r = raise_with(
            L(1024, INF),
            None,
            |_| {
                calls.set(calls.get() + 1);
                Err(libc::EINVAL)
            },
            || Some(L(1024, INF)),
        );
        assert_eq!((calls.get(), r.after), (1, L(1024, INF)));
        // both steps refused: the old limit stays
        let r = raise_with(L(1024, INF), None, |_| Err(libc::EPERM), || Some(L(1024, INF)));
        assert!(r.after == L(1024, INF) && r.warn.unwrap().contains("the old limit stays"));
    }

    #[test]
    fn rlim_conversions() {
        assert_eq!(from_rlim(libc::RLIM_INFINITY), INF);
        assert_eq!(to_rlim(INF), libc::RLIM_INFINITY);
        assert_eq!(from_rlim(to_rlim(1_073_741_816)), 1_073_741_816);
        let l = nofile().expect("getrlimit");
        assert!(l.soft <= l.hard);
    }

    #[test]
    fn budget_keeps_a_reserve_and_the_fixed_fds() {
        // the Docker default after the raise: 2 workers, 16 DNS threads, 12 fds open at the count
        let b = budget(524_288, 12, 16, 2);
        assert_eq!((b.fixed, b.reserve, b.usable), (20, 16 + 64 + 2, 524_288 - 20 - 82));
        // nofile 1024, hard 1024 (T5): 922 usable
        assert_eq!(budget(1024, 12, 16, 2).usable, 1024 - 20 - 82);
        // an 80-thread host at 1048576
        let b = budget(1_048_576, 4 + 4 * 80, 16, 80);
        assert_eq!((b.fixed, b.reserve, b.usable), (332, 160, 1_048_576 - 492));
        // a tiny limit: the reserve is at most a quarter of what the fixed fds leave
        let b = budget(256, 12, 16, 2);
        assert_eq!((b.fixed, b.reserve, b.usable), (20, 59, 177));
        // a limit below the fixed fds: nothing usable, no underflow
        assert_eq!(budget(16, 12, 16, 2), Budget { fixed: 20, reserve: 0, usable: 0 });
        assert_eq!(budget(0, 0, 1, 1).usable, 0);
        // an unlimited soft limit: clamped to the counter's range
        assert_eq!(budget(INF, 12, 16, 2).usable, u32::MAX);
        // the parser bounds neither --dns-threads nor --threads: no overflow, the reserve stays a quarter of the room
        for (dns, w) in [(usize::MAX, 2), (usize::MAX / 4 + 1, 2), (16, usize::MAX), (usize::MAX, usize::MAX)] {
            assert_eq!(budget(1024, 12, dns, w), Budget { fixed: 20, reserve: 251, usable: 753 }, "{dns} {w}");
        }
        assert_eq!(budget(INF, INF, usize::MAX, 2), Budget { fixed: INF, reserve: 0, usable: 0 });
        // usable + reserve + fixed never passes the limit
        for soft in [0, 20, 21, 64, 255, 1024, 65_536, NOFILE_AUTO_MAX] {
            for (dns, w) in [(1, 1), (16, 2), (64, 80), (1024, 256)] {
                let b = budget(soft, 4 + 4 * w as u64, dns, w);
                assert!(b.usable as u64 + b.reserve + b.fixed <= soft.max(b.fixed), "{soft} {dns} {w}: {b:?}");
            }
        }
        assert!(fixed_estimate(2) == 14 && fixed_estimate(usize::MAX) >= usize::MAX as u64);
    }

    #[test]
    fn block_is_a_64th_of_an_even_share() {
        assert_eq!(block(524_186, 2), 64);
        assert_eq!(block(1_048_084, 80), 64);
        assert_eq!(block(65_536, 80), 12);
        assert_eq!(block(922, 2), 7);
        assert_eq!(block(177, 2), 1);
        assert_eq!(block(0, 2), 1);
        assert_eq!(block(u32::MAX, 0), 64);
        // two unused blocks per worker: at most F/32 ahead of the real use
        for (f, w) in [(524_186u32, 2usize), (65_536, 80), (922, 2), (8192, 4)] {
            let b = block(f, w);
            assert!(b == 1 || 2 * b as u64 * w as u64 <= f as u64 / 32, "{f} {w}: {b}");
        }
    }

    #[test]
    fn gate_grants_exactly_the_limit_under_contention() {
        let g = Arc::new(FdGate::new(1000, 7));
        assert_eq!((g.limit(), g.block(), g.granted(), g.used()), (1000, 7, 0, 0));
        // at least `need`, at most `want`, never past the limit
        assert_eq!(g.grab(7, 1), 7);
        assert_eq!(g.grab(2000, 1), 993);
        assert_eq!((g.grab(7, 1), g.grab(1, 1), g.granted()), (0, 0, 1000));
        g.give(3);
        assert_eq!(g.grab(7, 4), 0, "fewer than needed: nothing is taken");
        assert_eq!((g.grab(7, 2), g.granted()), (3, 1000));
        g.give(1000);
        // 8 threads take and return blocks; the grants never pass the limit and all come back
        let over = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let (g, over) = (g.clone(), over.clone());
                std::thread::spawn(move || {
                    let mut have = 0;
                    for i in 0..20_000 {
                        let got = g.grab(7, 1 + i % 3);
                        have += got;
                        if g.granted() > 1000 {
                            over.store(true, Relaxed);
                        }
                        if have > 200 || got == 0 {
                            g.give(have);
                            have = 0;
                        }
                    }
                    g.give(have);
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert!(!over.load(Relaxed));
        assert_eq!(g.granted(), 0);
        // the limit set after the workers exist
        g.set_limit(5, 0);
        assert_eq!((g.limit(), g.block(), g.grab(64, 1)), (5, 1, 5));
        // `used` is the sum of the workers' own counts once they are known
        let st: Arc<Vec<Arc<Stats>>> = Arc::new((0..2).map(|_| Arc::new(Stats::new())).collect());
        st[0].fds.set(2);
        st[1].fds.set(1);
        g.set_stats(st);
        assert_eq!((g.used(), g.granted()), (3, 5));
        assert_eq!(FdGate::unlimited().grab(64, 1), 64);
    }

    #[test]
    fn log_lines_are_rate_limited_per_kind() {
        let g = FdGate::new(10, 1);
        assert!(g.log_due(Line10::ConnFd), "the first line at once");
        assert!(!g.log_due(Line10::ConnFd) && !g.log_due(Line10::ConnFd));
        assert!(g.log_due(Line10::StreamFd), "kinds do not share a limit");
        g.log_at.0[Line10::ConnFd as usize].store(crate::metrics::now_ms(), Relaxed); // its time has come
        assert!(g.log_due(Line10::ConnFd) && !g.log_due(Line10::ConnFd));
    }
    /// C the log follows the marks (review): a mark that came and went inside the 10 s of its line is told as "at
    /// rest" by the next change of the count after that time, not left as "armed"
    #[test]
    fn mark_log_follows_the_state() {
        let g = FdGate::new(1600, 64);
        g.set_marks(MARK_SHARE);
        assert_eq!(g.grab(1200, 1200), 1200);
        assert_eq!((g.marks(), g.logged.load(Relaxed)), (MARK_SHARE, MARK_SHARE), "in: logged");
        g.give(200);
        assert_eq!((g.marks(), g.logged.load(Relaxed)), (0, MARK_SHARE), "out inside the 10 s: no line");
        g.give(0);
        assert_eq!(g.logged.load(Relaxed), MARK_SHARE);
        g.log_at.0[Line10::MarkShare as usize].store(crate::metrics::now_ms(), Relaxed); // its time has come
        g.give(0);
        assert_eq!((g.marks(), g.logged.load(Relaxed)), (0, 0), "the next change of the count tells the state");
        g.give(0);
        assert!(g.log_at.0[Line10::MarkShare as usize].load(Relaxed) > crate::metrics::now_ms(), "and only once");
    }
    /// C the marks follow the granted count with an exit below the entry: share in at 3/4 of F, out below 11/16; host
    /// in at 7/8, out below 13/16. A mark that is not in use (its flag is off) is never set.
    #[test]
    fn marks_enter_and_leave_with_hysteresis() {
        const F: u32 = 1600;
        let both = MARK_SHARE | MARK_HOST;
        assert_eq!(
            (part16(F, SHARE_IN_16), part16(F, SHARE_OUT_16), part16(F, HOST_IN_16), part16(F, HOST_OUT_16)),
            (1200, 1100, 1400, 1300)
        );
        let f = |m, g| FdGate::marks_for(m, g, F, both);
        assert_eq!((f(0, 0), f(0, 1199), f(0, 1200), f(0, 1399), f(0, 1400), f(0, 1600)), (0, 0, MARK_SHARE, MARK_SHARE, both, both));
        // on the way down each mark stays until below its exit
        assert_eq!((f(both, 1399), f(both, 1300), f(both, 1299)), (both, both, MARK_SHARE));
        assert_eq!((f(MARK_SHARE, 1199), f(MARK_SHARE, 1100), f(MARK_SHARE, 1099)), (MARK_SHARE, MARK_SHARE, 0));
        // between exit and entry the mark keeps its state
        assert_eq!((f(0, 1150), f(MARK_SHARE, 1150), f(MARK_SHARE, 1350), f(both, 1350)), (0, MARK_SHARE, MARK_SHARE, both));
        // a mark not in use
        assert_eq!(
            (FdGate::marks_for(0, 1600, F, MARK_HOST), FdGate::marks_for(0, 1600, F, MARK_SHARE), FdGate::marks_for(both, 1600, F, 0)),
            (MARK_HOST, MARK_SHARE, 0)
        );
        // no overflow at the largest limit; a tiny limit still has its marks in order
        assert_eq!(part16(u32::MAX, HOST_IN_16), (u32::MAX as u64 * 14).div_ceil(16) as u32);
        // rounded up: with 2 usable fds one fd handed out is 1/2, not 7/8 (and not 3/4)
        assert_eq!((part16(2, HOST_IN_16), part16(2, SHARE_IN_16), part16(2, HOST_OUT_16)), (2, 2, 2));
        assert_eq!(FdGate::marks_for(0, 1, 2, MARK_SHARE | MARK_HOST), 0);
        assert_eq!(FdGate::marks_for(0, 2, 2, MARK_SHARE | MARK_HOST), MARK_SHARE | MARK_HOST);
        assert_eq!(FdGate::marks_for(MARK_SHARE | MARK_HOST, 1, 2, MARK_SHARE | MARK_HOST), 0);
        assert_eq!(
            (FdGate::marks_for(0, 11, 16, both), FdGate::marks_for(0, 12, 16, both), FdGate::marks_for(0, 14, 16, both)),
            (0, MARK_SHARE, both)
        );
        assert_eq!(FdGate::marks_for(0, 0, 0, both), 0, "no usable fd: nothing is handed out, nothing to mark");
        // the share rule's numbers: more than half of F; others at least F/64 and never fewer than 256
        assert_eq!(
            (share_rule(65_536), share_rule(1_048_000), share_rule(1000), share_rule(100)),
            ((32_768, 1024), (524_000, 16_375), (500, 256), (50, 256))
        );
    }

    /// C the gate moves its marks where the granted count moves (grab, give), only for the marks in use
    #[test]
    fn marks_move_with_grab_and_give() {
        let g = FdGate::new(1600, 8);
        g.grab(1500, 1);
        assert_eq!(g.marks(), 0, "both flags off: no mark");
        g.set_marks(MARK_SHARE | MARK_HOST);
        assert_eq!(g.marks(), MARK_SHARE | MARK_HOST, "set_marks looks at the count as it is");
        g.give(150);
        assert_eq!((g.granted(), g.marks()), (1350, MARK_SHARE | MARK_HOST));
        g.give(51);
        assert_eq!((g.granted(), g.marks()), (1299, MARK_SHARE));
        g.give(200);
        assert_eq!((g.granted(), g.marks()), (1099, 0));
        assert_eq!((g.grab(100, 1), g.marks()), (100, 0));
        assert_eq!((g.grab(1, 1), g.marks()), (1, MARK_SHARE));
        let h = FdGate::new(1600, 8);
        h.set_marks(MARK_HOST);
        h.grab(1400, 1);
        assert_eq!(h.marks(), MARK_HOST);
        // an unlimited gate (no readable limit, unit tests) never reaches a mark
        let u = FdGate::unlimited();
        u.set_marks(MARK_SHARE | MARK_HOST);
        u.grab(1 << 30, 1);
        assert_eq!(u.marks(), 0);
    }

    /// C threads that take and return blocks at once: when all are done the marks are those of the final count (no
    /// thread's stale view stays)
    #[test]
    fn marks_agree_with_the_count_after_contention() {
        for round in 0..20 {
            let g = Arc::new(FdGate::new(1600, 8));
            g.set_marks(MARK_SHARE | MARK_HOST);
            let hs: Vec<_> = (0..4u32)
                .map(|i| {
                    let g = g.clone();
                    std::thread::spawn(move || {
                        let mut have = 0;
                        for n in 0..5000u32 {
                            if (n + i) % 3 != 0 {
                                have += g.grab(60, 1);
                            } else {
                                g.give(have / 2);
                                have -= have / 2;
                            }
                        }
                        // leave a different amount per thread and round, anywhere between the marks
                        let keep = have.min(250 + 40 * i + 7 * round);
                        g.give(have - keep);
                    })
                })
                .collect();
            for h in hs {
                h.join().unwrap();
            }
            let (granted, m) = (g.granted(), g.marks());
            // the marks a single walk could have left at this count: exact outside the two bands
            let (lo, hi) = (FdGate::marks_for(0, granted, 1600, 3), FdGate::marks_for(3, granted, 1600, 3));
            assert!(m == lo || m == hi || m & !hi == 0 && m & lo == lo, "round {round}: granted {granted}, marks {m} (lo {lo}, hi {hi})");
        }
    }
}
