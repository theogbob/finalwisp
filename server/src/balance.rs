//! 60.74 --auto-balance (off by default): the observer thread and its rule. Stage 2 of the 60.64 prototype
//! (note 60.74; the design is 60.70 section 2.4): a move is judged by the server's TOTAL.
//!
//! Stage 1 finds a candidate, with no setting per host: a worker thread that used at least SRC of one CPU for RUN
//! ticks while another used at most DST. (60.64 also asked for idle CPU on the host; that gate is gone: idle CPU before
//! a move says nothing about the total after it, 60.64 section 10.4.)
//!
//! Stage 2 is a trial A1 / B / A2. Every worker takes a census at the start and the end of three windows of WINDOW
//! ticks: A1 (as it is), B (one busy connection moved from the bound worker to the idle one, SETTLE ticks after the
//! move), A2 (moved back, SETTLE ticks after that). A census is one worker's byte total (bytes read from clients plus
//! bytes sent to them, the closed ones included: no system call) and, per connection, the kernel's counters (one
//! getsockopt each). Two totals per window, summed over all workers: bytes per second, and data segments per second of
//! one cohort (the connections that are in all six censuses). The move is kept (moved there again) only if
//!   - the moved connection's own rate in B is at least GAIN of its rate in A1,
//!   - at least one total in B is above BOTH A windows by its margin, and neither total is below either A window by
//!     more than its margin. Margin = max(M_MIN, K x |A2 / A1 - 1|): the noise of this trial, measured at the spacing
//!     of the comparison. A trial whose A2 / A1 differs by more than NOISY is not judged (too noisy).
//!   - every worker answered every census, and no connection moved between workers inside a window (a new
//!     connection is not a move: its bytes count from 0, as the work it is).
//!
//! Else the connection stays where A2 had it (back on the bound worker), and that worker is not a source for a time
//! that doubles with every failed trial. Why A / B / A: a false "back" is the safe error (today's placement and a
//! backoff); a false "keep" is not, and with an A window on each side of B a drift in one direction cannot pass both.
//! One trial at a time in the whole process.
//!
//! Wake-ups (as 60.64): the thread sleeps (park) until a worker tells it that it used at least HOT of a CPU over its
//! sweep period, or until a worker takes a new connection. It then wakes every TICK and reads one CPU clock per
//! worker, and goes back to sleep after REST ticks without a worker at HOT and without a trial.

use crate::net::Inbox;
#[cfg(test)]
use crate::worker::R_NOTED;
use crate::worker::{answer, request, Census, M_BACK, M_CENSUS, M_END, M_MOVE, R_BUSY, R_GONE, R_MOVED, R_NONE};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// starting values (60.70 section 2.4; the null test of 60.74 settles M_MIN and K)
pub const TICK: Duration = Duration::from_millis(100);
/// per mille of one CPU: a worker tells the observer of a sweep period at or above this; below it for REST ticks the observer sleeps
pub const HOT: u32 = 500;
/// a source: at least this share of one CPU ...
pub const SRC: u32 = 950;
/// ... a destination: at most this ...
pub const DST: u32 = 100;
/// ... for this many ticks in a row
pub const RUN: u32 = 3;
/// a move is kept only if the moved connection's rate in B is at least this, per mille of its rate in A1
pub const GAIN: u64 = 1100;
/// the margin of a total, per mille: at least M_MIN, else K times the trial's noise |A2 / A1 - 1|
pub const M_MIN: u64 = 20;
pub const K: u64 = 2;
/// a trial whose |A2 / A1 - 1| is above this for a total (per mille) is too noisy to judge: no keep
pub const NOISY: u64 = 50;
/// ticks of one window (A1, B, A2) and between a move and the next window
pub const WINDOW: u64 = 5;
const SETTLE: u64 = 3;
/// ticks a request may stay unanswered or busy
const TRIES: u32 = 10;
/// ticks a connection that could not go back in TRIES is asked again (each tick), then it stays where it is
const LATE: u32 = 100;
const REST: u32 = 20;
/// after a failed trial the worker is not a source for this long, doubling up to BACKOFF_MAX; a kept move resets it
pub const BACKOFF: Duration = Duration::from_secs(10);
pub const BACKOFF_MAX: Duration = Duration::from_secs(320);
/// after any trial the worker is not a source for this long (the limit on moves per source) ...
const PAUSE: Duration = Duration::from_secs(1);
/// ... and a worker that received a kept connection is not a source for this long
const PIN: Duration = Duration::from_secs(10);

/// ticks in a row with a busy thread and no trial possible (no source, no destination, the sources resting): one
/// round with no move
const LOOK: u32 = 10;
/// rounds in a row with no move (a trial judged too noisy, a trial dropped, LOOK ticks with no candidate): the
/// observer naps NAP, doubling up to NAP_MAX, and takes no sample meanwhile (a judged trial or a rest resets it)
const CALM: u32 = 2;
pub const NAP: Duration = Duration::from_secs(5);
/// only a host with at most this many workers naps: there a trial is mostly noise (60.74 null test: 2 workers), and a
/// nap on a host with many cores held a move back by up to 40 s (60.74 section 4.3)
pub const NAP_MAX_WORKERS: usize = 4;
pub const NAP_MAX: Duration = Duration::from_secs(160);

static OBSERVER: OnceLock<std::thread::Thread> = OnceLock::new();
/// the observer naps: the workers do not wake it and do not read their CPU clock (one relaxed load each)
static NAPPING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// naps so far, and the length of the one under way in seconds (0: awake); the metrics line shows them
pub static NAPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static NAP_S: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The observer thread runs (--auto-balance with more than one worker): the metrics line shows its naps.
pub fn running() -> bool {
    OBSERVER.get().is_some()
}

/// The observer naps (mig_report: no clock read).
#[inline]
pub fn napping() -> bool {
    NAPPING.load(std::sync::atomic::Ordering::Relaxed)
}

/// A worker's sweep period was at or above HOT, or a worker took a new connection (load often starts right after the
/// accept, and the next sweep is up to 2 s away): wake the observer (no system call unless it sleeps).
pub fn hot() {
    if napping() {
        return; // (it looks again when the nap ends)
    }
    if let Some(t) = OBSERVER.get() {
        t.unpark();
    }
}

/// What the rule needs from the process (the tests give it a model).
pub trait Io {
    fn send(&mut self, w: usize, bits: u64, to: usize, seq: u32);
    /// worker `w`'s last answer: (request number, R_*, value)
    fn out(&mut self, w: usize) -> (u32, u64, u64);
    /// worker `w`'s census of request `seq`, once (None: not there yet, or another request's)
    fn census(&mut self, w: usize, seq: u32) -> Option<Census>;
    /// the socket cookie of the connection that worker `w` handed on at its M_MOVE of request `seq` (0: not known)
    fn moved(&mut self, w: usize, seq: u32) -> u64;
    /// take worker `w`'s request back: true if it was still in its word (it will never be acted on), false if the
    /// worker had taken it already (its answer will come)
    fn cancel(&mut self, w: usize) -> bool;
    fn note(&mut self, _line: std::fmt::Arguments) {}
}

/// One window's totals: bytes per second (all connections, all workers) and data segments per second (the cohort).
/// None: no measurement (a census counter went down, or a connection arrived or left inside the window).
pub type Totals = Option<[f64; 2]>;

/// Why a trial was not kept (the debug line; the tests)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Why {
    Keep,
    /// a window is not a measurement
    NoMeasure,
    /// neither total had traffic in the A windows
    Empty,
    /// |A2 / A1 - 1| above NOISY for a total
    Noisy,
    /// a total in B below an A window by more than its margin
    Fell,
    /// the moved connection did not gain GAIN (or its rate is not known)
    Moved,
    /// no total in B above both A windows by its margin
    Flat,
}

/// The verdict on a trial (pure: the unit tests drive it). `w`: the three windows A1, B, A2; `moved`: the moved
/// connection's rate in B over its rate in A1.
pub fn judge(w: [Totals; 3], moved: Option<f64>) -> (Why, [f64; 2]) {
    let mut margin = [0f64; 2];
    let [Some(a1), Some(b), Some(a2)] = w else { return (Why::NoMeasure, margin) };
    let (mut any, mut up) = (false, false);
    for q in 0..2 {
        let (x1, y, x2) = (a1[q], b[q], a2[q]);
        if x1 <= 0.0 && x2 <= 0.0 {
            continue; // no traffic of that kind (or an empty cohort): no verdict for this total
        }
        if x1 <= 0.0 || x2 <= 0.0 {
            return (Why::Noisy, margin);
        }
        any = true;
        let noise = (x2 / x1 - 1.0).abs();
        if noise * 1000.0 > NOISY as f64 {
            return (Why::Noisy, margin);
        }
        let m = (M_MIN as f64 / 1000.0).max(K as f64 * noise);
        margin[q] = m;
        if y < x1 * (1.0 - m) || y < x2 * (1.0 - m) {
            return (Why::Fell, margin);
        }
        up |= y > x1 * (1.0 + m) && y > x2 * (1.0 + m);
    }
    if !any {
        return (Why::Empty, margin);
    }
    if moved.is_none_or(|r| r * 1000.0 < GAIN as f64) {
        return (Why::Moved, margin);
    }
    (if up { Why::Keep } else { Why::Flat }, margin)
}

/// a connection in the six censuses: (time of the census, kernel bytes, data segments)
type Seen = [Option<(Instant, u64, u32)>; 6];

/// The six censuses of a trial (start and end of A1, B, A2), one per worker each: the totals of the three windows,
/// the cohort's size, and the rate of connection `cookie` in B over its rate in A1.
pub fn totals(snaps: &[Vec<Census>], cookie: u64) -> ([Totals; 3], usize, Option<f64>) {
    let mut out = [None; 3];
    // the cohort: connections (by cookie) in all six censuses
    let mut seen: HashMap<u64, Seen> = HashMap::new();
    for (k, snap) in snaps.iter().enumerate() {
        for c in snap {
            for &(id, b, s) in &c.conns {
                seen.entry(id).or_insert([None; 6])[k] = Some((c.at, b, s));
            }
        }
    }
    seen.retain(|_, v| v.iter().all(Option::is_some));
    let secs = |a: Instant, b: Instant| b.saturating_duration_since(a).as_secs_f64().max(1e-6);
    for (i, o) in out.iter_mut().enumerate() {
        let (s0, s1) = (&snaps[2 * i], &snaps[2 * i + 1]);
        if s0.len() != s1.len() {
            continue;
        }
        let mut bytes = 0f64;
        let mut ok = true;
        for (a, b) in s0.iter().zip(s1) {
            ok &= b.bytes >= a.bytes && b.moves == a.moves;
            bytes += b.bytes.wrapping_sub(a.bytes) as f64 / secs(a.at, b.at);
        }
        let segs: f64 = seen
            .values()
            .map(|v| v[2 * i + 1].unwrap().2.wrapping_sub(v[2 * i].unwrap().2) as f64 / secs(v[2 * i].unwrap().0, v[2 * i + 1].unwrap().0))
            .sum();
        *o = ok.then_some([bytes, segs]);
    }
    let rate = |v: &Seen, i: usize| {
        let (a, b) = (v[2 * i].unwrap(), v[2 * i + 1].unwrap());
        b.1.saturating_sub(a.1) as f64 / secs(a.0, b.0)
    };
    let moved = seen.get(&cookie).filter(|_| cookie != 0).and_then(|v| {
        let a1 = rate(v, 0);
        (a1 > 0.0).then(|| rate(v, 1) / a1)
    });
    (out, seen.len(), moved)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum St {
    Idle,
    /// census number `k` (0 to 5) of the trial, request `seq` sent at tick `at`, `tries` repeats (k 1 and 3: with
    /// the move)
    Snap {
        k: usize,
        seq: u32,
        at: u64,
        tries: u32,
    },
    /// waiting for census `k` until tick `at` (a window, or the settle time after a move)
    Wait {
        k: usize,
        at: u64,
    },
    /// the move was not answered in TRIES ticks and the worker had taken the request: its answer is waited for (LATE
    /// ticks at most), and a move that happened goes back
    Cancel {
        seq: u32,
        tries: u32,
    },
    /// the connection goes back to the source without a verdict (`tries` ticks so far; LATE at most)
    Return {
        seq: u32,
        tries: u32,
    },
    /// kept: the connection goes to the destination again
    Keep {
        seq: u32,
        tries: u32,
    },
}

pub struct Rule {
    src_n: Vec<u32>,
    dst_n: Vec<u32>,
    not_before: Vec<Instant>,
    backoff: Vec<Duration>,
    cool: u32,
    seq: u32,
    tick: u64,
    st: St,
    /// the trial: source, destination, the moved connection's cookie, the censuses so far (per census, per worker)
    s: usize,
    d: usize,
    cookie: u64,
    snaps: Vec<Vec<Option<Census>>>,
    /// ticks of a window (WINDOW; the pooltest hook FW_AB_TICKS changes it for the null test)
    pub win: u64,
    /// the null test (pooltest FW_AB_DRY): trials one after the other on workers 0 and 1, with NO move
    pub dry: bool,
    /// trials: kept, not kept (judged, or no measurement after the move), given up before a judgement
    pub kept: u64,
    pub back: u64,
    pub dropped: u64,
    /// the last trial's verdict and windows (tests)
    pub last: Option<Why>,
    pub windows: [Totals; 3],
    /// the judged trial's window lengths as measured, ms (0: not judged)
    real_ms: [u64; 3],
    /// rounds with no move in a row (CALM), ticks with no candidate in a row (LOOK), the next nap, a nap due
    calm: u32,
    look: u32,
    nap: Duration,
    nap_due: Option<Duration>,
}

impl Rule {
    pub fn new(workers: usize, now: Instant) -> Rule {
        Rule {
            src_n: vec![0; workers],
            dst_n: vec![0; workers],
            not_before: vec![now; workers],
            backoff: vec![BACKOFF; workers],
            cool: 0,
            seq: 0,
            tick: 0,
            st: St::Idle,
            s: 0,
            d: 0,
            cookie: 0,
            snaps: Vec::new(),
            win: WINDOW,
            dry: false,
            kept: 0,
            back: 0,
            dropped: 0,
            last: None,
            windows: [None; 3],
            real_ms: [0; 3],
            calm: 0,
            look: 0,
            nap: NAP,
            nap_due: None,
        }
    }

    /// Request numbers: 32 bits, never 0 (0 = no answer yet). A worker's last answer stays in its word, so a number
    /// must not come back while an old answer with it can still be there: 2^32 requests are years of trials.
    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    fn end(&mut self, io: &mut dyn Io) {
        io.send(self.s, M_END, 0, 0);
        io.send(self.d, M_END, 0, 0);
        self.snaps.clear();
        self.st = St::Idle;
    }

    /// A round with no move: a trial too noisy to judge or dropped, or LOOK ticks with no candidate. CALM of them in
    /// a row: a nap is due (the observer loop takes it), and the next one is twice as long (NAP_MAX at most). Only on
    /// a host with NAP_MAX_WORKERS workers or fewer.
    fn no_move(&mut self) {
        if self.dry || self.src_n.len() > NAP_MAX_WORKERS {
            return;
        }
        self.calm += 1;
        if self.calm >= CALM {
            self.calm = 0;
            self.nap_due = Some(self.nap);
            self.nap = (self.nap * 2).min(NAP_MAX);
        }
    }

    /// A nap that is due (None: none); the observer sleeps it, then calls woke.
    pub fn take_nap(&mut self) -> Option<Duration> {
        self.nap_due.take()
    }

    /// The trial ends without a verdict: one debug line, and the source rests `pause` (None: the backoff of a failed
    /// trial).
    fn drop_trial(&mut self, io: &mut dyn Io, now: Instant, why: &str, pause: Option<Duration>) {
        io.note(format_args!("trial w{} -> w{}: dropped: {why}", self.s, self.d));
        self.dropped += 1;
        self.no_move();
        match pause {
            Some(p) => self.not_before[self.s] = now + p,
            None => self.failed(now),
        }
        self.end(io);
    }

    fn failed(&mut self, now: Instant) {
        let s = self.s;
        self.not_before[s] = now + self.backoff[s];
        self.backoff[s] = (self.backoff[s] * 2).min(BACKOFF_MAX);
    }

    /// Census `k`: every worker; with it the source hands a connection on (k 1) and the destination hands it back
    /// (k 3). In the null test nothing moves.
    ///
    /// The worker that moves is asked LAST: the census request of the worker that receives is then in its word before
    /// the arrival can be, so it takes the census first (mig_cmd: a census before the arrivals of the same word) and
    /// the arrival falls between two windows, not inside one.
    fn ask(&mut self, io: &mut dyn Io, k: usize, tries: u32) {
        let q = self.next_seq();
        let mover = match k {
            1 if !self.dry => Some((self.s, M_MOVE, self.d)),
            3 if !self.dry => Some((self.d, M_BACK, self.s)),
            _ => None,
        };
        for w in (0..self.src_n.len()).filter(|&w| mover.is_none_or(|m| m.0 != w)) {
            io.send(w, M_CENSUS, 0, q);
        }
        if let Some((w, bit, to)) = mover {
            io.send(w, M_CENSUS | bit, to, q);
        }
        self.snaps[k] = vec![None; self.src_n.len()];
        self.st = St::Snap { k, seq: q, at: self.tick, tries };
    }

    /// The connection is on the destination and the trial cannot be judged: it goes back (Return).
    fn undo(&mut self, io: &mut dyn Io, why: &str) {
        io.note(format_args!("trial w{} -> w{}: {why}: back", self.s, self.d));
        if self.dry {
            self.back += 1;
            self.end(io);
            return;
        }
        let q = self.next_seq();
        io.send(self.d, M_BACK, self.s, q);
        self.st = St::Return { seq: q, tries: 0 };
    }

    /// The observer slept `parked` and was woken (a sweep report, a new connection): it watches for REST ticks again,
    /// and what it counted before the sleep is old. A sleep of NAP or more was a rest: the next busy period starts with
    /// no nap behind it. A shorter one (light load, new connections waking it) is a round with no move: such wakes
    /// end in naps too, during which a new connection does not wake it.
    pub fn parked(&mut self, parked: Duration) {
        if parked >= NAP {
            (self.calm, self.nap) = (0, NAP);
        } else {
            self.no_move();
        }
        self.woke();
    }

    /// The observer looks again after a sleep or a nap (see parked).
    pub fn woke(&mut self) {
        self.cool = 0;
        self.look = 0;
        self.src_n.fill(0);
        self.dst_n.fill(0);
    }

    /// One tick. `shares`: each worker's CPU share over the tick, per mille. Returns true when the observer may sleep.
    pub fn step(&mut self, shares: &[u32], now: Instant, io: &mut dyn Io) -> bool {
        self.tick += 1;
        for (i, &v) in shares.iter().enumerate() {
            self.src_n[i] = if v >= SRC { self.src_n[i] + 1 } else { 0 };
            self.dst_n[i] = if v <= DST { self.dst_n[i] + 1 } else { 0 };
        }
        self.cool = if shares.iter().any(|&v| v >= HOT) { 0 } else { self.cool + 1 };
        let (s, d) = (self.s, self.d);
        match self.st {
            St::Idle => {
                let pick = if self.dry {
                    (shares.len() > 1 && now >= self.not_before[0]).then_some((0, 1))
                } else {
                    let s = (0..shares.len()).filter(|&i| self.src_n[i] >= RUN && now >= self.not_before[i]).max_by_key(|&i| shares[i]);
                    // (every other thread in use: nothing moves)
                    s.and_then(|s| (0..shares.len()).filter(|&i| i != s && self.dst_n[i] >= RUN).min_by_key(|&i| shares[i]).map(|d| (s, d)))
                };
                let Some((s, d)) = pick else {
                    if !self.dry && self.cool >= REST {
                        return true; // no load (parked decides what the sleep was)
                    }
                    // (a round: LOOK ticks with a busy thread; a quiet tick is not one, REST counts those)
                    self.look = if self.cool == 0 { self.look + 1 } else { 0 };
                    if self.look >= LOOK {
                        self.look = 0;
                        self.no_move();
                    }
                    return false;
                };
                self.look = 0;
                (self.s, self.d, self.cookie) = (s, d, 0);
                self.snaps = vec![Vec::new(); 6];
                // a trial starts clean on both workers: what an earlier trial left there (a worker that answered too
                // late) is dropped before anything of this one happens (the worker handles M_END first)
                io.send(s, M_END, 0, 0);
                io.send(d, M_END, 0, 0);
                self.ask(io, 0, 0);
            }
            St::Wait { k, at } => {
                // A1: the candidate must still be one (the source busy, the destination not): else nothing is tried
                if k == 1 && !self.dry && (shares[s] < HOT || shares[d] >= HOT) {
                    self.drop_trial(io, now, "no longer a candidate in A1", Some(PAUSE));
                } else if self.tick >= at {
                    self.ask(io, k, 0);
                }
            }
            St::Snap { k, seq, at, tries } => {
                for (w, c) in self.snaps[k].iter_mut().enumerate() {
                    if c.is_none() {
                        *c = io.census(w, seq);
                    }
                }
                let all = self.snaps[k].iter().all(Option::is_some);
                let mover = match k {
                    1 if !self.dry => Some(s),
                    3 if !self.dry => Some(d),
                    _ => None,
                };
                let code = mover.map(|w| io.out(w)).filter(|a| a.0 == seq).map(|a| a.1);
                let late = self.tick >= at + TRIES as u64;
                match (k, mover, code) {
                    // the move: the source answers
                    (1, Some(_), Some(R_MOVED)) => {
                        self.cookie = io.moved(s, seq);
                        if all {
                            self.st = St::Wait { k: 2, at: at + SETTLE };
                        } else if late {
                            self.undo(io, "a census was not answered");
                        }
                    }
                    (1, Some(_), Some(R_NONE)) => {
                        // fewer than two busy connections (or not at rest): a thread bound by one connection stays
                        self.drop_trial(io, now, "no second busy connection", None);
                    }
                    (1, Some(_), Some(R_BUSY)) if tries + 1 < TRIES => self.ask(io, 1, tries + 1), // (A1 ends later)
                    (1, Some(_), Some(_)) => self.drop_trial(io, now, "no connection at rest", Some(PAUSE * 2)),
                    (1, Some(_), None) if late => {
                        // take the request back (a worker that takes it later must not move a connection that nobody
                        // would judge). If the worker had taken it already, its answer is waited for.
                        if io.cancel(s) {
                            self.drop_trial(io, now, "the move was not taken in 1 s", Some(PAUSE * 2));
                        } else {
                            self.st = St::Cancel { seq, tries: 0 };
                        }
                    }
                    // the move back: the destination answers
                    (3, Some(_), Some(R_MOVED)) => {
                        if all {
                            self.st = St::Wait { k: 4, at: at + SETTLE };
                        } else if late {
                            // back on the source, but window B has no measurement
                            self.verdict(io, now, Why::NoMeasure, [0.0; 2], [None; 3], 0, None);
                        }
                    }
                    (3, Some(_), Some(R_GONE)) => {
                        // the connection closed meanwhile: nothing to judge
                        self.drop_trial(io, now, "the connection closed", Some(PAUSE));
                    }
                    (3, Some(_), Some(R_BUSY)) if tries + 1 < TRIES => self.ask(io, 3, tries + 1), // (B ends later)
                    (3, Some(_), _) if late || code.is_some() => {
                        // not back in a second: no A2, a failed trial; it is asked back for up to LATE ticks
                        io.note(format_args!("trial w{s} -> w{d}: not at rest for the move back"));
                        let q = self.next_seq();
                        io.send(d, M_BACK, s, q);
                        self.st = St::Return { seq: q, tries: TRIES };
                    }
                    (_, Some(_), _) => {}
                    // a census only
                    (_, None, _) if all => {
                        let lost = k == 2 || k == 4; // the moved connection must be on the worker that got it
                        let at_w = if k == 2 { d } else { s };
                        let here = self.cookie == 0
                            || self.snaps[k][at_w].as_ref().is_some_and(|c| c.many || c.conns.iter().any(|x| x.0 == self.cookie));
                        if self.dry || !lost || here {
                            if k == 5 {
                                self.judge_now(io, now);
                            } else {
                                let gap = if k % 2 == 0 { self.win } else { SETTLE };
                                self.st = St::Wait { k: k + 1, at: at + gap }; // (from the tick the census was asked)
                            }
                        } else if k == 2 {
                            self.undo(io, "the connection is not on the destination");
                        } else {
                            // (closed, or reset at the move back)
                            self.drop_trial(io, now, "the connection is not on the source in A2", Some(PAUSE));
                        }
                    }
                    (_, None, _) if late => match k {
                        0 => self.drop_trial(io, now, "a census was not answered", Some(PAUSE * 2)),
                        2 => self.undo(io, "a census was not answered"),
                        // (4, 5: the connection is back on the source; no verdict)
                        _ => self.verdict(io, now, Why::NoMeasure, [0.0; 2], [None; 3], 0, None),
                    },
                    _ => {}
                }
            }
            St::Cancel { seq, tries } => match io.out(s) {
                (q, R_MOVED, _) if q == seq => {
                    self.cookie = io.moved(s, seq);
                    self.undo(io, "the move was late");
                }
                (q, _, _) if q == seq => self.drop_trial(io, now, "the move was late and did not happen", Some(PAUSE * 2)),
                // (a worker that does not answer for 10 s: nothing more can be done from here)
                _ if tries + 1 >= LATE => self.drop_trial(io, now, "the source did not answer the move for 10 s", Some(PAUSE * 2)),
                _ => self.st = St::Cancel { seq, tries: tries + 1 },
            },
            St::Return { seq, tries } => match io.out(d) {
                (q, R_GONE, _) if q == seq => self.drop_trial(io, now, "the connection closed before it went back", Some(PAUSE)),
                (q, R_MOVED, _) if q == seq => {
                    io.note(format_args!("trial w{s} -> w{d}: back on the source"));
                    self.back += 1;
                    self.no_move(); // (back without a verdict: nothing measured)
                    self.failed(now);
                    self.end(io);
                }
                (q, code, _) => {
                    if tries + 1 >= LATE {
                        // it holds something that cannot move (or its worker does not answer): the request is taken
                        // back and the connection stays where it is (the one placement nobody judged)
                        io.send(d, 0, 0, 0);
                        self.drop_trial(io, now, "not back in 10 s: it stays on the destination", None);
                    } else if q == seq && code == R_BUSY {
                        let q = self.next_seq();
                        io.send(d, M_BACK, s, q);
                        self.st = St::Return { seq: q, tries: tries + 1 };
                    } else {
                        self.st = St::Return { seq, tries: tries + 1 };
                    }
                }
            },
            St::Keep { seq, tries } => match io.out(s) {
                (q, R_MOVED, _) if q == seq => {
                    self.kept += 1;
                    self.backoff[s] = BACKOFF;
                    self.not_before[s] = now + PAUSE;
                    self.not_before[d] = now + PIN;
                    self.end(io);
                }
                (q, R_GONE, _) if q == seq => self.drop_trial(io, now, "kept, but the connection closed", Some(PAUSE)),
                (q, code, _) => {
                    if tries + 1 >= TRIES {
                        io.send(s, 0, 0, 0);
                        self.drop_trial(io, now, "kept, but not at rest for a second: it stays on the source", Some(PAUSE * 2));
                    } else if q == seq && code == R_BUSY {
                        let q = self.next_seq();
                        io.send(s, M_BACK, d, q);
                        self.st = St::Keep { seq: q, tries: tries + 1 };
                    } else {
                        self.st = St::Keep { seq, tries: tries + 1 };
                    }
                }
            },
        }
        false
    }

    fn judge_now(&mut self, io: &mut dyn Io, now: Instant) {
        let snaps: Vec<Vec<Census>> = std::mem::take(&mut self.snaps).into_iter().map(|v| v.into_iter().flatten().collect()).collect();
        let (w, cohort, moved) = totals(&snaps, self.cookie);
        let (why, margin) = judge(w, if self.dry { Some(f64::INFINITY) } else { moved });
        // the windows as measured (worker 0's censuses; the window is set in ticks, the census answers add to it)
        self.real_ms = [0, 1, 2].map(|i| snaps[2 * i + 1][0].at.saturating_duration_since(snaps[2 * i][0].at).as_millis() as u64);
        self.verdict(io, now, why, margin, w, cohort, moved);
    }

    /// The trial's line (debug log: one per judged trial, the six totals for the null test) and what follows.
    #[allow(clippy::too_many_arguments)]
    fn verdict(&mut self, io: &mut dyn Io, now: Instant, why: Why, margin: [f64; 2], w: [Totals; 3], cohort: usize, moved: Option<f64>) {
        let t = |i: usize, q: usize| w[i].map_or(-1.0, |v| v[q]);
        io.note(format_args!(
            "trial w{} -> w{} dry={} win_ms={} real_ms={},{},{} a1_bytes={:.0} b_bytes={:.0} a2_bytes={:.0} a1_segs={:.1} b_segs={:.1} a2_segs={:.1} cohort={cohort} moved={:.3} margin_bytes={:.3} margin_segs={:.3} verdict={why:?}",
            self.s,
            self.d,
            u8::from(self.dry),
            self.win * TICK.as_millis() as u64,
            self.real_ms[0],
            self.real_ms[1],
            self.real_ms[2],
            t(0, 0),
            t(1, 0),
            t(2, 0),
            t(0, 1),
            t(1, 1),
            t(2, 1),
            moved.unwrap_or(-1.0),
            margin[0],
            margin[1],
        ));
        (self.last, self.windows, self.real_ms) = (Some(why), w, [0; 3]);
        if matches!(why, Why::Noisy | Why::Empty | Why::NoMeasure) {
            self.no_move(); // (nothing measured)
        } else {
            // a judged trial: the rule has something to do here
            (self.calm, self.nap) = (0, NAP);
        }
        self.snaps.clear();
        if why == Why::Keep && !self.dry {
            let q = self.next_seq();
            io.send(self.s, M_BACK, self.d, q);
            self.st = St::Keep { seq: q, tries: 0 };
            return;
        }
        self.back += 1;
        if self.dry {
            self.end(io);
        } else {
            self.failed(now);
            self.end(io);
        }
    }
}

/// The CPU clock of a worker thread (the observer reads it; the worker runs no code for it).
pub fn cpu_clock<T>(h: &std::thread::JoinHandle<T>) -> Option<libc::clockid_t> {
    use std::os::unix::thread::JoinHandleExt as _;
    let mut c: libc::clockid_t = 0;
    (unsafe { libc::pthread_getcpuclockid(h.as_pthread_t(), &mut c) } == 0).then_some(c)
}

fn clock_ns(c: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(c, &mut ts) } != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// This thread's CPU time, ns (a worker's sweep report)
pub fn thread_cpu_ns() -> u64 {
    clock_ns(libc::CLOCK_THREAD_CPUTIME_ID)
}

struct Real {
    peers: Arc<Vec<Arc<Inbox>>>,
}

impl Io for Real {
    fn send(&mut self, w: usize, bits: u64, to: usize, seq: u32) {
        let m = &self.peers[w].mig;
        // only this thread writes request bits: an older request the worker did not take yet is replaced, but an
        // M_END it did not take yet stays (the worker handles it first: a trial's state never outlives its trial)
        m.cmd.fetch_and(crate::worker::M_IMPORT | M_END, std::sync::atomic::Ordering::AcqRel);
        if bits != 0 {
            m.cmd.fetch_or(request(bits, to, seq), std::sync::atomic::Ordering::AcqRel);
            self.peers[w].wake();
        } // (0: the request is taken back)
    }
    fn out(&mut self, w: usize) -> (u32, u64, u64) {
        answer(self.peers[w].mig.out.load(std::sync::atomic::Ordering::Acquire))
    }
    fn census(&mut self, w: usize, seq: u32) -> Option<Census> {
        let mut s = self.peers[w].mig.snap.lock().unwrap();
        if s.as_ref().is_some_and(|c| c.seq == seq) {
            s.take()
        } else {
            None
        }
    }
    fn moved(&mut self, w: usize, seq: u32) -> u64 {
        // (the worker stores both before its answer, which the caller read with Acquire)
        let m = &self.peers[w].mig;
        if m.moved_seq.load(std::sync::atomic::Ordering::Relaxed) == seq {
            m.moved.load(std::sync::atomic::Ordering::Relaxed)
        } else {
            0 // (a late move of an older request wrote it, or none: not known)
        }
    }
    fn cancel(&mut self, w: usize) -> bool {
        let keep = crate::worker::M_IMPORT | M_END;
        self.peers[w].mig.cmd.fetch_and(keep, std::sync::atomic::Ordering::AcqRel) & !keep != 0
    }
    fn note(&mut self, line: std::fmt::Arguments) {
        if crate::logs::on(crate::logs::Level::Debug) {
            crate::metrics::log_nowait(format!("finalwisp: auto-balance: {line}"));
        }
    }
}

/// Start the observer (main, with --auto-balance and more than one worker). `clocks`: the workers' CPU clocks, by index.
pub fn start(peers: Arc<Vec<Arc<Inbox>>>, clocks: Vec<libc::clockid_t>) {
    let spawned = std::thread::Builder::new().name("balance".into()).spawn(move || {
        let mut io = Real { peers };
        let mut rule = Rule::new(clocks.len(), Instant::now());
        // 60.74 test hooks (cargo feature pooltest, never in a release): the null test of the A / B / A windows
        #[cfg(feature = "pooltest")]
        {
            rule.dry = std::env::var("FW_AB_DRY").is_ok_and(|v| v == "1");
            if let Some(n) = std::env::var("FW_AB_TICKS").ok().and_then(|v| v.parse::<u64>().ok()).filter(|&n| (1..=100).contains(&n)) {
                rule.win = n;
            }
        }
        let mut shares = vec![0u32; clocks.len()];
        let mut last: Vec<u64> = clocks.iter().map(|&c| clock_ns(c)).collect();
        let mut at = Instant::now();
        let mut rest = !rule.dry; // (sleeps until the first report)
        loop {
            if rest {
                let t0 = Instant::now();
                std::thread::park();
                rule.parked(t0.elapsed());
                last = clocks.iter().map(|&c| clock_ns(c)).collect();
                at = Instant::now();
            }
            std::thread::sleep(TICK);
            let now = Instant::now();
            let ns = now.duration_since(at).as_nanos().max(1) as u64;
            for (i, &c) in clocks.iter().enumerate() {
                let v = clock_ns(c);
                shares[i] = (v.saturating_sub(last[i]).saturating_mul(1000) / ns).min(1000) as u32;
                last[i] = v;
            }
            at = now;
            rest = rule.step(&shares, now, &mut io);
            if let Some(nap) = rule.take_nap() {
                // nothing to do: no sample, no clock read, and the workers do not wake this thread until it ends
                use std::sync::atomic::Ordering::Relaxed;
                NAPPING.store(true, Relaxed);
                // (requests of the last trial still in a word, a census of a worker that answered late: taken back,
                // so no worker counts its connections during the nap)
                for w in 0..clocks.len() {
                    io.send(w, 0, 0, 0);
                }
                NAPS.fetch_add(1, Relaxed);
                NAP_S.store(nap.as_secs(), Relaxed);
                io.note(format_args!("nap {} s (no move in {CALM} rounds)", nap.as_secs()));
                std::thread::sleep(nap);
                NAP_S.store(0, Relaxed);
                NAPPING.store(false, Relaxed);
                rule.woke();
                last = clocks.iter().map(|&c| clock_ns(c)).collect();
                at = Instant::now();
                rest = false;
            }
        }
    });
    match spawned {
        Ok(h) => {
            let _ = OBSERVER.set(h.thread().clone());
        }
        Err(e) => crate::metrics::log_nowait(format!("finalwisp: --auto-balance is off: its thread did not start ({e})")),
    }
}

/// 60.74 the rule of the stage-2 build (79597662 = aa514831, which gold3 timed), frozen for tests::gt4_path_decides_as_stage_2
#[cfg(test)]
#[allow(clippy::all, unused_imports)]
#[path = "../testdata/balance_stage2.rs"]
mod stage2;

#[cfg(test)]
mod tests {
    use super::*;

    /// one connection of the model: its worker, its counters, its rate (bytes and segments per tick at factor 1)
    #[derive(Clone)]
    struct Conn {
        id: u64,
        w: usize,
        rx: f64,
        tx: f64,
        segs: f64,
        rate: f64,
    }

    /// A model of the workers: answers a request at once. The rate of each connection per tick is its `rate` times
    /// `factor(conn, the moved one is on the destination, tick)`.
    struct Model {
        conns: Vec<Conn>,
        rx: Vec<f64>,
        moves: Vec<u64>,
        snap: Vec<Option<Census>>,
        out: Vec<(u32, u64, u64)>,
        moved_id: Vec<u64>,
        moved_seq: Vec<u32>,
        /// a request taken back was taken by the worker already (Io::cancel answers false)
        taken: bool,
        /// (worker, n): the worker answers its first n censuses only
        mute_after: Option<(usize, usize)>,
        censuses: Vec<usize>,
        now: Instant,
        tick: u64,
        /// the answer to M_MOVE and to M_BACK
        on_move: u64,
        on_back: u64,
        /// (worker, request bit) that get no answer
        mute: Vec<(usize, u64)>,
        sent: Vec<(usize, u64, usize, u32)>,
        /// the trial's connection and where it went (source, destination)
        trial: Option<(u64, usize, usize)>,
        factor: fn(&Conn, bool, u64) -> f64,
    }

    impl Model {
        fn new(n: usize, conns: &[(usize, f64)], factor: fn(&Conn, bool, u64) -> f64) -> Model {
            Model {
                conns: conns
                    .iter()
                    .enumerate()
                    .map(|(i, &(w, rate))| Conn { id: 100 + i as u64, w, rx: 0.0, tx: 0.0, segs: 0.0, rate })
                    .collect(),
                rx: vec![0.0; n],
                moves: vec![0; n],
                snap: vec![None; n],
                out: vec![(0, 0, 0); n],
                moved_id: vec![0; n],
                moved_seq: vec![0; n],
                taken: false,
                mute_after: None,
                censuses: vec![0; n],
                now: Instant::now(),
                tick: 0,
                on_move: R_MOVED,
                on_back: R_MOVED,
                mute: Vec::new(),
                sent: Vec::new(),
                trial: None,
                factor,
            }
        }
        /// the moved connection is on the destination now
        fn away(&self) -> bool {
            self.trial.is_some_and(|(id, _, d)| self.conns.iter().any(|c| c.id == id && c.w == d))
        }
        fn advance(&mut self) {
            let away = self.away();
            for c in self.conns.iter_mut() {
                let r = c.rate * (self.factor)(c, away, self.tick);
                c.rx += r / 2.0;
                c.tx += r / 2.0;
                c.segs += r / 10.0;
                self.rx[c.w] += r / 2.0;
            }
            self.tick += 1;
            self.now += TICK;
        }
        fn take_census(&self, w: usize, seq: u32) -> Census {
            let on: Vec<&Conn> = self.conns.iter().filter(|c| c.w == w).collect();
            Census {
                seq,
                at: self.now,
                bytes: (self.rx[w] + on.iter().map(|c| c.tx).sum::<f64>()) as u64,
                conns: on.iter().map(|c| (c.id, (c.rx + c.tx) as u64, c.segs as u32)).collect(),
                many: false,
                moves: self.moves[w],
            }
        }
        fn shift(&mut self, id: u64, to: usize) {
            let c = self.conns.iter_mut().find(|c| c.id == id).unwrap();
            self.moves[c.w] += 1;
            self.moves[to] += 1;
            // (bytes read stay with the worker that read them; the bytes sent travel with the connection)
            c.w = to;
        }
        fn on(&self, id: u64) -> usize {
            self.conns.iter().find(|c| c.id == id).unwrap().w
        }
        fn bits(&self, bit: u64) -> usize {
            self.sent.iter().filter(|x| x.1 & bit != 0).count()
        }
    }

    impl Io for Model {
        fn send(&mut self, w: usize, bits: u64, to: usize, seq: u32) {
            self.sent.push((w, bits, to, seq));
            if bits & M_CENSUS != 0 {
                self.censuses[w] += 1;
            }
            let late = self.mute_after.is_some_and(|(mw, n)| mw == w && self.censuses[w] > n);
            if bits & M_CENSUS != 0 && !self.mute.contains(&(w, M_CENSUS)) && !late {
                self.snap[w] = Some(self.take_census(w, seq));
                if bits & (M_MOVE | M_BACK) == 0 {
                    self.out[w] = (seq, R_NOTED, 0);
                }
            }
            if bits & M_MOVE != 0 && !self.mute.contains(&(w, M_MOVE)) {
                self.out[w] = (seq, self.on_move, 0);
                if self.on_move == R_MOVED {
                    // the second connection of the worker goes
                    let id = self.conns.iter().filter(|c| c.w == w).nth(1).unwrap().id;
                    self.shift(id, to);
                    (self.moved_id[w], self.moved_seq[w]) = (id, seq);
                    self.trial = Some((id, w, to));
                }
            }
            if bits & M_BACK != 0 && !self.mute.contains(&(w, M_BACK)) {
                let id = self.trial.map(|t| t.0).filter(|&id| self.on(id) == w);
                self.out[w] = match id {
                    None => (seq, R_GONE, 0),
                    Some(_) if self.on_back != R_MOVED => (seq, self.on_back, 0),
                    Some(id) => {
                        self.shift(id, to);
                        (seq, R_MOVED, 0)
                    }
                };
            }
        }
        fn out(&mut self, w: usize) -> (u32, u64, u64) {
            self.out[w]
        }
        fn census(&mut self, w: usize, seq: u32) -> Option<Census> {
            self.snap[w].take_if(|c| c.seq == seq)
        }
        fn moved(&mut self, w: usize, seq: u32) -> u64 {
            if self.moved_seq[w] == seq {
                self.moved_id[w]
            } else {
                0
            }
        }
        fn cancel(&mut self, w: usize) -> bool {
            self.sent.push((w, 0, 0, 0));
            !self.taken
        }
    }

    fn run(r: &mut Rule, io: &mut Model, shares: &[u32], ticks: u64) {
        for _ in 0..ticks {
            io.advance();
            let now = io.now;
            r.step(shares, now, io);
        }
    }

    fn flat(_: &Conn, _: bool, _: u64) -> f64 {
        1.0
    }
    /// churn on a bound thread (60.64 section 10.4, churn 8x32): alone on a thread the moved one runs x1.3, nothing
    /// else changes: the total rises
    fn churn(c: &Conn, away: bool, _: u64) -> f64 {
        if away && c.id == 101 {
            1.3
        } else {
            1.0
        }
    }
    /// co-located bulk (60.64 section 10.4, native 8x4): the moved one and the one that stayed both run faster, the
    /// connections on the other threads lose more (the client and the target pay for the extra thread)
    fn bulk(c: &Conn, away: bool, _: u64) -> f64 {
        match (away, c.id) {
            (true, 101) => 1.45,
            (true, 100) => 1.2,
            (true, _) => 0.5,
            _ => 1.0,
        }
    }
    /// the moved one gains, the total does not move (a client-bound total: rr 10x10)
    fn bound_total(c: &Conn, away: bool, _: u64) -> f64 {
        match (away, c.id) {
            (true, 101) => 1.2,
            (true, 100) => 0.8,
            _ => 1.0,
        }
    }
    /// no effect of the move at all; the traffic rises by itself, 0.2% per tick
    fn drift(_: &Conn, _: bool, t: u64) -> f64 {
        1.0 + 0.002 * t as f64
    }

    const SH: [u32; 3] = [990, 20, 600];
    /// two busy connections on worker 0, one on worker 2; worker 1 idle
    fn model(f: fn(&Conn, bool, u64) -> f64) -> (Rule, Model) {
        let io = Model::new(3, &[(0, 1000.0), (0, 1000.0), (2, 1000.0)], f);
        (Rule::new(3, io.now), io)
    }

    #[test]
    fn the_total_rises_the_move_is_kept() {
        let (mut r, mut io) = model(churn);
        run(&mut r, &mut io, &SH, 30);
        assert_eq!((r.kept, r.back, r.dropped, r.last), (1, 0, 0, Some(Why::Keep)));
        assert_eq!(io.on(101), 1, "on the idle worker again");
        // one move, the move back, the move again; every census on every worker
        assert_eq!((io.bits(M_MOVE), io.bits(M_BACK)), (1, 2));
        assert_eq!(io.sent.iter().filter(|x| x.1 & M_CENSUS != 0).count(), 6 * 3);
        assert_eq!(io.sent.last().map(|x| x.1), Some(M_END));
    }

    /// The case 60.64 kept wrongly: the moved connection and the one that stayed both got faster, the total fell.
    #[test]
    fn the_moved_one_gains_while_the_total_falls_it_goes_back() {
        // two more bulk connections on worker 2: in B they run at half their rate
        let mut io = Model::new(3, &[(0, 1000.0), (0, 1000.0), (2, 1000.0), (2, 1000.0)], bulk);
        let mut r = Rule::new(3, io.now);
        run(&mut r, &mut io, &SH, 30);
        assert_eq!((r.kept, r.back, r.last), (0, 1, Some(Why::Fell)));
        assert_eq!(io.on(101), 0, "back where it was");
        assert_eq!((io.bits(M_MOVE), io.bits(M_BACK)), (1, 1), "not moved again");
        // the backoff: the source is not asked for 10 s
        let n = io.sent.len();
        run(&mut r, &mut io, &SH, 85);
        assert_eq!(io.sent.len(), n, "{:?}", &io.sent[n..]);
        run(&mut r, &mut io, &SH, 50);
        assert_eq!(r.back, 2, "a trial after the backoff");
    }

    #[test]
    fn a_flat_total_goes_back() {
        let (mut r, mut io) = model(bound_total);
        run(&mut r, &mut io, &SH, 40);
        assert_eq!((r.kept, r.back, r.last), (0, 1, Some(Why::Flat)));
        assert_eq!(io.on(101), 0);
        // and a total that rises while the moved one does not gain enough
        fn small(c: &Conn, away: bool, _: u64) -> f64 {
            if away && c.id == 101 {
                1.05
            } else {
                1.0
            }
        }
        let (mut r, mut io) = model(small);
        run(&mut r, &mut io, &SH, 40);
        assert_eq!((r.kept, r.last), (0, Some(Why::Moved)));
    }

    /// Traffic that rises by itself during B: B is above A1, but not above A2, and nothing is kept. (An A / B verdict
    /// with the same margin would keep it.)
    #[test]
    fn a_drift_does_not_pass_both_a_windows() {
        fn drift_gain(c: &Conn, away: bool, t: u64) -> f64 {
            drift(c, away, t) * if away && c.id == 101 { 1.2 } else { 1.0 }
        }
        let (mut r, mut io) = model(drift_gain);
        run(&mut r, &mut io, &SH, 40);
        assert_eq!((r.kept, r.back), (0, 1));
        assert!(matches!(r.last, Some(Why::Flat)), "{:?}", r.last);
        // the same windows judged A / B: B is above A1 by more than its margin, so a verdict without A2 would keep it
        let [a1, b, _] = r.windows.map(Option::unwrap);
        assert!(b[0] > a1[0] * (1.0 + M_MIN as f64 / 1000.0) && b[1] > a1[1] * (1.0 + M_MIN as f64 / 1000.0), "{a1:?} {b:?}");
    }

    #[test]
    fn a_census_that_is_not_answered_is_no_measurement() {
        // a worker that stops answering at census n (0: before anything moves; 2: start of B; 3: end of B, with the
        // move back; 4, 5: A2): nothing is kept, and the connection is back on the source at the end
        for (w, n) in [(2usize, 0usize), (1, 0), (2, 2), (1, 2), (2, 3), (2, 4), (1, 5), (2, 5)] {
            let (mut r, mut io) = model(churn);
            io.mute_after = Some((w, n));
            run(&mut r, &mut io, &SH, 80);
            assert_eq!(r.kept, 0, "worker {w} mute after {n}");
            assert_eq!(io.on(101), 0, "worker {w} mute after {n}: nothing stays moved without a measurement");
            assert!(io.bits(M_MOVE) <= 1);
            assert!(r.back + r.dropped >= 1);
        }
    }

    /// The move is not answered in time: taken back before the worker took it (nothing moves), or the worker had taken
    /// it and moves late (the connection goes back, nothing is kept).
    #[test]
    fn a_move_that_is_not_answered_in_time() {
        let (mut r, mut io) = model(churn);
        io.mute = vec![(0, M_MOVE)];
        run(&mut r, &mut io, &SH, 30);
        assert_eq!((r.kept, r.back, r.dropped), (0, 0, 1));
        assert!(io.sent.contains(&(0, 0, 0, 0)), "the request is taken back");
        assert_eq!(io.on(101), 0);
        // taken already: the late answer is waited for, and the move it made goes back
        let (mut r, mut io) = model(churn);
        (io.mute, io.taken) = (vec![(0, M_MOVE)], true);
        run(&mut r, &mut io, &SH, 25);
        let seq = io.sent.iter().rev().find(|x| x.1 & M_MOVE != 0).unwrap().3;
        io.on_move = R_MOVED;
        io.mute.clear();
        io.send(0, M_MOVE, 1, seq); // (the worker acts on the request it had taken)
        assert_eq!(io.on(101), 1);
        run(&mut r, &mut io, &SH, 20);
        assert_eq!(io.on(101), 0, "the late move went back");
        assert_eq!((r.kept, r.back), (0, 1));
        // taken, and no answer for 10 s: given up
        let (mut r, mut io) = model(churn);
        (io.mute, io.taken) = (vec![(0, M_MOVE)], true);
        run(&mut r, &mut io, &SH, 130);
        assert_eq!((r.kept, r.dropped), (0, 1));
    }

    #[test]
    fn a_connection_that_cannot_go_back_is_asked_for_ten_seconds_then_left() {
        let (mut r, mut io) = model(churn);
        io.on_back = R_BUSY;
        run(&mut r, &mut io, &SH, 200);
        assert_eq!((r.kept, r.back, r.dropped), (0, 0, 1));
        assert_eq!(io.on(101), 1, "it stays on the destination: the one unjudged placement");
        let backs = io.bits(M_BACK);
        assert!((LATE as usize..=LATE as usize + 2).contains(&backs), "asked back {backs} times");
        assert!(io.sent.contains(&(1, 0, 0, 0)), "the request is taken back");
    }

    #[test]
    fn nothing_moves_without_an_idle_thread_or_a_second_busy_connection() {
        let (mut r, mut io) = model(churn);
        run(&mut r, &mut io, &[990, 970, 400], 60);
        assert!(io.sent.is_empty(), "every thread in use");
        let (mut r, mut io) = model(churn);
        io.on_move = R_NONE;
        run(&mut r, &mut io, &SH, 60);
        assert_eq!((r.kept, r.back, r.dropped), (0, 0, 1));
        assert_eq!(io.bits(M_MOVE), 1, "and the backoff");
        // the source stops being bound in A1: nothing is tried
        let (mut r, mut io) = model(churn);
        run(&mut r, &mut io, &SH, 5);
        run(&mut r, &mut io, &[300, 20, 600], 10);
        assert_eq!((r.dropped, io.bits(M_MOVE)), (1, 0));
        // with no idle CPU on the host it is tried (60.64's host gate is gone): the total judges
        let (mut r, mut io) = model(churn);
        run(&mut r, &mut io, &SH, 40);
        assert_eq!(r.kept, 1);
    }

    /// 60.74 the nap: nothing to do (every thread busy: no destination) for CALM rounds of LOOK ticks: a nap is due,
    /// twice as long each time, NAP_MAX at most; a judged trial or a rest resets it; the null test never naps.
    #[test]
    fn the_observer_naps_when_no_move_is_possible() {
        let (mut r, mut io) = model(churn);
        let busy = [990, 970, 990];
        let mut naps = Vec::new();
        for _ in 0..9 {
            run(&mut r, &mut io, &busy, (LOOK * CALM - 1) as u64);
            assert_eq!(r.take_nap(), None, "not before CALM rounds");
            run(&mut r, &mut io, &busy, 1);
            naps.push(r.take_nap().expect("a nap after CALM rounds"));
            r.woke();
        }
        let secs: Vec<u64> = naps.iter().map(|n| n.as_secs()).collect();
        assert_eq!(secs, [5, 10, 20, 40, 80, 160, 160, 160, 160]);
        assert!(io.sent.is_empty(), "no request while there is nothing to do");
        // load goes away: a long sleep is a rest, and the next busy period starts with a short nap again
        run(&mut r, &mut io, &[0, 0, 0], REST as u64 + 1);
        r.parked(NAP * 3);
        run(&mut r, &mut io, &busy, (LOOK * CALM) as u64);
        assert_eq!(r.take_nap(), Some(NAP));
        r.woke();
        // one busy round, then quiet ticks: quiet ticks are not rounds (no nap before the load is gone)
        run(&mut r, &mut io, &busy, LOOK as u64);
        run(&mut r, &mut io, &[0, 0, 0], REST as u64 + 1);
        assert_eq!(r.take_nap(), None);
        // light load, new connections wake it at once: short sleeps are rounds too
        let (mut r, io) = model(churn);
        r.parked(Duration::from_millis(300));
        assert_eq!(r.take_nap(), None);
        r.parked(Duration::from_millis(300));
        assert_eq!(r.take_nap(), Some(NAP));
        r.parked(Duration::from_millis(300));
        r.parked(Duration::from_millis(300));
        assert_eq!(r.take_nap(), Some(NAP * 2));
        assert!(io.sent.is_empty());
        // one busy connection on the bound thread (R_NONE: a dropped trial, the source backs off): a nap
        let (mut r, mut io) = model(churn);
        io.on_move = R_NONE;
        let mut got = None;
        for _ in 0..100 {
            run(&mut r, &mut io, &SH, 1);
            if let Some(n) = r.take_nap() {
                got = Some(n);
                break;
            }
        }
        assert_eq!((got, r.dropped, io.bits(M_MOVE)), (Some(NAP), 1, 1));
        // the connection goes back without a verdict (a census not answered after the move): that is a round too,
        // the nap comes one LOOK round after it
        let (mut r, mut io) = model(churn);
        io.mute_after = Some((2, 2));
        let (mut back_at, mut got) = (None, None);
        for t in 0..200 {
            run(&mut r, &mut io, &SH, 1);
            if r.back == 1 && back_at.is_none() {
                back_at = Some(t);
            }
            if r.take_nap().is_some() {
                got = Some(t);
                break;
            }
        }
        assert_eq!((r.kept, r.dropped, io.on(101)), (0, 0, 0));
        assert!(got.unwrap() - back_at.unwrap() <= LOOK as usize + 1, "back at {back_at:?}, nap at {got:?}");
        // a trial too noisy to judge, then nothing to try: a nap; a judged trial: none
        let (mut r, mut io) = model(|_, _, t| if t % 7 < 3 { 1.0 } else { 1.5 });
        let mut got = None;
        for _ in 0..200 {
            run(&mut r, &mut io, &SH, 1);
            if let Some(n) = r.take_nap() {
                got = Some(n);
                break;
            }
        }
        assert_eq!(got, Some(NAP), "verdicts {:?}, dropped {}", r.last, r.dropped);
        // (a trial judged too noisy, then LOOK ticks with its source resting: two rounds)
        assert_eq!((r.last, r.back, r.dropped), (Some(Why::Noisy), 1, 0));
        let (mut r, mut io) = model(churn);
        run(&mut r, &mut io, &SH, 40);
        assert_eq!((r.kept, r.take_nap()), (1, None));
        // the null test never naps
        let (mut r, mut io) = model(flat);
        r.dry = true;
        for _ in 0..300 {
            run(&mut r, &mut io, &busy, 1);
            assert_eq!(r.take_nap(), None);
        }
    }

    /// 60.74 a host with more than NAP_MAX_WORKERS workers never naps, whatever the rounds (no destination, too noisy,
    /// dropped, short sleeps)
    #[test]
    fn many_workers_never_nap() {
        let n = NAP_MAX_WORKERS + 1;
        // (three on the source: a kept move leaves it two, so a later trial finds a second busy connection)
        let conns: Vec<(usize, f64)> = vec![(0, 1000.0), (0, 1000.0), (0, 1000.0), (2, 1000.0)];
        for (f, on_move) in [(churn as fn(&Conn, bool, u64) -> f64, R_MOVED), (churn, R_NONE), (flat, R_MOVED)] {
            let mut io = Model::new(n, &conns, f);
            io.on_move = on_move;
            let mut r = Rule::new(n, io.now);
            let mut sh = vec![600u32; n];
            (sh[0], sh[1]) = (990, 20);
            for t in 0..600u64 {
                let busy = vec![990u32; n];
                run(&mut r, &mut io, if t % 100 < 50 { &busy } else { &sh }, 1);
                if t % 37 == 0 {
                    r.parked(Duration::from_millis(200));
                }
                assert_eq!(r.take_nap(), None, "{n} workers, tick {t}");
            }
        }
        // the noisy case of the nap test, with many workers
        let mut io = Model::new(n, &conns, |_, _, t| if t % 7 < 3 { 1.0 } else { 1.5 });
        let mut r = Rule::new(n, io.now);
        let mut sh = vec![600u32; n];
        (sh[0], sh[1]) = (990, 20);
        for _ in 0..400 {
            run(&mut r, &mut io, &sh, 1);
            assert_eq!(r.take_nap(), None);
        }
        assert!(r.back + r.dropped >= 2, "trials ran: back {} dropped {}", r.back, r.dropped);
    }

    use super::stage2;

    /// A fake of the workers driven by a seeded generator: answers come after a random delay (some never), move
    /// answers are random (moved, none, busy), byte counters grow with noise and jumps. A move takes a connection from
    /// the worker's census to the other worker's (and a move back or a keep takes it on again), so the rule's census
    /// checks find it where it went and trials reach a verdict; with `boost` a connection carries twice as much away
    /// from its first worker (some trials are kept). Two instances with one seed answer alike as long as the rule asks
    /// alike; every call is logged.
    struct Fake {
        rng: u64,
        n: usize,
        boost: bool,
        now: Instant,
        bytes: Vec<u64>,
        /// per worker, the ids of its connections; connection `id` started on worker id / 10
        on: Vec<Vec<u64>>,
        conn_bytes: Vec<u64>,
        /// the connection of the last move (M_MOVE): the one M_BACK moves
        trial: u64,
        moves: Vec<u64>,
        pending: Vec<Option<(u64, usize, u32)>>,
        out: Vec<(u32, u64, u64)>,
        snap: Vec<Option<Census>>,
        moved: Vec<(u64, u32)>,
        log: Vec<String>,
    }

    impl Fake {
        fn new(n: usize, seed: u64) -> Fake {
            Fake {
                rng: seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1,
                n,
                boost: seed.is_multiple_of(2),
                now: Instant::now(),
                bytes: vec![0; n],
                on: (0..n).map(|w| (1..=3).map(|k| (w * 10 + k) as u64).collect()).collect(),
                conn_bytes: vec![0; n * 10 + 4],
                trial: 0,
                moves: vec![0; n],
                pending: vec![None; n],
                out: vec![(0, 0, 0); n],
                snap: vec![None; n],
                moved: vec![(0, 0); n],
                log: Vec::new(),
            }
        }
        fn r(&mut self, m: u64) -> u64 {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            self.rng % m
        }
        /// connection `id` from worker `w` to `to`, if it is on `w`
        fn shift(&mut self, id: u64, w: usize, to: usize) -> bool {
            let Some(i) = self.on[w].iter().position(|&x| x == id) else { return false };
            self.on[w].remove(i);
            self.on[to].push(id);
            true
        }
        /// one tick: traffic, and the answers that come now
        fn advance(&mut self) {
            self.now += TICK;
            for w in 0..self.n {
                for i in 0..self.on[w].len() {
                    let id = self.on[w][i];
                    let mut add = 1000 + self.r(300) + if self.r(50) == 0 { 5000 } else { 0 };
                    if self.boost && id as usize / 10 != w {
                        add *= 2;
                    }
                    self.conn_bytes[id as usize] += add;
                    self.bytes[w] += add;
                }
                let Some((bits, to, seq)) = self.pending[w] else { continue };
                if self.r(10) < 2 {
                    continue; // (later, or never)
                }
                self.pending[w] = None;
                if bits & M_CENSUS != 0 {
                    let conns = self.on[w]
                        .iter()
                        .map(|&id| (id, self.conn_bytes[id as usize], (self.conn_bytes[id as usize] / 100) as u32))
                        .collect();
                    self.snap[w] = Some(Census { seq, at: self.now, bytes: self.bytes[w], conns, many: false, moves: self.moves[w] });
                }
                let mut code = if bits & M_MOVE != 0 {
                    [R_MOVED, R_MOVED, R_MOVED, R_NONE, R_BUSY][self.r(5) as usize]
                } else if bits & M_BACK != 0 {
                    [R_MOVED, R_MOVED, R_MOVED, R_MOVED, R_MOVED, R_GONE][self.r(6) as usize]
                } else {
                    R_NOTED
                };
                if code == R_MOVED {
                    let id = if bits & M_MOVE != 0 { self.on[w].first().copied().unwrap_or(0) } else { self.trial };
                    if id != 0 && self.shift(id, w, to) {
                        if bits & M_MOVE != 0 {
                            self.trial = id;
                        }
                        self.moves[w] += 1;
                        self.moves[to] += 1;
                        self.moved[w] = (id, seq);
                    } else {
                        code = if bits & M_MOVE != 0 { R_NONE } else { R_GONE };
                    }
                }
                self.out[w] = (seq, code, 0);
            }
        }
    }

    macro_rules! fake_io {
        ($t:path) => {
            impl $t for Fake {
                fn send(&mut self, w: usize, bits: u64, to: usize, seq: u32) {
                    self.log.push(format!("send {w} {bits} {to} {seq}"));
                    if bits & !M_END != 0 {
                        self.pending[w] = Some((bits, to, seq));
                    } else if bits == 0 {
                        self.pending[w] = None;
                    }
                }
                fn out(&mut self, w: usize) -> (u32, u64, u64) {
                    self.out[w]
                }
                fn census(&mut self, w: usize, seq: u32) -> Option<Census> {
                    let c = self.snap[w].take_if(|c| c.seq == seq);
                    self.log.push(format!("census {w} {seq} {}", c.is_some()));
                    c
                }
                fn moved(&mut self, w: usize, seq: u32) -> u64 {
                    if self.moved[w].1 == seq {
                        self.moved[w].0
                    } else {
                        0
                    }
                }
                fn cancel(&mut self, w: usize) -> bool {
                    self.log.push(format!("cancel {w}"));
                    let was = self.pending[w].take().is_some();
                    was
                }
                fn note(&mut self, line: std::fmt::Arguments) {
                    self.log.push(format!("note {line}"));
                }
            }
        };
    }
    fake_io!(Io);
    fake_io!(stage2::Io);

    /// The two logs say the same: equal, except that a number in a trial line may differ by one in its last printed
    /// digit (totals sums the cohort over a HashMap, whose order, and so the float sum's last bits, differs per map)
    fn same_log(a: &[String], b: &[String]) -> bool {
        let num = |x: &str| x.parse::<f64>().ok().map(|v| (v, x.split_once('.').map_or(0, |d| d.1.len())));
        a.len() == b.len()
            && a.iter().zip(b).all(|(x, y)| {
                let (xs, ys): (Vec<&str>, Vec<&str>) = (x.split([' ', '=', ',']).collect(), y.split([' ', '=', ',']).collect());
                xs.len() == ys.len()
                    && xs.iter().zip(&ys).all(|(p, q)| {
                        p == q
                            || matches!((num(p), num(q)), (Some((u, d)), Some((v, e))) if d == e && (u - v).abs() <= 1.0001 * 10f64.powi(-(d as i32)))
                    })
            })
    }

    /// 60.74 on a host with more than NAP_MAX_WORKERS workers the rule decides as the stage-2 build did: the same
    /// rounds (CPU shares, sleeps, worker answers) give the same requests, censuses, notes, verdicts and rests, and no
    /// nap. (The observer loop differs only by the nap, which never comes here.)
    #[test]
    fn gt4_path_decides_as_stage_2() {
        let (mut trials, mut kept) = (0, 0);
        let mut seen = std::collections::BTreeMap::new();
        for seed in 1..=300u64 {
            let n = [NAP_MAX_WORKERS + 1, 8, 16][seed as usize % 3];
            let (mut a, mut b) = (Fake::new(n, seed), Fake::new(n, seed));
            let mut new = Rule::new(n, a.now);
            let mut old = stage2::Rule::new(n, b.now);
            let mut pick = Fake::new(n, seed ^ 0x55);
            for t in 0..3000u64 {
                a.advance();
                b.advance();
                // shares: phases of a busy pair, all busy, quiet, random
                let phase = (t / 150 + seed) % 4;
                let sh: Vec<u32> = (0..n)
                    .map(|i| match phase {
                        0 => [990, 20].get(i).copied().unwrap_or(400 + pick.r(200) as u32),
                        1 => 960 + pick.r(40) as u32,
                        2 => pick.r(100) as u32,
                        _ => pick.r(1001) as u32,
                    })
                    .collect();
                let (now_a, now_b) = (a.now, b.now);
                let ra = new.step(&sh, now_a, &mut a);
                let rb = old.step(&sh, now_b, &mut b);
                assert_eq!(ra, rb, "seed {seed} tick {t}: rest");
                assert_eq!(new.take_nap(), None, "seed {seed} tick {t}: a nap with {n} workers");
                if ra {
                    let slept = Duration::from_millis(100 * (1 + pick.r(100)));
                    new.parked(slept);
                    old.woke();
                }
                assert!(same_log(&a.log, &b.log), "seed {seed} tick {t}:\n{:?}\n{:?}", a.log, b.log);
                a.log.clear();
                b.log.clear();
                assert_eq!(
                    format!("{:?}", (new.kept, new.back, new.dropped, new.last)),
                    format!("{:?}", (old.kept, old.back, old.dropped, old.last)),
                    "seed {seed} tick {t}"
                );
                if let Some(why) = new.last {
                    *seen.entry(format!("{why:?}")).or_insert(0) += 1;
                }
                new.last = None;
                old.last = None;
            }
            trials += new.kept + new.back + new.dropped;
            kept += new.kept;
        }
        println!("gt4: {trials} trials, {kept} kept, verdicts {seen:?}");
        assert!(trials > 1000, "{trials} trials: the rounds reached the trial code");
        // the trials reach the verdict: kept ones, and ones that measured nothing
        assert!(kept > 0 && seen.get("Keep").is_some_and(|&n| n > 0), "a keep: {seen:?}");
        assert!(["NoMeasure", "Noisy"].iter().any(|k| seen.get(*k).is_some_and(|&n| n > 0)), "no measurement: {seen:?}");
    }

    #[test]
    fn a_busy_connection_is_asked_again_then_left() {
        let (mut r, mut io) = model(churn);
        io.on_move = R_BUSY;
        run(&mut r, &mut io, &SH, 30);
        assert_eq!(io.bits(M_MOVE), TRIES as usize);
        assert_eq!(r.dropped, 1);
    }

    #[test]
    fn the_null_test_moves_nothing() {
        let (mut r, mut io) = model(flat);
        r.dry = true;
        run(&mut r, &mut io, &[0, 0, 0], 100);
        assert_eq!((io.bits(M_MOVE), io.bits(M_BACK)), (0, 0));
        assert!(r.back >= 3, "{} dry trials", r.back);
        assert_eq!(r.last, Some(Why::Flat), "nothing changed: flat");
    }

    #[test]
    fn judge_by_its_rules() {
        let w = |a1: [f64; 2], b: [f64; 2], a2: [f64; 2]| [Some(a1), Some(b), Some(a2)];
        let up = Some(1.2);
        assert_eq!(judge(w([100.0, 10.0], [110.0, 10.0], [100.0, 10.0]), up).0, Why::Keep, "bytes up, segments flat");
        assert_eq!(judge(w([100.0, 10.0], [100.0, 11.0], [100.0, 10.0]), up).0, Why::Keep, "segments up, bytes flat");
        assert_eq!(judge(w([100.0, 10.0], [110.0, 9.0], [100.0, 10.0]), up).0, Why::Fell, "no keep while one falls");
        assert_eq!(judge(w([100.0, 10.0], [101.0, 10.1], [100.0, 10.0]), up).0, Why::Flat, "inside the margin");
        assert_eq!(judge(w([100.0, 10.0], [110.0, 10.0], [100.0, 10.0]), Some(1.05)).0, Why::Moved);
        assert_eq!(judge(w([100.0, 10.0], [110.0, 10.0], [100.0, 10.0]), None).0, Why::Moved, "its rate not known");
        // the margin follows the trial's noise: A2 4% above A1 makes it 8%
        let (why, m) = judge(w([100.0, 0.0], [110.0, 0.0], [104.0, 0.0]), up);
        assert_eq!(why, Why::Flat);
        assert!((m[0] - 0.08).abs() < 1e-9);
        assert_eq!(judge(w([100.0, 0.0], [130.0, 0.0], [104.0, 0.0]), up).0, Why::Keep);
        assert_eq!(judge(w([100.0, 10.0], [130.0, 10.0], [106.0, 10.0]), up).0, Why::Noisy, "A2 / A1 6%");
        // no traffic of a kind: that total gives no verdict; none at all: no verdict
        assert_eq!(judge(w([100.0, 0.0], [110.0, 0.0], [100.0, 0.0]), up).0, Why::Keep);
        assert_eq!(judge(w([0.0, 0.0], [10.0, 1.0], [0.0, 0.0]), up).0, Why::Empty);
        assert_eq!(judge(w([0.0, 10.0], [10.0, 12.0], [5.0, 10.0]), up).0, Why::Noisy, "traffic in one A window only");
        assert_eq!(judge(w([100.0, 10.0], [0.0, 10.0], [100.0, 10.0]), up).0, Why::Fell, "B fell to nothing");
        assert_eq!(judge([None, Some([1.0, 1.0]), Some([1.0, 1.0])], up).0, Why::NoMeasure);
    }

    #[test]
    fn totals_of_the_windows() {
        let t0 = Instant::now();
        let s = |k: u32, bytes: u64, conns: Vec<(u64, u64, u32)>, moves: u64| Census {
            seq: k,
            at: t0 + TICK * (5 * k),
            bytes,
            conns,
            many: false,
            moves,
        };
        // two workers; connection 7 moves from worker 0 to 1 between census 1 and 2 and back between 3 and 4;
        // connection 8 closes in B (its bytes stay in the worker's total); connection 9 opens in A2
        let snaps = vec![
            vec![s(0, 1000, vec![(7, 0, 0), (8, 0, 0)], 0), s(0, 0, vec![], 0)],
            vec![s(1, 2000, vec![(7, 500, 5), (8, 100, 1)], 0), s(1, 100, vec![], 0)],
            vec![s(2, 2100, vec![(8, 200, 2)], 1), s(2, 200, vec![(7, 600, 6)], 1)],
            vec![s(3, 2300, vec![], 1), s(3, 1300, vec![(7, 1600, 16)], 1)],
            vec![s(4, 3400, vec![(7, 1700, 17)], 2), s(4, 1400, vec![], 2)],
            vec![s(5, 4400, vec![(7, 2200, 22), (9, 50, 1)], 2), s(5, 1400, vec![], 2)],
        ];
        let (w, cohort, moved) = totals(&snaps, 7);
        assert_eq!(cohort, 1, "only connection 7 is in all six");
        let w = w.map(Option::unwrap);
        // per window: (bytes of both workers) / 0.5 s; segments of the cohort / 0.5 s
        assert_eq!(w[0], [2200.0, 10.0]);
        assert_eq!(w[1], [2600.0, 20.0]);
        assert_eq!(w[2], [2000.0, 10.0]);
        assert!((moved.unwrap() - 2.0).abs() < 1e-9, "B 1000 bytes against A1 500");
        // a worker whose move count changed inside a window: that window is no measurement
        let mut bad = snaps.clone();
        bad[3][1].moves = 2;
        assert!(totals(&bad, 7).0[1].is_none());
        // a total that went down: no measurement
        let mut bad = snaps.clone();
        bad[5][1].bytes = 1300;
        assert!(totals(&bad, 7).0[2].is_none());
        assert_eq!(totals(&snaps, 0).2, None, "no cookie: the moved one's rate is not known");
    }
}
