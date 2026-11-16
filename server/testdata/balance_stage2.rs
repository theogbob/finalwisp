//! TEST ONLY: the observer rule of the stage-2 build that gold3 timed (commit 79597662, release aa514831), the
//! non-test part of server/src/balance.rs at that commit, unchanged but for these lines and the doc comments made
//! plain. balance.rs tests::gt4_path_decides_as_stage_2 feeds it and the current rule the same rounds.
#![allow(dead_code)]
// 60.74 --auto-balance (off by default): the observer thread and its rule. Stage 2 of the 60.64 prototype
// (note 60.74; the design is 60.70 section 2.4): a move is judged by the server's TOTAL.
//
// Stage 1 finds a candidate, with no setting per host: a worker thread that used at least SRC of one CPU for RUN
// ticks while another used at most DST. (60.64 also asked for idle CPU on the host; that gate is gone: idle CPU before
// a move says nothing about the total after it, 60.64 section 10.4.)
//
// Stage 2 is a trial A1 / B / A2. Every worker takes a census at the start and the end of three windows of WINDOW
// ticks: A1 (as it is), B (one busy connection moved from the bound worker to the idle one, SETTLE ticks after the
// move), A2 (moved back, SETTLE ticks after that). A census is one worker's byte total (bytes read from clients plus
// bytes sent to them, the closed ones included: no system call) and, per connection, the kernel's counters (one
// getsockopt each). Two totals per window, summed over all workers: bytes per second, and data segments per second of
// one cohort (the connections that are in all six censuses). The move is kept (moved there again) only if
//   - the moved connection's own rate in B is at least GAIN of its rate in A1,
//   - at least one total in B is above BOTH A windows by its margin, and neither total is below either A window by
//     more than its margin. Margin = max(M_MIN, K x |A2 / A1 - 1|): the noise of this trial, measured at the spacing
//     of the comparison. A trial whose A2 / A1 differs by more than NOISY is not judged (too noisy).
//   - every worker answered every census, and no connection moved between workers inside a window (a new
//     connection is not a move: its bytes count from 0, as the work it is).
//
// Else the connection stays where A2 had it (back on the bound worker), and that worker is not a source for a time
// that doubles with every failed trial. Why A / B / A: a false "back" is the safe error (today's placement and a
// backoff); a false "keep" is not, and with an A window on each side of B a drift in one direction cannot pass both.
// One trial at a time in the whole process.
//
// Wake-ups (as 60.64): the thread sleeps (park) until a worker tells it that it used at least HOT of a CPU over its
// sweep period, or until a worker takes a new connection. It then wakes every TICK and reads one CPU clock per
// worker, and goes back to sleep after REST ticks without a worker at HOT and without a trial.

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

static OBSERVER: OnceLock<std::thread::Thread> = OnceLock::new();

/// A worker's sweep period was at or above HOT, or a worker took a new connection (load often starts right after the
/// accept, and the next sweep is up to 2 s away): wake the observer (no system call unless it sleeps).
pub fn hot() {
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

    /// The trial ends without a verdict: one debug line, and the source rests `pause` (None: the backoff of a failed
    /// trial).
    fn drop_trial(&mut self, io: &mut dyn Io, now: Instant, why: &str, pause: Option<Duration>) {
        io.note(format_args!("trial w{} -> w{}: dropped: {why}", self.s, self.d));
        self.dropped += 1;
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

    /// The observer slept and was woken (a sweep report, a new connection): it watches for REST ticks again, and what
    /// it counted before the sleep is old.
    pub fn woke(&mut self) {
        self.cool = 0;
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
                let Some((s, d)) = pick else { return !self.dry && self.cool >= REST };
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
                std::thread::park();
                rule.woke();
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
        }
    });
    match spawned {
        Ok(h) => {
            let _ = OBSERVER.set(h.thread().clone());
        }
        Err(e) => crate::metrics::log_nowait(format!("finalwisp: --auto-balance is off: its thread did not start ({e})")),
    }
}
