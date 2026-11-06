//! 20.30 upload credit v2 (default on since 60.13; `--no-credit-v2` = off). Wisp CONTINUE is absolute: a client sets its credit to
//! the value and drops what was left. Under base-2 the server cannot tell which CONTINUEs a client dropped, so
//! the credit it must treat as legal (`allow`) grows without limit on a long path ("ghost" credit, 20.27).
//! v2 sends a WS ping after each batch of CONTINUEs (one outstanding per connection). A pong proves that the
//! client processed every CONTINUE queued before that ping, so what was left of the older ones is retired:
//! the bound becomes `recv at the pong + the last CONTINUE` plus the CONTINUEs sent since (`Stream::bound`).
//! On that bound, level-0 grants are top-ups against a per-stream window (`Stream::win`). The window is
//! autotuned like TCP's receive buffer (`Stream::on_pong`). Pure state machines here; worker/upload.rs feeds them.
//! Doc: docs/summaries/20.30-upload-credit-v2.md.
use std::time::{Duration, Instant};

/// first window per stream (bytes): 1 MiB. A 2 MiB start (base-2's 128 packets at wbench's 16 KiB) kept 2-4 MiB of pend
/// per echo stream (echo 10x10 loopback VmHWM 313 MB vs 130 MB at 1 MiB, base-2 ~365 MB)
pub const WINIT: u64 = 1 << 20;
/// a new CONTINUE once the client consumed this much since the last one: win/16, at least 1 MiB (base-2: 64
/// packets = 1 MiB at 16 KiB), at most 3/4 of the window. A grant covers one RTT plus this, so the window needs
/// 2 x BDP + it (autotune: 2 x per-RTT; the step is 1/16 once the window is past 16 MiB)
const STEP_MIN: u64 = 1 << 20;
/// largest window per stream (bytes). 20.30 spike: 56 MiB ties base-2 behind a stalling sink at 200 ms
/// (1.08x, n=14); 32 MiB cost 0.94x
pub const WMAX: u64 = 56 << 20;
/// largest window the starvation rule alone reaches (doubling when the client ran dry): enough for a fast client on
/// loopback, where the credit loop's latency is app wakeups, not the path (loopback 1x1: 0.89x of base-2 at 1 MiB)
pub const WSTARVE: u64 = 4 << 20;
/// what the starvation rule may add over all streams of a worker (Worker::starve_pool): per stream, 100 echo
/// streams grew to 630-670 MB (4 MiB each) and 1.1-1.2 GB (no limit), against ~150 MB without the rule
pub const STARVE_POOL: u64 = 8 << 20;
/// smallest packet size a grant is sized with: a client of 64-byte packets would otherwise get 16k
/// packets per MiB of window (the per-stream PEND_HARD hold stays the byte safety net)
const PKT_MIN: u64 = 1024;
/// at most one ping per this interval (a probe excepted): on loopback/LAN the ping round trip (~50 us) made a ping
/// cycle per ~0.85 MiB of upload, +48% syscalls per GiB (a wakeup, a TCP_INFO read and a send per pong). Paths with a
/// longer RTT are not affected (one ping outstanding). A waiting epoch only retires later: the bound stays looser
pub const PING_GAP: Duration = Duration::from_millis(1);
/// a ping unanswered this long: the client is treated as one that does not pong (base rule) until it answers
pub const PONG_LATE: Duration = Duration::from_secs(5);

/// Per connection: the ping that closes the current epoch. Epoch = the seq of the ping that follows
/// the CONTINUEs of that epoch (the ping is queued after them, in the same output buffer).
#[derive(Default)]
pub struct Pinger {
    seq: u64,              // next ping seq (0 = none sent yet; seqs start at 1)
    out: u64,              // outstanding ping (0 = none)
    at: Option<Instant>,   // when `out` was queued
    wait: bool,            // epoch `seq` has CONTINUEs or a probe but no ping yet
    urgent: bool,          // a probe waits for that ping: PING_GAP does not hold it back (review r3)
    last: Option<Instant>, // when the last ping was queued (PING_GAP)
    pub pongs: u64,
    pub min_rtt: Option<(Duration, u32)>, // the kernel's min RTT, cached: (value, pongs until the next read)
}

impl Pinger {
    /// the epoch a CONTINUE queued now belongs to
    pub fn epoch(&self) -> u64 {
        self.seq.max(1)
    }

    fn start(&mut self, now: Instant) -> u64 {
        let s = self.seq.max(1);
        (self.out, self.at, self.seq, self.wait, self.urgent, self.last) = (s, Some(now), s + 1, false, false, Some(now));
        s
    }

    fn gap_ok(&self, now: Instant) -> bool {
        self.last.is_none_or(|l| now.saturating_duration_since(l) >= PING_GAP)
    }

    /// after queueing a CONTINUE: Some(seq) = queue a ping with this payload now
    pub fn after_continue(&mut self, now: Instant) -> Option<u64> {
        if self.out == 0 && self.gap_ok(now) {
            return Some(self.start(now));
        }
        self.wait = true;
        None
    }

    /// a probe needs a pong that leaves after now: (the seq to wait for, Some(seq) = queue that ping now)
    pub fn probe(&mut self, now: Instant) -> (u64, Option<u64>) {
        if self.out == 0 {
            let s = self.start(now);
            return (s, Some(s));
        }
        (self.wait, self.urgent) = (true, true);
        (self.epoch(), None)
    }

    /// a pong: Some((seq, rtt)) when it answers the outstanding ping (other payloads are ignored: RFC 6455
    /// allows unsolicited pongs, and a forged early pong only tightens the bound)
    pub fn on_pong(&mut self, payload: &[u8], now: Instant) -> Option<(u64, Duration)> {
        let s = u64::from_le_bytes(payload.try_into().ok()?);
        if s == 0 || s != self.out {
            return None;
        }
        self.out = 0;
        self.pongs += 1;
        Some((s, now.saturating_duration_since(self.at.take()?)))
    }

    /// after a pong was handled (and its grants queued), and at the sweep: Some(seq) = queue the ping of a waiting
    /// epoch now
    pub fn next(&mut self, now: Instant) -> Option<u64> {
        (self.wait && self.out == 0 && (self.urgent || self.gap_ok(now))).then(|| self.start(now))
    }

    /// test hook: the outstanding ping was queued `d` earlier
    #[cfg(test)]
    pub fn age(&mut self, d: Duration) {
        self.at = self.at.map(|a| a - d);
    }

    /// v2 grants apply: the client answered a ping, and none is outstanding for PONG_LATE
    pub fn active(&self, now: Instant) -> bool {
        self.pongs > 0 && self.at.is_none_or(|a| now.saturating_duration_since(a) < PONG_LATE)
    }
}

#[derive(Clone, Copy, Default)]
struct Epoch {
    ep: u64,   // ping seq that closes it
    sum: u64,  // packets granted in it
    last: u32, // its last CONTINUE value
}

/// what `Stream::grant` decided
#[derive(Debug, PartialEq)]
pub enum Grant {
    No,
    Continue(u32),
    /// no grant is due, but the client may be blocked on credit the bound only thinks it has
    Probe,
}

/// Per stream (TCP, credit-controlled).
pub struct Stream {
    recv: u64,  // DATA packets received
    bytes: u64, // their payload bytes
    pmax: u64,  // the largest of them (the strict cap counts the bound's rest at this size)
    lim: u64,   // packets legal in total by the CONTINUEs up to the last retired epoch
    ue: [Epoch; 2],
    nue: usize, // unretired epochs in ue[..nue] (at most 2: the outstanding ping's and the next one)
    pub win: u64,
    // bytes the client may still have in flight when a CONTINUE queued now arrives: bytes that arrived per ping
    // RTT between the last two pongs. u64::MAX until the first measurement: then the retired bound alone counts
    // (20.30 #2: the bound counts credit an overwriting client dropped, so alone it cut a fast single stream to
    // 0.67-0.90x). Too low only if the client speeds up within an RTT: then pend <= win + the bound's rest
    est: u64,
    probe: u64, // seq whose pong decides the probe (0 = none)
    probe_recv: u64,
    blocked: bool,                     // the probe saw no DATA for a whole ping RTT: grant as if no credit were left
    mark: Option<(Instant, u64, u64)>, // (when, consumed bytes, received bytes) at the last pong
    rate: u64,                         // bytes consumed per path RTT at the last pong (window growth term)
    starved: bool,                     // a grant since the last pong went out only after the client spent all of the last
    busy: bool,                        // the target's backlog reached the refill threshold since the last pong
    eased: bool,                       // ... and was below it at some write since the last pong (not a whole-interval stall)
    grow: bool,                        // starved in a calm interval: starve_grow may double the window
    pub extra: u64,                    // window bytes taken from the worker's STARVE_POOL (returned at close)
    pub viol: u64,                     // packets past the bound (the client overran even the retired bound)
}

impl Stream {
    /// a new stream starts with the handshake's credit (`hs`, Wisp v1/v2 stream-0 CONTINUE)
    pub fn new(hs: u32) -> Stream {
        Stream {
            recv: 0,
            bytes: 0,
            pmax: 0,
            lim: hs as u64,
            ue: [Epoch::default(); 2],
            nue: 0,
            win: WINIT,
            est: u64::MAX,
            probe: 0,
            probe_recv: 0,
            blocked: false,
            mark: None,
            rate: 0,
            starved: false,
            busy: false,
            eased: false,
            grow: false,
            extra: 0,
            viol: 0,
        }
    }

    /// 60.13: the state of a stream that received `recv` DATA packets (the true count: Target::since, not the halved upkts) (`bytes` in total, the largest `pmax`) and no
    /// CONTINUE yet, created on first use: until its first CONTINUE the bound is the handshake's credit `hs`, so this
    /// equals new(hs) followed by those on_data calls (the pong-interval flags start empty: they only matter once the
    /// stream has a window above WINIT or a v2 grant, which needs this state)
    pub fn resume(hs: u32, recv: u32, bytes: u64, pmax: u32) -> Stream {
        let recv = recv as u64;
        Stream { recv, bytes, pmax: pmax as u64, viol: recv.saturating_sub(hs as u64), ..Stream::new(hs) }
    }

    /// packets the client may legally have sent in total (an upper bound for overwriting and adding clients)
    pub fn bound(&self) -> u64 {
        self.lim + self.ue[..self.nue].iter().map(|e| e.sum).sum::<u64>()
    }

    pub fn on_data(&mut self, len: usize) {
        self.recv += 1;
        self.bytes += len as u64;
        self.pmax = self.pmax.max(len as u64);
        if self.recv > self.bound() {
            self.viol += 1;
        }
    }

    /// the target's backlog at a write (after_write): at or above `plow` the window does not grow until the next pong
    /// interval that stays below (echo 10x10: windows doubled while the downstream held the target back between pongs,
    /// 1.1-1.2 GB)
    pub fn backlog(&mut self, backlog: u64, plow: u64) {
        self.busy |= backlog >= plow;
        self.eased |= backlog < plow;
    }

    /// a v2 grant is going out after the client spent all of its last one (it may have run dry: the window is too
    /// small for the credit loop, whose latency the kernel's min RTT does not see on loopback/LAN: app wakeups)
    pub fn starved(&mut self) {
        self.starved = true;
    }

    /// a CONTINUE(n) was queued in epoch `ep` (every CONTINUE of the stream, base rule or v2)
    pub fn pushed(&mut self, ep: u64, n: u32) {
        (self.blocked, self.probe) = (false, 0);
        if self.nue > 0 && self.ue[self.nue - 1].ep == ep {
            let e = &mut self.ue[self.nue - 1];
            (e.sum, e.last) = (e.sum + n as u64, n);
        } else if self.nue < 2 {
            self.ue[self.nue] = Epoch { ep, sum: n as u64, last: n };
            self.nue += 1;
        } else {
            // not reachable (one ping outstanding: epochs out and out+1). Safe anyway: fold the older open
            // epoch into this one, which only retires later (a looser bound, never a tighter one)
            let e = &mut self.ue[1];
            (e.ep, e.sum, e.last) = (ep, e.sum + n as u64, n);
        }
    }

    /// the client processed every CONTINUE of epochs <= `seq`. `rtt` = this ping's RTT, `min_rtt` = the path's
    /// (kernel tcpi_min_rtt), `backlog` = the target's unwritten bytes, `plow` = the refill threshold
    #[allow(clippy::too_many_arguments)] // deliberate: plain per-pong inputs, one caller
    pub fn on_pong(&mut self, seq: u64, rtt: Duration, min_rtt: Duration, backlog: u64, plow: u64, siblings: bool, now: Instant) {
        let k = self.ue[..self.nue].iter().take_while(|e| e.ep <= seq).count();
        if k > 0 {
            self.lim = self.recv + self.ue[k - 1].last as u64; // what was left of older CONTINUEs is gone (overwritten)
            self.ue.copy_within(k..self.nue, 0);
            self.nue -= k;
        }
        if self.probe != 0 && seq >= self.probe {
            self.blocked = self.recv == self.probe_recv;
            self.probe = 0;
        }
        // starved and the target keeps up: double (once per pong; the client ran dry, so its rate says nothing)
        let calm = !std::mem::take(&mut self.busy) && backlog < plow;
        let starved = std::mem::take(&mut self.starved);
        // 20.30 A5/A3 (option 2): a target that held at least `plow` of backlog for the whole interval (every write
        // seen and the pong itself) is target-bound (stalled, or draining slower than the client sends): halve the window, floor WINIT.
        // Credit already out is not recalled,
        // but the next read phase starts small, so the next stall has less of this stream's data crossing the shared
        // connection ahead of its siblings (A5: S2 kept 0.67 of its solo rate) and an echo stream whose downstream
        // backs up keeps less in pend (A3). It regrows by the rate rule once the target reads again.
        let eased = std::mem::take(&mut self.eased);
        // Only with siblings on the connection: for a lone stream the backlog built in a stall is what the next read
        // phase drains at link speed (delay-line sim, stalling sink: 13x fewer packets delivered with the shrink;
        // rig A1: v2 1.45x base-2 without it); its memory is bounded by the cap.
        if siblings && backlog >= plow && !eased && self.win > WINIT {
            let w = (self.win / 2).max(WINIT);
            self.win = w; // (pool bytes stay claimed in `extra`: handing them on cost ~60 MB echo 10x10 VmHWM)
        }
        let cons = self.bytes - backlog.min(self.bytes);
        let (rtt, min) = (rtt.as_micros() as u64, (min_rtt.as_micros() as u64).max(1));
        if rtt < min / 2 {
            // review P3: a pong faster than the path can carry it was sent before our ping arrived (seqs are
            // predictable): retirement above is still right (it only tightens), but its timing says nothing
            return;
        }
        self.grow = starved && calm; // (review r3: not on an impossibly early pong)
        let mark = self.mark.replace((now, cons, self.bytes));
        if let Some((at, c0, b0)) = mark {
            let ival = (now.saturating_duration_since(at).as_micros() as u64).max(rtt).max(1);
            let scale = |b: u64, us: u64| (b as u128 * us as u128 / ival as u128) as u64;
            self.est = scale(self.bytes - b0, rtt);
            // window autotune, as tcp_rcv_space_adjust: 2 x bytes consumed per path RTT, plus twice that times the
            // growth since the last sample (6x while the rate doubles per RTT: in slow start the data in flight and
            // the next RTT's both need room; 2x alone kept the window at TCP's cwnd, so TCP turned app-limited and
            // slow start stalled: 0.94x at 200 ms). Only while the client moved at least half the window in one RTT
            // and the target kept up. (The rate rule never shrinks; option 2 above does.)
            let per_rtt = scale(cons.saturating_sub(c0), min);
            let prev = std::mem::replace(&mut self.rate, per_rtt);
            // (no "uninflated ping RTT" gate: the pong comes back behind the client's own queued upload, so the ping
            // RTT grows with our window; such a gate held the window near 1.25 BDP: 0.88x at 20 ms. Per-RTT
            // consumption is scaled by the kernel's min RTT, which kept echo memory down without it.)
            if 2 * per_rtt >= self.win && calm {
                let mut w = 2 * per_rtt;
                if prev > 0 && per_rtt > prev {
                    w += (w as u128 * 2 * (per_rtt - prev).min(prev) as u128 / prev as u128) as u64;
                }
                self.win = w.min(WMAX).max(self.win); // (not clamp: panics if win > WMAX)
            }
        }
    }

    /// level-0 grant decision. `since` = packets since the last CONTINUE, `last` = its value, `cap` = the most
    /// upload backlog an honest stream may ever build (the worker's PEND_HARD minus a margin)
    pub fn grant(&self, backlog: u64, since: u32, last: u32, cap: u64) -> Grant {
        let pkt = (self.bytes / self.recv.max(1)).max(PKT_MIN);
        let big = self.pmax.max(pkt);
        let rest = if self.blocked { 0 } else { self.bound().saturating_sub(self.recv) };
        let rem = rest.saturating_mul(pkt).min(self.est);
        // at least 2 of the client's largest packets (review: a client of packets above the window got n = 0 and,
        // with nothing outstanding, no probe either: a stall)
        let win = self.win.max(2 * big);
        // review P1 (review): the window uses the in-flight estimate, which can be low by up to one grant, so pend
        // could reach ~2 x win (112 MiB) > PEND_HARD and hold the whole connection. The strict bound (an upper bound
        // of what the client may still send, at its largest packet so far) keeps backlog + all of it + the new grant
        // <= cap: an honest stream with steady packet sizes never reaches the hold. (A probe-blocked stream counts 0:
        // its credit is gone, or it would have sent.) Not a guarantee: a client may legally switch to bigger packets
        // (frames up to 16 MiB), and a browser answers pings before its JS handled the CONTINUEs (WHATWG), so the
        // bound can be low by one earlier grant. Nothing enforces the bound; the hold stays the safety net.
        let by_win = win.saturating_sub(backlog.saturating_add(rem)) / pkt;
        let by_cap = cap.saturating_sub(backlog.saturating_add(rest.saturating_mul(big))) / big;
        let n = by_win.min(by_cap).min(u32::MAX as u64) as u32;
        let room = n as u64 * pkt;
        // absolute CONTINUE: a new one replaces what is left, and `rem` already counts what is in flight, so a grant
        // is due once enough was consumed since the last (20.30 #2: base's refill at half of the last grant
        // starved a fast stream: it waited for half of a grant that already left one RTT of data out)
        let spent = since >= last;
        let step = (win / 16).max(STEP_MIN).min(win / 4 * 3);
        // at least win/8 per CONTINUE: with a tiny room the escape below sent CONTINUE(1) per packet (worker test);
        // a client that may be blocked meanwhile gets the probe instead
        if n >= 1 && room >= win / 8 && (since as u64 * pkt >= step || spent) {
            return Grant::Continue(n);
        }
        if spent && rest > 0 && self.probe == 0 && !self.blocked {
            return Grant::Probe;
        }
        Grant::No
    }

    /// after on_pong: a stream that ran dry in a calm interval doubles its window up to WSTARVE, from the worker's
    /// pool (`pool`: bytes left)
    pub fn starve_grow(&mut self, pool: &mut u64) {
        if std::mem::take(&mut self.grow) && self.win < WSTARVE {
            // after a shrink the stream still holds its pool bytes (`extra` above win - WINIT): regrow from those first
            let want = (self.win * 2).min(WSTARVE) - self.win;
            let own = self.extra.saturating_sub(self.win - WINIT).min(want);
            let g = (want - own).min(*pool);
            (self.win, self.extra, *pool) = (self.win + own + g, self.extra + g, *pool - g);
        }
    }

    /// test helper: on_pong on a connection with several streams
    #[cfg(test)]
    pub fn on_pong_sib(&mut self, seq: u64, rtt: Duration, min_rtt: Duration, backlog: u64, plow: u64, now: Instant) {
        self.on_pong(seq, rtt, min_rtt, backlog, plow, true, now)
    }

    /// a probe was armed: decided by the pong of ping `seq`
    pub fn probing(&mut self, seq: u64) {
        (self.probe, self.probe_recv) = (seq, self.recv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const MS: Duration = Duration::from_millis(1);
    const CAP: u64 = 60 << 20;

    #[test]
    fn pinger_one_outstanding_and_waiting_epochs() {
        let t = Instant::now();
        let mut p = Pinger::default();
        assert_eq!(p.epoch(), 1);
        assert_eq!(p.after_continue(t), Some(1)); // first CONTINUE: ping 1 closes epoch 1
        assert_eq!(p.epoch(), 2);
        assert_eq!(p.after_continue(t), None); // ping outstanding: epoch 2 waits
        assert!(!p.active(t), "no pong yet");
        assert_eq!(p.on_pong(&7u64.to_le_bytes(), t + MS), None, "not the outstanding seq");
        assert_eq!(p.on_pong(b"wbench", t + MS), None, "foreign payload");
        assert_eq!(p.on_pong(&1u64.to_le_bytes(), t + 3 * MS), Some((1, 3 * MS)));
        assert_eq!(p.on_pong(&1u64.to_le_bytes(), t + 4 * MS), None, "duplicate");
        assert!(p.active(t + 4 * MS));
        assert_eq!(p.next(t + 4 * MS), Some(2), "the waiting epoch gets its ping");
        assert_eq!(p.next(t + 4 * MS), None);
        // PING_GAP: a pong 0.2 ms after the ping, a CONTINUE right after: its epoch waits for the gap (or the sweep)
        let mut q = Pinger::default();
        assert_eq!(q.after_continue(t), Some(1));
        q.on_pong(&1u64.to_le_bytes(), t + MS / 5);
        assert_eq!(q.after_continue(t + MS / 4), None);
        assert_eq!(q.next(t + MS / 2), None);
        assert_eq!(q.next(t + MS), Some(2));
        // review r3: a probe deferred behind an outstanding ping is not held back by PING_GAP at the pong
        let mut u = Pinger::default();
        assert_eq!(u.after_continue(t), Some(1));
        assert_eq!(u.probe(t), (2, None));
        u.on_pong(&1u64.to_le_bytes(), t + MS / 5);
        assert_eq!(u.next(t + MS / 5), Some(2));
        assert!(!p.active(t + 4 * MS + PONG_LATE), "an unanswered ping past PONG_LATE: base rule");
        // a CONTINUE queued after the pong but before next(): its ping covers the waiting epoch too
        let mut p = Pinger::default();
        p.after_continue(t);
        p.after_continue(t);
        p.on_pong(&1u64.to_le_bytes(), t + MS);
        assert_eq!(p.after_continue(t + MS), Some(2));
        assert_eq!(p.next(t + MS), None);
        // probe: outstanding ping -> wait for the next one, which next() sends
        let (s, ping) = p.probe(t + MS);
        assert_eq!((s, ping), (3, None));
        p.on_pong(&2u64.to_le_bytes(), t + 2 * MS);
        assert_eq!(p.next(t + 2 * MS), Some(3));
    }

    #[test]
    fn pong_retires_overwritten_credit() {
        let t = Instant::now();
        let mut s = Stream::new(128);
        for _ in 0..64 {
            s.on_data(16384);
        }
        s.pushed(1, 128); // ping 1
        s.pushed(2, 128); // ping 2 (outstanding 1)
        s.pushed(2, 128);
        assert_eq!(s.bound(), 128 + 3 * 128, "before any pong: additive (base-2's allow)");
        for _ in 0..10 {
            s.on_data(16384);
        }
        s.on_pong_sib(1, MS, MS, 0, 1 << 18, t);
        assert_eq!(s.bound(), 74 + 128 + 2 * 128, "epoch 1 retired: recv + its last CONTINUE + epoch 2");
        s.on_pong_sib(2, MS, MS, 0, 1 << 18, t);
        assert_eq!(s.bound(), 74 + 128, "the left-over of the overwritten CONTINUEs is gone");
        assert_eq!(s.viol, 0);
        // a pong of a later seq retires every older epoch (a stream with no CONTINUE in that epoch)
        s.pushed(5, 10);
        s.on_pong_sib(9, MS, MS, 0, 1 << 18, t);
        assert_eq!((s.bound(), s.nue), (74 + 10, 0));
    }

    #[test]
    fn grant_tops_up_to_the_window_and_probes_a_blocked_client() {
        let t = Instant::now();
        let mut s = Stream::new(64);
        for _ in 0..64 {
            s.on_data(16384);
        }
        // spent its 64: due; room = 1 MiB window - backlog
        assert_eq!(s.grant(0, 64, 64, CAP), Grant::Continue(64));
        assert_eq!(s.grant(512 << 10, 64, 64, CAP), Grant::Continue(32));
        assert_eq!(s.grant(0, 10, 64, CAP), Grant::No, "less than a step consumed, credit left");
        s.pushed(1, 64);
        // an eager client: sends its 64 before it answers the ping, so the pong's bound still counts 64 more
        for _ in 0..64 {
            s.on_data(16384);
        }
        s.on_pong_sib(1, MS, MS, 0, 1 << 18, t);
        assert_eq!(s.bound() - s.recv, 64);
        // no in-flight measurement yet: the bound's 1 MiB fills the window, the client waits -> probe
        assert_eq!(s.grant(0, 64, 64, CAP), Grant::Probe);
        s.probing(2);
        assert_eq!(s.grant(0, 64, 64, CAP), Grant::No, "one probe at a time");
        s.on_pong_sib(2, MS, MS, 0, 1 << 18, t + MS); // no DATA meanwhile: blocked
        assert_eq!(s.grant(0, 64, 64, CAP), Grant::Continue(64), "granted as if no credit were left");
        s.pushed(3, 64);
        assert!(!s.blocked);
        // a measured in-flight estimate replaces the bound's dropped credit: 48 packets per RTT in flight
        for _ in 0..48 {
            s.on_data(16384);
        }
        s.on_pong_sib(3, MS, MS, 1 << 18, 1 << 18, t + 2 * MS); // (target behind: no window growth here)
        assert_eq!(s.est, 48 * 16384);
        assert_eq!(s.grant(0, 48, 64, CAP), Grant::Continue(16), "window - est, not window - the bound's rest");
        // the cap: backlog + everything the strict bound still allows + the grant stays <= cap (review P1)
        let rest = (s.bound() - s.recv) * 16384; // 64 packets
        assert_eq!(s.grant(0, 48, 64, rest + (4 << 14)), Grant::No, "4 packets of room < win/8");
        assert_eq!(s.grant(0, 48, 64, rest + (12 << 14)), Grant::Continue(12));
        // an impossibly early pong (before the ping could arrive) retires but does not touch est or the window
        let (est, win) = (s.est, s.win);
        for _ in 0..640 {
            s.on_data(16384);
        }
        s.starved();
        s.on_pong_sib(4, Duration::from_micros(10), 20 * MS, 0, 1 << 18, t + 3 * MS);
        let mut pool = STARVE_POOL;
        s.starve_grow(&mut pool);
        assert_eq!((s.est, s.win, pool), (est, win, STARVE_POOL), "no est, rate or starvation growth");
    }

    #[test]
    fn starvation_grows_from_the_worker_pool_only_in_calm_intervals() {
        let t = Instant::now();
        let mut pool = STARVE_POOL;
        let (mut a, mut b) = (Stream::new(64), Stream::new(64));
        for s in [&mut a, &mut b] {
            s.starved();
            s.on_pong_sib(1, MS, MS, 0, 1 << 18, t);
            s.starve_grow(&mut pool);
        }
        assert_eq!((a.win, b.win, pool), (2 << 20, 2 << 20, STARVE_POOL - (2 << 20)));
        a.starved();
        a.backlog(1 << 18, 1 << 18); // the target fell behind in this interval: no growth
        a.on_pong_sib(2, MS, MS, 0, 1 << 18, t);
        a.starve_grow(&mut pool);
        assert_eq!(a.win, 2 << 20);
        for k in 3..6 {
            a.starved();
            a.on_pong_sib(k, MS, MS, 0, 1 << 18, t);
            a.starve_grow(&mut pool);
        }
        assert_eq!((a.win, a.extra), (WSTARVE, 3 << 20), "up to WSTARVE");
        assert_eq!(pool, STARVE_POOL - (4 << 20));
        let mut c = Stream::new(64);
        pool = 512 << 10;
        c.starved();
        c.on_pong_sib(1, MS, MS, 0, 1 << 18, t);
        c.starve_grow(&mut pool);
        assert_eq!((c.win, pool), ((1 << 20) + (512 << 10), 0), "limited by what the pool has left");
    }

    #[test]
    fn a_target_stalled_for_a_whole_interval_halves_the_window_keeping_its_pool_claim() {
        let t = Instant::now();
        let plow = 1 << 18;
        let mut pool = STARVE_POOL;
        let mut s = Stream::new(64);
        for k in 1..4 {
            s.starved();
            s.on_pong_sib(k, MS, MS, 0, plow, t);
            s.starve_grow(&mut pool);
        }
        assert_eq!((s.win, s.extra), (WSTARVE, 3 << 20));
        // backlog dipped below plow at a write: not a whole-interval stall
        s.backlog(1 << 20, plow);
        s.backlog(0, plow);
        s.on_pong_sib(4, MS, MS, 1 << 20, plow, t);
        s.starve_grow(&mut pool);
        assert_eq!(s.win, WSTARVE);
        // stalled all interval, but alone on its connection: no shrink
        s.on_pong(45, MS, MS, 1 << 20, plow, false, t);
        s.starve_grow(&mut pool);
        assert_eq!(s.win, WSTARVE);
        // stalled all interval (no write at all, backlog at the pong), with siblings: halve; the pool bytes stay claimed
        s.on_pong_sib(5, MS, MS, 1 << 20, plow, t);
        s.starve_grow(&mut pool);
        assert_eq!((s.win, s.extra, pool), (2 << 20, 3 << 20, STARVE_POOL - (3 << 20)));
        s.backlog(1 << 20, plow);
        s.on_pong_sib(6, MS, MS, 1 << 20, plow, t);
        s.on_pong_sib(7, MS, MS, 1 << 20, plow, t);
        s.starve_grow(&mut pool);
        assert_eq!(s.win, WINIT, "floor");
        s.on_pong_sib(8, MS, MS, 1 << 20, plow, t);
        s.starve_grow(&mut pool);
        assert_eq!((s.win, s.extra, pool), (WINIT, 3 << 20, STARVE_POOL - (3 << 20)));
        // starved again once the target drains: regrows from its own claim, the pool is untouched
        for k in 9..11 {
            s.starved();
            s.on_pong_sib(k, MS, MS, 0, plow, t);
            s.starve_grow(&mut pool);
        }
        assert_eq!((s.win, s.extra, pool), (WSTARVE, 3 << 20, STARVE_POOL - (3 << 20)));
    }

    #[test]
    fn resume_equals_new_plus_on_data() {
        // 60.13 lazy state: resume() must match a stream that had its state from the start
        let key = |s: &Stream| (s.recv, s.bytes, s.pmax, s.lim, s.nue, s.win, s.est, s.viol, s.bound(), s.extra);
        for hs in [1u32, 4, 128] {
            for n in [0u32, 1, 3, 4, 5, 200] {
                let mut a = Stream::new(hs);
                let (mut bytes, mut pmax) = (0u64, 0u32);
                for k in 0..n {
                    let len = 1000 + (k as usize * 7919) % 15000;
                    a.on_data(len);
                    (bytes, pmax) = (bytes + len as u64, pmax.max(len as u32));
                }
                let b = Stream::resume(hs, n, bytes, pmax);
                assert_eq!(key(&a), key(&b), "hs {hs} n {n}");
                for (backlog, since, last) in [(0, n, hs), (1 << 20, n, hs), (0, 0, hs)] {
                    assert_eq!(a.grant(backlog, since, last, 60 << 20), b.grant(backlog, since, last, 60 << 20));
                }
            }
        }
    }

    #[test]
    fn packets_larger_than_the_window_still_get_credit() {
        // review: 4 MiB DATA frames (legal up to 16 MiB) and a 1 MiB window: n was 0 and no probe
        let mut s = Stream::new(4);
        for _ in 0..4 {
            s.on_data(4 << 20);
        }
        assert_eq!(s.grant(0, 4, 4, CAP), Grant::Continue(2), "2 of the largest packets");
        // a client that switches from 16 KiB to 1 MiB packets: the cap counts the bound's rest at 1 MiB
        let mut s = Stream::new(128);
        for _ in 0..127 {
            s.on_data(16384);
        }
        s.on_data(1 << 20);
        s.pushed(1, 40);
        s.on_pong_sib(1, MS, MS, 0, 1 << 18, Instant::now()); // retired: rest = 40
                                                              // a step consumed, credit left: cap 44 MiB - 40 x 1 MiB = 4 packets < win/8; cap 60 MiB: 20 x 1 MiB fit
        assert_eq!(s.grant(0, 50, 64, 44 << 20), Grant::No);
        assert_eq!(s.grant(0, 50, 64, CAP), Grant::Continue(20));
    }

    #[test]
    fn window_grows_with_consumption_only_while_draining() {
        let t = Instant::now();
        let mut s = Stream::new(64);
        let rtt = 20 * MS;
        let plow = 1 << 18;
        s.on_pong_sib(1, rtt, rtt, 0, plow, t); // marks only
        let feed = |s: &mut Stream, b: u64| (0..b / 16384).for_each(|_| s.on_data(16384));
        feed(&mut s, 1 << 20); // 1 MiB in one RTT: >= half the 1 MiB window
        s.on_pong_sib(2, rtt, rtt, 0, plow, t + rtt);
        assert_eq!(s.win, 2 << 20);
        feed(&mut s, 2 << 20);
        s.on_pong_sib(3, 3 * rtt, rtt, 0, plow, t + 2 * rtt); // 2 MiB over 3 RTTs: < half the window per RTT: no growth
        assert_eq!(s.win, 2 << 20);
        feed(&mut s, 512 << 10);
        s.on_pong_sib(4, rtt, rtt, 0, plow, t + 3 * rtt); // less than half the window: no growth, no shrink
        assert_eq!(s.win, 2 << 20);
        feed(&mut s, 2 << 20);
        s.backlog(0, plow); // (it was below plow at a write: behind at the pong, not stalled all interval)
        s.on_pong_sib(5, rtt, rtt, 1 << 20, plow, t + 4 * rtt); // the target is behind: no growth
        assert_eq!(s.win, 2 << 20);
        for k in 6..40 {
            let w = s.win;
            feed(&mut s, w);
            s.on_pong_sib(k, rtt, rtt, 0, plow, t + k as u32 * rtt);
        }
        assert_eq!(s.win, WMAX);
    }

    /// Delay-line model: one stream, link `d` ticks each way, `cap` packets per tick upstream, an overwriting
    /// client that sends whenever it has credit (`eager`: before it answers a ping read in the same tick).
    /// The sink drains `drain(tick)` packets per tick. Returns (packets delivered after warm-up, max backlog,
    /// violations, final window).
    fn sim(d: usize, cap: u64, ticks: usize, eager: bool, drain: impl Fn(usize) -> u64) -> (u64, u64, u64, u64) {
        const PKT: u64 = 16384;
        let t0 = Instant::now();
        let tick = Duration::from_millis(1);
        let mut s = Stream::new(128);
        let mut p = Pinger::default();
        let (mut since, mut last) = (0u32, 128u32);
        let mut down: VecDeque<(usize, u8, u64)> = VecDeque::new(); // (arrival, 0 = CONTINUE / 1 = ping, value)
        let mut up: VecDeque<(usize, u8, u64)> = VecDeque::new(); // (arrival, 0 = DATA / 1 = pong, value)
        let (mut credit, mut backlog, mut maxb, mut delivered) = (128u64, 0u64, 0u64, 0u64);
        let mut queued_pkts = 0u64; // client-side: sent into the link, rate-limited by `cap`
        let mut link_free = 0usize;
        for now in 0..ticks {
            let at = t0 + tick * now as u32;
            // client: read what arrived; overwrite credit; answer pings (eager: after sending)
            let mut pongs = Vec::new();
            while down.front().is_some_and(|f| f.0 <= now) {
                let (_, k, v) = down.pop_front().unwrap();
                if k == 0 {
                    credit = v;
                } else if eager {
                    pongs.push(v);
                } else {
                    up.push_back((now.max(link_free) + d, 1, v));
                }
            }
            // client sends what credit allows, the link takes `cap` per tick (FIFO with the pongs)
            let k = credit.min(cap);
            credit -= k;
            for _ in 0..k {
                up.push_back((now.max(link_free) + d, 0, 0));
                queued_pkts += 1;
            }
            link_free = now.max(link_free) + (queued_pkts / cap) as usize;
            queued_pkts %= cap;
            for v in pongs {
                up.push_back((now.max(link_free) + d, 1, v));
            }
            // server
            while up.front().is_some_and(|f| f.0 <= now) {
                let (_, k, v) = up.pop_front().unwrap();
                if k == 0 {
                    s.on_data(PKT as usize);
                    since += 1;
                    backlog += PKT;
                } else if let Some((seq, rtt)) = p.on_pong(&v.to_le_bytes(), at) {
                    s.on_pong(seq, rtt, Duration::from_millis(2 * d as u64), backlog, 256 << 10, false, at);
                    // one stream
                }
            }
            let dr = (drain(now) * PKT).min(backlog);
            backlog -= dr;
            if dr > 0 || since > 0 {
                s.backlog(backlog, 256 << 10); // (the worker samples at target writes)
            }
            if now >= ticks / 2 {
                delivered += dr / PKT;
            }
            maxb = maxb.max(backlog);
            let g = s.grant(backlog, since, last, CAP);
            match g {
                Grant::Continue(n) => {
                    let ep = p.epoch();
                    s.pushed(ep, n);
                    (since, last) = (0, n);
                    down.push_back((now + d, 0, n as u64));
                    if let Some(q) = p.after_continue(at) {
                        down.push_back((now + d, 1, q));
                    }
                }
                Grant::Probe => {
                    let (q, ping) = p.probe(at);
                    s.probing(q);
                    if let Some(q) = ping {
                        down.push_back((now + d, 1, q));
                    }
                }
                Grant::No => {}
            }
            if let Some(q) = p.next(at) {
                down.push_back((now + d, 1, q));
            }
        }
        (delivered, maxb, s.viol, s.win)
    }

    #[test]
    fn sim_fast_sink_fills_the_link() {
        // 20.30 #2: 200 ms and 20 ms RTT, 1 Gbit-ish (8 packets of 16 KiB per ms), sink faster than the link
        for (d, eager) in [(100, false), (100, true), (10, false), (10, true)] {
            let ticks = 8000;
            let (got, _, viol, win) = sim(d, 8, ticks, eager, |_| 1 << 20);
            let rate = got as f64 / (ticks / 2) as f64;
            assert!(rate >= 0.95 * 8.0, "d={d} eager={eager}: {rate:.2} packets/ms of 8 (win {win})");
            assert_eq!(viol, 0);
        }
    }

    #[test]
    fn sim_stalling_sink_keeps_backlog_near_the_window() {
        // the sink reads 0.5 s, stalls 1 s; the backlog stays within ~2 windows (base-2: the client's buffers)
        for eager in [false, true] {
            let (_, maxb, viol, win) = sim(100, 8, 20000, eager, |t| if t % 1500 < 500 { 1 << 20 } else { 0 });
            assert!(maxb <= 2 * win, "eager={eager}: backlog {maxb} > 2 x win {win}");
            assert!(maxb <= CAP, "eager={eager}: backlog {maxb} > cap: an honest stream would be held");
            assert_eq!(viol, 0);
        }
    }
}
