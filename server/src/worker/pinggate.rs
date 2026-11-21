//! 20.34 ping gate: the CLOSE the server sends for an open TCP stream that its destination ended (FIN, or an error:
//! not 0x49, the server's own limits, which cut the stream anyway) waits until the client has
//! answered a WebSocket PING queued behind that stream's DATA, at most CAP_MS. A client whose WebSocket layer
//! delivers a stream's last DATA and its CLOSE from one socket read can lose that DATA (the same-read loss); once
//! the PONG is back, the client has processed the DATA. It does not help a client whose stream reader still holds
//! unread data when its WebSocket layer answers the PING (a slow reader). Browsers (the upgrade request had an Origin
//! header) are not held.
//!
//! The state is worker-local and beside the slabs (no Client or Target growth): the held CLOSEs in a slab of 40-byte
//! entries; per client slot a Conn (its held CLOSEs as a list, its one gate PING in flight, its flags); every held
//! CLOSE in hold order in a FIFO (each has the same cap, so hold order is deadline order). Nothing runs per read or
//! per frame; a loop turn tests `live` twice (Worker::run). Release is driven by events: the PONG (on_frame), the cap
//! (gate_expire, before flush_dirty), the client's own CLOSE (wisp.rs), shutdown (shutdown_step) and migration (a
//! connection with held CLOSEs does not move).
use super::*;
use std::collections::VecDeque;

/// 20.34 the longest a CLOSE waits for its PONG (ms); then it is sent. A connection whose gate PING is unanswered
/// for CAP_MS gets no more holds until that PONG comes: a client that never answers PINGs sees one CLOSE late by
/// CAP_MS per connection, then the v1.4.0 behaviour.
pub(super) const CAP_MS: u32 = 1000;
/// 20.34 held CLOSEs per connection; past it a CLOSE is sent at once (a const: --max-streams-per-conn counts streams,
/// and a held CLOSE is no stream any more)
pub(super) const PER_CONN: u16 = 1024;
/// 20.34 held CLOSEs per worker thread; past it a CLOSE is sent at once
pub(super) const PER_WORKER: u32 = 65536;
/// 20.34 the gate PING's payload is TAG + its u32 number (LE), 6 bytes. credit v2's PINGs carry 8 bytes (and
/// credit::Pinger takes only 8), so the PONG of one never stands for the other.
pub(super) const TAG: [u8; 2] = *b"fw";
const NIL: u32 = u32::MAX;
const BROWSER: u8 = 1; // the upgrade request had an Origin header: never held
const LOST: u8 = 2; // a gate PING was not answered in CAP_MS: no holds until its PONG
const GEN_MASK: u32 = 0x3fff_ffff; // (as Slab::get)

/// a held CLOSE (40 bytes)
#[derive(Clone, Copy)]
struct Held {
    lane: u64, // its stream's bulk-lane end (Target::bulk_end): a CLOSE sent without the PONG goes behind it
    ci: u32,
    cgen: u32,
    sid: u32,
    next: u32, // the next held CLOSE of the same connection (of a free entry: the next free one)
    born: u32, // Gate::ms when it was held
    tag: u32,  // the hold's number (never 0); 0 = a free entry. A FIFO entry with another tag is stale
    reason: u8,
}

/// the state of one client slot (40 bytes)
#[derive(Clone, Copy, Default)]
struct Conn {
    gen1: u32, // (generation & GEN_MASK) + 1 of the connection it belongs to; another = stale, reset at its next use
    head: u32, // its held CLOSEs, oldest first (valid while n > 0)
    tail: u32,
    n: u16,
    covered: u16, // the first `covered` of them wait for the PING in flight (their DATA was queued before it)
    seq: u32,     // the gate PING in flight (0 = none)
    sent: u32,    // Gate::ms when it was queued
    lane: u64,    // max bulk-lane end of the CLOSEs held since the last gate PING was queued (Gate::pong: a bound)
    flags: u8,
}
const _: () = assert!(std::mem::size_of::<Held>() == 40 && std::mem::size_of::<Conn>() == 40);

/// what goes along with a connection that moves to another worker (a connection with held CLOSEs does not move)
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub(super) struct Carry {
    flags: u8,
    seq: u32,
    sent: u32,
}

/// the answer of Gate::admit
#[derive(PartialEq, Debug)]
pub(super) enum Admit {
    /// held: queue gate PING `.0` (where: push_ping with `.1`)
    Ping(u32, u64),
    /// held behind the PING in flight: the next PING covers it
    Wait,
    /// sent at once: a browser connection
    Browser,
    /// sent at once: the connection's PING went unanswered for CAP_MS
    Lost,
    /// sent at once: PER_CONN or PER_WORKER held already
    Full,
}

/// a held CLOSE whose cap came (Gate::expire)
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Due {
    pub(super) ci: u32,
    pub(super) cgen: u32,
    pub(super) sid: u32,
    pub(super) reason: u8,
    pub(super) lane: u64,
}

/// a gate PING sent at `sent` (ms) is CAP_MS old at `now`. Signed: a send time a little ahead of `now` (a PING
/// queued on the source worker after the destination's turn began, carried by a move) reads young, not 49 days old.
/// (deliberate: a PING unanswered for 24.8 days with no CLOSE held or admitted meanwhile reads young again)
#[inline]
fn ping_old(now: u32, sent: u32) -> bool {
    now.wrapping_sub(sent) as i32 >= CAP_MS as i32
}

#[inline]
fn g1(cgen: u32) -> u32 {
    (cgen & GEN_MASK) + 1
}

/// one Instant for every worker, so that a carried `sent` means the same on the worker a connection moves to
fn epoch() -> Instant {
    static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *T0.get_or_init(Instant::now)
}

pub(super) struct Gate {
    held: Vec<Held>,
    free: u32,
    conns: Vec<Conn>,
    fifo: VecDeque<(u32, u32)>, // (held index, tag) in hold order; stale entries are dropped when met
    /// held CLOSEs now (Worker::run reads only this while nothing is held)
    pub(super) live: u32,
    seq: u32,
    tag: u32,
    t0: Instant,
    /// pong / take_all: the CLOSEs to send, (sid, reason, its bulk-lane end), oldest first
    pub(super) out: Vec<(u32, u8, u64)>,
    /// expire: the CLOSEs whose cap came, in hold order
    pub(super) due: Vec<Due>,
}

impl Gate {
    pub(super) fn new() -> Gate {
        Gate {
            held: Vec::new(),
            free: NIL,
            conns: Vec::new(),
            fifo: VecDeque::new(),
            live: 0,
            seq: 0,
            tag: 0,
            t0: epoch(),
            out: Vec::new(),
            due: Vec::new(),
        }
    }

    /// ms since the process epoch (wraps after 49 days: every compare is a wrapping difference; u32 arithmetic, not
    /// Duration::as_millis's u128)
    #[inline]
    pub(super) fn ms(&self, now: Instant) -> u32 {
        let d = now.saturating_duration_since(self.t0);
        (d.as_secs() as u32).wrapping_mul(1000).wrapping_add(d.subsec_millis())
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    /// the Conn of (ci, cgen): grown on demand, reset when it was another connection's
    fn conn(&mut self, ci: u32, cgen: u32) -> &mut Conn {
        let i = ci as usize;
        if self.conns.len() <= i {
            self.conns.resize(i + 1, Conn::default());
        }
        let k = &mut self.conns[i];
        if k.gen1 != g1(cgen) {
            *k = Conn { gen1: g1(cgen), ..Conn::default() };
        }
        k
    }

    fn get(&self, ci: u32, cgen: u32) -> Option<Conn> {
        self.conns.get(ci as usize).filter(|k| k.gen1 == g1(cgen)).copied()
    }

    /// held CLOSEs of connection (ci, cgen) (shutdown and migration wait for 0)
    pub(super) fn held(&self, ci: u32, cgen: u32) -> u32 {
        self.get(ci, cgen).map_or(0, |k| k.n as u32)
    }

    /// a WebSocket connection (ci, cgen) starts (upgrade.rs): its slot's row starts clean (a stale row of an old
    /// connection cannot alias after a generation wrap); browser = its upgrade request had an Origin header: its
    /// CLOSEs are never held
    pub(super) fn begin(&mut self, ci: u32, cgen: u32, browser: bool) {
        if browser {
            self.conn(ci, cgen).flags = BROWSER; // (conn resets a row of another generation)
        } else if let Some(k) = self.conns.get_mut(ci as usize) {
            *k = Conn::default();
        }
    }

    fn free_entry(&mut self, i: u32) {
        let e = &mut self.held[i as usize];
        (e.tag, e.next) = (0, self.free);
        self.free = i;
        self.live -= 1;
        if self.live == 0 {
            self.fifo.clear(); // (only stale entries are left)
        }
    }

    /// the target ended open TCP stream `sid` of (ci, cgen) with `reason`; `lane`: its Target::bulk_end; `now`: ms
    pub(super) fn admit(&mut self, ci: u32, cgen: u32, sid: u32, reason: u8, lane: u64, now: u32) -> Admit {
        if let Some(k) = self.get(ci, cgen) {
            if k.flags & BROWSER != 0 {
                return Admit::Browser;
            }
            if k.flags & LOST != 0 {
                return Admit::Lost;
            }
            if k.seq != 0 && ping_old(now, k.sent) {
                // its PING is past the cap (no CLOSE was held under it, or its cap was not checked yet)
                self.conns[ci as usize].flags |= LOST;
                return Admit::Lost;
            }
            if k.n >= PER_CONN {
                return Admit::Full;
            }
        }
        if self.live >= PER_WORKER {
            return Admit::Full;
        }
        self.tag = self.tag.wrapping_add(1).max(1);
        let e = Held { lane, ci, cgen, sid, next: NIL, born: now, tag: self.tag, reason };
        let i = if self.free != NIL {
            let i = self.free;
            self.free = self.held[i as usize].next;
            self.held[i as usize] = e;
            i
        } else {
            self.held.push(e);
            (self.held.len() - 1) as u32
        };
        self.live += 1;
        self.fifo.push_back((i, self.tag));
        if self.fifo.len() > 2 * self.live as usize + 1024 {
            let held = &self.held;
            self.fifo.retain(|&(j, t)| held[j as usize].tag == t); // (amortized O(1) per hold; memory O(live))
        }
        let mut k = *self.conn(ci, cgen);
        if k.n == 0 {
            k.head = i;
        } else {
            self.held[k.tail as usize].next = i;
        }
        k.tail = i;
        k.n += 1;
        k.lane = k.lane.max(lane);
        let ans = if k.seq == 0 {
            k.seq = self.next_seq();
            (k.sent, k.covered) = (now, k.n);
            Admit::Ping(k.seq, std::mem::take(&mut k.lane))
        } else {
            Admit::Wait
        };
        self.conns[ci as usize] = k;
        ans
    }

    /// the PONG of gate PING `seq` from (ci, cgen). None: not the PING in flight (ignored). Some((ping, lane)): `out`
    /// holds the CLOSEs it releases, oldest first; ping != 0: queue that gate PING for the CLOSEs still held
    pub(super) fn pong(&mut self, ci: u32, cgen: u32, seq: u32, now: u32) -> Option<(u32, u64)> {
        let mut k = self.get(ci, cgen).filter(|k| k.seq != 0 && k.seq == seq)?;
        self.out.clear();
        for _ in 0..k.covered {
            let i = k.head;
            let e = self.held[i as usize];
            self.out.push((e.sid, e.reason, e.lane));
            k.head = e.next;
            k.n -= 1;
            self.free_entry(i);
        }
        (k.seq, k.covered, k.flags) = (0, 0, k.flags & !LOST);
        // the lane end of the CLOSEs held since this PING (the next PING covers them). deliberate: an upper bound, not
        // lowered when one of them was dropped or capped meanwhile: the next PING may wait behind a dropped stream's
        // lane DATA, never go ahead of a covered stream's
        let lane = std::mem::take(&mut k.lane);
        if k.n > 0 {
            k.seq = self.next_seq();
            (k.sent, k.covered) = (now, k.n);
        }
        self.conns[ci as usize] = k;
        Some((k.seq, lane))
    }

    /// the client of (ci, cgen) closed stream `sid` itself: its held CLOSE (if any) is not sent. true = there was one
    pub(super) fn client_close(&mut self, ci: u32, cgen: u32, sid: u32) -> bool {
        let Some(mut k) = self.get(ci, cgen).filter(|k| k.n > 0) else { return false };
        let (mut prev, mut i) = (NIL, k.head);
        for pos in 0..k.n {
            let e = self.held[i as usize];
            if e.sid == sid {
                if prev == NIL {
                    k.head = e.next;
                } else {
                    self.held[prev as usize].next = e.next;
                }
                if k.tail == i {
                    k.tail = prev;
                }
                k.n -= 1;
                k.covered -= (pos < k.covered) as u16;
                self.conns[ci as usize] = k;
                self.free_entry(i);
                return true;
            }
            (prev, i) = (i, e.next); // (deliberate: a walk of at most PER_CONN; a map if a profile shows it)
        }
        false
    }

    /// the CLOSEs whose cap came by `now` go to `due` (hold order). Their connection gets LOST only if its gate PING
    /// in flight is CAP_MS old (a CLOSE held behind a PING may cap under the next, younger PING). (ping_old: a signed
    /// difference of u32 ms)
    pub(super) fn expire(&mut self, now: u32) {
        self.due.clear();
        while let Some(&(i, tag)) = self.fifo.front() {
            let e = self.held[i as usize];
            if e.tag != tag {
                self.fifo.pop_front(); // released before its cap
                continue;
            }
            if now.wrapping_sub(e.born) < CAP_MS {
                break;
            }
            self.fifo.pop_front();
            if let Some(k) = self.conns.get_mut(e.ci as usize).filter(|k| k.gen1 == g1(e.cgen)) {
                debug_assert_eq!(k.head, i, "20.34 the oldest held CLOSE of a connection is its head");
                k.head = e.next;
                k.n -= 1;
                k.covered = k.covered.saturating_sub(1);
                if k.seq != 0 && ping_old(now, k.sent) {
                    k.flags |= LOST;
                }
            } // (else its connection ended and the slot was reset: the worker drops it, the client is gone)
            self.due.push(Due { ci: e.ci, cgen: e.cgen, sid: e.sid, reason: e.reason, lane: e.lane });
            self.free_entry(i);
        }
    }

    /// ms until the next cap (u32::MAX: none held)
    pub(super) fn wait_ms(&mut self, now: u32) -> u32 {
        while let Some(&(i, tag)) = self.fifo.front() {
            let e = &self.held[i as usize];
            if e.tag != tag {
                self.fifo.pop_front();
                continue;
            }
            return CAP_MS.saturating_sub(now.wrapping_sub(e.born));
        }
        u32::MAX
    }

    /// every held CLOSE of (ci, cgen) to `out` (oldest first) and out of the gate
    pub(super) fn take_all(&mut self, ci: u32, cgen: u32) {
        self.out.clear();
        let Some(mut k) = self.get(ci, cgen) else { return };
        let mut i = k.head;
        for _ in 0..k.n {
            let e = self.held[i as usize];
            self.out.push((e.sid, e.reason, e.lane));
            self.free_entry(i);
            i = e.next;
        }
        (k.n, k.covered, k.lane) = (0, 0, 0);
        self.conns[ci as usize] = k;
    }

    /// (ci, cgen) leaves this worker (migrate.rs: only with nothing held): its flags and PING in flight go along
    pub(super) fn export(&mut self, ci: u32, cgen: u32) -> Carry {
        let Some(k) = self.get(ci, cgen) else { return Carry::default() };
        debug_assert_eq!(k.n, 0, "20.34 a connection with held CLOSEs does not move (mig_quiet)");
        self.conns[ci as usize].gen1 = 0;
        Carry { flags: k.flags, seq: k.seq, sent: k.sent }
    }

    /// a connection arrived as (ci, cgen) with `c`; the slot's row starts clean, as at begin
    pub(super) fn import(&mut self, ci: u32, cgen: u32, c: Carry) {
        if c != Carry::default() {
            *self.conn(ci, cgen) = Conn { gen1: g1(cgen), flags: c.flags, seq: c.seq, sent: c.sent, ..Conn::default() };
        } else if let Some(k) = self.conns.get_mut(ci as usize) {
            *k = Conn::default();
        }
    }

    /// Worker::run: memory the idle sweep can give back (keeps the sweep's wake armed on a worker without clients)
    pub(super) fn reclaimable(&self) -> bool {
        self.live == 0 && self.held.capacity() != 0
    }

    /// idle sweep: nothing held: the held slab and the FIFO are given back (the Conns stay: they carry the browser flag)
    pub(super) fn shrink(&mut self) {
        if self.live == 0 && self.held.capacity() != 0 {
            (self.held, self.free, self.fifo) = (Vec::new(), NIL, VecDeque::new());
            (self.out, self.due) = (Vec::new(), Vec::new());
        }
    }
}

/// the gate PING, behind everything queued for the held streams: in the bulk lane while one of them has DATA there
/// that is not sent (20.19: obuf goes out before the lane), else in obuf (then it does not wait for another stream's
/// bulk download)
fn push_ping(c: &mut Client, seq: u32, lane: u64) {
    let mut p = [0u8; 6];
    p[..2].copy_from_slice(&TAG);
    p[2..].copy_from_slice(&seq.to_le_bytes());
    if lane > c.bulk_sent {
        ws::push_frame(&mut c.bulk, OP_PING, &[&p]);
        c.bulk_frame_done();
    } else {
        ws::push_frame(&mut c.obuf, OP_PING, &[&p]);
    }
}

/// a held CLOSE sent without its PONG (the cap, shutdown): behind its stream's DATA, as close_target places it
fn push_close(c: &mut Client, sid: u32, reason: u8, lane: u64) {
    if lane > c.bulk_sent {
        let mut h = [0u8; 6];
        h[0] = PKT_CLOSE;
        h[1..5].copy_from_slice(&sid.to_le_bytes());
        h[5] = reason;
        ws::push_frame(&mut c.bulk, OP_BIN, &[&h]);
        c.bulk_frame_done();
    } else {
        c.push_wisp(PKT_CLOSE, sid, &[reason]);
    }
}

/// close_target, for the CLOSE of open TCP stream `t` (out of the slab) whose target ended with `reason`, its client
/// `c` open and not closing: true = held (the caller marks the client dirty: a PING may be queued); false = the
/// caller sends it now, as v1.4.0 did
#[inline(never)]
pub(super) fn hold(g: &mut Gate, c: &mut Client, t: &Target, reason: u8, now: Instant, st: &metrics::Stats) -> bool {
    let now = g.ms(now);
    match g.admit(t.client, t.cgen, t.sid, reason, t.bulk_end, now) {
        Admit::Ping(seq, lane) => {
            push_ping(c, seq, lane);
            st.ping_gate_pings.bump();
            st.ping_gate_held.bump();
            true
        }
        Admit::Wait => {
            st.ping_gate_held.bump();
            true
        }
        Admit::Browser => {
            st.ping_gate_browser.bump();
            false
        }
        Admit::Lost => {
            st.ping_gate_nopong.bump();
            false
        }
        Admit::Full => {
            st.ping_gate_full.bump();
            false
        }
    }
}

/// shutdown_step (the close phase): the held CLOSEs of (ci, cgen) go into obuf before its WebSocket Close. A CLOSE
/// whose stream still has DATA in the bulk lane is not sent (dropped): begin_close cuts that lane, and a CLOSE without
/// its DATA would tell the client the stream ended in full
pub(super) fn flush_held(g: &mut Gate, c: &mut Client, ci: u32, cgen: u32, st: &metrics::Stats) {
    g.take_all(ci, cgen);
    for &(sid, r, lane) in &g.out {
        debug_assert!(!c.streams.contains_key(&sid), "20.34 a CONNECT of a held id drops its CLOSE (wisp.rs)");
        if lane > c.bulk_sent {
            st.ping_gate_dropped.bump();
            continue;
        }
        c.push_wisp(PKT_CLOSE, sid, &[r]);
        st.close[r as usize].bump(); // 60.12 counted when sent
        st.ping_gate_capped.bump();
    }
}

impl Worker {
    /// Worker::run, while CLOSEs are held: the epoll timeout `t` (ms, -1 = none) shortened to the next cap. The time
    /// is the turn's (self.now, no clock read): a cap ends at most one turn's work late
    #[inline(never)]
    pub(super) fn gate_timeout(&mut self, t: i32) -> i32 {
        if t == 0 {
            return 0;
        }
        let left = self.gate.wait_ms(self.gate.ms(self.now));
        if left == u32::MAX {
            return t; // (none held: the caller tests live first)
        }
        let left = left.min(i32::MAX as u32) as i32;
        if t < 0 || left < t {
            left
        } else {
            t
        }
    }

    /// Worker::run, while CLOSEs are held, before flush_dirty: the CLOSEs whose cap came are sent
    #[inline(never)]
    pub(super) fn gate_expire(&mut self) {
        let now = self.gate.ms(self.now);
        self.gate.expire(now);
        for k in 0..self.gate.due.len() {
            let d = self.gate.due[k];
            match self.clients.get(d.ci, d.cgen) {
                Some(c) if !c.dead && !c.closing => {
                    debug_assert!(!c.streams.contains_key(&d.sid), "20.34 a CONNECT of a held id drops its CLOSE");
                    push_close(c, d.sid, d.reason, d.lane);
                    self.stats.close[d.reason as usize].bump(); // 60.12 counted when sent
                    self.stats.ping_gate_capped.bump();
                    self.mark_dirty(d.ci);
                }
                // its connection ended or is closing
                _ => self.stats.ping_gate_dropped.bump(),
            }
        }
    }

    /// on_frame: a PONG with a gate PING's length and tag (payload `p`) from client `ci`
    #[cold]
    #[inline(never)]
    pub(super) fn gate_pong(&mut self, ci: u32, p: &[u8]) {
        let seq = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
        let (cg, now) = (self.clients.gen(ci), self.gate.ms(self.now));
        let c = self.clients.at(ci);
        if c.dead || c.closing {
            return; // (its held CLOSEs are dropped at their cap)
        }
        let Some((ping, lane)) = self.gate.pong(ci, cg, seq, now) else { return };
        for &(sid, r, _) in &self.gate.out {
            debug_assert!(!c.streams.contains_key(&sid), "20.34 a CONNECT of a held id drops its CLOSE (wisp.rs)");
            c.push_wisp(PKT_CLOSE, sid, &[r]); // (its DATA reached the client before the PING did)
            self.stats.close[r as usize].bump(); // 60.12 counted when sent
            self.stats.ping_gate_released.bump();
        }
        if ping != 0 {
            push_ping(c, ping, lane);
            self.stats.ping_gate_pings.bump();
        }
        self.mark_dirty(ci);
    }

    /// wisp.rs: the client sent CLOSE for `sid`, which is no stream (any more), or CONNECT for `sid` (it opens the id
    /// again): a held CLOSE of it is not sent (it would end the new stream)
    #[cold]
    #[inline(never)]
    pub(super) fn gate_client_close(&mut self, ci: u32, sid: u32) {
        if self.gate.client_close(ci, self.clients.gen(ci), sid) {
            self.stats.ping_gate_dropped.bump();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// every list walks to its count, `live` is the sum, `covered` <= n, the FIFO holds every live entry once
    fn check(g: &Gate) {
        let mut sum = 0u32;
        for k in g.conns.iter().filter(|k| k.gen1 != 0) {
            assert!(k.covered <= k.n);
            let mut i = k.head;
            for _ in 0..k.n {
                let e = g.held[i as usize];
                assert_ne!(e.tag, 0, "a free entry in a list");
                assert_eq!(g1(e.cgen), k.gen1);
                i = e.next;
            }
            if k.n > 0 {
                assert_eq!(i, NIL, "the tail ends the list");
                sum += k.n as u32;
            }
        }
        let tags = g.held.iter().filter(|e| e.tag != 0).count() as u32;
        assert!(sum <= g.live && tags == g.live, "lists {sum}, live {}, entries {tags}", g.live);
        let live_refs = g.fifo.iter().filter(|&&(i, t)| g.held[i as usize].tag == t).count() as u32;
        assert_eq!(live_refs, g.live);
    }

    fn sids(g: &Gate) -> Vec<u32> {
        g.out.iter().map(|o| o.0).collect()
    }

    /// The first CLOSE queues a PING and waits for it; CLOSEs held while it is in flight wait for the next PING, which
    /// the PONG queues; PONGs release in hold order
    #[test]
    fn pong_releases_the_covered_closes_and_pings_for_the_rest() {
        let mut g = Gate::new();
        assert_eq!(g.admit(3, 7, 1, 2, 0, 100), Admit::Ping(1, 0));
        assert_eq!(g.admit(3, 7, 2, 2, 0, 101), Admit::Wait);
        assert_eq!(g.admit(3, 7, 3, 3, 50, 102), Admit::Wait);
        assert_eq!((g.live, g.held(3, 7)), (3, 3));
        check(&g);
        assert_eq!(g.pong(3, 7, 1, 110), Some((2, 50)), "the next PING covers the two that wait (behind lane end 50)");
        assert_eq!(g.out, vec![(1, 2, 0)]);
        check(&g);
        assert_eq!(g.admit(3, 7, 4, 2, 0, 111), Admit::Wait, "held after PING 2: waits for PING 3");
        assert_eq!(g.pong(3, 7, 2, 120), Some((3, 0)), "PING 3 covers only stream 4: its lane end, not 50");
        assert_eq!(sids(&g), vec![2, 3]);
        assert_eq!(g.out[1], (3, 3, 50), "the reason and the lane end travel");
        assert_eq!(g.pong(3, 7, 3, 130), Some((0, 0)));
        assert_eq!(sids(&g), vec![4]);
        assert_eq!((g.live, g.held(3, 7), g.fifo.len()), (0, 0, 0));
        check(&g);
        assert_eq!(g.admit(3, 7, 5, 2, 0, 131), Admit::Ping(4, 0), "no PING in flight: a new one");
    }

    /// A PONG that is not the PING in flight changes nothing: another number, an old one, 0, another connection or
    /// generation of the slot
    #[test]
    fn a_foreign_pong_releases_nothing() {
        let mut g = Gate::new();
        assert_eq!(g.admit(0, 1, 9, 2, 0, 0), Admit::Ping(1, 0));
        for (ci, cg, seq) in [(0, 1, 2), (0, 1, 0), (0, 2, 1), (1, 1, 1), (5, 1, 1), (0, 1 + (1 << 30), 2)] {
            assert_eq!(g.pong(ci, cg, seq, 5), None, "{ci} {cg} {seq}");
        }
        assert_eq!(g.held(0, 1), 1);
        assert_eq!(g.pong(0, 1 + (1 << 30), 1, 5), Some((0, 0)), "the generation compares as the slab's (30 bits)");
        assert_eq!(g.pong(0, 1, 1, 6), None, "answered: no PING in flight");
        check(&g);
    }

    /// A CLOSE goes at its cap (hold time + CAP_MS), oldest first; then its connection is LOST: new CLOSEs are sent
    /// at once until the late PONG, which releases what still waits and ends LOST
    #[test]
    fn the_cap_sends_and_marks_the_connection_lost_until_its_pong() {
        let mut g = Gate::new();
        assert_eq!(g.admit(0, 1, 1, 2, 0, 1000), Admit::Ping(1, 0));
        assert_eq!(g.admit(0, 1, 2, 2, 7, 1010), Admit::Wait);
        assert_eq!(g.admit(1, 4, 8, 2, 0, 1020), Admit::Ping(2, 0));
        assert_eq!(g.wait_ms(1500), 500);
        g.expire(1999);
        assert!(g.due.is_empty());
        g.expire(2000);
        assert_eq!(g.due, vec![Due { ci: 0, cgen: 1, sid: 1, reason: 2, lane: 0 }], "its own lane end, not stream 2's");
        check(&g);
        assert_eq!(g.wait_ms(2000), 10);
        assert_eq!(g.admit(0, 1, 3, 2, 0, 2001), Admit::Lost, "LOST after its cap");
        assert_eq!(g.admit(1, 4, 9, 2, 0, 2001), Admit::Wait, "another connection is not");
        g.expire(2010);
        assert_eq!(g.due.iter().map(|d| (d.sid, d.lane)).collect::<Vec<_>>(), vec![(2, 7)]);
        assert_eq!(g.held(0, 1), 0);
        assert_eq!(g.pong(0, 1, 1, 2500).map(|p| p.0), Some(0), "the late PONG: nothing left, no PING");
        assert!(g.out.is_empty());
        assert_eq!(g.admit(0, 1, 4, 2, 0, 2501), Admit::Ping(3, 0), "held again");
        g.expire(u32::MAX / 2);
        assert_eq!(g.due.iter().map(|d| d.sid).collect::<Vec<_>>(), vec![8, 9, 4]);
        assert_eq!((g.live, g.wait_ms(0)), (0, u32::MAX));
        check(&g);
    }

    /// A PING in flight for CAP_MS with nothing held under it (the client closed those streams first): the next CLOSE
    /// is sent at once and the connection is LOST
    #[test]
    fn an_unanswered_ping_without_held_closes_is_lost_at_the_next_close() {
        let mut g = Gate::new();
        assert_eq!(g.admit(0, 1, 1, 2, 0, 0), Admit::Ping(1, 0));
        assert!(g.client_close(0, 1, 1));
        assert_eq!(g.admit(0, 1, 2, 2, 0, 999), Admit::Wait, "within the cap: waits");
        assert!(g.client_close(0, 1, 2));
        assert_eq!(g.admit(0, 1, 3, 2, 0, 1000), Admit::Lost);
        assert_eq!(g.live, 0);
        assert_eq!(g.pong(0, 1, 1, 5000), Some((0, 0)));
        assert_eq!(g.admit(0, 1, 4, 2, 0, 5001), Admit::Ping(2, 0));
        check(&g);
    }

    /// The client's own CLOSE drops a held CLOSE anywhere in the list, the covered count follows
    #[test]
    fn a_client_close_drops_the_held_close() {
        let mut g = Gate::new();
        assert_eq!(g.admit(0, 1, 1, 2, 0, 0), Admit::Ping(1, 0));
        for sid in 2..=5 {
            assert_eq!(g.admit(0, 1, sid, 2, 0, 1), Admit::Wait);
        }
        assert!(g.pong(0, 1, 1, 2).is_some());
        assert_eq!(sids(&g), vec![1]);
        // 2..=5 covered by PING 2
        assert!(g.client_close(0, 1, 3));
        assert!(!g.client_close(0, 1, 3), "once");
        assert!(!g.client_close(0, 2, 4), "another generation");
        assert!(g.client_close(0, 1, 2), "the head");
        check(&g);
        assert_eq!(g.admit(0, 1, 6, 2, 0, 3), Admit::Wait);
        assert!(g.client_close(0, 1, 6), "the tail");
        assert_eq!(g.admit(0, 1, 7, 2, 0, 3), Admit::Wait, "a new tail after a removed tail");
        check(&g);
        assert_eq!(g.pong(0, 1, 2, 4), Some((3, 0)));
        assert_eq!(sids(&g), vec![4, 5]);
        assert_eq!(g.pong(0, 1, 3, 5), Some((0, 0)));
        assert_eq!(sids(&g), vec![7]);
        assert_eq!(g.live, 0);
        check(&g);
    }

    /// PER_CONN held CLOSEs on one connection, then the next goes at once; other connections are held up to
    /// PER_WORKER in all (the real consts)
    #[test]
    fn per_connection_and_per_worker_limits() {
        let mut g = Gate::new();
        let per = PER_CONN as u32;
        for sid in 0..per {
            assert!(matches!(g.admit(0, 1, sid, 2, 0, 0), Admit::Ping(..) | Admit::Wait));
        }
        assert_eq!(g.admit(0, 1, per, 2, 0, 0), Admit::Full);
        let conns = PER_WORKER / per;
        for ci in 1..conns {
            for sid in 0..per {
                assert!(matches!(g.admit(ci, 1, sid, 2, 0, 0), Admit::Ping(..) | Admit::Wait));
            }
        }
        assert_eq!(g.live, PER_WORKER);
        assert_eq!(g.admit(conns, 1, 0, 2, 0, 0), Admit::Full, "the worker's limit");
        check(&g);
        assert!(g.client_close(conns - 1, 1, 7));
        assert_eq!(g.admit(conns, 1, 0, 2, 0, 0), Admit::Ping(conns + 1, 0), "room again");
        g.expire(CAP_MS);
        assert_eq!((g.due.len() as u32, g.live), (PER_WORKER, 0));
        check(&g);
    }

    /// A browser connection is never held; the flag belongs to its generation, and a new connection's begin clears
    /// a stale row (so it cannot alias after the slab's 30-bit generation wraps)
    #[test]
    fn browser_connections_are_not_held() {
        let mut g = Gate::new();
        g.begin(2, 5, true);
        assert_eq!(g.admit(2, 5, 1, 2, 0, 0), Admit::Browser);
        assert_eq!(g.admit(2, 6, 1, 2, 0, 0), Admit::Ping(1, 0), "the next connection in the slot");
        assert_eq!(g.live, 1);
        g.begin(3, 5, true);
        g.begin(3, 5 + (1 << 30), false);
        assert_eq!(g.admit(3, 5 + (1 << 30), 1, 2, 0, 0), Admit::Ping(2, 0), "no stale BROWSER after a wrap");
        g.begin(4, 1, false);
        assert!(g.conns.len() < 5, "a plain begin grows nothing");
        g.begin(2, 9, true);
        g.import(2, 9 + (1 << 30), Carry::default());
        assert_eq!(g.admit(2, 9 + (1 << 30), 1, 2, 0, 0), Admit::Ping(3, 0), "a move in starts clean too");
        g.conns[3].lane = 77; // (a stale row of the slot (3, 5 + 2^30), aliased by (3, 5))
        g.import(3, 5, Carry { flags: 0, seq: 9, sent: 4 });
        let k = g.conns[3];
        assert!(k.n == 0 && k.covered == 0 && k.lane == 0 && (k.seq, k.sent) == (9, 4), "a carried move in starts clean too");
    }

    /// A PING's age compares signed: a send time a little ahead of now (carried by a move) is young
    #[test]
    fn ping_age_is_signed() {
        assert!(ping_old(1000, 0) && ping_old(5, u32::MAX - 995) && !ping_old(999, 0));
        assert!(!ping_old(10, 12), "sent 2 ms ahead (another worker's turn): young, not 49 days old");
    }

    /// A CLOSE held behind a PING caps under the next, young PING: it goes, and the connection is not LOST; LOST
    /// comes only from a gate PING unanswered for CAP_MS
    #[test]
    fn lost_only_when_the_ping_in_flight_is_cap_old() {
        let mut g = Gate::new();
        assert_eq!(g.admit(0, 1, 1, 2, 0, 0), Admit::Ping(1, 0));
        assert_eq!(g.admit(0, 1, 2, 2, 0, 1), Admit::Wait);
        assert_eq!(g.pong(0, 1, 1, 999), Some((2, 0)));
        g.expire(1001);
        assert_eq!(g.due.iter().map(|d| d.sid).collect::<Vec<_>>(), vec![2]);
        assert_eq!(g.admit(0, 1, 3, 2, 0, 1001), Admit::Wait, "PING 2 is 2 ms old: not LOST");
        g.expire(1998);
        assert!(g.due.is_empty());
        g.expire(2001);
        assert_eq!(g.due.iter().map(|d| d.sid).collect::<Vec<_>>(), vec![3]);
        assert_eq!(g.admit(0, 1, 4, 2, 0, 2001), Admit::Lost, "PING 2 unanswered for CAP_MS");
        check(&g);
    }

    /// A slot reused while CLOSEs of its old connection are held: the new connection starts empty, the old CLOSEs
    /// still go to `due` at their cap (the worker drops them: that client is gone)
    #[test]
    fn a_reused_slot_starts_empty() {
        let mut g = Gate::new();
        assert_eq!(g.admit(0, 1, 1, 2, 0, 0), Admit::Ping(1, 0));
        assert_eq!(g.admit(0, 1, 2, 2, 0, 0), Admit::Wait);
        assert_eq!(g.admit(0, 2, 1, 2, 0, 10), Admit::Ping(2, 0));
        assert_eq!((g.held(0, 1), g.held(0, 2), g.live), (0, 1, 3));
        assert_eq!(g.pong(0, 1, 1, 11), None);
        g.expire(1000);
        assert_eq!(g.due.iter().map(|d| (d.cgen, d.sid, d.lane)).collect::<Vec<_>>(), vec![(1, 1, 0), (1, 2, 0)]);
        assert_eq!(g.held(0, 2), 1);
        assert_eq!(g.admit(0, 2, 3, 2, 0, 1001), Admit::Wait, "the new connection is not LOST");
        assert_eq!(g.pong(0, 2, 2, 1002), Some((3, 0)));
        assert_eq!(sids(&g), vec![1]);
        check(&g);
    }

    /// The FIFO stays O(live) while CLOSEs come and go fast beside one that waits; stale entries never delay a cap
    #[test]
    fn the_fifo_stays_bounded() {
        let mut g = Gate::new();
        assert_eq!(g.admit(9, 1, 1, 2, 0, 0), Admit::Ping(1, 0));
        let mut max = 0;
        for k in 0..100_000u32 {
            let Admit::Ping(seq, _) = g.admit(0, 1, k, 2, 0, 0) else { panic!("{k}") };
            assert!(g.pong(0, 1, seq, 0).is_some());
            max = max.max(g.fifo.len());
        }
        assert!(max <= 2 * 2 + 1024, "{max}"); // (2 live at the check: the one that waits and the one just held)
        check(&g);
        assert!(matches!(g.admit(8, 1, 1, 2, 0, 1), Admit::Ping(..)));
        assert!(g.pong(9, 1, 1, 1).is_some(), "the oldest goes: stale entries are in front now");
        assert_eq!(g.wait_ms(500), 501);
        g.expire(1000);
        assert!(g.due.is_empty(), "no stale entry stands for a cap");
        g.expire(1001);
        assert_eq!((g.due.len(), g.live, g.fifo.len()), (1, 0, 0));
        check(&g);
    }

    /// PING numbers wrap and skip 0; hold times wrap (49 days of ms)
    #[test]
    fn numbers_and_times_wrap() {
        let mut g = Gate::new();
        g.seq = u32::MAX;
        g.tag = u32::MAX;
        let t = u32::MAX - 10;
        assert_eq!(g.admit(0, 1, 1, 2, 0, t), Admit::Ping(1, 0));
        assert_eq!(g.held[0].tag, 1);
        assert_eq!(g.wait_ms(t.wrapping_add(400)), 600);
        g.expire(t.wrapping_add(999));
        assert!(g.due.is_empty());
        g.expire(t.wrapping_add(1000));
        assert_eq!(g.due.len(), 1);
    }

    /// Shutdown takes every held CLOSE of a connection; a move carries the flags and the PING in flight
    #[test]
    fn take_all_and_carry() {
        let mut g = Gate::new();
        assert_eq!(g.admit(1, 1, 1, 2, 30, 0), Admit::Ping(1, 30));
        assert_eq!(g.admit(1, 1, 2, 3, 0, 0), Admit::Wait);
        assert_eq!(g.admit(2, 1, 5, 2, 0, 0), Admit::Ping(2, 0));
        g.take_all(1, 1);
        assert_eq!(g.out, vec![(1, 2, 30), (2, 3, 0)]);
        assert_eq!((g.held(1, 1), g.live), (0, 1));
        check(&g);
        g.take_all(1, 9);
        assert!(g.out.is_empty());
        // a move: the PING in flight (1) and LOST go along
        g.expire(2000);
        assert_eq!(g.admit(1, 1, 3, 2, 0, 2000), Admit::Lost, "PING 1 past the cap");
        let c = g.export(1, 1);
        assert_eq!(c, Carry { flags: LOST, seq: 1, sent: 0 });
        assert_eq!(g.export(1, 1), Carry::default(), "once");
        g.import(4, 8, c);
        assert_eq!(g.admit(4, 8, 1, 2, 0, 2001), Admit::Lost);
        assert_eq!(g.pong(4, 8, 1, 2002), Some((0, 0)));
        assert_eq!(g.admit(4, 8, 1, 2, 0, 2003), Admit::Ping(3, 0));
        g.begin(5, 1, true);
        let b = g.export(5, 1);
        g.import(6, 2, b);
        assert_eq!(g.admit(6, 2, 1, 2, 0, 0), Admit::Browser);
        g.import(7, 1, Carry::default());
        assert!(g.conns.len() < 8, "nothing to carry: no entry");
        check(&g);
    }

    /// The idle sweep gives the memory back only when nothing is held
    #[test]
    fn shrink_only_when_idle() {
        let mut g = Gate::new();
        assert_eq!(g.admit(0, 1, 1, 2, 0, 0), Admit::Ping(1, 0));
        g.shrink();
        assert!(g.held.capacity() > 0);
        assert!(g.pong(0, 1, 1, 1).is_some());
        g.shrink();
        assert_eq!((g.held.capacity(), g.fifo.capacity(), g.free), (0, 0, NIL));
        assert_eq!(g.admit(0, 1, 2, 2, 0, 2), Admit::Ping(2, 0));
        check(&g);
    }
}
