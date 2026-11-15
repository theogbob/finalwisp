//! 60.72 the worker's side of crate::slimits (--stream-share, --stream-pool). Nothing here is on a stream's path while
//! both are off: a worker reaches these functions from the out-of-line side of 60.57's fd count only (fd_more for a
//! CONNECT before DNS, fd_short for its refusal, fd_trim at an fd put in hold mode and at the idle sweep), and only
//! when the gate's mask has MARK_STREAM or MARK_POOL (fd_mask, which puts the worker in hold mode). The state of a
//! worker is its cell in crate::slimits' table (no Worker field), written by that worker only.
//!
//! --stream-pool and Worker::max_streams: on_connect refuses inline at max_streams, which set_levels sets to the
//! per-worker limit at each level change. With the pool it must be no limit; set_levels is inlined into the event
//! loop, so it is not changed: sl_short (every CONNECT that passes the inline test) and sl_trim (every fd put, every
//! idle sweep) set it back to no limit. deliberate: after a level change the per-worker limit holds until this
//! worker's next fd put or idle sweep (2 s) or a CONNECT below that limit; CONNECTs over it are refused inline
//! meanwhile (refuse_streams, rule stream_cap: the same as without the pool).
//!
//! wsproxy (one stream per connection, no CONNECT): its upgrade tests max_streams inline before the 101, so with the
//! pool a wsproxy request over the shared limit gets the 101 and then the close of its stream (fail_target), as at the
//! fd limit today, instead of a 503. Not changed: the upgrade is inlined into the per-frame function.

use super::fds::{EVERY, FIX};
use super::*;
use crate::fdgate::{Line10, MARK_STREAM};
use crate::slimits::{self as sl, WHY_POOL, WHY_SHARE};

impl Worker {
    /// The memory levels' stream limit of one worker at memory level `l` (Worker::max_streams). With --stream-pool none:
    /// fd_more takes the stream from the pool instead (sl_short), with the same total.
    pub(super) fn streams_cap(l: usize) -> usize {
        if sl::global().is_some_and(|s| s.pool) {
            usize::MAX
        } else {
            mem::max_streams(&mem::STAGES[l])
        }
    }

    /// The streams of connection `ci` (0: no such connection)
    fn sl_streams(&self, ci: u32) -> u32 {
        self.clients.slots.get(ci as usize).and_then(|s| s.1.as_ref()).map_or(0, |c| c.streams.len()) as u32
    }

    /// --stream-share: the cap for a connection now (the connections of all workers summed at most every CONNS_MS, at
    /// the loop turn's time: no clock read)
    fn sl_cap(&self, s: &sl::Slimits) -> u32 {
        let cell = s.cell(self.idx);
        let now = metrics::ms_at(self.now);
        let at = cell.conns_at.load(Relaxed);
        if at == 0 || now.saturating_sub(at) >= sl::CONNS_MS {
            let c: usize = self.peers.iter().map(|p| p.load.load(Relaxed)).sum();
            cell.conns.store(c.min(u32::MAX as usize) as u32, Relaxed);
            cell.conns_at.store(now.max(1), Relaxed);
        }
        sl::share_cap(self.fdg.limit(), self.fdg.granted(), cell.conns.load(Relaxed))
    }

    /// --stream-pool: the pool's size and block at this worker's memory level
    fn sl_pool(&self, s: &sl::Slimits) -> (u32, u32) {
        #[cfg(test)]
        if let p @ 1.. = s.test_per.load(Relaxed) {
            let n = s.cells.len() as u32;
            let total = sl::pool_total(p, n);
            return (total, sl::pool_block(total, n));
        }
        s.pool_at[self.lvl]
    }

    fn sl_live(&self) -> u32 {
        (self.targets.slots.len() - self.targets.free.len()) as u32
    }

    /// fd_more, for the CONNECT of stream `ti` (in the slab already, not yet in its connection's streams) before any
    /// DNS or socket work: true = refused (fd_short sends the CLOSE). --stream-share while its mark is set: the
    /// connection holds SHARE_MIN streams or more and at least its cap. --stream-pool: this worker's live streams are
    /// more than it holds of the pool, and the pool has no unit left.
    #[cold]
    #[inline(never)]
    pub(super) fn sl_short(&mut self, ti: u32) -> bool {
        let Some(s) = sl::global() else { return false };
        let Some(t) = self.targets.slots.get(ti as usize).and_then(|x| x.1.as_ref()) else { return false };
        let mut why = 0;
        if self.sl_share_hit(s, t.client, 0) {
            why = WHY_SHARE;
        }
        let cell = s.cell(self.idx);
        if s.pool {
            self.max_streams = usize::MAX; // (see the head of this file)
        }
        if why == 0 && s.pool {
            let (live, have) = (self.sl_live(), cell.have.load(Relaxed));
            let (total, block) = self.sl_pool(s);
            if s.granted() > total {
                // the total went down (a higher memory level): no stream from the units held, and the unused ones go
                // back, until the count is under the new total
                let spare = have.saturating_sub(live.saturating_sub(1)); // (live counts the stream in hand: refused)
                if spare > 0 {
                    s.give(spare);
                    cell.have.store(have - spare, Relaxed);
                }
                why = WHY_POOL;
            } else if live > have {
                let need = live - have;
                match s.grab(need.max(block), need, total) {
                    0 => why = WHY_POOL,
                    got => cell.have.store(have + got, Relaxed),
                }
            }
        }
        cell.why.store(why, Relaxed);
        why != 0
    }

    /// --stream-share while its mark is set: connection `ci` holds SHARE_MIN or more streams besides `own` (the stream
    /// in hand when it is already in the connection's streams) and at least the cap
    fn sl_share_hit(&self, s: &sl::Slimits, ci: u32, own: u32) -> bool {
        if !s.share || self.fdg.marks() & MARK_STREAM == 0 {
            return false;
        }
        let n = self.sl_streams(ci).saturating_sub(own);
        n >= sl::SHARE_MIN && n >= self.sl_cap(s)
    }

    /// fd_grab_t, for a connect attempt (or the UDP socket) of stream `ti`, in hold mode: true = refused (fd_short
    /// sends the CLOSE). The CONNECT itself was judged in fd_more, but the streams of one read are all judged before
    /// any of them takes an fd (an IP literal or a cached name connects at the end of the batch), and the mark moves
    /// only when fds are taken: so the rule judges a stream's first attempt again, when its fd is taken. Later
    /// attempts (the next address) belong to a stream that was let in.
    #[cold]
    #[inline(never)]
    pub(super) fn sl_attempt_short(&self, ti: u32) -> bool {
        let Some(s) = sl::global() else { return false };
        let t = self.targets.slots.get(ti as usize).and_then(|x| x.1.as_ref());
        let Some(t) = t.filter(|_| s.share && self.fdg.marks() & MARK_STREAM != 0) else {
            s.cell(self.idx).why.store(0, Relaxed); // (the rule is off or its mark is not set: no lookup)
            return false;
        };
        // (not a stream that was let in: a later address, the final DNS answer after its early addresses failed, TCP
        // or UDP (err set), or an upstream proxy's next try (proxy_hs idx past 0, where proxy_connect resets attempt
        // and err))
        let retry = self.proxy_hs.get(ti as usize).and_then(Option::as_ref).is_some_and(|h| h.idx > 0);
        if t.attempt != 0 || !t.conn.is_empty() || t.err != 0 || retry {
            s.cell(self.idx).why.store(0, Relaxed);
            return false;
        }
        let own = self.clients.slots.get(t.client as usize).and_then(|x| x.1.as_ref()).is_some_and(|c| c.streams.get(&t.sid) == Some(&ti));
        let hit = self.sl_share_hit(s, t.client, own as u32);
        s.cell(self.idx).why.store(if hit { WHY_SHARE } else { 0 }, Relaxed);
        hit
    }

    /// fd_short: the reason sl_short or sl_attempt_short gave for the stream in hand (0: none), taken
    pub(super) fn sl_why(&self) -> u8 {
        sl::global().map_or(0, |s| s.cell(self.idx).why.swap(0, Relaxed))
    }

    /// fd_short for a stream that sl_short refused: CLOSE 0x49, counter, stream log, and for --stream-share the
    /// warning (rate-limited)
    #[cold]
    #[inline(never)]
    pub(super) fn sl_refused(&mut self, ti: u32, why: u8) {
        if why == WHY_SHARE {
            self.stats.refuse_stream_share.bump();
            if self.fdg.log_due(Line10::StreamShare) {
                let ci = self.targets.at(ti).client;
                let n = self.sl_streams(ci);
                let cap = sl::global().map_or(0, |s| self.sl_cap(s));
                metrics::log_nowait(format!(
                    "finalwisp: --stream-share: a connection with {n} streams got no new one (the cap is {cap} streams per \
                     connection now; {}); connections with fewer streams go on. Fix: raise the open-file limit and restart \
                     ({FIX}) (counted as refuse_stream_share; {EVERY})",
                    self.fd_state()
                ));
            }
            if !self.streamlog.is_empty() {
                self.slog_why(ti, SWhy::Limit, "stream_share");
            }
        } else {
            debug_assert_eq!(why, WHY_POOL);
            self.stats.refuse_streams.bump(); // (the counter of the per-worker limit it replaces)
            if !self.streamlog.is_empty() {
                self.slog_why(ti, SWhy::Pressure, "stream_cap");
            }
        }
        self.fail_target(ti, CLOSE_THROTTLED);
    }

    /// fd_trim (an fd put in hold mode, the idle sweep): --stream-pool gives back what is above one unused block, past
    /// two blocks (as the fd count does); all of it when the worker holds no stream or at the idle sweep's keep
    #[cold]
    #[inline(never)]
    pub(super) fn sl_trim(&mut self, idle: bool) {
        let Some(s) = sl::global().filter(|s| s.pool) else { return };
        self.max_streams = usize::MAX; // (see the head of this file)
        let cell = s.cell(self.idx);
        let (live, have) = (self.sl_live(), cell.have.load(Relaxed));
        let block = self.sl_pool(s).1;
        let keep = if live == 0 { 0 } else { block };
        let slack = have.saturating_sub(live);
        if slack > keep && (idle || live == 0 || slack >= 2 * block) {
            s.give(slack - keep);
            cell.have.store(have - (slack - keep), Relaxed);
        }
    }

    /// Tests: the pool units this worker holds
    #[cfg(test)]
    pub(super) fn sl_have(&self) -> u32 {
        sl::global().map_or(0, |s| s.cell(self.idx).have.load(Relaxed))
    }
}
