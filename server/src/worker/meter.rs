//! 60.25 C10b upload limits: one metering point per client read (Worker::read_client) for a per-connection token bucket
//! (--upload-rate) and a per-client-key share leased from the C3b IpTable (--upload-rate-per-ip). A client whose
//! allowance is spent is not read (Client::lpaused; TCP flow control holds its sender) until Worker::meter_timers
//! resumes it. Off (Worker::meter false): no Meter exists and the read path pays two not-taken branches.

use super::*;

/// A paused client is woken only when it may read at least this much (or the whole free rbuf if smaller): no storm
/// of tiny reads at a low rate.
pub(super) const MIN_ROOM: usize = 4096;
/// An unread per-IP lease goes back to the key's bucket after this long without a successful read (checked at the idle
/// sweep: in practice 1-3 s after the last read), so idle connections do not hold the key's tokens.
const LEASE_IDLE_MS: u64 = 1000;

/// Per client slot (Worker::meters, beside the slab: no Client field, 60.22).
#[derive(Default, Clone)]
pub(super) struct Meter {
    own: u64,                 // milli-bytes left in the per-connection bucket (rate x ms)
    at: u64,                  // now_ms64 of the last refill (= last read attempt)
    rd: u64,                  // now_ms64 of the last successful read (idle-lease reclaim)
    pub(super) lease: u64,    // bytes leased from the key's per-IP bucket and not read yet
    boot: u64,                // bytes read before the per-IP key was known (charged to the key once it is: trusted proxy)
    ticket: Option<u32>,      // place in the key's starved-first queue (clientip::Upq)
    pub(super) blocked: bool, // paused by the limiter since the last idle sweep (count_stalls: not a stall)
    keyed: bool,              // the per-IP key was seen (boot charged)
}

/// ms until the next lwait scan at `lscan`, 1..=TIMER_TICK_MS (Worker::run's epoll timeout while clients are paused)
#[cold]
#[inline(never)]
pub(super) fn tick_left(lscan: u64) -> i32 {
    (lscan.saturating_sub(now_ms64()) as i32).clamp(1, TIMER_TICK_MS)
}

/// Monotonic ms since the first call (u64: no wrap; the per-IP table keeps its u32 clock and STALE_MS rule).
pub(super) fn now_ms64() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

impl Worker {
    /// a client was adopted at slot `i`: a full bucket, no lease. `keyed`: a direct peer charged at accept (its key is
    /// final: nothing to count as bootstrap)
    #[cold]
    #[inline(never)]
    pub(super) fn meter_adopt(&mut self, i: u32, keyed: bool) {
        let i = i as usize;
        if self.meters.len() <= i {
            self.meters.resize(i + 1, Meter::default());
        }
        let own = self.cfg.upload_rate.map_or(0, |(_, b)| b.saturating_mul(1000));
        let now = now_ms64();
        self.meters[i] = Meter { own, at: now, rd: now, keyed, ..Meter::default() };
    }

    /// 60.25 C10b the client's per-IP key is final (Worker::handle_http after client_ip, whatever its outcome; a direct
    /// peer at adopt): bytes read before it are charged to the key now, once, and counting stops (review: a client
    /// that closes right after the upgrade still pays; review: a client that never gets a key stops counting)
    #[cold]
    #[inline(never)]
    pub(super) fn meter_keyed(&mut self, ci: u32) {
        let Some(m) = self.meters.get_mut(ci as usize) else { return };
        if std::mem::replace(&mut m.keyed, true) {
            return;
        }
        let boot = std::mem::take(&mut m.boot);
        let key = self.peers_of.get(ci as usize).and_then(Option::as_ref).and_then(|p| p.key);
        let table = self.cfg.clientip.as_ref().and_then(|c| c.table.as_ref()).filter(|t| t.has_upload());
        if let (Some(t), Some(k), true) = (table, key, boot > 0) {
            t.charge_bytes(k, boot);
        }
    }

    /// a client ends: give back the unread lease (one release site, close_client; before `unload` drops the key)
    #[cold]
    #[inline(never)]
    pub(super) fn meter_close(&mut self, ci: u32, key: Option<clientip::IpKey>) {
        let Some(m) = self.meters.get_mut(ci as usize) else { return };
        let lease = std::mem::take(&mut m.lease);
        let ticket = m.ticket.take();
        if let (Some(k), true) = (key, lease > 0 || ticket.is_some()) {
            if let Some(t) = self.cfg.clientip.as_ref().and_then(|c| c.table.as_ref()) {
                t.give_bytes(k, lease, ticket); // exactly once: both were taken out of the Meter above
            }
        }
    }

    /// 60.25 (idle sweep, after count_stalls) a new stall interval starts: clear `blocked`; unread leases of connections
    /// without a successful read for LEASE_IDLE_MS go back to their key (review: outstanding leases add to what a
    /// key can read in a short window)
    #[cold]
    #[inline(never)]
    pub(super) fn meter_sweep(&mut self) {
        let t = self.cfg.clientip.as_ref().and_then(|c| c.table.as_ref()).filter(|t| t.has_upload());
        let now = now_ms64();
        for (i, m) in self.meters.iter_mut().enumerate() {
            m.blocked = false;
            let Some(t) = t else { continue };
            if m.lease == 0 || now.saturating_sub(m.rd) < LEASE_IDLE_MS {
                continue;
            }
            if let Some(k) = self.peers_of.get(i).and_then(Option::as_ref).and_then(|p| p.key) {
                t.give_bytes(k, std::mem::take(&mut m.lease), None);
            }
        }
    }

    /// 70.08 (count_stalls) client slot `i` was paused by the limiter during this sweep interval: our doing, not a stall
    pub(super) fn meter_blocked(meters: &[Meter], i: usize) -> bool {
        meters.get(i).is_some_and(|m| m.blocked)
    }

    /// resume paused clients whose time came. Scanned at most once per TIMER_TICK_MS (run() wakes at that tick while
    /// `lwait` is not empty). deliberate: a swap_remove list scanned per tick, as Worker::connecting (a heap if many
    /// thousands of clients per worker are paused at once). Entries of clients that closed meanwhile are dropped.
    #[cold]
    #[inline(never)]
    pub(super) fn meter_timers(&mut self) {
        let now = now_ms64();
        if now < self.lscan {
            return;
        }
        self.lscan = now + TIMER_TICK_MS as u64;
        let mut i = 0;
        while i < self.lwait.len() {
            let (ci, g, due) = self.lwait[i];
            let live = self.clients.get(ci, g).is_some_and(|c| c.lpaused && !c.dead);
            if live && due > now {
                i += 1;
                continue;
            }
            self.lwait.swap_remove(i);
            if live {
                self.clients.at(ci).lpaused = false;
                self.ready.push(tok(K_CLIENT, ci, g));
            }
        }
    }
}

/// Bytes client `ci` may read now, at most `space`. 0 = spent: `c.lpaused` is set and the client is listed in `lwait`
/// with the time its allowance reaches MIN_ROOM (a free function over disjoint Worker fields: read_client holds `c`).
#[allow(clippy::too_many_arguments)]
#[cold]
#[inline(never)]
pub(super) fn room(
    meters: &mut [Meter],
    lwait: &mut Vec<(u32, u32, u64)>,
    cfg: &Config,
    peers_of: &[Option<clientip::Peer>],
    stats: &metrics::Stats,
    c: &mut Client,
    ci: u32,
    g: u32,
    space: usize,
) -> usize {
    debug_assert!(space > 0, "0 means paused: a caller with no free rbuf would never be resumed");
    let Some(m) = meters.get_mut(ci as usize) else { return space };
    let now = now_ms64();
    let need = MIN_ROOM.min(space) as u64;
    let mut room = space as u64;
    let mut wait = 0u64;
    let dt = now.saturating_sub(m.at);
    m.at = now; // also the last read attempt (meter_reclaim)
    if let Some((rate, burst)) = cfg.upload_rate {
        m.own = m.own.saturating_add(dt.saturating_mul(rate)).min(burst.saturating_mul(1000));
        room = room.min(m.own / 1000);
        if room < need {
            wait = (need * 1000 - m.own).div_ceil(rate).max(1);
        }
    }
    let table = cfg.clientip.as_ref().and_then(|c| c.table.as_ref()).filter(|t| t.has_upload());
    let key = peers_of.get(ci as usize).and_then(Option::as_ref).and_then(|p| p.key);
    let mut ip_wait = false;
    if let (Some(t), Some(k)) = (table, key) {
        // (review: no lease while the connection's own bucket blocks it: siblings on the key keep those tokens)
        // the key's share for one connection (IpTable); None = the key is not in the table: fail open (Q11), nothing
        // leased, so nothing synthetic is ever given back
        if room >= need {
            // (60.25 merged A/B) a lease that covers this read only in part is topped up to the read when nobody waits
            // and the bucket can pay (else 0: the read stops at the lease edge as before)
            let got = if m.lease < need {
                t.take_bytes(k, need, &mut m.ticket)
            } else if m.lease < room {
                Some(t.top_up_bytes(k, m.lease, room))
            } else {
                Some(0)
            };
            if let Some(got) = got {
                m.lease += got;
                room = room.min(m.lease);
                if room < need {
                    ip_wait = true;
                    wait = wait.max(1); // the key's bucket or queue: try again at the next tick (meter_timers)
                }
            }
        }
    }
    if room < need {
        stats.upl_pauses.bump();
        if ip_wait {
            stats.upl_ip_waits.bump();
        }
        m.blocked = true;
        c.lpaused = true;
        lwait.push((ci, g, now + wait));
        return 0;
    }
    room as usize
}

/// `n` bytes were read (n <= the room given). Out of line: the OFF read path keeps only the branch.
#[cold]
#[inline(never)]
pub(super) fn debit(meters: &mut [Meter], ci: u32, n: usize) {
    if let Some(m) = meters.get_mut(ci as usize) {
        m.rd = m.at; // a successful read (at = this read's attempt time, set by room: no clock read here)
        if !m.keyed {
            m.boot = m.boot.saturating_add(n as u64);
        }
        m.own = m.own.saturating_sub(n as u64 * 1000);
        m.lease = m.lease.saturating_sub(n as u64);
    }
}
