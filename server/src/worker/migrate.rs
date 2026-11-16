//! 60.64 / 60.74 --auto-balance (off by default): a live connection moves to another worker.
//!
//! Why: SO_REUSEPORT places a connection by a hash at accept, when nothing is known about its load. Two long-lived
//! connections that become CPU-heavy later can share one worker thread while other threads idle (notes 60.64, the
//! prototype, and 60.74, stage 2). The observer thread (crate::balance) finds a worker that is thread-bound while another one
//! idles and asks the bound one to hand over one connection. This file is the hand-over.
//!
//! One owner at any time. The source takes the connection out of its tables at a point where nothing of it is in
//! flight inside the worker (`mig_quiet`), removes its fds from its epoll set, frees the slab slots (the generation
//! goes up, so every token and list entry that still names the old slots is dropped by the checks of 60.05 H1) and
//! pushes one boxed value into the destination's inbox. The destination inserts it, registers the fds (an
//! edge-triggered ADD reports the readiness of the moment) and runs the client once. A byte is either in a kernel
//! socket or pipe, or in a buffer that moved: nothing is copied, nothing is read twice, one thread writes a socket.
//!
//! Exhaustive by construction: `client_rest`, `target_rest` and `inventory` name every field of Client, Target and
//! Worker without `..`. A new field does not compile until it is given a class here: moves as it is, rebuilt by the
//! destination, or must be at rest for a move.
//!
//! Off: no Worker field is used but `mig` (None), the inbox word stays 0, and inbox_ready tests it once per wake.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Inbox::mig: what the observer (or a sending worker) asks of a worker, the worker's answer, and connections on
/// their way to it.
#[derive(Default)]
pub struct MigBox {
    /// M_* bits (bits 0-7), the other worker's index (M_TO, 16 bits) and the request's number (M_SEQ, 32 bits); the
    /// worker takes it with swap(0). One request at a time: the observer replaces a request that was not taken.
    pub cmd: AtomicU64,
    /// the answer to the request numbered M_SEQ: seq << 32 | R_* << 24 | value
    pub out: AtomicU64,
    #[allow(clippy::vec_box)] // (a Moved is some 600 bytes and goes on as a Box: export -> here -> import, never copied)
    pub moves: Mutex<Vec<Box<Moved>>>,
    /// 60.74 the worker's last census (M_CENSUS); the observer takes it once the answer carries its number
    pub snap: Mutex<Option<Census>>,
    /// 60.74 the socket cookie of the connection that left at the last M_MOVE (0: none or unknown)
    pub moved: AtomicU64,
    /// the number of the M_MOVE request that `moved` answers
    pub moved_seq: std::sync::atomic::AtomicU32,
}

/// 60.74 a census: one worker's traffic at one moment, for the observer's windows (a window's value is the difference
/// of two of them). `bytes`: bytes read from clients + bytes sent to clients, of every connection the worker had (the
/// closed ones too: Mig::closed_tx). `conns`: per connection, its socket cookie (it follows the socket from worker to
/// worker), the kernel's bytes (acked + received) and data segments (in + out); empty when `many`.
#[derive(Debug, Clone)]
pub struct Census {
    pub seq: u32,
    pub at: Instant,
    pub bytes: u64,
    pub conns: Vec<(u64, u64, u32)>,
    /// more than CENSUS_MAX connections: no per-connection entries
    pub many: bool,
    /// connections that moved to or from this worker so far (Mig::moves; an accept is not a move, its bytes count
    /// from 0): a window in which this number changed on
    /// a worker has a connection's whole byte count in it, or misses it, and is not a measurement
    pub moves: u64,
}

/// connections wait in `moves` (set by the sender, after its push)
pub const M_IMPORT: u64 = 1;
/// a census (MigBox::snap); with M_MOVE or M_BACK in the same word it is taken first (the connection is in it)
pub const M_CENSUS: u64 = 2;
/// hand one busy connection to worker M_TO, if at least two moved bytes since the census before
pub const M_MOVE: u64 = 4;
/// hand the connection under trial to worker M_TO (back to the source; or, at a keep, to the destination again)
pub const M_BACK: u64 = 16;
/// the trial is over (kept, or handed back): forget it (handled before the other bits of the same word)
pub const M_END: u64 = 32;
pub const M_TO_SHIFT: u32 = 8;
pub const M_SEQ_SHIFT: u32 = 24;

/// answers (MigBox::out)
pub const R_MOVED: u64 = 1;
/// fewer than two busy connections, or the worker is not at rest (memory level, shutdown): nothing to move
pub const R_NONE: u64 = 2;
/// the connection holds something that cannot move now (a lookup in flight): ask again
pub const R_BUSY: u64 = 3;
/// M_BACK: the connection is gone (closed)
pub const R_GONE: u64 = 5;
/// M_CENSUS done (alone; with M_MOVE / M_BACK their answer says it is done)
pub const R_NOTED: u64 = 6;

pub fn request(bits: u64, to: usize, seq: u32) -> u64 {
    bits | ((to as u64 & 0xffff) << M_TO_SHIFT) | ((seq as u64) << M_SEQ_SHIFT)
}
pub fn answer(out: u64) -> (u32, u64, u64) {
    ((out >> 32) as u32, (out >> 24) & 0xff, out & 0xff_ffff)
}

/// Test hook (cargo feature pooltest only, never in a release): main sets it from FW_FORCE_MOVE; every worker then
/// moves one connection at rest every that many loop turns (Worker::mig_force)
#[cfg(feature = "pooltest")]
pub static FORCE_EVERY: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// deliberate: a census is one getsockopt per connection; a worker with more connections than this is not asked to
/// move one (one connection of thousands is not what binds it)
pub const CENSUS_MAX: usize = 4096;

/// A connection between two workers: the client record, its streams, and its entries of the per-slot side tables.
pub struct Moved {
    c: Client,
    peer: Option<clientip::Peer>,
    log: Option<connlog::ConnLog>,
    meter: Option<meter::Meter>,
    far: bool,
    /// v1.3.1 K1: its keepalive idle time was spread already (Worker::ka_spread)
    ka: bool,
    streams: Vec<MovedT>,
    /// a move of a trial: its traffic rate (bytes per second) before the move (0: not known), and the number of the
    /// request that moved it; the worker it goes to notes it as the connection under trial (M_BACK)
    before: Option<(u64, u32)>,
}

impl Moved {
    #[cfg(test)]
    pub(super) fn for_trial(mut self: Box<Self>, rate: u64, seq: u32) -> Box<Self> {
        self.before = Some((rate, seq));
        self
    }

    /// Its counted fds (60.57 A2): the client socket, the splice pipe's ends, every stream's socket and connect
    /// attempts. Between the two workers these units of the fd allowance belong to this value: the source gave them up
    /// (fd_send) without returning them to the process count (FdGate::granted), the destination takes them (fd_recv).
    /// So the count that the limit, the reserve and the marks of --fd-admission / --conn-share act on never goes
    /// below the open fds; only the per-worker sums (the `fds` gauge, FdGate::used for log lines) are short meanwhile.
    pub(super) fn fds(&self) -> u32 {
        let mut n = 1 + self.c.pipe.iter().filter(|&&p| p >= 0).count() as u32;
        for s in &self.streams {
            n += (s.t.fd >= 0) as u32 + s.t.conn.len() as u32;
        }
        n
    }
}

struct MovedT {
    t: Target,
    old: u64, // its token on the source (the client's parked lists name it)
    log: Option<streamlog::StreamLog>,
    pace: Option<pace::PaceSt>,
    lock: Option<(rcvlock::LockSt, bool)>,
}

/// per worker, made at the first request (None: --auto-balance never acted here)
#[derive(Default)]
pub(super) struct Mig {
    /// per client slot at the last census: generation + 1 (0 = none), bytes, data segments
    seen: Vec<(u32, u64, u32)>,
    seen_at: Option<Instant>,
    /// 60.74 bytes sent to the clients this worker closed since this record was made (a census counts them: a
    /// connection that closes inside a window keeps its bytes in the window)
    pub(super) closed_tx: u64,
    /// 60.74 connections that moved here or away (Census::moves)
    moves: u64,
    /// the connection that came for a trial: (slot, generation, bytes per second before)
    pub(super) trial: Option<(u32, u32, u64)>,
    /// the number of the request that moved it here. A move that a stalled worker makes after its request was given
    /// up (balance: Cancel) carries an older number and never replaces the trial of a newer one.
    trial_seq: u32,
    /// the last sweep's (time, thread CPU ns): mig_report
    cpu: Option<(Instant, u64)>,
    #[cfg(any(feature = "pooltest", test, fuzzing))]
    force: (u32, u32), // forced moves: turns since the last one, the next slot to try
    /// forced moves: the connections that arrived from another worker in this loop turn. The hook leaves them for one
    /// turn: the readiness an ADD reports is read by the next epoll_wait, and a connection that left again before it
    /// would never have its target sockets read (two workers handing one connection back and forth: 190,000 moves in
    /// 4 s and no byte delivered). Nothing is lost by such a move (the next ADD reports the readiness again); the
    /// observer's rule keeps a connection for seconds (balance::PIN, SETTLE).
    #[cfg(any(feature = "pooltest", test, fuzzing))]
    fresh: Vec<(u32, u32)>,
}

/// Client: every field, by class. true = at rest (may move now).
fn client_rest(c: &Client) -> bool {
    let Client {
        // ---- moves as it is: the socket and what the kernel keeps for it (kTLS keys, buffers, TCP state)
        fd: _,
        ktls_on: _,
        ktls: _,
        tx_left: _,
        rx_left: _,
        rekey_at: _,
        ku: _,
        ku_asked: _,
        notified: _,
        local: _,
        lowat_off: _,
        tx_bytes: _,
        rate_check_at: _,
        rx_mark: _,
        gone_ack: _,
        rstall: _,
        wblock: _,
        // ---- moves as it is: input (a partial frame stays in rbuf, a fragmented message in frag)
        rbuf: _,
        rpos: _,
        rlen: _,
        need: _,
        frag: _,
        rfull: _,
        active: _,
        rdhup: _,
        paused: _,  // (flag only: after_write of its target resumes it)
        opaused: _, // (flag only: flush_dirty resumes it)
        // ---- moves as it is: output, in order (obuf, the bulk lane, the splice pipe with what is in it)
        obuf: _,
        ohead: _,
        pipe: _,
        splice: _,
        splice_pending: _,
        splice_at: _,
        bulk: _,
        bhead: _,
        bulk_sent: _,
        bulk_ends: _,
        bulk_boundary: _,
        // ---- moves as it is: credit and accounting
        hs_credit: _,
        cv: _,
        pend: _, // (the destination adds it to its pend_total / pend_clients)
        over: _,
        hp_sweeps: _,
        hs_sweeps: _,
        starve_at: _,
        starve_room: _,
        starve_since: _,
        starve_b: _,
        starve_read: _,
        drain_seen: _,
        // ---- rebuilt by the destination (they name slots or lists of the worker)
        streams: _,
        blocked: _,
        blocked_bulk: _,
        bulk_waiting: _,
        proxy_target: _,
        readable: _, // (set: one read probes the socket)
        dirty: _,    // (set: one flush)
        // ---- must be at rest
        state,
        dead,
        closing,
        tls,       // (the handshake: rustls state and Worker::tls_deadlines)
        challenge, // (WaitInfo only)
        lingering, // (Worker::lingering)
        starve,    // (Worker::starved)
        starve_due,
        mpaused, // (Worker::pend_paused)
        hpaused,
        lpaused, // (Worker::lwait)
        saved,   // (socket caps of a memory level: the worker must be at level 0 too)
        #[cfg(test)]
            send_log: _,
        #[cfg(test)]
            ku_refuse: _,
    } = c;
    matches!(state, CState::Open | CState::Wsproxy)
        && !dead
        && !closing
        && tls.is_none()
        && challenge.is_none()
        && !lingering
        && *starve == 0
        && !starve_due
        && !mpaused
        && !hpaused
        && !lpaused
        && *saved == (0, 0)
}

/// Target: every field, by class. true = at rest.
fn target_rest(t: &Target) -> bool {
    let Target {
        // ---- moves as it is
        fd: _,
        sid: _,
        port: _,
        addrs: _,
        attempt: _,
        pend: _,
        phead: _,
        since: _,
        rdhup: _,
        raw: _,
        wrote_since_read: _,
        urg: _,
        lane_read: _,
        bulk: _,
        bulk_end: _,
        conn: _, // (connect attempts in flight: their fds are registered again)
        next_try: _,
        err: _,
        tfo_fd: _,
        tfo_sent: _,
        deadline: _,
        udp: _,
        credit: _,
        allow: _,
        acct: _,
        keepalive: _,
        upkts: _,
        ubytes: _,
        umax: _,
        cv: _, // (its pool bytes go back to the source's pool and are taken from the destination's: credit::Stream::rehome)
        local: _,
        blocked: _, // (parked: stays in its client's list under the new token, or is resumed)
        // ---- rebuilt by the destination
        client: _,
        cgen: _,
        cidx: _,
        capped: _,
        moved: _,
        // ---- must be at rest
        state,    // (Resolving: the answer is addressed to the source's inbox and slot)
        dns_more, // (the late answer, as above)
        saved,
    } = t;
    // (with --upstream also every stream that is not open yet: mig_quiet, which knows the configuration)
    *state != TState::Resolving && !dns_more && *saved == (0, 0)
}

/// Worker: every field, by class (compile-time only: a new field must be classed here before the crate builds).
#[allow(dead_code)]
fn inventory(w: &Worker) {
    let Worker {
        // ---- the worker's own (not per connection)
        cfg: _,
        ep: _,
        lfd: _,
        inbox: _,
        idx: _,
        peers: _,
        dns_tx: _,
        next_scan: _,
        next_sweep: _,
        ip_sweep: _,
        outbox: _,
        logline: _,
        conn_seq: _,
        refused_win: _,
        sref_win: _,
        proxy_addrs: _,
        pipe_retry_at: _,
        accept_retry: _,
        dns_cache: _,
        he_lost: _,
        next_linger: _,
        starve_log_at: _,
        udp_buf: _,
        lvl: _,
        capl: _,
        st: _,
        accept_paused: _,
        stop_seen: _,
        stop_scan_at: _,
        floor0: _,
        pend_cap: _,
        pend_over_sweeps: _,
        l3_mark: _,
        l3_sweeps: _,
        max_streams: _,
        rbuf_max: _,
        win: _,
        bulk_at: _,
        stats: _,
        ufd: _,
        rx_total: _,
        meter: _,
        lscan: _,
        now: _,
        fdg: _,
        fd_block: _,
        spare: _,
        fd_mask: _,
        fd_pool: _,
        mig: _,
        bd: _, // 60.63 E: its per-connection entries are counted again (by_client, by_dest) or keyed by generation (dst, last); a worker in its hold mode is not at rest (mig_quiet)
        // ---- the slabs: the records leave (mig_export) and arrive (mig_import)
        clients: _,
        targets: _,
        // ---- per-slot side tables: the entry travels (Moved / MovedT)
        peers_of: _,
        connlog: _,
        streamlog: _,
        meters: _,
        cpace_st: _,
        rcvlock: _,
        splice_far: _,
        ka_spread: _, // v1.3.1 K1 (its socket keeps the idle time; the flag travels: Moved::ka)
        sfds: _,      // (published back at the source, noted again at the destination)
        // ---- sums over the worker's connections: the source subtracts, the destination adds
        pend_total: _,
        pend_clients: _,
        starve_pool: _,
        fd_have: _, // (with Stats::fds; Inbox::load likewise)
        // ---- lists of (slot, generation): entries of a connection that left are stale and skipped by generation
        dirty: _,
        ready: _,
        ready_spare: _,
        tls_deadlines: _,
        sdone: _, // (lines of streams already closed: written by the source)
        // ---- lists a moving connection must not be on (mig_quiet / client_rest / target_rest), or is taken off
        dead: _,
        connecting: _, // (taken off, listed again at the destination)
        deferred: _,   // (Resolving)
        lingering: _,
        starved: _,
        pend_paused: _,
        lwait: _,
        proxy_hs: _,     // (--upstream: a stream that is not open yet, mig_quiet)
        dns_inflight: _, // (Resolving)
        pending: _,      // (PROXY header: not a client yet)
        up_bufs: _,      // (nothing staged: up_n is 0)
        up_n: _,
        up_total: _,
        #[cfg(test)]
            up_writevs: _,
    } = w;
}

/// A worker's CPU share over its last sweep period, per mille. `last`: the sweep before (time, thread CPU ns). The
/// wall time counts at most one period: a worker sweeps on time while its loop turns, so a longer gap (or no sweep
/// before: the worker's first) was sleep without clients, and what it used since then it used in this period.
pub(super) fn sweep_share(last: Option<(Instant, u64)>, now: Instant, cpu: u64) -> u64 {
    let period = IDLE_SWEEP_MS * 1_000_000;
    let (wall, used) = match last {
        Some((at, was)) => ((now.saturating_duration_since(at).as_nanos() as u64).min(period), cpu.saturating_sub(was)),
        None => (period, cpu),
    };
    used.saturating_mul(1000) / wall.max(1)
}

fn ep_del(ep: RawFd, fd: RawFd) {
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
}

impl Worker {
    /// Connection `ci` (generation `cg`) can leave now: the worker is at memory level 0 without socket caps and not
    /// shutting down, nothing is staged, and neither the client nor one of its streams holds something that names
    /// this worker (client_rest, target_rest).
    pub(super) fn mig_quiet(&mut self, ci: u32, cg: u32) -> bool {
        if self.lvl != 0 || self.st.sock_cap != 0 || self.up_n != 0 || self.inbox.stop.load(Relaxed) != 0 {
            return false;
        }
        if self.fd_mask & bounds::HOLD_BOUNDS != 0 {
            return false; // 60.63 E a mark is set (hold mode): the host is short of something, as at a memory level
        }
        let Some(c) = self.clients.get(ci, cg) else { return false };
        if !client_rest(c) {
            return false;
        }
        // (a Wsproxy client's raw stream is named by slot and generation: one that is gone is not at rest; today
        // target_eof closes such a client at once, so this is the same check its other readers make)
        let proxy = self.clients.slots[ci as usize].1.as_ref().unwrap().proxy_target;
        if proxy.is_some_and(|(ti, tg)| self.targets.get(ti, tg).is_none()) {
            return false;
        }
        let c = self.clients.slots[ci as usize].1.as_ref().unwrap();
        let slots = &self.targets.slots;
        // 60.27 C6 with --upstream a stream holds a side entry (Worker::proxy_hs: the destination the proxy is asked
        // for, the handshake's state) from its first connect attempt until it is open: such a stream is not at rest
        let opening_ok = self.cfg.upstream.is_none();
        c.streams.values().copied().chain(c.proxy_target.map(|(ti, _)| ti)).all(|ti| {
            slots.get(ti as usize).and_then(|s| s.1.as_ref()).is_some_and(|t| target_rest(t) && (opening_ok || t.state == TState::Open))
        })
    }

    /// Take connection `ci` out of this worker (the caller checked mig_quiet). Its fds stay open and counted: the
    /// units of the fd allowance go with them, as with a --balance hand-over. Inbox::load is the caller's (the
    /// destination's goes up before ours goes down, so the sum main reads at shutdown is never short).
    pub(super) fn mig_export(&mut self, ci: u32) -> Box<Moved> {
        let mut fds = 1u32;
        let tis: Vec<u32> = {
            let c = self.clients.at(ci);
            c.streams.values().copied().chain(c.proxy_target.map(|(ti, _)| ti)).collect()
        };
        let mut streams = Vec::with_capacity(tis.len());
        for ti in tis {
            self.unlist(ti);
            let tg = self.targets.gen(ti);
            let old = tok(K_TARGET, ti, tg);
            let log = self.slog_out(ti);
            let pace = self.pace_out(ti, tg & 0x3fff_ffff);
            let lock = self.rcvlock_out(ti, tg & 0x3fff_ffff);
            let t = self.targets.remove(ti).expect("60.64 a stream of the client");
            if t.fd >= 0 {
                ep_del(self.ep, t.fd);
            }
            for &fd in &t.conn {
                ep_del(self.ep, fd);
            }
            fds += (t.fd >= 0) as u32 + t.conn.len() as u32;
            self.pend_total -= t.acct;
            if let Some(s) = t.cv.as_ref() {
                self.starve_pool += s.extra; // 20.30 (the destination takes them from its pool)
            }
            streams.push(MovedT { t, old, log, pace, lock });
        }
        self.stats.streams.set((self.targets.slots.len() - self.targets.free.len()) as u64);
        if self.fd_mask & crate::fdgate::MARK_SHARE != 0 {
            self.sfd_end(ci); // 60.57 C what it published goes back; the destination notes its fds again
        }
        let peer = self.peers_of.get_mut(ci as usize).and_then(Option::take);
        let log = self.log_out(ci);
        let meter = self.meters.get_mut(ci as usize).map(std::mem::take);
        let far = self.splice_far.get(ci as usize).copied().unwrap_or(false);
        let ka = self.ka_spread.get_mut(ci as usize).is_some_and(std::mem::take); // (as reap_dead: the slot is free)
        let mut c = self.clients.remove(ci).expect("60.64 the client");
        ep_del(self.ep, c.fd);
        fds += c.pipe.iter().filter(|&&p| p >= 0).count() as u32;
        if c.pend > 0 {
            self.pend_clients -= 1;
        }
        c.dirty = false;
        for _ in 0..fds {
            self.fd_send(); // 60.57 A2
        }
        if let Some(m) = self.mig.as_deref_mut() {
            m.moves += 1; // 60.74
        }
        Box::new(Moved { c, peer, log, meter, far, ka, streams, before: None })
    }

    /// A connection arrives (its fds counted by the sender's allowance units, Inbox::load already raised). Returns its
    /// slot and generation; None = an fd could not be registered and the connection was reset.
    pub(super) fn mig_import(&mut self, m: Box<Moved>) -> Option<(u32, u32)> {
        let fds = m.fds();
        let Moved { mut c, peer, log, meter, far, ka, streams, before } = *m;
        self.mig.get_or_insert_with(Default::default).moves += 1; // 60.74 (also when the import fails: it was a change)
        let own = fds - 1; // 60.57 C its counted fds besides its socket: the pipe and every stream fd
        for _ in 0..fds {
            self.fd_recv(); // 60.57 A2
        }
        // the lists that name slots: emptied here, filled again under the new tokens below
        let (old_blocked, old_bulk, waiting) =
            (std::mem::take(&mut c.blocked), std::mem::take(&mut c.blocked_bulk), std::mem::take(&mut c.bulk_waiting));
        let old_proxy = c.proxy_target.take();
        c.streams.clear();
        c.readable = true;
        c.dirty = true;
        let (cfd, unix, had_pend) = (c.fd, c.local == LOCAL_UNIX, c.pend > 0);
        if self.st.sock_cap > 0 && !(unix && self.lvl == 0) && !tcp_only_local(&mut c.local, cfd, self.lvl) {
            // this worker is in a capped stage (the source was not): as adopt does for a new client
            if self.floor0 {
                c.saved = net::buf_sizes(cfd);
            }
            net::cap_bufs(cfd, mem::client_caps(self.capl));
            self.stats.cap_apply.bump();
        }
        let (ci, cg) = self.clients.insert(c);
        self.dirty.push((ci, cg));
        self.ready.push(tok(K_CLIENT, ci, cg));
        if had_pend {
            self.pend_clients += 1;
        }
        if peer.is_some() || self.cfg.want_peer || self.cfg.unix.is_some() {
            self.set_peer(ci, peer);
        }
        self.log_in(ci, log);
        if let Some(mt) = meter {
            let i = ci as usize;
            if self.meters.len() <= i {
                self.meters.resize(i + 1, meter::Meter::default());
            }
            self.meters[i] = mt;
        }
        if self.cfg.adaptive_splice {
            let i = ci as usize;
            if self.splice_far.len() <= i {
                self.splice_far.resize(i + 1, false);
            }
            self.splice_far[i] = far;
        }
        if ka {
            let i = ci as usize;
            if self.ka_spread.len() <= i {
                self.ka_spread.resize(i + 1, false);
            }
            self.ka_spread[i] = true;
        }
        let mut map: HashMap<u64, u64> = HashMap::with_capacity(streams.len());
        let mut regs: Vec<(RawFd, u64, u32)> = Vec::with_capacity(streams.len() + 1);
        regs.push((cfd, tok(K_CLIENT, ci, cg), EV_ALL));
        let mut parked: Vec<u64> = Vec::new();
        for MovedT { mut t, old, log, pace, lock } in streams {
            (t.client, t.cgen, t.cidx) = (ci, cg, NOT_LISTED);
            (t.capped, t.moved) = (false, 0); // (this worker's caps: below, once the record is in its slot)
            if let Some(s) = t.cv.as_mut() {
                s.rehome(&mut self.starve_pool); // 20.30
            }
            let (sid, raw, acct, udp, fd, state, blocked) = (t.sid, t.raw, t.acct, t.udp, t.fd, t.state, t.blocked);
            let conn = t.conn.clone();
            let (ti, tg) = self.targets.insert(t);
            // 20.26 r4 this worker is in a capped stage (the source was not): the socket may have grown and a parked
            // stream would never count up to its lazy cap, so it is capped now, as set_level does for a live socket
            self.lazy_cap(ti, LAZY_CAP as usize);
            let new = tok(K_TARGET, ti, tg);
            map.insert(old, new);
            self.pend_total += acct;
            let c = self.clients.at(ci);
            if raw {
                debug_assert!(old_proxy.is_some());
                c.proxy_target = Some((ti, tg));
            } else {
                c.streams.insert(sid, ti);
            }
            if blocked {
                parked.push(new);
            }
            self.slog_in(ti, log);
            if let Some(p) = pace {
                self.pace_in(ti, tg & 0x3fff_ffff, p);
            }
            if let Some(l) = lock {
                self.rcvlock_in(ti, tg & 0x3fff_ffff, l);
            }
            if state == TState::Connecting {
                self.targets.at(ti).cidx = self.connecting.len();
                self.connecting.push((ti, tg));
            }
            let ev = if udp { (libc::EPOLLIN | libc::EPOLLET) as u32 } else { EV_TARGET };
            if fd >= 0 {
                regs.push((fd, new, ev));
            }
            for fd in conn {
                regs.push((fd, new, ev));
            }
        }
        self.stats.streams.set((self.targets.slots.len() - self.targets.free.len()) as u64);
        // the parked lists, in their order, under the new tokens (an entry without a stream is not possible:
        // close_target takes a stream out of both lists)
        let c = self.clients.at(ci);
        c.blocked = old_blocked.iter().filter_map(|t| map.get(t).copied()).collect();
        c.bulk_waiting = old_bulk.iter().take(waiting).filter(|t| map.contains_key(t)).count();
        c.blocked_bulk = old_bulk.iter().filter_map(|t| map.get(t).copied()).collect();
        // parked but on neither list: flush_dirty had moved it to the source's `ready` and it was not resumed yet
        for t in parked {
            if !c.blocked.contains(&t) && !c.blocked_bulk.contains(&t) {
                self.ready.push(t);
            }
        }
        if self.fd_mask & crate::fdgate::MARK_SHARE != 0 {
            let i = ci as usize;
            if self.sfds.len() <= i {
                self.sfds.resize(i + 1, [0, 0]);
            }
            self.sfds[i] = [own, 0];
            Self::sfd_apply(&mut self.sfds, &self.peers_of, &self.cfg, self.idx, ci, 0);
            // 60.57 C
        }
        // last: the fds. Edge-triggered ADD reports what is ready now, so no edge between the two workers is lost.
        if regs.iter().any(|&(fd, t, ev)| !ep_add(self.ep, fd, t, ev)) {
            self.stats.moved_reset.bump();
            self.reset_client(ci, Why::ServerClose); // (as adopt: a connection this worker cannot watch is closed)
            if let Some((_, seq)) = before {
                // an older trial's connection noted here must not stand in for this one (M_BACK)
                let m = self.mig.get_or_insert_with(Default::default);
                if m.trial.is_none() || seq.wrapping_sub(m.trial_seq) < 1 << 31 {
                    (m.trial, m.trial_seq) = (None, seq);
                }
            }
            return None;
        }
        if let Some((b, seq)) = before {
            let m = self.mig.get_or_insert_with(Default::default);
            if m.trial.is_none() || seq.wrapping_sub(m.trial_seq) < 1 << 31 {
                (m.trial, m.trial_seq) = (Some((ci, cg, b)), seq);
            }
        }
        Some((ci, cg))
    }

    /// Hand connection `ci` to worker `to` (the caller checked mig_quiet). `before`: see Moved.
    fn mig_send(&mut self, ci: u32, to: usize, before: Option<(u64, u32)>) {
        let mut m = self.mig_export(ci);
        m.before = before;
        let p = &self.peers[to];
        p.load.fetch_add(1, Relaxed);
        self.stats.rx_bytes.set(self.rx_total); // 60.25 C5 as close_client: before the load goes down (main's final totals)
        self.inbox.load.fetch_sub(1, Ordering::Release);
        p.mig.moves.lock().unwrap().push(m);
        p.mig.cmd.fetch_or(M_IMPORT, Ordering::AcqRel);
        p.wake();
    }

    /// The idle sweep with --auto-balance: this worker's CPU share since its last sweep; at or above balance::HOT the
    /// observer is woken (it sleeps while no worker is that busy). One clock read per sweep; none while the observer naps.
    #[cold]
    #[inline(never)]
    pub(super) fn mig_report(&mut self, now: Instant) {
        if crate::balance::napping() {
            return; // 60.74 the observer naps: nothing to tell it (the share after the nap only wakes it, awake)
        }
        let cpu = crate::balance::thread_cpu_ns();
        let m = self.mig.get_or_insert_with(Default::default);
        if sweep_share(m.cpu.replace((now, cpu)), now, cpu) >= crate::balance::HOT as u64 {
            crate::balance::hot();
        }
    }

    /// inbox_ready: the inbox word is not 0. The end of a trial first, then a census, the arrivals, then a move.
    #[cold]
    #[inline(never)]
    pub(super) fn mig_cmd(&mut self) {
        let cmd = self.inbox.mig.cmd.swap(0, Ordering::AcqRel);
        if cmd & M_END != 0 {
            // first: it belongs to the trial before, and may share the word with the next trial's arrival or request
            // (balance::Real::send keeps it)
            if let Some(m) = self.mig.as_mut() {
                m.trial = None;
            }
        }
        let (to, seq) = (((cmd >> M_TO_SHIFT) & 0xffff) as usize, (cmd >> M_SEQ_SHIFT) & 0xffff_ffff);
        let reply = |w: &Worker, code: u64, v: u64| w.inbox.mig.out.store(seq << 32 | code << 24 | v.min(0xff_ffff), Ordering::Release);
        // (a move picks by the rates since the census before; the census of this word ends that window)
        let rates = if cmd & M_MOVE != 0 { self.mig_rates() } else { Vec::new() };
        if cmd & M_CENSUS != 0 {
            // (with M_MOVE in the word the counters of the census before stay the base of the rates: a move asked
            // again after R_BUSY picks by the whole of A1, not by the tick since the last try)
            self.mig_census(seq as u32, cmd & M_MOVE == 0);
            if cmd & (M_MOVE | M_BACK) == 0 {
                reply(self, R_NOTED, 0);
            }
        }
        // 60.74 arrivals after the census of the same word (it ends a window that the arrival is not part of) and
        // before a move (M_BACK hands on what arrived)
        if cmd & M_IMPORT != 0 {
            let moves = std::mem::take(&mut *self.inbox.mig.moves.lock().unwrap());
            for m in moves {
                let _at = self.mig_import(m);
                #[cfg(any(feature = "pooltest", test, fuzzing))]
                if let Some(at) = _at {
                    self.mig.get_or_insert_with(Default::default).fresh.push(at);
                }
            }
        }
        if cmd & M_MOVE != 0 {
            let r = self.mig_move(to, seq as u32, rates);
            reply(self, r, 0);
        }
        if cmd & M_BACK != 0 {
            let r = self.mig_back(to, seq as u32);
            reply(self, r, 0);
        }
    }

    /// 60.74 A census: the worker's byte total and every connection's kernel counters, now (MigBox::snap). The
    /// per-slot counters are also kept for the next M_MOVE (mig_rates) when `base`.
    fn mig_census(&mut self, seq: u32, base: bool) {
        let m = self.mig.get_or_insert_with(Default::default);
        let mut seen = if base { std::mem::take(&mut m.seen) } else { Vec::new() };
        seen.clear();
        let many = self.clients.slots.len() - self.clients.free.len() > CENSUS_MAX;
        let (mut bytes, mut conns) = (self.rx_total, Vec::new());
        if !many {
            seen.resize(self.clients.slots.len(), (0, 0, 0));
        }
        for (i, (g, c)) in self.clients.slots.iter().enumerate() {
            let Some(c) = c.as_ref().filter(|c| !c.dead) else { continue };
            bytes = bytes.wrapping_add(c.tx_bytes);
            if many || c.local == LOCAL_UNIX {
                continue;
            }
            if let Some((b, segs)) = net::traffic(c.fd) {
                seen[i] = ((g & 0x3fff_ffff) + 1, b, segs);
                if let Some(k) = net::cookie(c.fd) {
                    conns.push((k, b, segs));
                }
            }
        }
        let m = self.mig.as_mut().unwrap();
        bytes = bytes.wrapping_add(m.closed_tx);
        let at = Instant::now();
        if base {
            (m.seen, m.seen_at) = (seen, Some(at));
        }
        let moves = m.moves;
        *self.inbox.mig.snap.lock().unwrap() = Some(Census { seq, at, bytes, conns, many, moves });
    }

    /// Since the last census: (slot, generation, bytes per second, data segments per second) of every connection
    /// that moved bytes.
    fn mig_rates(&mut self) -> Vec<(u32, u32, u64, u64)> {
        let Some(m) = self.mig.as_ref() else { return Vec::new() };
        let Some(at) = m.seen_at else { return Vec::new() };
        let us = at.elapsed().as_micros().max(1) as u64;
        let mut v = Vec::new();
        for (i, &(g1, bytes, segs)) in m.seen.iter().enumerate() {
            let Some((g, Some(c))) = self.clients.slots.get(i).map(|s| (s.0, s.1.as_ref())) else { continue };
            if g1 != (g & 0x3fff_ffff) + 1 || c.dead {
                continue;
            }
            let Some((b, s)) = net::traffic(c.fd) else { continue };
            let (db, ds) = (b.saturating_sub(bytes), s.wrapping_sub(segs) as u64);
            if db > 0 {
                v.push((i as u32, g, db.saturating_mul(1_000_000) / us, ds.saturating_mul(1_000_000) / us));
            }
        }
        v
    }

    /// M_MOVE: with at least two busy connections, the second busiest by data segments goes to worker `to` (the
    /// busiest stays: the worker keeps its main load, and the one that leaves carries enough to keep the other
    /// thread awake). The only busy connection never moves.
    fn mig_move(&mut self, to: usize, seq: u32, mut r: Vec<(u32, u32, u64, u64)>) -> u64 {
        self.inbox.mig.moved.store(0, Relaxed);
        if r.len() < 2 || to == self.idx || to >= self.peers.len() {
            return R_NONE;
        }
        r.sort_by_key(|x| std::cmp::Reverse(x.3));
        let Some(k) = (1..r.len()).find(|&k| self.mig_quiet(r[k].0, r[k].1)) else {
            // (level, caps, shutdown: no connection is at rest, and asking again does not help)
            return if self.lvl != 0 || self.st.sock_cap != 0 || self.inbox.stop.load(Relaxed) != 0 { R_NONE } else { R_BUSY };
        };
        let (ci, _, rate, _) = r[k];
        self.inbox.mig.moved.store(net::cookie(self.clients.at(ci).fd).unwrap_or(0), Relaxed); // (before the answer: Release)
        self.inbox.mig.moved_seq.store(seq, Relaxed);
        self.mig_send(ci, to, Some((rate, seq)));
        self.stats.moved_conns.bump();
        R_MOVED
    }

    /// M_BACK: the connection under trial goes to worker `to` (back to the source, or to the destination again at a
    /// keep). It stays the connection under trial there (request `seq`).
    fn mig_back(&mut self, to: usize, seq: u32) -> u64 {
        let Some((ci, cg, _)) = self.mig.as_ref().and_then(|m| m.trial) else { return R_GONE };
        if self.clients.get(ci, cg).is_none_or(|c| c.dead) {
            self.mig.as_mut().unwrap().trial = None;
            return R_GONE;
        }
        if to == self.idx || to >= self.peers.len() || !self.mig_quiet(ci, cg) {
            return R_BUSY;
        }
        let rate = self.mig.as_mut().unwrap().trial.take().map_or(0, |t| t.2);
        self.mig_send(ci, to, Some((rate, seq)));
        self.stats.moved_back.bump();
        R_MOVED
    }

    /// Test hook (cargo feature pooltest, unit tests, fuzzing; never in a release): every `every` loop turns, the next
    /// connection at rest moves to the next worker; with one worker it leaves and comes back (new slots, new
    /// generations, every list rebuilt). Returns (old slot, old generation, new slot, new generation) of a
    /// connection that came back to this worker. A connection that arrived from another worker in this turn stays for it.
    #[cfg(any(feature = "pooltest", test, fuzzing))]
    pub(super) fn mig_force(&mut self, every: u32) -> Option<(u32, u32, u32, u32)> {
        self.mig_force_at(every, true)
    }

    /// `turn_end`: false = called from inbox_ready, inside the turn's event batch (where a real request is handled):
    /// this turn's arrivals stay listed until the call at the turn's end, and the turns are counted there only. In a
    /// turn that moves, a connection also moves here if the inbox woke the worker.
    #[cfg(any(feature = "pooltest", test, fuzzing))]
    pub(super) fn mig_force_at(&mut self, every: u32, turn_end: bool) -> Option<(u32, u32, u32, u32)> {
        if every == 0 {
            return None;
        }
        let n = self.clients.slots.len() as u32;
        let (start, fresh) = {
            let m = self.mig.get_or_insert_with(Default::default);
            // (this turn's arrivals: see Mig::fresh)
            let fresh = if turn_end { std::mem::take(&mut m.fresh) } else { m.fresh.clone() };
            m.force.0 += u32::from(turn_end);
            if m.force.0 + u32::from(!turn_end) < every || n == 0 {
                return None;
            }
            if turn_end {
                m.force.0 = 0;
            }
            (m.force.1 % n, fresh)
        };
        let ci = (0..n).map(|k| (start + k) % n).find(|&i| {
            let g = self.clients.slots[i as usize].0;
            !fresh.contains(&(i, g)) && self.mig_quiet(i, g)
        })?;
        self.mig.as_mut().unwrap().force.1 = ci + 1;
        let cg = self.clients.gen(ci);
        if self.peers.len() > 1 {
            self.mig_send(ci, (self.idx + 1) % self.peers.len(), None);
            self.stats.moved_conns.bump();
            return None;
        }
        let m = self.mig_export(ci);
        self.stats.moved_conns.bump();
        self.mig_import(m).map(|(i, g)| (ci, cg, i, g))
    }
}
