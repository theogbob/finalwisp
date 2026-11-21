//! 60.63 the worker's side of section E (crate::bounds). Nothing here is on a stream's path while no mark is set: a
//! worker reaches these functions from the out-of-line side of 60.57's fd count and from its idle sweep.
//!
//! How a worker learns that a mark is set: `bd_pick` loads the process state where the worker is out of line anyway
//! (fd_grab: when its fd allowance is used up, every 64 fds at most; the idle sweep, every 2 s). While a
//! mark is set the worker is in 60.57's hold mode (HOLD_BOUNDS in fd_mask: fd_have is exactly its count), so every
//! CONNECT comes to fd_more (before DNS) and every connect attempt to fd_grab_t (with its stream): the rules run
//! there. When the marks clear, the same places take the worker out of hold mode. With --conn-share or
//! --fd-admission the worker is in hold mode already and picks the state up at every stream.
//!
//! E2 rides the same way. While a destination is busy, a TCP attempt that fd_grab_t stops leaves try_connect through
//! its fd_short exit, and fd_short hands it to try_connect_gated: the same source as try_connect (one macro,
//! worker/connect.rs), which asks bd_gate about each address (refused: the stream's next one; busy: the socket
//! option between socket() and connect()). try_connect itself has no test for any of this, and nothing here calls
//! it (a call back into it would make it recursive, and the compiler then builds it and its callers differently).

use super::*;
use crate::bounds::{
    self as bd, Bounds, Dest, DestTop, Dests, Log, Stall, UcLim, Unread, OPT_DEAD, OPT_PORT, OPT_RELIEF, OPT_TCPMEM, OPT_UNREAD, OPT_WATCH,
    PT_TOP, ST_PT_BUSY, ST_PT_SHORT, ST_TM_SHARE, ST_UNREAD,
};
use crate::clientip::IpKey;
use std::collections::HashSet;

/// fd_mask bit of this file: the worker is in hold mode for a rule of section E (never a bit of FdGate::mask)
pub(super) const HOLD_BOUNDS: u8 = 4;

/// why an attempt does not go on in try_connect (Wb::why, set by the rule, taken by fd_short)
const WHY_TM_SHARE: u8 = 1;
const WHY_PT_SHARE: u8 = 3;
const WHY_PT_FULL: u8 = 4;
const WHY_DEAD: u8 = 7;
const WHY_PT_LAST: u8 = 8;
/// not refusals. E2: the destination is busy (the attempt gets the socket option); a destination is busy somewhere
/// (the attempt goes on in try_connect_gated, which asks bd_gate about each address)
const WHY_RANGED: u8 = 5;
const WHY_GATED: u8 = 6;

/// while a mark is set a worker counts its target sockets again at most this often (else: at its sweep) ...
const RECOUNT_MS: u64 = 250;
/// ... and reads the other workers' counts at most this often
const SLOTS_MS: u64 = 100;
/// E2 the destinations a worker remembers as full (the oldest goes first)
const FULL_MAX: usize = 8;

pub(super) struct Wb {
    pub(super) g: Arc<Bounds>,
    /// the marks this worker acts on now (bounds::ST_*); 0 = at rest (no hold mode for this file)
    pub(super) live: u8,
    why: u8,
    count_at: u64,
    slots_at: u64,
    slots: Vec<Unread>,
    by_client: Vec<u32>,
    by_key: HashMap<IpKey, u32>,
    /// E2 every worker's destinations (read with `slots`)
    dests: Vec<Dests>,
    /// E2 the destination of an open target, by target index: (generation, destination); read once from its socket
    dst: Vec<(u32, Dest)>,
    /// E2 this worker's sockets per destination, and per (destination of `top`, client address), at the last count
    by_dest: HashMap<Dest, u32>,
    by_dest_key: HashMap<(u8, IpKey), u32>,
    /// E2 (destination, until ms): the kernel had no port left toward it
    full: Vec<(Dest, u64)>,
    /// E2 try_connect_gated: the stream (index, generation) whose newest address a rule refused, and the rule (0: none)
    last: (u32, u32, u8),
    /// E2 try_connect_gated: the attempt in hand goes to a busy destination
    ranged: bool,
    /// E3 the destinations that do not answer (at most DF_MAX); not empty = hold mode for this worker
    dead: Vec<Suspect>,
    /// E3 60.78 bundle B1 the failing destinations (at most DF_FAIL_MAX), each until a time (ms)
    fail: HashMap<Dest, u64>,
    /// E3 the destinations with an open target at the last count (kept while some destination is failing: `seen_ok`)
    seen: HashSet<Dest>,
    seen_ok: bool,
    /// E3 per client address: its connects in flight that are old (DF_AGE_MS) or go to a failing destination, and for
    /// an address that has such a connect also its young ones to destinations without an open target (the last
    /// count's, plus the attempts let in since)
    fly: HashMap<IpKey, u32>,
    /// E3 scratch of bd_fail_count: the young connects to destinations without an open target, by address
    young: Vec<(IpKey, u32)>,
    /// E3 an address has half of DF_FAIL_FLY or more (on; off below a quarter): hold mode (every attempt is judged)
    fly_hi: bool,
    /// E3 scratch of a count: the destinations with a connect in flight (an entry), how many of their connecting
    /// sockets are old (DF_AGE_MS) and how many are ripe (near their deadline: DF_RIPE_MS); and the destinations with
    /// a target that opened since the last count
    old: HashMap<Dest, (u32, u32)>,
    opened: Vec<Dest>,
    /// E3 the thresholds (bounds::DF_AGE_MS, DF_SYNS, DF_RIPE_MS; tests shorten them)
    df_age_ms: u64,
    df_syns: u8,
    df_ripe_ms: u64,
    /// E3 connecting sockets asked for their SYN count so far (one getsockopt each; the tests read it)
    asked: u64,
    /// E5 the credit of each connection, by client slot (bounds::uc_step), and the rule's constants
    uc: Vec<Stall>,
    uc_lim: UcLim,
    /// E5 the bytes in the receive queues of each connection's parked downloads at the last count, by client slot
    uc_held: Vec<u64>,
    /// 60.78 G70 --unread-close's relief: by target slot, a target whose receive buffer we locked and shrank
    rl: Vec<RlEnt>,
    /// 60.78 G70 the cap of the relief bytes (None: a quarter of the worker's memory budget; tests set it)
    rl_cap: Option<usize>,
}

impl Wb {
    /// E3 a suspect, or an address with half of its budget for failing destinations in flight: hold mode, and every
    /// TCP attempt is judged (bd_gate). (Not for any failing destination: one connect without an answer is common on
    /// a public server; below half the budget the attempts between two counts take fds out of line at most up to the
    /// next count, RECOUNT_MS at each fd block)
    fn df_live(&self) -> bool {
        !self.dead.is_empty() || self.fly_hi
    }
}

/// E3 a destination that does not answer
struct Suspect {
    dest: Dest,
    /// the next probe may go at this time (ms)
    probe_at: u64,
}

/// The address a connected socket goes to. (Not net::peer_ip: a call from here would change how the compiler builds
/// the functions that share it, and with section E off they must stay as they were.)
fn peer_of(fd: RawFd) -> Option<IpAddr> {
    // SAFETY: getpeername writes at most `len` bytes into the zeroed storage; the family says which form it wrote
    unsafe {
        let mut ss: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getpeername(fd, &mut ss as *mut _ as *mut _, &mut len) != 0 {
            return None;
        }
        match ss.ss_family as libc::c_int {
            libc::AF_INET => {
                Some(IpAddr::from(u32::from_be((*(&ss as *const _ as *const libc::sockaddr_in)).sin_addr.s_addr).to_be_bytes()))
            }
            libc::AF_INET6 => Some(IpAddr::from((*(&ss as *const _ as *const libc::sockaddr_in6)).sin6_addr.s6_addr)),
            _ => None,
        }
    }
}

impl Wb {
    pub(super) fn new(g: Arc<Bounds>) -> Box<Wb> {
        Box::new(Wb {
            g,
            live: 0,
            why: 0,
            count_at: 0,
            slots_at: 0,
            slots: Vec::new(),
            by_client: Vec::new(),
            by_key: HashMap::new(),
            dests: Vec::new(),
            dst: Vec::new(),
            by_dest: HashMap::new(),
            by_dest_key: HashMap::new(),
            full: Vec::new(),
            last: (0, 0, 0),
            ranged: false,
            dead: Vec::new(),
            fail: HashMap::new(),
            seen: HashSet::new(),
            seen_ok: false,
            young: Vec::new(),
            fly: HashMap::new(),
            fly_hi: false,
            old: HashMap::new(),
            opened: Vec::new(),
            df_age_ms: bd::DF_AGE_MS,
            df_syns: bd::DF_SYNS,
            df_ripe_ms: bd::DF_RIPE_MS,
            asked: 0,
            uc: Vec::new(),
            uc_lim: UcLim::REAL,
            uc_held: Vec::new(),
            rl: Vec::new(),
            rl_cap: None,
        })
    }
}

impl Worker {
    /// Tests: E3 with a connecting socket asked from `age_ms` and dead at `syns` SYNs; every socket that is old enough
    /// is ripe too (df_ripe sets the window)
    #[cfg(test)]
    pub(super) fn df_set(&mut self, age_ms: u64, syns: u8) {
        let b = self.bd.as_mut().unwrap();
        (b.df_age_ms, b.df_syns, b.df_ripe_ms) = (age_ms, syns, u64::MAX >> 2);
    }

    /// Tests: E3 a connecting socket is ripe in the last `ms` before its deadline
    #[cfg(test)]
    pub(super) fn df_ripe(&mut self, ms: u64) {
        self.bd.as_mut().unwrap().df_ripe_ms = ms;
    }

    /// Tests: E3 the failing destinations, and the connects in flight to them of the client address of `ip`
    #[cfg(test)]
    pub(super) fn df_fail(&self, ip: &str) -> (usize, u32) {
        let b = self.bd.as_ref().unwrap();
        (b.fail.len(), b.fly.get(&clientip::key(ip.parse().unwrap())).copied().unwrap_or(0))
    }

    /// Tests: the relief's cap in bytes (in place of a quarter of the memory budget)
    #[cfg(test)]
    pub(super) fn rl_set_cap(&mut self, cap: usize) {
        self.bd.as_mut().unwrap().rl_cap = Some(cap);
    }

    /// Tests: whether bd_relief holds a lock on target slot `ti`
    #[cfg(test)]
    pub(super) fn rl_held(&self, ti: u32) -> bool {
        self.bd.as_ref().unwrap().rl.get(ti as usize).is_some_and(|e| e.g1 != 0)
    }

    /// Tests: E5 with a starting credit of `ms` (the price of a byte scaled with it: UC_STALL_MS / `ms` x UC_RATE), a cap
    /// of `cap_ms`, and one full stream of `m0` bytes (0: the host's)
    #[cfg(test)]
    pub(super) fn uc_set(&mut self, ms: u64, cap_ms: u64, m0: u64) {
        let b = self.bd.as_mut().unwrap();
        (b.uc_lim.start_ms, b.uc_lim.cap_ms, b.uc_lim.m0) = (ms, cap_ms, m0);
        b.uc_lim.rate = bd::UC_RATE * bd::UC_STALL_MS / ms.max(1);
    }

    /// Tests: E3 the connecting sockets asked for their SYN count so far
    #[cfg(test)]
    pub(super) fn df_asked(&self) -> u64 {
        self.bd.as_ref().unwrap().asked
    }

    /// Tests: E2 a connect of stream `ti` (made with the socket option or not) failed at once with `e`; the number of
    /// destinations that are held for full afterwards
    #[cfg(test)]
    pub(super) fn pt_failed(&mut self, ti: u32, ranged: bool, e: i32) -> usize {
        self.bd.as_mut().unwrap().ranged = ranged;
        self.bd_connect_failed(ti, IpAddr::from([192, 0, 2, 1]), e);
        self.bd.as_ref().unwrap().full.len()
    }

    /// Tests: E3 the suspect table is full (of destinations nobody connects to)
    #[cfg(test)]
    pub(super) fn df_fill(&mut self) {
        let (b, now) = (self.bd.as_mut().unwrap(), metrics::now_ms());
        while b.dead.len() < bd::DF_MAX {
            let dest = (IpAddr::from([192, 0, 2, 1]), b.dead.len() as u16);
            b.dead.push(Suspect { dest, probe_at: now });
        }
    }

    /// fd_setup: this file's bit of fd_mask
    pub(super) fn bd_hold(&self) -> u8 {
        self.bd.as_ref().map_or(0, |b| if b.live != 0 || b.df_live() { HOLD_BOUNDS } else { 0 })
    }

    /// Take the process state: into hold mode when a mark is set, out of it when none is (see the head of this file)
    #[cold]
    #[inline(never)]
    pub(super) fn bd_pick(&mut self) {
        let Some(b) = self.bd.as_mut() else { return };
        let live = b.g.state() & !ST_UNREAD; // (E5 is read at the sweep: no hold mode)
        if live == b.live {
            return;
        }
        let armed = b.live == 0;
        b.live = live;
        self.fd_setup();
        if armed {
            self.bd_count(metrics::now_ms()); // (the counts of the last sweep are up to 2 s old)
        }
    }

    /// fd_grab (the worker is out of line: its fd allowance is used up; in hold mode at every fd): the process state,
    /// and for E3 a count if connects are in flight and the last one is RECOUNT_MS old (a destination that stopped
    /// answering is seen without waiting for the sweep)
    #[cold]
    #[inline(never)]
    pub(super) fn bd_grab(&mut self) {
        self.bd_pick();
        self.bd_recount();
    }

    /// bd_grab's E3 count. The time is the loop turn's (no clock read at each fd): a count comes at most one turn late.
    #[inline]
    fn bd_recount(&mut self) {
        if self.connecting.is_empty() || self.bd.as_ref().is_none_or(|b| b.g.opts & OPT_DEAD == 0) {
            return;
        }
        let now = metrics::ms_at(self.now);
        if self.bd.as_ref().is_some_and(|b| now.saturating_sub(b.count_at) >= RECOUNT_MS) {
            self.bd_count(now);
        }
    }

    /// the idle sweep (before fd_trim): the state, and this worker's counts for the other workers
    #[cold]
    #[inline(never)]
    pub(super) fn bd_sweep(&mut self) {
        self.bd_pick();
        let now = metrics::now_ms();
        self.bd_count(now);
        if self.bd.as_ref().is_some_and(|b| b.g.opts & OPT_UNREAD != 0) {
            self.bd_unread(now);
        }
    }

    /// E5 at the idle sweep, after bd_count (Wb::by_client holds each connection's parked downloads): a step of
    /// bounds::uc_step for every connection, and the reset of those it names (`now`: ms)
    #[cold]
    #[inline(never)]
    pub(super) fn bd_unread(&mut self, now: u64) {
        let Some(mut b) = self.bd.take() else { return };
        let pressed = b.g.state() & ST_UNREAD != 0;
        if b.uc_lim.m0 == 0 {
            b.uc_lim.m0 = bd::rmem_max() + self.cfg.notsent_lowat as u64;
        }
        if b.uc.len() < self.clients.slots.len() {
            b.uc.resize(self.clients.slots.len(), Stall::default());
        }
        let mut reset = Vec::new();
        for (ci, s) in self.clients.slots.iter().enumerate() {
            let parked = b.by_client.get(ci).is_some_and(|n| *n > 0);
            let info = match s.1.as_ref() {
                Some(c) if parked && !c.dead && !c.closing && c.local != LOCAL_UNIX => bd::wnd_acked(c.fd),
                _ => None,
            };
            // the host TCP memory it holds, read only with a parked download (the credit's use scales with it)
            let held = match (s.1.as_ref(), info) {
                (Some(c), Some(_)) => b.uc_held.get(ci).copied().unwrap_or(0) + bd::queued(c.fd, libc::TIOCOUTQ),
                _ => 0,
            };
            if bd::uc_step(&mut b.uc[ci], s.0, info, held, now, &b.uc_lim, pressed) {
                reset.push(ci as u32);
            }
        }
        if !reset.is_empty() && b.g.log_due(Log::UcReset) {
            metrics::log_nowait(format!(
                "finalwisp: --unread-close: {} connection(s) reset: each held a download its client did not read (receive \
                 window 0) until its stall time was used up ({} s to start, more for data it took) while host TCP memory is \
                 short ({} MiB). Fix: more memory or a larger net.ipv4.tcp_mem on the host; or --no-unread-close (counted as \
                 close_unread; at most one such line per 10 s)",
                reset.len(),
                b.uc_lim.start_ms / 1000,
                b.g.mib()
            ));
        }
        let relief = b.g.opts & OPT_RELIEF != 0;
        self.bd = Some(b);
        for ci in reset {
            self.stats.close_unread.bump();
            self.abort_client(ci, Why::Unread); // (review) RST on the targets too: memory pressure (20.26)
        }
        if relief {
            self.bd_relief(pressed); // 60.78 G70 (after the resets: their streams are gone)
        }
    }

    /// 60.78 G70 --unread-close's relief at the idle sweep, after bd_unread (OPT_RELIEF: the Mem form and SO_BUF_LOCK).
    /// Why: while the host's TCP memory is short, the kernel gives a socket memory for an arriving segment only while the
    /// socket holds less than its share (tcp_mem's maximum over the TCP sockets allocated: Bounds::share_bytes). A
    /// parked download's target socket that holds more drops every segment, the destination's head segment is never
    /// acknowledged, and the destination ends the connection after tcp_retries2 (~15 min): the stream ends with 0x03.
    /// What: such a socket (its memory, SO_MEMINFO's rmem_alloc as the kernel counts it for the share, above half the
    /// share S) gets SOCK_RCVBUF_LOCK (autotuning stops: our big read would grow the buffer) and a receive buffer of S/4
    /// (the kernel doubles it: S/2), and what it has queued is read out into its client's own queue. All of it (r9, VM
    /// rig: read down to S/4 of payload, a socket held 210 KiB of memory in a 176 KiB buffer, the kernel's overhead per
    /// segment being ~2.4 x its payload there, and dropped every arrival until the destination timed out). It keeps
    /// that buffer while the pressure lasts, also when it reads again (more would be above its share). Lifted once the
    /// pressure is over: rl_lift (the old size, then only the lock bit), unless a cap of the memory budget set another
    /// size since.
    /// Order: the target is parked (no read in flight), and its bytes are framed at the end of the queue read_target
    /// would use (its lane rule), so its next read continues after them; Client::flush sends the pipe of a pending
    /// splice before the obuf bytes after it. Close: at most what FIONREAD reported is read, so a read never returns 0
    /// or an error while data is queued (tcp_recvmsg reports EOF and sk_err only with nothing copied); the target's
    /// EOF or reset stays for read_target, which handles it as always. (A read that fails anyway stops here; its error
    /// is then consumed, and read_target sees the closed socket as an EOF.)
    /// Cap: the bytes over out_high in all client queues of this worker stay within a quarter of the worker's memory
    /// budget (no budget: no relief); candidates go in the order of their connection's E5 credit, the most first (a
    /// reader that earned time before one that did not), and one over the cap is counted (relief_capped), as is one
    /// whose bytes would take its client's queue to out_hard. The read is cut to the cap (more can come in before it).
    /// Scope: every parked TCP stream (not only download-only ones: a socket above the share drops segments anyway).
    /// Not while a stage of the memory budget caps sockets (its caps own the lock bits then). A socket that someone else
    /// locked is left alone (its lock is not ours to lift).
    /// Known limit: a connection moved by --auto-balance keeps the lock and the small buffer until it closes (the entry
    /// stays here and is dropped by the generation check).
    #[cold]
    #[inline(never)]
    pub(super) fn bd_relief(&mut self, pressed: bool) {
        let Some(mut b) = self.bd.take() else { return };
        // the locks held (not while a stage caps sockets: its caps own the bits then)
        if self.st.sock_cap == 0 {
            for ti in 0..b.rl.len() {
                let e = b.rl[ti];
                if e.g1 == 0 {
                    continue;
                }
                b.rl[ti] = match self.targets.get(ti as u32, e.g1.wrapping_sub(1)) {
                    None => RlEnt::default(), // closed (its socket with it), or a new target in the slot
                    Some(t) => rl_keep(t.fd, e, pressed),
                };
            }
        }
        let budget = b.rl_cap.unwrap_or(mem::WORKER_BUDGET.load(Relaxed) / 4);
        let share = b.g.share_bytes().unwrap_or(0) as usize;
        if !pressed || self.st.sock_cap != 0 || budget == 0 || share == 0 {
            self.bd = Some(b);
            return;
        }
        let (hi, keep, out_high, out_hard) = (share / 2, share / 4, self.st.out_high, self.st.out_hard); // keep: the new SO_RCVBUF
        let mut used: usize =
            self.clients.slots.iter().filter_map(|s| s.1.as_ref()).map(|c| c.out_pending().saturating_sub(out_high)).sum();
        let mut cands = Vec::new();
        for (ti, s) in self.targets.slots.iter().enumerate() {
            let Some(t) = s.1.as_ref() else { continue };
            if t.blocked == Park::Run || t.udp || t.state != TState::Open || t.fd < 0 {
                continue;
            }
            let c = self.clients.slots.get(t.client as usize).and_then(|c| c.1.as_ref());
            if c.is_none_or(|c| c.dead || c.closing) {
                continue; // (nothing after a closing connection's WS Close)
            }
            // (one we hold comes again only when the share fell below what its buffer lets it hold)
            if rl_rmem(t.fd).unwrap_or(0) as usize > hi {
                let q = bd::queued(t.fd, libc::FIONREAD) as usize;
                let cg1 = self.clients.slots[t.client as usize].0.wrapping_add(1);
                let credit = b.uc.get(t.client as usize).filter(|u| u.g1 == cg1).map_or(0, |u| u.credit);
                cands.push((credit, ti as u32, q));
            }
        }
        cands.sort_unstable_by_key(|c| std::cmp::Reverse(c.0));
        for (_, ti, q) in cands {
            let (fd, ci, g1) = (self.targets.at(ti).fd, self.targets.at(ti).client, self.targets.gen(ti).wrapping_add(1));
            // the client's own queue stays below out_hard (read_client stops reading a client at it: its CONNECTs, CLOSEs
            // and pings would wait behind the relief bytes)
            let room = out_hard.saturating_sub(self.clients.at(ci).out_pending() + 2 * CHUNK);
            if used + q > budget || q > room {
                self.stats.relief_capped.bump();
                continue;
            }
            // lock first (an unlocked buffer can grow at any time, and our read would grow it), then shrink, then read: a
            // window update of our read must not let the destination fill the old, large buffer again (on loopback that
            // happens inside the read). Arrivals while it holds more than the new buffer are dropped, as they are under
            // the pressure anyway; queued data is never pruned (tcp_prune_queue collapses it, drops only out of order).
            let held = b.rl.get(ti as usize).filter(|e| e.g1 == g1).copied();
            let mut e = match held {
                Some(e) => e, // locked already, its old size saved
                None => {
                    let Some(saved) = rl_rcvbuf_get(fd) else { continue };
                    if !rl_lock(fd) {
                        continue; // locked by someone else, or the syscall failed: left as it is
                    }
                    RlEnt { g1, saved, ours: 0 }
                }
            };
            rl_rcvbuf(fd, keep);
            let Some(ours) = rl_rcvbuf_get(fd) else {
                if held.is_none() {
                    rl_lift(fd, e); // (undone: no entry without the size we set)
                }
                continue;
            };
            e.ours = ours;
            if b.rl.len() <= ti as usize {
                b.rl.resize(ti as usize + 1, RlEnt::default());
            }
            b.rl[ti as usize] = e;
            // all that is queued now (more came since the count), within the cap and the client's room
            let n = (bd::queued(fd, libc::FIONREAD) as usize).min(budget - used).min(room);
            let got = self.relief_read(ti, n);
            used += got;
            self.stats.relief_bytes.add(got as u64);
            self.stats.relief_streams.bump();
        }
        self.bd = Some(b);
    }

    /// 60.78 G70 bd_relief's read: up to `n` bytes of parked target `ti` framed as DATA (raw: plain WS frames) at the end
    /// of its client's queue, the lane as read_target chooses it. The framing is read_target's, written out here (a call
    /// into its helpers would change how the compiler builds read_target). -> bytes read
    fn relief_read(&mut self, ti: u32, n: usize) -> usize {
        let t = self.targets.at(ti);
        let (fd, ci, sid, raw, tbulk, bulk_end) = (t.fd, t.client, t.sid, t.raw, t.bulk, t.bulk_end);
        let c = self.clients.at(ci);
        let lane = self.cfg.prio && !raw && (tbulk || bulk_end > c.bulk_sent);
        let room = if raw { ROOM_RAW } else { ROOM_WISP };
        let mut done = 0;
        while done < n {
            let want = (n - done).min(CHUNK);
            let c = self.clients.at(ci);
            let dst = if lane { &mut c.bulk } else { &mut c.obuf };
            dst.reserve(room + want);
            let base = dst.len();
            // SAFETY: reserve() above: capacity >= base + room + want, so the read stays in the spare capacity
            let r = unsafe { libc::read(fd, dst.as_mut_ptr().add(base + room) as *mut _, want) };
            if r <= 0 {
                break;
            }
            let k = r as usize;
            // SAFETY: as in read_target: capacity >= base + room + k; every byte up to the new length is written (the WS
            // header, hl = 2 or 4; the Wisp header at hl unless raw; the data at hl + room - 4, moved there when hl = 2)
            unsafe {
                let p = dst.as_mut_ptr().add(base);
                let plen = k + room - 4;
                let mut hl = 4;
                if plen <= 125 {
                    std::ptr::copy(p.add(room), p.add(room - 2), k);
                    hl = 2;
                    *p.add(1) = plen as u8;
                } else {
                    *p.add(1) = 126;
                    *p.add(2) = (plen >> 8) as u8;
                    *p.add(3) = plen as u8;
                }
                *p = 0x80 | OP_BIN;
                if !raw {
                    *p.add(hl) = PKT_DATA;
                    std::ptr::copy_nonoverlapping(sid.to_le_bytes().as_ptr(), p.add(hl + 1), 4);
                }
                dst.set_len(base + hl + plen);
            }
            if lane {
                let end = c.bulk_sent + (c.bulk.len() - c.bhead) as u64;
                c.bulk_ends.push_back(end);
                self.targets.at(ti).bulk_end = end;
            }
            done += k;
            if k < want {
                break;
            }
        }
        if done > 0 {
            self.targets.at(ti).wrote_since_read = false; // (the target spoke after our last write, as in read_target)
            let c = self.clients.at(ci);
            c.active = true;
            if !c.dirty {
                c.dirty = true;
                self.dirty.push((ci, self.clients.gen(ci)));
            }
        }
        done
    }

    /// The client address of connection `ci` as a key of section E: an IPv4 address or an IPv6 /64; behind a
    /// --trusted-proxy the address its header names. None: no one client's address (loopback, private, CGNAT and the
    /// other shared ranges; a trusted proxy's own address: no header, or before its request; a unix client; peers not
    /// kept). Such a client is never refused by a share rule and counts as "another client" for everyone.
    pub(super) fn bd_key(&self, ci: u32) -> Option<IpKey> {
        let ip = self.peer(ci)?.ip;
        if net::shared_addr(ip) || self.cfg.clientip.as_deref().is_some_and(|c| c.is_trusted(ip)) {
            return None;
        }
        Some(clientip::key(ip))
    }

    /// The destination of target `ti` as section E counts it, and how many sockets it holds there: an open TCP
    /// target's peer address (read from the socket once, then kept in Wb::dst; E3: a target seen open for the first
    /// time opened since the last count), a connecting one's newest address for each attempt in flight. With
    /// --upstream the socket goes to the proxy: its address and port.
    fn bd_dest(b: &mut Wb, up_port: Option<u16>, ti: usize, tg: u32, t: &Target) -> Option<(Dest, u32)> {
        if t.udp {
            return None;
        }
        match t.state {
            TState::Open => {
                if b.dst.len() <= ti {
                    b.dst.resize(ti + 1, (u32::MAX, DestTop::EMPTY.dest));
                }
                if b.dst[ti].0 != tg {
                    b.dst[ti] = (tg, (peer_of(t.fd)?, up_port.unwrap_or(t.port)));
                    if b.g.opts & OPT_DEAD != 0 && !b.opened.contains(&b.dst[ti].1) {
                        b.opened.push(b.dst[ti].1);
                    }
                }
                Some((b.dst[ti].1, 1))
            }
            TState::Connecting if !t.conn.is_empty() => {
                Some(((*t.addrs.get(t.attempt.checked_sub(1)?)?, up_port.unwrap_or(t.port)), t.conn.len() as u32))
            }
            _ => None,
        }
    }

    /// Count this worker's target sockets and publish. E1: the unread ones (TCP targets parked on their client's
    /// output: Target::blocked) per client address: all of them, the largest holder, and whether every connection has
    /// one key. E2: the TCP target sockets per destination: the PT_TOP largest, each with its largest holder. E3: the
    /// destinations that do not answer (bd_dead_count).
    #[cold]
    #[inline(never)]
    pub(super) fn bd_count(&mut self, now: u64) {
        let Some(mut b) = self.bd.take() else { return };
        let (tcpmem, port, dead) = (b.g.opts & OPT_TCPMEM != 0, b.g.opts & OPT_PORT != 0, b.g.opts & OPT_DEAD != 0);
        let uc = b.g.opts & OPT_UNREAD != 0;
        let up_port = self.cfg.upstream.as_deref().map(|u| u.port);
        b.by_client.clear();
        b.by_client.resize(self.clients.slots.len(), 0);
        if uc {
            b.uc_held.clear();
            b.uc_held.resize(self.clients.slots.len(), 0);
        }
        b.by_dest.clear();
        b.old.clear();
        b.opened.clear();
        // E3 a connect attempt is old when its deadline is this near, and ripe (asked for its SYNs) when it is this near
        let left = self.cfg.connect_timeout.saturating_sub(Duration::from_millis(b.df_age_ms));
        let t_now = Instant::now();
        let (near, ripe) = (t_now + left, t_now + left.min(Duration::from_millis(b.df_ripe_ms)));
        let mut unread = 0u32;
        // E3 the destinations that answer, while one is failing (bd_dead: an address over its budget gets no connect
        // to a destination without an open target)
        let track = dead && (!b.fail.is_empty() || b.fly_hi);
        b.seen.clear();
        b.seen_ok = track;
        for (ti, s) in self.targets.slots.iter().enumerate() {
            let Some(t) = s.1.as_ref() else { continue };
            if (tcpmem || uc) && t.blocked != Park::Run && !t.udp {
                if let Some(n) = b.by_client.get_mut(t.client as usize) {
                    *n += 1;
                    unread += 1;
                }
                if let Some(h) = b.uc_held.get_mut(t.client as usize).filter(|_| uc) {
                    *h += bd::queued(t.fd, libc::FIONREAD); // E5 what the parked download holds
                }
            }
            if port || dead {
                if let Some((d, n)) = Self::bd_dest(&mut b, up_port, ti, s.0, t) {
                    if port {
                        *b.by_dest.entry(d).or_default() += n;
                    }
                    if dead && t.state == TState::Connecting {
                        let e = b.old.entry(d).or_default();
                        (e.0, e.1) = (e.0 + (t.deadline <= near) as u32, e.1 + (t.deadline <= ripe) as u32);
                    } else if track && t.state == TState::Open {
                        b.seen.insert(d);
                    }
                }
            }
        }
        b.by_key.clear();
        let (mut conns, mut single, mut mixed) = (0u32, None, false);
        for (ci, s) in self.clients.slots.iter().enumerate() {
            // (a connection counts once it speaks Wisp: before that it has no stream, and behind a proxy no address)
            if !s.1.as_ref().is_some_and(|c| !c.dead && matches!(c.state, CState::Open | CState::WaitInfo | CState::Wsproxy)) {
                continue;
            }
            conns += 1;
            let n = b.by_client[ci];
            if mixed && n == 0 {
                continue; // (its key changes nothing)
            }
            let key = self.bd_key(ci as u32);
            match (key, single) {
                (Some(k), None) if conns == 1 => single = Some(k),
                (Some(k), Some(s)) if k == s => {}
                _ => mixed = true,
            }
            if let (Some(k), true) = (key, n > 0) {
                *b.by_key.entry(k).or_default() += n;
            }
        }
        if port {
            // the PT_TOP largest destinations (ties: any), then their sockets per client address
            let mut top = [DestTop::EMPTY; PT_TOP];
            for (d, n) in b.by_dest.iter() {
                let Some(i) = (0..PT_TOP).min_by_key(|i| top[*i].n).filter(|i| top[*i].n < *n) else { continue };
                top[i] = DestTop { dest: *d, n: *n, top: None, top_n: 0 };
            }
            b.by_dest_key.clear();
            if top.iter().any(|e| e.n > 0) {
                for (ti, s) in self.targets.slots.iter().enumerate() {
                    let Some(t) = s.1.as_ref() else { continue };
                    let Some((d, n)) = Self::bd_dest(&mut b, up_port, ti, s.0, t) else { continue };
                    let Some(i) = top.iter().position(|e| e.n > 0 && e.dest == d) else { continue };
                    if let Some(k) = self.bd_key(t.client) {
                        *b.by_dest_key.entry((i as u8, k)).or_default() += n;
                    }
                }
                for ((i, k), n) in b.by_dest_key.iter() {
                    let e = &mut top[*i as usize];
                    if *n > e.top_n {
                        (e.top, e.top_n) = (Some(*k), *n);
                    }
                }
            }
            b.g.publish_dests(self.idx, &top);
        }
        let top = b.by_key.iter().map(|(k, n)| (*n, *k)).max();
        b.g.publish(
            self.idx,
            Unread {
                at_ms: now.max(1),
                conns,
                single: if mixed { None } else { single },
                unread,
                top: top.map(|t| t.1),
                top_unread: top.map_or(0, |t| t.0),
                connecting: self.connecting.len() as u32,
            },
        );
        if b.g.opts & OPT_WATCH != 0 {
            self.stats.connecting.set(self.connecting.len() as u64);
        }
        b.count_at = now;
        b.g.read_slots(&mut b.slots);
        b.slots_at = now.max(1);
        if tcpmem {
            self.stats.tcpmem_unread.set(unread as u64);
        }
        if port {
            b.g.read_dests(&mut b.dests);
            let own = b.dests.get(self.idx).copied().unwrap_or([DestTop::EMPTY; PT_TOP]);
            let most = own.iter().filter(|e| e.n > 0).map(|e| bd::pt_view(&b.slots, &b.dests, now, e.dest, None).total).max();
            self.stats.port_dest_max.set(most.unwrap_or(0));
        }
        if dead {
            self.bd_dead_count(&mut b, now, ripe);
            self.bd_fail_count(&mut b, now, up_port, near);
        }
        self.bd = Some(b);
        if (self.fd_mask & HOLD_BOUNDS != 0) != (self.bd_hold() != 0) {
            self.fd_setup(); // (E3: into hold mode with the first suspect, out of it once none is left)
        }
    }

    /// E3 at a count (Wb::old and Wb::opened are this count's): which destinations do not answer. A new suspect: DF_K
    /// or more of its connecting sockets that are ripe (`ripe`: their deadline is at most DF_RIPE_MS away, 60.78 bundle
    /// B1: a host that answers a late SYN is never taken for dead) have each sent Wb::df_syns SYNs (asked of the kernel:
    /// at most DF_ASK_MAX sockets per count), and no target opened on it since the last count. A suspect stays while a
    /// connect to it is in flight and no target opened on it. So it goes when it answers (its probe or any stream
    /// opened, also one that is closed again by now; or it refuses the connection), and when nobody asks for it
    /// (its connects have timed out). A stream that asks counts first when the last count is RECOUNT_MS old.
    fn bd_dead_count(&mut self, b: &mut Wb, now: u64, ripe: Instant) {
        let mut cand: Vec<(Dest, u32)> = Vec::new();
        for (d, n) in b.old.iter() {
            if n.1 >= bd::DF_K && !b.opened.contains(d) && !b.dead.iter().any(|s| s.dest == *d) {
                cand.push((*d, 0));
            }
        }
        if !cand.is_empty() {
            let mut asked = 0;
            for &(ti, tg) in self.connecting.iter() {
                let Some(t) = self.targets.slots.get(ti as usize).filter(|x| x.0 == tg).and_then(|x| x.1.as_ref()) else { continue };
                // (a stream whose attempts are all in flight: its newest socket is the one to addrs[attempt - 1].
                // One of them ended, or a rule of this file refused an address: which socket goes where is not
                // known, and no address is blamed for another's silence)
                if t.udp || t.deadline > ripe || t.conn.len() != t.attempt {
                    continue;
                }
                let Some(&ip) = t.attempt.checked_sub(1).and_then(|i| t.addrs.get(i)) else { continue };
                let Some(c) = cand.iter_mut().find(|c| c.0 == (ip, t.port) && c.1 < bd::DF_K) else { continue };
                let Some(&fd) = t.conn.last() else { continue };
                asked += 1;
                b.asked += 1;
                c.1 += bd::syns_sent(fd).is_some_and(|n| n >= b.df_syns) as u32;
                if asked >= bd::DF_ASK_MAX {
                    break;
                }
            }
            for (d, n) in cand {
                if n >= bd::DF_K && b.dead.len() < bd::DF_MAX {
                    b.dead.push(Suspect { dest: d, probe_at: now + bd::DF_PROBE_MS });
                    if b.g.log_due(Log::DfSuspect) {
                        metrics::log_nowait(format!(
                            "finalwisp: --dest-failfast: {} does not answer ({} or more connects near their connect timeout got \
                             no answer to {} SYNs each, none opened): new streams to it are refused with 0x43 at once, except one probe per second, until \
                             it answers (--log-streams shows them; at most one such line per 10 s)",
                            SocketAddr::new(d.0, d.1),
                            bd::DF_K,
                            b.df_syns
                        ));
                    }
                }
            }
        }
        // (after the new ones: a full table stays full for this count)
        let (opened, flying) = (&b.opened, &b.old);
        b.dead.retain(|s| !opened.contains(&s.dest) && flying.contains_key(&s.dest));
        self.stats.dest_dead.set(b.dead.len() as u64);
    }

    /// E3 60.78 bundle B1 at a count, after bd_dead_count: the failing destinations (a connect to it is DF_AGE_MS old
    /// with no answer and nothing opened on it since the last count: kept DF_FAIL_KEEP_MS from then; it goes when a
    /// target to it opens and is seen open at a count: one that opens and closes between two counts is not seen), and
    /// per client address its connects in flight that are old (`near`) or go to a failing destination, and for an
    /// address with such a connect also its young ones to destinations without an open target while Wb::seen is kept
    /// (Wb::fly, the budget of bd_dead; a stream's sockets all count for its newest address, as E2 counts them).
    fn bd_fail_count(&mut self, b: &mut Wb, now: u64, up_port: Option<u16>, near: Instant) {
        let until = now + bd::DF_FAIL_KEEP_MS;
        for (d, n) in b.old.iter() {
            if n.0 == 0 || b.opened.contains(d) {
                continue;
            }
            if let Some(u) = b.fail.get_mut(d) {
                *u = until;
            } else if b.fail.len() < bd::DF_FAIL_MAX {
                b.fail.insert(*d, until);
            }
        }
        let opened = &b.opened;
        b.fail.retain(|d, u| now < *u && !opened.contains(d));
        b.fly.clear();
        b.young.clear();
        let was_hi = std::mem::take(&mut b.fly_hi);
        if b.fail.is_empty() {
            return;
        }
        for &(ti, tg) in self.connecting.iter() {
            let Some(t) = self.targets.slots.get(ti as usize).filter(|x| x.0 == tg).and_then(|x| x.1.as_ref()) else { continue };
            if t.udp || t.conn.is_empty() {
                continue;
            }
            let Some(&ip) = t.attempt.checked_sub(1).and_then(|i| t.addrs.get(i)) else { continue };
            let d = (ip, up_port.unwrap_or(t.port));
            let (old, failing) = (t.deadline <= near, b.fail.contains_key(&d));
            if !old && !failing && !(b.seen_ok && !b.seen.contains(&d)) {
                continue;
            }
            let Some(k) = self.bd_key(t.client) else { continue };
            // (a young connect to a destination without an open target counts only for an address that has an old
            // or failing one: the second pass below)
            if old || failing {
                *b.fly.entry(k).or_default() += t.conn.len() as u32;
            } else {
                b.young.push((k, t.conn.len() as u32));
            }
        }
        for (k, n) in b.young.drain(..) {
            if let Some(f) = b.fly.get_mut(&k) {
                *f += n;
            }
        }
        let most = b.fly.values().copied().max().unwrap_or(0);
        b.fly_hi = most >= bd::DF_FAIL_FLY / 2 || (was_hi && most >= bd::DF_FAIL_FLY / 4);
    }

    /// The other workers' counts, at most SLOTS_MS old, and this worker's own at most RECOUNT_MS old (a mark is set)
    fn bd_fresh(&mut self, now: u64) {
        if self.bd.as_ref().is_some_and(|b| now.saturating_sub(b.count_at) >= RECOUNT_MS) {
            self.bd_count(now); // (reads the slots too)
        }
        let Some(b) = self.bd.as_mut() else { return };
        if now.saturating_sub(b.slots_at) >= SLOTS_MS {
            b.g.read_slots(&mut b.slots);
            if b.g.opts & OPT_PORT != 0 {
                b.g.read_dests(&mut b.dests);
            }
            b.slots_at = now.max(1);
        }
    }

    /// E1 the share rule for connection `ci` (the mark is set): true = refuse its new stream
    fn bd_tm_share(&mut self, ci: u32) -> bool {
        let Some(key) = self.bd_key(ci) else { return false };
        let now = metrics::now_ms();
        self.bd_fresh(now);
        self.bd.as_ref().is_some_and(|b| bd::tm_share(&b.slots, now, key, b.g.floor()))
    }

    /// The rules for a new stream `ti` (the worker has taken the state): the reason it is refused, or 0.
    /// E1: at the share mark a TCP stream of the address that holds most of the unread downloads (a UDP stream holds
    /// no TCP memory).
    fn bd_judge(&mut self, ti: u32) -> u8 {
        if self.bd.as_ref().is_none_or(|b| b.live & ST_TM_SHARE == 0) {
            return 0;
        }
        let t = self.targets.at(ti);
        let (ci, udp) = (t.client, t.udp);
        if !udp && self.bd_tm_share(ci) {
            WHY_TM_SHARE
        } else {
            0
        }
    }

    /// The rules for a connect attempt of stream `ti` (TCP) to `ip`. E2: WHY_PT_FULL = the kernel had no port left
    /// toward that destination moments ago, WHY_PT_SHARE = the share rule, WHY_PT_LAST = the reserve (an address
    /// alone on the destination at 15/16 of the ports, another client on the server), WHY_RANGED = a busy destination
    /// (the attempt gets the socket option). E3: WHY_DEAD = the destination does not answer (and this attempt is not
    /// its probe). E2 first: an attempt that E2 refuses sends no SYN, so it must not be taken for E3's probe. 0 =
    /// nothing.
    fn bd_judge_addr(&mut self, ti: u32, ip: IpAddr) -> u8 {
        let Some((pt, df)) = self.bd.as_ref().map(|b| (b.live & (ST_PT_BUSY | ST_PT_SHORT) != 0, b.df_live())) else { return 0 };
        if !pt && !df {
            return 0;
        }
        let t = self.targets.at(ti);
        let (ci, port) = (t.client, t.port);
        let dest = (ip, self.cfg.upstream.as_deref().map_or(port, |u| u.port));
        let now = metrics::now_ms();
        self.bd_fresh(now);
        let key = self.bd_key(ci);
        let mut why = 0;
        if let Some(b) = self.bd.as_mut().filter(|_| pt) {
            b.full.retain(|f| now < f.1);
            if b.full.iter().any(|f| f.0 == dest) {
                return WHY_PT_FULL;
            }
            let (v, usable) = (bd::pt_view(&b.slots, &b.dests, now, dest, key), b.g.pt_usable());
            // (a client without a key holds nothing in the view: the share rule is never true for it)
            if bd::pt_share(v, usable) {
                return WHY_PT_SHARE;
            } else if bd::pt_last(v, usable) && key.is_some_and(|k| bd::others(&b.slots, now, k)) {
                return WHY_PT_LAST;
            } else if v.total >= bd::pt_part(usable, bd::PT_BUSY_IN_16) {
                why = WHY_RANGED;
            }
        }
        if df && self.bd_dead(dest, key, now) {
            return WHY_DEAD;
        }
        why
    }

    /// E3 an attempt of a client with `key` to `dest`: true = refused. To a suspect: one attempt per DF_PROBE_MS goes
    /// on as the suspect's probe (not for an address over its budget); the others are refused. 60.78 bundle B1 the
    /// budget: an address with DF_FAIL_FLY connects in flight that are old or go to failing destinations (Wb::fly) gets
    /// no connect to a failing destination, nor (while Wb::seen is kept) to one without an open target at the last
    /// count; under it such an attempt counts as one more. Refused only if the client has a key and another client is
    /// connected (P1: an address alone on the server is never refused: its SYNs take nothing from anyone). A
    /// destination that answers goes at the next count.
    fn bd_dead(&mut self, dest: Dest, key: Option<IpKey>, now: u64) -> bool {
        let Some(b) = self.bd.as_mut() else { return false };
        let over = key.is_some_and(|k| b.fly.get(&k).is_some_and(|n| *n >= bd::DF_FAIL_FLY));
        if let Some(s) = b.dead.iter_mut().find(|s| s.dest == dest) {
            if now >= s.probe_at && !over {
                s.probe_at = now + bd::DF_PROBE_MS;
                return false;
            }
            return key.is_some_and(|k| bd::others(&b.slots, now, k));
        }
        let Some(k) = key else { return false };
        let failing = b.fail.get_mut(&dest);
        if failing.is_none() && b.seen.contains(&dest) {
            return false;
        }
        let judged = failing.is_some() || b.seen_ok;
        if !over {
            // (an attempt to a destination without an open target counts only for an address with a connect that
            // got no answer: an honest address that connects to new hosts is never counted)
            if failing.is_some() {
                *b.fly.entry(k).or_default() += 1;
            } else if let Some(n) = b.fly.get_mut(&k).filter(|_| b.seen_ok) {
                *n += 1;
            }
            return false;
        }
        if let Some(u) = failing {
            *u = now + bd::DF_FAIL_KEEP_MS;
        }
        judged && bd::others(&b.slots, now, k)
    }

    /// fd_more, for the CONNECT of stream `ti` before any DNS or socket work: true = refused (fd_short sends the
    /// CLOSE). In hold mode every CONNECT comes here. (E1 only: E2 judges an address, and none is known yet.)
    #[cold]
    #[inline(never)]
    pub(super) fn bd_room_short(&mut self, ti: u32) -> bool {
        self.bd_pick();
        let why = self.bd_judge(ti);
        if let Some(b) = self.bd.as_mut() {
            b.why = why;
        }
        why != 0
    }

    /// fd_grab_t, for a connect attempt (or the UDP socket) of stream `ti`: false = the attempt does not go on in
    /// try_connect (fd_short takes the reason). E1 judges a stream's first attempt only: later ones (the next address,
    /// the other family) belong to a stream that was let in; it is judged here again after its lookup (a mark can come
    /// while it resolves), and here first when the worker took the mark at this very call. A stream that bd_park
    /// set back to no attempt (every address so far was refused by E2 or E3, and it waits for the rest of its
    /// lookup) is such a stream: it is judged again when the final answer comes. E2, E3: while a destination is busy
    /// or does not answer, every TCP attempt goes on in try_connect_gated, which judges each address.
    /// An attempt that goes on then takes its fd here (bd_grab's count, fd_grab): one call of fd_grab_t per fd.
    #[cold]
    #[inline(never)]
    pub(super) fn bd_take(&mut self, ti: u32) -> bool {
        self.bd_pick();
        let t = self.targets.at(ti);
        let (first, udp) = (t.attempt == 0 && t.conn.is_empty(), t.udp);
        let mut why = if first { self.bd_judge(ti) } else { 0 };
        if why == 0 && !udp && self.bd.as_ref().is_some_and(|b| b.live & (ST_PT_BUSY | ST_PT_SHORT) != 0 || b.df_live()) {
            why = WHY_GATED;
        }
        if let Some(b) = self.bd.as_mut() {
            b.why = why;
        }
        if why != 0 {
            return false;
        }
        self.bd_recount();
        self.fd_grab_n(1)
    }

    /// fd_short with a reason of this file for the attempt of stream `ti` that fd_grab_t stopped
    #[cold]
    #[inline(never)]
    pub(super) fn bd_short(&mut self, ti: u32, why: u8) {
        match why {
            WHY_GATED => self.try_connect_gated(ti),
            _ => self.bd_refused(ti, why),
        }
    }

    /// try_connect_gated before it takes the fd for an attempt of stream `ti` to `ip`. None: a rule refuses this
    /// address; it counts as tried (the stream's next address follows; with none left bd_end refuses the stream).
    /// Some(range): the attempt goes on, with the socket option's value for a busy destination (0: no option).
    #[cold]
    #[inline(never)]
    pub(super) fn bd_gate(&mut self, ti: u32, ip: IpAddr) -> Option<u32> {
        let why = self.bd_judge_addr(ti, ip);
        let tg = self.targets.gen(ti);
        let Some(b) = self.bd.as_mut() else { return Some(0) };
        b.ranged = why == WHY_RANGED;
        if matches!(why, WHY_PT_SHARE | WHY_PT_LAST | WHY_PT_FULL | WHY_DEAD) {
            b.last = (ti, tg, why);
            self.targets.at(ti).attempt += 1;
            return None;
        }
        b.last.2 = 0; // (a real attempt follows: its outcome is the stream's reason)
        Some(if b.ranged { b.g.pt_range(ip.is_ipv6()) } else { 0 })
    }

    /// E2 try_connect_gated: the connect of stream `ti` to `ip` failed at once with `e`. EADDRNOTAVAIL from a busy
    /// destination: the host has no source port left toward it (for PT_FULL_MS no attempt asks the kernel again),
    /// and that is the stream's reason if no other address is left.
    #[cold]
    #[inline(never)]
    pub(super) fn bd_connect_failed(&mut self, ti: u32, ip: IpAddr, e: i32) {
        let (tg, port) = (self.targets.gen(ti), self.targets.at(ti).port);
        let port = self.cfg.upstream.as_deref().map_or(port, |u| u.port);
        let Some(b) = self.bd.as_mut().filter(|b| b.ranged && e == libc::EADDRNOTAVAIL) else { return };
        if b.full.len() >= FULL_MAX {
            b.full.remove(0);
        }
        b.full.push(((ip, port), metrics::now_ms() + bd::PT_FULL_MS));
        b.last = (ti, tg, WHY_PT_FULL);
    }

    /// try_connect_gated parks stream `ti`: no address is left, no attempt is in flight, and the other family's
    /// lookup is still due. Where a rule refused its newest address (or the kernel had no port for it), that address
    /// does not count as tried: the final answer (dns_late) starts with it again, so the stream ends in bd_end with
    /// the rule's reason and counter (it ended in try_connect with 0x42 and no counter), or goes on if the rule no
    /// longer holds.
    #[cold]
    #[inline(never)]
    pub(super) fn bd_park(&mut self, ti: u32) {
        let tg = self.targets.gen(ti);
        let Some(b) = self.bd.as_mut().filter(|b| b.last.2 != 0 && (b.last.0, b.last.1) == (ti, tg)) else { return };
        b.last.2 = 0;
        let t = self.targets.at(ti);
        t.attempt = t.attempt.saturating_sub(1);
    }

    /// E2 try_connect_gated: no address of stream `ti` is left and no attempt is in flight. true: a rule refused
    /// its newest address, and the stream is refused here (0x49, the rule's counter); false: try_connect's own end.
    #[cold]
    #[inline(never)]
    pub(super) fn bd_end(&mut self, ti: u32) -> bool {
        let tg = self.targets.gen(ti);
        let Some(why) =
            self.bd.as_mut().filter(|b| b.last.2 != 0 && (b.last.0, b.last.1) == (ti, tg)).map(|b| std::mem::take(&mut b.last.2))
        else {
            return false;
        };
        self.bd_refused(ti, why);
        true
    }

    /// fd_short: the reason a rule of this file left for the stream that is refused now (0 = none: no fd)
    pub(super) fn bd_why(&mut self) -> u8 {
        self.bd.as_mut().map_or(0, |b| std::mem::take(&mut b.why))
    }

    /// A stream refused by a rule of this file: counter, rate-limited warning (it does not depend on the optional
    /// logs), --log-streams reason, CLOSE (0x49; E3: 0x43, what the stream would get at the connect deadline). The
    /// connection stays; nothing that is open is closed.
    #[cold]
    #[inline(never)]
    pub(super) fn bd_refused(&mut self, ti: u32, why: u8) {
        let Some(g) = self.bd.as_ref().map(|b| b.g.clone()) else { return };
        let mib = g.mib();
        let (rule, swhy, reason) = match why {
            WHY_PT_SHARE => {
                self.stats.refuse_port_share.bump();
                if g.log_due(Log::PtShareRefused) {
                    metrics::log_nowait(format!(
                        "finalwisp: --port-share: new streams of one client address to one destination are refused with 0x49: \
                         it holds more than half of the target sockets to that destination, 3/4 of the host's source ports \
                         toward it are in use and another client uses it ({}); its open streams go on (--log-streams shows \
                         the address and the destination). Fix: a wider net.ipv4.ip_local_port_range; or --no-port-share \
                         (counted as refuse_port_share; at most one such line per 10 s)",
                        g.pt_state()
                    ));
                }
                ("port_share", SWhy::Limit, CLOSE_THROTTLED)
            }
            WHY_PT_LAST => {
                self.stats.refuse_port_share.bump();
                if g.log_due(Log::PtLastRefused) {
                    metrics::log_nowait(format!(
                        "finalwisp: --port-share: new streams of one client address to one destination are refused with 0x49: \
                         it is alone on that destination and holds 15/16 of the host's source ports toward it, and another \
                         client is connected: the last ports stay free for the other clients ({}); its open streams go on \
                         (--log-streams shows the address and the destination). Fix: a wider net.ipv4.ip_local_port_range; \
                         or --no-port-share (counted as refuse_port_share; at most one such line per 10 s)",
                        g.pt_state()
                    ));
                }
                ("port_reserve", SWhy::Limit, CLOSE_THROTTLED)
            }
            WHY_PT_FULL => {
                self.stats.refuse_port_full.bump();
                if g.log_due(Log::PtFullRefused) {
                    metrics::log_nowait(format!(
                        "finalwisp: --port-share: new streams to one destination are refused with 0x49 for every client: the \
                         host has no source port left toward it ({}); open streams go on. Fix: a wider \
                         net.ipv4.ip_local_port_range, or more than one address for the destination (counted as \
                         refuse_port_full; at most one such line per 10 s)",
                        g.pt_state()
                    ));
                }
                ("port_full", SWhy::Limit, CLOSE_THROTTLED)
            }
            WHY_DEAD => {
                self.stats.refuse_dest_dead.bump();
                if g.log_due(Log::DfRefused) {
                    metrics::log_nowait(format!(
                        "finalwisp: --dest-failfast: new streams to a destination that does not answer are refused with 0x43 at \
                         once (the reason they would get at the connect timeout): to a destination taken for dead, but for one \
                         probe per second (the first that connects ends it), and from a client address with {} connects in \
                         flight on this worker thread that get no answer, to such a destination or to one without an open stream \
                         (--log-streams shows the destination). \
                         Or --no-dest-failfast (counted as refuse_dest_dead; at most one such line per 10 s)",
                        bd::DF_FAIL_FLY
                    ));
                }
                ("dest_dead", SWhy::ConnectFail, CLOSE_TIMEOUT)
            }
            _ => {
                // (WHY_TM_SHARE)
                self.stats.refuse_tcpmem_share.bump();
                if g.log_due(Log::TmShareRefused) {
                    metrics::log_nowait(format!(
                        "finalwisp: --tcpmem-share: new streams of one client address are refused with 0x49: it holds more \
                         than half of all unread downloads ({} or more target sockets) while the host's TCP memory is short \
                         (about {mib} MiB in use) and another client is connected; its open streams go on (--log-streams shows \
                         the address). Fix: more memory or a larger net.ipv4.tcp_mem on the host; or --no-tcpmem-share \
                         (counted as refuse_tcpmem_share; at most one such line per 10 s)",
                        g.floor()
                    ));
                }
                ("tcpmem_share", SWhy::Pressure, CLOSE_THROTTLED)
            }
        };
        if !self.streamlog.is_empty() {
            self.slog_why(ti, swhy, rule);
        }
        self.fail_target(ti, reason);
    }
}

/// 60.78 G70 a target socket bd_relief locked and shrank: its generation + 1 (0: none), SO_RCVBUF before (as the kernel
/// reports it, doubled) and the SO_RCVBUF we set (as reported)
#[derive(Clone, Copy, Default)]
pub(super) struct RlEnt {
    g1: u32,
    saved: i32,
    ours: i32,
}

/// 60.78 G70 a lock bd_relief holds, at a sweep without caps: kept while the pressure lasts (the bit set again if
/// someone cleared it: a caps episode's uncap_bufs (until 1.4.0 also --park-rcvlock's lift, which took a bit it found set after a
/// caps episode for its own), lifted after it (rl_lift). A size we did not set is someone else's: the entry goes and the
/// socket is left as it is. -> the entry to keep (default: none)
fn rl_keep(fd: RawFd, e: RlEnt, pressed: bool) -> RlEnt {
    match (rl_rcvbuf_get(fd), rl_bits(fd)) {
        (Some(cur), _) if cur != e.ours => RlEnt::default(),
        (Some(_), Some(bits)) if pressed => {
            if bits & RCVBUF_LOCK == 0 {
                rl_set(fd, SO_BUF_LOCK, bits | RCVBUF_LOCK); // (failed: tried again at the next sweep)
            }
            e
        }
        (Some(_), Some(_)) => rl_lift(fd, e),
        _ => e, // (a syscall failed: tried again at the next sweep)
    }
}

/// 60.78 G70 the lift (as net::uncap_bufs): the size from before, then only SOCK_RCVBUF_LOCK is cleared (setting
/// SO_RCVBUF sets it again). Clearing the bit alone would leave the buffer small: autotuning grows it only from more
/// data per RTT than its largest measure so far (20.26: a 16 KiB cap stayed at 32 KiB after an unlock). The restored
/// size is clamped to 2 x net.core.rmem_max, so a buffer that had grown past that comes back smaller and regrows only if
/// its data per RTT passes that measure (as 20.26's relief). -> the entry to keep: none when done; when the unlock
/// failed, the size it has now (so that the next sweep tries again)
fn rl_lift(fd: RawFd, mut e: RlEnt) -> RlEnt {
    rl_set(fd, libc::SO_RCVBUF, e.saved / 2);
    if rl_unlock(fd) {
        return RlEnt::default();
    }
    e.ours = rl_rcvbuf_get(fd).unwrap_or(e.ours);
    e
}

/// 60.78 G70 a socket's receive memory as the kernel counts it (SO_MEMINFO, Linux 4.6: SK_MEMINFO_RMEM_ALLOC; the
/// buffers' true size, not the payload)
fn rl_rmem(fd: RawFd) -> Option<u32> {
    let mut m = [0u32; 9]; // SK_MEMINFO_VARS (9 since Linux 4.18; the kernel copies at most `len`)
    let mut len = std::mem::size_of_val(&m) as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `m`
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, 55, m.as_mut_ptr() as *mut _, &mut len) };
    (r == 0 && len >= 4).then_some(m[0])
}

fn rl_rcvbuf_get(fd: RawFd) -> Option<libc::c_int> {
    let (mut v, mut len) = (0 as libc::c_int, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
    // SAFETY: getsockopt writes at most `len` bytes into `v`
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &mut v as *mut _ as *mut _, &mut len) };
    (r == 0).then_some(v)
}

/// 60.78 G70 SO_BUF_LOCK (Linux 5.15; main checked it) and SOCK_RCVBUF_LOCK in its mask. Own copies of net's helpers:
/// a call from here would change how the compiler builds net's functions for other callers (as peer_of above).
const SO_BUF_LOCK: libc::c_int = 72;
const RCVBUF_LOCK: libc::c_int = 2;

fn rl_bits(fd: RawFd) -> Option<libc::c_int> {
    let (mut v, mut len) = (0 as libc::c_int, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
    // SAFETY: getsockopt writes at most `len` bytes into `v`
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, SO_BUF_LOCK, &mut v as *mut _ as *mut _, &mut len) };
    (r == 0).then_some(v)
}

fn rl_set(fd: RawFd, opt: libc::c_int, v: libc::c_int) -> bool {
    // SAFETY: setsockopt reads one c_int
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, opt, &v as *const _ as *const _, std::mem::size_of::<libc::c_int>() as _) == 0 }
}

/// set SOCK_RCVBUF_LOCK if nobody holds it (false: held already, or a syscall failed)
fn rl_lock(fd: RawFd) -> bool {
    rl_bits(fd).is_some_and(|b| b & RCVBUF_LOCK == 0 && rl_set(fd, SO_BUF_LOCK, b | RCVBUF_LOCK))
}

/// clear only SOCK_RCVBUF_LOCK (autotuning goes on from the size it has); true also when it is clear already
fn rl_unlock(fd: RawFd) -> bool {
    match rl_bits(fd) {
        Some(b) if b & RCVBUF_LOCK == 0 => true,
        Some(b) => rl_set(fd, SO_BUF_LOCK, b & !RCVBUF_LOCK),
        None => false,
    }
}

/// SO_RCVBUF (the kernel doubles it; it also sets SOCK_RCVBUF_LOCK, which rl_lock set already)
fn rl_rcvbuf(fd: RawFd, bytes: usize) {
    rl_set(fd, libc::SO_RCVBUF, bytes.min(i32::MAX as usize) as libc::c_int);
}
