//! 60.63 the worker's side of section E (crate::bounds). Nothing here is on a stream's path while no mark is set: a
//! worker reaches these functions from the out-of-line side of 60.57's fd count and from its idle sweep.
//!
//! How a worker learns that a mark is set: `bd_pick` loads the process state where the worker is out of line anyway
//! (fd_grab: when its fd allowance is used up, every 64 fds at most; fd_trim at the idle sweep, every 2 s). While a
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
    self as bd, Bounds, Dest, DestTop, Dests, Log, Unread, OPT_DEAD, OPT_PORT, OPT_TCPMEM, OPT_WATCH, PT_TOP, ST_PT_BUSY, ST_PT_SHORT,
    ST_TM_SHARE,
};
use crate::clientip::IpKey;

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
    /// E3 scratch of a count: the destinations with a connect in flight (an entry) and how many of their connecting
    /// sockets are old enough to ask; and the destinations with a target that opened since the last count
    old: HashMap<Dest, u32>,
    opened: Vec<Dest>,
    /// E3 the thresholds (bounds::DF_AGE_MS, DF_SYNS; tests shorten them)
    df_age_ms: u64,
    df_syns: u8,
    /// E3 connecting sockets asked for their SYN count so far (one getsockopt each; the tests read it)
    asked: u64,
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
            old: HashMap::new(),
            opened: Vec::new(),
            df_age_ms: bd::DF_AGE_MS,
            df_syns: bd::DF_SYNS,
            asked: 0,
        })
    }
}

impl Worker {
    /// Tests: E3 with a connecting socket asked from `age_ms` and dead at `syns` SYNs
    #[cfg(test)]
    pub(super) fn df_set(&mut self, age_ms: u64, syns: u8) {
        let b = self.bd.as_mut().unwrap();
        (b.df_age_ms, b.df_syns) = (age_ms, syns);
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
        self.bd.as_ref().map_or(0, |b| if b.live != 0 || !b.dead.is_empty() { HOLD_BOUNDS } else { 0 })
    }

    /// Take the process state: into hold mode when a mark is set, out of it when none is (see the head of this file)
    #[cold]
    #[inline(never)]
    pub(super) fn bd_pick(&mut self) {
        let Some(b) = self.bd.as_mut() else { return };
        let live = b.g.state();
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
        if self.connecting.is_empty() || self.bd.as_ref().is_none_or(|b| b.g.opts & OPT_DEAD == 0) {
            return;
        }
        let now = metrics::now_ms();
        if self.bd.as_ref().is_some_and(|b| now.saturating_sub(b.count_at) >= RECOUNT_MS) {
            self.bd_count(now);
        }
    }

    /// fd_trim at the idle sweep: the state, and this worker's counts for the other workers
    #[cold]
    #[inline(never)]
    pub(super) fn bd_sweep(&mut self) {
        self.bd_pick();
        self.bd_count(metrics::now_ms());
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
        let up_port = self.cfg.upstream.as_deref().map(|u| u.port);
        b.by_client.clear();
        b.by_client.resize(self.clients.slots.len(), 0);
        b.by_dest.clear();
        b.old.clear();
        b.opened.clear();
        // E3 a connect attempt is old enough to ask when its deadline is this near
        let near = Instant::now() + self.cfg.connect_timeout.saturating_sub(Duration::from_millis(b.df_age_ms));
        let mut unread = 0u32;
        for (ti, s) in self.targets.slots.iter().enumerate() {
            let Some(t) = s.1.as_ref() else { continue };
            if tcpmem && t.blocked && !t.udp {
                if let Some(n) = b.by_client.get_mut(t.client as usize) {
                    *n += 1;
                    unread += 1;
                }
            }
            if port || dead {
                if let Some((d, n)) = Self::bd_dest(&mut b, up_port, ti, s.0, t) {
                    if port {
                        *b.by_dest.entry(d).or_default() += n;
                    }
                    if dead && t.state == TState::Connecting {
                        *b.old.entry(d).or_default() += (t.deadline <= near) as u32;
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
            self.bd_dead_count(&mut b, now, near);
        }
        self.bd = Some(b);
        if (self.fd_mask & HOLD_BOUNDS != 0) != (self.bd_hold() != 0) {
            self.fd_setup(); // (E3: into hold mode with the first suspect, out of it once none is left)
        }
    }

    /// E3 at a count (Wb::old and Wb::opened are this count's): which destinations do not answer. A new suspect: DF_K
    /// or more of its connecting sockets that are old enough have each sent Wb::df_syns SYNs (asked of the kernel: at
    /// most DF_ASK_MAX sockets per count), and no target opened on it since the last count. A suspect stays while a
    /// connect to it is in flight and no target opened on it. So it goes when it answers (its probe or any stream
    /// opened, also one that is closed again by now; or it refuses the connection), and when nobody asks for it
    /// (its connects have timed out). A stream that asks counts first when the last count is RECOUNT_MS old.
    fn bd_dead_count(&mut self, b: &mut Wb, now: u64, near: Instant) {
        let mut cand: Vec<(Dest, u32)> = Vec::new();
        for (d, n) in b.old.iter() {
            if *n >= bd::DF_K && !b.opened.contains(d) && !b.dead.iter().any(|s| s.dest == *d) {
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
                if t.udp || t.deadline > near || t.conn.len() != t.attempt {
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
                            "finalwisp: --dest-failfast: {} does not answer ({} or more connects got no answer to {} SYNs each, \
                             none opened): new streams to it are refused with 0x43 at once, except one probe per second, until \
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
        let Some((pt, df)) = self.bd.as_ref().map(|b| (b.live & (ST_PT_BUSY | ST_PT_SHORT) != 0, !b.dead.is_empty())) else { return 0 };
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

    /// E3 an attempt of a client with `key` to `dest`: true = refused. One attempt per DF_PROBE_MS goes on as the
    /// suspect's probe; the others are refused, if the client has a key and another client is connected (P1: an
    /// address alone on the server is never refused: its SYNs take nothing from anyone). A suspect that answers goes
    /// at the next count (bd_dead_count).
    fn bd_dead(&mut self, dest: Dest, key: Option<IpKey>, now: u64) -> bool {
        let Some(b) = self.bd.as_mut() else { return false };
        let Some(s) = b.dead.iter_mut().find(|s| s.dest == dest) else { return false };
        if now >= s.probe_at {
            s.probe_at = now + bd::DF_PROBE_MS;
            return false;
        }
        key.is_some_and(|k| bd::others(&b.slots, now, k))
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
    #[cold]
    #[inline(never)]
    pub(super) fn bd_attempt(&mut self, ti: u32) -> bool {
        self.bd_pick();
        let t = self.targets.at(ti);
        let (first, udp) = (t.attempt == 0 && t.conn.is_empty(), t.udp);
        let mut why = if first { self.bd_judge(ti) } else { 0 };
        if why == 0 && !udp && self.bd.as_ref().is_some_and(|b| b.live & (ST_PT_BUSY | ST_PT_SHORT) != 0 || !b.dead.is_empty()) {
            why = WHY_GATED;
        }
        if let Some(b) = self.bd.as_mut() {
            b.why = why;
        }
        why == 0
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
                    metrics::log_nowait(
                        "finalwisp: --dest-failfast: new streams to a destination that does not answer are refused with 0x43 at \
                         once (the reason they would get at the connect timeout); one probe per second goes on, and the first \
                         that connects ends it (--log-streams shows the destination). Or --no-dest-failfast (counted as \
                         refuse_dest_dead; at most one such line per 10 s)"
                            .to_string(),
                    );
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
