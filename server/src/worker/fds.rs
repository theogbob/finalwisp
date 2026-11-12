//! 60.57 A2 the worker's side of the fd count (crate::fdgate): every fd this worker opens for a connection or a
//! stream (client sockets, target sockets and their connect attempts, UDP sockets, splice pipes) is counted in
//! `Stats::fds` against the worker's allowance `fd_have`, which it takes from and returns to the process count in
//! blocks. The worker's fixed fds (listener, epoll, eventfd, spare) are not counted here: they are in the budget.
//! A stream's fd and a pipe's fds are counted from before they are opened (fd_take: no room = no open) until after
//! they are closed (fd_put), in the same function. A client socket is counted from just after accept4 until
//! `unload`, just before its close (one fd per worker at most is closed after its count went back: the reserve has
//! one fd per worker). C --conn-share uses the same count per connection: noted after the take and before the
//! allowance can go back, so what a connection published to its client address is at most its part of `Stats::fds`.
//!
//! C costs nothing here when it is off: a stream's fd take and put and the accept of a connection test no C flag.
//! A's two inline tests (fd_take: count + n <= fd_have; fd_put: fd_have - count >= two blocks) are all they run. With
//! --conn-share or --fd-admission the worker keeps `fd_have` exactly at its count and `fd_block` at 0 (fd_hold,
//! fd_setup), with the allowance it does not use in `fd_pool`: then both tests fail for every take and put, and the
//! out-of-line side does C's work (fd_grab_conn reads the host mark; fd_grab_t and fd_put_slow note the connection's
//! fds). No shared write per stream. The flag is still read: per closed connection, pipe open, idle sweep, share_rule.

use super::*;
use crate::fdgate::{FdGate, Line10, MARK_HOST, MARK_SHARE};

/// the fix every fd warning names
const FIX: &str = "ulimit -n, systemd LimitNOFILE, docker --ulimit nofile; the hard limit is what counts";
const EVERY: &str = "at most one such line per 10 s";
/// A3 connections one failed accept resets through the spare fd (the 10 ms retry comes back for more)
const SPARE_BATCH: u64 = 64;

/// C --conn-share: a connection publishes its fds (streams, splice pipe) to its key (clientip add_fds: a shard lock)
/// when it holds this many more than it published ...
const SHARE_BATCH: u32 = 8;
/// ... and when it holds fewer: then down to this many below what it holds, so that the next closes are free. Between
/// the two a connection's published count is at most its real one and at most SHARE_BATCH - 1 below it; the idle sweep
/// publishes the exact number.
const SHARE_BACK: u32 = 4;

/// fd_take_conn: counted; no fd left under the limit; C --fd-admission and the host mark is set
pub(super) const FD_OK: u8 = 0;
pub(super) const FD_NONE: u8 = 1;
pub(super) const FD_MARK: u8 = 2;

/// A3 the worker's spare fd: an eventfd (no file, no path, a few hundred bytes); -1 if it cannot be opened
pub(super) fn spare_fd() -> RawFd {
    unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) }
}

impl Worker {
    /// Count `n` more fds; false = the process is at its fd limit (nothing counted). No shared write unless the
    /// allowance is used up.
    #[inline]
    pub(super) fn fd_take(&mut self, n: u32) -> bool {
        let u = self.stats.fds.get() + n as u64;
        if u <= self.fd_have as u64 {
            self.stats.fds.set(u);
            true
        } else {
            self.fd_grab(n)
        }
    }

    /// fd_take past `fd_have`: a block from the process count if the allowance is used up (with a C flag every take
    /// comes here, and most find room in fd_pool)
    #[cold]
    #[inline(never)]
    fn fd_grab(&mut self, n: u32) -> bool {
        if self.bd.is_some() {
            self.bd_grab(); // 60.63 (out of line already: the place a worker learns that a mark of section E is set)
        }
        let used = self.stats.fds.get() as u32;
        let mut all = self.fd_have + self.fd_pool;
        if used + n > all {
            let need = used + n - all;
            let got = self.fdg.grab(need.max(self.fdg.block()), need);
            if got == 0 {
                return false;
            }
            all += got;
        }
        self.stats.fds.set((used + n) as u64);
        self.fd_hold(all);
        true
    }

    /// The worker's allowance is `all`: fd_have and fd_pool for it. C off: all of it in fd_have. With a C flag: fd_have
    /// is the worker's count, the rest waits in fd_pool (see the head of this file).
    fn fd_hold(&mut self, all: u32) {
        let used = self.stats.fds.get() as u32;
        self.fd_have = if self.fd_mask != 0 { used.min(all) } else { all };
        self.fd_pool = all - self.fd_have;
    }

    /// The gate's block and marks for this worker (run, once main has set them; tests after they change the gate)
    pub(super) fn fd_setup(&mut self) {
        self.fd_mask = self.fdg.mask() | self.bd_hold(); // (60.63: hold mode also while a mark of section E is set)
        self.fd_block = if self.fd_mask != 0 { 0 } else { self.fdg.block() };
        self.fd_hold(self.fd_have + self.fd_pool);
    }

    /// The allowance this worker holds (its count plus what it does not use)
    #[cfg(test)]
    pub(super) fn fd_all(&self) -> u32 {
        self.fd_have + self.fd_pool
    }

    /// fd_take(1) for a connect attempt or socket of stream `ti` (the same inline test; --conn-share notes it)
    #[inline]
    pub(super) fn fd_take_t(&mut self, ti: u32) -> bool {
        let u = self.stats.fds.get() + 1;
        if u <= self.fd_have as u64 {
            self.stats.fds.set(u);
            true
        } else {
            self.fd_grab_t(ti)
        }
    }

    #[cold]
    #[inline(never)]
    fn fd_grab_t(&mut self, ti: u32) -> bool {
        if self.bd.is_some() && !self.bd_attempt(ti) {
            return false; // 60.63 refused by a rule of section E (fd_short sends the CLOSE)
        }
        let ok = self.fd_grab(1);
        if ok {
            self.sfd(ti, 1);
        }
        ok
    }

    /// 60.63 fd_take_t for try_connect_gated: its attempts are judged by bd_gate (false: no fd)
    pub(super) fn fd_take_ranged(&mut self, ti: u32) -> bool {
        let ok = self.fd_grab(1);
        if ok {
            self.sfd(ti, 1);
        }
        ok
    }

    /// fd_put for `n` fds of a stream of connection `ci` (generation `cg`): the same inline test; --conn-share notes
    /// it, before the allowance can go back to the process count
    #[inline]
    pub(super) fn fd_put_c(&mut self, ci: u32, cg: u32, n: u32) {
        let u = self.stats.fds.get();
        if cfg!(any(test, debug_assertions)) {
            assert!(u >= n as u64, "60.57 fd count underflow");
        }
        let u = u.saturating_sub(n as u64);
        self.stats.fds.set(u);
        if self.fd_have as u64 - u >= 2 * self.fd_block as u64 {
            self.fd_put_slow(ci, cg, n);
        }
    }

    #[cold]
    #[inline(never)]
    fn fd_put_slow(&mut self, ci: u32, cg: u32, n: u32) {
        if self.fd_mask & MARK_SHARE != 0 {
            self.sfd_note(ci, cg, -(n as i32));
        }
        self.fd_trim(false);
    }

    /// fd_take_t / fd_put for stream `ti` out of line, for the places that are not on the normal path of a stream (UDP
    /// sockets, a failed, lost or timed-out connect attempt): their callers keep their code
    #[inline(never)]
    pub(super) fn fd_take_t_cold(&mut self, ti: u32) -> bool {
        self.fd_take_t(ti)
    }
    #[inline(never)]
    pub(super) fn fd_put_t(&mut self, ti: u32, n: u32) {
        self.sfd(ti, -(n as i32)); // (before the count goes down)
        self.fd_put(n)
    }
    /// ... and fd_close for a socket of stream `ti`
    #[inline(never)]
    pub(super) fn fd_close_t(&mut self, ti: u32, fd: RawFd) {
        self.sfd(ti, -1);
        self.fd_close(fd)
    }

    /// `n` counted fds were closed. Two unused blocks: one goes back (with a C flag fd_trim looks every time).
    #[inline]
    pub(super) fn fd_put(&mut self, n: u32) {
        let u = self.stats.fds.get();
        if cfg!(any(test, debug_assertions)) {
            assert!(u >= n as u64, "60.57 fd count underflow");
        }
        let u = u.saturating_sub(n as u64);
        self.stats.fds.set(u);
        if self.fd_have as u64 - u >= 2 * self.fd_block as u64 {
            self.fd_trim(false);
        }
    }

    /// fd_put out of line, for the places that are not on a per-connection or per-stream path (the splice pipes at a
    /// connection's end and in the sweep): their callers keep their code
    #[inline(never)]
    pub(super) fn fd_put_cold(&mut self, n: u32) {
        self.fd_put(n)
    }

    /// Return the allowance above one unused block (fd_put past two blocks; the idle sweep). A worker that holds no
    /// fd at all at its idle sweep returns everything: with few usable fds per worker (block 1) the idle workers would
    /// else keep one unit each from the busy ones.
    #[cold]
    #[inline(never)]
    pub(super) fn fd_trim(&mut self, idle: bool) {
        if idle && self.bd.is_some() {
            self.bd_sweep(); // 60.63 (the idle sweep's only call into section E)
        }
        let (used, block) = (self.stats.fds.get() as u32, self.fdg.block());
        let keep = if idle && used == 0 { 0 } else { block };
        let mut all = self.fd_have + self.fd_pool;
        let slack = all - used;
        // (a put: only past two blocks, which is fd_put's own test when C is off)
        if slack > keep && (idle || slack >= 2 * block) {
            self.fdg.give(slack - keep);
            all -= slack - keep;
        }
        self.fd_hold(all);
    }

    /// A4 room for one more fd (a CONNECT is checked before any DNS or socket work); takes a block if the allowance is
    /// used up, counts nothing
    #[inline]
    pub(super) fn fd_room(&mut self, ti: u32) -> bool {
        self.stats.fds.get() < self.fd_have as u64 || self.fd_more(ti)
    }

    /// (`ti`: the stream that asks, for the rules of section E; the fd count does not use it)
    #[cold]
    #[inline(never)]
    fn fd_more(&mut self, ti: u32) -> bool {
        if self.bd.is_some() && self.bd_room_short(ti) {
            return false; // 60.63 refused by a rule of section E, before any DNS work (fd_short sends the CLOSE)
        }
        if self.fd_pool > 0 {
            return true; // (a C flag is on)
        }
        let got = self.fdg.grab(self.fdg.block(), 1);
        self.fd_hold(self.fd_have + got);
        got > 0
    }

    /// A3 a connection was reset at accept because no fd is left under the limit: counter, --log-conns line, and the
    /// warning (rate-limited, independent of the optional logs)
    #[cold]
    #[inline(never)]
    pub(super) fn fd_refused_conn(&mut self, unix: bool, ss: &libc::sockaddr_storage) {
        self.stats.refuse_fd_conns.bump();
        if self.cfg.log_conns {
            let ip = if unix { Some(clientip::UNIX_PEER) } else { net::sockaddr_ip(ss) };
            self.log_refused(ip, Why::Limit);
        }
        if self.fdg.log_due(Line10::ConnFd) {
            metrics::log_nowait(format!(
                "finalwisp: out of file descriptors: new connections are reset at accept ({}); open connections go on. \
                 Fix: raise the open-file limit and restart ({FIX}) (counted as refuse_fd_conns; {EVERY})",
                self.fd_state()
            ));
        }
    }

    /// A5 a connection was reset at accept because the memory level is 2 or 3: counters (accept_paused once per
    /// episode, as before; refuse_level_conns per connection), --log-conns line, warning
    #[cold]
    #[inline(never)]
    pub(super) fn level_refused_conn(&mut self, unix: bool, ss: &libc::sockaddr_storage) {
        if !std::mem::replace(&mut self.accept_paused, true) {
            self.stats.accept_paused.bump(); // 60.12
        }
        self.stats.refuse_level_conns.bump();
        if self.cfg.log_conns {
            let ip = if unix { Some(clientip::UNIX_PEER) } else { net::sockaddr_ip(ss) };
            self.log_refused(ip, Why::PressureShed);
        }
        if self.fdg.log_due(Line10::ConnLevel) {
            metrics::log_nowait(format!(
                "finalwisp: memory level {}: new connections are reset at accept until the level is below 2; open connections \
                 go on. Fix: more memory for the server (its cgroup limit or --mem-budget), or fewer clients (counted as \
                 refuse_level_conns; {EVERY})",
                self.lvl
            ));
        }
    }

    /// A3 accept4 on `lfd` failed with EMFILE or ENFILE. The count and its reserve should make that impossible; it
    /// still happens when something else in the process holds fds, the limit was lowered while running, or the host's
    /// file table is full. Close this worker's spare fd, accept and reset up to SPARE_BATCH waiting connections, open
    /// the spare again. Best effort: another thread can take the freed slot first (then nothing is accepted here), and
    /// the spare may not open again (the next call tries). The caller keeps the 10 ms retry.
    #[cold]
    #[inline(never)]
    pub(super) fn accept_emfile(&mut self, lfd: RawFd) {
        if self.spare < 0 {
            self.spare = spare_fd();
        }
        let mut n = 0;
        if self.spare >= 0 {
            unsafe { libc::close(self.spare) };
            while n < SPARE_BATCH {
                let fd = unsafe { libc::accept4(lfd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
                if fd < 0 {
                    break;
                }
                net::linger_zero(fd);
                unsafe { libc::close(fd) };
                n += 1;
            }
            self.spare = spare_fd();
        }
        self.stats.refuse_fd_conns.add(n);
        if self.fdg.log_due(Line10::Emfile) {
            metrics::log_nowait(format!(
                "finalwisp: accept failed: the process or the host is out of file descriptors ({}), beyond what the server \
                 counts; {n} waiting connections were reset. Fix: raise the open-file limit and restart ({FIX}), or the \
                 host's fs.file-max (counted as accept_err_fd and refuse_fd_conns; {EVERY})",
                self.fd_state()
            ));
        }
    }

    /// A4 a stream was refused (0x49) because no fd is left under the limit: counter and warning
    #[cold]
    #[inline(never)]
    pub(super) fn fd_refused_stream(&mut self) {
        self.stats.refuse_fd.bump();
        if self.fdg.log_due(Line10::StreamFd) {
            metrics::log_nowait(format!(
                "finalwisp: out of file descriptors: new streams are refused with 0x49 ({}); open streams go on. \
                 Fix: raise the open-file limit and restart ({FIX}) (counted as refuse_fd; {EVERY})",
                self.fd_state()
            ));
        }
    }

    /// `1234 of 1234 usable fds in use, open-file limit 1024` for the warnings
    fn fd_state(&self) -> String {
        let soft = crate::fdgate::nofile().map_or("unknown".to_string(), |l| l.soft.to_string());
        match self.fdg.limit() {
            u32::MAX => format!("{} fds in use, open-file limit {soft}", self.fdg.used()),
            f => format!("{} of {f} usable fds in use, open-file limit {soft}", self.fdg.used()),
        }
    }

    /// A2/A4 no fd for a connect attempt of target `ti`. With another attempt in flight nothing happens (that one
    /// decides; run_timers tries again at its next tick); else the stream is refused: 0x49, counted (refuse_fd), logged.
    #[cold]
    #[inline(never)]
    pub(super) fn fd_short(&mut self, ti: u32) {
        if self.bd.is_some() {
            // 60.63 not the fd limit: a rule of section E stopped the attempt (its own counters and warnings)
            let why = self.bd_why();
            if why != 0 {
                return self.bd_short(ti, why);
            }
        }
        self.fd_short_fd(ti)
    }

    /// fd_short proper: no fd (try_connect_gated comes here directly)
    pub(super) fn fd_short_fd(&mut self, ti: u32) {
        if !self.targets.at(ti).conn.is_empty() {
            return;
        }
        self.fd_refused_stream();
        if !self.streamlog.is_empty() {
            self.slog_why(ti, SWhy::Limit, "fds"); // 60.35
        }
        self.fail_target(ti, CLOSE_THROTTLED);
    }

    /// A6 a stream whose connect failed: `reason` 0x43 = timed out, anything else = failed
    #[cold]
    pub(super) fn connect_failed(&self, reason: u8) {
        (if reason == CLOSE_TIMEOUT { &self.stats.connect_timeout } else { &self.stats.connect_fail }).bump();
    }

    /// close a counted fd (refusals at accept, a failed epoll registration)
    #[inline(never)]
    pub(super) fn fd_close(&mut self, fd: RawFd) {
        unsafe { libc::close(fd) };
        self.fd_put(1);
    }

    /// --balance: an accepted (counted) fd leaves for another worker with its unit of allowance
    pub(super) fn fd_send(&mut self) {
        debug_assert!(self.stats.fds.get() > 0 && self.fd_have > 0);
        self.stats.fds.set(self.stats.fds.get().saturating_sub(1));
        self.fd_have = self.fd_have.saturating_sub(1);
    }

    /// ... and arrives here (inbox_ready)
    pub(super) fn fd_recv(&mut self) {
        self.stats.fds.add(1);
        self.fd_have += 1;
    }

    /// The fds this worker's connections and streams hold, by walking them (tests: must equal Stats::fds)
    /// C --fd-admission: a connection was reset at accept because the host mark is set: counter, --log-conns line,
    /// warning (the crossing itself is logged by the gate)
    #[cold]
    #[inline(never)]
    pub(super) fn mark_refused_conn(&mut self, unix: bool, ss: &libc::sockaddr_storage) {
        self.stats.refuse_mark_conns.bump();
        if self.cfg.log_conns {
            let ip = if unix { Some(clientip::UNIX_PEER) } else { net::sockaddr_ip(ss) };
            self.log_refused(ip, Why::Limit);
        }
        if self.fdg.log_due(Line10::ConnMark) {
            metrics::log_nowait(format!(
                "finalwisp: --fd-admission: new connections are reset at accept ({}; from 7/8 of the usable fds until below \
                 13/16); open connections go on. Fix: raise the open-file limit and restart ({FIX}) (counted as \
                 refuse_mark_conns; {EVERY})",
                self.fd_state()
            ));
        }
    }

    /// C --conn-share: a connection of an address over its share was refused (reset at accept, 429 behind a trusted
    /// proxy): counter and warning. The address is in the --log-conns line only.
    #[cold]
    #[inline(never)]
    pub(super) fn share_refused(&self) {
        self.stats.refuse_share_conns.bump();
        if self.fdg.log_due(Line10::ConnShare) {
            let (key, floor) = crate::fdgate::share_rule(self.fdg.limit());
            metrics::log_nowait(format!(
                "finalwisp: --conn-share: one address holds more than {key} fds while others hold {floor} or more ({}): its \
                 new connections are refused, its open ones go on (--log-conns shows the address). Fix: raise the open-file \
                 limit and restart ({FIX}); if that address is your reverse proxy, set --trusted-proxy so that clients are \
                 told apart; or --no-conn-share (counted as refuse_share_conns; {EVERY})",
                self.fd_state()
            ));
        }
    }

    /// C --conn-share: the rule for a new connection of client address `ip`: Some((key, floor)) while the share mark
    /// is set (clientip charge_share). None: the flag is off, the mark is not set, or the address is never gated: a
    /// loopback, private or link-local one (a proxy or a bridge in front of many users) and a --trusted-proxy (an
    /// unparsable header charges the proxy's own address).
    #[inline]
    pub(super) fn share_rule(mask: u8, fdg: &FdGate, cip: &clientip::ClientIp, ip: std::net::IpAddr) -> Option<(u32, u32)> {
        if mask & MARK_SHARE == 0 || fdg.marks() & MARK_SHARE == 0 || net::local_peer(ip) || cip.is_trusted(ip) {
            return None;
        }
        Some(crate::fdgate::share_rule(fdg.limit()))
    }

    /// 60.20 / 60.57 C charge one connection to client address `ip` (key `k`): the per-IP limits and, while the share
    /// mark is set, the --conn-share rule. One call for both callers (accept, and the upgrade behind a trusted proxy)
    /// and out of line: the upgrade is inlined into process_frames, the per-frame function, which keeps one call there.
    #[inline(never)]
    pub(super) fn ip_charge(
        mask: u8,
        fdg: &FdGate,
        idx: usize,
        cip: &clientip::ClientIp,
        t: &clientip::IpTable,
        k: clientip::IpKey,
        ip: std::net::IpAddr,
    ) -> clientip::Charge {
        let rule = Self::share_rule(mask, fdg, cip, ip);
        t.charge_share(k, cip.max_conns, clientip::now_ms(), idx, rule)
    }

    /// C --conn-share: stream `ti` holds `d` more (or fewer) fds: noted for its connection. Called only from the
    /// out-of-line helpers above.
    #[inline]
    fn sfd(&mut self, ti: u32, d: i32) {
        if self.fd_mask & MARK_SHARE != 0 {
            let t = self.targets.at(ti);
            let (ci, cg) = (t.client, t.cgen);
            self.sfd_note(ci, cg, d);
        }
    }

    /// C --conn-share: connection `ci` (generation `cg`) holds `d` more counted fds besides its own socket: target
    /// sockets, connect attempts, its splice pipe. Called beside the fd_take / fd_put of those fds, so the number is
    /// the connection's part of this worker's count (Stats::fds). Published to its key in steps (sfd_apply).
    #[cold]
    #[inline(never)]
    pub(super) fn sfd_note(&mut self, ci: u32, cg: u32, d: i32) {
        if self.clients.get(ci, cg).is_some() {
            Self::sfd_apply(&mut self.sfds, &self.peers_of, &self.cfg, self.idx, ci, d);
        }
    }

    /// sfd_note on the worker's fields (the idle sweep calls it inside its loop over the clients, before it closes a
    /// pipe). Up: published once the connection holds SHARE_BATCH more than it published. Down: at once when it holds
    /// fewer than it published, and then SHARE_BACK below what it holds. So what a connection published is never
    /// more than what it holds, and a decrease is published before the fds are given back.
    pub(super) fn sfd_apply(sfds: &mut Vec<[u32; 2]>, peers_of: &[Option<clientip::Peer>], cfg: &Config, idx: usize, ci: u32, d: i32) {
        let i = ci as usize;
        if sfds.len() <= i {
            sfds.resize(i + 1, [0, 0]);
        }
        let [own, published] = sfds[i];
        debug_assert!(i64::from(own) + i64::from(d) >= 0, "60.57 per-connection fd count underflow");
        let own = (i64::from(own) + i64::from(d)).max(0) as u32;
        sfds[i][0] = own;
        if own >= published + SHARE_BATCH {
            Self::sfd_publish(sfds, peers_of, cfg, idx, ci, own);
        } else if own < published {
            Self::sfd_publish(sfds, peers_of, cfg, idx, ci, own.saturating_sub(SHARE_BACK));
        }
    }

    /// C the published fds of connection `ci` become `to` (at most what it holds). A connection without a key
    /// (untracked: its shard was full; no header behind a trusted proxy; a unix client) publishes nothing.
    fn sfd_publish(sfds: &mut [[u32; 2]], peers_of: &[Option<clientip::Peer>], cfg: &Config, idx: usize, ci: u32, to: u32) {
        let Some(k) = peers_of.get(ci as usize).and_then(Option::as_ref).and_then(|p| p.key) else { return };
        let Some(t) = cfg.clientip.as_ref().and_then(|c| c.table.as_ref()) else { return };
        let was = sfds[ci as usize][1];
        if to != was {
            t.add_fds(k, i64::from(to) - i64::from(was), idx);
            sfds[ci as usize][1] = to;
        }
    }

    /// C the idle sweep: every connection publishes its exact number (the steps of sfd_apply leave it up to
    /// SHARE_BATCH - 1 below)
    #[cold]
    #[inline(never)]
    pub(super) fn sfd_sweep(&mut self) {
        for ci in 0..self.sfds.len() {
            let [own, published] = self.sfds[ci];
            if own != published {
                Self::sfd_publish(&mut self.sfds, &self.peers_of, &self.cfg, self.idx, ci as u32, own);
            }
        }
    }

    /// C connection `ci` ends (its streams are closed, its pipe is closed next): what it published goes back, before
    /// its key is released
    #[cold]
    #[inline(never)]
    pub(super) fn sfd_end(&mut self, ci: u32) {
        if (ci as usize) < self.sfds.len() {
            Self::sfd_publish(&mut self.sfds, &self.peers_of, &self.cfg, self.idx, ci, 0);
            self.sfds[ci as usize] = [0, 0];
        }
    }

    /// A3 + C the fd of a socket that accept4 returned, as fd_take(1) (the same inline test, no test of a C flag):
    /// FD_OK = counted; else why not (FD_NONE no fd left under the limit, FD_MARK --fd-admission's host mark is set)
    #[inline]
    pub(super) fn fd_take_conn(&mut self) -> u8 {
        let u = self.stats.fds.get() + 1;
        if u <= self.fd_have as u64 {
            self.stats.fds.set(u);
            FD_OK
        } else {
            self.fd_grab_conn()
        }
    }

    /// ... past `fd_have`: with --fd-admission every accept comes here (fd_hold), and the host mark is read
    #[cold]
    #[inline(never)]
    fn fd_grab_conn(&mut self) -> u8 {
        if self.fd_mask & MARK_HOST != 0 && self.fdg.marks() & MARK_HOST != 0 {
            FD_MARK
        } else if self.fd_grab(1) {
            FD_OK
        } else {
            FD_NONE
        }
    }

    #[cfg(test)]
    pub(super) fn fds_held(&self) -> u64 {
        let clients: usize = self
            .clients
            .slots
            .iter()
            .filter_map(|s| s.1.as_ref())
            .filter(|c| !c.dead)
            .map(|c| 1 + c.pipe.iter().filter(|&&p| p >= 0).count())
            .sum();
        let targets: usize = self.targets.slots.iter().filter_map(|s| s.1.as_ref()).map(|t| (t.fd >= 0) as usize + t.conn.len()).sum();
        // C: what is noted for a connection is what its streams and its pipe hold, and it never published more
        for (ci, own) in self.sfds.iter().enumerate() {
            let streams: usize = self
                .targets
                .slots
                .iter()
                .filter_map(|s| s.1.as_ref())
                .filter(|t| t.client as usize == ci)
                .map(|t| (t.fd >= 0) as usize + t.conn.len())
                .sum();
            let pipe = self.clients.slots[ci].1.as_ref().map_or(0, |c| c.pipe.iter().filter(|&&p| p >= 0).count());
            assert_eq!(own[0] as usize, streams + pipe, "60.57 C fds noted for connection {ci}");
            assert!(own[1] <= own[0], "60.57 C connection {ci} published {} of {} fds", own[1], own[0]);
        }
        (self.pending.len() + clients + targets) as u64
    }
}
