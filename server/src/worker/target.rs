//! 20.05 TCP target streams: the Target record, lazy socket caps (20.26 r4, 20.31 B), reads (copy path and splice),
//! EOF and close.

use super::*;

#[derive(PartialEq, Clone, Copy)]
pub(super) enum TState {
    Resolving,
    Connecting,
    Open,
}

pub(super) struct Target {
    pub(super) fd: RawFd,
    pub(super) client: u32,
    pub(super) cgen: u32,
    pub(super) sid: u32,
    pub(super) state: TState,
    pub(super) port: u16,
    pub(super) addrs: Vec<IpAddr>,
    pub(super) attempt: usize,
    pub(super) pend: Vec<u8>,
    pub(super) phead: usize,
    pub(super) since: u32,
    pub(super) rdhup: bool,
    pub(super) blocked: Park, // 20.35 (Park: Run / Parked / Released; one byte, as the bool it replaced)
    pub(super) raw: bool,
    pub(super) wrote_since_read: bool,
    // 20.25 the target sent TCP urgent data (EPOLLPRI seen; sticky). read() stops short at the urgent
    // mark with ordinary data still queued, so a short read is "drained" only if not at the mark.
    // Known gap (review): the kernel raises PRI only once the urgent byte is in hand (TCP_URG_VALID); a
    // pointer that stays NOTYET with data queued (RFC 793 "last byte" senders, or the byte still
    // out of order) is not seen. Only a misbehaving target hits it, and it stalls only its own stream.
    pub(super) urg: bool,
    pub(super) lane_read: bool, // oh256: any read (copy or splice, either lane) since its last park in Client::blocked_bulk
    pub(super) bulk: bool,      // last copy read filled CHUNK: use the splice path next
    pub(super) bulk_end: u64,   // 20.19 end of this stream's last frame in the client's bulk lane (absolute)
    // 20.14 happy eyeballs: while Connecting, every in-flight attempt lives in `conn` (fd stays -1);
    // `attempt` counts addresses started; the first attempt to connect becomes `fd`.
    pub(super) conn: Vec<RawFd>,
    pub(super) next_try: Instant,
    pub(super) err: i32, // last connect error, for the CLOSE reason when every attempt fails
    // 70.10 (--dns-own) connecting on an early answer (one address family); the final answer with the other family is
    // still due (Worker::dns_late). With no address left to try, the target waits for it (parked: no attempt, unlisted).
    pub(super) dns_more: bool,
    // 20.15 TFO: pend[phead..phead + tfo_sent] went out in the SYN of `tfo_fd`; dropped from pend
    // only if that socket wins (another winner gets the bytes again).
    pub(super) tfo_fd: RawFd,
    pub(super) tfo_sent: usize,
    pub(super) deadline: Instant,
    pub(super) cidx: usize, // index in Worker::connecting, NOT_LISTED when absent
    // 20.16 UDP stream: connected datagram socket, no credit. Until Open, `pend` holds the queued
    // datagrams as [u16 LE length][bytes] records.
    pub(super) udp: bool,
    // 20.26 flow control: `credit` = the last CONTINUE grant; `allow` = packets the client may
    // legitimately send since that CONTINUE (new grant + what the previous one left in flight)
    pub(super) credit: u32,
    pub(super) allow: u32,
    pub(super) saved: (i32, i32), // 20.26 SO_RCVBUF/SO_SNDBUF before net::cap_bufs ((0, 0) = not capped)
    pub(super) acct: usize,       // 20.26 upload backlog counted in Worker::pend_total (updated in after_write)
    // 20.26 r4 lazy socket caps: `moved` = bytes read from / written to this socket while uncapped
    // under a capped stage; at LAZY_CAP the caps are set (Worker::lazy_cap). A short stream never pays.
    pub(super) capped: bool,
    pub(super) moved: u32,
    // 70.13 TCP keepalive set (Worker::sweep arms Open TCP targets: a stream that ends before the next sweep never pays)
    pub(super) keepalive: bool,
    // 20.26 r4 upload packets and bytes from the client (the mean packet size sizes the grant in
    // bytes under pressure, after_write)
    pub(super) upkts: u32,
    pub(super) ubytes: u64,
    pub(super) umax: u32, // 60.13 the largest upload packet (credit::Stream::resume rebuilds pmax from it)
    // 20.30 --credit-v2 TCP streams: bound and window. 60.13: created on first use (Worker::push_continue, after_write,
    // credit_pong), so idle and download-only streams cost what they cost without v2; None = not yet, off, UDP, wsproxy
    pub(super) cv: Option<Box<credit::Stream>>,
    // B (20.31 redesign): 0 = not known yet, 1 = remote, 2 = the target is on this host (tcp_only_local)
    pub(super) local: u8,
}

pub(super) const NOT_LISTED: usize = usize::MAX;

/// 20.35 a target's park state (Target::blocked). A park (read_target, splice_target, read_udp) turns Run into Parked
/// and lists the target once in its client's `blocked` or `blocked_bulk`. Only a release (Worker::release_parked, from
/// flush_dirty and starve_check) un-lists it: Parked -> Released, with one entry in Worker::ready. Worker::resume then
/// makes it Run and reads; a ready entry that finds it Parked is stale (pushed before the park: a read-budget
/// continuation, or a second entry of the same release) and is dropped, since the target is still listed and its
/// release is its wake. Before 20.35 any ready entry un-parked: on VPS1 such entries started 98 % of the download copy
/// runs (the target copied while its own splice was still in the pipe) and re-parked it while it was still listed, so
/// the lists filled with duplicates (the 20.35 note's diagnostic counts). Every other reader asks
/// `!= Park::Run`, so a Released target is still parked for them until its entry runs: it reads nothing on its own
/// events (lane order), a credit-pace grant stays held (60.42), bounds relief and the unread count see it parked.
/// Invariant (debug: Worker::park_check): Parked <=> exactly one entry in its client's two lists; Run, Released => none.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u8)]
pub(super) enum Park {
    Run,
    Parked,
    Released,
}
const _: () = assert!(std::mem::size_of::<Park>() == std::mem::size_of::<bool>()); // 20.35 no struct growth

impl Target {
    /// 60.27 C6: connected to the upstream proxy, handshake running (Connecting with the proxy socket in fd; a direct
    /// connect keeps fd -1 until won, its attempts live in conn). Invariants: conn and addrs empty, a proxy_hs entry,
    /// listed in Worker::connecting (worker/upstream.rs).
    #[inline]
    pub(super) fn in_handshake(&self) -> bool {
        self.state == TState::Connecting && self.fd >= 0
    }
}

/// 20.26 r4: a target socket is capped once the stream moved this many bytes (reads counted after,
/// writes before). Below it the kernel buffers cannot have grown: a fresh socket's rcvbuf stays at
/// tcp_rmem[1] until autotuning has seen ~128-200 KiB read (loopback probe, kernels 6.8/6.17), and
/// the send queue holds at most what was written. mem::max_streams counts such a stream as
/// tcp_rmem[1] + LAZY_CAP bytes. Churn (one 64-byte request and reply per stream) had paid 2
/// setsockopt per stream, +16% of its syscalls.
pub const LAZY_CAP: u32 = 16 * 1024;

/// B (20.31 redesign): the cap due now comes only from the host TCP level (memory level `ml` 0) and the socket (client
/// or target: `local`, `fd`) is on this host: no cap. What a capped receive buffer refuses waits in the sender's send
/// queue, which for a same-host sender is host TCP memory too, so the cap cannot lower it (b3cpu, VPS2 loopback: host
/// pages 32k -> 47k median with the caps, a self-sustaining TCP level 1), and below the loopback MSS (64 KiB) it made
/// each read run the local sender's transmit (server CPU per MiB 2.4-2.8x; the client caps ~0.13 ms/MiB of it).
/// Remote sockets keep the caps (1 Gbit bench: echo 50 MiB/s with the client caps, 46.6 without). Gap: a peer on
/// another address of this host (not loopback, not our local address) counts as remote. Behind a same-host reverse
/// proxy every client is same-host, so the TCP level caps no client there. `local`: 0 = not known yet, 1 = remote,
/// 2 = this host; read once per socket (two syscalls), only when such a cap is due.
pub(super) fn tcp_only_local(local: &mut u8, fd: RawFd, ml: usize) -> bool {
    if ml != 0 {
        return false;
    }
    if *local == 0 {
        *local = if net::same_host(fd) { 2 } else { 1 };
    }
    *local == 2
}

/// 60.31 C7 Client::local for a unix-socket client: no TCP (no TCP_INFO, keepalive, nodelay) and no host TCP memory, so
/// never capped at memory level 0 (the two client call sites test it before tcp_only_local; the target path is unchanged)
pub(super) const LOCAL_UNIX: u8 = 3;

impl Worker {
    /// 20.26 r4: count `n` bytes moved on target `ti` (reads after, writes before the syscall); at
    /// LAZY_CAP set the stage's socket caps. Nothing to do once capped, without a capped stage, for
    /// UDP, or before the socket exists (the bytes are counted again when it does). Tolerates a gone
    /// target (flush_upload runs after the batch).
    #[inline]
    pub(super) fn lazy_cap(&mut self, ti: u32, n: usize) {
        let (st, floor0, ml) = (self.st, self.floor0, self.lvl);
        let Some(t) = self.targets.slots.get_mut(ti as usize).and_then(|s| s.1.as_mut()) else { return };
        if t.capped || st.sock_cap == 0 || t.udp || t.fd < 0 {
            return;
        }
        t.moved = t.moved.saturating_add(n.min(u32::MAX as usize) as u32);
        if t.moved >= LAZY_CAP {
            if tcp_only_local(&mut t.local, t.fd, ml) {
                t.capped = true; // (decided: no cap; set_level revisits it at a level change)
                return;
            }
            if floor0 && t.saved == (0, 0) {
                t.saved = net::buf_sizes(t.fd);
            }
            net::cap_bufs(t.fd, mem::target_caps(&st));
            t.capped = true;
            self.stats.cap_apply.bump(); // 60.12
        }
    }
}

impl Worker {
    pub(super) fn target_event(&mut self, ti: u32, tg: u32, e: u32) {
        let Some(t) = self.targets.get(ti, tg) else { return };
        if t.udp {
            // 20.16: EPOLLIN = datagrams, EPOLLERR = ICMP error. `rdhup` (unused for UDP) = an error
            // is pending: read_udp then reads until EAGAIN instead of trusting a short batch.
            if e & libc::EPOLLERR as u32 != 0 {
                t.rdhup = true;
            }
            if t.state == TState::Open && e & (libc::EPOLLIN | libc::EPOLLERR) as u32 != 0 {
                self.read_udp(ti);
            }
            return;
        }
        // 20.14: the token is shared by all connect attempts, so a hangup event may belong to a loser
        // closed earlier in this batch: once Open, confirm it on the real fd (only on hangup events).
        if e & libc::EPOLLPRI as u32 != 0 {
            t.urg = true;
        }
        if e & (libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 && t.state == TState::Open && !t.rdhup {
            t.rdhup = net::peer_closed(t.fd);
        }
        match t.state {
            TState::Connecting => {
                if t.in_handshake() {
                    // 60.27 C6 proxy handshake, before the event mask below (an EPOLLIN-only event is a reply here)
                    return self.proxy_event(ti, tg, e);
                }
                if e & (libc::EPOLLOUT | libc::EPOLLERR | libc::EPOLLHUP) as u32 == 0 {
                    return;
                }
                self.connect_progress(ti);
                if self.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                    self.read_target(ti);
                }
            }
            TState::Open => {
                if e & libc::EPOLLOUT as u32 != 0 && t.pend.len() > t.phead {
                    self.flush_pending(ti);
                    if self.targets.get(ti, tg).is_none() {
                        return;
                    }
                }
                if e & (libc::EPOLLIN | libc::EPOLLPRI | libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
                    self.read_target(ti);
                }
            }
            TState::Resolving => {}
        }
    }

    /// Download path: read target bytes straight into the client's output buffer behind a
    /// reserved header gap, then write the headers in front. Zero payload copies.
    pub(super) fn read_target(&mut self, ti: u32) {
        let tg = self.targets.gen(ti);
        let mut slen = 0; // 60.46 splice length, fixed for this call at its first splice (no growth within one call)
        for _ in 0..BUDGET {
            let t = self.targets.at(ti);
            if t.blocked != Park::Run {
                return; // 20.35 (Released too: it reads when its ready entry runs, Worker::resume)
            }
            let (fd, ci, sid, raw, rdhup) = (t.fd, t.client, t.sid, t.raw, t.rdhup);
            let (bulk, bulk_end) = (t.bulk, t.bulk_end);
            let c = self.clients.at(ci);
            // 20.19 lane choice: bulk-mode streams (and streams with unsent bytes in the bulk lane,
            // which must keep their order) go to `bulk`; everything else to obuf. The splice path is
            // a bulk-mode read too: with --prio it counts as lane (cap Stage::out_high_bulk).
            let lane = self.cfg.prio && !raw && (bulk || bulk_end > c.bulk_sent);
            let pending = c.out_pending();
            // 50.02 B: a starved kTLS client's streams may read `starve_room` bytes past the caps (Worker::starve_check)
            let sroom = c.starve_room as usize;
            let past = (lane && pending >= self.st.out_high_bulk) || pending >= self.st.out_high;
            // 20.37 rule S: a bulk lane stream whose read cannot splice now waits (splice_wait) instead of copying behind
            // the pipe's payload or the lane's frames; the same park as at out_high_bulk. Not past a cap, not in a kTLS
            // starve episode (its slices), not without a pipe or with splicing off (copy path as before)
            let swait = bulk
                && lane
                && !past
                && c.starve == 0
                && c.splice != SPLICE_OFF
                && c.pipe[0] >= 0
                && !(c.splice_pending == 0 && c.obuf.len() == c.ohead && c.bulk.len() == c.bhead)
                && splice_wait(c, &mut self.lane_fence, ti, tg, bulk_end);
            if (lane && pending >= self.st.out_high_bulk && sroom == 0) || swait {
                self.targets.at(ti).blocked = Park::Parked;
                c.splice = c.splice.min(SPLICE_SLOW); // 60.46 backed up (also through the copy path): FAST -> SLOW, OFF stays
                                                      // Round-robin: the cap gap is only ~3 reads, so the first resumed stream refills it and the
                                                      // others park again without reading. Those keep their order at the front (behind earlier
                                                      // non-readers since the last drain); a stream that read since its last park goes to the
                                                      // back. Plain FIFO let one stream take nearly all of the lane (a page response waited behind
                                                      // the download: 100 Mbit page p50 +16-25%); insert(0) reversed the list and starved 3+
                                                      // streams (review P0); a rotate at the drain starved one of two streams when no-read rounds
                                                      // alternate (review P1); "no read in this call" missed reads before a BUDGET requeue (r3).
                let t = self.targets.at(ti);
                let read = std::mem::replace(&mut t.lane_read, false);
                if read {
                    c.blocked_bulk.push(tok(K_TARGET, ti, tg));
                } else {
                    let at = c.bulk_waiting.min(c.blocked_bulk.len());
                    c.blocked_bulk.insert(at, tok(K_TARGET, ti, tg));
                    c.bulk_waiting = at + 1;
                }
                return;
            }
            if pending >= self.st.out_high && sroom == 0 {
                self.targets.at(ti).blocked = Park::Parked;
                c.splice = c.splice.min(SPLICE_SLOW); // 60.46 (as above)
                c.blocked.push(tok(K_TARGET, ti, tg));
                return;
            }
            let want = if past { STARVE_SLICE.min(sroom) } else { CHUNK }; // 50.02 B: one slice per stream per retry
            if c.ohead > 0 && c.ohead >= c.obuf.len() - c.ohead {
                c.compact();
            }
            if c.bhead > 0 && c.bhead >= c.bulk.len() - c.bhead {
                c.compact_bulk();
            }
            let c = self.clients.at(ci);
            if bulk && !past && c.splice != SPLICE_OFF && c.splice_pending == 0 && c.obuf.len() == c.ohead && c.bulk.len() == c.bhead {
                if let Some(f) = self.lane_fence.get_mut(ti as usize) {
                    f.0 = 0; // 20.37 G: a splice ends the stream's L2 wait (splice_wait)
                }
                if slen == 0 {
                    // off (--no-adaptive-splice): SPLICE_PIPE always, the v1.1.1 length (Client::splice is still kept up to date)
                    // 60.51 and only for a far client (60.78 classified here at its first need: worker/splicefar.rs)
                    let adaptive =
                        self.cfg.adaptive_splice && c.splice == SPLICE_SLOW && c.streams.len() > SPLICE_FEW && self.splice_is_far(ci);
                    slen = if adaptive { SPLICE_SLICE } else { SPLICE_PIPE };
                }
                match self.splice_target(ti, ci, fd, sid, raw, slen) {
                    SpliceRes::Again => continue,
                    SpliceRes::Done => return,
                }
            }
            let c = self.clients.at(ci);
            let room = if raw { ROOM_RAW } else { ROOM_WISP };
            let dst = if lane { &mut c.bulk } else { &mut c.obuf };
            dst.reserve(room + CHUNK);
            let base = dst.len();
            // SAFETY: reserve() above: capacity >= base + room + CHUNK, so the read stays in the spare capacity.
            let n = unsafe { libc::read(fd, dst.as_mut_ptr().add(base + room) as *mut _, want) };
            if n > 0 {
                let n = n as usize;
                if past {
                    let c = self.clients.at(ci);
                    c.starve_room -= n as u32; // (n <= want <= starve_room)
                    c.starve_read += n as u64;
                    self.stats.ktls_starve_read.add(n as u64);
                    self.stats.ktls_starve_conn_max.max(c.starve_read);
                }
                let t = self.targets.at(ti);
                t.wrote_since_read = false;
                t.bulk = n >= self.bulk_at; // r5: mem::bulk_at (level 0: a full CHUNK, as before)
                t.lane_read = true;
                if !t.capped {
                    self.lazy_cap(ti, n); // 20.26 r4
                }
                let c = self.clients.at(ci);
                c.active = true;
                let dst = if lane { &mut c.bulk } else { &mut c.obuf };
                // SAFETY: same buffer as the read (nothing touched it since), so capacity >= base + room + CHUNK and
                // n <= CHUNK. Every byte up to the new length is written: the WS header (hl = 2 or 4, length fits:
                // const assert after ROOM_RAW), the Wisp header (room - 4 = 5 bytes, not raw) at hl, the data at
                // hl + room - 4 (read there, or moved there when hl = 2). set_len = base + hl + (room - 4) + n.
                unsafe {
                    let p = dst.as_mut_ptr().add(base);
                    let plen = n + room - 4; // WS payload = (room - 4 WS-header bytes) + data
                    let mut hl = 4;
                    if plen <= 125 {
                        // small: 2-byte WS header; shift the (<=125 byte) payload left by 2
                        std::ptr::copy(p.add(room), p.add(room - 2), n);
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
                    let end = c.bulk_frame_done();
                    self.targets.at(ti).bulk_end = end;
                }
                let c = self.clients.at(ci);
                if !c.dirty {
                    c.dirty = true;
                    self.dirty.push((ci, self.clients.gen(ci)));
                }
                if n < want && !rdhup && !(self.targets.at(ti).urg && net::at_mark(fd)) {
                    return; // drained (EPOLLET: next arrival raises a new edge)
                }
                if past {
                    // 50.02 B: one slice per stream per retry (review: else the first resumed stream took the
                    // whole room every time); parked again at the back until the next retry or the drain
                    let t = self.targets.at(ti);
                    t.blocked = Park::Parked;
                    let c = self.clients.at(ci);
                    if lane {
                        c.blocked_bulk.push(tok(K_TARGET, ti, tg));
                    } else {
                        c.blocked.push(tok(K_TARGET, ti, tg));
                    }
                    return;
                }
            } else if n == 0 {
                self.target_eof(ti, CLOSE_VOLUNTARY);
                return;
            } else {
                let e = net::errno();
                if would_block(e) {
                    return;
                }
                self.target_eof(ti, net::data_reason(e));
                return;
            }
        }
        self.ready.push(tok(K_TARGET, ti, tg));
    }

    /// 20.08 client `ci`'s splice pipe, opened at its first spliced read. false = no pipe for now (copy path; tried
    /// again after PIPE_RETRY). 60.57 A2: out of line (once per client, so read_target keeps its code), and the pipe's
    /// two fds are counted; none left under the fd limit is the same as a failed pipe2.
    #[cold]
    #[inline(never)]
    pub(super) fn pipe_open(&mut self, ci: u32) -> bool {
        if Instant::now() < self.pipe_retry_at {
            return false;
        }
        let mut p = [-1; 2];
        let counted = self.fd_take(2);
        if !counted || unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
            if counted {
                self.fd_put(2);
            }
            // 60.05 H6: out of fds/pipes is temporary: copy path for a while (as below), not forever
            self.pipe_retry_at = Instant::now() + PIPE_RETRY;
            return false;
        }
        // 30.09: over the per-user pipe quota the kernel refuses the size (EPERM) and the pipe
        // holds only 2 pages: not worth splicing through, so use the copy path for a while. A
        // refusal from fs.pipe-max-size < 256 KiB leaves the default 64 KiB pipe: keep it and
        // splice as before 30.09 (review r1).
        if unsafe { libc::fcntl(p[1], libc::F_SETPIPE_SZ, SPLICE_PIPE as libc::c_int) } < 0
            && unsafe { libc::fcntl(p[1], libc::F_GETPIPE_SZ) } < MIN_SPLICE_PIPE as libc::c_int
        {
            unsafe {
                libc::close(p[0]);
                libc::close(p[1]);
            }
            self.fd_put(2);
            self.pipe_retry_at = Instant::now() + PIPE_RETRY;
            return false;
        }
        self.clients.at(ci).pipe = p;
        if self.fd_mask & crate::fdgate::MARK_SHARE != 0 {
            // 60.57 C the pipe's two fds in the connection's count
            Self::sfd_apply(&mut self.sfds, &self.peers_of, &self.cfg, self.idx, ci, 2);
        }
        true
    }

    /// 20.08 splice download: target socket -> pipe -> client socket, payload never enters user
    /// space. Only used when nothing else is queued for the client, so stream order is trivial.
    /// 60.46: moves at most `len` bytes (SPLICE_PIPE, or with --adaptive-splice SPLICE_SLICE for a backed-up client with many
    /// streams: read_target).
    fn splice_target(&mut self, ti: u32, ci: u32, fd: RawFd, sid: u32, raw: bool, len: usize) -> SpliceRes {
        if self.clients.at(ci).pipe[0] < 0 && !self.pipe_open(ci) {
            self.targets.at(ti).bulk = false;
            return SpliceRes::Again;
        }
        let c = self.clients.at(ci);
        let n = unsafe {
            libc::splice(fd, std::ptr::null_mut(), c.pipe[1], std::ptr::null_mut(), len, libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK)
        };
        if n <= 0 {
            // TCP urgent data: splice stops at the urgent mark and reports EAGAIN/0 even though
            // ordinary data (or no FIN) is still queued. read() handles the mark; use it once.
            let eagain = n < 0 && would_block(net::errno());
            if (n == 0 || eagain) && net::at_mark(fd) {
                self.targets.at(ti).bulk = false;
                return SpliceRes::Again;
            }
            if n < 0 {
                let e = net::errno();
                if eagain {
                    return SpliceRes::Done;
                }
                if e == libc::EINVAL || e == libc::ENOSYS {
                    c.splice = SPLICE_OFF; // kernel/socket cannot splice: copy path from now on
                    self.targets.at(ti).bulk = false;
                    return SpliceRes::Again;
                }
                self.target_eof(ti, net::data_reason(e));
            } else {
                self.target_eof(ti, CLOSE_VOLUNTARY);
            }
            return SpliceRes::Done;
        }
        let n = n as usize;
        let (plen, mut hdr) = (n + if raw { 0 } else { 5 }, [0u8; 10]);
        let hl = ws::write_header(&mut hdr, OP_BIN, plen);
        c.obuf.extend_from_slice(&hdr[..hl]);
        if !raw {
            c.obuf.push(PKT_DATA);
            c.obuf.extend_from_slice(&sid.to_le_bytes());
        }
        c.splice_at = c.obuf.len();
        c.splice_pending = n;
        c.active = true; // 20.11: splice traffic counts as I/O for the idle sweep
        let broken = c.flush().is_err();
        let t = self.targets.at(ti);
        t.wrote_since_read = false;
        t.bulk = n >= SPLICE_MIN;
        t.lane_read = true;
        if !t.capped {
            self.lazy_cap(ti, n); // 20.26 r4
        }
        if broken {
            // 60.24 Why::Io: errno of the failed flush (lazy_cap's setsockopt calls leave it unless they fail too)
            self.close_client(ci, Why::Io);
            return SpliceRes::Done;
        }
        let c = self.clients.at(ci);
        let whole = c.splice_pending == 0 && c.ohead == c.obuf.len();
        c.splice = if whole { SPLICE_FAST } else { SPLICE_SLOW }; // 60.46 (not OFF here: EINVAL returned above)
        if !whole {
            // Client socket full: the rest goes out on EPOLLOUT via flush_dirty. Park the target in
            // `blocked` so flush_dirty resumes it — with EPOLLET a target whose data (and FIN) is
            // already buffered raises no new event, so without this the stream stalls forever.
            let tg = self.targets.gen(ti);
            self.targets.at(ti).blocked = Park::Parked;
            if self.cfg.prio && !raw {
                c.blocked_bulk.push(tok(K_TARGET, ti, tg)); // oh256: a splicing stream is bulk mode (it read: back)
                self.targets.at(ti).lane_read = false;
            } else {
                c.blocked.push(tok(K_TARGET, ti, tg));
            }
            if !c.dirty {
                c.dirty = true;
                self.dirty.push((ci, self.clients.gen(ci)));
            }
            return SpliceRes::Done;
        }
        c.obuf.clear();
        c.ohead = 0;
        // deliberate: never treat a short splice as "drained" (the pipe can run out of page slots
        // before bytes); only EAGAIN means drained. BUDGET bounds this loop.
        SpliceRes::Again
    }

    pub(super) fn target_eof(&mut self, ti: u32, reason: u8) {
        let t = self.targets.at(ti);
        if t.raw {
            let ci = t.client;
            if !self.streamlog.is_empty() {
                self.slog_raw_reason(ti, reason); // 60.35 (wsproxy sends no code: close_target gets None)
            }
            self.close_target(ti, None);
            let c = self.clients.at(ci);
            if !c.dead && !c.closing {
                ws::push_frame(&mut c.obuf, OP_CLOSE, &[&1000u16.to_be_bytes()]);
                self.begin_close(ci, Why::ServerClose);
            }
        } else {
            self.close_target(ti, Some(reason));
        }
    }

    pub(super) fn fail_target(&mut self, ti: u32, reason: u8) {
        self.target_eof(ti, reason)
    }

    pub(super) fn close_target(&mut self, ti: u32, reason: Option<u8>) {
        if self.targets.slots.get(ti as usize).is_none_or(|s| s.1.is_none()) {
            return;
        }
        if let Some(b) = self.up_bufs[..self.up_n].iter().position(|b| b.ti == ti && !b.iov.is_empty()) {
            self.flush_bucket(b); // data the client sent before CLOSE still goes out first
            if self.targets.slots.get(ti as usize).is_none_or(|s| s.1.is_none()) {
                return; // the flush hit a write error and already closed this target
            }
        }
        self.unlist(ti);
        if !self.streamlog.is_empty() {
            self.slog_close(ti, reason); // 60.35 (the target still in the slab, its socket open: TCP_INFO)
        }
        let tg = self.targets.gen(ti);
        let Some(t) = self.targets.remove(ti) else { return };
        if self.cfg.upstream.is_some() && t.state != TState::Open {
            if let Some(h) = self.proxy_hs.get_mut(ti as usize) {
                *h = None; // 60.27 C6 closed mid-open (client CLOSE, client gone, deadline): the side entry goes too
            }
        }
        // 60.12 gauge (also here: an idle worker stops sweeping, and the sweep's value would stay)
        self.stats.streams.set((self.targets.slots.len() - self.targets.free.len()) as u64);
        if self.cfg.dns_own && (t.dns_more || (t.state == TState::Resolving && t.addrs.is_empty())) {
            self.inbox.dns_live.lock().unwrap().remove(&tok(K_TARGET, ti, tg)); // 70.09 cancel the lookup (if any)
        }
        if t.acct > 0 {
            self.pend_account(t.client, 0, t.acct); // 20.26 (the client is still alive: close_client drops streams first)
        }
        if let Some(s) = t.cv.as_ref() {
            self.starve_pool += s.extra; // 20.30
        }
        if t.fd >= 0 {
            // Client-initiated close (reason None) of a live target with nothing left unsent or
            // unacked: abort with RST (SO_LINGER 0) so no TIME_WAIT piles up on our side. Under
            // stream churn TIME_WAIT made every connect() scan the ephemeral port space
            // (366% sys CPU at 16k streams/s). Wisp CLOSE 0x02 already means "reset".
            // Only when the target spoke last (it answered after our last write, so its app has
            // consumed what we sent) — otherwise RST could discard unread request bytes.
            if reason.is_none()
                && self.cfg.abort_close
                && !t.udp
                && t.state == TState::Open
                && !t.rdhup
                && !t.wrote_since_read
                && t.pend.len() == t.phead
                && net::outq(t.fd) == 0
            {
                net::linger_zero(t.fd);
            }
            unsafe { libc::close(t.fd) };
        }
        for &fd in &t.conn {
            unsafe { libc::close(fd) }; // 20.14 attempts still in flight
        }
        let closed = (t.fd >= 0) as u32 + t.conn.len() as u32; // 60.57 A2
        if closed > 0 {
            self.fd_put_c(t.client, t.cgen, closed); // (C: noted for the connection before the allowance can go back)
        }
        let Some(c) = self.clients.get(t.client, t.cgen) else { return };
        if t.blocked != Park::Run {
            // 20.35 Parked: its one entry (Released: listed nowhere, its ready entry fails the generation check)
            let tk = tok(K_TARGET, ti, tg);
            c.blocked.retain(|&x| x != tk);
            // keep the non-reader prefix exact
            let (mut i, waiting) = (0, c.bulk_waiting);
            let mut gone_in_prefix = 0;
            c.blocked_bulk.retain(|&x| {
                let keep = x != tk;
                gone_in_prefix += (!keep && i < waiting) as usize;
                i += 1;
                keep
            });
            c.bulk_waiting -= gone_in_prefix;
        }
        if c.dead || t.raw {
            return;
        }
        if c.streams.get(&t.sid) == Some(&ti) {
            c.streams.remove(&t.sid);
        }
        if let Some(r) = reason {
            if !c.closing {
                // 20.34 the CLOSE of an open TCP stream that its destination ended (FIN or error) waits for the PONG of a
                // PING queued behind its DATA (worker/pinggate.rs); 0x49 = the server's own limits cut the stream: at once
                let held = t.state == TState::Open
                    && !t.udp
                    && r != CLOSE_THROTTLED
                    && pinggate::hold(&mut self.gate, c, &t, r, self.now, &self.stats);
                if !held {
                    self.stats.close[r as usize].bump(); // 60.12 (20.34: counted when sent)
                    if t.bulk_end > c.bulk_sent {
                        // 20.19 the stream still has DATA queued in the bulk lane: its CLOSE goes behind it
                        let mut h = [0u8; 6];
                        h[0] = PKT_CLOSE;
                        h[1..5].copy_from_slice(&t.sid.to_le_bytes());
                        h[5] = r;
                        ws::push_frame(&mut c.bulk, OP_BIN, &[&h]);
                        c.bulk_frame_done();
                    } else {
                        c.push_wisp(PKT_CLOSE, t.sid, &[r]);
                    }
                }
                if !c.dirty {
                    c.dirty = true;
                    self.dirty.push((t.client, t.cgen));
                }
            }
        }
    }
}

/// 20.37 rule S, for a bulk lane stream whose read cannot splice now (Worker::read_target): true = park it. S1: a payload
/// is in the client's pipe (the read could only copy behind it). L1: its own frames are in the lane (a splice would
/// overtake them). L2: only other streams' frames are in the lane and obuf is empty: wait until the frames queued now are
/// sent, by a fence at the lane's end in `fences` (per target slot: the generation's 30 bits + 1, 0 = none; absolute lane
/// position; another generation is no fence). Target::bulk_end is not touched: the lane choice, CLOSE placement and the
/// ping gate read it as "this stream's last real lane frame" (pinggate flush_held drops a held CLOSE whose stream has
/// DATA in the lane).
/// G: at most one L2 wait between two reads: a passed fence is cleared and the stream copies behind the frames (as
/// before 20.37); a splice clears it too (read_target). Otherwise (obuf busy, no fence) it copies, as before.
/// A wait ends when the pipe drained (flush_dirty's release gate), the frames before the stream's own last frame or its
/// fence went out, and the connection's output fell below out_low_bulk (the release rule before 20.37: a sibling that
/// keeps it above holds every parked bulk stream, in base too; 20.37 parks a stream sooner). Out of line: at most once
/// per read that cannot splice.
#[inline(never)]
fn splice_wait(c: &Client, fences: &mut Vec<(u32, u64)>, ti: u32, tg: u32, bulk_end: u64) -> bool {
    if c.splice_pending > 0 || bulk_end > c.bulk_sent {
        return true; // S1, L1
    }
    let g1 = (tg & 0x3fff_ffff) + 1; // never 0 (= cleared); the token's 30 bits, as Slab::get compares them
    match fences.get_mut(ti as usize) {
        Some(f) if f.0 == g1 => {
            if f.1 > c.bulk_sent {
                return true; // L2 goes on: the frames before the fence are not all sent
            }
            f.0 = 0; // G: passed: this read copies
            false
        }
        _ if c.bulk.len() != c.bhead && c.obuf.len() == c.ohead => {
            let i = ti as usize;
            if fences.len() <= i {
                fences.resize(i + 1, (0, 0)); // (grown only here)
            }
            fences[i] = (g1, c.bulk_sent + (c.bulk.len() - c.bhead) as u64); // L2: the lane's end now (Client::bulk_end)
            true
        }
        _ => false,
    }
}

enum SpliceRes {
    Again, // keep reading this target
    Done,  // stop (drained, blocked, or target/client closed)
}
