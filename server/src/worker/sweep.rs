//! 20.11 / 20.26 the idle sweep (every IDLE_SWEEP_MS): idle buffers, dead peers, holds, stalls, and the shedding
//! at memory levels 2-3.

use super::*;

impl Worker {
    /// 20.11: every IDLE_SWEEP_MS, give back the buffers of clients that did no I/O during a whole
    /// period and hold nothing. They regrow on the next read (from RBUF_MIN) or target read (reserve).
    /// true = a sweep ran (70.25 run() then trims the pool's dirty set, after reap_dead). `now`: the turn's time (run:
    /// Worker::now, read after epoll_wait; 60.47)
    pub(super) fn idle_sweep(&mut self, now: Instant) -> bool {
        if now < self.next_sweep {
            return false;
        }
        // review (60.09 M4a): whole periods from the old deadline keep this worker's phase (from `now`, an
        // epoll_wait(-1) without clients would let every worker's deadline expire and line them up again)
        let p = Duration::from_millis(IDLE_SWEEP_MS);
        let behind = (now - self.next_sweep).as_millis() / p.as_millis();
        self.next_sweep += p * (behind as u32 + 1);
        self.sweep();
        if self.dns_cache.capacity() != 0 {
            self.dns_expire(now); // 60.41 (capacity: a table emptied by lookups still has slots to give back)
        }
        if self.meter {
            self.meter_sweep(); // 60.25 C10b (after count_stalls in sweep: a new stall interval starts)
        }
        self.stats.rx_bytes.set(self.rx_total); // 60.25 C5
        if !self.pending.is_empty() {
            self.pending_sweep(); // 60.34 PROXY headers that did not come
        }
        if self.cfg.clientip.as_ref().is_some_and(|c| c.table.is_some()) || self.cfg.dest_rate.is_some() {
            self.table_sweep();
        }
        true
    }

    /// 60.20 C3b / 60.39 the shared tables' part of the idle sweep (out of line and cold: idle_sweep is inlined into run).
    /// SWEEP_SHARDS consecutive shards per sweep: refills live entries and drops idle ones (both clocks u64 ms: 60.45). Every awake
    /// worker walks all shards (review: a stride by the thread count left a sleeping worker's shards unswept); workers
    /// start spread out. The per-destination table (same shard count) shares the cursor.
    #[cold]
    #[inline(never)]
    fn table_sweep(&mut self) {
        let ip = self.cfg.clientip.as_ref().and_then(|c| c.table.as_ref());
        let dest = self.cfg.dest_rate.as_deref();
        let now = clientip::now_ms();
        for _ in 0..clientip::SWEEP_SHARDS {
            if let Some(t) = ip {
                t.sweep(self.ip_sweep, now);
            }
            if let Some(d) = dest {
                d.sweep(self.ip_sweep, metrics::now_ms()); // (u64 ms: no wrap)
            }
            self.ip_sweep = (self.ip_sweep + 1) % clientip::SHARDS;
        }
        if let Some(t) = ip {
            self.stats.ip_keys_max.set(t.keys() as u64);
        }
        if let Some(d) = dest {
            self.stats.dest_keys_max.set(d.keys() as u64);
        }
    }

    pub(super) fn sweep(&mut self) {
        if self.up_n != 0 {
            return; // staged iovecs point into some rbuf (cannot happen here: flushed each turn)
        }
        // 60.12 gauge
        self.stats.streams.set((self.targets.slots.len() - self.targets.free.len()) as u64);
        // targets first: they read their client's `active` before the client loop clears it
        let keepalive = self.cfg.keepalive;
        for (_, slot) in self.targets.slots.iter_mut() {
            let Some(t) = slot.as_mut() else { continue };
            // 70.13 dead-target detection (net::KEEP_*), armed here and not at connect: churn streams that
            // end within a sweep skip the 4 setsockopt (cf. LAZY_CAP); detection comes at most one sweep
            // later. A failed setsockopt only loses the detection.
            if keepalive && !t.keepalive && !t.udp && t.state == TState::Open && t.fd >= 0 {
                t.keepalive = true;
                net::set_keepalive(t.fd);
            }
            if t.phead == t.pend.len() && t.pend.capacity() > 0 {
                let idle = self.clients.slots.get(t.client as usize).and_then(|s| s.1.as_ref()).is_some_and(|c| !c.active);
                if idle {
                    t.pend = Vec::new();
                    t.phead = 0;
                }
            }
        }
        // 20.30 --credit-v2 liveness net (review): the grant rule depends on time (a ping outstanding past
        // PONG_LATE falls back to the base rule) and on the level, and neither change writes the target, so
        // nothing else re-runs after_write for a stream whose client waits on credit. Off: no client has `cv`.
        if self.cfg.credit_v2 {
            let tis: Vec<u32> = (0..self.targets.slots.len() as u32)
                .filter(|&ti| {
                    self.targets.slots[ti as usize].1.as_ref().is_some_and(|t| {
                        // 60.13: also a stream not yet v2 of a client that has a Pinger (its first v2 decision may be due)
                        // (review r5: and any uploader: before 60.13 every client had a Pinger, so the sweep reached
                        // every TCP stream, e.g. one that became refill-eligible at a level change with no write after it)
                        t.state == TState::Open
                            && !t.udp
                            && (t.cv.is_some()
                                || t.upkts > 0
                                || self.clients.slots.get(t.client as usize).and_then(|s| s.1.as_ref()).is_some_and(|c| c.cv.is_some()))
                    })
                })
                .collect();
            for ti in tis {
                if self.targets.slots.get(ti as usize).is_some_and(|s| s.1.is_some()) {
                    self.after_write(ti);
                }
            }
            // a waiting epoch whose ping PING_GAP held back, with no CONTINUE or pong since
            let now = Instant::now();
            let mut pinged = Vec::new();
            for (ci, slot) in self.clients.slots.iter_mut().enumerate() {
                let Some(c) = slot.1.as_mut() else { continue };
                if let Some(s) = c.cv.as_mut().filter(|_| !c.closing && !c.dead).and_then(|p| p.next(now)) {
                    ws::push_frame(&mut c.obuf, OP_PING, &[&s.to_le_bytes()]);
                    pinged.push(ci as u32);
                }
            }
            for ci in pinged {
                self.mark_dirty(ci);
            }
        }
        // 60.05 H7c: big partial frames first (levels 2 and 3; not in the same round as the others: USED
        // predates what that freed)
        if self.lvl >= 2 {
            self.count_stalls();
        }
        let shed = self.lvl >= 2 && self.shed_partial();
        if !shed && !self.pend_sweep() {
            self.l3_sweep(); // 20.26 (not in a round that just shed: USED predates what that freed)
        }
        let mut expired = Vec::new(); // review r1: handshakes past HS_SWEEPS (active or not: slowloris)
        let mut gone = Vec::new(); // 70.02 dead peers with output queued
        let mut stuck = Vec::new(); // 20.27 0x49 hold: hpaused clients past HOLD_SWEEPS
        for (i, (_, slot)) in self.clients.slots.iter_mut().enumerate() {
            let Some(c) = slot.as_mut() else { continue };
            if c.hpaused && !c.dead {
                // 20.27 0x49 hold: the hold stops every stream of the connection, so it is bounded in time whether or
                // not the target drains (review: a trickling target would hold it for minutes)
                c.hp_sweeps += 1;
                if c.hp_sweeps >= HOLD_SWEEPS {
                    stuck.push(i as u32);
                }
            }
            if matches!(c.state, CState::Http | CState::WaitInfo) && !c.dead && !c.closing {
                c.hs_sweeps += 1;
                if c.hs_sweeps >= HS_SWEEPS {
                    expired.push(i as u32);
                }
            }
            if std::mem::replace(&mut c.active, false) || c.dead {
                // (gone_ack kept: `active` also means target reads; an ACK from the client makes the ACK age
                // small, which clears it at the next sweep that checks)
                continue;
            }
            // 70.02 output queued (ours, or only in the kernel: a finished response the peer never ACKed) and
            // no read for a whole sweep: a slow (zero-window) reader, or a peer that vanished. TCP keepalive
            // does not run while data is unacknowledged; TCP_INFO tells them apart (only for these clients).
            // `active` is a sampling gate (set by reads, not writes); the kernel's ACK clock decides.
            // 70.06 acted on at the second sweep in a row that sees it with no ACK in between (the ACK clock
            // only went up): a reply to a probe sent just before the first sweep is not just in flight.
            // 60.31 C7 not for unix clients: no TCP_INFO, and a local peer that dies closes its socket
            let suspect = keepalive && c.local != LOCAL_UNIX && (c.out_pending() > 0 || net::outq(c.fd) > 0);
            match suspect.then(|| net::peer_gone(c.fd)).flatten() {
                Some(ms) if c.gone_ack != 0 && ms > c.gone_ack => {
                    gone.push(i as u32);
                    continue;
                }
                Some(ms) => c.gone_ack = ms,
                None => c.gone_ack = 0,
            }
            if c.rpos == c.rlen && c.frag.is_none() && c.state != CState::Http && c.rbuf.capacity() > 0 {
                c.rbuf = Vec::new();
                c.rpos = 0;
                c.rlen = 0;
            }
            if c.ohead == c.obuf.len() && c.splice_at == NO_MARK && c.obuf.capacity() > 0 {
                c.obuf = Vec::new();
                c.ohead = 0;
            }
            if c.bhead == c.bulk.len() && c.bulk.capacity() > 0 {
                c.bulk_drop(); // 20.19 drained: nothing is lost
            }
            // 30.09: an idle client's splice pipe is empty (splice_at == NO_MARK means nothing is
            // queued in it): close it. It costs 2 fds and 64 pages of the user's pipe quota
            // (fs.pipe-user-pages-soft, 16384 pages by default = 256 such pipes per user).
            if c.pipe[0] >= 0 && c.splice_at == NO_MARK && c.splice_pending == 0 {
                for p in c.pipe {
                    unsafe { libc::close(p) };
                }
                c.pipe = [-1, -1];
            }
        }
        for ci in stuck {
            // close with 0x49 every stream still over PEND_HARD (review r2: several can cross it in one batch; a
            // survivor over it would take another batch after the release), or if none is (a trickle just
            // under it) the largest one over PEND_RESUME; then read again. Streams under that are kept (review
            // r1) and hold again only if they pass PEND_HARD themselves. Base closed such streams at once.
            let c = self.clients.at(ci);
            let tis: Vec<u32> = c.streams.values().copied().collect();
            let acct = |ti: u32| self.targets.slots.get(ti as usize).and_then(|s| s.1.as_ref()).map_or(0, |t| t.acct);
            let mut kill: Vec<u32> = tis.iter().copied().filter(|&ti| acct(ti) > PEND_HARD).collect();
            if kill.is_empty() {
                kill.extend(tis.into_iter().filter(|&ti| acct(ti) > PEND_RESUME).max_by_key(|&ti| acct(ti)));
            }
            self.stats.hold_expired.bump(); // 60.12
            self.stats.shed_hold.add(kill.len() as u64);
            self.shed(kill, "shed_hold");
            if let Some(c) = self.clients.slots.get_mut(ci as usize).and_then(|s| s.1.as_mut()) {
                if c.hpaused {
                    c.hpaused = false;
                    let g = self.clients.gen(ci);
                    self.ready.push(tok(K_CLIENT, ci, g));
                }
            }
        }
        self.stats.hs_expired.add(expired.len() as u64); // 60.12
        for ci in expired {
            self.close_client(ci, Why::HsTimeout);
        }
        for ci in gone {
            if !self.clients.at(ci).dead {
                self.stats.dead_peers.bump(); // 60.12 (review: not one an expired handshake just closed)
            }
            // RST to the client: a plain close would leave an orphan socket that keeps its send queue and
            // probes the dead peer for minutes more (measured on 6.8: still listed after 260 s). Its targets
            // close as usual (--graceful-close: FIN, upload bytes already queued are delivered).
            self.reset_client(ci, Why::DeadPeer); // (an expired handshake closed above is not touched again)
        }
    }

    /// 20.26 (idle sweep) upload backlog still over pend_cap for PEND_SHED_SWEEPS sweeps in a row
    /// (a target that does not read, paused clients cannot add more): shed the largest backlogs
    /// until the total is under 3/4 of the cap (review B). Under the cap: resume any paused client.
    /// Also between 3/4 of the cap and the cap while clients are paused (review: a paused client whose
    /// rest sits on a stalled target would otherwise wait for an unrelated drain). true = shed.
    /// deliberate: at every level, as the pause itself (pend_cap is the budget's share for uploads).
    fn pend_sweep(&mut self) -> bool {
        if self.pend_total <= self.pend_cap / 4 * 3 {
            self.pend_over_sweeps = 0;
            if !self.pend_paused.is_empty() {
                self.pend_resume_all();
            }
            return false;
        }
        if self.pend_total <= self.pend_cap && self.pend_paused.is_empty() {
            self.pend_over_sweeps = 0;
            return false;
        }
        self.pend_over_sweeps += 1;
        if self.pend_over_sweeps < PEND_SHED_SWEEPS {
            return false;
        }
        self.pend_over_sweeps = 0;
        let mut big: Vec<(usize, u32)> = (0..self.targets.slots.len() as u32)
            .filter_map(|i| self.targets.slots[i as usize].1.as_ref().filter(|t| t.acct > 0).map(|t| (t.acct, i)))
            .collect();
        big.sort_unstable_by(|a, b| b.cmp(a));
        let (mut left, goal) = (self.pend_total, self.pend_cap / 4 * 3);
        let (mut tis, mut cis) = (Vec::new(), Vec::new());
        for (acct, ti) in big {
            if left <= goal {
                break;
            }
            left -= acct;
            let t = self.targets.at(ti);
            if t.raw {
                cis.push(t.client); // r3 review: a wsproxy target is its client's only stream
            } else {
                tis.push(ti);
            }
        }
        let shed = !tis.is_empty() || !cis.is_empty();
        self.stats.shed_pend.add(tis.len() as u64); // 60.12
        self.stats.shed_client.add(cis.len() as u64);
        self.shed(tis, "shed_pend");
        for ci in cis {
            self.abort_client(ci, Why::PressureShed);
        }
        shed
    }

    /// 20.26 (idle sweep) review C: at level 3 the clients with an upload backlog are not read (60.15 T03 P4: those
    /// without one are) and only upload backlogs are shed; partial frames in rbuf, output queues of clients that do not read, ... can keep the
    /// level up. When usage (mem::USED) made no new low for L3_STUCK_SWEEPS sweeps, close the clients
    /// holding the most buffer memory, about 1/8 of this worker's budget per round.
    fn l3_sweep(&mut self) {
        if !self.st.shed_clients {
            return;
        }
        let used = mem::USED.load(Relaxed);
        if used < self.l3_mark {
            (self.l3_mark, self.l3_sweeps) = (used, 0);
            return;
        }
        self.l3_sweeps += 1;
        if self.l3_sweeps < L3_STUCK_SWEEPS {
            return;
        }
        self.l3_sweeps = 0;
        // r3 review: count the kernel queues of the client's own socket and its targets too (most of a
        // stuck client can be socket memory); ioctls, but only here (a stuck level 3, every 2 sweeps)
        let mut held: Vec<usize> = self
            .clients
            .slots
            .iter()
            .map(|s| {
                s.1.as_ref().filter(|c| !c.dead).map_or(0, |c| {
                    c.rbuf.capacity()
                        + c.obuf.capacity()
                        + c.bulk.capacity()
                        + c.pend
                        + c.frag.as_ref().map_or(0, |f| f.1.capacity())
                        + net::inq(c.fd)
                        + net::outq(c.fd).max(0) as usize
                })
            })
            .collect();
        for t in self.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| !t.udp) {
            if let Some(h) = held.get_mut(t.client as usize) {
                for fd in std::iter::once(t.fd).chain(t.conn.iter().copied()).filter(|&fd| fd >= 0) {
                    *h += net::inq(fd) + net::outq(fd).max(0) as usize;
                }
            }
        }
        let mut big: Vec<(usize, u32)> = (0..held.len() as u32)
            .filter(|&i| self.clients.slots[i as usize].1.as_ref().is_some_and(|c| !c.dead))
            .map(|i| (held[i as usize], i))
            .collect();
        big.sort_unstable_by(|a, b| b.cmp(a));
        let goal = (mem::WORKER_BUDGET.load(Relaxed) / 8).max(1);
        let mut freed = 0;
        for (n, (held, ci)) in big.into_iter().enumerate() {
            // at least one client per stuck round, even if nothing measurable is held
            if freed >= goal || (held == 0 && n > 0) {
                break;
            }
            freed += held;
            let c = self.clients.at(ci);
            if c.out_empty() && c.tls.is_none() && !c.ktls_on && matches!(c.state, CState::Open | CState::WaitInfo | CState::Wsproxy) {
                // best effort WS Close 1013 (try again later); only on an empty output (no frame cut)
                let f = [0x88u8, 2, (1013u16 >> 8) as u8, 1013u16 as u8];
                unsafe { libc::send(c.fd, f.as_ptr() as *const _, 4, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
            }
            self.stats.shed_client.bump(); // 60.12
            self.abort_client(ci, Why::PressureShed); // r3 review: RST (the close frame above is sent at once on an empty queue)
        }
    }

    /// 60.05 H7c: at levels 2 and 3, on every sweep: close the clients holding a big partial frame or
    /// fragmented message (Client::frame_held; not read at level 2+, so they cannot progress), largest
    /// first, until the usage would be under level 2's exit threshold (admission resumes below it).
    /// Level 2 too: paused holders neither grow (no level 3) nor free anything, so level 2 with
    /// admission off would last as long as they stay connected. A client's held bytes are its buffers
    /// plus its socket's receive queue. Clients without a big partial frame keep the stuck rule
    /// (l3_sweep). deliberate: each worker frees up to the whole excess from its own holders, so the
    /// over-shedding is bounded to holders and an attack on one worker is not shed 1/threads per sweep.
    /// 70.02 also clients whose frame above rbuf_max made no progress for STALL_SWEEPS (count_stalls): a
    /// partial frame below HOLD_FLOOR, or one in a buffer grown earlier, is read, so it is not frame_held.
    /// true = something was shed (or there were candidates).
    fn shed_partial(&mut self) -> bool {
        let budget = mem::WORKER_BUDGET.load(Relaxed) as u64 * self.cfg.threads as u64;
        let excess = mem::USED.load(Relaxed).saturating_sub(budget * mem::STAGES[2].exit as u64 / 1000) as usize;
        excess > 0 && self.shed_holders(excess)
    }

    /// shed_partial for a given excess (bytes): holders (frame_held) and stalled uploads (count_stalls)
    pub(super) fn shed_holders(&mut self, excess: usize) -> bool {
        let rmax = self.rbuf_max;
        let mut big: Vec<(usize, u32)> = self
            .clients
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                let c = s.1.as_ref().filter(|c| !c.dead && (c.frame_held(rmax) || c.rstall >= STALL_SWEEPS))?;
                Some((c.rbuf.capacity() + c.frag.as_ref().map_or(0, |f| f.1.capacity()) + net::inq(c.fd), i as u32))
            })
            .collect();
        big.sort_unstable_by(|a, b| b.cmp(a));
        let mut freed = 0;
        for &(held, ci) in &big {
            if freed >= excess {
                break;
            }
            freed += held;
            self.stats.shed_holder.bump(); // 60.12
            self.abort_client(ci, Why::PressureShed); // RST (as the stuck rule below; a holder gets no 1013: it is an attack or a stalled upload)
        }
        !big.is_empty()
    }

    /// 70.02 (idle sweep, level 2+; level 3 does not read, so there it only resets) sweeps in a row in which
    /// a WebSocket client with an in-progress frame above rbuf_max delivered less than STALL_MIN_BYTES. Such
    /// a frame is read (below HOLD_FLOOR, or it fits a buffer grown earlier: not frame_held), so a client that
    /// sends part of it and stops (or drips) holds its buffer and is never shed by the holder rule;
    /// shed_partial sheds it after STALL_SWEEPS. 70.08 progress = TCP_INFO tcpi_bytes_received: bytes the
    /// kernel took in (read or not, also those a kTLS parser holds in an incomplete record; buffer positions
    /// repeat across frames). Not counted: a client we do not read now (paused for its upload backlog or
    /// output, closing, level 3 with an upload backlog), and a client the upload limiter paused during the interval
    /// (60.25 C10b: our doing; its baseline restarts, review).
    pub(super) fn count_stalls(&mut self) {
        let rmax = self.rbuf_max;
        let read = self.st.read;
        for (i, s) in self.clients.slots.iter_mut().enumerate() {
            let Some(c) = s.1.as_mut() else { continue };
            let ws = matches!(c.state, CState::Open | CState::WaitInfo | CState::Wsproxy);
            // 60.15 T03 P4: level 3 reads a client without upload backlog (read_client), so it counts too (review)
            let held = ws
                && !c.dead
                && !c.closing
                && c.need > rmax
                && (read || c.pend == 0)
                && !c.paused
                && !c.opaused
                && !c.mpaused
                && !c.hpaused;
            // 60.31 C7 (60.20 user f): no TCP_INFO for unix clients, so no stall shed for them (40.01)
            let rx = if held && c.local != LOCAL_UNIX { net::bytes_received(c.fd) } else { None };
            if rx.is_some() && self.meter && Worker::meter_blocked(&self.meters, i) {
                c.rstall = 0;
                c.rx_mark = rx.unwrap_or(NO_RX);
                continue;
            }
            c.rstall = match rx {
                Some(v) if c.rx_mark != NO_RX && v.wrapping_sub(c.rx_mark) < STALL_MIN_BYTES => c.rstall.saturating_add(1),
                _ => 0,
            };
            c.rx_mark = rx.unwrap_or(NO_RX);
        }
    }

    /// 20.26 close stream targets with RST and CLOSE 0x49 (memory pressure; a plain close() would keep
    /// an unsent queue alive as an orphan socket, still charged to the cgroup).
    /// `rule`: the --log-streams rule= (60.35)
    pub(super) fn shed(&mut self, tis: Vec<u32>, rule: &'static str) {
        for ti in tis {
            if !self.streamlog.is_empty() {
                self.slog_why(ti, SWhy::Pressure, rule);
            }
            if let Some(t) = self.targets.slots.get(ti as usize).and_then(|s| s.1.as_ref()) {
                if t.fd >= 0 {
                    net::linger_zero(t.fd);
                }
                self.close_target(ti, Some(CLOSE_THROTTLED));
            }
        }
    }
}
