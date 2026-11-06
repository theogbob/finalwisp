//! 20.26 memory levels: applying a stage (queues, socket caps, credit) when the level changes.

use super::*;

/// 70.14 flush frees a drained client output buffer (obuf, bulk) above the stage's `keep` only at level 2+; at
/// level 1 only from 4 x keep (2 MiB) up, more than L1's own growth makes. Kept buffers stay until the idle
/// sweep, as at level 0. With the 16 KiB mmap threshold each free was an munmap and the regrow an mmap +
/// mremaps + page faults: strace, potato download at 32-128M (level 1 the whole run): the bulk lane grew
/// 69632 -> 135168 -> 266240 -> 528384 (Vec doubling from room + CHUNK lands 24 bytes above L1's keep of
/// 512 KiB; with an unsent prefix and read_target's compaction rule up to 1048624) and was freed at every
/// drain, ~230 cycles per 3 GiB; base-1.1 recycled it inside the arena. Review (review): a lane grown
/// at level 0 (2-4 MiB) that was not drained when level 1 started is still freed at its first drain. Level 1
/// bounds the queued bytes (out_high, out_hard) as before. set_level drops drained buffers above `keep` once
/// when `keep` shrinks (L0 -> L1, L1 -> L2), not on the way down.
#[inline]
pub(super) fn free_drained(level: usize, cap: usize, keep: usize) -> bool {
    match level {
        0 => false, // keep = usize::MAX
        1 => cap >= keep.saturating_mul(4),
        _ => cap > keep,
    }
}

/// 60.12 #2 review: what a drained upload backlog (pend) keeps. Levels 0/1: the stage's `keep`; levels 2/3: out_high
/// (64 KiB, the pre-60.12 keep there). pend grows by packets, not by reserve(room + CHUNK), so the 132 KiB obuf
/// keep does not apply: it would retain up to 128 KiB per stream at the levels meant to shed memory.
#[inline]
pub(super) fn pend_keep(level: usize, st: &mem::Stage) -> usize {
    if level >= 2 {
        st.out_high
    } else {
        st.keep
    }
}

impl Worker {
    /// 20.26 apply a new memory pressure level (mem::STAGES): buffer caps on live sockets, drained
    /// buffers above the new size, client reads, shedding, admission. Once per level change,
    /// O(clients + targets); the I/O paths only read `self.st`.
    pub(super) fn set_level(&mut self, l: usize) {
        // 20.31 (b): one cap_level read per change; the stage's socket fields and every client_caps/target_caps use it
        self.set_levels(l, mem::cap_level(l));
    }

    /// set_level with the cap level given (tests: no global TCP level). B: the first TCP-only cap level (0, 1) also reads
    /// the locality of every socket not yet classified (two syscalls each, once per socket; tcp_only_local)
    pub(super) fn set_levels(&mut self, l: usize, cl: usize) {
        let old = std::mem::replace(&mut self.st, mem::stage(l, cl));
        let old_l = std::mem::replace(&mut self.lvl, l);
        self.capl = cl;
        if (l >= 2) != (old_l >= 2) {
            mem::cache_pause(l >= 2); // 60.09 M2 first: the dirty set is capped at L2_BYTES before the buffers freed below land in it
        }
        let st = self.st;
        self.max_streams = mem::max_streams(&mem::STAGES[l]); // 20.31 (b): host TCP caps do not limit streams
        self.rbuf_max = mem::rbuf_max(l);
        self.win = mem::grant_window(cl); // 20.31 (b2) credit from the cap level
        let bulk_was = std::mem::replace(&mut self.bulk_at, mem::bulk_at(cl));
        if self.bulk_at > bulk_was {
            // r5 review: a stream the level-1 rule marked bulk re-qualifies under the new rule on its
            // next read (a CHUNK at level 0, as a stream that never saw level 1); splice_target already
            // hands a stream with splice_pending back to the copy path, so this is the short-splice case
            for t in self.targets.slots.iter_mut().filter_map(|s| s.1.as_mut()) {
                t.bulk = false;
            }
        }
        (self.l3_mark, self.l3_sweeps) = (u64::MAX, 0);
        // B: the same-host exemption holds at memory level 0 only, so crossing it refits the caps even if their sizes stay
        let ml0 = (l == 0) != (old_l == 0);
        if ml0
            || st.sock_cap != old.sock_cap
            || st.client_rcv != old.client_rcv
            || st.client_snd != old.client_snd
            || st.target_snd != old.target_snd
        {
            let (floor0, stats) = (self.floor0, &self.stats);
            let fit = |fd: RawFd, saved: &mut (i32, i32), sizes: Option<(u32, u32)>| {
                if let Some(v) = sizes {
                    if *saved == (0, 0) && floor0 {
                        *saved = net::buf_sizes(fd);
                    }
                    net::cap_bufs(fd, v);
                    stats.cap_apply.bump(); // 60.12
                } else if *saved != (0, 0) {
                    net::uncap_bufs(fd, std::mem::take(saved));
                    stats.cap_restore.bump();
                }
            };
            for c in self.clients.slots.iter_mut().filter_map(|s| s.1.as_mut()) {
                if !c.dead {
                    // 60.31 C7 a unix client: like a same-host one at level 0 (no TCP memory)
                    let sz = (st.sock_cap > 0 && !(c.local == LOCAL_UNIX && l == 0) && !tcp_only_local(&mut c.local, c.fd, l))
                        .then(|| mem::client_caps(cl));
                    fit(c.fd, &mut c.saved, sz);
                }
            }
            for t in self.targets.slots.iter_mut().filter_map(|s| s.1.as_mut()) {
                if t.fd >= 0 && !t.udp {
                    // 20.26 r4: live sockets are (re)capped at once at a transition; after a lift they
                    // are capped lazily again if a capped level returns. B: a same-host target is not capped
                    // by the host TCP level alone (memory level 0)
                    let sz = (st.sock_cap > 0 && !tcp_only_local(&mut t.local, t.fd, l)).then(|| mem::target_caps(&st));
                    fit(t.fd, &mut t.saved, sz);
                    (t.capped, t.moved) = (st.sock_cap > 0, 0);
                }
            }
        } else if st.sock_cap > 0 {
            // r4 review: same caps as before (level 2 <-> 3), but a target that connected since may
            // still be waiting for its lazy cap: cap it now, as the transition promises
            let floor0 = self.floor0;
            for t in self.targets.slots.iter_mut().filter_map(|s| s.1.as_mut()) {
                if t.fd >= 0 && !t.udp && !t.capped {
                    if !tcp_only_local(&mut t.local, t.fd, l) {
                        if floor0 && t.saved == (0, 0) {
                            t.saved = net::buf_sizes(t.fd);
                        }
                        net::cap_bufs(t.fd, mem::target_caps(&st));
                        self.stats.cap_apply.bump(); // 60.12
                    }
                    t.capped = true;
                }
            }
        }
        if cl > 0 && old.hs > st.hs {
            // r4 review: a stream that was granted level-0 credit keeps the server-side `credit` that
            // gates its next refill (since >= credit); with 128 it would run its whole level-0 grant
            // before the first small CONTINUE replaced it (up to 128 x 16 KiB per stream). A smaller
            // `credit` only makes the refill earlier: one CONTINUE then takes the leftover back, as r3 did.
            let g = self.cfg.buffer.min(st.hs);
            for t in self.targets.slots.iter_mut().filter_map(|s| s.1.as_mut()) {
                t.credit = t.credit.min(g);
            }
        }
        if st.keep < old.keep && self.up_n == 0 {
            for c in self.clients.slots.iter_mut().filter_map(|s| s.1.as_mut()) {
                if c.dead {
                    continue;
                }
                if c.ohead == c.obuf.len() && c.splice_at == NO_MARK && c.obuf.capacity() > st.keep {
                    c.obuf = Vec::new();
                    c.ohead = 0;
                }
                if c.bhead == c.bulk.len() && c.bulk.capacity() > st.keep {
                    c.bulk_drop(); // everything sent: nothing is lost
                }
                let hs = matches!(c.state, CState::Tls | CState::Http);
                if c.rpos == c.rlen && c.frag.is_none() && !hs && c.rbuf.len() > self.rbuf_max {
                    c.rbuf = Vec::new(); // regrows from RBUF_MIN on the next read (as after the idle sweep)
                    (c.rpos, c.rlen, c.rfull) = (0, 0, false);
                }
            }
            for t in self.targets.slots.iter_mut().filter_map(|s| s.1.as_mut()) {
                if t.phead == t.pend.len() && t.pend.capacity() > pend_keep(l, &st) {
                    t.pend = Vec::new();
                    t.phead = 0;
                }
            }
        }
        if st.shed > 0 && old.shed == 0 {
            // critical: streams sitting on a big upload backlog (a target that does not read) go
            // review E: unsent bytes only (SIOCOUTQNSD), so a healthy upload with much data in flight stays
            let shed: Vec<u32> = (0..self.targets.slots.len() as u32)
                .filter(|&i| {
                    self.targets.slots[i as usize].1.as_ref().is_some_and(|t| {
                        !t.raw && !t.udp && t.fd >= 0 && t.pend.len() - t.phead + net::outq_unsent(t.fd).max(0) as usize > st.shed
                    })
                })
                .collect();
            self.stats.shed_l3_enter.add(shed.len() as u64); // 60.12
            self.shed(shed, "l3");
        }
        if (st.read && !old.read) || (l < 2 && old_l >= 2) {
            // (60.05 H7b: below level 2 the clients holding a big partial frame are read again)
            for (i, (g, slot)) in self.clients.slots.iter().enumerate() {
                if slot.as_ref().is_some_and(|c| !c.dead && c.readable) {
                    self.ready.push(tok(K_CLIENT, i as u32, *g));
                }
            }
        }
        if st.admit && self.accept_paused {
            self.accept_paused = false;
            self.accept_all();
        }
    }
}
