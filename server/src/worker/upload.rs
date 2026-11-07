//! 20.09 / 20.33 upload path: batched writes to targets, the upload backlog (pend, 20.26 / 20.27 holds) and the
//! credit returned to the client (CONTINUE, credit v2 pings: 20.30, 60.13).

use super::*;

/// iovec list. SAFETY of Send: the Worker is moved to its thread once, while this is empty; the
/// pointers are only ever filled and used inside that thread within one process_input call.
/// 20.33 one target's staged upload iovecs (Worker::up_bufs)
pub(super) struct UpBucket {
    pub(super) ti: u32,
    pub(super) iov: Vec<libc::iovec>,
}

// SAFETY: the iovecs point into a client rbuf owned by the same Worker (thread); never shared across threads.
unsafe impl Send for UpBucket {}

const IOV_BATCH: usize = 64;

const UP_TARGETS: usize = 32; // 20.33 most targets staged at once (more: flush all first)

const UP_MAX: usize = 1024; // 20.33 most iovecs staged in all buckets together, then flush all (one writev takes <= IOV_BATCH)

impl Worker {
    /// 20.33 stage one DATA body (in the client's rbuf) for target `ti`: its bucket (first touch takes the next one; all
    /// UP_TARGETS in use flush all first). A bucket at IOV_BATCH flushes alone; UP_MAX staged in all flushes all.
    pub(super) fn stage_upload(&mut self, ti: u32, body: &[u8]) {
        let b = match self.up_bufs[..self.up_n].iter().position(|b| b.ti == ti) {
            Some(b) => b,
            None => {
                if self.up_n == UP_TARGETS {
                    self.flush_upload();
                }
                if self.up_n == self.up_bufs.len() {
                    self.up_bufs.push(UpBucket { ti, iov: Vec::with_capacity(IOV_BATCH) });
                }
                self.up_bufs[self.up_n].ti = ti;
                self.up_n += 1;
                self.up_n - 1
            }
        };
        self.up_bufs[b].iov.push(libc::iovec { iov_base: body.as_ptr() as *mut _, iov_len: body.len() });
        self.up_total += 1;
        if self.up_bufs[b].iov.len() >= IOV_BATCH {
            self.flush_bucket(b);
        }
        if self.up_total >= UP_MAX {
            self.flush_upload();
        }
    }

    /// 20.09 / 20.33 write everything staged: one writev per target, in first-touch order (per-stream order is kept:
    /// one bucket per target; across targets there is no order on the wire).
    pub(super) fn flush_upload(&mut self) {
        for b in 0..self.up_n {
            self.flush_bucket(b);
        }
        self.up_n = 0;
        debug_assert_eq!(self.up_total, 0);
        self.up_total = 0;
    }

    /// Upload path: send one target's staged DATA (iovecs into the unmasked WS read buffer) with one writev();
    /// copy only what the kernel refuses into `pend`. The bucket stays (empty) until flush_upload ends the batch.
    pub(super) fn flush_bucket(&mut self, b: usize) {
        let ti = self.up_bufs[b].ti;
        let iov = std::mem::take(&mut self.up_bufs[b].iov); // (empty while writing: close_target finds nothing to flush)
        self.up_total -= iov.len();
        if iov.is_empty() {
            self.up_bufs[b].iov = iov;
            return;
        }
        let total: usize = iov.iter().map(|v| v.iov_len).sum();
        self.lazy_cap(ti, total); // 20.26 r4 (before the write: the send queue never holds more uncapped)
        let Some(t) = self.targets.slots.get_mut(ti as usize).and_then(|s| s.1.as_mut()) else {
            self.up_bufs[b].iov = iov;
            self.up_bufs[b].iov.clear();
            return;
        };
        t.wrote_since_read = true;
        // SAFETY: each iovec points into a client's rbuf, which is not resized or freed until this flush
        // (see the up_bufs field doc); writev only reads them.
        let n = unsafe { libc::writev(t.fd, iov.as_ptr(), iov.len() as libc::c_int) };
        #[cfg(test)]
        {
            self.up_writevs += 1;
        }
        let mut done = if n < 0 {
            let e = net::errno();
            if !would_block(e) {
                self.up_bufs[b].iov = iov;
                self.up_bufs[b].iov.clear();
                self.target_eof(ti, net::data_reason(e));
                return;
            }
            0
        } else {
            n as usize
        };
        if done < total {
            // r3 review: the stage's cap for the rest, as in write_target (cold path)
            let over_credit = t.since > t.allow || t.raw; // (wsproxy has no credit: closed at the cap as before)
            let cap = if over_credit { self.st.pend_over } else { PEND_HARD };
            if total - done > cap {
                if over_credit {
                    self.up_bufs[b].iov = iov;
                    self.up_bufs[b].iov.clear();
                    self.stats.shed_over_credit.bump(); // 60.12
                    self.target_eof(ti, CLOSE_THROTTLED);
                    return;
                }
                if self.clients.at(t.client).hold() {
                    self.stats.holds.bump(); // 20.27 0x49 hold: in credit: stop reading the client, keep the data (60.12 counted)
                }
            }
            t.pend.clear();
            t.phead = 0;
            if self.lvl > 0 {
                t.pend.reserve_exact(total - done); // 20.26 r4 (as in write_target)
            }
            for v in &iov {
                // SAFETY: iov points into the client's rbuf, untouched since staging (see field doc)
                let s = unsafe { std::slice::from_raw_parts(v.iov_base as *const u8, v.iov_len) };
                if done >= s.len() {
                    done -= s.len();
                } else {
                    t.pend.extend_from_slice(&s[done..]);
                    done = 0;
                }
            }
        }
        self.up_bufs[b].iov = iov;
        self.up_bufs[b].iov.clear();
        self.after_write(ti);
    }

    pub(super) fn write_target(&mut self, ti: u32, data: &[u8]) {
        self.lazy_cap(ti, data.len()); // 20.26 r4 (queued data is counted again by flush_pending: harmless)
        let t = self.targets.at(ti);
        t.wrote_since_read = true;
        if t.state == TState::Open && t.pend.len() == t.phead {
            let n = unsafe { libc::write(t.fd, data.as_ptr() as *const _, data.len()) };
            let n = if n < 0 {
                let e = net::errno();
                if !would_block(e) {
                    self.target_eof(ti, net::data_reason(e));
                    return;
                }
                0
            } else {
                n as usize
            };
            if n < data.len() {
                // r3 review: the same cap as below for the rest of one big frame (cold path)
                let over_credit = t.since > t.allow || t.raw; // (wsproxy has no credit: closed at the cap as before)
                let cap = if over_credit { self.st.pend_over } else { PEND_HARD };
                if data.len() - n > cap {
                    if over_credit {
                        self.stats.shed_over_credit.bump(); // 60.12
                        self.target_eof(ti, CLOSE_THROTTLED);
                        return;
                    }
                    if self.clients.at(t.client).hold() {
                        self.stats.holds.bump(); // 20.27 0x49 hold (as in flush_upload)
                    }
                }
                t.pend.clear();
                t.phead = 0;
                t.pend.extend_from_slice(&data[n..]);
            }
        } else {
            // 20.26 a client past its credit (`allow`) gets the stage's smaller cap (1 MiB under hard pressure)
            let over_credit = t.since > t.allow || t.raw; // (wsproxy has no credit: closed at the cap as before)
            let cap = if over_credit { self.st.pend_over } else { PEND_HARD };
            if t.pend.len() - t.phead + data.len() > cap {
                if over_credit {
                    self.stats.shed_over_credit.bump(); // 60.12
                    self.target_eof(ti, CLOSE_THROTTLED);
                    return;
                }
                // 20.27 0x49 hold: within its credit the client is honest: what it sent was granted and is in flight
                // (absolute CONTINUE + refill at half let the in-flight data grow to the client's buffers on a
                // long path). Stop reading the client instead: the rest waits in TCP, memory stays bounded.
                if self.clients.at(t.client).hold() {
                    self.stats.holds.bump(); // 60.12
                }
            }
            if self.lvl > 0 {
                // 20.26 r4: no doubling under pressure (a 129 KiB backlog sat in a 256 KiB Vec x 100
                // streams); grow by a quarter at least so a big backlog still costs O(n) copying
                let spare = t.pend.capacity() - t.pend.len();
                if spare < data.len() {
                    t.pend.reserve_exact(data.len().max(t.pend.capacity() / 4));
                }
            }
            t.pend.extend_from_slice(data);
        }
        self.after_write(ti);
    }

    pub(super) fn flush_pending(&mut self, ti: u32) {
        let t = self.targets.at(ti);
        let rest = t.pend.len() - t.phead;
        self.lazy_cap(ti, rest); // 20.26 r4
        let t = self.targets.at(ti);
        while t.phead < t.pend.len() {
            let rest = &t.pend[t.phead..];
            let n = unsafe { libc::write(t.fd, rest.as_ptr() as *const _, rest.len()) };
            if n < 0 {
                let e = net::errno();
                if would_block(e) {
                    break;
                }
                self.target_eof(ti, net::data_reason(e));
                return;
            }
            t.phead += n as usize;
            if n > 0 {
                t.wrote_since_read = true;
            }
            if (n as usize) < rest.len() {
                break;
            }
        }
        if t.phead == t.pend.len() {
            t.pend.clear();
            t.phead = 0;
            let keep = pend_keep(self.lvl, &self.st);
            if t.pend.capacity() > (4 * 1024 * 1024).min(keep) {
                t.pend.shrink_to((256 * 1024).min(keep / 4)); // 20.26 smaller under memory pressure
            }
        } else if t.phead > (1024 * 1024).min(pend_keep(self.lvl, &self.st) / 4) && t.phead * 2 > t.pend.len() {
            // 20.26 r4: under pressure the sent prefix goes at 64 KiB (level 1), not 1 MiB: with it kept, a
            // stream's 128 KiB backlog sat in a 2 MiB Vec (laptop 32M upload: 4 MiB of backlog in 18 MiB)
            t.pend.drain(..t.phead);
            t.phead = 0;
        }
        self.after_write(ti);
    }

    /// 20.26 upload backlog accounting: target backlog `old` -> `new` for client `ci` (one add each on
    /// the worker and the client). pend is the only queue not bounded per client: credit is per packet
    /// and a client may hold credit on many streams to a target that stalls. Over pend_cap, only a
    /// client holding at least the average share is not read (review B: a client uploading to a
    /// draining target keeps flowing while another one's target stalls); a paused client resumes when
    /// its own backlog drained or the total is under 3/4 of the cap (all paused clients at once).
    pub(super) fn pend_account(&mut self, ci: u32, new: usize, old: usize) {
        self.pend_total = self.pend_total + new - old;
        let Some((g, Some(c))) = self.clients.slots.get_mut(ci as usize).map(|s| (s.0, s.1.as_mut())) else { return };
        let was = c.pend;
        c.pend = c.pend + new - old;
        if (was == 0) != (c.pend == 0) {
            if was == 0 {
                self.pend_clients += 1;
            } else {
                self.pend_clients -= 1;
                if !self.st.read && c.readable && !c.dead {
                    // 60.15 T03 P4: level 3 reads a client again once its upload backlog is gone (read_client)
                    self.ready.push(tok(K_CLIENT, ci, g));
                }
            }
        }
        // 20.27 0x49 hold: streams above PEND_RESUME; the last one going below resumes an hpaused client
        if old <= PEND_RESUME && new > PEND_RESUME {
            c.over += 1;
        } else if old > PEND_RESUME && new <= PEND_RESUME {
            c.over -= 1;
            if c.over == 0 && c.hpaused {
                c.hpaused = false;
                self.stats.hold_resumes.bump(); // 60.12
                let g = self.clients.gen(ci);
                self.ready.push(tok(K_CLIENT, ci, g));
            }
        }
        let Some(c) = self.clients.slots.get_mut(ci as usize).and_then(|s| s.1.as_mut()) else { return };
        if new > old {
            if self.pend_total > self.pend_cap && !c.mpaused && c.pend * self.pend_clients.max(1) >= self.pend_total {
                c.mpaused = true;
                self.stats.pend_pauses.bump(); // 60.12
                let g = self.clients.gen(ci);
                self.pend_paused.push((ci, g));
            }
        } else if c.mpaused && c.pend == 0 {
            c.mpaused = false;
            let g = self.clients.gen(ci);
            self.ready.push(tok(K_CLIENT, ci, g));
            self.pend_paused.retain(|&(i, _)| i != ci); // rare: keeps the list from growing per cycle
        }
        if new < old && self.pend_total <= self.pend_cap / 4 * 3 && !self.pend_paused.is_empty() {
            self.pend_resume_all();
        }
    }

    pub(super) fn pend_resume_all(&mut self) {
        for (ci, g) in std::mem::take(&mut self.pend_paused) {
            if let Some(c) = self.clients.get(ci, g) {
                if c.mpaused {
                    c.mpaused = false;
                    self.ready.push(tok(K_CLIENT, ci, g));
                }
            }
        }
    }

    /// Queue CONTINUE(n) for stream `sid` (target `ti`). 20.30 --credit-v2: record it in the stream's bound and
    /// queue the ping that closes its epoch right after it (one ping outstanding per connection; Pinger)
    pub(super) fn push_continue(&mut self, ci: u32, ti: u32, sid: u32, n: u32) {
        let c = self.clients.at(ci);
        c.push_wisp(PKT_CONTINUE, sid, &n.to_le_bytes());
        // 60.13: the Pinger is created at the connection's first CONTINUE (until then it would sit in its Default state:
        // no ping, no pong, not active) and the stream's state at its first CONTINUE (callers push before resetting
        // `since`, which resume() reads)
        if self.cfg.credit_v2 && c.cv.is_none() {
            c.cv = Some(Box::default());
        }
        if let Some(p) = c.cv.as_mut() {
            let ep = p.epoch();
            if let Some(s) = p.after_continue(Instant::now()) {
                ws::push_frame(&mut c.obuf, OP_PING, &[&s.to_le_bytes()]);
            }
            let t = self.targets.at(ti);
            if t.cv.is_none() && !t.udp && !t.raw {
                t.cv = Some(v2_state(t, c.hs_credit));
            }
            if let Some(st) = t.cv.as_mut() {
                st.pushed(ep, n);
            }
        }
        self.mark_dirty(ci);
    }

    /// 20.30 --credit-v2: the client answered ping `seq`: retire its streams' overwritten credit, update their
    /// windows, re-run the level-0 grant decision (a stream may wait on this pong), then ping a waiting epoch
    pub(super) fn credit_pong(&mut self, ci: u32, (seq, rtt): (u64, Duration)) {
        // review: DATA of this batch may still be staged (up_bufs): write it first, so backlog and the
        // consumption sample see where those bytes really are
        self.flush_upload();
        if self.clients.slots.get(ci as usize).is_none_or(|s| s.1.is_none()) {
            return;
        }
        let c = self.clients.at(ci);
        // the kernel's min RTT, read every 64 pongs (a windowed min that changes slowly; one getsockopt per pong
        // was 1203 calls per GiB on loopback)
        let p = c.cv.as_mut().unwrap();
        let min_rtt = match p.min_rtt {
            Some((v, k)) if k > 0 => {
                p.min_rtt = Some((v, k - 1));
                Some(v)
            }
            _ => {
                let v = net::min_rtt_us(c.fd).map(|us| Duration::from_micros(us as u64));
                p.min_rtt = v.map(|v| (v, 63));
                v
            }
        };
        let min_rtt = min_rtt.unwrap_or(rtt);
        let now = Instant::now();
        let plow = PEND_LOW.min(mem::STAGES[self.capl].out_low) as u64; // (as after_write)
        let tis: Vec<u32> = c.streams.values().copied().collect();
        let hs = c.hs_credit;
        // (20.30 option 2: shrink a target-bound window only where it can delay another stream, and only at cap level 0:
        // at capl >= 1 plow is 64 KiB, so every busy stream would look stalled and restart at WINIT (review r4))
        let siblings = tis.len() > 1 && self.capl == 0;
        for &ti in &tis {
            let t = self.targets.at(ti);
            let backlog = (t.pend.len() - t.phead) as u64;
            // 60.13: a stream that has sent DATA (but had no CONTINUE: else it has its state) gets it at this pong, as
            // before when every stream had it from the start. Known difference: a stream that began sending after an
            // earlier pong of this connection has no consumption mark from that pong, so its first rate/est sample
            // comes one pong later (est = MAX meanwhile: the retired bound alone counts, the conservative side)
            if t.cv.is_none() && t.upkts > 0 && !t.udp && !t.raw {
                t.cv = Some(v2_state(t, hs));
            }
            if let Some(s) = t.cv.as_mut() {
                s.on_pong(seq, rtt, min_rtt, backlog, plow, siblings, now);
                s.starve_grow(&mut self.starve_pool);
            }
        }
        // every level (review: a probe armed at level 0 whose pong lands at level 1+ must still get the base refill)
        for &ti in &tis {
            if self.targets.slots.get(ti as usize).is_some_and(|s| s.1.as_ref().is_some_and(|t| t.cv.is_some())) {
                self.after_write(ti);
            }
        }
        let c = self.clients.at(ci);
        if !c.closing {
            if let Some(s) = c.cv.as_mut().and_then(|p| p.next(now)) {
                ws::push_frame(&mut c.obuf, OP_PING, &[&s.to_le_bytes()]);
                self.mark_dirty(ci);
            }
        }
    }

    /// Flow control: refill the client's credit before it can run dry, but only while the
    /// target is keeping up. wsproxy: pause/resume WS reads instead.
    pub(super) fn after_write(&mut self, ti: u32) {
        // 20.26 grant = --buffer at level 0, fewer packets under memory pressure. Refill at half of
        // the smaller of the last grant and the new one: a big grant shrinks at once, a small one
        // grows back as soon as the pressure is gone (level 0: half = buffer / 2 as before).
        let t = self.targets.at(ti);
        let n = grant(self.cfg.buffer.min(self.st.grant), self.win, t.upkts, t.ubytes);
        let half = (t.credit.min(n) / 2).max(1);
        let backlog = t.pend.len() - t.phead;
        let (ci, sid) = (t.client, t.sid);
        let old = std::mem::replace(&mut t.acct, backlog);
        if backlog != old {
            self.pend_account(ci, backlog, old);
        }
        let t = self.targets.at(ti);
        if t.raw {
            let c = self.clients.at(ci);
            if backlog > self.st.out_high && !c.paused {
                c.paused = true;
            } else if backlog < PEND_LOW.min(self.st.out_low) && c.paused {
                // (review G: below the pause threshold at every level, so L2/L3 do not flap)
                c.paused = false;
                let g = self.clients.gen(ci);
                self.ready.push(tok(K_CLIENT, ci, g));
            }
            return;
        }
        // 20.26 r4: under pressure, refill only below the stage's out_low (64 KiB at level 1: the capped
        // target socket holds 64 KiB, 80 KiB send since 60.15 P1, so more backlog only costs heap) and by refill_due
        // 20.31 (b2): the refill rule and its out_low gate from the cap level (host TCP caps at memory level 0 too)
        let plow = PEND_LOW.min(mem::STAGES[self.capl].out_low);
        let c = self.clients.at(ci);
        if c.closing {
            return;
        }
        // 20.30 --credit-v2 at level 0, for a client that answers pings: top-up against the stream's window
        // (20.31 merge: v2 only at cap level 0 = memory level 0 and no host TCP caps; at TCP level 1 the base rule's
        // level-1 credit applies, as (b2) intends; capl >= lvl)
        let v2 = self.capl == 0 && !t.udp && c.cv.as_ref().is_some_and(|p| p.active(Instant::now()));
        if v2 && t.cv.is_none() {
            if t.upkts == 0 {
                // 60.13: no DATA yet, so nothing is due: a fresh state would decide Grant::No (since 0 < credit = hs)
                return;
            }
            t.cv = Some(v2_state(t, c.hs_credit));
        }
        if let Some(s) = t.cv.as_mut() {
            s.backlog(backlog as u64, plow as u64);
        }
        let n = if v2 {
            match t.cv.as_ref().unwrap().grant(backlog as u64, t.since, t.credit, (PEND_HARD - PEND_HARD / 16) as u64) {
                credit::Grant::Continue(n) => {
                    let pc = if self.cfg.credit_pace { self.pace_hold(ti) } else { pace::PACE_GO };
                    if pc == pace::PACE_HOLD {
                        return; // 60.42 the target is parked on the client's output: no new upload yet
                    }
                    let t = self.targets.at(ti);
                    if t.since >= t.credit && pc != pace::PACE_RELEASED {
                        t.cv.as_mut().unwrap().starved();
                    }
                    n
                }
                credit::Grant::Probe => {
                    let p = self.clients.at(ci).cv.as_mut().unwrap();
                    let (seq, ping) = p.probe(Instant::now());
                    if let Some(s) = ping {
                        ws::push_frame(&mut self.clients.at(ci).obuf, OP_PING, &[&s.to_le_bytes()]);
                        self.mark_dirty(ci);
                    }
                    self.targets.at(ti).cv.as_mut().unwrap().probing(seq);
                    return;
                }
                credit::Grant::No => return,
            }
        } else if refill_due(self.capl, t.since, t.allow, t.credit, n, half) && backlog < plow {
            if self.cfg.credit_pace && !t.udp && self.pace_hold(ti) == pace::PACE_HOLD {
                return; // 60.42 (as above)
            }
            n
        } else {
            return;
        };
        self.push_continue(ci, ti, sid, n); // (60.13: first, so a lazily created v2 state sees `since`)
        let t = self.targets.at(ti);
        t.allow = next_allow(t.allow, t.since, n); // before since is reset (review A)
        t.since = 0;
        t.credit = n;
    }
}

/// 60.13: a stream's credit v2 state, created on first use (it had no CONTINUE: `since` = its DATA packets, un-halved).
/// `ubytes` halves with `upkts` at 2^20 packets (the mean stays; legal before a first CONTINUE with a large --buffer,
/// review r5), so it is scaled back to `since` packets
fn v2_state(t: &Target, hs: u32) -> Box<credit::Stream> {
    Box::new(credit::Stream::resume(hs, t.since, scaled_bytes(t.since, t.upkts, t.ubytes), t.umax))
}

/// `ubytes` for `since` packets when the counters were halved (`upkts` < `since`): mean x since
pub(super) fn scaled_bytes(since: u32, upkts: u32, ubytes: u64) -> u64 {
    if upkts == 0 || upkts == since {
        ubytes
    } else {
        (ubytes as u128 * since as u128 / upkts as u128) as u64
    }
}

/// 20.26 packets a client may legitimately send after we send CONTINUE(n): what the earlier grants
/// still allowed (`allow` minus the `since` packets received since the previous CONTINUE; those may
/// already be in flight) plus the new grant. Wisp clients set their credit to n on CONTINUE, so this
/// is an upper bound. A client whose `since` exceeds it ignored its credit (write_target: pend_over).
pub(super) fn next_allow(allow: u32, since: u32, n: u32) -> u32 {
    n.saturating_add(allow.saturating_sub(since))
}

/// 20.26 r4 (level >= 1 only; `win` = 0 at level 0): the CONTINUE grant for a stream, `n` packets
/// (the stage's grant) or fewer so that one grant is about `win` bytes of this stream's mean upload
/// packet size (`upkts`, `ubytes`; the stage's grant until the first packet). Credit is per packet
/// and the packet size is the client's: a fixed count of 16 KiB packets x 100 streams filled a 128M
/// budget. 64-byte requests keep the stage's grant.
fn grant(n: u32, win: u64, upkts: u32, ubytes: u64) -> u32 {
    if win == 0 || upkts == 0 {
        return n;
    }
    let avg = (ubytes / upkts as u64).max(1);
    n.min((win / avg).max(1) as u32)
}

/// 20.26 r4: send the next CONTINUE(n)? Level 0: after `half` packets, as before 20.26. Under
/// pressure also only while the client's outstanding credit (`allow` - `since`, an upper bound:
/// in-flight packets count) is at most one grant, or once the whole last grant was consumed. Wisp
/// credit is replaced, not added, by CONTINUE: refilled at half alone, a client that outruns its
/// target gets n new packets per n/2 consumed and its backlog grows without bound (measured: 128M
/// upload 10x10 at grant 8 had allow 439, 1.2 MiB of pend per stream, level 2). The `since >=
/// credit` escape is needed: the upper bound keeps credit the client may have dropped at a CONTINUE,
/// and with a grant now smaller than that leftover the bound alone never refills again (unit test
/// pressure_refill_never_stalls_and_bounds_the_window). Outstanding stays <= n + the largest
/// earlier grant.
pub(super) fn refill_due(lvl: usize, since: u32, allow: u32, credit: u32, n: u32, half: u32) -> bool {
    since >= half && (lvl == 0 || allow.saturating_sub(since) <= n || since >= credit)
}
