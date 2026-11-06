//! 20.05 client connection state: the Client record and its output buffers (obuf, the --prio bulk lane, the kTLS
//! send path, KeyUpdate).

use super::*;

#[derive(PartialEq, Clone, Copy)]
pub(super) enum CState {
    Tls, // 20.13: TLS handshake in rustls; becomes Http once the keys are in the kernel
    Http,
    WaitInfo,
    Open,
    Wsproxy,
}

pub(super) struct Client {
    pub(super) fd: RawFd,
    pub(super) state: CState,
    pub(super) rbuf: Vec<u8>,
    pub(super) rpos: usize,
    pub(super) rlen: usize,
    pub(super) need: usize,
    pub(super) obuf: Vec<u8>,
    pub(super) ohead: usize,
    pub(super) readable: bool,
    pub(super) rdhup: bool,
    pub(super) paused: bool,  // wsproxy: target backlog high
    pub(super) opaused: bool, // own output backlog above OUT_HARD
    pub(super) dirty: bool,
    pub(super) dead: bool,
    pub(super) closing: bool, // stop reading input; close when output drained
    pub(super) streams: StreamMap,
    pub(super) blocked: Vec<u64>,
    pub(super) blocked_bulk: Vec<u64>, // oh256: targets parked by OUT_HIGH_BULK (bulk lane), resumed below OUT_LOW_BULK
    pub(super) bulk_waiting: usize,    // oh256: blocked_bulk[..bulk_waiting] parked without reading since the last drain
    pub(super) frag: Option<(u8, Vec<u8>)>,
    pub(super) proxy_target: Option<(u32, u32)>,
    // 20.08 splice download path: target bytes sit in `pipe` (not in obuf); they belong in the
    // output stream at obuf offset `splice_at` (right after their frame header).
    pub(super) pipe: [RawFd; 2],
    pub(super) splice_ok: bool,
    pub(super) splice_pending: usize,
    pub(super) splice_at: usize,
    pub(super) active: bool, // 20.11: I/O since the last idle sweep
    pub(super) rfull: bool,  // 20.11: last read filled rbuf -> grow it (up to RBUF) before the next read
    // 20.19 bulk lane (Config::prio): DATA of bulk-mode streams; sent after obuf. `bulk_sent` counts
    // every byte ever sent from it, so a target knows (Target::bulk_end) whether it still has unsent
    // bytes here and must keep its order by staying in this lane. Invariants: a frame is never split
    // between lanes; a partly sent lane frame is finished before anything from obuf (`bulk_ends`,
    // `bulk_boundary`); when the connection closes the lane is dropped except the rest of a partly sent
    // frame (bulk_cut: it must go out before the WS Close).
    pub(super) bulk: Vec<u8>,
    pub(super) bhead: usize,
    pub(super) bulk_sent: u64,
    pub(super) bulk_ends: VecDeque<u64>, // absolute end of every unsent (or partly sent) frame in the lane
    pub(super) bulk_boundary: u64,       // absolute end of the last frame sent completely (mid-frame iff bulk_sent > this)
    pub(super) tls: Option<Box<TlsHs>>,  // 20.13: only during the handshake
    // 20.17 after the handshake: keys are in the kernel (close sends close_notify) ...
    pub(super) ktls_on: bool,
    // ... and for TLS 1.3 the rustls key schedule, to derive KeyUpdate secrets
    pub(super) ktls: Option<Box<rustls::kernel::KernelConnection<rustls::server::ServerConnectionData>>>,
    // 20.13/20.17: records the current key may still carry, per direction (AEAD usage limit; the
    // kernel does not enforce it). Counted as 1 + bytes/16 KiB per syscall: an upper bound for TX;
    // for RX a client sending tiny records can exceed it (its own data's confidentiality).
    // At <= rekey_at (TLS 1.3) we send a KeyUpdate; at 0 we close (TLS 1.2, or a client that
    // never answers update_requested).
    pub(super) tx_left: u64,
    pub(super) rx_left: u64,
    pub(super) rekey_at: u64,
    // 20.17 KeyUpdate to send: 0 none, 1 ours (update_not_requested), 2 ours asking (update_requested), 3 the reply owed to the
    // peer's update_requested (update_not_requested; RFC 8446 4.6.3: before our next application data, 60.15 T40)
    pub(super) ku: u8,
    pub(super) ku_asked: bool, // 20.17 we sent update_requested and wait for the client's KeyUpdate
    pub(super) challenge: Option<Box<ext::Challenge>>, // 20.18 key auth: sent in INFO, freed after the client's INFO
    pub(super) hs_sweeps: u8,  // review r1: sweeps seen in Http/WaitInfo (handshake deadline, HS_SWEEPS)
    pub(super) notified: bool, // review r1: our close_notify was accepted by kTLS (ktls_drained)
    pub(super) lingering: bool, // review r1: on Worker::lingering, waiting for kTLS to drain before close
    pub(super) drain_seen: bool, // review r1: the previous drain sample saw TCP empty (ktls_drained)
    pub(super) tx_bytes: u64,  // 20.21 bytes sent to this client (adaptive lowat sampling)
    pub(super) rate_check_at: u64, // 20.21 next tx_bytes at which the delivery rate is sampled
    pub(super) lowat_off: bool, // 20.21 lowat lifted for this fast kTLS client
    pub(super) saved: (i32, i32), // 20.26 SO_RCVBUF/SO_SNDBUF before net::cap_bufs ((0, 0) = not capped)
    pub(super) mpaused: bool,  // 20.26 not read: holds an above-average share of an upload backlog over Worker::pend_cap
    pub(super) pend: usize,    // 20.26 sum of its targets' Target::acct (its share of Worker::pend_total)
    // 20.27 0x49 hold: not read: a stream within its credit holds more than PEND_HARD of upload backlog (an honest client's
    // data in flight when its target stalled; it cannot send more than its credit). `over` = its streams with a
    // backlog above PEND_RESUME; reads resume at 0. `hp_sweeps`: idle sweeps seen while held; at HOLD_SWEEPS
    // idle_sweep closes the streams over PEND_HARD (or else the largest over PEND_RESUME) with 0x49, as base did
    // at once, and reads again
    // Not RST by the 70.02/70.08 rules: count_stalls skips held clients (no read, no progress expected) and
    // peer_gone needs unACKed output plus retransmits/probes (a held client still ACKs). Under level 2+ memory
    // pressure a held client with a partial frame above rbuf_max is a frame_held holder (as mpaused clients).
    pub(super) hpaused: bool,
    pub(super) lpaused: bool, // 60.25 C10b upload allowance spent: not read until Worker::meter_timers (fits in padding)
    pub(super) over: u32,
    pub(super) hp_sweeps: u32,
    // 20.26 r4 the handshake CONTINUE: the credit every new stream of this client starts with
    // (--buffer, or the stage's grant under pressure: a new stream's first burst is then small)
    pub(super) hs_credit: u32,
    pub(super) cv: Option<Box<credit::Pinger>>, // 20.30 --credit-v2: the ping that closes the CONTINUE epoch (60.13: None = off or no CONTINUE yet)
    // 70.08 TCP bytes received from the client at the last sweep (NO_RX: no sample), and sweeps in a row
    // with less than STALL_MIN_BYTES for an in-progress frame above rbuf_max (Worker::count_stalls)
    pub(super) rx_mark: u64,
    pub(super) gone_ack: u32, // 70.06 tcpi_last_ack_recv when the last sweep saw net::peer_gone (0 = it did not)
    pub(super) rstall: u8,
    pub(super) local: u8, // B (20.31 redesign): 0 = not known yet, 1 = remote, 2 = the client is on this host (tcp_only_local)
    // 50.02 kTLS send starved by host TCP memory (Worker::starve_check): `wblock` = the last flush ended because the socket
    // took no more (EAGAIN or a short write); `starve` = retries in the current episode (0 = none), next one at
    // `starve_at`; `starve_room` = bytes its targets may still be read past their cap in this episode (STARVE_SLICE)
    pub(super) wblock: bool,
    pub(super) starve: u8,
    pub(super) starve_at: Instant,
    pub(super) starve_room: u32,
    pub(super) starve_since: Instant, // 50.02 start of the current episode (ktls_starve_ms_max)
    pub(super) starve_b: bool,        // 50.02 the current episode was given room (ktls_starve_slices)
    pub(super) starve_due: bool,      // 50.02 the next flush is starve_check's timer retry (only that one advances `starve`)
    pub(super) starve_read: u64,      // 50.02 bytes this connection read past the cap in all its episodes (ktls_starve_conn_max)
    #[cfg(test)]
    pub(super) send_log: Vec<u8>, // 60.15 T40 test: b'g' per gathered sendmsg, b'k' per KeyUpdate attempt, in send order
    #[cfg(test)]
    pub(super) ku_refuse: bool, // 60.15 T40 test: key_update acts as if the kernel refused the record
}

/// 20.13/20.17 handshake state: unbuffered rustls (so it can become a kernel connection) and its
/// pending output. rbuf[..kept] holds bytes rustls has seen but not released (a handshake
/// message spanning records); the next record is read right after them.
pub(super) struct TlsHs {
    pub(super) conn: rustls::server::UnbufferedServerConnection,
    pub(super) out: Vec<u8>,
    pub(super) sent: usize,
    pub(super) kept: usize,
    pub(super) done: bool,
}

impl Client {
    /// 20.27 0x49 hold: stop reading this client (an in-credit stream's backlog passed PEND_HARD); see `hpaused`.
    /// true = a new hold (60.12 metrics)
    pub(super) fn hold(&mut self) -> bool {
        if !self.hpaused {
            self.hpaused = true;
            self.hp_sweeps = 0;
            return true;
        }
        false
    }

    /// 60.05 H7b/H7c: an in-progress frame bigger than `rmax` (rbuf_max) that rbuf cannot take
    /// without growing (review: a frame that fits a buffer grown earlier is finished, so the buffer
    /// shrinks after it) or bigger than the level-0 RBUF (deliberate, conservative: its buffer came
    /// from the big-frame path, and an mmapped one gets its pages faulted in as the bytes are read),
    /// or a fragmented message bigger than `rmax`
    /// 70.02 a single frame is never held below HOLD_FLOOR: one ordinary client frame (wisp-js / epoxy /
    /// wbench send up to 64 KiB per DATA packet) is read and finished at every level that reads; holding it
    /// shed honest uploaders at L2/L3. Fragmented messages keep `rmax` (the clients above do not fragment;
    /// with the floor there too the frag stress run kept level 2+ longer: honest probes 37/48 vs 38/38).
    pub(super) fn frame_held(&self, rmax: usize) -> bool {
        // the floor is for whole messages only (FIN set, not a continuation; the in-progress frame starts at
        // rpos): a fragmented one is bounded by `rmax` from its first fragment on (frag stress: a holder still
        // in its first 64 KiB fragment escaped the shed round and finished its 10 MiB message after it)
        let ws = matches!(self.state, CState::Open | CState::WaitInfo | CState::Wsproxy); // not an HTTP request byte
        let whole = ws && self.rbuf.get(self.rpos).is_some_and(|&b| b & 0x80 != 0 && b & 0x0f != 0);
        let fmax = if whole { rmax.max(HOLD_FLOOR) } else { rmax };
        (self.need > fmax && (self.need > self.rbuf.len() || self.need > mem::STAGES[0].rbuf_max))
            || self.frag.as_ref().is_some_and(|f| f.1.len() > rmax)
    }
    #[inline]
    pub(super) fn out_pending(&self) -> usize {
        self.obuf.len() - self.ohead + self.splice_pending + self.bulk.len() - self.bhead
    }
    /// 20.19 absolute position of the end of the bulk lane (what a target records as bulk_end).
    #[inline]
    fn bulk_end(&self) -> u64 {
        self.bulk_sent + (self.bulk.len() - self.bhead) as u64
    }
    /// 20.19 both lanes drained and no splice chunk pending.
    #[inline]
    pub(super) fn out_empty(&self) -> bool {
        self.ohead == self.obuf.len() && self.bhead == self.bulk.len() && self.splice_at == NO_MARK
    }
    pub(super) fn compact_bulk(&mut self) {
        if self.bhead == 0 {
            return;
        }
        let (h, l) = (self.bhead, self.bulk.len());
        self.bulk.copy_within(h..l, 0);
        self.bulk.truncate(l - h);
        self.bhead = 0;
    }
    /// 20.19 record the end of a frame just appended to the bulk lane; returns it (for Target::bulk_end).
    #[inline]
    pub(super) fn bulk_frame_done(&mut self) -> u64 {
        let end = self.bulk_end();
        self.bulk_ends.push_back(end);
        end
    }
    /// 20.19 drop the bulk lane (connection closing, or idle and drained): unsent bytes are discarded.
    pub(super) fn bulk_drop(&mut self) {
        self.bulk = Vec::new();
        self.bhead = 0;
        self.bulk_ends.clear();
        self.bulk_boundary = self.bulk_sent;
    }
    /// 20.19 connection closing: drop the unsent lane DATA, except the rest of a frame that already went
    /// out partly. flush finishes that first, before the WS Close in obuf; dropping it too would put the
    /// Close (and any queued obuf frame) inside its payload (review r1, adversarial #16).
    pub(super) fn bulk_cut(&mut self) {
        match self.bulk_ends.front().copied() {
            Some(end) if self.bulk_sent > self.bulk_boundary => {
                self.bulk.truncate(self.bhead + (end - self.bulk_sent) as usize);
                self.bulk_ends.truncate(1);
            }
            _ => self.bulk_drop(),
        }
    }
    /// review r1: kTLS keeps the records TCP has not taken yet in its own list and frees them on
    /// close() (kernel tls_sw_release_resources_tx), whereas plain TCP still sends its queue after
    /// close(). So a closing kTLS socket first gets its close_notify accepted (EAGAIN = still full).
    /// Accepting it ends our TX: a pending KeyUpdate is dropped, nothing may follow the alert.
    pub(super) fn ktls_notify(&mut self) -> bool {
        if !self.notified {
            match tls::send_record(self.fd, tls::REC_ALERT, &[1, 0]) {
                Err(e) if e.raw_os_error().is_some_and(would_block) => return false,
                _ => {
                    self.notified = true;
                    self.ku = 0;
                }
            }
        }
        true
    }
    /// review r1: one drain sample per linger tick (Worker::linger_check, >= TIMER_TICK_MS apart).
    /// deliberate heuristic: kTLS exposes no "list empty". Its records move to TCP from a deferred job
    /// (tls_sw_write_space -> tx_work), so TCP empty (SIOCOUTQ == 0) on two samples a tick apart gives
    /// that job a whole tick to run, and close() still makes one last push into the empty TCP queue.
    /// An ioctl error counts as drained (nothing more can be delivered).
    pub(super) fn ktls_drained(&mut self) -> bool {
        if !self.ktls_notify() {
            return false;
        }
        let mut q: libc::c_int = 0;
        let r = unsafe { libc::ioctl(self.fd, libc::TIOCOUTQ, &mut q) }; // = SIOCOUTQ on TCP: unacked + unsent
        if r != 0 {
            return true;
        }
        std::mem::replace(&mut self.drain_seen, q == 0) && q == 0
    }
    /// 20.21 adaptive lowat (see RATE_CHECK_BYTES): one TCP_INFO per 4 MiB sent, kTLS clients only.
    /// false = TCP_INFO has no delivery rate (kernel < 4.9, uapi tcp.h v4.8 vs v4.9): stop sampling this client.
    pub(super) fn adapt_lowat(&mut self, lowat: u32) -> bool {
        let Some((rate, app_limited)) = net::delivery_rate(self.fd) else { return false };
        if !self.lowat_off && rate >= LOWAT_FAST {
            net::set_notsent_lowat(self.fd, i32::MAX as u32); // explicit: 0 would mean the host sysctl
            self.lowat_off = true;
        } else if self.lowat_off && rate < LOWAT_SLOW && !app_limited {
            net::set_notsent_lowat(self.fd, lowat);
            self.lowat_off = false;
        }
        true
    }
    /// 20.19 send the bulk lane up to index `upto`. Ok(false) = socket full before that.
    fn send_bulk(&mut self, upto: usize) -> Result<bool, ()> {
        while self.bhead < upto {
            let rest = &self.bulk[self.bhead..upto];
            let want = rest.len();
            let n = unsafe { libc::send(self.fd, rest.as_ptr() as *const _, want, libc::MSG_NOSIGNAL) };
            if n < 0 {
                return if would_block(net::errno()) { Ok(false) } else { Err(()) };
            }
            self.bulk_advance(n as usize);
            if self.tx_count(n as usize) {
                return Err(());
            }
            if (n as usize) < want {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// 20.19 `n` more lane bytes went out: frames sent completely move bulk_boundary
    fn bulk_advance(&mut self, n: usize) {
        self.bhead += n;
        self.bulk_sent += n as u64;
        while let Some(&e) = self.bulk_ends.front() {
            if e > self.bulk_sent {
                break;
            }
            self.bulk_boundary = e;
            self.bulk_ends.pop_front();
        }
    }
    /// 50.02 A2: the pieces flush would send next, in its order: the rest of a partly sent lane frame
    /// (bulk[bhead..a]), obuf up to the splice mark (obuf[ohead..o]), then, if no splice is pending, the rest of the
    /// lane (bulk[a..b]). Returns (a, o, b).
    fn gather_bounds(&self) -> (usize, usize, usize) {
        let a = if self.bulk_sent > self.bulk_boundary {
            let end = self.bulk_ends.front().copied().unwrap_or(self.bulk_sent);
            self.bhead + (end - self.bulk_sent) as usize
        } else {
            self.bhead
        };
        let o = if self.splice_at != NO_MARK { self.splice_at } else { self.obuf.len() };
        let b = if self.splice_at == NO_MARK { self.bulk.len() } else { a };
        (a, o, b)
    }
    /// 50.02 A2: bytes one gathered send (send_gather) would offer the socket now
    pub(super) fn gather_len(&self) -> usize {
        let (a, o, b) = self.gather_bounds();
        (a - self.bhead) + (o - self.ohead) + (b - a)
    }
    /// 50.02 A2 (starve retry only): one sendmsg of the pieces flush would send next, in the same order
    /// (gather_bounds). Over net.ipv4.tcp_mem[2] the kernel forces a send charge through only if wmem_queued + size is
    /// at least sk_sndbuf (net/core/sock.c __sk_mem_raise_allocated; the sndbuf is moderated to SOCK_MIN_SNDBUF 4608 by
    /// then). flush alone often offered just the few-byte rest of a lane frame (VPS1 trace: 2-32 B requests refused
    /// with an empty queue, again and again), so a starved kTLS sender never got its forced charge. Ok(true) = all
    /// of it went out (flush goes on as usual).
    fn send_gather(&mut self) -> Result<bool, ()> {
        let (a, o, b) = self.gather_bounds();
        let iov = [
            libc::iovec { iov_base: self.bulk[self.bhead..a].as_ptr() as *mut _, iov_len: a - self.bhead },
            libc::iovec { iov_base: self.obuf[self.ohead..o].as_ptr() as *mut _, iov_len: o - self.ohead },
            libc::iovec { iov_base: self.bulk[a..b].as_ptr() as *mut _, iov_len: b - a },
        ];
        let want = iov.iter().map(|v| v.iov_len).sum::<usize>();
        if want == 0 {
            return Ok(true);
        }
        // SAFETY: an all-zero msghdr is valid (no name, no control); iov points at the 3 live slices above.
        let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
        (mh.msg_iov, mh.msg_iovlen) = (iov.as_ptr() as *mut _, iov.len() as _);
        let flags = if self.splice_at != NO_MARK { libc::MSG_MORE } else { 0 } | libc::MSG_NOSIGNAL; // as flush
        let n = unsafe { libc::sendmsg(self.fd, &mh, flags) };
        if n < 0 {
            return if would_block(net::errno()) { Ok(false) } else { Err(()) };
        }
        let n = n as usize;
        #[cfg(test)]
        self.send_log.push(b'g');
        let k1 = n.min(a - self.bhead);
        let k2 = (n - k1).min(o - self.ohead);
        self.bulk_advance(k1);
        self.ohead += k2;
        self.bulk_advance(n - k1 - k2);
        if self.tx_count(n) {
            return Err(());
        }
        Ok(n == want)
    }
    /// Drop the already-sent prefix of obuf (keeps the splice marker consistent).
    pub(super) fn compact(&mut self) {
        if self.ohead == 0 {
            return;
        }
        let (h, l) = (self.ohead, self.obuf.len());
        self.obuf.copy_within(h..l, 0);
        self.obuf.truncate(l - h);
        if self.splice_at != NO_MARK {
            self.splice_at -= h;
        }
        self.ohead = 0;
    }
    /// Write as much output as the socket takes, in stream order. Err(()) = connection broken.
    /// 50.02: `wblock` tells whether it stopped because the socket took no more (Worker::flush_dirty checks kTLS ones).
    pub(super) fn flush(&mut self) -> Result<(), ()> {
        self.wblock = true; // every Ok(()) below but the drained one means the socket took no more

        // 50.02 A2. 60.15 T40: a KeyUpdate is its own tiny record (5 bytes, own record type; the TX key changes right after
        // it), so it is never gathered, and over tcp_mem[2] the kernel refuses it whatever we queue first: with an empty
        // queue its charge is not forced (wmem_queued + size < sndbuf), with a full one sk_stream_memory_free fails (VM
        // trace, 60.17). Our proactive one (ku 1) therefore does not hold the data back: a refused one is retried at every
        // flush while data goes on under the old key (rekey_at leaves 2^23 records before the hard limit), and so does ours
        // asking the peer (ku 2: the peer may then run into its RX limit later, which closes as before). The reply owed to
        // the peer's update_requested (ku 3) keeps the RFC 8446 4.6.3 order (before our next application data) and waits:
        // known limit (50.02).
        if self.ku == 3 && !self.key_update()? {
            return Ok(()); // refused: the reply owed to the peer goes first (retried on EPOLLOUT / the starve timer)
        }
        if self.starve_due && !self.send_gather()? {
            return Ok(()); // (an accepted owed reply above: the starve retry still gathers, review P3)
        }
        loop {
            if self.ku != 0 {
                self.key_update()?; // ku 1/2 (ku 3 went out above): a refused one stays pending, the data goes on
            }
            if self.bulk_sent > self.bulk_boundary {
                // 20.19 a bulk-lane frame went out partly: finish it before anything from obuf
                let end = self.bulk_ends.front().copied().unwrap_or(self.bulk_sent);
                let upto = self.bhead + (end - self.bulk_sent) as usize;
                if !self.send_bulk(upto)? {
                    return Ok(());
                }
            }
            let end = if self.splice_at != NO_MARK { self.splice_at } else { self.obuf.len() };
            while self.ohead < end {
                let rest = &self.obuf[self.ohead..end];
                let want = rest.len();
                let flags = if self.splice_at != NO_MARK { libc::MSG_MORE } else { 0 } | libc::MSG_NOSIGNAL;
                let n = unsafe { libc::send(self.fd, rest.as_ptr() as *const _, rest.len(), flags) };
                if n < 0 {
                    return if would_block(net::errno()) { Ok(()) } else { Err(()) };
                }
                self.ohead += n as usize;
                if self.tx_count(n as usize) {
                    return Err(()); // 20.13: AEAD usage limit reached: close
                }
                if (n as usize) < want {
                    return Ok(());
                }
            }
            if self.splice_at == NO_MARK {
                self.wblock = !self.send_bulk(self.bulk.len())?; // 20.19 bulk lane after everything else
                return Ok(());
            }
            while self.splice_pending > 0 {
                let n = unsafe {
                    libc::splice(
                        self.pipe[0],
                        std::ptr::null_mut(),
                        self.fd,
                        std::ptr::null_mut(),
                        self.splice_pending,
                        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                    )
                };
                if n < 0 {
                    return if would_block(net::errno()) { Ok(()) } else { Err(()) };
                }
                if n == 0 {
                    return Err(());
                }
                self.splice_pending -= n as usize;
                if self.tx_count(n as usize) {
                    return Err(());
                }
            }
            self.splice_at = NO_MARK;
        }
    }
    /// 20.13/20.17 count records sent under the current TX key. true = hard limit: close.
    #[inline]
    fn tx_count(&mut self, n: usize) -> bool {
        self.tx_bytes += n as u64;
        self.tx_left = self.tx_left.saturating_sub(1 + n as u64 / 16384);
        if self.tx_left <= self.rekey_at {
            if self.tx_left == 0 {
                return true;
            }
            if self.ku == 0 {
                self.ku = 1; // proactive server KeyUpdate (sent at the top of the next flush round)
            }
        }
        false
    }
    /// 20.17 Send our TLS 1.3 KeyUpdate (under the old key), then install the next TX key.
    /// Ok(false) = socket full, retry on EPOLLOUT. Err = connection broken.
    #[cold]
    fn key_update(&mut self) -> Result<bool, ()> {
        #[cfg(test)]
        {
            self.send_log.push(b'k');
            if self.ku_refuse {
                return Ok(false); // as a refused charge (EAGAIN)
            }
        }
        let Some(k) = self.ktls.as_mut() else {
            self.ku = 0;
            return Ok(true);
        };
        match tls::send_record(self.fd, tls::REC_HANDSHAKE, &tls::key_update_msg(self.ku == 2)) {
            Ok(5) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            _ => return Err(()),
        }
        let s = k.update_tx_secret().map_err(|_| ())?;
        tls::rekey(self.fd, false, &s).map_err(|_| ())?;
        self.ku = 0;
        self.tx_left = TLS_RECORD_BUDGET;
        Ok(true)
    }
    pub(super) fn push_wisp(&mut self, ty: u8, sid: u32, payload: &[u8]) {
        let mut h = [0u8; 5];
        h[0] = ty;
        h[1..5].copy_from_slice(&sid.to_le_bytes());
        ws::push_frame(&mut self.obuf, OP_BIN, &[&h, payload]);
    }
}
