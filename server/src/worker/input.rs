//! 20.05 client input: socket reads, WebSocket frames, partial-frame holds.

use super::*;

impl Worker {
    pub(super) fn read_client(&mut self, ci: u32) {
        if self.clients.at(ci).state == CState::Tls {
            return self.tls_drive(ci);
        }
        let g = self.clients.gen(ci);
        for _ in 0..BUDGET {
            let c = self.clients.at(ci);
            if c.dead || c.closing || c.paused || c.opaused || c.lpaused || !c.readable {
                return; // (60.25 C10b lpaused: no rdhup close, the client's queued upload is still read at its rate)
            }
            // 20.33: staged upload iovecs point into an rbuf; this read may compact or grow it
            debug_assert!(self.up_n == 0 && self.up_total == 0, "20.33: upload staged across a client read");
            if c.mpaused || c.hpaused || (!self.st.read && c.pend > 0) {
                // 20.26 not read under memory pressure (resumed by after_write / idle_sweep / set_level). A
                // peer that hung up is closed now (review): its unread input is dropped, its memory freed.
                // 60.15 T03 P4: level 3 (st.read false) reads a client while none of its streams has an upload
                // backlog (c.pend 0): its bytes then go straight to the (capped) target sockets, and reading is what
                // drains its own receive queue. Not reading it at all held queues filled at level 0 (up to tcp_rmem
                // max each) above level 3's exit for good: VPS1, 64M from level 0, upload 10x10: 10 of 12 runs at
                // 0 MiB/s for 6-22 s until l3_sweep closed clients. A backlog stops it again (pend_account resumes it).
                if c.rdhup {
                    self.close_client(ci, Why::ClientClose);
                }
                return;
            }
            if c.out_pending() > self.st.out_hard {
                c.opaused = true; // resumed by flush_dirty below OUT_LOW
                return;
            }
            let rmax = self.rbuf_max; // 20.26 RBUF at level 0, smaller under pressure (r4: by the budget at level 1)
            if self.lvl >= 2 && c.frame_held(rmax) {
                // 60.05 H7b: under hard pressure an in-progress frame or fragmented message bigger than
                // rbuf_max does not grow: its bytes wait in the (capped) socket buffer; l3_sweep sheds it
                // first (H7c), set_level reads it again below level 2. A peer that hung up goes now.
                if c.rdhup {
                    self.close_client(ci, Why::ClientClose);
                }
                return;
            }
            if c.rpos == c.rlen {
                c.rpos = 0;
                c.rlen = 0;
                if self.lvl > 0 && c.rbuf.len() > rmax && c.need <= rmax {
                    // (review: only under pressure; level 0 keeps a grown rbuf until the idle sweep as before)
                    c.rbuf = vec![0u8; rmax]; // 20.26 memory pressure: give back a big drained rbuf
                    c.rfull = false;
                }
            }
            // make room: frame that does not fit, or little free space -> compact/grow.
            // 60.05 H2: a frame bigger than rbuf is not allocated from its header (14 bytes claiming
            // 16 MiB made rbuf 16 MiB before any payload, pre-auth, past rbuf_max). rbuf grows toward
            // `need` only as the frame's bytes arrive: it doubles when less than 16 KiB would be free
            // after compaction (so at most ~2x the buffered bytes), and one legitimate big frame
            // still fits after log2(need / len) doublings (O(need) copies in total).
            let pending = c.rlen - c.rpos;
            let full = c.rbuf.len() - pending < 16 * 1024;
            let want = c.need.min(if full { 2 * c.rbuf.len() } else { c.rbuf.len() }).max(pending + 16 * 1024);
            let grow_now = c.rfull && c.rbuf.len() < rmax && c.state != CState::Http;
            if c.rbuf.len() - c.rpos < want || c.rbuf.len() - c.rlen < 16 * 1024 || grow_now {
                if c.rpos > 0 {
                    c.rbuf.copy_within(c.rpos..c.rlen, 0);
                    c.rlen -= c.rpos;
                    c.rpos = 0;
                }
                let grow = (c.rbuf.len() * 2).clamp(RBUF_MIN, rmax);
                let cap = want.max(if c.state == CState::Http { 4096 } else { grow });
                if c.rbuf.len() < cap {
                    if cap > rmax {
                        // 60.05 H7a: a big frame's buffer: a fresh zeroed allocation plus a copy of the
                        // buffered bytes. resize() zero-fills, touching every new page at once; a block of
                        // mem::MMAP_THRESHOLD or more is mmapped, and its pages stay untouched until the
                        // payload lands (one from the arena, e.g. past M_MMAP_MAX, is cleared by calloc, as resize
                        // did). The last step takes the whole frame plus the 16 KiB tail (review: sized to
                        // `need` alone, every short read near the frame's end re-allocated and copied it).
                        let cap = if cap >= c.need { cap.max(c.need + 16 * 1024) } else { cap };
                        let mut nb = vec![0u8; cap];
                        nb[..c.rlen].copy_from_slice(&c.rbuf[..c.rlen]);
                        c.rbuf = nb;
                    } else {
                        c.rbuf.resize(cap, 0);
                    }
                }
            }
            let space = c.rbuf.len() - c.rlen;
            // 60.25 C10b: read no more than the upload allowance (0: spent, lpaused set)
            let ask = if self.meter {
                match meter::room(&mut self.meters, &mut self.lwait, &self.cfg, &self.peers_of, &self.stats, c, ci, g, space) {
                    0 => return,
                    r => r,
                }
            } else {
                space
            };
            let n = unsafe { libc::read(c.fd, c.rbuf.as_mut_ptr().add(c.rlen) as *mut _, ask) };
            if n <= 0 {
                if n < 0 {
                    let e = net::errno();
                    if would_block(e) {
                        c.readable = false;
                        return;
                    }
                    if e == libc::EIO && c.ktls_on {
                        // 20.17 kTLS: the next record is not application data (alert, KeyUpdate)
                        if self.tls_control(ci) {
                            continue;
                        }
                        return;
                    }
                }
                // EOF; else a reset, a keepalive timeout or a kTLS record error (60.24)
                let why = if n == 0 { Why::ClientClose } else { Why::Io }; // 60.24 EOF; else reset, keepalive timeout, kTLS error
                self.close_client(ci, why);
                return;
            }
            let n = n as usize;
            c.rlen += n;
            self.rx_total += n as u64; // 60.25 C5 rx_bytes: bytes read from client sockets (published by idle_sweep)
            if self.meter {
                meter::debit(&mut self.meters, ci, n); // 60.25 C10b
            }
            c.active = true;
            c.rx_left = c.rx_left.saturating_sub(1 + n as u64 / 16384);
            if c.rx_left <= c.rekey_at {
                if c.rx_left == 0 {
                    self.close_client(ci, Why::TlsError); // 20.13: AEAD usage limit (TLS 1.2, or the client ignored update_requested)
                    return;
                }
                if !c.ku_asked && c.ku != 3 {
                    // 20.17: ask the client to update its key (our KeyUpdate with update_requested; not in place of an owed
                    // reply, 60.15 T40: asked after it went out)
                    c.ku_asked = true;
                    c.ku = 2;
                    if !c.dirty {
                        c.dirty = true;
                        self.dirty.push((ci, g));
                    }
                }
            }
            c.rfull = n == space;
            let drained = n < ask && !c.rdhup;
            if drained {
                c.readable = false;
            }
            self.process_input(ci);
            if drained {
                return;
            }
        }
        self.ready.push(tok(K_CLIENT, ci, g));
    }

    fn process_input(&mut self, ci: u32) {
        self.process_frames(ci);
        self.flush_upload();
        self.run_deferred();
    }

    pub(super) fn process_frames(&mut self, ci: u32) {
        if self.clients.at(ci).state == CState::Http {
            self.handle_http(ci);
        }
        loop {
            let c = self.clients.at(ci);
            if c.dead || c.closing || c.state == CState::Http {
                return;
            }
            let avail = &c.rbuf[c.rpos..c.rlen];
            let f = match ws::parse(avail, MAX_FRAME) {
                Ok(Some(f)) => f,
                Ok(None) => {
                    c.need = 14;
                    return;
                }
                Err(e) => {
                    // RFC 6455 7.4.1: 1009 = message too big (as the fragment path below), else 1002
                    self.ws_fail(ci, if matches!(e, ws::FrameError::TooBig) { 1009 } else { 1002 });
                    return;
                }
            };
            let total = f.hdr_len + f.len;
            if avail.len() < total {
                c.need = total;
                return;
            }
            c.need = 0;
            let start = c.rpos + f.hdr_len;
            c.rpos += total;
            let payload = &mut c.rbuf[start..start + f.len];
            let Some(m) = f.mask else {
                self.ws_fail(ci, 1002); // RFC 6455 5.1: clients MUST mask
                return;
            };
            ws::unmask(payload, m);
            // SAFETY: rbuf is not touched (resized/freed) until this frame is handled:
            // handlers never read client input, and client teardown is deferred to end of loop turn.
            let p: &[u8] = unsafe { std::slice::from_raw_parts(payload.as_ptr(), payload.len()) };
            self.on_frame(ci, f.fin, f.opcode, p);
        }
    }

    /// Handshake refusal: connection-level CLOSE(0, reason), WS close 1000, close the socket.
    pub(super) fn wisp_reject(&mut self, ci: u32, reason: u8) {
        let c = self.clients.at(ci);
        c.challenge = None;
        c.push_wisp(PKT_CLOSE, 0, &[reason]);
        self.stats.close[reason as usize].bump(); // 60.12
        ws::push_frame(&mut c.obuf, OP_CLOSE, &[&1000u16.to_be_bytes()]);
        let auth = matches!(reason, ext::CLOSE_BAD_PASSWORD | ext::CLOSE_BAD_SIGNATURE | ext::CLOSE_AUTH_REQUIRED);
        if let Some(l) = connlog::entry(&mut self.connlog, ci) {
            l.auth = if auth { connlog::Auth::Failed } else { l.auth };
        }
        self.begin_close(ci, if auth { Why::AuthFailed } else { Why::ProtocolError });
    }

    pub(super) fn ws_fail(&mut self, ci: u32, code: u16) {
        self.flush_upload(); // its CONTINUE must not land after our Close frame
        let c = self.clients.at(ci);
        ws::push_frame(&mut c.obuf, OP_CLOSE, &[&code.to_be_bytes()]);
        self.begin_close(ci, Why::WsError);
    }

    /// Stop input, drop all streams, close socket once output is flushed.
    /// `why`: see close_client
    pub(super) fn begin_close(&mut self, ci: u32, why: Why) {
        connlog::set_why(&mut self.connlog, ci, why); // 60.24 (empty when --log-conns is off)
        self.drop_streams(ci);
        let c = self.clients.at(ci);
        // 20.19 the WS Close frame is already in obuf; nothing may follow it (RFC 6455 5.5.1), so
        // unsent bulk-lane DATA is dropped (the client closed or broke the protocol; wsproxy never
        // uses the lane), all but the rest of a partly sent frame, which must go out before the Close.
        c.bulk_cut();
        c.closing = true;
        if !c.dirty {
            c.dirty = true;
            self.dirty.push((ci, self.clients.gen(ci)));
        }
    }

    pub(super) fn on_frame(&mut self, ci: u32, fin: bool, op: u8, p: &[u8]) {
        match op {
            OP_BIN | OP_TEXT => {
                if self.clients.at(ci).frag.is_some() {
                    self.ws_fail(ci, 1002); // new data message inside a fragmented one
                    return;
                }
                if fin {
                    if op == OP_BIN {
                        self.on_message(ci, p);
                    }
                } else {
                    self.clients.at(ci).frag = Some((op, p.to_vec()));
                }
            }
            OP_CONT => {
                let c = self.clients.at(ci);
                let Some((fop, buf)) = c.frag.as_mut() else {
                    self.ws_fail(ci, 1002);
                    return;
                };
                if buf.len() + p.len() > MAX_FRAME {
                    self.ws_fail(ci, 1009);
                    return;
                }
                buf.extend_from_slice(p);
                if fin {
                    let (fop, buf) = (*fop, c.frag.take().unwrap().1);
                    if fop == OP_BIN {
                        self.on_message(ci, &buf);
                        self.flush_upload(); // defensive: only rbuf bodies are staged (in_rbuf in on_message), never `buf`
                    }
                }
            }
            OP_PING => {
                self.flush_upload(); // 20.33: every non-DATA frame writes the staged DATA first (as CLOSE, PONG)
                let c = self.clients.at(ci);
                ws::push_frame(&mut c.obuf, OP_PONG, &[p]);
                self.mark_dirty(ci);
            }
            OP_PONG => {
                self.flush_upload(); // 20.33 (review): also for a PONG on_pong does not take
                let c = self.clients.at(ci);
                if let Some(pong) = c.cv.as_mut().and_then(|pg| pg.on_pong(p, Instant::now())) {
                    self.credit_pong(ci, pong);
                }
            }
            OP_CLOSE => {
                if p.len() == 1 {
                    self.ws_fail(ci, 1002);
                    return;
                }
                self.flush_upload(); // its CONTINUE must not land after our Close frame
                let code: &[u8] = if p.len() >= 2 { &p[..2] } else { &[] };
                let c = self.clients.at(ci);
                ws::push_frame(&mut c.obuf, OP_CLOSE, &[code]);
                self.begin_close(ci, Why::ClientClose);
            }
            _ => self.ws_fail(ci, 1002),
        }
    }

    #[inline]
    pub(super) fn mark_dirty(&mut self, ci: u32) {
        let c = self.clients.at(ci);
        if !c.dirty {
            c.dirty = true;
            self.dirty.push((ci, self.clients.gen(ci)));
        }
    }
}
