//! 20.13 built-in TLS: handshake, kTLS control records and KeyUpdate (20.17 / 60.15 T40), closing-socket linger
//! (review r1), and the 50.02 send-starvation retry.

use super::*;

impl Worker {
    /// Drive a client's handshake: feed whole records to rustls, send its output, and move the
    /// keys into the kernel once the handshake is done and every handshake byte is on the wire.
    pub(super) fn tls_drive(&mut self, ci: u32) {
        let hs_res = self.tls_read_records(ci);
        if let Hs::Close = hs_res {
            return self.close_client(ci, Why::TlsError);
        }
        if let Hs::Fail = hs_res {
            connlog::set_why(&mut self.connlog, ci, Why::TlsError); // 60.24 also when the alert below cannot be sent
        }
        // send what rustls produced: handshake flights, or (Fail) its alert, best effort
        let c = self.clients.at(ci);
        let Some(hs) = c.tls.as_mut() else { return };
        while hs.sent < hs.out.len() {
            let rest = &hs.out[hs.sent..];
            let n = unsafe { libc::send(c.fd, rest.as_ptr() as *const _, rest.len(), libc::MSG_NOSIGNAL) };
            if n < 0 {
                if would_block(net::errno()) && matches!(hs_res, Hs::Ok) {
                    return; // rest on EPOLLOUT
                }
                return self.close_client(ci, Why::ClientClose);
            }
            hs.sent += n as usize;
        }
        hs.out.clear();
        hs.sent = 0;
        match hs_res {
            Hs::Ok if hs.done => self.tls_finish(ci),
            Hs::Ok => {}
            _ => self.close_client(ci, Why::TlsError),
        }
    }

    /// Read and process handshake records one at a time: first the 5-byte header, then exactly
    /// the body. Never reads past the current record, so no byte meant for the kernel (records
    /// after the client's Finished) can end up inside rustls. Partial bytes stay in rbuf.
    fn tls_read_records(&mut self, ci: u32) -> Hs {
        let g = self.clients.gen(ci);
        let c = self.clients.at(ci);
        for _ in 0..TLS_RECORDS_PER_TURN {
            let Some(hs) = c.tls.as_mut() else { return Hs::Ok };
            if !c.readable || hs.done {
                return Hs::Ok;
            }
            // rbuf[..kept]: bytes rustls still holds on to; rbuf[kept..rlen]: the next record so far
            let k = hs.kept;
            let need = if c.rlen < k + tls::HEADER {
                k + tls::HEADER
            } else {
                match tls::record_len(&c.rbuf[k..k + tls::HEADER]) {
                    Some(len) => k + tls::HEADER + len,
                    None => {
                        connlog::set_why(&mut self.connlog, ci, Why::ProtocolError);
                        return Hs::Close; // not TLS (plain HTTP, garbage)
                    }
                }
            };
            if c.rlen < need {
                if c.rbuf.len() < need {
                    c.rbuf.resize(need.max(4096), 0); // the 20.11 idle sweep may have freed it
                }
                let n = unsafe { libc::read(c.fd, c.rbuf.as_mut_ptr().add(c.rlen) as *mut _, need - c.rlen) };
                if n < 0 && would_block(net::errno()) {
                    c.readable = false;
                    return Hs::Ok;
                }
                if n <= 0 {
                    connlog::set_why(&mut self.connlog, ci, Why::ClientClose); // EOF or reset during the handshake
                    return Hs::Close;
                }
                c.rlen += n as usize;
                c.active = true;
                continue;
            }
            let (step, used) = tls::hs_step(&mut hs.conn, &mut c.rbuf[..need], &mut hs.out);
            c.rbuf.copy_within(used..need, 0);
            c.rlen = need - used;
            hs.kept = c.rlen;
            match step {
                tls::Step::More => {}
                tls::Step::Done => {
                    hs.done = true;
                    return Hs::Ok;
                }
                tls::Step::Fail => return Hs::Fail,
                tls::Step::Close => {
                    connlog::set_why(&mut self.connlog, ci, Why::ClientClose); // close_notify
                    return Hs::Close;
                }
            }
        }
        self.ready.push(tok(K_CLIENT, ci, g));
        Hs::Ok
    }

    /// Handshake done and flushed: install kTLS TX+RX, keep the rustls key schedule for TLS 1.3
    /// KeyUpdates (20.17), continue as a plain HTTP client. Everything from here on is ordinary
    /// socket I/O.
    fn tls_finish(&mut self, ci: u32) {
        let rekey = self.cfg.tls_rekey;
        let c = self.clients.at(ci);
        let Some(hs) = c.tls.take() else { return };
        let version = hs.conn.protocol_version();
        // rustls keeps no bytes after the client's Finished (we never fed it any): rlen must be 0
        let kernel = match (version, c.rlen, hs.conn.dangerous_into_kernel_connection()) {
            (Some(v), 0, Ok((secrets, k))) if tls::install(c.fd, v, &secrets).is_ok() => k,
            _ => return self.close_client(ci, Why::TlsError),
        };
        c.ktls_on = true;
        c.tx_left = TLS_RECORD_BUDGET;
        c.rx_left = TLS_RECORD_BUDGET;
        if version == Some(rustls::ProtocolVersion::TLSv1_3) {
            c.ktls = Some(Box::new(kernel));
            c.rekey_at = if rekey == 0 { 0 } else { TLS_RECORD_BUDGET.saturating_sub(rekey) };
        }
        c.state = CState::Http;
        c.rpos = 0;
        c.need = 0;
        // The edge for data that arrived after the client's Finished may already be consumed
        // (we stopped reading at the record boundary), so read actively once now.
        c.readable = true;
        self.read_client(ci);
    }

    /// 20.17 read() on a kTLS client failed with EIO: the next record is not application data
    /// (kTLS keeps it queued). recvmsg it with its type. TLS 1.3 KeyUpdate: install the client's
    /// next key and queue ours if it asked. close_notify: close (close_client answers with ours).
    /// Other alerts or records: close. Returns true if the connection goes on.
    pub(super) fn tls_control(&mut self, ci: u32) -> bool {
        let c = self.clients.at(ci);
        let mut rec = [0u8; 64];
        let ok = match tls::recv_record(c.fd, &mut rec) {
            Ok((tls::REC_HANDSHAKE, n)) => match (tls::parse_key_update(&rec[..n]), c.ktls.as_mut()) {
                (Some(requested), Some(k)) => match k.update_rx_secret().map(|s| tls::rekey(c.fd, true, &s)) {
                    Ok(Ok(())) => {
                        c.rx_left = TLS_RECORD_BUDGET;
                        c.ku_asked = false;
                        c.ku = ku_after_peer_update(requested, c.ku);
                        if c.ku != 0 && !c.dirty {
                            c.dirty = true;
                            self.dirty.push((ci, self.clients.gen(ci)));
                        }
                        true
                    }
                    Ok(Err(e)) => {
                        tls::key_update_refused(&e); // 60.12: Linux < 6.14 (no kTLS rekey): count + rate-limited log
                        false
                    }
                    Err(_) => false,
                },
                _ => false, // TLS 1.2 renegotiation, post-handshake auth, malformed: not supported
            },
            Ok((tls::REC_ALERT, 2)) if rec[..2] == [1, 0] => {
                connlog::set_why(&mut self.connlog, ci, Why::ClientClose); // close_notify
                false
            }
            Ok((tls::REC_ALERT, _)) => {
                c.ktls_on = false; // other alerts are fatal: close without close_notify (RFC 8446 6.2)
                false
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // unreachable: we only get here after read() returned EIO, so the control record is already on rx_list
                c.readable = false;
                true
            }
            _ => false,
        };
        if !ok {
            self.close_client(ci, Why::TlsError);
        }
        ok
    }

    /// Close clients whose handshake is not done within TLS_HANDSHAKE_TIMEOUT.
    pub(super) fn tls_timeouts(&mut self) {
        let now = Instant::now();
        while let Some(&(ci, g, at)) = self.tls_deadlines.front() {
            if at > now {
                break;
            }
            self.tls_deadlines.pop_front();
            if matches!(self.clients.get(ci, g), Some(c) if !c.dead && c.state == CState::Tls) {
                self.stats.tls_expired.bump(); // 60.12
                self.close_client(ci, Why::HsTimeout);
            }
        }
    }

    /// review r1: close the kTLS clients waiting on `lingering` once drained (Client::ktls_drained)
    /// or at their deadline. An entry whose slot was reused or whose client is already dead goes.
    pub(super) fn linger_check(&mut self) {
        let now = Instant::now();
        if now < self.next_linger {
            return;
        }
        self.next_linger = now + Duration::from_millis(TIMER_TICK_MS as u64);
        let mut k = 0;
        while k < self.lingering.len() {
            let (ci, g, until) = self.lingering[k];
            let close = match self.clients.get(ci, g) {
                Some(c) if !c.dead => {
                    if now < until && !c.ktls_drained() {
                        k += 1;
                        continue;
                    }
                    true
                }
                _ => false,
            };
            self.lingering.swap_remove(k);
            if close {
                self.close_client(ci, Why::ServerClose);
            }
        }
    }

    /// 50.02 retry the starved kTLS sends that are due (Client::starve_at) through flush_dirty, which then sends
    /// everything queued as one request (A2, Client::send_gather). B (starve_room, read_target): the blocked streams may
    /// also read a slice each past the caps, from the second retry if that request is below STARVE_MIN_SEND, else from
    /// the third (two gathers failed). Entries of ended episodes and closed clients go.
    pub(super) fn starve_check(&mut self) {
        let now = Instant::now();
        let mut k = 0;
        while k < self.starved.len() {
            let (ci, g) = self.starved[k];
            let Some(c) = self.clients.get(ci, g).filter(|c| !c.dead && c.starve > 0) else {
                self.starved.swap_remove(k);
                continue;
            };
            k += 1;
            if now < c.starve_at {
                continue;
            }
            c.starve_at = now + starve_delay(c.starve.saturating_add(1)); // (flush_dirty re-arms it if still starved)
            c.starve_due = true;
            // A2 (send_gather, every retry) offers everything queued in one request. B is the fallback: at once if that
            // request is below the forced-charge size, else once two gathers failed (review: the kernel
            // does not moderate a SO_SNDBUF-locked socket (net::cap_bufs), and a page-frag rest can cut the charge
            // below 4608, so a big request is no guarantee). Bounded by STARVE_CAP over out_high.
            if c.starve >= 3 || (c.starve >= 2 && c.gather_len() < STARVE_MIN_SEND) {
                c.starve_room = starve_room(c.out_pending(), self.st.out_high, c.blocked.len() + c.blocked_bulk.len());
                if c.starve_room > 0 {
                    if !std::mem::replace(&mut c.starve_b, true) {
                        self.stats.ktls_starve_slices.bump();
                    }
                    self.ready.append(&mut c.blocked);
                    self.ready.append(&mut c.blocked_bulk);
                    c.bulk_waiting = 0;
                }
            }
            if !c.dirty {
                c.dirty = true;
                self.dirty.push((ci, g));
            }
        }
    }
}

/// 50.02 what one flush of a client says about a kTLS send starve episode (Worker::flush_dirty). Starved = a kTLS
/// socket took no more (`wblock`), output is still pending and nothing is in flight (SIOCOUTQ 0, read only then):
/// over tcp_mem[2], or under pressure (above tcp_mem[1]) for a socket above the average share, the kernel refuses
/// the record (sk_msg_alloc has no forced minimum, unlike TCP's tcp_wmem_schedule) and returns EAGAIN, and with an
/// empty queue no ACK ever raises EPOLLOUT (VPS1: 60 of 100 wss runs under pressure; at the hard limit, where
/// nothing else frees memory, base-3 stalled the whole run).
#[derive(Debug, PartialEq)]
pub(super) enum Starve {
    None,
    Start,
    Again,
    End,
}

pub(super) fn starve_step(ktls: bool, wblock: bool, pending: bool, outq: impl FnOnce() -> i32, starve: u8) -> Starve {
    let starved = ktls && wblock && pending && outq() == 0;
    match (starved, starve > 0) {
        (true, false) => Starve::Start,
        (true, true) => Starve::Again,
        (false, true) => Starve::End,
        (false, false) => Starve::None,
    }
}

/// 50.02 delay before retry `n` (1, 2, ...) of a starved send: STARVE_RETRY_MS doubling, at most TIMER_TICK_MS
pub(super) fn starve_delay(n: u8) -> Duration {
    Duration::from_millis((STARVE_RETRY_MS << n.saturating_sub(1).min(16)).min(TIMER_TICK_MS as u64))
}

/// 50.02 B: bytes a starved client's `streams` blocked streams may read now past their cap: STARVE_SLICE each, while its
/// pending output stays within STARVE_CAP over `cap` (out_high)
pub(super) fn starve_room(pending: usize, cap: usize, streams: usize) -> u32 {
    let left = STARVE_CAP.saturating_sub(pending.saturating_sub(cap));
    STARVE_SLICE.saturating_mul(streams).min(left) as u32
}

/// 20.15: the bytes of the first TLS record if it is a handshake record starting a ClientHello
/// (content type 0x16, version 0x03xx, handshake type 1). Only that record, never what follows it.
pub(super) fn client_hello(p: &[u8]) -> Option<&[u8]> {
    if p.len() < 6 || p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01 {
        return None;
    }
    let rec = 5 + u16::from_be_bytes([p[3], p[4]]) as usize;
    Some(&p[..rec.min(p.len())])
}

/// 20.17 / 60.15 T40: our pending KeyUpdate after the peer's KeyUpdate was installed. Its update_requested owes a reply
/// (3: update_not_requested before our next application data, RFC 8446 4.6.3; it also serves as our own update); without
/// it, our pending ask (2) is moot (the peer just changed its key): send a plain update (1), as 20.17 did.
pub(super) fn ku_after_peer_update(requested: bool, ku: u8) -> u8 {
    match (requested, ku) {
        (true, _) => 3,
        (false, 2) => 1,
        (false, k) => k,
    }
}

/// 20.13 outcome of reading handshake records
enum Hs {
    Ok,    // keep going (or wait for readiness)
    Close, // EOF, socket error, not TLS: close silently
    Fail,  // rustls rejected the handshake: send its alert, then close
}
