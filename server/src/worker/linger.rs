//! 60.78 bundle B3 lingering close (20.06 "Unread input at close"): a closing client whose input may still be unread is
//! not closed when its output is drained. close() with unread bytes in the receive queue makes TCP send RST, and a RST
//! drops our unsent tail (the kernel send queue: everything after the bytes the client already ACKed) and can drop
//! what the client has not read yet. So, as Apache / nginx do: shut down our direction (FIN after the queue), read and
//! discard until the client's EOF, then close(). kTLS first waits until its records are in TCP (Client::ktls_drained:
//! records still on the kTLS list die with SHUT_WR or close), then does the same.
//!
//! Which closes linger (flush_dirty): every kTLS close (as before), and a plain close whose input may be unread:
//! `readable` (EPOLLIN since the last short read; begin_close sets it for a close the server starts after the upgrade)
//! or bytes after the frame that ended it (rpos < rlen). A client that closed cleanly (its WebSocket Close or EOF read
//! to the end) and an HTTP refusal of a request that came alone close at once, as before.
//! Bounds (consts, no option): LINGER_PLAIN / LINGER_TLS from the start of the linger, LINGER_BYTES discarded; a
//! close at a bound may send RST and is counted (linger_capped). A lingering client keeps its fd and connection counts
//! until close_client. A close during shutdown does not wait for the client's EOF (linger_start), and at the close
//! phase every deadline is cut to LINGER_STOP (shutdown_step).
use super::*;

/// a plain close waits at most this for the client's EOF (nginx lingering_timeout)
pub(super) const LINGER_PLAIN: Duration = Duration::from_secs(5);
/// a kTLS close: its records into TCP, then the client's EOF (KTLS_LINGER before 60.78)
pub(super) const LINGER_TLS: Duration = Duration::from_secs(10);
/// at most this many bytes are read and discarded per connection
pub(super) const LINGER_BYTES: u64 = 1 << 20;
/// shutdown's close phase (main exits CLOSE_GRACE = 2 s after it starts): what is left of every linger, and the longest
/// kTLS drain wait of a close started then (in the drain phase a kTLS close keeps LINGER_TLS for its records)
pub(super) const LINGER_STOP: Duration = Duration::from_secs(1);

/// a Worker::lingering entry
#[derive(Clone, Copy)]
pub(super) struct Linger {
    pub(super) ci: u32,
    pub(super) g: u32,
    pub(super) until: Instant,
    read: u64,  // bytes discarded so far
    shut: bool, // our direction is shut down (plain: at once; kTLS: once its records are in TCP)
    eof: bool,  // kTLS: the client's EOF or close_notify came before its records were in TCP (or shutdown: no wait)
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(super) enum Drain {
    /// nothing more to read now
    More,
    /// the client's EOF (or its close_notify)
    Eof,
    /// a read error (reset, timeout) or a TLS record that ends the connection
    Io,
    /// LINGER_BYTES discarded
    Capped,
}

impl Worker {
    /// flush_dirty: the output of closing client `ci` is drained and its input may be unread
    #[cold]
    #[inline(never)]
    pub(super) fn linger_start(&mut self, ci: u32, g: u32) {
        let c = self.clients.at(ci);
        c.lingering = true;
        // its buffers go now (as the idle sweep frees them): the output is drained, and what the client sends from here
        // is read into linger_drain's stack buffer; bytes still unparsed in rbuf are input after the close, discarded
        // (need, rstall: no frame in progress any more, so the holder shed at level 2+ never resets a lingering client)
        c.rbuf = Vec::new();
        (c.rpos, c.rlen, c.need, c.rstall) = (0, 0, 0, 0);
        c.frag = None;
        c.obuf = Vec::new();
        c.ohead = 0;
        c.bulk_drop();
        let tls = c.ktls_on;
        if tls {
            c.ktls_notify();
        } else {
            unsafe { libc::shutdown(c.fd, libc::SHUT_WR) };
        }
        // during shutdown (its 1001 closes) no wait for the client's EOF: what it sent so far is read (close() then
        // finds nothing unread, unless more is on its way) and the socket closes; kTLS once its records are in TCP
        let quick = self.stop_seen != 0;
        let until = Instant::now()
            + match () {
                _ if self.stop_seen >= net::STOP_CLOSE => LINGER_STOP,
                _ if tls => LINGER_TLS,
                _ => LINGER_PLAIN,
            };
        let mut e = Linger { ci, g, until, read: 0, shut: !tls, eof: quick };
        if !tls {
            // (the client may have closed already: then there is nothing to wait for)
            match self.linger_drain(ci, &mut e.read) {
                Drain::More if !quick => {}
                Drain::More => return self.linger_end(ci, Drain::Eof),
                d => return self.linger_end(ci, d),
            }
        }
        self.lingering.push(e);
    }

    /// Read and discard what client `ci` sent (counted in `read`, at most LINGER_BYTES in all)
    pub(super) fn linger_drain(&mut self, ci: u32, read: &mut u64) -> Drain {
        let mut buf = [0u8; 16384];
        loop {
            if *read >= LINGER_BYTES {
                return Drain::Capped;
            }
            let c = self.clients.at(ci);
            let n = unsafe { libc::read(c.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n > 0 {
                *read += n as u64;
                self.rx_total += n as u64; // (rx_bytes: bytes read from client sockets)
                continue;
            }
            if n == 0 {
                return Drain::Eof;
            }
            let e = net::errno();
            if would_block(e) {
                return Drain::More;
            }
            if e == libc::EIO && c.ktls_on {
                match self.linger_control(ci) {
                    Some(true) => {
                        *read += buf.len() as u64; // (a KeyUpdate counts as a full record: a flood of them is bounded too)
                        continue;
                    }
                    Some(false) => return Drain::Eof,
                    None => return Drain::Io,
                }
            }
            return Drain::Io;
        }
    }

    /// A kTLS control record while lingering (not tls_control: that one closes at once and answers a KeyUpdate, and our
    /// direction ended with close_notify). Some(true): a KeyUpdate, the client's next key is installed; Some(false):
    /// its close_notify (as EOF); None: anything else (the connection ends).
    fn linger_control(&mut self, ci: u32) -> Option<bool> {
        let c = self.clients.at(ci);
        let mut rec = [0u8; 64];
        match tls::recv_record(c.fd, &mut rec) {
            Ok((tls::REC_ALERT, 2)) if rec[..2] == [1, 0] => Some(false),
            Ok((tls::REC_HANDSHAKE, n)) => {
                tls::parse_key_update(&rec[..n])?;
                let s = c.ktls.as_mut()?.update_rx_secret().ok()?;
                if let Err(e) = tls::rekey(c.fd, true, &s) {
                    tls::key_update_refused(&e); // (as tls_control: Linux < 6.14 has no kTLS rekey)
                    return None;
                }
                c.rx_left = TLS_RECORD_BUDGET;
                Some(true)
            }
            _ => None,
        }
    }

    /// close a lingering client after `d` (More: its deadline)
    fn linger_end(&mut self, ci: u32, d: Drain) {
        let why = match d {
            Drain::Io => Why::Io,
            Drain::Eof => Why::ServerClose,
            Drain::More | Drain::Capped => {
                self.stats.linger_capped.bump();
                Why::ServerClose
            }
        };
        self.close_client(ci, why); // (begin_close named the reason first: it stays in the log)
    }

    /// review r1 / 60.78: once per TIMER_TICK_MS: read what the lingering clients sent, shut kTLS ones down once their
    /// records are in TCP, close at EOF or at a bound. An entry whose slot was reused or whose client is dead goes.
    pub(super) fn linger_check(&mut self) {
        let now = Instant::now();
        if now < self.next_linger {
            return;
        }
        self.next_linger = now + Duration::from_millis(TIMER_TICK_MS as u64);
        let mut k = 0;
        while k < self.lingering.len() {
            let mut e = self.lingering[k];
            if !self.clients.get(e.ci, e.g).is_some_and(|c| !c.dead) {
                self.lingering.swap_remove(k);
                continue;
            }
            let d = self.linger_drain(e.ci, &mut e.read);
            let end = match d {
                Drain::Io | Drain::Capped => Some(d),
                Drain::Eof if e.shut => Some(d),
                Drain::Eof | Drain::More => {
                    e.eof |= d == Drain::Eof;
                    let c = self.clients.at(e.ci);
                    if !e.shut && c.ktls_drained() {
                        if e.eof {
                            Some(Drain::Eof) // (the client sent all it will: close() now finds nothing unread)
                        } else {
                            unsafe { libc::shutdown(c.fd, libc::SHUT_WR) };
                            e.shut = true;
                            None
                        }
                    } else {
                        None
                    }
                }
            };
            let end = end.or((now >= e.until).then_some(Drain::More));
            match end {
                Some(d) => {
                    self.lingering.swap_remove(k);
                    self.linger_end(e.ci, d);
                }
                None => {
                    self.lingering[k] = e;
                    k += 1;
                }
            }
        }
    }

    /// shutdown_step, close phase: what is left of every linger fits in main's last grace period
    pub(super) fn linger_cut(&mut self) {
        let cut = Instant::now() + LINGER_STOP;
        for e in &mut self.lingering {
            e.until = e.until.min(cut);
        }
    }
}
