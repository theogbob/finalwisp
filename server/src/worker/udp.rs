//! 20.16 UDP streams.

use super::*;

impl Worker {
    /// Open the connected datagram socket: the first address (filtered + interleaved like TCP) whose
    /// connect() succeeds. connect() on UDP sends nothing, so there is no timeout or racing; it fixes
    /// the peer, and the kernel then only delivers datagrams from that address and port.
    pub(super) fn udp_open(&mut self, ti: u32) {
        let tg = self.targets.gen(ti);
        let t = self.targets.at(ti);
        let addrs = std::mem::take(&mut t.addrs);
        let port = t.port;
        let mut err = 0;
        // 60.57 A2/A4 the socket's fd in the count (one for the stream: the loop holds one socket at a time)
        if !self.fd_take_t_cold(ti) {
            return self.fd_short(ti);
        }
        for ip in addrs {
            match net::udp_connect(&SocketAddr::new(ip, port)) {
                Ok(fd) => {
                    if !ep_add(self.ep, fd, tok(K_TARGET, ti, tg), (libc::EPOLLIN | libc::EPOLLET) as u32) {
                        unsafe { libc::close(fd) };
                        err = libc::ENOMEM;
                        continue;
                    }
                    let t = self.targets.at(ti);
                    t.fd = fd;
                    t.state = TState::Open;
                    if !self.streamlog.is_empty() {
                        if let Some(l) = self.slog(ti) {
                            l.dst = Some(ip); // 60.35
                        }
                    }
                    let t = self.targets.at(ti);
                    // datagrams that arrived while resolving: [u16 LE len][bytes] records
                    let pend = std::mem::take(&mut t.pend);
                    let mut p = &pend[..];
                    while p.len() >= 2 {
                        let n = u16::from_le_bytes([p[0], p[1]]) as usize;
                        match udp_send_one(fd, &p[2..2 + n]) {
                            Err(()) => return self.target_eof(ti, CLOSE_NETWORK),
                            Ok(true) if !self.streamlog.is_empty() => self.slog_udp_up(ti, n), // 60.35 sent only
                            Ok(_) => {}
                        }
                        p = &p[2 + n..];
                    }
                    return;
                }
                Err(e) => err = e,
            }
        }
        self.fd_put_t(ti, 1); // no address gave a socket
        let t = self.targets.at(ti);
        if t.dns_more {
            t.err = err; // 70.10 every early address failed: the final answer (other family) retries via start_connect
                         // (60.39: start_connect reads `udp && err != 0` as "already charged per destination")
            return;
        }
        if !self.streamlog.is_empty() {
            self.slog_why(ti, SWhy::ConnectFail, ""); // 60.35 (the addresses are taken: not a DNS failure)
        }
        self.connect_failed(0); // 60.57 A6 (a UDP connect sends nothing: never a timeout)
        self.fail_target(ti, if err == 0 { CLOSE_UNREACHABLE } else { net::connect_reason(err) });
    }

    /// Upload: one DATA payload = one datagram, never buffered once open. A full socket buffer or an
    /// ICMP error drops it (UDP semantics); payloads over UDP_MAX are dropped.
    pub(super) fn udp_send(&mut self, ti: u32, data: &[u8]) {
        if data.len() > UDP_MAX {
            return;
        }
        let t = self.targets.at(ti);
        if t.state != TState::Open {
            // 60.15 T03 P4 review: level 3 reads clients without a counted backlog, and this queue is not counted
            // (c.pend): drop instead, as a full socket would (UDP semantics)
            if self.st.read && t.pend.len() + 2 + data.len() <= UDP_PEND_MAX {
                t.pend.extend_from_slice(&(data.len() as u16).to_le_bytes());
                t.pend.extend_from_slice(data);
            }
            return;
        }
        match udp_send_one(t.fd, data) {
            Err(()) => self.target_eof(ti, CLOSE_NETWORK),
            // 60.35 datagrams sent (a dropped one is not counted). OFF: this test per datagram, not taken
            Ok(true) if !self.streamlog.is_empty() => self.slog_udp_up(ti, data.len()),
            Ok(_) => {}
        }
    }

    /// Download: recvmmsg up to UDP_BATCH datagrams into the worker scratch, one DATA packet each (fewer when
    /// the room under out_high is small, 60.15 T02). Fewer than asked = queue drained, so no EAGAIN round trip, unless an ICMP error is pending
    /// (`rdhup`, set on EPOLLERR): recvmmsg stops a batch at the error and stores it again without a
    /// new edge, so then we read until EAGAIN. (An error arriving after epoll_wait raises its own
    /// edge.) Back-pressure as for TCP: above OUT_HIGH the target parks in `blocked` and the kernel
    /// drops what overflows its receive buffer.
    pub(super) fn read_udp(&mut self, ti: u32) {
        let tg = self.targets.gen(ti);
        if self.udp_buf.is_empty() {
            self.udp_buf = vec![0u8; UDP_BATCH * UDP_SLOT];
        }
        for _ in 0..BUDGET {
            let t = self.targets.at(ti);
            if t.blocked {
                return;
            }
            let (fd, ci, sid, err_pending) = (t.fd, t.client, t.sid, t.rdhup);
            let c = self.clients.at(ci);
            let pending = c.out_pending();
            if pending >= self.st.out_high {
                self.targets.at(ti).blocked = true;
                c.blocked.push(tok(K_TARGET, ti, tg));
                return;
            }
            // 60.15 T02: as read_target, compact a sent prefix that is at least the unsent rest, and read only as many
            // datagrams as the room under out_high can take (each is at most UDP_SLOT): obuf stays below out_high +
            // one datagram payload + the frame headers (was up to UDP_BATCH x UDP_SLOT = ~512 KiB past it, plus the sent prefix)
            if c.ohead > 0 && c.ohead >= c.obuf.len() - c.ohead {
                c.compact();
            }
            let vlen = (self.st.out_high - pending).div_ceil(UDP_SLOT).min(UDP_BATCH);
            // SAFETY: udp_buf holds UDP_BATCH x UDP_SLOT bytes (allocated above), so every iovec is in bounds;
            // iov and msgs live on this stack frame for the whole recvmmsg call; zeroed iovec/mmsghdr are valid.
            let base = self.udp_buf.as_mut_ptr();
            let mut iov: [libc::iovec; UDP_BATCH] = unsafe { std::mem::zeroed() };
            let mut msgs: [libc::mmsghdr; UDP_BATCH] = unsafe { std::mem::zeroed() };
            for (i, (v, m)) in iov.iter_mut().zip(msgs.iter_mut()).enumerate() {
                *v = libc::iovec { iov_base: unsafe { base.add(i * UDP_SLOT) } as *mut _, iov_len: UDP_SLOT };
                m.msg_hdr.msg_iov = v;
                m.msg_hdr.msg_iovlen = 1;
            }
            let n = unsafe { libc::recvmmsg(fd, msgs.as_mut_ptr(), vlen as _, libc::MSG_DONTWAIT as _, std::ptr::null_mut()) };
            if n < 0 {
                let e = net::errno();
                if would_block(e) {
                    self.targets.at(ti).rdhup = false;
                    return;
                }
                if net::udp_soft_error(e) {
                    continue; // ICMP error consumed (sk_err cleared); datagrams may still be queued
                }
                return self.target_eof(ti, CLOSE_NETWORK);
            }
            let n = n as usize;
            let c = self.clients.at(ci);
            for (i, m) in msgs[..n].iter().enumerate() {
                let len = (m.msg_len as usize).min(UDP_SLOT); // 0-byte datagrams are valid DATA
                c.push_wisp(PKT_DATA, sid, &self.udp_buf[i * UDP_SLOT..i * UDP_SLOT + len]);
            }
            if n > 0 {
                c.active = true;
                if !c.dirty {
                    c.dirty = true;
                    self.dirty.push((ci, self.clients.gen(ci)));
                }
                if !self.streamlog.is_empty() {
                    // 60.35 (OFF: this test per recvmmsg batch, not taken)
                    let bytes = msgs[..n].iter().map(|m| (m.msg_len as usize).min(UDP_SLOT) as u64).sum();
                    self.slog_udp_down(ti, n as u64, bytes);
                }
            }
            if n < vlen && !err_pending {
                return;
            }
        }
        self.ready.push(tok(K_TARGET, ti, tg));
    }
}

/// 20.16 send one datagram. A pending ICMP error is reported by (and eats) the next send, so a soft
/// error is retried once; then the datagram is dropped. Err(()) = the socket itself is broken.
/// Ok(true) sent, Ok(false) dropped (a full socket buffer, or a soft error twice: UDP semantics), Err the socket failed
fn udp_send_one(fd: RawFd, data: &[u8]) -> Result<bool, ()> {
    for _ in 0..2 {
        let n = unsafe { libc::send(fd, data.as_ptr() as *const _, data.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        if n >= 0 {
            return Ok(true);
        }
        let e = net::errno();
        if would_block(e) {
            return Ok(false); // socket buffer full: drop
        }
        if !net::udp_soft_error(e) {
            return Err(());
        }
    }
    Ok(false)
}
