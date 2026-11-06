//! 60.34 PROXY protocol v1/v2 on a listener (--proxy-protocol tcp|unix; design 60.28, parser crate::proxyproto).
//! A connection on such a listener is not a client until its header has come: it waits in `Worker::pending` (by fd,
//! outside the slab: no Client slot, no buffer), registered in epoll as tok(K_LISTEN, PENDING0 + fd). Its Inbox.load
//! was counted once, by route on this (the final) worker, and it holds its --max-conns reservation; it is charged per IP
//! only after the header names the client. Exactly one release follows: `pending_drop`, or `adopt` (whose failure
//! exits and close_client release load, reservation and key: 60.22 unload).
use super::*;
use crate::proxyproto::{self, Parse};

/// tok(K_LISTEN, idx): 0 = the TCP listener, 1 = the unix listener, PENDING0 + fd = a connection waiting for its header
pub(super) const PENDING0: u32 = 2;
/// idle sweeps (IDLE_SWEEP_MS = 2 s each) a header may take: 4-6 s (60.28 Q6: fixed; the spec asks for at least 3 s, a
/// TCP retransmit). After an idle gap (epoll_wait(-1) passed the sweep deadline) up to ~8 s once, as HS_SWEEPS.
const PROXY_SWEEPS: u8 = 3;

pub(super) struct Pending {
    kind: u8,
    peer: Option<IpAddr>,
    sweeps: u8,
}

impl Worker {
    /// K_LISTEN events: idx 0 = the TCP listener, 1 = the unix listener (60.31 C7), PENDING0 + fd = a connection waiting
    /// for its header. Out of line: the match inlined into run moved run's register allocation (60.34 disassembly).
    #[inline(never)]
    pub(super) fn listen_event(&mut self, idx: u32, e: u32) {
        match idx {
            0 | 1 => self.accept_on(idx == 1),
            i => self.pending_event((i - PENDING0) as RawFd, e),
        }
    }

    /// A connection this worker owns (load counted): a PROXY listener's waits for its header, the rest is adopted.
    /// Called by route (accepted here) and inbox_ready (handed over).
    pub(super) fn take(&mut self, h: net::Handoff) {
        if h.kind & net::L_PROXY != 0 {
            self.pending_add(h);
        } else {
            self.adopt(h);
        }
    }

    fn pending_add(&mut self, h: net::Handoff) {
        let ev = (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32;
        if !ep_add(self.ep, h.fd, tok(K_LISTEN, PENDING0 + h.fd as u32, 0), ev) {
            unsafe { libc::close(h.fd) };
            self.unload(None);
            if self.cfg.log_conns {
                self.log_refused(h.peer, Why::ServerClose);
            }
            return;
        }
        self.pending.insert(h.fd, Pending { kind: h.kind, peer: h.peer, sweeps: 0 });
        self.pending_event(h.fd, 0); // the header often came with the handshake's last ACK (ADD reports it, but read now)
    }

    /// The one release of a pending connection: out of the map, closed (RST if `reset`; also leaves the epoll set),
    /// Inbox.load and the --max-conns reservation (no per-IP key yet: unload(None)). `why` for --log-conns
    /// (`ev=conn_refused`); ClientClose is not logged (a load balancer's TCP health check connects and closes).
    #[inline(never)]
    fn pending_drop(&mut self, fd: RawFd, reset: bool, why: Why) {
        let Some(p) = self.pending.remove(&fd) else { return };
        if reset {
            net::linger_zero(fd);
        }
        unsafe { libc::close(fd) };
        self.unload(None);
        if self.cfg.log_conns && why != Why::ClientClose {
            self.log_refused(p.peer, why);
        }
    }

    /// Readable (or hung up) pending connection `fd` (`e`: the epoll events, 0 from pending_add): peek, parse, consume
    /// exactly the header, charge per IP, adopt on this worker.
    pub(super) fn pending_event(&mut self, fd: RawFd, e: u32) {
        let Some(p) = self.pending.get(&fd) else { return }; // stale: closed (a reused fd number has a client token)
        let (kind, peer) = (p.kind, p.peer);
        let mut b = [0u8; proxyproto::MAX_HEADER];
        let n = unsafe { libc::recv(fd, b.as_mut_ptr() as *mut _, b.len(), libc::MSG_PEEK | libc::MSG_DONTWAIT) };
        if n < 0 && would_block(net::errno()) {
            return;
        }
        if n <= 0 {
            self.pending_drop(fd, false, Why::ClientClose); // EOF or an error before the header
            return;
        }
        let (len, src) = match proxyproto::parse(&b[..n as usize]) {
            Parse::Partial if e & (libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 => {
                self.pending_drop(fd, false, Why::ClientClose); // the rest can never come
                return;
            }
            Parse::Partial => return, // the next segment is a new edge; the sweep bounds the wait
            Parse::Bad => {
                self.stats.pp_bad.bump();
                self.pending_drop(fd, true, Why::ProtocolError);
                return;
            }
            Parse::Done { len, src } => (len, src),
        };
        // consume exactly the header (all of it is queued: the peek saw it); what follows stays for TLS / HTTP
        let got = unsafe { libc::recv(fd, b.as_mut_ptr() as *mut _, len, libc::MSG_DONTWAIT) };
        if got != len as isize {
            self.pending_drop(fd, true, Why::ServerClose);
            return;
        }
        let mut h = net::Handoff::bare(fd);
        h.kind = kind;
        // the header's source is the peer from now on (60.28: PROXY decides who the peer is; a trusted one's
        // X-Forwarded-For refines it at the upgrade); none (LOCAL, UNSPEC, UNKNOWN, AF_UNIX): the real endpoint
        h.peer = src.or(peer);
        if !self.charge(&mut h) {
            if let Some(p) = self.pending.get_mut(&fd) {
                p.peer = h.peer; // the line names the client over its limit, not the load balancer (review)
            }
            self.pending_drop(fd, true, Why::Limit); // over --max-conns-per-ip for the header's source
            return;
        }
        if src.is_none() {
            self.stats.pp_local.bump(); // (after the charge: pp_local is a part of pp_ok, review)
        }
        self.pending.remove(&fd);
        // adopt registers the client token (EPOLL_CTL_ADD reports the queued request, so no edge is lost)
        unsafe { libc::epoll_ctl(self.ep, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
        self.stats.pp_ok.bump();
        self.adopt(h);
    }

    /// Idle sweep: headers still missing after PROXY_SWEEPS sweeps are reset
    #[cold]
    #[inline(never)] // (60.34 disassembly: inlined into run via idle_sweep / shutdown_step it moved run's registers)
    pub(super) fn pending_sweep(&mut self) {
        let late: Vec<RawFd> = self
            .pending
            .iter_mut()
            .filter_map(|(&fd, p)| {
                p.sweeps += 1;
                (p.sweeps >= PROXY_SWEEPS).then_some(fd)
            })
            .collect();
        for fd in late {
            self.stats.pp_timeout.bump();
            self.pending_drop(fd, true, Why::HsTimeout);
        }
    }

    /// shutdown_step at STOP_CLOSE: every connection still waiting for its header is closed
    #[cold]
    #[inline(never)] // (60.34 disassembly: inlined into run via idle_sweep / shutdown_step it moved run's registers)
    pub(super) fn pending_close(&mut self) {
        for fd in self.pending.keys().copied().collect::<Vec<_>>() {
            self.pending_drop(fd, false, Why::ServerClose);
        }
    }
}
