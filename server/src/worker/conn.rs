//! 20.05 client connections: accept (and --balance handoff), adopt, close, abort and reset.

use super::*;

impl Worker {
    /// Accept everything queued on our listeners: the TCP one and (60.31 C7) the shared unix one
    pub(super) fn accept_all(&mut self) {
        self.accept_on(false);
        if self.ufd >= 0 {
            self.accept_on(true);
        }
    }

    /// Accept on the TCP listener, or (`unix`, 60.31 C7) on the shared unix one
    pub(super) fn accept_on(&mut self, unix: bool) {
        let lfd = if unix { self.ufd } else { self.lfd };
        if lfd < 0 {
            return; // 60.12 closed by shutdown_step (or no unix listener)
        }
        if !self.st.admit {
            // 20.26 hard memory pressure: leave connections in the listen backlog (the listener stays
            // open; set_level drains the backlog when the pressure is gone: the EPOLLET edge is used up)
            if !std::mem::replace(&mut self.accept_paused, true) {
                self.stats.accept_paused.bump(); // 60.12
            }
            return;
        }
        // 60.34 a PROXY listener: the header comes first (proxy.rs); the TCP peer must be in --proxy-protocol-from
        let proxy = if unix { self.cfg.proxy_unix } else { self.cfg.proxy_tcp };
        loop {
            // 60.20 C2/C3b, 60.24 --log-conns: the peer address only when one of them is on (else null, as before)
            let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut sl = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            // (60.31 C7: never on the unix listener, whose peer is UNIX_PEER; want_peer does not count --listen-unix.
            // 60.34 always on a TCP PROXY listener: the source check)
            let (sp, lp) = match (self.cfg.want_peer || proxy) && !unix {
                true => (&mut ss as *mut _ as *mut libc::sockaddr, &mut sl as *mut libc::socklen_t),
                false => (std::ptr::null_mut(), std::ptr::null_mut()),
            };
            let fd = unsafe { libc::accept4(lfd, sp, lp, libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
            if fd < 0 {
                let e = net::errno();
                if would_block(e) {
                    return;
                }
                if e == libc::EMFILE || e == libc::ENFILE || e == libc::ENOBUFS || e == libc::ENOMEM {
                    let fds = e == libc::EMFILE || e == libc::ENFILE; // 60.12
                    (if fds { &self.stats.accept_err_fd } else { &self.stats.accept_err_mem }).bump();
                    // edge-triggered: no new edge may come while the backlog is non-empty, so poll
                    self.accept_retry = true;
                    return;
                }
                continue; // ECONNABORTED etc.
            }
            // 60.20 C3a --max-conns: reserve before anything else (a refusal costs this one close); RST, not a backlog
            // wait (that is memory level 3's choice: policy refuses fast). The reservation travels with a --balance
            // hand-over and is released by the owning worker (unload).
            if let Some(g) = &self.cfg.conn_gate {
                if !g.try_reserve() {
                    net::linger_zero(fd);
                    unsafe { libc::close(fd) };
                    self.stats.refuse_conns.bump();
                    if self.cfg.log_conns {
                        let ip = if unix { Some(clientip::UNIX_PEER) } else { net::sockaddr_ip(&ss) }; // 60.31 ip=unix
                        self.log_refused(ip, Why::Limit);
                    }
                    continue;
                }
            }
            // 60.20 C3b a direct peer is charged here (charge), before any TLS/HTTP work and the --balance hand-over
            let mut h = net::Handoff::bare(fd);
            if unix {
                // 60.31 C7 a unix client: the sentinel peer, trusted (main), so never charged here
                h.kind = net::L_UNIX;
                h.peer = Some(clientip::UNIX_PEER);
            } else if self.cfg.want_peer || proxy {
                h.peer = net::sockaddr_ip(&ss);
                if self.ufd >= 0 && h.peer == Some(clientip::UNIX_PEER) {
                    // 60.31 C7 a TCP peer at exactly the sentinel would pass as the unix proxy (100::/64 is discard-only,
                    // RFC 6666: not seen on a real network)
                    net::linger_zero(fd);
                    unsafe { libc::close(fd) };
                    if let Some(g) = &self.cfg.conn_gate {
                        g.release(); // the C3a reservation taken just above
                    }
                    self.stats.refuse_sentinel.bump();
                    continue;
                }
            }
            let refused = if proxy {
                // 60.34 only listed sources may send the header (spec: the receiver must make sure only trusted
                // proxies use it); unix peers passed the socket file's mode. Charged per IP after the header (proxy.rs).
                h.kind |= net::L_PROXY;
                let ok = unix || h.peer.is_some_and(|ip| self.cfg.proxy_from.iter().any(|c| c.contains(ip)));
                if !ok {
                    self.stats.pp_refused.bump();
                }
                (!ok).then_some(Why::ProtocolError)
            } else {
                (!self.charge(&mut h)).then_some(Why::Limit) // 60.20 C3b over --max-conns-per-ip, 60.40 --conn-rate-per-ip
            };
            if let Some(why) = refused {
                net::linger_zero(fd);
                unsafe { libc::close(fd) };
                if let Some(g) = &self.cfg.conn_gate {
                    g.release(); // the C3a reservation taken just above
                }
                if self.cfg.log_conns {
                    self.log_refused(h.peer, why);
                }
                continue;
            }
            if unix {
                self.stats.accepted_unix.bump(); // 60.31 (no TCP options on a unix socket)
            } else {
                net::set_nodelay(fd);
                if self.cfg.notsent_lowat > 0 {
                    net::set_notsent_lowat(fd, self.cfg.notsent_lowat); // 20.19
                }
            }
            self.route(h);
        }
    }

    /// The owner of a new connection; Inbox.load is counted here, once, on the final owner.
    // 20.10 accept balancing: SO_REUSEPORT hashes connections to listeners, so two long-lived
    // Wisp connections can land on one core while others idle. Hand the fd to the least
    // loaded worker when it has fewer live clients than us. deliberate: count, not CPU load.
    // Opt-in (--balance): it steadies bulk throughput with few connections (worst case
    // 5.3 -> 6.7 GiB/s) but spreads small request/response traffic over more half-idle
    // threads, and their extra sleep/wake cycles cost 10-25% req/s (20.06 doc).
    // 60.31 C7: always for unix clients: the shared listener has no kernel spread (EPOLLEXCLUSIVE wakes the first idle
    // worker in registration order: 40 of 40 accepts on one worker without this, 10/10/10/10 with it, 60.28).
    fn route(&mut self, h: net::Handoff) {
        if self.cfg.balance || h.kind & net::L_UNIX != 0 {
            let my = self.inbox.load.load(Relaxed);
            let (mi, ml) =
                self.peers.iter().enumerate().map(|(i, p)| (i, p.load.load(Relaxed))).min_by_key(|&(_, l)| l).unwrap_or((self.idx, my));
            if mi != self.idx && ml < my {
                self.peers[mi].load.fetch_add(1, Relaxed);
                self.peers[mi].push_fd(h);
                return;
            }
        }
        self.inbox.load.fetch_add(1, Relaxed);
        self.take(h);
    }

    /// 60.20 C3b a direct peer (not a trusted proxy) is charged before any TLS/HTTP work and before the --balance
    /// hand-over (the key travels with the fd); a trusted proxy's client is charged in handle_http (client_ip). 60.34
    /// behind a PROXY header the peer is the header's source (called by pending_event). The load-bearing invariant
    /// (60.28): trusted peers are never charged here, so client_ip never overwrites a key. false = refused: over
    /// --max-conns-per-ip (refuse_ip_conns) or 60.40 --conn-rate-per-ip (refuse_ip_connrate); the caller closes and
    /// releases.
    pub(super) fn charge(&mut self, h: &mut net::Handoff) -> bool {
        let Some(cip) = &self.cfg.clientip else { return true };
        if let (Some(t), Some(ip)) = (&cip.table, h.peer.filter(|ip| !cip.is_trusted(*ip))) {
            let k = clientip::key(ip);
            match t.charge(k, cip.max_conns, clientip::now_ms()) {
                clientip::Charge::Charged => h.key = Some(k),
                clientip::Charge::Untracked => self.stats.ip_untracked.bump(),
                r @ (clientip::Charge::Refused | clientip::Charge::Rate) => {
                    self.ip_refused(r);
                    return false;
                }
            }
        }
        true
    }

    /// 60.20 C3b / 60.40 a per-IP refusal's counter: --max-conns-per-ip (refuse_ip_conns) or --conn-rate-per-ip
    /// (refuse_ip_connrate). Out of line: the accept path keeps one call where it had one bump.
    #[cold]
    #[inline(never)]
    pub(super) fn ip_refused(&self, r: clientip::Charge) {
        match r {
            clientip::Charge::Rate => self.stats.refuse_ip_connrate.bump(),
            _ => self.stats.refuse_ip_conns.bump(),
        }
    }

    /// 60.20 C3a one client fewer on this worker: `Inbox.load`, the --max-conns reservation and (C3b) the per-IP key it
    /// charged, together, at each of the three places a counted client ends (adopt's two failure exits, close_client),
    /// so no exit can drop one and keep another. `key`: Some only if that client charged it. (Fds still queued in an
    /// inbox when the process exits are not released: the process is ending.)
    pub(super) fn unload(&mut self, key: Option<clientip::IpKey>) {
        self.inbox.load.fetch_sub(1, std::sync::atomic::Ordering::Release); // 60.25 C5: after the rx_bytes publish

        if let Some(g) = &self.cfg.conn_gate {
            g.release();
        }
        if let (Some(k), Some(t)) = (key, self.cfg.clientip.as_ref().and_then(|c| c.table.as_ref())) {
            t.release(k, clientip::now_ms());
        }
    }

    /// 60.20 C2/C3b slot `i`'s peer (`peers_of` is used only when C2/C3b or --log-conns are on; close_client takes the entry).
    fn set_peer(&mut self, i: u32, p: Option<clientip::Peer>) {
        let i = i as usize;
        if self.peers_of.len() <= i {
            self.peers_of.resize_with(i + 1, || None);
        }
        self.peers_of[i] = p;
    }

    /// The peer of client `ci` (None when C2/C3b and --log-conns are off).
    pub(super) fn peer(&self, ci: u32) -> Option<&clientip::Peer> {
        self.peers_of.get(ci as usize).and_then(Option::as_ref)
    }

    /// Register an accepted client socket with this worker (load already counted).
    pub(super) fn adopt(&mut self, h: net::Handoff) {
        let fd = h.fd;
        // 60.31 C7 TLS only on the TCP listener (a unix client is plain ws://: TLS ends in the reverse proxy)
        let tls = match self.cfg.tls.as_ref().filter(|_| h.kind & net::L_UNIX == 0) {
            Some(cfg) => match rustls::server::UnbufferedServerConnection::new(cfg.clone()) {
                Ok(conn) => Some(Box::new(TlsHs { conn, out: Vec::new(), sent: 0, kept: 0, done: false })),
                Err(_) => {
                    unsafe { libc::close(fd) };
                    self.unload(h.key);
                    if self.cfg.log_conns {
                        self.log_refused(h.peer, Why::ServerClose); // 60.24 (review: no silent drop)
                    }
                    return;
                }
            },
            None => None,
        };
        {
            let c = Client {
                fd,
                state: if tls.is_some() { CState::Tls } else { CState::Http },
                rbuf: vec![0u8; 4096],
                rpos: 0,
                rlen: 0,
                need: 0,
                obuf: Vec::new(),
                ohead: 0,
                readable: true,
                rdhup: false,
                paused: false,
                opaused: false,
                dirty: false,
                dead: false,
                closing: false,
                streams: StreamMap::default(),
                blocked: Vec::new(),
                blocked_bulk: Vec::new(),
                bulk_waiting: 0,
                frag: None,
                proxy_target: None,
                pipe: [-1, -1],
                splice: if self.cfg.splice { SPLICE_SLOW } else { SPLICE_OFF },
                splice_pending: 0,
                splice_at: NO_MARK,
                active: true,
                rfull: false,
                bulk: Vec::new(),
                bhead: 0,
                bulk_sent: 0,
                bulk_ends: VecDeque::new(),
                bulk_boundary: 0,
                tls,
                ktls_on: false,
                ktls: None,
                tx_left: u64::MAX,
                rx_left: u64::MAX,
                rekey_at: 0,
                ku: 0,
                ku_asked: false,
                challenge: None,
                hs_sweeps: 0,
                notified: false,
                lingering: false,
                drain_seen: false,
                tx_bytes: 0,
                rate_check_at: RATE_CHECK_BYTES,
                lowat_off: false,
                saved: (0, 0),
                mpaused: false,
                pend: 0,
                hpaused: false,
                lpaused: false,
                over: 0,
                hp_sweeps: 0,
                hs_credit: 0,
                cv: None, // 60.13: created at the first CONTINUE (push_continue)
                rx_mark: NO_RX,
                gone_ack: 0,
                rstall: 0,
                local: if h.kind & net::L_UNIX != 0 { LOCAL_UNIX } else { 0 }, // 60.31 C7
                wblock: false,
                starve: 0,
                starve_at: Instant::now(),
                starve_room: 0,
                starve_since: Instant::now(),
                starve_b: false,
                starve_due: false,
                starve_read: 0,
                #[cfg(test)]
                send_log: Vec::new(),
                #[cfg(test)]
                ku_refuse: false,
            };
            let is_tls = c.tls.is_some();
            let mut c = c;
            if self.st.sock_cap > 0 && !(c.local == LOCAL_UNIX && self.lvl == 0) && !tcp_only_local(&mut c.local, fd, self.lvl) {
                if self.floor0 {
                    c.saved = net::buf_sizes(fd); // 20.26
                }
                net::cap_bufs(fd, mem::client_caps(self.capl));
                self.stats.cap_apply.bump(); // 60.12
            }
            let unix = c.local == LOCAL_UNIX;
            let (i, g) = self.clients.insert(c);
            if self.cfg.adaptive_splice {
                // 60.51 read once: the handshake's RTT sample (a unix client has none: near)
                let far = !unix && net::min_rtt_us(fd).is_some_and(|r| r >= SPLICE_FAR_RTT_US);
                let i = i as usize;
                if self.splice_far.len() <= i {
                    self.splice_far.resize(i + 1, false);
                }
                self.splice_far[i] = far;
            }
            if !ep_add(self.ep, fd, tok(K_CLIENT, i, g), EV_ALL) {
                unsafe { libc::close(fd) };
                self.clients.remove(i);
                self.unload(h.key);
                if self.cfg.log_conns {
                    self.log_refused(h.peer, Why::ServerClose); // 60.24
                }
            } else {
                self.stats.accepted.bump(); // 60.12
                if self.meter {
                    self.meter_adopt(i, h.key.is_some()); // 60.25 C10b
                }
                if self.cfg.want_peer || self.cfg.unix.is_some() {
                    // 60.20 C2/C3b, 60.24 --log-conns: the client's peer and key, beside the slab (a Client field made
                    // the slot 520 bytes instead of 512, 60.22). 60.31 C7 with --listen-unix always: a unix client's
                    // header is read, and a TCP client's slot is written None (close_client takes every entry; this
                    // keeps a slot from ever showing a TCP client a former unix client's trusted peer)
                    self.set_peer(i, h.peer.map(|ip| clientip::Peer { ip, key: h.key }));
                }
                if self.cfg.log_conns || self.cfg.log_streams {
                    self.log_open(i, is_tls, h.peer); // 60.35 also for --log-streams alone (the streams' cid)
                }
                if is_tls {
                    self.tls_deadlines.push_back((i, g, Instant::now() + TLS_HANDSHAKE_TIMEOUT));
                }
            }
        }
    }

    /// 20.26 close a client and all its targets with RST (memory pressure: a plain close() keeps
    /// unsent queues alive as orphan sockets, still charged to the cgroup).
    pub(super) fn abort_client(&mut self, ci: u32, why: Why) {
        let c = self.clients.at(ci);
        if c.dead {
            return;
        }
        // the connected socket, or the attempts still connecting (happy eyeballs; TFO data may sit in them)
        let fds: Vec<RawFd> = c
            .streams
            .values()
            .copied()
            .chain(c.proxy_target.map(|(ti, _)| ti))
            .filter_map(|ti| self.targets.slots.get(ti as usize).and_then(|s| s.1.as_ref()).filter(|t| !t.udp))
            .flat_map(|t| std::iter::once(t.fd).chain(t.conn.iter().copied()))
            .filter(|&fd| fd >= 0)
            .collect();
        for fd in fds {
            net::linger_zero(fd);
        }
        self.reset_client(ci, why);
    }

    /// RST to the client (SO_LINGER 0, then close_client). 70.07: no TLS close_notify first: a record queued
    /// on a socket being reset is discarded at once, and on a dead peer the send only adds to a queue.
    pub(super) fn reset_client(&mut self, ci: u32, why: Why) {
        let c = self.clients.at(ci);
        if c.dead {
            return;
        }
        net::linger_zero(c.fd);
        c.notified = true;
        self.close_client(ci, why);
    }

    pub(super) fn drop_streams(&mut self, ci: u32) {
        let c = self.clients.at(ci);
        let ids: Vec<u32> = c.streams.drain().map(|(_, t)| t).collect();
        let proxy = c.proxy_target.take();
        for ti in ids {
            if !self.streamlog.is_empty() {
                self.slog_why(ti, SWhy::ConnClose, ""); // 60.35
            }
            self.close_target(ti, None);
        }
        if let Some((ti, tg)) = proxy {
            if self.targets.get(ti, tg).is_some() {
                if !self.streamlog.is_empty() {
                    self.slog_why(ti, SWhy::ConnClose, "");
                }
                self.close_target(ti, None);
            }
        }
    }

    /// `why`: the reason for --log-conns (the first one given for the connection wins: begin_close names it first;
    /// Why::Io = a failed read or write, named here from errno)
    pub(super) fn close_client(&mut self, ci: u32, why: Why) {
        if self.clients.at(ci).dead {
            return;
        }
        if !self.connlog.is_empty() {
            // 60.24 Why::Io from errno before drop_streams makes other syscalls
            let why = if why == Why::Io { connlog::io_why_of(self.clients.at(ci)) } else { why };
            connlog::set_why(&mut self.connlog, ci, why);
        }
        self.drop_streams(ci);
        if !self.sdone.is_empty() {
            self.slog_flush(); // 60.35 before unload: main may flush the log and exit once the last connection is gone
        }
        let peer = self.peers_of.get_mut(ci as usize).and_then(Option::take);
        if !self.connlog.is_empty() {
            self.log_close(ci, peer.as_ref().map(|p| p.ip)); // 60.24 before the socket closes (TCP_INFO)
        }
        let key = peer.and_then(|p| p.key);
        if self.meter {
            self.meter_close(ci, key); // 60.25 C10b the unread lease goes back (before unload releases the key)
        }
        // 60.25 C5: published before unload's Release decrement of Inbox.load: main sees load 0 (Acquire) only after the
        // last close's bytes (review: an emptied worker may sleep without a sweep; shutdown's final line)
        self.stats.rx_bytes.set(self.rx_total);
        self.unload(key);
        let c = self.clients.at(ci);
        c.dead = true;
        if c.ktls_on && !c.notified {
            tls::send_close_notify(c.fd); // 20.17: best effort, MSG_DONTWAIT (review r1: unless already sent)
        }
        unsafe { libc::close(c.fd) };
        for p in c.pipe {
            if p >= 0 {
                unsafe { libc::close(p) };
            }
        }
        c.pipe = [-1, -1];
        c.splice_pending = 0;
        c.splice_at = NO_MARK;
        c.obuf = Vec::new();
        c.bulk_drop();
        if std::mem::take(&mut c.starve) >= 2 {
            self.stats.ktls_starve_end.bump(); // 50.02 a counted episode (starve_check drops the entry)
            self.stats.ktls_starve_ms_max.max(c.starve_since.elapsed().as_millis() as u64);
        }
        self.dead.push(ci);
    }
}
