//! 20.14 / 20.23 / 20.24 target streams before they are open: DNS (cache, in-flight, late answers), Happy
//! Eyeballs connects, TFO, connect deadlines (the timeout scan is Worker::run_timers in mod.rs); inbox_ready also
//! takes --balance handoffs and the shutdown signal.

use super::*;

impl Worker {
    /// Create a target and start resolving/connecting. Returns (index, generation) if it is still
    /// alive; None if it already failed synchronously (CLOSE has been queued).
    pub(super) fn new_target(&mut self, ci: u32, sid: u32, mut host: String, port: u16, raw: bool, udp: bool) -> Option<(u32, u32)> {
        // 60.35 --log-streams: the host as the client sent it (a copy only when on)
        let sent = if self.cfg.log_streams { host.clone() } else { String::new() };
        let log_host = sent.as_str();
        // 60.18 #16 one key per name for the cache and in-flight coalescing: `a.com.` = `a.com` (every lookup is absolute:
        // net::gai_name, dns::Resolver::lookup); `1.2.3.4.` is then the literal
        if host.ends_with('.') {
            host.pop();
        }
        if host.ends_with('.') {
            // review: policy matching strips one dot too; `a.com..` would match no rule and still resolve
            // `a.com` further down: refused here (0x42, no lookup)
            host.clear();
        }
        let cgen = self.clients.gen(ci);
        let hs = self.clients.at(ci).hs_credit.max(1); // 20.26 r4 (wsproxy: no handshake, no credit)
        let t = Target {
            fd: -1,
            client: ci,
            cgen,
            sid,
            state: TState::Resolving,
            port,
            addrs: Vec::new(),
            attempt: 0,
            pend: Vec::new(),
            phead: 0,
            since: 0,
            rdhup: false,
            blocked: false,
            raw,
            wrote_since_read: false,
            urg: false,
            lane_read: false,
            bulk: false,
            bulk_end: 0,
            conn: Vec::new(),
            next_try: Instant::now(),
            err: 0,
            dns_more: false,
            tfo_fd: -1,
            tfo_sent: 0,
            deadline: Instant::now(),
            cidx: NOT_LISTED,
            udp, // (60.35: set here, not after new_target: a stream that fails at once is logged with its type)
            credit: hs,
            allow: hs,
            saved: (0, 0),
            acct: 0,
            capped: false,
            moved: 0,
            keepalive: false,
            upkts: 0,
            ubytes: 0,
            umax: 0,
            cv: None,
            local: 0,
        };
        let (ti, tg) = self.targets.insert(t);
        if self.cfg.log_streams {
            self.slog_open(ti, ci, sid, log_host, port); // 60.35 the host as sent (before the trailing-dot rule)
        }
        // 60.12 gauge
        self.stats.streams.set((self.targets.slots.len() - self.targets.free.len()) as u64);
        // 20.15: IP literals and cache hits start connecting at the end of this input batch, so DATA
        // that arrived in the same read is already in `pend` and can ride in the SYN (TFO).
        if host.len() > MAX_HOST || host.is_empty() {
            // review 20.23: no DNS name is longer; also keeps attacker-sized keys out of the DNS caches ("" = the root ".")
            self.fail_target(ti, CLOSE_UNREACHABLE);
        } else if let Ok(ip) = host.parse::<IpAddr>() {
            self.targets.at(ti).addrs.push(ip);
            self.deferred.push((ti, tg));
        } else if self.cfg.upstream.as_deref().is_some_and(|u| u.remote_dns) {
            self.proxy_name(ti, host); // 60.27 C6 socks5h + --upstream-trust-dns: the proxy resolves the name
        } else if let Some((addrs, at)) = self.dns_cache.get(&host) {
            if addrs.is_empty() && at.elapsed() < DNS_NEG_TTL {
                self.stats.dns_neg_hit.bump(); // 60.12
                self.fail_target(ti, CLOSE_UNREACHABLE); // 20.23 negative entry: the name had no address moments ago
            } else if !addrs.is_empty() && at.elapsed() < DNS_TTL {
                self.stats.dns_hit.bump(); // 60.12
                self.targets.at(ti).addrs = addrs.clone();
                self.deferred.push((ti, tg));
            } else {
                self.dns_cache.remove(&host);
                self.resolve(ti, tg, host);
            }
        } else {
            self.resolve(ti, tg, host);
        }
        self.targets.get(ti, tg).is_some().then_some((ti, tg))
    }

    fn resolve(&mut self, ti: u32, tg: u32, host: String) {
        if self.dns_inflight >= DNS_INFLIGHT_MAX {
            self.stats.refuse_dns.bump(); // 60.12
            if !self.streamlog.is_empty() {
                self.slog_why(ti, SWhy::Limit, "dns_inflight"); // 60.35
            }
            self.fail_target(ti, CLOSE_THROTTLED);
            return;
        }
        self.stats.dns_miss.bump(); // 60.12
        let token = tok(K_TARGET, ti, tg);
        if self.cfg.dns_own {
            self.inbox.dns_live.lock().unwrap().insert(token); // 70.09 before the send: the pool may check at once
        }
        let req = DnsReq { host, token, inbox: self.inbox.clone(), at: Instant::now() };
        if self.dns_tx.send(req).is_err() {
            self.stats.dns_fail.bump(); // 60.12
            self.fail_target(ti, CLOSE_UNREACHABLE); // close_target drops the token again
        } else {
            self.dns_inflight += 1;
        }
    }

    pub(super) fn inbox_ready(&mut self) {
        let (dns, fds) = self.inbox.drain();
        for h in fds {
            self.take(h); // load (and the per-IP key, if any) was counted by the sender; 60.34 PROXY: wait for the header
        }
        let stop = self.inbox.stop.load(Relaxed);
        if stop != 0 && (stop != self.stop_seen || Instant::now() >= self.stop_scan_at) {
            // 60.12 (main wakes the inbox every 100 ms while it drains; DNS answers wake it too: scan at most every 100 ms)
            self.stop_seen = stop;
            self.stop_scan_at = Instant::now() + Duration::from_millis(100);
            self.shutdown_step(stop);
        }
        for r in dns {
            if r.more {
                if self.cfg.upstream.is_some() {
                    continue; // 60.27 C6 (start_dns_pool sends none then): dns_late would mix target and proxy addresses
                }
                // 70.10 early answer (--dns-own): connect to the family that answered; the final answer follows
                let (_, ti, tg) = untok(r.token);
                if let Some(t) = self.targets.get(ti, tg).filter(|t| t.state == TState::Resolving && t.addrs.is_empty()) {
                    t.addrs = r.addrs;
                    t.dns_more = true;
                    self.start_connect(ti);
                }
                continue;
            }
            self.dns_inflight = self.dns_inflight.saturating_sub(1);
            if self.cfg.dns_own {
                self.inbox.dns_live.lock().unwrap().remove(&r.token); // 70.09 answered (no-op if cancelled)
            }
            // review 20.23: a negative answer never replaces a fresh positive one (two lookups of one name can still overlap: one that gave up and a fresh one)
            let fresh_pos = r.nx && self.dns_cache.get(&r.host).is_some_and(|(a, at)| !a.is_empty() && at.elapsed() < DNS_TTL);
            if (!r.addrs.is_empty() || r.nx) && !fresh_pos {
                if self.dns_cache.len() > 4096 {
                    self.dns_cache.clear();
                }
                self.dns_cache.insert(r.host, (r.addrs.clone(), Instant::now()));
            }
            let (_, ti, tg) = untok(r.token);
            let Some(t) = self.targets.get(ti, tg) else { continue };
            if t.dns_more {
                self.dns_late(ti, r.addrs);
                continue;
            }
            if t.state != TState::Resolving {
                continue;
            }
            if r.addrs.is_empty() {
                self.stats.dns_fail.bump(); // 60.12
                self.fail_target(ti, CLOSE_UNREACHABLE);
            } else {
                t.addrs = r.addrs;
                self.start_connect(ti);
            }
        }
    }

    /// 70.10 the final DNS answer for a target that got an early one (dns_more): connected (or UDP): nothing to do;
    /// every early address filtered: start on the full answer; else the new addresses join the untried tail, and a
    /// parked target (nothing in flight) tries the next one now or fails with the last connect error.
    fn dns_late(&mut self, ti: u32, addrs: Vec<IpAddr>) {
        let filter = &self.cfg.filter;
        let t = self.targets.at(ti);
        t.dns_more = false;
        match t.state {
            TState::Open => {}
            TState::Resolving if t.addrs.is_empty() => {
                // Every early address was refused by the address rules. Contract (dns.rs ask, 70.10): an early answer
                // comes only from a family with addresses, and the final answer holds both families again (test
                // dns::tests::early_family_delivery), so start_connect sees them and sends 0x48. An empty final here
                // would send 0x42 / dns_fail instead of 0x48 / policy: triage an internal note (not published)
                debug_assert!(!addrs.is_empty(), "70.10: an empty final answer after an early one");
                t.addrs = addrs;
                self.start_connect(ti);
            }
            _ => {
                net::he_append(&mut t.addrs, t.attempt, addrs.into_iter().filter(|ip| filter.allowed(*ip)));
                if t.conn.is_empty() {
                    self.try_connect(ti);
                }
            }
        }
    }

    fn start_connect(&mut self, ti: u32) {
        let filter = &self.cfg.filter;
        let t = self.targets.at(ti);
        let before = t.addrs.len();
        let first = t.addrs.first().copied();
        t.addrs.retain(|ip| filter.allowed(*ip));
        if t.addrs.is_empty() {
            if t.dns_more {
                return; // 70.10 every early address filtered: stay Resolving, the final answer brings the rest
            }
            if before > 0 {
                self.stats.refuse_policy.bump(); // 60.20 C1 every address refused by the address rules
                if let (false, Some(ip)) = (self.streamlog.is_empty(), first) {
                    let rule = self.cfg.filter.refusal(ip).unwrap_or("");
                    self.slog_why(ti, SWhy::Policy, rule); // 60.35 the rule that refused the first address
                }
            }
            self.fail_target(ti, if before > 0 { CLOSE_BLOCKED } else { CLOSE_UNREACHABLE });
            return;
        }
        net::interleave(&mut t.addrs);
        if self.cfg.upstream.is_some() {
            return self.proxy_start(ti); // 60.27 C6 (UDP never gets here: refused at CONNECT with an upstream)
        }
        if t.udp {
            return self.udp_open(ti); // review 20.24: TCP history does not steer UDP (no race, no fallback there)
        }
        if !self.he_lost.is_empty() {
            net::he_prefer(&mut t.addrs, &self.he_lost, HE_MEMORY);
        }
        t.attempt = 0;
        self.try_connect(ti);
    }

    /// 20.15: start the connects deferred by new_target (see there).
    pub(super) fn run_deferred(&mut self) {
        while let Some((ti, tg)) = self.deferred.pop() {
            if self.targets.get(ti, tg).is_some_and(|t| t.state == TState::Resolving && !t.addrs.is_empty()) {
                self.start_connect(ti);
            }
        }
    }

    /// 20.14: start the next address (in parallel with attempts still in flight). Starts nothing and
    /// fails the target only when no address is left and nothing is in flight.
    pub(super) fn try_connect(&mut self, ti: u32) {
        loop {
            let tg = self.targets.gen(ti);
            let tfo = self.cfg.tfo;
            let t = self.targets.at(ti);
            let Some(&ip) = t.addrs.get(t.attempt) else {
                if t.conn.is_empty() && t.dns_more {
                    self.unlist(ti); // 70.10 parked: the other family's answer is still due (dns_late)
                } else if t.conn.is_empty() {
                    let r = if t.err == 0 { CLOSE_UNREACHABLE } else { net::connect_reason(t.err) };
                    if self.cfg.upstream.is_some() {
                        self.stats.upstream_fail.bump(); // 60.27 C6 no proxy address answered (close_target drops the side entry)
                        if !self.streamlog.is_empty() {
                            self.slog_why(ti, SWhy::UpstreamFail, "connect"); // 60.35
                        }
                    }
                    self.fail_target(ti, r);
                }
                return;
            };
            if self.cfg.upstream.is_some()
                && self.proxy_hs.get(ti as usize).and_then(Option::as_ref).is_some_and(|h| Instant::now() >= h.deadline)
            {
                // 60.27 C6: run_timers starts the next address after an attempt's deadline; past the whole open's
                // deadline (proxy connect + handshake + the proxy's connect + retries) no new proxy connection
                self.stats.upstream_fail.bump();
                if !self.streamlog.is_empty() {
                    self.slog_why(ti, SWhy::UpstreamFail, "timeout"); // 60.35
                }
                self.fail_target(ti, CLOSE_TIMEOUT);
                return;
            }
            let t = self.targets.at(ti);
            t.attempt += 1;
            let res = {
                // TFO only for an attempt no other attempt already carries SYN data for, and only with
                // the bytes of a TLS ClientHello record: a duplicated SYN may deliver them twice, which
                // is harmless for a hello but not for plain requests or TLS 1.3 0-RTT data behind it.
                let syn = if tfo && t.tfo_fd < 0 { client_hello(&t.pend[t.phead..]) } else { None };
                // 60.27 C6: with an upstream, t.addrs are the proxy's addresses (the target's wait in proxy_hs)
                let port = self.cfg.upstream.as_deref().map_or(t.port, |u| u.port);
                net::connect(&SocketAddr::new(ip, port), syn)
            };
            match res {
                Ok((fd, done, sent)) => {
                    if !ep_add(self.ep, fd, tok(K_TARGET, ti, tg), EV_TARGET) {
                        unsafe { libc::close(fd) };
                        t.err = libc::ENOMEM;
                        continue;
                    }
                    t.state = TState::Connecting;
                    t.conn.push(fd);
                    if sent > 0 {
                        t.tfo_fd = fd;
                        t.tfo_sent = sent;
                    }
                    if done {
                        self.won(ti, fd, false);
                        return;
                    }
                    let now = Instant::now();
                    t.deadline = now + self.cfg.connect_timeout;
                    if self.cfg.upstream.is_some() {
                        t.deadline = t.deadline.min(self.proxy_hs[ti as usize].as_ref().expect("side entry").deadline);
                    }
                    t.next_try = now + HE_DELAY;
                    if t.cidx == NOT_LISTED {
                        t.cidx = self.connecting.len();
                        self.connecting.push((ti, tg));
                    }
                    return;
                }
                Err(e) => t.err = e,
            }
        }
    }

    /// 20.14: a Connecting target got an event on one of its attempts (shared token): check them all.
    pub(super) fn connect_progress(&mut self, ti: u32) {
        let t = self.targets.at(ti);
        let mut i = 0;
        while i < t.conn.len() {
            match net::connect_state(t.conn[i]) {
                None => i += 1,
                Some((0, closed)) => {
                    let fd = t.conn[i];
                    self.won(ti, fd, closed);
                    return;
                }
                Some((e, _)) => {
                    let fd = t.conn.swap_remove(i);
                    unsafe { libc::close(fd) };
                    if t.tfo_fd == fd {
                        (t.tfo_fd, t.tfo_sent) = (-1, 0);
                    }
                    t.err = e;
                }
            }
        }
        if t.conn.is_empty() {
            t.rdhup = false; // set by a failed attempt's event
            self.try_connect(ti); // next address now, or fail
        }
    }

    /// 20.14: `fd` connected first: close the other attempts and switch the target to Open.
    fn won(&mut self, ti: u32, fd: RawFd, peer_closed: bool) {
        let up = self.cfg.pace.upload;
        if up > 0 && (pace_refused() || !(net::set_pacing(fd, up) && net::try_notsent_lowat(fd, net::pace_lowat(up)))) {
            // 60.30 C10a the cap, and an unsent-queue bound of 1/8 s (else ~tcp_wmem max of upload waits in the kernel
            // ahead of the cap, where the Wisp credit does not see it). Refused: the stream fails closed, not uncapped
            // (before the HE memory: a stream that fails here teaches it nothing). `fd` is in t.conn: close_target
            // closes it with the other attempts.
            self.stats.pace_fail.bump();
            if !self.streamlog.is_empty() {
                self.slog_why(ti, SWhy::ConnectFail, "pace_fail"); // 60.35
            }
            self.fail_target(ti, CLOSE_NETWORK);
            return;
        }
        let t = self.targets.at(ti);
        // 20.24 HE memory: a winner from the other family demotes the first address for HE_MEMORY;
        // a demoted address that wins is forgotten. Only races with more than one attempt cost a syscall.
        if let Some(&first) = t.addrs.first() {
            let winner = if t.attempt <= 1 { Some(first) } else { net::peer_ip(fd) };
            if let Some(w) = winner {
                if w.is_ipv4() != first.is_ipv4() {
                    if self.he_lost.len() >= 4096 {
                        self.he_lost.clear();
                    }
                    self.he_lost.insert(first, Instant::now());
                }
                if !self.he_lost.is_empty() {
                    self.he_lost.remove(&w);
                }
            }
        }
        if !self.streamlog.is_empty() {
            // 60.35 dst: the winner (as the HE memory above: a single attempt is the first address); with C6 the proxy
            let dst = if t.attempt <= 1 { t.addrs.first().copied() } else { net::peer_ip(fd) };
            if let Some(l) = self.slog(ti) {
                l.dst = dst;
            }
        }
        let t = self.targets.at(ti);
        for &o in &t.conn {
            if o != fd {
                unsafe { libc::close(o) };
            }
        }
        t.conn = Vec::new();
        t.fd = fd;
        // 20.26 r4: the socket caps come lazily (lazy_cap) once the stream has moved LAZY_CAP bytes;
        // without lazy caps (mem::LAZY: a host with a big tcp_rmem[1]) at once, as r3 did
        let tfo = if t.tfo_fd == fd {
            t.phead += t.tfo_sent; // those bytes are in this socket already
            t.tfo_sent
        } else {
            0
        };
        (t.tfo_fd, t.tfo_sent) = (-1, 0);
        t.rdhup = peer_closed;
        if self.st.sock_cap > 0 {
            if mem::LAZY.load(Relaxed) {
                self.lazy_cap(ti, tfo); // (TFO may have moved LAZY_CAP already, and all of pend)
            } else {
                let (floor0, ml, st) = (self.floor0, self.lvl, self.st);
                let t = self.targets.at(ti);
                if !tcp_only_local(&mut t.local, t.fd, ml) {
                    if floor0 {
                        t.saved = net::buf_sizes(fd);
                    }
                    net::cap_bufs(fd, mem::target_caps(&st));
                    self.stats.cap_apply.bump(); // 60.12
                }
                t.capped = true;
            }
        }
        let t = self.targets.at(ti);
        // 20.26 keep pend_total exact: TFO may have taken all of pend, then after_write does not run
        let (b, ci) = (t.pend.len() - t.phead, t.client);
        let old = std::mem::replace(&mut t.acct, b);
        if b != old {
            self.pend_account(ci, b, old);
        }
        if self.cfg.upstream.is_some() {
            return self.proxy_begin(ti); // 60.27 C6 the proxy answered the SYN: handshake next
        }
        self.connected(ti);
    }

    /// Remove a target from the in-flight connect list (O(1) swap_remove).
    pub(super) fn unlist(&mut self, ti: u32) {
        let i = std::mem::replace(&mut self.targets.at(ti).cidx, NOT_LISTED);
        if i == NOT_LISTED {
            return;
        }
        self.connecting.swap_remove(i);
        if let Some(&(mi, _)) = self.connecting.get(i) {
            self.targets.at(mi).cidx = i;
        }
    }

    pub(super) fn connected(&mut self, ti: u32) {
        self.unlist(ti);
        let t = self.targets.at(ti);
        t.state = TState::Open;
        t.addrs = Vec::new();
        if t.pend.len() > t.phead {
            self.flush_pending(ti);
        }
    }
}

/// 60.30 C10a test hook: make `won` act as if the kernel refused the upload-cap options (release builds: always false)
#[cfg(not(test))]
#[inline(always)]
fn pace_refused() -> bool {
    false
}
#[cfg(test)]
thread_local!(pub(super) static PACE_REFUSE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });
#[cfg(test)]
fn pace_refused() -> bool {
    PACE_REFUSE.with(|c| c.get())
}
