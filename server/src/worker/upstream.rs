//! 60.27 / 60.32 C6 upstream proxy, worker side. A proxied stream:
//! - Resolving: local DNS and the C1 address rules as for a direct stream (socks5h with --upstream-trust-dns: no DNS);
//! - Connecting, fd -1: Happy Eyeballs over the PROXY's addresses (t.addrs holds them; the target's wait in the side
//!   entry), the unchanged try_connect / connect_progress / won machinery;
//! - handshake = Connecting with fd >= 0 (`Target::in_handshake`): the proxy socket is t.fd, t.conn and t.addrs are
//!   empty, the target stays listed in `connecting`, so run_timers' deadline branch ends it with 0x43;
//! - Open: connected(), unchanged from here on (splice, kTLS, upload batching).
//!
//! No new TState: a fourth variant turned the per-event state match in target_event (inlined into run) into a jump
//! table (60.27 disassembly). Side entry `proxy_hs[ti]`: created by proxy_start / proxy_name, dropped just before
//! connected() and in close_target, which every other exit goes through (one owner, two drop sites).
use super::*;
use crate::upstream::{self as up, Dest, Parsed};

#[derive(PartialEq, Clone, Copy, Debug)]
pub(super) enum Step {
    Method,
    Auth,
    Reply,
    Http,
}

/// 60.27 Q-F: target addresses tried through the proxy per CONNECT (a deliberate cap: a DNS answer with 50 addresses must
/// not make 50 proxy connections); all of them within one deadline
const PROXY_TRIES: usize = 4;

/// socks5h names that reach the proxy host itself: RFC 6761 `localhost` (and below it), plus the loopback aliases of
/// Debian / RHEL /etc/hosts (review). Refused without --allow-loopback. The proxy's own hostname and custom hosts
/// entries cannot be known here (60.32 "what socks5h cannot enforce").
const LOOPBACK_NAMES: [&str; 6] =
    ["localhost", "localhost.localdomain", "localhost6", "localhost6.localdomain6", "ip6-localhost", "ip6-loopback"];

pub(super) struct ProxyHs {
    step: Step,
    out: Vec<u8>, // request bytes not yet written: out[wpos..]
    wpos: usize,
    tgt: Vec<IpAddr>, // local DNS: the target addresses (C1-filtered, IPv4 first); tgt[idx] is being tried
    idx: usize,
    name: Option<Box<str>>,       // socks5h + --upstream-trust-dns: the name the proxy resolves
    pub(super) deadline: Instant, // whole open: proxy connect + handshake + the proxy's own connect (+ retries)
}

impl Worker {
    fn hs_put(&mut self, ti: u32, hs: ProxyHs) {
        let i = ti as usize;
        if self.proxy_hs.len() <= i {
            self.proxy_hs.resize_with(i + 1, || None);
        }
        self.proxy_hs[i] = Some(Box::new(hs));
    }

    fn hs(&mut self, ti: u32) -> &mut ProxyHs {
        self.proxy_hs[ti as usize].as_mut().expect("60.27 proxied target without its side entry")
    }

    /// The proxy's current addresses: the worker's copy, refreshed when the upstream-dns thread published a new
    /// generation (one Acquire load; the lock only on a change). A worker that is idle meanwhile needs no wake-up.
    fn proxy_list(&mut self) -> Arc<Vec<IpAddr>> {
        let pa = &self.cfg.upstream.as_deref().expect("upstream").addrs;
        match &self.proxy_addrs {
            Some((g, l)) if *g == pa.gen() => l.clone(),
            _ => {
                let (g, l) = pa.snapshot();
                self.proxy_addrs = Some((g, l.clone()));
                l
            }
        }
    }

    /// new_target, socks5h + --upstream-trust-dns, a name: no local DNS. What can still be enforced on a name: the C1
    /// request rules (already run in on_connect), plus here: no inet_aton forms (`127.1`, `0x7f000001`: the proxy's
    /// getaddrinfo would turn them into addresses we never checked), no loopback names (LOOPBACK_NAMES and everything
    /// below `localhost`) without --allow-loopback, and LDH + `_` names only (IDN as punycode).
    pub(super) fn proxy_name(&mut self, ti: u32, host: String) {
        if policy::is_ip_literal(&host) {
            self.stats.refuse_policy.bump();
            if !self.streamlog.is_empty() {
                self.slog_why(ti, SWhy::Policy, "ip_form"); // 60.35 an inet_aton form the proxy would resolve
            }
            return self.fail_target(ti, CLOSE_BLOCKED);
        }
        let lower = host.to_ascii_lowercase();
        if !self.cfg.filter.allow_loopback && (LOOPBACK_NAMES.contains(&lower.as_str()) || lower.ends_with(".localhost")) {
            self.stats.refuse_policy.bump();
            if !self.streamlog.is_empty() {
                self.slog_why(ti, SWhy::Policy, "loopback");
            }
            return self.fail_target(ti, CLOSE_BLOCKED);
        }
        if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
            return self.fail_target(ti, wisp::CLOSE_INVALID);
        }
        // 60.18 #16 parity (review): the proxy gets an absolute name (`name.`), so its resolver applies no search
        // list, except .onion (upstream::proxy_name); new_target removed one trailing dot, and the ATYP 3 length byte
        // holds at most 255 (0x42, as a long name)
        let host = up::proxy_name(host);
        if host.len() > 255 {
            return self.fail_target(ti, CLOSE_UNREACHABLE);
        }
        if let Some(d) = self.cfg.dest_rate.as_deref() {
            // 60.39 no local address: the name is the key (case folded; new_target removed one trailing dot), after the
            // last check that can fail the stream (review: a 255-byte name failed 0x42 after its token)
            let k = d.name_key(&lower, self.targets.at(ti).port);
            if !self.dest_token(ti, d.take(k, metrics::now_ms())) {
                return;
            }
        }
        let deadline = Instant::now() + self.cfg.connect_timeout;
        self.hs_put(
            ti,
            ProxyHs { step: Step::Method, out: Vec::new(), wpos: 0, tgt: Vec::new(), idx: 0, name: Some(host.into()), deadline },
        );
        self.proxy_connect(ti);
    }

    /// start_connect (upstream set): t.addrs = the C1-filtered target addresses (local DNS, or an IP literal).
    /// wispurr parity: IPv4 first (its default dnsResultOrder ipv4first); the others follow as retries.
    pub(super) fn proxy_start(&mut self, ti: u32) {
        let t = self.targets.at(ti);
        let mut tgt = std::mem::take(&mut t.addrs);
        tgt.sort_by_key(|ip| !ip.to_canonical().is_ipv4()); // stable: the resolver's order within a family
        let deadline = Instant::now() + self.cfg.connect_timeout;
        self.hs_put(ti, ProxyHs { step: Step::Method, out: Vec::new(), wpos: 0, tgt, idx: 0, name: None, deadline });
        self.proxy_connect(ti);
    }

    /// (re)start the connect to the proxy: Happy Eyeballs over its addresses (try_connect, unchanged machinery)
    fn proxy_connect(&mut self, ti: u32) {
        let list = self.proxy_list(); // (deduplicated and interleaved by upstream::resolve)
        let t = self.targets.at(ti);
        t.addrs.clear();
        t.addrs.extend_from_slice(&list);
        if !self.he_lost.is_empty() {
            net::he_prefer(&mut t.addrs, &self.he_lost, HE_MEMORY);
        }
        (t.attempt, t.err) = (0, 0);
        self.try_connect(ti);
    }

    /// won (upstream set): the proxy accepted the TCP connection. Send the first request.
    pub(super) fn proxy_begin(&mut self, ti: u32) {
        let up = self.cfg.upstream.as_deref().expect("upstream");
        let t = self.targets.at(ti);
        t.addrs.clear(); // run_timers: no new attempt; only the deadline makes it due (and fails it with 0x43)
        t.rdhup = false; // the handshake reads see an EOF themselves
        let port = t.port;
        let hs = self.proxy_hs[ti as usize].as_mut().expect("side entry");
        (hs.step, hs.wpos) = match up.kind {
            up::Kind::Socks5 => {
                hs.out = up::socks_greeting(up.socks_auth.is_some()).to_vec();
                (Step::Method, 0)
            }
            up::Kind::Http => {
                hs.out = up::http_request(hs.tgt[hs.idx], port, up.http_auth.as_deref());
                (Step::Http, 0)
            }
        };
        let deadline = hs.deadline;
        let tg = self.targets.gen(ti);
        let t = self.targets.at(ti);
        t.deadline = deadline;
        debug_assert!(t.conn.is_empty() && t.addrs.is_empty());
        if t.cidx == NOT_LISTED {
            // review: a connect() that completed at once never listed the target (try_connect): the
            // handshake deadline needs the run_timers scan
            t.cidx = self.connecting.len();
            self.connecting.push((ti, tg));
        }
        self.proxy_io(ti, 0);
    }

    /// target_event, in_handshake (dispatched before the Connecting event mask: an EPOLLIN-only event matters here): any event (IN, OUT, HUP, ERR) runs the handshake as far as the bytes allow
    #[cold]
    #[inline(never)]
    pub(super) fn proxy_event(&mut self, ti: u32, tg: u32, e: u32) {
        self.proxy_io(ti, e);
        if let Some(t) = self.targets.get(ti, tg).filter(|t| t.state == TState::Open) {
            // review: a FIN in the same event as the reply and the tunnel bytes gets no new edge, and
            // target_event records hangups only for Open targets: record it here (confirmed on the fd, as target.rs)
            if e & (libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 && !t.rdhup {
                t.rdhup = net::peer_closed(t.fd);
            }
            self.read_target(ti); // tunnel bytes that came with the reply (edge-triggered: nobody else reads them)
        }
    }

    fn proxy_io(&mut self, ti: u32, e: u32) {
        let hup = e & (libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0;
        let mut buf = [0u8; up::HTTP_HEAD_MAX];
        loop {
            let fd = self.targets.at(ti).fd;
            let hs = self.hs(ti);
            while hs.wpos < hs.out.len() {
                let rest = &hs.out[hs.wpos..];
                let n = unsafe { libc::send(fd, rest.as_ptr().cast(), rest.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
                if n < 0 {
                    match net::errno() {
                        libc::EAGAIN => return,  // EPOLLOUT resumes
                        libc::EINTR => continue, // (review)
                        _ => return self.proxy_fail(ti, up::CLOSE_NETWORK, false),
                    }
                }
                hs.wpos += n as usize;
            }
            let step = hs.step;
            let cap = if step == Step::Http { up::HTTP_HEAD_MAX } else { 262 };
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), cap, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
            if n < 0 && net::errno() == libc::EINTR {
                continue; // (review) peek again
            }
            let parsed = if n > 0 {
                let b = &buf[..n as usize];
                let auth = self.cfg.upstream.as_deref().is_some_and(|u| u.socks_auth.is_some());
                match step {
                    Step::Method => up::socks_method(b, auth),
                    Step::Auth => up::socks_auth_reply(b),
                    Step::Reply => up::socks_reply(b),
                    Step::Http => up::http_reply(b),
                }
            } else if n == 0 || net::errno() != libc::EAGAIN {
                Parsed::Fail { reason: up::CLOSE_NETWORK, retry: false } // EOF or reset mid-handshake
            } else {
                Parsed::Need
            };
            match parsed {
                // closed mid-reply. review: the token is shared with the HE attempts, so a hangup in `e` may be
                // a loser's (closed by won in this batch): confirm it on this fd
                Parsed::Need if hup && net::peer_closed(fd) => return self.proxy_fail(ti, up::CLOSE_NETWORK, false),
                Parsed::Need => return,
                Parsed::Fail { reason, retry } => return self.proxy_fail(ti, reason, retry),
                Parsed::Done { len, val } => {
                    let got = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), len, libc::MSG_DONTWAIT) };
                    if got != len as isize {
                        return self.proxy_fail(ti, up::CLOSE_NETWORK, false);
                    }
                    let up = self.cfg.upstream.as_deref().expect("upstream");
                    let port = self.targets.at(ti).port;
                    let hs = self.proxy_hs[ti as usize].as_mut().expect("side entry");
                    let req = |hs: &ProxyHs| match &hs.name {
                        Some(n) => up::socks_request(&Dest::Name(n), port),
                        None => up::socks_request(&Dest::Ip(hs.tgt[hs.idx]), port),
                    };
                    match (step, val) {
                        (Step::Method, 2) => (hs.step, hs.out) = (Step::Auth, up.socks_auth.clone().expect("offered")),
                        (Step::Method, _) | (Step::Auth, _) => (hs.step, hs.out) = (Step::Reply, req(hs)),
                        (Step::Reply, _) | (Step::Http, _) => {
                            self.proxy_hs[ti as usize] = None;
                            self.stats.upstream_ok.bump();
                            self.connected(ti); // unlist, Open, flush what the client sent meanwhile
                            return;
                        }
                    }
                    hs.wpos = 0;
                }
            }
        }
    }

    /// A refused or broken handshake. Target-side refusals (SOCKS 03-06, HTTP 500/502-504) try the next target address
    /// over a new proxy connection while the deadline allows (local DNS only, at most PROXY_TRIES addresses); anything
    /// else ends the stream. A retry keeps the stream (its admission, memory accounting and C3b token stay; nothing
    /// is taken again) and its queued upload (pend).
    fn proxy_fail(&mut self, ti: u32, reason: u8, retry: bool) {
        let now = Instant::now();
        let hs = self.hs(ti);
        if retry && hs.name.is_none() && hs.idx + 1 < hs.tgt.len().min(PROXY_TRIES) && now < hs.deadline {
            hs.idx += 1;
            let abort = self.cfg.abort_close;
            let t = self.targets.at(ti);
            if abort {
                net::linger_zero(t.fd); // review: the proxy spoke last (its refusal): RST, no TIME_WAIT under churn
            }
            unsafe { libc::close(t.fd) };
            t.fd = -1;
            // the next socket starts uncapped (won applies the caps again) and with no hangup / urgent state
            (t.capped, t.saved, t.moved, t.local, t.urg, t.rdhup) = (false, (0, 0), 0, 0, false, false);
            self.fd_put_t(ti, 1); // 60.57 A2
            self.proxy_connect(ti);
            return;
        }
        if !retry {
            self.stats.upstream_fail.bump(); // the proxy itself failed or refused (an operator problem, mostly)
            if !self.streamlog.is_empty() {
                self.slog_why(ti, SWhy::UpstreamFail, "proxy"); // 60.35
            }
        } else {
            self.connect_failed(reason); // 60.57 A6 the proxy reported the target's refusal or timeout
        }
        self.fail_target(ti, reason); // close_target drops the side entry
    }
}
