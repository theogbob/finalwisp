//! 70.09 Own DNS resolver (C9, `--dns-own` / `--dns-server`), used by the net.rs DNS pool threads instead of
//! getaddrinfo: musl has no usable getaddrinfo for us, and glibc waits timeout x attempts (10 s) on a dead server.
//! /etc/hosts, then resolv.conf (nameservers, timeout, attempts, rotate; search / domain / ndots are ignored: every client
//! name is asked as an absolute name, 60.18 #16). A and AAAA are
//! asked at once, each on its own connected UDP socket (kernel-chosen ephemeral port, random ID, EDNS0 1232);
//! TC=1 retries over TCP, FORMERR with EDNS resends once without it. Each family moves to the next server on its
//! own, so a failed A keeps the AAAA answer. Same result contract as net::lookup: unfiltered addresses,
//! Err(true) = definitive (NXDOMAIN / no address in both families: cached 5 s), Err(false) = anything else.
//! Design and numbers: note 70.09.
//! unsafe (60.16): blocks without their own SAFETY comment are plain libc calls whose pointer arguments come from a
//! live local or slice with the length taken from the same value (or are plain integers); no pointer outlives the call.
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const T_A: u16 = 1;
const T_NS: u16 = 2;
const T_CNAME: u16 = 5;
const T_SOA: u16 = 6;
const T_AAAA: u16 = 28;
const T_OPT: u16 = 41;
const EDNS_PAYLOAD: u16 = 1232; // DNS flag day 2020: fits any path MTU
pub const MAX_SERVERS: usize = 3; // resolv.conf: glibc MAXNS (also the --dns-server limit, cli.rs)
const FLAG_QR: u16 = 0x8000; // header flags: a response
const FLAG_TC: u16 = 0x0200; // header flags: truncated (retry over TCP)
const MAX_CNAME: usize = 8;
const RELOAD_EVERY: Duration = Duration::from_secs(1);

/// Resolver settings from resolv.conf (servers replaced by --dns-server when given).
#[derive(Clone, Debug, PartialEq)]
pub struct Conf {
    pub servers: Vec<SocketAddr>,
    pub timeout: u64, // seconds, as written (the window is clamped to 1..=2 s, see window())
    pub attempts: usize,
    pub rotate: bool,
}

impl Conf {
    /// Per-server window: the resolv.conf timeout, clamped to 1..=2 s (70.09: dead servers fail fast).
    pub fn window(&self) -> Duration {
        Duration::from_secs(self.timeout.clamp(1, 2))
    }
    /// Tries per family: servers x attempts, at most 3. Deadline = admission + window x tries (worst 6 s).
    pub fn tries(&self) -> usize {
        (self.servers.len() * self.attempts).clamp(1, 3)
    }
}

/// `IP`, `IP:PORT`, `[IPv6]:PORT`, an IPv6 with `%scope` (interface name or index; also inside brackets).
/// Port 53 when not given. None for anything else (port 0, a scope on IPv4, an unknown interface).
pub fn parse_server(s: &str) -> Option<SocketAddr> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => 53,
            t => t.strip_prefix(':')?.parse().ok()?,
        };
        (h, port)
    } else if s.matches(':').count() == 1 {
        let (h, p) = s.split_once(':')?;
        (h, p.parse().ok()?)
    } else {
        (s, 53)
    };
    if port == 0 {
        return None;
    }
    let (ip, scope) = match host.split_once('%') {
        Some((ip, sc)) => (ip, Some(sc)),
        None => (host, None),
    };
    match (ip.parse::<IpAddr>().ok()?, scope) {
        (IpAddr::V6(v6), Some(sc)) => {
            let id = match sc.parse::<u32>() {
                Ok(n) => n,
                Err(_) => {
                    let c = std::ffi::CString::new(sc).ok()?;
                    unsafe { libc::if_nametoindex(c.as_ptr()) }
                }
            };
            (id != 0).then(|| SocketAddr::V6(SocketAddrV6::new(v6, port, 0, id)))
        }
        (IpAddr::V4(_), Some(_)) => None,
        (a, None) => Some(SocketAddr::new(a, port)),
    }
}

/// resolv.conf(5) subset. Unknown lines and options are ignored; missing values keep glibc's defaults.
pub fn parse_resolv(text: &str) -> Conf {
    let mut c = Conf { servers: Vec::new(), timeout: 5, attempts: 2, rotate: false };
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut tok = line.split_whitespace();
        match tok.next() {
            Some("nameserver") => {
                // resolv.conf has no port syntax: a bare address (IPv6 with an optional %scope)
                if let Some(a) = tok.next().filter(|a| !a.contains('[')).and_then(|a| {
                    let ip = a.split('%').next().unwrap_or("");
                    ip.parse::<IpAddr>().ok()?;
                    parse_server(&if ip.contains(':') { format!("[{a}]") } else { a.to_string() })
                }) {
                    if c.servers.len() < MAX_SERVERS {
                        c.servers.push(a);
                    }
                }
            }
            // search / domain / options ndots: ignored (60.18 #16: client names are absolute, never completed)
            Some("options") => {
                for o in tok {
                    let num = |p: &str| o.strip_prefix(p).and_then(|v| v.parse::<u64>().ok());
                    if let Some(n) = num("timeout:") {
                        c.timeout = n.clamp(1, 30);
                    } else if let Some(n) = num("attempts:") {
                        c.attempts = n.clamp(1, 5) as usize;
                    } else if o == "rotate" {
                        c.rotate = true;
                    }
                }
            }
            _ => {}
        }
    }
    c
}

fn domain(d: &str) -> Option<String> {
    let d = d.trim_end_matches('.').to_ascii_lowercase();
    (!d.is_empty()).then_some(d)
}

/// hosts(5): name (lowercase, no trailing dot) -> addresses in file order, both families.
pub fn parse_hosts(text: &str) -> HashMap<String, Vec<IpAddr>> {
    let mut m: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for line in text.lines() {
        let mut tok = line.split('#').next().unwrap_or("").split_whitespace();
        let Some(Ok(ip)) = tok.next().map(|a| a.split('%').next().unwrap_or("").parse::<IpAddr>()) else { continue };
        for name in tok.filter_map(domain) {
            let v = m.entry(name).or_default();
            if !v.contains(&ip) {
                v.push(ip);
            }
        }
    }
    m
}

/// Wire form of a name: length-prefixed lowercase labels, root byte. None: empty label, label > 63, name > 255.
pub fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

/// One question (RD set), with an EDNS0 OPT record (payload 1232, no DO bit) when `edns`.
pub fn query(id: u16, qname: &[u8], qtype: u16, edns: bool) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + qname.len() + 4 + 11);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, edns as u8]);
    q.extend_from_slice(qname);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    if edns {
        q.extend_from_slice(&[0]);
        q.extend_from_slice(&T_OPT.to_be_bytes());
        q.extend_from_slice(&EDNS_PAYLOAD.to_be_bytes());
        q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    q
}

#[derive(Debug, PartialEq)]
pub enum Reply {
    Addrs(Vec<IpAddr>),
    NoData,   // NOERROR without an address of the asked type at the end of the CNAME chain
    NxDomain, // RCODE 3
    Truncated,
    FormErr,
    ServFail, // SERVFAIL, REFUSED, NOTIMP and any other RCODE: try the next server
}

fn be16(m: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(m.get(at..at + 2)?.try_into().ok()?))
}

/// A (possibly compressed) name at `at` in wire form, lowercased, and the offset after it. Pointers must go
/// backwards, at most 32 of them, and the name must fit 255 bytes: no loop or blow-up on hostile input.
pub fn read_name(m: &[u8], at: usize) -> Option<(Vec<u8>, usize)> {
    let (mut out, mut p, mut end, mut jumps) = (Vec::new(), at, None, 0);
    loop {
        let len = *m.get(p)? as usize;
        match len & 0xC0 {
            0x00 if len == 0 => {
                out.push(0);
                return (out.len() <= 255).then(|| (out, end.unwrap_or(p + 1)));
            }
            0x00 => {
                out.push(len as u8);
                out.extend(m.get(p + 1..p + 1 + len)?.iter().map(|b| b.to_ascii_lowercase()));
                if out.len() > 255 {
                    return None;
                }
                p += 1 + len;
            }
            0xC0 => {
                let target = ((len & 0x3F) << 8) | *m.get(p + 1)? as usize;
                jumps += 1;
                if target >= p || jumps > 32 {
                    return None;
                }
                end.get_or_insert(p + 2);
                p = target;
            }
            _ => return None, // 0x40 / 0x80 label types: obsolete or unknown
        }
    }
}

/// Validate a reply to `query(id, qname, qtype, _)`. None = not our reply or malformed: the caller ignores the
/// packet and keeps waiting (a spoofed or garbage packet cannot fail a lookup). Checks: ID, QR, opcode 0, the
/// question echoes name/type/class IN (only a FORMERR may omit it). Addresses: of `qtype`, class IN, owned by
/// the end of the CNAME chain that starts at qname (at most 8 hops).
pub fn parse_reply(m: &[u8], id: u16, qname: &[u8], qtype: u16) -> Option<Reply> {
    let flags = be16(m, 2)?;
    if be16(m, 0)? != id || flags & FLAG_QR == 0 || (flags >> 11) & 0xF != 0 {
        return None;
    }
    let rcode = flags & 0xF;
    let (qd, an) = (be16(m, 4)?, be16(m, 6)?);
    if qd == 0 && rcode == 1 {
        return Some(Reply::FormErr);
    }
    if qd != 1 {
        return None;
    }
    let (name, mut p) = read_name(m, 12)?;
    if name != qname || be16(m, p)? != qtype || be16(m, p + 2)? != 1 {
        return None;
    }
    p += 4;
    if flags & FLAG_TC != 0 {
        return Some(Reply::Truncated);
    }
    let (mut cnames, mut addrs) = (Vec::new(), Vec::new());
    for _ in 0..an {
        let (owner, q) = read_name(m, p)?;
        let (rtype, class, rdlen) = (be16(m, q)?, be16(m, q + 2)?, be16(m, q + 8)? as usize);
        let rd = q + 10;
        let data = m.get(rd..rd + rdlen)?;
        p = rd + rdlen;
        if class != 1 {
            continue;
        }
        match (rtype, rdlen) {
            (T_CNAME, _) => {
                let (target, after) = read_name(m, rd)?;
                if after != p {
                    return None;
                }
                cnames.push((owner, target));
            }
            (T_A, 4) if qtype == T_A => addrs.push((owner, IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?)))),
            (T_AAAA, 16) if qtype == T_AAAA => addrs.push((owner, IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)))),
            _ => {}
        }
    }
    // review: authority + additional. EDNS extended RCODE (OPT TTL high byte, e.g. BADVERS) = an error, not
    // NOERROR; an empty answer with NS but no SOA in authority is a referral (not a recursive server), not NODATA.
    let (ns, ar) = (be16(m, 8)? as usize, be16(m, 10)? as usize);
    let (mut soa, mut deleg) = (false, false);
    for k in 0..ns + ar {
        let (_, q) = read_name(m, p)?;
        let (rtype, rdlen) = (be16(m, q)?, be16(m, q + 8)? as usize);
        m.get(q + 10..q + 10 + rdlen)?;
        p = q + 10 + rdlen;
        if k < ns {
            soa |= rtype == T_SOA;
            deleg |= rtype == T_NS;
        } else if rtype == T_OPT && m[q + 4] != 0 {
            return Some(Reply::ServFail); // the full RCODE is above 15: never NOERROR/NXDOMAIN
        }
    }
    match rcode {
        0 => {}
        1 => return Some(Reply::FormErr),
        3 => return Some(Reply::NxDomain),
        _ => return Some(Reply::ServFail),
    }
    let mut cur = qname.to_vec();
    for _ in 0..MAX_CNAME {
        match cnames.iter().find(|(o, _)| *o == cur) {
            Some((_, t)) => cur = t.clone(),
            None => break,
        }
    }
    if cnames.iter().any(|(o, _)| *o == cur) {
        return Some(Reply::ServFail); // review: a CNAME loop or a chain over 8 hops is a failure, never "no address"
    }
    let mut out: Vec<IpAddr> = Vec::new();
    for (o, a) in addrs {
        if o == cur && !out.contains(&a) {
            out.push(a);
        }
    }
    Some(match (out.is_empty(), deleg && !soa) {
        (false, _) => Reply::Addrs(out),
        (true, true) => Reply::ServFail,
        (true, false) => Reply::NoData,
    })
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    if unsafe { libc::getrandom(b.as_mut_ptr().cast(), 4, 0) } == 4 {
        return u32::from_ne_bytes(b);
    }
    // SipHash keyed from the OS RNG (getrandom is missing only on Linux < 3.17)
    std::collections::hash_map::RandomState::new().build_hasher().finish() as u32
}

fn sock(server: &SocketAddr, ty: libc::c_int) -> Option<OwnedFd> {
    let fam = if server.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(fam, ty | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: fd is a fresh socket we own
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let (ss, len) = crate::net::sockaddr(server);
    // SAFETY: ss is a sockaddr_storage filled for `server` with its used length `len`
    let r = unsafe { libc::connect(fd.as_raw_fd(), &ss as *const _ as *const libc::sockaddr, len) };
    (r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINPROGRESS)).then_some(fd)
}

/// Would a connect to `a` find a route (glibc RFC 6724 rule 1 stand-in)? A UDP connect sends nothing.
fn routable(a: Ipv6Addr) -> bool {
    sock(&SocketAddr::new(IpAddr::V6(a), 53), libc::SOCK_DGRAM).is_some()
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fam {
    Wait,
    Addrs, // in Q::addrs
    Neg,   // NXDOMAIN or NODATA
    Fail,  // out of tries / deadline
}

/// One family's query: the current try's socket (UDP, or TCP after TC=1), its window end, and the outcome.
struct Q {
    qtype: u16,
    fd: Option<OwnedFd>,
    id: u16,
    edns: bool,
    tcp: Option<Vec<u8>>, // Some = TCP; empty until the query is written, then the reply bytes so far
    tries: usize,
    server: usize,
    until: Instant,
    state: Fam,
    addrs: Vec<IpAddr>,
}

struct Ctx<'a> {
    conf: &'a Conf,
    v4_only: bool, // 60.20 C1 --no-ipv6-targets: no AAAA query
    qname: &'a [u8],
    deadline: Instant,
    start: usize,
}

impl Q {
    fn new(qtype: u16) -> Q {
        let now = Instant::now();
        Q { qtype, fd: None, id: 0, edns: true, tcp: None, tries: 0, server: 0, until: now, state: Fam::Wait, addrs: Vec::new() }
    }
    fn msg(&self, cx: &Ctx) -> Vec<u8> {
        query(self.id, cx.qname, self.qtype, self.edns)
    }
    /// Next server (UDP, EDNS on), or Fail when out of tries or time. A send error uses up the try at once.
    fn next_try(&mut self, cx: &Ctx) {
        self.tcp = None;
        loop {
            self.fd = None; // review: also after a failed send, or the next server's try reuses the old socket
            let now = Instant::now();
            if self.tries >= cx.conf.tries() || now >= cx.deadline {
                self.state = Fam::Fail;
                return;
            }
            self.server = (cx.start + self.tries) % cx.conf.servers.len();
            self.tries += 1;
            self.edns = true;
            if self.send_udp(cx) {
                return;
            }
        }
    }
    fn send_udp(&mut self, cx: &Ctx) -> bool {
        if self.fd.is_none() {
            self.fd = sock(&cx.conf.servers[self.server], libc::SOCK_DGRAM);
        }
        let Some(fd) = &self.fd else { return false };
        self.id = rand_u32() as u16;
        let m = self.msg(cx);
        let n = unsafe { libc::send(fd.as_raw_fd(), m.as_ptr().cast(), m.len(), libc::MSG_NOSIGNAL) };
        self.until = (Instant::now() + cx.conf.window()).min(cx.deadline);
        n == m.len() as isize
    }
    fn start_tcp(&mut self, cx: &Ctx) {
        self.fd = sock(&cx.conf.servers[self.server], libc::SOCK_STREAM);
        self.tcp = Some(Vec::new());
        self.until = (Instant::now() + cx.conf.window()).min(cx.deadline);
        if self.fd.is_none() {
            self.next_try(cx);
        }
    }
    fn events(&self) -> i16 {
        match &self.tcp {
            Some(b) if b.is_empty() => libc::POLLOUT,
            _ => libc::POLLIN,
        }
    }
    fn on_reply(&mut self, cx: &Ctx, r: Reply) {
        match r {
            Reply::Addrs(a) => {
                self.addrs = a;
                self.state = Fam::Addrs;
                self.fd = None;
            }
            Reply::NoData | Reply::NxDomain => {
                self.state = Fam::Neg;
                self.fd = None;
            }
            Reply::Truncated if self.tcp.is_none() => self.start_tcp(cx),
            Reply::FormErr if self.edns && self.tcp.is_none() => {
                self.edns = false; // an old server that rejects EDNS: once more without the OPT record
                let until = self.until; // review: inside the same window (the TCP retry after TC gets its own)
                let sent = self.send_udp(cx);
                self.until = until;
                if !sent {
                    self.next_try(cx);
                }
            }
            _ => self.next_try(cx),
        }
    }
    /// The socket is ready (or has an error / hangup).
    fn ready(&mut self, cx: &Ctx) {
        let Some(fd) = self.fd.as_ref().map(|f| f.as_raw_fd()) else { return };
        let m = if self.tcp.as_ref().is_some_and(|b| b.is_empty()) { self.msg(cx) } else { Vec::new() };
        let Some(buf) = &mut self.tcp else {
            let mut b = [0u8; 4096];
            // review: at most 16 datagrams per wakeup, so a flood cannot hold off the deadline, the cancel check
            // and the other family (what is left keeps the socket readable: poll() returns at once)
            for _ in 0..16 {
                let n = unsafe { libc::recv(fd, b.as_mut_ptr().cast(), b.len(), libc::MSG_TRUNC) };
                if n < 0 {
                    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EAGAIN) {
                        self.next_try(cx); // ECONNREFUSED (ICMP port unreachable) and the like
                    }
                    return;
                }
                // a datagram larger than the buffer was cut: ignore it like any malformed packet
                if let Some(r) = parse_reply(b.get(..n as usize).unwrap_or(&[]), self.id, cx.qname, self.qtype) {
                    self.on_reply(cx, r);
                    if self.state != Fam::Wait || self.fd.as_ref().is_none_or(|f| f.as_raw_fd() != fd) || self.tcp.is_some() {
                        return; // done, or a new socket / transport: the old one's queue is not ours any more
                    }
                }
            }
            return;
        };
        if buf.is_empty() {
            let mut err: libc::c_int = 0;
            let mut len = size_of::<libc::c_int>() as libc::socklen_t;
            unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&mut err as *mut libc::c_int).cast(), &mut len) };
            let mut framed = (m.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&m);
            let n = if err == 0 { unsafe { libc::send(fd, framed.as_ptr().cast(), framed.len(), libc::MSG_NOSIGNAL) } } else { -1 };
            if n != framed.len() as isize {
                return self.next_try(cx); // a short write of < 300 bytes on a fresh connection: give up this try
            }
            buf.push(1); // marker: the query is written; the reply bytes follow it
            return;
        }
        let mut b = [0u8; 4096];
        let n = unsafe { libc::recv(fd, b.as_mut_ptr().cast(), b.len(), 0) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
            return;
        }
        if n <= 0 {
            return self.next_try(cx); // EOF or error before the whole reply
        }
        buf.extend_from_slice(&b[..n as usize]);
        let got = &buf[1..];
        let Some(want) = be16(got, 0).map(|l| l as usize + 2) else { return };
        if got.len() < want {
            return;
        }
        match parse_reply(&got[2..want], self.id, cx.qname, self.qtype) {
            Some(Reply::Truncated) | None => self.next_try(cx),
            Some(r) => self.on_reply(cx, r),
        }
    }
}

/// Outcome of one candidate name: its addresses (AAAA first if routable), definitive negative, failure, or Gone (every
/// waiter left: give up, 70.09 cancel).
enum Cand {
    Addrs(Vec<IpAddr>),
    Neg,
    Fail,
    Gone,
}

/// 70.10 RFC 8305 s3 resolution delay: when A answers first, wait this long for AAAA before the A addresses are
/// handed out early (a routable AAAA answer is handed out at once).
pub const RESOLUTION_DELAY: Duration = Duration::from_millis(50);

/// Addresses of both families in connect order: AAAA first only if the host can route to the first AAAA.
fn ordered(a: Vec<IpAddr>, aaaa: Vec<IpAddr>) -> Vec<IpAddr> {
    let v6_first = aaaa.first().is_some_and(|x| matches!(x, IpAddr::V6(v) if routable(*v)));
    let (x, y) = if v6_first { (aaaa, a) } else { (a, aaaa) };
    x.into_iter().chain(y).collect()
}

/// `early` (70.10): called at most once, with one family's addresses, when that family answered and the other is
/// still outstanding (after RESOLUTION_DELAY unless it is a routable AAAA). The lookup then goes on to the normal
/// deadline for the other family; the final result holds both.
fn ask(cx: &Ctx, gone: &mut dyn FnMut() -> bool, early: &mut dyn FnMut(&[IpAddr])) -> Cand {
    let mut qs = [Q::new(T_A), Q::new(T_AAAA)];
    if cx.v4_only {
        qs[1].state = Fam::Neg; // 60.20 C1 --no-ipv6-targets: never asked (no early answer, no AAAA wait)
    }
    for q in qs.iter_mut().filter(|q| q.state == Fam::Wait) {
        q.next_try(cx);
    }
    let mut early_at: Option<Instant> = None; // when the one family's addresses go out early
    let mut early_sent = false;
    while qs.iter().any(|q| q.state == Fam::Wait) {
        let mut pfd = Vec::with_capacity(2);
        let mut idx = Vec::with_capacity(2);
        let mut until = cx.deadline;
        if let Some(t) = early_at.filter(|_| !early_sent) {
            until = until.min(t);
        }
        for (i, q) in qs.iter().enumerate() {
            if let (Fam::Wait, Some(fd)) = (q.state, &q.fd) {
                pfd.push(libc::pollfd { fd: fd.as_raw_fd(), events: q.events(), revents: 0 });
                idx.push(i);
                until = until.min(q.until);
            }
        }
        let ms = until.saturating_duration_since(Instant::now()).as_micros().div_ceil(1000).min(i32::MAX as u128) as i32;
        let r = unsafe { libc::poll(pfd.as_mut_ptr(), pfd.len() as libc::nfds_t, ms) };
        if gone() {
            return Cand::Gone; // before any retry goes out
        }
        if r > 0 {
            for (p, &i) in pfd.iter().zip(&idx) {
                if p.revents != 0 {
                    qs[i].ready(cx);
                }
            }
        }
        let now = Instant::now();
        for q in qs.iter_mut() {
            if q.state == Fam::Wait && now >= q.until {
                q.next_try(cx);
            }
        }
        if !early_sent {
            for (i, j) in [(0, 1), (1, 0)] {
                if qs[i].state == Fam::Addrs && qs[j].state == Fam::Wait {
                    let at_once = i == 1 && matches!(qs[1].addrs.first(), Some(IpAddr::V6(v)) if routable(*v));
                    let t = *early_at.get_or_insert(if at_once { now } else { now + RESOLUTION_DELAY });
                    if now >= t {
                        early(&qs[i].addrs);
                        early_sent = true;
                    }
                }
            }
        }
    }
    let [a, aaaa] = qs;
    if !a.addrs.is_empty() || !aaaa.addrs.is_empty() {
        return Cand::Addrs(ordered(a.addrs, aaaa.addrs));
    }
    if a.state == Fam::Neg && aaaa.state == Fam::Neg {
        Cand::Neg
    } else {
        Cand::Fail
    }
}

type FileId = Option<(i64, i64, u64, u64)>;

fn file_id(p: &PathBuf) -> FileId {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| (m.mtime(), m.mtime_nsec(), m.ino(), m.size()))
}

struct Files {
    conf: Arc<Conf>,
    hosts: Arc<HashMap<String, Vec<IpAddr>>>,
    checked: Option<Instant>,
    ids: (FileId, FileId),
}

pub struct Resolver {
    servers: Vec<SocketAddr>, // --dns-server: replaces the resolv.conf nameservers
    resolv: PathBuf,
    hosts: PathBuf,
    files: Mutex<Files>,
    v4_only: bool, // 60.20 C1 --no-ipv6-targets (ipv4_only)
}

impl Resolver {
    pub fn new(servers: Vec<SocketAddr>) -> Resolver {
        Resolver::with_paths(servers, "/etc/resolv.conf".into(), "/etc/hosts".into())
    }
    pub fn with_paths(servers: Vec<SocketAddr>, resolv: PathBuf, hosts: PathBuf) -> Resolver {
        let files = Files { conf: Arc::new(parse_resolv("")), hosts: Default::default(), checked: None, ids: (None, None) };
        Resolver { servers, resolv, hosts, files: Mutex::new(files), v4_only: false }
    }
    /// 60.20 C1 --no-ipv6-targets: ask A only (no AAAA query goes out)
    pub fn ipv4_only(mut self, on: bool) -> Resolver {
        self.v4_only = on;
        self
    }
    /// Current settings; resolv.conf and hosts are re-read when their mtime/inode/size changed (checked at most
    /// once per second, like glibc >= 2.26). No nameserver at all: 127.0.0.1 (glibc's default).
    pub fn files(&self) -> (Arc<Conf>, Arc<HashMap<String, Vec<IpAddr>>>) {
        let mut f = self.files.lock().unwrap();
        if f.checked.is_none_or(|t| t.elapsed() >= RELOAD_EVERY) {
            f.checked = Some(Instant::now());
            let ids = (file_id(&self.resolv), file_id(&self.hosts));
            if ids.0 != f.ids.0 || f.ids == (None, None) {
                let text = std::fs::read(&self.resolv).unwrap_or_default();
                let mut c = parse_resolv(&String::from_utf8_lossy(&text));
                if !self.servers.is_empty() {
                    c.servers = self.servers.clone();
                } else if c.servers.is_empty() {
                    c.servers.push(SocketAddr::from(([127, 0, 0, 1], 53)));
                }
                f.conf = Arc::new(c);
            }
            if ids.1 != f.ids.1 {
                let text = std::fs::read(&self.hosts).unwrap_or_default();
                f.hosts = Arc::new(parse_hosts(&String::from_utf8_lossy(&text)));
            }
            f.ids = ids;
        }
        (f.conf.clone(), f.hosts.clone())
    }
    /// The /etc/hosts addresses of `name` (no trailing dot; case-insensitive), re-read like files(). 60.18 #16: also used
    /// by the getaddrinfo pool before it asks for the absolute `name.`, which glibc never matches against /etc/hosts.
    pub fn hosts_entry(&self, name: &str) -> Option<Vec<IpAddr>> {
        let name = name.strip_suffix('.').unwrap_or(name);
        self.files().1.get(&name.to_ascii_lowercase()).cloned()
    }
    /// For the startup capability line.
    pub fn describe(&self) -> String {
        let (c, _) = self.files();
        let src = if self.servers.is_empty() { self.resolv.display().to_string() } else { "--dns-server".into() };
        let list: Vec<String> = c.servers.iter().map(|s| s.to_string()).collect();
        format!("own resolver ({} from {src}, {} s x {})", list.join(" "), c.window().as_secs(), c.tries())
    }
    /// net::lookup's contract. `at` = admission (time in the pool queue counts); `gone` is polled before every
    /// candidate and at every wakeup (a reply or a window end): true = nobody waits any more, give up (Err(false)).
    /// `early` (70.10, `ask`): one family's addresses before the other answered; the final Ok holds both families.
    pub fn lookup(
        &self,
        host: &str,
        at: Instant,
        gone: &mut dyn FnMut() -> bool,
        early: &mut dyn FnMut(&[IpAddr]),
    ) -> Result<Vec<IpAddr>, bool> {
        let bare = host.strip_suffix('.').unwrap_or(host);
        if bare.is_empty() || host.len() > 254 || host.contains('\0') || encode_name(bare).is_none() {
            return Err(false);
        }
        if let Some(a) = self.hosts_entry(bare) {
            return Ok(a);
        }
        let (conf, _) = self.files();
        let deadline = at + conf.window() * conf.tries() as u32;
        let start = if conf.rotate { rand_u32() as usize % conf.servers.len() } else { 0 };
        // 60.18 #16 the client's name as an absolute name only: no search list, no ndots (a short `wiki` must not
        // reach `wiki.<search domain>`, which --block-host never saw)
        if gone() {
            return Err(false);
        }
        let Some(qname) = encode_name(bare) else { return Err(false) };
        match ask(&Ctx { conf: &conf, v4_only: self.v4_only, qname: &qname, deadline, start }, gone, early) {
            Cand::Addrs(a) => Ok(a),
            Cand::Neg => Err(true),
            Cand::Fail | Cand::Gone => Err(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    fn nm(s: &str) -> Vec<u8> {
        encode_name(s).unwrap()
    }
    /// A reply to query `q`: header from the query, rcode/TC, the question copied, answers owned by `owner`
    /// (None = a pointer to the question name).
    type Rr<'a> = (Option<&'a [u8]>, u16, Vec<u8>); // owner (None = pointer to the question), type, data
    fn reply(q: &[u8], rcode: u16, tc: bool, ans: &[Rr]) -> Vec<u8> {
        let (_, qend) = read_name(q, 12).unwrap();
        let mut m = q[..2].to_vec();
        m.extend_from_slice(&(0x8180 | rcode | if tc { 0x0200 } else { 0 }).to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        m.extend_from_slice(&(ans.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(&q[12..qend + 4]);
        for (owner, ty, data) in ans {
            match owner {
                Some(o) => m.extend_from_slice(o),
                None => m.extend_from_slice(&[0xC0, 12]),
            }
            m.extend_from_slice(&ty.to_be_bytes());
            m.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            m.extend_from_slice(&(data.len() as u16).to_be_bytes());
            m.extend_from_slice(data);
        }
        m
    }

    #[test]
    fn query_layout() {
        assert_eq!(nm("Ab.c"), b"\x02ab\x01c\x00");
        assert!(encode_name("a..b").is_none() && encode_name("").is_none() && encode_name(&"x".repeat(64)).is_none());
        assert!(encode_name(&["a"; 127].join(".")).is_some() && encode_name(&["a"; 128].join(".")).is_none());
        let q = query(0x1234, &nm("a.b"), T_AAAA, true);
        assert_eq!(&q[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&q[12..21], b"\x01a\x01b\x00\x00\x1c\x00\x01");
        assert_eq!(&q[21..], &[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(query(1, &nm("a"), T_A, false).len(), 12 + 3 + 4);
    }

    #[test]
    fn reply_validation() {
        let qn = nm("www.example.com");
        let q = query(7, &qn, T_A, true);
        let a = |ip: [u8; 4]| (None, T_A, ip.to_vec());
        let ok = reply(&q, 0, false, &[a([1, 2, 3, 4]), a([5, 6, 7, 8]), a([1, 2, 3, 4])]);
        let want = Reply::Addrs(vec![IpAddr::from([1, 2, 3, 4]), IpAddr::from([5, 6, 7, 8])]);
        assert_eq!(parse_reply(&ok, 7, &qn, T_A), Some(want));
        assert_eq!(parse_reply(&ok, 8, &qn, T_A), None, "wrong ID");
        assert_eq!(parse_reply(&ok, 7, &nm("www.example.org"), T_A), None, "other question");
        assert_eq!(parse_reply(&ok, 7, &qn, T_AAAA), None, "other type");
        let mut q0 = ok.clone();
        q0[2] &= 0x7F;
        assert_eq!(parse_reply(&q0, 7, &qn, T_A), None, "QR=0");
        let mut up = ok.clone();
        up[13] = b'W'; // the echo may differ in case
        assert!(matches!(parse_reply(&up, 7, &qn, T_A), Some(Reply::Addrs(_))));
        for n in 0..ok.len() {
            assert_eq!(parse_reply(&ok[..n], 7, &qn, T_A), None, "cut at {n}");
        }
        assert_eq!(parse_reply(&reply(&q, 3, false, &[]), 7, &qn, T_A), Some(Reply::NxDomain));
        assert_eq!(parse_reply(&reply(&q, 2, false, &[]), 7, &qn, T_A), Some(Reply::ServFail));
        assert_eq!(parse_reply(&reply(&q, 5, false, &[]), 7, &qn, T_A), Some(Reply::ServFail));
        assert_eq!(parse_reply(&reply(&q, 1, false, &[]), 7, &qn, T_A), Some(Reply::FormErr));
        assert_eq!(parse_reply(&reply(&q, 0, true, &[a([1, 1, 1, 1])]), 7, &qn, T_A), Some(Reply::Truncated));
        assert_eq!(parse_reply(&reply(&q, 0, false, &[]), 7, &qn, T_A), Some(Reply::NoData));
        let formerr_bare = [0, 7, 0x81, 0x81, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_reply(&formerr_bare, 7, &qn, T_A), Some(Reply::FormErr), "FORMERR may omit the question");
        let servfail_bare = [0, 7, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_reply(&servfail_bare, 7, &qn, T_A), None);
        // authority / additional: NODATA with SOA, referral (NS, no SOA), EDNS extended RCODE (BADVERS)
        let with_m = |nsrecs: &[(u16, &[u8])], arrecs: &[(u16, [u8; 4])]| {
            let mut m = reply(&q, 0, false, &[]);
            m[9] = nsrecs.len() as u8;
            m[11] = arrecs.len() as u8;
            for (t, data) in nsrecs {
                m.extend_from_slice(&[0xC0, 0x10]);
                m.extend_from_slice(&t.to_be_bytes());
                m.extend_from_slice(&[0, 1, 0, 0, 0, 60, 0, data.len() as u8]);
                m.extend_from_slice(data);
            }
            for (t, ttl) in arrecs {
                m.push(0);
                m.extend_from_slice(&t.to_be_bytes());
                m.extend_from_slice(&[0x04, 0xD0]);
                m.extend_from_slice(ttl);
                m.extend_from_slice(&[0, 0]);
            }
            m
        };
        let with = |n: &[(u16, &[u8])], a: &[(u16, [u8; 4])]| parse_reply(&with_m(n, a), 7, &qn, T_A);
        let cut = with_m(&[(2, &[0, 1])], &[]);
        assert_eq!(
            with(&[(6, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])], &[(T_OPT, [0; 4])]),
            Some(Reply::NoData)
        );
        assert_eq!(with(&[(2, &[0]), (2, &[0])], &[]), Some(Reply::ServFail), "referral");
        assert_eq!(with(&[(2, &[0]), (6, &[0; 22])], &[]), Some(Reply::NoData));
        assert_eq!(with(&[], &[(T_OPT, [1, 0, 0, 0])]), Some(Reply::ServFail), "BADVERS");
        let mut nx_ext = with_m(&[], &[(T_OPT, [1, 0, 0, 0])]);
        nx_ext[3] |= 3; // full RCODE 19, low bits = NXDOMAIN's
        assert_eq!(parse_reply(&nx_ext, 7, &qn, T_A), Some(Reply::ServFail));
        assert_eq!(parse_reply(&cut[..cut.len() - 1], 7, &qn, T_A), None, "authority record cut short");
        // an AAAA record in an A reply and a short A record are skipped
        let odd = reply(&q, 0, false, &[(None, T_AAAA, vec![0; 16]), (None, T_A, vec![1, 2, 3])]);
        assert_eq!(parse_reply(&odd, 7, &qn, T_A), Some(Reply::NoData));
    }

    #[test]
    fn cname_chain_and_compression() {
        let qn = nm("a.test");
        let q = query(1, &qn, T_AAAA, false);
        // a.test -> b.test (uncompressed) -> c.test; records out of order; an address for a.test is not the end
        let six = vec![0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let m = reply(
            &q,
            0,
            false,
            &[
                (Some(b"\x01b\x04test\x00"), T_CNAME, b"\x01c\x04test\x00".to_vec()),
                (Some(b"\x01c\x04test\x00"), T_AAAA, six.clone()),
                (None, T_CNAME, b"\x01b\x04test\x00".to_vec()),
                (None, T_AAAA, vec![0xfe; 16]),
            ],
        );
        assert_eq!(parse_reply(&m, 1, &qn, T_AAAA), Some(Reply::Addrs(vec![IpAddr::from(<[u8; 16]>::try_from(six).unwrap())])));
        // CNAME loop a -> a: a failure (next server), not a cacheable "no address"; no hang
        let lp = reply(&q, 0, false, &[(None, T_CNAME, vec![0xC0, 12])]);
        assert_eq!(parse_reply(&lp, 1, &qn, T_AAAA), Some(Reply::ServFail));
        // a chain of 9 hops ending in an address: over the limit = failure
        let hop = |i: u8| vec![2, b'h', b'0' + i, 4, b't', b'e', b's', b't', 0];
        let mut chain: Vec<Rr> = vec![(None, T_CNAME, hop(0))];
        let owners: Vec<Vec<u8>> = (0..9).map(hop).collect();
        for i in 0..8u8 {
            chain.push((Some(&owners[i as usize]), T_CNAME, hop(i + 1)));
        }
        chain.push((Some(&owners[8]), T_AAAA, vec![1; 16]));
        assert_eq!(parse_reply(&reply(&q, 0, false, &chain), 1, &qn, T_AAAA), Some(Reply::ServFail));
        chain.remove(1); // h0 -> (nothing): 1 hop, the address owned by h8 is not the chain end
        assert_eq!(parse_reply(&reply(&q, 0, false, &chain), 1, &qn, T_AAAA), Some(Reply::NoData));
        // compression: forward pointer, self pointer, a pointer chain loop, bad label type
        let mut fwd = reply(&q, 0, false, &[(None, T_AAAA, vec![0; 16])]);
        let at = fwd.len() - 28;
        fwd[at..at + 2].copy_from_slice(&[0xC0, 0xFF]);
        assert_eq!(parse_reply(&fwd, 1, &qn, T_AAAA), None);
        assert_eq!(read_name(&[0xC0, 0], 0), None);
        assert_eq!(read_name(&[1, b'a', 0xC0, 1], 0), None, "loop through a label");
        assert_eq!(read_name(&[0x40, 0], 0), None);
        assert_eq!(read_name(&[1, b'A', 0xC0, 5, 9, 0], 0), None, "forward");
        assert_eq!(read_name(&[0, 1, b'X', 0xC0, 0], 1), Some((b"\x01x\x00".to_vec(), 5)));
        let long: Vec<u8> = (0..5).flat_map(|_| std::iter::once(63).chain([b'a'; 63])).chain([0]).collect();
        assert_eq!(read_name(&long, 0), None, "over 255 bytes");
    }

    #[test]
    fn config_files() {
        let lo = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        let c = parse_resolv(
            "# comment\nnameserver 10.0.0.1\nnameserver fe80::1%lo ; tail\nnameserver ::1\nnameserver 9.9.9.9\n\
             nameserver bogus\nsearch A.example. b.example\ndomain ignored.example\nsearch x.example y.example\n\
             options ndots:3 timeout:1 attempts:9 rotate edns0\n",
        );
        assert_eq!(
            c.servers,
            vec![
                "10.0.0.1:53".parse().unwrap(),
                SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, lo)),
                "[::1]:53".parse().unwrap()
            ]
        );
        assert_eq!((c.timeout, c.attempts, c.rotate), (1, 5, true), "search / domain / ndots lines are ignored (60.18 #16)");
        assert_eq!((c.window(), c.tries()), (Duration::from_secs(1), 3));
        let d = parse_resolv("domain Corp.Example.\n");
        assert_eq!((d.window(), d.tries()), (Duration::from_secs(2), 1));
        assert_eq!(parse_resolv("nameserver 1.1.1.1\noptions timeout:30").window(), Duration::from_secs(2));
        let h = parse_hosts("127.0.0.1 localhost Me.local # x\n::1 localhost\n10.0.0.9 me.local.\n# 1.1.1.1 off\nbad x\n");
        assert_eq!(h["localhost"], [IpAddr::from([127, 0, 0, 1]), "::1".parse().unwrap()]);
        assert_eq!(h["me.local"], [IpAddr::from([127, 0, 0, 1]), IpAddr::from([10, 0, 0, 9])]);
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn servers_and_candidates() {
        assert_eq!(parse_server("1.2.3.4"), Some("1.2.3.4:53".parse().unwrap()));
        assert_eq!(parse_server("1.2.3.4:5353"), Some("1.2.3.4:5353".parse().unwrap()));
        assert_eq!(parse_server("::1"), Some("[::1]:53".parse().unwrap()));
        assert_eq!(parse_server("[::1]:54"), Some("[::1]:54".parse().unwrap()));
        assert_eq!(parse_server("[fe80::1%1]:54"), Some(SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 54, 0, 1))));
        for bad in ["", "x", "1.2.3.4:0", "1.2.3.4:x", "[::1", "[::1]x", "1.2.3.4%lo", "fe80::1%nosuchif0", "fe80::1%0"] {
            assert_eq!(parse_server(bad), None, "{bad}");
        }
    }

    /// Fake server on 127.0.0.1 (UDP + TCP, same port). Names: ok (A 192.0.2.1 + AAAA 2001:db8::1),
    /// afail (A SERVFAIL, AAAA ok), tc (UDP: TC=1; TCP: A 192.0.2.7), nx (NXDOMAIN), junk (garbage and a wrong
    /// ID first, then ok), slow (no reply), cn (CNAME to ok.test).
    static COUNT4_AAAA: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static QNAMES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    fn fake() -> SocketAddr {
        fn answer(q: &[u8], tcp: bool) -> Vec<Vec<u8>> {
            let Some((name, e)) = read_name(q, 12) else { return vec![] };
            let qt = be16(q, e).unwrap_or(0);
            let host = String::from_utf8_lossy(&name[1..1 + name[0] as usize]).to_string();
            let a = (None, T_A, vec![192, 0, 2, 1]);
            let six = (None, T_AAAA, "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec());
            let good = if qt == T_A { reply(q, 0, false, &[a]) } else { reply(q, 0, false, &[six]) };
            match host.as_str() {
                "ok" => vec![good],
                "afail" if qt == T_A => vec![reply(q, 2, false, &[])],
                "afail" => vec![good],
                "tc" if !tcp => vec![reply(q, 0, true, &[])],
                "tc" if qt == T_A => vec![reply(q, 0, false, &[(None, T_A, vec![192, 0, 2, 7])])],
                "tc" => vec![reply(q, 0, false, &[])],
                "nx" => vec![reply(q, 3, false, &[])],
                "v4only" if qt == T_A => vec![good], // 70.10 AAAA never answered
                "wiki" | "example" => {
                    // 60.18 #16: every name asked for these is recorded (no search-list completion may be sent)
                    let (mut labels, mut i) = (Vec::new(), 0);
                    while name[i] != 0 {
                        labels.push(String::from_utf8_lossy(&name[i + 1..i + 1 + name[i] as usize]).to_string());
                        i += 1 + name[i] as usize;
                    }
                    QNAMES.lock().unwrap().push(labels.join("."));
                    vec![good]
                }
                "count4" => {
                    // 60.20 C1: AAAA queries for this name are counted (--no-ipv6-targets sends none)
                    if qt == T_AAAA {
                        COUNT4_AAAA.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    vec![good]
                }
                "aaaaonly" if qt == T_AAAA => vec![good], // 70.10 A never answered
                "late" if qt == T_A => vec![good],        // 70.10 AAAA answered 300 ms later (udp thread below)
                "junk" => {
                    let mut wrong = good.clone();
                    wrong[0] ^= 0xFF;
                    vec![b"\xff\xfe garbage".to_vec(), wrong, good]
                }
                "cn" => {
                    let mut r = reply(q, 0, false, &[(None, T_CNAME, b"\x02ok\x04test\x00".to_vec())]);
                    r[7] = 2;
                    r.extend_from_slice(b"\x02ok\x04test\x00");
                    r.extend_from_slice(&qt.to_be_bytes());
                    r.extend_from_slice(&[0, 1, 0, 0, 0, 9]);
                    let d = if qt == T_A { vec![192, 0, 2, 9] } else { vec![0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9] };
                    r.extend_from_slice(&(d.len() as u16).to_be_bytes());
                    r.extend_from_slice(&d);
                    vec![r]
                }
                _ => vec![],
            }
        }
        // UDP and TCP on the same port: the TCP port of a fresh UDP port can be taken (another test's connection or
        // listener: AddrInUse, 60.12 flaky), so a new pair is tried until both bind
        let (u, t) = (0..100)
            .find_map(|_| {
                let u = UdpSocket::bind("127.0.0.1:0").unwrap();
                TcpListener::bind(u.local_addr().unwrap()).ok().map(|t| (u, t))
            })
            .expect("no free UDP+TCP port pair in 100 tries");
        let addr = u.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = u.recv_from(&mut b) {
                let q = b[..n].to_vec();
                if read_name(&q, 12).is_some_and(|(nm, e)| nm.starts_with(b"\x04late\x04") && be16(&q, e) == Some(T_AAAA)) {
                    let (u2, six) = (u.try_clone().unwrap(), "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec());
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(300));
                        let _ = u2.send_to(&reply(&q, 0, false, &[(None, T_AAAA, six)]), from);
                    });
                    continue;
                }
                for r in answer(&q, false) {
                    u.send_to(&r, from).unwrap();
                }
            }
        });
        std::thread::spawn(move || {
            for s in t.incoming() {
                use std::io::{Read, Write};
                let mut s = s.unwrap();
                let mut l = [0u8; 2];
                s.read_exact(&mut l).unwrap();
                let mut q = vec![0u8; u16::from_be_bytes(l) as usize];
                s.read_exact(&mut q).unwrap();
                for r in answer(&q, true) {
                    s.write_all(&(r.len() as u16).to_be_bytes()).unwrap();
                    s.write_all(&r).unwrap();
                }
            }
        });
        addr
    }

    fn resolver(servers: Vec<SocketAddr>, resolv: &str, hosts: &str) -> (Resolver, PathBuf) {
        let dir = std::env::temp_dir().join(format!("fw-dns-{}-{}", std::process::id(), rand_u32()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("resolv.conf"), resolv).unwrap();
        std::fs::write(dir.join("hosts"), hosts).unwrap();
        (Resolver::with_paths(servers, dir.join("resolv.conf"), dir.join("hosts")), dir)
    }

    #[test]
    fn lookups_against_a_fake_server() {
        let srv = fake();
        // the first server refuses (ICMP port unreachable): every family moves on to the fake at once
        let dead = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let (r, _dir) = resolver(vec![dead, srv], "options timeout:1 attempts:1\n", "10.9.9.9 Pinned.Test\n");
        let mut never = || false;
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        let t0 = Instant::now();
        let ok = r.lookup("ok.test", Instant::now(), &mut never, &mut |_| {}).unwrap();
        assert!(ok.contains(&p("192.0.2.1")) && ok.contains(&p("2001:db8::1")) && ok.len() == 2, "{ok:?}");
        assert!(t0.elapsed() < Duration::from_millis(500), "refused server skipped at once: {:?}", t0.elapsed());
        assert_eq!(r.lookup("afail.test", Instant::now(), &mut never, &mut |_| {}), Ok(vec![p("2001:db8::1")]), "A failure keeps AAAA");
        assert_eq!(r.lookup("tc.test.", Instant::now(), &mut never, &mut |_| {}), Ok(vec![p("192.0.2.7")]), "TC -> TCP");
        assert_eq!(r.lookup("nx.test", Instant::now(), &mut never, &mut |_| {}), Err(true));
        assert!(r.lookup("junk.test", Instant::now(), &mut never, &mut |_| {}).is_ok_and(|a| a.len() == 2), "garbage ignored");
        let cn = r.lookup("cn.test", Instant::now(), &mut never, &mut |_| {}).unwrap();
        assert!(cn.contains(&p("192.0.2.9")) && cn.len() == 2, "{cn:?}");
        assert_eq!(r.lookup("pinned.test.", Instant::now(), &mut never, &mut |_| {}), Ok(vec![p("10.9.9.9")]), "hosts first");
        for bad in ["", ".", "a..b", "nul\0.test"] {
            assert_eq!(r.lookup(bad, Instant::now(), &mut never, &mut |_| {}), Err(false), "{bad:?}");
        }
        // tries = 2 servers x 1 attempt -> deadline 2 s from admission
        let t0 = Instant::now();
        assert_eq!(r.lookup("slow.test", Instant::now(), &mut never, &mut |_| {}), Err(false));
        let took = t0.elapsed();
        assert!(took >= Duration::from_millis(900) && took < Duration::from_millis(2500), "{took:?}");
        // admitted long ago (queue time counts): fails without asking
        let t0 = Instant::now();
        assert_eq!(r.lookup("ok.test", Instant::now() - Duration::from_secs(10), &mut never, &mut |_| {}), Err(false));
        assert!(t0.elapsed() < Duration::from_millis(100));
        // cancelled while waiting: gives up at the next wakeup (here: the 1 s window end)
        let t0 = Instant::now();
        let mut calls = 0;
        assert_eq!(
            r.lookup(
                "slow.test",
                Instant::now(),
                &mut || {
                    calls += 1;
                    calls > 2
                },
                &mut |_| {}
            ),
            Err(false)
        );
        assert!(t0.elapsed() < Duration::from_millis(1500), "{:?}", t0.elapsed());
    }

    /// 60.20 C1 --no-ipv6-targets: the own resolver asks A only (no AAAA query, no wait for one)
    /// 60.18 #16 a resolv.conf search list and ndots never complete a client's name: one name per lookup, absolute
    #[test]
    fn search_list_and_ndots_are_ignored() {
        let srv = fake();
        let (r, _dir) = resolver(vec![srv], "search corp.internal\noptions ndots:5 timeout:1 attempts:1\n", "");
        let mut never = || false;
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        for host in ["wiki", "example.com", "wiki."] {
            QNAMES.lock().unwrap().clear();
            let got = r.lookup(host, Instant::now(), &mut never, &mut |_| {});
            assert_eq!(
                got.map(|mut a| {
                    a.sort();
                    a
                }),
                Ok(vec![p("192.0.2.1"), p("2001:db8::1")]),
                "{host}"
            );
            let mut q = QNAMES.lock().unwrap().clone();
            q.sort();
            let want = host.strip_suffix('.').unwrap_or(host);
            assert_eq!(q, [want, want], "{host}: A + AAAA for the name only, never {want}.corp.internal");
        }
    }

    #[test]
    fn ipv4_only_sends_no_aaaa() {
        use std::sync::atomic::Ordering::Relaxed;
        let srv = fake();
        let (r, _dir) = resolver(vec![srv], "options timeout:1 attempts:1\n", "");
        let mut never = || false;
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        let both = r.lookup("count4.test", Instant::now(), &mut never, &mut |_| {}).unwrap();
        assert_eq!(both.len(), 2, "{both:?}");
        let seen = COUNT4_AAAA.load(Relaxed);
        assert!(seen >= 1);
        let r = r.ipv4_only(true);
        assert_eq!(r.lookup("count4.test", Instant::now(), &mut never, &mut |_| {}), Ok(vec![p("192.0.2.1")]));
        assert_eq!(COUNT4_AAAA.load(Relaxed), seen, "no AAAA query sent");
        let t0 = Instant::now();
        assert_eq!(r.lookup("v4only.test", Instant::now(), &mut never, &mut |_| {}), Ok(vec![p("192.0.2.1")]));
        assert!(t0.elapsed() < Duration::from_millis(500), "no wait for an AAAA answer: {:?}", t0.elapsed());
        assert_eq!(r.lookup("aaaaonly.test", Instant::now(), &mut never, &mut |_| {}), Err(false), "A never answered");
        assert_eq!(r.lookup("nx.test", Instant::now(), &mut never, &mut |_| {}), Err(true), "NXDOMAIN stays definitive");
    }

    /// 70.10 RFC 8305 s3: one family's addresses go out early (after RESOLUTION_DELAY for A), the lookup still waits for the
    /// other family, and the final result holds both; no early call when both families answer together.
    #[test]
    fn early_family_delivery() {
        let srv = fake();
        let (r, _dir) = resolver(vec![srv], "options timeout:1 attempts:1\n", "");
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        let run = |name: &str| {
            let t0 = Instant::now();
            let mut got = Vec::new();
            let res = r.lookup(name, Instant::now(), &mut || false, &mut |a| got.push((a.to_vec(), t0.elapsed())));
            (res, got, t0.elapsed())
        };
        let (res, got, _) = run("ok.test");
        assert!(res.is_ok_and(|a| a.len() == 2) && got.is_empty(), "{got:?}");
        // AAAA never answered: A early at ~50 ms, final at the deadline (1 s) with A only
        let (res, got, took) = run("v4only.test");
        assert_eq!(res, Ok(vec![p("192.0.2.1")]));
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, [p("192.0.2.1")]);
        assert!(got[0].1 >= RESOLUTION_DELAY && got[0].1 < Duration::from_millis(400), "{got:?}");
        assert!(took >= Duration::from_millis(900), "{took:?}");
        // A never answered: AAAA early (at once if routable, else after the delay)
        let (res, got, _) = run("aaaaonly.test");
        assert_eq!(res, Ok(vec![p("2001:db8::1")]));
        assert!(got.len() == 1 && got[0].0 == [p("2001:db8::1")] && got[0].1 < Duration::from_millis(400), "{got:?}");
        // AAAA 300 ms late: A early, then the final holds both
        let (res, got, took) = run("late.test");
        let all = res.unwrap();
        assert!(all.len() == 2 && all.contains(&p("192.0.2.1")) && all.contains(&p("2001:db8::1")), "{all:?}");
        assert!(got.len() == 1 && got[0].0 == [p("192.0.2.1")] && got[0].1 < Duration::from_millis(250), "{got:?}");
        assert!(took >= Duration::from_millis(250) && took < Duration::from_millis(900), "{took:?}");
    }

    #[test]
    fn files_reload_on_change() {
        let srv = fake();
        let (r, dir) = resolver(vec![], "nameserver 127.0.0.1\n", "10.0.0.1 h.test\n");
        let one = Some(vec![IpAddr::from([10, 0, 0, 1])]);
        assert_eq!((r.hosts_entry("h.test"), r.hosts_entry("H.Test."), r.hosts_entry("h")), (one.clone(), one, None), "60.18 #16");
        let mut never = || false;
        assert_eq!(r.lookup("h.test", Instant::now(), &mut never, &mut |_| {}), Ok(vec![IpAddr::from([10, 0, 0, 1])]));
        assert_eq!(r.files().0.servers, ["127.0.0.1:53".parse::<SocketAddr>().unwrap()]);
        // a different SIZE: change detection is mtime/inode/size, and on coarse-timestamp filesystems (CI container overlay)
        // a same-size rewrite in the same tick is not seen (editors replace the file = new inode, so real edits are)
        std::fs::write(dir.join("hosts"), "10.0.0.2  h.test\n").unwrap();
        std::fs::write(dir.join("resolv.conf"), format!("nameserver {}\n", srv.ip())).unwrap();
        r.files.lock().unwrap().checked = Some(Instant::now() - RELOAD_EVERY); // skip the 1 s wait
        assert_eq!(r.lookup("h.test", Instant::now(), &mut never, &mut |_| {}), Ok(vec![IpAddr::from([10, 0, 0, 2])]));
        let (_, missing) = resolver(vec![], "", "");
        let r2 = Resolver::with_paths(vec![], missing.join("nope"), missing.join("nope2"));
        assert_eq!(r2.files().0.servers, ["127.0.0.1:53".parse::<SocketAddr>().unwrap()], "glibc default");
        let r3 = Resolver::with_paths(vec![srv], missing.join("nope"), missing.join("nope2"));
        assert_eq!(r3.files().0.servers, [srv], "--dns-server replaces the nameservers");
    }
}
