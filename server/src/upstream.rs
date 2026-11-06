//! 60.27 / 60.32 C6 upstream proxy: the --upstream URL, the proxy's addresses (resolved at startup, refreshed by the
//! `upstream-dns` thread), the request bytes and pure reply parsers for SOCKS5 (RFC 1928 / 1929) and HTTP CONNECT
//! (RFC 9110 9.3.6). The per-stream state machine is worker/upstream.rs. Parsers take what MSG_PEEK saw and say how many bytes to consume:
//! nothing past the reply is ever read here, so tunnel bytes stay in the socket for the normal (splice) path.
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

pub const CLOSE_NETWORK: u8 = 0x03;
pub const CLOSE_UNREACHABLE: u8 = 0x42;
pub const CLOSE_TIMEOUT: u8 = 0x43;
pub const CLOSE_REFUSED: u8 = 0x44;
pub const CLOSE_BLOCKED: u8 = 0x48;

/// Largest HTTP CONNECT response head we accept (MSG_PEEK window; also the stack buffer in the worker)
pub const HTTP_HEAD_MAX: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Socks5,
    Http,
}

/// (no derived Debug: socks_auth / http_auth hold the credentials; Debug prints `shown`)
pub struct Upstream {
    pub kind: Kind,
    /// socks5h:// with --upstream-trust-dns: names go to the proxy (ATYP 3); no local DNS for names
    pub remote_dns: bool,
    pub host: String, // as written (name or IP literal, no brackets)
    pub port: u16,
    /// the proxy's addresses (main fills them; the refresh thread replaces them when the host is a name)
    pub addrs: Arc<ProxyAddrs>,
    /// RFC 1929 sub-negotiation message (precomputed), when credentials are set
    pub socks_auth: Option<Vec<u8>>,
    /// `Proxy-Authorization: Basic ...\r\n` (precomputed), when credentials are set
    pub http_auth: Option<String>,
    /// the URL with the whole userinfo replaced by `***` (for logs and errors)
    pub shown: String,
}

/// How often the refresh thread resolves a proxy host name again (60.27 Q-C)
pub const REFRESH: std::time::Duration = std::time::Duration::from_secs(30);

/// The proxy's addresses: an immutable snapshot, replaced whole (never edited) under the lock, with a generation the
/// workers compare before they take the lock (worker::Worker::proxy_addrs). A failed refresh keeps the last good list:
/// there is never a fall back to direct egress.
pub struct ProxyAddrs {
    gen: AtomicU64,
    list: Mutex<Arc<Vec<IpAddr>>>,
    /// metrics::now_ms() of the last successful resolution (startup counts)
    pub ok_at_ms: AtomicU64,
    /// refreshes that failed or gave no address (the old list stayed)
    pub fails: AtomicU64,
}

impl ProxyAddrs {
    pub fn new(list: Vec<IpAddr>) -> ProxyAddrs {
        ProxyAddrs { gen: AtomicU64::new(0), list: Mutex::new(Arc::new(list)), ok_at_ms: AtomicU64::new(0), fails: AtomicU64::new(0) }
    }
    #[inline]
    pub fn gen(&self) -> u64 {
        self.gen.load(std::sync::atomic::Ordering::Acquire)
    }
    /// (generation, list): the generation read under the lock belongs to that list
    pub fn snapshot(&self) -> (u64, Arc<Vec<IpAddr>>) {
        let l = self.list.lock().unwrap();
        (self.gen.load(Relaxed), l.clone())
    }
    /// ms since the last good resolution (0 if `now_ms` is older: the clocks are one, metrics::now_ms)
    pub fn age_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.ok_at_ms.load(Relaxed))
    }
    /// A refresh result: a new list (a new generation only if it differs), or a failure (the old list stays)
    pub fn publish(&self, r: Result<Vec<IpAddr>, String>, now_ms: u64) {
        match r {
            Ok(a) if !a.is_empty() => {
                let mut l = self.list.lock().unwrap();
                if **l != a {
                    *l = Arc::new(a);
                    self.gen.fetch_add(1, std::sync::atomic::Ordering::Release);
                }
                self.ok_at_ms.store(now_ms, Relaxed);
            }
            _ => {
                self.fails.fetch_add(1, Relaxed);
            }
        }
    }
}

/// The proxy host's addresses: the literal, or getaddrinfo (with the resolver's search list: the operator's name, e.g.
/// a Docker service), duplicates removed, families interleaved (Happy Eyeballs over them alternates). Err: no address.
pub fn resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    use std::net::ToSocketAddrs as _;
    let mut out: Vec<IpAddr> = Vec::new();
    match host.parse::<IpAddr>() {
        Ok(ip) => out.push(ip),
        Err(_) => {
            for a in (host, port).to_socket_addrs().map_err(|e| e.to_string())? {
                if !out.contains(&a.ip()) {
                    out.push(a.ip());
                }
            }
        }
    }
    crate::net::interleave(&mut out);
    if out.is_empty() {
        return Err("no address".to_string());
    }
    Ok(out)
}

/// The `upstream-dns` thread (60.27 Q-C): only for a proxy given by name (none for an IP literal; none when C6 is off).
/// Every REFRESH: resolve and publish. It never touches a worker: the workers pick a new generation up on their next
/// proxied connect.
pub fn start_refresh(up: &Upstream) {
    if up.host.parse::<IpAddr>().is_ok() {
        return;
    }
    let (host, port, addrs) = (up.host.clone(), up.port, up.addrs.clone());
    let _ = crate::metrics::UPSTREAM_DNS.set(addrs.clone());
    std::thread::Builder::new()
        .name("upstream-dns".into())
        .spawn(move || loop {
            std::thread::sleep(REFRESH);
            addrs.publish(resolve(&host, port), crate::metrics::now_ms());
        })
        .expect("spawn upstream-dns thread");
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.shown)
    }
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// RFC 3986 percent-decoding of userinfo (as Go's url.Parse does for wispurr). Malformed escapes are an error.
fn pct(s: &str) -> Result<Vec<u8>, ()> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = b.get(i + 1).copied().and_then(hex).ok_or(())?;
            let l = b.get(i + 2).copied().and_then(hex).ok_or(())?;
            out.push(h << 4 | l);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// Parse --upstream URL. Errors never contain the URL's userinfo (the caller prints only these messages).
/// Accepted: socks5://, socks5h://, http:// (scheme case-insensitive), optional user:pass@ (percent-encoded), host
/// (name, IPv4, [IPv6]), optional port (default 1080 / 80). No path (not even "/"), query or fragment (as wispurr).
pub fn parse_url(url: &str) -> Result<Upstream, String> {
    let (scheme, rest) = url.split_once("://").ok_or("--upstream: not a URL (scheme://host[:port])")?;
    let scheme = scheme.to_ascii_lowercase();
    let (kind, remote_dns, dport) = match scheme.as_str() {
        "socks5" => (Kind::Socks5, false, 1080),
        "socks5h" => (Kind::Socks5, true, 1080),
        "http" => (Kind::Http, false, 80),
        // 60.18 #17: refused loudly (wispurr supports TLS to the proxy; added only if a site needs it)
        "https" => return Err("--upstream: https:// (TLS to the proxy) is not supported; use http:// or socks5://".into()),
        _ => return Err("--upstream: scheme must be socks5, socks5h or http".into()),
    };
    if rest.contains(['/', '?', '#']) {
        return Err("--upstream: no path, query or fragment".into());
    }
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, after) = r.split_once(']').ok_or("--upstream: unclosed [")?;
        let p = match after {
            "" => None,
            a => Some(a.strip_prefix(':').ok_or("--upstream: junk after ]")?),
        };
        (h, p)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, _)) if h.contains(':') => return Err("--upstream: an IPv6 address goes in brackets ([::1]:1080)".into()),
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    let port = match port {
        None => dport,
        Some(p) => p.parse::<u16>().ok().filter(|&p| p != 0).ok_or("--upstream: bad port")?,
    };
    if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._:".contains(&b)) {
        return Err("--upstream: bad host".into());
    }
    if hostport.starts_with('[') && host.parse::<std::net::Ipv6Addr>().is_err() {
        return Err("--upstream: [..] must hold an IPv6 address".into());
    }
    let creds = match userinfo {
        None => None,
        Some(u) => {
            let (user, pass) = u.split_once(':').unwrap_or((u, ""));
            let user = pct(user).map_err(|_| "--upstream: bad %-escape in the user name")?;
            let pass = pct(pass).map_err(|_| "--upstream: bad %-escape in the password")?;
            // RFC 1929: ULEN and PLEN 1..255 (applied to HTTP Basic too, one rule)
            if user.is_empty() || user.len() > 255 || pass.len() > 255 {
                return Err("--upstream: user name 1-255 bytes, password up to 255 bytes".into());
            }
            if kind == Kind::Http && user.contains(&b':') {
                return Err("--upstream: an HTTP Basic user name cannot hold ':'".into());
            }
            Some((user, pass))
        }
    };
    let socks_auth = creds.as_ref().filter(|_| kind == Kind::Socks5).map(|(u, p)| {
        let mut m = vec![1, u.len() as u8];
        m.extend_from_slice(u);
        m.push(p.len() as u8);
        m.extend_from_slice(p);
        m
    });
    let http_auth = creds.as_ref().filter(|_| kind == Kind::Http).map(|(u, p)| {
        let mut up = u.clone();
        up.push(b':');
        up.extend_from_slice(p);
        format!("Proxy-Authorization: Basic {}\r\n", crate::ws::base64(&up))
    });
    let shown_host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    let shown = format!(
        "{scheme}://{}{shown_host}:{port}",
        match &creds {
            Some(_) => "***@".to_string(), // review: the user name is masked too
            None => String::new(),
        }
    );
    let addrs = Arc::new(ProxyAddrs::new(Vec::new()));
    Ok(Upstream { kind, remote_dns, host: host.to_string(), port, addrs, socks_auth, http_auth, shown })
}

/// Q1: socks5h only with --upstream-trust-dns, and the flag only with socks5h. A cross-flag rule, so it runs in
/// cli::check after parse_args (a --config line is checked alone by parse_args: 60.20 C8).
pub fn check_trust(remote_dns: Option<bool>, trust_dns: bool) -> Result<(), String> {
    match (remote_dns, trust_dns) {
        (Some(true), false) => Err("--upstream socks5h://: the proxy resolves names, so the loopback/private/own-address \
checks cannot apply to names; add --upstream-trust-dns to accept that, or use socks5:// (wispurr resolved locally for socks5h too)"
            .into()),
        (Some(false), true) | (None, true) => Err("--upstream-trust-dns: only with --upstream socks5h://...".into()),
        _ => Ok(()),
    }
}

/// What a parser makes of the bytes peeked so far.
#[derive(Debug, PartialEq)]
pub enum Parsed {
    /// incomplete: wait for more bytes (a hangup now = the proxy closed mid-reply)
    Need,
    /// complete: consume `len` bytes; `val` = the chosen method (SOCKS greeting), else 0
    Done { len: usize, val: u8 },
    /// refused or malformed: Wisp CLOSE `reason`; `retry` = a target-side failure (try the next target address)
    Fail { reason: u8, retry: bool },
}
use Parsed::*;

fn fail(reason: u8) -> Parsed {
    Fail { reason, retry: false }
}

/// Greeting: offer no-auth only, or no-auth + user/pass (as x/net/proxy, which wispurr uses).
pub fn socks_greeting(auth: bool) -> &'static [u8] {
    if auth {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    }
}

/// Method selection reply (VER METHOD). `auth`: we offered user/pass.
pub fn socks_method(b: &[u8], auth: bool) -> Parsed {
    if b.len() < 2 {
        return Need;
    }
    match (b[0], b[1]) {
        (5, 0) => Done { len: 2, val: 0 },
        (5, 2) if auth => Done { len: 2, val: 2 },
        _ => fail(CLOSE_NETWORK), // FF (no acceptable method), a method we did not offer, or not SOCKS5
    }
}

/// RFC 1929 status reply (VER STATUS); VER is 1 (some servers send 5: accepted, as curl does)
pub fn socks_auth_reply(b: &[u8]) -> Parsed {
    if b.len() < 2 {
        return Need;
    }
    if (b[0] == 1 || b[0] == 5) && b[1] == 0 {
        Done { len: 2, val: 0 }
    } else {
        fail(CLOSE_NETWORK)
    }
}

/// The SOCKS target: an address, or a name (socks5h with --upstream-trust-dns)
pub enum Dest<'a> {
    Ip(IpAddr),
    Name(&'a str),
}

/// CONNECT request (VER CMD RSV ATYP DST.ADDR DST.PORT). Mapped IPv6 goes out as IPv4 (as Go's To4()).
pub fn socks_request(d: &Dest, port: u16) -> Vec<u8> {
    let mut m = vec![5, 1, 0];
    match d {
        Dest::Ip(ip) => match ip.to_canonical() {
            IpAddr::V4(a) => {
                m.push(1);
                m.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                m.push(4);
                m.extend_from_slice(&a.octets());
            }
        },
        Dest::Name(n) => {
            m.push(3);
            m.push(n.len() as u8); // n.len() <= 255: MAX_HOST, checked at CONNECT
            m.extend_from_slice(n.as_bytes());
        }
    }
    m.extend_from_slice(&port.to_be_bytes());
    m
}

/// The ATYP 3 name for socks5h (60.32 #9). Names go absolute (`name.`, 60.18 #16: the proxy's resolver applies no search
/// list) except RFC 7686 special-use `.onion` names (any case): they never touch DNS, and Tor refuses the absolute form
/// (`x.onion.`: SOCKS REP 04, 40.01 "Tor upstream"). `host` has no trailing dot (new_target removed one).
pub fn proxy_name(mut host: String) -> String {
    let n = host.len();
    if !(n > 6 && host.as_bytes()[n - 6..].eq_ignore_ascii_case(b".onion")) {
        host.push('.');
    }
    host
}

/// SOCKS REP -> Wisp CLOSE (60.27 table; differences to wispurr marked there). retry = target-side.
pub fn socks_rep(rep: u8) -> (u8, bool) {
    match rep {
        0x02 => (CLOSE_BLOCKED, false),
        0x03 | 0x04 => (CLOSE_UNREACHABLE, true),
        0x05 => (CLOSE_REFUSED, true),
        0x06 => (CLOSE_TIMEOUT, true),
        _ => (CLOSE_NETWORK, false), // 01 general, 07 command, 08 address type, unknown
    }
}

/// CONNECT reply (VER REP RSV ATYP BND.ADDR BND.PORT), read to its exact length
pub fn socks_reply(b: &[u8]) -> Parsed {
    if b.len() < 2 {
        return Need;
    }
    if b[0] != 5 {
        return fail(CLOSE_NETWORK);
    }
    if b[1] != 0 {
        let (reason, retry) = socks_rep(b[1]);
        return Fail { reason, retry };
    }
    if b.len() < 5 {
        return Need;
    }
    if b[2] != 0 {
        return fail(CLOSE_NETWORK); // RSV must be 0 (as x/net)
    }
    let len = match b[3] {
        1 => 4 + 4 + 2,
        4 => 4 + 16 + 2,
        3 => 4 + 1 + b[4] as usize + 2,
        _ => return fail(CLOSE_NETWORK),
    };
    if b.len() < len {
        Need
    } else {
        Done { len, val: 0 }
    }
}

/// HTTP CONNECT request for an address (local DNS: we only ever send IP literals in the authority)
pub fn http_request(ip: IpAddr, port: u16, auth: Option<&str>) -> Vec<u8> {
    let a = match ip.to_canonical() {
        IpAddr::V4(v) => format!("{v}:{port}"),
        IpAddr::V6(v) => format!("[{v}]:{port}"),
    };
    format!("CONNECT {a} HTTP/1.1\r\nHost: {a}\r\n{}\r\n", auth.unwrap_or("")).into_bytes()
}

/// HTTP status -> Wisp CLOSE for a non-2xx answer (60.27 table). retry = the proxy could not reach this address.
pub fn http_status(code: u16) -> (u8, bool) {
    match code {
        403 => (CLOSE_BLOCKED, false),
        500 | 502 | 503 => (CLOSE_NETWORK, true), // 60.27 probe: tinyproxy 500, squid 503 for a refused / unknown target
        504 => (CLOSE_TIMEOUT, true),
        _ => (CLOSE_NETWORK, false), // 407 / 401 (tinyproxy: bad credentials), 400, 405, other 5xx, 1xx/3xx
    }
}

/// The response head: Done at the end of the header section (2xx: the tunnel starts right after it; RFC 9110 9.3.6:
/// a client MUST ignore Content-Length / Transfer-Encoding in a 2xx CONNECT answer). Fail on a non-2xx code or junk.
pub fn http_reply(b: &[u8]) -> Parsed {
    let mut hs = [httparse::EMPTY_HEADER; 64];
    let mut r = httparse::Response::new(&mut hs);
    match r.parse(b) {
        Ok(httparse::Status::Complete(len)) => match r.code {
            Some(c) if (200..300).contains(&c) => Done { len, val: 0 },
            Some(c) => {
                let (reason, retry) = http_status(c);
                Fail { reason, retry }
            }
            None => fail(CLOSE_NETWORK),
        },
        Ok(httparse::Status::Partial) if b.len() < HTTP_HEAD_MAX => Need,
        _ => fail(CLOSE_NETWORK), // malformed, more than 64 headers, or no end within HTTP_HEAD_MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("socks5://127.0.0.1:9050").unwrap();
        assert!(u.kind == Kind::Socks5 && !u.remote_dns && u.port == 9050 && u.socks_auth.is_none());
        let u = parse_url("SOCKS5H://user:p%40ss@[::1]").unwrap();
        assert!(u.remote_dns && u.port == 1080 && u.host == "::1");
        assert_eq!(u.socks_auth.unwrap(), b"\x01\x04user\x04p@ss");
        assert_eq!(u.shown, "socks5h://***@[::1]:1080");
        let u = parse_url("http://a:b@proxy.lan").unwrap();
        assert_eq!(u.http_auth.as_deref(), Some("Proxy-Authorization: Basic YTpi\r\n"));
        assert_eq!(u.port, 80);
        assert!(parse_url("https://h").unwrap_err().contains("not supported"));
        for bad in [
            "socks5://::1:1080",
            "socks5://::1",
            "https://u:p@h",
            "ftp://h",
            "http://h:3128/",
            "http://h:0",
            "http://:p@h",
            "http://h?x",
            "socks5://u:%zz@h",
            "http://[::1",
            "http://[x]:1",
            "noscheme",
        ] {
            let e = parse_url(bad).unwrap_err();
            assert!(!e.contains("%zz") && !e.contains(":p@"), "{e}");
        }
        assert!(check_trust(Some(true), false).is_err() && check_trust(Some(false), true).is_err());
        assert!(check_trust(None, true).is_err() && check_trust(Some(true), true).is_ok() && check_trust(None, false).is_ok());
    }

    #[test]
    fn socks_parsers() {
        assert_eq!(socks_method(&[5], true), Need);
        assert_eq!(socks_method(&[5, 2], true), Done { len: 2, val: 2 });
        assert_eq!(socks_method(&[5, 2], false), fail(CLOSE_NETWORK));
        assert_eq!(socks_method(&[5, 0xff], true), fail(CLOSE_NETWORK));
        assert_eq!(socks_auth_reply(&[1, 0, 9, 9]), Done { len: 2, val: 0 });
        assert_eq!(socks_auth_reply(&[1, 1]), fail(CLOSE_NETWORK));
        let ok4 = [5, 0, 0, 1, 1, 2, 3, 4, 0, 80, b'b', b'a', b'n'];
        assert_eq!(socks_reply(&ok4[..9]), Need);
        assert_eq!(socks_reply(&ok4), Done { len: 10, val: 0 }); // banner bytes not consumed
        let ok3 = [5, 0, 0, 3, 3, b'a', b'b', b'c', 0, 1];
        assert_eq!(socks_reply(&ok3), Done { len: 10, val: 0 });
        assert_eq!(socks_reply(&[5, 4]), Fail { reason: CLOSE_UNREACHABLE, retry: true });
        assert_eq!(socks_reply(&[5, 2]), Fail { reason: CLOSE_BLOCKED, retry: false });
        assert_eq!(socks_reply(&[5, 0, 0, 9, 0]), fail(CLOSE_NETWORK));
        assert_eq!(socks_reply(&[4, 0]), fail(CLOSE_NETWORK));
        assert_eq!(socks_reply(&[5, 0, 1, 1, 1, 2, 3, 4, 0, 80]), fail(CLOSE_NETWORK), "RSV != 0");
        assert_eq!(socks_request(&Dest::Ip("::ffff:1.2.3.4".parse().unwrap()), 443), [5, 1, 0, 1, 1, 2, 3, 4, 1, 187]);
        assert_eq!(socks_request(&Dest::Name("ab"), 1), [5, 1, 0, 3, 2, b'a', b'b', 0, 1]);
        // 60.32 #9: absolute names, except RFC 7686 .onion (Tor refuses `x.onion.`)
        let req = |h: &str| socks_request(&Dest::Name(&proxy_name(h.into())), 80);
        assert_eq!(req("x.onion"), [&[5, 1, 0, 3, 7][..], b"x.onion", &[0, 80]].concat());
        assert_eq!(req("EXAMPLE.ONION"), [&[5, 1, 0, 3, 13][..], b"EXAMPLE.ONION", &[0, 80]].concat());
        assert_eq!(req("example.com"), [&[5, 1, 0, 3, 12][..], b"example.com.", &[0, 80]].concat());
        for (h, want) in [
            ("onion", "onion."),
            (".onion", ".onion."),
            ("notonion", "notonion."),
            ("onion.example.com", "onion.example.com."),
            ("a.onion.example", "a.onion.example."),
        ] {
            assert_eq!(proxy_name(h.into()), want, "{h}");
        }
    }

    #[test]
    fn http_parsers() {
        assert_eq!(http_reply(b"HTTP/1.1 200 Connection established\r\n"), Need);
        assert_eq!(http_reply(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nBANNER"), Done { len: 25, val: 0 });
        assert_eq!(http_reply(b"HTTP/1.0 204 x\r\nContent-Length: 5\r\n\r\n"), Done { len: 37, val: 0 });
        assert_eq!(http_reply(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"), fail(CLOSE_NETWORK));
        assert_eq!(http_reply(b"HTTP/1.1 403 Forbidden\r\n\r\n"), fail(CLOSE_BLOCKED));
        assert_eq!(http_reply(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n"), Fail { reason: CLOSE_TIMEOUT, retry: true });
        assert_eq!(http_reply(b"SSH-2.0-x\r\n"), fail(CLOSE_NETWORK));
        let big = [b"HTTP/1.1 200 OK\r\n".as_slice(), &vec![b'a'; HTTP_HEAD_MAX]].concat();
        assert_eq!(http_reply(&big), fail(CLOSE_NETWORK));
        assert_eq!(
            http_request("2001:db8::1".parse().unwrap(), 443, Some("Proxy-Authorization: Basic YTpi\r\n")),
            b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\nProxy-Authorization: Basic YTpi\r\n\r\n"
        );
    }

    #[test]
    fn proxy_addrs_refresh() {
        // 60.27 Q-C: a new generation only on a change; a failed or empty refresh keeps the last good list
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let pa = ProxyAddrs::new(vec![a("10.0.0.1")]);
        let g0 = pa.gen();
        pa.publish(Ok(vec![a("10.0.0.1")]), 5);
        assert_eq!((pa.gen(), pa.ok_at_ms.load(Relaxed)), (g0, 5));
        pa.publish(Err("no address".into()), 6);
        pa.publish(Ok(Vec::new()), 7);
        assert_eq!((pa.gen(), pa.snapshot().1.to_vec(), pa.fails.load(Relaxed)), (g0, vec![a("10.0.0.1")], 2));
        pa.publish(Ok(vec![a("10.0.0.2"), a("::2")]), 8);
        let (g, l) = pa.snapshot();
        assert!(g != g0 && *l == vec![a("10.0.0.2"), a("::2")] && pa.gen() == g);
        // resolve: a literal as is; a name's addresses deduplicated and interleaved
        assert_eq!(resolve("::1", 1).unwrap(), vec![a("::1")]);
        let l = resolve("localhost", 1080).unwrap();
        assert!(!l.is_empty() && l.iter().all(|i| i.is_loopback()));
        assert!(resolve("no-such-host.invalid", 1).is_err());
    }
}
