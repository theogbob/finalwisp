//! 60.59 runtime hints about the proxy chain.
//! The server cannot know at startup what stands in front of it; some wrong setups show in the requests. Each hint is
//! one warn-level log line at the first occurrence, then at most one per HINT_EVERY_MS (a and b: with the number of
//! requests since), plus a counter. A hint never changes what the server does, does not depend on --log-conns, and says what to
//! check and how to fix it: it is not a diagnosis (each has a harmless look-alike, named in its text).
//! Where they run: only when the server keeps peer addresses for the client-address logic (Config::clientip: a per-IP
//! limit, --conn-share, --trusted-proxy or --listen-unix), on control paths (once per connection at the HTTP upgrade,
//! the idle sweep).
//! A plain `finalwisp` has no such state and runs none of this code.
use crate::clientip::{IpKey, IpTable};
use crate::metrics::Stats;
use crate::net::Inbox;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;

/// at most one line per hint in this time, after the first
pub const HINT_EVERY_MS: u64 = 3_600_000;
/// hint (c): fewer connections than this on one key are not worth a line (a test rig, one busy user)
pub const ONE_KEY_MIN: u32 = 64;
/// the headers a reverse proxy or CDN uses to name the client (lowercase)
const FWD_HEADERS: [&str; 4] = ["x-forwarded-for", "forwarded", "x-real-ip", "cf-connecting-ip"];

/// The rate limit of one hint, shared by the workers: `next` = metrics::now_ms from which a line may go (0: at once),
/// `since` = occurrences since the last line.
pub struct Hint {
    next: AtomicU64,
    since: AtomicU64,
}

impl Hint {
    pub const fn new() -> Hint {
        Hint { next: AtomicU64::new(0), since: AtomicU64::new(0) }
    }

    /// Count one occurrence. Some(n) = log a line now, for n occurrences since the last one (this one included).
    /// One compare-exchange decides which worker logs; a loser's occurrence is counted for the next line.
    pub fn due(&self, now_ms: u64, every_ms: u64) -> Option<u64> {
        self.since.fetch_add(1, Relaxed);
        let next = self.next.load(Relaxed);
        if now_ms < next || self.next.compare_exchange(next, now_ms.max(1) + every_ms, Relaxed, Relaxed).is_err() {
            return None;
        }
        Some(self.since.swap(0, Relaxed).max(1))
    }

    /// `counted`: the line names the occurrences since the last one (requests). Hint (c) passes false: its occurrences
    /// are sightings by every worker's sweep of one lasting state, not events (review).
    fn log(&self, counted: bool, line: impl FnOnce() -> String) {
        if !crate::logs::on(crate::logs::Level::Warn) {
            return; // (not counted towards a later line: nothing is ever printed below warn)
        }
        if let Some(n) = self.due(crate::metrics::now_ms(), HINT_EVERY_MS) {
            let more = if counted && n > 1 { format!(" ({n} times since the last such line)") } else { String::new() };
            crate::metrics::log_nowait(format!("finalwisp: hint: {}{more}", line()));
            // never blocks a worker
        }
    }
}

static FWD_UNTRUSTED: Hint = Hint::new();
static REALIP_MISSING: Hint = Hint::new();
static ONE_KEY: Hint = Hint::new();

/// A loopback or private address: where a reverse proxy, a container bridge or a NAT gateway on our side lives. A
/// client on the public internet never has one (IPv4: loopback, RFC 1918, link-local, 100.64/10; IPv6: ::1, unique
/// local, link-local; an IPv4-mapped address counts as IPv4).
pub fn local(ip: IpAddr) -> bool {
    match crate::clientip::canon(ip) {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_loopback() || a.is_private() || a.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(a) => {
            let s = a.segments()[0];
            a.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

/// The first forwarding header of an HTTP request head (`extra`: the --real-ip-header name, lowercase). The request
/// was already accepted by the HTTP parser, so its header lines are `Name: value`.
fn fwd_header<'a>(req: &[u8], extra: &'a str) -> Option<&'a str> {
    req.split(|&b| b == b'\n').skip(1).find_map(|line| {
        let name = &line[..line.iter().position(|&b| b == b':')?];
        FWD_HEADERS.iter().copied().chain([extra]).find(|h| name.eq_ignore_ascii_case(h.as_bytes()))
    })
}

/// Hint (a), at the HTTP upgrade of a peer that is not a trusted proxy and has a loopback or private address (the
/// caller checked both): if the request carries a forwarding header, this peer is probably a reverse proxy that
/// --trusted-proxy does not list, and every user behind it shares one address. Look-alike: a direct client on a
/// private network that sends such a header itself. `req`: the request head as parsed.
#[cold]
#[inline(never)]
pub fn fwd_untrusted(peer: IpAddr, req: &[u8], real_ip_header: &str, stats: &Stats) {
    let Some(name) = fwd_header(req, real_ip_header) else { return };
    stats.hint_fwd_untrusted.bump();
    FWD_UNTRUSTED.log(true, || fwd_untrusted_text(peer, name));
}

fn fwd_untrusted_text(peer: IpAddr, name: &str) -> String {
    format!(
        "a request from {peer} carries the header {name}, but {peer} is not a trusted proxy: the header is ignored and \
         every client behind {peer} counts as one address. If {peer} is your reverse proxy, start finalwisp with \
         --trusted-proxy {peer} and make the proxy set the header itself (nginx: proxy_set_header X-Forwarded-For \
         $proxy_add_x_forwarded_for). If it is a client of its own, ignore this line."
    )
}

/// Hint (b), next to the realip_missing counter: a trusted proxy sent a request without the client-address header, so
/// that connection has no client address and no per-address limit. Look-alike: a health check or a tool on the proxy's
/// host.
#[cold]
#[inline(never)]
pub fn realip_missing(proxy: IpAddr, header: &str) {
    REALIP_MISSING.log(true, || realip_missing_text(proxy, header));
}

fn realip_missing_text(proxy: IpAddr, header: &str) -> String {
    let who =
        if proxy == crate::clientip::UNIX_PEER { "the proxy on the unix socket".to_string() } else { format!("the trusted proxy {proxy}") };
    format!(
        "{who} sent a request without the header {header}: the client's address is unknown, so that connection is not \
         limited per address. Make the proxy set the header on every request (nginx: proxy_set_header X-Forwarded-For \
         $proxy_add_x_forwarded_for; Caddy sets it by default). A health check from the proxy's host looks the same."
    )
}

fn key_text(k: IpKey) -> (IpAddr, String) {
    if k == crate::clientip::key(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)) {
        // an IPv6 key is the /64, so ::1 is stored as ::, which no address class knows (review)
        return (IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), "::1".to_string());
    }
    match crate::clientip::canon(IpAddr::V6(std::net::Ipv6Addr::from(k))) {
        ip @ IpAddr::V4(_) => (ip, ip.to_string()),
        ip => (ip, format!("{ip}/64")),
    }
}

/// Hint (c), from the idle sweep of the per-address table (`shard`: the one just swept): one loopback or private
/// address holds at least ONE_KEY_MIN connections and more than half of all. A proxy, a NAT or a container port
/// forward in front of many users looks like this and gives no other sign (no header); so does one busy local client.
/// Costs one more pass over the shard's entries per sweep; only where the table exists.
pub fn one_key(t: &IpTable, shard: usize, peers: &[Arc<Inbox>], stats: &Stats) {
    let Some((k, n)) = t.top_conns(shard).filter(|&(_, n)| n >= ONE_KEY_MIN) else { return };
    let (ip, shown) = key_text(k);
    let total: usize = peers.iter().map(|p| p.load.load(Relaxed)).sum();
    if !local(ip) || !one_key_most(n, total) {
        return;
    }
    stats.one_key_conns_max.max(n as u64);
    ONE_KEY.log(false, || one_key_text(&shown, n, total));
}

fn one_key_most(n: u32, total: usize) -> bool {
    n >= ONE_KEY_MIN && (n as usize).saturating_mul(2) > total
}

fn one_key_text(shown: &str, n: u32, total: usize) -> String {
    format!(
        "{n} of {total} connections come from {shown}, a loopback or private address. Is a reverse proxy, a NAT or a \
         container port forward in front of this server? Then all its users share one address here: set --trusted-proxy \
         and the proxy's client-address header, or --proxy-protocol behind a TCP load balancer (a Docker published port \
         passes IPv6 clients as the bridge address). If it is one local client, ignore this line."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_at_once_then_rate_limited_with_the_count() {
        let h = Hint::new();
        assert_eq!(h.due(0, 1000), Some(1), "the first occurrence, also at time 0");
        assert_eq!(h.due(5, 1000), None);
        assert_eq!(h.due(999, 1000), None);
        assert_eq!(h.due(1001, 1000), Some(3), "the two not logged and this one");
        assert_eq!(h.due(1500, 1000), None);
        assert_eq!(h.due(9000, 1000), Some(2));
        // many threads at once: exactly one line per window, every occurrence counted once
        let h = Arc::new(Hint::new());
        let got: u64 = (0..8)
            .map(|_| {
                let h = h.clone();
                std::thread::spawn(move || (0..1000).filter_map(|_| h.due(50, 1000)).sum::<u64>())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .sum();
        assert_eq!(got + h.due(1100, 1000).unwrap(), 8001);
    }

    #[test]
    fn local_addresses() {
        for a in ["127.0.0.1", "127.9.9.9", "10.1.2.3", "172.17.0.1", "172.31.255.255", "192.168.1.1", "169.254.1.1", "100.64.0.1"] {
            assert!(local(a.parse().unwrap()), "{a}");
        }
        for a in ["::1", "fd00::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1"] {
            assert!(local(a.parse().unwrap()), "{a}");
        }
        for a in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "198.51.100.7", "2001:db8::1", "2a03:d9c2::a", "::ffff:8.8.8.8", "100::", "::"] {
            assert!(!local(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn forwarding_headers() {
        let req = |h: &str| format!("GET / HTTP/1.1\r\nHost: x\r\n{h}Upgrade: websocket\r\n\r\n").into_bytes();
        let f = |h: &str| fwd_header(&req(h), "x-forwarded-for").map(str::to_string);
        assert_eq!(f(""), None);
        assert_eq!(f("X-Forwarded-For: 1.2.3.4\r\n").as_deref(), Some("x-forwarded-for"));
        assert_eq!(f("x-real-ip: 1.2.3.4\r\n").as_deref(), Some("x-real-ip"));
        assert_eq!(f("FORWARDED: for=1.2.3.4\r\n").as_deref(), Some("forwarded"));
        assert_eq!(f("CF-Connecting-IP: 1.2.3.4\r\n").as_deref(), Some("cf-connecting-ip"));
        assert_eq!(f("X-Forwarded-Host: a\r\nX-Forwarded-Proto: https\r\n"), None, "not a client address");
        assert_eq!(f("Cookie: x-forwarded-for: 1.2.3.4\r\n"), None, "only a header name counts");
        assert_eq!(fwd_header(&req("True-Client-IP: 1.2.3.4\r\n"), "true-client-ip"), Some("true-client-ip"), "--real-ip-header");
        assert_eq!(fwd_header(b"GET /?x-real-ip: HTTP/1.1\r\n\r\n", "x-forwarded-for"), None, "the request line is skipped");
        assert_eq!(fwd_header(b"", "x-forwarded-for"), None);
    }

    #[test]
    fn one_key_needs_a_local_key_with_most_connections() {
        let run = |ip: &str, conns: u32, total: usize| {
            let (t, stats, inbox) = (IpTable::new(None), Stats::new(), Inbox::new());
            let k = crate::clientip::key(ip.parse().unwrap());
            for _ in 0..conns {
                assert_eq!(t.charge(k, 0, 0), crate::clientip::Charge::Charged);
            }
            // a second, smaller key in the same table
            assert_eq!(t.charge(crate::clientip::key("8.8.4.4".parse().unwrap()), 0, 0), crate::clientip::Charge::Charged);
            inbox.load.store(total, Relaxed);
            for shard in 0..crate::clientip::SHARDS {
                one_key(&t, shard, std::slice::from_ref(&inbox), &stats);
            }
            assert_eq!(t.conns(k), conns, "read only");
            unsafe { libc::close(inbox.efd) };
            stats.one_key_conns_max.get()
        };
        assert_eq!(run("172.17.0.1", 70, 100), 70, "a Docker bridge address with 70 of 100");
        assert_eq!(run("127.0.0.1", 64, 64), 64);
        assert_eq!(run("fd00::7", 200, 300), 200);
        assert_eq!(run("::1", 70, 70), 70, "IPv6 loopback: its key is the /64 of ::1");
        assert_eq!(key_text(crate::clientip::key("::1".parse().unwrap())).1, "::1");
        assert_eq!(key_text(crate::clientip::key("fd00::7".parse().unwrap())).1, "fd00::/64");
        assert_eq!(key_text(crate::clientip::key("::ffff:10.0.0.1".parse().unwrap())).1, "10.0.0.1");
        assert_eq!(run("172.17.0.1", 70, 140), 0, "exactly half is not most");
        assert_eq!(run("172.17.0.1", 63, 63), 0, "below the floor");
        assert_eq!(run("203.0.113.9", 500, 500), 0, "a public address (a school, a carrier NAT): no hint");
    }

    #[test]
    fn one_key_rule_and_texts() {
        assert!(!one_key_most(63, 63) && one_key_most(64, 64) && one_key_most(64, 127) && !one_key_most(64, 128));
        assert!(one_key_most(1000, 0), "the load counters can lag: never a panic or a wrong no");
        assert_eq!(key_text(crate::clientip::key("172.17.0.1".parse().unwrap())).1, "172.17.0.1");
        assert_eq!(key_text(crate::clientip::key("fd00:1:2:3:4::9".parse().unwrap())).1, "fd00:1:2:3::/64");
        // the texts name the fix, and hold no character that the config error check reserves for hidden values
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let a = fwd_untrusted_text(lo, "x-forwarded-for");
        assert!(a.contains("--trusted-proxy 127.0.0.1") && a.contains("proxy_set_header X-Forwarded-For"), "{a}");
        let b = realip_missing_text(lo, "x-forwarded-for");
        assert!(b.starts_with("the trusted proxy 127.0.0.1 sent a request without the header x-forwarded-for"), "{b}");
        assert!(realip_missing_text(crate::clientip::UNIX_PEER, "x-real-ip").starts_with("the proxy on the unix socket sent"));
        let c = one_key_text("172.17.0.1", 300, 310);
        assert!(
            c.starts_with("300 of 310 connections come from 172.17.0.1,")
                && c.contains("--trusted-proxy")
                && c.contains("--proxy-protocol")
        );
    }
}
