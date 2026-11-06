//! 60.20 C1 destination policy (design: 60.02 C1; decisions and the as-built spec: 60.21). Two stages:
//! - request rules (`Policy::allows`), on the CONNECT before DNS: ports, direct IP, host names (suffix match, no regex);
//! - address rules on every resolved address (`net::Filter::allowed`, at both filter sites), incl. the CIDR lists here.
//!
//! Everything is built once at startup and read-only after that (shared by the workers, no locks).
use std::collections::HashSet;
use std::net::IpAddr;

/// --block-smtp (60.02 Q3): the mail submission / relay ports, TCP only.
pub const SMTP_PORTS: [u16; 3] = [25, 465, 587];

/// Longest host a CONNECT may name (no DNS name is longer; also the stack buffer of `Policy::allows`).
pub const MAX_HOST: usize = 255;

/// Validation (0x41, before any rule): a host that is empty, too long, or holds a NUL, a control character, a space or
/// DEL is malformed, not a name (getaddrinfo would cut it at a NUL or reject it anyway). Non-ASCII passes (DNS fails it).
pub fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= MAX_HOST && h.bytes().all(|b| b > b' ' && b != 0x7f)
}

/// An IP literal for --no-direct-ip: what `IpAddr` parses, or a name whose last label is numeric (all digits, or 0x +
/// hex digits: the WHATWG URL rule), or anything with a colon (IPv6, incl. the scoped `ADDR%scope` form getaddrinfo takes). That catches the inet_aton forms getaddrinfo turns into addresses (`127.1`,
/// `2130706433`, `0x7f000001`, `0177.0.0.1`); no DNS name has a numeric top-level label.
pub fn is_ip_literal(h: &str) -> bool {
    if h.contains(':') || h.parse::<IpAddr>().is_ok() {
        return true; // review: no DNS name has a colon; glibc resolves `ADDR%scope` (`::1%1`, `fe80::1%eth0`) numerically
    }
    let h = h.strip_suffix('.').unwrap_or(h);
    let last = h.rsplit('.').next().unwrap_or("");
    let hex = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X"));
    match hex {
        Some(x) => x.bytes().all(|b| b.is_ascii_hexdigit()),
        None => !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()),
    }
}

/// A --allow-dest / --block-dest entry: `10.0.0.0/8`, `2001:db8::/32`, or a bare IP (/32, /128). IPv4 is kept as its
/// IPv4-mapped IPv6 form, so a mapped address (`::ffff:10.1.2.3`) matches the IPv4 rules. Host bits are cleared
/// (`10.1.2.3/8` = `10.0.0.0/8`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Cidr {
    net: u128,
    len: u8,
}

fn key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u128::from(a.to_ipv6_mapped()),
        IpAddr::V6(a) => u128::from(a),
    }
}

fn mask(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        !0u128 << (128 - len as u32)
    }
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, len) = match s.split_once('/') {
            Some((ip, l)) => (ip.parse::<IpAddr>().ok()?, Some(l.parse::<u8>().ok()?)),
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let len = match (ip, len) {
            (IpAddr::V4(_), Some(l)) if l <= 32 => l + 96,
            (IpAddr::V6(_), Some(l)) if l <= 128 => l,
            (_, Some(_)) => return None,
            (_, None) => 128,
        };
        Some(Cidr { net: key(ip) & mask(len), len })
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        key(ip) & mask(self.len) == self.net
    }
}

/// A --allow-ports / --block-ports entry: `N` or `N-M` (1..65535), optionally `tcp:` or `udp:` (else both).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PortRule {
    pub tcp: bool,
    pub udp: bool,
    pub lo: u16,
    pub hi: u16,
}

impl PortRule {
    pub fn parse(s: &str) -> Option<PortRule> {
        let (tcp, udp, r) = match s.split_once(':') {
            Some(("tcp", r)) => (true, false, r),
            Some(("udp", r)) => (false, true, r),
            Some(_) => return None,
            None => (true, true, s),
        };
        let (lo, hi) = match r.split_once('-') {
            Some((a, b)) => (a.parse::<u16>().ok()?, b.parse::<u16>().ok()?),
            None => {
                let p = r.parse::<u16>().ok()?;
                (p, p)
            }
        };
        (lo != 0 && lo <= hi).then_some(PortRule { tcp, udp, lo, hi })
    }
}

/// A --allow-host / --block-host entry, normalized: ASCII lowercase, one trailing dot removed. It matches the name and
/// every name below it (`example.com`: `a.b.example.com`, not `notexample.com`). Names as clients send them: ASCII, IDN
/// as punycode (`xn--...`); IP literals belong in --allow-dest / --block-dest (address rules).
pub fn host_entry(s: &str) -> Result<String, &'static str> {
    let t = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
    if t.parse::<IpAddr>().is_ok() || is_ip_literal(&t) {
        return Err("an IP address: use --allow-dest / --block-dest");
    }
    if t.starts_with("*.") {
        return Err("no wildcards: an entry already matches every name below it");
    }
    if t.is_empty() || t.len() > MAX_HOST || t.split('.').any(|l| l.is_empty()) {
        return Err("not a host name");
    }
    if !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
        return Err("not a host name (letters, digits, '-', '_' and '.'; IDN as punycode xn--)");
    }
    Ok(t)
}

/// The --config / command-line form of the rules (cli::Opts), before folding. Default = no rule (review: a derived
/// Default would mean --no-direct-ip --no-ipv6-targets).
#[derive(Clone, Debug, PartialEq)]
pub struct Rules {
    pub allow_hosts: Vec<String>,
    pub block_hosts: Vec<String>,
    pub allow_ports: Vec<PortRule>,
    pub block_ports: Vec<PortRule>,
    pub block_smtp: bool,
    pub direct_ip: bool,
    pub ipv6: bool,
}

impl Default for Rules {
    fn default() -> Rules {
        Rules {
            allow_hosts: Vec::new(),
            block_hosts: Vec::new(),
            allow_ports: Vec::new(),
            block_ports: Vec::new(),
            block_smtp: false,
            direct_ip: true,
            ipv6: true,
        }
    }
}

/// The request rules, folded for the CONNECT path.
pub struct Policy {
    /// blocked ports, one bit each: [tcp, udp] (allow and block lists folded at startup; block wins)
    ports: [Box<[u64; 1024]>; 2],
    allow_hosts: HashSet<Box<str>>,
    block_hosts: HashSet<Box<str>>,
    direct_ip: bool,
    ipv6: bool,
    pub summary: String,
}

fn set_bits(map: &mut [u64; 1024], lo: u16, hi: u16, on: bool) {
    for p in lo..=hi {
        let (w, b) = (p as usize / 64, p % 64);
        if on {
            map[w] |= 1 << b;
        } else {
            map[w] &= !(1 << b);
        }
    }
}

/// Any suffix of `name` at a label boundary (incl. the whole name) in `set`: O(labels) lookups.
fn any_suffix(set: &HashSet<Box<str>>, name: &str) -> bool {
    let mut s = name;
    loop {
        if set.contains(s) {
            return true;
        }
        match s.find('.') {
            Some(i) => s = &s[i + 1..],
            None => return false,
        }
    }
}

impl Policy {
    /// None when no request rule is set (the CONNECT path then pays one Option test).
    pub fn new(r: &Rules) -> Option<Policy> {
        if *r == Rules::default() {
            return None;
        }
        let mut ports = [Box::new([0u64; 1024]), Box::new([0u64; 1024])];
        for (i, map) in ports.iter_mut().enumerate() {
            let mine = |p: &&PortRule| if i == 0 { p.tcp } else { p.udp };
            if r.allow_ports.iter().any(|p| mine(&p)) {
                set_bits(map, 0, u16::MAX, true); // an allow list: everything else is refused
                for p in r.allow_ports.iter().filter(mine) {
                    set_bits(map, p.lo, p.hi, false);
                }
            }
            for p in r.block_ports.iter().filter(mine) {
                set_bits(map, p.lo, p.hi, true);
            }
            if i == 0 && r.block_smtp {
                for p in SMTP_PORTS {
                    set_bits(map, p, p, true);
                }
            }
        }
        let set = |v: &[String]| v.iter().map(|h| h.as_str().into()).collect::<HashSet<Box<str>>>();
        let mut s = Vec::new();
        if !r.allow_hosts.is_empty() || !r.block_hosts.is_empty() {
            s.push(format!("hosts +{} -{}", r.allow_hosts.len(), r.block_hosts.len()));
        }
        if !r.allow_ports.is_empty() || !r.block_ports.is_empty() {
            s.push(format!("ports +{} -{}", r.allow_ports.len(), r.block_ports.len()));
        }
        for (on, what) in [(r.block_smtp, "no smtp"), (!r.direct_ip, "no direct IP"), (!r.ipv6, "no IPv6 targets")] {
            if on {
                s.push(what.to_string());
            }
        }
        Some(Policy {
            ports,
            allow_hosts: set(&r.allow_hosts),
            block_hosts: set(&r.block_hosts),
            direct_ip: r.direct_ip,
            ipv6: r.ipv6,
            summary: s.join(", "),
        })
    }

    #[inline]
    pub fn port_blocked(&self, udp: bool, port: u16) -> bool {
        self.ports[udp as usize][port as usize / 64] & (1 << (port % 64)) != 0
    }

    /// The request rules for one CONNECT (a host that passed `valid_host`): false = refuse with 0x48. Order: ports,
    /// direct IP (an IP literal skips the name rules: the address rules judge it), names (block wins; a non-empty allow
    /// list refuses every other name). Before DNS: a refused name is never looked up or cached.
    pub fn allows(&self, udp: bool, host: &str, port: u16) -> bool {
        if self.port_blocked(udp, port) {
            return false;
        }
        if is_ip_literal(host) {
            // a scoped literal counts as v6; an IPv4-mapped one as v4
            let v6 = host.contains(':')
                && !matches!(host.split('%').next().unwrap_or("").parse::<IpAddr>(), Ok(IpAddr::V6(a)) if a.to_ipv4_mapped().is_some());
            return self.direct_ip && (self.ipv6 || !v6);
        }
        if self.allow_hosts.is_empty() && self.block_hosts.is_empty() {
            return true;
        }
        let mut buf = [0u8; MAX_HOST];
        let b = host.as_bytes();
        let b = b.strip_suffix(b".").unwrap_or(b);
        let n = b.len().min(MAX_HOST);
        for (d, s) in buf.iter_mut().zip(&b[..n]) {
            *d = s.to_ascii_lowercase();
        }
        let Ok(name) = std::str::from_utf8(&buf[..n]) else { return false }; // (ASCII lowercase keeps UTF-8 valid)
        if any_suffix(&self.block_hosts, name) {
            return false;
        }
        self.allow_hosts.is_empty() || any_suffix(&self.allow_hosts, name)
    }

    /// 60.35 C4 --log-streams: the rule that refuses this CONNECT (`rule=` in the log line), None = allowed. Only the
    /// log path calls it; a mirror of `allows` (kept separate so the hot check stays as it is), equal to `!allows` by a
    /// unit test and the policy-host fuzz target.
    pub fn refusal(&self, udp: bool, host: &str, port: u16) -> Option<&'static str> {
        if self.port_blocked(udp, port) {
            return Some("ports");
        }
        if is_ip_literal(host) {
            let v6 = host.contains(':')
                && !matches!(host.split('%').next().unwrap_or("").parse::<IpAddr>(), Ok(IpAddr::V6(a)) if a.to_ipv4_mapped().is_some());
            return if !self.direct_ip {
                Some("direct_ip")
            } else if v6 && !self.ipv6 {
                Some("ipv6")
            } else {
                None
            };
        }
        if self.allow_hosts.is_empty() && self.block_hosts.is_empty() {
            return None;
        }
        let mut buf = [0u8; MAX_HOST];
        let b = host.as_bytes();
        let b = b.strip_suffix(b".").unwrap_or(b);
        let n = b.len().min(MAX_HOST);
        for (d, s) in buf.iter_mut().zip(&b[..n]) {
            *d = s.to_ascii_lowercase();
        }
        let Ok(name) = std::str::from_utf8(&buf[..n]) else { return Some("block_host") }; // (as allows)
        if any_suffix(&self.block_hosts, name) {
            return Some("block_host");
        }
        (!self.allow_hosts.is_empty() && !any_suffix(&self.allow_hosts, name)).then_some("allow_host")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        Rules { direct_ip: true, ipv6: true, ..Rules::default() }
    }
    fn hosts(v: &[&str]) -> Vec<String> {
        v.iter().map(|h| host_entry(h).unwrap()).collect()
    }

    /// 60.35 Policy::refusal is Some exactly when allows() is false (rules x hosts x ports x udp), and names the rule
    #[test]
    fn refusal_mirrors_allows() {
        let hostsv = [
            "example.com",
            "Example.COM.",
            "a.example.com",
            "evil.org",
            "x.y.evil.org",
            "intranet",
            "1.2.3.4",
            "127.1",
            "::1",
            "[::1]",
            "2001:db8::1",
            "::ffff:1.2.3.4",
            "fe80::1%eth0",
            "bücher.example",
            "xn--bcher-kva.example",
            "a.com.",
        ];
        let ports = [22u16, 25, 80, 443, 587, 8080, 65535];
        for bits in 0u32..64 {
            let b = |i: u32| bits & (1 << i) != 0;
            let r = Rules {
                direct_ip: !b(0),
                ipv6: !b(1),
                block_smtp: b(2),
                allow_hosts: if b(3) { hosts(&["example.com", "xn--bcher-kva.example"]) } else { vec![] },
                block_hosts: if b(4) { hosts(&["evil.org", "a.example.com"]) } else { vec![] },
                allow_ports: if b(5) { vec![PortRule::parse("tcp:443").unwrap(), PortRule::parse("80-8080").unwrap()] } else { vec![] },
                ..rules()
            };
            let Some(p) = Policy::new(&r) else { continue };
            for h in hostsv {
                for &port in &ports {
                    for udp in [false, true] {
                        let got = p.refusal(udp, h, port);
                        assert_eq!(got.is_some(), !p.allows(udp, h, port), "{h} {port} {udp} bits {bits:06b} {got:?}");
                    }
                }
            }
        }
        let p = Policy::new(&Rules { block_hosts: hosts(&["evil.org"]), direct_ip: false, block_smtp: true, ..rules() }).unwrap();
        assert_eq!(p.refusal(false, "a.evil.org", 443), Some("block_host"));
        assert_eq!(p.refusal(false, "1.2.3.4", 443), Some("direct_ip"));
        assert_eq!(p.refusal(false, "ok.org", 25), Some("ports"));
        assert_eq!(p.refusal(false, "ok.org", 443), None);
        let p = Policy::new(&Rules { allow_hosts: hosts(&["ok.org"]), ..rules() }).unwrap();
        assert_eq!(p.refusal(false, "other.org", 443), Some("allow_host"));
    }

    #[test]
    fn validation_and_literals() {
        assert!(valid_host("example.com") && valid_host("xn--bcher-kva.example") && valid_host("bücher.example"));
        for bad in ["", "a b", "a\0b", "a\tb", "a\x7fb", "a\nb"] {
            assert!(!valid_host(bad), "{bad:?}");
        }
        assert!(valid_host(&"a".repeat(255)) && !valid_host(&"a".repeat(256)));
        for lit in [
            "127.0.0.1",
            "127.1",
            "2130706433",
            "0x7f000001",
            "0X7F000001",
            "0177.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "1.2.3.4.",
            "a.0x",
            "::1%1",
            "fe80::1%eth0",
            "[::1]",
        ] {
            assert!(is_ip_literal(lit), "{lit}");
        }
        for name in ["example.com", "a1.b2", "1a.example", "0xg.example", "x.0xg", "example.com.", "localhost"] {
            assert!(!is_ip_literal(name), "{name}");
        }
    }

    #[test]
    fn entries_parse() {
        assert_eq!(host_entry("Example.COM."), Ok("example.com".into()));
        for bad in ["", ".", "a..b", "*.example.com", "10.0.0.1", "127.1", "::1", "a b", "bücher.example", "a/b", "a:b"] {
            assert!(host_entry(bad).is_err(), "{bad:?}");
        }
        assert_eq!(PortRule::parse("80"), Some(PortRule { tcp: true, udp: true, lo: 80, hi: 80 }));
        assert_eq!(PortRule::parse("udp:1000-2000"), Some(PortRule { tcp: false, udp: true, lo: 1000, hi: 2000 }));
        assert_eq!(PortRule::parse("tcp:1-65535"), Some(PortRule { tcp: true, udp: false, lo: 1, hi: 65535 }));
        for bad in ["0", "0-10", "10-5", "65536", "sctp:80", "tcp:", "x", "1-", "-1", "tcp:80:81"] {
            assert_eq!(PortRule::parse(bad), None, "{bad:?}");
        }
        let c = Cidr::parse("10.1.2.3/8").unwrap();
        assert_eq!(c, Cidr::parse("10.0.0.0/8").unwrap(), "host bits cleared");
        assert!(c.contains("10.200.0.1".parse().unwrap()) && !c.contains("11.0.0.1".parse().unwrap()));
        assert!(c.contains("::ffff:10.9.9.9".parse().unwrap()), "mapped counts as IPv4");
        let one = Cidr::parse("192.0.2.7").unwrap();
        assert!(one.contains("192.0.2.7".parse().unwrap()) && !one.contains("192.0.2.8".parse().unwrap()));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()) && !v6.contains("2001:db9::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        assert!(!Cidr::parse("0.0.0.0/0").unwrap().contains("2001:db8::1".parse().unwrap()), "v4 /0 is not all of v6");
        assert!(Cidr::parse("::/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        for bad in ["10.0.0.0/33", "::/129", "10.0.0.0/", "x/8", "10.0.0.0/-1", "example.com"] {
            assert_eq!(Cidr::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn no_rules_no_policy() {
        assert_eq!(Rules::default(), rules());
        assert!(Policy::new(&rules()).is_none());
        assert!(Policy::new(&Rules { block_smtp: true, ..rules() }).is_some());
        assert!(Policy::new(&Rules { ipv6: false, ..rules() }).is_some());
    }

    #[test]
    fn ports_fold_block_wins_and_per_protocol() {
        let p = Policy::new(&Rules {
            allow_ports: vec![PortRule::parse("tcp:80").unwrap(), PortRule::parse("tcp:400-500").unwrap()],
            block_ports: vec![PortRule::parse("450").unwrap()],
            block_smtp: true,
            ..rules()
        })
        .unwrap();
        assert!(p.allows(false, "example.com", 80) && p.allows(false, "example.com", 400) && p.allows(false, "e.x", 500));
        assert!(!p.allows(false, "example.com", 450), "block wins over allow");
        assert!(!p.allows(false, "example.com", 1000) && !p.allows(false, "e.x", 79), "a tcp allow list refuses other tcp ports");
        assert!(p.allows(true, "example.com", 1000), "udp has no allow list");
        assert!(!p.allows(true, "example.com", 450), "an unprefixed block covers udp");
        assert!(!p.allows(false, "example.com", 25) && p.allows(true, "example.com", 25), "--block-smtp is tcp only");
        let s = Policy::new(&Rules { block_smtp: true, ..rules() }).unwrap();
        for port in [25, 465, 587] {
            assert!(!s.allows(false, "mail.example", port));
        }
        assert!(s.allows(false, "mail.example", 24) && s.allows(false, "mail.example", 65535) && s.allows(false, "x.y", 1));
    }

    #[test]
    fn host_suffix_rules() {
        let p = Policy::new(&Rules {
            allow_hosts: hosts(&["example.com", "Other.ORG."]),
            block_hosts: hosts(&["admin.example.com"]),
            ..rules()
        })
        .unwrap();
        for ok in ["example.com", "EXAMPLE.com.", "a.b.example.com", "other.org", "x.other.org"] {
            assert!(p.allows(false, ok, 443), "{ok}");
        }
        for no in ["admin.example.com", "x.ADMIN.example.com.", "notexample.com", "example.co", "com", "org", "example.com.evil"] {
            assert!(!p.allows(false, no, 443), "{no}");
        }
        assert!(p.allows(false, "10.0.0.1", 443) && p.allows(false, "::1", 443), "IP literals skip name rules");
        let b = Policy::new(&Rules { block_hosts: hosts(&["blocked.test"]), ..rules() }).unwrap();
        assert!(!b.allows(true, "BLOCKED.TEST.", 53) && !b.allows(false, "x.blocked.test", 1));
        assert!(b.allows(false, "notblocked.test", 1) && b.allows(false, "blocked.test.x", 1) && b.allows(false, "test", 1));
        assert!(b.allows(false, &"a.".repeat(127), 1), "long names: no panic");
        assert!(!b.allows(false, &format!("{}blocked.test", "a.".repeat(120)), 1));
    }

    #[test]
    fn direct_ip_and_ipv6_literals() {
        let p = Policy::new(&Rules { direct_ip: false, ..rules() }).unwrap();
        for lit in ["127.0.0.1", "127.1", "2130706433", "0x7f000001", "::ffff:127.0.0.1", "::1", "8.8.8.8.", "::1%1", "fe80::1%eth0"] {
            assert!(!p.allows(false, lit, 80), "{lit}");
        }
        assert!(p.allows(false, "example.com", 80));
        let v = Policy::new(&Rules { ipv6: false, ..rules() }).unwrap();
        assert!(!v.allows(false, "::1", 80) && !v.allows(true, "2001:db8::1", 53));
        assert!(!v.allows(false, "2001:db8::1%1", 80) && !v.allows(false, "fe80::1%eth0", 80), "scoped v6 literals");
        assert!(v.allows(false, "::ffff:127.0.0.1%1", 80));
        assert!(v.allows(false, "127.0.0.1", 80) && v.allows(false, "::ffff:127.0.0.1", 80), "v4 and mapped v4 pass");
        assert!(v.allows(false, "example.com", 80), "names: the address rules drop the v6 answers");
    }

    /// a slow reference for the suffix walk (the policy-host fuzz target uses it too)
    pub fn reference(set: &[&str], host: &str) -> bool {
        let h = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        set.iter().any(|e| h == *e || h.ends_with(&format!(".{e}")))
    }

    #[test]
    fn suffix_walk_matches_the_reference() {
        let set = ["example.com", "a.b", "x"];
        let hs: HashSet<Box<str>> = set.iter().map(|s| (*s).into()).collect();
        for h in ["example.com", "w.example.com", "wexample.com", "a.b", "c.a.b", "ab", "x", "y.x", "xx", "", ".", "..x", "x."] {
            let n = h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase();
            assert_eq!(any_suffix(&hs, &n), reference(&set, h), "{h:?}");
        }
    }
}
