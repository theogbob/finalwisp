#![no_main]
//! 60.20 C1 policy.rs on random rules and hosts: never panics; the host-rule result equals a slow reference (the name or
//! a dotted suffix of it, after ASCII lowercase and one trailing dot removed); the entry parsers never panic.
//! Input: rule entries separated by '\n' (each through host_entry, PortRule::parse and Cidr::parse), then 0xff, then the
//! host of the CONNECT (lossy UTF-8), then optionally 0xfe and two bytes of port.
//! 60.35: Policy::refusal and net::Filter::refusal (the --log-streams rule names) are Some exactly when allows() /
//! allowed() refuse, for rules and filter flags taken from the input (the port's bits).
use finalwisp_fuzz::net::Filter;
use finalwisp_fuzz::policy::{self, Cidr, Policy, PortRule, Rules};
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

fn reference(set: &[String], host: &str) -> bool {
    let h = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    set.iter().any(|e| h == *e || h.ends_with(&format!(".{e}")))
}

fuzz_target!(|data: &[u8]| {
    let (rules, rest) = match data.iter().position(|&b| b == 0xff) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &data[..0]),
    };
    let (host, port) = match rest.iter().position(|&b| b == 0xfe) {
        Some(i) if rest.len() >= i + 3 => (&rest[..i], u16::from_le_bytes([rest[i + 1], rest[i + 2]])),
        _ => (rest, 443),
    };
    let host = String::from_utf8_lossy(host).into_owned();
    let (mut entries, mut port_rules, mut cidrs) = (Vec::new(), Vec::new(), Vec::new());
    for e in String::from_utf8_lossy(rules).split('\n') {
        let (pr, c) = (PortRule::parse(e), Cidr::parse(e));
        port_rules.extend(pr);
        cidrs.extend(c);
        if let Ok(h) = policy::host_entry(e) {
            assert!(!h.is_empty() && !h.ends_with('.') && h == h.to_ascii_lowercase());
            entries.push(h);
        }
    }
    let _ = (policy::is_ip_literal(&host), Cidr::parse(&host).map(|c| c.contains("10.0.0.1".parse().unwrap())));
    // 60.35 the address rule names mirror allowed() (host as an address; flags from the port's bits)
    if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        let b = |i: u16| port & (1 << i) != 0;
        let (half, rest) = cidrs.split_at(cidrs.len() / 2);
        let f = Filter {
            allow_embedded: b(2),
            allow_self: b(3),
            ipv6: !b(4),
            own: vec![ip, "203.0.113.7".parse().unwrap()]
                .into_iter()
                .take(if b(5) { 2 } else { 1 })
                .skip(if b(6) { 0 } else { 1 })
                .collect(),
            allow_dests: half.into(),
            block_dests: rest.into(),
            ..Filter::new(b(0), b(1))
        };
        assert_eq!(f.refusal(ip).is_some(), !f.allowed(ip), "filter {ip} {port:016b}");
    }
    if !policy::valid_host(&host) || port == 0 {
        return;
    }
    let base = Rules { direct_ip: true, ipv6: true, ..Rules::default() };
    let literal = policy::is_ip_literal(&host);
    // 60.35 the request rule names mirror allows() on mixed rules (flags from the port's bits)
    let b = |i: u16| port & (1 << i) != 0;
    let mixed = Rules {
        direct_ip: !b(7),
        ipv6: !b(8),
        block_smtp: b(9),
        allow_hosts: if b(10) { entries.clone() } else { vec![] },
        block_hosts: if b(11) { entries.clone() } else { vec![] },
        allow_ports: if b(12) { port_rules.clone() } else { vec![] },
        block_ports: if b(13) { port_rules.clone() } else { vec![] },
        ..base.clone()
    };
    if let Some(p) = Policy::new(&mixed) {
        for udp in [false, true] {
            assert_eq!(p.refusal(udp, &host, port).is_some(), !p.allows(udp, &host, port), "mixed {host:?} {port} {udp}");
        }
    }
    if let Some(p) = Policy::new(&Rules { block_hosts: entries.clone(), ..base.clone() }) {
        let want = literal || !reference(&entries, &host);
        assert_eq!(p.allows(false, &host, port), want, "block {entries:?} {host:?}");
        assert_eq!(p.allows(true, &host, port), want);
    }
    if let Some(p) = Policy::new(&Rules { allow_hosts: entries.clone(), ..base.clone() }) {
        let want = literal || reference(&entries, &host);
        assert_eq!(p.allows(false, &host, port), want, "allow {entries:?} {host:?}");
    }
    if let Some(p) = Policy::new(&Rules { allow_hosts: entries.clone(), block_hosts: entries.clone(), ..base }) {
        assert!(p.allows(false, &host, port) == literal, "block wins: {entries:?} {host:?}");
    }
});
