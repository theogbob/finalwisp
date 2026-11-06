#![no_main]
//! 70.09 dns.rs reply parser on hostile bytes: parse_reply against a fixed question (www.example.com, A or
//! AAAA; the expected ID is taken from the packet so the fuzzer gets past the ID check), read_name at any offset,
//! and the resolv.conf / hosts / --dns-server parsers on the same bytes as text. Never panics; accepted
//! addresses are of the asked family, without duplicates; parsed settings stay inside their limits.
use finalwisp_fuzz::dns;
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, m)) = data.split_first() else { return };
    let qname = dns::encode_name("www.example.com").unwrap();
    let qtype = if sel & 1 == 0 { 1 } else { 28 };
    let id = u16::from_be_bytes([*m.first().unwrap_or(&0), *m.get(1).unwrap_or(&0)]);
    if let Some(dns::Reply::Addrs(a)) = dns::parse_reply(m, id, &qname, qtype) {
        assert!(!a.is_empty());
        assert!(a.iter().all(|x| matches!(x, IpAddr::V4(_)) == (qtype == 1)));
        for (i, x) in a.iter().enumerate() {
            assert!(!a[..i].contains(x));
        }
    }
    if let Some((name, end)) = dns::read_name(m, (sel >> 1) as usize) {
        assert!(name.len() <= 255 && end <= m.len() && name.last() == Some(&0));
    }
    let text = String::from_utf8_lossy(m);
    let c = dns::parse_resolv(&text);
    assert!(c.servers.len() <= 3 && (1..=5).contains(&c.attempts));
    let w = c.window().as_secs();
    assert!((1..=2).contains(&w));
    let _ = dns::parse_hosts(&text);
    for line in text.lines().take(4) {
        if let Some(s) = dns::parse_server(line) {
            assert!(s.port() != 0);
        }
    }
});
