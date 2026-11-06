#![no_main]
//! 70.01 http::parse (upgrade request, headers, Sec-WebSocket-* values) and the 101 response built
//! from what it returns (http::switching: no header injection), percent_decode (wsproxy paths).
//! 60.24: logs::value (the --log-conns logfmt escaper) on the same bytes, checked against an unescaper.
//! 60.20 C2: the X-Forwarded-For lines are captured and walked (clientip::real_ip) and compared with a slow reference.
use finalwisp_fuzz::{clientip, http, policy::Cidr, worker::fuzz_hooks};
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

/// the slow reference: split every line on ',', all entries right to left; trusted ones skipped, the first other one wins;
/// an unparsable one: the last trusted (or the peer); all trusted: the leftmost
fn reference(cip: &clientip::ClientIp, peer: IpAddr, lines: &[Vec<u8>]) -> IpAddr {
    // a non-UTF-8 entry is junk: lossy decoding keeps the commas and makes it unparsable
    let joined: Vec<String> = lines.iter().map(|l| String::from_utf8_lossy(l).into_owned()).collect();
    let all: Vec<String> = joined.join(",").split(',').map(|s| s.trim().to_string()).collect();
    let mut last = peer;
    for e in all.iter().rev() {
        let parsed = e
            .parse::<IpAddr>()
            .ok()
            .or_else(|| e.strip_prefix('[').and_then(|r| r.split(']').next()).and_then(|s| s.parse().ok()))
            .or_else(|| {
                e.rsplit_once(':')
                    .filter(|(_, p)| p.parse::<u16>().is_ok())
                    .and_then(|(i, _)| i.parse::<std::net::Ipv4Addr>().ok())
                    .map(IpAddr::V4)
            });
        match parsed.map(clientip::canon) {
            None => return last,
            Some(ip) if cip.is_trusted(ip) => last = ip,
            Some(ip) => return ip,
        }
    }
    last
}

/// 60.24 the inverse of logs::value (the reader's view): None = not a well-formed value
fn logfmt_unescape(v: &[u8]) -> Option<Vec<u8>> {
    let Some(q) = v.strip_prefix(b"\"").and_then(|r| r.strip_suffix(b"\"")) else { return Some(v.to_vec()) };
    let (mut out, mut i) = (Vec::new(), 0);
    while i < q.len() {
        if q[i] != b'\\' {
            out.push(q[i]);
            i += 1;
            continue;
        }
        let (b, n) = match *q.get(i + 1)? {
            b'"' => (b'"', 2),
            b'\\' => (b'\\', 2),
            b'n' => (b'\n', 2),
            b'r' => (b'\r', 2),
            b't' => (b'\t', 2),
            b'x' => (u8::from_str_radix(std::str::from_utf8(q.get(i + 2..i + 4)?).ok()?, 16).ok()?, 4),
            _ => return None,
        };
        out.push(b);
        i += n;
    }
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    // 60.24 logfmt values: one token (no space, newline or control byte outside quotes, no bare '=' or '"'), and the
    // reader gets the bytes back
    let mut v = Vec::new();
    finalwisp_fuzz::logs::value(&mut v, data);
    assert!(!v.is_empty() && v.iter().all(|&b| b >= b' ' && b != 0x7f));
    let quoted = v.len() >= 2 && v[0] == b'"' && v[v.len() - 1] == b'"';
    assert!(quoted || !v.iter().any(|&b| b == b' ' || b == b'=' || b == b'"' || b == b'\\'));
    if quoted {
        let inner = &v[1..v.len() - 1];
        assert!((0..inner.len()).all(|i| inner[i] != b'"' || (i > 0 && inner[i - 1] == b'\\')), "an inner quote is escaped");
    }
    assert_eq!(logfmt_unescape(&v).as_deref(), Some(data));
    if let http::Parsed::Done(req, _) = http::parse_capture(data, Some("x-forwarded-for")) {
        let cip = clientip::ClientIp {
            trusted: vec![Cidr::parse("127.0.0.1").unwrap(), Cidr::parse("10.0.0.0/8").unwrap(), Cidr::parse("::1").unwrap()].into(),
            header: "x-forwarded-for".into(),
            table: None,
            max_conns: 0,
        };
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let (ip, got) = cip.real_ip(peer, &req.fwd);
        if !req.fwd.is_empty() {
            assert!(got.is_some());
            if got == Some(clientip::Got::Header) {
                assert_eq!(ip, reference(&cip, peer, &req.fwd), "{:?}", req.fwd);
            } else {
                assert!(cip.is_trusted(ip), "a bad header falls back to a trusted hop: {ip}");
            }
        }
    }
    match http::parse_capture(data, None) {
        http::Parsed::Done(req, n) => {
            assert!(n > 0 && n <= data.len());
            assert!(data[..n].ends_with(b"\n"));
            // the request is complete at n: the same bytes parse the same way without what follows
            assert!(matches!(http::parse_capture(&data[..n], None), http::Parsed::Done(_, m) if m == n));
            if let Some(up) = &req.upgrade {
                assert_eq!(up.accept.len(), 28);
                let mut out = Vec::new();
                http::switching(&mut out, up);
                assert!(out.ends_with(b"\r\n\r\n"));
                let head = &out[..out.len() - 4];
                assert!(!head.windows(4).any(|w| w == b"\r\n\r\n"), "header block ends early");
                for line in head.split(|&b| b == b'\n') {
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    assert!(!line.contains(&b'\r'), "bare CR in response");
                }
                if let Some(p) = &up.protocol {
                    assert!(!p.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0));
                }
            }
            let _ = fuzz_hooks::percent_decode(&req.path);
        }
        http::Parsed::Partial => {}
        http::Parsed::Bad => {}
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let d = fuzz_hooks::percent_decode(s);
        assert!(d.len() <= 3 * s.len() + 3); // lossy replacement only grows by U+FFFD per byte
    }
});
