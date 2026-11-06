//! 60.34 PROXY protocol v1/v2 receiver (haproxy doc/proxy-protocol.txt; design 60.28). Pure parser: the worker peeks the
//! first bytes of a connection on a PROXY listener (MSG_PEEK, worker/proxy.rs), calls `parse`, and on Done consumes
//! exactly `len` bytes, so what follows (a TLS ClientHello, the HTTP request) stays in the kernel queue for the normal
//! path. Strict (spec: the receiver MUST NOT guess): bytes that cannot start a v1 or v2 header end the connection at once.
//! Fuzz target: proxy-parse.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Largest header accepted, and the peek buffer (v2 with TLVs: 16 + the length field; nginx
/// NGX_PROXY_PROTOCOL_MAX_HEADER is the same). A bigger one is refused as soon as its 16-byte prefix is in.
pub const MAX_HEADER: usize = 4096;
/// v1: the CRLF must come within 107 bytes (spec 2.1)
const V1_MAX: usize = 107;
const V2_SIG: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
const V1_SIG: &[u8] = b"PROXY ";

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Parse {
    /// a prefix of a valid header: wait for more bytes
    Partial,
    /// not a PROXY header (or a malformed one): drop the connection
    Bad,
    /// a complete header of `len` bytes. `src`: the original client address (None: LOCAL, UNSPEC, UNKNOWN or AF_UNIX;
    /// the real endpoint is used)
    Done { len: usize, src: Option<IpAddr> },
}

pub fn parse(b: &[u8]) -> Parse {
    let n = b.len().min(V2_SIG.len());
    if b[..n] == V2_SIG[..n] {
        return if b.len() < 16 { Parse::Partial } else { v2(b) };
    }
    let n = b.len().min(V1_SIG.len());
    if b[..n] == V1_SIG[..n] {
        return if b.len() < V1_SIG.len() { Parse::Partial } else { v1(b) };
    }
    Parse::Bad
}

fn v2(b: &[u8]) -> Parse {
    let (ver, cmd) = (b[12] >> 4, b[12] & 0x0f);
    let len = 16 + u16::from_be_bytes([b[14], b[15]]) as usize;
    if ver != 2 || cmd > 1 || len > MAX_HEADER {
        return Parse::Bad;
    }
    if b.len() < len {
        return Parse::Partial;
    }
    let a = &b[16..len];
    if cmd == 0 {
        return Parse::Done { len, src: None }; // LOCAL (health checks): the real endpoints, family ignored (spec)
    }
    let src = match b[13] {
        0x00 => None, // UNSPEC: the real endpoints
        0x11 if a.len() >= 12 => Some(IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))),
        0x21 if a.len() >= 36 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&a[..16]).unwrap()))),
        0x31 if a.len() >= 216 => None, // UNIX stream: no IP
        _ => return Parse::Bad,         // UDP (0x12/0x22/0x32 on a stream), unknown families, short address blocks
    };
    // TLVs after the address block are skipped (spec: "may choose to skip over and ignore")
    Parse::Done { len, src: src.and_then(usable) }
}

fn v1(b: &[u8]) -> Parse {
    let head = &b[..b.len().min(V1_MAX)];
    let Some(end) = head.windows(2).position(|w| w == b"\r\n") else {
        // a bare LF, or a CR not at the end of what is here (spec: no single CR or LF ends the line)
        let stray = head.iter().enumerate().any(|(i, &c)| c == b'\n' || (c == b'\r' && i + 1 < head.len()));
        return if stray || b.len() >= V1_MAX { Parse::Bad } else { Parse::Partial };
    };
    if b[..end].iter().any(|&c| c == b'\r' || c == b'\n') {
        return Parse::Bad; // a bare CR or LF before the CRLF (fuzz proxy-parse: UNKNOWN skipped the check)
    }
    let Ok(line) = std::str::from_utf8(&b[V1_SIG.len()..end]) else { return Parse::Bad };
    let len = end + 2;
    let f: Vec<&str> = line.split(' ').collect();
    if f.first() == Some(&"UNKNOWN") {
        return Parse::Done { len, src: None }; // the rest of the line is ignored (spec)
    }
    let [fam, s, d, sp, dp] = f[..] else { return Parse::Bad };
    let port = |p: &str| {
        !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|c| c.is_ascii_digit())
            && (p == "0" || !p.starts_with('0'))
            && p.parse::<u16>().is_ok()
    };
    if !port(sp) || !port(dp) {
        return Parse::Bad;
    }
    let src: IpAddr = match fam {
        "TCP4" => match (s.parse::<Ipv4Addr>(), d.parse::<Ipv4Addr>()) {
            (Ok(a), Ok(_)) => IpAddr::V4(a),
            _ => return Parse::Bad,
        },
        "TCP6" => match (s.parse::<Ipv6Addr>(), d.parse::<Ipv6Addr>()) {
            (Ok(a), Ok(_)) => IpAddr::V6(a),
            _ => return Parse::Bad,
        },
        _ => return Parse::Bad,
    };
    Parse::Done { len, src: usable(src) }
}

/// a source the header may name: not unspecified (0.0.0.0, ::) and not the unix sentinel's 100::/64 (60.28 review:
/// nothing on the wire may become the trusted unix peer, clientip::UNIX_PEER); such a header counts like LOCAL (the
/// real endpoint)
fn usable(ip: IpAddr) -> Option<IpAddr> {
    let ip = crate::clientip::canon(ip);
    let s = match crate::clientip::UNIX_PEER {
        IpAddr::V6(u) => u.segments(),
        IpAddr::V4(_) => unreachable!(),
    };
    let sentinel = matches!(ip, IpAddr::V6(a) if a.segments()[..4] == s[..4]);
    (!ip.is_unspecified() && !sentinel).then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }
    fn v2h(cmd: u8, fam: u8, addr: &[u8], tlv: &[u8]) -> Vec<u8> {
        let mut v = V2_SIG.to_vec();
        v.push(0x20 | cmd);
        v.push(fam);
        v.extend(((addr.len() + tlv.len()) as u16).to_be_bytes());
        v.extend(addr);
        v.extend(tlv);
        v
    }

    #[test]
    fn v1_cases() {
        let h = b"PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\nGET / HTTP/1.1\r\n";
        assert_eq!(parse(h), Parse::Done { len: 45, src: ip("192.0.2.1") });
        assert_eq!(parse(b"PROXY TCP6 2001:db8::1 ::1 1 2\r\n"), Parse::Done { len: 32, src: ip("2001:db8::1") });
        assert_eq!(parse(b"PROXY TCP6 ::ffff:1.2.3.4 ::1 1 2\r\n"), Parse::Done { len: 35, src: ip("1.2.3.4") }, "mapped = v4");
        assert_eq!(parse(b"PROXY UNKNOWN\r\n"), Parse::Done { len: 15, src: None });
        assert_eq!(parse(b"PROXY TCP6 :: ::1 1 2\r\n"), Parse::Done { len: 23, src: None }, "unspecified: the real peer");
        assert_eq!(parse(b"PROXY TCP6 100::5 ::1 1 2\r\n"), Parse::Done { len: 27, src: None }, "never the unix sentinel");
        assert_eq!(parse(b"PROXY TCP4 0.0.0.0 1.2.3.4 1 2\r\n"), Parse::Done { len: 32, src: None });
        assert_eq!(parse(b"PROXY UNKNOWN ffff::1 ::1 1 2\r\n"), Parse::Done { len: 31, src: None });
        for p in [&b"P"[..], b"PROXY", b"PROXY ", b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2", b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r"] {
            assert_eq!(parse(p), Parse::Partial, "{:?}", String::from_utf8_lossy(p));
        }
        for bad in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"\x16\x03\x01", // a TLS ClientHello
            b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\rx\n",
            b"PROXY UNKNOWN \n-\r\n", // a bare LF before the CRLF (fuzz)
            b"PROXY UNKNOWN \rx\r\n",
            b"PROXY TCP4 ::1 5.6.7.8 1 2\r\n",
            b"PROXY TCP4 01.2.3.4 5.6.7.8 1 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 65536 2\r\n",
            b"PROXY TCP4 1.2.3.4  5.6.7.8 1 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2 x\r\n",
            b"PROXY UDP4 1.2.3.4 5.6.7.8 1 2\r\n",
            b"proxy TCP4 1.2.3.4 5.6.7.8 1 2\r\n",
        ] {
            assert_eq!(parse(bad), Parse::Bad, "{:?}", String::from_utf8_lossy(bad));
        }
        let mut long = b"PROXY UNKNOWN ".to_vec();
        long.resize(V1_MAX, b'a');
        assert_eq!(parse(&long), Parse::Bad, "no CRLF within 107 bytes");
    }

    #[test]
    fn v2_cases() {
        let a4 = [192, 0, 2, 1, 198, 51, 100, 2, 0xdc, 0x04, 0x01, 0xbb];
        let h = v2h(1, 0x11, &a4, &[]);
        assert_eq!(parse(&h), Parse::Done { len: 28, src: ip("192.0.2.1") });
        let mut more = h.clone();
        more.extend(b"\x16\x03\x01");
        assert_eq!(parse(&more), Parse::Done { len: 28, src: ip("192.0.2.1") }, "what follows is not consumed");
        // TLVs skipped (AWS NLB: PP2_TYPE_AWS 0xEA with the VPC endpoint id; a NOOP)
        let tlv = [&[0xEA, 0x00, 0x05, 0x01][..], b"vpce", &[0x04, 0x00, 0x00]].concat();
        assert_eq!(parse(&v2h(1, 0x11, &a4, &tlv)), Parse::Done { len: 28 + tlv.len(), src: ip("192.0.2.1") });
        let mut a6 = [0u8; 36];
        a6[..16].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(parse(&v2h(1, 0x21, &a6, &[])), Parse::Done { len: 52, src: ip("2001:db8::7") });
        assert_eq!(parse(&v2h(0, 0x00, &[], &[])), Parse::Done { len: 16, src: None }, "LOCAL (health check)");
        assert_eq!(parse(&v2h(0, 0x11, &a4, &[])), Parse::Done { len: 28, src: None }, "LOCAL ignores the family");
        assert_eq!(parse(&v2h(1, 0x00, &[], &[])), Parse::Done { len: 16, src: None }, "UNSPEC");
        assert_eq!(parse(&v2h(1, 0x31, &[0u8; 216], &[])), Parse::Done { len: 232, src: None }, "AF_UNIX");
        for i in 0..h.len() {
            assert_eq!(parse(&h[..i]), Parse::Partial, "prefix {i}");
        }
        assert_eq!(parse(&v2h(1, 0x12, &a4, &[])), Parse::Bad, "UDP on a stream");
        assert_eq!(parse(&v2h(1, 0x11, &a4[..8], &[])), Parse::Bad, "short address block");
        assert_eq!(parse(&v2h(2, 0x11, &a4, &[])), Parse::Bad, "unassigned command");
        let mut v3 = h.clone();
        v3[12] = 0x31;
        assert_eq!(parse(&v3), Parse::Bad, "version 3");
        let big = v2h(1, 0x11, &a4, &vec![0x04; MAX_HEADER]);
        assert_eq!(parse(&big[..100]), Parse::Bad, "over MAX_HEADER: refused before it is all there");
    }

    #[test]
    fn parse_never_panics_on_prefixes_of_junk() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..20_000 {
            let mut b = if x & 1 == 0 { V2_SIG.to_vec() } else { b"PROXY TCP4 ".to_vec() };
            for _ in 0..(x >> 8) % 64 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                b.push((x >> 24) as u8);
            }
            if let Parse::Done { len, .. } = parse(&b) {
                assert!(len <= b.len() && len <= MAX_HEADER);
            }
        }
    }
}
