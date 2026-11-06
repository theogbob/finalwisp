#![no_main]
//! 60.34 proxyproto::parse on random input: never panics; a Done is within the bytes and MAX_HEADER, has no
//! unusable source (unspecified, the unix sentinel's 100::/64), and is monotonic like the worker uses it (it peeks and
//! parses again as bytes arrive): on every longer prefix a Done keeps its len and source and a Bad stays Bad; Partial
//! only comes before either.
use finalwisp_fuzz::proxyproto::{parse, Parse, MAX_HEADER};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let b = &data[..data.len().min(MAX_HEADER)];
    let full = parse(b);
    if let Parse::Done { len, src } = full {
        assert!(len > 0 && len <= b.len() && len <= MAX_HEADER);
        if let Some(ip) = src {
            assert!(!ip.is_unspecified());
            assert!(!matches!(ip, std::net::IpAddr::V6(a) if a.segments()[..4] == [0x100, 0, 0, 0]), "never the unix sentinel");
            assert!(!matches!(ip, std::net::IpAddr::V6(a) if a.to_ipv4_mapped().is_some()), "mapped IPv4 is canonical");
        }
        assert_eq!(parse(&b[..len]), full, "the header alone parses the same");
    }
    let mut seen: Option<Parse> = None;
    for k in (0..=16).map(|i| b.len() * i / 16) {
        let r = parse(&b[..k]);
        match (seen, r) {
            (None, Parse::Partial) => {}
            (None, r) => seen = Some(r),
            (Some(s), r) => assert_eq!(r, s, "prefix {k}: changed after a final answer"),
        }
    }
    if let Some(s) = seen {
        assert_eq!(s, full);
    }
});
