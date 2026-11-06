#![no_main]
//! 60.32 C6 upstream.rs on random input: never panics. Input: a selector byte, then the bytes.
//! - selector 0..=3: the reply parsers (socks_method with / without auth, socks_auth_reply, socks_reply) and 4: http_reply.
//!   The worker MSG_PEEKs and calls the parser again as bytes arrive, so a parser must be monotonic: on a longer prefix
//!   a Done keeps its len (and len <= the bytes seen) and a Fail its reason; Need only comes before either.
//! - any other selector: parse_url (lossy UTF-8). An accepted URL keeps the port non-zero and shows no userinfo
//!   (`shown` masks it whole as `***@`); no error quotes the userinfo.
use finalwisp_fuzz::upstream::{self as up, Parsed};
use libfuzzer_sys::fuzz_target;

fn parse(sel: u8, b: &[u8]) -> Parsed {
    match sel {
        0 => up::socks_method(b, false),
        1 => up::socks_method(b, true),
        2 => up::socks_auth_reply(b),
        3 => up::socks_reply(b),
        _ => up::http_reply(b),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, b)) = data.split_first() else { return };
    if sel <= 4 {
        let b = &b[..b.len().min(up::HTTP_HEAD_MAX)];
        // the full input and 8 prefixes (every prefix would be quadratic for http_reply)
        let mut last: Option<Parsed> = None;
        for k in (0..=8).map(|i| b.len() * i / 8) {
            let r = parse(sel, &b[..k]);
            if let Parsed::Done { len, .. } = r {
                assert!(len <= k && len > 0, "Done len {len} for {k} bytes");
            }
            match (&last, &r) {
                (Some(Parsed::Done { len: a, val: x }), Parsed::Done { len: c, val: y }) => assert!(a == c && x == y),
                (Some(Parsed::Done { .. }), _) => panic!("Done, then {r:?} on more bytes"),
                (Some(Parsed::Fail { reason: a, .. }), Parsed::Fail { reason: c, .. }) => assert_eq!(a, c),
                (Some(Parsed::Fail { .. }), _) if sel != 4 => panic!("Fail, then {r:?} on more bytes"),
                _ => {}
            }
            last = Some(r);
        }
        return;
    }
    let url = String::from_utf8_lossy(b).into_owned();
    let userinfo = url.split_once("://").and_then(|(_, r)| r.rsplit_once('@')).map(|(u, _)| u.to_string());
    match up::parse_url(&url) {
        Ok(u) => {
            assert!(u.port != 0 && !u.host.is_empty());
            let rest = u.shown.split_once("://").unwrap().1;
            assert_eq!(rest.starts_with("***@"), userinfo.is_some(), "{}", u.shown);
            assert!(u.socks_auth.is_none() || u.http_auth.is_none());
            if let Some(m) = &u.socks_auth {
                assert!(m.len() >= 3 && m.len() <= 3 + 255 + 255 && m[0] == 1);
            }
        }
        Err(e) => {
            // every message is a fixed text, so a userinfo can match one by chance (`m: unclosed` in "--upstream:
            // unclosed [", `;` in the https message: both found by this target): only a userinfo with a sub-delim that no
            // message holds counts
            if let Some(ui) = userinfo.filter(|u| u.contains(['~', '!', '*', '=', '&', '$', '+'])) {
                assert!(!e.contains(&ui), "{e}");
            }
        }
    }
});
