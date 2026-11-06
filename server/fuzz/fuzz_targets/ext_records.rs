#![no_main]
//! 70.01 ext.rs: the client INFO extension records (parse_records) and the auth decision (Ext::check:
//! password and ed25519 key auth payloads, both key-auth wire forms), plus the startup parsers
//! (auth file, PEM keys).
use finalwisp_fuzz::{ext, worker::fuzz_hooks};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn auth() -> &'static ext::Ext {
    static E: OnceLock<ext::Ext> = OnceLock::new();
    E.get_or_init(|| {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let k: [u8; 32] = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap().public_key().as_ref().try_into().unwrap();
        ext::Ext::new(true, ext::parse_auth_file("u:p\nalice:s3cr:et\n").unwrap(), vec![k], Some("m".into()))
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let ch = [9u8; ext::CHALLENGE_LEN];
    match mode % 4 {
        0 | 1 => {
            let e = auth();
            let parsed = ext::parse_records(rest);
            let verdict = e.check(rest, Some(&ch));
            assert_eq!(ext::Ext::default().check(rest, Some(&ch)), Ok(())); // no auth: records are not inspected
            match &parsed {
                Err(()) => assert_eq!(verdict, Err(ext::CLOSE_INCOMPATIBLE)),
                Ok(ci) => {
                    if verdict.is_ok() {
                        // only the configured credentials, or a signature the fuzzer cannot forge
                        let pw_ok = ci.password.is_some_and(|m| m == b"\x01up" || m == b"\x05alices3cr:et");
                        assert!(pw_ok || ci.cert.is_some(), "accepted without credentials: {ci:?}");
                        if ci.cert.is_some() && !pw_ok {
                            // a cert-only accept must carry our key's real signature over the challenge
                            let sig = fuzz_hooks::sign(&ch);
                            assert!(ci.cert.unwrap().ends_with(&sig));
                        }
                    }
                    if ci.password.is_none() && ci.cert.is_none() {
                        assert_eq!(verdict, Err(ext::CLOSE_AUTH_REQUIRED));
                    }
                }
            }
            if let Ok(ci) = parsed {
                // re-serialising the recognised records parses back the same
                let mut v = Vec::new();
                if ci.udp {
                    ext::record(&mut v, ext::EXT_UDP, &[]);
                }
                if let Some(p) = ci.password {
                    ext::record(&mut v, ext::EXT_PASSWORD, p);
                }
                if let Some(c) = ci.cert {
                    ext::record(&mut v, ext::EXT_CERT, c);
                }
                assert_eq!(ext::parse_records(&v), Ok(ci));
            }
        }
        2 => {
            // key auth in the spec form: u8 user_len | user | alg | hash | sig, user from the input
            let user = &rest[..rest.len().min(255)];
            let mut meta = vec![user.len() as u8];
            meta.extend_from_slice(user);
            meta.extend_from_slice(&fuzz_hooks::sign(&ch));
            let mut recs = Vec::new();
            ext::record(&mut recs, ext::EXT_CERT, &meta);
            assert_eq!(auth().check(&recs, Some(&ch)), Ok(()));
            assert_eq!(auth().check(&recs, Some(&[8u8; ext::CHALLENGE_LEN])), Err(ext::CLOSE_BAD_SIGNATURE));
        }
        _ => {
            if let Ok(s) = std::str::from_utf8(rest) {
                if let Err(e) = ext::parse_auth_file(s) {
                    assert!(e.len() < 64); // never echoes the line
                }
            }
            let _ = ext::parse_key_pem(rest);
        }
    }
});
