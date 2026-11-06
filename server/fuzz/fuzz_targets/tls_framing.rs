#![no_main]
//! 70.01 tls.rs record framing helpers (record_len, parse_key_update) and worker/ktls.rs client_hello
//! (20.15 first-record ClientHello extraction).
use finalwisp_fuzz::{tls, worker::fuzz_hooks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= tls::HEADER {
        if let Some(len) = tls::record_len(&data[..tls::HEADER]) {
            assert!(len <= tls::MAX_RECORD);
            assert!((20..=23).contains(&data[0]) && data[1] == 3);
        }
    }
    if let Some(req) = tls::parse_key_update(data) {
        assert_eq!(tls::key_update_msg(req)[..], data[..]);
    }
    if let Some(rec) = fuzz_hooks::client_hello(data) {
        assert!(data.starts_with(rec));
        // exactly the first record (header + body), cut at the end of the input
        assert_eq!(rec.len(), (5 + u16::from_be_bytes([data[3], data[4]]) as usize).min(data.len()));
        assert!(data[0] == 0x16 && data[1] == 3 && data[5] == 1);
    }
});
