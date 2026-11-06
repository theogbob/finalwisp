#![no_main]
//! 70.01 ws::parse (frame header: 7/16/64-bit lengths, mask, control frames, reserved bits),
//! ws::write_header round trip, ws::unmask (AVX2 / baseline) against a naive XOR.
use finalwisp_fuzz::ws;
use libfuzzer_sys::fuzz_target;

const MAX_FRAME: usize = 16 * 1024 * 1024; // worker/mod.rs MAX_FRAME

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let max = match data[0] & 3 {
        0 => MAX_FRAME,
        1 => 125,
        2 => 65535,
        _ => (data[0] as usize) << 10,
    };
    let b = &data[1..];
    match ws::parse(b, max) {
        Ok(Some(f)) => {
            assert!(f.hdr_len <= b.len());
            let base = match b[1] & 0x7f {
                126 => 4,
                127 => 10,
                _ => 2,
            };
            assert_eq!(f.hdr_len, base + if f.mask.is_some() { 4 } else { 0 });
            assert_eq!(f.mask.is_some(), b[1] & 0x80 != 0);
            assert!(f.len <= max);
            assert!(matches!(f.opcode, 0 | 1 | 2 | 8 | 9 | 10));
            assert_eq!(f.fin, b[0] & 0x80 != 0);
            assert_eq!(f.opcode, b[0] & 0x0f);
            assert_eq!(b[0] & 0x70, 0);
            if f.opcode >= 8 {
                assert!(f.fin && f.len <= 125);
            }
            let wire = match base {
                2 => (b[1] & 0x7f) as u64,
                4 => u16::from_be_bytes([b[2], b[3]]) as u64,
                _ => u64::from_be_bytes(b[2..10].try_into().unwrap()),
            };
            assert_eq!(wire, f.len as u64);
            // every shorter prefix is "need more bytes", never an error or another frame
            for k in 0..f.hdr_len {
                assert!(matches!(ws::parse(&b[..k], max), Ok(None)), "prefix {k}");
            }
            if let Some(m) = f.mask {
                let mut p = b[f.hdr_len..].to_vec();
                let naive: Vec<u8> = p.iter().enumerate().map(|(i, x)| x ^ m[i & 3]).collect();
                ws::unmask(&mut p, m);
                assert_eq!(p, naive);
            }
        }
        Ok(None) => assert!(b.len() < 14),
        Err(_) => {
            // more bytes never turn an error into a frame
            let mut longer = b.to_vec();
            longer.extend_from_slice(&[0u8; 16]);
            assert!(ws::parse(&longer, max).is_err());
        }
    }
    // server header round trip (write_header is what the client parses back)
    if data.len() >= 10 {
        let op = [ws::OP_BIN, ws::OP_TEXT, ws::OP_CLOSE, ws::OP_PING, ws::OP_PONG][data[1] as usize % 5];
        let raw = u64::from_le_bytes(data[2..10].try_into().unwrap());
        let len = (match data[0] >> 6 {
            0 => raw % 126,
            1 => raw % 65536,
            _ => raw % (MAX_FRAME as u64 + 1),
        }) as usize;
        let len = if op >= 8 { len % 126 } else { len };
        let mut h = [0u8; 10];
        let hl = ws::write_header(&mut h, op, len);
        let f = ws::parse(&h[..hl], MAX_FRAME).unwrap().unwrap();
        assert_eq!((f.fin, f.opcode, f.len, f.hdr_len, f.mask.is_none()), (true, op, len, hl, true));
        // minimal length encoding
        assert_eq!(
            hl,
            if len <= 125 {
                2
            } else if len <= 0xffff {
                4
            } else {
                10
            }
        );
    }
});
