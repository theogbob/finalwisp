#![no_main]
//! 70.01 stateful TLS: a real rustls client completes the handshake with the Worker over TCP loopback
//! (TLS 1.2/1.3, each kTLS cipher; optionally one corrupted handshake byte), then both sides run kTLS
//! and input-chosen ops go through the server's kTLS paths: application data (HTTP upgrade, WS/Wisp),
//! raw records of any type (tls_control: alerts, KeyUpdate, junk handshake), real KeyUpdates (rekey),
//! close_notify, idle sweeps, pressure levels. Input: [sel] [corrupt off] [corrupt xor] ops...
use finalwisp_fuzz::worker::fuzz_hooks::Harness;
use libfuzzer_sys::fuzz_target;
#[path = "common.rs"]
mod common;
use common::*;

const TLS_VARIANT: u8 = 3;

fn frame(out: &mut Vec<u8>, b0: u8, payload: &[u8], m: [u8; 4]) {
    out.push(b0);
    let n = payload.len();
    if n < 126 {
        out.push(0x80 | n as u8);
    } else {
        out.push(0x80 | 126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    }
    out.extend_from_slice(&m);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ m[i & 3]));
}

fn run(h: &mut Harness, data: &[u8]) {
    let (sel, off, x) = (data[0], data[1], data[2]);
    let mut ops = &data[3..];
    let corrupt = if sel & 0x30 == 0x30 { Some((off as usize * 4, x)) } else { None };
    let mut c = h.open_tls(sel & 1 == 0, (sel >> 1) & 3, sel & 0x08 == 0, corrupt);
    if c.ktls.is_none() {
        return h.close(c);
    }
    let mut n_ops = 0;
    let take = |ops: &mut &[u8], n: usize| {
        let k = n.min(ops.len());
        let (a, b) = ops.split_at(k);
        *ops = b;
        a.to_vec()
    };
    while let Some((&op, rest)) = ops.split_first() {
        ops = rest;
        n_ops += 1;
        if n_ops > 128 {
            break;
        }
        let arg = take(&mut ops, 1).first().copied().unwrap_or(0);
        let ok = match op % 8 {
            0 => {
                let d = take(&mut ops, arg as usize);
                h.feed(&mut c, &d, false)
            }
            1 => {
                let proto = if arg & 1 == 1 { "Sec-WebSocket-Protocol: wisp-v2\r\n" } else { "" };
                let path = if arg & 2 == 2 { "/p/127.0.0.1:4444" } else { "/" };
                let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{proto}\r\n");
                h.feed(&mut c, req.as_bytes(), false)
            }
            2 => {
                let p = take(&mut ops, arg as usize);
                let mut f = Vec::new();
                frame(&mut f, 0x82, &p, [arg, 7, 1, 9]);
                h.feed(&mut c, &f, false)
            }
            3 => {
                let typ = arg;
                let n = take(&mut ops, 1).first().copied().unwrap_or(0) as usize;
                let p = take(&mut ops, n);
                h.send_record(&mut c, typ, &p) && {
                    h.turn(false);
                    h.drain(&mut c);
                    h.alive(&c)
                }
            }
            4 => {
                h.client_key_update(&mut c, arg & 1 == 1) && {
                    h.turn(false);
                    h.drain(&mut c);
                    h.alive(&c)
                }
            }
            5 => {
                h.send_record(&mut c, 21, &[1, 0]) && {
                    h.turn(false);
                    h.drain(&mut c);
                    h.alive(&c)
                }
            }
            6 => {
                h.turn(arg & 1 == 1);
                h.drain(&mut c);
                h.check(&c);
                h.alive(&c)
            }
            _ => {
                h.set_level(level(arg));
                true
            }
        };
        if !ok {
            break;
        }
    }
    for _ in 0..4 {
        h.turn(false);
        h.drain(&mut c);
        h.check(&c);
    }
    h.close(c);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    with_harness(TLS_VARIANT, |h| {
        assert!(h.tls, "kTLS unavailable: worker-tls needs the tls module");
        h.reset();
        h.set_level(0);
        run(h, data);
        h.set_level(0);
        h.turn(false);
    });
});
