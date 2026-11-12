//! Minimal WebSocket client framing for wbench (pointer 30.01).
//! Hand-rolled HTTP/1.1 upgrade, masked client frames, unmasked server frames.
use bytes::BytesMut;
use std::io::{Error, ErrorKind};
use crate::tls::Sock;
use rustls::ClientConfig;
use std::sync::Arc;

pub const OP_CONT: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BIN: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub tls: bool, // 20.13 wss://
}

pub fn parse_url(url: &str) -> Result<Url, String> {
    let (tls, rest) = match (url.strip_prefix("ws://"), url.strip_prefix("wss://")) {
        (Some(r), _) => (false, r),
        (_, Some(r)) => (true, r),
        _ => return Err("only ws:// and wss:// URLs are supported".into()),
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "bad port in url")?),
        None => (hostport.to_string(), if tls { 443 } else { 80 }),
    };
    Ok(Url { host, port, path, tls })
}

/// 60.67 --xff-keys N: the number of client addresses the connections rotate through (0 = no header).
pub static XFF_KEYS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static XFF_NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The `X-Forwarded-For` line of the next connection, or nothing. Even k: IPv4 11.1.0.1 + k/2; odd k: one IPv6 /64 per k.
fn xff_header() -> String {
    use std::sync::atomic::Ordering::Relaxed;
    let n = XFF_KEYS.load(Relaxed);
    if n == 0 {
        return String::new();
    }
    xff_line(XFF_NEXT.fetch_add(1, Relaxed) % n)
}

fn xff_line(k: u64) -> String {
    let i = k / 2;
    if k.is_multiple_of(2) {
        let a = 0x0b01_0001u32.wrapping_add(i as u32);
        format!("X-Forwarded-For: {}\r\n", std::net::Ipv4Addr::from(a))
    } else {
        format!("X-Forwarded-For: 2a10:77:{:x}:{:x}::1\r\n", (i >> 16) & 0xffff, i & 0xffff)
    }
}

/// Connect + upgrade. Returns the socket and any bytes read past the HTTP response.
pub async fn connect(url: &Url, tls: Option<&Arc<ClientConfig>>) -> std::io::Result<(Sock, BytesMut)> {
    let mut sock = Sock::connect(url.host.as_str(), url.port, tls).await?;
    // No Sec-WebSocket-Protocol header => Wisp v1.
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{}\r\n",
        url.path, url.host, url.port, xff_header()
    );
    sock.write_all(req.as_bytes()).await?;
    let mut buf = BytesMut::with_capacity(512 * 1024);
    loop {
        if sock.read_some(&mut buf).await? == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "eof during ws handshake"));
        }
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let status = head.lines().next().unwrap_or("");
            if status.split_whitespace().nth(1) != Some("101") {
                return Err(Error::other(format!("ws upgrade failed: {status}")));
            }
            let _ = buf.split_to(end + 4);
            return Ok((sock, buf));
        }
        if buf.len() > 16 * 1024 {
            return Err(Error::new(ErrorKind::InvalidData, "ws handshake response too large"));
        }
    }
}

/// XOR `buf` with the 4-byte mask, 8 bytes at a time (auto-vectorizes).
#[inline]
pub fn apply_mask(buf: &mut [u8], key: [u8; 4]) {
    let k = u32::from_ne_bytes(key) as u64;
    let k64 = k | (k << 32);
    let (words, rest) = buf.as_chunks_mut::<8>();
    for c in words {
        *c = (u64::from_ne_bytes(*c) ^ k64).to_ne_bytes();
    }
    // chunks are multiples of 8 (and so of 4): remainder starts at key index 0.
    for (i, b) in rest.iter_mut().enumerate() {
        *b ^= key[i & 3];
    }
}

/// Cheap xorshift for mask keys. Not cryptographic; servers never check.
pub struct MaskGen(u32);
impl MaskGen {
    pub fn new(seed: u32) -> Self {
        MaskGen(seed | 1)
    }
    #[inline]
    pub fn next(&mut self) -> [u8; 4] {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x.to_ne_bytes()
    }
}

/// Append a masked frame: header, then `parts` concatenated as payload.
#[inline]
pub fn push_frame(out: &mut Vec<u8>, opcode: u8, parts: &[&[u8]], zero_tail: usize, key: [u8; 4]) {
    let len: usize = parts.iter().map(|p| p.len()).sum::<usize>() + zero_tail;
    out.push(0x80 | opcode);
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&key);
    let start = out.len();
    for p in parts {
        out.extend_from_slice(p);
    }
    out.resize(out.len() + zero_tail, 0);
    apply_mask(&mut out[start..], key);
}

pub struct FrameHdr {
    pub fin: bool,
    pub opcode: u8,
    pub hdr_len: usize,
    pub payload_len: usize,
    pub mask: Option<[u8; 4]>,
}

/// Parse a frame header. Ok(None) = need more bytes.
#[inline]
pub fn parse_hdr(b: &[u8]) -> Result<Option<FrameHdr>, &'static str> {
    if b.len() < 2 {
        return Ok(None);
    }
    let fin = b[0] & 0x80 != 0;
    if b[0] & 0x70 != 0 {
        return Err("ws frame with RSV bits set (compression not negotiated)");
    }
    let opcode = b[0] & 0x0F;
    let masked = b[1] & 0x80 != 0;
    let l7 = (b[1] & 0x7F) as usize;
    let (len, mut off) = match l7 {
        126 => {
            if b.len() < 4 {
                return Ok(None);
            }
            (u16::from_be_bytes([b[2], b[3]]) as usize, 4)
        }
        127 => {
            if b.len() < 10 {
                return Ok(None);
            }
            let l = u64::from_be_bytes(b[2..10].try_into().unwrap());
            if l > (1 << 30) {
                return Err("ws frame too large");
            }
            (l as usize, 10)
        }
        n => (n, 2),
    };
    let mask = if masked {
        if b.len() < off + 4 {
            return Ok(None);
        }
        let k = [b[off], b[off + 1], b[off + 2], b[off + 3]];
        off += 4;
        Some(k)
    } else {
        None
    };
    Ok(Some(FrameHdr { fin, opcode, hdr_len: off, payload_len: len, mask }))
}

#[cfg(test)]
mod xff_tests {
    #[test]
    fn xff_lines_are_public_addresses_one_key_each() {
        assert_eq!(super::xff_line(0), "X-Forwarded-For: 11.1.0.1\r\n");
        assert_eq!(super::xff_line(2), "X-Forwarded-For: 11.1.0.2\r\n");
        assert_eq!(super::xff_line(1), "X-Forwarded-For: 2a10:77:0:0::1\r\n");
        assert_eq!(super::xff_line(2 * 65536 + 7), "X-Forwarded-For: 2a10:77:1:3::1\r\n");
    }
}
