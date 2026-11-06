//! 20.02 WebSocket framing (RFC 6455) — server side only.
//! Client frames are masked; server frames are not. We never send fragmented frames.

pub const OP_CONT: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BIN: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

#[derive(Clone, Copy, Debug)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub mask: Option<[u8; 4]>,
    pub hdr_len: usize,
    pub len: usize,
}

#[derive(Debug)]
pub enum FrameError {
    Reserved,
    BadControl,
    TooBig,
}

/// Parse a frame header. Ok(None) = need more bytes.
#[inline]
pub fn parse(b: &[u8], max: usize) -> Result<Option<Frame>, FrameError> {
    if b.len() < 2 {
        return Ok(None);
    }
    let b0 = b[0];
    let b1 = b[1];
    if b0 & 0x70 != 0 {
        return Err(FrameError::Reserved); // no extensions negotiated
    }
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0f;
    let masked = b1 & 0x80 != 0;
    let mut len = (b1 & 0x7f) as usize;
    let mut hdr = 2;
    if len == 126 {
        if b.len() < 4 {
            return Ok(None);
        }
        len = u16::from_be_bytes([b[2], b[3]]) as usize;
        hdr = 4;
    } else if len == 127 {
        if b.len() < 10 {
            return Ok(None);
        }
        let l = u64::from_be_bytes(b[2..10].try_into().unwrap());
        if l > max as u64 {
            return Err(FrameError::TooBig);
        }
        len = l as usize;
        hdr = 10;
    }
    if opcode >= 0x8 && (!fin || len > 125) {
        return Err(FrameError::BadControl);
    }
    if !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
        return Err(FrameError::Reserved);
    }
    if len > max {
        return Err(FrameError::TooBig);
    }
    let mask = if masked {
        if b.len() < hdr + 4 {
            return Ok(None);
        }
        let m = [b[hdr], b[hdr + 1], b[hdr + 2], b[hdr + 3]];
        hdr += 4;
        Some(m)
    } else {
        None
    };
    Ok(Some(Frame { fin, opcode, mask, hdr_len: hdr, len }))
}

/// Server frame header for a FIN frame with `len` payload bytes. Returns header length.
#[inline(always)]
pub fn write_header(dst: &mut [u8; 10], opcode: u8, len: usize) -> usize {
    dst[0] = 0x80 | opcode;
    if len <= 125 {
        dst[1] = len as u8;
        2
    } else if len <= 0xffff {
        dst[1] = 126;
        dst[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        4
    } else {
        dst[1] = 127;
        dst[2..10].copy_from_slice(&(len as u64).to_be_bytes());
        10
    }
}

/// Append a complete server frame to `out`.
#[inline]
pub fn push_frame(out: &mut Vec<u8>, opcode: u8, parts: &[&[u8]]) {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut h = [0u8; 10];
    let hl = write_header(&mut h, opcode, len);
    out.extend_from_slice(&h[..hl]);
    for p in parts {
        out.extend_from_slice(p);
    }
}

#[inline(always)]
fn unmask_body(buf: &mut [u8], mask: [u8; 4]) {
    let m32 = u32::from_ne_bytes(mask) as u64;
    let m64 = m32 | (m32 << 32);
    let (chunks, rest) = buf.as_chunks_mut::<8>();
    for c in chunks {
        *c = (u64::from_ne_bytes(*c) ^ m64).to_ne_bytes();
    }
    for (i, b) in rest.iter_mut().enumerate() {
        *b ^= mask[i & 3];
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn unmask_avx2(buf: &mut [u8], mask: [u8; 4]) {
    unmask_body(buf, mask)
}

/// In-place unmask. Runtime-dispatched: AVX2 when present, otherwise the
/// baseline (SSE2 on x86_64 / NEON on aarch64) autovectorised loop.
#[inline]
pub fn unmask(buf: &mut [u8], mask: [u8; 4]) {
    #[cfg(target_arch = "x86_64")]
    {
        if buf.len() >= 64 && std::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 support was detected at runtime on the line above
            unsafe { return unmask_avx2(buf, mask) }
        }
    }
    unmask_body(buf, mask)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn accept_key(key: &str) -> String {
    let mut h = sha1_smol::Sha1::new();
    h.update(key.trim().as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64(&h.digest().bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc_accept_key() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
    #[test]
    fn unmask_roundtrip() {
        for n in [0usize, 1, 7, 8, 9, 63, 64, 65, 1000, 70000] {
            let orig: Vec<u8> = (0..n).map(|i| (i * 31) as u8).collect();
            let m = [0x12, 0x34, 0x56, 0x78];
            let mut v: Vec<u8> = orig.iter().enumerate().map(|(i, b)| b ^ m[i & 3]).collect();
            unmask(&mut v, m);
            assert_eq!(v, orig);
        }
    }
    #[test]
    fn parse_lengths() {
        let f = parse(&[0x82, 0x80 | 126, 0x01, 0x00, 1, 2, 3, 4], 1 << 24).unwrap().unwrap();
        assert_eq!((f.len, f.hdr_len, f.opcode, f.fin), (256, 8, OP_BIN, true));
        assert!(parse(&[0x82], 100).unwrap().is_none());
        assert!(parse(&[0x89, 126, 0, 200], 1000).is_err());
        assert!(parse(&[0xC2, 0], 1000).is_err());
    }
}
