//! 60.15 T06 byte integrity at rate (30.13 "cheapest next step"): `wbench run --verify` + `wbench target --verify`.
//! Every stream's TCP byte stream between wbench and its target carries a keyed, numbered pattern instead of zeros,
//! the receiver checks every byte, and an END handshake reconciles the sender's and the receiver's byte counts.
//! Wire format (little-endian u64s, inside the stream, i.e. what the Wisp server must relay unchanged):
//!   client -> target: HELLO [HELLO_MAGIC][key], then pattern bytes (upload), then END
//!   target -> client: pattern bytes (download), then END, then the target closes the connection
//!   END = [END_MAGIC][pattern bytes sent][pattern bytes received][content errors seen] (32 bytes)
//! Pattern: u64 word i of a stream is (i + 1 + key << 40) * ODD (wrapping): never zero for i < 2^40 words, different
//! per stream (a stream delivered on the wrong Wisp stream fails), and word i+1 = word i + ODD, so generating and
//! checking cost an add and a compare per 8 bytes.
//! A receiver cannot tell END from data by position (it does not know when the sender stops), so it holds back the
//! last END_LEN bytes and checks the rest; held bytes that start with END_MAGIC are the END (a pattern word equal to
//! the magic at that position: p ~ 2^-64).

pub const HELLO_MAGIC: u64 = 0x4f4c_4c45_4846_5701; // "\x01WFHELLO"
pub const END_MAGIC: u64 = 0x2121_444e_4546_5702; // "\x02WFEND!!"
pub const HELLO_LEN: usize = 16;
pub const END_LEN: usize = 32;
const ODD: u64 = 0x9E37_79B9_7F4A_7C15;

#[inline]
fn word(key: u64, i: u64) -> u64 {
    (i + 1).wrapping_add(key << 40).wrapping_mul(ODD)
}

pub fn hello(key: u64) -> [u8; HELLO_LEN] {
    let mut b = [0u8; HELLO_LEN];
    b[..8].copy_from_slice(&HELLO_MAGIC.to_le_bytes());
    b[8..].copy_from_slice(&key.to_le_bytes());
    b
}

/// key from a HELLO, or None if `b` is not one
pub fn parse_hello(b: &[u8; HELLO_LEN]) -> Option<u64> {
    (u64::from_le_bytes(b[..8].try_into().unwrap()) == HELLO_MAGIC).then(|| u64::from_le_bytes(b[8..].try_into().unwrap()))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct End {
    pub sent: u64,
    pub received: u64,
    pub errs: u64,
}

impl End {
    pub fn bytes(&self) -> [u8; END_LEN] {
        let mut b = [0u8; END_LEN];
        for (i, v) in [END_MAGIC, self.sent, self.received, self.errs].into_iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }
    fn parse(b: &[u8]) -> Option<End> {
        let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        (b.len() == END_LEN && w(0) == END_MAGIC).then(|| End { sent: w(1), received: w(2), errs: w(3) })
    }
}

/// Pattern bytes [off, off + buf.len()) of stream `key`.
pub fn fill(key: u64, off: u64, buf: &mut [u8]) {
    let mut i = 0usize;
    let mut o = off;
    if !o.is_multiple_of(8) {  // head: the rest of a partly sent word
        let w = word(key, o / 8).to_le_bytes();
        let k = ((8 - o % 8) as usize).min(buf.len());
        buf[..k].copy_from_slice(&w[(o % 8) as usize..(o % 8) as usize + k]);
        i = k;
        o += k as u64;
    }
    let mut v = word(key, o / 8);
    let (words, r) = buf[i..].as_chunks_mut::<8>();
    for c in words {
        *c = v.to_le_bytes();
        v = v.wrapping_add(ODD);
    }
    let n = r.len();
    r.copy_from_slice(&v.to_le_bytes()[..n]);
}

/// true if `data` equals pattern bytes [off, off + data.len()) of stream `key`
pub fn check(key: u64, off: u64, data: &[u8]) -> bool {
    let mut i = 0usize;
    let mut o = off;
    if !o.is_multiple_of(8) {
        let w = word(key, o / 8).to_le_bytes();
        let k = ((8 - o % 8) as usize).min(data.len());
        if data[..k] != w[(o % 8) as usize..(o % 8) as usize + k] {
            return false;
        }
        i = k;
        o += k as u64;
    }
    let mut v = word(key, o / 8);
    let mut diff = 0u64; // OR of all differences: no branch per word, so the loop stays at memory speed
    let (words, r) = data[i..].as_chunks::<8>();
    for c in words {
        diff |= u64::from_le_bytes(*c) ^ v;
        v = v.wrapping_add(ODD);
    }
    diff == 0 && r == &v.to_le_bytes()[..r.len()]
}

/// Receiving side of one stream: checks pattern bytes as they arrive, holding back the last END_LEN bytes.
#[derive(Default)]
pub struct Rx {
    pub key: u64,
    /// pattern bytes checked so far (= received, once the END is in)
    pub off: u64,
    /// pieces (one per call that had a mismatch) with a content error
    pub errs: u64,
    pub end: Option<End>,
    /// bytes after the END (a sender bug)
    pub trailing: u64,
    hold: Vec<u8>,
}

impl Rx {
    pub fn new(key: u64) -> Rx {
        Rx { key, hold: Vec::with_capacity(END_LEN), ..Rx::default() }
    }

    fn checked(&mut self, d: &[u8]) {
        if !check(self.key, self.off, d) {
            self.errs += 1;
        }
        self.off += d.len() as u64;
    }

    pub fn feed(&mut self, data: &[u8]) {
        if self.end.is_some() {
            self.trailing += data.len() as u64;
            return;
        }
        let total = self.hold.len() + data.len();
        if total > END_LEN {
            let release = total - END_LEN; // these bytes cannot be part of an END: check them
            let from_hold = release.min(self.hold.len());
            if from_hold > 0 {
                let mut h = [0u8; END_LEN]; // hold is at most END_LEN: no heap allocation per piece
                h[..from_hold].copy_from_slice(&self.hold[..from_hold]);
                self.hold.drain(..from_hold);
                self.checked(&h[..from_hold]);
            }
            self.checked(&data[..release - from_hold]);
            self.hold.extend_from_slice(&data[release - from_hold..]);
        } else {
            self.hold.extend_from_slice(data);
        }
        if self.hold.len() == END_LEN {
            self.end = End::parse(&self.hold);
        }
    }

    /// bytes held back and never resolved (no END came): a stream that ended without END
    #[cfg(test)]
    pub fn held(&self) -> usize {
        if self.end.is_some() { 0 } else { self.hold.len() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(key: u64, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        fill(key, 0, &mut b);
        b
    }

    #[test]
    fn fill_in_pieces_equals_fill_at_once_and_words_are_nonzero() {
        let all = stream(7, 1000);
        for cut in [0, 1, 3, 8, 9, 15, 16, 999] {
            let mut b = vec![0u8; 1000];
            fill(7, 0, &mut b[..cut]);
            fill(7, cut as u64, &mut b[cut..]);
            assert_eq!(b, all, "cut {cut}");
        }
        assert!(all.as_chunks::<8>().0.iter().all(|w| *w != [0u8; 8]));
        assert_ne!(stream(8, 1000), all, "keys give different streams");
    }

    #[test]
    fn check_finds_every_single_byte_change_at_any_offset() {
        let all = stream(3, 300);
        for off in [0usize, 1, 5, 8, 13] {
            assert!(check(3, off as u64, &all[off..]));
            assert!(!check(4, off as u64, &all[off..]), "wrong key");
            for pos in off..300 {
                let mut d = all[off..].to_vec();
                d[pos - off] ^= 0x10;
                assert!(!check(3, off as u64, &d), "flip at {pos} off {off}");
            }
        }
        assert!(!check(3, 1, &all[..299]), "shifted by one byte");
    }

    #[test]
    fn rx_split_anywhere_finds_end_and_counts() {
        let data = stream(9, 5000);
        let end = End { sent: 5000, received: 0, errs: 0 };
        let mut wire = data.clone();
        wire.extend_from_slice(&end.bytes());
        for piece in [1usize, 7, 31, 32, 33, 1000, 6000] {
            let mut rx = Rx::new(9);
            for c in wire.chunks(piece) {
                rx.feed(c);
            }
            assert_eq!((rx.off, rx.errs, rx.end, rx.trailing, rx.held()), (5000, 0, Some(end), 0, 0), "piece {piece}");
        }
        let mut rx = Rx::new(9);
        rx.feed(&end.bytes()); // no pattern at all (the target -> client side of an upload)
        assert_eq!((rx.off, rx.end), (0, Some(end)));
    }

    #[test]
    fn rx_counts_corruption_loss_and_missing_end() {
        let mut wire = stream(9, 5000);
        wire[1234] ^= 1;
        let mut rx = Rx::new(9);
        rx.feed(&wire);
        rx.feed(&End::default().bytes());
        assert_eq!((rx.errs, rx.off), (1, 5000));
        let wire = stream(9, 5000);
        let mut rx = Rx::new(9);
        rx.feed(&wire[..2000]);
        rx.feed(&wire[2008..]); // 8 bytes lost
        assert!(rx.errs > 0);
        assert_eq!(rx.end, None);
        assert_eq!(rx.held(), END_LEN);
    }

    /// The checker's own speed (verify must not be the limit): cargo test --release -- --ignored --nocapture speed
    #[test]
    #[ignore]
    fn speed() {
        let buf = stream(5, 64 * 1024);
        let t = std::time::Instant::now();
        let mut n = 0u64;
        while t.elapsed().as_secs_f64() < 2.0 {
            for k in 0..1000u64 {
                assert!(check(5, 0, std::hint::black_box(&buf)), "{k}");
                n += buf.len() as u64;
            }
        }
        let mut out = vec![0u8; 64 * 1024];
        let t2 = std::time::Instant::now();
        let mut m = 0u64;
        while t2.elapsed().as_secs_f64() < 2.0 {
            for _ in 0..1000 {
                fill(5, m, std::hint::black_box(&mut out));
                m += out.len() as u64;
            }
        }
        eprintln!("verify speed per core: check {:.1} GiB/s, fill {:.1} GiB/s",
                  n as f64 / t.elapsed().as_secs_f64() / (1u64 << 30) as f64, m as f64 / t2.elapsed().as_secs_f64() / (1u64 << 30) as f64);
    }
}
