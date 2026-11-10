//! 20.18 Wisp v2 protocol extensions: the server INFO payload and the check of the client's INFO.
//! Password auth (0x02), ed25519 key auth (0x03), MOTD (0x04); ref/wisp-protocol/protocol.md
//! "Protocol Extensions". Behaviour follows epoxy-server and wispurr where the spec is vague
//! (note 20.06, section 20.18).
use ring::digest::{digest, SHA256};
use ring::rand::SecureRandom;
use ring::signature::{UnparsedPublicKey, ED25519};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use std::borrow::Cow;

pub const EXT_UDP: u8 = 0x01;
pub const EXT_PASSWORD: u8 = 0x02;
pub const EXT_CERT: u8 = 0x03;
pub const EXT_MOTD: u8 = 0x04;

pub const CLOSE_INCOMPATIBLE: u8 = 0x04;
pub const CLOSE_BAD_PASSWORD: u8 = 0xc0;
pub const CLOSE_BAD_SIGNATURE: u8 = 0xc1;
pub const CLOSE_AUTH_REQUIRED: u8 = 0xc2;

/// Random bytes the client signs for key auth (spec: "around 512 bits"; epoxy uses 64 bytes).
pub const CHALLENGE_LEN: usize = 64;
pub type Challenge = [u8; CHALLENGE_LEN];
const ALG_ED25519: u8 = 0b0000_0001;
const SIG_LEN: usize = 64;
const CERT_BODY: usize = 1 + 32 + SIG_LEN; // algorithm | SHA-256(public key) | signature
/// DER prefix of an ed25519 SubjectPublicKeyInfo (RFC 8410); the 32 key bytes follow.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Server-side extension settings, built once at startup. `Ext::default()` = no extensions.
#[derive(Default)]
pub struct Ext {
    /// INFO payload (version + static records), without the per-connection key-auth record.
    info: Vec<u8>,
    /// SHA-256 of each credential in the client's wire format: u8 user_len | user | password.
    passwords: Vec<[u8; 32]>,
    /// (SHA-256 of the raw key, raw ed25519 public key)
    keys: Vec<([u8; 32], [u8; 32])>,
}

/// Append one extension record: u8 id | u32 LE length | metadata.
pub fn record(out: &mut Vec<u8>, id: u8, meta: &[u8]) {
    out.push(id);
    out.extend_from_slice(&(meta.len() as u32).to_le_bytes());
    out.extend_from_slice(meta);
}

impl Ext {
    /// `udp` = 20.16 UDP streams on (Config::udp): advertised as record 0x01 with no payload.
    pub fn new(udp: bool, passwords: Vec<[u8; 32]>, keys: Vec<[u8; 32]>, motd: Option<String>) -> Ext {
        let mut info = vec![2, 0]; // Wisp 2.0

        // ---- server extension list, in id order
        if udp {
            record(&mut info, EXT_UDP, &[]);
        }
        if !passwords.is_empty() {
            record(&mut info, EXT_PASSWORD, &[1]); // required = 1 (deliberate: no optional mode)
        }
        // 0x03 key auth: appended per connection by info() (it carries a fresh challenge).
        if let Some(m) = &motd {
            record(&mut info, EXT_MOTD, m.as_bytes());
        }
        let keys = keys.into_iter().map(|k| (sha256(&k), k)).collect();
        Ext { info, passwords, keys }
    }

    /// Any auth method configured. Every configured method is advertised as required.
    pub fn auth_required(&self) -> bool {
        !self.passwords.is_empty() || !self.keys.is_empty()
    }

    pub fn key_auth(&self) -> bool {
        !self.keys.is_empty()
    }

    /// The INFO payload (after the Wisp header). `challenge` must be Some when key_auth().
    pub fn info(&self, challenge: Option<&Challenge>) -> Cow<'_, [u8]> {
        if self.info.is_empty() {
            return Cow::Borrowed(&[2, 0]); // Ext::default()
        }
        match challenge.filter(|_| self.key_auth()) {
            None => Cow::Borrowed(&self.info),
            Some(ch) => {
                let mut v = self.info.clone();
                let mut meta = Vec::with_capacity(2 + CHALLENGE_LEN);
                meta.extend_from_slice(&[1, ALG_ED25519]); // required = 1, algorithms = ed25519
                meta.extend_from_slice(ch);
                record(&mut v, EXT_CERT, &meta);
                Cow::Owned(v)
            }
        }
    }

    /// Decide on a v2 client's INFO extension data (the bytes after major/minor).
    /// Ok = accept (send CONTINUE); Err(reason) = send CLOSE(0, reason) and close.
    pub fn check(&self, data: &[u8], challenge: Option<&Challenge>) -> Result<(), u8> {
        if !self.auth_required() {
            // deliberate: without auth nothing in the client's records matters to us, so they
            // are not inspected (pre-20.18 behaviour, also for malformed records).
            return Ok(());
        }
        let ci = parse_records(data).map_err(|()| CLOSE_INCOMPATIBLE)?;
        let mut ok = false;
        // Every method the client offers (and we support) must verify; one is enough.
        if let Some(meta) = ci.password.filter(|_| !self.passwords.is_empty()) {
            if !self.password_ok(meta) {
                return Err(CLOSE_BAD_PASSWORD);
            }
            ok = true;
        }
        if let Some(meta) = ci.cert.filter(|_| self.key_auth()) {
            if !challenge.is_some_and(|ch| self.signature_ok(meta, ch)) {
                return Err(CLOSE_BAD_SIGNATURE);
            }
            ok = true;
        }
        if ok {
            Ok(())
        } else {
            Err(CLOSE_AUTH_REQUIRED)
        }
    }

    /// Constant time with respect to the stored credentials: the client's credential is hashed
    /// once and compared with every entry without early exit, so timing tells neither whether the
    /// user exists nor how much of the password matched.
    fn password_ok(&self, meta: &[u8]) -> bool {
        if meta.is_empty() || meta[0] as usize > meta.len() - 1 {
            return false; // user length beyond the payload: malformed = wrong credentials
        }
        let d = digest(&SHA256, meta);
        let d = d.as_ref();
        let mut hit = 0u8;
        for p in &self.passwords {
            let mut x = 0u8;
            for i in 0..32 {
                x |= p[i] ^ d[i];
            }
            hit |= (std::hint::black_box(x) == 0) as u8;
        }
        hit == 1
    }

    /// epoxy-tls sends `algorithm | hash | signature` (97 bytes); the spec puts
    /// `u8 user_len | user` in front. Both are accepted (lengths never collide: the spec form is
    /// >= 98 bytes); the username is ignored, keys are not bound to users (as in epoxy).
    fn signature_ok(&self, meta: &[u8], challenge: &Challenge) -> bool {
        let body = if meta.len() == CERT_BODY {
            meta
        } else if !meta.is_empty() && meta.len() == 1 + meta[0] as usize + CERT_BODY {
            &meta[1 + meta[0] as usize..]
        } else {
            return false;
        };
        if body[0] != ALG_ED25519 {
            return false;
        }
        let (hash, sig) = (&body[1..33], &body[33..]);
        self.keys.iter().filter(|(h, _)| h[..] == *hash).any(|(_, k)| UnparsedPublicKey::new(&ED25519, k).verify(challenge, sig).is_ok())
    }
}

/// Records of a client INFO that the server looks at. Unknown ids are skipped.
#[derive(Default, Debug, PartialEq)]
pub struct ClientInfo<'a> {
    pub udp: bool,
    pub password: Option<&'a [u8]>,
    pub cert: Option<&'a [u8]>,
}

/// Parse the extension records of a client INFO. Err = malformed: a truncated header or
/// payload, trailing bytes that are not a whole record, or a repeated id.
pub fn parse_records(mut data: &[u8]) -> Result<ClientInfo<'_>, ()> {
    let mut out = ClientInfo::default();
    let mut seen = [0u64; 4];
    while !data.is_empty() {
        if data.len() < 5 {
            return Err(());
        }
        let id = data[0];
        let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        let rest = &data[5..];
        if rest.len() < len {
            return Err(());
        }
        let (meta, tail) = rest.split_at(len);
        let (w, b) = ((id >> 6) as usize, 1u64 << (id & 63));
        if seen[w] & b != 0 {
            return Err(());
        }
        seen[w] |= b;
        match id {
            EXT_UDP => out.udp = true,
            EXT_PASSWORD => out.password = Some(meta),
            EXT_CERT => out.cert = Some(meta),
            _ => {}
        }
        data = tail;
    }
    Ok(out)
}

fn sha256(b: &[u8]) -> [u8; 32] {
    digest(&SHA256, b).as_ref().try_into().unwrap()
}

/// A fresh key-auth challenge; None if the OS RNG fails (the caller then refuses the client).
pub fn new_challenge() -> Option<Box<Challenge>> {
    let mut ch = Box::new([0u8; CHALLENGE_LEN]);
    ring::rand::SystemRandom::new().fill(&mut ch[..]).ok()?;
    Some(ch)
}

/// `--auth-file`: one `user:password` per line (split at the first ':', so passwords may contain
/// ':'). Blank lines and lines starting with '#' are skipped. Error messages never echo secrets.
pub fn parse_auth_file(text: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((user, pass)) = line.split_once(':') else {
            return Err(format!("line {}: expected user:password", n + 1));
        };
        if user.is_empty() || user.len() > 255 {
            return Err(format!("line {}: user name must be 1..=255 bytes", n + 1));
        }
        let mut wire = Vec::with_capacity(1 + line.len());
        wire.push(user.len() as u8);
        wire.extend_from_slice(user.as_bytes());
        wire.extend_from_slice(pass.as_bytes());
        out.push(sha256(&wire));
    }
    if out.is_empty() {
        return Err("no user:password lines".into());
    }
    Ok(out)
}

/// `--cert-auth-key`: ed25519 public keys as PEM "PUBLIC KEY" (SPKI) blocks, e.g. from
/// `openssl pkey -in key.pem -pubout` (the format epoxy-server reads). A file may hold several.
pub fn parse_key_pem(pem: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    for der in SubjectPublicKeyInfoDer::pem_slice_iter(pem) {
        let der = der.map_err(|e| format!("bad PEM: {e}"))?;
        let d: &[u8] = der.as_ref();
        match d.strip_prefix(&ED25519_SPKI_PREFIX[..]) {
            Some(k) if k.len() == 32 => out.push(k.try_into().unwrap()),
            _ => return Err("not an ed25519 public key".into()),
        }
    }
    if out.is_empty() {
        return Err("no PUBLIC KEY block".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn rec(id: u8, meta: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        record(&mut v, id, meta);
        v
    }
    fn pw_meta(user: &str, pass: &str) -> Vec<u8> {
        let mut m = vec![user.len() as u8];
        m.extend_from_slice(user.as_bytes());
        m.extend_from_slice(pass.as_bytes());
        m
    }
    fn pw_ext() -> Ext {
        Ext::new(false, parse_auth_file("# c\n\nalice:s3cr:et\r\nbob:\n").unwrap(), vec![], None)
    }
    fn keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap()
    }

    #[test]
    fn default_info_is_bare_v2() {
        assert_eq!(&*Ext::default().info(None), &[2, 0]);
        assert_eq!(&*Ext::new(false, vec![], vec![], None).info(None), &[2, 0]);
        assert!(!Ext::default().auth_required());
        // 20.16 + 20.18: UDP only = the pre-20.18 INFO bytes exactly; with MOTD, records in id order
        assert_eq!(&*Ext::new(true, vec![], vec![], None).info(None), &[2, 0, 0x01, 0, 0, 0, 0]);
        let e = Ext::new(true, vec![], vec![], Some("m".into()));
        assert_eq!(&*e.info(None), &[2, 0, 0x01, 0, 0, 0, 0, 0x04, 1, 0, 0, 0, b'm']);
        assert!(!e.auth_required());
    }

    #[test]
    fn info_records() {
        let e = Ext::new(false, parse_auth_file("u:p").unwrap(), vec![], Some("hi".into()));
        let mut want = vec![2, 0];
        want.extend(rec(EXT_PASSWORD, &[1]));
        want.extend(rec(EXT_MOTD, b"hi"));
        assert_eq!(&*e.info(None), &want[..]);
        let info = e.info(None);
        let ci = parse_records(&info[2..]).unwrap();
        assert_eq!(ci.password, Some(&[1u8][..]));
        let k = keypair();
        let e = Ext::new(false, vec![], vec![k.public_key().as_ref().try_into().unwrap()], None);
        let ch = [7u8; CHALLENGE_LEN];
        let info = e.info(Some(&ch));
        let ci = parse_records(&info[2..]).unwrap();
        let meta = ci.cert.unwrap();
        assert_eq!(&meta[..2], &[1, ALG_ED25519]);
        assert_eq!(&meta[2..], &ch);
    }

    #[test]
    fn parse_malformed() {
        assert_eq!(parse_records(&[]), Ok(ClientInfo::default()));
        assert!(parse_records(&[0x02]).is_err()); // truncated header
        assert!(parse_records(&[0x02, 5, 0, 0, 0, 1, 2]).is_err()); // truncated payload
        assert!(parse_records(&[0x02, 0xff, 0xff, 0xff, 0xff, 1]).is_err()); // huge length
        let mut two = rec(0x02, b"\x01ab");
        two.extend(rec(0x02, b"\x01ab"));
        assert!(parse_records(&two).is_err()); // repeated id
        let mut trail = rec(0x01, b"");
        trail.extend([0x02, 0]);
        assert!(parse_records(&trail).is_err()); // trailing partial record
        let mut ok = rec(0x99, &[0u8; 1000]); // unknown id skipped
        ok.extend(rec(0x01, b""));
        ok.extend(rec(0x05, b""));
        let ci = parse_records(&ok).unwrap();
        assert!(ci.udp && ci.password.is_none() && ci.cert.is_none());
    }

    #[test]
    fn password_check() {
        let e = pw_ext();
        assert_eq!(e.check(&rec(EXT_PASSWORD, &pw_meta("alice", "s3cr:et")), None), Ok(()));
        assert_eq!(e.check(&rec(EXT_PASSWORD, &pw_meta("bob", "")), None), Ok(()));
        assert_eq!(e.check(&rec(EXT_PASSWORD, &pw_meta("alice", "s3cr:eT")), None), Err(CLOSE_BAD_PASSWORD));
        assert_eq!(e.check(&rec(EXT_PASSWORD, &pw_meta("alice", "s3cr:et ")), None), Err(CLOSE_BAD_PASSWORD));
        assert_eq!(e.check(&rec(EXT_PASSWORD, &pw_meta("mallory", "s3cr:et")), None), Err(CLOSE_BAD_PASSWORD));
        // user/password boundary matters: "alices3cr:et" split differently must fail
        assert_eq!(e.check(&rec(EXT_PASSWORD, &pw_meta("alic", "es3cr:et")), None), Err(CLOSE_BAD_PASSWORD));
        assert_eq!(e.check(&rec(EXT_PASSWORD, &[]), None), Err(CLOSE_BAD_PASSWORD));
        assert_eq!(e.check(&rec(EXT_PASSWORD, &[9, b'a']), None), Err(CLOSE_BAD_PASSWORD)); // ulen too big
        assert_eq!(e.check(&[], None), Err(CLOSE_AUTH_REQUIRED));
        assert_eq!(e.check(&rec(EXT_UDP, &[]), None), Err(CLOSE_AUTH_REQUIRED));
        assert_eq!(e.check(&rec(EXT_CERT, &[0; 97]), None), Err(CLOSE_AUTH_REQUIRED)); // not offered
        assert_eq!(e.check(&[EXT_PASSWORD, 1], None), Err(CLOSE_INCOMPATIBLE));
        // no auth configured: records are not inspected at all
        assert_eq!(Ext::default().check(&[EXT_PASSWORD, 1], None), Ok(()));
    }

    #[test]
    fn auth_file_errors() {
        assert!(parse_auth_file("").is_err());
        assert!(parse_auth_file("nocolon").is_err());
        assert!(parse_auth_file(":pw").is_err());
        assert!(parse_auth_file(&format!("{}:p", "u".repeat(256))).is_err());
        let e = parse_auth_file("secretuser-secretpass").unwrap_err();
        assert!(!e.contains("secret"), "error must not echo the line");
    }

    #[test]
    fn signature_check() {
        let k = keypair();
        let other = keypair();
        let pubk: [u8; 32] = k.public_key().as_ref().try_into().unwrap();
        let e = Ext::new(false, vec![], vec![pubk], None);
        let ch = new_challenge().unwrap();
        let body = |kp: &Ed25519KeyPair, ch: &Challenge, alg: u8| {
            let mut m = vec![alg];
            m.extend_from_slice(&sha256(kp.public_key().as_ref()));
            m.extend_from_slice(kp.sign(ch).as_ref());
            m
        };
        let good = body(&k, &ch, ALG_ED25519);
        assert_eq!(e.check(&rec(EXT_CERT, &good), Some(&ch)), Ok(())); // epoxy form
        let mut spec = vec![3, b'b', b'o', b'b'];
        spec.extend_from_slice(&good);
        assert_eq!(e.check(&rec(EXT_CERT, &spec), Some(&ch)), Ok(())); // spec form with username
        let mut spec0 = vec![0];
        spec0.extend_from_slice(&good);
        assert_eq!(e.check(&rec(EXT_CERT, &spec0), Some(&ch)), Ok(()));
        let wrong_ch = [0u8; CHALLENGE_LEN];
        assert_eq!(e.check(&rec(EXT_CERT, &good), Some(&wrong_ch)), Err(CLOSE_BAD_SIGNATURE));
        assert_eq!(e.check(&rec(EXT_CERT, &good), None), Err(CLOSE_BAD_SIGNATURE));
        assert_eq!(e.check(&rec(EXT_CERT, &body(&other, &ch, 1)), Some(&ch)), Err(CLOSE_BAD_SIGNATURE));
        assert_eq!(e.check(&rec(EXT_CERT, &body(&k, &ch, 2)), Some(&ch)), Err(CLOSE_BAD_SIGNATURE));
        // other key's signature under our key's hash
        let mut forged = body(&other, &ch, 1);
        forged[1..33].copy_from_slice(&sha256(&pubk));
        assert_eq!(e.check(&rec(EXT_CERT, &forged), Some(&ch)), Err(CLOSE_BAD_SIGNATURE));
        assert_eq!(e.check(&rec(EXT_CERT, &good[..96]), Some(&ch)), Err(CLOSE_BAD_SIGNATURE));
        assert_eq!(e.check(&rec(EXT_CERT, &[]), Some(&ch)), Err(CLOSE_BAD_SIGNATURE));
        assert_eq!(e.check(&[], Some(&ch)), Err(CLOSE_AUTH_REQUIRED));
    }

    #[test]
    fn both_methods() {
        let k = keypair();
        let e = Ext::new(false, parse_auth_file("u:p").unwrap(), vec![k.public_key().as_ref().try_into().unwrap()], None);
        let ch = [1u8; CHALLENGE_LEN];
        let info = e.info(Some(&ch));
        let ci = parse_records(&info[2..]).unwrap();
        assert!(ci.password.is_some() && ci.cert.is_some());
        let mut c = vec![ALG_ED25519];
        c.extend_from_slice(&sha256(k.public_key().as_ref()));
        c.extend_from_slice(k.sign(&ch).as_ref());
        assert_eq!(e.check(&rec(EXT_CERT, &c), Some(&ch)), Ok(()));
        assert_eq!(e.check(&rec(EXT_PASSWORD, &pw_meta("u", "p")), Some(&ch)), Ok(()));
        let mut both = rec(EXT_PASSWORD, &pw_meta("u", "x"));
        both.extend(rec(EXT_CERT, &c));
        assert_eq!(e.check(&both, Some(&ch)), Err(CLOSE_BAD_PASSWORD)); // an offered method failed
    }

    #[test]
    fn key_pem() {
        let k = keypair();
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(k.public_key().as_ref());
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", b64(&der));
        assert_eq!(parse_key_pem(pem.as_bytes()).unwrap(), vec![<[u8; 32]>::try_from(k.public_key().as_ref()).unwrap()]);
        let two = format!("{pem}{pem}");
        assert_eq!(parse_key_pem(two.as_bytes()).unwrap().len(), 2);
        assert!(parse_key_pem(b"nothing").is_err());
        let rsa_like = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", b64(&[0x30, 0x03, 1, 2, 3]));
        assert!(parse_key_pem(rsa_like.as_bytes()).is_err());
    }

    fn b64(d: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in d.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
            }
        }
        s
    }
}
