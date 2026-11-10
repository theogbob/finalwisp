//! 20.13 Built-in TLS via kernel TLS (kTLS).
//! rustls (ring) runs only the handshake, inside the epoll loop. Then the session keys move into
//! the kernel (TCP_ULP "tls" + TLS_TX/TLS_RX), and every later read/write/writev/splice on the
//! client socket is plain: the kernel en/decrypts. There is no userspace TLS data path.
//! See note 20.06 (section 20.13).
//! unsafe (60.16): blocks without their own SAFETY comment are plain libc calls whose pointer arguments come from a
//! live local or slice with the length taken from the same value (or are plain integers); no pointer outlives the call.
use rustls::crypto::ring as ring_provider;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, DnsName, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ParsedCertificate, ResolvesServerCert, ServerConnectionData, UnbufferedServerConnection};
use rustls::sign::CertifiedKey;
use rustls::unbuffered::{ConnectionState, EncodeError, EncodeTlsData};
use rustls::{ConnectionTrafficSecrets, ExtractedSecrets, ProtocolVersion, ServerConfig, SupportedCipherSuite};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// linux/tcp.h, linux/socket.h, linux/tls.h (defined here so we do not depend on the libc version)
const TCP_ULP: libc::c_int = 31;
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
const TLS_SET_RECORD_TYPE: libc::c_int = 1; // cmsg types (linux/tls.h)
const TLS_GET_RECORD_TYPE: libc::c_int = 2;
pub const REC_ALERT: u8 = 21;
pub const REC_HANDSHAKE: u8 = 22;
const TLS_1_2_VERSION: u16 = 0x0303;
const TLS_1_3_VERSION: u16 = 0x0304;
const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;
const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

/// struct tls_crypto_info + tls12_crypto_info_aes_gcm_128 (linux/tls.h)
#[repr(C)]
struct AesGcm128 {
    version: u16,
    cipher_type: u16,
    iv: [u8; 8],
    key: [u8; 16],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}
/// tls12_crypto_info_aes_gcm_256
#[repr(C)]
struct AesGcm256 {
    version: u16,
    cipher_type: u16,
    iv: [u8; 8],
    key: [u8; 32],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}
/// tls12_crypto_info_chacha20_poly1305 (salt[0])
#[repr(C)]
struct Chacha20Poly1305 {
    version: u16,
    cipher_type: u16,
    iv: [u8; 12],
    key: [u8; 32],
    rec_seq: [u8; 8],
}
const _: () = assert!(size_of::<AesGcm128>() == 40 && size_of::<AesGcm256>() == 56 && size_of::<Chacha20Poly1305>() == 56);

/// Largest TLS record we accept during the handshake: 2^14 plaintext + 2048 expansion (RFC 5246 6.2.3).
pub const MAX_RECORD: usize = 16384 + 2048;
pub const HEADER: usize = 5;

/// Body length of the record whose 5-byte header is `h`, or None if it cannot be a TLS record
/// (plain HTTP, garbage): content type 20..=23, legacy version major 3, sane length.
pub fn record_len(h: &[u8]) -> Option<usize> {
    let len = u16::from_be_bytes([h[3], h[4]]) as usize;
    ((20..=23).contains(&h[0]) && h[1] == 3 && len <= MAX_RECORD).then_some(len)
}

fn kernel_cipher(s: &SupportedCipherSuite) -> Option<u16> {
    let name = format!("{:?}", s.suite());
    if name.contains("AES_128_GCM") {
        Some(TLS_CIPHER_AES_GCM_128)
    } else if name.contains("AES_256_GCM") {
        Some(TLS_CIPHER_AES_GCM_256)
    } else if name.contains("CHACHA20_POLY1305") {
        Some(TLS_CIPHER_CHACHA20_POLY1305)
    } else {
        None
    }
}

fn kernel_version(v: ProtocolVersion) -> Option<u16> {
    match v {
        ProtocolVersion::TLSv1_2 => Some(TLS_1_2_VERSION),
        ProtocolVersion::TLSv1_3 => Some(TLS_1_3_VERSION),
        _ => None,
    }
}

/// setsockopt with the option value `v` (60.16: the length is always size_of::<T>(), so the kernel never reads past `v`)
fn setsockopt<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, v: &T) -> io::Result<()> {
    // SAFETY: v is a live &T and the kernel reads exactly size_of::<T>() bytes from it
    if unsafe { libc::setsockopt(fd, level, name, v as *const T as *const _, size_of::<T>() as _) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_ulp(fd: RawFd) -> io::Result<()> {
    setsockopt(fd, libc::IPPROTO_TCP, TCP_ULP, b"tls") // the 3 bytes "tls", no NUL
}

/// Install one direction (TLS_TX or TLS_RX). AES-GCM: the 12-byte rustls IV is 4 bytes salt
/// (implicit) + 8 bytes iv; ChaCha20-Poly1305 takes all 12 as iv. rec_seq is big-endian.
fn set_raw(fd: RawFd, dir: libc::c_int, version: u16, cipher: u16, key: &[u8], iv: &[u8], seq: u64) -> io::Result<()> {
    let rec_seq = seq.to_be_bytes();
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, "kTLS key/iv length");
    if iv.len() != 12 {
        return Err(bad());
    }
    // TLS 1.2 AES-GCM TX: rustls built record k's nonce as salt || (base XOR k) and extracts `base`; the
    // kernel instead sends salt || iv for its first record and increments iv by one per record (no XOR,
    // net/tls/tls.h tls_advance_record_sn). Passing `base` would reuse the Finished record's nonce
    // (seq 0) = AES-GCM key compromise. Start the kernel at base + seq: every nonce rustls used is
    // base ^ k <= base + k < base + seq (k < seq), so the ranges cannot meet before a 2^64 wrap.
    // (TLS 1.3 and ChaCha20 XOR the sequence into the iv in both, so they take `base` unchanged;
    // TLS 1.2 GCM RX reads the explicit nonce from each record.)
    let mut explicit = [0u8; 8];
    explicit.copy_from_slice(&iv[4..]);
    if version == TLS_1_2_VERSION && dir == TLS_TX && cipher != TLS_CIPHER_CHACHA20_POLY1305 {
        explicit = u64::from_be_bytes(explicit).wrapping_add(seq).to_be_bytes();
    }
    match cipher {
        TLS_CIPHER_AES_GCM_128 => {
            let mut c =
                AesGcm128 { version, cipher_type: cipher, iv: explicit, key: key.try_into().map_err(|_| bad())?, salt: [0; 4], rec_seq };
            c.salt.copy_from_slice(&iv[..4]);
            setsockopt(fd, SOL_TLS, dir, &c)
        }
        TLS_CIPHER_AES_GCM_256 => {
            let mut c =
                AesGcm256 { version, cipher_type: cipher, iv: explicit, key: key.try_into().map_err(|_| bad())?, salt: [0; 4], rec_seq };
            c.salt.copy_from_slice(&iv[..4]);
            setsockopt(fd, SOL_TLS, dir, &c)
        }
        TLS_CIPHER_CHACHA20_POLY1305 => {
            let c = Chacha20Poly1305 {
                version,
                cipher_type: cipher,
                iv: iv.try_into().unwrap(),
                key: key.try_into().map_err(|_| bad())?,
                rec_seq,
            };
            setsockopt(fd, SOL_TLS, dir, &c)
        }
        _ => Err(io::Error::new(io::ErrorKind::Unsupported, "cipher not supported by kTLS")),
    }
}

fn set_dir(fd: RawFd, dir: libc::c_int, version: u16, (seq, s): &(u64, ConnectionTrafficSecrets)) -> io::Result<()> {
    let (cipher, key, iv) = match s {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (TLS_CIPHER_AES_GCM_128, key, iv),
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (TLS_CIPHER_AES_GCM_256, key, iv),
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (TLS_CIPHER_CHACHA20_POLY1305, key, iv),
        _ => return Err(io::Error::new(io::ErrorKind::Unsupported, "cipher not supported by kTLS")),
    };
    set_raw(fd, dir, version, cipher, key.as_ref(), iv.as_ref(), *seq)
}

/// Move a finished session into the kernel. The caller must have flushed every rustls record to
/// the socket first (bytes written after TLS_TX would be encrypted again).
pub fn install(fd: RawFd, version: ProtocolVersion, secrets: &ExtractedSecrets) -> io::Result<()> {
    let v = kernel_version(version).ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "TLS version"))?;
    set_ulp(fd)?;
    set_dir(fd, TLS_TX, v, &secrets.tx)?;
    set_dir(fd, TLS_RX, v, &secrets.rx)
}

/// A connected loopback TCP pair (server side first).
fn loopback_pair() -> io::Result<(std::net::TcpStream, std::net::TcpStream)> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    let peer = std::net::TcpStream::connect(l.local_addr()?)?;
    Ok((l.accept()?.0, peer))
}

/// Try TCP_ULP + TLS_TX + TLS_RX with dummy keys on a fresh loopback connection.
fn probe_one(version: u16, cipher: u16) -> io::Result<()> {
    let (s, _peer) = loopback_pair()?;
    let fd = s.as_raw_fd();
    set_ulp(fd)?;
    let key = [0u8; 32];
    let key = if cipher == TLS_CIPHER_AES_GCM_128 { &key[..16] } else { &key[..] };
    set_raw(fd, TLS_TX, version, cipher, key, &[0; 12], 0)?;
    set_raw(fd, TLS_RX, version, cipher, key, &[0; 12], 0)
}

/// 20.17 In-kernel kTLS rekey (a second TLS_TX/TLS_RX on a TLS 1.3 socket, needed for KeyUpdate)
/// landed in Linux 6.14; older kernels refuse it with EBUSY ("we don't support set crypto info
/// more than one time", net/tls/tls_main.c up to v6.13). Probe: TLS_TX twice on a TLS 1.3 loopback
/// socket. Err = no rekey, with the reason for the startup log. Fail safe: any error = no rekey.
fn probe_rekey(cipher: u16) -> Result<(), String> {
    let r = (|| {
        let (s, _peer) = loopback_pair()?;
        let fd = s.as_raw_fd();
        set_ulp(fd)?;
        let key = [0u8; 32];
        let key = if cipher == TLS_CIPHER_AES_GCM_128 { &key[..16] } else { &key[..] };
        set_raw(fd, TLS_TX, TLS_1_3_VERSION, cipher, key, &[0; 12], 0)?;
        set_raw(fd, TLS_TX, TLS_1_3_VERSION, cipher, key, &[1; 12], 0)
    })();
    match r {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => Err("this kernel has no kTLS rekey (Linux < 6.14)".into()),
        Err(e) => Err(format!("kTLS rekey probe failed ({e}), assuming no kTLS rekey")),
    }
}

/// 80.01 F3 what to do without kTLS: finalwisp has no userspace TLS data path.
const PROXY_HINT: &str = "finalwisp's wss:// needs kTLS; without it, run a TLS-terminating proxy (nginx, Caddy, HAProxy) \
                          in front and serve ws:// (no --tls-cert/--tls-key)";

/// 80.01 F3 startup error when TCP_ULP "tls" fails. ENOPROTOOPT = no ULP support at all (Linux < 4.13).
/// ENOENT = the ULP is not registered: the module is not loaded, or none is installed for this kernel (Debian 11's
/// 5.10 is built without CONFIG_TLS). `modules_dep`: /lib/modules/<release>/modules.dep (None = unreadable, e.g. in
/// a container): no tls.ko* in it = no module installed.
fn no_ulp_message(e: &io::Error, release: &str, modules_dep: Option<&str>) -> String {
    let has_module =
        modules_dep.map(|d| d.lines().filter_map(|l| l.split(':').next()).any(|p| p.ends_with("/tls.ko") || p.contains("/tls.ko.")));
    match e.raw_os_error() {
        Some(libc::ENOPROTOOPT) => {
            return format!(
                "kernel TLS (kTLS) is not available: this kernel ({release}) has no TCP_ULP (Linux < 4.13). {PROXY_HINT}; \
                 or use a kernel with kTLS (Linux 4.17+, CONFIG_TLS)."
            )
        }
        Some(libc::ENOENT) if has_module == Some(false) => {
            return format!(
                "kernel TLS (kTLS) is not available: no tls module is installed for this kernel ({release}; none in \
                 /lib/modules/{release}/modules.dep; e.g. Debian 11's kernel is built without CONFIG_TLS). {PROXY_HINT}; \
                 or use a kernel with kTLS (Linux 4.17+, CONFIG_TLS)."
            )
        }
        _ => {}
    }
    format!(
        "kernel TLS (kTLS) is not available: setsockopt(TCP_ULP, \"tls\"): {e}. Load the module with \
         `sudo modprobe tls` (persist: echo tls | sudo tee /etc/modules-load.d/tls.conf), or run the \
         server with CAP_NET_ADMIN so the kernel can autoload it. If this kernel ({release}) has no tls module: {PROXY_HINT}."
    )
}

/// 80.01 F3 kTLS with a transmit side only (Linux 4.13-4.16, e.g. Amazon Linux 2's 4.14): TLS 1.2
/// AES-128-GCM, which every kTLS kernel has, is accepted for TLS_TX, and TLS_RX is an unknown option
/// (ENOPROTOOPT, v4.14 do_tls_setsockopt). Any other RX error is not this case (review, 2 of 2).
fn rx_missing() -> bool {
    let Ok((s, _peer)) = loopback_pair() else { return false };
    let fd = s.as_raw_fd();
    let tx = |dir| set_raw(fd, dir, TLS_1_2_VERSION, TLS_CIPHER_AES_GCM_128, &[0; 16], &[0; 12], 0);
    set_ulp(fd).is_ok() && tx(TLS_TX).is_ok() && tx(TLS_RX).is_err_and(|e| e.raw_os_error() == Some(libc::ENOPROTOOPT))
}

/// 80.01 F3 startup error when no cipher suite passed the TX + RX probe.
fn no_suite_message(rx_missing: bool, release: &str) -> String {
    if rx_missing {
        format!("kernel TLS (kTLS) on this kernel ({release}) can encrypt but not decrypt (TLS_RX needs Linux 4.17+). {PROXY_HINT}.")
    } else {
        format!("kernel TLS (kTLS) is loaded but supports none of AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305 ({release}). {PROXY_HINT}.")
    }
}

// ------------------------------------------------------------------ 20.17 certificates (SNI, reload)

/// 20.17 The certificate set: one CertifiedKey per --tls-cert/--tls-key pair, in flag order.
/// Picked per handshake by SNI; swapped as a whole on SIGHUP (`reload`). New handshakes read the
/// current set once (one uncontended lock + Arc clone per handshake); live kTLS connections never
/// look at it again.
#[derive(Debug)]
pub struct Certs {
    pairs: Vec<(String, String)>,
    provider: Arc<CryptoProvider>,
    set: Mutex<Arc<Vec<Arc<CertifiedKey>>>>,
}

fn load_pair(cert: &str, key: &str, provider: &CryptoProvider) -> Result<CertifiedKey, String> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cert).and_then(|it| it.collect::<Result<_, _>>()).map_err(|e| format!("--tls-cert {cert}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("--tls-cert {cert}: no certificate found"));
    }
    let der = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("--tls-key {key}: {e}"))?;
    let ck = CertifiedKey::from_der(certs, der, provider).map_err(|e| format!("tls: certificate/key {cert} {key}: {e}"))?;
    // SNI matching parses the end-entity certificate on every handshake: refuse one that does not parse.
    ck.end_entity_cert().and_then(ParsedCertificate::try_from).map_err(|e| format!("--tls-cert {cert}: {e}"))?;
    Ok(ck)
}

impl Certs {
    /// Re-read every pair from disk. All or nothing: on any error the current set stays in use.
    /// Returns the number of pairs now in use.
    pub fn reload(&self) -> Result<usize, String> {
        let set = self.pairs.iter().map(|(c, k)| load_pair(c, k, &self.provider).map(Arc::new)).collect::<Result<Vec<_>, _>>()?;
        let n = set.len();
        *self.set.lock().unwrap_or_else(|e| e.into_inner()) = Arc::new(set);
        Ok(n)
    }
    fn current(&self) -> Arc<Vec<Arc<CertifiedKey>>> {
        self.set.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// First pair whose end-entity certificate is valid for `sni` (SAN DNS names, wildcards: webpki
/// rules), else the first pair (no SNI, an IP literal, or no match).
fn pick(set: &[Arc<CertifiedKey>], sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
    if set.len() > 1 {
        if let Some(name) = sni.and_then(|s| DnsName::try_from(s).ok()) {
            let name = ServerName::DnsName(name);
            let ok = |ck: &CertifiedKey| {
                ck.end_entity_cert()
                    .and_then(ParsedCertificate::try_from)
                    .and_then(|p| rustls::client::verify_server_name(&p, &name))
                    .is_ok()
            };
            if let Some(ck) = set.iter().find(|ck| ok(ck)) {
                return Some(ck.clone());
            }
        }
    }
    set.first().cloned()
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        pick(&self.current(), hello.server_name())
    }
}

/// `server_config` result: the config, the reloadable cert set, and the rekey probe (`probe_rekey`).
pub type ServerSetup = (Arc<ServerConfig>, Arc<Certs>, Result<(), String>);

/// Build the server config: cert chains + keys from PEM file pairs (picked by SNI, 20.17), ALPN
/// http/1.1, TLS 1.2 + 1.3, only the cipher suites this kernel can offload (probed).
/// `server_order` (20.17 --tls-cipher-order server): AES-GCM before ChaCha20, and rustls ignores
/// the client's preference. The third value is the rekey probe (`probe_rekey`). Err = message for the operator.
pub fn server_config(pairs: &[(String, String)], server_order: bool) -> Result<ServerSetup, String> {
    let certs = Arc::new(Certs { pairs: pairs.to_vec(), provider: Arc::new(ring_provider::default_provider()), set: Mutex::default() });
    certs.reload()?;
    // Startup probe. TCP_ULP "tls" needs the `tls` kernel module; the kernel autoloads it only for
    // callers with CAP_NET_ADMIN, so an unprivileged server usually needs it preloaded.
    let (s, _peer) = loopback_pair()
        .map_err(|e| format!("kTLS startup probe: cannot open a TCP connection on 127.0.0.1 ({e}); is the loopback interface up?"))?;
    if let Err(e) = set_ulp(s.as_raw_fd()) {
        let release = crate::net::kernel_release();
        let dep = std::fs::read_to_string(format!("/lib/modules/{release}/modules.dep")).ok();
        return Err(no_ulp_message(&e, &release, dep.as_deref()));
    }
    drop((s, _peer));
    let mut provider = ring_provider::default_provider();
    provider.cipher_suites.retain(|s| {
        let v = kernel_version(s.version().version);
        match (v, kernel_cipher(s)) {
            (Some(v), Some(c)) => probe_one(v, c).is_ok(),
            _ => false,
        }
    });
    if provider.cipher_suites.is_empty() {
        return Err(no_suite_message(rx_missing(), &crate::net::kernel_release()));
    }
    let tls13 = provider.cipher_suites.iter().find(|s| s.version().version == ProtocolVersion::TLSv1_3);
    let rekey = tls13.and_then(kernel_cipher).map_or(Ok(()), probe_rekey);
    if server_order {
        // ChaCha20 last; stable, so the rest keeps the ring default order (AES-256-GCM, AES-128-GCM;
        // TLS 1.3 before 1.2). Measured: kTLS AES-GCM ~1.7-2x ChaCha20 (20.06 doc, 20.17).
        provider.cipher_suites.sort_by_key(|s| kernel_cipher(s) == Some(TLS_CIPHER_CHACHA20_POLY1305));
    }
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("tls: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(certs.clone());
    cfg.ignore_client_order = server_order;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    // deliberate: no TLS 1.3 session tickets. They are post-handshake records that rustls would
    // still owe the peer after the keys moved into the kernel. (TLS 1.2 session-id resumption via
    // the default in-memory cache still works: it happens inside the handshake.)
    cfg.send_tls13_tickets = 0;
    cfg.enable_secret_extraction = true;
    Ok((Arc::new(cfg), certs, rekey))
}

/// Whether a config offers a TLS 1.3 suite (the kTLS rekey probe runs only then; startup banner).
pub fn has_tls13(cfg: &ServerConfig) -> bool {
    cfg.crypto_provider().cipher_suites.iter().any(|s| s.version().version == ProtocolVersion::TLSv1_3)
}

/// Names of the cipher suites a config offers (for the startup banner).
pub fn suite_names(cfg: &ServerConfig) -> String {
    cfg.crypto_provider().cipher_suites.iter().map(|s| format!("{:?}", s.suite())).collect::<Vec<_>>().join(",")
}

// ------------------------------------------------------------------ 20.17 handshake (unbuffered rustls)

/// Outcome of one handshake step.
#[derive(Debug, PartialEq)]
pub enum Step {
    More,  // need the next record
    Done,  // handshake complete (after the output in `out` is sent)
    Fail,  // rustls rejected the handshake; `out` holds its alert (best effort)
    Close, // close_notify / peer closed during the handshake
}

fn encode(e: &mut EncodeTlsData<'_, ServerConnectionData>, out: &mut Vec<u8>) -> Result<(), ()> {
    let start = out.len();
    let mut room = 4096;
    loop {
        out.resize(start + room, 0);
        match e.encode(&mut out[start..]) {
            Ok(n) => {
                out.truncate(start + n);
                return Ok(());
            }
            Err(EncodeError::InsufficientSize(s)) if s.required_size > room => room = s.required_size,
            Err(_) => {
                out.truncate(start);
                return Err(());
            }
        }
    }
}

/// Feed `buf` (bytes rustls kept from earlier calls + one whole new record) to the unbuffered
/// rustls server and append every TLS record it wants to send to `out`. Returns the step and how
/// many bytes from the front of `buf` rustls is done with (the caller drops them; the rest must be
/// passed again, in front of the next record: a handshake message may span records).
pub fn hs_step(conn: &mut UnbufferedServerConnection, buf: &mut [u8], out: &mut Vec<u8>) -> (Step, usize) {
    let mut off = 0;
    loop {
        let st = conn.process_tls_records(&mut buf[off..]);
        off += st.discard;
        let step = match st.state {
            Ok(ConnectionState::EncodeTlsData(mut e)) => match encode(&mut e, out) {
                Ok(()) => continue,
                Err(()) => Step::Fail,
            },
            Ok(ConnectionState::TransmitTlsData(t)) => {
                t.done(); // the bytes are in `out`; the caller sends them before anything else
                continue;
            }
            Ok(ConnectionState::BlockedHandshake) => Step::More,
            Ok(ConnectionState::WriteTraffic(_)) => Step::Done, // TLS 1.3: also after our Finished (0.5-RTT)
            Ok(ConnectionState::PeerClosed | ConnectionState::Closed) => Step::Close,
            Ok(_) | Err(_) => Step::Fail, // application/early data before the handshake ended, or an error
        };
        return match step {
            Step::Done if conn.is_handshaking() => (Step::More, off),
            Step::Fail => {
                // rustls queued its fatal alert (after any records of the same flight) with the error:
                // drain exactly that queue. A deframe error does not consume the bad record, so one call
                // past the empty queue would deframe it again and queue a second alert (70.01 F1).
                // same buffer as before: rustls' deframer tracks offsets into it
                while conn.wants_write() {
                    match conn.process_tls_records(&mut buf[off..]).state {
                        Ok(ConnectionState::EncodeTlsData(mut e)) => {
                            if encode(&mut e, out).is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                (Step::Fail, off)
            }
            s => (s, off),
        };
    }
}

// ------------------------------------------------------------------ 20.17 kTLS control records

/// sendmsg one TLS record of content type `typ` through kTLS (cmsg SOL_TLS/TLS_SET_RECORD_TYPE).
/// Never blocks (MSG_DONTWAIT). The kernel closes any open data record first.
pub fn send_record(fd: RawFd, typ: u8, payload: &[u8]) -> io::Result<usize> {
    let mut cbuf = [0u64; 4]; // >= CMSG_SPACE(1), cmsghdr-aligned
    let mut iov = libc::iovec { iov_base: payload.as_ptr() as *mut _, iov_len: payload.len() };
    // SAFETY: msghdr is plain data (all-zero = no name, no iov, no control); CMSG_SPACE is arithmetic only
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(1) } as _;
    // SAFETY: msg_control points to cbuf (32 bytes, 8-aligned >= CMSG_SPACE(1)), so CMSG_FIRSTHDR is non-null
    // and the header plus its 1 data byte fit; iov and cbuf outlive the sendmsg call.
    let n = unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = SOL_TLS;
        (*c).cmsg_type = TLS_SET_RECORD_TYPE;
        (*c).cmsg_len = libc::CMSG_LEN(1) as _;
        *libc::CMSG_DATA(c) = typ;
        libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Best effort close_notify alert (level warning, description 0). Never blocks or fails.
pub fn send_close_notify(fd: RawFd) {
    let _ = send_record(fd, REC_ALERT, &[1, 0]);
}

/// recvmsg the next record from a kTLS socket with its content type (TLS_GET_RECORD_TYPE).
/// Called after read() failed with EIO, which kTLS returns when the next record is not
/// application data (the record stays queued). Ok((0, 0)) = EOF.
pub fn recv_record(fd: RawFd, buf: &mut [u8]) -> io::Result<(u8, usize)> {
    let mut cbuf = [0u64; 4];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
    // SAFETY: msghdr is plain data; recvmsg writes into buf (via iov) and cbuf within the lengths given, both live here
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = size_of::<[u64; 4]>() as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut typ = 0;
    // SAFETY: the kernel filled msg_control (cbuf) and set msg_controllen to the bytes it used;
    // CMSG_FIRSTHDR/NXTHDR return null past that length, so every dereferenced header is inside cbuf.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == SOL_TLS && (*c).cmsg_type == TLS_GET_RECORD_TYPE {
                typ = *libc::CMSG_DATA(c);
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    Ok((typ, n as usize))
}

/// A TLS 1.3 KeyUpdate handshake message (RFC 8446 4.6.3): type 24, length 1, request_update.
pub fn key_update_msg(request: bool) -> [u8; 5] {
    [24, 0, 0, 1, request as u8]
}

/// Some(update_requested) if `rec` is exactly one KeyUpdate message. (The kernel pauses RX
/// after a handshake record that starts with type 24; a KeyUpdate must end its record.)
pub fn parse_key_update(rec: &[u8]) -> Option<bool> {
    (rec.len() == 5 && rec[..4] == [24, 0, 0, 1] && rec[4] <= 1).then(|| rec[4] == 1)
}

/// 60.12 connections closed because a client sent a TLS 1.3 KeyUpdate that this kernel could not apply
/// (no kTLS rekey before Linux 6.14). Read by the metrics line (C5) if any.
pub static KEYUPDATE_CLOSES: AtomicU64 = AtomicU64::new(0);
/// Seconds (CLOCK_MONOTONIC) + 1 of the last KeyUpdate log line; 0 = none yet.
static KEYUPDATE_LOGGED: AtomicU64 = AtomicU64::new(0);
const KEYUPDATE_LOG_EVERY: u64 = 60;

fn monotonic_secs() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) }; // SAFETY: writes one timespec into the local ts
    ts.tv_sec as u64
}

/// 60.12 (decision 2026-10-27, option A): a client KeyUpdate whose new RX key the kernel refused
/// (`e`, from `rekey`) closes the connection. Count it; log one line at most every KEYUPDATE_LOG_EVERY
/// seconds (all worker threads together) with the reason and what to do. Called on a worker thread, so the line goes
/// through metrics::log_nowait (60.16: a direct stderr write could block the event loop on a full pipe, 70.05 / 50.02).
pub fn key_update_refused(e: &io::Error) {
    let n = KEYUPDATE_CLOSES.fetch_add(1, Ordering::Relaxed) + 1;
    let now = monotonic_secs() + 1;
    let last = KEYUPDATE_LOGGED.load(Ordering::Relaxed);
    if (last != 0 && now < last + KEYUPDATE_LOG_EVERY)
        || KEYUPDATE_LOGGED.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err()
    {
        return;
    }
    crate::metrics::log_nowait(refused_message(e, &crate::net::kernel_release(), n));
}

fn refused_message(e: &io::Error, release: &str, n: u64) -> String {
    let head = "finalwisp: tls: closed a connection: the client sent a TLS 1.3 KeyUpdate and";
    let count = format!("{n} such close(s) since start (logged at most every {KEYUPDATE_LOG_EVERY} s)");
    if e.raw_os_error() != Some(libc::EBUSY) {
        return format!("{head} the kernel refused the new key ({e}; kernel {release}); {count}");
    }
    // 60.12 (kucheck, source-verified): browsers never send KeyUpdate in practice; native rustls clients send
    // update_requested after 2^24 records under one AES-GCM key, never under ChaCha20. kTLS ChaCha20: Linux 5.11+.
    format!(
        "{head} this kernel ({release}) has no kTLS rekey (Linux < 6.14); {count}. Native rustls clients (e.g. native \
         wisp-mux/epoxy) rekey after 2^24 (16.8M) records under an AES-GCM key (browsers practically never: Firefox after ~1.8e10). Fix: Linux 6.14+, or \
         terminate TLS at a reverse proxy and serve ws:// to finalwisp; ChaCha20 suites never rekey (kernels with kTLS \
         ChaCha20, 5.11+)"
    )
}

/// Install a new TLS 1.3 traffic key on a live kTLS socket (kernel rekey, Linux 6.14+). RX: after
/// the peer's KeyUpdate record was read (the kernel returns EKEYEXPIRED until then). TX: after our
/// KeyUpdate record went out under the old key.
pub fn rekey(fd: RawFd, rx: bool, secrets: &(u64, ConnectionTrafficSecrets)) -> io::Result<()> {
    set_dir(fd, if rx { TLS_RX } else { TLS_TX }, TLS_1_3_VERSION, secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 60.37 review: a new directory only this user can enter (mode 0700, created by mkdir: fails on any existing path or
    /// symlink, so a name planted by another user is skipped, never followed). The name has the pid and the clock.
    fn private_temp_dir(prefix: &str) -> Result<std::path::PathBuf, String> {
        use std::os::unix::fs::DirBuilderExt;
        for n in 0..100u32 {
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("{prefix}-{}-{t:x}-{n}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(dir),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("{}: {e}", dir.display())),
            }
        }
        Err("no free temp directory name".into())
    }

    /// 60.37: a self-signed CN=localhost pair made once per test process with openssl(1) in the temp dir (no key in
    /// git). Paths (cert, key).
    fn throwaway_pair() -> (String, String) {
        static PAIR: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
        PAIR.get_or_init(|| {
            let dir = private_temp_dir("finalwisp-test-pair").unwrap();
            let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
            let ok = std::process::Command::new("openssl")
                .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2"])
                .args(["-subj", "/CN=localhost", "-keyout"])
                .arg(&key)
                .arg("-out")
                .arg(&cert)
                .stderr(std::process::Stdio::null())
                .status()
                .expect("the TLS tests need openssl(1) for a throwaway certificate");
            assert!(ok.success(), "openssl req failed");
            (cert.display().to_string(), key.display().to_string())
        })
        .clone()
    }
    #[test]
    fn record_header() {
        assert_eq!(record_len(&[22, 3, 1, 0x02, 0x00]), Some(512));
        assert_eq!(record_len(b"GET /"), None);
        assert_eq!(record_len(&[22, 3, 3, 0xff, 0xff]), None);
        assert_eq!(record_len(&[24, 3, 3, 0, 1]), None);
        assert_eq!(record_len(&[23, 2, 0, 0, 1]), None);
    }
    /// 70.01 F1 (fuzz, worker-stream TLS variant): a record rustls cannot deframe (an empty or
    /// oversized record, an unknown content type) fails the handshake with one fatal alert. hs_step's
    /// Fail branch called process_tls_records again on the same bytes after collecting the alert: a
    /// deframe error does not consume the record, so rustls deframed it a second time and queued a
    /// second fatal alert (debug builds: rustls' debug_assert!(!sent_fatal_alert) panics; release: the
    /// extra alert stays queued, never sent). `!wants_write()` catches it in release too. Fixed in
    /// base-1.2: hs_step drains only what rustls queued (`while conn.wants_write()`).
    /// The TLS 1.3 case below is the other shape the fix must keep: a process_msg error after
    /// ServerHello + CCS were queued (ClientHello without our ALPN): all three records go out.
    #[test]
    fn bad_record_fails_with_one_alert() {
        let provider = Arc::new(ring_provider::default_provider());
        let (cert, key) = throwaway_pair();
        let ck = Arc::new(load_pair(&cert, &key, &provider).unwrap());
        #[derive(Debug)]
        struct One(Arc<CertifiedKey>);
        impl ResolvesServerCert for One {
            fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                Some(self.0.clone())
            }
        }
        let mut cfg = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(One(ck)));
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        let run = |input: &[u8]| {
            let mut conn = UnbufferedServerConnection::new(cfg.clone()).unwrap();
            let (mut buf, mut out) = (input.to_vec(), Vec::new());
            let (step, _) = hs_step(&mut conn, &mut buf, &mut out);
            assert!(matches!(step, Step::Fail), "{input:?}");
            assert!(!conn.wants_write(), "a second alert was queued");
            let mut types = Vec::new();
            let mut r = &out[..];
            while r.len() >= 5 {
                types.push(r[0]);
                r = &r[(5 + u16::from_be_bytes([r[3], r[4]]) as usize).min(r.len())..];
            }
            (out, types)
        };
        // deframe errors (empty record, unknown type, longer than 2^14 + 2048): exactly one plaintext
        // alert, level fatal (2), decode_error (50)
        let mut big = vec![22u8, 3, 3, 0x48, 0x01];
        big.resize(5 + 0x4801, 0);
        for rec in [&[22u8, 3, 1, 0, 0][..], &[22, 3, 8, 0, 0], &[21, 3, 3, 0, 0], &[99, 3, 3, 0, 1, 0], &big] {
            assert_eq!(run(rec).0, [21, 3, 3, 0, 2, 2, 50], "{:?}", &rec[..5]);
        }
        // TLS 1.3 ClientHello offering only h2: ServerHello, CCS, then the (encrypted) alert
        let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        ccfg.alpn_protocols = vec![b"h2".to_vec()];
        let mut client = rustls::ClientConnection::new(Arc::new(ccfg), ServerName::try_from("localhost").unwrap()).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        assert_eq!(run(&hello).1, [REC_HANDSHAKE, 20, 23]);
    }
    /// 80.01 F3: the kTLS-missing messages pick the right advice
    #[test]
    fn no_ktls_messages() {
        let enoent = io::Error::from_raw_os_error(libc::ENOENT);
        let dep_without = "kernel/net/ipv4/tcp_bbr.ko.zst:\nkernel/net/tls/ktls_x.ko:\n";
        let dep_with = "kernel/net/ipv4/tcp_bbr.ko:\nkernel/net/tls/tls.ko.zst:\n";
        let m = no_ulp_message(&enoent, "5.10.0-28-amd64", Some(dep_without));
        assert!(m.contains("no tls module is installed") && m.contains("TLS-terminating proxy") && !m.contains("modprobe"), "{m}");
        let m = no_ulp_message(&io::Error::from_raw_os_error(libc::ENOPROTOOPT), "4.9.0", None);
        assert!(m.contains("no TCP_ULP (Linux < 4.13)") && m.contains("ws://") && !m.contains("modprobe"), "{m}");
        for (e, dep) in [(&enoent, Some(dep_with)), (&enoent, None), (&io::Error::from_raw_os_error(libc::EPERM), Some(dep_without))] {
            let m = no_ulp_message(e, "6.8.0", dep);
            assert!(m.contains("sudo modprobe tls") && m.contains("TLS-terminating proxy"), "{m}");
        }
        assert!(no_ulp_message(&enoent, "6.8.0", Some("kernel/net/tls/tls.ko:\n")).contains("modprobe"));
        let m = no_suite_message(true, "4.14.355");
        assert!(m.contains("TLS_RX needs Linux 4.17+") && m.contains("4.14.355") && m.contains("ws://"), "{m}");
        assert!(no_suite_message(false, "x").contains("supports none"));
    }
    #[test]
    fn key_update_refused_message() {
        let m = refused_message(&io::Error::from_raw_os_error(libc::EBUSY), "6.8.0-45-generic", 3);
        assert!(m.contains("Linux < 6.14") && m.contains("kernel (6.8.0-45-generic)") && m.contains("3 such close(s)"), "{m}");
        assert!(m.contains("reverse proxy") && m.contains("Linux 6.14+") && m.contains("16.8M"), "{m}");
        let m = refused_message(&io::Error::from_raw_os_error(libc::EINVAL), "7.0.0", 1);
        assert!(m.contains("refused the new key") && m.contains("kernel 7.0.0") && !m.contains("6.14"), "{m}");
    }
    #[test]
    fn key_update_message() {
        assert_eq!(parse_key_update(&key_update_msg(true)), Some(true));
        assert_eq!(parse_key_update(&key_update_msg(false)), Some(false));
        assert_eq!(parse_key_update(&[24, 0, 0, 1, 2]), None);
        assert_eq!(parse_key_update(&[24, 0, 0, 2, 0, 0]), None);
        assert_eq!(parse_key_update(&[4, 0, 0, 1, 0]), None);
        assert_eq!(parse_key_update(&[]), None);
    }
}
