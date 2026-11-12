//! 70.01 cfg(fuzzing) only (server/fuzz, cargo-fuzz): drives the real Worker on socketpairs, as the H1
//! test in worker/tests.rs does. Never compiled into the server. Harness code only (sockets, a fake resolver,
//! a loopback echo sink); every protocol byte goes through the unmodified Worker code paths.
use super::*;

/// The in-process echo "internet" (TCP + UDP on 127.0.0.1 and ::1). Only reachable when the harness
/// runs in its own network namespace (bwrap --unshare-net), checked in Harness::new.
pub const SINK_PORT: u16 = 4444;

/// 16 MiB + the longest frame header: the most `need` can legitimately be.
pub const NEED_MAX: usize = MAX_FRAME + 14;

pub fn client_hello(p: &[u8]) -> Option<&[u8]> {
    super::client_hello(p)
}
pub fn percent_decode(s: &str) -> String {
    super::percent_decode(s)
}

pub struct Conn {
    pub ci: u32,
    pub g: u32,
    pub peer: RawFd,
    /// bytes the peer managed to write into the socket (an upper bound for what the server read)
    pub sent: usize,
    /// server output seen by the peer (the first OUT_KEEP bytes are kept in `out`)
    pub got: usize,
    pub out: Vec<u8>,
    /// worker-tls: the client's kTLS key schedule (TLS 1.3 KeyUpdate) once the handshake is done
    pub ktls: Option<Box<rustls::kernel::KernelConnection<rustls::client::ClientConnectionData>>>,
    pub tcp: bool,
    /// control records the client received (type, first bytes)
    pub ctrl: Vec<(u8, Vec<u8>)>,
}
const OUT_KEEP: usize = 1 << 16;

pub struct Harness {
    pub w: Worker,
    dns_rx: mpsc::Receiver<DnsReq>,
    late: Vec<net::DnsResp>, // 70.10 final answers held back one resolver() call
    evs: Vec<libc::epoll_event>,
    pub tls: bool,
}

fn fixed_key() -> [u8; 32] {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap().public_key().as_ref().try_into().unwrap()
}

/// Sign a key-auth challenge with the harness key (the client side of ext key auth).
pub fn sign(challenge: &[u8]) -> Vec<u8> {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let k = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
    let mut m = vec![1u8]; // ALG_ED25519
    m.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, k.public_key().as_ref()).as_ref());
    m.extend_from_slice(k.sign(challenge).as_ref());
    m
}

/// Config variants. 0: defaults + loopback sink; 1: v2 auth (password u:p + ed25519 key) + MOTD + --upload-rate
/// 8K/16K (60.25); 2: --no-udp --no-prio
/// --no-splice --no-credit-v2, loopback filtered; 3: built-in TLS (if kTLS is available). Credit v2 (the default since
/// 60.13) runs in 0, 1 and 3 (60.16 review: it ran only in 1).
pub const VARIANTS: u8 = 4;

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

/// 60.37: the TLS variant's self-signed CN=localhost pair, made once per fuzz process with openssl(1) in the temp dir
/// (no key in git). Without openssl the TLS variant is disabled, as without kTLS.
fn throwaway_pair() -> Result<(String, String), String> {
    static PAIR: std::sync::OnceLock<Result<(String, String), String>> = std::sync::OnceLock::new();
    PAIR.get_or_init(|| {
        let dir = private_temp_dir("finalwisp-fuzz-pair")?;
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        let ok = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2"])
            .args(["-subj", "/CN=localhost", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("openssl(1) for a throwaway certificate: {e}"))?;
        if !ok.success() {
            return Err("openssl req failed".into());
        }
        Ok((cert.display().to_string(), key.display().to_string()))
    })
    .clone()
}

fn config(v: u8) -> Option<Config> {
    let ext = match v {
        1 => ext::Ext::new(true, ext::parse_auth_file("u:p\n").unwrap(), vec![fixed_key()], Some("motd".into())),
        _ => ext::Ext::default(),
    };
    let tls = if v == 3 {
        let pair = match throwaway_pair() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("fuzz harness: TLS variant disabled: {e}");
                return None;
            }
        };
        match tls::server_config(&[pair], false) {
            Ok((cfg, _, _)) => Some(cfg),
            Err(e) => {
                eprintln!("fuzz harness: TLS variant disabled: {e}");
                return None;
            }
        }
    } else {
        None
    };
    Some(Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads: 1,
        buffer: 128,
        filter: net::Filter::new(v != 2, false),
        connect_timeout: Duration::from_secs(10),
        dns_own: true, // 70.10 early answers (names with "late") exist only with the own resolver
        abort_close: true,
        splice: v != 2,
        balance: false,
        tfo: false,
        tls,
        udp: v != 2,
        tls_rekey: 0,
        notsent_lowat: 0,
        adapt_lowat: 0,
        keepalive: false,
        prio: v != 2,
        ext,
        credit_v2: v != 2,   // 20.30 credit v2 is the default (60.13); variant 2 (the off-switches) runs the base-2 rule
        credit_pace: v != 2, // 60.42 default on; variant 2 (the off-switches) runs without it
        park_rcvlock: if v == 1 { 512 << 10 } else { 0 }, // 60.47 opt-in: variant 1 runs with it
        adaptive_splice: v != 2, // 60.51 default on since v1.2.1; variant 2 (the off-switches) runs without it
        conn_gate: None,
        max_streams_per_conn: 0,
        policy: None,
        clientip: None,
        // 60.24 off: Worker::new registers each outbox in a process-wide list (one per fuzz input would grow it)
        log_conns: false,
        log_streams: false,
        want_peer: false,
        pace: net::Pacing::default(),
        unix: None,
        upstream: None,
        // 60.25 C10b variant 1: an upload limit (8 KiB/s, burst 16 KiB): reads end at arbitrary allowances, longer inputs
        // pause and resume on the 100 ms tick
        upload_rate: (v == 1).then_some((8192, 16384)),
        proxy_tcp: false,
        proxy_unix: false,
        proxy_from: Box::new([]),
        // 60.39 variant 1: a per-destination table at the top rates: every stream takes its token, none is refused (the
        // harness lives across inputs: a binding limit would make refusals depend on earlier inputs and the clock)
        dest_rate: (v == 1).then(|| Box::new(crate::destrate::DestTable::new(Some((1_000_000, 2_000_000)), Some(60_000_000)))),
    })
}

fn nonblocking_socket(dom: i32, ty: i32) -> RawFd {
    let fd = unsafe { libc::socket(dom, ty | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0);
    fd
}

fn bind_sink(v6: bool, udp: bool) -> RawFd {
    let addr: SocketAddr = if v6 { format!("[::1]:{SINK_PORT}") } else { format!("127.0.0.1:{SINK_PORT}") }.parse().unwrap();
    let fd = nonblocking_socket(if v6 { libc::AF_INET6 } else { libc::AF_INET }, if udp { libc::SOCK_DGRAM } else { libc::SOCK_STREAM });
    let one: i32 = 1;
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one as *const _ as *const _, 4) };
    let (ss, len) = net::sockaddr(&addr);
    let r = unsafe { libc::bind(fd, &ss as *const _ as *const _, len) };
    assert!(r == 0, "sink bind {addr}: {}", std::io::Error::last_os_error());
    if !udp {
        assert!(unsafe { libc::listen(fd, 1024) } == 0);
    }
    fd
}

/// Refuse to run with a real network: CONNECT targets must not leave the box.
fn assert_isolated() {
    let fd = nonblocking_socket(libc::AF_INET, libc::SOCK_DGRAM);
    let (ss, len) = net::sockaddr(&"1.1.1.1:53".parse().unwrap());
    let r = unsafe { libc::connect(fd, &ss as *const _ as *const _, len) }; // UDP connect: no packet
    unsafe { libc::close(fd) };
    assert!(r < 0, "fuzz harness must run in an isolated network namespace (bwrap --unshare-net --dev-bind / /)");
}

/// 70.27 (pool.rs lsan): a malloc'd block referenced only from a pool block is not a leak for LeakSanitizer. Without
/// the root regions LSan does not scan pool chunks and reported such a block (one worker-tls fork lane, 70.27). Once per
/// harness, on the pool thread; nothing without a sanitizer.
fn lsan_pool_check() {
    unsafe extern "C" {
        #[linkage = "extern_weak"]
        static __lsan_do_recoverable_leak_check: Option<unsafe extern "C" fn() -> libc::c_int>;
    }
    // SAFETY: reading a weak symbol address
    let Some(check) = (unsafe { __lsan_do_recoverable_leak_check }) else { return };
    let mut holder = vec![0usize; 4096]; // 32 KiB: a pool block on this pool thread
    assert!(crate::pool::is_pool(holder.as_mut_ptr() as *mut u8), "lsan_pool_check: holder is not a pool block");
    lsan_hide(&mut holder);
    // (review) check()'s frames reuse lsan_hide's dead frame: no stale copy of the pointer there
    lsan_scrub();
    // SAFETY: plain call into the sanitizer runtime
    let leaked = unsafe { check() } != 0;
    // SAFETY: holder[0] is the Box made in lsan_hide, freed once
    drop(unsafe { Box::from_raw(holder[0] as *mut [u8; 64]) });
    assert!(!leaked, "LeakSanitizer reported a block held only by a pool block: pool.rs lsan root regions missing");
}

/// A new 64-byte block (below pool::MIN: glibc, the heap LSan scans) whose only reference is holder[0]. Out of line, so
/// no copy of the pointer stays in the caller's frame (LSan scans live stack frames and registers).
#[inline(never)]
fn lsan_hide(holder: &mut [usize]) {
    holder[0] = std::hint::black_box(Box::into_raw(Box::new([7u8; 64]))) as usize;
}

/// Zero 2 KiB of the stack below the caller's frame (where lsan_hide ran).
#[inline(never)]
fn lsan_scrub() {
    std::hint::black_box(&mut [0usize; 256]);
}

impl Harness {
    pub fn new(v: u8) -> Option<Harness> {
        assert_isolated();
        mem::WORKER_BUDGET.store(64 << 20, Relaxed);
        let cfg = config(v)?;
        let tls = cfg.tls.is_some();
        let (tx, rx) = mpsc::channel();
        let w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).ok()?;
        mem::cache_on(); // 70.25: the fuzzing thread is a pool thread
        lsan_pool_check();
        Some(Harness { w, dns_rx: rx, late: Vec::new(), evs: vec![libc::epoll_event { events: 0, u64: 0 }; 256], tls })
    }

    /// Memory pressure level for the next turns (as mem's sampler publishes it).
    /// mem::USED follows (the sampler is not running): the level's entry threshold, so H7c shedding
    /// (shed_partial: usage over level 2's exit) and the level-3 stuck rule see real pressure.
    pub fn set_level(&mut self, l: usize) {
        let l = l.min(3);
        mem::LEVEL.store(l as u8, Relaxed);
        let budget = mem::WORKER_BUDGET.load(Relaxed) as u64 * self.w.cfg.threads as u64;
        mem::USED.store(budget * mem::STAGES[l].enter as u64 / 1000, Relaxed);
    }

    /// Per-input reset of caches that would make runs depend on earlier inputs or the clock.
    pub fn reset(&mut self) {
        self.w.dns_cache.clear();
        self.w.he_lost.clear();
    }

    pub fn open(&mut self) -> Conn {
        let mut fds = [0; 2];
        let r =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) };
        assert_eq!(r, 0);
        self.w.inbox.load.fetch_add(1, Relaxed);
        assert!(self.w.fd_take(1)); // 60.57 A2 (accept_on counts the fd)
        self.w.adopt(net::Handoff::bare(fds[0]));
        let ci = (0..self.w.clients.slots.len() as u32)
            .find(|&i| self.w.clients.slots[i as usize].1.as_ref().is_some_and(|c| c.fd == fds[0]))
            .expect("adopted");
        Conn { ci, g: self.w.clients.gen(ci), peer: fds[1], sent: 0, got: 0, out: Vec::new(), ktls: None, tcp: false, ctrl: Vec::new() }
    }

    /// worker-tls: a TCP loopback connection (kTLS needs TCP) through a real TLS handshake by a rustls
    /// client: `tls13` picks the version, `suite` the cipher (0 AES-128-GCM, 1 AES-256-GCM, 2 ChaCha20),
    /// `corrupt` = Some((offset, xor)) flips one byte of the client's handshake bytes. After a
    /// completed handshake the client moves its keys into its own kTLS socket (as the server does), so
    /// `feed` sends application data records and `send_record` any record type.
    pub fn open_tls(&mut self, tls13: bool, suite: u8, alpn: bool, corrupt: Option<(usize, u8)>) -> Conn {
        use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
        #[derive(Debug)]
        struct AnyCert(Arc<rustls::crypto::CryptoProvider>);
        impl ServerCertVerifier for AnyCert {
            fn verify_server_cert(
                &self,
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &[rustls::pki_types::CertificateDer<'_>],
                _: &rustls::pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.0.signature_verification_algorithms.supported_schemes()
            }
        }
        static LISTENER: std::sync::OnceLock<RawFd> = std::sync::OnceLock::new();
        const TLS_PORT: u16 = 4445;
        let lfd = *LISTENER.get_or_init(|| {
            let fd = nonblocking_socket(libc::AF_INET, libc::SOCK_STREAM);
            let one: i32 = 1; // fork mode: the previous job's connections may sit in TIME_WAIT
            unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one as *const _ as *const _, 4) };
            let (ss, len) = net::sockaddr(&format!("127.0.0.1:{TLS_PORT}").parse().unwrap());
            let r = unsafe { libc::bind(fd, &ss as *const _ as *const _, len) };
            assert!(r == 0, "tls listener bind: {}", std::io::Error::last_os_error());
            assert!(unsafe { libc::listen(fd, 64) } == 0);
            fd
        });
        let cfd = nonblocking_socket(libc::AF_INET, libc::SOCK_STREAM);
        let (ss, len) = net::sockaddr(&format!("127.0.0.1:{TLS_PORT}").parse().unwrap());
        unsafe { libc::connect(cfd, &ss as *const _ as *const _, len) };
        let mut sfd = -1;
        for _ in 0..100 {
            sfd = unsafe { libc::accept4(lfd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
            if sfd >= 0 {
                break;
            }
            std::thread::yield_now();
        }
        assert!(sfd >= 0, "loopback accept");
        let one: i32 = 1;
        unsafe { libc::setsockopt(cfd, libc::IPPROTO_TCP, libc::TCP_NODELAY, &one as *const _ as *const _, 4) };
        self.w.inbox.load.fetch_add(1, Relaxed);
        assert!(self.w.fd_take(1)); // 60.57 A2 (accept_on counts the fd)
        self.w.adopt(net::Handoff::bare(sfd));
        let ci = (0..self.w.clients.slots.len() as u32)
            .find(|&i| self.w.clients.slots[i as usize].1.as_ref().is_some_and(|c| c.fd == sfd))
            .expect("adopted");
        let mut c =
            Conn { ci, g: self.w.clients.gen(ci), peer: cfd, sent: 0, got: 0, out: Vec::new(), ktls: None, tcp: true, ctrl: Vec::new() };

        let mut provider = rustls::crypto::ring::default_provider();
        let want = [
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ];
        let want12 = [
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ];
        let pick = if tls13 { want[suite as usize % 3] } else { want12[suite as usize % 3] };
        provider.cipher_suites.retain(|s| s.suite() == pick);
        let provider = Arc::new(provider);
        let versions: &[&rustls::SupportedProtocolVersion] = if tls13 { &[&rustls::version::TLS13] } else { &[&rustls::version::TLS12] };
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth();
        cfg.enable_secret_extraction = true;
        if alpn {
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        use rustls::unbuffered::{ConnectionState, EncodeError};
        let mut cl =
            rustls::client::UnbufferedClientConnection::new(Arc::new(cfg), rustls::pki_types::ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut written = 0usize;
        let mut inb: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut done = false;
        for _ in 0..32 {
            // client step: everything rustls wants to send, until it blocks on input
            let mut out = Vec::new();
            loop {
                let st = cl.process_tls_records(&mut inb);
                let discard = st.discard;
                let next = match st.state {
                    Ok(ConnectionState::EncodeTlsData(mut e)) => {
                        let mut tmp = vec![0u8; 1 << 15];
                        match e.encode(&mut tmp) {
                            Ok(n) => {
                                out.extend_from_slice(&tmp[..n]);
                                Some(true)
                            }
                            Err(EncodeError::InsufficientSize(_)) | Err(_) => Some(false),
                        }
                    }
                    Ok(ConnectionState::TransmitTlsData(t)) => {
                        t.done();
                        Some(true)
                    }
                    Ok(ConnectionState::WriteTraffic(_)) => {
                        done = true;
                        None
                    }
                    Ok(ConnectionState::BlockedHandshake) => None,
                    _ => Some(false), // error / closed: the client gives up (corrupted handshake)
                };
                inb.drain(..discard);
                match next {
                    Some(true) => continue,
                    Some(false) => {
                        written = usize::MAX;
                        break;
                    }
                    None => break,
                }
            }
            if written == usize::MAX {
                return c;
            }
            if let Some((off, x)) = corrupt {
                if off >= written && off < written + out.len() {
                    out[off - written] ^= x.max(1);
                }
            }
            written += out.len();
            let mut o = 0;
            while o < out.len() {
                let n = unsafe { libc::send(cfd, out[o..].as_ptr() as *const _, out.len() - o, libc::MSG_NOSIGNAL) };
                if n <= 0 {
                    break;
                }
                o += n as usize;
                c.sent += n as usize;
            }
            self.turn(false); // server: reads the flight (TLS 1.3: Finished -> kTLS)
            self.check(&c);
            if !self.alive(&c) {
                return c;
            }
            if done {
                break;
            }
            loop {
                let n = unsafe { libc::read(cfd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n <= 0 {
                    break;
                }
                c.got += n as usize;
                inb.extend_from_slice(&buf[..n as usize]);
            }
        }
        if !done || !inb.is_empty() || !self.alive(&c) {
            return c;
        }
        let version = cl.protocol_version().unwrap();
        let Ok((secrets, k)) = cl.dangerous_into_kernel_connection() else { return c };
        tls::install(cfd, version, &secrets).expect("client kTLS install");
        c.ktls = Some(Box::new(k));
        c
    }

    /// worker-tls: one record of type `typ` through the client's kTLS socket (false if it did not fit).
    pub fn send_record(&mut self, c: &mut Conn, typ: u8, payload: &[u8]) -> bool {
        for _ in 0..4 {
            match tls::send_record(c.peer, typ, payload) {
                Ok(n) => {
                    c.sent += n;
                    return true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.turn(false);
                    self.drain(c);
                }
                Err(_) => return false,
            }
        }
        false
    }

    /// worker-tls: a TLS 1.3 KeyUpdate from the client (then the client's TX key changes).
    pub fn client_key_update(&mut self, c: &mut Conn, request: bool) -> bool {
        if c.ktls.is_none() || !self.send_record(c, tls::REC_HANDSHAKE, &tls::key_update_msg(request)) {
            return false;
        }
        match c.ktls.as_mut().unwrap().update_tx_secret() {
            Ok(s) => tls::rekey(c.peer, false, &s).is_ok(),
            Err(_) => false, // TLS 1.2
        }
    }

    pub fn alive(&mut self, c: &Conn) -> bool {
        self.w.clients.get(c.ci, c.g).is_some_and(|cl| !cl.dead)
    }

    /// One event-loop turn, in Worker::run order, without blocking (epoll_wait timeout 0). The fake
    /// resolver and the echo sink run first. `sweep` forces the 2 s idle sweep now.
    pub fn turn(&mut self, sweep: bool) {
        self.resolver();
        self.sink();
        let n = unsafe { libc::epoll_wait(self.w.ep, self.evs.as_mut_ptr(), self.evs.len() as i32, 0) };
        self.w.now = Instant::now(); // 60.47 as Worker::run
        for ev in &self.evs[..n.max(0) as usize] {
            let (t, e) = (ev.u64, ev.events);
            self.w.dispatch(t, e);
        }
        let l = mem::LEVEL.load(Relaxed) as usize;
        if l != self.w.lvl {
            self.w.set_level(l);
        }
        let mut ready = std::mem::take(&mut self.w.ready);
        for t in ready.drain(..) {
            self.w.resume(t);
        }
        self.w.run_deferred();
        self.w.flush_dirty();
        if !self.w.connecting.is_empty() {
            self.w.run_timers();
        }
        if !self.w.lingering.is_empty() {
            self.w.linger_check();
        }
        if !self.w.lwait.is_empty() {
            self.w.meter_timers(); // 60.25 C10b (variant 1 runs an upload limit)
        }
        if sweep {
            self.w.next_sweep = self.w.now;
        }
        let swept = self.w.idle_sweep(self.w.now);
        self.w.tls_timeouts();
        self.w.reap_dead();
        if swept {
            crate::pool::sweep();
        }
        mem::turn_end();
    }

    /// The DNS pool's job: names starting with "nx" do not exist, "fail" fails, names ending in "6"
    /// get ::1 and 127.0.0.1 (happy eyeballs), the rest 127.0.0.1. 70.10: names containing "late" get an early
    /// answer (127.0.0.1) at once and the final one (::1 and 127.0.0.1) at the next call.
    fn resolver(&mut self) {
        let mut any = !self.late.is_empty();
        for r in self.late.drain(..) {
            self.w.inbox.q.lock().unwrap().push(r);
        }
        while let Ok(r) = self.dns_rx.try_recv() {
            if r.host.contains("late") {
                let early = vec!["127.0.0.1".parse().unwrap()];
                r.inbox.q.lock().unwrap().push(net::DnsResp { host: r.host.clone(), token: r.token, addrs: early, nx: false, more: true });
                let all = vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()];
                self.late.push(net::DnsResp { host: r.host, token: r.token, addrs: all, nx: false, more: false });
                any = true;
                continue;
            }
            let (addrs, nx) = if r.host.starts_with("nx") {
                (vec![], true)
            } else if r.host.starts_with("fail") {
                (vec![], false)
            } else if r.host.ends_with('6') {
                (vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()], false)
            } else {
                (vec!["127.0.0.1".parse().unwrap()], false)
            };
            r.inbox.q.lock().unwrap().push(net::DnsResp { host: r.host, token: r.token, addrs, nx, more: false });
            any = true;
        }
        if any {
            self.w.inbox.wake();
        }
    }

    /// Echo everything back (best effort: what does not fit the socket is dropped). One sink per
    /// process, shared by all variants.
    fn sink(&mut self) {
        static SINKS: std::sync::OnceLock<Vec<(RawFd, bool)>> = std::sync::OnceLock::new();
        static CONNS: std::sync::Mutex<Vec<RawFd>> = std::sync::Mutex::new(Vec::new());
        let sinks = SINKS.get_or_init(|| {
            [(false, false), (false, true), (true, false), (true, true)].map(|(v6, udp)| (bind_sink(v6, udp), udp)).to_vec()
        });
        let mut conns = CONNS.lock().unwrap();
        let mut buf = [0u8; 65536];
        for &(fd, udp) in sinks {
            if udp {
                for _ in 0..64 {
                    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                    let mut sl = std::mem::size_of_val(&sa) as libc::socklen_t;
                    let n = unsafe { libc::recvfrom(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0, &mut sa as *mut _ as *mut _, &mut sl) };
                    if n < 0 {
                        break;
                    }
                    unsafe { libc::sendto(fd, buf.as_ptr() as *const _, n as usize, 0, &sa as *const _ as *const _, sl) };
                }
            } else {
                loop {
                    let c =
                        unsafe { libc::accept4(fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
                    if c < 0 {
                        break;
                    }
                    conns.push(c);
                }
            }
        }
        conns.retain(|&fd| {
            for _ in 0..16 {
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n == 0 || (n < 0 && !would_block(net::errno())) {
                    unsafe { libc::close(fd) };
                    return false;
                }
                if n < 0 {
                    break;
                }
                unsafe { libc::send(fd, buf.as_ptr() as *const _, n as usize, libc::MSG_NOSIGNAL) };
            }
            true
        });
    }

    /// Read what the server sent so far.
    pub fn drain(&mut self, c: &mut Conn) {
        let mut buf = [0u8; 65536];
        loop {
            let n = unsafe { libc::read(c.peer, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 && net::errno() == libc::EIO && c.ktls.is_some() {
                // kTLS: the next record is not application data
                let Ok((typ, n)) = tls::recv_record(c.peer, &mut buf) else { return };
                if n == 0 {
                    return;
                }
                c.ctrl.push((typ, buf[..n.min(16)].to_vec()));
                if typ == tls::REC_HANDSHAKE && tls::parse_key_update(&buf[..n]).is_some() {
                    let k = c.ktls.as_mut().unwrap();
                    match k.update_rx_secret() {
                        Ok(s) if tls::rekey(c.peer, true, &s).is_ok() => continue,
                        _ => return,
                    }
                }
                if typ == tls::REC_ALERT {
                    return;
                }
                continue;
            }
            if n <= 0 {
                return;
            }
            let n = n as usize;
            c.got += n;
            let keep = OUT_KEEP.saturating_sub(c.out.len()).min(n);
            c.out.extend_from_slice(&buf[..keep]);
        }
    }

    /// Write `data` as one chunk, then run turns until it is consumed or the server stops taking
    /// bytes. Returns false once the client is gone. Invariants are checked after every turn.
    pub fn feed(&mut self, c: &mut Conn, data: &[u8], sweep: bool) -> bool {
        let mut off = 0;
        let mut stalls = 0;
        while off < data.len() && stalls < 4 {
            let n = unsafe { libc::send(c.peer, data[off..].as_ptr() as *const _, data.len() - off, libc::MSG_NOSIGNAL) };
            if n > 0 {
                off += n as usize;
                c.sent += n as usize;
            } else {
                stalls += 1;
            }
            self.turn(false);
            self.drain(c);
            self.check(c);
            if !self.alive(c) {
                return false;
            }
        }
        self.turn(sweep);
        self.drain(c);
        self.check(c);
        self.alive(c)
    }

    /// Server-side invariants for a live client.
    pub fn check(&mut self, c: &Conn) {
        let sent = c.sent;
        let Some(cl) = self.w.clients.get(c.ci, c.g) else { return };
        if cl.dead {
            return;
        }
        assert!(cl.rpos <= cl.rlen && cl.rlen <= cl.rbuf.len(), "rpos {} rlen {} rbuf {}", cl.rpos, cl.rlen, cl.rbuf.len());
        assert!(cl.need <= NEED_MAX, "need {} > max frame", cl.need);
        // 60.05 H2: rbuf follows received bytes (doubling: at most ~2x buffered + 16 KiB tail), never a header's claim
        let cap = mem::STAGES[0].rbuf_max.max(2 * sent + 64 * 1024);
        assert!(cl.rbuf.len() <= cap, "rbuf {} after {} bytes received", cl.rbuf.len(), sent);
        let frag = cl.frag.as_ref().map_or(0, |f| f.1.len());
        assert!(frag <= MAX_FRAME, "frag {frag}");
        assert!(frag <= sent, "frag {frag} > received {sent}");
        assert!(cl.ohead <= cl.obuf.len());
    }

    /// Close the peer, let the server notice, then force-close what is left. Afterwards nothing of
    /// the connection may remain: no client, no target, no lingering entry.
    pub fn close(&mut self, c: Conn) {
        static DEBUG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if *DEBUG.get_or_init(|| std::env::var_os("FW_FUZZ_DEBUG").is_some()) {
            eprintln!(
                "fuzz conn: sent {} got {} ctrl {:?} out {:?}",
                c.sent,
                c.got,
                c.ctrl,
                String::from_utf8_lossy(&c.out[..c.out.len().min(600)])
            );
        }
        unsafe { libc::close(c.peer) };
        for _ in 0..8 {
            if !self.alive(&c) {
                break;
            }
            self.turn(false);
        }
        if self.alive(&c) {
            self.w.close_client(c.ci, super::Why::ClientClose); // paused/mpaused clients do not read their EOF: the idle sweep's job
        }
        for _ in 0..3 {
            self.turn(false); // DNS answers for closed targets are consumed (dns_inflight)
        }
        self.w.reap_dead();
        // worker-level state is quiescent again (attributes leaks to the input that made them)
        let w = &self.w;
        assert_eq!(w.inbox.load.load(Relaxed), 0, "inbox.load (live client count) leaked");
        assert_eq!((w.pend_total, w.pend_clients), (0, 0), "upload backlog accounting leaked");
        assert!(w.connecting.is_empty() && w.deferred.is_empty(), "connecting/deferred entries left");
        assert_eq!((w.up_n, w.up_total), (0, 0), "staged upload iovecs left");
        assert_eq!(w.dns_inflight, 0, "dns_inflight leaked");
        assert!(w.inbox.dns_live.lock().unwrap().is_empty() && self.late.is_empty(), "70.10 dns_live token / held answer leaked");
        let live_c = self.w.clients.slots.len() - self.w.clients.free.len();
        let live_t = self.w.targets.slots.len() - self.w.targets.free.len();
        assert_eq!(live_c, 0, "client slot left after close");
        assert_eq!(live_t, 0, "target slot left after its client closed");
        // fd leak check every 1024 connections (the 1st sample is the baseline: sink, epoll, pipes)
        static CLOSES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        static BASE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = CLOSES.fetch_add(1, Relaxed) + 1;
        if n % 1024 == 0 {
            let fds = std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0);
            let base = match BASE.load(Relaxed) {
                0 => {
                    BASE.store(fds, Relaxed);
                    fds
                }
                b => b,
            };
            assert!(fds <= base + 64, "fd leak: {fds} open fds, {base} after the first 1024 connections");
        }
    }
}
