//! 20.13 wss:// support for wbench (pointer 30.01): a readiness-style socket wrapper so the load
//! loop keeps its try_read/try_write shape. TLS runs in userspace (rustls, ring) on the client side
//! so the client works against any wss server (finalwisp kTLS, Caddy, epoxy...).
//! Certificate verification is OFF (--insecure is required for wss:// URLs): benchmark use only.
use bytes::BytesMut;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use std::io::{self, ErrorKind, Read, Write};
use std::sync::Arc;
use tokio::io::{Interest, Ready};
use tokio::net::TcpStream;

const TLS_OUT_LIMIT: usize = 256 * 1024; // plaintext rustls buffers before try_write reports WouldBlock
const READ_CHUNK: usize = 64 * 1024;

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Client config without certificate verification, ALPN http/1.1, TLS 1.2 + 1.3.
pub fn insecure_config() -> Arc<ClientConfig> {
    let mut provider = rustls::crypto::ring::default_provider();
    // Optional: WBENCH_TLS_SUITES=TLS13_AES_128_GCM_SHA256,... restricts the offered suites (rustls names).
    if let Ok(list) = std::env::var("WBENCH_TLS_SUITES") {
        provider.cipher_suites.retain(|s| list.split(',').any(|n| n.trim() == format!("{:?}", s.suite())));
        assert!(!provider.cipher_suites.is_empty(), "WBENCH_TLS_SUITES matches no suite");
    }
    let provider = Arc::new(provider);
    let mut cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// TCP socket, optionally with a rustls client session on top. Same call shape as TcpStream's
/// readiness API: ready(), try_read_buf(), try_write(); plus wants_write() for TLS output that
/// is still queued inside rustls.
pub struct Sock {
    tcp: TcpStream,
    tls: Option<Box<ClientConnection>>,
    raw: Vec<u8>, // ciphertext read from the socket, not yet fed to rustls: raw[rpos..rlen]
    rpos: usize,
    rlen: usize,
    eof: bool,
}

struct TcpW<'a>(&'a TcpStream);
impl Write for TcpW<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.try_write(b)
    }
    fn write_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.0.try_write_vectored(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn tls_err(e: rustls::Error) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, format!("tls: {e}"))
}

impl Sock {
    pub async fn connect(host: &str, port: u16, tls: Option<&Arc<ClientConfig>>) -> io::Result<Sock> {
        let tcp = TcpStream::connect((host, port)).await?;
        tcp.set_nodelay(true)?;
        let tls = match tls {
            Some(cfg) => {
                let name = ServerName::try_from(host.to_string()).map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
                let mut c = ClientConnection::new(cfg.clone(), name).map_err(tls_err)?;
                c.set_buffer_limit(Some(TLS_OUT_LIMIT));
                Some(Box::new(c))
            }
            None => None,
        };
        let mut s = Sock { tcp, tls, raw: vec![0; READ_CHUNK], rpos: 0, rlen: 0, eof: false };
        s.handshake().await?;
        Ok(s)
    }

    async fn handshake(&mut self) -> io::Result<()> {
        loop {
            self.flush_tls()?;
            let Some(c) = self.tls.as_ref() else { return Ok(()) };
            if !c.is_handshaking() && !c.wants_write() {
                return Ok(());
            }
            let interest = if c.wants_write() { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE };
            let r = self.tcp.ready(interest).await?;
            if r.is_readable() || r.is_read_closed() {
                // handshake messages produce no plaintext; app data after it stays in raw/rustls
                while self.fill_raw()? && self.feed()? && self.tls.as_ref().is_some_and(|c| c.is_handshaking()) {}
                if self.eof {
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "eof during tls handshake"));
                }
            }
        }
    }

    pub async fn ready(&self, interest: Interest) -> io::Result<Ready> {
        self.tcp.ready(interest).await
    }

    /// TLS records queued in rustls that the socket has not taken yet.
    #[inline]
    pub fn wants_write(&self) -> bool {
        self.tls.as_ref().is_some_and(|c| c.wants_write())
    }

    /// Send queued TLS records until the socket would block.
    fn flush_tls(&mut self) -> io::Result<()> {
        let Some(c) = self.tls.as_mut() else { return Ok(()) };
        while c.wants_write() {
            match c.write_tls(&mut TcpW(&self.tcp)) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Feed buffered raw bytes into rustls, one read_tls() call (it may take only part), then
    /// process them. Ok(false) = nothing buffered. The caller drains plaintext between calls,
    /// otherwise rustls refuses input ("received plaintext buffer full").
    fn feed(&mut self) -> io::Result<bool> {
        if self.rpos == self.rlen {
            return Ok(false);
        }
        let c = self.tls.as_mut().expect("tls");
        let mut s = &self.raw[self.rpos..self.rlen];
        let n = c.read_tls(&mut s)?;
        self.rpos += n;
        c.process_new_packets().map_err(tls_err)?;
        Ok(true)
    }

    /// One raw socket read into the raw buffer (only when it is empty). Ok(false) = would block / EOF.
    fn fill_raw(&mut self) -> io::Result<bool> {
        if self.rpos < self.rlen {
            return Ok(true);
        }
        match self.tcp.try_read(&mut self.raw) {
            Ok(0) => {
                self.eof = true;
                Ok(false)
            }
            Ok(n) => {
                (self.rpos, self.rlen) = (0, n);
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Like TcpStream::try_read_buf: Ok(0) = closed, WouldBlock = nothing (decrypted) available.
    pub fn try_read_buf(&mut self, rbuf: &mut BytesMut) -> io::Result<usize> {
        if self.tls.is_none() {
            return self.tcp.try_read_buf(rbuf);
        }
        let mut total = 0;
        let mut closed = false;
        loop {
            let c = self.tls.as_mut().unwrap();
            loop {
                let start = rbuf.len();
                rbuf.resize(start + READ_CHUNK, 0);
                let r = c.reader().read(&mut rbuf[start..]);
                match r {
                    Ok(0) => {
                        rbuf.truncate(start);
                        closed = true; // close_notify
                        break;
                    }
                    Ok(n) => {
                        rbuf.truncate(start + n);
                        total += n;
                    }
                    Err(e) => {
                        rbuf.truncate(start);
                        if e.kind() == ErrorKind::WouldBlock {
                            break;
                        }
                        return Err(e);
                    }
                }
            }
            if closed || total >= 4 * READ_CHUNK {
                break;
            }
            if !self.feed()? && !self.fill_raw()? {
                break;
            }
        }
        self.flush_tls()?; // rustls may owe the peer something (alerts, key updates)
        if total > 0 {
            Ok(total)
        } else if closed || (self.eof && self.rpos == self.rlen) {
            Ok(0)
        } else {
            Err(ErrorKind::WouldBlock.into())
        }
    }

    /// Like TcpStream::try_write. With TLS: plaintext goes into rustls (bounded), records go to the
    /// socket; WouldBlock only when rustls is full and the socket takes nothing.
    pub fn try_write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.tls.is_none() {
            return self.tcp.try_write(data);
        }
        self.flush_tls()?;
        let n = self.tls.as_mut().unwrap().writer().write(data)?;
        self.flush_tls()?;
        if n == 0 && !data.is_empty() {
            return Err(ErrorKind::WouldBlock.into());
        }
        Ok(n)
    }

    /// Blocking-style helpers for the HTTP upgrade.
    pub async fn write_all(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() || self.wants_write() {
            match self.try_write(data) {
                Ok(n) => data = &data[n..],
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            if !data.is_empty() || self.wants_write() {
                self.tcp.ready(Interest::WRITABLE).await?;
            }
        }
        Ok(())
    }

    /// 30.10 connchurn: after the plaintext end (TLS close_notify), wait until the peer's TCP FIN, so the
    /// server closes TCP first (its TIME_WAIT, not the client's ephemeral port). Bytes after close are dropped.
    pub async fn wait_tcp_eof(&mut self) -> io::Result<()> {
        while !self.eof {
            self.rpos = self.rlen; // discard: nothing after close_notify is used
            if !self.fill_raw()? && !self.eof {
                self.tcp.ready(Interest::READABLE).await?;
            }
        }
        Ok(())
    }

    pub async fn read_some(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        loop {
            match self.try_read_buf(buf) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    self.tcp.ready(Interest::READABLE).await?;
                }
                r => return r,
            }
        }
    }
}
