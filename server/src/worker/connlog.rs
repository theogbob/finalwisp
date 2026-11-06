//! 60.24 (60.20 C4 step 1) --log-conns: one logfmt line per connection that reached adopt (`ev=conn_close`; `ev=conn_open`
//! at --log-level debug) and a flood-limited `ev=conn_refused` per accept-time refusal. The per-connection fields sit in
//! the side vector Worker::connlog (by slab slot, empty when the log is off: 60.02 rule 3, no Client growth); the lines
//! go to the worker's logs::Outbox, never to stderr.
use super::*;
use crate::logs;
use std::io::Write;

/// Why a connection ended (60.02 C4 list). The first site that names one wins (Worker::close_client and friends take
/// it as an argument; a later close of the same connection keeps the first).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Why {
    Unset,
    ClientClose,
    WsError,
    ProtocolError,
    HsTimeout,
    AuthFailed,
    TlsError,
    PressureShed,
    DeadPeer,
    Limit,
    ServerClose,
    /// a failed client read or write: close_client names it from errno (io_why) when the log is on
    Io,
}

impl Why {
    pub(super) fn name(self) -> &'static str {
        match self {
            Why::Unset => "unknown",
            Why::ClientClose => "client_close",
            Why::WsError => "ws_error",
            Why::ProtocolError => "protocol_error",
            Why::HsTimeout => "hs_timeout",
            Why::AuthFailed => "auth_failed",
            Why::TlsError => "tls_error",
            Why::PressureShed => "pressure_shed",
            Why::DeadPeer => "dead_peer",
            Why::Limit => "limit",
            Why::ServerClose => "server_close",
            Why::Io => "client_close", // (replaced by io_why in close_client)
        }
    }
}

/// What the connection became after its HTTP request
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Proto {
    Http,
    V1,
    V2,
    Wsproxy,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Auth {
    None,
    Ok,
    Failed,
}

pub(super) struct ConnLog {
    pub(super) seq: u64,
    start_ms: u64,
    pub(super) connects: u64, // CONNECTs received (u64: stream ids can be reused without end; review)
    pub(super) opened: u64,   // CONNECTs that became a stream (the others were refused: refused = connects - opened)
    pub(super) why: Why,
    pub(super) proto: Proto,
    pub(super) auth: Auth,
    tls: bool,
    /// the trusted proxy the connection came through (60.22: the header's client is the peer then)
    pub(super) via: Option<IpAddr>,
}

/// Client `ci`'s entry; None when the log is off (one length check)
pub(super) fn entry(log: &mut [Option<ConnLog>], ci: u32) -> Option<&mut ConnLog> {
    log.get_mut(ci as usize).and_then(Option::as_mut)
}

/// The first reason wins
pub(super) fn set_why(log: &mut [Option<ConnLog>], ci: u32, w: Why) {
    if let Some(l) = entry(log, ci) {
        if l.why == Why::Unset {
            l.why = w;
        }
    }
}

/// The reason for a failed client read or write, from errno right after the call and the client's TX record budget
/// (review: transport, keepalive and kTLS failures all end in the same close calls)
/// Why::Io resolved (close_client with the log on, before it makes any other syscall)
#[cold]
pub(super) fn io_why_of(c: &Client) -> Why {
    io_why(net::errno(), c.ktls_on, c.tx_left)
}

pub(super) fn io_why(e: i32, ktls: bool, tx_left: u64) -> Why {
    if tx_left == 0 {
        return Why::TlsError; // 20.13 AEAD usage limit (Client::tx_count)
    }
    match e {
        libc::ETIMEDOUT | libc::EHOSTUNREACH => Why::DeadPeer, // keepalive or retransmission timeout
        libc::ECONNRESET | libc::EPIPE => Why::ClientClose,
        _ if ktls => Why::TlsError, // a record the kernel could not decrypt (EBADMSG), a failed KeyUpdate / rekey
        _ => Why::ClientClose,
    }
}

/// An address for a line: canonical, and `unix` for the 60.31 C7 sentinel (a unix-socket client without a header)
fn ip_value(b: &mut Vec<u8>, ip: IpAddr) {
    if ip == clientip::UNIX_PEER {
        b.extend_from_slice(b"unix");
    } else {
        logs::value(b, clientip::canon(ip).to_string().as_bytes());
    }
}

/// conn_refused lines per worker and second; more are counted (`ev=refused_suppressed`, written by the log thread)
const REFUSED_PER_SEC: u32 = 20;

impl Worker {
    /// adopt (with --log-conns or --log-streams): the entry for slot `i`, and `ev=conn_open` at debug (--log-conns)
    pub(super) fn log_open(&mut self, i: u32, tls: bool, peer: Option<IpAddr>) {
        let ui = i as usize;
        if self.connlog.len() <= ui {
            self.connlog.resize_with(ui + 1, || None);
        }
        self.conn_seq += 1;
        let seq = self.conn_seq;
        self.connlog[ui] = Some(ConnLog {
            seq,
            start_ms: metrics::now_ms(),
            connects: 0,
            opened: 0,
            why: Why::Unset,
            proto: Proto::Http,
            auth: Auth::None,
            tls,
            via: None,
        });
        if self.cfg.log_conns && logs::on(logs::Level::Debug) {
            let mut b = std::mem::take(&mut self.logline);
            self.line_head(&mut b, "conn_open", Some(seq), peer);
            let _ = writeln!(b, " tls={}", u8::from(tls));
            self.log_push(&b);
            self.logline = b;
        }
    }

    /// close_client (with --log-conns), before the socket is closed: `ev=conn_close` with TCP_INFO byte counts
    #[cold]
    pub(super) fn log_close(&mut self, ci: u32, peer: Option<IpAddr>) {
        let Some(l) = self.connlog.get_mut(ci as usize).and_then(Option::take) else { return };
        if !self.cfg.log_conns {
            return; // 60.35 --log-streams alone: the entry only gave the streams their cid
        }
        let fd = self.clients.at(ci).fd;
        let mut b = std::mem::take(&mut self.logline);
        self.line_head(&mut b, "conn_close", Some(l.seq), peer);
        if let Some(v) = l.via {
            b.extend_from_slice(b" via=");
            ip_value(&mut b, v);
        }
        let proto = match l.proto {
            Proto::Http => "http",
            Proto::V1 => "v1",
            Proto::V2 => "v2",
            Proto::Wsproxy => "wsproxy",
        };
        let auth = match l.auth {
            Auth::None => "none",
            Auth::Ok => "ok",
            Auth::Failed => "failed",
        };
        let _ = write!(
            b,
            " tls={} proto={proto} auth={auth} dur_ms={} streams={} refused={}",
            u8::from(l.tls),
            metrics::now_ms().saturating_sub(l.start_ms),
            l.opened,
            l.connects.saturating_sub(l.opened)
        );
        if let Some((rx, tx)) = net::bytes_rx_tx(fd) {
            let _ = write!(b, " rx={rx} tx={tx}"); // wire bytes (WebSocket and TLS framing included)
        }
        let _ = writeln!(b, " why={}", l.why.name());
        self.log_push(&b);
        self.logline = b;
    }

    /// accept_all / adopt (with --log-conns): a connection refused before adopt (--max-conns, --max-conns-per-ip: limit)
    /// or dropped by adopt (no TLS state, epoll refused: server_close)
    #[cold]
    pub(super) fn log_refused(&mut self, ip: Option<IpAddr>, why: Why) {
        let sec = metrics::now_ms() / 1000;
        if self.refused_win.0 != sec {
            self.refused_win = (sec, 0);
        }
        if self.refused_win.1 >= REFUSED_PER_SEC {
            if let Some(o) = &self.outbox {
                o.suppressed.fetch_add(1, Relaxed);
            }
            return;
        }
        self.refused_win.1 += 1;
        let mut b = std::mem::take(&mut self.logline);
        self.line_head(&mut b, "conn_refused", None, ip);
        let _ = writeln!(b, " why={}", why.name());
        self.log_push(&b);
        self.logline = b;
    }

    /// `finalwisp: ev=E ts=.. w=N [cid=N:S] ip=A` into `b` (cleared first)
    pub(super) fn line_head(&self, b: &mut Vec<u8>, ev: &str, seq: Option<u64>, ip: Option<IpAddr>) {
        b.clear();
        b.extend_from_slice(b"finalwisp: ev=");
        b.extend_from_slice(ev.as_bytes());
        logs::ts(b);
        let _ = write!(b, " w={}", self.idx);
        if let Some(s) = seq {
            let _ = write!(b, " cid={}:{s}", self.idx);
        }
        b.extend_from_slice(b" ip=");
        match ip {
            Some(ip) => ip_value(b, ip),
            None => b.push(b'-'),
        }
    }

    pub(super) fn log_push(&self, line: &[u8]) {
        if let Some(o) = &self.outbox {
            if !o.push(line) {
                self.stats.log_dropped.bump();
            }
        }
    }
}
