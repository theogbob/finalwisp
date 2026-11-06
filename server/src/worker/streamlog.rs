//! 60.35 (60.20 C4 step 2) --log-streams: one logfmt line per stream that got a Target (`ev=stream_close`) and a
//! flood-limited `ev=stream_refused` per CONNECT refused before one existed. Per-stream fields sit in the side vector
//! Worker::streamlog (by target slot, empty when the log is off: no Target growth); lines go to the worker's
//! logs::Outbox like the connection lines (worker/connlog.rs). Hostnames are browsing data: they appear only here.
use super::wisp::{STREAM_TCP, STREAM_UDP};
use super::*;
use crate::logs;
use std::io::Write;

/// Why a stream ended. The first site that names one wins; close_target derives it from the CLOSE reason and the
/// stream's state when no site named one (stream_why).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum SWhy {
    Unset,
    /// the target ended it (EOF, RST, a send or receive error), or the wsproxy target closed
    TargetClose,
    /// the client sent CLOSE for the stream
    ClientClose,
    /// the client connection ended (any reason: the conn_close line has it)
    ConnClose,
    DnsFail,
    ConnectFail,
    /// 60.32 C6 the upstream proxy failed or refused (an operator-side problem)
    UpstreamFail,
    /// 0x48: a C1 rule (rule=)
    Policy,
    /// 0x49 from a C3 limit or the DNS in-flight cap (rule=)
    Limit,
    /// 0x49 under memory pressure (rule=)
    Pressure,
    /// 0x41: a bad CONNECT
    Invalid,
}

impl SWhy {
    pub(super) fn name(self) -> &'static str {
        match self {
            SWhy::Unset => "unknown",
            SWhy::TargetClose => "target_close",
            SWhy::ClientClose => "client_close",
            SWhy::ConnClose => "conn_close",
            SWhy::DnsFail => "dns_fail",
            SWhy::ConnectFail => "connect_fail",
            SWhy::UpstreamFail => "upstream_fail",
            SWhy::Policy => "policy",
            SWhy::Limit => "limit",
            SWhy::Pressure => "pressure",
            SWhy::Invalid => "invalid",
        }
    }
}

fn phase(t: &Target) -> Phase {
    match t.state {
        TState::Open => Phase::Open,
        TState::Resolving if t.addrs.is_empty() => Phase::Dns,
        _ => Phase::Connect,
    }
}

/// Where a stream was when it closed (for the reasons no site named)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Phase {
    /// resolving, no address yet: a 0x42 here is the DNS answer (none, or the name refused before DNS)
    Dns,
    /// addresses known, not connected (TCP attempts, UDP connect, C6 proxy open)
    Connect,
    /// connected: 0x02 / 0x03 / 0x47 come from the data path (net::data_reason)
    Open,
}

/// The reason for a stream no site named: from the CLOSE code (None = none sent: the client closed the stream or the
/// connection; a wsproxy target's code is passed by target_eof, which sends none) and the phase. Sites name what this
/// cannot tell apart (drop_streams: ConnClose; the DNS in-flight cap: Limit; sheds: Pressure; C6: UpstreamFail).
pub(super) fn stream_why(reason: Option<u8>, phase: Phase) -> (SWhy, &'static str) {
    match (reason, phase) {
        (None, _) => (SWhy::ClientClose, ""),
        (Some(0x41), _) => (SWhy::Invalid, ""),
        (Some(0x48), _) => (SWhy::Policy, ""),
        // the only unnamed 0x49 site: an upload over the stage's pend_over cap past its credit (upload.rs)
        (Some(0x49), _) => (SWhy::Pressure, "over_credit"),
        (Some(_), Phase::Open) => (SWhy::TargetClose, ""),
        (Some(0x42), Phase::Dns) => (SWhy::DnsFail, ""),
        (Some(_), _) => (SWhy::ConnectFail, ""),
    }
}

pub(super) struct StreamLog {
    seq: u64, // the connection's cid sequence (ConnLog::seq)
    sid: u32,
    host: Box<str>,
    port: u16,
    start_ms: u64,
    why: SWhy,
    rule: &'static str,
    /// the address the stream went to (won / udp_open; with C6 the proxy's)
    pub(super) dst: Option<IpAddr>,
    up: u64, // UDP only (TCP: TCP_INFO at close)
    down: u64,
    dg_up: u64,
    dg_down: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Tcp,
    Udp,
    WsProxy,
}

/// A stream closed in this loop turn, its line not written yet (slog_close -> slog_flush)
pub(super) struct Closed {
    l: StreamLog,
    reason: Option<u8>,
    kind: Kind,
    why: SWhy,
    rule: &'static str,
    bytes: Option<(u64, u64)>, // TCP_INFO (bytes_received, bytes_acked)
    ip: Option<IpAddr>,
    end_ms: u64,
}

/// stream_refused lines per worker and second; more are counted (`ev=stream_refused_suppressed`, written by the log thread)
const REFUSED_PER_SEC: u32 = 20;

impl Worker {
    /// Target `ti`'s entry; None when the log is off (one length check)
    #[inline]
    pub(super) fn slog(&mut self, ti: u32) -> Option<&mut StreamLog> {
        self.streamlog.get_mut(ti as usize).and_then(Option::as_mut)
    }

    /// Name the reason (and rule) for target `ti`; the first one wins
    #[cold]
    pub(super) fn slog_why(&mut self, ti: u32, why: SWhy, rule: &'static str) {
        if let Some(l) = self.slog(ti) {
            if l.why == SWhy::Unset {
                (l.why, l.rule) = (why, rule);
            }
        }
    }

    /// new_target (with --log-streams): the entry for slot `ti`, the host as the client sent it
    #[cold]
    pub(super) fn slog_open(&mut self, ti: u32, ci: u32, sid: u32, host: &str, port: u16) {
        let seq = self.connlog.get(ci as usize).and_then(Option::as_ref).map_or(0, |c| c.seq);
        let ui = ti as usize;
        if self.streamlog.len() <= ui {
            self.streamlog.resize_with(ui + 1, || None);
        }
        self.streamlog[ui] = Some(StreamLog {
            seq,
            sid,
            host: host.into(),
            port,
            start_ms: metrics::now_ms(),
            why: SWhy::Unset,
            rule: "",
            dst: None,
            up: 0,
            down: 0,
            dg_up: 0,
            dg_down: 0,
        });
    }

    /// udp_send / udp_open: one datagram of `n` bytes to the target
    #[cold]
    pub(super) fn slog_udp_up(&mut self, ti: u32, n: usize) {
        if let Some(l) = self.slog(ti) {
            (l.up, l.dg_up) = (l.up + n as u64, l.dg_up + 1);
        }
    }

    /// read_udp: `dg` datagrams of `n` bytes in all from the target
    #[cold]
    pub(super) fn slog_udp_down(&mut self, ti: u32, dg: u64, n: u64) {
        if let Some(l) = self.slog(ti) {
            (l.down, l.dg_down) = (l.down + n, l.dg_down + dg);
        }
    }

    /// close_target (with --log-streams), the target still in the slab and its socket open: take the entry and what the
    /// line needs (TCP_INFO byte counts for TCP) into `sdone`; reap_dead writes the lines at the end of the loop turn.
    /// deliberate: no formatting here. close_target is in one call-graph cycle with the per-byte paths (flush_bucket,
    /// target_eof, write_target); a `write!` with a Worker field (line_head) lets `self` escape there, and LLVM then
    /// reloads and re-checks fields after every syscall in those paths (measured, disasm_norm). 60.35
    #[cold]
    pub(super) fn slog_close(&mut self, ti: u32, reason: Option<u8>) {
        let Some(l) = self.streamlog.get_mut(ti as usize).and_then(Option::take) else { return };
        let t = self.targets.at(ti);
        let kind = if t.raw {
            Kind::WsProxy
        } else if t.udp {
            Kind::Udp
        } else {
            Kind::Tcp
        };
        let (why, rule) = if l.why == SWhy::Unset { stream_why(reason, phase(t)) } else { (l.why, l.rule) };
        let bytes = if kind != Kind::Udp && t.fd >= 0 { net::bytes_rx_tx(t.fd) } else { None };
        let ip = self.peers_of.get(t.client as usize).and_then(Option::as_ref).map(|p| p.ip);
        let end_ms = metrics::now_ms();
        self.sdone.push(Closed { l, reason, kind, why, rule, bytes, ip, end_ms });
    }

    /// target_eof of a wsproxy target (it sends no CLOSE code: close_target gets None): name the reason from the code
    #[cold]
    pub(super) fn slog_raw_reason(&mut self, ti: u32, reason: u8) {
        let p = phase(self.targets.at(ti));
        let (why, rule) = stream_why(Some(reason), p);
        self.slog_why(ti, why, rule);
    }

    /// reap_dead (end of a loop turn): the `ev=stream_close` lines of the streams closed in it
    #[cold]
    pub(super) fn slog_flush(&mut self) {
        let mut done = std::mem::take(&mut self.sdone);
        let mut b = std::mem::take(&mut self.logline);
        for c in done.drain(..) {
            let l = &c.l;
            self.line_head(&mut b, "stream_close", Some(l.seq), c.ip);
            let kind = match c.kind {
                Kind::Tcp => "tcp",
                Kind::Udp => "udp",
                Kind::WsProxy => "wsproxy",
            };
            let _ = write!(b, " sid={} t={kind} host=", l.sid);
            logs::value(&mut b, l.host.as_bytes());
            let _ = write!(b, " port={}", l.port);
            if let Some(d) = l.dst {
                b.extend_from_slice(b" dst=");
                logs::value(&mut b, crate::clientip::canon(d).to_string().as_bytes());
            }
            if self.cfg.upstream.is_some() {
                b.extend_from_slice(b" upstream=1"); // 60.32 C6: dst is the proxy; up/down include its handshake
            }
            let _ = write!(b, " dur_ms={}", c.end_ms.saturating_sub(l.start_ms));
            if c.kind == Kind::Udp {
                let _ = write!(b, " up={} down={} dgrams_up={} dgrams_down={}", l.up, l.down, l.dg_up, l.dg_down);
            } else if let Some((rx, tx)) = c.bytes {
                // TCP payload the target acked / sent (its TLS records included). An active open counts its own SYN as
                // acked (tcpi_bytes_acked = 1 right after connect(); measured, Linux 6.x): not a byte of the stream
                let _ = write!(b, " up={} down={rx}", tx.saturating_sub(1));
            } else {
                b.extend_from_slice(b" up=0 down=0"); // never connected
            }
            match c.reason {
                Some(r) => {
                    let _ = write!(b, " reason=0x{r:02x}");
                }
                None => b.extend_from_slice(b" reason=none"),
            }
            let _ = write!(b, " why={}", c.why.name());
            if !c.rule.is_empty() {
                let _ = write!(b, " rule={}", c.rule);
            }
            b.push(b'\n');
            self.log_push(&b);
        }
        self.logline = b;
        self.sdone = done; // (its capacity kept)
    }

    /// on_connect (with --log-streams): a CONNECT refused before any Target (`body` = the CONNECT payload after the
    /// stream id; host and port as sent). 0x48 names the request rule here (Policy::refusal).
    #[cold]
    pub(super) fn slog_refused(&mut self, ci: u32, sid: u32, body: &[u8], code: u8, why: SWhy, rule: &'static str) {
        let sec = metrics::now_ms() / 1000;
        if self.sref_win.0 != sec {
            self.sref_win = (sec, 0);
        }
        if self.sref_win.1 >= REFUSED_PER_SEC {
            if let Some(o) = &self.outbox {
                o.stream_suppressed.fetch_add(1, Relaxed);
            }
            return;
        }
        self.sref_win.1 += 1;
        let (stype, port, host) = match body {
            [s, p0, p1, h @ ..] => (*s, u16::from_le_bytes([*p0, *p1]), h),
            _ => (0, 0, &[][..]),
        };
        let udp = stype == STREAM_UDP;
        let rule = match (code, &self.cfg.policy) {
            (CLOSE_BLOCKED, _) if udp && !self.cfg.udp => "no_udp",
            (CLOSE_BLOCKED, Some(p)) => std::str::from_utf8(host).ok().and_then(|h| p.refusal(udp, h, port)).unwrap_or(rule),
            _ => rule,
        };
        let seq = self.connlog.get(ci as usize).and_then(Option::as_ref).map(|c| c.seq);
        let ip = self.peers_of.get(ci as usize).and_then(Option::as_ref).map(|p| p.ip);
        let mut b = std::mem::take(&mut self.logline);
        self.line_head(&mut b, "stream_refused", seq, ip);
        let kind = match stype {
            STREAM_TCP => "tcp",
            STREAM_UDP => "udp",
            _ => "-",
        };
        let _ = write!(b, " sid={sid} t={kind} host=");
        // a refused host can be a whole frame (16 MiB): the first MAX_HOST bytes, and its length when cut (review)
        logs::value(&mut b, &host[..host.len().min(policy::MAX_HOST)]);
        if host.len() > policy::MAX_HOST {
            let _ = write!(b, " host_len={}", host.len());
        }
        let _ = write!(b, " port={port} reason=0x{code:02x} why={}", why.name());
        if !rule.is_empty() {
            let _ = write!(b, " rule={rule}");
        }
        b.push(b'\n');
        self.log_push(&b);
        self.logline = b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn why_from_the_close_reason() {
        use Phase::*;
        assert_eq!(stream_why(None, Open).0, SWhy::ClientClose);
        assert_eq!(stream_why(None, Dns).0, SWhy::ClientClose);
        assert_eq!(stream_why(Some(0x02), Open).0, SWhy::TargetClose);
        assert_eq!(stream_why(Some(0x03), Open).0, SWhy::TargetClose);
        assert_eq!(stream_why(Some(0x47), Open).0, SWhy::TargetClose, "a data-path error (net::data_reason)");
        assert_eq!(stream_why(Some(0x03), Connect).0, SWhy::ConnectFail, "net::connect_reason's default");
        assert_eq!(stream_why(Some(0x41), Dns).0, SWhy::Invalid);
        assert_eq!(stream_why(Some(0x42), Dns).0, SWhy::DnsFail);
        assert_eq!(stream_why(Some(0x42), Connect).0, SWhy::ConnectFail, "every connect() failed at once");
        assert_eq!(stream_why(Some(0x43), Connect).0, SWhy::ConnectFail);
        assert_eq!(stream_why(Some(0x44), Connect).0, SWhy::ConnectFail);
        assert_eq!(stream_why(Some(0x48), Connect).0, SWhy::Policy);
        assert_eq!(stream_why(Some(0x49), Open), (SWhy::Pressure, "over_credit"));
    }
}
