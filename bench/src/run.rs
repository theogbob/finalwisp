//! Wisp v1 load generator (pointer 30.01).
//! One tokio task per WebSocket connection owns the socket and all its streams.
//! It uses readiness (`ready` + `try_read_buf`/`try_write`) so reads and writes are
//! serviced fairly in one loop without locks.
use crate::errkind::ErrKinds;
use crate::verify;
use crate::ws::{self, MaskGen, OP_BIN, OP_CLOSE, OP_CONT, OP_PING, OP_PONG, OP_TEXT};
use crate::{RunArgs, Test};
use bytes::{Buf, BytesMut};
use hdrhistogram::Histogram;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::sync::{mpsc, watch};

#[path = "connchurn.rs"]
mod connchurn; // child module: shares Plan, Shared and the frame helpers

const WBUF_HIGH: usize = 512 * 1024;
const RBUF_CAP: usize = 1024 * 1024;
const MAX_PRINTED_ERRORS: u64 = 8;

const T_CONNECT: u8 = 1;
const T_DATA: u8 = 2;
const T_CONTINUE: u8 = 3;
const T_CLOSE: u8 = 4;
const T_INFO: u8 = 5;

struct Shared {
    /// [measure_start, end): set once before "go". Counting is decided by the clock, not by a phase flag that the
    /// main task flips on timer wakeups: on a busy box tokio timers fired seconds late, so the flag window drifted
    /// from the reported duration and once missed the whole window (duration 0, 60.12 scale tests).
    window: OnceLock<(Instant, Instant)>,
    printed: AtomicU64,
}

impl Shared {
    fn err(&self, msg: impl FnOnce() -> String) {
        if self.printed.fetch_add(1, Relaxed) < MAX_PRINTED_ERRORS {
            eprintln!("wbench error: {}", msg());
        }
    }
    #[inline]
    fn measuring(&self) -> bool {
        self.window.get().is_some_and(|&(s, e)| {
            let now = Instant::now();
            now >= s && now < e
        })
    }
}

fn new_hist() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 120_000_000, 3).expect("histogram")
}

struct ConnResult {
    up: u64,
    down: u64,
    ops: u64,
    errors: u64,
    stall_pings: u64,
    lost: u64,
    udp_continues: u64,
    hist: Histogram<u64>,
    pages: u64,
    page_hist: Histogram<u64>,
    bulk_down: u64,
    v: VerifyStats,
    errk: ErrKinds, // 30.16: errors by kind (sums to `errors`)
}

/// 60.15 T06 per-run verify totals (all zero without --verify)
#[derive(Default, Clone, Copy)]
struct VerifyStats {
    streams: u64,
    ok: u64,
    /// pieces with wrong content: seen here (download) + reported by the target (upload) + bytes after an END
    content_errors: u64,
    /// END present but the counts differ (target sent != we received, or target received != we sent), or no CLOSE after it
    count_errors: u64,
    /// streams without the target's END (closed early, drain timeout, connection lost)
    missing: u64,
    bytes_rx: u64,
    bytes_tx: u64,
    /// the targets' own counts from their ENDs (download: sent, upload: received)
    target_sent: u64,
    target_received: u64,
}

impl VerifyStats {
    fn add(&mut self, o: &VerifyStats) {
        self.streams += o.streams;
        self.ok += o.ok;
        self.content_errors += o.content_errors;
        self.count_errors += o.count_errors;
        self.missing += o.missing;
        self.bytes_rx += o.bytes_rx;
        self.bytes_tx += o.bytes_tx;
        self.target_sent += o.target_sent;
        self.target_received += o.target_received;
    }
    fn bad(&self) -> bool {
        self.content_errors + self.count_errors + self.missing > 0 || self.ok != self.streams
    }
}

/// 60.15 T06 one stream's verify state: pattern bytes we sent, the receiving side, our END queued
struct VSlot {
    tx: u64,
    rx: verify::Rx,
    end_sent: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    NeedOpen,
    Open,
    /// Closed by the server in a non-churn test: not reopened (avoids CONNECT storms).
    Dead,
}

struct Slot {
    id: u32,
    gen: u32,
    st: St,
    credit: u32,
    queued: bool,
    awaiting: bool,
    need: usize,
    t0: Instant,
    reqs_done: u32, // 20.19 browse: requests answered on this stream so far
}

struct Conn {
    test: Test,
    size: usize,
    slot_bits: u32,
    host: Vec<u8>,
    port: u16,
    initial_credit: u32,
    handshake_done: bool,
    slots: Vec<Slot>,
    ready: VecDeque<usize>,
    wbuf: Vec<u8>,
    woff: usize,
    mg: MaskGen,
    frag: Vec<u8>,
    in_frag: bool,
    sh: Arc<Shared>,
    up: u64,
    down: u64,
    ops: u64,
    errors: u64,
    hist: Histogram<u64>,
    /// Debug counters (printed with WBENCH_DEBUG=1).
    rx_continue: u64,
    rx_packets: u64,
    stall_ping: Duration,
    stall_pings: u64,
    max_continue: u32,
    /// 20.16 udp-rr: requests re-sent after UDP_LOSS_TIMEOUT, and CONTINUEs seen on UDP streams
    /// (the spec forbids them).
    lost: u64,
    udp_continues: u64,
    next_loss_scan: Instant,
    // 20.19 browse: slots[..page_streams] are short streams, slots[page_streams..] bulk streams
    page_streams: usize,
    resp_sizes: Vec<usize>,
    resp_idx: usize,
    reqs_per_stream: u32,
    bulk_size: usize,
    page_gap: Duration,
    page_t0: Instant,
    page_open: usize,            // short streams of the current page not yet closed
    page_next: Option<Instant>,  // waiting for the next page to start
    page_hist: Histogram<u64>,
    pages: u64,
    bulk_down: u64,
    // 60.15 T06 --verify (download/upload): one VSlot per slot (empty when off), pattern scratch, drain phase
    ver: Vec<VSlot>,
    vbuf: Vec<u8>,
    draining: bool,
    vstray: u64,
    errk: ErrKinds, // 30.16: one key per counted error (errkind.rs)
}
const UDP_LOSS_TIMEOUT: Duration = Duration::from_millis(200);

impl Conn {
    #[inline]
    fn wisp_hdr(ty: u8, id: u32) -> [u8; 5] {
        let i = id.to_le_bytes();
        [ty, i[0], i[1], i[2], i[3]]
    }

    fn push_wisp(&mut self, ty: u8, id: u32, body: &[u8], zero_tail: usize) {
        let key = self.mg.next();
        ws::push_frame(&mut self.wbuf, OP_BIN, &[&Self::wisp_hdr(ty, id), body], zero_tail, key);
    }

    fn queue(&mut self, s: usize) {
        if !self.slots[s].queued {
            self.slots[s].queued = true;
            self.ready.push_back(s);
        }
    }

    #[inline]
    fn lookup(&self, id: u32) -> Option<usize> {
        let s = (id & ((1u32 << self.slot_bits) - 1)) as usize;
        let sl = self.slots.get(s)?;
        (sl.id == id && sl.st == St::Open).then_some(s)
    }

    fn open(&mut self, s: usize) {
        let bits = self.slot_bits;
        let sl = &mut self.slots[s];
        loop {
            sl.gen = sl.gen.wrapping_add(1);
            sl.id = (sl.gen << bits) | s as u32;
            if sl.id != 0 {
                break;
            }
        }
        sl.st = St::Open;
        let udp = self.test == Test::UdpRr;
        sl.credit = if udp { u32::MAX } else { self.initial_credit }; // 20.16: UDP has no credit
        sl.awaiting = false;
        let id = sl.id;
        let mut body = Vec::with_capacity(3 + self.host.len());
        body.push(if udp { 2u8 } else { 1u8 }); // UDP / TCP
        body.extend_from_slice(&self.port.to_le_bytes());
        body.extend_from_slice(&self.host);
        self.push_wisp(T_CONNECT, id, &body, 0);
        // churn: latency is measured from CONNECT.
        self.slots[s].t0 = Instant::now();
        if let Some(v) = self.ver.get(s) {
            // 60.15 T06: the stream starts with HELLO (its key); download/upload streams are opened once (never reopened)
            let h = verify::hello(v.rx.key);
            self.slots[s].credit -= 1;
            self.push_wisp(T_DATA, id, &h, 0);
        }
    }

    /// 60.15 T06 drain: our END (pattern bytes sent / received so far) once the stream has credit for it
    fn send_end(&mut self, s: usize) {
        let sl = &self.slots[s];
        if sl.st != St::Open || sl.credit == 0 || self.ver[s].end_sent {
            return;
        }
        let v = &self.ver[s];
        let e = verify::End { sent: v.tx, received: v.rx.off, errs: v.rx.errs }.bytes();
        let id = sl.id;
        self.slots[s].credit -= 1;
        self.ver[s].end_sent = true;
        self.push_wisp(T_DATA, id, &e, 0);
    }

    fn send_data(&mut self, s: usize, size: usize) {
        let id = self.slots[s].id;
        assert!(self.slots[s].credit > 0, "bug: DATA without credit");
        if self.test != Test::UdpRr {
            self.slots[s].credit -= 1;
        }
        if let Some(v) = self.ver.get_mut(s) {
            // 60.15 T06: pattern instead of zeros (upload)
            let mut b = std::mem::take(&mut self.vbuf);
            b.resize(size, 0);
            verify::fill(v.rx.key, v.tx, &mut b);
            v.tx += size as u64;
            self.push_wisp(T_DATA, id, &b, 0);
            self.vbuf = b;
        } else {
            self.push_wisp(T_DATA, id, &[], size);
        }
        if self.sh.measuring() {
            self.up += size as u64;
        }
    }

    fn send_request(&mut self, s: usize, keep_t0: bool) {
        self.send_data(s, self.size);
        let sl = &mut self.slots[s];
        sl.awaiting = true;
        sl.need = self.size;
        if !keep_t0 {
            sl.t0 = Instant::now();
        }
    }

    /// 20.19 browse: one request = `size` bytes whose first 8 bytes are [resp_len][req_len] (LE u32),
    /// answered by a `reply` target with resp_len bytes.
    fn send_browse_request(&mut self, s: usize, keep_t0: bool) {
        let resp = if s >= self.page_streams {
            self.bulk_size
        } else {
            let r = self.resp_sizes[self.resp_idx % self.resp_sizes.len()];
            self.resp_idx += 1;
            r
        };
        let id = self.slots[s].id;
        assert!(self.slots[s].credit > 0, "bug: DATA without credit");
        self.slots[s].credit -= 1;
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&(resp as u32).to_le_bytes());
        hdr[4..].copy_from_slice(&(self.size as u32).to_le_bytes());
        let key = self.mg.next();
        ws::push_frame(&mut self.wbuf, OP_BIN, &[&Self::wisp_hdr(T_DATA, id), &hdr], self.size - 8, key);
        if self.sh.measuring() {
            self.up += self.size as u64;
        }
        let sl = &mut self.slots[s];
        sl.awaiting = true;
        sl.need = resp;
        if !keep_t0 {
            sl.t0 = Instant::now();
        }
    }

    /// 20.19 browse: open every short stream of a new page at once.
    fn start_page(&mut self) {
        self.page_next = None;
        self.page_t0 = Instant::now();
        self.page_open = self.page_streams;
        for s in 0..self.page_streams {
            self.queue(s);
        }
    }

    /// Generate outgoing frames until the write buffer is full or nobody can send.
    fn fill(&mut self) {
        while self.wbuf.len() - self.woff < WBUF_HIGH {
            let Some(s) = self.ready.pop_front() else { break };
            self.slots[s].queued = false;
            if self.slots[s].st == St::Dead {
                continue;
            }
            if self.draining {
                self.send_end(s); // 60.15 T06: no new streams or data, only ENDs
                continue;
            }
            if self.slots[s].st == St::NeedOpen {
                self.open(s);
                match self.test {
                    Test::Download | Test::ConnChurn => {} // connchurn never uses Conn (connchurn.rs)
                    Test::Upload | Test::Echo => self.queue(s),
                    Test::Rr | Test::Churn | Test::UdpRr => {
                        if self.slots[s].credit > 0 {
                            self.send_request(s, self.test == Test::Churn);
                        }
                    }
                    Test::Browse => {
                        self.slots[s].reqs_done = 0;
                        if self.slots[s].credit > 0 {
                            self.send_browse_request(s, true); // latency from CONNECT, like churn
                        }
                    }
                }
                continue;
            }
            let sl = &self.slots[s];
            match self.test {
                Test::Upload | Test::Echo => {
                    if sl.credit > 0 {
                        self.send_data(s, self.size);
                        if self.slots[s].credit > 0 {
                            self.queue(s);
                        }
                    }
                }
                Test::Rr | Test::Churn | Test::UdpRr => {
                    if !sl.awaiting && sl.credit > 0 {
                        self.send_request(s, false);
                    }
                }
                Test::Browse => {
                    if !sl.awaiting && sl.credit > 0 {
                        self.send_browse_request(s, false);
                    }
                }
                Test::Download | Test::ConnChurn => {}
            }
        }
    }

    /// 20.16 udp-rr: a request without a reply after UDP_LOSS_TIMEOUT was lost (UDP): send a new one.
    fn udp_loss_scan(&mut self) {
        for s in 0..self.slots.len() {
            let sl = &mut self.slots[s];
            if sl.st == St::Open && sl.awaiting && sl.t0.elapsed() >= UDP_LOSS_TIMEOUT {
                sl.awaiting = false;
                if self.sh.measuring() {
                    self.lost += 1;
                }
                self.queue(s);
            }
        }
        self.next_loss_scan = Instant::now() + UDP_LOSS_TIMEOUT / 2;
    }

    fn complete(&mut self, s: usize) {
        let sl = &mut self.slots[s];
        sl.awaiting = false;
        if self.test == Test::Browse {
            if s >= self.page_streams {
                self.queue(s); // bulk: next request right away, not timed
                return;
            }
            if self.sh.measuring() {
                self.ops += 1;
                self.hist.saturating_record(sl.t0.elapsed().as_micros() as u64);
            }
            sl.reqs_done += 1;
            if sl.reqs_done < self.reqs_per_stream {
                self.queue(s);
                return;
            }
            let id = sl.id;
            sl.st = St::NeedOpen;
            self.push_wisp(T_CLOSE, id, &[0x02], 0);
            self.page_open -= 1;
            if self.page_open == 0 {
                if self.sh.measuring() {
                    self.pages += 1;
                    self.page_hist.saturating_record(self.page_t0.elapsed().as_micros() as u64);
                }
                self.page_next = Some(Instant::now() + self.page_gap);
            }
            return;
        }
        if self.sh.measuring() {
            self.ops += 1;
            self.hist.saturating_record(sl.t0.elapsed().as_micros() as u64);
        }
        if self.test == Test::Churn {
            let id = sl.id;
            sl.st = St::NeedOpen;
            self.push_wisp(T_CLOSE, id, &[0x02], 0);
        }
        self.queue(s);
    }

    fn proto_err(&mut self, msg: impl FnOnce() -> String) {
        self.errors += 1;
        self.errk.key("proto");
        self.sh.err(msg);
    }

    /// Handle one Wisp packet. Err = fatal for the connection.
    fn on_packet(&mut self, p: &[u8]) -> Result<(), String> {
        if p.len() < 5 {
            self.proto_err(|| format!("short wisp packet ({} bytes)", p.len()));
            return Ok(());
        }
        let ty = p[0];
        let id = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
        let body = &p[5..];
        self.rx_packets += 1;
        match ty {
            T_DATA => {
                if self.sh.measuring() {
                    self.down += body.len() as u64;
                }
                if !self.ver.is_empty() {
                    match self.lookup(id) {
                        Some(s) => self.ver[s].rx.feed(body), // 60.15 T06 (download pattern, or the target's END)
                        None => self.vstray += body.len() as u64, // DATA on no open stream: never verified, an error
                    }
                }
                if matches!(self.test, Test::Rr | Test::Churn | Test::UdpRr | Test::Browse) {
                    if let Some(s) = self.lookup(id) {
                        if self.test == Test::Browse && s >= self.page_streams && self.sh.measuring() {
                            self.bulk_down += body.len() as u64;
                        }
                        let sl = &mut self.slots[s];
                        if sl.awaiting {
                            sl.need = sl.need.saturating_sub(body.len());
                            if sl.need == 0 {
                                self.complete(s);
                            }
                        }
                    }
                }
            }
            T_CONTINUE => {
                if body.len() < 4 {
                    self.proto_err(|| "short CONTINUE".into());
                    return Ok(());
                }
                let v = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                self.rx_continue += 1;
                self.max_continue = self.max_continue.max(v);
                if id == 0 {
                    if !self.handshake_done {
                        self.initial_credit = v;
                        self.handshake_done = true;
                    }
                } else if self.test == Test::UdpRr {
                    self.udp_continues += 1; // ignored: UDP streams have no credit
                } else if let Some(s) = self.lookup(id) {
                    self.slots[s].credit = v;
                    if v > 0 && !(matches!(self.test, Test::Rr) && self.slots[s].awaiting) {
                        self.queue(s);
                    }
                }
            }
            T_CLOSE => {
                let reason = body.first().copied().unwrap_or(0);
                if id == 0 {
                    return Err(format!("server sent connection CLOSE (reason 0x{reason:02x})"));
                }
                if let Some(s) = self.lookup(id).filter(|&s| self.ver.get(s).is_some_and(|v| v.rx.end.is_some())) {
                    self.slots[s].st = St::Dead; // 60.15 T06: the target closes after its END: expected
                } else if let Some(s) = self.lookup(id) {
                    self.errors += 1;
                    self.errk.stream_close(reason);
                    self.sh.err(|| format!("server closed stream {id} (reason 0x{reason:02x})"));
                    let reopen = matches!(self.test, Test::Churn | Test::Browse);
                    let sl = &mut self.slots[s];
                    sl.awaiting = false;
                    if reopen {
                        sl.st = St::NeedOpen;
                        self.queue(s);
                    } else {
                        sl.st = St::Dead;
                    }
                }
            }
            T_INFO => {}
            t => self.proto_err(|| format!("unknown wisp packet type {t}")),
        }
        Ok(())
    }

    /// Parse all complete WS frames in `rbuf`. Err = fatal.
    fn process(&mut self, rbuf: &mut BytesMut) -> Result<(), String> {
        loop {
            let h = match ws::parse_hdr(rbuf) {
                Ok(Some(h)) => h,
                Ok(None) => return Ok(()),
                Err(e) => return Err(e.to_string()),
            };
            let total = h.hdr_len + h.payload_len;
            if rbuf.len() < total {
                rbuf.reserve(total - rbuf.len());
                return Ok(());
            }
            if h.mask.is_some() {
                return Err("server sent a masked frame".into());
            }
            let payload = &rbuf[h.hdr_len..total];
            match h.opcode {
                OP_BIN | OP_TEXT if h.fin && !self.in_frag => self.on_packet(payload)?,
                OP_BIN | OP_TEXT if !self.in_frag => {
                    self.in_frag = true;
                    self.frag.clear();
                    self.frag.extend_from_slice(payload);
                }
                OP_CONT if self.in_frag => {
                    self.frag.extend_from_slice(payload);
                    if h.fin {
                        self.in_frag = false;
                        let f = std::mem::take(&mut self.frag);
                        let r = self.on_packet(&f);
                        self.frag = f;
                        r?;
                    }
                }
                OP_PING => {
                    let key = self.mg.next();
                    ws::push_frame(&mut self.wbuf, OP_PONG, &[payload], 0, key);
                }
                OP_PONG => {}
                OP_CLOSE => {
                    let code = if payload.len() >= 2 { u16::from_be_bytes([payload[0], payload[1]]) } else { 0 };
                    return Err(format!("websocket closed by server (code {code})"));
                }
                op => return Err(format!("unexpected ws opcode {op} (in_frag={})", self.in_frag)),
            }
            rbuf.advance(total);
        }
    }
}

enum Io {
    Progress,
    Deadline,
}

/// One readiness round: read what is available and write what is pending.
async fn io_round(
    c: &mut Conn,
    sock: &mut crate::tls::Sock,
    rbuf: &mut BytesMut,
    sleep: &mut std::pin::Pin<&mut tokio::time::Sleep>,
) -> Result<Io, String> {
    if c.woff == c.wbuf.len() {
        c.wbuf.clear();
        c.woff = 0;
    } else if c.woff > 4 * WBUF_HIGH {
        c.wbuf.drain(..c.woff);
        c.woff = 0;
    }
    c.fill();
    let pending = c.woff < c.wbuf.len() || sock.wants_write(); // 20.13: TLS records queued in rustls
    let interest = if pending { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE };
    // Optional workaround for servers that queue CONTINUE without flushing it:
    // when idle for `stall_ping`, send a WS ping so the server writes (and flushes) a pong.
    // Only tests that can block on credit (churn uses 1 credit/stream, download sends nothing).
    let can_starve = matches!(c.test, Test::Upload | Test::Echo | Test::Rr | Test::UdpRr);
    let stall = if !pending && can_starve && c.stall_ping > Duration::ZERO { Some(c.stall_ping) } else { None };
    let udp = c.test == Test::UdpRr;
    let loss_at = c.next_loss_scan;
    let page_at = c.page_next; // 20.19 browse: next page after the gap
    let ready = tokio::select! {
        _ = tokio::time::sleep_until(loss_at.into()), if udp => {
            c.udp_loss_scan();
            return Ok(Io::Progress);
        }
        _ = tokio::time::sleep_until(page_at.unwrap_or(loss_at).into()), if page_at.is_some() => {
            c.start_page();
            return Ok(Io::Progress);
        }
        r = sock.ready(interest) => r.map_err(|e| format!("socket: {e}"))?,
        _ = sleep.as_mut() => return Ok(Io::Deadline),
        _ = async { tokio::time::sleep(stall.unwrap()).await }, if stall.is_some() => {
            let key = c.mg.next();
            ws::push_frame(&mut c.wbuf, OP_PING, &[b"wbench"], 0, key);
            c.stall_pings += 1;
            return Ok(Io::Progress);
        }
    };
    if ready.is_readable() || ready.is_read_closed() {
        if rbuf.capacity() - rbuf.len() < 64 * 1024 {
            rbuf.reserve(RBUF_CAP);
        }
        match sock.try_read_buf(rbuf) {
            Ok(0) => return Err("websocket TCP connection closed by server".into()),
            Ok(_) => c.process(rbuf)?,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    if pending && ready.is_writable() {
        match sock.try_write(&c.wbuf[c.woff..]) {
            Ok(n) => c.woff += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(format!("write: {e}")),
        }
    }
    Ok(Io::Progress)
}

struct Plan {
    url: ws::Url,
    test: Test,
    size: usize,
    streams: usize,
    host: String,
    port: u16,
    stall_ping: Duration,
    tls: Option<Arc<rustls::ClientConfig>>,
    // 20.19 browse
    resp_sizes: Vec<usize>,
    reqs_per_stream: u32,
    page_gap: Duration,
    bulk: usize,
    bulk_size: usize,
    verify: bool,
}

/// 60.15 T06: how long the END handshake may take after the measured window (in-flight data drains first)
const DRAIN: Duration = Duration::from_secs(15);

async fn conn_task(
    idx: usize,
    plan: Arc<Plan>,
    sh: Arc<Shared>,
    ready_tx: mpsc::Sender<Result<(), String>>,
    mut go: watch::Receiver<Option<Instant>>,
    setup_deadline: Instant,
) -> ConnResult {
    let streams = plan.streams + plan.bulk; // 20.19 browse: bulk slots after the short-stream slots
    let slot_bits = (usize::BITS - (streams.max(2) - 1).leading_zeros()).max(1);
    let now = Instant::now();
    let mut c = Conn {
        test: plan.test,
        size: plan.size,
        slot_bits,
        host: plan.host.as_bytes().to_vec(),
        port: plan.port,
        initial_credit: 0,
        handshake_done: false,
        slots: (0..streams)
            .map(|_| Slot { id: 0, gen: 0, st: St::NeedOpen, credit: 0, queued: false, awaiting: false, need: 0, t0: now, reqs_done: 0 })
            .collect(),
        ready: VecDeque::with_capacity(streams),
        wbuf: Vec::with_capacity(WBUF_HIGH * 2),
        woff: 0,
        mg: MaskGen::new(0x9E37_79B9u32.wrapping_mul(idx as u32 + 1)),
        frag: Vec::new(),
        in_frag: false,
        sh: sh.clone(),
        up: 0,
        down: 0,
        ops: 0,
        errors: 0,
        hist: new_hist(),
        rx_continue: 0,
        rx_packets: 0,
        stall_ping: plan.stall_ping,
        stall_pings: 0,
        max_continue: 0,
        lost: 0,
        udp_continues: 0,
        next_loss_scan: now + UDP_LOSS_TIMEOUT,
        page_streams: plan.streams,
        resp_sizes: plan.resp_sizes.clone(),
        resp_idx: 0,
        reqs_per_stream: plan.reqs_per_stream.max(1),
        bulk_size: plan.bulk_size,
        page_gap: plan.page_gap,
        page_t0: now,
        page_open: 0,
        page_next: None,
        page_hist: new_hist(),
        pages: 0,
        bulk_down: 0,
        // key = stream number + 1 (< 2^24, checked in run()): unique per stream of this run
        ver: if plan.verify {
            (0..streams).map(|s| VSlot { tx: 0, rx: verify::Rx::new((idx * streams + s + 1) as u64), end_sent: false }).collect()
        } else {
            Vec::new()
        },
        vbuf: Vec::new(),
        draining: false,
        vstray: 0,
        errk: ErrKinds::default(),
    };
    let fail = |c: &mut Conn, msg: String| {
        c.errors += 1;
        c.errk.msg(&msg);
        sh.err(|| format!("conn {idx}: {msg}"));
    };

    // --- setup: WS upgrade + Wisp v1 handshake (CONTINUE on stream 0) ---
    let setup = async {
        let (mut sock, mut rbuf) = ws::connect(&plan.url, plan.tls.as_ref()).await.map_err(|e| e.to_string())?;
        let far = tokio::time::sleep_until(setup_deadline.into());
        tokio::pin!(far);
        while !c.handshake_done {
            c.process(&mut rbuf)?;
            if c.handshake_done {
                break;
            }
            if let Io::Deadline = io_round(&mut c, &mut sock, &mut rbuf, &mut far).await? {
                return Err("timeout waiting for Wisp CONTINUE handshake".to_string());
            }
        }
        Ok::<_, String>((sock, rbuf))
    };
    let setup = tokio::time::timeout_at(setup_deadline.into(), setup).await;
    let (mut sock, mut rbuf) = match setup {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            let _ = ready_tx.send(Err(e.clone())).await;
            fail(&mut c, e);
            return c.into_result();
        }
        Err(_) => {
            let _ = ready_tx.send(Err("setup timeout".into())).await;
            fail(&mut c, "setup timeout".into());
            return c.into_result();
        }
    };
    let _ = ready_tx.send(Ok(())).await;
    drop(ready_tx);
    let deadline = loop {
        if let Some(d) = *go.borrow_and_update() {
            break d;
        }
        if go.changed().await.is_err() {
            return c.into_result();
        }
    };

    if c.test == Test::Browse {
        c.start_page();
        for s in c.page_streams..streams {
            c.queue(s);
        }
    } else {
        for s in 0..streams {
            c.queue(s);
        }
    }
    let sleep = tokio::time::sleep_until(deadline.into());
    tokio::pin!(sleep);
    // Frames that arrived while waiting for "go".
    if let Err(e) = c.process(&mut rbuf) {
        fail(&mut c, e);
        return c.into_result();
    }
    loop {
        match io_round(&mut c, &mut sock, &mut rbuf, &mut sleep).await {
            Ok(Io::Progress) => {}
            Ok(Io::Deadline) => {
                if !c.ver.is_empty() {
                    drain(&mut c, &mut sock, &mut rbuf).await;
                }
                break;
            }
            Err(e) => {
                if Instant::now() < deadline {
                    fail(&mut c, e);
                }
                break;
            }
        }
    }
    c.into_result()
}

/// 60.15 T06: after the measured window, send END on every open stream and read on (unmeasured) until every stream
/// is closed (the target closes after its END, the server relays that as CLOSE: bytes between END and CLOSE are
/// caught as trailing) or DRAIN passed. What is still missing then is counted in into_result.
async fn drain(c: &mut Conn, sock: &mut crate::tls::Sock, rbuf: &mut BytesMut) {
    c.draining = true;
    for s in 0..c.slots.len() {
        c.queue(s);
    }
    let far = tokio::time::sleep(DRAIN);
    tokio::pin!(far);
    let done = |c: &Conn| c.slots.iter().all(|sl| sl.st != St::Open);
    while !done(c) {
        match io_round(c, sock, rbuf, &mut far).await {
            Ok(Io::Progress) => {}
            Ok(Io::Deadline) | Err(_) => break,
        }
    }
}

impl Conn {
    fn into_result(self) -> ConnResult {
        if std::env::var_os("WBENCH_DEBUG").is_some() {
            let credits: Vec<u32> = self.slots.iter().take(8).map(|s| s.credit).collect();
            eprintln!(
                "debug: rx_packets={} rx_continue={} max_continue={} stall_pings={} initial_credit={} credits(first 8)={credits:?} wbuf_pending={}",
                self.rx_packets,
                self.rx_continue,
                self.max_continue,
                self.stall_pings,
                self.initial_credit,
                self.wbuf.len() - self.woff
            );
        }
        let mut v = VerifyStats::default();
        v.content_errors += u64::from(self.vstray > 0);
        for (sl, x) in self.slots.iter().zip(&self.ver) {
            v.streams += 1;
            v.bytes_rx += x.rx.off;
            v.bytes_tx += x.tx;
            v.content_errors += x.rx.errs + u64::from(x.rx.trailing > 0);
            match x.rx.end {
                None => v.missing += 1,
                Some(e) => {
                    v.content_errors += e.errs;
                    v.target_sent += e.sent;
                    v.target_received += e.received;
                    // still Open = no CLOSE after the END within DRAIN: termination incomplete, counted as a mismatch
                    let counts_ok = e.sent == x.rx.off && e.received == x.tx && sl.st != St::Open;
                    v.count_errors += u64::from(!counts_ok);
                    v.ok += u64::from(counts_ok && e.errs == 0 && x.rx.errs == 0 && x.rx.trailing == 0);
                }
            }
        }
        ConnResult { up: self.up, down: self.down, ops: self.ops, errors: self.errors, stall_pings: self.stall_pings, lost: self.lost, udp_continues: self.udp_continues, hist: self.hist, pages: self.pages, page_hist: self.page_hist, bulk_down: self.bulk_down, v, errk: self.errk }
    }
}

pub async fn run(a: RunArgs) -> Result<i32, String> {
    let url = ws::parse_url(&a.url)?;
    let (host, port) = a.target.rsplit_once(':').ok_or("--target must be host:port")?;
    let port: u16 = port.parse().map_err(|_| "bad --target port")?;
    if a.conns == 0 || a.streams == 0 {
        return Err("--conns and --streams must be >= 1".into());
    }
    if a.duration.is_nan() || a.duration <= 0.0 {
        return Err("--duration must be > 0 (rates divide by it)".into());
    }
    if a.streams > (1 << 20) {
        return Err("--streams must be <= 1048576".into());
    }
    let size = a.size.unwrap_or(match a.test {
        Test::Upload | Test::Echo => 16384,
        Test::Rr | Test::Churn | Test::UdpRr | Test::ConnChurn => 64,
        Test::Browse => 512,
        Test::Download => 0,
    });
    if matches!(a.test, Test::Upload | Test::Echo | Test::Rr | Test::Churn | Test::UdpRr | Test::ConnChurn) && size == 0 {
        return Err("--size must be > 0".into());
    }
    if a.test == Test::Browse && size < 8 {
        return Err("browse: --size must be >= 8 (request header)".into());
    }
    if a.verify && !matches!(a.test, Test::Download | Test::Upload) {
        return Err("--verify supports --test download and upload (60.15 T06)".into());
    }
    if a.verify && a.conns.saturating_mul(a.streams) >= 1 << 24 {
        return Err("--verify: at most 2^24 - 1 streams (pattern key)".into());
    }
    let resp_sizes: Vec<usize> = a.resp.split(',').map(|s| s.trim().parse::<usize>().map_err(|_| format!("bad --resp value {s:?}"))).collect::<Result<_, _>>()?;
    if resp_sizes.is_empty() {
        return Err("--resp needs at least one size".into());
    }
    let tls = match (url.tls, a.insecure) {
        (false, _) => None,
        (true, true) => Some(crate::tls::insecure_config()),
        (true, false) => return Err("wss:// needs --insecure (wbench does not verify certificates)".into()),
    };
    let plan = Arc::new(Plan {
        url,
        test: a.test,
        size,
        streams: a.streams,
        host: host.to_string(),
        port,
        stall_ping: Duration::from_micros((a.stall_ping_ms * 1000.0) as u64),
        tls,
        resp_sizes,
        reqs_per_stream: a.reqs_per_stream,
        page_gap: Duration::from_micros((a.page_gap_ms * 1000.0) as u64),
        bulk: if a.test == Test::Browse { a.bulk } else { 0 },
        bulk_size: a.bulk_size.max(1),
        verify: a.verify,
    });
    if a.test == Test::ConnChurn {
        let start = Instant::now();
        let measure_start = start + Duration::from_secs_f64(a.warmup);
        let end = measure_start + Duration::from_secs_f64(a.duration);
        let (ops, errors, hist, ok, errk) = connchurn::run(plan, a.conns * a.streams, measure_start, end).await;
        debug_assert_eq!(errk.total(), errors, "30.16: every counted error has a kind");
        let elapsed = a.duration;
        let rps = ops as f64 / elapsed;
        let pct = |q: f64| if hist.is_empty() { 0 } else { hist.value_at_quantile(q) };
        let (p50, p90, p99, p999) = (pct(0.50), pct(0.90), pct(0.99), pct(0.999));
        println!(
            "connchurn conns={} streams={} size={size} {elapsed:.2}s: {rps:.0} conns/s, p50={p50}us p90={p90}us p99={p99}us p999={p999}us, errors={errors} (loops ok {ok}/{})",
            a.conns, a.streams, a.conns * a.streams
        );
        if a.json {
            println!(
                "{{\"test\":\"connchurn\",\"conns\":{},\"streams\":{},\"size\":{size},\"duration\":{elapsed:.3},\"mib_s_up\":0.00,\"mib_s_down\":0.00,\"rps\":{rps:.1},\"p50_us\":{p50},\"p90_us\":{p90},\"p99_us\":{p99},\"p999_us\":{p999},\"errors\":{errors},\"conns_ok\":{ok},\"stall_pings\":0,\"lost\":0,\"pages_s\":0.00,\"page_p50_us\":0,\"page_p99_us\":0,\"bulk_mib_s\":0.00,\"error_kinds\":{}}}",
                a.conns, a.streams, errk.json()
            );
        }
        return Ok(if ok == 0 { 3 } else { 0 });
    }
    let sh = Arc::new(Shared { window: OnceLock::new(), printed: AtomicU64::new(0) });
    let (ready_tx, mut ready_rx) = mpsc::channel(a.conns.min(4096));
    let (go_tx, go_rx) = watch::channel(None);
    let setup_deadline = Instant::now() + Duration::from_secs(15);

    let mut handles = Vec::with_capacity(a.conns);
    for i in 0..a.conns {
        handles.push(tokio::spawn(conn_task(
            i,
            plan.clone(),
            sh.clone(),
            ready_tx.clone(),
            go_rx.clone(),
            setup_deadline,
        )));
    }
    drop(ready_tx);
    let mut ok = 0usize;
    while let Some(r) = ready_rx.recv().await {
        if r.is_ok() {
            ok += 1;
        }
    }
    let start = Instant::now();
    let measure_start = start + Duration::from_secs_f64(a.warmup);
    let end = measure_start + Duration::from_secs_f64(a.duration);
    let _ = sh.window.set((measure_start, end));
    let _ = go_tx.send(Some(end));
    tokio::time::sleep_until(end.into()).await;
    // how late the end timer fired (diagnostic: > ~10 ms means a starved client runtime)
    let timer_late_ms = end.elapsed().as_secs_f64() * 1000.0;
    let elapsed = a.duration;

    let (mut up, mut down, mut ops, mut errors, mut pings) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut lost, mut udp_continues) = (0u64, 0u64);
    let (mut pages, mut bulk_down) = (0u64, 0u64);
    let mut hist = new_hist();
    let mut page_hist = new_hist();
    let mut v = VerifyStats::default();
    let mut errk = ErrKinds::default();
    for h in handles {
        // Tasks exit at `end` (+ DRAIN with --verify); bound the join anyway.
        match tokio::time::timeout(Duration::from_secs(5) + if a.verify { DRAIN } else { Duration::ZERO }, h).await {
            Ok(Ok(r)) => {
                v.add(&r.v);
                up += r.up;
                down += r.down;
                ops += r.ops;
                errors += r.errors;
                errk.merge(&r.errk);
                pings += r.stall_pings;
                lost += r.lost;
                udp_continues += r.udp_continues;
                pages += r.pages;
                bulk_down += r.bulk_down;
                let _ = hist.add(&r.hist);
                let _ = page_hist.add(&r.page_hist);
            }
            _ => {
                errors += 1;
                errk.key("join_timeout");
                if a.verify {
                    // 60.15 T06: this conn's streams were never reconciled
                    v.streams += a.streams as u64;
                    v.missing += a.streams as u64;
                }
            }
        }
    }
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0) / elapsed;
    let (mib_up, mib_down) = (mib(up), mib(down));
    let rps = ops as f64 / elapsed;
    let pct = |q: f64| if hist.is_empty() { 0 } else { hist.value_at_quantile(q) };
    let (p50, p90, p99, p999) = (pct(0.50), pct(0.90), pct(0.99), pct(0.999));
    let ppct = |q: f64| if page_hist.is_empty() { 0 } else { page_hist.value_at_quantile(q) };
    let (pg50, pg99) = (ppct(0.50), ppct(0.99));
    let bulk_mib = mib(bulk_down);
    let name = a.test.name();
    match a.test {
        Test::Browse => println!(
            "browse conns={} streams={} bulk={} size={size} {elapsed:.2}s: {rps:.0} req/s, req p50={p50}us p90={p90}us p99={p99}us; {:.1} pages/s, page p50={pg50}us p99={pg99}us; bulk {bulk_mib:.1} MiB/s, down total {mib_down:.1} MiB/s, errors={errors} (conns ok {ok}/{})",
            a.conns, a.streams, a.bulk, pages as f64 / elapsed, a.conns
        ),
        Test::Upload | Test::Download | Test::Echo => println!(
            "{name} conns={} streams={} size={size} {elapsed:.2}s: up {mib_up:.1} MiB/s, down {mib_down:.1} MiB/s, errors={errors} (conns ok {ok}/{}){}",
            a.conns, a.streams, a.conns, if pings > 0 { format!(" stall_pings={pings}") } else { String::new() }
        ),
        Test::Rr | Test::Churn | Test::UdpRr => println!(
            "{name} conns={} streams={} size={size} {elapsed:.2}s: {rps:.0} {}/s, p50={p50}us p90={p90}us p99={p99}us p999={p999}us, errors={errors} (conns ok {ok}/{}){}",
            a.conns,
            a.streams,
            match a.test { Test::Rr => "req", Test::UdpRr => "dgram-rr", _ => "streams" },
            a.conns,
            if a.test == Test::UdpRr { format!(" lost={lost} udp_continues={udp_continues}") } else { String::new() }
        ),
        Test::ConnChurn => unreachable!("connchurn returns early"),
    }
    if a.verify {
        println!(
            "verify: streams ok {}/{}, content errors {}, count mismatches {}, missing END {}; pattern bytes received {} (targets sent {}), sent {} (targets received {})",
            v.ok, v.streams, v.content_errors, v.count_errors, v.missing, v.bytes_rx, v.target_sent, v.bytes_tx, v.target_received
        );
    }
    if a.json {
        let vj = if a.verify {
            format!(
                ",\"verify_streams\":{},\"verify_ok\":{},\"verify_content_errors\":{},\"verify_count_errors\":{},\"verify_missing\":{},\"verify_bytes_rx\":{},\"verify_bytes_tx\":{},\"verify_target_sent\":{},\"verify_target_received\":{}",
                v.streams, v.ok, v.content_errors, v.count_errors, v.missing, v.bytes_rx, v.bytes_tx, v.target_sent, v.target_received
            )
        } else {
            String::new()
        };
        println!(
            "{{\"test\":\"{name}\",\"conns\":{},\"streams\":{},\"size\":{size},\"duration\":{elapsed:.3},\"mib_s_up\":{mib_up:.2},\"mib_s_down\":{mib_down:.2},\"rps\":{rps:.1},\"p50_us\":{p50},\"p90_us\":{p90},\"p99_us\":{p99},\"p999_us\":{p999},\"errors\":{errors},\"conns_ok\":{ok},\"stall_pings\":{pings},\"lost\":{lost},\"pages_s\":{:.2},\"page_p50_us\":{pg50},\"page_p99_us\":{pg99},\"bulk_mib_s\":{bulk_mib:.2},\"timer_late_ms\":{timer_late_ms:.1},\"error_kinds\":{}{vj}}}",
            a.conns, a.streams, pages as f64 / elapsed, errk.json()
        );
    }
    debug_assert_eq!(errk.total(), errors, "30.16: every counted error has a kind");
    Ok(if ok == 0 {
        3
    } else if a.verify && v.bad() {
        4 // 60.15 T06: wrong, missing or unreconciled bytes
    } else {
        0
    })
}
