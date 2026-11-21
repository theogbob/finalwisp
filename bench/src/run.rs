//! Wisp v1 load generator (pointer 30.01).
//! One tokio task per WebSocket connection owns the socket and all its streams.
//! It uses readiness (`ready` + `try_read_buf`/`try_write`) so reads and writes are
//! serviced fairly in one loop without locks.
use crate::edges;
use crate::errkind::ErrKinds;
use crate::lat::{self, Dist};
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
    /// 80.04 --rate: the instant of "go" (start of the warm-up): every connection's arrival schedule starts here
    go_at: OnceLock<Instant>,
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
    lat: Option<Dist>,          // 80.04 --lat / --rate
    ol: Option<Box<OpenLoop>>, // 80.04 --rate (counts after censoring)
    cnt: Counts,                // 80.04 --counts
}

/// 80.04 --counts: exact counts over the measured window (wisp DATA packets each way, echo messages fully back)
#[derive(Default, Clone, Copy)]
struct Counts {
    frames_up: u64,
    frames_down: u64,
    msgs: u64,
}

impl Counts {
    fn add(&mut self, o: &Counts) {
        self.frames_up += o.frames_up;
        self.frames_down += o.frames_down;
        self.msgs += o.msgs;
    }
}

/// 80.04 per-message latency of one connection (--lat, --rate)
struct LatTrack {
    /// true: a message completes when its last byte has come back (byte offsets per stream: echo, and every --rate
    /// test); false: rr / churn closed loop (complete() records the request's time)
    bytes: bool,
    /// per slot: (end offset, intended send time, actual send time) of the messages in flight
    fl: Vec<VecDeque<(u64, Instant, Instant)>>,
    tx: Vec<u64>,
    rx: Vec<u64>,
    lat: Dist,
}

/// 80.04 --rate: the open-loop state of one connection. Every arrival whose intended time is in the measured
/// window [ms, stop) ends as exactly one of: completed (latency recorded from the intended time), censored (still
/// unsent or in flight when the drain after the window ended: recorded at its age then, so a percentile that reaches
/// into the censored share is a lower bound), or dropped (refused at a full backlog or for a dead stream; never sent,
/// not in the histogram). sched = done + censored + dropped.
struct OpenLoop {
    sched: lat::Sched,
    ms: Instant,
    stop: Instant,
    rr: usize,
    pend: Vec<VecDeque<Instant>>, // per slot: intended times not sent yet (no credit, or the write buffer is full)
    backlog: u64,
    max_backlog: u64,
    sched_n: u64,
    out: u64, // window arrivals queued and not completed yet
    dropped: u64,
    censored: u64,
    unsent: u64,
    inflight: u64,
    svc: Dist, // from the actual send (what the server and the path took)
    lag: Dist, // intended -> actual send (this client's own delay: timer, runtime, credit, write buffer)
}
const OL_BACKLOG_MAX: u64 = 1 << 20;
const OL_BATCH: u32 = 4096; // arrivals scheduled per io_round at most

impl OpenLoop {
    fn add(&mut self, o: &OpenLoop) {
        self.max_backlog = self.max_backlog.max(o.max_backlog);
        self.sched_n += o.sched_n;
        self.dropped += o.dropped;
        self.censored += o.censored;
        self.unsent += o.unsent;
        self.inflight += o.inflight;
        self.svc.add(&o.svc);
        self.lag.add(&o.lag);
    }
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
    rx_b: u64,      // 80.04 --counts echo: bytes back on this stream since it opened (message k is back at k * size)
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
    cnt: Counts, // 80.04 --counts (counted always: a few adds per packet)
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
    lt: Option<Box<LatTrack>>, // 80.04 --lat / --rate
    ol: Option<Box<OpenLoop>>, // 80.04 --rate (set at "go")
    /// 80.04 --rate: the last read or write of this connection (the stall ping counts from here: arrival timer
    /// wake-ups must not restart it)
    idle_since: Instant,
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
        sl.rx_b = 0;
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
            self.cnt.frames_up += 1;
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
            self.cnt.frames_up += 1;
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
            if self.ol.is_some() {
                self.ol_fill(s); // 80.04 --rate: send what the schedule asked for, not what credit allows
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
                        if self.lt.is_some() {
                            self.lat_tx(s); // 80.04 --lat echo
                        }
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
            let e = sl.t0.elapsed();
            self.hist.saturating_record(e.as_micros() as u64);
            if let Some(lt) = self.lt.as_deref_mut() {
                lat_rec(lt, e); // 80.04 --lat
            }
        }
        if self.test == Test::Churn {
            let id = sl.id;
            sl.st = St::NeedOpen;
            self.push_wisp(T_CLOSE, id, &[0x02], 0);
        }
        self.queue(s);
    }

    /// 80.04: `n` bytes came back on slot s: complete every message whose last byte is now in.
    #[inline(never)] // 80.04: out of on_packet's closed-loop path
    fn lat_rx(&mut self, s: usize, n: usize) {
        let now = Instant::now();
        let measuring = self.sh.measuring();
        let Some(lt) = self.lt.as_deref_mut() else { return };
        lt.rx[s] += n as u64;
        while let Some(&(end, ti, ts)) = lt.fl[s].front() {
            if end > lt.rx[s] {
                break;
            }
            lt.fl[s].pop_front();
            let counted = match self.ol.as_deref_mut() {
                Some(ol) => {
                    let c = ti >= ol.ms && ti < ol.stop;
                    if c {
                        ol.svc.rec(now - ts);
                        ol.out -= 1;
                    }
                    c
                }
                None => measuring,
            };
            if counted {
                lt.lat.rec(now - ti);
            }
            if measuring {
                self.ops += 1;
            }
        }
    }

    /// 80.04 --rate: every arrival that is due by now goes to the next stream's queue (round robin).
    fn ol_schedule(&mut self) {
        let Some(ol) = self.ol.as_deref_mut() else { return };
        let now = Instant::now();
        let n = self.slots.len();
        let mut budget = OL_BATCH; // bounded catch-up per round: the socket is served between batches
        while ol.sched.next() <= now && ol.sched.next() < ol.stop && budget > 0 {
            budget -= 1;
            let ti = ol.sched.advance();
            let counted = ti >= ol.ms;
            let s = ol.rr;
            ol.rr = (ol.rr + 1) % n;
            if ol.backlog >= OL_BACKLOG_MAX || self.slots[s].st == St::Dead {
                if counted {
                    ol.sched_n += 1;
                    ol.dropped += 1;
                }
                continue;
            }
            ol.pend[s].push_back(ti);
            ol.backlog += 1;
            ol.max_backlog = ol.max_backlog.max(ol.backlog);
            if counted {
                ol.sched_n += 1;
                ol.out += 1;
            }
            if !self.slots[s].queued {
                self.slots[s].queued = true;
                self.ready.push_back(s);
            }
        }
    }

    /// 80.04 --rate: slot s went dead (the server closed the stream): its window arrivals that wait or are in flight
    /// can never complete: counted as dropped, out of the backlog and of `out`
    #[cold]
    #[inline(never)]
    fn ol_retire(&mut self, s: usize) {
        let (Some(ol), Some(lt)) = (self.ol.as_deref_mut(), self.lt.as_deref_mut()) else { return };
        let (ms, stop) = (ol.ms, ol.stop);
        let win = |t: Instant| t >= ms && t < stop;
        let waiting = ol.pend[s].iter().filter(|&&t| win(t)).count() as u64;
        let flying = lt.fl[s].iter().filter(|e| win(e.1)).count() as u64;
        ol.backlog -= ol.pend[s].len() as u64;
        ol.pend[s].clear();
        lt.fl[s].clear();
        ol.dropped += waiting + flying;
        ol.out -= waiting + flying;
    }

    /// 80.04 --rate: the next arrival time, None when the window has no more arrivals
    fn ol_next(&self) -> Option<Instant> {
        self.ol.as_deref().map(|o| o.sched.next()).filter(|&t| self.ol.as_deref().is_some_and(|o| t < o.stop))
    }

    /// 80.04 --lat echo: the message just sent on slot s completes when its last byte is back (out of line)
    #[inline(never)]
    fn lat_tx(&mut self, s: usize) {
        let Some(lt) = self.lt.as_mut() else { return };
        let now = Instant::now();
        lt.tx[s] += self.size as u64;
        lt.fl[s].push_back((lt.tx[s], now, now));
    }

    /// 80.04 --rate: slot s is ready: open it if needed, then send its oldest waiting message if it has credit.
    #[cold]
    #[inline(never)] // 80.04: out of line, so the closed loop's fill stays as small as before 80.04
    fn ol_fill(&mut self, s: usize) {
        if self.slots[s].st == St::NeedOpen {
            self.open(s);
        }
        if self.slots[s].st != St::Open || self.slots[s].credit == 0 {
            return; // a CONTINUE queues it again
        }
        let Some(ti) = self.ol.as_deref().and_then(|o| o.pend[s].front().copied()) else { return };
        self.send_data(s, self.size);
        let now = Instant::now();
        let size = self.size as u64;
        let (Some(ol), Some(lt)) = (self.ol.as_deref_mut(), self.lt.as_deref_mut()) else { return };
        ol.pend[s].pop_front();
        ol.backlog -= 1;
        if ti >= ol.ms && ti < ol.stop {
            ol.lag.rec(now - ti);
        }
        lt.tx[s] += size;
        lt.fl[s].push_back((lt.tx[s], ti, now));
        let more = !ol.pend[s].is_empty();
        if more && self.slots[s].credit > 0 {
            self.queue(s);
        }
    }

    /// 80.04 --rate, at the end: every window arrival still unsent or in flight is recorded at its age now (censored).
    fn ol_censor(&mut self) {
        let (Some(ol), Some(lt)) = (self.ol.as_deref_mut(), self.lt.as_deref_mut()) else { return };
        let now = Instant::now();
        let (ms, stop) = (ol.ms, ol.stop);
        let win = |t: Instant| t >= ms && t < stop;
        for q in &ol.pend {
            for &ti in q.iter().filter(|&&t| win(t)) {
                lt.lat.rec(now - ti);
                ol.censored += 1;
                ol.unsent += 1;
            }
        }
        for q in &lt.fl {
            for &(_, ti, _) in q.iter().filter(|e| win(e.1)) {
                lt.lat.rec(now - ti);
                ol.censored += 1;
                ol.inflight += 1;
            }
        }
        for q in ol.pend.iter_mut() {
            q.clear();
        }
        for q in lt.fl.iter_mut() {
            q.clear();
        }
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
                let measuring = self.sh.measuring();
                if measuring {
                    self.down += body.len() as u64;
                    self.cnt.frames_down += 1;
                }
                if self.test == Test::Echo && self.size > 0 {
                    // 80.04 --counts: echo message k of a stream is back when its k * size-th byte is
                    if let Some(s) = self.lookup(id) {
                        let (sz, sl) = (self.size as u64, &mut self.slots[s]);
                        let before = sl.rx_b / sz;
                        sl.rx_b += body.len() as u64;
                        if measuring {
                            self.cnt.msgs += sl.rx_b / sz - before;
                        }
                    }
                }
                if self.lt.as_ref().is_some_and(|l| l.bytes) {
                    if let Some(s) = self.lookup(id) {
                        self.lat_rx(s, body.len()); // 80.04
                    }
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
                        self.ol_retire(s); // 80.04 --rate (no-op without)
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

/// 80.04 --lat: one request's latency (out of line, so complete() stays as small as before 80.04)
#[inline(never)]
fn lat_rec(lt: &mut LatTrack, e: Duration) {
    lt.lat.rec(e);
}

/// One readiness round: read what is available and write what is pending.
/// One read/write round of a connection. OL = the connection runs --rate (c.ol is Some): the open-loop code is compiled
/// only into the OL instantiation, so the closed loop runs the same per-round work as before 80.04 (counted: the
/// unconditional open-loop code cost the closed loop +6 % user instructions per request on rr 1x1, counted)
async fn io_round<const OL: bool>(
    c: &mut Conn,
    sock: &mut crate::tls::Sock,
    rbuf: &mut BytesMut,
    sleep: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    tm: &mut Option<lat::Timer>,
) -> Result<Io, String> {
    if c.woff == c.wbuf.len() {
        c.wbuf.clear();
        c.woff = 0;
    } else if c.woff > 4 * WBUF_HIGH {
        c.wbuf.drain(..c.woff);
        c.woff = 0;
    }
    debug_assert_eq!(OL, c.ol.is_some());
    if OL {
        c.ol_schedule(); // 80.04 --rate
    }
    c.fill();
    let pending = c.woff < c.wbuf.len() || sock.wants_write(); // 20.13: TLS records queued in rustls
    let interest = if pending { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE };
    // Optional workaround for servers that queue CONTINUE without flushing it:
    // when idle for `stall_ping`, send a WS ping so the server writes (and flushes) a pong.
    // Only tests that can block on credit (churn uses 1 credit/stream, download sends nothing).
    let can_starve = matches!(c.test, Test::Upload | Test::Echo | Test::Rr | Test::UdpRr);
    let stall = if !pending && can_starve && c.stall_ping > Duration::ZERO { Some(c.stall_ping) } else { None };
    let stall_at = if OL { Some(c.idle_since + c.stall_ping) } else { None }; // 80.04 --rate: absolute
    let udp = c.test == Test::UdpRr;
    let loss_at = c.next_loss_scan;
    let page_at = c.page_next; // 20.19 browse: next page after the gap
    // 80.04 --rate: the timerfd wakes the task at the next arrival (only while the window still has arrivals)
    let tm_on = OL
        && match (tm.as_mut(), c.ol_next()) {
            (Some(t), Some(at)) => {
                t.arm(at).map_err(|e| format!("timerfd: {e}"))?;
                true
            }
            _ => false,
        };
    // 80.04: the closed loop (OL = false) keeps the pre-80.04 select! exactly (no timer branch, relative stall sleep)
    let ready = if OL {
        tokio::select! {
            r = async { tm.as_mut().unwrap().wait().await }, if tm_on => {
                r.map_err(|e| format!("timerfd: {e}"))?;
                return Ok(Io::Progress);
            }
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
            _ = async {
                match stall_at {
                    Some(t) => tokio::time::sleep_until(t.into()).await,
                    None => tokio::time::sleep(stall.unwrap()).await,
                }
            }, if stall.is_some() => {
                let key = c.mg.next();
                ws::push_frame(&mut c.wbuf, OP_PING, &[b"wbench"], 0, key);
                c.stall_pings += 1;
                c.idle_since = Instant::now();
                return Ok(Io::Progress);
            }
        }
    } else {
        tokio::select! {
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
        }
    };
    if ready.is_readable() || ready.is_read_closed() {
        if rbuf.capacity() - rbuf.len() < 64 * 1024 {
            rbuf.reserve(RBUF_CAP);
        }
        match sock.try_read_buf(rbuf) {
            Ok(0) => return Err("websocket TCP connection closed by server".into()),
            Ok(_) => {
                if OL {
                    c.idle_since = Instant::now(); // 80.04 --rate's absolute stall timer only
                }
                c.process(rbuf)?
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    if pending && ready.is_writable() {
        match sock.try_write(&c.wbuf[c.woff..]) {
            Ok(n) => {
                c.woff += n;
                if OL && n > 0 {
                    c.idle_since = Instant::now();
                }
            }
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
    // 80.04
    lat: bool,
    rate: Option<f64>,
    poisson: bool,
    drain: Duration,
    src_port: Option<u16>,
    conns: usize,
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
            .map(|_| Slot { id: 0, gen: 0, st: St::NeedOpen, credit: 0, queued: false, awaiting: false, need: 0, t0: now, reqs_done: 0, rx_b: 0 })
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
        cnt: Counts::default(),
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
        lt: plan.lat.then(|| {
            let bytes = plan.test == Test::Echo || plan.rate.is_some();
            let k = if bytes { streams } else { 0 }; // rr / churn closed loop: complete() records, no byte offsets
            Box::new(LatTrack { bytes, fl: vec![VecDeque::new(); k], tx: vec![0; k], rx: vec![0; k], lat: Dist::new() })
        }),
        ol: None,
        idle_since: now,
    };
    let fail = |c: &mut Conn, msg: String| {
        c.errors += 1;
        c.errk.msg(&msg);
        sh.err(|| format!("conn {idx}: {msg}"));
    };

    // --- setup: WS upgrade + Wisp v1 handshake (CONTINUE on stream 0) ---
    let setup = async {
        let local = plan.src_port.map(|b| b + idx as u16); // 80.04 --src-port (range checked in run())
        let (mut sock, mut rbuf) = ws::connect(&plan.url, plan.tls.as_ref(), local).await.map_err(|e| e.to_string())?;
        let far = tokio::time::sleep_until(setup_deadline.into());
        tokio::pin!(far);
        while !c.handshake_done {
            c.process(&mut rbuf)?;
            if c.handshake_done {
                break;
            }
            if let Io::Deadline = io_round::<false>(&mut c, &mut sock, &mut rbuf, &mut far, &mut None).await? {
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
    let mut tm: Option<lat::Timer> = None;
    if let Some(rate) = plan.rate {
        // 80.04 --rate: arrivals from the shared "go" instant (the warm-up has load; arrivals before the window are not
        // recorded; a task that sees "go" late catches up at once), connections staggered by idx / conns of a gap
        let (ms, stop) = *sh.window.get().expect("window is set before go");
        let k = plan.streams;
        let seed = 0x9E37_79B9_7F4A_7C15u64.wrapping_mul(idx as u64 + 1);
        c.ol = Some(Box::new(OpenLoop {
            sched: lat::Sched::new(rate / plan.conns as f64, plan.poisson, seed, *sh.go_at.get().unwrap_or(&ms), idx as f64 / plan.conns as f64),
            ms,
            stop,
            rr: 0,
            pend: vec![VecDeque::new(); k],
            backlog: 0,
            max_backlog: 0,
            sched_n: 0,
            out: 0,
            dropped: 0,
            censored: 0,
            unsent: 0,
            inflight: 0,
            svc: Dist::new(),
            lag: Dist::new(),
        }));
        c.idle_since = Instant::now(); // the closed-loop handshake rounds do not advance it: the stall timer starts at go
        match lat::Timer::new() {
            Ok(t) => tm = Some(t),
            Err(e) => {
                fail(&mut c, format!("timerfd: {e}"));
                return c.into_result();
            }
        }
    }

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
        let r = if c.ol.is_some() {
            io_round::<true>(&mut c, &mut sock, &mut rbuf, &mut sleep, &mut tm).await
        } else {
            io_round::<false>(&mut c, &mut sock, &mut rbuf, &mut sleep, &mut tm).await
        };
        match r {
            Ok(Io::Progress) => {}
            Ok(Io::Deadline) => {
                if !c.ver.is_empty() {
                    drain(&mut c, &mut sock, &mut rbuf).await;
                }
                if c.ol.is_some() {
                    ol_drain(&mut c, &mut sock, &mut rbuf, &mut tm, plan.drain).await;
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
        let r = if c.ol.is_some() {
            io_round::<true>(c, sock, rbuf, &mut far, &mut None).await
        } else {
            io_round::<false>(c, sock, rbuf, &mut far, &mut None).await
        };
        match r {
            Ok(Io::Progress) => {}
            Ok(Io::Deadline) | Err(_) => break,
        }
    }
}

/// 80.04 --rate: after the window, no new arrivals; read and write on until every window arrival has completed or the
/// window end + `d` has passed (one absolute cutoff; what is still open then is censored in into_result). The arrivals
/// still due before the window end (a late task: the deadline won select! first) are scheduled before anything else.
async fn ol_drain(c: &mut Conn, sock: &mut crate::tls::Sock, rbuf: &mut BytesMut, tm: &mut Option<lat::Timer>, d: Duration) {
    let Some(stop) = c.ol.as_deref().map(|o| o.stop) else { return };
    while c.ol_next().is_some_and(|t| t <= Instant::now()) {
        c.ol_schedule(); // OL_BATCH per call
    }
    let far = tokio::time::sleep_until((stop + d).into());
    tokio::pin!(far);
    while c.ol.as_deref().is_some_and(|o| o.out > 0) {
        match io_round::<true>(c, sock, rbuf, &mut far, tm).await {
            Ok(Io::Progress) => {}
            Ok(Io::Deadline) | Err(_) => break,
        }
    }
}

impl Conn {
    fn into_result(mut self) -> ConnResult {
        self.ol_censor(); // 80.04 --rate: whatever is still open now (every path ends here)
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
        ConnResult { up: self.up, down: self.down, ops: self.ops, errors: self.errors, stall_pings: self.stall_pings, lost: self.lost, udp_continues: self.udp_continues, hist: self.hist, pages: self.pages, page_hist: self.page_hist, bulk_down: self.bulk_down, v, errk: self.errk, lat: self.lt.map(|l| l.lat), ol: self.ol, cnt: self.cnt }
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
    // 80.04 options
    if let Some(r) = a.rate {
        if !r.is_finite() || r < 0.001 * a.conns as f64 || r > 1e7 {
            return Err("--rate: from 0.001 per connection to 1e7 messages per second".into());
        }
        if !matches!(a.test, Test::Echo | Test::Rr) {
            return Err("--rate (open loop) supports --test echo and rr (80.04)".into());
        }
    }
    let lat_on = a.lat || a.rate.is_some();
    if lat_on && !matches!(a.test, Test::Echo | Test::Rr | Test::Churn) {
        return Err("--lat supports --test echo, rr and churn (80.04; connchurn and browse have their own latency)".into());
    }
    if a.test == Test::ConnChurn && (a.edges || a.cpu_cgroup.is_some() || !a.cpu_pids.is_empty()) {
        return Err("--edges / --cpu-cgroup / --cpu-pids: not for connchurn (80.04)".into());
    }
    if a.cpu_cgroup.is_some() || !a.cpu_pids.is_empty() {
        edges::check(&edges::Cfg { cgroup: a.cpu_cgroup.clone(), pids: a.cpu_pids.clone() })?;
    }
    if let Some(b) = a.src_port {
        if a.test == Test::ConnChurn {
            return Err("--src-port: not for connchurn (a new connection per request)".into());
        }
        if b < 1024 || b as usize + a.conns - 1 > 65535 {
            return Err(format!("--src-port {b}: BASE >= 1024 and BASE + conns - 1 <= 65535"));
        }
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
        lat: lat_on,
        rate: a.rate,
        poisson: a.arrival == crate::Arrival::Poisson,
        drain: Duration::from_secs_f64(a.drain),
        src_port: a.src_port,
        conns: a.conns,
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
                "{{\"test\":\"connchurn\",\"conns\":{},\"streams\":{},\"size\":{size},\"duration\":{elapsed:.3},\"mib_s_up\":0.00,\"mib_s_down\":0.00,\"rps\":{rps:.1},\"p50_us\":{p50},\"p90_us\":{p90},\"p99_us\":{p99},\"p999_us\":{p999},\"errors\":{errors},\"conns_ok\":{ok},\"stall_pings\":0,\"lost\":0,\"pages_s\":0.00,\"page_p50_us\":0,\"page_p99_us\":0,\"bulk_mib_s\":0.00,\"error_kinds\":{}{}}}",
                a.conns, a.streams, errk.json(),
                if a.counts {
                    // 80.04 --counts: per completed loop (CONNECT, one size-byte DATA, echoed back); the DATA packets
                    // that carried the echo are not counted (null); "derived": from the loops, not counted per packet
                    let b = ops * size as u64;
                    format!(",\"counts\":{{\"window_s\":{elapsed},\"frames_up\":{ops},\"frames_down\":null,\"bytes_up\":{b},\"bytes_down\":{b},\"msgs\":{ops},\"derived\":true}}")
                } else {
                    String::new()
                }
            );
        }
        return Ok(if ok == 0 { 3 } else { 0 });
    }
    let sh = Arc::new(Shared { window: OnceLock::new(), printed: AtomicU64::new(0), go_at: OnceLock::new() });
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
    let _ = sh.go_at.set(start);
    let _ = go_tx.send(Some(end));
    // 80.04 --edges: counters at the window's start and end, read by an OS thread of its own (a tokio timer on a
    // saturated box fired up to 10 ms late; "late0_us" / "late1_us" say how late the thread was)
    let ecfg = (a.edges || a.cpu_cgroup.is_some() || !a.cpu_pids.is_empty())
        .then(|| edges::Cfg { cgroup: a.cpu_cgroup.clone(), pids: a.cpu_pids.clone() });
    let eth = ecfg.map(|c| {
        std::thread::spawn(move || {
            let at = |t: Instant| std::thread::sleep(t.saturating_duration_since(Instant::now()));
            at(measure_start);
            let e0 = edges::sample(&c);
            at(end);
            (e0, edges::sample(&c))
        })
    });
    tokio::time::sleep_until(end.into()).await;
    // how late the end timer fired (diagnostic: > ~10 ms means a starved client runtime)
    let timer_late_ms = end.elapsed().as_secs_f64() * 1000.0;
    let (e0, e1) = match eth.map(|h| h.join()) {
        Some(Ok((x, y))) => (Some(x), Some(y)),
        _ => (None, None),
    };
    let elapsed = a.duration;

    let (mut up, mut down, mut ops, mut errors, mut pings) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut lost, mut udp_continues) = (0u64, 0u64);
    let (mut pages, mut bulk_down) = (0u64, 0u64);
    let mut cnt = Counts::default();
    let mut hist = new_hist();
    let mut page_hist = new_hist();
    let mut v = VerifyStats::default();
    let mut errk = ErrKinds::default();
    let mut lat_all = lat_on.then(Dist::new);
    let mut ol_all: Option<Box<OpenLoop>> = None;
    let mut lat_lost = 0u64; // 80.04 connections whose latency never came back (join timeout)
    for h in handles {
        // Tasks exit at `end` (+ DRAIN with --verify, + --drain with --rate); bound the join anyway.
        let more = if a.verify { DRAIN } else { Duration::ZERO } + if a.rate.is_some() { plan.drain } else { Duration::ZERO };
        match tokio::time::timeout(Duration::from_secs(5) + more, h).await {
            Ok(Ok(mut r)) => {
                if let (Some(all), Some(l)) = (lat_all.as_mut(), r.lat.as_ref()) {
                    all.add(l);
                }
                if let Some(o) = r.ol.take() {
                    match ol_all.as_mut() {
                        Some(all) => all.add(&o),
                        None => ol_all = Some(o),
                    }
                }
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
                cnt.add(&r.cnt);
                let _ = hist.add(&r.hist);
                let _ = page_hist.add(&r.page_hist);
            }
            _ => {
                errors += 1;
                lat_lost += 1;
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
    // 80.04: the new keys of the --json line (empty without the new flags: the line is unchanged)
    let mut x = String::new();
    if let Some(l) = &lat_all {
        let us = |ns: u64| ns as f64 / 1000.0;
        let q = |p: f64| if l.n() == 0 { 0 } else { l.h.value_at_quantile(p) };
        let cens = ol_all.as_ref().map_or(0, |o| o.censored);
        println!(
            "lat: n={} mean={:.1}us p50={:.1}us p90={:.1}us p99={:.1}us p999={:.1}us max={:.1}us{}",
            l.n(),
            if l.n() == 0 { 0.0 } else { l.sum as f64 / l.n() as f64 / 1000.0 },
            us(q(0.5)),
            us(q(0.9)),
            us(q(0.99)),
            us(q(0.999)),
            us(l.max),
            if cens > 0 { format!(" (censored {cens}: tail percentiles are lower bounds)") } else { String::new() }
        );
        x.push_str(&format!(",\"lat\":{},\"lat_lost_conns\":{lat_lost}", l.json(true)));
    }
    if let (Some(r), Some(o)) = (a.rate, ol_all.as_ref()) {
        let done = o.sched_n - o.censored - o.dropped;
        println!(
            "open loop: offered {:.0}/s ({:?}), scheduled {} in the window, completed {done}, censored {} (unsent {}, in flight {}), dropped {}, max backlog {}",
            r, a.arrival, o.sched_n, o.censored, o.unsent, o.inflight, o.dropped, o.max_backlog
        );
        x.push_str(&format!(
            ",\"ol\":{{\"rate\":{r},\"arrival\":\"{}\",\"offered_rps\":{:.1},\"sched\":{},\"done\":{done},\"censored\":{},\"unsent\":{},\"inflight\":{},\"dropped\":{},\"max_backlog\":{},\"drain_s\":{},\"svc\":{},\"lag\":{}}}",
            if a.arrival == crate::Arrival::Poisson { "poisson" } else { "fixed" },
            o.sched_n as f64 / elapsed,
            o.sched_n,
            o.censored,
            o.unsent,
            o.inflight,
            o.dropped,
            o.max_backlog,
            a.drain,
            o.svc.json(true),
            o.lag.json(false)
        ));
    }
    if let (Some(e0), Some(e1)) = (&e0, &e1) {
        x.push_str(&format!(",\"edges\":{}", edges::json(e0, e1, (measure_start, end))));
    }
    if let Some(b) = a.src_port {
        x.push_str(&format!(",\"src_port\":{b}"));
    }
    if a.counts {
        // 80.04 exact counts over the window: wisp DATA packets and payload bytes each way; msgs = echo messages fully
        // back (k-th message of a stream at its k * size-th byte), rr / churn / udp-rr / browse requests done; null for
        // upload / download (a message is a frame there)
        let msgs = match a.test {
            Test::Echo => cnt.msgs.to_string(),
            Test::Rr | Test::Churn | Test::UdpRr | Test::Browse => ops.to_string(),
            _ => "null".to_string(),
        };
        x.push_str(&format!(
            ",\"counts\":{{\"window_s\":{elapsed},\"frames_up\":{},\"frames_down\":{},\"bytes_up\":{up},\"bytes_down\":{down},\"msgs\":{msgs}}}",
            cnt.frames_up, cnt.frames_down
        ));
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
            "{{\"test\":\"{name}\",\"conns\":{},\"streams\":{},\"size\":{size},\"duration\":{elapsed:.3},\"mib_s_up\":{mib_up:.2},\"mib_s_down\":{mib_down:.2},\"rps\":{rps:.1},\"p50_us\":{p50},\"p90_us\":{p90},\"p99_us\":{p99},\"p999_us\":{p999},\"errors\":{errors},\"conns_ok\":{ok},\"stall_pings\":{pings},\"lost\":{lost},\"pages_s\":{:.2},\"page_p50_us\":{pg50},\"page_p99_us\":{pg99},\"bulk_mib_s\":{bulk_mib:.2},\"timer_late_ms\":{timer_late_ms:.1},\"error_kinds\":{}{vj}{x}}}",
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
