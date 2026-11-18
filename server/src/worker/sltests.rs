//! 60.72 worker tests for --stream-share and --stream-pool (crate::slimits, worker/slimits.rs). Each test drives real
//! Workers through their own epoll (the helpers of fdtests.rs); the other workers' fds and connections are set by hand
//! (FdGate::grab, Inbox::load), as they would be.
use super::super::*;
use super::fd::{client, closed_with, connect, drain, fd_cfg, fds, pump, until, wisp};
use crate::fdgate::{FdGate, MARK_HOST, MARK_POOL, MARK_STREAM};
use crate::slimits::{self as sl, Slimits};
use std::io::Write as _;
use std::net::{TcpListener, TcpStream};

/// A worker `idx` of `n` (peers: `n` inboxes) with its own fd gate (`limit` usable fds in blocks of 4, the marks of
/// `mask`)
fn rig_n(idx: usize, n: usize, limit: u32, mask: u8) -> (Worker, u16, mpsc::Receiver<DnsReq>, Arc<FdGate>) {
    let (tx, rx) = mpsc::channel();
    let mut cfg = fd_cfg();
    cfg.threads = n;
    let peers: Arc<Vec<Arc<Inbox>>> = Arc::new((0..n).map(|_| Inbox::new()).collect());
    let mut w = Worker::new(Arc::new(cfg), tx, idx, peers, Arc::default()).unwrap();
    let g = Arc::new(FdGate::new(limit, 4));
    g.set_marks(mask);
    w.fdg = g.clone();
    w.fd_setup();
    let port = unsafe { <TcpListener as std::os::fd::FromRawFd>::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    (w, port, rx, g)
}

fn live(w: &Worker) -> usize {
    w.targets.slots.len() - w.targets.free.len()
}

/// `n` CONNECTs on `c` (ids from `sid`) to `lp`, pumped until each is open or refused
fn ask(w: &mut Worker, c: &mut TcpStream, sid: u32, n: u32, lp: u16, refused: impl Fn(&Worker) -> u64) {
    let want = live(w) as u64 + refused(w) + n as u64;
    for s in sid..sid + n {
        c.write_all(&connect(s, false, lp)).unwrap();
    }
    until(w, "every CONNECT answered", |w| live(w) as u64 + refused(w) == want);
}

/// what the server sent on `c` holds CLOSE 0x49 for each of `sids` (at most 3 s)
fn throttled(w: &mut Worker, c: &mut TcpStream, got: &mut Vec<u8>, sids: impl Iterator<Item = u32> + Clone) -> bool {
    for _ in 0..600 {
        drain(c, got);
        if sids.clone().all(|s| closed_with(got, s, CLOSE_THROTTLED)) {
            return true;
        }
        pump(w, 5);
    }
    false
}

fn end(w: Worker) {
    for fd in [w.ep, w.lfd, w.inbox.efd, w.spare] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w); // (as fdtests: no frees while mem::tests::heap_counter_moves measures)
}

/// --stream-share end to end. 1000 usable fds, 875 of them held by other workers (the mark is set), 61 connections in
/// all: share 16, cap 32 (the floor) at the mark. The heavy connection gets 32 streams, then 0x49 for each new one
/// (refuse_stream_share); a light connection opens streams; open streams go on. Below 13/16 the mark is at rest and
/// the heavy connection opens streams again. Without the option (the mark not in the gate's mask, no state) the same
/// load is not refused.
#[test]
fn stream_share_caps_the_busiest_connection_from_the_mark() {
    for on in [true, false] {
        sl::set_test(on.then(|| Slimits::new(true, false, 1)));
        let (mut w, port, _rx, g) = rig_n(0, 1, 1000, if on { MARK_STREAM } else { 0 });
        assert_eq!(w.fd_mask & MARK_STREAM != 0, on, "hold mode with the option");
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let lp = l.local_addr().unwrap().port();
        let (mut heavy, _) = client(&mut w, port);
        let (mut light, _) = client(&mut w, port);
        w.inbox.load.fetch_add(59, Relaxed); // (59 connections of other workers)
        assert_eq!(g.grab(875, 875), 875, "the other workers' fds");
        assert_eq!(g.marks() & MARK_STREAM != 0, on);
        let refused = |w: &Worker| w.stats.refuse_stream_share.get();
        ask(&mut w, &mut heavy, 1, 40, lp, refused);
        let mut got = Vec::new();
        if on {
            assert_eq!((live(&w), refused(&w)), (32, 8), "the cap at the mark: 2 x 1000 / 61, at least 32");
            assert!(throttled(&mut w, &mut heavy, &mut got, 33..41));
            assert!(!closed_with(&got, 32, CLOSE_THROTTLED));
        } else {
            assert_eq!((live(&w), refused(&w)), (40, 0));
        }
        assert_eq!(w.stats.refuse_fd.get(), 0, "not the fd limit");
        // a light connection goes on
        ask(&mut w, &mut light, 1, 5, lp, refused);
        assert_eq!(refused(&w), if on { 8 } else { 0 });
        // the mark at rest: the heavy connection opens streams again
        g.give(875);
        assert_eq!(g.marks() & MARK_STREAM, 0);
        ask(&mut w, &mut heavy, 41, 2, lp, refused);
        assert_eq!((live(&w), refused(&w)), (if on { 39 } else { 47 }, if on { 8 } else { 0 }));
        assert_eq!(fds(&w), live(&w) as u64 + 2);
        end(w);
    }
    sl::set_test(None);
}

/// --stream-share alone (no --fd-admission): its mark moves with the host mark's parts, the host mark stays off
#[test]
fn stream_mark_is_its_own_bit() {
    let g = FdGate::new(160, 4);
    g.set_marks(MARK_STREAM);
    assert_eq!(g.grab(139, 139), 139);
    assert_eq!(g.marks(), 0, "below 7/8 (140)");
    assert_eq!(g.grab(1, 1), 1);
    assert_eq!(g.marks(), MARK_STREAM);
    g.give(10);
    assert_eq!(g.marks(), MARK_STREAM, "until below 13/16 (130)");
    g.give(1);
    assert_eq!(g.marks(), 0);
    // with --fd-admission too: both bits; MARK_POOL is never a mark
    let g = FdGate::new(160, 4);
    g.set_marks(MARK_STREAM | MARK_HOST | MARK_POOL);
    assert_eq!(g.grab(160, 160), 160);
    assert_eq!(g.marks(), MARK_STREAM | MARK_HOST);
}

/// --stream-pool end to end with two workers that share a pool of 2 x 10 streams (block 1): worker 0 opens 15 (above
/// its per-worker limit of 10), worker 1 then gets 5 and 0x49 for the 6th (refuse_streams). Worker 0 closes 5: its
/// slack beyond one block goes back at the fd puts and worker 1 gets 4 more. A level change that sets the per-worker
/// limit again is undone at the next fd put. Without the option worker 0 stops at 10.
#[test]
fn stream_pool_shares_the_memory_stream_limit() {
    let s = Slimits::new(false, true, 2);
    s.test_per.store(10, Relaxed);
    sl::set_test(Some(s));
    let (mut w0, p0, _r0, _) = rig_n(0, 2, u32::MAX, MARK_POOL);
    let (mut w1, p1, _r1, _) = rig_n(1, 2, u32::MAX, MARK_POOL);
    assert_eq!((w0.max_streams, w1.max_streams), (usize::MAX, usize::MAX), "no per-worker limit with the pool");
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let refused = |w: &Worker| w.stats.refuse_streams.get();
    let (mut c0, _) = client(&mut w0, p0);
    let (mut c1, _) = client(&mut w1, p1);
    ask(&mut w0, &mut c0, 1, 15, lp, refused);
    assert_eq!((live(&w0), refused(&w0), w0.sl_have()), (15, 0, 15));
    ask(&mut w1, &mut c1, 1, 6, lp, refused);
    assert_eq!((live(&w1), refused(&w1), w1.sl_have()), (5, 1, 5));
    let mut got = Vec::new();
    assert!(throttled(&mut w1, &mut c1, &mut got, 6..7));
    // worker 0 closes 5 streams (client CLOSE): it keeps one unused unit
    for sid in 1..=5u32 {
        c0.write_all(&wisp(0x04, sid, &[0x02])).unwrap();
    }
    until(&mut w0, "5 streams closed", |w| live(w) == 10);
    assert_eq!(w0.sl_have(), 11);
    ask(&mut w1, &mut c1, 7, 5, lp, refused);
    assert_eq!((live(&w1), refused(&w1)), (9, 2));
    // a level change sets the per-worker limit (set_levels); the next fd put undoes it
    w0.max_streams = 3;
    c0.write_all(&wisp(0x04, 6, &[0x02])).unwrap();
    until(&mut w0, "a stream closed", |w| live(w) == 9);
    assert_eq!(w0.max_streams, usize::MAX);
    // the idle sweep gives back all but one block; a worker without streams gives back everything
    w0.fd_trim(true);
    assert_eq!(w0.sl_have(), 10);
    // the total goes down (a higher level): no stream from held units, the spare ones go back
    sl::global().unwrap().test_per.store(4, Relaxed);
    let before = refused(&w0);
    ask(&mut w0, &mut c0, 100, 1, lp, refused);
    assert_eq!((refused(&w0), live(&w0), w0.sl_have()), (before + 1, 9, 9), "over the new total of 8: refused, the spare unit given back");
    sl::global().unwrap().test_per.store(10, Relaxed);
    drop(c1);
    until(&mut w1, "worker 1's client is gone", |w| live(w) == 0 && w.clients.slots.iter().all(|s| s.1.as_ref().is_none_or(|c| c.dead)));
    w1.fd_trim(true);
    assert_eq!(w1.sl_have(), 0);
    end(w0);
    end(w1);
    // without the option: the per-worker limit, in on_connect
    sl::set_test(None);
    let (mut w, p, _r, _) = rig_n(0, 2, u32::MAX, 0);
    w.max_streams = 10;
    let (mut c, _) = client(&mut w, p);
    ask(&mut w, &mut c, 1, 15, lp, refused);
    assert_eq!((live(&w), refused(&w)), (10, 5));
    end(w);
}

/// a wsproxy request for 127.0.0.1:`lp` on the worker's listener: the client, once accepted (before its request), and
/// a function that sends the request and returns the HTTP answer
fn wsproxy_client(w: &mut Worker, port: u16) -> TcpStream {
    let before = w.stats.accepted.get();
    let c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    until(w, "client accepted", |w| w.stats.accepted.get() > before);
    c.set_nonblocking(true).unwrap();
    c
}

fn wsproxy_ask(w: &mut Worker, c: &mut TcpStream, lp: u16) -> String {
    let req = format!(
        "GET /p/127.0.0.1:{lp} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    c.write_all(req.as_bytes()).unwrap();
    let mut got = Vec::new();
    until(w, "the HTTP answer", |_| {
        drain(c, &mut got);
        got.windows(4).any(|x| x == b"\r\n\r\n")
    });
    String::from_utf8_lossy(&got).into_owned()
}

/// 60.78 G44 --stream-pool and the wsproxy upgrade. The other worker holds all units of the pool but one: a wsproxy
/// request gets the 101 and its stream holds the last unit, taken before the 101; the next one gets a 503 and no 101
/// (refuse_streams), and its client is closed. A wsproxy stream that fails after the 101 because no fd is left (the
/// documented case: the fd is taken after the 101) gives its unit back when its connection closes (marked G44 (b) below).
#[test]
fn stream_pool_answers_a_wsproxy_upgrade_over_the_limit_with_503() {
    let s = Slimits::new(false, true, 2);
    s.test_per.store(4, Relaxed);
    sl::set_test(Some(s));
    let pool = sl::global().unwrap();
    let total = sl::pool_total(4, 2);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let (mut w, p, _r, g) = rig_n(0, 2, 64, MARK_POOL);
    assert_eq!(pool.grab(total - 1, total - 1, total), total - 1, "the other worker's units");
    let mut a = wsproxy_client(&mut w, p);
    let got = wsproxy_ask(&mut w, &mut a, lp);
    assert!(got.starts_with("HTTP/1.1 101"), "{got}");
    until(&mut w, "the wsproxy stream", |w| live(w) == 1);
    assert_eq!((w.sl_have(), pool.granted(), w.stats.refuse_streams.get()), (1, total, 0));
    let mut b = wsproxy_client(&mut w, p);
    let got = wsproxy_ask(&mut w, &mut b, lp);
    assert!(got.starts_with("HTTP/1.1 503") && !got.contains(" 101 "), "{got}");
    assert_eq!((live(&w), w.sl_have(), w.stats.refuse_streams.get()), (1, 1, 1), "no stream, no unit for the refused one");
    // the first stream ends: its unit is unused now
    drop(a);
    until(&mut w, "the wsproxy stream closed", |w| live(w) == 0);
    w.fd_trim(true);
    assert_eq!((w.sl_have(), pool.granted()), (0, total - 1));
    // the documented case: no fd is left after the 101. The unit taken for the upgrade is not lost: it stays with the
    // worker until fd_trim (here the idle sweep's) gives it back
    let mut c = wsproxy_client(&mut w, p);
    g.give(std::mem::take(&mut w.fd_pool)); // (the worker's unused fds of its block go back: none left in hand)
    let held = g.granted();
    assert_eq!(g.grab(64, 1), 64 - held, "every fd taken (other workers)");
    let got = wsproxy_ask(&mut w, &mut c, lp);
    assert!(got.starts_with("HTTP/1.1 101"), "the fd is taken after the 101: {got}");
    until(&mut w, "the stream refused at the fd limit", |w| live(w) == 0 && w.stats.refuse_fd.get() >= 1);
    // G44 (b): the unit of the wsproxy stream that failed after the 101 goes back with the connection. The stream never
    // had an fd; its failure closes the connection (target_eof of a wsproxy stream, a close the server starts after the
    // upgrade: 60.78 B3 it lingers until the client's EOF, at most LINGER_PLAIN), whose fd put trims (hold mode), or
    // else the idle sweep does (fd_trim(true)); sl_trim keeps no unit for a worker without streams.
    // (1) the client reads the Close and closes: the connection, its fd and the unit go at once
    assert_eq!((w.lingering.len(), w.sl_have()), (1, 1), "lingering, the unit still held");
    drop(c);
    until(&mut w, "the lingering connection closed at the client's EOF", |w| w.clients.slots.iter().all(|s| s.1.is_none()));
    assert_eq!((w.sl_have(), pool.granted(), w.stats.linger_capped.get()), (0, total - 1, 0), "the upgrade's unit given back");
    assert_eq!(super::fd::fds(&w), 0, "and its fd");
    // (2) a client that never closes: the connection, its fd and the unit go at the linger's bound
    let mut d = wsproxy_client(&mut w, p);
    let got = wsproxy_ask(&mut w, &mut d, lp);
    assert!(got.starts_with("HTTP/1.1 101"), "{got}");
    until(&mut w, "the second stream refused at the fd limit", |w| w.stats.refuse_fd.get() >= 2 && w.lingering.len() == 1);
    assert_eq!(w.sl_have(), 1);
    let bound = w.lingering[0].until;
    assert!(bound <= Instant::now() + super::super::linger::LINGER_PLAIN, "the bound: LINGER_PLAIN at most");
    w.lingering[0].until = Instant::now(); // (the bound, without the 5 s wait: lgtests' trickle test waits for it)
    until(&mut w, "the lingering connection closed at its bound", |w| w.clients.slots.iter().all(|s| s.1.is_none()));
    assert_eq!((w.sl_have(), pool.granted(), w.stats.linger_capped.get()), (0, total - 1, 1), "the unit given back at the bound");
    assert_eq!(super::fd::fds(&w), 0, "and its fd");
    drop(d);
    g.give(64 - held);
    end(w);
    sl::set_test(None);
}

/// a masked (zero key) binary frame with one Wisp DATA packet of `n` bytes, 64-bit length form
fn big_data(sid: u32, n: usize) -> Vec<u8> {
    let mut f = vec![0x82, 0x80 | 127];
    f.extend(((5 + n) as u64).to_be_bytes());
    f.extend([0, 0, 0, 0, 0x02]);
    f.extend(sid.to_le_bytes());
    f.resize(f.len() + n, 0x5a);
    f
}

/// 60.78 bundle B4 (not the stream limits): 20.06 known limit "128 credits x 16 MiB frames could exceed the 64 MiB
/// per-stream pending cap". A client within its credit sends 16 MiB DATA frames to a target that reads nothing: the
/// stream's backlog never passes PEND_CEIL (PEND_HARD + the level-0 rbuf), the stream is closed with 0x49 (shed_hold)
/// when a frame would take it past, and the connection survives: a second stream of it carries data afterwards, and
/// the client is read again. (64 KiB frames past PEND_HARD and PEND_CEIL get the hold, not this close:
/// worker::tests::honest_upload_over_pend_hard_pauses_instead_of_close.) Mutation check: PEND_CEIL = usize::MAX makes
/// the stream only held: the 20 s deadline fails the test.
#[test]
fn big_frames_in_credit_stop_at_pend_ceil() {
    sl::set_test(None);
    let (mut w, p, _r, _) = rig_n(0, 1, u32::MAX, 0);
    w.pend_cap = usize::MAX; // (mem::tests may set a global budget meanwhile: pend_sweep would shed)
    let stall = TcpListener::bind("127.0.0.1:0").unwrap(); // never accepted, never read
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut c, ci) = client(&mut w, p);
    c.write_all(&connect(1, false, stall.local_addr().unwrap().port())).unwrap();
    until(&mut w, "stream 1 open", |w| w.clients.at(ci).streams.get(&1).is_some_and(|&ti| w.targets.at(ti).state == TState::Open));
    let ti = *w.clients.at(ci).streams.get(&1).unwrap();
    // 7 frames of 16 MiB (112 MiB, 7 of the 128 credits), written as the worker reads them
    let frame = big_data(1, MAX_FRAME - 64);
    let (mut sent, total, mut peak) = (0usize, 7 * frame.len(), 0usize);
    let mut got = Vec::new();
    // (a deadline: a stream that is only held, never closed, must fail the test, not hang it)
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while sent < total && !closed_with(&got, 1, CLOSE_THROTTLED) {
        assert!(
            std::time::Instant::now() < deadline,
            "stream 1 neither closed nor done in 20 s (held at {peak} of backlog, {sent} of {total} bytes sent)"
        );
        let at = sent % frame.len();
        match c.write(&frame[at..]) {
            Ok(n) => sent += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("client write: {e}"),
        }
        pump(&mut w, 1);
        if let Some(t) = w.targets.get(ti, w.targets.gen(ti)) {
            peak = peak.max(t.pend.len() - t.phead);
        }
        drain(&mut c, &mut got);
    }
    assert!(peak <= PEND_HARD + mem::STAGES[0].rbuf_max, "backlog past PEND_CEIL: {peak}");
    assert!(throttled(&mut w, &mut c, &mut got, 1..2), "stream 1 closed with 0x49 ({sent} of {total} bytes sent)");
    assert!(peak > PEND_HARD - MAX_FRAME, "the stream had got near the cap: {peak}");
    assert_eq!(w.stats.shed_hold.get(), 1, "counted as shed_hold");
    // the connection goes on: what it still sends for stream 1 is dropped (the stream is gone); a new stream carries data
    // (the frame in progress is finished first: its rest is dropped with the stream)
    let mut left = (frame.len() - sent % frame.len()) % frame.len();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while left > 0 {
        assert!(std::time::Instant::now() < deadline, "the rest of the frame was not read in 20 s");
        match c.write(&frame[frame.len() - left..]) {
            Ok(n) => left -= n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("client write: {e}"),
        }
        pump(&mut w, 1);
    }
    until(&mut w, "the client read again", |w| !w.clients.at(ci).hpaused && w.clients.at(ci).rpos == w.clients.at(ci).rlen);
    c.set_nonblocking(false).unwrap();
    c.write_all(&connect(2, false, sink.local_addr().unwrap().port())).unwrap();
    c.write_all(&wisp(0x02, 2, b"after the close")).unwrap();
    c.set_nonblocking(true).unwrap();
    let (mut peer, _) = {
        sink.set_nonblocking(true).unwrap();
        let mut a = None;
        until(&mut w, "stream 2 connected", |_| {
            a = sink.accept().ok();
            a.is_some()
        });
        a.unwrap()
    };
    peer.set_nonblocking(true).unwrap();
    let mut seen = Vec::new();
    until(&mut w, "stream 2's data at its target", |_| {
        let mut b = [0u8; 256];
        if let Ok(n) = std::io::Read::read(&mut peer, &mut b) {
            seen.extend_from_slice(&b[..n]);
        }
        seen.ends_with(b"after the close")
    });
    assert!(w.clients.get(ci, w.clients.gen(ci)).is_some_and(|c| !c.dead && !c.closing), "the connection survived");
    drop(stall);
    end(w);
}
