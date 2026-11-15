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
