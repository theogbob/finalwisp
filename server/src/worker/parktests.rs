//! 20.35 worker tests: only a release un-parks a target (target.rs Park, Worker::release_parked, Worker::resume). Each
//! test drives the worker's methods directly on a socketpair client and a loopback target, as the splice tests do; the
//! debug invariant (Worker::park_check: Parked <=> exactly one list entry) also runs at every flush_dirty.
use super::super::*;
use super::fd::fd_cfg;
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};

struct Rig {
    w: Worker,
    ci: u32,
    ti: u32,
    tg: u32,
    peer: TcpStream, // the target's other end
    us: RawFd,       // our end of the client's socketpair
    _l: TcpListener,
    _rx: mpsc::Receiver<DnsReq>,
}

/// one client (slot 0, Open, a socketpair) with one open TCP target (stream 1) whose receive buffer is large
fn rig(cfg: Config) -> Rig {
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.pend_cap = usize::MAX;
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two fds into the array
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    assert!(w.fd_take(1)); // 60.57 A2 (accept_on counts the fd)
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    w.clients.at(ci).state = CState::Open;
    w.clients.at(ci).hs_credit = 128;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let (ti, tg) = w.new_target(ci, 1, "127.0.0.1".into(), l.local_addr().unwrap().port(), false, false).unwrap();
    w.clients.at(ci).streams.insert(1, ti);
    w.run_deferred();
    let (peer, _) = l.accept().unwrap();
    for _ in 0..1000 {
        if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
            break;
        }
        w.target_event(ti, tg, libc::EPOLLOUT as u32);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open), "target open");
    let big = 4i32 << 20;
    // SAFETY: a valid socket fd and a c_int option value
    unsafe { libc::setsockopt(w.targets.at(ti).fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &big as *const i32 as *const _, 4) };
    peer.set_nonblocking(true).unwrap();
    Rig { w, ci, ti, tg, peer, us: fds[1], _l: l, _rx: rx }
}

impl Rig {
    fn tk(&self) -> u64 {
        tok(K_TARGET, self.ti, self.tg)
    }
    fn state(&mut self) -> Park {
        self.w.targets.at(self.ti).blocked
    }
    /// (entries in `blocked`, in `blocked_bulk`)
    fn lists(&mut self) -> (usize, usize) {
        let c = self.w.clients.at(self.ci);
        (c.blocked.len(), c.blocked_bulk.len())
    }
    /// bytes waiting in the target socket
    fn queued(&mut self) -> usize {
        let mut n: libc::c_int = 0;
        // SAFETY: FIONREAD writes one c_int
        assert_eq!(unsafe { libc::ioctl(self.w.targets.at(self.ti).fd, libc::FIONREAD, &mut n) }, 0);
        n as usize
    }
    /// bytes copied into the client's user-space queues (obuf and the bulk lane), not sent
    fn copied(&mut self) -> usize {
        let c = self.w.clients.at(self.ci);
        c.obuf.len() - c.ohead + c.bulk.len() - c.bhead
    }
    fn splice_pending(&mut self) -> usize {
        self.w.clients.at(self.ci).splice_pending
    }
    /// the target's peer writes until at least `n` bytes wait in the target socket
    fn feed(&mut self, n: usize) {
        let chunk = [7u8; 64 * 1024];
        for _ in 0..2000 {
            if self.queued() >= n {
                return;
            }
            let _ = self.peer.write(&chunk);
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("target queue stayed at {} (want {n})", self.queued());
    }
    /// the worker's client socket full: nothing it sends goes out
    fn fill_client(&mut self) {
        let fd = self.w.clients.at(self.ci).fd;
        let junk = [0u8; 64 * 1024];
        // SAFETY: writes from a live buffer into the worker's non-blocking client socket until it is full
        while unsafe { libc::write(fd, junk.as_ptr() as *const _, junk.len()) } > 0 {}
    }
    /// our end reads everything queued
    fn empty_client(&mut self) {
        let mut buf = vec![0u8; 1 << 20];
        // SAFETY: reads into a live buffer from our end of the socketpair
        while unsafe { libc::read(self.us, buf.as_mut_ptr() as *mut _, buf.len()) } > 0 {}
    }
    /// flush_dirty on the client (listed as dirty first), with our end emptied before each try, until the target is
    /// no longer Parked (released) or `tries` flushes passed
    fn drain_release(&mut self, tries: usize) {
        for _ in 0..tries {
            self.empty_client();
            let (ci, g) = (self.ci, self.w.clients.gen(self.ci));
            let c = self.w.clients.at(ci);
            if !c.dirty {
                c.dirty = true;
                self.w.dirty.push((ci, g));
            }
            self.w.flush_dirty();
            if self.state() != Park::Parked {
                return;
            }
        }
        panic!("not released after {tries} flushes (pending {})", self.w.clients.at(self.ci).out_pending());
    }
    /// the ready entries, as the loop runs them
    fn run_ready(&mut self) {
        for t in std::mem::take(&mut self.w.ready) {
            self.w.resume(t);
        }
    }
    /// the WS frames queued in obuf since `from`: (opcode, payload)
    fn frames(&mut self, from: usize) -> Vec<(u8, Vec<u8>)> {
        let c = self.w.clients.at(self.ci);
        let (mut b, mut out) = (&c.obuf[from..], Vec::new());
        while b.len() >= 2 {
            let (op, l7) = (b[0] & 0x0f, (b[1] & 0x7f) as usize);
            let (len, h) = match l7 {
                126 => (u16::from_be_bytes([b[2], b[3]]) as usize, 4),
                127 => (u64::from_be_bytes(b[2..10].try_into().unwrap()) as usize, 10),
                n => (n, 2),
            };
            out.push((op, b[h..h + len].to_vec()));
            b = &b[h + len..];
        }
        out
    }
    /// `n` upload DATA packets of 16 KiB to stream 1 (the target's peer reads them)
    fn upload(&mut self, n: usize) {
        let mut msg = vec![2u8, 1, 0, 0, 0];
        msg.resize(5 + 16384, 7);
        let mut sink = vec![0u8; 1 << 20];
        for _ in 0..n {
            self.w.on_message(self.ci, &msg);
            while self.peer.read(&mut sink).is_ok_and(|k| k > 0) {}
            self.w.target_event(self.ti, self.tg, libc::EPOLLOUT as u32);
        }
    }
    /// park the target through the copy path: the client's output at out_high (unsent zeros in obuf)
    fn park_at_high(&mut self) {
        let high = self.w.st.out_high;
        let c = self.w.clients.at(self.ci);
        (c.obuf, c.ohead) = (vec![0u8; high], 0);
        self.w.read_target(self.ti);
        assert_eq!((self.state(), self.lists()), (Park::Parked, (1, 0)), "parked at out_high, listed once");
    }
    /// the client's output went out (the zeros of park_at_high)
    fn sent_all(&mut self) {
        let c = self.w.clients.at(self.ci);
        (c.obuf, c.ohead) = (Vec::new(), 0);
    }
}

/// The stale wake of the 20.35 note: a ready entry pushed before a splice park (a read-budget continuation) used to
/// un-park the target while its own splice was still in the pipe, and read_target then copied (the splice path needs
/// an empty pipe). Now it finds the target Parked and is dropped: no copy, nothing read, still listed once; the
/// target's own EPOLLIN reads nothing either. The release (flush_dirty, once the pipe went out) makes it Released with
/// one ready entry, and an edge before that entry runs still reads nothing (lane order); the entry reads. With and
/// without --prio (a splice parks in `blocked_bulk`, or in `blocked`).
#[test]
fn a_stale_entry_does_not_unpark_a_spliced_park() {
    for prio in [true, false] {
        let mut cfg = fd_cfg();
        cfg.prio = prio;
        let mut r = rig(cfg);
        let tk = r.tk();
        r.feed(64 * 1024);
        r.fill_client();
        r.w.targets.at(r.ti).bulk = true; // (the splice path, as after a full copy read)
        r.w.ready.push(tk); // an entry pushed before the park
        r.w.read_target(r.ti); // splices; the full socket keeps the pipe pending: the target parks
        if r.w.clients.at(r.ci).pipe[0] < 0 {
            // no splice pipe here (pipe quota, fs.pipe-max-size): the copy path, nothing to test (as splice_length_steps)
            eprintln!("a_stale_entry_does_not_unpark_a_spliced_park(prio {prio}): no splice pipe, skipped");
            r.w.close_client(r.ci, Why::ServerClose);
            // SAFETY: our end of the socketpair, not used after this
            unsafe { libc::close(r.us) };
            std::mem::forget(r.w);
            continue;
        }
        let parked_in = if prio { (0, 1) } else { (1, 0) };
        assert!(r.splice_pending() > 0, "prio {prio}: the splice waits in the pipe");
        assert_eq!((r.state(), r.lists()), (Park::Parked, parked_in), "prio {prio}");
        r.feed(64 * 1024); // more data behind the park: a read now would copy it (the pipe is not empty)
        let at_park = (r.queued(), r.copied(), r.splice_pending());
        r.run_ready(); // the earlier entry
        r.w.target_event(r.ti, r.tg, libc::EPOLLIN as u32); // and an edge of the target
        assert_eq!((r.state(), r.lists()), (Park::Parked, parked_in), "prio {prio}: still parked, listed once");
        // (more of the peer's bytes may still arrive: a read can only lower the target queue)
        assert!(r.queued() >= at_park.0, "prio {prio}: nothing read from the target");
        assert_eq!((r.copied(), r.splice_pending()), (at_park.1, at_park.2), "prio {prio}: no copy behind the pipe");
        // the client takes its data: the pipe goes out and the release follows
        r.drain_release(100);
        assert_eq!((r.state(), r.lists()), (Park::Released, (0, 0)), "prio {prio}: released");
        assert_eq!(r.w.ready, [tk], "prio {prio}: one ready entry");
        let q = r.queued();
        r.w.target_event(r.ti, r.tg, libc::EPOLLIN as u32);
        assert_eq!((r.state(), r.copied()), (Park::Released, 0), "prio {prio}: Released reads only from its entry");
        assert!(r.queued() >= q, "prio {prio}: nothing read on the event");
        let q = r.queued();
        r.run_ready();
        assert!(r.queued() < q, "prio {prio}: the entry read");
        assert!(r.state() == Park::Run || r.lists().0 + r.lists().1 == 1, "prio {prio}: running, or parked again once");
        r.w.park_check();
        r.w.close_client(r.ci, Why::ServerClose);
        // SAFETY: our end of the socketpair, not used after this
        unsafe { libc::close(r.us) };
        std::mem::forget(r.w);
    }
}

/// A FIN behind parked data: its edge (EPOLLIN | EPOLLRDHUP) comes and goes while the target is parked and reads
/// nothing (rdhup is noted); after the release the entry reads the data and the EOF, and the stream ends with its CLOSE
/// behind its DATA: 20.34 queues the gate PING behind the DATA, and its PONG releases the CLOSE.
#[test]
fn a_fin_consumed_while_parked_still_ends_the_stream() {
    let mut r = rig(fd_cfg());
    let (ti, tg) = (r.ti, r.tg);
    r.park_at_high();
    r.peer.write_all(&[5u8; 1000]).unwrap();
    r.peer.shutdown(Shutdown::Write).unwrap();
    let fd = r.w.targets.at(ti).fd;
    let end = Instant::now() + Duration::from_secs(10);
    while !(r.queued() == 1000 && net::peer_closed(fd)) {
        assert!(Instant::now() < end, "the data and the FIN did not arrive (queued {})", r.queued());
        std::thread::sleep(Duration::from_millis(1));
    }
    r.w.target_event(ti, tg, (libc::EPOLLIN | libc::EPOLLRDHUP) as u32);
    assert_eq!((r.state(), r.queued()), (Park::Parked, 1000), "the edge is consumed, nothing read");
    assert!(r.w.targets.at(ti).rdhup, "the hangup is noted");
    r.sent_all();
    r.drain_release(10);
    assert_eq!(r.state(), Park::Released);
    r.run_ready();
    assert!(r.w.targets.get(ti, tg).is_none(), "the stream ended");
    let f = r.frames(0);
    assert_eq!(f.len(), 2, "DATA, then the gate PING (20.34: the CLOSE waits for its PONG): {f:?}");
    assert_eq!((f[0].0, f[0].1.len(), f[0].1[0]), (OP_BIN, 1005, PKT_DATA), "the 1000 bytes first");
    assert!(f[1].0 == OP_PING && f[1].1.len() == 6 && f[1].1[..2] == pinggate::TAG, "then the gate PING: {:?}", f[1]);
    let p = f[1].1.clone();
    r.w.on_frame(r.ci, true, OP_PONG, &p);
    let f = r.frames(0);
    assert_eq!(f.len(), 3, "DATA, gate PING, then the CLOSE: {f:?}");
    assert_eq!((f[2].0, f[2].1[0], f[2].1[5]), (OP_BIN, PKT_CLOSE, CLOSE_VOLUNTARY), "its CLOSE after the PONG");
    // SAFETY: our end of the socketpair, not used after this
    unsafe { libc::close(r.us) };
    std::mem::forget(r.w);
}

/// A connection moves (60.64) right after a release, before the target's entry ran: the target has no data and no FIN
/// (so the destination's EPOLL_CTL_ADD reports no edge) and holds a credit-pace grant. It arrives Released with a ready
/// entry on the destination (mig_import), and that entry reads (EAGAIN) and re-decides the grant: the CONTINUE goes out.
/// Without the entry neither side would wake: the client waits for credit, the target for a request.
#[test]
fn a_move_right_after_a_release_keeps_the_wake_and_the_grant() {
    let mut cfg = fd_cfg();
    cfg.credit_pace = true;
    let mut r = rig(cfg);
    let ti = r.ti;
    r.upload(63);
    r.park_at_high();
    r.upload(1); // the 64th packet: CONTINUE(128) due while parked
    assert!(r.w.cpace_st[ti as usize].held, "held while parked");
    r.sent_all();
    r.drain_release(10);
    assert_eq!((r.state(), r.lists(), r.w.ready.clone()), (Park::Released, (0, 0), vec![r.tk()]));
    assert_eq!(r.queued(), 0, "no data");
    let g = r.w.clients.gen(r.ci);
    assert!(r.w.mig_quiet(r.ci, g), "at rest: it may move");
    let m = r.w.mig_export(r.ci);
    let (ci2, _) = r.w.mig_import(m).expect("imported");
    let ti2 = r.w.clients.at(ci2).streams[&1];
    let tk2 = tok(K_TARGET, ti2, r.w.targets.gen(ti2));
    assert_eq!(r.w.targets.at(ti2).blocked, Park::Released, "arrives Released");
    assert!(r.w.ready.contains(&tk2), "with a ready entry on the destination");
    assert!(r.w.cpace_st[ti2 as usize].held, "the hold moved with it");
    (r.ci, r.ti, r.tg) = (ci2, ti2, r.w.targets.gen(ti2));
    r.run_ready(); // (the source's entry fails the generation check; the new one runs)
    assert_eq!(r.state(), Park::Run);
    let cont = (OP_BIN, [&[3u8, 1, 0, 0, 0][..], &128u32.to_le_bytes()].concat());
    assert_eq!(r.frames(0), [cont], "the held CONTINUE goes out");
    assert!(!r.w.cpace_st[ti2 as usize].held);
    r.w.park_check();
    // SAFETY: our end of the socketpair, not used after this
    unsafe { libc::close(r.us) };
    std::mem::forget(r.w);
}
