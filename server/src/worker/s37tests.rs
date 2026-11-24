//! 20.37 worker tests: rule S (target.rs splice_wait; flush_dirty's release gate). A bulk lane stream whose read cannot
//! splice now waits instead of copying: S1 (a payload in the client's pipe), L1 (its own lane frames), L2 (only other
//! streams' lane frames: a fence at the lane's end), G (at most one L2 wait between two reads). Each test drives the
//! worker's methods directly on a socketpair client and loopback targets, as parktests.rs does; park_check runs after
//! every step that parks or releases. A host without a splice pipe (pipe quota, fs.pipe-max-size) skips them.
use super::super::*;
use super::fd::{fd_cfg, pump};
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};

struct St {
    ti: u32,
    tg: u32,
    sid: u32,
    peer: TcpStream, // the target's other end
}

struct Rig {
    w: Worker,
    ci: u32,
    s: Vec<St>,
    us: RawFd,    // our end of the client's socketpair
    got: Vec<u8>, // what our end read since the last `grab` start (Rig::grab)
    keep: bool,   // empty_client keeps what it reads in `got`
    _l: TcpListener,
    _rx: mpsc::Receiver<DnsReq>,
}

/// one client (slot 0, Open, a socketpair, its splice pipe open) with `n` open TCP targets (streams 1..=n) whose
/// receive buffers are large. None = no splice pipe on this host (the caller skips)
fn rig(cfg: Config, n: usize) -> Option<Rig> {
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.pend_cap = usize::MAX;
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two fds into the array
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    assert!(w.fd_take(1));
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    w.clients.at(ci).state = CState::Open;
    w.clients.at(ci).hs_credit = 128;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut s = Vec::new();
    for k in 0..n {
        let sid = k as u32 + 1;
        let (ti, tg) = w.new_target(ci, sid, "127.0.0.1".into(), l.local_addr().unwrap().port(), false, false).unwrap();
        w.clients.at(ci).streams.insert(sid, ti);
        w.run_deferred();
        let (peer, _) = l.accept().unwrap();
        for _ in 0..1000 {
            if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                break;
            }
            w.target_event(ti, tg, libc::EPOLLOUT as u32);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open), "target {sid} open");
        let big = 4i32 << 20;
        // SAFETY: a valid socket fd and a c_int option value
        unsafe { libc::setsockopt(w.targets.at(ti).fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &big as *const i32 as *const _, 4) };
        peer.set_nonblocking(true).unwrap();
        s.push(St { ti, tg, sid, peer });
    }
    let mut r = Rig { w, ci, s, us: fds[1], got: Vec::new(), keep: false, _l: l, _rx: rx };
    if !r.w.pipe_open(ci) {
        eprintln!("s37 tests: no splice pipe on this host, skipped");
        r.end();
        return None;
    }
    Some(r)
}

impl Rig {
    fn tk(&self, k: usize) -> u64 {
        tok(K_TARGET, self.s[k].ti, self.s[k].tg)
    }
    fn state(&mut self, k: usize) -> Park {
        self.w.targets.at(self.s[k].ti).blocked
    }
    fn alive(&mut self, k: usize) -> bool {
        self.w.targets.get(self.s[k].ti, self.s[k].tg).is_some()
    }
    /// (entries in `blocked`, in `blocked_bulk`)
    fn lists(&mut self) -> (usize, usize) {
        let c = self.w.clients.at(self.ci);
        (c.blocked.len(), c.blocked_bulk.len())
    }
    fn lane(&mut self) -> usize {
        let c = self.w.clients.at(self.ci);
        c.bulk.len() - c.bhead
    }
    fn obuf(&mut self) -> usize {
        let c = self.w.clients.at(self.ci);
        c.obuf.len() - c.ohead
    }
    fn pend(&mut self) -> usize {
        self.w.clients.at(self.ci).splice_pending
    }
    fn splice(&mut self) -> u8 {
        self.w.clients.at(self.ci).splice
    }
    fn bulk_end(&mut self, k: usize) -> u64 {
        self.w.targets.at(self.s[k].ti).bulk_end
    }
    /// stream k's live L2 fence (its generation's entry)
    fn fence(&mut self, k: usize) -> Option<u64> {
        let (ti, tg) = (self.s[k].ti, self.s[k].tg);
        self.w.lane_fence.get(ti as usize).filter(|f| f.0 == (tg & 0x3fff_ffff) + 1).map(|f| f.1)
    }
    fn set_bulk(&mut self, k: usize) {
        self.w.targets.at(self.s[k].ti).bulk = true;
    }
    fn read(&mut self, k: usize) {
        self.w.read_target(self.s[k].ti);
    }
    /// bytes waiting in target k's socket
    fn queued(&mut self, k: usize) -> usize {
        let mut n: libc::c_int = 0;
        // SAFETY: FIONREAD writes one c_int
        assert_eq!(unsafe { libc::ioctl(self.w.targets.at(self.s[k].ti).fd, libc::FIONREAD, &mut n) }, 0);
        n as usize
    }
    /// target k's peer writes `n` bytes; returns once they all wait in the target socket. Non-blocking writes under one
    /// deadline: a host whose receive buffer cannot hold them fails here, naming its limit, instead of hanging
    fn put(&mut self, k: usize, n: usize) {
        let want = self.queued(k) + n;
        let (data, mut off) = (vec![7u8; n], 0);
        let end = Instant::now() + Duration::from_secs(10);
        while off < n || self.queued(k) < want {
            if off < n {
                match self.s[k].peer.write(&data[off..]) {
                    Ok(x) => off += x,
                    Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock, "target {k}: peer write"),
                }
            }
            let q = self.queued(k);
            assert!(Instant::now() < end, "target {k}: queue {q} (want {want}; SO_RCVBUF {})", self.rcvbuf(k));
            if off < n || q < want {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    /// target k's SO_RCVBUF as the kernel granted it (the request doubled, capped at twice net.core.rmem_max)
    fn rcvbuf(&mut self, k: usize) -> usize {
        let (fd, mut v, mut len): (RawFd, libc::c_int, libc::socklen_t) = (self.w.targets.at(self.s[k].ti).fd, 0, 4);
        // SAFETY: getsockopt writes one c_int and its length
        let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &mut v as *mut _ as *mut _, &mut len) };
        assert_eq!(rc, 0, "getsockopt SO_RCVBUF");
        v as usize
    }
    /// cut the client's (empty) splice pipe to `n` bytes; returns the size the kernel set (F_SETPIPE_SZ rounds up)
    fn pipe_cut(&mut self, n: usize) -> usize {
        let fd = self.w.clients.at(self.ci).pipe[1];
        assert_eq!(self.pend(), 0, "(an empty pipe)");
        // SAFETY: fcntl on the client's open pipe fd
        let got = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, n as libc::c_int) };
        assert!(got >= n as libc::c_int, "F_SETPIPE_SZ {n}: {got} ({})", std::io::Error::last_os_error());
        got as usize
    }
    /// the worker's client socket full: nothing it sends goes out
    fn fill_client(&mut self) {
        let fd = self.w.clients.at(self.ci).fd;
        let junk = [0u8; 64 * 1024];
        // SAFETY: writes from a live buffer into the worker's non-blocking client socket until it is full
        while unsafe { libc::write(fd, junk.as_ptr() as *const _, junk.len()) } > 0 {}
    }
    /// our end reads everything queued (kept in `got` while `keep`)
    fn empty_client(&mut self) {
        let mut buf = vec![0u8; 1 << 20];
        loop {
            // SAFETY: reads into a live buffer from our end of the socketpair
            let n = unsafe { libc::read(self.us, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                break;
            }
            if self.keep {
                self.got.extend_from_slice(&buf[..n as usize]);
            }
        }
    }
    /// flush_dirty on the client (listed as dirty first)
    fn flush(&mut self) {
        let (ci, g) = (self.ci, self.w.clients.gen(self.ci));
        let c = self.w.clients.at(ci);
        if !c.dirty {
            c.dirty = true;
            self.w.dirty.push((ci, g));
        }
        self.w.flush_dirty();
        self.w.park_check();
    }
    /// the ready entries, as the loop runs them
    fn run_ready(&mut self) {
        for t in std::mem::take(&mut self.w.ready) {
            self.w.resume(t);
        }
        self.w.park_check();
    }
    /// a small frame in obuf (zeros, as parktests' park_at_high): obuf busy
    fn small_obuf(&mut self) {
        let c = self.w.clients.at(self.ci);
        assert_eq!(c.splice_at, NO_MARK, "(no splice header in obuf)");
        c.obuf.extend_from_slice(&[0u8; 100]);
    }
    /// obuf went out (only without a splice header in it)
    fn obuf_sent(&mut self) {
        let c = self.w.clients.at(self.ci);
        assert_eq!(c.splice_at, NO_MARK, "(no splice header in obuf)");
        (c.obuf, c.ohead) = (Vec::new(), 0);
    }
    /// stream k splices `n` bytes into the pipe with the client socket full: the payload stays in the pipe and k parks
    fn splice_stuck(&mut self, k: usize, n: usize) {
        self.fill_client();
        self.put(k, n);
        self.set_bulk(k);
        self.read(k);
        assert_eq!(self.pend(), n, "stream {k}'s payload in the pipe");
        assert_eq!(self.state(k), Park::Parked, "stream {k} parked on its splice");
        self.w.park_check();
    }
    /// stream k puts one lane frame of `n` (< CHUNK) bytes (obuf busy, so its read copies; then obuf went out)
    fn lane_frame(&mut self, k: usize, n: usize) {
        let lane = self.lane();
        self.small_obuf();
        self.put(k, n);
        self.set_bulk(k);
        self.read(k);
        assert_eq!(self.lane(), lane + n + 9, "stream {k}'s frame in the lane (4-byte WS header + 5-byte Wisp header)");
        assert_eq!(self.state(k), Park::Run, "a short read: drained, not parked");
        self.obuf_sent();
    }
    /// `n` upload DATA packets of 16 KiB to stream k (the target's peer reads them)
    fn upload(&mut self, k: usize, n: usize) {
        let mut msg = vec![2u8];
        msg.extend_from_slice(&self.s[k].sid.to_le_bytes());
        msg.resize(5 + 16384, 7);
        let mut sink = vec![0u8; 1 << 20];
        for _ in 0..n {
            self.w.on_message(self.ci, &msg);
            while self.s[k].peer.read(&mut sink).is_ok_and(|x| x > 0) {}
            self.w.target_event(self.s[k].ti, self.s[k].tg, libc::EPOLLOUT as u32);
        }
    }
    fn end(mut self) {
        self.w.close_client(self.ci, Why::ServerClose);
        // SAFETY: our end of the socketpair, not used after this
        unsafe { libc::close(self.us) };
        std::mem::forget(self.w);
    }
}

/// complete WS frames in `b`: (opcode, payload); the rest stays unparsed
fn frames(b: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let (mut i, mut v) = (0, Vec::new());
    while i + 2 <= b.len() {
        let (mut len, mut h) = ((b[i + 1] & 0x7f) as usize, 2);
        if len == 126 {
            if i + 4 > b.len() {
                break;
            }
            len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
            h = 4;
        } else if len == 127 {
            if i + 10 > b.len() {
                break;
            }
            len = u64::from_be_bytes(b[i + 2..i + 10].try_into().unwrap()) as usize;
            h = 10;
        }
        if i + h + len > b.len() {
            break;
        }
        v.push((b[i] & 0x0f, b[i + h..i + h + len].to_vec()));
        i += h + len;
    }
    v
}

/// DATA payload bytes per stream id in `f`
fn data_of(f: &[(u8, Vec<u8>)], sid: u32) -> usize {
    f.iter()
        .filter(|(op, p)| *op == OP_BIN && p.len() >= 5 && p[0] == PKT_DATA && p[1..5] == sid.to_le_bytes())
        .map(|(_, p)| p.len() - 5)
        .sum()
}

/// S1: a sibling's payload is in the pipe. The bulk stream's read parks (no copy: lane, obuf and its target queue
/// unchanged), listed once, splice SLOW. Neither stream is released while the payload is in the pipe, even with the
/// output below out_low_bulk (where the release before 20.37 came); once it went out both are, the waiter first (the
/// non-reader prefix), and its bytes go through the pipe: nothing is copied.
#[test]
fn s1_a_busy_pipe_parks_the_sibling_until_it_drained() {
    let Some(mut r) = rig(fd_cfg(), 2) else { return };
    r.splice_stuck(0, 32 * 1024);
    r.put(1, 200 * 1024);
    r.set_bulk(1);
    r.w.clients.at(r.ci).splice = SPLICE_FAST;
    let ob = r.obuf();
    r.read(1);
    assert_eq!((r.state(1), r.lists()), (Park::Parked, (0, 2)), "S1: parked, listed once");
    assert_eq!((r.lane(), r.obuf(), r.queued(1), r.pend()), (0, ob, 200 * 1024, 32 * 1024), "nothing copied or read");
    assert_eq!(r.splice(), SPLICE_SLOW, "an S park backs off FAST (60.46)");
    assert!(r.w.clients.at(r.ci).out_pending() < r.w.st.out_low_bulk, "(below the release mark)");
    for _ in 0..3 {
        r.flush(); // the socket is still full: the payload stays in the pipe
        assert_eq!((r.state(0), r.state(1), r.lists()), (Park::Parked, Park::Parked, (0, 2)), "no release before the pipe drained");
    }
    r.empty_client();
    r.flush();
    assert_eq!((r.state(0), r.state(1), r.lists(), r.pend()), (Park::Released, Park::Released, (0, 0), 0), "released once it drained");
    assert_eq!(r.w.ready, [r.tk(1), r.tk(0)], "the waiter first (non-reader prefix)");
    r.run_ready();
    assert_eq!(r.lane(), 0, "no copy");
    assert!(r.queued(1) < 200 * 1024, "the waiter spliced");
    r.end();
}

/// L1: obuf is busy, so the bulk stream's first read copies into the lane (as before 20.37); its next read finds its own
/// frame there and parks (one CHUNK copied where the copy path took the lane to out_high_bulk). Released once the
/// output went out, it splices.
#[test]
fn l1_own_lane_frames_park_and_the_release_splices() {
    let Some(mut r) = rig(fd_cfg(), 1) else { return };
    r.fill_client();
    r.small_obuf();
    r.put(0, 300 * 1024);
    r.set_bulk(0);
    r.w.clients.at(r.ci).splice = SPLICE_FAST;
    r.read(0);
    assert_eq!(r.lane(), CHUNK + 9, "one copy into the lane (obuf busy, no own frame yet)");
    assert_eq!(r.queued(0), 300 * 1024 - CHUNK);
    assert_eq!((r.state(0), r.lists(), r.splice()), (Park::Parked, (0, 1), SPLICE_SLOW), "L1: parked behind its own frame");
    assert!(r.bulk_end(0) > r.w.clients.at(r.ci).bulk_sent);
    r.w.park_check();
    r.empty_client();
    r.flush();
    assert_eq!((r.state(0), r.lane(), r.obuf()), (Park::Released, 0, 0), "released once its frame went out");
    let q = r.queued(0);
    r.run_ready();
    assert_eq!(r.lane(), 0, "the release splices: no copy");
    assert!(r.queued(0) < q, "it read");
    r.end();
}

/// L2: only another stream's frame is in the lane and obuf is empty. The bulk stream records a fence at the lane's end
/// (a stale entry of another generation is no fence: it is overwritten), parks, and leaves its bulk_end alone. Over k
/// releases while the client takes nothing (the lane head does not move), it parks again each time and no payload
/// enters the pipe (no overtake); once the frame went out it splices and the splice clears the fence (G).
#[test]
fn l2_waits_behind_other_frames_without_overtaking() {
    let Some(mut r) = rig(fd_cfg(), 2) else { return };
    r.fill_client();
    r.lane_frame(0, 30 * 1024);
    let lane = r.lane();
    let f_at = r.w.clients.at(r.ci).bulk_sent + lane as u64;
    let (ti, tg) = (r.s[1].ti, r.s[1].tg);
    if r.w.lane_fence.len() <= ti as usize {
        r.w.lane_fence.resize(ti as usize + 1, (0, 0));
    }
    r.w.lane_fence[ti as usize] = (((tg + 1) & 0x3fff_ffff) + 1, u64::MAX); // a stale entry (another generation)
    r.put(1, 200 * 1024);
    r.set_bulk(1);
    r.w.clients.at(r.ci).splice = SPLICE_FAST;
    r.read(1);
    assert_eq!((r.state(1), r.lists(), r.splice()), (Park::Parked, (0, 1), SPLICE_SLOW), "L2: parked");
    assert_eq!(r.fence(1), Some(f_at), "fence at the lane's end (the stale entry did not count)");
    assert_eq!((r.bulk_end(1), r.lane(), r.queued(1), r.pend()), (0, lane, 200 * 1024, 0), "bulk_end untouched, nothing read");
    for i in 0..5 {
        r.flush(); // nothing goes out; the output is below out_low_bulk: a release
        assert_eq!(r.state(1), Park::Released, "release {i}");
        r.run_ready();
        assert_eq!((r.state(1), r.lists()), (Park::Parked, (0, 1)), "release {i}: parked again");
        assert_eq!((r.lane(), r.queued(1), r.pend()), (lane, 200 * 1024, 0), "release {i}: no copy, no splice");
    }
    r.empty_client();
    r.flush();
    assert_eq!(r.state(1), Park::Released);
    r.run_ready();
    assert_eq!(r.lane(), 0, "it spliced, no copy");
    assert!(r.queued(1) < 200 * 1024);
    assert_eq!(r.fence(1), None, "the splice cleared the fence");
    r.end();
}

/// G: the fence passed, but before the stream ran a sticky lane stream put a new frame in the lane. The stream does not
/// fence again (that could go on as long as the lane never empties): it copies behind the frame, then parks on its own
/// frame (L1).
#[test]
fn g_one_l2_wait_between_two_reads() {
    let Some(mut r) = rig(fd_cfg(), 2) else { return };
    r.fill_client();
    r.lane_frame(0, 30 * 1024);
    r.put(1, 200 * 1024);
    r.set_bulk(1);
    r.read(1);
    assert!(r.fence(1).is_some() && r.state(1) == Park::Parked, "L2 wait");
    r.empty_client();
    r.flush();
    assert_eq!(r.state(1), Park::Released, "its frames went out");
    r.fill_client();
    r.lane_frame(0, 20 * 1024); // the other stream again, before the waiter ran
    let lane = r.lane();
    r.run_ready();
    assert_eq!(r.queued(1), 200 * 1024 - CHUNK, "G: one copy");
    assert_eq!(r.lane(), lane + CHUNK + 9);
    assert_eq!(r.fence(1), None, "the passed fence is cleared");
    assert_eq!((r.state(1), r.lists()), (Park::Parked, (0, 1)), "then L1: parked behind its own frame");
    r.end();
}

/// Not changed: with splicing off, without --prio (no lane) and in a kTLS starve episode the bulk stream copies behind
/// the pipe's payload as before 20.37; in a starve episode the release does not wait for the pipe either.
#[test]
fn no_s_without_splice_lane_or_in_a_starve_episode() {
    for case in ["splice off", "no prio", "starve"] {
        let mut cfg = fd_cfg();
        cfg.prio = case != "no prio";
        let Some(mut r) = rig(cfg, 2) else { return };
        r.splice_stuck(0, 32 * 1024);
        match case {
            "splice off" => r.w.clients.at(r.ci).splice = SPLICE_OFF,
            "starve" => r.w.clients.at(r.ci).starve = 1,
            _ => {}
        }
        let n = if case == "starve" { 20 * 1024 } else { 100 * 1024 }; // (starve: the output stays below out_low_bulk)
        r.put(1, n);
        r.set_bulk(1);
        let ob = r.obuf();
        r.read(1);
        assert_eq!(r.lane() + r.obuf() - ob, n + if n > CHUNK { 18 } else { 9 }, "{case}: it copied all of it");
        assert_eq!((r.queued(1), r.state(1)), (0, Park::Run), "{case}: read to EAGAIN, not parked");
        if case == "starve" {
            assert!(r.w.clients.at(r.ci).out_pending() < r.w.st.out_low_bulk);
            r.flush(); // the socket is full: the payload stays in the pipe
            assert_eq!((r.pend(), r.state(0)), (32 * 1024, Park::Released), "starve: released with the payload in the pipe");
            r.w.clients.at(r.ci).starve = 0;
        }
        r.end();
    }
}

/// A FIN behind an S park ends the stream within one release: S1 (behind a sibling's payload) and L2 (behind a
/// sibling's lane frame). Its DATA, then the gate PING reach the client; its PONG releases the CLOSE (20.34).
#[test]
fn a_fin_behind_an_s_park_ends_within_one_release() {
    for case in ["S1", "L2"] {
        let Some(mut r) = rig(fd_cfg(), 2) else { return };
        if case == "S1" {
            r.splice_stuck(0, 32 * 1024);
        } else {
            r.fill_client();
            r.lane_frame(0, 30 * 1024);
        }
        let (ti, tg) = (r.s[1].ti, r.s[1].tg);
        r.s[1].peer.write_all(&[5u8; 1000]).unwrap();
        r.s[1].peer.shutdown(Shutdown::Write).unwrap();
        let fd = r.w.targets.at(ti).fd;
        let end = Instant::now() + Duration::from_secs(10);
        while !(r.queued(1) == 1000 && net::peer_closed(fd)) {
            assert!(Instant::now() < end, "{case}: the data and the FIN did not arrive");
            std::thread::sleep(Duration::from_millis(1));
        }
        r.set_bulk(1);
        r.w.target_event(ti, tg, (libc::EPOLLIN | libc::EPOLLRDHUP) as u32);
        assert_eq!((r.state(1), r.queued(1)), (Park::Parked, 1000), "{case}: an S park, nothing read");
        r.empty_client();
        r.keep = true;
        let mut releases = 0;
        while r.alive(1) {
            assert!(releases < 1, "{case}: the stream did not end within one release");
            r.flush();
            assert_eq!(r.state(1), Park::Released, "{case}: released");
            releases += 1;
            r.run_ready();
        }
        r.flush();
        r.empty_client();
        let f = frames(&r.got);
        assert_eq!(data_of(&f, 2), 1000, "{case}: its DATA");
        let is_ping = |x: &(u8, Vec<u8>)| x.0 == OP_PING && x.1.len() == 6 && x.1[..2] == pinggate::TAG;
        let is_close = |x: &(u8, Vec<u8>)| x.0 == OP_BIN && x.1.len() == 6 && x.1[0] == PKT_CLOSE && x.1[1..5] == 2u32.to_le_bytes();
        let pings: Vec<usize> = (0..f.len()).filter(|&i| is_ping(&f[i])).collect();
        assert_eq!(pings.len(), 1, "{case}: one gate PING");
        let last_data = f.iter().rposition(|(op, p)| *op == OP_BIN && p.len() > 5 && p[0] == PKT_DATA && p[1..5] == 2u32.to_le_bytes());
        assert!(last_data.is_some_and(|d| d < pings[0]), "{case}: its DATA before the gate PING: {f:?}");
        assert!(!f.iter().any(is_close), "{case}: no CLOSE before the PONG");
        let p = f[pings[0]].1.clone();
        r.got.clear();
        r.w.on_frame(r.ci, true, OP_PONG, &p);
        r.flush();
        r.empty_client();
        let f = frames(&r.got);
        assert!(
            f.iter().any(|(op, p)| *op == OP_BIN && p.len() == 6 && p[0] == PKT_CLOSE && p[1..5] == 2u32.to_le_bytes()),
            "{case}: its CLOSE after the PONG: {f:?}"
        );
        r.end();
    }
}

/// A fence never moves a CLOSE. A stream waits in L2 behind another stream's lane frame (a real fence), then leaves bulk
/// mode before the fence passed (as a level raise clears Target::bulk, levels.rs); its data and FIN come. Released, it
/// reads by the copy path into obuf (its bulk_end was never moved, so it is not a lane stream), its gate PING goes to obuf,
/// and shutdown's flush_held sends its held CLOSE (it drops only the CLOSE of a stream whose DATA is still in the lane,
/// pinggate.rs). v3 of the 20.37 design kept the fence in bulk_end: this stream's DATA and PING would have gone into the
/// lane behind the other stream's frame and flush_held would have dropped its CLOSE.
#[test]
fn a_fence_never_holds_back_a_close() {
    let Some(mut r) = rig(fd_cfg(), 2) else { return };
    r.fill_client();
    r.lane_frame(0, 30 * 1024); // another stream's frame, unsent
    let (ti, tg) = (r.s[1].ti, r.s[1].tg);
    r.put(1, 1000);
    r.set_bulk(1);
    r.read(1);
    assert!(r.fence(1).is_some() && r.state(1) == Park::Parked, "L2 wait: a live fence");
    assert_eq!(r.bulk_end(1), 0, "bulk_end untouched");
    r.s[1].peer.shutdown(Shutdown::Write).unwrap();
    let fd = r.w.targets.at(ti).fd;
    let end = Instant::now() + Duration::from_secs(10);
    while !net::peer_closed(fd) {
        assert!(Instant::now() < end, "the FIN did not arrive");
        std::thread::sleep(Duration::from_millis(1));
    }
    r.w.target_event(ti, tg, (libc::EPOLLIN | libc::EPOLLRDHUP) as u32); // (parked: noted, nothing read)
    r.w.targets.at(ti).bulk = false; // as a level raise (levels.rs)
    let ob = r.w.clients.at(r.ci).obuf.len();
    let lane = r.lane();
    r.flush(); // the client takes nothing; the output is below out_low_bulk and the pipe empty: the release
    assert_eq!(r.state(1), Park::Released);
    assert!(r.fence(1).is_some(), "(the fence has not passed: the other stream's frame is unsent)");
    r.run_ready();
    assert!(!r.alive(1), "the stream ended");
    assert_eq!(r.lane(), lane, "nothing of it in the lane");
    let c = r.w.clients.at(r.ci);
    let f = frames(&c.obuf[ob..]);
    assert_eq!(data_of(&f, 2), 1000, "its DATA in obuf: {f:?}");
    let pos_data = f.iter().position(|(op, p)| *op == OP_BIN && p.len() > 5 && p[0] == PKT_DATA && p[1..5] == 2u32.to_le_bytes()).unwrap();
    let pos_ping = f.iter().position(|(op, p)| *op == OP_PING && p.len() == 6 && p[..2] == pinggate::TAG).expect("its gate PING in obuf");
    assert!(pos_data < pos_ping, "DATA before the gate PING");
    let cg = r.w.clients.gen(r.ci);
    assert_eq!(r.w.gate.held(r.ci, cg), 1, "its CLOSE held");
    let c = r.w.clients.at(r.ci);
    let at = c.obuf.len();
    pinggate::flush_held(&mut r.w.gate, c, r.ci, cg, &r.w.stats);
    let c = r.w.clients.at(r.ci);
    let f = frames(&c.obuf[at..]);
    assert!(
        f.iter().any(|(op, p)| *op == OP_BIN && p.len() == 6 && p[0] == PKT_CLOSE && p[1..5] == 2u32.to_le_bytes()),
        "the CLOSE is sent, not dropped: {f:?}"
    );
    r.end();
}

/// Closing a waiter inside the non-reader prefix, and closing the stream whose payload is in the pipe, leave the lists
/// consistent; the payload still goes out and the remaining waiter is released and splices.
#[test]
fn closing_a_waiter_or_the_splicer() {
    let Some(mut r) = rig(fd_cfg(), 3) else { return };
    r.splice_stuck(0, 32 * 1024);
    for k in [1, 2] {
        r.put(k, 100 * 1024);
        r.set_bulk(k);
        r.read(k);
        assert_eq!(r.state(k), Park::Parked, "S1 {k}");
    }
    assert_eq!(r.lists(), (0, 3));
    r.w.close_target(r.s[1].ti, None);
    r.w.park_check();
    assert_eq!(r.lists(), (0, 2), "the closed waiter left the list");
    r.w.close_target(r.s[0].ti, None);
    r.w.park_check();
    assert_eq!((r.lists(), r.pend()), ((0, 1), 32 * 1024), "the splicer left the list; its payload stays queued");
    r.empty_client();
    r.flush();
    assert_eq!((r.pend(), r.state(2)), (0, Park::Released), "the payload went out; the waiter is released");
    r.run_ready();
    assert_eq!(r.lane(), 0);
    assert!(r.queued(2) < 100 * 1024, "it spliced");
    r.end();
}

/// --credit-pace: a grant due while the stream is S-parked is held (60.42) and goes out when the released stream reads
/// without parking again.
#[test]
fn a_grant_due_while_s_parked_is_held_until_the_read() {
    let mut cfg = fd_cfg();
    cfg.credit_pace = true;
    let Some(mut r) = rig(cfg, 2) else { return };
    let ti = r.s[1].ti;
    r.upload(1, 63);
    r.splice_stuck(0, 32 * 1024);
    r.put(1, 20 * 1024);
    r.set_bulk(1);
    r.read(1);
    assert_eq!(r.state(1), Park::Parked, "S1");
    r.upload(1, 1); // the 64th packet: CONTINUE(128) due while parked
    assert!(r.w.cpace_st[ti as usize].held, "held while S-parked");
    r.empty_client();
    r.keep = true;
    r.flush();
    assert_eq!(r.state(1), Park::Released);
    r.run_ready();
    assert_eq!(r.state(1), Park::Run, "it read to EAGAIN");
    assert!(!r.w.cpace_st[ti as usize].held, "released at the read");
    r.flush();
    r.empty_client();
    let f = frames(&r.got);
    let cont = [&[3u8, 2, 0, 0, 0][..], &128u32.to_le_bytes()].concat();
    assert!(f.iter().any(|(op, p)| *op == OP_BIN && *p == cont), "the held CONTINUE went out");
    r.end();
}

/// A connection moves (60.64) while a stream waits in L2: the fence stays behind (a new slot generation on the
/// destination: no fence there), the stream arrives Parked in its list and is released and splices once the lane went
/// out.
#[test]
fn a_move_during_an_l2_wait() {
    let Some(mut r) = rig(fd_cfg(), 2) else { return };
    r.fill_client();
    r.lane_frame(0, 30 * 1024);
    r.put(1, 200 * 1024);
    r.set_bulk(1);
    r.read(1);
    assert!(r.fence(1).is_some() && r.state(1) == Park::Parked, "L2 wait");
    let g = r.w.clients.gen(r.ci);
    assert!(r.w.mig_quiet(r.ci, g), "at rest: it may move");
    let m = r.w.mig_export(r.ci);
    let (ci2, _) = r.w.mig_import(m).expect("imported");
    r.ci = ci2;
    for k in 0..2 {
        let ti2 = r.w.clients.at(ci2).streams[&r.s[k].sid];
        (r.s[k].ti, r.s[k].tg) = (ti2, r.w.targets.gen(ti2));
    }
    assert_eq!((r.state(1), r.lists()), (Park::Parked, (0, 1)), "arrives parked, listed once");
    assert_eq!(r.fence(1), None, "no fence on the destination");
    r.empty_client();
    r.flush();
    assert_eq!(r.state(1), Park::Released);
    r.run_ready();
    assert_eq!(r.lane(), 0, "it spliced");
    assert!(r.queued(1) < 200 * 1024);
    r.end();
}

/// Fairness and no lane copy under a shared pipe (a property v1.5.0 also has: the test passes with splice_wait off, with
/// flush_dirty's pipe gate off, and with both off; rule S's own logic is checked by the other tests of this file). Two
/// bulk streams on one connection whose client takes what is queued at each drain: over k drains each stream's bytes go
/// out in at least k/2 - 1 of them, no lane frame is pending at a drain's end, and both streams are bulk streams at each
/// drain's end. The client's pipe is cut to 64 KiB, and after each drain each target socket is topped up to 192 KiB
/// queued (from 2 MiB per stream, with the EPOLLIN edge epoll would deliver). Tested at the kernel's default buffer
/// limits (net.core.rmem_max and wmem_default 212992: a target socket holds about 384 KiB; CI run 614 failed there when
/// this test queued 2 MiB at once) and at larger ones. With these sizes the client socket takes most of what is queued
/// at each drain, so the streams seldom wait for each other.
#[test]
fn two_streams_share_the_pipe() {
    let Some(mut r) = rig(fd_cfg(), 2) else { return };
    let (pipe, q) = (r.pipe_cut(64 << 10), 192usize << 10);
    let mut left = [2usize << 20; 2];
    for (k, l) in left.iter_mut().enumerate() {
        r.put(k, q);
        *l -= q;
        r.set_bulk(k);
    }
    r.keep = true;
    r.read(0);
    r.read(1);
    let k_drains = 12;
    let (mut seen, mut before, mut lane_max) = ([0usize; 2], [0usize; 2], 0);
    for _ in 0..k_drains {
        r.empty_client();
        r.flush();
        r.run_ready();
        r.flush();
        r.empty_client();
        let f = frames(&r.got); // (all of it: a frame can span two drains)
        for k in 0..2 {
            let b = data_of(&f, r.s[k].sid);
            seen[k] += (b > before[k]) as usize;
            before[k] = b;
            assert!(r.w.targets.at(r.s[k].ti).bulk, "stream {k} stays a bulk stream ({before:?})");
        }
        lane_max = lane_max.max(r.lane());
        for (k, l) in left.iter_mut().enumerate() {
            let n = (*l).min(q.saturating_sub(r.queued(k)));
            if n > 0 {
                r.put(k, n);
                *l -= n;
                r.w.target_event(r.s[k].ti, r.s[k].tg, libc::EPOLLIN as u32);
                r.w.park_check();
                lane_max = lane_max.max(r.lane());
            }
        }
    }
    assert_eq!(lane_max, 0, "no lane copy (pipe {pipe})");
    for (k, &n) in seen.iter().enumerate() {
        assert!(n >= k_drains / 2 - 1, "stream {k}: bytes in {n} of {k_drains} drains ({before:?}, pipe {pipe})");
    }
    r.end();
}

/// Bound (b), the release rule before 20.37, unchanged: an S-parked stream waits while the connection's output stays at
/// or above out_low_bulk, here only other streams' obuf frames (its own lane frame went out first), and is released at
/// one byte below. obuf is still busy then, so its read copies one CHUNK into the lane (as before 20.37) and parks
/// behind that frame (L1).
#[test]
fn an_s_park_waits_for_out_low_bulk() {
    let Some(mut r) = rig(fd_cfg(), 1) else { return };
    r.fill_client();
    r.small_obuf();
    r.put(0, 300 * 1024);
    r.set_bulk(0);
    r.read(0);
    assert_eq!(r.state(0), Park::Parked, "L1");
    let low = r.w.st.out_low_bulk;
    let c = r.w.clients.at(r.ci);
    let lane = c.bulk.len() - c.bhead;
    (c.bhead, c.bulk_sent) = (c.bulk.len(), c.bulk_sent + lane as u64); // its own frame went out
    c.bulk_ends.clear();
    c.bulk_boundary = c.bulk_sent;
    c.obuf.extend_from_slice(&vec![0u8; low]); // obuf frames of other streams
    c.ohead = c.obuf.len() - low; // pending output: exactly out_low_bulk
    for _ in 0..3 {
        r.flush();
        assert_eq!((r.state(0), r.lane(), r.obuf()), (Park::Parked, 0, low), "no release at out_low_bulk (only obuf holds it)");
    }
    r.w.clients.at(r.ci).ohead += 1; // one byte below
    r.flush();
    assert_eq!(r.state(0), Park::Released, "released below out_low_bulk");
    let q = r.queued(0);
    r.run_ready();
    assert_eq!(r.queued(0), q - CHUNK, "the released stream read: one copy (obuf busy)");
    assert_eq!((r.lane(), r.state(0), r.lists()), (CHUNK + 9, Park::Parked, (0, 1)), "then L1 behind its frame");
    r.end();
}

/// S1's release comes from the client's EPOLLOUT edge alone: the real loop turn (fdtests' pump: epoll_wait, dispatch,
/// ready entries, flush_dirty), nothing marks the client dirty by hand. While our end reads nothing no turn releases
/// either stream; once it reads, the edge brings the flush that drains the pipe and the release, and the waiter splices.
#[test]
fn s1_release_comes_from_the_epollout_edge() {
    let Some(mut r) = rig(fd_cfg(), 2) else { return };
    r.splice_stuck(0, 32 * 1024);
    r.put(1, 200 * 1024);
    r.set_bulk(1);
    r.read(1);
    assert_eq!((r.state(1), r.pend()), (Park::Parked, 32 * 1024), "S1");
    for _ in 0..3 {
        pump(&mut r.w, 0); // (the splice's own dirty entry and any queued edge: the socket is still full)
        assert_eq!((r.state(0), r.state(1), r.pend()), (Park::Parked, Park::Parked, 32 * 1024), "no release while full");
    }
    assert!(r.w.dirty.is_empty() && !r.w.clients.at(r.ci).dirty, "(nothing pending: only an edge can wake the client)");
    let end = Instant::now() + Duration::from_secs(10);
    while r.queued(1) == 200 * 1024 {
        assert!(Instant::now() < end, "no release from the EPOLLOUT edge ({:?} {:?}, pending {})", r.state(0), r.state(1), r.pend());
        r.empty_client();
        pump(&mut r.w, 5);
    }
    assert_eq!(r.lane(), 0, "the waiter spliced: no copy");
    r.end();
}
