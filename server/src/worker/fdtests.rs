//! 60.57 worker tests for the fd count (A2), the refusals when fds are short (A3, A4), accept at memory level 2+ (A5)
//! and the connect counters (A6). Each test drives a real Worker through its own epoll (`pump` = one loop turn of
//! Worker::run); reap_dead asserts after every turn that Stats::fds is what the connections and streams hold.
use super::super::*;
use crate::fdgate::FdGate;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::fd::FromRawFd;

const UPGRADE: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

pub(super) fn fd_cfg() -> Config {
    Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads: 1,
        buffer: 128,
        filter: net::Filter::new(true, false),
        connect_timeout: Duration::from_secs(10),
        dns_own: false,
        abort_close: true,
        splice: true,
        balance: false,
        tfo: false,
        tls: None,
        udp: true,
        tls_rekey: 0,
        notsent_lowat: 0,
        adapt_lowat: 0,
        keepalive: true,
        prio: true,
        ext: ext::Ext::default(),
        credit_v2: false,
        credit_pace: false,
        park_rcvlock: 0,
        adaptive_splice: false,
        conn_gate: None,
        max_streams_per_conn: 0,
        policy: None,
        clientip: None,
        log_conns: false,
        log_streams: false,
        want_peer: false,
        pace: net::Pacing::default(),
        unix: None,
        upstream: None,
        upload_rate: None,
        proxy_tcp: false,
        proxy_unix: false,
        proxy_from: Box::new([]),
        dest_rate: None,
    }
}

/// A worker with its own fd gate (`limit` usable fds, taken in blocks of `block`) and its listener's port
pub(super) fn rig(cfg: Config, limit: u32, block: u32) -> (Worker, u16, mpsc::Receiver<DnsReq>) {
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.fdg = Arc::new(FdGate::new(limit, block));
    w.fd_setup();
    let port = unsafe { TcpListener::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    (w, port, rx)
}

/// One loop turn, as Worker::run (without the level check and the idle sweep)
pub(super) fn pump(w: &mut Worker, ms: i32) {
    let mut evs = [libc::epoll_event { events: 0, u64: 0 }; 64];
    let n = unsafe { libc::epoll_wait(w.ep, evs.as_mut_ptr(), 64, ms) };
    for ev in &evs[..n.max(0) as usize] {
        let (t, e) = (ev.u64, ev.events);
        w.dispatch(t, e);
    }
    for t in std::mem::take(&mut w.ready) {
        w.resume(t);
    }
    w.run_deferred();
    w.flush_dirty();
    if !w.connecting.is_empty() {
        w.run_timers();
    }
    if std::mem::take(&mut w.accept_retry) {
        w.accept_all();
    }
    w.reap_dead();
}

/// pump until `done` (at most 3 s)
pub(super) fn until(w: &mut Worker, what: &str, mut done: impl FnMut(&mut Worker) -> bool) {
    for _ in 0..600 {
        if done(w) {
            return;
        }
        pump(w, 5);
    }
    panic!("not reached in 3 s: {what}");
}

pub(super) fn fds(w: &Worker) -> u64 {
    assert_eq!(w.stats.fds.get(), w.fds_held());
    w.stats.fds.get()
}

/// a masked (zero key) binary frame with one Wisp packet
pub(super) fn wisp(ty: u8, sid: u32, body: &[u8]) -> Vec<u8> {
    let n = 5 + body.len();
    let mut f = vec![0x82];
    if n < 126 {
        f.push(0x80 | n as u8);
    } else {
        f.push(0x80 | 126);
        f.extend((n as u16).to_be_bytes());
    }
    f.extend([0, 0, 0, 0, ty]);
    f.extend(sid.to_le_bytes());
    f.extend(body);
    f
}

pub(super) fn connect(sid: u32, udp: bool, port: u16) -> Vec<u8> {
    let mut b = vec![if udp { 2 } else { 1 }];
    b.extend(port.to_le_bytes());
    b.extend(b"127.0.0.1");
    wisp(0x01, sid, &b)
}

/// A Wisp v1 client on the worker's listener, upgraded (the worker's newest client slot is returned with it)
pub(super) fn client(w: &mut Worker, port: u16) -> (TcpStream, u32) {
    client_with(w, port, UPGRADE)
}

/// `client` with its own first bytes (a PROXY header before the request, a request with a forwarding header)
pub(super) fn client_with(w: &mut Worker, port: u16, hello: &[u8]) -> (TcpStream, u32) {
    let before = w.stats.accepted.get();
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.write_all(hello).unwrap();
    until(w, "client accepted", |w| w.stats.accepted.get() > before);
    let fd_of = |w: &Worker, ci: usize| w.clients.slots[ci].1.as_ref().filter(|c| !c.dead).map(|c| c.fd);
    let peer = c.local_addr().unwrap();
    let ci = (0..w.clients.slots.len())
        .find(|&ci| fd_of(w, ci).is_some_and(|fd| net::peer_ip(fd) == Some(peer.ip()) && peer_port(fd) == peer.port()))
        .expect("the client's slot") as u32;
    until(w, "client upgraded", |w| w.clients.at(ci).state == CState::Open);
    c.set_nonblocking(true).unwrap();
    (c, ci)
}

fn peer_port(fd: RawFd) -> u16 {
    let s = std::mem::ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(fd) });
    s.peer_addr().map_or(0, |a| a.port())
}

/// everything the server sent to `c` so far (non-blocking)
pub(super) fn drain(c: &mut TcpStream, into: &mut Vec<u8>) {
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => return,
            Ok(n) => into.extend_from_slice(&b[..n]),
        }
    }
}

/// The DATA payload bytes in what the server sent: seen = (bytes of got read so far, payload so far), complete
/// frames only, the HTTP answer skipped
pub(super) fn data_len(got: &[u8], seen: &mut (usize, usize)) {
    let (mut i, mut n) = *seen;
    if i == 0 && got.starts_with(b"HTTP/") {
        match got.windows(4).take(8192).position(|w| w == b"\r\n\r\n") {
            Some(p) => i = p + 4,
            None => return,
        }
    }
    while i + 2 <= got.len() {
        let (mut len, mut head) = ((got[i + 1] & 0x7f) as usize, 2);
        if len >= 126 {
            head = if len == 126 { 4 } else { 10 };
            if i + head > got.len() {
                break;
            }
            len = if head == 4 {
                u16::from_be_bytes([got[i + 2], got[i + 3]]) as usize
            } else {
                u64::from_be_bytes(got[i + 2..i + 10].try_into().unwrap()) as usize
            };
        }
        if i + head + len > got.len() {
            break;
        }
        if got[i] & 0x0f == 2 && len >= 5 && got[i + head] == 0x02 {
            n += len - 5;
        }
        i += head + len;
    }
    *seen = (i, n);
}

/// a Wisp CLOSE for `sid` with `reason` is in the bytes the server sent
pub(super) fn closed_with(got: &[u8], sid: u32, reason: u8) -> bool {
    let mut p = vec![0x04];
    p.extend(sid.to_le_bytes());
    p.push(reason);
    got.windows(6).any(|x| x == p)
}

fn live_streams(w: &Worker) -> usize {
    w.targets.slots.len() - w.targets.free.len()
}

fn end(w: Worker) {
    for fd in [w.ep, w.lfd, w.inbox.efd, w.spare] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w); // (no frees while mem::tests::heap_counter_moves measures the heap counter)
}

/// A2 every fd a connection or stream opens is counted and every close gives it back: TCP streams, a refused
/// connect, a connect that times out, a UDP stream, a splice pipe (also closed by the idle sweep), a client close with
/// streams open. (reap_dead compares the count with a walk of the slabs after every turn.)
#[test]
fn fd_count_follows_every_open_and_close() {
    let mut cfg = fd_cfg();
    cfg.connect_timeout = Duration::from_millis(300);
    let (mut w, port, _rx) = rig(cfg, u32::MAX, 4);
    assert_eq!(fds(&w), 0);
    let (mut c, ci) = client(&mut w, port);
    assert_eq!(fds(&w), 1);
    // three TCP streams to a listener that accepts
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    for sid in 1..=3 {
        c.write_all(&connect(sid, false, lp)).unwrap();
    }
    until(&mut w, "3 streams open", |w| {
        w.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| t.state == TState::Open).count() == 3
    });
    assert_eq!(fds(&w), 4);
    let mut targets: Vec<TcpStream> = (0..3).map(|_| l.accept().unwrap().0).collect();
    // a refused connect: a bound socket that does not listen
    let hole = TcpListener::bind("127.0.0.1:0").unwrap();
    let hp = hole.local_addr().unwrap().port();
    drop(hole);
    let holder = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    (sa.sin_family, sa.sin_port, sa.sin_addr.s_addr) = (libc::AF_INET as u16, hp.to_be(), u32::from_be_bytes([127, 0, 0, 1]).to_be());
    assert_eq!(unsafe { libc::bind(holder, &sa as *const _ as *const libc::sockaddr, std::mem::size_of_val(&sa) as u32) }, 0);
    c.write_all(&connect(4, false, hp)).unwrap();
    until(&mut w, "stream 4 refused by the target", |w| w.stats.connect_fail.get() == 1);
    assert_eq!((fds(&w), live_streams(&w), w.stats.connect_timeout.get()), (4, 3, 0));
    unsafe { libc::close(holder) };
    // a connect that never completes: a listener whose accept queue is full drops the SYN
    let full = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    sa.sin_port = 0;
    let mut len = std::mem::size_of_val(&sa) as u32;
    unsafe {
        assert_eq!(libc::bind(full, &sa as *const _ as *const libc::sockaddr, len), 0);
        assert_eq!(libc::listen(full, 0), 0);
        assert_eq!(libc::getsockname(full, &mut sa as *mut _ as *mut libc::sockaddr, &mut len), 0);
    }
    let fp = u16::from_be(sa.sin_port);
    let fillers: Vec<TcpStream> =
        (0..2).filter_map(|_| TcpStream::connect_timeout(&([127, 0, 0, 1], fp).into(), Duration::from_millis(200)).ok()).collect();
    c.write_all(&connect(5, false, fp)).unwrap();
    until(&mut w, "stream 5 connecting", |w| w.connecting.len() == 1);
    assert_eq!(fds(&w), 5, "the attempt in flight holds an fd");
    until(&mut w, "stream 5 timed out", |w| w.stats.connect_timeout.get() == 1);
    assert_eq!((fds(&w), live_streams(&w), w.stats.connect_fail.get()), (4, 3, 1));
    drop(fillers);
    unsafe { libc::close(full) };
    // a UDP stream
    let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    c.write_all(&connect(6, true, u.local_addr().unwrap().port())).unwrap();
    until(&mut w, "UDP stream open", |w| live_streams(w) == 4);
    assert_eq!(fds(&w), 5);
    // a download on the splice path: the client's pipe is 2 more fds. The worker splices a stream whose last read
    // filled the read buffer (CHUNK bytes), once nothing waits for the client. So the target sends CHUNK bytes, alone
    // in its socket, turn after turn until the pipe is open. (Before: 4 MiB at once and "4 MiB arrived"; under load
    // every turn could end with a short read, then nothing was spliced; and the bytes on the wire reached 4 MiB before
    // the last payload did, whose tail opened the pipe again after the sweep below.) Every byte sent has arrived when
    // the DATA frames hold as many.
    let unit = vec![7u8; crate::worker::CHUNK];
    targets[0].set_nonblocking(true).unwrap();
    let (mut sent, mut got, mut seen) = (0, Vec::new(), (0, 0));
    until(&mut w, "the download spliced (this test needs the pipe) and arrived", |w| {
        let piped = w.clients.at(ci).pipe[0] >= 0;
        drain(&mut c, &mut got);
        data_len(&got, &mut seen);
        if !piped && seen.1 == sent {
            let mut left = &unit[..];
            for _ in 0..100_000 {
                match targets[0].write(left) {
                    Ok(n) => (sent, left) = (sent + n, &left[n..]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::yield_now(),
                    Err(e) => panic!("target write: {e}"),
                }
                if left.is_empty() {
                    break;
                }
            }
            assert!(left.is_empty(), "an empty loopback socket did not take {} bytes", unit.len());
        }
        piped && seen.1 == sent
    });
    assert_eq!(fds(&w), 7);
    // the idle sweep closes an idle client's empty pipe (the first sweep clears `active`)
    w.sweep();
    w.sweep();
    assert!(w.clients.at(ci).pipe[0] < 0);
    assert_eq!(fds(&w), 5);
    // the client closes one stream; then the connection goes with the rest open
    c.write_all(&wisp(0x04, 2, &[0x02])).unwrap();
    until(&mut w, "stream 2 closed", |w| live_streams(w) == 3);
    assert_eq!(fds(&w), 4);
    drop(c);
    until(&mut w, "client gone", |w| w.clients.slots.len() == w.clients.free.len());
    assert_eq!((fds(&w), live_streams(&w)), (0, 0));
    // the allowance: what the worker holds is what the process count granted; the idle sweep returns all but a block
    assert_eq!(w.fdg.granted(), w.fd_all());
    w.fd_trim(false);
    assert_eq!((w.fdg.granted(), w.fd_all()), (4, 4));
    // and a worker without any fd at its idle sweep returns the block too (an idle worker keeps nothing from the others)
    w.fd_trim(true);
    assert_eq!((w.fdg.granted(), w.fd_all()), (0, 0));
    end(w);
}

/// A3 + A4 (T8 in one process) with 4 usable fds: a connection and 3 streams hold them all. A CONNECT then gets 0x49
/// (refuse_fd) and a new connection is reset at once (refuse_fd_conns); the open connection and its streams go on;
/// after a stream closes both work again. The count never passes the limit.
#[test]
fn at_the_fd_limit_connections_are_reset_and_streams_refused() {
    let (mut w, port, _rx) = rig(fd_cfg(), 4, 1);
    let (mut c, _) = client(&mut w, port);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    for sid in 1..=3 {
        c.write_all(&connect(sid, false, lp)).unwrap();
    }
    until(&mut w, "3 streams", |w| w.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| t.state == TState::Open).count() == 3);
    assert_eq!((fds(&w), w.fdg.granted()), (4, 4));
    // a fourth stream: refused at CONNECT, before any socket
    let mut got = Vec::new();
    c.write_all(&connect(4, false, lp)).unwrap();
    until(&mut w, "stream 4 refused", |w| w.stats.refuse_fd.get() == 1);
    pump(&mut w, 5);
    drain(&mut c, &mut got);
    assert!(closed_with(&got, 4, 0x49), "CLOSE 0x49 for stream 4");
    assert_eq!((fds(&w), live_streams(&w), w.stats.close[0x49].get()), (4, 3, 1));
    // a new connection: accepted and reset, not left waiting
    let mut n = TcpStream::connect(("127.0.0.1", port)).unwrap();
    until(&mut w, "connection reset", |w| w.stats.refuse_fd_conns.get() == 1);
    n.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let e = n.read(&mut [0u8; 8]).expect_err("a reset, not EOF or data");
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    assert_eq!((fds(&w), w.stats.accepted.get()), (4, 1));
    // the open streams still work
    let mut t = l.accept().unwrap().0;
    t.write_all(b"hello").unwrap();
    until(&mut w, "data on an open stream", |_| {
        drain(&mut c, &mut got);
        got.windows(5).any(|x| x == b"hello")
    });
    // one stream closes: one fd is free for a stream or a connection
    c.write_all(&wisp(0x04, 1, &[0x02])).unwrap();
    until(&mut w, "stream 1 closed", |w| live_streams(w) == 2);
    let (_c2, _) = client(&mut w, port);
    assert_eq!((fds(&w), w.stats.refuse_fd_conns.get(), w.stats.refuse_fd.get()), (4, 1, 1));
    end(w);
}

/// A4 a stream that passed the CONNECT check and finds no fd at its connect (another stream took it meanwhile) is
/// refused the same way; a Happy Eyeballs attempt that finds none just does not start.
#[test]
fn a_connect_attempt_without_an_fd_refuses_the_stream() {
    let (mut w, port, _rx) = rig(fd_cfg(), 2, 1);
    let (mut c, ci) = client(&mut w, port);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    // two CONNECTs in one read: both pass the check (one fd is free), the second finds none at its connect
    let mut two = connect(1, false, lp);
    two.extend(connect(2, false, lp));
    c.write_all(&two).unwrap();
    until(&mut w, "one refused", |w| w.stats.refuse_fd.get() == 1);
    let mut got = Vec::new();
    until(&mut w, "its CLOSE", |_| {
        drain(&mut c, &mut got);
        closed_with(&got, 1, 0x49) || closed_with(&got, 2, 0x49)
    });
    assert_eq!((fds(&w), live_streams(&w), w.stats.connect_fail.get()), (2, 1, 0));
    // an attempt in flight + no fd for a second address: nothing is refused, the first attempt decides
    let ti = *w.clients.at(ci).streams.values().next().unwrap();
    let t = w.targets.at(ti);
    (t.state, t.conn, t.fd) = (TState::Connecting, vec![t.fd], -1);
    t.addrs = vec!["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()];
    t.attempt = 1;
    w.try_connect(ti);
    assert_eq!((w.stats.refuse_fd.get(), live_streams(&w), fds(&w)), (1, 1, 2));
    end(w);
}

/// A2 --balance: a connection handed to another worker takes its unit of the allowance along: the process count does
/// not move, the sender's count goes down, the receiver's up, and the close on the receiver gives the fd back.
#[test]
fn a_handed_over_connection_keeps_its_fd_unit() {
    handed_over(0);
}

/// ... and with --conn-share, where a worker's fd_have is exactly its count and the rest of its allowance is in fd_pool
#[test]
fn a_handed_over_connection_keeps_its_fd_unit_with_conn_share() {
    handed_over(MARK_SHARE);
}

fn handed_over(mask: u8) {
    let mut cfg = fd_cfg();
    (cfg.balance, cfg.threads) = (true, 2);
    let cfg = Arc::new(cfg);
    let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
    let (tx, _rx) = mpsc::channel();
    let gate = Arc::new(FdGate::new(100, 8));
    gate.set_marks(mask);
    let mut ws: Vec<Worker> = (0..2)
        .map(|i| {
            let mut w = Worker::new(cfg.clone(), tx.clone(), i, peers.clone(), Arc::default()).unwrap();
            w.fdg = gate.clone();
            w.fd_setup();
            w
        })
        .collect();
    let port = unsafe { TcpListener::from_raw_fd(libc::dup(ws[0].lfd)) }.local_addr().unwrap().port();
    // SO_REUSEPORT picks a listener per connection: keep both workers turning until both connections are owned
    let c: Vec<TcpStream> = (0..2).map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap()).collect();
    for _ in 0..200 {
        for w in ws.iter_mut() {
            pump(w, 1);
        }
        if ws.iter().map(|w| w.stats.accepted.get()).sum::<u64>() == 2 {
            break;
        }
    }
    // (load 1 each: the second connection went to the worker without one, by hand-over unless the kernel chose it)
    assert_eq!((ws[0].stats.accepted.get(), ws[1].stats.accepted.get()), (1, 1));
    assert_eq!((fds(&ws[0]), fds(&ws[1])), (1, 1));
    if mask & MARK_SHARE != 0 {
        assert_eq!((ws[0].fd_have, ws[1].fd_have), (1, 1), "--conn-share: fd_have is the count, on both sides of a hand-over");
    }
    assert_eq!(gate.granted(), ws[0].fd_all() + ws[1].fd_all(), "allowances add up to the process count");
    drop(c);
    for _ in 0..200 {
        for w in ws.iter_mut() {
            pump(w, 1);
        }
        if ws.iter().all(|w| w.clients.slots.len() == w.clients.free.len()) {
            break;
        }
    }
    assert_eq!((fds(&ws[0]), fds(&ws[1])), (0, 0));
    assert_eq!(gate.granted(), ws[0].fd_all() + ws[1].fd_all());
    for w in ws.iter_mut() {
        w.fd_trim(false);
    }
    assert!(gate.granted() <= 16, "at most one unused block per worker: {}", gate.granted());
    for w in ws.iter_mut() {
        w.fd_trim(true);
    }
    assert_eq!(gate.granted(), 0, "idle workers return everything at the idle sweep");
    for w in ws {
        end(w);
    }
}

/// A2 the unit moves with the fd, shown without the kernel's choice of listener: route on worker 0 with worker 1 less
/// loaded
#[test]
fn route_moves_the_fd_unit_to_the_other_worker() {
    let mut cfg = fd_cfg();
    (cfg.balance, cfg.threads) = (true, 2);
    let cfg = Arc::new(cfg);
    let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
    let (tx, _rx) = mpsc::channel();
    let gate = Arc::new(FdGate::new(3, 1));
    let mut ws: Vec<Worker> = (0..2)
        .map(|i| {
            let mut w = Worker::new(cfg.clone(), tx.clone(), i, peers.clone(), Arc::default()).unwrap();
            w.fdg = gate.clone();
            w.fd_setup();
            w
        })
        .collect();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut held = Vec::new();
    let mut handed = 0;
    for i in 0..3 {
        held.push(TcpStream::connect(l.local_addr().unwrap()).unwrap());
        let s = l.accept().unwrap().0;
        s.set_nonblocking(true).unwrap();
        assert!(ws[0].fd_take(1));
        let before = ws[0].stats.fds.get();
        ws[0].route(net::Handoff::bare(std::os::fd::IntoRawFd::into_raw_fd(s)));
        handed += (ws[0].stats.fds.get() < before) as u32;
        ws[1].inbox_ready();
        assert_eq!(fds(&ws[0]) + fds(&ws[1]), i + 1);
        assert_eq!(gate.granted(), ws[0].fd_all() + ws[1].fd_all());
    }
    assert!(handed >= 1, "worker 1 had the lower load at least once");
    assert_eq!(gate.granted(), 3);
    assert!(!ws[0].fd_take(1) && !ws[1].fd_take(1), "the limit holds on both workers");
    drop(held);
    for w in ws.iter_mut() {
        for _ in 0..50 {
            pump(w, 1);
        }
    }
    assert_eq!((fds(&ws[0]), fds(&ws[1]), gate.granted()), (0, 0, ws[0].fd_all() + ws[1].fd_all()));
    for w in ws {
        end(w);
    }
}

/// A5 at memory level 2 a new connection is accepted and reset (before: it waited in the listen backlog). Counted per
/// connection (refuse_level_conns) and once per episode (accept_paused); back at level 0 connections are served.
#[test]
fn memory_level_2_resets_new_connections() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (_keep, _) = client(&mut w, port);
    w.set_level(2);
    for i in 1..=2u64 {
        let mut n = TcpStream::connect(("127.0.0.1", port)).unwrap();
        until(&mut w, "reset at level 2", |w| w.stats.refuse_level_conns.get() == i);
        n.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(n.read(&mut [0u8; 8]).expect_err("a reset").kind(), std::io::ErrorKind::ConnectionReset);
    }
    assert_eq!((w.stats.accept_paused.get(), w.stats.accepted.get(), fds(&w)), (1, 1, 1));
    w.set_level(0);
    assert!(!w.accept_paused);
    let (_c2, _) = client(&mut w, port);
    assert_eq!((w.stats.accepted.get(), w.stats.refuse_level_conns.get(), fds(&w)), (2, 2, 2));
    // a second episode counts again
    w.set_level(3);
    let _n = TcpStream::connect(("127.0.0.1", port)).unwrap();
    until(&mut w, "reset at level 3", |w| w.stats.refuse_level_conns.get() == 3);
    assert_eq!(w.stats.accept_paused.get(), 2);
    w.set_level(0);
    end(w);
}

/// A3 accept failed for lack of fds: the worker closes its spare fd, accepts and resets what waits on its listener,
/// and opens the spare again
#[test]
fn accept_emfile_resets_the_waiting_connections_through_the_spare_fd() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    assert!(w.spare >= 0);
    let mut cs: Vec<TcpStream> = (0..3).map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(20));
    w.accept_emfile(w.lfd);
    assert!(w.spare >= 0, "the spare is open again");
    assert_eq!((w.stats.refuse_fd_conns.get(), w.stats.accepted.get(), fds(&w)), (3, 0, 0));
    for c in cs.iter_mut() {
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(c.read(&mut [0u8; 8]).expect_err("a reset").kind(), std::io::ErrorKind::ConnectionReset);
    }
    // without a spare (it could not be reopened) the next call opens one first
    unsafe { libc::close(w.spare) };
    w.spare = -1;
    let _c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    w.accept_emfile(w.lfd);
    assert!(w.spare >= 0 && w.stats.refuse_fd_conns.get() == 4);
    end(w);
}

/// A2 a connection waiting for its PROXY header is counted, and its drop gives the fd back
#[test]
fn a_pending_proxy_connection_is_counted() {
    let mut cfg = fd_cfg();
    (cfg.proxy_tcp, cfg.want_peer) = (true, true);
    cfg.proxy_from = Box::new([crate::policy::Cidr::parse("127.0.0.0/8").unwrap()]);
    let (mut w, port, _rx) = rig(cfg, u32::MAX, 4);
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    until(&mut w, "pending", |w| w.pending.len() == 1);
    assert_eq!(fds(&w), 1);
    c.write_all(b"PROXY TCP4 9.9.9.9 1.1.1.1 1000 443\r\n").unwrap();
    until(&mut w, "adopted", |w| w.stats.accepted.get() == 1);
    assert_eq!((fds(&w), w.pending.len()), (1, 0));
    let c2 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    until(&mut w, "second pending", |w| w.pending.len() == 1);
    assert_eq!(fds(&w), 2);
    drop(c2);
    until(&mut w, "pending dropped", |w| w.pending.is_empty());
    assert_eq!(fds(&w), 1);
    drop(c);
    until(&mut w, "client gone", |w| w.clients.slots.len() == w.clients.free.len());
    assert_eq!(fds(&w), 0);
    end(w);
}

// ---- C: --fd-admission (the host mark) and --conn-share (the share rule)

use crate::fdgate::{MARK_HOST, MARK_SHARE};

/// One test with many fds at a time (each holds several hundred in this process), under a soft open-file limit that
/// has room for it
fn many_fds() -> std::sync::MutexGuard<'static, ()> {
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut l), 0);
        if l.rlim_cur < 4096 {
            l.rlim_cur = l.rlim_max.min(4096);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &l), 0);
        }
    }
    assert!(l.rlim_cur >= 2048, "these tests need an open-file limit of 2048 or more (hard limit {})", l.rlim_max);
    g
}

/// A worker whose clients have the address their first bytes name: a PROXY header (charged before the request, a
/// refusal is a reset), or with `xff` an X-Forwarded-For header behind a trusted proxy (charged at the upgrade, a
/// refusal is a 429). --conn-share on (`mask`), `limit` usable fds in blocks of 1 (the marks are exact).
fn share_rig(xff: bool, limit: u32, mask: u8) -> (Worker, u16, mpsc::Receiver<DnsReq>) {
    let mut cfg = fd_cfg();
    cfg.want_peer = true;
    let lo = crate::policy::Cidr::parse("127.0.0.0/8").unwrap();
    let mut trusted = Vec::new();
    if xff {
        trusted.push(lo);
    } else {
        cfg.proxy_tcp = true;
        cfg.proxy_from = Box::new([lo]);
    }
    cfg.clientip = Some(Box::new(clientip::ClientIp {
        trusted: trusted.into(),
        header: "x-forwarded-for".into(),
        table: Some(clientip::IpTable::with_rates(None, None, None).with_share(1)),
        max_conns: 0,
    }));
    let (mut w, port, rx) = rig(cfg, limit, 1);
    w.fdg.set_marks(mask);
    w.fd_setup();
    (w, port, rx)
}

fn hello(ip: &str, xff: bool) -> Vec<u8> {
    if xff {
        let s = String::from_utf8_lossy(UPGRADE).replace("Host: x\r\n", &format!("Host: x\r\nX-Forwarded-For: {ip}\r\n"));
        s.into_bytes()
    } else {
        [format!("PROXY TCP4 {ip} 192.0.2.1 1000 443\r\n").as_bytes(), UPGRADE].concat()
    }
}

/// `n` UDP streams more on `c` (a UDP stream holds one fd and needs no peer), stream ids from `sid`
fn udp_streams(w: &mut Worker, c: &mut TcpStream, sid: u32, n: u32, port: u16) {
    let want = live_streams(w) + n as usize;
    for s in sid..sid + n {
        c.write_all(&connect(s, true, port)).unwrap();
        if s % 64 == 0 {
            pump(w, 0);
        }
    }
    until(w, "the UDP streams are open", |w| live_streams(w) == want);
}

/// (connections, published stream fds) of the key of `ip`
fn held(w: &Worker, ip: &str) -> (u32, u32) {
    w.cfg.clientip.as_ref().unwrap().table.as_ref().unwrap().held(clientip::key(ip.parse().unwrap()))
}

/// 60.57 C the share rule end to end, F = 1000 usable fds (a key above 500, others at 256 or more, from 750 in use).
/// (i) with the mark set and a big key, a probe connection with 3 streams from a second address does not arm the
/// rule; (ii) once the second address holds 256 fds the big key gets no new connection (a reset after its PROXY
/// header, or a 429 behind a trusted proxy), while its open connections still open streams and the small key still
/// connects. The published count lags the real one by at most 7 fds per connection until the idle sweep: the rule
/// acts late (step 7), never early. `big` loopback or private: never gated.
fn share_scenario(big: &str, xff: bool, gated: bool) {
    let _one = many_fds();
    const SMALL: &str = "198.51.100.7";
    let (mut w, port, _rx) = share_rig(xff, 1000, MARK_SHARE);
    let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let up = u.local_addr().unwrap().port();
    // 1-2: the big key: two connections with 520 and 240 streams = 762 fds: over half, and the share mark is set
    let (mut b1, _) = client_with(&mut w, port, &hello(big, xff));
    udp_streams(&mut w, &mut b1, 1, 520, up);
    assert_eq!((held(&w, big), w.fdg.marks()), ((1, 520), 0));
    let (mut b2, _) = client_with(&mut w, port, &hello(big, xff));
    udp_streams(&mut w, &mut b2, 1, 240, up);
    assert_eq!((held(&w, big), fds(&w), w.fdg.marks()), ((2, 760), 762, MARK_SHARE));
    // 3-4 (i): a probe from a second address, one connection and 3 streams: the big key still connects
    let (mut s1, _) = client_with(&mut w, port, &hello(SMALL, xff));
    udp_streams(&mut w, &mut s1, 1, 3, up);
    assert_eq!(held(&w, SMALL), (1, 0), "3 stream fds: below the publish step");
    let (_b3, _) = client_with(&mut w, port, &hello(big, xff));
    assert_eq!((held(&w, big), w.stats.refuse_share_conns.get()), ((3, 760), 0));
    // 5: the big key's second connection goes: its fds leave the key, the mark clears
    drop(b2);
    until(&mut w, "b2 gone", |w| w.stats.fds.get() == 526);
    assert_eq!((held(&w, big), w.fdg.marks()), ((2, 520), 0));
    // 6-7: the second address grows to 256 fds (1 + 255); 248 of the 255 are published: the rule is not armed yet
    udp_streams(&mut w, &mut s1, 4, 252, up);
    assert_eq!((held(&w, SMALL), fds(&w), w.fdg.marks()), ((1, 248), 778, MARK_SHARE));
    let (_b4, _) = client_with(&mut w, port, &hello(big, xff));
    assert_eq!(w.stats.refuse_share_conns.get(), 0, "the published count is behind: the rule acts late, never early");
    // 8-9 (ii): the idle sweep publishes the exact number: 256 on the second address
    w.sfd_sweep();
    assert_eq!(held(&w, SMALL), (1, 255));
    if gated {
        let mut n = TcpStream::connect(("127.0.0.1", port)).unwrap();
        n.write_all(&hello(big, xff)).unwrap();
        until(&mut w, "the big key's connection is refused", |w| w.stats.refuse_share_conns.get() == 1);
        for _ in 0..20 {
            pump(&mut w, 5);
        }
        n.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut got = [0u8; 64];
        match (xff, n.read(&mut got)) {
            (true, Ok(k)) => assert!(got[..k].starts_with(b"HTTP/1.1 429 "), "{:?}", String::from_utf8_lossy(&got[..k])),
            (false, Err(e)) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset),
            (_, r) => panic!("refusal: {r:?}"),
        }
        until(&mut w, "the refused connection is gone", |w| w.stats.fds.get() == 779);
        assert_eq!(held(&w, big), (3, 520), "a refusal leaves the key as it was");
    } else {
        let (_b5, _) = client_with(&mut w, port, &hello(big, xff));
        assert_eq!((held(&w, big), w.stats.refuse_share_conns.get()), ((4, 520), 0), "a loopback or private address is never gated");
    }
    // 10: the big key's open connection still opens streams; the small key still connects
    udp_streams(&mut w, &mut b1, 600, 2, up);
    let (_s2, _) = client_with(&mut w, port, &hello(SMALL, xff));
    assert_eq!(held(&w, SMALL), (2, 255));
    // the end: every connection gone: nothing is left in the table or in the count
    drop((b1, s1, _b3, _b4, _s2));
    if !gated {
        // (_b5 went out of scope above)
    }
    until(&mut w, "all gone", |w| w.clients.slots.len() == w.clients.free.len());
    let t = w.cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    assert_eq!((fds(&w), t.keys(), t.share_total()), (0, 0, 0));
    end(w);
}

#[test]
fn share_rule_gates_the_big_key_after_a_proxy_header() {
    share_scenario("203.0.113.1", false, true);
}

#[test]
fn share_rule_gates_the_big_key_behind_a_trusted_proxy() {
    share_scenario("203.0.113.1", true, true);
}

#[test]
fn share_rule_never_gates_a_private_key() {
    share_scenario("10.9.8.7", false, false);
}

/// 60.57 C which addresses the rule is for: not while the mark is clear, not with the flag off, never a loopback,
/// private, link-local or CGNAT address, never a --trusted-proxy
#[test]
fn share_rule_exempt_addresses() {
    let cip = clientip::ClientIp {
        trusted: Box::new([crate::policy::Cidr::parse("203.0.113.0/24").unwrap()]),
        header: "x-forwarded-for".into(),
        table: None,
        max_conns: 0,
    };
    let g = FdGate::new(1000, 1);
    g.set_marks(MARK_SHARE);
    let rule = |g: &FdGate, mask: u8, ip: &str| Worker::share_rule(mask, g, &cip, ip.parse().unwrap());
    assert_eq!(rule(&g, MARK_SHARE, "198.51.100.1"), None, "the mark is clear");
    g.grab(750, 1);
    assert_eq!(rule(&g, MARK_SHARE, "198.51.100.1"), Some((500, 256)));
    assert_eq!(rule(&g, MARK_SHARE, "2001:db8::1"), Some((500, 256)));
    assert_eq!(rule(&g, 0, "198.51.100.1"), None, "the flag is off");
    assert_eq!(rule(&g, MARK_HOST, "198.51.100.1"), None);
    for ip in
        ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1"]
    {
        assert_eq!(rule(&g, MARK_SHARE, ip), None, "{ip} is a proxy or a bridge, not one client");
    }
    assert_eq!(rule(&g, MARK_SHARE, "203.0.113.5"), None, "a trusted proxy's own address");
}

/// 60.57 C how a connection publishes its stream fds to its key: nothing below 8, then in steps of 8; a close below
/// the published number publishes 4 under the real one; the idle sweep publishes the exact number; the splice pipe is
/// in it; the connection's end takes everything back. Published <= real at every step (also asserted per loop turn).
#[test]
fn stream_fds_are_published_in_steps() {
    const IP: &str = "203.0.113.9";
    let (mut w, port, _rx) = share_rig(false, u32::MAX, MARK_SHARE);
    let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let up = u.local_addr().unwrap().port();
    let (mut c, ci) = client_with(&mut w, port, &hello(IP, false));
    udp_streams(&mut w, &mut c, 1, 7, up);
    assert_eq!((held(&w, IP), w.sfds[ci as usize]), ((1, 0), [7, 0]));
    udp_streams(&mut w, &mut c, 8, 1, up);
    assert_eq!(held(&w, IP), (1, 8));
    udp_streams(&mut w, &mut c, 9, 7, up);
    assert_eq!((held(&w, IP), w.sfds[ci as usize]), ((1, 8), [15, 8]));
    // closes: down to 8 nothing is published; the next close publishes 7 - 4
    for sid in 9..=15 {
        c.write_all(&wisp(0x04, sid, &[0x02])).unwrap();
    }
    until(&mut w, "7 closed", |w| live_streams(w) == 8);
    assert_eq!(held(&w, IP), (1, 8));
    c.write_all(&wisp(0x04, 8, &[0x02])).unwrap();
    until(&mut w, "8 closed", |w| live_streams(w) == 7);
    assert_eq!((held(&w, IP), w.sfds[ci as usize]), ((1, 3), [7, 3]));
    // the idle sweep publishes the exact number; the splice pipe's two fds count like stream fds
    w.sfd_sweep();
    assert_eq!(held(&w, IP), (1, 7));
    assert!(w.pipe_open(ci));
    assert_eq!((held(&w, IP), w.sfds[ci as usize]), ((1, 7), [9, 7]));
    w.sfd_sweep();
    assert_eq!((held(&w, IP), fds(&w)), ((1, 9), 10));
    // a second connection of the key adds to the same entry
    let (mut c2, _) = client_with(&mut w, port, &hello(IP, false));
    udp_streams(&mut w, &mut c2, 1, 8, up);
    assert_eq!(held(&w, IP), (2, 17));
    drop(c);
    until(&mut w, "first gone", |w| w.stats.fds.get() == 9);
    assert_eq!(held(&w, IP), (1, 8));
    drop(c2);
    until(&mut w, "all gone", |w| w.clients.slots.len() == w.clients.free.len());
    let t = w.cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    assert_eq!((held(&w, IP), t.keys(), t.share_total(), fds(&w)), ((0, 0), 0, 0, 0));
    // a connection whose only published fds are its splice pipe's (no stream closes that would take them back)
    let (c3, ci) = client_with(&mut w, port, &hello(IP, false));
    assert!(w.pipe_open(ci));
    w.sfd_sweep();
    let t = w.cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    assert_eq!((held(&w, IP), t.share_total()), ((1, 2), 3));
    // the idle sweep closes the pipe of an idle client: the key's count goes down with it (review: not later)
    w.sweep();
    w.sweep();
    assert_eq!((w.clients.at(ci).pipe, w.sfds[ci as usize], held(&w, IP), fds(&w)), ([-1, -1], [0, 0], (1, 0), 1));
    assert!(w.pipe_open(ci));
    w.sfd_sweep();
    assert_eq!(held(&w, IP), (1, 2));
    drop(c3);
    until(&mut w, "c3 gone", |w| w.clients.slots.len() == w.clients.free.len());
    let t = w.cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    assert_eq!((t.keys(), t.share_total(), fds(&w)), (0, 0, 0), "the connection's end takes back what it published");
    end(w);
}

/// 60.57 C is free when off: no connection or stream path tests its flags. A's two inline tests (fd_take: count + n
/// <= fd_have; fd_put: fd_have - count >= two blocks) are all they run. With --conn-share or --fd-admission the
/// worker holds fd_have at its count and fd_block at 0, so both tests fail for every take and put and the out-of-line
/// side does C's work (--conn-share: the connection's fds are noted); the allowance it does not use waits in fd_pool,
/// so the process count still moves by blocks only (no shared write per stream). Off: fd_pool is 0, nothing is noted,
/// and the numbers are section A's.
#[test]
fn c_flags_are_served_by_the_fd_count_itself() {
    const IP: &str = "203.0.113.9";
    for mask in [MARK_SHARE, MARK_HOST, 0] {
        // (tight: fd_have is the count; on: the connection's fds are noted)
        let (tight, on) = (mask != 0, mask & MARK_SHARE != 0);
        let (mut w, port, _rx) = share_rig(false, 100, mask);
        w.fdg = Arc::new(FdGate::new(100, 8));
        w.fdg.set_marks(mask);
        w.fd_setup();
        let hold = |w: &Worker| (w.fd_have, w.fd_pool, w.fd_block);
        let noted = |w: &Worker, ci: u32| w.sfds.get(ci as usize).copied();
        let (mut c, ci) = client_with(&mut w, port, &hello(IP, false));
        assert_eq!((fds(&w), w.fdg.granted(), hold(&w)), (1, 8, if tight { (1, 7, 0) } else { (8, 0, 8) }));
        // TCP streams (try_connect) and UDP streams
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let lp = l.local_addr().unwrap().port();
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let up = u.local_addr().unwrap().port();
        for sid in 1..=3 {
            c.write_all(&connect(sid, false, lp)).unwrap();
        }
        until(&mut w, "3 TCP streams open", |w| {
            w.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| t.state == TState::Open).count() == 3
        });
        udp_streams(&mut w, &mut c, 4, 2, up);
        assert_eq!((fds(&w), w.fdg.granted(), hold(&w)), (6, 8, if tight { (6, 2, 0) } else { (8, 0, 8) }));
        assert_eq!(noted(&w, ci), on.then_some([5, 0]));
        // a refused connect (a bound socket that does not listen): its fd is taken and given back, noted both ways
        let holder = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        (sa.sin_family, sa.sin_addr.s_addr) = (libc::AF_INET as u16, u32::from_be_bytes([127, 0, 0, 1]).to_be());
        let mut len = std::mem::size_of_val(&sa) as u32;
        unsafe {
            assert_eq!(libc::bind(holder, &sa as *const _ as *const libc::sockaddr, len), 0);
            assert_eq!(libc::getsockname(holder, &mut sa as *mut _ as *mut libc::sockaddr, &mut len), 0);
        }
        c.write_all(&connect(6, false, u16::from_be(sa.sin_port))).unwrap();
        until(&mut w, "stream 6 refused by the target", |w| w.stats.connect_fail.get() == 1);
        unsafe { libc::close(holder) };
        assert_eq!((fds(&w), w.fdg.granted(), noted(&w, ci)), (6, 8, on.then_some([5, 0])));
        // six more: the second block; the connection publishes at 8
        udp_streams(&mut w, &mut c, 7, 6, up);
        assert_eq!((fds(&w), w.fdg.granted(), hold(&w)), (12, 16, if tight { (12, 4, 0) } else { (16, 0, 8) }));
        assert_eq!((noted(&w, ci), held(&w, IP)), if on { (Some([11, 8]), (1, 8)) } else { (None, (1, 0)) });
        // stream churn: the process count does not move, with the flag or without
        for sid in 20..60 {
            udp_streams(&mut w, &mut c, sid, 1, up);
            c.write_all(&wisp(0x04, sid, &[0x02])).unwrap();
            until(&mut w, "the churn stream closed", |w| live_streams(w) == 11);
            assert_eq!((w.fdg.granted(), w.fd_all(), fds(&w)), (16, 16, 12));
            if tight {
                assert_eq!(hold(&w), (12, 4, 0));
            }
        }
        // every stream closed: less than two unused blocks, nothing goes back yet
        for sid in [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12] {
            c.write_all(&wisp(0x04, sid, &[0x02])).unwrap();
        }
        until(&mut w, "all streams closed", |w| live_streams(w) == 0);
        assert_eq!((fds(&w), w.fdg.granted(), hold(&w)), (1, 16, if tight { (1, 15, 0) } else { (16, 0, 8) }));
        assert_eq!((noted(&w, ci), held(&w, IP)), if on { (Some([0, 0]), (1, 0)) } else { (None, (1, 0)) });
        // the connection's end: two unused blocks, one goes back; the idle sweep of an idle worker returns the rest
        drop(c);
        until(&mut w, "client gone", |w| w.clients.slots.len() == w.clients.free.len());
        assert_eq!((fds(&w), w.fdg.granted(), hold(&w)), (0, 8, if tight { (0, 8, 0) } else { (8, 0, 8) }));
        w.fd_trim(true);
        assert_eq!((w.fdg.granted(), w.fd_all()), (0, 0));
        end(w);
    }
}

/// 60.57 C --fd-admission with 16 usable fds: from 14 handed out a new connection is reset (refuse_mark_conns), the
/// open ones go on and still open streams; below 13 connections are taken again. Off (the default): no reset before
/// the limit itself.
#[test]
fn host_mark_resets_new_connections() {
    for on in [true, false] {
        let (mut w, port, _rx) = rig(fd_cfg(), 16, 1);
        let mask = if on { MARK_HOST } else { 0 };
        w.fdg.set_marks(mask);
        w.fd_setup();
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let up = u.local_addr().unwrap().port();
        let (mut c, _) = client(&mut w, port);
        udp_streams(&mut w, &mut c, 1, 11, up);
        let (_c2, _) = client(&mut w, port);
        assert_eq!((fds(&w), w.fdg.marks()), (13, 0));
        udp_streams(&mut w, &mut c, 12, 1, up);
        assert_eq!((fds(&w), w.fdg.marks()), (14, mask));
        if !on {
            let (_c3, _) = client(&mut w, port);
            assert_eq!((fds(&w), w.stats.refuse_mark_conns.get()), (15, 0));
            end(w);
            continue;
        }
        let mut n = TcpStream::connect(("127.0.0.1", port)).unwrap();
        until(&mut w, "reset at the host mark", |w| w.stats.refuse_mark_conns.get() == 1);
        n.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(n.read(&mut [0u8; 8]).expect_err("a reset").kind(), std::io::ErrorKind::ConnectionReset);
        // open connections go on: two more streams (16 = the limit)
        udp_streams(&mut w, &mut c, 13, 2, up);
        assert_eq!((fds(&w), w.stats.accepted.get()), (16, 2));
        // 5 streams close: 11 fds, the count handed out falls below 13: connections are taken again
        for sid in 1..=5 {
            c.write_all(&wisp(0x04, sid, &[0x02])).unwrap();
        }
        until(&mut w, "5 closed", |w| live_streams(w) == 9);
        assert_eq!((fds(&w), w.fdg.marks()), (11, 0));
        let (_c3, _) = client(&mut w, port);
        assert_eq!((fds(&w), w.stats.refuse_mark_conns.get(), w.stats.accepted.get()), (12, 1, 3));
        end(w);
    }
}
