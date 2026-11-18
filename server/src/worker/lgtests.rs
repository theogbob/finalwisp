//! 60.78 bundle B3 worker tests for the lingering close (worker/linger.rs): a client that still sends when the server
//! closes gets the whole tail and a clean EOF, never a reset; the bounds (bytes, time, a slow trickle) close an abusive
//! sender; refusals of a request that came alone and clean client closes do not linger.
use super::super::linger::{LINGER_BYTES, LINGER_PLAIN};
use super::super::*;
use super::fd::{client, fd_cfg, fds, peer_port, rig};
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::TcpStream;
use std::os::fd::FromRawFd as _;

const UPGRADE: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const PLAIN_GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

/// one loop turn as Worker::run, the linger tick included (fd::pump has no linger_check)
fn turn(w: &mut Worker, ms: i32) {
    super::fd::pump(w, ms);
    if !w.lingering.is_empty() {
        w.next_linger = Instant::now(); // (the tick: every turn here)
        w.linger_check();
        w.reap_dead();
    }
}

fn end(w: Worker) {
    for fd in [w.ep, w.lfd, w.inbox.efd, w.spare] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

fn live_clients(w: &Worker) -> usize {
    w.clients.slots.iter().filter(|s| s.1.as_ref().is_some_and(|c| !c.dead)).count()
}

/// a client socket with a small receive buffer (set before connect: the window stays small), upgraded; its slot
fn small_client(w: &mut Worker, port: u16, rcvbuf: i32) -> (TcpStream, u32) {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let sz = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    assert_eq!(unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, (&rcvbuf as *const i32).cast(), sz) }, 0);
    let mut c = unsafe { TcpStream::from_raw_fd(fd) };
    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) },
        sin_zero: [0; 8],
    };
    assert_eq!(unsafe { libc::connect(fd, (&sa as *const libc::sockaddr_in).cast(), std::mem::size_of_val(&sa) as u32) }, 0);
    c.write_all(UPGRADE).unwrap();
    let before = w.stats.accepted.get();
    let end_at = Instant::now() + Duration::from_secs(10);
    while w.stats.accepted.get() == before {
        turn(w, 5);
        assert!(Instant::now() < end_at, "not accepted");
    }
    let me = c.local_addr().unwrap().port();
    let ci = (0..w.clients.slots.len() as u32)
        .find(|&i| w.clients.slots[i as usize].1.as_ref().is_some_and(|x| !x.dead && peer_port(x.fd) == me))
        .unwrap();
    while w.clients.at(ci).state != CState::Open {
        turn(w, 5);
        assert!(Instant::now() < end_at, "not upgraded");
    }
    c.set_nonblocking(true).unwrap();
    (c, ci)
}

/// a masked (zero key) frame
fn frame(op: u8, p: &[u8]) -> Vec<u8> {
    assert!(p.len() < 126);
    let mut f = vec![0x80 | op, 0x80 | p.len() as u8, 0, 0, 0, 0];
    f.extend_from_slice(p);
    f
}

/// write all of `b` (non-blocking), turning the worker meanwhile
fn send(w: &mut Worker, c: &mut TcpStream, mut b: &[u8]) {
    let end_at = Instant::now() + Duration::from_secs(20);
    while !b.is_empty() {
        match c.write(b) {
            Ok(n) => b = &b[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock => turn(w, 1),
            Err(e) => panic!("write: {e}"),
        }
        assert!(Instant::now() < end_at, "write stuck");
    }
}

/// read until EOF (Ok) or an error (Err), turning the worker meanwhile; `got` collects the bytes
fn read_to_end(w: &mut Worker, c: &mut TcpStream, got: &mut Vec<u8>) -> std::io::Result<()> {
    let mut b = [0u8; 65536];
    let end_at = Instant::now() + Duration::from_secs(20);
    loop {
        match c.read(&mut b) {
            Ok(0) => return Ok(()),
            Ok(n) => got.extend_from_slice(&b[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => turn(w, 1),
            Err(e) => return Err(e),
        }
        assert!(Instant::now() < end_at, "no EOF in 20 s ({} bytes)", got.len());
    }
}

/// the server frames in `got` (unmasked): (opcode, payload)
fn frames(got: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut v = Vec::new();
    let mut i = 0;
    while i + 2 <= got.len() {
        let (mut len, mut h) = ((got[i + 1] & 0x7f) as usize, 2);
        if len == 126 {
            len = u16::from_be_bytes([got[i + 2], got[i + 3]]) as usize;
            h = 4;
        } else if len == 127 {
            len = u64::from_be_bytes(got[i + 2..i + 10].try_into().unwrap()) as usize;
            h = 10;
        }
        assert!(i + h + len <= got.len(), "a cut frame at {i} of {}", got.len());
        v.push((got[i] & 0x0f, got[i + h..i + h + len].to_vec()));
        i += h + len;
    }
    assert_eq!(i, got.len());
    v
}

/// The client is still sending when the server closes (a bad frame behind 4000 pings, junk behind it) and reads late,
/// through a small window: every pong arrives, then the Close (1002), then a clean EOF, no reset. The server shuts its
/// direction down, discards the junk and closes at the client's EOF (not at a bound). Without the linger close() finds
/// the junk unread and resets: the queued pongs are lost and the read fails (mutation check of the 60.78 report).
#[test]
fn a_client_still_sending_at_the_close_gets_its_whole_tail() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut c, ci) = small_client(&mut w, port, 8192);
    const N: usize = 4000;
    let ping: Vec<u8> = frame(0x9, &[0x5a; 120]);
    let mut out = Vec::with_capacity(N * ping.len() + (20 << 10));
    for _ in 0..N {
        out.extend_from_slice(&ping);
    }
    out.extend_from_slice(&[0x82, 0x05, 1, 2, 3, 4, 5]); // unmasked: the server fails the connection (1002)
    out.extend(std::iter::repeat_n(0x33u8, 16 << 10)); // what the client still sends (one unread byte is enough for the RST)
    send(&mut w, &mut c, &out);
    let end_at = Instant::now() + Duration::from_secs(10);
    while w.clients.slots[ci as usize].1.as_ref().is_some_and(|x| !x.closing && !x.dead) {
        turn(&mut w, 1);
        assert!(Instant::now() < end_at, "the bad frame was not read");
    }
    let mut got = Vec::new();
    read_to_end(&mut w, &mut c, &mut got).expect("a clean EOF, not a reset");
    let head = got.windows(4).position(|x| x == b"\r\n\r\n").expect("the 101 answer") + 4;
    let f = frames(&got[head..]);
    let pongs = f.iter().filter(|(op, p)| *op == 0xa && p.as_slice() == [0x5a; 120]).count();
    assert_eq!((f[0].0, pongs, f.len()), (0x2, N, N + 2), "the CONTINUE, every pong, then one more frame");
    assert_eq!(f[N + 1], (0x8, 1002u16.to_be_bytes().to_vec()), "the Close last");
    assert!(w.clients.slots[ci as usize].1.as_ref().is_some_and(|x| x.lingering && !x.dead), "waits for the client's EOF");
    drop(c);
    let end_at = Instant::now() + Duration::from_secs(10);
    while live_clients(&w) > 0 {
        turn(&mut w, 5);
        assert!(Instant::now() < end_at, "not closed at the client's EOF");
    }
    assert!(w.lingering.is_empty());
    assert_eq!((w.stats.linger_capped.get(), fds(&w)), (0, 0), "closed at EOF, not at a bound");
    end(w);
}

/// A client that sends without end after the server's close is closed once LINGER_BYTES are discarded (counted)
#[test]
fn an_endless_sender_is_closed_at_the_byte_bound() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut c, ci) = client(&mut w, port);
    send(&mut w, &mut c, &[0x82, 0x05, 1, 2, 3, 4, 5]);
    let junk = [0x33u8; 65536];
    let (t0, mut sent) = (Instant::now(), 0u64);
    while live_clients(&w) > 0 {
        match c.write(&junk) {
            Ok(n) => sent += n as u64,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(_) => break, // (the reset of the close at the bound)
        }
        turn(&mut w, 1);
        assert!(sent < 64 * LINGER_BYTES, "still open after {sent} bytes");
    }
    assert!(t0.elapsed() < LINGER_PLAIN, "closed by the byte bound, not the time bound ({:?})", t0.elapsed());
    assert!(sent >= LINGER_BYTES, "{sent}");
    assert_eq!((w.stats.linger_capped.get(), fds(&w)), (1, 0));
    let _ = ci;
    end(w);
}

/// The slowloris shape: an HTTP request with more behind it (so the refusal lingers), then one byte every 4 s (far
/// under the byte bound): closed at LINGER_PLAIN from the start of the linger, counted. (Real time: about 5 s.)
#[test]
fn a_slow_trickle_is_closed_at_the_time_bound() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.write_all(&[PLAIN_GET, b"x"].concat()).unwrap();
    c.set_nonblocking(true).unwrap();
    let end_at = Instant::now() + Duration::from_secs(10);
    while w.lingering.is_empty() {
        turn(&mut w, 5);
        assert!(Instant::now() < end_at, "no linger");
    }
    let (t0, until) = (Instant::now(), w.lingering[0].until);
    let mut next = t0 + Duration::from_secs(4);
    while live_clients(&w) > 0 {
        if Instant::now() >= next {
            let _ = c.write(b"y");
            next += Duration::from_secs(4);
        }
        turn(&mut w, 20);
        assert!(t0.elapsed() < LINGER_PLAIN + Duration::from_secs(2), "still open");
    }
    assert!(Instant::now() >= until, "closed before the bound");
    assert!(until.duration_since(t0) + Duration::from_millis(500) >= LINGER_PLAIN, "the bound is LINGER_PLAIN from the start");
    assert_eq!((w.stats.linger_capped.get(), fds(&w)), (1, 0));
    let mut got = Vec::new();
    let _ = read_to_end(&mut w, &mut c, &mut got);
    assert!(got.starts_with(b"HTTP/1.1 200 OK"), "the answer came first");
    end(w);
}

/// Refusals of a request that came alone close at once (no linger, the fd back at once: a flood holds nothing); with
/// more behind each request they linger, keep their fds counted, and all close at the bound.
#[test]
fn refusals_linger_only_with_unread_input() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    const N: usize = 40;
    let mut cs: Vec<TcpStream> = (0..N).map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap()).collect();
    for c in &mut cs {
        c.write_all(PLAIN_GET).unwrap();
    }
    let end_at = Instant::now() + Duration::from_secs(10);
    while w.stats.accepted.get() < N as u64 || live_clients(&w) > 0 {
        turn(&mut w, 5);
        assert!(w.lingering.is_empty(), "a request that came alone lingered");
        assert!(Instant::now() < end_at, "refusals not closed");
    }
    assert_eq!(fds(&w), 0);
    for c in &mut cs {
        let mut got = Vec::new();
        c.read_to_end(&mut got).expect("the answer and a clean EOF");
        assert!(got.starts_with(b"HTTP/1.1 200 OK"));
    }
    // more behind each request: they linger, each holding its fd
    let mut cs: Vec<TcpStream> = (0..N).map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap()).collect();
    for c in &mut cs {
        c.write_all(&[PLAIN_GET, b"junk"].concat()).unwrap();
    }
    let end_at = Instant::now() + Duration::from_secs(10);
    while w.lingering.len() < N {
        turn(&mut w, 5);
        assert!(Instant::now() < end_at, "{} of {N} lingering", w.lingering.len());
    }
    assert_eq!((live_clients(&w), fds(&w)), (N, N as u64), "a lingering client keeps its fd counted");
    let now = Instant::now();
    for e in &mut w.lingering {
        e.until = now; // (the bound, without the wait: the trickle test waits for it)
    }
    turn(&mut w, 1);
    assert_eq!((live_clients(&w), fds(&w), w.stats.linger_capped.get()), (0, 0, N as u64));
    end(w);
}

/// A client that closes itself (its WebSocket Close, then it waits for ours and the FIN, as wbench connchurn does) does
/// not linger: its close is what it was before
#[test]
fn a_clean_client_close_does_not_linger() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    for _ in 0..20 {
        let (mut c, ci) = client(&mut w, port);
        send(&mut w, &mut c, &frame(0x8, &1000u16.to_be_bytes()));
        let end_at = Instant::now() + Duration::from_secs(10);
        while w.clients.slots[ci as usize].1.as_ref().is_some_and(|x| !x.dead) {
            turn(&mut w, 1);
            assert!(w.lingering.is_empty(), "a clean client close lingered");
            assert!(Instant::now() < end_at);
        }
        let mut got = Vec::new();
        read_to_end(&mut w, &mut c, &mut got).expect("a clean EOF");
        assert!(got.ends_with(&[0x88, 0x02, 0x03, 0xe8]), "the Close echoed");
    }
    assert_eq!((w.stats.linger_capped.get(), fds(&w)), (0, 0));
    end(w);
}

/// Shutdown: a close it starts (its 1001) does not wait for the client's EOF (main exits once no connection is left,
/// drain.py: within 1 s); at the close phase (main exits CLOSE_GRACE = 2 s after it starts) a linger already running
/// is cut to LINGER_STOP
#[test]
fn shutdown_does_not_wait_for_the_clients_eof() {
    use super::super::linger::LINGER_STOP;
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut a, ca) = client(&mut w, port);
    let (mut b, cb) = client(&mut w, port);
    send(&mut w, &mut a, &[0x82, 0x05, 1, 2, 3, 4, 5]); // a closes (1002) with more behind it: it lingers
    a.write_all(b"junk").unwrap();
    let end_at = Instant::now() + Duration::from_secs(10);
    while w.lingering.is_empty() {
        turn(&mut w, 1);
        assert!(Instant::now() < end_at, "no linger");
    }
    // the drain phase: b (idle) gets its 1001 and closes at once, its FIN after the Close frame
    w.stop_seen = net::STOP_DRAIN;
    w.shutdown_step(net::STOP_DRAIN);
    turn(&mut w, 1);
    assert!(w.clients.slots[cb as usize].1.as_ref().is_none_or(|x| x.dead), "b closed in the turn of its 1001");
    let mut got = Vec::new();
    read_to_end(&mut w, &mut b, &mut got).expect("b: a clean EOF");
    assert!(got.ends_with(&[0x88, 0x02, 0x03, 0xe9]), "b: the 1001 last");
    assert_eq!(w.lingering.len(), 1, "a still lingers");
    // the close phase: a's deadline is cut
    let t0 = Instant::now();
    w.stop_seen = net::STOP_CLOSE;
    w.shutdown_step(net::STOP_CLOSE);
    let cut = Instant::now() + LINGER_STOP;
    assert!(w.lingering.iter().all(|e| e.until <= cut), "cut to LINGER_STOP");
    while live_clients(&w) > 0 {
        let _ = a.write(b"z"); // (it keeps sending, never closes)
        turn(&mut w, 20);
        assert!(t0.elapsed() < LINGER_STOP + Duration::from_secs(1), "still open");
    }
    assert_eq!((w.stats.linger_capped.get(), fds(&w)), (1, 0));
    let _ = ca;
    end(w);
}

/// A plain linger whose only reason is input left in rbuf (rpos < rlen): pings, the client's Close and junk in one
/// write (one short read: `readable` is false; the Close ends the parsing, the junk stays unparsed), the socket quiet
/// after it. The client reads late: every pong, the Close echo, then a clean EOF; the server closes at the client's EOF.
/// Its buffers are released at the start of the linger. (Mutation of the 60.78 report: without `rpos < rlen` in
/// flush_dirty's condition this close resets.)
#[test]
fn input_left_in_rbuf_alone_makes_the_close_linger() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut c, ci) = small_client(&mut w, port, 8192);
    const N: usize = 40;
    let mut out = Vec::new();
    for _ in 0..N {
        out.extend_from_slice(&frame(0x9, &[0x5a; 120]));
    }
    out.extend_from_slice(&frame(0x8, &1000u16.to_be_bytes()));
    out.extend_from_slice(&[0x33; 200]); // after the Close: never parsed
    send(&mut w, &mut c, &out);
    let end_at = Instant::now() + Duration::from_secs(10);
    while w.lingering.is_empty() {
        turn(&mut w, 1);
        assert!(w.clients.slots[ci as usize].1.as_ref().is_some_and(|x| !x.dead), "closed without a linger");
        assert!(Instant::now() < end_at, "no linger");
    }
    let x = w.clients.at(ci);
    assert!(!x.readable && !x.ktls_on, "the only reason is the unparsed input");
    assert_eq!((x.rbuf.capacity(), x.obuf.capacity(), x.frag.is_none()), (0, 0, true), "buffers released");
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    let end_at = Instant::now() + Duration::from_secs(10);
    let head = loop {
        // (read the 101, the pongs and the Close; then the client closes: its EOF ends the linger)
        match c.read(&mut b) {
            Ok(0) => panic!("EOF before the client closed"),
            Ok(n) => got.extend_from_slice(&b[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => turn(&mut w, 1),
            Err(e) => panic!("a reset, not the tail: {e}"),
        }
        if let Some(h) = got.windows(4).position(|x| x == b"\r\n\r\n") {
            if got.ends_with(&[0x88, 0x02, 0x03, 0xe8]) {
                break h + 4;
            }
        }
        assert!(Instant::now() < end_at, "no Close ({} bytes)", got.len());
    };
    let f = frames(&got[head..]);
    let pongs = f.iter().filter(|(op, p)| *op == 0xa && p.as_slice() == [0x5a; 120]).count();
    assert_eq!((f[0].0, pongs, f.len()), (0x2, N, N + 2), "the CONTINUE, every pong, the Close");
    c.shutdown(std::net::Shutdown::Write).unwrap(); // the client's EOF
    let mut rest = Vec::new();
    read_to_end(&mut w, &mut c, &mut rest).expect("a clean EOF after the Close, not a reset");
    assert!(rest.is_empty());
    let end_at = Instant::now() + Duration::from_secs(10);
    while live_clients(&w) > 0 {
        turn(&mut w, 5);
        assert!(Instant::now() < end_at, "not closed at the client's EOF");
    }
    assert_eq!((w.stats.linger_capped.get(), fds(&w)), (0, 0), "closed at EOF, not at a bound");
    end(w);
}

/// A server-started close while the client is in the middle of a frame (here the 1001 of shutdown's drain phase, the
/// tick's stop_seen left at 0 so that the close lingers as any other): the frame in progress goes with the buffers, so
/// the holder shed at level 2+ (frame_held at a 16 KiB rbuf_max) does not reset the lingering client (review: `need`
/// left from the frame made it a "holder")
#[test]
fn a_close_mid_frame_is_no_holder_while_lingering() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut c, ci) = client(&mut w, port);
    let mut f = vec![0x82, 0x80 | 126, (40000u16 >> 8) as u8, 40000u16 as u8, 0, 0, 0, 0]; // 40000-byte frame, zero key
    f.extend_from_slice(&[0u8; 1000]); // its first 1000 bytes
    send(&mut w, &mut c, &f);
    let end_at = Instant::now() + Duration::from_secs(10);
    while w.clients.at(ci).need < 40000 {
        turn(&mut w, 1);
        assert!(Instant::now() < end_at, "the frame was not started");
    }
    // an ordinary whole frame under HOLD_FLOOR is no holder (70.02) as long as rbuf shows its header; with rbuf released
    // and `need` kept it would count against the 16 KiB alone
    assert!(!w.clients.at(ci).frame_held(16 << 10), "mid-frame, before the close: no holder");
    w.shutdown_step(net::STOP_DRAIN); // (an idle WebSocket client: 1001, a server-started close)
    while w.lingering.is_empty() {
        turn(&mut w, 1);
        assert!(Instant::now() < end_at, "no linger");
    }
    let x = w.clients.at(ci);
    assert!(!x.frame_held(16 << 10), "no holder while lingering");
    assert_eq!((x.rbuf.capacity(), x.obuf.capacity(), x.need), (0, 0, 0), "buffers and the frame in progress gone");
    end(w);
}
