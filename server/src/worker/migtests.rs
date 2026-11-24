//! 60.64 worker tests for a connection that moves (worker/migrate.rs). The proof is forced moves: a connection that
//! leaves and comes back after every loop turn (new slots, new generations, every list rebuilt) must carry every byte
//! in order, and the worker it left must hold no trace of it. (reap_dead compares the fd count with a walk of the
//! slabs after every turn.)
use super::super::*;
use super::fd::{client, client_with, connect, drain, fd_cfg, fds, pump, rig, until, wisp};
use crate::fdgate::{FdGate, MARK_SHARE};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};

fn pat(sid: u32, i: usize) -> u8 {
    (sid as usize * 37 + i * 7 + (i >> 8)) as u8
}

/// the Wisp packets in what the server sent (complete frames from `pos` on; the HTTP answer skipped)
fn packets(got: &[u8], pos: &mut usize, mut f: impl FnMut(u8, u32, &[u8])) {
    if *pos == 0 {
        match got.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(p) => *pos = p + 4,
            None => return,
        }
    }
    while *pos + 2 <= got.len() {
        let (hl, len) = match got[*pos + 1] & 0x7f {
            126 if *pos + 4 <= got.len() => (4, u16::from_be_bytes([got[*pos + 2], got[*pos + 3]]) as usize),
            127 if *pos + 10 <= got.len() => (10, u64::from_be_bytes(got[*pos + 2..*pos + 10].try_into().unwrap()) as usize),
            126 | 127 => return,
            n => (2, n as usize),
        };
        if *pos + hl + len > got.len() {
            return;
        }
        let p = &got[*pos + hl..*pos + hl + len];
        if got[*pos] & 0x0f == 2 && len >= 5 {
            f(p[0], u32::from_le_bytes(p[1..5].try_into().unwrap()), &p[5..]);
        }
        *pos += hl + len;
    }
}

/// the one live client of `w`
fn only(w: &Worker) -> u32 {
    let live: Vec<usize> = (0..w.clients.slots.len()).filter(|&i| w.clients.slots[i].1.as_ref().is_some_and(|c| !c.dead)).collect();
    assert_eq!(live.len(), 1, "one live client");
    live[0] as u32
}

/// one loop turn, then the connection leaves and comes back (if it is at rest); returns 1 if it did
fn step(w: &mut Worker) -> u32 {
    pump(w, 1);
    w.mig_force(1).is_some() as u32
}

fn write_all(w: &mut Worker, s: &mut TcpStream, mut b: &[u8], moves: &mut u32) {
    let end = Instant::now() + Duration::from_secs(20);
    while !b.is_empty() {
        match s.write(b) {
            Ok(n) => b = &b[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("write: {e}"),
        }
        *moves += step(w);
        assert!(Instant::now() < end, "write stuck");
    }
}

fn end(w: Worker) {
    for fd in [w.ep, w.lfd, w.inbox.efd, w.spare] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w); // (no frees while mem::tests::heap_counter_moves measures the heap counter)
}

/// the worker holds nothing of any connection
fn empty(w: &Worker) {
    assert_eq!(w.stats.fds.get(), w.fds_held());
    assert_eq!((w.stats.fds.get(), w.inbox.load.load(Relaxed)), (0, 0), "fds, load");
    assert_eq!((w.pend_total, w.pend_clients, w.starve_pool), (0, 0, credit::STARVE_POOL), "upload backlog, starve pool");
    assert!(w.connecting.is_empty() && w.lingering.is_empty() && w.starved.is_empty() && w.lwait.is_empty());
    assert_eq!(w.targets.slots.len() - w.targets.free.len(), 0, "target slots");
    assert_eq!(w.clients.slots.len() - w.clients.free.len(), 0, "client slots");
    assert!(w.peers_of.iter().all(Option::is_none) && w.connlog.iter().all(Option::is_none) && w.streamlog.iter().all(Option::is_none));
    assert!(w.sfds.iter().all(|s| *s == [0, 0]));
}

/// Upload, download against a client that does not read (parked streams, the bulk lane, the splice pipe), a connect
/// in flight, a UDP stream, a target's EOF and a client's CLOSE, with a move after every loop turn: every byte
/// arrives once and in order, and at the end the worker holds nothing.
fn moves_every_turn(variant: u8) {
    const N: u32 = 4;
    const UP: usize = 100 * 16384;
    const DOWN: usize = 6 << 20;
    let mut cfg = fd_cfg();
    cfg.connect_timeout = Duration::from_secs(30);
    // the worker listens on an address of its own in 127/8 (as a_connection_moves_to_another_worker_with_its_counts):
    // a connection that another test sends to a port of 127.0.0.1 the kernel gave out before (a freed port it probes,
    // or the next SYN of a connect that waited on a full accept queue that has closed since) cannot reach it. Seen
    // once as a second live client in only() (CI run 602, credit_v2_pace).
    cfg.addr = "127.73.74.2:0".parse().unwrap();
    match variant {
        1 => (cfg.credit_v2, cfg.credit_pace, cfg.adaptive_splice) = (true, true, true),
        2 => {
            (cfg.splice, cfg.prio, cfg.log_conns, cfg.log_streams, cfg.want_peer) = (false, false, true, true, true);
            cfg.upload_rate = Some((1 << 30, 1 << 30));
        }
        _ => {}
    }
    let (mut w, port, _rx) = rig(cfg, u32::MAX, 4);
    let (mut c, _) = client(&mut w, port);
    let mut moves = 0;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let mut targets = Vec::new();
    for sid in 1..=N {
        write_all(&mut w, &mut c, &connect(sid, false, lp), &mut moves);
        let end = Instant::now() + Duration::from_secs(5);
        l.set_nonblocking(true).unwrap();
        let t = loop {
            match l.accept() {
                Ok((t, _)) => break t,
                Err(_) => moves += step(&mut w),
            }
            assert!(Instant::now() < end, "target {sid} not connected");
        };
        t.set_nonblocking(true).unwrap();
        targets.push(t);
    }
    // ---- upload: interleaved 16 KiB DATA frames, within the first credit
    let mut sent = vec![0usize; N as usize];
    let mut at_target = vec![Vec::new(); N as usize];
    let mut buf = vec![0u8; 1 << 16];
    for _ in 0..UP / 16384 {
        for sid in 1..=N {
            let k = sid as usize - 1;
            let body: Vec<u8> = (sent[k]..sent[k] + 16384).map(|i| pat(sid, i)).collect();
            sent[k] += 16384;
            write_all(&mut w, &mut c, &wisp(0x02, sid, &body), &mut moves);
            while let Ok(n) = targets[k].read(&mut buf) {
                if n == 0 {
                    break;
                }
                at_target[k].extend_from_slice(&buf[..n]);
            }
        }
    }
    let end_at = Instant::now() + Duration::from_secs(20);
    while at_target.iter().any(|t| t.len() < UP) {
        for k in 0..N as usize {
            while let Ok(n) = targets[k].read(&mut buf) {
                if n == 0 {
                    break;
                }
                at_target[k].extend_from_slice(&buf[..n]);
            }
        }
        moves += step(&mut w);
        assert!(Instant::now() < end_at, "upload stuck: {:?}", at_target.iter().map(Vec::len).collect::<Vec<_>>());
    }
    for sid in 1..=N {
        let t = &at_target[sid as usize - 1];
        assert_eq!(t.len(), UP, "stream {sid}: upload length");
        assert!(t.iter().enumerate().all(|(i, &b)| b == pat(sid, i)), "stream {sid}: upload bytes or order");
    }
    // ---- download: the targets write while the client reads nothing for a while (streams park), then it reads
    let mut wrote = vec![0usize; N as usize];
    let (mut got, mut pos) = (Vec::new(), 0usize);
    let mut down = vec![0usize; N as usize];
    let mut bad = None;
    let mut turns = 0u32;
    let end_at = Instant::now() + Duration::from_secs(60);
    let mut parked_seen = false;
    while down.iter().any(|&d| d < DOWN) {
        for sid in 1..=N {
            let k = sid as usize - 1;
            if wrote[k] < DOWN {
                let chunk: Vec<u8> = (wrote[k]..(wrote[k] + 65536).min(DOWN)).map(|i| pat(sid + 100, i)).collect();
                if let Ok(n) = targets[k].write(&chunk) {
                    wrote[k] += n;
                }
            }
        }
        moves += step(&mut w);
        turns += 1;
        let ci = only(&w);
        parked_seen |= !w.clients.at(ci).blocked.is_empty() || !w.clients.at(ci).blocked_bulk.is_empty();
        if turns > 300 {
            drain(&mut c, &mut got);
            packets(&got, &mut pos, |ty, sid, body| {
                if ty == 0x02 && (1..=N).contains(&sid) {
                    let k = sid as usize - 1;
                    if bad.is_none() && !body.iter().enumerate().all(|(i, &b)| b == pat(sid + 100, down[k] + i)) {
                        bad = Some((sid, down[k]));
                    }
                    down[k] += body.len();
                }
            });
            if pos > 1 << 20 {
                got.drain(..pos - 4); // (keeps 4 bytes in front: packets skips a header only at position 0)
                pos = 4;
            }
        }
        assert!(Instant::now() < end_at, "download stuck: {down:?} of {DOWN}, wrote {wrote:?}");
    }
    assert_eq!(bad, None, "download bytes or order (stream, offset)");
    assert_eq!(down, vec![DOWN; N as usize]);
    assert!(parked_seen, "the test did not park a stream: it proves nothing about the parked lists");
    // ---- a connect in flight (a listener whose accept queue is full drops the SYN) moves too, and its CLOSE ends it
    let full = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    (sa.sin_family, sa.sin_addr.s_addr) = (libc::AF_INET as u16, u32::from_be_bytes([127, 0, 0, 1]).to_be());
    let mut len = std::mem::size_of_val(&sa) as u32;
    unsafe {
        assert_eq!(libc::bind(full, &sa as *const _ as *const libc::sockaddr, len), 0);
        assert_eq!(libc::listen(full, 0), 0);
        assert_eq!(libc::getsockname(full, &mut sa as *mut _ as *mut libc::sockaddr, &mut len), 0);
    }
    let fp = u16::from_be(sa.sin_port);
    let _fillers: Vec<TcpStream> =
        (0..3).filter_map(|_| TcpStream::connect_timeout(&([127, 0, 0, 1], fp).into(), Duration::from_millis(200)).ok()).collect();
    write_all(&mut w, &mut c, &connect(50, false, fp), &mut moves);
    let before = moves;
    for _ in 0..20 {
        moves += step(&mut w);
    }
    let connecting = w.connecting.len();
    if connecting == 1 {
        assert!(moves > before, "a connection with a connect in flight moves");
        let (ti, tg) = w.connecting[0];
        assert_eq!(w.targets.get(ti, tg).map(|t| t.cidx), Some(0), "listed again under its new slot");
    }
    write_all(&mut w, &mut c, &wisp(0x04, 50, &[0x02]), &mut moves);
    until(&mut w, "the connecting stream closed", |w| w.connecting.is_empty());
    // closed by its CLOSE, not by the connect timeout (30 s, as long as until waits)
    assert_eq!(w.stats.connect_timeout.get(), 0);
    unsafe { libc::close(full) };
    // ---- a UDP stream: one datagram there and back
    let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_nonblocking(true).unwrap();
    write_all(&mut w, &mut c, &connect(60, true, u.local_addr().unwrap().port()), &mut moves);
    write_all(&mut w, &mut c, &wisp(0x02, 60, b"ping"), &mut moves);
    let mut d = [0u8; 16];
    let end_at = Instant::now() + Duration::from_secs(5);
    let from = loop {
        if let Ok((n, from)) = u.recv_from(&mut d) {
            assert_eq!(&d[..n], b"ping");
            break from;
        }
        moves += step(&mut w);
        assert!(Instant::now() < end_at, "datagram not delivered");
    };
    u.send_to(b"pong", from).unwrap();
    // ---- a target's EOF closes its stream (0x02), the others stay
    drop(targets.remove(0));
    let (mut pong, mut closed) = (false, false);
    let end_at = Instant::now() + Duration::from_secs(5);
    while !(pong && closed) {
        moves += step(&mut w);
        drain(&mut c, &mut got);
        packets(&got, &mut pos, |ty, sid, body| {
            pong |= ty == 0x02 && sid == 60 && body == b"pong";
            closed |= ty == 0x04 && sid == 1;
        });
        assert!(Instant::now() < end_at, "pong {pong}, stream 1 closed {closed}");
    }
    let ci = only(&w);
    assert_eq!(w.clients.at(ci).streams.len(), N as usize - 1 + 1, "three TCP streams and the UDP one");
    assert!(moves > 200, "{moves} moves: the connection was rarely at rest");
    assert_eq!(w.stats.moved_conns.get(), moves as u64);
    assert_eq!(w.stats.moved_reset.get(), 0);
    // ---- the client goes: nothing is left
    drop(c);
    until(&mut w, "the client is gone", |w| w.inbox.load.load(Relaxed) == 0);
    pump(&mut w, 1);
    empty(&w);
    end(w);
}

#[test]
fn a_connection_that_moves_every_turn_loses_nothing() {
    moves_every_turn(0);
}
#[test]
fn a_connection_that_moves_every_turn_loses_nothing_credit_v2_pace() {
    moves_every_turn(1);
}
#[test]
fn a_connection_that_moves_every_turn_loses_nothing_copy_path_logs_meter() {
    moves_every_turn(2);
}

/// Two workers: the connection goes to the other one with its fd units, its load, its per-address key and its
/// published stream fds (--conn-share); the worker it left holds nothing and ignores what still names the old slots;
/// the stream goes on at the new worker; the close releases the key there.
#[test]
fn a_connection_moves_to_another_worker_with_its_counts() {
    const IP: &str = "203.0.113.9";
    let mut cfg = fd_cfg();
    (cfg.threads, cfg.want_peer, cfg.proxy_tcp) = (2, true, true);
    // (this test needs the workers' listeners; on an address of its own in 127/8 a connection that another test sends
    // to a port of 127.0.0.1 it freed cannot reach them: see no_accepts)
    cfg.addr = "127.73.74.1:0".parse().unwrap();
    cfg.proxy_from = Box::new([crate::policy::Cidr::parse("127.0.0.0/8").unwrap()]);
    cfg.clientip = Some(Box::new(clientip::ClientIp {
        trusted: Vec::new().into(),
        header: "x-forwarded-for".into(),
        table: Some(clientip::IpTable::with_rates(None, None, None).with_share(2)),
        max_conns: 0,
    }));
    let cfg = Arc::new(cfg);
    let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
    let (tx, _rx) = mpsc::channel();
    let gate = Arc::new(FdGate::new(u32::MAX, 1));
    gate.set_marks(MARK_SHARE);
    let mut ws: Vec<Worker> = (0..2)
        .map(|i| {
            let mut w = Worker::new(cfg.clone(), tx.clone(), i, peers.clone(), Arc::default()).unwrap();
            w.fdg = gate.clone();
            w.fd_setup();
            w
        })
        .collect();
    let held = |w: &Worker| w.cfg.clientip.as_ref().unwrap().table.as_ref().unwrap().held(clientip::key(IP.parse().unwrap()));
    // each worker binds 127.73.74.1:0 on its own (two ports): the client connects to worker 0's port; the loop below
    // still finds the worker that took it
    let port = unsafe { <TcpListener as std::os::fd::FromRawFd>::from_raw_fd(libc::dup(ws[0].lfd)) }.local_addr().unwrap().port();
    let hello = [format!("PROXY TCP4 {IP} 192.0.2.1 1000 443\r\n").as_bytes(), &b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"[..]].concat();
    let mut c = TcpStream::connect(("127.73.74.1", port)).unwrap();
    c.write_all(&hello).unwrap();
    let end_at = Instant::now() + Duration::from_secs(5);
    let a = loop {
        for w in ws.iter_mut() {
            pump(w, 1);
        }
        if let Some(a) = (0..2).find(|&i| ws[i].clients.slots.iter().any(|s| s.1.as_ref().is_some_and(|c| c.state == CState::Open))) {
            break a;
        }
        assert!(Instant::now() < end_at, "client not upgraded");
    };
    let live = |w: &Worker| w.clients.slots.iter().filter(|s| s.1.as_ref().is_some_and(|c| !c.dead)).count();
    assert_eq!(live(&ws[0]) + live(&ws[1]), 1, "the test's client only");
    let b = 1 - a;
    c.set_nonblocking(true).unwrap();
    // 9 UDP streams (one fd each, published in steps of 8) and one TCP stream
    let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for sid in 1..=9 {
        c.write_all(&connect(sid, true, u.local_addr().unwrap().port())).unwrap();
    }
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    c.write_all(&connect(20, false, l.local_addr().unwrap().port())).unwrap();
    until(&mut ws[a], "10 streams", |w| {
        w.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| t.state == TState::Open).count() == 10
    });
    let mut t = l.accept().unwrap().0;
    t.set_nonblocking(true).unwrap();
    assert_eq!((fds(&ws[a]), fds(&ws[b]), held(&ws[a])), (11, 0, (1, 8)));
    assert_eq!((ws[a].inbox.load.load(Relaxed), ws[b].inbox.load.load(Relaxed)), (1, 0));
    let granted = gate.granted();
    // the fds an epoll set watches (/proc: one `tfd:` line each)
    let watched = |w: &Worker| std::fs::read_to_string(format!("/proc/self/fdinfo/{}", w.ep)).unwrap().matches("tfd:").count();
    let (wa, wb) = (watched(&ws[a]), watched(&ws[b]));
    // the move
    assert!(ws[a].mig_force(1).is_none(), "handed to the other worker, not back to this one");
    assert_eq!((watched(&ws[a]), watched(&ws[b])), (wa - 11, wb), "between the workers no epoll set watches its fds");
    // 60.57 A2 its 11 fds are open and nobody's gauge shows them, but the process count (what the limit, the reserve
    // and the marks act on) still holds them: the units of the allowance are in the value that waits in the inbox
    assert_eq!(in_transit(&peers), 11);
    assert_eq!(gate.granted(), granted);
    assert_eq!(gate.granted() - (ws[0].fd_all() + ws[1].fd_all()), 11);
    // 60.25 C5 the bytes it received at the old worker are published before that worker's load goes down
    assert!(ws[a].rx_total > 0 && ws[a].stats.rx_bytes.get() == ws[a].rx_total);
    assert_eq!((fds(&ws[a]), ws[a].inbox.load.load(Relaxed), ws[b].inbox.load.load(Relaxed)), (0, 0, 1));
    assert_eq!(held(&ws[a]), (1, 0), "between the workers: the key keeps its connection, its stream fds are not published");
    empty_but_load(&ws[a]);
    ws[b].inbox_ready();
    assert_eq!((watched(&ws[a]), watched(&ws[b])), (wa - 11, wb + 11), "one owner: only the new worker watches them");
    assert_eq!((fds(&ws[b]), held(&ws[b])), (11, (1, 10)), "published again at the new worker (10 >= the step of 8)");
    assert_eq!(gate.granted(), granted, "the units of the allowance moved with the fds");
    assert_eq!(gate.granted(), ws[0].fd_all() + ws[1].fd_all());
    // the old worker gets nothing more of it; the stream goes on at the new one, both ways
    c.write_all(&wisp(0x02, 20, b"hello")).unwrap();
    t.write_all(b"world").unwrap();
    let (mut got, mut pos, mut seen, mut up) = (Vec::new(), 0, Vec::new(), [0u8; 5]);
    let end_at = Instant::now() + Duration::from_secs(5);
    let mut n = 0;
    while seen != b"world" || n < 5 {
        pump(&mut ws[a], 0);
        pump(&mut ws[b], 1);
        drain(&mut c, &mut got);
        packets(&got, &mut pos, |ty, sid, body| {
            if ty == 0x02 && sid == 20 {
                seen.extend_from_slice(body);
            }
        });
        if let Ok(k) = t.read(&mut up[n..]) {
            n += k;
        }
        assert!(Instant::now() < end_at, "stream stuck after the move: down {seen:?}, up {n}");
    }
    assert_eq!(&up, b"hello");
    assert_eq!(ws[a].stats.accepted.get() + ws[b].stats.accepted.get(), 1, "a move is not an accept");
    // the close: at the new worker, and the key is released (a connection charged in one worker's slot and released
    // in the other's: the sum is 0)
    drop(c);
    until(&mut ws[b], "closed", |w| w.inbox.load.load(Relaxed) == 0);
    pump(&mut ws[b], 1);
    assert_eq!(ws[b].cfg.clientip.as_ref().unwrap().table.as_ref().unwrap().keys(), 0);
    assert_eq!(ws[b].cfg.clientip.as_ref().unwrap().table.as_ref().unwrap().share_total(), 0);
    for w in ws {
        empty_but_load(&w);
        assert_eq!(w.inbox.load.load(Relaxed), 0);
        end(w);
    }
}

fn empty_but_load(w: &Worker) {
    assert_eq!(w.stats.fds.get(), w.fds_held());
    assert_eq!((w.stats.fds.get(), w.pend_total, w.pend_clients), (0, 0, 0));
    assert_eq!(w.targets.slots.len() - w.targets.free.len(), 0, "target slots");
    assert_eq!(w.clients.slots.len() - w.clients.free.len(), 0, "client slots");
    assert!(w.peers_of.iter().all(Option::is_none) && w.sfds.iter().all(|s| *s == [0, 0]));
}

/// What cannot move now: a handshake, a lookup in flight, a closing connection, a worker at a memory level or
/// shutting down. And the connection is whole afterwards.
#[test]
fn a_connection_that_is_not_at_rest_stays() {
    let mut cfg = fd_cfg();
    cfg.dns_own = true;
    let (mut w, port, rx) = rig(cfg, u32::MAX, 4);
    // before the upgrade: Http
    let mut raw = TcpStream::connect(("127.0.0.1", port)).unwrap();
    until(&mut w, "accepted", |w| w.stats.accepted.get() == 1);
    assert!(w.mig_force(1).is_none());
    raw.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
    until(&mut w, "upgraded", |w| w.clients.at(only(w)).state == CState::Open);
    assert!(w.mig_force(1).is_some(), "open and idle: moves");
    // a name being resolved: the answer is addressed to this worker and the old slot
    let mut b = vec![1];
    b.extend(80u16.to_le_bytes());
    b.extend(b"name.test");
    raw.write_all(&wisp(0x01, 7, &b)).unwrap();
    until(&mut w, "lookup sent", |w| w.dns_inflight == 1);
    assert!(w.mig_force(1).is_none(), "a lookup in flight");
    let req = rx.try_recv().unwrap();
    req.inbox.q.lock().unwrap().push(net::DnsResp { host: req.host, token: req.token, addrs: vec![], nx: true, more: false });
    w.inbox_ready();
    pump(&mut w, 1);
    assert_eq!((w.dns_inflight, w.targets.slots.len() - w.targets.free.len()), (0, 0));
    assert!(w.mig_force(1).is_some(), "the lookup is answered: moves again");
    // a memory level with socket caps
    w.set_level(1);
    assert!(w.mig_force(1).is_none(), "level 1");
    w.set_level(0);
    assert!(w.mig_force(1).is_some());
    // shutdown
    w.inbox.stop.store(net::STOP_DRAIN, Relaxed);
    assert!(w.mig_force(1).is_none(), "draining");
    w.inbox.stop.store(0, Relaxed);
    // closing: the WS Close is queued, the connection waits for its output
    let ci = only(&w);
    w.clients.at(ci).closing = true;
    assert!(w.mig_force(1).is_none(), "closing");
    w.clients.at(ci).closing = false;
    drop(raw);
    until(&mut w, "gone", |w| w.inbox.load.load(Relaxed) == 0);
    pump(&mut w, 1);
    empty(&w);
    end(w);
}

/// --upstream: a stream that is not open yet (its connect to the proxy or the proxy handshake runs) holds a side entry
/// in this worker: its connection stays until the stream is open or gone.
#[test]
fn a_stream_opening_through_an_upstream_proxy_keeps_its_connection() {
    let prox = TcpListener::bind("127.0.0.1:0").unwrap();
    let up = crate::upstream::parse_url(&format!("socks5://127.0.0.1:{}", prox.local_addr().unwrap().port())).unwrap();
    up.addrs.publish(Ok(vec!["127.0.0.1".parse().unwrap()]), 0);
    let mut cfg = fd_cfg();
    (cfg.upstream, cfg.udp) = (Some(Box::new(up)), false);
    let (mut w, port, _rx) = rig(cfg, u32::MAX, 4);
    let (mut c, ci) = client(&mut w, port);
    assert!(w.mig_force(1).is_some(), "no stream: moves");
    c.write_all(&connect(1, false, 9)).unwrap();
    until(&mut w, "the stream is on its way to the proxy", |w| w.targets.slots.iter().any(|s| s.1.is_some()));
    let _held = prox.accept().unwrap(); // the proxy takes the connection and says nothing: the handshake waits
    for _ in 0..20 {
        pump(&mut w, 1);
        assert!(w.mig_force(1).is_none(), "a stream that is opening through the proxy");
    }
    assert!(w.proxy_hs.iter().any(Option::is_some), "its side entry is where it was");
    let _ = ci;
    drop(c);
    until(&mut w, "gone", |w| w.inbox.load.load(Relaxed) == 0);
    pump(&mut w, 1);
    assert!(w.proxy_hs.iter().all(Option::is_none));
    empty(&w);
    end(w);
}

/// The observer's requests: a census, then the move of the second busiest of two busy connections (with a census in
/// the same word); the only busy connection never moves; the censuses of window B on both sides; the way back; a close
/// inside a window (60.74).
#[test]
fn census_move_and_back() {
    use super::super::migrate::*;
    let mut cfg = fd_cfg();
    cfg.threads = 2;
    let cfg = Arc::new(cfg);
    let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
    let (tx, _rx) = mpsc::channel();
    let mut ws: Vec<Worker> = (0..2).map(|i| Worker::new(cfg.clone(), tx.clone(), i, peers.clone(), Arc::default()).unwrap()).collect();
    for w in ws.iter_mut() {
        no_accepts(w);
        w.fd_setup();
    }
    let ask = |w: &mut Worker, bits: u64, to: usize, seq: u32| {
        w.inbox.mig.cmd.fetch_or(request(bits, to, seq), std::sync::atomic::Ordering::AcqRel);
        w.inbox_ready();
        answer(w.inbox.mig.out.load(std::sync::atomic::Ordering::Acquire))
    };
    // three clients on worker 0 (accepted by hand: both listeners share the port), each with an echo stream
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let cl = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cs = Vec::new();
    for _ in 0..3 {
        let mut c = TcpStream::connect(cl.local_addr().unwrap()).unwrap();
        let s = cl.accept().unwrap().0;
        s.set_nonblocking(true).unwrap();
        ws[0].inbox.load.fetch_add(1, Relaxed);
        assert!(ws[0].fd_take(1));
        ws[0].adopt(net::Handoff::bare(std::os::fd::IntoRawFd::into_raw_fd(s)));
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
        c.write_all(&connect(1, false, lp)).unwrap();
        let n = cs.len() + 1;
        until(&mut ws[0], "stream open", |w| {
            w.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| t.state == TState::Open).count() == n
        });
        let t = l.accept().unwrap().0;
        c.set_nonblocking(true).unwrap();
        cs.push((c, t));
    }
    // traffic: client 0 many small frames, client 1 fewer, client 2 none
    let send = |ws: &mut Vec<Worker>, cs: &mut Vec<(TcpStream, TcpStream)>, k: usize, n: usize| {
        let mut sink = [0u8; 4096];
        for _ in 0..n {
            cs[k].0.write_all(&wisp(0x02, 1, &[7u8; 64])).unwrap();
            for w in ws.iter_mut() {
                pump(w, 0);
            }
            cs[k].1.set_nonblocking(true).unwrap();
            while cs[k].1.read(&mut sink).is_ok_and(|n| n > 0) {}
        }
        std::thread::sleep(Duration::from_millis(30)); // (the ACKs)
        for w in ws.iter_mut() {
            pump(w, 0);
        }
    };
    let snap = |w: &Worker, seq: u32| {
        let s = w.inbox.mig.snap.lock().unwrap().take().expect("a census");
        assert_eq!(s.seq, seq);
        s
    };
    // a connection of another test to the workers' port is not taken (no_accepts): the loads stay the test's own
    let port = unsafe { <TcpListener as std::os::fd::FromRawFd>::from_raw_fd(libc::dup(ws[0].lfd)) }.local_addr().unwrap().port();
    let _stray = TcpStream::connect(("127.0.0.1", port)).unwrap();
    for w in ws.iter_mut() {
        pump(w, 20);
    }
    assert_eq!((ws[0].inbox.load.load(Relaxed), ws[1].inbox.load.load(Relaxed)), (3, 0), "no stray connection counted");
    assert_eq!(ask(&mut ws[0], M_CENSUS, 0, 1), (1, R_NOTED, 0));
    let c1 = snap(&ws[0], 1);
    assert_eq!((c1.conns.len(), c1.many, c1.moves), (3, false, 0), "every connection, by its cookie");
    send(&mut ws, &mut cs, 0, 40);
    assert_eq!(ask(&mut ws[0], M_MOVE, 1, 2), (2, R_NONE, 0), "one busy connection: it stays");
    assert_eq!(ws[0].stats.moved_conns.get(), 0);
    send(&mut ws, &mut cs, 1, 10);
    send(&mut ws, &mut cs, 0, 10);
    // the census and the move in one word: the census first, with the connection in it
    assert_eq!(ask(&mut ws[0], M_CENSUS | M_MOVE, 1, 3), (3, R_MOVED, 0), "two busy connections: the second busiest goes");
    let c3 = snap(&ws[0], 3);
    assert_eq!((c3.conns.len(), c3.moves), (3, 0));
    assert!(c3.bytes > c1.bytes, "bytes read and sent since");
    let cookie = ws[0].inbox.mig.moved.load(Relaxed);
    assert_ne!(cookie, 0);
    // (an M_END of the trial before that this worker did not take yet: it is handled before the arrival)
    ws[1].inbox.mig.cmd.fetch_or(M_END, std::sync::atomic::Ordering::AcqRel);
    ws[1].inbox_ready();
    assert_eq!((ws[0].inbox.load.load(Relaxed), ws[1].inbox.load.load(Relaxed)), (2, 1));
    let (ci, cg, before) = ws[1].mig.as_ref().unwrap().trial.expect("the trial is noted where the connection arrived");
    assert!(before > 0);
    let moved_fd = ws[1].clients.get(ci, cg).unwrap().fd;
    assert_eq!(net::cookie(moved_fd), Some(cookie), "the cookie names the socket that moved");
    // client 1 is the one that moved: its frames now reach its target through worker 1
    send(&mut ws, &mut cs, 1, 5);
    assert_eq!(ws[1].clients.get(ci, cg).unwrap().fd, moved_fd);
    // window B: a census on both, traffic, a census on both with the way back
    assert_eq!(ask(&mut ws[0], M_CENSUS, 0, 4).1, R_NOTED);
    assert_eq!(ask(&mut ws[1], M_CENSUS, 0, 4).1, R_NOTED);
    let (s0, d0) = (snap(&ws[0], 4), snap(&ws[1], 4));
    assert_eq!((s0.conns.len(), d0.conns.len(), s0.moves, d0.moves), (2, 1, 1, 1));
    assert_eq!(d0.conns[0].0, cookie);
    send(&mut ws, &mut cs, 0, 20);
    send(&mut ws, &mut cs, 1, 20);
    assert_eq!(ask(&mut ws[0], M_CENSUS, 0, 5).1, R_NOTED);
    assert_eq!(ask(&mut ws[1], M_CENSUS | M_BACK, 0, 5), (5, R_MOVED, 0));
    let (s1, d1) = (snap(&ws[0], 5), snap(&ws[1], 5));
    assert_eq!((s1.moves, d1.moves), (1, 1), "no connection arrived or left inside the window");
    assert!(s1.bytes > s0.bytes && d1.bytes > d0.bytes, "both carried traffic in B");
    assert!(d1.conns[0].1 > d0.conns[0].1 && d1.conns[0].2 != d0.conns[0].2, "its kernel counters");
    ws[0].inbox_ready();
    assert_eq!((ws[0].inbox.load.load(Relaxed), ws[1].inbox.load.load(Relaxed)), (3, 0));
    assert_eq!((ws[0].stats.moved_conns.get(), ws[1].stats.moved_back.get()), (1, 1));
    assert_eq!(ask(&mut ws[1], M_BACK, 0, 7), (7, R_GONE, 0), "no trial left");
    // back on the source, it is the connection under trial there (a keep moves it again)
    let (ci0, cg0, _) = ws[0].mig.as_ref().unwrap().trial.expect("the trial is noted at the source");
    assert_eq!(net::cookie(ws[0].clients.get(ci0, cg0).unwrap().fd), Some(cookie));
    ask(&mut ws[0], M_END, 0, 0);
    assert!(ws[0].mig.as_ref().unwrap().trial.is_none());
    send(&mut ws, &mut cs, 1, 5); // (still whole)
                                  // an M_END the worker did not take yet shares the word with the next trial's request: it is handled first
    assert_eq!(ask(&mut ws[0], M_CENSUS, 0, 8).1, R_NOTED);
    send(&mut ws, &mut cs, 0, 20);
    send(&mut ws, &mut cs, 1, 10);
    assert_eq!(ask(&mut ws[0], M_END | M_CENSUS | M_MOVE, 1, 9), (9, R_MOVED, 0));
    ws[1].inbox_ready();
    assert!(ws[1].mig.as_ref().unwrap().trial.is_some(), "the new trial's state is not cleared by the old M_END");
    assert_eq!((ws[0].inbox.load.load(Relaxed), ws[1].inbox.load.load(Relaxed)), (2, 1));
    // a client that closes inside a window keeps its bytes in its worker's total (Mig::closed_tx)
    assert_eq!(ask(&mut ws[1], M_CENSUS, 0, 10).1, R_NOTED);
    let before_close = snap(&ws[1], 10);
    send(&mut ws, &mut cs, 1, 5);
    let (ci, cg, _) = ws[1].mig.as_ref().unwrap().trial.unwrap();
    let tx = ws[1].clients.get(ci, cg).unwrap().tx_bytes;
    ws[1].close_client(ci, Why::ServerClose);
    assert_eq!(ask(&mut ws[1], M_CENSUS, 0, 11).1, R_NOTED);
    let after_close = snap(&ws[1], 11);
    assert!(after_close.bytes >= before_close.bytes, "a close does not take bytes out of the total");
    assert_eq!(after_close.bytes, ws[1].rx_total + tx, "its bytes are counted as closed");
    assert!(after_close.conns.is_empty());
    drop(cs);
    let end_at = Instant::now() + Duration::from_secs(5);
    while ws[0].inbox.load.load(Relaxed) + ws[1].inbox.load.load(Relaxed) > 0 {
        for w in ws.iter_mut() {
            pump(w, 1);
        }
        assert!(Instant::now() < end_at, "not closed");
    }
    for w in ws.iter_mut() {
        pump(w, 1);
    }
    for w in ws {
        empty(&w);
        end(w);
    }
}

/// These tests hand their clients to the workers themselves (adopt): the workers' own listeners take nothing. Their
/// port is a free port of the host, and a test that runs at the same time can connect to it: a test that frees a
/// port and then connects to it to find it closed (e.g. tests.rs, the connect-deadline case) lands on this listener if
/// the kernel gave the port to it in between, and is accepted and counted in Inbox.load. Seen as one connection more
/// on worker 0 in census_move_and_back, rarely and only with the whole suite running (an accept is the only way the
/// workers' loads can add up to more than the clients the test made). The listener leaves the epoll set, so no
/// connection of another test is accepted here.
fn no_accepts(w: &Worker) {
    unsafe { libc::epoll_ctl(w.ep, libc::EPOLL_CTL_DEL, w.lfd, std::ptr::null_mut()) };
}

type Pair = (Vec<Worker>, Arc<FdGate>, Arc<Vec<Arc<Inbox>>>, TcpStream, TcpListener);

/// Two workers on one fd gate, a client on worker 0 with one TCP stream to a listener (returned, not accepted yet).
fn pair() -> Pair {
    let mut cfg = fd_cfg();
    cfg.threads = 2;
    let cfg = Arc::new(cfg);
    let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
    let (tx, _rx) = mpsc::channel();
    let gate = Arc::new(FdGate::new(u32::MAX, 1));
    let mut ws: Vec<Worker> = (0..2)
        .map(|i| {
            let mut w = Worker::new(cfg.clone(), tx.clone(), i, peers.clone(), Arc::default()).unwrap();
            no_accepts(&w);
            w.fdg = gate.clone();
            w.fd_setup();
            w
        })
        .collect();
    let cl = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = TcpStream::connect(cl.local_addr().unwrap()).unwrap();
    let s = cl.accept().unwrap().0;
    s.set_nonblocking(true).unwrap();
    ws[0].inbox.load.fetch_add(1, Relaxed);
    assert!(ws[0].fd_take(1));
    ws[0].adopt(net::Handoff::bare(std::os::fd::IntoRawFd::into_raw_fd(s)));
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    c.write_all(&connect(1, false, l.local_addr().unwrap().port())).unwrap();
    c.set_nonblocking(true).unwrap();
    l.set_nonblocking(true).unwrap();
    (ws, gate, peers, c, l)
}

/// the counted fds of the connections that are between two workers now
fn in_transit(peers: &[Arc<Inbox>]) -> u32 {
    peers.iter().map(|p| p.mig.moves.lock().unwrap().iter().map(|m| m.fds()).sum::<u32>()).sum()
}

/// Two workers that hand one connection back and forth after every loop turn (the hook at its fastest): the stream
/// still makes progress, because a connection that arrived in a turn stays for it (Mig::fresh). Without that the
/// target socket was never registered across an epoll_wait and no reply was ever read.
/// 60.57 A2 at every step the process count (FdGate::granted: what the limit, the reserve and the marks act on) holds
/// every open fd of the connection, also while it is between the workers: the units travel with the value.
#[test]
fn a_connection_handed_back_and_forth_every_turn_still_makes_progress() {
    let (mut ws, gate, peers, mut c, l) = pair();
    let (mut target, mut got, mut pos, mut down, mut up) = (None::<TcpStream>, Vec::new(), 0usize, Vec::new(), Vec::new());
    let (mut sent, mut buf) = (0usize, [0u8; 4096]);
    let (mut between, mut steps) = (0u32, 0u32);
    // (a guard against a hang, not a time limit: it ends when the bytes are back. 60.74 4.5: it fails only when no
    // byte moved either way for 30 s; under a loaded host the suite's other tests can starve it for seconds)
    let mut last = (0usize, 0usize, Instant::now());
    while down.len() < 64 * 200 {
        for i in 0..2 {
            pump(&mut ws[i], 1);
            ws[i].mig_force(1);
            let (held, air) = ((fds(&ws[0]) + fds(&ws[1])) as u32, in_transit(&peers));
            assert_eq!(gate.granted(), ws[0].fd_all() + ws[1].fd_all() + air, "allowance: the workers' and the units on their way");
            assert!(gate.granted() >= held + air && held + air >= 1, "the process count is never below the open fds");
            between += (air > 0) as u32;
            steps += 1;
        }
        if target.is_none() {
            target = l.accept().ok().map(|(t, _)| {
                t.set_nonblocking(true).unwrap();
                t
            });
        }
        if let Some(t) = target.as_mut() {
            if sent < 200 && c.write_all(&wisp(0x02, 1, &[sent as u8; 64])).is_ok() {
                sent += 1;
            }
            while let Ok(n) = t.read(&mut buf) {
                if n == 0 {
                    break;
                }
                up.extend_from_slice(&buf[..n]);
                t.write_all(&buf[..n]).unwrap(); // echo
            }
        }
        drain(&mut c, &mut got);
        packets(&got, &mut pos, |ty, sid, body| {
            if ty == 0x02 && sid == 1 {
                down.extend_from_slice(body);
            }
        });
        if (up.len(), down.len()) != (last.0, last.1) {
            last = (up.len(), down.len(), Instant::now());
        }
        assert!(last.2.elapsed() < Duration::from_secs(30), "no progress for 30 s: up {} down {} of {}", up.len(), down.len(), 64 * 200);
    }
    assert!(up == down && (0..200).all(|k| down[k * 64..(k + 1) * 64].iter().all(|&b| b == k as u8)), "bytes or order");
    let moves = ws[0].stats.moved_conns.get() + ws[1].stats.moved_conns.get();
    assert!(moves >= 50, "{moves} moves between the two workers");
    assert!(between >= 25, "the count was checked with the connection between the workers ({between} of {steps} steps)");
    drop(c);
    drop(target);
    let end_at = Instant::now() + Duration::from_secs(5);
    while ws[0].inbox.load.load(Relaxed) + ws[1].inbox.load.load(Relaxed) > 0 {
        for w in ws.iter_mut() {
            pump(w, 1);
        }
        assert!(Instant::now() < end_at, "not closed");
    }
    for mut w in ws {
        pump(&mut w, 1);
        empty(&w);
        end(w);
    }
}

/// 20.26 r4 a connection that arrives at a worker in a capped stage: its client socket and its stream's socket get
/// that worker's caps at once (a parked stream would never count up to its lazy cap), and the stream goes on.
#[test]
fn a_connection_that_arrives_in_a_capped_stage_is_capped_there() {
    let (mut ws, _gate, _peers, mut c, l) = pair();
    until(&mut ws[0], "stream open", |w| w.targets.slots.iter().filter_map(|s| s.1.as_ref()).any(|t| t.state == TState::Open));
    let mut t = l.accept().unwrap().0;
    t.set_nonblocking(true).unwrap();
    ws[1].set_level(2);
    assert!(ws[1].st.sock_cap > 0 && ws[0].st.sock_cap == 0);
    let caps = ws[1].stats.cap_apply.get();
    assert!(ws[0].mig_force(1).is_none());
    ws[1].inbox_ready();
    let tt = ws[1].targets.slots.iter().filter_map(|s| s.1.as_ref()).next().expect("the stream arrived");
    assert!(tt.capped, "capped at the import, not after LAZY_CAP more bytes");
    assert_eq!(ws[1].stats.cap_apply.get(), caps + 2, "the client socket and the stream socket");
    assert_eq!(net::buf_sizes(tt.fd).1, 2 * mem::target_caps(&ws[1].st).1 as i32, "the stage's send cap (the kernel doubles it)");
    c.write_all(&wisp(0x02, 1, b"hello")).unwrap();
    t.write_all(b"world").unwrap();
    let (mut got, mut pos, mut seen, mut up, mut n) = (Vec::new(), 0, Vec::new(), [0u8; 5], 0);
    let end_at = Instant::now() + Duration::from_secs(5);
    while seen != b"world" || n < 5 {
        pump(&mut ws[1], 1);
        drain(&mut c, &mut got);
        packets(&got, &mut pos, |ty, sid, body| {
            if ty == 0x02 && sid == 1 {
                seen.extend_from_slice(body);
            }
        });
        if let Ok(k) = t.read(&mut up[n..]) {
            n += k;
        }
        assert!(Instant::now() < end_at, "stream stuck: down {seen:?}, up {n}");
    }
    assert_eq!(&up, b"hello");
    drop(c);
    until(&mut ws[1], "closed", |w| w.inbox.load.load(Relaxed) == 0);
    for mut w in ws {
        pump(&mut w, 1);
        empty(&w);
        end(w);
    }
}

/// A move that a stalled worker makes late (its request was given up, a newer trial runs) arrives with an older request
/// number: it does not replace the trial of the newer one, in either order of arrival.
#[test]
fn a_late_move_does_not_replace_a_newer_trial() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (c, ci) = client(&mut w, port);
    let trial = |w: &Worker| w.mig.as_ref().unwrap().trial;
    let m = w.mig_export(ci).for_trial(1000, 5);
    let (i5, g5) = w.mig_import(m).unwrap();
    assert_eq!(trial(&w), Some((i5, g5, 1000)));
    let m = w.mig_export(i5).for_trial(2000, 4); // (older: the late one arrives second)
    let (i4, _) = w.mig_import(m).unwrap();
    assert_eq!(trial(&w), Some((i5, g5, 1000)), "the newer trial stays");
    let m = w.mig_export(i4).for_trial(3000, 6); // (newer: the late one had arrived first)
    let (i6, g6) = w.mig_import(m).unwrap();
    assert_eq!(trial(&w), Some((i6, g6, 3000)));
    // the numbers wrap: through the whole range and past 0, each one is newer than the one before
    let mut i = i6;
    for (k, seq) in [0x4000_0006u32, 0x8000_0006, 0xc000_0006, 2].into_iter().enumerate() {
        let m = w.mig_export(i).for_trial(4000 + k as u64, seq);
        let at = w.mig_import(m).unwrap();
        assert_eq!(trial(&w), Some((at.0, at.1, 4000 + k as u64)), "request {seq:#x}");
        i = at.0;
    }
    drop(c);
    until(&mut w, "gone", |w| w.inbox.load.load(Relaxed) == 0);
    pump(&mut w, 1);
    empty(&w);
    end(w);
}

/// The sweep report: the share of the last period; a worker's first sweep and a sweep after a sleep count the CPU
/// against one period (a busy worker is reported at its first sweep, not at its second).
#[test]
fn the_sweep_report_counts_one_period() {
    use super::super::migrate::sweep_share;
    let (t0, s) = (Instant::now(), Duration::from_secs(1));
    let ms = 1_000_000u64;
    assert_eq!(sweep_share(Some((t0, 5000 * ms)), t0 + 2 * s, 6000 * ms), 500, "1 s of CPU in a 2 s period");
    assert_eq!(sweep_share(None, t0, 1900 * ms), 950, "the first sweep: all its CPU against one period");
    assert_eq!(sweep_share(Some((t0, 100 * ms)), t0 + 60 * s, 2000 * ms), 950, "after a minute of sleep: against one period");
    assert_eq!(sweep_share(Some((t0, 100 * ms)), t0 + 2 * s, 100 * ms), 0);
    assert_eq!(sweep_share(Some((t0, 100 * ms)), t0, 50 * ms), 0, "no time passed, a clock that went back: no report");
}

/// --log-conns: a connection that moved keeps the cid of the worker that accepted it
#[test]
fn a_moved_connection_keeps_its_cid() {
    use super::super::connlog::{seq_origin, seq_stamp};
    assert_eq!(seq_origin(5, 3), (3, 5), "never moved: the writer is its origin");
    let s = seq_stamp(5, 3);
    assert_eq!((seq_origin(s, 0), seq_origin(s, 7)), ((3, 5), (3, 5)), "moved: the origin travels");
    assert_eq!(seq_stamp(s, 9), s, "a second move keeps the first origin");
    assert_eq!(seq_origin(seq_stamp(1, 0), 4), (0, 1), "worker 0 is an origin too");
    let _ = client_with; // (helpers shared with the fd tests)
}
