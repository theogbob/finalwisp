//! worker unit tests (moved from worker.rs by the 60.16 #10 split; unchanged)
use super::{client_hello, percent_decode};

/// 60.05 H1: a client marked dirty and then closed in the same loop turn (run_timers -> close_target
/// pushes a CLOSE and marks it; idle_sweep -> l3_sweep -> abort_client closes it; the dead drain
/// frees the slot) must not make the next turn's flush_dirty unwrap a vacant slot (base-1: panic,
/// and with panic = "abort" the whole server). A reused slot (new gen) is not flushed for it either.
#[test]
fn dirty_client_closed_in_same_turn_is_skipped() {
    use super::*;
    let cfg = Arc::new(Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads: 1,
        buffer: 128,
        filter: net::Filter::new(false, false),
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
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let pair = || {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) },
            0
        );
        fds
    };
    let a = pair();
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(a[0]));
    let ci = 0;
    let g = w.clients.gen(ci);
    w.mark_dirty(ci); // run_timers: fail_target -> close_target queued a CLOSE
    w.abort_client(ci, Why::ServerClose); // idle_sweep -> l3_sweep
    w.reap_dead(); // end of the turn
    assert!(w.clients.get(ci, g).is_none());
    w.flush_dirty(); // next turn
    assert!(w.dirty.is_empty());
    // stale entry + the slot reused by a new client: the new client is not touched
    w.dirty.push((ci, g));
    let b = pair();
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(b[0]));
    let g2 = w.clients.gen(ci);
    assert_ne!(g2, g);
    let c = w.clients.get(ci, g2).unwrap();
    c.obuf.extend_from_slice(b"x"); // output the stale entry must not flush (nor clear `dirty`)
    c.dirty = true;
    w.flush_dirty();
    assert!(w.clients.get(ci, g2).is_some_and(|c| !c.dead && c.dirty && c.ohead == 0));
    let mut buf = [0u8; 4];
    assert!(unsafe { libc::recv(b[1], buf.as_mut_ptr() as *mut _, 4, libc::MSG_DONTWAIT) } < 0);
    for fd in [a[1], b[0], b[1], w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    // review: no frees while mem::tests::heap_counter_moves measures the global heap counter
    std::mem::forget(w);
}
/// 70.02/70.08 L2: a client that sends 40 KiB of a 64 KiB frame and then drips (1 byte per sweep) is read
/// (below HOLD_FLOOR: not frame_held) but holds its buffer; shed_partial sheds it after STALL_SWEEPS sweeps
/// with less than STALL_MIN_BYTES. Uploaders that send 8 KiB per sweep are not shed (also one that finishes a
/// frame each sweep and stops at the same offset of the next: buffer positions repeat). TCP sockets: the
/// progress counter is TCP_INFO's.
#[test]
fn stalled_partial_frame_is_shed_at_level_2() {
    use super::*;
    use std::os::fd::IntoRawFd;
    let cfg = Arc::new(Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads: 1,
        buffer: 128,
        filter: net::Filter::new(false, false),
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
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.set_level(2);
    let rd = |w: &mut Worker, ci: u32| {
        w.clients.at(ci).readable = true; // (epoll would)
        w.read_client(ci);
    };
    let push = |w: &mut Worker, ci: u32, fd: RawFd, mut b: &[u8]| {
        while !b.is_empty() {
            let n = unsafe { libc::send(fd, b.as_ptr() as *const _, b.len(), libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
            if n > 0 {
                b = &b[n as usize..];
            } else {
                assert!(would_block(net::errno()));
            }
            rd(w, ci);
        }
        // until the server's kernel has ACKed all of it (a capped receive window holds the rest in our queue)
        for _ in 0..2000 {
            if net::outq(fd) == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
            rd(w, ci);
        }
        assert_eq!(net::outq(fd), 0);
        rd(w, ci);
    };
    // a 64 KiB binary frame (14-byte header: 64-bit length, zero mask key) holding a Wisp DATA packet for a
    // stream that is not open (ignored)
    let mut f = vec![0x82u8, 0x80 | 127];
    f.extend_from_slice(&(64u64 << 10).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 0x02, 99, 0, 0, 0]);
    f.resize(14 + (64 << 10), 0);
    // client 0 sends 40 KiB of the frame, then 1 byte per sweep; 1 sends 20 KiB, then 8 KiB per sweep; 2 sends
    // 20 KiB, then per sweep the rest of the frame and the same 20 KiB of the next one
    let first = [14 + (40 << 10), 14 + (20 << 10), 14 + (20 << 10)];
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peers = Vec::new();
    for (ci, &n) in first.iter().enumerate() {
        let ci = ci as u32;
        let p = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        p.set_nonblocking(true).unwrap();
        let (s, _) = l.accept().unwrap();
        s.set_nonblocking(true).unwrap();
        let p = p.into_raw_fd();
        w.inbox.load.fetch_add(1, Relaxed);
        w.adopt(net::Handoff::bare(s.into_raw_fd()));
        push(&mut w, ci, p, b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
        assert!(w.clients.at(ci).state == CState::Open);
        push(&mut w, ci, p, &f[..n]);
        let c = w.clients.at(ci);
        assert_eq!((c.need, c.rlen - c.rpos), (f.len(), n));
        assert!(!c.frame_held(w.rbuf_max)); // read at level 2 (HOLD_FLOOR)
        peers.push(p);
    }
    let sweep = |w: &mut Worker| {
        w.count_stalls();
        w.shed_holders(usize::MAX)
    };
    for k in 1..=4 {
        let shed = sweep(&mut w);
        let dead: Vec<bool> = (0..3).map(|ci| w.clients.at(ci).dead).collect();
        // sweep 1 records the counter, 2 and 3 see under STALL_MIN_BYTES: shed at 3 (STALL_SWEEPS = 2 periods)
        assert_eq!((dead[0], shed), (k >= 3, k == 3), "sweep {k}");
        assert!(!dead[1] && !dead[2], "sweep {k}: the uploaders send 8 KiB+ between sweeps");
        if !dead[0] {
            push(&mut w, 0, peers[0], &[0]);
        }
        push(&mut w, 1, peers[1], &[0; 8 << 10]);
        push(&mut w, 2, peers[2], &f[first[2]..]);
        push(&mut w, 2, peers[2], &f[..first[2]]);
        let c = w.clients.at(2);
        assert_eq!((c.dead, c.need, c.rlen - c.rpos), (false, f.len(), first[2]));
    }
    assert_eq!(w.stats.shed_holder.get(), 1); // 60.12
    assert_eq!(w.stats.cap_apply.get(), 3, "60.12 three clients accepted at level 2: capped");
    assert_eq!(w.stats.accepted.get(), 3);
    for fd in peers.into_iter().chain([w.ep, w.lfd, w.inbox.efd]) {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w); // as above: no frees while mem::tests::heap_counter_moves runs
}
/// 70.10 early DNS answers (--dns-own), on the worker side, with responses fed into the inbox by hand: (1) the late
/// family arrives while the early address connects: no second connect, the addresses are appended; (2) every early
/// address failed: the target waits (parked, unlisted), the late family is tried; (3) a stream closed while the
/// late family is due cancels the lookup, and the final answer still settles dns_inflight; (4) the connect deadline
/// passes while parked: CLOSE 0x43 once the final answer brings nothing new. dns_inflight / dns_live end at 0.
#[test]
fn early_dns_answer_and_late_family() {
    use super::*;
    use std::os::fd::IntoRawFd;
    let cfg = Arc::new(Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads: 1,
        buffer: 128,
        filter: net::Filter::new(true, false),
        connect_timeout: Duration::from_secs(10),
        dns_own: true,
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
    });
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    // one upgraded client
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (s, _) = l.accept().unwrap();
    s.set_nonblocking(true).unwrap();
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(s.into_raw_fd()));
    std::io::Write::write_all(&mut &peer, b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
    for _ in 0..200 {
        w.clients.at(0).readable = true;
        w.read_client(0);
        if w.clients.at(0).state == CState::Open {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(w.clients.at(0).state == CState::Open);
    let resp = |w: &mut Worker, ti: u32, tg: u32, addrs: Vec<IpAddr>, more: bool| {
        let host = format!("s{}.test", w.targets.get(ti, tg).map_or(0, |t| t.sid));
        let r = net::DnsResp { host, token: tok(K_TARGET, ti, tg), addrs, nx: false, more };
        w.inbox.q.lock().unwrap().push(r);
        w.inbox_ready();
    };
    let open = |w: &mut Worker, sid: u32, port: u16| {
        let (ti, tg) = w.new_target(0, sid, format!("s{sid}.test"), port, false, false).unwrap(); // one name per case (cache)
        let req = rx.try_recv().unwrap();
        assert_eq!(req.token, tok(K_TARGET, ti, tg));
        assert!(w.inbox.dns_live.lock().unwrap().contains(&req.token));
        (ti, tg)
    };
    let settle = |w: &mut Worker, ti: u32, tg: u32| {
        for _ in 0..500 {
            match w.targets.get(ti, tg) {
                Some(t) if t.state == TState::Connecting && !t.conn.is_empty() => {}
                _ => return,
            }
            std::thread::sleep(Duration::from_millis(2));
            w.connect_progress(ti);
        }
    };
    let accepted = |l: &std::net::TcpListener| {
        l.set_nonblocking(true).unwrap();
        std::iter::from_fn(|| l.accept().ok()).count()
    };
    let (v4, v6): (IpAddr, IpAddr) = ("127.0.0.1".parse().unwrap(), "::1".parse().unwrap());
    let has_v6 = std::net::TcpListener::bind("[::1]:0").is_ok();
    let quiet = |w: &Worker| (w.dns_inflight, w.inbox.dns_live.lock().unwrap().len());

    // (1) A early -> connecting to 127.0.0.1; AAAA arrives: appended after the attempt, no second connect yet
    let l4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (ti, tg) = open(&mut w, 1, l4.local_addr().unwrap().port());
    resp(&mut w, ti, tg, vec![v4], true);
    let t = w.targets.get(ti, tg).unwrap();
    assert!(t.dns_more && t.attempt == 1 && t.state != TState::Resolving);
    assert_eq!(w.dns_inflight, 1, "an early answer is not the final one");
    resp(&mut w, ti, tg, vec![v4, v6], false);
    let t = w.targets.get(ti, tg).unwrap();
    assert!(!t.dns_more && t.attempt == 1, "no extra connect on the late answer");
    assert!(t.state == TState::Open || t.addrs == [v4, v6], "{:?}", t.addrs);
    settle(&mut w, ti, tg);
    assert!(w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open));
    assert_eq!(accepted(&l4), 1);
    assert_eq!(quiet(&w), (0, 0));
    w.close_target(ti, None);

    // (2) the early address refuses: parked until the late family, which connects
    if has_v6 {
        // 60.12 flaky (1/50): another test could listen on 127.0.0.1:port; a bound, non-listening TCP socket there
        // reserves the port and refuses connects (RST), so the early v4 address always fails
        let (l6, _hole4) = (0..100)
            .find_map(|_| {
                let l6 = std::net::TcpListener::bind("[::1]:0").unwrap();
                let port = l6.local_addr().unwrap().port();
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
                let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                (sa.sin_family, sa.sin_port, sa.sin_addr.s_addr) =
                    (libc::AF_INET as u16, port.to_be(), u32::from_be_bytes([127, 0, 0, 1]).to_be());
                let ok = unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of_val(&sa) as u32) } == 0;
                let hole = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
                ok.then_some((l6, hole))
            })
            .expect("no free [::1] + 127.0.0.1 port pair in 100 tries");
        let port = l6.local_addr().unwrap().port(); // (127.0.0.1:port is bound, not listening: refused)
        let (ti, tg) = open(&mut w, 2, port);
        resp(&mut w, ti, tg, vec![v4], true);
        settle(&mut w, ti, tg);
        let t = w.targets.get(ti, tg).expect("parked, not failed");
        assert!(t.conn.is_empty() && t.cidx == NOT_LISTED && t.dns_more && t.err == libc::ECONNREFUSED);
        resp(&mut w, ti, tg, vec![v6, v4], false);
        settle(&mut w, ti, tg);
        let t = w.targets.get(ti, tg).unwrap();
        assert!(t.state == TState::Open && !t.dns_more);
        assert_eq!(accepted(&l6), 1);
        assert_eq!(quiet(&w), (0, 0));
        w.close_target(ti, None);
    }

    // (3) closed while the late family is due: the lookup is cancelled; the final answer settles the count
    let (ti, tg) = open(&mut w, 3, l4.local_addr().unwrap().port());
    resp(&mut w, ti, tg, vec![v4], true);
    w.close_target(ti, Some(0x02));
    assert_eq!(quiet(&w), (1, 0), "token cancelled, answer still due");
    resp(&mut w, ti, tg, vec![v4, v6], false);
    assert_eq!(quiet(&w), (0, 0));
    assert_eq!(accepted(&l4), 1);

    // (4) connect deadline while the late family is due: parked; final answer with nothing new -> CLOSE 0x43
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (ti, tg) = open(&mut w, 4, dead);
    resp(&mut w, ti, tg, vec![v4], true);
    let t = w.targets.get(ti, tg).unwrap();
    assert!(!t.conn.is_empty() || t.state == TState::Connecting);
    t.deadline = Instant::now() - Duration::from_millis(1);
    w.next_scan = Instant::now() - Duration::from_millis(1);
    w.run_timers();
    let t = w.targets.get(ti, tg).expect("parked at the deadline");
    assert!(t.conn.is_empty() && t.cidx == NOT_LISTED && t.err == libc::ETIMEDOUT);
    resp(&mut w, ti, tg, vec![v4], false);
    assert!(w.targets.get(ti, tg).is_none());
    let ob = &w.clients.at(0).obuf;
    assert!(ob.windows(6).any(|x| x == [0x04, 4, 0, 0, 0, 0x43]), "CLOSE 0x43 for stream 4");
    assert_eq!(quiet(&w), (0, 0));
    drop(peer);
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w); // as the tests above: no frees while mem::tests::heap_counter_moves runs
}
/// 20.30 --credit-v2 wiring: a ping follows the CONTINUE in the same output buffer; its pong retires the
/// overwritten credit and turns on the v2 grant rule (top-ups of the 1 MiB window: none while the bound still
/// counts more than that, a probe once the client spent its last CONTINUE; base would refill 128 at half).
#[test]
fn credit_v2_ping_after_continue_pong_retires_and_grants() {
    use super::*;
    let cfg = Arc::new(Config {
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
        credit_v2: true,
        credit_pace: false,
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
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.pend_cap = usize::MAX;
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    w.clients.at(ci).state = CState::Open;
    w.clients.at(ci).hs_credit = 128;
    assert!(w.clients.at(ci).cv.is_none(), "60.13: no Pinger before the first CONTINUE");
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (ti, tg) = w.new_target(ci, 1, "127.0.0.1".into(), l.local_addr().unwrap().port(), false, false).unwrap();
    w.clients.at(ci).streams.insert(1, ti);
    w.run_deferred();
    let (mut peer, _) = l.accept().unwrap();
    peer.set_nonblocking(true).unwrap();
    for _ in 0..1000 {
        if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
            break;
        }
        w.target_event(ti, tg, libc::EPOLLOUT as u32);
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut msg = vec![2u8, 1, 0, 0, 0];
    msg.resize(5 + 16384, 7);
    let mut sink = vec![0u8; 1 << 20];
    let mut data = |w: &mut Worker, n: usize| {
        for _ in 0..n {
            w.on_message(ci, &msg);
            while std::io::Read::read(&mut peer, &mut sink).is_ok_and(|k| k > 0) {}
            w.target_event(ti, tg, libc::EPOLLOUT as u32);
        }
    };
    // the frames queued for the client since the last call: (opcode, payload)
    let frames = |w: &mut Worker| {
        let c = w.clients.at(ci);
        let (mut b, mut out) = (&c.obuf[c.ohead..], Vec::new());
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
        c.obuf.clear();
        c.ohead = 0;
        out
    };
    let cont = |n: u32| (OP_BIN, [&[3u8, 1, 0, 0, 0][..], &n.to_le_bytes()].concat());
    // no pong yet: base rule (refill 128 at half); the CONTINUE is followed by ping 1
    data(&mut w, 63);
    assert!(w.clients.at(ci).cv.is_none() && w.targets.at(ti).cv.is_none(), "60.13: lazy until the first CONTINUE");
    data(&mut w, 1);
    assert_eq!(frames(&mut w), [cont(128), (OP_PING, 1u64.to_le_bytes().to_vec())]);
    assert!(w.clients.at(ci).cv.is_some());
    assert_eq!(w.targets.at(ti).cv.as_ref().unwrap().bound(), 128 + 128, "rebuilt: handshake credit + CONTINUE");
    data(&mut w, 30);
    let bound = |w: &mut Worker| w.targets.at(ti).cv.as_ref().unwrap().bound();
    assert_eq!(bound(&mut w), 128 + 128, "before the pong: additive");
    w.on_frame(ci, true, OP_PONG, b"wbench");
    assert_eq!(w.clients.at(ci).cv.as_ref().unwrap().pongs, 0, "a foreign pong is ignored");
    w.on_frame(ci, true, OP_PONG, &1u64.to_le_bytes());
    assert_eq!(w.clients.at(ci).cv.as_ref().unwrap().pongs, 1);
    std::thread::sleep(credit::PING_GAP); // (the next CONTINUE's ping is not held back by PING_GAP)
    assert_eq!(bound(&mut w), 94 + 128, "retired: recv at the pong + the last CONTINUE");
    assert!(frames(&mut w).is_empty(), "30 of 128 used: nothing due, no ping");
    // v2: no in-flight estimate yet (one pong), so outstanding = the retired bound's rest (222 - recv packets).
    // A top-up needs room >= win/8 (128 KiB = 8 packets) and a 768 KiB step (48 packets) since the CONTINUE:
    // at recv 166 the rest is 56 packets (896 KiB), room 128 KiB: CONTINUE(8), then ping 2 (none outstanding)
    data(&mut w, 71);
    assert!(frames(&mut w).is_empty(), "room < win/8 until recv 166");
    data(&mut w, 1);
    assert_eq!(frames(&mut w), [cont(8), (OP_PING, 2u64.to_le_bytes().to_vec())]);
    assert_eq!(bound(&mut w), 222 + 8);
    w.on_frame(ci, true, OP_PONG, &2u64.to_le_bytes());
    assert_eq!(w.clients.at(ci).cv.as_ref().unwrap().pongs, 2);
    assert_eq!(bound(&mut w), 166 + 8, "the 56 left of CONTINUE(128) are retired");
    std::thread::sleep(credit::PING_GAP);
    // review (liveness): the client stops answering. Its ping goes stale past PONG_LATE; no target write
    // follows (the client waits on credit), so only the sweep re-runs the grant: base rule, CONTINUE(128).
    // Here v2 stays quiet: a grant needs a 1 MiB step, so 40 of the 64 packets (640 KiB) leave none due
    frames(&mut w);
    data(&mut w, 8); // CONTINUE(64) + ping 3, never answered
    assert_eq!(frames(&mut w), [cont(64), (OP_PING, 3u64.to_le_bytes().to_vec())]);
    data(&mut w, 40);
    assert!(frames(&mut w).is_empty());
    assert_eq!(w.targets.at(ti).since, 40);
    w.sweep();
    assert!(frames(&mut w).is_empty(), "ping 3 is not late yet: v2 still applies");
    w.clients.at(ci).cv.as_mut().unwrap().age(credit::PONG_LATE + Duration::from_secs(1));
    w.sweep();
    assert_eq!(frames(&mut w).first(), Some(&cont(128)), "late pong: the sweep refills by the base rule");
    assert_eq!(w.targets.at(ti).cv.as_ref().unwrap().viol, 0);
    w.close_target(ti, None);
}

/// 60.13: credit v2 state is created on first use. An idle or download-only stream and a connection without a
/// CONTINUE hold none; the first CONTINUE creates the Pinger and that stream's state; at the first pong a stream
/// that has sent DATA gets its state, one that has not does not (also not at the sweep)
#[test]
fn credit_v2_state_is_lazy() {
    use super::*;
    let cfg = Arc::new(Config {
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
        credit_v2: true,
        credit_pace: false,
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
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.pend_cap = usize::MAX;
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    w.clients.at(ci).state = CState::Open;
    w.clients.at(ci).hs_credit = 128;
    assert!(w.clients.at(ci).cv.is_none());
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let open = |w: &mut Worker, sid: u32| {
        let (ti, tg) = w.new_target(ci, sid, "127.0.0.1".into(), port, false, false).unwrap();
        w.clients.at(ci).streams.insert(sid, ti);
        w.run_deferred();
        let (peer, _) = l.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        for _ in 0..1000 {
            if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                break;
            }
            w.target_event(ti, tg, libc::EPOLLOUT as u32);
            std::thread::sleep(Duration::from_millis(1));
        }
        (ti, tg, peer)
    };
    let s1 = open(&mut w, 1);
    let s2 = open(&mut w, 2);
    let s3 = open(&mut w, 3);
    let mut sink = vec![0u8; 1 << 20];
    let mut data = |w: &mut Worker, (ti, tg, peer): &mut (u32, u32, std::net::TcpStream), sid: u8, n: usize| {
        let mut msg = vec![2u8, sid, 0, 0, 0];
        msg.resize(5 + 16384, 7);
        for _ in 0..n {
            w.on_message(ci, &msg);
            while std::io::Read::read(peer, &mut sink).is_ok_and(|k| k > 0) {}
            w.target_event(*ti, *tg, libc::EPOLLOUT as u32);
        }
    };
    let (mut s1, mut s2, s3) = (s1, s2, s3);
    let has = |w: &mut Worker, ti: u32| w.targets.at(ti).cv.is_some();
    // stream 2 sends a little and goes idle: no state anywhere, also after a sweep
    data(&mut w, &mut s2, 2, 4);
    w.sweep();
    assert!(w.clients.at(ci).cv.is_none() && !has(&mut w, s1.0) && !has(&mut w, s2.0) && !has(&mut w, s3.0));
    // stream 1's first CONTINUE (base rule at half: 64 packets) creates the Pinger and stream 1's state only
    data(&mut w, &mut s1, 1, 64);
    assert!(w.clients.at(ci).cv.is_some() && has(&mut w, s1.0));
    assert!(!has(&mut w, s2.0) && !has(&mut w, s3.0));
    // the first pong: stream 2 (4 DATA, no CONTINUE) gets its state, rebuilt from the handshake credit; 3 does not
    w.on_frame(ci, true, OP_PONG, &1u64.to_le_bytes());
    assert_eq!(w.clients.at(ci).cv.as_ref().unwrap().pongs, 1);
    assert_eq!(w.targets.at(s2.0).cv.as_ref().map(|s| (s.bound(), s.viol)), Some((128, 0)));
    assert!(!has(&mut w, s3.0));
    // v2 active now: the sweep's v2 decision for a stream with no DATA creates nothing
    w.sweep();
    assert!(!has(&mut w, s3.0), "download-only stream stays without state");
    for (ti, _, _) in [s1, s2, s3] {
        w.close_target(ti, None);
    }
    assert_eq!(w.starve_pool, credit::STARVE_POOL);
}

/// 60.13 review r5: the byte total behind a lazily created v2 state survives the 2^20 halving
#[test]
fn scaled_bytes_undoes_the_halving() {
    assert_eq!(super::scaled_bytes(7, 7, 7000), 7000);
    assert_eq!(super::scaled_bytes(0, 0, 0), 0);
    assert_eq!(super::scaled_bytes((1 << 20) + 6, (1 << 19) + 3, ((1 << 19) + 3) * 1000), ((1 << 20) + 6) * 1000);
}

/// 60.13: idle cost guard: Target was 240 bytes before umax (it fits in padding); every stream pays it
#[test]
fn target_size() {
    assert!(std::mem::size_of::<super::Target>() <= 240, "{}", std::mem::size_of::<super::Target>());
}

/// 50.02 the starve state machine: starved = kTLS + the socket took no more + output pending + nothing in flight
#[test]
fn starve_step_states() {
    use super::{starve_delay, starve_room, starve_step, Starve, STARVE_CAP, STARVE_SLICE};
    let q0 = || 0;
    let q1 = || 1;
    let qerr = || -1;
    assert_eq!(starve_step(true, true, true, q0, 0), Starve::Start);
    assert_eq!(starve_step(true, true, true, q0, 3), Starve::Again);
    assert_eq!(starve_step(true, true, true, q1, 0), Starve::None, "data in flight: an ACK raises EPOLLOUT");
    assert_eq!(starve_step(true, true, true, q1, 2), Starve::End);
    assert_eq!(starve_step(true, true, true, qerr, 0), Starve::None, "ioctl error: not starved");
    assert_eq!(starve_step(true, true, false, q0, 0), Starve::None, "nothing pending");
    assert_eq!(starve_step(true, false, true, q0, 1), Starve::End, "the socket took everything");
    assert_eq!(starve_step(false, true, true, q0, 0), Starve::None, "plain TCP has a forced minimum");
    // SIOCOUTQ is read only when the rest says starved
    assert_eq!(starve_step(true, false, true, || panic!("no ioctl"), 0), Starve::None);
    assert_eq!(starve_step(false, true, true, || panic!("no ioctl"), 0), Starve::None);
    let ms = |n| starve_delay(n).as_millis();
    assert_eq!((ms(1), ms(2), ms(3), ms(6), ms(7), ms(200)), (2, 4, 8, 64, 100, 100));
    assert_eq!(starve_room(0, 1000, 4) as usize, 4 * STARVE_SLICE);
    assert_eq!(starve_room(1000 + STARVE_CAP - 100, 1000, 4), 100);
    assert_eq!(starve_room(1000 + STARVE_CAP, 1000, 4), 0);
    assert_eq!(starve_room(1000 + 2 * STARVE_CAP, 1000, 4), 0);
    assert_eq!(starve_room(0, 1000, 100) as usize, STARVE_CAP);
    assert_eq!(starve_room(0, 1000, 0), 0);
}

/// 50.02 A2: a starve retry (send_gather) sends the same byte stream as plain flush, in the same order (rest of a
/// partly sent lane frame, obuf up to a splice mark, the lane), across partial writes at any point
#[test]
fn starve_retry_keeps_flush_order() {
    use super::*;
    use std::io::Read;
    for (case, mark) in [(0, false), (1, false), (2, true), (3, true)] {
        let cfg = Arc::new(Config {
            addr: "127.0.0.1:0".parse().unwrap(),
            threads: 1,
            buffer: 128,
            filter: net::Filter::new(true, false),
            connect_timeout: Duration::from_secs(10),
            dns_own: false,
            abort_close: true,
            splice: false,
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
        });
        let (tx, _rx) = mpsc::channel();
        let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
        net::cap_bufs(fds[0], (4096, 4096)); // partial writes at many points
        w.inbox.load.fetch_add(1, Relaxed);
        w.adopt(net::Handoff::bare(fds[0]));
        let mut peer = unsafe { <std::os::unix::net::UnixStream as std::os::fd::FromRawFd>::from_raw_fd(fds[1]) };
        let mut k = 0u32;
        let mut piece = |n: usize| {
            (0..n)
                .map(|_| {
                    k += 1;
                    (k % 251) as u8
                })
                .collect::<Vec<u8>>()
        };
        // stream order as flush sends it: the lane frame's rest, O1, [splice mark], O2, F2, F3
        let (tail, o1, o2, f2, f3) = (piece(3), piece(200), piece(6000), piece(5000), piece(3000));
        let c = w.clients.at(0);
        c.state = CState::Open;
        c.obuf = [o1.clone(), o2.clone()].concat();
        c.bulk = [tail.clone(), f2.clone(), f3.clone()].concat();
        (c.bulk_sent, c.bulk_boundary) = (1000, 997); // mid-frame: 3 bytes of it left
        c.bulk_ends = [1003u64, 6003, 9003].into_iter().collect();
        if mark {
            c.splice_at = o1.len(); // an (empty) splice chunk between O1 and O2
        }
        let want = [tail, o1, o2, f2, f3].concat();
        let mut got = Vec::new();
        let mut buf = vec![0u8; 1500 + 997 * case];
        for i in 0..100_000 {
            let c = w.clients.at(0);
            if c.out_empty() {
                break;
            }
            c.starve_due = (i + case) % 3 != 0; // starve retries mixed with plain flushes
            c.flush().unwrap();
            if let Ok(n) = peer.read(&mut buf) {
                got.extend_from_slice(&buf[..n]);
            }
        }
        while let Ok(n) = peer.read(&mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got.len(), want.len(), "case {case}");
        assert!(got == want, "case {case}: order changed");
        let c = w.clients.at(0);
        assert_eq!((c.bulk_sent, c.bulk_boundary, c.bulk_ends.len()), (9003, 9003, 0), "case {case}");
        c.starve_due = false;
    }
}

/// 60.15 T40: a refused KeyUpdate (over tcp_mem[2] the kernel refuses the tiny record whatever is queued) holds the
/// data back only when it is the reply owed to the peer's update_requested (ku 3, RFC 8446 4.6.3); ours (ku 1, and ku 2
/// asking the peer) stay pending while every byte goes out under the old key, and are retried at the next flush. On a
/// starve retry the gather goes first for ku 1/2 and right after an accepted ku 3. Accepted KeyUpdates: first, then the data.
#[test]
fn refused_key_update_holds_data_only_when_reply_owed() {
    use std::io::Read;
    assert_eq!(
        [(true, 0), (true, 1), (true, 2), (true, 3), (false, 0), (false, 1), (false, 2), (false, 3)]
            .map(|(r, k)| super::ku_after_peer_update(r, k)),
        [3, 3, 3, 3, 0, 1, 1, 3],
        "a peer's update_requested always owes the reply; an unasked peer update turns our ask into a plain update"
    );
    for (ku, starve, refuse, want_log, all_out) in [
        (1u8, false, true, &b"k"[..], true),
        (1, true, true, b"gk", true),
        (2, false, true, b"k", true),
        (2, true, true, b"gk", true),
        (3, false, true, b"k", false),
        (3, true, true, b"k", false),
        (1, false, false, b"k", true),
        (1, true, false, b"gk", true),
        (3, true, false, b"kg", true),
    ] {
        let (mut w, _peers, cl) = up_rig(0, false);
        let mut peer = cl;
        peer.set_nonblocking(true).unwrap();
        let data: Vec<u8> = (0..20000u32).map(|i| (i % 251) as u8).collect();
        let c = w.clients.at(0);
        c.obuf = data.clone();
        (c.ku, c.starve_due, c.ku_refuse) = (ku, starve, refuse);
        c.flush().unwrap();
        let c = w.clients.at(0);
        let case = format!("ku {ku} starve {starve} refuse {refuse}: send order {:?}", c.send_log);
        assert!(c.send_log.starts_with(want_log), "{case}");
        assert_eq!(c.ku, if refuse { ku } else { 0 }, "{case}: a refused KeyUpdate stays pending");
        assert_eq!(c.out_empty(), all_out, "{case}");
        let (mut got, mut buf) = (Vec::new(), vec![0u8; 65536]);
        while let Ok(n) = peer.read(&mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert!(if all_out { got == data } else { got.is_empty() }, "{case}: {} bytes out", got.len());
    }
}

/// 50.02 B (fallback): a starved client's blocked streams read nothing on the first retry nor on the second while
/// A2's gathered request is >= STARVE_MIN_SEND; below it, or from the third retry, one slice per stream past out_high
/// (bounded by STARVE_CAP), then park again; a client already STARVE_CAP over gets no room
#[test]
fn starved_client_reads_a_bounded_slice() {
    use super::*;
    use std::io::Write;
    let cfg = Arc::new(Config {
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
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    w.clients.at(ci).state = CState::Open;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let mut peers = Vec::new();
    let mut tis = Vec::new();
    for sid in 1..5 {
        let (ti, tg) = w.new_target(ci, sid, "127.0.0.1".into(), port, false, false).unwrap();
        w.clients.at(ci).streams.insert(sid, ti);
        w.run_deferred();
        let p = l.accept().unwrap().0;
        p.set_nonblocking(true).unwrap();
        peers.push(p);
        for _ in 0..1000 {
            if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                break;
            }
            w.target_event(ti, tg, libc::EPOLLOUT as u32);
            std::thread::sleep(Duration::from_millis(1));
        }
        tis.push(ti);
    }
    std::thread::sleep(Duration::from_millis(20));
    let high = w.st.out_high;
    let c = w.clients.at(ci);
    c.obuf = vec![0u8; high]; // output stuck at the cap
    c.ohead = 0;
    for &ti in &tis {
        w.read_target(ti); // parks: pending >= out_high
    }
    let parked = |w: &mut Worker| tis.iter().all(|&ti| w.targets.at(ti).blocked);
    assert!(parked(&mut w));
    for p in &mut peers {
        assert!(p.write(&[7u8; 64 * 1024]).unwrap() > 2 * STARVE_SLICE); // queued in the parked targets' receive buffers
    }
    std::thread::sleep(Duration::from_millis(20));
    let c = w.clients.at(ci);
    assert_eq!(c.blocked.len() + c.blocked_bulk.len(), 4);
    let read = |w: &Worker| w.stats.ktls_starve_read.get();
    assert_eq!(read(&w), 0);
    let g = w.clients.gen(ci);
    let run_ready = |w: &mut Worker| {
        for t in std::mem::take(&mut w.ready) {
            w.resume(t);
        }
    };
    // first retry: A only (flush again), no reads past the cap
    let c = w.clients.at(ci);
    (c.starve, c.starve_at) = (1, Instant::now());
    w.starved.push((ci, g));
    w.starve_check();
    assert_eq!((w.clients.at(ci).starve_room, w.ready.len()), (0, 0));
    assert!(w.clients.at(ci).dirty);
    // later retries: A2 sends everything queued in one request (>= STARVE_MIN_SEND here), so no B
    let c = w.clients.at(ci);
    (c.starve, c.starve_at) = (2, Instant::now());
    assert_eq!(c.gather_len(), high);
    w.starve_check();
    assert_eq!((w.clients.at(ci).starve_room, w.ready.len()), (0, 0));
    // B fallback: the request flush can offer is below STARVE_MIN_SEND (here: all of obuf sits after a splice mark)
    let c = w.clients.at(ci);
    (c.splice_at, c.starve_at) = (0, Instant::now());
    assert_eq!(c.gather_len(), 0);
    w.starve_check();
    assert_eq!(w.clients.at(ci).starve_room as usize, 4 * STARVE_SLICE);
    assert_eq!(w.ready.len(), 4);
    let p0 = w.clients.at(ci).out_pending();
    run_ready(&mut w);
    assert_eq!(read(&w) as usize, 4 * STARVE_SLICE, "exactly the room");
    assert_eq!(w.stats.ktls_starve_slices.get(), 1);
    assert_eq!(w.stats.ktls_starve_conn_max.get() as usize, 4 * STARVE_SLICE);
    assert_eq!(w.clients.at(ci).starve_room, 0);
    assert!(parked(&mut w), "one slice per stream, then parked again (review: not the whole room to one stream)");
    let over = w.clients.at(ci).out_pending() - p0; // data + WS/Wisp headers
    assert!((4 * STARVE_SLICE..=4 * STARVE_SLICE + 8 * 9).contains(&over), "{over}");
    // two gathers failed (starve 3): B also with a big request (a SO_SNDBUF-locked socket is never forced)
    let c = w.clients.at(ci);
    (c.splice_at, c.starve, c.starve_at) = (NO_MARK, 3, Instant::now());
    assert!(c.gather_len() >= STARVE_MIN_SEND);
    w.starve_check();
    assert_eq!(w.clients.at(ci).starve_room as usize, 4 * STARVE_SLICE);
    run_ready(&mut w);
    assert!(parked(&mut w));
    w.clients.at(ci).starve = 2;
    // the per-connection cap: nothing more once STARVE_CAP over out_high
    let c = w.clients.at(ci);
    c.obuf.resize(high + STARVE_CAP, 0);
    c.starve_at = Instant::now();
    w.starve_check();
    assert_eq!((w.clients.at(ci).starve_room, w.ready.len()), (0, 0));
    // a bulk-lane-only client: A2 covers a full lane; B only below STARVE_MIN_SEND, room from out_high
    let bcap = w.st.out_high_bulk;
    let c = w.clients.at(ci);
    (c.obuf, c.ohead, c.splice_at) = (Vec::new(), 0, NO_MARK);
    (c.bulk, c.bhead) = (vec![0u8; bcap], 0);
    c.blocked.clear();
    c.blocked_bulk.clear();
    for &ti in &tis {
        let t = w.targets.at(ti);
        (t.bulk, t.blocked) = (true, false);
        w.read_target(ti); // parks in the bulk lane: pending >= out_high_bulk
    }
    let c = w.clients.at(ci);
    assert_eq!((c.blocked.len(), c.blocked_bulk.len()), (0, 4));
    assert_eq!(c.gather_len(), c.bulk.len());
    c.starve_at = Instant::now();
    w.starve_check();
    assert_eq!((w.clients.at(ci).starve_room, w.ready.len()), (0, 0));
    let r0 = read(&w);
    let c = w.clients.at(ci);
    (c.splice_at, c.starve_at) = (0, Instant::now()); // the lane waits behind a splice: not in the request
    w.starve_check();
    assert_eq!(w.clients.at(ci).starve_room as usize, 4 * STARVE_SLICE);
    run_ready(&mut w);
    assert_eq!(read(&w) - r0, 4 * STARVE_SLICE as u64);
    let c = w.clients.at(ci);
    assert_eq!((c.blocked.len(), c.blocked_bulk.len()), (0, 4), "re-parked in the bulk lane");
    c.bulk.resize(w.st.out_high + STARVE_CAP, 0); // at the bound
    c.starve_at = Instant::now();
    w.starve_check();
    assert_eq!((w.clients.at(ci).starve_room, w.ready.len()), (0, 0));
    w.clients.at(ci).splice_at = NO_MARK;
    // the episode ends at close: counted, entry dropped
    let e0 = w.stats.ktls_starve_end.get();
    w.close_client(ci, Why::ServerClose);
    assert_eq!(w.stats.ktls_starve_end.get() - e0, 1);
    w.starve_check();
    assert!(w.starved.is_empty());
}

/// B (20.31 redesign): caps from the host TCP level alone (memory level 0, cap level 1) go on remote sockets only,
/// clients and targets; memory level 1 caps all of them as before, also when the cap sizes do not change
#[test]
fn tcp_level_caps_remote_sockets_only() {
    use super::*;
    let cfg = Arc::new(Config {
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
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.pend_cap = usize::MAX;
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    w.clients.at(ci).state = CState::Open;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let mut peers = Vec::new();
    let mut tis = Vec::new();
    for sid in 1..3 {
        let (ti, tg) = w.new_target(ci, sid, "127.0.0.1".into(), port, false, false).unwrap();
        w.clients.at(ci).streams.insert(sid, ti);
        w.run_deferred();
        peers.push(l.accept().unwrap().0);
        for _ in 0..1000 {
            if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                break;
            }
            w.target_event(ti, tg, libc::EPOLLOUT as u32);
            std::thread::sleep(Duration::from_millis(1));
        }
        tis.push(ti);
    }
    w.targets.at(tis[1]).local = 1; // stands for a target on another host
    w.clients.at(ci).local = 1; // and a client (a socketpair has no IP peer)
    w.floor0 = true; // caps are lifted again: sizes saved and restored
    let rcv = |w: &mut Worker, ti: u32| net::buf_sizes(w.targets.at(ti).fd).0;
    let cap2 = 2 * mem::STAGES[1].sock_cap as i32; // (the kernel doubles it)
    let applied = |w: &Worker| w.stats.cap_apply.get();
    let r0 = rcv(&mut w, tis[0]);
    let a0 = applied(&w);
    w.set_levels(0, 1);
    assert_eq!(applied(&w) - a0, 2, "the remote client and the remote target");
    assert_eq!(w.targets.at(tis[0]).local, 2, "127.0.0.1 is this host");
    assert_eq!(rcv(&mut w, tis[0]), r0, "the same-host target keeps its size");
    assert_eq!(rcv(&mut w, tis[1]), cap2);
    w.set_levels(1, 1); // same receive caps as (0, 1) (60.15 P1: sends 40 KiB): the exemption ends all the same
    assert_eq!(applied(&w) - a0, 2 + 3, "memory level 1: the client and both targets");
    assert_eq!(rcv(&mut w, tis[0]), cap2);
    let restored = w.stats.cap_restore.get();
    w.set_levels(0, 1); // same sizes again: the exemption starts, the same-host target is uncapped
    assert_eq!(applied(&w) - a0, 2 + 3 + 2, "the remote client and target again");
    assert_eq!(w.stats.cap_restore.get() - restored, 1);
    assert_eq!(rcv(&mut w, tis[0]), r0);
    // the lazy cap of a stream at (0, 1): none for the same-host target, the cap for the remote one
    let a1 = applied(&w);
    w.targets.at(tis[0]).capped = false;
    w.lazy_cap(tis[0], LAZY_CAP as usize);
    assert!(w.targets.at(tis[0]).capped, "decided: no cap");
    assert_eq!((applied(&w), w.targets.at(tis[0]).saved), (a1, (0, 0)));
    w.targets.at(tis[1]).capped = false;
    w.lazy_cap(tis[1], LAZY_CAP as usize);
    assert_eq!(applied(&w) - a1, 1);
    w.set_levels(0, 0);
    w.clients.at(ci).local = 2; // a client on this host
    let a2 = applied(&w);
    w.set_levels(0, 1);
    assert_eq!(applied(&w) - a2, 1, "only the remote target");
    w.set_levels(0, 0);
    for ti in tis {
        w.close_target(ti, None);
    }
}

/// 20.33 test rig: a worker, one Open client on a socketpair, `n` streams to TCP peers the test reads (small buffers
/// when `small`), all granted far past what the test sends
fn up_rig(n: u32, small: bool) -> (super::Worker, Vec<(u32, u32, std::net::TcpStream)>, std::os::unix::net::UnixStream) {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    let cfg = Arc::new(Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads: 1,
        buffer: 128,
        filter: net::Filter::new(true, false),
        connect_timeout: Duration::from_secs(10),
        dns_own: false,
        abort_close: true,
        splice: false,
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
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.pend_cap = usize::MAX;
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(fds[0]));
    w.clients.at(0).state = CState::Open;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let mut out = Vec::new();
    for sid in 1..=n {
        let (ti, tg) = w.new_target(0, sid, "127.0.0.1".into(), port, false, false).unwrap();
        w.clients.at(0).streams.insert(sid, ti);
        w.run_deferred();
        let (peer, _) = l.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        for _ in 0..1000 {
            if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                break;
            }
            w.target_event(ti, tg, libc::EPOLLOUT as u32);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open));
        if small {
            net::cap_bufs(w.targets.at(ti).fd, (4096, 4096));
            net::cap_bufs(peer.as_raw_fd(), (4096, 4096));
        }
        w.targets.at(ti).allow = 1 << 20;
        out.push((ti, tg, peer));
    }
    let cl = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fds[1]) };
    (w, out, cl)
}

/// 20.33: a masked (key 0) WS frame
fn up_frame(op: u8, fin: bool, p: &[u8]) -> Vec<u8> {
    let mut f = vec![if fin { 0x80 } else { 0 } | op];
    match p.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n < 65536 => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.extend_from_slice(p);
    f
}

/// 20.33: a Wisp message (type, stream id, body)
fn up_wisp(ty: u8, sid: u32, body: &[u8]) -> Vec<u8> {
    [&[ty][..], &sid.to_le_bytes(), body].concat()
}

/// 20.33: one client read batch in the rbuf, parsed (process_frames: staging only, no final flush)
fn up_feed(w: &mut super::Worker, bytes: &[u8]) {
    assert_eq!(w.up_n, 0, "20.33 rule: nothing staged when the rbuf is replaced");
    let c = w.clients.at(0);
    c.rbuf = bytes.to_vec();
    (c.rpos, c.rlen) = (0, bytes.len());
    w.process_frames(0);
}

/// 20.33: read every peer and write every backlog until nothing moves; returns what each peer got
fn up_drain(w: &mut super::Worker, peers: &mut [(u32, u32, std::net::TcpStream)], got: &mut [Vec<u8>]) {
    use std::io::Read;
    let mut buf = vec![0u8; 1 << 16];
    let left = |w: &mut super::Worker, ti: u32, tg: u32| w.targets.get(ti, tg).map_or(0, |t| t.pend.len() - t.phead);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(20); // (review: never hang)
    let mut idle = 0;
    while idle < 1000 && std::time::Instant::now() < end {
        // (1 s without progress: tiny buffers can wait on TCP's zero-window probe, ~200 ms+)
        let mut moved = false;
        for (k, (ti, tg, p)) in peers.iter_mut().enumerate() {
            while let Ok(n) = p.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got[k].extend_from_slice(&buf[..n]);
                moved = true;
            }
            let before = left(w, *ti, *tg);
            if before > 0 {
                w.target_event(*ti, *tg, libc::EPOLLOUT as u32);
                moved |= left(w, *ti, *tg) != before;
            }
        }
        idle = if moved { 0 } else { idle + 1 };
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn up_data(sid: u32, k: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| (sid as usize * 37 + k * 11 + i) as u8).collect()
}

/// 60.15 T02: read_udp reads only as many datagrams as fit under out_high (one may pass it, never a whole
/// batch), compacts a sent prefix first, and loses or reorders nothing across repeated parked reads
#[test]
fn udp_read_stays_near_out_high() {
    use super::*;
    let (mut w, _peers, _cl) = up_rig(0, false);
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = peer.local_addr().unwrap().port();
    let (ti, tg) = w.new_target(0, 1, "127.0.0.1".into(), port, false, false).unwrap();
    w.targets.at(ti).udp = true;
    w.clients.at(0).streams.insert(1, ti);
    w.run_deferred();
    for _ in 0..1000 {
        if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
            break;
        }
        w.run_deferred();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open && t.udp));
    w.udp_send(ti, b"hi");
    let mut b = [0u8; 8];
    let (_, from) = peer.recv_from(&mut b).unwrap();
    const N: usize = 8;
    const LEN: usize = 16000; // 8 x 16000 fit the default UDP receive buffer
    let dgram = |k: usize| -> Vec<u8> { (0..LEN).map(|i| (k * 31 + i) as u8).collect() };
    for k in 0..N {
        peer.send_to(&dgram(k), from).unwrap();
    }
    std::thread::sleep(Duration::from_millis(20));
    let oh = 32 * 1024;
    w.st.out_high = oh;
    let c = w.clients.at(0);
    (c.obuf, c.ohead) = (vec![0xAB; oh - 1000], 0); // unsent bytes just under out_high
    let frame = LEN + 4 + 5; // WS header (126 + u16) + Wisp header + payload
    w.read_udp(ti);
    let c = w.clients.at(0);
    assert!(c.out_pending() < oh + frame, "pending {} with out_high {oh}: one datagram may pass it, not a batch", c.out_pending());
    assert!(w.targets.at(ti).blocked, "parked at out_high");
    // everything sent: resume until the socket is empty; the sent prefix must be compacted, not kept
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut first = true;
    for _ in 0..100 {
        let c = w.clients.at(0);
        let mut p = c.ohead;
        if first {
            p = oh - 1000; // skip the filler
            first = false;
        }
        while p < c.obuf.len() {
            let l = u16::from_be_bytes([c.obuf[p + 2], c.obuf[p + 3]]) as usize;
            assert_eq!((c.obuf[p], c.obuf[p + 1], c.obuf[p + 4]), (0x82, 126, 0x02));
            got.push(c.obuf[p + 9..p + 4 + l].to_vec());
            p += 4 + l;
        }
        assert!(c.obuf.capacity() < 2 * (oh + frame), "sent prefix kept: capacity {}", c.obuf.capacity());
        c.ohead = c.obuf.len();
        if got.len() == N {
            break;
        }
        w.targets.at(ti).blocked = false;
        w.read_udp(ti);
        assert!(w.clients.at(0).out_pending() < oh + frame);
    }
    assert_eq!(got.len(), N, "every datagram delivered");
    for (k, g) in got.iter().enumerate() {
        assert_eq!(g, &dgram(k), "datagram {k} in order and intact");
    }
}

/// 60.15 T03 P4: level 3 reads a client whose streams have no upload backlog (its bytes go straight to the targets,
/// and reading drains its receive queue); with a backlog it is not read, and the backlog draining resumes it. On
/// master level 3 read no client at all: queues filled at level 0 held usage above level 3's exit (stuck at 0 MiB/s).
#[test]
fn level3_reads_a_client_without_upload_backlog() {
    use super::*;
    use std::io::Write;
    let (mut w, mut peers, mut cl) = up_rig(1, false);
    w.set_levels(3, 3);
    let ti = peers[0].0;
    let mut want = Vec::new();
    let frames = |want: &mut Vec<u8>, ks: std::ops::Range<usize>| {
        let mut b = Vec::new();
        for k in ks {
            let d = up_data(1, k, 4096);
            b.extend(up_frame(OP_BIN, true, &up_wisp(0x02, 1, &d)));
            want.extend_from_slice(&d);
        }
        b
    };
    let read = |w: &mut super::Worker| {
        w.clients.at(0).readable = true;
        w.read_client(0);
        w.flush_upload();
        net::inq(w.clients.at(0).fd)
    };
    // no backlog: read at level 3 (master: not read, the bytes stayed in the socket)
    let b1 = frames(&mut want, 0..8);
    cl.write_all(&b1).unwrap();
    assert_eq!(read(&mut w), 0, "level 3, no upload backlog: the client is read");
    // the target socket full (written around the worker): the next DATA becomes upload backlog
    let fill = vec![0xEEu8; 1 << 16];
    let fd = w.targets.at(ti).fd;
    loop {
        let n = unsafe { libc::write(fd, fill.as_ptr() as *const _, fill.len()) };
        if n <= 0 {
            break;
        }
        want.extend_from_slice(&fill[..n as usize]);
    }
    let b2 = frames(&mut want, 8..10);
    cl.write_all(&b2).unwrap();
    assert_eq!(read(&mut w), 0, "still no backlog when read");
    let t = w.targets.at(ti);
    assert!(t.pend.len() > t.phead && w.clients.at(0).pend > 0, "EAGAIN: upload backlog");
    let b3 = frames(&mut want, 10..12);
    cl.write_all(&b3).unwrap();
    w.ready.clear();
    assert_eq!(read(&mut w), b3.len(), "level 3 with an upload backlog: not read");
    // the peer reads: the backlog drains, which queues the client again; reading it moves the rest
    let mut got = vec![Vec::new()];
    up_drain(&mut w, &mut peers, &mut got);
    assert_eq!(w.clients.at(0).pend, 0);
    let g = w.clients.gen(0);
    assert!(w.ready.iter().any(|&tk| tk == tok(K_CLIENT, 0, g)), "the drained backlog resumes the client");
    assert_eq!(read(&mut w), 0);
    up_drain(&mut w, &mut peers, &mut got);
    assert_eq!(got[0].len(), want.len());
    assert!(got[0] == want, "every byte in order");
}

/// 60.15 T03 P4 review: level 3 reads clients without a counted backlog, so it does not queue datagrams for a
/// UDP stream that is still resolving (that queue is not in c.pend): dropped as by a full socket. Below level 3 they
/// are queued as before (UDP_PEND_MAX).
#[test]
fn level3_drops_datagrams_for_a_resolving_udp_stream() {
    use super::*;
    let (mut w, _peers, _cl) = up_rig(0, false);
    let (ti, _tg) = w.new_target(0, 1, "127.0.0.1".into(), 9, false, false).unwrap();
    w.targets.at(ti).udp = true;
    w.clients.at(0).streams.insert(1, ti);
    assert!(w.targets.at(ti).state != TState::Open, "not connected yet (deferred)");
    w.set_levels(3, 3);
    w.udp_send(ti, b"dropped");
    assert!(w.targets.at(ti).pend.is_empty(), "level 3: not queued");
    w.set_levels(1, 1);
    w.udp_send(ti, b"queued");
    assert_eq!(w.targets.at(ti).pend, [&6u16.to_le_bytes()[..], b"queued"].concat(), "level 1: queued as before");
}

/// 60.15 T03 P1: at level 1 a capped target socket sends 40 KiB (the kernel doubles it) and receives the cap; level 2
/// refits it to the cap both ways
#[test]
fn level1_target_send_buffer() {
    use super::*;
    let (mut w, peers, _cl) = up_rig(1, false);
    let fd = w.targets.at(peers[0].0).fd;
    w.set_levels(1, 1);
    assert_eq!(net::buf_sizes(fd), (2 * (32 << 10), 2 * (40 << 10)));
    w.set_levels(2, 2);
    assert_eq!(net::buf_sizes(fd), (2 * (32 << 10), 2 * (32 << 10)));
}

/// 20.33: interleaved DATA of 3 streams in one read batch is staged per target (one bucket each, in order) and
/// written with one writev per target; a fragmented (copied, not staged) message flushes everything first; each
/// target receives exactly its bytes in order
#[test]
fn upload_interleaved_streams_batch_per_target() {
    use super::*;
    let (mut w, mut peers, _cl) = up_rig(3, false);
    let mut batch = Vec::new();
    let mut want = vec![Vec::new(); 3];
    for k in 0..20 {
        for sid in 1..=3u32 {
            let d = up_data(sid, k, 1024);
            batch.extend(up_frame(OP_BIN, true, &up_wisp(0x02, sid, &d)));
            want[sid as usize - 1].extend_from_slice(&d);
        }
    }
    up_feed(&mut w, &batch);
    assert_eq!(w.up_n, 3, "one bucket per target");
    assert_eq!(w.up_bufs[..3].iter().map(|b| b.iov.len()).collect::<Vec<_>>(), vec![20, 20, 20]);
    assert_eq!(w.up_bufs[..3].iter().map(|b| b.ti).collect::<Vec<_>>(), peers.iter().map(|p| p.0).collect::<Vec<_>>());
    let wv0 = w.up_writevs;
    w.flush_upload();
    assert_eq!(w.up_writevs - wv0, 3, "one writev per target for 60 interleaved frames (review: counted, not inferred)");
    // stream 2's next message comes fragmented (copied out of the rbuf: written directly): everything staged first
    let mut b2 = Vec::new();
    let d1 = up_data(1, 99, 3000);
    b2.extend(up_frame(OP_BIN, true, &up_wisp(0x02, 1, &d1)));
    let frag = up_wisp(0x02, 2, &up_data(2, 98, 5000));
    b2.extend(up_frame(OP_BIN, false, &frag[..2000]));
    b2.extend(up_frame(OP_CONT, true, &frag[2000..]));
    let d3 = up_data(3, 97, 700);
    b2.extend(up_frame(OP_BIN, true, &up_wisp(0x02, 3, &d3)));
    up_feed(&mut w, &b2);
    want[0].extend_from_slice(&d1);
    want[1].extend_from_slice(&frag[5..]);
    want[2].extend_from_slice(&d3);
    assert_eq!(w.up_n, 1, "the fragmented message flushed stream 1, then stream 3 staged anew");
    w.flush_upload();
    assert_eq!((w.up_n, w.up_total), (0, 0));
    let mut got = vec![Vec::new(); 3];
    up_drain(&mut w, &mut peers, &mut got);
    for k in 0..3 {
        assert_eq!(got[k].len(), want[k].len(), "stream {}", k + 1);
        assert!(got[k] == want[k], "stream {}: bytes or order differ", k + 1);
    }
}

/// 20.33: in one batch, one bucket's writev is partial (small buffers, peer not reading) and another bucket's
/// target is already full (EAGAIN): the rests go to pend in order, and once the peers read, each gets exactly its
/// bytes in order (the full target: its earlier bytes first)
#[test]
fn upload_batch_partial_and_eagain_buckets() {
    use super::*;
    let (mut w, mut peers, _cl) = up_rig(2, true);
    // stream 2's target socket full before the batch (written around the worker: pend stays empty)
    let pre = vec![0xEEu8; 1 << 16];
    let mut pre_n = 0;
    let fd2 = w.targets.at(peers[1].0).fd;
    loop {
        let n = unsafe { libc::write(fd2, pre.as_ptr() as *const _, pre.len()) };
        if n <= 0 {
            break;
        }
        pre_n += n as usize;
    }
    let mut batch = Vec::new();
    let mut want = [Vec::new(), vec![0xEEu8; pre_n]];
    for k in 0..40 {
        for sid in 1..=2u32 {
            let d = up_data(sid, k, 4096);
            batch.extend(up_frame(OP_BIN, true, &up_wisp(0x02, sid, &d)));
            want[sid as usize - 1].extend_from_slice(&d);
        }
    }
    up_feed(&mut w, &batch);
    assert_eq!(w.up_n, 2);
    w.flush_upload();
    let left = |w: &mut super::Worker, ti: u32| {
        let t = w.targets.at(ti);
        t.pend.len() - t.phead
    };
    let (p1, p2) = (left(&mut w, peers[0].0), left(&mut w, peers[1].0));
    assert!(p1 > 0 && p1 < 40 * 4096, "stream 1: partial writev ({p1} left)");
    assert_eq!(p2, 40 * 4096, "stream 2: EAGAIN, all of it in pend");
    let mut got = vec![Vec::new(); 2];
    up_drain(&mut w, &mut peers, &mut got);
    for k in 0..2 {
        assert_eq!(got[k].len(), want[k].len(), "stream {}", k + 1);
        assert!(got[k] == want[k], "stream {}: bytes or order differ", k + 1);
    }
}

/// 20.33: a non-DATA frame after staged DATA of streams A and B flushes both first: a Wisp CLOSE for A (A's data
/// goes out before its close), and a WS PING (nothing stays staged behind it)
#[test]
fn upload_non_data_frame_flushes_all_buckets() {
    use super::*;
    let (mut w, mut peers, _cl) = up_rig(3, false);
    let (da, db) = (up_data(1, 0, 1500), up_data(2, 0, 1500));
    let mut batch = Vec::new();
    batch.extend(up_frame(OP_BIN, true, &up_wisp(0x02, 1, &da)));
    batch.extend(up_frame(OP_BIN, true, &up_wisp(0x02, 2, &db)));
    batch.extend(up_frame(OP_BIN, true, &up_wisp(0x04, 1, &[0x02])));
    up_feed(&mut w, &batch);
    assert_eq!((w.up_n, w.up_total), (0, 0), "the CLOSE flushed A and B");
    assert!(!w.clients.at(0).streams.contains_key(&1), "A closed");
    // PING: B and C staged, then a ping: both flushed by it (process_frames itself does not flush at the end)
    let (db2, dc) = (up_data(2, 1, 900), up_data(3, 0, 900));
    let mut b2 = Vec::new();
    b2.extend(up_frame(OP_BIN, true, &up_wisp(0x02, 2, &db2)));
    b2.extend(up_frame(OP_BIN, true, &up_wisp(0x02, 3, &dc)));
    b2.extend(up_frame(OP_PING, true, b"p"));
    up_feed(&mut w, &b2);
    assert_eq!((w.up_n, w.up_total), (0, 0), "the PING flushed B and C");
    // an unsolicited PONG (no credit-v2 state takes it) flushes too (review)
    let db3 = up_data(2, 2, 600);
    let mut b3 = up_frame(OP_BIN, true, &up_wisp(0x02, 2, &db3));
    b3.extend(up_frame(OP_PONG, true, b"zz"));
    up_feed(&mut w, &b3);
    assert_eq!((w.up_n, w.up_total), (0, 0), "the PONG flushed B");
    let mut got = vec![Vec::new(); 3];
    up_drain(&mut w, &mut peers, &mut got);
    assert!(got[0] == da, "A: its data before the close");
    assert!(got[1] == [db, db2, db3].concat());
    assert!(got[2] == dc);
}

/// 20.27 0x49 hold: an honest upload (within its credit, `since <= allow`) whose target stalls while more than
/// PEND_HARD of granted data is in flight is not closed: its client is no longer read (hpaused) and resumes
/// once the backlog drained to PEND_RESUME. The hold is bounded: at HOLD_SWEEPS idle sweeps (drain or not)
/// the streams over PEND_HARD, or else the largest over PEND_RESUME, are closed (0x49) and reads resume; a
/// sibling under that is kept. A held client that hangs up is closed. A client past its credit is still
/// closed at the cap (base behaviour). Base closed the honest stream at PEND_HARD (mutation check: the old
/// queued-write rule fails part 1: "an honest stream was closed at 63 MiB of backlog").
#[test]
fn honest_upload_over_pend_hard_pauses_instead_of_close() {
    use super::*;
    let cfg = Arc::new(Config {
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
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.pend_cap = usize::MAX; // review r2: mem::tests may set a global budget meanwhile (pend_sweep would shed)
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    let cg = w.clients.gen(ci);
    w.clients.at(ci).state = CState::Open; // review: in Http the 5th sweep would expire the handshake
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    // an open stream to a target the test controls (accepted, read only when the test says)
    let open = |w: &mut Worker, sid: u32| {
        let (ti, tg) = w.new_target(ci, sid, "127.0.0.1".into(), port, false, false).unwrap();
        w.clients.at(ci).streams.insert(sid, ti);
        w.run_deferred();
        let (peer, _) = l.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        for _ in 0..1000 {
            if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                break;
            }
            w.target_event(ti, tg, libc::EPOLLOUT as u32);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open));
        (ti, tg, peer)
    };
    let chunk = vec![7u8; 1 << 20];
    let backlog = |w: &mut Worker, ti: u32| {
        let t = w.targets.at(ti);
        t.pend.len() - t.phead
    };
    let has_ready = |w: &Worker| w.ready.contains(&tok(K_CLIENT, ci, cg));

    // 1. in credit (granted far more than PEND_HARD): never closed; the client is held past PEND_HARD
    let (ti, tg, mut peer) = open(&mut w, 1);
    w.targets.at(ti).allow = 1 << 20;
    while backlog(&mut w, ti) <= PEND_HARD + (2 << 20) {
        let before = backlog(&mut w, ti);
        w.write_target(ti, &chunk);
        assert!(w.targets.get(ti, tg).is_some(), "an honest stream was closed at {} MiB of backlog", before >> 20);
        let b = backlog(&mut w, ti);
        assert_eq!(w.clients.at(ci).hpaused, b > PEND_HARD);
    }
    // 2. the target drains: reads resume at PEND_RESUME, not before
    w.ready.clear();
    let mut buf = vec![0u8; 1 << 20];
    while w.clients.at(ci).hpaused {
        assert!(!has_ready(&w));
        match std::io::Read::read(&mut peer, &mut buf) {
            Ok(n) => assert!(n > 0),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
        }
        w.target_event(ti, tg, libc::EPOLLOUT as u32);
    }
    assert!(backlog(&mut w, ti) <= PEND_RESUME && backlog(&mut w, ti) > PEND_RESUME - (8 << 20));
    assert!(has_ready(&w), "a resumed client is queued for reading");
    assert_eq!(w.clients.at(ci).over, 0);
    assert_eq!((w.stats.holds.get(), w.stats.hold_resumes.get()), (1, 1), "60.12 one hold, one resume");

    // 3. a sibling stream between PEND_RESUME and PEND_HARD, then held again by the first one, whose target
    // only trickles (1 MiB read per sweep): the hold is bounded in time anyway. At the HOLD_SWEEPS-th sweep the
    // largest backlog is closed (0x49, as base did at once), the sibling is kept, the client is read again
    let (ts, tsg, _peer_s) = open(&mut w, 2);
    w.targets.at(ts).allow = 1 << 20;
    while backlog(&mut w, ts) <= PEND_RESUME + (4 << 20) {
        w.write_target(ts, &chunk);
    }
    assert!(!w.clients.at(ci).hpaused && w.clients.at(ci).over == 1);
    while backlog(&mut w, ti) <= PEND_HARD {
        w.write_target(ti, &chunk);
    }
    assert!(w.clients.at(ci).hpaused && w.clients.at(ci).over == 2);
    for k in 1..=HOLD_SWEEPS {
        assert!(w.targets.get(ti, tg).is_some() && w.clients.at(ci).hpaused, "released early, sweep {k}");
        let _ = std::io::Read::read(&mut peer, &mut buf); // the trickle
        w.target_event(ti, tg, libc::EPOLLOUT as u32);
        w.next_sweep = Instant::now();
        w.idle_sweep();
    }
    assert!(w.targets.get(ti, tg).is_none(), "a held stream past HOLD_SWEEPS is closed");
    assert!(w.targets.get(ts, tsg).is_some(), "the sibling under PEND_HARD is kept");
    let c = w.clients.at(ci);
    assert!(!c.hpaused && c.over == 1 && c.pend == backlog(&mut w, ts));
    w.close_target(ts, None);
    assert!(w.clients.at(ci).over == 0 && w.clients.at(ci).pend == 0);
    let s = &w.stats; // 60.12: the second hold expired, one stream shed with CLOSE 0x49
    assert_eq!((s.holds.get(), s.hold_expired.get(), s.shed_hold.get(), s.close[0x49].get()), (2, 1, 1, 1));

    // 3b. two streams over PEND_HARD (one input batch can carry both): the timeout closes both (review r2: a
    // survivor over PEND_HARD would take another batch after the release)
    let (ta, tag, _pa) = open(&mut w, 6);
    let (tb, tbg, _pb) = open(&mut w, 7);
    for t in [ta, tb] {
        w.targets.at(t).allow = 1 << 20;
        while backlog(&mut w, t) <= PEND_HARD {
            w.write_target(t, &chunk);
        }
    }
    assert!(w.clients.at(ci).hpaused && w.clients.at(ci).over == 2);
    for _ in 0..HOLD_SWEEPS {
        w.next_sweep = Instant::now();
        w.idle_sweep();
    }
    assert!(w.targets.get(ta, tag).is_none() && w.targets.get(tb, tbg).is_none(), "every stream over PEND_HARD closed");
    let c = w.clients.at(ci);
    assert!(!c.hpaused && c.over == 0 && c.pend == 0);

    // 4. past its credit: closed at the cap as before (no hold)
    let (ti, tg, _peer2) = open(&mut w, 3);
    // (the kernel takes what fits in the socket buffers first: write until closed, at most 512 MiB)
    for _ in 0..512 {
        if w.targets.get(ti, tg).is_none() {
            break;
        }
        assert!(backlog(&mut w, ti) <= w.st.pend_over, "over-credit backlog past the cap");
        // (set before each write: a refill while the kernel still takes everything resets since/allow)
        (w.targets.at(ti).since, w.targets.at(ti).allow) = (1000, 5);
        w.write_target(ti, &chunk);
    }
    assert!(w.targets.get(ti, tg).is_none(), "over-credit stream not closed");
    assert!(!w.clients.at(ci).hpaused);

    assert!(w.clients.get(ci, cg).is_some_and(|c| !c.dead), "the client survived the sweeps");
    // 5. a client that hangs up while held is closed at once (not kept with its backlog until the hold ends)
    let (ti, _tg, _peer5) = open(&mut w, 5);
    w.targets.at(ti).allow = 1 << 20;
    while !w.clients.at(ci).hpaused {
        w.write_target(ti, &chunk);
    }
    let c = w.clients.at(ci);
    (c.rdhup, c.readable) = (true, true);
    w.read_client(ci);
    assert!(w.clients.get(ci, cg).is_none_or(|c| c.dead), "a held client that hung up is closed");
    for fd in [fds[1], w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w); // as above: no frees while mem::tests::heap_counter_moves runs
}

/// 70.25 the 60.09 M2 rule with the pool: at level 2+ the turn-end release cuts the dirty set to
/// mem::L2_BYTES (bounded batches); level 1 keeps it; below level 2 the full cap again.
#[test]
fn pool_is_small_at_level_2() {
    use super::*;
    // built on a non-pool thread, as main does (its 1 MiB slab arrays are System blocks; forgotten below)
    let w = std::thread::spawn(|| {
        let cfg = Arc::new(Config {
            addr: "127.0.0.1:0".parse().unwrap(),
            threads: 1,
            buffer: 128,
            filter: net::Filter::new(false, false),
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
        });
        let (tx, rx) = mpsc::channel();
        std::mem::forget(rx);
        Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap()
    })
    .join()
    .unwrap();
    crate::pool::tests::on_pool_thread(4 << 20, false, move || {
        let mut w = w;
        w.set_level(0);
        let obufs = |k: usize| (0..k).map(|_| Vec::<u8>::with_capacity(ROOM_WISP + CHUNK)).collect::<Vec<_>>();
        let small = mem::L2_BYTES / (80 << 10); // dirty obuf blocks (80 KiB class) that fit the level-2 cap
        drop(obufs(2 * small));
        crate::pool::tests::settle();
        assert_eq!(crate::pool::tests::dirty_blocks(), 2 * small);
        w.set_level(1);
        crate::pool::tests::settle();
        assert_eq!(crate::pool::tests::dirty_blocks(), 2 * small, "level 1 keeps the dirty set");
        w.set_level(2);
        assert!(mem::release_backlog(), "level 2: the turn end releases down to L2_BYTES");
        crate::pool::tests::settle();
        assert!(crate::pool::dirty_bytes() <= mem::L2_BYTES && crate::pool::dirty_bytes() > 0);
        drop(obufs(2 * small));
        crate::pool::tests::settle();
        assert!(crate::pool::dirty_bytes() <= mem::L2_BYTES, "level 2: at most L2_BYTES");
        w.set_level(3);
        drop(obufs(2 * small));
        crate::pool::tests::settle();
        assert!(crate::pool::dirty_bytes() <= mem::L2_BYTES, "level 3: at most L2_BYTES");
        w.set_level(1);
        drop(obufs(2 * small));
        crate::pool::tests::settle();
        assert_eq!(crate::pool::tests::dirty_blocks(), 2 * small, "below level 2: the full cap again");
        for fd in [w.ep, w.lfd, w.inbox.efd] {
            unsafe { libc::close(fd) };
        }
        std::mem::forget(w);
    });
}
/// 70.14 flush frees drained output buffers above keep at level 2+, at level 1 only those level 1 does not
/// grow to itself (free_drained)
#[test]
fn drained_buffers_freed_by_level() {
    use super::*;
    let k1 = mem::STAGES[1].keep;
    for cap in [65539, 131078, 524312, 1048576, 1048624, 2097152, 2097248, 4194496, 8 << 20] {
        assert!(!free_drained(0, cap, mem::STAGES[0].keep));
        assert_eq!(free_drained(1, cap, k1), cap >= 2 << 20, "level 1, capacity {cap}");
        for l in [2, 3] {
            assert_eq!(free_drained(l, cap, mem::STAGES[l].keep), cap > mem::STAGES[l].keep);
        }
    }
    assert_eq!(k1, 512 << 10); // the bound above is 4 x this

    // 60.12 #2: level 2+ keeps what its own reads grow to: one doubling of room + CHUNK plus small frames
    // queued in front (diag: 65539..131144); a level-1 buffer (262156+) is still freed at its drain
    for l in [2, 3] {
        let k = mem::STAGES[l].keep;
        assert!((2 * (ROOM_WISP + CHUNK) + 4000..262156).contains(&k), "level {l} keep {k}");
        assert!(!free_drained(l, 131144, k) && free_drained(l, 262156, k));
        assert_eq!(pend_keep(l, &mem::STAGES[l]), 64 << 10); // review: pend keeps the pre-60.12 value
    }
    assert_eq!(pend_keep(1, &mem::STAGES[1]), k1);
}
/// 20.26 review A: simulate a Wisp client (credit = n on each CONTINUE, which arrives `lag`
/// packets after it was sent) against the server's refill rule. After `stall` refills the target
/// stops draining (no more CONTINUE). An honest client then stops within `allow`, at any lag and
/// over many refills and grant changes; a client that keeps sending past its credit is caught.
#[test]
fn credit_allowance_catches_over_credit_after_refills() {
    use super::next_allow;
    // true = over-credit detected
    fn run(buffer: u32, grants: &[u32], lag: usize, stall: usize, cheat: bool) -> bool {
        let (mut credit_srv, mut allow, mut since) = (buffer, buffer, 0u32);
        let mut client_credit = buffer as i64;
        let mut inflight: std::collections::VecDeque<(usize, u32)> = Default::default(); // (deliver at packet #, n)
        let mut refills = 0usize;
        for pkt in 0..100_000usize {
            while inflight.front().is_some_and(|&(at, _)| at <= pkt) {
                client_credit = inflight.pop_front().unwrap().1 as i64;
            }
            if client_credit <= 0 && !cheat {
                match inflight.pop_front() {
                    Some((_, n)) => client_credit = n as i64, // waits for the CONTINUE in flight
                    None => return false,                     // stalled target: honest client stops
                }
            }
            client_credit -= 1;
            since += 1;
            if since > allow {
                return true;
            }
            let n = grants[(refills / 3) % grants.len()];
            let half = (credit_srv.min(n) / 2).max(1);
            if since >= half && refills < stall {
                allow = next_allow(allow, since, n);
                since = 0;
                credit_srv = n;
                refills += 1;
                inflight.push_back((pkt + lag, n));
            }
        }
        false
    }
    for lag in [0, 1, 3, 10, 40, 63] {
        for grants in [&[128u32][..], &[32, 8, 128], &[8], &[128, 8, 32, 8]] {
            for stall in [0, 1, 5, 40] {
                assert!(!run(128, grants, lag, stall, false), "honest flagged: lag {lag} grants {grants:?} stall {stall}");
                assert!(run(128, grants, lag, stall, true), "cheater not caught: lag {lag} grants {grants:?} stall {stall}");
            }
        }
    }
    assert_eq!(next_allow(u32::MAX, 0, u32::MAX), u32::MAX); // no overflow
}

/// 20.26 r4: the refill rule under pressure (after_write: `since >= half && (allow - since <= n
/// || since >= credit)`, grants that change with the packet size) never leaves an honest client
/// without credit while its target drains, and keeps its outstanding packets bounded, at any
/// CONTINUE lag and even when the client sends faster than the target drains (`pace`). The old
/// rule (`since >= half` alone) lets the backlog grow without bound; the bound alone stalls once a
/// grant shrinks below the credit the client dropped at an earlier CONTINUE.
#[test]
fn pressure_refill_never_stalls_and_bounds_the_window() {
    use super::next_allow;
    // -> (max outstanding packets, stalled)
    fn run(hs: u32, grants: &[u32], lag: usize, pace: usize, rule: fn(u32, u32, u32, u32, u32) -> bool) -> (usize, bool) {
        let (mut credit_srv, mut allow, mut since) = (hs, hs, 0u32);
        let mut client_credit = hs;
        let mut inflight = 0usize;
        let mut pending: std::collections::VecDeque<(usize, u32)> = Default::default();
        let (mut k, mut maxout) = (0usize, 0usize);
        for step in 0..3000usize {
            for _ in 0..pace {
                if client_credit > 0 {
                    client_credit -= 1;
                    inflight += 1;
                }
            }
            while pending.front().is_some_and(|&(at, _)| at <= step) {
                client_credit = pending.pop_front().unwrap().1;
            }
            maxout = maxout.max(inflight);
            if inflight > 0 {
                inflight -= 1;
                since += 1;
                let n = grants[k % grants.len()];
                let half = (credit_srv.min(n) / 2).max(1);
                if rule(since, allow, n, half, credit_srv) {
                    allow = next_allow(allow, since, n);
                    (since, credit_srv, k) = (0, n, k + 1);
                    pending.push_back((step + lag, n));
                }
            } else if client_credit == 0 && pending.is_empty() {
                return (maxout, true); // nothing in flight, no credit, no CONTINUE coming
            }
        }
        (maxout, false)
    }
    type Rule = fn(u32, u32, u32, u32, u32) -> bool;
    let old: Rule = |since, allow, n, half, credit| super::refill_due(0, since, allow, credit, n, half);
    let bound: Rule = |since, allow, n, half, _credit| since >= half && allow - since <= n;
    let fix: Rule = |since, allow, n, half, credit| super::refill_due(1, since, allow, credit, n, half);
    let grants: [&[u32]; 6] = [&[2], &[8, 2], &[8, 32, 2, 2], &[2, 8], &[32, 2, 32, 2], &[1]];
    for g in grants {
        for lag in [0, 3, 40] {
            for pace in [1, 2, 4] {
                let (out, stalled) = run(8, g, lag, pace, fix);
                assert!(!stalled, "stalled: grants {g:?} lag {lag} pace {pace}");
                let bound_pkts = (g.iter().copied().max().unwrap() + 8) as usize * 2;
                assert!(out <= bound_pkts, "outstanding {out} > {bound_pkts}: grants {g:?} lag {lag} pace {pace}");
            }
        }
    }
    assert!(run(8, &[2], 0, 2, old).0 > 1000); // the old rule: unbounded
    assert!(run(8, &[8, 2], 0, 1, bound).1); // the bound alone: stalls after the grant shrinks
}

#[test]
fn client_hello_only_first_record() {
    let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0xaa, 0xbb, 0xcc];
    ch.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x02, 0xee, 0xee]); // 0-RTT data record behind it
    assert_eq!(client_hello(&ch), Some(&ch[..9]));
    assert_eq!(client_hello(&ch[..7]), Some(&ch[..7])); // partial hello: what is there
    assert_eq!(client_hello(b"GET / HTTP/1.1\r\n"), None);
    assert_eq!(client_hello(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0, 0, 0]), None); // ServerHello
    assert_eq!(client_hello(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x01]), None);
    assert_eq!(client_hello(&[0x16, 0x03]), None);
}
#[test]
fn percent_decode_never_panics() {
    assert_eq!(percent_decode("a%20b"), "a b");
    assert_eq!(percent_decode("%aé"), "%aé");
    assert_eq!(percent_decode("%"), "%");
    assert_eq!(percent_decode("x%4"), "x%4");
    assert_eq!(percent_decode("%e2%82%ac"), "€");
}

/// 60.20 C3a --max-conns: the reservation is taken in accept_all (the client over the limit is reset before any work)
/// and released at every end of a counted client: close_client (also via abort / reset / shutdown_step) and both
/// adopt failure exits (rustls refuses the config; epoll refuses the fd). The gate ends at 0 with Inbox.load.
#[test]
fn conn_gate_reserve_and_release_on_every_exit() {
    use super::*;
    use std::io::Read as _;
    use std::os::fd::FromRawFd;
    let gate = Arc::new(net::ConnGate::new(2));
    let mk = |tls: Option<Arc<rustls::ServerConfig>>| {
        Arc::new(Config {
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
            tls,
            udp: true,
            tls_rekey: 0,
            notsent_lowat: 0,
            adapt_lowat: 0,
            keepalive: true,
            prio: true,
            ext: ext::Ext::default(),
            credit_v2: false,
            credit_pace: false,
            conn_gate: Some(gate.clone()),
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
        })
    };
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(mk(None), tx.clone(), 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    let connect =
        |n: usize| -> Vec<std::net::TcpStream> { (0..n).map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).unwrap()).collect() };
    let load = |w: &Worker| w.inbox.load.load(Relaxed);
    // three connections, limit 2: two adopted, the third reset at accept
    let mut peers = connect(3);
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    assert_eq!((gate.used(), load(&w), w.stats.refuse_conns.get()), (2, 2, 1));
    peers[2].set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let e = peers[2].read(&mut [0u8; 1]).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "the refused client gets an RST");
    // close_client and abort_client (reset_client -> close_client) release; reap frees the slots
    w.close_client(0, Why::ServerClose);
    w.abort_client(1, Why::ServerClose);
    w.reap_dead();
    assert_eq!((gate.used(), load(&w)), (0, 0));
    // room again: two more, then shutdown (STOP_CLOSE closes clients still in the HTTP state)
    peers.extend(connect(2));
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    assert_eq!((gate.used(), load(&w), w.stats.refuse_conns.get()), (2, 2, 1));
    w.shutdown_step(net::STOP_CLOSE);
    w.reap_dead();
    assert_eq!((gate.used(), load(&w)), (0, 0));
    // adopt exit 1: epoll refuses the fd (a memfd is a regular file, not pollable) -> closed, released. "Closed" is
    // checked by identity, not by fd number: another test thread may reuse the number at once (was flaky)
    let null = unsafe { libc::memfd_create(c"c3a-gate".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(null >= 0 && gate.try_reserve());
    let ident = |fd: i32| {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
    };
    let ours = ident(null).unwrap();
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(null));
    assert_eq!((gate.used(), load(&w)), (0, 0));
    assert_ne!(ident(null), Some(ours), "adopt closed the fd (its number may hold another file now)");
    // adopt exit 2: rustls refuses to create the connection state (max_fragment_size 1 is invalid)
    #[derive(Debug)]
    struct NoCert;
    impl rustls::server::ResolvesServerCert for NoCert {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }
    let mut tc = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoCert));
    tc.max_fragment_size = Some(1);
    let mut wt = Worker::new(mk(Some(Arc::new(tc))), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let afd = std::os::fd::IntoRawFd::into_raw_fd(a);
    assert!(gate.try_reserve());
    wt.inbox.load.fetch_add(1, Relaxed);
    wt.adopt(net::Handoff::bare(afd));
    assert_eq!((gate.used(), load(&wt)), (0, 0));
    assert!(wt.clients.slots.iter().all(|s| s.1.is_none()), "no client was created");
    for fd in [w.ep, w.inbox.efd, wt.ep, wt.lfd, wt.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    drop(peers);
    std::mem::forget(w); // review (mem::tests): no frees while the global heap counter is measured
    std::mem::forget(wt);
}

/// 60.20 C3a --max-streams-per-conn: c.streams holds a stream from CONNECT until close_target (resolving, connecting,
/// open); a CONNECT over the cap gets CLOSE 0x49 (refuse_limit) and the connection stays. Every way a stream ends frees
/// its slot: a client CLOSE, a DNS failure, a refused connect (the target's RST), a close from the server side.
#[test]
fn streams_per_conn_cap_and_every_stream_end_frees_a_slot() {
    use super::*;
    use std::io::Write as _;
    use std::os::fd::IntoRawFd;
    let cfg = Arc::new(Config {
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
        conn_gate: None,
        max_streams_per_conn: 2,
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
    });
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (s, _) = l.accept().unwrap();
    s.set_nonblocking(true).unwrap();
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(s.into_raw_fd()));
    peer.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
    let feed = |w: &mut Worker| {
        for _ in 0..100 {
            w.clients.at(0).readable = true;
            w.read_client(0);
            if net::inq(w.clients.at(0).fd) == 0 {
                break;
            }
        }
    };
    std::thread::sleep(Duration::from_millis(10));
    feed(&mut w);
    assert!(w.clients.at(0).state == CState::Open);
    let pkt = |ty: u8, sid: u32, body: &[u8]| {
        let mut p = vec![ty];
        p.extend(sid.to_le_bytes());
        p.extend(body);
        let mut f = vec![0x82, 0x80 | p.len() as u8, 0, 0, 0, 0]; // masked with a zero key
        f.extend(p);
        f
    };
    let connect = |sid: u32, port: u16, host: &str| {
        let mut b = vec![1u8];
        b.extend(port.to_le_bytes());
        b.extend(host.as_bytes());
        pkt(0x01, sid, &b)
    };
    let send = |w: &mut Worker, peer: &mut std::net::TcpStream, bytes: Vec<u8>| {
        peer.write_all(&bytes).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        feed(w);
    };
    let n = |w: &mut Worker| w.clients.at(0).streams.len();
    let up = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let uport = up.local_addr().unwrap().port();
    // 1, 2 accepted; 3 refused (0x49), the connection stays
    send(&mut w, &mut peer, [connect(1, uport, "127.0.0.1"), connect(2, uport, "127.0.0.1"), connect(3, uport, "127.0.0.1")].concat());
    assert_eq!((n(&mut w), w.stats.refuse_limit.get()), (2, 1));
    assert!(!w.clients.at(0).dead && !w.clients.at(0).closing);
    // a client CLOSE frees one
    send(&mut w, &mut peer, pkt(0x04, 1, &[0x02]));
    assert_eq!(n(&mut w), 1);
    // a DNS failure frees one
    send(&mut w, &mut peer, connect(4, 80, "nx.test"));
    assert_eq!(n(&mut w), 2);
    let req = rx.try_recv().unwrap();
    w.inbox.q.lock().unwrap().push(net::DnsResp { host: req.host, token: req.token, addrs: vec![], nx: true, more: false });
    w.inbox_ready();
    assert_eq!(n(&mut w), 1);
    // a refused connect (RST from the target's host) frees one
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dport = dead.local_addr().unwrap().port();
    drop(dead);
    send(&mut w, &mut peer, connect(5, dport, "127.0.0.1"));
    assert_eq!(n(&mut w), 2);
    let ti = *w.clients.at(0).streams.get(&5).unwrap();
    for _ in 0..500 {
        if !w.clients.at(0).streams.contains_key(&5) {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
        w.connect_progress(ti);
    }
    assert_eq!(n(&mut w), 1, "the refused connect ended the stream");
    // a close from the server side (the target's EOF path) frees the last one
    let ti = *w.clients.at(0).streams.get(&2).unwrap();
    w.close_target(ti, Some(CLOSE_VOLUNTARY));
    assert_eq!(n(&mut w), 0);
    // and the cap counts again from 0
    send(&mut w, &mut peer, [connect(6, uport, "127.0.0.1"), connect(7, uport, "127.0.0.1"), connect(8, uport, "127.0.0.1")].concat());
    assert_eq!((n(&mut w), w.stats.refuse_limit.get()), (2, 2));
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.20 C3a --max-conns with --balance: the accepting worker reserves, hands the fd over, and the adopting worker
/// releases it (its close_client -> unload); a hand-over keeps the reservation in between.
#[test]
fn conn_gate_follows_a_balance_hand_over() {
    use super::*;
    use std::os::fd::FromRawFd;
    let gate = Arc::new(net::ConnGate::new(4));
    let cfg = Arc::new(Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads: 2,
        buffer: 128,
        filter: net::Filter::new(true, false),
        connect_timeout: Duration::from_secs(10),
        dns_own: false,
        abort_close: true,
        splice: true,
        balance: true,
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
        conn_gate: Some(gate.clone()),
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
    });
    let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
    let (tx, _rx) = mpsc::channel();
    let mut w0 = Worker::new(cfg.clone(), tx.clone(), 0, peers.clone(), Arc::default()).unwrap();
    let mut w1 = Worker::new(cfg, tx, 1, peers.clone(), Arc::default()).unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w0.lfd)) }.local_addr().unwrap().port();
    w0.inbox.load.fetch_add(1, Relaxed); // w0 looks busier: its next accept goes to w1
    let _peer = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    w0.accept_all();
    assert_eq!(gate.used(), 1, "reserved by the accepting worker");
    assert_eq!(peers[1].fds.lock().unwrap().len(), 1, "handed over to w1");
    assert!(w0.clients.slots.iter().all(|s| s.1.is_none()));
    w1.inbox_ready();
    assert_eq!((gate.used(), w1.inbox.load.load(Relaxed)), (1, 1), "the reservation travelled with the fd");
    w1.close_client(0, Why::ServerClose);
    w1.reap_dead();
    assert_eq!((gate.used(), w1.inbox.load.load(Relaxed)), (0, 0), "released by the adopting worker");
    w0.inbox.load.fetch_sub(1, Relaxed);
    for fd in [w0.ep, w0.inbox.efd, w1.ep, w1.lfd, w1.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w0);
    std::mem::forget(w1);
}

/// 60.20 C1: the request rules (ports, names, IPv6 literals, UDP with --no-udp = Q7) refuse with 0x48 before the stream
/// cap, memory admission and DNS (no slot, no lookup); malformed hosts get 0x41; the address rules run at both filter
/// sites (start_connect: every address refused = 0x48; dns_late: a refused late address never joins the list); wsproxy
/// gets a 403 before the 101.
#[test]
fn policy_refuses_before_the_cap_and_dns_and_filters_late_answers() {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::fd::IntoRawFd;
    let rules = policy::Rules {
        block_hosts: vec!["blocked.test".into()],
        block_ports: vec![policy::PortRule::parse("tcp:25").unwrap()],
        direct_ip: true,
        ipv6: false,
        ..Default::default()
    };
    let cfg = Arc::new(Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads: 1,
        buffer: 128,
        filter: net::Filter { block_dests: vec![policy::Cidr::parse("127.0.0.3").unwrap()].into(), ..net::Filter::new(true, false) },
        connect_timeout: Duration::from_secs(10),
        dns_own: false,
        abort_close: true,
        splice: true,
        balance: false,
        tfo: false,
        tls: None,
        udp: false,
        tls_rekey: 0,
        notsent_lowat: 0,
        adapt_lowat: 0,
        keepalive: true,
        prio: true,
        ext: ext::Ext::default(),
        credit_v2: false,
        credit_pace: false,
        conn_gate: None,
        max_streams_per_conn: 1,
        policy: policy::Policy::new(&rules).map(Box::new),
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
    });
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let open = |w: &mut Worker, path: &str| {
        let mut peer = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        s.set_nonblocking(true).unwrap();
        w.inbox.load.fetch_add(1, Relaxed);
        w.adopt(net::Handoff::bare(s.into_raw_fd()));
        let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
        peer.write_all(req.as_bytes()).unwrap();
        peer
    };
    let feed = |w: &mut Worker, ci: u32| {
        for _ in 0..100 {
            w.clients.at(ci).readable = true;
            w.read_client(ci);
            if w.clients.get(ci, w.clients.gen(ci)).is_none_or(|c| net::inq(c.fd) == 0) {
                break;
            }
        }
    };
    let mut peer = open(&mut w, "/");
    std::thread::sleep(Duration::from_millis(10));
    feed(&mut w, 0);
    assert!(w.clients.at(0).state == CState::Open);
    let pkt = |ty: u8, sid: u32, body: &[u8]| {
        let mut p = vec![ty];
        p.extend(sid.to_le_bytes());
        p.extend(body);
        let mut f = vec![0x82, 0x80 | p.len() as u8, 0, 0, 0, 0]; // masked with a zero key
        f.extend(p);
        f
    };
    let connect = |sid: u32, ty: u8, port: u16, host: &str| {
        let mut b = vec![ty];
        b.extend(port.to_le_bytes());
        b.extend(host.as_bytes());
        pkt(0x01, sid, &b)
    };
    let send = |w: &mut Worker, peer: &mut std::net::TcpStream, bytes: Vec<u8>| {
        peer.write_all(&bytes).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        feed(w, 0);
    };
    let n = |w: &mut Worker| w.clients.at(0).streams.len();
    let up = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let uport = up.local_addr().unwrap().port();
    send(
        &mut w,
        &mut peer,
        [
            connect(1, 1, 25, "mail.example"),    // port rule
            connect(2, 1, 80, "x.BLOCKED.test."), // name rule (case, trailing dot, subdomain)
            connect(3, 2, 53, "127.0.0.1"),       // UDP with --no-udp (Q7)
            connect(4, 1, 80, "::1"),             // IPv6 literal with --no-ipv6-targets
            connect(5, 1, 80, "a b"),             // malformed: 0x41
            connect(6, 1, 80, "a\0b"),            // malformed: 0x41
            connect(7, 3, 80, "example.com"),     // unknown stream type: 0x41
        ]
        .concat(),
    );
    let st = w.stats.clone();
    assert_eq!((st.close[0x48].get(), st.refuse_policy.get(), st.close[0x41].get()), (4, 4, 3));
    assert_eq!((n(&mut w), st.refuse_limit.get(), st.connects.get()), (0, 0, 0), "no slot, no target");
    assert!(rx.try_recv().is_err(), "refused before DNS: no lookup");
    assert!(!w.clients.at(0).dead && !w.clients.at(0).closing);
    // the cap (1) is still free: the refusals took no slot
    send(&mut w, &mut peer, connect(8, 1, uport, "127.0.0.1"));
    assert_eq!((n(&mut w), w.stats.refuse_limit.get()), (1, 0));
    send(&mut w, &mut peer, pkt(0x04, 8, &[0x02]));
    assert_eq!(n(&mut w), 0);
    // address stage in start_connect: every address refused -> 0x48
    send(&mut w, &mut peer, connect(9, 1, uport, "only-blocked.test"));
    let req = rx.try_recv().unwrap();
    let a3: IpAddr = "127.0.0.3".parse().unwrap();
    w.inbox.q.lock().unwrap().push(net::DnsResp { host: req.host, token: req.token, addrs: vec![a3], nx: false, more: false });
    w.inbox_ready();
    assert_eq!((n(&mut w), w.stats.close[0x48].get(), w.stats.refuse_policy.get()), (0, 5, 5));
    // dns_late: an early answer starts the connect; the refused address of the final answer never joins the list
    send(&mut w, &mut peer, connect(10, 1, uport, "late.test"));
    let req = rx.try_recv().unwrap();
    let (a1, a4): (IpAddr, IpAddr) = ("127.0.0.1".parse().unwrap(), "127.0.0.4".parse().unwrap());
    let (h, token) = (req.host.clone(), req.token);
    w.inbox.q.lock().unwrap().push(net::DnsResp { host: h.clone(), token, addrs: vec![a1], nx: false, more: true });
    w.inbox_ready();
    let ti = *w.clients.at(0).streams.get(&10).unwrap();
    assert!(w.targets.at(ti).dns_more && w.targets.at(ti).state != TState::Resolving);
    w.inbox.q.lock().unwrap().push(net::DnsResp { host: h, token, addrs: vec![a3, a4], nx: false, more: false });
    w.inbox_ready();
    let t = w.targets.at(ti);
    assert!(!t.addrs.contains(&a3) && t.addrs.contains(&a4), "{:?}", t.addrs);
    // wsproxy: the request rules before the 101
    let mut wp = open(&mut w, "/p/x.blocked.test:80");
    std::thread::sleep(Duration::from_millis(10));
    feed(&mut w, 1);
    let mut got = w.clients.get(1, w.clients.gen(1)).map(|c| c.obuf.clone()).unwrap_or_default();
    wp.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let mut b = [0u8; 512];
    if let Ok(k) = wp.read(&mut b) {
        got.extend_from_slice(&b[..k]);
    }
    let got = String::from_utf8_lossy(&got);
    assert!(got.contains("403 Forbidden") && !got.contains("101"), "{got}");
    assert_eq!(w.stats.refuse_policy.get(), 6);
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// A TCP connection from `src` (a 127.0.0.x source address) to 127.0.0.1:port.
fn connect_from(src: [u8; 4], port: u16) -> std::net::TcpStream {
    use std::os::fd::FromRawFd;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0);
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_addr.s_addr = u32::from_ne_bytes(src);
        let len = std::mem::size_of::<libc::sockaddr_in>() as u32;
        assert_eq!(libc::bind(fd, &sa as *const _ as *const _, len), 0);
        sa.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        sa.sin_port = port.to_be();
        assert_eq!(libc::connect(fd, &sa as *const _ as *const _, len), 0);
        std::net::TcpStream::from_raw_fd(fd)
    }
}

fn clientip_cfg(
    trusted: &[&str],
    max_conns: u32,
    balance: bool,
    threads: usize,
    tls: Option<std::sync::Arc<rustls::ServerConfig>>,
) -> std::sync::Arc<super::Config> {
    use super::*;
    Arc::new(Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads,
        buffer: 128,
        filter: net::Filter::new(true, false),
        connect_timeout: Duration::from_secs(10),
        dns_own: false,
        abort_close: true,
        splice: true,
        balance,
        tfo: false,
        tls,
        udp: true,
        tls_rekey: 0,
        notsent_lowat: 0,
        adapt_lowat: 0,
        keepalive: true,
        prio: true,
        ext: ext::Ext::default(),
        credit_v2: false,
        credit_pace: false,
        conn_gate: None,
        max_streams_per_conn: 0,
        policy: None,
        clientip: Some(Box::new(clientip::ClientIp {
            trusted: trusted.iter().map(|s| crate::policy::Cidr::parse(s).unwrap()).collect(),
            header: "x-forwarded-for".into(),
            table: Some(clientip::IpTable::new(None)),
            max_conns,
        })),
        log_conns: false,
        log_streams: false,
        want_peer: true,
        pace: net::Pacing::default(),
        unix: None,
        upstream: None,
        upload_rate: None,
        proxy_tcp: false,
        proxy_unix: false,
        proxy_from: Box::new([]),
        dest_rate: None,
    })
}

/// 60.20 C3b a direct peer's key is charged at accept (over --max-conns-per-ip: RST) and released at every exit of a
/// counted client: close_client (also via abort / shutdown_step) and both adopt failure exits with a charged key.
#[test]
fn per_ip_key_charged_at_accept_and_released_on_every_exit() {
    use super::*;
    use std::io::Read as _;
    use std::os::fd::FromRawFd;
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(clientip_cfg(&[], 2, false, 1, None), tx.clone(), 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    let t = |w: &Worker| w.cfg.clientip.as_ref().unwrap().table.as_ref().unwrap() as *const clientip::IpTable;
    let tab = unsafe { &*t(&w) };
    let k1 = clientip::key("127.0.0.1".parse().unwrap());
    let k2 = clientip::key("127.0.0.2".parse().unwrap());
    let mut peers: Vec<_> = (0..3).map(|_| connect_from([127, 0, 0, 1], port)).collect();
    peers.push(connect_from([127, 0, 0, 2], port));
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    assert_eq!((tab.conns(k1), tab.conns(k2), w.stats.refuse_ip_conns.get(), w.inbox.load.load(Relaxed)), (2, 1, 1, 3));
    let refused = peers
        .iter_mut()
        .map(|p| {
            p.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
            matches!(p.read(&mut [0u8; 1]), Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
        })
        .filter(|&r| r);
    assert_eq!(refused.count(), 1, "the third from 127.0.0.1 got an RST");
    assert!((0..3).all(|i| w.peer(i).is_some_and(|p| p.key.is_some())));
    w.close_client(0, Why::ServerClose);
    w.abort_client(1, Why::ServerClose);
    w.reap_dead();
    assert_eq!((tab.conns(k1), tab.conns(k2)), (0, 1));
    w.shutdown_step(net::STOP_CLOSE);
    w.reap_dead();
    assert_eq!((tab.conns(k1), tab.conns(k2), tab.keys(), w.inbox.load.load(Relaxed)), (0, 0, 0, 0));
    // adopt exit 1 (epoll refuses /dev/null) with a charged key
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert_eq!(tab.charge(k1, 2, 0), clientip::Charge::Charged);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff { fd: null, peer: Some("127.0.0.1".parse().unwrap()), key: Some(k1), kind: 0 });
    assert_eq!((tab.conns(k1), tab.keys(), w.inbox.load.load(Relaxed)), (0, 0, 0));
    // adopt exit 2 (rustls refuses the config) with a charged key
    #[derive(Debug)]
    struct NoCert;
    impl rustls::server::ResolvesServerCert for NoCert {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }
    let mut tc = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoCert));
    tc.max_fragment_size = Some(1);
    let mut wt =
        Worker::new(clientip_cfg(&[], 2, false, 1, Some(Arc::new(tc))), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let tabt = unsafe { &*t(&wt) };
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(tabt.charge(k1, 2, 0), clientip::Charge::Charged);
    wt.inbox.load.fetch_add(1, Relaxed);
    wt.adopt(net::Handoff { fd: std::os::fd::IntoRawFd::into_raw_fd(a), peer: Some("127.0.0.1".parse().unwrap()), key: Some(k1), kind: 0 });
    assert_eq!((tabt.conns(k1), tabt.keys(), wt.inbox.load.load(Relaxed)), (0, 0, 0));
    for fd in [w.ep, w.inbox.efd, wt.ep, wt.lfd, wt.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    drop(peers);
    std::mem::forget(w);
    std::mem::forget(wt);
}

/// 60.20 C3b --balance: the accepting worker charges the key and hands it over with the fd; the adopting worker
/// releases it (close_client -> unload).
#[test]
fn per_ip_key_follows_a_balance_hand_over() {
    use super::*;
    use std::os::fd::FromRawFd;
    let cfg = clientip_cfg(&[], 4, true, 2, None);
    let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
    let (tx, _rx) = mpsc::channel();
    let mut w0 = Worker::new(cfg.clone(), tx.clone(), 0, peers.clone(), Arc::default()).unwrap();
    let mut w1 = Worker::new(cfg.clone(), tx, 1, peers.clone(), Arc::default()).unwrap();
    let tab = cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let k = clientip::key("127.0.0.3".parse().unwrap());
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w0.lfd)) }.local_addr().unwrap().port();
    w0.inbox.load.fetch_add(1, Relaxed); // w0 looks busier: its next accept goes to w1
    let _peer = connect_from([127, 0, 0, 3], port);
    std::thread::sleep(Duration::from_millis(20));
    w0.accept_all();
    let h = *peers[1].fds.lock().unwrap().first().expect("handed over to w1");
    assert_eq!((h.peer, h.key, tab.conns(k)), (Some("127.0.0.3".parse().unwrap()), Some(k), 1), "charged by w0, travelling");
    w1.inbox_ready();
    assert_eq!(w1.peer(0).map(|p| (p.ip, p.key)), Some(("127.0.0.3".parse().unwrap(), Some(k))));
    w1.close_client(0, Why::ServerClose);
    w1.reap_dead();
    assert_eq!((tab.conns(k), tab.keys()), (0, 0), "released by the adopting worker");
    w0.inbox.load.fetch_sub(1, Relaxed);
    for fd in [w0.ep, w0.inbox.efd, w1.ep, w1.lfd, w1.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w0);
    std::mem::forget(w1);
}

/// 60.31 C7 the shared unix listener: a unix accept always goes to the least loaded worker (route, load counted once,
/// on the owner); a unix client is plain HTTP whatever the TLS config, LOCAL_UNIX, its peer the trusted sentinel (its
/// X-Forwarded-For is read and charged after the request; no header: not charged); the last worker to let go removes
/// the socket file.
#[test]
fn unix_listener_hands_over_trusts_the_header_and_removes_the_path() {
    use super::*;
    use std::io::Write as _;
    use std::os::fd::FromRawFd;
    #[derive(Debug)]
    struct NoCert;
    impl rustls::server::ResolvesServerCert for NoCert {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }
    let tc = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoCert));
    let dir = std::env::temp_dir().join(format!("fw-unix-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("w.sock");
    let u = Arc::new(net::listen_unix(&path, 0o660, 2).unwrap());
    {
        use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
        let m = std::fs::symlink_metadata(&path).unwrap();
        assert!(m.file_type().is_socket());
        assert_eq!(m.permissions().mode() & 0o777, 0o660, "created with exactly the mode (umask around bind)");
    }
    let e = net::listen_unix(&path, 0o660, 1).err().unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse, "a second instance on the path: the flock refuses it");
    let mut cfg = clientip_cfg(&["100::/128"], 1, false, 2, Some(Arc::new(tc)));
    Arc::get_mut(&mut cfg).unwrap().unix = Some(u.clone());
    let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
    let (tx, _rx) = mpsc::channel();
    let mut w0 = Worker::new(cfg.clone(), tx.clone(), 0, peers.clone(), Arc::default()).unwrap();
    let mut w1 = Worker::new(cfg.clone(), tx, 1, peers.clone(), Arc::default()).unwrap();
    let tab = cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let up = |xff: Option<&str>| {
        let h = xff.map_or(String::new(), |x| format!("X-Forwarded-For: {x}\r\n"));
        format!("GET / HTTP/1.1\r\nHost: x\r\n{h}Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    };
    let mut socks: Vec<_> = (0..4).map(|_| std::os::unix::net::UnixStream::connect(&path).unwrap()).collect();
    socks[0].write_all(up(Some("9.9.9.9")).as_bytes()).unwrap();
    socks[2].write_all(up(None).as_bytes()).unwrap();
    w0.accept_on(true);
    assert_eq!((w0.stats.accepted_unix.get(), w0.inbox.load.load(Relaxed), w1.inbox.load.load(Relaxed)), (4, 2, 2), "alternating");
    w1.inbox_ready();
    for w in [&mut w0, &mut w1] {
        assert_eq!(w.clients.slots.iter().filter(|s| s.1.is_some()).count(), 2);
        for i in 0..2u32 {
            let c = w.clients.at(i);
            assert!(c.state == CState::Http && c.tls.is_none() && c.local == LOCAL_UNIX, "plain ws:// on the unix socket");
            assert_eq!(w.peer(i).map(|p| (p.ip, p.key)), Some((clientip::UNIX_PEER, None)), "the sentinel, not charged");
        }
    }
    // w0 kept sockets 0 and 2 (it was least loaded first and third)
    for i in 0..2u32 {
        w0.clients.at(i).readable = true;
        w0.read_client(i);
    }
    assert_eq!(w0.peer(0).map(|p| (p.ip, p.key)), Some(("9.9.9.9".parse().unwrap(), Some(clientip::key("9.9.9.9".parse().unwrap())))));
    assert_eq!(w0.peer(1).map(|p| (p.ip, p.key)), Some((clientip::UNIX_PEER, None)), "no header: the sentinel, not charged");
    assert_eq!((tab.keys(), w0.stats.realip_missing.get()), (1, 1));
    // a TCP client on the same worker (the TLS listener here): its own address, charged at accept, not trusted (review)
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w0.lfd)) }.local_addr().unwrap().port();
    let tcp = connect_from([127, 0, 0, 1], port);
    std::thread::sleep(Duration::from_millis(20));
    w0.accept_on(false);
    let ip = w0.peer(2).map(|p| p.ip).unwrap();
    assert!(ip == "127.0.0.1".parse::<std::net::IpAddr>().unwrap() && !cfg.clientip.as_ref().unwrap().is_trusted(ip));
    assert!(w0.clients.at(2).tls.is_some() && w0.clients.at(2).local != LOCAL_UNIX, "TLS on TCP");
    assert_eq!((tab.keys(), w0.stats.accepted_unix.get()), (2, 4));
    w0.shutdown_step(net::STOP_CLOSE);
    assert!(path.exists(), "w1 still holds the listener");
    w1.shutdown_step(net::STOP_CLOSE);
    assert!(!path.exists(), "the last holder removed the path");
    for w in [&mut w0, &mut w1] {
        for i in 0..w.clients.slots.len() as u32 {
            if w.clients.get(i, w.clients.gen(i)).is_some_and(|c| !c.dead) {
                w.close_client(i, Why::ServerClose);
            }
        }
        w.reap_dead();
    }
    assert_eq!((tab.keys(), w0.inbox.load.load(Relaxed), w1.inbox.load.load(Relaxed)), (0, 0, 0), "keys and load released");
    // a stale socket file (nothing listens) is replaced; a regular file at the path is refused (another path: the
    // first listener's lock lives as long as its UnixListen, held by the forgotten workers)
    let p2 = dir.join("s.sock");
    drop(std::os::unix::net::UnixListener::bind(&p2).unwrap());
    let u2 = net::listen_unix(&p2, 0o600, 1).unwrap();
    u2.release();
    assert!(!p2.exists());
    drop(u2);
    std::fs::write(&p2, b"x").unwrap();
    assert!(net::listen_unix(&p2, 0o600, 1).is_err(), "not a socket");
    std::fs::remove_file(&p2).unwrap();
    drop((socks, tcp));
    for fd in [w0.ep, w0.inbox.efd, w1.ep, w1.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w0);
    std::mem::forget(w1);
    for f in ["w.sock.lock", "s.sock.lock"] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    let _ = std::fs::remove_dir(&dir);
}

/// 60.34 PROXY protocol on the TCP listener: the source must be in --proxy-protocol-from (else RST at accept); the
/// header's source is the peer and is charged per IP after the header; LOCAL = the real peer; a bad header is reset;
/// a missing one times out after PROXY_SWEEPS sweeps; STOP_CLOSE drops the waiting ones; load and the --max-conns
/// reservation come back to 0 on every exit; what follows the header is the HTTP request.
#[test]
fn proxy_protocol_header_names_the_peer_and_every_exit_releases() {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::fd::FromRawFd;
    let mut cfg = clientip_cfg(&[], 1, false, 1, None);
    {
        let c = Arc::get_mut(&mut cfg).unwrap();
        c.proxy_tcp = true;
        c.proxy_from = Box::new([crate::policy::Cidr::parse("127.0.0.1").unwrap()]);
        c.conn_gate = Some(Arc::new(net::ConnGate::new(100)));
    }
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg.clone(), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let tab = cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let gate = cfg.conn_gate.as_ref().unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    let up = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let local = [&b"\r\n\r\n\x00\r\nQUIT\n"[..], b"\x20\x00\x00\x00"].concat(); // v2 LOCAL
    let send = |src: [u8; 4], pre: &[u8], http: bool| {
        let mut s = connect_from(src, port);
        s.write_all(pre).unwrap();
        if http {
            s.write_all(up.as_bytes()).unwrap();
        }
        s
    };
    let mut socks = vec![
        send([127, 0, 0, 1], b"PROXY TCP4 9.9.9.9 1.1.1.1 1000 443\r\n", true), // 0: admitted as 9.9.9.9
        send([127, 0, 0, 1], b"PROXY TCP4 9.9.9.9 1.1.1.1 1001 443\r\n", true), // 1: 9.9.9.9 again: over 1, RST
        send([127, 0, 0, 1], &local, true),                                     // 2: LOCAL: the real peer 127.0.0.1
        send([127, 0, 0, 2], b"PROXY TCP4 8.8.8.8 1.1.1.1 1 443\r\n", true),    // 3: source not allowed: RST at accept
        send([127, 0, 0, 1], up.as_bytes(), false),                             // 4: no header: bad, RST
        send([127, 0, 0, 1], b"PROXY TCP4 7.7.7", false),                       // 5: partial: waits, then times out
    ];
    std::thread::sleep(Duration::from_millis(30));
    w.accept_on(false);
    let s = &w.stats;
    assert_eq!((s.pp_refused.get(), s.pp_bad.get(), s.pp_ok.get(), s.pp_local.get(), s.refuse_ip_conns.get()), (1, 1, 2, 1, 1));
    // (a refused LOCAL header would not count in pp_local: it is part of pp_ok)
    assert_eq!((w.pending.len(), w.inbox.load.load(Relaxed), gate.used()), (1, 3, 3), "2 clients + 1 waiting");
    assert_eq!((tab.conns(clientip::key("9.9.9.9".parse().unwrap())), tab.conns(clientip::key("127.0.0.1".parse().unwrap()))), (1, 1));
    assert_eq!(w.peer(0).map(|p| p.ip), Some("9.9.9.9".parse().unwrap()), "the header's source is the peer");
    assert_eq!(w.peer(1).map(|p| p.ip), Some("127.0.0.1".parse().unwrap()), "LOCAL: the real peer");
    for i in 0..2u32 {
        w.clients.at(i).readable = true;
        w.read_client(i);
        assert!(w.clients.at(i).state == CState::Open, "the bytes after the header are the HTTP request");
    }
    for (i, want_rst) in [(1, true), (3, true), (4, true)] {
        socks[i].set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let r = socks[i].read(&mut [0u8; 1]);
        assert_eq!(matches!(r, Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset), want_rst, "sock {i}: {r:?}");
    }
    // the rest of a split header completes it; then the partial one times out
    socks.push(send([127, 0, 0, 1], b"PROXY TCP4 6.6.6.6 1.1.1.1 1 443", false)); // 6
    std::thread::sleep(Duration::from_millis(20));
    let before: Vec<RawFd> = w.pending.keys().copied().collect();
    w.accept_on(false);
    socks[6].write_all(b"\r\n").unwrap();
    socks[6].write_all(up.as_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let fd6 = *w.pending.keys().find(|k| !before.contains(k)).unwrap(); // (fd numbers are reused: not the largest)
    w.pending_event(fd6, libc::EPOLLIN as u32);
    assert_eq!((w.pending.len(), w.stats.pp_ok.get()), (1, 3));
    for _ in 0..3 {
        w.pending_sweep();
    }
    assert_eq!((w.pending.len(), w.stats.pp_timeout.get(), w.inbox.load.load(Relaxed)), (0, 1, 3));
    // closed before the header (a health check), and a partial header then a half-close: both released (review)
    let s7 = send([127, 0, 0, 1], b"", false);
    let s8 = send([127, 0, 0, 1], b"PROXY TCP4 1.2", false);
    std::thread::sleep(Duration::from_millis(20));
    let before: Vec<RawFd> = w.pending.keys().copied().collect();
    w.accept_on(false);
    let new: Vec<RawFd> = w.pending.keys().copied().filter(|k| !before.contains(k)).collect();
    assert_eq!((new.len(), w.inbox.load.load(Relaxed)), (2, 5));
    drop(s7);
    s8.shutdown(std::net::Shutdown::Write).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    for fd in new {
        w.pending_event(fd, (libc::EPOLLIN | libc::EPOLLRDHUP) as u32);
    }
    assert_eq!((w.pending.len(), w.inbox.load.load(Relaxed), w.stats.pp_bad.get()), (0, 3, 1), "EOF / partial + RDHUP: dropped");
    // STOP_CLOSE drops a waiting one
    socks.push(send([127, 0, 0, 1], b"PROXY ", false));
    std::thread::sleep(Duration::from_millis(20));
    w.accept_on(false);
    assert_eq!((w.pending.len(), w.inbox.load.load(Relaxed)), (1, 4));
    w.shutdown_step(net::STOP_CLOSE);
    assert!(w.pending.is_empty());
    for i in 0..w.clients.slots.len() as u32 {
        if w.clients.get(i, w.clients.gen(i)).is_some_and(|c| !c.dead) {
            w.close_client(i, Why::ServerClose);
        }
    }
    w.reap_dead();
    assert_eq!((tab.keys(), w.inbox.load.load(Relaxed), gate.used()), (0, 0, 0), "keys, load and reservations released");
    drop(socks);
    for fd in [w.ep, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.34 a --balance hand-over of a PROXY connection: load counted once by the accepting worker for the owner; the
/// owner waits for the header (inbox_ready -> take) and charges the header's source.
#[test]
fn proxy_protocol_after_a_balance_hand_over() {
    use super::*;
    use std::io::Write as _;
    use std::os::fd::FromRawFd;
    let mut cfg = clientip_cfg(&[], 4, true, 2, None);
    {
        let c = Arc::get_mut(&mut cfg).unwrap();
        c.proxy_tcp = true;
        c.proxy_from = Box::new([crate::policy::Cidr::parse("127.0.0.0/8").unwrap()]);
    }
    let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
    let (tx, _rx) = mpsc::channel();
    let mut w0 = Worker::new(cfg.clone(), tx.clone(), 0, peers.clone(), Arc::default()).unwrap();
    let mut w1 = Worker::new(cfg.clone(), tx, 1, peers.clone(), Arc::default()).unwrap();
    let tab = cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w0.lfd)) }.local_addr().unwrap().port();
    w0.inbox.load.fetch_add(1, Relaxed); // w0 looks busier: its next accept goes to w1
    let mut s = connect_from([127, 0, 0, 1], port);
    std::thread::sleep(Duration::from_millis(20));
    w0.accept_on(false);
    assert_eq!((w0.inbox.load.load(Relaxed), w1.inbox.load.load(Relaxed), w0.pending.len()), (1, 1, 0));
    w1.inbox_ready();
    assert_eq!(w1.pending.len(), 1, "waiting on the owner");
    s.write_all(b"PROXY TCP6 2001:db8::5 ::1 1 443\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let fd = *w1.pending.keys().next().unwrap();
    w1.pending_event(fd, libc::EPOLLIN as u32);
    assert_eq!((w1.pending.len(), tab.conns(clientip::key("2001:db8::5".parse().unwrap()))), (0, 1));
    assert_eq!(w1.peer(0).map(|p| p.ip), Some("2001:db8::5".parse().unwrap()));
    w1.close_client(0, Why::ServerClose);
    w1.reap_dead();
    w0.inbox.load.fetch_sub(1, Relaxed);
    assert_eq!((tab.keys(), w0.inbox.load.load(Relaxed), w1.inbox.load.load(Relaxed)), (0, 0, 0));
    drop(s);
    for fd in [w0.ep, w0.inbox.efd, w1.ep, w1.lfd, w1.inbox.efd, w0.lfd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w0);
    std::mem::forget(w1);
}

/// 60.20 C2 / C3b behind a trusted proxy: not charged at accept; the real IP from X-Forwarded-For is charged after
/// the HTTP request (over the limit: 429); no header: not charged (realip_missing); an untrusted peer's header is
/// ignored (its own address is the key).
#[test]
fn trusted_proxy_client_charged_at_upgrade_and_spoofing_ignored() {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::fd::FromRawFd;
    let cfg = clientip_cfg(&["127.0.0.1"], 1, false, 1, None);
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg.clone(), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let tab = cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    let up = |xff: Option<&str>| {
        let h = xff.map_or(String::new(), |x| format!("X-Forwarded-For: {x}\r\n"));
        format!("GET / HTTP/1.1\r\nHost: x\r\n{h}Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    };
    let k = |s: &str| clientip::key(s.parse().unwrap());
    // proxy (127.0.0.1): A, A again (over 1: 429), B, no header; spoofer (127.0.0.2) claiming B
    let reqs = [
        ([127, 0, 0, 1], Some("6.6.6.6, 9.9.9.9")),
        ([127, 0, 0, 1], Some("9.9.9.9")),
        ([127, 0, 0, 1], Some("8.8.8.8")),
        ([127, 0, 0, 1], None),
        ([127, 0, 0, 2], Some("7.7.7.7")),
    ];
    let mut socks = Vec::new();
    for (src, xff) in reqs {
        let mut s = connect_from(src, port);
        s.write_all(up(xff).as_bytes()).unwrap();
        socks.push(s);
    }
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    assert_eq!((tab.conns(k("127.0.0.1")), tab.conns(k("127.0.0.2"))), (0, 1), "the proxy is not charged at accept");
    for i in 0..5u32 {
        w.clients.at(i).readable = true;
        w.read_client(i);
    }
    assert_eq!((tab.conns(k("9.9.9.9")), tab.conns(k("8.8.8.8")), tab.conns(k("7.7.7.7"))), (1, 1, 0));
    assert_eq!((w.stats.refuse_ip_conns.get(), w.stats.realip_missing.get(), tab.keys()), (1, 1, 3));
    let mut got = w.clients.at(1).obuf.clone(); // queued, or already written to the socket
    let mut b = [0u8; 256];
    socks[1].set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    if let Ok(n) = socks[1].read(&mut b) {
        got.extend_from_slice(&b[..n]);
    }
    assert!(got.starts_with(b"HTTP/1.1 429"), "{:?}", String::from_utf8_lossy(&got));
    assert_eq!(w.peer(0).map(|p| p.ip), Some("9.9.9.9".parse().unwrap()), "rightmost untrusted XFF entry");
    assert_eq!(w.peer(3).map(|p| (p.ip, p.key)), Some(("127.0.0.1".parse().unwrap(), None)));
    assert_eq!(w.peer(4).map(|p| p.ip), Some("127.0.0.2".parse().unwrap()), "spoofed header ignored");
    w.shutdown_step(net::STOP_CLOSE);
    w.reap_dead();
    for _ in 0..5 {
        w.reap_dead();
    }
    for i in 0..5u32 {
        if w.clients.get(i, w.clients.gen(i)).is_some_and(|c| !c.dead) {
            w.close_client(i, Why::ServerClose);
        }
    }
    w.reap_dead();
    assert_eq!((tab.keys(), w.inbox.load.load(Relaxed)), (0, 0), "every charged key released");
    for fd in [w.ep, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    drop(socks);
    std::mem::forget(w);
}

/// 60.40 --conn-rate-per-ip: a direct peer over its rate is reset at accept (refuse_ip_connrate, not refuse_ip_conns),
/// closing its connections does not give its tokens back, and behind a trusted proxy the header's client over its rate
/// gets 429 after the HTTP request (the proxy itself is not charged).
#[test]
fn conn_rate_per_ip_at_accept_and_at_upgrade() {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::fd::FromRawFd;
    let rated = |trusted: &[&str]| {
        let mut cfg = clientip_cfg(trusted, 0, false, 1, None);
        // 1 per 1000 s (none comes back during the test), burst 2
        Arc::get_mut(&mut cfg).unwrap().clientip.as_mut().unwrap().table =
            Some(clientip::IpTable::with_rates(None, None, Some((1e-6, 2.0))));
        cfg
    };
    let reset = |p: &mut std::net::TcpStream| {
        p.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        matches!(p.read(&mut [0u8; 1]), Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
    };
    // direct peers
    let cfg = rated(&[]);
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg.clone(), tx.clone(), 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let tab = cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    let k1 = clientip::key("127.0.0.1".parse().unwrap());
    let mut peers: Vec<_> = (0..3).map(|_| connect_from([127, 0, 0, 1], port)).collect();
    peers.push(connect_from([127, 0, 0, 2], port));
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    let s = &w.stats;
    assert_eq!((tab.conns(k1), s.refuse_ip_connrate.get(), s.refuse_ip_conns.get(), w.inbox.load.load(Relaxed)), (2, 1, 0, 3));
    assert_eq!(peers.iter_mut().map(reset).filter(|&r| r).count(), 1, "the third from 127.0.0.1 got an RST");
    w.close_client(0, Why::ClientClose);
    w.close_client(1, Why::ClientClose);
    w.reap_dead();
    assert_eq!((tab.conns(k1), tab.keys()), (0, 2), "127.0.0.1's drained bucket is kept with no connection");
    let mut again = connect_from([127, 0, 0, 1], port);
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    assert!(reset(&mut again), "reconnecting does not reset the bucket");
    assert_eq!(w.stats.refuse_ip_connrate.get(), 2);
    w.shutdown_step(net::STOP_CLOSE);
    w.reap_dead();
    assert_eq!((tab.conns(k1), w.inbox.load.load(Relaxed)), (0, 0));
    for fd in [w.ep, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    drop((peers, again));
    std::mem::forget(w);
    // behind a trusted proxy: the header's client, after the HTTP request
    let cfg = rated(&["127.0.0.1"]);
    let mut w = Worker::new(cfg.clone(), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let tab = cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    let up = "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 9.9.9.9\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let mut socks = Vec::new();
    for _ in 0..3 {
        let mut s = connect_from([127, 0, 0, 1], port);
        s.write_all(up.as_bytes()).unwrap();
        socks.push(s);
    }
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    assert_eq!((tab.keys(), w.inbox.load.load(Relaxed)), (0, 3), "the proxy is not charged at accept");
    for i in 0..3u32 {
        w.clients.at(i).readable = true;
        w.read_client(i);
    }
    let k9 = clientip::key("9.9.9.9".parse().unwrap());
    assert_eq!((tab.conns(k9), w.stats.refuse_ip_connrate.get(), w.stats.refuse_ip_conns.get()), (2, 1, 0));
    let mut got = w.clients.at(2).obuf.clone(); // queued, or already written to the socket
    let mut b = [0u8; 256];
    socks[2].set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    if let Ok(n) = socks[2].read(&mut b) {
        got.extend_from_slice(&b[..n]);
    }
    assert!(got.starts_with(b"HTTP/1.1 429"), "{:?}", String::from_utf8_lossy(&got));
    w.shutdown_step(net::STOP_CLOSE);
    for _ in 0..5 {
        w.reap_dead();
    }
    for i in 0..3u32 {
        if w.clients.get(i, w.clients.gen(i)).is_some_and(|c| !c.dead) {
            w.close_client(i, Why::ServerClose);
        }
    }
    w.reap_dead();
    assert_eq!((tab.conns(k9), tab.keys(), w.inbox.load.load(Relaxed)), (0, 1, 0), "released; the drained bucket stays");
    for fd in [w.ep, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    drop(socks);
    std::mem::forget(w);
}

/// 60.18 #16 one cache / in-flight key per name: `cached.test.` hits the entry of `cached.test`; a DNS request carries the
/// name without the trailing dot (the pool makes it absolute); `.` (the root) fails without a lookup.
#[test]
fn trailing_dot_shares_the_dns_cache_key() {
    use super::*;
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(clientip_cfg(&[], 0, false, 1, None), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(std::os::fd::IntoRawFd::into_raw_fd(a)));
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    w.dns_cache.insert("cached.test".into(), (vec![ip], Instant::now()));
    assert!(w.new_target(0, 1, "cached.test.".into(), 80, false, false).is_some());
    assert_eq!((w.stats.dns_hit.get(), w.stats.dns_miss.get()), (1, 0), "the trailing-dot form hits the same entry");
    assert!(w.new_target(0, 3, "fresh.test.".into(), 80, false, false).is_some());
    assert_eq!(rx.try_recv().map(|r: net::DnsReq| r.host), Ok("fresh.test".to_string()), "one key for the in-flight map");
    assert!(w.new_target(0, 5, ".".into(), 80, false, false).is_none());
    assert!(w.new_target(0, 7, "cached.test..".into(), 80, false, false).is_none(), "two dots: refused, not cached.test");
    assert_eq!((w.stats.dns_miss.get(), w.stats.dns_hit.get()), (1, 1), "the root and `..`: no lookup, no cache hit");
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.41 the idle sweep drops cache entries past their TTL (NX 5 s, addresses 30 s), keeps the fresh ones, and gives the
/// table back when nothing is left; the shrink also follows a big expiry.
#[test]
fn idle_sweep_expires_dns_cache_entries() {
    use super::*;
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(clientip_cfg(&[], 0, false, 1, None), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let t0 = Instant::now();
    w.dns_cache.insert("nx.test".into(), (vec![], t0));
    w.dns_cache.insert("pos.test".into(), (vec![ip], t0));
    w.dns_expire(t0 + DNS_NEG_TTL - Duration::from_millis(1));
    assert_eq!(w.dns_cache.len(), 2, "both still fresh");
    w.dns_expire(t0 + DNS_NEG_TTL);
    assert!(!w.dns_cache.contains_key("nx.test") && w.dns_cache.contains_key("pos.test"), "NX gone after 5 s, positive kept");
    w.dns_expire(t0 + DNS_TTL);
    assert!(w.dns_cache.is_empty() && w.dns_cache.capacity() == 0, "positive gone after 30 s, table freed");
    // a full table (the 4096 cap) of NX names: one sweep empties it; a few fresh names keep a small table
    for i in 0..4097 {
        w.dns_cache.insert(format!("n{i}.test"), (vec![], t0));
    }
    let t1 = t0 + Duration::from_secs(10);
    for i in 0..10 {
        w.dns_cache.insert(format!("f{i}.test"), (vec![], t1));
    }
    let big = w.dns_cache.capacity();
    w.dns_expire(t1 + Duration::from_secs(1));
    assert_eq!(w.dns_cache.len(), 10);
    assert!(w.dns_cache.capacity() < big / 16, "shrunk: {} of {big}", w.dns_cache.capacity());
    // wired into idle_sweep: an NX entry 6 s old goes at the next due sweep, and so does the table of a map emptied
    // by lookups (remove + a refused re-resolve): capacity, not len, keeps the sweep (and the idle wake) on
    w.dns_cache.clear();
    assert!(w.dns_cache.is_empty() && w.dns_cache.capacity() > 0);
    w.next_sweep = Instant::now();
    assert!(w.idle_sweep());
    assert_eq!(w.dns_cache.capacity(), 0, "an empty map with slots is given back");
    if let Some(old) = Instant::now().checked_sub(Duration::from_secs(6)) {
        w.dns_cache.insert("old-nx.test".into(), (vec![], old));
        w.next_sweep = Instant::now();
        assert!(w.idle_sweep());
        assert!(w.dns_cache.is_empty() && w.dns_cache.capacity() == 0, "expired by the idle sweep");
    }
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.41 measurement (ignored; run on a timing box: `--ignored --nocapture dns_expire_cost`): one expiry sweep over a
/// full table (4097 NX entries with 253-byte names), all expired / none expired.
#[test]
#[ignore]
fn dns_expire_cost() {
    use super::*;
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(clientip_cfg(&[], 0, false, 1, None), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    for len in [21usize, 253] {
        let (mut all, mut none) = (Vec::new(), Vec::new());
        for _ in 0..21 {
            let t0 = Instant::now();
            for i in 0..4097 {
                let mut n = format!("{i:08}.");
                n.extend(std::iter::repeat_n('x', len - n.len()));
                w.dns_cache.insert(n, (vec![], t0));
            }
            let s = Instant::now();
            w.dns_expire(t0); // none expired
            none.push(s.elapsed().as_micros());
            let s = Instant::now();
            w.dns_expire(t0 + DNS_NEG_TTL); // all expired
            all.push(s.elapsed().as_micros());
        }
        all.sort();
        none.sort();
        println!(
            "dns_expire 4097 x {len} B: none expired median {} us max {}; all expired median {} us max {}",
            none[10], none[20], all[10], all[20]
        );
    }
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.24 --log-conns: one conn_close line per adopted connection, the first reason wins at each close path, peers_of is
/// filled without C2/C3b, rx/tx are the socket's wire bytes, and accept-time refusals are flood-limited.
#[test]
fn conn_log_lines_name_the_close_reason() {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::fd::FromRawFd;
    let mut cfg = Arc::into_inner(clientip_cfg(&[], 0, false, 1, None)).unwrap();
    (cfg.clientip, cfg.log_conns, cfg.want_peer, cfg.max_streams_per_conn) = (None, true, true, 1);
    cfg.conn_gate = Some(Arc::new(net::ConnGate::new(5)));
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    let up = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let mut socks: Vec<std::net::TcpStream> = (0..5u8).map(|i| connect_from([127, 0, 0, 10 + i], port)).collect();
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    assert_eq!(w.peer(2).map(|p| p.ip), Some("127.0.0.12".parse().unwrap()), "peers_of filled for the log alone");
    // 25 more over --max-conns 5 are reset at accept: 20 conn_refused lines in this second, the rest counted
    let more: Vec<_> = (0..25u8).map(|i| connect_from([127, 0, 1, i], port)).collect();
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    assert_eq!(w.stats.refuse_conns.get(), 25);
    let feed = |w: &mut Worker, i: u32| {
        std::thread::sleep(Duration::from_millis(10));
        if w.clients.get(i, w.clients.gen(i)).is_some_and(|c| !c.dead) {
            w.clients.at(i).readable = true;
            w.read_client(i);
            w.flush_dirty();
        }
    };
    let ws = |p: &[u8], masked: bool| {
        let mut f = vec![0x82, p.len() as u8 | if masked { 0x80 } else { 0 }];
        if masked {
            f.extend([0u8; 4]);
        }
        f.extend(p);
        f
    };
    let connect = |sid: u32| {
        let mut p = vec![0x01u8];
        p.extend(sid.to_le_bytes());
        p.extend([1u8, 80, 0]);
        p.extend(b"127.0.0.1");
        ws(&p, true)
    };
    // 0: v1, two CONNECTs (the second over --max-streams-per-conn 1), then a WS Close (client_close; the drained
    // close after it keeps that reason)
    socks[0].write_all(up.as_bytes()).unwrap();
    feed(&mut w, 0);
    let mut b = [0u8; 4096];
    socks[0].set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let n101 = socks[0].read(&mut b).unwrap();
    assert!(b.starts_with(b"HTTP/1.1 101"));
    let sent = [connect(1), connect(2), vec![0x88, 0x82, 0, 0, 0, 0, 0x03, 0xe8]].concat();
    socks[0].write_all(&sent).unwrap();
    feed(&mut w, 0);
    // 1: not HTTP (400: protocol_error); 2: an unmasked frame (ws_error); 3: EOF (client_close); 4: server shutdown
    socks[1].write_all(b"NOT HTTP\r\n\r\n").unwrap();
    feed(&mut w, 1);
    socks[2].write_all(up.as_bytes()).unwrap();
    feed(&mut w, 2);
    socks[2].write_all(&ws(&[0, 1, 2], false)).unwrap();
    feed(&mut w, 2);
    socks[3].shutdown(std::net::Shutdown::Write).unwrap();
    feed(&mut w, 3);
    w.shutdown_step(net::STOP_CLOSE);
    for i in 0..5 {
        feed(&mut w, i);
    }
    for i in 0..5u32 {
        if w.clients.get(i, w.clients.gen(i)).is_some_and(|c| !c.dead) {
            w.close_client(i, Why::ServerClose);
        }
    }
    w.reap_dead();
    let mut all = Vec::new();
    assert_eq!(w.outbox.as_ref().unwrap().take(&mut all), 0, "nothing dropped");
    let text = String::from_utf8(all).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| l.contains("ev=conn_close")).collect();
    assert_eq!(lines.len(), 5, "{text}");
    let field = |l: &str, k: &str| l.split(' ').find_map(|f| f.strip_prefix(&format!("{k}="))).unwrap_or("").to_string();
    let by_ip = |ip: &str| *lines.iter().find(|l| field(l, "ip") == ip).unwrap_or_else(|| panic!("{ip}: {text}"));
    let l0 = by_ip("127.0.0.10");
    assert_eq!((field(l0, "why"), field(l0, "proto"), field(l0, "auth")), ("client_close".into(), "v1".into(), "none".into()));
    assert_eq!((field(l0, "streams"), field(l0, "refused"), field(l0, "tls")), ("1".into(), "1".into(), "0".into()));
    let (rx, tx_) = (field(l0, "rx").parse::<usize>().unwrap(), field(l0, "tx").parse::<usize>().unwrap());
    assert!(rx == up.len() + sent.len() && tx_ >= n101, "rx {rx} tx {tx_}: wire bytes");
    assert!(l0.starts_with("finalwisp: ev=conn_close ts=20") && field(l0, "cid") == "0:1" && field(l0, "w") == "0", "{l0}");
    let w1 = by_ip("127.0.0.11");
    assert_eq!((field(w1, "why"), field(w1, "proto")), ("protocol_error".into(), "http".into()));
    assert_eq!(field(by_ip("127.0.0.12"), "why"), "ws_error");
    assert_eq!(field(by_ip("127.0.0.13"), "why"), "client_close");
    assert_eq!(field(by_ip("127.0.0.14"), "why"), "server_close");
    assert!(lines.iter().all(|l| !l.contains("via=")), "no proxy");
    let refused: Vec<&str> = text.lines().filter(|l| l.contains("ev=conn_refused")).collect();
    let suppressed = w.outbox.as_ref().unwrap().suppressed.load(Relaxed);
    // (a second boundary inside the burst lets a few more through)
    assert!(refused.len() >= 20 && refused.len() as u64 + suppressed == 25, "{} + {suppressed}", refused.len());
    assert!(refused.iter().all(|l| field(l, "why") == "limit" && field(l, "ip").starts_with("127.0.1.") && field(l, "cid").is_empty()));
    for fd in [w.ep, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    drop((socks, more));
    std::mem::forget(w);
}

/// 60.24 review: a failed read or write is named by errno and the TX record budget
#[test]
fn io_why_names_the_failure() {
    use super::connlog::io_why;
    use super::Why;
    assert_eq!(io_why(libc::ECONNRESET, true, 5), Why::ClientClose);
    assert_eq!(io_why(libc::EPIPE, false, 5), Why::ClientClose);
    assert_eq!(io_why(libc::ETIMEDOUT, true, 5), Why::DeadPeer);
    assert_eq!(io_why(libc::EBADMSG, true, 5), Why::TlsError);
    assert_eq!(io_why(libc::EBADMSG, false, 5), Why::ClientClose);
    assert_eq!(io_why(libc::EAGAIN, true, 0), Why::TlsError, "AEAD limit (errno stale)");
}

/// 60.30 C10a --download-rate: the listener's SO_MAX_PACING_RATE is on the accepted client socket, also after a --balance
/// hand-over (the same fd); --upload-rate-per-stream: `won` puts the cap and the 1/8 s lowat on the connected target.
/// Off: neither socket has a cap. (Removing the listener or the `won` hook fails this test.)
#[test]
fn pacing_caps_on_clients_and_targets() {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    let lowat = |fd: i32| {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NOTSENT_LOWAT, &mut v as *mut _ as *mut _, &mut len) };
        v as u32
    };
    for pace in [net::Pacing { download: 2 << 20, upload: 1 << 20 }, net::Pacing::default()] {
        let mk = || {
            let mut c = Arc::into_inner(clientip_cfg(&[], 0, true, 2, None)).unwrap();
            (c.clientip, c.want_peer, c.pace) = (None, false, pace);
            Arc::new(c)
        };
        let peers = Arc::new(vec![Inbox::new(), Inbox::new()]);
        let (tx, _rx) = mpsc::channel();
        let mut w0 = Worker::new(mk(), tx.clone(), 0, peers.clone(), Arc::default()).unwrap();
        let mut w1 = Worker::new(mk(), tx, 1, peers.clone(), Arc::default()).unwrap();
        let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w0.lfd)) }.local_addr().unwrap().port();
        w0.inbox.load.fetch_add(1, Relaxed); // w0 looks busier: its next accept goes to w1
        let _peer = connect_from([127, 0, 0, 1], port);
        std::thread::sleep(Duration::from_millis(20));
        w0.accept_all();
        w1.inbox_ready();
        let none = if pace.download > 0 { pace.download } else { u32::MAX };
        assert_eq!(net::pacing(w1.clients.at(0).fd), Some(none), "the handed-over client socket");
        w1.clients.at(0).state = CState::Open;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (ti, tg) = w1.new_target(0, 1, "127.0.0.1".into(), l.local_addr().unwrap().port(), false, false).unwrap();
        w1.clients.at(0).streams.insert(1, ti);
        w1.run_deferred();
        let _tp = l.accept().unwrap();
        for _ in 0..1000 {
            if w1.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                break;
            }
            w1.target_event(ti, tg, libc::EPOLLOUT as u32);
            std::thread::sleep(Duration::from_millis(1));
        }
        let fd = w1.targets.at(ti).fd;
        assert!(w1.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) && fd.as_raw_fd() >= 0);
        if pace.upload > 0 {
            assert_eq!((net::pacing(fd), lowat(fd)), (Some(pace.upload), net::pace_lowat(pace.upload)));
        } else {
            assert_eq!(net::pacing(fd), Some(u32::MAX));
        }
        assert_eq!(w1.stats.pace_fail.get(), 0);
        if pace.upload > 0 {
            // fail closed: the kernel "refuses" the options (test hook) -> CLOSE 0x03, pace_fail, the fd closed, the
            // stream gone from the client, the pending upload released
            let (ti2, tg2) = w1.new_target(0, 3, "127.0.0.1".into(), l.local_addr().unwrap().port(), false, false).unwrap();
            w1.clients.at(0).streams.insert(3, ti2);
            let p0 = (w1.pend_total, w1.clients.at(0).pend);
            w1.targets.at(ti2).pend.extend_from_slice(&[1u8; 1000]);
            w1.targets.at(ti2).acct = 1000;
            w1.pend_account(0, 1000, 0); // as stage_upload accounts queued upload
            assert_eq!((w1.pend_total, w1.clients.at(0).pend), (p0.0 + 1000, p0.1 + 1000));
            super::connect::PACE_REFUSE.with(|c| c.set(true));
            w1.run_deferred();
            let (mut tp2, _) = l.accept().unwrap();
            for _ in 0..1000 {
                if w1.targets.get(ti2, tg2).is_none() {
                    break;
                }
                w1.target_event(ti2, tg2, libc::EPOLLOUT as u32);
                std::thread::sleep(Duration::from_millis(1));
            }
            super::connect::PACE_REFUSE.with(|c| c.set(false));
            assert!(w1.targets.get(ti2, tg2).is_none(), "the stream is closed");
            assert_eq!((w1.stats.pace_fail.get(), w1.stats.close[0x03].get()), (1, 1));
            assert!(!w1.clients.at(0).streams.contains_key(&3));
            assert_eq!((w1.pend_total, w1.clients.at(0).pend), p0, "the pending upload is released");
            // review r2: the attempt's fd is closed (close_target via t.conn): the target sees EOF (an fd-number check
            // could race with other test threads reusing the number)
            tp2.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            assert_eq!(std::io::Read::read(&mut tp2, &mut [0u8; 1]).unwrap(), 0, "EOF, no data sent");
        }
        w1.close_client(0, Why::ServerClose);
        w1.reap_dead();
        w0.inbox.load.fetch_sub(1, Relaxed);
        for fd in [w0.ep, w0.lfd, w0.inbox.efd, w1.ep, w1.lfd, w1.inbox.efd] {
            unsafe { libc::close(fd) };
        }
        std::mem::forget(w0);
        std::mem::forget(w1);
    }
}

/// 60.30 C10a (review): no adaptive lowat lift for clients under a download cap below LOWAT_FAST
#[test]
fn adapt_lowat_off_under_a_download_cap() {
    use super::adapt_lowat;
    assert_eq!(adapt_lowat(128 << 10, 0), 128 << 10, "default: on, restores the lowat");
    assert_eq!(adapt_lowat(0, 0), 0, "--notsent-lowat 0: off");
    assert_eq!((adapt_lowat(16 << 10, 125_000), adapt_lowat(128 << 10, (1 << 30) - 1)), (0, 0), "capped below 1 GiB/s: off");
    assert_eq!(adapt_lowat(128 << 10, 1 << 30), 128 << 10, "a cap at LOWAT_FAST or above can be passed: on");
}

/// 60.32 C6: a proxied stream through a SOCKS5 proxy played by the test. The side entry (proxy_hs) and the stream go
/// on every exit: a client CLOSE mid-handshake, a refusal (REP 05 -> 0x44), the deadline (0x43, upstream_fail), the
/// client gone; a success is Open with no side entry, and tunnel bytes that came with the reply are read at once.
#[test]
fn upstream_side_entry_released_on_every_exit() {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::fd::IntoRawFd;
    let prox = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let up = crate::upstream::parse_url(&format!("socks5://127.0.0.1:{}", prox.local_addr().unwrap().port())).unwrap();
    up.addrs.publish(Ok(vec!["127.0.0.1".parse().unwrap()]), 0);
    let cfg = Arc::new(Config {
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
        udp: false,
        tls_rekey: 0,
        notsent_lowat: 0,
        adapt_lowat: 0,
        keepalive: true,
        prio: true,
        ext: ext::Ext::default(),
        credit_v2: false,
        credit_pace: false,
        conn_gate: None,
        max_streams_per_conn: 0,
        policy: None,
        clientip: None,
        log_conns: false,
        log_streams: false,
        want_peer: false,
        pace: net::Pacing::default(),
        unix: None,
        upstream: Some(Box::new(up)),
        upload_rate: None,
        proxy_tcp: false,
        proxy_unix: false,
        proxy_from: Box::new([]),
        dest_rate: None,
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (s, _) = l.accept().unwrap();
    s.set_nonblocking(true).unwrap();
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(s.into_raw_fd()));
    peer.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
    let feed = |w: &mut Worker| {
        for _ in 0..100 {
            w.clients.at(0).readable = true;
            w.read_client(0);
            if w.clients.get(0, w.clients.gen(0)).is_none_or(|c| net::inq(c.fd) == 0) {
                break;
            }
        }
    };
    std::thread::sleep(Duration::from_millis(10));
    feed(&mut w);
    assert!(w.clients.at(0).state == CState::Open);
    let pkt = |ty: u8, sid: u32, body: &[u8]| {
        let mut p = vec![ty];
        p.extend(sid.to_le_bytes());
        p.extend(body);
        let mut f = vec![0x82, 0x80 | p.len() as u8, 0, 0, 0, 0]; // masked with a zero key
        f.extend(p);
        f
    };
    let send = |w: &mut Worker, peer: &mut std::net::TcpStream, bytes: Vec<u8>| {
        peer.write_all(&bytes).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        feed(w);
    };
    let n = |w: &mut Worker| w.clients.at(0).streams.len();
    let side = |w: &Worker| w.proxy_hs.iter().filter(|h| h.is_some()).count();
    // CONNECT sid -> the worker connects to the proxy and sends the greeting: (target index, the proxy's side)
    let open = |w: &mut Worker, peer: &mut std::net::TcpStream, sid: u32| {
        send(w, peer, pkt(0x01, sid, &[1, 80, 0, b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1']));
        let ti = *w.clients.at(0).streams.get(&sid).unwrap();
        let (mut ps, _) = prox.accept().unwrap();
        ps.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        for _ in 0..500 {
            if w.targets.at(ti).in_handshake() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
            w.connect_progress(ti);
        }
        assert!(w.targets.at(ti).in_handshake() && w.proxy_hs[ti as usize].is_some());
        let mut g = [0u8; 3];
        ps.read_exact(&mut g).unwrap();
        assert_eq!(g, [5, 1, 0], "greeting: no auth only");
        (ti, ps)
    };
    let event = |w: &mut Worker, ti: u32| {
        std::thread::sleep(Duration::from_millis(5));
        let tg = w.targets.gen(ti);
        w.target_event(ti, tg, libc::EPOLLIN as u32);
    };
    let request = |ps: &mut std::net::TcpStream| {
        let mut r = [0u8; 10];
        ps.read_exact(&mut r).unwrap();
        assert_eq!(r, [5, 1, 0, 1, 127, 0, 0, 1, 0, 80], "CONNECT 127.0.0.1:80, ATYP 1");
    };
    // 1. a client CLOSE mid-handshake
    let (_, mut ps) = open(&mut w, &mut peer, 1);
    send(&mut w, &mut peer, pkt(0x04, 1, &[0x02]));
    assert_eq!((n(&mut w), side(&w)), (0, 0));
    // review: only EOF or a reset proves the close (a read timeout would hide a leaked fd)
    match ps.read(&mut [0u8; 1]) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        r => panic!("the proxy socket is still open: {r:?}"),
    }
    // 2. REP 05 (one target address: no retry) -> CLOSE 0x44, not the proxy's failure
    let (ti, mut ps) = open(&mut w, &mut peer, 2);
    ps.write_all(&[5, 0]).unwrap();
    event(&mut w, ti);
    request(&mut ps);
    ps.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    event(&mut w, ti);
    assert_eq!((n(&mut w), side(&w), w.stats.close[0x44].get(), w.stats.upstream_fail.get()), (0, 0, 1, 0));
    // 3. success, with tunnel bytes in the reply's segment: Open, no side entry, the bytes read at once
    let (ti, mut ps) = open(&mut w, &mut peer, 3);
    ps.write_all(&[5, 0]).unwrap();
    event(&mut w, ti);
    request(&mut ps);
    ps.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0, b'h', b'i']).unwrap();
    event(&mut w, ti);
    let t = w.targets.at(ti);
    assert!(t.state == TState::Open && net::inq(t.fd) == 0, "Open, tunnel bytes taken");
    assert_eq!((n(&mut w), side(&w), w.stats.upstream_ok.get()), (1, 0, 1));
    // 4. the deadline mid-handshake -> 0x43 and upstream_fail
    let (ti, _ps4) = open(&mut w, &mut peer, 4);
    w.targets.at(ti).deadline = Instant::now();
    w.run_timers();
    assert_eq!((n(&mut w), side(&w), w.stats.close[0x43].get(), w.stats.upstream_fail.get()), (1, 0, 1, 1));
    // 4b. a proxy that never answers the SYN (TEST-NET-1; or no route: refused at once): upstream_fail either way.
    // The list moves through ProxyAddrs::publish: the worker picks the new generation up on its next proxied connect.
    let pa = w.cfg.upstream.as_deref().unwrap().addrs.clone();
    pa.publish(Ok(vec!["192.0.2.1".parse().unwrap()]), 1);
    send(&mut w, &mut peer, pkt(0x01, 6, &[1, 80, 0, b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1']));
    if let Some(&ti) = w.clients.at(0).streams.get(&6) {
        assert!(w.targets.at(ti).state == TState::Connecting && w.targets.at(ti).fd < 0);
        assert_eq!(w.targets.at(ti).addrs, vec!["192.0.2.1".parse::<IpAddr>().unwrap()], "the new generation is used");
        w.targets.at(ti).deadline = Instant::now();
        w.next_scan = Instant::now(); // (run_timers scans once per TIMER_TICK_MS)
        w.run_timers();
    }
    assert_eq!((n(&mut w), side(&w), w.stats.upstream_fail.get()), (1, 0, 2));
    pa.publish(Ok(vec!["127.0.0.1".parse().unwrap()]), 2);
    // 5. the client goes away with a stream mid-handshake
    let (_, _ps5) = open(&mut w, &mut peer, 5);
    assert_eq!(side(&w), 1);
    w.close_client(0, connlog::Why::ClientClose);
    assert_eq!(side(&w), 0);
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.25 C10b --upload-rate: a read never takes more than the allowance; a spent allowance pauses the client (lpaused,
/// listed in lwait, no read) until meter_timers resumes it, which reads about rate x elapsed more. (The 70.08 stall rule
/// does not skip a paused client: R >= 8K keeps a limited client's kernel intake above STALL_MIN_BYTES per sweep.)
#[test]
fn upload_rate_pauses_and_resumes() {
    use super::*;
    let cfg = Arc::new(Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        threads: 1,
        buffer: 128,
        filter: net::Filter::new(false, false),
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
        keepalive: true,
        prio: true,
        ext: ext::Ext::default(),
        credit_v2: false,
        credit_pace: false,
        conn_gate: None,
        max_streams_per_conn: 0,
        policy: None,
        clientip: None,
        log_conns: false,
        log_streams: false,
        want_peer: false,
        pace: net::Pacing::default(),
        unix: None,
        adapt_lowat: 0,
        upstream: None,
        upload_rate: Some((8192, 16384)),
        proxy_tcp: false,
        proxy_unix: false,
        proxy_from: Box::new([]),
        dest_rate: None,
    });
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    assert!(w.meter);
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    w.clients.at(ci).state = CState::Open;
    // one masked binary frame of 65535 bytes, 40000 of them sent: a partial frame waits in rbuf
    let mut b = vec![0x82u8, 0x80 | 126, 0xff, 0xff, 1, 2, 3, 4];
    b.resize(8 + 40000, 0x55);
    let n = unsafe { libc::send(fds[1], b.as_ptr() as *const _, b.len(), libc::MSG_DONTWAIT) };
    assert_eq!(n as usize, b.len());
    w.clients.at(ci).readable = true;
    w.read_client(ci);
    let c = w.clients.at(ci);
    assert!(c.rlen <= 16384, "the burst: {}", c.rlen);
    assert!(c.lpaused && w.lwait.len() == 1);
    let first = c.rlen;
    assert!(Worker::meter_blocked(&w.meters, ci as usize), "count_stalls skips a limiter pause of this interval");
    w.meter_sweep();
    assert!(!Worker::meter_blocked(&w.meters, ci as usize), "a new interval starts at the idle sweep");
    w.read_client(ci); // a paused client is not read
    assert_eq!(w.clients.at(ci).rlen, first);
    w.meter_timers(); // not due yet (MIN_ROOM at 8 KiB/s = 0.5 s)
    assert!(w.clients.at(ci).lpaused);
    std::thread::sleep(Duration::from_millis(700));
    w.lscan = 0;
    w.meter_timers();
    assert!(!w.clients.at(ci).lpaused && w.ready.len() == 1);
    w.ready.clear();
    w.read_client(ci);
    let more = w.clients.at(ci).rlen - first;
    assert!((4096..=8192).contains(&more), "about 0.7 s x 8 KiB/s: {more}");
    assert!(w.clients.at(ci).lpaused, "spent again");
    w.close_client(ci, Why::ClientClose);
    w.reap_dead();
    w.lscan = 0; // (the next tick)
    w.meter_timers(); // the entry of a closed client is dropped at the next scan, due or not
    assert!(w.lwait.is_empty());
    for fd in [fds[1], w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.25 C10b (review) a client the limiter paused during a sweep interval is not a 70.08 stall (its baseline
/// restarts); once an interval passes without a limiter pause, the stall rule counts it again. And the release Client
/// stays in its 512-byte slab slot (lpaused uses padding, 60.22).
#[test]
fn upload_limiter_pause_is_not_a_stall() {
    use super::*;
    use std::os::fd::IntoRawFd;
    assert!(std::mem::size_of::<Client>() <= 504 + if cfg!(test) { 32 } else { 0 }, "60.22 slot 512 (test fields aside)");
    let mut cfg = Arc::into_inner(clientip_cfg(&[], 0, false, 1, None)).unwrap();
    cfg.upload_rate = Some((8192, 16384));
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.set_level(2);
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (s, _) = l.accept().unwrap();
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(s.into_raw_fd()));
    let ci = 0;
    let rmax = w.rbuf_max;
    {
        let c = w.clients.at(ci);
        c.state = CState::Open;
        c.need = rmax + 1; // an in-progress frame above rbuf_max that delivers nothing
    }
    w.meters[ci as usize].blocked = true; // (room sets it when it pauses)
    for _ in 0..4 {
        w.count_stalls();
        assert_eq!(w.clients.at(ci).rstall, 0, "limiter-blocked: not a stall");
    }
    w.meter_sweep();
    for k in 1..=3u8 {
        w.count_stalls();
        assert_eq!(w.clients.at(ci).rstall, k, "not blocked: counted from the baseline the last blocked sweep set");
    }
    w.close_client(ci, Why::ClientClose);
    drop(p);
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.25 C10b (review) bytes read before the per-IP key is known (behind a trusted proxy: after the upgrade) are
/// charged to the key once it is; a closing client gives back its unread lease exactly once.
#[test]
fn upload_bootstrap_bytes_charged_to_the_key() {
    use super::*;
    let mut cfg = Arc::into_inner(clientip_cfg(&[], 0, false, 1, None)).unwrap();
    let burst = 1_000_000.0;
    cfg.clientip.as_mut().unwrap().table = Some(clientip::IpTable::with_upload(None, Some((1.0, burst))));
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    assert!(w.meter);
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    w.clients.at(ci).state = CState::Open;
    // a partial binary frame (64 KiB announced, 30000 bytes sent) read while the client has no key
    let mut b = vec![0x82u8, 0x80 | 127];
    b.extend_from_slice(&(64u64 << 10).to_be_bytes());
    b.extend_from_slice(&[1, 2, 3, 4]);
    b.resize(14 + 30000, 0x55);
    assert_eq!(unsafe { libc::send(fds[1], b.as_ptr() as *const _, b.len(), 0) } as usize, b.len());
    w.clients.at(ci).readable = true;
    w.read_client(ci);
    let read = w.clients.at(ci).rlen;
    assert_eq!(read, b.len(), "no key: per-IP not applied yet");
    let cfg = w.cfg.clone();
    let table = cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let k = clientip::key("10.1.2.3".parse().unwrap());
    assert_eq!(table.charge(k, 0, clientip::now_ms()), clientip::Charge::Charged);
    w.peers_of.resize_with(1, || None);
    w.peers_of[0] = Some(clientip::Peer { ip: "10.1.2.3".parse().unwrap(), key: Some(k) });
    w.meter_keyed(ci); // (handle_http after client_ip) the 30014 bootstrap bytes are charged once
    w.meter_keyed(ci);
    assert!((burst - table.upload_left(k).unwrap() - read as f64).abs() < 5.0, "charged once, at the key");
    assert_eq!(unsafe { libc::send(fds[1], [0x55u8; 100].as_ptr() as *const _, 100, 0) }, 100);
    w.clients.at(ci).readable = true;
    w.read_client(ci); // a share is leased
    let left = table.upload_left(k).unwrap();
    let lease = w.meters[0].lease as f64;
    let total = left + lease + read as f64 + 100.0; // (the 100 bytes just read came out of the lease)
    assert!((burst - total).abs() < 5.0, "burst {burst} = left {left} + lease {lease} + boot {read} + 100");
    let key = w.peers_of[0].as_ref().and_then(|p| p.key);
    w.close_client(ci, Why::ClientClose);
    assert_eq!(w.meters[0].lease, 0);
    let back = table.upload_left(k).unwrap_or(burst);
    assert!(key.is_some() && (back - (left + lease)).abs() < 5.0, "the unread lease came back once: {back}");
    for fd in [fds[1], w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.25 merged A/B (review) the top-up at the room level: a lease that covers a read only in part is topped up
/// to the whole read while nobody waits on the key; with a sibling waiting (a ticket out) the read stops at the lease
/// edge as before.
#[test]
fn upload_lease_top_up_in_room() {
    use super::*;
    let mut cfg = Arc::into_inner(clientip_cfg(&[], 0, false, 1, None)).unwrap();
    cfg.clientip.as_mut().unwrap().table = Some(clientip::IpTable::with_upload(None, Some((1.0, 1_000_000.0))));
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(fds[0]));
    let ci = 0;
    w.clients.at(ci).state = CState::Open;
    let cfg = w.cfg.clone();
    let table = cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let k = clientip::key("10.1.2.4".parse().unwrap());
    assert_eq!(table.charge(k, 0, clientip::now_ms()), clientip::Charge::Charged);
    w.peers_of.resize_with(1, || None);
    w.peers_of[0] = Some(clientip::Peer { ip: "10.1.2.4".parse().unwrap(), key: Some(k) });
    w.meter_keyed(ci);
    let room = |w: &mut Worker, space: usize| {
        let c = w.clients.at(ci);
        meter::room(&mut w.meters, &mut w.lwait, &w.cfg, &w.peers_of, &w.stats, c, ci, 0, space)
    };
    // nobody waits: a 16 KiB lease against 240000 bytes of room is topped up to the whole read
    w.meters[0].lease = 16_384;
    let left = table.upload_left(k).unwrap();
    assert_eq!(room(&mut w, 240_000), 240_000, "one read, not two");
    assert_eq!(w.meters[0].lease, 240_000);
    assert!((left - table.upload_left(k).unwrap() - (240_000.0 - 16_384.0)).abs() < 5.0, "the top-up came from the key");
    // a sibling waits (drained the bucket and holds a ticket): the read stops at the lease edge, nothing is taken
    let mut sib = None;
    while table.take_bytes(k, 4096, &mut sib).unwrap() > 0 {}
    assert!(sib.is_some());
    w.meters[0].lease = 16_384;
    assert_eq!(room(&mut w, 240_000), 16_384, "a ticket is out: the old lease edge");
    assert_eq!(w.meters[0].lease, 16_384);
    for fd in [fds[1], w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.35 --log-streams: one stream_close line per stream with its reason (target EOF, client CLOSE, connection end,
/// policy after DNS with the rule, DNS failure), exact TCP bytes from TCP_INFO, UDP datagram and byte counts, the dst,
/// stream_refused lines for CONNECTs refused before a target (rule= from the C1 request rules) with the flood limit;
/// off: the side vector stays empty.
#[test]
fn stream_log_lines_name_the_reason() {
    use super::*;
    use std::io::{Read as _, Write as _};
    let run = |on: bool| {
        let mut cfg = Arc::into_inner(clientip_cfg(&[], 0, false, 1, None)).unwrap();
        cfg.clientip = None;
        cfg.log_streams = on;
        let rules = crate::policy::Rules {
            direct_ip: true,
            ipv6: true,
            block_ports: vec![crate::policy::PortRule::parse("22").unwrap()],
            ..Default::default()
        };
        cfg.policy = crate::policy::Policy::new(&rules).map(Box::new);
        let (tx, _rx) = mpsc::channel();
        let mut w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
        w.inbox.load.fetch_add(1, Relaxed);
        w.adopt(net::Handoff::bare(fds[0]));
        let ci = 0;
        w.clients.at(ci).state = CState::Open;
        w.clients.at(ci).hs_credit = 128;
        let msg = |ty: u8, sid: u32, body: &[u8]| [&[ty][..], &sid.to_le_bytes(), body].concat();
        let connect = |stype: u8, port: u16, host: &str| [&[stype][..], &port.to_le_bytes(), host.as_bytes()].concat();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let lport = l.local_addr().unwrap().port();
        let ti_of = |w: &mut Worker, sid: u32| w.clients.at(ci).streams.get(&sid).copied();
        let open = |w: &mut Worker, sid: u32| -> std::net::TcpStream {
            w.on_message(ci, &msg(1, sid, &connect(1, lport, "127.0.0.1")));
            w.run_deferred();
            let (peer, _) = l.accept().unwrap();
            let ti = ti_of(w, sid).unwrap();
            let tg = w.targets.gen(ti);
            for _ in 0..1000 {
                if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                    break;
                }
                w.target_event(ti, tg, libc::EPOLLOUT as u32);
                std::thread::sleep(Duration::from_millis(1));
            }
            peer
        };
        // sid 1: 5 bytes up, 7 down, then the target closes (0x02 target_close)
        let mut p1 = open(&mut w, 1);
        w.on_message(ci, &msg(2, 1, b"hello"));
        let ti = ti_of(&mut w, 1).unwrap();
        let tg = w.targets.gen(ti);
        w.target_event(ti, tg, libc::EPOLLOUT as u32);
        let mut b = [0u8; 16];
        p1.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        p1.read_exact(&mut b[..5]).unwrap();
        p1.write_all(b"goodbye").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        w.target_event(ti, tg, libc::EPOLLIN as u32);
        drop(p1);
        std::thread::sleep(Duration::from_millis(20));
        for _ in 0..10 {
            if w.targets.get(ti, tg).is_none() {
                break;
            }
            w.target_event(ti, tg, (libc::EPOLLIN | libc::EPOLLRDHUP) as u32);
        }
        // sid 3: the client sends CLOSE (client_close, no reason sent); sid 11: the connection ends (conn_close)
        let _p3 = open(&mut w, 3);
        w.on_message(ci, &msg(4, 3, &[2]));
        let _p11 = open(&mut w, 11);
        // sid 5: port 22 (request rule: stream_refused rule=ports); sid 7: bad stream type (invalid)
        w.on_message(ci, &msg(1, 5, &connect(1, 22, "example.com")));
        w.on_message(ci, &msg(1, 7, &connect(9, 80, "example.com")));
        // sid 9: a private literal, refused after "DNS" by the address rules (stream_close why=policy rule=private)
        w.on_message(ci, &msg(1, 9, &connect(1, 80, "10.0.0.1")));
        w.run_deferred();
        // sid 13: `a..` gets 0x42 at once (dns_fail); its host is logged as sent, escaped: a hostile host stays one field
        w.on_message(ci, &msg(1, 13, &connect(1, 80, "a..")));
        w.on_message(ci, &msg(1, 15, &connect(1, 80, "x\" why=fake")));
        // sid 17: UDP, 3 datagrams up (4+5+6 bytes), 2 down (10 bytes each), then CLOSE
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        w.on_message(ci, &msg(1, 17, &connect(2, u.local_addr().unwrap().port(), "127.0.0.1")));
        w.run_deferred();
        let uti = ti_of(&mut w, 17).unwrap();
        let utg = w.targets.gen(uti);
        let mut from = None;
        for n in [4usize, 5, 6] {
            w.on_message(ci, &msg(2, 17, &vec![1u8; n]));
            let (k, a) = u.recv_from(&mut [0u8; 64]).unwrap();
            assert_eq!(k, n);
            from = Some(a);
        }
        for _ in 0..2 {
            u.send_to(&[2u8; 10], from.unwrap()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
        w.target_event(uti, utg, libc::EPOLLIN as u32);
        w.on_message(ci, &msg(4, 17, &[2]));
        // 25 more refusals (port 22): with sids 5, 7 and 15, 28 stream_refused in all; at most 20 per second are lines
        for sid in 0..25u32 {
            w.on_message(ci, &msg(1, 101 + 2 * sid, &connect(1, 22, "example.com")));
        }
        w.close_client(ci, Why::ServerClose);
        w.reap_dead();
        let (mut all, sup) = (Vec::new(), w.outbox.as_ref().map(|o| o.stream_suppressed.load(Relaxed)));
        if let Some(o) = &w.outbox {
            assert_eq!(o.take(&mut all), 0, "nothing dropped");
        }
        let empty = w.streamlog.iter().all(Option::is_none);
        for fd in [w.ep, w.lfd, w.inbox.efd] {
            unsafe { libc::close(fd) };
        }
        std::mem::forget(w);
        (String::from_utf8(all).unwrap(), sup, empty)
    };
    let (off, sup, _) = run(false);
    assert!(off.is_empty() && sup.is_none(), "off: no outbox, no lines: {off}");
    let (text, sup, empty) = run(true);
    assert!(empty, "every entry taken at close");
    let field = |l: &str, k: &str| l.split(' ').find_map(|f| f.strip_prefix(&format!("{k}="))).unwrap_or("").to_string();
    let closes: Vec<&str> = text.lines().filter(|l| l.contains("ev=stream_close")).collect();
    let by_sid = |sid: u32| *closes.iter().find(|l| field(l, "sid") == sid.to_string()).unwrap_or_else(|| panic!("sid {sid}: {text}"));
    let l1 = by_sid(1);
    assert!(l1.starts_with("finalwisp: ev=stream_close ts=") && l1.contains(" w=0 cid=0:1 ip=- sid=1 t=tcp host=127.0.0.1 "), "{l1}");
    assert_eq!(
        [field(l1, "up"), field(l1, "down"), field(l1, "reason"), field(l1, "why"), field(l1, "dst")],
        ["5", "7", "0x02", "target_close", "127.0.0.1"],
        "{l1}"
    );
    assert_eq!([field(by_sid(3), "reason"), field(by_sid(3), "why")], ["none", "client_close"]);
    assert_eq!(field(by_sid(11), "why"), "conn_close");
    assert_eq!([field(by_sid(9), "reason"), field(by_sid(9), "why"), field(by_sid(9), "rule")], ["0x48", "policy", "private"]);
    assert_eq!([field(by_sid(13), "host"), field(by_sid(13), "reason"), field(by_sid(13), "why")], ["a..", "0x42", "dns_fail"]);
    let u = by_sid(17);
    assert_eq!(
        [field(u, "t"), field(u, "up"), field(u, "down"), field(u, "dgrams_up"), field(u, "dgrams_down"), field(u, "why")],
        ["udp", "15", "20", "3", "2", "client_close"],
        "{u}"
    );
    assert_eq!(closes.len(), 6, "{text}");
    let refused: Vec<&str> = text.lines().filter(|l| l.contains("ev=stream_refused")).collect();
    let r5 = refused.iter().find(|l| field(l, "sid") == "5").unwrap();
    assert!(r5.ends_with(" sid=5 t=tcp host=example.com port=22 reason=0x48 why=policy rule=ports"), "{r5}");
    let r7 = refused.iter().find(|l| field(l, "sid") == "7").unwrap();
    assert!(r7.contains(" t=- host=example.com port=80 reason=0x41 why=invalid"), "{r7}");
    let r15 = refused.iter().find(|l| field(l, "sid") == "15").unwrap();
    assert!(r15.contains(r#" host="x\" why=fake" port=80 "#) && r15.ends_with(" reason=0x41 why=invalid"), "{r15}"); // (a space: not a valid host)
    let sup = sup.unwrap() as usize;
    assert!((20..=28).contains(&refused.len()) && refused.len() + sup == 28, "{} lines + {sup} suppressed", refused.len());
}

/// 60.39 per-destination limits: a Config with `dest` and, if given, an upstream proxy (socks5h: names go to the proxy)
fn dest_cfg(dest: crate::destrate::DestTable, upstream: Option<crate::upstream::Upstream>) -> std::sync::Arc<super::Config> {
    use super::*;
    Arc::new(Config {
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
        conn_gate: None,
        max_streams_per_conn: 0,
        policy: None,
        clientip: None,
        log_conns: false,
        log_streams: true,
        want_peer: true, // (--log-streams wants the peer)
        pace: net::Pacing::default(),
        unix: None,
        upstream: upstream.map(Box::new),
        upload_rate: None,
        proxy_tcp: false,
        proxy_unix: false,
        proxy_from: Box::new([]),
        dest_rate: Some(Box::new(dest)),
        credit_pace: false,
    })
}

/// 60.39 one open Wisp client on worker `w` (slot 0): (peer socket, send = write + feed)
fn dest_client(w: &mut super::Worker) -> std::net::TcpStream {
    use super::*;
    use std::io::Write as _;
    use std::os::fd::IntoRawFd;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (s, _) = l.accept().unwrap();
    s.set_nonblocking(true).unwrap();
    w.inbox.load.fetch_add(1, Relaxed);
    w.adopt(net::Handoff::bare(s.into_raw_fd()));
    peer.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(10));
    dest_feed(w);
    assert!(w.clients.at(0).state == CState::Open);
    peer
}

fn dest_feed(w: &mut super::Worker) {
    use super::*;
    for _ in 0..100 {
        w.clients.at(0).readable = true;
        w.read_client(0);
        if w.clients.get(0, w.clients.gen(0)).is_none_or(|c| net::inq(c.fd) == 0) {
            break;
        }
    }
}

/// 60.39 one CONNECT with a host too long for dest_send's 7-bit frame length (16-bit WebSocket length)
fn dest_send_long(w: &mut super::Worker, peer: &mut std::net::TcpStream, sid: u32, host: &str) {
    use super::*;
    use std::io::Write as _;
    let mut p = vec![0x01];
    p.extend(sid.to_le_bytes());
    p.push(1);
    p.extend(443u16.to_le_bytes());
    p.extend(host.as_bytes());
    let mut f = vec![0x82, 0x80 | 126];
    f.extend((p.len() as u16).to_be_bytes());
    f.extend([0, 0, 0, 0]); // masked with a zero key
    f.extend(p);
    peer.write_all(&f).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    dest_feed(w);
}

/// 60.39 the stream lines written so far (reap_dead flushes the closed streams' lines to the outbox)
fn dest_log(w: &mut super::Worker) -> String {
    w.reap_dead();
    let mut all = Vec::new();
    if let Some(o) = &w.outbox {
        o.take(&mut all);
    }
    String::from_utf8(all).unwrap()
}

fn dest_send(w: &mut super::Worker, peer: &mut std::net::TcpStream, frames: &[(u32, u8, u16, &str)]) {
    use super::*;
    use std::io::Write as _;
    let mut bytes = Vec::new();
    for &(sid, ty, port, host) in frames {
        let mut p = vec![0x01];
        p.extend(sid.to_le_bytes());
        p.push(ty);
        p.extend(port.to_le_bytes());
        p.extend(host.as_bytes());
        bytes.extend([0x82, 0x80 | p.len() as u8, 0, 0, 0, 0]); // masked with a zero key
        bytes.extend(p);
    }
    peer.write_all(&bytes).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    dest_feed(w);
    w.run_deferred();
}

#[test]
fn dest_rate_keys_on_the_resolved_address_and_refuses_with_0x49() {
    use super::*;
    let up = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let uport = up.local_addr().unwrap().port();
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let oport = other.local_addr().unwrap().port();
    // burst 3 per second (refill 1/s: nothing comes back unless the test stalls for a second), and a minute bucket of 4
    let cfg = dest_cfg(crate::destrate::DestTable::new(Some((1, 3)), Some(4)), None);
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let mut peer = dest_client(&mut w);
    let st = w.stats.clone();
    dest_send(&mut w, &mut peer, &[(1, 1, uport, "127.0.0.1"), (2, 1, uport, "127.0.0.1"), (3, 2, uport, "127.0.0.1")]);
    assert_eq!((st.refuse_dest_rate.get(), st.close[0x49].get()), (0, 0), "burst 3 (a UDP stream counts too)");
    dest_send(&mut w, &mut peer, &[(4, 1, uport, "::ffff:127.0.0.1"), (5, 1, oport, "127.0.0.1")]);
    assert_eq!(
        (st.refuse_dest_rate.get(), st.close[0x49].get()),
        (1, 1),
        "the 4th to 127.0.0.1:uport (mapped = IPv4); another port is its own key"
    );
    assert!(!w.clients.at(0).streams.contains_key(&4) && w.clients.at(0).streams.contains_key(&5));
    // a name that resolves to the same address shares the key: refused after its DNS answer (one lookup, then 0x49)
    dest_send(&mut w, &mut peer, &[(6, 1, uport, "site.test")]);
    let req = rx.try_recv().unwrap();
    let a1: IpAddr = "127.0.0.1".parse().unwrap();
    w.inbox.q.lock().unwrap().push(net::DnsResp { host: req.host, token: req.token, addrs: vec![a1], nx: false, more: false });
    w.inbox_ready();
    assert_eq!(st.refuse_dest_rate.get(), 2);
    assert!(!w.clients.at(0).streams.contains_key(&6));
    assert!(!w.clients.at(0).dead && !w.clients.at(0).closing, "a refused stream, not a refused connection");
    // the stream log names the rule
    let lines = dest_log(&mut w);
    assert_eq!(lines.lines().filter(|l| l.ends_with(" reason=0x49 why=limit rule=dest_rate")).count(), 2, "{lines}");
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

#[test]
fn dest_rate_minute_refusal_and_socks5h_names() {
    use super::*;
    let prox = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let up = crate::upstream::parse_url(&format!("socks5h://127.0.0.1:{}", prox.local_addr().unwrap().port())).unwrap();
    up.addrs.publish(Ok(vec!["127.0.0.1".parse().unwrap()]), 0);
    assert!(up.remote_dns);
    // minute bucket only: 2 per name and port
    let cfg = dest_cfg(crate::destrate::DestTable::new(None, Some(2)), Some(up));
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let mut peer = dest_client(&mut w);
    let st = w.stats.clone();
    dest_send(&mut w, &mut peer, &[(1, 1, 443, "Site.Test"), (2, 1, 443, "site.test."), (3, 1, 443, "SITE.test")]);
    assert!(rx.try_recv().is_err(), "socks5h: no local lookup");
    assert_eq!((st.refuse_dest_rate.get(), st.close[0x49].get()), (1, 1), "case and one trailing dot fold into one key");
    assert!(w.clients.at(0).streams.contains_key(&2) && !w.clients.at(0).streams.contains_key(&3));
    dest_send(&mut w, &mut peer, &[(4, 1, 443, "other.test"), (5, 1, 80, "site.test")]);
    assert_eq!(st.refuse_dest_rate.get(), 1, "another name, another port: other keys");
    let lines = dest_log(&mut w);
    assert!(lines.lines().any(|l| l.ends_with(" reason=0x49 why=limit rule=dest_rate_minute")), "{lines}");
    // review: a name the proxy cannot take (over 255 bytes with its trailing dot: 0x42) spends no token
    let long = "a".repeat(63) + "." + &"b".repeat(63) + "." + &"c".repeat(63) + "." + &"d".repeat(63); // 255 bytes
    let keys = w.cfg.dest_rate.as_ref().unwrap().keys();
    dest_send_long(&mut w, &mut peer, 6, &long);
    assert_eq!((w.cfg.dest_rate.as_ref().unwrap().keys(), st.close[0x42].get()), (keys, 1), "0x42, no new key");
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

#[test]
fn dest_rate_charges_a_udp_stream_once_across_early_and_final_answers() {
    use super::*;
    // review: an early answer whose UDP connects all fail leaves the stream Resolving without addresses; the final
    // answer goes through start_connect again and must not take a second token. 255.255.255.255 is allowed here
    // (--allow-dest) so that its UDP connect fails at once (EACCES without SO_BROADCAST).
    let mut c = Arc::into_inner(dest_cfg(crate::destrate::DestTable::new(Some((1, 5)), None), None)).unwrap();
    c.filter = net::Filter { allow_dests: vec![policy::Cidr::parse("255.255.255.255").unwrap()].into(), ..net::Filter::new(true, false) };
    let (tx, rx) = mpsc::channel();
    let mut w = Worker::new(Arc::new(c), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let mut peer = dest_client(&mut w);
    let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let uport = u.local_addr().unwrap().port();
    dest_send(&mut w, &mut peer, &[(1, 2, uport, "dual.test")]);
    let req = rx.try_recv().unwrap();
    let (h, token) = (req.host.clone(), req.token);
    let keys = |w: &Worker| w.cfg.dest_rate.as_ref().unwrap().keys();
    w.inbox.q.lock().unwrap().push(net::DnsResp {
        host: h.clone(),
        token,
        addrs: vec!["255.255.255.255".parse().unwrap()],
        nx: false,
        more: true,
    });
    w.inbox_ready();
    let ti = *w.clients.at(0).streams.get(&1).unwrap();
    let t = w.targets.at(ti);
    assert!(t.state == TState::Resolving && t.addrs.is_empty() && t.err != 0 && t.dns_more, "the early UDP connect failed");
    assert_eq!(keys(&w), 1, "charged at the early answer");
    w.inbox.q.lock().unwrap().push(net::DnsResp { host: h, token, addrs: vec!["127.0.0.1".parse().unwrap()], nx: false, more: false });
    w.inbox_ready();
    assert!(w.targets.at(ti).state == TState::Open, "the final answer opened the stream");
    assert_eq!((keys(&w), w.stats.refuse_dest_rate.get()), (1, 0), "no second token for the same stream");
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}

/// 60.42 --credit-pace: a due CONTINUE waits while the stream's target is parked (Target::blocked) and goes out when a
/// resume reads the target without parking it again (pace_resume); a resume that parks it again keeps it held; off, it
/// goes out at once. Base rule (refill 128 at half) and the credit v2 top-up both; slot reuse does not inherit a hold.
#[test]
fn credit_pace_holds_grants_while_the_target_is_parked() {
    use super::*;
    for (v2, pace) in [(false, false), (false, true), (true, true)] {
        let cfg = Arc::new(Config {
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
            credit_v2: v2,
            credit_pace: pace,
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
        });
        let (tx, _rx) = mpsc::channel();
        let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
        w.pend_cap = usize::MAX;
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
        w.inbox.load.fetch_add(1, Relaxed);
        w.adopt(net::Handoff::bare(fds[0]));
        let ci = 0;
        w.clients.at(ci).state = CState::Open;
        w.clients.at(ci).hs_credit = 128;
        assert!(w.clients.at(ci).cv.is_none(), "60.13: no Pinger before the first CONTINUE");
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (ti, tg) = w.new_target(ci, 1, "127.0.0.1".into(), l.local_addr().unwrap().port(), false, false).unwrap();
        w.clients.at(ci).streams.insert(1, ti);
        w.run_deferred();
        let (mut peer, _) = l.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        for _ in 0..1000 {
            if w.targets.get(ti, tg).is_some_and(|t| t.state == TState::Open) {
                break;
            }
            w.target_event(ti, tg, libc::EPOLLOUT as u32);
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut msg = vec![2u8, 1, 0, 0, 0];
        msg.resize(5 + 16384, 7);
        let mut sink = vec![0u8; 1 << 20];
        let mut data = |w: &mut Worker, n: usize| {
            for _ in 0..n {
                w.on_message(ci, &msg);
                while std::io::Read::read(&mut peer, &mut sink).is_ok_and(|k| k > 0) {}
                w.target_event(ti, tg, libc::EPOLLOUT as u32);
            }
        };
        // the frames queued for the client since the last call: (opcode, payload)
        let frames = |w: &mut Worker| {
            let c = w.clients.at(ci);
            let (mut b, mut out) = (&c.obuf[c.ohead..], Vec::new());
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
            c.obuf.clear();
            c.ohead = 0;
            out
        };
        let cont = |n: u32| (OP_BIN, [&[3u8, 1, 0, 0, 0][..], &n.to_le_bytes()].concat());
        // base rule: the 64th packet makes CONTINUE(128) due; the target is parked on the client's output
        data(&mut w, 63);
        w.targets.at(ti).blocked = true;
        data(&mut w, 1);
        let ping1 = (OP_PING, 1u64.to_le_bytes().to_vec());
        if !pace {
            assert_eq!(frames(&mut w), [cont(128)], "off: granted while parked");
            assert!(w.cpace_st.is_empty(), "off: side vector untouched");
            w.close_target(ti, None);
            continue;
        }
        assert!(frames(&mut w).is_empty(), "held while parked");
        assert_eq!(w.stats.cpace_holds.get(), 1);
        data(&mut w, 2);
        assert!(frames(&mut w).is_empty(), "still parked: still held, counted once");
        assert_eq!(w.stats.cpace_holds.get(), 1);
        // a resume whose read parks the target again (the client's output is still at out_high): still held
        let high = w.st.out_high;
        w.clients.at(ci).obuf = vec![0; high];
        w.resume(tok(K_TARGET, ti, tg));
        assert!(w.targets.at(ti).blocked, "parked again");
        assert_eq!(w.clients.at(ci).obuf.len(), high, "nothing granted");
        w.clients.at(ci).obuf.clear();
        w.clients.at(ci).blocked.clear();
        // the resume that reads without parking releases it
        w.resume(tok(K_TARGET, ti, tg));
        let want = if v2 { vec![cont(128), ping1] } else { vec![cont(128)] };
        assert_eq!(frames(&mut w), want, "released when the target runs again");
        if v2 {
            // the v2 top-up path (after the first pong)
            w.on_frame(ci, true, OP_PONG, &1u64.to_le_bytes());
            std::thread::sleep(credit::PING_GAP);
            w.targets.at(ti).blocked = true;
            let h0 = w.stats.cpace_holds.get();
            for _ in 0..300 {
                data(&mut w, 1);
                if w.stats.cpace_holds.get() > h0 {
                    break;
                }
            }
            assert_eq!(w.stats.cpace_holds.get(), h0 + 1, "a v2 top-up came due while parked");
            assert!(frames(&mut w).is_empty(), "v2 grant held while parked");
            w.resume(tok(K_TARGET, ti, tg));
            let f = frames(&mut w);
            assert!(matches!(f.first(), Some((OP_BIN, p)) if p[0] == 3), "v2 CONTINUE after the release: {f:?}");
        }
        // held, then closed: a new target in the same slot starts unheld
        let since = w.targets.at(ti).since;
        w.targets.at(ti).blocked = true;
        data(&mut w, 128 - since as usize);
        assert!(w.cpace_st[ti as usize].held);
        w.close_target(ti, None);
        let (t2, g2) = w.new_target(ci, 3, "127.0.0.1".into(), l.local_addr().unwrap().port(), false, false).unwrap();
        assert_eq!(t2, ti, "slot reused");
        frames(&mut w);
        w.pace_resume(t2, g2);
        assert!(frames(&mut w).is_empty(), "another generation's hold releases nothing");
        assert!(w.pace_hold(t2) == pace::PACE_GO && !w.cpace_st[ti as usize].held, "not parked: the stale hold is reset");
        w.close_target(t2, None);
    }
}
