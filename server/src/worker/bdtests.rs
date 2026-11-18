//! 60.63 worker tests for section E (crate::bounds, worker/bounds.rs). Each test drives a real Worker through its own
//! epoll (the helpers of fdtests.rs); the host state is set by hand (Bounds::set_state), as the guard thread would.
use super::super::*;
use super::fd::{client_with, closed_with, connect, drain, fd_cfg, fds, pump, rig, until, until_eq, wisp};
use crate::bounds::{
    self as bd, Bounds, TcpForm, Unread, OPT_DEAD, OPT_PORT, OPT_RELIEF, OPT_TCPMEM, OPT_UNREAD, ST_PT_BUSY, ST_PT_SHORT, ST_TM_SHARE,
};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};

const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const BIG: &str = "203.0.113.1";
const SMALL: &str = "198.51.100.7";

impl Worker {
    /// the idle sweep's steps for section E: bd_sweep, then fd_trim (Worker::idle_sweep)
    fn bd_idle(&mut self) {
        if self.bd.is_some() {
            self.bd_sweep();
        }
        self.fd_trim(true);
    }
}

/// A worker whose clients have the address their first bytes name (a PROXY header, or with `xff` an X-Forwarded-For
/// header behind a trusted proxy), with --tcpmem-share on a host whose tcp_mem maximum is 1600 pages: the floor is 4
/// unread target sockets (1600 x 4096 / 16 / 131072, rounded up). `block`: the fd block (non-hold mode takes it).
fn tm_rig(xff: bool, block: u32) -> (Worker, u16, mpsc::Receiver<DnsReq>, Arc<Bounds>) {
    let g = Arc::new(Bounds::new(OPT_TCPMEM, 1, TcpForm::Mem { max_pages: 1600 }, 4096, 131_072));
    assert_eq!(g.floor(), 4);
    let (w, port, rx) = bd_rig(xff, block, g.clone());
    (w, port, rx, g)
}

/// A worker with the state `g` of section E and clients whose first bytes name their address
fn bd_rig(xff: bool, block: u32, g: Arc<Bounds>) -> (Worker, u16, mpsc::Receiver<DnsReq>) {
    bd_rig_t(xff, block, g, Duration::from_secs(10))
}

/// ... and this connect timeout
fn bd_rig_t(xff: bool, block: u32, g: Arc<Bounds>, connect_timeout: Duration) -> (Worker, u16, mpsc::Receiver<DnsReq>) {
    bd_rig_cfg(xff, block, g, |c| c.connect_timeout = connect_timeout)
}

/// ... and the configuration changed by `f`
fn bd_rig_cfg(xff: bool, block: u32, g: Arc<Bounds>, f: impl FnOnce(&mut Config)) -> (Worker, u16, mpsc::Receiver<DnsReq>) {
    let mut cfg = fd_cfg();
    cfg.connect_timeout = Duration::from_secs(10);
    f(&mut cfg);
    cfg.want_peer = true;
    let lo = crate::policy::Cidr::parse("127.0.0.0/8").unwrap();
    if xff {
        cfg.clientip =
            Some(Box::new(clientip::ClientIp { trusted: Box::new([lo]), header: "x-forwarded-for".into(), table: None, max_conns: 0 }));
    } else {
        cfg.proxy_tcp = true;
        cfg.proxy_from = Box::new([lo]);
    }
    let (mut w, port, rx) = rig(cfg, u32::MAX, block);
    w.bd = Some(bounds::Wb::new(g));
    (w, port, rx)
}

fn hello(ip: &str, xff: bool) -> Vec<u8> {
    if xff {
        UPGRADE.replace("Host: x\r\n", &format!("Host: x\r\nX-Forwarded-For: {ip}\r\n")).into_bytes()
    } else {
        format!("PROXY TCP4 {ip} 192.0.2.1 1000 443\r\n{UPGRADE}").into_bytes()
    }
}

/// A client whose socket takes little: the server's side of it has a small send buffer, so a download that is not
/// read backs up in the server after a few KiB
fn slow_client(w: &mut Worker, port: u16, ip: &str, xff: bool) -> (TcpStream, u32) {
    let (c, ci) = client_with(w, port, &hello(ip, xff));
    let v: libc::c_int = 4096;
    for (fd, opt) in [(c.as_raw_fd(), libc::SO_RCVBUF), (w.clients.at(ci).fd, libc::SO_SNDBUF)] {
        assert_eq!(unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, opt, &v as *const _ as *const _, 4) }, 0);
    }
    (c, ci)
}

fn open_streams(w: &Worker) -> usize {
    w.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| t.state == TState::Open).count()
}

fn unread(w: &Worker) -> usize {
    w.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| t.blocked && !t.udp).count()
}

/// `n` more streams on `c` (ids from `sid`) to the listener `l`, and their target sides
fn streams(w: &mut Worker, c: &mut TcpStream, sid: u32, n: u32, l: &TcpListener) -> Vec<TcpStream> {
    let want = open_streams(w) + n as usize;
    for s in sid..sid + n {
        c.write_all(&connect(s, false, l.local_addr().unwrap().port())).unwrap();
    }
    until_eq(w, "the streams are open", want, |w| open_streams(w));
    (0..n)
        .map(|_| {
            let t = l.accept().unwrap().0;
            t.set_nonblocking(true).unwrap();
            t
        })
        .collect()
}

/// The targets send 256 KiB each and the client does not read: until all of them are parked on the client's output
/// (a download parks when its last read filled the read buffer and the client's bulk lane is over its cap)
fn park(w: &mut Worker, targets: &mut [TcpStream]) {
    let want = unread(w) + targets.len();
    let mut left = vec![256usize << 10; targets.len()];
    let chunk = [7u8; 65536];
    until_eq(w, "the downloads are parked on the client's output", want, |w| {
        for (t, l) in targets.iter_mut().zip(left.iter_mut()) {
            if *l > 0 {
                if let Ok(n) = t.write(&chunk[..chunk.len().min(*l)]) {
                    *l -= n;
                }
            }
        }
        unread(w)
    });
}

/// CONNECT (TCP) of stream `sid` to `host`:`port`
fn named(sid: u32, port: u16, host: &str) -> Vec<u8> {
    let mut p = vec![1u8];
    p.extend(port.to_le_bytes());
    p.extend(host.as_bytes());
    wisp(0x01, sid, &p)
}

fn slot(g: &Bounds) -> Unread {
    let mut v = Vec::new();
    g.read_slots(&mut v);
    v[0]
}

/// `closed` for a client whose bytes so far are kept in `got` (at most 3 s)
fn wire(w: &mut Worker, c: &mut TcpStream, got: &mut Vec<u8>, sid: u32, reason: u8) -> bool {
    for _ in 0..600 {
        drain(c, got);
        if closed_with(got, sid, reason) {
            return true;
        }
        pump(w, 5);
    }
    false
}

/// CLOSE with `reason` for stream `sid` waits in the output of connection `ci` (a client that does not read)
fn queued(w: &mut Worker, ci: u32, sid: u32, reason: u8) -> bool {
    let c = w.clients.at(ci);
    closed_with(&c.obuf[c.ohead..], sid, reason)
}

/// refuse_tcpmem_share
fn refusals(w: &Worker) -> u64 {
    w.stats.refuse_tcpmem_share.get()
}

fn end(w: Worker) {
    for fd in [w.ep, w.lfd, w.inbox.efd, w.spare] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w); // (as fdtests: no frees while mem::tests::heap_counter_moves measures)
}

/// E1 end to end on one worker. The big address holds 6 unread downloads, a second client is connected and reads.
/// No mark: nothing is refused and the worker is not in hold mode. Share mark: the big address gets 0x49 for a new
/// stream (TCP; a UDP stream goes on), the small one opens streams, nothing that is open is closed. The second client
/// leaves: the big address is alone and opens streams again. The mark clears: the worker leaves hold mode.
fn tm_scenario(big: &str, xff: bool, gated: bool) {
    let (mut w, port, _rx, g) = tm_rig(xff, 4);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let (mut a, ca) = slow_client(&mut w, port, big, xff);
    let mut ta = streams(&mut w, &mut a, 1, 6, &l);
    park(&mut w, &mut ta);
    let (mut b, _) = client_with(&mut w, port, &hello(SMALL, xff));
    let _tb = streams(&mut w, &mut b, 1, 1, &l);
    // the sweep's count: 2 connections of two addresses, 6 unread target sockets, all of the big address
    w.bd_idle();
    let key = (!crate::net::shared_addr(big.parse().unwrap())).then(|| clientip::key(big.parse().unwrap()));
    let s = slot(&g);
    assert_eq!((s.conns, s.single, s.unread, s.top, s.top_unread), (2, None, 6, key, if gated { 6 } else { 0 }));
    assert_eq!(w.stats.tcpmem_unread.get(), 6);
    // no mark: no hold mode, nothing refused
    assert_eq!(w.fd_mask & bounds::HOLD_BOUNDS, 0);
    let _t7 = streams(&mut w, &mut a, 7, 1, &l);
    // the share mark; the worker takes it at its next sweep
    g.set_state(ST_TM_SHARE);
    w.bd_idle();
    assert_eq!((w.fd_mask & bounds::HOLD_BOUNDS, w.fd_have as u64), (bounds::HOLD_BOUNDS, fds(&w)), "hold mode: fd_have is the count");
    a.write_all(&connect(8, false, lp)).unwrap();
    if gated {
        // (the client does not read: the CLOSE waits behind its downloads; it is checked on the wire at the end)
        until(&mut w, "the big address's new stream is refused", |w| refusals(w) == 1);
        assert_eq!(w.stats.refuse_fd.get(), 0);
    } else {
        until(&mut w, "a shared address is never the address", |w| open_streams(w) == 9);
        assert_eq!(w.stats.refuse_tcpmem_share.get(), 0);
    }
    let open = open_streams(&w);
    assert_eq!((unread(&w), open), (6, if gated { 8 } else { 9 }), "nothing that is open is closed");
    // a UDP stream of the big address holds no TCP memory: not refused; the other client is not refused
    let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    a.write_all(&connect(9, true, u.local_addr().unwrap().port())).unwrap();
    until(&mut w, "the UDP stream is open", |w| open_streams(w) == open + 1);
    // ... and is never an unread download in the count, also when it waits for its client's output
    let ui = w.targets.slots.iter().position(|s| s.1.as_ref().is_some_and(|t| t.udp)).unwrap() as u32;
    w.targets.at(ui).blocked = true;
    w.bd_count(metrics::now_ms());
    assert_eq!(w.stats.tcpmem_unread.get(), 6);
    w.targets.at(ui).blocked = false;
    let _tb2 = streams(&mut w, &mut b, 2, 2, &l);
    assert_eq!(w.stats.refuse_tcpmem_share.get(), gated as u64);
    // the second client leaves: the big address is alone on the server and is not refused
    drop(b);
    until(&mut w, "the second client is gone", |w| w.clients.slots.len() - w.clients.free.len() == 1);
    w.bd_count(metrics::now_ms());
    assert_eq!(slot(&g).single, key);
    let _t10 = streams(&mut w, &mut a, 10, 1, &l);
    assert_eq!(w.stats.refuse_tcpmem_share.get(), gated as u64, "one address alone is never refused by the share rule");
    // a new client is not refused, whatever the host's memory is: there is no host-wide stop
    let (mut d, _) = client_with(&mut w, port, &hello(SMALL, xff));
    let _td = streams(&mut w, &mut d, 1, 2, &l);
    assert_eq!(refusals(&w), gated as u64);
    drop(d);
    until(&mut w, "the new client is gone", |w| w.clients.slots.len() - w.clients.free.len() == 1);
    // the mark clears: the next stream takes the worker out of hold mode
    g.set_state(0);
    let _t13 = streams(&mut w, &mut a, 13, 1, &l);
    assert_eq!((w.fd_mask & bounds::HOLD_BOUNDS, w.fd_block), (0, 4));
    assert_eq!(w.fd_have, w.fd_all(), "out of hold mode the allowance is in fd_have again");
    // the CLOSE of each refused stream waits in the big address's output (it does not read), and of no other stream
    for sid in 7..=13 {
        assert_eq!(queued(&mut w, ca, sid, 0x49), gated && sid == 8, "stream {sid}");
    }
    drop(a);
    until(&mut w, "all gone", |w| w.clients.slots.len() == w.clients.free.len());
    assert_eq!(fds(&w), 0);
    w.bd_idle();
    assert_eq!((slot(&g).conns, slot(&g).unread, w.stats.tcpmem_unread.get()), (0, 0, 0));
    end(w);
}

#[test]
fn tcpmem_share_refuses_the_big_address_after_a_proxy_header() {
    tm_scenario(BIG, false, true);
}

/// behind --trusted-proxy the key is the address the proxy's header names, not the proxy
#[test]
fn tcpmem_share_refuses_the_big_address_behind_a_trusted_proxy() {
    tm_scenario(BIG, true, true);
}

/// a private (or loopback, CGNAT) address is a proxy or a bridge in front of many users: never "the address"
#[test]
fn tcpmem_share_never_refuses_a_shared_address() {
    tm_scenario("10.9.8.7", false, false);
}

/// E1 which client is a key: public addresses (IPv4, IPv6 /64); behind a trusted proxy the forwarded address; never
/// the proxy's own address (a request without the header), never a shared range
#[test]
fn keys_of_section_e() {
    let (mut w, port, _rx, _g) = tm_rig(true, 4);
    let mut keep = Vec::new();
    for (ip, want) in [
        (Some("203.0.113.9"), Some("203.0.113.9")),
        (Some("2001:db8:1:2:3:4:5:6"), Some("2001:db8:1:2::")),
        (Some("10.1.2.3"), None),
        (Some("100.64.0.9"), None),
        (Some("127.0.0.1"), None),
        (None, None),
    ] {
        let h = ip.map_or(UPGRADE.as_bytes().to_vec(), |ip| hello(ip, true));
        let (c, ci) = client_with(&mut w, port, &h);
        assert_eq!(w.bd_key(ci), want.map(|k| clientip::key(k.parse().unwrap())), "{ip:?}");
        keep.push(c);
    }
    // a trusted proxy with a public address: its own address (a request without the header) is no key, the address
    // it names is one, and so is another public peer
    let mut cfg = fd_cfg();
    (cfg.want_peer, cfg.proxy_tcp, cfg.proxy_from) = (true, true, Box::new([crate::policy::Cidr::parse("127.0.0.0/8").unwrap()]));
    let trusted = Box::new([crate::policy::Cidr::parse("203.0.113.50/32").unwrap()]);
    cfg.clientip = Some(Box::new(clientip::ClientIp { trusted, header: "x-forwarded-for".into(), table: None, max_conns: 0 }));
    let (mut w3, port3, _rx3) = rig(cfg, u32::MAX, 4);
    w3.bd = Some(bounds::Wb::new(Arc::new(Bounds::new(OPT_TCPMEM, 1, TcpForm::Flag, 4096, 131_072))));
    let via = |peer: &str, named: Option<&str>| {
        let up = named.map_or(UPGRADE.to_string(), |ip| UPGRADE.replace("Host: x\r\n", &format!("Host: x\r\nX-Forwarded-For: {ip}\r\n")));
        format!("PROXY TCP4 {peer} 192.0.2.1 1000 443\r\n{up}").into_bytes()
    };
    for (peer, named, want) in [
        ("203.0.113.50", None, None),
        ("203.0.113.50", Some("198.51.100.7"), Some("198.51.100.7")),
        ("203.0.113.51", None, Some("203.0.113.51")),
    ] {
        let (c, ci) = client_with(&mut w3, port3, &via(peer, named));
        assert_eq!(w3.bd_key(ci), want.map(|k| clientip::key(k.parse().unwrap())), "{peer} {named:?}");
        keep.push(c);
    }
    end(w3);
    // peers not kept (no option that needs them): no key, so no share rule
    let (mut w2, port2, _rx2) = rig(fd_cfg(), u32::MAX, 4);
    let (_c, ci) = client_with(&mut w2, port2, UPGRADE.as_bytes());
    assert_eq!(w2.bd_key(ci), None);
    end(w);
    end(w2);
}

/// E1 the floor: an address with fewer unread target sockets than can matter on this host is not refused, also with
/// every unread socket of the server (one honest user's paused downloads)
#[test]
fn tcpmem_share_floor() {
    let (mut w, port, _rx, g) = tm_rig(false, 4);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut a, _) = slow_client(&mut w, port, BIG, false);
    let mut ta = streams(&mut w, &mut a, 1, 3, &l);
    park(&mut w, &mut ta);
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    g.set_state(ST_TM_SHARE);
    w.bd_idle();
    assert_eq!((slot(&g).top_unread, g.floor()), (3, 4));
    let mut t4 = streams(&mut w, &mut a, 4, 1, &l);
    assert_eq!(w.stats.refuse_tcpmem_share.get(), 0, "3 unread sockets, floor 4");
    // the fourth parks: at the floor
    park(&mut w, &mut t4);
    w.bd_count(metrics::now_ms());
    a.write_all(&connect(5, false, l.local_addr().unwrap().port())).unwrap();
    until(&mut w, "refused at the floor", |w| refusals(w) == 1);
    end(w);
}

/// E1 the share rule runs at its own mark only: a worker that is in hold mode for another part's mark does not judge
/// with it. And a stream is judged when it starts, not at each address: one that was let in goes on to its next
/// address after the mark is set.
#[test]
fn tcpmem_share_judges_a_new_stream_at_its_own_mark() {
    let (mut w, port, rx, g) = tm_rig(false, 4);
    let dead = Dead::new();
    let Ok(l2) = TcpListener::bind(("127.0.0.2", dead.port)) else { return eprintln!("127.0.0.2:{} is taken: skipped", dead.port) };
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let (mut a, _) = slow_client(&mut w, port, BIG, false);
    let mut ta = streams(&mut w, &mut a, 1, 6, &l);
    park(&mut w, &mut ta);
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    // another part's mark: hold mode, and the address that holds every unread download is not refused
    g.set_state(ST_PT_BUSY);
    w.bd_idle();
    assert_eq!((w.fd_mask & bounds::HOLD_BOUNDS, w.stats.tcpmem_unread.get()), (bounds::HOLD_BOUNDS, 6));
    let _t = streams(&mut w, &mut a, 7, 2, &l);
    assert_eq!(refusals(&w), 0);
    // a stream to a name with two addresses starts: the first address does not answer
    a.write_all(&named(20, dead.port, "two.test")).unwrap();
    let mut req = None;
    until(&mut w, "the lookup", |_| {
        req = req.take().or_else(|| rx.try_recv().ok());
        req.is_some()
    });
    let req = req.unwrap();
    let addrs = ["127.0.0.1", "127.0.0.2"].iter().map(|a| a.parse().unwrap()).collect();
    w.inbox.q.lock().unwrap().push(net::DnsResp { host: req.host, token: req.token, addrs, nx: false, more: false });
    w.inbox_ready();
    until(&mut w, "the first attempt is in flight", |w| w.connecting.len() == 1);
    // the share mark comes: the stream goes on to its second address; a new stream is refused
    let open = open_streams(&w);
    g.set_state(ST_PT_BUSY | ST_TM_SHARE);
    w.bd_idle();
    until_s(&mut w, 8, "the stream opens at its second address", |w| open_streams(w) == open + 1);
    l2.set_nonblocking(true).unwrap();
    assert!(l2.accept().is_ok(), "connected to 127.0.0.2");
    assert_eq!(refusals(&w), 0);
    a.write_all(&connect(21, false, lp)).unwrap();
    until(&mut w, "a new stream is refused", |w| refusals(w) == 1);
    end(w);
}

/// E1 a worker that is not in hold mode learns of a mark when its fd allowance is used up (a block of 4 here; 64 at
/// most in a server) or at its idle sweep: the rule acts late, never early. While the mark is set the worker counts
/// again by itself (RECOUNT_MS), so a download that parks after the mark is seen without a sweep.
#[test]
fn a_mark_is_taken_at_the_next_fd_block() {
    let (mut w, port, _rx, g) = tm_rig(false, 4);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let (mut a, _) = slow_client(&mut w, port, BIG, false);
    let mut ta = streams(&mut w, &mut a, 1, 5, &l);
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    w.bd_idle(); // (a sweep before the downloads park: the published count is 0)
    let unused = w.fd_all() - fds(&w) as u32;
    assert!(slot(&g).unread == 0 && (1..=4).contains(&unused), "at most one unused block: {unused}");
    park(&mut w, &mut ta);
    g.set_state(ST_TM_SHARE);
    // the unused part of the allowance: that many more streams open before the worker is out of line again
    let _t = streams(&mut w, &mut a, 6, unused, &l);
    assert_eq!((w.fd_mask & bounds::HOLD_BOUNDS, w.stats.refuse_tcpmem_share.get()), (0, 0));
    // the next one takes a block: the worker sees the mark, counts (5 unread, floor 4) and refuses
    a.write_all(&connect(10, false, lp)).unwrap();
    until(&mut w, "refused once the mark is taken", |w| refusals(w) == 1);
    assert_eq!(w.fd_mask & bounds::HOLD_BOUNDS, bounds::HOLD_BOUNDS);
    assert_eq!(slot(&g).unread, 5);
    end(w);
}

/// E1 with --conn-share or --fd-admission the worker is in hold mode already: a mark is taken at the next stream
#[test]
fn a_mark_is_taken_at_once_in_hold_mode() {
    let (mut w, port, rx, g) = tm_rig(false, 4);
    w.fdg.set_marks(crate::fdgate::MARK_HOST);
    w.fd_setup();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let (mut a, _) = slow_client(&mut w, port, BIG, false);
    let mut ta = streams(&mut w, &mut a, 1, 5, &l);
    park(&mut w, &mut ta);
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    g.set_state(ST_TM_SHARE);
    a.write_all(&connect(6, false, l.local_addr().unwrap().port())).unwrap();
    until(&mut w, "refused at the next stream", |w| refusals(w) == 1);
    // a stream with a name is refused before its lookup ...
    assert!(rx.try_recv().is_err());
    a.write_all(&named(7, lp, "refused.test")).unwrap();
    until(&mut w, "refused before the lookup", |w| refusals(w) == 2);
    assert!(rx.try_recv().is_err(), "no lookup for a refused stream");
    // ... and one that was let in before the mark is judged again when its answer comes
    g.set_state(0);
    a.write_all(&named(8, lp, "slow.test")).unwrap();
    let mut req = None;
    until(&mut w, "the lookup of the stream that was let in", |_| {
        req = req.take().or_else(|| rx.try_recv().ok());
        req.is_some()
    });
    let req = req.unwrap();
    g.set_state(ST_TM_SHARE);
    w.inbox.q.lock().unwrap().push(net::DnsResp {
        host: req.host,
        token: req.token,
        addrs: vec!["127.0.0.1".parse().unwrap()],
        nx: false,
        more: false,
    });
    w.inbox_ready();
    until(&mut w, "refused after the lookup: the mark came while it resolved", |w| refusals(w) == 3);
    // the marks clear: this file's bit goes, the fd gate's hold mode stays
    g.set_state(0);
    let _t = streams(&mut w, &mut a, 9, 1, &l);
    assert_eq!((w.fd_mask, w.fd_block, w.fd_have as u64), (crate::fdgate::MARK_HOST, 0, fds(&w)));
    end(w);
}

/// Section E off (no state installed): the hooks do nothing, also in the fd gate's hold mode
#[test]
fn off_is_off() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    assert!(w.bd.is_none());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut a, _) = client_with(&mut w, port, UPGRADE.as_bytes());
    let _t = streams(&mut w, &mut a, 1, 9, &l);
    w.bd_idle();
    assert_eq!((w.fd_mask, w.bd_hold(), w.bd_why()), (0, 0, 0));
    assert_eq!(w.stats.tcpmem_unread.get() + w.stats.refuse_tcpmem_share.get(), 0);
    end(w);
}

// ---- E2 --port-share

/// A worker with --port-share on a host with `usable` source ports toward one destination (16: the socket option
/// from 4 sockets to one destination, the share rule from 12). `window`: the port range the socket option names
/// (None: the host's own).
fn pt_rig(xff: bool, usable: u32, window: Option<(u16, u16)>) -> (Worker, u16, mpsc::Receiver<DnsReq>, Arc<Bounds>) {
    let g = Arc::new(Bounds::new(OPT_PORT, 1, TcpForm::Flag, 4096, 131_072));
    let (lo, hi, _) = bd::host_ports().expect("net.ipv4.ip_local_port_range");
    let (lo, hi) = window.unwrap_or((lo, hi));
    let r = lo as u32 | (hi as u32) << 16;
    g.set_ports(lo, hi, usable, bd::port_range_probe(false, r) as u8 | (bd::port_range_probe(true, r) as u8) << 1);
    let (w, port, rx) = bd_rig(xff, 4, g.clone());
    (w, port, rx, g)
}

/// the guard thread's step for the port counts
fn guard(g: &Bounds) -> u8 {
    g.pt_step(metrics::now_ms(), &mut Vec::new(), &mut Vec::new())
}

/// (refuse_port_share, refuse_port_full)
fn pt_refusals(w: &Worker) -> (u64, u64) {
    (w.stats.refuse_port_share.get(), w.stats.refuse_port_full.get())
}

/// the worker's sweep, the guard thread's step, and the worker's next sweep (it takes the state there)
fn settle(w: &mut Worker, g: &Bounds) -> u8 {
    w.bd_idle();
    let st = guard(g);
    w.bd_idle();
    st
}

/// E2 the share rule on one worker, 16 usable ports. The big address holds 12 sockets to one destination and other
/// clients are on the server with other destinations: it is alone on that destination and is not refused. A second
/// client (`other`: its address; None = a client without a key) takes one socket to it: the big address gets 0x49
/// for a new stream to it, not for another destination, not for UDP; the second client is not refused. The second
/// client leaves: the big address is alone again. Nothing that is open is closed.
fn pt_scenario(big: &str, other: Option<&str>, xff: bool, gated: bool) {
    let (mut w, port, _rx, g) = pt_rig(xff, 16, None);
    // (a TCP port whose number is free for UDP too: the UDP stream below goes to the same number)
    let (l, u) = loop {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        if let Ok(u) = std::net::UdpSocket::bind(("127.0.0.1", l.local_addr().unwrap().port())) {
            break (l, u);
        }
    };
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let (mut a, _) = client_with(&mut w, port, &hello(big, xff));
    let mut got = Vec::new();
    let (mut b, _) = client_with(&mut w, port, &other.map_or(UPGRADE.as_bytes().to_vec(), |ip| hello(ip, xff)));
    let _ta = streams(&mut w, &mut a, 1, 12, &l);
    let _tb = streams(&mut w, &mut b, 1, 1, &l2);
    assert_eq!(w.fd_mask & bounds::HOLD_BOUNDS, 0);
    assert_eq!(settle(&mut w, &g), ST_PT_BUSY | ST_PT_SHORT);
    assert_eq!((w.stats.port_dest_max.get(), w.fd_mask & bounds::HOLD_BOUNDS), (12, bounds::HOLD_BOUNDS));
    // alone on the destination: never refused by the share rule, with another client on the server
    let _ta2 = streams(&mut w, &mut a, 13, 2, &l);
    assert_eq!(pt_refusals(&w), (0, 0), "the large holder alone on the destination");
    // the second client takes one socket to that destination
    let _tb2 = streams(&mut w, &mut b, 2, 1, &l);
    w.bd_count(metrics::now_ms());
    assert_eq!(w.stats.port_dest_max.get(), 15);
    a.write_all(&connect(15, false, lp)).unwrap();
    if gated {
        until(&mut w, "the large holder is refused", |w| pt_refusals(w) == (1, 0));
        assert!(wire(&mut w, &mut a, &mut got, 15, 0x49), "CLOSE 0x49");
        assert_eq!((w.stats.refuse_fd.get(), w.stats.connect_fail.get()), (0, 0));
    } else {
        until(&mut w, "an address that is not public is never the address", |w| open_streams(w) == 17);
    }
    let open = open_streams(&w);
    // another destination, a UDP stream to the same port, the other client: not refused
    let _ta3 = streams(&mut w, &mut a, 16, 1, &l2);
    a.write_all(&connect(17, true, u.local_addr().unwrap().port())).unwrap();
    until(&mut w, "the UDP stream is open", |w| open_streams(w) == open + 2);
    let _tb3 = streams(&mut w, &mut b, 3, 1, &l);
    assert_eq!(pt_refusals(&w), (gated as u64, 0));
    // the second client leaves: alone on the destination again
    drop(b);
    until(&mut w, "the second client is gone", |w| w.clients.slots.len() - w.clients.free.len() == 1);
    w.bd_count(metrics::now_ms());
    let _ta4 = streams(&mut w, &mut a, 18, 1, &l);
    assert_eq!(pt_refusals(&w), (gated as u64, 0));
    // everything closes: the marks clear and the worker leaves hold mode
    drop(a);
    until(&mut w, "all gone", |w| w.clients.slots.len() == w.clients.free.len());
    assert_eq!(settle(&mut w, &g), 0);
    assert_eq!((w.fd_mask & bounds::HOLD_BOUNDS, w.stats.port_dest_max.get(), fds(&w)), (0, 0, 0));
    end(w);
}

/// E2 the reserve, 16 usable ports. The big address is alone on a destination and another client (`other`: its
/// address; None = a client without a key) is on the server with another destination: the big address gets its
/// sockets up to 15 (15/16) and 0x49 for the next; the other client then gets a socket to that destination, and from
/// then on the share rule holds the big address. `gated` false: an address that is not public is never refused.
fn pt_reserve(big: &str, other: Option<&str>, xff: bool, gated: bool) {
    let (mut w, port, _rx, g) = pt_rig(xff, 16, None);
    let (l, l2) = (TcpListener::bind("127.0.0.1:0").unwrap(), TcpListener::bind("127.0.0.1:0").unwrap());
    let lp = l.local_addr().unwrap().port();
    let (mut a, _) = client_with(&mut w, port, &hello(big, xff));
    let (mut b, _) = client_with(&mut w, port, &other.map_or(UPGRADE.as_bytes().to_vec(), |ip| hello(ip, xff)));
    let mut got = Vec::new();
    let _tb = streams(&mut w, &mut b, 1, 1, &l2);
    let _ta = streams(&mut w, &mut a, 1, 12, &l);
    assert_eq!(settle(&mut w, &g), ST_PT_BUSY | ST_PT_SHORT);
    let _ta2 = streams(&mut w, &mut a, 13, 2, &l);
    w.bd_count(metrics::now_ms());
    let _ta3 = streams(&mut w, &mut a, 15, 1, &l);
    assert_eq!(pt_refusals(&w), (0, 0), "alone on the destination below 15/16: not refused");
    w.bd_count(metrics::now_ms());
    assert_eq!(w.stats.port_dest_max.get(), 15);
    a.write_all(&connect(16, false, lp)).unwrap();
    if !gated {
        until(&mut w, "an address that is not public is never refused", |w| open_streams(w) == 17);
        assert_eq!(pt_refusals(&w), (0, 0));
        return end(w);
    }
    until(&mut w, "the reserve: refused at 15/16", |w| pt_refusals(w) == (1, 0));
    assert!(wire(&mut w, &mut a, &mut got, 16, 0x49), "CLOSE 0x49");
    assert_eq!((w.stats.refuse_fd.get(), w.stats.connect_fail.get(), open_streams(&w)), (0, 0, 16));
    // another destination: not refused
    let _ta4 = streams(&mut w, &mut a, 17, 1, &l2);
    // the address that comes later gets a socket to the destination
    let _tb2 = streams(&mut w, &mut b, 2, 1, &l);
    assert_eq!(pt_refusals(&w), (1, 0), "the later address is not refused");
    // now the share rule holds the big address
    w.bd_count(metrics::now_ms());
    a.write_all(&connect(18, false, lp)).unwrap();
    until(&mut w, "the share rule", |w| pt_refusals(w) == (2, 0));
    assert!(wire(&mut w, &mut a, &mut got, 18, 0x49));
    end(w);
}

#[test]
fn port_reserve_keeps_the_last_ports_for_an_address_that_comes_later() {
    pt_reserve(BIG, Some(SMALL), false, true);
}

#[test]
fn port_reserve_behind_a_trusted_proxy() {
    pt_reserve(BIG, Some(SMALL), true, true);
}

#[test]
fn port_reserve_counts_a_client_without_a_key_as_another() {
    pt_reserve(BIG, None, true, true);
}

#[test]
fn port_reserve_never_refuses_a_shared_address() {
    pt_reserve("10.9.8.7", Some(SMALL), false, false);
}

/// E2 the reserve, the other order: an address alone on the SERVER takes every port of a destination and is never
/// refused (16 usable ports: 17 sockets). Then another client connects to the server: the big address gets 0x49 for
/// the next stream to that destination, and no stream of it is closed.
#[test]
fn port_reserve_an_address_alone_on_the_server_takes_the_whole_range() {
    let (mut w, port, _rx, g) = pt_rig(false, 16, None);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let mut got = Vec::new();
    let _ta = streams(&mut w, &mut a, 1, 12, &l);
    assert_eq!(settle(&mut w, &g), ST_PT_BUSY | ST_PT_SHORT);
    let mut held = Vec::new();
    for sid in 13..=17 {
        w.bd_count(metrics::now_ms());
        held.push(streams(&mut w, &mut a, sid, 1, &l));
    }
    assert_eq!((pt_refusals(&w), open_streams(&w)), ((0, 0), 17), "nobody else on the server");
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    w.bd_count(metrics::now_ms());
    a.write_all(&connect(18, false, lp)).unwrap();
    until(&mut w, "the reserve, once another client is connected", |w| pt_refusals(w) == (1, 0));
    assert!(wire(&mut w, &mut a, &mut got, 18, 0x49));
    assert_eq!(open_streams(&w), 17, "nothing is closed");
    end(w);
}

#[test]
fn port_share_refuses_the_large_holder_once_another_address_uses_the_destination() {
    pt_scenario(BIG, Some(SMALL), false, true);
}

#[test]
fn port_share_behind_a_trusted_proxy() {
    pt_scenario(BIG, Some(SMALL), true, true);
}

/// the second client has no key (the trusted proxy's own address: a request without the header): it counts as another
#[test]
fn port_share_counts_a_client_without_a_key_as_another() {
    pt_scenario(BIG, None, true, true);
}

#[test]
fn port_share_never_refuses_a_shared_address() {
    pt_scenario("10.9.8.7", Some(SMALL), false, false);
}

/// what a target socket was made with: the options net::connect and Worker::won set, and the file flags
fn sock_made(fd: RawFd) -> Vec<(&'static str, i64)> {
    let get = |level, name| {
        let (mut v, mut len) = (0 as libc::c_int, 4 as libc::socklen_t);
        assert_eq!(unsafe { libc::getsockopt(fd, level, name, &mut v as *mut _ as *mut _, &mut len) }, 0);
        v as i64
    };
    vec![
        ("TCP_NODELAY", get(libc::IPPROTO_TCP, libc::TCP_NODELAY)),
        ("SO_KEEPALIVE", get(libc::SOL_SOCKET, libc::SO_KEEPALIVE)),
        ("TCP_KEEPIDLE", get(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE)),
        ("TCP_NOTSENT_LOWAT", get(libc::IPPROTO_TCP, libc::TCP_NOTSENT_LOWAT)),
        ("TCP_USER_TIMEOUT", get(libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT)),
        ("SO_TYPE", get(libc::SOL_SOCKET, libc::SO_TYPE)),
        ("SO_REUSEADDR", get(libc::SOL_SOCKET, libc::SO_REUSEADDR)),
        ("SO_MAX_PACING_RATE", get(libc::SOL_SOCKET, libc::SO_MAX_PACING_RATE)),
        ("F_GETFL", unsafe { libc::fcntl(fd, libc::F_GETFL) } as i64),
        ("F_GETFD", unsafe { libc::fcntl(fd, libc::F_GETFD) } as i64),
    ]
}

/// (local port, the socket's own port range) of a target socket
fn sock_port(fd: RawFd) -> (u16, u32) {
    let (mut r, mut len) = (0u32, 4 as libc::socklen_t);
    assert_eq!(unsafe { libc::getsockopt(fd, libc::IPPROTO_IP, bd::IP_LOCAL_PORT_RANGE, &mut r as *mut _ as *mut _, &mut len) }, 0);
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    assert_eq!(unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut _, &mut len) }, 0);
    // (sin_port and sin6_port are at the same place)
    (u16::from_be(unsafe { *(&ss as *const _ as *const libc::sockaddr_in) }.sin_port), r)
}

/// the fds of the open TCP targets, in stream order of connection `ci`
fn target_fds(w: &Worker) -> Vec<(u32, RawFd)> {
    let mut v: Vec<(u32, RawFd)> =
        w.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| t.state == TState::Open && !t.udp).map(|t| (t.sid, t.fd)).collect();
    v.sort();
    v
}

/// a window of 4 ports inside the host's range whose first port was free a moment ago
fn window() -> (u16, u16) {
    let (_, hi, _) = bd::host_ports().unwrap();
    let p = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port().min(hi - 3);
    (p, p + 3)
}

/// E2 the socket option and the end of the ports, with the kernel: the socket option names a window of 4 ports, so
/// the kernel itself runs out of ports toward the destination. Target sockets to a destination below 1/4 of the
/// range are made by try_connect, without the option; from 1/4 by try_connect_ranged, with it: their local ports are
/// in the window, and everything else about the two kinds of socket is the same. When the kernel has no port left
/// (EADDRNOTAVAIL) the stream gets 0x49 (not 0x42), counted as refuse_port_full and not as connect_fail; for
/// PT_FULL_MS streams to that destination are refused without a connect; then, with a port free again, a stream opens.
fn full_scenario(host: &str) {
    let (lo, hi) = window();
    let (mut w, port, _rx, g) = pt_rig(false, 16, Some((lo, hi)));
    let range = lo as u32 | (hi as u32) << 16;
    if g.pt_range(host.contains(':')) == 0 {
        eprintln!("IP_LOCAL_PORT_RANGE is not taken by this kernel for {host}: skipped");
        return end(w);
    }
    let l = TcpListener::bind((host, 0)).unwrap();
    let lp = l.local_addr().unwrap().port();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let mut got = Vec::new();
    let mut next = 1;
    let mut open = |a: &mut TcpStream, n: u32| {
        for sid in next..next + n {
            a.write_all(&named(sid, lp, host)).unwrap();
        }
        next += n;
        next - 1
    };
    open(&mut a, 4);
    until(&mut w, "4 streams by try_connect", |w| open_streams(w) == 4);
    assert_eq!(settle(&mut w, &g), ST_PT_BUSY);
    // from here the destination is busy: streams until the kernel has no port in the window
    let mut ranged = 0;
    let last = loop {
        let (sid, before) = (open(&mut a, 1), open_streams(&w));
        until(&mut w, "the stream opens or is refused", |w| open_streams(w) > before || pt_refusals(w).1 > 0);
        if pt_refusals(&w).1 > 0 {
            break sid;
        }
        ranged += 1;
        assert!(ranged <= 4, "a window of 4 ports");
    };
    assert!(ranged >= 1, "no port of the window {lo}-{hi} was free");
    assert_eq!((pt_refusals(&w), w.stats.connect_fail.get(), w.stats.refuse_fd.get()), ((0, 1), 0, 0));
    assert!(wire(&mut w, &mut a, &mut got, last, 0x49) && !closed_with(&got, last, 0x42), "0x49, not 0x42");
    let fds_ = target_fds(&w);
    let (plain, with) = (&fds_[..4], &fds_[4..]);
    assert_eq!(with.len(), ranged);
    for (sid, fd) in plain {
        assert_eq!(sock_port(*fd).1, 0, "stream {sid}: made by try_connect, no option");
        assert_eq!(sock_made(*fd), sock_made(plain[0].1));
    }
    for (sid, fd) in with {
        let (p, r) = sock_port(*fd);
        assert!(r == range && (lo..=hi).contains(&p), "stream {sid}: port {p}, range {r:#x}");
        assert_eq!(sock_made(*fd), sock_made(plain[0].1), "stream {sid}: the two kinds of socket differ only in the option");
    }
    // within PT_FULL_MS: refused without asking the kernel; a stream to another destination opens
    let l2 = TcpListener::bind((host, 0)).unwrap();
    let lp2 = l2.local_addr().unwrap().port();
    let (sid, before) = (open(&mut a, 1), open_streams(&w));
    a.write_all(&named(900, lp2, host)).unwrap();
    until(&mut w, "refused in the window", |w| pt_refusals(w) == (0, 2) && open_streams(w) == before + 1);
    assert!(wire(&mut w, &mut a, &mut got, sid, 0x49));
    // the other destination is below 1/4 of the range (2 sockets, counted): its sockets get no option
    w.bd_count(metrics::now_ms());
    a.write_all(&named(901, lp2, host)).unwrap();
    until(&mut w, "the second stream to the other destination", |w| open_streams(w) == before + 2);
    for (sid, fd) in target_fds(&w).iter().filter(|t| t.0 >= 900) {
        assert_eq!(sock_port(*fd).1, 0, "stream {sid}: a destination that is not busy, no option");
    }
    a.write_all(&[wisp(0x04, 900, &[0x02]), wisp(0x04, 901, &[0x02])].concat()).unwrap();
    until(&mut w, "the two are closed", |w| open_streams(w) == before);
    // a port comes free (the client closes a stream that holds one), the window passes: the next stream opens
    let before = open_streams(&w);
    a.write_all(&wisp(0x04, with[0].0, &[0x02])).unwrap();
    until(&mut w, "the stream is closed", |w| open_streams(w) == before - 1);
    std::thread::sleep(Duration::from_millis(bd::PT_FULL_MS + 20));
    open(&mut a, 1);
    until(&mut w, "a stream opens again", |w| open_streams(w) == before);
    assert_eq!((pt_refusals(&w), w.stats.connect_fail.get()), ((0, 2), 0));
    end(w);
}

/// E2 only EADDRNOTAVAIL from a connect that was made with the socket option means "no port left": another error,
/// or that error from a connect without the option (a destination that is not busy), marks nothing
#[test]
fn port_full_is_only_the_kernels_answer_to_a_ranged_connect() {
    let (mut w, port, _rx, _g) = pt_rig(false, 16, None);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let _t = streams(&mut w, &mut a, 1, 1, &l);
    let ti = w.targets.slots.iter().position(|s| s.1.is_some()).unwrap() as u32;
    assert_eq!(w.pt_failed(ti, true, libc::ECONNREFUSED), 0, "another error of a ranged connect");
    assert_eq!(w.pt_failed(ti, true, libc::ENETUNREACH), 0);
    assert_eq!(w.pt_failed(ti, false, libc::EADDRNOTAVAIL), 0, "a connect without the option");
    assert_eq!(w.pt_failed(ti, true, libc::EADDRNOTAVAIL), 1);
    end(w);
}

#[test]
fn port_full_and_the_socket_option_ipv4() {
    full_scenario("127.0.0.1");
}

/// (IP_LOCAL_PORT_RANGE is an IPPROTO_IP option; the kernel takes it on an AF_INET6 TCP socket too)
#[test]
fn port_full_and_the_socket_option_ipv6() {
    if TcpListener::bind("[::1]:0").is_err() {
        return eprintln!("no ::1 on this host: skipped");
    }
    full_scenario("::1");
}

/// E2 the rule judges an address, not a stream: a name with a second address goes on with it (so dual-stack works
/// and nothing is gained by a name that hides the destination behind another address); the stream is refused only
/// when no address is left
#[test]
fn port_share_tries_the_next_address() {
    let (mut w, port, rx, g) = pt_rig(false, 16, None);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let lp = l.local_addr().unwrap().port();
    let Ok(l2) = TcpListener::bind(("127.0.0.2", lp)) else { return eprintln!("127.0.0.2:{lp} is taken: skipped") };
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (mut b, _) = client_with(&mut w, port, &hello(SMALL, false));
    let _ta = streams(&mut w, &mut a, 1, 12, &l);
    let _tb = streams(&mut w, &mut b, 1, 1, &l);
    assert_eq!(settle(&mut w, &g), ST_PT_BUSY | ST_PT_SHORT);
    let answer = |w: &mut Worker, a: &mut TcpStream, sid: u32, name: &str, addrs: &[&str]| {
        a.write_all(&named(sid, lp, name)).unwrap();
        let mut req = None;
        until(w, "the lookup", |_| {
            req = req.take().or_else(|| rx.try_recv().ok());
            req.is_some()
        });
        let req = req.unwrap();
        let addrs = addrs.iter().map(|a| a.parse().unwrap()).collect();
        w.inbox.q.lock().unwrap().push(net::DnsResp { host: req.host, token: req.token, addrs, nx: false, more: false });
        w.inbox_ready();
    };
    // the refused destination first, another address second: the stream opens there
    answer(&mut w, &mut a, 20, "two.test", &["127.0.0.1", "127.0.0.2"]);
    until(&mut w, "the stream opens at the second address", |w| open_streams(w) == 14);
    l2.set_nonblocking(true).unwrap();
    assert!(l2.accept().is_ok(), "connected to 127.0.0.2");
    assert_eq!(pt_refusals(&w), (0, 0));
    // only the refused destination: 0x49
    answer(&mut w, &mut a, 21, "one.test", &["127.0.0.1"]);
    until(&mut w, "refused: no other address", |w| pt_refusals(w) == (1, 0));
    let mut got = Vec::new();
    assert!(wire(&mut w, &mut a, &mut got, 21, 0x49) && !closed_with(&got, 20, 0x49));
    assert_eq!(w.stats.connect_fail.get(), 0);
    end(w);
}

// ---- E3 --dest-failfast

/// A destination that does not answer: a listener whose accept queue is full drops every SYN (the kernel of the
/// connecting socket sends it again after 1 s, 2 s, 3 s). `revive`: it answers from now on.
struct Dead {
    fd: RawFd,
    port: u16,
    fillers: Vec<TcpStream>,
}

impl Dead {
    fn new() -> Dead {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        (sa.sin_family, sa.sin_addr.s_addr) = (libc::AF_INET as u16, u32::from_be_bytes([127, 0, 0, 1]).to_be());
        let mut len = std::mem::size_of_val(&sa) as u32;
        unsafe {
            assert_eq!(libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len), 0);
            assert_eq!(libc::listen(fd, 0), 0);
            assert_eq!(libc::getsockname(fd, &mut sa as *mut _ as *mut libc::sockaddr, &mut len), 0);
        }
        let port = u16::from_be(sa.sin_port);
        let fillers =
            (0..2).filter_map(|_| TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(200)).ok()).collect();
        Dead { fd, port, fillers }
    }

    /// it answers every SYN from now on (a long accept queue)
    fn revive(&mut self) {
        assert_eq!(unsafe { libc::listen(self.fd, 4096) }, 0);
        self.accept(usize::MAX);
    }

    /// take `n` connections from the queue (each makes room for one more); the accepted sockets stay open
    fn accept(&mut self, n: usize) -> usize {
        let mut got = 0;
        while got < n {
            let s = unsafe { libc::accept4(self.fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
            if s < 0 {
                break;
            }
            self.fillers.push(unsafe { TcpStream::from_raw_fd(s) });
            got += 1;
        }
        got
    }
}

impl Drop for Dead {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// pump until `done` (at most `secs` s: the kernel's SYN retransmits come 1 s apart)
fn until_s(w: &mut Worker, secs: u64, what: &str, mut done: impl FnMut(&mut Worker) -> bool) {
    let t0 = Instant::now();
    while !done(w) {
        assert!(t0.elapsed() < Duration::from_secs(secs), "not reached in {secs} s: {what}");
        pump(w, 5);
    }
}

/// A worker with --dest-failfast; `fast`: a connecting socket counts as dead after 2 SYNs (asked from 1 s of age)
/// instead of 4 (3 s)
fn df_rig(xff: bool, fast: bool, connect_timeout: Duration) -> (Worker, u16, mpsc::Receiver<DnsReq>) {
    let g = Arc::new(Bounds::new(OPT_DEAD, 1, TcpForm::Flag, 4096, 131_072));
    let (mut w, port, rx) = bd_rig_t(xff, 4, g, connect_timeout);
    if fast {
        w.df_set(1000, 2);
    } else {
        w.df_set(1000, bd::DF_SYNS); // (asked from 1 s, so that the tests see the SYN count decide)
    }
    (w, port, rx)
}

fn df_state(w: &Worker) -> (u64, u64, u8) {
    (w.stats.dest_dead.get(), w.stats.refuse_dest_dead.get(), w.fd_mask & bounds::HOLD_BOUNDS)
}

/// `n` CONNECTs on `c` (ids from `sid`) to a destination that does not answer, until they are in flight
fn hang(w: &mut Worker, c: &mut TcpStream, sid: u32, n: u32, port: u16) {
    let want = w.connecting.len() + n as usize;
    for s in sid..sid + n {
        c.write_all(&connect(s, false, port)).unwrap();
    }
    until_s(w, 8, "the connects are in flight", |w| w.connecting.len() == want);
}

/// count (as the sweep does) until the worker holds `n` suspects; the time it took
fn suspects(w: &mut Worker, n: u64) -> Duration {
    let t0 = Instant::now();
    until_s(w, 8, "the count of suspects", |w| {
        w.bd_count(metrics::now_ms());
        w.stats.dest_dead.get() == n
    });
    t0.elapsed()
}

/// E3 on one worker. A client has 8 connects in flight to a destination that does not answer and another client is
/// connected (`other`: its address; None = a client without a key). Before the second SYN of each: nothing. After it
/// (`fast` rig): the destination is a suspect, the worker in hold mode; a new stream to it gets 0x43 at once (not
/// counted as a connect timeout), from either client with a key; a stream to another destination and a UDP stream
/// to the same port open. One stream per second goes on as the probe. The destination answers: the probe opens, the
/// next stream to it is not refused, and the worker leaves hold mode at its next count.
fn df_scenario(big: &str, other: Option<&str>, xff: bool, gated: bool) {
    let (mut w, port, _rx) = df_rig(xff, true, Duration::from_secs(10));
    // (a dead TCP port whose number is free for UDP too: the UDP stream below goes to the same number)
    let (mut dead, u) = loop {
        let d = Dead::new();
        if let Ok(u) = std::net::UdpSocket::bind(("127.0.0.1", d.port)) {
            break (d, u);
        }
    };
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut a, _) = client_with(&mut w, port, &hello(big, xff));
    let (mut b, _) = client_with(&mut w, port, &other.map_or(UPGRADE.as_bytes().to_vec(), |ip| hello(ip, xff)));
    let (mut got, mut got_b) = (Vec::new(), Vec::new());
    let t0 = Instant::now();
    hang(&mut w, &mut a, 1, 8, dead.port);
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (0, 0, 0), "8 connects that are young: no suspect");
    suspects(&mut w, 1);
    assert!(t0.elapsed() >= Duration::from_millis(1000), "not before the second SYN: {:?}", t0.elapsed());
    let seen = Instant::now();
    assert_eq!(df_state(&w), (1, 0, bounds::HOLD_BOUNDS));
    let refused = |w: &Worker| w.stats.refuse_dest_dead.get();
    // a new stream to it
    a.write_all(&connect(20, false, dead.port)).unwrap();
    if gated {
        until_s(&mut w, 8, "refused at once", |w| refused(w) == 1);
        assert!(wire(&mut w, &mut a, &mut got, 20, 0x43), "CLOSE 0x43");
        assert_eq!(w.connecting.len(), 8);
    } else {
        until_s(&mut w, 8, "an address that is not public is never refused", |w| w.connecting.len() == 9);
    }
    assert_eq!((w.stats.connect_timeout.get(), w.stats.connect_fail.get(), w.stats.refuse_fd.get()), (0, 0, 0));
    // the other client's stream to it: refused if it has a key
    let flying = w.connecting.len();
    b.write_all(&connect(1, false, dead.port)).unwrap();
    if other.is_some() {
        until_s(&mut w, 8, "the other client is refused too", |w| refused(w) == gated as u64 + 1);
        assert!(wire(&mut w, &mut b, &mut got_b, 1, 0x43));
    } else {
        until_s(&mut w, 8, "a client without a key is never refused", |w| w.connecting.len() == flying + 1);
    }
    let n = refused(&w);
    // another destination, and a UDP stream to the same port: not refused
    let open = open_streams(&w);
    let _t = streams(&mut w, &mut a, 21, 1, &l);
    a.write_all(&connect(22, true, u.local_addr().unwrap().port())).unwrap();
    until_s(&mut w, 8, "the UDP stream is open", |w| open_streams(w) == open + 2);
    assert_eq!(refused(&w), n);
    if !gated {
        return end(w);
    }
    // one probe per second: the first stream after the second is not refused, the next one is
    until_s(&mut w, 8, "the probe's time", |_| seen.elapsed() >= Duration::from_millis(bd::DF_PROBE_MS + 20));
    let flying = w.connecting.len();
    a.write_all(&connect(30, false, dead.port)).unwrap();
    until_s(&mut w, 8, "the probe is in flight", |w| w.connecting.len() == flying + 1);
    a.write_all(&connect(31, false, dead.port)).unwrap();
    until_s(&mut w, 8, "one probe only", |w| refused(w) == n + 1);
    assert!(wire(&mut w, &mut a, &mut got, 31, 0x43) && !closed_with(&got, 30, 0x43));
    assert_eq!(df_state(&w), (1, n + 1, bounds::HOLD_BOUNDS));
    // the destination answers again
    dead.revive();
    until_s(&mut w, 8, "the probe is open", |w| {
        w.targets.slots.iter().filter_map(|s| s.1.as_ref()).any(|t| t.sid == 30 && t.state == TState::Open)
    });
    let open = open_streams(&w);
    a.write_all(&connect(40, false, dead.port)).unwrap();
    until_s(&mut w, 8, "the next stream to it opens", |w| {
        w.targets.slots.iter().filter_map(|s| s.1.as_ref()).any(|t| t.sid == 40 && t.state == TState::Open)
    });
    assert!(open_streams(&w) > open);
    assert_eq!(refused(&w), n + 1);
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (0, n + 1, 0), "no suspect, out of hold mode");
    assert_eq!(w.stats.connect_timeout.get(), 0);
    end(w);
}

#[test]
fn dead_destination_is_refused_at_once_and_probed() {
    df_scenario(BIG, Some(SMALL), false, true);
}

#[test]
fn dest_failfast_behind_a_trusted_proxy() {
    df_scenario(BIG, Some(SMALL), true, true);
}

/// the second client has no key (the trusted proxy's own address): it counts as another, and is never refused
#[test]
fn dest_failfast_counts_a_client_without_a_key_as_another() {
    df_scenario(BIG, None, true, true);
}

#[test]
fn dest_failfast_never_refuses_a_shared_address() {
    df_scenario("10.9.8.7", Some(SMALL), false, false);
}

/// E3 P1: a client that is alone on the server is never refused (its connects take nothing from anyone); with a
/// second client connected it is
#[test]
fn dest_failfast_never_refuses_a_client_alone() {
    let (mut w, port, _rx) = df_rig(false, true, Duration::from_secs(10));
    let dead = Dead::new();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    hang(&mut w, &mut a, 1, 8, dead.port);
    suspects(&mut w, 1);
    hang(&mut w, &mut a, 20, 3, dead.port);
    assert_eq!(df_state(&w), (1, 0, bounds::HOLD_BOUNDS), "a suspect, and nothing refused");
    // a second connection of the same address: still one address
    let (_a2, _) = client_with(&mut w, port, &hello(BIG, false));
    w.bd_count(metrics::now_ms());
    hang(&mut w, &mut a, 30, 1, dead.port);
    assert_eq!(w.stats.refuse_dest_dead.get(), 0);
    // another address connects
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    w.bd_count(metrics::now_ms());
    a.write_all(&connect(40, false, dead.port)).unwrap();
    a.write_all(&connect(41, false, dead.port)).unwrap();
    // (at most one of the two is the probe)
    until_s(&mut w, 8, "refused once another client is connected", |w| w.stats.refuse_dest_dead.get() >= 1);
    let mut got = Vec::new();
    assert!(wire(&mut w, &mut a, &mut got, 41, 0x43));
    end(w);
}

/// E3 what makes a connecting socket look dead is the SYNs it has sent, not its age: with 2 and with 3 SYNs sent (a
/// target that answers the second or the third SYN is at this point) the destination is no suspect; with 4 it is
#[test]
fn dest_failfast_waits_for_four_syns() {
    // 60.74 4.5: each check falls between two SYNs of the kernel (1 s apart): judged with the host lag
    // below 300 ms
    crate::testlag::judged("dest_failfast_waits_for_four_syns", Duration::from_millis(300), 5, |_| dest_failfast_waits_for_four_syns_run());
}
fn dest_failfast_waits_for_four_syns_run() {
    let (mut w, port, _rx) = df_rig(false, false, Duration::from_secs(10));
    let dead = Dead::new();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    let t0 = Instant::now();
    hang(&mut w, &mut a, 1, 8, dead.port);
    let syns = |w: &Worker| -> Vec<u8> {
        w.targets.slots.iter().filter_map(|s| s.1.as_ref()).flat_map(|t| t.conn.iter()).map(|fd| bd::syns_sent(*fd).unwrap()).collect()
    };
    assert_eq!(syns(&w), [1; 8]);
    // (the worker counts by itself too while connects are in flight: the sockets asked are read over one count)
    let count = |w: &mut Worker| {
        let before = w.df_asked();
        w.bd_count(metrics::now_ms());
        w.df_asked() - before
    };
    assert_eq!(count(&mut w), 0, "a socket that is young is not asked");
    for sent in [2u8, 3] {
        until_s(&mut w, 8, "the next SYN of each", |w| syns(w).iter().all(|n| *n >= sent));
        assert_eq!(count(&mut w), 8, "each of the 8 asked once per count");
        assert_eq!((syns(&w), df_state(&w)), (vec![sent; 8], (0, 0, 0)), "{sent} SYNs sent each: no suspect ({:?})", t0.elapsed());
    }
    // two more connects to it: young, so not asked, and the 8 are not at 4 SYNs yet
    hang(&mut w, &mut a, 10, 2, dead.port);
    assert_eq!((count(&mut w), df_state(&w)), (8, (0, 0, 0)));
    until_s(&mut w, 8, "the fourth SYN of the 8", |w| syns(w).iter().filter(|n| **n >= 4).count() >= 8);
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (1, 0, bounds::HOLD_BOUNDS), "4 SYNs each: a suspect ({:?})", t0.elapsed());
    // 7 such sockets are not enough: a second destination with 7
    let dead2 = Dead::new();
    hang(&mut w, &mut a, 20, 7, dead2.port);
    until_s(&mut w, 8, "the second SYN of each", |w| syns(w).iter().all(|n| *n >= 2));
    assert_eq!((count(&mut w), w.stats.dest_dead.get()), (0, 1), "7 connects that are old enough: none asked");
    // an eighth, one second behind: when the 7 have sent 4 SYNs it is old enough to be asked and has sent 3
    hang(&mut w, &mut a, 30, 1, dead2.port);
    until_s(&mut w, 8, "the fourth SYN of the 7", |w| syns(w).iter().filter(|n| **n >= 4).count() >= 17);
    assert_eq!((count(&mut w), w.stats.dest_dead.get()), (8, 1), "8 asked, 7 with 4 SYNs: no suspect");
    until_s(&mut w, 8, "the fourth SYN of the eighth", |w| syns(w).iter().all(|n| *n >= 4));
    w.bd_count(metrics::now_ms());
    assert_eq!(w.stats.dest_dead.get(), 2, "8: a suspect");
    end(w);
}

/// E3 a destination with a target that opened since the last count answers: no suspect at that count, whatever its
/// other connects look like; with nothing opened since, it is one
#[test]
fn dest_failfast_an_open_since_the_last_count_is_an_answer() {
    // (fd block 64: the worker does not count on its own in this test)
    let g = Arc::new(Bounds::new(OPT_DEAD, 1, TcpForm::Flag, 4096, 131_072));
    let (mut w, port, _rx) = bd_rig_t(false, 64, g, Duration::from_secs(10));
    w.df_set(1000, 2);
    let mut dead = Dead::new();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    w.bd_count(metrics::now_ms());
    // the queue has room for one connection: the first stream opens, and fills it again
    assert_eq!(dead.accept(1), 1);
    a.write_all(&connect(1, false, dead.port)).unwrap();
    until_s(&mut w, 8, "the first stream opens", |w| open_streams(w) == 1);
    hang(&mut w, &mut a, 2, 8, dead.port);
    let young = |w: &Worker| {
        w.targets
            .slots
            .iter()
            .filter_map(|s| s.1.as_ref())
            .flat_map(|t| t.conn.iter())
            .filter(|fd| bd::syns_sent(**fd).unwrap() < 2)
            .count()
    };
    until_s(&mut w, 8, "the second SYN of the 8", |w| young(w) == 0);
    assert_eq!((w.connecting.len(), open_streams(&w)), (8, 1));
    let asked = w.df_asked();
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (0, 0, 0), "8 connects look dead and one opened since the last count: no suspect");
    assert_eq!(w.df_asked(), asked, "... and no socket is asked for a destination that answered");
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (1, 0, bounds::HOLD_BOUNDS), "nothing opened since: a suspect");
    end(w);
}

/// E3 a count asks the kernel about a bounded number of sockets: at most DF_ASK_MAX in all, and no more of a
/// destination once DF_K of its sockets have the SYN count
#[test]
fn dest_failfast_asks_a_bounded_number_of_sockets() {
    let (mut w, port, _rx) = df_rig(false, false, Duration::from_secs(10));
    let dead = Dead::new();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    let n = bd::DF_ASK_MAX + 4;
    hang(&mut w, &mut a, 1, n, dead.port);
    w.df_set(0, 9); // (every socket is old enough, none has 9 SYNs; set after the connects are in flight: before, the
                    // worker's own counts would take the destination for failing and refuse above DF_FAIL_FLY)
                    // (the worker counts by itself too while connects are in flight: the sockets asked are read over one count)
    let before = w.df_asked();
    w.bd_count(metrics::now_ms());
    // (no suspect; hold mode: the address has more than half of DF_FAIL_FLY in flight to a failing destination)
    assert_eq!((w.df_asked() - before, df_state(&w)), (bd::DF_ASK_MAX as u64, (0, 0, bounds::HOLD_BOUNDS)), "{n} connecting sockets");
    w.df_set(0, 1);
    let before = w.df_asked();
    w.bd_count(metrics::now_ms());
    assert_eq!((w.df_asked() - before, df_state(&w)), (bd::DF_K as u64, (1, 0, bounds::HOLD_BOUNDS)));
    end(w);
}

/// E3 the table of suspects is full: a new dead destination is not kept at that count and nothing is refused for
/// it. (The test's entries have no connect in flight, so the count drops them: the next count has room.)
#[test]
fn dest_failfast_table_full_refuses_nothing() {
    let (mut w, port, _rx) = df_rig(false, true, Duration::from_secs(10));
    let dead = Dead::new();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    hang(&mut w, &mut a, 1, 8, dead.port);
    until_s(&mut w, 8, "the second SYN of each", |w| {
        w.targets.slots.iter().filter_map(|s| s.1.as_ref()).flat_map(|t| t.conn.iter()).all(|fd| bd::syns_sent(*fd).unwrap() >= 2)
    });
    if df_state(&w).0 != 0 {
        return eprintln!("the worker's own sweep counted first: skipped");
    }
    w.df_fill();
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (0, 0, 0), "not kept: the table was full");
    hang(&mut w, &mut a, 20, 4, dead.port);
    assert_eq!(w.stats.refuse_dest_dead.get(), 0);
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (1, 0, bounds::HOLD_BOUNDS), "room again");
    end(w);
}

/// E3 a suspect stays while a connect to it is in flight, also when nobody asks; when its connects have timed out
/// and nobody asked for it, it is dropped and the worker leaves hold mode
#[test]
fn dest_failfast_forgets_a_destination_nobody_asks_for() {
    let (mut w, port, _rx) = df_rig(false, true, Duration::from_millis(2500));
    let dead = Dead::new();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    hang(&mut w, &mut a, 1, 8, dead.port);
    suspects(&mut w, 1);
    // one connect is left in flight: kept
    for sid in 1..=7 {
        a.write_all(&wisp(0x04, sid, &[0x02])).unwrap();
    }
    until_s(&mut w, 8, "7 of the 8 connects are closed by the client", |w| w.connecting.len() <= 1);
    w.bd_count(metrics::now_ms());
    if w.connecting.len() == 1 {
        assert_eq!(df_state(&w), (1, 0, bounds::HOLD_BOUNDS), "kept while a connect to it is in flight");
    }
    until_s(&mut w, 8, "the last connect times out", |w| w.stats.connect_timeout.get() == 1);
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (0, 0, 0), "no connect in flight: dropped, out of hold mode");
    end(w);
}

/// E3 one target that opens ends the suspect, also while other connects to it are still in flight. (The queue of
/// the destination gets room for one connection: the probe or one of the waiting connects opens. 7 of the 8 are
/// left before that, so at most 7 wait afterwards: too few for a new suspect.)
#[test]
fn dest_failfast_one_open_target_ends_the_suspect() {
    let (mut w, port, _rx) = df_rig(false, true, Duration::from_secs(10));
    let mut dead = Dead::new();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    hang(&mut w, &mut a, 1, 8, dead.port);
    suspects(&mut w, 1);
    let seen = Instant::now();
    a.write_all(&wisp(0x04, 1, &[0x02])).unwrap();
    until_s(&mut w, 8, "the probe's time, 7 connects in flight", |w| {
        w.connecting.len() == 7 && seen.elapsed() >= Duration::from_millis(bd::DF_PROBE_MS + 20)
    });
    assert_eq!(dead.accept(1), 1);
    a.write_all(&connect(30, false, dead.port)).unwrap();
    until_s(&mut w, 8, "one target opens", |w| open_streams(w) >= 1);
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (0, 0, 0), "it answered: no suspect, also with connects to it in flight");
    end(w);
}

/// E3 the suspect's probe is a connect in flight, at any age: the client gave up on the 8 connects that made the
/// suspect, and the young probe alone keeps it
#[test]
fn dest_failfast_a_probe_in_flight_keeps_the_suspect() {
    let (mut w, port, _rx) = df_rig(false, true, Duration::from_secs(10));
    let dead = Dead::new();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    hang(&mut w, &mut a, 1, 8, dead.port);
    suspects(&mut w, 1);
    let seen = Instant::now();
    until_s(&mut w, 8, "the probe's time", |_| seen.elapsed() >= Duration::from_millis(bd::DF_PROBE_MS + 20));
    hang(&mut w, &mut a, 30, 1, dead.port);
    let sent = Instant::now();
    for sid in 1..=8 {
        a.write_all(&wisp(0x04, sid, &[0x02])).unwrap();
    }
    until_s(&mut w, 8, "the client closed the 8 connects", |w| w.connecting.len() == 1);
    w.bd_count(metrics::now_ms());
    if sent.elapsed() < Duration::from_millis(900) {
        assert_eq!(df_state(&w), (1, 0, bounds::HOLD_BOUNDS), "kept: its probe is in flight");
    }
    a.write_all(&wisp(0x04, 30, &[0x02])).unwrap();
    until_s(&mut w, 8, "the client closed the probe", |w| w.connecting.is_empty());
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (0, 0, 0), "no connect in flight: dropped");
    end(w);
}

/// E3 a destination that comes back and refuses the connection (its port is closed now): the connects in flight
/// fail, none is left, and the suspect goes. A new stream gets the kernel's answer (0x44), not 0x43.
#[test]
fn dest_failfast_a_destination_that_refuses_is_no_suspect() {
    let (mut w, port, _rx) = df_rig(false, true, Duration::from_secs(10));
    let dead = Dead::new();
    let dport = dead.port;
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    hang(&mut w, &mut a, 1, 8, dport);
    suspects(&mut w, 1);
    drop(dead); // (the listener is closed: the next SYN of each connect gets a reset)
    until_s(&mut w, 8, "the 8 connects are refused", |w| w.connecting.is_empty());
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (0, 0, 0), "no connect in flight: no suspect");
    a.write_all(&connect(20, false, dport)).unwrap();
    let mut got = Vec::new();
    assert!(wire(&mut w, &mut a, &mut got, 20, 0x44), "the kernel's answer");
    assert_eq!(w.stats.refuse_dest_dead.get(), 0);
    assert_eq!(w.stats.connect_timeout.get(), 0);
    end(w);
}

/// E3 the rule judges an address: a name with a second address goes on with it; with only the dead one, 0x43
#[test]
fn dest_failfast_tries_the_next_address() {
    let (mut w, port, rx) = df_rig(false, true, Duration::from_secs(10));
    let dead = Dead::new();
    let Ok(l2) = TcpListener::bind(("127.0.0.2", dead.port)) else { return eprintln!("127.0.0.2:{} is taken: skipped", dead.port) };
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    hang(&mut w, &mut a, 1, 8, dead.port);
    suspects(&mut w, 1);
    let lp = dead.port;
    let answer = |w: &mut Worker, a: &mut TcpStream, sid: u32, name: &str, addrs: &[&str]| {
        a.write_all(&named(sid, lp, name)).unwrap();
        let mut req = None;
        until_s(w, 8, "the lookup", |_| {
            req = req.take().or_else(|| rx.try_recv().ok());
            req.is_some()
        });
        let req = req.unwrap();
        let addrs = addrs.iter().map(|a| a.parse().unwrap()).collect();
        w.inbox.q.lock().unwrap().push(net::DnsResp { host: req.host, token: req.token, addrs, nx: false, more: false });
        w.inbox_ready();
    };
    answer(&mut w, &mut a, 20, "two.test", &["127.0.0.1", "127.0.0.2"]);
    until_s(&mut w, 8, "the stream opens at the second address", |w| open_streams(w) == 1);
    l2.set_nonblocking(true).unwrap();
    assert!(l2.accept().is_ok(), "connected to 127.0.0.2");
    assert_eq!(w.stats.refuse_dest_dead.get(), 0);
    answer(&mut w, &mut a, 21, "one.test", &["127.0.0.1"]);
    until_s(&mut w, 8, "refused: no other address", |w| w.stats.refuse_dest_dead.get() == 1);
    let mut got = Vec::new();
    assert!(wire(&mut w, &mut a, &mut got, 21, 0x43) && !closed_with(&got, 20, 0x43));
    assert_eq!((w.stats.connect_fail.get(), w.stats.connect_timeout.get()), (0, 0));
    end(w);
}

/// The lookup that a CONNECT by name starts, as the resolver gets it
fn lookup(w: &mut Worker, rx: &mpsc::Receiver<DnsReq>, c: &mut TcpStream, sid: u32, port: u16, name: &str) -> DnsReq {
    c.write_all(&named(sid, port, name)).unwrap();
    let mut req = None;
    until_s(w, 8, "the lookup", |_| {
        req = req.take().or_else(|| rx.try_recv().ok());
        req.is_some()
    });
    req.unwrap()
}

/// ... and its answer (`more`: the early one of a lookup in two parts; the final one follows)
fn dns(w: &mut Worker, req: &DnsReq, addrs: &[&str], more: bool) {
    let addrs = addrs.iter().map(|a| a.parse().unwrap()).collect();
    w.inbox.q.lock().unwrap().push(net::DnsResp { host: req.host.clone(), token: req.token, addrs, nx: false, more });
    w.inbox_ready();
}

fn stream(w: &Worker, sid: u32) -> &Target {
    w.targets.slots.iter().filter_map(|s| s.1.as_ref()).find(|t| t.sid == sid).expect("the stream is there")
}

/// E3 with a lookup in two parts (one family answers first). The early answer holds only the dead address: the stream
/// waits for the final answer, and the refused address does not count as tried. The final answer brings nothing new:
/// 0x43 and the rule's counter (it was 0x42 and a failed connect). It brings another address: the stream opens there.
#[test]
fn dest_failfast_keeps_its_reason_while_a_lookup_is_due() {
    let (mut w, port, rx) = df_rig(false, true, Duration::from_secs(10));
    let dead = Dead::new();
    let Ok(l2) = TcpListener::bind(("127.0.0.2", dead.port)) else { return eprintln!("127.0.0.2:{} is taken: skipped", dead.port) };
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    hang(&mut w, &mut a, 1, 8, dead.port);
    suspects(&mut w, 1);
    let r1 = lookup(&mut w, &rx, &mut a, 20, dead.port, "one.test");
    let r2 = lookup(&mut w, &rx, &mut a, 21, dead.port, "two.test");
    dns(&mut w, &r1, &["127.0.0.1"], true);
    dns(&mut w, &r2, &["127.0.0.1"], true);
    for sid in [20, 21] {
        let t = stream(&w, sid);
        assert!(t.dns_more && t.conn.is_empty() && t.cidx == NOT_LISTED, "{sid}: it waits for the final answer");
        assert_eq!(t.attempt, 0, "{sid}: the refused address is not tried");
    }
    assert_eq!((w.stats.refuse_dest_dead.get(), w.connecting.len()), (0, 8), "nothing refused yet, no socket made");
    dns(&mut w, &r1, &["127.0.0.1"], false);
    dns(&mut w, &r2, &["127.0.0.1", "127.0.0.2"], false);
    until_s(&mut w, 8, "the second stream opens at the other address", |w| open_streams(w) == 1);
    l2.set_nonblocking(true).unwrap();
    assert!(l2.accept().is_ok(), "connected to 127.0.0.2");
    let mut got = Vec::new();
    assert!(wire(&mut w, &mut a, &mut got, 20, 0x43) && !closed_with(&got, 21, 0x43));
    assert_eq!((w.stats.refuse_dest_dead.get(), w.stats.connect_fail.get(), w.stats.connect_timeout.get()), (1, 0, 0));
    assert_eq!(w.stats.close[0x42].get(), 0);
    end(w);
}

/// E3 a name with two addresses: the first does not answer, the second refuses the connection. The socket that is
/// left belongs to the first, and the stream's newest address is the second: it is not asked in its name (8 such
/// streams made the address that refuses a suspect). Streams whose attempts are all in flight are asked as before.
#[test]
fn dest_failfast_blames_no_address_for_the_silence_of_another() {
    let (mut w, port, rx) = df_rig(false, true, Duration::from_secs(10));
    let dead = Dead::new();
    if TcpStream::connect(("127.0.0.2", dead.port)).is_ok() {
        return eprintln!("127.0.0.2:{} is taken: skipped", dead.port);
    }
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    for sid in 1..=8 {
        let r = lookup(&mut w, &rx, &mut a, sid, dead.port, &format!("n{sid}.test"));
        dns(&mut w, &r, &["127.0.0.1", "127.0.0.2"], false);
    }
    until_s(&mut w, 8, "the second address refused each stream", |w| {
        w.targets.slots.iter().filter_map(|s| s.1.as_ref()).filter(|t| t.attempt == 2 && t.conn.len() == 1).count() == 8
    });
    let (asked, t0) = (w.df_asked(), Instant::now());
    until_s(&mut w, 8, "the sockets that are left sent their second SYN", |_| t0.elapsed() >= Duration::from_millis(1500));
    w.bd_count(metrics::now_ms());
    assert_eq!((df_state(&w), w.df_asked() - asked), ((0, 0, 0), 0), "no socket asked, no suspect");
    hang(&mut w, &mut a, 20, 8, dead.port);
    suspects(&mut w, 1);
    assert_eq!(w.stats.connect_fail.get(), 0);
    end(w);
}

/// E3 the probe is a stream by name with a second address, and it opens there: that is no answer from the suspect
/// (the open probe cleared it)
#[test]
fn dest_failfast_a_probe_that_opens_at_another_address_is_no_answer() {
    // 60.74 4.5: the suspect and the probe run on the kernel's SYN clock: judged with the host lag below
    // 500 ms
    crate::testlag::judged("dest_failfast_a_probe_that_opens_at_another_address_is_no_answer", Duration::from_millis(500), 5, |_| {
        dest_failfast_a_probe_that_opens_at_another_address_is_no_answer_run()
    });
}
fn dest_failfast_a_probe_that_opens_at_another_address_is_no_answer_run() {
    let (mut w, port, rx) = df_rig(false, true, Duration::from_secs(10));
    let dead = Dead::new();
    let Ok(_l2) = TcpListener::bind(("127.0.0.2", dead.port)) else { return eprintln!("127.0.0.2:{} is taken: skipped", dead.port) };
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    hang(&mut w, &mut a, 1, 8, dead.port);
    suspects(&mut w, 1);
    let seen = Instant::now();
    until_s(&mut w, 8, "the probe's time", |_| seen.elapsed() >= Duration::from_millis(bd::DF_PROBE_MS + 20));
    let r = lookup(&mut w, &rx, &mut a, 20, dead.port, "two.test");
    dns(&mut w, &r, &["127.0.0.1", "127.0.0.2"], false);
    assert_eq!(w.connecting.len(), 9, "the probe is in flight to the suspect");
    until_s(&mut w, 8, "the probe's stream opens at its second address", |w| open_streams(w) == 1);
    a.write_all(&connect(21, false, dead.port)).unwrap();
    until_s(&mut w, 8, "the next stream to the suspect is refused", |w| w.stats.refuse_dest_dead.get() == 1);
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (1, 1, bounds::HOLD_BOUNDS), "still a suspect");
    end(w);
}

/// E3 the honest case that decides it: one tab (one connection, one worker) loads a page with many resources from
/// one host that is slow but alive, while another client is connected. 30 streams at once, then `late` more, one per
/// 200 ms; the host answers nothing until the 30 send their `nth` SYN (1 s, 2 s, 4 s after the first), then
/// everything. The rule as shipped (4 SYNs, asked from 3 s), counted every 250 ms (a worker cannot count more often).
/// Returns (streams refused, streams open at the end, most suspects at a count).
fn page_load(nth: u64, late: u32) -> (u64, usize, u64) {
    let g = Arc::new(Bounds::new(OPT_DEAD, 1, TcpForm::Flag, 4096, 131_072));
    let (mut w, port, _rx) = bd_rig_t(false, 4, g, Duration::from_secs(10));
    let mut dead = Dead::new();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    w.bd_count(metrics::now_ms());
    let t0 = Instant::now();
    for sid in 1..=30 {
        a.write_all(&connect(sid, false, dead.port)).unwrap();
    }
    // (SYNs leave at 0, 1, 2, 3, 4 s: net.ipv4.tcp_syn_linear_timeouts)
    let answer_at = (nth - 1) * 1000 - 300;
    let end = answer_at.max(late as u64 * 200) + 1500;
    let (mut sent, mut next_count, mut most, mut alive) = (0u32, 250u64, 0u64, false);
    loop {
        let ms = t0.elapsed().as_millis() as u64;
        if ms >= end {
            break;
        }
        if sent < late && ms >= (sent as u64 + 1) * 200 {
            a.write_all(&connect(100 + sent, false, dead.port)).unwrap();
            sent += 1;
        }
        if ms >= answer_at && !alive {
            alive = true;
            dead.revive();
        }
        if ms >= next_count {
            w.bd_count(metrics::now_ms());
            most = most.max(w.stats.dest_dead.get());
            next_count += 250;
        }
        pump(&mut w, 5);
    }
    assert_eq!((sent, w.stats.connect_timeout.get(), w.stats.connect_fail.get()), (late, 0, 0));
    let r = (w.stats.refuse_dest_dead.get(), open_streams(&w), most);
    self::end(w);
    r
}

#[test]
fn dest_failfast_page_load_from_a_host_that_answers_the_second_syn() {
    assert_eq!(page_load(2, 10), (0, 40, 0));
}

#[test]
fn dest_failfast_page_load_from_a_host_that_answers_the_third_syn() {
    assert_eq!(page_load(3, 10), (0, 40, 0));
    assert_eq!(page_load(3, 30), (0, 60, 0), "streams that keep coming for 6 s");
}

/// ... the fifth SYN (4 s): 60.78 bundle B1 its connects have 4 SYNs from 3 s but are not ripe (DF_RIPE_MS before the
/// deadline: 7.5 s), so it is never a suspect; its 30 + 40 streams stay below DF_FAIL_FLY in flight: none refused, also
/// for a page that keeps asking for 8 s. (The rule before: a suspect from 3 s until it answered, 1 to 6 refused.)
#[test]
fn dest_failfast_page_load_from_a_host_that_answers_the_fifth_syn() {
    // 60.74 4.5: the host answers at 3.7 s, counted every 250 ms, and the late streams come one per 200 ms:
    // judged with the host lag below 150 ms
    crate::testlag::judged("dest_failfast_page_load_from_a_host_that_answers_the_fifth_syn", Duration::from_millis(150), 5, |_| {
        dest_failfast_page_load_from_a_host_that_answers_the_fifth_syn_run()
    });
}
fn dest_failfast_page_load_from_a_host_that_answers_the_fifth_syn_run() {
    assert_eq!(page_load(5, 10), (0, 40, 0));
    assert_eq!(page_load(5, 40), (0, 70, 0), "30 + 40 streams over 8 s");
}

/// E3 60.78 bundle B1 only connects near their deadline (ripe: the last DF_RIPE_MS) make a suspect, however many SYNs
/// they sent. A connect timeout of 4 s, ripe in its last 1.5 s (from 2.5 s of age), dead at 2 SYNs: two destinations
/// with 8 connects each that have sent 2 SYNs by 1.5 s: no suspect (the rule before: a suspect). One answers at 2 s:
/// all its streams open and it is never a suspect; the other is one once its connects are ripe.
#[test]
fn dest_failfast_takes_only_ripe_connects_for_dead() {
    crate::testlag::judged("dest_failfast_takes_only_ripe_connects_for_dead", Duration::from_millis(300), 5, |_| {
        dest_failfast_takes_only_ripe_connects_for_dead_run()
    });
}
fn dest_failfast_takes_only_ripe_connects_for_dead_run() {
    let (mut w, port, _rx) = df_rig(false, true, Duration::from_secs(4));
    w.df_ripe(1500);
    let (dead, mut late) = (Dead::new(), Dead::new());
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (_b, _) = client_with(&mut w, port, &hello(SMALL, false));
    let t0 = Instant::now();
    hang(&mut w, &mut a, 1, 8, dead.port);
    hang(&mut w, &mut a, 20, 8, late.port);
    let at = |w: &mut Worker, ms: u64| until_s(w, 8, "the time", |_| t0.elapsed() >= Duration::from_millis(ms));
    at(&mut w, 1500);
    let syns = |w: &Worker| -> Vec<u8> {
        w.targets.slots.iter().filter_map(|s| s.1.as_ref()).flat_map(|t| t.conn.iter()).map(|fd| bd::syns_sent(*fd).unwrap()).collect()
    };
    assert!(syns(&w).iter().all(|n| *n >= 2), "{:?}", syns(&w));
    w.bd_count(metrics::now_ms());
    assert_eq!(df_state(&w), (0, 0, 0), "2 SYNs each, not ripe: no suspect");
    at(&mut w, 2000);
    late.revive();
    until_s(&mut w, 8, "the late host's streams open", |w| open_streams(w) == 8);
    at(&mut w, 2700);
    w.bd_count(metrics::now_ms());
    assert_eq!((df_state(&w), open_streams(&w), w.connecting.len()), ((1, 0, bounds::HOLD_BOUNDS), 8, 8), "ripe: a suspect");
    end(w);
}

/// E3 60.78 bundle B1 many distinct destinations that do not answer: one client address may have DF_FAIL_FLY connects
/// in flight that are old (DF_AGE_MS without an answer) or go to failing destinations, on a worker. Over it, its next
/// connect to a failing destination is refused with 0x43 at once, and so is one to a destination without an open
/// stream on the worker (it could be the next one that does not answer); another address's is not, nor one of it to a
/// destination with an open stream. A destination that answers leaves the failing ones and gives the address room.
#[test]
fn dest_failfast_bounds_one_address_on_many_failing_destinations() {
    let (mut w, port, _rx) = df_rig(false, false, Duration::from_secs(10));
    w.df_ripe(1); // (no suspect in this test: no connect is ripe)
    let mut dests: Vec<Dead> = (0..4).map(|_| Dead::new()).collect();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (mut b, _) = client_with(&mut w, port, &hello(SMALL, false));
    let per = bd::DF_FAIL_FLY / 4;
    for (i, d) in dests.iter().enumerate() {
        hang(&mut w, &mut a, 1 + i as u32 * per, per, d.port);
    }
    w.bd_count(metrics::now_ms());
    assert_eq!((w.df_fail(BIG), df_state(&w)), ((0, 0), (0, 0, 0)), "young: none failing");
    std::thread::sleep(Duration::from_millis(1050));
    w.bd_count(metrics::now_ms());
    w.bd_count(metrics::now_ms()); // (the second count keeps the destinations that answer: none yet)
    assert_eq!((w.df_fail(BIG), w.df_fail(SMALL).1, df_state(&w)), ((4, bd::DF_FAIL_FLY), 0, (0, 0, bounds::HOLD_BOUNDS)));
    let refused = |w: &Worker| w.stats.refuse_dest_dead.get();
    let (mut got, flying) = (Vec::new(), w.connecting.len());
    a.write_all(&connect(500, false, dests[0].port)).unwrap();
    until_s(&mut w, 8, "refused at once", |w| refused(w) == 1);
    assert!(wire(&mut w, &mut a, &mut got, 500, 0x43), "CLOSE 0x43");
    assert_eq!((w.connecting.len(), w.stats.connect_timeout.get()), (flying, 0));
    // another address: its own budget
    b.write_all(&connect(1, false, dests[0].port)).unwrap();
    until_s(&mut w, 8, "the other address's connect is in flight", |w| w.connecting.len() == flying + 1);
    // over its budget, a destination without an open stream: refused too
    let lp = l.local_addr().unwrap().port();
    a.write_all(&connect(501, false, lp)).unwrap();
    until_s(&mut w, 8, "refused: no open stream to it", |w| refused(w) == 2);
    assert!(wire(&mut w, &mut a, &mut got, 501, 0x43));
    // the other address opens one there; from the next count the first address may connect to it
    let open = open_streams(&w);
    let _t = streams(&mut w, &mut b, 2, 1, &l);
    w.bd_count(metrics::now_ms());
    let _t2 = streams(&mut w, &mut a, 600, 1, &l);
    assert_eq!((open_streams(&w), refused(&w)), (open + 2, 2));
    // the first destination answers: it is not failing any more, and the address has room for `per` connects
    dests[0].revive();
    until_s(&mut w, 8, "its streams open", |w| open_streams(w) == open + 2 + per as usize + 1);
    w.bd_count(metrics::now_ms());
    assert_eq!(w.df_fail(BIG), (3, bd::DF_FAIL_FLY - per));
    let flying = w.connecting.len();
    a.write_all(&connect(700, false, dests[1].port)).unwrap();
    until_s(&mut w, 8, "in flight", |w| w.connecting.len() == flying + 1);
    assert_eq!((refused(&w), w.stats.dest_dead.get()), (2, 0));
    end(w);
}

/// E3 60.78 bundle B1 an address with connects that got no answer: its young connects to destinations without an
/// open target count too (between two counts and at the count), so a scan cannot start a new 64 at every count; an
/// address without such a connect is not counted for them however many it makes
#[test]
fn dest_failfast_counts_young_connects_only_for_an_address_with_old_ones() {
    let (mut w, port, _rx) = df_rig(false, false, Duration::from_secs(10));
    w.df_ripe(1);
    let (old_n, young_n) = (bd::DF_FAIL_FLY as usize / 2, bd::DF_FAIL_FLY as usize / 2 + 8);
    let dests: Vec<Dead> = (0..old_n + young_n).map(|_| Dead::new()).collect();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (mut b, _) = client_with(&mut w, port, &hello(SMALL, false));
    for (i, d) in dests[..old_n].iter().enumerate() {
        hang(&mut w, &mut a, 1 + i as u32, 1, d.port);
    }
    std::thread::sleep(Duration::from_millis(1050));
    w.bd_count(metrics::now_ms());
    w.bd_count(metrics::now_ms());
    assert_eq!((w.df_fail(BIG), df_state(&w).2), ((old_n, old_n as u32), bounds::HOLD_BOUNDS), "half the budget: hold mode");
    // the other address: many young connects to destinations without an open target, none counted or refused
    let flying = w.connecting.len();
    for (i, d) in dests[old_n..].iter().cycle().take(bd::DF_FAIL_FLY as usize + 6).enumerate() {
        b.write_all(&connect(100 + i as u32, false, d.port)).unwrap();
    }
    until_s(&mut w, 8, "all in flight", |w| w.connecting.len() == flying + bd::DF_FAIL_FLY as usize + 6);
    assert_eq!((w.stats.refuse_dest_dead.get(), w.df_fail(SMALL).1), (0, 0));
    // the first address: young connects to new destinations count from its old ones on
    for (i, d) in dests[old_n..].iter().enumerate() {
        a.write_all(&connect(500 + i as u32, false, d.port)).unwrap();
    }
    until_s(&mut w, 8, "the ones above the budget refused", |w| {
        w.stats.refuse_dest_dead.get() == (old_n + young_n) as u64 - bd::DF_FAIL_FLY as u64
    });
    w.bd_count(metrics::now_ms());
    assert_eq!(w.df_fail(BIG).1, bd::DF_FAIL_FLY, "the young ones still count at the count");
    end(w);
}

/// E3 60.78 bundle B1 an address that never asks for the same destination twice (a scan of ports or hosts that do not
/// answer): its old connects count, so the budget holds as well; another address is not refused
#[test]
fn dest_failfast_bounds_one_address_on_destinations_it_asks_once() {
    let (mut w, port, _rx) = df_rig(false, false, Duration::from_secs(10));
    w.df_ripe(1);
    let n = bd::DF_FAIL_FLY as usize;
    let dests: Vec<Dead> = (0..n + 1).map(|_| Dead::new()).collect();
    let (mut a, _) = client_with(&mut w, port, &hello(BIG, false));
    let (mut b, _) = client_with(&mut w, port, &hello(SMALL, false));
    for (i, d) in dests[..n].iter().enumerate() {
        hang(&mut w, &mut a, 1 + i as u32, 1, d.port);
    }
    std::thread::sleep(Duration::from_millis(1050));
    w.bd_count(metrics::now_ms());
    w.bd_count(metrics::now_ms());
    assert_eq!((w.df_fail(BIG), df_state(&w)), ((n, bd::DF_FAIL_FLY), (0, 0, bounds::HOLD_BOUNDS)));
    let mut got = Vec::new();
    a.write_all(&connect(500, false, dests[n].port)).unwrap();
    until_s(&mut w, 8, "a new destination: refused", |w| w.stats.refuse_dest_dead.get() == 1);
    assert!(wire(&mut w, &mut a, &mut got, 500, 0x43));
    let flying = w.connecting.len();
    b.write_all(&connect(1, false, dests[n].port)).unwrap();
    until_s(&mut w, 8, "the other address's connect is in flight", |w| w.connecting.len() == flying + 1);
    end(w);
}

/// E5: a worker with --unread-close (the stall limit shortened to UC_TEST_MS) on a host whose tcp_mem maximum is 1600
/// pages, and one client of a public address whose downloads are parked (6 streams); returned once the client's
/// receive window is 0
fn uc_rig() -> (Worker, Arc<Bounds>, TcpStream, Vec<TcpStream>, TcpListener) {
    uc_rig_with(UC_TEST_MS, Some(8192), UC_TEST_M0)
}

/// ... with the starting credit `limit_ms` (the cap: 10 x it, or bounds::UC_CAP_MS at the real start), the client's
/// receive buffer `rcvbuf` (uc_client) and one full stream of `m0` bytes (0: this host's)
fn uc_rig_with(limit_ms: u64, rcvbuf: Option<i32>, m0: u64) -> (Worker, Arc<Bounds>, TcpStream, Vec<TcpStream>, TcpListener) {
    let g = Arc::new(Bounds::new(OPT_UNREAD, 1, TcpForm::Mem { max_pages: 1600 }, 4096, 131_072));
    let (mut w, port, _rx) = bd_rig(false, 4, g.clone());
    w.uc_set(limit_ms, if limit_ms == bd::UC_STALL_MS { bd::UC_CAP_MS } else { 10 * limit_ms }, m0);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut c, ci) = uc_client(&mut w, port, rcvbuf);
    let mut t = streams(&mut w, &mut c, 1, 6, &l);
    park(&mut w, &mut t);
    c.set_nonblocking(true).unwrap();
    let fd = w.clients.at(ci).fd;
    until(&mut w, "the client's receive window is 0", |_| bd::wnd_acked(fd).is_some_and(|i| i.0 == 0));
    (w, g, c, t, l)
}

/// E5 the tests' starting credit (bounds::UC_STALL_MS is 600 s), sweep period (the worker's is 2 s), and one full
/// stream (far above what the rig's connection holds: its credit is used at the rate of time)
const UC_TEST_MS: u64 = 4_000;
const UC_TEST_M0: u64 = 1 << 40;
const UC_SWEEP_MS: u64 = 500;

/// E5 a client of the address BIG as on a real network: it announces an MSS of 1448 (loopback's 64 KiB MSS would let
/// the server send to a reader only in probes), with the receive buffer `rcvbuf` (doubled by the kernel; a set size
/// stops its autotuning; None: the kernel's default, autotuned); the server's side of it has a small send buffer
fn uc_client(w: &mut Worker, port: u16, rcvbuf: Option<i32>) -> (TcpStream, u32) {
    let before = w.stats.accepted.get();
    // SAFETY: plain libc calls; the fd goes into the TcpStream that owns it from here on
    let mut c = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0);
        let mss: libc::c_int = 1448;
        assert_eq!(libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_MAXSEG, &mss as *const _ as *const _, 4), 0);
        if let Some(rcv) = rcvbuf {
            assert_eq!(libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &rcv as *const _ as *const _, 4), 0);
        }
        let mut a: libc::sockaddr_in = std::mem::zeroed();
        a.sin_family = libc::AF_INET as libc::sa_family_t;
        a.sin_port = port.to_be();
        a.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let n = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        assert_eq!(libc::connect(fd, &a as *const _ as *const _, n), 0);
        TcpStream::from_raw_fd(fd)
    };
    c.write_all(&hello(BIG, false)).unwrap();
    until(w, "client accepted", |w| w.stats.accepted.get() > before);
    let me = c.local_addr().unwrap().port();
    until(w, "client upgraded", |w| {
        w.clients.slots.iter().any(|s| s.1.as_ref().is_some_and(|x| x.state == CState::Open && super::fd::peer_port(x.fd) == me))
    });
    let ci = w.clients.slots.iter().position(|s| s.1.as_ref().is_some_and(|x| !x.dead && super::fd::peer_port(x.fd) == me)).unwrap();
    let v: libc::c_int = 4096;
    let fd = w.clients.at(ci as u32).fd;
    assert_eq!(unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &v as *const _ as *const _, 4) }, 0);
    (c, ci as u32)
}

/// E5 `ms` of real time: the client reads what `read(elapsed ms)` allows in all (a cumulative byte count), the targets
/// send what their sockets take, the worker runs, and every UC_SWEEP_MS (uc_run_at: `sweep_ms`) a sweep's step (bd_count, then bd_unread). The
/// ms at which the connection was reset (close_unread), or None.
fn uc_run(w: &mut Worker, c: &mut TcpStream, t: &mut [TcpStream], ms: u64, read: impl Fn(u64) -> u64) -> Option<u64> {
    uc_run_at(w, c, t, ms, UC_SWEEP_MS, read)
}

/// ... with a sweep every `sweep_ms`
fn uc_run_at(w: &mut Worker, c: &mut TcpStream, t: &mut [TcpStream], ms: u64, sweep_ms: u64, read: impl Fn(u64) -> u64) -> Option<u64> {
    uc_run_sweeps(w, c, t, ms, sweep_ms, read).map(|(at, _)| at)
}

/// ... and the time of every sweep up to the reset (the last one is the sweep that reset): the `now` it gave the rule,
/// ms after the start (the clock the stall limit is judged on, read after the loop turn)
fn uc_run_sweeps(
    w: &mut Worker,
    c: &mut TcpStream,
    t: &mut [TcpStream],
    ms: u64,
    sweep_ms: u64,
    read: impl Fn(u64) -> u64,
) -> Option<(u64, Vec<u64>)> {
    let chunk = [7u8; 16384];
    let mut buf = vec![0u8; 1 << 16];
    let (before, start, mut taken, mut swept, mut sweeps) = (w.stats.close_unread.get(), Instant::now(), 0u64, 0u64, Vec::new());
    let start_ms = metrics::now_ms();
    loop {
        let el = start.elapsed().as_millis() as u64;
        if el >= ms {
            return None;
        }
        while taken < read(el) {
            let want = (read(el) - taken).min(buf.len() as u64) as usize;
            match c.read(&mut buf[..want]) {
                Ok(0) | Err(_) => break,
                Ok(n) => taken += n as u64,
            }
        }
        for x in t.iter_mut() {
            let _ = x.write(&chunk);
        }
        pump(w, 10);
        if el >= swept + sweep_ms {
            swept = el;
            let now = metrics::now_ms();
            sweeps.push(now.saturating_sub(start_ms));
            w.bd_count(now);
            w.bd_unread(now);
            if w.stats.close_unread.get() > before {
                return Some((el, sweeps));
            }
        }
    }
}

/// E5 the client that does not read: kept while the host has TCP memory to spare (2 limits), reset at the first sweep
/// after the mark (its stall is older than the limit); the client sees the reset and every stream is closed. A client
/// that does not read with the mark set: reset after the limit, not before.
#[test]
fn uc_resets_a_client_that_does_not_read() {
    // 60.74 4.5: the sweeps are counted (a loop turn under load is late, the rule acts per sweep); the times keep
    // their bounds plus the measured host lag
    let lag = crate::testlag::Lag::start();
    let (mut w, g, mut c, mut t, _l) = uc_rig();
    assert_eq!(uc_run(&mut w, &mut c, &mut t, 2 * UC_TEST_MS, |_| 0), None, "no mark: never");
    g.set_state(bd::ST_UNREAD);
    lag.reset();
    let at = uc_run_sweeps(&mut w, &mut c, &mut t, UC_TEST_MS, UC_SWEEP_MS, |_| 0);
    assert!(
        at.as_ref().is_some_and(|(ms, s)| s.len() == 1 && *ms <= lag.bound(Duration::from_millis(UC_SWEEP_MS + 100), 2).as_millis() as u64),
        "at the first sweep with the mark: {at:?} (lag {:?})",
        lag.max()
    );
    assert_eq!(w.stats.close_unread.get(), 1);
    pump(&mut w, 5);
    assert_eq!(open_streams(&w), 0, "every stream of the connection is closed");
    c.set_nonblocking(false).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut b = [0u8; 65536];
    let reset = loop {
        match c.read(&mut b) {
            Ok(n) if n > 0 => continue,
            Err(e) => break e.kind() == std::io::ErrorKind::ConnectionReset,
            Ok(_) => break false,
        }
    };
    assert!(reset, "the client gets a TCP reset");
    end(w);
    let (mut w, g, mut c, mut t, _l) = uc_rig();
    g.set_state(bd::ST_UNREAD);
    lag.reset();
    // after the limit, and at the first sweep that can see it: the stall is noted by the first or second sweep, so the
    // sweep before the reset is less than the limit after the second sweep (on time: the old bound limit + 2 sweeps)
    let at = uc_run_sweeps(&mut w, &mut c, &mut t, 2 * UC_TEST_MS, UC_SWEEP_MS, |_| 0);
    assert!(
        at.as_ref().is_some_and(|(ms, s)| s[s.len() - 1] >= UC_TEST_MS
            && s.len() >= 3
            && s[s.len() - 2] < s[1] + UC_TEST_MS
            && *ms <= lag.bound(Duration::from_millis(UC_TEST_MS + 2 * UC_SWEEP_MS + 100), 4).as_millis() as u64),
        "after the limit: {at:?} (lag {:?})",
        lag.max()
    );
    end(w);
}

/// E5 a client that pauses for 3/4 of the limit under the mark and then reads what it has (an app that comes back to
/// the foreground; the 15 s of 120 s scaled up to the shortened limit): kept for 3 limits. (A slow reader cannot be
/// shortened: its window gap is real time and set by its buffer; tests/compat/unread_close.py.)
#[test]
fn uc_keeps_a_client_that_pauses_and_reads() {
    let (mut w, g, mut c, mut t, _l) = uc_rig();
    g.set_state(bd::ST_UNREAD);
    let pause = UC_TEST_MS / 4 * 3;
    assert_eq!(uc_run(&mut w, &mut c, &mut t, 3 * UC_TEST_MS, |ms| if ms < pause { 0 } else { u64::MAX }), None);
    assert_eq!(w.stats.close_unread.get(), 0);
    end(w);
}

/// E5 a client that pauses for 3/4 of its credit, reads for a while, and pauses again for 3/4: the bytes it took bought
/// the credit back (kept); one that takes 4 KiB between the pauses is reset in the second (60.78 T2: v1.3.3
/// gave every pause a fresh limit, so a trickler was kept for ever)
#[test]
fn uc_credit_comes_back_only_with_bytes_taken() {
    let (mut w, g, mut c, mut t, _l) = uc_rig();
    g.set_state(bd::ST_UNREAD);
    let p = UC_TEST_MS / 4 * 3;
    let read = |ms: u64| if (p..p + 1000).contains(&ms) { u64::MAX } else { 0 };
    let first = uc_run(&mut w, &mut c, &mut t, p + 1000, read);
    assert_eq!(first, None);
    // (uc_run's byte count starts at 0 again: nothing more is read)
    assert_eq!(uc_run(&mut w, &mut c, &mut t, p, |_| 0), None, "the bytes it took bought the credit back");
    end(w);
    let (mut w, g, mut c, mut t, _l) = uc_rig();
    g.set_state(bd::ST_UNREAD);
    assert_eq!(uc_run(&mut w, &mut c, &mut t, p, |_| 0), None);
    let at = uc_run(&mut w, &mut c, &mut t, 2 * UC_TEST_MS, |_| 4096);
    assert!(at.is_some_and(|ms| ms <= UC_TEST_MS / 4 + 3 * UC_SWEEP_MS), "reset in the second pause: {at:?}");
    end(w);
}

/// E5 a connection that holds far more of the host's TCP memory than one full stream (here: m0 = 4 KiB) uses its
/// credit up that much faster: reset within a few sweeps under the mark, long before the starting credit
#[test]
fn uc_a_connection_that_holds_more_uses_its_credit_faster() {
    let (mut w, g, mut c, mut t, _l) = uc_rig_with(UC_TEST_MS, Some(8192), 4096);
    g.set_state(bd::ST_UNREAD);
    let at = uc_run(&mut w, &mut c, &mut t, 2 * UC_TEST_MS, |_| 0);
    assert!(at.is_some_and(|ms| ms <= 3 * UC_SWEEP_MS + 100), "{at:?}");
    end(w);
}

/// E5 at the real times (bounds::UC_STALL_MS = 600 s, a sweep every 2 s) with the kernel's default client buffer
/// (autotuned), under the mark, for UC_REAL_MS (1.5 limits): a reader of 2 KiB per second, one that pauses 15 s and then
/// reads 2 KiB per second, and one that first reads 5 MiB at 1 MiB/s (its buffer grows) and then 2 KiB per second, are
/// kept. Real time (the window gap of a slow reader is set by its buffer and the kernel's timers; 60.73 T-wnd-big):
/// opt-in, `cargo test --release -- --ignored uc_real` (about 15 minutes; the three run side by side).
const UC_REAL_MS: u64 = 900_000;

#[test]
#[ignore]
fn uc_real_keeps_a_reader_of_2_kib_per_s() {
    let (mut w, g, mut c, mut t, _l) = uc_rig_with(bd::UC_STALL_MS, None, 0);
    g.set_state(bd::ST_UNREAD);
    assert_eq!(uc_run_at(&mut w, &mut c, &mut t, UC_REAL_MS, 2_000, |ms| ms * 2048 / 1000), None);
    end(w);
}

#[test]
#[ignore]
fn uc_real_keeps_a_reader_after_a_pause_of_15_s() {
    let (mut w, g, mut c, mut t, _l) = uc_rig_with(bd::UC_STALL_MS, None, 0);
    g.set_state(bd::ST_UNREAD);
    assert_eq!(uc_run_at(&mut w, &mut c, &mut t, UC_REAL_MS, 2_000, |ms| ms.saturating_sub(15_000) * 2048 / 1000), None);
    end(w);
}

#[test]
#[ignore]
fn uc_real_keeps_a_reader_of_2_kib_per_s_after_a_fast_start() {
    let (mut w, g, mut c, mut t, _l) = uc_rig_with(bd::UC_STALL_MS, None, 0);
    g.set_state(bd::ST_UNREAD);
    let read = |ms: u64| if ms < 5_000 { ms * 1024 } else { (5 << 20) + (ms - 5_000) * 2048 / 1000 };
    assert_eq!(uc_run_at(&mut w, &mut c, &mut t, UC_REAL_MS, 2_000, read), None);
    end(w);
}

// ---- 60.78 G70 --unread-close's relief

/// G70: --unread-close (with its relief) on a host of 1600 pages with 100 TCP sockets allocated: the share is 64 KiB,
/// so a parked target socket whose memory is above 32 KiB is read out (its buffer then: 2 x 16 KiB). One client of
/// a public address that does not read (8 KiB receive buffer) with one stream (sid 1); `f` changes the configuration.
fn rl_rig(f: impl FnOnce(&mut Config)) -> (Worker, Arc<Bounds>, TcpStream, u32, TcpStream) {
    let g = Arc::new(Bounds::new(OPT_UNREAD | OPT_RELIEF, 1, TcpForm::Mem { max_pages: 1600 }, 4096, 131_072));
    g.set_socks(100);
    assert_eq!(g.share_bytes(), Some(64 << 10));
    let (mut w, port, _rx) = bd_rig_cfg(false, 4, g.clone(), f);
    w.rl_set_cap(64 << 20);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    // the destination sends segments of 1448 bytes, as on a real network (loopback's 64 KiB MSS does not fit the small
    // buffer relief sets, and the sender would wait for zero-window probes)
    let mss: libc::c_int = 1448;
    assert_eq!(unsafe { libc::setsockopt(l.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_MAXSEG, &mss as *const _ as *const _, 4) }, 0);
    let (mut c, ci) = uc_client(&mut w, port, Some(8192));
    let t = streams(&mut w, &mut c, 1, 1, &l).pop().unwrap();
    c.set_nonblocking(true).unwrap();
    (w, g, c, ci, t)
}

/// the test's byte at offset `i` of the download: a sequence that shows a lost, repeated or moved byte
fn rl_byte(i: u64) -> u8 {
    (i % 251) as u8
}

/// the target sends the sequence on from `sent` until its socket takes no more, or `upto` bytes in all
fn rl_feed(t: &mut TcpStream, sent: &mut u64, upto: u64) {
    while *sent < upto {
        let n = (upto - *sent).min(16384) as usize;
        let b: Vec<u8> = (*sent..*sent + n as u64).map(rl_byte).collect();
        match t.write(&b) {
            Ok(k) if k > 0 => *sent += k as u64,
            _ => return,
        }
    }
}

/// the one target's slot, and the bytes in its socket's receive queue (our side)
fn rl_ti(w: &Worker) -> u32 {
    w.targets.slots.iter().position(|s| s.1.is_some()).unwrap() as u32
}
fn rl_q(w: &mut Worker) -> u64 {
    let ti = rl_ti(w);
    bd::queued(w.targets.at(ti).fd, libc::FIONREAD)
}

/// What the client got of stream 1: the DATA bytes (checked against the sequence as they come) and the CLOSE reason
#[derive(Default)]
struct RlRead {
    buf: Vec<u8>,
    upgraded: bool,
    got: u64,
    closed: Option<u8>,
}

impl RlRead {
    /// reads what the client socket has and checks every DATA byte of stream 1 against the sequence
    fn read(&mut self, c: &mut TcpStream) {
        let mut b = vec![0u8; 1 << 16];
        while let Ok(n) = c.read(&mut b) {
            if n == 0 {
                break;
            }
            self.buf.extend_from_slice(&b[..n]);
        }
        if !self.upgraded {
            // (the 101 response first: uc_client never read it)
            let Some(at) = self.buf.windows(4).position(|x| x == b"\r\n\r\n") else { return };
            self.buf.drain(..at + 4);
            self.upgraded = true;
        }
        loop {
            if self.buf.len() < 2 {
                return;
            }
            let (hl, plen) = match self.buf[1] & 0x7f {
                126 if self.buf.len() >= 4 => (4, u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize),
                126 => return,
                127 if self.buf.len() >= 10 => (10, u64::from_be_bytes(self.buf[2..10].try_into().unwrap()) as usize),
                127 => return, // (a splice frame: its length takes 8 bytes)
                n => (2, n as usize),
            };
            if self.buf.len() < hl + plen {
                return;
            }
            let p: Vec<u8> = self.buf[hl..hl + plen].to_vec();
            self.buf.drain(..hl + plen);
            if p.len() < 5 || u32::from_le_bytes([p[1], p[2], p[3], p[4]]) != 1 {
                continue;
            }
            match p[0] {
                2 => {
                    for (k, &x) in p[5..].iter().enumerate() {
                        let at = self.got + k as u64;
                        assert_eq!(x, rl_byte(at), "stream 1, byte {at}: lost, repeated or out of order");
                    }
                    assert!(self.closed.is_none(), "DATA after CLOSE");
                    self.got += (p.len() - 5) as u64;
                }
                4 => self.closed = Some(p[5]),
                _ => {}
            }
        }
    }
}

/// one sweep's steps of section E (bd_count, then bd_unread: E5's step, then the relief)
fn rl_sweep(w: &mut Worker) {
    let now = metrics::now_ms();
    w.bd_count(now);
    w.bd_unread(now);
}

/// the receive memory of the one target's socket (SO_MEMINFO's rmem_alloc: what relief compares with the share)
fn rl_mem(w: &mut Worker) -> u64 {
    let ti = rl_ti(w);
    let mut m = [0u32; 9];
    let mut len = 36u32;
    assert_eq!(unsafe { libc::getsockopt(w.targets.at(ti).fd, libc::SOL_SOCKET, 55, m.as_mut_ptr() as *mut _, &mut len) }, 0);
    m[0] as u64
}

/// the target sends and the client does not read: until the stream is parked and its socket's memory is above `n`
fn rl_fill(w: &mut Worker, t: &mut TcpStream, sent: &mut u64, n: u64) {
    // (still so after a pump without new bytes: a stream parked behind its own splice with the client's output below
    // out_high is resumed at the next flush and reads on; it parks for good only at out_high)
    loop {
        let mut last;
        let end_at = Instant::now() + Duration::from_secs(20);
        let mut moved = (*sent, Instant::now());
        while {
            rl_feed(t, sent, u64::MAX);
            last = (unread(w), rl_mem(w), *sent);
            !(last.0 == 1 && last.1 > n)
        } {
            if *sent != moved.0 {
                moved = (*sent, Instant::now());
            } else if moved.1.elapsed() > Duration::from_millis(300) {
                // the destination waits in zero-window probes (backoff: up to seconds) after our socket's window was
                // 0 and the worker read it down without a window update (seen on a loaded host); a peek runs the
                // kernel's tcp_cleanup_rbuf, which sends one. (Not relief's doing: before any sweep.)
                let ti = rl_ti(w);
                let mut b = 0u8;
                unsafe { libc::recv(w.targets.at(ti).fd, &mut b as *mut u8 as *mut _, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
                moved.1 = Instant::now();
            }
            if Instant::now() >= end_at {
                let ti = rl_ti(w);
                let tfd = w.targets.at(ti).fd;
                let mut info = [0u8; 232];
                let mut len = info.len() as libc::socklen_t;
                unsafe { libc::getsockopt(tfd, libc::IPPROTO_TCP, libc::TCP_INFO, info.as_mut_ptr() as *mut _, &mut len) };
                let rcv_space = u32::from_ne_bytes(info[120..124].try_into().unwrap());
                let rcv_ssthresh = u32::from_ne_bytes(info[64..68].try_into().unwrap());
                let (ci, capped, bulk) = (w.targets.at(ti).client, w.targets.at(ti).capped, w.targets.at(ti).bulk);
                let mut di = [0u8; 232];
                let mut dl = di.len() as libc::socklen_t;
                unsafe { libc::getsockopt(t.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_INFO, di.as_mut_ptr() as *mut _, &mut dl) };
                eprintln!(
                    "dest: probes {} backoff {} unsent(outq) {} rto {}",
                    di[3],
                    di[4],
                    bd::queued(t.as_raw_fd(), libc::TIOCOUTQ),
                    u32::from_ne_bytes(di[8..12].try_into().unwrap())
                );
                panic!(
                    "not parked above half the share: (parked, memory, sent) {last:?}; lock/rcvbuf {:?} sock_cap {} capped {} pend {} rcv_space {rcv_space} rcv_ssthresh {rcv_ssthresh} bulk {}",
                    rl_lock_rcv(tfd), w.st.sock_cap, capped, w.clients.at(ci).out_pending(), bulk
                );
            }
            pump(w, 5);
        }
        pump(w, 20);
        if unread(w) == 1 && rl_mem(w) > n {
            return;
        }
    }
}

/// SO_BUF_LOCK's bits and SO_RCVBUF of a socket
fn rl_lock_rcv(fd: RawFd) -> (i32, i32) {
    let get = |opt| {
        let (mut v, mut len) = (0i32, 4u32);
        assert_eq!(unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, opt, &mut v as *mut _ as *mut _, &mut len) }, 0);
        v
    };
    (get(72), get(libc::SO_RCVBUF))
}

/// G70 relief end to end, for both lanes (`prio`: the bulk lane, with splice; else obuf only): no mark, nothing moves;
/// with the mark the parked socket is read out under the lock and a 32 KiB buffer; the client then reads
/// every byte the target sent, in order (relief bytes between what was queued before them and what the next read
/// takes); reading again under the pressure keeps the lock and the small buffer, the end of the pressure lifts it.
/// `warm`: the stream's next read takes the splice path (Target::bulk set, as tests.rs splice_length_steps does; the
/// queues are empty): the target parks with bytes in the splice pipe that the client socket did not take, and relief's
/// bytes must go out after them.
fn rl_order(prio: bool, warm: bool) {
    rl_order_with(prio, warm, false)
}

/// ... `short`: the stream's last read was short (Target::bulk false) while its earlier frames wait in the bulk lane:
/// the lane is still the bulk lane (bulk_end), and the next read must stay behind relief's frames (bulk_end moves)
fn rl_order_with(prio: bool, warm: bool, short: bool) {
    let (mut w, g, mut c, ci, mut t) = rl_rig(|cfg| cfg.prio = prio);
    let mut sent = 0u64;
    let mut rd = RlRead::default();
    if warm {
        let ti = rl_ti(&w);
        w.targets.at(ti).bulk = true;
    }
    rl_fill(&mut w, &mut t, &mut sent, 32 << 10);
    if short {
        let ti = rl_ti(&w);
        let c = w.targets.at(ti).client;
        let (bs, be) = (w.clients.at(c).bulk_sent, w.targets.at(ti).bulk_end);
        assert!(be > bs, "the case: frames of the stream wait in the bulk lane");
        w.targets.at(ti).bulk = false;
    }
    rl_sweep(&mut w);
    assert_eq!((w.stats.relief_streams.get(), w.stats.relief_bytes.get()), (0, 0), "no mark: nothing");
    g.set_state(bd::ST_UNREAD);
    let (q, ti) = (rl_q(&mut w), rl_ti(&w));
    let saved = rl_lock_rcv(w.targets.at(ti).fd).1;
    let (pipe, lane) = (w.clients.at(ci).splice_pending, w.clients.at(ci).bulk.len() - w.clients.at(ci).bhead);
    eprintln!("prio {prio} warm {warm}: {q} bytes queued at relief, {pipe} in the splice pipe, {lane} in the bulk lane");
    assert!(!warm || pipe > 0, "the case: bytes in the splice pipe at relief");
    rl_sweep(&mut w);
    assert_eq!(w.stats.relief_streams.get(), 1);
    assert!(w.stats.relief_bytes.get() >= q, "all that was queued: {} of {q}", w.stats.relief_bytes.get());
    let left = rl_q(&mut w);
    assert!(left <= 32 << 10, "read down under its new buffer: {left}");
    let fd = w.targets.at(ti).fd;
    assert_eq!(rl_lock_rcv(fd), (2, 32 << 10), "locked, buffer 2 x 16 KiB");
    assert!(w.rl_held(ti));
    rl_sweep(&mut w);
    assert_eq!(w.stats.relief_streams.get(), 1, "under the lock it holds no more: no second relief");
    let total = sent + (4 << 20);
    until(&mut w, "the client has every byte", |_| {
        rd.read(&mut c);
        rl_feed(&mut t, &mut sent, total);
        rd.got == total
    });
    rl_sweep(&mut w);
    assert!(w.rl_held(ti), "read again under the pressure: still locked");
    assert_eq!(rl_lock_rcv(fd), (2, 32 << 10));
    g.set_state(0);
    rl_sweep(&mut w);
    assert!(!w.rl_held(ti), "the pressure is over: lifted");
    // the size from before as rl_lift sets it: SO_RCVBUF of half of it, which the kernel clamps to net.core.rmem_max and
    // doubles (a buffer that autotuning grew past 2 x rmem_max comes back at that bound: CI's default rmem_max 212992).
    // The expected size is measured the same way on a socket of its own (rmem_max may not be readable in a container)
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let half: libc::c_int = saved / 2;
    // SAFETY: setsockopt reads one c_int from `half`
    let r = unsafe { libc::setsockopt(probe.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, &half as *const _ as *const _, 4) };
    assert_eq!(r, 0);
    let back = rl_lock_rcv(probe.as_raw_fd()).1;
    assert_eq!(rl_lock_rcv(fd), (0, back), "the size from before (its half doubled, rmem_max clamp), the lock bit clear");
    end(w);
}

#[test]
fn rl_keeps_the_order_bulk_lane() {
    rl_order(true, false);
}

#[test]
fn rl_keeps_the_order_obuf() {
    rl_order(false, false);
}

#[test]
fn rl_keeps_the_order_lane_after_a_short_read() {
    rl_order_with(true, false, true);
}

#[test]
fn rl_keeps_the_order_behind_a_splice() {
    rl_order(true, true);
    rl_order(false, true);
}

/// G70 the target ends while relief bytes are queued: FIN, then (second case) a reset. Relief reads only what is
/// queued, so the end stays for read_target: the client gets every byte, then the stream's CLOSE.
fn rl_end(reset: bool) {
    let (mut w, g, mut c, _ci, mut t) = rl_rig(|_| {});
    let mut sent = 0u64;
    rl_fill(&mut w, &mut t, &mut sent, 32 << 10);
    // what reached our side (a reset drops what the destination had not sent yet)
    let ti = rl_ti(&w);
    let mut info = [0u8; 232];
    let mut len = info.len() as libc::socklen_t;
    let fd = w.targets.at(ti).fd;
    assert_eq!(unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, info.as_mut_ptr() as *mut _, &mut len) }, 0);
    let arrived = u64::from_ne_bytes(info[128..136].try_into().unwrap());
    if reset {
        let l = libc::linger { l_onoff: 1, l_linger: 0 };
        assert_eq!(unsafe { libc::setsockopt(t.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER, &l as *const _ as *const _, 8) }, 0);
        drop(t);
    } else {
        t.shutdown(std::net::Shutdown::Write).unwrap();
    }
    pump(&mut w, 20);
    g.set_state(bd::ST_UNREAD);
    rl_sweep(&mut w);
    assert_eq!(w.stats.relief_streams.get(), 1);
    let mut rd = RlRead::default();
    until(&mut w, "the client has the stream's CLOSE", |_| {
        rd.read(&mut c);
        rd.closed.is_some()
    });
    eprintln!("reset {reset}: {} of {sent} bytes, CLOSE {:#x}", rd.got, rd.closed.unwrap());
    assert_eq!(rd.got, if reset { arrived } else { sent }, "every byte that reached us, before the CLOSE");
    let want = if reset { net::data_reason(libc::ECONNRESET) } else { CLOSE_VOLUNTARY };
    assert_eq!(rd.closed, Some(want), "the end's reason (a reset is not reported as a FIN)");
    end(w);
}

#[test]
fn rl_a_fin_waits_behind_the_relief_bytes() {
    rl_end(false);
}

#[test]
fn rl_a_reset_waits_behind_the_relief_bytes() {
    rl_end(true);
}

/// G70 the cap: a socket whose bytes would pass it is left as it is and counted; a socket locked by someone else
/// (a cap of the memory budget, or another lock holder) is left alone; a closed target's entry goes at the next sweep
#[test]
fn rl_cap_foreign_lock_and_close() {
    let (mut w, g, mut c, _ci, mut t) = rl_rig(|_| {});
    let mut sent = 0u64;
    rl_fill(&mut w, &mut t, &mut sent, 32 << 10);
    g.set_state(bd::ST_UNREAD);
    w.rl_set_cap(1000);
    rl_sweep(&mut w);
    assert_eq!((w.stats.relief_streams.get(), w.stats.relief_capped.get()), (0, 1), "over the cap: counted, left");
    let ti = rl_ti(&w);
    let fd = w.targets.at(ti).fd;
    assert_eq!(rl_lock_rcv(fd).0, 0, "not locked");
    w.rl_set_cap(64 << 20);
    let v = 2i32;
    assert_eq!(unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, 72, &v as *const _ as *const _, 4) }, 0);
    rl_sweep(&mut w);
    assert_eq!(w.stats.relief_streams.get(), 0, "someone else's lock: left alone");
    let v = 0i32;
    assert_eq!(unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, 72, &v as *const _ as *const _, 4) }, 0);
    rl_sweep(&mut w);
    assert_eq!(w.stats.relief_streams.get(), 1);
    assert!(w.rl_held(ti));
    c.write_all(&wisp(0x04, 1, &[0x02])).unwrap(); // the client closes the stream
    until(&mut w, "the stream is closed", |w| open_streams(w) == 0);
    rl_sweep(&mut w);
    assert!(!w.rl_held(ti), "a closed target's entry goes");
    end(w);
}

/// G70 the pressure ends while the stream is still parked: the lift at the next sweep gives back the size from before
/// and clears the lock bit; a size someone else set since is left as it is
#[test]
fn rl_lifts_when_the_pressure_ends() {
    let (mut w, g, _c, _ci, mut t) = rl_rig(|_| {});
    let mut sent = 0u64;
    rl_fill(&mut w, &mut t, &mut sent, 32 << 10);
    let ti = rl_ti(&w);
    let fd = w.targets.at(ti).fd;
    let saved = rl_lock_rcv(fd).1;
    g.set_state(bd::ST_UNREAD);
    rl_sweep(&mut w);
    assert!(w.rl_held(ti) && rl_lock_rcv(fd).0 == 2);
    g.set_state(0);
    rl_sweep(&mut w);
    assert!(w.targets.at(ti).blocked, "still parked");
    assert!(!w.rl_held(ti));
    assert_eq!(rl_lock_rcv(fd), (0, saved & !1), "lock bit clear, the size from before");
    assert_eq!(w.stats.relief_streams.get(), 1);
    end(w);
    // a size set by someone else since (a cap of the memory budget and its uncap) is left as it is
    let (mut w, g, _c, _ci, mut t) = rl_rig(|_| {});
    let mut sent = 0u64;
    rl_fill(&mut w, &mut t, &mut sent, 32 << 10);
    let ti = rl_ti(&w);
    let fd = w.targets.at(ti).fd;
    g.set_state(bd::ST_UNREAD);
    rl_sweep(&mut w);
    assert!(w.rl_held(ti));
    let v = 6000i32;
    assert_eq!(unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &v as *const _ as *const _, 4) }, 0);
    g.set_state(0);
    rl_sweep(&mut w);
    assert!(!w.rl_held(ti));
    assert_eq!(rl_lock_rcv(fd), (2, 12000), "not ours: left");
    end(w);
}

/// G70 someone clears our lock bit while the pressure lasts (a caps episode's uncap, or another holder's lift): the next
/// sweep sets it again; after the pressure the lift still gives back the size from before
#[test]
fn rl_takes_the_lock_again_under_the_pressure() {
    let (mut w, g, _c, _ci, mut t) = rl_rig(|_| {});
    let mut sent = 0u64;
    rl_fill(&mut w, &mut t, &mut sent, 32 << 10);
    let ti = rl_ti(&w);
    let fd = w.targets.at(ti).fd;
    let saved = rl_lock_rcv(fd).1;
    g.set_state(bd::ST_UNREAD);
    rl_sweep(&mut w);
    assert_eq!(rl_lock_rcv(fd), (2, 32 << 10));
    let v = 0i32;
    assert_eq!(unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, 72, &v as *const _ as *const _, 4) }, 0);
    rl_sweep(&mut w);
    assert_eq!(rl_lock_rcv(fd), (2, 32 << 10), "locked again");
    assert_eq!(w.stats.relief_streams.get(), 1, "no second read-down");
    g.set_state(0);
    rl_sweep(&mut w);
    assert_eq!(rl_lock_rcv(fd), (0, saved & !1));
    end(w);
}
