//! 60.78 G16: the counters no test asserted before (bench/tools/counter_cover.py lists them): one test per event, on the
//! worker rigs of tests.rs. accept_err_mem is the one exception (counter_cover.py EXCEPTIONS: accept4 failing with ENOBUFS
//! / ENOMEM needs kernel memory exhaustion; the same branch counts accept_err_fd for EMFILE / ENFILE).
use super::super::*;
use super::fd;

/// a worker with one Open client on a socketpair (slot 0) and its peer end
fn one_client(cfg: Config) -> (Worker, std::os::unix::net::UnixStream) {
    use std::os::fd::FromRawFd;
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(Arc::new(cfg), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    w.pend_cap = usize::MAX; // (mem::tests may set a global budget meanwhile)
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
    w.inbox.load.fetch_add(1, Relaxed);
    assert!(w.fd_take(1));
    w.adopt(net::Handoff::bare(fds[0]));
    (w, unsafe { std::os::unix::net::UnixStream::from_raw_fd(fds[1]) })
}

/// the backlog queued on target `ti` (bytes not yet taken by its socket)
fn backlog(w: &mut Worker, ti: u32) -> usize {
    let t = w.targets.at(ti);
    t.pend.len() - t.phead
}

/// pend_pauses: the client with the largest share of an upload backlog over pend_cap is not read; shed_pend: still over
/// the cap PEND_SHED_SWEEPS sweeps later, the largest backlog is shed (CLOSE 0x49)
#[test]
fn upload_backlog_over_pend_cap_pauses_then_sheds() {
    let (mut w, mut peers, _cl) = super::up_rig(1, true);
    let (ti, tg, _) = peers[0];
    w.targets.at(ti).allow = 1 << 30; // in credit: no over-credit close
    w.pend_cap = 1 << 20;
    let chunk = vec![7u8; 1 << 20];
    while backlog(&mut w, ti) <= 1 << 20 {
        w.write_target(ti, &chunk);
    }
    assert!(w.clients.at(0).mpaused);
    assert_eq!(w.stats.pend_pauses.get(), 1);
    for _ in 0..PEND_SHED_SWEEPS {
        assert!(w.targets.get(ti, tg).is_some());
        w.sweep();
    }
    assert!(w.targets.get(ti, tg).is_none(), "shed");
    assert_eq!((w.stats.shed_pend.get(), w.stats.close[0x49].get()), (1, 1));
    assert!(!w.clients.at(0).dead && !w.clients.at(0).mpaused, "the client stays and is read again");
    drop(peers.drain(..));
    std::mem::forget(w);
}

/// shed_l3_enter: entering level 3, a stream with more than 1 MiB of unsent upload is shed (CLOSE 0x49)
#[test]
fn entering_level_3_sheds_a_big_upload_backlog() {
    let (mut w, peers, _cl) = super::up_rig(2, true);
    let ((big, bg, _), (small, sg, _)) = (&peers[0], &peers[1]);
    let (big, bg, small, sg) = (*big, *bg, *small, *sg);
    w.targets.at(big).allow = 1 << 30;
    let chunk = vec![7u8; 1 << 20];
    while backlog(&mut w, big) <= 3 << 19 {
        w.write_target(big, &chunk);
    }
    w.write_target(small, &[7u8; 1000]);
    w.set_levels(3, 0);
    assert!(w.targets.get(big, bg).is_none() && w.targets.get(small, sg).is_some());
    assert_eq!((w.stats.shed_l3_enter.get(), w.stats.close[0x49].get()), (1, 1));
    w.set_levels(0, 0); // (the pool pause of level 2+ ends)
    std::mem::forget(w);
}

/// shed_client: level 3 without progress for L3_STUCK_SWEEPS sweeps closes the client holding the most memory (RST)
#[test]
fn a_stuck_level_3_sheds_a_client() {
    let (mut w, _peers, _cl) = super::up_rig(0, false);
    w.set_levels(3, 0);
    (w.l3_mark, w.l3_sweeps) = (0, L3_STUCK_SWEEPS - 1); // (mem::USED made no new low: no global state read)
    w.sweep();
    assert!(w.clients.at(0).dead, "shed");
    assert_eq!(w.stats.shed_client.get(), 1);
    w.reap_dead();
    w.set_levels(0, 0);
    std::mem::forget(w);
}

/// hs_expired: a connection that has not finished its HTTP upgrade by the HS_SWEEPS-th sweep is closed
#[test]
fn an_unfinished_upgrade_expires() {
    let (mut w, _peer) = one_client(fd::fd_cfg());
    assert!(w.clients.at(0).state == CState::Http);
    for k in 1..HS_SWEEPS {
        w.sweep();
        assert!(!w.clients.at(0).dead, "sweep {k}");
    }
    w.sweep();
    assert!(w.clients.at(0).dead);
    assert_eq!(w.stats.hs_expired.get(), 1);
    w.reap_dead();
    std::mem::forget(w);
}

/// tls_expired: a TLS client whose handshake is not done by its deadline (TLS_HANDSHAKE_TIMEOUT) is closed
#[test]
fn an_unfinished_tls_handshake_expires() {
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
    let mut cfg = fd::fd_cfg();
    cfg.tls = Some(Arc::new(tc));
    let (mut w, _peer) = one_client(cfg);
    assert!(w.clients.at(0).state == CState::Tls);
    w.tls_timeouts();
    assert!(!w.clients.at(0).dead, "before the deadline");
    assert_eq!(w.tls_deadlines.len(), 1);
    w.tls_deadlines[0].2 = Instant::now() - Duration::from_millis(1); // (the deadline has passed)
    w.tls_timeouts();
    assert!(w.clients.at(0).dead);
    assert_eq!(w.stats.tls_expired.get(), 1);
    w.reap_dead();
    std::mem::forget(w);
}

/// refuse_dns: a CONNECT to a name while DNS_INFLIGHT_MAX lookups are in flight gets CLOSE 0x49 at once
#[test]
fn a_connect_over_the_dns_inflight_cap_is_refused() {
    let (mut w, _peers, _cl) = super::up_rig(0, false);
    w.dns_inflight = DNS_INFLIGHT_MAX;
    assert!(w.new_target(0, 1, "name.test".into(), 80, false, false).is_none());
    assert_eq!((w.stats.refuse_dns.get(), w.stats.dns_miss.get(), w.stats.close[0x49].get()), (1, 0, 1));
    w.dns_inflight = 0;
    std::mem::forget(w);
}

/// ktls_starve: a kTLS client whose send is refused with nothing in flight is still refused at the first timer retry
/// (the episode counts once, at its second step); ktls_starve_end when it closes. The refusal is the T40 test hook
/// (Client::ku_refuse: a KeyUpdate refused like a charge over tcp_mem[2]); the socket has nothing in flight.
#[test]
fn a_starved_ktls_send_counts_one_episode() {
    let (mut w, _peer) = one_client(fd::fd_cfg());
    let c = w.clients.at(0);
    c.state = CState::Open;
    (c.ktls_on, c.ku, c.ku_refuse) = (true, 3, true);
    c.obuf = vec![1u8; 100];
    w.mark_dirty(0);
    w.flush_dirty(); // Start (starve 1): not counted yet
    assert_eq!((w.clients.at(0).starve, w.stats.ktls_starve.get()), (1, 0));
    w.clients.at(0).starve_due = true; // the timer retry (starve_check)
    w.mark_dirty(0);
    w.flush_dirty();
    assert_eq!((w.clients.at(0).starve, w.stats.ktls_starve.get()), (2, 1));
    w.clients.at(0).starve_due = true;
    w.mark_dirty(0);
    w.flush_dirty();
    assert_eq!(w.stats.ktls_starve.get(), 1, "one episode");
    w.close_client(0, Why::ServerClose);
    assert_eq!(w.stats.ktls_starve_end.get(), 1);
    w.reap_dead();
    std::mem::forget(w);
}

/// ip_untracked: a client whose key finds its per-IP table shard full is not tracked (fail open: accepted, counted)
#[test]
fn a_client_over_a_full_ip_table_is_untracked() {
    use std::os::fd::FromRawFd;
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(super::clientip_cfg(&[], 0, false, 1, None), tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let port = unsafe { std::net::TcpListener::from_raw_fd(libc::dup(w.lfd)) }.local_addr().unwrap().port();
    let tab = w.cfg.clientip.as_ref().unwrap().table.as_ref().unwrap();
    let mut n = 0u32;
    while tab.keys() < clientip::SHARDS * clientip::SHARD_CAP {
        let k = clientip::key(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n)));
        let _ = tab.charge(k, 0, 0);
        n += 1;
        assert!(n < 4_000_000);
    }
    let p = super::connect_from([127, 0, 0, 3], port);
    std::thread::sleep(Duration::from_millis(20));
    w.accept_all();
    assert_eq!((w.stats.accepted.get(), w.stats.ip_untracked.get()), (1, 1));
    assert!(w.peer(0).is_some_and(|p| p.key.is_none()), "not charged");
    for fd in [w.ep, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    drop(p);
    std::mem::forget(w);
}

/// dest_untracked: a stream whose destination finds its table shard full of live entries is not limited (fail open);
/// dest_keys_max: the keys in the table at the idle sweep
#[test]
fn a_stream_over_a_full_dest_table_is_untracked() {
    let up = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let uport = up.local_addr().unwrap().port();
    // a minute bucket of 4: one take leaves an entry live for 15 s (a full shard keeps it)
    let cfg = super::dest_cfg(crate::destrate::DestTable::new(None, Some(4)), None);
    let (tx, _rx) = mpsc::channel();
    let mut w = Worker::new(cfg, tx, 0, Arc::new(vec![Inbox::new()]), Arc::default()).unwrap();
    let mut peer = super::dest_client(&mut w);
    let d = w.cfg.dest_rate.as_deref().unwrap();
    let full = clientip::SHARDS * clientip::SHARD_CAP;
    let mut n = 0u32;
    while d.keys() < full {
        let k = crate::destrate::DestTable::ip_key(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n)), 443);
        let _ = d.take(k, metrics::now_ms());
        n += 1;
        assert!(n < 4_000_000);
    }
    super::dest_send(&mut w, &mut peer, &[(1, 1, uport, "127.0.0.1")]);
    assert_eq!((w.stats.dest_untracked.get(), w.stats.refuse_dest_rate.get()), (1, 0));
    assert!(w.clients.at(0).streams.contains_key(&1), "not refused");
    w.next_sweep = Instant::now();
    assert!(w.idle_sweep(Instant::now()));
    assert_eq!(w.stats.dest_keys_max.get(), full as u64);
    for fd in [w.ep, w.lfd, w.inbox.efd] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w);
}
