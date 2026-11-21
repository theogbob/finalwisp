//! 20.34 worker tests for the ping gate (worker/pinggate.rs): a real Worker through its own epoll (the helpers of
//! fdtests.rs), real client and destination sockets. The client of these tests answers the gate PING by hand (as a
//! WebSocket client must, RFC 6455 5.5.2), or never, to pin what a client that does not answer gets.
use super::super::pinggate::{CAP_MS, PER_CONN, TAG};
use super::super::*;
use super::fd::{client_with, closed_with, connect, drain, fd_cfg, pump, rig, until, wisp};
use std::io::Write as _;
use std::net::{TcpListener, TcpStream};

const VOLUNTARY: u8 = 0x02;

fn hello(v2: bool, origin: bool) -> Vec<u8> {
    let mut h = b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n".to_vec();
    if v2 {
        h.extend(b"Sec-WebSocket-Protocol: wisp-v2\r\n");
    }
    if origin {
        h.extend(b"Origin: https://a.example\r\n");
    }
    h.extend(b"\r\n");
    if v2 {
        h.extend(wisp(0x05, 0, &[2, 0])); // the client's INFO (Wisp 2.0, no extension)
    }
    h
}

/// a masked (zero key) control frame
fn ctl(op: u8, p: &[u8]) -> Vec<u8> {
    let mut f = vec![0x80 | op, 0x80 | p.len() as u8, 0, 0, 0, 0];
    f.extend_from_slice(p);
    f
}

/// the server frames in `got` after the 101 answer, complete frames only: (opcode, payload)
fn frames(got: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut i = got.windows(4).position(|x| x == b"\r\n\r\n").map_or(got.len(), |p| p + 4);
    let mut v = Vec::new();
    while i + 2 <= got.len() {
        let (mut len, mut h) = ((got[i + 1] & 0x7f) as usize, 2);
        if len == 126 {
            len = u16::from_be_bytes([got[i + 2], got[i + 3]]) as usize;
            h = 4;
        } else if len == 127 {
            len = u64::from_be_bytes(got[i + 2..i + 10].try_into().unwrap()) as usize;
            h = 10;
        }
        if i + h + len > got.len() {
            break;
        }
        v.push((got[i] & 0x0f, got[i + h..i + h + len].to_vec()));
        i += h + len;
    }
    v
}

/// the gate PINGs in `got`, in order (their payloads)
fn pings(got: &[u8]) -> Vec<Vec<u8>> {
    frames(got).into_iter().filter(|(op, p)| *op == 0x9 && p.len() == 6 && p[..2] == TAG).map(|f| f.1).collect()
}

/// Wisp CLOSEs for `sid` in `got`
fn closes(got: &[u8], sid: u32) -> usize {
    frames(got).iter().filter(|(op, p)| *op == 0x2 && p.len() == 6 && p[0] == 0x04 && p[1..5] == sid.to_le_bytes()).count()
}

/// CONNECT stream `sid` to `l` and wait until it is open; its destination socket
fn open(w: &mut Worker, c: &mut TcpStream, ci: u32, sid: u32, l: &TcpListener) -> TcpStream {
    c.write_all(&connect(sid, false, l.local_addr().unwrap().port())).unwrap();
    until(w, "stream open", |w| {
        let ti = w.clients.at(ci).streams.get(&sid).copied();
        ti.is_some_and(|ti| w.targets.slots[ti as usize].1.as_ref().is_some_and(|t| t.state == TState::Open))
    });
    l.accept().unwrap().0
}

/// the destination sends its last bytes and ends the stream (FIN); returns once the worker has handled it
fn end_stream(w: &mut Worker, ci: u32, sid: u32, mut t: TcpStream) {
    t.write_all(b"the last bytes").unwrap();
    drop(t);
    until(w, "the destination's end handled", |w| !w.clients.at(ci).streams.contains_key(&sid));
}

fn cg(w: &Worker, ci: u32) -> u32 {
    w.clients.slots[ci as usize].0
}

/// pump for `ms` (the client reads meanwhile)
fn pump_for(w: &mut Worker, c: &mut TcpStream, got: &mut Vec<u8>, ms: u64) {
    let end_at = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < end_at {
        pump(w, 5);
        drain(c, got);
    }
}

fn end(w: Worker) {
    for fd in [w.ep, w.lfd, w.inbox.efd, w.spare] {
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    std::mem::forget(w); // (as fdtests)
}

/// Wisp v1 and v2: the destination ends a stream; its DATA, then the gate PING (6 bytes: TAG + number) reach the
/// client, its CLOSE does not. A credit-v2 PONG (8 bytes), a gate PONG with another number or without the tag release
/// nothing; the PONG of the PING releases the CLOSE (counted in close[2] only then)
#[test]
fn a_close_waits_for_the_pong_v1_and_v2() {
    for v2 in [false, true] {
        let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
        let (mut c, ci) = client_with(&mut w, port, &hello(v2, false));
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let t = open(&mut w, &mut c, ci, 1, &l);
        end_stream(&mut w, ci, 1, t);
        let mut got = Vec::new();
        until(&mut w, "the gate PING", |w| {
            pump(w, 0);
            drain(&mut c, &mut got);
            !pings(&got).is_empty()
        });
        let f = frames(&got);
        let data = f.iter().position(|(op, p)| *op == 0x2 && p[0] == 0x02 && p[1..5] == 1u32.to_le_bytes()).expect("its DATA");
        let ping = f.iter().position(|(op, _)| *op == 0x9).unwrap();
        assert!(data < ping, "v2 {v2}: the PING goes behind the stream's DATA");
        let p = pings(&got)[0].clone();
        assert_eq!((w.gate.held(ci, cg(&w, ci)), w.stats.ping_gate_held.get(), w.stats.ping_gate_pings.get()), (1, 1, 1));
        assert_eq!(w.stats.close[VOLUNTARY as usize].get(), 0, "counted when sent");
        pump_for(&mut w, &mut c, &mut got, 200);
        let mut wrong = p.clone();
        wrong[2] ^= 1;
        let mut untagged = p.clone();
        untagged[0] = b'x';
        for f in [ctl(0xA, &7u64.to_le_bytes()), ctl(0xA, &wrong), ctl(0xA, &untagged), ctl(0x9, &p)] {
            c.write_all(&f).unwrap(); // (the last one: a PING from the client is answered, it is no PONG)
        }
        pump_for(&mut w, &mut c, &mut got, 100);
        assert_eq!(closes(&got, 1), 0, "v2 {v2}: no CLOSE without the PONG");
        assert_eq!(w.gate.held(ci, cg(&w, ci)), 1);
        c.write_all(&ctl(0xA, &p)).unwrap();
        until(&mut w, "the CLOSE after the PONG", |_| {
            drain(&mut c, &mut got);
            closed_with(&got, 1, VOLUNTARY)
        });
        let s = &w.stats;
        assert_eq!((s.ping_gate_released.get(), s.ping_gate_capped.get(), s.close[VOLUNTARY as usize].get(), w.gate.live), (1, 0, 1, 0));
        assert_eq!(closes(&got, 1), 1);
        drop(c);
        end(w);
    }
}

/// A client that never answers PINGs (the behaviour pinned, not hidden): its first held CLOSE goes after CAP_MS
/// (counted capped) and the connection is LOST: the next CLOSE goes at once (nopong), without a PING. A late PONG ends
/// LOST: CLOSEs are held again
#[test]
fn a_client_that_never_answers_gets_one_close_after_the_cap_then_at_once() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut c, ci) = client_with(&mut w, port, &hello(false, false));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let t = open(&mut w, &mut c, ci, 1, &l);
    end_stream(&mut w, ci, 1, t);
    let held_at = Instant::now();
    let mut got = Vec::new();
    until(&mut w, "the capped CLOSE", |_| {
        drain(&mut c, &mut got);
        closed_with(&got, 1, VOLUNTARY)
    });
    let waited = held_at.elapsed();
    assert!(waited >= Duration::from_millis(CAP_MS as u64 - 20) && waited < Duration::from_secs(5), "{waited:?}");
    let first = pings(&got);
    assert_eq!(first.len(), 1);
    assert_eq!((w.stats.ping_gate_capped.get(), w.stats.ping_gate_nopong.get(), w.stats.close[VOLUNTARY as usize].get()), (1, 0, 1));
    // LOST: at once, no new PING
    let t = open(&mut w, &mut c, ci, 2, &l);
    let at = Instant::now();
    end_stream(&mut w, ci, 2, t);
    until(&mut w, "the CLOSE at once", |_| {
        drain(&mut c, &mut got);
        closed_with(&got, 2, VOLUNTARY)
    });
    assert!(at.elapsed() < Duration::from_millis(CAP_MS as u64 / 2), "{:?}", at.elapsed());
    assert_eq!((w.stats.ping_gate_nopong.get(), w.stats.ping_gate_held.get(), pings(&got).len()), (1, 1, 1));
    // the late PONG: held again
    c.write_all(&ctl(0xA, &first[0])).unwrap();
    pump_for(&mut w, &mut c, &mut got, 50);
    let t = open(&mut w, &mut c, ci, 3, &l);
    end_stream(&mut w, ci, 3, t);
    assert_eq!((w.stats.ping_gate_held.get(), w.stats.ping_gate_pings.get(), w.gate.held(ci, cg(&w, ci))), (2, 2, 1));
    drop(c);
    end(w);
}

/// A browser (Origin header at the upgrade) gets its CLOSE at once, no PING; the flag goes along when the connection
/// moves to another worker slot (mig_export / mig_import)
#[test]
fn a_browser_is_not_held_also_after_a_move() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut c, ci) = client_with(&mut w, port, &hello(true, true));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let t = open(&mut w, &mut c, ci, 1, &l);
    end_stream(&mut w, ci, 1, t);
    let mut got = Vec::new();
    pump_for(&mut w, &mut c, &mut got, 50);
    assert_eq!((closes(&got, 1), pings(&got).len(), w.stats.ping_gate_browser.get(), w.stats.ping_gate_held.get()), (1, 0, 1, 0));
    let m = w.mig_export(ci);
    let (b, _) = w.mig_import(m).unwrap();
    let t = open(&mut w, &mut c, b, 2, &l);
    end_stream(&mut w, b, 2, t);
    pump_for(&mut w, &mut c, &mut got, 50);
    assert_eq!((closes(&got, 2), pings(&got).len(), w.stats.ping_gate_browser.get()), (1, 0, 2));
    drop(c);
    end(w);
}

/// The client closes a stream whose CLOSE is held (dropped: never sent). A CONNECT of a held id drops the held CLOSE
/// too (it would end the new stream), also when the new stream ends before the PONG: the PONG then releases only the
/// new stream's CLOSE, once, after its DATA
#[test]
fn the_clients_own_close_or_a_reused_id_drops_the_held_close() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut c, ci) = client_with(&mut w, port, &hello(false, false));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let t1 = open(&mut w, &mut c, ci, 1, &l);
    let t2 = open(&mut w, &mut c, ci, 2, &l);
    end_stream(&mut w, ci, 1, t1);
    c.write_all(&wisp(0x04, 1, &[VOLUNTARY])).unwrap();
    until(&mut w, "dropped", |w| w.stats.ping_gate_dropped.get() == 1);
    end_stream(&mut w, ci, 2, t2); // held behind the PING in flight
    let t2b = open(&mut w, &mut c, ci, 2, &l); // the client opens id 2 again
    assert_eq!((w.stats.ping_gate_dropped.get(), w.gate.live), (2, 0), "dropped at the CONNECT");
    let mut got = Vec::new();
    until(&mut w, "PING 1", |w| {
        pump(w, 0);
        drain(&mut c, &mut got);
        !pings(&got).is_empty()
    });
    c.write_all(&ctl(0xA, &pings(&got)[0])).unwrap();
    pump_for(&mut w, &mut c, &mut got, 50);
    let s = &w.stats;
    assert_eq!((s.ping_gate_released.get(), s.close[VOLUNTARY as usize].get(), pings(&got).len()), (0, 0, 1));
    assert_eq!((closes(&got, 1), closes(&got, 2)), (0, 0));
    assert!(w.clients.at(ci).streams.contains_key(&2), "the new stream 2 lives");
    // id 3 ends, is opened again and ends again before the PONG: one CLOSE 3, the new one's, after the new DATA
    let t3 = open(&mut w, &mut c, ci, 3, &l);
    end_stream(&mut w, ci, 3, t3); // PING 2
    let t3b = open(&mut w, &mut c, ci, 3, &l);
    assert_eq!(w.stats.ping_gate_dropped.get(), 3);
    end_stream(&mut w, ci, 3, t3b); // held behind PING 2
    end_stream(&mut w, ci, 2, t2b); // held behind PING 2
    until(&mut w, "PING 2", |w| {
        pump(w, 0);
        drain(&mut c, &mut got);
        pings(&got).len() == 2
    });
    c.write_all(&ctl(0xA, &pings(&got)[1])).unwrap();
    until(&mut w, "PING 3 (covers the new 3 and 2)", |w| {
        pump(w, 0);
        drain(&mut c, &mut got);
        pings(&got).len() == 3
    });
    assert_eq!((closes(&got, 2), closes(&got, 3)), (0, 0), "nothing released by PING 2: its CLOSE was dropped");
    c.write_all(&ctl(0xA, &pings(&got)[2])).unwrap();
    until(&mut w, "both CLOSEs", |_| {
        drain(&mut c, &mut got);
        closed_with(&got, 2, VOLUNTARY) && closed_with(&got, 3, VOLUNTARY)
    });
    let f = frames(&got);
    let data3 = f.iter().rposition(|(op, p)| *op == 0x2 && p[0] == 0x02 && p[1..5] == 3u32.to_le_bytes()).unwrap();
    let close3 = f.iter().position(|(op, p)| *op == 0x2 && p[0] == 0x04 && p[1..5] == 3u32.to_le_bytes()).unwrap();
    assert!(data3 < close3, "the new stream's DATA before its CLOSE");
    assert_eq!((closes(&got, 2), closes(&got, 3), w.stats.ping_gate_released.get(), w.gate.live), (1, 1, 2, 0));
    drop(c);
    end(w);
}

/// Shutdown: the drain phase does not close a connection while it holds a CLOSE (it waits for the PONG, at most
/// CAP_MS); the close phase sends held CLOSEs before the WebSocket Close 1001
#[test]
fn shutdown_waits_for_the_pong_and_sends_held_closes_before_the_close() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut c1, a) = client_with(&mut w, port, &hello(false, false));
    let (mut c2, b) = client_with(&mut w, port, &hello(false, false));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let t = open(&mut w, &mut c1, a, 1, &l);
    end_stream(&mut w, a, 1, t);
    let t = open(&mut w, &mut c2, b, 5, &l);
    end_stream(&mut w, b, 5, t);
    let (mut g1, mut g2) = (Vec::new(), Vec::new());
    until(&mut w, "the PINGs", |w| {
        pump(w, 0);
        drain(&mut c1, &mut g1);
        drain(&mut c2, &mut g2);
        pings(&g1).len() == 1 && pings(&g2).len() == 1
    });
    w.shutdown_step(net::STOP_DRAIN);
    pump_for(&mut w, &mut c1, &mut g1, 50);
    assert!(!w.clients.at(a).closing && !w.clients.at(b).closing, "held CLOSEs: not idle");
    let ga = cg(&w, a);
    assert!(w.gate.held(a, ga) == 1 && !w.mig_quiet(a, ga), "held CLOSEs: does not move");
    c1.write_all(&ctl(0xA, &pings(&g1)[0])).unwrap();
    until(&mut w, "released", |_| {
        drain(&mut c1, &mut g1);
        closed_with(&g1, 1, VOLUNTARY)
    });
    pump_for(&mut w, &mut c1, &mut g1, 20);
    assert!(w.mig_quiet(a, cg(&w, a)), "nothing held: it may move again");
    w.shutdown_step(net::STOP_DRAIN);
    pump_for(&mut w, &mut c1, &mut g1, 50);
    let f = frames(&g1);
    assert_eq!(f.last().unwrap(), &(0x8, 1001u16.to_be_bytes().to_vec()), "idle now: the Close");
    assert!(!w.clients.slots[b as usize].1.as_ref().unwrap().closing, "b still waits");
    w.shutdown_step(net::STOP_CLOSE);
    pump_for(&mut w, &mut c2, &mut g2, 50);
    let f = frames(&g2);
    let n = f.len();
    assert!(n >= 2 && f[n - 1] == (0x8, 1001u16.to_be_bytes().to_vec()), "{f:?}");
    assert_eq!(f[n - 2], (0x2, [&[0x04][..], &5u32.to_le_bytes(), &[VOLUNTARY]].concat()), "the held CLOSE before the Close");
    let s = &w.stats;
    assert_eq!((s.ping_gate_released.get(), s.ping_gate_capped.get(), w.gate.live), (1, 1, 0));
    drop((c1, c2));
    end(w);
}

/// A connection that ends with a held CLOSE: the CLOSE is dropped at its cap (the client is gone)
#[test]
fn a_connection_that_ends_drops_its_held_close() {
    let (mut w, port, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (mut c, ci) = client_with(&mut w, port, &hello(false, false));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let t = open(&mut w, &mut c, ci, 1, &l);
    end_stream(&mut w, ci, 1, t);
    assert_eq!(w.gate.live, 1);
    drop(c);
    until(&mut w, "the client gone", |w| w.clients.slots[ci as usize].1.is_none());
    until(&mut w, "nothing held", |w| w.gate.live == 0);
    let s = &w.stats;
    assert_eq!((s.ping_gate_dropped.get(), s.ping_gate_capped.get(), s.close[VOLUNTARY as usize].get()), (1, 0, 0));
    end(w);
}

/// Where the PING and the CLOSEs go (20.19 lanes): a held stream with no DATA left in the bulk lane gets its PING in
/// obuf (it does not wait behind another stream's bulk download); one whose DATA is still in the lane, behind it; a
/// capped CLOSE of such a stream goes behind its DATA too. PER_CONN held: the next CLOSE goes at once (full)
#[test]
fn ping_and_close_placement_and_the_connection_limit() {
    let (mut w, peers, _cl) = super::up_rig(4, false);
    let (ta, tb, tc, td) = (peers[0].0, peers[1].0, peers[2].0, peers[3].0);
    let frame = |op: u8, p: &[u8]| {
        let mut v = Vec::new();
        ws::push_frame(&mut v, op, &[p]);
        v
    };
    // stream 1's DATA waits in the bulk lane
    let c = w.clients.at(0);
    ws::push_frame(&mut c.bulk, OP_BIN, &[&[0x02, 1, 0, 0, 0, 9, 9]]);
    let end = c.bulk_frame_done();
    w.targets.at(ta).bulk_end = end;
    let lane0 = w.clients.at(0).bulk.clone();
    // stream 2 ends: its PING goes to obuf, not behind stream 1's lane DATA
    w.close_target(tb, Some(VOLUNTARY));
    let p1 = [&TAG[..], &1u32.to_le_bytes()].concat();
    assert!(w.clients.at(0).obuf.ends_with(&frame(OP_PING, &p1)));
    assert_eq!(w.clients.at(0).bulk, lane0);
    // stream 1 ends while PING 1 is in flight: it waits; the PONG releases stream 2's CLOSE into obuf, PING 2 goes into
    // the lane behind stream 1's DATA
    w.close_target(ta, Some(VOLUNTARY));
    assert_eq!(w.stats.close[VOLUNTARY as usize].get(), 0);
    super::up_feed(&mut w, &super::up_frame(OP_PONG, true, &p1));
    let close2 = frame(OP_BIN, &[&[0x04][..], &2u32.to_le_bytes(), &[VOLUNTARY]].concat());
    let p2 = [&TAG[..], &2u32.to_le_bytes()].concat();
    assert!(w.clients.at(0).obuf.ends_with(&close2));
    assert_eq!(w.clients.at(0).bulk, [lane0.clone(), frame(OP_PING, &p2)].concat());
    assert_eq!((w.stats.close[VOLUNTARY as usize].get(), w.stats.ping_gate_released.get()), (1, 1));
    // no PONG: at the cap stream 1's CLOSE goes into the lane, behind its DATA
    w.now += Duration::from_millis(CAP_MS as u64 + 5);
    w.gate_expire();
    let close1 = frame(OP_BIN, &[&[0x04][..], &1u32.to_le_bytes(), &[VOLUNTARY]].concat());
    assert_eq!(w.clients.at(0).bulk, [lane0, frame(OP_PING, &p2), close1].concat());
    assert_eq!((w.stats.ping_gate_capped.get(), w.gate.live), (1, 0));
    // the late PONG (PING 2) ends LOST. A 0x49 CLOSE (the server's own limit cut the stream) is never held
    super::up_feed(&mut w, &super::up_frame(OP_PONG, true, &p2));
    w.close_target(td, Some(0x49));
    let close4 = frame(OP_BIN, &[&[0x04][..], &4u32.to_le_bytes(), &[0x49]].concat());
    assert!(w.clients.at(0).obuf.ends_with(&close4));
    assert_eq!((w.stats.ping_gate_held.get(), w.stats.ping_gate_pings.get(), w.gate.live), (2, 2, 0));
    // PER_CONN held CLOSEs (put in by hand): stream 3's goes at once
    let (g, now) = (w.clients.gen(0), w.gate.ms(w.now));
    for sid in 0..PER_CONN as u32 {
        let _ = w.gate.admit(0, g, 1000 + sid, VOLUNTARY, 0, now);
    }
    assert_eq!(w.gate.held(0, g), PER_CONN as u32);
    w.close_target(tc, Some(VOLUNTARY));
    let close3 = frame(OP_BIN, &[&[0x04][..], &3u32.to_le_bytes(), &[VOLUNTARY]].concat());
    assert!(w.clients.at(0).obuf.ends_with(&close3));
    assert_eq!((w.stats.ping_gate_full.get(), w.stats.close[VOLUNTARY as usize].get()), (1, 3));
    drop(peers);
    std::mem::forget(w);
}

/// The close phase of a shutdown: a held CLOSE whose stream still has DATA in the bulk lane is not sent (begin_close
/// cuts that lane: the CLOSE would tell the client its stream ended in full; dropped); one whose DATA left goes into
/// obuf before the 1001
#[test]
fn shutdown_close_phase_drops_a_held_close_whose_data_is_cut() {
    let (mut w, peers, _cl) = super::up_rig(2, false);
    let (ta, tb) = (peers[0].0, peers[1].0);
    let frame = |op: u8, p: &[u8]| {
        let mut v = Vec::new();
        ws::push_frame(&mut v, op, &[p]);
        v
    };
    let c = w.clients.at(0);
    ws::push_frame(&mut c.bulk, OP_BIN, &[&[0x02, 1, 0, 0, 0, 9, 9]]);
    let end = c.bulk_frame_done();
    w.targets.at(ta).bulk_end = end;
    w.close_target(ta, Some(VOLUNTARY)); // PING 1 into the lane, behind stream 1's DATA
    w.close_target(tb, Some(VOLUNTARY)); // waits behind PING 1
    assert_eq!(w.gate.live, 2);
    w.shutdown_step(net::STOP_CLOSE);
    let close2 = frame(OP_BIN, &[&[0x04][..], &2u32.to_le_bytes(), &[VOLUNTARY]].concat());
    let close1 = frame(OP_BIN, &[&[0x04][..], &1u32.to_le_bytes(), &[VOLUNTARY]].concat());
    let obuf = w.clients.at(0).obuf.clone();
    assert!(obuf.ends_with(&[close2, frame(OP_CLOSE, &1001u16.to_be_bytes())].concat()), "{obuf:?}");
    assert!(!obuf.windows(close1.len()).any(|x| x == close1), "no CLOSE for the stream whose DATA is cut");
    let s = &w.stats;
    assert_eq!((s.ping_gate_capped.get(), s.ping_gate_dropped.get(), s.close[VOLUNTARY as usize].get(), w.gate.live), (1, 1, 1, 0));
    drop(peers);
    std::mem::forget(w);
}

/// Worker::run's epoll timeout while CLOSEs are held (gate_timeout): none (-1) and longer waits become the time to
/// the next cap, 0 and shorter waits stay; past the cap: 0. After the last one goes, the sweep can give the memory back
#[test]
fn the_epoll_timeout_follows_the_next_cap() {
    let (mut w, peers, _cl) = super::up_rig(1, false);
    w.now = Instant::now(); // (Worker::new read its time before the gate's epoch existed: ms would clamp to 0)
    w.close_target(peers[0].0, Some(VOLUNTARY));
    assert_eq!(w.gate.live, 1);
    let cap = CAP_MS as i32;
    assert_eq!([w.gate_timeout(-1), w.gate_timeout(0), w.gate_timeout(5), w.gate_timeout(cap + 500)], [cap, 0, 5, cap]);
    w.now += Duration::from_millis(400);
    assert_eq!((w.gate_timeout(-1), w.gate_timeout(cap)), (cap - 400, cap - 400));
    w.now += Duration::from_millis(700);
    assert_eq!(w.gate_timeout(-1), 0, "past the cap: at once");
    w.gate_expire();
    assert_eq!((w.gate.live, w.stats.ping_gate_capped.get()), (0, 1));
    assert!(w.gate.reclaimable(), "Worker::run keeps the sweep's wake armed");
    w.gate.shrink();
    assert!(!w.gate.reclaimable());
    drop(peers);
    std::mem::forget(w);
}

/// credit v2 and the gate on one connection, each with a PING in flight: credit's PONG (8 bytes) answers credit only,
/// the gate's PONG (6 bytes) releases the held CLOSE only
#[test]
fn credit_and_gate_pongs_answer_their_own_ping_only() {
    let (mut w, peers, _cl) = super::up_rig(1, false);
    let now = w.now;
    let c = w.clients.at(0);
    c.cv = Some(Box::default());
    let s = c.cv.as_mut().unwrap().after_continue(now).expect("credit's PING");
    w.close_target(peers[0].0, Some(VOLUNTARY)); // gate PING 1
    let gate1 = [&TAG[..], &1u32.to_le_bytes()].concat();
    super::up_feed(&mut w, &super::up_frame(OP_PONG, true, &s.to_le_bytes()));
    assert_eq!((w.clients.at(0).cv.as_ref().unwrap().pongs, w.gate.live), (1, 1), "credit's PONG: the CLOSE waits");
    super::up_feed(&mut w, &super::up_frame(OP_PONG, true, &gate1));
    assert_eq!((w.clients.at(0).cv.as_ref().unwrap().pongs, w.gate.live), (1, 0), "the gate's PONG: credit untouched");
    assert_eq!((w.stats.ping_gate_released.get(), w.stats.close[VOLUNTARY as usize].get()), (1, 1));
    drop(peers);
    std::mem::forget(w);
}
