//! 60.78 worker tests for the adaptive-splice class (worker/splicefar.rs): read at the first need of rule B, never at
//! accept; kept for the connection; not read past the kernel's min RTT window (fake clock: Worker::now and the pass's
//! `now` are set by hand); a moving connection takes its stamp or class along.
use super::super::splicefar::{first_class, t0, Class, AGE_PASS, FAR_FAR, FAR_NEAR};
use super::super::*;
use super::fd::{client, fd_cfg, rig, until};
use std::cell::Cell;
use std::sync::atomic::Ordering::Relaxed;

const WLEN: Duration = Duration::from_secs(300);

fn s(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn end(w: Worker) {
    for fd in [w.ep, w.lfd, w.inbox.efd, w.spare] {
        unsafe { libc::close(fd) };
    }
    std::mem::forget(w); // (as migtests: no frees while mem::tests measures the heap counter)
}

fn adaptive_rig() -> (Worker, u16) {
    let mut cfg = fd_cfg();
    cfg.adaptive_splice = true;
    let (w, port, _rx) = rig(cfg, u32::MAX, 4);
    (w, port)
}

/// (near, far, old) counts
fn counts(w: &Worker) -> (u64, u64, u64) {
    (w.stats.splice_near.get(), w.stats.splice_far.get(), w.stats.splice_old.get())
}

fn entry(w: &Worker, ci: u32) -> Option<u32> {
    let tag = w.clients.gen(ci).wrapping_add(1);
    w.splice_far.get(ci as usize).filter(|e| e.0 == tag).map(|e| e.1)
}

#[test]
fn the_class_rule_reads_only_a_young_connection() {
    let reads = Cell::new(0);
    let rtt = |v: Option<u32>| {
        let reads = &reads;
        move || {
            reads.set(reads.get() + 1);
            v
        }
    };
    // stamp 1: accepted after t0. Young up to the window minus the margin (300 - 30 s)
    assert_eq!(first_class(1, s(0), WLEN, rtt(Some(20_000))), Class::Far);
    assert_eq!(first_class(1, s(239), WLEN, rtt(Some(9_999))), Class::Near);
    assert_eq!(first_class(1, s(269), WLEN, rtt(None)), Class::Near, "no sample: near");
    assert_eq!(first_class(1, s(269), WLEN, rtt(Some(10_000))), Class::Far, "10 ms is far");
    assert_eq!(reads.get(), 4);
    assert_eq!(first_class(1, s(270), WLEN, rtt(Some(20_000))), Class::Old, "past the window: not read");
    assert_eq!(first_class(1, s(5000), WLEN, rtt(Some(20_000))), Class::Old);
    // stamp 10: accepted after t0 + 9 passes (270 s): its age is counted from there
    assert_eq!(first_class(10, s(500), WLEN, rtt(Some(500))), Class::Near);
    assert_eq!(first_class(10, s(539), WLEN, rtt(Some(20_000))), Class::Far);
    assert_eq!(reads.get(), 6);
    assert_eq!(first_class(10, s(540), WLEN, rtt(Some(500))), Class::Old);
    // a window shorter than the margin: never read (the v1.1.1 length for everyone)
    assert_eq!(first_class(1, s(0), s(0), rtt(Some(20_000))), Class::Old);
    assert_eq!(first_class(1, s(0), s(30), rtt(Some(20_000))), Class::Old);
    assert_eq!(reads.get(), 6, "an old connection is never read");
}

/// Nothing at accept; the first need reads once and keeps the class; past the window the class is near without a read;
/// a unix client is near without a read
#[test]
fn a_client_is_classed_once_at_its_first_need() {
    let (mut w, port) = adaptive_rig();
    let (_c1, a) = client(&mut w, port);
    assert!(w.splice_far.is_empty(), "nothing written at accept");
    // young (w.now: the real time; the worker's stamp is the current pass number + 1): read, loopback = near
    assert!(!w.splice_is_far(a));
    assert_eq!((counts(&w), entry(&w, a)), ((1, 0, 0), Some(FAR_NEAR)));
    assert!(!w.splice_is_far(a));
    assert_eq!(counts(&w), (1, 0, 0), "kept: no second classification");
    // a class set far is kept as far
    w.splice_far[a as usize].1 = FAR_FAR;
    assert!(w.splice_is_far(a));
    assert_eq!(counts(&w), (1, 0, 0));
    // old: the clock 300 s after the stamp's start
    let (_c2, b) = client(&mut w, port);
    let real = w.now;
    w.now = t0() + AGE_PASS * (w.age_k - 1) + WLEN;
    assert!(!w.splice_is_far(b));
    assert_eq!((counts(&w), entry(&w, b)), ((1, 0, 1), Some(FAR_NEAR)), "old: near, counted as old");
    // a unix client: near, even when it is old (no read, no old count)
    let (_c3, u) = client(&mut w, port);
    let was = std::mem::replace(&mut w.clients.at(u).local, LOCAL_UNIX);
    assert!(!w.splice_is_far(u));
    assert_eq!(counts(&w), (2, 0, 1));
    w.clients.at(u).local = was;
    w.now = real;
    // a reused slot (new generation) starts unclassified
    w.close_client(a, Why::ServerClose);
    until(&mut w, "slot freed", |w| w.clients.slots[a as usize].1.is_none());
    let (_c4, a2) = client(&mut w, port);
    if a2 == a {
        assert_eq!(entry(&w, a2), None, "the old generation's class is not the new client's");
    }
    end(w);
}

/// The stamping pass: a client it sees keeps the stamp of its accept period; a client after the pass has the next one
#[test]
fn the_pass_stamps_clients_and_old_ones_are_not_read() {
    let (mut w, port) = adaptive_rig();
    let (_c1, a) = client(&mut w, port);
    let k0 = w.age_k;
    let at = w.age_pass_at;
    assert_eq!(at, t0() + AGE_PASS * k0);
    w.splice_age_pass(at);
    assert_eq!((entry(&w, a), w.age_k, w.age_pass_at), (Some(k0), k0 + 1, at + AGE_PASS));
    // a later pass does not stamp it again
    w.splice_age_pass(at + AGE_PASS);
    assert_eq!((entry(&w, a), w.age_k), (Some(k0), k0 + 2));
    // a pass that comes late (a worker asleep) skips to the current period
    w.splice_age_pass(at + AGE_PASS * 5 + s(1));
    assert_eq!(w.age_k, k0 + 6);
    w.age_k = k0 + 1; // (back to the state after the first pass)
    let (_c2, b) = client(&mut w, port);
    // 280 s after a's period began: a is old (not read); b, accepted after the first pass, is 250 s old: read
    w.now = t0() + AGE_PASS * (k0 - 1) + s(280);
    assert!(!w.splice_is_far(a));
    assert!(!w.splice_is_far(b));
    assert_eq!(counts(&w), (1, 0, 1));
    assert_eq!((entry(&w, a), entry(&w, b)), (Some(FAR_NEAR), Some(FAR_NEAR)));
    end(w);
}

/// A connection that moves takes its stamp (not classified yet) or its class along, under its new slot and generation
#[test]
fn a_moving_connection_takes_its_class_along() {
    let (mut w, port) = adaptive_rig();
    let (c, a) = client(&mut w, port);
    let k = w.age_k;
    let m = w.mig_export(a);
    let (b, _) = w.mig_import(m).unwrap();
    assert_eq!(entry(&w, b), Some(k), "the stamp travels");
    w.splice_far[b as usize].1 = FAR_FAR;
    let m = w.mig_export(b);
    let (d, _) = w.mig_import(m).unwrap();
    assert_eq!(entry(&w, d), Some(FAR_FAR), "the class travels");
    assert!(w.splice_is_far(d));
    assert_eq!(counts(&w), (0, 0, 0), "no classification on the way");
    // without the flag nothing is written
    let (mut w2, port2, _rx) = rig(fd_cfg(), u32::MAX, 4);
    let (c2, e) = client(&mut w2, port2);
    let m = w2.mig_export(e);
    let _ = w2.mig_import(m).unwrap();
    assert!(w2.splice_far.is_empty());
    drop((c, c2));
    until(&mut w, "gone", |w| w.inbox.load.load(Relaxed) == 0);
    until(&mut w2, "gone", |w| w.inbox.load.load(Relaxed) == 0);
    end(w);
    end(w2);
}
