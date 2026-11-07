//! 60.39 per-destination connect limits (wispurr maxConnectsPerDestPerSecond / PerMinute): caps on NEW streams from all
//! clients together to one destination, so the server cannot be used to flood one site. Design and numbers: 60.39.
//! - Key: the resolved target IP:port (the first address that passed the C1 address rules; IPv4-mapped = IPv4), taken
//!   once per stream in Worker::start_connect; with socks5h + --upstream-trust-dns (no local address) the lowercase host
//!   name:port, taken in Worker::proxy_name.
//! - One process-wide table (not per worker: N workers would allow N x the rate): 64 SipHash shards x 1024 keys, two
//!   token buckets per key (--stream-rate-per-dest R/B per second, --stream-rate-per-dest-minute N). A stream needs a
//!   token in every set bucket and then spends one in each (a refusal spends nothing). A full shard first drops its
//!   idle entries, then fails open (dest_untracked). Touched once per new stream and by the idle sweep; never per packet.
//!   Time: u64 ms (metrics::now_ms), so no wrap rule.
use crate::clientip::{SHARDS, SHARD_CAP};
use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;

/// A destination: a target address and port, or (no local DNS: socks5h) a keyed hash of the lowercase name and the port
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DestKey {
    Ip(IpAddr, u16),
    Name(u64, u16),
}

#[derive(Debug, PartialEq)]
pub enum Take {
    Ok,
    /// the per-second bucket is empty (nothing was spent)
    Second,
    /// the per-minute bucket is empty (nothing was spent)
    Minute,
    /// the key's shard is full of live entries: not tracked, not limited (fail open, like C3b Q11)
    Untracked,
}

struct Entry {
    sec: f64,
    min: f64,
    at: u64, // metrics::now_ms
}

pub struct DestTable {
    shards: Box<[Mutex<HashMap<DestKey, Entry, RandomState>>]>,
    hash: RandomState,
    names: RandomState,
    keys: AtomicUsize,
    sec: Option<(f64, f64)>, // (tokens per ms, burst)
    min: Option<(f64, f64)>,
}

impl DestTable {
    /// `sec` = --stream-rate-per-dest (per second, burst), `min` = --stream-rate-per-dest-minute (per minute; burst = N)
    pub fn new(sec: Option<(u32, u32)>, min: Option<u32>) -> DestTable {
        let shards = (0..SHARDS).map(|_| Mutex::new(HashMap::with_hasher(RandomState::new()))).collect();
        DestTable {
            shards,
            hash: RandomState::new(),
            names: RandomState::new(),
            keys: AtomicUsize::new(0),
            sec: sec.map(|(r, b)| (r as f64 / 1000.0, b as f64)),
            min: min.map(|n| (n as f64 / 60_000.0, n as f64)),
        }
    }

    pub fn ip_key(ip: IpAddr, port: u16) -> DestKey {
        DestKey::Ip(crate::clientip::canon(ip), port)
    }

    /// a host name the upstream proxy resolves: ASCII case folded (the caller removed one trailing dot)
    pub fn name_key(&self, name: &str, port: u16) -> DestKey {
        DestKey::Name(self.names.hash_one(name.to_ascii_lowercase()), port)
    }

    fn shard(&self, k: &DestKey) -> &Mutex<HashMap<DestKey, Entry, RandomState>> {
        &self.shards[self.hash.hash_one(k) as usize % SHARDS]
    }

    /// refill `e` to `now`, clamped to the burst. u64 ms (metrics::now_ms): no wrap, also for an entry no sweep has
    /// refreshed for weeks (a worker without clients sleeps; review). A `now` older than `e.at` (the clock is read
    /// before the shard lock: a reordering between threads) refills nothing and the time never moves back.
    fn refill(&self, e: &mut Entry, now: u64) {
        let Some(dt) = now.checked_sub(e.at) else { return };
        if let Some((per_ms, burst)) = self.sec {
            e.sec = (e.sec + dt as f64 * per_ms).min(burst);
        }
        if let Some((per_ms, burst)) = self.min {
            e.min = (e.min + dt as f64 * per_ms).min(burst);
        }
        e.at = now;
    }

    /// full buckets: nothing to remember (a missing key starts full)
    fn idle(&self, e: &Entry) -> bool {
        self.sec.is_none_or(|(_, b)| e.sec >= b) && self.min.is_none_or(|(_, b)| e.min >= b)
    }

    /// One new stream to `k`.
    pub fn take(&self, k: DestKey, now: u64) -> Take {
        let mut m = self.shard(&k).lock().unwrap();
        if let Some(e) = m.get_mut(&k) {
            return self.spend(e, now); // (a known key: one hash under the lock, review)
        }
        if m.len() >= SHARD_CAP {
            // deliberate: an O(SHARD_CAP) scan, only when the shard is full; a drained entry refills within
            // burst/rate, so a shard full of live entries needs a sustained flood to over 1000 destinations at once
            let before = m.len();
            m.retain(|_, e| {
                self.refill(e, now);
                !self.idle(e)
            });
            self.keys.fetch_sub(before - m.len(), Relaxed);
            if m.len() >= SHARD_CAP {
                return Take::Untracked;
            }
        }
        let sec = self.sec.map_or(0.0, |(_, b)| b);
        let min = self.min.map_or(0.0, |(_, b)| b);
        self.keys.fetch_add(1, Relaxed);
        self.spend(m.entry(k).or_insert(Entry { sec, min, at: now }), now)
    }

    /// refill, then spend one token in every set bucket if each has one; a refusal spends nothing
    fn spend(&self, e: &mut Entry, now: u64) -> Take {
        self.refill(e, now);
        if self.sec.is_some() && e.sec < 1.0 {
            return Take::Second;
        }
        if self.min.is_some() && e.min < 1.0 {
            return Take::Minute;
        }
        e.sec -= 1.0; // (an unset bucket's value is never read)
        e.min -= 1.0;
        Take::Ok
    }

    /// The idle sweep of one shard: refill every entry and drop the full ones.
    pub fn sweep(&self, shard: usize, now: u64) {
        let mut m = self.shards[shard % SHARDS].lock().unwrap();
        let before = m.len();
        m.retain(|_, e| {
            self.refill(e, now);
            !self.idle(e)
        });
        self.keys.fetch_sub(before - m.len(), Relaxed);
    }

    pub fn keys(&self) -> usize {
        self.keys.load(Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn second_bucket_burst_refill_and_wrap() {
        let t = DestTable::new(Some((10, 20)), None); // 10/s, burst 20
        let k = DestTable::ip_key(ip("1.1.1.1"), 443);
        assert!((0..20).all(|_| t.take(k, 1000) == Take::Ok), "burst");
        assert_eq!(t.take(k, 1000), Take::Second);
        assert_eq!(t.take(k, 1050), Take::Second, "half a token after 50 ms");
        assert_eq!(t.take(k, 1100), Take::Ok, "one token per 100 ms");
        assert_eq!(t.take(k, 1090), Take::Second, "an older now (reordering): no 49-day refill");
        assert_eq!(t.take(k, 1200), Take::Ok, "the entry's time did not move back");
        assert_eq!(t.take(DestTable::ip_key(ip("1.1.1.1"), 80), 1200), Take::Ok, "another port: another key");
        assert_eq!(t.take(DestTable::ip_key(ip("::ffff:1.1.1.1"), 443), 1200), Take::Second, "mapped IPv6 = IPv4");
        // an entry no sweep refreshed for longer than a u32 of ms (a sleeping worker): full again, not a wrapped gap
        let w = DestTable::ip_key(ip("3.3.3.3"), 443);
        assert!((0..20).all(|_| t.take(w, 1000) == Take::Ok) && t.take(w, 1000) == Take::Second);
        let later = 1000 + (1u64 << 32);
        assert!((0..20).all(|_| t.take(w, later) == Take::Ok), "a full burst after 49.7 days");
        assert_eq!(t.take(w, later), Take::Second);
    }

    #[test]
    fn a_refusal_spends_no_token_in_the_other_bucket() {
        // per second 5 (burst 5), per minute 8: the minute bucket refuses the 9th; the second bucket refuses first
        // within one second and must not drain the minute bucket meanwhile
        let t = DestTable::new(Some((5, 5)), Some(8));
        let k = DestTable::ip_key(ip("2001:db8::1"), 443);
        assert!((0..5).all(|_| t.take(k, 0) == Take::Ok));
        assert!((0..100).all(|_| t.take(k, 0) == Take::Second), "the second bucket refuses: the minute's 3 tokens stay");
        assert!((0..3).all(|_| t.take(k, 1000) == Take::Ok), "1 s later: the minute bucket still has 3 (plus 1/7.5)");
        assert_eq!(t.take(k, 1000), Take::Minute, "8 in the minute");
        assert!((0..100).all(|_| t.take(k, 1000) == Take::Minute));
        assert_eq!(t.take(k, 1100), Take::Minute, "the minute refusals spent no second token either (and it refills)");
        let e = |t: &DestTable| t.shard(&k).lock().unwrap()[&k].sec;
        assert!((e(&t) - 2.5).abs() < 1e-9, "per-second bucket: 5 - 3 + 0.5 (100 ms) = 2.5: the refusals spent nothing");
        assert_eq!(t.take(k, 1000 + 7500), Take::Ok, "one minute token per 7.5 s");
    }

    #[test]
    fn names_fold_case_and_the_sweep_drops_full_entries() {
        let t = DestTable::new(None, Some(2));
        let a = t.name_key("Example.COM", 443);
        assert_eq!(a, t.name_key("example.com", 443));
        assert_ne!(a, t.name_key("example.com", 80));
        assert_ne!(a, t.name_key("example.org", 443));
        assert_eq!((t.take(a, 0), t.take(a, 0), t.take(a, 0)), (Take::Ok, Take::Ok, Take::Minute));
        assert_eq!(t.keys(), 1);
        (0..SHARDS).for_each(|s| t.sweep(s, 30_000));
        assert_eq!(t.keys(), 1, "1 token after 30 s: not full, kept (a new key would start full)");
        (0..SHARDS).for_each(|s| t.sweep(s, 60_000));
        assert_eq!(t.keys(), 0, "full after 60 s: dropped");
    }

    #[test]
    fn full_shard_evicts_idle_then_fails_open() {
        let t = DestTable::new(Some((1, 1)), None); // 1/s burst 1: one take drains a key for a second
        let mut keys = Vec::new();
        let mut n = 0u32;
        let mut untracked = 0;
        while t.keys() < SHARDS * SHARD_CAP {
            let k = DestTable::ip_key(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n)), 443);
            n += 1;
            match t.take(k, 0) {
                Take::Ok => keys.push(k),
                Take::Untracked => untracked += 1,
                r => panic!("{r:?}"),
            }
            assert!(n < 4_000_000);
        }
        assert!(untracked > 0 && t.keys() == keys.len());
        let k = DestTable::ip_key(ip("192.0.2.1"), 443);
        assert_eq!(t.take(k, 0), Take::Untracked, "every shard full of live (drained) entries: fail open");
        assert_eq!(t.take(keys[0], 0), Take::Second, "known keys are still limited");
        // 1 s later every entry is full again: the new key's full shard drops its idle entries and tracks the new key
        assert_eq!(t.take(k, 1000), Take::Ok);
        assert_eq!(t.take(k, 1000), Take::Second, "tracked, not failed open");
        assert_eq!(t.keys(), SHARDS * SHARD_CAP - SHARD_CAP + 1, "only the new key's shard was scanned");
    }
}
