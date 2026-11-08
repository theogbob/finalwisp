//! 60.20 C2 real client IP and C3b per-IP limits (design 60.02 C2 / C3; as built and decisions: 60.22).
//! - C2: the client IP is the TCP peer, or, for a peer in --trusted-proxy, the configured header (exactly one; XFF by a
//!   right-to-left walk that skips trusted hops). It is used for the per-IP keys (and C4 logs later), never for routing.
//! - C3b: one process-wide table of per-IP keys (64 SipHash shards, 1024 keys each): concurrent connections
//!   (--max-conns-per-ip), a stream token bucket (--stream-rate-per-ip) and (60.40) a new-connection token bucket
//!   (--conn-rate-per-ip). A key is released only if it was charged.
use crate::policy::Cidr;
use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;

/// The per-IP key: IPv4 as its IPv4-mapped form (/32), IPv6 as its /64 prefix (one subscriber normally holds a /64:
/// per-address keys are bypassed by rotating addresses).
pub type IpKey = u128;

/// 60.31 C7 the peer address a unix-socket client gets (it has no IP): 100:: (RFC 6666 discard-only prefix, never a TCP
/// peer; its /64 key is no real client's, unlike `::`, whose key 0 is also ::1's: 60.28 review). With --listen-unix
/// main adds it to ClientIp::trusted, so a unix peer's client-IP header is believed like a --trusted-proxy's (the
/// socket file's mode decides who connects); a TCP peer with exactly this address is reset at accept then (it could
/// otherwise pose as the unix proxy). Logged as `unix` (connlog).
pub const UNIX_PEER: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0));

pub const SHARDS: usize = 64;
/// 60.22 keys per shard (65,536 in all, about 5 MiB at worst); a full shard charges no new key (Q11: fail open)
pub const SHARD_CAP: usize = 1024;
/// shards one idle sweep visits (consecutive; each awake worker walks all 64 in 16 sweeps = 32 s)
pub const SWEEP_SHARDS: usize = 4;
/// 60.25 C10b per-IP upload lease: this many ms of the key's rate, split by its connections, at most LEASE_MAX bytes
const LEASE_MS: u64 = 50;
const LEASE_MAX: u64 = 256 << 10;
/// 60.25 merged A/B: the most a top-up may bring one connection's lease to (2 x LEASE_MAX: the bound's L doubles)
const TOPUP_MAX: u64 = 2 * LEASE_MAX;
/// 60.45 buckets count milli-tokens (milli-bytes for the upload bucket): R per second is exactly R milli-units per ms,
/// so a refill is integer and refills in steps add up to one refill (f32 tokens did not: review)
const MILLI: u64 = 1000;

/// An IPv4-mapped IPv6 address as IPv4 (a dual-stack listener reports IPv4 peers that way).
pub fn canon(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

pub fn key(ip: IpAddr) -> IpKey {
    match canon(ip) {
        IpAddr::V4(a) => u128::from(a.to_ipv6_mapped()),
        IpAddr::V6(a) => u128::from(a) & !((1u128 << 64) - 1),
    }
}

/// The client state a connection keeps (the worker side vector Worker::peers_of, by slab slot): its IP and the key it charged (None: not charged, e.g.
/// a trusted proxy before its HTTP request, an untracked key, or no per-IP limit).
pub struct Peer {
    pub ip: IpAddr,
    pub key: Option<IpKey>,
}

/// What the header gave (for the realip_* counters).
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Got {
    Header,
    /// unparsable or ambiguous: the last trusted hop (the proxy) is the client
    Bad,
    /// a trusted peer without the header: the peer is the client
    Missing,
}

pub struct ClientIp {
    pub trusted: Box<[Cidr]>,
    /// the header name, lowercase (matched ASCII case-insensitively); "x-forwarded-for" is a list, any other one value
    pub header: Box<str>,
    pub table: Option<IpTable>,
    pub max_conns: u32,
    // --stream-rate-per-ip lives only in the table (IpTable::has_rate): one owner, no second copy to diverge
}

/// One entry of a header: an IP, with an optional port (`1.2.3.4:5678`, `[2001:db8::1]:443`) or brackets.
fn entry(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Some(r) = s.strip_prefix('[') {
        let (ip, rest) = r.split_once(']')?;
        if !(rest.is_empty() || rest.strip_prefix(':').is_some_and(|p| p.parse::<u16>().is_ok())) {
            return None;
        }
        return ip.parse::<std::net::Ipv6Addr>().ok().map(|a| canon(IpAddr::V6(a)));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(canon(ip));
    }
    let (ip, port) = s.rsplit_once(':')?; // IPv4:port only (a bare IPv6 parsed above)
    port.parse::<u16>().ok()?;
    ip.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

impl ClientIp {
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|c| c.contains(ip))
    }

    /// The client IP for a connection from `peer` with the captured header lines `lines` (in order). An untrusted
    /// peer: the peer, headers ignored.
    pub fn real_ip(&self, peer: IpAddr, lines: &[Vec<u8>]) -> (IpAddr, Option<Got>) {
        let peer = canon(peer);
        if !self.is_trusted(peer) {
            return (peer, None);
        }
        if lines.is_empty() {
            return (peer, Some(Got::Missing));
        }
        if &*self.header != "x-forwarded-for" {
            // one value; the same header on several lines is ambiguous (which one did the proxy set?): bad
            let one = (lines.len() == 1).then(|| std::str::from_utf8(&lines[0]).ok().and_then(entry)).flatten();
            return one.map_or((peer, Some(Got::Bad)), |ip| (ip, Some(Got::Header)));
        }
        // XFF (RFC 9110 field-line combination: the lines joined with ',' in order), right to left: skip trusted hops,
        // the first untrusted entry is the client; all trusted: the leftmost; an unparsable entry ends the walk at the
        // last trusted hop (the proxy shares one key: fail safe)
        let mut last = peer;
        for line in lines.iter().rev() {
            // per entry: a non-UTF-8 entry is unparsable like any other junk (the entries right of it still count)
            for e in line.rsplit(|&b| b == b',') {
                match std::str::from_utf8(e).ok().and_then(entry) {
                    None => return (last, Some(Got::Bad)),
                    Some(ip) if self.is_trusted(ip) => last = ip,
                    Some(ip) => return (ip, Some(Got::Header)),
                }
            }
        }
        (last, Some(Got::Header))
    }
}

struct Entry {
    conns: u32,
    tokens: u32, // --stream-rate-per-ip milli-tokens (60.45; burst <= 2e6 tokens: <= 2e9)
    // 60.45 now_ms (u64: no wrap) up to which every bucket of the entry is refilled (60.40's own conn time merged in:
    // an exact clamped refill composes, so one time for all buckets gives the same tokens; Entry stays 96 bytes)
    at: u64,
    ct: u32, // 60.40 --conn-rate-per-ip milli-tokens
    ub: i64, // 60.25 C10b milli-bytes left in the key's --upload-rate-per-ip bucket (leased out by take_bytes / top_up_bytes; down to -burst)
    q: Upq,  // 60.25 C10b waiters for that bucket
}

/// 60.45 `v` milli-units refilled for `dt` ms at `per_s` per second (= milli-units per ms), clamped to `cap` milli-units.
/// Exact: min(min(v + a, cap) + b, cap) = min(v + a + b, cap), so refills in steps give one refill.
fn fill(v: u64, per_s: u64, cap: u64, dt: u64) -> u64 {
    v.saturating_add(per_s.saturating_mul(dt)).min(cap)
}

/// 60.25 C10b the starved-first queue of one key's --upload-rate-per-ip waiters (review: a shared cap needs a
/// bounded service time, not a race on the shard lock). A connection whose lease came up short takes a ticket (`tail`);
/// while any ticket is out, the bucket serves tickets in order. `done`: bit i = ticket head + i was served or given
/// back out of order (the WINDOW tickets after head); a ticket further out that is given back is kept in `late`
/// (sorted, inline: no allocation and no drop glue in Entry) until it enters the window (review: every
/// waiter keeps its place; bounded work under the shard lock). Past LATE give-backs beyond the window, one is dropped:
/// that ticket is then skipped as a stale head. A head whose grant has been fundable for SLOT_MS without its holder
/// claiming it is skipped (review: timed from when the bucket could pay it, so a deficit cannot expire a live head).
#[derive(Default)]
struct Upq {
    head: u32,
    tail: u32,
    ready_at: Option<NonZeroU64>, // now_ms (at least 1) when the head's grant first became fundable (60.45: u64, 8 bytes)
    done: u64,
    late_n: u8,
    late: [u32; Upq::LATE], // given back beyond the window, sorted by distance from head
}

impl Upq {
    const WINDOW: u32 = 64;
    /// grace for the head holder once its grant is fundable: two 100 ms resume ticks plus margin (review)
    const SLOT_MS: u64 = 300;
    const LATE: usize = 8;

    fn join(&mut self) -> u32 {
        let t = self.tail;
        self.tail = self.tail.wrapping_add(1);
        t
    }

    /// `t` is a ticket still in the queue (not passed by head)
    fn holds(&self, t: u32) -> bool {
        t.wrapping_sub(self.head) < self.tail.wrapping_sub(self.head)
    }

    /// ticket `t` is served or given back: mark it, then move head past every finished ticket
    fn release(&mut self, t: u32, now: u64) {
        let off = t.wrapping_sub(self.head);
        if off < Self::WINDOW {
            self.done |= 1 << off;
        } else if (self.late_n as usize) < Self::LATE {
            let (head, n) = (self.head, self.late_n as usize);
            let at = self.late[..n].partition_point(|&x| x.wrapping_sub(head) < off);
            self.late.copy_within(at..n, at + 1);
            self.late[at] = t;
            self.late_n += 1;
        }
        self.settle(now, None);
    }

    /// move head past finished tickets, and past one head whose fundable grant waited SLOT_MS unclaimed. `fundable`:
    /// whether the bucket can pay the head's grant now (None: not known, a give-back); an unfundable poll restarts the
    /// grace (review: a bootstrap charge after readiness must not expire a live head)
    fn settle(&mut self, now: u64, fundable: Option<bool>) {
        match fundable {
            Some(true) if self.head != self.tail && self.ready_at.is_none() => self.ready_at = NonZeroU64::new(now.max(1)),
            Some(false) => self.ready_at = None,
            _ => {}
        }
        let mut skipped = false;
        while self.head != self.tail {
            // late tickets that entered the window become done bits (sorted: only the front can)
            while self.late_n > 0 {
                let off = self.late[0].wrapping_sub(self.head);
                if off >= Self::WINDOW && off < self.tail.wrapping_sub(self.head) {
                    break;
                }
                if off < Self::WINDOW {
                    self.done |= 1 << off;
                }
                self.late.copy_within(1..self.late_n as usize, 0);
                self.late_n -= 1;
            }
            let stale = !skipped && self.ready_at.is_some_and(|r| now.saturating_sub(r.get()) > Self::SLOT_MS); // (u64: no wrap)
            if self.done & 1 == 0 && !stale {
                break;
            }
            skipped |= self.done & 1 == 0;
            self.head = self.head.wrapping_add(1);
            self.done >>= 1;
            self.ready_at = None;
        }
        if self.head == self.tail {
            self.done = 0;
            self.late_n = 0;
            self.ready_at = None;
        }
    }
}

/// The C3b table: 64 shards x Mutex<HashMap>, SipHash with a per-process random key (std RandomState): the keys are
/// attacker-chosen (IPv6 /64 rotation), so no fixed hash. Touched at accept / upgrade, at CONNECT (stream rate), at
/// release and by the idle sweep; never per packet.
pub struct IpTable {
    shards: Box<[Mutex<HashMap<IpKey, Entry, RandomState>>]>,
    hash: RandomState,
    keys: AtomicUsize,
    rate: Option<(u32, u32)>,      // --stream-rate-per-ip (per second, burst; cli: R <= 1e6, B <= 2e6)
    up: Option<(u64, u64)>,        // 60.25 C10b --upload-rate-per-ip (bytes per second, burst; cli: R <= 2^40, B <= 2^42)
    conn_rate: Option<(u32, u32)>, // 60.40 --conn-rate-per-ip (per second, burst; as `rate`)
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Charge {
    Charged,
    /// over --max-conns-per-ip
    Refused,
    /// 60.40 over --conn-rate-per-ip (its bucket is empty; no token was taken, the connection count is unchanged)
    Rate,
    /// the key's shard is full: not tracked, not limited (Q11)
    Untracked,
}

/// Milliseconds since process start. 60.45: u64, no wrap (the u32 clock wrapped after 49.7 days, and an entry that no
/// sweep refreshed that long, every worker asleep without clients, refilled for a wrong gap).
pub fn now_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64
}

impl IpTable {
    #[cfg(test)]
    pub fn new(rate: Option<(u32, u32)>) -> IpTable {
        Self::with_upload(rate, None)
    }

    /// 60.25 C10b: `up` = (bytes per second, burst bytes) of --upload-rate-per-ip
    #[cfg(test)]
    pub fn with_upload(rate: Option<(u32, u32)>, up: Option<(u64, u64)>) -> IpTable {
        Self::with_rates(rate, up, None)
    }

    /// Per second and burst, as cli parses them: `rate` --stream-rate-per-ip (R <= 1e6, B <= 2e6); `up` 60.25 C10b
    /// --upload-rate-per-ip (bytes, R <= 2^40, B <= 2^42); `conn_rate` 60.40 --conn-rate-per-ip (as `rate`).
    /// (Tests use R = 0: nothing refills.)
    pub fn with_rates(rate: Option<(u32, u32)>, up: Option<(u64, u64)>, conn_rate: Option<(u32, u32)>) -> IpTable {
        let shards = (0..SHARDS).map(|_| Mutex::new(HashMap::with_hasher(RandomState::new()))).collect();
        IpTable { shards, hash: RandomState::new(), keys: AtomicUsize::new(0), rate, up, conn_rate }
    }

    fn shard(&self, k: IpKey) -> &Mutex<HashMap<IpKey, Entry, RandomState>> {
        &self.shards[self.hash.hash_one(k) as usize % SHARDS]
    }

    /// refill every bucket of `e` to `now`, clamped to its burst. 60.45: u64 ms, so any gap is the real one (also 2^32
    /// ms or more: an entry no sweep refreshed because every worker slept). Callers read the clock before taking the
    /// shard lock, so a thread can arrive with a `now` a little older than `e.at`: such a reordering refills nothing and
    /// `at` never moves back. Integer milli-units (saturating, then clamped): exact for any gap, also in steps.
    fn refill(&self, e: &mut Entry, now: u64) {
        let Some(dt) = now.checked_sub(e.at) else { return };
        if let Some((r, b)) = self.rate {
            e.tokens = fill(e.tokens.into(), r.into(), u64::from(b) * MILLI, dt) as u32;
            // (cap <= 2e9: cli)
        }
        if let Some((r, b)) = self.conn_rate {
            e.ct = fill(e.ct.into(), r.into(), u64::from(b) * MILLI, dt) as u32;
        }
        if let Some((r, b)) = self.up {
            // ub >= -cap, so adding at most 2 x cap (<= 8.8e15) reaches the cap: no i64 overflow, still exact
            let cap = b * MILLI;
            e.ub = (e.ub + r.saturating_mul(dt).min(2 * cap) as i64).min(cap as i64);
        }
        e.at = now;
    }

    fn idle(&self, e: &Entry) -> bool {
        e.conns == 0
            && self.rate.is_none_or(|(_, b)| u64::from(e.tokens) >= u64::from(b) * MILLI)
            && self.up.is_none_or(|(_, b)| e.ub >= (b * MILLI) as i64)
            && self.conn_rate.is_none_or(|(_, b)| u64::from(e.ct) >= u64::from(b) * MILLI)
    }

    /// One connection more for `k`; `max` 0 = no connection limit (the key is still tracked for the rates). Checked in
    /// order: --max-conns-per-ip (Refused), then 60.40 --conn-rate-per-ip (Rate); a refused connection takes no token.
    pub fn charge(&self, k: IpKey, max: u32, now: u64) -> Charge {
        let mut m = self.shard(k).lock().unwrap();
        if let Some(e) = m.get_mut(&k) {
            if max > 0 && e.conns >= max {
                return Charge::Refused;
            }
            self.refill(e, now);
            if self.conn_rate.is_some() {
                if u64::from(e.ct) < MILLI {
                    return Charge::Rate;
                }
                e.ct -= MILLI as u32;
            }
            e.conns += 1;
            return Charge::Charged;
        }
        if m.len() >= SHARD_CAP {
            return Charge::Untracked;
        }
        let tokens = self.rate.map_or(0, |(_, b)| b * MILLI as u32); // (milli-units: <= 2e9, cli)
        let ub = self.up.map_or(0, |(_, b)| (b * MILLI) as i64);
        let ct = self.conn_rate.map_or(0, |(_, b)| (b - 1) * MILLI as u32); // (burst >= 1: cli)
        m.insert(k, Entry { conns: 1, tokens, at: now, ct, ub, q: Upq::default() });
        self.keys.fetch_add(1, Relaxed);
        Charge::Charged
    }

    /// One connection fewer for a key that was charged. The entry goes once nothing is left to remember (no
    /// connection, a full bucket); else the sweep removes it after the refill.
    pub fn release(&self, k: IpKey, now: u64) {
        let mut m = self.shard(k).lock().unwrap();
        let Some(e) = m.get_mut(&k) else {
            debug_assert!(false, "release of an uncharged key");
            return;
        };
        debug_assert!(e.conns > 0, "per-IP release underflow");
        e.conns = e.conns.saturating_sub(1);
        self.refill(e, now);
        if self.idle(e) {
            m.remove(&k);
            self.keys.fetch_sub(1, Relaxed);
        }
    }

    /// --stream-rate-per-ip: take one token. An untracked key is not limited (fail open).
    pub fn take(&self, k: IpKey, now: u64) -> bool {
        let mut m = self.shard(k).lock().unwrap();
        let Some(e) = m.get_mut(&k) else { return true };
        self.refill(e, now);
        if u64::from(e.tokens) >= MILLI {
            e.tokens -= MILLI as u32;
            true
        } else {
            false
        }
    }

    /// The idle sweep of one shard: refill every entry and drop the idle ones.
    pub fn sweep(&self, shard: usize, now: u64) {
        let mut m = self.shards[shard % SHARDS].lock().unwrap();
        let before = m.len();
        m.retain(|_, e| {
            self.refill(e, now);
            !self.idle(e)
        });
        self.keys.fetch_sub(before - m.len(), Relaxed);
    }

    /// 60.25 C10b --upload-rate-per-ip: lease one connection's share from the key's bucket: LEASE_MS of the rate divided
    /// by the key's connections, within need..LEASE_MAX and at most the burst (shares keep one busy connection from taking
    /// every refill: review). Whole bytes; the bucket never goes below 0 here. While a connection of the key waits
    /// (the bucket was short), grants follow the key's starved-first queue (Upq). `ticket`: the caller's place in that
    /// queue (kept in its Meter). An untracked key is not limited (fail open, Q11, user 60.18 #17): None, and the caller
    /// adds nothing to its lease (so nothing synthetic is ever given back). The clock is read under the shard lock
    /// (review: no reordered `now`).
    pub fn take_bytes(&self, k: IpKey, need: u64, ticket: &mut Option<u32>) -> Option<u64> {
        let mut m = self.shard(k).lock().unwrap();
        let now = now_ms();
        self.take_bytes_at(&mut m, k, need, ticket, now)
    }

    fn take_bytes_at(
        &self,
        m: &mut HashMap<IpKey, Entry, RandomState>,
        k: IpKey,
        need: u64,
        ticket: &mut Option<u32>,
        now: u64,
    ) -> Option<u64> {
        let e = m.get_mut(&k)?;
        let (rate, burst) = self.up?;
        self.refill(e, now);
        let share = rate * LEASE_MS / MILLI / u64::from(e.conns.max(1)); // (R <= 2^40: cli)
        let want = share.clamp(need, LEASE_MAX.max(need)).min(burst).max(need);
        let avail = e.ub.max(0) as u64 / MILLI;
        let q = &mut e.q;
        q.settle(now, Some(avail >= want));
        if q.head == q.tail {
            *ticket = None;
            if avail >= need {
                let got = avail.min(want);
                e.ub -= (got * MILLI) as i64; // (got <= avail)
                return Some(got);
            }
            *ticket = Some(q.join());
            return Some(0);
        }
        // someone waits: served in ticket order, each only if the bucket also covers everyone unserved ahead of it
        let t = match *ticket {
            Some(t) if q.holds(t) => t,
            _ => q.join(),
        };
        *ticket = Some(t);
        let off = t.wrapping_sub(q.head);
        if off >= Upq::WINDOW {
            return Some(0);
        }
        let ahead = off as u64 - (q.done & ((1u64 << off) - 1)).count_ones() as u64;
        if avail < want.saturating_mul(ahead + 1) {
            return Some(0);
        }
        e.ub -= (want * MILLI) as i64; // (want <= avail)
        e.q.release(t, now);
        *ticket = None;
        Some(want)
    }

    /// 60.25 merged A/B (VPS2): a holder whose lease covers a read only in part tops it up to `to` (the read's room,
    /// capped at TOPUP_MAX) when nobody waits on the key (no ticket out) and the bucket can pay the whole top-up; else
    /// 0 and the caller's path is unchanged (a queue or a short bucket: today's lease edge). Without it, a 256 KiB lease
    /// against an rbuf with ~240 KiB free split every lease into two reads (8.2 vs 4.3 reads per MiB, -13% upload 10x10).
    /// Out of line: room's other paths keep their code. An untracked key: 0 (fail open, nothing leased).
    #[inline(never)]
    pub fn top_up_bytes(&self, k: IpKey, have: u64, to: u64) -> u64 {
        let mut m = self.shard(k).lock().unwrap();
        let now = now_ms();
        self.top_up_at(&mut m, k, have, to, now)
    }

    fn top_up_at(&self, m: &mut HashMap<IpKey, Entry, RandomState>, k: IpKey, have: u64, to: u64, now: u64) -> u64 {
        let n = to.min(TOPUP_MAX).saturating_sub(have);
        let Some(e) = m.get_mut(&k) else { return 0 };
        if n == 0 || self.up.is_none() || e.q.head != e.q.tail {
            return 0;
        }
        self.refill(e, now);
        if e.ub < (n * MILLI) as i64 {
            return 0; // (n <= TOPUP_MAX)
        }
        e.ub -= (n * MILLI) as i64;
        n
    }

    #[cfg(test)]
    fn top_up_now(&self, k: IpKey, have: u64, to: u64, now: u64) -> u64 {
        let mut m = self.shard(k).lock().unwrap();
        self.top_up_at(&mut m, k, have, to, now)
    }

    #[cfg(test)]
    fn take_bytes_now(&self, k: IpKey, need: u64, ticket: &mut Option<u32>, now: u64) -> Option<u64> {
        let mut m = self.shard(k).lock().unwrap();
        self.take_bytes_at(&mut m, k, need, ticket, now)
    }

    /// 60.25 C10b: a connection gives back leased bytes it did not read and its queue place (close, idle reclaim;
    /// clamped to the burst). Clock read under the shard lock.
    pub fn give_bytes(&self, k: IpKey, n: u64, ticket: Option<u32>) {
        let mut m = self.shard(k).lock().unwrap();
        let now = now_ms();
        self.give_bytes_at(&mut m, k, n, ticket, now)
    }

    fn give_bytes_at(&self, m: &mut HashMap<IpKey, Entry, RandomState>, k: IpKey, n: u64, ticket: Option<u32>, now: u64) {
        let Some(e) = m.get_mut(&k) else { return };
        self.refill(e, now);
        if let Some((_, b)) = self.up {
            let cap = b * MILLI;
            e.ub = (e.ub + n.saturating_mul(MILLI).min(2 * cap) as i64).min(cap as i64);
            // (ub >= -cap: no overflow)
        }
        if let Some(t) = ticket.filter(|&t| e.q.holds(t)) {
            e.q.release(t, now);
        }
    }

    /// 60.25 C10b (trusted proxy, review) bytes a connection read before its key was known are charged once it is:
    /// the bucket may go below 0 (down to -burst), and the key's next leases wait until it refills.
    pub fn charge_bytes(&self, k: IpKey, n: u64) {
        let mut m = self.shard(k).lock().unwrap();
        let now = now_ms();
        let Some(e) = m.get_mut(&k) else { return };
        self.refill(e, now);
        if let Some((_, b)) = self.up {
            let cap = b * MILLI;
            e.ub = (e.ub - n.saturating_mul(MILLI).min(2 * cap) as i64).max(-(cap as i64));
            // (ub <= cap: no overflow)
        }
    }

    /// 60.25 C10b --upload-rate-per-ip is on
    pub fn has_upload(&self) -> bool {
        self.up.is_some()
    }

    /// 60.40 --conn-rate-per-ip is on
    #[cfg(test)]
    pub fn has_conn_rate(&self) -> bool {
        self.conn_rate.is_some()
    }

    /// --stream-rate-per-ip is on (the only copy of the rate)
    pub fn has_rate(&self) -> bool {
        self.rate.is_some()
    }

    pub fn keys(&self) -> usize {
        self.keys.load(Relaxed)
    }

    #[cfg(test)]
    pub fn upload_left(&self, k: IpKey) -> Option<f64> {
        self.shard(k).lock().unwrap().get(&k).map(|e| e.ub as f64 / MILLI as f64)
    }

    #[cfg(test)]
    pub fn shard_of(&self, k: IpKey) -> usize {
        self.hash.hash_one(k) as usize % SHARDS
    }

    #[cfg(test)]
    pub fn conns(&self, k: IpKey) -> u32 {
        self.shard(k).lock().unwrap().get(&k).map_or(0, |e| e.conns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn cfg(trusted: &[&str], header: &str) -> ClientIp {
        ClientIp { trusted: trusted.iter().map(|s| Cidr::parse(s).unwrap()).collect(), header: header.into(), table: None, max_conns: 0 }
    }
    fn lines(v: &[&str]) -> Vec<Vec<u8>> {
        v.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn keys_and_canon() {
        assert_eq!(key(ip("1.2.3.4")), key(ip("::ffff:1.2.3.4")));
        assert_ne!(key(ip("1.2.3.4")), key(ip("1.2.3.5")));
        assert_eq!(key(ip("2001:db8:1:2:aaaa::1")), key(ip("2001:db8:1:2:ffff::9")), "one /64");
        assert_ne!(key(ip("2001:db8:1:2::1")), key(ip("2001:db8:1:3::1")));
        assert_ne!(key(ip("::1.2.3.4")), key(ip("1.2.3.4")), "::/96 is IPv6");
        assert_eq!(canon(ip("::ffff:10.0.0.1")), ip("10.0.0.1"));
    }

    #[test]
    fn untrusted_peer_ignores_headers() {
        let c = cfg(&["127.0.0.1"], "x-forwarded-for");
        assert_eq!(c.real_ip(ip("127.0.0.2"), &lines(&["9.9.9.9"])), (ip("127.0.0.2"), None));
        assert_eq!(c.real_ip(ip("::ffff:127.0.0.2"), &lines(&["9.9.9.9"])), (ip("127.0.0.2"), None));
        assert_eq!(c.real_ip(ip("::ffff:127.0.0.1"), &lines(&["9.9.9.9"])), (ip("9.9.9.9"), Some(Got::Header)), "mapped peer");
    }

    #[test]
    fn xff_walk() {
        let c = cfg(&["127.0.0.1", "10.0.0.0/8"], "x-forwarded-for");
        let p = ip("127.0.0.1");
        let r = |v: &[&str]| c.real_ip(p, &lines(v));
        assert_eq!(r(&["1.1.1.1"]), (ip("1.1.1.1"), Some(Got::Header)));
        assert_eq!(r(&["6.6.6.6, 1.1.1.1"]), (ip("1.1.1.1"), Some(Got::Header)), "rightmost untrusted, not the client's leftmost");
        assert_eq!(r(&["6.6.6.6, 1.1.1.1, 10.0.0.5"]), (ip("1.1.1.1"), Some(Got::Header)), "trusted hops skipped");
        assert_eq!(r(&["10.0.0.7, 10.0.0.5"]), (ip("10.0.0.7"), Some(Got::Header)), "all trusted: the leftmost");
        assert_eq!(r(&["6.6.6.6", "1.1.1.1, 10.0.0.5"]), (ip("1.1.1.1"), Some(Got::Header)), "lines joined in order");
        assert_eq!(r(&["1.1.1.1", "10.0.0.5"]), (ip("1.1.1.1"), Some(Got::Header)));
        assert_eq!(r(&["1.1.1.1:5678"]), (ip("1.1.1.1"), Some(Got::Header)));
        assert_eq!(r(&["[2001:db8::1]:443"]), (ip("2001:db8::1"), Some(Got::Header)));
        assert_eq!(r(&["[2001:db8::1]"]), (ip("2001:db8::1"), Some(Got::Header)));
        assert_eq!(r(&[" 2001:db8::2 "]), (ip("2001:db8::2"), Some(Got::Header)));
        assert_eq!(r(&["::ffff:1.2.3.4"]), (ip("1.2.3.4"), Some(Got::Header)));
        assert_eq!(r(&["1.1.1.1, unknown, 10.0.0.5"]), (ip("10.0.0.5"), Some(Got::Bad)), "junk ends the walk at the last trusted hop");
        assert_eq!(r(&["1.1.1.1, unknown"]), (p, Some(Got::Bad)), "junk right after the peer: the peer");
        assert_eq!(r(&["_hidden"]), (p, Some(Got::Bad)));
        assert_eq!(r(&[""]), (p, Some(Got::Bad)));
        assert_eq!(r(&["1.1.1.1,"]), (p, Some(Got::Bad)));
        assert_eq!(r(&["[::1"]), (p, Some(Got::Bad)));
        assert_eq!(r(&["[::1]:x"]), (p, Some(Got::Bad)));
        assert_eq!(r(&["1.2.3.4:99999"]), (p, Some(Got::Bad)));
        assert_eq!(c.real_ip(p, &[vec![0xff, 0xfe]]), (p, Some(Got::Bad)));
        assert_eq!(r(&[]), (p, Some(Got::Missing)));
        // a non-UTF-8 entry is junk, the entries right of it still count (bytes, not a whole-line decode)
        let raw = |b: &[u8]| c.real_ip(p, &[b.to_vec()]);
        assert_eq!(raw(b"1.1.1.1, \xff\xff, 9.9.9.9"), (ip("9.9.9.9"), Some(Got::Header)));
        assert_eq!(raw(b"1.1.1.1, \xff\xff, 10.0.0.1"), (ip("10.0.0.1"), Some(Got::Bad)));
    }

    #[test]
    fn single_value_headers() {
        let c = cfg(&["127.0.0.1"], "x-real-ip");
        let p = ip("127.0.0.1");
        assert_eq!(c.real_ip(p, &lines(&["1.1.1.1"])), (ip("1.1.1.1"), Some(Got::Header)));
        assert_eq!(c.real_ip(p, &lines(&["1.1.1.1:80"])), (ip("1.1.1.1"), Some(Got::Header)));
        assert_eq!(c.real_ip(p, &lines(&["1.1.1.1, 2.2.2.2"])), (p, Some(Got::Bad)), "a list in a single-value header");
        assert_eq!(c.real_ip(p, &lines(&["1.1.1.1", "2.2.2.2"])), (p, Some(Got::Bad)), "several lines: ambiguous, not first-wins");
        assert_eq!(c.real_ip(p, &lines(&[])), (p, Some(Got::Missing)));
        assert_eq!(c.real_ip(p, &lines(&["127.0.0.1"])), (p, Some(Got::Header)), "a single value is taken as is");
    }

    #[test]
    fn upload_lease_bounded_and_given_back() {
        let t = IpTable::with_upload(None, Some((1000, 100_000))); // 1000 B/s, burst 100 KB
        let a = key(ip("1.1.1.1"));
        assert_eq!(t.charge(a, 0, 0), Charge::Charged);
        let mut tk = None;
        assert_eq!(t.take_bytes_now(a, 60_000, &mut tk, 0), Some(60_000), "at least `need`");
        assert_eq!(t.take_bytes_now(a, 60_000, &mut tk, 0), Some(0), "short (40 KB left): nothing, never below 0");
        assert_eq!(tk, Some(0), "and the first waiter's ticket");
        assert_eq!(t.take_bytes_now(a, 60_000, &mut tk, 19_000), Some(0), "59 KB: still short");
        assert_eq!(t.take_bytes_now(a, 60_000, &mut tk, 20_000), Some(60_000), "refill 1 B/ms: the head is served");
        assert_eq!(tk, None);
        {
            let mut m = t.shard(a).lock().unwrap();
            t.give_bytes_at(&mut m, a, 1_000_000, None, 20_000);
        }
        assert_eq!(t.take_bytes_now(a, 100_000, &mut tk, 20_000), Some(100_000), "give back clamped to the burst");
        assert_eq!(t.take_bytes_now(a, 10, &mut tk, 19_990), Some(0), "a stale now (before at) refills nothing");
        assert_eq!(t.take_bytes_now(key(ip("9.9.9.9")), 77, &mut None, 0), None, "untracked key: fail open (nothing leased)");
        {
            let mut m = t.shard(a).lock().unwrap();
            t.give_bytes_at(&mut m, a, 0, tk.take(), 20_000); // a closing waiter gives its ticket back
            assert!(m[&a].q.head == m[&a].q.tail, "queue empty again");
        }
        t.release(a, 600);
        assert_eq!(t.keys(), 1, "kept until its bucket is full again (a reconnect cannot reset it)");
        t.sweep(t.shard_of(a), 600 + 200_000);
        assert_eq!(t.keys(), 0);
        // the share: 50 ms of the rate split by the key's connections
        let f = IpTable::with_upload(None, Some((10_000_000, 1_000_000_000))); // 10 MB/s: 500 KB per 50 ms
        let b = key(ip("2.2.2.2"));
        assert_eq!(f.charge(b, 0, 0), Charge::Charged);
        assert_eq!(f.take_bytes_now(b, 4096, &mut None, 0), Some(256 << 10), "one connection: LEASE_MAX");
        for _ in 0..9 {
            f.charge(b, 0, 0);
        }
        assert_eq!(f.take_bytes_now(b, 4096, &mut None, 0), Some(50_000), "ten connections: a tenth");
    }

    /// 60.25 merged A/B top-up: a lease that covers only part of a read is topped up to the read's room when nobody
    /// waits and the bucket can pay it all; a waiting sibling (a ticket out) or a short bucket leaves it alone
    #[test]
    fn upload_top_up_only_when_uncontended() {
        let t = IpTable::with_upload(None, Some((1000, 1_000_000))); // 1000 B/s, burst 1 MB
        let k = key(ip("6.6.6.6"));
        for _ in 0..2 {
            assert_eq!(t.charge(k, 0, 0), Charge::Charged);
        }
        let ub = |t: &IpTable| t.upload_left(k).unwrap();
        let full = ub(&t);
        assert_eq!(t.top_up_now(k, 16_384, 245_955, 0), 245_955 - 16_384, "topped up to the read's room");
        assert_eq!(ub(&t), full - (245_955 - 16_384) as f64);
        assert_eq!(t.top_up_now(k, 16_384, 4 << 20, 0), TOPUP_MAX - 16_384, "capped at TOPUP_MAX");
        assert_eq!(t.top_up_now(k, 300_000, 200_000, 0), 0, "the lease covers the read: nothing");
        assert_eq!(t.top_up_now(key(ip("6.6.6.7")), 0, 100_000, 0), 0, "untracked key: fail open, nothing leased");
        // short bucket: all or nothing
        let before = ub(&t);
        assert_eq!(t.top_up_now(k, 0, before as u64 + 1, 0), 0, "short bucket: no partial top-up");
        assert_eq!(ub(&t), before);
        assert_eq!(t.top_up_now(k, 0, before as u64 + 1, 2000), before as u64 + 1, "2 s of refill pay it: topped up");
        t.shard(k).lock().unwrap().get_mut(&k).unwrap().ub = (before * 1000.0) as i64;
        // a waiting sibling blocks it, even when the bucket could pay
        let mut x = None;
        while t.take_bytes_now(k, 4096, &mut x, 0) != Some(0) {}
        assert!(x.is_some(), "x waits with a ticket");
        t.shard(k).lock().unwrap().get_mut(&k).unwrap().ub = 500_000_000;
        assert_eq!(t.top_up_now(k, 16_384, 200_000, 0), 0, "a ticket is out: no top-up");
        assert_eq!(ub(&t), 500_000.0);
        assert_eq!(t.take_bytes_now(k, 4096, &mut x, 0).map(|g| g > 0), Some(true), "x served first");
        assert_eq!(t.top_up_now(k, 16_384, 200_000, 0), 200_000 - 16_384, "queue empty again: top-up");
    }

    /// 60.25 C10b starved-first queue (review): while a connection of the key waits, a newcomer cannot jump it, the
    /// bucket serves tickets in order, and a holder that does not come back is skipped after its slot
    #[test]
    fn upload_queue_serves_in_order() {
        let t = IpTable::with_upload(None, Some((1000, 16_384))); // 1000 B/s, burst 16 KiB
        let k = key(ip("3.3.3.3"));
        for _ in 0..3 {
            assert_eq!(t.charge(k, 0, 0), Charge::Charged);
        }
        let (mut x, mut y, mut z) = (None, None, None);
        for _ in 0..4 {
            assert_eq!(t.take_bytes_now(k, 4096, &mut x, 0), Some(4096));
        }
        assert_eq!(t.take_bytes_now(k, 4096, &mut x, 0), Some(0), "spent: x waits");
        assert_eq!(t.take_bytes_now(k, 4096, &mut y, 0), Some(0), "y waits behind x");
        assert_eq!((x, y), (Some(0), Some(1)));
        assert_eq!(t.take_bytes_now(k, 4096, &mut y, 4096), Some(0), "4 KiB back: x first, not y");
        assert_eq!(t.take_bytes_now(k, 4096, &mut x, 4096), Some(4096), "x served");
        assert_eq!(t.take_bytes_now(k, 4096, &mut z, 8192), Some(0), "z (no ticket) cannot jump y");
        assert_eq!(z, Some(2));
        assert_eq!(t.take_bytes_now(k, 4096, &mut y, 8192), Some(4096), "y served");
        // z never comes back; a newcomer waits behind it until z's slot (refill 4096 ms + SLOT_MS) has passed
        let mut w = None;
        assert_eq!(t.take_bytes_now(k, 4096, &mut w, 12_288), Some(0));
        assert_eq!(t.take_bytes_now(k, 4096, &mut w, 8192 + 4096 + Upq::SLOT_MS + 1), Some(4096), "z skipped");
        assert_eq!(t.take_bytes_now(k, 4096, &mut z, 20_000), Some(4096), "z's old ticket is gone; nobody waits: served");
        assert_eq!(z, None);
        // (review) more than WINDOW waiters: everyone gets a ticket; tickets beyond the window that are given
        // back out of order (closing waiters) are kept in `late` and folded in when they reach the window
        let n = Upq::WINDOW as usize + Upq::LATE;
        let mut ts: Vec<Option<u32>> = vec![None; n];
        for tk in ts.iter_mut() {
            assert_eq!(t.take_bytes_now(k, 16_384, tk, 20_000), Some(0));
        }
        assert!(ts.iter().all(Option::is_some));
        {
            let mut m = t.shard(k).lock().unwrap();
            for tk in ts.iter_mut().rev() {
                t.give_bytes_at(&mut m, k, 0, tk.take(), 20_000); // the last ones first: out of window
            }
            assert!(m[&k].q.head == m[&k].q.tail && m[&k].q.late_n == 0, "every ticket given back: empty");
        }
        // (review) a head behind a deficit (a bootstrap charge) is not skipped before its grant is fundable
        let d = IpTable::with_upload(None, Some((1000, 16_384)));
        let kd = key(ip("4.4.4.4"));
        assert_eq!(d.charge(kd, 0, 0), Charge::Charged);
        d.charge(kd, 0, 0);
        {
            let mut m = d.shard(kd).lock().unwrap();
            let e = m.get_mut(&kd).unwrap();
            e.ub = -16_384_000; // the bucket owes a full burst (milli-bytes)
        }
        let (mut a, mut b) = (None, None);
        assert_eq!(d.take_bytes_now(kd, 4096, &mut a, 0), Some(0));
        assert_eq!(a, Some(0));
        // 20 s later the deficit is paid (bucket 3.6 KiB < 4 KiB): b must not have skipped a
        assert_eq!(d.take_bytes_now(kd, 4096, &mut b, 20_000), Some(0));
        assert_eq!(d.take_bytes_now(kd, 4096, &mut a, 20_500), Some(4096), "a kept its place behind the deficit");
        // (review) the head's grant fundable once (a follower arms ready_at), then a bootstrap charge takes it
        // away: later polls restart the grace instead of skipping the live head
        for charged in [true, false] {
            let d = IpTable::with_upload(None, Some((1000, 16_384)));
            let k3 = key(ip("5.5.5.5"));
            assert_eq!(d.charge(k3, 0, 0), Charge::Charged);
            d.shard(k3).lock().unwrap().get_mut(&k3).unwrap().ub = 0;
            let (mut a, mut b) = (None, None);
            assert_eq!(d.take_bytes_now(k3, 4096, &mut a, 0), Some(0)); // a: the head
            d.shard(k3).lock().unwrap().get_mut(&k3).unwrap().ub = 5_000_000; // a's grant fundable, not a's + b's
            assert_eq!(d.take_bytes_now(k3, 4096, &mut b, 10), Some(0)); // b behind a, ready_at = 10
            if charged {
                d.charge_bytes(k3, 1 << 30); // bucket to -burst
            }
            // charged: b still waits behind a; control: a's fundable grant expired unclaimed, b is served
            let got = d.take_bytes_now(k3, 4096, &mut b, 400);
            assert_eq!(got, Some(if charged { 0 } else { 4096 }));
            let held = d.shard(k3).lock().unwrap()[&k3].q.holds(a.unwrap());
            assert_eq!(held, charged, "charged: grace restarted, a kept; control: a's fundable grant expired");
        }
    }

    #[test]
    fn table_charge_release_and_cap() {
        let t = IpTable::new(None);
        let (a, b) = (key(ip("1.1.1.1")), key(ip("2.2.2.2")));
        assert_eq!((t.charge(a, 2, 0), t.charge(a, 2, 0), t.charge(a, 2, 0)), (Charge::Charged, Charge::Charged, Charge::Refused));
        assert_eq!(t.charge(b, 2, 0), Charge::Charged);
        assert_eq!(t.keys(), 2);
        t.release(a, 0);
        assert_eq!(t.charge(a, 2, 0), Charge::Charged, "a release makes room");
        t.release(a, 0);
        t.release(a, 0);
        t.release(b, 0);
        assert_eq!(t.keys(), 0, "no rate: the entry goes with its last connection");
        // a full shard: new keys are untracked (fail open), known keys still work
        let mut n = 0u32;
        let mut keys = Vec::new();
        while keys.len() < SHARDS * SHARD_CAP + 10 {
            let k = key(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n)));
            n += 1;
            if t.charge(k, 0, 0) == Charge::Untracked {
                keys.push(None);
            } else {
                keys.push(Some(k));
            }
        }
        assert!(keys.iter().filter(|k| k.is_none()).count() >= 10);
        assert!(t.keys() <= SHARDS * SHARD_CAP);
        let known = keys.iter().flatten().next().copied().unwrap();
        assert_eq!(t.charge(known, 0, 0), Charge::Charged);
    }

    /// 60.40 --conn-rate-per-ip: a token per new connection; over the limit nothing is taken and the count is
    /// unchanged; --max-conns-per-ip is checked first; wispurr's 200 per 10 s window is 20/200 (a full burst of 200,
    /// then 20 per second = 200 per 10 s)
    #[test]
    fn conn_rate_bucket() {
        let t = IpTable::with_rates(None, None, Some((20, 200)));
        assert!(t.has_conn_rate() && !t.has_rate());
        let k = key(ip("1.1.1.1"));
        assert!((0..200).all(|_| t.charge(k, 0, 0) == Charge::Charged), "the burst: 200 at once");
        assert_eq!(t.charge(k, 0, 0), Charge::Rate, "the 201st in the same instant");
        assert_eq!(t.conns(k), 200, "a refused connection is not counted");
        assert_eq!(t.charge(k, 0, 49), Charge::Rate, "0.98 of a token after 49 ms");
        assert_eq!(t.charge(k, 0, 51), Charge::Charged, "one per 50 ms (20/s)");
        assert_eq!(t.charge(k, 0, 51), Charge::Rate);
        // a steady client gets 200 in each further 10 s (one every 50 ms), not more
        let n = (1..=200u64).filter(|i| t.charge(k, 0, 51 + i * 50) == Charge::Charged).count();
        assert_eq!(n, 200);
        assert_eq!(t.charge(k, 0, 10_051), Charge::Rate);
        assert_eq!(t.charge(k, 0, 10_040), Charge::Rate, "a reordered older now: no 49-day refill");
        assert_eq!(t.conns(k), 401);
        // the --max-conns-per-ip check comes first and takes no token
        let m = IpTable::with_rates(None, None, Some((1, 2)));
        let a = key(ip("2.2.2.2"));
        assert_eq!((m.charge(a, 1, 0), m.charge(a, 1, 0)), (Charge::Charged, Charge::Refused));
        m.release(a, 0);
        assert_eq!(m.charge(a, 1, 0), Charge::Charged, "the refusal took no token: the second of the burst is left");
        m.release(a, 0);
        assert_eq!(m.charge(a, 1, 0), Charge::Rate, "now the bucket is empty");
        // an untracked key (full shard) is not limited (Q11 fail open): shown by the shard cap test; a separate key has
        // its own bucket
        assert_eq!(m.charge(key(ip("2.2.2.3")), 1, 0), Charge::Charged);
    }

    /// 60.40 a client cannot reset its --conn-rate-per-ip bucket by closing its connections: release keeps a drained
    /// entry (no connection, bucket not full); the sweep refills it and drops it only when it is full again
    #[test]
    fn conn_rate_survives_reconnect() {
        let t = IpTable::with_rates(None, None, Some((1, 3))); // 1/s, burst 3
        let k = key(ip("5.5.5.5"));
        for _ in 0..3 {
            assert_eq!(t.charge(k, 0, 0), Charge::Charged);
            t.release(k, 0); // connect, close, connect again
        }
        assert_eq!(t.keys(), 1, "drained: kept after its last connection");
        assert_eq!(t.charge(k, 0, 10), Charge::Rate, "reconnecting does not reset the bucket");
        for s in 0..SHARDS {
            t.sweep(s, 1000);
        }
        assert_eq!(t.keys(), 1, "one token back after 1 s: not full, kept");
        assert_eq!(t.charge(k, 0, 1000), Charge::Charged);
        t.release(k, 1000);
        for s in 0..SHARDS {
            t.sweep(s, 4000);
        }
        assert_eq!(t.keys(), 0, "full after 3 s more: dropped");
        // a fresh entry starts with burst - 1 (the connection that created it took a token)
        assert!((0..3).all(|_| t.charge(k, 0, 4000) == Charge::Charged) && t.charge(k, 0, 4000) == Charge::Rate);
        // with the rate off, an entry with no connection goes at release as before
        let off = IpTable::new(None);
        assert_eq!(off.charge(k, 0, 0), Charge::Charged);
        off.release(k, 0);
        assert_eq!(off.keys(), 0);
    }

    /// 60.45 the table clock as a caller passes it: `now_ms()` of a process that has run `t` ms
    fn ms(t: u64) -> u64 {
        t
    }

    /// 60.45 an entry no sweep refreshed for 2^32 ms or more (every worker asleep: a server without clients for 49.7
    /// days) refills as for the real gap: a full burst, in every bucket. With the old u32 clock a gap of 2^32 + x ms
    /// read as x ms and a gap just under 2^32 as a reordering (no refill at all).
    #[test]
    fn idle_beyond_u32_ms_refills_fully() {
        const W: u64 = 1 << 32;
        for gap in [W + 10, W - 30_000, 3 * W + 7] {
            // --stream-rate-per-ip 10/s burst 20 and --conn-rate-per-ip 1/s burst 3 in one table
            let t = IpTable::with_rates(Some((10, 20)), None, Some((1, 3)));
            let k = key(ip("1.1.1.1"));
            assert!((0..3).all(|_| t.charge(k, 0, ms(1000)) == Charge::Charged), "conn burst");
            assert_eq!(t.charge(k, 0, ms(1000)), Charge::Rate);
            assert!((0..20).all(|_| t.take(k, ms(1000))) && !t.take(k, ms(1000)), "stream burst spent");
            let late = ms(1000 + gap);
            assert!((0..20).all(|_| t.take(k, late)), "gap {gap}: a full stream burst after the idle time");
            assert!(!t.take(k, late));
            assert!((0..3).all(|_| t.charge(k, 0, late) == Charge::Charged), "gap {gap}: a full conn burst");
            assert_eq!(t.charge(k, 0, late), Charge::Rate);
            // a drained entry without connections that no sweep saw for that long: the first sweep drops it
            let d = key(ip("2.2.2.2"));
            assert_eq!(t.charge(d, 0, ms(1000)), Charge::Charged);
            t.release(d, ms(1000));
            assert_eq!(t.conns(d), 0);
            assert_eq!(t.keys(), 2, "k (connected) and the drained d");
            t.sweep(t.shard_of(d), late);
            assert_eq!(t.keys(), 1, "gap {gap}: d full again: dropped by the sweep; k kept (connected)");
            assert!((0..3).all(|_| t.charge(d, 0, late) == Charge::Charged), "gap {gap}: d starts a full burst");
            assert_eq!(t.charge(d, 0, late), Charge::Rate);
            // --upload-rate-per-ip: the whole burst again
            let u = IpTable::with_upload(None, Some((1000, 100_000)));
            assert_eq!(u.charge(k, 0, ms(1000)), Charge::Charged);
            assert_eq!(u.take_bytes_now(k, 100_000, &mut None, ms(1000)), Some(100_000));
            assert_eq!(u.take_bytes_now(k, 100_000, &mut None, ms(1000 + gap)), Some(100_000), "gap {gap}: upload burst");
        }
    }

    /// 60.45 a waiting head whose grant became fundable (ready_at) and then nobody polled for 2^32 ms or more: its slot
    /// has long expired, so the next poll skips it. With the old u32 ready_at the age wrapped to a few ms (or into the
    /// reordering window) and the follower kept waiting behind a holder that never came back.
    #[test]
    fn stale_head_skipped_after_u32_ms() {
        const W: u64 = 1 << 32;
        for gap in [W + 100, W - 30_000] {
            let d = IpTable::with_upload(None, Some((1000, 6000))); // burst 6000: one 4096 grant, not two
            let k = key(ip("5.5.5.5"));
            assert_eq!(d.charge(k, 0, ms(0)), Charge::Charged);
            d.shard(k).lock().unwrap().get_mut(&k).unwrap().ub = 0;
            let (mut a, mut b) = (None, None);
            assert_eq!(d.take_bytes_now(k, 4096, &mut a, ms(0)), Some(0)); // a: the head
            d.shard(k).lock().unwrap().get_mut(&k).unwrap().ub = 5_000_000; // a's grant fundable, not a's + b's
            assert_eq!(d.take_bytes_now(k, 4096, &mut b, ms(10)), Some(0)); // b behind a, ready_at = 10
            assert_eq!(d.take_bytes_now(k, 4096, &mut b, ms(10 + gap)), Some(4096), "gap {gap}: a's slot expired, b served");
            assert!(!d.shard(k).lock().unwrap()[&k].q.holds(a.unwrap()), "gap {gap}: a skipped");
        }
    }

    /// 60.45 (parent review) a gap up to the end of u64 refills exactly the burst (saturating milli-units: no overflow),
    /// and a reordered older `now` refills nothing and leaves the entry's time where it was
    #[test]
    fn huge_gap_and_reordered_now() {
        let t = IpTable::with_rates(Some((10, 20)), Some((1000, 100_000)), Some((1, 3)));
        let k = key(ip("7.7.7.7"));
        let at = |t: &IpTable| t.shard(k).lock().unwrap()[&k].at;
        let buckets = |t: &IpTable| {
            let m = t.shard(k).lock().unwrap();
            (m[&k].tokens, m[&k].ct, m[&k].ub)
        };
        assert_eq!(t.charge(k, 0, 5000), Charge::Charged);
        assert!((0..20).all(|_| t.take(k, 5000)));
        assert_eq!(buckets(&t), (0, 2000, 100_000_000), "milli-units");
        // older now: nothing refilled, at unchanged (not moved back), the refusal stands
        assert!(!t.take(k, 4000));
        assert_eq!(at(&t), 5000);
        assert_eq!(t.charge(k, 0, 1), Charge::Charged); // (ct 2 -> 1: the charge spends, the refill adds nothing)
        assert_eq!((at(&t), buckets(&t)), (5000, (0, 1000, 100_000_000)));
        t.release(k, 0);
        t.sweep(t.shard_of(k), 4999);
        assert_eq!((at(&t), buckets(&t)), (5000, (0, 1000, 100_000_000)), "release and sweep with an older now: no change");
        for now in [5000 + (1u64 << 40), u64::MAX] {
            assert!(t.take(k, now));
            let (tk, ct, ub) = buckets(&t);
            assert_eq!((tk, ct, ub), (19_000, 3000, 100_000_000), "{now}: exactly the burst");
            assert_eq!(at(&t), now);
            assert!((0..19).all(|_| t.take(k, now)) && !t.take(k, now));
        }
    }

    /// 60.45 review: the conn bucket refilled in steps (a stream take in between) must give the same tokens as
    /// one refill: 20/s burst 1, 20 ms then 30 ms is exactly one token (f32 gave 0.99999994: refused)
    #[test]
    fn refill_in_steps_is_exact() {
        let t = IpTable::with_rates(Some((10, 20)), None, Some((20, 1)));
        let k = key(ip("8.8.8.8"));
        assert_eq!(t.charge(k, 0, 0), Charge::Charged);
        assert!(t.take(k, 20));
        assert_eq!(t.charge(k, 0, 50), Charge::Charged, "50 ms of 20/s: one token, in two refills");
        assert_eq!(t.charge(k, 0, 50), Charge::Rate);
    }

    /// 60.45 review: a large burst refilled by an upload every ms (1 ms = 1 milli-token at 1/s) fills up as in
    /// one step (f32 at 1e5 dropped every 0.001 token)
    #[test]
    fn small_refills_of_a_large_burst_add_up() {
        let t = IpTable::with_rates(None, Some((1000, 1_000_000_000)), Some((1, 100_000)));
        let k = key(ip("8.8.4.4"));
        assert_eq!(t.charge(k, 0, 0), Charge::Charged); // conn bucket 99,999
        for now in 1..=1000 {
            assert!(t.take_bytes_now(k, 1, &mut None, now).is_some_and(|g| g > 0));
        }
        let n = (0..100_001).take_while(|_| t.charge(k, 0, 1000) == Charge::Charged).count();
        assert_eq!(n, 100_000, "1000 refills of 1 ms = one token: the bucket is full again");
    }

    /// 60.40 the per-entry size the conn bucket costs (the table exists only with a per-IP limit on: main build_clientip)
    #[test]
    fn entry_size() {
        assert_eq!(std::mem::size_of::<Entry>(), 96);
        assert_eq!(std::mem::size_of::<(IpKey, Entry)>(), 112);
    }

    #[test]
    fn bucket_refill_burst_and_wrap() {
        let t = IpTable::new(Some((10, 20))); // 10/s, burst 20
        let k = key(ip("1.1.1.1"));
        assert_eq!(t.charge(k, 0, 1000), Charge::Charged);
        assert!((0..20).all(|_| t.take(k, 1000)), "burst");
        assert!(!t.take(k, 1000), "empty");
        assert!(!t.take(k, 1050), "half a token after 50 ms");
        assert!(t.take(k, 1100), "one token per 100 ms");
        assert!(!t.take(k, 1100));
        assert!(!t.take(k, 1090), "a now older than the entry's (lock reordering): no 49-day refill");
        assert!(!t.take(k, 1150) && t.take(k, 1200), "the entry's time did not move back");
        assert!(t.take(k, 1_000_000) && (0..19).all(|_| t.take(k, 1_000_000)) && !t.take(k, 1_000_000), "refill clamped at the burst");
        // 60.45 past 2^32 ms (where the old u32 clock wrapped): 100 ms from 2^32 - 50 to 2^32 + 50 is one token
        let w = key(ip("3.3.3.3"));
        let w0 = (1u64 << 32) - 50;
        assert_eq!(t.charge(w, 0, w0), Charge::Charged);
        assert!((0..20).all(|_| t.take(w, w0)) && !t.take(w, w0));
        assert!(t.take(w, w0 + 100) && !t.take(w, w0 + 100), "one token over 2^32 ms, not a full burst");
        assert!(t.take(key(ip("9.9.9.9")), 0), "an untracked key is not limited");
        // release keeps a drained bucket (a reconnect cannot reset it); the sweep drops it once refilled
        t.release(k, 1_000_000);
        assert_eq!(t.keys(), 2);
        for s in 0..SHARDS {
            t.sweep(s, 1_000_100);
        }
        assert_eq!(t.keys(), 2, "k: 1 token after 100 ms, not full: kept");
        for s in 0..SHARDS {
            t.sweep(s, 1_010_000);
        }
        assert_eq!(t.keys(), 1, "k full after 10 s: dropped; w has a connection");
        t.release(w, w0 + 10_100); // (w's time is past 2^32 ms: full 10 s after its last take)
        assert_eq!(t.keys(), 0);
    }
}
