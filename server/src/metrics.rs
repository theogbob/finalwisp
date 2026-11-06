//! 60.12 C5-lite metrics (60.02 C5): per-worker event counters at control points only (accept, CONNECT, close,
//! level change, idle sweep), never per byte or frame. Each worker owns one `Stats` and is its only writer:
//! `bump` is a relaxed load + store (a plain add on x86-64/aarch64, no locked instruction, no shared cache
//! line). The counters are always counted; `--metrics-interval SECS` (default 0 = off) only starts the thread
//! that sums them and logs one `ev=metrics` line per interval, plus one `ev=metrics_final` line at SIGTERM /
//! SIGINT (main.rs). Values are cumulative since start (a dropped or missed line loses nothing).
use crate::net::Inbox;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// One event counter or gauge. deliberate: single writer (the owning worker); a second writer would lose adds.
#[derive(Default)]
pub struct Ctr(AtomicU64);
impl Ctr {
    #[inline]
    pub fn bump(&self) {
        self.add(1)
    }
    #[inline]
    pub fn add(&self, n: u64) {
        self.0.store(self.0.load(Relaxed).wrapping_add(n), Relaxed); // single writer: no locked instruction
    }
    /// 50.02 raise to `v` (max gauges; one writer per worker)
    #[inline]
    pub fn max(&self, v: u64) {
        if v > self.get() {
            self.set(v)
        }
    }
    #[inline]
    pub fn set(&self, v: u64) {
        self.0.store(v, Relaxed)
    }
    pub fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
}

/// The counters, listed once: field, log key and meaning come from the same line.
macro_rules! stats {
    ($($(#[doc = $d:literal])* $(#[cfg($c:meta)])? $name:ident,)*) => {
        /// 60.12 per-worker event counters (see the module doc). `close[r]`: Wisp CLOSE packets sent with reason r.
        /// A name ending in `_max` is a max gauge: line() merges it across workers by max, every other one by sum.
        #[repr(align(128))]
        pub struct Stats {
            $($(#[doc = $d])* $(#[cfg($c)])? pub $name: Ctr,)*
            pub close: [Ctr; 256],
        }
        impl Stats {
            pub fn new() -> Stats {
                Stats { $($(#[cfg($c)])? $name: Ctr::default(),)* close: std::array::from_fn(|_| Ctr::default()) }
            }
            /// (key, value) of every named counter, in declaration order
            fn named(&self) -> Vec<(&'static str, u64)> {
                let mut v = Vec::new();
                $($(#[cfg($c)])? v.push((stringify!($name), self.$name.get()));)*
                v
            }
            /// 60.29 C5 (name, doc text) of every named counter, in declaration order (the Prometheus HELP lines)
            pub(crate) fn help() -> Vec<(&'static str, &'static str)> {
                let mut v = Vec::new();
                $($(#[cfg($c)])? v.push((stringify!($name), concat!($($d),*)));)*
                v
            }
        }
    };
}

stats! {
    /// connections taken by the worker threads (accepted, or handed over by --balance)
    accepted,
    /// accept() failed for lack of fds (EMFILE / ENFILE); retried every 10 ms while it lasts
    accept_err_fd,
    /// accept() failed for lack of kernel memory (ENOBUFS / ENOMEM)
    accept_err_mem,
    /// accept paused by memory pressure (level 2+; once per pause)
    accept_paused,
    /// CONNECTs admitted past the admission and stream limits (a target was created; it may still fail at once, e.g.
    /// a negative DNS entry: see the close_* counts)
    connects,
    /// CONNECT refused with 0x49: admission off (memory level 2+)
    refuse_admit,
    /// CONNECT refused with 0x49: the worker's stream limit under capped socket buffers (mem::max_streams)
    refuse_streams,
    /// CONNECT refused with 0x49: too many DNS lookups in flight
    refuse_dns,
    /// 60.20 C3a CONNECT refused with 0x49: --max-streams-per-conn reached on that connection
    refuse_limit,
    /// 60.20 C3a connections reset at accept: --max-conns reached
    refuse_conns,
    /// DNS answered from the worker cache (positive)
    dns_hit,
    /// DNS answered from the negative cache (0x42 at once)
    dns_neg_hit,
    /// DNS lookups sent to the pool (cache miss or expired)
    dns_miss,
    /// DNS lookups that gave no address (0x42), incl. a pool that could not be reached
    dns_fail,
    /// 20.27 0x49 hold: clients held (not read) because an in-credit stream passed PEND_HARD. Held now = holds -
    /// hold_resumes - hold_expired (minus held clients that closed)
    holds,
    /// 20.27 held clients resumed because their backlog drained below PEND_RESUME
    hold_resumes,
    /// 20.27 held clients released after HOLD_SWEEPS (their largest backlogs shed with 0x49)
    hold_expired,
    /// 20.26 clients not read for an above-average share of an upload backlog over pend_cap
    pend_pauses,
    /// streams shed with 0x49 (RST): upload backlog over pend_cap for 2 sweeps (pend_sweep)
    shed_pend,
    /// streams shed with 0x49 (RST): a 0x49 hold that expired (hold_expired)
    shed_hold,
    /// streams shed with 0x49 (RST): unsent upload backlog over 1 MiB on entering level 3
    shed_l3_enter,
    /// streams closed with 0x49: a client sent more than its credit and passed the stage's pend_over cap
    shed_over_credit,
    /// clients reset (RST): a big partial frame or a stalled upload at level 2+ (shed_holders)
    shed_holder,
    /// clients reset (RST): level 3 without progress (l3_sweep) or a wsproxy backlog over pend_cap
    shed_client,
    /// 70.02 clients reset as dead peers (no ACK for 150 s with output queued)
    dead_peers,
    /// HTTP upgrade handshakes expired (HS_SWEEPS)
    hs_expired,
    /// TLS handshakes expired (TLS_HANDSHAKE_TIMEOUT)
    tls_expired,
    /// 20.26 sockets capped (SO_RCVBUF/SO_SNDBUF; at a level change, accept, connect or lazily)
    cap_apply,
    /// 20.26 sockets given back their saved sizes (level 0 again)
    cap_restore,
    /// 70.25 pool allocations served by a dirty (warm) block (published at each idle sweep; the name is from the
    /// 70.11 block cache it replaced)
    cache_hit,
    /// 70.25 pool allocations from a clean or fresh block (published at each idle sweep)
    cache_miss,
    /// 70.25 pool allocations that went to glibc because no chunk could be mapped (ENOMEM: RLIMIT_AS, map limit) or the
    /// chunk budget refused one (also counted in pool_capped)
    pool_fallback,
    /// 70.25 pool blocks freed by another thread (drained by the owner; Inbox.fds)
    pool_remote,
    /// 70.25 madvise(MADV_DONTNEED) calls that released dirty blocks
    pool_madvise,
    /// 70.25 empty chunks unmapped
    pool_munmap,
    /// 70.25 failed madvise / munmap calls (the blocks stay dirty / the chunk stays mapped; retried after the next sweep)
    pool_madvise_fail,
    /// 70.25 failed munmap calls (the chunk stays mapped; retried after the next sweep)
    pool_munmap_fail,
    /// 70.25 new chunks refused by the process-wide chunk budget (pool::limits: max_map_count / RLIMIT_AS); glibc served
    pool_capped,
    /// 70.25 gauge: pool chunks mapped (4 MiB each), at the last idle sweep
    pool_chunks,
    /// 70.25 gauge: dirty (resident, reusable) pool KiB, at the last idle sweep
    pool_dirty_kib,
    /// 50.02 kTLS clients whose send was refused with nothing in flight (host TCP memory pressure: tcp_mem[2], or above
    /// tcp_mem[1] for a socket above the average share) and still was at the first timer retry: episodes
    ktls_starve,
    /// 50.02 such episodes that ended (the send moved again, the output drained, or the client closed)
    ktls_starve_end,
    /// 50.02 bytes read from the targets of starved clients past their cap (bounded: STARVE_CAP per connection over it)
    ktls_starve_read,
    /// 50.02 episodes given B room (the bounded read; counted once per episode, from the second timer retry)
    ktls_starve_slices,
    /// 50.02 gauge (max, not summed): the longest episode so far, ms
    ktls_starve_ms_max,
    /// 50.02 gauge (max, not summed): the most bytes one connection read past the cap over its life
    ktls_starve_conn_max,
    /// gauge: live streams (targets), set when one is created or closed and at each idle sweep
    streams,
    // 60.20 rule: new counters go last, from here on (a new field here moves no hot offset; a plain comment: the doc
    // lines are the Prometheus HELP text, 60.29)
    /// 60.20 C1 CONNECTs refused by the destination policy (0x48; wsproxy: 403): the request rules, UDP with --no-udp,
    /// or every resolved address refused by the address rules
    refuse_policy,
    /// 60.20 C3b connections refused by --max-conns-per-ip (direct peers: RST at accept; behind a trusted proxy: 429)
    refuse_ip_conns,
    /// 60.20 C3b CONNECTs refused by --stream-rate-per-ip (0x49; wsproxy: 429)
    refuse_ip_rate,
    /// 60.20 C2 a trusted proxy sent an unparsable or ambiguous client-IP header (the last trusted hop is the client)
    realip_bad,
    /// 60.20 C2 a trusted proxy sent no client-IP header (the peer is the client; not charged per IP)
    realip_missing,
    /// 60.20 C3b clients not tracked per IP: their key's table shard was full (Q11: fail open, --max-conns stays)
    ip_untracked,
    /// 60.20 C3b gauge (max, not summed): keys in the per-IP table, at the last idle sweep
    ip_keys_max,
    /// 60.24 --log-conns lines dropped because the worker's log outbox was full (a slow or stalled stderr)
    log_dropped,
    /// 60.30 C10a streams closed (0x03) because the kernel refused the --upload-rate-per-stream options on the target
    pace_fail,
    /// 60.31 C7 connections accepted on the --listen-unix socket (also counted in accepted)
    accepted_unix,
    /// 60.31 C7 TCP connections reset at accept because their peer address was the unix sentinel 100:: (with --listen-unix)
    refuse_sentinel,
    /// 60.27 C6 proxied opens that completed the proxy handshake
    upstream_ok,
    /// 60.27 C6 the proxy failed: unreachable, closed or broken handshake, auth or a refusal not about the target, deadline
    upstream_fail,
    /// 60.25 C5 bytes read from client sockets (upload direction, WebSocket framing included, TLS handshake not;
    /// published at each idle sweep and client close)
    rx_bytes,
    /// 60.25 C10b times a client was paused by --upload-rate / --upload-rate-per-ip (not read until its allowance is back)
    upl_pauses,
    /// 60.25 C10b of those, pauses because the client key's --upload-rate-per-ip bucket or queue had nothing for it
    upl_ip_waits,
    /// 60.34 PROXY protocol headers accepted (the connection went on to TLS / HTTP; a per-IP refusal after the header
    /// counts in refuse_ip_conns instead)
    pp_ok,
    /// 60.34 of those, headers without a client address (LOCAL health checks, UNSPEC, UNKNOWN, AF_UNIX): the real peer
    pp_local,
    /// 60.34 connections reset: not a valid PROXY header (also one over 4096 bytes)
    pp_bad,
    /// 60.34 connections reset: no complete PROXY header within 4-6 s
    pp_timeout,
    /// 60.34 connections reset at accept: a TCP peer of a PROXY listener not in --proxy-protocol-from
    pp_refused,
}

impl Stats {
    /// 70.25 publish one pool sweep (pool::sweep)
    pub fn pool_sweep(&self, s: crate::pool::Sweep) {
        self.cache_hit.add(s.hits);
        self.cache_miss.add(s.misses);
        self.pool_fallback.add(s.fallback);
        self.pool_remote.add(s.remote);
        self.pool_madvise.add(s.madvise);
        self.pool_munmap.add(s.munmaps);
        self.pool_madvise_fail.add(s.madvise_fail);
        self.pool_munmap_fail.add(s.munmap_fail);
        self.pool_capped.add(s.capped);
        self.pool_chunks.set(s.chunks);
        self.pool_dirty_kib.set(s.dirty >> 10);
    }
}

impl Default for Stats {
    fn default() -> Self {
        Stats::new()
    }
}

static EPOCH: OnceLock<Instant> = OnceLock::new();

/// 60.20 C3a the --max-conns reservation, for the line (main sets it once when --max-conns is on)
pub static GATE: OnceLock<Arc<crate::net::ConnGate>> = OnceLock::new();

/// 60.32 C6 the proxy's addresses, for the refresh health in the line (upstream::start_refresh sets it: a proxy by name)
pub static UPSTREAM_DNS: OnceLock<Arc<crate::upstream::ProxyAddrs>> = OnceLock::new();

/// Milliseconds since the first call (main calls it at startup).
pub fn now_ms() -> u64 {
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// One logfmt line: `finalwisp: ev=<ev> up=<s> ...`. Counters summed over the workers, the memory level and
/// time at each level from the sampler (mem::LEVEL_*), open connections from the inboxes. deliberate: read
/// without a snapshot (counters move while summed; each value is exact, the set is not a single instant).
pub fn line(ev: &str, stats: &[Arc<Stats>], peers: &[Arc<Inbox>]) -> String {
    let now = now_ms();
    let mut s = format!("finalwisp: ev={ev} up={}", now / 1000);
    let level = crate::mem::LEVEL.load(Relaxed) as usize;
    let conns: usize = peers.iter().map(|p| p.load.load(Relaxed)).sum();
    s += &format!(" level={level}");
    if crate::mem::WORKER_BUDGET.load(Relaxed) > 0 {
        // (review: only with a budget, i.e. a sampler that measures it; else it would read 0)
        s += &format!(" used_mib={}", crate::mem::USED.load(Relaxed) >> 20);
    }
    s += &format!(" conns={conns}");
    if let Some(g) = GATE.get() {
        s += &format!(" conns_reserved={} conns_max={}", g.used(), g.max); // 60.20 C3a (exact, unlike conns)
    }
    if crate::mem::TCP_ON.load(Relaxed) {
        // 20.31 B3: TCP level, host TCP pages, our share (per mille; na = not read yet, unknown = read failed), entries and seconds at TCP level 1
        let own = crate::mem::TCP_OWN_PM.load(Relaxed);
        let (enters, ms) = crate::mem::tcp_times(now);
        s += &format!(
            " tcp_level={} tcp_pages={} tcp_moved={} tcp_own_pm={} tcp_enters={enters} t_tcp1={}",
            crate::mem::TCP_LEVEL.load(Relaxed),
            crate::mem::TCP_PAGES.load(Relaxed),
            crate::mem::TCP_MOVED.load(Relaxed), // 20.31 (iii) pages moved into our heap this episode
            match own {
                u64::MAX => "na".to_string(), // not read yet (only near the threshold)
                o if o == u64::MAX - 1 => "unknown".to_string(),
                o => o.to_string(),
            },
            ms / 1000
        );
    }
    if let Some((n, ms)) = kernel_tcp_pressure() {
        s += &format!(" host_tcp_pressures={n} host_tcp_pressure_ms={ms}"); // since boot (TcpExt), this netns
    }
    let (changes, times) = crate::mem::level_times(now);
    s += &format!(" level_changes={changes}");
    for (l, t) in times.iter().enumerate() {
        s += &format!(" t_l{l}={}", t / 1000);
    }
    let (sum, close) = sum(stats);
    for (k, v) in sum {
        s += &format!(" {k}={v}");
    }
    // 60.12 ops: client KeyUpdates that closed a connection (kernel < 6.14, tls.rs)
    s += &format!(" keyupdate_closes={}", crate::tls::KEYUPDATE_CLOSES.load(Relaxed));
    // 70.25 longest turn-end release (process max, elapsed); 60.16 its thread CPU time (process max)
    s += &format!(" pool_release_max_us={}", crate::pool::RELEASE_MAX_US.load(Relaxed));
    s += &format!(" pool_release_cpu_max_us={}", crate::pool::RELEASE_CPU_MAX_US.load(Relaxed));
    if let Some(a) = UPSTREAM_DNS.get() {
        // 60.32 C6 the upstream-dns thread: failed refreshes (the old list stayed), seconds since the last good answer
        s += &format!(" upstream_dns_fail={} upstream_dns_age_s={}", a.fails.load(Relaxed), a.age_ms(now) / 1000);
    }
    #[cfg(feature = "pooltest")]
    {
        s += &crate::mem::pt::line();
    }
    for (r, n) in close.iter().enumerate().filter(|(_, n)| **n > 0) {
        s += &format!(" close_{r:02x}={n}");
    }
    s
}

/// 60.12 the named counters summed over the workers (a `_max` gauge by max, every other one by sum) and the CLOSE
/// counts by reason. The one merge rule for line() and the 60.29 Prometheus page (prom::render).
pub(crate) fn sum(stats: &[Arc<Stats>]) -> (Vec<(&'static str, u64)>, [u64; 256]) {
    let mut sum: Vec<(&'static str, u64)> = Vec::new();
    let mut close = [0u64; 256];
    for st in stats {
        for (i, (k, v)) in st.named().into_iter().enumerate() {
            match sum.get_mut(i) {
                Some(e) if k.ends_with("_max") => e.1 = e.1.max(v), // 50.02 max gauges
                Some(e) => e.1 += v,
                None => sum.push((k, v)),
            }
        }
        for (r, c) in st.close.iter().enumerate() {
            close[r] += c.get();
        }
    }
    (sum, close)
}

/// 20.31 TcpExt TCPMemoryPressures / TCPMemoryPressuresChrono (times the kernel entered TCP memory pressure, ms in it;
/// since boot, this network namespace). Read by the metrics thread and the final line.
pub(crate) fn kernel_tcp_pressure() -> Option<(u64, u64)> {
    let t = std::fs::read_to_string("/proc/net/netstat").ok()?;
    let mut l = t.lines().filter(|l| l.starts_with("TcpExt:"));
    let (k, v) = (l.next()?, l.next()?);
    let d: std::collections::HashMap<&str, &str> = k.split_whitespace().zip(v.split_whitespace()).collect();
    Some((d.get("TCPMemoryPressures")?.parse().ok()?, d.get("TCPMemoryPressuresChrono")?.parse().ok()?))
}

/// 50.02 / 70.05 a log line from a thread that must never block on stderr (today tls::key_update_refused, called on a
/// worker thread): queued (at most LOG_QUEUE lines) to a logger thread started on first use. A full queue drops the line,
/// and a later line that fits says how many were dropped (60.16; as mem::Log). A failed write is dropped (60.05 H3: no
/// panic on a dead pipe). If the logger thread cannot be started (EAGAIN / ENOMEM), the line is dropped (counted) and
/// the next call tries again. 60.24: warn level.
pub fn log_nowait(line: String) {
    if !crate::logs::on(crate::logs::Level::Warn) {
        return; // 60.24 both callers' lines are warnings
    }
    const LOG_QUEUE: usize = 8; // deliberate: the callers are rate-limited (one line per minute or per starve episode)
    static TX: OnceLock<std::sync::mpsc::SyncSender<String>> = OnceLock::new();
    static DROPPED: AtomicU64 = AtomicU64::new(0);
    let tx = match TX.get() {
        Some(tx) => tx,
        None => {
            let (tx, rx) = std::sync::mpsc::sync_channel::<String>(LOG_QUEUE);
            let spawned = std::thread::Builder::new().name("log".into()).spawn(move || {
                for l in rx {
                    let _ = std::io::stderr().write_all((l + "\n").as_bytes()); // one write per line (see start)
                }
            });
            if spawned.is_err() {
                DROPPED.fetch_add(1, Relaxed);
                return;
            }
            // a racing first caller may have won: then this sender drops here and its logger thread ends
            TX.get_or_init(|| tx)
        }
    };
    let n = DROPPED.swap(0, Relaxed);
    if tx.try_send(with_dropped(line, n)).is_err() {
        DROPPED.fetch_add(n + 1, Relaxed);
    }
}

fn with_dropped(line: String, n: u64) -> String {
    if n == 0 {
        line
    } else {
        format!("{line} ({n} earlier log lines dropped)")
    }
}

/// 60.12 --metrics-interval: a thread that logs `line("metrics")` every `every`. A blocked stderr stalls only
/// this thread (the workers never wait on it); a failed write is dropped (60.05 H3: no panic on a dead pipe).
pub fn start(every: Duration, stats: Arc<Vec<Arc<Stats>>>, peers: Arc<Vec<Arc<Inbox>>>) {
    std::thread::Builder::new()
        .name("metrics".into())
        .spawn(move || loop {
            std::thread::sleep(every);
            // one write_all of the whole line (writeln! writes the line and its newline separately: a final line written
            // meanwhile by main's log_bounded could land between them)
            let _ = std::io::stderr().write_all((line("metrics", &stats, &peers) + "\n").as_bytes());
        })
        .expect("spawn metrics");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_lines_are_reported_on_the_next_line() {
        assert_eq!(with_dropped("a".into(), 0), "a");
        assert_eq!(with_dropped("a".into(), 3), "a (3 earlier log lines dropped)");
        log_nowait("finalwisp: test line from metrics::tests (ignore)".into()); // starts the logger; must not block
    }

    #[test]
    fn line_sums_workers_and_lists_sent_close_reasons() {
        let a = Arc::new(Stats::new());
        let b = Arc::new(Stats::new());
        a.accepted.bump();
        b.accepted.add(2);
        a.close[0x49].bump();
        b.close[0x49].bump();
        b.close[0x02].add(5);
        b.streams.set(7);
        let peers = vec![Inbox::new()];
        let l = line("metrics", &[a, b], &peers);
        assert!(l.starts_with("finalwisp: ev=metrics up="), "{l}");
        for want in [" accepted=3 ", " streams=7", " close_02=5", " close_49=2", " conns=0 ", " t_l0=", " level_changes="] {
            assert!(l.contains(want), "{want} missing: {l}");
        }
        assert!(!l.contains("close_41"), "{l}");
        // every value is key=value (logfmt, no spaces inside values)
        assert!(l.split(' ').skip(1).all(|kv| kv.split_once('=').is_some_and(|(k, v)| !k.is_empty() && !v.is_empty())), "{l}");
    }
}
