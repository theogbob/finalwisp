//! 20.05 Per-core event loop. Shared-nothing: one listener, one epoll, one slab set per thread.
//! Every fd is registered once, edge-triggered (clients: IN | OUT | RDHUP; TCP targets: the same + PRI for
//! urgent data; UDP targets, the listener and the DNS eventfd: IN only); readiness is tracked in flags,
//! so there are no epoll_ctl calls on the hot path.
use crate::clientip;
use crate::credit;
use crate::ext;
use crate::http;
use crate::mem;
use crate::metrics;
use crate::net::{self, DnsReq, Filter, Inbox};
use crate::policy;
use crate::tls;
use crate::ws::{self, OP_BIN, OP_CLOSE, OP_CONT, OP_PING, OP_PONG, OP_TEXT};
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

// 60.16 #10 split by concern (pure move; worker.rs at base-4-rc1 had all of it): the event loop, the Worker state and
// the tuning constants stay here; each module below adds `impl Worker` methods (and its own types) for one concern.
mod client;
mod conn;
mod connect;
mod connlog;
mod input;
mod ktls;
mod levels;
mod meter;
mod proxy;
mod streamlog;
mod sweep;
mod target;
mod udp;
mod upgrade;
mod upload;
mod upstream;
mod wisp;

use client::{CState, Client, TlsHs};
use connlog::Why;
use ktls::{client_hello, starve_delay, starve_step, Starve};
#[cfg(test)]
use ktls::{ku_after_peer_update, starve_room};
use levels::{free_drained, pend_keep};
use streamlog::SWhy;
pub use target::LAZY_CAP;
use target::{tcp_only_local, TState, Target, LOCAL_UNIX, NOT_LISTED};
#[cfg(any(test, fuzzing))]
use upgrade::percent_decode;
use upload::{next_allow, UpBucket};
#[cfg(test)]
use upload::{refill_due, scaled_bytes};
use wisp::{
    CLOSE_BLOCKED, CLOSE_NETWORK, CLOSE_THROTTLED, CLOSE_TIMEOUT, CLOSE_UNREACHABLE, CLOSE_VOLUNTARY, PKT_CLOSE, PKT_CONTINUE, PKT_DATA,
    PKT_INFO,
};

pub struct Config {
    pub addr: SocketAddr,
    pub threads: usize,
    pub buffer: u32,
    pub filter: Filter,
    pub connect_timeout: Duration,
    /// 70.09 the DNS pool uses the own resolver (dns.rs): closing a Resolving target cancels its lookup
    pub dns_own: bool,
    pub abort_close: bool,
    pub splice: bool,
    pub balance: bool,
    pub tfo: bool,
    /// 20.13 built-in TLS (kTLS after the handshake); None = plain ws://
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// 20.16 UDP streams (CONNECT type 0x02; v2 INFO advertises extension 0x01). false = --no-udp
    pub udp: bool,
    /// 20.17 records per direction after which the server sends a TLS 1.3 KeyUpdate (0 = never)
    pub tls_rekey: u64,
    /// 20.19 TCP_NOTSENT_LOWAT on client sockets, bytes (0 = kernel default). Caps the *unsent*
    /// part of the kernel send queue per WebSocket, so a bulk stream cannot park megabytes in the
    /// socket ahead of the other streams' frames: on a 100 Mbit / 20 ms link a small response behind
    /// one bulk download took 610 ms with the default and 222 ms with 128 KiB; single-stream
    /// throughput is unchanged (bytes in flight are not limited, only bytes not yet sent).
    pub notsent_lowat: u32,
    /// 20.21 / 60.30 the lowat the adaptive lowat restores (= notsent_lowat); 0 = no adaptive lowat (worker::adapt_lowat)
    pub adapt_lowat: u32,
    /// 70.02 dead-peer detection on client sockets (default on, `--no-keepalive` = off): TCP keepalive
    /// (net::KEEP_*; idle peers) and net::peer_gone at the idle sweep (peers with output queued).
    pub keepalive: bool,
    /// 20.19 two-lane client output (20.22 default on, `--no-prio` = off): DATA frames of streams in bulk mode
    /// (last read filled CHUNK) go to a second buffer that is written only after everything else
    /// (CONTINUE, CLOSE, small responses), so a big download on the connection does not delay the
    /// other streams by the whole obuf backlog. On a 100 Mbit / 20 ms link with --notsent-lowat:
    /// small response behind one bulk download 222 -> 168 ms; neutral on loopback.
    pub prio: bool,
    /// 20.18 Wisp v2 extensions (INFO records, auth); Ext::default() = none
    pub ext: ext::Ext,
    /// 20.30 upload credit v2 (default on since 60.13; `--no-credit-v2` = off): a WS ping after CONTINUEs retires overwritten credit;
    /// level-0 grants are top-ups against an autotuned per-stream window (credit.rs). Off: base-2 unchanged.
    pub credit_v2: bool,
    /// 60.20 C3a `--max-conns` (None = off): the process-wide reservation, taken in accept_all, released in unload
    pub conn_gate: Option<Arc<net::ConnGate>>,
    /// 60.20 C3a `--max-streams-per-conn` (0 = off): open streams per Wisp connection (c.streams) before CONNECT gets 0x49
    pub max_streams_per_conn: u32,
    /// 60.20 C1 request rules (None = none set): checked in on_connect / the wsproxy upgrade before DNS (0x48 / 403)
    pub policy: Option<Box<crate::policy::Policy>>,
    /// 60.20 C2 / C3b (None = all off): trusted proxies + header, the per-IP table and limits
    pub clientip: Option<Box<clientip::ClientIp>>,
    /// 60.24 --log-conns: a line per connection (worker/connlog.rs; off = the side vector stays empty)
    pub log_conns: bool,
    /// 60.35 --log-streams: a line per stream and per refused CONNECT (worker/streamlog.rs; off = its side vector stays
    /// empty; the connlog entries are kept for the cid even without --log-conns)
    pub log_streams: bool,
    /// 60.24 accept4 asks for the peer address and adopt keeps it (peers_of): C2/C3b or --log-conns
    pub want_peer: bool,
    /// 60.30 C10a bandwidth caps (0 = off): download on the listener (inherited by accepted sockets), upload per TCP
    /// target in `won` (SO_MAX_PACING_RATE + TCP_NOTSENT_LOWAT)
    pub pace: net::Pacing,
    /// 60.31 C7 --listen-unix: the shared unix listener (None = off: no fd, no epoll entry)
    pub unix: Option<Arc<net::UnixListen>>,
    /// 60.27 C6 --upstream (None = direct egress)
    pub upstream: Option<Box<crate::upstream::Upstream>>,
    /// 60.25 C10b --upload-rate (bytes/s, burst bytes) per connection; None = off
    pub upload_rate: Option<(u64, u64)>,
    /// 60.34 --proxy-protocol tcp / unix: every connection on that listener starts with a PROXY v1/v2 header (proxy.rs);
    /// --proxy-protocol-from: the TCP peers that may send it (others are reset at accept; unix peers always may)
    pub proxy_tcp: bool,
    pub proxy_unix: bool,
    pub proxy_from: Box<[policy::Cidr]>,
}

// ---- tuning (deliberate constants; benchmark before changing)
// 20.26: RBUF (256 KiB), OUT_HIGH (1 MiB), OUT_LOW (256 KiB), OUT_HARD (8 MiB) are now the level-0 values of
// mem::STAGES (Worker::st), smaller under memory pressure. oh256 (20.06): so are OUT_HIGH_BULK (256 KiB) and
// OUT_LOW_BULK (64 KiB), the --prio bulk-lane cap (Stage::out_high_bulk; read_target).
const RBUF_MIN: usize = 16 * 1024; // 20.11: first size after the upgrade; doubles toward RBUF only under load
const TLS_RECORD_BUDGET: u64 = 1 << 24; // 20.13: below the AES-GCM limit of 2^24.5 records per key (RFC 8446 5.5)
const IDLE_SWEEP_MS: u64 = 2000; // 20.11: free the buffers of clients idle for a whole sweep period
const PIPE_RETRY: Duration = Duration::from_secs(1); // 30.09 after a refused 256 KiB pipe, copy path only for this long
const MAX_FRAME: usize = 16 * 1024 * 1024; // largest accepted WS frame
pub(crate) const CHUNK: usize = 65530; // max target read => WS payload <= 65535 => 4-byte WS header
const ROOM_WISP: usize = 9; // 4 (WS) + 5 (Wisp) header reserved in front of each read
const ROOM_RAW: usize = 4; // wsproxy: WS header only
/// 70.02 the largest in-progress frame Client::frame_held never holds: 64 KiB of WS payload plus the WS
/// header (<= 14 bytes) and slack. Measured: at L2/L3 (rbuf_max 16 KiB) wbench's 16 KiB DATA frames
/// (16397 bytes) and wisp-js-sized 64 KiB frames were held and then reset by shed_partial (all 6
/// honest uploaders of one run). Big-frame attackers (10 MiB frames) stay above it.
const HOLD_FLOOR: usize = 64 * 1024 + 64;
/// 70.02 sweeps (IDLE_SWEEP_MS each) without new bytes for an in-progress frame above rbuf_max before
/// shed_partial sheds its client at level 2+ (Worker::count_stalls)
const STALL_SWEEPS: u8 = 2;
/// 70.08 less than this many bytes from the client in a sweep is a stall (count_stalls). With "any byte",
/// a client dripping 1 byte per sweep held an ~80 KiB partial frame at level 2 forever (~1500-2300 such
/// connections kept admission off at ~1 KB/s in total). 4 KiB per 2 s sweep = 16 kbit/s: holding memory
/// now costs the holder upload bandwidth (80 KiB held per 2 KiB/s). An honest uploader only meets this
/// rule at level 2+ and only inside a frame above rbuf_max (16 KiB there): one slower than 16 kbit/s for
/// two whole sweeps in such a frame is shed (its streams reset; it can reconnect after the pressure).
const STALL_MIN_BYTES: u64 = 4096;
const NO_RX: u64 = u64::MAX;

// 60.04 F6: read_target writes a 2- or 4-byte WS header in front of each read; the 16-bit length must fit.
const _: () = assert!(CHUNK + ROOM_WISP - 4 <= u16::MAX as usize);
const PEND_LOW: usize = 256 * 1024; // grant credit only when target backlog is below this
const PEND_SHED_SWEEPS: u32 = 2; // 20.26 idle sweeps (2 s each) over pend_cap before the largest backlogs are shed
const L3_STUCK_SWEEPS: u32 = 2; // 20.26 idle sweeps at level 3 without progress before clients are closed
const PEND_HARD: usize = 64 * 1024 * 1024; // misbehaving client cap per stream (20.26: Stage::pend_over for over-credit clients)
/// 20.27 0x49 hold: an in-credit stream over PEND_HARD stops its client's reads (Client::hpaused) instead of CLOSE 0x49; reads
/// resume once every stream of the client is at or below PEND_RESUME (Worker::pend_account)
const PEND_RESUME: usize = PEND_HARD / 4 * 3; // 48 MiB (parent): to resume within the hold a target drains 16 MiB in 4-6 s (~2.7-4 MiB/s; at /2: 5-8)
/// 20.27 0x49 hold: the hold lasts at most this many idle sweeps (2 s each: 4-6 s; the whole connection is not read meanwhile)
const HOLD_SWEEPS: u32 = 3;
const BUDGET: usize = 8; // reads per readiness turn (fairness)
const OBUF_COMPACT: usize = 1024 * 1024; // compact the sent prefix of a partially flushed obuf beyond this
const DNS_INFLIGHT_MAX: usize = 1024; // per worker; excess CONNECTs get CLOSE 0x49
const DNS_TTL: Duration = Duration::from_secs(30); // positive cache entries
const MAX_HOST: usize = 255; // review 20.23: longest DNS name (253 chars + a trailing dot, with slack)
const DNS_NEG_TTL: Duration = Duration::from_secs(5); // 20.23 names with no address (empty entry): CLOSE 0x42 at once
const TIMER_TICK_MS: i32 = 100; // connect-timeout scan granularity
/// 50.02 kTLS send starved by host TCP memory (Worker::starve_check): retry after STARVE_RETRY_MS, doubling up to
/// TIMER_TICK_MS (the kernel's own retry for a blocking sender is a random 2-200 ms sleep, sk_stream_wait_memory vm_wait).
const STARVE_RETRY_MS: u64 = 2;
/// 50.02 B (fallback, Worker::starve_check): each retry lets every blocked stream of a starved client read this much past
/// its cap (one TLS record) ...
const STARVE_SLICE: usize = 16 * 1024;
/// ... up to this much pending output over out_high per connection (also for bulk-lane streams: see starve_check)
const STARVE_CAP: usize = 256 * 1024;
/// 50.02 A2: SOCK_MIN_SNDBUF (2 * (2048 + SKB_TRUESIZE(0)) = 4608 on x86-64): the moderated sndbuf of a starved
/// socket, so the request size a forced send charge needs with an empty queue. Not for a socket whose SO_SNDBUF we set
/// (net::cap_bufs/uncap_bufs: SOCK_SNDBUF_LOCK, the kernel does not moderate it): B covers those (starve_check).
const STARVE_MIN_SEND: usize = 4608;
/// 50.02 at most one starve log line per worker per this
const STARVE_LOG_EVERY: Duration = Duration::from_secs(10);
const HE_DELAY: Duration = Duration::from_millis(250); // 20.14 RFC 8305 connection attempt delay (+ up to one tick)
const HE_MEMORY: Duration = Duration::from_secs(300); // 20.24 how long a first address that lost to the other family stays demoted
const HE_PARALLEL: usize = 4; // 20.14 most attempts in flight per target (blackholed names cost fds until the deadline)
const SPLICE_PIPE: usize = 256 * 1024; // per-client pipe for the splice download path
const MIN_SPLICE_PIPE: usize = 64 * 1024; // review r1: the default pipe size; smaller (over quota) = copy path

// 20.21 adaptive lowat for kTLS (b1): --notsent-lowat costs kTLS clients ~7-11% of bulk throughput when the
// server is CPU-bound (more, smaller packets: one TLS record per TCP push), and buys nothing where the queue
// drains in microseconds. Every connection starts with lowat; every RATE_CHECK_BYTES sent, a kTLS client's
// TCP_INFO delivery rate decides: >= LOWAT_FAST (a lower bound even when app-limited) lifts the cap, a real
// (not app-limited) sample < LOWAT_SLOW puts it back.
const RATE_CHECK_BYTES: u64 = 4 << 20;
const LOWAT_FAST: u64 = 1 << 30; // bytes/s
const LOWAT_SLOW: u64 = 256 << 20; // bytes/s
/// 20.21 Config::adapt_lowat: the client lowat, or 0 (no adaptive lowat) under a download cap below LOWAT_FAST (60.30
/// C10a, review: a delivery-rate sample excludes pacing gaps, could pass LOWAT_FAST and lift the paced lowat)
pub fn adapt_lowat(lowat: u32, download_cap: u32) -> u32 {
    if download_cap == 0 || download_cap as u64 >= LOWAT_FAST {
        lowat
    } else {
        0
    }
}
const KTLS_LINGER: Duration = Duration::from_secs(10); // review r1: longest wait for a closing kTLS socket to drain
/// review r1: a client still in Http/WaitInfo after 5 sweeps (8-10 s, active or not) is closed. 60.09 M4a: the first
/// client after an idle gap (epoll_wait(-1), sweep deadline passed) can get ~6-8 s once: the phase-keeping catch-up puts
/// the next sweep within one period. Kept: an upper (slowloris) bound; resetting from `now` would line workers up again.
const HS_SWEEPS: u8 = 5;
const SPLICE_MIN: usize = 16 * 1024; // splice read smaller than this => back to the copy path
const NO_MARK: usize = usize::MAX;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10); // 20.13: slow/stalled handshakes are closed
const TLS_RECORDS_PER_TURN: usize = 32; // 20.13: handshake records per readiness turn (fairness)
const UDP_MAX: usize = 65507; // 20.16 largest DATA payload sent as a datagram (IPv4 limit); larger ones are dropped
const UDP_BATCH: usize = 8; // 20.16 datagrams per recvmmsg (worker scratch = UDP_BATCH x UDP_SLOT)
const UDP_SLOT: usize = CHUNK; // 65530 >= largest UDP payload (IPv6: 65527), so nothing is truncated
const UDP_PEND_MAX: usize = 256 * 1024; // 20.16 datagrams queued while resolving; beyond this they are dropped

const K_LISTEN: u64 = 0;
const K_CLIENT: u64 = 1;
const K_TARGET: u64 = 2;
const K_DNS: u64 = 3;

#[inline(always)]
fn tok(kind: u64, idx: u32, gen: u32) -> u64 {
    (kind << 62) | (((gen as u64) & 0x3fff_ffff) << 32) | idx as u64
}
#[inline(always)]
fn untok(t: u64) -> (u64, u32, u32) {
    (t >> 62, t as u32, ((t >> 32) & 0x3fff_ffff) as u32)
}

// ---- tiny slab with generations
/// 20.06 idle RSS: the slot array starts at >= 128 KiB, glibc's initial mmap threshold, so it is
/// its own mapping (Worker::new runs in main before the first idle sweep can free a >= 128 KiB
/// buffer, which would raise the dynamic threshold) and grows by mremap (mem::Counting forwards
/// realloc to libc), never inside a malloc arena. Grown by push during a burst, it landed at the top
/// of the worker's arena above the freed burst buffers and pinned them: 2000 idle clients after a
/// 64 KiB echo held 110 KiB each instead of 15 (20.26 made a target slot 192 -> 232 bytes; a 256-slot
/// array of 49 KiB still fitted a freed 16K+32K rbuf hole, 58 KiB did not). Any per-worker Vec that
/// grows during a burst can pin the same way. Unused capacity is never touched, so it costs no RSS,
/// but it counts in mem::heap_bytes (host mode subtracts the unused part: mem::SLAB_UNTOUCHED).
/// 60.05 H7: glibc's mmap threshold is pinned (mem::MMAP_THRESHOLD; main). 70.03: 1 MiB, no longer tied
/// to it: at or above the threshold the array is its own mapping either way.
const SLAB_RESERVE: usize = 1 << 20;
const _: () = assert!(SLAB_RESERVE >= mem::MMAP_THRESHOLD);
struct Slab<T> {
    slots: Vec<(u32, Option<T>)>,
    free: Vec<u32>,
    untouched: usize, // 60.05 H7: this slab's share of mem::SLAB_UNTOUCHED
}
impl<T> Drop for Slab<T> {
    fn drop(&mut self) {
        mem::SLAB_UNTOUCHED.fetch_sub(self.untouched as isize, Relaxed); // (workers never drop; tests)
    }
}
impl<T> Slab<T> {
    fn new() -> Self {
        let n = SLAB_RESERVE.div_ceil(std::mem::size_of::<(u32, Option<T>)>());
        let untouched = n * std::mem::size_of::<(u32, Option<T>)>();
        mem::SLAB_UNTOUCHED.fetch_add(untouched as isize, Relaxed);
        Slab { slots: Vec::with_capacity(n), free: Vec::new(), untouched }
    }
    fn insert(&mut self, v: T) -> (u32, u32) {
        if let Some(i) = self.free.pop() {
            let s = &mut self.slots[i as usize];
            s.1 = Some(v);
            (i, s.0)
        } else {
            self.slots.push((0, Some(v)));
            if self.untouched > 0 {
                // 60.05 H7: a new slot (only on growth): its bytes are now real memory for the budget.
                // Past the reserve (grown by mremap) nothing is subtracted, as before.
                let size = std::mem::size_of::<(u32, Option<T>)>();
                mem::SLAB_UNTOUCHED.fetch_sub(size.min(self.untouched) as isize, Relaxed);
                self.untouched = self.untouched.saturating_sub(size);
            }
            ((self.slots.len() - 1) as u32, 0)
        }
    }
    #[inline]
    fn get(&mut self, i: u32, gen: u32) -> Option<&mut T> {
        match self.slots.get_mut(i as usize) {
            Some((g, Some(v))) if (*g & 0x3fff_ffff) == (gen & 0x3fff_ffff) => Some(v),
            _ => None,
        }
    }
    #[inline]
    fn at(&mut self, i: u32) -> &mut T {
        self.slots[i as usize].1.as_mut().unwrap()
    }
    fn gen(&self, i: u32) -> u32 {
        self.slots[i as usize].0
    }
    fn remove(&mut self, i: u32) -> Option<T> {
        let s = &mut self.slots[i as usize];
        let v = s.1.take();
        if v.is_some() {
            s.0 = s.0.wrapping_add(1);
            self.free.push(i);
        }
        v
    }
}

#[derive(Default)]
struct IdHasher(u64);
impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!()
    }
    fn write_u32(&mut self, n: u32) {
        self.0 = (n as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}
type StreamMap = HashMap<u32, u32, BuildHasherDefault<IdHasher>>;

pub struct Worker {
    cfg: Arc<Config>,
    ep: RawFd,
    lfd: RawFd,
    inbox: Arc<Inbox>,
    idx: usize,
    peers: Arc<Vec<Arc<Inbox>>>,
    dns_tx: mpsc::Sender<DnsReq>,
    clients: Slab<Client>,
    targets: Slab<Target>,
    dirty: Vec<(u32, u32)>, // 60.05 H1: (index, gen); a client can close and its slot be freed while listed
    ready: Vec<u64>,
    ready_spare: Vec<u64>,
    dead: Vec<u32>,
    // deliberate: in-flight connects in a swap_remove list scanned every TIMER_TICK_MS instead of
    // a heap (a heap kept ~1.2M stale entries at 119k streams/s; this list holds only live connects).
    connecting: Vec<(u32, u32)>,
    next_scan: Instant,
    next_sweep: Instant,
    /// 60.20 C3b the next per-IP table shard this worker sweeps (starts at idx * SWEEP_SHARDS, then consecutive)
    ip_sweep: usize,
    /// 60.20 C2/C3b per client slot: its peer and charged key (empty when C2/C3b are off; beside the slab so the
    /// Client slot stays 512 bytes, 60.22)
    peers_of: Vec<Option<clientip::Peer>>,
    /// 60.24 --log-conns per client slot (empty when off), the queue to the log thread, scratch, sequence, and the
    /// conn_refused window (second, lines in it)
    connlog: Vec<Option<connlog::ConnLog>>,
    outbox: Option<Arc<crate::logs::Outbox>>,
    logline: Vec<u8>,
    conn_seq: u64,
    refused_win: (u64, u32),
    /// 60.35 --log-streams per target slot (empty when off: Target unchanged) and the stream_refused window
    streamlog: Vec<Option<streamlog::StreamLog>>,
    sref_win: (u64, u32),
    sdone: Vec<streamlog::Closed>, // 60.35 closed this turn, lines written by reap_dead
    /// 60.27 C6 per target slot: the proxy handshake state (empty without --upstream; beside the slab: Target unchanged)
    proxy_hs: Vec<Option<Box<upstream::ProxyHs>>>,
    /// 60.27 C6 this worker's copy of the proxy's addresses (generation, list): Worker::proxy_list
    proxy_addrs: Option<(u64, Arc<Vec<IpAddr>>)>,
    pipe_retry_at: Instant,    // 30.09
    deferred: Vec<(u32, u32)>, // 20.15 connects to start at the end of the input batch
    accept_retry: bool,
    dns_inflight: usize,
    dns_cache: HashMap<String, (Vec<IpAddr>, Instant)>,
    he_lost: HashMap<IpAddr, Instant>, // 20.24 first addresses that lost a connect race to the other family
    // 20.09 / 20.33 upload batching: the DATA payloads of one client read batch are staged per target (pointers into
    // the client's rbuf), interleaved streams included, and each target gets one writev() per flush. Buckets in
    // first-touch order; `up_n` in use (the rest keep their capacity: no per-op heap). RULE: staged iovecs point into
    // ONE client's rbuf, which is not compacted, grown, re-read or freed while anything is staged: flush_upload runs
    // before process_input returns, before every non-DATA frame, and read_client asserts nothing is staged.
    up_bufs: Vec<UpBucket>,
    up_n: usize,
    up_total: usize, // iovecs staged in all buckets (UP_MAX)
    #[cfg(test)]
    up_writevs: usize, // 20.33 test: target writev calls made by flush_bucket
    // 20.13 handshake deadlines in accept order (constant timeout => FIFO is sorted). deliberate:
    // entries of finished handshakes stay until their deadline (bounded by accept rate x timeout).
    tls_deadlines: VecDeque<(u32, u32, Instant)>,
    // review r1: closing kTLS clients waiting to drain (client, gen, deadline); see Client::ktls_drained
    lingering: Vec<(u32, u32, Instant)>,
    next_linger: Instant,
    // 50.02 kTLS clients whose send is starved by host TCP memory (client, gen); see starve_check
    starved: Vec<(u32, u32)>,
    starve_log_at: Option<Instant>,
    udp_buf: Vec<u8>, // 20.16 recvmmsg scratch, allocated on first UDP read
    // 20.26 memory pressure level (mem::LEVEL, checked once per loop turn) and its limits
    lvl: usize,
    // 20.31 (b) the level the socket caps and (b2) the credit come from (mem::cap_level: 1 at memory level 0 with host TCP caps)
    capl: usize,
    st: mem::Stage,
    accept_paused: bool,
    stop_seen: u8,         // 60.12 the last Inbox::stop acted on
    stop_scan_at: Instant, // 60.12 next shutdown scan (inbox_ready)
    // 20.26 the budget's floor level is 0: socket caps are lifted again, so take the sizes to restore
    // (buf_sizes, 2 getsockopt per socket); with a floor >= 1 the caps stay and that is skipped
    floor0: bool,
    // 20.26 upload backlog (pend) of all targets of this worker, and the share of the memory budget
    // above which a client adding to it is not read until it drains (usize::MAX = no budget)
    pend_total: usize,
    pend_cap: usize,
    starve_pool: u64,    // 20.30 --credit-v2: window bytes the starvation rule may still hand out (credit::STARVE_POOL)
    pend_clients: usize, // 20.26 clients with Client::pend > 0
    pend_paused: Vec<(u32, u32)>, // 20.26 mpaused clients (index, gen), all resumed below 3/4 of pend_cap
    pend_over_sweeps: u32, // 20.26 idle sweeps in a row with pend_total over pend_cap
    l3_mark: u64,        // 20.26 lowest mem::USED seen at level 3 (no-progress escape)
    l3_sweeps: u32,      // 20.26 sweeps at level 3 without a new low
    max_streams: usize,  // 20.26 mem::max_streams for the current stage
    rbuf_max: usize,     // 20.26 r4 mem::rbuf_max for the current stage (level 1: scaled by the worker budget)
    win: u64,            // 20.26 r4 mem::grant_window of the cap level (20.31 b2; 0 at level 0: grant in packets only)
    bulk_at: usize,      // r5 mem::bulk_at for the current stage: a target read this large marks the stream bulk
    stats: Arc<metrics::Stats>, // 60.12 event counters (control points only; metrics.rs)
    ufd: RawFd,          // 60.31 C7 the shared unix listener in our epoll set (-1 = off or let go in shutdown_step)
    rx_total: u64,       // 60.25 C5 bytes read from client sockets since start (Stats::rx_bytes at each sweep)
    /// 60.25 C10b an upload limit is on (--upload-rate or --upload-rate-per-ip): read_client meters every read
    meter: bool,
    meters: Vec<meter::Meter>,               // 60.25 C10b per client slot (empty when `meter` is false)
    lwait: Vec<(u32, u32, u64)>,             // 60.25 C10b lpaused clients (index, gen, resume at now_ms64)
    lscan: u64,                              // 60.25 C10b next lwait scan (now_ms64)
    pending: HashMap<RawFd, proxy::Pending>, // 60.34 connections waiting for their PROXY header (empty when off)
}

#[must_use]
fn ep_add(ep: RawFd, fd: RawFd, token: u64, events: u32) -> bool {
    let mut ev = libc::epoll_event { events, u64: token };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) == 0 }
}
const EV_ALL: u32 = (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLRDHUP | libc::EPOLLET) as u32;
const EV_TARGET: u32 = EV_ALL | libc::EPOLLPRI as u32; // 20.25 PRI = TCP urgent data (see Target::urg)

#[inline]
fn would_block(e: i32) -> bool {
    e == libc::EAGAIN || e == libc::EWOULDBLOCK
}

impl Worker {
    pub fn new(
        cfg: Arc<Config>,
        dns_tx: mpsc::Sender<DnsReq>,
        idx: usize,
        peers: Arc<Vec<Arc<Inbox>>>,
        stats: Arc<metrics::Stats>,
    ) -> std::io::Result<Worker> {
        let lfd = net::listen(&cfg.addr, cfg.keepalive, cfg.pace.download)?;
        // 60.24 want_peer is derived in main; a config that logs or limits per IP without it would log ip=- (review)
        // (60.31 C7 --listen-unix alone: a ClientIp holding only the unix sentinel, which needs no sockaddr)
        let unix_only = |c: &clientip::ClientIp| cfg.unix.is_some() && c.table.is_none() && c.trusted.len() == 1;
        assert!(
            cfg.want_peer || (cfg.clientip.as_deref().is_none_or(unix_only) && !cfg.log_conns && !cfg.log_streams),
            "Config::want_peer"
        );
        // 60.24 the log thread picks the outbox up at its next tick
        let outbox = (cfg.log_conns || cfg.log_streams).then(|| {
            let o = Arc::new(crate::logs::Outbox::default());
            crate::logs::register(o.clone());
            o
        });
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if ep < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let inbox = peers[idx].clone();
        // 60.31 C7 the shared unix listener: EPOLLEXCLUSIVE wakes one (or a few) of the waiting workers per connection,
        // not all; before Linux 4.5 the flag is EINVAL: a plain registration then (every worker wakes, one accept wins)
        let ufd = cfg.unix.as_ref().map_or(-1, |u| u.fd);
        if ufd >= 0
            && !ep_add(ep, ufd, tok(K_LISTEN, 1, 0), (libc::EPOLLIN | libc::EPOLLET | libc::EPOLLEXCLUSIVE) as u32)
            && !ep_add(ep, ufd, tok(K_LISTEN, 1, 0), (libc::EPOLLIN | libc::EPOLLET) as u32)
        {
            return Err(std::io::Error::last_os_error());
        }
        if !ep_add(ep, lfd, tok(K_LISTEN, 0, 0), (libc::EPOLLIN | libc::EPOLLET) as u32)
            || !ep_add(ep, inbox.efd, tok(K_DNS, 0, 0), (libc::EPOLLIN | libc::EPOLLET) as u32)
        {
            return Err(std::io::Error::last_os_error());
        }
        // 60.09 M4a workers sweep at different times (spread over one period), not all at once
        let first_sweep = Duration::from_millis(IDLE_SWEEP_MS + IDLE_SWEEP_MS * idx as u64 / cfg.threads.max(1) as u64);
        let meter = cfg.upload_rate.is_some() || cfg.clientip.as_ref().and_then(|c| c.table.as_ref()).is_some_and(|t| t.has_upload());
        Ok(Worker {
            cfg,
            ep,
            lfd,
            inbox,
            idx,
            peers,
            dns_tx,
            clients: Slab::new(),
            targets: Slab::new(),
            dirty: Vec::new(),
            ready: Vec::new(),
            ready_spare: Vec::new(),
            dead: Vec::new(),
            connecting: Vec::new(),
            next_scan: Instant::now(),
            next_sweep: Instant::now() + first_sweep,
            ip_sweep: idx * clientip::SWEEP_SHARDS % clientip::SHARDS,
            peers_of: Vec::new(),
            connlog: Vec::new(),
            outbox,
            logline: Vec::new(),
            conn_seq: 0,
            refused_win: (0, 0),
            streamlog: Vec::new(),
            sref_win: (0, 0),
            sdone: Vec::new(),
            proxy_hs: Vec::new(),
            proxy_addrs: None,
            pipe_retry_at: Instant::now(),
            deferred: Vec::new(),
            accept_retry: false,
            dns_inflight: 0,
            dns_cache: HashMap::new(),
            he_lost: HashMap::new(),
            up_bufs: Vec::new(),
            up_n: 0,
            up_total: 0,
            #[cfg(test)]
            up_writevs: 0,
            tls_deadlines: VecDeque::new(),
            lingering: Vec::new(),
            next_linger: Instant::now(),
            starved: Vec::new(),
            starve_log_at: None,
            udp_buf: Vec::new(),
            // review D: start at the published level (the floor for small budgets is set before the
            // workers exist), so the first accept batch already gets the caps
            lvl: mem::LEVEL.load(Relaxed) as usize,
            capl: mem::cap_level(mem::LEVEL.load(Relaxed) as usize),
            floor0: mem::FLOOR.load(Relaxed) == 0,
            st: mem::stage(mem::LEVEL.load(Relaxed) as usize, mem::cap_level(mem::LEVEL.load(Relaxed) as usize)),
            accept_paused: false,
            stop_seen: 0,
            stop_scan_at: Instant::now(),
            pend_total: 0,
            pend_cap: mem::pend_cap(),
            starve_pool: credit::STARVE_POOL,
            pend_clients: 0,
            pend_paused: Vec::new(),
            pend_over_sweeps: 0,
            l3_mark: u64::MAX,
            l3_sweeps: 0,
            max_streams: mem::max_streams(&mem::STAGES[mem::LEVEL.load(Relaxed) as usize]),
            rbuf_max: mem::rbuf_max(mem::LEVEL.load(Relaxed) as usize),
            win: mem::grant_window(mem::cap_level(mem::LEVEL.load(Relaxed) as usize)),
            bulk_at: mem::bulk_at(mem::cap_level(mem::LEVEL.load(Relaxed) as usize)),
            stats,
            ufd,
            rx_total: 0,
            meter,
            meters: Vec::new(),
            lwait: Vec::new(),
            lscan: 0,
            pending: HashMap::new(),
        })
    }

    pub fn run(mut self) -> ! {
        mem::cache_pause(self.lvl >= 2); // 60.09 M2 (a worker can start at a level set_level never saw)
        let mut evs: Vec<libc::epoll_event> = vec![libc::epoll_event { events: 0, u64: 0 }; 1024];
        loop {
            // 70.25 wake rule: timeout 0 while the pool has release work left (mem::release_backlog: false without it)
            let timeout = if !self.ready.is_empty() || !self.dirty.is_empty() || mem::release_backlog() {
                0
            } else if self.accept_retry {
                10
            } else if !self.starved.is_empty() {
                STARVE_RETRY_MS as i32 // 50.02 (rare episodes: starve_check decides who is due)
            } else if !self.lwait.is_empty() {
                // 60.25 C10b (review) wake at the next lwait scan, not a tick after the last wake: a wake just
                // before lscan would otherwise stretch the resume gap to ~200 ms (the B >= R/10 rule assumes 100)
                meter::tick_left(self.lscan)
            } else if !self.connecting.is_empty() || !self.lingering.is_empty() {
                TIMER_TICK_MS
            } else if self.clients.slots.len() > self.clients.free.len() || mem::cache_held() > 0 || !self.pending.is_empty() {
                // 20.11: wake for the idle sweep while clients exist (70.25 or the pool has a chunk mapped: remote frees
                // reach only the owner, and empty chunks are unmapped by sweeps; 60.34 or PROXY headers are awaited:
                // their timeout is the sweep)
                self.next_sweep.saturating_duration_since(Instant::now()).as_millis().min(IDLE_SWEEP_MS as u128) as i32 + 1
            } else {
                -1
            };
            let n = unsafe { libc::epoll_wait(self.ep, evs.as_mut_ptr(), evs.len() as i32, timeout) };
            if n < 0 {
                if net::errno() == libc::EINTR {
                    continue;
                }
                panic!("epoll_wait: {}", std::io::Error::last_os_error());
            }
            for ev in &evs[..n as usize] {
                let (t, e) = (ev.u64, ev.events);
                self.dispatch(t, e);
            }
            // 20.26 one load per turn, after the inbox was drained in dispatch (review: a wake consumed
            // there is never lost: the sampler stores LEVEL before it writes the eventfd)
            let l = mem::LEVEL.load(Relaxed) as usize;
            if l != self.lvl || mem::cap_level(l) != self.capl {
                self.set_level(l); // 20.31 (b) also when only the host TCP caps changed
            }
            // continue streams/clients that hit their read budget
            std::mem::swap(&mut self.ready, &mut self.ready_spare);
            let mut ready = std::mem::take(&mut self.ready_spare);
            for t in ready.drain(..) {
                self.resume(t);
            }
            self.ready_spare = ready;
            self.run_deferred(); // safety net: targets created outside process_input
            if !self.starved.is_empty() {
                self.starve_check();
            }
            self.flush_dirty();
            if !self.connecting.is_empty() {
                self.run_timers();
            }
            if !self.lingering.is_empty() {
                self.linger_check();
            }
            if !self.lwait.is_empty() {
                self.meter_timers(); // 60.25 C10b
            }
            let swept = self.idle_sweep();
            self.tls_timeouts();
            if self.accept_retry {
                self.accept_retry = false;
                self.accept_all();
            }
            self.reap_dead();
            if swept {
                // after the sweep and reap_dead, which free idle and closed clients' buffers (into the pool's dirty
                // set); 60.09 M4b / 70.25: release only what the dirty set did not need since the last sweep
                self.stats.pool_sweep(crate::pool::sweep());
            }
            mem::turn_end(); // 70.25 bounded release
        }
    }

    /// End of a loop turn: free the slots of the clients closed during it. Until here a closed
    /// client's slot (and its rbuf, see process_frames) stays valid for the rest of the turn.
    fn reap_dead(&mut self) {
        for ci in self.dead.drain(..) {
            self.clients.remove(ci);
        }
        if !self.sdone.is_empty() {
            self.slog_flush(); // 60.35
        }
    }

    fn dispatch(&mut self, t: u64, e: u32) {
        let (kind, idx, gen) = untok(t);
        match kind {
            K_CLIENT => {
                let Some(c) = self.clients.get(idx, gen) else { return };
                if c.dead {
                    return;
                }
                if c.lingering && e & (libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
                    self.close_client(idx, Why::ClientClose); // review r1: peer gone, nothing more can be delivered
                    return;
                }
                if c.state == CState::Tls {
                    if e & (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
                        c.readable = true;
                    }
                    if e & (libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
                        c.rdhup = true; // kept for read_client after the handshake (EOF may follow the request)
                    }
                    self.tls_drive(idx);
                    return;
                }
                if e & (libc::EPOLLOUT | libc::EPOLLERR | libc::EPOLLHUP) as u32 != 0 && !c.dirty {
                    c.dirty = true;
                    self.dirty.push((idx, gen));
                }
                if e & (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
                    c.readable = true;
                    if e & (libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
                        c.rdhup = true;
                    }
                    self.read_client(idx);
                } else if e & libc::EPOLLOUT as u32 != 0 && !c.readable && c.ktls.is_some() {
                    // 20.17 kTLS 1.3, KeyUpdate right behind application data: read() returns the data
                    // short with the KeyUpdate already decrypted and queued, and from then on the kernel
                    // polls not-readable until we set the new RX key (Linux 6.14+ tls_sk_poll,
                    // key_update_pending), so no EPOLLIN ever comes. But the record became ready during
                    // that read (tls_rx_msg_ready wakes the socket), and the masked wakeup arrives as
                    // EPOLLOUT alone: probe with one read (EIO -> tls_control). Cost: one read per
                    // EPOLLOUT-only event on TLS 1.3 clients (after a full send buffer), never per data
                    // read. Linux 7.2+ wakes only for a record parsed but not yet read (msg_announced):
                    // a lone [data][KeyUpdate] then waits for the client's next segment (no data is held
                    // back; only the rekey is late). Test: 40.09 tls_extras.py "KeyUpdate ... behind data".
                    c.readable = true;
                    self.read_client(idx);
                }
            }
            K_TARGET => self.target_event(idx, gen, e),
            K_LISTEN => self.listen_event(idx, e), // 60.31 C7 / 60.34 (proxy.rs: out of line, run's registers stay)
            _ => self.inbox_ready(),
        }
    }

    fn resume(&mut self, t: u64) {
        let (kind, idx, gen) = untok(t);
        match kind {
            K_CLIENT => {
                if matches!(self.clients.get(idx, gen), Some(c) if !c.dead && c.readable) {
                    self.read_client(idx)
                }
            }
            K_TARGET => {
                if let Some(tg) = self.targets.get(idx, gen) {
                    tg.blocked = false;
                    if tg.state == TState::Open {
                        if tg.udp {
                            self.read_udp(idx);
                        } else {
                            self.read_target(idx);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// 60.12 graceful shutdown, from inbox_ready (net::Inbox::stop). STOP_DRAIN: accept what is queued on our
    /// SO_REUSEPORT listener (served, not reset; with --max-conns full they are reset like any connection over it), then close it (new connections are refused); close every Wisp
    /// connection that has no stream and nothing queued with WS 1001 (going away); the rest are served (repeated at
    /// every wake: a connection becomes idle when its last stream ends; a v2 client still in WaitInfo has none either).
    /// STOP_CLOSE: 1001 to all, handshakes closed.
    fn shutdown_step(&mut self, stop: u8) {
        if self.lfd >= 0 {
            self.accept_all(); // deliberate: at memory levels 2-3 (admission off) nothing is accepted; those are reset
            unsafe { libc::close(self.lfd) }; // also leaves the epoll set
            self.lfd = -1;
            if self.ufd >= 0 {
                // 60.31 C7 the unix fd is shared: leave our epoll set only (before `stopped`: no accept on it after
                // that); the last worker to let go removes the path and closes it (UnixListen::release)
                let r = unsafe { libc::epoll_ctl(self.ep, libc::EPOLL_CTL_DEL, self.ufd, std::ptr::null_mut()) };
                debug_assert_eq!(r, 0, "the shared unix fd left our epoll set before release"); // (review)
                self.ufd = -1;
                if let Some(u) = &self.cfg.unix {
                    u.release();
                }
            }
            self.inbox.stopped.store(true, std::sync::atomic::Ordering::Release);
            // main may now trust `load` (the accepted ones are in it)
        }
        if stop >= net::STOP_CLOSE && !self.pending.is_empty() {
            self.pending_close(); // 60.34 PROXY headers still missing at the close phase (STOP_DRAIN: their timeout)
        }
        self.flush_upload(); // a staged CONTINUE must not land after our Close frame (as ws_fail)
        for ci in 0..self.clients.slots.len() as u32 {
            let Some(c) = self.clients.slots[ci as usize].1.as_mut() else { continue };
            if c.dead || c.closing {
                continue;
            }
            if stop >= net::STOP_CLOSE && matches!(c.state, CState::Tls | CState::Http) {
                self.close_client(ci, Why::ServerClose); // no WebSocket yet
            } else if stop >= net::STOP_CLOSE
                || (matches!(c.state, CState::Open | CState::WaitInfo) && c.streams.is_empty() && c.out_empty())
            {
                ws::push_frame(&mut c.obuf, OP_CLOSE, &[&1001u16.to_be_bytes()]);
                self.begin_close(ci, Why::ServerClose);
            }
        }
    }

    fn run_timers(&mut self) {
        let now = Instant::now();
        if now < self.next_scan {
            return;
        }
        self.next_scan = now + Duration::from_millis(TIMER_TICK_MS as u64);
        // 60.05 H1/F5: (index, gen) and a liveness check per entry: a hook in fail_target/try_connect/
        // won/connected that closes a client would close its other targets listed here
        let due: Vec<(u32, u32)> =
            self.connecting
                .iter()
                .filter(|&&(ti, _)| {
                    self.targets.slots[ti as usize].1.as_ref().is_some_and(|t| {
                        t.deadline <= now || (t.next_try <= now && t.attempt < t.addrs.len() && t.conn.len() < HE_PARALLEL)
                    })
                })
                .copied()
                .collect();
        for (ti, tg) in due {
            let Some(t) = self.targets.get(ti, tg) else { continue };
            if t.state != TState::Connecting {
                continue;
            }
            if t.deadline <= now {
                for fd in t.conn.drain(..) {
                    unsafe { libc::close(fd) };
                }
                (t.tfo_fd, t.tfo_sent) = (-1, 0);
                t.rdhup = false;
                if t.attempt >= t.addrs.len() {
                    if t.dns_more {
                        t.err = libc::ETIMEDOUT; // 70.10 parked; 0x43 if the final answer brings nothing new
                        self.unlist(ti);
                    } else {
                        if self.cfg.upstream.is_some() {
                            // 60.27 C6 the proxy did not answer the SYN (fd -1) or finish the handshake (fd >= 0) in
                            // time (review: both are the proxy's failure)
                            self.stats.upstream_fail.bump();
                            if !self.streamlog.is_empty() {
                                self.slog_why(ti, SWhy::UpstreamFail, "timeout");
                                // 60.35
                            }
                        }
                        self.fail_target(ti, CLOSE_TIMEOUT);
                    }
                    continue;
                }
            }
            self.try_connect(ti); // 20.14: next address in parallel (or after a timeout)
        }
    }

    fn flush_dirty(&mut self) {
        let mut list = std::mem::take(&mut self.dirty);
        for &(ci, g) in &list {
            // 60.05 H1: the client may have closed after it was listed (run_timers marks it, l3_sweep
            // closes it, the dead drain frees the slot): skip a freed or reused slot
            let Some(c) = self.clients.get(ci, g) else { continue };
            c.dirty = false;
            if c.dead {
                continue;
            }
            if c.flush().is_err() {
                self.close_client(ci, Why::Io); // 60.24
                continue;
            }
            if c.ktls_on && (c.wblock || c.starve > 0) {
                let fd = c.fd;
                match starve_step(true, c.wblock, !c.out_empty(), || net::outq(fd), c.starve) {
                    // A first hit is often kTLS's own record list (counted in sk_wmem_queued, not in SIOCOUTQ) waiting
                    // for its tx work: VPS1 smoke, 19 such per 5 s wss run below the pressure line, all gone at the first
                    // retry. So an episode counts (and logs) only when the first retry is still starved.
                    Starve::Start => {
                        let now = Instant::now();
                        (c.starve, c.starve_at, c.starve_since, c.starve_b) = (1, now + starve_delay(1), now, false);
                        self.starved.push((ci, g));
                    }
                    // review: an incidental flush (a sibling stream's read, a CONTINUE) only retries the
                    // send; the episode advances (count, backoff, room) on starve_check's timer retries alone
                    Starve::Again if !std::mem::take(&mut c.starve_due) => {}
                    Starve::Again => {
                        c.starve = c.starve.saturating_add(1);
                        c.starve_at = Instant::now() + starve_delay(c.starve);
                        if c.starve == 2 {
                            self.stats.ktls_starve.bump();
                            let now = Instant::now();
                            if self.starve_log_at.is_none_or(|t| now >= t) {
                                self.starve_log_at = Some(now + STARVE_LOG_EVERY);
                                crate::metrics::log_nowait(format!(
                                    "finalwisp: kTLS send refused with nothing in flight (host TCP memory pressure, net.ipv4.tcp_mem): \
                                     retrying from a timer and sending all queued output in one request (50.02; \
                                     counted as ktls_starve, at most one line per {} s per worker)",
                                    STARVE_LOG_EVERY.as_secs()
                                ));
                            }
                        }
                    }
                    Starve::End => {
                        c.starve_due = false;
                        if std::mem::take(&mut c.starve) >= 2 {
                            self.stats.ktls_starve_end.bump();
                            self.stats.ktls_starve_ms_max.max(c.starve_since.elapsed().as_millis() as u64);
                        }
                        c.starve_room = 0;
                    }
                    Starve::None => {}
                }
            }
            // 20.21 a splice-fed client reaches here only after a short write (splice_target flushes
            // directly), so sampling is lazier than 4 MiB once lifted. That is enough: the restore only
            // matters for a client that slowed down, and a slow client fills the socket and lands here.
            if c.ktls_on && c.tx_bytes >= c.rate_check_at && self.cfg.adapt_lowat > 0 {
                c.rate_check_at = c.tx_bytes + RATE_CHECK_BYTES;
                if !c.adapt_lowat(self.cfg.adapt_lowat) {
                    c.rate_check_at = u64::MAX;
                }
            }
            if c.ohead == c.obuf.len() && c.splice_at == NO_MARK {
                c.obuf.clear();
                c.ohead = 0;
                if free_drained(self.lvl, c.obuf.capacity(), self.st.keep) {
                    c.obuf = Vec::new(); // 20.26 memory pressure: do not keep a big drained buffer
                }
            } else if c.ohead >= OBUF_COMPACT && c.ohead * 2 >= c.obuf.len() {
                c.compact();
            }
            if c.bhead == c.bulk.len() {
                c.bulk.clear();
                c.bhead = 0;
                if free_drained(self.lvl, c.bulk.capacity(), self.st.keep) {
                    c.bulk = Vec::new(); // 20.26 (bulk_ends is empty: everything was sent)
                }
            } else if c.bhead >= OBUF_COMPACT && c.bhead * 2 >= c.bulk.len() {
                c.compact_bulk();
            }
            if c.out_empty() && c.closing {
                // review r1: kTLS sockets close from `lingering` once drained (Client::ktls_drained)
                if c.ktls_on {
                    c.ktls_notify();
                    if !std::mem::replace(&mut c.lingering, true) {
                        self.lingering.push((ci, g, Instant::now() + KTLS_LINGER));
                    }
                    continue;
                }
                self.close_client(ci, Why::ServerClose);
                continue;
            }
            if c.opaused && c.out_pending() < self.st.out_low {
                c.opaused = false;
                self.ready.push(tok(K_CLIENT, ci, g));
            }
            if !c.blocked.is_empty() && c.out_pending() < self.st.out_low {
                self.ready.append(&mut c.blocked);
            }
            if !c.blocked_bulk.is_empty() && c.out_pending() < self.st.out_low_bulk {
                self.ready.append(&mut c.blocked_bulk); // order: see read_target (round-robin)
                c.bulk_waiting = 0;
            }
        }
        list.clear();
        if self.dirty.is_empty() {
            self.dirty = list;
        }
    }
}

// 70.01 cargo-fuzz harness hooks (server/fuzz): compiled only with --cfg fuzzing, never into the server.
#[cfg(fuzzing)]
#[path = "../../fuzz/worker_hooks.rs"]
pub mod fuzz_hooks;

#[cfg(test)]
mod tests;
