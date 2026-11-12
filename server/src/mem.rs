//! 20.26 global memory budget: the server slows down instead of being OOM-killed.
//! A sampler thread compares the memory in use with a budget (cgroup v2 memory.max/high, or half of
//! MemTotal) and publishes a pressure level. Each worker loads LEVEL once per loop turn and changes
//! its limits (Stage) only when the level changes, so there is no cost on the I/O paths.
//! Also: a counting global allocator (heap bytes in use, per-thread slots, no shared cache line).
use crate::net::Inbox;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicU8, AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Per-level limits. Level 0 is exactly the pre-20.26 behaviour.
#[derive(Clone, Copy, Debug)]
pub struct Stage {
    /// enter this level when usage >= enter permille of the budget (checked from the level below)
    pub enter: u32,
    /// leave this level (one down) when usage < exit permille
    pub exit: u32,
    /// stop reading a target while its client's output backlog is >= out_high; resume below out_low
    pub out_high: usize,
    pub out_low: usize,
    /// oh256 (20.06, --prio only): a bulk-lane stream stops reading at this client backlog (obuf + lane +
    /// splice) and resumes below out_low_bulk; obuf-lane streams keep out_high/out_low. At level 0 the lane
    /// then holds at most 256 KiB + CHUNK, so small streams always find >= 700 KiB of room (VPS3 vs
    /// 1M: download 10x10 +10%, peak RSS -47%, 100 Mbit page p99 -35%; a single shared 256K cap starved
    /// small streams behind the lane). Levels 1+: min(256 KiB, out_high) and min(64 KiB, out_low).
    pub out_high_bulk: usize,
    pub out_low_bulk: usize,
    /// stop reading a client whose own output (pongs, CONTINUEs, ...) piles up beyond this
    pub out_hard: usize,
    /// largest client read buffer (a single bigger WS frame still gets room)
    pub rbuf_max: usize,
    /// a drained obuf/bulk/pend with a larger capacity is freed at once (not at the idle sweep).
    /// r5, level 1: 2 x out_high. An obuf that filled to out_high has reserve()d past it (room +
    /// CHUNK), and with keep == out_high every full drain freed and re-allocated it (2-vCPU box at
    /// 128M download: 0.92 -> 0.69 CPU ms per MiB with the splice lane, 2 x the CPU per MiB in the copy
    /// path). Levels 2/3 (60.12 #2): 132 KiB, one doubling of room + CHUNK (131078) plus <= ~2 KiB of small
    /// frames queued before the first read (CONTINUE: 11 bytes; the same reason as the old 70.11 block cache's CACHE_MAX, 132 KiB).
    /// Upload backlogs (pend) keep the old level 2/3 value (worker/levels.rs pend_keep).
    /// With out_high (64 KiB) every obuf that read once (>= 65539) was freed at its drain and regrown
    /// (diag, echo/download 16M: level 2 obufs grow only to 65539..131144, never beyond).
    pub keep: usize,
    /// CONTINUE grant (packets); min'ed with --buffer. r4: under pressure the grant for a stream is
    /// also sized in bytes from its mean packet size (worker/upload.rs after_write)
    pub grant: u32,
    /// r4: the handshake CONTINUE, every new stream's first credit (packets); min'ed with --buffer.
    /// Small under pressure: a client's first burst on a new stream is hs x its packet size, before
    /// any byte-sized grant can apply (100 streams x 128 x 16 KiB = 200 MiB at level 0)
    pub hs: u32,
    /// SO_RCVBUF/SO_SNDBUF on TCP target sockets (bytes; 0 = autotune; the send side: target_snd); also sets the
    /// stream limit (max_streams). Client sockets: see client_caps
    pub sock_cap: u32,
    /// SO_RCVBUF of client sockets while capped (sock_cap > 0); r5: at level 1 scaled by the budget
    /// up to 2 x this (mem::client_caps)
    pub client_rcv: u32,
    /// r5: SO_SNDBUF of client sockets while capped (0 = max(sock_cap, 64K)). At level 1 128 KiB: the
    /// kernel's 2x is the splice pipe (worker/mod.rs SPLICE_PIPE), so one splice drains into the socket and
    /// the download path splices instead of copying (2-vCPU box, 128M: 1116 -> 1455 MiB/s with the bulk
    /// rule and keep below). A bigger socket does not help (256 KiB: the same), and in the copy path a
    /// socket that never fills costs 2x the CPU per MiB (every full drain freed the obuf: keep).
    pub client_snd: u32,
    /// 60.15 T03 P1: SO_SNDBUF of TCP target sockets while capped (0 = sock_cap; mem::target_caps). Level 1 40 KiB: with
    /// the 32 KiB cap a loopback upload stream ran at 0.1-0.5 of uncapped (one segment in flight against delayed ACKs);
    /// 40, 48, 64, 128 and 256 KiB measured the same (VPS1/VPS2, 200M: upload 1x1 x2.8-4.3, 10x10 x1.6-1.8, VmHWM 38 ->
    /// 30-33 MiB). 40 KiB keeps stream_bytes at the level-1 floor (2 x 32 + 2 x 40 = 144 KiB = tcp_rmem[1] + LAZY_CAP):
    /// 64 KiB cut a 32 MiB worker to 85 streams and failed compat membudget (download 10x10 = 100 streams, 15 refused).
    /// The receive side stays sock_cap (uncapped target receive queues pushed download 10x10 into L3).
    pub target_snd: u32,
    /// per-stream upload backlog cap for a client that sent more than its credit (CLOSE 0x49)
    pub pend_over: usize,
    /// accept new connections and new streams (false: CLOSE 0x49 for CONNECT, accept paused)
    pub admit: bool,
    /// read every client (false, 60.15 T03 P4: only clients without an upload backlog are read, so a client's
    /// receive queue drains straight into the capped target sockets; the others' input waits in the kernel buffer)
    pub read: bool,
    /// on entering: close streams whose unsent upload backlog exceeds this with CLOSE 0x49 (0 = none)
    pub shed: usize,
    /// no progress for a while: close the clients holding the most memory (Worker::l3_sweep)
    pub shed_clients: bool,
}

const K: usize = 1024;
const M: usize = 1024 * 1024;
/// Tuned from the potato curves (16/32/64/128 MiB) and the no-pressure A/B in 20.26 rounds 4-5 ("r4"/"r5" below) and
/// 60.12 #2/#2b (L2/L3 keep 132K, sock_cap 32K). Level 0 values must stay equal to the old constants (worker/mod.rs).
pub const STAGES: [Stage; 4] = [
    // L0: no pressure, the old constants (OUT_HIGH 1M, OUT_LOW 256K, OUT_HIGH_BULK 256K, OUT_LOW_BULK 64K, OUT_HARD 8M,
    // RBUF 256K, PEND_HARD 64M)
    Stage {
        enter: 0,
        exit: 0,
        out_high: M,
        out_low: 256 * K,
        out_high_bulk: 256 * K,
        out_low_bulk: 64 * K,
        out_hard: 8 * M,
        rbuf_max: 256 * K,
        keep: usize::MAX,
        grant: u32::MAX,
        hs: u32::MAX,
        sock_cap: 0,
        client_rcv: 0,
        client_snd: 0,
        target_snd: 0,
        pend_over: 64 * M,
        admit: true,
        read: true,
        shed: 0,
        shed_clients: false,
    },
    // L1 soft: smaller queues and credit, kernel buffers capped (autotuning stops growing them).
    // 32 KiB cap on loopback (MSS 64 KiB): ~820 MiB/s per socket; 64 KiB: ~6.5 GiB/s; 16 KiB: 4 MiB/s.
    // Client receive 128 KiB from a 32 MiB worker budget (worker/conn.rs, levels.rs caps; potato 128M, 1 core, upload
    // 10x10: 32 KiB 1440 MiB/s, 64 KiB 1430, 128 KiB 1600, uncapped 1610, master 1668; 256 KiB lets the
    // upload outrun the 32 KiB target sockets into pend)
    Stage {
        enter: 500,
        exit: 400,
        out_high: 256 * K,
        out_low: 64 * K,
        out_high_bulk: 256 * K,
        out_low_bulk: 64 * K,
        out_hard: M,
        rbuf_max: 64 * K,
        keep: 512 * K,
        grant: 8,
        hs: 8,
        sock_cap: 32 * K as u32,
        client_rcv: 128 * K as u32,
        client_snd: 128 * K as u32,
        target_snd: 40 * K as u32,
        pend_over: 64 * M,
        admit: true,
        read: true,
        shed: 0,
        shed_clients: false,
    },
    // L2 hard: minimal queues, no new connections or streams. 60.12 #2b: socket cap 32K as L1 (was 16K): a 16K
    // cap (32K in the kernel) on loopback stalled streams for RTOs on kernel 7.0 (receiver drops, TCPRcvQDrop:
    // echo 10x10 at 16M stalled in 2-4 of 8 runs; with 32K 0 of 8); 20.26's probe already had 16K at 4 MiB/s
    Stage {
        enter: 700,
        exit: 600,
        out_high: 64 * K,
        out_low: 16 * K,
        out_high_bulk: 64 * K,
        out_low_bulk: 16 * K,
        out_hard: 256 * K,
        rbuf_max: 16 * K,
        keep: 132 * K,
        grant: 8,
        hs: 8,
        sock_cap: 32 * K as u32,
        client_rcv: 32 * K as u32, // 60.15 T03: was 16K (see client_caps)
        client_snd: 0,
        target_snd: 0,
        pend_over: M,
        admit: false,
        read: true,
        shed: 0,
        shed_clients: false,
    },
    // L3 critical: stop reading clients, shed streams holding over 1 MiB of unsent upload backlog; no
    // progress for 2 sweeps: close the clients holding the most memory
    Stage {
        enter: 850,
        exit: 750,
        out_high: 64 * K,
        out_low: 16 * K,
        out_high_bulk: 64 * K,
        out_low_bulk: 16 * K,
        out_hard: 256 * K,
        rbuf_max: 16 * K,
        keep: 132 * K,
        grant: 8,
        hs: 8,
        sock_cap: 32 * K as u32,
        client_rcv: 32 * K as u32, // 60.15 T03: was 16K (see client_caps)
        client_snd: 0,
        target_snd: 0,
        pend_over: M,
        admit: false,
        read: false,
        shed: M,
        shed_clients: true,
    },
];

/// Below this budget the server never runs at level 0. Measured (potato, 1 core, loopback download
/// 10x10): memory goes from 1 to 32 MiB in ~25 ms at level 0 (obuf/bulk up to 2 MiB per client,
/// autotuned target receive queues), faster than any sampler can react; started at level 1 it stays
/// near 23 MiB and survives 16 MiB. Above it, growth is bounded by real link rates and the sampler.
/// 60.15 T03 P2 (not taken): 128 MiB cost nothing on the 2-vCPU boxes (and gave light loads 30-90 % at 128-200M), but
/// on a 1-vCPU VM a level-0 start at 128M still refused up to 300 streams, reached level 3 and caused host TCP pressure
/// under upload 40x10, also with the flap damping (Dwell); started at level 1 it did none of that (60.17).
pub const SMALL_BUDGET: u64 = 256 << 20;
/// The floor of the detected budget, set by main before the workers start.
pub static FLOOR: AtomicU8 = AtomicU8::new(0);
/// Lowest level for a budget (1 = start and stay at least at level 1).
pub fn floor(budget: u64) -> usize {
    (budget < SMALL_BUDGET) as usize
}

/// Share of the budget (per mille) that the upload backlog (pend) may use before clients adding to
/// it are no longer read (Worker::pend_cap).
pub const PEND_SHARE: u64 = 250;
/// Share of the budget (per mille) for kernel socket buffers while they are capped (level >= 1):
/// a TCP stream then holds up to ~4 x sock_cap (the kernel doubles the cap, and one write may
/// overshoot it; measured: 128 upload streams to a stalled sink peaked at 150 KiB each with a 64 KiB
/// cap), so the budget implies a stream count; beyond it new streams get CLOSE 0x49
/// (Worker::max_streams). 32 MiB at level 1 (32 KiB cap, tcp_rmem[1] 128 KiB): 113 streams, also with the 40 KiB level-1
/// target send buffer (60.15 T03 P1: stream_bytes 2 x 32 + 2 x 40 KiB = the 144 KiB lazy floor).
pub const SOCK_SHARE: u64 = 500;
/// The budget divided by the number of workers, set by main before the workers start (0 = none).
pub static WORKER_BUDGET: AtomicUsize = AtomicUsize::new(0);

/// Upload backlog cap for one worker (usize::MAX = no budget).
pub fn pend_cap() -> usize {
    match WORKER_BUDGET.load(Relaxed) {
        0 => usize::MAX,
        b => (b / 1000 * PEND_SHARE as usize).max(1 << 20),
    }
}

/// Initial TCP receive buffer (tcp_rmem[1]; 128 KiB if unreadable), set by detect(): the most a
/// target socket not yet capped (worker/target.rs lazy_cap) can hold queued.
pub static RMEM_DEFAULT: AtomicUsize = AtomicUsize::new(128 << 10);

fn tcp_rmem_default() -> Option<usize> {
    let s = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_rmem").ok()?;
    s.split_whitespace().nth(1)?.parse().ok()
}

/// Lazy target socket caps (worker/target.rs lazy_cap) are used when an uncapped stream costs at most
/// 2 x what a capped one may hold (tcp_rmem[1] + LAZY_CAP <= 8 x the level-1 cap, 256 KiB): on a
/// host tuned to a big tcp_rmem[1] the caps are set at connect, as in r3. Set by detect(). (Since 60.15 P1 a level-1
/// stream may hold more, 2 x 32 + 2 x 40 KiB; the rule keeps 8 x the level-1 receive cap.)
pub static LAZY: AtomicBool = AtomicBool::new(true);

/// Kernel memory one capped stream may hold at a stage: ~4 x the cap (the kernel doubles it, one
/// write may overshoot), or, for a stream still uncapped (lazy_cap), tcp_rmem[1] queued + LAZY_CAP.
/// 60.15 T03 P1: the receive and send halves separately (target_snd may exceed the cap at level 1).
pub fn stream_bytes(st: &Stage) -> usize {
    let lazy = if LAZY.load(Relaxed) { RMEM_DEFAULT.load(Relaxed) + crate::worker::LAZY_CAP as usize } else { 0 };
    let (rcv, snd) = target_caps(st);
    (2 * rcv as usize + 2 * snd as usize).max(lazy)
}

/// 60.15 T03 P1: (SO_RCVBUF, SO_SNDBUF) of a capped TCP target socket at a (composed) stage (worker/connect.rs, target.rs, levels.rs).
/// The receive cap (32 KiB on loopback: ~820 MiB/s per socket; a 1448-byte MSS is unaffected) bounds per-stream kernel
/// memory on every interface; a 64 KiB cap both ways was measured worse (2-vCPU box, 128M: download 0.80, upload 0.95).
/// Level 1 sends target_snd (40 KiB): upload x1.6-4.3 at 200M with the 32 KiB receive cap kept.
pub fn target_caps(st: &Stage) -> (u32, u32) {
    (st.sock_cap, if st.target_snd > 0 { st.target_snd } else { st.sock_cap })
}

/// r4: bytes one CONTINUE grants a stream under pressure (worker/upload.rs grant; 0 = packets only, level
/// 0): the target socket cap, at level 1 from a 128 MiB worker budget 2 x the cap (r5). With the
/// refill rule at most two grants are outstanding per stream, and the capped socket holds 2 x the
/// cap, so a draining target keeps the backlog (heap) at ~0 with the cap, and at most one grant of
/// it with 2 x the cap (100 streams at 128M: 6.4 MiB, 5% of the budget; measured peak 33 MiB). 60.15 P1: a level-1
/// target socket sends 2 x target_snd (80 KiB); the window stays the cap (conservative: a grant fits the socket).
/// Measured (10x10 upload, 16 KiB packets): the cap (32 KiB): 2-vCPU box at 128M 958 MiB/s, pend 0;
/// 2 x the cap at 32M: pend ~128 KiB per stream, level 2 (laptop); 4 x the cap at 128M: 266 MiB/s
/// (each grant overflows the socket into pend and the refill waits for out_low). A WAN upload
/// stream under pressure gets this much per RTT.
pub fn grant_window(level: usize) -> u64 {
    let cap = STAGES[level].sock_cap as u64;
    if level == 1 {
        (WORKER_BUDGET.load(Relaxed) as u64 / 2048).clamp(cap, 2 * cap)
    } else {
        cap
    }
}

/// r5: (SO_RCVBUF, SO_SNDBUF) of a client socket at a capped stage. Receive: `client_rcv`, only with a
/// worker budget >= 256 x it (32 MiB at 128 KiB: at 16 MiB the bigger window pushed a 1-core upload
/// 10x10 into level 2/3), at level 1 up to 2 x it from a 128 MiB budget (fewer, larger reads: 8.8 ->
/// 4.4 read() per MiB uploaded); else the plain cap. Send: `client_snd`, or max(cap, 64 KiB): two
/// loopback segments, else one is in flight at a time and the receiver's delayed ACK paces it
/// (download 10x10 at 32 KiB: 18 MiB/s; 64 KiB: 1.5 GiB/s). Level 1 keeps `client_snd` only with a
/// budget >= 256 x it, as the receive side. 60.15 T03: levels 2/3 receive 32 KiB (was 16 KiB), the measured loopback
/// floor (as sock_cap, 60.12 #2b: a receive buffer too small for loopback's 64 KiB skbs drops them and waits for RTOs):
/// with 16 KiB a capped client's upload crawled (~2 MiB/s) and usage stayed just above level 2's exit for the rest of
/// the run (VPS1, 256M upload 40x10: 6/8 runs; 32 KiB: 0/8, median 2 -> 300 MiB/s, 60.17).
pub fn client_caps(level: usize) -> (u32, u32) {
    let st = &STAGES[level];
    let b = WORKER_BUDGET.load(Relaxed);
    let big = |v: u32| b >= 256 * v as usize;
    let rcv = if !big(st.client_rcv) {
        st.sock_cap.min(st.client_rcv) // (60.12 review: a small budget keeps the stage's client_rcv when below the cap)
    } else if level == 1 {
        (b as u64 / 512).clamp(st.client_rcv as u64, 2 * st.client_rcv as u64) as u32
    } else {
        st.client_rcv
    };
    let snd = if st.client_snd > 0 && big(st.client_snd) { st.client_snd } else { st.sock_cap.max(64 * 1024) };
    (rcv, snd)
}

/// r5: a target read of this many bytes marks the stream bulk (worker/target.rs: the splice lane). Level 0:
/// a full CHUNK (65530, as before r5). A capped target socket holds ~2 x the cap, so a CHUNK read
/// never comes under pressure and the splice lane never engaged (copy path only): there a read of a
/// cap's worth is the signal, when the client socket is sized for the lane (`client_snd`, from a
/// 32 MiB budget: 2-vCPU box at 128M download 1112 -> 1371 MiB/s; at 16M, with a 64 KiB client
/// socket, the lane was 0.94 of the copy path, which batches the streams' data into one send).
pub fn bulk_at(level: usize) -> usize {
    let st = &STAGES[level];
    if st.sock_cap > 0 && client_caps(level).1 >= st.client_snd && st.client_snd > 0 {
        st.sock_cap as usize
    } else {
        crate::worker::CHUNK
    }
}

/// Largest client read buffer at a stage. r4: at level 1 it follows the worker budget (1/512 of it,
/// 64 KiB to 256 KiB: 32M 64K, 64M 128K, 128M+ 256K): a 64 KiB rbuf costs a loopback upload 5x the
/// read syscalls of level 0 (24 per MiB instead of 4; the 2-vCPU box at 128M: 750 -> 950 MiB/s with
/// 256K), while rbuf is per loaded client and 256 KiB x 100 clients would be most of a 32M budget.
pub fn rbuf_max(level: usize) -> usize {
    let st = &STAGES[level];
    if level == 1 {
        (WORKER_BUDGET.load(Relaxed) / 512).clamp(st.rbuf_max, STAGES[0].rbuf_max)
    } else {
        st.rbuf_max
    }
}

/// 20.31 (b) the level the socket caps come from: the memory level, or 1 at memory level 0 while the host TCP level
/// (--tcpmem-adapt) is 1: the socket caps and (b2) the credit come from it; queues, keep, rbuf, streams stay at level 0
/// (the full level-1 stage cost download 10x10 13% when the kernel pressure was short).
pub fn cap_level(level: usize) -> usize {
    if level == 0 && TCP_LEVEL.load(Relaxed) > 0 {
        1
    } else {
        level
    }
}

/// 20.31 (b) the stage of memory level `level` with the socket caps of level `capl` (cap_level). (b2): and the
/// credit of `capl` (grant, hs; the worker also takes grant_window, the refill rule and its out_low gate from `capl`):
/// with level-0 credit into 32 KiB target sockets the upload backlog (pend) went to the heap (loopback upload 10x10
/// peak 7 -> 399 MiB, 0.44 throughput). Queues (out_*), keep, rbuf, pend_over, streams stay at `level`.
/// B (20.31 redesign): the worker skips the caps of the host TCP level alone (memory level 0) on a same-host socket,
/// client or target (worker/target.rs tcp_only_local).
/// 60.15 T03 P1: target_snd stays the memory level's (0 at memory level 0: the host TCP level alone keeps 32 KiB sends).
pub fn stage(level: usize, capl: usize) -> Stage {
    let (mut s, c) = (STAGES[level], &STAGES[capl]);
    (s.sock_cap, s.client_rcv, s.client_snd) = (c.sock_cap, c.client_rcv, c.client_snd);
    (s.grant, s.hs) = (c.grant, c.hs);
    s
}

/// Live streams one worker may hold at a stage (usize::MAX = no limit).
pub fn max_streams(st: &Stage) -> usize {
    match WORKER_BUDGET.load(Relaxed) {
        b if b == 0 || st.sock_cap == 0 => usize::MAX,
        b => (b / 1000 * SOCK_SHARE as usize / stream_bytes(st)).max(16),
    }
}

/// Memory in use as the sampler last measured it (bytes), for Worker::l3_sweep.
pub static USED: AtomicU64 = AtomicU64::new(0);
/// deliberate: a level steps down only this long after the last change; up at once (review H:
/// L1 <-> L2 flapped every ~0.5 s at 16 MiB). 60.15 T03: the base of Dwell (doubled per flap).
const DWELL_DOWN: Duration = Duration::from_millis(250);
/// 60.15 T03 flap damping: a step up within FLAP_WINDOW of a step down from that level (or higher) is a flap and doubles
/// the dwell before the next step down, up to DWELL_MAX; CALM after the last step down it is back to DWELL_DOWN. Why: stepping down undoes what the level did (level 0 restores the socket sizes and grants full credit),
/// so a steady load that only fits at level 1 rose again at once: L0 <-> L1 ~6 times a second (potato 1 vCPU 128M
/// upload 10x10: 105 changes in 17 s; VPS1 256M upload 10x10, 60.17).
const FLAP_WINDOW: Duration = Duration::from_secs(2);
const DWELL_MAX: Duration = Duration::from_secs(4);
const CALM: Duration = Duration::from_secs(10);

/// 60.15 T03 the step-down dwell of the memory level (see FLAP_WINDOW). Only the step down from the level that flapped
/// waits longer: a global longer dwell held level 3 (no admission, backlogged clients unread) for up to 4 s after a spike
/// (potato 128M upload 40x10: 8-474 MiB/s vs ~3000 flapping).
#[derive(Debug, Clone, Copy)]
pub struct Dwell {
    /// the dwell of a step down from `level`
    pub cur: Duration,
    pub level: usize,
    /// the last step down: when, and from which level
    down: Option<(Instant, usize)>,
}
impl Dwell {
    pub fn new() -> Dwell {
        Dwell { cur: DWELL_DOWN, level: 0, down: None }
    }
    /// the sampler's next level: `want` (next_level) held at `ml` while a step down is due only after the dwell
    pub fn next(&mut self, ml: usize, want: usize, changed_at: Instant, now: Instant) -> usize {
        if let Some((at, _)) = self.down {
            if now.duration_since(at) >= CALM {
                (self.cur, self.down) = (DWELL_DOWN, None); // calm: no step down for CALM (review: also mid-hold)
            }
        }
        let dwell = if ml == self.level { self.cur } else { DWELL_DOWN };
        if want < ml && now.duration_since(changed_at) < dwell {
            return ml;
        }
        if want < ml {
            self.down = Some((now, ml));
        } else if want > ml {
            if let Some((at, from)) = self.down {
                // review: only a step back up through `from` (a ramp 0 -> 1 -> 2 counts once)
                if ml < from && want >= from && now.duration_since(at) < FLAP_WINDOW {
                    // a flap of `from`: its step down waits twice as long (another level's flap starts over)
                    self.cur = if from == self.level { (self.cur * 2).min(DWELL_MAX) } else { 2 * DWELL_DOWN };
                    self.level = from;
                }
            }
        }
        want
    }
}

/// Current pressure level (index into STAGES). Written only by the sampler.
pub static LEVEL: AtomicU8 = AtomicU8::new(0);

/// 60.12 metrics: level changes, and milliseconds spent at each level before the current one began
/// (LEVEL_AT, metrics::now_ms). Written only by the sampler, at a change; read by metrics::line.
static LEVEL_CHANGES: AtomicU64 = AtomicU64::new(0);
static LEVEL_MS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static LEVEL_AT: AtomicU64 = AtomicU64::new(0);

/// 60.29 seqlock over the sampler's time accounting (LEVEL with LEVEL_*; TCP_LEVEL with TCP_ENTERS / TCP_L1_*): a
/// reader (metrics line, /metrics, the final line) gets one coherent set, so a counter built from them never goes back
/// (review: a read between the level store and note_level credited a whole episode to the new level, then lost it).
/// One writer (the sampler); odd = a write in progress; readers retry (the write is a few stores).
static TIMES_SEQ: AtomicU64 = AtomicU64::new(0);
/// 60.29 the latest `now` a reader counted an open episode up to. The writer closes an episode at no earlier time
/// (review: a reader whose clock passed the writer's could count past the close, and the next read went back).
static TIMES_READ_MAX: AtomicU64 = AtomicU64::new(0);

/// `f` gets the time to close or open an episode at: now_ms, raised to any time a reader already counted up to
fn times_write(f: impl FnOnce(u64)) {
    use std::sync::atomic::{fence, Ordering::*};
    let s = TIMES_SEQ.load(Relaxed);
    TIMES_SEQ.store(s.wrapping_add(1), Relaxed);
    // SeqCst (Dekker with times_read): either this load sees a reader's time, or that reader sees the odd sequence
    fence(SeqCst);
    let now = crate::metrics::now_ms().max(TIMES_READ_MAX.load(Relaxed));
    f(now);
    TIMES_SEQ.store(s.wrapping_add(2), Release);
}

/// One coherent read of the sampler's times, for a reader that counts open episodes up to `now`
fn times_read<T>(now: u64, f: impl Fn() -> T) -> T {
    use std::sync::atomic::{fence, Ordering::*};
    loop {
        let s = TIMES_SEQ.load(Acquire);
        if s & 1 == 0 {
            TIMES_READ_MAX.fetch_max(now, Relaxed);
            fence(SeqCst);
            let v = f();
            fence(Acquire);
            if TIMES_SEQ.load(Relaxed) == s {
                return v;
            }
        }
        std::hint::spin_loop();
    }
}

/// sampler: account the time at `old` up to now (ms) and count the change (inside times_write, with the LEVEL store)
fn note_level(old: usize, now: u64) {
    let at = LEVEL_AT.load(Relaxed);
    LEVEL_MS[old].store(LEVEL_MS[old].load(Relaxed) + now.saturating_sub(at), Relaxed);
    LEVEL_AT.store(now, Relaxed);
    LEVEL_CHANGES.store(LEVEL_CHANGES.load(Relaxed) + 1, Relaxed);
}

/// 60.12 (level changes, ms at each level) up to `now` (metrics::now_ms). Without a sampler (no budget) all
/// time is at the start level. 60.29: one coherent read (times_read).
pub fn level_times(now: u64) -> (u64, [u64; 4]) {
    let (changes, mut t, cur, at) = times_read(now, || {
        let t: [u64; 4] = std::array::from_fn(|l| LEVEL_MS[l].load(Relaxed));
        (LEVEL_CHANGES.load(Relaxed), t, (LEVEL.load(Relaxed) as usize).min(3), LEVEL_AT.load(Relaxed))
    });
    t[cur] += now.saturating_sub(at);
    (changes, t)
}

// ---------------------------------------------------------------- counting allocator

#[repr(align(128))]
struct Slot(AtomicIsize);
const SLOTS: usize = 64;
static HEAP: [Slot; SLOTS] = [const { Slot(AtomicIsize::new(0)) }; SLOTS];
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    // const init, no destructor: safe to use inside the allocator, also during thread exit
    static MY_SLOT: Cell<usize> = const { Cell::new(usize::MAX) };
}

#[inline]
pub(crate) fn account(d: isize) {
    let i = MY_SLOT.with(|s| {
        let mut i = s.get();
        if i == usize::MAX {
            i = NEXT_SLOT.fetch_add(1, Relaxed).min(SLOTS - 1);
            s.set(i);
        }
        i
    });
    let a = &HEAP[i].0;
    if i < SLOTS - 1 {
        a.store(a.load(Relaxed) + d, Relaxed); // single writer: no locked instruction
    } else {
        a.fetch_add(d, Relaxed); // shared overflow slot
    }
}

/// 60.05 H7: bytes of the worker slab arrays' reserved capacity that no slot uses yet (worker/mod.rs Slab:
/// published when a slab grows). Counted in heap_bytes but never touched, so no RSS; host mode subtracts it.
pub static SLAB_UNTOUCHED: AtomicIsize = AtomicIsize::new(0);

/// Heap bytes in use (requested sizes), summed over all threads. Racy but never torn.
pub fn heap_bytes() -> usize {
    HEAP.iter().map(|s| s.0.load(Relaxed)).sum::<isize>().max(0) as usize
}

// ---------------------------------------------------------------- the pool's dirty-set rules (70.11 -> 70.25)

/// bytes per worker thread at most in the pool's dirty set, and at most 1/16 of the worker's memory budget (the 70.11
/// block cache's cap, kept by the pool; the cache itself is gone with the old allocator path, 60.18 #11)
const CACHE_BYTES: usize = 16 << 20;
/// 60.09 M2b most bytes held at memory level 2+ (cache_pause): the dirty set is cut at the transition and then
/// keeps only this much, so it adds at most 1 MiB per worker to USED (the shed rules' input) instead of
/// min(16 MiB, budget/16), and the drained buffers that level 2+ frees at once are still recycled (strict off:
/// download at --mem-budget 32M/128M, level 3: mmap+munmap+mremap 2.5-4.5 per MiB -> 13.7-15.3; echo 128M
/// (L1 -> L2 -> L1) 4.0-4.6 -> 5.6-7.1)
pub(crate) const L2_BYTES: usize = 1 << 20;

/// 70.25 the pool replaces the 70.11 block cache: same cap (CACHE_BYTES, 1/16 of the worker budget) for its dirty
/// set, same L2_BYTES at level 2+, released at the turn end (turn_end) and the idle sweep (pool::sweep).
pub fn cache_on() {
    let cap = match WORKER_BUDGET.load(Relaxed) {
        0 => CACHE_BYTES,
        b => CACHE_BYTES.min(b / 16),
    };
    // false (page size != 4096, or more than pool::MAX_POOLS workers): this thread stays on glibc, base-3 behaviour;
    // main's capability line says so (pool::refused)
    crate::pool::on(cap);
}
/// 70.25 wake rule: mapped pool chunks of this thread (the worker wakes for the idle sweep while > 0)
pub fn cache_held() -> usize {
    crate::pool::chunks()
}
/// 60.09 M2 at level 2+ the dirty set is cut to L2_BYTES in bounded batches from this turn's end on
pub fn cache_pause(off: bool) {
    crate::pool::pause(off)
}
/// 70.25 end of every worker loop turn: drain remote frees, bounded release, bounded unmap
#[inline]
pub fn turn_end() {
    #[cfg(not(feature = "pooltest"))]
    crate::pool::release();
    #[cfg(feature = "pooltest")]
    pt::release();
}
/// 70.25 wake rule: release work is left (the worker polls with timeout 0)
#[inline]
pub fn release_backlog() -> bool {
    crate::pool::backlog()
}

pub struct Counting;
// SAFETY: every method forwards to System with the same arguments and returns its result unchanged, so
// System's GlobalAlloc contract holds; the counting (account) never allocates (thread-local slot + atomic).
// 70.25 except the pool: alloc may return a pool block (pool.rs: page aligned,
// >= the request, zero for alloc_zeroed); dealloc/realloc of a pointer in a mapped pool chunk (pool::is_pool; only
// checked for sizes in the pool range, which every live pool block's layout is in: the soundness invariant, kept by
// realloc moving a block out of the pool whenever its new size or the thread does not fit) go to the pool, never to
// System; every other pointer goes to System as before.
impl Counting {
    #[inline(always)]
    unsafe fn alloc_(&self, l: Layout) -> *mut u8 {
        if crate::pool::in_range(l.size(), l.align()) {
            let p = crate::pool::alloc(l.size(), false);
            if !p.is_null() {
                account(l.size() as isize);
                return p;
            }
        }
        let p = System.alloc(l);
        if !p.is_null() {
            account(l.size() as isize);
        }
        p
    }
    #[inline(always)]
    unsafe fn alloc_zeroed_(&self, l: Layout) -> *mut u8 {
        // vec![0u8; rmax] at pressure levels (worker/input.rs) takes this path
        if crate::pool::in_range(l.size(), l.align()) {
            let p = crate::pool::alloc(l.size(), true); // a dirty block is cleared there; a clean one is zero pages
            if !p.is_null() {
                account(l.size() as isize);
                return p;
            }
        }
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            account(l.size() as isize);
        }
        p
    }
    #[inline(always)]
    unsafe fn dealloc_(&self, p: *mut u8, l: Layout) {
        if crate::pool::size_in_range(l.size()) && crate::pool::is_pool(p) {
            crate::pool::free(p, l.size()); // owner: dirty (counted at its class size there); else the remote stack
            account(-(l.size() as isize));
            return;
        }
        System.dealloc(p, l);
        account(-(l.size() as isize));
    }
    #[inline(always)]
    unsafe fn realloc_(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        // 70.25 2.1 the realloc matrix, by origin
        {
            use crate::pool;
            if pool::size_in_range(l.size()) && pool::is_pool(p) {
                // 1. same class on the owner: in place
                if pool::keeps(p, new, l.align()) {
                    account(new as isize - l.size() as isize);
                    return p;
                }
                // 2. other class, out of the pool range, or not the owner: move (pool or System by self.alloc); 5. if
                // both fail: null, the old block and the accounting unchanged
                // SAFETY: GlobalAlloc::realloc's contract: new > 0 and new rounded to l.align() does not overflow isize
                let q = self.alloc_(Layout::from_size_align_unchecked(new, l.align()));
                if !q.is_null() {
                    // SAFETY: q is a different live block of >= new bytes; p holds l.size() bytes
                    std::ptr::copy_nonoverlapping(p, q, l.size().min(new));
                    self.dealloc_(p, l);
                }
                return q;
            }
            // 3. System -> the pool range on a pool thread: a pool block + copy (every rbuf starts as a 4 KiB System
            // block; growing it by mremap would keep the connection's buffers in glibc)
            if pool::in_range(new, l.align()) {
                let q = pool::alloc(new, false);
                if !q.is_null() {
                    // SAFETY: q is a fresh pool block of >= new bytes; p is a live System block of layout l
                    std::ptr::copy_nonoverlapping(p, q, l.size().min(new));
                    System.dealloc(p, l);
                    account(new as isize - l.size() as isize);
                    return q;
                }
            }
            // 4. System -> anything else (or the pool failed): System.realloc as before
        }
        let q = System.realloc(p, l, new);
        if !q.is_null() {
            account(new as isize - l.size() as isize);
        }
        q
    }
}

/// 70.25 pooltest (test-only feature, never in a release): every allocator call is timed (pt::timed); identity otherwise
macro_rules! timed {
    ($e:expr) => {{
        #[cfg(feature = "pooltest")]
        {
            pt::timed(|| $e)
        }
        #[cfg(not(feature = "pooltest"))]
        {
            $e
        }
    }};
}

// SAFETY: see impl Counting above (its methods keep System's or the pool's contract; timed! only measures).
unsafe impl GlobalAlloc for Counting {
    #[inline]
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        timed!(self.alloc_(l))
    }
    #[inline]
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        timed!(self.alloc_zeroed_(l))
    }
    #[inline]
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        timed!(self.dealloc_(p, l))
    }
    #[inline]
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        timed!(self.realloc_(p, l, new))
    }
}

/// 70.25 pooltest (cargo feature, test-only, never in a release; the 70.24 trimtest method): every allocator call is
/// timed, and getrusage(RUSAGE_THREAD) ru_nvcsw before/after marks a call >= 200 us as BLOCKED (a voluntary switch: a
/// lock or mmap_lock wait, not a preemption). Calls are "in" a release when any worker's turn-end release (pool::release)
/// ran during them. Also: each release's own duration (the releasing worker is busy that long). FW_PT_MMAP_MAX=n
/// overrides M_MMAP_MAX (the 70.23 forced-arena repro). Reported in the metrics line (pt_*).
#[cfg(feature = "pooltest")]
pub mod pt {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use std::time::Instant;
    /// releases in progress, and started so far
    static ACTIVE: AtomicU64 = AtomicU64::new(0);
    static SEQ: AtomicU64 = AtomicU64::new(0);
    static IN_MAX: AtomicU64 = AtomicU64::new(0);
    static IN_BLK_MAX: AtomicU64 = AtomicU64::new(0);
    static OUT_MAX: AtomicU64 = AtomicU64::new(0);
    static OUT_BLK_MAX: AtomicU64 = AtomicU64::new(0);
    static REL_N: AtomicU64 = AtomicU64::new(0);
    static REL_MAX: AtomicU64 = AtomicU64::new(0);
    static REL_CPU_MAX: AtomicU64 = AtomicU64::new(0);
    /// chunk mappings (mmap 8 MiB + the alignment cuts + NOHUGEPAGE: mmap_lock for write) and the longest
    static MAP_N: AtomicU64 = AtomicU64::new(0);
    static MAP_MAX: AtomicU64 = AtomicU64::new(0);
    pub fn chunk_map(us: u64) {
        MAP_N.fetch_add(1, Relaxed);
        MAP_MAX.fetch_max(us, Relaxed);
    }
    fn cpu_us() -> u64 {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1000
    }
    /// by duration: < 0.5, < 1, < 2, < 5, < 10, < 20, < 50, < 100, >= 100 ms
    static HIST_IN: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
    static HIST_OUT: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
    static HIST_REL: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
    const EDGES_US: [u64; 8] = [500, 1000, 2000, 5000, 10000, 20000, 50000, 100000];
    pub fn mmap_max(max: usize) -> usize {
        std::env::var("FW_PT_MMAP_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(max)
    }
    fn nvcsw() -> i64 {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut ru) };
        ru.ru_nvcsw
    }
    fn bucket(us: u64) -> usize {
        EDGES_US.iter().position(|&e| us < e).unwrap_or(8)
    }
    #[inline(always)]
    pub fn timed<T>(f: impl FnOnce() -> T) -> T {
        let (a0, s0, v0, t) = (ACTIVE.load(Relaxed), SEQ.load(Relaxed), nvcsw(), Instant::now());
        let r = f();
        let us = t.elapsed().as_micros() as u64;
        let inside = a0 > 0 || SEQ.load(Relaxed) != s0;
        let blocked = us >= 200 && nvcsw() > v0;
        let (max, blk, hist) = if inside { (&IN_MAX, &IN_BLK_MAX, &HIST_IN) } else { (&OUT_MAX, &OUT_BLK_MAX, &HIST_OUT) };
        max.fetch_max(us, Relaxed);
        if blocked {
            blk.fetch_max(us, Relaxed);
            hist[bucket(us)].fetch_add(1, Relaxed);
        }
        r
    }
    pub fn release() {
        if !crate::pool::backlog() && !crate::pool::remote_pending() {
            return crate::pool::release(); // nothing to release: not a release window
        }
        SEQ.fetch_add(1, Relaxed);
        ACTIVE.fetch_add(1, Relaxed);
        let (t, c0) = (Instant::now(), cpu_us());
        crate::pool::release();
        let us = t.elapsed().as_micros() as u64;
        ACTIVE.fetch_sub(1, Relaxed);
        REL_N.fetch_add(1, Relaxed);
        REL_MAX.fetch_max(us, Relaxed);
        REL_CPU_MAX.fetch_max(cpu_us().saturating_sub(c0), Relaxed); // (elapsed includes preemption; this does not)
        HIST_REL[bucket(us)].fetch_add(1, Relaxed);
    }
    pub fn line() -> String {
        let h = |a: &[AtomicU64; 9]| a.iter().map(|x| x.load(Relaxed).to_string()).collect::<Vec<_>>().join(",");
        format!(
            " pt_releases={} pt_release_max_us={} pt_release_cpu_max_us={} pt_in_max_us={} pt_in_blk_max_us={} pt_out_max_us={} pt_out_blk_max_us={} pt_hist_in={} pt_hist_out={} pt_hist_rel={} pt_chunk_maps={} pt_chunk_map_max_us={}",
            REL_N.load(Relaxed),
            REL_MAX.load(Relaxed),
            REL_CPU_MAX.load(Relaxed),
            IN_MAX.load(Relaxed),
            IN_BLK_MAX.load(Relaxed),
            OUT_MAX.load(Relaxed),
            OUT_BLK_MAX.load(Relaxed),
            h(&HIST_IN),
            h(&HIST_OUT),
            h(&HIST_REL),
            MAP_N.load(Relaxed),
            MAP_MAX.load(Relaxed)
        )
    }
}

// ---------------------------------------------------------------- budget source

#[derive(Debug, PartialEq)]
pub enum Source {
    /// cgroup v2 directory whose memory.max/memory.high is the smallest limit on our path
    Cgroup(PathBuf),
    /// 80.01 cgroup v1 memory-controller directory whose memory.limit_in_bytes (or, for our own directory, the
    /// kernel's hierarchical_memory_limit) is the smallest limit on our path. Usage: memory.usage_in_bytes -
    /// total_inactive_file. v1 charges no socket buffers to the cgroup (unless kmem.tcp is limited), so they are
    /// neither in that usage nor under that limit: the budget then guards what the v1 OOM killer counts.
    /// `hidden` (M3): the limit is our hierarchical_memory_limit and below every limit we can see, so it belongs to
    /// an ancestor above the mount (e.g. a pod) whose usage includes siblings we cannot read: usage is still ours
    /// only (the budget stays that limit), and main warns and suggests --mem-budget.
    CgroupV1 { dir: PathBuf, hidden: bool },
    /// no cgroup limit: heap bytes + the host's TCP memory (/proc/net/sockstat)
    Host,
    /// 60.15 T03 P3: no cgroup limit, but our own cgroup v2 directory (memory.current + a memory.stat `sock` line, socket
    /// accounting not off): heap bytes + our cgroup's socket memory (memory.stat `sock`, TCP and UDP, our subtree only).
    /// A neighbour's TCP memory no longer counts (the kernel's host-wide tcp_mem pressure is B3's, --tcpmem-adapt).
    HostSock(PathBuf),
}

/// 80.01 v1 shows "no limit" as PAGE_COUNTER_MAX pages (9223372036854771712 with 4 KiB pages): this or more = none
const V1_UNLIMITED: u64 = 1 << 62;

fn read_limit(dir: &Path, file: &str) -> Option<u64> {
    let s = std::fs::read_to_string(dir.join(file)).ok()?;
    s.trim().parse().ok() // "max" -> None
}

/// The v2 path from /proc/self/cgroup ("0::/a/b").
pub fn cgroup_path(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("0::"))
}

/// 80.01 F7 cgroup layout from /proc/self/cgroup: "v2" (only the "0::" line), "v1" (only v1 hierarchies),
/// "hybrid" (both: v2 is mounted but the controllers, memory included, are usually on v1), "?" (empty).
pub fn cgroup_mode(text: &str) -> &'static str {
    let (mut v2, mut v1) = (false, false);
    for l in text.lines().filter(|l| !l.is_empty()) {
        if l.starts_with("0::") {
            v2 = true;
        } else {
            v1 = true;
        }
    }
    match (v1, v2) {
        (true, true) => "hybrid",
        (true, false) => "v1",
        (false, true) => "v2",
        (false, false) => "?",
    }
}

/// Smallest memory.max / memory.high on the path from `root`/`rel` (the leaf) up to `root` (inclusive).
pub fn cgroup_limit(root: &Path, rel: &str) -> Option<(u64, PathBuf)> {
    smallest_limit(root, root.join(rel.trim_start_matches('/')), &["memory.max", "memory.high"])
}

/// Smallest value of `files` in `dir` and its parents up to `root` (inclusive), with the directory it is in.
fn smallest_limit(root: &Path, mut dir: PathBuf, files: &[&str]) -> Option<(u64, PathBuf)> {
    let mut best: Option<(u64, PathBuf)> = None;
    loop {
        for &f in files {
            if let Some(v) = read_limit(&dir, f) {
                if best.as_ref().is_none_or(|b| v < b.0) {
                    best = Some((v, dir.clone()));
                }
            }
        }
        if dir == root || !dir.pop() || !dir.starts_with(root) {
            break;
        }
    }
    best
}

/// 80.01 v1 memory controller: (mount point, our directory). Our path is the "N:...memory...:/path" line of
/// /proc/self/cgroup; the mount is a /proc/self/mountinfo line with fstype "cgroup" and "memory" in its super
/// options, whose root field is the hierarchy path mounted there (a container sees its own cgroup as "/" or as
/// its full path, e.g. /docker/<id>). None if our path is not under that root, climbs out of it (another
/// cgroup namespace) or is not a directory under that mount: the visible directories are then not ours. deliberate: mount points with escaped
/// characters (\040) are not decoded (cgroup mounts never have them in practice).
pub fn cgroup_v1_dir(cgroup: &str, mountinfo: &str) -> Option<(PathBuf, PathBuf)> {
    let path = cgroup.lines().find_map(|l| {
        let mut f = l.splitn(3, ':');
        let (_, ctl, p) = (f.next()?, f.next()?, f.next()?);
        ctl.split(',').any(|c| c == "memory").then_some(p)
    })?;
    mountinfo.lines().find_map(|l| {
        let (pre, post) = l.split_once(" - ")?;
        let mut post = post.split(' ');
        let (fstype, _source, opts) = (post.next()?, post.next()?, post.next()?);
        if fstype != "cgroup" || !opts.split(',').any(|o| o == "memory") {
            return None;
        }
        let mut pre = pre.split(' ');
        let (root, mnt) = (pre.nth(3)?, pre.next()?);
        let rel = if root == "/" { path } else { path.strip_prefix(root).filter(|r| r.is_empty() || r.starts_with('/'))? };
        if rel.split('/').any(|c| c == "..") {
            return None;
        }
        // review: several memory mounts (a host-root bind and the container's own): only one shows our directory
        let mnt = PathBuf::from(mnt);
        let leaf = mnt.join(rel.trim_start_matches('/'));
        leaf.is_dir().then_some((mnt, leaf))
    })
}

/// 80.01 effective v1 limit: the smallest memory.limit_in_bytes from `leaf` up to the mount `root`, or the
/// leaf's hierarchical_memory_limit (memory.stat; the kernel's own minimum, which also sees ancestors above
/// the mount, e.g. a pod limit) if smaller. None = unlimited everywhere. The bool (M3): the limit comes only
/// from hierarchical_memory_limit, i.e. from an ancestor we cannot see (a tie goes to the visible walk).
pub fn cgroup_v1_limit(root: &Path, leaf: &Path) -> Option<(u64, PathBuf, bool)> {
    let walk = smallest_limit(root, leaf.to_path_buf(), &["memory.limit_in_bytes"]).map(|(v, d)| (v, d, false));
    let hier = std::fs::read(leaf.join("memory.stat"))
        .ok()
        .and_then(|s| field(&s, b"hierarchical_memory_limit "))
        .map(|v| (v, leaf.to_path_buf(), true));
    [walk, hier].into_iter().flatten().min_by_key(|b| b.0).filter(|b| b.0 < V1_UNLIMITED)
}

/// 80.01 the cgroup budget: v2 first (as before), then v1 (pure v1, or hybrid where v2 has no memory limit on
/// our path). `cgroup`, `mountinfo`: /proc/self/{cgroup,mountinfo}; `v2_root`: the v2 mount (/sys/fs/cgroup).
/// Parameters, not fixed paths, so the tests run on fake trees.
fn cgroup_budget(cgroup: &str, mountinfo: &str, v2_root: &Path) -> Option<(u64, Source)> {
    if let Some((b, dir)) = cgroup_path(cgroup).and_then(|p| cgroup_limit(v2_root, p)) {
        return Some((b, Source::Cgroup(dir)));
    }
    let (root, leaf) = cgroup_v1_dir(cgroup, mountinfo)?;
    cgroup_v1_limit(&root, &leaf).map(|(b, dir, hidden)| (b, Source::CgroupV1 { dir, hidden }))
}

/// 80.01 the sampler's files for a cgroup source: (usage, memory.stat, its inactive-file key). None = Host.
fn usage_files(src: &Source) -> Option<(PathBuf, PathBuf, &'static [u8])> {
    match src {
        Source::Cgroup(d) => Some((d.join("memory.current"), d.join("memory.stat"), b"inactive_file ")),
        // v1 memory.stat has both: inactive_file (this cgroup only) and total_inactive_file (with children, as usage)
        Source::CgroupV1 { dir: d, .. } => Some((d.join("memory.usage_in_bytes"), d.join("memory.stat"), b"total_inactive_file ")),
        Source::Host | Source::HostSock(_) => None,
    }
}

fn mem_total() -> u64 {
    let s = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    s.lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        .map_or(0, |k| k * 1024)
}

/// Budget and where usage is read from. `over`: --mem-budget (None = auto).
pub fn detect(over: Option<u64>) -> (u64, Source) {
    if let Some(v) = tcp_rmem_default() {
        RMEM_DEFAULT.store(v, Relaxed);
        LAZY.store(v + crate::worker::LAZY_CAP as usize <= 8 * STAGES[1].sock_cap as usize, Relaxed);
    }
    let read = |p| std::fs::read_to_string(p).unwrap_or_default();
    let cg = cgroup_budget(&read("/proc/self/cgroup"), &read("/proc/self/mountinfo"), Path::new("/sys/fs/cgroup"));
    let r = match (over, cg) {
        (Some(b), Some((_, src))) => (b, src),
        (Some(b), None) => (b, Source::Host),
        (None, Some((b, src))) => (b, src),
        (None, None) => (mem_total() / 2, Source::Host),
    };
    // 60.15 T03 P3: Host mode counts our own cgroup's socket memory when it can (else the host's, as before)
    let r = match r {
        (b, Source::Host) => match own_sock_stat_here() {
            Some(f) => {
                SOCK0.store(std::fs::read(&f).ok().and_then(|s| field(&s, b"sock ")).unwrap_or(0), Relaxed);
                (b, Source::HostSock(f.parent().map(Path::to_path_buf).unwrap_or_default()))
            }
            None => (b, Source::Host),
        },
        r => r,
    };
    if matches!(r.1, Source::Host | Source::HostSock(_)) {
        // r3 review: the baseline is taken here, before the workers accept anything (review: also for HostSock,
        // whose sampler falls back to sockstat if its memory.stat does not open)
        let t = ProcFile::open(Path::new("/proc/net/sockstat")).and_then(|mut f| host_tcp_pages(&mut f));
        TCP0.store(t.unwrap_or(0), Relaxed);
    }
    r
}

/// glibc's mmap threshold, fixed at startup (pin_mmap_threshold). Blocks of this size and more are
/// eligible for their own mapping, returned to the kernel on free (not guaranteed: a realloc can grow a
/// block in place in the arena, a fresh one can fit free arena space, and past M_MMAP_MAX the arena is used).
/// 70.03 16 KiB (was 1 MiB, 60.05 H7): a client's buffers (rbuf from 16 KiB up, obuf, bulk, pend) are then
/// their own mappings, not in a per-thread arena where one small block allocated during a peak pins every
/// freed buffer below it (free() only returns an arena's top). Measured (alloc-inv, REPORT-alloc.md): idle
/// 4.7 KiB/conn at 2 and 16 threads, 2000 and 10000 conns, also after a burst/close (1 MiB: 167-177);
/// 1.5 MiB anon after a 100x10 burst (1 MiB: 22-46); echo 10x10 peak -3% (idle-echo peak +3-6%: a header
/// page per block). Cost: one mmap + munmap per buffer
/// lifetime (a few hundred per 3 s run; the buffers stay while busy at level 0) and ~1.4 mappings per busy
/// stream. Replaces the idle2 trim thread (no thread, no timing). Not tied to worker/mod.rs SLAB_RESERVE (1 MiB).
pub const MMAP_THRESHOLD: usize = 16 << 10;
/// upper bound for glibc's M_MMAP_MAX (its default)
#[cfg(target_env = "gnu")]
const MMAP_MAX_CAP: usize = 65536;

/// 60.05 H7: pin glibc's mmap threshold at MMAP_THRESHOLD. glibc's default is dynamic: after an
/// mmapped block is freed it raises the mmap threshold to that size and the trim threshold to twice
/// it. After 10 MiB frame buffers were freed, each worker's arena kept a free top of 9-15 MiB
/// (a stress run: RSS 160 MiB at a live heap of 4 MiB). The cgroup counts those pages, so usage stayed
/// above level 2's exit with nothing left to shed, and admission stayed off. malloc_trim(0) did not
/// help (measured: 52 trims, no change; it releases free chunks in the bins, and an arena's top only
/// below the ratcheted trim threshold, ~20 MiB here). Setting the mmap threshold disables the ratchet
/// for both thresholds: M_TRIM_THRESHOLD stays at its default 128 KiB (nothing freed a big mmapped block
/// before main), so a free that leaves an arena top above it trims the top.
/// 70.03 M_MMAP_MAX = min(65536, vm.max_map_count / 4) (70.25: was / 2 before the pool; its chunks take another quarter,
/// pool::limits): with many small mmapped blocks the process can
/// reach the kernel's mapping limit (default 65530 on many hosts; ~45k busy streams). At that limit an
/// mmap fails and glibc's arena cannot grow either (a new heap or mprotect split is a mapping too):
/// malloc returns NULL and Rust aborts (measured on VPS1 with max_map_count 1024: SIGABRT, all
/// connections lost). Below its own M_MMAP_MAX glibc falls back to the arena instead (measured: max 500,
/// maps level off at ~640, 2000 streams, 0 errors). Half the limit leaves room for the arenas, thread
/// stacks, the binary and munmap splits. Must run before the workers allocate.
/// Some((threshold, max mmapped blocks, 0 = not set)) = applied (glibc only); None = not glibc or mallopt failed.
/// If M_MMAP_MAX cannot be set (or vm.max_map_count is unreadable), the threshold stays at 1 MiB (60.05 H7:
/// the ratchet fix without the many mappings).
pub fn pin_mmap_threshold() -> Option<(usize, usize)> {
    #[cfg(target_env = "gnu")]
    {
        // review: an unknown limit (no /proc) may be below the kernel default: then no cap and 1 MiB
        let limit = std::fs::read_to_string("/proc/sys/vm/max_map_count").ok().and_then(|s| s.trim().parse::<usize>().ok());
        // 70.25: glibc gets a quarter, the pool's chunks another (pool::limits): the same half in total
        // (deliberate: a binding as before 60.18 #11; `l / 4` inline changed main's register allocation, disasm_norm)
        let share = 4;
        let max = limit.map_or(0, |l| (l / share).min(MMAP_MAX_CAP));
        #[cfg(feature = "pooltest")]
        let max = pt::mmap_max(max); // 70.25 test-only: the forced-arena repro (FW_PT_MMAP_MAX)
        let set = |opt: libc::c_int, v: usize| unsafe { libc::mallopt(opt, v as libc::c_int) == 1 };
        // (SAFETY of `set`: mallopt takes two integers; this runs before the worker threads exist)
        let capped = max > 0 && set(libc::M_MMAP_MAX, max);
        if capped && set(libc::M_MMAP_THRESHOLD, MMAP_THRESHOLD) {
            Some((MMAP_THRESHOLD, max))
        } else if set(libc::M_MMAP_THRESHOLD, 1 << 20) {
            Some((1 << 20, if capped { max } else { 0 })) // 0: M_MMAP_MAX not set (glibc default or tunable)
        } else {
            None
        }
    }
    #[cfg(not(target_env = "gnu"))]
    {
        None
    }
}

/// Host mode: TCP memory (pages) of the host at detect(), the sampler's first baseline.
static TCP0: AtomicU64 = AtomicU64::new(0);
/// 60.15 T03 P3 HostSock: our cgroup's `sock` bytes at detect() (before the first accept), the first baseline (then
/// taken again while idle, as TCP0: a shared cgroup's steady sockets of other processes do not count)
static SOCK0: AtomicU64 = AtomicU64::new(0);
/// 60.15 T03 P3 HostSock: memory.stat is read at most this often (8-11 us per read idle, 2 vCPU; between reads the last
/// value is used)
const SOCK_READ_EVERY: Duration = Duration::from_millis(5);

/// Host TCP memory in pages (/proc/net/sockstat "TCP: ... mem N").
fn host_tcp_pages(s: &mut ProcFile) -> Option<u64> {
    let t = s.read();
    let l = t.split(|&b| b == b'\n').find(|l| l.starts_with(b"TCP:"))?;
    let s = std::str::from_utf8(l).ok()?;
    s.split_whitespace().skip_while(|w| *w != "mem").nth(1)?.parse::<u64>().ok()
}

// ---------------------------------------------------------------- sampler

/// Reads a small /proc or /sys file through a kept-open fd (pread at 0: one syscall).
struct ProcFile(std::fs::File, Vec<u8>);
impl ProcFile {
    fn open(p: &Path) -> Option<ProcFile> {
        std::fs::File::open(p).ok().map(|f| ProcFile(f, vec![0; 8192]))
    }
    fn read(&mut self) -> &[u8] {
        use std::os::unix::fs::FileExt;
        let n = self.0.read_at(&mut self.1, 0).unwrap_or(0);
        &self.1[..n]
    }
}

fn field(text: &[u8], key: &[u8]) -> Option<u64> {
    text.split(|&b| b == b'\n').find_map(|l| {
        let rest = l.strip_prefix(key)?;
        std::str::from_utf8(rest).ok()?.split_whitespace().next()?.parse().ok()
    })
}

/// Level for `permille` given the current level (hysteresis: enter at `enter`, leave below `exit`).
pub fn next_level(cur: usize, permille: u64) -> usize {
    let mut l = cur;
    while l + 1 < STAGES.len() && permille >= STAGES[l + 1].enter as u64 {
        l += 1;
    }
    while l > 0 && permille < STAGES[l].exit as u64 {
        l -= 1;
    }
    l
}

/// deliberate: at most one level-change line per LOG_EVERY (levels can flap under steady load);
/// changes into and out of the critical level, and back to the base level, are always logged
const LOG_EVERY: Duration = Duration::from_secs(5);

/// 70.05 the sampler's log lines go through a bounded queue to a logger thread: a blocked stderr (a full
/// pipe nobody reads) stalled the sampler, so no later level change happened. A full queue drops the line
/// and the next one that fits says how many were dropped.
struct Log {
    tx: std::sync::mpsc::SyncSender<String>,
    dropped: u32,
}
impl Log {
    fn start() -> Log {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(16);
        std::thread::Builder::new()
            .name("memlog".into())
            .spawn(move || {
                for l in rx {
                    // 60.05 H3: eprintln! panics on a write error (a dead log pipe), and panic = "abort" would
                    // end the server; a failed log write is dropped instead
                    // 60.12 review: one write (writeln! writes the newline separately; main's log_bounded lines bypass
                    // the std lock and could land in between)
                    let _ = std::io::stderr().write_all((l + "\n").as_bytes());
                }
            })
            .expect("spawn mem logger");
        Log { tx, dropped: 0 }
    }
    /// 60.24 a line of level `lvl` (filtered by --log-level)
    fn send(&mut self, lvl: crate::logs::Level, mut l: String) {
        if !crate::logs::on(lvl) {
            return;
        }
        if self.dropped > 0 {
            l += &format!(" ({} earlier log lines dropped)", self.dropped);
        }
        match self.tx.try_send(l) {
            Ok(()) => self.dropped = 0,
            Err(_) => self.dropped += 1,
        }
    }
}

/// 60.59 TcpExt TCPMemoryPressures and TCPMemoryPressuresChrono (ms) from the text of /proc/net/netstat: how often this
/// network namespace's sockets took the host into TCP memory pressure since boot, and the time spent in it (added when
/// a period ends). No allocation (the sampler reads it once a second).
fn tcp_pressures(text: &[u8]) -> Option<(u64, u64)> {
    let mut l = text.split(|&b| b == b'\n').filter(|l| l.starts_with(b"TcpExt:"));
    let (names, values) = (std::str::from_utf8(l.next()?).ok()?, std::str::from_utf8(l.next()?).ok()?);
    let (mut n, mut ms) = (None, None);
    for (k, v) in names.split_whitespace().zip(values.split_whitespace()) {
        match k {
            "TCPMemoryPressures" => n = v.parse().ok(),
            "TCPMemoryPressuresChrono" => ms = v.parse().ok(),
            _ => {}
        }
    }
    Some((n?, ms?))
}

/// 60.59 one log line when the host enters kernel TCP memory pressure: the first entry at once, then at most one line
/// per PRESS_LOG_EVERY, which counts the entries since the last line (pressure can flap many times a second).
struct PressLog {
    file: Option<ProcFile>,
    read_at: Option<Instant>, // the last read attempt, good or not (None: none yet)
    seen: Option<u64>,        // TCPMemoryPressures at the last good read (None: none yet; the first value is the baseline)
    pending: u64,             // entries not logged yet
    logged_at: Option<Instant>,
}

const PRESS_READ_EVERY: Duration = Duration::from_secs(1);
const PRESS_LOG_EVERY: Duration = Duration::from_secs(60);

impl PressLog {
    fn new() -> PressLog {
        // (16 KiB: the file is about 3 KiB on Linux 6.x, the two TcpExt lines come first)
        let file = std::fs::File::open("/proc/net/netstat").ok().map(|f| ProcFile(f, vec![0; 16 << 10]));
        PressLog { file, read_at: None, seen: None, pending: 0, logged_at: None }
    }

    /// `count` = TCPMemoryPressures now. Some(n): log a line for n entries.
    fn note(&mut self, count: u64, now: Instant) -> Option<u64> {
        self.pending += count.saturating_sub(self.seen.unwrap_or(count)); // (a counter that went back: a new namespace; no entry)
        self.seen = Some(count);
        if self.pending == 0 || self.logged_at.is_some_and(|t| now.saturating_duration_since(t) < PRESS_LOG_EVERY) {
            return None;
        }
        self.logged_at = Some(now);
        Some(std::mem::take(&mut self.pending))
    }

    /// true at most once per PRESS_READ_EVERY: a read may go now. The gate is on attempts, good or not: a file without
    /// the counters is not read again every sampler turn (review).
    fn due(&mut self, now: Instant) -> bool {
        if self.read_at.is_some_and(|t| now.saturating_duration_since(t) < PRESS_READ_EVERY) {
            return false;
        }
        self.read_at = Some(now);
        true
    }

    /// called every sampler turn; reads the file at most once per PRESS_READ_EVERY
    fn poll(&mut self, log: &mut Log) {
        let now = Instant::now();
        if !self.due(now) {
            return;
        }
        let Some((count, _)) = self.file.as_mut().and_then(|f| tcp_pressures(f.read())) else { return };
        if let Some(n) = self.note(count, now) {
            log.send(crate::logs::Level::Warn, press_text(n));
        }
    }
}

fn press_text(n: u64) -> String {
    let times = if n == 1 { String::new() } else { format!(" {n} times since the last such line") };
    format!(
        "finalwisp: warning: the host entered kernel TCP memory pressure{times}: while it lasts the kernel throttles \
         every TCP socket on this host, so all clients slow down. It comes from many streams with full socket buffers \
         (downloads that slow clients do not read, bulk echo). What helps: fewer parallel streams per client \
         (--max-streams-per-conn), --no-splice when the clients are far away, more RAM or a larger net.ipv4.tcp_mem \
         (see the docs page memory.md, small hosts)"
    )
}

// ---------------------------------------------------------------- 20.31 B3 host TCP memory adaptation

/// 20.31 --tcpmem-adapt: the host's TCP memory (/proc/net/sockstat) against net.ipv4.tcp_mem (read once at startup;
/// the server never writes sysctls). Near the kernel's pressure threshold the sampler publishes TCP level 1
/// (TCP_LEVEL; (b) after the benchmark: at memory level 0 the workers then apply the level-1 socket caps and
/// (b2) the level-1 credit (cap_level/stage), through the same set_level path, so sizes are saved and restored once; queues, keep,
/// streams stay level 0). Never above level 1 (parent 2026-10-27: kernel TCP pressure is not OOM; level 2
/// would refuse streams).
pub struct TcpAdapt {
    /// net.ipv4.tcp_mem (pages): no pressure below [0], pressure from [1], hard limit [2]
    pub mem: [u64; 3],
    /// 20.31 guard (a): our own cgroup v2 memory.stat (its `sock` line = our socket memory, TCP and UDP). Required:
    /// without it the adaptation is off (parent 2026-10-27: capping us when our share is unknown can cost us for
    /// someone else's pressure)
    pub own_stat: PathBuf,
}

/// enter TCP level 1 at this share (per mille) of tcp_mem[1]: just below the kernel's pressure threshold
pub const TCP_ENTER_PM: u64 = 900;
/// enter only while our own share of the host's TCP memory is at least this (per mille; guard (a)): capping our sockets
/// cannot end a pressure that other processes cause. Checked on entry only: once capped our share falls by design.
pub const TCP_OWN_MIN_PM: u64 = 250;
/// deliberate: TCP level 1 is left only this long after it was entered (premise: flapping 1 <-> 0 cost upload 60%)
pub const TCP_DWELL_DOWN: Duration = Duration::from_secs(2);
/// 20.31 (iii) our heap growth counts toward the exit only this long into an episode (review: bounded, 5 x the dwell)
pub const TCP_MOVED_FOR: Duration = Duration::from_secs(10);

impl TcpAdapt {
    pub fn enter_pages(&self) -> u64 {
        self.mem[1] * TCP_ENTER_PM / 1000
    }
    /// leave below tcp_mem[0] (where the kernel leaves pressure), and in any case 10% under the entry
    pub fn exit_pages(&self) -> u64 {
        self.mem[0].min(self.enter_pages() - self.enter_pages() / 10)
    }
}

/// 20.31 next TCP level (0 or 1). `own_pm`: our share of the host's TCP pages (None = unknown: not entered).
pub fn tcp_next(cur: usize, pages: u64, own_pm: Option<u64>, t: &TcpAdapt, since_change: Duration) -> usize {
    if cur == 0 {
        (pages >= t.enter_pages() && own_pm.is_some_and(|o| o >= TCP_OWN_MIN_PM)) as usize
    } else if pages < t.exit_pages() && since_change >= TCP_DWELL_DOWN {
        0
    } else {
        1
    }
}

/// 20.31 tcp_mem from its sysctl text: three page counts, 0 < [0] <= [1] <= [2].
pub fn parse_tcp_mem(s: &str) -> Option<[u64; 3]> {
    let v: Vec<u64> = s.split_whitespace().map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let m: [u64; 3] = v.try_into().ok()?;
    (m[0] > 0 && m[0] <= m[1] && m[1] <= m[2]).then_some(m)
}

/// 20.31 our own cgroup v2 memory.stat if it has a `sock` line (the memory controller is on for our cgroup).
/// 60.15 T03 P3: and memory.current in the same directory: the real root cgroup has a memory.stat (everyone's sockets)
/// but no memory.current; and socket accounting not off (`cgroup.memory=nosocket` on the kernel command line: sock
/// stays 0).
fn own_sock_stat(cgroup: &str, cmdline: Option<&str>, v2_root: &Path) -> Option<PathBuf> {
    // review: an unreadable /proc/cmdline (None) is not proof that socket accounting is on
    let nosocket =
        cmdline?.split_whitespace().filter_map(|w| w.strip_prefix("cgroup.memory=")).any(|v| v.split(',').any(|o| o == "nosocket"));
    let dir = v2_root.join(cgroup_path(cgroup)?.trim_start_matches('/'));
    let f = dir.join("memory.stat");
    (!nosocket && dir.join("memory.current").is_file() && field(&std::fs::read(&f).ok()?, b"sock ").is_some()).then_some(f)
}

/// 60.15 T03 P3 /proc/self/cgroup and /proc/cmdline for own_sock_stat
fn own_sock_stat_here() -> Option<PathBuf> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok();
    own_sock_stat(&std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default(), cmdline.as_deref(), Path::new("/sys/fs/cgroup"))
}

/// 20.31 the TcpAdapt for this host, or why not. Our cgroup v2 memory.stat is read in every budget mode (also host
/// mode: a systemd service or container is in a v2 cgroup with the memory controller on most distros).
pub fn tcp_adapt_setup() -> Result<TcpAdapt, String> {
    // (only the initial network namespace shows tcp_mem: a container with its own netns cannot read it)
    let mem = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_mem")
        .ok()
        .and_then(|s| parse_tcp_mem(&s))
        .ok_or("net.ipv4.tcp_mem is unreadable (not the host's network namespace?)")?;
    ProcFile::open(Path::new("/proc/net/sockstat")).and_then(|mut f| host_tcp_pages(&mut f)).ok_or("/proc/net/sockstat is unreadable")?;
    let own_stat = own_sock_stat_here().ok_or(
        "share unknown: no own cgroup v2 memory.stat with a sock line (cgroup v1, no memory controller, the root cgroup, \
         cgroup.memory=nosocket, or /proc/cmdline unreadable)",
    )?;
    Ok(TcpAdapt { mem, own_stat })
}

/// 20.31 for metrics.rs: adaptation on, TCP level, host TCP pages, our share (per mille; u64::MAX = not read yet: it is
/// read only near the threshold; u64::MAX - 1 = the read failed), entries
/// into TCP level 1, ms at TCP level 1 before the current episode, and when it began (metrics::now_ms). Sampler-written.
pub static TCP_ON: AtomicBool = AtomicBool::new(false);
pub static TCP_LEVEL: AtomicU8 = AtomicU8::new(0);
pub static TCP_PAGES: AtomicU64 = AtomicU64::new(0);
/// 20.31 (iii) our heap growth since the episode began (pages; counted toward the exit)
pub static TCP_MOVED: AtomicU64 = AtomicU64::new(0);
pub static TCP_OWN_PM: AtomicU64 = AtomicU64::new(u64::MAX);
static TCP_ENTERS: AtomicU64 = AtomicU64::new(0);
static TCP_L1_MS: AtomicU64 = AtomicU64::new(0);
static TCP_L1_AT: AtomicU64 = AtomicU64::new(0);

/// 20.31 (entries into TCP level 1, ms at TCP level 1) up to `now` (metrics::now_ms)
pub fn tcp_times(now: u64) -> (u64, u64) {
    let (enters, mut ms, on, at) =
        times_read(now, || (TCP_ENTERS.load(Relaxed), TCP_L1_MS.load(Relaxed), TCP_LEVEL.load(Relaxed) > 0, TCP_L1_AT.load(Relaxed)));
    if on {
        ms += now.saturating_sub(at);
    }
    (enters, ms)
}

/// Start the sampler thread. Workers are woken through their inboxes when the level changes.
/// 20.31 `tcp`: --tcpmem-adapt (main checked SO_BUF_LOCK and the budget).
pub fn start(budget: u64, src: Source, peers: Arc<Vec<Arc<Inbox>>>, tcp: Option<TcpAdapt>) {
    TCP_ON.store(tcp.is_some(), Relaxed);
    std::thread::Builder::new().name("mem".into()).spawn(move || sampler(budget, src, peers, tcp)).expect("spawn mem sampler");
}

fn sampler(budget: u64, src: Source, peers: Arc<Vec<Arc<Inbox>>>, tcp: Option<TcpAdapt>) -> ! {
    // SAFETY: sysconf has no memory arguments
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    // 80.01 v2: memory.current + inactive_file; v1: memory.usage_in_bytes + total_inactive_file (usage_files)
    let files = usage_files(&src);
    let (mut cur, mut stat, mut sock) = match &files {
        Some((u, s, _)) => (ProcFile::open(u), ProcFile::open(s), None),
        None => (None, None, None),
    };
    // 60.15 T03 P3 HostSock: our cgroup's memory.stat (`sock`); if it does not open: the host's TCP memory, as Host
    let mut own_sock = match &src {
        Source::HostSock(d) => ProcFile::open(&d.join("memory.stat")),
        _ => None,
    };
    let mut log = Log::start();
    // 60.16 review: a cgroup usage file that does not open falls back to host accounting (heap + host TCP above the
    // idle baseline), and says so naming that file (it warned about sockstat, which it had not opened)
    if let (Some((u, _, _)), None) = (&files, &cur) {
        log.send(
            crate::logs::Level::Warn,
            format!("finalwisp: memory: opening {} failed; counting heap + host TCP memory (/proc/net/sockstat) instead", u.display()),
        );
    }
    if let (Source::HostSock(d), None) = (&src, &own_sock) {
        log.send(
            crate::logs::Level::Warn,
            format!(
                "finalwisp: memory: opening {}/memory.stat failed; counting heap + host TCP memory (/proc/net/sockstat) instead",
                d.display()
            ),
        );
    }
    if cur.is_none() && own_sock.is_none() {
        sock = ProcFile::open(Path::new("/proc/net/sockstat"));
    }
    let (cur_name, inactive_key) = match &files {
        Some((u, _, k)) => (u.file_name().map_or(String::new(), |n| n.to_string_lossy().into_owned()), *k),
        None => (String::new(), &b""[..]),
    };
    let stat_name = format!("memory.stat {}", String::from_utf8_lossy(inactive_key).trim_end());
    // 20.31 host TCP pages for --tcpmem-adapt: host mode reads them already (sock); cgroup mode opens sockstat here
    let mut tsock = if tcp.is_some() && sock.is_none() { ProcFile::open(Path::new("/proc/net/sockstat")) } else { None };
    let mut own = tcp.as_ref().and_then(|t| ProcFile::open(&t.own_stat));
    let (mut tl, mut tl_at, mut own_at, mut own_pm) = (0usize, Instant::now(), Instant::now() - Duration::from_secs(1), None);
    let (mut last_tpages, mut own_warned, mut own_read, mut heap0) = (0u64, false, false, 0u64);
    let floor = floor(budget);
    if floor > 0 {
        LEVEL.store(floor as u8, Relaxed);
        for p in peers.iter() {
            p.wake();
        }
    }
    let (mut level, mut inactive, mut stat_at) = (floor, 0u64, Instant::now() - Duration::from_secs(1));
    // 20.31 `ml` = the memory level (its own hysteresis and dwell), published as LEVEL; the TCP level is published on
    // its own (TCP_LEVEL: (b) socket caps, (b2) + credit, at memory level 0, mem::cap_level)
    let (mut logged_at, mut quiet, mut changed_at, mut ml) = (Instant::now() - LOG_EVERY, 0u32, Instant::now(), floor);
    // review F: host mode counts only TCP memory above a baseline: the host's at detect(), taken again
    // once this server has had no clients for a second (its closed sockets drained; then all of it is
    // others'). Not lowered while clients are connected: that would absorb our own pages (r3 review).
    let mut dwell = Dwell::new();
    let mut tcp0 = TCP0.load(Relaxed);
    let (mut sock0, mut sock_b, mut sock_at) = (SOCK0.load(Relaxed), 0u64, Instant::now() - Duration::from_secs(1));
    // (60.16 review) the cgroup fallback has no detect() baseline: take the host's TCP pages now (our few startup
    // sockets count as others' until the idle re-baseline), not 0 (all host TCP memory would count as ours). Host and
    // HostSock keep detect's TCP0, also a real 0 (review)
    if matches!(src, Source::Cgroup(_) | Source::CgroupV1 { .. }) && tcp0 == 0 {
        tcp0 = sock.as_mut().and_then(host_tcp_pages).unwrap_or(0);
    }
    let mut idle_since: Option<Instant> = None;
    let low = STAGES[1].enter as u64 * budget / 1000;
    // 70.05 a failed read keeps the last good value (was 0: the level could drop while memory was high)
    // 60.16: one warning per file (a single flag hid a later failure of another file); at most 3 names
    let (mut last_raw, mut last_tcp, mut last_sock, mut warned) = (0u64, 0u64, 0u64, Vec::<String>::new());
    // `fallback`: what a failed read gives (60.16 review: the warning says it; memory.stat gives no credit, 0)
    let mut keep = |v: Option<u64>, last: &mut u64, what: &str, fallback: &str, log: &mut Log| {
        match v {
            Some(v) => *last = v,
            None if !warned.iter().any(|w| w == what) => {
                warned.push(what.to_string());
                log.send(crate::logs::Level::Warn, format!("finalwisp: memory: reading {what} failed; {fallback} (logged once per file)"));
            }
            None => {}
        }
        *last
    };
    const KEPT: &str = "the last value is kept";
    let mut press = PressLog::new(); // 60.59
    loop {
        press.poll(&mut log);
        let mut host_pages = None;
        let used = if let Some(c) = cur.as_mut() {
            let raw = keep(field(c.read(), b""), &mut last_raw, &cur_name, KEPT, &mut log);
            // memory.current includes page cache; above the first threshold subtract the reclaimable
            // inactive file pages (memory.stat is costlier: read at most every 100 ms)
            if raw >= low {
                if stat_at.elapsed() >= Duration::from_millis(100) {
                    stat_at = Instant::now();
                    // review: a failed read gives no credit (0), not the last one: it is subtracted, and keeping
                    // a stale credit after the cache was reclaimed would understate usage
                    let v = stat.as_mut().and_then(|s| field(s.read(), inactive_key));
                    let mut none = 0;
                    keep(v, &mut none, &stat_name, "no inactive-file credit (0) until it reads again", &mut log);
                    inactive = v.unwrap_or(0);
                }
                raw.saturating_sub(inactive)
            } else {
                raw
            }
        } else {
            // 60.05 H7: minus the untouched part of the slab reservations (worker/mod.rs Slab, SLAB_RESERVE)
            let heap = heap_bytes().saturating_sub(SLAB_UNTOUCHED.load(Relaxed).max(0) as usize) as u64;
            // review F: the baselines are taken again once this server has had no clients for a second; checked after
            // the read (review: a client arriving between the check and the read would enter the baseline)
            let mut idle = || {
                if peers.iter().all(|p| p.load.load(Relaxed) == 0) {
                    idle_since.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(1)
                } else {
                    idle_since = None;
                    false
                }
            };
            if let Some(f) = own_sock.as_mut() {
                // 60.15 T03 P3 HostSock: heap + our cgroup's socket bytes above its idle baseline
                if sock_at.elapsed() >= SOCK_READ_EVERY {
                    sock_at = Instant::now();
                    sock_b = keep(field(f.read(), b"sock "), &mut last_sock, "memory.stat sock", KEPT, &mut log);
                }
                if idle() {
                    sock0 = sock_b;
                }
                heap + sock_b.saturating_sub(sock0)
            } else {
                let tcp = keep(sock.as_mut().and_then(host_tcp_pages), &mut last_tcp, "/proc/net/sockstat", KEPT, &mut log);
                host_pages = Some(tcp);
                if idle() {
                    tcp0 = tcp;
                }
                heap + tcp.saturating_sub(tcp0) * page
            }
        };
        let pm = used.saturating_mul(1000) / budget.max(1);
        USED.store(used, Relaxed);
        // review H: step down only after a dwell; step up at once. 60.15 T03: the dwell doubles per flap (Dwell)
        let nml = dwell.next(ml, next_level(ml, pm).max(floor), changed_at, Instant::now());
        if nml != ml {
            (ml, changed_at) = (nml, Instant::now());
        }
        // 20.31 the TCP level (0 or 1), published as TCP_LEVEL (socket caps + credit only: cap_level)
        let old_tl = tl;
        let mut tpages = 0;
        if let Some(t) = tcp.as_ref() {
            tpages = match host_pages {
                Some(p) => p,
                None => keep(tsock.as_mut().and_then(host_tcp_pages), &mut last_tpages, "/proc/net/sockstat", KEPT, &mut log),
            };
            if tl == 0 && tpages >= t.enter_pages() && own_at.elapsed() >= Duration::from_millis(100) {
                // guard (a): our cgroup's socket memory (memory.stat is costlier: only near the threshold, <= 10/s)
                own_at = Instant::now();
                own_read = true;
                let sock = own.as_mut().and_then(|f| field(f.read(), b"sock "));
                // review: a read that fails, or a sock count of 0 while we have connections (cgroup.memory=nosocket),
                // is an unknown share: not entered, logged once
                let ours = peers.iter().any(|p| p.load.load(Relaxed) > 0);
                own_pm = sock.filter(|&b| b > 0 || !ours).map(|b| b * 1000 / (tpages * page).max(1));
                if own_pm.is_none() && !own_warned {
                    own_warned = true;
                    log.send(
                        crate::logs::Level::Warn,
                        "finalwisp: tcpmem adapt: our socket memory (memory.stat sock) is unreadable or 0; not capping \
                              while it is unknown (logged once)"
                            .to_string(),
                    );
                }
            }
            // 20.31 (iii): during an episode our heap growth since its start counts as TCP pages for the exit. The caps move
            // granted data from kernel socket buffers into our heap (pend: credit granted at level 0 cannot be taken back);
            // without this the host pages fell under the exit within the dwell, level 0 granted full credit again and the
            // next entry moved it again (loopback upload 10x10: 3 entries in 6 s, peak RSS 7 -> 227 MiB). All heap growth
            // counts, not only pend (deliberate: one counter). Review (review): unrelated heap growth could then hold
            // the episode indefinitely, so it counts only for the first TCP_MOVED_FOR of an episode; after that the host
            // pages alone decide (at worst one re-grant per TCP_MOVED_FOR instead of one per dwell).
            let heap_now = heap_bytes().saturating_sub(SLAB_UNTOUCHED.load(Relaxed).max(0) as usize) as u64;
            let moved = if tl > 0 && tl_at.elapsed() < TCP_MOVED_FOR { heap_now.saturating_sub(heap0) / page } else { 0 };
            tl = tcp_next(tl, tpages + moved, own_pm, t, tl_at.elapsed());
            if tl > 0 && old_tl == 0 {
                heap0 = heap_now;
            }
            TCP_MOVED.store(if tl > 0 { moved } else { 0 }, Relaxed);
            TCP_PAGES.store(tpages, Relaxed);
            TCP_OWN_PM.store(
                match (own_read, own_pm) {
                    (false, _) => u64::MAX,
                    (true, None) => u64::MAX - 1,
                    (true, Some(o)) => o,
                },
                Relaxed,
            );
            if tl != old_tl {
                // review: the episode times and TCP_LEVEL in one times_write (60.29: tcp_times reads
                // them as one set), then the wakeups (the workers compare cap_level: (b)), logged last (60.05 H3)
                tl_at = Instant::now();
                times_write(|now| {
                    if tl > 0 {
                        TCP_ENTERS.store(TCP_ENTERS.load(Relaxed) + 1, Relaxed);
                        TCP_L1_AT.store(now, Relaxed);
                    } else {
                        TCP_L1_MS.store(TCP_L1_MS.load(Relaxed) + now.saturating_sub(TCP_L1_AT.load(Relaxed)), Relaxed);
                    }
                    TCP_LEVEL.store(tl as u8, Relaxed);
                });
                for p in peers.iter() {
                    p.wake();
                }
                log.send(
                    crate::logs::Level::Info,
                    format!(
                        "finalwisp: tcp level {old_tl} -> {tl} (host TCP memory {tpages} of {} pages tcp_mem[1], {moved} pages moved \
                     into our heap, own share {})",
                        t.mem[1],
                        own_pm.map_or("unknown".to_string(), |o| format!("{}%", o / 10))
                    ),
                );
            }
        }
        let l = ml;
        if l != level {
            let log_it = logged_at.elapsed() >= LOG_EVERY || l == floor || l == STAGES.len() - 1 || level == STAGES.len() - 1;
            let old = level;
            level = l;
            // 60.05 H3: publish and wake first, log after: a blocked stderr must not delay the new level. 60.29: the
            // store and its time accounting (note_level, a few stores) in one times_write, before the wakeups
            times_write(|now| {
                LEVEL.store(l as u8, Relaxed);
                note_level(old, now); // 60.12
            });
            for p in peers.iter() {
                p.wake();
            }
            if log_it {
                let more = if quiet > 0 { format!(", {quiet} changes not logged") } else { String::new() };
                let tcp_note = match tcp.as_ref() {
                    Some(t) => format!(
                        ", host TCP memory {tpages} of {} pages (tcp_mem[1]), tcp level {tl}, own share {}",
                        t.mem[1],
                        own_pm.map_or("unknown".to_string(), |o| format!("{}%", o / 10))
                    ),
                    None => String::new(),
                };
                log.send(
                    if l >= 2 { crate::logs::Level::Warn } else { crate::logs::Level::Info },
                    format!(
                        "finalwisp: memory level {old} -> {l} (in use {} MiB of {} MiB budget, heap {} MiB{tcp_note}{more})",
                        used >> 20,
                        budget >> 20,
                        heap_bytes().saturating_sub(SLAB_UNTOUCHED.load(Relaxed).max(0) as usize) >> 20
                    ),
                );
                (logged_at, quiet) = (Instant::now(), 0);
            } else {
                quiet += 1;
            }
        }
        // deliberate: 20 ms far from the first threshold, 5 ms near it, 2 ms under pressure
        let near_tcp = tcp.as_ref().is_some_and(|t| tpages >= t.exit_pages() * 3 / 4); // 20.31
        let ms = if level > floor || tl > 0 || pm >= 400 {
            2
        } else if pm >= 250 || near_tcp {
            5
        } else {
            20
        };
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// 60.59 the TCP memory pressure line: the first entry at once, then at most one line per minute with the count
    #[test]
    fn tcp_pressure_line_is_rate_limited() {
        let text = b"TcpExt: SyncookiesSent TCPMemoryPressures TCPMemoryPressuresChrono TCPAbortOnData\nTcpExt: 0 7 1234 9\nIpExt: InNoRoutes\nIpExt: 0\n";
        assert_eq!(tcp_pressures(text), Some((7, 1234)));
        assert_eq!(tcp_pressures(b"TcpExt: A B\nTcpExt: 1 2\n"), None, "a kernel without the counters");
        assert_eq!(tcp_pressures(b""), None);
        assert_eq!(tcp_pressures(b"TcpExt: TCPMemoryPressures TCPMemoryPressuresChrono\n"), None, "a cut read");
        // the real file on this host parses (Linux 4.13+ has both counters)
        let real = std::fs::read("/proc/net/netstat").unwrap();
        assert!(real.len() < 16 << 10 && tcp_pressures(&real).is_some(), "{} bytes", real.len());
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut p = PressLog { file: None, read_at: None, seen: None, pending: 0, logged_at: None };
        assert!(p.due(t0) && !p.due(t0) && !p.due(t0 + Duration::from_millis(999)), "one read a second, also before a good read");
        assert!(p.due(at(1)) && !p.due(at(1)) && p.seen.is_none());
        assert_eq!(p.note(7, at(0)), None, "the count at startup is the baseline, not an entry");
        assert_eq!(p.note(7, at(1)), None);
        assert_eq!(p.note(8, at(2)), Some(1), "the first entry: at once");
        assert_eq!(p.note(11, at(3)), None, "inside the minute");
        assert_eq!(p.note(12, at(30)), None);
        assert_eq!(p.note(12, at(61)), None, "still inside the minute after the line at 2 s");
        assert_eq!(p.note(12, at(62)), Some(4), "the entries since the last line, once the minute is over");
        assert_eq!(p.note(12, at(200)), None, "no entry, no line");
        assert_eq!(p.note(13, at(201)), Some(1));
        assert_eq!(p.note(2, at(300)), None, "a counter that went back is no entry");
        assert_eq!(p.note(3, at(301)), Some(1));
        let one = press_text(1);
        assert!(
            one.starts_with("finalwisp: warning: the host entered kernel TCP memory pressure: while") && one.contains("net.ipv4.tcp_mem")
        );
        assert!(press_text(4).contains("pressure 4 times since the last such line: "));
        assert!(!one.contains("  ") && !one.contains('\n'), "one line, single spaces (review): {one}");
    }

    /// 60.29 a write never closes an episode before a time a reader already counted it up to (the reader's clock ran
    /// ahead of the sampler's: the interleaving of the review)
    /// times_write has one writer (the sampler): the tests that write take turns (review)
    static TIMES_WRITERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn times_write_starts_at_or_after_a_read() {
        let _one = TIMES_WRITERS.lock().unwrap_or_else(|e| e.into_inner());
        let r = crate::metrics::now_ms() + 50;
        times_read(r, || ());
        let mut got = 0;
        times_write(|now| got = now);
        assert!(got >= r, "{got} < {r}");
    }

    /// 60.29 times_read never returns a half-written set (two values a writer keeps equal)
    #[test]
    fn times_read_sees_whole_writes() {
        let _one = TIMES_WRITERS.lock().unwrap_or_else(|e| e.into_inner()); // held through the join below
        static A: AtomicU64 = AtomicU64::new(0);
        static B: AtomicU64 = AtomicU64::new(0);
        let w = std::thread::spawn(|| {
            for i in 1..=200_000u64 {
                times_write(|_| {
                    A.store(i, Relaxed);
                    B.store(i, Relaxed);
                });
            }
        });
        let mut last = 0;
        while !w.is_finished() {
            let (a, b) = times_read(0, || (A.load(Relaxed), B.load(Relaxed)));
            assert!(a == b && a >= last, "{a} {b} {last}");
            last = a;
        }
        w.join().unwrap();
        assert_eq!(times_read(0, || (A.load(Relaxed), B.load(Relaxed))), (200_000, 200_000));
    }

    /// 70.05 a log queue nobody drains never blocks the sender; the drops are reported in the next line
    #[test]
    fn sampler_log_never_blocks() {
        let (tx, rx) = std::sync::mpsc::sync_channel(2);
        let mut log = Log { tx, dropped: 0 };
        for i in 0..5 {
            log.send(crate::logs::Level::Warn, format!("line {i}"));
        }
        assert_eq!(log.dropped, 3);
        assert_eq!((rx.recv().unwrap(), rx.recv().unwrap()), ("line 0".to_string(), "line 1".to_string()));
        log.send(crate::logs::Level::Warn, "next".into());
        assert_eq!(rx.recv().unwrap(), "next (3 earlier log lines dropped)");
        assert_eq!(log.dropped, 0);
    }

    #[test]
    fn cgroup_path_parses_v2_line() {
        assert_eq!(cgroup_path("0::/user.slice/x.scope\n"), Some("/user.slice/x.scope"));
        assert_eq!(cgroup_path("12:memory:/a\n0::/\n"), Some("/"));
        assert_eq!(cgroup_path("12:memory:/a\n"), None);
    }

    #[test]
    fn cgroup_mode_from_proc_self_cgroup() {
        assert_eq!(cgroup_mode("0::/user.slice/x.scope\n"), "v2");
        assert_eq!(cgroup_mode("12:memory:/a\n1:name=systemd:/a\n0::/a\n"), "hybrid");
        assert_eq!(cgroup_mode("12:memory:/a\n1:name=systemd:/a\n"), "v1");
        assert_eq!(cgroup_mode(""), "?");
    }

    #[test]
    fn cgroup_limit_takes_the_smallest_on_the_path() {
        let root = std::env::temp_dir().join(format!("fw-cg-{}", std::process::id()));
        let leaf = root.join("a/b");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(root.join("a/memory.max"), "1000\n").unwrap();
        std::fs::write(root.join("a/memory.high"), "max\n").unwrap();
        std::fs::write(leaf.join("memory.max"), "max\n").unwrap();
        std::fs::write(leaf.join("memory.high"), "5000\n").unwrap();
        assert_eq!(cgroup_limit(&root, "/a/b"), Some((1000, root.join("a"))));
        std::fs::write(leaf.join("memory.high"), "500\n").unwrap();
        assert_eq!(cgroup_limit(&root, "/a/b"), Some((500, leaf.clone())));
        assert_eq!(cgroup_limit(&root, "/nope"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 80.01 F4 fake cgroup trees (no root needed): v2 unchanged, v1 host (RHEL 8 / AL2), hybrid (Ubuntu 20.04),
    /// v1 container (docker without a cgroup namespace), a smaller limit above the mount, co-mounted controllers,
    /// unlimited, and paths that are not ours
    #[test]
    fn cgroup_budget_v1_hybrid_v2_layouts() {
        let t = std::env::temp_dir().join(format!("fw-cgl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let w = |dir: &Path, f: &str, v: &str| {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join(f), v).unwrap();
        };
        const UNL: &str = "9223372036854771712\n";
        // v2: as before (memory.max on the parent)
        let v2 = t.join("v2");
        w(&v2.join("a"), "memory.max", "1000\n");
        std::fs::create_dir_all(v2.join("a/b")).unwrap();
        let mi2 = format!("30 1 0:26 / {} rw,nosuid shared:4 - cgroup2 cgroup2 rw\n", v2.display());
        assert_eq!(cgroup_budget("0::/a/b\n", &mi2, &v2), Some((1000, Source::Cgroup(v2.join("a")))));
        // v1 host: memory hierarchy at <t>/v1/memory (root "/"), the limit on the slice, unlimited elsewhere
        let v1 = t.join("v1");
        let m1 = v1.join("memory");
        let svc = m1.join("system.slice/fw.service");
        w(&m1, "memory.limit_in_bytes", UNL);
        w(&m1.join("system.slice"), "memory.limit_in_bytes", "4000\n");
        w(&svc, "memory.limit_in_bytes", UNL);
        w(&svc, "memory.stat", "inactive_file 1\nhierarchical_memory_limit 4000\ntotal_inactive_file 2\n");
        let mi1 = format!(
            "24 1 0:21 / {} ro,nosuid shared:5 - tmpfs tmpfs ro,mode=755\n25 24 0:22 / {} rw,nosuid shared:9 - cgroup cgroup rw,memory\n",
            v1.display(),
            m1.display()
        );
        let cg1 = "11:memory:/system.slice/fw.service\n1:name=systemd:/system.slice/fw.service\n";
        let v1s = |dir: PathBuf, hidden| Source::CgroupV1 { dir, hidden };
        let want = Some((4000, v1s(m1.join("system.slice"), false)));
        assert_eq!(cgroup_budget(cg1, &mi1, &v1), want);
        // hybrid: a 0:: line and a cgroup2 mount too, but no memory.max under the v2 root: v1 decides
        let cgh = format!("{cg1}0::/system.slice/fw.service\n");
        // (the v2 root passed is /sys/fs/cgroup, which on a hybrid host is the tmpfs holding the v1 mounts)
        let mih = format!("{mi1}26 24 0:23 / {} rw shared:6 - cgroup2 cgroup2 rw\n", v1.join("unified").display());
        assert_eq!(cgroup_budget(&cgh, &mih, &v1), want);
        // a v2 limit on our path wins over a v1 one (v2 behaviour unchanged)
        w(&v1.join("system.slice"), "memory.max", "8000\n");
        assert_eq!(cgroup_budget(&cgh, &mih, &v1), Some((8000, Source::Cgroup(v1.join("system.slice")))));
        std::fs::remove_file(v1.join("system.slice/memory.max")).unwrap();
        // M3: our hierarchical_memory_limit below every visible limit: an ancestor we cannot see -> hidden
        w(&svc, "memory.stat", "hierarchical_memory_limit 3000\ntotal_inactive_file 2\n");
        assert_eq!(cgroup_budget(cg1, &mi1, &v1), Some((3000, v1s(svc.clone(), true))));
        // equal to the visible minimum: the visible walk wins, not hidden
        w(&svc, "memory.stat", "hierarchical_memory_limit 4000\ntotal_inactive_file 2\n");
        assert_eq!(cgroup_budget(cg1, &mi1, &v1), want);
        // v1 container: our own cgroup is the mount (root /docker/x), its limit on the mount point
        let mc = t.join("ctr/memory");
        w(&mc, "memory.limit_in_bytes", "3000\n");
        let mic = format!("40 39 0:22 /docker/x {} ro,nosuid master:9 - cgroup cgroup rw,memory\n", mc.display());
        assert_eq!(cgroup_budget("9:memory:/docker/x\n", &mic, &t.join("ctr")), Some((3000, v1s(mc.clone(), false))));
        // a smaller limit above the mount (a pod limit): only hierarchical_memory_limit sees it; M3: marked hidden
        w(&mc, "memory.stat", "hierarchical_memory_limit 2500\ntotal_inactive_file 0\n");
        assert_eq!(cgroup_budget("9:memory:/docker/x\n", &mic, &t.join("ctr")), Some((2500, v1s(mc.clone(), true))));
        // our own limit equal to the pod's: visible, not hidden
        w(&mc, "memory.limit_in_bytes", "2500\n");
        assert_eq!(cgroup_budget("9:memory:/docker/x\n", &mic, &t.join("ctr")), Some((2500, v1s(mc.clone(), false))));
        // co-mounted controllers
        let mico = mic.replace("rw,memory", "rw,cpu,memory");
        assert_eq!(cgroup_v1_dir("9:cpu,memory:/docker/x\n", &mico), Some((mc.clone(), mc.clone())));
        // two memory mounts, the first (root "/") does not show our directory: the second is ours
        let mi2m = format!("38 39 0:22 / {} ro - cgroup cgroup rw,memory\n{mic}", t.join("hostroot").display());
        std::fs::create_dir_all(t.join("hostroot")).unwrap();
        assert_eq!(cgroup_v1_dir("9:memory:/docker/x\n", &mi2m), Some((mc.clone(), mc.clone())));
        // unlimited everywhere: no cgroup budget
        w(&mc, "memory.limit_in_bytes", UNL);
        w(&mc, "memory.stat", "hierarchical_memory_limit 9223372036854771712\n");
        assert_eq!(cgroup_budget("9:memory:/docker/x\n", &mic, &t.join("ctr")), None);
        // not ours: a path outside the mount root (another namespace), a sibling prefix, "..": no guess
        assert_eq!(cgroup_v1_dir("9:memory:/other\n", &mic), None);
        assert_eq!(cgroup_v1_dir("9:memory:/docker/xy\n", &mic), None);
        assert_eq!(cgroup_v1_dir("9:memory:/docker/x/../../y\n", &mic), None);
        assert_eq!(cgroup_v1_dir("9:memory:/../y\n", &mi1), None);
        // no memory line, or no v1 memory mount
        assert_eq!(cgroup_v1_dir("1:name=systemd:/a\n", &mi1), None);
        assert_eq!(cgroup_v1_dir(cg1, &mi2), None);
        assert_eq!(cgroup_budget("", "", &t), None);
        let _ = std::fs::remove_dir_all(&t);
    }

    /// 80.01 F4 the sampler reads v1 usage_in_bytes and total_inactive_file (not this cgroup's own inactive_file)
    #[test]
    fn v1_sampler_files() {
        let d = std::env::temp_dir().join(format!("fw-cgs-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("memory.usage_in_bytes"), "7000\n").unwrap();
        std::fs::write(d.join("memory.stat"), "cache 9\ninactive_file 100\ntotal_cache 9\ntotal_inactive_file 300\n").unwrap();
        let (u, s, key) = usage_files(&Source::CgroupV1 { dir: d.clone(), hidden: false }).unwrap();
        assert_eq!(field(ProcFile::open(&u).unwrap().read(), b""), Some(7000));
        assert_eq!(field(ProcFile::open(&s).unwrap().read(), key), Some(300));
        let (u2, s2, k2) = usage_files(&Source::Cgroup(d.clone())).unwrap();
        assert_eq!((u2, s2, k2), (d.join("memory.current"), d.join("memory.stat"), &b"inactive_file "[..]));
        assert_eq!(usage_files(&Source::Host), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 20.31 TCP level: enter at 90% of tcp_mem[1] only with our share >= 1/4 (unknown: not entered), leave below tcp_mem[0]
    /// and only TCP_DWELL_DOWN after entering; tcp_mem parsing; our cgroup's memory.stat `sock`
    #[test]
    fn tcp_level_enter_exit_guard_dwell() {
        let t = TcpAdapt { mem: [750, 1000, 1500], own_stat: PathBuf::new() };
        assert_eq!((t.enter_pages(), t.exit_pages()), (900, 750));
        let long = TCP_DWELL_DOWN;
        assert_eq!(tcp_next(0, 899, Some(1000), &t, long), 0);
        assert_eq!(tcp_next(0, 900, Some(1000), &t, long), 1);
        assert_eq!(tcp_next(0, 2000, None, &t, long), 0, "share unknown: no caps (parent 2026-10-27)");
        assert_eq!(tcp_next(0, 2000, Some(249), &t, long), 0, "someone else's pressure: no caps");
        assert_eq!(tcp_next(0, 900, Some(250), &t, long), 1);
        assert_eq!(tcp_next(1, 760, Some(0), &t, long), 1, "the share is not checked once capped");
        assert_eq!(tcp_next(1, 749, None, &t, Duration::from_millis(1999)), 1, "dwell");
        assert_eq!(tcp_next(1, 749, None, &t, long), 0);
        // tcp_mem[0] close to [1]: exit at least 10% under the entry
        let t2 = TcpAdapt { mem: [990, 1000, 1500], own_stat: PathBuf::new() };
        assert_eq!(t2.exit_pages(), 810);
        assert_eq!(parse_tcp_mem("44769\t59692\t89538\n"), Some([44769, 59692, 89538]));
        for bad in ["", "1 2", "1 2 3 4", "0 1 2", "3 2 1", "a b c"] {
            assert_eq!(parse_tcp_mem(bad), None, "{bad:?}");
        }
        let root = std::env::temp_dir().join(format!("fw-sock-{}", std::process::id()));
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/memory.stat"), "anon 5\nsock 4096\nshmem 0\n").unwrap();
        std::fs::write(root.join("a/b/memory.current"), "123\n").unwrap();
        let cmd = "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet\n";
        assert_eq!(own_sock_stat("0::/a/b\n", Some(cmd), &root), Some(root.join("a/b/memory.stat")));
        assert_eq!(own_sock_stat("0::/a\n", Some(cmd), &root), None, "no memory.stat: share unknown");
        assert_eq!(own_sock_stat("12:memory:/a/b\n", Some(cmd), &root), None, "v1 only: unknown");
        // 60.15 T03 P3: socket accounting off; the root cgroup (memory.stat, no memory.current); no sock line
        assert_eq!(own_sock_stat("0::/a/b\n", Some("ro cgroup.memory=nokmem,nosocket quiet"), &root), None, "nosocket");
        assert_eq!(own_sock_stat("0::/a/b\n", Some("ro cgroup.memory=nokmem quiet"), &root), Some(root.join("a/b/memory.stat")));
        std::fs::write(root.join("memory.stat"), "anon 5\nsock 999999\n").unwrap();
        assert_eq!(own_sock_stat("0::/\n", Some(cmd), &root), None, "the root cgroup: everyone's sockets");
        std::fs::create_dir_all(root.join("c")).unwrap();
        std::fs::write(root.join("c/memory.stat"), "anon 5\nshmem 0\n").unwrap();
        std::fs::write(root.join("c/memory.current"), "1\n").unwrap();
        assert_eq!(own_sock_stat("0::/c\n", Some(cmd), &root), None, "no sock line");
        assert_eq!(own_sock_stat("0::/a/b\n", None, &root), None, "/proc/cmdline unreadable: not proven on");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tcp_caps_stage_is_level_0_with_level_1_socket_caps() {
        // 20.31 (b): the socket fields come from the cap level, (b2) also the credit; queues, keep, streams stay
        let (s, l0, l1) = (stage(0, 1), STAGES[0], STAGES[1]);
        assert_eq!((s.sock_cap, s.client_rcv, s.client_snd), (l1.sock_cap, l1.client_rcv, l1.client_snd));
        assert_eq!((s.grant, s.hs), (l1.grant, l1.hs));
        assert_eq!(
            (s.out_high, s.out_low, s.keep, s.rbuf_max, s.pend_over, s.admit),
            (l0.out_high, l0.out_low, l0.keep, l0.rbuf_max, l0.pend_over, l0.admit)
        );
        for (l, st) in STAGES.iter().enumerate() {
            let s = stage(l, l);
            assert_eq!((s.sock_cap, s.client_rcv, s.client_snd, s.out_high), (st.sock_cap, st.client_rcv, st.client_snd, st.out_high));
        }
    }

    #[test]
    fn levels_have_hysteresis() {
        assert_eq!(next_level(0, 0), 0);
        assert_eq!(next_level(0, 499), 0);
        assert_eq!(next_level(0, 500), 1);
        assert_eq!(next_level(1, 450), 1);
        assert_eq!(next_level(1, 399), 0);
        assert_eq!(next_level(0, 900), 3);
        assert_eq!(next_level(3, 100), 0);
        assert_eq!(next_level(3, 800), 3);
        assert_eq!(next_level(3, 700), 2);
    }

    /// 60.15 T03 soak (gold, host mode): a neighbour's host TCP memory swings by GiBs, so usage jumps from just below
    /// level 1's exit to above its entry many times a second (~100 flaps in 10-30 s with the fixed 250 ms dwell). The
    /// sampler loop (2 ms ticks at level 1) with Dwell flaps at most once per DWELL_MAX once damped.
    #[test]
    fn dwell_damps_a_noisy_neighbour_around_the_exit() {
        let t0 = Instant::now();
        let run = |damped: bool| {
            let (mut ml, mut changed_at, mut d, mut changes, mut x) = (0usize, t0, Dwell::new(), 0u32, 12345u64);
            for tick in 0..15_000u64 {
                let now = t0 + Duration::from_millis(2 * tick);
                // a swing every ~20-120 ms: mostly just below level 1's exit (400), now and then above its entry (500)
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let pm = if (x >> 33) % 40 == 0 { 520 } else { 395 };
                let want = next_level(ml, pm);
                let nml = if damped {
                    d.next(ml, want, changed_at, now)
                } else if want < ml && now.duration_since(changed_at) < DWELL_DOWN {
                    ml
                } else {
                    want
                };
                if nml != ml {
                    (ml, changed_at, changes) = (nml, now, changes + 1);
                }
            }
            changes
        };
        let (old, new) = (run(false), run(true));
        // 30 s: the old rule changes level every ~0.3 s; damped: <= 2 per DWELL_MAX after the first few
        assert!(old >= 100, "fixed dwell: {old} changes");
        assert!(new <= 2 * 30 / 4 + 10, "damped: {new} changes (fixed dwell {old})");
    }

    /// 60.15 T03 flap damping: a step up soon after a step down doubles the step-down dwell (to DWELL_MAX); calm resets
    #[test]
    fn dwell_doubles_per_flap_and_resets_when_calm() {
        let t0 = Instant::now();
        let ms = |v: u64| t0 + Duration::from_millis(v);
        let mut d = Dwell::new();
        // up at once, down only after the dwell
        assert_eq!(d.next(0, 1, t0, ms(0)), 1);
        assert_eq!(d.next(1, 0, ms(0), ms(100)), 1, "within 250 ms");
        assert_eq!(d.next(1, 0, ms(0), ms(250)), 0);
        // L0 <-> L1 flap: each re-entry within FLAP_WINDOW doubles the dwell
        let (mut now, mut flaps) = (250u64, 0);
        for want in [500u64, 1000, 2000, 4000, 4000] {
            assert_eq!(d.next(0, 1, ms(now), ms(now + 50)), 1);
            now += 50;
            flaps += 1;
            assert_eq!(d.cur, Duration::from_millis(want), "after {flaps} flaps");
            assert_eq!(d.next(1, 0, ms(now), ms(now + want - 1)), 1, "held for the dwell");
            assert_eq!(d.next(1, 0, ms(now), ms(now + want)), 0);
            now += want;
        }
        // with level 1 damped, a spike to level 3 leaves level 3 after the base dwell (then waits at level 1)
        let mut e = d;
        assert_eq!(e.next(0, 3, ms(now), ms(now + 10)), 3);
        assert_eq!(e.next(3, 1, ms(now + 10), ms(now + 260)), 1, "level 3 is not the damped level");
        assert_eq!(e.next(1, 0, ms(now + 260), ms(now + 600)), 1, "level 1 is");
        // a step up long after the step down is no flap; CALM without a step up resets
        assert_eq!(d.next(0, 0, ms(now), ms(now + 10_000)), 0);
        assert_eq!(d.cur, DWELL_DOWN);
        assert_eq!(d.next(0, 1, ms(now), ms(now + 10_001)), 1);
        assert_eq!(d.cur, DWELL_DOWN);
        // review: a ramp 0 -> 1 -> 2 after a step down from 1 is one flap of level 1, not two
        let mut r = Dwell::new();
        assert_eq!(r.next(1, 0, t0, ms(300)), 0);
        assert_eq!(r.next(0, 1, ms(300), ms(350)), 1);
        assert_eq!(r.next(1, 2, ms(350), ms(400)), 2);
        assert_eq!((r.level, r.cur), (1, Duration::from_millis(500)));
        // CALM also ends a hold in progress (review)
        let mut c = Dwell::new();
        assert_eq!(c.next(1, 0, t0, ms(300)), 0);
        assert_eq!(c.next(0, 1, ms(300), ms(400)), 1);
        assert_eq!(c.cur, Duration::from_millis(500));
        assert_eq!(c.next(1, 0, ms(10_000), ms(10_301)), 0, "10 s after the last step down: the base dwell");
        // a step up to a lower level than the one left (3 -> 1 -> 2) is no flap of that level
        let mut d = Dwell::new();
        assert_eq!(d.next(3, 1, t0, ms(300)), 1);
        assert_eq!(d.next(1, 2, ms(300), ms(400)), 2);
        assert_eq!(d.cur, DWELL_DOWN);
    }

    /// the level-1 floor below 256 MiB (60.15 T03 P2: 128 MiB was not taken)
    #[test]
    fn small_budget_floor() {
        assert_eq!(floor(16 << 20), 1);
        assert_eq!(floor(200 << 20), 1);
        assert_eq!(floor((256 << 20) - 1), 1);
        assert_eq!(floor(256 << 20), 0);
    }

    #[test]
    fn stage_zero_is_the_old_behaviour() {
        let s = STAGES[0];
        assert!(s.admit && s.read && s.sock_cap == 0 && s.shed == 0 && s.keep == usize::MAX && s.grant == u32::MAX && s.hs == u32::MAX);
        assert!(s.out_high == 1 << 20 && s.out_low == 256 << 10 && s.out_hard == 8 << 20 && s.rbuf_max == 256 << 10);
        // oh256: the bulk-lane cap; levels 1+ never let the lane above the stage's own cap
        assert!(s.out_high_bulk == 256 << 10 && s.out_low_bulk == 64 << 10);
        for st in &STAGES[1..] {
            assert_eq!(st.out_high_bulk, s.out_high_bulk.min(st.out_high));
            assert_eq!(st.out_low_bulk, s.out_low_bulk.min(st.out_low));
        }
        for w in STAGES.windows(2) {
            assert!(w[1].enter > w[0].enter && w[1].exit < w[1].enter && w[1].exit >= w[0].exit);
            assert!(w[1].rbuf_max >= 16 * 1024 && w[1].out_low < w[1].out_high);
        }
        assert!(STAGES[1].keep >= 2 * STAGES[1].out_high, "keep below 2 x out_high frees the obuf at every drain");
        // r5: budget-scaled client caps and grant window (worker budget set by main; here by the test)
        WORKER_BUDGET.store(32 << 20, Relaxed);
        assert_eq!(client_caps(1), (128 << 10, 128 << 10));
        assert_eq!(grant_window(1), 32 << 10);
        assert_eq!(bulk_at(1), 32 << 10);
        WORKER_BUDGET.store(128 << 20, Relaxed);
        assert_eq!(client_caps(1), (256 << 10, 128 << 10));
        assert_eq!(grant_window(1), 64 << 10);
        assert_eq!(client_caps(2), (32 << 10, 64 << 10));
        assert_eq!(grant_window(2), 32 << 10); // 60.12 #2b: the L2 cap (was 16K)
        assert_eq!(bulk_at(2), crate::worker::CHUNK);
        WORKER_BUDGET.store(2 << 20, Relaxed); // 60.12 review: a small worker budget keeps the L2/L3 client receive cap
        assert_eq!(client_caps(2), (32 << 10, 64 << 10));
        // 60.15 T03: no capped client receive buffer below the measured loopback floor (32 KiB): 16 KiB held level 2 at
        // ~2 MiB/s
        for b in [2usize << 20, 16 << 20, 128 << 20] {
            WORKER_BUDGET.store(b, Relaxed);
            for l in 1..STAGES.len() {
                assert!(client_caps(l).0 >= 32 << 10, "level {l}, worker budget {b}: client receive {}", client_caps(l).0);
            }
        }
        WORKER_BUDGET.store(2 << 20, Relaxed);
        assert_eq!(client_caps(1), (32 << 10, 64 << 10));
        WORKER_BUDGET.store(16 << 20, Relaxed);
        assert_eq!(client_caps(1), (32 << 10, 64 << 10));
        assert_eq!(grant_window(1), 32 << 10);
        assert_eq!(bulk_at(1), crate::worker::CHUNK);
        assert_eq!(bulk_at(0), crate::worker::CHUNK);
        // 60.15 T03 P1: level-1 targets send 40 KiB, receive the cap; levels 2/3 and the host TCP level alone (memory
        // level 0, caps of level 1) keep the cap both ways; stream_bytes counts both halves
        assert_eq!(target_caps(&STAGES[1]), (32 << 10, 40 << 10));
        assert_eq!(target_caps(&STAGES[2]), (32 << 10, 32 << 10));
        assert_eq!(target_caps(&STAGES[3]), (32 << 10, 32 << 10));
        assert_eq!(target_caps(&stage(0, 1)), (32 << 10, 32 << 10));
        assert_eq!(target_caps(&stage(1, 1)), (32 << 10, 40 << 10));
        assert!(stream_bytes(&STAGES[1]) >= 2 * (32 << 10) + 2 * (40 << 10));
        assert!(stream_bytes(&STAGES[2]) >= 4 * (32 << 10));
        // compat membudget: a 32 MiB worker at level 1 admits download 10x10 (100 streams) with headroom at the default
        // tcp_rmem[1] (128 KiB; the capped size 2 x 32 + 2 x 40 KiB equals the lazy floor; a bigger tcp_rmem[1] lowers
        // the lazy floor's count, as before)
        WORKER_BUDGET.store(32 << 20, Relaxed);
        assert!(max_streams(&STAGES[1]) >= 110, "level 1 at 32M: {} streams", max_streams(&STAGES[1]));
        WORKER_BUDGET.store(0, Relaxed);
    }

    /// test helper (pool.rs tests): this thread's heap slot, None for the shared overflow slot
    pub(crate) fn my_heap() -> Option<isize> {
        let _warm = Box::new(0u8);
        let slot = MY_SLOT.with(|s| s.get());
        (slot < SLOTS - 1).then(|| HEAP[slot].0.load(Relaxed))
    }

    #[test]
    fn heap_counter_moves() {
        // review 70.11: this thread's own slot, not the global sum (other tests allocate and free concurrently)
        std::thread::spawn(|| {
            let _warm = Box::new(0u8);
            let slot = MY_SLOT.with(|s| s.get());
            if slot == SLOTS - 1 {
                return; // shared overflow slot
            }
            let before = HEAP[slot].0.load(Relaxed);
            let v = vec![0u8; 8 << 20];
            assert_eq!(HEAP[slot].0.load(Relaxed), before + (8 << 20));
            drop(v);
            assert_eq!(HEAP[slot].0.load(Relaxed), before);
        })
        .join()
        .unwrap();
    }
}
