//! 70.25 design B: finalwisp's own allocator for the big per-connection buffers ("the pool"; the only path
//! since 60.18 #11: the old glibc + 70.11 block cache build is gone).
//! mem::Counting routes 16 KiB..MAX_CLASS allocations (align <= 4096) of worker threads (on()) here; everything else
//! stays on glibc. Each worker owns chunks of 4 MiB (4 MiB aligned, one mapping each, header in page 0) of one size
//! class each (13 page-multiple classes, 4 per doubling, 16 KiB .. 128 KiB). A freed block is "dirty" (resident, counted in heap_bytes at
//! its class size: the 70.11 block cache) until it is reused or released with madvise(MADV_DONTNEED) ("clean": zero
//! pages, not counted). Release is bounded per loop turn (release(): RELEASE_CALLS / RELEASE_BYTES / RELEASE_TIME) and
//! follows the 70.11 rules (cap, low-water mark at each idle sweep, L2_BYTES at level 2+); chunks empty at two
//! consecutive sweeps are unmapped (<= UNMAPS_PER_TURN per turn). A free on another thread (Inbox.fds, 70.25 2.7)
//! pushes the block on its chunk's lock-free stack, which only the owner drains. Ownership is by address: a static
//! bitmap of 4 MiB granules (MEMBER). Nothing here allocates (fixed arrays, intrusive lists in the chunk headers).
//! Soundness invariant (70.25 2.1): every live pool block's layout is in the pool domain and maps to its chunk's class;
//! the class is read from the chunk header, never from the layout; a pool pointer never reaches glibc.
//!
//! Safety contract of the `unsafe fn`s here (no per-block SAFETY comments inside them): a `ch: *mut Hdr` is the base of a
//! chunk this process mapped (map_chunk) and has not unmapped, with the header written by new_chunk; its non-atomic
//! fields (bitmaps, counters, list links) are touched only by the owner thread (`Hdr::owner`, the thread whose `P` holds
//! that id), except `owner`/`class`/`magic` (written once before the membership bit is set, read by any thread) and the
//! atomic `remote` stack. A `p: *mut u8` is a block start inside `ch` (block(), or a pointer that came from alloc()).
//! `s: &Pool` is the calling thread's own `P`. Raw libc calls pass these addresses with the lengths computed next to them.
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering::*};
use std::time::{Duration, Instant};

pub const PAGE: usize = 4096;
/// smallest / largest request the pool serves (70.25 2.2: rbuf 16 KiB up). The largest class was 1280 KiB (the whole
/// obuf/bulk chain up to 1048624); 320 KiB since the VPS2 echo100x10 LOSS (0.909, p < 0.001): above it glibc grows a
/// buffer in place with mremap, the pool had to copy it to the next class, and the freed big blocks pushed the dirty
/// set over its cap (madvise + refault, 2x page faults). With 320 KiB: 0.992 (p 0.90). 128 KiB since the big-box echo
/// CPU check (70.25 round 4: epyc2 t48 CPU +3.0% at 320 KiB, +1.2% at 128 KiB): above it every doubling of a growing
/// obuf/bulk buffer was a copy into fresh pages (glibc: mremap in place); the obuf at ROOM + CHUNK (80 KiB class, the
/// 70.11 connchurn reuse) stays pooled. 64 KiB lost that reuse (connchurn100x10 0.56).
pub const MIN: usize = 16 << 10;
pub const MAX_CLASS: usize = 128 << 10;
pub const CLASSES: usize = 13;
const CH_SHIFT: u32 = 22;
/// chunk size and alignment (4 MiB)
pub const CH: usize = 1 << CH_SHIFT;
/// at most this many blocks per chunk (four u64 bitmap words; the 16 KiB class has exactly 255)
const MAX_BLOCKS: usize = 255;
/// user address bits covered by the membership bitmap (x86_64 4-level paging); a chunk above is not used (la57)
const ADDR_BITS: u32 = 47;
/// pool ids (u16 in the chunk header); pool threads beyond this run without a pool
pub const MAX_POOLS: usize = 1024;
const MAGIC: u64 = 0x3730_2e32_3570_6f6f; // "oop52.07"
const NONE: u16 = u16::MAX;
// compile-time checks of the layout rules above (60.16): the class table ends at MAX_CLASS and starts at MIN, the header
// fits in page 0, the 16 KiB class fills the four bitmap words, and the class id fits Hdr::class (u8)
const _: () = assert!(class_bytes(0) == MIN && class_bytes(CLASSES - 1) == MAX_CLASS);
const _: () = assert!(std::mem::size_of::<Hdr>() <= PAGE);
const _: () = assert!(MAX_BLOCKS < 4 * 64 && (CH - PAGE) / MIN >= MAX_BLOCKS && blocks(0) == MAX_BLOCKS);
const _: () = assert!(CLASSES <= u8::MAX as usize && MAX_BLOCKS <= u16::MAX as usize);

/// 70.25 2.5 release bounds per loop turn (kept after the 100k stall probe, 70.25 round 3): madvise calls,
/// bytes, elapsed time (checked between calls); one merged run is split at RUN_MAX
const RELEASE_CALLS: u32 = 16;
const RELEASE_BYTES: usize = 8 << 20;
const RUN_MAX: usize = 2 << 20;
const RELEASE_TIME: Duration = Duration::from_millis(1);
/// munmap takes mmap_lock for write (on kernels < 6.4 a waiting writer blocks every thread's page faults)
const UNMAPS_PER_TURN: u32 = 4;
/// a chunk is unmapped once it was empty (no live, no dirty block) at this many consecutive idle sweeps
const EMPTY_SWEEPS: u8 = 2;

/// pages of class c: 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32 (16 KiB .. 128 KiB)
const fn class_pages(c: usize) -> usize {
    (4 + (c & 3)) << (c >> 2)
}
pub const fn class_bytes(c: usize) -> usize {
    class_pages(c) * PAGE
}
/// blocks of class c in one chunk (after the header page)
const fn blocks(c: usize) -> usize {
    let n = (CH - PAGE) / class_bytes(c);
    if n > MAX_BLOCKS {
        MAX_BLOCKS
    } else {
        n
    }
}

/// The smallest class that holds `size` (MIN..=MAX_CLASS), O(1) (jemalloc size2index style): with n pages and
/// g = max(0, floor(log2(n - 1)) - 2), the class is 4g + ceil(n / 2^g) - 4 (i = 4 is class 4(g+1) + 0).
#[inline]
pub fn class_of(size: usize) -> usize {
    debug_assert!((MIN..=MAX_CLASS).contains(&size));
    let n = size.div_ceil(PAGE);
    let lg = usize::BITS - 1 - (n - 1).leading_zeros();
    let g = lg.saturating_sub(2) as usize;
    4 * g + n.div_ceil(1 << g) - 4
}

/// A request the pool may serve (on a pool thread): its size range, page alignment at most (blocks are page aligned).
#[inline]
pub fn in_range(size: usize, align: usize) -> bool {
    (MIN..=MAX_CLASS).contains(&size) && align <= PAGE
}
/// A freed or reallocated block whose layout size is in this range may be a pool block (then is_pool decides).
#[inline]
pub fn size_in_range(size: usize) -> bool {
    (MIN..=MAX_CLASS).contains(&size)
}

// ---------------------------------------------------------------- membership (address -> pool chunk)

const GRANULES: usize = 1 << (ADDR_BITS - CH_SHIFT);
/// one bit per 4 MiB granule of the 47-bit address space: 4 MiB of BSS (VSZ; RSS = the touched words only)
static MEMBER: [AtomicU64; GRANULES / 64] = [const { AtomicU64::new(0) }; GRANULES / 64];

/// p is inside a mapped pool chunk. Set (Release) by the owner after the header is written, cleared before munmap; a
/// glibc pointer never lies in a mapped chunk, and no pointer into a chunk exists when it is unmapped (live == 0).
#[inline]
pub fn is_pool(p: *mut u8) -> bool {
    let g = p as usize >> CH_SHIFT;
    g < GRANULES && MEMBER[g / 64].load(Acquire) & (1 << (g % 64)) != 0
}
fn set_member(base: usize, on: bool) {
    #[cfg(fuzzing)]
    lsan::root(base, on);
    let g = base >> CH_SHIFT;
    if on {
        MEMBER[g / 64].fetch_or(1 << (g % 64), Release);
    } else {
        MEMBER[g / 64].fetch_and(!(1 << (g % 64)), Release);
    }
}

/// 70.27 fuzz builds only (--cfg fuzzing): LeakSanitizer does not scan mmap'd memory, so a malloc'd block referenced only
/// from a pool block looked leaked (a false report in a worker-tls fork lane). Every mapped chunk is an LSan root region
/// while it is a member (set_member). A pointer left in a freed pool block can then hide a real leak (the accepted
/// tradeoff; the old no-pool fuzz build that had full precision is gone, 60.18 #11). The symbols are weak: null without a sanitizer
/// (cargo fuzz coverage), then nothing happens.
#[cfg(fuzzing)]
mod lsan {
    unsafe extern "C" {
        #[linkage = "extern_weak"]
        static __lsan_register_root_region: Option<unsafe extern "C" fn(*const libc::c_void, usize)>;
        #[linkage = "extern_weak"]
        static __lsan_unregister_root_region: Option<unsafe extern "C" fn(*const libc::c_void, usize)>;
    }
    pub(super) fn root(base: usize, on: bool) {
        // SAFETY: reading weak symbol addresses; the LSan calls only record or drop (begin, size) of a whole chunk
        unsafe {
            if let Some(f) = if on { __lsan_register_root_region } else { __lsan_unregister_root_region } {
                f(base as *const libc::c_void, super::CH);
            }
        }
    }
}

// ---------------------------------------------------------------- process-wide chunk budget

/// 70.25 item 4 (VPS2): most chunks mapped by all threads together. Without it the pool used up the mapping limit
/// (max_map_count 512) or the address space (RLIMIT_AS 2 GiB) where base-3 kept running: then glibc's fallback failed
/// too and Rust aborted. Set once by limits() before the workers start; at the cap a new chunk is refused like a failed
/// mmap (glibc serves, pool_capped).
static CHUNK_MAX: AtomicUsize = AtomicUsize::new(usize::MAX);
static CHUNKS_ALL: AtomicUsize = AtomicUsize::new(0);

/// the chunk budget for these limits: a quarter of the mapping limit (glibc gets another quarter, mem::pin_mmap_threshold;
/// together the half that 70.03 gave glibc alone) and a sixteenth of the smaller of RLIMIT_AS / RLIMIT_DATA. (VPS2, 2000
/// streams at RLIMIT_AS 2 GiB, 4 reps each: a quarter aborted 5/7 at the cap, VSZ 2047 MB, glibc's fallback out of
/// address space; an eighth survived 4/4 but peaked at 2044 MB; a sixteenth 4/4 at 1856-1941 MB, base-3's 1857-1949.)
pub(crate) fn chunk_max(max_map_count: Option<usize>, bytes: Option<usize>) -> usize {
    // an unreadable max_map_count: assume the kernel default
    (max_map_count.unwrap_or(65530) / 4).min(bytes.map_or(usize::MAX, |b| b / 16 / CH))
}

/// read the limits and set the chunk budget (main, before the workers); returns it and the limit that sets it
pub fn limits() -> (usize, String) {
    let max_map_count = std::fs::read_to_string("/proc/sys/vm/max_map_count").ok().and_then(|s| s.trim().parse::<usize>().ok());
    let rl = |r| {
        let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: getrlimit writes one rlimit into the live local `l`
        (unsafe { libc::getrlimit(r, &mut l) } == 0 && l.rlim_cur != libc::RLIM_INFINITY).then_some(l.rlim_cur as usize)
    };
    let bytes = [rl(libc::RLIMIT_AS), rl(libc::RLIMIT_DATA)].into_iter().flatten().min();
    let max = chunk_max(max_map_count, bytes);
    CHUNK_MAX.store(max, Relaxed);
    // review: which limit binds (the capabilities line)
    let by = if bytes.is_some_and(|b| b / 16 / CH == max) {
        format!("RLIMIT_AS/DATA {} MiB / 16", bytes.unwrap_or(0) >> 20)
    } else {
        format!("max_map_count {} / 4", max_map_count.map_or("unknown, 65530".to_string(), |m| m.to_string()))
    };
    (max, by)
}

// ---------------------------------------------------------------- chunk header (page 0 of a chunk)

/// list ids: a chunk is on its class's dirty list while it has a dirty free block, on its class's clean list while it
/// has a clean free block or room to bump, and on its owner's list of all chunks while mapped
const L_DIRTY: usize = 0;
const L_CLEAN: usize = 1;
const L_ALL: usize = 2;

#[repr(C)]
struct Hdr {
    magic: u64,
    /// set at map time, read by any thread (free): never written again
    owner: u16,
    class: u8,
    /// owner-only from here on (except `remote`)
    empty_sweeps: u8,
    nblocks: u16,
    /// blocks [bump, nblocks) were never handed out (fresh zero pages)
    bump: u16,
    /// blocks handed out and not freed by the owner (a remote free counts as live until drained)
    live: u16,
    /// free blocks (dirty or clean) among [0, bump), and the dirty ones (resident) among them
    free: [u64; 4],
    dirty: [u64; 4],
    /// [list][prev, next]
    link: [[*mut Hdr; 2]; 3],
    on: [bool; 3],
    /// remote frees: a push-only Treiber stack through the blocks' first words, swapped out by the owner (no ABA)
    remote: AtomicPtr<u8>,
}

#[inline]
fn bit(w: &[u64; 4], i: usize) -> bool {
    w[i / 64] & (1 << (i % 64)) != 0
}
#[inline]
fn first(w: [u64; 4]) -> Option<usize> {
    w.iter().enumerate().find(|(_, &x)| x != 0).map(|(k, &x)| k * 64 + x.trailing_zeros() as usize)
}
#[inline]
unsafe fn block(ch: *mut Hdr, i: usize, cb: usize) -> *mut u8 {
    (ch as *mut u8).add(PAGE + i * cb)
}
#[inline]
unsafe fn index(ch: *mut Hdr, p: *mut u8, cb: usize) -> usize {
    let off = p as usize - ch as usize - PAGE;
    debug_assert!(off.is_multiple_of(cb) && off / cb < (*ch).bump as usize, "pool: not a block start");
    off / cb
}
#[inline]
unsafe fn clean_bits(ch: *mut Hdr) -> [u64; 4] {
    let (f, d) = ((*ch).free, (*ch).dirty);
    [f[0] & !d[0], f[1] & !d[1], f[2] & !d[2], f[3] & !d[3]]
}
#[inline]
unsafe fn has_clean(ch: *mut Hdr) -> bool {
    (*ch).bump < (*ch).nblocks || clean_bits(ch) != [0; 4]
}
#[inline]
unsafe fn has_dirty(ch: *mut Hdr) -> bool {
    (*ch).dirty != [0; 4]
}
#[inline]
unsafe fn is_empty(ch: *mut Hdr) -> bool {
    (*ch).live == 0 && !has_dirty(ch) && (*ch).remote.load(Relaxed).is_null()
}

// ---------------------------------------------------------------- per-thread pool

/// The calling thread's pool. const init, no destructor (as mem::MY_SLOT): usable inside the allocator, also during
/// thread exit.
struct Pool {
    /// NONE = not a pool thread
    id: Cell<u16>,
    /// most dirty bytes kept (70.11 CACHE_BYTES rule), L2_BYTES while `off` (level 2+, mem::cache_pause)
    cap: Cell<usize>,
    off: Cell<bool>,
    /// dirty free bytes (class sizes; counted in heap_bytes)
    dirty: Cell<usize>,
    /// bytes the last idle sweep decided to release (60.09 M4b low-water rule), released in bounded batches
    owed: Cell<usize>,
    /// fewest dirty bytes since the last sweep, and whether a dirty block was taken meanwhile
    low: Cell<usize>,
    taken: Cell<bool>,
    chunks: Cell<usize>,
    /// a syscall failed: no new mmap / madvise / munmap attempt until the next sweep (70.25 2.9)
    map_blocked: Cell<bool>,
    advise_blocked: Cell<bool>,
    unmap_blocked: Cell<bool>,
    /// a chunk was empty at EMPTY_SWEEPS sweeps: unmap in bounded batches
    unmap_due: Cell<bool>,
    /// list heads [head, tail]: dirty of class c at c, clean of class c at CLASSES + c, all at 2 * CLASSES
    heads: [[Cell<*mut Hdr>; 2]; 2 * CLASSES + 1],
    /// counters since the last sweep (returned by pool::sweep, published by metrics::Stats::pool_sweep)
    hits: Cell<u64>,
    misses: Cell<u64>,
    fallback: Cell<u64>,
    remote: Cell<u64>,
    madvise: Cell<u64>,
    munmaps: Cell<u64>,
    madvise_fail: Cell<u64>,
    munmap_fail: Cell<u64>,
    /// new chunks refused by the process-wide budget (CHUNK_MAX)
    capped: Cell<u64>,
    /// test-only failure injection (F_*), sticky until cleared
    #[cfg(test)]
    fail: Cell<u8>,
    /// test-only chunk budget of this thread alone (CHUNK_MAX is process-wide: other tests run at the same time)
    #[cfg(test)]
    test_max: Cell<usize>,
}
thread_local! {
    static P: Pool = const {
        Pool {
            id: Cell::new(NONE),
            cap: Cell::new(0),
            off: Cell::new(false),
            dirty: Cell::new(0),
            owed: Cell::new(0),
            low: Cell::new(0),
            taken: Cell::new(false),
            chunks: Cell::new(0),
            map_blocked: Cell::new(false),
            advise_blocked: Cell::new(false),
            unmap_blocked: Cell::new(false),
            unmap_due: Cell::new(false),
            heads: [const { [const { Cell::new(null_mut()) }; 2] }; 2 * CLASSES + 1],
            hits: Cell::new(0),
            misses: Cell::new(0),
            fallback: Cell::new(0),
            remote: Cell::new(0),
            madvise: Cell::new(0),
            munmaps: Cell::new(0),
            madvise_fail: Cell::new(0),
            munmap_fail: Cell::new(0),
            capped: Cell::new(0),
            #[cfg(test)]
            fail: Cell::new(0),
            #[cfg(test)]
            test_max: Cell::new(usize::MAX),
        }
    };
}

/// pool ids in use (a thread that turned its pool off with no chunk left gives its id back: tests, fuzzing)
static IDS: [AtomicU64; MAX_POOLS / 64] = [const { AtomicU64::new(0) }; MAX_POOLS / 64];
/// set by a remote free (after its push), swapped by the owner at its next turn end
static REMOTE: [AtomicBool; MAX_POOLS] = [const { AtomicBool::new(false) }; MAX_POOLS];
/// 70.25 4.7 longest release() in microseconds, process-wide (metrics: pool_release_max_us)
pub static RELEASE_MAX_US: AtomicU64 = AtomicU64::new(0);
/// 60.16 / 30.14 the thread CPU time of that step's longest run (metrics: pool_release_cpu_max_us): beside the elapsed
/// max it tells syscall work (cpu ~ elapsed) from waiting (mmap_lock, preemption: cpu << elapsed). Process-wide; the two
/// maxima can come from different calls.
pub static RELEASE_CPU_MAX_US: AtomicU64 = AtomicU64::new(0);

/// CPU time of the calling thread in nanoseconds (CLOCK_THREAD_CPUTIME_ID, a vDSO-less syscall: only on a release that
/// does work)
fn thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes one timespec into the live local ts
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[inline]
fn head_ix(c: usize, k: usize) -> usize {
    match k {
        L_DIRTY => c,
        L_CLEAN => CLASSES + c,
        _ => 2 * CLASSES,
    }
}
/// append ch to list k (no-op if on it)
unsafe fn push(s: &Pool, ch: *mut Hdr, k: usize) {
    if (*ch).on[k] {
        return;
    }
    let h = &s.heads[head_ix((*ch).class as usize, k)];
    let tail = h[1].get();
    (*ch).link[k] = [tail, null_mut()];
    if tail.is_null() {
        h[0].set(ch);
    } else {
        (*tail).link[k][1] = ch;
    }
    h[1].set(ch);
    (*ch).on[k] = true;
}
/// remove ch from list k (no-op if not on it)
unsafe fn unlink(s: &Pool, ch: *mut Hdr, k: usize) {
    if !(*ch).on[k] {
        return;
    }
    let h = &s.heads[head_ix((*ch).class as usize, k)];
    let [prev, next] = (*ch).link[k];
    if prev.is_null() {
        h[0].set(next);
    } else {
        (*prev).link[k][1] = next;
    }
    if next.is_null() {
        h[1].set(prev);
    } else {
        (*next).link[k][0] = prev;
    }
    (*ch).on[k] = false;
}

// ---------------------------------------------------------------- syscalls (with test-only failure injection)

/// test-only failure injection bits (Pool::fail): the chunk mmap, the first / second alignment cut, madvise, munmap.
/// Outside tests `injected` is a constant false, so the checks compile away.
pub(crate) const F_MMAP: u8 = 1;
pub(crate) const F_TRIM: u8 = 2;
pub(crate) const F_TRIM2: u8 = 16;
pub(crate) const F_MADVISE: u8 = 4;
pub(crate) const F_MUNMAP: u8 = 8;

#[inline]
fn injected(_s: &Pool, _f: u8) -> bool {
    #[cfg(test)]
    {
        _s.fail.get() & _f != 0
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// mmap len bytes (anonymous, private, no reserve); null on failure
unsafe fn sys_mmap(s: &Pool, len: usize) -> *mut u8 {
    if injected(s, F_MMAP) {
        return null_mut();
    }
    let p = libc::mmap(
        null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        null_mut()
    } else {
        p as *mut u8
    }
}
/// munmap; `f` = the injection bit that makes this call fail (tests)
unsafe fn sys_munmap(s: &Pool, a: usize, len: usize, f: u8) -> bool {
    if injected(s, f) {
        return false;
    }
    libc::munmap(a as *mut libc::c_void, len) == 0
}
unsafe fn sys_madvise(s: &Pool, a: *mut u8, len: usize) -> bool {
    if injected(s, F_MADVISE) {
        return false;
    }
    libc::madvise(a as *mut libc::c_void, len, libc::MADV_DONTNEED) == 0
}

/// A 4 MiB aligned chunk: mmap 8 MiB, unmap the unaligned head and/or tail, MADV_NOHUGEPAGE (up to 4 syscalls per chunk;
/// THP=always would fault 2 MiB pages and split them at each block release). Its base address, or 0 on any failure
/// (nothing kept).
unsafe fn map_chunk(s: &Pool) -> usize {
    let raw = sys_mmap(s, 2 * CH) as usize;
    if raw == 0 {
        return 0;
    }
    let base = (raw + CH - 1) & !(CH - 1);
    let (head, tail) = (base - raw, raw + 2 * CH - (base + CH));
    let mut cut = F_TRIM; // (test injection: the first cut, then F_TRIM2 for the second)
    if head > 0 {
        if !sys_munmap(s, raw, head, cut) {
            libc::munmap(raw as *mut libc::c_void, 2 * CH); // nothing given back yet: the whole range is still ours
            return 0;
        }
        cut = F_TRIM2;
    }
    if tail > 0 && !sys_munmap(s, base + CH, tail, cut) {
        // review: [raw, base) is given back and may already be another thread's mapping: clean up only
        // what is still ours. (At the map limit the tail cut can need a VMA split and fail while the head cut worked.)
        libc::munmap(base as *mut libc::c_void, raw + 2 * CH - base);
        return 0;
    }
    if base + CH > 1 << ADDR_BITS {
        libc::munmap(base as *mut libc::c_void, CH); // above the membership bitmap (la57): not used
        return 0;
    }
    // EINVAL: a kernel without THP, nothing to do. Another error (ENOMEM: the VMA split at the map limit, review):
    // without it THP=always would fault 2 MiB pages into the chunk, so the chunk is not used (glibc serves).
    if libc::madvise(base as *mut libc::c_void, CH, libc::MADV_NOHUGEPAGE) != 0 && *libc::__errno_location() != libc::EINVAL {
        s.madvise_fail.set(s.madvise_fail.get() + 1); // (review round 2: visible apart from an mmap ENOMEM)
        libc::munmap(base as *mut libc::c_void, CH);
        return 0;
    }
    base
}

unsafe fn new_chunk(s: &Pool, c: usize) -> *mut Hdr {
    if s.map_blocked.get() {
        return null_mut();
    }
    // the process-wide budget: reserve a slot first (racing threads cannot overshoot it)
    #[cfg(test)]
    let over = s.chunks.get() >= s.test_max.get();
    #[cfg(not(test))]
    let over = false;
    if CHUNKS_ALL.fetch_add(1, Relaxed) >= CHUNK_MAX.load(Relaxed) || over {
        CHUNKS_ALL.fetch_sub(1, Relaxed);
        s.capped.set(s.capped.get() + 1);
        s.map_blocked.set(true); // as a failed mmap: glibc serves until the next sweep
        return null_mut();
    }
    #[cfg(feature = "pooltest")]
    let t0 = Instant::now();
    let base = map_chunk(s);
    #[cfg(feature = "pooltest")]
    crate::mem::pt::chunk_map(t0.elapsed().as_micros() as u64);
    if base == 0 {
        CHUNKS_ALL.fetch_sub(1, Relaxed);
        s.map_blocked.set(true); // no failing mmap per allocation: retried after the next sweep
        return null_mut();
    }
    let ch = base as *mut Hdr;
    ch.write(Hdr {
        magic: MAGIC,
        owner: s.id.get(),
        class: c as u8,
        empty_sweeps: 0,
        nblocks: blocks(c) as u16,
        bump: 0,
        live: 0,
        free: [0; 4],
        dirty: [0; 4],
        link: [[null_mut(); 2]; 3],
        on: [false; 3],
        remote: AtomicPtr::new(null_mut()),
    });
    set_member(base, true);
    push(s, ch, L_ALL);
    push(s, ch, L_CLEAN);
    s.chunks.set(s.chunks.get() + 1);
    crate::mem::account(PAGE as isize); // 70.25 2.6: the header page is resident
    ch
}

/// clear the membership bit and munmap; on failure the chunk stays (clean, empty) and the bit is set again
unsafe fn unmap(s: &Pool, ch: *mut Hdr) -> bool {
    debug_assert!(is_empty(ch));
    for k in [L_DIRTY, L_CLEAN, L_ALL] {
        unlink(s, ch, k);
    }
    set_member(ch as usize, false);
    if !sys_munmap(s, ch as usize, CH, F_MUNMAP) {
        set_member(ch as usize, true);
        push(s, ch, L_ALL);
        push(s, ch, L_CLEAN);
        return false;
    }
    s.chunks.set(s.chunks.get() - 1);
    CHUNKS_ALL.fetch_sub(1, Relaxed);
    s.munmaps.set(s.munmaps.get() + 1);
    crate::mem::account(-(PAGE as isize));
    true
}

// ---------------------------------------------------------------- public API (allocator side)

/// 70.25 turn the pool on for the calling thread (the workers; main.rs): `cap` = most dirty bytes kept. Fails closed
/// (false, the thread stays on glibc) if the page size is not 4096 or the pool ids are used up. The thread must never
/// exit with live blocks (a worker's run() never returns; tests call test_off()).
pub fn on(cap: usize) -> bool {
    on_page(unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize, cap) // SAFETY: sysconf has no memory arguments
}
/// 60.16 why some or all of `workers` worker threads run without the pool (on() fails closed), for the capability line;
/// None = all of them get one. The same conditions as on(): the page size, then the pool ids.
pub fn refused(workers: usize) -> Option<String> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize; // SAFETY: sysconf has no memory arguments
    refused_for(page, workers)
}
pub(crate) fn refused_for(page: usize, workers: usize) -> Option<String> {
    if page != PAGE {
        Some(format!("off: page size {page}, not {PAGE}; glibc serves"))
    } else if workers > MAX_POOLS {
        Some(format!("{MAX_POOLS} of {workers} workers; the rest use glibc"))
    } else {
        None
    }
}
pub(crate) fn on_page(page: usize, cap: usize) -> bool {
    if page != PAGE {
        return false;
    }
    P.with(|s| {
        if s.id.get() == NONE {
            let Some(id) = take_id() else { return false };
            s.id.set(id as u16);
        }
        s.cap.set(cap);
        true
    })
}

fn take_id() -> Option<usize> {
    for (k, w) in IDS.iter().enumerate() {
        let mut v = w.load(Relaxed);
        while v != u64::MAX {
            let b = (!v).trailing_zeros() as usize;
            match w.compare_exchange_weak(v, v | 1 << b, Relaxed, Relaxed) {
                Ok(_) => return Some(k * 64 + b),
                Err(x) => v = x,
            }
        }
    }
    None
}

#[cfg(any(test, fuzzing))]
/// the calling thread is a pool thread
#[inline]
pub fn active() -> bool {
    P.with(|s| s.id.get() != NONE)
}

/// A block of >= size bytes (in_range) from the calling thread's pool, zeroed if `zero`; null if this is not a pool
/// thread or no chunk can be mapped (then the caller uses System: 70.25 2.9, counted as pool_fallback). Accounts only
/// the dirty bytes it takes (the caller accounts the requested size).
///
/// # Safety
/// Only for the global allocator (mem::Counting): `size` is in_range (MIN..=MAX_CLASS), and the block is given back only
/// through free() with a layout size of the same class.
#[inline]
pub unsafe fn alloc(size: usize, zero: bool) -> *mut u8 {
    P.with(|s| if s.id.get() == NONE { null_mut() } else { alloc_in(s, size, zero) })
}

unsafe fn alloc_in(s: &Pool, size: usize, zero: bool) -> *mut u8 {
    let c = class_of(size);
    let cb = class_bytes(c);
    // 1. a dirty block (warm, no page faults: the 70.11 cache hit), newest dirty chunk first
    let ch = s.heads[head_ix(c, L_DIRTY)][1].get();
    if !ch.is_null() {
        let i = first((*ch).dirty).expect("pool: chunk on the dirty list without a dirty block");
        (*ch).free[i / 64] &= !(1 << (i % 64));
        (*ch).dirty[i / 64] &= !(1 << (i % 64));
        if !has_dirty(ch) {
            unlink(s, ch, L_DIRTY);
        }
        (*ch).live += 1;
        (*ch).empty_sweeps = 0;
        s.dirty.set(s.dirty.get() - cb);
        s.low.set(s.low.get().min(s.dirty.get()));
        s.owed.set(s.owed.get().saturating_sub(cb)); // needed after all: owe less (70.11 freed the low-water mark at once)
        s.taken.set(true);
        s.hits.set(s.hits.get() + 1);
        crate::mem::account(-(cb as isize)); // counted at its class size while dirty
        let p = block(ch, i, cb);
        if zero {
            std::ptr::write_bytes(p, 0, size);
        }
        return p;
    }
    s.misses.set(s.misses.get() + 1);
    // 2. a clean free block, else a fresh one (bump), else a new chunk; all zero pages (no memset for alloc_zeroed)
    let mut ch = s.heads[head_ix(c, L_CLEAN)][0].get();
    if ch.is_null() {
        ch = new_chunk(s, c);
        if ch.is_null() {
            s.fallback.set(s.fallback.get() + 1);
            return null_mut();
        }
    }
    let i = match first(clean_bits(ch)) {
        Some(i) => {
            (*ch).free[i / 64] &= !(1 << (i % 64));
            i
        }
        None => {
            debug_assert!((*ch).bump < (*ch).nblocks);
            (*ch).bump += 1;
            (*ch).bump as usize - 1
        }
    };
    if !has_clean(ch) {
        unlink(s, ch, L_CLEAN);
    }
    (*ch).live += 1;
    (*ch).empty_sweeps = 0;
    block(ch, i, cb)
}

/// realloc rule 1 (70.25 2.1): pool block p can stay for `new` bytes (same class, calling thread is the owner)
///
/// # Safety
/// `p` is a live pool block (is_pool(p)): its chunk header is mapped.
#[inline]
pub unsafe fn keeps(p: *mut u8, new: usize, align: usize) -> bool {
    let ch = (p as usize & !(CH - 1)) as *mut Hdr;
    in_range(new, align) && class_of(new) == (*ch).class as usize && P.with(|s| s.id.get() == (*ch).owner)
}

/// Free pool block p (is_pool(p); `size` = its layout size, debug-checked against the class): the owner marks it dirty
/// (accounts its class size), any other thread pushes it on the chunk's remote stack.
///
/// # Safety
/// `p` is a live pool block (is_pool(p), from alloc(), not freed yet) and `size` is its layout size; after the call `p`
/// is not touched again.
#[inline]
pub unsafe fn free(p: *mut u8, size: usize) {
    let ch = (p as usize & !(CH - 1)) as *mut Hdr;
    debug_assert_eq!((*ch).magic, MAGIC, "pool: free into a chunk without a header");
    debug_assert_eq!(class_of(size), (*ch).class as usize, "pool: layout size {size} not in the block's class");
    let _ = size;
    let owner = (*ch).owner;
    if !P.with(|s| {
        let mine = s.id.get() == owner;
        if mine {
            free_own(s, ch, p);
        }
        mine
    }) {
        free_remote(ch, p, owner);
    }
}

unsafe fn free_own(s: &Pool, ch: *mut Hdr, p: *mut u8) {
    let cb = class_bytes((*ch).class as usize);
    let i = index(ch, p, cb);
    debug_assert!(!bit(&(*ch).free, i), "pool: double free");
    debug_assert!((*ch).live > 0);
    (*ch).free[i / 64] |= 1 << (i % 64);
    (*ch).dirty[i / 64] |= 1 << (i % 64);
    (*ch).live -= 1;
    s.dirty.set(s.dirty.get() + cb);
    crate::mem::account(cb as isize);
    push(s, ch, L_DIRTY);
}

/// 70.25 2.7: Treiber push (link in the block's first word), then flag the owner. After the CAS this thread touches no
/// chunk memory (the owner may drain and unmap at once).
unsafe fn free_remote(ch: *mut Hdr, p: *mut u8, owner: u16) {
    let head = &(*ch).remote;
    let mut old = head.load(Relaxed);
    loop {
        (p as *mut *mut u8).write(old);
        match head.compare_exchange_weak(old, p, Release, Relaxed) {
            Ok(_) => break,
            Err(o) => old = o,
        }
    }
    REMOTE[owner as usize].store(true, Release);
}

/// owner: take every chunk's remote stack (only when flagged) and free the blocks as dirty
unsafe fn drain(s: &Pool) {
    let id = s.id.get() as usize;
    if !REMOTE[id].load(Relaxed) || !REMOTE[id].swap(false, Acquire) {
        return;
    }
    let mut ch = s.heads[head_ix(0, L_ALL)][0].get();
    while !ch.is_null() {
        let mut p = (*ch).remote.swap(null_mut(), Acquire);
        while !p.is_null() {
            let next = *(p as *mut *mut u8);
            free_own(s, ch, p);
            s.remote.set(s.remote.get() + 1);
            p = next;
        }
        ch = (*ch).link[L_ALL][1];
    }
}

// ---------------------------------------------------------------- release (owner, end of a loop turn / sweep)

/// dirty bytes to release now: the excess over the cap (L2_BYTES at level 2+), or what the last sweep owes
fn wanted(s: &Pool) -> usize {
    let cap = if s.off.get() { s.cap.get().min(crate::mem::L2_BYTES) } else { s.cap.get() };
    let d = s.dirty.get();
    d.saturating_sub(cap).max(s.owed.get().min(d))
}

/// madvise(DONTNEED) runs of contiguous dirty blocks (largest class first, oldest dirty chunk first, address order),
/// up to `want` bytes and the per-turn bounds. A failed madvise keeps the blocks dirty until the next sweep.
unsafe fn advise(s: &Pool, want: usize, bounded: bool) {
    let t0 = Instant::now(); // (the time bound; release() measures the whole turn-end step)
    let (mut calls, mut done) = (0u32, 0usize);
    'classes: for c in (0..CLASSES).rev() {
        let cb = class_bytes(c);
        let mut ch = s.heads[head_ix(c, L_DIRTY)][0].get();
        while !ch.is_null() {
            let next = (*ch).link[L_DIRTY][1];
            let n = (*ch).bump as usize;
            let mut i = 0;
            while i < n {
                if !bit(&(*ch).dirty, i) {
                    i += 1;
                    continue;
                }
                let need = (want - done).div_ceil(cb);
                // review: the byte bound holds (only a turn's first call may pass it); a smaller class
                // may still fit
                if bounded && calls > 0 && RELEASE_BYTES - done < cb {
                    continue 'classes;
                }
                let lim = if bounded { need.min((RUN_MAX / cb).max(1)).min(((RELEASE_BYTES - done) / cb).max(1)) } else { need };
                let mut j = i + 1;
                while j < n && j - i < lim && bit(&(*ch).dirty, j) {
                    j += 1;
                }
                let len = (j - i) * cb;
                if !sys_madvise(s, block(ch, i, cb), len) {
                    s.advise_blocked.set(true);
                    s.madvise_fail.set(s.madvise_fail.get() + 1);
                    break 'classes;
                }
                for k in i..j {
                    (*ch).dirty[k / 64] &= !(1 << (k % 64));
                }
                s.dirty.set(s.dirty.get() - len);
                s.owed.set(s.owed.get().saturating_sub(len));
                s.low.set(s.low.get().min(s.dirty.get()));
                s.madvise.set(s.madvise.get() + 1);
                crate::mem::account(-(len as isize));
                push(s, ch, L_CLEAN);
                if !has_dirty(ch) {
                    unlink(s, ch, L_DIRTY);
                }
                done += len;
                calls += 1;
                if done >= want || (bounded && (calls >= RELEASE_CALLS || done >= RELEASE_BYTES || t0.elapsed() >= RELEASE_TIME)) {
                    break 'classes;
                }
                i = j;
            }
            ch = next;
        }
    }
}

/// unmap up to UNMAPS_PER_TURN chunks that were empty at EMPTY_SWEEPS sweeps and still are
unsafe fn unmap_some(s: &Pool, limit: u32) {
    let mut n = 0;
    let mut ch = s.heads[head_ix(0, L_ALL)][0].get();
    while !ch.is_null() {
        let next = (*ch).link[L_ALL][1];
        if (*ch).empty_sweeps >= EMPTY_SWEEPS && is_empty(ch) {
            if n == limit {
                return; // more next turn (unmap_due stays)
            }
            if !unmap(s, ch) {
                s.unmap_blocked.set(true);
                s.munmap_fail.set(s.munmap_fail.get() + 1);
                return;
            }
            n += 1;
        }
        ch = next;
    }
    s.unmap_due.set(false);
}

/// 70.25 2.5 end of a loop turn (Worker::run, after reap_dead and the sweep): drain remote frees, then release dirty
/// bytes over the cap or owed by the last sweep (bounded), then unmap due chunks (bounded). Order: drain -> madvise ->
/// munmap (a remote link word written after the advise would break the list and the zero fill).
pub fn release() {
    // SAFETY: s is this thread's pool; the chunks on its lists are mapped and owned by it (module contract)
    P.with(|s| unsafe {
        if s.id.get() == NONE {
            return;
        }
        let want = wanted(s);
        let advise_now = want > 0 && !s.advise_blocked.get();
        let unmap_now = s.unmap_due.get() && !s.unmap_blocked.get();
        if !advise_now && !unmap_now && !REMOTE[s.id.get() as usize].load(Relaxed) {
            return; // the common turn: nothing to do, no clock read
        }
        let t0 = Instant::now();
        let c0 = thread_cpu_ns();
        drain(s);
        let want = wanted(s); // (drained blocks may add to the excess over the cap)
        if want > 0 && !s.advise_blocked.get() {
            advise(s, want, true);
        }
        if s.unmap_due.get() && !s.unmap_blocked.get() {
            unmap_some(s, UNMAPS_PER_TURN);
        }
        // review: the whole step (drain, advise, unmap): the releasing worker is busy this long
        let cpu = thread_cpu_ns().saturating_sub(c0) / 1000; // read inside the elapsed window: cpu <= elapsed
        let us = t0.elapsed().as_micros() as u64;
        if us > RELEASE_MAX_US.load(Relaxed) {
            RELEASE_MAX_US.fetch_max(us, Relaxed);
        }
        if cpu > RELEASE_CPU_MAX_US.load(Relaxed) {
            RELEASE_CPU_MAX_US.fetch_max(cpu, Relaxed);
        }
    })
}

/// 70.25 wake rule: release() has work left (the worker loop polls with timeout 0 meanwhile). False while the work is
/// blocked by a failed syscall (no busy loop; retried after the next sweep).
pub fn backlog() -> bool {
    P.with(|s| s.id.get() != NONE && ((wanted(s) > 0 && !s.advise_blocked.get()) || (s.unmap_due.get() && !s.unmap_blocked.get())))
}

/// a remote free is waiting for this thread's next release (pooltest)
#[cfg(feature = "pooltest")]
pub fn remote_pending() -> bool {
    P.with(|s| s.id.get() != NONE && REMOTE[s.id.get() as usize].load(Relaxed))
}

/// mapped chunks of this thread (the worker wakes for idle sweeps while > 0: remote frees, unmapping)
pub fn chunks() -> usize {
    P.with(|s| s.chunks.get())
}

/// 60.09 M2 level 2+: keep at most L2_BYTES dirty (the turn-end release brings it down in bounded batches)
pub fn pause(off: bool) {
    P.with(|s| s.off.set(off))
}

/// What one sweep publishes (counters since the last sweep; chunks/dirty are gauges)
#[derive(Default, Debug, Clone, Copy)]
pub struct Sweep {
    pub hits: u64,
    pub misses: u64,
    pub fallback: u64,
    pub remote: u64,
    pub madvise: u64,
    pub munmaps: u64,
    pub madvise_fail: u64,
    pub munmap_fail: u64,
    pub capped: u64,
    pub chunks: u64,
    pub dirty: u64,
}

/// 70.25 2.5 at each idle sweep: owe what the dirty set did not need since the last sweep (its low-water mark, or all
/// of it if no dirty block was taken: 60.09 M4b), count empty chunks, clear the failure blocks (retry), publish.
pub fn sweep() -> Sweep {
    // SAFETY: as release(): only this thread's own chunks
    P.with(|s| unsafe {
        if s.id.get() == NONE {
            return Sweep::default();
        }
        drain(s);
        let d = s.dirty.get();
        // review: what the last sweep owed and could not release yet (a failed madvise) stays owed
        let owed = if s.taken.get() { s.low.get().min(d) } else { d }.max(s.owed.get().min(d));
        s.owed.set(owed);
        s.low.set(d - owed);
        s.taken.set(false);
        s.map_blocked.set(false);
        s.advise_blocked.set(false);
        s.unmap_blocked.set(false);
        let mut ch = s.heads[head_ix(0, L_ALL)][0].get();
        while !ch.is_null() {
            if is_empty(ch) {
                (*ch).empty_sweeps = (*ch).empty_sweeps.saturating_add(1);
                if (*ch).empty_sweeps >= EMPTY_SWEEPS {
                    s.unmap_due.set(true);
                }
            } else {
                (*ch).empty_sweeps = 0;
            }
            ch = (*ch).link[L_ALL][1];
        }
        Sweep {
            hits: s.hits.replace(0),
            misses: s.misses.replace(0),
            fallback: s.fallback.replace(0),
            remote: s.remote.replace(0),
            madvise: s.madvise.replace(0),
            munmaps: s.munmaps.replace(0),
            madvise_fail: s.madvise_fail.replace(0),
            munmap_fail: s.munmap_fail.replace(0),
            capped: s.capped.replace(0),
            chunks: s.chunks.get() as u64,
            dirty: s.dirty.get() as u64,
        }
    })
}

#[cfg(any(test, fuzzing))]
/// Release every dirty block now (unbounded; tests, off()): drain, then madvise all.
pub fn flush() {
    P.with(|s| unsafe {
        if s.id.get() == NONE {
            return;
        }
        drain(s);
        let d = s.dirty.get();
        if d > 0 {
            advise(s, d, false);
        }
    })
}

#[cfg(any(test, fuzzing))]
/// this thread's pool state (failure messages): flags, failure counters and every mapped chunk
pub fn state() -> String {
    P.with(|s| unsafe {
        let mut o = format!(
            "id {} chunks {} dirty {} owed {} blocked map/advise/unmap {}/{}/{} unmap_due {} fail madvise/munmap {}/{} remote_flag {}",
            s.id.get(),
            s.chunks.get(),
            s.dirty.get(),
            s.owed.get(),
            s.map_blocked.get(),
            s.advise_blocked.get(),
            s.unmap_blocked.get(),
            s.unmap_due.get(),
            s.madvise_fail.get(),
            s.munmap_fail.get(),
            s.id.get() != NONE && REMOTE[s.id.get() as usize].load(Relaxed)
        );
        let mut ch = s.heads[head_ix(0, L_ALL)][0].get();
        while !ch.is_null() {
            // review: copy the header first: growing `o` may map a chunk and relink this one (a chunk mapped by
            // the dump itself may be missed: diagnostics only)
            let ones = |w: [u64; 4]| w.iter().map(|x| x.count_ones()).sum::<u32>();
            let (owner, class, live, bump, free, dirty, remote, on, es, next) = (
                (*ch).owner,
                (*ch).class,
                (*ch).live,
                (*ch).bump,
                ones((*ch).free),
                ones((*ch).dirty),
                !(*ch).remote.load(Relaxed).is_null(),
                (*ch).on,
                (*ch).empty_sweeps,
                (*ch).link[L_ALL][1],
            );
            o += &format!(
                "; chunk {:#x} owner {owner} class {class} live {live} bump {bump} free {free} dirty {dirty} remote {remote} on {on:?} empty_sweeps {es}",
                ch as usize
            );
            ch = next;
        }
        o
    })
}

#[cfg(any(test, fuzzing))]
/// dirty bytes of this thread (tests)
pub fn dirty_bytes() -> usize {
    P.with(|s| s.dirty.get())
}

#[cfg(any(test, fuzzing))]
/// Test/thread-exit helper: flush, unmap every empty chunk (ignoring the sweep count) and turn the pool off for this
/// thread. Returns the chunks left mapped (they hold live blocks: leaked if the thread exits, 70.25 R7).
pub fn off() -> usize {
    flush();
    P.with(|s| unsafe {
        if s.id.get() == NONE {
            return 0;
        }
        let mut ch = s.heads[head_ix(0, L_ALL)][0].get();
        while !ch.is_null() {
            let next = (*ch).link[L_ALL][1];
            if is_empty(ch) && !unmap(s, ch) {
                s.unmap_blocked.set(true);
            }
            ch = next;
        }
        let left = s.chunks.get();
        if left == 0 {
            let id = s.id.replace(NONE) as usize;
            IDS[id / 64].fetch_and(!(1 << (id % 64)), Relaxed);
            s.dirty.set(0);
            s.owed.set(0);
            s.low.set(0);
            s.taken.set(false);
            s.unmap_due.set(false);
        }
        left
    })
}

/// 70.25 4.2 model/stress, shared by the unit test and the fuzz target (server/fuzz pool-ops): random alloc /
/// alloc_zeroed / realloc / free / release / sweep on 2 pool threads + 1 foreign thread, sizes 1..2 MiB, alignments
/// 1..8192, blocks handed between the threads (remote frees, non-owner reallocs). Shadow checks: every live block is
/// poisoned with its id and checked on free and realloc (prefix); a shared reference map of live ranges catches any
/// overlap; alloc_zeroed must return zeros; at the end every pool thread unmaps all its chunks (off() == 0).
#[cfg(any(test, fuzzing))]
pub mod model {
    use super::*;
    use std::alloc::Layout;
    use std::collections::BTreeMap;
    use std::sync::{mpsc, Arc, Barrier, Mutex};

    type Blk = (usize, usize, usize, u64); // ptr, size, align, id

    fn poison(p: usize, size: usize, id: u64) {
        let s = unsafe { std::slice::from_raw_parts_mut(p as *mut u8, size) };
        for i in (0..size).step_by(509) {
            s[i] = (id as u8).wrapping_add((i / 509) as u8);
        }
        if size >= 8 {
            unsafe { (p as *mut u64).write_unaligned(id) };
        }
    }
    /// the first n bytes of a block poisoned at `orig` bytes
    fn verify(p: usize, n: usize, orig: usize, id: u64) {
        let s = unsafe { std::slice::from_raw_parts(p as *const u8, n) };
        let hdr = orig >= 8;
        if hdr && n >= 8 {
            assert_eq!(unsafe { (p as *const u64).read_unaligned() }, id, "block {id}: header");
        }
        for i in (0..n.min(orig)).step_by(509).skip(hdr as usize) {
            assert_eq!(s[i], (id as u8).wrapping_add((i / 509) as u8), "block {id}: byte {i}");
        }
    }
    fn insert(m: &Mutex<BTreeMap<usize, usize>>, p: usize, size: usize) {
        let mut m = m.lock().unwrap();
        if let Some((&a, &l)) = m.range(..=p).next_back() {
            assert!(a + l <= p, "overlap: [{a:#x}+{l}) and [{p:#x}+{size})");
        }
        if let Some((&a, _)) = m.range(p..).next() {
            assert!(p + size <= a, "overlap: [{p:#x}+{size}) and {a:#x}");
        }
        m.insert(p, size);
    }

    /// `data` drives the ops (8 bytes per decision, then a xorshift continues); `ops` per thread
    pub fn stress(data: &[u8], ops: usize) {
        let ranges = Arc::new(Mutex::new(BTreeMap::new()));
        let (b1, b2) = (Arc::new(Barrier::new(3)), Arc::new(Barrier::new(3)));
        let (txs, rxs): (Vec<_>, Vec<_>) = (0..3).map(|_| mpsc::channel::<Vec<Blk>>()).unzip();
        let mut hs = Vec::new();
        for (t, rx) in rxs.into_iter().enumerate() {
            let (txs, ranges, b1, b2) = (txs.clone(), ranges.clone(), b1.clone(), b2.clone());
            let data: Vec<u8> = data.iter().skip(t * 8).copied().collect();
            hs.push(std::thread::spawn(move || {
                let pool = t < 2;
                if pool {
                    assert!(on_page(PAGE, 2 << 20), "pool ids");
                }
                let mut seed = 0x9E37_79B9_7F4A_7C15u64 ^ t as u64;
                let mut pos = 0;
                let mut next = move || {
                    if pos + 8 <= data.len() {
                        let v = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                        pos += 24; // the three threads read interleaved words
                        seed ^= v;
                    }
                    seed ^= seed >> 12;
                    seed ^= seed << 25;
                    seed ^= seed >> 27;
                    seed.wrapping_mul(0x2545_F491_4F6C_DD1D)
                };
                let mut live: Vec<Blk> = Vec::new();
                let mut id = (t as u64) << 40;
                let free = |b: Blk| {
                    let (p, s, a, i) = b;
                    verify(p, s, s, i);
                    ranges.lock().unwrap().remove(&p).expect("freed block in the map");
                    unsafe { std::alloc::dealloc(p as *mut u8, Layout::from_size_align(s, a).unwrap()) };
                };
                for _ in 0..ops {
                    let r = next();
                    let size = match r % 8 {
                        0 => 1 + (r >> 8) as usize % (16 << 10),
                        1 => MIN - 1 + (r >> 8) as usize % 3,
                        2 => MAX_CLASS - 1 + (r >> 8) as usize % 3,
                        3 => (2 << 20) - (r >> 8) as usize % 4096,
                        _ => MIN + (r >> 8) as usize % (MAX_CLASS - MIN),
                    };
                    let align = [1usize, 8, 64, 4096, 8192][(r >> 40) as usize % 5];
                    let mut op = (r >> 48) % 16;
                    if live.len() > 48 && op < 5 {
                        op = 5; // bounded live set
                    }
                    match op {
                        0..=4 => unsafe {
                            let l = Layout::from_size_align(size, align).unwrap();
                            let p = if op == 4 { std::alloc::alloc_zeroed(l) } else { std::alloc::alloc(l) } as usize;
                            assert!(p != 0 && p.is_multiple_of(align));
                            if op == 4 {
                                // (chunks compared with memcmp: a byte loop is slow under the fuzzer's compare tracing)
                                static ZERO: [u8; 4096] = [0; 4096];
                                let z = std::slice::from_raw_parts(p as *const u8, size);
                                assert!(z.chunks(4096).all(|c| c == &ZERO[..c.len()]), "alloc_zeroed");
                            }
                            insert(&ranges, p, size);
                            id += 1;
                            poison(p, size, id);
                            live.push((p, size, align, id));
                        },
                        5..=7 if !live.is_empty() => free(live.swap_remove((r >> 8) as usize % live.len())),
                        8..=10 if !live.is_empty() => unsafe {
                            let j = (r >> 8) as usize % live.len();
                            let (p, s, a, i) = live[j];
                            verify(p, s, s, i);
                            ranges.lock().unwrap().remove(&p);
                            let q = std::alloc::realloc(p as *mut u8, Layout::from_size_align(s, a).unwrap(), size) as usize;
                            assert!(q != 0 && q.is_multiple_of(a));
                            verify(q, s.min(size), s, i);
                            insert(&ranges, q, size);
                            poison(q, size, i);
                            live[j] = (q, size, a, i);
                        },
                        11 if !live.is_empty() => {
                            let n = 1 + (r >> 8) as usize % live.len().min(4);
                            let to = (t + 1 + (r >> 20) as usize % 2) % 3;
                            txs[to].send(live.drain(..n).collect()).unwrap();
                        }
                        12 | 13 => release(),
                        14 if (r >> 8) % 16 == 0 => {
                            sweep();
                        }
                        _ => {}
                    }
                    while let Ok(got) = rx.try_recv() {
                        live.extend(got);
                    }
                }
                b1.wait(); // every send is done
                while let Ok(got) = rx.try_recv() {
                    live.extend(got);
                }
                for b in live.drain(..) {
                    free(b);
                }
                // the live list itself: 256+ entries (blocks received from slow peers) is a 16 KiB+ buffer, a pool block
                // of this thread that off() below would count as live (the rare "chunks left mapped: 1, class 0, live 1")
                drop(live);
                b2.wait(); // every free (remote ones too) is done
                if pool {
                    let left = off();
                    assert!(left == 0, "chunks left mapped after every block was freed: {left}, {}", state());
                }
            }));
        }
        drop(txs);
        for h in hs {
            h.join().unwrap();
        }
        assert!(ranges.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mem::tests::my_heap;
    use std::alloc::{GlobalAlloc, Layout, System};

    /// run f on a fresh pool thread (cap `cap`); at the end every chunk must be unmapped and, if `exact`, this thread's
    /// heap count back where it started (not with remote frees: another thread's slot counts those)
    pub(crate) fn on_pool_thread(cap: usize, exact: bool, f: impl FnOnce() + Send + 'static) {
        std::thread::spawn(move || {
            let _warm = Box::new(0u8); // takes this thread's heap slot
            let start = my_heap();
            assert!(on_page(PAGE, cap));
            f();
            P.with(|s| s.fail.set(0));
            assert_eq!(off(), 0, "chunks left mapped (live pool blocks at the end of the test)");
            if exact {
                assert_eq!(my_heap(), start, "heap count after the pool test");
            }
        })
        .join()
        .unwrap();
    }
    /// a buffer of capacity n that the optimizer cannot remove: in release builds an allocation whose pointer is never
    /// used (alloc + drop) may be elided, and the pool then never sees it (the 70.25 "flaky" syscall_failures)
    fn cap(n: usize) -> Vec<u8> {
        std::hint::black_box(Vec::with_capacity(n))
    }
    fn fail(f: u8) {
        P.with(|s| s.fail.set(f));
    }
    /// turn-end releases until no backlog is left (what the worker loop does with timeout 0)
    pub(crate) fn settle() {
        let mut n = 0;
        while backlog() {
            release();
            n += 1;
            assert!(n < 100_000, "release backlog never ends");
        }
    }
    pub(crate) fn dirty_blocks() -> usize {
        P.with(|s| unsafe {
            let mut n = 0;
            for c in 0..CLASSES {
                let mut ch = s.heads[head_ix(c, L_DIRTY)][0].get();
                while !ch.is_null() {
                    n += (*ch).dirty.iter().map(|w| w.count_ones() as usize).sum::<usize>();
                    ch = (*ch).link[L_DIRTY][1];
                }
            }
            n
        })
    }
    fn fill(v: &mut [u8], seed: u8) {
        for (i, b) in v.iter_mut().enumerate() {
            *b = seed.wrapping_add((i / 7) as u8);
        }
    }
    fn check(v: &[u8], seed: u8) {
        for (i, &b) in v.iter().enumerate() {
            assert_eq!(b, seed.wrapping_add((i / 7) as u8), "byte {i}");
        }
    }

    /// 70.25 2.2 the class table, class_of exact at every class size +-1 and monotone, the measured chains
    #[test]
    fn classes() {
        let kib: Vec<usize> = (0..CLASSES).map(|c| class_bytes(c) >> 10).collect();
        assert_eq!(kib, [16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128]);
        assert_eq!(class_bytes(CLASSES - 1), MAX_CLASS);
        let mut last = 0;
        for size in MIN..=MAX_CLASS {
            let c = class_of(size);
            assert!(class_bytes(c) >= size && (c == 0 || class_bytes(c - 1) < size), "size {size} -> class {c}");
            assert!(c >= last);
            last = c;
        }
        for c in 0..CLASSES {
            let b = class_bytes(c);
            assert_eq!(class_of(b), c);
            if c > 0 {
                assert_eq!(class_of(b - 1), c);
            }
            if c + 1 < CLASSES {
                assert_eq!(class_of(b + 1), c + 1);
            }
            let n = blocks(c);
            assert!((3..=MAX_BLOCKS).contains(&n) && PAGE + n * b <= CH, "class {c}: {n} blocks");
            assert!(n * b * 4 >= (CH - PAGE) * 3, "class {c}: fill below 75%");
        }
        // 70.20 / 70.11 chains: rbuf exact, obuf/bulk room + CHUNK doublings into the 5/4 classes (above 128 KiB: glibc)
        for (size, k) in [(16384, 16), (32768, 32), (65536, 64), (131072, 128), (65539, 80)] {
            assert_eq!(class_bytes(class_of(size)) >> 10, k, "{size}");
        }
        assert!(!in_range(MIN - 1, 1) && in_range(MIN, 1) && in_range(MAX_CLASS, 1) && !in_range(MAX_CLASS + 1, 1));
        for a in [1, 2, 4, 8, 16, 64, 4096] {
            assert!(in_range(MIN, a));
        }
        assert!(!in_range(MIN, 8192));
    }

    /// alloc/free/reuse, alloc_zeroed on a dirty and on a released block, the cap, release in runs, unmap after
    /// two empty sweeps; heap_bytes exact throughout
    #[test]
    fn reuse_release_unmap() {
        on_pool_thread(1 << 20, true, || {
            let h0 = my_heap();
            let mut v = cap(20000);
            let p = v.as_mut_ptr();
            assert!(is_pool(p) && (p as usize).is_multiple_of(PAGE));
            assert_eq!(chunks(), 1);
            v.resize(20000, 0);
            fill(&mut v, 3);
            drop(v);
            assert_eq!((dirty_blocks(), dirty_bytes()), (1, 20 << 10));
            let w = cap(17000); // same class (20 K): the dirty block again
            assert_eq!(w.as_ptr(), p as *const u8);
            drop(w);
            let z = vec![0u8; 20000]; // alloc_zeroed on the dirty block: cleared
            assert_eq!(z.as_ptr(), p as *const u8);
            assert!(z.iter().all(|&b| b == 0));
            let mut z = z;
            fill(&mut z, 9);
            drop(z);
            flush(); // released: clean
            assert_eq!(dirty_bytes(), 0);
            let z = vec![0u8; 20000]; // a clean block: zero pages without a memset
            assert_eq!(z.as_ptr(), p as *const u8);
            assert!(z.iter().all(|&b| b == 0));
            drop(z);
            // over the cap (1 MiB): the turn end releases the excess only (largest class first)
            let many: Vec<Vec<u8>> = (0..100).map(|_| cap(MIN)).collect();
            drop(many);
            assert_eq!(dirty_bytes(), 100 * MIN + (20 << 10));
            assert!(backlog());
            settle();
            assert_eq!(dirty_bytes(), 1 << 20);
            if let (Some(a), Some(b)) = (my_heap(), h0) {
                assert_eq!(a - b, (1 << 20) + 2 * PAGE as isize, "dirty + 2 header pages");
            }
            sweep(); // blocks were taken since the start (low-water 0): nothing owed
            settle();
            assert_eq!(dirty_bytes(), 1 << 20);
            sweep(); // idle: all owed
            settle();
            assert_eq!(dirty_bytes(), 0);
            assert_eq!(chunks(), 1, "the 20 K chunk (released by the cap) was empty at two sweeps: unmapped");
            sweep();
            assert!(!backlog(), "empty at one sweep only");
            sweep();
            assert!(backlog());
            settle();
            assert_eq!(chunks(), 0);
            assert_eq!(my_heap(), h0);
        });
    }

    /// 60.09 M4b ported (the 70.11 test): the sweep owes the low-water mark (all when nothing was taken), a flush lowers
    /// it; M2: at most L2_BYTES dirty at level 2+, the full cap again below
    #[test]
    fn sweep_low_water_and_pause() {
        on_pool_thread(4 << 20, true, || {
            let blocks = |k: usize| (0..k).map(|_| cap(MIN)).collect::<Vec<_>>();
            drop(blocks(4));
            sweep();
            settle();
            assert_eq!(dirty_blocks(), 0, "nothing taken since the last sweep: all released");
            drop(blocks(4)); // clean blocks again: no take
            let keep = blocks(1); // a take (low-water mark 0 since the last sweep)
            sweep();
            settle();
            assert_eq!(dirty_blocks(), 3, "low-water mark 0: nothing released");
            drop(blocks(2)); // churn: 2 taken (3 -> 1, the low-water mark) and given back
            assert_eq!(dirty_blocks(), 3);
            sweep();
            settle();
            assert_eq!(dirty_blocks(), 2, "the one block not needed since the last sweep");
            sweep(); // idle
            settle();
            assert_eq!(dirty_blocks(), 0);
            drop(blocks(4));
            drop(blocks(1)); // a take (low 0) and a put back: 4 dirty
            sweep(); // keeps all 4; low = 4
            settle();
            assert_eq!(dirty_blocks(), 4);
            flush(); // e.g. at level 2: lowers the low-water mark
            drop(blocks(4));
            drop(blocks(1));
            sweep();
            settle();
            assert_eq!(dirty_blocks(), 4, "low-water mark 0 after the flush: the new working set is kept");
            pause(true);
            let n = crate::mem::L2_BYTES / MIN + 8;
            drop(blocks(n));
            assert!(backlog());
            settle();
            assert!(dirty_bytes() <= crate::mem::L2_BYTES && dirty_bytes() > 0, "paused: at most L2_BYTES");
            pause(false);
            drop(blocks(n));
            settle();
            assert_eq!(dirty_blocks(), n, "the full cap again");
            drop(keep);
        });
    }

    /// the realloc matrix by origin (70.25 2.1), contents preserved (patterns)
    #[test]
    fn realloc_matrix() {
        on_pool_thread(16 << 20, false, || {
            // System 4 KiB -> 16 KiB on a pool thread: into the pool (rule 3: every rbuf starts as vec![0; 4096])
            let mut r = vec![0u8; 4096];
            assert!(!is_pool(r.as_mut_ptr()));
            fill(&mut r, 1);
            r.reserve_exact(MIN - 4096);
            assert!(is_pool(r.as_mut_ptr()));
            check(&r, 1);
            // same class (65539 -> 70000, 80 K): in place (rule 1)
            let mut v = vec![0u8; 65539];
            fill(&mut v, 2);
            let p = v.as_ptr();
            v.reserve_exact(70000 - v.len());
            assert_eq!(v.as_ptr(), p);
            // the obuf chain to MAX_CLASS: other classes (rule 2), then past MAX_CLASS -> glibc (one copy, then mremap)
            for want in [100000, 131072] {
                v.reserve_exact(want - v.len());
                assert!(is_pool(v.as_mut_ptr()), "{want}");
                check(&v, 2);
                v.resize(want, 0);
                fill(&mut v, 2);
            }
            for want in [131078, 262156, 524312, 1048624, 2097248] {
                v.reserve_exact(want - v.len());
                assert!(!is_pool(v.as_mut_ptr()), "{want} > MAX_CLASS: glibc");
                check(&v, 2);
                v.resize(want, 0);
                fill(&mut v, 2);
            }
            // shrink_to: glibc 2 MiB -> 128 KiB (System -> pool), then -> 8 KiB (pool -> System)
            v.truncate(100000);
            v.shrink_to(128 << 10);
            assert!(is_pool(v.as_mut_ptr()));
            check(&v, 2);
            v.truncate(8000);
            v.shrink_to(8 << 10);
            assert!(!is_pool(v.as_mut_ptr()));
            check(&v, 2);
            // pend.shrink_to(keep / 4 = 16384) at L2/L3 (worker/upload.rs): exactly the lower bound, stays in the pool
            let mut q = cap(100000);
            q.resize(10000, 0);
            fill(&mut q, 4);
            q.shrink_to(16384);
            assert!(is_pool(q.as_mut_ptr()));
            check(&q, 4);
            // main-thread (System) 1 MiB blocks grown on a worker: past MAX_CLASS System.realloc (rule 4), within: pool
            let (mut big, mut big2) = std::thread::spawn(|| {
                let mk = || {
                    let mut b = vec![0u8; 1 << 20];
                    fill(&mut b, 5);
                    b
                };
                (mk(), mk())
            })
            .join()
            .unwrap();
            assert!(!is_pool(big.as_mut_ptr()) && !is_pool(big2.as_mut_ptr()));
            big.reserve_exact(1 << 20);
            assert!(!is_pool(big.as_mut_ptr()));
            check(&big, 5);
            big2.truncate(100 << 10);
            big2.shrink_to(120 << 10);
            assert!(is_pool(big2.as_mut_ptr()), "System 1 MiB -> 120 KiB on a pool thread: pool");
            check(&big2, 5);
            // alignments: <= 4096 pooled, 8192 stays on glibc
            unsafe {
                for a in [8, 4096, 8192] {
                    let l = Layout::from_size_align(MIN, a).unwrap();
                    let p = std::alloc::alloc(l);
                    assert!(!p.is_null() && (p as usize).is_multiple_of(a));
                    assert_eq!(is_pool(p), a <= 4096);
                    let q = std::alloc::realloc(p, l, 100000);
                    assert!((q as usize).is_multiple_of(a));
                    assert_eq!(is_pool(q), a <= 4096);
                    std::alloc::dealloc(q, Layout::from_size_align(100000, a).unwrap());
                }
            }
            drop((r, v, q, big, big2));
        });
    }

    /// 70.25 2.7: Inbox.fds grown on one worker and dropped on another (a real remote free), a non-owner realloc, a
    /// non-pool thread's free; counted live until drained, then released and unmapped
    #[test]
    fn remote_frees() {
        on_pool_thread(16 << 20, false, || {
            let mut fds = Vec::<i32>::new();
            for fd in 0..5000 {
                fds.push(fd); // grows past 16 KiB into the pool
            }
            assert!(is_pool(fds.as_ptr() as *mut u8));
            let mut buf = vec![0u8; 40000];
            fill(&mut buf, 6);
            let mut other = vec![0u8; 70000];
            fill(&mut other, 7);
            let me = P.with(|s| s.id.get());
            std::thread::spawn(move || {
                assert!(on_page(PAGE, 16 << 20));
                assert!(P.with(|s| s.id.get()) != me);
                assert!((0..5000).eq(fds.iter().copied()));
                drop(fds); // worker -> worker remote free
                check(&buf, 6);
                buf.reserve_exact(60000); // non-owner realloc: a block here + copy + remote free
                assert!(is_pool(buf.as_mut_ptr()));
                check(&buf, 6);
                drop(buf);
                assert_eq!(off(), 0);
            })
            .join()
            .unwrap();
            std::thread::spawn(move || {
                check(&other, 7);
                drop(other); // a non-pool thread's free
            })
            .join()
            .unwrap();
            assert_eq!(dirty_bytes(), 16 << 10, "fds' first pool block only: remote-freed blocks count as live until drained");
            assert!(REMOTE[me as usize].load(Relaxed));
            release(); // drains (16 MiB cap: nothing released)
            assert_eq!(dirty_bytes(), (32 << 10) + (40 << 10) + (80 << 10) + (16 << 10), "fds 16 K + 32 K, buf, other");
            let sw = sweep();
            assert_eq!(sw.remote, 3);
            settle(); // idle sweep: all owed
            assert_eq!(dirty_bytes(), 0);
            sweep();
            sweep();
            settle();
            assert_eq!(chunks(), 0);
        });
    }

    /// 70.25 2.9 failure injection, each on its own: mmap and the alignment trim (System serves, counted, retried
    /// after a sweep), madvise (blocks stay dirty, no busy loop), munmap (chunk kept and usable, retried)
    #[test]
    fn syscall_failures() {
        on_pool_thread(0, true, || {
            // F_TRIM2 fails the second cut, which exists only when the 8 MiB mapping was not 4 MiB aligned (almost
            // always; an aligned one has a single cut): then the chunk is simply mapped
            for f in [F_MMAP, F_TRIM, F_TRIM2] {
                fail(f);
                let v = cap(MIN);
                if f == F_TRIM2 && is_pool(v.as_ptr() as *mut u8) {
                    drop(v);
                    fail(0);
                    settle();
                    sweep();
                    sweep();
                    settle();
                    continue;
                }
                assert!(!is_pool(v.as_ptr() as *mut u8), "System serves");
                assert_eq!(chunks(), 0);
                drop(v);
                fail(0);
                let v = cap(MIN);
                assert!(!is_pool(v.as_ptr() as *mut u8), "no new mmap attempt before the next sweep");
                drop(v);
                assert_eq!(sweep().fallback, 2);
                let v = cap(MIN);
                assert!(is_pool(v.as_ptr() as *mut u8), "retried after the sweep");
                drop(v);
                settle();
                sweep();
                sweep();
                settle();
                assert_eq!(chunks(), 0);
            }
            // madvise (cap 0: every free is over the cap)
            let v = cap(MIN);
            let state =
                || P.with(|s| (is_pool(v.as_ptr() as *mut u8), s.chunks.get(), s.map_blocked.get(), s.advise_blocked.get(), s.dirty.get()));
            let st0 = state();
            fail(F_MADVISE);
            drop(v);
            assert!(backlog(), "{st0:?}");
            release();
            assert_eq!(dirty_bytes(), MIN, "stays dirty");
            assert!(!backlog(), "blocked until the next sweep: no busy loop");
            fail(0);
            release();
            assert_eq!(dirty_bytes(), MIN);
            sweep();
            settle();
            assert_eq!(dirty_bytes(), 0, "retried after the sweep");
            // munmap
            sweep();
            sweep();
            fail(F_MUNMAP);
            settle();
            assert_eq!(chunks(), 1, "kept");
            assert!(!backlog());
            let v = cap(MIN); // the kept chunk is usable
            assert!(is_pool(v.as_ptr() as *mut u8));
            drop(v);
            fail(0);
            settle();
            sweep();
            sweep();
            settle();
            assert_eq!(chunks(), 0, "retried");
        });
    }

    /// 70.25 item 4: the chunk budget. At the cap a new chunk is refused like a failed mmap (System serves, counted,
    /// retried after the next sweep); blocks of the mapped chunks are still used. And the budget arithmetic.
    #[test]
    fn chunk_budget() {
        assert_eq!(chunk_max(Some(1024), None), 256);
        assert_eq!(chunk_max(Some(512), Some(8 << 30)), 128);
        assert_eq!(chunk_max(Some(512), Some(2 << 30)), 32);
        assert_eq!(chunk_max(Some(65530), Some(2 << 30)), 32, "RLIMIT_AS 2 GiB: a sixteenth of it in 4 MiB chunks");
        assert_eq!(chunk_max(Some(65530), Some(32 << 20)), 0, "a tiny limit: no pool");
        assert_eq!(chunk_max(None, None), 65530 / 4);
        assert_eq!(chunk_max(Some(3), None), 0);
        let per = blocks(CLASSES - 1); // MAX_CLASS blocks per chunk
        for max in [0, 1, 2] {
            on_pool_thread(0, true, move || {
                P.with(|s| s.test_max.set(max));
                let v: Vec<Vec<u8>> = (0..max * per + 1).map(|_| cap(MAX_CLASS)).collect();
                let pooled = v.iter().filter(|b| is_pool(b.as_ptr() as *mut u8)).count();
                assert_eq!(pooled, max * per, "the mapped chunks are filled");
                assert!(!is_pool(v[max * per].as_ptr() as *mut u8), "System serves at the cap");
                assert_eq!(chunks(), max);
                let more = cap(MAX_CLASS);
                assert!(!is_pool(more.as_ptr() as *mut u8));
                drop(more);
                let sw = sweep();
                assert_eq!((sw.capped, sw.fallback), (1, 2), "one refusal, then blocked until the sweep");
                P.with(|s| s.test_max.set(usize::MAX));
                let after = cap(MAX_CLASS);
                assert!(is_pool(after.as_ptr() as *mut u8), "retried after the sweep");
                drop(after);
                drop(v);
                settle();
                sweep();
                sweep();
                settle();
                assert_eq!(chunks(), 0);
            });
        }
    }

    /// 70.25 4.1 release bounds: a big idle release takes several turns of <= RELEASE_CALLS calls / RELEASE_BYTES
    #[test]
    fn release_is_bounded() {
        on_pool_thread(16 << 20, true, || {
            let many: Vec<Vec<u8>> = (0..1000).map(|_| cap(64 << 10)).collect();
            for (i, v) in many.into_iter().enumerate() {
                if i % 2 == 0 {
                    drop(v); // every other block: runs of one block, no merging
                } else {
                    std::mem::forget(v);
                }
            }
            sweep(); // nothing taken: all 500 owed
            let before = dirty_bytes();
            release();
            let one = before - dirty_bytes();
            assert!(one > 0 && one <= RELEASE_CALLS as usize * (64 << 10), "{one}");
            settle();
            assert_eq!(dirty_bytes(), 0);
            // review (review; final review): the byte bound binds before the call bound: ~19 MiB of
            // contiguous MAX_CLASS blocks in runs of RUN_MAX, the last call of the turn cut to what still fits
            let big: Vec<Vec<u8>> = (0..(19 << 20) / MAX_CLASS).map(|_| cap(MAX_CLASS)).collect();
            drop(big);
            sweep();
            let before = dirty_bytes();
            assert!(before > 2 * RELEASE_BYTES);
            release();
            let one = before - dirty_bytes();
            assert!(one > RELEASE_BYTES - MAX_CLASS && one <= RELEASE_BYTES, "{one}");
            assert!(P.with(|s| s.madvise.get()) < RELEASE_CALLS as u64 * 2, "the bytes bound, not the calls bound");
            // 60.16 the CPU max comes from a window inside the elapsed one (+1: rounding). Order matters across threads:
            // release() stores elapsed before cpu, this reads cpu before elapsed (both only grow)
            let cpu = RELEASE_CPU_MAX_US.load(Relaxed);
            assert!(cpu <= RELEASE_MAX_US.load(Relaxed) + 1, "cpu {cpu} > elapsed");
            assert!(backlog(), "the rest in later turns");
            settle();
            // the forgotten blocks: free them now (pointers recomputed from the chunks would be overkill: flush + off
            // below leave their chunks mapped, so collect them back instead)
            P.with(|s| unsafe {
                let c = class_of(64 << 10);
                let mut ch = s.heads[head_ix(0, L_ALL)][0].get();
                while !ch.is_null() {
                    let next = (*ch).link[L_ALL][1];
                    if (*ch).class as usize == c {
                        for i in 0..(*ch).bump as usize {
                            if !bit(&(*ch).free, i) {
                                std::alloc::dealloc(block(ch, i, class_bytes(c)), Layout::from_size_align(64 << 10, 1).unwrap());
                            }
                        }
                    }
                    ch = next;
                }
            });
        });
    }

    /// 60.16 pool_release_cpu_max_us: the thread CPU clock advances with this thread's work (spin until it moved 2 ms;
    /// review: spinning on CPU time, not wall time, cannot flake under preemption) and not while it sleeps (20 ms asleep:
    /// well under 10 ms)
    #[test]
    fn thread_cpu_clock() {
        let (c0, t0) = (thread_cpu_ns(), Instant::now());
        while thread_cpu_ns().saturating_sub(c0) < 2_000_000 {
            assert!(t0.elapsed() < std::time::Duration::from_secs(10), "thread CPU clock does not advance");
            std::hint::spin_loop();
        }
        let c1 = thread_cpu_ns();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(thread_cpu_ns().saturating_sub(c1) < 10_000_000);
    }

    /// review: bytes a sweep owed that a failed madvise kept dirty stay owed at the next sweep, also when a block
    /// was taken meanwhile (low-water mark 0)
    #[test]
    fn failed_release_stays_owed() {
        on_pool_thread(16 << 20, true, || {
            let blocks = |k: usize| (0..k).map(|_| cap(MIN)).collect::<Vec<_>>();
            drop(blocks(3));
            sweep(); // nothing taken: all 3 owed
            fail(F_MADVISE);
            release();
            assert_eq!(dirty_blocks(), 3);
            fail(0);
            drop(blocks(1)); // a take (owed 2, low-water 0) and back
            sweep();
            settle();
            assert_eq!(dirty_blocks(), 1, "the 2 still owed are released");
            sweep();
            settle();
        });
    }

    /// 70.25 2.1 accidental clients: a HashMap that grows past 16 KiB and shrinks; is_pool is false for System pointers
    /// of every pool size; a page size other than 4096 keeps the thread on glibc (4.9)
    #[test]
    fn accidental_clients_and_gates() {
        on_pool_thread(16 << 20, true, || {
            let mut m = std::collections::HashMap::<u64, u64>::new();
            for i in 0..5000 {
                m.insert(i, i * 3);
            }
            for i in 0..4990 {
                m.remove(&i);
            }
            m.shrink_to_fit();
            assert!((4990..5000).all(|i| m[&i] == i * 3));
            drop(m);
        });
        std::thread::spawn(|| {
            for c in 0..CLASSES {
                for size in [class_bytes(c) - 1, class_bytes(c)] {
                    let v = cap(size);
                    assert!(!is_pool(v.as_ptr() as *mut u8));
                }
            }
            assert!(!on_page(16384, 1 << 20));
            assert!(!active());
            // 60.16 the capability line says so
            assert_eq!(refused_for(16384, 4).as_deref(), Some("off: page size 16384, not 4096; glibc serves"));
            assert_eq!(refused_for(PAGE, MAX_POOLS), None);
            assert_eq!(refused_for(PAGE, MAX_POOLS + 1), Some(format!("{MAX_POOLS} of {} workers; the rest use glibc", MAX_POOLS + 1)));
            let v = cap(MIN);
            assert!(!is_pool(v.as_ptr() as *mut u8));
            unsafe {
                let l = Layout::from_size_align(MIN, 8).unwrap();
                let p = System.alloc(l);
                assert!(!is_pool(p));
                System.dealloc(p, l);
            }
        })
        .join()
        .unwrap();
    }

    #[test]
    fn model_stress() {
        for seed in 0u64..3 {
            model::stress(&seed.to_le_bytes(), 2000);
        }
    }
}
