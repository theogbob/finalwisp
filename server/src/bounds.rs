//! 60.63 section E of the public preset: guards on what the server can see on its host. Each is an option, off by
//! default, and free when off: no stream path tests an option of this file. A worker reaches this code only from the
//! out-of-line side of 60.57's fd count (worker/fds.rs: fd_grab, fd_grab_t, fd_more, fd_short, fd_trim) and from its
//! own idle sweep (worker/bounds.rs).
//!
//! E1 --tcpmem-share: host TCP memory (/proc/net/sockstat) against net.ipv4.tcp_mem's maximum. From 3/4 of it a
//! client address that holds more than half of all unread target sockets, while another client is connected, gets
//! its new streams refused. Where tcp_mem is not readable (a container with its own network namespace) the kernel's
//! pressure flag (/proc/net/protocols) arms the share rule. There is no host-wide stop: one was built and measured
//! (60.63, cell e1M): new unread downloads bring their memory 1 to 2 s after they are admitted, so a burst from many
//! addresses passed the mark, and the stop then refused the honest clients and saved nothing.
//!
//! E2 --port-share: the host's source ports toward one destination ip:port (TCP). The usable range is
//! net.ipv4.ip_local_port_range minus the reserved ports in it. From 1/4 of it in use toward one destination, new
//! target sockets to that destination get the socket option IP_LOCAL_PORT_RANGE (the kernel then searches every port,
//! not the even ones first: 60.63 E2). From 3/4, a client address that holds more than half of the sockets to that
//! destination gets its new streams to it refused while another client holds a socket to it. When the kernel has no
//! port left (EADDRNOTAVAIL) the stream is refused, and for PT_FULL_MS new attempts to that destination are refused
//! without the kernel's search.
//!
//! E3 --dest-failfast: a destination that does not answer gets no new SYN. Worker-local (worker/bounds.rs): a
//! destination is a suspect when DF_K of the worker's connecting sockets to it are ripe (in the last DF_RIPE_MS before
//! their deadline) and have each sent DF_SYNS SYNs without an answer, and no target to it opened since the last count;
//! until it answers, a new stream to it is refused at once (the CLOSE it would get at the connect deadline), except
//! one probe per DF_PROBE_MS. 60.78 bundle B1: a destination with a connect DF_AGE_MS old and no answer is failing
//! (DF_FAIL_KEEP_MS, or until a target to it opens); a client address with DF_FAIL_FLY connects in flight per worker
//! that are that old or go to failing destinations gets no new connect to a failing destination or to one without an
//! open target (many distinct destinations that do not answer).
//!
//! E5 --unread-close: a connection whose client stopped reading its downloads, while the host's TCP memory is short
//! (the reading and the marks of E1: TM_SHARE_IN_16 / TM_SHARE_OUT_16), is reset. A worker judges at its idle sweep only: a connection
//! with a parked download (Target::blocked, as E1 counts it) whose client advertises a zero receive window (TCP_INFO
//! tcpi_snd_wnd: the client's own buffer is full, so neither the host's memory nor the network is the cause) and
//! takes no byte (tcpi_bytes_acked) uses up its credit (uc_step): UC_STALL_MS to start, bought back by bytes taken
//! (UC_RATE per second, at most UC_CAP_MS), used faster when the connection holds more than one full stream. A reset frees the target sockets'
//! receive buffers and the client socket's send queue; a CLOSE per stream cannot reach a client that reads nothing.
//!
//! E4 --net-watch: no refusal. What the server cannot bound, because the host has no readable limit for packets out:
//! connects to many destinations that do not answer (SYN retransmits) and UDP datagrams. Two host counters in the
//! metrics, a gauge of the connects in flight, and a log line per shape from the guard thread (nw_lines).

use crate::clientip::IpKey;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// which options are on (Bounds::opts)
pub const OPT_TCPMEM: u8 = 1;
pub const OPT_PORT: u8 = 2;
pub const OPT_DEAD: u8 = 4;
pub const OPT_WATCH: u8 = 8;
pub const OPT_UNREAD: u8 = 16;
/// 60.78 G70 the relief part of --unread-close (OPT_UNREAD with the Mem form and SO_BUF_LOCK)
pub const OPT_RELIEF: u8 = 32;

/// Bounds::state bits: E1 the share mark
pub const ST_TM_SHARE: u8 = 1;
/// E5 the host's TCP memory is short (the same marks as E1). Not a hold-mode bit: a worker reads it at its sweep.
pub const ST_UNREAD: u8 = 2;
/// E2 some destination holds 1/4 of the port range (the socket option), 3/4 (the share rule)
pub const ST_PT_BUSY: u8 = 4;
pub const ST_PT_SHORT: u8 = 8;

/// E2 the marks as parts of the usable port range in 16ths. The state bits have an exit mark (a worker's hold mode
/// does not flap); one destination is judged against the entry mark alone.
pub const PT_BUSY_IN_16: u64 = 4;
pub const PT_BUSY_OUT_16: u64 = 3;
pub const PT_SHORT_IN_16: u64 = 12;
pub const PT_SHORT_OUT_16: u64 = 11;
/// E2 the reserve: the last 1/16 of the ports toward a destination is kept for an address that comes later (pt_last)
pub const PT_LAST_IN_16: u64 = 15;
/// E2 an address is refused only when it holds more than 1 / PT_KEY_DIV of the sockets to the destination
pub const PT_KEY_DIV: u64 = 2;
/// E2 the destinations a worker publishes (its largest); a destination beyond them is not seen (the rules act late)
pub const PT_TOP: usize = 8;
/// E2 after the kernel had no port left toward a destination, attempts to it are refused for this long (then one
/// attempt asks the kernel again)
pub const PT_FULL_MS: u64 = 250;
/// E2 the guard thread's period for the port counts, and how often it reads the host's port range again
pub const PT_PERIOD_MS: u64 = 250;
pub const PT_RANGE_EVERY_MS: u64 = 10_000;
/// E3 a destination is a suspect with this many connecting sockets that look dead (above a browser's 6 parallel
/// connections to one host; the 60.63 model gives the same result for 4, 8 and 16)
pub const DF_K: u32 = 8;
/// E3 a connecting socket looks dead when the kernel has sent this many SYNs on it without an answer (the first and
/// 3 retransmits: a target that answers the 2nd or the 3rd SYN is never taken for dead, on any retransmit schedule)
pub const DF_SYNS: u8 = 4;
/// E3 no kernel sends its 4th SYN before this age (the first retransmit timeout is 1 s): younger sockets are not asked
pub const DF_AGE_MS: u64 = 3000;
/// E3 a connecting socket counts toward a suspect only in the last this many ms before its connect deadline (from 7.5 s
/// of age at the default --connect-timeout 10): a destination that answers a late SYN (the 5th at 4 s, the 4th of the
/// standard schedule at 7 s) is never taken for dead. Above the idle sweep's 2 s, so that a count sees every such socket.
/// 60.78 bundle B1
pub const DF_RIPE_MS: u64 = 2500;
/// E3 a destination is failing from the first count that sees a connect to it DF_AGE_MS old without an answer, and
/// stays so until a target to it opens or for this long after the last such count (or refused attempt). 60.78 bundle B1
pub const DF_FAIL_KEEP_MS: u64 = 30_000;
/// E3 the failing destinations a worker keeps (more: not kept, their connects are not in the budget)
pub const DF_FAIL_MAX: usize = 4096;
/// E3 one client address may have this many connects in flight per worker thread that are DF_AGE_MS old or go to failing
/// destinations; above it its new connect to a failing destination or to one without an open target is refused (many
/// distinct destinations that do not answer). Above a page of a browser on one slow host (60.78 bundle B1: e3five, at
/// most about 50 in flight).
pub const DF_FAIL_FLY: u32 = 64;
/// E3 one probe per this per worker to a suspect destination
pub const DF_PROBE_MS: u64 = 1000;
/// E3 the suspects a worker keeps (more: not kept, nothing refused for them)
pub const DF_MAX: usize = 256;
/// E3 at most this many connecting sockets are asked for their SYN count at one count (one getsockopt each)
pub const DF_ASK_MAX: u32 = 256;
/// E4 the guard thread compares the host's packet counters over this window
pub const NW_WINDOW_MS: u64 = 10_000;
/// E4 the SYN line needs this many SYN retransmits per connect attempt of the host in the window. 60.63: the largest
/// honest window has 0.86 (100 browsers, a page host that is slow but alive; no window with 100 retransmits is above
/// 1.72). 60.63: connects to ports that do not answer have 5.8 to 6.2.
pub const NW_SYN_PER_OPEN: u64 = 3;
/// ... and this many SYN retransmits in the window. A threshold for a log line, not a limit. 60.63: 2,969 per second
/// was the largest step without harm to other clients, 4,157 the first with harm; the largest honest window of 60.63
/// has 19,160 in 10 s.
pub const NW_SYN_FLOOR: u64 = 30_000;
/// E4 the UDP line needs UDP datagrams to be 1/NW_UDP_DIV of all packets the host sent in the window ...
pub const NW_UDP_DIV: u64 = 2;
/// ... and this many. 60.63: 5,000 datagrams per second did no harm to other clients, 10,000 did.
pub const NW_UDP_FLOOR: u64 = 75_000;
/// IPPROTO_IP socket option (Linux 6.3): the socket's own local port range, low | high << 16
pub const IP_LOCAL_PORT_RANGE: libc::c_int = 51;

/// E1 the mark as parts of tcp_mem's maximum in 16ths, entry and exit (the fractions of 60.57 C). Starting values.
pub const TM_SHARE_IN_16: u64 = 12;
pub const TM_SHARE_OUT_16: u64 = 11;
/// E1 an address is refused only when it holds more than 1 / TM_KEY_DIV of all unread target sockets ...
pub const TM_KEY_DIV: u64 = 2;
/// ... and only when those sockets could matter on this host: their number times the kernel's default receive buffer
/// (tcp_rmem[1], what a socket that was never read fast holds) is at least 1 / TM_FLOOR_DIV of the memory limit
pub const TM_FLOOR_DIV: u64 = 16;
/// E5 the credit of a connection (60.78 T2): every connection starts with UC_STALL_MS of stall time. A stall is the time
/// between two sweeps that both see a zero receive window and no new byte taken; it uses the credit up. Bytes the client
/// takes buy credit back at UC_RATE bytes per second of stall (the first bytes seen, its fill, at UC_FILL_DIV x that
/// price), up to UC_CAP_MS. A connection whose credit is used up is reset while the host is short. Why: a Linux client
/// with a full buffer opens its window again only when much of it is free, so an honest slow reader takes nothing for
/// long, and how long grows with its buffer (60.73 T-wnd-big: 168-187 s at 2 KiB/s with the autotuned default buffer,
/// 315-346 s with 8 MiB). That gap is paid for: the drain before the window opens again is at most 1.30 x the bytes
/// taken in the take before it, and at most 0.086 x the fill (8 MB and more). So credit bought with taken bytes keeps a
/// reader of 1 KiB/s or more with any buffer, and a client that takes nothing (or a byte now and then) gets
/// UC_STALL_MS in all, whatever it announces. v1.3.2/v1.3.3: a fixed 600 s per stall, restarted by any byte taken.
pub const UC_STALL_MS: u64 = 600_000;
/// E5 the most credit a connection can hold (a reader with a 32 MiB buffer at 1 KiB/s: an estimated first gap of 2100 s)
pub const UC_CAP_MS: u64 = 3_600_000;
/// E5 bytes taken per second of credit (half of the slowest reader the rule keeps, 1 KiB/s)
pub const UC_RATE: u64 = 512;
/// E5 the first bytes seen of a connection (its fill) buy credit at this many times UC_RATE. Only the bytes of the
/// first sweep that sees the connection with a parked download: a client parked early pays the rest of its fill at
/// UC_RATE, which is the re-buy price any client has (review)
pub const UC_FILL_DIV: u64 = 8;
/// E5 the TCP_INFO bytes up to tcpi_snd_wnd (offset 228, Linux 5.4 and later)
pub const UC_INFO_LEN: usize = 232;

/// E1 a worker's published counts are used for this long (three idle sweeps: a worker without clients does not sweep)
pub const SLOT_FRESH_MS: u64 = 6000;
/// E1 flag form: the share mark stays this long after the kernel's pressure flag went off (it flaps)
pub const FLAG_HOLD_MS: u64 = 1000;
/// the guard thread's period: far below the first mark, near it, and from it on
pub const PERIOD_FAR_MS: u64 = 250;
pub const PERIOD_NEAR_MS: u64 = 50;
pub const PERIOD_AT_MS: u64 = 20;
/// at most one log line per kind per this
pub const LOG_EVERY_MS: u64 = 10_000;

/// One value alone on its cache lines (as fdgate::Line)
#[repr(align(128))]
#[derive(Default)]
struct Line<T>(T);

/// E1 which host signal is in use
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TcpForm {
    /// tcp_mem is readable: its maximum in pages
    Mem { max_pages: u64 },
    /// tcp_mem is not readable: the kernel's pressure flag only (share rule while it is set)
    Flag,
}

/// rate-limited log lines (one slot each in Bounds::log_at)
#[derive(Clone, Copy)]
#[allow(clippy::enum_variant_names)] // (E1 only so far: the other parts of section E add kinds with other prefixes)
pub enum Log {
    TmShareMark,
    TmShareRefused,
    PtShortMark,
    PtShareRefused,
    PtFullRefused,
    DfSuspect,
    DfRefused,
    PtLastRefused,
    UcReset,
    UcMark,
}
const LOG_KINDS: usize = 10;

/// E2 a destination: the address and port a target socket is connected (or connecting) to
pub type Dest = (IpAddr, u16);

/// E2 one destination of one worker at its last sweep: its sockets to it (`n`; 0 = an empty entry), and the client
/// address with the most of them (`top`, `top_n`). Sockets of clients without a key are in `n` only.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct DestTop {
    pub dest: Dest,
    pub n: u32,
    pub top: Option<IpKey>,
    pub top_n: u32,
}
impl DestTop {
    pub const EMPTY: DestTop = DestTop { dest: (IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0), n: 0, top: None, top_n: 0 };
}
pub type Dests = [DestTop; PT_TOP];

/// E2 what the workers know of `dest`, for the client address `key` (None: a client without a key)
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct DestView {
    /// sockets to it, all workers (a lower bound: a worker publishes its PT_TOP largest destinations)
    pub total: u64,
    /// those of `key` (a lower bound: only where `key` is a worker's largest holder)
    pub mine: u64,
    /// a socket to it that is not `key`'s exists
    pub others: bool,
    /// sockets to it that the workers may hold without publishing them (an upper bound): a worker whose PT_TOP
    /// published destinations do not hold it can have as many as its smallest published one
    pub hidden: u64,
}

/// E2 sum the published destinations (`dests[i]` of the worker whose counts are `slots[i]`, those fresh at `now_ms`)
pub fn pt_view(slots: &[Unread], dests: &[Dests], now_ms: u64, dest: Dest, key: Option<IpKey>) -> DestView {
    let mut v = DestView::default();
    for (s, d) in slots.iter().zip(dests) {
        if s.at_ms == 0 || now_ms.saturating_sub(s.at_ms) > SLOT_FRESH_MS {
            continue;
        }
        let mut seen = false;
        for e in d.iter().filter(|e| e.n > 0 && e.dest == dest) {
            seen = true;
            v.total += e.n as u64;
            // (an entry without a largest holder has top_n 0: a client without a key holds nothing here)
            if e.top == key {
                v.mine += e.top_n as u64;
                v.others |= e.n > e.top_n;
            } else {
                v.others = true;
            }
        }
        if !seen {
            // (a list with a free entry holds every destination of its worker)
            v.hidden += d.iter().map(|e| e.n as u64).min().unwrap_or(0);
        }
    }
    v
}

/// E2 the share rule for one destination: true = refuse the new stream of the address that holds `v.mine`. The
/// destination is at 3/4 of the `usable` ports, the address holds more than half of its sockets, and another client
/// holds a socket to it (ports are a pool per destination: a client that does not ask for it loses nothing). "More
/// than half" is proven: sockets that a worker may hold without publishing them count against the address.
pub fn pt_share(v: DestView, usable: u32) -> bool {
    v.total >= pt_part(usable, PT_SHORT_IN_16) && v.others && v.mine * PT_KEY_DIV > v.total + v.hidden
}

/// E2 the reserve for one destination: true = the address that asks is alone on it (every socket to it is its own)
/// and holds 15/16 of the `usable` ports. The caller refuses its new stream while another client is connected to the
/// server: the last 1/16 stays for an address that comes later, and from that address's first socket pt_share holds
/// the large one. (Without it the address took every port, and refusing it afterwards frees none: nothing is closed.)
pub fn pt_last(v: DestView, usable: u32) -> bool {
    v.total >= pt_part(usable, PT_LAST_IN_16) && !v.others
}

/// E2 `p`/16 of the usable ports, rounded up, at least 1
pub fn pt_part(usable: u32, p: u64) -> u64 {
    (usable as u64 * p).div_ceil(16).max(1)
}

/// E2 the state bits for the largest destination count `max` when they were `cur`
pub fn pt_marks(cur: u8, max: u64, usable: u32) -> u8 {
    let step = |m: u8, bit: u8, i: u64, o: u64| {
        if max >= pt_part(usable, i) {
            m | bit
        } else if max < pt_part(usable, o) {
            m & !bit
        } else {
            m
        }
    };
    step(step(cur, ST_PT_BUSY, PT_BUSY_IN_16, PT_BUSY_OUT_16), ST_PT_SHORT, PT_SHORT_IN_16, PT_SHORT_OUT_16)
}

/// E2 the host's local port range and how many of its ports are usable: `range` is the text of
/// net.ipv4.ip_local_port_range (`32768\t60999`), `reserved` of net.ipv4.ip_local_reserved_ports (`8080,9148-9150`,
/// or empty). None: not a range.
pub fn port_range(range: &str, reserved: &str) -> Option<(u16, u16, u32)> {
    let mut w = range.split_whitespace();
    let (lo, hi) = (w.next()?.parse::<u16>().ok()?, w.next()?.parse::<u16>().ok()?);
    if lo == 0 || hi < lo {
        return None;
    }
    let mut out = 0u32;
    for part in reserved.trim().split(',').filter(|p| !p.is_empty()) {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) else { continue };
        let (a, b) = (a.max(lo), b.min(hi));
        if a <= b {
            out += (b - a) as u32 + 1;
        }
    }
    Some((lo, hi, ((hi - lo) as u32 + 1).saturating_sub(out).max(1)))
}

/// E2 set the socket's own local port range (`range`: low | high << 16); false = the kernel does not have the option
pub fn set_port_range(fd: RawFd, range: u32) -> bool {
    // SAFETY: the option value is a live local of the size passed
    unsafe { libc::setsockopt(fd, libc::IPPROTO_IP, IP_LOCAL_PORT_RANGE, &range as *const _ as *const _, 4) == 0 }
}

/// E2 does this kernel take the option on a TCP socket of the family (`v6`)? (Linux 6.3 and later; one socket, closed)
pub fn port_range_probe(v6: bool, range: u32) -> bool {
    // SAFETY: plain libc calls on an fd that is closed here
    unsafe {
        let fd = libc::socket(if v6 { libc::AF_INET6 } else { libc::AF_INET }, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return false;
        }
        let ok = set_port_range(fd, range);
        libc::close(fd);
        ok
    }
}

/// E1 what one worker counted at its last sweep. `single`: the key of every connection of the worker, when they all
/// have the same one (None: no connection, more than one key, or a connection without a key). `top`: the key with the
/// most unread target sockets on this worker and its count.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Unread {
    pub at_ms: u64,
    pub conns: u32,
    pub single: Option<IpKey>,
    pub unread: u32,
    pub top: Option<IpKey>,
    pub top_unread: u32,
    /// E4 streams with a connect in flight
    pub connecting: u32,
}

/// E1 `p`/16 of `max` pages, rounded up, at least 1 (any u64: an administrator can set tcp_mem to the largest number)
pub fn tm_part(max: u64, p: u64) -> u64 {
    (max as u128 * p as u128).div_ceil(16).max(1) as u64
}

/// E1 the share mark for `pages` of host TCP memory when the state was `cur`: in at the entry part of `max`, out
/// below the exit part (parts rounded up, at least 1 page)
pub fn tm_marks(cur: u8, pages: u64, max: u64) -> u8 {
    if pages >= tm_part(max, TM_SHARE_IN_16) {
        cur | ST_TM_SHARE
    } else if pages < tm_part(max, TM_SHARE_OUT_16) {
        cur & !ST_TM_SHARE
    } else {
        cur
    }
}

/// E1 the floor in sockets: the fewest unread target sockets of one address that can matter against `limit_pages` of
/// host TCP memory: limit / TM_FLOOR_DIV in bytes over the default receive buffer `rmem`, rounded up, at least 1
pub fn tm_floor(limit_pages: u64, page: u64, rmem: u64) -> u32 {
    let bytes = limit_pages as u128 * page as u128 / TM_FLOOR_DIV as u128;
    bytes.div_ceil(rmem.max(1) as u128).clamp(1, u32::MAX as u128) as u32
}

/// E1 the share rule for the client address `key`, from what the workers published (`slots`, those fresh at `now_ms`):
/// true = refuse its new stream. It holds at least `floor` unread target sockets, more than half of all, and another
/// client is connected. What `key` holds is a lower bound (only the workers where it is the largest holder count), so
/// the rule can act late and never early.
pub fn tm_share(slots: &[Unread], now_ms: u64, key: IpKey, floor: u32) -> bool {
    let (mut mine, mut total) = (0u64, 0u64);
    for s in slots.iter().filter(|s| s.at_ms != 0 && now_ms.saturating_sub(s.at_ms) <= SLOT_FRESH_MS) {
        total += s.unread as u64;
        if s.top == Some(key) {
            mine += s.top_unread as u64;
        }
    }
    others(slots, now_ms, key) && mine >= floor as u64 && mine * TM_KEY_DIV > total
}

/// Another client than the address `key` is connected to the server (some worker has a connection that is not
/// `key`'s: another address, or a client without a key), by the workers' fresh counts
pub fn others(slots: &[Unread], now_ms: u64, key: IpKey) -> bool {
    slots.iter().any(|s| s.at_ms != 0 && now_ms.saturating_sub(s.at_ms) <= SLOT_FRESH_MS && s.conns > 0 && s.single != Some(key))
}

/// E4 the host's packet counters (since boot, this network namespace): SYN retransmits (TcpExt TCPSynRetrans),
/// connect attempts (Tcp ActiveOpens), UDP datagrams sent and IP packets sent (IPv4 + IPv6)
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Net {
    pub syn_retrans: u64,
    pub opens: u64,
    pub udp_out: u64,
    pub ip_out: u64,
}

/// A value of /proc/net/snmp or /proc/net/netstat: the line `proto: name name ...` and the line `proto: 1 2 ...`
pub fn mib_field(text: &str, proto: &str, name: &str) -> Option<u64> {
    let mut l = text.lines().filter(|l| l.strip_prefix(proto).is_some_and(|r| r.starts_with(':')));
    let (k, v) = (l.next()?, l.next()?);
    k.split_whitespace().zip(v.split_whitespace()).find(|f| f.0 == name)?.1.parse().ok()
}

/// A value of /proc/net/snmp6 (`name value` per line)
pub fn mib6_field(text: &str, name: &str) -> Option<u64> {
    let mut w = text.lines().find(|l| l.split_whitespace().next() == Some(name))?.split_whitespace();
    w.nth(1)?.parse().ok()
}

/// The counters from the three files' text (snmp6 is empty on a host without IPv6: its two values count as 0)
pub fn net_parse(netstat: &str, snmp: &str, snmp6: &str) -> Option<Net> {
    Some(Net {
        syn_retrans: mib_field(netstat, "TcpExt", "TCPSynRetrans")?,
        opens: mib_field(snmp, "Tcp", "ActiveOpens")?,
        udp_out: mib_field(snmp, "Udp", "OutDatagrams")? + mib6_field(snmp6, "Udp6OutDatagrams").unwrap_or(0),
        ip_out: mib_field(snmp, "Ip", "OutRequests")? + mib6_field(snmp6, "Ip6OutRequests").unwrap_or(0),
    })
}

/// The host's counters now (None: not readable here)
pub fn net_read() -> Option<Net> {
    let f = |p: &str| std::fs::read_to_string(p).ok();
    net_parse(&f("/proc/net/netstat")?, &f("/proc/net/snmp")?, &f("/proc/net/snmp6").unwrap_or_default())
}

/// E4 the lines for one window: `d` = what the counters moved in it, `connecting` = the server's streams with a
/// connect in flight, `last` = the value of the last line of each shape (SYN, UDP). A shape gets a line when it is
/// over its floor and its ratio (NW_*) and more than twice its last line: at most a few lines per shape, each a fact.
pub fn nw_lines(d: Net, connecting: u64, last: &mut (u64, u64)) -> Vec<String> {
    let mut out = Vec::new();
    if d.syn_retrans >= NW_SYN_FLOOR && d.syn_retrans >= NW_SYN_PER_OPEN.saturating_mul(d.opens) && d.syn_retrans / 2 > last.0 {
        last.0 = d.syn_retrans;
        out.push(format!(
            "finalwisp: --net-watch: SYN retransmits on this host: {} in 10 s, {} per connect attempt ({} attempts); {connecting} \
             streams of this server are connecting. Connects that get no answer do this, and the host's packet rate out is \
             the limit for every client. --dest-failfast bounds this per client address, not for many. Counters \
             host_syn_retrans, connecting, connect_timeout; the next such line at twice this value",
            d.syn_retrans,
            d.syn_retrans / d.opens.max(1),
            d.opens
        ));
    }
    if d.udp_out >= NW_UDP_FLOOR && d.udp_out.saturating_mul(NW_UDP_DIV) >= d.ip_out && d.udp_out / 2 > last.1 {
        last.1 = d.udp_out;
        out.push(format!(
            "finalwisp: --net-watch: UDP datagrams sent by this host: {} in 10 s, {} of every 100 packets it sent. The host's \
             packet rate out is the limit for every client, and finalwisp has no limit on UDP datagrams per second. \
             --no-udp turns UDP streams off. Counter host_udp_out; the next such line at twice this value",
            d.udp_out,
            (d.udp_out as u128 * 100 / d.ip_out.max(1) as u128).min(100)
        ));
    }
    out
}

/// E4 the host's connection-tracking table: (entries, size) from /proc/sys/net/netfilter (None: no conntrack module
/// in this network namespace, or not readable here, as in many containers)
pub fn conntrack() -> Option<(u64, u64)> {
    let f = |p: &str| std::fs::read_to_string(p).ok()?.trim().parse::<u64>().ok();
    let max = f("/proc/sys/net/netfilter/nf_conntrack_max").filter(|m| *m > 0)?;
    Some((f("/proc/sys/net/netfilter/nf_conntrack_count")?, max))
}

/// E4 the table counts as near full from 3/4 of its size; the line comes again only after it was below 1/2
pub const CT_FULL_IN_4: u64 = 3;
pub const CT_FULL_OUT_2: u64 = 1;

/// E4 the guard thread's line for the table (`said`: the last line was "near full", until below the exit mark)
pub fn ct_line(count: u64, max: u64, said: &mut bool) -> Option<String> {
    if !*said && count.saturating_mul(4) >= max.saturating_mul(CT_FULL_IN_4) {
        *said = true;
        return Some(format!(
            "finalwisp: --net-watch: the host's connection-tracking table holds {count} of {max} entries (nf_conntrack_count, \
             nf_conntrack_max). When it is full, the kernel drops the packets of new connections, of clients and of targets \
             alike. Fix: a larger net.netfilter.nf_conntrack_max on the host, or no connection tracking for this server's \
             traffic. Gauge host_conntrack; the next such line after the table was below half"
        ));
    }
    if *said && count.saturating_mul(2) < max.saturating_mul(CT_FULL_OUT_2) {
        *said = false;
    }
    None
}

/// E4 the start's warning for the table (`watch`: --net-watch is in effect): only its state, 3/4 full (as ct_line).
/// It records in CT_START what it printed, for the guard thread's first line (ct_primed).
pub fn ct_warnings(watch: bool) -> Vec<String> {
    if !watch {
        return Vec::new();
    }
    let w = conntrack().and_then(|(count, max)| ct_warn(count, max));
    CT_START.store(ct_start_code(w.is_some()), Relaxed);
    w.into_iter().collect()
}

/// E4 what the start's warnings printed for the table: 0 = they have not looked yet, CT_START_SAID = a warning,
/// CT_START_QUIET = none (table below 3/4, or not readable). (review, v1.3.2: the guard took a sample of its
/// own; a start at 74% and a guard at 80% gave no line until the table had been below half.)
static CT_START: AtomicU8 = AtomicU8::new(0);
const CT_START_SAID: u8 = 1;
const CT_START_QUIET: u8 = 2;

fn ct_start_code(warned: bool) -> u8 {
    if warned {
        CT_START_SAID
    } else {
        CT_START_QUIET
    }
}

/// E4 the guard's `said` before its first line, from CT_START: None while the start has not looked (the guard skips
/// the table in that window), Some(true) when the start warned (no 2nd line for the same state), else Some(false)
fn ct_primed(start: u8) -> Option<bool> {
    match start {
        0 => None,
        CT_START_SAID => Some(true),
        _ => Some(false),
    }
}

/// E4 ct_warnings for a table of `max` entries with `count` in use
pub fn ct_warn(count: u64, max: u64) -> Option<String> {
    (count.saturating_mul(4) >= max.saturating_mul(CT_FULL_IN_4)).then(|| {
        format!(
            "the host's connection-tracking table holds {count} of {max} entries (nf_conntrack_count, nf_conntrack_max): \
             when it is full, the kernel drops the packets of new connections. Fix: a larger net.netfilter.nf_conntrack_max \
             on the host."
        )
    })
}

/// E4 the --show-config row of the table against `fds` (the file descriptors the server may use for connections and
/// streams): a plain row, not a warning (60.73: with nofile raised most hosts have the smaller table).
/// Each connection and stream takes an entry (on loopback both sides of a stream), and a closed one keeps it for up to
/// 2 minutes: a table smaller than the descriptors can fill first. None: --net-watch off or no readable table.
pub fn ct_row(watch: bool, fds: Option<u64>) -> Option<(&'static str, String)> {
    let (count, max) = conntrack().filter(|_| watch)?;
    Some(("connection tracking", ct_row_text(count, max, fds)))
}

pub fn ct_row_text(count: u64, max: u64, fds: Option<u64>) -> String {
    let vs = match fds {
        Some(f) if f > max => format!(
            "; fewer than the about {f} file descriptors for connections and streams: the table can fill before they do \
             (net.netfilter.nf_conntrack_max)"
        ),
        Some(f) => format!("; not fewer than the about {f} file descriptors for connections and streams"),
        None => String::new(),
    };
    format!("{count} of {max} entries in use{vs}")
}

/// E3 the SYNs the kernel has sent on a connecting TCP socket (1 + the retransmits of TCP_INFO); None: not readable
pub fn syns_sent(fd: RawFd) -> Option<u8> {
    // SAFETY: getsockopt writes at most `len` bytes into the zeroed struct
    unsafe {
        let mut i: libc::tcp_info = std::mem::zeroed();
        let mut len = size_of::<libc::tcp_info>() as libc::socklen_t;
        (libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, &mut i as *mut _ as *mut _, &mut len) == 0)
            .then(|| i.tcpi_retransmits.saturating_add(1))
    }
}

/// E5 one connection's record (Wb::uc, by client slot): its slot generation + 1 (0: never used; a slot's first
/// generation is 0, so a plain generation would take a fresh record for one in use), whether its fill was counted, its client's
/// bytes_acked at the last sweep that read it, the time of the last sweep that saw it in a stall (0: not in one), and
/// its credit in ms of stall
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Stall {
    pub g1: u32,
    pub filled: bool,
    pub acked: u64,
    pub at: u64,
    pub credit: u64,
}

/// E5 the credit's constants (UC_STALL_MS, UC_CAP_MS, UC_RATE; tests shorten the times) and `m0`: the bytes one full
/// stream holds on this host (tcp_rmem's maximum + --notsent-lowat; 0 until a worker reads it). A connection that holds
/// more of the host's TCP memory than m0 uses its credit up faster, by held / m0: its streams, not its client's buffer,
/// decide what it costs.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct UcLim {
    pub start_ms: u64,
    pub cap_ms: u64,
    pub rate: u64,
    pub m0: u64,
}

impl UcLim {
    pub const REAL: UcLim = UcLim { start_ms: UC_STALL_MS, cap_ms: UC_CAP_MS, rate: UC_RATE, m0: 0 };
}

/// E5 a sweep's step for one connection: `info` = (the client's receive window, bytes it took) when the connection holds
/// a parked download (None: it holds none, or TCP_INFO is not readable), `held` = the bytes of host TCP memory it holds
/// (its send queue and its parked targets' receive queues), `pressed` = ST_UNREAD. true = reset it: its credit is used
/// up, it is in a stall, and the host is short.
pub fn uc_step(e: &mut Stall, gen: u32, info: Option<(u32, u64)>, held: u64, now_ms: u64, lim: &UcLim, pressed: bool) -> bool {
    if e.g1 != gen.wrapping_add(1) {
        *e = Stall { g1: gen.wrapping_add(1), credit: lim.start_ms, ..Stall::default() };
    }
    let Some((wnd, acked)) = info else {
        e.at = 0;
        return false;
    };
    // the time since a sweep that saw a stall is used up first, whatever this sweep sees: a client that takes a byte
    // at every sweep pays for its stalls too (review)
    let mut used = 0;
    if e.at != 0 {
        let m0 = lim.m0.max(1) as u128;
        used = (now_ms.saturating_sub(e.at) as u128 * (held as u128).max(m0) / m0).min(u64::MAX as u128) as u64;
        e.credit = e.credit.saturating_sub(used);
    }
    e.at = if wnd == 0 { now_ms.max(1) } else { 0 };
    if acked > e.acked {
        // bytes taken since the last reading buy credit (the first reading: the fill, at UC_FILL_DIV x the price)
        let div = if e.filled { lim.rate } else { lim.rate * UC_FILL_DIV };
        let gain = ((acked - e.acked) as u128 * 1000 / div.max(1) as u128).min(lim.cap_ms as u128) as u64;
        (e.credit, e.acked) = (e.credit.saturating_add(gain).min(lim.cap_ms), acked);
    }
    e.filled = true;
    // used up: in a stall, and what is left does not pay for another interval like the one just spent (a few bytes at
    // every sweep do not keep a connection)
    wnd == 0 && pressed && (e.credit == 0 || e.credit < used)
}

/// E5 the bytes one full stream can hold on this host: tcp_rmem's maximum (6 MiB, the Linux default, if unreadable)
pub fn rmem_max() -> u64 {
    let v = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_rmem").ok().and_then(|s| s.split_whitespace().nth(2)?.parse().ok());
    v.filter(|v| *v > 0).unwrap_or(6 << 20)
}

/// E5 a TCP socket's peer receive window and the bytes the peer took (tcpi_snd_wnd, tcpi_bytes_acked); None: not a
/// TCP socket, or a kernel without tcpi_snd_wnd
pub fn wnd_acked(fd: RawFd) -> Option<(u32, u64)> {
    let mut b = [0u8; UC_INFO_LEN];
    let mut len = b.len() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into the buffer
    let r = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, b.as_mut_ptr() as *mut _, &mut len) };
    (r == 0 && len as usize >= UC_INFO_LEN)
        .then(|| (u32::from_ne_bytes(b[228..232].try_into().unwrap()), u64::from_ne_bytes(b[120..128].try_into().unwrap())))
}

/// E5 the bytes in a socket's receive queue (`req` = FIONREAD) or send queue (TIOCOUTQ); 0 on an error
pub fn queued(fd: RawFd, req: libc::c_ulong) -> u64 {
    let mut n: libc::c_int = 0;
    // SAFETY: both requests write one c_int
    let r = unsafe { libc::ioctl(fd, req as _, &mut n) };
    if r != 0 {
        return 0;
    }
    n.max(0) as u64
}

/// E5 does this kernel's TCP_INFO have tcpi_snd_wnd? (one socket, closed)
pub fn wnd_probe() -> bool {
    // SAFETY: plain libc calls on an fd that is closed here
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return false;
        }
        let ok = wnd_acked(fd).is_some();
        libc::close(fd);
        ok
    }
}

/// The process-wide state of section E
pub struct Bounds {
    /// OPT_* bits
    pub opts: u8,
    /// ST_* bits; written by the guard thread at a crossing, read by a worker on the out-of-line side of its fd count
    state: Line<AtomicU8>,
    /// E1 one per worker, written by its owner at its sweep
    slots: Box<[Line<Mutex<Unread>>]>,
    pub tcp: TcpForm,
    page: u64,
    rmem: u64,
    /// E1 the floor in sockets (Mem form: fixed; Flag form: from the host's TCP memory while the flag is set)
    floor: AtomicU32,
    /// E1 host TCP pages at the guard thread's last read
    pages: AtomicU64,
    /// E2 one per worker (beside `slots`, which says how fresh it is)
    dests: Box<[Line<Mutex<Dests>>]>,
    /// E2 the host's port range as the socket option takes it (low | high << 16) and its usable ports
    pt_range: AtomicU32,
    pt_usable: AtomicU32,
    /// E2 the kernel takes IP_LOCAL_PORT_RANGE on an IPv4 (bit 0) / IPv6 (bit 1) TCP socket
    pt_opt: AtomicU8,
    /// E2 the largest destination and its sockets at the guard thread's last sum (for the log)
    pt_max: Mutex<Option<(Dest, u64)>>,
    log_at: Line<[AtomicU64; LOG_KINDS]>,
    /// the marks whose "armed" line was printed (ST_* bits): mark_line
    said: AtomicU8,
    /// 60.78 G70 TCP sockets allocated on the host (sockstat TCP `alloc`) at the guard thread's last read; 0 = none yet
    socks: AtomicU64,
}

impl Bounds {
    pub fn new(opts: u8, workers: usize, tcp: TcpForm, page: u64, rmem: u64) -> Bounds {
        let floor = match tcp {
            TcpForm::Mem { max_pages } => tm_floor(max_pages, page, rmem),
            TcpForm::Flag => u32::MAX, // (until the flag is seen with a memory reading)
        };
        Bounds {
            opts,
            state: Line(AtomicU8::new(0)),
            slots: (0..workers.max(1)).map(|_| Line(Mutex::new(Unread::default()))).collect(),
            tcp,
            page,
            rmem,
            floor: AtomicU32::new(floor),
            pages: AtomicU64::new(0),
            dests: (0..workers.max(1)).map(|_| Line(Mutex::new([DestTop::EMPTY; PT_TOP]))).collect(),
            pt_range: AtomicU32::new(0),
            pt_usable: AtomicU32::new(u32::MAX),
            pt_opt: AtomicU8::new(0),
            pt_max: Mutex::new(None),
            log_at: Line(Default::default()),
            said: AtomicU8::new(0),
            socks: AtomicU64::new(0),
        }
    }
    /// 60.78 G70 a TCP socket's share of the host's TCP memory under pressure, in bytes: tcp_mem's maximum over the
    /// sockets allocated (the kernel's rule in __sk_mem_raise_allocated: under pressure a socket gets memory only while
    /// it holds less than that). None: the Flag form, or no reading yet
    pub fn share_bytes(&self) -> Option<u64> {
        let n = self.socks.load(Relaxed);
        match self.tcp {
            TcpForm::Mem { max_pages } if n > 0 => Some(max_pages * self.page / n),
            _ => None,
        }
    }
    /// Tests: the sockets allocated as the guard thread would publish them
    #[cfg(test)]
    pub fn set_socks(&self, n: u64) {
        self.socks.store(n, Relaxed);
    }
    /// The guard's reading of /proc/net/sockstat (`t`): TCP memory in pages; with OPT_RELIEF it also publishes the TCP
    /// sockets allocated (none before the first good reading: no share known, no relief)
    fn read_mem(&self, t: &[u8]) -> Option<u64> {
        let pages = sockstat_tcp_pages(t);
        if self.opts & OPT_RELIEF != 0 && pages.is_some() {
            // 60.78 G70 (a failed read keeps the last value, as the pages do)
            if let Some(n) = sockstat_tcp_alloc(t) {
                self.socks.store(n, Relaxed);
            }
        }
        pages
    }
    /// E2 the host's port range (`lo`..=`hi`, `usable` of them) and which socket families take the option
    pub fn set_ports(&self, lo: u16, hi: u16, usable: u32, opt: u8) {
        self.pt_range.store(lo as u32 | (hi as u32) << 16, Relaxed);
        self.pt_usable.store(usable.max(1), Relaxed);
        self.pt_opt.store(opt, Relaxed);
    }
    /// E2 the value of the socket option for a target socket of the family (0: this kernel does not take it there)
    pub fn pt_range(&self, v6: bool) -> u32 {
        if self.pt_opt.load(Relaxed) & (1 << v6 as u8) != 0 {
            self.pt_range.load(Relaxed)
        } else {
            0
        }
    }
    pub fn pt_usable(&self) -> u32 {
        self.pt_usable.load(Relaxed)
    }
    /// E2 worker `idx` publishes its largest destinations (before its counts: `publish` makes them fresh)
    pub fn publish_dests(&self, idx: usize, d: &Dests) {
        if let Some(s) = self.dests.get(idx) {
            *s.0.lock().unwrap_or_else(|e| e.into_inner()) = *d;
        }
    }
    /// E2 every worker's destinations, copied into `out`
    pub fn read_dests(&self, out: &mut Vec<Dests>) {
        out.clear();
        out.extend(self.dests.iter().map(|s| *s.0.lock().unwrap_or_else(|e| e.into_inner())));
    }
    /// E2 the guard thread's step: the largest destination over all workers against the marks. Returns the state.
    pub fn pt_step(&self, now_ms: u64, slots: &mut Vec<Unread>, dests: &mut Vec<Dests>) -> u8 {
        self.read_slots(slots);
        self.read_dests(dests);
        let mut max: Option<(Dest, u64)> = None;
        for (i, d) in dests.iter().enumerate() {
            for e in d.iter().filter(|e| e.n > 0) {
                // (each destination is summed once per worker that has it: at most PT_TOP x workers sums of that many)
                if dests[..i].iter().flatten().any(|x| x.n > 0 && x.dest == e.dest) {
                    continue;
                }
                let t = pt_view(slots, dests, now_ms, e.dest, None).total;
                if max.is_none_or(|m| t > m.1) {
                    max = Some((e.dest, t));
                }
            }
        }
        *self.pt_max.lock().unwrap_or_else(|e| e.into_inner()) = max;
        let cur = self.state();
        let new =
            (cur & !(ST_PT_BUSY | ST_PT_SHORT)) | pt_marks(cur & (ST_PT_BUSY | ST_PT_SHORT), max.map_or(0, |m| m.1), self.pt_usable());
        if new != cur {
            // (only the guard thread writes the state: no other writer can be lost)
            self.state.0.store(new, Relaxed);
            if (cur ^ new) & ST_PT_SHORT != 0 && self.mark_line(Log::PtShortMark, ST_PT_SHORT, new & ST_PT_SHORT != 0) {
                let (d, n) = max.map_or((String::new(), 0), |m| (format!(" to {}", std::net::SocketAddr::new(m.0 .0, m.0 .1)), m.1));
                crate::metrics::log_nowait(if new & ST_PT_SHORT != 0 {
                    format!(
                        "finalwisp: --port-share is armed: {n} target sockets{d}, of {} source ports the host has \
                         toward one destination (net.ipv4.ip_local_port_range). A client address that holds more than \
                         half of the sockets to a destination with 3/4 of the ports in use gets no new streams to it \
                         while another client uses that destination. Fix: a wider net.ipv4.ip_local_port_range, or \
                         more than one address for the destination; or --no-port-share (at most one such line per 10 \
                         s)",
                        self.pt_usable()
                    )
                } else {
                    format!(
                        "finalwisp: --port-share is at rest: at most {n} target sockets to one destination, of {} source ports",
                        self.pt_usable()
                    )
                });
            }
        }
        new
    }
    /// E2 `to 203.0.113.5:443 (21180 target sockets of 28232 source ports)` for the warnings: the largest destination
    pub fn pt_state(&self) -> String {
        match *self.pt_max.lock().unwrap_or_else(|e| e.into_inner()) {
            Some((d, n)) => {
                format!("most sockets: {n} to {}, of {} source ports", std::net::SocketAddr::new(d.0, d.1), self.pt_usable())
            }
            None => format!("{} source ports", self.pt_usable()),
        }
    }
    #[inline]
    pub fn state(&self) -> u8 {
        self.state.0.load(Relaxed)
    }
    pub fn floor(&self) -> u32 {
        self.floor.load(Relaxed)
    }
    pub fn pages(&self) -> u64 {
        self.pages.load(Relaxed)
    }
    /// host TCP memory at the guard thread's last read, MiB (for the warnings)
    pub fn mib(&self) -> u64 {
        self.pages().saturating_mul(self.page) >> 20
    }
    /// E1 worker `idx` publishes its counts
    pub fn publish(&self, idx: usize, u: Unread) {
        if let Some(s) = self.slots.get(idx) {
            *s.0.lock().unwrap_or_else(|e| e.into_inner()) = u;
        }
    }
    /// E1 every worker's counts, copied into `out`
    pub fn read_slots(&self, out: &mut Vec<Unread>) {
        out.clear();
        out.extend(self.slots.iter().map(|s| *s.0.lock().unwrap_or_else(|e| e.into_inner())));
    }
    /// E1 the guard thread's step with a reading of the host: TCP pages, and in the flag form the kernel's flag.
    /// Returns the state (changed or not).
    pub fn tm_step(&self, pages: u64, flag: bool, now_ms: u64, flag_until: &mut u64) -> u8 {
        self.pages.store(pages, Relaxed);
        let cur = self.state();
        // (E1 and E5 share the marks: both bits move together; either one is the mark's state)
        let was = if cur & (ST_TM_SHARE | ST_UNREAD) != 0 { ST_TM_SHARE } else { 0 };
        let tm = match self.tcp {
            TcpForm::Mem { max_pages } => tm_marks(was, pages, max_pages),
            TcpForm::Flag => {
                if flag {
                    *flag_until = now_ms + FLAG_HOLD_MS;
                    // (the memory at which this host is in pressure is the only size the container can read)
                    self.floor.store(tm_floor(pages, self.page, self.rmem), Relaxed);
                }
                if now_ms < *flag_until {
                    ST_TM_SHARE
                } else {
                    0
                }
            }
        };
        let on = ((self.opts & OPT_TCPMEM != 0) as u8 * ST_TM_SHARE) | ((self.opts & OPT_UNREAD != 0) as u8 * ST_UNREAD);
        let new = (cur & !(ST_TM_SHARE | ST_UNREAD)) | if tm & ST_TM_SHARE != 0 { on } else { 0 };
        if new != cur {
            self.state.0.store(new, Relaxed);
            self.tm_crossed(cur, new, pages);
        }
        new
    }
    #[cold]
    fn tm_crossed(&self, was: u8, now: u8, pages: u64) {
        let mib = |p: u64| p.saturating_mul(self.page) >> 20;
        let of = match self.tcp {
            TcpForm::Mem { max_pages } => {
                format!("host TCP memory {} MiB of {} MiB (net.ipv4.tcp_mem maximum)", mib(pages), mib(max_pages))
            }
            TcpForm::Flag => format!("host TCP memory {} MiB, kernel pressure flag (net.ipv4.tcp_mem is not readable here)", mib(pages)),
        };
        const FIX: &str =
            "more memory or a larger net.ipv4.tcp_mem on the host, or fewer parallel downloads per client (--max-streams-per-conn)";
        if (was ^ now) & ST_TM_SHARE != 0 && self.mark_line(Log::TmShareMark, ST_TM_SHARE, now & ST_TM_SHARE != 0) {
            crate::metrics::log_nowait(if now & ST_TM_SHARE != 0 {
                format!(
                    "finalwisp: --tcpmem-share is armed: {of}. A client address that holds more than half of all unread \
                     downloads ({} or more target sockets) gets no new streams while another client is connected. Fix: {FIX}; \
                     or --no-tcpmem-share (at most one such line per 10 s)",
                    self.floor()
                )
            } else {
                format!("finalwisp: --tcpmem-share is at rest: {of}")
            });
        }
        // E5 alone (with E1 the line above names the same mark): its own pair, limited as E1's
        if self.opts & OPT_TCPMEM == 0 && (was ^ now) & ST_UNREAD != 0 && self.mark_line(Log::UcMark, ST_UNREAD, now & ST_UNREAD != 0) {
            crate::metrics::log_nowait(if now & ST_UNREAD != 0 {
                format!(
                    "finalwisp: --unread-close is armed: {of}. A connection whose client took no data with its receive \
                     window at 0 until its stall time was used up ({} s to start, more for data it took) is reset. Fix: {FIX}; \
                     or --no-unread-close (at most one such line per 10 s)",
                    UC_STALL_MS / 1000
                )
            } else {
                format!("finalwisp: --unread-close is at rest: {of}")
            });
        }
    }
    /// The two log lines of a mark (`bit`) come as a pair: the line for its end is printed exactly when the line for
    /// its start was (at most one pair per LOG_EVERY_MS). So a mark that is off never has "armed" as its last line.
    pub fn mark_line(&self, kind: Log, bit: u8, armed: bool) -> bool {
        if armed {
            let due = self.log_due(kind);
            if due {
                self.said.fetch_or(bit, Relaxed);
            }
            due
        } else {
            self.said.fetch_and(!bit, Relaxed) & bit != 0
        }
    }
    /// true at most once per LOG_EVERY_MS per kind (the first call at once)
    pub fn log_due(&self, kind: Log) -> bool {
        let now = crate::metrics::now_ms().max(1);
        let at = &self.log_at.0[kind as usize];
        let next = at.load(Relaxed);
        now >= next && at.compare_exchange(next, now + LOG_EVERY_MS, Relaxed, Relaxed).is_ok()
    }
    #[cfg(any(test, fuzzing))]
    pub fn set_state(&self, s: u8) {
        self.state.0.store(s, Relaxed);
    }
    /// One line per option that is on, for --show-config (label, text) and the start's detail lines
    pub fn describe(&self) -> Vec<(&'static str, String)> {
        let mut rows = Vec::new();
        let mib = |p: u64| p.saturating_mul(self.page) >> 20;
        if self.opts & OPT_TCPMEM != 0 {
            rows.push((
                "TCP memory guard",
                match self.tcp {
                    TcpForm::Mem { max_pages } => format!(
                        "host TCP memory against net.ipv4.tcp_mem's maximum ({} MiB): from {} MiB (3/4; until below \
                         {} MiB) no new streams for a client address that holds more than half of all unread \
                         downloads ({} or more target sockets) while another client is connected",
                        mib(max_pages),
                        mib(tm_part(max_pages, TM_SHARE_IN_16)),
                        mib(tm_part(max_pages, TM_SHARE_OUT_16)),
                        self.floor()
                    ),
                    TcpForm::Flag => "net.ipv4.tcp_mem is not readable here (a container with its own network namespace): the share \
                     rule runs while the kernel's TCP memory pressure flag is set"
                        .to_string(),
                },
            ));
        }
        if self.opts & OPT_PORT != 0 {
            let (r, u) = (self.pt_range.load(Relaxed), self.pt_usable());
            let opt = match self.pt_opt.load(Relaxed) {
                3 => format!("from {} the socket option IP_LOCAL_PORT_RANGE on new target sockets to it", pt_part(u, PT_BUSY_IN_16)),
                1 => format!(
                    "from {} the socket option IP_LOCAL_PORT_RANGE on new IPv4 target sockets to it (this kernel does \
                     not take it on IPv6 sockets)",
                    pt_part(u, PT_BUSY_IN_16)
                ),
                _ => "this kernel has no socket option IP_LOCAL_PORT_RANGE (Linux 6.3): connects slow down past half of the ports"
                    .to_string(),
            };
            rows.push((
                "source port guard",
                format!(
                    "{u} source ports toward one destination address and port (net.ipv4.ip_local_port_range {}-{}): \
                     {opt}; from {} sockets to one destination (3/4) no new streams to it for a client address that \
                     holds more than half of them while another client uses it; from {} (15/16) none for an address \
                     that is alone on it while another client is connected; no port left: the stream is refused",
                    r & 0xffff,
                    r >> 16,
                    pt_part(u, PT_SHORT_IN_16),
                    pt_part(u, PT_LAST_IN_16)
                ),
            ));
        }
        if self.opts & OPT_DEAD != 0 {
            rows.push((
                "dead destination guard",
                format!(
                    "a destination with {DF_K} or more connects of one worker thread in the last {} s of the connect timeout \
                     that got no answer to {DF_SYNS} SYNs each, and none that opened, gets no new connect (CLOSE 0x43 at once) \
                     except one probe per second per worker thread, until it answers; one client address with \
                     {DF_FAIL_FLY} connects per worker thread in flight that got no answer for {} s or go to such a \
                     destination gets no new connect to such a destination or to one without an open stream (CLOSE 0x43 \
                     at once); only while another client is connected",
                    DF_RIPE_MS as f64 / 1000.0,
                    DF_AGE_MS / 1000
                ),
            ));
        }
        if self.opts & OPT_UNREAD != 0 {
            let at = match self.tcp {
                TcpForm::Mem { max_pages } => format!(
                    "while host TCP memory is at {} MiB or more (3/4 of net.ipv4.tcp_mem's maximum; until below {} MiB)",
                    mib(tm_part(max_pages, TM_SHARE_IN_16)),
                    mib(tm_part(max_pages, TM_SHARE_OUT_16))
                ),
                TcpForm::Flag => "while the kernel's TCP memory pressure flag is set (net.ipv4.tcp_mem is not readable here)".to_string(),
            };
            rows.push((
                "unread download guard",
                format!(
                    "{at}, a connection with a download waiting for its client is reset when its stall time is used up: \
                     {} s to start (the client's receive window 0 and no data taken), 1 s more per {UC_RATE} bytes it takes \
                     (at most {} s), used up faster by a connection that holds more than tcp_rmem's maximum",
                    UC_STALL_MS / 1000,
                    UC_CAP_MS / 1000
                ),
            ));
        }
        if self.opts & OPT_RELIEF != 0 {
            rows.push((
                "unread download relief",
                "at the same marks, a download waiting for its client whose target socket holds more than half of a socket's \
                 share of host TCP memory (tcp_mem's maximum over the TCP sockets) is read out into the client's queue, \
                 and its receive buffer is kept at half the share until the pressure ends (then its old size \
                 comes back); at most a quarter of the memory budget in such queues"
                    .to_string(),
            ));
        }
        if self.opts & OPT_WATCH != 0 {
            rows.push((
                "network watch",
                format!(
                    "counters host_syn_retrans, host_udp_out and connecting; a log line when the host sends {NW_SYN_FLOOR} or \
                     more SYN retransmits in 10 s and {NW_SYN_PER_OPEN} or more per connect attempt, or {NW_UDP_FLOOR} or more \
                     UDP datagrams in 10 s and they are half of its packets; {}; nothing is refused",
                    match conntrack() {
                        Some((_, max)) =>
                            format!("the connection-tracking table ({max} entries): gauge host_conntrack, a log line from 3/4 full"),
                        None => "no connection-tracking table is readable here".to_string(),
                    }
                ),
            ));
        }
        rows
    }
}

// ---- the host files

/// A small /proc file through a kept-open fd (one pread per read)
pub struct ProcFile(std::fs::File, Vec<u8>);
impl ProcFile {
    pub fn open(p: &str, cap: usize) -> Option<ProcFile> {
        std::fs::File::open(p).ok().map(|f| ProcFile(f, vec![0; cap]))
    }
    pub fn read(&mut self) -> &[u8] {
        let n = self.0.read_at(&mut self.1, 0).unwrap_or(0);
        &self.1[..n]
    }
}

/// Host TCP memory in pages from the text of /proc/net/sockstat (`TCP: inuse 5 orphan 0 tw 0 alloc 7 mem 1`)
pub fn sockstat_tcp_pages(text: &[u8]) -> Option<u64> {
    sockstat_tcp(text, "mem")
}

/// 60.78 G70 the TCP sockets allocated (`alloc`) of /proc/net/sockstat
pub fn sockstat_tcp_alloc(text: &[u8]) -> Option<u64> {
    sockstat_tcp(text, "alloc")
}

fn sockstat_tcp(text: &[u8], key: &str) -> Option<u64> {
    let l = text.split(|&b| b == b'\n').find(|l| l.starts_with(b"TCP:"))?;
    std::str::from_utf8(l).ok()?.split_whitespace().skip_while(|w| *w != key).nth(1)?.parse().ok()
}

/// (pages, pressure flag) of the TCP row of /proc/net/protocols (`TCP 2368 7 1 no 320 yes kernel ...`: protocol,
/// size, sockets, memory, press); `NI` or a missing row: None
pub fn protocols_tcp(text: &[u8]) -> Option<(u64, bool)> {
    let l = text.split(|&b| b == b'\n').find(|l| l.starts_with(b"TCP ") || l.starts_with(b"TCP\t"))?;
    let mut w = std::str::from_utf8(l).ok()?.split_whitespace().skip(3);
    let pages = w.next()?.parse::<i64>().ok()?.max(0) as u64;
    match w.next()? {
        "yes" => Some((pages, true)),
        "no" => Some((pages, false)),
        _ => None,
    }
}

/// What E1 can read on this host: Ok(form), or why the option cannot work at all
pub fn tcp_form() -> Result<TcpForm, String> {
    let mem = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_mem").ok().and_then(|s| crate::mem::parse_tcp_mem(&s));
    let stat = std::fs::read("/proc/net/sockstat").ok().and_then(|t| sockstat_tcp_pages(&t));
    match (mem, stat) {
        (Some(m), Some(_)) => Ok(TcpForm::Mem { max_pages: m[2] }),
        _ => match std::fs::read("/proc/net/protocols").ok().and_then(|t| protocols_tcp(&t)) {
            Some(_) => Ok(TcpForm::Flag),
            None => Err("neither net.ipv4.tcp_mem with /proc/net/sockstat nor the TCP row of /proc/net/protocols is readable".to_string()),
        },
    }
}

/// The kernel's default receive buffer of a TCP socket (tcp_rmem's second value; 131072 if unreadable)
pub fn rmem_default() -> u64 {
    let v = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_rmem").ok().and_then(|s| s.split_whitespace().nth(1)?.parse().ok());
    v.filter(|v| *v > 0).unwrap_or(131_072)
}

/// E2 read the host's port range (None: unreadable)
pub fn host_ports() -> Option<(u16, u16, u32)> {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
    let reserved = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_reserved_ports").unwrap_or_default();
    port_range(&range, &reserved)
}

/// main: the state for the options that are on (`tcpmem`: --tcpmem-share, `port`: --port-share, `dead`:
/// --dest-failfast, `watch`: --net-watch, `unread`: --unread-close (with its relief part where
/// the host allows it: OPT_RELIEF); `upstream`: an --upstream proxy is set), or None
/// when none can work here, and the warnings of a start (an option that is on and not in effect)
pub fn build(
    tcpmem: bool,
    port: bool,
    dead: bool,
    watch: bool,
    unread: bool,
    upstream: bool,
    workers: usize,
) -> (Option<Bounds>, Vec<String>) {
    let (mut opts, mut tcp, mut warn) = (0, TcpForm::Flag, Vec::new());
    let form = if tcpmem || unread { Some(tcp_form()) } else { None };
    if tcpmem {
        match form.clone().unwrap() {
            Ok(f) => (opts, tcp) = (opts | OPT_TCPMEM, f),
            Err(e) => warn.push(format!("--tcpmem-share is not in effect: {e}.")),
        }
    }
    if unread {
        match form.unwrap() {
            Ok(_) if !wnd_probe() => warn.push(
                "--unread-close is not in effect: this kernel does not report a peer's receive window (TCP_INFO, Linux 5.4).".to_string(),
            ),
            Ok(f) => (opts, tcp) = (opts | OPT_UNREAD, f),
            Err(e) => warn.push(format!("--unread-close is not in effect: {e}.")),
        }
    }
    // 60.78 G70: the share needs tcp_mem's maximum (the Mem form), and the buffer it shrinks must grow again after the
    // pressure (SO_BUF_LOCK lifts the lock that SO_RCVBUF sets; without it a stream would keep the small buffer for life)
    if opts & OPT_UNREAD != 0 {
        opts |= relief_bit(matches!(tcp, TcpForm::Mem { .. }), crate::net::buf_lock_supported(), &mut warn);
    }
    if dead && upstream {
        // (every target socket goes to the proxy: a destination that does not answer is the proxy's to see)
        warn.push("--dest-failfast is not in effect with --upstream: every connect goes to the proxy.".to_string());
    } else if dead {
        opts |= OPT_DEAD;
    }
    if watch && net_read().is_some() {
        opts |= OPT_WATCH;
    } else if watch {
        warn.push("--net-watch is not in effect: /proc/net/netstat or /proc/net/snmp is not readable.".to_string());
    }
    let ports = if port { host_ports() } else { None };
    match ports {
        Some(_) => opts |= OPT_PORT,
        None if port => warn.push("--port-share is not in effect: net.ipv4.ip_local_port_range is not readable.".to_string()),
        None => {}
    }
    if opts == 0 {
        return (None, warn);
    }
    // SAFETY: sysconf has no memory arguments
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let b = Bounds::new(opts, workers, tcp, page, rmem_default());
    if let Some((lo, hi, usable)) = ports {
        let r = lo as u32 | (hi as u32) << 16;
        b.set_ports(lo, hi, usable, port_range_probe(false, r) as u8 | (port_range_probe(true, r) as u8) << 1);
    }
    (Some(b), warn)
}

/// 60.78 bundle B2: the relief part of --unread-close (OPT_RELIEF) where the host allows it (`mem`: the Mem form of the
/// TCP memory reading; `buf_lock`: net::buf_lock_supported), else a start warning; the reset part works either way
fn relief_bit(mem: bool, buf_lock: Option<bool>, warn: &mut Vec<String>) -> u8 {
    let why = if !mem {
        "net.ipv4.tcp_mem is not readable here"
    } else if buf_lock != Some(true) {
        "this kernel cannot unlock a receive buffer (SO_BUF_LOCK, Linux 5.15)"
    } else {
        return OPT_RELIEF;
    };
    warn.push(format!("--unread-close: its relief of waiting downloads is not in effect: {why}."));
    0
}

/// The guard thread's sleep: the shortest period of the parts that are on. `nw_ms`: the time since E4's last window
/// (E4 alone: one wake per window; with E4 off its window is no deadline).
pub fn guard_sleep_ms(opts: u8, tcp: TcpForm, pages: u64, state: u8, nw_ms: u64) -> u64 {
    let mut ms = u64::MAX;
    if opts & OPT_WATCH != 0 {
        ms = NW_WINDOW_MS.saturating_sub(nw_ms).max(1);
    }
    if opts & (OPT_TCPMEM | OPT_UNREAD) != 0 {
        ms = ms.min(period_ms(tcp, pages, state));
    }
    if opts & OPT_PORT != 0 {
        ms = ms.min(PT_PERIOD_MS);
    }
    ms.min(NW_WINDOW_MS) // (the thread runs with one of the three only; never a sleep without an end)
}

/// E1 the guard thread's period for this reading
pub fn period_ms(tcp: TcpForm, pages: u64, state: u8) -> u64 {
    match tcp {
        _ if state & (ST_TM_SHARE | ST_UNREAD) != 0 => PERIOD_AT_MS,
        TcpForm::Mem { max_pages } => {
            let out = tm_part(max_pages, TM_SHARE_OUT_16);
            if pages >= out {
                PERIOD_AT_MS
            } else if pages >= out / 2 {
                PERIOD_NEAR_MS
            } else {
                PERIOD_FAR_MS
            }
        }
        TcpForm::Flag => PERIOD_NEAR_MS * 2,
    }
}

static GLOBAL: OnceLock<Arc<Bounds>> = OnceLock::new();

/// main, before the workers are built
pub fn install(b: Arc<Bounds>) {
    let _ = GLOBAL.set(b);
}
/// the server's state (None: no option of section E is on; unit tests, the fuzz harness)
pub fn global() -> Option<Arc<Bounds>> {
    GLOBAL.get().cloned()
}

/// Start the guard thread (main; only with an option of section E that reads the host: E3 is the workers' own)
pub fn start(b: Arc<Bounds>) {
    if b.opts & (OPT_TCPMEM | OPT_PORT | OPT_WATCH | OPT_UNREAD) == 0 {
        return;
    }
    std::thread::Builder::new().name("guard".into()).spawn(move || guard(b)).expect("spawn guard");
}

fn guard(b: Arc<Bounds>) -> ! {
    let mut stat = ProcFile::open("/proc/net/sockstat", 4096);
    let mut prot = if b.tcp == TcpForm::Flag { ProcFile::open("/proc/net/protocols", 16 << 10) } else { None };
    let mut flag_until = 0;
    let (mut pages, mut warned) = (0u64, false);
    let (mut pt_at, mut range_at, mut slots, mut dests) = (0u64, crate::metrics::now_ms(), Vec::new(), Vec::new());
    // ct_said: None until main's start warnings have looked at the table (ct_primed; the guard starts before them)
    let (mut nw_at, mut nw_prev, mut nw_last, mut ct_said) = (crate::metrics::now_ms(), net_read(), (0u64, 0u64), None);
    loop {
        let now = crate::metrics::now_ms();
        let mut state = b.state();
        if b.opts & OPT_WATCH != 0 && now.saturating_sub(nw_at) >= NW_WINDOW_MS {
            let cur = net_read();
            if let (Some(p), Some(c), true) = (nw_prev, cur, now - nw_at < 2 * NW_WINDOW_MS) {
                // (a window that is not about 10 s, after a stall of this thread, is skipped: the lines say 10 s)
                let d = Net {
                    syn_retrans: c.syn_retrans.saturating_sub(p.syn_retrans),
                    opens: c.opens.saturating_sub(p.opens),
                    udp_out: c.udp_out.saturating_sub(p.udp_out),
                    ip_out: c.ip_out.saturating_sub(p.ip_out),
                };
                b.read_slots(&mut slots);
                let fresh = slots.iter().filter(|s| s.at_ms != 0 && now.saturating_sub(s.at_ms) <= SLOT_FRESH_MS);
                let connecting = fresh.map(|s| s.connecting as u64).sum();
                nw_lines(d, connecting, &mut nw_last).into_iter().for_each(crate::metrics::log_nowait);
            }
            ct_said = ct_said.or_else(|| ct_primed(CT_START.load(Relaxed)));
            if let Some(l) = ct_said.as_mut().and_then(|said| conntrack().and_then(|(n, m)| ct_line(n, m, said))) {
                crate::metrics::log_nowait(l);
            }
            (nw_at, nw_prev) = (now, cur);
        }
        if b.opts & OPT_PORT != 0 && now.saturating_sub(pt_at) >= PT_PERIOD_MS {
            pt_at = now;
            if now.saturating_sub(range_at) >= PT_RANGE_EVERY_MS {
                range_at = now;
                // (an administrator can change the range while the server runs; an unreadable file keeps the last one)
                if let Some((lo, hi, usable)) = host_ports() {
                    b.set_ports(lo, hi, usable, b.pt_opt.load(Relaxed));
                }
            }
            state = b.pt_step(now, &mut slots, &mut dests);
        }
        if b.opts & (OPT_TCPMEM | OPT_UNREAD) != 0 {
            // a failed read keeps the last value (and says so once): a mark never falls because a file went away
            let read = match b.tcp {
                TcpForm::Mem { .. } => stat.as_mut().and_then(|f| b.read_mem(f.read())).map(|p| (p, false)),
                TcpForm::Flag => prot.as_mut().and_then(|f| protocols_tcp(f.read())),
            };
            match read {
                Some((p, flag)) => {
                    pages = p;
                    state = b.tm_step(p, flag, now, &mut flag_until);
                }
                None if !warned => {
                    warned = true;
                    let opt = if b.opts & OPT_TCPMEM != 0 { "--tcpmem-share" } else { "--unread-close" };
                    crate::metrics::log_nowait(format!(
                        "finalwisp: {opt}: reading the host's TCP memory failed; the last value is kept (logged once)"
                    ));
                }
                None => {}
            }
        }
        std::thread::sleep(Duration::from_millis(guard_sleep_ms(b.opts, b.tcp, pages, state, now.saturating_sub(nw_at))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_have_hysteresis_and_order() {
        // the VPS of 60.63: tcp_mem maximum 89538 pages (349.8 MiB)
        const MAX: u64 = 89_538;
        let (share_in, share_out) = (67_154, 61_558);
        assert_eq!(tm_marks(0, share_in - 1, MAX), 0);
        assert_eq!(tm_marks(0, share_in, MAX), ST_TM_SHARE);
        assert_eq!(tm_marks(ST_TM_SHARE, share_out, MAX), ST_TM_SHARE, "between exit and entry the mark stays");
        assert_eq!(tm_marks(ST_TM_SHARE, share_out - 1, MAX), 0);
        assert_eq!(tm_marks(0, share_out, MAX), 0, "... and is not set from below");
        // the largest number an administrator can write into tcp_mem
        assert_eq!((tm_part(u64::MAX, 12), tm_part(u64::MAX, 11)), (u64::MAX / 4 * 3 + 3, 12_682_136_550_675_316_736));
        assert_eq!(tm_marks(0, u64::MAX / 4 * 3 + 2, u64::MAX), 0);
        assert_eq!(tm_marks(0, u64::MAX / 4 * 3 + 3, u64::MAX), ST_TM_SHARE);
        let huge = TcpForm::Mem { max_pages: u64::MAX };
        assert_eq!(
            (period_ms(huge, 0, 0), period_ms(huge, u64::MAX / 2, 0), period_ms(huge, u64::MAX - 1, 0)),
            (PERIOD_FAR_MS, PERIOD_NEAR_MS, PERIOD_AT_MS)
        );
        assert!(Bounds::new(OPT_TCPMEM, 1, huge, 4096, 131_072).describe()[0].1.contains("3/4"));
        // there is no second mark: at the maximum and above it the state is the share mark alone
        assert_eq!(tm_marks(ST_TM_SHARE, MAX, MAX), ST_TM_SHARE);
        assert_eq!(tm_marks(0, u64::MAX, MAX), ST_TM_SHARE);
        // the bits of the other parts are not touched
        assert_eq!(tm_marks(ST_PT_BUSY | ST_PT_SHORT, share_in, MAX), ST_PT_BUSY | ST_PT_SHORT | ST_TM_SHARE);
        assert_eq!(tm_marks(ST_PT_BUSY | ST_TM_SHARE, 0, MAX), ST_PT_BUSY);
        // tiny and huge maxima: the mark is monotonic in the pages, no overflow
        for max in [1, 2, 15, 16, 17, 1000, u64::MAX] {
            let mut last = 0;
            for p in [0, max / 16, max / 2, max / 16 * 11, max / 4 * 3, max / 8 * 7, max] {
                let m = tm_marks(0, p, max);
                assert!(m >= last && m & !ST_TM_SHARE == 0, "{max} {p}: {m}");
                last = m;
            }
            assert_eq!(tm_marks(ST_TM_SHARE, 0, max), 0);
        }
    }

    #[test]
    fn uc_step_resets_only_a_stalled_client_under_pressure() {
        const L: u64 = UC_STALL_MS;
        const M0: u64 = 1 << 20;
        let lim = UcLim { m0: M0, ..UcLim::REAL };
        // a sweep every 2 s from `t0` until `t1` (ms) with `info(t)` and `held`: the time of the reset, or None
        let run = |e: &mut Stall, t0: u64, t1: u64, held: u64, pressed: bool, info: &dyn Fn(u64) -> (u32, u64)| {
            (t0..t1).step_by(2000).find(|&t| uc_step(e, 7, Some(info(t)), held, t, &lim, pressed))
        };
        let run_g0 = |e: &mut Stall, lim: &UcLim| (2001..10 * L).step_by(2000).find(|&t| uc_step(e, 0, Some((0, 0)), M0, t, lim, true));
        // a client with a zero window that takes nothing (no fill either): its credit is L; never without the mark
        let mut e = Stall::default();
        assert!(!uc_step(&mut e, 7, Some((0, 0)), 0, 1, &lim, true), "the first sweep only starts the stall");
        assert_eq!(e, Stall { g1: 8, filled: true, acked: 0, at: 1, credit: L });
        assert_eq!(run(&mut e.clone(), 2001, 10 * L, M0, false, &|_| (0, 0)), None, "no mark: never");
        assert_eq!(run(&mut e, 2001, 10 * L, M0, true, &|_| (0, 0)), Some(L + 1), "the credit is used up at L");
        // the fill buys credit at UC_FILL_DIV x the price: 8 MiB = 8 MiB / (8 x 512) s
        let mut e = Stall::default();
        assert!(!uc_step(&mut e, 7, Some((0, 8 << 20)), 0, 1, &lim, true));
        assert_eq!(e.credit, L + (8 << 20) * 1000 / (8 * UC_RATE));
        // ... at most UC_CAP_MS
        let mut e = Stall::default();
        assert!(!uc_step(&mut e, 7, Some((0, 1 << 40)), 0, 1, &lim, true));
        assert_eq!(e.credit, UC_CAP_MS);
        // an open window (the network or the host is slow, not the client): no stall, also under pressure
        let mut e = Stall::default();
        assert_eq!(run(&mut e, 0, 10 * L, M0, true, &|_| (65_535, 1000)), None);
        assert_eq!((e.at, e.credit), (0, L + 1000 * 1000 / (8 * UC_RATE)));
        // a trickler: one byte per L - 2000 ms keeps its window 0: it gets about L in all (v1.3.3: kept for ever)
        let mut e = Stall::default();
        let at = run(&mut e, 0, 10 * L, M0, true, &|t| (0, t / (L - 2000)));
        assert!(at.is_some_and(|t| (L..L + 10_000).contains(&t)), "{at:?}");
        // ... and one that takes a byte at every sweep (its window 0 at each): the same, its stalls are paid for
        let mut e = Stall::default();
        let at = run(&mut e, 0, 10 * L, M0, true, &|t| (0, t / 2000));
        assert!(at.is_some_and(|t| (L..L + 10_000).contains(&t)), "{at:?}");
        // an honest slow reader of 1 KiB/s (60.73 T-wnd-big: each gap drains 1.30 x the take before it): takes of
        // 350 KB, a gap of 1.30 x 350 KB / 1 KiB/s (444 s) between them: kept for 10 hours
        let p = 350_000u64;
        let gap = p * 130 / 100 * 1000 / 1024 / 2000 * 2000;
        let mut e = Stall::default();
        assert_eq!(run(&mut e, 0, 36_000_000, M0, true, &|t| (0, p * (1 + t / gap))), None);
        // a connection that holds 4 x one full stream uses its credit 4 x as fast
        let mut e = Stall::default();
        assert!(!uc_step(&mut e, 7, Some((0, 0)), 4 * M0, 1, &lim, true));
        assert_eq!(run(&mut e, 2001, 10 * L, 4 * M0, true, &|_| (0, 0)), Some(L / 4 + 1));
        // a pause shorter than L, then an open window without a byte taken: the credit is not bought back
        let mut e = Stall::default();
        assert_eq!(run(&mut e, 1, L - 1000, M0, true, &|_| (0, 5)), None);
        assert!(!uc_step(&mut e, 7, Some((4096, 5)), M0, L, &lim, true));
        assert_eq!(e.at, 0);
        assert_eq!(run(&mut e, L + 2000, 3 * L, M0, true, &|_| (0, 5)).map(|t| t <= L + 8000), Some(true));
        // no parked download (None): no stall; a new connection in the slot (another generation): a new credit
        let mut e = Stall { g1: 8, filled: true, acked: 0, at: 1, credit: 0 };
        assert!(!uc_step(&mut e, 7, None, 0, L * 5, &lim, true));
        assert_eq!(e.at, 0);
        let mut e = Stall { g1: 8, filled: true, acked: 0, at: 1, credit: 0 };
        assert!(!uc_step(&mut e, 8, Some((0, 0)), 0, L * 5, &lim, true));
        assert_eq!(e, Stall { g1: 9, filled: true, acked: 0, at: L * 5, credit: L });
        // a slot's first connection has generation 0: a fresh record gets the starting credit too (60.78 T2: the
        // prototype took the zeroed record for one in use, credit 0, and reset such connections at the first mark)
        let mut e = Stall::default();
        assert!(!uc_step(&mut e, 0, Some((0, 0)), 0, 1, &lim, true));
        assert_eq!((e.g1, e.credit), (1, L));
        assert_eq!(run_g0(&mut e, &lim), Some(L + 1));
        // the shared mark: E5's bit follows E1's marks, also with E1 off; E1's bit only with E1 on
        for (opts, bit) in [(OPT_UNREAD, ST_UNREAD), (OPT_TCPMEM, ST_TM_SHARE), (OPT_UNREAD | OPT_TCPMEM, ST_UNREAD | ST_TM_SHARE)] {
            let b = Bounds::new(opts, 1, TcpForm::Mem { max_pages: 1600 }, 4096, 131_072);
            let mut until = 0;
            assert_eq!(b.tm_step(1200, false, 1, &mut until), bit, "{opts}: 3/4 of 1600");
            // the armed line: E1's when E1 is on, E5's own only without E1 (said holds the bit of the line printed)
            let said = b.said.load(Relaxed);
            assert_eq!(said & (ST_UNREAD | ST_TM_SHARE), if opts & OPT_TCPMEM != 0 { ST_TM_SHARE } else { ST_UNREAD }, "{opts}");
            assert_eq!(b.tm_step(1100, false, 2, &mut until), bit, "{opts}: 11/16 is still in");
            assert_eq!(b.tm_step(1099, false, 3, &mut until), 0, "{opts}: below 11/16 out");
            assert_eq!(b.said.load(Relaxed) & (ST_UNREAD | ST_TM_SHARE), 0, "{opts}: the at-rest line came with the armed one");
            assert_eq!(b.tm_step(1199, false, 4, &mut until), 0, "{opts}: not in from below 3/4");
        }
        let b = Bounds::new(OPT_UNREAD, 1, TcpForm::Flag, 4096, 131_072);
        let mut until = 0;
        assert_eq!(b.tm_step(10, true, 100, &mut until), ST_UNREAD);
        assert_eq!(b.tm_step(10, false, 100 + FLAG_HOLD_MS, &mut until), 0);
        assert!(Bounds::new(OPT_UNREAD, 1, TcpForm::Mem { max_pages: 1600 }, 4096, 131_072).describe()[0].1.contains("600 s"));
        // this kernel has the window in TCP_INFO (the laptop, the CI images and the boxes run 5.4 or later)
        assert!(wnd_probe());
    }

    #[test]
    fn floor_is_a_share_of_the_host_limit() {
        // the VPS: 89538 pages of 4 KiB; a receive buffer of 131072 bytes: 1/16 of 349.8 MiB is 21.9 MiB = 167 buffers
        assert_eq!(tm_floor(89_538, 4096, 131_072), 175);
        assert_eq!(tm_floor(89_538, 4096, 87_380), 263);
        // a small host has a small floor, a big one a big floor; never 0
        assert_eq!(tm_floor(4_096, 4096, 131_072), 8);
        assert_eq!(tm_floor(22_000_000, 4096, 131_072), 42_969);
        assert_eq!(tm_floor(0, 4096, 131_072), 1);
        assert_eq!(tm_floor(1, 4096, 0), 256);
        assert_eq!(tm_floor(u64::MAX, u64::MAX, 1), u32::MAX);
    }

    const A: IpKey = 0xa << 64;
    const B: IpKey = 0xb << 64;
    fn slot(conns: u32, single: Option<IpKey>, unread: u32, top: Option<IpKey>, top_unread: u32) -> Unread {
        Unread { at_ms: 1000, conns, single, unread, top, top_unread, connecting: 0 }
    }

    #[test]
    fn share_rule_needs_half_the_floor_and_another_client() {
        // A alone on the server, with every unread socket: never refused
        assert!(!tm_share(&[slot(30, Some(A), 3000, Some(A), 3000)], 1000, A, 100));
        // ... a second client that reads its download (no unread socket) is enough
        assert!(tm_share(&[slot(31, None, 3000, Some(A), 3000)], 1000, A, 100));
        // ... also on another worker
        assert!(tm_share(&[slot(30, Some(A), 3000, Some(A), 3000), slot(1, Some(B), 0, None, 0)], 1000, A, 100));
        // ... and B is never refused there: it holds nothing
        assert!(!tm_share(&[slot(30, Some(A), 3000, Some(A), 3000), slot(1, Some(B), 0, None, 0)], 1000, B, 100));
        // exactly half is not more than half
        assert!(!tm_share(&[slot(2, None, 400, Some(A), 200)], 1000, A, 100));
        assert!(tm_share(&[slot(2, None, 399, Some(A), 200)], 1000, A, 100));
        // below the floor: a few paused downloads of one honest user are not "the address"
        assert!(!tm_share(&[slot(2, None, 99, Some(A), 99)], 1000, A, 100));
        assert!(tm_share(&[slot(2, None, 100, Some(A), 100)], 1000, A, 100));
        // what an address holds is summed over the workers where it is the largest holder (a lower bound)
        let two = [slot(5, None, 300, Some(A), 250), slot(5, None, 300, Some(B), 160)];
        assert!(!tm_share(&two, 1000, A, 100), "250 of 600: A's 140 on the second worker are not seen");
        assert!(!tm_share(&two, 1000, B, 100));
        let two = [slot(5, None, 300, Some(A), 250), slot(5, None, 200, Some(A), 150)];
        assert!(tm_share(&two, 1000, A, 100));
        // a worker's counts are used for SLOT_FRESH_MS; a slot never written is not used
        let old = [slot(30, Some(A), 3000, Some(A), 3000), Unread { at_ms: 500, ..slot(1, Some(B), 0, None, 0) }];
        assert!(tm_share(&old, 500 + SLOT_FRESH_MS, A, 100));
        assert!(!tm_share(&old, 501 + SLOT_FRESH_MS, A, 100), "the other client's worker has not swept for 6 s: A is alone");
        assert!(!tm_share(&[slot(31, None, 3000, Some(A), 3000)], 1001 + SLOT_FRESH_MS, A, 100));
        assert!(!tm_share(&[Unread { at_ms: 0, ..slot(31, None, 3000, Some(A), 3000) }], 0, A, 1));
        // the unread sockets of a worker that has not swept are in nobody's count
        let stale = [slot(2, None, 300, Some(A), 250), Unread { at_ms: 500, ..slot(5, None, 1000, Some(B), 900) }];
        assert!(!tm_share(&stale, 500 + SLOT_FRESH_MS, A, 100), "250 of 1300");
        assert!(tm_share(&stale, 501 + SLOT_FRESH_MS, A, 100), "250 of 300: the other worker's 1000 are stale");
        // no overflow with full counters
        let big = [slot(u32::MAX, None, u32::MAX, Some(A), u32::MAX); 64];
        assert!(tm_share(&big, 1000, A, u32::MAX));
    }

    #[test]
    fn host_files_parse() {
        assert_eq!(sockstat_tcp_pages(b"sockets: used 150\nTCP: inuse 5 orphan 0 tw 0 alloc 7 mem 1234\nUDP: inuse 2 mem 9\n"), Some(1234));
        assert_eq!(sockstat_tcp_pages(b"sockets: used 150\nUDP: inuse 2 mem 9\n"), None);
        assert_eq!(sockstat_tcp_pages(b"TCP: inuse 5 mem\n"), None);
        assert_eq!(sockstat_tcp_pages(b""), None);
        let p = b"protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em\n\
                  TCPv6     2496      2       2   no     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n\
                  UDP       1344      1       0   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  y  n  n  y  y  y  n\n\
                  TCP       2336      7     123  yes     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n";
        assert_eq!(protocols_tcp(p), Some((123, true)));
        assert_eq!(protocols_tcp(b"TCP 2336 7 5 no 320 yes kernel\n"), Some((5, false)));
        assert_eq!(protocols_tcp(b"TCP 2336 7 -1 no 320\n"), Some((0, false)));
        assert_eq!(protocols_tcp(b"TCP 2336 7 5 NI 320\n"), None);
        assert_eq!(protocols_tcp(b"TCPv6 2336 7 5 yes 320\n"), None);
        assert_eq!(protocols_tcp(b""), None);
        // this host
        if let Ok(t) = std::fs::read("/proc/net/protocols") {
            assert!(protocols_tcp(&t).is_some(), "{}", String::from_utf8_lossy(&t));
        }
        if let Ok(t) = std::fs::read("/proc/net/sockstat") {
            assert!(sockstat_tcp_pages(&t).is_some());
        }
    }

    #[test]
    fn guard_steps_in_both_forms() {
        // Mem form: the state follows the pages with hysteresis; the floor is fixed
        let b = Bounds::new(OPT_TCPMEM, 2, TcpForm::Mem { max_pages: 1600 }, 4096, 131_072);
        let mut fu = 0;
        assert_eq!((b.state(), b.floor()), (0, 4));
        assert_eq!(b.tm_step(1199, false, 10, &mut fu), 0);
        assert_eq!(b.tm_step(1200, false, 20, &mut fu), ST_TM_SHARE);
        assert_eq!(b.tm_step(1600, true, 30, &mut fu), ST_TM_SHARE, "at the maximum: the share mark, nothing else");
        assert_eq!(b.tm_step(1100, false, 50, &mut fu), ST_TM_SHARE);
        assert_eq!(b.tm_step(1099, false, 60, &mut fu), 0);
        assert_eq!((b.pages(), b.floor(), fu), (1099, 4, 0));
        // Flag form: the share mark while the flag is set and FLAG_HOLD_MS after; the floor comes from the memory at
        // which the flag is set
        let b = Bounds::new(OPT_TCPMEM, 2, TcpForm::Flag, 4096, 131_072);
        assert_eq!((b.state(), b.floor()), (0, u32::MAX));
        assert_eq!(b.tm_step(60_000, false, 100, &mut fu), 0);
        assert_eq!(b.tm_step(60_000, true, 200, &mut fu), ST_TM_SHARE);
        assert_eq!(b.floor(), tm_floor(60_000, 4096, 131_072));
        assert_eq!(b.tm_step(90_000, true, 300, &mut fu), ST_TM_SHARE);
        assert_eq!(b.tm_step(50_000, false, 300 + FLAG_HOLD_MS - 1, &mut fu), ST_TM_SHARE);
        assert_eq!(b.tm_step(50_000, false, 300 + FLAG_HOLD_MS, &mut fu), 0);
        assert_eq!(b.floor(), tm_floor(90_000, 4096, 131_072), "the floor of the last reading with the flag set");
        // the period: slow far below the first mark, fast near it and while a mark is set
        let m = TcpForm::Mem { max_pages: 1600 };
        assert_eq!(period_ms(m, 0, 0), PERIOD_FAR_MS);
        assert_eq!(period_ms(m, 549, 0), PERIOD_FAR_MS);
        assert_eq!(period_ms(m, 550, 0), PERIOD_NEAR_MS);
        assert_eq!(period_ms(m, 1100, 0), PERIOD_AT_MS);
        assert_eq!(period_ms(m, 0, ST_TM_SHARE), PERIOD_AT_MS);
        assert_eq!(period_ms(TcpForm::Flag, 0, 0), 2 * PERIOD_NEAR_MS);
        assert_eq!(period_ms(TcpForm::Flag, 0, ST_TM_SHARE), PERIOD_AT_MS);
        // the thread's sleep: the shortest period of the parts that are on; E4's window counts only with E4 on
        // (it did with E4 off: after 10 s the thread woke every millisecond)
        for late in [0, NW_WINDOW_MS - 1, NW_WINDOW_MS, 10 * NW_WINDOW_MS] {
            assert_eq!(guard_sleep_ms(OPT_TCPMEM, m, 0, 0, late), PERIOD_FAR_MS, "{late}");
            assert_eq!(guard_sleep_ms(OPT_TCPMEM | OPT_DEAD, m, 1100, 0, late), PERIOD_AT_MS);
            assert_eq!(guard_sleep_ms(OPT_PORT, m, 0, 0, late), PT_PERIOD_MS);
            assert_eq!(guard_sleep_ms(OPT_PORT | OPT_TCPMEM, m, 0, ST_TM_SHARE, late), PERIOD_AT_MS.min(PT_PERIOD_MS));
        }
        assert_eq!(guard_sleep_ms(OPT_WATCH, m, 0, 0, 0), NW_WINDOW_MS);
        assert_eq!(guard_sleep_ms(OPT_WATCH, m, 0, 0, NW_WINDOW_MS - 7), 7);
        assert_eq!(guard_sleep_ms(OPT_WATCH, m, 0, 0, 2 * NW_WINDOW_MS), 1, "a late window is read at once");
        assert_eq!(guard_sleep_ms(OPT_WATCH | OPT_TCPMEM, m, 0, 0, 0), PERIOD_FAR_MS);
        assert_eq!(guard_sleep_ms(OPT_WATCH | OPT_PORT, m, 0, 0, NW_WINDOW_MS - 7), 7);
        assert_eq!(guard_sleep_ms(0, m, 0, 0, 0), NW_WINDOW_MS);
    }

    #[test]
    fn slots_and_log_rate() {
        let b = Bounds::new(OPT_TCPMEM, 3, TcpForm::Flag, 4096, 131_072);
        let mut v = vec![Unread::default(); 9];
        b.publish(1, slot(4, Some(A), 7, Some(A), 7));
        b.publish(9, slot(1, None, 1, None, 0)); // (no such worker: ignored)
        b.read_slots(&mut v);
        assert_eq!(v, [Unread::default(), slot(4, Some(A), 7, Some(A), 7), Unread::default()]);
        assert!(b.log_due(Log::TmShareRefused));
        assert!(!b.log_due(Log::TmShareRefused));
        assert!(b.log_due(Log::PtShareRefused), "each kind has its own time");
        // the two lines of a mark come as a pair: the end is said exactly when the start was
        assert!(b.mark_line(Log::TmShareMark, ST_TM_SHARE, true), "armed: the first line at once");
        assert!(b.mark_line(Log::PtShortMark, ST_PT_SHORT, true), "each mark has its own pair");
        assert!(b.mark_line(Log::TmShareMark, ST_TM_SHARE, false), "at rest: said, also within the 10 s");
        assert!(!b.mark_line(Log::TmShareMark, ST_TM_SHARE, false), "... once");
        assert!(!b.mark_line(Log::TmShareMark, ST_TM_SHARE, true), "armed again within 10 s: not said");
        assert!(!b.mark_line(Log::TmShareMark, ST_TM_SHARE, false), "... so its end is not said either");
        assert!(b.mark_line(Log::PtShortMark, ST_PT_SHORT, false), "the other mark's pair is whole");
        for form in [TcpForm::Flag, TcpForm::Mem { max_pages: 89_538 }] {
            for opt in 0..4 {
                let b = Bounds::new(OPT_TCPMEM | OPT_PORT, 1, form, 4096, 131_072);
                b.set_ports(32768, 60999, 28_232, opt);
                let d = b.describe();
                assert_eq!(d.iter().map(|r| r.0).collect::<Vec<_>>(), ["TCP memory guard", "source port guard"]);
                assert!(d.iter().all(|r| !r.1.contains(|c| crate::cli::REDACTION_MARKS.contains(c))), "{d:?}");
                assert_eq!(d[1].1.contains("this kernel"), opt != 3, "{}", d[1].1);
                for part in ["28232 source ports", "32768-60999", "21174 sockets"] {
                    assert!(d[1].1.contains(part), "{part}: {}", d[1].1);
                }
            }
        }
        assert!(Bounds::new(0, 1, TcpForm::Flag, 4096, 1).describe().is_empty());
        let d = Bounds::new(OPT_TCPMEM | OPT_DEAD, 1, TcpForm::Flag, 4096, 131_072).describe();
        assert_eq!(d.iter().map(|r| r.0).collect::<Vec<_>>(), ["TCP memory guard", "dead destination guard"]);
        assert!(
            d[1].1.contains("8 or more connects")
                && d[1].1.contains("4 SYNs")
                && !d[1].1.contains(|c| crate::cli::REDACTION_MARKS.contains(c)),
            "{d:?}"
        );
    }

    /// 60.78 bundle B2: --unread-close carries the relief wherever the host allows it (the Mem form, SO_BUF_LOCK); else
    /// one start line says the relief is not in effect, and the reset part works
    #[test]
    fn unread_close_carries_the_relief() {
        let mut w = Vec::new();
        assert_eq!(relief_bit(true, Some(true), &mut w), OPT_RELIEF);
        assert!(w.is_empty());
        for (mem, lock, why) in [(false, Some(true), "tcp_mem"), (true, Some(false), "SO_BUF_LOCK"), (true, None, "SO_BUF_LOCK")] {
            let mut w = Vec::new();
            assert_eq!(relief_bit(mem, lock, &mut w), 0);
            assert!(w.len() == 1 && w[0].starts_with("--unread-close: its relief") && w[0].contains(why), "{w:?}");
            assert!(!w[0].contains(|c| crate::cli::REDACTION_MARKS.contains(c)));
        }
        // on this host: --unread-close alone sets OPT_RELIEF exactly when the host allows it
        let (b, warn) = build(false, false, false, false, true, false, 1);
        if let Some(b) = b.filter(|b| b.opts & OPT_UNREAD != 0) {
            let host = matches!(b.tcp, TcpForm::Mem { .. }) && crate::net::buf_lock_supported() == Some(true);
            assert_eq!(b.opts & OPT_RELIEF != 0, host, "{warn:?}");
            assert_eq!(warn.iter().any(|w| w.contains("its relief")), !host, "{warn:?}");
        }
    }

    // ---- E3

    #[test]
    fn dest_failfast_is_off_with_an_upstream_proxy() {
        let (b, warn) = build(false, false, true, false, false, true, 2);
        assert!(b.is_none() && warn.len() == 1 && warn[0].contains("--dest-failfast is not in effect with --upstream"), "{warn:?}");
        assert!(!warn[0].contains(|c| crate::cli::REDACTION_MARKS.contains(c)));
        let (b, warn) = build(false, false, true, false, false, false, 2);
        assert!(warn.is_empty() && b.is_some_and(|b| b.opts == OPT_DEAD));
        assert!(
            build(false, false, false, false, false, false, 2).0.is_none()
                && build(false, false, false, false, false, true, 2).1.is_empty()
        );
    }

    /// 'another client is connected' as E1 and E3 read it: a connection that is not this address's, on any worker,
    /// by a fresh count
    #[test]
    fn others_are_connections_of_another_address() {
        let now = 100_000;
        let at = |conns, single| Unread { at_ms: now, conns, single, ..Unread::default() };
        assert!(!others(&[], now, A));
        assert!(!others(&[at(0, None), at(3, Some(A))], now, A), "only this address's connections");
        assert!(others(&[at(3, Some(A)), at(1, Some(B))], now, A), "another address on another worker");
        assert!(others(&[at(2, None)], now, A), "a worker with more than one address, or a client without a key");
        assert!(!others(&[Unread { at_ms: now - SLOT_FRESH_MS - 1, ..at(1, Some(B)) }], now, A), "a stale count");
        assert!(others(&[Unread { at_ms: now - SLOT_FRESH_MS, ..at(1, Some(B)) }], now, A));
        assert!(!others(&[Unread { at_ms: 0, ..at(1, Some(B)) }], now, A), "a worker that never counted");
    }

    // ---- E4

    const NETSTAT: &str =
        "TcpExt: SyncookiesSent TCPSynRetrans TCPTimeouts\nTcpExt: 0 1234 77\nIpExt: InNoRoutes TCPSynRetrans\nIpExt: 5 9\n";
    const SNMP: &str = "Ip: Forwarding DefaultTTL OutRequests\nIp: 1 64 5000\nTcp: RtoAlgorithm ActiveOpens PassiveOpens\nTcp: 1 300 20\n\
                        Udp: InDatagrams NoPorts InErrors OutDatagrams\nUdp: 9 8 7 600\nUdpLite: InDatagrams OutDatagrams\nUdpLite: 1 2\n";
    const SNMP6: &str = "Ip6InReceives                   \t11\nIp6OutRequests                  \t1000\nUdp6OutDatagrams                \t40\nUdpLite6OutDatagrams \t3\n";

    #[test]
    fn host_packet_counters() {
        assert_eq!(mib_field(NETSTAT, "TcpExt", "TCPSynRetrans"), Some(1234));
        assert_eq!(mib_field(NETSTAT, "IpExt", "TCPSynRetrans"), Some(9), "the protocol's own line pair");
        assert_eq!(mib_field(SNMP, "Udp", "OutDatagrams"), Some(600), "not UdpLite's");
        assert_eq!(
            (mib_field(SNMP, "Udp", "Nope"), mib_field(SNMP, "Sctp", "X"), mib_field("Tcp: ActiveOpens\n", "Tcp", "ActiveOpens")),
            (None, None, None)
        );
        assert_eq!(mib_field("Tcp: ActiveOpens\nTcp: x\n", "Tcp", "ActiveOpens"), None);
        assert_eq!(
            (mib6_field(SNMP6, "Udp6OutDatagrams"), mib6_field(SNMP6, "Ip6OutRequests"), mib6_field(SNMP6, "OutDatagrams")),
            (Some(40), Some(1000), None)
        );
        let n = Net { syn_retrans: 1234, opens: 300, udp_out: 640, ip_out: 6000 };
        assert_eq!(net_parse(NETSTAT, SNMP, SNMP6), Some(n));
        assert_eq!(net_parse(NETSTAT, SNMP, ""), Some(Net { udp_out: 600, ip_out: 5000, ..n }), "a host without IPv6");
        assert_eq!((net_parse("", SNMP, SNMP6), net_parse(NETSTAT, "", SNMP6)), (None, None));
        // this host
        let a = net_read().expect("/proc/net/netstat and /proc/net/snmp");
        let b = net_read().unwrap();
        assert!(b.ip_out >= a.ip_out && b.opens >= a.opens && b.syn_retrans >= a.syn_retrans && b.udp_out >= a.udp_out);
    }

    /// E4 when a line is written (10 s windows). The numbers are those of the raw data the thresholds come from.
    #[test]
    fn net_watch_lines() {
        let win = |syn_retrans, opens, udp_out, ip_out| Net { syn_retrans, opens, udp_out, ip_out };
        let mut last = (0, 0);
        let mut none = |d: Net, what: &str| assert!(nw_lines(d, 0, &mut last).is_empty() && last == (0, 0), "{what}");
        // a quiet server, one user whose page host is dead: 266 connects, 5 retransmits each
        none(win(1330, 266, 0, 1700), "a quiet server with one dead page");
        // 60.63 the mass case: 100 browsers, the page host slow but alive: the largest window
        none(win(19_160, 22_197, 0, 400_000), "the honest mass case");
        // ... its largest ratio in a window: 1.72 per attempt; and the same ratio at 4 times the volume
        none(win(17_200, 10_000, 0, 200_000), "the honest mass case, largest ratio");
        none(win(76_640, 44_394, 0, 800_000), "under 3 per attempt");
        // 60.63 the ramp to ports that do not answer: 300 CONNECT per s (no harm): 1,777 retransmits per s
        none(win(17_770, 3033, 0, 31_820), "the ramp below the floor");
        none(win(NW_SYN_FLOOR - 1, 100, 0, 100_000), "one under the floor");
        none(win(NW_SYN_FLOOR, NW_SYN_FLOOR / NW_SYN_PER_OPEN + 1, 0, 100_000), "one attempt over the ratio");
        assert_eq!(
            nw_lines(win(NW_SYN_FLOOR, NW_SYN_FLOOR / NW_SYN_PER_OPEN, 0, 100_000), 0, &mut (0, 0)).len(),
            1,
            "at the floor and the ratio"
        );
        assert_eq!(nw_lines(win(0, 0, NW_UDP_FLOOR, NW_UDP_FLOOR), 0, &mut (0, 0)).len(), 1, "UDP at the floor");
        // UDP: 5,000 datagrams per s (no harm in 60.63); many datagrams that are a small part of the packets
        none(win(0, 0, 50_000, 74_000), "UDP below the floor");
        none(win(0, 0, NW_UDP_FLOOR - 1, NW_UDP_FLOOR), "UDP one under the floor");
        none(win(0, 0, 200_000, 400_001), "UDP under half of the packets");
        // the ramp at 1,000 CONNECT per s (the first step with harm): 5,926 retransmits per s, 5.9 per attempt
        let l = nw_lines(win(59_260, 10_105, 0, 85_110), 9103, &mut last);
        assert_eq!((l.len(), last), (1, (59_260, 0)));
        for part in [
            "SYN retransmits on this host: 59260 in 10 s",
            "5 per connect attempt (10105 attempts)",
            "9103 streams of this server are connecting",
        ] {
            assert!(l[0].contains(part), "{part}: {}", l[0]);
        }
        // the next line of the shape only above twice that value
        assert!(nw_lines(win(118_520, 20_201, 0, 154_190), 0, &mut last).is_empty(), "twice the value: no line");
        assert_eq!(nw_lines(win(118_522, 20_201, 0, 154_190), 0, &mut last).len(), 1);
        assert_eq!(last, (118_522, 0));
        assert!(nw_lines(win(NW_SYN_FLOOR, 0, 0, 0), 0, &mut (0, 0)).len() == 1, "no attempt in the window: retransmits of older ones");
        // UDP: 10,000 datagrams per s of 12,075 packets (the first step with harm)
        let l = nw_lines(win(0, 0, 100_000, 120_750), 0, &mut last);
        assert_eq!((l.len(), last), (1, (118_522, 100_000)));
        assert!(l[0].contains("UDP datagrams sent by this host: 100000 in 10 s, 82 of every 100 packets"), "{}", l[0]);
        assert!(nw_lines(win(0, 0, 200_000, 240_000), 0, &mut last).is_empty());
        assert_eq!(nw_lines(win(0, 0, 200_002, 400_004), 0, &mut last).len(), 1, "exactly half of the packets");
        // both shapes in one window; no counter can overflow the tests
        let l = nw_lines(win(u64::MAX, 1, u64::MAX, u64::MAX), u64::MAX, &mut (0, 0));
        assert_eq!(l.len(), 2);
        for line in l.iter().chain(&nw_lines(win(59_260, 10_105, 100_000, 120_750), 7, &mut (0, 0))) {
            assert!(!line.contains(|c| crate::cli::REDACTION_MARKS.contains(c)) && !line.contains("60."), "{line}");
            assert!(line.len() <= 480, "{}: {line}", line.len());
        }
    }

    #[test]
    fn net_watch_needs_the_host_counters() {
        let (b, warn) = build(false, false, false, true, false, true, 1);
        assert!(warn.is_empty() && b.as_ref().is_some_and(|b| b.opts == OPT_WATCH), "{warn:?}");
        let d = b.unwrap().describe();
        assert_eq!(d.iter().map(|r| r.0).collect::<Vec<_>>(), ["network watch"]);
        assert!(
            d[0].1.contains("30000 or more SYN retransmits in 10 s and 3 or more per connect attempt")
                && d[0].1.contains("75000 or more UDP"),
            "{d:?}"
        );
        assert!(!d[0].1.contains(|c| crate::cli::REDACTION_MARKS.contains(c)));
    }

    #[test]
    fn conntrack_lines_and_warnings() {
        // the table of the rented containers (60.67): 262144 entries
        const MAX: u64 = 262_144;
        let mut said = false;
        assert_eq!(ct_line(196_607, MAX, &mut said), None);
        let l = ct_line(196_608, MAX, &mut said).expect("3/4 full: a line");
        assert!(l.contains("196608 of 262144 entries") && said);
        assert_eq!(ct_line(MAX, MAX, &mut said), None, "one line until the table was below half");
        assert_eq!(ct_line(131_072, MAX, &mut said), None);
        assert!(said, "half is not below half");
        assert_eq!(ct_line(131_071, MAX, &mut said), None);
        assert!(!said);
        assert!(ct_line(200_000, MAX, &mut said).is_some(), "again after it was below half");
        // the start: only the state (3/4 full), never the size against the descriptors (that is a --show-config row)
        assert_eq!(ct_warn(196_607, MAX), None);
        assert!(ct_warn(200_000, MAX).unwrap().contains("holds 200000 of 262144 entries"));
        assert_eq!(ct_row_text(331, MAX, Some(524_122)), "331 of 262144 entries in use; fewer than the about 524122 file descriptors for connections and streams: the table can fill before they do (net.netfilter.nf_conntrack_max)");
        assert_eq!(
            ct_row_text(331, MAX, Some(MAX)),
            "331 of 262144 entries in use; not fewer than the about 262144 file descriptors for connections and streams"
        );
        assert_eq!(ct_row_text(331, MAX, None), "331 of 262144 entries in use");
        for w in ct_warn(200_000, MAX).iter().chain(ct_line(MAX, MAX, &mut false).iter()) {
            assert!(!w.contains(|c| crate::cli::REDACTION_MARKS.contains(c)), "{w}");
        }
        // without --net-watch nothing is read or said
        assert!(ct_warnings(false).is_empty() && ct_row(false, Some(u64::MAX)).is_none());
        // the guard's first line follows what the start printed, in both orders of the two samples (review)
        assert_eq!(ct_primed(0), None, "the start has not looked yet: the guard waits");
        // start at 74% (no warning), guard at 80%: the guard's line comes
        let start = ct_start_code(ct_warn(194_000, MAX).is_some());
        let mut said = ct_primed(start).unwrap();
        assert!(ct_line(210_000, MAX, &mut said).is_some(), "start quiet at 74%, the guard at 80% says it");
        // start at 80% (warning), guard at 74%..80%: no 2nd line until the table was below half
        let start = ct_start_code(ct_warn(210_000, MAX).is_some());
        let mut said = ct_primed(start).unwrap();
        assert_eq!(ct_line(210_000, MAX, &mut said), None, "the start said it");
        assert_eq!(ct_line(194_000, MAX, &mut said), None);
        assert_eq!(ct_line(100_000, MAX, &mut said), None);
        assert!(ct_line(200_000, MAX, &mut said).is_some(), "again after below half");
        // start at 80% (warning), guard at 70%: nothing, and the next rise after below half is said
        let mut said = ct_primed(ct_start_code(true)).unwrap();
        assert_eq!(ct_line(183_500, MAX, &mut said), None);
        assert!(said, "70% is not below half");
        // a table not readable at the start: quiet
        assert_eq!(ct_primed(ct_start_code(false)), Some(false));
    }

    #[test]
    fn syn_count_of_a_socket() {
        assert_eq!(syns_sent(-1), None);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        assert_eq!(syns_sent(std::os::fd::AsRawFd::as_raw_fd(&c)), Some(1), "connected at the first SYN");
    }

    // ---- E2

    #[test]
    fn port_range_of_the_host() {
        assert_eq!(port_range("32768\t60999\n", "\n"), Some((32768, 60999, 28_232)));
        assert_eq!(port_range("32768 60999", ""), Some((32768, 60999, 28_232)));
        // reserved ports inside the range are not usable; those outside do not count; a list with ranges
        assert_eq!(port_range("32768 60999", "8080,40000,50000-50009,60990-61010\n"), Some((32768, 60999, 28_232 - 1 - 10 - 10)));
        assert_eq!(port_range("1024 65535", "1-70000,x"), Some((1024, 65535, 64_512)), "a part that is no port is skipped");
        assert_eq!(port_range("40000 40000", "40000"), Some((40000, 40000, 1)), "never 0");
        for bad in ["", "32768", "60999 32768", "0 100", "a b", "70000 80000"] {
            assert_eq!(port_range(bad, ""), None, "{bad}");
        }
        // the parts of the default range (rounded up): 1/4 = 7058, 3/4 = 21174
        assert_eq!((pt_part(28_232, PT_BUSY_IN_16), pt_part(28_232, PT_SHORT_IN_16)), (7058, 21_174));
        // the reserve: alone on the destination from 15/16
        assert_eq!(pt_part(28_232, PT_LAST_IN_16), 26_468);
        let v = |total, mine, others| DestView { total, mine, others, hidden: 0 };
        assert!(pt_last(v(15, 15, false), 16) && pt_last(v(16, 16, false), 16));
        assert!(!pt_last(v(14, 14, false), 16), "below 15/16");
        assert!(!pt_last(v(15, 14, true), 16), "another address holds a socket to it: the share rule's case");
        assert!(!pt_last(v(15, 0, true), 16), "the address that comes later");
        // a client without a key is never alone on a destination in the view (its sockets are "another's" to everyone)
        let live = [slot(1, None, 0, None, 0)];
        let all = [DestTop { dest: (IpAddr::from([192, 0, 2, 1]), 443), n: 16, top: None, top_n: 0 }];
        let mut d = [DestTop::EMPTY; PT_TOP];
        d[0] = all[0];
        let seen = pt_view(&live, &[d], 1000, all[0].dest, None);
        assert_eq!(seen, DestView { total: 16, mine: 0, others: true, hidden: 0 });
        assert!(!pt_last(seen, 16) && !pt_share(seen, 16));
        assert_eq!((pt_part(1, 4), pt_part(0, 4), pt_part(u32::MAX, 16)), (1, 1, u32::MAX as u64));
    }

    #[test]
    fn port_marks_have_hysteresis() {
        const U: u32 = 28_232;
        assert_eq!(pt_marks(0, 7057, U), 0);
        assert_eq!(pt_marks(0, 7058, U), ST_PT_BUSY);
        assert_eq!(pt_marks(ST_PT_BUSY, 5294, U), ST_PT_BUSY, "between exit (3/16) and entry the bit stays");
        assert_eq!(pt_marks(ST_PT_BUSY, 5293, U), 0);
        assert_eq!(pt_marks(0, 5294, U), 0);
        assert_eq!(pt_marks(ST_PT_BUSY, 21_173, U), ST_PT_BUSY);
        assert_eq!(pt_marks(ST_PT_BUSY, 21_174, U), ST_PT_BUSY | ST_PT_SHORT);
        assert_eq!(pt_marks(ST_PT_BUSY | ST_PT_SHORT, 19_410, U), ST_PT_BUSY | ST_PT_SHORT);
        assert_eq!(pt_marks(ST_PT_BUSY | ST_PT_SHORT, 19_409, U), ST_PT_BUSY);
        assert_eq!(pt_marks(0, u64::MAX, U), ST_PT_BUSY | ST_PT_SHORT);
        assert_eq!(pt_marks(ST_PT_BUSY | ST_PT_SHORT, 0, U), 0);
    }

    fn dest(n: u8) -> Dest {
        (IpAddr::from([192, 0, 2, n]), 443)
    }
    fn dt(d: Dest, n: u32, top: Option<IpKey>, top_n: u32) -> DestTop {
        DestTop { dest: d, n, top, top_n }
    }
    fn dests(e: &[DestTop]) -> Dests {
        let mut d = [DestTop::EMPTY; PT_TOP];
        d[..e.len()].copy_from_slice(e);
        d
    }

    #[test]
    fn port_share_needs_another_client_on_that_destination() {
        const U: u32 = 16; // 3/4 = 12 sockets
        let live = [slot(1, None, 0, None, 0)];
        let view = |e: &[DestTop], key| pt_view(&live, &[dests(e)], 1000, dest(1), key);
        // one address alone on the destination is never refused, also at every port of the range and with other
        // clients on the server (they use other destinations)
        let v = view(&[dt(dest(1), 16, Some(A), 16), dt(dest(2), 9, Some(B), 9)], Some(A));
        assert_eq!(v, DestView { total: 16, mine: 16, others: false, hidden: 0 });
        assert!(!pt_share(v, U));
        // a second address takes one socket there: the large holder is refused, the newcomer is not
        let e = [dt(dest(1), 13, Some(A), 12)];
        assert_eq!(view(&e, Some(A)), DestView { total: 13, mine: 12, others: true, hidden: 0 });
        assert!(pt_share(view(&e, Some(A)), U) && !pt_share(view(&e, Some(B)), U));
        // the other socket is of a client without a key (a private address, a trusted proxy's own): the same
        assert!(pt_share(view(&[dt(dest(1), 13, Some(A), 12)], Some(A)), U));
        // a client without a key is never refused
        assert!(!pt_share(view(&e, None), U));
        // below 3/4 of the ports nobody is refused
        assert!(!pt_share(view(&[dt(dest(1), 11, Some(A), 10)], Some(A)), U));
        // at 3/4 of the ports exactly
        assert!(pt_share(view(&[dt(dest(1), 12, Some(A), 7)], Some(A)), U));
        // a client without a key is never refused, also where the sockets of clients without a key are the most
        let e0 = [dt(dest(1), 13, None, 0)];
        assert_eq!(view(&e0, None), DestView { total: 13, mine: 0, others: true, hidden: 0 });
        assert!(!pt_share(view(&e0, None), U));
        // exactly half is not more than half
        assert!(!pt_share(view(&[dt(dest(1), 12, Some(A), 6)], Some(A)), U));
        assert!(pt_share(view(&[dt(dest(1), 13, Some(A), 7)], Some(A)), U));
        // another destination's sockets are not this one's (address or port)
        assert_eq!(pt_view(&live, &[dests(&e)], 1000, dest(2), Some(A)), DestView::default());
        assert_eq!(pt_view(&live, &[dests(&e)], 1000, (dest(1).0, 80), Some(A)), DestView::default());
    }

    #[test]
    fn port_share_sums_the_workers() {
        const U: u32 = 16;
        let stale = slot(1, None, 0, None, 0);
        let fresh = Unread { at_ms: stale.at_ms + SLOT_FRESH_MS + 1, ..stale };
        // two workers: A is the largest holder on both; a third worker's old counts are not used
        let d = [
            dests(&[dt(dest(1), 7, Some(A), 6)]),
            dests(&[dt(dest(2), 3, Some(B), 3), dt(dest(1), 6, Some(A), 6)]),
            dests(&[dt(dest(1), 99, Some(B), 99)]),
        ];
        let v = pt_view(&[fresh, fresh, stale], &d, fresh.at_ms, dest(1), Some(A));
        assert_eq!(v, DestView { total: 13, mine: 12, others: true, hidden: 0 });
        assert!(pt_share(v, U));
        // where A is not a worker's largest holder its sockets there are not known: what A holds is a lower bound, so
        // the rule can only miss (act late), never refuse an address that holds less than half
        let d = [dests(&[dt(dest(1), 7, Some(A), 6)]), dests(&[dt(dest(1), 6, Some(B), 4)])];
        let v = pt_view(&[fresh, fresh], &d, fresh.at_ms, dest(1), Some(A));
        assert_eq!(v, DestView { total: 13, mine: 6, others: true, hidden: 0 });
        assert!(!pt_share(v, U));
        // a destination that is not among a worker's PT_TOP largest is not seen there (the table is full): late again
        assert_eq!(PT_TOP, 8);
        // ... but that worker can hold up to its smallest published count of it, and those count against the address:
        // 22,000 published sockets with 11,001 of A, and a second worker with eight larger destinations
        let full: Vec<DestTop> = (10..18).map(|n| dt(dest(n), 6000 + n as u32, Some(B), 1)).collect();
        let d = [dests(&[dt(dest(1), 22_000, Some(A), 11_001)]), dests(&full)];
        let v = pt_view(&[fresh, fresh], &d, fresh.at_ms, dest(1), Some(A));
        assert_eq!(v, DestView { total: 22_000, mine: 11_001, others: true, hidden: 6010 });
        assert!(!pt_share(v, 28_232), "A may hold less than half of them");
        assert!(pt_share(DestView { hidden: 1, ..v }, 28_232) && !pt_share(DestView { hidden: 2, ..v }, 28_232));
        assert_eq!(pt_view(&[fresh, stale], &d, fresh.at_ms, dest(1), Some(A)).hidden, 0, "old counts are not used");
        // a list with a free entry holds all its worker has
        let d = [d[0], dests(&full[..7])];
        let v = pt_view(&[fresh, fresh], &d, fresh.at_ms, dest(1), Some(A));
        assert_eq!(v, DestView { total: 22_000, mine: 11_001, others: true, hidden: 0 });
        assert!(pt_share(v, 28_232));
        // a full list that holds the destination itself hides nothing of it
        let mut with = full.clone();
        with[7] = dt(dest(1), 6500, Some(A), 6500);
        let d = [d[0], dests(&with)];
        let v = pt_view(&[fresh, fresh], &d, fresh.at_ms, dest(1), Some(A));
        assert_eq!(v, DestView { total: 28_500, mine: 17_501, others: true, hidden: 0 });
        // a counter cannot wrap: u32 counts of every worker summed in u64
        let big = [dests(&[dt(dest(1), u32::MAX, Some(A), u32::MAX)]); 3];
        let v = pt_view(&[fresh; 3], &big, fresh.at_ms, dest(1), Some(A));
        assert_eq!((v.total, v.mine, v.others), (3 * u32::MAX as u64, 3 * u32::MAX as u64, false));
        assert!(!pt_share(v, u32::MAX));
    }

    #[test]
    fn port_guard_steps() {
        let b = Bounds::new(OPT_PORT, 2, TcpForm::Flag, 4096, 131_072);
        b.set_ports(40000, 40015, 16, 3);
        assert_eq!((b.pt_usable(), b.pt_range(false), b.pt_range(true)), (16, 40000 | 40015 << 16, 40000 | 40015 << 16));
        let (mut s, mut d) = (Vec::new(), Vec::new());
        assert_eq!(b.pt_step(1000, &mut s, &mut d), 0);
        // 3 + 1 sockets to one destination on two workers: 1/4 of 16 ports
        b.publish_dests(0, &dests(&[dt(dest(1), 3, Some(A), 3), dt(dest(2), 3, None, 0)]));
        b.publish(0, slot(1, Some(A), 0, None, 0));
        assert_eq!(b.pt_step(1000, &mut s, &mut d), 0);
        b.publish_dests(1, &dests(&[dt(dest(1), 1, Some(B), 1)]));
        b.publish(1, slot(1, Some(B), 0, None, 0));
        assert_eq!(b.pt_step(1000, &mut s, &mut d), ST_PT_BUSY);
        assert!(b.pt_state().contains("4 to 192.0.2.1:443, of 16 source ports"), "{}", b.pt_state());
        b.publish_dests(0, &dests(&[dt(dest(1), 11, Some(A), 11)]));
        assert_eq!(b.pt_step(1000, &mut s, &mut d), ST_PT_BUSY | ST_PT_SHORT);
        // the guard's own bits only: E1's stay as they are
        b.set_state(ST_TM_SHARE | ST_PT_BUSY | ST_PT_SHORT);
        b.publish_dests(0, &dests(&[dt(dest(1), 2, Some(A), 2)]));
        assert_eq!(b.pt_step(1000, &mut s, &mut d), ST_TM_SHARE | ST_PT_BUSY, "3 of 16: between the busy marks");
        // a worker that stops publishing: its counts are dropped once they are old
        assert_eq!(b.pt_step(1000 + SLOT_FRESH_MS + 1, &mut s, &mut d), ST_TM_SHARE);
        // a kernel without the option (or without it on IPv6 sockets): no value for that family
        b.set_ports(40000, 40015, 16, 1);
        assert_eq!((b.pt_range(false), b.pt_range(true)), (40000 | 40015 << 16, 0));
        b.set_ports(40000, 40015, 16, 0);
        assert_eq!((b.pt_range(false), b.pt_range(true)), (0, 0));
    }

    /// what this kernel does with the option (the laptop and the CI image are Linux 6.3 or later): IPv4 and IPv6 TCP
    /// sockets take it and give it back
    #[test]
    fn port_range_socket_option_on_this_kernel() {
        let (lo, hi, _) = host_ports().expect("ip_local_port_range");
        let r = lo as u32 | (hi as u32) << 16;
        for v6 in [false, true] {
            if !port_range_probe(v6, r) {
                eprintln!("IP_LOCAL_PORT_RANGE is not taken on a TCP socket (v6: {v6}) by this kernel: skipped");
                continue;
            }
            unsafe {
                let fd = libc::socket(if v6 { libc::AF_INET6 } else { libc::AF_INET }, libc::SOCK_STREAM, 0);
                assert!(set_port_range(fd, r));
                let (mut got, mut len) = (0u32, 4 as libc::socklen_t);
                assert_eq!(libc::getsockopt(fd, libc::IPPROTO_IP, IP_LOCAL_PORT_RANGE, &mut got as *mut _ as *mut _, &mut len), 0);
                assert_eq!(got, r, "v6: {v6}");
                libc::close(fd);
            }
        }
    }
}
