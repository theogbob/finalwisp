//! 20.04 Raw socket helpers, SSRF filter, async DNS pool.
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{mpsc, Arc, Mutex};

pub fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn set_nodelay(fd: RawFd) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, &one as *const _ as *const _, size_of::<libc::c_int>() as _);
    }
}

/// 20.21 TCP_INFO delivery rate (bytes/s) and its app-limited flag (then the rate is a lower bound).
/// Raw buffer: tcpi_delivery_rate is the u64 at offset 160, the flag bit 0 of byte 7 (linux/tcp.h).
pub fn delivery_rate(fd: RawFd) -> Option<(u64, bool)> {
    let mut b = [0u8; 232];
    let mut len = b.len() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, b.as_mut_ptr() as *mut _, &mut len) };
    if r != 0 || (len as usize) < 168 {
        return None;
    }
    // C bitfield: the first bit is the LSB on little-endian, the MSB on big-endian (review 20.21)
    let app_limited = if cfg!(target_endian = "little") { 0x01 } else { 0x80 };
    Some((u64::from_ne_bytes(b[160..168].try_into().unwrap()), b[7] & app_limited != 0))
}

/// 70.02 dead-peer detection on client sockets (`Config::keepalive`): TCP keepalive after KEEP_IDLE s
/// without traffic, every KEEP_INTVL s, KEEP_CNT unanswered probes => the kernel closes the socket
/// (ETIMEDOUT): an idle peer that vanished (no FIN/RST: power loss, NAT drop) is gone after ~3 min.
/// Set on the listener: accepted sockets inherit the options (checked on Linux 7.0). Keepalive does
/// not run while data is unacknowledged; `peer_gone` covers that case.
/// 70.13 also on open TCP target sockets (armed by `Worker::sweep`, within IDLE_SWEEP_MS): a site
/// that vanished while the stream is idle or only downloading (nothing unacked on our side) ends with
/// CLOSE 0x47 after ~3 min.
/// A live idle target ACKs the probes. Unacked upload data still waits for the retransmission timeout.
pub const KEEP_IDLE: i32 = 120;
pub const KEEP_INTVL: i32 = 15;
pub const KEEP_CNT: i32 = 4;

pub fn set_keepalive(fd: RawFd) -> bool {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)
        && setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, KEEP_IDLE)
        && setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, KEEP_INTVL)
        && setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, KEEP_CNT)
}

/// 70.02 Shortest time without any ACK from the peer while we have data out before the peer counts as
/// gone. Above TCP_RTO_MAX (120 s, the longest gap between two zero-window probes or retransmissions;
/// not settable higher on 7.0): a live client that stops reading ACKs every probe. Not
/// TCP_USER_TIMEOUT: since Linux 5.11 that also aborts a live zero-window peer after the timeout
/// (measured on 7.0: a client that stopped reading, 10 s timeout, ETIMEDOUT at 10.5 s).
pub const PEER_GONE_MS: u32 = 150_000;

/// 70.02 The peer has ACKed nothing for PEER_GONE_MS and at least PEER_GONE_PROBES retransmissions or
/// zero-window probes in a row are unanswered (TCP_INFO: tcpi_retransmits byte 2, tcpi_probes byte 3, consecutive
/// since the last ACK; tcpi_last_ack_recv u32 at 56). The counter rises when a probe is sent and any ACK clears it,
/// so N in a row = N probe exchanges (probe or reply) lost. 60.17 (RC1 gold soak): 2 was one loss short: a live
/// zero-window reader lost the probes at ~205 and ~325 s of its pause on a CPU-saturated host (loopback softnet and
/// socket backlog drops) and was reset (1 of 2,058 pauses; reproduced with netem loss on lo, 60.17). With 3 a live
/// peer must lose 3 exchanges in a row (at the 120 s backoff a burst of >= 240 s). The backoff keeps doubling while
/// the window stays shut, so the third unanswered probe comes 7 x the probe interval at death after the last ACK
/// (was 3 x): a peer that dies within ~25 s of the pause start (interval <= ~21 s; keepalive_dead.py: cut at ~3 s) is
/// still caught at ~150 s, later deaths at up to ~360 s at full backoff (was ~240 s). Known limits (review): tcpi_retransmits is only cleared by an ACK of new data, so a peer that
/// shrinks its window during a retransmission episode keeps it. 70.06: the caller acts only when this holds on two
/// sweeps in a row with no ACK between them (the last probe's reply is then not just in flight).
/// Some(tcpi_last_ack_recv in ms) = gone.
pub fn peer_gone(fd: RawFd) -> Option<u32> {
    let mut b = [0u8; 64];
    let mut len = b.len() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, b.as_mut_ptr() as *mut _, &mut len) };
    if r != 0 || (len as usize) < 60 {
        return None;
    }
    gone_by(&b)
}

/// 60.17 Unanswered probes or retransmissions in a row before a silent peer counts as gone (see peer_gone).
pub const PEER_GONE_PROBES: u8 = 3;

/// peer_gone's rule on the first 60 bytes of struct tcp_info.
fn gone_by(b: &[u8; 64]) -> Option<u32> {
    let last_ack_recv = u32::from_ne_bytes(b[56..60].try_into().unwrap());
    (last_ack_recv >= PEER_GONE_MS && (b[2] >= PEER_GONE_PROBES || b[3] >= PEER_GONE_PROBES)).then_some(last_ack_recv)
}

/// 70.08 TCP_INFO tcpi_bytes_received (u64 at 128, Linux 4.1+): payload bytes the peer delivered, in
/// order (what a kTLS socket has taken in, also while its parser holds an incomplete record). None =
/// not available.
pub fn bytes_received(fd: RawFd) -> Option<u64> {
    let mut b = [0u8; 136];
    let mut len = b.len() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, b.as_mut_ptr() as *mut _, &mut len) };
    (r == 0 && len as usize >= 136).then(|| u64::from_ne_bytes(b[128..136].try_into().unwrap()))
}

/// 60.24 TCP_INFO (tcpi_bytes_received at 128, tcpi_bytes_acked at 120; Linux 4.1+): the connection's wire bytes in
/// and out (for --log-conns at close), without the peer's FIN. None = not TCP or an older kernel.
pub fn bytes_rx_tx(fd: RawFd) -> Option<(u64, u64)> {
    let mut b = [0u8; 136];
    let mut len = b.len() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, b.as_mut_ptr() as *mut _, &mut len) };
    let u = |o: usize| u64::from_ne_bytes(b[o..o + 8].try_into().unwrap());
    // the peer's FIN takes one sequence number and is counted as received (CLOSE_WAIT: it came, ours did not go yet)
    const TCP_CLOSE_WAIT: u8 = 8; // include/net/tcp_states.h (not in the libc crate)
    let fin = u64::from(b[0] == TCP_CLOSE_WAIT);
    (r == 0 && len as usize >= 136).then(|| (u(128).saturating_sub(fin), u(120)))
}

/// 20.30 TCP_INFO tcpi_min_rtt (u32 microseconds at 148, Linux 4.6+): the path's minimum RTT as the kernel
/// saw it (credit.rs window autotune; our own ping RTT also holds both ends' queueing). None = not available.
pub fn min_rtt_us(fd: RawFd) -> Option<u32> {
    let mut b = [0u8; 152];
    let mut len = b.len() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, b.as_mut_ptr() as *mut _, &mut len) };
    (r == 0 && len as usize >= 152).then(|| u32::from_ne_bytes(b[148..152].try_into().unwrap())).filter(|&v| v > 0 && v != u32::MAX)
    // (review: ~0 = no sample yet)
}

/// 20.19 TCP_NOTSENT_LOWAT: the socket reports writable (and send() takes more) only while fewer
/// than `bytes` are queued but not yet sent, so the server's own queue decides what goes out next
/// instead of a multi-megabyte kernel FIFO. Bytes in flight (cwnd) are not limited.
pub fn set_notsent_lowat(fd: RawFd, bytes: u32) {
    let _ = try_notsent_lowat(fd, bytes); // best effort: a failure keeps the kernel default
}

/// 60.30 C10a set_notsent_lowat with the result (the upload cap fails its stream closed when the setting is refused).
#[must_use]
pub fn try_notsent_lowat(fd: RawFd, bytes: u32) -> bool {
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_NOTSENT_LOWAT, bytes as libc::c_int)
}

/// 60.30 C10a bandwidth caps by kernel TCP pacing, bytes/s (0 = off): `download` on every listener (accepted sockets
/// inherit it: sk_clone copies sk_max_pacing_rate and sk_pacing_status, 60.26), `upload` per TCP target (won).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pacing {
    pub download: u32,
    pub upload: u32,
}

impl Pacing {
    /// 60.30 C10a what a download cap does to two other settings: splice off (60.18 #17: with splice a binding cap
    /// split wss streams unevenly, 60.26) and the client lowat lowered to paced_lowat. (splice, notsent_lowat)
    pub fn client_settings(&self, splice: bool, lowat: u32) -> (bool, u32) {
        (splice && self.download == 0, paced_lowat(lowat, self.download))
    }
}

/// 60.30 C10a smallest cap: below 16 KiB/s the 16 KiB lowat floor alone is > 1 s of queue, fq's 10 s horizon can drop
/// EDT-stamped packets and a close tail outlasts the 10 s kTLS linger (60.26 design review)
pub const MIN_RATE: u32 = 16 << 10;
/// 60.30 C10a largest cap: the u32 form of SO_MAX_PACING_RATE (0xFFFFFFFF means "no limit" to the kernel)
pub const MAX_RATE: u32 = 4095 << 20;

/// 60.30 C10a SO_MAX_PACING_RATE (bytes/s of TCP payload; kernel internal pacing since 4.13, or fq).
#[must_use]
pub fn set_pacing(fd: RawFd, rate: u32) -> bool {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_MAX_PACING_RATE, rate as i32)
}

/// 60.30 C10a SO_MAX_PACING_RATE as the kernel reports it (u32 form; u32::MAX = none). None = getsockopt failed.
pub fn pacing(fd: RawFd) -> Option<u32> {
    let mut v: u32 = 0;
    let mut len = size_of::<u32>() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_MAX_PACING_RATE, &mut v as *mut _ as *mut _, &mut len) };
    (r == 0 && len as usize == size_of::<u32>()).then_some(v)
}

/// 60.30 C10a the unsent-queue bound that goes with a pacing cap: 1/8 s of the rate, at least 16 KiB (a queue bound,
/// not a latency bound). Client sockets: never above the configured --notsent-lowat; 0 (= kernel default, chosen by
/// the operator) stays 0. rate 0 = no cap: `lowat` unchanged.
pub fn paced_lowat(lowat: u32, rate: u32) -> u32 {
    if rate == 0 || lowat == 0 {
        return lowat;
    }
    lowat.min(pace_lowat(rate))
}

/// 60.30 C10a max(16 KiB, rate / 8)
pub fn pace_lowat(rate: u32) -> u32 {
    (rate / 8).max(16 << 10)
}

/// 60.30 C10a startup self-check: does an accepted socket carry its listener's SO_MAX_PACING_RATE (the download cap
/// relies on it)? A loopback listener with `rate`, one connect, one accept (all three fds owned: closed on every path;
/// at most ~1 s). Some(true) = inherited, Some(false) = the option is refused or the accepted socket has another value
/// (refuse to start),
/// None = the probe could not run (no loopback, ...): unverified. It proves inheritance only, not that every route
/// enforces the rate (60.26 [rt2]).
pub fn pacing_inherited(rate: u32) -> Option<bool> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let sock = || {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
        (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
    };
    let l = sock()?;
    let lo = SocketAddr::from(([127, 0, 0, 1], 0));
    let (ss, len) = sockaddr(&lo);
    if !set_pacing(l.as_raw_fd(), rate) {
        return Some(false); // review: the kernel refuses the option itself (the listeners would too)
    }
    if unsafe { libc::bind(l.as_raw_fd(), &ss as *const _ as *const _, len) } < 0 || unsafe { libc::listen(l.as_raw_fd(), 1) } < 0 {
        return None;
    }
    let mut at: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut alen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe { libc::getsockname(l.as_raw_fd(), &mut at as *mut _ as *mut _, &mut alen) } < 0 {
        return None;
    }
    let c = sock()?;
    let r = unsafe { libc::connect(c.as_raw_fd(), &at as *const _ as *const _, alen) };
    if r < 0 && errno() != libc::EINPROGRESS {
        return None;
    }
    let mut p = libc::pollfd { fd: l.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut p, 1, 1000) } != 1 {
        return None;
    }
    let a = unsafe { libc::accept4(l.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
    if a < 0 {
        return None;
    }
    let a = unsafe { OwnedFd::from_raw_fd(a) };
    Some(pacing(a.as_raw_fd())? == rate)
}

fn setsockopt_int(fd: RawFd, level: i32, opt: i32, v: i32) -> bool {
    unsafe { libc::setsockopt(fd, level, opt, &v as *const _ as *const _, size_of::<libc::c_int>() as _) == 0 }
}

/// 20.26 memory pressure: fix SO_RCVBUF and SO_SNDBUF (the kernel doubles the value and stops
/// autotuning). A live socket keeps what is already queued; new data is limited at once. The sizes
/// per socket kind and level come from `caps` (worker/conn.rs, connect.rs, target.rs, levels.rs).
pub fn cap_bufs(fd: RawFd, (rcv, snd): (u32, u32)) {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, rcv as i32);
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, snd as i32);
}

/// 20.26 SO_RCVBUF and SO_SNDBUF as the kernel reports them (already doubled), saved before a cap.
pub fn buf_sizes(fd: RawFd) -> (i32, i32) {
    let get = |opt| {
        let mut v: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, opt, &mut v as *mut _ as *mut _, &mut len) };
        v
    };
    (get(libc::SO_RCVBUF), get(libc::SO_SNDBUF))
}

/// 20.26 pressure gone: give back the sizes from before the cap (`saved`, from buf_sizes), then clear
/// the buffer locks (SO_BUF_LOCK, Linux 5.15+: absent from v5.14 net/core/sock.c and from RHEL 9) so autotuning continues from there. Clearing the lock
/// alone is not enough: a capped receive buffer does not regrow (measured on loopback: a 16 KiB cap
/// stayed at 32 KiB and ~0 MiB/s after the unlock; restored + unlocked: 9 GiB/s and growing).
/// Restored values are clamped to net.core.rmem_max/wmem_max (autotuned sizes can be larger); with
/// SO_BUF_LOCK they regrow from there, on older kernels (< 5.15) they stay locked at that size.
pub fn uncap_bufs(fd: RawFd, saved: (i32, i32)) {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, saved.0 / 2); // the kernel doubles it again
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, saved.1 / 2);
    setsockopt_int(fd, libc::SOL_SOCKET, SO_BUF_LOCK, 0);
}

const SO_BUF_LOCK: i32 = 72; // asm-generic/socket.h (not in every libc version)

/// 60.47 SOCK_RCVBUF_LOCK in SO_BUF_LOCK's bit mask (include/net/sock.h; SOCK_SNDBUF_LOCK = 1)
pub const RCVBUF_LOCK: i32 = 2;

fn getsockopt_int(fd: RawFd, level: i32, opt: i32) -> Option<i32> {
    let mut v: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    (unsafe { libc::getsockopt(fd, level, opt, &mut v as *mut _ as *mut _, &mut len) } == 0).then_some(v)
}

/// 60.47 (Linux 5.15+) the socket's buffer lock bits (SO_BUF_LOCK: SOCK_SNDBUF_LOCK | SOCK_RCVBUF_LOCK); None = error
pub fn buf_lock(fd: RawFd) -> Option<i32> {
    getsockopt_int(fd, libc::SOL_SOCKET, SO_BUF_LOCK)
}

/// 60.47 set the lock bits (no size change: a locked receive buffer keeps its size, autotuning stops growing it)
pub fn set_buf_lock(fd: RawFd, bits: i32) -> bool {
    setsockopt_int(fd, libc::SOL_SOCKET, SO_BUF_LOCK, bits)
}

/// 60.47 SO_RCVBUF as the kernel reports it (doubled); None = error
pub fn rcvbuf(fd: RawFd) -> Option<i32> {
    getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)
}

/// 60.47 2 x net.core.rmem_max as the kernel applies it: SO_RCVBUF on a throwaway socket is clamped to it, so a huge
/// request reads back that limit (works where the net sysctls are hidden, e.g. containers). None = the probe failed
pub fn rcvbuf_limit() -> Option<u64> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    let v = (setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, i32::MAX / 2)).then(|| rcvbuf(fd)).flatten();
    unsafe { libc::close(fd) };
    v.filter(|&v| v > 0).map(|v| v as u64)
}

/// 60.47 SO_RCVBUF (`kernel` = the reported, doubled size wanted; clamped to 2 x net.core.rmem_max; also sets
/// SOCK_RCVBUF_LOCK)
pub fn set_rcvbuf(fd: RawFd, kernel: i32) -> bool {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, kernel / 2)
}

/// 80.01 F2 startup probe: does this kernel have SO_BUF_LOCK (Linux 5.15+; not in RHEL 9)? Sets it to 0 on
/// a throwaway socket (no buffer is locked there, so no effect). Some(false) = ENOPROTOOPT: sockets capped
/// under memory pressure stay capped (`uncap_bufs`); None = the probe itself failed. Log only, no behaviour change.
pub fn buf_lock_supported() -> Option<bool> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    let ok = setsockopt_int(fd, libc::SOL_SOCKET, SO_BUF_LOCK, 0);
    let e = errno();
    unsafe { libc::close(fd) };
    match (ok, e) {
        (true, _) => Some(true),
        (false, libc::ENOPROTOOPT) => Some(false),
        _ => None,
    }
}

/// 80.01 F7 kernel release (uname -r), for the capability line and startup errors. "?" if uname fails.
pub fn kernel_release() -> String {
    let mut u: libc::utsname = unsafe { zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return "?".into();
    }
    // SAFETY: uname NUL-terminates release inside the array
    unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy().into_owned()
}

pub fn sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut ss: libc::sockaddr_storage = unsafe { zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            // SAFETY: sockaddr_storage is large and aligned enough for any sockaddr type (its purpose)
            let sin = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as _;
            sin.sin_port = a.port().to_be();
            sin.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) };
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            // SAFETY: as above
            let sin6 = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as _;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_addr = libc::in6_addr { s6_addr: a.ip().octets() };
            sin6.sin6_flowinfo = a.flowinfo();
            sin6.sin6_scope_id = a.scope_id();
            size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as _)
}

/// Refuse to share a port with another process. SO_REUSEPORT would otherwise let a second
/// (possibly stale) instance silently take part of the traffic. Probe without SO_REUSEPORT.
pub fn ensure_port_free(addr: &SocketAddr) -> io::Result<()> {
    unsafe {
        let dom = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let fd = libc::socket(dom, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one as *const _ as *const _, 4);
        let (ss, len) = sockaddr(addr);
        let r = libc::bind(fd, &ss as *const _ as *const _, len);
        let e = io::Error::last_os_error();
        libc::close(fd);
        if r < 0 {
            return Err(e);
        }
        Ok(())
    }
}

/// Bind a SO_REUSEPORT listener (one per worker thread).
/// 60.30 C10a `pacing` (bytes/s, 0 = off): SO_MAX_PACING_RATE before bind/listen, so every accepted socket has it.
pub fn listen(addr: &SocketAddr, keepalive: bool, pacing: u32) -> io::Result<RawFd> {
    unsafe {
        let dom = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let fd = libc::socket(dom, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
            libc::setsockopt(fd, libc::SOL_SOCKET, opt, &one as *const _ as *const _, 4);
        }
        // 70.02 inherited by every accepted socket
        if keepalive && !set_keepalive(fd) {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(io::Error::new(e.kind(), format!("TCP keepalive on the listener ({e}); --no-keepalive turns it off")));
        }
        // 60.30 C10a also inherited by every accepted socket (a cap that cannot be set must not run uncapped)
        if pacing > 0 && !set_pacing(fd, pacing) {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(io::Error::new(e.kind(), format!("SO_MAX_PACING_RATE on the listener ({e}): --download-rate")));
        }
        let (ss, len) = sockaddr(addr);
        if libc::bind(fd, &ss as *const _ as *const _, len) < 0 || libc::listen(fd, 4096) < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

static TFO_OFF: AtomicBool = AtomicBool::new(false);

/// 60.63 E2 `connect`, written once for its two forms. The plain form's expansion is, token for token, the function
/// as it was before 60.63. The ranged form sets the socket's own local port range (IP_LOCAL_PORT_RANGE, low | high
/// << 16; 0 = not set) before the connect picks a port; a kernel that refuses the option connects as without it.
macro_rules! connect_fn {
    ($(#[$m:meta])* $name:ident $(, $range:ident)?) => {
        $(#[$m])*
        pub fn $name(addr: &SocketAddr, syn_data: Option<&[u8]> $(, $range: u32)?) -> Result<(RawFd, bool, usize), i32> {
        unsafe {
            let dom = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
            let fd = libc::socket(dom, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(errno());
            }
            $( if $range != 0 { crate::bounds::set_port_range(fd, $range); } )?
            set_nodelay(fd);
            let (ss, len) = sockaddr(addr);
            if let Some(d) = syn_data.filter(|d| !d.is_empty() && !TFO_OFF.load(Relaxed)) {
                let n = libc::sendto(
                    fd,
                    d.as_ptr() as *const _,
                    d.len(),
                    libc::MSG_FASTOPEN | libc::MSG_NOSIGNAL,
                    &ss as *const _ as *const _,
                    len,
                );
                if n >= 0 {
                    return Ok((fd, false, n as usize));
                }
                match errno() {
                    libc::EINPROGRESS => return Ok((fd, false, 0)),
                    libc::EOPNOTSUPP | libc::EPROTONOSUPPORT => TFO_OFF.store(true, Relaxed), // fall through
                    e => {
                        libc::close(fd);
                        return Err(e);
                    }
                }
            }
            if libc::connect(fd, &ss as *const _ as *const _, len) == 0 {
                return Ok((fd, true, 0));
            }
            let e = errno();
            if e == libc::EINPROGRESS {
                Ok((fd, false, 0))
            } else {
                libc::close(fd);
                Err(e)
            }
        }
    }
    };
}

connect_fn!(
    /// Start a non-blocking TCP connect. Ok((fd, done_immediately, bytes_in_syn)).
    /// 20.15: with `syn_data`, try TCP Fast Open (sendto MSG_FASTOPEN): with a cached cookie the SYN
    /// carries up to one MSS of it (bytes_in_syn > 0, still connecting); without one the kernel sends a
    /// cookie-request SYN and takes nothing (EINPROGRESS, bytes_in_syn = 0). The caller keeps the bytes
    /// until this socket wins. TFO unsupported (EOPNOTSUPP) => disabled for the process, plain connect.
    connect
);
connect_fn!(
    /// `connect` with the socket option IP_LOCAL_PORT_RANGE (60.63 E2: a destination that holds a large part of the
    /// host's source ports)
    connect_ranged,
    range
);

/// 20.14: state of a connecting socket, without blocking (one poll). None = in progress,
/// Some((0, peer_closed)) = connected, Some((errno, _)) = failed.
pub fn connect_state(fd: RawFd) -> Option<(i32, bool)> {
    let mut p = libc::pollfd { fd, events: libc::POLLOUT | libc::POLLRDHUP, revents: 0 };
    if unsafe { libc::poll(&mut p, 1, 0) } <= 0 || p.revents == 0 {
        return None;
    }
    let closed = p.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0;
    match so_error(fd) {
        0 if p.revents & libc::POLLOUT != 0 => Some((0, closed)),
        0 if p.revents & libc::POLLRDHUP != 0 => None, // half-closed before OUT is reported: wait
        0 => Some((libc::ECONNRESET, true)),
        e => Some((e, true)),
    }
}

/// True if the peer already closed (or reset) this socket.
pub fn peer_closed(fd: RawFd) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLRDHUP, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) > 0 && p.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0 }
}

/// 20.14 (RFC 8305 section 4): keep the resolver's order (RFC 6724 sorting) but alternate address
/// families, starting with the family of the first address. Duplicates are dropped.
pub fn interleave(addrs: &mut Vec<IpAddr>) {
    let mut seen = Vec::with_capacity(addrs.len());
    addrs.retain(|a| {
        if seen.contains(a) {
            false
        } else {
            seen.push(*a);
            true
        }
    });
    let Some(first) = addrs.first().map(|a| a.is_ipv4()) else { return };
    let (mut a, mut b): (Vec<IpAddr>, Vec<IpAddr>) = addrs.iter().partition(|x| x.is_ipv4() == first);
    addrs.clear();
    let (mut a, mut b) = (a.drain(..), b.drain(..));
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => addrs.extend(x.into_iter().chain(y)),
        }
    }
}

/// 70.10 RFC 8305 s4: the late address family's answer joins a target that is already connecting. New addresses
/// (duplicates dropped) go into the untried tail addrs[tried..], which then starts with the family the last attempt
/// did not use and alternates families; the tried head is kept as is.
pub fn he_append(addrs: &mut Vec<IpAddr>, tried: usize, new: impl IntoIterator<Item = IpAddr>) {
    for ip in new {
        if !addrs.contains(&ip) {
            addrs.push(ip);
        }
    }
    let mut tail = addrs.split_off(tried.min(addrs.len()));
    if let Some(last) = addrs.last() {
        if let Some(i) = tail.iter().position(|a| a.is_ipv4() != last.is_ipv4()) {
            let a = tail.remove(i);
            tail.insert(0, a);
        }
    }
    interleave(&mut tail);
    addrs.extend(tail);
}

/// 20.24 RFC 8305 s5 history: `lost` holds first addresses that recently lost a connect race to the
/// other family. If the (interleaved) first address is one of them, start with the other family instead,
/// unless its first address lost too. Order inside each family is kept.
pub fn he_prefer(addrs: &mut Vec<IpAddr>, lost: &std::collections::HashMap<IpAddr, std::time::Instant>, ttl: std::time::Duration) {
    let fresh = |ip: &IpAddr| lost.get(ip).is_some_and(|at| at.elapsed() < ttl);
    let Some(&first) = addrs.first() else { return };
    if !fresh(&first) {
        return;
    }
    if let Some(i) = addrs.iter().position(|a| a.is_ipv4() != first.is_ipv4()) {
        if !fresh(&addrs[i]) {
            let a = addrs.remove(i);
            addrs.insert(0, a);
            interleave(addrs);
        }
    }
}

/// 20.24 the remote address of a connected socket.
pub fn peer_ip(fd: RawFd) -> Option<IpAddr> {
    sock_ip(fd, true)
}

/// the address of a connected socket's remote end (`peer`) or local end
fn sock_ip(fd: RawFd, peer: bool) -> Option<IpAddr> {
    let mut ss: libc::sockaddr_storage = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let p = &mut ss as *mut _ as *mut _;
    if unsafe {
        if peer {
            libc::getpeername(fd, p, &mut len)
        } else {
            libc::getsockname(fd, p, &mut len)
        }
    } != 0
    {
        return None;
    }
    match ss.ss_family as libc::c_int {
        // SAFETY (both arms): sockaddr_storage fits and aligns any sockaddr; ss_family says which one the call wrote
        libc::AF_INET => {
            let sa = unsafe { &*(&ss as *const _ as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            let sa = unsafe { &*(&ss as *const _ as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// B (20.31 redesign): is a connected TCP socket's peer on this host? A loopback peer (127/8, ::1, v4-mapped), or a
/// peer address equal to our own end's (the kernel's source choice for a local destination: connecting to one of the
/// box's addresses binds that address). Known gap (deliberate, no interface scan): a peer on ANOTHER of this box's
/// non-loopback addresses with a different source chosen counts as remote. None of either end: remote.
pub fn same_host(fd: RawFd) -> bool {
    let canon = |a: IpAddr| a.to_canonical();
    match (sock_ip(fd, true).map(canon), sock_ip(fd, false).map(canon)) {
        (Some(p), Some(l)) => p.is_loopback() || p == l,
        (Some(p), None) => p.is_loopback(),
        _ => false,
    }
}

/// 20.16 non-blocking UDP socket connected to `addr`: send() needs no address and the kernel only
/// delivers datagrams from that peer. connect() sends nothing (no handshake, no timeout).
pub fn udp_connect(addr: &SocketAddr) -> Result<RawFd, i32> {
    unsafe {
        let dom = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let fd = libc::socket(dom, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(errno());
        }
        let (ss, len) = sockaddr(addr);
        if libc::connect(fd, &ss as *const _ as *const _, len) < 0 {
            let e = errno();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

/// 20.16 errors a connected UDP socket reports for a single datagram: ICMP errors from the peer or
/// path (stored in sk_err, reported once by the next send/recv, then cleared), no buffer memory,
/// datagram too big for the path, a local firewall drop. The socket stays usable.
pub fn udp_soft_error(e: i32) -> bool {
    matches!(
        e,
        libc::ECONNREFUSED
            | libc::EHOSTUNREACH
            | libc::ENETUNREACH
            | libc::EHOSTDOWN
            | libc::ENETDOWN
            | libc::EPROTO
            | libc::EMSGSIZE
            | libc::ENOBUFS
            | libc::ENOMEM
            | libc::EPERM
            | libc::EACCES
            | libc::EINTR
    )
}

/// Bytes in the socket send queue not yet acknowledged by the peer (SIOCOUTQ). -1 on error.
pub fn outq(fd: RawFd) -> i32 {
    let mut n: libc::c_int = 0;
    if unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut n) } < 0 {
        return -1;
    }
    n
}

/// 20.26 unsent bytes in the send queue (SIOCOUTQNSD; SIOCOUTQ also counts sent-but-unacked)
pub fn outq_unsent(fd: RawFd) -> i32 {
    const SIOCOUTQNSD: libc::c_ulong = 0x894B; // linux sockios.h
    let mut v: libc::c_int = 0;
    if unsafe { libc::ioctl(fd, SIOCOUTQNSD as _, &mut v) } != 0 {
        return 0;
    }
    v
}

/// 20.26 bytes in the receive queue (SIOCINQ = FIONREAD). 0 on error.
pub fn inq(fd: RawFd) -> usize {
    let mut v: libc::c_int = 0;
    if unsafe { libc::ioctl(fd, libc::FIONREAD, &mut v) } != 0 {
        return 0;
    }
    v.max(0) as usize
}

/// True if the socket's read position is at the TCP urgent mark (SIOCATMARK).
pub fn at_mark(fd: RawFd) -> bool {
    let mut v: libc::c_int = 0;
    const SIOCATMARK: libc::c_ulong = 0x8905; // linux asm-generic/sockios.h (not exported by libc)
    unsafe { libc::ioctl(fd, SIOCATMARK as _, &mut v) == 0 && v != 0 }
}

/// Make the next close() send RST instead of FIN (no TIME_WAIT).
pub fn linger_zero(fd: RawFd) {
    let l = libc::linger { l_onoff: 1, l_linger: 0 };
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_LINGER, &l as *const _ as *const _, size_of::<libc::linger>() as _) };
}

pub fn so_error(fd: RawFd) -> i32 {
    let mut e: libc::c_int = 0;
    let mut l = size_of::<libc::c_int>() as libc::socklen_t;
    unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut e as *mut _ as *mut _, &mut l) };
    e
}

/// 70.13 Wisp close reason for a read/write error on an open target: a TCP timeout (keepalive or
/// retransmission) = 0x47 "TCP data transfer timed out", anything else (ECONNRESET, EPIPE, ...) 0x03
/// network error. The timeout reports the last soft error if an ICMP error came meanwhile
/// (tcp_write_err: sk_err_soft ?: ETIMEDOUT); without IP_RECVERR/IPV6_RECVERR an open socket gets the
/// icmp_err_convert / icmpv6_err_convert errnos (and EMSGSIZE from a PMTU drop) only that way
/// (ECONNREFUSED from a reset is SYN_SENT only, consumed by connect_state).
pub fn data_reason(e: i32) -> u8 {
    match e {
        libc::ETIMEDOUT
        | libc::EHOSTUNREACH
        | libc::ENETUNREACH
        | libc::ECONNREFUSED
        | libc::EACCES
        | libc::EHOSTDOWN
        | libc::ENONET
        | libc::ENOPROTOOPT
        | libc::EOPNOTSUPP
        | libc::EPROTO
        | libc::EMSGSIZE => 0x47,
        _ => 0x03,
    }
}

/// Map a connect errno to a Wisp close reason.
pub fn connect_reason(e: i32) -> u8 {
    match e {
        libc::ECONNREFUSED => 0x44,
        libc::ETIMEDOUT => 0x43,
        libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EADDRNOTAVAIL => 0x42,
        _ => 0x03,
    }
}

/// The address rules (every resolved address, both filter sites: Worker::start_connect and dns_late). 60.20 C1: the
/// classes are bits, each lifted by its own flag; the CIDR lists and the own-address set come with the policy (60.21).
#[derive(Clone)]
pub struct Filter {
    pub allow_loopback: bool,
    pub allow_private: bool,
    /// 60.20 C1 / Q2 --allow-embedded-v4: IPv6 forms that carry or reach an IPv4 address (class EMB)
    pub allow_embedded: bool,
    /// 60.20 C1 / Q2 --allow-self: the server's own interface addresses (`own`)
    pub allow_self: bool,
    /// --no-ipv6-targets clears it: IPv6 addresses are dropped (an IPv4-mapped one counts as IPv4)
    pub ipv6: bool,
    /// startup snapshot of the interface addresses, loopback-class ones left out (--allow-loopback governs those)
    pub own: Box<[IpAddr]>,
    pub allow_dests: Box<[crate::policy::Cidr]>,
    pub block_dests: Box<[crate::policy::Cidr]>,
}

/// address classes (bits): loopback-like, private / reserved, an IPv6 form embedding or reaching IPv4
const LOOP: u8 = 1;
const PRIV: u8 = 2;
const EMB: u8 = 4;

fn v4_class(a: Ipv4Addr) -> u8 {
    let o = a.octets();
    // 0.0.0.0/8 is loopback-like: connect() to 0.0.0.0 reaches the local host on Linux
    let loop_like = a.is_loopback() || o[0] == 0;
    let private = a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
        || o[0] >= 240
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18);
    (loop_like as u8 * LOOP) | (private as u8 * PRIV)
}

/// 60.21 (PENDING USER, parent's proposal is the default): the NAT64 well-known prefix 64:ff9b::/96 is judged by the
/// IPv4 address it carries, like ::ffff:0:0/96 (an IPv6-only box with DNS64 gets every IPv4 target in this form). false =
/// treat it as the other embedding forms (blocked unless --allow-embedded-v4). The one line that decides: v6_class_with.
const NAT64_WKP_BY_V4: bool = true;

fn v6_class(a: Ipv6Addr) -> u8 {
    v6_class_with(a, NAT64_WKP_BY_V4)
}

fn v6_class_with(a: Ipv6Addr, nat64_wkp_by_v4: bool) -> u8 {
    if let Some(v4) = a.to_ipv4_mapped() {
        return v4_class(v4);
    }
    let s = a.segments();
    let v4 = |hi: u16, lo: u16| v4_class(Ipv4Addr::from((hi as u32) << 16 | lo as u32));
    if s[..6] == [0; 6] {
        if s[6] == 0 && s[7] <= 1 {
            return LOOP; // :: and ::1 (connect to :: reaches the local host), not an embedding
        }
        return EMB | v4(s[6], s[7]); // ::/96 IPv4-compatible (70.04: the v4 decides once embedding is allowed)
    }
    if s[0] == 0x2002 {
        return EMB | v4(s[1], s[2]); // 6to4: the v4 is segments 1-2
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return if nat64_wkp_by_v4 { v4(s[6], s[7]) } else { EMB | v4(s[6], s[7]) };
        // 64:ff9b::/96 (see NAT64_WKP_BY_V4)
    }
    if (s[0] == 0x64 && s[1] == 0xff9b) || (s[0] == 0x2001 && s[1] == 0) {
        // the rest of 64:ff9b::/32 (local-use NAT64 64:ff9b:1::/48: the v4's position depends on the operator's prefix
        // length) and Teredo 2001::/32 (the v4s are obfuscated): cannot be checked, so private as well
        return EMB | PRIV;
    }
    let loop_like = a.is_loopback() || a.is_unspecified();
    let private = (s[0] & 0xfe00) == 0xfc00 // ULA
        || (s[0] & 0xffc0) == 0xfe80 // link-local
        || (s[0] & 0xffc0) == 0xfec0 // 60.20 C1 site-local (deprecated, still routable on Linux)
        || (s[0] & 0xff00) == 0xff00 // multicast
        || s[..4] == [0x100, 0, 0, 0]; // 60.20 C1 discard-only 100::/64
    (loop_like as u8 * LOOP) | (private as u8 * PRIV)
}

/// The IPv4 address an IPv6 form carries in a checkable place (mapped, ::/96, 6to4, NAT64 well-known prefix): the
/// own-address check looks through these too (64:ff9b::<our IPv4> reaches us through the NAT64 gateway).
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = a.segments();
    let v4 = |hi: u16, lo: u16| Some(Ipv4Addr::from((hi as u32) << 16 | lo as u32));
    if let Some(v) = a.to_ipv4_mapped() {
        Some(v)
    } else if s[..6] == [0; 6] || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        v4(s[6], s[7])
    } else if s[0] == 0x2002 {
        v4(s[1], s[2])
    } else {
        None
    }
}

fn class(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(a) => v4_class(a),
        IpAddr::V6(a) => v6_class(a),
    }
}

/// 60.58 a client address that is a proxy or a bridge in front of many users, not one client: loopback, private,
/// CGNAT, link-local and the other reserved ranges, and the unix-socket peer (100::). For --dns-share such an address
/// is no group: its connections count one by one (60.57 C, the same rule: the server cannot tell the users behind it apart).
pub fn shared_addr(ip: IpAddr) -> bool {
    class(crate::clientip::canon(ip)) & (LOOP | PRIV) != 0
}

/// 60.57 C a client address that is loopback, private, link-local, CGNAT or otherwise not a public unicast address
/// (the classes the SSRF guard knows): a proxy or a bridge in front of many users, never gated by --conn-share
pub fn local_peer(ip: IpAddr) -> bool {
    class(ip) & (LOOP | PRIV) != 0
}

impl Filter {
    /// The base-4 flags only; the C1 parts at their defaults (classes blocked, IPv6 on, no lists, no own addresses).
    pub fn new(allow_loopback: bool, allow_private: bool) -> Filter {
        Filter {
            allow_loopback,
            allow_private,
            allow_embedded: false,
            allow_self: false,
            ipv6: true,
            own: Box::default(),
            allow_dests: Box::default(),
            block_dests: Box::default(),
        }
    }

    /// Order (60.21): --block-dest, then --no-ipv6-targets, then --allow-dest (an explicit CIDR beats every class), then
    /// the classes, then the own addresses. Name allows never lift any of this (rebinding).
    pub fn allowed(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        // review: an IPv4 --block-dest also covers the checkable IPv6 forms of that address (NAT64 WKP, ::/96, 6to4)
        let emb = match ip {
            IpAddr::V6(a) => embedded_v4(a).map(IpAddr::V4),
            _ => None,
        };
        if self.block_dests.iter().any(|c| c.contains(ip) || emb.is_some_and(|e| c.contains(e))) || (!self.ipv6 && ip.is_ipv6()) {
            return false;
        }
        if self.allow_dests.iter().any(|c| c.contains(ip)) {
            return true;
        }
        let c = class(ip);
        if (c & LOOP != 0 && !self.allow_loopback) || (c & PRIV != 0 && !self.allow_private) || (c & EMB != 0 && !self.allow_embedded) {
            return false;
        }
        self.allow_self || !self.is_own(ip, emb)
    }

    /// 60.35 C4 --log-streams: the rule that refuses `ip` (`rule=`), None = allowed. A mirror of `allowed` for the log
    /// path only (equal to `!allowed`: unit test, policy-host fuzz target).
    pub fn refusal(&self, ip: IpAddr) -> Option<&'static str> {
        let ip = match ip {
            IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        let emb = match ip {
            IpAddr::V6(a) => embedded_v4(a).map(IpAddr::V4),
            _ => None,
        };
        if self.block_dests.iter().any(|c| c.contains(ip) || emb.is_some_and(|e| c.contains(e))) {
            return Some("block_dest");
        }
        if !self.ipv6 && ip.is_ipv6() {
            return Some("ipv6");
        }
        if self.allow_dests.iter().any(|c| c.contains(ip)) {
            return None;
        }
        let c = class(ip);
        if c & LOOP != 0 && !self.allow_loopback {
            return Some("loopback");
        }
        if c & PRIV != 0 && !self.allow_private {
            return Some("private");
        }
        if c & EMB != 0 && !self.allow_embedded {
            return Some("embedded_v4");
        }
        (!self.allow_self && self.is_own(ip, emb)).then_some("own")
    }

    fn is_own(&self, ip: IpAddr, emb: Option<IpAddr>) -> bool {
        self.own.iter().any(|o| *o == ip || Some(*o) == emb)
    }
}

/// 60.20 C1 / Q2 (decision c): the interface addresses at startup (getifaddrs), minus loopback-class ones. A public
/// address that is not on an interface (cloud 1:1 NAT, an EC2 elastic IP) is not here: --block-dest it. Err: getifaddrs
/// failed (main refuses to start without --allow-self: an empty set would silently drop the protection).
pub fn own_addrs() -> std::io::Result<Vec<IpAddr>> {
    let mut out = Vec::new();
    let mut ifa: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifa) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut p = ifa;
    // SAFETY: getifaddrs succeeded, so ifa is a valid list until freeifaddrs (after the loop); ifa_addr is
    // null-checked and points to the sockaddr type given by its family.
    while !p.is_null() {
        let i = unsafe { &*p };
        if !i.ifa_addr.is_null() {
            let ip = match unsafe { (*i.ifa_addr).sa_family } as i32 {
                libc::AF_INET => {
                    let sa = unsafe { &*(i.ifa_addr as *const libc::sockaddr_in) };
                    Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))))
                }
                libc::AF_INET6 => {
                    let sa = unsafe { &*(i.ifa_addr as *const libc::sockaddr_in6) };
                    Some(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)))
                }
                _ => None,
            };
            if let Some(ip) = ip.filter(|ip| class(*ip) & LOOP == 0 && !out.contains(ip)) {
                out.push(ip);
            }
        }
        p = i.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifa) };
    Ok(out)
}

/// 60.20 C3a `--max-conns`: one process-wide connection reservation. The worker that accepts reserves (before
/// --balance hands the fd on); the worker that owns the client releases it where its `Inbox.load` drops
/// (Worker::unload), so a handed-over fd keeps its reservation. Exact (a CAS, not a sum of the per-worker loads,
/// which is not a snapshot: two workers could both see room).
pub struct ConnGate {
    pub max: u32,
    used: std::sync::atomic::AtomicU32,
}

impl ConnGate {
    pub fn new(max: u32) -> ConnGate {
        ConnGate { max, used: Default::default() }
    }
    /// take one slot; false = full
    pub fn try_reserve(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let mut u = self.used.load(Relaxed);
        while u < self.max {
            match self.used.compare_exchange_weak(u, u + 1, Relaxed, Relaxed) {
                Ok(_) => return true,
                Err(now) => u = now,
            }
        }
        false
    }
    pub fn release(&self) {
        let prev = self.used.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        debug_assert!(prev > 0, "ConnGate released more often than reserved");
    }
    pub fn used(&self) -> u32 {
        self.used.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ---- DNS: a small shared thread pool doing getaddrinfo; results go back to the
// owning worker through its inbox + eventfd. Workers cache results.

pub struct DnsReq {
    pub host: String,
    pub token: u64,
    pub inbox: Arc<Inbox>,
    /// 70.09 admission time: the own resolver's deadline counts from here (time in the queue too)
    pub at: std::time::Instant,
    /// 60.58 who asks (read only with --dns-share): the connection, and its per-address key (None: no peer address known)
    pub conn: DnsConn,
    pub key: Option<crate::clientip::IpKey>,
}

/// 60.58 a client connection as the DNS pool sees it: worker index, client slot, slot generation
pub type DnsConn = (u32, u32, u32);

pub struct DnsResp {
    pub host: String,
    pub token: u64,
    pub addrs: Vec<IpAddr>,
    /// 20.23 empty `addrs` because the name has no address (NXDOMAIN / no A or AAAA): cacheable
    pub nx: bool,
    /// 70.10 (--dns-own only) an early answer: one family's addresses, the other family is still being asked. At most one
    /// per request, always followed by the final response (more = false), which alone counts for dns_inflight, the
    /// dns_live token and the cache.
    pub more: bool,
}

/// 60.18 #16 the name getaddrinfo gets for a client's host: absolute (`name.`), so glibc never completes it with the
/// resolv.conf search list (a short `wiki` must not reach `wiki.<search domain>`, which --block-host never saw).
/// Only what glibc converts numerically stays as it is (a trailing dot would make it a DNS query): an inet_aton form
/// (`127.1`, `0x7f000001`, `0177.0.0.1`) or anything with ':' (IPv6, `ADDR%scope`). Review (review): not
/// policy::is_ip_literal, which also counts `node.7` (a numeric last label) and would leave that name relative.
pub fn gai_name(host: &str) -> std::borrow::Cow<'_, str> {
    if host.ends_with('.') || host.contains(':') || inet_aton_ok(host) {
        host.into()
    } else {
        format!("{host}.").into()
    }
}

/// 60.18 #16 /etc/hosts addresses for the pool, as glibc's files backend gives them: mapped addresses as IPv4; with
/// `v4_only` (AF_INET) only IPv4, where `::1` counts as 127.0.0.1 (glibc files-hosts, review).
fn hosts_family(a: Vec<IpAddr>, v4_only: bool) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::with_capacity(a.len());
    for ip in a.into_iter().map(|ip| ip.to_canonical()) {
        let ip = match ip {
            IpAddr::V6(v6) if v4_only && v6.is_loopback() => IpAddr::from([127, 0, 0, 1]),
            ip => ip,
        };
        if (!v4_only || ip.is_ipv4()) && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// glibc's numeric IPv4 parse (the one getaddrinfo tries before NSS). The callers' names hold no space (valid_host),
/// so the public inet_aton (which stops at whitespace) gives the same answer as glibc's internal exact form.
fn inet_aton_ok(host: &str) -> bool {
    unsafe extern "C" {
        fn inet_aton(cp: *const libc::c_char, inp: *mut libc::in_addr) -> libc::c_int;
    }
    let Ok(c) = std::ffi::CString::new(host) else { return false };
    let mut a: libc::in_addr = unsafe { zeroed() };
    unsafe { inet_aton(c.as_ptr(), &mut a) != 0 }
}

/// 20.23 getaddrinfo that keeps the error kind (std's to_socket_addrs folds every failure into one
/// io::Error). Err(true) = definitive: EAI_NONAME (NXDOMAIN). Err(false) = anything else, never cached:
/// EAI_AGAIN (timeout/SERVFAIL), EAI_FAIL, EAI_SYSTEM, NUL in the name, a name over 255 bytes, and
/// EAI_NODATA (review: glibc can report NODATA when one of the parallel A/AAAA queries SERVFAILed). Same hints as std: any family, SOCK_STREAM (one entry per address); `v4_only` (60.20 C1
/// --no-ipv6-targets): AF_INET, so glibc sends no AAAA query.
pub fn lookup(host: &str, v4_only: bool) -> Result<Vec<IpAddr>, bool> {
    if host.len() > 255 {
        return Err(false);
    }
    let Ok(name) = std::ffi::CString::new(gai_name(host).into_owned()) else { return Err(false) };
    let mut hints: libc::addrinfo = unsafe { zeroed() };
    hints.ai_socktype = libc::SOCK_STREAM;
    if v4_only {
        hints.ai_family = libc::AF_INET; // 60.20 C1 --no-ipv6-targets: no AAAA query
    }
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let r = unsafe { libc::getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if r != 0 {
        return Err(r == libc::EAI_NONAME);
    }
    let mut out = Vec::new();
    let mut p = res;
    // SAFETY: getaddrinfo succeeded, so res is a valid list until freeaddrinfo (after the loop); each
    // ai_addr is non-null-checked and points to the sockaddr type given by ai_family.
    while !p.is_null() {
        let ai = unsafe { &*p };
        if ai.ai_family == libc::AF_INET && !ai.ai_addr.is_null() {
            let sa = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
            out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))));
        } else if ai.ai_family == libc::AF_INET6 && !ai.ai_addr.is_null() {
            let sa = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in6) };
            out.push(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)));
        }
        p = ai.ai_next;
    }
    unsafe { libc::freeaddrinfo(res) };
    if out.is_empty() {
        return Err(false);
    }
    Ok(out)
}

pub struct Inbox {
    pub efd: RawFd,
    pub q: Mutex<Vec<DnsResp>>,
    /// 20.10 accepted client fds handed over by another worker (accept balancing), with what travels with them
    pub fds: Mutex<Vec<Handoff>>,
    /// live clients owned by this worker (incl. handed-over fds not yet adopted)
    pub load: std::sync::atomic::AtomicUsize,
    /// 70.09 --dns-own: tokens of requests whose answer is still wanted. The worker adds one before sending the
    /// request and removes it when the answer arrives or the target closes (= cancel); a lookup whose waiters are
    /// all gone stops. Holds at most this worker's in-flight requests.
    pub dns_live: Mutex<std::collections::HashSet<u64>>,
    /// 60.12 graceful shutdown, set by main (signal loop) before it wakes the worker: 0 run, STOP_DRAIN (accept what
    /// is queued, close the listener, close idle Wisp connections), STOP_CLOSE (close every connection).
    pub stop: std::sync::atomic::AtomicU8,
    /// 60.12 set by the worker once its listener is closed (every connection it accepted is in `load` by then)
    pub stopped: std::sync::atomic::AtomicBool,
}
pub const STOP_DRAIN: u8 = 1;
pub const STOP_CLOSE: u8 = 2;

impl Inbox {
    pub fn new() -> Arc<Inbox> {
        let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(efd >= 0, "eventfd failed");
        Arc::new(Inbox {
            efd,
            q: Mutex::new(Vec::new()),
            fds: Mutex::new(Vec::new()),
            load: Default::default(),
            dns_live: Default::default(),
            stop: Default::default(),
            stopped: Default::default(),
        })
    }
    pub fn wake(&self) {
        let one = 1u64;
        unsafe { libc::write(self.efd, &one as *const _ as *const _, 8) };
    }
    /// Consume the wakeup, then take everything queued (anything pushed later re-arms the eventfd).
    pub fn drain(&self) -> (Vec<DnsResp>, Vec<Handoff>) {
        let mut v = 0u64;
        unsafe { libc::read(self.efd, &mut v as *mut _ as *mut _, 8) };
        let dns = std::mem::take(&mut *self.q.lock().unwrap());
        let fds = std::mem::take(&mut *self.fds.lock().unwrap());
        (dns, fds)
    }
    pub fn push_fd(&self, h: Handoff) {
        self.fds.lock().unwrap().push(h);
        self.wake();
    }
}

/// 60.20 an accepted client fd and what the accepting worker learned about it (the one push_fd payload for C2/C3b and
/// C7's listener kind): the peer IP (when C2/C3b are on) and the per-IP key it charged (the adopting worker
/// releases that key, like the --max-conns reservation).
#[derive(Debug, Clone, Copy)]
pub struct Handoff {
    pub fd: RawFd,
    pub peer: Option<IpAddr>,
    pub key: Option<crate::clientip::IpKey>,
    /// 60.31 C7 the listener it came from: L_* bits (0 = the TCP listener without PROXY protocol); 60.34 L_PROXY
    pub kind: u8,
}

/// 60.31 C7 Handoff::kind: accepted on the unix listener
pub const L_UNIX: u8 = 1;
/// 60.34 Handoff::kind: accepted on a --proxy-protocol listener (the header is still to come)
pub const L_PROXY: u8 = 2;

impl Handoff {
    pub fn bare(fd: RawFd) -> Handoff {
        Handoff { fd, peer: None, key: None, kind: 0 }
    }
}

/// 60.31 C7 the unix listener (--listen-unix): one listening fd for all workers (AF_UNIX has no SO_REUSEPORT groups),
/// in every worker's epoll with EPOLLEXCLUSIVE. `left` = workers that still hold it; the last one to let go removes the
/// path (only if it is still our file) and closes the fd (release). `lock` = the PATH.lock fd, held (flock) for the life
/// of the process: a second instance on the same path refuses to start.
pub struct UnixListen {
    pub fd: RawFd,
    pub path: std::path::PathBuf,
    pub left: std::sync::atomic::AtomicUsize,
    id: Option<(u64, u64)>,
    _lock: std::fs::File,
}

impl UnixListen {
    /// A worker lets go of the listener (it already removed it from its epoll). The last one: unlink first, and only if
    /// the path is still the file we bound (dev, ino: a newer instance may have replaced it), then close (60.28 review:
    /// closing first would let a new instance judge the file stale, bind, and then lose its file to our unlink).
    pub fn release(&self) {
        if self.left.fetch_sub(1, std::sync::atomic::Ordering::AcqRel) == 1 {
            if self.id.is_some() && file_id(&self.path) == self.id {
                let _ = std::fs::remove_file(&self.path);
            }
            unsafe { libc::close(self.fd) };
        }
    }
}

/// (dev, ino) of a path, not following a symlink
fn file_id(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// 60.31 C7 bind and listen on a unix stream socket at `path` with permissions `mode`, for `holders` workers. Steps:
/// 1. `PATH.lock` (created 0600 if missing, never removed) is flocked for the life of the process: a second instance
///    on this path fails here, so the steps below never race another finalwisp;
/// 2. an existing path: not a socket = error; a socket that accepts a non-blocking connect() (or whose backlog is full,
///    EAGAIN) = a live server (error; the probe is a real zero-byte connection to it); ECONNREFUSED = stale, removed
///    (known limit, review: a socket another program has bound but not yet listen()ed on also refuses, and is removed;
///    the flock only orders finalwisp instances, so give --listen-unix a path no other program uses);
/// 3. socket (SOCK_NONBLOCK: a worker that loses the EPOLLEXCLUSIVE race must get EAGAIN), bind under
///    umask(!mode & 0777) so the file is created with exactly `mode` (no chmod: it would follow a symlink swapped in at
///    the path), the old umask restored right after bind; listen(4096).
///
/// umask is process-wide: main calls this before any other thread exists.
pub fn listen_unix(path: &std::path::Path, mode: u32, holders: usize) -> io::Result<UnixListen> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _};
    let bytes = path.as_os_str().as_bytes();
    let mut sa: libc::sockaddr_un = unsafe { zeroed() };
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= sa.sun_path.len() {
        let max = sa.sun_path.len() - 1;
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not a usable socket path (1-{max} bytes, no NUL)")));
    }
    sa.sun_family = libc::AF_UNIX as _;
    for (d, s) in sa.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let len = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|e| io::Error::new(e.kind(), format!("lock file {}: {e}", std::path::Path::new(&lock_path).display())))?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let e = io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            io::Error::new(io::ErrorKind::AddrInUse, "another finalwisp holds this path (its .lock file is locked)")
        } else {
            io::Error::new(e.kind(), format!("flock on the .lock file: {e}"))
        });
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_socket() => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "exists and is not a socket")),
        Ok(_) => match probe_unix(&sa, len) {
            libc::ECONNREFUSED => std::fs::remove_file(path)?, // stale: nothing listens on it (see 2. above)
            0 | libc::EAGAIN => return Err(io::Error::new(io::ErrorKind::AddrInUse, "a server is accepting on it")),
            e => {
                let e = io::Error::from_raw_os_error(e);
                return Err(io::Error::new(e.kind(), format!("exists, and connect() to it failed: {e}")));
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let old = libc::umask(!(mode as libc::mode_t) & 0o777);
        let r = libc::bind(fd, &sa as *const _ as *const _, len);
        let e = io::Error::last_os_error();
        libc::umask(old);
        if r < 0 {
            libc::close(fd);
            return Err(e);
        }
        let id = file_id(path);
        if libc::listen(fd, 4096) < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        Ok(UnixListen { fd, path: path.to_owned(), left: std::sync::atomic::AtomicUsize::new(holders.max(1)), id, _lock: lock })
    }
}

/// connect() a fresh non-blocking unix socket to `sa`: 0 = connected (a live server), else the errno
fn probe_unix(sa: &libc::sockaddr_un, len: libc::socklen_t) -> i32 {
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return errno();
        }
        let r = if libc::connect(fd, sa as *const _ as *const _, len) == 0 { 0 } else { errno() };
        libc::close(fd);
        r
    }
}

/// The IP of an accept4 / getpeername sockaddr (IPv4-mapped IPv6 as IPv4), None for another family.
pub fn sockaddr_ip(ss: &libc::sockaddr_storage) -> Option<IpAddr> {
    match ss.ss_family as i32 {
        libc::AF_INET => {
            // SAFETY: the family says this storage holds a sockaddr_in
            let sa = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this storage holds a sockaddr_in6
            let sa = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            Some(crate::clientip::canon(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr))))
        }
        _ => None,
    }
}

/// 20.19 names being resolved right now -> the requests waiting for the same answer, and (70.10) the early answer
/// already handed out, for requests that join later.
type Waiters = (Vec<(u64, Arc<Inbox>)>, Option<Vec<IpAddr>>);
type InFlight = Mutex<std::collections::HashMap<String, Waiters>>;

/// 60.58 A6 `req` left the queue (a thread took it, it joined a running lookup of its name, or it expired): its time
/// since the send goes to its worker's wait counters. The pool threads are the only writers of these counters (the
/// worker never touches them, so its event loop keeps its code); a pool without the workers' Stats (tests) counts nothing.
fn waited(req: &DnsReq, cfg: &DnsSched) -> Option<()> {
    let st = cfg.stats.get(req.conn.0 as usize)?;
    let us = req.at.elapsed().as_micros().min(u64::MAX as u128) as u64;
    st.dns_wait_us.add_shared(us);
    st.dns_wait_ms_max.max_shared(us / 1000);
    Some(())
}

/// 20.19 `req` joins the lookup of its name that already runs (`e`: the in-flight entry): it gets the early answer if
/// one was handed out, and the final one from the thread that runs the lookup.
fn join(e: &mut Waiters, req: DnsReq, cfg: &DnsSched) {
    waited(&req, cfg);
    if let Some(a) = &e.1 {
        req.inbox.q.lock().unwrap().push(DnsResp { host: req.host, token: req.token, addrs: a.clone(), nx: false, more: true });
        req.inbox.wake();
    }
    e.0.push((req.token, req.inbox));
}

/// 60.58 a lookup that waited for a thread longer than `expire` (the connect timeout) is answered as failed without a
/// query. Before, on the getaddrinfo path (which has no deadline: the own resolver's counts from the send) a
/// request stayed queued, and counted against its worker's DNS_INFLIGHT_MAX, until a thread reached it: names that
/// never resolve at more than threads / 10 s filled the 1,024 of a worker within minutes, and from then on every
/// client of that worker got 0x49 for each new name.
fn expired(req: DnsReq, cfg: &DnsSched) {
    waited(&req, cfg);
    if let Some(st) = cfg.stats.get(req.conn.0 as usize) {
        st.dns_expired.add_shared(1);
    }
    req.inbox.q.lock().unwrap().push(DnsResp { host: req.host, token: req.token, addrs: Vec::new(), nx: false, more: false });
    req.inbox.wake();
}

/// 60.58 what the pool gets besides the resolver: the workers' Stats, the expiry of queued requests (see expired),
/// --dns-share (DnsShare decides the order; off = arrival order), and --dns-reserve (the reserve of DnsShare; main
/// sets `share` with it).
#[derive(Clone)]
pub struct DnsSched {
    /// the workers' Stats, by worker index (DnsReq::conn.0), for the wait counters (empty: not counted)
    pub stats: Arc<Vec<Arc<crate::metrics::Stats>>>,
    pub expire: std::time::Duration,
    pub share: bool,
    pub reserve: bool,
}

/// 60.58 who the rule counts as one: all connections of a public client address (DnsReq::key Some: clientip::key, an
/// IPv4 address or an IPv6 /64), or a connection alone (key None: no peer address, or a loopback / private /
/// link-local / unix peer, which is a proxy or a bridge in front of many users).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
enum Group {
    Addr(crate::clientip::IpKey),
    Conn(DnsConn),
}

/// 60.58 --dns-reserve: a lookup that runs this long makes its group slow, and the group stays slow for
/// DNS_RESERVE_HOLD after the lookup is back
const DNS_RESERVE_AGE: std::time::Duration = std::time::Duration::from_secs(1);
const DNS_RESERVE_HOLD: std::time::Duration = std::time::Duration::from_secs(60);

struct ShareConn {
    /// waiting lookups in arrival order, with their arrival number
    q: std::collections::VecDeque<(u64, DnsReq)>,
    /// start times of the running lookups charged to this connection
    run: Vec<std::time::Instant>,
    group: Group,
}

#[derive(Default)]
struct ShareGroup {
    /// (arrival number, connection) of the oldest waiting lookup of each of its connections that has one
    heads: std::collections::BTreeSet<(u64, DnsConn)>,
    run: Vec<std::time::Instant>,
    /// the reserve: slow (see DnsShare; always false without --dns-reserve) ...
    slow: bool,
    /// ... and at least until then, by a slow lookup that is back
    slow_until: Option<std::time::Instant>,
}

/// 60.58 --dns-share: the lookups that wait for a pool thread, and what the running ones are charged to. Rule: a
/// free thread takes the waiting lookup of the group (Group: a public client address, or a connection alone behind a
/// local address) that runs the fewest lookups, inside it of the connection that runs the fewest, and the oldest
/// among equals. Without the reserve there are no caps: a connection or an address alone takes every thread, and no
/// thread stays free while a lookup waits. So a new client waits for one thread to come back, however many lookups
/// others have queued; it does not wait less than that.
/// A running lookup is charged to the request the thread took (the first asker) until the thread is back, also when
/// that stream is gone by then. Requests that join it use no thread and are charged nothing.
/// --dns-reserve (cfg.reserve): a group is slow while one of its lookups has run for DNS_RESERVE_AGE and for
/// DNS_RESERVE_HOLD after such a lookup is back. All slow groups together run on at most slow_cap threads; the rest of
/// the pool is only for groups that are not slow, also when it is free and slow ones wait.
/// Only pool threads touch this (the workers send through the channel). Lock order: receiver -> DnsShare -> InFlight.
/// A pick costs O(log n) plus the groups and connections with a running lookup (at most one per thread): every group
/// keeps its connections' oldest lookups in order, and `oldest` keeps the groups in order, the slow ones apart, so a
/// pick never walks the groups it may not take.
struct DnsShare {
    seq: u64,
    waiting: usize,
    conns: std::collections::HashMap<DnsConn, ShareConn>,
    groups: std::collections::HashMap<Group, ShareGroup>,
    /// (the first of ShareGroup::heads, group) of every group that has a waiting lookup: [not slow, slow]
    oldest: [std::collections::BTreeSet<(u64, Group)>; 2],
    cfg: DnsSched,
    /// the reserve: the threads all slow groups may hold together (the pool less a quarter, at least 1)
    slow_cap: usize,
    /// the connections with a running lookup (at most one per thread)
    busy: Vec<DnsConn>,
    /// the reserve: when each ShareGroup::slow_until ends, in time order
    marks: std::collections::VecDeque<(std::time::Instant, Group)>,
    /// the reserve: the lookups started in the last DNS_RESERVE_AGE, in time order (the group is slow when one of
    /// them still runs after that time)
    started: std::collections::VecDeque<(std::time::Instant, Group)>,
}

/// 60.58 the threads that all slow groups may hold together with --dns-reserve: a quarter of the pool (at least one
/// thread) is kept from them, and they keep at least one. So 1 thread has no reserve.
pub fn dns_slow_cap(threads: usize) -> usize {
    threads.saturating_sub((threads / 4).max(1)).max(1)
}

impl DnsShare {
    fn new(threads: usize, cfg: DnsSched) -> DnsShare {
        DnsShare {
            seq: 0,
            waiting: 0,
            conns: Default::default(),
            groups: Default::default(),
            oldest: Default::default(),
            cfg,
            slow_cap: dns_slow_cap(threads),
            busy: Vec::new(),
            marks: Default::default(),
            started: Default::default(),
        }
    }

    /// `f` changes group `g` (its heads, its slow state); `oldest` follows, and a group with nothing waiting, nothing
    /// running and no slow state goes.
    fn group(&mut self, g: Group, f: impl FnOnce(&mut ShareGroup)) {
        let e = self.groups.entry(g).or_default();
        let before = (e.heads.first().map(|h| h.0), e.slow);
        f(e);
        let after = (e.heads.first().map(|h| h.0), e.slow);
        if before != after {
            if let Some(s) = before.0 {
                self.oldest[before.1 as usize].remove(&(s, g));
            }
            if let Some(s) = after.0 {
                self.oldest[after.1 as usize].insert((s, g));
            }
        }
        if e.heads.is_empty() && e.run.is_empty() && !e.slow {
            self.groups.remove(&g);
        }
    }

    /// A request from the channel: it joins the lookup of its name if one runs, else it waits.
    fn admit(&mut self, req: DnsReq, inflight: &InFlight) {
        // (review: as in arrival order, the expiry comes before the join; a request can sit in the channel for a whole
        // lookup time when every thread is in a lookup)
        if req.at.elapsed() >= self.cfg.expire {
            return expired(req, &self.cfg);
        }
        {
            let mut m = inflight.lock().unwrap();
            if let Some(e) = m.get_mut(&req.host) {
                return join(e, req, &self.cfg);
            }
        }
        self.seq += 1;
        self.waiting += 1;
        let (seq, conn) = (self.seq, req.conn);
        let c = self.conns.entry(conn).or_insert_with(|| ShareConn::of(&req));
        let (first, g) = (c.q.is_empty(), c.group);
        c.q.push_back((seq, req));
        if first {
            self.group(g, |e| {
                e.heads.insert((seq, conn));
            });
        }
    }

    /// The oldest waiting lookup of connection `conn` leaves the queue.
    fn pop(&mut self, conn: DnsConn) -> DnsReq {
        let c = self.conns.get_mut(&conn).expect("a head without its connection");
        let (seq, req) = c.q.pop_front().expect("a head without a lookup");
        let (next, g) = (c.q.front().map(|n| n.0), c.group);
        if c.q.is_empty() && c.run.is_empty() {
            self.conns.remove(&conn);
        }
        self.waiting -= 1;
        self.group(g, |e| {
            e.heads.remove(&(seq, conn));
            if let Some(n) = next {
                e.heads.insert((n, conn));
            }
        });
        req
    }

    /// The oldest waiting lookup of all: (the connection, when the request was made)
    fn first(&self) -> Option<(DnsConn, std::time::Instant)> {
        let (_, g) = self.oldest.iter().filter_map(|s| s.first()).min()?;
        let conn = self.groups[g].heads.first().expect("a group in `oldest` has a head").1;
        Some((conn, self.conns[&conn].q[0].1.at))
    }

    /// The reserve: do the slow groups together hold slow_cap threads? Then a slow group gets no further thread.
    fn lane_full(&self) -> bool {
        let held = |c: &DnsConn| {
            let c = &self.conns[c];
            if self.groups[&c.group].slow {
                c.run.len()
            } else {
                0
            }
        };
        self.cfg.reserve && self.busy.iter().map(held).sum::<usize>() >= self.slow_cap
    }

    /// The connection whose oldest waiting lookup a free thread takes now (the rule: see DnsShare; the slow state is
    /// that of the last `slow_now`). None: nothing waits, or (the reserve) only slow groups wait and their threads
    /// are in use.
    /// Cost: the groups and connections with a running lookup (at most one per thread) are looked at one by one; the
    /// others are found through the ordered sets.
    fn pick(&self) -> Option<DnsConn> {
        let full = self.lane_full();
        // 1. a group that runs nothing: the oldest lookup of such a group (in a full lane: of one that is not slow)
        let idle = |set: &std::collections::BTreeSet<(u64, Group)>| set.iter().find(|(_, g)| self.groups[g].run.is_empty()).copied();
        let sets = if full { &self.oldest[..1] } else { &self.oldest[..] };
        if let Some((_, g)) = sets.iter().filter_map(idle).min() {
            return self.groups[&g].heads.first().map(|h| h.1);
        }
        // 2. every waiting lookup's group runs something: the groups of the running connections, one by one
        // (lookups its group runs, lookups it runs, arrival) of the best waiting lookup so far
        let mut best: Option<((usize, usize, u64), DnsConn)> = None;
        let mut offer = |rank: (usize, usize, u64), conn: DnsConn| {
            if best.is_none_or(|b| rank < b.0) {
                best = Some((rank, conn));
            }
        };
        for (i, bc) in self.busy.iter().enumerate() {
            let c = &self.conns[bc];
            let (g, e) = (c.group, &self.groups[&c.group]);
            if full && e.slow {
                continue;
            }
            if let Some(head) = c.q.front() {
                offer((e.run.len(), c.run.len(), head.0), *bc);
            }
            // a connection of the same group with nothing running (once per group)
            if !self.busy[..i].iter().any(|o| self.conns[o].group == g) {
                if let Some(&(seq, conn)) = e.heads.iter().find(|(_, conn)| self.conns[conn].run.is_empty()) {
                    offer((e.run.len(), 0, seq), conn);
                }
            }
        }
        best.map(|b| b.1)
    }

    /// The next lookup for a free thread, charged to its connection and group (its start time: `now`). On the way,
    /// requests that waited longer than `expire` are answered as failed, and a picked request whose name runs by now
    /// joins that lookup (no thread).
    fn next(&mut self, inflight: &InFlight, now: std::time::Instant) -> Option<DnsReq> {
        self.slow_now(now);
        while let Some((conn, _)) = self.first().filter(|f| now.saturating_duration_since(f.1) >= self.cfg.expire) {
            let req = self.pop(conn);
            expired(req, &self.cfg);
        }
        while let Some(conn) = self.pick() {
            let req = self.pop(conn);
            // (review: the sweep above goes by arrival at the pool; workers stamp their requests before the send, so a
            // request a little older than the one in front of it can be past the expiry here)
            if now.saturating_duration_since(req.at) >= self.cfg.expire {
                expired(req, &self.cfg);
                continue;
            }
            let mut m = inflight.lock().unwrap();
            if let Some(e) = m.get_mut(&req.host) {
                join(e, req, &self.cfg);
                continue;
            }
            m.insert(req.host.clone(), (Vec::new(), None));
            drop(m);
            let c = self.conns.entry(conn).or_insert_with(|| ShareConn::of(&req));
            if c.run.is_empty() {
                self.busy.push(conn);
            }
            c.run.push(now);
            let g = c.group;
            if self.cfg.reserve {
                self.started.push_back((now, g));
            }
            self.group(g, |e| e.run.push(now));
            return Some(req);
        }
        None
    }

    /// The thread that ran a lookup of `conn` since `start` is back (at `now`).
    fn done(&mut self, conn: DnsConn, start: std::time::Instant, now: std::time::Instant) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        if let Some(i) = c.run.iter().position(|s| *s == start) {
            c.run.swap_remove(i);
        }
        if c.run.is_empty() {
            self.busy.retain(|b| *b != conn);
        }
        let g = c.group;
        if c.q.is_empty() && c.run.is_empty() {
            self.conns.remove(&conn);
        }
        // the reserve: the lookup was slow: its group stays slow for DNS_RESERVE_HOLD
        let mark = (self.cfg.reserve && now.saturating_duration_since(start) >= DNS_RESERVE_AGE).then(|| now + DNS_RESERVE_HOLD);
        if let Some(until) = mark {
            self.marks.push_back((until, g));
        }
        self.group(g, |e| {
            if let Some(i) = e.run.iter().position(|s| *s == start) {
                e.run.swap_remove(i);
            }
            if mark.is_some() {
                (e.slow, e.slow_until) = (true, mark);
            }
        });
    }

    /// The reserve: the slow state of every group as of `now` (nothing to do without it: both lists are empty). A
    /// group whose slow_until ended is slow no more, unless a lookup of it runs that long; a group with a lookup that
    /// has run for DNS_RESERVE_AGE is slow.
    fn slow_now(&mut self, now: std::time::Instant) {
        let old = |s: &std::time::Instant| now.saturating_duration_since(*s) >= DNS_RESERVE_AGE;
        while self.marks.front().is_some_and(|m| m.0 <= now) {
            let (_, g) = self.marks.pop_front().expect("checked");
            // (a later slow lookup of the group moved slow_until on: its own entry follows)
            if self.groups.get(&g).is_some_and(|e| e.slow_until.is_some_and(|u| u <= now)) {
                self.group(g, |e| (e.slow, e.slow_until) = (e.run.iter().any(old), None));
            }
        }
        while self.started.front().is_some_and(|s| old(&s.0)) {
            let (start, g) = self.started.pop_front().expect("checked");
            if self.groups.get(&g).is_some_and(|e| !e.slow && e.run.contains(&start)) {
                self.group(g, |e| e.slow = true);
            }
        }
    }

    /// The reserve: lookups wait though this thread is free (only slow groups wait, and their threads are in use).
    /// When to look again if no thread comes back and no request arrives before: a slow_until ends, or the oldest
    /// waiting lookup expires; and not later than DNS_RESERVE_HOLD from `now` (review: a thread that comes back while
    /// this one sleeps can set a slow_until, and none that is set after `now` ends before that). None: nothing waits.
    fn wake(&self, now: std::time::Instant) -> Option<std::time::Instant> {
        let expires = self.first()?.1.checked_add(self.cfg.expire);
        self.marks.front().map(|m| m.0).into_iter().chain(expires).chain([now + DNS_RESERVE_HOLD]).min()
    }
}

impl ShareConn {
    fn of(req: &DnsReq) -> ShareConn {
        ShareConn { q: Default::default(), run: Vec::new(), group: req.key.map_or(Group::Conn(req.conn), Group::Addr) }
    }
}

/// 60.58 the next request for a pool thread with --dns-share. `back`: the lookup this thread just finished.
/// Idle threads queue on the receiver lock; its holder blocks in recv, so a request that arrives is seen at once, and
/// a thread that comes back from a lookup picks without that lock (it only empties the channel if nobody holds it).
/// None: every sender is gone.
fn share_next(
    rx: &Mutex<mpsc::Receiver<DnsReq>>,
    share: &Mutex<DnsShare>,
    inflight: &InFlight,
    back: Option<(DnsConn, std::time::Instant)>,
) -> Option<(DnsReq, std::time::Instant)> {
    {
        let chan = rx.try_lock(); // (not held: a receiver in recv is emptying the channel)
        let mut sh = share.lock().unwrap();
        if let Some((conn, start)) = back {
            sh.done(conn, start, std::time::Instant::now());
        }
        if let Ok(chan) = &chan {
            while let Ok(r) = chan.try_recv() {
                sh.admit(r, inflight);
            }
        }
        let now = std::time::Instant::now();
        if let Some(r) = sh.next(inflight, now) {
            return Some((r, now));
        }
    }
    let chan = rx.lock().unwrap();
    loop {
        let wake = {
            let mut sh = share.lock().unwrap();
            while let Ok(r) = chan.try_recv() {
                sh.admit(r, inflight);
            }
            let now = std::time::Instant::now();
            if let Some(r) = sh.next(inflight, now) {
                return Some((r, now));
            }
            sh.wake(now) // (Some only with the reserve: without it nothing waits while a thread is free)
        };
        let got = match wake {
            // a thread that comes back picks on its own; this one looks again when the wait can end without one
            Some(at) => match chan.recv_timeout(at.saturating_duration_since(std::time::Instant::now())) {
                Ok(r) => Some(r),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            },
            None => Some(chan.recv().ok()?),
        };
        if let Some(r) = got {
            share.lock().unwrap().admit(r, inflight);
        }
    }
}

/// `threads` getaddrinfo workers shared by all event loops. Identical names in flight share one lookup
/// (20.19; always on since 60.18, --no-dns-coalesce removed): a page load opens several streams to one host before the first
/// answer is back, and the per-worker cache only knows answers. Measured with a 20 ms resolver: the
/// DNS phase of a page of 3 hosts x 6 streams 107 -> 23 ms, and one stalled name no longer blocks
/// every other lookup (6 streams to a 3 s name + one fast name: fast answered after 3,024 ms with 4
/// busy threads, 22 ms coalesced). Every waiter gets its own DnsResp (also for failures).
/// 70.09 `own`: resolve with dns.rs instead of getaddrinfo (deadline from admission, cancellable).
/// 60.27 C6 `early_on` false (an upstream proxy): no early answers (connects go to the proxy, not to an address family)
/// 60.58 `sched`: the expiry of queued requests, and --dns-share (DnsShare; off: arrival order, as before)
pub fn start_dns_pool(
    threads: usize,
    own: Option<Arc<crate::dns::Resolver>>,
    v4_only: bool,
    early_on: bool,
    sched: DnsSched,
) -> mpsc::Sender<DnsReq> {
    let (tx, rx) = mpsc::channel::<DnsReq>();
    let rx = Arc::new(Mutex::new(rx));
    let inflight: Arc<InFlight> = Default::default();
    let share = sched.share.then(|| Arc::new(Mutex::new(DnsShare::new(threads, sched.clone()))));
    // 60.18 #16 getaddrinfo gets absolute names (gai_name), and glibc matches no `name.` against /etc/hosts: hosts names
    // (Docker --add-host, Kubernetes hostAliases, local aliases) are looked up here first, as glibc's files-then-dns did
    let hosts = own.is_none().then(|| Arc::new(crate::dns::Resolver::new(Vec::new())));
    for i in 0..threads {
        let rx = rx.clone();
        let inflight = inflight.clone();
        let own = own.clone();
        let hosts = hosts.clone();
        let share = share.clone();
        let sched = sched.clone();
        std::thread::Builder::new()
            .name(format!("dns-{i}"))
            .spawn(move || {
                let mut back: Option<(DnsConn, std::time::Instant)> = None; // 60.58 the charge of the lookup just finished
                loop {
                    let req = match &share {
                        Some(sh) => {
                            // 60.58 --dns-share: the request is out of the queue, in `inflight` and charged
                            let Some((req, start)) = share_next(&rx, sh, &inflight, back.take()) else { return };
                            back = Some((req.conn, start));
                            req
                        }
                        None => {
                            let req = match rx.lock().unwrap().recv() {
                                Ok(r) => r,
                                Err(_) => return,
                            };
                            if req.at.elapsed() >= sched.expire {
                                expired(req, &sched); // 60.58
                                continue;
                            }
                            // (block: the in-flight lock is released before the lookup)
                            let mut m = inflight.lock().unwrap();
                            if let Some(e) = m.get_mut(&req.host) {
                                join(e, req, &sched);
                                continue; // the thread already resolving this name delivers to us too
                            }
                            m.insert(req.host.clone(), (Vec::new(), None));
                            req
                        }
                    };
                    // 60.58 A6
                    waited(&req, &sched);
                    // 70.09 cancel: every waiter's token has left its inbox's dns_live set. The check and
                    // the removal of the in-flight entry are one critical section, so a request arriving later starts
                    // a fresh lookup instead of joining one that is giving up.
                    let mut taken: Option<Vec<(u64, Arc<Inbox>)>> = None;
                    let res = match &own {
                        None => {
                            // an entry with no address of the asked family left falls through to DNS, as glibc's files
                            // backend reports NOTFOUND for that family (review)
                            let from_hosts = hosts.as_ref().and_then(|h| h.hosts_entry(&req.host)).map(|a| hosts_family(a, v4_only));
                            match from_hosts {
                                Some(a) if !a.is_empty() => Ok(a),
                                _ => lookup(&req.host, v4_only),
                            }
                        }
                        Some(r) => r.lookup(
                            &req.host,
                            req.at,
                            &mut || {
                                let live = |t: &u64, ib: &Inbox| ib.dns_live.lock().unwrap().contains(t);
                                if live(&req.token, &req.inbox) {
                                    return false;
                                }
                                let mut m = inflight.lock().unwrap();
                                if m.get(&req.host).is_some_and(|w| w.0.iter().any(|(t, ib)| live(t, ib))) {
                                    return false;
                                }
                                taken = Some(m.remove(&req.host).unwrap_or_default().0);
                                true
                            },
                            &mut |a: &[IpAddr]| {
                                if !early_on {
                                    return;
                                }
                                // 70.10 early answer: to this request and every waiter so far; later joiners get it on joining
                                let early = |token| DnsResp { host: req.host.clone(), token, addrs: a.to_vec(), nx: false, more: true };
                                req.inbox.q.lock().unwrap().push(early(req.token));
                                req.inbox.wake();
                                if let Some((waiters, e)) = inflight.lock().unwrap().get_mut(&req.host) {
                                    *e = Some(a.to_vec());
                                    for (token, inbox) in waiters.iter() {
                                        inbox.q.lock().unwrap().push(early(*token));
                                        inbox.wake();
                                    }
                                }
                            },
                        ),
                    };
                    let (addrs, nx) = match res {
                        Ok(a) => (a, false),
                        Err(nx) => (Vec::new(), nx),
                    };
                    let waiters = match taken {
                        Some(w) => w,
                        None => inflight.lock().unwrap().remove(&req.host).unwrap_or_default().0,
                    };
                    for (token, inbox) in waiters {
                        inbox.q.lock().unwrap().push(DnsResp { host: req.host.clone(), token, addrs: addrs.clone(), nx, more: false });
                        inbox.wake();
                    }
                    req.inbox.q.lock().unwrap().push(DnsResp { host: req.host, token: req.token, addrs, nx, more: false });
                    req.inbox.wake();
                }
            })
            .expect("spawn dns thread");
    }
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    /// 60.20 C3a: 4 threads racing on one gate never hold more than `max` slots at once, and end at 0
    #[test]
    fn conn_gate_is_exact_under_contention() {
        use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
        let g = Arc::new(ConnGate::new(3));
        let held = Arc::new(AtomicU32::new(0));
        let ts: Vec<_> = (0..4)
            .map(|_| {
                let (g, held) = (g.clone(), held.clone());
                std::thread::spawn(move || {
                    let mut got = 0u32;
                    for _ in 0..20_000 {
                        if g.try_reserve() {
                            got += 1;
                            assert!(held.fetch_add(1, SeqCst) < 3, "more than max held");
                            held.fetch_sub(1, SeqCst);
                            g.release();
                        }
                    }
                    got
                })
            })
            .collect();
        let total: u32 = ts.into_iter().map(|t| t.join().unwrap()).sum();
        assert!(total > 0);
        assert_eq!(g.used(), 0);
        assert!(!ConnGate::new(0).try_reserve(), "max 0 admits nothing (main uses None for off)");
    }
    /// 60.17: a live zero-window reader that lost 2 probe exchanges in a row (RC1 gold soak) is not gone; 3 unanswered
    /// probes or retransmissions in a row with no ACK for PEER_GONE_MS are gone
    #[test]
    fn peer_gone_needs_three_unanswered_probes() {
        let info = |retrans: u8, probes: u8, ack_ms: u32| {
            let mut b = [0u8; 64];
            b[2] = retrans;
            b[3] = probes;
            b[56..60].copy_from_slice(&ack_ms.to_ne_bytes());
            b
        };
        assert_eq!(gone_by(&info(0, 2, 330_000)), None, "2 lost probe exchanges of a live reader");
        assert_eq!(gone_by(&info(2, 0, 330_000)), None);
        assert_eq!(gone_by(&info(0, 3, 330_000)), Some(330_000));
        assert_eq!(gone_by(&info(3, 0, 150_000)), Some(150_000));
        assert_eq!(gone_by(&info(0, 5, 152_000)), Some(152_000), "a peer dead from the pause start: several probes by 150 s");
        assert_eq!(gone_by(&info(0, 9, PEER_GONE_MS - 1)), None, "ACK age below PEER_GONE_MS");
    }
    /// 60.18: coalescing is unconditional (--no-dns-coalesce removed): three requests for one name while its lookup is in
    /// flight cause one query per family at the server, and every requester gets its own final answer
    #[test]
    fn dns_pool_coalesces_identical_names() {
        // 60.58 with the queue in arrival order and with --dns-share
        dns_pool_coalesces_identical_names_with(false);
        dns_pool_coalesces_identical_names_with(true);
    }
    fn dns_pool_coalesces_identical_names_with(share: bool) {
        use std::net::UdpSocket;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        let srv = u.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let qn = queries.clone();
        std::thread::spawn(move || {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = u.recv_from(&mut b) {
                qn.fetch_add(1, Ordering::SeqCst);
                let q = b[..n].to_vec();
                let u2 = u.try_clone().unwrap();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(300)); // the other requests arrive meanwhile
                    let qend = 12 + q[12..].iter().position(|&x| x == 0).unwrap() + 1 + 4; // name, type, class
                    let is_a = q[qend - 4..qend - 2] == [0, 1];
                    let mut r = q[..qend].to_vec();
                    r[2..4].copy_from_slice(&[0x81, 0x80]); // response, RD, RA, NOERROR
                    r[6..8].copy_from_slice(&[0, is_a as u8]); // one A answer; AAAA: no data
                    r[8..12].fill(0);
                    if is_a {
                        r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 5]);
                    }
                    let _ = u2.send_to(&r, from);
                });
            }
        });
        let dir = std::env::temp_dir().join(format!("fw-net-coalesce-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("resolv.conf"), "options timeout:2 attempts:1\n").unwrap();
        std::fs::write(dir.join("hosts"), "").unwrap();
        let own = Arc::new(crate::dns::Resolver::with_paths(vec![srv], dir.join("resolv.conf"), dir.join("hosts")));
        let tx = start_dns_pool(3, Some(own), false, true, pool_mode(share));
        let inbox = Inbox::new();
        for token in 1..=3u64 {
            inbox.dns_live.lock().unwrap().insert(token); // the worker's side of the 70.09 cancel contract
            let req = DnsReq {
                host: "co.test".into(),
                token,
                inbox: inbox.clone(),
                at: std::time::Instant::now(),
                conn: who(token).0,
                key: who(token).1,
            };
            tx.send(req).unwrap();
        }
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let finals = || inbox.q.lock().unwrap().iter().filter(|r| !r.more).map(|r| (r.token, r.addrs.clone())).collect::<Vec<_>>();
        while finals().len() < 3 && std::time::Instant::now() < end {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut got = finals();
        got.sort();
        let want: Vec<IpAddr> = vec!["192.0.2.5".parse().unwrap()];
        assert_eq!(got, (1..=3).map(|t| (t, want.clone())).collect::<Vec<_>>(), "every requester answered");
        assert_eq!(queries.load(Ordering::SeqCst), 2, "one lookup (A + AAAA) for three requests");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn data_reason_maps_tcp_timeouts_to_0x47() {
        for e in [libc::ETIMEDOUT, libc::EHOSTUNREACH, libc::ENETUNREACH, libc::ECONNREFUSED, libc::EACCES] {
            assert_eq!(data_reason(e), 0x47);
        }
        for e in [libc::ECONNRESET, libc::EPIPE, libc::ECONNABORTED] {
            assert_eq!(data_reason(e), 0x03);
        }
    }

    #[test]
    fn he_prefer_demotes_a_lost_first_family() {
        use std::collections::HashMap;
        use std::time::{Duration, Instant};
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        let ttl = Duration::from_secs(300);
        let base = vec![p("::1"), p("1.1.1.1"), p("::2"), p("2.2.2.2")];
        let mut lost = HashMap::new();
        let mut v = base.clone();
        he_prefer(&mut v, &lost, ttl);
        assert_eq!(v, base); // nothing lost: resolver order
        lost.insert(p("::1"), Instant::now());
        he_prefer(&mut v, &lost, ttl);
        assert_eq!(v, vec![p("1.1.1.1"), p("::1"), p("2.2.2.2"), p("::2")]);
        lost.insert(p("1.1.1.1"), Instant::now()); // both families lost: keep the resolver order
        let mut w = base.clone();
        he_prefer(&mut w, &lost, ttl);
        assert_eq!(w, base);
        let mut old = HashMap::new(); // expired entry: ignored
        old.insert(p("::1"), Instant::now() - Duration::from_secs(301));
        let mut x = base.clone();
        he_prefer(&mut x, &old, ttl);
        assert_eq!(x, base);
        let mut one = vec![p("::1"), p("::2")]; // no other family: unchanged
        he_prefer(&mut one, &lost, ttl);
        assert_eq!(one, vec![p("::1"), p("::2")]);
    }
    #[test]
    fn hosts_family_as_glibc_files() {
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        let a = vec![p("::1"), p("::ffff:10.0.0.1"), p("2001:db8::1"), p("127.0.0.1")];
        assert_eq!(hosts_family(a.clone(), false), [p("::1"), p("10.0.0.1"), p("2001:db8::1"), p("127.0.0.1")]);
        assert_eq!(hosts_family(a, true), [p("127.0.0.1"), p("10.0.0.1")], "AF_INET: ::1 = 127.0.0.1, mapped = v4, deduped");
        assert!(hosts_family(vec![p("2001:db8::1")], true).is_empty(), "nothing left: the pool falls through to DNS");
    }

    #[test]
    fn gai_name_is_absolute_except_literals() {
        assert_eq!(gai_name("wiki"), "wiki.");
        assert_eq!(gai_name("example.com"), "example.com.");
        assert_eq!(gai_name("example.com."), "example.com.");
        for lit in ["127.1", "2130706433", "0x7f000001", "0177.0.0.1", "1.2.3.4", "::1", "fe80::1%eth0"] {
            assert_eq!(gai_name(lit), lit, "an IP literal stays numeric");
        }
        for name in ["node.7", "wiki.1", "1.2.3.4.5", "999.1", "a.0x", "256.1.1.1"] {
            assert_eq!(gai_name(name), format!("{name}."), "review: not numeric for glibc, so absolute");
        }
    }

    #[test]
    fn lookup_keeps_the_error_kind() {
        // review: no `localhost` here: getaddrinfo now gets `localhost.`, which only a DNS server answers (hosts names go
        // through the pool's /etc/hosts lookup, dns_pool tests); literals need no network
        assert_eq!(lookup("127.1", true), Ok(vec![p4()]), "60.20 C1 v4 only; an inet_aton form stays numeric");
        assert!(lookup("::1", true).is_err(), "a v6 literal has no v4 form");
        assert_eq!(lookup("127.0.0.1", false), Ok(vec![p4()]));
        assert_eq!(lookup("a\0b", false), Err(false)); // NUL: not cacheable
        assert_eq!(lookup(&"a".repeat(2000), false), Err(false)); // oversized: not cacheable (review 20.23)
        fn p4() -> IpAddr {
            "127.0.0.1".parse().unwrap()
        }
    }
    #[test]
    fn interleave_alternates_families_and_dedupes() {
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        let mut v = vec![p("::1"), p("::2"), p("::1"), p("1.1.1.1"), p("::3"), p("2.2.2.2"), p("3.3.3.3"), p("4.4.4.4")];
        interleave(&mut v);
        assert_eq!(v, vec![p("::1"), p("1.1.1.1"), p("::2"), p("2.2.2.2"), p("::3"), p("3.3.3.3"), p("4.4.4.4")]);
        let mut w = vec![p("1.1.1.1"), p("2.2.2.2"), p("::1")];
        interleave(&mut w);
        assert_eq!(w, vec![p("1.1.1.1"), p("::1"), p("2.2.2.2")]);
        let mut e: Vec<IpAddr> = vec![];
        interleave(&mut e);
        assert!(e.is_empty());
    }
    #[test]
    fn he_append_fills_the_untried_tail() {
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        let (a1, a2, a3, b1, b2) = (p("1.1.1.1"), p("2.2.2.2"), p("3.3.3.3"), p("::1"), p("::2"));
        let mut v = vec![a1, a2, a3];
        he_append(&mut v, 1, [b1, a2, b2]); // a1 tried: the tail starts with v6, alternates; a2 not twice
        assert_eq!(v, [a1, b1, a2, b2, a3]);
        let mut v = vec![a1];
        he_append(&mut v, 1, [b1, b2]); // every early address tried
        assert_eq!(v, [a1, b1, b2]);
        let mut v = vec![a1, a2];
        he_append(&mut v, 2, [a1, a2]); // nothing new
        assert_eq!(v, [a1, a2]);
        let mut v = vec![b1, a1];
        he_append(&mut v, 0, [a2]); // nothing tried yet: interleaved from the first address
        assert_eq!(v, [b1, a1, a2]);
    }
    #[test]
    fn connect_state_reports_success_and_refusal() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (fd, done, sent) = connect(&l.local_addr().unwrap(), None).unwrap();
        assert_eq!(sent, 0);
        let mut st = if done { Some((0, false)) } else { None };
        for _ in 0..200 {
            if st.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            st = connect_state(fd);
        }
        assert_eq!(st.map(|s| s.0), Some(0));
        unsafe { libc::close(fd) };
        let dead = {
            let x = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            x.local_addr().unwrap()
        }; // closed port
        match connect(&dead, None) {
            Err(e) => assert_eq!(e, libc::ECONNREFUSED),
            Ok((fd, _, _)) => {
                let mut st = None;
                for _ in 0..200 {
                    st = connect_state(fd);
                    if st.is_some() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                assert_eq!(st.map(|s| s.0), Some(libc::ECONNREFUSED));
                unsafe { libc::close(fd) };
            }
        }
    }
    #[test]
    fn at_mark_detects_urgent_data() {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tx = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut rx, _) = l.accept().unwrap();
        unsafe {
            libc::send(tx.as_raw_fd(), b"ab".as_ptr() as *const _, 2, 0);
            libc::send(tx.as_raw_fd(), b"!".as_ptr() as *const _, 1, libc::MSG_OOB);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!at_mark(rx.as_raw_fd()), "mark is after the 2 normal bytes");
        let mut b = [0u8; 2];
        rx.read_exact(&mut b).unwrap();
        assert!(at_mark(rx.as_raw_fd()), "read position reached the urgent mark");
    }
    #[test]
    fn udp_icmp_refusal_is_soft_and_socket_survives() {
        // 20.16: a connected UDP socket to a closed port gets ECONNREFUSED once (ICMP), then works
        let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port(); // now closed
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let fd = udp_connect(&addr).unwrap();
        let send = |b: &[u8]| unsafe { libc::send(fd, b.as_ptr() as *const _, b.len(), libc::MSG_DONTWAIT) };
        assert_eq!(send(b"x"), 1);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut buf = [0u8; 16];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, 16, libc::MSG_DONTWAIT) };
        assert!(n < 0 && errno() == libc::ECONNREFUSED && udp_soft_error(errno()));
        let peer = std::net::UdpSocket::bind(addr).unwrap();
        assert_eq!(send(b"hi"), 2);
        let (k, from) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..k], b"hi");
        peer.send_to(b"back", from).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, 16, libc::MSG_DONTWAIT) };
        assert_eq!(&buf[..n as usize], b"back");
        // only the connected peer's datagrams arrive
        let other = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mine = unsafe {
            let mut ss: libc::sockaddr_in = std::mem::zeroed();
            let mut l = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            libc::getsockname(fd, &mut ss as *mut _ as *mut _, &mut l);
            u16::from_be(ss.sin_port)
        };
        other.send_to(b"spoof", ("127.0.0.1", mine)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, 16, libc::MSG_DONTWAIT) };
        assert!(n < 0 && errno() == libc::EAGAIN);
        unsafe { libc::close(fd) };
        assert!(!udp_soft_error(libc::EBADF));
    }
    #[test]
    fn dns_coalescing_answers_every_waiter() {
        // 60.58 with the queue in arrival order and with --dns-share
        dns_coalescing_answers_every_waiter_with(false);
        dns_coalescing_answers_every_waiter_with(true);
    }
    fn dns_coalescing_answers_every_waiter_with(share: bool) {
        // 20.19: many requests for one name in flight -> one lookup, one DnsResp per request (also failures)
        let tx = start_dns_pool(2, None, false, true, pool_mode(share));
        let inbox = Inbox::new();
        for t in 0..20u64 {
            let (conn, key) = who(t);
            tx.send(DnsReq { host: "localhost".into(), token: t, inbox: inbox.clone(), at: std::time::Instant::now(), conn, key }).unwrap();
        }
        for t in 100..105u64 {
            let (conn, key) = who(t);
            tx.send(DnsReq {
                host: "does-not-exist.invalid".into(),
                token: t,
                inbox: inbox.clone(),
                at: std::time::Instant::now(),
                conn,
                key,
            })
            .unwrap();
        }
        let mut got = Vec::new();
        for _ in 0..400 {
            let (dns, _) = inbox.drain();
            got.extend(dns);
            if got.len() >= 25 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let mut tokens: Vec<u64> = got.iter().map(|r| r.token).collect();
        tokens.sort();
        assert_eq!(tokens, (0..20).chain(100..105).collect::<Vec<_>>());
        assert!(got.iter().filter(|r| r.token < 20).all(|r| !r.addrs.is_empty() && r.host == "localhost"));
        assert!(got.iter().filter(|r| r.token >= 100).all(|r| r.addrs.is_empty()));
        // 70.10 inert by default: getaddrinfo never answers early, so no response is `more` and nothing follows the final one
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(got.iter().all(|r| !r.more) && inbox.drain().0.is_empty());
    }
    #[test]
    fn own_dns_early_answer_reaches_every_waiter_once() {
        // 60.58 with the queue in arrival order and with --dns-share
        own_dns_early_answer_reaches_every_waiter_once_with(false);
        own_dns_early_answer_reaches_every_waiter_once_with(true);
    }
    fn own_dns_early_answer_reaches_every_waiter_once_with(share: bool) {
        // 70.10: A answered at once, AAAA never: every waiter gets one early answer (a joiner after it was sent gets it on
        // joining) and then exactly one final answer at the deadline (1 server x 1 s)
        use std::time::{Duration, Instant};
        let srv = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 1500];
            while let Ok((k, from)) = srv.recv_from(&mut b) {
                let q = &b[..k];
                let mut e = 12;
                while e < k && q[e] != 0 {
                    e += 1 + q[e] as usize;
                }
                if q.get(e + 1..e + 3) != Some(&[0, 1]) {
                    continue; // AAAA: never answered
                }
                let mut r = q[..2].to_vec();
                r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                r.extend_from_slice(&q[12..e + 5]);
                r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
                let _ = srv.send_to(&r, from);
            }
        });
        let dir = std::env::temp_dir().join(format!("fw-pool-early-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("r"), "options timeout:1 attempts:1\n").unwrap();
        let own = Arc::new(crate::dns::Resolver::with_paths(vec![addr], dir.join("r"), dir.join("h")));
        let tx = start_dns_pool(2, Some(own), false, true, pool_mode(share));
        let (a, b) = (Inbox::new(), Inbox::new());
        let send = |t: u64, ib: &Arc<Inbox>| {
            ib.dns_live.lock().unwrap().insert(t);
            let (conn, key) = who(t);
            tx.send(DnsReq { host: "v4.test".into(), token: t, inbox: ib.clone(), at: Instant::now(), conn, key }).unwrap();
        };
        let t0 = Instant::now();
        send(1, &a);
        std::thread::sleep(Duration::from_millis(300));
        let early_a = a.drain().0;
        send(2, &b); // joins after the early answer went out
        std::thread::sleep(Duration::from_millis(100));
        let early_b = b.drain().0;
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        for (e, t) in [(&early_a, 1), (&early_b, 2)] {
            assert_eq!(e.iter().map(|r| (r.token, r.more, r.addrs.clone())).collect::<Vec<_>>(), [(t, true, vec![ip])]);
        }
        let mut fin = Vec::new();
        for _ in 0..100 {
            fin.extend(a.drain().0);
            fin.extend(b.drain().0);
            if fin.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(t0.elapsed() >= Duration::from_millis(900), "the final answer waits for AAAA: {:?}", t0.elapsed());
        fin.sort_by_key(|r| r.token);
        assert_eq!(
            fin.iter().map(|r| (r.token, r.more, r.addrs.clone())).collect::<Vec<_>>(),
            [(1, false, vec![ip]), (2, false, vec![ip])]
        );
        std::thread::sleep(Duration::from_millis(100));
        assert!(a.drain().0.is_empty() && b.drain().0.is_empty());
    }
    #[test]
    fn own_dns_lookup_stops_when_every_waiter_cancelled() {
        // 60.58 with the queue in arrival order and with --dns-share
        own_dns_lookup_stops_when_every_waiter_cancelled_with(false);
        own_dns_lookup_stops_when_every_waiter_cancelled_with(true);
    }
    fn own_dns_lookup_stops_when_every_waiter_cancelled_with(share: bool) {
        // 70.09: two silent servers, window 1 s x 2 tries: a lookup runs 2 s unless its waiters cancel
        use std::time::{Duration, Instant};
        let silent: Vec<_> = (0..2).map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap()).collect();
        let dir = std::env::temp_dir().join(format!("fw-pool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("r"), "options timeout:1 attempts:1\n").unwrap();
        let servers = silent.iter().map(|s| s.local_addr().unwrap()).collect();
        let own = Arc::new(crate::dns::Resolver::with_paths(servers, dir.join("r"), dir.join("h")));
        let tx = start_dns_pool(2, Some(own), false, true, pool_mode(share));
        let (a, b) = (Inbox::new(), Inbox::new());
        let send = |host: &str, t: u64, ib: &Arc<Inbox>| {
            ib.dns_live.lock().unwrap().insert(t);
            let (conn, key) = who(t);
            tx.send(DnsReq { host: host.into(), token: t, inbox: ib.clone(), at: Instant::now(), conn, key }).unwrap();
        };
        let wait = |ib: &Arc<Inbox>, n: usize| {
            let mut got = Vec::new();
            for _ in 0..200 {
                got.extend(ib.drain().0);
                if got.len() >= n {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            got
        };
        // one waiter in each inbox for one name; only one cancels: the lookup keeps going for the other
        let t0 = Instant::now();
        send("x.test", 1, &a);
        send("x.test", 2, &b);
        std::thread::sleep(Duration::from_millis(100));
        a.dns_live.lock().unwrap().remove(&1);
        let got = wait(&b, 1);
        assert!(t0.elapsed() >= Duration::from_millis(1900), "ran to the deadline: {:?}", t0.elapsed());
        assert_eq!(got.iter().map(|r| (r.token, r.nx, r.addrs.len())).collect::<Vec<_>>(), [(2, false, 0)]);
        assert_eq!(wait(&a, 1).len(), 1, "the cancelled waiter still gets its answer");
        // both cancel: the lookup ends at the next wakeup (the first window end), not at the deadline
        let t0 = Instant::now();
        send("y.test", 3, &a);
        send("y.test", 4, &b);
        std::thread::sleep(Duration::from_millis(100));
        a.dns_live.lock().unwrap().remove(&3);
        b.dns_live.lock().unwrap().remove(&4);
        let (ga, gb) = (wait(&a, 1), wait(&b, 1));
        assert!(t0.elapsed() < Duration::from_millis(1500), "{:?}", t0.elapsed());
        assert_eq!((ga.len(), gb.len(), ga[0].nx || gb[0].nx), (1, 1, false));
    }
    #[test]
    fn min_rtt_of_a_loopback_peer() {
        // 60.51: a loopback connection has its handshake sample at accept (far below 10 ms); a unix socket has none
        use std::os::fd::AsRawFd;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        let v = min_rtt_us(s.as_raw_fd()).expect("TCP_INFO min_rtt");
        assert!(v < 10_000, "{v}");
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(min_rtt_us(a.as_raw_fd()), None);
    }
    #[test]
    fn same_host_peers() {
        // B: loopback (v4, v6, another 127/8 address) is this host; a socket with no peer is not
        let pair = |bind: &str, to: &str| {
            let l = std::net::TcpListener::bind(bind).unwrap();
            let mut a = l.local_addr().unwrap();
            a.set_ip(to.parse().unwrap());
            let c = std::net::TcpStream::connect(a).unwrap();
            (l, c)
        };
        use std::os::fd::AsRawFd;
        let (_l, c) = pair("127.0.0.1:0", "127.0.0.1");
        assert!(same_host(c.as_raw_fd()));
        let (_l2, c2) = pair("0.0.0.0:0", "127.0.0.2");
        assert!(same_host(c2.as_raw_fd()), "127.0.0.2: another loopback address");
        if let Ok(l6) = std::net::TcpListener::bind("[::1]:0") {
            let c6 = std::net::TcpStream::connect(l6.local_addr().unwrap()).unwrap();
            assert!(same_host(c6.as_raw_fd()));
        }
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(!same_host(u.as_raw_fd()), "no peer");
    }

    #[test]
    fn bytes_received_counts_payload() {
        use std::os::fd::AsRawFd;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut s, _) = l.accept().unwrap();
        let b0 = bytes_received(s.as_raw_fd()).unwrap();
        std::io::Write::write_all(&mut c, &[7u8; 5000]).unwrap();
        let mut got = vec![0u8; 5000];
        std::io::Read::read_exact(&mut s, &mut got).unwrap();
        assert_eq!(bytes_received(s.as_raw_fd()).unwrap() - b0, 5000);
        assert_eq!(bytes_received(-1), None);
    }
    /// 60.30 C10a lowat derivation: 1/8 s of the cap, 16 KiB floor, never above the configured value, 0 stays 0
    #[test]
    fn paced_lowat_rule() {
        assert_eq!(paced_lowat(128 << 10, 0), 128 << 10, "no cap: unchanged");
        assert_eq!(paced_lowat(0, 1 << 20), 0, "kernel default (0) stays the operator's choice");
        assert_eq!(paced_lowat(128 << 10, 125_000), 16 << 10, "1 Mbit/s: the floor");
        assert_eq!(paced_lowat(128 << 10, 1 << 20), 128 << 10, "8 Mbit/s: rate/8 = 128 KiB");
        assert_eq!(paced_lowat(128 << 10, 12_500_000), 128 << 10, "100 Mbit/s: the configured value");
        assert_eq!(paced_lowat(64 << 10, 256 << 10), 32 << 10);
        assert_eq!((pace_lowat(MIN_RATE), pace_lowat(MAX_RATE)), (16 << 10, MAX_RATE / 8));
        let (off, cap) = (Pacing::default(), Pacing { download: 125_000, upload: 0 });
        assert_eq!(off.client_settings(true, 128 << 10), (true, 128 << 10), "off: nothing changes");
        assert_eq!(cap.client_settings(true, 128 << 10), (false, 16 << 10), "a download cap: splice off, lowat 16 KiB");
        assert_eq!(Pacing { download: 0, upload: 1 << 20 }.client_settings(true, 128 << 10), (true, 128 << 10), "upload only");
    }
    /// 60.30 C10a a listener's pacing cap is on every accepted socket (net::listen sets it before bind/listen); the
    /// self-check says so on this kernel; a socket without a cap reports u32::MAX
    #[test]
    fn pacing_inherited_by_accepted_sockets() {
        use std::os::fd::{FromRawFd, IntoRawFd};
        assert_eq!(pacing_inherited(1 << 20), Some(true));
        let lfd = listen(&"127.0.0.1:0".parse().unwrap(), false, 3 << 20).unwrap();
        let l = unsafe { std::net::TcpListener::from_raw_fd(lfd) };
        l.set_nonblocking(false).unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        let sfd = s.into_raw_fd();
        assert_eq!(pacing(sfd), Some(3 << 20));
        assert_eq!(pacing(std::os::fd::AsRawFd::as_raw_fd(&c)), Some(u32::MAX), "the client side has none");
        assert!(set_pacing(sfd, 1 << 20) && pacing(sfd) == Some(1 << 20), "a per-socket value overrides it");
        assert!(try_notsent_lowat(sfd, 16 << 10));
        unsafe { libc::close(sfd) };
        assert_eq!(pacing(-1), None);
        assert!(!set_pacing(-1, 1 << 20) && !try_notsent_lowat(-1, 1));
        let plain = listen(&"127.0.0.1:0".parse().unwrap(), false, 0).unwrap();
        assert_eq!(pacing(plain), Some(u32::MAX), "off: no cap on the listener");
        unsafe { libc::close(plain) };
    }
    /// 80.01 F2/F7: the probe answers on this kernel (the laptop runs >= 5.15: Some(true)); the release is uname -r
    #[test]
    fn buf_lock_probe_and_release() {
        let rel = kernel_release();
        let major: u32 = rel.split('.').next().unwrap().parse().unwrap();
        let minor: u32 = rel.split('.').nth(1).unwrap().parse().unwrap();
        // vendor kernels below 5.15 may have a backport: only the upstream direction is asserted
        let probe = buf_lock_supported();
        assert!(probe.is_some(), "{rel}");
        if (major, minor) >= (5, 15) {
            assert_eq!(probe, Some(true), "{rel}");
        }
    }

    #[test]
    fn filter() {
        let f = Filter::new(false, false);
        for s in ["127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254", "::1", "fd00::1", "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1"]
        {
            assert!(!f.allowed(s.parse().unwrap()), "{s}");
        }
        for s in ["1.1.1.1", "2606:4700::1111", "8.8.8.8", "::ffff:8.8.8.8", "2001:4860:4860::8888", "2001:db8::1"] {
            assert!(f.allowed(s.parse().unwrap()), "{s}");
        }
        let lo = Filter::new(true, false);
        assert!(lo.allowed("127.0.0.1".parse().unwrap()) && !lo.allowed("10.0.0.1".parse().unwrap()));
        // unspecified stays loopback-like (connect to it reaches the local host): only --allow-loopback lifts it
        for s in ["0.0.0.0", "0.1.2.3", "::", "::1", "::ffff:0.0.0.0"] {
            assert!(!f.allowed(s.parse().unwrap()) && lo.allowed(s.parse().unwrap()), "{s}");
            assert!(
                !Filter { allow_private: true, allow_embedded: true, allow_self: true, ..Filter::new(false, true) }
                    .allowed(s.parse().unwrap()),
                "{s}"
            );
        }
    }

    /// 60.35 Filter::refusal is Some exactly when allowed() is false, for every flag combination (and names the class)
    #[test]
    fn filter_refusal_mirrors_allowed() {
        let ips: Vec<IpAddr> = [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "192.168.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "1.1.1.1",
            "8.8.8.8",
            "203.0.113.7",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "100::1",
            "2606:4700::1111",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
            "::8.8.8.8",
            "::10.0.0.1",
            "2002:808:808::1",
            "2002:a00:1::1",
            "2001:0:4136:e378::1",
            "64:ff9b::808:808",
            "64:ff9b::a00:1",
            "64:ff9b:1::808:808",
            "198.51.100.9",
            "2001:db8:1::5",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let cidr = |s: &str| crate::policy::Cidr::parse(s).unwrap();
        for bits in 0u32..128 {
            let b = |i: u32| bits & (1 << i) != 0;
            let f = Filter {
                allow_embedded: b(2),
                allow_self: b(3),
                ipv6: !b(4),
                own: vec!["203.0.113.7".parse().unwrap(), "2001:db8:1::5".parse().unwrap()].into(),
                allow_dests: if b(5) { vec![cidr("10.0.0.0/8"), cidr("::1")].into() } else { Box::default() },
                block_dests: if b(6) { vec![cidr("8.8.8.8"), cidr("2606:4700::/32")].into() } else { Box::default() },
                ..Filter::new(b(0), b(1))
            };
            for &ip in &ips {
                let r = f.refusal(ip);
                assert_eq!(r.is_some(), !f.allowed(ip), "{ip} bits {bits:07b} {r:?}");
            }
        }
        let f = Filter::new(false, false);
        let why = |s: &str| f.refusal(s.parse().unwrap());
        assert_eq!(
            (why("127.0.0.1"), why("10.0.0.1"), why("::10.0.0.1"), why("1.1.1.1")),
            (Some("loopback"), Some("private"), Some("private"), None)
        );
        let f = Filter { allow_private: true, ..Filter::new(false, true) };
        assert_eq!(f.refusal("::8.8.8.8".parse().unwrap()), Some("embedded_v4"));
    }

    /// 60.20 C1 / Q2: IPv6 forms embedding IPv4 are class EMB: blocked even with --allow-private; --allow-embedded-v4
    /// gives the 70.04 rule (::/96 and 6to4 judged by their v4, Teredo and local-use NAT64 private).
    #[test]
    fn embedded_v4_forms() {
        let all = |lo, pr| Filter::new(lo, pr);
        let emb = |lo, pr| Filter { allow_embedded: true, ..Filter::new(lo, pr) };
        let ok = |f: &Filter, s: &str| f.allowed(s.parse().unwrap());
        let emb_public = ["::8.8.8.8", "2002:808:808::1"];
        let emb_private = [
            "::10.0.0.1",
            "::a9fe:a9fe",
            "2002:a00:1::1",
            "2002:a9fe:a9fe::",
            "2002:c0a8:101::",
            "2001:0:4136:e378::1",
            "2001::1",
            "64:ff9b:1::808:808",
            "64:ff9b:2::1",
        ];
        let emb_loop = ["::127.0.0.1", "2002:7f00:1::"];
        for s in emb_public.iter().chain(&emb_private).chain(&emb_loop) {
            for (lo, pr) in [(false, false), (true, false), (false, true), (true, true)] {
                assert!(!ok(&all(lo, pr), s), "{s} blocked without --allow-embedded-v4 ({lo} {pr})");
            }
        }
        for s in emb_public {
            assert!(ok(&emb(false, false), s), "{s}");
        }
        for s in emb_private {
            assert!(!ok(&emb(true, false), s) && ok(&emb(false, true), s), "{s}");
        }
        for s in emb_loop {
            assert!(!ok(&emb(false, true), s) && ok(&emb(true, false), s), "{s}");
        }
        // new private ranges: site-local fec0::/10, discard 100::/64
        for s in ["fec0::1", "feff::1", "100::1"] {
            assert!(!ok(&all(true, false), s) && ok(&all(false, true), s), "{s}");
        }
        assert!(ok(&all(false, false), "100:0:0:1::1"), "outside 100::/64");
    }

    /// 60.21 NAT64 well-known prefix: both choices of the one classification line
    #[test]
    fn nat64_wkp_both_ways() {
        let c = |s: &str, by_v4| v6_class_with(s.parse().unwrap(), by_v4);
        // by its v4 (the default proposal): DNS64 deployments keep working, the v4 class still applies
        assert_eq!((c("64:ff9b::808:808", true), c("64:ff9b::7f00:1", true), c("64:ff9b::a00:1", true)), (0, LOOP, PRIV));
        // the alternative: an embedding form like 6to4 (blocked unless --allow-embedded-v4, then by its v4)
        assert_eq!((c("64:ff9b::808:808", false), c("64:ff9b::7f00:1", false)), (EMB, EMB | LOOP));
        // the rest of 64:ff9b::/32 is EMB | PRIV either way
        assert_eq!((c("64:ff9b:1::808:808", true), c("64:ff9b:1::808:808", false)), (EMB | PRIV, EMB | PRIV));
        let f = Filter::new(false, false);
        assert_eq!(f.allowed("64:ff9b::808:808".parse().unwrap()), NAT64_WKP_BY_V4);
        assert!(!f.allowed("64:ff9b::7f00:1".parse().unwrap()) && !f.allowed("64:ff9b::c0a8:1".parse().unwrap()));
    }

    /// 60.20 C1: --block-dest, --no-ipv6-targets, --allow-dest, own addresses, and their order
    #[test]
    fn dest_lists_ipv6_and_own_addresses() {
        use crate::policy::Cidr;
        let cidrs = |v: &[&str]| v.iter().map(|s| Cidr::parse(s).unwrap()).collect::<Box<[Cidr]>>();
        let ok = |f: &Filter, s: &str| f.allowed(s.parse().unwrap());
        let f = Filter {
            allow_dests: cidrs(&["127.0.0.2", "10.0.0.0/8", "2002::/16", "203.0.113.0/24"]),
            block_dests: cidrs(&["8.8.4.4", "10.9.0.0/16", "2001:db8::/32"]),
            own: vec!["203.0.113.5".parse().unwrap(), "198.51.100.7".parse().unwrap(), "2a01:4f8::5".parse().unwrap()].into(),
            ..Filter::new(false, false)
        };
        assert!(ok(&f, "127.0.0.2") && !ok(&f, "127.0.0.3"), "--allow-dest lifts loopback for that CIDR only");
        assert!(ok(&f, "10.1.1.1") && !ok(&f, "10.9.1.1"), "block wins over allow");
        assert!(ok(&f, "2002:a00:1::1"), "--allow-dest lifts the embedded class");
        assert!(!ok(&f, "8.8.4.4") && !ok(&f, "::ffff:8.8.4.4") && ok(&f, "8.8.8.8"), "mapped counts as v4");
        assert!(!ok(&f, "2001:db8::9"));
        for s in ["64:ff9b::808:404", "::808:404", "2002:808:404::1"] {
            assert!(!ok(&Filter { allow_embedded: true, ..f.clone() }, s), "review: --block-dest 8.8.4.4 covers {s}");
        }
        assert!(ok(&f, "64:ff9b::808:808") == NAT64_WKP_BY_V4);
        assert!(ok(&f, "203.0.113.5"), "--allow-dest beats the own-address class");
        for s in ["198.51.100.7", "::ffff:198.51.100.7", "2a01:4f8::5"] {
            assert!(!ok(&f, s), "own address {s}");
        }
        let own = Filter { own: vec!["198.51.100.7".parse().unwrap()].into(), ..Filter::new(true, true) };
        assert!(!ok(&own, "198.51.100.7"), "--allow-private / --allow-loopback do not lift own addresses");
        assert!(!ok(&own, "64:ff9b::c633:6407") || !NAT64_WKP_BY_V4, "own v4 through the NAT64 prefix");
        let emb = Filter { allow_embedded: true, ..own.clone() };
        assert!(!ok(&emb, "2002:c633:6407::1") && !ok(&emb, "::c633:6407"), "own v4 inside 6to4 / ::/96");
        assert!(ok(&Filter { allow_self: true, ..own.clone() }, "198.51.100.7"));
        assert!(ok(&own, "198.51.100.8"));
        let v4 = Filter { ipv6: false, ..Filter::new(true, true) };
        assert!(!ok(&v4, "::1") && !ok(&v4, "2606:4700::1111") && ok(&v4, "::ffff:1.1.1.1") && ok(&v4, "1.1.1.1"));
        let v4a = Filter { ipv6: false, allow_dests: cidrs(&["::/0"]), ..Filter::new(false, false) };
        assert!(!ok(&v4a, "2606:4700::1111"), "--no-ipv6-targets before --allow-dest");
    }

    #[test]
    fn own_addrs_snapshot() {
        let a = own_addrs().unwrap();
        assert!(a.iter().all(|ip| class(*ip) & LOOP == 0), "{a:?}");
        let mut d = a.clone();
        d.sort();
        d.dedup();
        assert_eq!(d.len(), a.len());
    }

    // ---- 60.58 --dns-share
    type KeyId = Option<crate::clientip::IpKey>;
    const K1: KeyId = Some(1 << 64);
    const K2: KeyId = Some(2 << 64);
    const G1: Group = Group::Addr(1 << 64);
    const G2: Group = Group::Addr(2 << 64);
    /// nothing waits, nothing runs, nothing is slow
    fn empty(sh: &DnsShare) -> bool {
        sh.conns.is_empty() && sh.groups.is_empty() && sh.oldest.iter().all(|o| o.is_empty()) && sh.marks.is_empty() && sh.waiting == 0
    }
    /// The pool's settings in a test: no expiry, the queue in arrival order or shared
    fn pool_mode(share: bool) -> DnsSched {
        DnsSched { stats: test_stats(), expire: std::time::Duration::from_secs(3600), share, reserve: false }
    }
    /// A test request's connection and address: one of each per token
    fn who(token: u64) -> (DnsConn, KeyId) {
        ((0, token as u32, 1), Some((token as u128 + 100) << 64))
    }
    fn sched(reserve: bool) -> DnsSched {
        DnsSched { stats: test_stats(), expire: std::time::Duration::from_secs(3600), share: true, reserve }
    }
    /// Stats for 4 workers (the tests' connections name workers 0 to 3)
    fn test_stats() -> Arc<Vec<Arc<crate::metrics::Stats>>> {
        Arc::new((0..4).map(|_| Arc::new(crate::metrics::Stats::new())).collect())
    }
    fn ask(sh: &mut DnsShare, fl: &InFlight, ib: &Arc<Inbox>, host: &str, conn: DnsConn, key: KeyId) {
        let req = DnsReq { host: host.into(), token: 0, inbox: ib.clone(), at: std::time::Instant::now(), conn, key };
        sh.admit(req, fl);
    }
    /// The lookup a free thread takes now: (name, connection)
    fn take(sh: &mut DnsShare, fl: &InFlight, now: std::time::Instant) -> Option<(String, DnsConn)> {
        sh.next(fl, now).map(|r| (r.host, r.conn))
    }
    /// The thread that ran `host` for `conn` since `start` is back
    fn back(sh: &mut DnsShare, fl: &InFlight, host: &str, conn: DnsConn, start: std::time::Instant) {
        fl.lock().unwrap().remove(host);
        sh.done(conn, start, start);
    }
    fn names(sh: &mut DnsShare, fl: &InFlight, now: std::time::Instant, n: usize) -> Vec<String> {
        (0..n).map(|_| take(sh, fl, now).expect("a lookup waits").0).collect()
    }

    /// 60.58 --dns-threads 1, 2 and 3. With 1 thread nothing runs when the thread is free, so the order is arrival
    /// order; with 2 and 3 a second connection gets the next free thread.
    #[test]
    fn dns_share_small_pools() {
        let (ib, now) = (Inbox::new(), std::time::Instant::now());
        let (a, b) = ((0, 1, 1), (0, 2, 1));
        for t in [0usize, 1, 2, 3] {
            let mut sh = DnsShare::new(t, sched(false));
            let fl = InFlight::default();
            for i in 0..4 {
                ask(&mut sh, &fl, &ib, &format!("a{i}"), a, K1);
            }
            // the pool's threads take what they can, then B asks, then one thread comes back at a time
            let free = t.max(1);
            let mut order = names(&mut sh, &fl, now, free);
            ask(&mut sh, &fl, &ib, "b0", b, K2);
            let mut running: Vec<String> = order.clone();
            while sh.waiting > 0 {
                let h = running.remove(0);
                back(&mut sh, &fl, &h, if h.starts_with('a') { a } else { b }, now);
                let n = take(&mut sh, &fl, now).unwrap().0;
                running.push(n.clone());
                order.push(n);
            }
            let want: &[&str] = match free {
                1 => &["a0", "a1", "a2", "a3", "b0"],
                2 => &["a0", "a1", "b0", "a2", "a3"],
                _ => &["a0", "a1", "a2", "b0", "a3"],
            };
            assert_eq!(order, want, "{t} threads");
        }
    }

    /// 60.58 identical names: a request whose name runs joins that lookup at once and is charged nothing; a waiting
    /// request joins when it is picked, if its name runs by then (no thread). The lookup is charged to the request the
    /// thread took, until `done`.
    #[test]
    fn dns_share_coalesce_and_charge() {
        let (ia, ibx, now) = (Inbox::new(), Inbox::new(), std::time::Instant::now());
        let fl = InFlight::default();
        let mut sh = DnsShare::new(2, sched(false));
        let (a, b) = ((0, 1, 1), (0, 2, 1));
        ask(&mut sh, &fl, &ia, "x", a, K1);
        assert_eq!(take(&mut sh, &fl, now), Some(("x".into(), a)));
        ask(&mut sh, &fl, &ibx, "x", b, K2);
        assert_eq!(sh.waiting, 0, "B joined the running lookup");
        assert_eq!(fl.lock().unwrap()["x"].0.len(), 1);
        assert!(!sh.conns.contains_key(&b) && sh.conns[&a].run.len() == 1 && sh.groups[&G1].run.len() == 1, "charged to A alone");
        // y waits twice (both threads busy: x and s); then B's y runs, and A's y joins it when it is picked
        ask(&mut sh, &fl, &ia, "s", a, K1);
        assert_eq!(take(&mut sh, &fl, now), Some(("s".into(), a)));
        ask(&mut sh, &fl, &ia, "y", a, K1);
        ask(&mut sh, &fl, &ibx, "y", b, K2);
        back(&mut sh, &fl, "x", a, now);
        assert_eq!(take(&mut sh, &fl, now), Some(("y".into(), b)), "A runs s, B nothing: B's y");
        back(&mut sh, &fl, "s", a, now);
        assert_eq!(take(&mut sh, &fl, now), None, "A's y joined B's lookup: the thread stays free");
        assert_eq!((sh.waiting, fl.lock().unwrap()["y"].0.len()), (0, 1));
        assert!(!sh.conns.contains_key(&a), "nothing charged to A");
        back(&mut sh, &fl, "y", b, now);
        assert!(empty(&sh));
        // a join with an early answer handed out gets it at once (70.10)
        fl.lock().unwrap().insert("e".into(), (Vec::new(), Some(vec![IpAddr::from([192, 0, 2, 1])])));
        ibx.q.lock().unwrap().clear();
        ask(&mut sh, &fl, &ibx, "e", b, K2);
        let q = ibx.q.lock().unwrap();
        assert!(q.len() == 1 && q[0].more && q[0].addrs == [IpAddr::from([192, 0, 2, 1])]);
    }

    /// 60.58 a request that waited longer than `expire` is answered as failed, without a thread, when a thread next
    /// looks at the queue; younger ones stay.
    #[test]
    fn dns_share_expires_old_requests() {
        let (ib, fl, now) = (Inbox::new(), InFlight::default(), std::time::Instant::now());
        let st = test_stats();
        let ten = DnsSched { stats: st.clone(), expire: std::time::Duration::from_secs(10), share: true, reserve: false };
        let mut sh = DnsShare::new(4, ten);
        for (i, age) in [12u64, 11, 3].into_iter().enumerate() {
            let at = now - std::time::Duration::from_secs(age);
            sh.admit(DnsReq { host: format!("h{i}"), token: i as u64, inbox: ib.clone(), at, conn: (0, i as u32, 1), key: K1 }, &fl);
        }
        assert_eq!(take(&mut sh, &fl, now).map(|r| r.0), Some("h2".into()));
        let q = ib.q.lock().unwrap();
        assert_eq!(
            q.iter().map(|r| (r.token, r.addrs.len(), r.nx, r.more)).collect::<Vec<_>>(),
            [(0, 0, false, false), (1, 0, false, false)]
        );
        assert_eq!(st[0].dns_expired.get(), 2);
        assert!(st[0].dns_wait_ms_max.get() >= 12_000 && st[0].dns_wait_us.get() >= 23_000_000, "the two expired ones");
        assert_eq!(st[1].dns_wait_us.get(), 0, "counted for the worker that asked");
        drop(q);

        // (review) requests that expire while they wait in the queue: the sweep takes them when a thread looks, and a
        // request that is older than the one that arrived before it (stamped by another worker) is caught at the pick
        let st = test_stats();
        let ten = DnsSched { stats: st.clone(), expire: std::time::Duration::from_secs(10), share: true, reserve: false };
        let mut sh = DnsShare::new(4, ten);
        let ago = |s: u64| now - std::time::Duration::from_secs(s);
        let later = now + std::time::Duration::from_secs(2);
        sh.admit(DnsReq { host: "young".into(), token: 10, inbox: ib.clone(), at: ago(5), conn: (1, 1, 1), key: K1 }, &fl);
        sh.admit(DnsReq { host: "old".into(), token: 11, inbox: ib.clone(), at: ago(9), conn: (1, 2, 1), key: K2 }, &fl);
        sh.admit(DnsReq { host: "mid".into(), token: 12, inbox: ib.clone(), at: ago(6), conn: (1, 3, 1), key: K2 }, &fl);
        assert_eq!(sh.waiting, 3, "none is past the expiry at admission");
        assert_eq!(names(&mut sh, &fl, later, 2), ["young", "mid"], "at +2 s: 7 s, 11 s (expired, behind a younger one), 8 s");
        assert_eq!((sh.waiting, take(&mut sh, &fl, later)), (0, None));
        assert_eq!(st[1].dns_expired.get(), 1);
        assert_eq!(ib.q.lock().unwrap().iter().filter(|r| r.token >= 10).map(|r| r.token).collect::<Vec<_>>(), [11]);
        // a request past the expiry never joins a running lookup of its name (as in arrival order)
        sh.admit(DnsReq { host: "young".into(), token: 13, inbox: ib.clone(), at: ago(11), conn: (1, 4, 1), key: K2 }, &fl);
        assert_eq!((sh.waiting, st[1].dns_expired.get(), fl.lock().unwrap()["young"].0.len()), (0, 2, 0));
        back(&mut sh, &fl, "young", (1, 1, 1), later);
        back(&mut sh, &fl, "mid", (1, 3, 1), later);
        assert!(empty(&sh), "nothing left behind");
    }

    /// 60.58 --dns-reserve, 16 threads: 12 for slow groups, 4 only for others.
    /// A group with a lookup that has run for DNS_RESERVE_AGE is slow, and stays so for DNS_RESERVE_HOLD after that
    /// lookup is back: a public address with all its connections, also a new one. The slow ones together get no
    /// thread past 12, also when threads are free and only they wait. Behind a local address only the connection is
    /// slow. A group with fast lookups is never held.
    #[test]
    fn dns_share_reserve() {
        let (ib, t0) = (Inbox::new(), std::time::Instant::now());
        let sec = |n: u64| t0 + std::time::Duration::from_secs(n);
        let fl = InFlight::default();
        let mut sh = DnsShare::new(16, sched(true));
        assert_eq!([1usize, 2, 3, 4, 8, 16, 32].map(|t| DnsShare::new(t, sched(true)).slow_cap), [1, 1, 2, 3, 6, 12, 24]);
        let (a, a2, b) = ((0, 1, 1), (0, 9, 1), (0, 2, 1));
        for i in 0..20 {
            ask(&mut sh, &fl, &ib, &format!("a{i}"), a, K1);
        }
        assert_eq!(names(&mut sh, &fl, t0, 16).len(), 16, "nothing is slow in the first second: every thread");
        assert_eq!((take(&mut sh, &fl, sec(1)), sh.waiting), (None, 4), "a lookup of A has run 1 s: A is slow and holds 16 >= 12");
        ask(&mut sh, &fl, &ib, "b0", b, K2);
        assert_eq!(take(&mut sh, &fl, sec(1)), Some(("b0".into(), b)), "B is not slow");
        sh.done(b, sec(1), sec(1)); // B's lookup was fast: no mark
        fl.lock().unwrap().remove("b0");
        assert!(!sh.conns.contains_key(&b) && !sh.groups.contains_key(&G2));
        // A's 16 come back after 4 s: A is marked. It gets 12 threads and no more, though 4 are free and only A waits
        for i in 0..16 {
            fl.lock().unwrap().remove(&format!("a{i}"));
            sh.done(a, t0, sec(4));
        }
        for i in 20..32 {
            ask(&mut sh, &fl, &ib, &format!("a{i}"), a, K1);
        }
        assert_eq!(names(&mut sh, &fl, sec(4), 12).len(), 12);
        assert_eq!((take(&mut sh, &fl, sec(4)), sh.waiting), (None, 4), "young lookups, but the mark holds: 4 threads stay free");
        // a new connection of A's address is slow from its first lookup; a connection of another address is not
        ask(&mut sh, &fl, &ib, "c0", a2, K1);
        assert_eq!(take(&mut sh, &fl, sec(4)), None, "the address is marked");
        for i in 0..6 {
            ask(&mut sh, &fl, &ib, &format!("b1{i}"), b, K2);
        }
        assert_eq!(names(&mut sh, &fl, sec(4), 6), ["b10", "b11", "b12", "b13", "b14", "b15"], "not slow: never held");
        // one of A's threads comes back: the slow ones share it by the rule (the connection that runs nothing first)
        fl.lock().unwrap().remove("a16");
        sh.done(a, sec(4), sec(4));
        assert_eq!(take(&mut sh, &fl, sec(4)), Some(("c0".into(), a2)));
        assert_eq!(take(&mut sh, &fl, sec(4)), None);
        // all back fast; the mark holds until 60 s after the last slow lookup came back (4 s), then A is free again
        for h in (17..28).map(|i| format!("a{i}")).chain(["c0".to_string()]) {
            fl.lock().unwrap().remove(&h);
            sh.done(if h.starts_with('a') { a } else { a2 }, sec(4), sec(4));
        }
        for i in 0..6 {
            fl.lock().unwrap().remove(&format!("b1{i}"));
            sh.done(b, sec(4), sec(4));
        }
        for i in 40..56 {
            ask(&mut sh, &fl, &ib, &format!("a{i}"), a, K1);
        }
        assert_eq!(names(&mut sh, &fl, sec(63), 12).len(), 12, "A had 4 waiting + 16 new");
        assert_eq!(take(&mut sh, &fl, sec(63)), None, "the mark (set at 4 s) still holds at 63 s");
        for i in 28..40 {
            let h = if i < 32 { format!("a{i}") } else { format!("a{}", i + 8) };
            fl.lock().unwrap().remove(&h);
            sh.done(a, sec(63), sec(63));
        }
        assert_eq!(names(&mut sh, &fl, sec(65), 8).len(), 8, "the mark is over and A's lookups were fast: every thread again");

        // behind a local address (key None) only the connection is marked: 3 slow connections hold the 12 threads,
        // a new connection behind the same address is not slow
        let mut sh = DnsShare::new(16, sched(true));
        let fl = InFlight::default();
        for n in 0..3u32 {
            for i in 0..6 {
                ask(&mut sh, &fl, &ib, &format!("l{n}{i}"), (1, n, 1), None);
            }
        }
        assert_eq!(names(&mut sh, &fl, t0, 12).len(), 12);
        assert_eq!((take(&mut sh, &fl, sec(2)), sh.waiting), (None, 6), "all three are slow: 12 threads together");
        ask(&mut sh, &fl, &ib, "n0", (1, 7, 1), None);
        assert_eq!(take(&mut sh, &fl, sec(2)), Some(("n0".into(), (1, 7, 1))));
        // slow connections of 4 addresses stop at 12 together, and a connection that is not slow gets a thread at once
        let mut sh = DnsShare::new(16, sched(true));
        let fl = InFlight::default();
        for n in 0..4u32 {
            for i in 0..6 {
                ask(&mut sh, &fl, &ib, &format!("m{n}{i}"), (2, n, 1), Some((50 + n as u128) << 64));
            }
        }
        assert_eq!(names(&mut sh, &fl, t0, 16).len(), 16, "nothing is slow in the first second");
        for n in 0..4u32 {
            for i in 0..4 {
                fl.lock().unwrap().remove(&format!("m{n}{i}"));
                sh.done((2, n, 1), t0, sec(4)); // all 16 come back slow: 4 marked addresses, 2 lookups wait for each
            }
        }
        assert_eq!(names(&mut sh, &fl, sec(4), 8).len(), 8);
        for n in 0..4u32 {
            for i in 0..4 {
                ask(&mut sh, &fl, &ib, &format!("q{n}{i}"), (2, n, 1), Some((50 + n as u128) << 64));
            }
        }
        assert_eq!(names(&mut sh, &fl, sec(4), 4).len(), 4, "12 threads for the slow ones together");
        assert!((0..4).all(|n| sh.conns[&(2, n, 1)].run.len() == 3), "3 each: the rule shares them");
        assert_eq!((take(&mut sh, &fl, sec(4)), sh.waiting), (None, 12), "4 threads stay free");
        ask(&mut sh, &fl, &ib, "b1", b, K2);
        assert_eq!(take(&mut sh, &fl, sec(4)), Some(("b1".into(), b)));
        // marks end and leave nothing behind
        let mut sh = DnsShare::new(16, sched(true));
        let fl = InFlight::default();
        ask(&mut sh, &fl, &ib, "x", a, K1);
        assert!(take(&mut sh, &fl, t0).is_some());
        fl.lock().unwrap().remove("x");
        sh.done(a, t0, sec(2));
        assert!(sh.conns.is_empty() && sh.groups[&G1].slow && sh.groups[&G1].slow_until == Some(sec(62)), "kept by the mark");
        assert_eq!(take(&mut sh, &fl, sec(61)), None);
        assert!(sh.groups[&G1].slow);
        assert_eq!(take(&mut sh, &fl, sec(62)), None);
        assert!(empty(&sh));
    }

    /// 60.58 --dns-reserve with many slow addresses waiting (an attacker with an address per connection): they stand
    /// in their own ordered set, so a pick for the reserve does not walk them, and a thread of theirs that comes back
    /// takes their oldest.
    #[test]
    fn dns_reserve_many_slow_groups() {
        let (ib, t0) = (Inbox::new(), std::time::Instant::now());
        let sec = |n: u64| t0 + std::time::Duration::from_secs(n);
        let fl = InFlight::default();
        let mut sh = DnsShare::new(16, sched(true));
        let who = |i: u32| ((0, i, 1), Some((i as u128 + 10) << 64));
        // 2,000 addresses, one lookup each that took 2 s: all slow until 62 s
        for i in 0..2000 {
            let (c, k) = who(i);
            ask(&mut sh, &fl, &ib, &format!("s{i}"), c, k);
            assert!(take(&mut sh, &fl, t0).is_some());
            fl.lock().unwrap().remove(&format!("s{i}"));
            sh.done(c, t0, sec(2));
        }
        assert_eq!((sh.groups.len(), sh.marks.len(), sh.conns.len(), sh.started.len()), (2000, 2000, 0, 2000));
        for i in 0..2000 {
            let (c, k) = who(i);
            ask(&mut sh, &fl, &ib, &format!("t{i}"), c, k);
        }
        assert_eq!(names(&mut sh, &fl, sec(2), 12), (0..12).map(|i| format!("t{i}")).collect::<Vec<_>>(), "the oldest 12");
        assert!(sh.started.len() == 12, "the lookups of the first second are forgotten");
        assert_eq!((take(&mut sh, &fl, sec(2)), sh.waiting), (None, 1988));
        assert_eq!((sh.oldest[0].len(), sh.oldest[1].len()), (0, 1988), "the slow ones wait apart");
        ask(&mut sh, &fl, &ib, "b0", (1, 1, 1), K2);
        assert_eq!((sh.oldest[0].len(), sh.pick()), (1, Some((1, 1, 1))));
        assert_eq!(take(&mut sh, &fl, sec(2)), Some(("b0".into(), (1, 1, 1))));
        back(&mut sh, &fl, "b0", (1, 1, 1), sec(2));
        fl.lock().unwrap().remove("t5");
        sh.done(who(5).0, sec(2), sec(2));
        assert_eq!(take(&mut sh, &fl, sec(2)).map(|t| t.0), Some("t12".into()), "a thread of the slow ones is back: their oldest");
        // the marks end at 62 s: nothing is slow, and every thread is theirs again
        assert_eq!(names(&mut sh, &fl, sec(62), 4).len(), 4);
        assert_eq!((sh.oldest[0].len(), sh.oldest[1].len(), sh.marks.len()), (1983, 0, 0));
    }

    /// 60.58 --dns-reserve: when a free thread has to look again while slow lookups wait (no thread comes back, no
    /// request arrives): at the end of the first slow_until, or when the oldest waiting lookup expires.
    #[test]
    fn dns_reserve_wake() {
        let (ib, t0) = (Inbox::new(), std::time::Instant::now());
        let ms = |n: u64| t0 + std::time::Duration::from_millis(n);
        let fl = InFlight::default();
        let a = (0, 1, 1);
        let mut sh = DnsShare::new(2, sched(true)); // 2 threads: 1 for the slow ones
        assert_eq!(sh.wake(t0), None, "nothing waits");
        ask(&mut sh, &fl, &ib, "a0", a, K1);
        assert!(take(&mut sh, &fl, t0).is_some() && sh.wake(t0).is_none());
        fl.lock().unwrap().remove("a0");
        sh.done(a, t0, ms(2000)); // slow until 62 s
        assert_eq!(sh.wake(ms(2000)), None, "a slow group, but nothing waits");
        ask(&mut sh, &fl, &ib, "a1", a, K1);
        ask(&mut sh, &fl, &ib, "a2", a, K1);
        assert_eq!(take(&mut sh, &fl, ms(61_500)).map(|t| t.0), Some("a1".into()));
        assert_eq!((take(&mut sh, &fl, ms(61_500)), sh.waiting), (None, 1), "a2 is held: the second thread is the reserve");
        assert_eq!(sh.wake(ms(61_500)), Some(ms(62_000)), "the end of slow_until comes first (the expiry: an hour)");
        assert_eq!(take(&mut sh, &fl, ms(61_999)), None);
        assert_eq!(take(&mut sh, &fl, ms(62_000)).map(|t| t.0), Some("a2".into()), "a1 has run for half a second: not slow");
        assert_eq!(sh.wake(ms(62_000)), None);
        // a lookup that runs for a second makes the group slow again, without a mark
        ask(&mut sh, &fl, &ib, "a3", a, K1);
        assert_eq!((take(&mut sh, &fl, ms(62_500)), sh.wake(ms(62_500))), (None, Some(ms(122_500))), "a1 has run 1 s: slow, 2 >= 1");
        fl.lock().unwrap().remove("a1");
        sh.done(a, ms(61_500), ms(62_600));
        assert_eq!((take(&mut sh, &fl, ms(62_600)), sh.groups[&G1].slow_until), (None, Some(ms(122_600))), "a2 holds the one thread");
        fl.lock().unwrap().remove("a2");
        sh.done(a, ms(62_000), ms(62_700));
        assert_eq!(take(&mut sh, &fl, ms(62_700)).map(|t| t.0), Some("a3".into()));
        // slow_until ends while a lookup of the group has run for a second or more: the group stays slow
        ask(&mut sh, &fl, &ib, "a4", a, K1);
        assert_eq!((take(&mut sh, &fl, ms(64_000)), sh.wake(ms(64_000))), (None, Some(ms(122_600))));
        assert_eq!((take(&mut sh, &fl, ms(122_600)), sh.waiting), (None, 1), "a3 has run for a minute");
        assert_eq!((sh.groups[&G1].slow, sh.groups[&G1].slow_until, sh.marks.len()), (true, None, 0));
        fl.lock().unwrap().remove("a3");
        sh.done(a, ms(62_700), ms(122_700));
        assert_eq!(take(&mut sh, &fl, ms(122_700)).map(|t| t.0), Some("a4".into()));
        // no slow_until: the expiry of the oldest waiting lookup
        let ten = std::time::Duration::from_secs(10);
        let mut sh = DnsShare::new(2, DnsSched { expire: ten, ..sched(true) });
        let fl = InFlight::default();
        ask(&mut sh, &fl, &ib, "b0", a, K1);
        assert!(take(&mut sh, &fl, t0).is_some());
        ask(&mut sh, &fl, &ib, "b1", a, K1);
        let asked = sh.conns[&a].q[0].1.at;
        assert_eq!(
            (take(&mut sh, &fl, ms(1000)), sh.wake(ms(1000))),
            (None, Some(asked + ten)),
            "b0 has run 1 s: b1 is held until it expires"
        );
        // no slow_until and a late expiry: not later than DNS_RESERVE_HOLD from now. A thread that comes back while this
        // one sleeps sets a slow_until that this one did not see; it ends after that time at the earliest.
        let mut sh = DnsShare::new(2, sched(true));
        let fl = InFlight::default();
        ask(&mut sh, &fl, &ib, "c0", a, K1);
        assert!(take(&mut sh, &fl, t0).is_some());
        ask(&mut sh, &fl, &ib, "c1", a, K1);
        assert_eq!((take(&mut sh, &fl, ms(1000)), sh.wake(ms(1000))), (None, Some(ms(61_000))), "the expiry is an hour away");
        fl.lock().unwrap().remove("c0");
        sh.done(a, t0, ms(1500)); // the other thread: c0 is back, slow until 61.5 s; it takes c1
        assert_eq!(take(&mut sh, &fl, ms(1500)).map(|t| t.0), Some("c1".into()));
        ask(&mut sh, &fl, &ib, "c2", a, K1);
        fl.lock().unwrap().remove("c1");
        sh.done(a, ms(1500), ms(1600)); // c1 was fast; c2 waits, held by slow_until alone
        assert_eq!(take(&mut sh, &fl, ms(1600)).map(|t| t.0), Some("c2".into()), "1 thread is theirs");
    }

    /// 60.58 --dns-reserve in the pool end to end, 4 threads (3 for slow connections), against a server the test
    /// answers by hand. A's four lookups run for a second: A is slow. A thread that comes back goes to B, and then
    /// stays free though A's fifth lookup waits; B's next lookup starts at once. A's fifth expires on time, with no
    /// thread coming back and no request arriving (the free thread wakes for it).
    #[test]
    fn dns_pool_reserve_end_to_end() {
        let (mut srv, own) = HandDns::new();
        let st = test_stats();
        let sched = DnsSched { stats: st.clone(), expire: std::time::Duration::from_secs(2), share: true, reserve: true };
        let tx = start_dns_pool(4, Some(own), true, true, sched);
        let (a, b) = (Inbox::new(), Inbox::new());
        let send = |host: &str, t: u64, ib: &Arc<Inbox>, conn: DnsConn, key: KeyId| {
            ib.dns_live.lock().unwrap().insert(t);
            tx.send(DnsReq { host: host.into(), token: t, inbox: ib.clone(), at: std::time::Instant::now(), conn, key }).unwrap();
        };
        let (ca, cb) = ((0, 1, 1), (1, 1, 1));
        let t0 = std::time::Instant::now();
        for t in 1..=5 {
            send(&format!("a{t}.test"), t, &a, ca, K1);
        }
        let mut first: Vec<String> = (0..4).map(|_| srv.next(3000).unwrap()).collect();
        first.sort();
        assert_eq!(first, ["a1", "a2", "a3", "a4"], "nothing is slow in the first second: every thread");
        std::thread::sleep(std::time::Duration::from_millis(1150).saturating_sub(t0.elapsed()));
        send("b1.test", 11, &b, cb, K2);
        assert_eq!(srv.next(100), None, "every thread is busy");
        srv.answer("a1");
        assert_eq!(srv.next(3000).as_deref(), Some("b1"), "B is not slow");
        srv.answer("b1");
        assert_eq!(finals(&b, 1), [(11, 1)]);
        assert_eq!(srv.next(300), None, "a thread is free and a5 waits: A is slow and holds its 3 threads");
        send("b2.test", 12, &b, cb, K2);
        assert_eq!(srv.next(3000).as_deref(), Some("b2"), "the reserve");
        srv.answer("b2");
        // a5 was asked at 0 s and expires at 2 s; A's other lookups run until 6 s
        assert_eq!(finals(&a, 2), [(1, 1), (5, 0)]);
        let took = t0.elapsed();
        assert!(took >= std::time::Duration::from_millis(1900) && took < std::time::Duration::from_millis(3500), "{took:?}");
        assert_eq!((st[0].dns_expired.get(), st[1].dns_expired.get()), (1, 0));
        // These lookups were asked at 0 s and the resolver's first attempt ends at 2 s (timeout:2), which is now: an
        // answer can cross the retry and be lost. So answer until all are in (the latest query of each name).
        let end = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while a.q.lock().unwrap().iter().filter(|r| !r.more).count() < 5 && std::time::Instant::now() < end {
            for n in ["a2", "a3", "a4"] {
                srv.answer(n);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!((finals(&a, 5), finals(&b, 2)), (vec![(1, 1), (2, 1), (3, 1), (4, 1), (5, 0)], vec![(11, 1), (12, 1)]));
    }

    /// 60.58 the rule on the queue alone, 16 threads: the free thread goes to the address that runs the fewest
    /// lookups, inside it to the connection that runs the fewest, the oldest among equals. An address alone takes
    /// every thread; a newcomer gets the next free thread, however many addresses hold the pool; two addresses with a
    /// backlog end at half the pool each; a local address is no group (its connections count one by one).
    #[test]
    fn dns_share_rule() {
        let (ib, now) = (Inbox::new(), std::time::Instant::now());
        let fair = sched(false);
        let fl = InFlight::default();
        let mut sh = DnsShare::new(16, fair.clone());
        let (a, b) = ((0, 1, 1), (0, 2, 1));
        for i in 0..40 {
            ask(&mut sh, &fl, &ib, &format!("a{i}"), a, K1);
        }
        assert_eq!(names(&mut sh, &fl, now, 16), (0..16).map(|i| format!("a{i}")).collect::<Vec<_>>(), "alone: every thread");
        for i in 0..12 {
            ask(&mut sh, &fl, &ib, &format!("b{i}"), b, K2);
        }
        // A runs 16, B 0: the next 8 free threads are B's (15:1, 14:2, .. 8:8); then each thread that A gives back is A's
        let mut got = Vec::new();
        for i in 0..11 {
            back(&mut sh, &fl, &format!("a{i}"), a, now);
            got.push(take(&mut sh, &fl, now).unwrap().0);
        }
        assert_eq!(got, ["b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "a16", "a17", "a18"]);
        assert_eq!((sh.groups[&G1].run.len(), sh.groups[&G2].run.len()), (8, 8));
        back(&mut sh, &fl, "b0", b, now);
        assert_eq!(take(&mut sh, &fl, now), Some(("b8".into(), b)), "and each one B gives back is B's");

        // 4 addresses hold the pool (4 threads each) and have a backlog; a newcomer gets the next free thread
        let mut sh = DnsShare::new(16, fair.clone());
        let fl = InFlight::default();
        let addr = |n: u32| Some((50 + n as u128) << 64);
        for i in 0..8 {
            for n in 0..4u32 {
                ask(&mut sh, &fl, &ib, &format!("m{n}x{i}"), (2, n, 1), addr(n));
            }
        }
        assert_eq!(names(&mut sh, &fl, now, 16).len(), 16);
        assert!((0..4).all(|n| sh.groups[&Group::Addr(addr(n).unwrap())].run.len() == 4), "4 each");
        ask(&mut sh, &fl, &ib, "b0", b, K2);
        back(&mut sh, &fl, "m0x0", (2, 0, 1), now);
        assert_eq!(take(&mut sh, &fl, now), Some(("b0".into(), b)));

        // inside an address the connection that runs the fewest; between addresses the address that runs the fewest
        let mut sh = DnsShare::new(16, fair.clone());
        let fl = InFlight::default();
        let (a1, a2, c) = ((0, 5, 1), (0, 6, 1), (1, 1, 1));
        for i in 0..3 {
            ask(&mut sh, &fl, &ib, &format!("x{i}"), a1, K1);
        }
        for i in 0..5 {
            ask(&mut sh, &fl, &ib, &format!("c{i}"), c, K2);
        }
        assert_eq!(names(&mut sh, &fl, now, 8).len(), 8); // K1 runs 3 (all a1), K2 runs 5
        ask(&mut sh, &fl, &ib, "c5", c, K2);
        ask(&mut sh, &fl, &ib, "x3", a1, K1);
        ask(&mut sh, &fl, &ib, "y0", a2, K1);
        assert_eq!(names(&mut sh, &fl, now, 3), ["y0", "x3", "c5"], "K1 (3) before K2 (5); in K1 a2 (0) before a1 (3)");

        // a local address is no group: its connections count one by one
        let mut sh = DnsShare::new(16, fair.clone());
        let fl = InFlight::default();
        let (p1, p2) = ((3, 1, 1), (3, 2, 1));
        for i in 0..4 {
            ask(&mut sh, &fl, &ib, &format!("p{i}"), p1, None);
            ask(&mut sh, &fl, &ib, &format!("k{i}"), a, K1);
        }
        assert_eq!(names(&mut sh, &fl, now, 8).len(), 8);
        ask(&mut sh, &fl, &ib, "k4", a, K1);
        ask(&mut sh, &fl, &ib, "p4", p1, None);
        ask(&mut sh, &fl, &ib, "q0", p2, None);
        back(&mut sh, &fl, "p0", p1, now); // p1 runs 3, K1 runs 4, p2 runs 0
        assert_eq!(names(&mut sh, &fl, now, 3), ["q0", "p4", "k4"]);
        assert!(sh.oldest.iter().all(|o| o.is_empty()) && sh.waiting == 0);
        assert!(sh.started.is_empty() && sh.marks.is_empty() && sh.oldest[1].is_empty(), "no slow state without --dns-reserve");
    }

    /// A DNS server a test drives by hand (A queries only: the resolver is IPv4-only): `next` is the next name asked
    /// that was not asked before, `answer` replies 192.0.2.1 to the latest query for a name.
    struct HandDns {
        sock: std::net::UdpSocket,
        asked: Vec<(String, Vec<u8>, SocketAddr)>,
    }
    impl HandDns {
        fn new() -> (HandDns, Arc<crate::dns::Resolver>) {
            let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let dir = std::env::temp_dir().join(format!("fw-pool-hand-{}-{}", std::process::id(), sock.local_addr().unwrap().port()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("r"), "options timeout:2 attempts:3\n").unwrap(); // 6 s for a lookup: no test waits that long
            let own = crate::dns::Resolver::with_paths(vec![sock.local_addr().unwrap()], dir.join("r"), dir.join("h")).ipv4_only(true);
            (HandDns { sock, asked: Vec::new() }, Arc::new(own))
        }
        fn next(&mut self, wait_ms: u64) -> Option<String> {
            let end = std::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
            let mut b = [0u8; 1500];
            loop {
                let left = end.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return None;
                }
                self.sock.set_read_timeout(Some(left)).unwrap();
                let Ok((n, from)) = self.sock.recv_from(&mut b) else { return None };
                let name = String::from_utf8_lossy(&b[13..13 + b[12] as usize]).to_string();
                let again = self.asked.iter_mut().find(|a| a.0 == name);
                let new = again.is_none();
                match again {
                    Some(a) => (a.1, a.2) = (b[..n].to_vec(), from), // a retry: answer that one
                    None => self.asked.push((name.clone(), b[..n].to_vec(), from)),
                }
                if new {
                    return Some(name);
                }
            }
        }
        fn answer(&mut self, name: &str) {
            while self.next(1).is_some() {} // (retries that are already here)
            let (_, q, from) = self.asked.iter().find(|a| a.0 == name).expect("asked");
            let e = 12 + q[12..].iter().position(|&x| x == 0).unwrap();
            let mut r = q[..2].to_vec();
            r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            r.extend_from_slice(&q[12..e + 5]);
            r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
            self.sock.send_to(&r, from).unwrap();
        }
    }
    /// The final answers in `ib` once it holds `n` (or after 5 s): (token, addresses) sorted
    fn finals(ib: &Arc<Inbox>, n: usize) -> Vec<(u64, usize)> {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let get = || ib.q.lock().unwrap().iter().filter(|r| !r.more).map(|r| (r.token, r.addrs.len())).collect::<Vec<_>>();
        while get().len() < n && std::time::Instant::now() < end {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let mut v = get();
        v.sort();
        v
    }

    /// 60.58 the pool end to end, 2 threads, against a server the test answers by hand. A's two lookups hold both
    /// threads, A's third and then B's first wait. Off: the freed thread takes A's third (arrival order, as before).
    /// --dns-share: it takes B's (A still runs one, B nothing), and A's third after that. Every request gets exactly one
    /// final answer, and the wait is counted for its worker.
    #[test]
    fn dns_pool_share_end_to_end() {
        for share in [false, true] {
            let (mut srv, own) = HandDns::new();
            let mode = pool_mode(share);
            let st = mode.stats.clone();
            let tx = start_dns_pool(2, Some(own), true, true, mode);
            let (a, b) = (Inbox::new(), Inbox::new());
            let send = |host: &str, t: u64, ib: &Arc<Inbox>, conn: DnsConn, key: KeyId| {
                ib.dns_live.lock().unwrap().insert(t);
                tx.send(DnsReq { host: host.into(), token: t, inbox: ib.clone(), at: std::time::Instant::now(), conn, key }).unwrap();
            };
            let (ca, cb) = ((0, 1, 1), (1, 1, 1));
            send("a1.test", 1, &a, ca, K1);
            send("a2.test", 2, &a, ca, K1);
            let mut first = [srv.next(3000).unwrap(), srv.next(3000).unwrap()];
            first.sort();
            assert_eq!(first, ["a1", "a2"]);
            send("a3.test", 3, &a, ca, K1);
            send("b1.test", 4, &b, cb, K2);
            assert_eq!(srv.next(150), None, "both threads are busy");
            srv.answer("a1");
            let (second, third) = if share { ("b1", "a3") } else { ("a3", "b1") };
            assert_eq!(srv.next(3000).as_deref(), Some(second), "share {share}");
            srv.answer(second);
            assert_eq!(srv.next(3000).as_deref(), Some(third), "share {share}");
            srv.answer(third);
            srv.answer("a2");
            assert_eq!((finals(&a, 3), finals(&b, 1)), (vec![(1, 1), (2, 1), (3, 1)], vec![(4, 1)]), "share {share}");
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert_eq!((a.q.lock().unwrap().len(), b.q.lock().unwrap().len()), (3, 1), "one answer each, nothing after it");
            // (A is worker 0, B worker 1) B's one lookup waited while A's ran; A's third waited at least as long
            assert!(st[1].dns_wait_us.get() > 0 && st[0].dns_wait_us.get() >= st[1].dns_wait_us.get() / 2);
            assert_eq!(st[0].dns_expired.get() + st[1].dns_expired.get(), 0);
        }
    }

    /// 60.58 a request that waited for a thread longer than the expiry (the connect timeout) is answered as failed
    /// without a query, in arrival order and with --dns-share; the lookup that runs is not touched.
    #[test]
    fn dns_pool_expires_queued_requests() {
        for share in [false, true] {
            let (mut srv, own) = HandDns::new();
            let st = test_stats();
            let sched = DnsSched { stats: st.clone(), expire: std::time::Duration::from_millis(300), share, reserve: false };
            let tx = start_dns_pool(1, Some(own), true, true, sched);
            let (a, b) = (Inbox::new(), Inbox::new());
            let send = |host: &str, t: u64, ib: &Arc<Inbox>, conn: DnsConn, key: KeyId| {
                ib.dns_live.lock().unwrap().insert(t);
                tx.send(DnsReq { host: host.into(), token: t, inbox: ib.clone(), at: std::time::Instant::now(), conn, key }).unwrap();
            };
            send("e1.test", 1, &a, (0, 1, 1), K1);
            assert_eq!(srv.next(3000).as_deref(), Some("e1"));
            send("e2.test", 2, &a, (0, 1, 1), K1);
            send("e3.test", 3, &b, (1, 1, 1), K2);
            std::thread::sleep(std::time::Duration::from_millis(400));
            srv.answer("e1");
            assert_eq!((finals(&a, 2), finals(&b, 1)), (vec![(1, 1), (2, 0)], vec![(3, 0)]), "share {share}");
            assert!(a.q.lock().unwrap().iter().chain(b.q.lock().unwrap().iter()).all(|r| !r.nx), "a failure, not a cacheable NXDOMAIN");
            assert_eq!(srv.next(150), None, "no query for an expired request");
            assert_eq!((st[0].dns_expired.get(), st[1].dns_expired.get()), (1, 1), "share {share}");
            assert!(st[1].dns_wait_ms_max.get() >= 300);
            // the pool still works: a new request runs
            send("e4.test", 4, &b, (1, 1, 1), K2);
            assert_eq!(srv.next(3000).as_deref(), Some("e4"));
            srv.answer("e4");
            assert_eq!(finals(&b, 2), [(3, 0), (4, 1)]);
        }
    }

    /// 60.58 many connections and addresses, few names, 4 threads, a server that answers at once: every request gets
    /// exactly one final answer with --dns-share (joins at admission and at the pick, picks from every tier).
    #[test]
    fn dns_pool_share_answers_every_request_once() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut b) {
                let q = &b[..n];
                let e = 12 + q[12..].iter().position(|&x| x == 0).unwrap();
                let mut r = q[..2].to_vec();
                r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                r.extend_from_slice(&q[12..e + 5]);
                r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
                let _ = sock.send_to(&r, from);
            }
        });
        let dir = std::env::temp_dir().join(format!("fw-pool-once-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("r"), "options timeout:2 attempts:3\n").unwrap();
        let own = Arc::new(crate::dns::Resolver::with_paths(vec![addr], dir.join("r"), dir.join("h")).ipv4_only(true));
        let tx = start_dns_pool(4, Some(own), true, true, pool_mode(true));
        let boxes: Vec<Arc<Inbox>> = (0..3).map(|_| Inbox::new()).collect();
        const N: u64 = 3000;
        for t in 0..N {
            let ib = &boxes[(t % 3) as usize];
            ib.dns_live.lock().unwrap().insert(t);
            // 12 connections on 5 addresses (one of them local: no key), 40 names
            let c = (t * 7 % 12) as u32;
            let key = (!c.is_multiple_of(5)).then_some((c as u128 % 5) << 64);
            let host = format!("n{}.test", t * 13 % 40);
            tx.send(DnsReq { host, token: t, inbox: ib.clone(), at: std::time::Instant::now(), conn: ((t % 3) as u32, c, 1), key })
                .unwrap();
        }
        let mut got: Vec<(u64, usize)> = boxes.iter().flat_map(|ib| finals(ib, N as usize / 3)).collect();
        got.sort();
        assert_eq!(got, (0..N).map(|t| (t, 1)).collect::<Vec<_>>());
    }

    /// 60.58 the cost of one pick at the ceiling of the waiting list (80 workers x DNS_INFLIGHT_MAX = 81,920), in the
    /// three shapes where the lookup to take is behind the most others. Run on a timing box:
    /// `cargo test --release dns_share_pick_cost -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dns_share_pick_cost() {
        const N: u32 = 81_920;
        let (ib, now) = (Inbox::new(), std::time::Instant::now());
        type Who = fn(u32) -> (DnsConn, KeyId);
        let shapes: [(&str, Who); 3] = [
            ("one connection", |_| ((0, 1, 1), K1)),
            ("one address, a connection each", |i| ((0, i, 1), K1)),
            ("an address each", |i| ((0, i, 1), Some((i as u128 + 10) << 64))),
        ];
        for (what, who) in shapes {
            let fl = InFlight::default();
            let mut sh = DnsShare::new(16, sched(false));
            let t = std::time::Instant::now();
            for i in 0..N {
                let (conn, key) = who(i);
                ask(&mut sh, &fl, &ib, &format!("n{i}"), conn, key);
            }
            let admit = t.elapsed().as_nanos() / N as u128;
            let run = names(&mut sh, &fl, now, 15); // the attacker's lookups run on 15 threads
            let mut picks = Vec::new();
            for r in 0..2000u32 {
                // a legit connection of another address asks; the free thread must find it behind everything else
                let legit = (9, r, 1);
                ask(&mut sh, &fl, &ib, &format!("legit{r}"), legit, K2);
                let t = std::time::Instant::now();
                let got = sh.pick();
                picks.push(t.elapsed().as_nanos());
                if what != "an address each" {
                    assert_eq!(got, Some(legit), "{what}");
                }
                let (h, c) = take(&mut sh, &fl, now).unwrap();
                back(&mut sh, &fl, &h, c, now);
                if c != legit {
                    // (an address each: the oldest waiting address ran; put a lookup back so the list stays full)
                    let (conn, key) = who(N + r);
                    ask(&mut sh, &fl, &ib, &format!("m{r}"), conn, key);
                    let l = take(&mut sh, &fl, now).unwrap();
                    back(&mut sh, &fl, &l.0, l.1, now);
                }
            }
            picks.sort();
            println!(
                "dns_share_pick_cost {what}: {} waiting, {} running; admit {admit} ns each; pick median {} ns, p99 {} ns, max {} ns",
                sh.waiting,
                run.len(),
                picks[picks.len() / 2],
                picks[picks.len() * 99 / 100],
                picks[picks.len() - 1]
            );
        }
        // --dns-reserve: an address each, every one of them slow and waiting, their 12 threads in use
        let (fl, sec) = (InFlight::default(), |n: u64| now + std::time::Duration::from_secs(n));
        let mut sh = DnsShare::new(16, sched(true));
        let who = |i: u32| ((0, i, 1), Some((i as u128 + 10) << 64));
        for i in 0..N {
            let (conn, key) = who(i);
            ask(&mut sh, &fl, &ib, &format!("s{i}"), conn, key);
            let l = take(&mut sh, &fl, now).unwrap();
            fl.lock().unwrap().remove(&l.0);
            sh.done(l.1, now, sec(2));
        }
        for i in 0..N {
            let (conn, key) = who(i);
            ask(&mut sh, &fl, &ib, &format!("n{i}"), conn, key);
        }
        let run = names(&mut sh, &fl, sec(2), 12);
        assert_eq!(take(&mut sh, &fl, sec(2)), None);
        let mut picks = Vec::new();
        for r in 0..2000u32 {
            let legit = (9, r, 1);
            ask(&mut sh, &fl, &ib, &format!("legit{r}"), legit, K2);
            let t = std::time::Instant::now();
            let got = sh.pick();
            picks.push(t.elapsed().as_nanos());
            assert_eq!(got, Some(legit));
            let (h, c) = take(&mut sh, &fl, sec(2)).unwrap();
            back(&mut sh, &fl, &h, c, sec(2));
        }
        picks.sort();
        println!(
            "dns_share_pick_cost reserve, an address each, all slow: {} waiting, {} running; pick median {} ns, p99 {} ns, max {} ns",
            sh.waiting,
            run.len(),
            picks[picks.len() / 2],
            picks[picks.len() * 99 / 100],
            picks[picks.len() - 1]
        );
    }

    /// 60.58 the addresses that are no group for --dns-share (a proxy or a bridge in front of many users)
    #[test]
    fn shared_addr_classes() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "172.17.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "100::",
            "::ffff:10.0.0.1",
        ] {
            assert!(shared_addr(s.parse().unwrap()), "{s}");
        }
        for s in ["203.0.113.9", "8.8.8.8", "2001:db8::1", "2a01:4f8::5", "::ffff:8.8.8.8"] {
            assert!(!shared_addr(s.parse().unwrap()), "{s}");
        }
        // 60.57 C local_peer (--conn-share) is the same rule; the two came from two branches and agree on every class
        // (one function is a follow-up of the v1.3.0 merge)
        let more = [
            "2001::1",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "::8.8.8.8",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "::",
        ];
        let all = ["127.0.0.1", "10.1.2.3", "100.64.0.1", "169.254.1.1", "::1", "fd00::1", "fe80::1", "100::", "::ffff:10.0.0.1"];
        for s in all.iter().chain(&more).chain(&["203.0.113.9", "8.8.8.8", "2001:db8::1", "::ffff:8.8.8.8"]) {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(local_peer(ip), shared_addr(ip), "{s}");
        }
    }
}
