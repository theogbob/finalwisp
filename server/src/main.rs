//! 20.01 finalwisp — entry point. See docs/summaries/10.01-wisp-protocol.md and the roadmap (60.01).
//! unsafe (60.16): blocks without their own SAFETY comment are plain libc calls whose pointer arguments come from a
//! live local or slice with the length taken from the same value (or are plain integers); no pointer outlives the call.
mod cli;
mod clientip;
mod credit;
mod destrate; // 60.39
mod dns;
mod ext;
mod http;
mod logs;
mod mem;
mod metrics;
mod net;
mod policy;
mod pool;
mod prom;
mod proxyproto; // 60.34
mod tls;
mod upstream;
mod worker;
mod ws;

use std::sync::Arc;
use std::time::Duration;
use worker::{Config, Worker};

/// 60.24 a startup line printed when its level passes --log-level (eprintln: one write per line, as before)
macro_rules! say {
    ($lvl:ident, $($a:tt)*) => {
        if logs::on(logs::Level::$lvl) {
            eprintln!($($a)*)
        }
    };
}

#[global_allocator]
static ALLOC: mem::Counting = mem::Counting; // 20.26 heap bytes in use (mem::heap_bytes)

/// 60.20 C8: read a --config file for cli::expand_config: (at most CONFIG_MAX_BYTES + 1 bytes, st_mode). The extra byte
/// lets the parser report "too big" (a pipe or /dev/zero is read only that far).
fn read_config(path: &str) -> Result<(Vec<u8>, u32), String> {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mode = f.metadata().map_err(|e| e.to_string())?.permissions().mode();
    if mode & libc::S_IFMT == libc::S_IFDIR {
        return Err("is a directory".to_string());
    }
    let mut data = Vec::new();
    f.take(cli::CONFIG_MAX_BYTES as u64 + 1).read_to_end(&mut data).map_err(|e| e.to_string())?;
    Ok((data, mode))
}

fn usage() -> ! {
    eprintln!("{}", cli::USAGE);
    std::process::exit(2)
}

/// Signals handled by `signal_loop`; blocked in main before any thread exists, so every thread inherits the mask.
const SIGNALS: [libc::c_int; 3] = [libc::SIGHUP, libc::SIGTERM, libc::SIGINT];

/// 60.12 flag 1: the set main blocks and signal_loop waits for. SIGINT ignored at startup (POSIX: `cmd &` in a
/// non-interactive shell, nohup-style launchers) stays ignored: it is left out, so it is neither blocked nor waited
/// for and the kernel discards it. SIGTERM always drains. The disposition never changes later (no handlers are set),
/// so main and signal_loop compute the same set.
fn signal_set() -> libc::sigset_t {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        for s in SIGNALS {
            if s == libc::SIGINT && signal_ignored(s) {
                continue;
            }
            libc::sigaddset(&mut set, s);
        }
    }
    set
}

fn signal_ignored(sig: libc::c_int) -> bool {
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::sigaction(sig, std::ptr::null(), &mut old) };
    rc == 0 && old.sa_sigaction == libc::SIG_IGN
}

fn log(msg: std::fmt::Arguments) {
    // 60.05 H3: a failed log write is dropped (eprintln! would panic); 60.12 review: bounded (log_bounded)
    if logs::on(logs::Level::Info) {
        // 60.24 the signal / drain / shutdown lines are info
        log_bounded(format!("finalwisp: {msg}"));
    }
}

/// 20.17 / 60.04 F7 / 60.12 the main thread after startup: waits for signals (sigtimedwait: no signal handlers, so
/// no EINTR on the event loops). SIGHUP: reload the TLS certificates from the same files (a bad file keeps the old
/// set; without TLS only logged). SIGTERM/SIGINT: graceful shutdown: every worker accepts what is queued, closes its
/// listener and closes idle Wisp connections (WS 1001); the rest are served until they end or `drain` passes, then
/// all get 1001 and the process exits 0 once no connection is left (at most CLOSE_GRACE later). A second
/// SIGTERM/SIGINT, or `drain` 0, exits at once.
/// 60.12 C5-lite: `final_line` (with --metrics-interval) is logged once before the process exits.
fn signal_loop(certs: Option<&tls::Certs>, peers: &[Arc<net::Inbox>], drain: Duration, final_line: Option<&dyn Fn() -> String>) -> ! {
    const TICK: Duration = Duration::from_millis(100);
    const CLOSE_GRACE: Duration = Duration::from_secs(2);
    let set = signal_set();
    let live = || peers.iter().map(|p| p.load.load(std::sync::atomic::Ordering::Acquire)).sum::<usize>(); // 60.25 C5
    let tell = |stop: u8| {
        for p in peers {
            p.stop.store(stop, std::sync::atomic::Ordering::Relaxed);
            p.wake(); // the worker reads `stop` after the eventfd wakeup (inbox_ready)
        }
    };
    let mut phase: Option<(u8, std::time::Instant)> = None; // (stop state, its deadline) while shutting down
    loop {
        let sig = match phase {
            None => {
                let mut sig = 0;
                if unsafe { libc::sigwait(&set, &mut sig) } != 0 {
                    continue;
                }
                sig
            }
            Some(_) => {
                let ts = libc::timespec { tv_sec: 0, tv_nsec: TICK.as_nanos() as _ };
                unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &ts) } // -1 = tick (EAGAIN) or EINTR
            }
        };
        match sig {
            libc::SIGHUP if phase.is_some() => log(format_args!("SIGHUP: shutting down, not reloading")),
            libc::SIGHUP => match certs.map(|c| c.reload()) {
                None => log(format_args!("SIGHUP: no TLS certificates, nothing to reload")),
                Some(Ok(n)) => log(format_args!("SIGHUP: reloaded {n} TLS certificate(s)")),
                Some(Err(e)) => log(format_args!("SIGHUP: reload failed, keeping the current certificates: {e}")),
            },
            libc::SIGTERM | libc::SIGINT => {
                let name = if sig == libc::SIGTERM { "SIGTERM" } else { "SIGINT" };
                if phase.is_some() || drain.is_zero() {
                    log(format_args!("{name}: exiting now ({} connection(s) open)", live()));
                    exit0(final_line);
                }
                log(format_args!(
                    "{name}: shutting down: listeners closed, idle connections closed (1001); {} connection(s) open get up \
                     to {} s to finish (a second {name} exits now)",
                    live(),
                    drain.as_secs()
                ));
                phase = Some((net::STOP_DRAIN, std::time::Instant::now() + drain));
            }
            _ => {}
        }
        if let Some((stop, until)) = phase {
            // review: every `stopped` first (Acquire), then the loads: a connection accepted before a
            // listener closed is in `load` by then, and with every listener closed the sum can only fall
            if peers.iter().all(|p| p.stopped.load(std::sync::atomic::Ordering::Acquire)) && live() == 0 {
                log(format_args!("shutdown: no connection left, exiting"));
                exit0(final_line);
            }
            if std::time::Instant::now() < until {
                tell(stop);
            } else if stop == net::STOP_DRAIN {
                log(format_args!("shutdown: drain timeout: closing the {} remaining connection(s) (1001)", live()));
                phase = Some((net::STOP_CLOSE, std::time::Instant::now() + CLOSE_GRACE));
                tell(net::STOP_CLOSE);
            } else {
                log(format_args!("shutdown: exiting with {} connection(s) still closing", live()));
                exit0(final_line);
            }
        }
    }
}

/// 60.12 exit 0 (graceful shutdown done), the final metrics line first (bounded: log_bounded)
fn exit0(final_line: Option<&dyn Fn() -> String>) -> ! {
    logs::flush(Duration::from_millis(500)); // 60.24 connection lines still queued (no-op without --log-conns)
    if let Some(f) = final_line.filter(|_| logs::on(logs::Level::Info)) {
        log_bounded(f());
    }
    std::process::exit(0)
}

/// 60.12 review: the signal thread also ends the process, so its log lines must not keep it: a stderr write blocks
/// on a full pipe nobody reads (70.05), on a slow file or terminal, and on the std stderr lock while another thread's
/// write (the metrics line) is blocked there. The line is written by a short-lived thread (write(2) on fd 2, no lock);
/// this thread waits for it at most LOG_WAIT and goes on (a stuck writer ends with the process).
fn log_bounded(line: String) {
    const LOG_WAIT: Duration = Duration::from_millis(500);
    fn write_fd2(b: &[u8]) {
        let mut s = b;
        while !s.is_empty() {
            let n = unsafe { libc::write(2, s.as_ptr() as *const libc::c_void, s.len()) };
            if n <= 0 {
                if n < 0 && net::errno() == libc::EINTR {
                    continue;
                }
                break; // a dead pipe: dropped (60.05 H3)
            }
            s = &s[n as usize..];
        }
    }
    let b = std::sync::Arc::new(format!("{line}\n").into_bytes());
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let b2 = b.clone();
    let spawned = std::thread::Builder::new().name("lastlog".into()).spawn(move || {
        write_fd2(&b2);
        let _ = tx.send(());
    });
    match spawned {
        Ok(_) => {
            let _ = rx.recv_timeout(LOG_WAIT);
        }
        Err(_) => write_fd2(&b), // review: no thread (pids.max, memory): written inline (unbounded, as before 60.12)
    }
}

/// 20.18 Wisp v2 extensions from the command line. Exits on bad files; never prints secrets.
fn load_ext(udp: bool, auth_file: Option<&str>, cert_keys: &[String], motd: Option<String>) -> ext::Ext {
    let fail = |what: &str, path: &str, e: String| -> ! {
        eprintln!("finalwisp: {what} {path}: {e}");
        std::process::exit(1)
    };
    let passwords = match auth_file {
        None => Vec::new(),
        Some(p) => {
            use std::os::unix::fs::PermissionsExt;
            let text = std::fs::read_to_string(p).unwrap_or_else(|e| fail("--auth-file", p, e.to_string()));
            if std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o077 != 0) {
                say!(Warn, "finalwisp: warning: --auth-file {p} is readable by group/others (passwords are plaintext)");
            }
            ext::parse_auth_file(&text).unwrap_or_else(|e| fail("--auth-file", p, e))
        }
    };
    let mut keys = Vec::new();
    for p in cert_keys {
        let pem = std::fs::read(p).unwrap_or_else(|e| fail("--cert-auth-key", p, e.to_string()));
        keys.extend(ext::parse_key_pem(&pem).unwrap_or_else(|e| fail("--cert-auth-key", p, e)));
    }
    ext::Ext::new(udp, passwords, keys, motd)
}

/// 60.01 host limits for the startup capability line, read once from /proc/sys and getrlimit. A value
/// that cannot be read (containers often hide /proc/sys) is None: left out of the line, no warning.
#[derive(Default)]
struct Host {
    tcp_wmem_max: Option<u64>,
    tcp_rmem_max: Option<u64>,
    somaxconn: Option<u64>,
    tcp_mem_max: Option<u64>, // net.ipv4.tcp_mem[2] in bytes (pages x page size)
    tcp_fastopen: Option<u64>,
    nofile: Option<u64>, // RLIMIT_NOFILE soft limit
}

/// Below these the startup warns (it never changes anything).
const WARN_SOCK_MAX: u64 = 16 << 20;
const WARN_TCP_MEM: u64 = 512 << 20;
const WARN_SOMAXCONN: u64 = 4096; // net::listen asks for a backlog of 4096
const WARN_NOFILE: u64 = 65536;
const WARN_RTT_MS: u64 = 50;

/// 60.47 --park-rcvlock: the worker's receive-buffer floor (Config::park_rcvlock, kernel units: SO_RCVBUF as reported, i.e.
/// doubled) from the SO_BUF_LOCK probe and `limit` = 2 x net.core.rmem_max (net::rcvbuf_limit: a probe, not the sysctl,
/// which containers hide). SO_RCVBUF is clamped to that, so the floor stays at or below it (a raise never shrinks a
/// buffer); limit unknown: refused (a floor of 1 never raises: the 60.47 gold2 loss).
fn park_rcvlock_floor(buf_lock: Option<bool>, limit: Option<u64>) -> Result<u32, &'static str> {
    const FLOOR: u64 = 512 << 10;
    match buf_lock {
        Some(true) => limit.map(|m| FLOOR.min(m).max(1) as u32).ok_or("--park-rcvlock: the receive buffer limit probe failed"),
        Some(false) => Err("--park-rcvlock needs SO_BUF_LOCK (Linux 5.15 or later)"),
        None => Err("--park-rcvlock: the SO_BUF_LOCK probe failed"),
    }
}

fn sysctl(path: &str, field: usize) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.split_whitespace().nth(field)?.parse().ok()
}

fn mib(v: u64) -> String {
    if v >= 1 << 20 {
        let m = v as f64 / (1u64 << 20) as f64;
        if v.is_multiple_of(1 << 20) {
            format!("{m:.0} MiB")
        } else {
            format!("{m:.1} MiB")
        }
    } else {
        format!("{} KiB", v >> 10)
    }
}

impl Host {
    fn read() -> Host {
        let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        #[allow(clippy::unnecessary_cast)] // rlim_t is u32 on 32-bit GNU targets
        let nofile = (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0).then_some(rl.rlim_cur as u64);
        Host {
            tcp_wmem_max: sysctl("/proc/sys/net/ipv4/tcp_wmem", 2),
            tcp_rmem_max: sysctl("/proc/sys/net/ipv4/tcp_rmem", 2),
            somaxconn: sysctl("/proc/sys/net/core/somaxconn", 0),
            tcp_mem_max: sysctl("/proc/sys/net/ipv4/tcp_mem", 2)
                .and_then(|p| p.checked_mul(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64)),
            tcp_fastopen: sysctl("/proc/sys/net/ipv4/tcp_fastopen", 0),
            nofile,
        }
    }

    fn describe(&self) -> String {
        let mut v = Vec::new();
        if let Some(x) = self.tcp_wmem_max {
            v.push(format!("tcp_wmem max {}", mib(x)));
        }
        if let Some(x) = self.tcp_rmem_max {
            v.push(format!("tcp_rmem max {}", mib(x)));
        }
        if let Some(x) = self.tcp_mem_max {
            v.push(format!("tcp_mem max {}", mib(x)));
        }
        if let Some(x) = self.somaxconn {
            v.push(format!("somaxconn {x}"));
        }
        if let Some(x) = self.nofile {
            v.push(format!("nofile {x}"));
        }
        if v.is_empty() {
            "limits unreadable".to_string()
        } else {
            v.join(", ")
        }
    }

    fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        let low: Vec<(&str, u64)> = [("tcp_wmem", self.tcp_wmem_max), ("tcp_rmem", self.tcp_rmem_max)]
            .into_iter()
            .filter_map(|(n, v)| v.filter(|&v| v < WARN_SOCK_MAX).map(|v| (n, v)))
            .collect();
        if let Some(min) = low.iter().map(|x| x.1).min() {
            let names = low.iter().map(|(n, v)| format!("net.ipv4.{n} max {}", mib(*v))).collect::<Vec<_>>().join(", ");
            let rate = (min * 1000 / WARN_RTT_MS) >> 20;
            w.push(format!(
                "{names}: a single stream is limited to about {rate} MiB/s at {WARN_RTT_MS} ms RTT (max/RTT); \
                 raise net.ipv4.tcp_wmem/tcp_rmem for long fast links"
            ));
        }
        if let Some(x) = self.tcp_mem_max.filter(|&x| x < WARN_TCP_MEM) {
            w.push(format!(
                "net.ipv4.tcp_mem max {} < {}: under many fast streams the kernel enters TCP memory pressure and \
                 throttles every socket (seen on a 3 GB box at 100 streams x 1 Gbit/40 ms: 1.4 MiB/s total)",
                mib(x),
                mib(WARN_TCP_MEM)
            ));
        }
        if let Some(x) = self.somaxconn.filter(|&x| x < WARN_SOMAXCONN) {
            w.push(format!(
                "net.core.somaxconn {x} < {WARN_SOMAXCONN}: the listen backlog is cut to {x}; a burst of new connections may be dropped"
            ));
        }
        if let Some(x) = self.nofile.filter(|&x| x < WARN_NOFILE) {
            w.push(format!(
                "open file limit (RLIMIT_NOFILE) {x} < {WARN_NOFILE}: connections + streams are limited to about {x} sockets; \
                 raise it (ulimit -n, systemd LimitNOFILE=)"
            ));
        }
        w
    }
}

/// 70.12 static glibc build (crt-static): getaddrinfo must not dlopen NSS modules (/etc/nsswitch.conf entries
/// such as mymachines, resolve, mdns4_minimal, myhostname): that loads the host's libc.so.6 into this process,
/// and a host glibc other than the one linked crashed it (Ubuntu 24.04, glibc 2.39, `hosts: files compat dns`:
/// SIGFPE at the first lookup). files and dns are built into libc since 2.34: only those for hosts.
#[cfg(all(target_env = "gnu", target_feature = "crt-static"))]
fn nss_builtin_only() -> bool {
    extern "C" {
        fn __nss_configure_lookup(db: *const libc::c_char, service_line: *const libc::c_char) -> libc::c_int;
    }
    // SAFETY: a glibc-internal function (no header); the declaration above is our own assertion of its signature
    // (glibc nss/nsswitch.c: int __nss_configure_lookup(const char *dbname, const char *service_line)). Static glibc
    // builds only (the cfg), called once from main before any thread exists; both arguments are NUL-terminated literals.
    unsafe { __nss_configure_lookup(c"hosts".as_ptr(), c"files dns".as_ptr()) == 0 }
}
#[cfg(not(all(target_env = "gnu", target_feature = "crt-static")))]
fn nss_builtin_only() -> bool {
    false
}

/// 20.31 / 60.14: why B3 stays off, checked in this order (None = go on to mem::tcp_adapt_setup). The SO_BUF_LOCK probe is
/// only run when the earlier checks pass.
fn tcp_adapt_off_reason(adapt: bool, credit_v2: bool, budget_on: bool, buf_lock: impl Fn() -> Option<bool>) -> Option<&'static str> {
    if !adapt {
        Some("default; --tcpmem-adapt to enable")
    } else if !credit_v2 {
        Some("needs credit v2; --no-credit-v2 is set")
    } else if !budget_on {
        Some("needs the memory budget, which is off")
    } else {
        match buf_lock() {
            Some(true) => None,
            Some(false) => Some("no SO_BUF_LOCK, kernel < 5.15: capped sockets would stay capped"),
            None => Some("SO_BUF_LOCK probe failed"),
        }
    }
}

/// 60.30 C10a startup: the download cap relies on accepted sockets inheriting the listener's SO_MAX_PACING_RATE; check
/// it once (net::pacing_inherited) and refuse to start if the kernel gives an accepted socket another value. Returns the
/// capability-line part (`, pacing: ...`), empty when both caps are off.
fn check_pacing(pace: net::Pacing, splice_asked: bool) -> String {
    if pace == net::Pacing::default() {
        return String::new();
    }
    let rate = |r: u32| format!("{r} B/s = {:.1} Mbit/s", r as f64 * 8.0 / 1e6);
    let mut s = ", pacing:".to_string();
    if pace.download > 0 {
        match net::pacing_inherited(pace.download) {
            Some(true) => {}
            Some(false) => {
                eprintln!(
                    "finalwisp: --download-rate: this kernel refuses SO_MAX_PACING_RATE or does not pass a listener's value on \
                     to accepted sockets (self-check on 127.0.0.1); the cap would not apply"
                );
                std::process::exit(1)
            }
            None => say!(
                Warn,
                "finalwisp: warning: --download-rate: the inheritance self-check could not run (no 127.0.0.1?); cap not verified"
            ),
        }
        s += &format!(" download/conn {}", rate(pace.download));
        if splice_asked {
            s += " (splice off)";
        }
    }
    if pace.upload > 0 {
        s += &format!(" upload/stream {} (TCP streams only)", rate(pace.upload));
    }
    s
}

/// 60.20 C2 / C3b: None when every flag is off (no sockaddr at accept, no table, no header capture). 60.31 C7
/// --listen-unix forces it (its clients' header is read: the unix sentinel is trusted), and the TCP accept path still
/// asks for the peer only when a C2/C3b flag or --log-conns is on (Config::want_peer).
fn build_clientip(o: &cli::Opts) -> Option<Box<clientip::ClientIp>> {
    let per_ip = o.per_ip();
    (per_ip || !o.trusted_proxies.is_empty() || o.listen_unix.is_some()).then(|| {
        let sentinel = o.listen_unix.as_ref().map(|_| policy::Cidr::parse(&format!("{}/128", clientip::UNIX_PEER)).unwrap());
        Box::new(clientip::ClientIp {
            trusted: o.trusted_proxies.iter().copied().chain(sentinel).collect(),
            header: o.real_ip_header.clone().into(),
            table: per_ip.then(|| clientip::IpTable::with_rates(o.stream_rate, o.upload_rate_ip, o.conn_rate)), // (60.40, 60.45)
            max_conns: o.max_conns_per_ip,
        })
    })
}

fn main() {
    // 70.12 before any thread or lookup
    let nss_fixed = nss_builtin_only();
    // 60.12 the metrics epoch (uptime, time at each memory level)
    metrics::now_ms();
    // 60.05 H7: before any big allocation and before the threads exist (mem::pin_mmap_threshold)
    let malloc_pinned = mem::pin_mmap_threshold();
    let pool_max = pool::limits(); // 70.25 item 4: the process-wide chunk budget, before the workers
    let default_threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    // 60.20 C8: --config FILE is expanded into flags first (cli::expand_config); its errors also exit 2 here, before any socket
    let mut config_note = String::new();
    let o = cli::utf8_args(std::env::args_os().skip(1))
        .and_then(|a| cli::expand_config(a, read_config))
        .and_then(|ex| {
            if let Some(p) = &ex.config {
                config_note = format!(", config {p}");
            }
            let o = cli::parse_args(ex.args, default_threads);
            // 60.24 the file's warning waits for --log-level (an unparsable command line shows it with its error)
            if let Some(w) = &ex.warning {
                if o.as_ref().map_or(true, |o| o.log_level >= logs::Level::Warn) {
                    eprintln!("finalwisp: warning: {w}");
                }
            }
            o
        })
        .and_then(cli::check)
        .unwrap_or_else(|e| {
            if !e.is_empty() {
                eprintln!("finalwisp: {e}");
            }
            usage()
        });
    logs::set_level(o.log_level); // 60.24 before the first line it filters
    let mut tls_rekey = o.tls_rekey;
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    // 20.17 / 60.04 F7 / 60.12: SIGHUP, SIGTERM, SIGINT are handled by signal_loop. Block them here, before any thread
    // exists, so every thread inherits the mask and only that sigwait sees them.
    // 60.12 flag 1: an inherited SIG_IGN for SIGINT is kept (signal_set leaves it out)
    let set = signal_set();
    unsafe {
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    // 20.13 built-in TLS: handshake in rustls, then kTLS. Fails at startup if kTLS is unusable.
    let mut rekey_note = "";
    let (tls, certs) = if o.tls_pairs.is_empty() {
        (None, None)
    } else {
        let (cfg, certs, rekey) = tls::server_config(&o.tls_pairs, o.cipher_server_order).unwrap_or_else(|e| {
            eprintln!("finalwisp: {e}");
            std::process::exit(1)
        });
        rekey_note = match &rekey {
            _ if !tls::has_tls13(&cfg) => "rekey n/a: no TLS 1.3 suite",
            Ok(()) => "rekey yes",
            Err(_) => "rekey no",
        };
        if let Err(why) = rekey {
            // 20.17: without kernel rekey a KeyUpdate cannot work: none from us (TLS 1.3 then closes at
            // the 2^24 record limit like TLS 1.2), and a client KeyUpdate closes the connection.
            say!(
                Warn,
                "finalwisp: {why}: no TLS 1.3 KeyUpdate (--tls-rekey-records ignored); a client KeyUpdate \
                 closes the connection; connections close at the AEAD record limit (2^24 records per direction)"
            );
            tls_rekey = 0;
        }
        (Some(cfg), Some(certs))
    };
    let auth_note = match (o.auth_file.is_some(), o.cert_keys.len()) {
        (false, 0) => String::new(),
        (p, k) => format!(
            ", auth required:{}{}",
            if p { " password" } else { "" },
            if k > 0 { format!(" {k} key file(s)") } else { String::new() }
        ),
    };
    // 60.20 C2 / C3b, 60.31 C7 (before o.motd moves)
    let clientip = build_clientip(&o);

    // 60.27 C6 --upstream: parsed again (cli checked it), the proxy resolved here (upstream::resolve: getaddrinfo with the
    // search list, the operator's name, e.g. a Docker service) and every 30 s by the upstream-dns thread. With an
    // upstream: no UDP (Q1b: 0x48, extension 0x01 not advertised), no TFO to the proxy, no early DNS answers.
    let upstream = o.upstream.as_deref().map(|u| {
        let up = upstream::parse_url(u).unwrap_or_else(|e| {
            eprintln!("finalwisp: {e}");
            std::process::exit(2)
        });
        match upstream::resolve(&up.host, up.port) {
            Ok(a) => up.addrs.publish(Ok(a), metrics::now_ms()),
            Err(e) => {
                eprintln!("finalwisp: --upstream {}: the proxy host has no address ({e})", up.shown);
                std::process::exit(1)
            }
        }
        if u.contains('@') && std::env::args_os().any(|a| a == "--upstream") {
            say!(
                Warn,
                "finalwisp: warning: --upstream credentials on the command line may be readable by other local users \
(/proc/PID/cmdline); put them in --config FILE (mode 0600)"
            );
        }
        if up.http_auth.is_some() || up.socks_auth.is_some() {
            // (also on a private network: the path to the proxy is not ours to judge)
            say!(Warn, "finalwisp: warning: --upstream sends the proxy credentials in clear text (HTTP Basic / SOCKS RFC 1929)");
        }
        if up.remote_dns {
            say!(
                Warn,
                "finalwisp: warning: --upstream socks5h (--upstream-trust-dns): names are resolved by the proxy; loopback, \
private, own-address and --block-dest checks apply to IP literals only"
            );
        }
        upstream::start_refresh(&up);
        Box::new(up)
    });
    let udp_on = o.udp && upstream.is_none();
    let per_ip = o.per_ip(); // (before o.motd moves out)
    let ext = load_ext(udp_on, o.auth_file.as_deref(), &o.cert_keys, o.motd);
    let scheme = if tls.is_some() { "wss" } else { "ws" };
    let tls_note = match tls.as_deref() {
        Some(c) => format!("kTLS {} ({rekey_note})", tls::suite_names(c)),
        None => "TLS off".to_string(),
    };
    // 60.20 C1: the request rules (None when none is set) and the own-address snapshot (Q2, decision c: startup only)
    let policy = policy::Policy::new(&o.rules);
    let own = if o.allow_self {
        Vec::new()
    } else {
        net::own_addrs().unwrap_or_else(|e| {
            eprintln!(
                "finalwisp: cannot read the interface addresses (getifaddrs: {e}); --allow-self starts without the own-address check"
            );
            std::process::exit(1)
        })
    };
    let policy_note = {
        let mut p: Vec<String> = policy.iter().map(|p| p.summary.clone()).filter(|s| !s.is_empty()).collect();
        if !o.allow_dests.is_empty() || !o.block_dests.is_empty() {
            p.push(format!("dests +{} -{}", o.allow_dests.len(), o.block_dests.len()));
        }
        p.push(if o.allow_self { "own addresses allowed".to_string() } else { format!("own addresses blocked ({})", own.len()) });
        if o.allow_embedded {
            p.push("IPv4-embedding IPv6 allowed".to_string());
        }
        format!(", policy: {}", p.join(", "))
    };
    let clientip_note = match &clientip {
        None => String::new(),
        Some(c) => {
            let mut s = String::new();
            if !o.trusted_proxies.is_empty() {
                s += &format!(", client ip: {} trusted proxies (header {})", o.trusted_proxies.len(), c.header);
            }
            if per_ip {
                s += ", per-ip:";
                if c.max_conns > 0 {
                    s += &format!(" conns {}", c.max_conns);
                }
                if let Some((r, b)) = o.stream_rate {
                    s += &format!(" streams {r}/s burst {b}");
                }
                if let Some((r, b)) = o.conn_rate {
                    s += &format!(" new conns {r}/s burst {b}"); // 60.40
                }
                if let Some((r, b)) = o.upload_rate_ip {
                    s += &format!(" upload {r} B/s burst {b}");
                }
            }
            s
        }
    };
    // 60.34 PROXY protocol: which listeners require the header, and from how many TCP source ranges
    let proxy_note = match (o.proxy_tcp, o.proxy_unix) {
        (false, false) => String::new(),
        (t, u) => {
            let tcp = format!("tcp (from {} ranges)", o.proxy_from.len());
            let l: Vec<&str> = [t.then_some(tcp.as_str()), u.then_some("unix")].into_iter().flatten().collect();
            format!(", proxy protocol: {}", l.join(", "))
        }
    };
    let smtp_open =
        !o.rules.block_smtp && !policy::SMTP_PORTS.iter().all(|&p| policy.as_ref().is_some_and(|pol| pol.port_blocked(false, p)));
    let paced_client = o.pace.client_settings(o.splice, o.notsent_lowat);
    // 60.31 C7 bound before any worker exists (listen_unix sets the umask around bind; the workers register the fd)
    let unix_mode = o.unix_mode.unwrap_or(0o660);
    let unix = o.listen_unix.as_ref().map(|p| {
        Arc::new(net::listen_unix(p, unix_mode, o.threads.max(1)).unwrap_or_else(|e| {
            eprintln!("finalwisp: --listen-unix {}: {e}", p.display());
            std::process::exit(1)
        }))
    });
    // 60.47 --park-rcvlock: refused without SO_BUF_LOCK (a lock it could not lift would stay for the stream's life)
    let park_rcvlock = if o.park_rcvlock {
        park_rcvlock_floor(net::buf_lock_supported(), net::rcvbuf_limit()).unwrap_or_else(|e| {
            eprintln!("finalwisp: {e}");
            std::process::exit(2)
        })
    } else {
        0
    };
    let cfg = Arc::new(Config {
        addr: std::net::SocketAddr::new(o.ip, o.port),
        threads: o.threads.max(1),
        buffer: o.buffer.max(1),
        filter: net::Filter {
            allow_embedded: o.allow_embedded,
            allow_self: o.allow_self,
            ipv6: o.rules.ipv6,
            own: own.clone().into(),
            allow_dests: o.allow_dests.clone().into(),
            block_dests: o.block_dests.clone().into(),
            ..net::Filter::new(o.allow_loopback, o.allow_private)
        },
        connect_timeout: Duration::from_secs(o.connect_timeout),
        dns_own: o.dns_own,
        abort_close: o.abort_close,
        splice: paced_client.0, // 60.30 C10a (60.18 #17): splice off with a download cap
        balance: o.balance,
        tfo: o.tfo && upstream.is_none(), // 60.27 C6 no TFO to the proxy
        keepalive: o.keepalive,
        tls,
        udp: udp_on,
        tls_rekey,
        notsent_lowat: paced_client.1, // 60.30 C10a 1/8 s of the cap
        adapt_lowat: worker::adapt_lowat(paced_client.1, o.pace.download),
        prio: o.prio,
        ext,
        credit_v2: o.credit_v2,
        credit_pace: o.credit_pace,
        park_rcvlock,
        adaptive_splice: o.adaptive_splice,
        conn_gate: (o.max_conns > 0).then(|| Arc::new(net::ConnGate::new(o.max_conns))),
        max_streams_per_conn: o.max_streams_per_conn,
        policy: policy.map(Box::new),
        // (60.31 C7: not for --listen-unix alone: a unix client's peer is the sentinel, set without a sockaddr)
        want_peer: per_ip || !o.trusted_proxies.is_empty() || ((o.log_conns || o.log_streams) && o.log_level >= logs::Level::Info),
        clientip,
        log_conns: o.log_conns && o.log_level >= logs::Level::Info, // 60.24 connection lines are info (review)
        log_streams: o.log_streams && o.log_level >= logs::Level::Info, // 60.35 stream lines are info too
        pace: o.pace,
        unix,
        upstream,
        upload_rate: o.upload_rate, // 60.25 C10b
        proxy_tcp: o.proxy_tcp,     // 60.34
        proxy_unix: o.proxy_unix,
        proxy_from: o.proxy_from.clone().into(),
        dest_rate: (o.dest_rate.is_some() || o.dest_rate_min.is_some())
            .then(|| Box::new(destrate::DestTable::new(o.dest_rate, o.dest_rate_min))), // 60.39
    });
    if let Some(g) = &cfg.conn_gate {
        let _ = metrics::GATE.set(g.clone()); // 60.20 C3a conns_reserved in the metrics line
    }
    if let Err(e) = net::ensure_port_free(&cfg.addr) {
        eprintln!("finalwisp: {} is already in use ({e}); is another server running?", cfg.addr);
        std::process::exit(1)
    }
    // 60.30 C10a (exits if the kernel does not inherit it)
    let pacing_note = check_pacing(cfg.pace, o.splice);

    // 60.29 C5 bound before the workers start: a taken port is a startup error, not an endpoint missing later
    let metrics_listener = o.metrics_listen.map(|a| {
        std::net::TcpListener::bind(a).unwrap_or_else(|e| {
            eprintln!("finalwisp: --metrics-listen {a}: cannot listen: {e}");
            std::process::exit(2)
        })
    });
    let membudget = (o.mem_budget != Some(0)).then(|| mem::detect(o.mem_budget));
    if let Some((b, _)) = &membudget {
        if *b > 0 {
            mem::WORKER_BUDGET.store((*b / cfg.threads as u64) as usize, std::sync::atomic::Ordering::Relaxed);
            // review: the floor level is in place before the first accept (the sampler starts later)
            mem::FLOOR.store(mem::floor(*b) as u8, std::sync::atomic::Ordering::Relaxed);
            mem::LEVEL.store(mem::floor(*b) as u8, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let own_dns = o.dns_own.then(|| Arc::new(dns::Resolver::new(o.dns_servers.clone()).ipv4_only(!o.rules.ipv6)));
    let dns = net::start_dns_pool(o.dns_threads.max(1), own_dns.clone(), !o.rules.ipv6, cfg.upstream.is_none());
    let peers: Arc<Vec<Arc<net::Inbox>>> = Arc::new((0..cfg.threads).map(|_| net::Inbox::new()).collect());
    let stats: Arc<Vec<Arc<metrics::Stats>>> = Arc::new((0..cfg.threads).map(|_| Arc::new(metrics::Stats::new())).collect());
    for i in 0..cfg.threads {
        let w = Worker::new(cfg.clone(), dns.clone(), i, peers.clone(), stats[i].clone()).unwrap_or_else(|e| {
            eprintln!("finalwisp: bind {}: {e}", cfg.addr);
            std::process::exit(1)
        });
        // detached: the workers run forever (a panic aborts the process, panic = "abort")
        std::thread::Builder::new()
            .name(format!("w{i}"))
            .spawn(move || {
                mem::cache_on(); // 70.25 the pool for this worker (its dirty set is trimmed by each idle sweep)
                w.run()
            })
            .unwrap();
    }
    let v2_note = if cfg.credit_v2 { ", upload credit v2" } else { "" }; // 20.30
    let pace_note = if cfg.credit_pace { ", credit pace" } else { "" }; // 60.42
    let lock_note = if cfg.park_rcvlock != 0 { ", park rcvlock" } else { "" }; // 60.47
    let splice_note = if cfg.adaptive_splice && cfg.splice { ", adaptive splice" } else { "" }; // 60.46 (inert without splice)
    say!(
        Info,
        "finalwisp listening on {scheme}://{}/ ({} threads, buffer {}{v2_note}{pace_note}{lock_note}{splice_note}{auth_note})",
        cfg.addr,
        cfg.threads,
        cfg.buffer
    );
    if let Some(u) = &cfg.unix {
        // 60.31 C7 plain ws:// whatever the TCP listener speaks; who may connect = the file's mode and directory
        say!(
            Info,
            "finalwisp listening on unix:{} (ws://, mode {unix_mode:03o}; its peers' client-IP header is believed)",
            u.path.display()
        );
        if cfg.pace.download > 0 {
            say!(Warn, "finalwisp: warning: --download-rate does not cap --listen-unix clients (no TCP pacing on a unix socket)");
        }
    }
    // 20.26 memory budget: the sampler raises a pressure level; workers shrink queues, cap socket
    // buffers and stop admitting new streams/connections instead of running into the OOM killer.
    // 60.01 the budget is part of the startup capability line (below), with the host's limits.
    // M3: an inherited v1 limit whose usage we cannot read (siblings share it): warn once, after the capability line
    let mem_warn = match (&membudget, o.mem_budget) {
        (Some((b, mem::Source::CgroupV1 { hidden: true, .. })), None) => Some(format!(
            "cgroup v1 memory limit {} MiB comes from an ancestor above our cgroup mount (e.g. a pod); its usage includes \
             siblings finalwisp cannot see, so the budget counts only our own usage and the ancestor can run out first; \
             set --mem-budget to this server's safe share",
            b >> 20
        )),
        // 60.16: MemTotal unreadable (host mode, no cgroup limit) gives a budget of 0: off, and say why
        (Some((0, mem::Source::Host | mem::Source::HostSock(_))), None) => {
            Some("memory budget off: no cgroup limit and /proc/meminfo is unreadable; set --mem-budget".to_string())
        }
        _ => None,
    };
    // 20.31 B3 --tcpmem-adapt (default off, 60.14): needs credit v2 (without it, level-0 credit moves into the heap when the
    // caps apply: loopback upload 0.36x, peak 6 -> 201 MiB, 60.14), the sampler (memory budget on) and SO_BUF_LOCK (Linux
    // 5.15+: without it a socket capped during an episode would stay capped for its life, without autotuning). Startup only.
    let gate = tcp_adapt_off_reason(o.tcpmem_adapt, o.credit_v2, membudget.as_ref().is_some_and(|(b, _)| *b > 0), net::buf_lock_supported);
    let (tcp_adapt, tcp_note) = if let Some(why) = gate {
        (None, format!("tcpmem adapt off ({why})"))
    } else {
        match mem::tcp_adapt_setup() {
            Err(e) => (None, format!("tcpmem adapt disabled: {e}")),
            Ok(t) => {
                let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
                let n = format!(
                    "tcpmem adapt on (level 1 from {} to below {}, tcp_mem[1] {}; own share: {} sock)",
                    mib(t.enter_pages() * page),
                    mib(t.exit_pages() * page),
                    mib(t.mem[1] * page),
                    t.own_stat.display()
                );
                (Some(t), n)
            }
        }
    };
    let mut tcp_adapt = tcp_adapt;
    let mem_note = match membudget {
        None => "memory budget off (--mem-budget 0)".to_string(),
        Some((budget, src)) => {
            let from = match (&src, o.mem_budget) {
                (_, Some(_)) => "--mem-budget".to_string(),
                (mem::Source::Cgroup(d), None) => format!("cgroup limit {}", d.display()),
                (mem::Source::CgroupV1 { dir, hidden: false }, None) => format!("cgroup v1 limit {}", dir.display()),
                (mem::Source::CgroupV1 { dir, hidden: true }, None) => {
                    format!("cgroup v1 limit of a hidden ancestor, seen from {} (see the warning)", dir.display())
                }
                (mem::Source::Host | mem::Source::HostSock(_), None) => "MemTotal/2".to_string(),
            };
            let usage = match &src {
                mem::Source::Cgroup(_) => "cgroup memory.current - inactive_file".to_string(),
                mem::Source::CgroupV1 { .. } => "cgroup v1 memory.usage_in_bytes - total_inactive_file".to_string(),
                mem::Source::Host => "heap + host TCP memory above its level at startup / while idle".to_string(),
                // 60.15 T03 P3
                mem::Source::HostSock(d) => format!("heap + our socket memory, {}/memory.stat sock", d.display()),
            };
            let small = if mem::floor(budget) > 0 { ", small: level 1 from the start" } else { "" };
            // 60.16: a host-mode budget of 0 means MemTotal was unreadable: off, and say why (not "0 MiB")
            let note = if budget == 0 && o.mem_budget.is_none() && matches!(src, mem::Source::Host | mem::Source::HostSock(_)) {
                "memory budget off (no cgroup limit, /proc/meminfo unreadable; see the warning)".to_string()
            } else {
                format!("memory budget {} MiB ({from}; usage = {usage}{small})", budget >> 20)
            };
            if budget > 0 {
                mem::start(budget, src, peers.clone(), tcp_adapt.take());
            }
            note
        }
    };
    let malloc_note = if let Some((at, max)) = malloc_pinned {
        let max = if max > 0 { max.to_string() } else { "unchanged".to_string() };
        format!("malloc: mmap threshold {}KiB, mmap_max {max}", at >> 10)
    } else if cfg!(target_env = "gnu") {
        "malloc: mallopt failed, glibc default thresholds".to_string()
    } else {
        "malloc: default (not glibc)".to_string()
    };
    // 70.25 item 4: the pool's chunk budget (max_map_count / 4, RLIMIT_AS or RLIMIT_DATA / 16); round 5 / 60.16: on, off
    // (with why), or on for some workers
    let malloc_note = match pool::refused(cfg.threads) {
        None => format!("{malloc_note}, pool on: chunks max {} (4 MiB; {})", pool_max.0, pool_max.1),
        Some(why) if why.starts_with("off") => format!("{malloc_note}, pool {why}"), // 60.16: the truth, not "on"
        Some(why) => format!("{malloc_note}, pool on for {why}: chunks max {} (4 MiB; {})", pool_max.0, pool_max.1),
    };
    let host = Host::read();
    let on = |b: bool| if b { "on" } else { "off" };
    // 60.27 C6 (password shown as ***)
    let upstream_note = cfg.upstream.as_deref().map_or(String::new(), |u| {
        let addrs: Vec<String> = u.addrs.snapshot().1.iter().map(|a| a.to_string()).collect();
        format!(", upstream {} ({}; {} DNS)", u.shown, addrs.join(" "), if u.remote_dns { "proxy" } else { "local" })
    });
    let tfo_note = match host.tcp_fastopen {
        Some(v) if cfg.tfo && v & 1 == 0 => format!("on (kernel client TFO off: net.ipv4.tcp_fastopen={v})"),
        _ => on(cfg.tfo).to_string(),
    };
    let keep_note = if cfg.keepalive {
        format!("dead peers {}s+{}x{}s", net::KEEP_IDLE, net::KEEP_CNT, net::KEEP_INTVL)
    } else {
        "dead peers off".to_string()
    };
    // 70.09 which resolver; a resolv.conf without a usable nameserver falls back to 127.0.0.1 (glibc's default)
    let dns_note = own_dns.as_ref().map_or("DNS getaddrinfo".to_string(), |r| format!("DNS {}", r.describe()));
    if own_dns.is_some()
        && o.dns_servers.is_empty()
        && dns::parse_resolv(&String::from_utf8_lossy(&std::fs::read("/etc/resolv.conf").unwrap_or_default())).servers.is_empty()
    {
        say!(Warn, "finalwisp: warning: --dns-own: no nameserver in /etc/resolv.conf, using 127.0.0.1");
    }
    // 60.20 C3a policy limits, only when set
    let limits_note = match (o.max_conns, o.max_streams_per_conn) {
        (0, 0) => String::new(),
        (c, s) => {
            let part = |n: u32, what: &str| (n > 0).then(|| format!(" {what} {n}"));
            format!(", limits:{}{}", part(c, "conns").unwrap_or_default(), part(s, "streams/conn").unwrap_or_default())
        }
    };
    // 60.25 C10b (the per-IP form is in the per-ip part)
    let limits_note =
        limits_note + &o.upload_rate.map_or(String::new(), |(r, b)| format!(", upload cap: {r} B/s burst {b} per connection"));
    // 60.39 per destination
    let limits_note = limits_note
        + &match (o.dest_rate, o.dest_rate_min) {
            (None, None) => String::new(),
            (s, m) => format!(
                ", per-dest:{}{}",
                s.map_or(String::new(), |(r, b)| format!(" streams {r}/s burst {b}")),
                m.map_or(String::new(), |n| format!(" streams {n}/min"))
            ),
        };
    // 80.01 F7: kernel, cgroup layout and SO_BUF_LOCK (F2), so a support report shows them without guessing
    let cgroup = mem::cgroup_mode(&std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default());
    let buflock = match net::buf_lock_supported() {
        Some(true) => "yes",
        Some(false) => "no (kernel < 5.15: sockets capped under memory pressure stay capped)",
        None => "unknown (probe failed)",
    };
    say!(
        Info,
        "finalwisp: capabilities: {} threads, {mem_note}, {tcp_note}, {malloc_note}{}, {}, splice {}, TFO {tfo_note}, {keep_note}, UDP {}, two-lane {}, {dns_note}{limits_note}{pacing_note}{policy_note}{clientip_note}{upstream_note}{proxy_note}{config_note}; \
         kernel: {}, cgroup: {cgroup}, buflock: {buflock}; host: {}",
        cfg.threads,
        if nss_fixed { ", static: hosts via files dns (nsswitch.conf ignored)" } else { "" },
        tls_note,
        on(cfg.splice),
        on(cfg.udp),
        on(cfg.prio),
        net::kernel_release(),
        host.describe()
    );
    for w in mem_warn.into_iter().chain(host.warnings()) {
        say!(Warn, "finalwisp: warning: {w}");
    }
    if o.trusted_proxies.iter().any(|c| *c == policy::Cidr::parse("0.0.0.0/0").unwrap() || *c == policy::Cidr::parse("::/0").unwrap()) {
        say!(Warn, "finalwisp: warning: --trusted-proxy trusts every address: any client can choose its own IP with the header");
    }
    if o.proxy_from.iter().any(|c| *c == policy::Cidr::parse("0.0.0.0/0").unwrap() || *c == policy::Cidr::parse("::/0").unwrap()) {
        // 60.34 (as --trusted-proxy): right only when the network lets nothing but the load balancer reach the port
        say!(Warn, "finalwisp: warning: --proxy-protocol-from accepts every address: any client that reaches the port can name its own IP");
    }
    if o.trusted_proxies.is_empty() && o.listen_unix.is_none() && o.real_ip_header != "x-forwarded-for" {
        // (60.31 C7 review: --listen-unix peers read it too)
        say!(Warn, "finalwisp: warning: --real-ip-header is ignored without --trusted-proxy or --listen-unix");
    }
    if smtp_open {
        // 60.02 Q3: open by default (the other servers too), one line so an operator decides
        say!(Info, "finalwisp: hint: mail ports 25/465/587 are open to clients; --block-smtp closes them");
    }
    if let (Some(l), Some(a)) = (metrics_listener, o.metrics_listen) {
        // 60.29 C5 (no auth: decision d, loopback by default); before logs::start, as the other startup lines
        if !a.ip().is_loopback() {
            say!(Warn, "finalwisp: warning: --metrics-listen {a} is not a loopback address and /metrics has no auth");
        }
        if let Err(e) = prom::serve(l, stats.clone(), peers.clone()) {
            eprintln!("finalwisp: --metrics-listen: cannot start its thread: {e}");
            std::process::exit(1)
        }
        say!(Info, "finalwisp: metrics on http://{a}/metrics (Prometheus)");
    }
    // 60.12 C5-lite: a metrics line every --metrics-interval seconds and one when the process exits (off by default)
    let final_line = || metrics::line("metrics_final", &stats, &peers);
    if cfg.log_conns || cfg.log_streams {
        // 60.24 the only writer of connection lines, after the startup lines (eprintln may write a line in parts); the
        // workers queue meanwhile
        logs::start();
    }
    if o.metrics_interval > 0 && logs::on(logs::Level::Info) {
        // 60.24 metrics lines are info
        metrics::start(Duration::from_secs(o.metrics_interval), stats.clone(), peers.clone());
    }
    // never returns; exits on SIGTERM/SIGINT
    signal_loop(
        certs.as_deref(),
        &peers,
        Duration::from_secs(o.drain_timeout),
        (o.metrics_interval > 0).then_some(&final_line as &dyn Fn() -> String),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_sentinel_trusted_only_with_listen_unix() {
        // 60.31 C7 (60.28 design review 2): --listen-unix forces a ClientIp whose trusted list holds the sentinel; without
        // it the sentinel is nobody's proxy (and no ClientIp exists when the C2/C3b flags are off)
        let o = |a: &str| cli::parse_args(a.split_whitespace().map(String::from), 1).unwrap();
        assert!(build_clientip(&o("")).is_none());
        let c = build_clientip(&o("--trusted-proxy 10.0.0.0/8")).unwrap();
        assert!(!c.is_trusted(clientip::UNIX_PEER) && c.is_trusted("10.1.2.3".parse().unwrap()));
        let c = build_clientip(&o("--listen-unix /run/x.sock")).unwrap();
        assert!(c.is_trusted(clientip::UNIX_PEER) && c.table.is_none() && c.trusted.len() == 1);
        assert!(!c.is_trusted("100::1".parse().unwrap()) && !c.is_trusted("::".parse().unwrap()), "exactly 100::");
        let c = build_clientip(&o("--listen-unix /run/x.sock --trusted-proxy 10.0.0.0/8 --max-conns-per-ip 3")).unwrap();
        assert!(c.is_trusted(clientip::UNIX_PEER) && c.is_trusted("10.1.2.3".parse().unwrap()) && c.table.is_some());
    }

    #[test]
    fn park_rcvlock_floor_rules() {
        // 60.47: 512 KiB, or the SO_RCVBUF limit (2 x rmem_max) below that (stock 425984); refused without SO_BUF_LOCK
        assert_eq!(park_rcvlock_floor(Some(true), Some(8 << 20)), Ok(512 << 10));
        assert_eq!(park_rcvlock_floor(Some(true), Some(425984)), Ok(425984));
        let lim = net::rcvbuf_limit().expect("probe");
        assert!(lim >= 4608 && lim.is_multiple_of(2), "2 x rmem_max: {lim}");
        assert_eq!(park_rcvlock_floor(Some(true), Some(0)), Ok(1));
        assert!(park_rcvlock_floor(Some(true), None).is_err()); // (refused: a floor of 1 never raises, a measured loss)
        assert!(park_rcvlock_floor(Some(false), Some(1 << 20)).unwrap_err().contains("SO_BUF_LOCK"));
        assert!(park_rcvlock_floor(None, Some(1 << 20)).is_err());
        for e in [park_rcvlock_floor(Some(false), None), park_rcvlock_floor(None, None), park_rcvlock_floor(Some(true), None)] {
            assert!(!e.unwrap_err().contains(|c| cli::REDACTION_MARKS.contains(c)));
        }
    }

    #[test]
    fn tcp_adapt_gate() {
        // 60.14: B3 is opt-in and requires credit v2 (B3 alone moves level-0 credit into the heap)
        let yes = || Some(true);
        assert_eq!(tcp_adapt_off_reason(false, true, true, yes), Some("default; --tcpmem-adapt to enable"));
        assert_eq!(tcp_adapt_off_reason(true, false, true, yes), Some("needs credit v2; --no-credit-v2 is set"));
        assert_eq!(tcp_adapt_off_reason(true, true, false, yes), Some("needs the memory budget, which is off"));
        assert!(tcp_adapt_off_reason(true, true, true, || Some(false)).unwrap().starts_with("no SO_BUF_LOCK"));
        assert_eq!(tcp_adapt_off_reason(true, true, true, || None), Some("SO_BUF_LOCK probe failed"));
        assert_eq!(tcp_adapt_off_reason(true, true, true, yes), None);
        let probed = std::cell::Cell::new(false);
        assert!(tcp_adapt_off_reason(true, false, true, || {
            probed.set(true);
            Some(true)
        })
        .is_some());
        assert!(!probed.get(), "no SO_BUF_LOCK probe when an earlier check already says off");
    }

    #[test]
    fn host_warnings_only_below_the_limits() {
        let good = Host {
            tcp_wmem_max: Some(32 << 20),
            tcp_rmem_max: Some(16 << 20),
            somaxconn: Some(4096),
            tcp_mem_max: Some(512 << 20),
            tcp_fastopen: Some(1),
            nofile: Some(1 << 20),
        };
        assert!(good.warnings().is_empty());
        assert!(Host::default().warnings().is_empty(), "unreadable values: no warning");
        assert_eq!(Host::default().describe(), "limits unreadable");
        let low = Host {
            tcp_wmem_max: Some(4 << 20),
            tcp_rmem_max: Some(6 << 20),
            somaxconn: Some(128),
            tcp_mem_max: Some(256 << 20),
            tcp_fastopen: None,
            nofile: Some(1024),
        };
        let w = low.warnings();
        assert_eq!(w.len(), 4);
        assert!(
            w[0].starts_with(
                "net.ipv4.tcp_wmem max 4 MiB, net.ipv4.tcp_rmem max 6 MiB: a single stream is limited to about 80 MiB/s at 50 ms RTT"
            ),
            "{}",
            w[0]
        );
        assert!(w[1].starts_with("net.ipv4.tcp_mem max 256 MiB < 512 MiB: under many fast streams"), "{}", w[1]);
        assert!(w[2].contains("somaxconn 128 < 4096") && w[3].contains("1024 < 65536"));
        assert_eq!(low.describe(), "tcp_wmem max 4 MiB, tcp_rmem max 6 MiB, tcp_mem max 256 MiB, somaxconn 128, nofile 1024");
        assert_eq!(mib(6 << 19), "3 MiB");
        assert_eq!(mib(212992), "208 KiB");
        assert_eq!(mib(1572864), "1.5 MiB");
    }
}
