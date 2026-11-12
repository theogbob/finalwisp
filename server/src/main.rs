//! 20.01 finalwisp — entry point. See note 10.01 and the roadmap (60.01).
//! unsafe (60.16): blocks without their own SAFETY comment are plain libc calls whose pointer arguments come from a
//! live local or slice with the length taken from the same value (or are plain integers); no pointer outlives the call.
mod bounds; // 60.63
mod cli;
mod clientip;
mod credit;
mod destrate; // 60.39
mod dns;
mod ext;
mod fdgate; // 60.57
mod hints; // 60.59
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
mod ui; // 60.60
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

/// 60.60 the colours of stderr (ui::Paint::of: only on a terminal), decided once
fn paint() -> ui::Paint {
    static PAINT: std::sync::OnceLock<ui::Paint> = std::sync::OnceLock::new();
    *PAINT.get_or_init(|| ui::Paint::of(2))
}

/// 60.60 startup warnings and hints wait here until the start block is printed (the first line a reader sees is
/// `finalwisp listening on ...`), then go straight to stderr. None: the block was printed.
static HELD: std::sync::Mutex<Option<Vec<String>>> = std::sync::Mutex::new(Some(Vec::new()));

/// Print the held warnings and stop holding. Also runs at exit (atexit), so a start that fails still shows them, after
/// its error line.
extern "C" fn release_notes() {
    let held = HELD.lock().map(|mut h| h.take()).unwrap_or_default();
    for line in held.into_iter().flatten() {
        eprintln!("{line}");
    }
}

/// 60.60 one warning or hint at its --log-level: what, the effect, the fix. On a terminal it is wrapped at 80 columns
/// (at most 2 lines for the built-in texts) and the word is coloured; in a file, a pipe or journald it is one line, as
/// every log line (one event, one line: grep and log collectors see the whole text).
fn note(level: logs::Level, kind: &str, text: &str) {
    if !logs::on(level) {
        return;
    }
    static TTY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    // SAFETY: isatty only reads the descriptor number
    let line = match *TTY.get_or_init(|| unsafe { libc::isatty(2) } == 1) {
        true => paint().note(kind, text),
        false => format!("finalwisp: {kind}: {text}"),
    };
    match HELD.lock().as_deref_mut() {
        Ok(Some(held)) => held.push(line),
        _ => eprintln!("{line}"),
    }
}

fn warn(text: &str) {
    note(logs::Level::Warn, "warning", text)
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
                    "{name}: shutting down: no new connections; {} open connection(s) get up to {} s to finish (a second \
                     {name} exits now)",
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
                log(format_args!("shutdown: drain timeout: closing the {} remaining connection(s)", live()));
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
                warn(&format!("--auth-file {p} is readable by group and others, and its passwords are plain text. Fix: chmod 600 it."));
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
    nofile: Option<u64>, // RLIMIT_NOFILE soft limit (read after the raise of 60.57 A1)
    /// 60.57 the raise was not asked for (--no-nofile-raise) and the hard limit is this high, WARN_NOFILE or more
    /// (`kept_below`): the fix of the open-file warning is then to drop the option
    nofile_kept_below: Option<u64>,
}

/// Below these the startup warns (it never changes anything).
const WARN_SOCK_MAX: u64 = 16 << 20;
const WARN_TCP_MEM: u64 = 512 << 20;
const WARN_SOMAXCONN: u64 = 4096; // net::listen asks for a backlog of 4096
const WARN_NOFILE: u64 = 65536;
const WARN_RTT_MS: u64 = 50;
/// 60.60 the key of the start block's row for socket buffers below WARN_SOCK_MAX (Host::buffer_row). Not longer than
/// `open files`: the block's key column keeps its width, so no other row moves when this one is there.
const BUFFER_ROW: &str = "TCP buffer";

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
            nofile_kept_below: None,
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

    /// What an operator can act on, at the default log level: (what, the effect. Fix: the fix). Each fits 2 lines.
    fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if let Some(x) = self.nofile.filter(|&x| x < WARN_NOFILE) {
            // 60.57 the server raised its soft limit to the hard limit, so the hard limit is what to raise (the two
            // forms below set both); with --no-nofile-raise and a higher hard limit the fix is the option itself
            w.push(match self.nofile_kept_below {
                Some(hard) => format!(
                    "open-file limit {x}: it caps connections plus streams. \
                     Fix: start without --no-nofile-raise (the hard limit is {}).",
                    if hard == fdgate::INF { "unlimited".to_string() } else { hard.to_string() }
                ),
                None => format!(
                    "open-file limit {x}: it caps connections plus streams. \
                     Fix: LimitNOFILE={WARN_NOFILE} in the systemd unit, or docker --ulimit nofile={WARN_NOFILE}."
                ),
            });
        }
        if let Some(x) = self.tcp_mem_max.filter(|&x| x < WARN_TCP_MEM) {
            w.push(format!(
                "net.ipv4.tcp_mem max {} (below {}): under many fast streams the kernel throttles every socket. \
                 Fix: raise net.ipv4.tcp_mem.",
                mib(x),
                mib(WARN_TCP_MEM)
            ));
        }
        if let Some(x) = self.somaxconn.filter(|&x| x < WARN_SOMAXCONN) {
            w.push(format!(
                "net.core.somaxconn {x} (below {WARN_SOMAXCONN}): a burst of new connections may be dropped. \
                 Fix: raise net.core.somaxconn."
            ));
        }
        w
    }

    /// The kernel's largest TCP socket buffers that are below WARN_SOCK_MAX: (sysctl, direction, bytes). Empty: none
    /// is (or neither could be read). The one condition of the start block's row and of the note.
    fn low_buffers(&self) -> Vec<(&'static str, &'static str, u64)> {
        [("tcp_wmem", "send", self.tcp_wmem_max), ("tcp_rmem", "receive", self.tcp_rmem_max)]
            .into_iter()
            .filter_map(|(n, dir, v)| v.filter(|&v| v < WARN_SOCK_MAX).map(|v| (n, dir, v)))
            .collect()
    }

    /// 60.60 the start block's `TCP buffer` row, present when low_buffers is not empty (the condition of the startup
    /// warning of v1.2.1): the sizes, what they are compared with, where the explanation is. One line of the block
    /// for every value (the key has the width of `open files`, so the other rows stand where they stood).
    fn buffer_row(&self) -> Option<String> {
        let low = self.low_buffers();
        let sizes = low.iter().map(|(_, dir, v)| format!("{} {dir}", mib(*v))).collect::<Vec<_>>().join(", ");
        (!low.is_empty()).then(|| format!("{sizes}: below {}, see --show-config", mib(WARN_SOCK_MAX)))
    }

    /// 60.60 true of nearly every host and no fault of a setting (the kernel's default tcp_wmem / tcp_rmem maximum is
    /// 4 / 6 MiB): the explanation is in --show-config and at --log-level debug; the start block has one row
    /// (buffer_row), and there is no warning
    fn notes(&self) -> Vec<String> {
        let low = self.low_buffers();
        let Some(min) = low.iter().map(|x| x.2).min() else { return Vec::new() };
        let names = low.iter().map(|(n, _, v)| format!("net.ipv4.{n} max {}", mib(*v))).collect::<Vec<_>>().join(", ");
        let rate = (min * 1000 / WARN_RTT_MS) >> 20;
        vec![format!(
            "{names}: a single stream is limited to about {rate} MiB/s at {WARN_RTT_MS} ms round trip (max / round \
             trip). Raise net.ipv4.tcp_wmem and tcp_rmem for long fast links."
        )]
    }
}

/// 60.60 the memory budget for the start block (plain words) and for the detail line (where it comes from, how usage
/// is measured). `budget`: mem::detect's result, None with --mem-budget 0; `over`: --mem-budget.
fn mem_texts(budget: &Option<(u64, mem::Source)>, over: Option<u64>) -> (String, String) {
    let (plain, detail, _) = mem_rows(budget, over);
    (plain, detail)
}

/// mem_texts, and as the third text how the memory in use is measured (its own row in --show-config: it can hold a
/// long cgroup path)
fn mem_rows(budget: &Option<(u64, mem::Source)>, over: Option<u64>) -> (String, String, String) {
    let none = |plain: &str, detail: &str| (plain.to_string(), detail.to_string(), "not measured".to_string());
    let Some((budget, src)) = budget else {
        return none("no budget (--mem-budget 0)", "memory budget off (--mem-budget 0)");
    };
    let host = matches!(src, mem::Source::Host | mem::Source::HostSock(_));
    // 60.16: a host-mode budget of 0 means MemTotal was unreadable: off, and say why (not "0 MiB")
    if *budget == 0 && over.is_none() && host {
        return none("no budget (see the warning)", "memory budget off (no cgroup limit, /proc/meminfo unreadable; see the warning)");
    }
    let (plain, from) = match (src, over) {
        (_, Some(_)) => ("--mem-budget", "--mem-budget".to_string()),
        (mem::Source::Cgroup(d), None) => ("the memory limit of this container or service", format!("cgroup limit {}", d.display())),
        (mem::Source::CgroupV1 { dir, hidden: false }, None) => {
            ("the memory limit of this container or service", format!("cgroup v1 limit {}", dir.display()))
        }
        (mem::Source::CgroupV1 { dir, hidden: true }, None) => (
            "a memory limit shared with other services",
            format!("cgroup v1 limit of a hidden ancestor, seen from {} (see the warning)", dir.display()),
        ),
        (mem::Source::Host | mem::Source::HostSock(_), None) => ("half of this machine's memory", "MemTotal/2".to_string()),
    };
    let usage = match src {
        mem::Source::Cgroup(_) => "cgroup memory.current - inactive_file".to_string(),
        mem::Source::CgroupV1 { .. } => "cgroup v1 memory.usage_in_bytes - total_inactive_file".to_string(),
        mem::Source::Host => "heap + host TCP memory above its level at startup / while idle".to_string(),
        // 60.15 T03 P3
        mem::Source::HostSock(d) => format!("heap + our socket memory, {}/memory.stat sock", d.display()),
    };
    let small = if mem::floor(*budget) > 0 { ", small: level 1 from the start" } else { "" };
    let mb = budget >> 20;
    (
        format!("up to {mb} MiB ({plain})"),
        format!("memory budget {mb} MiB ({from}; usage = {usage}{small})"),
        format!("{usage}{small} (the budget: {from})"),
    )
}

/// The warning for a memory budget that cannot work as meant (M3, 60.16), if any
fn mem_warning(budget: &Option<(u64, mem::Source)>, over: Option<u64>) -> Option<String> {
    match (budget, over) {
        // M3: an inherited v1 limit whose usage we cannot read (siblings share it)
        (Some((b, mem::Source::CgroupV1 { hidden: true, .. })), None) => Some(format!(
            "cgroup v1 limit {} MiB is shared with other services: the budget cannot see their memory. \
             Fix: --mem-budget with this server's share.",
            b >> 20
        )),
        // 60.16: MemTotal unreadable (host mode, no cgroup limit) gives a budget of 0: off, and say why
        (Some((0, mem::Source::Host | mem::Source::HostSock(_))), None) => {
            Some("no memory budget: no cgroup limit, and /proc/meminfo is unreadable. Fix: set --mem-budget.".to_string())
        }
        _ => None,
    }
}

/// The allocator part of the detail line: malloc thresholds (mem::pin_mmap_threshold's result) and the pool's chunk
/// budget (70.25 item 4: max_map_count / 4, RLIMIT_AS or RLIMIT_DATA / 16); round 5 / 60.16: on, off (with why), or on
/// for some workers
fn malloc_text(pinned: Option<(usize, usize)>, pool_max: &(usize, String), threads: usize) -> String {
    let malloc = if let Some((at, max)) = pinned {
        let max = if max > 0 { max.to_string() } else { "unchanged".to_string() };
        format!("malloc: mmap threshold {}KiB, mmap_max {max}", at >> 10)
    } else if cfg!(target_env = "gnu") {
        "malloc: mallopt failed, glibc default thresholds".to_string()
    } else {
        "malloc: default (not glibc)".to_string()
    };
    match pool::refused(threads) {
        None => format!("{malloc}, pool on: chunks max {} (4 MiB; {})", pool_max.0, pool_max.1),
        Some(why) if why.starts_with("off") => format!("{malloc}, pool {why}"), // 60.16: the truth, not "on"
        Some(why) => format!("{malloc}, pool on for {why}: chunks max {} (4 MiB; {})", pool_max.0, pool_max.1),
    }
}

fn buflock_text() -> &'static str {
    match net::buf_lock_supported() {
        Some(true) => "yes",
        Some(false) => "no (kernel < 5.15: sockets capped under memory pressure stay capped)",
        None => "unknown (probe failed)",
    }
}

/// 60.60 `--show-config`: the settings in effect and what this host allows, on stdout; exit 0. Nothing is opened or
/// started: no listener, no thread, and the files that options name (certificates, password files) are not read.
fn show_config(
    mut st: cli::Start,
    upstream_on_cmdline: bool,
    nss_fixed: bool,
    pinned: Option<(usize, usize)>,
    pool_max: &(usize, String),
) -> ! {
    let o = &st.opts;
    // what a start refuses from the options and this kernel alone is refused here too (exit 2, as there)
    if let Some(e) = o.park_rcvlock.then(|| park_rcvlock_floor(net::buf_lock_supported(), net::rcvbuf_limit()).err()).flatten() {
        // SAFETY: isatty only reads the descriptor number
        eprint!("{}", ui::usage_error(e, unsafe { libc::isatty(2) } == 1));
        std::process::exit(2)
    }
    // 60.57 A1 the raise as a start does it (this process exits), so the rows show what a start gets. A2: nothing is
    // opened here, so the fixed fds are the estimate.
    let nofile = fdgate::raise_nofile(o.nofile_raise);
    let host = host_after_raise(&nofile, o.nofile_raise);
    let workers = o.threads.max(1);
    let fd_budget = nofile.as_ref().map(|r| fdgate::budget(r.after.soft, fdgate::fixed_estimate(workers), o.dns_threads.max(1), workers));
    let budget = (o.mem_budget != Some(0)).then(|| mem::detect(o.mem_budget));
    let some = |v: Option<u64>, f: &dyn Fn(u64) -> String| v.map_or("unreadable".to_string(), f);
    let adapt = tcp_adapt_off_reason(o.tcpmem_adapt, o.credit_v2, budget.as_ref().is_some_and(|(b, _)| *b > 0), net::buf_lock_supported);
    let adapt_warning = adapt.filter(|_| o.tcpmem_adapt).map(|why| format!("--tcpmem-adapt is not in effect: {why}"));
    let mem = mem_rows(&budget, o.mem_budget);
    let mut rows = vec![
        ("kernel", net::kernel_release()),
        ("CPUs", std::thread::available_parallelism().map_or("unreadable".to_string(), |n| n.to_string())),
        ("memory budget", mem.0.trim_start_matches("up to ").to_string()),
        ("memory measured", mem.2),
        ("open files", nofile_detail(&nofile, o.nofile_raise)),
        (
            "kernel TCP memory",
            format!(
                "tcp_mem max {}, tcp_wmem max {}, tcp_rmem max {}; tcpmem adapt {}",
                some(host.tcp_mem_max, &mib),
                some(host.tcp_wmem_max, &mib),
                some(host.tcp_rmem_max, &mib),
                adapt.map_or("can be set up at start".to_string(), |why| format!("off ({why})"))
            ),
        ),
        ("listen backlog", some(host.somaxconn, &|n| format!("somaxconn {n}"))),
        ("TCP fast open", some(host.tcp_fastopen, &|v| format!("net.ipv4.tcp_fastopen={v}"))),
        ("dead peers", format!("closed after {} s idle + {} probes {} s apart", net::KEEP_IDLE, net::KEEP_CNT, net::KEEP_INTVL)),
        ("socket buffer lock", format!("{} (SO_BUF_LOCK)", buflock_text())),
        ("cgroup", mem::cgroup_mode(&std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default()).to_string()),
        ("allocator", malloc_text(pinned, pool_max, o.threads.max(1))),
    ];
    let lookups = match o.dns_own {
        true => dns::Resolver::new(o.dns_servers.clone()).ipv4_only(!o.rules.ipv6).describe(),
        false => "getaddrinfo".to_string(),
    };
    rows.push((
        "name lookups",
        if nss_fixed { format!("{lookups}; static build: hosts via files dns (nsswitch.conf ignored)") } else { lookups },
    ));
    rows.push((
        "own addresses",
        match (o.allow_self, net::own_addrs()) {
            (true, _) => "allowed as destinations (--allow-self)".to_string(),
            (false, Ok(a)) => format!("{} (blocked as destinations)", a.len()),
            (false, Err(e)) => format!("unreadable ({e}): the server would not start without --allow-self"),
        },
    ));
    if let Some(b) = &fd_budget {
        // (after `open files`)
        let at = rows.iter().position(|r| r.0 == "open files").map_or(rows.len(), |i| i + 1);
        let marks = fd_marks_note(b.usable, o.conn_share, o.fd_admission);
        if !marks.is_empty() {
            rows.insert(at, ("open-file marks", marks.trim_start_matches("; ").to_string()));
        }
        rows.insert(
            at,
            (
                "connections + streams",
                format!("about {} file descriptors (the limit less about {} fixed and {} in reserve)", b.usable, b.fixed, b.reserve),
            ),
        );
    }
    // 60.63 section E: which form of each guard this host allows (nothing is started here)
    let (bd, bd_warn) = bounds::build(o.tcpmem_share, o.port_share, o.dest_failfast, o.net_watch, o.upstream.is_some(), workers);
    rows.extend(bd.iter().flat_map(|b| b.describe()));
    let rows: Vec<(String, String)> = rows.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    // the warnings of a start that need nothing opened, in its order, then the notes
    let notes: Vec<String> = (st.warning.clone().into_iter())
        .chain(option_warnings(o, upstream_on_cmdline))
        .chain(raise_warning(&nofile))
        .chain(adapt_warning)
        .chain(fd_warnings(&nofile, fd_budget, o.conn_share || o.fd_admission))
        .chain(bd_warn)
        .chain(mem_warning(&budget, o.mem_budget))
        .chain(host.warnings())
        .chain(host.notes())
        .collect();
    // the setting's row shows the effect too (as cli::implied does for what the options alone decide)
    if let Some(why) = adapt.filter(|_| o.tcpmem_adapt) {
        if let Some(s) = st.settings.iter_mut().find(|s| s.key == "tcpmem-adapt") {
            s.value = format!("off ({why})");
        }
    }
    use std::io::Write as _;
    let ok = std::io::stdout().write_all(ui::show_config(ui::Paint::of(1), &st, &rows, &notes).as_bytes()).is_ok();
    std::process::exit(if ok { 0 } else { 1 })
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
            None => warn("--download-rate: the inheritance self-check could not run (no 127.0.0.1?); cap not verified"),
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

/// 60.58 how long a lookup may wait for a resolver thread: the connect timeout, at least 1 s (review: with
/// --connect-timeout 0 every lookup would expire before a thread could take it).
fn dns_expire(connect_timeout: Duration) -> Duration {
    connect_timeout.max(Duration::from_secs(1))
}

/// 60.57 A1 the host limits as the warnings need them: read after the raise
fn host_after_raise(nofile: &Option<fdgate::Raise>, raise: bool) -> Host {
    Host { nofile_kept_below: kept_below(nofile, raise), ..Host::read() }
}

/// 60.57 A1 the hard limit, when a start without --no-nofile-raise would end the open-file warning: the raise was not
/// asked for and the hard limit is at or above WARN_NOFILE. (A lower hard limit is what to raise, with the option or
/// without it. deliberate: fs.nr_open is not read here; a host that has it below WARN_NOFILE gets the option named
/// and, on the next start, the LimitNOFILE fix.)
fn kept_below(nofile: &Option<fdgate::Raise>, raise: bool) -> Option<u64> {
    nofile.as_ref().filter(|r| !raise && r.after.hard > r.after.soft && r.after.hard >= WARN_NOFILE).map(|r| r.after.hard)
}

/// 60.57 A1 what the raise itself reported (a failed call, a lowered hard limit). A start holds it right after the
/// raise, so it also comes out when the start fails later.
fn raise_warning(nofile: &Option<fdgate::Raise>) -> Option<String> {
    nofile.as_ref().and_then(|r| r.warn.clone())
}

/// 60.57 A1 the open-file limit in the start block: the limit in effect, and what it was when the server raised it
fn nofile_row(nofile: &Option<fdgate::Raise>) -> String {
    match nofile {
        None => "limit unreadable".to_string(),
        Some(r) if r.after.soft == fdgate::INF => "unlimited".to_string(),
        Some(r) if r.after.soft > r.before.soft => format!("up to {} (raised from {})", r.after.soft, r.before.soft),
        Some(r) => format!("up to {}", r.after.soft),
    }
}

/// 60.57 A1 the open-file limit in --show-config: soft and hard, and what the raise did
fn nofile_detail(nofile: &Option<fdgate::Raise>, raise: bool) -> String {
    let n = |v: u64| if v == fdgate::INF { "unlimited".to_string() } else { v.to_string() };
    let Some(r) = nofile else { return "unreadable".to_string() };
    let how = match () {
        () if r.after.soft > r.before.soft => format!("raised from {}", n(r.before.soft)),
        () if !raise => "not raised: --no-nofile-raise".to_string(),
        () => "not raised".to_string(),
    };
    format!("{} (the soft limit, RLIMIT_NOFILE; {how}; hard limit {})", n(r.after.soft), n(r.after.hard))
}

/// 60.57 A1 / A2 the warnings about the open-file limit that the limits alone decide (a start and --show-config):
/// an unreadable limit, or a limit that leaves fewer than fdgate::USABLE_WARN fds
fn fd_warnings(nofile: &Option<fdgate::Raise>, budget: Option<fdgate::Budget>, marks_asked: bool) -> Vec<String> {
    let Some(r) = nofile else {
        return vec![format!(
            "open-file limit unreadable: the server does not limit its file descriptors{}.",
            // 60.57 C (review: not silently)
            if marks_asked { ", and --conn-share and --fd-admission do nothing" } else { "" }
        )];
    };
    let low = budget.filter(|b| (b.usable as u64) < fdgate::USABLE_WARN).map(|b| {
        format!(
            "only {} file descriptors left for connections and streams (limit {}, {} fixed, {} reserve). \
             Fix: raise the open-file limit.",
            b.usable, r.after.soft, b.fixed, b.reserve
        )
    });
    low.into_iter().collect()
}

/// 60.57 C the marks for the startup line (empty with both flags off)
fn fd_marks_note(usable: u32, conn_share: bool, fd_admission: bool) -> String {
    let mut s = String::new();
    if conn_share {
        let (key, floor) = fdgate::share_rule(usable);
        s += &format!(
            "; --conn-share: from {} fds (3/4; until below {}) no new connections for an address that holds more than {key} \
             while others hold {floor} or more",
            fdgate::part16(usable, fdgate::SHARE_IN_16),
            fdgate::part16(usable, fdgate::SHARE_OUT_16)
        );
    }
    if fd_admission {
        s += &format!(
            "; --fd-admission: from {} fds (7/8; until below {}) no new connections",
            fdgate::part16(usable, fdgate::HOST_IN_16),
            fdgate::part16(usable, fdgate::HOST_OUT_16)
        );
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
            // (60.40, 60.45; 60.57 C --conn-share: the fds per address, summed in one slot per worker)
            table: per_ip.then(|| {
                let t = clientip::IpTable::with_rates(o.stream_rate, o.upload_rate_ip, o.conn_rate);
                if o.conn_share {
                    t.with_share(o.threads)
                } else {
                    t
                }
            }),
            max_conns: o.max_conns_per_ip,
        })
    })
}

/// 60.60 the warnings that the options alone decide (no file, socket or kernel probe), for the start and for
/// --show-config. `upstream_on_cmdline`: the command line holds an --upstream word.
fn option_warnings(o: &cli::Opts, upstream_on_cmdline: bool) -> Vec<String> {
    let mut w = Vec::new();
    let any = |list: &[policy::Cidr]| {
        list.iter().any(|c| *c == policy::Cidr::parse("0.0.0.0/0").unwrap() || *c == policy::Cidr::parse("::/0").unwrap())
    };
    if let Some((u, up)) = o.upstream.as_deref().and_then(|u| upstream::parse_url(u).ok().map(|up| (u, up))) {
        if u.contains('@') && upstream_on_cmdline {
            w.push(
                "--upstream credentials on the command line can be read by other local users (/proc/PID/cmdline). \
                 Fix: put the URL in a --config file with mode 0600."
                    .to_string(),
            );
        }
        if up.http_auth.is_some() || up.socks_auth.is_some() {
            // (also on a private network: the path to the proxy is not ours to judge)
            w.push("--upstream sends the proxy credentials in clear text (HTTP Basic / SOCKS RFC 1929)".to_string());
        }
        if up.remote_dns {
            w.push(
                "--upstream socks5h (--upstream-trust-dns): the proxy resolves the names, so the loopback, private, \
                 own-address and --block-dest checks apply to IP literals only"
                    .to_string(),
            );
        }
    }
    if o.listen_unix.is_some() && o.pace.download > 0 {
        w.push("--download-rate does not cap --listen-unix clients (no TCP pacing on a unix socket)".to_string());
    }
    if let Some(a) = o.metrics_listen.filter(|a| !a.ip().is_loopback()) {
        w.push(format!("--metrics-listen {a} is not a loopback address and /metrics has no auth"));
    }
    if any(&o.trusted_proxies) {
        w.push("--trusted-proxy trusts every address: any client can choose its own IP with the header".to_string());
    }
    if any(&o.proxy_from) {
        // 60.34 (as --trusted-proxy): right only when the network lets nothing but the load balancer reach the port
        w.push("--proxy-protocol-from accepts every address: any client that reaches the port can name its own IP".to_string());
    }
    if o.trusted_proxies.is_empty() && o.listen_unix.is_none() && o.real_ip_header != "x-forwarded-for" {
        // (60.31 C7 review: --listen-unix peers read it too)
        w.push("--real-ip-header is ignored without --trusted-proxy or --listen-unix".to_string());
    }
    if o.dns_reserve && o.dns_threads <= 1 {
        // 60.58 (net::dns_slow_cap: the slow clients keep at least one thread)
        w.push("--dns-reserve keeps no thread with 1 resolver thread. Fix: --dns-threads 2 or more (the default is 16)".to_string());
    }
    w
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
    // 60.60 the arguments to a command (cli::command: `--name=value`, the preset and the --config file, parse, check).
    // --help, --version and --print-preset print on stdout and exit 0; a usage error is 1 to 3 lines and exits 2.
    // Nothing is opened before this point.
    let argv = cli::utf8_args(std::env::args_os().skip(1));
    // (60.27: as before, any --upstream word of the command line counts, also one that a later --config file
    // overrides: the URL is in /proc/PID/cmdline all the same)
    let upstream_on_cmdline = argv.as_ref().is_ok_and(|a| a.iter().any(|w| w == "--upstream" || w.starts_with("--upstream=")));
    let cmd = argv.map_err(|e| (e, None)).and_then(|a| cli::command(a, default_threads, read_config));
    let st = match cmd {
        Ok(cli::Command::Start(st)) => *st,
        Ok(cli::Command::Special(s)) => {
            let text = match s {
                cli::Special::Help(None) => Ok(ui::help_main(ui::Paint::of(1))),
                cli::Special::Help(Some(topic)) => ui::help_topic(ui::Paint::of(1), &topic),
                cli::Special::Version => Ok(format!("finalwisp {}\n", ui::VERSION)),
                cli::Special::Preset(text) => Ok(text.to_string()), // 60.59 the preset's exact bytes
            };
            use std::io::Write as _;
            match text {
                Ok(t) => std::process::exit(if std::io::stdout().write_all(t.as_bytes()).is_ok() { 0 } else { 1 }),
                Err(e) => {
                    eprint!("{e}");
                    std::process::exit(2)
                }
            }
        }
        Err((e, warning)) => {
            // 60.24 an unparsable command line shows the config file's warning with its error
            if let Some(w) = warning {
                note(logs::Level::Warn, "warning", &w);
                release_notes();
            }
            // SAFETY: isatty only reads the descriptor number
            eprint!("{}", ui::usage_error(&e, unsafe { libc::isatty(2) } == 1));
            std::process::exit(2)
        }
    };
    logs::set_level(st.opts.log_level); // 60.24 before the first line it filters
    if st.show {
        show_config(st, upstream_on_cmdline, nss_fixed, malloc_pinned, &pool_max)
    }
    // the held warnings also come out when the start fails: at exit, and before a panic's message (the release
    // profile aborts on a panic, which skips atexit)
    // SAFETY: registers a function that takes no argument and touches only a static
    unsafe { libc::atexit(release_notes) };
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // (try_lock: a panic while this thread holds the queue must not wait for itself)
        let held = HELD.try_lock().ok().and_then(|mut h| h.take());
        for line in held.into_iter().flatten() {
            eprintln!("{line}");
        }
        report(info)
    }));
    for w in st.warning.iter().cloned().chain(option_warnings(&st.opts, upstream_on_cmdline)) {
        warn(&w);
    }
    let layer_rows = ui::layer_rows(&st); // 60.60 the start block's preset / config file / command line rows
    let cli::Start { opts: o, config, preset_line: preset_note, .. } = st;
    let config_note = config.map_or(String::new(), |p| format!(", config {p}"));
    let nofile = fdgate::raise_nofile(o.nofile_raise); // 60.57 A1 before any worker or listener
    if let Some(w) = raise_warning(&nofile) {
        warn(&w); // held with the other warnings of the start: after the block, or at exit when the start fails
    }
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
            warn(&format!(
                "{why}: a TLS 1.3 connection is closed after 2^24 records in one direction, or when the client asks \
                 for new keys. Fix: Linux 6.14 or later, or TLS at a reverse proxy."
            ));
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
    // 60.63 section E: the state the workers and the guard thread share (None: no option of it is on, or none can work
    // on this host). Built before the configuration: the options that are in effect decide whether a connection's
    // peer is kept. Installed before the workers are built; the thread starts after them.
    let (bd, bd_warn) = bounds::build(o.tcpmem_share, o.port_share, o.dest_failfast, o.net_watch, o.upstream.is_some(), o.threads.max(1));
    let bd = bd.map(Arc::new);
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
        // (60.58 --dns-share: the pool keys a lookup by the client's address)
        want_peer: per_ip
            || !o.trusted_proxies.is_empty()
            || ((o.log_conns || o.log_streams) && o.log_level >= logs::Level::Info)
            || o.dns_share
            // (60.63 E: the rules that are in effect key a stream by its client's address)
            || bd.as_ref().is_some_and(|b| b.opts & (bounds::OPT_TCPMEM | bounds::OPT_PORT | bounds::OPT_DEAD) != 0),
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
    // 60.58 a queued lookup expires after the connect timeout; --dns-share, --dns-reserve (cli: it sets dns_share)
    let stats: Arc<Vec<Arc<metrics::Stats>>> = Arc::new((0..cfg.threads).map(|_| Arc::new(metrics::Stats::new())).collect());
    let dns_sched =
        net::DnsSched { stats: stats.clone(), expire: dns_expire(cfg.connect_timeout), share: o.dns_share, reserve: o.dns_reserve };
    let dns = net::start_dns_pool(o.dns_threads.max(1), own_dns.clone(), !o.rules.ipv6, cfg.upstream.is_none(), dns_sched.clone());
    let peers: Arc<Vec<Arc<net::Inbox>>> = Arc::new((0..cfg.threads).map(|_| net::Inbox::new()).collect());
    // 60.57 A2 the fd count the workers share. Its limit F = soft limit - fixed fds - reserve is set once every worker is
    // built (their listeners, epoll and event fds are the fixed part) and before any of them runs.
    let fdg = Arc::new(fdgate::FdGate::unlimited());
    fdg.set_stats(stats.clone());
    fdgate::install(fdg.clone());
    if let Some(b) = &bd {
        bounds::install(b.clone());
    }
    let workers: Vec<Worker> = (0..cfg.threads)
        .map(|i| {
            Worker::new(cfg.clone(), dns.clone(), i, peers.clone(), stats[i].clone()).unwrap_or_else(|e| {
                eprintln!("finalwisp: bind {}: {e}", cfg.addr);
                std::process::exit(1)
            })
        })
        .collect();
    let fd_budget = nofile.as_ref().map(|r| {
        let open = fdgate::open_fds().unwrap_or_else(|| fdgate::fixed_estimate(cfg.threads));
        fdgate::budget(r.after.soft, open, o.dns_threads.max(1), cfg.threads)
    });
    if let Some(b) = &fd_budget {
        fdg.set_limit(b.usable, fdgate::block(b.usable, cfg.threads));
        // 60.57 C the marks in use (without a readable limit there is nothing to take parts of)
        fdg.set_marks(if o.conn_share { fdgate::MARK_SHARE } else { 0 } | if o.fd_admission { fdgate::MARK_HOST } else { 0 });
    }
    for (i, w) in workers.into_iter().enumerate() {
        // detached: the workers run forever (a panic aborts the process, panic = "abort")
        std::thread::Builder::new()
            .name(format!("w{i}"))
            .spawn(move || {
                mem::cache_on(); // 70.25 the pool for this worker (its dirty set is trimmed by each idle sweep)
                w.run()
            })
            .unwrap();
    }
    if let Some(b) = &bd {
        bounds::start(b.clone()); // 60.63
    }
    let v2_note = if cfg.credit_v2 { ", upload credit v2" } else { "" }; // 20.30
    let pace_note = if cfg.credit_pace { ", credit pace" } else { "" }; // 60.42
    let lock_note = if cfg.park_rcvlock != 0 { ", park rcvlock" } else { "" }; // 60.47
    let splice_note = if cfg.adaptive_splice && cfg.splice { ", adaptive splice" } else { "" }; // 60.46 (inert without splice)
                                                                                                // 60.60 the first line: tools wait for "listening on"; the details follow in the block and, at debug, in two lines
    say!(Info, "{}", paint().bold(&format!("finalwisp listening on {scheme}://{}/", cfg.addr)));
    if let Some(u) = &cfg.unix {
        // 60.31 C7 plain ws:// whatever the TCP listener speaks; who may connect = the file's mode and directory
        say!(
            Info,
            "finalwisp listening on unix:{} (ws://, mode {unix_mode:03o}; its peers' client-IP header is believed)",
            u.path.display()
        );
    }
    // 20.26 memory budget: the sampler raises a pressure level; workers shrink queues, cap socket
    // buffers and stop admitting new streams/connections instead of running into the OOM killer.
    let mem_warn = mem_warning(&membudget, o.mem_budget);
    let (mem_plain, mem_note) = mem_texts(&membudget, o.mem_budget);
    // 20.31 B3 --tcpmem-adapt (default off, 60.14): needs credit v2 (without it, level-0 credit moves into the heap when the
    // caps apply: loopback upload 0.36x, peak 6 -> 201 MiB, 60.14), the sampler (memory budget on) and SO_BUF_LOCK (Linux
    // 5.15+: without it a socket capped during an episode would stay capped for its life, without autotuning). Startup only.
    let gate = tcp_adapt_off_reason(o.tcpmem_adapt, o.credit_v2, membudget.as_ref().is_some_and(|(b, _)| *b > 0), net::buf_lock_supported);
    let (tcp_adapt, tcp_note) = if let Some(why) = gate {
        if o.tcpmem_adapt {
            warn(&format!("--tcpmem-adapt is not in effect: {why}")); // 60.60 (was only in the detail line)
        }
        (None, format!("tcpmem adapt off ({why})"))
    } else {
        match mem::tcp_adapt_setup() {
            Err(e) => {
                warn(&format!("--tcpmem-adapt is not in effect: {e}"));
                (None, format!("tcpmem adapt disabled: {e}"))
            }
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
    if let Some((budget, src)) = membudget {
        if budget > 0 {
            mem::start(budget, src, peers.clone(), tcp_adapt);
        }
    }
    let malloc_note = malloc_text(malloc_pinned, &pool_max, cfg.threads);
    let host = host_after_raise(&nofile, o.nofile_raise);
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
    // 60.58 --dns-share, --dns-reserve
    let dns_note = match (o.dns_share, o.dns_reserve) {
        (false, _) => dns_note,
        (true, false) => format!("{dns_note}, DNS share"),
        (true, true) => {
            let t = o.dns_threads.max(1);
            format!("{dns_note}, DNS share (reserve: {} of {t} threads)", t - net::dns_slow_cap(t))
        }
    };
    if own_dns.is_some()
        && o.dns_servers.is_empty()
        && dns::parse_resolv(&String::from_utf8_lossy(&std::fs::read("/etc/resolv.conf").unwrap_or_default())).servers.is_empty()
    {
        warn("--dns-own: no nameserver in /etc/resolv.conf, using 127.0.0.1");
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
    // 60.29 C5 (no auth: decision d, loopback by default); started before the block that names it
    let metrics_url = match (metrics_listener, o.metrics_listen) {
        (Some(l), Some(a)) => {
            if let Err(e) = prom::serve(l, stats.clone(), peers.clone()) {
                eprintln!("finalwisp: --metrics-listen: cannot start its thread: {e}");
                std::process::exit(1)
            }
            Some(format!("http://{a}/metrics"))
        }
        _ => None,
    };
    // 60.60 the start block: what a reader checks first, and every setting that is not the default (layer_rows)
    let row = |k: &str, v: String| (k.to_string(), v);
    let mut block = vec![
        row("version", ui::VERSION.to_string()),
        row("threads", cfg.threads.to_string()),
        row("memory", mem_plain),
        row("open files", nofile_row(&nofile)),
    ];
    block.extend(host.buffer_row().map(|v| row(BUFFER_ROW, v)));
    block.extend([row("TLS", if cfg.tls.is_some() { format!("on, {} certificate(s)", o.tls_pairs.len()) } else { "off".to_string() })]);
    block.extend(layer_rows);
    block.extend(metrics_url.map(|u| row("metrics", u)));
    say!(Info, "{}", ui::block(&block).trim_end());
    // The details, at --log-level debug (and, without a start, in --show-config): the line tools and bug reports read.
    // 80.01 F7: kernel, cgroup layout and SO_BUF_LOCK (F2), so a support report shows them without guessing
    say!(Debug, "finalwisp: start: {} threads, buffer {}{v2_note}{pace_note}{lock_note}{splice_note}{auth_note}", cfg.threads, cfg.buffer);
    let cgroup = mem::cgroup_mode(&std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default());
    let buflock = buflock_text();
    say!(
        Debug,
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
    if let Some(p) = &preset_note {
        say!(Debug, "finalwisp: {p}"); // 60.59 every setting of the preset with its layer
    }
    for n in host.notes() {
        say!(Debug, "finalwisp: note: {n}");
    }
    // 60.57 A1 the open-file limit as read back after the raise; A2 what of it connections and streams may use (the
    // start block has the limit; this is the detail line)
    if let (Some(r), Some(b)) = (&nofile, &fd_budget) {
        say!(
            Debug,
            "finalwisp: fds: {}{}; fixed {}, reserve {}, usable {} (client sockets, target sockets, splice pipes; over it new \
             connections are reset and new streams refused){}",
            r.describe(),
            if o.nofile_raise { "" } else { " (--no-nofile-raise)" },
            b.fixed,
            b.reserve,
            b.usable,
            fd_marks_note(b.usable, o.conn_share, o.fd_admission)
        );
    }
    for (label, text) in bd.iter().flat_map(|b| b.describe()) {
        say!(Debug, "finalwisp: {label}: {text}"); // 60.63 which form of each guard is active on this host
    }
    // 60.60 from here warnings go straight out: first the ones held since the start, then the host's and the settings'
    release_notes();
    for w in
        fd_warnings(&nofile, fd_budget, o.conn_share || o.fd_admission).into_iter().chain(bd_warn).chain(mem_warn).chain(host.warnings())
    {
        warn(&w);
    }
    if smtp_open {
        // 60.02 Q3: open by default (the other servers too), one hint so an operator decides
        note(logs::Level::Info, "hint", "mail ports 25, 465 and 587 are open to clients. Fix: --block-smtp (part of --preset public).");
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
    fn dns_expiry_follows_the_connect_timeout() {
        let s = Duration::from_secs;
        assert_eq!([0, 1, 10, 86400].map(|t| dns_expire(s(t))), [s(1), s(1), s(10), s(86400)]);
    }

    /// 60.58 --dns-reserve keeps a quarter of the threads, at least one, and leaves the slow clients at least one: with
    /// 1 thread it keeps none, and the start says so
    #[test]
    fn dns_reserve_needs_two_threads() {
        assert_eq!([0usize, 1, 2, 3, 4, 8, 16, 32].map(|t| t.max(1) - net::dns_slow_cap(t.max(1))), [0, 0, 1, 1, 1, 2, 4, 8]);
        let warns = |cmd: &str| {
            let o = cli::parse_args(cmd.split_whitespace().map(String::from), 4).unwrap();
            option_warnings(&o, false).iter().filter(|w| w.starts_with("--dns-reserve keeps no thread")).count()
        };
        assert_eq!([warns("--dns-reserve --dns-threads 1"), warns("--dns-reserve --dns-threads 0")], [1, 1]);
        assert_eq!(
            [
                warns("--dns-reserve"),
                warns("--dns-reserve --dns-threads 2"),
                warns("--dns-threads 1"),
                warns("--dns-share --dns-threads 1")
            ],
            [0; 4]
        );
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
            nofile_kept_below: None,
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
            nofile_kept_below: None,
        };
        // 60.60 what an operator can act on, each with its fix, in at most 2 lines of 80 columns
        let w = low.warnings();
        assert_eq!(w.len(), 3);
        assert!(w[0].starts_with("open-file limit 1024: it caps connections plus streams.") && w[0].contains("Fix: LimitNOFILE=65536"));
        assert!(w[1].starts_with("net.ipv4.tcp_mem max 256 MiB (below 512 MiB): under many fast streams the kernel throttles"), "{}", w[1]);
        assert!(w[2].starts_with("net.core.somaxconn 128 (below 4096)"), "{}", w[2]);
        for t in &w {
            let shown = ui::Paint(false).note("warning", t);
            assert!(t.contains(" Fix: ") && shown.lines().count() <= 2 && shown.lines().all(|l| l.len() <= ui::WIDTH), "{shown}");
            assert!(!t.contains("user"), "no count of users in a warning: {t}");
            // (the measured cost per user is in the docs)
        }
        // the socket buffer maximum is a note (--show-config, --log-level debug), not a warning
        let n = low.notes();
        assert_eq!(n.len(), 1);
        assert!(
            n[0].starts_with(
                "net.ipv4.tcp_wmem max 4 MiB, net.ipv4.tcp_rmem max 6 MiB: a single stream is limited to about 80 MiB/s at 50 ms"
            ),
            "{}",
            n[0]
        );
        assert!(good.notes().is_empty() && Host::default().notes().is_empty());
        // ... and one row of the start block: the sizes that are below the limit, the limit, where the detail is
        assert_eq!(low.buffer_row().as_deref(), Some("4 MiB send, 6 MiB receive: below 16 MiB, see --show-config"));
        let one = |w: u64, r: u64| Host { tcp_wmem_max: Some(w), tcp_rmem_max: Some(r), ..Host::default() }.buffer_row();
        assert_eq!(one(4 << 20, 32 << 20).as_deref(), Some("4 MiB send: below 16 MiB, see --show-config"));
        assert_eq!(one(64 << 20, 6 << 20).as_deref(), Some("6 MiB receive: below 16 MiB, see --show-config"));
        assert_eq!(one((16 << 20) - 1, 16 << 20).as_deref(), Some("16.0 MiB send: below 16 MiB, see --show-config"));
        assert_eq!(one(16 << 20, 16 << 20), None, "at the limit: no row");
        assert_eq!((good.buffer_row(), Host::default().buffer_row()), (None, None), "large or unreadable: no row");
        let unread = Host { tcp_wmem_max: None, tcp_rmem_max: Some(6 << 20), ..Host::default() };
        assert_eq!(unread.buffer_row().as_deref(), Some("6 MiB receive: below 16 MiB, see --show-config"));
        // the row and the note have one condition (the startup warning's of v1.2.1), and the row is no warning
        for (w, r) in [
            (0, 0),
            (4096, 1 << 20),
            (4 << 20, 6 << 20),
            ((16 << 20) - 1, 1 << 30),
            (1 << 30, (16 << 20) - 1),
            (16 << 20, 16 << 20),
            (1 << 30, 1 << 30),
        ] {
            let h = Host { tcp_wmem_max: Some(w), tcp_rmem_max: Some(r), ..Host::default() };
            assert_eq!(h.buffer_row().is_some(), w < WARN_SOCK_MAX || r < WARN_SOCK_MAX, "{w} {r}");
            assert_eq!(h.buffer_row().is_some(), !h.notes().is_empty(), "{w} {r}");
            assert!(h.warnings().is_empty(), "{w} {r}: the buffer sizes give no warning");
        }
        // one line of the block for every size, and no other row moves: with the row or without it, the values of
        // the block start in the same column (the key is not longer than `open files`)
        assert!(BUFFER_ROW.len() <= "open files".len());
        // (`wide`: with the block's longest key, `command line`, as when an option is given)
        let rows = |extra: Option<String>, wide: bool| {
            let mut b = vec![("version".to_string(), "1.3.0".to_string()), ("open files".to_string(), "up to 1024".to_string())];
            b.extend(extra.map(|v| (BUFFER_ROW.to_string(), v)));
            b.push(("TLS".to_string(), "off".to_string()));
            b.extend(wide.then(|| ("command line".to_string(), "port 7000".to_string())));
            ui::block(&b)
        };
        for wide in [false, true] {
            let without = rows(None, wide);
            for (w, r) in [(4 << 20, 6 << 20), ((16 << 20) - 1, (16 << 20) - 1), (1023 << 10, 1023 << 10), (4096, 87380), (0, 0)] {
                let with = rows(one(w, r), wide);
                let row: Vec<&str> = with.lines().filter(|l| l.starts_with("  TCP buffer  ")).collect();
                assert_eq!(row.len(), 1, "{with}");
                assert!(row[0].len() <= ui::WIDTH && row[0].is_ascii() && row[0].ends_with(", see --show-config"), "{}", row[0]);
                assert!(!row[0].contains("warning") && !row[0].contains('\u{1b}'));
                assert_eq!(with.lines().count(), without.lines().count() + 1, "one line, never wrapped: {with}");
                let rest: String = with.lines().filter(|l| !l.starts_with("  TCP buffer  ")).map(|l| format!("{l}\n")).collect();
                assert_eq!(rest, without, "the other rows are unchanged");
            }
        }
        assert_eq!(
            rows(one(4 << 20, 6 << 20), false).lines().nth(2),
            Some("  TCP buffer  4 MiB send, 6 MiB receive: below 16 MiB, see --show-config")
        );
        assert_eq!(
            rows(one(4 << 20, 6 << 20), true).lines().nth(2),
            Some("  TCP buffer    4 MiB send, 6 MiB receive: below 16 MiB, see --show-config")
        );
        assert_eq!(low.describe(), "tcp_wmem max 4 MiB, tcp_rmem max 6 MiB, tcp_mem max 256 MiB, somaxconn 128, nofile 1024");
        assert_eq!(mib(6 << 19), "3 MiB");
        assert_eq!(mib(212992), "208 KiB");
        assert_eq!(mib(1572864), "1.5 MiB");
    }

    /// 60.57 in the forms of 60.60: the open-file row of the start block and of --show-config, and the warnings (what,
    /// the effect, the fix; at most 2 lines of 80 columns; no count of users)
    #[test]
    fn open_file_rows_and_warnings() {
        use fdgate::{Limits, Raise, INF};
        let raise = |b: (u64, u64), a: (u64, u64)| {
            Some(Raise { before: Limits { soft: b.0, hard: b.1 }, after: Limits { soft: a.0, hard: a.1 }, warn: None })
        };
        let two_lines = |t: &str| {
            let shown = ui::Paint(false).note("warning", t);
            assert!(shown.lines().count() <= 2 && shown.lines().all(|l| l.len() <= ui::WIDTH) && !t.contains("user"), "{shown}");
        };
        // the block row: the limit in effect, and where it came from when the server raised it
        assert_eq!(nofile_row(&raise((1024, 524288), (524288, 524288))), "up to 524288 (raised from 1024)");
        assert_eq!(nofile_row(&raise((1024, 524288), (1024, 524288))), "up to 1024");
        assert_eq!(nofile_row(&raise((INF, INF), (INF, INF))), "unlimited");
        assert_eq!(nofile_row(&None), "limit unreadable");
        // --show-config: both limits and what the raise did
        assert_eq!(
            nofile_detail(&raise((1024, 524288), (524288, 524288)), true),
            "524288 (the soft limit, RLIMIT_NOFILE; raised from 1024; hard limit 524288)"
        );
        assert_eq!(
            nofile_detail(&raise((1024, INF), (1024, INF)), false),
            "1024 (the soft limit, RLIMIT_NOFILE; not raised: --no-nofile-raise; hard limit unlimited)"
        );
        assert_eq!(
            nofile_detail(&raise((4096, 4096), (4096, 4096)), true),
            "4096 (the soft limit, RLIMIT_NOFILE; not raised; hard limit 4096)"
        );
        assert_eq!(nofile_detail(&None, true), "unreadable");
        // a low limit: the fix is the hard limit, or the option when --no-nofile-raise keeps the soft limit below it
        for (soft, kept, fix) in [
            (1024, None, "Fix: LimitNOFILE=65536 in the systemd unit, or docker --ulimit nofile=65536."),
            (65535, None, "Fix: LimitNOFILE=65536 in the systemd unit, or docker --ulimit nofile=65536."),
            (1024, Some(1048576), "Fix: start without --no-nofile-raise (the hard limit is 1048576)."),
            (1024, Some(INF), "Fix: start without --no-nofile-raise (the hard limit is unlimited)."),
        ] {
            let w = Host { nofile: Some(soft), nofile_kept_below: kept, ..Host::default() }.warnings();
            assert_eq!(w, [format!("open-file limit {soft}: it caps connections plus streams. {fix}")]);
            two_lines(&w[0]);
        }
        // the option is the fix only when it was given and the hard limit is high enough to end the warning
        for (limits, raised, want) in [
            ((1024, 1048576), false, Some(1048576)),
            ((1024, INF), false, Some(INF)),
            ((1024, 65536), false, Some(65536)),
            ((1024, 4096), false, None), // the hard limit is what to raise
            ((1024, 65535), false, None),
            ((4096, 4096), false, None),
            ((1024, 1048576), true, None), // (a raise that failed: its own warning says so)
        ] {
            assert_eq!(kept_below(&raise(limits, limits), raised), want, "{limits:?} {raised}");
        }
        assert_eq!(kept_below(&None, false), None);
        // nothing to say with a usable limit; an unreadable limit; a limit that leaves almost nothing; the raise's own
        assert!(fd_warnings(&raise((1024, 4096), (4096, 4096)), Some(fdgate::budget(4096, 40, 16, 2)), true).is_empty());
        let w = fd_warnings(&None, None, false);
        assert_eq!(w, ["open-file limit unreadable: the server does not limit its file descriptors."]);
        let w = fd_warnings(&None, None, true);
        assert!(w.len() == 1 && w[0].ends_with("file descriptors, and --conn-share and --fd-admission do nothing."), "{w:?}");
        two_lines(&w[0]);
        let b = fdgate::budget(200, 40, 16, 2);
        assert!((b.usable as u64) < fdgate::USABLE_WARN);
        let w = fd_warnings(&raise((200, 200), (200, 200)), Some(b), false);
        assert_eq!(
            w,
            [format!(
                "only {} file descriptors left for connections and streams (limit 200, {} fixed, {} reserve). \
                 Fix: raise the open-file limit.",
                b.usable, b.fixed, b.reserve
            )]
        );
        two_lines(&w[0]);
        // (many workers: a 7-digit limit can leave this little)
        let b = fdgate::budget(1_048_576, 1_048_440, 16, 2);
        let w = fd_warnings(&raise((1_048_576, 1_048_576), (1_048_576, 1_048_576)), Some(b), false);
        assert!(w.len() == 1 && w[0].contains("(limit 1048576, 1048448 fixed, "), "{w:?}");
        two_lines(&w[0]);
        // what the raise reported is its own warning (a start holds it right after the raise), with fdgate's real texts
        let mut r = raise((1024, 524288), (1024, 524288));
        assert_eq!(raise_warning(&r), None);
        r.as_mut().unwrap().warn = Some("the raise failed".to_string());
        assert!(fd_warnings(&r, Some(fdgate::budget(1024, 40, 16, 2)), false).is_empty());
        assert_eq!(raise_warning(&r).as_deref(), Some("the raise failed"));
        assert_eq!(raise_warning(&None), None);
        let unlimited = Limits { soft: 1024, hard: INF };
        let texts = [
            // a hard limit above the largest fs.nr_open: lowered to it
            fdgate::raise_with(unlimited, Some(2_147_483_584), |_| Ok(()), || None).warn,
            // fs.nr_open unreadable: EPERM with the hard limit as it is, then lowered to the target
            fdgate::raise_with(unlimited, None, |l| if l.hard == INF { Err(libc::EPERM) } else { Ok(()) }, || None).warn,
            // refused
            fdgate::raise_with(Limits { soft: 999_999, hard: INF }, None, |_| Err(libc::EPERM), || None).warn,
            fdgate::raise_with(Limits { soft: 1024, hard: 524_288 }, Some(1_048_576), |_| Err(libc::EINVAL), || None).warn,
            // (cannot happen) the soft limit read back lower
            fdgate::raise_with(
                Limits { soft: 1_048_576, hard: INF },
                Some(2_147_483_584),
                |_| Ok(()),
                || Some(Limits { soft: 1024, hard: 2_147_483_584 }),
            )
            .warn,
        ];
        let starts = [
            "hard open-file limit lowered to 2147483584 (fs.nr_open): ",
            "hard open-file limit lowered to 1048576 (fs.nr_open unreadable): ",
            "open-file limit: the raise from 999999 to 1048576 failed (",
            "open-file limit: the raise from 1024 to 524288 failed (",
            "open-file limit: the soft limit went down from 1048576 to 1024.",
        ];
        for (t, start) in texts.iter().zip(starts) {
            let t = t.as_deref().expect(start);
            assert!(t.starts_with(start) && t.ends_with('.'), "{t}");
            two_lines(t);
        }
    }
}
