//! 60.29 C5 `--metrics-listen [ADDR:]PORT`: the Prometheus text exposition (format 0.0.4) of the values the metrics line
//! shows, served by one thread with its own blocking listener (design: 60.28 C5; as built: 60.29). Off by default: then
//! this thread and its listener do not exist. The thread only reads atomics (the workers' Stats and the process-wide
//! values), so a slow scraper can delay only the next scrape, never a worker. No auth: loopback by default.
use crate::metrics::{self, Stats};
use crate::net::Inbox;
use std::fmt::{Display, Write as _};
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Named counters that are gauges, listed explicitly (test: every `_max` name, the line's max rule, is here). Every
/// other named counter is a counter (`_total`).
const GAUGES: &[&str] = &[
    "pool_chunks",
    "pool_dirty_kib",
    "streams",
    "ktls_starve_ms_max",
    "ktls_starve_conn_max",
    "ip_keys_max",
    "dest_keys_max",
    "one_key_conns_max",
    "dns_wait_ms_max",
    "fds",
    "tcpmem_unread", // 60.63
    "port_dest_max",
    "dest_dead",
    "connecting",
];

#[derive(Clone, Copy)]
enum Unit {
    Same,
    Kib, // x 1024 -> bytes
    Ms,  // / 1000 -> seconds
    Us,  // / 1,000,000 -> seconds (60.58)
}

/// Base units (Prometheus naming, the unit last): (named counter, exported name without `finalwisp_` and `_total`,
/// conversion, HELP in that unit or "" = the doc comment). Never exported in KiB / ms (test: no exported name ends in
/// _kib, _mib, _ms or _us).
const RENAMES: &[(&str, &str, Unit, &str)] = &[
    ("pool_dirty_kib", "pool_dirty_bytes", Unit::Kib, "70.25 gauge: dirty (resident, reusable) pool bytes, at the last idle sweep"),
    (
        "ktls_starve_ms_max",
        "ktls_starve_max_seconds",
        Unit::Ms,
        "50.02 gauge (max over the threads): the longest kTLS starve episode so far, seconds",
    ),
    ("ktls_starve_read", "ktls_starve_read_bytes", Unit::Same, ""),
    ("ktls_starve_conn_max", "ktls_starve_conn_max_bytes", Unit::Same, ""),
    (
        "dns_wait_us",
        "dns_wait_seconds",
        Unit::Us,
        "60.58 seconds DNS lookups waited for a resolver thread (until a thread took the lookup, it joined a running lookup of \
         the same name, or it expired); the mean wait is this / dns_miss_total",
    ),
    (
        "dns_wait_ms_max",
        "dns_wait_max_seconds",
        Unit::Ms,
        "60.58 gauge (max over the threads): the longest wait of a DNS lookup for a resolver thread since the start, seconds",
    ),
];

/// 200 answers written in full (this thread is the only writer; a page shows the scrapes before it)
static SCRAPES: AtomicU64 = AtomicU64::new(0);

/// HELP text escaping (exposition format 0.0.4: backslash and line feed)
fn esc_help(h: &str) -> String {
    h.trim().replace('\\', "\\\\").replace('\n', "\\n")
}

struct Page(String);
impl Page {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = write!(self.0, "# HELP finalwisp_{name} {}\n# TYPE finalwisp_{name} {kind}\n", esc_help(help));
    }
    fn sample(&mut self, name: &str, labels: &str, v: impl Display) {
        let _ = writeln!(self.0, "finalwisp_{name}{labels} {v}");
    }
    fn one(&mut self, name: &str, kind: &str, help: &str, v: impl Display) {
        self.family(name, kind, help);
        self.sample(name, "", v);
    }
}

fn secs(ms: u64) -> f64 {
    ms as f64 / 1000.0
}

/// The page: the metrics line's values (metrics::line) with the same merge over the workers (metrics::sum), in base
/// units. No per-client or per-destination label (cardinality, privacy) and no configuration (no secrets).
pub fn render(stats: &[Arc<Stats>], peers: &[Arc<Inbox>]) -> String {
    let mut p = Page(String::with_capacity(24 << 10));
    let now = metrics::now_ms();
    p.family("build_info", "gauge", "build of this binary (the value is always 1)");
    p.sample("build_info", concat!("{version=\"", env!("CARGO_PKG_VERSION"), "\"}"), 1);
    p.one("uptime_seconds", "gauge", "seconds since start", secs(now));
    let conns: usize = peers.iter().map(|q| q.load.load(Relaxed)).sum();
    p.one("connections", "gauge", "open client connections (conns in the metrics line; incl. handed over, not yet adopted)", conns);
    if let Some(g) = metrics::GATE.get() {
        p.one("conns_reserved", "gauge", "60.20 C3a --max-conns reservations held (exact, unlike connections)", g.used());
        p.one("conns_max", "gauge", "60.20 C3a --max-conns", g.max);
    }
    if let Some(g) = crate::fdgate::global() {
        p.one("fd_limit", "gauge", "60.57 file descriptors connections and streams may hold in all (fds = held now)", g.limit());
    }
    p.one("memory_level", "gauge", "20.26 memory pressure level (0-3)", crate::mem::LEVEL.load(Relaxed));
    if crate::mem::WORKER_BUDGET.load(Relaxed) > 0 {
        p.one("memory_used_bytes", "gauge", "20.26 memory the budget counts", crate::mem::USED.load(Relaxed));
    }
    let (changes, times) = crate::mem::level_times(now);
    p.one("memory_level_changes_total", "counter", "20.26 memory level changes", changes);
    p.family("memory_level_seconds_total", "counter", "20.26 seconds spent at each memory level");
    for (l, t) in times.iter().enumerate() {
        p.sample("memory_level_seconds_total", &format!("{{level=\"{l}\"}}"), secs(*t));
    }
    if crate::mem::TCP_ON.load(Relaxed) {
        let (enters, ms) = crate::mem::tcp_times(now);
        p.one("tcp_level", "gauge", "20.31 B3 TCP memory level (0-1)", crate::mem::TCP_LEVEL.load(Relaxed));
        p.one("tcp_pages", "gauge", "20.31 B3 host TCP memory, pages", crate::mem::TCP_PAGES.load(Relaxed));
        p.one("tcp_moved_pages", "gauge", "20.31 B3 pages moved into our heap this episode", crate::mem::TCP_MOVED.load(Relaxed));
        let own = crate::mem::TCP_OWN_PM.load(Relaxed);
        if own < u64::MAX - 1 {
            p.one("tcp_own_ratio", "gauge", "20.31 B3 our share of the host TCP memory (0-1)", own as f64 / 1000.0);
        }
        p.one("tcp_level_enters_total", "counter", "20.31 B3 entries into TCP level 1", enters);
        p.one("tcp_level1_seconds_total", "counter", "20.31 B3 seconds at TCP level 1", secs(ms));
    }
    if let Some((n, ms)) = metrics::kernel_tcp_pressure() {
        p.one("host_tcp_pressures_total", "counter", "20.31 times the kernel entered TCP memory pressure (since boot, this netns)", n);
        p.one(
            "host_tcp_pressure_seconds_total",
            "counter",
            "20.31 seconds in kernel TCP memory pressure (since boot, this netns)",
            secs(ms),
        );
    }
    if let Some(n) = metrics::host_net() {
        p.one("host_syn_retrans_total", "counter", "60.63 SYN retransmits sent by the host (since boot, this netns)", n.syn_retrans);
        p.one("host_udp_out_total", "counter", "60.63 UDP datagrams sent by the host (since boot, this netns)", n.udp_out);
    }
    let (sum, close) = metrics::sum(stats);
    for (i, (k, help)) in Stats::help().into_iter().enumerate() {
        let v = sum.get(i).map_or(0, |e| e.1);
        let (name, unit, help) = match RENAMES.iter().find(|r| r.0 == k) {
            Some(r) => (r.1, r.2, if r.3.is_empty() { help } else { r.3 }),
            None => (k, Unit::Same, help),
        };
        let kind = if GAUGES.contains(&k) { "gauge" } else { "counter" };
        let name = if kind == "counter" { format!("{name}_total") } else { name.to_string() };
        match unit {
            Unit::Same => p.one(&name, kind, help, v),
            Unit::Kib => p.one(&name, kind, help, v.saturating_mul(1024)),
            Unit::Ms => p.one(&name, kind, help, secs(v)),
            Unit::Us => p.one(&name, kind, help, v as f64 / 1e6),
        }
    }
    p.one(
        "keyupdate_closes_total",
        "counter",
        "60.12 client KeyUpdates that closed a connection (kernel < 6.14)",
        crate::tls::KEYUPDATE_CLOSES.load(Relaxed),
    );
    let us = |v: u64| v as f64 / 1e6;
    p.one(
        "pool_release_max_seconds",
        "gauge",
        "70.25 longest turn-end pool release (elapsed, process max)",
        us(crate::pool::RELEASE_MAX_US.load(Relaxed)),
    );
    p.one(
        "pool_release_cpu_max_seconds",
        "gauge",
        "60.16 longest turn-end pool release (thread CPU time, process max)",
        us(crate::pool::RELEASE_CPU_MAX_US.load(Relaxed)),
    );
    if let Some(rss) = std::fs::read_to_string("/proc/self/statm").ok().and_then(|t| t.split_whitespace().nth(1)?.parse::<u64>().ok()) {
        // SAFETY: sysconf has no preconditions
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
        p.one("process_resident_bytes", "gauge", "resident set size (/proc/self/statm)", rss * page);
    }
    p.one(
        "metrics_scrapes_total",
        "counter",
        "60.29 scrapes answered with 200 and written in full (this scrape not included)",
        SCRAPES.load(Relaxed),
    );
    if let Some(a) = metrics::UPSTREAM_DNS.get() {
        p.one(
            "upstream_dns_fail_total",
            "counter",
            "60.32 C6 proxy name refreshes that failed (the last list stayed)",
            a.fails.load(Relaxed),
        );
        p.one("upstream_dns_age_seconds", "gauge", "60.32 C6 seconds since the proxy name last resolved", secs(a.age_ms(now)));
    }
    p.family("close_total", "counter", "Wisp CLOSE packets sent, by reason (only reasons sent at least once)");
    for (r, n) in close.iter().enumerate().filter(|(_, n)| **n > 0) {
        p.sample("close_total", &format!("{{reason=\"0x{r:02x}\"}}"), n);
    }
    p.0
}

/// What a request gets
#[derive(Debug, PartialEq)]
enum Route {
    Metrics,
    NotFound,
    BadMethod,
    Bad,
}

/// The request line of a complete request head. deliberate: no httparse in this thread (60.28: a second caller of
/// httparse::Request::parse made LLVM stop inlining it into handle_http, which changed the hot process_frames).
fn route(head: &[u8]) -> Route {
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut f = line.split(|&b| b == b' ');
    let (Some(m), Some(target), Some(ver), None) = (f.next(), f.next(), f.next(), f.next()) else {
        return Route::Bad;
    };
    if m.is_empty() || !m.iter().all(|b| b.is_ascii_uppercase()) || !target.starts_with(b"/") || !(ver == b"HTTP/1.1" || ver == b"HTTP/1.0")
    {
        return Route::Bad;
    }
    if m != b"GET" {
        return Route::BadMethod;
    }
    match target.split(|&b| b == b'?').next() {
        Some(b"/metrics") => Route::Metrics,
        _ => Route::NotFound,
    }
}

/// End of the request head (a blank line; a bare LF accepted as well) in `buf`, scanning from `from`
fn head_end(buf: &[u8], from: usize) -> bool {
    let s = &buf[from.saturating_sub(3)..];
    s.windows(4).any(|w| w == b"\r\n\r\n") || s.windows(2).any(|w| w == b"\n\n")
}

/// Per scrape: at most this long in total (reads and the write; the timeouts are recomputed before each call, so a
/// client that drips one byte at a time cannot extend it)
const DEADLINE: Duration = Duration::from_secs(2);
/// Largest request head
const MAX_REQ: usize = 8 << 10;

fn left(until: Instant) -> Option<Duration> {
    Some(until.saturating_duration_since(Instant::now())).filter(|d| !d.is_zero())
}

/// Read the request head (to the blank line: closing with unread bytes sends a RST, which can drop the response at the
/// client). None = no complete head within the deadline, EOF or an error: then the connection is closed unanswered.
fn read_head(c: &mut TcpStream, until: Instant) -> Option<Route> {
    let mut buf = [0u8; MAX_REQ];
    let mut n = 0;
    loop {
        let d = left(until)?;
        c.set_read_timeout(Some(d)).ok()?;
        match c.read(&mut buf[n..]) {
            Ok(0) => return None,
            Ok(k) => {
                n += k;
                if head_end(&buf[..n], n - k) {
                    return Some(route(&buf[..n]));
                }
                if n == MAX_REQ {
                    return Some(Route::Bad);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
}

/// true = all of `data` was written before the deadline
fn write_by(c: &mut TcpStream, mut data: &[u8], until: Instant) -> bool {
    while !data.is_empty() {
        let Some(d) = left(until) else { return false };
        if c.set_write_timeout(Some(d)).is_err() {
            return false;
        }
        match c.write(data) {
            Ok(0) => return false,
            Ok(k) => data = &data[k..],
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// After the answer: half-close and read the client's leftovers (at most 64 KiB, within the deadline) so that the close does
/// not reset the connection before the client has read the answer.
fn linger(c: &mut TcpStream, until: Instant) {
    let _ = c.shutdown(std::net::Shutdown::Write);
    let mut buf = [0u8; 4096];
    for _ in 0..16 {
        let Some(d) = left(until) else { return };
        if c.set_read_timeout(Some(d)).is_err() {
            return;
        }
        match c.read(&mut buf) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

fn response(r: Route, stats: &[Arc<Stats>], peers: &[Arc<Inbox>]) -> Vec<u8> {
    const END: &str = "Connection: close\r\n\r\n";
    match r {
        Route::Metrics => {
            let body = render(stats, peers);
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\n{END}{body}",
                body.len()
            )
            .into_bytes()
        }
        Route::NotFound => {
            format!("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n{END}/metrics\n").into_bytes()
        }
        Route::BadMethod => format!("HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\n{END}").into_bytes(),
        Route::Bad => format!("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n{END}").into_bytes(),
    }
}

/// Start the `metrics-http` thread on `l` (main binds it before the workers start). One connection at a time, each
/// bounded by DEADLINE; a connect flood fills the listen backlog (scrapes fail, the workers do not notice).
pub fn serve(l: TcpListener, stats: Arc<Vec<Arc<Stats>>>, peers: Arc<Vec<Arc<Inbox>>>) -> std::io::Result<()> {
    std::thread::Builder::new().name("metrics-http".into()).spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else {
                std::thread::sleep(Duration::from_millis(10)); // EMFILE etc.: no busy loop
                continue;
            };
            let until = Instant::now() + DEADLINE;
            if let Some(r) = read_head(&mut c, until) {
                let is_page = r == Route::Metrics;
                if write_by(&mut c, &response(r, &stats, &peers), until) && is_page {
                    SCRAPES.fetch_add(1, Relaxed); // 60.29 review: completed writes, not requests
                }
                // unread bytes (a body, a pipelined request, a head over MAX_REQ) would make the close send RST (review)
                linger(&mut c, until);
            }
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> String {
        let a = Arc::new(Stats::new());
        let b = Arc::new(Stats::new());
        a.accepted.bump();
        b.accepted.add(2);
        a.ip_keys_max.max(5);
        b.ip_keys_max.max(3);
        a.pool_dirty_kib.set(2);
        a.ktls_starve_ms_max.max(1500);
        a.close[0x49].bump();
        b.close[0x49].add(2);
        b.close[0x02].bump();
        render(&[a, b], &[Inbox::new()])
    }

    #[test]
    fn page_sums_like_the_line_in_base_units() {
        let s = page();
        for want in [
            "finalwisp_accepted_total 3\n",
            "# TYPE finalwisp_accepted_total counter\n",
            "finalwisp_ip_keys_max 5\n", // max, not sum (the line's rule)
            "# TYPE finalwisp_ip_keys_max gauge\n",
            "finalwisp_pool_dirty_bytes 2048\n",
            "finalwisp_ktls_starve_max_seconds 1.5\n",
            "# HELP finalwisp_pool_dirty_bytes 70.25 gauge: dirty (resident, reusable) pool bytes, at the last idle sweep\n",
            "finalwisp_ktls_starve_read_bytes_total 0\n",
            "finalwisp_streams 0\n",
            "finalwisp_close_total{reason=\"0x49\"} 3\n",
            "finalwisp_close_total{reason=\"0x02\"} 1\n",
            "finalwisp_build_info{version=\"",
            "finalwisp_connections 0\n",
            "finalwisp_memory_level_seconds_total{level=\"0\"} ",
            "# HELP finalwisp_accepted_total connections taken by the worker threads (accepted, or handed over by --balance)\n",
        ] {
            assert!(s.contains(want), "{want:?} missing:\n{s}");
        }
        assert!(!s.contains("reason=\"0x41\""), "only reasons sent");
        assert!(!s.contains("_kib") && !s.contains("_ms_") && !s.contains("finalwisp_pool_chunks_total"), "{s}");
    }

    #[test]
    fn page_is_well_formed() {
        let s = page();
        let mut typed = std::collections::HashSet::new();
        let mut helped = std::collections::HashSet::new();
        for l in s.lines() {
            if let Some(r) = l.strip_prefix("# HELP ") {
                let (n, h) = r.split_once(' ').unwrap();
                assert!(!h.is_empty() && !h.contains('\n'), "{l}");
                assert!(helped.insert(n.to_string()), "HELP twice: {l}");
            } else if let Some(r) = l.strip_prefix("# TYPE ") {
                let (n, t) = r.split_once(' ').unwrap();
                assert!(t == "counter" || t == "gauge", "{l}");
                assert_eq!(t == "counter", n.ends_with("_total"), "counters and only counters end in _total: {l}");
                assert!(typed.insert(n.to_string()), "TYPE twice: {l}");
            } else {
                let (n, v) = l.rsplit_once(' ').unwrap();
                let base = n.split('{').next().unwrap();
                assert!(typed.contains(base) && helped.contains(base), "sample before its TYPE/HELP: {l}");
                assert!(
                    base.starts_with("finalwisp_") && base.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                    "{l}"
                );
                assert!(v.parse::<f64>().is_ok(), "{l}");
                for bad in ["_kib", "_mib", "_ms", "_us"] {
                    assert!(!base.ends_with(bad) && !base.contains(&format!("{bad}_")), "not a base unit: {l}");
                }
            }
        }
        // one family per named counter, plus the process-wide ones
        assert!(typed.len() > Stats::help().len(), "{}", typed.len());
    }

    #[test]
    fn gauges_and_renames_name_real_counters() {
        let names: Vec<_> = Stats::help().into_iter().map(|(n, _)| n).collect();
        for g in GAUGES.iter().chain(RENAMES.iter().map(|r| &r.0)) {
            assert!(names.contains(g), "{g} is not a Stats counter");
        }
        for n in &names {
            if n.ends_with("_max") {
                assert!(GAUGES.contains(n), "{n}: a _max gauge (merged by max) missing from GAUGES");
            }
        }
        assert!(Stats::help().iter().all(|(_, h)| !h.trim().is_empty()), "every counter has a doc line");
    }

    #[test]
    fn help_is_escaped() {
        assert_eq!(esc_help(" a\\b\nc "), "a\\\\b\\nc");
        let mut p = Page(String::new());
        p.one("x_total", "counter", "two\nlines \\ here", 1);
        assert_eq!(p.0, "# HELP finalwisp_x_total two\\nlines \\\\ here\n# TYPE finalwisp_x_total counter\nfinalwisp_x_total 1\n");
    }

    #[test]
    fn request_line_routes() {
        assert_eq!(route(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"), Route::Metrics);
        assert_eq!(route(b"GET /metrics?x=1 HTTP/1.0\r\n\r\n"), Route::Metrics);
        assert_eq!(route(b"GET /metrics HTTP/1.1\n\n"), Route::Metrics);
        assert_eq!(route(b"GET / HTTP/1.1\r\n\r\n"), Route::NotFound);
        assert_eq!(route(b"GET /metricsx HTTP/1.1\r\n\r\n"), Route::NotFound);
        assert_eq!(route(b"POST /metrics HTTP/1.1\r\n\r\n"), Route::BadMethod);
        assert_eq!(route(b"HEAD /metrics HTTP/1.1\r\n\r\n"), Route::BadMethod);
        for junk in [
            &b"\r\n\r\n"[..],
            b"GET\r\n\r\n",
            b"GET /metrics\r\n\r\n",
            b"GET  /metrics HTTP/1.1\r\n\r\n",
            b"get /metrics HTTP/1.1\r\n\r\n",
            b"GET metrics HTTP/1.1\r\n\r\n",
            b"GET /metrics SSH-2.0\r\n\r\n",
            b"GET /metrics HTTP/1.1 x\r\n\r\n",
            b"GET /metrics HTTP/1.\r\n\r\n",
            b"GET /metrics HTTP/1.1x\r\n\r\n",
            b"GET /metrics HTTP/2.0\r\n\r\n",
            b"\x16\x03\x01\x00\n\n",
        ] {
            assert_eq!(route(junk), Route::Bad, "{junk:?}");
        }
        assert!(head_end(b"GET / HTTP/1.1\r\n\r\n", 0) && head_end(b"GET / HTTP/1.1\r\n\r\n", 17) && head_end(b"a\n\n", 2));
        assert!(!head_end(b"GET / HTTP/1.1\r\nHost: x\r\n", 0));
    }
}
