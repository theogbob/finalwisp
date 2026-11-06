//! 60.24 (60.20 C4 step 1) logging: the --log-level filter for every stderr line, the logfmt helpers, and the
//! --log-conns writer. Workers never write stderr for connection lines: each appends whole lines to its own Outbox
//! (a Mutex<Vec<u8>> held only for a memcpy or a swap; at most OUTBOX_CAP bytes, over it the line is dropped and
//! counted), and one `connlog` thread swaps the outboxes every TICK (sooner when one passes half its cap) and writes
//! them with blocking write(2). A stalled stderr then stalls only that thread.
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            _ => return None,
        })
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// --log-level (main, once, before the first line that depends on it)
pub fn set_level(l: Level) {
    LEVEL.store(l as u8, Relaxed);
}

/// A line of level `l` is printed (error lines always are: Error = 0)
pub fn on(l: Level) -> bool {
    l as u8 <= LEVEL.load(Relaxed)
}

/// One logfmt value: as is when it needs no quoting; else quoted with \" \\ \n \r \t and \xNN for other control
/// bytes, DEL and every byte that is not valid UTF-8 (60.35 review: a refused host is client bytes, maybe cut in a
/// character), so a value can neither end the line, fake another key, nor make the line invalid UTF-8.
pub fn value(out: &mut Vec<u8>, v: &[u8]) {
    let hex = |out: &mut Vec<u8>, b: u8| {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.extend_from_slice(&[b'\\', b'x', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
    };
    if !v.is_empty()
        && v.iter().all(|&b| b > b' ' && b != b'"' && b != b'\\' && b != b'=' && b != 0x7f)
        && (v.is_ascii() || std::str::from_utf8(v).is_ok())
    {
        out.extend_from_slice(v);
        return;
    }
    out.push(b'"');
    for chunk in v.utf8_chunks() {
        for &b in chunk.valid().as_bytes() {
            match b {
                b'"' => out.extend_from_slice(b"\\\""),
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b if b < b' ' || b == 0x7f => hex(out, b),
                b => out.push(b),
            }
        }
        for &b in chunk.invalid() {
            hex(out, b);
        }
    }
    out.push(b'"');
}

/// ` ts=2026-11-01T12:00:00.123Z` (CLOCK_REALTIME_COARSE: no syscall, a few ms of resolution)
pub fn ts(out: &mut Vec<u8>) {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut t) };
    #[allow(clippy::unnecessary_cast)] // time_t is not i64 on every target
    ts_at(out, t.tv_sec as i64, (t.tv_nsec / 1_000_000) as u32);
}

fn ts_at(out: &mut Vec<u8>, secs: i64, ms: u32) {
    use std::io::Write;
    // days since 1970-01-01 to a civil date (H. Hinnant's days_from_civil inverse)
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let _ = write!(out, " ts={y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z", sod / 3600, sod % 3600 / 60, sod % 60);
}

/// Bytes one worker may hold for the writer (60.20 C4 (c): 256 KiB per worker; past half of it the writer is woken)
pub const OUTBOX_CAP: usize = 256 << 10;
const TICK: Duration = Duration::from_millis(100);
/// write(2) chunks of whole lines up to PIPE_BUF: on a pipe each is atomic, so a line never interleaves with the
/// other stderr writers (startup, metrics, memory, signal lines: one write per line each)
const CHUNK: usize = 4096;

#[derive(Default)]
struct Pending {
    buf: Vec<u8>,
    dropped: u64,
}

/// One worker's queue of connection log lines.
#[derive(Default)]
pub struct Outbox {
    q: Mutex<Pending>,
    /// conn_refused lines over the per-second limit (the writer reports them once per second)
    pub suppressed: AtomicU64,
    /// 60.35 stream_refused lines over the per-second limit (likewise, as `ev=stream_refused_suppressed`)
    pub stream_suppressed: AtomicU64,
}

impl Outbox {
    /// Queue one whole line (with its '\n'). false = over the cap: dropped and counted.
    pub fn push(&self, line: &[u8]) -> bool {
        let mut p = self.q.lock().unwrap_or_else(|e| e.into_inner());
        let before = p.buf.len();
        if before + line.len() > OUTBOX_CAP {
            p.dropped += 1;
            return false;
        }
        p.buf.extend_from_slice(line);
        drop(p);
        if before < OUTBOX_CAP / 2 && before + line.len() >= OUTBOX_CAP / 2 {
            if let Some(t) = WRITER.get() {
                t.unpark(); // drain early (a park_timeout returns at once)
            }
        }
        true
    }

    /// The queued bytes and the dropped count since the last take (the writer; tests)
    pub fn take(&self, spare: &mut Vec<u8>) -> u64 {
        spare.clear(); // (review: the swap would hand old bytes back to the box)
        let mut p = self.q.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::swap(&mut p.buf, spare);
        std::mem::take(&mut p.dropped)
    }
}

static OUTBOXES: Mutex<Vec<Arc<Outbox>>> = Mutex::new(Vec::new());
static WRITER: OnceLock<std::thread::Thread> = OnceLock::new();

/// A worker's outbox (Worker::new with --log-conns); the writer picks it up at its next tick
pub fn register(o: Arc<Outbox>) {
    OUTBOXES.lock().unwrap_or_else(|e| e.into_inner()).push(o);
}

static FLUSH_REQ: AtomicU64 = AtomicU64::new(0);
static FLUSH_ACK: AtomicU64 = AtomicU64::new(0);

/// main at exit: the writer writes everything queued so far and its counters; waits at most `wait` (a stalled stderr
/// must not keep the process). Without the writer: nothing to do.
pub fn flush(wait: Duration) {
    let Some(t) = WRITER.get() else { return };
    let req = FLUSH_REQ.fetch_add(1, Relaxed) + 1;
    t.unpark();
    let end = std::time::Instant::now() + wait;
    while FLUSH_ACK.load(std::sync::atomic::Ordering::Acquire) < req && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// The writer thread (main, with --log-conns or --log-streams). Lines lost to a full outbox give `ev=log_dropped n=`;
/// conn_refused / stream_refused lines over the limit give `ev=refused_suppressed n=` / `ev=stream_refused_suppressed n=`
/// (at most one each per second).
pub fn start() {
    let spawned = std::thread::Builder::new().name("connlog".into()).spawn(|| {
        let (mut spare, mut out) = (Vec::new(), Vec::new());
        let (mut dropped, mut suppressed, mut ssup) = (0u64, 0u64, 0u64);
        let mut last = std::time::Instant::now();
        loop {
            std::thread::park_timeout(TICK);
            let req = FLUSH_REQ.load(Relaxed); // before the swap: every line pushed before flush() is in this round
            let boxes: Vec<Arc<Outbox>> = OUTBOXES.lock().unwrap_or_else(|e| e.into_inner()).clone();
            for b in &boxes {
                dropped += b.take(&mut spare);
                write_lines(&spare);
            }
            if last.elapsed() >= Duration::from_secs(1) || req > FLUSH_ACK.load(Relaxed) {
                last = std::time::Instant::now();
                suppressed += boxes.iter().map(|b| b.suppressed.swap(0, Relaxed)).sum::<u64>();
                ssup += boxes.iter().map(|b| b.stream_suppressed.swap(0, Relaxed)).sum::<u64>();
                for (ev, n) in
                    [("log_dropped", &mut dropped), ("refused_suppressed", &mut suppressed), ("stream_refused_suppressed", &mut ssup)]
                {
                    if *n > 0 {
                        out.clear();
                        out.extend_from_slice(b"finalwisp: ev=");
                        out.extend_from_slice(ev.as_bytes());
                        ts(&mut out);
                        out.extend_from_slice(format!(" n={n}\n").as_bytes());
                        write_lines(&out);
                        *n = 0;
                    }
                }
            }
            FLUSH_ACK.fetch_max(req, std::sync::atomic::Ordering::Release);
        }
    });
    match spawned {
        Ok(h) => {
            let _ = WRITER.set(h.thread().clone());
        }
        // deliberate: without the thread the lines stay queued (capped) and are counted as dropped
        Err(e) => eprintln!("finalwisp: warning: --log-conns: no log thread ({e}): connection lines are dropped"),
    }
}

/// The next write: whole lines up to CHUNK bytes (all of `b` when it fits)
fn chunk_len(b: &[u8]) -> usize {
    if b.len() <= CHUNK {
        return b.len();
    }
    b[..CHUNK].iter().rposition(|&c| c == b'\n').map_or(CHUNK, |i| i + 1)
}

/// Blocking write(2) on fd 2 in chunks of whole lines; a failed write (EPIPE, a closed stderr) drops the rest
/// (60.05 H3: no panic on a dead pipe)
fn write_lines(mut b: &[u8]) {
    while !b.is_empty() {
        let n = chunk_len(b);
        let mut s = &b[..n];
        while !s.is_empty() {
            let w = unsafe { libc::write(2, s.as_ptr() as *const libc::c_void, s.len()) };
            if w <= 0 {
                if w < 0 && crate::net::errno() == libc::EINTR {
                    continue;
                }
                return;
            }
            s = &s[w as usize..];
        }
        b = &b[n..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[u8]) -> String {
        let mut o = Vec::new();
        value(&mut o, s);
        String::from_utf8(o).unwrap()
    }

    #[test]
    fn logfmt_values_cannot_forge_a_line_or_a_key() {
        assert_eq!(v(b"203.0.113.9"), "203.0.113.9");
        assert_eq!(v(b"2001:db8::1"), "2001:db8::1");
        assert_eq!(v(b""), "\"\"");
        assert_eq!(v(b"a b"), "\"a b\"");
        assert_eq!(v(b"x=1"), "\"x=1\"");
        assert_eq!(v(b"a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(v(b"l1\nfinalwisp: ev=conn_close"), "\"l1\\nfinalwisp: ev=conn_close\"");
        assert_eq!(v(b"\r\t\x00\x1b\x7f"), "\"\\r\\t\\x00\\x1b\\x7f\"");
        assert_eq!(v("é".as_bytes()), "é");
        // 60.35 not UTF-8 (a refused host, maybe cut inside a character): escaped, the line stays valid UTF-8
        assert_eq!(v(b"ab\xc3"), "\"ab\\xc3\"");
        assert_eq!(v(b"\xff\xfe x"), "\"\\xff\\xfe x\"");
        assert_eq!(v("aé".as_bytes()), "aé");
        assert_eq!(v(&"é".as_bytes()[..1]), "\"\\xc3\"");
    }

    #[test]
    fn level_filter() {
        assert_eq!(Level::parse("warn"), Some(Level::Warn));
        assert_eq!(Level::parse("WARN"), None);
        assert!(Level::Error < Level::Warn && Level::Info < Level::Debug);
        // the default (no test sets LEVEL: it is process-wide)
        assert!(on(Level::Error) && on(Level::Warn) && on(Level::Info) && !on(Level::Debug));
    }

    #[test]
    fn ts_is_iso8601_utc_ms() {
        let t = |s, ms| {
            let mut o = Vec::new();
            ts_at(&mut o, s, ms);
            String::from_utf8(o).unwrap()
        };
        assert_eq!(t(0, 0), " ts=1970-01-01T00:00:00.000Z");
        assert_eq!(t(951_782_400, 7), " ts=2000-02-29T00:00:00.007Z"); // leap day
        assert_eq!(t(1_793_534_400 + 3723, 123), " ts=2026-11-01T13:02:03.123Z");
        assert_eq!(t(4_102_444_799, 999), " ts=2099-12-31T23:59:59.999Z");
        let mut o = Vec::new();
        ts(&mut o);
        assert!(o.starts_with(b" ts=20") && o.ends_with(b"Z") && o.len() == 28, "{}", String::from_utf8_lossy(&o));
    }

    #[test]
    fn outbox_caps_and_counts_drops() {
        let b = Outbox::default();
        let line = [b'x'; 1000];
        let fits = OUTBOX_CAP / line.len();
        assert!((0..fits).all(|_| b.push(&line)));
        assert!(!b.push(&line), "over the cap: dropped");
        assert!(b.push(b"y"), "a line that still fits is kept");
        let mut got = Vec::new();
        assert_eq!(b.take(&mut got), 1, "one dropped");
        assert_eq!(got.len(), fits * line.len() + 1);
        assert!(b.push(&line), "room again after the take");
        assert_eq!(b.take(&mut got), 0);
        assert_eq!(got, line);
    }

    #[test]
    fn chunks_end_on_line_ends() {
        let mut b = Vec::new();
        for i in 0..200 {
            b.extend_from_slice(format!("finalwisp: ev=conn_close cid=0:{i} {}\n", "x".repeat(i % 90)).as_bytes());
        }
        let (mut s, mut n_chunks) = (&b[..], 0);
        while !s.is_empty() {
            let n = chunk_len(s);
            assert!(n <= CHUNK && s[n - 1] == b'\n');
            s = &s[n..];
            n_chunks += 1;
        }
        assert!(n_chunks > 2);
        let long = vec![b'z'; CHUNK + 10]; // a line longer than a chunk (never written by us) is cut, not looped on
        assert_eq!(chunk_len(&long), CHUNK);
    }
}
