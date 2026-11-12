//! wbench: Wisp v1 benchmark tool (pointer 30.01).
//! `wbench target` = plain TCP echo/sink/source server.
//! `wbench run`    = Wisp v1 load generator over a hand-rolled WebSocket client.

mod errkind;
mod run;
mod target;
mod tls;
mod verify;
mod ws;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "wbench", about = "Wisp server benchmark tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, Eq)]
pub enum TargetMode {
    Echo,
    Sink,
    Source,
    /// 20.16 UDP echo: every datagram is sent back to its sender.
    UdpEcho,
    /// 20.19 request/response: a request starts with [u32 LE response_len][u32 LE request_len];
    /// after request_len bytes the target writes response_len bytes (HTTP-like keep-alive).
    Reply,
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, Eq)]
pub enum Test {
    Upload,
    Download,
    Echo,
    Rr,
    Churn,
    /// 20.16 UDP request/response over Wisp UDP streams (CONNECT type 2, no credit); lost datagrams
    /// are re-sent after 200 ms and counted.
    UdpRr,
    /// 20.19 browsing: per connection, "pages" of `streams` short streams (CONNECT, one request,
    /// a response of --resp bytes, --reqs-per-stream times, CLOSE), all opened at once, the next
    /// page --page-gap-ms after the last stream closed; plus --bulk continuous download streams
    /// on the same connection. Needs a `reply` target. Reports request + page latency and bulk MiB/s.
    Browse,
    /// 30.10 a new WebSocket connection per request: connect, upgrade (TLS with wss://), CONNECT one
    /// stream, one --size echo, close; conns x streams such loops. rps = connections/s, latency per
    /// connection from TCP connect to the echo.
    #[value(name = "connchurn")]
    ConnChurn,
}

impl Test {
    pub fn name(self) -> &'static str {
        match self {
            Test::Upload => "upload",
            Test::Download => "download",
            Test::Echo => "echo",
            Test::Rr => "rr",
            Test::Churn => "churn",
            Test::UdpRr => "udp-rr",
            Test::Browse => "browse",
            Test::ConnChurn => "connchurn",
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Plain TCP target server (echo / sink / source), or UDP echo (udp-echo).
    Target {
        #[arg(long)]
        port: u16,
        #[arg(long, value_enum)]
        mode: TargetMode,
        #[arg(long, default_value_t = 65536)]
        chunk: usize,
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// Print byte counters (rates + cumulative) to stderr every N milliseconds (0 = off).
        #[arg(long, default_value_t = 0)]
        report: u64,
        /// Tokio worker threads (0 = number of CPUs).
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// 60.15 T06: byte integrity mode for `run --verify` (source/sink only): numbered pattern, END handshake.
        #[arg(long)]
        verify: bool,
    },
    /// Wisp v1 load generator.
    Run(RunArgs),
}

#[derive(clap::Args, Clone, Debug)]
pub struct RunArgs {
    /// Wisp server URL, e.g. ws://127.0.0.1:6001/ or wss://host:port/ (with --insecure)
    #[arg(long)]
    pub url: String,
    /// TCP target host:port that every stream CONNECTs to.
    #[arg(long)]
    pub target: String,
    #[arg(long, default_value_t = 1)]
    pub conns: usize,
    #[arg(long, default_value_t = 1)]
    pub streams: usize,
    /// Measured duration in seconds (after warmup).
    #[arg(long, default_value_t = 5.0, value_parser = duration_secs)]
    pub duration: f64,
    #[arg(long, value_enum)]
    pub test: Test,
    /// DATA payload size (default: 16384 for upload/echo, 64 for rr/churn/connchurn).
    #[arg(long)]
    pub size: Option<usize>,
    #[arg(long, default_value_t = 1.0, value_parser = secs)]
    pub warmup: f64,
    /// Print one JSON object line in addition to the human summary.
    #[arg(long)]
    pub json: bool,
    /// Tokio worker threads (0 = number of CPUs).
    #[arg(long, default_value_t = 0)]
    pub threads: usize,
    /// Workaround: send a WS ping after this many ms idle (0 = off). Unsticks
    /// servers that queue CONTINUE without flushing (epoxy-server upload).
    #[arg(long, default_value_t = 0.0)]
    pub stall_ping_ms: f64,
    /// 20.13: allow wss:// URLs; the server certificate is NOT verified (benchmarks only).
    #[arg(long)]
    pub insecure: bool,
    /// 60.67 (acceptance test T2): every connection sends `X-Forwarded-For` with one of N public addresses in rotation
    /// (even: IPv4 11.1.0.1 + k/2, odd: the IPv6 /64 2a10:77:H:L::1), for a server that trusts this client's address as
    /// a proxy. Header text only: nothing is sent to those addresses. 0 = no header (the default).
    #[arg(long, default_value_t = 0)]
    pub xff_keys: u64,
    /// 20.19 browse: response sizes in bytes, cycled per request (comma list).
    #[arg(long, default_value = "2048,8192,32768,131072")]
    pub resp: String,
    /// 20.19 browse: requests per short stream before CLOSE (HTTP keep-alive reuse).
    #[arg(long, default_value_t = 1)]
    pub reqs_per_stream: u32,
    /// 20.19 browse: pause between pages of one connection (ms).
    #[arg(long, default_value_t = 0.0)]
    pub page_gap_ms: f64,
    /// 20.19 browse: continuous download streams per connection (each requests --bulk-size bytes, again and again).
    #[arg(long, default_value_t = 0)]
    pub bulk: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub bulk_size: usize,
    /// 60.15 T06 (download, upload): every stream carries a numbered pattern that the receiver checks; at the end an
    /// END handshake reconciles both sides' byte counts (drain up to 15 s). Needs `target --verify` (source/sink).
    /// Verify errors are counted apart from `errors`; any of them: exit status 4.
    #[arg(long)]
    pub verify: bool,
}

/// Longest --duration / --warmup: 30 days (soak runs are hours). Larger values would overflow Instant + Duration.
const MAX_SECS: f64 = 30.0 * 86400.0;

/// --duration / --warmup: seconds, finite and within 0..=MAX_SECS, checked at parse time (inf, NaN or a negative value
/// panicked in Duration::from_secs_f64 = an abort under panic = "abort"). --duration > 0 is checked by run().
fn secs(s: &str) -> Result<f64, String> {
    let v: f64 = s.trim().parse().map_err(|_| format!("not a number of seconds: {s:?}"))?;
    if !v.is_finite() || !(0.0..=MAX_SECS).contains(&v) {
        return Err(format!("seconds must be finite and within 0..={MAX_SECS}, not {s:?}"));
    }
    Ok(v)
}

/// --duration: as secs() and at least 1 ms (a tiny positive value became Duration::ZERO, and the rates divided by it
/// printed `inf` into the --json line)
fn duration_secs(s: &str) -> Result<f64, String> {
    let v = secs(s)?;
    if v < 0.001 {
        return Err(format!("--duration must be at least 0.001 seconds, not {s:?}"));
    }
    Ok(v)
}

fn runtime(threads: usize) -> tokio::runtime::Runtime {
    let mut b = tokio::runtime::Builder::new_multi_thread();
    if threads > 0 {
        b.worker_threads(threads);
    }
    b.enable_all().build().expect("tokio runtime")
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Target { port, mode, chunk, bind, report, threads, verify } => {
            let rt = runtime(threads);
            if let Err(e) = rt.block_on(target::serve(&bind, port, mode, chunk.max(1), report, verify)) {
                eprintln!("target: {e}");
                std::process::exit(1);
            }
        }
        Cmd::Run(args) => {
            ws::XFF_KEYS.store(args.xff_keys, std::sync::atomic::Ordering::Relaxed);
            let rt = runtime(args.threads);
            match rt.block_on(run::run(args)) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("run: {e}");
                    std::process::exit(2);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secs_refuses_inf_nan_negative_and_huge() {
        assert_eq!(secs("5"), Ok(5.0));
        assert_eq!(secs("0.5"), Ok(0.5));
        assert_eq!(secs("0"), Ok(0.0)); // --warmup 0 is valid; --duration 0 is refused by run()
        assert_eq!(secs(&MAX_SECS.to_string()), Ok(MAX_SECS));
        for bad in ["inf", "-inf", "infinity", "NaN", "-1", "-0.001", "1e300", "2592001", "x", ""] {
            assert!(secs(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn duration_is_at_least_one_ms() {
        assert_eq!(duration_secs("0.001"), Ok(0.001));
        assert_eq!(duration_secs("5"), Ok(5.0));
        for bad in ["0", "-0", "0.0009", "5e-324", "inf", "-1"] {
            assert!(duration_secs(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn run_args_refuse_bad_seconds_at_parse_time() {
        let parse = |extra: &[&str]| {
            let base = ["wbench", "run", "--url", "ws://127.0.0.1:1/", "--target", "127.0.0.1:2", "--test", "rr"];
            Cli::try_parse_from(base.iter().chain(extra))
        };
        assert!(parse(&[]).is_ok());
        assert!(parse(&["--warmup", "0", "--duration", "1.5"]).is_ok());
        for bad in [["--duration", "inf"], ["--duration", "NaN"], ["--warmup", "-1"], ["--warmup", "inf"], ["--duration", "1e20"]] {
            assert!(parse(&bad).is_err(), "{bad:?} accepted");
        }
        // "--warmup -1" fails as an unknown flag; the = form reaches secs()
        let e = parse(&["--warmup=-1"]).err().expect("--warmup=-1 accepted");
        assert!(e.to_string().contains("seconds must be finite"), "{e}");
    }
}
