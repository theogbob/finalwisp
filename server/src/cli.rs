//! 20.01 / 60.04 F4 command line: `parse_args` turns the arguments into `Opts` or an error message.
//! Pure (no file/network I/O, no exit; only `--dns-server ...%ifname` asks the kernel for the interface index), so it is unit-tested; main() prints the error and the usage and exits 2.
//! 60.20 C8: `expand_config` turns `--config FILE` into flags first (main reads the file and passes its bytes in).
use std::net::IpAddr;

/// 60.18 / 60.16 section 3: the main options; the opt-in ones with when they pay; then the advanced / diagnostic ones
/// (off-switches and A/B levers). Rule: a flag is in this text or it does not exist (test every_flag_is_in_usage).
pub const USAGE: &str = "usage: finalwisp [PORT] [--config FILE] [--host H] [--port P] [--threads N] [--buffer N] [--allow-loopback] [--allow-private] \
[--connect-timeout SECS] [--no-udp] [--tls-cert FILE --tls-key FILE]... [--tls-cipher-order client|server] \
[--dns-threads N] [--dns-own] [--dns-server IP[:PORT]]... [--auth-file FILE] [--cert-auth-key FILE]... [--motd TEXT] \
[--mem-budget BYTES[K|M|G] (0 = off)] [--drain-timeout SECS] [--metrics-interval SECS (0 = off)] [--no-credit-v2] \
[--no-credit-pace (give a stream new upload credit even while its download waits on the client; the default holds it, so \
full-duplex bulk such as echo keeps less socket memory and small hosts reach TCP memory pressure later)] \
[--log-level error|warn|info|debug (default info)] [--log-conns (a line per connection, with the client IP)] \
[--log-streams (a line per stream and per refused CONNECT, with the client IP and the target host)] \
[--metrics-listen [ADDR:]PORT (Prometheus GET /metrics, no auth; a bare PORT listens on 127.0.0.1; off by default)]
opt-in: [--balance (spread new connections evenly over the threads: helps a few busy long-lived connections, \
+4..11% on 36-72 thread boxes; costs 1-7% on connection churn)] [--tcpmem-adapt (cap remote sockets near host TCP memory pressure; needs credit v2 and the memory budget)] \
[--max-conns N (connections over N are reset at accept)] [--max-streams-per-conn N (CONNECT over N streams on one connection gets 0x49)]
client IP and per-IP limits (off by default): [--trusted-proxy CIDRS] [--real-ip-header NAME (default x-forwarded-for)] \
[--max-conns-per-ip N] [--stream-rate-per-ip R[/B] (CONNECTs per second, burst B, default 2R)] \
[--conn-rate-per-ip R[/B] (new connections per second, burst B, default 2R)]
per-destination limits (off by default; all clients together, per target IP:port; over: 0x49): \
[--stream-rate-per-dest R[/B] (new streams per second, burst B, default 2R)] [--stream-rate-per-dest-minute N (new streams per minute)]
bandwidth caps (kernel TCP pacing; RATE = bytes/s, K/M/G = KiB/MiB/GiB, 1M = 8.4 Mbit/s; off by default): \
[--download-rate RATE (per connection)] [--upload-rate-per-stream RATE (per TCP stream)]
unix socket listener (off by default; for a reverse proxy on this host): [--listen-unix PATH (plain ws://, besides the TCP \
listener; its peers' client-IP header is believed)] [--unix-mode OCTAL (default 660)]
upload caps (off by default; the client is not read while over; R = bytes/s, K/M/G; burst B default max(R, 16K), B >= R/10): \
[--upload-rate R[/B] (per connection)] [--upload-rate-per-ip R[/B] (shared by a client key)]
PROXY protocol v1/v2 (off by default; behind a TCP load balancer): [--proxy-protocol tcp|unix,... (every connection on that \
listener must start with the header)] [--proxy-protocol-from CIDRS (who may send it on TCP; required for tcp)]
destination policy (refused with 0x48; lists are comma-separated and repeatable): [--allow-host NAMES] [--block-host NAMES] \
[--allow-ports [tcp:|udp:]N[-M],...] [--block-ports [tcp:|udp:]N[-M],...] [--block-smtp] [--allow-dest CIDRS] [--block-dest CIDRS] \
[--no-direct-ip] [--no-ipv6-targets] [--allow-self (the server's own addresses)] [--allow-embedded-v4 (IPv6 forms that carry IPv4)]
upstream proxy (off by default; UDP is then refused with 0x48): [--upstream socks5|socks5h|http://[USER:PASS@]HOST[:PORT] (put it in --config FILE, mode 0600)] \
[--upstream-trust-dns (required for socks5h: the proxy resolves names)]
advanced / diagnostic (leave at the default unless a problem points here): [--graceful-close] [--no-splice] [--no-tfo] \
[--no-keepalive] [--no-prio] [--notsent-lowat BYTES (0 = kernel)] [--tls-rekey-records N (0 = off)]";

/// Longest --connect-timeout: `Instant + Duration` panics on overflow, so a huge value is refused here.
pub const MAX_CONNECT_TIMEOUT: u64 = 86_400; // 1 day
/// Longest --drain-timeout (as MAX_CONNECT_TIMEOUT)
pub const MAX_DRAIN_TIMEOUT: u64 = 86_400;
/// Longest --metrics-interval (as MAX_CONNECT_TIMEOUT: a typo such as 6000000 is refused, not a silent never)
pub const MAX_METRICS_INTERVAL: u64 = 86_400;

pub struct Opts {
    pub ip: IpAddr,
    pub port: u16,
    pub threads: usize,
    pub buffer: u32,
    pub allow_loopback: bool,
    pub allow_private: bool,
    pub connect_timeout: u64, // seconds, <= MAX_CONNECT_TIMEOUT
    pub abort_close: bool,
    pub splice: bool,
    pub balance: bool,
    pub tfo: bool,
    pub keepalive: bool, // 70.02 dead-peer detection on client sockets (worker Config::keepalive)
    pub udp: bool,
    /// 20.17: --tls-cert/--tls-key may repeat (pairs in order, picked by SNI; the first is the default)
    pub tls_pairs: Vec<(String, String)>,
    pub cipher_server_order: bool,
    pub tls_rekey: u64,     // 20.17: proactive KeyUpdate at half the 2^24 record budget
    pub notsent_lowat: u32, // 20.19: unsent-queue cap per client socket (0 = kernel default)
    pub dns_threads: usize, // 20.19: resolver pool (was 4; getaddrinfo, or dns.rs with --dns-own, 70.09); a stalled upstream costs one
    pub dns_own: bool,      // 70.09 own resolver (dns.rs) instead of getaddrinfo
    /// 70.09 --dns-server (repeatable, implies --dns-own): these servers instead of the resolv.conf nameservers
    pub dns_servers: Vec<std::net::SocketAddr>,
    pub prio: bool, // 20.19 two-lane client output; 20.22 default on (--no-prio = one FIFO buffer)
    pub auth_file: Option<String>,
    pub cert_keys: Vec<String>,
    pub motd: Option<String>,
    pub mem_budget: Option<u64>,   // 20.26 None = auto (cgroup limit or MemTotal/2), Some(0) = off
    pub drain_timeout: u64,        // 60.12 SIGTERM/SIGINT: seconds live connections may finish (0 = exit at once)
    pub tcpmem_adapt: bool,        // 20.31 B3 cap our sockets near the host's TCP memory pressure (opt-in; 60.14: default off again)
    pub metrics_interval: u64,     // 60.12 seconds between `ev=metrics` log lines (0 = off), <= MAX_METRICS_INTERVAL
    pub credit_v2: bool,           // 20.30 upload credit v2 (worker Config::credit_v2); 60.13: default on
    pub credit_pace: bool,         // 60.42 no upload credit while the stream's download waits on the client (default on, 60.42 verify)
    pub max_conns: u32,            // 60.20 C3a --max-conns (0 = off): connections over it are reset at accept
    pub max_streams_per_conn: u32, // 60.20 C3a --max-streams-per-conn (0 = off): CONNECT over it gets 0x49
    /// 60.20 C1 request rules (--allow-host, --block-host, --allow-ports, --block-ports, --block-smtp, --no-direct-ip,
    /// --no-ipv6-targets); the address rules below
    pub rules: crate::policy::Rules,
    pub allow_dests: Vec<crate::policy::Cidr>,
    pub block_dests: Vec<crate::policy::Cidr>,
    pub allow_self: bool,     // 60.20 C1 / Q2 --allow-self
    pub allow_embedded: bool, // 60.20 C1 / Q2 --allow-embedded-v4
    /// 60.20 C2 --trusted-proxy: peers whose client-IP header is believed
    pub trusted_proxies: Vec<crate::policy::Cidr>,
    pub real_ip_header: String,          // 60.20 C2 --real-ip-header, lowercase
    pub max_conns_per_ip: u32,           // 60.20 C3b (0 = off)
    pub stream_rate: Option<(u32, u32)>, // 60.20 C3b --stream-rate-per-ip (per second, burst)
    pub conn_rate: Option<(u32, u32)>,   // 60.40 --conn-rate-per-ip (new connections per second, burst)
    pub dest_rate: Option<(u32, u32)>,   // 60.39 --stream-rate-per-dest (per second, burst)
    pub dest_rate_min: Option<u32>,      // 60.39 --stream-rate-per-dest-minute (per minute)
    pub pace: crate::net::Pacing,        // 60.30 C10a --download-rate, --upload-rate-per-stream (bytes/s, 0 = off)
    pub log_level: crate::logs::Level,   // 60.24 --log-level (default info)
    pub log_conns: bool,                 // 60.24 --log-conns
    pub log_streams: bool,               // 60.35 --log-streams
    /// 60.29 C5 --metrics-listen (None = off: no thread, no listener)
    pub metrics_listen: Option<std::net::SocketAddr>,
    /// 60.31 C7 --listen-unix PATH (None = off) and --unix-mode (None = not given: 0o660)
    pub listen_unix: Option<std::path::PathBuf>,
    pub unix_mode: Option<u32>,
    pub upstream: Option<String>, // 60.27 C6 --upstream URL (a secret: never printed; checked by upstream::parse_url)
    pub upstream_trust_dns: bool, // 60.27 C6 / Q1
    pub upload_rate: Option<(u64, u64)>, // 60.25 C10b --upload-rate (bytes/s, burst bytes) per connection
    pub upload_rate_ip: Option<(u64, u64)>, // 60.25 C10b --upload-rate-per-ip (bytes/s, burst bytes) per client key
    /// 60.34 --proxy-protocol tcp / unix: the header is required on that listener; --proxy-protocol-from: TCP sources
    pub proxy_tcp: bool,
    pub proxy_unix: bool,
    pub proxy_from: Vec<crate::policy::Cidr>,
}

impl Opts {
    /// 60.20 C3b a per-IP limit is on, so the per-IP table exists (60.25 --upload-rate-per-ip, 60.40 --conn-rate-per-ip)
    pub fn per_ip(&self) -> bool {
        self.max_conns_per_ip > 0 || self.stream_rate.is_some() || self.upload_rate_ip.is_some() || self.conn_rate.is_some()
    }
}

/// 60.20 C8: every long option parse_args accepts, and whether it takes a value. The --config file accepts exactly these
/// names (without the dashes); tests check this table against USAGE and parse_args. --config itself is not here: it is
/// expanded before parse_args (expand_config).
pub const FLAGS: &[(&str, bool)] = &[
    ("--host", true),
    ("--port", true),
    ("--threads", true),
    ("--buffer", true),
    ("--allow-loopback", false),
    ("--allow-private", false),
    ("--connect-timeout", true),
    ("--drain-timeout", true),
    ("--graceful-close", false),
    ("--no-splice", false),
    ("--balance", false),
    ("--no-tfo", false),
    ("--no-keepalive", false),
    ("--no-udp", false),
    ("--no-credit-v2", false),
    ("--tls-cert", true),
    ("--tls-key", true),
    ("--tls-cipher-order", true),
    ("--tls-rekey-records", true),
    ("--notsent-lowat", true),
    ("--dns-threads", true),
    ("--dns-own", false),
    ("--dns-server", true),
    ("--no-prio", false),
    ("--auth-file", true),
    ("--cert-auth-key", true),
    ("--motd", true),
    ("--mem-budget", true),
    ("--tcpmem-adapt", false),
    ("--no-credit-pace", false),
    ("--metrics-interval", true),
    ("--max-conns", true),
    ("--max-streams-per-conn", true),
    ("--allow-host", true),
    ("--block-host", true),
    ("--allow-ports", true),
    ("--block-ports", true),
    ("--allow-dest", true),
    ("--block-dest", true),
    ("--block-smtp", false),
    ("--no-direct-ip", false),
    ("--no-ipv6-targets", false),
    ("--allow-self", false),
    ("--allow-embedded-v4", false),
    ("--trusted-proxy", true),
    ("--real-ip-header", true),
    ("--max-conns-per-ip", true),
    ("--stream-rate-per-ip", true),
    ("--conn-rate-per-ip", true),            // 60.40
    ("--stream-rate-per-dest", true),        // 60.39
    ("--stream-rate-per-dest-minute", true), // 60.39
    ("--download-rate", true),               // 60.30 C10a
    ("--upload-rate-per-stream", true),      // 60.30 C10a
    ("--log-level", true),
    ("--log-conns", false),
    ("--log-streams", false),
    ("--metrics-listen", true),
    ("--listen-unix", true), // 60.31 C7
    ("--unix-mode", true),   // 60.31 C7
    ("--upstream", true),
    ("--upstream-trust-dns", false),
    ("--upload-rate", true),
    ("--upload-rate-per-ip", true),
    ("--proxy-protocol", true),      // 60.34
    ("--proxy-protocol-from", true), // 60.34
];

/// 60.20 C8 / 60.18 #13 a: list flags. One given on the command line replaces the file's whole list (no merging: merged
/// lists hide rules); --tls-cert and --tls-key are one group (they pair up in order).
const LIST_GROUPS: &[&[&str]] = &[
    &["--tls-cert", "--tls-key"],
    &["--dns-server"],
    &["--cert-auth-key"],
    &["--allow-host"], // 60.20 C1: each policy list is its own group
    &["--block-host"],
    &["--allow-ports"],
    &["--block-ports"],
    &["--allow-dest"],
    &["--block-dest"],
    &["--trusted-proxy"],       // 60.20 C2
    &["--proxy-protocol-from"], // 60.34
    &["--proxy-protocol"],      // 60.34 (review: a command-line listener list replaces the file's)
];

/// 60.20 C8: flags whose value is itself a secret (--auth-file and --cert-auth-key name files). A config file that holds
/// one should not be group/world readable (a startup warning). 60.27 C6: `--upstream URL` may hold proxy credentials.
const SECRET_FLAGS: &[&str] = &["--upstream"];

/// 70.28 characters that no error text of parse_args, check or expand_config contains (test
/// `error_texts_have_no_redaction_marks`). The config-parse fuzz target relies on it: a --config value with one of these
/// must never show up in an error (values are redacted). F1/F2 in 70.28 were messages that broke this premise.
#[cfg(any(test, fuzzing))]
pub const REDACTION_MARKS: &str = "@!$&*=~^|{}";

/// 60.20 C8 limits of a --config file
pub const CONFIG_MAX_BYTES: usize = 1 << 20;
pub const CONFIG_MAX_LINE: usize = 16 << 10;

/// expand_config's result: the arguments for parse_args, the config file (for the capability line) and a warning.
/// (no derived Debug: `args` can hold a secret flag's value, e.g. an --upstream URL; 60.27 review)
#[derive(PartialEq)]
pub struct Expanded {
    pub args: Vec<String>,
    pub config: Option<String>,
    pub warning: Option<String>,
}

impl std::fmt::Debug for Expanded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Expanded {{ args: <{} hidden>, config: {:?}, warning: {:?} }}", self.args.len(), self.config, self.warning)
    }
}

fn takes_value(flag: &str) -> Option<bool> {
    FLAGS.iter().find(|(f, _)| *f == flag).map(|&(_, v)| v)
}

/// a name that can be shown in an error: a mistyped secret on a line of its own must not be echoed
fn flag_like(name: &str) -> bool {
    !name.is_empty() && name.len() <= 40 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// 60.20 C8: the lines of a --config file as (line number, flag with dashes, value). Format (60.02 Q9): `flag value` or a
/// bare `flag` per line, the long option names without the leading dashes; blank lines and lines starting with `#` are
/// skipped; the value is the rest of the line with outer whitespace trimmed (no quoting, no inline comments). Each line
/// is checked as it is read (the first bad line is reported). Errors name FILE:LINE and the flag, never the value (the
/// file may hold secrets).
pub fn parse_config(path: &str, data: &[u8]) -> Result<Vec<(usize, String, Option<String>)>, String> {
    if data.len() > CONFIG_MAX_BYTES {
        return Err(format!("--config {path}: larger than {} KiB", CONFIG_MAX_BYTES >> 10));
    }
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data); // a UTF-8 byte order mark (Windows editors)
    let mut out = Vec::new();
    for (i, raw) in data.split(|&b| b == b'\n').enumerate() {
        let at = format!("{path}:{}", i + 1);
        if raw.len() > CONFIG_MAX_LINE {
            return Err(format!("{at}: line longer than {} KiB", CONFIG_MAX_LINE >> 10));
        }
        let s = std::str::from_utf8(raw).map_err(|_| format!("{at}: not valid UTF-8"))?;
        let s = s.strip_suffix('\r').unwrap_or(s); // CRLF files
        if s.chars().any(|c| c.is_control() && c != '\t') {
            return Err(format!("{at}: control character"));
        }
        let t = s.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (name, value) = match t.split_once([' ', '\t']) {
            Some((n, v)) => (n, Some(v.trim().to_string())),
            None => (t, None),
        };
        if name.starts_with('-') {
            return Err(format!("{at}: write flag names without the leading dashes"));
        }
        if !flag_like(name) {
            return Err(format!("{at}: unknown flag (not shown: not a flag name)"));
        }
        let flag = format!("--{name}");
        if name == "config" {
            return Err(format!("{at}: --config inside a config file (no includes)"));
        }
        match takes_value(&flag) {
            None => {
                return Err(match removed(&flag) {
                    Some(why) => format!("{at}: {flag} was removed before v1.0.0: {why}; drop it"),
                    None => format!("{at}: unknown flag {name:?}"),
                })
            }
            Some(true) if value.is_none() => return Err(format!("{at}: {flag} needs a value")),
            Some(false) if value.is_some() => return Err(format!("{at}: {flag} takes no value")),
            _ => {}
        }
        // the value, checked alone by parse_args (so the error has this line); a lone --tls-cert or --tls-key fails the
        // pairing check at the end of parse_args, so it gets a partner. Values are hidden: parse_args prints them {v:?}.
        let mut one: Vec<String> = std::iter::once(flag.clone()).chain(value.clone()).collect();
        match flag.as_str() {
            "--tls-cert" => one.extend(["--tls-key".to_string(), "k".to_string()]),
            "--tls-key" => one.extend(["--tls-cert".to_string(), "c".to_string()]),
            _ => {}
        }
        if let Err(e) = parse_args(one, 1) {
            let e = match &value {
                Some(v) => e.replace(&format!("{v:?}"), "(value not shown)"),
                None => e,
            };
            return Err(format!("{at}: {e}"));
        }
        out.push((i + 1, flag, value));
    }
    Ok(out)
}

/// 60.20 C8 `--config FILE`: replace it by the file's flags at its position, so flags after it override the file (the
/// parser is last-wins) and one parser does all the checks. A list flag (LIST_GROUPS) anywhere on the command line drops
/// the file's entries of that list. Each file line is checked alone with parse_args first, so a bad value is reported
/// as FILE:LINE with the value hidden (parse_config). `load` reads the file: (contents, st_mode) or an error message (main: read_config).
pub fn expand_config<F>(args: Vec<String>, load: F) -> Result<Expanded, String>
where
    F: FnOnce(&str) -> Result<(Vec<u8>, u32), String>,
{
    expand_config_with(args, load, SECRET_FLAGS)
}

/// expand_config with the list of secret flags as a parameter (the tests pass their own)
fn expand_config_with<F>(args: Vec<String>, load: F, secret_flags: &[&str]) -> Result<Expanded, String>
where
    F: FnOnce(&str) -> Result<(Vec<u8>, u32), String>,
{
    // find --config as an option, not as the value of another one (`--motd --config`)
    let (mut at, mut lists, mut i) = (Vec::new(), Vec::new(), 0);
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--config" {
            at.push(i);
        }
        if let Some(g) = LIST_GROUPS.iter().position(|g| g.contains(&a)) {
            lists.push(g);
        }
        i += if a == "--config" || takes_value(a) == Some(true) { 2 } else { 1 };
    }
    let Some(&pos) = at.first() else {
        return Ok(Expanded { args, config: None, warning: None });
    };
    if at.len() > 1 {
        return Err("--config: only one config file".to_string());
    }
    let path = args.get(pos + 1).ok_or("--config needs a value")?.clone();
    let (data, mode) = load(&path).map_err(|e| format!("--config {path}: {e}"))?;
    let mut file = Vec::new();
    let mut secret = false;
    for (_, flag, value) in parse_config(&path, &data)? {
        secret |= secret_flags.contains(&flag.as_str()); // the file holds it, even when the command line replaces it
        if lists.iter().any(|&g| LIST_GROUPS[g].contains(&flag.as_str())) {
            continue; // the command line's list replaces the file's (60.18 #13 a)
        }
        file.push(flag);
        file.extend(value);
    }
    // checks across lines (more than 3 dns-server lines, unpaired tls-cert / tls-key): the file alone, named in the error
    // (these messages hold no values; every value was checked per line)
    parse_args(file.clone(), 1).map_err(|e| format!("--config {path}: {e}"))?;
    let warning =
        (secret && mode & 0o044 != 0).then(|| format!("--config {path} holds a secret and is readable by group/others (chmod 600 it)"));
    let mut out = args[..pos].to_vec();
    out.extend(file);
    out.extend_from_slice(&args[pos + 2..]);
    Ok(Expanded { args: out, config: Some(path), warning })
}

/// 60.20 C3b / 60.39 a stream rate `R` or `R/B`: per second 1..=1000000, burst 1..=2000000 (default 2R)
fn stream_rate(flag: &str, v: &str) -> Result<(u32, u32), String> {
    let bad = || format!("{flag}: R or R/B (R 1..1000000 per second, burst B 1..2000000): {v:?}");
    let (r, b) = match v.split_once('/') {
        Some((r, b)) => (r.parse::<u32>().map_err(|_| bad())?, b.parse::<u32>().map_err(|_| bad())?),
        None => {
            let r = v.parse::<u32>().map_err(|_| bad())?;
            (r, r.saturating_mul(2))
        }
    };
    if !(1..=1_000_000).contains(&r) || !(1..=2_000_000).contains(&b) {
        return Err(bad());
    }
    Ok((r, b))
}

/// 60.30 C10a a pacing rate (SO_MAX_PACING_RATE), bytes per second with parse_size's suffixes (K/M/G = KiB/MiB/GiB):
/// 0 = off, else MIN_RATE..=MAX_RATE.
fn rate(flag: &str, v: &str) -> Result<u32, String> {
    match parse_size(v) {
        Some(0) => Ok(0),
        Some(n) if (crate::net::MIN_RATE as u64..=crate::net::MAX_RATE as u64).contains(&n) => Ok(n as u32),
        _ => Err(format!("{flag}: bytes per second, 0 (off) or 16K..4095M (K/M/G: KiB/MiB/GiB; 1M is 8.4 Mbit/s), not {v:?}")),
    }
}

/// 20.26 "64M", "512K", "1G" or plain bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let (n, mul) = match s.as_bytes().last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 1u64 << 10),
        b'M' | b'm' => (&s[..s.len() - 1], 1 << 20),
        b'G' | b'g' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    n.parse::<u64>().ok()?.checked_mul(mul)
}

/// 60.18: flags removed in base-4 (no-op aliases of the default, and the DNS coalescing opt-out) and why; a start command
/// that still passes one exits 2 with this reason instead of a bare "unknown argument"
fn removed(flag: &str) -> Option<&'static str> {
    Some(match flag {
        "--credit-v2" => "upload credit v2 is the default (--no-credit-v2 turns it off)",
        "--prio" => "the priority lane is the default (--no-prio turns it off)",
        "--no-tcpmem-adapt" => "tcpmem adapt is off by default (--tcpmem-adapt turns it on)",
        "--no-dns-coalesce" => "identical DNS names in flight always share one lookup",
        _ => return None,
    })
}

/// 60.20 C1 a comma-separated list value (repeatable flags append). Errors show the whole value as {v:?} (a --config line
/// hides it, parse_config) and which entry is wrong.
fn list<T>(flag: &str, v: &str, one: impl Fn(&str) -> Result<T, &'static str>) -> Result<Vec<T>, String> {
    v.split(',').enumerate().map(|(i, e)| one(e.trim()).map_err(|why| format!("{flag}: entry {} of {v:?}: {why}", i + 1))).collect()
}

fn num<T: std::str::FromStr>(flag: &str, v: String) -> Result<T, String> {
    v.parse().map_err(|_| format!("{flag}: bad value {v:?}"))
}

/// 70.01 F2: the arguments as Strings, or an error for one that is not valid UTF-8 (std::env::args() panics on
/// it, which with panic = "abort" was a core dump). deliberate: no lossy conversion, it would silently change a
/// non-UTF-8 file path (--tls-cert, --auth-file) into another one.
pub fn utf8_args<I: IntoIterator<Item = std::ffi::OsString>>(args: I) -> Result<Vec<String>, String> {
    args.into_iter()
        .map(|a| {
            a.into_string().map_err(|a| {
                let _ = a; // 60.27 C6: not echoed (it may be a secret, e.g. an --upstream URL)
                "an argument is not valid UTF-8".to_string()
            })
        })
        .collect()
}

/// Parse the arguments (without the program name). Err(message); an empty message = only the usage
/// (--help). `threads` is the default thread count (the caller passes available_parallelism).
pub fn parse_args<I: IntoIterator<Item = String>>(args: I, threads: usize) -> Result<Opts, String> {
    let mut host = "127.0.0.1".to_string();
    let mut o = Opts {
        ip: IpAddr::from([127, 0, 0, 1]),
        port: 6001,
        threads,
        buffer: 128,
        allow_loopback: false,
        allow_private: false,
        connect_timeout: 10,
        abort_close: true,
        splice: true,
        balance: false,
        tfo: true,
        keepalive: true,
        udp: true,
        tls_pairs: Vec::new(),
        cipher_server_order: false,
        tls_rekey: 1 << 23,
        notsent_lowat: 128 * 1024,
        dns_threads: 16,
        dns_own: false,
        dns_servers: Vec::new(),
        prio: true,
        auth_file: None,
        cert_keys: Vec::new(),
        motd: None,
        mem_budget: None,
        drain_timeout: 30,
        metrics_interval: 0,
        tcpmem_adapt: false, // 60.14: off again (VPS A/B: bulk download 0.65-0.83 under host TCP pressure, 2.8x CPU/MiB)
        credit_v2: true,     // 60.13 default on (20.30 acceptance + browser compat)
        credit_pace: true,   // 60.42 default on (Default-ON verification, owner 2026-11-07)
        max_conns: 0,
        max_streams_per_conn: 0,
        rules: crate::policy::Rules { direct_ip: true, ipv6: true, ..Default::default() },
        allow_dests: Vec::new(),
        block_dests: Vec::new(),
        allow_self: false,
        allow_embedded: false,
        trusted_proxies: Vec::new(),
        real_ip_header: "x-forwarded-for".to_string(),
        max_conns_per_ip: 0,
        stream_rate: None,
        conn_rate: None,
        dest_rate: None,
        dest_rate_min: None,
        pace: crate::net::Pacing::default(),
        log_level: crate::logs::Level::Info,
        log_conns: false,
        log_streams: false,
        metrics_listen: None,
        listen_unix: None,
        unix_mode: None,
        upstream: None,
        upstream_trust_dns: false,
        upload_rate: None,
        upload_rate_ip: None,
        proxy_tcp: false,
        proxy_unix: false,
        proxy_from: Vec::new(),
    };
    let (mut tls_certs, mut tls_keys) = (Vec::<String>::new(), Vec::<String>::new());
    let mut args = args.into_iter();
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--host" => host = val()?,
            "--port" => o.port = num(&a, val()?)?,
            "--threads" => o.threads = num(&a, val()?)?,
            "--buffer" => o.buffer = num(&a, val()?)?,
            "--connect-timeout" => {
                o.connect_timeout = num(&a, val()?)?;
                if o.connect_timeout > MAX_CONNECT_TIMEOUT {
                    return Err(format!("--connect-timeout: at most {MAX_CONNECT_TIMEOUT} seconds"));
                }
            }
            "--drain-timeout" => {
                o.drain_timeout = num(&a, val()?)?;
                if o.drain_timeout > MAX_DRAIN_TIMEOUT {
                    return Err(format!("--drain-timeout: at most {MAX_DRAIN_TIMEOUT} seconds"));
                }
            }
            "--allow-loopback" => o.allow_loopback = true,
            "--allow-private" => o.allow_private = true,
            "--graceful-close" => o.abort_close = false,
            "--no-splice" => o.splice = false,
            "--balance" => o.balance = true,
            "--no-tfo" => o.tfo = false,
            "--no-keepalive" => o.keepalive = false,
            "--no-udp" => o.udp = false,
            "--no-credit-v2" => o.credit_v2 = false,
            "--tls-cert" => tls_certs.push(val()?),
            "--tls-key" => tls_keys.push(val()?),
            "--tls-cipher-order" => {
                o.cipher_server_order = match val()?.as_str() {
                    "client" => false,
                    "server" => true,
                    v => return Err(format!("--tls-cipher-order: client or server, not {v:?}")),
                }
            }
            "--tls-rekey-records" => o.tls_rekey = num(&a, val()?)?,
            "--notsent-lowat" => o.notsent_lowat = num(&a, val()?)?,
            "--dns-threads" => o.dns_threads = num(&a, val()?)?,
            "--dns-own" => o.dns_own = true,
            "--dns-server" => {
                let v = val()?;
                let s = crate::dns::parse_server(&v).ok_or_else(|| format!("--dns-server: not IP[:PORT] / [IPv6[%scope]]:PORT: {v:?}"))?;
                if o.dns_servers.len() == crate::dns::MAX_SERVERS {
                    let n = crate::dns::MAX_SERVERS;
                    return Err(format!("--dns-server: at most {n} (only the first {n} servers are ever asked)"));
                }
                o.dns_servers.push(s);
                o.dns_own = true;
            }
            "--no-prio" => o.prio = false,
            "--auth-file" => o.auth_file = Some(val()?),
            "--cert-auth-key" => o.cert_keys.push(val()?),
            "--motd" => o.motd = Some(val()?),
            "--mem-budget" => {
                let v = val()?;
                o.mem_budget = Some(parse_size(&v).ok_or_else(|| format!("--mem-budget: bad size {v:?}"))?);
            }
            "--tcpmem-adapt" => o.tcpmem_adapt = true,   // 60.14 opt-in
            "--no-credit-pace" => o.credit_pace = false, // 60.42 default on
            "--metrics-interval" => {
                o.metrics_interval = num(&a, val()?)?;
                if o.metrics_interval > MAX_METRICS_INTERVAL {
                    return Err(format!("--metrics-interval: at most {MAX_METRICS_INTERVAL} seconds"));
                }
            }
            "--max-conns" => o.max_conns = num(&a, val()?)?,
            "--log-level" => {
                let v = val()?;
                o.log_level = crate::logs::Level::parse(&v).ok_or_else(|| format!("--log-level: error, warn, info or debug, not {v:?}"))?;
            }
            "--log-conns" => o.log_conns = true,
            "--log-streams" => o.log_streams = true,
            "--metrics-listen" => {
                let v = val()?;
                o.metrics_listen = Some(match v.parse::<u16>() {
                    Ok(p) => std::net::SocketAddr::from(([127, 0, 0, 1], p)), // 60.29 decision d: a bare port is loopback
                    Err(_) => v.parse().map_err(|_| format!("--metrics-listen: PORT, IP:PORT or [IPv6]:PORT, not {v:?}"))?,
                });
            }
            "--max-streams-per-conn" => o.max_streams_per_conn = num(&a, val()?)?,
            // 60.31 C7 (the path itself is checked when it is bound: net::listen_unix)
            "--listen-unix" => o.listen_unix = Some(val()?.into()),
            "--unix-mode" => {
                let v = val()?;
                let digits = !v.is_empty() && v.bytes().all(|b| (b'0'..=b'7').contains(&b)); // (no sign: review)
                let m = u32::from_str_radix(&v, 8).ok().filter(|m| digits && *m <= 0o777);
                o.unix_mode = Some(m.ok_or_else(|| format!("--unix-mode: an octal mode 0-777 (e.g. 660), not {v:?}"))?);
            }
            // 60.34 PROXY protocol (repeatable: the listeners add up)
            "--proxy-protocol" => {
                let v = val()?;
                for (i, l) in v.split(',').enumerate() {
                    match l.trim() {
                        "tcp" => o.proxy_tcp = true,
                        "unix" => o.proxy_unix = true,
                        // the whole value (a --config line hides it; 70.28 review: an entry alone was not hidden)
                        _ => return Err(format!("--proxy-protocol: entry {} of {v:?}: not tcp or unix", i + 1)),
                    }
                }
            }
            "--proxy-protocol-from" => {
                let v = list(&a, &val()?, |e| crate::policy::Cidr::parse(e).ok_or("not an IP or IP/prefix"))?;
                o.proxy_from.extend(v);
            }
            // 60.20 C1 destination policy
            "--allow-host" | "--block-host" => {
                let v = list(&a, &val()?, crate::policy::host_entry)?;
                (if a == "--allow-host" { &mut o.rules.allow_hosts } else { &mut o.rules.block_hosts }).extend(v);
            }
            "--allow-ports" | "--block-ports" => {
                let v = list(&a, &val()?, |e| {
                    crate::policy::PortRule::parse(e).ok_or("not N or N-M (1-65535), optionally after tcp: or udp:")
                })?;
                (if a == "--allow-ports" { &mut o.rules.allow_ports } else { &mut o.rules.block_ports }).extend(v);
            }
            "--allow-dest" | "--block-dest" => {
                let v = list(&a, &val()?, |e| crate::policy::Cidr::parse(e).ok_or("not an IP or IP/prefix"))?;
                (if a == "--allow-dest" { &mut o.allow_dests } else { &mut o.block_dests }).extend(v);
            }
            "--block-smtp" => o.rules.block_smtp = true,
            "--no-direct-ip" => o.rules.direct_ip = false,
            "--no-ipv6-targets" => o.rules.ipv6 = false,
            "--allow-self" => o.allow_self = true,
            "--allow-embedded-v4" => o.allow_embedded = true,
            // 60.20 C2 / C3b
            "--trusted-proxy" => {
                let v = list(&a, &val()?, |e| crate::policy::Cidr::parse(e).ok_or("not an IP or IP/prefix"))?;
                o.trusted_proxies.extend(v);
            }
            "--real-ip-header" => {
                let v = val()?;
                // an HTTP field name (RFC 9110 token); stored lowercase, matched case-insensitively
                if v.is_empty() || v.len() > 64 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)) {
                    return Err(format!("--real-ip-header: not a header name: {v:?}"));
                }
                o.real_ip_header = v.to_ascii_lowercase();
            }
            "--max-conns-per-ip" => o.max_conns_per_ip = num(&a, val()?)?,
            "--upload-rate" | "--upload-rate-per-ip" => {
                // 60.25 C10b: R or R/B in bytes (K/M/G); R >= 8K (the 70.08 stall rule needs 2 KiB/s), B >= 16K
                let v = val()?;
                let bad =
                    || format!("{a}: R or R/B in bytes per second (K/M/G; R 8K..1T, burst B at least 16K and R/10, default R): {v:?}");
                let (r, b) = match v.split_once('/') {
                    Some((r, b)) => (parse_size(r).ok_or_else(bad)?, parse_size(b).ok_or_else(bad)?),
                    None => {
                        let r = parse_size(&v).ok_or_else(bad)?;
                        (r, r.max(16 << 10))
                    }
                };
                if !((8 << 10)..=(1 << 40)).contains(&r) || !((16 << 10)..=(1 << 42)).contains(&b) {
                    return Err(bad());
                }
                if b < r.div_ceil(10) {
                    // 60.25: paused clients resume on the 100 ms tick, so a burst below 100 ms of R caps the rate at 10 B/s
                    // (review: 1M/16K would give ~160 KiB/s)
                    return Err(format!("{a}: the burst is below 100 ms of the rate (B at least R/10): {v:?}"));
                    // the whole value (70.28 review)
                }
                if a == "--upload-rate" {
                    o.upload_rate = Some((r, b));
                } else {
                    o.upload_rate_ip = Some((r, b));
                }
            }
            "--stream-rate-per-ip" => o.stream_rate = Some(stream_rate(&a, &val()?)?),
            "--conn-rate-per-ip" => o.conn_rate = Some(stream_rate(&a, &val()?)?), // 60.40
            "--stream-rate-per-dest" => o.dest_rate = Some(stream_rate(&a, &val()?)?), // 60.39
            "--stream-rate-per-dest-minute" => {
                let v = val()?;
                match v.parse::<u32>() {
                    Ok(n) if (1..=60_000_000).contains(&n) => o.dest_rate_min = Some(n),
                    _ => return Err(format!("--stream-rate-per-dest-minute: new streams per minute, 1..60000000: {v:?}")),
                }
            }
            "--download-rate" => o.pace.download = rate(&a, &val()?)?,
            "--upload-rate-per-stream" => o.pace.upload = rate(&a, &val()?)?,
            "--upstream" => o.upstream = Some(val()?),
            "--upstream-trust-dns" => o.upstream_trust_dns = true,
            "-h" | "--help" => return Err(String::new()),
            p => {
                if let Some(why) = removed(p) {
                    return Err(format!("{p} was removed before v1.0.0: {why}; drop it"));
                }
                // 60.27 C6: an unknown argument is echoed only if it looks like a flag name (a mistyped `--upstrem URL` or
                // `--upstream=URL` must not print the URL's password)
                o.port = p.parse().map_err(|_| match flag_like(p.trim_start_matches('-')) {
                    true => format!("unknown argument {p:?}"),
                    false => "unknown argument (not shown: not a flag name; it may hold a secret)".to_string(),
                })?
            }
        }
    }
    o.ip = host.parse().map_err(|_| format!("--host: not an IP address: {host:?}"))?;
    // 20.13 built-in TLS: cert and key files come in pairs
    if tls_certs.len() != tls_keys.len() {
        return Err("--tls-cert and --tls-key must be given together (the same number of each)".to_string());
    }
    o.tls_pairs = tls_certs.into_iter().zip(tls_keys).collect();
    if o.metrics_listen.is_some_and(|m| m.port() == 0) {
        return Err("--metrics-listen: port 0 (a random port) is not allowed".to_string());
    }
    // 60.27 C6: the URL is checked here (its errors never quote it: it may hold a password); syntax only, the socks5h /
    // --upstream-trust-dns pairing is a cross-flag rule (cli::check)
    if let Some(u) = &o.upstream {
        crate::upstream::parse_url(u)?;
    }
    Ok(o)
}

/// Checks across options of the final command line. Not in parse_args: parse_config validates each file line alone
/// (review: `port 7000` + `metrics-listen 6001` in one file would meet the default port there). main calls it after
/// parse_args.
pub fn check(o: Opts) -> Result<Opts, String> {
    // 60.29 metrics never on the Wisp port (whatever the addresses: one port number, one service)
    if let Some(m) = o.metrics_listen.filter(|m| m.port() == o.port) {
        return Err(format!("--metrics-listen: port {} is the Wisp port; metrics are never served on it", m.port()));
    }
    // 60.31 C7 flags that would silently do nothing
    if o.unix_mode.is_some() && o.listen_unix.is_none() {
        return Err("--unix-mode needs --listen-unix".to_string());
    }
    // 60.27 C6 / Q1: socks5h only with --upstream-trust-dns, and that flag only with socks5h
    let remote = match &o.upstream {
        Some(u) => Some(crate::upstream::parse_url(u)?.remote_dns),
        None => None,
    };
    crate::upstream::check_trust(remote, o.upstream_trust_dns)?;
    // 60.34 PROXY protocol flags that would do nothing, or accept the header from anyone by accident
    if o.proxy_unix && o.listen_unix.is_none() {
        return Err("--proxy-protocol unix needs --listen-unix".to_string());
    }
    if o.proxy_tcp && o.proxy_from.is_empty() {
        return Err("--proxy-protocol tcp needs --proxy-protocol-from CIDRS (the load balancers' addresses; 0.0.0.0/0,::/0 \
                    only if the network lets nothing else reach the port)"
            .to_string());
    }
    if !o.proxy_from.is_empty() && !o.proxy_tcp {
        return Err("--proxy-protocol-from needs --proxy-protocol tcp".to_string());
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(a: &str) -> Result<Opts, String> {
        parse_args(a.split_whitespace().map(String::from), 4).and_then(check)
    }

    #[test]
    fn defaults_and_values() {
        let o = parse("").unwrap();
        assert_eq!((o.ip, o.port, o.threads, o.buffer, o.connect_timeout), (IpAddr::from([127, 0, 0, 1]), 6001, 4, 128, 10));
        assert!(o.abort_close && o.splice && o.tfo && o.keepalive && o.udp && o.prio && o.mem_budget.is_none());
        assert!(!parse("--no-keepalive").unwrap().keepalive);
        assert!(o.credit_v2 && !parse("--no-credit-v2").unwrap().credit_v2); // 60.13
        let o = parse("7000 --host :: --threads 2 --connect-timeout 86400 --no-prio --mem-budget 64M --tls-cipher-order server").unwrap();
        assert_eq!((o.port, o.threads, o.connect_timeout, o.prio, o.mem_budget), (7000, 2, 86400, false, Some(64 << 20)));
        assert_eq!((o.drain_timeout, parse("--drain-timeout 0").unwrap().drain_timeout), (30, 0)); // 60.12
        assert!(o.ip.is_ipv6() && o.cipher_server_order);
        let o = parse("--port 1 --tls-cert a --tls-key b --tls-cert c --tls-key d --cert-auth-key k1 --cert-auth-key k2").unwrap();
        assert_eq!(o.port, 1);
        assert_eq!(o.tls_pairs, vec![("a".into(), "b".into()), ("c".into(), "d".into())]);
        assert_eq!(o.cert_keys, vec!["k1", "k2"]);
        assert_eq!(parse("--mem-budget 0").unwrap().mem_budget, Some(0));
        assert!(!o.dns_own && parse("--dns-own").unwrap().dns_own);
        let o = parse("--dns-server 10.0.0.1 --dns-server [::1]:5353 --dns-server 127.0.0.1:53").unwrap();
        assert!(o.dns_own);
        assert_eq!(o.dns_servers, ["10.0.0.1:53".parse().unwrap(), "[::1]:5353".parse().unwrap(), "127.0.0.1:53".parse().unwrap()]);
        assert_eq!(parse("").unwrap().metrics_interval, 0); // 60.12 off by default
        assert_eq!(parse("--metrics-interval 60").unwrap().metrics_interval, 60);
        // 60.24 logging: info and no connection lines by default
        let o = parse("").unwrap();
        assert!(o.log_level == crate::logs::Level::Info && !o.log_conns);
        let o = parse("--log-level warn --log-conns").unwrap();
        assert!(o.log_level == crate::logs::Level::Warn && o.log_conns);
        assert!(!parse("").unwrap().log_streams && parse("--log-streams").unwrap().log_streams); // 60.35
        assert!(parse("--log-level verbose").is_err() && parse("--log-level").is_err());
        assert!(!parse("").unwrap().tcpmem_adapt && parse("--tcpmem-adapt").unwrap().tcpmem_adapt);
        assert!(parse("").unwrap().credit_pace && !parse("--no-credit-pace").unwrap().credit_pace); // 60.42 default on
                                                                                                    // 60.20 C3a: off by default (Q4)
        let o = parse("--max-conns 1000 --max-streams-per-conn 64").unwrap();
        assert_eq!((o.max_conns, o.max_streams_per_conn), (1000, 64));
        let o = parse("").unwrap();
        assert_eq!((o.max_conns, o.max_streams_per_conn), (0, 0));
        // 20.31 / 60.14 opt-in
        // 60.20 C1: no rules by default; lists append across repeats
        let o = parse("").unwrap();
        assert!(crate::policy::Policy::new(&o.rules).is_none() && o.allow_dests.is_empty() && o.block_dests.is_empty());
        assert!(!o.allow_self && !o.allow_embedded);
        let o = parse(
            "--allow-host Example.com.,b.org --allow-host c.net --block-host admin.example.com --allow-ports tcp:443,udp:53 \
             --block-ports 1-1023 --block-smtp --allow-dest 127.0.0.2,10.0.0.0/8 --block-dest 2001:db8::/32 --no-direct-ip \
             --no-ipv6-targets --allow-self --allow-embedded-v4",
        )
        .unwrap();
        assert_eq!(o.rules.allow_hosts, ["example.com", "b.org", "c.net"]);
        assert_eq!(o.rules.block_hosts, ["admin.example.com"]);
        assert_eq!((o.rules.allow_ports.len(), o.rules.block_ports.len(), o.allow_dests.len(), o.block_dests.len()), (2, 1, 2, 1));
        assert!(o.rules.block_smtp && !o.rules.direct_ip && !o.rules.ipv6 && o.allow_self && o.allow_embedded);
        // 60.20 C2 / C3b: off by default
        let o = parse("").unwrap();
        assert!(o.trusted_proxies.is_empty() && o.max_conns_per_ip == 0 && o.stream_rate.is_none());
        assert_eq!(o.real_ip_header, "x-forwarded-for");
        let o = parse("--trusted-proxy 127.0.0.1,10.0.0.0/8 --trusted-proxy ::1 --real-ip-header X-Real-IP --max-conns-per-ip 8 --stream-rate-per-ip 50").unwrap();
        assert_eq!(
            (o.trusted_proxies.len(), o.real_ip_header.as_str(), o.max_conns_per_ip, o.stream_rate),
            (3, "x-real-ip", 8, Some((50, 100)))
        );
        assert_eq!(parse("--stream-rate-per-ip 10/15").unwrap().stream_rate, Some((10, 15)));
        // 60.40 --conn-rate-per-ip: off by default, R[/B] like --stream-rate-per-ip; wispurr's 200 per 10 s = 20/200
        assert!(parse("").unwrap().conn_rate.is_none() && !parse("").unwrap().per_ip());
        let o = parse("--conn-rate-per-ip 20/200").unwrap();
        assert_eq!((o.conn_rate, o.stream_rate, o.per_ip()), (Some((20, 200)), None, true));
        assert_eq!(parse("--conn-rate-per-ip 5").unwrap().conn_rate, Some((5, 10)));
        // 60.39: off by default; R[/B] as per IP; the minute form
        let o = parse("").unwrap();
        assert!(o.dest_rate.is_none() && o.dest_rate_min.is_none());
        let o = parse("--stream-rate-per-dest 250 --stream-rate-per-dest-minute 6000").unwrap();
        assert_eq!((o.dest_rate, o.dest_rate_min), (Some((250, 500)), Some(6000)));
        assert_eq!(parse("--stream-rate-per-dest 250/250").unwrap().dest_rate, Some((250, 250)));
        assert_eq!(parse("--stream-rate-per-dest-minute 60000000").unwrap().dest_rate_min, Some(60_000_000));
        // 60.29 C5: off by default; a bare port is loopback; IPv4 and [IPv6] forms
        assert!(parse("").unwrap().metrics_listen.is_none());
        assert_eq!(parse("--metrics-listen 9100").unwrap().metrics_listen, Some("127.0.0.1:9100".parse().unwrap()));
        assert_eq!(parse("--metrics-listen 10.0.0.5:9100").unwrap().metrics_listen, Some("10.0.0.5:9100".parse().unwrap()));
        assert_eq!(parse("--metrics-listen [::1]:9100").unwrap().metrics_listen, Some("[::1]:9100".parse().unwrap()));
        // never the Wisp port, whichever form sets either port
        for a in [
            "--metrics-listen 6001",
            "--port 7000 --metrics-listen 0.0.0.0:7000",
            "7000 --metrics-listen [::]:7000",
            "--metrics-listen 7000 --port 7000",
        ] {
            assert!(parse(a).err().is_some_and(|e| e.contains("is the Wisp port")), "{a}");
        }
        // 60.31 C7
        let o = parse("--listen-unix /run/fw/w.sock --unix-mode 0640").unwrap();
        assert_eq!((o.listen_unix.as_deref(), o.unix_mode), (Some(std::path::Path::new("/run/fw/w.sock")), Some(0o640)));
        assert!(parse("").unwrap().listen_unix.is_none());
        for bad in [
            "--unix-mode 660",
            "--listen-unix x --unix-mode 800",
            "--listen-unix x --unix-mode +660",
            "--listen-unix x --unix-mode -0",
            "--listen-unix x --unix-mode 1777",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        // 60.34 PROXY protocol
        let o = parse("--proxy-protocol tcp --proxy-protocol-from 10.0.0.0/8,192.0.2.1").unwrap();
        assert!(o.proxy_tcp && !o.proxy_unix && o.proxy_from.len() == 2);
        let o = parse("--listen-unix /run/x.sock --proxy-protocol unix --proxy-protocol tcp,unix --proxy-protocol-from ::/0").unwrap();
        assert!(o.proxy_tcp && o.proxy_unix);
        assert!(!parse("").unwrap().proxy_tcp && !parse("").unwrap().proxy_unix);
        for bad in [
            "--proxy-protocol tcp",
            "--proxy-protocol unix",
            "--proxy-protocol-from 10.0.0.1",
            "--proxy-protocol udp --proxy-protocol-from 10.0.0.1",
            "--proxy-protocol tcp --proxy-protocol-from 10.0.0.300",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    /// 60.30 C10a rates: bytes/s with K/M/G (binary), 0 = off, 16K..4095M; both flags also in a --config file
    #[test]
    fn pacing_rates() {
        let p = |a: &str| parse(a).map(|o| (o.pace.download, o.pace.upload));
        assert_eq!(p("--port 1"), Ok((0, 0)));
        assert_eq!(p("--download-rate 10M --upload-rate-per-stream 512K"), Ok((10 << 20, 512 << 10)));
        assert_eq!(p("--download-rate 16K --upload-rate-per-stream 4095M"), Ok((16 << 10, 4095 << 20)));
        assert_eq!(p("--download-rate 16384 --upload-rate-per-stream 0"), Ok((16384, 0)));
        assert_eq!(p("--download-rate 1g"), Ok((1 << 30, 0)));
        for a in [
            "--download-rate 16383",
            "--download-rate 4G",
            "--upload-rate-per-stream 4096M",
            "--download-rate 1.5M",
            "--download-rate -1",
            "--download-rate x",
            "--download-rate",
            "--upload-rate-per-stream 99999999999G",
        ] {
            let e = parse(a).err().unwrap_or_else(|| panic!("{a} accepted"));
            assert!(e.contains("16K..4095M") || e.contains("needs a value"), "{a}: {e}");
        }
        let f = "download-rate 2M\nupload-rate-per-stream 1M\n";
        let o = parse_args(ex("--config f", f).unwrap().args, 4).unwrap();
        assert_eq!((o.pace.download, o.pace.upload), (2 << 20, 1 << 20));
        let o = parse_args(ex("--config f --download-rate 0", f).unwrap().args, 4).unwrap();
        assert_eq!((o.pace.download, o.pace.upload), (0, 1 << 20), "the command line after --config overrides");
    }

    /// 60.25 C10b upload caps: R[/B] bytes/s K/M/G, R 8K..1T, B >= 16K and >= R/10, default B = max(R, 16K)
    #[test]
    fn upload_rates() {
        assert_eq!(parse("--upload-rate 1M").unwrap().upload_rate, Some((1 << 20, 1 << 20)));
        assert_eq!(parse("--upload-rate 8K").unwrap().upload_rate, Some((8 << 10, 16 << 10)), "burst at least 16K");
        assert_eq!(parse("--upload-rate-per-ip 1M/128K").unwrap().upload_rate_ip, Some((1 << 20, 128 << 10)));
        for a in [
            "--upload-rate 4K",
            "--upload-rate 1M/16K",
            "--upload-rate 163841/16384",
            "--upload-rate-per-ip 2T",
            "--upload-rate 1M/x",
            "--upload-rate",
        ] {
            assert!(parse(a).is_err(), "{a}");
        }
        let o = parse_args(ex("--config f", "upload-rate 1M\nupload-rate-per-ip 4M/1M\n").unwrap().args, 4).unwrap();
        assert_eq!((o.upload_rate, o.upload_rate_ip), (Some((1 << 20, 1 << 20)), Some((4 << 20, 1 << 20))));
    }

    #[test]
    fn bad_values_are_errors_not_panics() {
        for a in [
            "--port 70000",
            "--port",
            "--threads x",
            "--threads -1",
            "--buffer 4294967296",
            "--connect-timeout 18446744073709551615", // 60.04 F4: was a panic at the first connect
            "--connect-timeout 86401",
            "--drain-timeout 86401",
            "--drain-timeout x",
            "--connect-timeout -1",
            "--tls-cipher-order fast",
            "--mem-budget 1x",
            "--metrics-interval 86401",
            "--metrics-interval -1",
            "--metrics-interval",
            "--metrics-listen",
            "--metrics-listen 70000",
            "--metrics-listen localhost:9100",
            "--metrics-listen ::1:9100",
            "--metrics-listen 0",
            "--metrics-listen 127.0.0.1:0",
            "--mem-budget 99999999999G",
            "--notsent-lowat 4294967296",
            "--host localhost",
            "--dns-server",
            "--dns-server dns.google",
            "--dns-server 1.1.1.1:0",
            "--dns-server 1.1.1.1%eth0",
            "--dns-server 1.1.1.1 --dns-server 1.1.1.2 --dns-server 1.1.1.3 --dns-server 1.1.1.4",
            "--tls-cert a",
            "--tls-cert a --tls-key b --tls-key c",
            "--bogus",
            "70000",
            "--max-conns -1",
            "--max-conns 4294967296",
            "--max-streams-per-conn x",
            "--allow-host 10.0.0.1",
            "--block-host *.example.com",
            "--block-host a,,b",
            "--block-host",
            "--allow-ports 0",
            "--block-ports tcp:80-70",
            "--block-ports sctp:80",
            "--allow-dest 10.0.0.0/33",
            "--block-dest example.com",
            "--trusted-proxy 10.0.0.0/40",
            "--real-ip-header",
            "--real-ip-header a:b",
            "--real-ip-header x\u{e9}",
            "--max-conns-per-ip -1",
            "--stream-rate-per-ip 0",
            "--upload-rate 4K",
            "--upload-rate 1M/16K",
            "--upload-rate-per-ip 2T",
            "--stream-rate-per-ip 10/0",
            "--stream-rate-per-ip 10/x",
            "--stream-rate-per-ip 1000001",
            "--conn-rate-per-ip 0",
            "--conn-rate-per-ip 1/0",
            "--conn-rate-per-ip 1/2000001",
            "--conn-rate-per-ip x",
            "--conn-rate-per-ip",
            "--stream-rate-per-dest 0",
            "--stream-rate-per-dest 10/",
            "--stream-rate-per-dest 1000001",
            "--stream-rate-per-dest",
            "--stream-rate-per-dest-minute 0",
            "--stream-rate-per-dest-minute 60000001",
            "--stream-rate-per-dest-minute 5/s",
        ] {
            let e = parse(a).err().unwrap_or_else(|| panic!("{a} accepted"));
            assert!(!e.is_empty(), "{a}");
        }
        // 60.18 removed in base-4: an error that names the flag and the reason (main prints it and exits 2), also late
        // in the line and after the opposite flag (parsing was last-wins)
        for a in ["--credit-v2", "--prio", "--no-tcpmem-adapt", "--no-dns-coalesce"] {
            for line in [a.to_string(), format!("7000 --threads 2 {a}"), format!("--tcpmem-adapt --no-prio {a} --balance")] {
                let e = parse(&line).err().unwrap_or_else(|| panic!("{line} accepted"));
                assert!(e.starts_with(&format!("{a} was removed before v1.0.0: ")) && e.ends_with("; drop it"), "{e}");
            }
        }
        assert_eq!(parse("--help").err(), Some(String::new()));
    }

    /// 60.16 rule "in usage, or deleted": every flag parse_args accepts is in USAGE; the removed ones are not
    #[test]
    fn every_flag_is_in_usage() {
        for &(f, _) in FLAGS {
            assert!(USAGE.contains(&format!("[{f}")) || USAGE.contains(&format!(" {f} ")), "{f} not in USAGE");
            assert!(removed(f).is_none());
        }
        // 60.20 C8: and the other way round: every option in USAGE is in FLAGS (the config file's key list), except --config
        let mut seen = 0;
        for w in USAGE.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).filter(|w| w.starts_with("--") && w.len() > 2) {
            assert!(w == "--config" || takes_value(w).is_some(), "{w} in USAGE but not in FLAGS");
            seen += 1;
        }
        assert!(seen >= FLAGS.len());
        for f in ["--credit-v2", "--prio", "--no-tcpmem-adapt", "--no-dns-coalesce"] {
            assert!(!USAGE.contains(&format!("[{f}")), "{f} still in USAGE");
        }
    }

    /// 60.20 C8: FLAGS agrees with parse_args: a value flag alone asks for its value, a bare flag parses alone
    #[test]
    fn flags_table_matches_parse_args() {
        for &(f, v) in FLAGS {
            let r = parse_args([f.to_string()], 4);
            if v {
                assert_eq!(r.err().as_deref(), Some(format!("{f} needs a value").as_str()), "{f}");
            } else {
                assert!(r.is_ok(), "{f}");
            }
        }
    }

    fn load_ok(data: &'static str, mode: u32) -> impl FnOnce(&str) -> Result<(Vec<u8>, u32), String> {
        move |_| Ok((data.as_bytes().to_vec(), mode))
    }

    fn ex(cmd: &str, file: &'static str) -> Result<Expanded, String> {
        expand_config(cmd.split_whitespace().map(String::from).collect(), load_ok(file, 0o600))
    }

    #[test]
    fn config_file_format() {
        let f = "# comment\n\n  port 7000  \nallow-loopback\r\nmotd  hello  world # not a comment \n\tthreads\t3\n";
        let e = ex("--config f.conf", f).unwrap();
        assert_eq!(e.args, ["--port", "7000", "--allow-loopback", "--motd", "hello  world # not a comment", "--threads", "3"]);
        assert_eq!((e.config.as_deref(), e.warning), (Some("f.conf"), None));
        let o = parse_args(e.args, 4).unwrap();
        assert_eq!((o.port, o.threads, o.allow_loopback), (7000, 3, true));
        // no --config: unchanged, the loader is never called
        let e = expand_config(vec!["7000".into()], |_| -> Result<(Vec<u8>, u32), String> { panic!("loaded") }).unwrap();
        assert_eq!(e, Expanded { args: vec!["7000".into()], config: None, warning: None });
        // a byte order mark and an empty file
        assert_eq!(ex("--config f", "\u{feff}port 1\n").unwrap().args, ["--port", "1"]);
        assert!(ex("--config f", "").unwrap().args.is_empty());
        // --config as the value of another flag is not a config file
        assert_eq!(ex("--motd --config", "port 1").unwrap().args, ["--motd", "--config"]);
    }

    #[test]
    fn config_override_and_lists() {
        // position decides for scalars: after --config overrides the file, before it is overridden
        let f = "port 7000\nthreads 3\ndns-server 10.0.0.1\ndns-server 10.0.0.2\ncert-auth-key a\ncert-auth-key b\n";
        let o = parse_args(ex("--threads 9 --config f --port 8000", f).unwrap().args, 4).unwrap();
        assert_eq!((o.port, o.threads), (8000, 3));
        // a repeated key appends
        assert_eq!(o.dns_servers, ["10.0.0.1:53".parse().unwrap(), "10.0.0.2:53".parse().unwrap()]);
        assert_eq!(o.cert_keys, ["a", "b"]);
        // a list flag on the command line replaces the file's list (before or after --config); others stay
        let o = parse_args(ex("--dns-server 10.9.9.9 --config f", f).unwrap().args, 4).unwrap();
        assert_eq!((o.dns_servers, o.cert_keys), (vec!["10.9.9.9:53".parse().unwrap()], vec!["a".to_string(), "b".into()]));
        let o = parse_args(ex("--config f --cert-auth-key z", f).unwrap().args, 4).unwrap();
        assert_eq!((o.dns_servers.len(), o.cert_keys), (2, vec!["z".to_string()]));
        // --tls-cert / --tls-key replace as one group (pairs stay in order)
        let f = "tls-cert a.pem\ntls-key a.key\ntls-cert b.pem\ntls-key b.key\n";
        let o = parse_args(ex("--config f", f).unwrap().args, 4).unwrap();
        assert_eq!(o.tls_pairs, [("a.pem".into(), "a.key".into()), ("b.pem".into(), "b.key".into())]);
        let o = parse_args(ex("--config f --tls-cert c.pem --tls-key c.key", f).unwrap().args, 4).unwrap();
        assert_eq!(o.tls_pairs, [("c.pem".to_string(), "c.key".to_string())]);
        // 60.34 --proxy-protocol replaces the file's listener list like any list flag (review)
        let f = "listen-unix /run/x.sock\nproxy-protocol unix\nproxy-protocol-from 10.0.0.1\n";
        let o = parse_args(ex("--config f --proxy-protocol tcp", f).unwrap().args, 4).unwrap();
        assert!(o.proxy_tcp && !o.proxy_unix && o.proxy_from.len() == 1);
        // 60.29 the Wisp-port check sees the final command line, not one file line (review)
        let f = "port 7000\nmetrics-listen 6001\n";
        let o = check(parse_args(ex("--config f", f).unwrap().args, 4).unwrap()).unwrap();
        assert_eq!((o.port, o.metrics_listen.map(|m| m.port())), (7000, Some(6001)));
        assert!(ex("--config f", "metrics-listen 6001\n").is_ok()); // the file alone is valid; with the default port check refuses
        assert!(check(parse_args(ex("--config f", "metrics-listen 6001\n").unwrap().args, 4).unwrap()).is_err());
        // 60.20 C1: each policy list replaces alone (a command-line --block-host keeps the file's --allow-host)
        let f = "allow-host a.example\nallow-host b.example\nblock-host x.example\nblock-ports 25\nblock-dest 10.0.0.0/8\n";
        let o = parse_args(ex("--config f", f).unwrap().args, 4).unwrap();
        assert_eq!((o.rules.allow_hosts.len(), o.rules.block_hosts.len(), o.rules.block_ports.len(), o.block_dests.len()), (2, 1, 1, 1));
        let o = parse_args(ex("--block-host y.example,z.example --config f --block-dest 192.0.2.0/24", f).unwrap().args, 4).unwrap();
        assert_eq!(o.rules.allow_hosts, ["a.example", "b.example"]);
        assert_eq!(o.rules.block_hosts, ["y.example", "z.example"]);
        assert_eq!((o.rules.block_ports.len(), o.block_dests), (1, vec![crate::policy::Cidr::parse("192.0.2.0/24").unwrap()]));
    }

    #[test]
    fn config_errors_name_the_line_not_the_value() {
        const SECRET: &str = "s3cretVALUE";
        for (file, want) in [
            ("port 1\nthreads s3cretVALUE\n", "f:2: --threads: bad value (value not shown)"),
            ("host s3cretVALUE", "f:1: --host: not an IP address: (value not shown)"),
            ("mem-budget s3cretVALUE", "f:1: --mem-budget: bad size (value not shown)"),
            ("tls-cipher-order s3cretVALUE", "f:1: --tls-cipher-order: client or server, not (value not shown)"),
            ("dns-server s3cretVALUE", "f:1: --dns-server: not IP[:PORT] / [IPv6[%scope]]:PORT: (value not shown)"),
            ("connect-timeout 86401", "f:1: --connect-timeout: at most 86400 seconds"),
            ("s3cretVALUE", "f:1: unknown flag (not shown: not a flag name)"),
            ("block-host a.example,s3cretVALUE*", "f:1: --block-host: entry 2 of (value not shown): not a host name (letters, digits, '-', '_' and '.'; IDN as punycode xn--)"),
            ("# x\nbogus 1", "f:2: unknown flag \"bogus\""),
            ("--port 1", "f:1: write flag names without the leading dashes"),
            ("port", "f:1: --port needs a value"),
            ("balance s3cretVALUE", "f:1: --balance takes no value"),
            ("config other.conf", "f:1: --config inside a config file (no includes)"),
            ("help", "f:1: unknown flag \"help\""),
            ("prio", "f:1: --prio was removed before v1.0.0: the priority lane is the default (--no-prio turns it off); drop it"),
            ("motd a\u{1}b", "f:1: control character"),
        ] {
            let e = ex("--config f", file).unwrap_err();
            assert_eq!(e, want, "{file:?}");
            assert!(!e.contains(SECRET), "{e}");
        }
        let bad_utf8: &'static [u8] = b"port 1\nmotd \xff\n";
        let e = expand_config(vec!["--config".into(), "f".into()], |_| Ok((bad_utf8.to_vec(), 0o600))).unwrap_err();
        assert_eq!(e, "f:2: not valid UTF-8");
        let long = format!("motd {}\n", "x".repeat(CONFIG_MAX_LINE));
        let e = expand_config(vec!["--config".into(), "f".into()], |_| Ok((long.into_bytes(), 0o600))).unwrap_err();
        assert_eq!(e, "f:1: line longer than 16 KiB");
        let big = vec![b'\n'; CONFIG_MAX_BYTES + 1];
        let e = expand_config(vec!["--config".into(), "f".into()], |_| Ok((big, 0o600))).unwrap_err();
        assert_eq!(e, "--config f: larger than 1024 KiB");
        let e = expand_config(vec!["--config".into(), "f".into()], |_| Err("No such file or directory".into())).unwrap_err();
        assert_eq!(e, "--config f: No such file or directory");
        // across lines: the file is named (no line), no value
        let e = ex("--config f", "dns-server 10.0.0.1\ndns-server 10.0.0.2\ndns-server 10.0.0.3\ndns-server 10.0.0.4\n").unwrap_err();
        assert!(e.starts_with("--config f: --dns-server: at most 3"), "{e}");
        let e = ex("--config f", "tls-cert s3cretVALUE.pem\n").unwrap_err();
        assert!(e.starts_with("--config f: --tls-cert and --tls-key must be given together") && !e.contains(SECRET), "{e}");
        assert!(ex("--config f --tls-cert c --tls-key k", "tls-cert s3cretVALUE.pem\n").is_ok()); // replaced by the command line
                                                                                                  // the first bad line wins
        assert_eq!(ex("--config f", "threads x\nbogus 1\n").unwrap_err(), "f:1: --threads: bad value (value not shown)");
        assert_eq!(ex("--config", "").unwrap_err(), "--config needs a value");
        assert_eq!(ex("--config a --config b", "").unwrap_err(), "--config: only one config file");
        // parse_args itself does not know --config (main expands it first)
        assert!(parse("--config f").is_err());
    }

    #[test]
    fn config_secret_warning() {
        let args = || vec!["--config".to_string(), "f".to_string()];
        let w = |mode, file: &'static str| expand_config_with(args(), load_ok(file, mode), &["--motd"]).unwrap().warning;
        assert!(w(0o644, "motd x").unwrap().contains("readable by group/others"));
        assert!(w(0o640, "motd x").is_some());
        assert!(w(0o600, "motd x").is_none());
        assert!(w(0o644, "port 1").is_none());
        // a secret list flag replaced on the command line still sits in the file: still a warning
        let a = vec!["--config".to_string(), "f".to_string(), "--cert-auth-key".to_string(), "z".to_string()];
        assert!(expand_config_with(a, load_ok("cert-auth-key x", 0o644), &["--cert-auth-key"]).unwrap().warning.is_some());
        assert!(SECRET_FLAGS.iter().all(|f| takes_value(f) == Some(true)));
        // 60.27 C6: the real list (expand_config's) holds --upstream
        let a = vec!["--config".to_string(), "f".to_string()];
        assert!(expand_config_with(a, load_ok("upstream socks5://u:pw@h", 0o644), SECRET_FLAGS).unwrap().warning.is_some());
    }

    #[test]
    fn upstream_flags() {
        // 60.27 / 60.32 C6: syntax in parse_args, the socks5h / --upstream-trust-dns pairing in check; no error quotes the URL
        let o = parse("--upstream socks5://u:hunter2@127.0.0.1:1080").unwrap();
        assert_eq!(o.upstream.as_deref(), Some("socks5://u:hunter2@127.0.0.1:1080"));
        assert!(parse("--upstream socks5h://h --upstream-trust-dns").is_ok());
        for (args, want) in [
            ("--upstream https://u:hunter2@h", "not supported"),
            ("--upstream socks5h://u:hunter2@h", "--upstream-trust-dns"),
            ("--upstream socks5://u:hunter2@h --upstream-trust-dns", "only with --upstream socks5h"),
            ("--upstream-trust-dns", "only with --upstream socks5h"),
            ("--upstream socks5://u:hunter2@::1:1080", "brackets"),
            ("--upstream ftp://u:hunter2@h", "scheme"),
            ("--upstream socks5://u:hunter2@h/", "no path"),
        ] {
            let Err(e) = parse(args) else { panic!("{args}: accepted") };
            assert!(e.contains(want) && !e.contains("hunter2") && !e.contains("u:"), "{args}: {e}");
        }
    }

    #[test]
    fn non_utf8_argument_is_an_error() {
        use std::os::unix::ffi::OsStringExt;
        let ok = utf8_args(["--port".into(), "7000".into()]).unwrap();
        assert_eq!(ok, ["--port", "7000"]);
        let e = utf8_args(["--tls-cert".into(), std::ffi::OsString::from_vec(vec![b'a', 0xff])]).unwrap_err();
        assert!(e.contains("not valid UTF-8") && !e.contains("\\xFF"), "{e}"); // 60.27: never echoed (may be a secret)
                                                                               // 60.27 C6: a non-flag-shaped unknown argument is not echoed (a mistyped --upstream=URL)
        let e = parse_args(["--upstream=socks5://u:hunter2@h".to_string()], 4).err().unwrap();
        assert!(!e.contains("hunter2"), "{e}");
        assert!(parse_args(["--nope".to_string()], 4).err().unwrap().contains("--nope"));
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("512K"), Some(512 << 10));
        assert_eq!(parse_size("1g"), Some(1 << 30));
        assert_eq!(parse_size("123"), Some(123));
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("M"), None);
    }

    /// 70.28: no error text has a REDACTION_MARKS character (the premise of the config-parse fuzz target's redaction
    /// check). Every flag on the command line and as a --config key, with bad and plausible values (none with a mark),
    /// missing values, values on value-less flags, and the config file's own line errors.
    #[test]
    fn error_texts_have_no_redaction_marks() {
        const VALUES: &[&str] = &[
            "x",
            "-1",
            "99999999999",
            "",
            "0",
            "1",
            "65535",
            "1-",
            "a,b",
            ":",
            "0x",
            "1.5M",
            "10/s",
            "10/s:0",
            "127.0.0.1",
            "127.0.0.1:1",
            "::1",
            "[::1]:1",
            "10.0.0.0/8",
            "10.0.0.0/99",
            "tcp:1",
            "udp:0",
            "socks5h://h:1",
            "socks5://h",
            "http://h:1/p",
            "ftp://h:1",
            "https://h:1",
            "socks5://[::1",
            "socks5://::1:1",
            "socks5://h:0",
            "socks5://h:99999",
            "socks5://h:x",
            "socks5://:1",
            "socks5://h:1/",
            "socks5://[::1]x:1",
            "socks5://[zz]:1",
            "socks5://[]:1",
            "1M/16K",
            "1M/2",
            "tcp,x",
            "tcp,unix",
            "0660",
            "999",
            "debug",
            "verbose",
            "chacha",
            "server",
            "/nonexistent/f",
        ];
        assert!(VALUES.iter().all(|v| !v.contains(|c| REDACTION_MARKS.contains(c))));
        let mut errors = Vec::new();
        let mut cmd = |args: Vec<String>| {
            if let Err(e) = parse_args(args, 4).and_then(check) {
                errors.push(e);
            }
        };
        cmd(vec!["x".into()]);
        cmd(vec!["--no-such-flag".into()]);
        for f in ["--credit-v2", "--prio", "--no-tcpmem-adapt", "--no-dns-coalesce"] {
            cmd(vec![f.into()]);
        }
        for &(flag, takes) in FLAGS {
            if takes {
                cmd(vec![flag.into()]);
                for v in VALUES {
                    cmd(vec![flag.into(), v.to_string()]);
                }
            } else {
                cmd(vec![format!("{flag}=x")]);
            }
        }
        let mut file = |data: String| {
            let r = expand_config(vec!["--config".into(), "f".into()], |_| Ok((data.into_bytes(), 0o644)));
            if let Err(e) = r.and_then(|e| parse_args(e.args, 4).and_then(check).map(|_| ())) {
                errors.push(e);
            }
        };
        for &(flag, takes) in FLAGS {
            let name = &flag[2..];
            if takes {
                file(format!("{name}\n"));
                for v in VALUES {
                    file(format!("{name} {v}\n"));
                }
            } else {
                file(format!("{name} x\n"));
            }
        }
        for line in
            ["--port 1", "no-such-flag 1", "Port 1", "config x", "credit-v2", "port 1\x07", "x".repeat(CONFIG_MAX_LINE + 1).as_str()]
        {
            file(format!("{line}\n"));
        }
        file("\n".repeat(CONFIG_MAX_BYTES + 1));
        let bad_utf8 = expand_config(vec!["--config".into(), "f".into()], |_| Ok((b"port \xff\n".to_vec(), 0o644)));
        errors.push(bad_utf8.err().unwrap());
        errors.push(expand_config(vec!["--config".into(), "f".into()], |_| Err("No such file or directory".into())).unwrap_err());
        // argument shapes and check() prerequisites (review)
        let mut cmd = |args: &[&str]| {
            if let Err(e) = expand_config(args.iter().map(|s| s.to_string()).collect(), |_| Ok((b"port 1\n".to_vec(), 0o644)))
                .and_then(|e| parse_args(e.args, 4).and_then(check))
            {
                errors.push(e);
            }
        };
        for args in [
            &["--config"][..],
            &["--config", "a", "--config", "b"],
            &["--upstream-trust-dns"],
            &["--metrics-listen", "127.0.0.1:6001"],
            &["--proxy-protocol", "tcp"],
            &["--proxy-protocol", "unix"],
            &["--proxy-protocol-from", "10.0.0.0/8"],
            &["--unix-mode", "660"],
            &["--tls-cert", "a"],
            &["--dns-server", "1.1.1.1", "--dns-server", "1.1.1.2", "--dns-server", "1.1.1.3", "--dns-server", "1.1.1.4"],
        ] {
            cmd(args);
        }
        // values that need a mark: only in a --config file, where the value is hidden (a mark may not be left over)
        let mut file = |data: String| {
            let r = expand_config(vec!["--config".into(), "f".into()], |_| Ok((data.into_bytes(), 0o644)));
            if let Err(e) = r.and_then(|e| parse_args(e.args, 4).and_then(check).map(|_| ())) {
                errors.push(e);
            }
        };
        let long_user = format!("socks5://{}:p@h:1", "u".repeat(300));
        let long_pw = format!("socks5://u:{}@h:1", "p".repeat(300));
        let mut marked = vec![long_user.as_str(), long_pw.as_str()];
        marked.extend(["socks5://%zz@h:1", "socks5://u%4:p@h:1", "http://a%3Ab:p@h:1", "socks5://u:p%@h:1", "socks5://@h:1"]);
        marked.extend(["socks5://u:p@h:1", "socks5://u@h", "http://u:p@h:1/x", "*.example.com", "a@b,c", "tcp,x@y"]);
        marked.extend(["x=1", "1M/1K=", "10/s:2^"]);
        for &(flag, takes) in FLAGS {
            if takes {
                for &v in &marked {
                    file(format!("{} {v}\n", &flag[2..]));
                }
            }
        }
        file("dns-server 1.1.1.1\ndns-server 1.1.1.2\ndns-server 1.1.1.3\ndns-server 1.1.1.4\n".into());
        file("upstream-trust-dns\n".into());
        assert!(errors.len() > 1000, "{} errors", errors.len());
        let bad: Vec<&String> = errors.iter().filter(|e| e.contains(|c| REDACTION_MARKS.contains(c))).collect();
        assert!(bad.is_empty(), "error texts with a redaction mark ({REDACTION_MARKS}): {bad:#?}");
    }
}
