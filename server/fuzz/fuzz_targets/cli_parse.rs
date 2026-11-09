#![no_main]
//! 70.01 cli.rs parse_args on random argv: never panics; an accepted result keeps the documented limits.
//! Input: arguments separated by NUL. A token whose first byte b is 0x01..=0x1f is replaced by a known flag (so the
//! fuzzer reaches every value parser): FLAGS[(b - 1 + 31 * (token length - 1)) % FLAGS.len()], so 1-byte tokens give
//! the first 31 entries, 2-byte tokens the next 31 and 3-byte tokens the rest (60.16: `b % len` reached only 31 of 40);
//! other tokens are used as they are (lossy UTF-8).
use finalwisp_fuzz::cli;
use libfuzzer_sys::fuzz_target;

const FLAGS: [&str; 77] = [
    "--log-level", // 60.24 C4 (missing here since C4/C5)
    "--log-conns",
    "--log-streams",    // 60.35
    "--metrics-listen", // 60.29 C5
    "--host",
    "--port",
    "--threads",
    "--buffer",
    "--connect-timeout",
    "--drain-timeout",
    "--metrics-interval",
    "--tcpmem-adapt",
    "--no-credit-pace",
    "--park-rcvlock",    // 60.47
    "--adaptive-splice", // 60.46 opt-in (v1.2.0)
    "--allow-loopback",
    "--allow-private",
    "--graceful-close",
    "--no-splice",
    "--balance",
    "--no-tfo",
    "--no-keepalive",
    "--no-udp",
    "--no-credit-v2",
    "--tls-cert",
    "--tls-key",
    "--tls-cipher-order",
    "--tls-rekey-records",
    "--notsent-lowat",
    "--dns-threads",
    "--dns-own",
    "--dns-server",
    "--no-prio",
    "--auth-file",
    "--cert-auth-key",
    "--motd",
    "--mem-budget",
    "--max-conns",            // 60.20 C3a
    "--max-streams-per-conn", // 60.20 C3a
    "--allow-host",           // 60.20 C1
    "--block-host",
    "--allow-ports",
    "--block-ports",
    "--allow-dest",
    "--block-dest",
    "--block-smtp",
    "--no-direct-ip",
    "--no-ipv6-targets",
    "--allow-self",
    "--allow-embedded-v4",
    "--trusted-proxy", // 60.20 C2 / C3b
    "--real-ip-header",
    "--max-conns-per-ip",
    "--stream-rate-per-ip",
    "--conn-rate-per-ip", // 60.40
    "--download-rate",    // 60.30 C10a
    "--upload-rate-per-stream",
    "--listen-unix", // 60.31 C7
    "--unix-mode",
    "--upstream", // 60.32 C6
    "--upstream-trust-dns",
    "--upload-rate", // 60.25 C10b
    "--upload-rate-per-ip",
    "--proxy-protocol", // 60.34
    "--proxy-protocol-from",
    "--stream-rate-per-dest", // 60.39
    "--stream-rate-per-dest-minute",
    "-h",
    "--help",
    "--credit-v2", // 60.18 removed: the "removed in base-4" error
    "--prio",
    "--no-tcpmem-adapt",
    "--no-dns-coalesce",
    "server",
    "client",
    "::",
    "64M",
];
// 1- to 3-byte selector tokens reach 3 x 31 entries
const _: () = assert!(FLAGS.len() <= 93);

fuzz_target!(|data: &[u8]| {
    let args: Vec<String> = data
        .split(|&b| b == 0)
        .map(|t| match t.first() {
            Some(&b @ 1..=0x1f) => FLAGS[(b as usize - 1 + 31 * (t.len() - 1)) % FLAGS.len()].to_string(),
            _ => String::from_utf8_lossy(t).into_owned(),
        })
        .collect();
    let help = args.iter().any(|a| a == "-h" || a == "--help");
    match cli::parse_args(args.clone(), 4) {
        Ok(o) => {
            assert!(o.connect_timeout <= cli::MAX_CONNECT_TIMEOUT);
            assert!(o.drain_timeout <= cli::MAX_DRAIN_TIMEOUT && o.metrics_interval <= cli::MAX_METRICS_INTERVAL);
            assert!(o.dns_servers.len() <= finalwisp_fuzz::dns::MAX_SERVERS);
            let certs = args.iter().filter(|a| *a == "--tls-cert").count();
            assert!(o.tls_pairs.len() <= certs);
            assert!(o.dns_servers.is_empty() || o.dns_own); // 70.09 --dns-server implies --dns-own
                                                            // main() builds these from the options: they must not overflow
            let _ = std::time::Instant::now() + std::time::Duration::from_secs(o.connect_timeout);
            // 60.30 C10a a rate is off or in range (the kernel's u32 form, never its "no limit" value)
            let rate_ok = |r: u32| r == 0 || (finalwisp_fuzz::net::MIN_RATE..=finalwisp_fuzz::net::MAX_RATE).contains(&r);
            assert!(rate_ok(o.pace.download) && rate_ok(o.pace.upload));
            // 60.31 C7 (umask(!mode & 0777) in net::listen_unix)
            assert!(o.unix_mode.is_none_or(|m| m <= 0o777));
            // 60.25 C10b R 8K..1T, B >= 16K and >= R/10 (meter.rs milli-byte arithmetic, the 100 ms resume tick)
            for (r, b) in [o.upload_rate, o.upload_rate_ip].into_iter().flatten() {
                assert!(((8 << 10)..=(1 << 40)).contains(&r) && b >= (16 << 10) && b >= r.div_ceil(10) && b <= (1 << 42));
            }
        }
        Err(e) => assert!(!e.is_empty() || help, "empty error without --help"),
    }
    for a in &args {
        let _ = cli::parse_size(a);
    }
});
