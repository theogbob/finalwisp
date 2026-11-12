#![no_main]
//! 70.01 cli.rs parse_args on random argv: never panics; an accepted result keeps the documented limits.
//! Input: arguments separated by NUL. A token whose first byte b is 0x01..=0x1f is replaced by a known flag (so the
//! fuzzer reaches every value parser): FLAGS[(b - 1 + 31 * (token length - 1)) % FLAGS.len()], so 1-byte tokens give
//! the first 31 entries, 2-byte tokens the next 31, 3-byte tokens the next 31 and 4-byte tokens the rest (60.16: `b % len`
//! reached only 31 of 40; since 1.3.0 the list has more than 93 entries). The index wraps at FLAGS.len(), so when the
//! list grows, a token whose index was at or above the old length (3 bytes from 0x1d on and longer ones, at 90
//! entries; 4 bytes from 0x05 on, at 97) selects another flag: a saved input keeps its bytes, not its flags;
//! other tokens are used as they are (lossy UTF-8).
//! 60.60 then the whole way main takes (cli::command: `--name=value`, the printing commands, preset, config file,
//! parse, check) and what main prints from it (ui.rs): never panics; an error is never empty and ends with the Try
//! line; `--name value` and `--name=value` give the same argument list.
use finalwisp_fuzz::{cli, ui};
use libfuzzer_sys::fuzz_target;

const FLAGS: [&str; 108] = [
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
    "--adaptive-splice", // 60.46 (default on since v1.2.1)
    "--no-adaptive-splice",
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
    "--no-block-smtp", // 60.59 (new entries go last: the selector bytes of the entries above stay)
    "--show-config",   // 60.60
    "--version",
    "-V",
    "--preset",
    "public",
    "--print-preset",
    "--config",
    "--port=7000",
    "--motd=--help",
    "--block-smtp=on",
    "limits",
    "--dns-share", // 60.58
    "--no-dns-share",
    "--no-nofile-raise", // 60.57 A1
    "--fd-admission",    // 60.57 C
    "--no-fd-admission",
    "--conn-share",
    "--no-conn-share",
    "--dns-reserve", // 60.58
    "--no-dns-reserve",
    "--no-dns-own",
    "--tcpmem-share", // 60.63 E
    "--no-tcpmem-share",
    "--port-share",
    "--no-port-share",
    "--dest-failfast",
    "--no-dest-failfast",
    "--net-watch",
    "--no-net-watch",
];
// 1- to 4-byte selector tokens reach 4 x 31 entries
const _: () = assert!(FLAGS.len() <= 124);

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
    // 60.60 `--name=value`: splitting is stable, and the joined form of the split list splits back to it. (Not with
    // a --help=WORD: its word is an optional topic and not a value, so the word itself is split by a second pass.)
    let help_eq = args.iter().any(|a| a.starts_with("--help="));
    if let Some(split) = cli::split_eq(args.clone()).ok().filter(|_| !help_eq) {
        assert!(cli::split_eq(split.clone()).as_ref() == Ok(&split));
        let takes = |t: &str| matches!(t, "--config" | "--preset" | "--print-preset") || cli::FLAGS.iter().any(|&(f, v)| v && f == t);
        let (mut joined, mut i) = (Vec::new(), 0);
        while i < split.len() {
            if takes(&split[i]) && i + 1 < split.len() {
                joined.push(format!("{}={}", split[i], split[i + 1]));
                i += 2;
            } else {
                joined.push(split[i].clone());
                i += 1;
            }
        }
        assert!(cli::split_eq(joined).as_ref() == Ok(&split));
    }
    // the way main takes, and its texts
    let plain = ui::Paint(false);
    match cli::command(args, 4, |_| Ok((b"threads 2\nblock-smtp\n".to_vec(), 0o600))) {
        Ok(cli::Command::Special(cli::Special::Help(topic))) => match topic {
            Some(t) => match ui::help_topic(plain, &t) {
                Ok(page) => assert!(!page.is_empty()),
                Err(e) => assert!(e.starts_with("finalwisp: --help: no ") && e.ends_with("Try: finalwisp --help\n")),
            },
            None => assert!(!ui::help_main(plain).is_empty()),
        },
        Ok(cli::Command::Special(_)) => {}
        Ok(cli::Command::Start(st)) => {
            assert!(st.opts.connect_timeout <= cli::MAX_CONNECT_TIMEOUT && st.opts.drain_timeout <= cli::MAX_DRAIN_TIMEOUT);
            // one row per setting, and the texts main prints from them
            for (n, s) in st.settings.iter().enumerate() {
                assert!(st.settings[..n].iter().all(|t| t.key != s.key), "setting {} twice", s.key);
                // a row without a layer is the default (or what another option implies): never `changed`
                assert!(s.src.is_some() || !s.changed, "{}: changed without a layer", s.key);
                // the proxy URL shows no user and no password
                if s.key == "upstream" {
                    assert!(!s.value.contains('@') || s.value.contains("://***@"), "upstream row");
                }
            }
            let block = ui::block(&ui::layer_rows(&st));
            assert!(block.is_empty() || block.ends_with('\n'));
            assert!(!ui::show_config(plain, &st, &[], &[]).is_empty());
        }
        Err((e, _)) => {
            assert!(!e.is_empty());
            for tty in [false, true] {
                let shown = ui::usage_error(&e, tty);
                let last = shown.lines().last().unwrap_or("");
                assert!(shown.starts_with("finalwisp: ") && last.starts_with("Try: finalwisp --help"), "{shown}");
            }
        }
    }
});
