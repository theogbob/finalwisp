//! 20.01 / 60.04 F4 command line: `parse_args` turns the arguments into `Opts` or an error message.
//! Pure (no file/network I/O, no exit; only `--dns-server ...%ifname` asks the kernel for the interface index), so it is unit-tested; main() prints the error and exits 2.
//! 60.20 C8: `expand_config` turns `--config FILE` into flags first (main reads the file and passes its bytes in).
//! 60.60: OPTIONS is the one table of the options (the parser's FLAGS list, --help and --show-config come from it; the
//! texts are rendered by ui.rs).
use std::net::IpAddr;

/// 60.60 one option: its name, the placeholder of its value ("" = a switch), its --help topic, the default as --help
/// shows it, a one-line summary and the longer text of `--help TOPIC`. `parsed` = parse_args handles it (it is in FLAGS
/// and a --config file accepts it); the others are handled before parse_args (--config, --preset, --help, ...).
pub struct OptSpec {
    pub name: &'static str,
    pub arg: &'static str,
    pub topic: &'static str,
    pub default: &'static str,
    pub summary: &'static str,
    pub long: &'static str,
    pub parsed: bool,
}

impl OptSpec {
    const fn early(mut self) -> OptSpec {
        self.parsed = false;
        self
    }
}

const fn o(
    name: &'static str,
    arg: &'static str,
    topic: &'static str,
    default: &'static str,
    summary: &'static str,
    long: &'static str,
) -> OptSpec {
    OptSpec { name, arg, topic, default, summary, long, parsed: true }
}

/// 60.60 the --help topics in the order --help lists them: (name, one line, the first paragraph of `--help NAME`)
pub const TOPICS: &[(&str, &str, &str)] = &[
    (
        "config",
        "config file, presets, checking the settings",
        "Options come from a preset, a config file and the command line, in this order; the later one wins. These \
         options choose the layers and print what they give. They work on the command line only (a config file can \
         name a preset: preset NAME).",
    ),
    ("listen", "address, port, threads, unix socket", "Where the server listens and how many threads serve."),
    (
        "tls",
        "certificates for wss://",
        "Built-in TLS (kernel TLS). Without these options the server speaks plain ws://, which is right behind a \
         reverse proxy that does TLS.",
    ),
    (
        "client-ip",
        "the real client address behind a proxy or load balancer",
        "Behind a reverse proxy or a load balancer every connection comes from the proxy's address. These options tell \
         the server who may name the real client address, so the per-address limits and the logs see the clients.",
    ),
    (
        "limits",
        "timeouts, connections, streams, rates and bandwidth",
        "Every limit is off unless you set it (the public preset sets some: finalwisp --print-preset public).",
    ),
    (
        "destinations",
        "where clients may connect: hosts, ports, address ranges",
        "By default clients reach every public address and port; loopback, private ranges and the server's own \
         addresses are blocked. A refused CONNECT gets Wisp CLOSE 0x48.",
    ),
    ("auth", "passwords and keys for clients", "Wisp v2 authentication. Without these options every client is served."),
    (
        "upstream",
        "send every stream through a SOCKS5 or HTTP proxy",
        "One outgoing proxy for every TCP stream. Off by default: the server connects to the targets itself.",
    ),
    ("dns", "resolver threads and name servers", "How target host names are looked up."),
    ("logs", "log level, connection and stream logs, metrics", "Everything is written to stderr, one line per event."),
    (
        "memory",
        "memory budget, kernel TCP memory",
        "The server keeps its memory under a budget and holds back traffic that would fill the kernel's socket buffers.",
    ),
    ("advanced", "tuning and diagnostic switches", "Leave these at the default unless a measurement or a problem points here."),
];

/// 60.60 the options --help shows on its first page
pub const COMMON: &[&str] =
    &["--host", "--port", "--preset", "--config", "--tls-cert", "--tls-key", "--trusted-proxy", "--threads", "--mem-budget", "--log-level"];

/// 60.60 THE option table. A new option is one row here and its arm in parse_args; new rows go LAST (the fuzz corpus
/// selects flags by their position in FLAGS). Rule (60.16): an option is in this table or it does not exist.
/// A placeholder (`arg`) is part of error texts: no REDACTION_MARKS character in it.
pub const OPTIONS: &[OptSpec] = &[
    o("--config", "FILE", "config", "", "read options from FILE", "Read options from a file: one option per line, the name without the leading dashes, then its value (port 6001), or the name alone for a switch. Lines that start with # are skipped. An option after --config overrides the file; a list option on the command line replaces the file's whole list. Use a file for secrets such as an --upstream URL with a password (mode 0600).").early(),
    o("--preset", "NAME", "config", "none", "built-in settings: public or none", "Start from a set of options that is built into the binary. public: the settings for a server that anyone can reach. none: no preset (use it to drop the preset of a start command, such as the Docker image's). The order is preset, config file, command line; the later one wins. In a config file: preset NAME.").early(),
    o("--print-preset", "NAME", "config", "", "print the settings of a preset and exit", "Print the settings of the preset on stdout, in the config file format, and exit. Nothing else is checked or started.").early(),
    o("--show-config", "", "config", "", "check the options, print the settings, exit", "Check the preset, the config file and the command line, print every setting in effect with the layer that set it and what this host allows (kernel, memory, open files), then exit with status 0. No listener is opened. A wrong option exits with status 2, as at a normal start.").early(),
    o("--help", "[TOPIC]", "config", "", "print this help, or the options of a topic", "Print the overview, the options of one topic, or with the topic all a one-line list of every option. Also -h.").early(),
    o("--version", "", "config", "", "print the version and exit", "Print the version and exit. Also -V.").early(),
    o("--host", "IP", "listen", "127.0.0.1", "address to listen on", "The address to listen on: an IP address, not a name. Use 0.0.0.0 or :: for direct clients; keep 127.0.0.1 behind a reverse proxy on the same host."),
    o("--port", "PORT", "listen", "6001", "port to listen on", "The TCP port to listen on (1 to 65535). A bare number does the same: finalwisp 7000. 0 is accepted but do not use it: the kernel then picks the port, and the start line does not show it."),
    o("--threads", "N", "listen", "one per CPU", "worker threads", "The number of worker threads. Lower it to leave CPUs to other services. 0 counts as 1."),
    o("--buffer", "N", "advanced", "128", "first upload credit of a stream, in packets", "The first stream credit (packets) the server grants. 0 counts as 1. Leave it, except on a small host where streams that upload and download at once cause kernel TCP memory pressure: --buffer 32 holds less memory there, but a large upload on an open connection waits one more round trip."),
    o("--allow-loopback", "", "destinations", "off", "let clients reach loopback addresses", "Let clients reach loopback targets (127.0.0.0/8, ::1). Only for tests or a trusted service on the same host."),
    o("--allow-private", "", "destinations", "off", "let clients reach private address ranges", "Let clients reach private, link-local, carrier-grade NAT and other reserved ranges. Only on a trusted network. It does not lift the blocks on the server's own addresses and on IPv6 forms that carry IPv4."),
    o("--connect-timeout", "SECS", "limits", "10", "how long a connect to a target may take", "How long a connect to a target may take (at most 86400). A timeout closes the stream with CLOSE 0x43."),
    o("--drain-timeout", "SECS", "limits", "30", "time for open connections at shutdown", "On SIGTERM or SIGINT, how long open connections may go on before they are closed (at most 86400; 0 exits at once)."),
    o("--graceful-close", "", "advanced", "off", "close finished target connections with FIN", "Close a finished target connection with FIN instead of a TCP reset when the client closes the stream. The reset is much faster under connection churn and leaves no TIME_WAIT sockets."),
    o("--no-splice", "", "advanced", "splice on", "copy downloads in user space, not with splice", "Copy downloads through user space instead of the kernel's zero-copy splice. On a small host with far clients it can hold less kernel TCP memory; with near, fast clients downloads get slower. See the docs page memory.md, small hosts."),
    o("--balance", "", "advanced", "off", "hand new connections to the least busy thread", "Hand each new connection to the least busy thread instead of letting the kernel choose. Helps a few busy long-lived connections on big machines (4-11% on 36-72 threads) and costs 1-7% when many short connections come and go."),
    o("--no-tfo", "", "advanced", "TFO on", "no TCP Fast Open to targets", "Do not use TCP Fast Open to targets. Try it if a middlebox drops SYN packets that carry data."),
    o("--no-keepalive", "", "advanced", "keepalive on", "no dead-peer detection (TCP keepalive)", "Turn off dead-peer detection on clients and targets (TCP keepalive). With it on, an idle dead peer is closed after about 180 s."),
    o("--no-udp", "", "destinations", "UDP on", "refuse UDP streams", "Refuse Wisp UDP streams (CLOSE 0x48)."),
    o("--no-credit-v2", "", "advanced", "credit v2 on", "use the old upload credit scheme", "Turn off the upload credit scheme that pings the client after a CONTINUE. A compatibility fallback; leave it on."),
    o("--tls-cert", "FILE", "tls", "off", "serve wss:// with this certificate (PEM)", "Serve wss:// with kernel TLS. Give --tls-cert and --tls-key together; both files are PEM. Repeat the pair for more names: the certificate is picked by SNI, and the first pair is used when nothing matches. Needs the kernel's tls module (modprobe tls). SIGHUP reloads the files."),
    o("--tls-key", "FILE", "tls", "off", "the private key of the certificate (PEM)", "The private key that belongs to the --tls-cert before or after it (pairs match in order)."),
    o("--tls-cipher-order", "SIDE", "tls", "client", "client or server: whose cipher order wins", "server prefers AES-GCM over ChaCha20 whatever the client prefers. Useful on CPUs with AES instructions."),
    o("--tls-rekey-records", "N", "tls", "8388608", "TLS 1.3: new keys after N records", "With built-in TLS 1.3, send a KeyUpdate after N records. 0, or 16777216 and above, turns it off. Works only on Linux 6.14 or later."),
    o("--notsent-lowat", "BYTES", "advanced", "131072", "unsent data the kernel holds per client socket", "TCP_NOTSENT_LOWAT on client sockets: how much unsent data the kernel holds per socket. 0 leaves it to the kernel. A plain number of bytes."),
    o("--dns-threads", "N", "dns", "16", "resolver threads", "Resolver threads. Each runs one lookup at a time, so at most N new names are looked up at once; further lookups wait. Identical names looked up at the same time share one lookup. 0 counts as 1."),
    o("--dns-own", "", "dns", "off", "use the built-in resolver, not the system's", "Use the built-in resolver instead of the system's (getaddrinfo). It gives up on a dead name server after 1-2 s instead of about 10 s. From /etc/resolv.conf it reads the name servers (the first 3) and the options timeout, attempts and rotate; its other options and sortlist are ignored. It reads /etc/hosts. The public preset sets it."),
    o("--dns-server", "IP[:PORT]", "dns", "from /etc/resolv.conf", "name server for the built-in resolver", "A name server for the built-in resolver. Repeat it for up to 3. Turns on --dns-own. IPv6 with a port: [addr]:port."),
    o("--no-prio", "", "advanced", "two lanes", "one output queue per client, not two", "Use one output queue per client. By default data of bulk streams waits in a second lane, so small replies on other streams go first."),
    o("--auth-file", "FILE", "auth", "off", "require a password (Wisp v2); FILE: user:password", "Wisp v2 password authentication. The file holds one user:password per line; # lines and blank lines are skipped. The passwords are plain text: keep the file private."),
    o("--cert-auth-key", "FILE", "auth", "off", "require a client key (Wisp v2, ed25519)", "Wisp v2 ed25519 key authentication. The file holds one or more PEM PUBLIC KEY blocks. Repeatable."),
    o("--motd", "TEXT", "auth", "off", "message of the day for Wisp v2 clients", "A Wisp v2 message of the day, sent to every client."),
    o("--mem-budget", "SIZE", "memory", "automatic", "memory to stay under, 0 turns it off", "The memory the server plans to stay under (K, M, G are KiB, MiB, GiB). Automatic: the memory limit of the container or service (cgroup), else half of the machine's memory. Near the budget the server shrinks queues and buffers and stops taking new streams instead of running into the out-of-memory killer. 0 turns the budget off."),
    o("--tcpmem-adapt", "", "memory", "off", "shrink socket buffers near the kernel TCP limit", "When the host is near its kernel TCP memory limit (net.ipv4.tcp_mem), shrink the buffers of this server's sockets to remote peers. For a small host that runs out of TCP memory under many fast streams. Needs cgroup v2 socket accounting, Linux 5.15 or later, the host network namespace, credit v2 and the memory budget; --show-config says why it is off otherwise."),
    o("--no-credit-pace", "", "memory", "credit pace on", "give upload credit while a download waits", "Turn off credit pacing. By default a stream gets no new upload credit while its download waits on the client, so streams that upload and download at once cannot fill the kernel socket buffers faster than the client reads. Turn it off only to compare or roll back."),
    o("--park-rcvlock", "", "memory", "off", "freeze the receive buffer of a waiting download", "Stop the kernel from growing the receive buffer of a download's target connection while the stream waits on a slow client. Many waiting downloads then hold less kernel memory on a small host. The buffer is never made smaller and grows again once the client catches up. Needs Linux 5.15 or later (the server refuses to start otherwise)."),
    o("--adaptive-splice", "", "memory", "on", "the default; kept for 1.2.0 configs", "Turn adaptive splice on. It is on by default; this option undoes an earlier --no-adaptive-splice and keeps 1.2.0 configs valid."),
    o("--no-adaptive-splice", "", "memory", "adaptive splice on", "same read size for far and near clients", "Turn off adaptive splice. By default a client 10 ms or more away with more than 4 streams whose socket is backed up gets 64 KiB reads from its targets instead of 256 KiB, so many slow far downloads hold less kernel TCP memory on a small host. Clients closer than 10 ms, clients behind a reverse proxy on the same host and clients on --listen-unix always get 256 KiB. Turn it off only to compare or roll back."),
    o("--metrics-interval", "SECS", "logs", "off", "print a line with all counters every SECS", "Print one line with all counters on stderr every SECS seconds, and a last one at exit. 0 is off."),
    o("--max-conns", "N", "limits", "off", "the most client connections in total", "The most client connections in total. A new connection over the limit is reset right after accept. 0 is off."),
    o("--max-streams-per-conn", "N", "limits", "off", "the most streams on one connection", "The most streams on one connection. A CONNECT over it is refused with CLOSE 0x49 (throttled); the connection stays. 0 is off. The public preset sets 1024."),
    o("--allow-host", "NAMES", "destinations", "none", "only these host names (and names below them)", "Only these host names and the names below them (example.com also allows a.example.com). Any other name is refused with CLOSE 0x48. IP addresses skip host rules. Comma-separated, repeatable."),
    o("--block-host", "NAMES", "destinations", "none", "refuse these host names", "Refuse these host names and the names below them. Wins over --allow-host. Comma-separated, repeatable."),
    o("--allow-ports", "PORTS", "destinations", "none", "only these ports: 443 or tcp:80-90,udp:53", "Only these ports (1-65535). An entry is N or N-M, optionally after tcp: or udp:; without a prefix it covers both. A list with only tcp: entries leaves UDP ports open. Comma-separated, repeatable."),
    o("--block-ports", "PORTS", "destinations", "none", "refuse these ports", "Refuse these ports (the form of --allow-ports). Wins over --allow-ports."),
    o("--allow-dest", "CIDRS", "destinations", "none", "let these addresses through the address blocks", "Let these addresses or ranges through every address block (loopback, private, own, embedded IPv4). Not through --block-dest. Comma-separated, repeatable."),
    o("--block-dest", "CIDRS", "destinations", "none", "refuse these addresses or ranges", "Refuse these addresses or ranges. Checked first. Comma-separated, repeatable."),
    o("--block-smtp", "", "destinations", "off", "refuse the mail ports 25, 465 and 587", "Refuse the mail ports, the same as --block-ports tcp:25,tcp:465,tcp:587. Without it the server prints a hint at startup. The public preset sets it."),
    o("--no-direct-ip", "", "destinations", "off", "refuse a CONNECT to an IP address", "Refuse a CONNECT to an IP address (also forms such as 127.1 or 2130706433): clients must send a name."),
    o("--no-ipv6-targets", "", "destinations", "off", "IPv4 targets only", "Use IPv4 targets only: no IPv6 addresses, no AAAA lookups."),
    o("--allow-self", "", "destinations", "off", "let clients reach the server's own addresses", "Let clients reach the server's own interface addresses. Blocked by default, also with --allow-private."),
    o("--allow-embedded-v4", "", "destinations", "off", "let clients reach IPv6 forms that carry IPv4", "Let clients reach IPv6 forms that carry an IPv4 address (::/96, 6to4, Teredo, local-use NAT64). Blocked by default."),
    o("--trusted-proxy", "CIDRS", "client-ip", "none", "reverse proxies that name the client address", "The reverse proxies whose client address header is believed (--real-ip-header). From any other peer the header is ignored. List only your own proxies; per-address limits then count the real clients. Comma-separated, repeatable."),
    o("--real-ip-header", "NAME", "client-ip", "x-forwarded-for", "the header a trusted proxy puts the address in", "The one header read from a trusted proxy. x-forwarded-for is read right to left, skipping trusted hops. Any other name (x-real-ip, cf-connecting-ip) is read as one address."),
    o("--max-conns-per-ip", "N", "limits", "off", "the most connections per client address", "The most connections per client address (an IPv4 address or an IPv6 /64). A direct client over it is reset at accept; behind a trusted proxy it gets 429 Too Many Requests. 0 is off."),
    o("--stream-rate-per-ip", "R[/B]", "limits", "off", "new streams per second per client address", "New streams per second per client address, with a burst of B (default 2R). R is 1 to 1000000. Over it: CLOSE 0x49."),
    o("--conn-rate-per-ip", "R[/B]", "limits", "off", "new connections per second per client address", "New connections per second per client address, with a burst of B (default 2R). 200 connections per 10 seconds is 20/200. Over it: as --max-conns-per-ip."),
    o("--stream-rate-per-dest", "R[/B]", "limits", "off", "new streams per second to one destination", "New streams per second to one destination (target address and port), all clients together, with a burst of B (default 2R). Over it: CLOSE 0x49."),
    o("--stream-rate-per-dest-minute", "N", "limits", "off", "new streams per minute to one destination", "New streams per minute to one destination, all clients together (1 to 60000000). Over it: CLOSE 0x49."),
    o("--download-rate", "RATE", "limits", "off", "bytes per second to one client connection", "The most the server sends on one client connection per second, all its streams together (kernel TCP pacing). 16K to 4095M bytes per second; K, M, G are KiB, MiB, GiB; 1M is 8.4 Mbit/s. 0 is off. Turns off splice."),
    o("--upload-rate-per-stream", "RATE", "limits", "off", "bytes per second to one target, per stream", "The most the server sends to one TCP target per second, per stream (kernel TCP pacing). 16K to 4095M; 0 is off."),
    o("--log-level", "LEVEL", "logs", "info", "error, warn, info or debug", "Which lines are printed on stderr. error: fatal startup errors only. warn: also warnings and hints. info: also the start block, shutdown and metrics lines. debug: also one line with every start detail, and a line when a connection opens (with --log-conns)."),
    o("--log-conns", "", "logs", "off", "a line per connection, with the client address", "One line per connection when it closes: client address, duration, bytes, close reason."),
    o("--log-streams", "", "logs", "off", "a line per stream, with the target host", "One line per stream (client address, target host and port, bytes, close reason) and one per refused CONNECT. This logs where your users go: a privacy decision."),
    o("--metrics-listen", "[ADDR:]PORT", "logs", "off", "serve Prometheus metrics on this port", "Serve Prometheus metrics at GET /metrics on their own port. A bare port listens on 127.0.0.1. No authentication: keep it on loopback or a private address. It cannot share the Wisp port."),
    o("--listen-unix", "PATH", "listen", "off", "also listen on a unix socket (plain ws://)", "A second listener on a unix socket, next to the TCP one. Plain ws:// only. Meant for a reverse proxy on the same host: its clients are trusted to send the client address header, like --trusted-proxy."),
    o("--unix-mode", "OCTAL", "listen", "660", "permissions of the unix socket file", "Permissions of the unix socket file. Whoever may write the file may connect. Needs --listen-unix."),
    o("--upstream", "URL", "upstream", "off", "send every TCP stream through this proxy", "Send every TCP stream through one proxy: socks5://, socks5h:// or http:// (HTTP CONNECT), then [USER:PASS@]HOST[:PORT]. Default ports: 1080 for SOCKS, 80 for HTTP. UDP streams are then refused with CLOSE 0x48. A URL with a password belongs in a --config file with mode 0600, not on the command line."),
    o("--upstream-trust-dns", "", "upstream", "off", "let a socks5h proxy resolve the names", "Required with socks5h://, refused otherwise: the proxy resolves the target names instead of finalwisp, so the address rules apply to IP literals only."),
    o("--upload-rate", "R[/B]", "limits", "off", "bytes per second read from one connection", "The most the server reads from one client connection per second (all its streams). R is 8K to 1T; burst B defaults to max(R, 16K) and must be at least 16K and R/10. Over the limit the client is not read until it is under again; nothing is dropped."),
    o("--upload-rate-per-ip", "R[/B]", "limits", "off", "the same, shared by one client address", "The same as --upload-rate, shared by all connections of one client address."),
    o("--proxy-protocol", "LISTENERS", "client-ip", "off", "require a PROXY header on tcp, unix or both", "Every connection on that listener (tcp, unix or both, comma-separated) must start with a PROXY protocol v1 or v2 header. Use it behind a TCP load balancer that sends one. A connection without the header is reset."),
    o("--proxy-protocol-from", "CIDRS", "client-ip", "none", "who may send the PROXY header on TCP", "The load balancers allowed to send the PROXY header on TCP. Required with --proxy-protocol tcp. Any other peer is reset. Comma-separated, repeatable."),
    o("--no-block-smtp", "", "destinations", "", "undo --block-smtp", "Undo --block-smtp of a preset, a config file or earlier on the command line. It does not remove the mail ports from a --block-ports list."),
    o("--dns-share", "", "dns", "off", "share the resolver threads between clients", "Share the resolver threads between clients. A thread that comes back goes to the client address with the fewest lookups running, and for that address to its connection with the fewest. A new client then waits for one thread to come back, not behind the queue of a client that has lookups running. Nothing is refused, no thread is kept free, and a client alone uses every thread. Needs 2 or more resolver threads; best with --dns-own. --dns-reserve adds kept threads to it."),
    o("--no-dns-share", "", "dns", "", "undo --dns-share", "Undo --dns-share of a preset, a config file or earlier on the command line. Refused together with --dns-reserve, which needs it."),
    o("--no-nofile-raise", "", "limits", "raise on", "keep the open-file limit of the start", "Keep the soft open-file limit (RLIMIT_NOFILE) the server was started with. By default the server raises its soft limit to the hard limit at startup, but not above 1048576, and never lowers it. Each connection and each stream needs one file descriptor, so the limit bounds connections plus streams. The start block shows the limit in effect."),
    o("--fd-admission", "", "limits", "off", "no new connections when open files run short", "Keep room for the connections that are already open. While 7/8 of the file descriptors the server can use are handed out to the worker threads, a new connection is reset right after accept; this ends below 13/16. Open connections and their new streams go on. Without it the server takes connections until the last file descriptor, and then streams on open connections are refused (CLOSE 0x49). The public preset sets it."),
    o("--no-fd-admission", "", "limits", "", "undo --fd-admission", "Undo --fd-admission of a preset, a config file or earlier on the command line."),
    o("--conn-share", "", "limits", "off", "one address cannot take most of the open files", "Stop one client address from taking the file descriptors that other clients use. From 3/4 of the usable file descriptors handed out (until below 11/16), a client address (an IPv4 address or an IPv6 /64) that holds more than half of them gets no new connection, if all other addresses together hold at least 1/64 of them and at least 256. A direct client is reset at accept; behind a trusted proxy it gets 429 Too Many Requests. Its open connections go on. Never applies to loopback, private and other addresses that are not public, to --trusted-proxy addresses and to a client without a client address. Behind a reverse proxy it needs --trusted-proxy, or every client has the proxy's address. The public preset sets it."),
    o("--no-conn-share", "", "limits", "", "undo --conn-share", "Undo --conn-share of a preset, a config file or earlier on the command line."),
    o("--dns-reserve", "", "dns", "off", "keep resolver threads for clients with fast names", "Keep a quarter of the resolver threads (at least one) for clients whose names answer fast. A client is slow while one of its lookups has run for 1 s, and for 60 s after such a lookup: its connection, and every connection of its address when that is a public address. All slow clients together use the other threads and no more. So names that never answer cannot take every thread, and the name of another client starts at once. Costs: the kept threads stand free while slow lookups wait; a client on the same public address as a slow client is slow with it; a client that opens pages with dead names in quick succession waits longer for the live names of its next pages. Turns on --dns-share, which it is a part of. Needs 2 or more resolver threads. The public preset sets it."),
    o("--no-dns-reserve", "", "dns", "", "undo --dns-reserve", "Undo --dns-reserve of a preset, a config file or earlier on the command line. It leaves --dns-share as it was set."),
    o("--no-dns-own", "", "dns", "", "undo --dns-own: use the system resolver", "Undo --dns-own of a preset, a config file or earlier on the command line: names are looked up with the system resolver (getaddrinfo). Refused together with --dns-server."),
    o("--tcpmem-share", "", "limits", "off", "one address cannot keep adding unread downloads", "Stops one client address from adding downloads that it does not read while the host's TCP memory is short. The server reads the host's TCP memory against the kernel's limit (net.ipv4.tcp_mem, the third value). From 3/4 of the limit (until below 11/16), a client address (an IPv4 address or an IPv6 /64) that holds more than half of all downloads which their clients do not read gets no new streams (CLOSE 0x49) while another client is connected. It must hold enough of them to matter on this host: their number times the kernel's default receive buffer is 1/16 of the limit or more. Open streams go on and nothing is closed. Never applies to loopback, private and other addresses that are not public, to --trusted-proxy addresses and to a client without a client address. Behind a reverse proxy it needs --trusted-proxy, or every client has the proxy's address. In a container that cannot read net.ipv4.tcp_mem the rule runs while the kernel reports TCP memory pressure. It acts against an address that keeps adding such downloads: a burst of them within a second or two is not stopped, and other clients can still be slowed. The public preset sets it."),
    o("--no-tcpmem-share", "", "limits", "", "undo --tcpmem-share", "Undo --tcpmem-share of a preset, a config file or earlier on the command line."),
    o("--port-share", "", "limits", "off", "one address cannot take a destination's ports", "Keep the host's source ports toward one destination for all clients. A host has a fixed number of source ports toward one destination address and port (net.ipv4.ip_local_port_range, about 28000 by default), so that many target sockets to it at most. From 1/4 of them in use toward one destination, new target sockets to it get the socket option IP_LOCAL_PORT_RANGE (Linux 6.3; without it connects slow down past half of the ports). From 3/4, a client address (an IPv4 address or an IPv6 /64) that holds more than half of the sockets to that destination gets no new streams to it (CLOSE 0x49) while another client holds a socket to it. From 15/16, an address that is alone on the destination gets none while another client is connected, so the last ports stay free for a client that comes later. When no port is left the stream is refused with CLOSE 0x49. Open streams go on and nothing is closed. Never applies to loopback, private and other addresses that are not public, to --trusted-proxy addresses and to a client without a client address. Behind a reverse proxy it needs --trusted-proxy, or every client has the proxy's address. TCP streams only. The public preset sets it."),
    o("--no-port-share", "", "limits", "", "undo --port-share", "Undo --port-share of a preset, a config file or earlier on the command line."),
    o("--dest-failfast", "", "limits", "off", "no new connects to a destination that is dead", "Stop sending connects to a destination that does not answer. A destination (target address and port) is taken for dead when 8 or more connects of one worker thread to it have each got no answer to 4 SYNs and none has opened. Until it answers, a new stream to it is refused at once with CLOSE 0x43, the reason it would get at the connect timeout; one connect per second per worker thread still goes out as a probe, and the first one that connects ends it. Only while another client is connected: a client alone on the server is never refused. A name with more addresses goes on with the next one. Streams that are connecting go on until --connect-timeout. Never applies to loopback, private and other addresses that are not public, to --trusted-proxy addresses and to a client without a client address. TCP streams only; not in effect with --upstream. The public preset sets it."),
    o("--no-dest-failfast", "", "limits", "", "undo --dest-failfast", "Undo --dest-failfast of a preset, a config file or earlier on the command line."),
    o("--net-watch", "", "limits", "off", "counters and a log line: SYN retransmits, UDP", "Watch two things that no option bounds, because the host has no readable limit for packets out: connects to many destinations that do not answer, and UDP datagrams. Nothing is refused. The metrics get host_syn_retrans and host_udp_out (SYN retransmits and UDP datagrams sent by the host since boot) and the gauge connecting (streams with a connect in flight). Every 10 seconds one thread compares the host's counters: a warning is logged when the host sent 30000 or more SYN retransmits in 10 seconds and 3 or more per connect attempt, or 75000 or more UDP datagrams in 10 seconds and they are half of all its packets; the next warning of a kind comes only at twice that value. The public preset sets it."),
    o("--no-net-watch", "", "limits", "", "undo --net-watch", "Undo --net-watch of a preset, a config file or earlier on the command line."),
];

/// Longest --connect-timeout: `Instant + Duration` panics on overflow, so a huge value is refused here.
pub const MAX_CONNECT_TIMEOUT: u64 = 86_400; // 1 day
/// Longest --drain-timeout (as MAX_CONNECT_TIMEOUT)
pub const MAX_DRAIN_TIMEOUT: u64 = 86_400;
/// Longest --metrics-interval (as MAX_CONNECT_TIMEOUT: a typo such as 6000000 is refused, not a silent never)
pub const MAX_METRICS_INTERVAL: u64 = 86_400;

#[cfg_attr(test, derive(Debug, PartialEq))] // (test only: `upstream` can hold a secret)
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
    pub dns_share: bool, // 60.58 --dns-share: the resolver threads are shared by connection and client address (opt-in)
    /// 60.58 --dns-reserve: a quarter of the resolver threads only for clients without slow lookups (sets dns_share)
    pub dns_reserve: bool,
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
    pub park_rcvlock: bool,        // 60.47 lock a parked download-only target's receive buffer (opt-in)
    pub adaptive_splice: bool,     // 60.46 rule B splice length; 60.51 far clients only; default on since v1.2.1
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
    pub nofile_raise: bool,  // 60.57 A1 raise the soft RLIMIT_NOFILE at startup (default on; --no-nofile-raise)
    pub fd_admission: bool,  // 60.57 C the host mark (default off; the later of --fd-admission / --no-fd-admission wins)
    pub conn_share: bool,    // 60.57 C the share rule (default off; as fd_admission); builds the per-IP table
    pub tcpmem_share: bool,  // 60.63 E1 host TCP memory: a share rule on unread downloads (default off)
    pub port_share: bool,    // 60.63 E2 source ports toward one destination: socket option, share rule (default off)
    pub dest_failfast: bool, // 60.63 E3 a destination that does not answer gets no new connect (default off)
    pub net_watch: bool,     // 60.63 E4 counters and a log line for SYN retransmits and UDP datagrams (default off)
}

impl Opts {
    /// 60.20 C3b a per-IP limit is on, so the per-IP table exists (60.25 --upload-rate-per-ip, 60.40 --conn-rate-per-ip,
    /// 60.57 --conn-share: the fds per address live in it)
    pub fn per_ip(&self) -> bool {
        self.max_conns_per_ip > 0
            || self.stream_rate.is_some()
            || self.upload_rate_ip.is_some()
            || self.conn_rate.is_some()
            || self.conn_share
    }
}

/// 60.20 C8: every long option parse_args accepts, and whether it takes a value: the `parsed` rows of OPTIONS, in
/// their order. The --config file accepts exactly these names (without the dashes).
pub const FLAGS: &[(&str, bool)] = &FLAGS_ARRAY;
const N_FLAGS: usize = {
    let (mut n, mut i) = (0, 0);
    while i < OPTIONS.len() {
        n += OPTIONS[i].parsed as usize;
        i += 1;
    }
    n
};
const FLAGS_ARRAY: [(&str, bool); N_FLAGS] = {
    let mut out = [("", false); N_FLAGS];
    let (mut n, mut i) = (0, 0);
    while i < OPTIONS.len() {
        if OPTIONS[i].parsed {
            out[n] = (OPTIONS[i].name, !OPTIONS[i].arg.is_empty());
            n += 1;
        }
        i += 1;
    }
    out
};

/// 60.60 the table row of an option name
pub fn spec(flag: &str) -> Option<&'static OptSpec> {
    OPTIONS.iter().find(|s| s.name == flag)
}

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

/// 60.59 the built-in presets: (name, settings in the --config file format). `public` is contrib/public.conf, the one
/// source of the preset (--print-preset prints these bytes); `none` holds nothing: the off value of a start command that
/// carries `--preset public` (the Docker image's ENTRYPOINT, the systemd unit).
pub const PRESETS: &[(&str, &str)] = &[("public", include_str!("../../contrib/public.conf")), ("none", "")];

/// 60.59 where a token of the final argument list comes from. The layers, lowest first: preset, --config file, command line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Src {
    Preset,
    File,
    Cmd,
}

impl Src {
    pub fn name(self) -> &'static str {
        match self {
            Src::Preset => "preset",
            Src::File => "file",
            Src::Cmd => "command line",
        }
    }
}

/// expand_config's result: the arguments for parse_args, the config file (for the startup lines) and a warning.
/// 60.59 `preset`: the preset in effect and the layer that named it; `src`: the layer of each token of `args`.
/// (no derived Debug: `args` can hold a secret flag's value, e.g. an --upstream URL; 60.27 review)
#[derive(PartialEq)]
pub struct Expanded {
    pub args: Vec<String>,
    pub config: Option<String>,
    pub warning: Option<String>,
    pub preset: Option<(&'static str, Src)>,
    pub src: Vec<Src>,
    /// 60.60 `--show-config` was given (taken out of `args`)
    pub show: bool,
}

impl std::fmt::Debug for Expanded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (n, c, w, p) = (self.args.len(), &self.config, &self.warning, &self.preset);
        write!(f, "Expanded {{ args: <{n} hidden>, config: {c:?}, warning: {w:?}, preset: {p:?} }}")
    }
}

fn takes_value(flag: &str) -> Option<bool> {
    FLAGS.iter().find(|(f, _)| *f == flag).map(|&(_, v)| v)
}

/// how many tokens the option `a` takes on the command line (itself and its value). --config, --preset and
/// --print-preset are not in FLAGS (they are handled before parse_args) and take a value.
fn arg_step(a: &str) -> usize {
    if matches!(a, "--config" | "--preset" | "--print-preset") || takes_value(a) == Some(true) {
        2
    } else {
        1
    }
}

fn list_group(flag: &str) -> Option<usize> {
    LIST_GROUPS.iter().position(|g| g.contains(&flag))
}

/// a name that can be shown in an error: a mistyped secret on a line of its own must not be echoed
pub fn flag_like(name: &str) -> bool {
    !name.is_empty() && name.len() <= 40 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// 60.60 the error for an option without its value, with the option's form
fn needs_value(flag: &str) -> String {
    match spec(flag).map(|s| s.arg).filter(|a| !a.is_empty()) {
        Some(arg) => format!("{flag} needs a value: {flag} {arg}"),
        None => format!("{flag} needs a value"),
    }
}

/// 60.60 edit distance (Levenshtein) of two short ASCII names
fn distance(a: &[u8], b: &[u8]) -> usize {
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, &x) in a.iter().enumerate() {
        let mut diag = row[0];
        row[0] = i + 1;
        for (j, &y) in b.iter().enumerate() {
            let next = (diag + (x != y) as usize).min(row[j] + 1).min(row[j + 1] + 1);
            diag = row[j + 1];
            row[j + 1] = next;
        }
    }
    row[b.len()]
}

/// 60.60 the nearest name of `names` to a mistyped `typed` (both without dashes): the one name that starts with it (3
/// letters or more), else the closest by edit distance when that is 1, or 2 for a name of 6 letters or more.
pub fn nearest<'a>(typed: &str, names: impl Iterator<Item = &'a str> + Clone) -> Option<&'a str> {
    if !flag_like(typed) {
        return None; // (also bounds the work: at most 40 bytes)
    }
    let mut starts = names.clone().filter(|n| typed.len() >= 3 && n.starts_with(typed));
    if let (Some(one), None) = (starts.next(), starts.next()) {
        return Some(one);
    }
    let max = if typed.len() >= 6 { 2 } else { 1 };
    names.map(|n| (distance(typed.as_bytes(), n.as_bytes()), n)).filter(|(d, _)| *d <= max).min_by_key(|(d, _)| *d).map(|(_, n)| n)
}

/// 60.60 the nearest option to a mistyped one, with its dashes
fn nearest_option(typed: &str) -> Option<&'static str> {
    let n = nearest(typed.trim_start_matches('-'), OPTIONS.iter().map(|s| &s.name[2..]))?;
    OPTIONS.iter().map(|s| s.name).find(|s| &s[2..] == n)
}

/// 60.60 the error for an argument that is no option and no port. 60.27 C6: it is echoed only if it looks like an
/// option name (a mistyped `--upstrem URL` must not print the URL's password); of `--name=value` only the name.
fn unknown(p: &str) -> String {
    if let Some(typed) = p.strip_prefix('-') {
        let name = p.split_once('=').map_or(p, |(n, _)| n);
        if !flag_like(name.trim_start_matches('-')) || typed.is_empty() {
            return "unknown option (not shown: not an option name; it may hold a secret)".to_string();
        }
        return match nearest_option(name) {
            Some(n) => format!("unknown option {name} (did you mean {n}?)"),
            None => format!("unknown option {name}"),
        };
    }
    if !flag_like(p) {
        return "unknown argument (not shown: not an option name; it may hold a secret)".to_string();
    }
    if p.bytes().all(|b| b.is_ascii_digit()) {
        return format!("{p:?} is not a port (0-65535)");
    }
    match spec(&format!("--{p}")) {
        Some(s) => format!("unknown argument {p:?} (did you mean {}?)", s.name),
        None => format!("unknown argument {p:?} (options start with two dashes; a bare number is the port)"),
    }
}

/// 60.60 `--name=value` is the same as `--name value`, for the options that take a value. A switch with a value is an
/// error; an unknown name is left for parse_args (which does not echo the value). Only words at an option's place are
/// looked at: the value of another option is never split (`--motd --a=b`).
#[cfg(any(test, fuzzing))] // (main goes through `command`)
pub fn split_eq(args: Vec<String>) -> Result<Vec<String>, String> {
    match split_eq_all(args) {
        (args, None) => Ok(args),
        (_, Some(e)) => Err(e),
    }
}

/// split_eq with the error beside the list (a switch with a value stays as it was typed): `command` looks for the
/// printing commands first, and those check nothing else (`--print-preset public --no-udp=1` prints the preset)
fn split_eq_all(args: Vec<String>) -> (Vec<String>, Option<String>) {
    let mut out = Vec::with_capacity(args.len());
    let mut err = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if let Some((name, value)) = a.split_once('=').filter(|(n, _)| n.starts_with("--")) {
            match spec(name) {
                Some(s) if !s.arg.is_empty() => {
                    out.extend([name.to_string(), value.to_string()]);
                    continue;
                }
                Some(_) => err = err.or(Some(format!("{name} takes no value"))),
                None => {}
            }
        }
        let step = arg_step(&a);
        out.push(a);
        if step == 2 {
            out.extend(it.next());
        }
    }
    (out, err)
}

/// 60.60 the commands that print something and exit 0 before any option is checked
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Special {
    /// `--help` / `-h`, with the topic if one follows
    Help(Option<String>),
    /// `--version` / `-V`
    Version,
    /// `--print-preset NAME`: the preset's bytes
    Preset(&'static str),
}

/// 60.60 the first of --print-preset (wherever it stands: 60.59), --help [TOPIC] and --version at an option's place
pub fn special(args: &[String]) -> Option<Result<Special, String>> {
    if let Some(p) = print_preset(args) {
        return Some(p.map(Special::Preset));
    }
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return Some(Ok(Special::Help(args.get(i + 1).filter(|t| !t.starts_with('-')).cloned()))),
            "--version" | "-V" => return Some(Ok(Special::Version)),
            a => i += arg_step(a),
        }
    }
    None
}

fn preset_names(presets: &[(&'static str, &str)]) -> String {
    presets.iter().map(|p| p.0).collect::<Vec<_>>().join(", ")
}

/// 60.59 the error for a preset name that does not exist: it lists the names that do (the name is echoed only when it
/// looks like one: the rule of flag_like)
fn unknown_preset(flag: &str, name: &str) -> String {
    let shown = if flag_like(name) { format!(" {name:?}") } else { String::new() };
    format!("{flag}: unknown preset{shown} (the presets: {})", preset_names(PRESETS))
}

/// 60.59 `--print-preset NAME` on the command line (as an option, not as the value of another one): the preset's exact
/// bytes, or the error. main prints them and exits 0 before anything else is checked, so the Docker image, whose
/// ENTRYPOINT carries `--preset public`, can print its preset too.
pub fn print_preset(args: &[String]) -> Option<Result<&'static str, String>> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--print-preset" {
            return Some(match args.get(i + 1) {
                None => Err(needs_value("--print-preset")),
                Some(n) => PRESETS.iter().find(|p| p.0 == n).map(|p| p.1).ok_or_else(|| unknown_preset("--print-preset", n)),
            });
        }
        i += arg_step(a);
    }
    None
}

/// 60.20 C8: the lines of a --config file as (line number, flag with dashes, value). Format (60.02 Q9): `flag value` or a
/// bare `flag` per line, the long option names without the leading dashes; blank lines and lines starting with `#` are
/// skipped; the value is the rest of the line with outer whitespace trimmed (no quoting, no inline comments). Each line
/// is checked as it is read (the first bad line is reported). Errors name FILE:LINE and the flag, never the value (the
/// file may hold secrets). 60.59: a `preset NAME` line comes back as ("--preset", NAME), its name checked.
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
            return Err(format!("{at}: write option names without the leading dashes"));
        }
        if !flag_like(name) {
            return Err(format!("{at}: unknown option (not shown: not an option name)"));
        }
        let flag = format!("--{name}");
        if name == "config" {
            return Err(format!("{at}: --config inside a config file (no includes)"));
        }
        if name == "preset" {
            // 60.59 (the value is not shown, as for every line)
            if !value.as_deref().is_some_and(|v| PRESETS.iter().any(|p| p.0 == v)) {
                return Err(format!("{at}: --preset needs the name of a preset ({})", preset_names(PRESETS)));
            }
            out.push((i + 1, flag, value));
            continue;
        }
        match takes_value(&flag) {
            None => {
                return Err(match removed(&flag) {
                    Some(why) => format!("{at}: {flag} was removed before v1.0.0: {why}; drop it"),
                    None => match nearest(name, FLAGS.iter().map(|f| &f.0[2..])) {
                        Some(n) => format!("{at}: unknown option {name:?} (did you mean {n}?)"),
                        None => format!("{at}: unknown option {name:?}"),
                    },
                })
            }
            Some(true) if value.is_none() => return Err(format!("{at}: {}", needs_value(&flag))),
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
/// 60.59 `--preset NAME` (or the file line `preset NAME`; the command line's name wins, and the last one of several):
/// the preset's flags go to the FRONT of the list, so the file and the command line override them. The layers are
/// preset, file, command line.
pub fn expand_config<F>(args: Vec<String>, load: F) -> Result<Expanded, String>
where
    F: FnOnce(&str) -> Result<(Vec<u8>, u32), String>,
{
    expand_config_with(args, load, SECRET_FLAGS, PRESETS)
}

/// 60.59 the settings of a preset text as (flag, value). A preset holds no list option (a list from two layers would
/// need a merge rule; the file and the command line keep theirs: the command line's list replaces the file's) and names
/// no other preset. The built-in text is checked by a unit test, so these errors show only in a build with a bad file.
fn preset_settings(name: &str, text: &str) -> Result<Vec<(String, Option<String>)>, String> {
    let mut out = Vec::new();
    for (line, flag, value) in parse_config(&format!("preset {name}"), text.as_bytes())? {
        if flag == "--preset" || list_group(&flag).is_some() {
            return Err(format!("preset {name}:{line}: {flag} cannot be set by a preset"));
        }
        out.push((flag, value));
    }
    Ok(out)
}

/// expand_config with the list of secret flags and the preset texts as parameters (the tests pass their own; the preset
/// NAMES are always those of PRESETS)
fn expand_config_with<F>(args: Vec<String>, load: F, secret_flags: &[&str], presets: &[(&'static str, &str)]) -> Result<Expanded, String>
where
    F: FnOnce(&str) -> Result<(Vec<u8>, u32), String>,
{
    let named = |n: &str| presets.iter().find(|p| p.0 == n).map(|p| p.0);
    // find --config and --preset as options, not as the value of another one (`--motd --config`)
    let (mut at, mut lists, mut cmd_preset, mut show, mut i) = (Vec::new(), Vec::new(), None, false, 0);
    let mut own = vec![true; args.len()]; // false: a --preset NAME pair or --show-config (taken out of the list)
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--config" {
            at.push(i);
        }
        if a == "--preset" {
            let n = args.get(i + 1).ok_or_else(|| needs_value("--preset"))?;
            cmd_preset = Some(named(n).ok_or_else(|| unknown_preset("--preset", n))?); // (the last one wins)
            (own[i], own[i + 1]) = (false, false);
        }
        if a == "--show-config" {
            (own[i], show) = (false, true); // 60.60
        }
        lists.extend(list_group(a));
        i += arg_step(a);
    }
    if at.len() > 1 {
        return Err("--config: only one config file".to_string());
    }
    let pos = at.first().copied();
    let (mut file, mut config, mut warning, mut file_preset) = (Vec::new(), None, None, None);
    if let Some(pos) = pos {
        let path = args.get(pos + 1).ok_or_else(|| needs_value("--config"))?.clone();
        let (data, mode) = load(&path).map_err(|e| format!("--config {path}: {e}"))?;
        let mut secret = false;
        for (_, flag, value) in parse_config(&path, &data)? {
            if flag == "--preset" {
                file_preset = value.as_deref().and_then(named); // (parse_config checked the name; the last line wins)
                continue;
            }
            secret |= secret_flags.contains(&flag.as_str()); // the file holds it, even when the command line replaces it
            if list_group(&flag).is_some_and(|g| lists.contains(&g)) {
                continue; // the command line's list replaces the file's (60.18 #13 a)
            }
            file.push(flag);
            file.extend(value);
        }
        // checks across lines (more than 3 dns-server lines, unpaired tls-cert / tls-key): the file alone, named in the error
        // (these messages hold no values; every value was checked per line)
        parse_args_of(file.clone(), 1, false).map_err(|e| format!("--config {path}: {e}"))?;
        warning =
            (secret && mode & 0o044 != 0).then(|| format!("--config {path} holds a secret and is readable by group/others (chmod 600 it)"));
        config = Some(path);
    }
    let preset = cmd_preset.map(|n| (n, Src::Cmd)).or(file_preset.map(|n| (n, Src::File)));
    let (mut out, mut src) = (Vec::new(), Vec::new());
    if let Some((name, _)) = preset {
        let text = presets.iter().find(|p| p.0 == name).map_or("", |p| p.1);
        for (flag, value) in preset_settings(name, text)? {
            out.push(flag);
            out.extend(value);
        }
        src.resize(out.len(), Src::Preset);
    }
    // the command line in order, with the file's flags in the place of `--config FILE`
    let mut i = 0;
    while i < args.len() {
        if Some(i) == pos {
            out.append(&mut file);
            src.resize(out.len(), Src::File);
            i += 2;
            continue;
        }
        if own[i] {
            out.push(args[i].clone());
            src.push(Src::Cmd);
        }
        i += 1;
    }
    Ok(Expanded { args: out, config, warning, preset, src, show })
}

/// 60.59 the off form of a switch: `--no-X` for `--X` and the other way round, if parse_args knows it
fn negation(flag: &str) -> Option<String> {
    let name = flag.strip_prefix("--")?;
    let neg = match name.strip_prefix("no-") {
        Some(rest) => format!("--{rest}"),
        None => format!("--no-{name}"),
    };
    (takes_value(&neg) == Some(false)).then_some(neg)
}

/// 60.59 the startup line of a preset: every setting the preset touches, with the value in effect and the layer that
/// gave it (default, preset, file, command line). None without `--preset`. Read from the final argument list, not from
/// Opts: the parser is last-wins, so the last token of a setting (or of its off form) is the one in effect, and a line
/// added to contrib/public.conf needs no code here. A setting no layer gives is `off (default)`: every preset setting
/// is off in a plain `finalwisp` (unit test preset_settings_have_off_values).
pub fn preset_line(ex: &Expanded) -> Option<String> {
    preset_line_of(ex, PRESETS[0].1)
}

/// preset_line with the text of `public` as a parameter (the tests pass their own)
fn preset_line_of(ex: &Expanded, public: &str) -> Option<String> {
    let (name, from) = ex.preset?;
    let settings = preset_settings("public", public).ok()?;
    let mut parts = Vec::new();
    for (flag, value) in settings {
        let neg = if value.is_none() { negation(&flag) } else { None };
        let (mut last, mut i) = (None, 0);
        while i < ex.args.len() {
            let a = ex.args[i].as_str();
            if a == flag || Some(a) == neg.as_deref() {
                last = Some(i);
            }
            i += arg_step(a);
        }
        let shown = match last {
            None => "off (default)".to_string(),
            Some(i) => {
                let v = match (&value, ex.args.get(i + 1)) {
                    (Some(_), Some(v)) if v != "0" && v != "off" => v.as_str(),
                    (None, _) if ex.args[i] == flag => "on",
                    _ => "off",
                };
                format!("{v} ({})", ex.src.get(i).map_or("command line", |s| s.name()))
            }
        };
        parts.push(format!("{} {shown}", &flag[2..]));
    }
    Some(format!("preset {name} ({}): {}", from.name(), parts.join(", ")))
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

/// 60.60 one setting as the start block and --show-config show it: the EFFECT, not the spelling. `key` is the option
/// name without dashes; a switch drops its `no-` (`--no-udp` is the setting `udp`, on by default) and a pair such as
/// --block-smtp / --no-block-smtp is one setting. `value`: on / off, the value in effect (a secret redacted, a list
/// joined) or the default's text; `src`: the layer that decides it (None: the default); `changed`: it is not the default.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Setting {
    pub key: &'static str,
    pub topic: &'static str,
    pub value: String,
    pub src: Option<Src>,
    pub changed: bool,
}

/// 60.60 a value as it may be printed: the value of a secret option (SECRET_FLAGS: the --upstream URL) is shown the
/// way the proxy is named elsewhere (upstream::parse_url's `shown`: no user, no password), or not at all.
pub fn shown_value(flag: &str, v: &str) -> String {
    if !SECRET_FLAGS.contains(&flag) {
        // (a control character of a value, such as an escape sequence in a --motd, is not sent to the terminal)
        return v.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
    }
    crate::upstream::parse_url(v).map_or("(not shown)".to_string(), |u| u.shown.clone())
}

/// 60.60 the settings in effect, one per setting, in the order of OPTIONS. Read from the final argument list (as
/// preset_line): the parser is last-wins, so the last word of a setting, or of its off form, decides; list options
/// show every entry. `args` passed parse_args (so a bare word is the port); `src`: the layer of each word.
pub fn settings(args: &[String], src: &[Src]) -> Vec<Setting> {
    // (index of the word, option name, value)
    let mut seen: Vec<(usize, &str, Option<&str>)> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match arg_step(a) {
            2 => seen.push((i, a, args.get(i + 1).map(String::as_str))),
            _ if a.starts_with('-') => seen.push((i, a, None)),
            _ => seen.push((i, "--port", Some(a))),
        }
        i += arg_step(a);
    }
    let layer = |i: usize| Some(src.get(i).copied().unwrap_or(Src::Cmd));
    let mut out = Vec::new();
    for s in OPTIONS.iter().filter(|s| s.parsed) {
        let name = &s.name[2..];
        if s.arg.is_empty() {
            // a switch: `on` is the positive form's state
            let other = negation(s.name);
            let (key, on_form, default_on) = match name.strip_prefix("no-") {
                Some(_) if other.is_some() => continue, // the row of the positive form shows the pair
                Some(rest) => (rest, None, true),
                None => (name, Some(s.name), other.is_some() && s.default == "on"),
            };
            let last = seen.iter().rev().find(|(_, f, _)| *f == s.name || Some(*f) == other.as_deref());
            let on = last.map_or(default_on, |(_, f, _)| Some(*f) == on_form);
            let value = if on { "on" } else { "off" }.to_string();
            out.push(Setting { key, topic: s.topic, value, src: last.and_then(|l| layer(l.0)), changed: on != default_on });
            continue;
        }
        let mut given = seen.iter().filter(|(_, f, _)| *f == s.name).peekable();
        let Some(&&(first, _, _)) = given.peek() else {
            out.push(Setting { key: name, topic: s.topic, value: s.default.to_string(), src: None, changed: false });
            continue;
        };
        let values: Vec<String> = given.map(|(_, _, v)| shown_value(s.name, v.unwrap_or(""))).collect();
        // a list shows every entry (all from one layer: LIST_GROUPS); else the last value decides
        let (value, at) = match list_group(s.name) {
            Some(_) => (values.join(", "), first),
            None => (values[values.len() - 1].clone(), seen.iter().rev().find(|(_, f, _)| *f == s.name).map_or(first, |l| l.0)),
        };
        // a number option that 0 turns off shows `off`. A default that is a word and not a value (off, none,
        // automatic, ...) is never equal to a given value: `--motd off` is a MOTD, and it is shown as set.
        let number = matches!(s.arg, "N" | "SECS" | "RATE" | "R[/B]");
        let (value, changed) = match () {
            () if number && s.default == "off" && value == "0" => ("off".to_string(), false),
            () => {
                let word = matches!(s.default, "off" | "none" | "automatic") || s.default.contains(' ');
                let changed = word || value != s.default;
                (value, changed)
            }
        };
        out.push(Setting { key: name, topic: s.topic, value, src: layer(at), changed });
    }
    out
}

/// 60.60 what one option does to another setting, so that the settings show the effect: --dns-server turns the own
/// resolver on (parse_args); with an --upstream proxy there is no UDP and no TCP fast open to it (main);
/// --download-rate turns splice off (main), and without splice the adaptive rule has nothing to act on; connection
/// and stream lines are info lines (main). The reason stands in the value, and the row is not `changed`: the option
/// that causes it is the one the start block names. (--tcpmem-adapt needs a kernel probe: main's show_config.)
fn implied(mut settings: Vec<Setting>, o: &Opts) -> Vec<Setting> {
    let mut set = |key: &str, from: &str, to: &str, why: &str| {
        if let Some(s) = settings.iter_mut().find(|s| s.key == key && s.value == from) {
            (s.value, s.changed) = (format!("{to} ({why})"), false);
        }
    };
    if o.dns_own {
        set("dns-own", "off", "on", "set by dns-server");
    }
    if o.dns_reserve {
        set("dns-share", "off", "on", "set by dns-reserve");
    }
    if o.upstream.is_some() {
        set("udp", "on", "off", "with an upstream proxy");
        set("tfo", "on", "off", "with an upstream proxy");
    }
    if o.pace.download > 0 {
        set("splice", "on", "off", "with download-rate");
    }
    if !o.splice || o.pace.download > 0 {
        set("adaptive-splice", "on", "off", "splice is off");
    }
    if o.log_level < crate::logs::Level::Info {
        set("log-conns", "on", "off", "log-level is below info");
        set("log-streams", "on", "off", "log-level is below info");
    }
    settings
}

/// 60.60 the setting names (Setting::key) that the preset in effect sets, in the preset's order
pub fn preset_keys(preset: Option<(&'static str, Src)>) -> Vec<String> {
    let Some((name, _)) = preset else { return Vec::new() };
    let text = PRESETS.iter().find(|p| p.0 == name).map_or("", |p| p.1);
    let flags = preset_settings(name, text).unwrap_or_default();
    flags.iter().map(|(f, v)| if v.is_none() { f[2..].trim_start_matches("no-") } else { &f[2..] }.to_string()).collect()
}

/// 60.60 what a command line asks for
pub enum Command {
    Special(Special),
    /// start the server, or with `show` (--show-config) print the settings and exit
    Start(Box<Start>),
}

/// 60.60 a checked start: the options, and what the startup lines say about where they came from
pub struct Start {
    pub opts: Opts,
    pub show: bool,
    pub config: Option<String>,
    pub warning: Option<String>,
    pub preset: Option<(&'static str, Src)>,
    pub preset_line: Option<String>,
    pub settings: Vec<Setting>,
}

/// 60.60 the whole way from the arguments to a command, as main runs it: `--name=value` forms, the commands that only
/// print, the preset and the config file (`load` reads it), parse_args, check. Err: (message, the config file's
/// warning if the file was read: an unparsable command line shows it with its error).
pub fn command<F>(args: Vec<String>, threads: usize, load: F) -> Result<Command, (String, Option<String>)>
where
    F: FnOnce(&str) -> Result<(Vec<u8>, u32), String>,
{
    let (args, eq_error) = split_eq_all(args);
    if let Some(s) = special(&args) {
        return s.map(Command::Special).map_err(|e| (e, None));
    }
    if let Some(e) = eq_error {
        return Err((e, None));
    }
    let ex = expand_config(args, load).map_err(|e| (e, None))?;
    let (preset_line, settings) = (preset_line(&ex), settings(&ex.args, &ex.src));
    let Expanded { args, config, warning, preset, show, .. } = ex;
    // 60.24 the file's warning waits for --log-level: an unparsable command line shows it with its error; one that
    // parses and fails a check shows it only at warn and above
    let opts = match parse_args(args, threads) {
        Ok(o) => o,
        Err(e) => return Err((e, warning)),
    };
    let warning = warning.filter(|_| opts.log_level >= crate::logs::Level::Warn);
    match check(opts) {
        Ok(opts) => {
            let settings = implied(settings, &opts);
            Ok(Command::Start(Box::new(Start { opts, show, config, warning, preset, preset_line, settings })))
        }
        Err(e) => Err((e, warning)),
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

/// a number; the error says what is expected (`what`: "a port (0-65535)")
fn num<T: std::str::FromStr>(flag: &str, v: String, what: &str) -> Result<T, String> {
    v.parse().map_err(|_| format!("{flag}: {v:?} is not {what}"))
}

/// what `num` expects, by the type of the setting
const COUNT: &str = "a whole number";
const COUNT32: &str = "a whole number (at most 4294967295)";
const SECONDS: &str = "a number of seconds";

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

/// Parse the arguments (without the program name). Err(message), never empty. `threads` is the default thread count
/// (the caller passes available_parallelism).
pub fn parse_args<I: IntoIterator<Item = String>>(args: I, threads: usize) -> Result<Opts, String> {
    parse_args_of(args, threads, true)
}

/// parse_args; `whole` false: the arguments are one layer alone (a config file), so the two settings that another
/// layer can still complete are not judged (review: `no-dns-own` + `dns-server` in a file, `--dns-own` after it)
fn parse_args_of<I: IntoIterator<Item = String>>(args: I, threads: usize, whole: bool) -> Result<Opts, String> {
    let mut host = "127.0.0.1".to_string();
    // 60.58 the last word of the pair was the off form (see the end of this function)
    let (mut no_own, mut no_share) = (false, false);
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
        dns_share: false, // 60.58 opt-in
        dns_reserve: false,
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
        park_rcvlock: false, // 60.47 opt-in
        adaptive_splice: true, // 60.46 + 60.51 far-client gate: default on since v1.2.1 (owner 2026-11-09)
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
        nofile_raise: true, // 60.57 A1
        fd_admission: false,
        conn_share: false,
        tcpmem_share: false,
        port_share: false,
        dest_failfast: false,
        net_watch: false,
    };
    let (mut tls_certs, mut tls_keys) = (Vec::<String>::new(), Vec::<String>::new());
    let mut args = args.into_iter();
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or_else(|| needs_value(&a));
        match a.as_str() {
            "--host" => host = val()?,
            "--port" => o.port = num(&a, val()?, "a port (0-65535)")?,
            "--threads" => o.threads = num(&a, val()?, COUNT)?,
            "--buffer" => o.buffer = num(&a, val()?, COUNT32)?,
            "--connect-timeout" => {
                o.connect_timeout = num(&a, val()?, SECONDS)?;
                if o.connect_timeout > MAX_CONNECT_TIMEOUT {
                    return Err(format!("--connect-timeout: at most {MAX_CONNECT_TIMEOUT} seconds"));
                }
            }
            "--drain-timeout" => {
                o.drain_timeout = num(&a, val()?, SECONDS)?;
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
            "--tls-rekey-records" => o.tls_rekey = num(&a, val()?, COUNT)?,
            "--notsent-lowat" => o.notsent_lowat = num(&a, val()?, "a number of bytes (at most 4294967295)")?,
            "--dns-threads" => o.dns_threads = num(&a, val()?, COUNT)?,
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
            "--dns-own" => (o.dns_own, no_own) = (true, false),
            "--no-dns-own" => (o.dns_own, no_own) = (false, true), // 60.58 (the later one wins)
            "--dns-share" => (o.dns_share, no_share) = (true, false), // 60.58 opt-in
            "--no-dns-share" => (o.dns_share, no_share) = (false, true), // 60.58 (the later one wins)
            "--dns-reserve" => o.dns_reserve = true,
            "--no-dns-reserve" => o.dns_reserve = false,
            "--no-prio" => o.prio = false,
            "--auth-file" => o.auth_file = Some(val()?),
            "--cert-auth-key" => o.cert_keys.push(val()?),
            "--motd" => o.motd = Some(val()?),
            "--mem-budget" => {
                let v = val()?;
                o.mem_budget = Some(
                    parse_size(&v).ok_or_else(|| format!("--mem-budget: {v:?} is not a size (bytes, or a whole number with K, M or G)"))?,
                );
            }
            "--tcpmem-adapt" => o.tcpmem_adapt = true,           // 60.14 opt-in
            "--no-credit-pace" => o.credit_pace = false,         // 60.42 default on
            "--park-rcvlock" => o.park_rcvlock = true,           // 60.47 opt-in
            "--adaptive-splice" => o.adaptive_splice = true,     // 60.46 (the default since v1.2.1; kept for v1.2.0 configs)
            "--no-adaptive-splice" => o.adaptive_splice = false, // 60.51 default on
            "--metrics-interval" => {
                o.metrics_interval = num(&a, val()?, SECONDS)?;
                if o.metrics_interval > MAX_METRICS_INTERVAL {
                    return Err(format!("--metrics-interval: at most {MAX_METRICS_INTERVAL} seconds"));
                }
            }
            "--max-conns" => o.max_conns = num(&a, val()?, COUNT32)?,
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
            "--max-streams-per-conn" => o.max_streams_per_conn = num(&a, val()?, COUNT32)?,
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
            "--no-nofile-raise" => o.nofile_raise = false, // 60.57 A1
            "--fd-admission" => o.fd_admission = true,     // 60.57 C (the later one wins: a preset turns it on, the
            "--no-fd-admission" => o.fd_admission = false, // command line off again)
            "--conn-share" => o.conn_share = true,
            "--no-conn-share" => o.conn_share = false,
            "--tcpmem-share" => o.tcpmem_share = true, // 60.63 E (each pair: the later one wins)
            "--no-tcpmem-share" => o.tcpmem_share = false,
            "--port-share" => o.port_share = true,
            "--no-port-share" => o.port_share = false,
            "--dest-failfast" => o.dest_failfast = true,
            "--no-dest-failfast" => o.dest_failfast = false,
            "--net-watch" => o.net_watch = true,
            "--no-net-watch" => o.net_watch = false,
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
            "--no-block-smtp" => o.rules.block_smtp = false, // 60.59
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
            "--max-conns-per-ip" => o.max_conns_per_ip = num(&a, val()?, COUNT32)?,
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
            p => {
                if let Some(why) = removed(p) {
                    return Err(format!("{p} was removed before v1.0.0: {why}; drop it"));
                }
                // a bare number is the port; anything else is unknown (60.60: --help and --version are handled before
                // parse_args, cli::special, so here they are unknown too)
                o.port = p.parse().map_err(|_| unknown(p))?
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
    // 60.58 an option that needs another one turns it on (--dns-server: --dns-own, in its arm; --dns-reserve:
    // --dns-share). With that one turned off by name the two contradict, in either order: the off form of a setting
    // always decides it (preset_line and settings read the last word of a setting).
    if whole && no_own && !o.dns_servers.is_empty() {
        return Err("--no-dns-own and --dns-server together: a name server is for the built-in resolver. Remove one of the two".to_string());
    }
    if o.dns_reserve {
        if whole && no_share {
            let fix = "Remove one of the two (--no-dns-reserve turns the reserve off)";
            return Err(format!("--no-dns-share and --dns-reserve together: the reserve is a part of the thread sharing. {fix}"));
        }
        o.dns_share = true;
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
        return Err("--proxy-protocol tcp needs --proxy-protocol-from CIDRS: the addresses of the load balancers".to_string());
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
        assert!(!parse("").unwrap().park_rcvlock && parse("--park-rcvlock").unwrap().park_rcvlock); // 60.47 opt-in
        assert!(parse("").unwrap().adaptive_splice && !parse("--no-adaptive-splice").unwrap().adaptive_splice); // 60.51 default on
        assert!(parse("--no-adaptive-splice --adaptive-splice").unwrap().adaptive_splice); // (v1.2.0 spelling still accepted)

        // 60.58 --dns-share: off by default, the later of the two switches wins
        assert!(!parse("").unwrap().dns_share && parse("--dns-share").unwrap().dns_share);
        assert!(!parse("--dns-share --no-dns-share").unwrap().dns_share && parse("--no-dns-share --dns-share").unwrap().dns_share);
        // 60.58 --dns-reserve: off by default, the later of its two switches wins, and it turns --dns-share on
        let r = |s: &str| parse(s).map(|o| (o.dns_share, o.dns_reserve));
        assert_eq!((r(""), r("--dns-reserve")), (Ok((false, false)), Ok((true, true))));
        assert_eq!(r("--dns-reserve --no-dns-reserve"), Ok((false, false)), "undone: a plain finalwisp again");
        assert_eq!(r("--dns-share --dns-reserve --no-dns-reserve"), Ok((true, false)), "--dns-share stays as it was set");
        assert_eq!(r("--no-dns-reserve --dns-reserve"), Ok((true, true)));
        assert_eq!(r("--no-dns-share --dns-share --dns-reserve"), Ok((true, true)));
        assert_eq!(r("--dns-reserve --no-dns-share --no-dns-reserve"), Ok((false, false)));
        // --dns-share turned off by name contradicts it, in either order
        for bad in ["--dns-reserve --no-dns-share", "--no-dns-share --dns-reserve", "--dns-share --no-dns-share --dns-reserve"] {
            let e = parse(bad).unwrap_err();
            assert!(e.starts_with("--no-dns-share and --dns-reserve together: ") && e.contains("--no-dns-reserve"), "{bad}: {e}");
        }
        // 60.58 --no-dns-own: the later of --dns-own / --no-dns-own wins; with a --dns-server it is a contradiction
        let own = |s: &str| parse(s).map(|o| o.dns_own);
        assert_eq!((own("--no-dns-own"), own("--dns-own --no-dns-own"), own("--no-dns-own --dns-own")), (Ok(false), Ok(false), Ok(true)));
        assert_eq!(own("--no-dns-own --dns-server 10.0.0.1 --dns-own"), Ok(true));
        for bad in
            ["--dns-server 10.0.0.1 --no-dns-own", "--no-dns-own --dns-server 10.0.0.1", "--dns-own --dns-server 10.0.0.1 --no-dns-own"]
        {
            assert!(own(bad).unwrap_err().starts_with("--no-dns-own and --dns-server together: "), "{bad}");
        }

        // 60.57 A1 default on
        assert!(parse("").unwrap().nofile_raise && !parse("--no-nofile-raise").unwrap().nofile_raise);
        // 60.57 C off by default; the later of the pair wins; --conn-share builds the per-IP table
        let o = parse("").unwrap();
        assert!(!o.fd_admission && !o.conn_share && !o.per_ip());
        let o = parse("--fd-admission --conn-share").unwrap();
        assert!(o.fd_admission && o.conn_share && o.per_ip());
        let o = parse("--fd-admission --conn-share --no-fd-admission --no-conn-share").unwrap();
        assert!(!o.fd_admission && !o.conn_share && !o.per_ip());
        assert!(
            parse("--no-conn-share --conn-share").unwrap().conn_share && parse("--no-fd-admission --fd-admission").unwrap().fd_admission
        );
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
        assert!(parse("--help").is_err() && parse("-h").is_err(), "handled before parse_args (cli::special)");
    }

    /// 60.60 the table is well formed: unique names, a known topic, texts, no placeholder with a redaction mark, no
    /// note id in a text; every topic has an option; the first page's options exist; a removed option is not in it
    #[test]
    fn option_table_is_well_formed() {
        let note_id = |t: &str| t.as_bytes().windows(5).any(|w| w[2] == b'.' && [w[0], w[1], w[3], w[4]].iter().all(u8::is_ascii_digit));
        for (i, s) in OPTIONS.iter().enumerate() {
            assert!(s.name.starts_with("--") && flag_like(&s.name[2..]), "{}", s.name);
            assert!(!OPTIONS[..i].iter().any(|t| t.name == s.name), "{} twice", s.name);
            assert!(TOPICS.iter().filter(|t| t.0 == s.topic).count() == 1, "{}: topic {:?}", s.name, s.topic);
            assert!(!s.summary.is_empty() && s.summary.len() <= 50 && !s.long.is_empty(), "{}", s.name);
            assert!(!s.arg.contains(|c| REDACTION_MARKS.contains(c)), "{}: its placeholder is part of error texts", s.name);
            assert!(![s.summary, s.long, s.default].iter().any(|t| note_id(t)), "{}: a note id in a help text", s.name);
            assert!(removed(s.name).is_none());
            // a switch's default is on or off in plain words; a pair names the state exactly (settings() reads it)
            if s.arg.is_empty() && s.parsed && negation(s.name).is_some() && !s.name.starts_with("--no-") {
                assert!(s.default == "on" || s.default == "off", "{}", s.name);
            }
        }
        for (name, line, intro) in TOPICS {
            assert!(OPTIONS.iter().any(|s| s.topic == *name), "topic {name} has no option");
            assert!(!line.is_empty() && !intro.is_empty() && !note_id(line) && !note_id(intro));
        }
        assert!(COMMON.iter().all(|n| spec(n).is_some()));
        for f in ["--credit-v2", "--prio", "--no-tcpmem-adapt", "--no-dns-coalesce"] {
            assert!(spec(f).is_none() && removed(f).is_some(), "{f}");
        }
    }

    /// 60.60 table = parser. FLAGS is the table's parsed rows in order; every option name in the source of parse_args
    /// is a row (so an arm without a row fails here), and every row has an arm (flags_table_matches_parse_args). The
    /// options handled before parse_args are rows that parse_args does not know.
    #[test]
    fn option_table_is_the_parser() {
        let parsed: Vec<(&str, bool)> = OPTIONS.iter().filter(|s| s.parsed).map(|s| (s.name, !s.arg.is_empty())).collect();
        assert_eq!(FLAGS, &parsed[..]);
        let src = include_str!("cli.rs");
        let body = &src[src.find("pub fn parse_args").unwrap()..src.find("pub fn check").unwrap()];
        let mut arms = 0;
        for lit in body.split('"').skip(1).step_by(2).filter(|l| l.starts_with("--") && flag_like(&l[2..]) && l.len() > 2) {
            assert!(takes_value(lit).is_some(), "{lit} is in parse_args but not in OPTIONS");
            arms += 1;
        }
        assert!(arms >= FLAGS.len(), "{arms} option names in parse_args, {} in FLAGS", FLAGS.len());
        for s in OPTIONS.iter().filter(|s| !s.parsed) {
            assert!(takes_value(s.name).is_none());
            let e = parse_args([s.name.to_string()], 4).err().unwrap_or_else(|| panic!("{}: parse_args knows it", s.name));
            assert!(e.starts_with("unknown option"), "{e}");
        }
        // the value-taking early options are the ones arg_step knows (a word after them is their value)
        for s in OPTIONS.iter().filter(|s| !s.parsed && s.name != "--help") {
            assert_eq!(arg_step(s.name) == 2, !s.arg.is_empty(), "{}", s.name);
        }
    }

    /// 60.60 the other lists follow the table: the fuzz target's flag list holds every parsed option, and
    /// docs/configuration.md names every option. DOCS_PENDING: options of this release that the docs rewrite adds;
    /// the test fails when one of them IS in the docs, so the list empties itself.
    #[test]
    fn fuzz_list_and_docs_follow_the_table() {
        const DOCS_PENDING: &[&str] = &[]; // (empty since the v1.3.0 merge: the docs name every option)
        let fuzz = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/fuzz_targets/cli_parse.rs")).unwrap();
        let docs = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/configuration.md")).unwrap();
        let named = |text: &str, name: &str| {
            text.match_indices(name).any(|(i, _)| !text[i + name.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '-'))
        };
        for s in OPTIONS {
            assert!(!s.parsed || fuzz.contains(&format!("\"{}\"", s.name)), "{} is not in the fuzz FLAGS list", s.name);
            let pending = DOCS_PENDING.contains(&s.name);
            assert_eq!(named(&docs, s.name), !pending, "{}: docs/configuration.md and DOCS_PENDING disagree", s.name);
        }
        // and the other way round: an option that a table row of the docs names is in the table
        for row in docs.lines().filter(|l| l.starts_with("| `--")) {
            let name = row[3..].split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).next().unwrap();
            assert!(spec(name).is_some(), "docs/configuration.md documents {name}, which is not an option");
        }
    }

    /// 60.20 C8: FLAGS agrees with parse_args: a value flag alone asks for its value, a bare flag parses alone
    #[test]
    fn flags_table_matches_parse_args() {
        for &(f, v) in FLAGS {
            let r = parse_args([f.to_string()], 4);
            if v {
                assert_eq!(r.err(), Some(needs_value(f)), "{f}");
                assert!(needs_value(f).starts_with(&format!("{f} needs a value: {f} ")), "{f}");
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
        assert_eq!(e, Expanded { args: vec!["7000".into()], config: None, warning: None, preset: None, src: vec![Src::Cmd], show: false });
        // a byte order mark and an empty file
        assert_eq!(ex("--config f", "\u{feff}port 1\n").unwrap().args, ["--port", "1"]);
        assert!(ex("--config f", "").unwrap().args.is_empty());
        // --config as the value of another flag is not a config file
        assert_eq!(ex("--motd --config", "port 1").unwrap().args, ["--motd", "--config"]);
        // 60.46 --adaptive-splice / --no-adaptive-splice as config keys (default on since v1.2.1)
        assert!(parse_args(ex("--config f", "adaptive-splice\n").unwrap().args, 1).unwrap().adaptive_splice);
        assert!(!parse_args(ex("--config f", "no-adaptive-splice\n").unwrap().args, 1).unwrap().adaptive_splice);
        // 60.58 --dns-share as a config key; the command line comes after the file, so --no-dns-share undoes it
        assert!(parse_args(ex("--config f", "dns-share\n").unwrap().args, 1).unwrap().dns_share);
        assert!(!parse_args(ex("--config f --no-dns-share", "dns-share\n").unwrap().args, 1).unwrap().dns_share);
        // 60.58 dns-reserve, no-dns-reserve, no-dns-own as config keys. The two refused pairs are judged on all layers
        // together (review): a file alone may hold a pair that the command line completes, as the flat arguments do
        let whole = |cmd: &str, file: &'static str| {
            ex(cmd, file).and_then(|e| parse_args(e.args, 1)).map(|o| (o.dns_own, o.dns_share, o.dns_reserve))
        };
        assert_eq!(whole("--config f", "dns-reserve\n"), Ok((false, true, true)));
        assert_eq!(whole("--config f --no-dns-reserve", "dns-reserve\n"), Ok((false, false, false)));
        assert_eq!(whole("--dns-own --config f", "no-dns-own\n"), Ok((false, false, false)));
        assert_eq!(whole("--config f --dns-own", "no-dns-own\ndns-server 10.0.0.1\n"), Ok((true, false, false)));
        assert_eq!(whole("--config f --no-dns-reserve", "dns-reserve\nno-dns-share\n"), Ok((false, false, false)));
        assert_eq!(whole("--config f --dns-share", "dns-reserve\nno-dns-share\n"), Ok((false, true, true)));
        for (cmd, file, pair) in [
            ("--config f", "no-dns-own\ndns-server 10.0.0.1\n", "--no-dns-own and --dns-server together"),
            ("--config f", "dns-reserve\nno-dns-share\n", "--no-dns-share and --dns-reserve together"),
            ("--dns-reserve --config f", "no-dns-share\n", "--no-dns-share and --dns-reserve together"),
            ("--config f --no-dns-own", "dns-server 10.0.0.1\n", "--no-dns-own and --dns-server together"),
        ] {
            assert!(whole(cmd, file).unwrap_err().starts_with(pair), "{cmd} {file:?}");
        }
        // 60.57 A1
        assert!(!parse_args(ex("--config f", "no-nofile-raise\n").unwrap().args, 1).unwrap().nofile_raise);
        // 60.57 C as config keys; the command line turns a file's key off again
        let o = parse_args(ex("--config f", "fd-admission\nconn-share\n").unwrap().args, 1).unwrap();
        assert!(o.fd_admission && o.conn_share);
        let o = parse_args(ex("--config f --no-conn-share --no-fd-admission", "fd-admission\nconn-share\n").unwrap().args, 1).unwrap();
        assert!(!o.fd_admission && !o.conn_share);
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
            ("port 1\nthreads s3cretVALUE\n", "f:2: --threads: (value not shown) is not a whole number"),
            ("host s3cretVALUE", "f:1: --host: not an IP address: (value not shown)"),
            ("mem-budget s3cretVALUE", "f:1: --mem-budget: (value not shown) is not a size (bytes, or a whole number with K, M or G)"),
            ("tls-cipher-order s3cretVALUE", "f:1: --tls-cipher-order: client or server, not (value not shown)"),
            ("dns-server s3cretVALUE", "f:1: --dns-server: not IP[:PORT] / [IPv6[%scope]]:PORT: (value not shown)"),
            ("connect-timeout 86401", "f:1: --connect-timeout: at most 86400 seconds"),
            ("s3cretVALUE", "f:1: unknown option (not shown: not an option name)"),
            ("block-host a.example,s3cretVALUE*", "f:1: --block-host: entry 2 of (value not shown): not a host name (letters, digits, '-', '_' and '.'; IDN as punycode xn--)"),
            ("# x\nbogus 1", "f:2: unknown option \"bogus\""),
            ("max-con 5", "f:1: unknown option \"max-con\" (did you mean max-conns?)"),
            ("--port 1", "f:1: write option names without the leading dashes"),
            ("port", "f:1: --port needs a value: --port PORT"),
            ("balance s3cretVALUE", "f:1: --balance takes no value"),
            ("config other.conf", "f:1: --config inside a config file (no includes)"),
            ("help", "f:1: unknown option \"help\""),
            ("show-config", "f:1: unknown option \"show-config\""),
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
        assert_eq!(ex("--config f", "threads x\nbogus 1\n").unwrap_err(), "f:1: --threads: (value not shown) is not a whole number");
        assert_eq!(ex("--config", "").unwrap_err(), "--config needs a value: --config FILE");
        assert_eq!(ex("--config a --config b", "").unwrap_err(), "--config: only one config file");
        // parse_args itself does not know --config (main expands it first)
        assert!(parse("--config f").is_err());
    }

    #[test]
    fn config_secret_warning() {
        let args = || vec!["--config".to_string(), "f".to_string()];
        let w = |mode, file: &'static str| expand_config_with(args(), load_ok(file, mode), &["--motd"], PRESETS).unwrap().warning;
        assert!(w(0o644, "motd x").unwrap().contains("readable by group/others"));
        assert!(w(0o640, "motd x").is_some());
        assert!(w(0o600, "motd x").is_none());
        assert!(w(0o644, "port 1").is_none());
        // a secret list flag replaced on the command line still sits in the file: still a warning
        let a = vec!["--config".to_string(), "f".to_string(), "--cert-auth-key".to_string(), "z".to_string()];
        assert!(expand_config_with(a, load_ok("cert-auth-key x", 0o644), &["--cert-auth-key"], PRESETS).unwrap().warning.is_some());
        assert!(SECRET_FLAGS.iter().all(|f| takes_value(f) == Some(true)));
        // 60.27 C6: the real list (expand_config's) holds --upstream
        let a = vec!["--config".to_string(), "f".to_string()];
        assert!(expand_config_with(a, load_ok("upstream socks5://u:pw@h", 0o644), SECRET_FLAGS, PRESETS).unwrap().warning.is_some());
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
        for line in [
            "--port 1",
            "no-such-flag 1",
            "Port 1",
            "config x",
            "preset",
            "preset x",
            "credit-v2",
            "port 1\x07",
            "x".repeat(CONFIG_MAX_LINE + 1).as_str(),
        ] {
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
            &["--preset"],
            &["--preset", "x"],
            &["--preset", "public", "--config"],
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
        // 60.60 the shape main prints (ui::usage_error): the message in at most 2 lines of 80 columns, then the
        // `Try:` line; no mark and no note id in it either
        for e in &errors {
            let shown = crate::ui::usage_error(e, true);
            assert_eq!(crate::ui::usage_error(e, false).lines().count(), 2, "{e}");
            let lines: Vec<&str> = shown.lines().collect();
            assert!(lines.len() <= 3 && lines[0].starts_with("finalwisp: "), "{shown}");
            assert!(lines.last().unwrap().starts_with("Try: finalwisp --help"), "{shown}");
            assert!(lines.iter().all(|l| l.chars().count() <= crate::ui::WIDTH || !l.trim_start().contains(' ')), "{shown}");
            assert!(!shown.contains(|c| REDACTION_MARKS.contains(c)), "{shown}");
        }
    }

    // ---------------------------------------------------------------- 60.59 presets

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    /// expand with a command line, a config file's text ("" with no --config in `cmd`: never loaded) and the preset texts
    fn exp(cmd: &str, file: &str, presets: &[(&'static str, &str)]) -> Result<Expanded, String> {
        let data = file.as_bytes().to_vec();
        expand_config_with(words(cmd), move |_| Ok((data, 0o600)), SECRET_FLAGS, presets)
    }

    fn opts(e: Expanded) -> Opts {
        parse_args(e.args, 4).and_then(check).unwrap()
    }

    /// the off form of a preset line as command-line tokens: the negation of a switch, the value 0 or off of a limit
    fn off_form(flag: &str, value: &Option<String>) -> Vec<String> {
        match value {
            None => vec![negation(flag).unwrap_or_else(|| panic!("{flag}: a preset switch needs a --no- form"))],
            Some(_) => ["0", "off"]
                .iter()
                .map(|v| vec![flag.to_string(), v.to_string()])
                .find(|a| parse_args(a.clone(), 4).is_ok())
                .unwrap_or_else(|| panic!("{flag}: a preset limit needs the off value 0 or off")),
        }
    }

    fn on_form(flag: &str, value: &Option<String>) -> Vec<String> {
        std::iter::once(flag.to_string()).chain(value.clone()).collect()
    }

    /// command-line tokens as config-file lines
    fn as_file(tokens: &[String]) -> String {
        let mut s = String::new();
        let mut i = 0;
        while i < tokens.len() {
            let n = arg_step(&tokens[i]);
            s += &format!("{}\n", &tokens[i..i + n].join(" ")[2..]);
            i += n;
        }
        s
    }

    fn public() -> Vec<(String, Option<String>)> {
        preset_settings("public", PRESETS[0].1).unwrap()
    }

    /// The docs follow the preset: the table "What `public` sets" of docs/configuration.md has one row per line of
    /// contrib/public.conf, in its order, with the value and the off form; the comment of each line of the file names
    /// the same off form (`Off: ...`, in the config file's spelling).
    #[test]
    fn docs_and_comments_follow_the_preset() {
        let docs = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/configuration.md")).unwrap();
        let table = docs.split_once("What `public` sets:").expect("the table's lead-in").1;
        let rows: Vec<String> =
            table.lines().skip_while(|l| !l.starts_with("|---")).skip(1).take_while(|l| l.starts_with('|')).map(String::from).collect();
        let want: Vec<String> = public()
            .iter()
            .map(|(f, v)| {
                format!(
                    "| `{}` | {} | `{}` |",
                    &f[2..],
                    v.as_ref().map_or("on".to_string(), |v| format!("`{v}`")),
                    off_form(f, v).join(" ")
                )
            })
            .collect();
        assert_eq!(rows, want);
        let comments: Vec<&str> = PRESETS[0].1.lines().filter_map(|l| l.split_once(" Off: ")).map(|c| c.1).collect();
        let offs: Vec<String> = public().iter().map(|(f, v)| as_file(&off_form(f, v)).trim().to_string()).collect();
        assert_eq!(comments, offs);
    }

    /// T7 "printed bytes = shipped bytes": the embedded text is contrib/public.conf, --print-preset gives exactly it (main
    /// writes these bytes to stdout), also beside other flags (the Docker ENTRYPOINT carries --preset public)
    #[test]
    fn print_preset_gives_the_shipped_bytes() {
        let shipped = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../contrib/public.conf")).unwrap();
        assert_eq!(PRESETS[0], ("public", shipped.as_str()));
        assert_eq!(print_preset(&words("--print-preset public")), Some(Ok(shipped.as_str())));
        assert_eq!(print_preset(&words("--preset public --host 0.0.0.0 --port 6001 --print-preset public")), Some(Ok(shipped.as_str())));
        assert_eq!(print_preset(&words("--print-preset none")), Some(Ok("")));
        assert_eq!(print_preset(&words("--preset public --port 1")), None);
        assert_eq!(print_preset(&words("--motd --print-preset")), None, "the value of another flag");
        assert_eq!(print_preset(&words("--print-preset")), Some(Err("--print-preset needs a value: --print-preset NAME".to_string())));
        let e = print_preset(&words("--print-preset pubic")).unwrap().unwrap_err();
        assert_eq!(e, "--print-preset: unknown preset \"pubic\" (the presets: public, none)");
        // the file itself: it parses, sets something, holds no list, no secret and no preset line, and passes check()
        let p = public();
        assert!(!p.is_empty());
        assert!(p.iter().all(|(f, _)| !SECRET_FLAGS.contains(&f.as_str()) && list_group(f).is_none()));
        check(parse_args(p.iter().flat_map(|(f, v)| on_form(f, v)), 4).unwrap()).unwrap();
        // every preset is listed in --help
        for (n, _) in PRESETS {
            assert!(spec("--preset").unwrap().summary.contains(n) && spec("--preset").unwrap().long.contains(n), "{n}");
        }
    }

    /// T7 "every setting off": each line of the preset has an off form, the off form gives a plain finalwisp, and the
    /// line itself changes something (so "off (default)" in the startup line is true). Lines added to
    /// contrib/public.conf are covered without a change here.
    #[test]
    fn preset_settings_have_off_values() {
        let bare = parse("").unwrap();
        let with = opts(exp("--preset public", "", PRESETS).unwrap());
        assert!(with != bare);
        let mut all_off = words("--preset public");
        for (flag, value) in public() {
            let (on, off) = (on_form(&flag, &value), off_form(&flag, &value));
            assert!(parse_args(on.clone(), 4).unwrap() != bare, "{flag}: on by default, or the line does nothing");
            assert!(parse_args(off.clone(), 4).unwrap() == bare, "{flag}: its off form is not the default");
            // one setting off on the command line: the others stay
            let mut a = words("--preset public");
            a.extend(off.clone());
            let o = opts(expand_config(a, |_| panic!("no file")).unwrap());
            let rest: Vec<String> = public().iter().filter(|(f, _)| *f != flag).flat_map(|(f, v)| on_form(f, v)).collect();
            assert!(o == parse_args(rest, 4).unwrap(), "{flag} off: the other settings changed");
            // the same from a config file
            let e = exp("--preset public --config f", &as_file(&off), PRESETS).unwrap();
            assert!(opts(e) == o, "{flag} off in a file");
            all_off.extend(off);
        }
        assert!(opts(expand_config(all_off, |_| panic!("no file")).unwrap()) == bare, "every setting off is a plain finalwisp");
        assert!(opts(exp("--preset public --preset none", "", PRESETS).unwrap()) == bare);
        assert!(opts(exp("--preset none", "", PRESETS).unwrap()) == bare);
    }

    /// T7 "layer order" for every preset setting: preset, then file, then command line; and the startup line names the
    /// layer that gave the value in effect
    #[test]
    fn preset_layer_order() {
        let line = |cmd: &str, file: &str| preset_line(&exp(cmd, file, PRESETS).unwrap()).unwrap();
        let part = |l: &str, flag: &str| {
            let name = format!("{} ", &flag[2..]);
            l.split_once(": ")
                .unwrap()
                .1
                .split(", ")
                .find(|p| p.starts_with(&name))
                .unwrap_or_else(|| panic!("{flag} not in {l}"))
                .to_string()
        };
        let with = opts(exp("--preset public", "", PRESETS).unwrap());
        for (flag, value) in public() {
            let (on, off) = (on_form(&flag, &value), off_form(&flag, &value));
            let (name, shown) = (&flag[2..], value.clone().unwrap_or("on".to_string()));
            // 1. the preset alone
            assert_eq!(part(&line("--preset public", ""), &flag), format!("{name} {shown} (preset)"));
            // 2. the file over the preset (wherever --preset stands)
            for cmd in ["--preset public --config f", "--config f --preset public"] {
                let e = exp(cmd, &as_file(&off), PRESETS).unwrap();
                assert_eq!(part(&preset_line(&e).unwrap(), &flag), format!("{name} off (file)"), "{cmd}");
                assert!(opts(e) != with);
            }
            // 3. the command line over the file over the preset
            let e = exp(&format!("--preset public --config f {}", on.join(" ")), &as_file(&off), PRESETS).unwrap();
            assert_eq!(part(&preset_line(&e).unwrap(), &flag), format!("{name} {shown} (command line)"));
            assert!(opts(e) == with);
            // 4. the command line over the preset
            let e = exp(&format!("--preset public {}", off.join(" ")), "", PRESETS).unwrap();
            assert_eq!(part(&preset_line(&e).unwrap(), &flag), format!("{name} off (command line)"));
            let e = exp(&format!("{} --preset public", off.join(" ")), "", PRESETS).unwrap();
            assert_eq!(part(&preset_line(&e).unwrap(), &flag), format!("{name} off (command line)"), "--preset after the flag");
            // 5. as before 1.3.0: an option before --config is overridden by the file
            let e = exp(&format!("--preset public {} --config f", off.join(" ")), &as_file(&on), PRESETS).unwrap();
            assert_eq!(part(&preset_line(&e).unwrap(), &flag), format!("{name} {shown} (file)"));
            // 6. the preset named by the file: the same layers
            let e = exp("--config f", &format!("{}preset public\n", as_file(&off)), PRESETS).unwrap();
            assert_eq!(part(&preset_line(&e).unwrap(), &flag), format!("{name} off (file)"), "a file line over its own preset");
            let e = exp(&format!("--config f {}", off.join(" ")), "preset public\n", PRESETS).unwrap();
            assert_eq!(part(&preset_line(&e).unwrap(), &flag), format!("{name} off (command line)"));
            // 7. no preset in effect
            assert_eq!(part(&line("--preset none", ""), &flag), format!("{name} off (default)"));
            assert_eq!(part(&line(&format!("--preset none {}", on.join(" ")), ""), &flag), format!("{name} {shown} (command line)"));
        }
        // which preset: the last on the command line; the command line over the file; the last line of the file
        let which = |cmd: &str, file: &str| exp(cmd, file, PRESETS).unwrap().preset;
        assert_eq!(which("--port 1", ""), None);
        assert_eq!(which("--config f", "port 1\n"), None);
        assert_eq!(which("--preset public", ""), Some(("public", Src::Cmd)));
        assert_eq!(which("--preset public --port 1 --preset none", ""), Some(("none", Src::Cmd)));
        assert_eq!(which("--preset none --preset public", ""), Some(("public", Src::Cmd)));
        assert_eq!(which("--config f", "preset public\n"), Some(("public", Src::File)));
        assert_eq!(which("--config f", "preset public\npreset none\n"), Some(("none", Src::File)));
        assert_eq!(which("--config f --preset none", "preset public\n"), Some(("none", Src::Cmd)));
        assert_eq!(which("--preset public --config f", "preset none\n"), Some(("public", Src::Cmd)));
        assert!(line("--config f", "preset public\n").starts_with("preset public (file): "));
        assert!(line("--preset none", "").starts_with("preset none (command line): "));
        // no --preset: no line, and the arguments are untouched (a plain finalwisp is as before)
        let e = exp("7000 --block-smtp", "", PRESETS).unwrap();
        assert_eq!((preset_line(&e), e.args.clone(), e.src.clone()), (None, words("7000 --block-smtp"), vec![Src::Cmd; 2]));
        // --preset as the value of another option is not a preset
        let e = exp("--motd --preset", "", PRESETS).unwrap();
        assert_eq!((e.args, e.preset), (words("--motd --preset"), None));
        // parse_args itself does not know --preset (main expands it first), as --config
        assert!(parse("--preset public").is_err());
    }

    /// 60.59 a preset text with more lines (what a later release adds to contrib/public.conf): the expansion, the layer of
    /// every token and the startup line need no code for a new line
    #[test]
    fn preset_with_added_lines() {
        const P: &[(&str, &str)] = &[("public", "# c\nblock-smtp\nmax-streams-per-conn 1024\n\nno-udp\nmax-conns 500\n"), ("none", "")];
        let e = exp("--threads 2 --preset public --config f --max-conns 0 --port 7000", "max-streams-per-conn 64\nmotd hi\n", P).unwrap();
        assert_eq!(
            e.args,
            words("--block-smtp --max-streams-per-conn 1024 --no-udp --max-conns 500 --threads 2 --max-streams-per-conn 64 --motd hi --max-conns 0 --port 7000")
        );
        use Src::{Cmd as C, File as F, Preset as S};
        assert_eq!(e.src, [S, S, S, S, S, S, C, C, F, F, F, F, C, C, C, C]);
        assert_eq!((e.config.as_deref(), e.preset), (Some("f"), Some(("public", C))));
        assert_eq!(
            preset_line_of(&e, P[0].1).unwrap(),
            "preset public (command line): block-smtp on (preset), max-streams-per-conn 64 (file), no-udp on (preset), max-conns off (command line)"
        );
        let o = opts(e);
        assert_eq!((o.rules.block_smtp, o.max_streams_per_conn, o.udp, o.max_conns, o.threads, o.port), (true, 64, false, 0, 2, 7000));
        // a switch whose negation exists the other way round (`adaptive-splice` after `no-adaptive-splice`)
        const Q: &[(&str, &str)] = &[("public", "no-adaptive-splice\n"), ("none", "")];
        let e = exp("--preset public --adaptive-splice", "", Q).unwrap();
        assert_eq!(preset_line_of(&e, Q[0].1).unwrap(), "preset public (command line): no-adaptive-splice off (command line)");
        // today's file, exactly (this one assertion changes when the file does)
        let e = exp("--preset public", "", PRESETS).unwrap();
        assert_eq!(
            e.args,
            words(
                "--block-smtp --max-streams-per-conn 1024 --fd-admission --conn-share --dns-own --dns-reserve --tcpmem-share \
                 --port-share --dest-failfast --net-watch"
            )
        );
        assert_eq!(
            preset_line(&e).unwrap(),
            "preset public (command line): block-smtp on (preset), max-streams-per-conn 1024 (preset), fd-admission on (preset), \
             conn-share on (preset), dns-own on (preset), dns-reserve on (preset), tcpmem-share on (preset), port-share on \
             (preset), dest-failfast on (preset), net-watch on (preset)"
        );
    }

    #[test]
    fn preset_errors() {
        let err = |cmd: &str, file: &str, p: &[(&'static str, &str)]| exp(cmd, file, p).unwrap_err();
        assert_eq!(err("--preset pubic", "", PRESETS), "--preset: unknown preset \"pubic\" (the presets: public, none)");
        assert_eq!(err("--preset", "", PRESETS), "--preset needs a value: --preset NAME");
        assert_eq!(err("--preset public --preset", "", PRESETS), "--preset needs a value: --preset NAME");
        // a name that does not look like one is not echoed (it may be a mistyped secret)
        let e = err("--preset s3cret/VALUE", "", PRESETS);
        assert_eq!(e, "--preset: unknown preset (the presets: public, none)");
        // in a file: the line, never the value
        for file in ["port 1\npreset s3cretVALUE\n", "port 1\npreset\n", "port 1\npreset public x\n"] {
            assert_eq!(err("--config f", file, PRESETS), "f:2: --preset needs the name of a preset (public, none)", "{file:?}");
        }
        // an unknown name on the command line is an error even when the file names a good one
        assert!(err("--config f --preset nope", "preset public\n", PRESETS).starts_with("--preset: unknown preset \"nope\""));
        // a preset holds no list option, no preset line and no unknown flag (the built-in file: print_preset_gives_the_shipped_bytes)
        for (text, want) in [
            ("block-smtp\nblock-host a.example\n", "preset public:2: --block-host cannot be set by a preset"),
            ("trusted-proxy 127.0.0.1\n", "preset public:1: --trusted-proxy cannot be set by a preset"),
            ("preset none\n", "preset public:1: --preset cannot be set by a preset"),
            ("bogus 1\n", "preset public:1: unknown option \"bogus\""),
            ("max-conns x\n", "preset public:1: --max-conns: (value not shown) is not a whole number (at most 4294967295)"),
        ] {
            assert_eq!(err("--preset public", "", &[("public", text), ("none", "")]), want);
        }
        for e in [err("--preset pubic", "", PRESETS), err("--config f", "preset x\n", PRESETS), err("--preset x@y", "", PRESETS)] {
            assert!(!e.contains(|c| REDACTION_MARKS.contains(c)), "{e}");
        }
    }

    /// 60.59 the off value of block-smtp (a preset or a config file sets it; before 1.3.0 a switch could not be undone)
    #[test]
    fn no_block_smtp() {
        assert!(!parse("").unwrap().rules.block_smtp && parse("--block-smtp").unwrap().rules.block_smtp);
        assert!(!parse("--block-smtp --no-block-smtp").unwrap().rules.block_smtp);
        assert!(parse("--no-block-smtp --block-smtp").unwrap().rules.block_smtp, "the last one wins");
        assert!(!opts(exp("--config f --no-block-smtp", "block-smtp\n", PRESETS).unwrap()).rules.block_smtp);
        assert!(!opts(exp("--config f", "block-smtp\nno-block-smtp\n", PRESETS).unwrap()).rules.block_smtp);
        assert_eq!(exp("--config f", "no-block-smtp x\n", PRESETS).unwrap_err(), "f:1: --no-block-smtp takes no value");
        assert!(parse("--no-block-smtp").unwrap() == parse("").unwrap());
    }

    /// 60.59 lists across a config file and the command line are as before 1.3.0 (v1.2.1's rule, pinned token by token):
    /// repeats inside one layer add up; a list option anywhere on the command line drops the file's entries of that
    /// list; a preset in front changes nothing (a preset holds no list)
    #[test]
    fn lists_between_file_and_command_line_are_unchanged() {
        let f = "dns-server 10.0.0.1\ndns-server 10.0.0.2\nblock-host a.example\nblock-host b.example\nallow-ports 443\ntrusted-proxy 127.0.0.1\n";
        for (cmd, want) in [
            ("--config f", "--dns-server 10.0.0.1 --dns-server 10.0.0.2 --block-host a.example --block-host b.example --allow-ports 443 --trusted-proxy 127.0.0.1"),
            ("--dns-server 10.9.9.9 --config f", "--dns-server 10.9.9.9 --block-host a.example --block-host b.example --allow-ports 443 --trusted-proxy 127.0.0.1"),
            ("--config f --block-host x.example --block-host y.example", "--dns-server 10.0.0.1 --dns-server 10.0.0.2 --allow-ports 443 --trusted-proxy 127.0.0.1 --block-host x.example --block-host y.example"),
            ("--trusted-proxy 10.0.0.0/8 --config f --trusted-proxy ::1", "--trusted-proxy 10.0.0.0/8 --dns-server 10.0.0.1 --dns-server 10.0.0.2 --block-host a.example --block-host b.example --allow-ports 443 --trusted-proxy ::1"),
        ] {
            let e = exp(cmd, f, PRESETS).unwrap();
            assert_eq!(e.args, words(want), "{cmd}");
            assert!(e.preset.is_none());
            let p = exp(&format!("--preset public {cmd}"), f, PRESETS).unwrap();
            let n = public().iter().map(|(f, v)| on_form(f, v).len()).sum::<usize>();
            assert_eq!(p.args[n..], words(want)[..], "--preset public {cmd}");
            assert!(p.src[..n].iter().all(|s| *s == Src::Preset) && p.src[n..].iter().all(|s| *s != Src::Preset));
        }
    }

    /// The words of a JSON string array on a Dockerfile line that starts with `key` (ENTRYPOINT ["a", "b"])
    fn docker_words(text: &str, key: &str) -> Vec<String> {
        let l = text.lines().find(|l| l.starts_with(key)).unwrap_or_else(|| panic!("no {key} line"));
        let inner = l[key.len()..].trim().strip_prefix('[').and_then(|s| s.strip_suffix(']')).expect("exec form");
        inner.split(',').map(|w| w.trim().trim_matches('"').to_string()).collect()
    }

    /// T7 "Docker arguments" and the unit: the argv the image and the unit run (docker replaces CMD by the arguments after
    /// the image name and keeps ENTRYPOINT). The preset is in ENTRYPOINT, so extra arguments keep it; `--preset none` or
    /// a setting's off value turns it off; neither start command passes --trusted-proxy.
    #[test]
    fn docker_and_unit_start_with_the_preset() {
        let docker = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../contrib/docker/Dockerfile")).unwrap();
        let (entry, cmd) = (docker_words(&docker, "ENTRYPOINT"), docker_words(&docker, "CMD"));
        assert_eq!(entry, ["/finalwisp", "--preset", "public"]);
        assert_eq!(cmd, ["--host", "0.0.0.0", "--port", "6001"]);
        let run = |extra: Option<&str>| {
            let mut a = entry[1..].to_vec();
            a.extend(extra.map_or(cmd.clone(), words));
            assert!(!a.iter().any(|w| w == "--trusted-proxy"));
            expand_config(a, |_| panic!("no file")).unwrap()
        };
        let with = opts(exp("--preset public --host 0.0.0.0 --port 6001", "", PRESETS).unwrap());
        // docker run IMAGE
        let e = run(None);
        assert_eq!(e.preset, Some(("public", Src::Cmd)));
        let o = opts(e);
        assert!(o == with && o.rules.block_smtp && o.trusted_proxies.is_empty());
        assert_eq!((o.ip.to_string().as_str(), o.port), ("0.0.0.0", 6001));
        // docker run IMAGE --host 0.0.0.0 --port 6001 --motd hi: the arguments replace CMD, the preset stays
        let o = opts(run(Some("--host 0.0.0.0 --port 6001 --motd hi")));
        assert!(o.rules.block_smtp && o.max_streams_per_conn == with.max_streams_per_conn && o.motd.as_deref() == Some("hi"));
        // docker run IMAGE --port 7000: CMD is gone, so the host is the default again (as before 1.3.0), the preset stays
        let o = opts(run(Some("--port 7000")));
        assert!(o.rules.block_smtp && o.ip.is_loopback());
        // off: --preset none, or one setting's off value
        let e = run(Some("--host 0.0.0.0 --port 6001 --preset none"));
        assert_eq!(e.preset, Some(("none", Src::Cmd)));
        assert!(opts(e) == parse("--host 0.0.0.0 --port 6001").unwrap());
        let o = opts(run(Some("--host 0.0.0.0 --port 6001 --no-block-smtp")));
        assert!(!o.rules.block_smtp && o.max_streams_per_conn == with.max_streams_per_conn);
        // docker run IMAGE --print-preset public
        let mut a = entry[1..].to_vec();
        a.extend(words("--print-preset public"));
        assert_eq!(print_preset(&a), Some(Ok(PRESETS[0].1)));
        // the systemd unit
        let unit = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../contrib/finalwisp.service")).unwrap();
        let start = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        let a = words(start.split_once(' ').unwrap().1);
        assert!(a.starts_with(&words("--preset public")) && !a.iter().any(|w| w == "--trusted-proxy"), "{start}");
        let e = expand_config(a, |_| panic!("no file")).unwrap();
        assert_eq!(e.preset, Some(("public", Src::Cmd)));
        let o = opts(e);
        assert!(o.rules.block_smtp && o.ip.is_loopback() && o.port == 6001 && o.drain_timeout == 30 && o.trusted_proxies.is_empty());
    }

    // ---------------------------------------------------------------- 60.60 the corpus of real command lines

    /// the bytes of a corpus field (bench/v13-ux-corpus.py: %XX escapes; a lone `%` is empty)
    fn unpct(s: &str) -> Vec<u8> {
        if s == "%" {
            return Vec::new();
        }
        let (b, mut out, mut i) = (s.as_bytes(), Vec::new(), 0);
        while i < b.len() {
            if b[i] == b'%' {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }

    /// the fields of an Opts as its Debug text gives them (`name: value`), split at the top level
    fn opts_fields(o: &Opts) -> Vec<String> {
        let d = format!("{o:?}");
        let d = d.strip_prefix("Opts { ").and_then(|d| d.strip_suffix(" }")).expect("Opts Debug form");
        let (mut out, mut depth, mut quote, mut skip, mut from) = (Vec::new(), 0, false, false, 0);
        for (i, c) in d.char_indices() {
            match c {
                _ if skip => skip = false,
                '\\' if quote => skip = true,
                '"' => quote = !quote,
                _ if quote => {}
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(d[from..i].to_string());
                    from = i + 2;
                }
                _ => {}
            }
        }
        out.push(d[from..].to_string());
        out
    }

    /// the fields of `o` that differ from a plain `finalwisp`, tab-separated
    fn opts_diff(o: &Opts) -> String {
        let bare = opts_fields(&parse_args(Vec::new(), 4).unwrap());
        opts_fields(o).into_iter().filter(|f| !bare.contains(f)).collect::<Vec<_>>().join("\t")
    }

    /// opts_diff of a corpus case as the base commit saw it (`base`: the corpus column). The corpus was classified when
    /// the public preset had two lines; v1.3.0 added switches to it (fd-admission, conn-share, dns-reserve, which sets
    /// dns-share, and the four of 60.63: tcpmem-share, port-share, dest-failfast, net-watch). No old command line names
    /// them, so they are on exactly when the public preset is in effect: checked here, then left out of the comparison
    /// with the corpus column. The preset's dns-own is a setting that old command lines do name (--dns-own,
    /// --dns-server): on with the preset, and left out where the base had it off.
    fn diff_as_at_base(st: &Start, base: &str) -> String {
        const ADDED: [&str; 8] = [
            "dns_share: true",
            "dns_reserve: true",
            "fd_admission: true",
            "conn_share: true",
            "tcpmem_share: true",
            "port_share: true",
            "dest_failfast: true",
            "net_watch: true",
        ];
        const OWN: &str = "dns_own: true";
        let diff = opts_diff(&st.opts);
        let public = st.preset.is_some_and(|p| p.0 == "public");
        let on = diff.split('\t').filter(|f| ADDED.contains(f)).count();
        assert_eq!(on, if public { ADDED.len() } else { 0 }, "the preset's new switches: {diff}");
        assert!(!public || diff.split('\t').any(|f| f == OWN), "the preset's resolver: {diff}");
        let own_added = public && !base.split('\t').any(|f| f == OWN);
        diff.split('\t').filter(|f| !ADDED.contains(f) && !(own_added && *f == OWN)).collect::<Vec<_>>().join("\t")
    }

    const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/cli-corpus.txt");

    /// one corpus line: (the words, the --config file's bytes, what the base parser made of it: `run` + the changed
    /// fields, `err`, `preset`)
    fn corpus() -> Vec<(Vec<String>, Option<Vec<u8>>, String)> {
        let text = std::fs::read_to_string(CORPUS).unwrap();
        let mut out = Vec::new();
        for l in text.lines().filter(|l| !l.starts_with('#')) {
            let mut f = l.splitn(3, '\t');
            let (cmd, file, class) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap_or(""));
            let words = cmd.split(' ').filter(|w| !w.is_empty()).map(|w| String::from_utf8(unpct(w)).unwrap()).collect();
            out.push((words, (file != "-").then(|| unpct(file)), class.to_string()));
        }
        out
    }

    fn run(words: Vec<String>, file: Option<Vec<u8>>) -> Result<Command, (String, Option<String>)> {
        command(words, 4, |_| file.map(|d| (d, 0o600)).ok_or("No such file or directory".to_string()))
    }

    /// 60.60 H: no behaviour change outside text. testdata/cli-corpus.txt holds real command lines and config files
    /// (the compat tests, the docs, contrib/ and the fuzz corpus: bench/v13-ux-corpus.py) with what the parser of the
    /// commit before this work (016cc67c: v1.2.1 + the preset form) made of each: `run` and the Opts fields that differ
    /// from a plain finalwisp, `err`, or `preset` (--print-preset). That column was written by this same decoding and
    /// Opts-diff code, pasted into that commit's cli.rs tests with that commit's pipeline (print_preset, expand_config,
    /// parse_args, check). Here every case runs through cli::command, the pipeline of main:
    /// - `run` must give the same Opts (a field added later must have its default for an old command line; the three
    ///   switches that the merge added to the public preset: diff_as_at_base),
    /// - `preset` must still print the preset,
    /// - `err` must still be an error, except for the words this work made valid on purpose: --help / -h, --version /
    ///   -V, --show-config and `--name=value`.
    #[test]
    fn corpus_parses_as_before() {
        let cases = corpus();
        let (mut runs, mut errs, mut new_ok) = (0, 0, 0);
        for (words, file, class) in cases {
            let added = |w: &String| matches!(w.as_str(), "-h" | "--help" | "-V" | "--version" | "--show-config");
            let new_form = words.iter().any(|w| added(w) || (w.starts_with("--") && w.contains('=')));
            let (kind, diff) = class.split_once('\t').unwrap_or((class.as_str(), ""));
            match (kind, run(words.clone(), file)) {
                ("run", Ok(Command::Start(st))) => {
                    assert_eq!(diff_as_at_base(&st, diff), diff, "{words:?}: another Config than before");
                    assert!(!st.show);
                    runs += 1;
                }
                ("preset", Ok(Command::Special(Special::Preset(_)))) => {}
                ("err", Err((e, _))) => {
                    assert!(!e.is_empty());
                    errs += 1;
                }
                ("err", Ok(_)) if new_form => new_ok += 1,
                (was, now) => panic!("{words:?}: was {was}, is now {}", if now.is_ok() { "accepted" } else { "an error" }),
            }
        }
        assert!(runs >= 490 && errs >= 2000, "{runs} run, {errs} err: the corpus shrank");
        assert!(new_ok < 200, "{new_ok} old errors are accepted now");
    }

    /// 60.60 the second corpus: every `run` case again with its options in the `--name=value` form: the same Opts
    #[test]
    fn corpus_with_equals_forms_parses_equal() {
        let mut merged = 0;
        for (words, file, class) in corpus().into_iter().filter(|c| c.2.starts_with("run")) {
            let (mut eq, mut i) = (Vec::new(), 0);
            while i < words.len() {
                // (a name that is not a real option, or the last word, stays as it is)
                if arg_step(&words[i]) == 2 && i + 1 < words.len() {
                    eq.push(format!("{}={}", words[i], words[i + 1]));
                    merged += 1;
                    i += 2;
                } else {
                    eq.push(words[i].clone());
                    i += 1;
                }
            }
            let (Ok(Command::Start(a)), Ok(Command::Start(b))) = (run(words.clone(), file.clone()), run(eq.clone(), file)) else {
                panic!("{eq:?}: not accepted")
            };
            assert!(a.opts == b.opts, "{eq:?}");
            let base = class.split_once('\t').map_or("", |c| c.1);
            assert_eq!(diff_as_at_base(&b, base), base, "{eq:?}");
        }
        assert!(merged > 500, "{merged}");
    }

    #[test]
    fn name_equals_value() {
        let split = |a: &str| split_eq(words(a));
        assert_eq!(split("--port=7000 --host=:: --no-udp 7001"), Ok(words("--port 7000 --host :: --no-udp 7001")));
        assert_eq!(
            split("--motd=a=b --config=f --preset=public --print-preset=none --help=limits"),
            Ok(words("--motd a=b --config f --preset public --print-preset none --help limits"))
        );
        assert_eq!(split("--port="), Ok(vec!["--port".to_string(), String::new()]));
        // the value of another option is never split, nor a word that is no option
        assert_eq!(split("--motd --port=1 --allow-host a=b 7000 x=y -p=1"), Ok(words("--motd --port=1 --allow-host a=b 7000 x=y -p=1")));
        assert_eq!(split("--port"), Ok(words("--port")));
        // a switch takes no value
        for a in ["--block-smtp=1", "--no-udp=", "--show-config=x", "--version=1"] {
            let name = a.split('=').next().unwrap();
            assert_eq!(split(a), Err(format!("{name} takes no value")), "{a}");
        }
        // an unknown name is left alone; parse_args then shows the name, never the value
        assert_eq!(split("--upstrem=socks5://u:hunter2@h"), Ok(words("--upstrem=socks5://u:hunter2@h")));
        let e = parse("--upstrem=socks5://u:hunter2@h").unwrap_err();
        assert_eq!(e, "unknown option --upstrem (did you mean --upstream?)");
        // every value option, both forms: the same Opts (the corpus covers real lines; this covers every row)
        for s in OPTIONS.iter().filter(|s| s.parsed && !s.arg.is_empty()) {
            for v in ["1", "64M", "10.0.0.1", "a.example", "tcp", "x", "info", "client", "socks5://h", "660", "/run/x"] {
                let two = parse_args([s.name.to_string(), v.to_string()], 4);
                let one = split_eq(vec![format!("{}={v}", s.name)]).and_then(|a| parse_args(a, 4));
                assert!(two == one, "{} {v}", s.name);
            }
        }
        let o = |a: &str| match run(words(a), None) {
            Ok(Command::Start(st)) => st.opts,
            _ => panic!("{a}"),
        };
        assert!(o("--port=7000 --max-conns=5 --preset=public") == o("--port 7000 --max-conns 5 --preset public"));
    }

    #[test]
    fn special_commands() {
        let sp = |a: &str| special(&words(a));
        assert_eq!(sp("--help"), Some(Ok(Special::Help(None))));
        assert_eq!(sp("--port 1 -h"), Some(Ok(Special::Help(None))));
        assert_eq!(sp("--help limits"), Some(Ok(Special::Help(Some("limits".into())))));
        assert_eq!(sp("--preset public -h tls --port 1"), Some(Ok(Special::Help(Some("tls".into())))));
        assert_eq!(sp("--help --port 1"), Some(Ok(Special::Help(None))), "an option after --help is not its topic");
        assert_eq!(sp("--version"), Some(Ok(Special::Version)));
        assert_eq!(sp("--preset public --host 0.0.0.0 -V"), Some(Ok(Special::Version)), "beside the Docker image's arguments");
        assert_eq!(sp("--version --help"), Some(Ok(Special::Version)), "the first one");
        // as the value of another option they are values
        assert_eq!(sp("--motd --help"), None);
        assert_eq!(sp("--motd -V --port 1"), None);
        assert_eq!(sp("--port 1 --show-config"), None);
        // --print-preset wins wherever it stands (60.59: nothing else is checked)
        assert_eq!(sp("--help --print-preset public"), Some(Ok(Special::Preset(PRESETS[0].1))));
        assert!(matches!(sp("--print-preset nope"), Some(Err(_))));
        // through the whole pipeline; a config file is not read for them
        let cmd = |a: &str| command(words(a), 4, |_| -> Result<(Vec<u8>, u32), String> { panic!("loaded") });
        assert!(matches!(cmd("--config f --help=limits"), Ok(Command::Special(Special::Help(Some(t)))) if t == "limits"));
        assert!(matches!(cmd("--bogus --version"), Ok(Command::Special(Special::Version))));
        // nothing else is checked for them (60.59), also not a switch with a value; without them it is the error
        assert!(matches!(cmd("--print-preset public --no-udp=1"), Ok(Command::Special(Special::Preset(_)))));
        assert!(matches!(cmd("--no-udp=1 --print-preset=public"), Ok(Command::Special(Special::Preset(_)))));
        assert!(matches!(cmd("--no-udp=1 -h"), Ok(Command::Special(Special::Help(None)))));
        assert!(matches!(cmd("--no-udp=1 --port 1"), Err((e, None)) if e == "--no-udp takes no value"));
        // --show-config: a start that only prints; the options are checked as always
        let show = |a: &str| match run(words(a), Some(b"max-conns 9\n".to_vec())) {
            Ok(Command::Start(st)) => (st.show, st.opts.max_conns, st.opts.port),
            Ok(_) => panic!("{a}: not a start"),
            Err((e, _)) => panic!("{a}: {e}"),
        };
        assert_eq!(show("--port 7000"), (false, 0, 7000));
        assert_eq!(show("--show-config --port 7000 --config f"), (true, 9, 7000));
        assert_eq!(show("--config f --show-config"), (true, 9, 6001));
        assert_eq!(show("--motd --show-config"), (false, 0, 6001), "the value of --motd");
        assert!(run(words("--show-config --port x"), None).is_err());
        assert!(run(words("--show-config --metrics-listen 6001"), None).is_err(), "check() runs too");
    }

    /// 60.60 D: an unknown word names the nearest option when one is close; a word that does not look like an option
    /// name is never echoed
    #[test]
    fn unknown_words_get_the_nearest_option() {
        for (typed, want) in [
            ("--max-con", "unknown option --max-con (did you mean --max-conns?)"),
            ("--trusted", "unknown option --trusted (did you mean --trusted-proxy?)"),
            ("--thread", "unknown option --thread (did you mean --threads?)"),
            ("--treads", "unknown option --treads (did you mean --threads?)"),
            ("--blocksmtp", "unknown option --blocksmtp (did you mean --block-smtp?)"),
            ("--alow-host", "unknown option --alow-host (did you mean --allow-host?)"),
            ("-port", "unknown option -port (did you mean --port?)"),
            ("--versoin", "unknown option --versoin (did you mean --version?)"),
            ("--show-conf", "unknown option --show-conf (did you mean --show-config?)"),
            ("--frobnicate", "unknown option --frobnicate"),
            ("--max", "unknown option --max"), // (three options start with it)
            ("-x", "unknown option -x"),
            ("help", "unknown argument \"help\" (did you mean --help?)"),
            ("version", "unknown argument \"version\" (did you mean --version?)"),
            ("port", "unknown argument \"port\" (did you mean --port?)"),
            ("start", "unknown argument \"start\" (options start with two dashes; a bare number is the port)"),
            ("70000", "\"70000\" is not a port (0-65535)"),
            ("--port=1", "unknown option --port (did you mean --port?)"), // (only when split_eq did not run before)
            ("--Upstream", "unknown option (not shown: not an option name; it may hold a secret)"),
            ("-", "unknown option (not shown: not an option name; it may hold a secret)"),
            ("--", "unknown option (not shown: not an option name; it may hold a secret)"),
            ("socks5://u:hunter2@h", "unknown argument (not shown: not an option name; it may hold a secret)"),
            ("--s3cret/VALUE=x", "unknown option (not shown: not an option name; it may hold a secret)"),
        ] {
            assert_eq!(parse_args([typed.to_string()], 4).unwrap_err(), want, "{typed}");
        }
        assert_eq!(distance(b"kitten", b"sitting"), 3);
        assert_eq!((distance(b"", b"abc"), distance(b"abc", b""), distance(b"abc", b"abc"), distance(b"ab", b"ba")), (3, 3, 0, 2));
        // a bad value says what is expected
        for (line, want) in [
            ("--port abc", "--port: \"abc\" is not a port (0-65535)"),
            ("--port 70000", "--port: \"70000\" is not a port (0-65535)"),
            ("--threads many", "--threads: \"many\" is not a whole number"),
            ("--max-conns -1", "--max-conns: \"-1\" is not a whole number (at most 4294967295)"),
            ("--drain-timeout soon", "--drain-timeout: \"soon\" is not a number of seconds"),
            ("--mem-budget 1.5G", "--mem-budget: \"1.5G\" is not a size (bytes, or a whole number with K, M or G)"),
            ("--max-conns", "--max-conns needs a value: --max-conns N"),
            ("--tls-cipher-order", "--tls-cipher-order needs a value: --tls-cipher-order SIDE"),
        ] {
            assert_eq!(parse(line).unwrap_err(), want, "{line}");
        }
    }

    /// 60.60 the settings view (the start block and --show-config): the effect, one row per setting, the layer that
    /// decides, and never a credential
    #[test]
    fn settings_show_the_effect_and_the_layer() {
        let view = |cmd: &str, file: &str| {
            let e = exp(cmd, file, PRESETS).unwrap();
            let s = settings(&e.args, &e.src);
            parse_args(e.args, 4).unwrap(); // (settings() reads lines that parse)
            s
        };
        let get = |s: &[Setting], key: &str| {
            let hit: Vec<&Setting> = s.iter().filter(|x| x.key == key).collect();
            assert_eq!(hit.len(), 1, "{key}: one row per setting");
            (hit[0].value.clone(), hit[0].src, hit[0].changed)
        };
        // a plain finalwisp: every setting at its default, switches by their effect
        let s = view("", "");
        assert!(s.iter().all(|x| x.src.is_none() && !x.changed));
        for (key, value) in [
            ("udp", "on"),
            ("splice", "on"),
            ("tfo", "on"),
            ("keepalive", "on"),
            ("prio", "on"),
            ("credit-v2", "on"),
            ("credit-pace", "on"),
            ("adaptive-splice", "on"),
            ("direct-ip", "on"),
            ("ipv6-targets", "on"),
            ("block-smtp", "off"),
            ("balance", "off"),
            ("allow-loopback", "off"),
            ("graceful-close", "off"),
            ("port", "6001"),
            ("max-conns", "off"),
            ("mem-budget", "automatic"),
            ("threads", "one per CPU"),
        ] {
            assert_eq!(get(&s, key), (value.to_string(), None, false), "{key}");
        }
        // no row is a spelling: no key starts with no-, and a pair is one row
        assert!(s.iter().all(|x| !x.key.starts_with("no-")));
        assert_eq!(
            s.len(),
            FLAGS.len() - 11,
            "the pairs (block-smtp, adaptive-splice, dns-share, fd-admission, conn-share, dns-reserve, dns-own and the four of section E) are one row each"
        );
        // the default state of every switch is what the parser does without it (the table's texts cannot drift)
        let bare = parse("").unwrap();
        for sp in OPTIONS.iter().filter(|s| s.parsed && s.arg.is_empty()) {
            let key = sp.name[2..].strip_prefix("no-").unwrap_or(&sp.name[2..]);
            let default_on = get(&s, key).0 == "on";
            let given_on = !sp.name.starts_with("--no-");
            assert_eq!(parse_args([sp.name.to_string()], 4).unwrap() == bare, given_on == default_on, "{}: default of {key}", sp.name);
            let one = view(sp.name, "");
            assert_eq!(
                get(&one, key),
                (if given_on { "on" } else { "off" }.to_string(), Some(Src::Cmd), given_on != default_on),
                "{}",
                sp.name
            );
        }
        // the layers; the last word decides; a bare number is the port; 0 of a limit is off; a list shows every entry
        let s = view(
            "--preset public --config f --no-block-smtp 7000 --port 7001 --max-conns 0 --allow-host a.example --allow-host b.example,c.example",
            "max-streams-per-conn 64\nno-udp\nthreads 2\nallow-host z.example\n",
        );
        assert_eq!(get(&s, "block-smtp"), ("off".to_string(), Some(Src::Cmd), false));
        assert_eq!(get(&s, "max-streams-per-conn"), ("64".to_string(), Some(Src::File), true));
        assert_eq!(get(&s, "udp"), ("off".to_string(), Some(Src::File), true));
        assert_eq!(get(&s, "threads"), ("2".to_string(), Some(Src::File), true));
        assert_eq!(get(&s, "port"), ("7001".to_string(), Some(Src::Cmd), true));
        assert_eq!(get(&s, "max-conns"), ("off".to_string(), Some(Src::Cmd), false));
        assert_eq!(get(&s, "allow-host"), ("a.example, b.example,c.example".to_string(), Some(Src::Cmd), true));
        assert_eq!(get(&view("7000", ""), "port"), ("7000".to_string(), Some(Src::Cmd), true));
        assert_eq!(get(&view("--preset public", ""), "block-smtp"), ("on".to_string(), Some(Src::Preset), true));
        assert_eq!(get(&view("--no-adaptive-splice --adaptive-splice", ""), "adaptive-splice"), ("on".to_string(), Some(Src::Cmd), false));
        assert_eq!(
            preset_keys(Some(("public", Src::Cmd))),
            [
                "block-smtp",
                "max-streams-per-conn",
                "fd-admission",
                "conn-share",
                "dns-own",
                "dns-reserve",
                "tcpmem-share",
                "port-share",
                "dest-failfast",
                "net-watch"
            ]
        );
        assert!(preset_keys(None).is_empty() && preset_keys(Some(("none", Src::Cmd))).is_empty());
        // a text value is never taken for the default's word or for "off"; a default typed out is the default
        assert_eq!(get(&view("--motd 0", ""), "motd"), ("0".to_string(), Some(Src::Cmd), true));
        assert_eq!(get(&view("--motd off", ""), "motd"), ("off".to_string(), Some(Src::Cmd), true));
        assert_eq!(get(&view("--auth-file 0", ""), "auth-file"), ("0".to_string(), Some(Src::Cmd), true));
        assert_eq!(get(&view("--port 6001", ""), "port"), ("6001".to_string(), Some(Src::Cmd), false));
        assert_eq!(get(&view("--metrics-interval 0", ""), "metrics-interval"), ("off".to_string(), Some(Src::Cmd), false));
        // a control character of a value is not shown as it is
        // (a config file refuses one; the command line does not)
        let args = ["--motd".to_string(), "a\u{1b}[31mb".to_string()];
        assert_eq!(get(&settings(&args, &[Src::Cmd, Src::Cmd]), "motd").0, "a?[31mb");
    }

    /// 60.60 what one option does to another setting is shown as the effect, with the reason, on that setting's row
    #[test]
    fn settings_show_what_another_option_implies() {
        let view = |cmd: &str| match command(cmd.split_whitespace().map(String::from).collect(), 4, |_| Err("no file".to_string())) {
            Ok(Command::Start(st)) => st,
            _ => panic!("{cmd}: not a start"),
        };
        let get = |st: &Start, key: &str| {
            let s = st.settings.iter().find(|s| s.key == key).unwrap();
            (s.value.clone(), s.src, s.changed)
        };
        let st = view("--dns-server 192.0.2.1");
        assert!(st.opts.dns_own);
        assert_eq!(get(&st, "dns-own"), ("on (set by dns-server)".to_string(), None, false));
        assert_eq!(get(&view("--dns-own"), "dns-own"), ("on".to_string(), Some(Src::Cmd), true));
        // 60.58 --dns-reserve turns the thread sharing on; a --dns-share that was given is its own row
        let st = view("--dns-reserve");
        assert!(st.opts.dns_share && st.opts.dns_reserve);
        assert_eq!(get(&st, "dns-share"), ("on (set by dns-reserve)".to_string(), None, false));
        assert_eq!(get(&st, "dns-reserve"), ("on".to_string(), Some(Src::Cmd), true));
        assert_eq!(get(&view("--dns-share --dns-reserve"), "dns-share"), ("on".to_string(), Some(Src::Cmd), true));
        let st = view("--preset public");
        assert_eq!(get(&st, "dns-share"), ("on (set by dns-reserve)".to_string(), None, false));
        assert_eq!(get(&st, "dns-reserve"), ("on".to_string(), Some(Src::Preset), true));
        assert_eq!(get(&st, "dns-own"), ("on".to_string(), Some(Src::Preset), true));
        let st = view("--preset public --no-dns-reserve --no-dns-own");
        assert!(!st.opts.dns_share && !st.opts.dns_reserve && !st.opts.dns_own);
        assert_eq!((get(&st, "dns-share").0, get(&st, "dns-reserve").0, get(&st, "dns-own").0), ("off".into(), "off".into(), "off".into()));
        let st = view("--upstream socks5://127.0.0.1:1080");
        assert_eq!(get(&st, "udp"), ("off (with an upstream proxy)".to_string(), None, false));
        assert_eq!(get(&st, "tfo"), ("off (with an upstream proxy)".to_string(), None, false));
        assert_eq!(get(&view("--upstream socks5://127.0.0.1:1080 --no-udp"), "udp"), ("off".to_string(), Some(Src::Cmd), true));
        let st = view("--download-rate 1M");
        assert!(!st.opts.pace.client_settings(st.opts.splice, st.opts.notsent_lowat).0);
        assert_eq!(get(&st, "splice"), ("off (with download-rate)".to_string(), None, false));
        assert_eq!(get(&st, "adaptive-splice"), ("off (splice is off)".to_string(), None, false));
        assert_eq!(get(&view("--no-splice"), "adaptive-splice").0, "off (splice is off)");
        assert_eq!(get(&view("--no-splice --no-adaptive-splice"), "adaptive-splice"), ("off".to_string(), Some(Src::Cmd), true));
        let st = view("--log-level warn --log-conns --log-streams");
        assert_eq!(get(&st, "log-conns"), ("off (log-level is below info)".to_string(), Some(Src::Cmd), false));
        assert_eq!(get(&st, "log-streams").0, "off (log-level is below info)");
        assert_eq!(get(&view("--log-level debug --log-conns"), "log-conns"), ("on".to_string(), Some(Src::Cmd), true));
        let st = view("");
        let rows = ["dns-own", "dns-share", "udp", "tfo", "splice", "adaptive-splice", "log-conns", "log-streams"];
        assert!(rows.iter().all(|k| get(&st, k).1.is_none() && !get(&st, k).0.contains('(')));
        // 60.24 the config file's warning with an error: always for a line that does not parse; for a failed check
        // only at --log-level warn and above (the level is known then)
        let loose = |cmd: &str| match command(cmd.split_whitespace().map(String::from).collect(), 4, |_| {
            Ok((b"upstream socks5://u:p@127.0.0.1:1\n".to_vec(), 0o644))
        }) {
            Err((_, w)) => w.is_some(),
            Ok(_) => panic!("{cmd}: no error"),
        };
        assert!(loose("--config f --port x"));
        assert!(loose("--config f --port x --log-level error"), "the level of a line that does not parse is not known");
        assert!(loose("--config f --unix-mode 600"), "a failed check, default level");
        assert!(!loose("--config f --unix-mode 600 --log-level error"), "a failed check below warn");
    }

    /// 60.60 a credential never shows: the --upstream URL from each layer, in the settings, the start block's rows and
    /// --show-config (one function, shown_value, redacts for all of them)
    #[test]
    fn credentials_are_redacted_in_every_layer() {
        const URL: &str = "socks5://alice:hunter2@10.0.0.9:1080";
        const P: &[(&str, &str)] = &[("public", "block-smtp\n"), ("none", "")];
        assert_eq!(shown_value("--upstream", URL), "socks5://***@10.0.0.9:1080");
        assert_eq!(shown_value("--upstream", "not a url alice:hunter2"), "(not shown)");
        assert_eq!(shown_value("--motd", URL), URL, "only the secret options");
        assert!(SECRET_FLAGS.iter().all(|f| shown_value(f, "hunter2") == "(not shown)"));
        for (cmd, file, layer) in [
            (format!("--upstream {URL}"), String::new(), Src::Cmd),
            (format!("--upstream={URL} --preset public"), String::new(), Src::Cmd),
            ("--config f".to_string(), format!("upstream {URL}\n"), Src::File),
            ("--preset public --config f --port 7000".to_string(), format!("preset none\nupstream {URL}\n"), Src::File),
        ] {
            let Ok(Command::Start(st)) = command(split_eq(words(&cmd)).unwrap(), 4, |_| Ok((file.clone().into_bytes(), 0o600))) else {
                panic!("{cmd}")
            };
            assert_eq!(st.opts.upstream.as_deref(), Some(URL), "the server itself gets the URL");
            let s: Vec<&Setting> = st.settings.iter().filter(|s| s.key == "upstream").collect();
            assert_eq!((s.len(), s[0].value.as_str(), s[0].src), (1, "socks5://***@10.0.0.9:1080", Some(layer)), "{cmd}");
            let block = crate::ui::block(&crate::ui::layer_rows(&st));
            let shown = crate::ui::show_config(crate::ui::Paint(false), &st, &[], &[]);
            for text in [block, shown] {
                assert!(text.contains("socks5://***@10.0.0.9:1080"), "{cmd}: {text}");
                assert!(!text.contains("hunter2") && !text.contains("alice"), "{cmd}: {text}");
            }
        }
        // (a preset cannot hold a secret: the built-in one is checked by print_preset_gives_the_shipped_bytes; if one
        // did, the same function would redact it)
        let e = exp("--preset public", "", &[("public", "upstream socks5://alice:hunter2@h\n"), ("none", "")]).unwrap();
        let s = settings(&e.args, &e.src);
        assert_eq!(
            s.iter().find(|s| s.key == "upstream").map(|s| (s.value.as_str(), s.src)),
            Some(("socks5://***@h:1080", Some(Src::Preset)))
        );
        let _ = P;
    }

    /// 60.60 C: the version has one source, server/Cargo.toml. The top heading of CHANGELOG.md names it (a release
    /// cannot forget the bump), and bench/release.sh and bench/package.sh read the same line.
    #[test]
    fn version_has_one_source() {
        let v = crate::ui::VERSION;
        assert!(v.split('.').count() == 3 && v.split('.').all(|p| p.parse::<u32>().is_ok()), "{v}");
        let log = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../CHANGELOG.md")).unwrap();
        let top = log.lines().find(|l| l.starts_with("## ")).unwrap();
        assert!(top.split_whitespace().any(|w| w == format!("v{v}")), "CHANGELOG.md starts with {top:?}, Cargo.toml says {v}");
        for script in ["release.sh", "package.sh"] {
            let s = std::fs::read_to_string(format!("{}/../bench/{script}", env!("CARGO_MANIFEST_DIR"))).unwrap();
            assert!(s.contains("server/Cargo.toml") && s.contains("^version = "), "bench/{script} does not read the version");
        }
    }
}
