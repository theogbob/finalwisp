# Securing a public server

Start a server that anyone can reach with the `public` preset, and know what the preset covers and what it does not.

```sh
# behind nginx or Caddy on this host
finalwisp --preset public --host 127.0.0.1 --port 6001 --trusted-proxy 127.0.0.1
# direct clients, built-in TLS
finalwisp --preset public --host 0.0.0.0 --port 443 --tls-cert fullchain.pem --tls-key privkey.pem
```

- [What is on by default](#what-is-on-by-default)
- [What the preset does](#what-the-preset-does)
- [What the preset does not do](#what-the-preset-does-not-do)
- [More limits you can add](#more-limits-you-can-add)
- [What a user costs](#what-a-user-costs): file descriptors and the open-file limit
- [Destination policy](#destination-policy)
- [Per-destination limits](#per-destination-limits)
- [Slow names and the resolver threads](#slow-names-and-the-resolver-threads)

## What is on by default

By default finalwisp already refuses loopback, private and reserved targets, the server's own addresses, and IPv6
forms that hide an IPv4 address. Clients can reach the public internet on any port. For a server that anyone can
reach, start from the `public` preset, then decide what clients may reach.

The systemd unit and the Docker image start with `--preset public` (since 1.3.0). `finalwisp --print-preset public`
prints its settings, and the lines at startup show them, with what a config file or the command line changed. How a config
file and the command line override it is in the [configuration reference](configuration.md#presets).

## What the preset does

| part | what it does |
|---|---|
| `block-smtp` | Closes the mail ports 25, 465 and 587. An open Wisp server is otherwise a spam relay, and hosting providers react quickly to that. |
| `max-streams-per-conn 1024` | A backstop against one connection that opens streams without end (a port scan, for example). It is set far above what pages need: in our tests of 36 public pages with 4 browser client setups, the busiest page held 268 streams at once on one connection. A test page with 1,000 images on one HTTP/1.1 host held 999. Do not lower it to tune load: a refused stream is a lost request (a missing image or script), and the clients we tested do not try it again. |
| `fd-admission`, `conn-share` | Connection admission and connection share. While fewer than 3/4 of the server's file descriptors are handed out, nothing is refused. When they run short, new connections are refused first (at once, counted and logged) and new streams last. An address that holds most of the descriptors stops getting new connections before the other addresses do. The marks are in the [reference](configuration.md#--fd-admission). |
| `dns-own` | The built-in resolver instead of the system's. A name whose name server never answers is given up after 4 to 6 s instead of 10 s, and within 2 s when the client closes the stream. It reads the name servers of `/etc/resolv.conf`, and `/etc/hosts`; [what it does not read](configuration.md#--dns-own). |
| `dns-reserve` | DNS thread reserve. A quarter of the resolver threads is kept for clients whose names answer fast; clients with slow names share the other threads, and among them a thread that comes back goes to the client address with the fewest lookups running. So a client that asks for names that never answer cannot make the names of other clients wait, once it counts as slow (one of its lookups has run for 1 s). Nothing is refused. It has three costs: see [slow names](#slow-names-and-the-resolver-threads). |
| `tcpmem-share` | Kernel TCP memory share. Downloads that a client does not read stay in the kernel's TCP memory, and when that is full the kernel slows every connection of the host. From 3/4 of the host's limit, the client address that holds more than half of the unread downloads gets no new streams while another client is connected. Open streams go on. On a 2-core VPS, one address that kept adding unread downloads filled the host's TCP memory without this part: another client's upload stopped, and its download fell from 8.0 to 0.03 MiB/s. With it (three runs) the address got no stream past 2,000 and the host stayed below its limit. The other client kept working, but not always at full speed: its download was 8.0 MiB/s in one run and 0.7 MiB/s in two. A burst is not stopped (see below). The marks are in the [reference](configuration.md#--tcpmem-share). |
| `port-share` | Source port share. The host has a fixed number of source ports toward one destination address and port (28,232 with the Linux defaults). From 3/4 of them in use, the client address that holds more than half of the sockets to that destination gets no new streams to it while another client uses it. From 15/16 of them in use, an address that is alone on a destination gets no new streams to it while other clients are connected, so ports are left for a client that comes later (the same counter, `refuse_port_share`; the stream log names the rule `port_share` or `port_reserve`). From 1/4, new sockets to it get a socket option that keeps connects fast (Linux 6.3 and later). See the [reference](configuration.md#--port-share). |
| `dest-failfast` | Dead destinations. When 8 connects of one worker thread to one destination have each got no answer to 4 SYN packets (3 seconds or more, by the kernel's retransmit schedule), that thread's new streams to it fail at once and no longer hold a socket for the connect timeout. One connect per second per worker thread still goes out, and the first answer ends it. On a 2-core VPS, 2,000 streams per second to one dead port held 27,843 file descriptors and took another client's requests from 1,764 to 116 per 45 seconds without this part; with it the server held 39 file descriptors and the other client kept 1,626 of 1,812. See the [reference](configuration.md#--dest-failfast). |
| `net-watch` | Counters and a log line for two things that no part of the preset bounds: SYN retransmits and UDP datagrams (see [what the preset does not do](#what-the-preset-does-not-do)). It refuses nothing. See the [reference](configuration.md#--net-watch). |

The server also raises its own open-file limit to the hard limit at startup (but not above 1048576), with or without
the preset. `--no-nofile-raise` turns that off. See [what a user costs](#what-a-user-costs) for the number you need.

The preset holds no fixed per-address number and no fixed connection count, on purpose:

- An address is not a user. Behind one IPv4 address (or one IPv6 /64) there can be one person, or a school or a mobile
  carrier with thousands. In our tests, 100 real browsers behind one address opened 5,560 streams within one second on
  the largest page, and 1,000 replayed users behind one address made 979 new connections within one second after a
  server restart.
- A number low enough to stop one abuser is far below that. Before 1.3.0 this guide suggested
  `--max-conns 10000 --max-conns-per-ip 50 --max-streams-per-conn 256 --stream-rate-per-ip 50`. In our abuse tests on
  a 2-core VPS, those flags stopped two of the four attack shapes that slowed other clients down (for one attacker
  address), did not stop the other two, and in three shapes that did no harm without them they locked out every user
  who shared the attacker's address.
- So the preset refuses nothing while the host has room, and when the host is short it refuses new connections
  before streams: a refused connection gives an error at once and the client connects again at the next
  page load, while a refused stream breaks a page that is already open.

## What the preset does not do

- **Nothing inside one address.** Users who share an address with an abuser share its fate.
- **Many addresses at once.** A botnet, or one client that rotates through many IPv6 networks, is many addresses to
  the server. Only the host-wide part of the admission applies.
- **A client that chooses its own address.** That happens behind a trusted proxy that does not set the client-address
  header itself: see [what the server can and cannot tell](reverse-proxy.md#what-the-server-can-and-cannot-tell).
- **Streams on connections that are already open.** The connection share acts on new connections. A client can
  still open streams on the connections it has, up to 1024 on each, until one of the stream guards of the table
  above refuses them.
- **Two load shapes that use the host's packet rate.** On a 2-core VPS, one client slowed other clients down with
  streams to many targets that never answer the connect (the kernel sends each SYN packet again and again: 4,200 SYN
  retransmits per second), and with a very high rate of UDP datagrams (10,000 per second). The preset sets no bound
  for these, because the host has no limit for its packet rate that the server could read. `net-watch` counts both
  and logs a warning that names them; `dest-failfast` stops the first one only where 8 or more connects of one worker
  thread go to the same destination.
- **Many addresses that each hold a little.** The share rules judge one client address against the others. When no
  address holds more than half, nobody is refused. For the ports, a stream is then refused only when a destination
  has no port left.
- **Kernel TCP memory that fills.** Downloads that clients do not read stay in the kernel's TCP memory, and when it
  is full every connection of the host slows down. The preset does not prevent this. The option
  [`--tcpmem-share`](configuration.md#--tcpmem-share) covers one case: one address that keeps adding downloads it
  never reads. Its reference says what it does not cover, with the tests: many addresses that each hold a few, a
  burst from one address within a second or two, and downloads that ran at full speed and were then paused (honest
  clients or not). The warning "the host entered kernel TCP memory pressure" names the state. See
  [small hosts and many slow downloads](memory.md#small-hosts-and-many-slow-downloads).
- **A destination that comes back.** `dest-failfast` also refuses streams to a destination that comes back, until
  its next probe: in a test with a destination that was down for 12 seconds and came back, 60 of 270 streams were
  refused at once, and 59 of them would have connected after a wait of up to 7 seconds without this part. The first
  answer came at the same time with and without it.
- **Very many users behind one address on one destination.** Toward one destination address and port, one client
  address gets no new streams from 15/16 of the host's source ports in use while other clients are connected (26,468
  with the Linux defaults), and from 3/4 (21,174) once another address uses that destination too. The server counts
  a few times a second, so an address that opens streams fast stops a little above the mark: in our test it held
  27,000, and a client that came later got the 1,232 ports that were left. In our tests, 100 browsers behind one
  address held 18,145 streams to one destination address and port at the busiest moment of the largest test page.
  So the two marks are at about 146 and about 117 such users behind one address. A wider
  `net.ipv4.ip_local_port_range` on the host moves both.
- **Bandwidth.** No caps: the preset cannot know your link. See `--download-rate`, `--upload-rate` and
  `--upload-rate-per-ip` below.
- **UDP stays on.** In 125 rendered page loads with 4 browser client setups, no page opened a UDP stream. If your
  clients do not need UDP, `--no-udp` removes it.
- **Who may connect and where to.** Authentication and destination lists are your policy (below).
- **Idle connections** are never closed by a timeout of the server. There is one known issue with very many
  connections that arrive within the same second or two and then stay idle: see
  [known limits](troubleshooting.md#known-limits).

## More limits you can add

All of these work with or without the preset. A later option overrides the preset's value.

- **Connection limits.** `--max-conns` caps the whole process. `--max-conns-per-ip` caps one address, and
  `--conn-rate-per-ip R/B` limits how fast one address opens new connections: `20/200` allows a burst of 200, then 20
  per second, the same as "200 connections per 10 seconds". A closed connection does not give its token back. Use the
  per-address options only when you know who is behind your users' addresses (a private server for known clients, for
  example): every user behind a shared address counts against the same number.
- **Stream limits.** `--max-streams-per-conn` caps the streams on one connection. `--stream-rate-per-ip` limits how
  fast one address opens streams. One page load opened up to 244 streams within one second in our tests, so a low rate
  breaks pages.
- **Per destination.** `--stream-rate-per-dest` caps how fast all clients together open streams to one target, so
  your server cannot be used to flood one site (see [per-destination limits](#per-destination-limits)).
- **Bandwidth.** `--download-rate` and `--upload-rate` cap one connection; `--upload-rate-per-ip` caps one address.
  There is no per-IP download cap (see [known limits](troubleshooting.md#known-limits)).
- **Destinations.** `--allow-ports tcp:80,tcp:443 --no-udp` keeps clients on the web (an allow list for TCP alone leaves UDP
  open). `--block-dest` refuses address ranges,
  `--block-host` names. `--no-direct-ip` forces clients to send names. `--no-udp` refuses UDP streams.
- **Authentication.** `--auth-file` (passwords) or `--cert-auth-key` (ed25519 keys) restrict the server to your own
  clients. This uses Wisp v2; v1 clients cannot connect then.

## What a user costs

File descriptors are the capacity number to plan with. Each connection is one, each open stream is one (up to four
while it connects), and a connection that downloads through splice holds two more.

What we measured, with a browser proxy that opens one Wisp connection per tab and a user who loads a new page every
20 seconds:

- With the epoxy client: about 88 file descriptors per active user (87.4 to 88.7, with 1,000 replayed users). 100
  real browsers held a little more: 93 on average in one test and a median of 95 in another.
- With the libcurl.js client: fewer. Single real sessions held 51 open streams on average, and each open stream is
  one descriptor.
- A user who only keeps a tab open holds far fewer. Other clients: estimate from the streams they keep open.

| open-file limit | active users at 88 descriptors each (computed, not measured) |
|---|---|
| 1,024 | 10 |
| 65,536 | about 745 |
| 524,288 | about 5,960 |
| 1,048,576 | about 11,900 |

The server keeps some descriptors for itself: about 100 on a host with 2 threads, more with more threads. That
counts at a small limit (of 1,024, about 920 are left for connections and streams, so the first row is 10).
CPU, memory or the network can run out before the descriptors do; the table is only the descriptor part. One
measured point: with a limit of 65,536 and users arriving one after another, the descriptors ran out when 902 users
were connected.

When the descriptors run out, new streams fail to open, and pages lose requests. Nobody is disconnected. The server
counts and logs it and refuses new connections at once.

The preset refuses new connections earlier, from 7/8 of the descriptors (806 connected users in the same test), and
leaves the rest to the users who are already connected. That is room, not a guarantee: in the test their streams
used it up 50 seconds later. Over the run they lost about a third of the requests they lost without the preset
(60,269 against 168,096), and 194 of 1,000 users never got in (18 without it). Raise the limit before it comes to
this.

Measured at the limit of the shipped systemd unit (1,048,576), on a virtual machine with 14 CPU threads that also
ran the clients and the destinations. One run each; the users loaded pages at the usual rate, but each answer had
1/100 of its real size:

- 12,000 active users, all connected before the first mark: they held 1,047,256 descriptors (99.9% of the usable
  ones), and no stream was refused. A new connection that came after 7/8 was reset.
- 14,000 users arriving over 7 minutes, one address per user: nothing was refused until 7/8. From there (12,413
  connected users) new connections were refused, and 1,587 users did not get in. The streams of the connected users
  used up the room 73 seconds later. Nobody was disconnected.
- 7,800 users behind one address and 200 behind a second, at 67% of the descriptors: nothing was refused.
- 13,440 users arriving from one address and 560 from a second: from 3/4 of the descriptors on (10,927 connected
  users) the big address got HTTP 429 for new connections (the clients came through a trusted proxy; 2,145 were
  refused), while the second address went on connecting. From 7/8 on, new connections from both addresses were
  reset. In all, 2,985 of the 14,000 users did not get in. The descriptors did not run out, and no request failed.

With the clients and the destinations on it, that machine was near its CPU limit at 12,000 users. So the test shows
what the marks do at this limit. It does not show whether the descriptors run out first with answers of real size.

How to raise the limit (the `open files` line at startup shows the value in effect):

- systemd: `LimitNOFILE=1048576` in the unit (the shipped unit has it).
- Docker: `docker run --ulimit nofile=1048576:1048576 ...`. Docker 29 with default settings started our test
  container with a soft limit of 1,024 and a hard limit of 524,288; finalwisp raises its soft limit to that hard limit
  at startup.
- A shell: `ulimit -n 1048576` before the start (the hard limit must allow it). finalwisp raises the soft limit to
  the hard limit by itself, but not above 1048576; `--no-nofile-raise` turns that off.

Memory is the second number: see [memory budget](memory.md#memory-budget).

The connection-tracking table can run out before either. A host that tracks connections (Docker with its default
network, or a firewall with stateful or NAT rules) keeps one entry in a kernel table for every TCP connection, and a
closed connection keeps its entry for about 2 more minutes. In our replay an active user held about 340 entries:
86 open (one connection and its streams) and about 250 that had closed in the last 2 minutes. With a table
of 262,144 entries, a common size, 580 such users filled almost 80% of it, while they used under 10% of the file
descriptors of that server. When the table is full the kernel drops the packets of new connections: connects to
destinations time out, new clients do not get in, and nothing in the server's counters names the cause (the kernel
log usually says `nf_conntrack: table full, dropping packet`). finalwisp does not read this table. Look at
`sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max` on the host under load, and raise
`nf_conntrack_max` if the count comes near it.

## Destination policy

Points to know about the destination policy:

- The server's own addresses are read once at startup. An address added later (DHCP, a cloud change) needs a restart.
- A public IP that is not on an interface (cloud 1:1 NAT, an EC2 elastic IP) is not in that set. Block it with
  `--block-dest`, or clients can reach your own services through it.
- Host rules match the name as the client sent it and cannot see DNS aliases. Use `--block-dest` for hard blocks.
- An allowed name never lifts an address block: a name that resolves to a private address is still refused.
- `--allow-private` opens your whole internal network to every client. Use it only on a trusted network.

Per-IP limits use IPv4 addresses and IPv6 /64 networks. The table holds up to 65,536 addresses; when it is full, new
addresses are not limited per IP (`--max-conns` still applies).

## Per-destination limits

Per-IP limits stop one client. They do not stop many clients that all open streams to the same site, and to that site
the flood comes from your server's address: abuse reports and IP bans then hit every user. Two options cap new
streams to one destination from all clients together:

```sh
finalwisp ... --stream-rate-per-dest 250/250 --stream-rate-per-dest-minute 6000
```

- `--stream-rate-per-dest R[/B]`: R new streams per second, burst B (default 2R).
- `--stream-rate-per-dest-minute N`: N new streams per minute (refilled evenly, N/60 per second).
- A stream needs room under both. Over either, the stream gets CLOSE `0x49` (throttled); the connection stays open.
  A refused stream uses up no per-destination budget. Open streams are not counted, only new ones.
- The destination is the target IP address and port, after DNS: a name and its address share one limit, and a site
  with several addresses gets the limit per address. With `--upstream socks5h://...` (the proxy resolves names) it is
  the host name and port instead (case-insensitive); a client can then spread its streams over other names of the site.
- The limit counts every client on the whole server (all threads share one table). The table holds 65,536
  destinations; a full table section first drops the entries that have refilled, and if none has, new destinations are
  not limited (counted in `dest_untracked`).
- Refusals are counted in `refuse_dest_rate`; with `--log-streams` they have `rule=dest_rate` (per second) or
  `rule=dest_rate_minute`.

Coming from wispurr: `maxConnectsPerDestPerSecond: 250` and `maxConnectsPerDestPerMinute: 6000` are
`--stream-rate-per-dest 250/250 --stream-rate-per-dest-minute 6000`. wispurr counts in fixed windows; finalwisp
uses token buckets, so the per-minute budget refills gradually instead of all at once at the window's end.

## Slow names and the resolver threads

A name that is not in the cache needs one of the resolver threads (`--dns-threads`, 16 by default) until its lookup
ends. A name whose name server does not answer keeps its thread for a long time: about 10 s with the system
resolver; with `--dns-own` 4 s when the host has one name server and at most 6 s when it has several. A client
that asks for many such names can keep every thread busy, and then the new names of all other clients wait in a
queue.

What the server does about it:

- **Always:** a lookup that waited as long as `--connect-timeout` (at least 1 s) is given up (CLOSE `0x42`, counted in
  `dns_expired`), so the queue cannot grow without limit.
- **`--dns-own`** makes each such name cheaper: its thread is back after 4 to 6 s at most, and within 2 s when the
  client has closed the stream. The system resolver cannot be stopped once it has started a lookup. The preset sets
  `--dns-own`.
- **`--dns-share`** changes who gets a thread that comes back. Without it, lookups run in the order they arrived, so
  a new client waits behind the whole queue of another client. With it, the thread goes to the client address that
  has the fewest lookups running, and for that address to its connection with the fewest. A new client then waits
  for one thread to come back, not behind the queue of a client that already has lookups running. (Clients that
  have nothing running take turns by age.) This needs at least 2 resolver threads: with `--dns-threads 1` nothing
  runs at the moment the thread is free, so lookups still run in arrival order.

- **`--dns-reserve`** (in the preset; it turns `--dns-share` on) keeps a quarter of the threads, 4 of 16, for
  clients that are not slow. A client is slow while one of its lookups has run for 1 s, and for 60 s after such a
  lookup: its connection, and every connection of its address when the address is public. All slow clients together
  get the other 12 threads and no more. A new name of a client that is not slow then starts at once, also when a
  client that is slow already sends 16 names at the same moment.

What `--dns-share` does not do: it keeps no thread free. When all threads are busy with slow names, a new name
still waits until the first of them is back. Against a client that sends its slow names steadily, that is a short
wait, because the threads come back one after the other. Against a client that sends 16 at once it can be as long
as one slow lookup (4 to 6 s with `--dns-own`, up to 10 s with the system resolver). So use `--dns-share` together
with `--dns-own`, and keep `--max-streams-per-conn` set (the preset sets both): it limits how many names one
connection can ask for at once.

It also does not help against a client that comes from very many addresses (an IPv6 /48 has 65,536 /64 networks):
each address counts as a client of its own.

`--dns-reserve` closes the first gap: the kept threads are free for a new name when a slow client holds all the
others. It has three costs (measured with the built-in resolver):

- **The kept threads can stand free while slow lookups wait.** That is what a reserve is. When a name server is
  down or late, every client is slow, and a quarter of the threads does nothing.
- **A client on the same public address as a slow client is slow with it** (a school or an office behind one
  address, with one user who asks for dead names). It gets what `--dns-share` gives it, not the reserve.
- **A client that opens pages with dead names in quick succession** waits longer for the live names of its next
  pages. In our test (pages 1.5 s apart, each with 4 or 8 names that never answer), the live names of the third and
  later pages waited about 1 s. With 15 s between the pages there was no difference.

To keep the system resolver with the preset, add `--no-dns-own`: the reserve stays on. On a calm host we measured
no difference between the two resolvers (a new name in about 3 ms). With the system resolver a name that never
answers holds its thread for about 10 s instead of 4 to 6 s, and its lookup cannot be stopped.

Two things the reserve does not do. A client is not slow before one of its lookups has run for 1 s: its first
names can take every thread once, for one lookup time (4 to 6 s). And the second gap stays open: a client that
brings a new address every few seconds starts again with each address.

Clients behind a reverse proxy are told apart by their real address (`--trusted-proxy`). Clients whose address is
loopback, private, CGNAT, link-local or another reserved range (also Teredo, `2001::/32`), and clients on
`--listen-unix` that send no client address, are told apart by connection only: such an address is a proxy or a gateway in front of many users.

Nothing is refused by `--dns-share`, and when only one client has lookups it uses every thread. With
`--dns-reserve` nothing is refused either, and a slow client that is alone uses 12 of the 16 threads. Watch
`finalwisp_dns_wait_seconds_total` / `finalwisp_dns_miss_total` (the mean wait for a thread) and
`finalwisp_dns_wait_max_seconds`.
