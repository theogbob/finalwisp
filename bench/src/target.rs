//! TCP target server for wbench (pointer 30.01).
use crate::TargetMode;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Default)]
struct Counters {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    conns: AtomicU64,
}

pub async fn serve(bind: &str, port: u16, mode: TargetMode, chunk: usize, report: u64, verify: bool) -> std::io::Result<()> {
    if verify && !matches!(mode, TargetMode::Source | TargetMode::Sink) {
        return Err(std::io::Error::other("--verify needs --mode source or sink (60.15 T06)"));
    }
    if mode == TargetMode::UdpEcho {
        return serve_udp(bind, port).await;
    }
    // Several SO_REUSEPORT listeners with a deep backlog: one accept loop (backlog 1024) overflowed
    // under churn and added 1 s SYN-retransmit tails to every server's numbers.
    let addr: std::net::SocketAddr = tokio::net::lookup_host((bind, port)).await?.next().expect("bind addr");
    let acceptors = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(8);
    let mut listeners = Vec::new();
    for _ in 0..acceptors {
        let s = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
        s.set_reuseaddr(true)?;
        s.set_reuseport(true)?;
        s.bind(addr)?;
        listeners.push(s.listen(65535)?);
    }
    eprintln!("wbench target: {mode:?} on {bind}:{port} chunk={chunk} acceptors={acceptors}{}", if verify { " verify" } else { "" });
    let c = Arc::new(Counters::default());
    if report > 0 {
        let c = c.clone();
        tokio::spawn(async move {
            let mut last = (0u64, 0u64);
            let mut tick = tokio::time::interval(Duration::from_millis(report));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.tick().await;
            loop {
                tick.tick().await;
                let now = (c.bytes_in.load(Relaxed), c.bytes_out.load(Relaxed));
                let mib = |b: u64| b as f64 / (1024.0 * 1024.0) / (report as f64 / 1000.0);
                // cum_in/cum_out = cumulative bytes since start, for exact windowed rates (30.03 wispmark.py)
                eprintln!(
                    "target: conns={} in={:.1} MiB/s out={:.1} MiB/s cum_in={} cum_out={}",
                    c.conns.load(Relaxed),
                    mib(now.0 - last.0),
                    mib(now.1 - last.1),
                    now.0,
                    now.1
                );
                last = now;
            }
        });
    }

    let mut tasks = Vec::new();
    for listener in listeners {
        let c = c.clone();
        tasks.push(tokio::spawn(accept_loop(listener, mode, chunk, verify, c)));
    }
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

async fn accept_loop(listener: TcpListener, mode: TargetMode, chunk: usize, verify: bool, c: Arc<Counters>) {
    loop {
        let (sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // EMFILE etc.: back off instead of spinning.
                eprintln!("target accept: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let c = c.clone();
        c.conns.fetch_add(1, Relaxed);
        tokio::spawn(async move {
            let r = if verify { handle_verify(sock, mode, chunk, &c).await } else { handle(sock, mode, chunk, &c).await };
            if let (true, Err(e)) = (verify, r) {
                eprintln!("target verify: {e}"); // a broken verify stream must be visible (the client counts it too)
            }
            c.conns.fetch_sub(1, Relaxed);
        });
    }
}

async fn handle(mut sock: TcpStream, mode: TargetMode, chunk: usize, c: &Counters) -> std::io::Result<()> {
    match mode {
        TargetMode::Echo => {
            let mut buf = vec![0u8; chunk];
            loop {
                let n = sock.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                c.bytes_in.fetch_add(n as u64, Relaxed);
                sock.write_all(&buf[..n]).await?;
                c.bytes_out.fetch_add(n as u64, Relaxed);
            }
        }
        TargetMode::Sink => {
            let mut buf = vec![0u8; chunk.max(256 * 1024)];
            loop {
                let n = sock.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                c.bytes_in.fetch_add(n as u64, Relaxed);
            }
        }
        TargetMode::UdpEcho => unreachable!("UDP has its own loop (serve_udp)"),
        TargetMode::Reply => {
            // 20.19: [u32 LE response_len][u32 LE request_len] + padding -> response_len zero bytes
            let mut buf = vec![0u8; chunk.max(65536)];
            let zeros = vec![0u8; chunk];
            let (mut hdr, mut hl, mut skip) = ([0u8; 8], 0usize, 0usize);
            let mut resp = 0usize;
            loop {
                let n = sock.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                c.bytes_in.fetch_add(n as u64, Relaxed);
                let mut p = &buf[..n];
                while !p.is_empty() {
                    if skip > 0 {
                        let k = skip.min(p.len());
                        skip -= k;
                        p = &p[k..];
                    } else {
                        let k = (8 - hl).min(p.len());
                        hdr[hl..hl + k].copy_from_slice(&p[..k]);
                        hl += k;
                        p = &p[k..];
                        if hl < 8 {
                            continue;
                        }
                        hl = 0;
                        resp = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                        skip = (u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize).saturating_sub(8);
                    }
                    if skip == 0 {
                        let mut left = resp;
                        while left > 0 {
                            let w = left.min(zeros.len());
                            sock.write_all(&zeros[..w]).await?;
                            c.bytes_out.fetch_add(w as u64, Relaxed);
                            left -= w;
                        }
                    }
                }
            }
        }
        TargetMode::Source => {
            let buf = vec![0u8; chunk];
            let (mut rd, mut wr) = sock.split();
            // Stop writing once the peer closes (read side hits EOF / error).
            let mut sink = [0u8; 4096];
            loop {
                tokio::select! {
                    r = rd.read(&mut sink) => {
                        match r { Ok(0) | Err(_) => return Ok(()), Ok(n) => { c.bytes_in.fetch_add(n as u64, Relaxed); } }
                    }
                    r = wr.write(&buf) => {
                        let n = r?;
                        c.bytes_out.fetch_add(n as u64, Relaxed);
                    }
                }
            }
        }
    }
}

/// 60.15 T06 (bench/src/verify.rs): read HELLO, then send pattern (source) or check incoming pattern (sink) until
/// the client's END; answer with our END (bytes sent, bytes received, content errors) and close.
async fn handle_verify(mut sock: TcpStream, mode: TargetMode, chunk: usize, c: &Counters) -> std::io::Result<()> {
    use crate::verify;
    let mut h = [0u8; verify::HELLO_LEN];
    // a client without --verify (or a lost first DATA) must not hang this stream silently
    tokio::time::timeout(Duration::from_secs(15), sock.read_exact(&mut h))
        .await
        .map_err(|_| std::io::Error::other("no HELLO within 15 s (client without --verify?)"))??;
    c.bytes_in.fetch_add(h.len() as u64, Relaxed);
    let key = verify::parse_hello(&h).ok_or_else(|| std::io::Error::other("no HELLO at the start of the stream"))?;
    let mut rx = verify::Rx::new(key);
    // source only reads the client's END: a small buffer (thousands of streams)
    let mut rbuf = vec![0u8; if mode == TargetMode::Source { 4096 } else { chunk.max(256 * 1024) }];
    let mut wbuf = vec![0u8; if mode == TargetMode::Source { chunk } else { 0 }];
    let mut sent = 0u64;
    let (mut rd, mut wr) = sock.split();
    while rx.end.is_none() {
        let n = if mode == TargetMode::Source {
            verify::fill(key, sent, &mut wbuf); // regenerated from `sent` every time: a partial write leaves no gap
            tokio::select! {
                r = rd.read(&mut rbuf) => Some(r?),
                r = wr.write(&wbuf) => {
                    let n = r?;
                    sent += n as u64;
                    c.bytes_out.fetch_add(n as u64, Relaxed);
                    None
                }
            }
        } else {
            Some(rd.read(&mut rbuf).await?)
        };
        match n {
            Some(0) => return Err(std::io::Error::other(format!("stream ended without END after {} pattern bytes", rx.off))),
            Some(n) => {
                c.bytes_in.fetch_add(n as u64, Relaxed);
                rx.feed(&rbuf[..n]);
            }
            None => {}
        }
    }
    let end = verify::End { sent, received: rx.off, errs: rx.errs };
    wr.write_all(&end.bytes()).await?;
    c.bytes_out.fetch_add(verify::END_LEN as u64, Relaxed);
    wr.shutdown().await?;
    // wait for the client's side to close (the Wisp server closes the target socket after the stream's CLOSE)
    let _ = tokio::time::timeout(Duration::from_secs(30), async { while rd.read(&mut rbuf).await.is_ok_and(|n| n > 0) {} }).await;
    Ok(())
}

/// 20.16 UDP echo target: a few tasks share one socket, each datagram goes back to its sender.
async fn serve_udp(bind: &str, port: u16) -> std::io::Result<()> {
    let sock = Arc::new(UdpSocket::bind((bind, port)).await?);
    eprintln!("wbench target: UdpEcho on {bind}:{port}");
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let sock = sock.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}
