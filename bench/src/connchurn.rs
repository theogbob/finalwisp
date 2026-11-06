//! 30.10 connchurn (pointer 30.01): a NEW WebSocket connection for every request. Each of conns x streams
//! loops runs, one after another: TCP connect -> WS upgrade (TLS with wss://) -> Wisp v1 CONTINUE ->
//! CONNECT one TCP stream -> one `size`-byte DATA, echoed back -> WS close frame; the next connection starts
//! at once while a closer task waits for the server's FIN (`close`). Latency = TCP connect start -> full
//! echo received.
//! Counts the per-connection cost churn does not see (churn reuses its WebSocket connections).
use super::*;

const ITER_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_WAIT: Duration = Duration::from_secs(2);
/// closing sockets per loop at most (fds: loops x this; 10x10 = 1600)
const CLOSERS_PER_LOOP: usize = 16;

/// One whole frame from rbuf (reading more when needed): (opcode, payload).
async fn frame(sock: &mut crate::tls::Sock, rbuf: &mut BytesMut) -> Result<(u8, BytesMut), String> {
    loop {
        if let Some(h) = ws::parse_hdr(rbuf).map_err(|e| e.to_string())? {
            if rbuf.len() >= h.hdr_len + h.payload_len {
                if !h.fin || h.opcode == OP_CONT {
                    return Err("fragmented ws frame (not expected for one small reply)".into());
                }
                if h.mask.is_some() {
                    return Err("masked frame from the server (RFC 6455 5.1)".into());
                }
                rbuf.advance(h.hdr_len);
                return Ok((h.opcode, rbuf.split_to(h.payload_len)));
            }
        }
        if sock.read_some(rbuf).await.map_err(|e| e.to_string())? == 0 {
            return Err("eof".into());
        }
    }
}

/// 30.16 the status code of a close frame's payload (0 = none)
fn close_code(p: &[u8]) -> u16 {
    if p.len() >= 2 { u16::from_be_bytes([p[0], p[1]]) } else { 0 }
}

/// One connection up to the echo + the client close frame: Ok((latency in us, socket, buffer)) for `close`.
async fn one(plan: &Plan, mg: &mut MaskGen) -> Result<(u64, crate::tls::Sock, BytesMut), String> {
    let t0 = Instant::now();
    let (mut sock, mut rbuf) = ws::connect(&plan.url, plan.tls.as_ref()).await.map_err(|e| format!("connect/upgrade: {e}"))?;
    // Wisp v1: the server opens with CONTINUE on stream 0 (initial credit).
    loop {
        let (op, p) = frame(&mut sock, &mut rbuf).await.map_err(|e| format!("waiting for CONTINUE: {e}"))?;
        match op {
            OP_BIN if p.len() >= 5 && p[0] == T_CONTINUE && p[1..5] == [0, 0, 0, 0] => {
                // u32 LE buffer remaining: the DATA below needs >= 1
                if p.len() < 9 || u32::from_le_bytes([p[5], p[6], p[7], p[8]]) == 0 {
                    return Err(format!("bad initial CONTINUE ({} bytes, or credit 0)", p.len()));
                }
                break;
            }
            OP_BIN | OP_PING | OP_PONG => {}
            OP_CLOSE => return Err(format!("server closed before CONTINUE (code {})", close_code(&p))),
            o => return Err(format!("unexpected ws opcode {o} before CONTINUE")),
        }
    }
    let mut out = Vec::with_capacity(64 + plan.size + plan.host.len());
    let mut connect = vec![T_CONNECT, 1, 0, 0, 0, 0x01];
    connect.extend_from_slice(&plan.port.to_le_bytes());
    connect.extend_from_slice(plan.host.as_bytes());
    ws::push_frame(&mut out, OP_BIN, &[&connect], 0, mg.next());
    ws::push_frame(&mut out, OP_BIN, &[&[T_DATA, 1, 0, 0, 0]], plan.size, mg.next());
    sock.write_all(&out).await.map_err(|e| format!("send CONNECT+DATA: {e}"))?;
    let mut got = 0usize;
    while got < plan.size {
        let (op, p) = frame(&mut sock, &mut rbuf).await.map_err(|e| format!("waiting for the echo: {e}"))?;
        match op {
            OP_BIN if p.len() >= 5 && p[1..5] == [1, 0, 0, 0] => match p[0] {
                T_DATA => got += p.len() - 5,
                T_CLOSE => return Err(format!("stream closed by the server (reason 0x{:02x})", p.get(5).copied().unwrap_or(0))),
                _ => {} // CONTINUE / INFO
            },
            OP_BIN | OP_PING | OP_PONG => {}
            OP_CLOSE => return Err(format!("server closed the WebSocket before the echo (code {})", close_code(&p))),
            o => return Err(format!("unexpected ws opcode {o}")),
        }
    }
    let lat = t0.elapsed().as_micros() as u64;
    out.clear();
    ws::push_frame(&mut out, OP_CLOSE, &[&1000u16.to_be_bytes()], 0, mg.next());
    let _ = sock.write_all(&out).await; // after the measured part: a failure here only ends the connection
    Ok((lat, sock, rbuf))
}

/// The closing half, off the loop's path: read past the server's close frame until its TCP FIN (TLS: after
/// close_notify), so the server closes TCP first, as RFC 6455 asks; this keeps TIME_WAIT off the client's
/// ephemeral ports (cross-host runs would run out of them). finalwisp closes kTLS sockets from a 100 ms
/// linger tick, so waiting inline would measure that tick, not the connection cost.
async fn close(mut sock: crate::tls::Sock, mut rbuf: BytesMut) {
    let _ = tokio::time::timeout(CLOSE_WAIT, async {
        while frame(&mut sock, &mut rbuf).await.is_ok() {}
        let _ = sock.wait_tcp_eof().await;
    })
    .await;
}

/// Runs the measurement; returns (completed connections, errors, latency histogram, loops with >= 1 success,
/// errors by kind).
pub(super) async fn run(plan: Arc<Plan>, loops: usize, measure_start: Instant, end: Instant) -> (u64, u64, Histogram<u64>, usize, ErrKinds) {
    let sh = Arc::new(Shared { window: OnceLock::new(), printed: AtomicU64::new(0) }); // only err() is used here;
    let mut handles = Vec::with_capacity(loops);
    for i in 0..loops {
        let (plan, sh) = (plan.clone(), sh.clone());
        handles.push(tokio::spawn(async move {
            let mut mg = MaskGen::new(0x9E37_79B9u32.wrapping_mul(i as u32 + 1));
            let (mut ops, mut errors, mut hist, mut any_ok) = (0u64, 0u64, new_hist(), false);
            let mut errk = ErrKinds::default();
            let mut closing = tokio::task::JoinSet::new();
            while Instant::now() < end {
                while closing.len() >= CLOSERS_PER_LOOP {
                    closing.join_next().await;
                }
                let r = tokio::time::timeout(ITER_TIMEOUT, one(&plan, &mut mg)).await.unwrap_or_else(|_| Err("timeout (10 s)".into()));
                let done = Instant::now();
                match r {
                    Ok((us, sock, rbuf)) => {
                        closing.spawn(close(sock, rbuf));
                        any_ok = true;
                        if done >= measure_start && done < end {
                            ops += 1;
                            let _ = hist.record(us.max(1));
                        }
                    }
                    Err(e) => {
                        // every iteration started before `end`, so any failure counts (incl. a 10 s timeout
                        // that ends after the window: a stall must not read as zero errors)
                        errors += 1;
                        errk.msg(&e);
                        sh.err(|| format!("connchurn loop {i}: {e}"));
                    }
                }
            }
            while closing.join_next().await.is_some() {}
            (ops, errors, hist, any_ok, errk)
        }));
    }
    let (mut ops, mut errors, mut hist, mut ok) = (0u64, 0u64, new_hist(), 0usize);
    let mut errk = ErrKinds::default();
    for h in handles {
        match tokio::time::timeout_at((end + ITER_TIMEOUT + Duration::from_secs(5)).into(), h).await {
            Ok(Ok((o, e, hh, any, ek))) => {
                ops += o;
                errors += e;
                errk.merge(&ek);
                let _ = hist.add(&hh);
                ok += any as usize;
            }
            _ => {
                errors += 1;
                errk.key("join_timeout");
            }
        }
    }
    (ops, errors, hist, ok, errk)
}
