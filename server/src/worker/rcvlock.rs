//! 60.47 --park-rcvlock (opt-in): lock the receive buffer of a download-only stream's target socket while the stream
//! waits on its client, so kernel receive autotuning does not grow it to tcp_rmem max while nobody reads it.
//!
//! Why (docs/summaries/60.47-park-rcvlock.md): a stream parked on its client's output (Target::blocked) still lets the
//! origin fill our target socket's receive queue up to its receive buffer, and autotuning (DRS) grows that buffer from
//! the largest drain per RTT. 100 parked downloads held 140-230 MiB on a 2-vCPU host (60.43), enough for tcp_mem
//! pressure. 60.44's prototype shrank SO_RCVBUF at the park: a buffer below what is queued makes the kernel prune and
//! drop arriving segments (TcpExt RcvPruned / TCPRcvQDrop, then an RTO at the sender), which cost echo 10x10 half its
//! throughput. TCP_WINDOW_CLAMP limits only the window beyond what is queued, not the queue. So this never shrinks: it
//! sets SOCK_RCVBUF_LOCK (SO_BUF_LOCK, Linux 5.15+; main refuses the flag without it) at the size the buffer has, after
//! raising a buffer below the floor (Config::park_rcvlock, at most 2 x rmem_max, so the raise never shrinks either).
//!
//! Scope: a Wisp TCP stream whose client sent no DATA on it, or whose DATA count did not change for RCVLOCK_QUIET (as
//! seen at its reparks, with the loop turn's time Worker::now), and whose upload grant credit pacing does not hold
//! (60.42: a held grant means upload is waiting; on a 2-vCPU box under pressure echo streams stalled > 250 ms by RTOs
//! looked quiet): full-duplex streams (echo, a proxied bidirectional transfer) keep autotuning. wsproxy streams are out of scope (their uploads are not counted per stream).
//! When: Worker::resume, after a resumed target parked again (sustained client-limited, not one full turn). Every unpark
//! goes through Worker::resume, so the same site lifts it: a resume whose read ends without parking again (drained, short
//! read or EAGAIN, or its read budget ran out: the client took what was queued) restores the old lock bits, and
//! autotuning continues from the locked size. (A drain site in read_target would miss the short-read drains, and it is
//! the per-byte path.) The lift clears only SOCK_RCVBUF_LOCK. 20.26 caps (memory levels, --tcpmem-adapt) also set and
//! clear the lock bits: no lock and no lift while a stage caps sockets (a same-host target the caps exempt keeps our lock
//! past the episode: its next unparked resume lifts it, one that never parks again keeps it, at its locked size, until it
//! closes; known limit, release review v1.2.0); a stage without caps happens only without a memory floor, where uncap_bufs restores every capped socket
//! and clears its bits, so a bit still set after an episode is ours. With a memory floor (budget < 256 MiB) every stage
//! caps sockets, so the flag does nothing there (the caps already bound the target buffers).
//! Cost: locking = 2 getsockopt + 1 setsockopt (+ 1 setsockopt + 1 getsockopt to raise a small buffer), unlocking =
//! 1 getsockopt + 1 setsockopt, per episode (not per park). Off: one Config
//! u32 test in Worker::resume, the side vector stays empty; read_target and splice_target are unchanged.

use super::*;

/// a stream counts as download-only once its DATA count did not change for this long (as seen at its reparks)
pub(super) const RCVLOCK_QUIET: Duration = Duration::from_millis(250);

const UNLOCKED: u8 = 0;
const LOCKED: u8 = 1; // we set SOCK_RCVBUF_LOCK on this socket
const FOREIGN: u8 = 2; // the buffer was locked by someone else (or a lock syscall failed): left alone until the next lift

/// per target slot (Worker::rcvlock, a side vector: Target unchanged)
#[derive(Clone, Copy)]
pub(super) struct LockSt {
    g1: u32,     // the target's generation + 1 (0 = never used)
    up: u32,     // Target::upkts when last seen changed
    at: Instant, // the turn time (Worker::now) when `up` was seen changed
    caps: u32,   // Stats::cap_apply (low 32 bits) when we locked: changed = a caps episode ran since
    state: u8,   // UNLOCKED / LOCKED / FOREIGN
}

impl Worker {
    /// Worker::resume after read_target of an Open TCP target (Config::park_rcvlock != 0): parked again = lock a
    /// download-only stream's receive buffer; not parked = lift our lock
    #[inline(never)]
    pub(super) fn rcvlock_resumed(&mut self, ti: u32, tg: u32) {
        let Some(t) = self.targets.get(ti, tg) else { return };
        if !t.blocked {
            return self.rcvlock_lift(ti, tg);
        }
        if t.raw || t.fd < 0 {
            return;
        }
        let (fd, up, now, g1) = (t.fd, t.upkts, self.now, tg.wrapping_add(1));
        let (caps, capping) = (self.stats.cap_apply.get() as u32, self.st.sock_cap != 0);
        let i = ti as usize;
        if self.rcvlock.len() <= i {
            self.rcvlock.resize(i + 1, LockSt { g1: 0, up: 0, at: now, caps: 0, state: UNLOCKED });
        }
        let s = &mut self.rcvlock[i];
        if s.g1 != g1 {
            *s = LockSt { g1, up, at: now, caps, state: UNLOCKED };
        }
        if s.state == LOCKED {
            if s.caps == caps || capping {
                return; // still ours (or a stage caps sockets now: decided once it is over)
            }
            // a caps episode ran since our lock and is over (only possible without a memory floor: uncap_bufs restored every
            // capped socket and cleared its bits): bit cleared = lock again below, bit set = still ours
            match net::buf_lock(fd) {
                Some(b) => {
                    s.caps = caps;
                    if b & net::RCVBUF_LOCK != 0 {
                        return;
                    }
                    s.state = UNLOCKED;
                }
                None => {
                    self.stats.rcvlock_errors.bump(); // (caps not advanced: the next repark looks again)
                    return;
                }
            }
        }
        if s.state != UNLOCKED || capping {
            return;
        }
        if s.up != up {
            (s.up, s.at) = (up, now);
        }
        if up != 0 && now.saturating_duration_since(s.at) < RCVLOCK_QUIET {
            return; // the client sent DATA lately: full duplex, autotuning stays
        }
        if self.cpace_st.get(i).is_some_and(|p| p.held && p.g1 == g1) {
            return; // credit pacing holds this stream's upload grant: full duplex by definition (a stall looks quiet)
        }
        let s = &mut self.rcvlock[i];
        let Some(bits) = net::buf_lock(fd) else {
            s.state = FOREIGN;
            self.stats.rcvlock_errors.bump();
            return;
        };
        if bits & net::RCVBUF_LOCK != 0 {
            s.state = FOREIGN; // locked by someone else (a cap kept at a lift without a floor): not ours to lift
            return;
        }
        // lock first, then read the size: the kernel can grow an unlocked buffer at any time (DRS in our reads,
        // tcp_clamp_window in softirq), so a size read before the lock could be stale and a raise to it a shrink
        if !net::set_buf_lock(fd, bits | net::RCVBUF_LOCK) {
            s.state = FOREIGN;
            self.stats.rcvlock_errors.bump();
            return;
        }
        (s.state, s.caps) = (LOCKED, caps);
        self.stats.rcvlock_locks.bump();
        let floor = self.cfg.park_rcvlock as i32;
        if let Some(size) = net::rcvbuf(fd).filter(|&v| v < floor) {
            // below the floor: raise it (clamped to 2 x rmem_max; main sized the floor from it, but a smaller rmem_max set
            // at runtime would make this a shrink: counted as an error)
            if !net::set_rcvbuf(fd, floor) || net::rcvbuf(fd).is_none_or(|v| v < size) {
                self.stats.rcvlock_errors.bump();
            }
        }
    }

    /// the resumed target read without parking again: lift our lock (only SOCK_RCVBUF_LOCK; FOREIGN: forget it, the next
    /// repark looks again). A failed unlock keeps LOCKED: the next unparked resume tries again
    fn rcvlock_lift(&mut self, ti: u32, tg: u32) {
        let Some(s) = self.rcvlock.get_mut(ti as usize) else { return };
        if s.g1 != tg.wrapping_add(1) || s.state == UNLOCKED {
            return;
        }
        if s.state == FOREIGN {
            s.state = UNLOCKED;
            return;
        }
        if self.st.sock_cap != 0 {
            return; // a stage caps sockets: keep it until that is over (the caps may own the bits now)
        }
        // (sock_cap == 0 happens only without a memory floor, whose caps episodes end in uncap_bufs: a bit still set is ours)
        let fd = self.targets.at(ti).fd;
        let ok = match net::buf_lock(fd) {
            Some(b) if b & net::RCVBUF_LOCK == 0 => true, // uncap_bufs cleared it already
            Some(b) => net::set_buf_lock(fd, b & !net::RCVBUF_LOCK),
            None => false,
        };
        let s = &mut self.rcvlock[ti as usize];
        if ok {
            s.state = UNLOCKED;
        } else {
            self.stats.rcvlock_errors.bump();
        }
    }
}
