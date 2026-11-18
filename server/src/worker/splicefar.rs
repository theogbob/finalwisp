//! 60.78 --adaptive-splice: a client's far / near class (Worker::splice_far), read at its first need of rule B
//! (read_target: the flag, Client::splice SLOW, more than SPLICE_FEW streams), not at accept. v1.2.1 to v1.3.3 read
//! TCP_INFO (one getsockopt) for every accepted TCP connection; most connections never reach rule B, so a connection
//! that opens, sends a few frames and closes paid a syscall for nothing.
//!
//! tcpi_min_rtt is a windowed minimum (net.ipv4.tcp_min_rtt_wlen, 300 s by default). Inside that window a later read
//! is at most the handshake sample (more samples, same or lower), so a near client stays near; a client read as far
//! saw no sample under SPLICE_FAR_RTT_US. Once the window has passed it may hold only samples with queueing in them,
//! so a read then is not trusted: such a client is near (the v1.1.1 length, what --no-adaptive-splice gives) and
//! counted (Stats::splice_old). The class is kept for the life of the connection (one read at most).
//!
//! The age without per-connection work at accept: every AGE_PASS a pass (from idle_sweep, flag on) stamps each client
//! slot that has no entry for its generation with Worker::age_k, the number such that the client was accepted after
//! t0 + (age_k - 1) * AGE_PASS (t0: the first worker's start, shared). A client with no entry yet has age_k as its
//! stamp. A connection that moves takes its stamp or class along (mig_export / mig_import).
use super::*;
use std::sync::atomic::AtomicU32;
use std::sync::OnceLock;

/// Worker::splice_far values besides a stamp (stamps stay far below these)
pub(super) const FAR_NEAR: u32 = u32::MAX;
pub(super) const FAR_FAR: u32 = u32::MAX - 1;
/// the stamping pass period
pub(super) const AGE_PASS: Duration = Duration::from_secs(30);
/// a read is trusted only for a connection younger than the kernel's window minus this (a pass that runs late: one
/// loop turn; a connection that moves while its two workers' passes are due)
const AGE_MARGIN: Duration = Duration::from_secs(30);

static T0: OnceLock<Instant> = OnceLock::new();
/// net.ipv4.tcp_min_rtt_wlen in seconds (main reads it at start; the kernel default until then)
static WLEN_S: AtomicU32 = AtomicU32::new(300);

/// main at start, with adaptive splice in effect: the kernel's min RTT window (read from /proc; None keeps 300 s)
pub(crate) fn set_rtt_wlen(s: Option<u32>) {
    if let Some(s) = s {
        WLEN_S.store(s, Relaxed);
    }
}

/// the shared start of the stamps
pub(super) fn t0() -> Instant {
    *T0.get_or_init(Instant::now)
}

/// Worker::new: the stamp of the clients it takes before its first pass (all come after its start)
pub(super) fn first_k() -> u32 {
    (t0().elapsed().as_secs() / AGE_PASS.as_secs()) as u32 + 1
}

/// The class of a client at its first need of rule B
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Class {
    Near,
    Far,
    /// past the kernel's window: not read, treated as near
    Old,
}

/// The rule (pure, for the tests' clock): `k` = the client's stamp, `since` = now - t0, `wlen` = the kernel's window,
/// `rtt` = the read (called only for a young connection)
pub(super) fn first_class(k: u32, since: Duration, wlen: Duration, rtt: impl FnOnce() -> Option<u32>) -> Class {
    let accepted_after = AGE_PASS * k.saturating_sub(1);
    if since.saturating_sub(accepted_after) + AGE_MARGIN >= wlen {
        return Class::Old;
    }
    if rtt().is_some_and(|r| r >= SPLICE_FAR_RTT_US) {
        Class::Far
    } else {
        Class::Near
    }
}

impl Worker {
    /// rule B's last condition (read_target): is this client far? Classified at the first call for the connection.
    #[inline]
    pub(super) fn splice_is_far(&mut self, ci: u32) -> bool {
        let tag = self.clients.gen(ci).wrapping_add(1);
        match self.splice_far.get(ci as usize) {
            Some(&(t, v)) if t == tag && v >= FAR_FAR => v == FAR_FAR,
            _ => self.splice_classify(ci, tag),
        }
    }

    /// the client's stamp or class (its entry, else the stamp the next pass gives it)
    fn splice_entry(&self, ci: u32, tag: u32) -> u32 {
        match self.splice_far.get(ci as usize) {
            Some(&(t, v)) if t == tag => v,
            _ => self.age_k,
        }
    }

    #[cold]
    #[inline(never)]
    fn splice_classify(&mut self, ci: u32, tag: u32) -> bool {
        let k = self.splice_entry(ci, tag);
        let c = self.clients.at(ci);
        let (fd, unix) = (c.fd, c.local == LOCAL_UNIX);
        let wlen = Duration::from_secs(WLEN_S.load(Relaxed) as u64);
        let class = if unix {
            Class::Near // no TCP RTT
        } else {
            first_class(k, self.now.saturating_duration_since(t0()), wlen, || net::min_rtt_us(fd))
        };
        let v = match class {
            Class::Near => {
                self.stats.splice_near.bump();
                FAR_NEAR
            }
            Class::Far => {
                self.stats.splice_far.bump();
                FAR_FAR
            }
            Class::Old => {
                self.stats.splice_old.bump();
                FAR_NEAR
            }
        };
        self.splice_set(ci, tag, v);
        v == FAR_FAR
    }

    fn splice_set(&mut self, ci: u32, tag: u32, v: u32) {
        let i = ci as usize;
        if self.splice_far.len() <= i {
            self.splice_far.resize(i + 1, (0, 0));
        }
        self.splice_far[i] = (tag, v);
    }

    /// The stamping pass (idle_sweep, every AGE_PASS with the flag on; `now`: the turn's time)
    #[cold]
    #[inline(never)]
    pub(super) fn splice_age_pass(&mut self, now: Instant) {
        let t0 = t0();
        let e = (now.saturating_duration_since(t0).as_secs() / AGE_PASS.as_secs()) as u32;
        let (k, n) = (self.age_k, self.clients.slots.len());
        if self.splice_far.len() < n {
            self.splice_far.resize(n, (0, 0));
        }
        for (i, (g, slot)) in self.clients.slots.iter().enumerate() {
            let tag = g.wrapping_add(1);
            if slot.is_some() && self.splice_far[i].0 != tag {
                self.splice_far[i] = (tag, k);
            }
        }
        // clients that have no entry after this pass came after it (now >= t0 + e * AGE_PASS)
        self.age_k = self.age_k.max(e + 1);
        self.age_pass_at = t0 + AGE_PASS * self.age_k;
    }

    /// mig_export: what a moving connection takes along (its slot is still its own)
    pub(super) fn splice_out(&self, ci: u32) -> u32 {
        self.splice_entry(ci, self.clients.gen(ci).wrapping_add(1))
    }

    /// mig_import: the moved connection's stamp or class in its new slot
    pub(super) fn splice_in(&mut self, ci: u32, cg: u32, v: u32) {
        if self.cfg.adaptive_splice {
            self.splice_set(ci, cg.wrapping_add(1), v);
        }
    }
}
