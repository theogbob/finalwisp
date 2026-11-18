//! Test support (60.74 4.5, the timing tests that fail under load): the host's scheduling lag, measured while a case
//! runs. A probe thread sleeps 1 ms in a loop and keeps the largest overshoot. A timing bound of a test is then
//! `base + hops x lag` (a chain of `hops` thread wakeups, each late by at most about the lag the probe saw), and a
//! case whose outcome depends on a deadline (an answer before a window ends) is judged only on a run in which the lag
//! stayed below what the case tolerates; else it runs again ([`judged`]). On a quiet host the lag is a few tens of
//! microseconds, so the bounds are the old ones.
use std::sync::atomic::{
    AtomicBool, AtomicU64,
    Ordering::{Acquire, Relaxed, Release},
};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Lag {
    stop: Arc<AtomicBool>,
    max_us: Arc<AtomicU64>,
    /// the start of the probe's current sleep, us after `base` (a stall that is still under way counts in `max`)
    cur_us: Arc<AtomicU64>,
    base: Instant,
    h: Option<std::thread::JoinHandle<()>>,
}

impl Lag {
    pub fn start() -> Lag {
        let (stop, max_us, cur_us, base) =
            (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)), Instant::now());
        let (s, m, c) = (stop.clone(), max_us.clone(), cur_us.clone());
        let h = std::thread::spawn(move || {
            while !s.load(Relaxed) {
                let t = Instant::now();
                // (Release: a reader that sees this start also sees the maximum of the sleep before it)
                c.store(t.duration_since(base).as_micros() as u64, Release);
                std::thread::sleep(Duration::from_millis(1));
                let over = t.elapsed().saturating_sub(Duration::from_millis(1));
                m.fetch_max(over.as_micros() as u64, Relaxed);
            }
        });
        // (the probe runs before the case starts: a lag at the case's first step is seen)
        std::thread::sleep(Duration::from_millis(2));
        Lag { stop, max_us, cur_us, base, h: Some(h) }
    }

    /// the largest overshoot of a 1 ms sleep since start (or the last reset), the probe's current sleep included (a case
    /// that wakes from the same stall as the probe reads it before the probe has run again), plus the probe's own 1 ms
    pub fn max(&self) -> Duration {
        // (the start first: a sleep that ended between the two loads is then in the maximum, Acquire / Release)
        let start = self.cur_us.load(Acquire);
        let cur = (self.base.elapsed().as_micros() as u64).saturating_sub(start).saturating_sub(1000);
        Duration::from_micros(self.max_us.load(Relaxed).max(cur)) + Duration::from_millis(1)
    }

    pub fn reset(&self) {
        self.max_us.store(0, Relaxed);
    }

    /// `base` plus `hops` times the lag seen so far
    pub fn bound(&self, base: Duration, hops: u32) -> Duration {
        base + self.max() * hops
    }
}

impl Drop for Lag {
    fn drop(&mut self) {
        self.stop.store(true, Relaxed);
        if let Some(h) = self.h.take() {
            let _ = h.join();
        }
    }
}

/// Runs `case` (a fresh lag meter each run). A run that passes is the result. A run that fails while the host lag was
/// above `tol` (what the case's deadlines tolerate) is no judgement of the case: its failure is printed with the lag
/// and the case runs again, at most `tries` runs. A failure with the lag at or below `tol` is the case's failure (at
/// once), and so is the last run's failure (a host too busy to judge is a loud failure, never a pass).
pub fn judged<T>(what: &str, tol: Duration, tries: u32, mut case: impl FnMut(&Lag) -> T) -> T {
    for i in 1..=tries {
        let lag = Lag::start();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| case(&lag))) {
            Ok(r) => return r,
            Err(e) => {
                let m = lag.max();
                if m <= tol || i == tries {
                    eprintln!("{what}: failed in run {i} with a host lag of {m:?} (tolerance {tol:?})");
                    std::panic::resume_unwind(e);
                }
                eprintln!("{what}: run {i} failed with a host lag of {m:?}, above {tol:?}: not a judgement, again");
            }
        }
    }
    unreachable!("tries >= 1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lag_sees_a_stalled_thread_and_judged_retries() {
        let lag = Lag::start();
        std::thread::sleep(Duration::from_millis(20));
        assert!(lag.max() < Duration::from_secs(5));
        assert_eq!(lag.bound(Duration::from_millis(10), 0), Duration::from_millis(10));
        // a failure above the tolerance runs again (max() adds the probe's own 1 ms: a tolerance of 0 is always exceeded),
        // up to `tries`; a failure within the tolerance fails at once; a pass is the result
        let mut n = 0;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            judged("t", Duration::ZERO, 3, |_| {
                n += 1;
                assert!(n == 0)
            })
        }));
        assert!(r.is_err() && n == 3, "{n}");
        let mut n = 0;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            judged("t", Duration::from_secs(5), 3, |_| {
                n += 1;
                assert!(n == 0)
            })
        }));
        assert!(r.is_err() && n == 1, "{n}");
        let mut n = 0;
        assert_eq!(
            judged("t", Duration::ZERO, 3, |_| {
                n += 1;
                if n < 2 {
                    panic!("first")
                }
                7
            }),
            7
        );
    }
}
