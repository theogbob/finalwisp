//! 80.04 (pointer 30.01): per-message latency for `wbench run --lat` / `--rate`: HDR histograms in ns with
//! exact count, sum and max, exported as buckets so that runs merge exactly without storing samples; the open-loop
//! arrival schedule (`--rate`, fixed or Poisson gaps) and a timerfd timer (tokio timers round up to 1 ms, too coarse
//! for an offered rate of thousands of messages per second).
use hdrhistogram::Histogram;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;

/// Largest recorded value: 10 s. A larger value is recorded as 10 s and counted in `sat`.
pub const MAX_NS: u64 = 10_000_000_000;

/// One latency distribution: HDR histogram (1 ns .. 10 s, 3 significant digits) + exact count, sum, max.
pub struct Dist {
    pub h: Histogram<u64>,
    pub sum: u128,
    pub max: u64,
    pub sat: u64,
}

impl Dist {
    pub fn new() -> Self {
        Dist { h: Histogram::new_with_bounds(1, MAX_NS, 3).expect("histogram"), sum: 0, max: 0, sat: 0 }
    }
    /// The histogram holds at most MAX_NS (a larger value is recorded as MAX_NS and counted in `sat`); `sum` and
    /// `max` stay exact over all values.
    #[inline]
    pub fn rec(&mut self, d: Duration) {
        let v = (d.as_nanos().min(u64::MAX as u128) as u64).max(1);
        if v > MAX_NS {
            self.sat += 1;
        }
        self.h.saturating_record(v.min(MAX_NS));
        self.sum += v as u128;
        self.max = self.max.max(v);
    }
    pub fn add(&mut self, o: &Dist) {
        let _ = self.h.add(&o.h);
        self.sum += o.sum;
        self.max = self.max.max(o.max);
        self.sat += o.sat;
    }
    pub fn n(&self) -> u64 {
        self.h.len()
    }
    /// {"n","sum","mean","p50","p90","p99","p999","max","sat"} in ns (sum, mean and max exact, percentiles the
    /// bucket's highest equivalent value), plus "b": [[value, count], ...] for every non-empty bucket when `buckets`.
    pub fn json(&self, buckets: bool) -> String {
        let n = self.n();
        let q = |x: f64| if n == 0 { 0 } else { self.h.value_at_quantile(x) };
        let mean = if n == 0 { 0.0 } else { self.sum as f64 / n as f64 };
        let mut s = format!(
            "{{\"n\":{n},\"sum\":{},\"mean\":{mean:.1},\"p50\":{},\"p90\":{},\"p99\":{},\"p999\":{},\"max\":{},\"sat\":{}",
            self.sum,
            q(0.50),
            q(0.90),
            q(0.99),
            q(0.999),
            self.max,
            self.sat
        );
        if buckets {
            s.push_str(",\"b\":[");
            let mut first = true;
            for v in self.h.iter_recorded() {
                if !first {
                    s.push(',');
                }
                first = false;
                s.push_str(&format!("[{},{}]", v.value_iterated_to(), v.count_at_value()));
            }
            s.push(']');
        }
        s.push('}');
        s
    }
}

/// Open-loop arrivals of one connection: `rate` per second from `start`, fixed gaps or exponential (Poisson) gaps.
/// Times are offsets from `start` in f64 seconds (no drift from summing rounded Durations).
pub struct Sched {
    start: Instant,
    gap: f64,
    poisson: bool,
    rng: u64,
    t: f64,
    next: Instant,
}

impl Sched {
    /// phase in [0, 1): the first arrival is at start + phase * gap (connections are staggered)
    pub fn new(rate: f64, poisson: bool, seed: u64, start: Instant, phase: f64) -> Self {
        let mut s = Sched { start, gap: 1.0 / rate, poisson, rng: seed | 1, t: 0.0, next: start };
        s.t = if poisson { s.draw() * phase.max(0.0) } else { s.gap * phase };
        s.next = start + Duration::from_secs_f64(s.t);
        s
    }
    fn draw(&mut self) -> f64 {
        // xorshift64*, u in (0, 1]: -ln(u) * gap is an exponential gap with mean `gap`
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        let u = ((x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 + 1.0) / (1u64 << 53) as f64;
        -u.ln() * self.gap
    }
    #[inline]
    pub fn next(&self) -> Instant {
        self.next
    }
    /// -> the intended time of this arrival; moves to the next one
    pub fn advance(&mut self) -> Instant {
        let cur = self.next;
        self.t += if self.poisson { self.draw() } else { self.gap };
        self.next = self.start + Duration::from_secs_f64(self.t);
        cur
    }
}

/// A one-shot timerfd (CLOCK_MONOTONIC, absolute, ns) in tokio's reactor. Instant is CLOCK_MONOTONIC on Linux, so
/// an Instant maps to the clock through one (Instant, clock_gettime) pair taken at creation.
pub struct Timer {
    fd: AsyncFd<OwnedFd>,
    base: Instant,
    base_ns: u64,
    armed: Option<Instant>,
}

fn mono_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

impl Timer {
    pub fn new() -> io::Result<Self> {
        let raw = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // the (Instant, clock) pair: bracketed, retried when a preemption made the bracket wider than 20 us
        let (mut base, mut base_ns) = (Instant::now(), mono_ns());
        for _ in 0..10 {
            let t1 = Instant::now();
            let ns = mono_ns();
            let t2 = Instant::now();
            let w = t2.duration_since(t1);
            (base, base_ns) = (t1 + w / 2, ns);
            if w < Duration::from_micros(20) {
                break;
            }
        }
        // SAFETY: the OwnedFd is moved into the AsyncFd, so the descriptor stays open and the same for its lifetime
        let fd = unsafe { AsyncFd::register_with_interest(fd, tokio::io::Interest::READABLE) }?;
        Ok(Timer { fd, base, base_ns, armed: None })
    }
    /// Fire at `at` (at once if it has passed). Re-arming for the same time is a no-op.
    pub fn arm(&mut self, at: Instant) -> io::Result<()> {
        if self.armed == Some(at) {
            return Ok(());
        }
        let ns = self.base_ns + at.saturating_duration_since(self.base).as_nanos() as u64;
        let its = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: (ns / 1_000_000_000) as libc::time_t, tv_nsec: (ns % 1_000_000_000) as libc::c_long },
        };
        let r = unsafe { libc::timerfd_settime(self.fd.as_raw_fd(), libc::TFD_TIMER_ABSTIME, &its, std::ptr::null_mut()) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        self.armed = Some(at);
        Ok(())
    }
    /// Wait until the armed time has passed (the expiry count is read and dropped).
    pub async fn wait(&mut self) -> io::Result<()> {
        loop {
            let mut g = self.fd.readable().await?;
            let mut buf = [0u8; 8];
            match g.try_io(|f| {
                let n = unsafe { libc::read(f.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, 8) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
            }) {
                Ok(Ok(())) => {
                    self.armed = None;
                    return Ok(());
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

/// 80.04 --rate: timer slack of the calling thread (inherited by threads it creates) down to 1 ns, so the kernel
/// does not delay timerfd expiries by its default 50 us slack.
pub fn tight_timer_slack() {
    unsafe {
        libc::prctl(libc::PR_SET_TIMERSLACK, 1 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dist_exact_mean_max_and_buckets_merge() {
        let mut a = Dist::new();
        let mut b = Dist::new();
        for us in [10u64, 20, 30] {
            a.rec(Duration::from_micros(us));
        }
        b.rec(Duration::from_millis(5));
        a.add(&b);
        assert_eq!(a.n(), 4);
        assert_eq!(a.max, 5_000_000);
        assert_eq!(a.sum, 5_060_000);
        let j = a.json(true);
        assert!(j.contains("\"n\":4,\"sum\":5060000,\"mean\":1265000.0"), "{j}");
        assert!(j.contains("\"b\":[["), "{j}");
        // bucket counts sum to n
        let tot: u64 = a.h.iter_recorded().map(|v| v.count_at_value()).sum();
        assert_eq!(tot, 4);
    }

    #[test]
    fn dist_saturates_above_10_s() {
        let mut a = Dist::new();
        a.rec(Duration::from_secs(20));
        assert_eq!(a.sat, 1);
        assert_eq!(a.n(), 1);
        assert_eq!(a.max, 20_000_000_000); // exact max, the histogram holds 10 s
        assert!(a.h.max() <= MAX_NS + MAX_NS / 1000, "{}", a.h.max());
    }

    #[test]
    fn sched_fixed_rate_has_no_drift_and_poisson_mean_is_near_the_gap() {
        let t0 = Instant::now();
        let mut s = Sched::new(1000.0, false, 1, t0, 0.5);
        assert_eq!(s.next(), t0 + Duration::from_micros(500));
        for _ in 0..100_000 {
            s.advance();
        }
        let d = s.next().duration_since(t0).as_secs_f64();
        assert!((d - 100.0005).abs() < 1e-6, "{d}");
        let mut p = Sched::new(1000.0, true, 7, t0, 0.0);
        for _ in 0..200_000 {
            p.advance();
        }
        let m = p.next().duration_since(t0).as_secs_f64() / 200_000.0;
        assert!((m - 0.001).abs() < 0.00002, "{m}");
    }
}
