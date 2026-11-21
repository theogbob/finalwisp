//! 80.04 (pointer 30.01): `wbench run --edges`: counters read at the two edges of the measured window, so
//! that CPU per unit of work and the host state belong to exactly the window that the rates count (a server
//! sampled by the suite before and after the client also counts setup, warm-up and teardown).
//! Server: the cgroup of its transient unit (`--cpu-cgroup DIR`: cpu.stat usage / user / system usec) and/or its
//! processes (`--cpu-pids P,P`: on-CPU ns of every thread from schedstat + utime / stime ticks from stat).
//! Client: this process (getrusage). Host: the cpu line of /proc/stat (ticks), TcpExt TCPMemoryPressures(+Chrono),
//! the TCP memory pages of sockstat.
use std::collections::HashMap;
use std::time::Instant;

pub struct Cfg {
    pub cgroup: Option<String>,
    pub pids: Vec<u32>,
}

pub struct Edge {
    /// the middle of the reads (they take tens to hundreds of us); `read_us` = how long they took
    pub t: Instant,
    pub read_us: u64,
    pub cg: Option<[u64; 3]>,
    /// on-CPU ns per thread (pid, tid) of the server pids
    pub sched: Option<HashMap<(u32, String), u64>>,
    pub ticks: Option<[u64; 2]>,
    pub cli: [u64; 2],
    pub host: Option<[u64; 8]>,
    pub press: Option<[u64; 2]>,
    pub tcp_mem: Option<u64>,
}

fn read(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn cgroup(dir: &str) -> Option<[u64; 3]> {
    let s = read(&format!("{}/cpu.stat", dir.trim_end_matches('/')))?;
    let mut v = [None; 3];
    for l in s.lines() {
        let mut it = l.split_whitespace();
        let (Some(k), Some(x)) = (it.next(), it.next()) else { continue };
        let i = match k {
            "usage_usec" => 0,
            "user_usec" => 1,
            "system_usec" => 2,
            _ => continue,
        };
        v[i] = x.parse::<u64>().ok();
    }
    Some([v[0]?, v[1]?, v[2]?])
}

/// on-CPU ns of every thread of every pid (schedstat field 1), and utime + stime ticks of the processes (stat: these
/// include threads that have exited)
type Sched = HashMap<(u32, String), u64>;
fn pids(p: &[u32]) -> (Option<Sched>, Option<[u64; 2]>) {
    let (mut m, mut ut, mut st, mut ok) = (HashMap::new(), 0u64, 0u64, false);
    for pid in p {
        if let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/task")) {
            for e in rd.flatten() {
                let tid = e.file_name().to_string_lossy().to_string();
                if let Some(s) = read(&format!("/proc/{pid}/task/{tid}/schedstat")) {
                    if let Some(ns) = s.split_whitespace().next().and_then(|x| x.parse::<u64>().ok()) {
                        m.insert((*pid, tid), ns);
                        ok = true;
                    }
                }
            }
        }
        if let Some(s) = read(&format!("/proc/{pid}/stat")) {
            if let Some(i) = s.rfind(')') {
                let f: Vec<&str> = s[i + 1..].split_whitespace().collect();
                ut += f.get(11).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
                st += f.get(12).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
            }
        }
    }
    if ok { (Some(m), Some([ut, st])) } else { (None, None) }
}

fn rusage_self() -> [u64; 2] {
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) };
    let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    [us(r.ru_utime), us(r.ru_stime)]
}

/// user nice system idle iowait irq softirq steal (ticks)
fn host_cpu() -> Option<[u64; 8]> {
    let s = read("/proc/stat")?;
    let l = s.lines().next()?;
    let v: Vec<u64> = l.split_whitespace().skip(1).take(8).filter_map(|x| x.parse().ok()).collect();
    (v.len() == 8).then(|| [v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]])
}

fn pressure() -> Option<[u64; 2]> {
    let s = read("/proc/net/netstat")?;
    let l: Vec<&str> = s.lines().filter(|l| l.starts_with("TcpExt:")).collect();
    if l.len() < 2 {
        return None;
    }
    let (k, v) = (l[0].split_whitespace(), l[1].split_whitespace());
    let (mut a, mut b) = (None, None);
    for (k, v) in k.zip(v) {
        match k {
            "TCPMemoryPressures" => a = v.parse().ok(),
            "TCPMemoryPressuresChrono" => b = v.parse().ok(),
            _ => {}
        }
    }
    Some([a?, b?])
}

fn tcp_mem() -> Option<u64> {
    let s = read("/proc/net/sockstat")?;
    let l = s.lines().find(|l| l.starts_with("TCP:"))?;
    let x: Vec<&str> = l.split_whitespace().collect();
    x.iter().position(|k| *k == "mem").and_then(|i| x.get(i + 1)).and_then(|v| v.parse().ok())
}

pub fn sample(c: &Cfg) -> Edge {
    let t0 = Instant::now();
    let cg = c.cgroup.as_deref().and_then(cgroup);
    let (sched, ticks) = if c.pids.is_empty() { (None, None) } else { pids(&c.pids) };
    let cli = rusage_self();
    let host = host_cpu();
    let (press, tcp_mem) = (pressure(), tcp_mem());
    let w = t0.elapsed();
    Edge { t: t0 + w / 2, read_us: w.as_micros() as u64, cg, sched, ticks, cli, host, press, tcp_mem }
}

/// 80.04: refuse at the start what would leave the server's CPU out silently (a wrong cgroup path, a dead pid)
pub fn check(c: &Cfg) -> Result<(), String> {
    if let Some(d) = &c.cgroup {
        cgroup(d).ok_or_else(|| format!("--cpu-cgroup {d}: no readable cpu.stat with usage_usec, user_usec, system_usec"))?;
    }
    for pid in &c.pids {
        if pids(&[*pid]).0.is_none() {
            return Err(format!("--cpu-pids: pid {pid} has no readable thread schedstat"));
        }
    }
    Ok(())
}

/// JSON object of the window between two edges; `due` = the intended times of the two samples (lateness in us).
pub fn json(a: &Edge, b: &Edge, due: (Instant, Instant)) -> String {
    let dt = b.t.duration_since(a.t).as_secs_f64();
    let late = |e: &Edge, d: Instant| e.t.saturating_duration_since(d).as_micros();
    let mut s = format!(
        "{{\"dt_s\":{dt:.6},\"late0_us\":{},\"late1_us\":{},\"read_us\":{}",
        late(a, due.0),
        late(b, due.1),
        a.read_us.max(b.read_us)
    );
    if let (Some(x), Some(y)) = (a.cg, b.cg) {
        if y[0] >= x[0] {
            s.push_str(&format!(",\"srv_cg_us\":{},\"srv_cg_user_us\":{},\"srv_cg_sys_us\":{}", y[0] - x[0], y[1].saturating_sub(x[1]), y[2].saturating_sub(x[2])));
        } // a counter that went back (the cgroup was made again): no server CPU for this window
    }
    if let (Some(x), Some(y)) = (&a.sched, &b.sched) {
        // per thread: the change of the threads seen at both edges, the whole count of new ones; threads that exited
        // in the window took their time with them: counted in srv_sched_lost_threads (then use the stat ticks)
        let sum: u64 = y.iter().map(|(k, v)| v.saturating_sub(x.get(k).copied().unwrap_or(0))).sum();
        let lost = x.keys().filter(|k| !y.contains_key(*k)).count();
        s.push_str(&format!(",\"srv_sched_ns\":{sum},\"srv_sched_lost_threads\":{lost}"));
    }
    if let (Some(x), Some(y)) = (a.ticks, b.ticks) {
        s.push_str(&format!(",\"srv_utime\":{},\"srv_stime\":{}", y[0].saturating_sub(x[0]), y[1].saturating_sub(x[1])));
    }
    s.push_str(&format!(",\"cli_user_us\":{},\"cli_sys_us\":{}", b.cli[0].saturating_sub(a.cli[0]), b.cli[1].saturating_sub(a.cli[1])));
    if let (Some(x), Some(y)) = (a.host, b.host) {
        let n = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"];
        s.push_str(",\"host\":{");
        for i in 0..8 {
            s.push_str(&format!("{}\"{}\":{}", if i > 0 { "," } else { "" }, n[i], y[i].saturating_sub(x[i])));
        }
        s.push('}');
    }
    if let (Some(x), Some(y)) = (a.press, b.press) {
        s.push_str(&format!(",\"tcp_press\":{},\"tcp_press_ms\":{}", y[0].saturating_sub(x[0]), y[1].saturating_sub(x[1])));
    }
    if let (Some(x), Some(y)) = (a.tcp_mem, b.tcp_mem) {
        s.push_str(&format!(",\"tcp_mem\":[{x},{y}]"));
    }
    s.push('}');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_sample_reads_proc_and_counts_own_cpu() {
        let me = std::process::id();
        let c = Cfg { cgroup: None, pids: vec![me] };
        let a = sample(&c);
        let mut x = 0u64;
        for i in 0..20_000_000u64 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(i);
        }
        std::hint::black_box(x);
        let b = sample(&c);
        let tot = |e: &Edge| e.sched.as_ref().unwrap().values().sum::<u64>();
        assert!(tot(&b) > tot(&a));
        assert!(check(&c).is_ok());
        assert!(check(&Cfg { cgroup: Some("/nonexistent".into()), pids: vec![] }).is_err());
        let j = json(&a, &b, (a.t, b.t)); // lost threads may be > 0: the other tests' threads exit meanwhile
        assert!(j.contains("\"srv_sched_ns\":") && j.contains("\"srv_sched_lost_threads\":") && j.contains("\"cli_user_us\":") && j.contains("\"host\":{\"user\":"), "{j}");
    }
}
