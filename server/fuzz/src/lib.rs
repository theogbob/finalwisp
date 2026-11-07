//! 70.01 The finalwisp server modules, compiled as a library for the fuzz targets. The sources are the
//! server's own files (#[path]), unchanged; worker/mod.rs adds `fuzz_hooks` under --cfg fuzzing only.
#![allow(dead_code, unused_imports, clippy::all)]
#![feature(linkage)] // 70.27 weak LSan symbols (pool.rs lsan, lsan_pool_check)
#[path = "../../src/cli.rs"]
pub mod cli;
#[path = "../../src/clientip.rs"]
pub mod clientip;
#[path = "../../src/credit.rs"]
pub mod credit;
#[path = "../../src/destrate.rs"]
pub mod destrate; // 60.39
#[path = "../../src/dns.rs"]
pub mod dns;
#[path = "../../src/ext.rs"]
pub mod ext;
#[path = "../../src/http.rs"]
pub mod http;
#[path = "../../src/logs.rs"]
pub mod logs;
#[path = "../../src/mem.rs"]
pub mod mem;
#[path = "../../src/metrics.rs"]
pub mod metrics;
#[path = "../../src/net.rs"]
pub mod net;
#[path = "../../src/policy.rs"]
pub mod policy;
#[path = "../../src/pool.rs"]
pub mod pool;
#[path = "../../src/proxyproto.rs"]
pub mod proxyproto; // 60.34
#[path = "../../src/tls.rs"]
pub mod tls;
#[path = "../../src/upstream.rs"]
pub mod upstream; // 60.32 C6
#[path = "../../src/worker/mod.rs"]
pub mod worker;
#[path = "../../src/ws.rs"]
pub mod ws;

/// 70.25 with the pool the targets run on finalwisp's own allocator, the harness thread is a pool
/// thread (worker_hooks Harness::new) and pool-ops runs the pool's model test
#[global_allocator]
static ALLOC: mem::Counting = mem::Counting;
