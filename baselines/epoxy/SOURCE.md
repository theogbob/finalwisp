# epoxy-server baseline
Source: https://github.com/MercuryWorkshop/epoxy-tls, server/ (default branch "multiplexed"). Upstream checked 2026-11-16 15:45Z (git ls-remote, GitHub API, npm view, PyPI JSON) for 60.78 G02 (bench/showpair.py).
- `epoxy` = **9cde724** (2026-10-22, multiplexed = tag "latest"; unchanged since 60.71). Built as its README says
  (`cargo b -r`, its own Cargo.lock: tokio-websockets 0.12.0); built with `cargo build --release --locked -p epoxy-server`,
  rustc 1.100.0-nightly; md5 8ed88c23. tokio-websockets 0.12.0 panics (src/proto/stream.rs:152, 64-entry IoSlice array)
  when 32+ frames are queued and the whole server exits (60.71 "epoxy-server: which build is as it ships").
- `epoxy-9cde724-lock0123` = the same commit with one lock change, `cargo update -p tokio-websockets --precise 0.12.3`
  (does not crash); md5 b3281c54. Both columns are kept (60.71).
Build logs: raw data (not published) (main checkout).
