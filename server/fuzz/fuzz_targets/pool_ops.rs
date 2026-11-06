#![no_main]
//! 70.25 4.2 the pool's model test over input-chosen op sequences: 2 pool threads + 1 foreign thread, random
//! alloc / alloc_zeroed / realloc / free / release / sweep, blocks handed between threads, shadow-checked
//! (pool::model::stress).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    finalwisp_fuzz::pool::model::stress(data, 64 + data.len().min(4096) / 2);
});
