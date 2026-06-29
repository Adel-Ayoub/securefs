#![no_main]

use libfuzzer_sys::fuzz_target;
use securefs_server_core::crypto;

// The stored wrapped-DEK parser must tolerate any bytes the database hands back.
// wrapped_generation reads the length prefix; unwrap_with_master runs the length
// split then an AES-256-GCM unwrap under a caller-supplied master. Arbitrary
// master and wrapped bytes must yield Err/None, never a panic.
fuzz_target!(|data: &[u8]| {
    let _ = crypto::wrapped_generation(data);
    if !data.is_empty() {
        let (master, wrapped) = data.split_at(data.len() / 2);
        let _ = crypto::unwrap_with_master(wrapped, master);
    }
});
