#![no_main]

use libfuzzer_sys::fuzz_target;
use securefs_channel::secure_channel::{Role, SecureChannel};

// open() parses an attacker-controlled wire frame: outer JSON -> hex-decode ->
// AES-256-GCM decrypt -> inner JSON. Every layer must reject malformed input
// with an Err, never a panic. The key is fixed and unknown to the fuzzer, so
// this exercises the parser/auth path on arbitrary bytes (forgery is not the
// goal); the invariant under test is "no input makes open() panic".
fuzz_target!(|data: &[u8]| {
    if let Ok(wire) = std::str::from_utf8(data) {
        let mut channel = SecureChannel::new(&[0u8; 32], Role::Server);
        let _ = channel.open(wire);
    }
});
