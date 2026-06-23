#![no_main]

use libfuzzer_sys::fuzz_target;
use securefs_server::health::parse_request_target;

// parse_request_target runs on raw, unauthenticated bytes straight off the
// health socket. It must never panic, and its result is a borrow into the
// input, so the returned slice can never be longer than the bytes fed in.
fuzz_target!(|data: &[u8]| {
    let target = parse_request_target(data);
    assert!(target.len() <= data.len());
});
