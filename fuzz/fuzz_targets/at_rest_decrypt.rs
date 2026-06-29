#![no_main]

use libfuzzer_sys::fuzz_target;
use securefs_server_core::crypto;

// decrypt_file_content runs on stored ciphertext: a version byte then an
// (optionally chunked) AEAD body, with an optional wrapped DEK. The version
// dispatch, the chunk-length parser, and the AEAD/DEK unwrap all see
// attacker-influenced bytes, so every malformed blob must surface as Err, never
// a panic. The master falls back to a fixed dev key, so forgery is not the goal;
// the invariant under test is "no input makes decrypt panic".
fuzz_target!(|data: &[u8]| {
    let _ = crypto::decrypt_file_content(data, None);
    // 61 bytes = generation(1) || nonce(12) || ciphertext+tag(48): a stored
    // DEK's on-disk length, so the envelope and chunked arms reach the real
    // unwrap path instead of bailing on a bad wrapped-DEK length.
    if data.len() >= 61 {
        let (wrapped, body) = data.split_at(61);
        let _ = crypto::decrypt_file_content(body, Some(wrapped));
    }
});
