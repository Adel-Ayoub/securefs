#![no_main]

use libfuzzer_sys::fuzz_target;
use securefs_proto::cmd::{MapStr, NumArgs};
use securefs_proto::protocol::{AppMessage, Cmd};

// Command parsing runs on attacker-controlled bytes off the wire. The string ->
// Cmd mapping and the arity lookup must reject unknown input with Err, and the
// JSON envelope decode (Cmd + args) must reject malformed frames with Err -
// never a panic, on any input.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = <Cmd as MapStr>::from_str(s.to_string());
        let _ = <Cmd as NumArgs>::num_args(s.to_string());
        let _ = serde_json::from_str::<AppMessage>(s);
    }
});
