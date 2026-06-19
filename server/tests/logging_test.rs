// A structured JSON log line is valid JSON with the expected fields, stays on a
// single line, and escapes special characters in the message.

use securefs_server::logging::log_json;

#[test]
fn json_line_is_valid_with_fields() {
    let line = log_json(
        1_718_800_000_000,
        "INFO",
        "securefs_server::main",
        "started \"ok\"\nnext",
    );
    let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
    assert_eq!(v["ts_ms"], 1_718_800_000_000u64);
    assert_eq!(v["level"], "INFO");
    assert_eq!(v["target"], "securefs_server::main");
    assert_eq!(v["msg"], "started \"ok\"\nnext");
    assert_eq!(line.lines().count(), 1, "must be one line: {}", line);
}
