use std::time::{SystemTime, UNIX_EPOCH};

// Initialize the global logger. Default level is info (overridable via RUST_LOG).
// LOG_FORMAT=json emits one structured JSON object per line for log aggregation;
// otherwise the human-readable env_logger format is used.
pub fn init() {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    if std::env::var("LOG_FORMAT").ok().as_deref() == Some("json") {
        builder.format(|buf, record| {
            use std::io::Write;
            let ts_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            writeln!(
                buf,
                "{}",
                log_json(
                    ts_ms,
                    record.level().as_str(),
                    record.target(),
                    &record.args().to_string()
                )
            )
        });
    }
    builder.init();
}

// One compact JSON log line. Kept separate from init() so the formatting is unit
// testable without touching the process-global logger.
pub fn log_json(ts_ms: u64, level: &str, target: &str, msg: &str) -> String {
    serde_json::json!({
        "ts_ms": ts_ms,
        "level": level,
        "target": target,
        "msg": msg,
    })
    .to_string()
}
