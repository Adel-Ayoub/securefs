// Metrics render in Prometheus text format with the expected names and values.

use securefs_server_core::metrics::Metrics;
use std::sync::atomic::Ordering;

#[test]
fn render_exposes_counters() {
    let m = Metrics::default();
    m.connections_total.fetch_add(3, Ordering::Relaxed);
    m.connections_active.fetch_add(2, Ordering::Relaxed);

    let out = m.render();
    assert!(
        out.contains("# TYPE securefs_connections_total counter"),
        "{}",
        out
    );
    assert!(out.contains("securefs_connections_total 3"), "{}", out);
    assert!(out.contains("securefs_connections_active 2"), "{}", out);
    assert!(
        out.contains("securefs_connections_rejected_total 0"),
        "{}",
        out
    );
}
