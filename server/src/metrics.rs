use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// Process-wide counters shared between the accept loop (writers) and the
// /metrics endpoint (reader). Relaxed ordering is fine: each is an independent
// counter, not a guard for other state.
#[derive(Default)]
pub struct Metrics {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub connections_rejected_total: AtomicU64,
}

pub type SharedMetrics = Arc<Metrics>;

impl Metrics {
    // Prometheus text exposition format.
    pub fn render(&self) -> String {
        format!(
            "# HELP securefs_connections_total Total WebSocket connections accepted.\n\
             # TYPE securefs_connections_total counter\n\
             securefs_connections_total {}\n\
             # HELP securefs_connections_active Currently active WebSocket connections.\n\
             # TYPE securefs_connections_active gauge\n\
             securefs_connections_active {}\n\
             # HELP securefs_connections_rejected_total Connections refused at capacity.\n\
             # TYPE securefs_connections_rejected_total counter\n\
             securefs_connections_rejected_total {}\n",
            self.connections_total.load(Ordering::Relaxed),
            self.connections_active.load(Ordering::Relaxed),
            self.connections_rejected_total.load(Ordering::Relaxed),
        )
    }
}
