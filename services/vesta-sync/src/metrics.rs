//! vesta-sync metrics: the shared `HttpMetrics` core (requests/latency/inflight + their
//! Prometheus format, in `vesta-transport`) plus vesta-sync's own domain series (ops
//! accepted/deduped, live-tail subscribers). Exposed on a **loopback-only** listener — op/device
//! counts are exactly the metadata the at-rest model protects. `std` + atomics, no extra crates.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use vesta_transport::http::HttpMetrics;

/// Prometheus series prefix (`vault_sync_*`).
const PREFIX: &str = "vault_sync";

#[derive(Default)]
pub struct Metrics {
    http: HttpMetrics,
    ops_accepted: AtomicU64,
    ops_duplicate: AtomicU64,
}

impl Metrics {
    /// Record one served request (delegates to the shared http core).
    pub fn record_request(&self, route: &str, method: &str, status: u16, dur: Duration) {
        self.http.record_request(route, method, status, dur);
    }

    /// Adjust the in-flight gauge.
    pub fn inflight_add(&self, delta: i64) {
        self.http.inflight_add(delta);
    }

    /// Account a completed push's accepted + duplicate op counts.
    pub fn add_ops(&self, accepted: u64, duplicate: u64) {
        self.ops_accepted.fetch_add(accepted, Ordering::Relaxed);
        self.ops_duplicate.fetch_add(duplicate, Ordering::Relaxed);
    }

    /// Render the full exposition: the shared `vault_sync_http_*` series plus vesta-sync's
    /// domain series. `tail_subscribers` is the live gauge (computed by the caller at scrape).
    #[must_use]
    pub fn render(&self, tail_subscribers: u64) -> String {
        use std::fmt::Write as _;
        let mut out = self.http.render(PREFIX);
        let _ = writeln!(
            out,
            "# HELP {PREFIX}_tail_subscribers Active live-tail WebSocket subscribers.\n# TYPE {PREFIX}_tail_subscribers gauge\n{PREFIX}_tail_subscribers {tail_subscribers}"
        );
        let _ = writeln!(
            out,
            "# HELP {PREFIX}_ops_accepted_total Ops newly stored by push.\n# TYPE {PREFIX}_ops_accepted_total counter\n{PREFIX}_ops_accepted_total {}",
            self.ops_accepted.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP {PREFIX}_ops_duplicate_total Ops deduped by push (op_id seen).\n# TYPE {PREFIX}_ops_duplicate_total counter\n{PREFIX}_ops_duplicate_total {}",
            self.ops_duplicate.load(Ordering::Relaxed)
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_counters_and_gauges() {
        let m = Metrics::default();
        m.record_request(
            "/v1/sync/{vesta_id}/push",
            "POST",
            200,
            Duration::from_millis(5),
        );
        m.add_ops(3, 1);
        m.inflight_add(2);
        let text = m.render(4);
        assert!(text.contains("vault_sync_ops_accepted_total 3"));
        assert!(text.contains("vault_sync_ops_duplicate_total 1"));
        assert!(text.contains("vault_sync_tail_subscribers 4"));
        assert!(text.contains("vault_sync_http_inflight 2"));
        assert!(text.contains(
            "vault_sync_http_requests_total{route=\"/v1/sync/{vesta_id}/push\",method=\"POST\",status=\"200\"} 1"
        ));
        assert!(text.contains(
            "vault_sync_http_request_duration_ms_count{route=\"/v1/sync/{vesta_id}/push\"} 1"
        ));
    }
}
