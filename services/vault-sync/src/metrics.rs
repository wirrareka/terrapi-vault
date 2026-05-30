//! Minimal in-process metrics for vault-sync, exposed as Prometheus text on a **loopback-only**
//! listener (never the public API surface — op/device counts are exactly the metadata the
//! at-rest threat model protects). Mirrors the broker's lightweight approach: `std` + atomics,
//! no extra crates. Series are namespaced `vault_sync_*`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

#[derive(PartialEq, Eq, Hash)]
struct ReqKey {
    route: String,
    method: String,
    status: u16,
}

/// Counters/gauges bumped from the request middleware and the push handler. Cheap to clone as
/// `Arc<Metrics>` inside [`crate::state::AppState`].
#[derive(Default)]
pub struct Metrics {
    /// `vault_sync_http_requests_total{route,method,status}` — `route` is the MatchedPath
    /// template (e.g. `/v1/sync/{vault_id}/push`), never the concrete id (bounded cardinality).
    requests: Mutex<HashMap<ReqKey, u64>>,
    /// Per-route latency: `route -> (count, sum_millis)`.
    latency: Mutex<HashMap<String, (u64, u64)>>,
    /// Requests currently executing past the concurrency gate.
    inflight: AtomicI64,
    /// Ops newly stored vs. deduped, across all pushes.
    ops_accepted: AtomicU64,
    ops_duplicate: AtomicU64,
}

impl Metrics {
    /// Record one served request: bump `{route,method,status}` and add its latency to the
    /// per-route sum/count.
    pub fn record_request(&self, route: &str, method: &str, status: u16, dur: Duration) {
        *self
            .requests
            .lock()
            .expect("metrics lock")
            .entry(ReqKey {
                route: route.to_owned(),
                method: method.to_owned(),
                status,
            })
            .or_insert(0) += 1;
        let ms = u64::try_from(dur.as_millis()).unwrap_or(u64::MAX);
        let mut lat = self.latency.lock().expect("metrics lock");
        let e = lat.entry(route.to_owned()).or_insert((0, 0));
        e.0 += 1;
        e.1 = e.1.saturating_add(ms);
    }

    /// Adjust the in-flight gauge (`+1` on entry, `-1` on exit).
    pub fn inflight_add(&self, delta: i64) {
        self.inflight.fetch_add(delta, Ordering::Relaxed);
    }

    /// Account a completed push's accepted + duplicate op counts.
    pub fn add_ops(&self, accepted: u64, duplicate: u64) {
        self.ops_accepted.fetch_add(accepted, Ordering::Relaxed);
        self.ops_duplicate.fetch_add(duplicate, Ordering::Relaxed);
    }

    /// Render the Prometheus text exposition. `tail_subscribers` is the live gauge (computed by
    /// the caller from the broadcast map at scrape time).
    #[must_use]
    pub fn render(&self, tail_subscribers: u64) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();

        out.push_str("# HELP vault_sync_http_inflight Requests currently being served.\n");
        out.push_str("# TYPE vault_sync_http_inflight gauge\n");
        let _ = writeln!(
            out,
            "vault_sync_http_inflight {}",
            self.inflight.load(Ordering::Relaxed).max(0)
        );

        out.push_str(
            "# HELP vault_sync_tail_subscribers Active live-tail WebSocket subscribers.\n",
        );
        out.push_str("# TYPE vault_sync_tail_subscribers gauge\n");
        let _ = writeln!(out, "vault_sync_tail_subscribers {tail_subscribers}");

        out.push_str("# HELP vault_sync_ops_accepted_total Ops newly stored by push.\n");
        out.push_str("# TYPE vault_sync_ops_accepted_total counter\n");
        let _ = writeln!(
            out,
            "vault_sync_ops_accepted_total {}",
            self.ops_accepted.load(Ordering::Relaxed)
        );
        out.push_str("# HELP vault_sync_ops_duplicate_total Ops deduped by push (op_id seen).\n");
        out.push_str("# TYPE vault_sync_ops_duplicate_total counter\n");
        let _ = writeln!(
            out,
            "vault_sync_ops_duplicate_total {}",
            self.ops_duplicate.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP vault_sync_http_requests_total Served HTTP requests, by route/method/status.\n",
        );
        out.push_str("# TYPE vault_sync_http_requests_total counter\n");
        let reqs = self.requests.lock().expect("metrics lock");
        let mut rows: Vec<_> = reqs.iter().collect();
        rows.sort_by(|a, b| {
            (&a.0.route, &a.0.method, a.0.status).cmp(&(&b.0.route, &b.0.method, b.0.status))
        });
        for (k, n) in rows {
            let _ = writeln!(
                out,
                "vault_sync_http_requests_total{{route=\"{}\",method=\"{}\",status=\"{}\"}} {n}",
                k.route, k.method, k.status
            );
        }

        out.push_str(
            "# HELP vault_sync_http_request_duration_ms Per-route request latency (sum/count).\n",
        );
        out.push_str("# TYPE vault_sync_http_request_duration_ms summary\n");
        let lat = self.latency.lock().expect("metrics lock");
        let mut lrows: Vec<_> = lat.iter().collect();
        lrows.sort_by(|a, b| a.0.cmp(b.0));
        for (route, (count, sum)) in lrows {
            let _ = writeln!(
                out,
                "vault_sync_http_request_duration_ms_count{{route=\"{route}\"}} {count}"
            );
            let _ = writeln!(
                out,
                "vault_sync_http_request_duration_ms_sum{{route=\"{route}\"}} {sum}"
            );
        }
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
            "/v1/sync/{vault_id}/push",
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
            "vault_sync_http_requests_total{route=\"/v1/sync/{vault_id}/push\",method=\"POST\",status=\"200\"} 1"
        ));
        assert!(text.contains(
            "vault_sync_http_request_duration_ms_count{route=\"/v1/sync/{vault_id}/push\"} 1"
        ));
    }
}
