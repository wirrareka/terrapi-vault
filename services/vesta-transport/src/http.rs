//! Small HTTP wire helpers shared by both service worlds. Deliberately framework-free
//! (serde + std only) so this crate stays axum/tokio-neutral — each service keeps its own
//! thin `err()`/handler glue around these shapes.

use crate::lock::MutexExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

#[derive(PartialEq, Eq, Hash)]
struct ReqKey {
    route: String,
    method: String,
    status: u16,
}

/// Shared HTTP request metrics: requests by `{route,method,status}`, per-route latency
/// (sum/count), and an in-flight gauge — plus their Prometheus exposition. Framework-free
/// (`std` + atomics), so both services embed it (broker + vesta-sync) and render their own
/// domain series alongside under the same `prefix`, keeping the `*_http_*` series format defined
/// **once**. `route` should be the matched-path template, never a concrete id (bounded labels).
#[derive(Default)]
pub struct HttpMetrics {
    requests: Mutex<HashMap<ReqKey, u64>>,
    latency: Mutex<HashMap<String, (u64, u64)>>,
    inflight: AtomicI64,
}

impl HttpMetrics {
    /// Record one served request: bump `{route,method,status}` and add latency to the per-route
    /// sum/count.
    ///
    /// # Panics
    /// If the internal metrics mutex is poisoned (a thread panicked while holding it).
    pub fn record_request(&self, route: &str, method: &str, status: u16, dur: Duration) {
        *self
            .requests
            .lock_recover()
            .entry(ReqKey {
                route: route.to_owned(),
                method: method.to_owned(),
                status,
            })
            .or_insert(0) += 1;
        let ms = u64::try_from(dur.as_millis()).unwrap_or(u64::MAX);
        let mut lat = self.latency.lock_recover();
        let e = lat.entry(route.to_owned()).or_insert((0, 0));
        e.0 += 1;
        e.1 = e.1.saturating_add(ms);
    }

    /// Adjust the in-flight gauge (`+1` on entry, `-1` on exit).
    pub fn inflight_add(&self, delta: i64) {
        self.inflight.fetch_add(delta, Ordering::Relaxed);
    }

    /// Render the `{prefix}_http_*` Prometheus series (inflight gauge, requests counter,
    /// per-route latency summary). The caller appends its own domain series.
    ///
    /// # Panics
    /// If the internal metrics mutex is poisoned (a thread panicked while holding it).
    #[must_use]
    pub fn render(&self, prefix: &str) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP {prefix}_http_inflight Requests currently being served.\n# TYPE {prefix}_http_inflight gauge\n{prefix}_http_inflight {}",
            self.inflight.load(Ordering::Relaxed).max(0)
        );
        let _ = writeln!(
            out,
            "# HELP {prefix}_http_requests_total Served HTTP requests, by route/method/status.\n# TYPE {prefix}_http_requests_total counter"
        );
        let reqs = self.requests.lock_recover();
        let mut rows: Vec<_> = reqs.iter().collect();
        rows.sort_by(|a, b| {
            (&a.0.route, &a.0.method, a.0.status).cmp(&(&b.0.route, &b.0.method, b.0.status))
        });
        for (k, n) in rows {
            let _ = writeln!(
                out,
                "{prefix}_http_requests_total{{route=\"{}\",method=\"{}\",status=\"{}\"}} {n}",
                k.route, k.method, k.status
            );
        }
        let _ = writeln!(
            out,
            "# HELP {prefix}_http_request_duration_ms Per-route request latency (sum/count).\n# TYPE {prefix}_http_request_duration_ms summary"
        );
        let lat = self.latency.lock_recover();
        let mut lrows: Vec<_> = lat.iter().collect();
        lrows.sort_by(|a, b| a.0.cmp(b.0));
        for (route, (count, sum)) in lrows {
            let _ = writeln!(
                out,
                "{prefix}_http_request_duration_ms_count{{route=\"{route}\"}} {count}\n{prefix}_http_request_duration_ms_sum{{route=\"{route}\"}} {sum}"
            );
        }
        out
    }
}

/// Uniform error envelope returned by both services: a stable machine `error` code plus a
/// human-readable, non-contractual `detail`. The code enums are documented in each service's
/// OpenAPI spec (`spec/{broker,sync}-openapi.yaml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    pub detail: String,
}

/// Minimal success acknowledgement (`{"ok": true}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ack {
    pub ok: bool,
}

/// Parse environment variable `key` into `T`, or `None` if it is unset/empty/unparseable.
/// The shared idiom behind every service's `from_env` config loader.
#[must_use]
pub fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok().and_then(|s| s.parse().ok())
}

/// Backward-compat for the `vault` → `vesta` rename: mirror every `VAULT_*` env var to its
/// `VESTA_*` name when the new name is unset, so deploy units still on the old prefix keep working
/// during the migration window. **Call once at the very top of `main()`**, before anything reads
/// the environment. Remove once all units have flipped to `VESTA_*` (rename plan, Stage 4).
///
/// Safe: runs single-threaded at process start, before any other thread exists.
pub fn apply_vault_env_compat() {
    // Snapshot first — we mutate the environment while iterating the old values.
    let pairs: Vec<(String, String)> = std::env::vars().collect();
    for (key, value) in pairs {
        if let Some(suffix) = key.strip_prefix("VAULT_") {
            let new_key = format!("VESTA_{suffix}");
            if std::env::var_os(&new_key).is_none() {
                std::env::set_var(&new_key, &value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body_roundtrips() {
        let e = ErrorBody {
            error: "replay".into(),
            detail: "seen".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, r#"{"error":"replay","detail":"seen"}"#);
        let back: ErrorBody = serde_json::from_str(&s).unwrap();
        assert_eq!(back.error, "replay");
    }

    #[test]
    fn ack_shape() {
        assert_eq!(
            serde_json::to_string(&Ack { ok: true }).unwrap(),
            r#"{"ok":true}"#
        );
    }

    #[test]
    fn env_parse_handles_missing_and_bad() {
        // A name that is almost certainly unset → None (not a panic).
        assert_eq!(
            env_parse::<u32>("VESTA_TRANSPORT_DEFINITELY_UNSET_XYZ"),
            None
        );
    }
}
