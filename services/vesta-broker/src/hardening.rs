//! Broker hardening: defensive request limits + per-principal rate limiting + request
//! observability + uniform error surface. All implemented with `axum`/`tokio`/`std`
//! primitives — no extra crates — and applied as middleware in [`crate::http::router`].
//!
//! Layer order (outermost → innermost): security headers · request metrics (matched routes,
//! so the `MatchedPath` template — never the tenant-bearing concrete path — is the label) ·
//! per-principal rate limit (`429`) · global concurrency limit (`503`) · request timeout
//! (`408`) · body-size limit (`413`). A throttled or overloaded request is rejected before
//! it reaches a handler.

use crate::auth::ClientSan;
use crate::config::Hardening;
use crate::dto::ErrorBody;
use crate::state::AppState;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::Semaphore;

/// Runtime hardening state shared across requests: the limits, the global concurrency
/// permits, and the per-principal token buckets.
pub struct HardenState {
    pub limits: Hardening,
    sem: Arc<Semaphore>,
    buckets: Mutex<HashMap<String, Bucket>>,
}

/// Cap on distinct per-principal buckets held at once. Production keys are the few registered
/// SANs (well under this); the cap only bites on the dev header path, where the key is
/// caller-controlled. At the cap, idle (fully-refilled) buckets are evicted before a new key
/// is admitted, so the map cannot grow without bound.
const MAX_BUCKETS: usize = 4096;

/// A per-principal token bucket: `tokens` refilled at `rate_per_sec`, capped at `rate_burst`.
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl HardenState {
    #[must_use]
    pub fn new(limits: Hardening) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(limits.max_concurrency)),
            buckets: Mutex::new(HashMap::new()),
            limits,
        }
    }

    /// Consume one token for `key`; `true` if allowed, `false` if the bucket is empty. A
    /// first-seen principal starts full (a burst's worth), so normal traffic never waits.
    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate lock");
        // Before admitting a brand-new principal at capacity, evict idle buckets (those that
        // have refilled to full), so a flood of distinct keys can't grow the map without bound.
        if !buckets.contains_key(key) && buckets.len() >= MAX_BUCKETS {
            let (rate, burst) = (self.limits.rate_per_sec, self.limits.rate_burst);
            buckets.retain(|_, b| {
                let refilled = b.tokens + now.duration_since(b.last).as_secs_f64() * rate;
                refilled < burst
            });
        }
        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: self.limits.rate_burst,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens =
            (bucket.tokens + elapsed * self.limits.rate_per_sec).min(self.limits.rate_burst);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn reject(status: StatusCode, error: &str, detail: &str) -> Response {
    let mut resp = (
        status,
        Json(ErrorBody {
            error: error.to_owned(),
            detail: detail.to_owned(),
        }),
    )
        .into_response();
    // Transient rejections advertise when to retry (clients/proxies honour Retry-After).
    if matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::REQUEST_TIMEOUT
    ) {
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_static("1"),
        );
    }
    resp
}

/// Echo the caller's `X-Request-Id` (bounded, ASCII) back on the response, or generate one when
/// absent, so a client can correlate its request with this broker's response. Outermost layer,
/// so even rejected requests carry the id.
pub async fn request_id(req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 128 && s.is_ascii())
        .map_or_else(crate::state::random_id, str::to_owned);
    let mut resp = next.run(req).await;
    if let Ok(hv) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", hv);
    }
    resp
}

/// Uniform JSON `404` for any unrouted path (the router fallback).
pub async fn not_found() -> Response {
    reject(
        StatusCode::NOT_FOUND,
        "not_found",
        "no such route on this broker",
    )
}

/// The principal a request is throttled under: the verified mTLS SAN (prod), the dev
/// header (insecure dev), else a shared `anonymous` bucket. In production every request
/// carries a verified `ClientSan`, so throttling is genuinely per-daemon.
fn principal_key(req: &Request) -> String {
    if let Some(ClientSan(san)) = req.extensions().get::<ClientSan>() {
        return san.clone();
    }
    req.headers()
        .get("x-client-cert-san")
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| "anonymous".to_owned(), str::to_owned)
}

/// Per-principal token-bucket rate limit → `429` when a principal exceeds its burst/rate.
pub async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if state.harden.allow(&principal_key(&req)) {
        next.run(req).await
    } else {
        reject(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "per-principal request rate exceeded; slow down",
        )
    }
}

/// Global concurrency cap → `503` when all permits are in use (back-pressure rather than
/// unbounded queueing). The permit is held for the lifetime of the inner request and also
/// drives the `vault_http_inflight` gauge.
pub async fn concurrency_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = state.harden.sem.clone().try_acquire_owned() else {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "broker is at capacity; retry shortly",
        );
    };
    state.metrics.inflight_add(1);
    let resp = next.run(req).await;
    state.metrics.inflight_add(-1);
    resp
}

/// Abort a request that runs longer than the configured timeout → `408`.
pub async fn timeout(State(state): State<AppState>, req: Request, next: Next) -> Response {
    match tokio::time::timeout(state.harden.limits.request_timeout, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => reject(
            StatusCode::REQUEST_TIMEOUT,
            "timeout",
            "request exceeded the broker time budget",
        ),
    }
}

/// Record `vault_http_*` for a served request. Applied as a `route_layer`, so it runs after
/// routing and the `MatchedPath` template is available as the (bounded, tenant-free) label.
pub async fn record_metrics(
    State(state): State<AppState>,
    matched: Option<MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    let route = matched.map_or_else(|| "<unmatched>".to_owned(), |m| m.as_str().to_owned());
    let method = req.method().as_str().to_owned();
    let start = Instant::now();
    let resp = next.run(req).await;
    state
        .metrics
        .record_request(&route, &method, resp.status().as_u16(), start.elapsed());
    resp
}

/// Add conservative security headers to every response (incl. error/limit responses, since
/// this is the outermost layer). This is a JSON API over WG, so the relevant ones are
/// `nosniff`, no caching of secret material, and a strict referrer policy.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("X-Content-Type-Options", "nosniff".parse().expect("hv"));
    h.insert("Cache-Control", "no-store".parse().expect("hv"));
    h.insert("Referrer-Policy", "no-referrer".parse().expect("hv"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(rate: f64, burst: f64) -> Hardening {
        Hardening {
            rate_per_sec: rate,
            rate_burst: burst,
            ..Hardening::default()
        }
    }

    #[test]
    fn bucket_allows_a_burst_then_throttles() {
        let h = HardenState::new(limits(0.0, 3.0)); // no refill, burst of 3
        assert!(h.allow("demon")); // 3 -> 2
        assert!(h.allow("demon")); // 2 -> 1
        assert!(h.allow("demon")); // 1 -> 0
        assert!(!h.allow("demon")); // empty -> throttled
    }

    #[test]
    fn buckets_are_per_principal() {
        let h = HardenState::new(limits(0.0, 1.0));
        assert!(h.allow("demon-operator"));
        assert!(!h.allow("demon-operator")); // operator exhausted
        assert!(h.allow("demon-system")); // system has its own bucket
    }
}
