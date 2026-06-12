//! Lightweight request hardening for vesta-sync: a global concurrency cap (`503`
//! back-pressure) and a per-request timeout (`408`). Mirrors the broker's approach with
//! `axum`/`tokio`/`std` only — no extra crates. The body-size cap stays on the router
//! (`DefaultBodyLimit`); the unauthenticated `enroll-challenge` has its own token bucket.

use crate::dto::ErrorBody;
use crate::state::AppState;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::sync::atomic::{AtomicU64, Ordering};

fn reject(status: StatusCode, error: &str, detail: &str) -> Response {
    let mut resp = (
        status,
        Json(ErrorBody {
            error: error.to_owned(),
            detail: detail.to_owned(),
        }),
    )
        .into_response();
    // Transient rejections advertise when to retry.
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

/// Per-process request counter for generated correlation ids (no runtime RNG dep; the value is
/// only for log/response correlation within a run).
static REQ_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Echo the caller's `X-Request-Id` (bounded, ASCII) or generate one, so a client can correlate
/// its request with the server's response. Outermost layer, so even rejects carry it.
pub async fn request_id(req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 128 && s.is_ascii())
        .map_or_else(
            || format!("req-{:016x}", REQ_COUNTER.fetch_add(1, Ordering::Relaxed)),
            str::to_owned,
        );
    let mut resp = next.run(req).await;
    if let Ok(hv) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", hv);
    }
    resp
}

/// Global concurrency cap → `503` when all permits are in use. The permit is held only for the
/// handler's lifetime; the `/tail` upgrade returns immediately, so a live WebSocket does **not**
/// hold a permit.
pub async fn concurrency_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = state.sem.clone().try_acquire_owned() else {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "server is at capacity; retry shortly",
        );
    };
    state.metrics.inflight_add(1);
    let resp = next.run(req).await;
    state.metrics.inflight_add(-1);
    resp
}

/// Record `vault_sync_http_*` for a served request. Applied as a `route_layer`, so it runs
/// after routing and the `MatchedPath` template (e.g. `/v1/sync/{vault_id}/push`) is the
/// (bounded, id-free) label — never the concrete vault id.
pub async fn record_metrics(
    State(state): State<AppState>,
    matched: Option<MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    let route = matched.map_or_else(|| "<unmatched>".to_owned(), |m| m.as_str().to_owned());
    let method = req.method().as_str().to_owned();
    let start = std::time::Instant::now();
    let resp = next.run(req).await;
    state
        .metrics
        .record_request(&route, &method, resp.status().as_u16(), start.elapsed());
    resp
}

/// Abort a request that runs past the configured budget → `408`. The `/tail` upgrade completes
/// before the budget (it hands the socket to a background task), so the live socket is unaffected.
pub async fn timeout(State(state): State<AppState>, req: Request, next: Next) -> Response {
    match tokio::time::timeout(state.cfg.request_timeout, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => reject(
            StatusCode::REQUEST_TIMEOUT,
            "timeout",
            "request exceeded the server time budget",
        ),
    }
}
