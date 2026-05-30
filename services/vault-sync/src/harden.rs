//! Lightweight request hardening for vault-sync: a global concurrency cap (`503`
//! back-pressure) and a per-request timeout (`408`). Mirrors the broker's approach with
//! `axum`/`tokio`/`std` only — no extra crates. The body-size cap stays on the router
//! (`DefaultBodyLimit`); the unauthenticated `enroll-challenge` has its own token bucket.

use crate::dto::ErrorBody;
use crate::state::AppState;
use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

fn reject(status: StatusCode, error: &str, detail: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            error: error.to_owned(),
            detail: detail.to_owned(),
        }),
    )
        .into_response()
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
