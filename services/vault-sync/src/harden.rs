//! Lightweight request hardening for vault-sync: a global concurrency cap (`503`
//! back-pressure) and a per-request timeout (`408`). Mirrors the broker's approach with
//! `axum`/`tokio`/`std` only — no extra crates. The body-size cap stays on the router
//! (`DefaultBodyLimit`); the unauthenticated `enroll-challenge` has its own token bucket.

use crate::dto::ErrorBody;
use crate::state::AppState;
use axum::extract::{Request, State};
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
    next.run(req).await
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
