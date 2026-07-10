//! vesta-sync HTTP surface (axum). Endpoints: account / enroll-challenge / enroll / push /
//! pull / status (+ healthz). Every op-bearing call is device-signed; account + enroll are
//! self-signed by the device key being registered (proves key possession) and enrol is gated
//! by the enrolment proof. See `docs/planning/02-vesta-sync-oplog.md`.

use crate::dto::ErrorBody;
use crate::state::AppState;
use crate::store::Store;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine as _;

type ErrResp = (StatusCode, Json<ErrorBody>);
type ApiResult<T> = Result<Json<T>, ErrResp>;

fn err(status: StatusCode, error: &str, detail: &str) -> ErrResp {
    (
        status,
        Json(ErrorBody {
            error: error.to_owned(),
            detail: detail.to_owned(),
        }),
    )
}

/// A `500` for a storage fault. The rusqlite/SQL detail can leak filesystem paths or schema
/// internals, so it is logged server-side and the client gets only a stable generic message.
fn db_err(e: impl std::fmt::Display) -> ErrResp {
    eprintln!("vesta-sync: store error: {e}");
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "store_error",
        "internal storage error",
    )
}

/// Run a blocking store operation off the async runtime. `Store` is `Send + Sync` (each
/// connection sits behind its own mutex), so it moves into the blocking pool as a cheap `Arc`
/// clone — keeping SQLite I/O from stalling tokio worker threads and letting pooled reads run
/// in parallel. A `JoinError` (the blocking task panicked) maps to a generic `500`.
async fn store_op<T, F>(state: &AppState, f: F) -> Result<T, ErrResp>
where
    F: FnOnce(&Store) -> T + Send + 'static,
    T: Send + 'static,
{
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || f(&store))
        .await
        .map_err(|e| {
            eprintln!("vesta-sync: blocking store task failed: {e}");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "internal storage error",
            )
        })
}

/// Lowercase-UUIDv4 check for `{vesta_id}` (no `uuid` crate). Personal vault ids are random
/// UUIDv4 — rejecting anything else keeps attacker-chosen keys out of the store and the
/// in-memory replay/tail maps entirely.
fn is_uuid_v4_lower(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            14 => {
                if c != b'4' {
                    return false;
                }
            } // version
            19 => {
                if !matches!(c, b'8' | b'9' | b'a' | b'b') {
                    return false;
                }
            } // variant
            _ => {
                if !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c) {
                    return false;
                }
            }
        }
    }
    true
}

/// Path extractor that validates `{vesta_id}` is a lowercase UUIDv4 **before** any handler
/// (or body parse) runs, rejecting a bogus id with `400`. This is the single choke point that
/// stops malformed ids from creating accounts or seeding the replay/tail maps.
pub struct VestaId(pub String);

impl FromRequestParts<AppState> for VestaId {
    type Rejection = ErrResp;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ErrResp> {
        let Path(vesta_id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                err(
                    StatusCode::BAD_REQUEST,
                    "bad_vesta_id",
                    "missing vesta_id path segment",
                )
            })?;
        if !is_uuid_v4_lower(&vesta_id) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "bad_vesta_id",
                "vesta_id must be a lowercase UUIDv4",
            ));
        }
        Ok(VestaId(vesta_id))
    }
}

pub fn router(state: AppState) -> Router {
    let max_body = state.cfg.max_body_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/sync/{vesta_id}/account", post(create_account))
        .route(
            "/v1/sync/{vesta_id}/enroll-challenge",
            get(enroll_challenge),
        )
        .route("/v1/sync/{vesta_id}/enroll", post(enroll))
        .route("/v1/sync/{vesta_id}/push", post(push))
        .route("/v1/sync/{vesta_id}/pull", get(pull))
        .route("/v1/sync/{vesta_id}/status", get(status))
        .route("/v1/sync/{vesta_id}/devices", get(list_devices))
        .route(
            "/v1/sync/{vesta_id}/devices/{device_id}",
            delete(revoke_device),
        )
        .route("/v1/sync/{vesta_id}/tail", get(tail))
        // Per-route so metrics run after routing and see the `MatchedPath` template (id-free).
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::harden::record_metrics,
        ))
        .layer(DefaultBodyLimit::max(max_body))
        // Outer → inner: concurrency cap (503) · request timeout (408) · body limit (413).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::harden::timeout,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::harden::concurrency_limit,
        ))
        // Outermost: stamp every response (incl. rejects) with a correlation id.
        .layer(axum::middleware::from_fn(crate::harden::request_id))
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

/// Loopback-only metrics router (Prometheus text). Exposed on a separate listener — never on
/// the public API surface — because op/device counts are the metadata the at-rest model guards.
pub fn metrics_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/metrics",
            get(|State(s): State<AppState>| async move {
                s.metrics.render(s.tail_subscriber_count())
            }),
        )
        .with_state(state)
}

// ── auth helpers ────────────────────────────────────────────────────────────

mod devices;
mod enroll;
mod oplog;
mod tail;
mod verify;

pub(crate) use devices::*;
pub(crate) use enroll::*;
pub(crate) use oplog::*;
pub(crate) use tail::*;
pub(crate) use verify::*;

#[cfg(test)]
mod tests;
