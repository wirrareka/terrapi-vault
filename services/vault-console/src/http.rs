//! Console HTTP API (`/api/v1/*`). Read-only observe aggregation + auth. P1a: the API only —
//! the SPA is served by the Vite dev proxy (dev) / embedded later (prod). Auth is a dev stub;
//! OIDC RP (identity, `private_key_jwt`, `acr=mfa`) lands in P1b.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::broker::BrokerHub;

#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<BrokerHub>,
    /// `allow_insecure_dev`: grants a `dev` operator session (no OIDC) — local only.
    pub dev: bool,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/auth/me", get(auth_me))
        .route("/api/v1/auth/login", get(auth_login))
        .route("/api/v1/auth/callback", get(auth_callback))
        .route("/api/v1/auth/logout", get(auth_logout))
        .route("/api/v1/brokers", get(brokers))
        .route("/api/v1/observe/leases", get(obs_leases))
        .route("/api/v1/observe/sessions", get(obs_sessions))
        .route("/api/v1/observe/roles", get(obs_roles))
        .route("/api/v1/observe/ssh", get(obs_ssh))
        .route("/api/v1/observe/kms", get(obs_kms))
        .route("/api/v1/observe/object-store", get(obs_object_store))
        .route("/api/v1/observe/audit", get(obs_audit))
        // Everything else → the SPA (embedded in release, a stub otherwise). API 404s stay 404.
        .fallback(crate::ui::fallback)
        .with_state(state)
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

// --- auth (P1a stubs; OIDC RP = P1b) --------------------------------------------------

async fn auth_me(State(s): State<AppState>) -> Response {
    if s.dev {
        Json(json!({ "subject": "dev@local", "email": "dev@local", "role": "operator" }))
            .into_response()
    } else {
        unauthorized()
    }
}

async fn auth_login() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "OIDC login not wired yet (P1b)",
    )
        .into_response()
}
async fn auth_callback() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "OIDC callback not wired yet (P1b)",
    )
        .into_response()
}
async fn auth_logout() -> Response {
    (StatusCode::NOT_IMPLEMENTED, "logout not wired yet (P1b)").into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "auth_required" })),
    )
        .into_response()
}

/// P1a session gate: `None` = allowed (dev), `Some(401)` = denied (forces the OIDC RP, P1b — the
/// SPA's API client redirects to `/api/v1/auth/login` on a 401).
fn gate(s: &AppState) -> Option<Response> {
    if s.dev {
        None
    } else {
        Some(unauthorized())
    }
}

// --- observe (read-only, aggregated across the group's brokers) ----------------------

async fn brokers(State(s): State<AppState>) -> Response {
    if let Some(e) = gate(&s) {
        return e;
    }
    Json(s.hub.brokers().await).into_response()
}

async fn obs_leases(State(s): State<AppState>) -> Response {
    if let Some(e) = gate(&s) {
        return e;
    }
    Json(
        s.hub
            .observe("/v1/sys/observe/leases", &["leases"], &["now"])
            .await,
    )
    .into_response()
}

async fn obs_sessions(State(s): State<AppState>) -> Response {
    if let Some(e) = gate(&s) {
        return e;
    }
    Json(
        s.hub
            .observe("/v1/sys/observe/sessions", &["sessions"], &["now"])
            .await,
    )
    .into_response()
}

async fn obs_roles(State(s): State<AppState>) -> Response {
    if let Some(e) = gate(&s) {
        return e;
    }
    Json(
        s.hub
            .observe("/v1/sys/observe/roles", &["roles"], &[])
            .await,
    )
    .into_response()
}

async fn obs_ssh(State(s): State<AppState>) -> Response {
    if let Some(e) = gate(&s) {
        return e;
    }
    let path = format!("/v1/{}/observe/ssh", s.hub.group());
    Json(s.hub.observe(&path, &["issued", "revoked"], &[]).await).into_response()
}

async fn obs_kms(State(s): State<AppState>) -> Response {
    if let Some(e) = gate(&s) {
        return e;
    }
    let path = format!("/v1/{}/observe/kms", s.hub.group());
    Json(s.hub.observe(&path, &["keys"], &[]).await).into_response()
}

async fn obs_object_store(State(s): State<AppState>) -> Response {
    if let Some(e) = gate(&s) {
        return e;
    }
    Json(s.hub.object_store().await).into_response()
}

#[derive(Deserialize)]
struct AuditQuery {
    since: Option<u64>,
    limit: Option<usize>,
}

async fn obs_audit(State(s): State<AppState>, Query(q): Query<AuditQuery>) -> Response {
    if let Some(e) = gate(&s) {
        return e;
    }
    let since = q.since.unwrap_or(0);
    let limit = q.limit.unwrap_or(200).clamp(1, 500);
    let path = format!("/v1/sys/observe/audit?since={since}&limit={limit}");
    Json(s.hub.observe(&path, &["records"], &["next_seq"]).await).into_response()
}
