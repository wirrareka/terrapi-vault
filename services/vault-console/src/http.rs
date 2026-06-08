//! Console HTTP API (`/api/v1/*`). Read-only observe aggregation + auth. P1b: OIDC RP login
//! (identity, `private_key_jwt`, `acr=mfa`) backs a cookie session; the dev stub remains for
//! `VAULT_CONSOLE_ALLOW_INSECURE_DEV`. The SPA is served by the Vite dev proxy (dev) / embedded
//! (release). NEVER surfaces a secret value.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::broker::BrokerHub;
use crate::oidc::{OidcClient, Operator};
use crate::session::{PendingAuth, Sessions, COOKIE_NAME};

#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<BrokerHub>,
    /// The OIDC RP (P1b). `None` when OIDC is unconfigured (dev, or login disabled).
    pub oidc: Option<Arc<OidcClient>>,
    pub sessions: Arc<Sessions>,
    pub pending: Arc<PendingAuth>,
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

// --- auth (OIDC RP, P1b) --------------------------------------------------------------

/// The current operator: the dev stub (insecure dev), else the cookie session.
fn current_operator(s: &AppState, headers: &HeaderMap) -> Option<Operator> {
    if s.dev {
        return Some(Operator {
            subject: "dev@local".into(),
            email: Some("dev@local".into()),
        });
    }
    let sid = cookie_value(headers, COOKIE_NAME)?;
    s.sessions.get(&sid)
}

async fn auth_me(State(s): State<AppState>, headers: HeaderMap) -> Response {
    match current_operator(&s, &headers) {
        Some(op) => Json(json!({
            "subject": op.subject,
            "email": op.email,
            "role": "operator",
        }))
        .into_response(),
        None => unauthorized(),
    }
}

async fn auth_login(State(s): State<AppState>) -> Response {
    let Some(oidc) = s.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "OIDC not configured").into_response();
    };
    let req = oidc.auth_request();
    s.pending.put(req.state, req.verifier, req.nonce);
    Redirect::to(&req.url).into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn auth_callback(State(s): State<AppState>, Query(q): Query<CallbackQuery>) -> Response {
    let Some(oidc) = s.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "OIDC not configured").into_response();
    };
    if let Some(err) = q.error {
        let desc = q.error_description.unwrap_or_default();
        return (
            StatusCode::UNAUTHORIZED,
            format!("identity error: {err} {desc}"),
        )
            .into_response();
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return (StatusCode::BAD_REQUEST, "missing code/state").into_response();
    };
    let Some((verifier, nonce)) = s.pending.take(&state) else {
        return (StatusCode::BAD_REQUEST, "unknown or expired state").into_response();
    };
    match oidc.complete(&code, &verifier, &nonce).await {
        Ok(op) => {
            let sid = s.sessions.create(op);
            (
                AppendHeaders([(header::SET_COOKIE, session_cookie(&sid))]),
                Redirect::to("/"),
            )
                .into_response()
        }
        Err(e) => {
            // Auth failures (acr/nonce/token) → 401; the operator can retry from the SPA.
            (StatusCode::UNAUTHORIZED, format!("login failed: {e}")).into_response()
        }
    }
}

async fn auth_logout(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(sid) = cookie_value(&headers, COOKIE_NAME) {
        s.sessions.remove(&sid);
    }
    (
        AppendHeaders([(header::SET_COOKIE, cleared_cookie())]),
        Redirect::to("/"),
    )
        .into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "auth_required" })),
    )
        .into_response()
}

/// Session gate: `None` = allowed, `Some(401)` = denied (the SPA's API client redirects to
/// `/api/v1/auth/login` on a 401).
fn gate(s: &AppState, headers: &HeaderMap) -> Option<Response> {
    if current_operator(s, headers).is_some() {
        None
    } else {
        Some(unauthorized())
    }
}

/// Read a cookie value by name from the `Cookie` header (no cookie crate — one small parse).
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|kv| kv.split_once('='))
        .find_map(|(k, v)| (k.trim() == name).then(|| v.trim().to_string()))
}

/// `Set-Cookie` for a new session — HttpOnly + Secure (the browser reaches us over the HTTPS
/// edge) + SameSite=Lax (the OIDC redirect is a top-level GET).
fn session_cookie(sid: &str) -> String {
    format!("{COOKIE_NAME}={sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800")
}

fn cleared_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
}

// --- observe (read-only, aggregated across the group's brokers) ----------------------

async fn brokers(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(e) = gate(&s, &headers) {
        return e;
    }
    Json(s.hub.brokers().await).into_response()
}

async fn obs_leases(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(e) = gate(&s, &headers) {
        return e;
    }
    Json(
        s.hub
            .observe("/v1/sys/observe/leases", &["leases"], &["now"])
            .await,
    )
    .into_response()
}

async fn obs_sessions(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(e) = gate(&s, &headers) {
        return e;
    }
    Json(
        s.hub
            .observe("/v1/sys/observe/sessions", &["sessions"], &["now"])
            .await,
    )
    .into_response()
}

async fn obs_roles(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(e) = gate(&s, &headers) {
        return e;
    }
    Json(
        s.hub
            .observe("/v1/sys/observe/roles", &["roles"], &[])
            .await,
    )
    .into_response()
}

async fn obs_ssh(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(e) = gate(&s, &headers) {
        return e;
    }
    let path = format!("/v1/{}/observe/ssh", s.hub.group());
    Json(s.hub.observe(&path, &["issued", "revoked"], &[]).await).into_response()
}

async fn obs_kms(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(e) = gate(&s, &headers) {
        return e;
    }
    let path = format!("/v1/{}/observe/kms", s.hub.group());
    Json(s.hub.observe(&path, &["keys"], &[]).await).into_response()
}

async fn obs_object_store(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(e) = gate(&s, &headers) {
        return e;
    }
    Json(s.hub.object_store().await).into_response()
}

#[derive(Deserialize)]
struct AuditQuery {
    since: Option<u64>,
    limit: Option<usize>,
}

async fn obs_audit(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Response {
    if let Some(e) = gate(&s, &headers) {
        return e;
    }
    let since = q.since.unwrap_or(0);
    let limit = q.limit.unwrap_or(200).clamp(1, 500);
    let path = format!("/v1/sys/observe/audit?since={since}&limit={limit}");
    Json(s.hub.observe(&path, &["records"], &["next_seq"]).await).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_cookie(raw: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, raw.parse().unwrap());
        h
    }

    #[test]
    fn cookie_value_parses_named_cookie() {
        let h = headers_with_cookie("other=1; vc_session=abc123; foo=bar");
        assert_eq!(cookie_value(&h, COOKIE_NAME).as_deref(), Some("abc123"));
    }

    #[test]
    fn cookie_value_absent_is_none() {
        let h = headers_with_cookie("other=1");
        assert!(cookie_value(&h, COOKIE_NAME).is_none());
    }

    #[test]
    fn session_cookie_is_hardened() {
        let c = session_cookie("xyz");
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("Secure"));
        assert!(c.contains("SameSite=Lax"));
        assert!(c.contains("vc_session=xyz"));
    }
}
