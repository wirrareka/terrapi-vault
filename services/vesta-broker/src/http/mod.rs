//! v1 broker HTTP surface (axum). All v1 ops are implemented: sessions + leases (against
//! the lease engine), the SSH-CA (`ssh/ca`, `ssh/sign`), and dynamic creds (`creds`, via
//! the OpenSearch engine). Issuance is session-bound + sealed-gated; every state-changing
//! op emits a B3 audit event (`source:"vesta"`).

use crate::auth::{Capability, Principal};
use crate::dto::{ErrorBody, SealStatus};
use crate::state::AppState;
use axum::extract::{FromRequestParts, RawPathParams, State};
use axum::http::{request::Parts, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use vesta_transport::audit::{Actor, ActorKind, AuditEvent};
use vesta_transport::ResidencyGroup;

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ErrorBody>)>;

fn err(status: StatusCode, error: &str, detail: &str) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            error: error.to_owned(),
            detail: detail.to_owned(),
        }),
    )
}

/// A `5xx` whose underlying detail must NOT reach the client — it can carry rusqlite/SQL
/// text, filesystem paths, or other internals. The real error is logged server-side; the
/// client gets the stable machine `code` and a generic detail.
fn internal(code: &str, context: &str, e: impl std::fmt::Display) -> (StatusCode, Json<ErrorBody>) {
    eprintln!("vesta-broker: {context}: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, code, "internal error")
}

/// A `502` for an upstream backend (e.g. OpenSearch) failure — same redaction: the backend's
/// message is logged locally, the client gets a generic detail so backend internals (URLs,
/// index names, status text) never leak across the trust boundary.
fn backend(context: &str, e: impl std::fmt::Display) -> (StatusCode, Json<ErrorBody>) {
    eprintln!("vesta-broker: {context}: {e}");
    err(
        StatusCode::BAD_GATEWAY,
        "backend_error",
        "upstream backend error",
    )
}

/// A path `:group` must equal this instance's group, else `404` — a cred for one
/// region must not even be addressable on another's broker (residency air-gap).
fn check_group(state: &AppState, group: &str) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let want = state.cfg.residency_group.as_str();
    let parsed = match group {
        "eu" => Some(ResidencyGroup::Eu),
        "uae" => Some(ResidencyGroup::Uae),
        _ => None,
    };
    if parsed == Some(state.cfg.residency_group) {
        Ok(())
    } else {
        Err(err(
            StatusCode::NOT_FOUND,
            "group_mismatch",
            &format!("this broker serves residency_group={want}"),
        ))
    }
}

/// Validated `:group` path extractor: the segment must equal this instance's
/// `residency_group`, else `404` (residency air-gap — a cred for one region must not even
/// be *addressable* on another region's broker). It is a [`FromRequestParts`] extractor on
/// purpose: the group decision then happens **during extraction, before the request body is
/// read**, so a wrong-group request returns `404` regardless of whether its JSON body is
/// well-formed. (Previously `check_group` ran in the handler body, after the `Json`
/// extractor, so a malformed body to the wrong group `400`'d before the group `404`.)
pub struct Group(#[allow(dead_code)] pub String);

impl FromRequestParts<AppState> for Group {
    type Rejection = (StatusCode, Json<ErrorBody>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Re-reading the path params here is cheap and non-consuming: the router stores them
        // as a request extension, so a handler's own `Path(...)` still sees them too.
        let params = RawPathParams::from_request_parts(parts, state)
            .await
            .map_err(|_| err(StatusCode::NOT_FOUND, "group_mismatch", "missing :group"))?;
        let group = params
            .iter()
            .find_map(|(k, v)| (k == "group").then(|| v.to_owned()))
            .unwrap_or_default();
        check_group(state, &group)?;
        Ok(Group(group))
    }
}

/// Lowercase UUIDv4 check (Vulture organization_id), without pulling a uuid crate.
pub(crate) fn is_uuid_v4_lower(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != b'-' {
                    return false;
                }
            }
            14 => {
                if *c != b'4' {
                    return false;
                }
            } // version
            19 => {
                if !matches!(c, b'8' | b'9' | b'a' | b'b') {
                    return false;
                }
            } // variant
            _ => {
                if !c.is_ascii_hexdigit() || c.is_ascii_uppercase() {
                    return false;
                }
            }
        }
    }
    true
}

pub fn router(state: AppState) -> Router {
    use crate::hardening as hard;
    use axum::extract::DefaultBodyLimit;
    use axum::middleware::{from_fn, from_fn_with_state};

    let max_body = state.harden.limits.max_body_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/sys/seal-status", get(seal_status))
        .route("/v1/{group}/ssh/ca", get(ssh_ca))
        .route("/v1/{group}/ssh/revoked", get(ssh_revoked))
        .route("/v1/{group}/ssh/sign", post(ssh_sign))
        .route("/v1/{group}/{tenant_id}/creds/{role}", post(creds))
        .route("/v1/{group}/{tenant_id}/kms/{key_id}/wrap", post(kms_wrap))
        .route(
            "/v1/{group}/{tenant_id}/kms/{key_id}/unwrap",
            post(kms_unwrap),
        )
        .route(
            "/v1/{group}/{tenant_id}/kms/{key_id}/rotate",
            post(kms_rotate),
        )
        .route(
            "/v1/{group}/{tenant_id}/kms/{key_id}/rewrap",
            post(kms_rewrap),
        )
        .route("/v1/{group}/object-store/presign", post(presign))
        .route("/v1/{group}/object-store/presign-get", post(presign_get))
        .route("/v1/sys/observe/leases", get(observe_leases))
        .route("/v1/sys/observe/sessions", get(observe_sessions))
        .route("/v1/sys/observe/roles", get(observe_roles))
        .route("/v1/sys/observe/audit", get(observe_audit))
        .route("/v1/{group}/observe/ssh", get(observe_ssh))
        .route("/v1/{group}/observe/kms", get(observe_kms))
        .route(
            "/v1/{group}/observe/object-store",
            get(observe_object_store),
        )
        .route("/v1/sys/session", post(session_open))
        .route("/v1/sys/session/{id}", delete(session_end))
        .route("/v1/sys/store-snapshot", post(store_snapshot))
        .route("/v1/sys/leases/renew", post(lease_renew))
        .route("/v1/sys/leases/revoke", post(lease_revoke))
        // Per-route so the metrics middleware runs *after* routing and sees `MatchedPath`.
        .route_layer(from_fn_with_state(state.clone(), hard::record_metrics))
        .fallback(hard::not_found)
        // Outer → inner: security headers · rate limit · concurrency · timeout · body size.
        .layer(DefaultBodyLimit::max(max_body))
        .layer(from_fn_with_state(state.clone(), hard::timeout))
        .layer(from_fn_with_state(state.clone(), hard::concurrency_limit))
        .layer(from_fn_with_state(state.clone(), hard::rate_limit))
        .layer(from_fn(hard::security_headers))
        // Outermost: stamp every response (incl. rejects) with a correlation id.
        .layer(from_fn(hard::request_id))
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

/// Loopback-only metrics router (`8201`): Prometheus text, no auth (WG/loopback bound).
pub fn metrics_router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn metrics(State(state): State<AppState>) -> String {
    state.metrics.render(state.is_sealed())
}

/// Readiness probe (unauthenticated): is the master key unsealed yet? Demon polls this
/// before issuing; mutating ops MAY 503 while sealed.
async fn seal_status(State(state): State<AppState>) -> Json<SealStatus> {
    Json(SealStatus {
        sealed: state.is_sealed(),
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
    })
}

/// Least-privilege gate: the principal's role must hold `cap`, else `403`.
fn require_cap(
    principal: &Principal,
    cap: Capability,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if principal.allows(cap) {
        Ok(())
    } else {
        Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this principal's role is not granted this operation",
        ))
    }
}

/// Gate every mutating op on the broker being unsealed. A sealed broker has no master
/// key and is not operational → `503` (the consumer polls `/v1/sys/seal-status`).
fn require_unsealed(state: &AppState) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if state.is_sealed() {
        Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "sealed",
            "broker is sealed; an operator must unseal it before issuing",
        ))
    } else {
        Ok(())
    }
}

/// Emit an issuance/sensitive-op audit event **fail-closed**: `503 audit_unavailable` if the
/// record can't be durably written, so the op's result (a wrapped/unwrapped KEK, a presigned URL,
/// an opened session) is never returned without a durable trace. For ops with **no** artifact to
/// tear down on failure; `ssh_sign`/`creds` use their own teardown-aware variants.
fn require_audit(
    state: &AppState,
    event: &AuditEvent,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    state.try_emit(event).map_err(|_| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "operation refused: the audit record could not be durably written",
        )
    })
}

mod creds_api;
mod kms;
mod object_store;
mod observe;
mod session;
mod ssh;
mod sys;

pub(crate) use creds_api::*;
pub(crate) use kms::*;
pub(crate) use object_store::*;
pub(crate) use observe::*;
pub(crate) use session::*;
pub(crate) use ssh::*;
pub(crate) use sys::*;

#[cfg(test)]
mod tests;

/// RFC3339 UTC rendering of a unix-seconds timestamp (for `valid_before` in the response).
fn rfc3339(unix_secs: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    i64::try_from(unix_secs)
        .ok()
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

fn system_actor(principal: &Principal) -> Actor {
    Actor {
        label: principal.san.clone(),
        kind: ActorKind::System,
        id: Some(principal.role.clone()),
        tenant: None,
    }
}
