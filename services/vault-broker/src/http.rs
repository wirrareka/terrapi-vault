//! v1 broker HTTP surface (axum). Sessions + leases are implemented against the
//! lease engine; SSH-CA and dynamic creds are typed `501` stubs whose request/response
//! shapes are already fixed (the backends — SSH signing, OpenSearch RBAC, RethinkDB —
//! land next). Every state-changing op that IS implemented emits a B3 audit event.

use crate::auth::Principal;
use crate::dto::{
    Ack, CredsRequest, ErrorBody, LeaseRenewRequest, LeaseRenewResponse, LeaseRevokeRequest,
    SealStatus, SessionEndResponse, SessionOpenRequest, SessionOpenResponse, SshSignRequest,
};
use crate::state::{AppState, DEFAULT_SESSION_IDLE_SECS, DEFAULT_SESSION_TTL_SECS};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use vault_transport::audit::{Actor, ActorKind, AuditEvent, Outcome, Target};
use vault_transport::ResidencyGroup;

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

/// Lowercase UUIDv4 check (Vulture organization_id), without pulling a uuid crate.
fn is_uuid_v4_lower(s: &str) -> bool {
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
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/sys/seal-status", get(seal_status))
        .route("/v1/{group}/ssh/ca", get(ssh_ca))
        .route("/v1/{group}/ssh/sign", post(ssh_sign))
        .route("/v1/{group}/{tenant_id}/creds/{role}", post(creds))
        .route("/v1/sys/session", post(session_open))
        .route("/v1/sys/session/{id}", delete(session_end))
        .route("/v1/sys/leases/renew", post(lease_renew))
        .route("/v1/sys/leases/revoke", post(lease_revoke))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

/// Readiness probe (unauthenticated): is the master key unsealed yet? Demon polls this
/// before issuing; mutating ops MAY 503 while sealed.
async fn seal_status(State(state): State<AppState>) -> Json<SealStatus> {
    Json(SealStatus {
        sealed: state.is_sealed(),
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
    })
}

fn not_implemented(what: &str) -> (StatusCode, Json<ErrorBody>) {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "not_implemented",
        &format!("{what} backend lands in the next sub-phase; the contract shape is fixed"),
    )
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

async fn ssh_ca(
    State(state): State<AppState>,
    _principal: Principal,
    Path(group): Path<String>,
) -> ApiResult<crate::dto::SshCaResponse> {
    check_group(&state, &group)?;
    Err(not_implemented("ssh-ca"))
}

async fn ssh_sign(
    State(state): State<AppState>,
    _principal: Principal,
    Path(group): Path<String>,
    Json(_req): Json<SshSignRequest>,
) -> ApiResult<crate::dto::SshSignResponse> {
    check_group(&state, &group)?;
    require_unsealed(&state)?;
    Err(not_implemented("ssh-sign"))
}

async fn creds(
    State(state): State<AppState>,
    _principal: Principal,
    Path((group, tenant_id, _role)): Path<(String, String, String)>,
    Json(_req): Json<CredsRequest>,
) -> ApiResult<crate::dto::CredsResponse> {
    check_group(&state, &group)?;
    require_unsealed(&state)?;
    if !is_uuid_v4_lower(&tenant_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_tenant_id",
            "tenant_id must be a lowercase UUIDv4 (Vulture organization_id)",
        ));
    }
    Err(not_implemented(
        "dynamic-creds (OpenSearch RBAC / RethinkDB)",
    ))
}

fn system_actor(principal: &Principal) -> Actor {
    Actor {
        label: principal.san.clone(),
        kind: ActorKind::System,
        id: Some(principal.role.clone()),
        tenant: None,
    }
}

async fn session_open(
    State(state): State<AppState>,
    principal: Principal,
    Json(req): Json<SessionOpenRequest>,
) -> ApiResult<SessionOpenResponse> {
    require_unsealed(&state)?;
    let ttl = req.ttl_secs.unwrap_or(DEFAULT_SESSION_TTL_SECS);
    let idle = req.idle_timeout_secs.unwrap_or(DEFAULT_SESSION_IDLE_SECS);
    let id = {
        let mut eng = state.leases.lock().expect("lease lock");
        eng.open_session(ttl, idle)
    };
    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(&principal),
        "session.open",
        Target {
            kind: "session".into(),
            id: Some(id.clone()),
        },
        Outcome::Success,
        None,
    ));
    Ok(Json(SessionOpenResponse {
        session_id: id,
        ttl_secs: ttl,
        idle_timeout_secs: idle,
    }))
}

async fn session_end(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<SessionEndResponse> {
    require_unsealed(&state)?;
    let revoked = {
        let mut eng = state.leases.lock().expect("lease lock");
        eng.end_session(&id)
            .map_err(|e| err(StatusCode::NOT_FOUND, "no_such_session", &e.to_string()))?
    };
    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(&principal),
        "session.end",
        Target {
            kind: "session".into(),
            id: Some(id.clone()),
        },
        Outcome::Success,
        None,
    ));
    Ok(Json(SessionEndResponse {
        session_id: id,
        revoked_leases: revoked,
    }))
}

async fn lease_renew(
    State(state): State<AppState>,
    _principal: Principal,
    Json(req): Json<LeaseRenewRequest>,
) -> ApiResult<LeaseRenewResponse> {
    require_unsealed(&state)?;
    let ttl = {
        let mut eng = state.leases.lock().expect("lease lock");
        eng.renew(&req.lease_id, req.increment_secs)
            .map_err(|e| err(StatusCode::CONFLICT, "renew_failed", &e.to_string()))?
    };
    Ok(Json(LeaseRenewResponse {
        lease_id: req.lease_id,
        ttl_secs: ttl,
    }))
}

async fn lease_revoke(
    State(state): State<AppState>,
    principal: Principal,
    Json(req): Json<LeaseRevokeRequest>,
) -> ApiResult<Ack> {
    require_unsealed(&state)?;
    {
        let mut eng = state.leases.lock().expect("lease lock");
        eng.revoke(&req.lease_id)
            .map_err(|e| err(StatusCode::CONFLICT, "revoke_failed", &e.to_string()))?;
    }
    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(&principal),
        "lease.revoke",
        Target {
            kind: "lease".into(),
            id: Some(req.lease_id),
        },
        Outcome::Success,
        None,
    ));
    Ok(Json(Ack { ok: true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v4_validation() {
        assert!(is_uuid_v4_lower("11111111-1111-4111-8111-111111111111"));
        assert!(!is_uuid_v4_lower("11111111-1111-1111-8111-111111111111")); // not v4
        assert!(!is_uuid_v4_lower("11111111-1111-4111-c111-111111111111")); // bad variant
        assert!(!is_uuid_v4_lower("11111111-1111-4111-8111-11111111111A")); // uppercase
        assert!(!is_uuid_v4_lower("short"));
    }
}
