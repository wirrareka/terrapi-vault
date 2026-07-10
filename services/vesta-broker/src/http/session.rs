//! Operator sessions and lease lifecycle: open/end, renew/revoke, ownership gate.
use super::{
    err, record_revoked_ssh, require_audit, require_cap, require_unsealed, system_actor,
    tear_down_creds, ApiResult,
};
use crate::auth::{Capability, Principal};
use crate::dto::{
    Ack, ErrorBody, LeaseRenewRequest, LeaseRenewResponse, LeaseRevokeRequest, SessionEndResponse,
    SessionOpenRequest, SessionOpenResponse,
};
use crate::state::{
    now_unix, AppState, DEFAULT_SESSION_IDLE_SECS, DEFAULT_SESSION_TTL_SECS, MAX_SESSION_TTL_SECS,
};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vesta_transport::audit::{AuditEvent, Outcome, Target};
use vesta_transport::lock::MutexExt;

pub(crate) async fn session_open(
    State(state): State<AppState>,
    principal: Principal,
    Json(req): Json<SessionOpenRequest>,
) -> ApiResult<SessionOpenResponse> {
    require_cap(&principal, Capability::Session)?;
    require_unsealed(&state)?;
    // Clamp to hard ceilings so a large request value can't extend a session (and every child
    // SSH/cred lease that inherits its lifetime) past the operator-session cap. Idle ≤ ttl.
    let ttl = req
        .ttl_secs
        .unwrap_or(DEFAULT_SESSION_TTL_SECS)
        .clamp(1, MAX_SESSION_TTL_SECS);
    let idle = req
        .idle_timeout_secs
        .unwrap_or(DEFAULT_SESSION_IDLE_SECS)
        .clamp(1, ttl);
    // One active session per principal: if this SAN already has one, end it (cascade-revoke its
    // child leases + tear down their backend users) before opening the replacement. Otherwise the
    // superseded session and its creds would linger live until TTL/idle expiry.
    if let Some(prev) = state.active_session(&principal.san) {
        let revoked = {
            let mut eng = state.leases.lock_recover();
            eng.end_session(&prev).unwrap_or_default()
        };
        state.unbind_session(&prev);
        tear_down_creds(&state, &principal, &revoked).await;
        record_revoked_ssh(&state, &revoked);
        state.emit(&AuditEvent::vault(
            AppState::now_ts(),
            state.cfg.node.clone(),
            Some(state.cfg.residency_group.as_str().to_owned()),
            system_actor(&principal),
            "session.end",
            Target {
                kind: "session".into(),
                id: Some(prev),
            },
            Outcome::Success,
            None,
        ));
    }
    let id = {
        let mut eng = state.leases.lock_recover();
        eng.open_session(now_unix(), ttl, idle)
    };
    state.bind_session(&principal.san, &id);
    // Fail closed: a session is the parent of every issued credential, so one that can't be
    // durably recorded must not enable issuance. End + unbind the just-opened (child-less) session
    // and refuse. (The rebind teardown above is a revocation — fail-safe — so it stays best-effort.)
    if require_audit(
        &state,
        &AuditEvent::vault(
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
        ),
    )
    .is_err()
    {
        {
            let mut eng = state.leases.lock_recover();
            let _ = eng.end_session(&id);
        }
        state.unbind_session(&id);
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "session refused: the audit record could not be durably written",
        ));
    }
    Ok(Json(SessionOpenResponse {
        session_id: id,
        ttl_secs: ttl,
        idle_timeout_secs: idle,
    }))
}

pub(crate) async fn session_end(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<SessionEndResponse> {
    require_cap(&principal, Capability::Session)?;
    require_unsealed(&state)?;
    // Ownership: a principal may only end its OWN active session. Reject anything else as
    // not-found (don't reveal whether another principal's session id exists).
    if !state.owns_session(&principal.san, &id) {
        return Err(err(
            StatusCode::NOT_FOUND,
            "no_such_session",
            "no such session for this principal",
        ));
    }
    let revoked = {
        let mut eng = state.leases.lock_recover();
        eng.end_session(&id)
            .map_err(|e| err(StatusCode::NOT_FOUND, "no_such_session", &e.to_string()))?
    };
    state.unbind_session(&id);
    // Cascade-revoke deleted child leases in the engine; now delete any backend users
    // those cred leases owned + record any SSH cert serials as revoked.
    tear_down_creds(&state, &principal, &revoked).await;
    record_revoked_ssh(&state, &revoked);
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

/// Ownership gate for a lease op: the lease must be a child of the caller's own active session.
/// `404 no_such_lease` if the lease is unknown OR belongs to another principal — the two are
/// deliberately indistinguishable so a `leases`-capped principal can't probe for others' lease ids.
pub(crate) fn require_lease_owner(
    state: &AppState,
    principal: &Principal,
    lease_id: &str,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let parent = {
        let id = lease_id.to_owned(); // LeaseEngine::lease takes &LeaseId (&String)
        let eng = state.leases.lock_recover();
        eng.lease(&id).map(|l| l.parent_session.clone())
    };
    match parent {
        Some(p) if state.owns_session(&principal.san, &p) => Ok(()),
        _ => Err(err(
            StatusCode::NOT_FOUND,
            "no_such_lease",
            "no such lease for this principal",
        )),
    }
}

pub(crate) async fn lease_renew(
    State(state): State<AppState>,
    principal: Principal,
    Json(req): Json<LeaseRenewRequest>,
) -> ApiResult<LeaseRenewResponse> {
    require_cap(&principal, Capability::Leases)?;
    require_unsealed(&state)?;
    require_lease_owner(&state, &principal, &req.lease_id)?;
    let ttl = {
        let mut eng = state.leases.lock_recover();
        eng.renew(now_unix(), &req.lease_id, req.increment_secs)
            .map_err(|e| err(StatusCode::CONFLICT, "renew_failed", &e.to_string()))?
    };
    Ok(Json(LeaseRenewResponse {
        lease_id: req.lease_id,
        ttl_secs: ttl,
    }))
}

pub(crate) async fn lease_revoke(
    State(state): State<AppState>,
    principal: Principal,
    Json(req): Json<LeaseRevokeRequest>,
) -> ApiResult<Ack> {
    require_cap(&principal, Capability::Leases)?;
    require_unsealed(&state)?;
    require_lease_owner(&state, &principal, &req.lease_id)?;
    let lease_id = req.lease_id;
    {
        let mut eng = state.leases.lock_recover();
        eng.revoke(&lease_id)
            .map_err(|e| err(StatusCode::CONFLICT, "revoke_failed", &e.to_string()))?;
    }
    // If this lease owned a backend user, delete it (emits its own creds.revoke); if it
    // owned an SSH cert, record its serial as revoked.
    tear_down_creds(&state, &principal, std::slice::from_ref(&lease_id)).await;
    record_revoked_ssh(&state, std::slice::from_ref(&lease_id));
    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(&principal),
        "lease.revoke",
        Target {
            kind: "lease".into(),
            id: Some(lease_id),
        },
        Outcome::Success,
        None,
    ));
    Ok(Json(Ack { ok: true }))
}
