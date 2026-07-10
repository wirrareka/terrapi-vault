//! Leased service-admin cred issuance (creds cap) + teardown/audit plumbing.
use super::{
    backend, err, is_uuid_v4_lower, require_cap, require_unsealed, system_actor, ApiResult, Group,
};
use crate::auth::{Capability, Principal};
use crate::dto::{CredsRequest, ErrorBody};
use crate::state::{now_unix, AppState, CREDS_DEFAULT_TTL_SECS};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vesta_transport::audit::{AuditEvent, Outcome, Target};
use vesta_transport::lock::MutexExt;

pub(crate) async fn creds(
    State(state): State<AppState>,
    principal: Principal,
    Path((_group, tenant_id, role)): Path<(String, String, String)>,
    _group_check: Group,
    Json(req): Json<CredsRequest>,
) -> ApiResult<crate::dto::CredsResponse> {
    require_cap(&principal, Capability::Creds)?;
    require_unsealed(&state)?;
    if !is_uuid_v4_lower(&tenant_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_tenant_id",
            "tenant_id must be a lowercase UUIDv4 (Vulture organization_id)",
        ));
    }
    // Unknown role (or no engine wired for it in this instance) → 404, structurally
    // indistinguishable from an unprovisioned path (no oracle on which roles exist).
    if state.engines.get(&role).is_none() {
        return Err(err(
            StatusCode::NOT_FOUND,
            "unknown_role",
            "no credential engine for this role in this instance",
        ));
    }

    // Every issued cred is a child of the caller's active session.
    let Some(session_id) = state.active_session(&principal.san) else {
        return Err(err(
            StatusCode::CONFLICT,
            "no_active_session",
            "open a session (POST /v1/sys/session) before issuing credentials",
        ));
    };

    let ttl = req.ttl_secs.unwrap_or(CREDS_DEFAULT_TTL_SECS);

    // Create the ephemeral backend user first; if the lease can't be bound afterwards we
    // tear it back down so no user outlives a missing lease.
    let issued = state
        .engines
        .get(&role)
        .expect("engine present (checked above)")
        .issue(&tenant_id, ttl)
        .await
        .map_err(|e| backend("creds issue", e))?;

    // Reserve the lease AND register its revoke handle under one hold of the leases lock (both
    // ops are synchronous — no await inside). The sweeper takes the leases lock to sweep before
    // it tears creds down, so it cannot revoke this lease in the gap before its handle exists —
    // which would otherwise orphan the backend user (teardown would find no handle to revoke).
    // Lock order here is leases→cred_handles; the sweeper releases leases before taking
    // cred_handles and teardown never takes leases, so there is no deadlock.
    let lease_id = {
        let mut eng = state.leases.lock_recover();
        match eng.issue_lease(now_unix(), &session_id, ttl, issued.max_ttl_secs, true) {
            Ok(lease_id) => {
                state.cred_handles.lock_recover().insert(
                    lease_id.clone(),
                    crate::creds::CredHandle {
                        role: role.clone(),
                        username: issued.username.clone(),
                    },
                );
                Some(lease_id)
            }
            Err(_) => None,
        }
    };
    let Some(lease_id) = lease_id else {
        // session ended between the active-session check and issue → undo the user (the leases
        // lock is already released here, so this async revoke holds no guard).
        let _ = state
            .engines
            .get(&role)
            .expect("engine present")
            .revoke(&issued.username)
            .await;
        return Err(err(
            StatusCode::CONFLICT,
            "no_active_session",
            "the operator session has ended",
        ));
    };

    // Fail closed: if the issuance can't be durably audited, revoke the lease + delete the
    // just-created backend user — no credential is returned without an audit record.
    audit_creds_issue_or_teardown(&state, &principal, &role, &tenant_id, &lease_id).await?;

    Ok(Json(crate::dto::CredsResponse {
        username: issued.username,
        password: issued.password,
        lease_id,
        ttl_secs: ttl,
        renewable: true,
        max_ttl_secs: issued.max_ttl_secs,
    }))
}

/// Emit the `creds.issue` event fail-closed. On a durable-audit failure, revoke the lease and
/// delete the just-created backend user, then return `503` — no credential is handed out without
/// an audit record. `Ok(())` once the issuance is durably recorded.
pub(crate) async fn audit_creds_issue_or_teardown(
    state: &AppState,
    principal: &Principal,
    role: &str,
    tenant_id: &str,
    lease_id: &str,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let audited = state.try_emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(principal),
        "creds.issue",
        Target {
            kind: "creds".into(),
            id: Some(format!("role={role};tenant={tenant_id};lease={lease_id}")),
        },
        Outcome::Success,
        None,
    ));
    if audited.is_ok() {
        return Ok(());
    }
    let lid = lease_id.to_owned();
    {
        let mut eng = state.leases.lock_recover();
        let _ = eng.revoke(&lid);
    }
    tear_down_creds(state, principal, std::slice::from_ref(&lid)).await;
    Err(err(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
        "issuance refused: the audit record could not be durably written",
    ))
}

pub(crate) async fn tear_down_creds(state: &AppState, principal: &Principal, revoked: &[String]) {
    let torn = crate::creds::teardown(&state.engines, &state.cred_handles, revoked).await;
    for t in torn {
        state.emit(&AuditEvent::vault(
            AppState::now_ts(),
            state.cfg.node.clone(),
            Some(state.cfg.residency_group.as_str().to_owned()),
            system_actor(principal),
            "creds.revoke",
            Target {
                kind: "creds".into(),
                id: Some(format!("role={}", t.role)),
            },
            if t.outcome_ok {
                Outcome::Success
            } else {
                Outcome::Failure
            },
            None,
        ));
    }
}
