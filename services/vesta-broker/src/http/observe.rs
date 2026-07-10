//! Read-only observe API (observe cap): state only, never secret values.
use super::{internal, require_cap, ApiResult, Group};
use crate::auth::{Capability, Principal};
use crate::state::{now_unix, AppState};
use axum::extract::{Query, State};
use axum::Json;
use vesta_transport::lock::MutexExt;

/// Active leases: id, parent session, expiry/ceiling, renewable, and (for cred leases) the role.
pub(crate) async fn observe_leases(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<crate::dto::ObserveLeasesResponse> {
    require_cap(&principal, Capability::Observe)?;
    let now = now_unix();
    let roles = state.cred_roles();
    let active = {
        let eng = state.leases.lock_recover();
        eng.active_leases(now)
    };
    let leases = active
        .into_iter()
        .map(|l| crate::dto::ObserveLease {
            role: roles.get(&l.id).cloned(),
            lease_id: l.id,
            parent_session: l.parent_session,
            expires_at: l.expires_at,
            max_deadline: l.max_deadline,
            renewable: l.renewable,
        })
        .collect();
    Ok(Json(crate::dto::ObserveLeasesResponse { now, leases }))
}

/// Active operator sessions: id, bound principal SAN (if known), expiry/idle, child-lease count.
pub(crate) async fn observe_sessions(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<crate::dto::ObserveSessionsResponse> {
    require_cap(&principal, Capability::Observe)?;
    let now = now_unix();
    let san_by_sid: std::collections::HashMap<String, String> = state
        .list_sessions()
        .into_iter()
        .map(|(san, sid)| (sid, san))
        .collect();
    let active = {
        let eng = state.leases.lock_recover();
        eng.active_sessions(now)
    };
    let sessions = active
        .into_iter()
        .map(|s| crate::dto::ObserveSession {
            principal: san_by_sid.get(&s.id).cloned(),
            session_id: s.id,
            expires_at: s.expires_at,
            idle_deadline: s.idle_deadline,
            child_count: s.child_count,
        })
        .collect();
    Ok(Json(crate::dto::ObserveSessionsResponse { now, sessions }))
}

/// Registered principals: SAN → {role, caps} (the loaded `VESTA_ROLES_CONFIG`). Non-secret.
pub(crate) async fn observe_roles(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<crate::dto::ObserveRolesResponse> {
    require_cap(&principal, Capability::Observe)?;
    let mut roles: Vec<crate::dto::ObserveRole> = state
        .cfg
        .roles
        .iter()
        .map(|(san, rp)| {
            let mut caps: Vec<String> = rp.caps.iter().map(|c| c.as_str().to_owned()).collect();
            caps.sort();
            crate::dto::ObserveRole {
                san: san.clone(),
                role: rp.role.clone(),
                caps,
            }
        })
        .collect();
    roles.sort_by(|a, b| a.san.cmp(&b.san));
    Ok(Json(crate::dto::ObserveRolesResponse { roles }))
}

/// Issued SSH cert serials (tracked against live leases) + the CA revocation list. Group-scoped.
pub(crate) async fn observe_ssh(
    State(state): State<AppState>,
    principal: Principal,
    _group: Group,
) -> ApiResult<crate::dto::ObserveSshResponse> {
    require_cap(&principal, Capability::Observe)?;
    let issued = state
        .list_ssh_serials()
        .into_iter()
        .map(|(lease_id, serial)| crate::dto::ObserveSshSerial { lease_id, serial })
        .collect();
    let revoked = match &state.store {
        Some(s) => {
            let v = s.lock_recover();
            crate::ssh_ca::list_revoked(&v)
                .map_err(|e| internal("store_error", "ssh revoked", e))?
        }
        None => Vec::new(), // sealed → store closed → nothing to list
    };
    Ok(Json(crate::dto::ObserveSshResponse { issued, revoked }))
}

/// KMS KEK inventory for this group — identity + current version only, never key bytes. Group-scoped.
pub(crate) async fn observe_kms(
    State(state): State<AppState>,
    principal: Principal,
    _group: Group,
) -> ApiResult<crate::dto::ObserveKmsResponse> {
    require_cap(&principal, Capability::Observe)?;
    let group = state.cfg.residency_group.as_str();
    let raw = match &state.store {
        Some(s) => {
            let v = s.lock_recover();
            crate::kms::list_keys(&v, group).map_err(|e| internal("store_error", "kms list", e))?
        }
        None => Vec::new(),
    };
    let keys = raw
        .into_iter()
        .map(
            |(tenant_id, key_id, current_version)| crate::dto::ObserveKmsKey {
                tenant_id,
                key_id,
                current_version,
            },
        )
        .collect();
    Ok(Json(crate::dto::ObserveKmsResponse { keys }))
}

/// Whether object-store presign is configured on this broker. Group-scoped.
pub(crate) async fn observe_object_store(
    State(state): State<AppState>,
    principal: Principal,
    _group: Group,
) -> ApiResult<crate::dto::ObserveObjectStoreResponse> {
    require_cap(&principal, Capability::Observe)?;
    Ok(Json(crate::dto::ObserveObjectStoreResponse {
        configured: state.object_store.is_some(),
    }))
}

/// Query for the audit tail: `?since=<seq>&limit=<n>`.
#[derive(serde::Deserialize)]
pub(crate) struct AuditQuery {
    #[serde(default)]
    since: u64,
    limit: Option<usize>,
}

/// Tail of the local hash-chained B3 audit (`seq >= since`, capped). Already redacted at emit —
/// never secret material. Reads the broker's own chain file directly (source of truth).
pub(crate) async fn observe_audit(
    State(state): State<AppState>,
    principal: Principal,
    Query(q): Query<AuditQuery>,
) -> ApiResult<crate::dto::ObserveAuditResponse> {
    require_cap(&principal, Capability::Observe)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let records: Vec<crate::dto::ObserveAuditRecord> =
        vesta_transport::audit::read_tail(&state.cfg.audit_path, q.since, limit)
            .into_iter()
            .map(|t| crate::dto::ObserveAuditRecord {
                seq: t.seq,
                event: t.event,
            })
            .collect();
    let next_seq = records.last().map_or(q.since, |r| r.seq + 1);
    Ok(Json(crate::dto::ObserveAuditResponse { records, next_seq }))
}
