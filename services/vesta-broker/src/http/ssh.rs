//! SSH signed-cert CA endpoints: CA pubkey, revocation list, cert signing.
use super::{
    err, internal, is_uuid_v4_lower, require_cap, require_unsealed, rfc3339, system_actor,
    ApiResult, Group,
};
use crate::auth::{Capability, Principal};
use crate::dto::SshSignRequest;
use crate::state::{now_unix, AppState, SSH_CERT_MAX_TTL_SECS, SSH_CERT_TTL_INTERACTIVE_SECS};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ssh_key::certificate::CertType;
use vesta_transport::audit::{AuditEvent, Outcome, Target};
use vesta_transport::lock::MutexExt;

pub(crate) async fn ssh_ca(
    State(state): State<AppState>,
    principal: Principal,
    _group: Group,
) -> ApiResult<crate::dto::SshCaResponse> {
    require_cap(&principal, Capability::SshCa)?;
    let Some(ca) = state.ssh_ca.clone() else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "sealed",
            "broker is sealed; the SSH CA is unavailable until it is unsealed",
        ));
    };
    Ok(Json(crate::dto::SshCaResponse {
        ca_public_key: ca.public_openssh(),
    }))
}

pub(crate) async fn ssh_revoked(
    State(state): State<AppState>,
    principal: Principal,
    _group: Group,
) -> ApiResult<crate::dto::SshRevokedResponse> {
    require_cap(&principal, Capability::SshCa)?;
    let Some(store) = state.store.clone() else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "sealed",
            "broker is sealed",
        ));
    };
    let revoked_serials = {
        let v = store.lock_recover();
        crate::ssh_ca::list_revoked(&v)
    }
    .map_err(|e| internal("store_error", "ssh revoked-list read", e))?;
    Ok(Json(crate::dto::SshRevokedResponse { revoked_serials }))
}

// Validation + session-bound lease + sign + audit in one place; reads linearly.
#[allow(clippy::too_many_lines)]
pub(crate) async fn ssh_sign(
    State(state): State<AppState>,
    principal: Principal,
    _group: Group,
    Json(req): Json<SshSignRequest>,
) -> ApiResult<crate::dto::SshSignResponse> {
    require_cap(&principal, Capability::SshSign)?;
    require_unsealed(&state)?;
    let Some(ca) = state.ssh_ca.clone() else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "sealed",
            "broker is sealed",
        ));
    };

    // Host certs are group-scoped: they must not carry a tenant. User certs may.
    let cert_type = match req.cert_type {
        crate::dto::CertType::User => CertType::User,
        crate::dto::CertType::Host => CertType::Host,
    };
    if matches!(req.cert_type, crate::dto::CertType::Host) && req.tenant_id.is_some() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "host_cert_tenant",
            "cert_type=host is group-scoped and must have a null tenant_id",
        ));
    }
    if let Some(t) = &req.tenant_id {
        if !is_uuid_v4_lower(t) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "bad_tenant_id",
                "tenant_id must be a lowercase UUIDv4 (Vulture organization_id)",
            ));
        }
    }

    // Per-role SSH principal allowlist: a role may only mint certs for the cert subject
    // principals it is configured for, so an `ssh-sign` role cannot request `root` or an
    // arbitrary user/host. No-op when the role has no allowlist (legacy / dev).
    if !principal.allows_ssh_principals(&req.principals) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "principal_not_allowed",
            "a requested SSH principal is not in this role's allowlist",
        ));
    }

    // Every issued cred is a child of the caller's active session.
    let Some(session_id) = state.active_session(&principal.san) else {
        return Err(err(
            StatusCode::CONFLICT,
            "no_active_session",
            "open a session (POST /v1/sys/session) before issuing certificates",
        ));
    };

    // Clamp to the hard ceiling: a signed cert outlives lease revoke (KRL is best-effort), so
    // the requested ttl must not be able to exceed SSH_CERT_MAX_TTL_SECS (short-TTL guarantee).
    let ttl = req
        .ttl_secs
        .unwrap_or(SSH_CERT_TTL_INTERACTIVE_SECS)
        .clamp(1, SSH_CERT_MAX_TTL_SECS);
    let now = now_unix();
    let valid_before = now.saturating_add(ttl);

    // Reserve the lease first (binds to the session / 409 if it ended), then sign; if
    // signing fails, revoke the orphan so no dangling lease remains.
    let lease_id = {
        let mut eng = state.leases.lock_recover();
        eng.issue_lease(now, &session_id, ttl, ttl, false)
    }
    .map_err(|_| {
        err(
            StatusCode::CONFLICT,
            "no_active_session",
            "the operator session has ended",
        )
    })?;

    let key_id = format!(
        "{}|tenant={}",
        principal.san,
        req.tenant_id.as_deref().unwrap_or("-")
    );
    let signed = match ca.sign(
        &req.public_key,
        cert_type,
        &req.principals,
        &key_id,
        now,
        valid_before,
    ) {
        Ok(s) => s,
        Err(e) => {
            let mut eng = state.leases.lock_recover();
            let _ = eng.revoke(&lease_id);
            return Err(match e {
                crate::ssh_ca::CaError::BadRequest(m) => {
                    err(StatusCode::BAD_REQUEST, "bad_request", &m)
                }
                other => internal("sign_failed", "ssh sign", other),
            });
        }
    };

    // Remember the serial so revoking/expiring this lease can record it in the CA's
    // revocation list.
    state.record_ssh_serial(&lease_id, signed.serial);

    // Fail closed: if the issuance can't be durably audited, do NOT hand the cert to the client —
    // revoke its lease and put the serial on the KRL so the (already-minted) cert is short-lived
    // and revoked. No credential leaves the broker without an audit record.
    if state
        .try_emit(&AuditEvent::vault(
            AppState::now_ts(),
            state.cfg.node.clone(),
            Some(state.cfg.residency_group.as_str().to_owned()),
            system_actor(&principal),
            "ssh.sign",
            Target {
                kind: "ssh-cert".into(),
                id: Some(format!("serial={}", signed.serial)),
            },
            Outcome::Success,
            None,
        ))
        .is_err()
    {
        {
            let mut eng = state.leases.lock_recover();
            let _ = eng.revoke(&lease_id);
        }
        record_revoked_ssh(&state, std::slice::from_ref(&lease_id));
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "issuance refused: the audit record could not be durably written",
        ));
    }

    Ok(Json(crate::dto::SshSignResponse {
        signed_certificate: signed.openssh,
        serial: signed.serial,
        valid_before: rfc3339(signed.valid_before),
        lease_id,
    }))
}

/// Delete the backend users owned by `revoked` cred leases and emit a `creds.revoke`
/// event per torn-down handle. SSH-cert leases (no backend user) are skipped.
/// Record the SSH cert serials owned by `revoked` leases in the CA revocation list.
pub(crate) fn record_revoked_ssh(state: &AppState, revoked: &[String]) {
    let serials = state.take_ssh_serials(revoked);
    if serials.is_empty() {
        return;
    }
    if let Some(store) = state.store.clone() {
        let now = AppState::now_ts();
        let v = store.lock_recover();
        if let Err(e) = crate::ssh_ca::record_revoked(&v, &serials, &now) {
            eprintln!("vesta-broker: failed to record revoked SSH serials: {e}");
        }
    }
}
