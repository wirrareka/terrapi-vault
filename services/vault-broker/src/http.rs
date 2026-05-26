//! v1 broker HTTP surface (axum). All v1 ops are implemented: sessions + leases (against
//! the lease engine), the SSH-CA (`ssh/ca`, `ssh/sign`), and dynamic creds (`creds`, via
//! the OpenSearch engine). Issuance is session-bound + sealed-gated; every state-changing
//! op emits a B3 audit event (`source:"vault"`).

use crate::auth::{Capability, Principal};
use crate::dto::{
    Ack, CredsRequest, ErrorBody, KmsRotateResponse, KmsUnwrapRequest, KmsUnwrapResponse,
    KmsWrapRequest, KmsWrapResponse, LeaseRenewRequest, LeaseRenewResponse, LeaseRevokeRequest,
    SealStatus, SessionEndResponse, SessionOpenRequest, SessionOpenResponse, SshSignRequest,
};
use base64::Engine as _;
use crate::state::{
    now_unix, AppState, CREDS_DEFAULT_TTL_SECS, DEFAULT_SESSION_IDLE_SECS,
    DEFAULT_SESSION_TTL_SECS, SSH_CERT_TTL_INTERACTIVE_SECS,
};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use ssh_key::certificate::CertType;
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
        .route("/v1/{group}/ssh/revoked", get(ssh_revoked))
        .route("/v1/{group}/ssh/sign", post(ssh_sign))
        .route("/v1/{group}/{tenant_id}/creds/{role}", post(creds))
        .route("/v1/{group}/{tenant_id}/kms/{key_id}/wrap", post(kms_wrap))
        .route("/v1/{group}/{tenant_id}/kms/{key_id}/unwrap", post(kms_unwrap))
        .route("/v1/{group}/{tenant_id}/kms/{key_id}/rotate", post(kms_rotate))
        .route("/v1/sys/session", post(session_open))
        .route("/v1/sys/session/{id}", delete(session_end))
        .route("/v1/sys/store-snapshot", post(store_snapshot))
        .route("/v1/sys/leases/renew", post(lease_renew))
        .route("/v1/sys/leases/revoke", post(lease_revoke))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

/// Loopback-only metrics router (`8201`): Prometheus text, no auth (WG/loopback bound).
pub fn metrics_router(state: AppState) -> Router {
    Router::new().route("/metrics", get(metrics)).with_state(state)
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

async fn ssh_ca(
    State(state): State<AppState>,
    principal: Principal,
    Path(group): Path<String>,
) -> ApiResult<crate::dto::SshCaResponse> {
    require_cap(&principal, Capability::SshCa)?;
    check_group(&state, &group)?;
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

async fn ssh_revoked(
    State(state): State<AppState>,
    principal: Principal,
    Path(group): Path<String>,
) -> ApiResult<crate::dto::SshRevokedResponse> {
    require_cap(&principal, Capability::SshCa)?;
    check_group(&state, &group)?;
    let Some(store) = state.store.clone() else {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "sealed", "broker is sealed"));
    };
    let revoked_serials = {
        let v = store.lock().expect("store lock");
        crate::ssh_ca::list_revoked(&v)
    }
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "store_error", &e.to_string()))?;
    Ok(Json(crate::dto::SshRevokedResponse { revoked_serials }))
}

async fn ssh_sign(
    State(state): State<AppState>,
    principal: Principal,
    Path(group): Path<String>,
    Json(req): Json<SshSignRequest>,
) -> ApiResult<crate::dto::SshSignResponse> {
    require_cap(&principal, Capability::SshSign)?;
    check_group(&state, &group)?;
    require_unsealed(&state)?;
    let Some(ca) = state.ssh_ca.clone() else {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "sealed", "broker is sealed"));
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

    // Every issued cred is a child of the caller's active session.
    let Some(session_id) = state.active_session(&principal.san) else {
        return Err(err(
            StatusCode::CONFLICT,
            "no_active_session",
            "open a session (POST /v1/sys/session) before issuing certificates",
        ));
    };

    let ttl = req.ttl_secs.unwrap_or(SSH_CERT_TTL_INTERACTIVE_SECS);
    let now = now_unix();
    let valid_before = now.saturating_add(ttl);

    // Reserve the lease first (binds to the session / 409 if it ended), then sign; if
    // signing fails, revoke the orphan so no dangling lease remains.
    let lease_id = {
        let mut eng = state.leases.lock().expect("lease lock");
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
    let signed = match ca.sign(&req.public_key, cert_type, &req.principals, &key_id, now, valid_before)
    {
        Ok(s) => s,
        Err(e) => {
            let mut eng = state.leases.lock().expect("lease lock");
            let _ = eng.revoke(&lease_id);
            return Err(match e {
                crate::ssh_ca::CaError::BadRequest(m) => err(StatusCode::BAD_REQUEST, "bad_request", &m),
                other => err(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed", &other.to_string()),
            });
        }
    };

    // Remember the serial so revoking/expiring this lease can record it in the CA's
    // revocation list.
    state.record_ssh_serial(&lease_id, signed.serial);

    state.emit(&AuditEvent::vault(
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
    ));

    Ok(Json(crate::dto::SshSignResponse {
        signed_certificate: signed.openssh,
        serial: signed.serial,
        valid_before: rfc3339(signed.valid_before),
        lease_id,
    }))
}

async fn store_snapshot(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<crate::dto::StoreSnapshotResponse> {
    require_cap(&principal, Capability::Snapshot)?;
    require_unsealed(&state)?;
    let Some(store) = state.store.clone() else {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "sealed", "broker is sealed"));
    };
    if let Err(e) = std::fs::create_dir_all(&state.cfg.snapshot_dir) {
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "store_error", &e.to_string()));
    }
    let snap_path = state.cfg.snapshot_dir.join(format!(
        "vault-store-{}-{}.sqlcipher",
        state.cfg.residency_group.as_str(),
        now_unix()
    ));
    let snap_str = snap_path.to_string_lossy().to_string();

    // Online, consistent snapshot — SQLCipher copies under the same key (ciphertext).
    {
        let v = store.lock().expect("store lock");
        v.with_connection(|c| c.execute("VACUUM INTO ?1", [snap_str.as_str()]).map(|_| ()))
    }
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "snapshot_failed", &e.to_string()))?;

    let data = std::fs::read(&snap_path)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "store_error", &e.to_string()))?;
    let sha256 = {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;
        let d = Sha256::digest(&data);
        let mut s = String::with_capacity(64);
        for b in d {
            let _ = write!(s, "{b:02x}");
        }
        s
    };
    let bytes = data.len() as u64;
    let meta_path = terrapi_vault::meta_path_for(&state.cfg.store_path)
        .to_string_lossy()
        .to_string();

    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(&principal),
        "store.snapshot",
        Target {
            kind: "store".into(),
            id: Some(snap_str.clone()),
        },
        Outcome::Success,
        None,
    ));

    Ok(Json(crate::dto::StoreSnapshotResponse {
        snapshot_path: snap_str,
        meta_path,
        sha256,
        bytes,
    }))
}

/// RFC3339 UTC rendering of a unix-seconds timestamp (for `valid_before` in the response).
fn rfc3339(unix_secs: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    i64::try_from(unix_secs)
        .ok()
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

async fn creds(
    State(state): State<AppState>,
    principal: Principal,
    Path((group, tenant_id, role)): Path<(String, String, String)>,
    Json(req): Json<CredsRequest>,
) -> ApiResult<crate::dto::CredsResponse> {
    require_cap(&principal, Capability::Creds)?;
    check_group(&state, &group)?;
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
        .map_err(|e| err(StatusCode::BAD_GATEWAY, "backend_error", &e.to_string()))?;

    let issued_lease = {
        let mut eng = state.leases.lock().expect("lease lock");
        eng.issue_lease(now_unix(), &session_id, ttl, issued.max_ttl_secs, true)
    };
    let Ok(lease_id) = issued_lease else {
        // session ended between the active-session check and issue → undo the user
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

    state.cred_handles.lock().expect("cred handles lock").insert(
        lease_id.clone(),
        crate::creds::CredHandle {
            role: role.clone(),
            username: issued.username.clone(),
        },
    );

    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(&principal),
        "creds.issue",
        Target {
            kind: "creds".into(),
            id: Some(format!("role={role};tenant={tenant_id};lease={lease_id}")),
        },
        Outcome::Success,
        None,
    ));

    Ok(Json(crate::dto::CredsResponse {
        username: issued.username,
        password: issued.password,
        lease_id,
        ttl_secs: ttl,
        renewable: true,
        max_ttl_secs: issued.max_ttl_secs,
    }))
}

/// Backup-target key id: a short, filesystem/DB-safe token (the aether `target_id`).
fn is_valid_key_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Common validation for the KMS ops: capability, group, unsealed, tenant UUIDv4, key_id.
/// Returns the unsealed store on success.
fn kms_preflight(
    state: &AppState,
    principal: &Principal,
    group: &str,
    tenant_id: &str,
    key_id: &str,
) -> Result<std::sync::Arc<std::sync::Mutex<terrapi_vault::Vault>>, (StatusCode, Json<ErrorBody>)> {
    require_cap(principal, Capability::Kms)?;
    check_group(state, group)?;
    require_unsealed(state)?;
    if !is_uuid_v4_lower(tenant_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_tenant_id",
            "tenant_id must be a lowercase UUIDv4 (Vulture organization_id)",
        ));
    }
    if !is_valid_key_id(key_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_key_id",
            "key_id must be 1-128 chars of [A-Za-z0-9._-]",
        ));
    }
    state.store.clone().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "sealed", "broker is sealed")
    })
}

fn map_kms_err(e: crate::kms::KmsError) -> (StatusCode, Json<ErrorBody>) {
    use crate::kms::KmsError;
    match e {
        KmsError::BadInput(m) => err(StatusCode::BAD_REQUEST, "bad_request", &m),
        KmsError::Crypto => err(
            StatusCode::BAD_REQUEST,
            "unwrap_failed",
            "blob did not authenticate under this target's key (wrong target or tampered)",
        ),
        KmsError::Store(m) => err(StatusCode::INTERNAL_SERVER_ERROR, "store_error", &m),
    }
}

async fn kms_wrap(
    State(state): State<AppState>,
    principal: Principal,
    Path((group, tenant_id, key_id)): Path<(String, String, String)>,
    Json(req): Json<KmsWrapRequest>,
) -> ApiResult<KmsWrapResponse> {
    let store = kms_preflight(&state, &principal, &group, &tenant_id, &key_id)?;
    let dek = base64::engine::general_purpose::STANDARD
        .decode(req.dek.as_bytes())
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad_dek", "dek must be valid base64"))?;
    let wrapped = {
        let v = store.lock().expect("store lock");
        crate::kms::wrap(&v, &group, &tenant_id, &key_id, &dek)
    }
    .map_err(map_kms_err)?;

    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(&principal),
        "kms.wrap",
        Target {
            kind: "kms-kek".into(),
            id: Some(format!("{group}/{tenant_id}/{key_id}")),
        },
        Outcome::Success,
        None,
    ));
    Ok(Json(KmsWrapResponse {
        wrapped: base64::engine::general_purpose::STANDARD.encode(wrapped),
        kek_id: format!("{group}/{tenant_id}/{key_id}"),
    }))
}

async fn kms_unwrap(
    State(state): State<AppState>,
    principal: Principal,
    Path((group, tenant_id, key_id)): Path<(String, String, String)>,
    Json(req): Json<KmsUnwrapRequest>,
) -> ApiResult<KmsUnwrapResponse> {
    let store = kms_preflight(&state, &principal, &group, &tenant_id, &key_id)?;
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(req.wrapped.as_bytes())
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad_wrapped", "wrapped must be valid base64"))?;
    let dek = {
        let v = store.lock().expect("store lock");
        crate::kms::unwrap(&v, &group, &tenant_id, &key_id, &wrapped)
    }
    .map_err(map_kms_err)?;

    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(&principal),
        "kms.unwrap",
        Target {
            kind: "kms-kek".into(),
            id: Some(format!("{group}/{tenant_id}/{key_id}")),
        },
        Outcome::Success,
        None,
    ));
    Ok(Json(KmsUnwrapResponse {
        dek: base64::engine::general_purpose::STANDARD.encode(dek),
    }))
}

async fn kms_rotate(
    State(state): State<AppState>,
    principal: Principal,
    Path((group, tenant_id, key_id)): Path<(String, String, String)>,
) -> ApiResult<KmsRotateResponse> {
    let store = kms_preflight(&state, &principal, &group, &tenant_id, &key_id)?;
    let version = {
        let v = store.lock().expect("store lock");
        crate::kms::rotate(&v, &group, &tenant_id, &key_id)
    }
    .map_err(map_kms_err)?;

    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        system_actor(&principal),
        "kms.rotate",
        Target {
            kind: "kms-kek".into(),
            id: Some(format!("{group}/{tenant_id}/{key_id}")),
        },
        Outcome::Success,
        None,
    ));
    Ok(Json(KmsRotateResponse {
        kek_id: format!("{group}/{tenant_id}/{key_id}"),
        version,
    }))
}

fn system_actor(principal: &Principal) -> Actor {
    Actor {
        label: principal.san.clone(),
        kind: ActorKind::System,
        id: Some(principal.role.clone()),
        tenant: None,
    }
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
        let v = store.lock().expect("store lock");
        if let Err(e) = crate::ssh_ca::record_revoked(&v, &serials, &now) {
            eprintln!("vault-broker: failed to record revoked SSH serials: {e}");
        }
    }
}

async fn tear_down_creds(state: &AppState, principal: &Principal, revoked: &[String]) {
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
            if t.outcome_ok { Outcome::Success } else { Outcome::Failure },
            None,
        ));
    }
}

async fn session_open(
    State(state): State<AppState>,
    principal: Principal,
    Json(req): Json<SessionOpenRequest>,
) -> ApiResult<SessionOpenResponse> {
    require_cap(&principal, Capability::Session)?;
    require_unsealed(&state)?;
    let ttl = req.ttl_secs.unwrap_or(DEFAULT_SESSION_TTL_SECS);
    let idle = req.idle_timeout_secs.unwrap_or(DEFAULT_SESSION_IDLE_SECS);
    let id = {
        let mut eng = state.leases.lock().expect("lease lock");
        eng.open_session(now_unix(), ttl, idle)
    };
    state.bind_session(&principal.san, &id);
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
    require_cap(&principal, Capability::Session)?;
    require_unsealed(&state)?;
    let revoked = {
        let mut eng = state.leases.lock().expect("lease lock");
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

async fn lease_renew(
    State(state): State<AppState>,
    principal: Principal,
    Json(req): Json<LeaseRenewRequest>,
) -> ApiResult<LeaseRenewResponse> {
    require_cap(&principal, Capability::Leases)?;
    require_unsealed(&state)?;
    let ttl = {
        let mut eng = state.leases.lock().expect("lease lock");
        eng.renew(now_unix(), &req.lease_id, req.increment_secs)
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
    require_cap(&principal, Capability::Leases)?;
    require_unsealed(&state)?;
    let lease_id = req.lease_id;
    {
        let mut eng = state.leases.lock().expect("lease lock");
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
