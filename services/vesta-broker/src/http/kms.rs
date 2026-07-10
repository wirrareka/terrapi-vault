//! KMS wrap/unwrap/rotate/rewrap + the kms-cap JWT authorization plumbing.
use super::{
    backend, err, internal, is_uuid_v4_lower, require_audit, require_cap, require_unsealed,
    system_actor, ApiResult, Group,
};
use crate::auth::{Capability, Principal};
use crate::dto::{
    ErrorBody, KmsRewrapRequest, KmsRotateResponse, KmsUnwrapRequest, KmsUnwrapResponse,
    KmsWrapRequest, KmsWrapResponse,
};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::Json;
use base64::Engine as _;
use vesta_transport::audit::{AuditEvent, Outcome, Target};
use vesta_transport::lock::MutexExt;

/// Backup-target key id: a short, filesystem/DB-safe token (the aether `target_id`).
pub(crate) fn is_valid_key_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The `Bearer <token>` value from the `Authorization` header, if present and well-formed.
pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Map a kms-JWT rejection to a status (secrets-broker.md §KMS root-of-trust). Token/header
/// failures → `401`; policy failures (scope/residency) → `403`; a JWKS-fetch failure (identity
/// unreachable) → `502` (the bearer may be fine — don't tell the client it's invalid).
pub(crate) fn map_jwt_err(e: crate::jwt::JwtError) -> (StatusCode, Json<ErrorBody>) {
    use crate::jwt::JwtError;
    match e {
        JwtError::Missing => err(
            StatusCode::UNAUTHORIZED,
            "missing_token",
            "kms requires an identity-minted bearer JWT",
        ),
        JwtError::ScopeMissing => err(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "token scope does not include 'kms'",
        ),
        JwtError::ResidencyMismatch => err(
            StatusCode::FORBIDDEN,
            "residency_mismatch",
            "token residency_group does not match this broker",
        ),
        JwtError::BadTenant => err(
            StatusCode::BAD_REQUEST,
            "bad_tenant_id",
            "token tenant_id must be a lowercase UUIDv4",
        ),
        JwtError::Jwks(detail) => backend("kms jwt jwks", detail),
        // header / signature / iss / aud / exp / unknown-kid → terse 401 (no internals leak).
        JwtError::Header(_) | JwtError::UnknownKid | JwtError::Invalid => err(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "kms bearer token rejected",
        ),
    }
}

/// Authorize a kms op. When the kms-JWT verifier is configured (Option J), the `kms` cap is
/// proven **per call** by a valid identity-minted ES256 bearer token whose `tenant_id` equals
/// the request path tenant (a cred for tenant X can only act on X). The mTLS `Principal` still
/// authenticated the channel. When the verifier is NOT configured, kms falls back to the
/// cert-SAN capability (`Capability::Kms`) — the existing aether fleet-backup path.
pub(crate) async fn kms_authorize(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    tenant_id: &str,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    // The mTLS principal must ALWAYS hold the `kms` cap. When the kms-JWT verifier is configured
    // (Option J) the identity-minted bearer is an ADDITIONAL per-call, per-tenant proof — not a
    // replacement for the channel's role grant. Without this, any registered SAN holding a stolen
    // tenant JWT could wrap/unwrap; the cap requirement keeps it to SANs explicitly granted kms.
    require_cap(principal, Capability::Kms)?;
    let Some(verifier) = state.kms_jwt.as_ref() else {
        return Ok(());
    };
    let token = bearer(headers).ok_or_else(|| map_jwt_err(crate::jwt::JwtError::Missing))?;
    let grant = verifier.verify(token).await.map_err(map_jwt_err)?;
    if grant.tenant_id != tenant_id {
        return Err(err(
            StatusCode::FORBIDDEN,
            "tenant_mismatch",
            "token tenant_id does not match the request path tenant",
        ));
    }
    Ok(())
}

/// Common preflight for the KMS ops: authorize (JWT or cap), unsealed, tenant UUIDv4, key_id.
/// The `:group` segment is validated upstream by the [`Group`] extractor (residency `404`
/// before the body is read), so it is not re-checked here. Returns the unsealed store.
pub(crate) async fn kms_preflight(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    tenant_id: &str,
    key_id: &str,
) -> Result<std::sync::Arc<std::sync::Mutex<terrapi_vesta::Vesta>>, (StatusCode, Json<ErrorBody>)> {
    // Cheap, local checks first so a sealed broker or a malformed tenant/key_id fails fast —
    // without triggering the JWT path's outbound JWKS round-trip to identity (DoS hardening).
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
    // Authorize last — the JWT path (when configured) may hit identity's JWKS over the network.
    kms_authorize(state, principal, headers, tenant_id).await?;
    state.store.clone().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "sealed",
            "broker is sealed",
        )
    })
}

pub(crate) fn map_kms_err(e: crate::kms::KmsError) -> (StatusCode, Json<ErrorBody>) {
    use crate::kms::KmsError;
    match e {
        KmsError::BadInput(m) => err(StatusCode::BAD_REQUEST, "bad_request", &m),
        KmsError::Crypto => err(
            StatusCode::BAD_REQUEST,
            "unwrap_failed",
            "blob did not authenticate under this target's key (wrong target or tampered)",
        ),
        KmsError::Store(m) => internal("store_error", "kms store", m),
    }
}

pub(crate) async fn kms_wrap(
    State(state): State<AppState>,
    principal: Principal,
    Path((group, tenant_id, key_id)): Path<(String, String, String)>,
    _group_check: Group,
    headers: HeaderMap,
    Json(req): Json<KmsWrapRequest>,
) -> ApiResult<KmsWrapResponse> {
    let store = kms_preflight(&state, &principal, &headers, &tenant_id, &key_id).await?;
    let dek = base64::engine::general_purpose::STANDARD
        .decode(req.dek.as_bytes())
        .map_err(|_| {
            err(
                StatusCode::BAD_REQUEST,
                "bad_dek",
                "dek must be valid base64",
            )
        })?;
    let wrapped = {
        let v = store.lock_recover();
        crate::kms::wrap(&v, &group, &tenant_id, &key_id, &dek)
    }
    .map_err(map_kms_err)?;

    require_audit(
        &state,
        &AuditEvent::vault(
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
        ),
    )?;
    Ok(Json(KmsWrapResponse {
        wrapped: base64::engine::general_purpose::STANDARD.encode(wrapped),
        kek_id: format!("{group}/{tenant_id}/{key_id}"),
    }))
}

pub(crate) async fn kms_unwrap(
    State(state): State<AppState>,
    principal: Principal,
    Path((group, tenant_id, key_id)): Path<(String, String, String)>,
    _group_check: Group,
    headers: HeaderMap,
    Json(req): Json<KmsUnwrapRequest>,
) -> ApiResult<KmsUnwrapResponse> {
    let store = kms_preflight(&state, &principal, &headers, &tenant_id, &key_id).await?;
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(req.wrapped.as_bytes())
        .map_err(|_| {
            err(
                StatusCode::BAD_REQUEST,
                "bad_wrapped",
                "wrapped must be valid base64",
            )
        })?;
    let dek = {
        let v = store.lock_recover();
        crate::kms::unwrap(&v, &group, &tenant_id, &key_id, &wrapped)
    }
    .map_err(map_kms_err)?;

    require_audit(
        &state,
        &AuditEvent::vault(
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
        ),
    )?;
    Ok(Json(KmsUnwrapResponse {
        dek: base64::engine::general_purpose::STANDARD.encode(dek),
    }))
}

pub(crate) async fn kms_rotate(
    State(state): State<AppState>,
    principal: Principal,
    Path((group, tenant_id, key_id)): Path<(String, String, String)>,
    _group_check: Group,
    headers: HeaderMap,
) -> ApiResult<KmsRotateResponse> {
    let store = kms_preflight(&state, &principal, &headers, &tenant_id, &key_id).await?;
    let version = {
        let v = store.lock_recover();
        crate::kms::rotate(&v, &group, &tenant_id, &key_id)
    }
    .map_err(map_kms_err)?;

    require_audit(
        &state,
        &AuditEvent::vault(
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
        ),
    )?;
    Ok(Json(KmsRotateResponse {
        kek_id: format!("{group}/{tenant_id}/{key_id}"),
        version,
    }))
}

/// Server-side re-wrap: move a wrapped blob onto the target's current KEK version after a
/// [`kms_rotate`], without the plaintext DEK ever leaving the broker. Drives the ack-gated
/// re-wrap flow (secrets-broker.md §KMS root-of-trust) — a consumer streams its blobs here,
/// then emits `kms.rewrap_complete` once all are migrated so identity can retire the old root.
pub(crate) async fn kms_rewrap(
    State(state): State<AppState>,
    principal: Principal,
    Path((group, tenant_id, key_id)): Path<(String, String, String)>,
    _group_check: Group,
    headers: HeaderMap,
    Json(req): Json<KmsRewrapRequest>,
) -> ApiResult<KmsWrapResponse> {
    let store = kms_preflight(&state, &principal, &headers, &tenant_id, &key_id).await?;
    let wrapped_in = base64::engine::general_purpose::STANDARD
        .decode(req.wrapped.as_bytes())
        .map_err(|_| {
            err(
                StatusCode::BAD_REQUEST,
                "bad_wrapped",
                "wrapped must be valid base64",
            )
        })?;
    let wrapped_out = {
        let v = store.lock_recover();
        crate::kms::rewrap(&v, &group, &tenant_id, &key_id, &wrapped_in)
    }
    .map_err(map_kms_err)?;

    require_audit(
        &state,
        &AuditEvent::vault(
            AppState::now_ts(),
            state.cfg.node.clone(),
            Some(state.cfg.residency_group.as_str().to_owned()),
            system_actor(&principal),
            "kms.rewrap",
            Target {
                kind: "kms-kek".into(),
                id: Some(format!("{group}/{tenant_id}/{key_id}")),
            },
            Outcome::Success,
            None,
        ),
    )?;
    Ok(Json(KmsWrapResponse {
        wrapped: base64::engine::general_purpose::STANDARD.encode(wrapped_out),
        kek_id: format!("{group}/{tenant_id}/{key_id}"),
    }))
}
