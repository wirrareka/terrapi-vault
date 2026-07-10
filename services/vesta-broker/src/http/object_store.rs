//! Object-store presign endpoints (SigV4 presigned URLs for DO Spaces).
use super::{err, is_uuid_v4_lower, require_audit, require_cap, system_actor, ApiResult, Group};
use crate::auth::{Capability, Principal};
use crate::state::{now_unix, AppState};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use vesta_transport::audit::{AuditEvent, Outcome, Target};

/// Sign a short-TTL presigned **PUT** URL for a tile archive or its manifest pointer (the publish
/// path, cap `object-store`; consumer proximiio-outer-map). See [`do_presign`].
pub(crate) async fn presign(
    State(state): State<AppState>,
    principal: Principal,
    _group: Group,
    Json(req): Json<crate::dto::PresignRequest>,
) -> ApiResult<crate::dto::PresignResponse> {
    do_presign(
        &state,
        &principal,
        &req,
        Capability::ObjectStore,
        "PUT",
        "object_store.presign",
    )
}

/// Sign a short-TTL presigned **GET** URL for the same keys (the serve/read path, cap
/// `object-store-read`; consumer proximiio-belt). The `Range` header is unsigned, so the URL
/// serves range-GETs unchanged. See [`do_presign`].
pub(crate) async fn presign_get(
    State(state): State<AppState>,
    principal: Principal,
    _group: Group,
    Json(req): Json<crate::dto::PresignRequest>,
) -> ApiResult<crate::dto::PresignResponse> {
    do_presign(
        &state,
        &principal,
        &req,
        Capability::ObjectStoreRead,
        "GET",
        "object_store.presign_get",
    )
}

/// Shared presign logic for the PUT (publish) and GET (serve) ops. **Stateless** — no lease: the
/// URL authorises exactly one `method` request to one server-constructed key until it expires,
/// and nothing else (DO Spaces has no per-key API, so the per-tenant / single-object scoping lives
/// in the signature). `cap` gates it; residency is enforced by the `Group` extractor (the bucket
/// is per-instance). See `object_store.rs` + `inbox/vault/proximiio-outer-map-object-storage-creds.md`.
pub(crate) fn do_presign(
    state: &AppState,
    principal: &Principal,
    req: &crate::dto::PresignRequest,
    cap: Capability,
    method: &str,
    action: &'static str,
) -> ApiResult<crate::dto::PresignResponse> {
    require_cap(principal, cap)?;
    let Some(signer) = state.object_store.clone() else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_configured",
            "object-store presign is not configured on this instance",
        ));
    };
    if !is_uuid_v4_lower(&req.tenant_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_tenant_id",
            "tenant_id must be a lowercase UUIDv4 (Vulture organization_id)",
        ));
    }
    if !is_safe_segment(&req.map_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_map_id",
            "map_id must be 1-128 chars of [A-Za-z0-9._-] and not '.'/'..'",
        ));
    }
    let kind = match req.kind {
        crate::dto::PresignKind::Archive => crate::object_store::Kind::Archive,
        crate::dto::PresignKind::Manifest => crate::object_store::Kind::Manifest,
    };
    // `version` only appears in the archive key; validate it where it's used.
    if matches!(kind, crate::object_store::Kind::Archive) && !is_safe_segment(&req.version) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_version",
            "version must be 1-128 chars of [A-Za-z0-9._-] and not '.'/'..'",
        ));
    }

    let key = crate::object_store::ObjectStoreSigner::object_key(
        kind,
        &req.tenant_id,
        &req.map_id,
        &req.version,
    );
    let ttl = signer.clamp_ttl(req.ttl_secs);
    let (url, expires) = signer.presign(method, &key, now_unix(), ttl);

    // Audit the issuance fail-closed — the object key + tenant + expiry only. NEVER the URL or
    // signature. A signed URL is not returned unless its issuance is durably recorded.
    require_audit(
        state,
        &AuditEvent::vault(
            AppState::now_ts(),
            state.cfg.node.clone(),
            Some(state.cfg.residency_group.as_str().to_owned()),
            system_actor(principal),
            action,
            Target {
                kind: "object-store".into(),
                id: Some(format!(
                    "key={key};tenant={};expires={expires}",
                    req.tenant_id
                )),
            },
            Outcome::Success,
            None,
        ),
    )?;

    Ok(Json(crate::dto::PresignResponse {
        url,
        method: method.to_owned(),
        key,
        expires,
    }))
}

/// A single object-key path component: non-empty, ≤128 of `[A-Za-z0-9._-]`, and not `.`/`..`
/// — so a caller can't escape its server-constructed prefix (`/` is already off the charset).
pub(crate) fn is_safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

// --- Observe (read-only operator observability; the vesta-console plane) --------------
// All `observe`-capped, read-only, NOT seal-gated (observing a sealed broker is valid). These
// surface in-process STATE only — never a secret value.
