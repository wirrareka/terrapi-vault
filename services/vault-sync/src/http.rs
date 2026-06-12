//! vault-sync HTTP surface (axum). Endpoints: account / enroll-challenge / enroll / push /
//! pull / status (+ healthz). Every op-bearing call is device-signed; account + enroll are
//! self-signed by the device key being registered (proves key possession) and enrol is gated
//! by the enrolment proof. See `docs/planning/02-vault-sync-oplog.md`.

use crate::auth::{self, SignedHeaders};
use crate::dto::{
    Ack, CreateAccountRequest, DeviceInfo, DevicesResponse, EnrollChallenge, EnrollRequest,
    ErrorBody, PullResponse, PushRequest, PushResponse, StatusResponse,
};
use crate::state::AppState;
use crate::store::{now_unix, AccountError, PushError, Store};
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, FromRequestParts, OriginalUri, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use tokio::sync::broadcast;

type ErrResp = (StatusCode, Json<ErrorBody>);
type ApiResult<T> = Result<Json<T>, ErrResp>;

fn err(status: StatusCode, error: &str, detail: &str) -> ErrResp {
    (
        status,
        Json(ErrorBody {
            error: error.to_owned(),
            detail: detail.to_owned(),
        }),
    )
}

/// A `500` for a storage fault. The rusqlite/SQL detail can leak filesystem paths or schema
/// internals, so it is logged server-side and the client gets only a stable generic message.
fn db_err(e: impl std::fmt::Display) -> ErrResp {
    eprintln!("vault-sync: store error: {e}");
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "store_error",
        "internal storage error",
    )
}

/// Run a blocking store operation off the async runtime. `Store` is `Send + Sync` (each
/// connection sits behind its own mutex), so it moves into the blocking pool as a cheap `Arc`
/// clone — keeping SQLite I/O from stalling tokio worker threads and letting pooled reads run
/// in parallel. A `JoinError` (the blocking task panicked) maps to a generic `500`.
async fn store_op<T, F>(state: &AppState, f: F) -> Result<T, ErrResp>
where
    F: FnOnce(&Store) -> T + Send + 'static,
    T: Send + 'static,
{
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || f(&store))
        .await
        .map_err(|e| {
            eprintln!("vault-sync: blocking store task failed: {e}");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "internal storage error",
            )
        })
}

/// Lowercase-UUIDv4 check for `{vault_id}` (no `uuid` crate). Personal vault ids are random
/// UUIDv4 — rejecting anything else keeps attacker-chosen keys out of the store and the
/// in-memory replay/tail maps entirely.
fn is_uuid_v4_lower(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            14 => {
                if c != b'4' {
                    return false;
                }
            } // version
            19 => {
                if !matches!(c, b'8' | b'9' | b'a' | b'b') {
                    return false;
                }
            } // variant
            _ => {
                if !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c) {
                    return false;
                }
            }
        }
    }
    true
}

/// Path extractor that validates `{vault_id}` is a lowercase UUIDv4 **before** any handler
/// (or body parse) runs, rejecting a bogus id with `400`. This is the single choke point that
/// stops malformed ids from creating accounts or seeding the replay/tail maps.
pub struct VaultId(pub String);

impl FromRequestParts<AppState> for VaultId {
    type Rejection = ErrResp;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ErrResp> {
        let Path(vault_id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                err(
                    StatusCode::BAD_REQUEST,
                    "bad_vault_id",
                    "missing vault_id path segment",
                )
            })?;
        if !is_uuid_v4_lower(&vault_id) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "bad_vault_id",
                "vault_id must be a lowercase UUIDv4",
            ));
        }
        Ok(VaultId(vault_id))
    }
}

pub fn router(state: AppState) -> Router {
    let max_body = state.cfg.max_body_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/sync/{vault_id}/account", post(create_account))
        .route(
            "/v1/sync/{vault_id}/enroll-challenge",
            get(enroll_challenge),
        )
        .route("/v1/sync/{vault_id}/enroll", post(enroll))
        .route("/v1/sync/{vault_id}/push", post(push))
        .route("/v1/sync/{vault_id}/pull", get(pull))
        .route("/v1/sync/{vault_id}/status", get(status))
        .route("/v1/sync/{vault_id}/devices", get(list_devices))
        .route(
            "/v1/sync/{vault_id}/devices/{device_id}",
            delete(revoke_device),
        )
        .route("/v1/sync/{vault_id}/tail", get(tail))
        // Per-route so metrics run after routing and see the `MatchedPath` template (id-free).
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::harden::record_metrics,
        ))
        .layer(DefaultBodyLimit::max(max_body))
        // Outer → inner: concurrency cap (503) · request timeout (408) · body limit (413).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::harden::timeout,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::harden::concurrency_limit,
        ))
        // Outermost: stamp every response (incl. rejects) with a correlation id.
        .layer(axum::middleware::from_fn(crate::harden::request_id))
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

/// Loopback-only metrics router (Prometheus text). Exposed on a separate listener — never on
/// the public API surface — because op/device counts are the metadata the at-rest model guards.
pub fn metrics_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/metrics",
            get(|State(s): State<AppState>| async move {
                s.metrics.render(s.tail_subscriber_count())
            }),
        )
        .with_state(state)
}

// ── auth helpers ────────────────────────────────────────────────────────────

/// Parse the `X-Device-Id` / `X-Sync-Ts` / `X-Sync-Nonce` / `X-Sync-Sig` headers.
fn signed_headers(h: &HeaderMap) -> Result<SignedHeaders, ErrResp> {
    let get_str = |name: &str| h.get(name).and_then(|v| v.to_str().ok());
    let device_id = get_str("x-device-id")
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "missing_device",
                "X-Device-Id required",
            )
        })?
        .to_owned();
    let ts: i64 = get_str("x-sync-ts")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "bad_ts",
                "X-Sync-Ts required (unix secs)",
            )
        })?;
    let nonce = get_str("x-sync-nonce")
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "missing_nonce",
                "X-Sync-Nonce required",
            )
        })?
        .to_owned();
    if nonce.len() > auth::MAX_NONCE_LEN {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "bad_nonce",
            "X-Sync-Nonce is too long",
        ));
    }
    let sig = get_str("x-sync-sig")
        .and_then(auth::parse_sig_b64)
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "bad_sig",
                "X-Sync-Sig must be base64 ed25519 (64 bytes)",
            )
        })?;
    Ok(SignedHeaders {
        device_id,
        ts,
        nonce,
        sig,
    })
}

fn check_skew(ts: i64) -> Result<(), ErrResp> {
    if (now_unix() - ts).abs() <= auth::MAX_SKEW_SECS {
        Ok(())
    } else {
        Err(err(
            StatusCode::UNAUTHORIZED,
            "stale_request",
            "X-Sync-Ts outside the accepted clock-skew window",
        ))
    }
}

/// Verify the request signature under `pubkey` and record the nonce (replay protection).
fn verify_signed(
    state: &AppState,
    pubkey: &[u8; 32],
    sh: &SignedHeaders,
    method: &str,
    path_and_query: &str,
    vault_id: &str,
    body: &[u8],
) -> Result<(), ErrResp> {
    let canonical = auth::canonical_string(
        method,
        path_and_query,
        vault_id,
        sh.ts,
        &sh.nonce,
        &auth::sha256_hex(body),
    );
    if !auth::verify_ed25519(pubkey, canonical.as_bytes(), &sh.sig) {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "bad_signature",
            "request signature did not verify",
        ));
    }
    if !state
        .replay
        .check_and_record(&sh.device_id, &sh.nonce, now_unix())
    {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "replay",
            "this (device, nonce) was already used",
        ));
    }
    Ok(())
}

/// Authenticate a request from an already-enrolled device; returns its `device_id`.
async fn auth_registered(
    state: &AppState,
    method: &Method,
    path_and_query: &str,
    vault_id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, ErrResp> {
    let sh = signed_headers(headers)?;
    check_skew(sh.ts)?;
    let vid = vault_id.to_owned();
    let did = sh.device_id.clone();
    let pubkey = store_op(state, move |s| s.device_pubkey(&vid, &did))
        .await?
        .map_err(db_err)?
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "unknown_device",
                "device is not enrolled",
            )
        })?;
    verify_signed(
        state,
        &pubkey,
        &sh,
        method.as_str(),
        path_and_query,
        vault_id,
        body,
    )?;
    Ok(sh.device_id)
}

fn paq(uri: &axum::http::Uri) -> String {
    uri.path_and_query()
        .map_or_else(|| uri.path().to_owned(), |pq| pq.as_str().to_owned())
}

// ── handlers ──────────────────────────────────────────────────────────────

async fn enroll_challenge(
    State(state): State<AppState>,
    VaultId(vault_id): VaultId,
) -> ApiResult<EnrollChallenge> {
    // This is the only fully-unauthenticated endpoint and it hands back enrolment salt+params,
    // so rate-limit it to blunt offline-dictionary harvesting and account-existence probing.
    // (A TLS-terminating proxy does per-IP limiting in front; this is the in-process backstop.)
    if !state.challenge_rl.allow(&vault_id) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many enrolment challenges; slow down",
        ));
    }
    let rec = store_op(&state, move |s| s.enroll_record(&vault_id))
        .await?
        .map_err(db_err)?;
    let (salt, params, _hash) = rec.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "no_account",
            "no sync account for this vault",
        )
    })?;
    Ok(Json(EnrollChallenge {
        salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
        params,
    }))
}

async fn create_account(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VaultId(vault_id): VaultId,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Ack>), ErrResp> {
    // Unauthenticated surface (only a self-signed proof): rate-limit so an attacker can't cheaply
    // mass-create accounts (disk-fill) or flood the replay-nonce guard. Shared with the challenge
    // bucket; a TLS proxy does per-IP limiting in front, this is the in-process backstop.
    if !state.enroll_rl.allow(&vault_id) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many account/enrol attempts; slow down",
        ));
    }
    let req: CreateAccountRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "bad_body", &e.to_string()))?;
    // Self-signed: the first device proves possession of the key it is registering.
    let pubkey = self_signed_pubkey(
        &state,
        &method,
        &paq(&uri),
        &vault_id,
        &headers,
        &body,
        &req.device.device_id,
        &req.device.pubkey_b64,
    )?;
    // Enrollability gate: the creator must prove it can derive the very enrolment secret it is
    // registering (`SHA-256(proof) == enroll.hash_b64`). This guarantees a second device with
    // the same passphrase can enrol and rejects a garbage verifier that would brick the vault.
    let hash = base64::engine::general_purpose::STANDARD
        .decode(req.enroll.hash_b64.as_bytes())
        .map_err(|_| {
            err(
                StatusCode::BAD_REQUEST,
                "bad_verifier",
                "enroll.hash_b64 must be base64",
            )
        })?;
    let proof = base64::engine::general_purpose::STANDARD
        .decode(req.proof_b64.as_bytes())
        .map_err(|_| {
            err(
                StatusCode::BAD_REQUEST,
                "bad_proof",
                "proof_b64 must be base64",
            )
        })?;
    if !auth::verify_enroll_proof(&proof, &hash) {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "bad_proof",
            "create proof does not match the enrolment verifier",
        ));
    }
    let (vid, enroll, did) = (
        vault_id.clone(),
        req.enroll.clone(),
        req.device.device_id.clone(),
    );
    let created = store_op(&state, move |s| {
        s.create_account(&vid, &enroll, &did, &pubkey)
    })
    .await?
    .map_err(|e| match e {
        AccountError::InvalidVerifier => err(
            StatusCode::BAD_REQUEST,
            "bad_verifier",
            "enrolment verifier is malformed (hash must be 32-byte SHA-256)",
        ),
        AccountError::Db(d) => db_err(d),
    })?;
    if created {
        Ok((StatusCode::CREATED, Json(Ack { ok: true })))
    } else {
        Err(err(
            StatusCode::CONFLICT,
            "account_exists",
            "a sync account already exists for this vault",
        ))
    }
}

async fn enroll(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VaultId(vault_id): VaultId,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Ack>), ErrResp> {
    // Unauthenticated surface (proof + self-signed key only): rate-limit like /account so device
    // enrolment can't be used to flood the account/nonce state.
    if !state.enroll_rl.allow(&vault_id) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many account/enrol attempts; slow down",
        ));
    }
    let req: EnrollRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "bad_body", &e.to_string()))?;
    // Gate on the enrolment proof (server holds only SHA-256 of the secret).
    let vid = vault_id.clone();
    let rec = store_op(&state, move |s| s.enroll_record(&vid))
        .await?
        .map_err(db_err)?;
    let (_salt, _params, hash) = rec.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "no_account",
            "no sync account for this vault",
        )
    })?;
    let proof = base64::engine::general_purpose::STANDARD
        .decode(req.proof_b64.as_bytes())
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad_proof", "proof must be base64"))?;
    if !auth::verify_enroll_proof(&proof, &hash) {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "bad_proof",
            "enrolment proof did not verify",
        ));
    }
    // Self-signed: the new device proves possession of the key it is registering.
    let pubkey = self_signed_pubkey(
        &state,
        &method,
        &paq(&uri),
        &vault_id,
        &headers,
        &body,
        &req.device.device_id,
        &req.device.pubkey_b64,
    )?;
    let (vid2, did) = (vault_id.clone(), req.device.device_id.clone());
    let dev_log = req.device.device_id.clone();
    let upsert = store_op(&state, move |s| s.register_device(&vid2, &did, &pubkey))
        .await?
        .map_err(db_err)?;
    // A key replacement on an existing device_id is security-relevant (possible hijack of the id),
    // not a routine enrol — surface it loudly so it isn't silent. (Op/device counts are the
    // metadata the at-rest model guards, so this stays a local log, not an emitted record.)
    if upsert == crate::store::DeviceUpsert::KeyReplaced {
        eprintln!(
            "vault-sync: WARNING device '{dev_log}' key REPLACED on vault {vault_id} — verify this \
             was an intentional re-key, not a hijack of an existing device id."
        );
    }
    Ok((StatusCode::OK, Json(Ack { ok: true })))
}

/// Verify a self-signed (account/enroll) request: the signature must verify under the pubkey
/// in the body, and the header `device_id` must match the body's. Returns the parsed pubkey.
#[allow(clippy::too_many_arguments)]
fn self_signed_pubkey(
    state: &AppState,
    method: &Method,
    path_and_query: &str,
    vault_id: &str,
    headers: &HeaderMap,
    body: &[u8],
    body_device_id: &str,
    body_pubkey_b64: &str,
) -> Result<[u8; 32], ErrResp> {
    let sh = signed_headers(headers)?;
    check_skew(sh.ts)?;
    if sh.device_id != body_device_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "device_mismatch",
            "X-Device-Id must match device.device_id",
        ));
    }
    let pubkey = auth::parse_pubkey_b64(body_pubkey_b64).ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "bad_pubkey",
            "pubkey must be base64 ed25519 (32 bytes)",
        )
    })?;
    verify_signed(
        state,
        &pubkey,
        &sh,
        method.as_str(),
        path_and_query,
        vault_id,
        body,
    )?;
    Ok(pubkey)
}

async fn push(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VaultId(vault_id): VaultId,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<PushResponse> {
    let device_id =
        auth_registered(&state, &method, &paq(&uri), &vault_id, &headers, &body).await?;
    let req: PushRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "bad_body", &e.to_string()))?;
    // Bound the batch size and reject oversized/empty identifier fields before they hit the store.
    if req.ops.len() > crate::dto::MAX_OPS_PER_PUSH {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "too_many_ops",
            "push batch exceeds the per-request op limit",
        ));
    }
    if req.ops.iter().any(|o| {
        o.op_id.is_empty()
            || o.op_id.len() > crate::dto::MAX_OP_ID_LEN
            || o.device_id.is_empty()
            || o.device_id.len() > crate::dto::MAX_OP_ID_LEN
            || o.collection_id.len() > crate::dto::MAX_OP_ID_LEN
    }) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_op_field",
            "op_id/device_id/collection_id is empty or exceeds the length limit",
        ));
    }
    // A device may only author ops under its own id.
    if req.ops.iter().any(|o| o.device_id != device_id) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "device_mismatch",
            "every op.device_id must equal the calling device",
        ));
    }
    // Append + get back exactly this push's stored ops (with their assigned `seq`), built in the
    // same write transaction — no post-commit re-read, so no pooled-reader visibility question.
    let vid = vault_id.clone();
    let ops = req.ops;
    let (accepted, duplicates, latest_seq, new_ops) =
        store_op(&state, move |s| s.push_ops(&vid, &ops))
            .await?
            .map_err(|e| match e {
                PushError::InvalidPayload => err(
                    StatusCode::BAD_REQUEST,
                    "bad_payload",
                    "an op payload was not valid base64",
                ),
                PushError::Db(d) => db_err(d),
            })?;
    state.metrics.add_ops(accepted, duplicates);
    // Fan the newly-stored ops out to live-tail subscribers (best-effort).
    if accepted > 0 {
        let messages: Vec<String> = new_ops
            .iter()
            .filter_map(|o| serde_json::to_string(o).ok())
            .collect();
        state.publish(&vault_id, &messages);
    }
    Ok(Json(PushResponse {
        accepted,
        duplicates,
        latest_seq,
    }))
}

#[derive(Debug, Deserialize)]
struct PullQuery {
    since: Option<u64>,
    limit: Option<u32>,
}

async fn pull(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VaultId(vault_id): VaultId,
    Query(q): Query<PullQuery>,
    headers: HeaderMap,
) -> ApiResult<PullResponse> {
    auth_registered(&state, &method, &paq(&uri), &vault_id, &headers, b"").await?;
    let limit = q
        .limit
        .unwrap_or(state.cfg.max_pull)
        .min(state.cfg.max_pull);
    let since = q.since.unwrap_or(0);
    let vid = vault_id.clone();
    let (ops, latest_seq) = store_op(&state, move |s| s.pull_ops(&vid, since, limit))
        .await?
        .map_err(db_err)?;
    Ok(Json(PullResponse { ops, latest_seq }))
}

async fn status(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VaultId(vault_id): VaultId,
    headers: HeaderMap,
) -> ApiResult<StatusResponse> {
    auth_registered(&state, &method, &paq(&uri), &vault_id, &headers, b"").await?;
    let vid = vault_id.clone();
    let (latest_seq, op_count, device_count) = store_op(&state, move |s| s.status(&vid))
        .await?
        .map_err(db_err)?;
    Ok(Json(StatusResponse {
        latest_seq,
        op_count,
        device_count,
    }))
}

/// `GET /v1/sync/{vault_id}/devices` — list the vault's enrolled devices (id + enrolment time).
/// Device-signed like any read; lets a client show its devices and spot one it doesn't recognise.
async fn list_devices(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VaultId(vault_id): VaultId,
    headers: HeaderMap,
) -> ApiResult<DevicesResponse> {
    auth_registered(&state, &method, &paq(&uri), &vault_id, &headers, b"").await?;
    let vid = vault_id.clone();
    let rows = store_op(&state, move |s| s.list_devices(&vid))
        .await?
        .map_err(db_err)?;
    let devices = rows
        .into_iter()
        .map(|(device_id, enrolled_at)| DeviceInfo {
            device_id,
            enrolled_at,
        })
        .collect();
    Ok(Json(DevicesResponse { devices }))
}

/// `DELETE /v1/sync/{vault_id}/devices/{device_id}` — revoke a device's key so it can no longer
/// sign requests (it must re-enrol with the passphrase proof to return). Device-signed; any
/// enrolled device of this (single-user) vault may revoke a lost/compromised one. `404` if the
/// device is unknown.
async fn revoke_device(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Path((vault_id, target_device_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Ack> {
    if !is_uuid_v4_lower(&vault_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_vault_id",
            "vault_id must be a lowercase UUIDv4",
        ));
    }
    // Bound the path-supplied device id (consistent with the push op-id caps) before it reaches
    // the store / logs.
    if target_device_id.is_empty() || target_device_id.len() > crate::dto::MAX_OP_ID_LEN {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_device_id",
            "device_id is empty or exceeds the length limit",
        ));
    }
    let caller = auth_registered(&state, &method, &paq(&uri), &vault_id, &headers, b"").await?;
    // Refuse to revoke the LAST remaining device — that would lock the vault out of all signing
    // (a new device could only return via the passphrase enrol path). A compromised device can
    // still revoke its siblings (any device is the single user in this model), but never strand
    // the vault with zero keys.
    let vid_count = vault_id.clone();
    let devices = store_op(&state, move |s| s.list_devices(&vid_count))
        .await?
        .map_err(db_err)?;
    if devices.len() <= 1 && devices.iter().any(|(id, _)| id == &target_device_id) {
        return Err(err(
            StatusCode::CONFLICT,
            "last_device",
            "cannot revoke the last remaining device; enrol another device first",
        ));
    }
    let (vid, did) = (vault_id.clone(), target_device_id.clone());
    let removed = store_op(&state, move |s| s.revoke_device(&vid, &did))
        .await?
        .map_err(db_err)?;
    if !removed {
        return Err(err(
            StatusCode::NOT_FOUND,
            "no_such_device",
            "no such device for this vault",
        ));
    }
    eprintln!(
        "vault-sync: device '{target_device_id}' revoked on vault {vault_id} by device '{caller}'"
    );
    Ok(Json(Ack { ok: true }))
}

/// `GET /v1/sync/{vault_id}/tail` — WebSocket live tail. The upgrade request is device-signed
/// exactly like a GET (empty body); after it verifies, the socket streams each newly-pushed
/// `StoredOp` as a JSON text frame. A subscriber that falls behind the buffer is sent
/// `{"resync":true}` and should do a full `pull`.
async fn tail(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VaultId(vault_id): VaultId,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(rejection) =
        auth_registered(&state, &method, &paq(&uri), &vault_id, &headers, b"").await
    {
        return rejection.into_response();
    }
    let rx = state.subscribe(&vault_id);
    ws.on_upgrade(move |socket| tail_loop(socket, rx))
}

async fn tail_loop(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    loop {
        tokio::select! {
            // Detect client close / error so the task ends and the receiver is dropped.
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    _ => {}
                }
            }
            event = rx.recv() => {
                match event {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = socket.send(Message::Text("{\"resync\":true}".into())).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::Store;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt as _;

    const VID: &str = "11111111-1111-4111-8111-111111111111";
    const SECRET: &[u8] = b"argon2-derived-enrolment-secret";

    fn b64e(b: impl AsRef<[u8]>) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn state() -> AppState {
        let cfg = Config {
            bind: "127.0.0.1:8300".parse().unwrap(),
            db_path: String::new(),
            db_key: None,
            max_body_bytes: 1 << 20,
            max_pull: 500,
            max_concurrency: 64,
            request_timeout: std::time::Duration::from_secs(30),
            readers: 0,
        };
        AppState::new(cfg, Store::open_memory().unwrap())
    }

    /// Build a device-signed request (matches what the real client does).
    fn signed(
        method: &str,
        uri: &str,
        body: &[u8],
        sk: &SigningKey,
        device_id: &str,
        nonce: &str,
    ) -> Request<Body> {
        let ts = now_unix();
        let canonical =
            auth::canonical_string(method, uri, VID, ts, nonce, &auth::sha256_hex(body));
        let sig = sk.sign(canonical.as_bytes()).to_bytes();
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-device-id", device_id)
            .header("x-sync-ts", ts.to_string())
            .header("x-sync-nonce", nonce)
            .header("x-sync-sig", b64e(sig))
            .body(Body::from(body.to_vec()))
            .unwrap()
    }

    async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let resp = router(state.clone()).oneshot(req).await.unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, body)
    }

    fn create_body(sk: &SigningKey, device_id: &str) -> Vec<u8> {
        let enroll = crate::dto::EnrollVerifier {
            salt_b64: b64e(b"enrol-salt-16byte"),
            params: terrapi_vault::KdfParams::default(),
            hash_b64: b64e(Sha256::digest(SECRET)),
        };
        let req = CreateAccountRequest {
            enroll,
            proof_b64: b64e(SECRET),
            device: crate::dto::DeviceRegistration {
                device_id: device_id.into(),
                pubkey_b64: b64e(sk.verifying_key().to_bytes()),
            },
        };
        serde_json::to_vec(&req).unwrap()
    }

    fn op(device_id: &str, op_id: &str) -> crate::dto::Op {
        crate::dto::Op {
            op_id: op_id.into(),
            device_id: device_id.into(),
            hlc: vault_transport::Hlc {
                wall_ms: 1,
                counter: 0,
            },
            collection_id: "notes".into(),
            encrypted_payload: b64e(b"ciphertext"),
        }
    }

    #[tokio::test]
    async fn full_two_device_flow() {
        let st = state();
        let dev_a = SigningKey::generate(&mut OsRng);
        let dev_b = SigningKey::generate(&mut OsRng);
        let acct = format!("/v1/sync/{VID}/account");

        // 1. Device A creates the account (self-signed).
        let body = create_body(&dev_a, "A");
        let (status, _) = send(&st, signed("POST", &acct, &body, &dev_a, "A", "n1")).await;
        assert_eq!(status, StatusCode::CREATED);
        // Re-create → 409.
        let (status, _) = send(&st, signed("POST", &acct, &body, &dev_a, "A", "n2")).await;
        assert_eq!(status, StatusCode::CONFLICT);

        // 2. Enroll-challenge is unauthenticated and returns the salt+params.
        let (status, body) = send(
            &st,
            Request::builder()
                .method("GET")
                .uri(format!("/v1/sync/{VID}/enroll-challenge"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let ch: EnrollChallenge = serde_json::from_slice(&body).unwrap();
        assert_eq!(ch.salt_b64, b64e(b"enrol-salt-16byte"));

        // 3. Device B enrolls with the correct proof (self-signed by B).
        let enroll_uri = format!("/v1/sync/{VID}/enroll");
        let good = serde_json::to_vec(&EnrollRequest {
            proof_b64: b64e(SECRET),
            device: crate::dto::DeviceRegistration {
                device_id: "B".into(),
                pubkey_b64: b64e(dev_b.verifying_key().to_bytes()),
            },
        })
        .unwrap();
        let (status, _) = send(&st, signed("POST", &enroll_uri, &good, &dev_b, "B", "n3")).await;
        assert_eq!(status, StatusCode::OK);

        // Wrong proof → 401.
        let bad = serde_json::to_vec(&EnrollRequest {
            proof_b64: b64e(b"wrong-secret"),
            device: crate::dto::DeviceRegistration {
                device_id: "C".into(),
                pubkey_b64: b64e(SigningKey::generate(&mut OsRng).verifying_key().to_bytes()),
            },
        })
        .unwrap();
        let dev_c = SigningKey::generate(&mut OsRng);
        let (status, _) = send(&st, signed("POST", &enroll_uri, &bad, &dev_c, "C", "n4")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // 4. Device A pushes one op.
        let push_uri = format!("/v1/sync/{VID}/push");
        let push = serde_json::to_vec(&PushRequest {
            ops: vec![op("A", "op-1")],
        })
        .unwrap();
        let (status, body) = send(&st, signed("POST", &push_uri, &push, &dev_a, "A", "n5")).await;
        assert_eq!(status, StatusCode::OK);
        let pr: PushResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!((pr.accepted, pr.duplicates, pr.latest_seq), (1, 0, 1));

        // A cannot author an op under B's device_id.
        let spoof = serde_json::to_vec(&PushRequest {
            ops: vec![op("B", "op-2")],
        })
        .unwrap();
        let (status, _) = send(&st, signed("POST", &push_uri, &spoof, &dev_a, "A", "n6")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // 5. Device B pulls and sees A's op.
        let pull_uri = format!("/v1/sync/{VID}/pull?since=0&limit=100");
        let (status, body) = send(&st, signed("GET", &pull_uri, b"", &dev_b, "B", "n7")).await;
        assert_eq!(status, StatusCode::OK);
        let pull: PullResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(pull.ops.len(), 1);
        assert_eq!(pull.ops[0].op_id, "op-1");
        assert_eq!(pull.ops[0].seq, 1);

        // 6. Status.
        let status_uri = format!("/v1/sync/{VID}/status");
        let (status, body) = send(&st, signed("GET", &status_uri, b"", &dev_a, "A", "n8")).await;
        assert_eq!(status, StatusCode::OK);
        let s: StatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!((s.latest_seq, s.op_count, s.device_count), (1, 1, 2));
    }

    #[tokio::test]
    async fn unsigned_push_is_401() {
        let st = state();
        // Create the account first so the route exists with an enrolled device.
        let dev_a = SigningKey::generate(&mut OsRng);
        let body = create_body(&dev_a, "A");
        let acct = format!("/v1/sync/{VID}/account");
        let _ = send(&st, signed("POST", &acct, &body, &dev_a, "A", "n1")).await;

        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/sync/{VID}/push"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"ops":[]}"#))
            .unwrap();
        let (status, _) = send(&st, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn replayed_nonce_is_rejected() {
        let st = state();
        let dev_a = SigningKey::generate(&mut OsRng);
        let acct = format!("/v1/sync/{VID}/account");
        let _ = send(
            &st,
            signed("POST", &acct, &create_body(&dev_a, "A"), &dev_a, "A", "n1"),
        )
        .await;

        let status_uri = format!("/v1/sync/{VID}/status");
        let req1 = signed("GET", &status_uri, b"", &dev_a, "A", "dup-nonce");
        let (s1, _) = send(&st, req1).await;
        assert_eq!(s1, StatusCode::OK);
        // Same nonce again → replay rejected.
        let req2 = signed("GET", &status_uri, b"", &dev_a, "A", "dup-nonce");
        let (s2, _) = send(&st, req2).await;
        assert_eq!(s2, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn push_notifies_tail_subscribers() {
        let st = state();
        let dev_a = SigningKey::generate(&mut OsRng);
        let acct = format!("/v1/sync/{VID}/account");
        let _ = send(
            &st,
            signed("POST", &acct, &create_body(&dev_a, "A"), &dev_a, "A", "n1"),
        )
        .await;

        // Subscribe to the live tail, then push an op.
        let mut rx = st.subscribe(VID);
        let push_uri = format!("/v1/sync/{VID}/push");
        let push = serde_json::to_vec(&PushRequest {
            ops: vec![op("A", "op-1")],
        })
        .unwrap();
        let (status, _) = send(&st, signed("POST", &push_uri, &push, &dev_a, "A", "n2")).await;
        assert_eq!(status, StatusCode::OK);

        // The stored op (with its server seq) was fanned out to the subscriber.
        let json = rx
            .try_recv()
            .expect("subscriber should have received the op");
        let stored: crate::dto::StoredOp = serde_json::from_str(&json).unwrap();
        assert_eq!(stored.op_id, "op-1");
        assert_eq!(stored.seq, 1);
    }

    #[tokio::test]
    async fn tail_fanout_is_exactly_this_push() {
        // Guards the fan-out range (`before = latest_seq - accepted`): a push must publish ONLY
        // its own ops, never ops that already existed before the subscriber joined.
        let st = state();
        let dev_a = SigningKey::generate(&mut OsRng);
        let acct = format!("/v1/sync/{VID}/account");
        let _ = send(
            &st,
            signed("POST", &acct, &create_body(&dev_a, "A"), &dev_a, "A", "n1"),
        )
        .await;
        let push_uri = format!("/v1/sync/{VID}/push");
        // Pre-seed op-1 (seq 1) BEFORE anyone subscribes.
        let p1 = serde_json::to_vec(&PushRequest {
            ops: vec![op("A", "op-1")],
        })
        .unwrap();
        assert_eq!(
            send(&st, signed("POST", &push_uri, &p1, &dev_a, "A", "n2"))
                .await
                .0,
            StatusCode::OK
        );
        // Subscribe, then push op-2 (seq 2).
        let mut rx = st.subscribe(VID);
        let p2 = serde_json::to_vec(&PushRequest {
            ops: vec![op("A", "op-2")],
        })
        .unwrap();
        assert_eq!(
            send(&st, signed("POST", &push_uri, &p2, &dev_a, "A", "n3"))
                .await
                .0,
            StatusCode::OK
        );
        // The subscriber receives exactly op-2 (seq 2) — never the pre-seeded op-1 — and nothing more.
        let stored: crate::dto::StoredOp =
            serde_json::from_str(&rx.try_recv().expect("the new op")).unwrap();
        assert_eq!((stored.op_id.as_str(), stored.seq), ("op-2", 2));
        assert!(
            rx.try_recv().is_err(),
            "only this push's single op should have been published"
        );
    }

    #[tokio::test]
    async fn create_with_mismatched_proof_is_401() {
        let st = state();
        let dev_a = SigningKey::generate(&mut OsRng);
        // Verifier hash is SHA-256(SECRET) but the proof is a different secret → 401, and no
        // account is created (a follow-up correct create then succeeds).
        let enroll = crate::dto::EnrollVerifier {
            salt_b64: b64e(b"enrol-salt-16byte"),
            params: terrapi_vault::KdfParams::default(),
            hash_b64: b64e(Sha256::digest(SECRET)),
        };
        let bad = serde_json::to_vec(&CreateAccountRequest {
            enroll: enroll.clone(),
            proof_b64: b64e(b"the-wrong-secret"),
            device: crate::dto::DeviceRegistration {
                device_id: "A".into(),
                pubkey_b64: b64e(dev_a.verifying_key().to_bytes()),
            },
        })
        .unwrap();
        let acct = format!("/v1/sync/{VID}/account");
        let (status, _) = send(&st, signed("POST", &acct, &bad, &dev_a, "A", "n1")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // A correct create still works (the bad attempt committed nothing).
        let good = create_body(&dev_a, "A");
        let (status, _) = send(&st, signed("POST", &acct, &good, &dev_a, "A", "n2")).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn non_uuid_vault_id_is_400() {
        let st = state();
        // A bogus (non-UUIDv4) vault id is rejected at the extractor, before any store touch.
        let req = Request::builder()
            .method("GET")
            .uri("/v1/sync/not-a-uuid/enroll-challenge")
            .body(Body::empty())
            .unwrap();
        let (status, body) = send(&st, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let e: ErrorBody = serde_json::from_slice(&body).unwrap();
        assert_eq!(e.error, "bad_vault_id");
    }

    /// End-to-end live tail over a real WebSocket: an enrolled device opens a (device-signed)
    /// `/tail` upgrade, then a push fans the new op out and the socket receives it as a text
    /// frame. Exercises the WS auth + framing path the oneshot tests can't reach.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tail_websocket_receives_pushed_op() {
        use futures_util::StreamExt as _;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::Message;

        let st = state();
        let dev_a = SigningKey::generate(&mut OsRng);
        // Enrol device A directly in the store (the create/enrol HTTP flow is covered elsewhere).
        let enroll = crate::dto::EnrollVerifier {
            salt_b64: b64e(b"enrol-salt-16byte"),
            params: terrapi_vault::KdfParams::default(),
            hash_b64: b64e(Sha256::digest(SECRET)),
        };
        st.store
            .create_account(VID, &enroll, "A", &dev_a.verifying_key().to_bytes())
            .unwrap();

        // Start a real server on an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(st.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // Build the device-signed WS upgrade (signed exactly like a GET over an empty body).
        let path = format!("/v1/sync/{VID}/tail");
        let ts = now_unix();
        let canonical =
            auth::canonical_string("GET", &path, VID, ts, "ws1", &auth::sha256_hex(b""));
        let sig = b64e(dev_a.sign(canonical.as_bytes()).to_bytes());
        let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
        let h = req.headers_mut();
        h.insert("x-device-id", "A".parse().unwrap());
        h.insert("x-sync-ts", ts.to_string().parse().unwrap());
        h.insert("x-sync-nonce", "ws1".parse().unwrap());
        h.insert("x-sync-sig", sig.parse().unwrap());
        let (mut ws, _resp) = tokio_tungstenite::connect_async(req).await.unwrap();

        // The handshake completed → the handler subscribed. Now fan an op out (as push does).
        let stored = crate::dto::StoredOp::from_op(1, op("A", "op-1"));
        st.publish(VID, &[serde_json::to_string(&stored).unwrap()]);

        // The socket receives the op as a JSON text frame.
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
            .await
            .expect("frame within timeout")
            .expect("a frame")
            .expect("ok frame");
        let txt = match msg {
            Message::Text(t) => t.to_string(),
            other => panic!("expected text frame, got {other:?}"),
        };
        let got: crate::dto::StoredOp = serde_json::from_str(&txt).unwrap();
        assert_eq!(got.op_id, "op-1");
        assert_eq!(got.seq, 1);
    }
}
