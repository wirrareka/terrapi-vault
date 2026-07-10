//! Account + device enrollment (challenge, create-account, enroll).
use super::*;
use crate::auth::{self};
use crate::dto::{Ack, CreateAccountRequest, EnrollChallenge, EnrollRequest};
use crate::state::AppState;
use crate::store::AccountError;
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::Json;

pub(crate) async fn enroll_challenge(
    State(state): State<AppState>,
    VestaId(vesta_id): VestaId,
) -> ApiResult<EnrollChallenge> {
    // This is the only fully-unauthenticated endpoint and it hands back enrolment salt+params,
    // so rate-limit it to blunt offline-dictionary harvesting and account-existence probing.
    // (A TLS-terminating proxy does per-IP limiting in front; this is the in-process backstop.)
    if !state.challenge_rl.allow(&vesta_id) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many enrolment challenges; slow down",
        ));
    }
    let rec = store_op(&state, move |s| s.enroll_record(&vesta_id))
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

pub(crate) async fn create_account(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VestaId(vesta_id): VestaId,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Ack>), ErrResp> {
    // Unauthenticated surface (only a self-signed proof): rate-limit so an attacker can't cheaply
    // mass-create accounts (disk-fill) or flood the replay-nonce guard. Shared with the challenge
    // bucket; a TLS proxy does per-IP limiting in front, this is the in-process backstop.
    if !state.enroll_rl.allow(&vesta_id) {
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
        &vesta_id,
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
        vesta_id.clone(),
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

pub(crate) async fn enroll(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VestaId(vesta_id): VestaId,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Ack>), ErrResp> {
    // Unauthenticated surface (proof + self-signed key only): rate-limit like /account so device
    // enrolment can't be used to flood the account/nonce state.
    if !state.enroll_rl.allow(&vesta_id) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many account/enrol attempts; slow down",
        ));
    }
    let req: EnrollRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "bad_body", &e.to_string()))?;
    // Gate on the enrolment proof (server holds only SHA-256 of the secret).
    let vid = vesta_id.clone();
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
        &vesta_id,
        &headers,
        &body,
        &req.device.device_id,
        &req.device.pubkey_b64,
    )?;
    let (vid2, did) = (vesta_id.clone(), req.device.device_id.clone());
    let dev_log = req.device.device_id.clone();
    let upsert = store_op(&state, move |s| s.register_device(&vid2, &did, &pubkey))
        .await?
        .map_err(db_err)?;
    // A key replacement on an existing device_id is security-relevant (possible hijack of the id),
    // not a routine enrol — surface it loudly so it isn't silent. (Op/device counts are the
    // metadata the at-rest model guards, so this stays a local log, not an emitted record.)
    if upsert == crate::store::DeviceUpsert::KeyReplaced {
        eprintln!(
            "vesta-sync: WARNING device '{dev_log}' key REPLACED on vault {vesta_id} — verify this \
             was an intentional re-key, not a hijack of an existing device id."
        );
    }
    Ok((StatusCode::OK, Json(Ack { ok: true })))
}

/// Verify a self-signed (account/enroll) request: the signature must verify under the pubkey
/// in the body, and the header `device_id` must match the body's. Returns the parsed pubkey.
#[allow(clippy::too_many_arguments)]
pub(crate) fn self_signed_pubkey(
    state: &AppState,
    method: &Method,
    path_and_query: &str,
    vesta_id: &str,
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
        vesta_id,
        body,
    )?;
    Ok(pubkey)
}
