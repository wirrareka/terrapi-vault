//! vault-sync HTTP surface (axum). Endpoints: account / enroll-challenge / enroll / push /
//! pull / status (+ healthz). Every op-bearing call is device-signed; account + enroll are
//! self-signed by the device key being registered (proves key possession) and enrol is gated
//! by the enrolment proof. See `docs/planning/02-vault-sync-oplog.md`.

use crate::auth::{self, SignedHeaders};
use crate::dto::{
    Ack, CreateAccountRequest, EnrollChallenge, EnrollRequest, ErrorBody, PullResponse,
    PushRequest, PushResponse, StatusResponse,
};
use crate::state::AppState;
use crate::store::{now_unix, PushError};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;

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

fn db_err(e: impl std::fmt::Display) -> ErrResp {
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "store_error",
        &e.to_string(),
    )
}

pub fn router(state: AppState) -> Router {
    let max_body = state.cfg.max_body_bytes;
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/sync/{vault_id}/account", post(create_account))
        .route(
            "/v1/sync/{vault_id}/enroll-challenge",
            get(enroll_challenge),
        )
        .route("/v1/sync/{vault_id}/enroll", post(enroll))
        .route("/v1/sync/{vault_id}/push", post(push))
        .route("/v1/sync/{vault_id}/pull", get(pull))
        .route("/v1/sync/{vault_id}/status", get(status))
        .layer(DefaultBodyLimit::max(max_body))
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
fn auth_registered(
    state: &AppState,
    method: &Method,
    path_and_query: &str,
    vault_id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, ErrResp> {
    let sh = signed_headers(headers)?;
    check_skew(sh.ts)?;
    let pubkey = {
        let store = state.store.lock().expect("store lock");
        store
            .device_pubkey(vault_id, &sh.device_id)
            .map_err(db_err)?
    }
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
    Path(vault_id): Path<String>,
) -> ApiResult<EnrollChallenge> {
    let rec = {
        let store = state.store.lock().expect("store lock");
        store.enroll_record(&vault_id).map_err(db_err)?
    };
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
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Ack>), ErrResp> {
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
    let created = {
        let store = state.store.lock().expect("store lock");
        store
            .create_account(&vault_id, &req.enroll, &req.device.device_id, &pubkey)
            .map_err(db_err)?
    };
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
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Ack>), ErrResp> {
    let req: EnrollRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "bad_body", &e.to_string()))?;
    // Gate on the enrolment proof (server holds only SHA-256 of the secret).
    let rec = {
        let store = state.store.lock().expect("store lock");
        store.enroll_record(&vault_id).map_err(db_err)?
    };
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
    {
        let store = state.store.lock().expect("store lock");
        store
            .register_device(&vault_id, &req.device.device_id, &pubkey)
            .map_err(db_err)?;
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
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<PushResponse> {
    let device_id = auth_registered(&state, &method, &paq(&uri), &vault_id, &headers, &body)?;
    let req: PushRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "bad_body", &e.to_string()))?;
    // A device may only author ops under its own id.
    if req.ops.iter().any(|o| o.device_id != device_id) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "device_mismatch",
            "every op.device_id must equal the calling device",
        ));
    }
    let (accepted, duplicates, latest_seq) = {
        let store = state.store.lock().expect("store lock");
        store.push_ops(&vault_id, &req.ops).map_err(|e| match e {
            PushError::InvalidPayload => err(
                StatusCode::BAD_REQUEST,
                "bad_payload",
                "an op payload was not valid base64",
            ),
            PushError::Db(d) => db_err(d),
        })?
    };
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
    Path(vault_id): Path<String>,
    Query(q): Query<PullQuery>,
    headers: HeaderMap,
) -> ApiResult<PullResponse> {
    auth_registered(&state, &method, &paq(&uri), &vault_id, &headers, b"")?;
    let limit = q
        .limit
        .unwrap_or(state.cfg.max_pull)
        .min(state.cfg.max_pull);
    let (ops, latest_seq) = {
        let store = state.store.lock().expect("store lock");
        store
            .pull_ops(&vault_id, q.since.unwrap_or(0), limit)
            .map_err(db_err)?
    };
    Ok(Json(PullResponse { ops, latest_seq }))
}

async fn status(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusResponse> {
    auth_registered(&state, &method, &paq(&uri), &vault_id, &headers, b"")?;
    let (latest_seq, op_count, device_count) = {
        let store = state.store.lock().expect("store lock");
        store.status(&vault_id).map_err(db_err)?
    };
    Ok(Json(StatusResponse {
        latest_seq,
        op_count,
        device_count,
    }))
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
            max_body_bytes: 1 << 20,
            max_pull: 500,
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
        assert_eq!(pull.ops[0].op.op_id, "op-1");
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
}
