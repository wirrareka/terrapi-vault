//! Signed-request verification: device-signature headers, skew check, principal gate.
use super::{db_err, err, store_op, ErrResp};
use crate::auth::{self, SignedHeaders};
use crate::state::AppState;
use crate::store::now_unix;
use axum::http::{HeaderMap, Method, StatusCode};

/// Parse the `X-Device-Id` / `X-Sync-Ts` / `X-Sync-Nonce` / `X-Sync-Sig` headers.
pub(crate) fn signed_headers(h: &HeaderMap) -> Result<SignedHeaders, ErrResp> {
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

pub(crate) fn check_skew(ts: i64) -> Result<(), ErrResp> {
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
pub(crate) fn verify_signed(
    state: &AppState,
    pubkey: &[u8; 32],
    sh: &SignedHeaders,
    method: &str,
    path_and_query: &str,
    vesta_id: &str,
    body: &[u8],
) -> Result<(), ErrResp> {
    let canonical = auth::canonical_string(
        method,
        path_and_query,
        vesta_id,
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
pub(crate) async fn auth_registered(
    state: &AppState,
    method: &Method,
    path_and_query: &str,
    vesta_id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, ErrResp> {
    let sh = signed_headers(headers)?;
    check_skew(sh.ts)?;
    let vid = vesta_id.to_owned();
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
        vesta_id,
        body,
    )?;
    Ok(sh.device_id)
}

pub(crate) fn paq(uri: &axum::http::Uri) -> String {
    uri.path_and_query()
        .map_or_else(|| uri.path().to_owned(), |pq| pq.as_str().to_owned())
}

// ── handlers ──────────────────────────────────────────────────────────────
