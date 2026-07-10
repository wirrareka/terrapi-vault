//! Device management: list + revoke.
use super::{auth_registered, db_err, err, is_uuid_v4_lower, paq, store_op, ApiResult, VestaId};
use crate::dto::{Ack, DeviceInfo, DevicesResponse};
use crate::state::AppState;
use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::Json;

/// `GET /v1/sync/{vesta_id}/devices` — list the vault's enrolled devices (id + enrolment time).
/// Device-signed like any read; lets a client show its devices and spot one it doesn't recognise.
pub(crate) async fn list_devices(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VestaId(vesta_id): VestaId,
    headers: HeaderMap,
) -> ApiResult<DevicesResponse> {
    auth_registered(&state, &method, &paq(&uri), &vesta_id, &headers, b"").await?;
    let vid = vesta_id.clone();
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

/// `DELETE /v1/sync/{vesta_id}/devices/{device_id}` — revoke a device's key so it can no longer
/// sign requests (it must re-enrol with the passphrase proof to return). Device-signed; any
/// enrolled device of this (single-user) vault may revoke a lost/compromised one. `404` if the
/// device is unknown.
pub(crate) async fn revoke_device(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Path((vesta_id, target_device_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Ack> {
    if !is_uuid_v4_lower(&vesta_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "bad_vesta_id",
            "vesta_id must be a lowercase UUIDv4",
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
    let caller = auth_registered(&state, &method, &paq(&uri), &vesta_id, &headers, b"").await?;
    // Refuse to revoke the LAST remaining device — that would lock the vault out of all signing
    // (a new device could only return via the passphrase enrol path). A compromised device can
    // still revoke its siblings (any device is the single user in this model), but never strand
    // the vault with zero keys.
    let vid_count = vesta_id.clone();
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
    let (vid, did) = (vesta_id.clone(), target_device_id.clone());
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
        "vesta-sync: device '{target_device_id}' revoked on vault {vesta_id} by device '{caller}'"
    );
    Ok(Json(Ack { ok: true }))
}
