//! The row-level oplog surface: push / pull / status.
use super::{auth_registered, db_err, err, paq, store_op, ApiResult, VestaId};
use crate::dto::{PullResponse, PushRequest, PushResponse, StatusResponse};
use crate::state::AppState;
use crate::store::PushError;
use axum::body::Bytes;
use axum::extract::{OriginalUri, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::Json;
use serde::Deserialize;

pub(crate) async fn push(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VestaId(vesta_id): VestaId,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<PushResponse> {
    let device_id =
        auth_registered(&state, &method, &paq(&uri), &vesta_id, &headers, &body).await?;
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
    let vid = vesta_id.clone();
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
        state.publish(&vesta_id, &messages);
    }
    Ok(Json(PushResponse {
        accepted,
        duplicates,
        latest_seq,
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct PullQuery {
    since: Option<u64>,
    limit: Option<u32>,
}

pub(crate) async fn pull(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VestaId(vesta_id): VestaId,
    Query(q): Query<PullQuery>,
    headers: HeaderMap,
) -> ApiResult<PullResponse> {
    auth_registered(&state, &method, &paq(&uri), &vesta_id, &headers, b"").await?;
    let limit = q
        .limit
        .unwrap_or(state.cfg.max_pull)
        .min(state.cfg.max_pull);
    let since = q.since.unwrap_or(0);
    let vid = vesta_id.clone();
    let (ops, latest_seq) = store_op(&state, move |s| s.pull_ops(&vid, since, limit))
        .await?
        .map_err(db_err)?;
    Ok(Json(PullResponse { ops, latest_seq }))
}

pub(crate) async fn status(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    VestaId(vesta_id): VestaId,
    headers: HeaderMap,
) -> ApiResult<StatusResponse> {
    auth_registered(&state, &method, &paq(&uri), &vesta_id, &headers, b"").await?;
    let vid = vesta_id.clone();
    let (latest_seq, op_count, device_count) = store_op(&state, move |s| s.status(&vid))
        .await?
        .map_err(db_err)?;
    Ok(Json(StatusResponse {
        latest_seq,
        op_count,
        device_count,
    }))
}
