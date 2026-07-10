//! System ops: at-rest store snapshot.
use super::{err, internal, require_cap, require_unsealed, system_actor, ApiResult};
use crate::auth::{Capability, Principal};
use crate::state::{now_unix, AppState};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use vesta_transport::audit::{AuditEvent, Outcome, Target};
use vesta_transport::lock::MutexExt;

pub(crate) async fn store_snapshot(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<crate::dto::StoreSnapshotResponse> {
    require_cap(&principal, Capability::Snapshot)?;
    require_unsealed(&state)?;
    let Some(store) = state.store.clone() else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "sealed",
            "broker is sealed",
        ));
    };
    if let Err(e) = std::fs::create_dir_all(&state.cfg.snapshot_dir) {
        return Err(internal("store_error", "snapshot mkdir", e));
    }
    let snap_path = state.cfg.snapshot_dir.join(format!(
        "vault-store-{}-{}.sqlcipher",
        state.cfg.residency_group.as_str(),
        now_unix()
    ));
    let snap_str = snap_path.to_string_lossy().to_string();

    // Online, consistent snapshot — SQLCipher copies under the same key (ciphertext).
    {
        let v = store.lock_recover();
        v.with_connection(|c| c.execute("VACUUM INTO ?1", [snap_str.as_str()]).map(|_| ()))
    }
    .map_err(|e| internal("snapshot_failed", "snapshot vacuum", e))?;

    let data =
        std::fs::read(&snap_path).map_err(|e| internal("store_error", "snapshot read", e))?;
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
    // Return only the opaque filename (no host directory) to the caller — the absolute path is
    // an internal detail (review S11; aether confirmed it consumes no path, 2026-05-30). The
    // full path stays in the local audit event below for operator IR.
    let snapshot_id = snap_path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());

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
        snapshot_id,
        sha256,
        bytes,
    }))
}
