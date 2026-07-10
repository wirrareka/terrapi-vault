//! Background expiry sweeper — enforces lease/session TTL + idle timeouts.
//!
//! The lease engine tracks absolute deadlines but is passive; this task drives it on a
//! timer so short-TTL creds actually auto-expire (not only on explicit revoke / session
//! end). On each tick it sweeps the engine, unbinds principals whose session ended,
//! deletes the backend users owned by expired cred leases, and emits B3 audit events
//! (`session.expire`, `lease.expire`, `creds.revoke`).

use crate::creds;
use crate::state::{now_unix, AppState};
use std::time::Duration;
use vesta_transport::audit::{Actor, ActorKind, AuditEvent, Outcome, Target};
use vesta_transport::lock::MutexExt;

/// Run forever, sweeping every `interval`. Missed ticks (e.g. a slow teardown) are
/// skipped rather than bursting.
pub async fn run(state: AppState, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        sweep_once(&state).await;
    }
}

async fn sweep_once(state: &AppState) {
    let swept = {
        let mut eng = state.leases.lock_recover();
        eng.sweep(now_unix())
    };
    if swept.is_empty() {
        return;
    }

    for sid in &swept.ended_sessions {
        state.unbind_session(sid);
        emit(
            state,
            "session.expire",
            "session",
            Some(sid.clone()),
            Outcome::Success,
        );
    }

    // Record any expired SSH cert serials in the CA revocation list.
    crate::http::record_revoked_ssh(state, &swept.revoked_leases);

    // Delete the backend users owned by expired cred leases (SSH-cert leases have none).
    let torn = creds::teardown(&state.engines, &state.cred_handles, &swept.revoked_leases).await;
    for t in torn {
        let outcome = if t.outcome_ok {
            Outcome::Success
        } else {
            Outcome::Failure
        };
        emit(
            state,
            "creds.revoke",
            "creds",
            Some(format!("role={}", t.role)),
            outcome,
        );
    }

    for lid in &swept.revoked_leases {
        emit(
            state,
            "lease.expire",
            "lease",
            Some(lid.clone()),
            Outcome::Success,
        );
    }
}

fn emit(state: &AppState, action: &str, kind: &str, id: Option<String>, outcome: Outcome) {
    state.emit(&AuditEvent::vault(
        AppState::now_ts(),
        state.cfg.node.clone(),
        Some(state.cfg.residency_group.as_str().to_owned()),
        Actor {
            label: "vault-sweeper".into(),
            kind: ActorKind::System,
            id: Some("sweeper".into()),
            tenant: None,
        },
        action,
        Target {
            kind: kind.into(),
            id,
        },
        outcome,
        None,
    ));
}
