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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creds::CredHandle;
    use crate::state::now_unix;
    use std::sync::{Arc, Mutex};
    use vesta_transport::audit::AuditSink;

    /// Records (action, target id, success) per emitted event.
    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<(String, Option<String>, bool)>>);

    impl AuditSink for RecordingSink {
        fn emit(&self, event: &AuditEvent) {
            self.0.lock_recover().push((
                event.action.clone(),
                event.target.id.clone(),
                matches!(event.outcome, Outcome::Success),
            ));
        }
    }

    impl RecordingSink {
        fn actions(&self) -> Vec<(String, Option<String>, bool)> {
            self.0.lock_recover().clone()
        }
    }

    fn test_state(audit: Arc<RecordingSink>) -> AppState {
        AppState::test_dev(audit)
    }

    #[tokio::test]
    async fn nothing_expired_emits_no_events() {
        let sink = Arc::new(RecordingSink::default());
        let state = test_state(sink.clone());
        let now = now_unix();
        let sid = state.leases.lock_recover().open_session(now, 900, 900);
        state.bind_session("san-a", &sid);
        state
            .leases
            .lock_recover()
            .issue_lease(now, &sid, 900, 900, true)
            .expect("issue");

        sweep_once(&state).await;

        assert!(sink.actions().is_empty());
        assert!(state.owns_session("san-a", &sid), "live session survives");
    }

    #[tokio::test]
    async fn expired_session_cascades_leases_creds_and_audit() {
        let sink = Arc::new(RecordingSink::default());
        let state = test_state(sink.clone());
        // Session opened in the past with a short TTL → already expired at sweep time.
        let then = now_unix() - 100;
        let (sid, lease) = {
            let mut eng = state.leases.lock_recover();
            let sid = eng.open_session(then, 10, 10);
            let lease = eng.issue_lease(then, &sid, 900, 900, true).expect("issue");
            (sid, lease)
        };
        state.bind_session("san-a", &sid);
        // The lease owns a backend cred in the dev MockEngine's role.
        state.cred_handles.lock_recover().insert(
            lease.clone(),
            CredHandle {
                role: "audit-writer".into(),
                username: "v-audit-writer-test".into(),
            },
        );

        sweep_once(&state).await;

        // Principal unbound, cred handle consumed.
        assert!(!state.owns_session("san-a", &sid));
        assert!(state.cred_handles.lock_recover().is_empty());

        let actions = sink.actions();
        assert!(
            actions.contains(&("session.expire".into(), Some(sid), true)),
            "session.expire emitted: {actions:?}"
        );
        assert!(
            actions.contains(&(
                "creds.revoke".into(),
                Some("role=audit-writer".into()),
                true
            )),
            "creds.revoke emitted: {actions:?}"
        );
        assert!(
            actions.contains(&("lease.expire".into(), Some(lease), true)),
            "lease.expire emitted: {actions:?}"
        );
    }

    #[tokio::test]
    async fn expired_lease_under_live_session_keeps_the_session() {
        let sink = Arc::new(RecordingSink::default());
        let state = test_state(sink.clone());
        // Live session; the lease's own TTL is already behind us.
        let now = now_unix();
        let (sid, lease) = {
            let mut eng = state.leases.lock_recover();
            let sid = eng.open_session(now - 50, 900, 900);
            let lease = eng
                .issue_lease(now - 50, &sid, 10, 10, true)
                .expect("issue");
            (sid, lease)
        };
        state.bind_session("san-a", &sid);

        sweep_once(&state).await;

        assert!(state.owns_session("san-a", &sid), "session must survive");
        let actions = sink.actions();
        assert!(actions.contains(&("lease.expire".into(), Some(lease), true)));
        assert!(
            !actions.iter().any(|(a, _, _)| a == "session.expire"),
            "no session.expire: {actions:?}"
        );
    }

    #[tokio::test]
    async fn teardown_without_engine_audits_a_failure() {
        let sink = Arc::new(RecordingSink::default());
        let state = test_state(sink.clone());
        let then = now_unix() - 100;
        let lease = {
            let mut eng = state.leases.lock_recover();
            let sid = eng.open_session(then, 10, 10);
            eng.issue_lease(then, &sid, 900, 900, true).expect("issue")
        };
        // Handle for a role no engine serves — the backend user can't be deleted.
        state.cred_handles.lock_recover().insert(
            lease,
            CredHandle {
                role: "no-such-engine".into(),
                username: "orphan".into(),
            },
        );

        sweep_once(&state).await;

        assert!(sink.actions().contains(&(
            "creds.revoke".into(),
            Some("role=no-such-engine".into()),
            false
        )));
    }
}
