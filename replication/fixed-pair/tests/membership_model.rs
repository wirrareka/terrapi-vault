#[path = "support/membership_model.rs"]
mod model;
use model::*;

#[path = "support/membership_peers.rs"]
mod peers;

#[path = "support/membership_peer_tests.rs"]
mod peer_tests;

#[path = "support/membership_store.rs"]
mod store;
#[path = "support/membership_store_tests.rs"]
mod store_tests;

#[path = "support/membership_durable_pair.rs"]
mod durable_pair;

#[path = "support/recovery_grant.rs"]
mod recovery_grant;
#[path = "support/recovery_grant_tests.rs"]
mod recovery_grant_tests;

#[path = "support/recovery_registry.rs"]
mod recovery_registry;
#[path = "support/recovery_registry_tests.rs"]
mod recovery_registry_tests;

#[path = "support/authorized_recovery_tests.rs"]
mod authorized_recovery_tests;

#[path = "support/authorized_recovery_crashes.rs"]
mod authorized_recovery_crashes;

#[path = "support/recovery_diagnostics.rs"]
mod recovery_diagnostics;
#[path = "support/recovery_diagnostics_tests.rs"]
mod recovery_diagnostics_tests;

#[path = "support/recovery_completion.rs"]
mod recovery_completion;
#[path = "support/recovery_completion_tests.rs"]
mod recovery_completion_tests;

#[path = "support/recovery_rollback_tests.rs"]
mod recovery_rollback_tests;

#[path = "support/recovery_witness_model.rs"]
mod recovery_witness_model;

#[path = "support/recovery_witness_registry.rs"]
mod recovery_witness_registry;
#[path = "support/recovery_witness_registry_tests.rs"]
mod recovery_witness_registry_tests;

#[path = "support/recovery_witness_completion.rs"]
mod recovery_witness_completion;
#[path = "support/recovery_witness_completion_tests.rs"]
mod recovery_witness_completion_tests;

#[path = "support/recovery_witness_activation.rs"]
mod recovery_witness_activation;
#[path = "support/recovery_witness_activation_tests.rs"]
mod recovery_witness_activation_tests;

fn fixture() -> (Model, Plan) {
    let baseline = Baseline {
        scope: "eu/tenant-a/lineage-1/schema-1".into(),
        revision: 4,
        digest: [4; 32],
        old_primary: [1; 32],
        survivor: [2; 32],
        survivor_generation: [3; 32],
        checkpoint: [9; 32],
    };
    let plan = Plan {
        recovery_id: [5; 32],
        baseline: baseline.clone(),
        revision: 5,
        candidate: [6; 32],
    };
    (Model::new(baseline), plan)
}
fn sequence(p: &Plan) -> Vec<Event> {
    vec![
        Event::Authorize,
        Event::Fence(Fence::Isolated(p.baseline.old_primary)),
        Event::Seal {
            checkpoint: p.baseline.checkpoint,
            tail: Tail::Quiescent,
        },
        Event::Install(p.baseline.checkpoint),
        Event::Prepare(p.baseline.survivor),
        Event::Prepare(p.candidate),
        Event::Activate(p.baseline.survivor),
        Event::Activate(p.candidate),
    ]
}
fn ready() -> (Model, Plan) {
    let (mut m, p) = fixture();
    for e in sequence(&p) {
        m.step(&p, e).unwrap();
    }
    (m, p)
}
fn rejects(m: &mut Model, p: &Plan, e: Event) {
    let before = m.clone();
    assert!(m.step(p, e).is_err());
    assert_eq!(*m, before, "rejection changed model");
}

#[test]
fn happy_path_requires_both_active_and_live_peer() {
    let (mut m, p) = fixture();
    for e in sequence(&p) {
        assert!(!m.write_eligible(&p, p.candidate, true));
        m.step(&p, e).unwrap();
    }
    assert!(m.write_eligible(&p, p.candidate, true));
    for member in [p.baseline.old_primary, p.baseline.survivor, [7; 32]] {
        assert!(!m.write_eligible(&p, member, true));
    }
    assert!(!m.write_eligible(&p, p.candidate, false));
}

#[test]
fn health_check_is_not_fencing_and_wrong_instance_is_rejected() {
    let (mut m, p) = fixture();
    m.step(&p, Event::Authorize).unwrap();
    rejects(&mut m, &p, Event::Fence(Fence::HealthFailed));
    rejects(&mut m, &p, Event::Fence(Fence::Isolated(p.candidate)));
}

#[test]
fn uncertain_or_corrupt_source_never_seals() {
    let (mut m, p) = fixture();
    for e in sequence(&p).into_iter().take(2) {
        m.step(&p, e).unwrap();
    }
    for tail in [Tail::Prepared, Tail::Decided, Tail::Corrupt, Tail::Unknown] {
        rejects(
            &mut m,
            &p,
            Event::Seal {
                checkpoint: p.baseline.checkpoint,
                tail,
            },
        );
    }
    rejects(
        &mut m,
        &p,
        Event::Seal {
            checkpoint: [8; 32],
            tail: Tail::Quiescent,
        },
    );
    rejects(&mut m, &p, Event::Install(p.baseline.checkpoint));
}

#[test]
fn every_plan_field_is_bound_even_for_retries() {
    let (m, p) = ready();
    let mut variants = Vec::new();
    macro_rules! changed {
        ($field:expr, $value:expr) => {{
            let mut q = p.clone();
            ($field)(&mut q, $value);
            variants.push(q);
        }};
    }
    changed!(|q: &mut Plan, v| q.recovery_id = v, [8; 32]);
    changed!(|q: &mut Plan, v| q.candidate = v, [8; 32]);
    changed!(|q: &mut Plan, v| q.revision = v, 6);
    changed!(
        |q: &mut Plan, v| q.baseline.scope = v,
        "other-tenant".into()
    );
    changed!(|q: &mut Plan, v| q.baseline.revision = v, 3);
    changed!(|q: &mut Plan, v| q.baseline.digest = v, [8; 32]);
    changed!(|q: &mut Plan, v| q.baseline.old_primary = v, [8; 32]);
    changed!(|q: &mut Plan, v| q.baseline.survivor = v, [8; 32]);
    changed!(
        |q: &mut Plan, v| q.baseline.survivor_generation = v,
        [8; 32]
    );
    changed!(|q: &mut Plan, v| q.baseline.checkpoint = v, [8; 32]);
    for q in variants {
        for e in sequence(&q) {
            rejects(&mut m.clone(), &q, e);
        }
        assert!(!m.write_eligible(&q, q.candidate, true));
    }
}

#[test]
fn concurrent_candidate_cannot_replace_authorized_plan() {
    let (mut m, p) = fixture();
    m.step(&p, Event::Authorize).unwrap();
    let mut q = p.clone();
    q.candidate = [7; 32];
    q.recovery_id = [8; 32];
    rejects(&mut m, &q, Event::Authorize);
    for e in sequence(&p) {
        m.step(&p, e).unwrap();
    }
    rejects(&mut m, &q, Event::Authorize);
}

#[test]
fn invalid_initial_plan_and_revision_overflow_fail_closed() {
    let (m, p) = fixture();
    for candidate in [[0; 32], p.baseline.old_primary, p.baseline.survivor] {
        let mut q = p.clone();
        q.candidate = candidate;
        rejects(&mut m.clone(), &q, Event::Authorize);
    }
    for revision in [0, 4, 6, u64::MAX] {
        let mut q = p.clone();
        q.revision = revision;
        rejects(&mut m.clone(), &q, Event::Authorize);
    }
    let mut q = p.clone();
    q.recovery_id = [0; 32];
    rejects(&mut m.clone(), &q, Event::Authorize);
    let mut q = p;
    q.baseline.revision = u64::MAX;
    q.revision = 0;
    rejects(&mut Model::new(q.baseline.clone()), &q, Event::Authorize);
}

#[test]
fn bad_install_and_nonmembers_do_not_advance() {
    let (mut m, p) = fixture();
    for e in sequence(&p).into_iter().take(3) {
        m.step(&p, e).unwrap();
    }
    rejects(&mut m, &p, Event::Install([8; 32]));
    m.step(&p, Event::Install(p.baseline.checkpoint)).unwrap();
    for member in [p.baseline.old_primary, [8; 32]] {
        rejects(&mut m, &p, Event::Prepare(member));
        rejects(&mut m, &p, Event::Activate(member));
    }
}

#[test]
fn malformed_baseline_is_rejected_even_if_plan_matches_it() {
    let (_, p) = fixture();
    for field in 0..7 {
        let mut q = p.clone();
        match field {
            0 => q.baseline.scope = " ".into(),
            1 => q.baseline.digest = [0; 32],
            2 => q.baseline.old_primary = [0; 32],
            3 => q.baseline.survivor = [0; 32],
            4 => q.baseline.survivor_generation = [0; 32],
            5 => q.baseline.checkpoint = [0; 32],
            _ => q.baseline.old_primary = q.baseline.survivor,
        }
        rejects(&mut Model::new(q.baseline.clone()), &q, Event::Authorize);
    }
}

#[test]
fn both_activation_orders_work_but_one_prepared_side_is_insufficient() {
    for first in [0, 1] {
        let (mut m, p) = fixture();
        for e in sequence(&p).into_iter().take(4) {
            m.step(&p, e).unwrap();
        }
        let ids = [p.candidate, p.baseline.survivor];
        m.step(&p, Event::Prepare(ids[first])).unwrap();
        rejects(&mut m, &p, Event::Activate(ids[first]));
        m.step(&p, Event::Prepare(ids[1 - first])).unwrap();
        m.step(&p, Event::Activate(ids[first])).unwrap();
        assert!(!m.write_eligible(&p, p.candidate, true));
        m.step(&p, Event::Activate(ids[1 - first])).unwrap();
        assert!(m.write_eligible(&p, p.candidate, true));
    }
}

#[test]
fn lost_ack_retry_at_every_abstract_atomic_boundary() {
    let (m, p) = fixture();
    let events = sequence(&p);
    for cut in 0..=events.len() {
        let mut saved = m.clone();
        for e in events.iter().take(cut) {
            saved.step(&p, e.clone()).unwrap();
        }
        // Copies represent abstract saved states, NOT actual disk/crash durability.
        let mut resumed = saved.clone();
        for e in &events {
            resumed.step(&p, e.clone()).unwrap();
        }
        assert!(resumed.write_eligible(&p, p.candidate, true));
        let active = resumed.clone();
        for e in &events {
            resumed.step(&p, e.clone()).unwrap();
        }
        assert_eq!(active, resumed);
    }
}

#[test]
fn explore_all_reachable_states_and_out_of_order_events() {
    let (m, p) = fixture();
    let events = sequence(&p);
    let mut states = vec![m];
    let mut index = 0;
    while index < states.len() {
        let before = states[index].clone();
        index += 1;
        for event in &events {
            let mut after = before.clone();
            match after.step(&p, event.clone()) {
                Err(_) => assert_eq!(after, before),
                Ok(()) => {
                    if after.write_eligible(&p, p.candidate, true) {
                        assert!(after.both_active());
                        assert!(!after.write_eligible(&p, p.candidate, false));
                    }
                    if !states.contains(&after) {
                        states.push(after);
                    }
                }
            }
        }
    }
    assert_eq!(states.len(), 11);
}
