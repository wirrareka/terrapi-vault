use super::{
    authorized_recovery_tests::{peer, seed, Harness},
    fixture,
    peers::Local,
    recovery_diagnostics::*,
    store::Crash,
};

fn activate(h: &Harness, primary: bool) {
    let store = h.store(primary);
    let registry = h.registry();
    let current = store.load(&seed(primary)).unwrap();
    store
        .activate_authorized(
            &current,
            [10; 32],
            peer(primary, [11; 32]).report([10; 32]),
            &h.token,
            &registry,
            || h.ctx(),
            Crash::None,
        )
        .unwrap();
}

#[test]
fn prepared_partial_and_both_active_are_observations_not_completion() {
    let h = Harness::new();
    let p = h.store(true);
    let s = h.store(false);
    let r = h.registry();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.pair, Pair::WaitingForActivation);
    assert_eq!(report.authorization, Authorization::ValidAtObservation);
    activate(&h, true);
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.pair, Pair::PartialActivation);
    activate(&h, false);
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.pair, Pair::BothActiveObserved);
    assert_eq!(report.completion, Completion::NotEstablished);
    assert!(report.non_atomic_observation);
}

#[test]
fn expiry_and_missing_registry_do_not_relabel_active_as_prepared() {
    let h = Harness::new();
    activate(&h, true);
    activate(&h, false);
    let p = h.store(true);
    let s = h.store(false);
    let r = h.registry();
    let mut ctx = h.ctx();
    ctx.now = 200;
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &ctx);
    assert_eq!(report.authorization, Authorization::Rejected);
    assert_eq!(report.pair, Pair::BothActiveObserved);
    let report = diagnose([Some(&p), Some(&s)], None, &fixture().1, &ctx);
    assert_eq!(report.registry, RegistryState::Unavailable);
    assert_eq!(report.members[0], Member::ActiveUnverified);
    assert_eq!(report.pair, Pair::InspectionIncomplete);
    assert_eq!(report.completion, Completion::Unavailable);
}

#[test]
fn quarantine_missing_member_and_wrong_role_are_reported_fail_closed() {
    let h = Harness::new();
    activate(&h, true);
    let p = h.store(true);
    let s = h.store(false);
    let r = h.registry();
    let current = p.load(&seed(true)).unwrap();
    let mut local = Local::restart(current.saved, [10; 32]).unwrap();
    local.quarantine();
    p.update(&p.load(&seed(true)).unwrap(), local.saved(), Crash::None)
        .unwrap();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.pair, Pair::Quarantined);
    assert_eq!(report.members[0], Member::Quarantined);
    let report = diagnose([None, Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.members[0], Member::Unavailable);
    assert_eq!(report.pair, Pair::InspectionIncomplete);
    let report = diagnose([Some(&s), Some(&p)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.members, [Member::Invalid, Member::Invalid]);
}

#[test]
fn corrupt_binding_and_registry_are_not_reported_as_success() {
    let h = Harness::new();
    activate(&h, true);
    let p = h.store(true);
    let s = h.store(false);
    let r = h.registry();
    p.connection(|c| {
        c.execute_batch("DELETE FROM recovery_grants")?;
        Ok(())
    })
    .unwrap();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.members[0], Member::ActiveWithoutBinding);
    assert_eq!(report.pair, Pair::InspectionIncomplete);
    r.connection(|c| {
        c.execute_batch("UPDATE registry SET format=9")?;
        Ok(())
    })
    .unwrap();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.registry, RegistryState::Invalid);
    assert_eq!(report.authorization, Authorization::NotChecked);
}

#[test]
fn report_is_redacted_and_works_with_query_only_connections_without_changes() {
    let h = Harness::new();
    activate(&h, true);
    activate(&h, false);
    let p = h.store(true);
    let s = h.store(false);
    let r = h.registry();
    let before = [p.load(&seed(true)).unwrap(), s.load(&seed(false)).unwrap()];
    let registry_before = r.load().unwrap();
    for store in [&p, &s] {
        store
            .connection(|c| {
                c.pragma_update(None, "query_only", true)?;
                Ok(())
            })
            .unwrap();
    }
    r.connection(|c| {
        c.pragma_update(None, "query_only", true)?;
        Ok(())
    })
    .unwrap();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.pair, Pair::BothActiveObserved);
    let serialized = serde_json::to_string(&report).unwrap();
    let debug = format!("{report:?}");
    for output in [serialized, debug] {
        for secret in [
            &h.token,
            "fixture-install",
            "tenant-a",
            "fixture-key",
            "fencing_ref",
        ] {
            assert!(!output.contains(secret));
        }
    }
    assert_eq!(
        [p.load(&seed(true)).unwrap(), s.load(&seed(false)).unwrap()],
        before
    );
    assert_eq!(r.load().unwrap(), registry_before);
}

#[test]
fn empty_reserved_wrong_binding_and_wrong_registry_scope_remain_distinct() {
    use super::recovery_registry::{Crash as RegistryCrash, Registry};
    let h = Harness::new();
    let p = h.store(true);
    let s = h.store(false);
    let r = Registry::create(
        &h.dir.path().join("empty.db"),
        fixture().1.baseline,
        "fixture-install",
        "eu",
    )
    .unwrap();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.registry, RegistryState::Empty);
    assert_eq!(report.authorization, Authorization::NotChecked);
    let input = h.token.rsplit_once('.').unwrap().0;
    r.reserve(input, &h.ctx(), RegistryCrash::None).unwrap();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.registry, RegistryState::Reserved);
    assert_eq!(report.authorization, Authorization::NotChecked);
    activate(&h, true);
    let r = h.registry();
    p.connection(|c| {
        c.execute_batch("UPDATE recovery_grants SET token='other'")?;
        Ok(())
    })
    .unwrap();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.members[0], Member::GrantMismatch);
    assert_eq!(report.pair, Pair::InspectionIncomplete);
    // A valid token does not validate corrupted registry metadata.
    r.connection(|c| {
        c.execute_batch("UPDATE registry SET install='other'")?;
        Ok(())
    })
    .unwrap();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &h.ctx());
    assert_eq!(report.registry, RegistryState::Published);
    assert_eq!(report.authorization, Authorization::Rejected);
}
