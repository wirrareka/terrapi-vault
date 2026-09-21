use terrapi_vesta_replication::*;
fn identity() -> Identity {
    Identity {
        cluster: "pair".into(),
        tenant: "one".into(),
        epoch: 1,
        schema: 1,
    }
}
fn batch(id: &str) -> Batch {
    Batch {
        identity: identity(),
        operation_id: id.into(),
        changes: vec![Change::PutPlace {
            id: id.into(),
            name: "Airport".into(),
        }],
    }
}
fn nodes(dir: &std::path::Path) -> (Node, Node) {
    (
        Node::open(
            dir.join("p.vesta"),
            Role::Primary,
            identity(),
            "test passphrase",
        )
        .unwrap(),
        Node::open(
            dir.join("s.vesta"),
            Role::Secondary,
            identity(),
            "test passphrase",
        )
        .unwrap(),
    )
}
#[test]
fn empty_secondary_requires_confirmation_and_survives_restart_without_primary() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    assert!(s.verified_view().unwrap().is_none());
    recover(&mut p, &mut s).unwrap();
    assert_eq!(s.verified_view().unwrap(), Some(View::default()));
    commit(&mut p, &mut s, batch("one")).unwrap();
    let expected = s.verified_view().unwrap();
    drop(p);
    drop(s);
    let s = Node::open(
        dir.path().join("s.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    assert_eq!(s.verified_view().unwrap(), expected);
    assert_eq!(expected.unwrap().places.len(), 1);
}
#[test]
fn wrong_checkpoint_and_unresolved_transaction_cannot_enable_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    let expected = p.checkpoint().unwrap();
    for field in [
        "epoch", "tenant", "cluster", "schema", "sequence", "view", "journal",
    ] {
        let mut wrong = expected.clone();
        match field {
            "epoch" => wrong.identity.epoch += 1,
            "tenant" => wrong.identity.tenant = "other".into(),
            "cluster" => wrong.identity.cluster = "other".into(),
            "schema" => wrong.identity.schema += 1,
            "sequence" => wrong.sequence += 1,
            "view" => wrong.view_digest = "bad".into(),
            _ => wrong.journal_digest = "bad".into(),
        }
        assert!(s.confirm_checkpoint(wrong).is_err());
        assert!(s.verified_view().unwrap().is_none());
    }
    s.stage(p.prepare(batch("one")).unwrap()).unwrap();
    assert!(p.checkpoint().is_err());
    assert!(s.confirm_checkpoint(expected.clone()).is_err());
    assert!(s.verified_view().unwrap().is_none());
    assert!(p.confirm_checkpoint(expected).is_err());
}
#[test]
fn confirmed_prefix_remains_readable_during_prepare_and_advances_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    recover(&mut p, &mut s).unwrap();
    s.stage(p.prepare(batch("one")).unwrap()).unwrap();
    assert_eq!(s.verified_view().unwrap(), Some(View::default()));
    s.apply(p.decide("one").unwrap()).unwrap();
    assert_eq!(s.verified_view().unwrap().unwrap().places.len(), 1);
    assert!(p.view().unwrap().places.is_empty());
}
#[test]
fn quarantine_survives_restart_and_requires_current_primary_reconciliation() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    commit(&mut p, &mut s, batch("one")).unwrap();
    let mut other = Node::open(
        dir.path().join("other.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    other.install(p.snapshot().unwrap()).unwrap();
    commit(&mut p, &mut other, batch("two")).unwrap();
    s.quarantine().unwrap();
    assert!(s.verified_view().unwrap().is_none());
    drop(s);
    let mut s = Node::open(
        dir.path().join("s.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    assert!(s.verified_view().unwrap().is_none());
    assert_eq!(s.view().unwrap().places.len(), 1);
    recover(&mut p, &mut s).unwrap();
    assert_eq!(s.verified_view().unwrap().unwrap().places.len(), 2);
}
#[test]
fn snapshot_install_is_not_a_readiness_grant_even_for_empty_database() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    recover(&mut p, &mut s).unwrap();
    assert!(s.verified_view().unwrap().is_some());
    s.install(p.snapshot().unwrap()).unwrap();
    assert!(s.verified_view().unwrap().is_none());
    s.confirm_checkpoint(p.checkpoint().unwrap()).unwrap();
    assert!(s.verified_view().unwrap().is_some());
}

#[test]
fn old_generation_cannot_reapprove_quarantined_copy_even_with_matching_data() {
    let dir = tempfile::tempdir().unwrap();
    let (p, mut s) = nodes(dir.path());
    let checkpoint = p.checkpoint().unwrap();
    let generation = s.status().unwrap().read_generation;
    s.confirm_generation(checkpoint.clone(), generation)
        .unwrap();
    s.quarantine().unwrap();
    drop(s);
    let mut s = Node::open(
        dir.path().join("s.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    assert_ne!(s.status().unwrap().read_generation, generation);
    assert!(s
        .confirm_generation(checkpoint.clone(), generation)
        .is_err());
    assert!(s.verified_view().unwrap().is_none());
    s.confirm_generation(checkpoint, s.status().unwrap().read_generation)
        .unwrap();
    assert!(s.verified_view().unwrap().is_some());
}
