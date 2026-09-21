use terrapi_vesta_replication::*;

fn identity() -> Identity {
    Identity {
        cluster: "eu-pair".into(),
        tenant: "tenant-a".into(),
        epoch: 1,
        schema: 1,
    }
}

fn batch(id: &str, name: &str) -> Batch {
    Batch {
        identity: identity(),
        operation_id: id.into(),
        changes: vec![Change::PutPlace {
            id: "place-1".into(),
            name: name.into(),
        }],
    }
}

fn nodes(dir: &std::path::Path) -> (Node, Node) {
    (
        Node::open(
            dir.join("primary.vesta"),
            Role::Primary,
            identity(),
            "test passphrase",
        )
        .unwrap(),
        Node::open(
            dir.join("secondary.vesta"),
            Role::Secondary,
            identity(),
            "test passphrase",
        )
        .unwrap(),
    )
}

#[test]
fn sqlcipher_session_full_durability_and_idempotence() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    let status = p.status().unwrap();
    assert!(!status.cipher_version.is_empty());
    assert_eq!(status.synchronous, 2);
    assert_eq!(status.journal_mode, "wal");
    commit(&mut p, &mut s, batch("op-1", "Airport")).unwrap();
    commit(&mut p, &mut s, batch("op-1", "Airport")).unwrap();
    assert_eq!(p.view().unwrap(), s.view().unwrap());
    assert_eq!(p.status().unwrap().entries.len(), 1);
    assert_eq!(p.view().unwrap().places[0].name, "Airport");
    assert!(commit(&mut p, &mut s, batch("op-1", "Different")).is_err());
    let bytes = std::fs::read(dir.path().join("primary.vesta")).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3"));
    assert!(!bytes.windows(7).any(|w| w == b"Airport"));
}

#[test]
fn prepared_changes_are_invisible_and_abort_on_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    let entry = p.prepare(batch("op-1", "Airport")).unwrap();
    s.stage(entry).unwrap();
    assert!(p.view().unwrap().places.is_empty());
    assert!(s.view().unwrap().places.is_empty());
    assert_eq!(recover(&mut p, &mut s).unwrap(), 0);
    assert!(p.status().unwrap().entries.is_empty());
    assert!(s.status().unwrap().entries.is_empty());
    commit(&mut p, &mut s, batch("op-1", "Airport")).unwrap();
}

#[test]
fn durable_decision_is_completed_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (mut p, mut s) = nodes(dir.path());
        let entry = p.prepare(batch("op-1", "Airport")).unwrap();
        s.stage(entry).unwrap();
        p.decide("op-1").unwrap();
        assert!(p.view().unwrap().places.is_empty());
        assert!(s.view().unwrap().places.is_empty());
    }
    let (mut p, mut s) = nodes(dir.path());
    assert_eq!(recover(&mut p, &mut s).unwrap(), 1);
    assert_eq!(p.view().unwrap(), s.view().unwrap());
    assert_eq!(p.view().unwrap().places.len(), 1);
    assert_eq!(recover(&mut p, &mut s).unwrap(), 0);
}

#[test]
fn decision_retry_after_secondary_apply_does_not_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    s.stage(p.prepare(batch("op-1", "Airport")).unwrap())
        .unwrap();
    let decision = p.decide("op-1").unwrap();
    s.apply(decision).unwrap();
    assert!(p.view().unwrap().places.is_empty());
    assert_eq!(s.view().unwrap().places.len(), 1);
    commit(&mut p, &mut s, batch("op-1", "Airport")).unwrap();
    assert_eq!(p.view().unwrap(), s.view().unwrap());
    assert_eq!(p.status().unwrap().entries.len(), 1);
}

#[test]
fn changesets_replicate_foreign_keys_updates_and_cascaded_deletes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    let mut b = batch("op-1", "Airport");
    b.changes.push(Change::PutFeature {
        id: "feature-1".into(),
        place_id: "place-1".into(),
        geojson: r#"{"type":"Point","coordinates":[17,48]}"#.into(),
    });
    commit(&mut p, &mut s, b).unwrap();
    commit(&mut p, &mut s, batch("op-2", "Terminal")).unwrap();
    assert_eq!(s.view().unwrap().features.len(), 1);
    let mut b = batch("op-3", "");
    b.changes = vec![Change::DeletePlace {
        id: "place-1".into(),
    }];
    commit(&mut p, &mut s, b).unwrap();
    assert_eq!(p.view().unwrap(), View::default());
    assert_eq!(p.view().unwrap(), s.view().unwrap());
}

#[test]
fn rejects_wrong_tenant_epoch_schema_role_and_tampered_changeset() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    assert!(s.prepare(batch("bad-role", "Airport")).is_err());
    for field in ["tenant", "epoch", "schema"] {
        let mut b = batch(field, "Airport");
        match field {
            "tenant" => b.identity.tenant = "tenant-b".into(),
            "epoch" => b.identity.epoch = 2,
            _ => b.identity.schema = 2,
        }
        assert!(p.prepare(b).is_err());
    }
    let entry = p.prepare(batch("op-1", "Airport")).unwrap();
    let mut bad = entry.clone();
    bad.changeset.push(0);
    assert!(s.stage(bad).is_err());
    let mut out_of_order = entry;
    out_of_order.sequence = 2;
    assert!(s.stage(out_of_order).is_err());
    assert!(s.view().unwrap().places.is_empty());
}

#[test]
fn invalid_business_transaction_leaves_no_partial_changes_or_journal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, _) = nodes(dir.path());
    let mut b = batch("op-1", "Airport");
    b.changes.push(Change::PutFeature {
        id: "feature".into(),
        place_id: "missing".into(),
        geojson: "{}".into(),
    });
    assert!(p.prepare(b).is_err());
    assert_eq!(p.view().unwrap(), View::default());
    assert!(p.status().unwrap().entries.is_empty());
}

#[test]
fn exclusive_node_lock_and_persisted_identity() {
    let dir = tempfile::tempdir().unwrap();
    let (p, s) = nodes(dir.path());
    assert!(Node::open(
        dir.path().join("primary.vesta"),
        Role::Primary,
        identity(),
        "test passphrase"
    )
    .is_err());
    drop(p);
    drop(s);
    assert!(Node::open(
        dir.path().join("primary.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase"
    )
    .is_err());
    let mut wrong = identity();
    wrong.tenant = "other".into();
    assert!(Node::open(
        dir.path().join("primary.vesta"),
        Role::Primary,
        wrong,
        "test passphrase"
    )
    .is_err());
    assert!(Node::open(
        dir.path().join("primary.vesta"),
        Role::Primary,
        identity(),
        "wrong password"
    )
    .is_err());
}

#[test]
fn snapshot_seed_then_tail_keeps_data_and_deduplication_history() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    commit(&mut p, &mut s, batch("op-1", "Airport")).unwrap();
    let snapshot = p.snapshot().unwrap();
    let mut replacement = Node::open(
        dir.path().join("replacement.vesta"),
        Role::Secondary,
        identity(),
        "another passphrase",
    )
    .unwrap();
    replacement.install(snapshot).unwrap();
    assert_eq!(p.view().unwrap(), replacement.view().unwrap());
    commit(&mut p, &mut replacement, batch("op-2", "Terminal")).unwrap();
    commit(&mut p, &mut replacement, batch("op-1", "Airport")).unwrap();
    assert_eq!(replacement.view().unwrap().places[0].name, "Terminal");
    assert_eq!(p.view().unwrap(), replacement.view().unwrap());
}

#[test]
fn no_op_duplicate_stage_and_invalid_decision_are_safe() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    let e = p.prepare(batch("one", "Airport")).unwrap();
    assert!(p.apply(e.clone()).is_err());
    assert!(s.apply(e.clone()).is_err());
    s.stage(e.clone()).unwrap();
    s.stage(e).unwrap();
    let e = p.decide("one").unwrap();
    assert!(p.abort("one").is_err());
    s.apply(e.clone()).unwrap();
    s.apply(e.clone()).unwrap();
    p.apply(e).unwrap();
    // Empty changeset, but still a distinct durable idempotency record.
    let result = commit(&mut p, &mut s, batch("no-op", "Airport")).unwrap();
    assert_eq!(result.operation_id, "no-op");
    assert_eq!(result.sequence, 2);
    assert_eq!(p.status().unwrap().entries.len(), 2);
    assert_eq!(p.view().unwrap(), s.view().unwrap());
}

#[test]
fn snapshot_is_atomic_and_rejects_pending_or_nonempty_targets() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    p.prepare(batch("one", "Airport")).unwrap();
    assert!(p.snapshot().is_err());
    commit(&mut p, &mut s, batch("one", "Airport")).unwrap();
    assert!(s.install(p.snapshot().unwrap()).is_err());
    let mut replacement = Node::open(
        dir.path().join("new.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    let mut snapshot = p.snapshot().unwrap();
    snapshot.view.places[0].name = "tampered".into();
    assert!(replacement.install(snapshot).is_err());
    assert_eq!(replacement.view().unwrap(), View::default());
    assert!(replacement.status().unwrap().entries.is_empty());
    replacement.install(p.snapshot().unwrap()).unwrap();
    assert_eq!(replacement.view().unwrap(), p.view().unwrap());
}

#[test]
fn divergent_secondary_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut p, mut s) = nodes(dir.path());
    let mut other = Node::open(
        dir.path().join("other.vesta"),
        Role::Primary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    let conflicting = other.prepare(batch("conflict", "Other Airport")).unwrap();
    s.stage(conflicting).unwrap();
    p.prepare(batch("one", "Airport")).unwrap();
    assert!(recover(&mut p, &mut s).is_err());
    assert_eq!(p.view().unwrap(), View::default());
    assert_eq!(s.view().unwrap(), View::default());
    assert_eq!(p.status().unwrap().entries.len(), 1);
    assert_eq!(s.status().unwrap().entries.len(), 1);
}
