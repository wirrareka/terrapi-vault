use terrapi_vesta_replication::*;

fn identity() -> Identity {
    Identity {
        cluster: "pair".into(),
        tenant: "tenant".into(),
        epoch: 1,
        schema: 1,
    }
}
fn batch(id: &str, name: &str) -> Batch {
    Batch {
        identity: identity(),
        operation_id: id.into(),
        changes: vec![Change::PutPlace {
            id: "place".into(),
            name: name.into(),
        }],
    }
}
fn open(dir: &std::path::Path, name: &str, role: Role) -> Node {
    Node::open(dir.join(name), role, identity(), "receipt fixture").unwrap()
}

#[test]
fn durable_receipts_return_original_result_without_replaying_old_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let first;
    {
        let mut p = open(dir.path(), "p", Role::Primary);
        let mut s = open(dir.path(), "s", Role::Secondary);
        first = commit(&mut p, &mut s, batch("one", "old")).unwrap();
        assert_eq!(first.operation_id, "one");
        assert_eq!(p.receipt("one").unwrap(), s.receipt("one").unwrap());
        commit(&mut p, &mut s, batch("two", "new")).unwrap();
    }
    let mut p = open(dir.path(), "p", Role::Primary);
    let mut s = open(dir.path(), "s", Role::Secondary);
    assert_eq!(commit(&mut p, &mut s, batch("one", "old")).unwrap(), first);
    assert!(commit(&mut p, &mut s, batch("one", "conflict")).is_err());
    assert_eq!(p.view().unwrap().places[0].name, "new");
    assert_eq!(p.journal_head().unwrap().length, 2);
    assert_eq!(p.checkpoint().unwrap(), s.checkpoint().unwrap());
}

#[test]
fn receipts_exist_only_after_apply_and_survive_lost_secondary_ack() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = open(dir.path(), "p", Role::Primary);
    let mut s = open(dir.path(), "s", Role::Secondary);
    s.stage(p.prepare(batch("abort", "old")).unwrap()).unwrap();
    assert!(p.receipt("abort").unwrap().is_none());
    recover(&mut p, &mut s).unwrap();
    assert!(s.receipt("abort").unwrap().is_none());
    s.stage(p.prepare(batch("one", "old")).unwrap()).unwrap();
    let decision = p.decide("one").unwrap();
    assert!(p.receipt("one").unwrap().is_none());
    s.apply(decision).unwrap();
    assert!(s.receipt("one").unwrap().is_some());
    drop(p);
    drop(s);
    let mut p = open(dir.path(), "p", Role::Primary);
    let mut s = open(dir.path(), "s", Role::Secondary);
    let result = commit(&mut p, &mut s, batch("one", "old")).unwrap();
    assert_eq!(result.sequence, 1);
    assert_eq!(p.receipt("one").unwrap(), s.receipt("one").unwrap());
}

#[test]
fn both_snapshot_paths_reconstruct_and_verify_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = open(dir.path(), "p", Role::Primary);
    let mut s = open(dir.path(), "s", Role::Secondary);
    commit(&mut p, &mut s, batch("one", "old")).unwrap();
    let mut legacy = open(dir.path(), "legacy", Role::Secondary);
    legacy.install(p.snapshot().unwrap()).unwrap();
    assert_eq!(legacy.receipt("one").unwrap(), p.receipt("one").unwrap());
    let mut staged = open(dir.path(), "staged", Role::Secondary);
    let manifest = p.snapshot_manifest().unwrap();
    let progress = staged.snapshot_begin(manifest.clone()).unwrap();
    staged
        .snapshot_chunk(
            progress.token,
            p.journal_page(&manifest.head, 0, 32).unwrap(),
        )
        .unwrap();
    staged.snapshot_finish(progress.token).unwrap();
    assert_eq!(staged.receipt("one").unwrap(), p.receipt("one").unwrap());
    assert!(staged.verified_view().unwrap().is_none());
    recover(&mut p, &mut staged).unwrap();
    assert_eq!(staged.checkpoint().unwrap(), p.checkpoint().unwrap());
}
