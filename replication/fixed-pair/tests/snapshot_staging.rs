use terrapi_vesta_replication::{journal::MAX_PAGE_ENTRIES, *};

fn identity() -> Identity {
    Identity {
        cluster: "test".into(),
        tenant: "one".into(),
        epoch: 1,
        schema: 1,
    }
}
fn source(path: &std::path::Path) -> Node {
    let mut p = Node::open(path, Role::Primary, identity(), "fixture").unwrap();
    for id in ["one", "two", "three"] {
        let b = Batch {
            identity: identity(),
            operation_id: id.into(),
            changes: vec![Change::PutPlace {
                id: id.into(),
                name: "secret-staging-marker".into(),
            }],
        };
        p.prepare(b).unwrap();
        let e = p.decide(id).unwrap();
        p.apply(e).unwrap();
    }
    p
}

#[test]
fn staging_survives_restart_retries_and_installs_atomically_without_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let p = source(&dir.path().join("p"));
    let path = dir.path().join("s");
    let mut s = Node::open(&path, Role::Secondary, identity(), "fixture").unwrap();
    let manifest = p.snapshot_manifest().unwrap();
    let progress = s.snapshot_begin(manifest.clone()).unwrap();
    let page = p.journal_page(&manifest.head, 0, 1).unwrap();
    s.snapshot_chunk(progress.token, page.clone()).unwrap();
    // Fixture scan of encrypted DB/WAL while the secret exists only in staging.
    for file in [
        path.clone(),
        std::path::PathBuf::from(format!("{}-wal", path.display())),
    ] {
        if let Ok(bytes) = std::fs::read(file) {
            let marker = b"secret-staging-marker";
            assert!(!bytes.windows(marker.len()).any(|b| b == marker));
        }
    }
    assert_eq!(s.snapshot_chunk(progress.token, page).unwrap().received, 1);
    assert!(s.snapshot_finish(progress.token).is_err());
    assert!(s.view().unwrap().places.is_empty());
    drop(s);
    let mut s = Node::open(&path, Role::Secondary, identity(), "fixture").unwrap();
    let resumed = s.snapshot_begin(manifest.clone()).unwrap();
    assert_eq!(resumed.token, progress.token);
    assert_eq!(resumed.received, 1);
    assert!(s.verified_view().unwrap().is_none());
    s.snapshot_chunk(
        progress.token,
        p.journal_page(&manifest.head, 1, MAX_PAGE_ENTRIES).unwrap(),
    )
    .unwrap();
    s.snapshot_finish(progress.token).unwrap();
    s.snapshot_finish(progress.token).unwrap();
    assert_eq!(s.view().unwrap(), p.view().unwrap());
    assert!(s.verified_view().unwrap().is_none());
    s.confirm_checkpoint(p.checkpoint().unwrap()).unwrap();
    assert_eq!(s.verified_view().unwrap(), Some(p.view().unwrap()));
}

#[test]
fn active_transfer_blocks_live_mutations_and_rejects_bad_pages() {
    let dir = tempfile::tempdir().unwrap();
    let p = source(&dir.path().join("p"));
    let mut s = Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture").unwrap();
    let empty = s.checkpoint().unwrap();
    s.confirm_checkpoint(empty.clone()).unwrap();
    let m = p.snapshot_manifest().unwrap();
    let t = s.snapshot_begin(m.clone()).unwrap();
    assert!(s.verified_view().unwrap().is_none());
    let first = p.journal_page(&m.head, 0, 1).unwrap();
    assert!(s.stage(first.entries[0].clone()).is_err());
    assert!(s.apply(first.entries[0].clone()).is_err());
    assert!(s.abort("one").is_err());
    assert!(s.install(p.snapshot().unwrap()).is_err());
    assert!(s.confirm_checkpoint(empty).is_err());
    let gap = p.journal_page(&m.head, 1, 1).unwrap();
    assert!(s.snapshot_chunk(t.token, gap).is_err());
    for case in 0..3 {
        let mut bad = first.clone();
        match case {
            0 => bad.head.revision[0] ^= 1,
            1 => bad.entries[0].state = State::Prepared,
            _ => bad.entries[0].digest = "wrong".into(),
        }
        assert!(s.snapshot_chunk(t.token, bad).is_err());
    }
    assert_eq!(s.snapshot_progress().unwrap().unwrap().received, 0);
    s.snapshot_chunk(t.token, p.journal_page(&m.head, 0, 2).unwrap())
        .unwrap();
    assert!(s
        .snapshot_chunk(t.token, p.journal_page(&m.head, 1, 2).unwrap())
        .is_err());
    assert!(s.view().unwrap().places.is_empty());
}

#[test]
fn bad_final_checkpoint_rolls_back_all_live_data_and_preserves_staging() {
    let dir = tempfile::tempdir().unwrap();
    let p = source(&dir.path().join("p"));
    let mut s = Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture").unwrap();
    let mut m = p.snapshot_manifest().unwrap();
    m.checkpoint.journal_digest = "wrong".into();
    let t = s.snapshot_begin(m.clone()).unwrap();
    s.snapshot_chunk(
        t.token,
        p.journal_page(&m.head, 0, MAX_PAGE_ENTRIES).unwrap(),
    )
    .unwrap();
    let head = s.journal_head().unwrap();
    assert!(s.snapshot_finish(t.token).is_err());
    assert_eq!(s.journal_head().unwrap(), head);
    assert!(s.view().unwrap().places.is_empty());
    let progress = s.snapshot_progress().unwrap().unwrap();
    assert_eq!(progress.received, 3);
    assert!(!progress.complete);
    assert!(s.verified_view().unwrap().is_none());
}

#[test]
fn quarantine_cancel_and_new_transfer_reject_delayed_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = source(&dir.path().join("p"));
    let mut s = Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture").unwrap();
    let m = p.snapshot_manifest().unwrap();
    let page = p.journal_page(&m.head, 0, MAX_PAGE_ENTRIES).unwrap();
    let old = s.snapshot_begin(m.clone()).unwrap();
    s.quarantine().unwrap();
    assert!(s.snapshot_chunk(old.token, page.clone()).is_err());
    assert!(s.snapshot_finish(old.token).is_err());
    assert!(s.snapshot_begin(m.clone()).is_err());
    s.snapshot_cancel(old.token).unwrap();
    let new = s.snapshot_begin(m).unwrap();
    assert_ne!(old.token, new.token);
    assert!(s.snapshot_cancel(old.token).is_err());
    assert!(s.snapshot_finish(old.token).is_err());
    assert!(s.snapshot_chunk(old.token, page.clone()).is_err());
    s.snapshot_chunk(new.token, page).unwrap();
    s.snapshot_finish(new.token).unwrap();
    recover(&mut p, &mut s).unwrap();
    commit(
        &mut p,
        &mut s,
        Batch {
            identity: identity(),
            operation_id: "tail".into(),
            changes: vec![],
        },
    )
    .unwrap();
    assert!(s.snapshot_finish(new.token).is_err());
    s.snapshot_cancel(new.token).unwrap();
    assert_eq!(s.verified_view().unwrap(), Some(p.view().unwrap()));
}

#[test]
fn empty_snapshots_source_changes_identity_and_nonempty_target() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    let mut s = Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture").unwrap();
    let m = p.snapshot_manifest().unwrap();
    assert!(p.snapshot_begin(m.clone()).is_err());
    assert!(s.snapshot_manifest().is_err());
    let mut wrong = m.clone();
    wrong.head.identity.tenant = "other".into();
    assert!(s.snapshot_begin(wrong).is_err());
    let mut wrong = m.clone();
    wrong.head.length = snapshot_staging::MAX_STAGED_ENTRIES + 1;
    wrong.checkpoint.sequence = wrong.head.length;
    assert!(s.snapshot_begin(wrong).is_err());
    let t = s.snapshot_begin(m.clone()).unwrap();
    s.snapshot_finish(t.token).unwrap();
    assert!(s.verified_view().unwrap().is_none());
    s.confirm_checkpoint(m.checkpoint.clone()).unwrap();
    s.snapshot_cancel(t.token).unwrap();
    p.prepare(Batch {
        identity: identity(),
        operation_id: "one".into(),
        changes: vec![],
    })
    .unwrap();
    assert!(p.snapshot_manifest().is_err());
    assert!(p.journal_page(&m.head, 0, MAX_PAGE_ENTRIES).is_err());
    p.decide("one").unwrap();
    recover(&mut p, &mut s).unwrap();
    assert!(s.snapshot_begin(p.snapshot_manifest().unwrap()).is_err());
}
