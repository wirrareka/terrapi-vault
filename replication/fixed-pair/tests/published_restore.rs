use terrapi_vesta_replication::{publication::publish_base, *};
fn identity() -> Identity {
    Identity {
        cluster: "eu-pair".into(),
        tenant: "tenant-a".into(),
        epoch: 1,
        schema: 1,
    }
}
fn node(path: &std::path::Path, name: &str, role: Role) -> Node {
    Node::open(path.join(name), role, identity(), "fixture").unwrap()
}
fn batch(id: &str) -> Batch {
    Batch {
        identity: identity(),
        operation_id: id.into(),
        changes: vec![Change::PutPlace {
            id: "place".into(),
            name: id.into(),
        }],
    }
}
fn install(p: &Node, s: &mut Node, m: &materialized::Manifest) {
    let mut progress = s.materialized_begin(m.clone()).unwrap();
    while progress.received < m.rows().unwrap() {
        progress = s
            .materialized_chunk(
                progress.token,
                p.published_page(m, progress.received).unwrap(),
            )
            .unwrap();
    }
    s.materialized_finish(progress.token).unwrap();
}

#[test]
fn frozen_export_survives_live_changes_restart_and_restores_geo_receipts_then_tail() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut old = node(dir.path(), "old", Role::Secondary);
    let mut first = batch("one");
    first.changes.push(Change::PutFeature {
        id: "geo".into(),
        place_id: "place".into(),
        geojson: "{\"type\":\"Point\",\"coordinates\":[1,2]}".into(),
    });
    let result = commit(&mut p, &mut old, first.clone()).unwrap();
    publish_base(&mut p, &mut old).unwrap();
    let m = p.published_manifest().unwrap();
    let frozen = p.published_page(&m, 0).unwrap();
    let mut delete = batch("delete");
    delete.changes = vec![Change::DeletePlace { id: "place".into() }];
    commit(&mut p, &mut old, delete).unwrap();
    p.prepare(batch("pending")).unwrap();
    assert_eq!(p.published_page(&m, 0).unwrap(), frozen);
    drop(p);
    let mut p = node(dir.path(), "p", Role::Primary);
    assert_eq!(p.published_manifest().unwrap(), m);
    let mut s = node(dir.path(), "replacement", Role::Secondary);
    install(&p, &mut s, &m);
    assert_eq!(s.view().unwrap().features.len(), 1);
    assert_eq!(s.receipt("one").unwrap(), p.receipt("one").unwrap());
    assert!(s.verified_view().unwrap().is_none());
    assert!(s.status().unwrap().entries.is_empty());
    recover(&mut p, &mut s).unwrap();
    assert!(s.view().unwrap().places.is_empty());
    assert!(s.view().unwrap().features.is_empty());
    assert_eq!(commit(&mut p, &mut s, first).unwrap(), result);
    commit(&mut p, &mut s, batch("after")).unwrap();
    assert_eq!(p.checkpoint().unwrap(), s.checkpoint().unwrap());
    assert_eq!(p.status().unwrap().entries.len(), 3);
}

#[test]
fn frozen_transfer_resumes_after_both_restarts_and_live_source_advances() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut old = node(dir.path(), "old", Role::Secondary);
    let mut b = batch("one");
    b.changes = (0..40)
        .map(|i| Change::PutPlace {
            id: format!("p{i}"),
            name: "name".into(),
        })
        .collect();
    commit(&mut p, &mut old, b).unwrap();
    publish_base(&mut p, &mut old).unwrap();
    let m = p.published_manifest().unwrap();
    let mut s = node(dir.path(), "s", Role::Secondary);
    let progress = s.materialized_begin(m.clone()).unwrap();
    let page = p.published_page(&m, 0).unwrap();
    let progress = s.materialized_chunk(progress.token, page.clone()).unwrap();
    assert_eq!(
        s.materialized_chunk(progress.token, page).unwrap(),
        progress
    );
    assert!(!progress.complete);
    commit(&mut p, &mut old, batch("later")).unwrap();
    drop(p);
    drop(s);
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    assert_eq!(s.materialized_progress().unwrap(), Some(progress));
    install(&p, &mut s, &m);
    recover(&mut p, &mut s).unwrap();
    assert_eq!(p.checkpoint().unwrap(), s.checkpoint().unwrap());
}

#[test]
fn export_requires_confirmed_primary_and_rejects_manifest_substitution() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    assert!(p.published_manifest().is_err());
    let proposal = publication::Proposal {
        checkpoint: p.checkpoint().unwrap(),
        token: [1; 32],
        primary_generation: p.journal_head().unwrap().read_generation,
        secondary_generation: s.journal_head().unwrap().read_generation,
    };
    p.capture_base(proposal).unwrap();
    assert!(p.published_manifest().is_err());
    publish_base(&mut p, &mut s).unwrap();
    assert!(s.published_manifest().is_err());
    let m = p.published_manifest().unwrap();
    assert!(p.published_page(&m, 1).is_err());
    let mut bad = m.clone();
    bad.head.revision = [0; 32];
    assert!(p.published_page(&bad, 0).is_err());
    let mut bad = m.clone();
    bad.publication = None;
    assert!(p.published_page(&bad, 0).is_err());
    assert!(p.materialized_page(&m, 0).is_err());
    let mut target = node(dir.path(), "target", Role::Secondary);
    install(&p, &mut target, &m);
    assert!(target.verified_view().unwrap().is_none());
    recover(&mut p, &mut target).unwrap();
    assert_eq!(target.verified_view().unwrap(), Some(View::default()));
}

#[test]
fn frozen_restore_commit_crashes_preserve_receipts_and_resume_tail() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    for (point, code, committed) in [("before_commit", 89, false), ("after_commit", 90, true)] {
        let dir = tempfile::tempdir().unwrap();
        let mut p = node(dir.path(), "p", Role::Primary);
        let mut old = node(dir.path(), "old", Role::Secondary);
        commit(&mut p, &mut old, batch("one")).unwrap();
        publish_base(&mut p, &mut old).unwrap();
        let m = p.published_manifest().unwrap();
        commit(&mut p, &mut old, batch("two")).unwrap();
        let mut s = node(dir.path(), "s", Role::Secondary);
        let progress = s.materialized_begin(m.clone()).unwrap();
        s.materialized_chunk(progress.token, p.published_page(&m, 0).unwrap())
            .unwrap();
        drop(s);
        let mut child = Command::new(env!("CARGO_BIN_EXE_vesta-node"))
            .arg(dir.path().join("s"))
            .arg("secondary")
            .env("VESTA_PROTOTYPE_PASSPHRASE", "fixture")
            .env("VESTA_PROTOTYPE_CRASH_MATERIALIZED", point)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            child.stdin.take().unwrap(),
            "{}",
            serde_json::json!({"command":"materialized_finish","token":progress.token})
        )
        .unwrap();
        assert_eq!(child.wait_with_output().unwrap().status.code(), Some(code));
        let mut s = node(dir.path(), "s", Role::Secondary);
        assert_eq!(s.receipt("one").unwrap().is_some(), committed);
        assert_eq!(s.view().unwrap().places.len(), usize::from(committed));
        assert!(s.verified_view().unwrap().is_none());
        install(&p, &mut s, &m);
        recover(&mut p, &mut s).unwrap();
        assert_eq!(s.checkpoint().unwrap(), p.checkpoint().unwrap());
    }
}

#[test]
fn corrupted_frozen_page_cannot_publish_live_state_and_can_be_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut old = node(dir.path(), "old", Role::Secondary);
    commit(&mut p, &mut old, batch("one")).unwrap();
    publish_base(&mut p, &mut old).unwrap();
    let m = p.published_manifest().unwrap();
    let mut s = node(dir.path(), "s", Role::Secondary);
    let progress = s.materialized_begin(m.clone()).unwrap();
    let mut page = p.published_page(&m, 0).unwrap();
    if let materialized::Row::Place(place) = &mut page.rows[0] {
        place.name = "corrupt".into();
    }
    s.materialized_chunk(progress.token, page).unwrap();
    assert!(s.materialized_finish(progress.token).is_err());
    assert_eq!(s.view().unwrap(), View::default());
    assert!(s.receipt("one").unwrap().is_none());
    assert!(s.verified_view().unwrap().is_none());
    s.materialized_cancel(progress.token).unwrap();
    install(&p, &mut s, &m);
    recover(&mut p, &mut s).unwrap();
}
