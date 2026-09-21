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
fn node(dir: &std::path::Path, name: &str, role: Role) -> Node {
    Node::open(dir.join(name), role, identity(), "fixture").unwrap()
}
fn install(p: &Node, s: &mut Node) {
    let m = p.materialized_manifest().unwrap();
    let mut t = s.materialized_begin(m.clone()).unwrap();
    while t.received < m.rows().unwrap() {
        t = s
            .materialized_chunk(t.token, p.materialized_page(&m, t.received).unwrap())
            .unwrap();
    }
    s.materialized_finish(t.token).unwrap();
}

#[test]
fn materialized_base_has_no_old_journal_and_recovers_tail_with_same_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut old = node(dir.path(), "old", Role::Secondary);
    let first = commit(&mut p, &mut old, batch("one", "old")).unwrap();
    commit(&mut p, &mut old, batch("two", "new")).unwrap();
    let mut s = node(dir.path(), "s", Role::Secondary);
    install(&p, &mut s);
    assert!(s.status().unwrap().entries.is_empty());
    assert_eq!(s.journal_head().unwrap().length, 2);
    assert_eq!(s.checkpoint().unwrap(), p.checkpoint().unwrap());
    assert_eq!(s.receipt("one").unwrap(), p.receipt("one").unwrap());
    assert!(s.verified_view().unwrap().is_none());
    // Source moves on while replacement has only its base.
    commit(&mut p, &mut old, batch("three", "latest")).unwrap();
    recover(&mut p, &mut s).unwrap();
    assert_eq!(s.status().unwrap().entries[0].sequence, 3);
    assert_eq!(s.checkpoint().unwrap(), p.checkpoint().unwrap());
    assert_eq!(commit(&mut p, &mut s, batch("one", "old")).unwrap(), first);
    assert_eq!(s.view().unwrap().places[0].name, "latest");
    drop(s);
    let mut s = node(dir.path(), "s", Role::Secondary);
    assert!(s.verified_view().unwrap().is_some());
    commit(&mut p, &mut s, batch("four", "after restart")).unwrap();
    assert_eq!(s.checkpoint().unwrap(), p.checkpoint().unwrap());
    assert_eq!(p.status().unwrap().entries.len(), 4);
    assert_eq!(s.status().unwrap().entries.len(), 2);
}

#[test]
fn materialized_transfer_resumes_and_rejects_partial_or_changed_source() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut old = node(dir.path(), "old", Role::Secondary);
    for i in 0..35 {
        commit(&mut p, &mut old, batch(&format!("op-{i}"), "name")).unwrap();
    }
    let mut s = node(dir.path(), "s", Role::Secondary);
    let m = p.materialized_manifest().unwrap();
    let t = s.materialized_begin(m.clone()).unwrap();
    let page = p.materialized_page(&m, 0).unwrap();
    let progress = s.materialized_chunk(t.token, page.clone()).unwrap();
    assert_eq!(s.materialized_chunk(t.token, page).unwrap(), progress);
    assert!(s.materialized_finish(t.token).is_err());
    assert!(s.confirm_checkpoint(p.checkpoint().unwrap()).is_err());
    assert!(s.snapshot_begin(p.snapshot_manifest().unwrap()).is_err());
    assert_eq!(s.view().unwrap(), View::default());
    drop(s);
    let mut s = node(dir.path(), "s", Role::Secondary);
    assert_eq!(s.materialized_progress().unwrap(), Some(progress));
    install(&p, &mut s);
    recover(&mut p, &mut s).unwrap();
    commit(&mut p, &mut s, batch("later", "changed")).unwrap();
    assert!(p.materialized_page(&m, 0).is_err());
    assert!(s.materialized_finish(t.token).is_err());
}

#[test]
fn materialized_bad_content_cancel_tokens_and_schema_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut old = node(dir.path(), "old", Role::Secondary);
    commit(&mut p, &mut old, batch("one", "name")).unwrap();
    let mut s = node(dir.path(), "s", Role::Secondary);
    let m = p.materialized_manifest().unwrap();
    for field in ["identity", "format", "count"] {
        let mut bad = m.clone();
        match field {
            "identity" => bad.checkpoint.identity.tenant = "wrong".into(),
            "format" => bad.checkpoint.format = 0,
            _ => bad.places = u64::MAX,
        }
        assert!(s.materialized_begin(bad).is_err());
    }
    for receipt_corruption in [false, true] {
        let t = s.materialized_begin(m.clone()).unwrap();
        let mut page = p.materialized_page(&m, 0).unwrap();
        if receipt_corruption {
            if let materialized::Row::Receipt(r) = &mut page.rows[1] {
                r.request_digest = "0".repeat(64);
            }
        } else if let materialized::Row::Place(v) = &mut page.rows[0] {
            v.name = "wrong".into();
        }
        s.materialized_chunk(t.token, page).unwrap();
        assert!(s.materialized_finish(t.token).is_err());
        assert_eq!(s.view().unwrap(), View::default());
        assert!(s.journal_head().unwrap().base.is_none());
        assert!(s.receipt("one").unwrap().is_none());
        s.quarantine().unwrap();
        assert!(s.materialized_finish(t.token).is_err());
        s.materialized_cancel(t.token).unwrap();
        let next = s.materialized_begin(m.clone()).unwrap();
        assert_ne!(next.token, t.token);
        assert!(s.materialized_cancel(t.token).is_err());
        s.materialized_cancel(next.token).unwrap();
    }
    install(&p, &mut s);
    assert!(s.materialized_begin(m).is_ok());
    recover(&mut p, &mut s).unwrap();
    assert_eq!(s.checkpoint().unwrap(), p.checkpoint().unwrap());
}

#[test]
fn materialized_geo_foreign_keys_delete_tail_and_divergent_primary() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut old = node(dir.path(), "old", Role::Secondary);
    let mut b = batch("one", "name");
    b.changes.push(Change::PutFeature {
        id: "f".into(),
        place_id: "place".into(),
        geojson: r#"{"type":"Point","coordinates":[17,48]}"#.into(),
    });
    commit(&mut p, &mut old, b).unwrap();
    let mut s = node(dir.path(), "s", Role::Secondary);
    install(&p, &mut s);
    assert_eq!(s.view().unwrap(), p.view().unwrap());
    let mut wrong = node(dir.path(), "wrong", Role::Primary);
    wrong.prepare(batch("other", "same-looking place")).unwrap();
    let e = wrong.decide("other").unwrap();
    wrong.apply(e).unwrap();
    assert!(recover(&mut wrong, &mut s).is_err());
    assert!(s.verified_view().unwrap().is_none());
    let mut delete = batch("delete", "");
    delete.changes = vec![Change::DeletePlace { id: "place".into() }];
    commit(&mut p, &mut s, delete).unwrap();
    assert_eq!(s.view().unwrap(), View::default());
    assert_eq!(s.checkpoint().unwrap(), p.checkpoint().unwrap());
}

#[test]
fn empty_materialized_base_requires_confirmation_and_blocks_old_snapshot_install() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    install(&p, &mut s);
    assert!(s.verified_view().unwrap().is_none());
    assert!(s.install(p.snapshot().unwrap()).is_err());
    recover(&mut p, &mut s).unwrap();
    commit(&mut p, &mut s, batch("one", "after empty")).unwrap();
    assert_eq!(s.checkpoint().unwrap(), p.checkpoint().unwrap());
}
