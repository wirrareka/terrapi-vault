use terrapi_vesta_replication::{publication::*, *};
fn identity() -> Identity {
    Identity {
        cluster: "eu-pair".into(),
        tenant: "tenant-a".into(),
        epoch: 1,
        schema: 1,
    }
}
fn node(dir: &std::path::Path, name: &str, role: Role) -> Node {
    Node::open(dir.join(name), role, identity(), "fixture").unwrap()
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

#[test]
fn activation_preserves_records_and_recovers_with_either_side_activated_first() {
    for primary_first in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let mut p = node(dir.path(), "p", Role::Primary);
        let mut s = node(dir.path(), "s", Role::Secondary);
        let first = commit(&mut p, &mut s, batch("one")).unwrap();
        let r = publish_base(&mut p, &mut s).unwrap();
        let before = p.checkpoint().unwrap();
        let old_head = p.journal_head().unwrap();
        if primary_first {
            p.activate_published_base(r.proposal.clone()).unwrap();
        } else {
            s.activate_published_base(r.proposal.clone()).unwrap();
        }
        recover(&mut p, &mut s).unwrap();
        commit(&mut p, &mut s, batch("two")).unwrap();
        activate_base(&mut p, &mut s).unwrap();
        assert_eq!(p.journal_head().unwrap().base, Some(before.clone()));
        assert_eq!(s.journal_head().unwrap().base, Some(before));
        assert!(p.journal_page(&old_head, 0, 1).is_err());
        assert!(p.journal_page(&p.journal_head().unwrap(), 0, 1).is_err());
        assert_eq!(p.status().unwrap().entries.len(), 2);
        assert_eq!(s.status().unwrap().entries.len(), 2);
        assert!(s.verified_view().unwrap().is_some());
        assert!(p.snapshot().is_err());
        assert!(p.snapshot_manifest().is_err());
        drop(p);
        drop(s);
        let mut p = node(dir.path(), "p", Role::Primary);
        let mut s = node(dir.path(), "s", Role::Secondary);
        activate_base(&mut p, &mut s).unwrap();
        assert_eq!(commit(&mut p, &mut s, batch("one")).unwrap(), first);
        assert_eq!(commit(&mut p, &mut s, batch("three")).unwrap().sequence, 3);
        assert_eq!(p.checkpoint().unwrap(), s.checkpoint().unwrap());
    }
}

#[test]
fn lagging_peer_requires_explicit_snapshot_and_both_export_modes_work() {
    for frozen in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut p = node(dir.path(), "p", Role::Primary);
        let mut old = node(dir.path(), "old", Role::Secondary);
        commit(&mut p, &mut old, batch("one")).unwrap();
        publish_base(&mut p, &mut old).unwrap();
        activate_base(&mut p, &mut old).unwrap();
        commit(&mut p, &mut old, batch("two")).unwrap();
        let mut s = node(dir.path(), "s", Role::Secondary);
        assert!(recover(&mut p, &mut s).is_err());
        assert_eq!(s.view().unwrap(), View::default());
        let m = if frozen {
            p.published_manifest().unwrap()
        } else {
            p.materialized_manifest().unwrap()
        };
        let t = s.materialized_begin(m.clone()).unwrap();
        let page = if frozen {
            p.published_page(&m, 0).unwrap()
        } else {
            p.materialized_page(&m, 0).unwrap()
        };
        s.materialized_chunk(t.token, page).unwrap();
        s.materialized_finish(t.token).unwrap();
        recover(&mut p, &mut s).unwrap();
        assert_eq!(p.checkpoint().unwrap(), s.checkpoint().unwrap());
    }
}

#[test]
fn activation_rejects_pending_unconfirmed_conflicting_and_stale_proposals() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    assert!(activate_base(&mut p, &mut s).is_err());
    let proposal = Proposal {
        checkpoint: p.checkpoint().unwrap(),
        token: [1; 32],
        primary_generation: p.journal_head().unwrap().read_generation,
        secondary_generation: s.journal_head().unwrap().read_generation,
    };
    p.capture_base(proposal.clone()).unwrap();
    assert!(p.activate_published_base(proposal.clone()).is_err());
    publish_base(&mut p, &mut s).unwrap();
    let mut bad = proposal.clone();
    bad.token = [2; 32];
    assert!(p.activate_published_base(bad).is_err());
    p.prepare(batch("pending")).unwrap();
    assert!(p.activate_published_base(proposal.clone()).is_err());
    p.abort("pending").unwrap();
    s.quarantine().unwrap();
    assert!(s.activate_published_base(proposal.clone()).is_err());
    assert!(activate_base(&mut p, &mut s).is_err());
    assert!(p.journal_head().unwrap().base.is_none());
}

#[test]
fn empty_base_can_activate_on_primary_before_secondary() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    let r = publish_base(&mut p, &mut s).unwrap();
    p.activate_published_base(r.proposal).unwrap();
    recover(&mut p, &mut s).unwrap();
    assert_eq!(commit(&mut p, &mut s, batch("first")).unwrap().sequence, 1);
    activate_base(&mut p, &mut s).unwrap();
}

#[test]
fn divergent_lower_floor_is_rejected_before_tail_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut old = node(dir.path(), "old", Role::Secondary);
    commit(&mut p, &mut old, batch("one")).unwrap();
    publish_base(&mut p, &mut old).unwrap();
    activate_base(&mut p, &mut old).unwrap();
    commit(&mut p, &mut old, batch("two")).unwrap();
    let mut q = node(dir.path(), "q", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    commit(&mut q, &mut s, batch("different")).unwrap();
    let before = s.journal_head().unwrap();
    assert!(recover(&mut p, &mut s).is_err());
    assert_eq!(s.journal_head().unwrap(), before);
    assert_eq!(s.view().unwrap().places[0].name, "different");
}

#[test]
fn activation_crashes_before_and_after_commit_on_both_roles_resume_atomically() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    for primary in [false, true] {
        for (point, code, committed) in [
            ("activate_before_commit", 95, false),
            ("activate_after_commit", 96, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut p = node(dir.path(), "p", Role::Primary);
            let mut s = node(dir.path(), "s", Role::Secondary);
            commit(&mut p, &mut s, batch("one")).unwrap();
            let r = publish_base(&mut p, &mut s).unwrap();
            if primary {
                s.activate_published_base(r.proposal.clone()).unwrap();
            }
            let before = if primary {
                p.journal_head().unwrap()
            } else {
                s.journal_head().unwrap()
            };
            let cp = p.checkpoint().unwrap();
            drop(p);
            drop(s);
            let (name, role) = if primary {
                ("p", "primary")
            } else {
                ("s", "secondary")
            };
            let mut child = Command::new(env!("CARGO_BIN_EXE_vesta-node"))
                .arg(dir.path().join(name))
                .arg(role)
                .env("VESTA_PROTOTYPE_PASSPHRASE", "fixture")
                .env("VESTA_PROTOTYPE_CRASH_PUBLICATION", point)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            writeln!(
                child.stdin.take().unwrap(),
                "{}",
                serde_json::json!({"command":"activate_base","proposal":r.proposal})
            )
            .unwrap();
            assert_eq!(child.wait_with_output().unwrap().status.code(), Some(code));
            let mut p = node(dir.path(), "p", Role::Primary);
            let mut s = node(dir.path(), "s", Role::Secondary);
            let head = if primary {
                p.journal_head().unwrap()
            } else {
                s.journal_head().unwrap()
            };
            assert_eq!(head.base.is_some(), committed);
            assert_eq!(head.revision == before.revision, !committed);
            assert_eq!(head.read_generation, before.read_generation);
            assert_eq!(p.checkpoint().unwrap(), cp);
            assert_eq!(s.checkpoint().unwrap(), cp);
            assert_eq!(p.status().unwrap().entries.len(), 1);
            assert_eq!(s.status().unwrap().entries.len(), 1);
            activate_base(&mut p, &mut s).unwrap();
            assert_eq!(commit(&mut p, &mut s, batch("after")).unwrap().sequence, 2);
        }
    }
}
