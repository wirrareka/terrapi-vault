use terrapi_vesta_replication::{publication::*, *};
fn identity() -> Identity {
    Identity {
        cluster: "eu-pair".into(),
        tenant: "tenant-a".into(),
        epoch: 1,
        schema: 1,
    }
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
fn node(dir: &std::path::Path, name: &str, role: Role) -> Node {
    Node::open(dir.join(name), role, identity(), "fixture").unwrap()
}

#[test]
fn publication_keeps_both_journals_and_immutable_base_after_new_writes() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    commit(&mut p, &mut s, batch("one")).unwrap();
    let record = publish_base(&mut p, &mut s).unwrap();
    assert_eq!(record.phase, Phase::Confirmed);
    assert_eq!(s.base_status().unwrap(), Some(record.clone()));
    assert_eq!(p.status().unwrap().entries.len(), 1);
    assert!(p.journal_head().unwrap().base.is_none());
    commit(&mut p, &mut s, batch("two")).unwrap();
    assert_eq!(p.published_view().unwrap().unwrap().places[0].name, "one");
    assert_eq!(s.published_view().unwrap(), p.published_view().unwrap());
    drop(p);
    drop(s);
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    assert_eq!(publish_base(&mut p, &mut s).unwrap(), record);
    assert_eq!(p.view().unwrap().places[0].name, "two");
    assert_eq!(p.status().unwrap().entries.len(), 2);
}

#[test]
fn interrupted_publication_blocks_new_writes_and_resumes_original_proposal() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    commit(&mut p, &mut s, batch("one")).unwrap();
    let proposal = Proposal {
        checkpoint: p.checkpoint().unwrap(),
        token: [7; 32],
        primary_generation: p.journal_head().unwrap().read_generation,
        secondary_generation: s.journal_head().unwrap().read_generation,
    };
    p.capture_base(proposal.clone()).unwrap();
    assert!(p.prepare(batch("blocked")).is_err());
    s.capture_base(proposal.clone()).unwrap();
    s.confirm_base(proposal.clone()).unwrap(); // Secondary ACK is lost.
    assert_eq!(p.base_status().unwrap().unwrap().phase, Phase::Captured);
    drop(p);
    drop(s);
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    let record = publish_base(&mut p, &mut s).unwrap();
    assert_eq!(record.proposal, proposal);
    commit(&mut p, &mut s, batch("after")).unwrap();
}

#[test]
fn publication_rejects_changed_generation_and_never_replaces_existing_base() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    let record = publish_base(&mut p, &mut s).unwrap();
    let mut different = record.proposal.clone();
    different.token = [9; 32];
    assert!(p.capture_base(different).is_err());
    assert!(s.install(p.snapshot().unwrap()).is_err());
    assert!(s.snapshot_begin(p.snapshot_manifest().unwrap()).is_err());
    assert!(s
        .materialized_begin(p.materialized_manifest().unwrap())
        .is_err());
    s.quarantine().unwrap();
    assert!(publish_base(&mut p, &mut s).is_err());
    assert_eq!(p.base_status().unwrap(), Some(record));
}

fn proposal(p: &Node, s: &Node) -> Proposal {
    Proposal {
        checkpoint: p.checkpoint().unwrap(),
        token: [4; 32],
        primary_generation: p.journal_head().unwrap().read_generation,
        secondary_generation: s.journal_head().unwrap().read_generation,
    }
}

#[test]
fn captured_empty_base_blocks_all_bootstrap_paths_and_keeps_reads() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    recover(&mut p, &mut s).unwrap();
    let proposal = proposal(&p, &s);
    s.capture_base(proposal.clone()).unwrap();
    assert!(s.install(p.snapshot().unwrap()).is_err());
    assert!(s.snapshot_begin(p.snapshot_manifest().unwrap()).is_err());
    assert!(s
        .materialized_begin(p.materialized_manifest().unwrap())
        .is_err());
    let entry = p.prepare(batch("blocked-on-secondary")).unwrap();
    assert!(s.stage(entry).is_err());
    p.abort("blocked-on-secondary").unwrap();
    p.capture_base(proposal).unwrap();
    assert_eq!(s.verified_view().unwrap(), Some(View::default()));
    let mut gate = coordinator::Coordinator::new(p, s).unwrap();
    assert!(gate.reconcile().is_err());
    assert_eq!(gate.write(batch("blocked")).unwrap_err().status_code, 503);
    assert!(!gate.capabilities().writable);
    assert!(gate.capabilities().readable);
    assert_eq!(gate.view().unwrap(), View::default());
}

#[test]
fn invalid_proposals_and_active_transfer_leave_no_partial_base() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut s = node(dir.path(), "s", Role::Secondary);
    let good = proposal(&p, &s);
    let mut wrong = good.clone();
    wrong.checkpoint.journal_digest = "0".repeat(64);
    assert!(p.capture_base(wrong).is_err());
    let mut wrong = good.clone();
    wrong.primary_generation = [0; 32];
    assert!(p.capture_base(wrong).is_err());
    assert!(p.confirm_base(good.clone()).is_err());
    p.prepare(batch("pending")).unwrap();
    assert!(p.capture_base(good).is_err());
    assert!(p.base_status().unwrap().is_none());
    p.abort("pending").unwrap();
    let transfer = s
        .materialized_begin(p.materialized_manifest().unwrap())
        .unwrap();
    assert!(s.capture_base(proposal(&p, &s)).is_err());
    assert!(s.base_status().unwrap().is_none());
    s.materialized_cancel(transfer.token).unwrap();
    publish_base(&mut p, &mut s).unwrap();
}

#[test]
fn publication_on_materialized_secondary_preserves_absolute_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = node(dir.path(), "p", Role::Primary);
    let mut old = node(dir.path(), "old", Role::Secondary);
    commit(&mut p, &mut old, batch("one")).unwrap();
    let mut s = node(dir.path(), "s", Role::Secondary);
    let manifest = p.materialized_manifest().unwrap();
    let progress = s.materialized_begin(manifest.clone()).unwrap();
    s.materialized_chunk(progress.token, p.materialized_page(&manifest, 0).unwrap())
        .unwrap();
    s.materialized_finish(progress.token).unwrap();
    let record = publish_base(&mut p, &mut s).unwrap();
    assert_eq!(record.proposal.checkpoint.sequence, 1);
    assert!(s.status().unwrap().entries.is_empty());
    commit(&mut p, &mut s, batch("two")).unwrap();
    assert_eq!(s.status().unwrap().entries.len(), 1);
    assert_eq!(s.published_view().unwrap(), p.published_view().unwrap());
}

#[test]
fn publication_process_crashes_are_atomic_on_both_roles_and_resume() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    for role in [Role::Primary, Role::Secondary] {
        for (point, code, capturing, committed) in [
            ("capture_before_commit", 91, true, false),
            ("capture_after_commit", 92, true, true),
            ("confirm_before_commit", 93, false, false),
            ("confirm_after_commit", 94, false, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut p = node(dir.path(), "p", Role::Primary);
            let mut s = node(dir.path(), "s", Role::Secondary);
            commit(&mut p, &mut s, batch("one")).unwrap();
            let proposal = proposal(&p, &s);
            if !capturing {
                p.capture_base(proposal.clone()).unwrap();
                s.capture_base(proposal.clone()).unwrap();
                if role == Role::Primary {
                    s.confirm_base(proposal.clone()).unwrap();
                }
            } else if role == Role::Secondary {
                p.capture_base(proposal.clone()).unwrap();
            }
            let before = p.checkpoint().unwrap();
            drop(p);
            drop(s);
            let (name, arg) = if role == Role::Primary {
                ("p", "primary")
            } else {
                ("s", "secondary")
            };
            let mut child = Command::new(env!("CARGO_BIN_EXE_vesta-node"))
                .arg(dir.path().join(name))
                .arg(arg)
                .env("VESTA_PROTOTYPE_PASSPHRASE", "fixture")
                .env("VESTA_PROTOTYPE_CRASH_PUBLICATION", point)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let command = if capturing {
                "capture_base"
            } else {
                "confirm_base"
            };
            writeln!(
                child.stdin.take().unwrap(),
                "{}",
                serde_json::json!({"command":command,"proposal":proposal})
            )
            .unwrap();
            let output = child.wait_with_output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(code),
                "{point}: {:?}",
                output.stdout
            );
            let mut p = node(dir.path(), "p", Role::Primary);
            let mut s = node(dir.path(), "s", Role::Secondary);
            let target = if role == Role::Primary { &p } else { &s };
            let phase = target.base_status().unwrap().map(|r| r.phase);
            assert_eq!(
                phase,
                if capturing && !committed {
                    None
                } else if !capturing && committed {
                    Some(Phase::Confirmed)
                } else {
                    Some(Phase::Captured)
                }
            );
            assert_eq!(p.checkpoint().unwrap(), before);
            assert_eq!(s.checkpoint().unwrap(), before);
            assert_eq!(p.status().unwrap().entries.len(), 1);
            assert_eq!(s.status().unwrap().entries.len(), 1);
            let record = publish_base(&mut p, &mut s).unwrap();
            if !(role == Role::Primary && capturing && !committed) {
                assert_eq!(record.proposal, proposal);
            }
            assert_eq!(record.phase, Phase::Confirmed);
            commit(&mut p, &mut s, batch("after")).unwrap();
        }
    }
}
