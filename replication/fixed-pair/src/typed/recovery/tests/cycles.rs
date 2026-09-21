use super::*;
use crate::envelope_tests::StockChange;

struct CompletedPair {
    p: Node<StockSchema>,
    s: Node<StockSchema>,
    journal: Journal,
    authority: Authority,
    request: DecisionRequest,
    decision: CommittedDecision,
}

fn completed_pair(dir: &Path) -> Result<CompletedPair> {
    let batch = stock_entry().batch;
    let id = batch.identity.clone();
    let mut old = Node::open(
        dir.join("original"),
        Role::Primary,
        id.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        dir.join("survivor"),
        Role::Secondary,
        id.clone(),
        "fixture",
        StockSchema,
    )?;
    commit(&mut old, &mut s, batch)?;
    let plan = Plan {
        recovery_id: [5; 32],
        revision: 5,
        candidate: [3; 32],
        baseline: Baseline {
            scope: serde_json::to_string(&id)?,
            revision: 4,
            digest: [4; 32],
            old_primary: [1; 32],
            survivor: [2; 32],
            survivor_generation: s.journal_head()?.read_generation,
            checkpoint: s.recovery_checkpoint_digest()?,
        },
    };
    s.seal_recovery_source(&plan)?;
    let manifest = s.publish_recovery_snapshot()?;
    let mut p = Node::open(
        dir.join("candidate1"),
        Role::Secondary,
        id,
        "fixture",
        StockSchema,
    )?;
    p.begin_snapshot(&manifest)?;
    for n in 0..manifest.pages {
        p.receive_snapshot(&s.snapshot_page(&manifest, n)?)?;
    }
    p.finish_snapshot(&manifest)?;
    let request = DecisionRequest {
        id: [10; 32],
        prepared: [
            p.inspect_recovery(&plan, plan.candidate)?,
            s.inspect_recovery(&plan, plan.baseline.survivor)?,
        ],
        plan,
    };
    let authority = Authority::new(request.clone());
    let journal = Journal::create(&dir.join("authority1"), "fixture", authority.scope.clone())?;
    journal.decide(request.clone(), &authority.token(), &authority)?;
    let decision = journal.fetch(&request, &authority)?;
    p.record_recovery_decision(&decision, request.plan.candidate)?;
    s.record_recovery_decision(&decision, request.plan.baseline.survivor)?;
    activate_pair(&mut p, &mut s, &journal, &request, &authority)?;
    complete_pair(&mut p, &mut s, &journal, &request, [12; 32], &authority)?;
    recover(&mut p, &mut s)?;
    Ok(CompletedPair {
        p,
        s,
        journal,
        authority,
        request,
        decision,
    })
}

pub(crate) fn recovered_pair_for_pending(
    dir: &Path,
) -> Result<(Node<StockSchema>, Node<StockSchema>)> {
    let pair = completed_pair(dir)?;
    let (manifest, pages) = pair.s.connection(|c| {
        let manifest: String = c.query_row(
            "SELECT manifest FROM node_publication WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        let pages: Vec<(u64, String)> = c
            .prepare("SELECT position,page FROM node_publication_pages ORDER BY position")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok((manifest, pages))
    })?;
    pair.p.connection(|c|{
        c.execute("INSERT INTO node_publication VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET manifest=excluded.manifest",[manifest])?;
        c.execute("DELETE FROM node_publication_pages",[])?;
        for (position,page) in pages { c.execute("INSERT INTO node_publication_pages VALUES(?1,?2)",params![position,page])?; }
        Ok(())
    })?;
    Ok((pair.p, pair.s))
}

fn next_plan(s: &Node<StockSchema>, previous: &Plan) -> Result<Plan> {
    Ok(Plan {
        recovery_id: [6; 32],
        revision: previous.revision + 1,
        candidate: [7; 32],
        baseline: Baseline {
            scope: previous.baseline.scope.clone(),
            revision: previous.revision,
            digest: s.summary()?.membership.ok_or("membership missing")?,
            old_primary: previous.candidate,
            survivor: previous.baseline.survivor,
            survivor_generation: s.journal_head()?.read_generation,
            checkpoint: s.recovery_checkpoint_digest()?,
        },
    })
}

#[test]
fn completed_survivor_can_seal_the_next_generation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let CompletedPair {
        mut p,
        mut s,
        request,
        ..
    } = completed_pair(dir.path())?;
    p.enable_maintenance()?;
    s.enable_maintenance()?;
    let mut batch = stock_entry().batch;
    batch.operation_id = "between-cycles".into();
    commit(&mut p, &mut s, batch.clone())?;
    let plan = next_plan(&s, &request.plan)?;
    s.seal_recovery_source(&plan)?;
    s.connection(|c| {
        assert_eq!(
            c.query_row("SELECT format FROM node_runtime WHERE id=1", [], |r| r
                .get::<_, u32>(0))?,
            4
        );
        s.verify_owner(c)?;
        Ok(())
    })?;
    assert!(s.summary().is_err());
    assert!(commit(&mut p, &mut s, batch).is_err());
    s.seal_recovery_source(&plan)?;
    Ok(())
}

#[test]
#[ignore = "subprocess fixture invoked by repeated_cycle_crash_rotation_and_stale_authority"]
fn cycle_crash_child() -> Result<()> {
    let dir = std::env::var("VESTA_CYCLE_DIR")?;
    let plan: Plan = serde_json::from_str(&std::env::var("VESTA_CYCLE_PLAN")?)?;
    let mut s = Node::open(
        Path::new(&dir).join("survivor"),
        Role::Secondary,
        stock_entry().batch.identity,
        "fixture",
        StockSchema,
    )?;
    s.seal_recovery_source(&plan)?;
    std::process::exit(73)
}

#[test]
fn repeated_cycle_crash_rotation_and_stale_authority() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let CompletedPair {
        mut p,
        mut s,
        journal,
        authority,
        request: first,
        decision: old_decision,
    } = completed_pair(dir.path())?;
    let id = s.identity().clone();
    let mut batch = stock_entry().batch;
    batch.operation_id = "between-cycles".into();
    batch.changes = vec![StockChange::Set {
        sku: "second-cycle".into(),
        quantity: 2,
    }];
    commit(&mut p, &mut s, batch.clone())?;
    let plan = next_plan(&s, &first.plan)?;
    let old_publication = s
        .published_snapshot()?
        .ok_or("missing original publication")?;
    for field in 0..9 {
        let mut bad = plan.clone();
        match field {
            0 => bad.baseline.digest = [42; 32],
            1 => bad.baseline.revision += 1,
            2 => bad.baseline.old_primary = [42; 32],
            3 => bad.baseline.survivor = [42; 32],
            4 => bad.baseline.survivor_generation = [42; 32],
            5 => bad.baseline.checkpoint = [42; 32],
            6 => bad.baseline.scope.push('x'),
            7 => bad.candidate = first.plan.baseline.old_primary,
            _ => bad.recovery_id = first.plan.recovery_id,
        }
        assert!(s.seal_recovery_source(&bad).is_err(), "field {field}");
        assert_eq!(s.checkpoint()?, p.checkpoint()?);
    }
    s.connection(|c| { c.execute_batch("CREATE TRIGGER fail_cycle AFTER UPDATE ON recovery_seal BEGIN SELECT RAISE(ABORT,'fixture cycle fault'); END;")?; Ok(()) })?;
    assert!(s.seal_recovery_source(&plan).is_err());
    assert_eq!(s.required_recovery_peer()?, Some(first.plan.candidate));
    s.connection(|c| {
        assert!(!table(c, "recovery_cycles")?);
        c.execute_batch("DROP TRIGGER fail_cycle")?;
        Ok(())
    })?;
    drop(s);
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "typed::recovery::tests::cycles::cycle_crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("VESTA_CYCLE_DIR", dir.path())
        .env("VESTA_CYCLE_PLAN", serde_json::to_string(&plan)?)
        .status()?;
    ensure(
        status.code() == Some(73),
        "cycle subprocess did not reach committed seal",
    )?;
    let spath = dir.path().join("survivor");
    let mut s = Node::open(&spath, Role::Secondary, id.clone(), "fixture", StockSchema)?;
    s.seal_recovery_source(&plan)?;
    assert!(s.summary().is_err());
    assert!(s
        .record_recovery_decision(&old_decision, first.plan.baseline.survivor)
        .is_err());
    assert!(complete_pair(&mut p, &mut s, &journal, &first, [12; 32], &authority).is_err());
    assert!(s.publish_recovery_snapshot().is_err()); // Old frozen checkpoint, never substituted.
    assert_eq!(s.published_snapshot()?, Some(old_publication.clone()));
    let manifest = s.rotate_snapshot(&old_publication)?;
    assert_ne!(manifest, old_publication);
    assert!(s.snapshot_page(&old_publication, 0).is_err());
    assert!(s.rotate_snapshot(&old_publication).is_err());
    drop(s);
    let mut s = Node::open(&spath, Role::Secondary, id.clone(), "fixture", StockSchema)?;
    assert_eq!(s.publish_recovery_snapshot()?, manifest);
    let cpath = dir.path().join("candidate2");
    let mut c = Node::open(&cpath, Role::Secondary, id.clone(), "fixture", StockSchema)?;
    c.begin_snapshot(&manifest)?;
    for n in 0..manifest.pages {
        c.receive_snapshot(&s.snapshot_page(&manifest, n)?)?;
    }
    c.finish_snapshot(&manifest)?;
    let request = DecisionRequest {
        id: [11; 32],
        prepared: [
            c.inspect_recovery(&plan, plan.candidate)?,
            s.inspect_recovery(&plan, plan.baseline.survivor)?,
        ],
        plan,
    };
    let authority2 = Authority::new(request.clone());
    let journal2 = Journal::create(
        &dir.path().join("authority2"),
        "fixture",
        authority2.scope.clone(),
    )?;
    journal2.decide(request.clone(), &authority2.token(), &authority2)?;
    let decision = journal2.fetch(&request, &authority2)?;
    c.record_recovery_decision(&decision, request.plan.candidate)?;
    s.record_recovery_decision(&decision, request.plan.baseline.survivor)?;
    activate_pair(&mut c, &mut s, &journal2, &request, &authority2)?;
    assert!(commit(&mut c, &mut s, batch.clone()).is_err());
    complete_pair(&mut c, &mut s, &journal2, &request, [13; 32], &authority2)?;
    assert!(recover(&mut p, &mut s).is_err());
    let mut original = Node::open(
        dir.path().join("original"),
        Role::Primary,
        id.clone(),
        "fixture",
        StockSchema,
    )?;
    assert!(recover(&mut original, &mut s).is_err());
    assert_eq!(commit(&mut c, &mut s, stock_entry().batch)?.sequence, 1);
    assert_eq!(commit(&mut c, &mut s, batch.clone())?.sequence, 2);
    batch.operation_id = "after-two-replacements".into();
    batch.changes = vec![StockChange::Set {
        sku: "third-write".into(),
        quantity: 3,
    }];
    assert_eq!(commit(&mut c, &mut s, batch)?.sequence, 3);
    drop(c);
    drop(s);
    let c = Node::open(&cpath, Role::Primary, id.clone(), "fixture", StockSchema)?;
    let mut s = Node::open(&spath, Role::Secondary, id, "fixture", StockSchema)?;
    assert_eq!(c.checkpoint()?, s.checkpoint()?);
    let mut third = next_plan(&s, &request.plan)?;
    third.recovery_id = [20; 32];
    third.candidate = [21; 32];
    for retired in [first.plan.baseline.old_primary, first.plan.candidate] {
        let mut bad = third.clone();
        bad.candidate = retired;
        assert!(s.seal_recovery_source(&bad).is_err());
    }
    let mut reused = third.clone();
    reused.recovery_id = first.plan.recovery_id;
    assert!(s.seal_recovery_source(&reused).is_err());
    s.seal_recovery_source(&third)?;
    // Prefix removal, tail removal, content corruption and format downgrade fail closed.
    for sql in [
        "DELETE FROM recovery_cycles WHERE revision=5",
        "DELETE FROM recovery_cycles WHERE revision=6",
        "UPDATE recovery_cycles SET digest='bad'",
        "UPDATE node_runtime SET format=1",
        "DROP TABLE recovery_cycles",
    ] {
        s.connection(|db| {
            let tx = db.unchecked_transaction()?;
            tx.execute_batch(sql)?;
            assert!(s.verify_owner(&tx).is_err(), "{sql}");
            tx.rollback()?;
            Ok(())
        })?;
    }
    Ok(())
}
