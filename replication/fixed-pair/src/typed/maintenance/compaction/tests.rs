use super::*;
use crate::envelope_tests::{stock_entry, StockSchema};

#[test]
fn repeated_compaction_preserves_receipts_and_resumes_partial_installation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let id = batch.identity.clone();
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        id.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        id.clone(),
        "fixture",
        StockSchema,
    )?;
    let result = commit(&mut p, &mut s, batch.clone())?;
    p.enable_maintenance()?;
    s.enable_maintenance()?;
    let pm = p.publish_snapshot()?;
    let sm = s.publish_snapshot()?;
    let plan = plan_pair(&p, &s)?;
    p.pin_snapshot(&pm, "transfer")?;
    assert!(compact_pair(&mut p, &mut s, &plan).is_err());
    assert!(p.compaction_progress()?.is_none());
    p.release_snapshot_pin(&pm, "transfer")?;
    p.connection(|c| {c.execute_batch("CREATE TRIGGER fail_base BEFORE INSERT ON replication_base BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())})?;
    assert!(compact_pair(&mut p, &mut s, &plan).is_err());
    assert_eq!(p.compaction_progress()?.unwrap().phase, Phase::Decided);
    assert_eq!(s.compaction_progress()?.unwrap().phase, Phase::Applied);
    assert!(p.summary().is_err());
    assert!(s.summary().is_err());
    p.connection(|c| {
        c.execute_batch("DROP TRIGGER fail_base")?;
        Ok(())
    })?;
    drop(p);
    drop(s);
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        id.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        id,
        "fixture",
        StockSchema,
    )?;
    compact_pair(&mut p, &mut s, &plan)?;
    compact_pair(&mut p, &mut s, &plan)?;
    assert_eq!(p.plan_compaction()?.covered_journal_entries, 0);
    assert_eq!(commit(&mut p, &mut s, batch.clone())?, result);
    let mut next = batch.clone();
    next.operation_id = "next".into();
    commit(&mut p, &mut s, next)?;
    p.rotate_snapshot(&pm)?;
    s.rotate_snapshot(&sm)?;
    let next_plan = plan_pair(&p, &s)?;
    compact_pair(&mut p, &mut s, &next_plan)?;
    assert!(compact_pair(&mut p, &mut s, &plan).is_err());
    assert_eq!(p.plan_compaction()?.covered_journal_entries, 0);
    assert_eq!(p.checkpoint()?, s.checkpoint()?);
    assert_eq!(commit(&mut p, &mut s, batch)?, result);
    let manifest = p.published_snapshot()?.ok_or("missing publication")?;
    let mut target = Node::open(
        dir.path().join("target"),
        Role::Secondary,
        p.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    target.begin_snapshot(&manifest)?;
    for n in 0..manifest.pages {
        target.receive_snapshot(&p.snapshot_page(&manifest, n)?)?;
    }
    target.finish_snapshot(&manifest)?;
    assert_eq!(target.checkpoint()?, p.checkpoint()?);
    assert_eq!(target.receipt("next")?, p.receipt("next")?);
    p.connection(|c| {
        for sql in [
            "DELETE FROM node_compaction_history WHERE sequence=1",
            "DELETE FROM node_compaction_history",
        ] {
            let tx = c.unchecked_transaction()?;
            tx.execute(sql, [])?;
            assert!(p.verify_owner(&tx).is_err());
            tx.rollback()?;
        }
        let tx = c.unchecked_transaction()?;
        tx.execute(
            "UPDATE node_compaction_history SET digest='bad' WHERE sequence=1",
            [],
        )?;
        assert!(p.verify_owner(&tx).is_err());
        tx.rollback()?;
        Ok(())
    })?;
    Ok(())
}

#[test]
fn recovered_plan_is_rejected_without_mutation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    commit(&mut p, &mut s, batch)?;
    p.publish_snapshot()?;
    s.publish_snapshot()?;
    let mut plan = plan_pair(&p, &s)?;
    plan.primary.membership = Some([1; 32]);
    plan.secondary.membership = Some([1; 32]);
    plan.primary.recovery_anchor = Some(plan.primary.checkpoint.clone());
    plan.secondary.recovery_anchor = Some(plan.secondary.checkpoint.clone());
    assert!(plan.validate_structural().is_ok());
    assert!(plan.validate().is_err());
    assert!(compact_pair(&mut p, &mut s, &plan).is_err());
    assert!(p.compaction_progress()?.is_none());
    assert!(s.compaction_progress()?.is_none());
    Ok(())
}

#[test]
fn recovered_structural_validation_rejects_mismatched_pair_bindings() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    commit(&mut p, &mut s, batch)?;
    p.publish_snapshot()?;
    s.publish_snapshot()?;
    let base = plan_pair(&p, &s)?;
    let mut recovered = base.clone();
    recovered.primary.membership = Some([1; 32]);
    recovered.secondary.membership = Some([1; 32]);
    recovered.primary.recovery_anchor = Some(recovered.primary.checkpoint.clone());
    recovered.secondary.recovery_anchor = Some(recovered.secondary.checkpoint.clone());
    assert!(recovered.validate_structural().is_ok());
    for bad in 0..5 {
        let mut plan = recovered.clone();
        match bad {
            0 => plan.secondary.membership = Some([2; 32]),
            1 => {
                plan.secondary.recovery_anchor = Some(Prefix {
                    sequence: 0,
                    ..plan.secondary.checkpoint.clone()
                })
            }
            2 => plan.secondary.role = Role::Primary,
            3 => plan.secondary.checkpoint.sequence += 1,
            _ => plan.primary.recovery_anchor = None,
        }
        assert!(plan.validate_structural().is_err());
    }
    Ok(())
}

#[test]
fn corrupt_publication_prevents_pruning() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    commit(&mut p, &mut s, batch)?;
    p.enable_maintenance()?;
    s.enable_maintenance()?;
    p.publish_snapshot()?;
    s.publish_snapshot()?;
    let plan = plan_pair(&p, &s)?;
    p.connection(|c| {
        c.execute(
            "UPDATE node_publication_pages SET page='{}' WHERE position=0",
            [],
        )?;
        Ok(())
    })?;
    assert!(compact_pair(&mut p, &mut s, &plan).is_err());
    assert!(p.compaction_progress()?.is_none());
    assert_eq!(p.plan_compaction()?.covered_journal_entries, 1);
    Ok(())
}

#[test]
#[ignore = "subprocess fixture for compaction_crash_boundaries"]
fn compaction_crash_child() -> Result<()> {
    let path = std::path::PathBuf::from(std::env::var("VESTA_COMPACTION_PATH")?);
    let plan: PairPlan = serde_json::from_str(&std::env::var("VESTA_COMPACTION_PLAN")?)?;
    let stop: usize = std::env::var("VESTA_COMPACTION_STAGE")?.parse()?;
    let id = plan.primary.checkpoint.identity.clone();
    let mut p = Node::open(
        path.join("p"),
        Role::Primary,
        id.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(path.join("s"), Role::Secondary, id, "fixture", StockSchema)?;
    for step in 1..=8 {
        match step {
            1 => p.prepare_compaction(&plan)?,
            2 => s.prepare_compaction(&plan)?,
            3 => p.compaction_step(&plan, Phase::Decided)?,
            4 => s.compaction_step(&plan, Phase::Decided)?,
            5 => s.compaction_step(&plan, Phase::Applied)?,
            6 => p.compaction_step(&plan, Phase::Applied)?,
            7 => s.compaction_step(&plan, Phase::Complete)?,
            _ => p.compaction_step(&plan, Phase::Complete)?,
        }
        if step == stop {
            std::process::exit(73);
        }
    }
    Err("invalid crash stage".into())
}

#[test]
fn compaction_crash_boundaries() -> Result<()> {
    for stage in 1..=8 {
        let dir = tempfile::tempdir()?;
        let batch = stock_entry().batch;
        let id = batch.identity.clone();
        let mut p = Node::open(
            dir.path().join("p"),
            Role::Primary,
            id.clone(),
            "fixture",
            StockSchema,
        )?;
        let mut s = Node::open(
            dir.path().join("s"),
            Role::Secondary,
            id.clone(),
            "fixture",
            StockSchema,
        )?;
        let result = commit(&mut p, &mut s, batch.clone())?;
        p.enable_maintenance()?;
        s.enable_maintenance()?;
        p.publish_snapshot()?;
        s.publish_snapshot()?;
        let plan = plan_pair(&p, &s)?;
        drop(p);
        drop(s);
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "typed::maintenance::compaction::tests::compaction_crash_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env("VESTA_COMPACTION_PATH", dir.path())
            .env("VESTA_COMPACTION_PLAN", serde_json::to_string(&plan)?)
            .env("VESTA_COMPACTION_STAGE", stage.to_string())
            .status()?;
        assert_eq!(status.code(), Some(73), "stage={stage}");
        let mut p = Node::open(
            dir.path().join("p"),
            Role::Primary,
            id.clone(),
            "fixture",
            StockSchema,
        )?;
        let mut s = Node::open(
            dir.path().join("s"),
            Role::Secondary,
            id,
            "fixture",
            StockSchema,
        )?;
        if stage < 8 {
            assert!(p.summary().is_err());
        }
        compact_pair(&mut p, &mut s, &plan)?;
        assert_eq!(commit(&mut p, &mut s, batch)?, result);
        assert_eq!(p.checkpoint()?, s.checkpoint()?);
    }
    Ok(())
}
