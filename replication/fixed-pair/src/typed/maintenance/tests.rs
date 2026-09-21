use super::*;
use crate::envelope_tests::{stock_entry, StockSchema};

#[test]
fn planner_is_read_only_and_reports_pending_tail() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut batch = stock_entry().batch;
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
    assert_eq!(p.plan_compaction()?.covered_journal_entries, 0);
    commit(&mut p, &mut s, batch.clone())?;
    let head = p.summary()?.head;
    let plan = p.plan_compaction()?;
    assert_eq!(plan.head, head);
    assert_eq!(plan.covered_journal_entries, 1);
    assert!(plan.covered_journal_bytes > 0);
    assert_eq!(plan.retained_receipts, 1);
    assert!(!plan.unresolved_tail);
    assert!(plan.publication.is_none());
    assert_eq!(p.summary()?.head, head);
    batch.operation_id = "pending".into();
    p.prepare(batch)?;
    let pending = p.plan_compaction()?;
    assert!(pending.unresolved_tail);
    assert_eq!(pending.checkpoint, plan.checkpoint);
    assert_eq!(pending.covered_journal_bytes, plan.covered_journal_bytes);
    Ok(())
}

#[test]
fn pins_survive_restart_block_rotation_and_release_by_exact_manifest() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let path = dir.path().join("p");
    let mut p = Node::open(
        &path,
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
    commit(&mut p, &mut s, batch.clone())?;
    let manifest = p.publish_snapshot()?;
    assert!(p.pin_snapshot(&manifest, "transfer-1").is_err());
    p.enable_maintenance()?;
    p.enable_maintenance()?;
    p.pin_snapshot(&manifest, "transfer-1")?;
    p.pin_snapshot(&manifest, "transfer-1")?;
    assert!(p.rotate_snapshot(&manifest).is_err());
    drop(p);
    let mut p = Node::open(&path, Role::Primary, batch.identity, "fixture", StockSchema)?;
    assert!(p.rotate_snapshot(&manifest).is_err());
    let mut wrong = manifest.clone();
    wrong.receipt_bytes += 1;
    assert!(p.release_snapshot_pin(&wrong, "transfer-1").is_err());
    p.release_snapshot_pin(&manifest, "transfer-1")?;
    p.release_snapshot_pin(&manifest, "transfer-1")?;
    assert_eq!(p.rotate_snapshot(&manifest)?, manifest);
    p.connection(|c| {
        let tx = c.unchecked_transaction()?;
        tx.execute("UPDATE node_runtime SET format=1", [])?;
        assert!(p.verify_owner(&tx).is_err());
        tx.rollback()?;
        Ok(())
    })?;
    Ok(())
}

#[test]
fn maintenance_upgrade_failure_is_atomic() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        batch.identity,
        "fixture",
        StockSchema,
    )?;
    p.connection(|c| {
        c.execute_batch("CREATE TRIGGER fail_upgrade BEFORE UPDATE ON node_runtime BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;
        Ok(())
    })?;
    assert!(p.enable_maintenance().is_err());
    p.connection(|c| {
        assert!(!present(c)?);
        p.verify_owner(c)?;
        c.execute_batch("DROP TRIGGER fail_upgrade")?;
        Ok(())
    })?;
    p.enable_maintenance()?;
    Ok(())
}
