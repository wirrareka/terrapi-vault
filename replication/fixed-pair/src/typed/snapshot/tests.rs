use super::*;
use crate::envelope_tests::{stock_entry, StockSchema};

#[test]
fn streaming_publication_binds_pages_and_rolls_back_finalization() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut batch = stock_entry().batch;
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
    let empty = p.publish_snapshot()?;
    assert_eq!(empty.pages, 0);
    batch.changes = (0..513)
        .map(|n| crate::envelope_tests::StockChange::Set {
            sku: format!("item-{n:04}"),
            quantity: n,
        })
        .collect();
    commit(&mut p, &mut s, batch)?;
    let expected = p.connection(|c| sql_snapshot::export(c, &StockSchema, &scope(&id)))?;
    let expected_pages = expected.pages(sql_snapshot::MAX_PAGE_ROWS)?;
    assert_eq!(expected_pages.len(), 3);
    p.connection(|c| {
        c.execute_batch("CREATE TRIGGER fail_finalization AFTER UPDATE ON node_publication_pages WHEN NEW.position=1 BEGIN SELECT RAISE(ABORT,'fixture finalization fault'); END;")?;
        Ok(())
    })?;
    assert!(p.rotate_snapshot(&empty).is_err());
    assert_eq!(p.published_snapshot()?, Some(empty.clone()));
    p.connection(|c| {
        assert_eq!(
            c.query_row("SELECT count(*) FROM node_publication_pages", [], |r| r
                .get::<_, u64>(0))?,
            0
        );
        c.execute_batch("DROP TRIGGER fail_finalization")?;
        c.execute_batch("CREATE TRIGGER skip_finalization BEFORE UPDATE ON node_publication_pages WHEN NEW.position=1 BEGIN SELECT RAISE(IGNORE); END;")?;
        Ok(())
    })?;
    assert!(p.rotate_snapshot(&empty).is_err());
    assert_eq!(p.published_snapshot()?, Some(empty.clone()));
    p.connection(|c| {
        assert_eq!(
            c.query_row("SELECT count(*) FROM node_publication_pages", [], |r| r
                .get::<_, u64>(0))?,
            0
        );
        c.execute_batch("DROP TRIGGER skip_finalization")?;
        Ok(())
    })?;
    let manifest = p.rotate_snapshot(&empty)?;
    assert_eq!(manifest.data, expected.manifest);
    assert_eq!(manifest.pages, 4);
    for (n, page) in expected_pages.into_iter().enumerate() {
        let published = p.snapshot_page(&manifest, n as u64)?;
        assert_eq!(published.content, Content::Data(page));
        assert_eq!(published.manifest_digest, manifest.digest()?);
    }
    let mut target = Node::open(
        dir.path().join("target"),
        Role::Secondary,
        id,
        "fixture",
        StockSchema,
    )?;
    target.begin_snapshot(&manifest)?;
    for n in 0..manifest.pages {
        target.receive_snapshot(&p.snapshot_page(&manifest, n)?)?;
    }
    target.finish_snapshot(&manifest)?;
    assert_eq!(target.view()?, p.view()?);
    assert_eq!(target.checkpoint()?, p.checkpoint()?);
    Ok(())
}

#[test]
fn streaming_publication_respects_byte_limits_for_data_and_receipts() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut batch = stock_entry().batch;
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
    for n in 0..7 {
        batch.operation_id = format!("{n}-{}", "o".repeat(180_000));
        batch.changes = vec![crate::envelope_tests::StockChange::Set {
            sku: format!("{n}-{}", "s".repeat(180_000)),
            quantity: n,
        }];
        commit(&mut p, &mut s, batch.clone())?;
    }
    let expected = p.connection(|c| sql_snapshot::export(c, &StockSchema, &scope(&id)))?;
    let data_pages = expected.pages(sql_snapshot::MAX_PAGE_ROWS)?;
    assert_eq!(data_pages.len(), 2);
    let manifest = p.publish_snapshot()?;
    assert_eq!(manifest.pages, 4);
    assert_eq!(manifest.data, expected.manifest);
    let mut receipt_count = 0;
    let mut receipt_bytes = 0;
    for n in 0..manifest.pages {
        let page = p.snapshot_page(&manifest, n)?;
        assert!(page.encode()?.len() <= MAX_PAGE_BYTES);
        match page.content {
            Content::Data(data) => assert_eq!(data, data_pages[n as usize]),
            Content::Receipts(receipts) => {
                assert!(receipts.len() < sql_snapshot::MAX_PAGE_ROWS);
                for receipt in receipts {
                    receipt_count += 1;
                    receipt_bytes += serde_json::to_vec(&receipt)?.len() as u64;
                }
            }
        }
    }
    assert_eq!(receipt_count, 7);
    assert_eq!(receipt_bytes, manifest.receipt_bytes);
    Ok(())
}

#[test]
fn rotation_is_atomic_compare_and_swap_and_restores_after_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut batch = stock_entry().batch;
    let id = batch.identity.clone();
    let path = dir.path().join("p");
    let mut p = Node::open(&path, Role::Primary, id.clone(), "fixture", StockSchema)?;
    assert!(p.published_snapshot()?.is_none());
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        id.clone(),
        "fixture",
        StockSchema,
    )?;
    commit(&mut p, &mut s, batch.clone())?;
    let old = p.publish_snapshot()?;
    let first = p.snapshot_page(&old, 0)?;
    batch.operation_id = "after-publication".into();
    commit(&mut p, &mut s, batch)?;
    let checkpoint = p.checkpoint()?;
    p.connection(|c| {
        c.execute_batch("CREATE TRIGGER fail_rotation AFTER INSERT ON node_publication BEGIN SELECT RAISE(ABORT,'fixture rotation fault'); END;")?;
        Ok(())
    })?;
    assert!(p.rotate_snapshot(&old).is_err());
    assert_eq!(p.publish_snapshot()?, old);
    assert_eq!(p.published_snapshot()?, Some(old.clone()));
    assert_eq!(p.snapshot_page(&old, 0)?, first);
    assert_eq!(p.checkpoint()?, checkpoint);
    p.connection(|c| {
        c.execute_batch("DROP TRIGGER fail_rotation")?;
        Ok(())
    })?;
    let mut stale = old.clone();
    stale.checkpoint.sequence += 1;
    assert!(p.rotate_snapshot(&stale).is_err());
    assert_eq!(p.publish_snapshot()?, old);
    let new = p.rotate_snapshot(&old)?;
    assert_eq!(new.checkpoint, checkpoint);
    assert!(p.snapshot_page(&old, 0).is_err());
    assert!(p.rotate_snapshot(&old).is_err());
    drop(p);
    let mut p = Node::open(&path, Role::Primary, id.clone(), "fixture", StockSchema)?;
    assert_eq!(p.publish_snapshot()?, new);
    assert_eq!(p.published_snapshot()?, Some(new.clone()));
    let mut target = Node::open(
        dir.path().join("target"),
        Role::Secondary,
        id,
        "fixture",
        StockSchema,
    )?;
    assert!(target.rotate_snapshot(&new).is_err());
    target.begin_snapshot(&new)?;
    for n in 0..new.pages {
        target.receive_snapshot(&p.snapshot_page(&new, n)?)?;
    }
    target.finish_snapshot(&new)?;
    recover(&mut p, &mut target)?;
    assert_eq!(target.checkpoint()?, checkpoint);
    assert_eq!(
        target.receipt("after-publication")?,
        p.receipt("after-publication")?
    );
    Ok(())
}
