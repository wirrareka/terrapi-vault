use super::*;
use crate::envelope_tests::{stock_entry, StockSchema};

#[test]
fn checkpoint_checks_applied_and_pending_integrity_without_trusting_receipts() -> Result<()> {
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
        id,
        "fixture",
        StockSchema,
    )?;
    commit(&mut p, &mut s, batch.clone())?;
    let expected = p.checkpoint()?;
    batch.operation_id = "pending".into();
    p.prepare(batch)?;
    p.connection(|c| {
        assert_eq!(p.current(c, false)?.0, expected);
        for sequence in [1, 2] {
            let json: String = c.query_row(
                "SELECT entry FROM replication_log WHERE sequence=?1",
                [sequence],
                |r| r.get(0),
            )?;
            let original: Record<StockSchema> = serde_json::from_str(&json)?;
            for mutation in 0..4 {
                let mut entry = original.clone();
                match mutation {
                    0 => entry.digest = "0".repeat(64),
                    1 => {
                        entry.batch.identity.epoch += 1;
                        entry.digest = entry.checksum()?;
                    }
                    2 => {
                        entry.before = "0".repeat(64);
                        entry.digest = entry.checksum()?;
                    }
                    _ => {
                        entry.batch.operation_id = "wrong-key".into();
                        entry.digest = entry.checksum()?;
                    }
                }
                let tx = c.unchecked_transaction()?;
                tx.execute(
                    "UPDATE replication_log SET entry=?1 WHERE sequence=?2",
                    params![serde_json::to_string(&entry)?, sequence],
                )?;
                assert!(
                    p.current(&tx, false).is_err(),
                    "sequence={sequence} mutation={mutation}"
                );
                if sequence == 1 && mutation == 0 {
                    assert!(OperationReceipt::from_applied(&StockSchema, &entry).is_err());
                }
                tx.rollback()?;
            }
        }
        let tx = c.unchecked_transaction()?;
        tx.execute("DELETE FROM operation_receipts WHERE sequence=1", [])?;
        assert!(p.current(&tx, false).is_err());
        tx.rollback()?;
        assert_eq!(p.current(c, false)?.0, expected);
        Ok(())
    })
}
