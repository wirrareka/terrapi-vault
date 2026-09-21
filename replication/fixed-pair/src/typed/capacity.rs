//! Admission against the current snapshot format, not a disk-space reservation.
use super::*;

pub const RECEIPT_FORMAT_LEDGER: u32 = 2;
pub const MAX_RECEIPTS_V2: u64 = 1_000_000;

fn normalized_schema(sql: &str) -> String {
    sql.chars()
        .filter(|c| !c.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn ledger_schema() -> Vec<(&'static str, &'static str, String)> {
    vec![
        (
            "table",
            "receipt_capacity",
            normalized_schema(
                "CREATE TABLE receipt_capacity(
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    receipt_count INTEGER NOT NULL CHECK(receipt_count>=0 AND receipt_count<=1000000),
                    receipt_bytes INTEGER NOT NULL CHECK(receipt_bytes>=0 AND receipt_bytes<=268435456))",
            ),
        ),
        (
            "trigger",
            "receipt_capacity_insert",
            normalized_schema(
                "CREATE TRIGGER receipt_capacity_insert AFTER INSERT ON operation_receipts BEGIN
                    UPDATE receipt_capacity SET
                        receipt_count=receipt_count+1,
                        receipt_bytes=receipt_bytes+length(CAST(NEW.receipt AS BLOB))
                    WHERE id=1 AND receipt_count<1000000
                        AND receipt_bytes<=268435456-length(CAST(NEW.receipt AS BLOB));
                    SELECT CASE WHEN changes()!=1 THEN RAISE(ABORT,'receipt capacity exceeded') END;
                END",
            ),
        ),
        (
            "trigger",
            "receipt_capacity_delete",
            normalized_schema(
                "CREATE TRIGGER receipt_capacity_delete BEFORE DELETE ON operation_receipts BEGIN
                    SELECT RAISE(ABORT,'operation receipts are immutable');
                END",
            ),
        ),
        (
            "trigger",
            "receipt_capacity_update",
            normalized_schema(
                "CREATE TRIGGER receipt_capacity_update BEFORE UPDATE ON operation_receipts BEGIN
                    SELECT RAISE(ABORT,'operation receipts are immutable');
                END",
            ),
        ),
    ]
}

fn receipt_format(c: &Connection) -> Result<u32> {
    let versions: Vec<u32> = c
        .prepare("SELECT version FROM receipt_format")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        versions.len() == 1 && matches!(versions[0], 1 | RECEIPT_FORMAT_LEDGER),
        "typed node receipt format mismatch",
    )?;
    Ok(versions[0])
}

fn max_receipts(format: u32) -> u64 {
    if format == RECEIPT_FORMAT_LEDGER {
        MAX_RECEIPTS_V2
    } else {
        sql_snapshot::MAX_ROWS
    }
}

pub(super) fn install_ledger(c: &Connection, count: u64, bytes: u64) -> Result<()> {
    ensure(
        count <= MAX_RECEIPTS_V2 && bytes <= sql_snapshot::MAX_BYTES,
        "invalid receipt capacity seed",
    )?;
    c.execute_batch(
        "CREATE TABLE receipt_capacity(
             id INTEGER PRIMARY KEY CHECK(id=1),
             receipt_count INTEGER NOT NULL CHECK(receipt_count>=0 AND receipt_count<=1000000),
             receipt_bytes INTEGER NOT NULL CHECK(receipt_bytes>=0 AND receipt_bytes<=268435456));
         CREATE TRIGGER receipt_capacity_insert AFTER INSERT ON operation_receipts BEGIN
             UPDATE receipt_capacity SET
                 receipt_count=receipt_count+1,
                 receipt_bytes=receipt_bytes+length(CAST(NEW.receipt AS BLOB))
             WHERE id=1 AND receipt_count<1000000
                 AND receipt_bytes<=268435456-length(CAST(NEW.receipt AS BLOB));
             SELECT CASE WHEN changes()!=1 THEN RAISE(ABORT,'receipt capacity exceeded') END;
         END;
         CREATE TRIGGER receipt_capacity_delete BEFORE DELETE ON operation_receipts BEGIN
             SELECT RAISE(ABORT,'operation receipts are immutable');
         END;
         CREATE TRIGGER receipt_capacity_update BEFORE UPDATE ON operation_receipts BEGIN
             SELECT RAISE(ABORT,'operation receipts are immutable');
         END;",
    )?;
    ensure(
        c.execute(
            "INSERT INTO receipt_capacity VALUES(1,?1,?2)",
            params![count, bytes],
        )? == 1,
        "receipt capacity seed failed",
    )?;
    Ok(())
}

pub(super) fn verify_schema(c: &Connection) -> Result<u32> {
    let format = receipt_format(c)?;
    if format == RECEIPT_FORMAT_LEDGER {
        let objects: Vec<(String, String, String, String)> = c
            .prepare(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema
                 WHERE name GLOB 'receipt_capacity*' ORDER BY name",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let expected = ledger_schema();
        ensure(
            objects.len() == expected.len()
                && objects.iter().all(|(kind, name, table, sql)| {
                    expected
                        .iter()
                        .any(|(expected_kind, expected_name, expected_sql)| {
                            kind == expected_kind
                                && name == expected_name
                                && table
                                    == if *expected_kind == "table" {
                                        "receipt_capacity"
                                    } else {
                                        "operation_receipts"
                                    }
                                && normalized_schema(sql) == *expected_sql
                        })
                }),
            "receipt capacity schema mismatch",
        )?;
    } else {
        let objects: u64 = c.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'receipt_capacity*'",
            [],
            |r| r.get(0),
        )?;
        ensure(objects == 0, "legacy receipt format has capacity objects")?;
    }
    Ok(format)
}

pub(super) fn format(c: &Connection) -> Result<u32> {
    verify_schema(c)
}

pub(super) fn verify_accounting(c: &Connection) -> Result<()> {
    if verify_schema(c)? == RECEIPT_FORMAT_LEDGER {
        let actual: (u64, u64) = c.query_row(
            "SELECT count(*),coalesce(sum(length(CAST(receipt AS BLOB))),0) FROM operation_receipts",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let ledger: (u64, u64) = c.query_row(
            "SELECT receipt_count,receipt_bytes FROM receipt_capacity WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure(
            actual == ledger && actual.0 <= MAX_RECEIPTS_V2 && actual.1 <= sql_snapshot::MAX_BYTES,
            "receipt capacity ledger mismatch",
        )?;
    }
    Ok(())
}

/// Encoded snapshot content, excluding page wrappers, journal and cipher overhead.
/// Measuring scans application rows and receipts; it is not a hot-path metric.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capacity {
    pub data_rows: u64,
    pub data_bytes: u64,
    pub receipts: u64,
    pub receipt_bytes: u64,
}

impl Capacity {
    fn add_receipt(&mut self, receipt: &OperationReceipt) -> Result<()> {
        let bytes = serde_json::to_vec(receipt)?.len();
        ensure(
            bytes <= sql_snapshot::MAX_ROW_BYTES,
            "snapshot receipt too large",
        )?;
        self.receipts = self
            .receipts
            .checked_add(1)
            .ok_or("receipt count overflow")?;
        self.receipt_bytes = self
            .receipt_bytes
            .checked_add(bytes as u64)
            .ok_or("receipt bytes overflow")?;
        ensure(
            self.receipts <= MAX_RECEIPTS_V2 && self.receipt_bytes <= sql_snapshot::MAX_BYTES,
            "snapshot receipt quota exceeded",
        )
    }
}

impl<A: ReplicatedSchema> Node<A> {
    fn capacity_in(&self, tx: &rusqlite::Transaction<'_>) -> Result<Capacity> {
        let data =
            sql_snapshot::scan_in(tx, &self.adapter, &snapshot::scope(&self.identity), |_| {
                Ok(())
            })?;
        let mut capacity = Capacity {
            data_rows: data.rows,
            data_bytes: data.bytes,
            receipts: 0,
            receipt_bytes: 0,
        };
        let mut stmt = tx.prepare("SELECT receipt FROM operation_receipts ORDER BY sequence")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let receipt: OperationReceipt = serde_json::from_str(&row.get::<_, String>(0)?)?;
            capacity.add_receipt(&receipt)?;
        }
        ensure(
            capacity.receipts <= max_receipts(receipt_format(tx)?),
            "snapshot receipt quota exceeded",
        )?;
        Ok(capacity)
    }

    fn audit_capacity_in(&self, tx: &rusqlite::Transaction<'_>) -> Result<Capacity> {
        let capacity = self.capacity_in(tx)?;
        if receipt_format(tx)? == RECEIPT_FORMAT_LEDGER {
            let ledger: (u64, u64) = tx.query_row(
                "SELECT receipt_count,receipt_bytes FROM receipt_capacity WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure(
                ledger == (capacity.receipts, capacity.receipt_bytes),
                "receipt capacity ledger mismatch",
            )?;
        }
        Ok(capacity)
    }

    /// Atomically install receipt-format 2 after fully validating the existing
    /// lifetime receipt prefix. No receipt is removed or reinterpreted.
    pub fn upgrade_receipt_capacity(&mut self) -> Result<Capacity> {
        self.connection(|c| {
            self.admission(c)?;
            let tx = c.unchecked_transaction()?;
            ensure(
                receipt_format(&tx)? == 1,
                "receipt capacity already upgraded",
            )?;
            // This is the authoritative receipt-prefix/checkpoint validation and
            // runs inside the same transaction as schema installation and marker flip.
            self.current(&tx, true)?;
            let capacity = self.capacity_in(&tx)?;
            install_ledger(&tx, capacity.receipts, capacity.receipt_bytes)?;
            ensure(
                tx.execute(
                    "UPDATE receipt_format SET version=?1 WHERE id=1 AND version=1",
                    [RECEIPT_FORMAT_LEDGER],
                )? == 1,
                "receipt capacity upgrade conflict",
            )?;
            tx.commit()?;
            Ok(capacity)
        })
    }

    /// Full streaming audit for offline qualification and post-copy checks.
    pub fn audit_snapshot_capacity(&self) -> Result<Capacity> {
        self.connection(|c| {
            self.admission(c)?;
            let tx = c.unchecked_transaction()?;
            self.current(&tx, true)?;
            let capacity = self.audit_capacity_in(&tx)?;
            tx.rollback()?;
            Ok(capacity)
        })
    }

    /// Validate and measure the current recoverable content under a read transaction.
    /// Exceeding a format limit returns an error; it never revokes read admission.
    pub fn snapshot_capacity(&self) -> Result<Capacity> {
        self.connection(|c| {
            self.admission(c)?;
            let tx = c.unchecked_transaction()?;
            self.current(&tx, true)?;
            let capacity = self.audit_capacity_in(&tx)?;
            tx.rollback()?;
            Ok(capacity)
        })
    }

    // Run before prepare/stage and before turning a legacy Prepared into Decided.
    // Never reject an already durable decision here: it must remain replayable.
    pub(super) fn check_write_capacity(&self, c: &Connection, entry: &Record<A>) -> Result<()> {
        let tx = c.unchecked_transaction()?;
        schema::replay_data(
            &tx,
            &self.adapter,
            &self.identity.schema,
            &entry.before,
            &entry.after,
            &entry.changeset,
        )?;
        let format = receipt_format(&tx)?;
        let mut capacity = if format == RECEIPT_FORMAT_LEDGER {
            let data = sql_snapshot::scan_in(
                &tx,
                &self.adapter,
                &snapshot::scope(&self.identity),
                |_| Ok(()),
            )?;
            let (receipts, receipt_bytes) = tx.query_row(
                "SELECT receipt_count,receipt_bytes FROM receipt_capacity WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Capacity {
                data_rows: data.rows,
                data_bytes: data.bytes,
                receipts,
                receipt_bytes,
            }
        } else {
            self.capacity_in(&tx)?
        };
        ensure(
            capacity.receipts.checked_add(1) == Some(entry.sequence),
            "snapshot receipt sequence mismatch",
        )?;
        let mut applied = entry.clone();
        applied.state = State::Applied;
        capacity.add_receipt(&OperationReceipt::from_applied(&self.adapter, &applied)?)?;
        ensure(
            capacity.receipts <= max_receipts(format),
            "snapshot receipt quota exceeded",
        )?;
        tx.rollback()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_count_and_encoded_byte_boundaries() -> Result<()> {
        let receipt = OperationReceipt {
            fingerprint_version: 1,
            request_digest: "a".repeat(64),
            result_version: 1,
            result: WriteResult {
                operation_id: "boundary".into(),
                sequence: 1,
            },
        };
        let size = serde_json::to_vec(&receipt)?.len() as u64;
        let mut capacity = Capacity {
            data_rows: 0,
            data_bytes: 0,
            receipts: MAX_RECEIPTS_V2 - 1,
            receipt_bytes: 0,
        };
        capacity.add_receipt(&receipt)?;
        assert_eq!(capacity.receipts, MAX_RECEIPTS_V2);
        assert!(capacity.add_receipt(&receipt).is_err());
        let mut capacity = Capacity {
            data_rows: 0,
            data_bytes: 0,
            receipts: 0,
            receipt_bytes: sql_snapshot::MAX_BYTES - size,
        };
        capacity.add_receipt(&receipt)?;
        assert_eq!(capacity.receipt_bytes, sql_snapshot::MAX_BYTES);
        assert!(capacity.add_receipt(&receipt).is_err());
        let mut capacity = Capacity {
            data_rows: 0,
            data_bytes: 0,
            receipts: 0,
            receipt_bytes: 0,
        };
        let mut exact = receipt.clone();
        exact
            .result
            .operation_id
            .push_str(&"x".repeat(sql_snapshot::MAX_ROW_BYTES - size as usize));
        capacity.add_receipt(&exact)?;
        exact.result.operation_id.push('x');
        assert!(capacity.add_receipt(&exact).is_err());
        Ok(())
    }
}
