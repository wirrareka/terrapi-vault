//! Durable local application receipts. A receipt alone is not a two-copy ACK.
use crate::schema::RequestSchema;
use crate::*;
use rusqlite::OptionalExtension;

// This runtime reads the legacy receipt format only. An adapter encoding change
// must not silently rewrite the meaning of existing idempotency keys.
const _: () = assert!(reference::Proximi::FINGERPRINT_VERSION == 1);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteResult {
    pub operation_id: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationReceipt {
    pub fingerprint_version: u32,
    pub request_digest: String,
    pub result_version: u32,
    pub result: WriteResult,
}

// The adapter owns canonical encoding and domain separation. Transport scope is
// enforced by the owning protocol, not by a business-content fingerprint.
fn fingerprint_for<S: RequestSchema>(schema: &S, changes: &[S::Change]) -> String {
    schema
        .request_fingerprint(changes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
#[cfg(test)]
fn fingerprint(batch: &Batch) -> String {
    fingerprint_for(&reference::Proximi, &batch.changes)
}
impl OperationReceipt {
    /// Construct receipt contents for an applied journal envelope. This checks
    /// content integrity, not SQL application or durable/two-copy commit authority.
    /// The owning protocol must enforce expected scope, transitions and schema binding.
    pub fn from_applied<S: RequestSchema, I: Serialize + PartialEq>(
        schema: &S,
        e: &Entry<S::Change, I>,
    ) -> Result<Self>
    where
        S::Change: Serialize,
    {
        ensure(e.state == State::Applied, "receipt requires applied entry")?;
        ensure(
            S::FINGERPRINT_VERSION > 0,
            "invalid request fingerprint version",
        )?;
        ensure(
            !e.batch.operation_id.is_empty() && e.sequence > 0 && e.sequence <= i64::MAX as u64,
            "invalid receipt key",
        )?;
        e.validate(&e.batch.identity)?;
        Ok(Self {
            fingerprint_version: S::FINGERPRINT_VERSION,
            request_digest: fingerprint_for(schema, &e.batch.changes),
            result_version: 1,
            result: WriteResult {
                operation_id: e.batch.operation_id.clone(),
                sequence: e.sequence,
            },
        })
    }
    pub(super) fn matches(&self, batch: &Batch) -> Result<()> {
        self.matches_request(&reference::Proximi, batch)
    }
    /// Compare business request identity only. Tenant/epoch/schema admission and
    /// the receipt's sequence in the committed history are separate protocol checks.
    pub fn matches_request<S: RequestSchema, I>(
        &self,
        schema: &S,
        batch: &Batch<S::Change, I>,
    ) -> Result<()> {
        ensure(
            S::FINGERPRINT_VERSION > 0
                && self.fingerprint_version == S::FINGERPRINT_VERSION
                && self.result_version == 1,
            "unsupported receipt version",
        )?;
        ensure(
            !batch.operation_id.is_empty()
                && self.result.sequence > 0
                && self.result.sequence <= i64::MAX as u64
                && self.result.operation_id == batch.operation_id
                && self.request_digest == fingerprint_for(schema, &batch.changes),
            "idempotency key reused for different request",
        )
    }
}
pub(super) fn get(c: &Connection, id: &str) -> Result<Option<OperationReceipt>> {
    get_for(c, &reference::Proximi, id)
}
pub(crate) fn get_for<S: RequestSchema>(
    c: &Connection,
    _schema: &S,
    id: &str,
) -> Result<Option<OperationReceipt>> {
    ensure(
        S::FINGERPRINT_VERSION > 0,
        "invalid request fingerprint version",
    )?;
    let row: Option<(u64, String)> = c
        .query_row(
            "SELECT sequence,receipt FROM operation_receipts WHERE operation_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(sequence, json)| {
        let receipt: OperationReceipt = serde_json::from_str(&json)?;
        ensure(
            sequence > 0
                && !id.is_empty()
                && receipt.result.sequence == sequence
                && receipt.result.operation_id == id
                && receipt.fingerprint_version == S::FINGERPRINT_VERSION
                && receipt.result_version == 1,
            "invalid receipt metadata/version",
        )?;
        Ok(receipt)
    })
    .transpose()
}
pub(super) fn insert(c: &Connection, e: &Entry) -> Result<()> {
    insert_for(c, &reference::Proximi, e)
}
// Participate in the caller's entity/journal/receipt transaction; do not open or
// commit a separate transaction. No schema/tenant binding is inferred here.
pub(crate) fn insert_for<S: RequestSchema, I: Serialize + PartialEq>(
    c: &Connection,
    schema: &S,
    e: &Entry<S::Change, I>,
) -> Result<()>
where
    S::Change: Serialize,
{
    let receipt = OperationReceipt::from_applied(schema, e)?;
    if let Some(old) = get_for(c, schema, &e.batch.operation_id)? {
        return ensure(old == receipt, "receipt conflict");
    }
    c.execute(
        "INSERT INTO operation_receipts(operation_id,sequence,receipt) VALUES(?1,?2,?3)",
        params![
            receipt.result.operation_id,
            receipt.result.sequence,
            serde_json::to_string(&receipt)?
        ],
    )?;
    Ok(())
}
pub(super) fn validate_entry(c: &Connection, e: &Entry) -> Result<Option<OperationReceipt>> {
    validate_entry_for(c, &reference::Proximi, e)
}
pub(crate) fn validate_entry_for<S: RequestSchema, I: Serialize + PartialEq>(
    c: &Connection,
    schema: &S,
    e: &Entry<S::Change, I>,
) -> Result<Option<OperationReceipt>>
where
    S::Change: Serialize,
{
    let actual = get_for(c, schema, &e.batch.operation_id)?;
    let expected = if e.state == State::Applied {
        Some(OperationReceipt::from_applied(schema, e)?)
    } else {
        None
    };
    ensure(actual == expected, "receipt/journal mismatch")?;
    Ok(actual)
}
pub(super) fn count(c: &Connection) -> Result<u64> {
    Ok(c.query_row("SELECT count(*) FROM operation_receipts", [], |r| r.get(0))?)
}

pub(super) fn initialize(c: &Connection, identity: &Identity) -> Result<()> {
    let tx = c.unchecked_transaction()?;
    let tables: u64 = tx.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('operation_receipts','receipt_format')", [], |r| r.get(0))?;
    if tables == 0 {
        // Both tables and the completed migration marker commit together. Never
        // silently refill missing rows once this format has been installed.
        tx.execute_batch("CREATE TABLE operation_receipts(operation_id TEXT PRIMARY KEY NOT NULL,sequence INTEGER UNIQUE NOT NULL,receipt TEXT NOT NULL);
            CREATE TABLE receipt_format(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
            INSERT INTO receipt_format VALUES(1,1);")?;
        {
            let mut stmt = tx.prepare("SELECT entry FROM replication_log ORDER BY sequence")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let e: Entry = serde_json::from_str(&row.get::<_, String>(0)?)?;
                e.validate(identity)?;
                if e.state == State::Applied {
                    insert(&tx, &e)?;
                }
            }
        }
        // Old readiness proofs do not cover receipts. Normal pair reconciliation
        // must re-admit this replica. Existing snapshot staging is not deleted.
        tx.execute("DELETE FROM replication_readiness", [])?;
    } else {
        ensure(tables == 2, "incomplete receipt schema")?;
        let versions: Vec<u32> = tx
            .prepare("SELECT version FROM receipt_format")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        ensure(versions == [1], "unsupported/missing receipt format")?;
    }
    checkpoint::current(&tx, identity, false)?;
    tx.commit()?;
    Ok(())
}

impl Node {
    /// Local application evidence, not proof of a successful two-copy commit.
    pub fn receipt(&self, id: &str) -> Result<Option<OperationReceipt>> {
        self.connection(|c| match journal::by_operation(c, id)? {
            Some(e) => validate_entry(c, &e),
            None => {
                let receipt = get(c, id)?;
                if let Some(r) = &receipt {
                    let base = checkpoint::base(c)?.ok_or("orphan receipt")?;
                    ensure(r.result.sequence <= base.sequence, "orphan receipt")?;
                    checkpoint::current(c, &self.identity, false)?;
                }
                Ok(receipt)
            }
        })
    }
    pub(super) fn completed_result(&self, batch: &Batch) -> Result<Option<WriteResult>> {
        ensure(
            batch.identity == self.identity && !batch.operation_id.is_empty(),
            "invalid batch identity",
        )?;
        self.receipt(&batch.operation_id)?
            .map(|r| {
                r.matches(batch)?;
                Ok(r.result)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity {
            cluster: "pair".into(),
            tenant: "tenant".into(),
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
    fn node(dir: &std::path::Path, role: Role) -> Node {
        Node::open(dir.join("db"), role, identity(), "fixture").unwrap()
    }
    fn applied(p: &mut Node, id: &str) {
        p.prepare(batch(id)).unwrap();
        let e = p.decide(id).unwrap();
        p.apply(e).unwrap();
    }
    // Test-only construction of the exact pre-receipt table layout.
    fn legacy(p: &Node) {
        p.connection(|c| {
            c.execute_batch("DROP TABLE operation_receipts; DROP TABLE receipt_format;")?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn fingerprint_is_versioned_unambiguous_and_excludes_transport_identity() {
        let a = batch("one");
        let mut b = a.clone();
        b.operation_id = "two".into();
        b.identity.epoch = 2;
        b.identity.schema = 2;
        assert_eq!(fingerprint(&a), fingerprint(&b));
        assert_eq!(
            fingerprint(&a),
            "4f6eb28f0b7555bf639eff6cb38575414b80061e1f480c1e13af5cc371c1ef8d"
        );
        b.changes.reverse();
        b.changes.push(Change::DeletePlace { id: "place".into() });
        assert_ne!(fingerprint(&a), fingerprint(&b));
        let ordered = fingerprint(&b);
        b.changes.reverse();
        assert_ne!(ordered, fingerprint(&b));
        let mut x = batch("one");
        x.changes = vec![Change::PutPlace {
            id: "a".into(),
            name: "bc".into(),
        }];
        let mut y = x.clone();
        y.changes = vec![Change::PutPlace {
            id: "ab".into(),
            name: "c".into(),
        }];
        assert_ne!(fingerprint(&x), fingerprint(&y));
        x.changes = vec![Change::PutFeature {
            id: "f".into(),
            place_id: "p".into(),
            geojson: "{}".into(),
        }];
        y.changes = vec![Change::PutFeature {
            id: "f".into(),
            place_id: "p".into(),
            geojson: "{ }".into(),
        }];
        assert_ne!(fingerprint(&x), fingerprint(&y));
    }

    #[test]
    fn legacy_migration_backfills_only_applied_and_invalidates_old_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = node(dir.path(), Role::Primary);
        applied(&mut p, "one");
        let expected = p.receipt("one").unwrap();
        p.connection(|c| checkpoint::advance(c, &identity()))
            .unwrap();
        p.prepare(batch("pending")).unwrap();
        legacy(&p);
        drop(p);
        let p = node(dir.path(), Role::Primary);
        assert_eq!(p.receipt("one").unwrap(), expected);
        assert!(p.receipt("pending").unwrap().is_none());
        let markers: u64 = p
            .connection(|c| {
                Ok(
                    c.query_row("SELECT count(*) FROM replication_readiness", [], |r| {
                        r.get(0)
                    })?,
                )
            })
            .unwrap();
        assert_eq!(markers, 0);
        assert_eq!(p.journal_head().unwrap().length, 2);
    }

    #[test]
    fn corrupt_legacy_history_rolls_back_entire_migration() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = node(dir.path(), Role::Primary);
        applied(&mut p, "one");
        applied(&mut p, "two");
        legacy(&p);
        p.connection(|c| {
            let mut e = journal::by_operation(c, "two")?.unwrap();
            e.before = "wrong chain".into();
            e.digest = e.checksum()?;
            c.execute("UPDATE replication_log SET entry=?1 WHERE operation_id='two'", [serde_json::to_string(&e)?])?;
            assert!(initialize(c, &identity()).is_err());
            let n: u64 = c.query_row("SELECT count(*) FROM sqlite_master WHERE name IN ('operation_receipts','receipt_format')", [], |r| r.get(0))?;
            assert_eq!(n, 0);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn missing_changed_or_orphan_receipts_fail_closed_without_backfill() {
        for sql in [
            "DELETE FROM operation_receipts",
            "UPDATE operation_receipts SET receipt=json_set(receipt,'$.request_digest','wrong')",
            "UPDATE operation_receipts SET receipt=json_set(receipt,'$.fingerprint_version',99)",
            "UPDATE operation_receipts SET receipt=json_set(receipt,'$.result_version',99)",
            "UPDATE operation_receipts SET sequence=2",
            "UPDATE replication_log SET operation_id='wrong'",
            "DELETE FROM receipt_format",
            "DROP TABLE receipt_format",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut p = node(dir.path(), Role::Primary);
            applied(&mut p, "one");
            p.connection(|c| {
                c.execute_batch(sql)?;
                Ok(())
            })
            .unwrap();
            drop(p);
            assert!(
                Node::open(dir.path().join("db"), Role::Primary, identity(), "fixture").is_err(),
                "{sql}"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let mut p = node(dir.path(), Role::Primary);
        applied(&mut p, "one");
        p.connection(|c| {
            let mut orphan = get(c, "one")?.unwrap();
            orphan.result = WriteResult {
                operation_id: "orphan".into(),
                sequence: 2,
            };
            c.execute(
                "INSERT INTO operation_receipts VALUES('orphan',2,?1)",
                [serde_json::to_string(&orphan)?],
            )?;
            Ok(())
        })
        .unwrap();
        assert!(p.checkpoint().is_err());
        assert!(p.receipt("orphan").is_err());
        assert!(p.snapshot().is_err());
    }

    #[test]
    fn receipt_insert_failure_rolls_back_business_and_applied_journal() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = node(dir.path(), Role::Primary);
        p.prepare(batch("one")).unwrap();
        let e = p.decide("one").unwrap();
        p.connection(|c| { c.execute_batch("CREATE TRIGGER reject_receipt BEFORE INSERT ON operation_receipts BEGIN SELECT RAISE(ABORT,'injected'); END;")?; Ok(()) }).unwrap();
        assert!(p.apply(e.clone()).is_err());
        assert_eq!(p.view().unwrap(), View::default());
        assert_eq!(p.operation("one").unwrap().unwrap().state, State::Decided);
        assert!(p.receipt("one").unwrap().is_none());
        p.connection(|c| {
            c.execute_batch("DROP TRIGGER reject_receipt")?;
            Ok(())
        })
        .unwrap();
        p.apply(e).unwrap();
        assert!(p.receipt("one").unwrap().is_some());
    }

    #[test]
    fn snapshot_receipt_mismatch_rolls_back_all_live_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = node(dir.path(), Role::Primary);
        applied(&mut p, "one");
        let other = tempfile::tempdir().unwrap();
        let mut s = node(other.path(), Role::Secondary);
        let mut manifest = p.snapshot_manifest().unwrap();
        manifest.checkpoint.receipt_digest = "0".repeat(64);
        let t = s.snapshot_begin(manifest.clone()).unwrap();
        s.snapshot_chunk(t.token, p.journal_page(&manifest.head, 0, 32).unwrap())
            .unwrap();
        assert!(s.snapshot_finish(t.token).is_err());
        assert_eq!(s.view().unwrap(), View::default());
        assert!(s.receipt("one").unwrap().is_none());
        assert_eq!(s.journal_head().unwrap().length, 0);
        assert!(!s.snapshot_progress().unwrap().unwrap().complete);
        s.snapshot_cancel(t.token).unwrap();
        let mut snapshot = p.snapshot().unwrap();
        snapshot.receipt_digest = "0".repeat(64);
        snapshot.digest = hash(&(
            &snapshot.identity,
            &snapshot.view,
            &snapshot.entries,
            &snapshot.receipt_digest,
        ))
        .unwrap();
        assert!(s.install(snapshot).is_err());
        assert!(s.receipt("one").unwrap().is_none());
        assert_eq!(s.view().unwrap(), View::default());
    }
}
