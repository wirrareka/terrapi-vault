use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use terrapi_vesta::Vesta;
use terrapi_vesta_replication::{
    commit,
    schema::{RequestSchema, Schema, SchemaId},
    typed::{snapshot::Content, Node, Request},
    Batch, Identity, Result, Role,
};

const PASSWORD: &str = "capacity-contract";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Change(String);
#[derive(Clone, Copy)]
struct Adapter;

impl Schema for Adapter {
    type Change = Change;
    type View = Vec<String>;
    fn identity(&self) -> SchemaId {
        SchemaId {
            name: "capacity.fixture".into(),
            version: 1,
        }
    }
    fn tables(&self) -> &'static [&'static str] {
        &["capacity_values"]
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS capacity_values(value TEXT PRIMARY KEY NOT NULL)",
        )?;
        Ok(())
    }
    fn execute(&self, c: &Connection, changes: &[Change]) -> Result<()> {
        for change in changes {
            c.execute(
                "INSERT OR REPLACE INTO capacity_values VALUES(?1)",
                [&change.0],
            )?;
        }
        Ok(())
    }
    fn view(&self, c: &Connection) -> Result<Self::View> {
        Ok(
            c.prepare("SELECT value FROM capacity_values ORDER BY value")?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?,
        )
    }
}
impl RequestSchema for Adapter {
    const FINGERPRINT_VERSION: u32 = 1;
    fn request_fingerprint(&self, changes: &[Change]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"capacity.fixture.v1\0");
        for change in changes {
            h.update((change.0.len() as u64).to_be_bytes());
            h.update(change.0.as_bytes());
        }
        h.finalize().into()
    }
}

fn identity() -> Identity<SchemaId> {
    Identity {
        cluster: "capacity".into(),
        tenant: "qualification".into(),
        epoch: 1,
        schema: Adapter.identity(),
    }
}
fn request(id: &Identity<SchemaId>, operation: &str, value: &str) -> Request<Adapter> {
    Batch {
        identity: id.clone(),
        operation_id: operation.into(),
        changes: vec![Change(value.into())],
    }
}

#[test]
fn format_two_migrates_reopens_and_preserves_lifetime_idempotency() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (primary_path, secondary_path) = (
        dir.path().join("primary.db"),
        dir.path().join("secondary.db"),
    );
    let restored_path = dir.path().join("restored.db");
    let id = identity();
    let original = request(&id, "stable-operation", "one");
    let expected = {
        let mut primary = Node::open(&primary_path, Role::Primary, id.clone(), PASSWORD, Adapter)?;
        let mut secondary = Node::open(
            &secondary_path,
            Role::Secondary,
            id.clone(),
            PASSWORD,
            Adapter,
        )?;
        let result = commit(&mut primary, &mut secondary, original.clone())?;
        let before = primary.snapshot_capacity()?;
        assert_eq!(primary.upgrade_receipt_capacity()?, before);
        assert_eq!(secondary.upgrade_receipt_capacity()?, before);
        assert_eq!(primary.audit_snapshot_capacity()?, before);
        let manifest = primary.publish_snapshot()?;
        assert_eq!(manifest.format, 2);
        let mut restored = Node::open(
            &restored_path,
            Role::Secondary,
            id.clone(),
            PASSWORD,
            Adapter,
        )?;
        assert_eq!(restored.begin_snapshot(&manifest)?, 0);
        for position in 0..manifest.pages {
            let page = primary.snapshot_page(&manifest, position)?;
            restored.receive_snapshot(&page)?;
        }
        restored.finish_snapshot(&manifest)?;
        assert_eq!(restored.audit_snapshot_capacity()?, before);
        drop(restored);
        assert_eq!(
            Node::open(
                &restored_path,
                Role::Secondary,
                id.clone(),
                PASSWORD,
                Adapter,
            )?
            .audit_snapshot_capacity()?,
            before
        );
        result
    };

    // A legacy reader's exact version-1 admission rejects without mutating data.
    let vault = Vesta::open(&primary_path, PASSWORD)?;
    vault.with_connection(|c| {
        let version: u32 = c.query_row("SELECT version FROM receipt_format", [], |r| r.get(0))?;
        assert_eq!(version, 2);
        assert_ne!(version, 1);
        Ok(())
    })?;
    drop(vault);

    let mut primary = Node::open(&primary_path, Role::Primary, id.clone(), PASSWORD, Adapter)?;
    let mut secondary = Node::open(
        &secondary_path,
        Role::Secondary,
        id.clone(),
        PASSWORD,
        Adapter,
    )?;
    assert_eq!(
        commit(&mut primary, &mut secondary, original.clone())?,
        expected
    );
    assert!(commit(
        &mut primary,
        &mut secondary,
        request(&id, "stable-operation", "different")
    )
    .is_err());
    let second = request(&id, "operation-🗺️-café", "two");
    commit(&mut primary, &mut secondary, second)?;
    let audited = primary.audit_snapshot_capacity()?;
    assert_eq!(audited.receipts, 2);
    assert_eq!(audited, secondary.audit_snapshot_capacity()?);
    let vault = Vesta::open(&primary_path, PASSWORD)?;
    vault.with_connection(|c| {
        let recomputed: u64 = c.query_row(
            "SELECT coalesce(sum(length(CAST(receipt AS BLOB))),0) FROM operation_receipts",
            [],
            |r| r.get(0),
        )?;
        let ledger: u64 = c.query_row(
            "SELECT receipt_bytes FROM receipt_capacity WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(ledger, recomputed);
        assert_eq!(ledger, audited.receipt_bytes);
        Ok(())
    })?;
    drop(primary);
    let reopened = Node::open(&primary_path, Role::Primary, id, PASSWORD, Adapter)?;
    assert_eq!(
        reopened.audit_snapshot_capacity()?.receipt_bytes,
        audited.receipt_bytes
    );
    Ok(())
}

#[test]
fn ledger_mismatch_and_corrupt_legacy_upgrade_fail_closed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("node.db");
    let id = identity();
    let mut node = Node::open(&path, Role::Primary, id.clone(), PASSWORD, Adapter)?;
    let prepared = node.prepare(request(&id, "one", "one"))?;
    let decided = node.decide(&prepared.batch.operation_id)?;
    node.apply(decided)?;
    node.upgrade_receipt_capacity()?;
    drop(node);

    let vault = Vesta::open(&path, PASSWORD)?;
    vault.with_connection(|c| {
        assert!(c.execute("DELETE FROM operation_receipts", []).is_err());
        assert!(c
            .execute(
                "UPDATE operation_receipts SET receipt=receipt WHERE sequence=1",
                [],
            )
            .is_err());
        Ok(())
    })?;
    vault.with_connection(|c| {
        c.execute(
            "UPDATE receipt_capacity SET receipt_bytes=receipt_bytes+1 WHERE id=1",
            [],
        )?;
        Ok(())
    })?;
    drop(vault);
    assert!(Node::open(&path, Role::Primary, id, PASSWORD, Adapter).is_err());
    Ok(())
}

#[test]
fn schema_tampering_and_orphan_v2_objects_fail_closed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("tampered-v2.db");
    let id = identity();
    let mut node = Node::open(&path, Role::Primary, id.clone(), PASSWORD, Adapter)?;
    node.upgrade_receipt_capacity()?;
    drop(node);
    let vault = Vesta::open(&path, PASSWORD)?;
    vault.with_connection(|c| {
        c.execute_batch(
            "DROP TRIGGER receipt_capacity_insert;
             CREATE TRIGGER receipt_capacity_insert AFTER INSERT ON operation_receipts BEGIN
                 SELECT 1;
             END;",
        )?;
        Ok(())
    })?;
    drop(vault);
    assert!(Node::open(&path, Role::Primary, id.clone(), PASSWORD, Adapter).is_err());

    let legacy_path = dir.path().join("legacy-orphan.db");
    drop(Node::open(
        &legacy_path,
        Role::Primary,
        id.clone(),
        PASSWORD,
        Adapter,
    )?);
    let vault = Vesta::open(&legacy_path, PASSWORD)?;
    vault.with_connection(|c| {
        c.execute_batch("CREATE TABLE receipt_capacity_orphan(value INTEGER)")?;
        Ok(())
    })?;
    drop(vault);
    assert!(Node::open(&legacy_path, Role::Primary, id, PASSWORD, Adapter).is_err());
    Ok(())
}

#[test]
fn corrupt_v1_prefix_cannot_partially_upgrade() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let id = identity();
    for (case, mutation) in [
        ("sequence", "UPDATE operation_receipts SET sequence=7 WHERE sequence=1"),
        ("id", "UPDATE operation_receipts SET operation_id='different' WHERE sequence=1"),
        ("digest", "UPDATE operation_receipts SET receipt=json_set(receipt,'$.request_digest','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff') WHERE sequence=1"),
    ] {
        let path = dir.path().join(format!("corrupt-v1-{case}.db"));
        let mut node = Node::open(&path, Role::Primary, id.clone(), PASSWORD, Adapter)?;
        let prepared = node.prepare(request(&id, "one", "one"))?;
        let decided = node.decide(&prepared.batch.operation_id)?;
        node.apply(decided)?;
        let vault = Vesta::open(&path, PASSWORD)?;
        vault.with_connection(|c| { c.execute(mutation, [])?; Ok(()) })?;
        assert!(node.upgrade_receipt_capacity().is_err());
        vault.with_connection(|c| {
            let version: u32 = c.query_row("SELECT version FROM receipt_format", [], |r| r.get(0))?;
            assert_eq!(version, 1);
            let capacity_objects: u64 = c.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'receipt_capacity*'", [], |r| r.get(0),
            )?;
            assert_eq!(capacity_objects, 0);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn marker_update_failure_rolls_back_entire_capacity_migration() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("marker-failure.db");
    let id = identity();
    let mut node = Node::open(&path, Role::Primary, id.clone(), PASSWORD, Adapter)?;
    let vault = Vesta::open(&path, PASSWORD)?;
    vault.with_connection(|c| {
        c.execute_batch(
            "CREATE TRIGGER reject_capacity_marker BEFORE UPDATE ON receipt_format BEGIN
                 SELECT RAISE(ABORT,'injected marker failure');
             END;",
        )?;
        Ok(())
    })?;
    assert!(node.upgrade_receipt_capacity().is_err());
    drop(node);
    vault.with_connection(|c| {
        let version: u32 = c.query_row("SELECT version FROM receipt_format", [], |r| r.get(0))?;
        assert_eq!(version, 1);
        let objects: u64 = c.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'receipt_capacity*'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(objects, 0);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn failed_v2_snapshot_finish_rolls_back_upgrade_and_v2_rejects_v1_manifest() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let id = identity();
    let mut primary = Node::open(
        dir.path().join("source-primary.db"),
        Role::Primary,
        id.clone(),
        PASSWORD,
        Adapter,
    )?;
    let mut secondary = Node::open(
        dir.path().join("source-secondary.db"),
        Role::Secondary,
        id.clone(),
        PASSWORD,
        Adapter,
    )?;
    commit(
        &mut primary,
        &mut secondary,
        request(&id, "snapshot-operation", "snapshot-value"),
    )?;
    primary.upgrade_receipt_capacity()?;
    secondary.upgrade_receipt_capacity()?;
    let manifest = primary.publish_snapshot()?;

    let target_path = dir.path().join("target.db");
    let mut target = Node::open(&target_path, Role::Secondary, id.clone(), PASSWORD, Adapter)?;
    target.begin_snapshot(&manifest)?;
    for position in 0..manifest.pages {
        let mut page = primary.snapshot_page(&manifest, position)?;
        if let Content::Receipts(receipts) = &mut page.content {
            receipts[0].request_digest = "0".repeat(64);
        }
        target.receive_snapshot(&page)?;
    }
    assert!(target.finish_snapshot(&manifest).is_err());
    drop(target);
    let vault = Vesta::open(&target_path, PASSWORD)?;
    vault.with_connection(|c| {
        let version: u32 = c.query_row("SELECT version FROM receipt_format", [], |r| r.get(0))?;
        assert_eq!(version, 1);
        let objects: u64 = c.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'receipt_capacity*'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(objects, 0);
        Ok(())
    })?;

    let upgraded_target_path = dir.path().join("upgraded-target.db");
    let mut upgraded_target =
        Node::open(upgraded_target_path, Role::Secondary, id, PASSWORD, Adapter)?;
    upgraded_target.upgrade_receipt_capacity()?;
    let mut legacy_manifest = manifest.clone();
    legacy_manifest.format = 1;
    assert!(upgraded_target.begin_snapshot(&legacy_manifest).is_err());
    Ok(())
}

/// Manual qualification harness; CI correctness runs do not treat timings as
/// assertions. Set VESTA_CAPACITY_PROFILE_RECEIPTS to the intended profile size.
#[test]
#[ignore = "manual capacity latency and storage profile"]
fn profile_format_two_capacity_paths() -> Result<()> {
    let receipts: u64 = std::env::var("VESTA_CAPACITY_PROFILE_RECEIPTS")
        .unwrap_or_else(|_| "10000".into())
        .parse()?;
    let dir = tempfile::tempdir()?;
    let primary_path = dir.path().join("profile-primary.db");
    let secondary_path = dir.path().join("profile-secondary.db");
    let id = identity();
    let mut primary = Node::open(&primary_path, Role::Primary, id.clone(), PASSWORD, Adapter)?;
    let mut secondary = Node::open(
        &secondary_path,
        Role::Secondary,
        id.clone(),
        PASSWORD,
        Adapter,
    )?;
    primary.upgrade_receipt_capacity()?;
    secondary.upgrade_receipt_capacity()?;
    let writes = std::time::Instant::now();
    for sequence in 0..receipts {
        commit(
            &mut primary,
            &mut secondary,
            request(
                &id,
                &format!("profile-{sequence}"),
                &format!("value-{sequence}"),
            ),
        )?;
    }
    let write_elapsed = writes.elapsed();
    let checkpoint = std::time::Instant::now();
    primary.checkpoint()?;
    let checkpoint_elapsed = checkpoint.elapsed();
    let audit = std::time::Instant::now();
    let capacity = primary.audit_snapshot_capacity()?;
    let audit_elapsed = audit.elapsed();
    let publish = std::time::Instant::now();
    let manifest = primary.publish_snapshot()?;
    let publish_elapsed = publish.elapsed();
    eprintln!(
        "receipts={receipts} receipt_bytes={} db_bytes={} wal_bytes={} pages={} write_total_ms={} checkpoint_ms={} audit_ms={} publish_ms={}",
        capacity.receipt_bytes,
        std::fs::metadata(&primary_path)?.len(),
        std::fs::metadata(primary_path.with_extension("db-wal")).map(|m| m.len()).unwrap_or(0),
        manifest.pages,
        write_elapsed.as_millis(),
        checkpoint_elapsed.as_millis(),
        audit_elapsed.as_millis(),
        publish_elapsed.as_millis(),
    );
    Ok(())
}
