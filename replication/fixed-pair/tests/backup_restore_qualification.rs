use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};
use terrapi_vesta::Vesta;
use terrapi_vesta_replication::{
    commit, recover,
    schema::{RequestSchema, Schema, SchemaId},
    typed::{maintenance::compaction, Node, Request},
    Batch, Identity, Result, Role,
};

const PASSPHRASE: &str = "backup-restore-qualification";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum Change {
    Set { sku: String, quantity: i64 },
}

#[derive(Clone, Copy)]
struct Inventory;

impl Schema for Inventory {
    type Change = Change;
    type View = Vec<(String, i64)>;

    fn identity(&self) -> SchemaId {
        SchemaId {
            name: "qualification.inventory".into(),
            version: 1,
        }
    }

    fn tables(&self) -> &'static [&'static str] {
        &["qualification_stock"]
    }

    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS qualification_stock(
                sku TEXT PRIMARY KEY NOT NULL,
                quantity INTEGER NOT NULL CHECK(quantity >= 0)
            )",
        )?;
        Ok(())
    }

    fn execute(&self, c: &Connection, changes: &[Change]) -> Result<()> {
        for Change::Set { sku, quantity } in changes {
            c.execute(
                "INSERT INTO qualification_stock VALUES(?1,?2)
                 ON CONFLICT(sku) DO UPDATE SET quantity=excluded.quantity",
                params![sku, quantity],
            )?;
        }
        Ok(())
    }

    fn view(&self, c: &Connection) -> Result<Self::View> {
        Ok(
            c.prepare("SELECT sku,quantity FROM qualification_stock ORDER BY sku")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?,
        )
    }
}

impl RequestSchema for Inventory {
    const FINGERPRINT_VERSION: u32 = 1;

    fn request_fingerprint(&self, changes: &[Change]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"qualification.inventory.request-v1\0");
        digest.update((changes.len() as u64).to_be_bytes());
        for Change::Set { sku, quantity } in changes {
            digest.update((sku.len() as u64).to_be_bytes());
            digest.update(sku.as_bytes());
            digest.update(quantity.to_be_bytes());
        }
        digest.finalize().into()
    }
}

fn identity() -> Identity<SchemaId> {
    Identity {
        cluster: "qualification".into(),
        tenant: "backup-restore".into(),
        epoch: 1,
        schema: Inventory.identity(),
    }
}

fn request(
    identity: &Identity<SchemaId>,
    operation_id: &str,
    sku: &str,
    quantity: i64,
) -> Request<Inventory> {
    Batch {
        identity: identity.clone(),
        operation_id: operation_id.into(),
        changes: vec![Change::Set {
            sku: sku.into(),
            quantity,
        }],
    }
}

fn meta_path(path: &Path) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(".meta.json");
    value.into()
}

fn wal_path(path: &Path) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push("-wal");
    value.into()
}

fn ensure_no_uncheckpointed_wal(path: &Path) -> Result<()> {
    let wal = wal_path(path);
    if wal.exists() && fs::metadata(&wal)?.len() != 0 {
        return Err(format!(
            "stopped backup requires an empty or absent WAL: {}",
            wal.display()
        )
        .into());
    }
    Ok(())
}

/// Copy a cleanly closed Vesta database and its required key-slot sidecar.
/// This deliberately is not a live-database backup helper.
fn copy_stopped_vault(source: &Path, destination: &Path, passphrase: &str) -> Result<()> {
    ensure_no_uncheckpointed_wal(source)?;
    let vault = Vesta::open(source, passphrase)?;
    let (database, metadata) = (vault.path().to_owned(), vault.meta_path().to_owned());
    vault.lock();
    ensure_no_uncheckpointed_wal(source)?;
    fs::copy(database, destination)?;
    fs::copy(metadata, meta_path(destination))?;
    Ok(())
}

#[test]
fn nonempty_wal_is_rejected_before_backup_files_are_created() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("source.db");
    let destination = dir.path().join("destination.db");
    drop(Node::open(
        &source,
        Role::Primary,
        identity(),
        PASSPHRASE,
        Inventory,
    )?);
    fs::write(wal_path(&source), b"synthetic uncheckpointed WAL")?;

    let error = copy_stopped_vault(&source, &destination, PASSPHRASE)
        .expect_err("a nonempty WAL must block a DB-only backup");
    assert!(error
        .to_string()
        .contains("stopped backup requires an empty or absent WAL"));
    assert!(!destination.exists());
    assert!(!meta_path(&destination).exists());
    Ok(())
}

#[test]
fn stopped_pair_backup_restores_exact_retries_scope_and_passphrase_rewrap() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let source_primary = dir.path().join("source-primary.db");
    let source_secondary = dir.path().join("source-secondary.db");
    let restored_primary = dir.path().join("restored-primary.db");
    let restored_secondary = dir.path().join("restored-secondary.db");
    let id = identity();
    let first = request(&id, "operation-one", "widget", 3);
    let second = request(&id, "operation-two", "gadget", 7);

    let (
        expected_view,
        expected_checkpoint,
        expected_capacity,
        expected_receipts,
        expected_primary_progress,
        expected_secondary_progress,
    ) = {
        let mut primary = Node::open(
            &source_primary,
            Role::Primary,
            id.clone(),
            PASSPHRASE,
            Inventory,
        )?;
        let mut secondary = Node::open(
            &source_secondary,
            Role::Secondary,
            id.clone(),
            PASSPHRASE,
            Inventory,
        )?;
        commit(&mut primary, &mut secondary, first.clone())?;
        commit(&mut primary, &mut secondary, second.clone())?;
        primary.enable_maintenance()?;
        secondary.enable_maintenance()?;
        primary.publish_snapshot()?;
        secondary.publish_snapshot()?;
        let plan = compaction::plan_pair(&primary, &secondary)?;
        compaction::compact_pair(&mut primary, &mut secondary, &plan)?;
        assert_eq!(primary.checkpoint()?, secondary.checkpoint()?);
        assert_eq!(
            primary.journal_head()?.base.as_ref(),
            Some(&primary.checkpoint()?)
        );
        assert_eq!(
            secondary.journal_head()?.base.as_ref(),
            Some(&secondary.checkpoint()?)
        );
        (
            primary.view()?,
            primary.checkpoint()?,
            primary.snapshot_capacity()?,
            vec![
                primary.receipt(&first.operation_id)?.unwrap(),
                primary.receipt(&second.operation_id)?.unwrap(),
            ],
            primary.compaction_progress()?.unwrap(),
            secondary.compaction_progress()?.unwrap(),
        )
    };

    // Both Node handles are dropped before either file is copied. The source pair is
    // advanced and stopped separately before the restored pair is exercised below;
    // the two pairs are never joined or open concurrently.
    copy_stopped_vault(&source_primary, &restored_primary, PASSPHRASE)?;
    copy_stopped_vault(&source_secondary, &restored_secondary, PASSPHRASE)?;

    // Prove that this is a point-in-time clone, not rollback protection. The
    // source pair is advanced and stopped again before the restored pair opens.
    let source_advanced_checkpoint = {
        let mut primary = Node::open(
            &source_primary,
            Role::Primary,
            id.clone(),
            PASSPHRASE,
            Inventory,
        )?;
        let mut secondary = Node::open(
            &source_secondary,
            Role::Secondary,
            id.clone(),
            PASSPHRASE,
            Inventory,
        )?;
        commit(
            &mut primary,
            &mut secondary,
            request(&id, "operation-after-backup", "later", 11),
        )?;
        primary.checkpoint()?
    };
    assert_ne!(source_advanced_checkpoint, expected_checkpoint);

    assert!(Node::open(
        &restored_primary,
        Role::Primary,
        id.clone(),
        "wrong passphrase",
        Inventory,
    )
    .is_err());
    let mut wrong_scope = id.clone();
    wrong_scope.tenant = "another-tenant".into();
    assert!(Node::open(
        &restored_primary,
        Role::Primary,
        wrong_scope,
        PASSPHRASE,
        Inventory,
    )
    .is_err());

    // Root Vesta supports passphrase rotation by re-wrapping the stable DEK.
    // Exercise it only while this restored primary is stopped.
    let mut vault = Vesta::open(&restored_primary, PASSPHRASE)?;
    vault.rotate_key(PASSPHRASE, "rotated-backup-passphrase")?;
    vault.lock();
    assert!(Vesta::open(&restored_primary, PASSPHRASE).is_err());

    let mut primary = Node::open(
        &restored_primary,
        Role::Primary,
        id.clone(),
        "rotated-backup-passphrase",
        Inventory,
    )?;
    let mut secondary = Node::open(
        &restored_secondary,
        Role::Secondary,
        id.clone(),
        PASSPHRASE,
        Inventory,
    )?;
    recover(&mut primary, &mut secondary)?;
    assert_eq!(primary.view()?, expected_view);
    assert_eq!(secondary.verified_view()?.unwrap(), expected_view);
    assert_eq!(primary.checkpoint()?, expected_checkpoint);
    assert_eq!(secondary.checkpoint()?, expected_checkpoint);
    assert_eq!(primary.snapshot_capacity()?, expected_capacity);
    assert_eq!(secondary.snapshot_capacity()?, expected_capacity);
    assert_eq!(
        primary.compaction_progress()?.unwrap(),
        expected_primary_progress
    );
    assert_eq!(
        secondary.compaction_progress()?.unwrap(),
        expected_secondary_progress
    );
    assert_eq!(
        primary.journal_head()?.base.as_ref(),
        Some(&expected_checkpoint)
    );
    assert_eq!(
        secondary.journal_head()?.base.as_ref(),
        Some(&expected_checkpoint)
    );
    assert_eq!(
        primary.receipt(&first.operation_id)?.unwrap(),
        expected_receipts[0]
    );
    assert_eq!(
        primary.receipt(&second.operation_id)?.unwrap(),
        expected_receipts[1]
    );

    let retry = commit(&mut primary, &mut secondary, first.clone())?;
    assert_eq!(retry, expected_receipts[0].result);
    let conflict = request(&id, &first.operation_id, "widget", 99);
    assert!(commit(&mut primary, &mut secondary, conflict).is_err());
    assert_eq!(primary.view()?, expected_view);
    assert_eq!(primary.checkpoint()?, expected_checkpoint);
    Ok(())
}

#[test]
fn corrupt_or_truncated_stopped_copy_fails_closed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("source.db");
    let truncated = dir.path().join("truncated.db");
    let missing_metadata = dir.path().join("missing-metadata.db");
    let damaged_metadata = dir.path().join("damaged-metadata.db");
    let id = identity();
    drop(Node::open(
        &source,
        Role::Primary,
        id.clone(),
        PASSPHRASE,
        Inventory,
    )?);

    copy_stopped_vault(&source, &truncated, PASSPHRASE)?;
    let file = OpenOptions::new().write(true).open(&truncated)?;
    file.set_len(fs::metadata(&truncated)?.len() / 2)?;
    drop(file);
    assert!(Node::open(&truncated, Role::Primary, id.clone(), PASSPHRASE, Inventory,).is_err());

    fs::copy(&source, &missing_metadata)?;
    assert!(Node::open(
        &missing_metadata,
        Role::Primary,
        id.clone(),
        PASSPHRASE,
        Inventory,
    )
    .is_err());

    copy_stopped_vault(&source, &damaged_metadata, PASSPHRASE)?;
    fs::write(meta_path(&damaged_metadata), b"{\"format_version\":999}")?;
    assert!(Node::open(&damaged_metadata, Role::Primary, id, PASSPHRASE, Inventory,).is_err());
    Ok(())
}
