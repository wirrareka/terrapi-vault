//! Application-owned SQL schemas and transactional changeset capture/replay.
//!
//! Adapters are trusted code, not a sandbox for user-supplied SQL. They must not
//! commit transactions, change connection pragmas, perform DDL during execution,
//! write outside their declared tables, or perform external side effects.
//! Every declared table needs an explicit non-null primary key. `view` must cover
//! all replicated state in deterministic order, preserving every SQL value.
//! Schema identities describe immutable contracts; migrations require a separate
//! coordinated protocol. These helpers do not provide durable decisions or ACKs.
use crate::{ensure, hash, Result};
use rusqlite::{
    session::{ConflictAction, ConflictType, Session},
    Connection, Transaction,
};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaId {
    pub name: String,
    pub version: u32,
}

pub trait Schema {
    type Change;
    type View: Serialize + PartialEq;
    fn identity(&self) -> SchemaId;
    /// Lowercase SQL identifiers, in a stable order. Never protocol tables.
    fn tables(&self) -> &'static [&'static str];
    /// Idempotent DDL only; called explicitly, never during changeset replay.
    fn initialize(&self, connection: &Connection) -> Result<()>;
    fn execute(&self, connection: &Connection, changes: &[Self::Change]) -> Result<()>;
    fn view(&self, connection: &Connection) -> Result<Self::View>;
}

/// Application-owned identity of a request, independent of its resulting state.
///
/// Implementations must use a stable, domain-separated, unambiguous encoding of
/// the ordered changes. A change of encoding requires a new nonzero version and
/// an explicit receipt migration policy; never reinterpret stored receipts.
/// Tenant, epoch and operation ID are separately enforced by the host protocol.
/// Equal resulting SQL state is not sufficient to identify equal requests.
/// There is deliberately no default based on `Debug` or arbitrary JSON maps.
pub trait RequestSchema: Schema {
    const FINGERPRINT_VERSION: u32;
    fn request_fingerprint(&self, changes: &[Self::Change]) -> [u8; 32];
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Captured {
    pub schema: SchemaId,
    pub before: String,
    pub after: String,
    pub changeset: Vec<u8>,
}

fn descriptor<S: Schema>(schema: &S) -> Result<()> {
    let id = schema.identity();
    ensure(
        !id.name.is_empty()
            && id.name.len() <= 128
            && id.version > 0
            && id
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid SQL schema identity",
    )?;
    let tables = schema.tables();
    ensure(
        !tables.is_empty() && tables.len() <= 128,
        "invalid SQL table count",
    )?;
    for (i, table) in tables.iter().enumerate() {
        ensure(
            !table.is_empty()
                && table.len() <= 128
                && table.as_bytes()[0].is_ascii_lowercase()
                && table
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                && !tables[..i].contains(table)
                && ![
                    "sqlite_",
                    "checkpoint_",
                    "receipt_",
                    "node_",
                    "replication_",
                    "operation_",
                    "published_",
                    "materialized_",
                    "snapshot_",
                    "recovery_",
                ]
                .iter()
                .any(|prefix| table.starts_with(prefix)),
            "invalid/reserved SQL table name",
        )?;
    }
    Ok(())
}

pub(crate) fn validate<S: Schema>(c: &Connection, schema: &S) -> Result<()> {
    descriptor(schema)?;
    let foreign_keys: bool = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
    ensure(foreign_keys, "SQL schema requires foreign_keys=ON")?;
    for table in schema.tables() {
        let sql: String = c.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |r| r.get(0),
        )?;
        ensure(
            !sql.to_ascii_uppercase().contains("CREATE VIRTUAL TABLE"),
            "virtual tables unsupported",
        )?;
        let keys = c
            .prepare("SELECT name,\"notnull\" FROM pragma_table_info(?1) WHERE pk>0")?
            .query_map([table], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure(
            !keys.is_empty() && keys.iter().all(|(_, not_null)| *not_null),
            "replicated table requires explicit non-null primary key",
        )?;
    }
    Ok(())
}

pub(crate) fn foreign_key_check(c: &Connection) -> Result<()> {
    let bad: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    ensure(!bad, "SQL foreign key violation")
}

/// Initialize an application schema atomically. Not a migration/adoption API.
pub fn initialize<S: Schema>(c: &Connection, schema: &S) -> Result<()> {
    descriptor(schema)?;
    let tx = c.unchecked_transaction()?;
    schema.initialize(&tx)?;
    validate(&tx, schema)?;
    foreign_key_check(&tx)?;
    tx.commit()?;
    Ok(())
}

/// Preview a request inside a rolled-back transaction. No application data is committed.
pub fn capture<S: Schema>(c: &Connection, schema: &S, changes: &[S::Change]) -> Result<Captured> {
    let tx = c.unchecked_transaction()?;
    validate(&tx, schema)?;
    let before = hash(&schema.view(&tx)?)?;
    let mut session = Session::new(&tx)?;
    for table in schema.tables() {
        session.attach(Some(table))?;
    }
    schema.execute(&tx, changes)?;
    foreign_key_check(&tx)?;
    let after = hash(&schema.view(&tx)?)?;
    let mut changeset = Vec::new();
    session.changeset_strm(&mut changeset)?;
    drop(session);
    tx.rollback()?;
    Ok(Captured {
        schema: schema.identity(),
        before,
        after,
        changeset,
    })
}

/// Apply atomically after validating schema, before/after state and table allowlist.
/// The caller must authenticate/bind the envelope and provide durable commit authority.
/// This low-level operation is deliberately not an idempotent two-copy write API.
pub fn replay<S: Schema>(c: &Connection, schema: &S, captured: &Captured) -> Result<()> {
    let tx = c.unchecked_transaction()?;
    replay_in(&tx, schema, captured)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn replay_in<S: Schema>(
    tx: &Transaction<'_>,
    schema: &S,
    captured: &Captured,
) -> Result<()> {
    replay_data(
        tx,
        schema,
        &captured.schema,
        &captured.before,
        &captured.after,
        &captured.changeset,
    )
}

pub(crate) fn replay_data<S: Schema>(
    tx: &Transaction<'_>,
    schema: &S,
    identity: &SchemaId,
    before: &str,
    after: &str,
    changeset: &[u8],
) -> Result<()> {
    validate(tx, schema)?;
    ensure(
        *identity == schema.identity(),
        "SQL schema identity mismatch",
    )?;
    ensure(hash(&schema.view(tx)?)? == before, "base state mismatch")?;
    let tables = schema.tables();
    let rejected = Arc::new(AtomicBool::new(false));
    let flag = rejected.clone();
    tx.apply_strm(
        &mut &changeset[..],
        Some(move |table: &str| {
            let allowed = tables.contains(&table);
            if !allowed {
                flag.store(true, Ordering::Relaxed);
            }
            allowed
        }),
        |kind, _| {
            // A cascading delete may precede an explicit row delete. Exact whole-state
            // hashes still bind the result; all other conflicts abort.
            if kind == ConflictType::SQLITE_CHANGESET_NOTFOUND {
                ConflictAction::SQLITE_CHANGESET_OMIT
            } else {
                ConflictAction::SQLITE_CHANGESET_ABORT
            }
        },
    )?;
    ensure(
        !rejected.load(Ordering::Relaxed),
        "changeset contains undeclared SQL table",
    )?;
    foreign_key_check(tx)?;
    ensure(
        hash(&schema.view(tx)?)? == after,
        "post-apply state mismatch",
    )
}
