//! Internal typed codec for the existing journal table. No DDL, transaction,
//! durability pragma, receipt, admission or state-transition ownership lives here.
//! Callers must bind the expected scope and validate the journal chain. Decoding
//! checks row keys and content integrity, not authenticated writer authority.
use crate::{ensure, Entry, Result};
use rusqlite::{params, Connection, OptionalExtension, Params, Row};
use serde::{de::DeserializeOwned, Serialize};

type Stored = (u64, String, String);

fn stored(row: &Row<'_>) -> rusqlite::Result<Stored> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
}

fn decode<C, S>((sequence, operation, json): Stored) -> Result<Entry<C, S>>
where
    C: DeserializeOwned + Serialize,
    S: DeserializeOwned + Serialize + PartialEq,
{
    let entry: Entry<C, S> = serde_json::from_str(&json)?;
    ensure(
        sequence > 0
            && !operation.is_empty()
            && entry.sequence == sequence
            && entry.batch.operation_id == operation,
        "stored journal key mismatch",
    )?;
    entry.validate(&entry.batch.identity)?;
    Ok(entry)
}

fn one<C, S>(c: &Connection, sql: &str, parameters: impl Params) -> Result<Option<Entry<C, S>>>
where
    C: DeserializeOwned + Serialize,
    S: DeserializeOwned + Serialize + PartialEq,
{
    c.query_row(sql, parameters, stored)
        .optional()?
        .map(decode)
        .transpose()
}

pub(crate) fn by_operation<C, S>(c: &Connection, id: &str) -> Result<Option<Entry<C, S>>>
where
    C: DeserializeOwned + Serialize,
    S: DeserializeOwned + Serialize + PartialEq,
{
    one(
        c,
        "SELECT sequence,operation_id,entry FROM replication_log WHERE operation_id=?1",
        [id],
    )
}

pub(crate) fn by_sequence<C, S>(c: &Connection, sequence: u64) -> Result<Option<Entry<C, S>>>
where
    C: DeserializeOwned + Serialize,
    S: DeserializeOwned + Serialize + PartialEq,
{
    one(
        c,
        "SELECT sequence,operation_id,entry FROM replication_log WHERE sequence=?1",
        [sequence],
    )
}

pub(crate) fn tail<C, S>(c: &Connection) -> Result<Option<Entry<C, S>>>
where
    C: DeserializeOwned + Serialize,
    S: DeserializeOwned + Serialize + PartialEq,
{
    one(
        c,
        "SELECT sequence,operation_id,entry FROM replication_log ORDER BY sequence DESC LIMIT 1",
        [],
    )
}

pub(crate) fn all<C, S>(c: &Connection) -> Result<Vec<Entry<C, S>>>
where
    C: DeserializeOwned + Serialize,
    S: DeserializeOwned + Serialize + PartialEq,
{
    let mut statement =
        c.prepare("SELECT sequence,operation_id,entry FROM replication_log ORDER BY sequence")?;
    let rows = statement.query_map([], stored)?;
    rows.map(|row| decode(row?)).collect()
}

/// One SQL statement, participating in any transaction already owned by caller.
/// Applied entries still need their receipts written in that same transaction.
pub(crate) fn write<C: Serialize, S: Serialize + PartialEq>(
    c: &Connection,
    e: &Entry<C, S>,
) -> Result<()> {
    ensure(
        e.sequence > 0 && e.sequence <= i64::MAX as u64 && !e.batch.operation_id.is_empty(),
        "invalid journal key",
    )?;
    e.validate(&e.batch.identity)?;
    let changed = c.execute(
        "INSERT INTO replication_log(sequence,operation_id,entry) VALUES(?1,?2,?3)
         ON CONFLICT(sequence) DO UPDATE SET entry=excluded.entry
         WHERE replication_log.operation_id=excluded.operation_id",
        params![e.sequence, e.batch.operation_id, serde_json::to_string(e)?],
    )?;
    ensure(
        changed == 1,
        "journal sequence belongs to another operation",
    )
}
