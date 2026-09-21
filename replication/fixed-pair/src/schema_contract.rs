//! Immutable application adapter contract. A digest is not writer authority.
use crate::{
    ensure, hash,
    schema::{self, RequestSchema, SchemaId},
    Result,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub format: u32,
    pub schema: SchemaId,
    pub fingerprint_version: u32,
    pub catalog_digest: String,
}

/// Describe the actual application catalog, not protocol tables or application data.
/// Exact DDL and table ordering are part of the immutable contract. Adapter code,
/// collations and custom functions remain trusted and cannot be hashed by this API.
pub fn describe<S: RequestSchema>(c: &Connection, adapter: &S) -> Result<Contract> {
    schema::validate(c, adapter)?;
    ensure(
        S::FINGERPRINT_VERSION > 0,
        "invalid request fingerprint version",
    )?;
    let temporary: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type IN ('table','view','trigger'))",
        [],
        |r| r.get(0),
    )?;
    ensure(!temporary, "temporary schema objects cannot be bound")?;
    let mut definitions = Vec::new();
    for name in adapter.tables() {
        let ddl = c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE lower(tbl_name)=?1 ORDER BY type,name")?
            .query_map([name], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        definitions.push((name, ddl));
    }
    Ok(Contract {
        format: 1,
        schema: adapter.identity(),
        fingerprint_version: S::FINGERPRINT_VERSION,
        catalog_digest: hash(&definitions)?,
    })
}

/// Build the expected contract from trusted adapter DDL in an isolated in-memory
/// database. Do not derive the expected contract from the database being admitted.
pub fn expected<S: RequestSchema>(adapter: &S) -> Result<Contract> {
    let c = Connection::open_in_memory()?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    schema::initialize(&c, adapter)?;
    describe(&c, adapter)
}

pub(crate) fn exists(c: &Connection) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='node_schema_contract')",
        [],
        |r| r.get(0),
    )?)
}

pub(crate) fn verify<S: RequestSchema>(
    c: &Connection,
    adapter: &S,
    expected: &Contract,
) -> Result<()> {
    ensure(
        describe(c, adapter)? == *expected,
        "application schema contract mismatch",
    )?;
    let count: u32 = c.query_row("SELECT count(*) FROM node_schema_contract", [], |r| {
        r.get(0)
    })?;
    ensure(count == 1, "missing/ambiguous persisted schema contract")?;
    let stored: String = c.query_row(
        "SELECT contract FROM node_schema_contract WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    ensure(
        stored == serde_json::to_string(expected)?,
        "persisted schema contract mismatch",
    )
}

/// Called only after the owning Node has validated identity and existing history.
/// Never repair an existing table or rewrite a contract, even if it is empty.
pub(crate) fn install<S: RequestSchema>(
    c: &Connection,
    adapter: &S,
    expected: &Contract,
) -> Result<()> {
    let tx = c.unchecked_transaction()?;
    ensure(
        describe(&tx, adapter)? == *expected,
        "application schema contract mismatch",
    )?;
    tx.execute_batch("CREATE TABLE node_schema_contract(id INTEGER PRIMARY KEY CHECK(id=1),contract TEXT NOT NULL)")?;
    tx.execute(
        "INSERT INTO node_schema_contract VALUES(1,?1)",
        [serde_json::to_string(expected)?],
    )?;
    verify(&tx, adapter, expected)?;
    tx.commit()?;
    Ok(())
}
