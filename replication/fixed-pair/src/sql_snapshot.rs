//! Versioned, schema-neutral SQL snapshots and bounded page codecs.
//!
//! This is an application-data transfer primitive, not a commit/membership protocol.
//! Callers authenticate the manifest and peer, fence writers, and keep read admission
//! closed until completion. Protocol receipts and recovery authority are not exported.
//! Use a Vesta-owned connection to keep staging encrypted at rest.
pub mod transport;
use crate::{
    ensure, hash,
    schema::{self, Schema, SchemaId},
    Result,
};
use rusqlite::{
    params, params_from_iter,
    types::{Value, ValueRef},
    Connection, OptionalExtension,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_ROWS: u64 = 100_000;
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ROW_BYTES: usize = 256 * 1024;
pub const MAX_PAGE_BYTES: usize = 1024 * 1024;
pub const MAX_PAGE_ROWS: usize = 256;
pub const MAX_MANIFEST_BYTES: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub cluster: String,
    pub tenant: String,
    pub epoch: u64,
    pub schema: SchemaId,
}
impl Scope {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure(
            self.epoch > 0
                && self.schema.version > 0
                && !self.schema.name.is_empty()
                && self.schema.name.len() <= 128
                && self
                    .schema
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && [&self.cluster, &self.tenant]
                    .iter()
                    .all(|s| !s.trim().is_empty() && s.len() <= 256),
            "invalid snapshot scope",
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SqlValue {
    Null,
    Integer(i64),
    RealBits(u64),
    Text(String),
    Blob(Vec<u8>),
}
impl SqlValue {
    fn read(v: ValueRef<'_>) -> Result<Self> {
        Ok(match v {
            ValueRef::Null => Self::Null,
            ValueRef::Integer(n) => Self::Integer(n),
            ValueRef::Real(n) => Self::RealBits(n.to_bits()),
            ValueRef::Text(s) => {
                ensure(s.len() <= MAX_ROW_BYTES, "snapshot cell too large")?;
                Self::Text(std::str::from_utf8(s)?.into())
            }
            ValueRef::Blob(b) => {
                ensure(b.len() <= MAX_ROW_BYTES, "snapshot cell too large")?;
                Self::Blob(b.into())
            }
        })
    }
    fn sql(&self) -> Result<Value> {
        Ok(match self {
            Self::Null => Value::Null,
            Self::Integer(n) => Value::Integer(*n),
            Self::RealBits(b) => {
                let n = f64::from_bits(*b);
                ensure(!n.is_nan(), "NaN cannot roundtrip through SQLite")?;
                Value::Real(n)
            }
            Self::Text(s) => Value::Text(s.clone()),
            Self::Blob(b) => Value::Blob(b.clone()),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub table: u32,
    pub values: Vec<SqlValue>,
}
fn row_json(row: &Row) -> Result<String> {
    ensure(
        !row.values.is_empty() && row.values.len() <= 256,
        "invalid snapshot column count",
    )?;
    let json = serde_json::to_string(row)?;
    ensure(json.len() <= MAX_ROW_BYTES, "snapshot row too large")?;
    Ok(json)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub scope: Scope,
    pub catalog_digest: String,
    pub state_digest: String,
    pub rows: u64,
    pub bytes: u64,
    pub content_digest: String,
}
impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "SQL snapshot manifest exceeds wire limit",
        )?;
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "SQL snapshot manifest exceeds wire limit",
        )?;
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }
    pub fn digest(&self) -> Result<String> {
        hash(self)
    }
    fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        ensure(
            self.format == 1
                && self.rows <= MAX_ROWS
                && self.bytes <= MAX_BYTES
                && (self.rows == 0) == (self.bytes == 0)
                && self.bytes >= self.rows
                && [
                    &self.catalog_digest,
                    &self.state_digest,
                    &self.content_digest,
                ]
                .iter()
                .all(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                }),
            "invalid SQL snapshot manifest",
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub format: u32,
    pub manifest_digest: String,
    pub offset: u64,
    pub rows: Vec<Row>,
}
impl Page {
    fn validate(&self) -> Result<()> {
        ensure(
            self.format == 1
                && !self.rows.is_empty()
                && self.rows.len() <= MAX_PAGE_ROWS
                && self.offset <= MAX_ROWS
                && self.rows.len() as u64 <= MAX_ROWS - self.offset
                && self.manifest_digest.len() == 64
                && self
                    .manifest_digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "invalid SQL snapshot page",
        )?;
        for row in &self.rows {
            row_json(row)?;
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure(
            bytes.len() <= MAX_PAGE_BYTES,
            "SQL snapshot page exceeds wire limit",
        )?;
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure(
            bytes.len() <= MAX_PAGE_BYTES,
            "SQL snapshot page exceeds wire limit",
        )?;
        let page: Self = serde_json::from_slice(bytes)?;
        page.validate()?;
        Ok(page)
    }
}
pub struct Export {
    pub manifest: Manifest,
    rows: Vec<Row>,
}
impl Export {
    pub fn pages(&self, rows_per_page: usize) -> Result<Vec<Page>> {
        ensure(
            rows_per_page > 0 && rows_per_page <= MAX_PAGE_ROWS,
            "invalid page row limit",
        )?;
        let mut pages = Vec::new();
        let mut offset = 0;
        while offset < self.rows.len() {
            let mut bytes = 512;
            let mut rows = Vec::new();
            for row in self.rows[offset..].iter().take(rows_per_page) {
                let len = row_json(row)?.len() + 1;
                if bytes + len > MAX_PAGE_BYTES {
                    break;
                }
                bytes += len;
                rows.push(row.clone());
            }
            let page = Page {
                format: 1,
                manifest_digest: self.manifest.digest()?,
                offset: offset as u64,
                rows,
            };
            page.encode()?;
            offset += page.rows.len();
            pages.push(page);
        }
        Ok(pages)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub manifest: Manifest,
    pub received: u64,
    pub bytes: u64,
    pub complete: bool,
}

struct Table {
    name: String,
    columns: Vec<String>,
    keys: Vec<String>,
}
fn quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}
fn durability(c: &Connection) -> Result<()> {
    let synchronous: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    let journal: String = c.query_row("PRAGMA main.journal_mode", [], |r| r.get(0))?;
    let file: String = c.query_row(
        "SELECT file FROM pragma_database_list WHERE name='main'",
        [],
        |r| r.get(0),
    )?;
    let temp_store: i64 = c.query_row("PRAGMA temp_store", [], |r| r.get(0))?;
    ensure(
        matches!(synchronous, 2 | 3),
        "SQL snapshot requires synchronous=FULL or EXTRA; rebind after reopen",
    )?;
    ensure(
        matches!(journal.as_str(), "wal" | "delete" | "truncate" | "persist")
            || (journal == "memory" && file.is_empty()),
        "SQL snapshot requires transactional journaling",
    )?;
    ensure(
        file.is_empty() || temp_store == 2,
        "persistent SQL snapshots require temp_store=MEMORY",
    )
}
fn catalog<S: Schema>(c: &Connection, schema: &S) -> Result<(Vec<Table>, String)> {
    durability(c)?;
    schema::validate(c, schema)?;
    let temp_objects: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type IN ('table','view','trigger'))",
        [],
        |r| r.get(0),
    )?;
    ensure(
        !temp_objects,
        "temporary tables/views/triggers unsupported by SQL snapshots",
    )?;
    let mut tables = Vec::new();
    let mut definitions = Vec::new();
    for name in schema.tables() {
        let triggers:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='trigger' AND lower(tbl_name)=?1)",[name],|r|r.get(0))?;
        ensure(!triggers, "trigger tables unsupported by SQL snapshots")?;
        let columns = c
            .prepare("SELECT name,pk,hidden FROM pragma_table_xinfo(?1) ORDER BY cid")?
            .query_map([name], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, u32>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure(
            !columns.is_empty() && columns.len() <= 256 && columns.iter().all(|x| x.2 == 0),
            "generated/hidden columns unsupported by SQL snapshots",
        )?;
        let foreign = c
            .prepare("SELECT \"table\" FROM pragma_foreign_key_list(?1)")?
            .query_map([name], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure(
            foreign
                .iter()
                .all(|t| schema.tables().contains(&t.as_str())),
            "snapshot foreign key escapes schema",
        )?;
        let mut keys: Vec<_> = columns.iter().filter(|x| x.1 > 0).collect();
        keys.sort_by_key(|x| x.1);
        tables.push(Table {
            name: (*name).into(),
            columns: columns.iter().map(|x| x.0.clone()).collect(),
            keys: keys.iter().map(|x| x.0.clone()).collect(),
        });
        let ddl=c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE lower(tbl_name)=?1 ORDER BY type,name")?
            .query_map([name],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure(
            !ddl.iter().any(|(_, _, sql)| {
                sql.as_ref()
                    .is_some_and(|s| s.to_ascii_uppercase().contains("AUTOINCREMENT"))
            }),
            "AUTOINCREMENT sequence state unsupported by SQL snapshots",
        )?;
        definitions.push((name, ddl));
    }
    Ok((tables, hash(&definitions)?))
}
fn empty(c: &Connection, tables: &[Table]) -> Result<()> {
    for table in tables {
        let occupied: bool = c.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {})", quoted(&table.name)),
            [],
            |r| r.get(0),
        )?;
        ensure(!occupied, "SQL snapshot target must be empty")?;
    }
    Ok(())
}
fn metadata_present(c: &Connection) -> Result<bool> {
    let count: u32 = c.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('snapshot_sql_binding','snapshot_sql_progress','snapshot_sql_rows')",
        [], |r| r.get(0))?;
    ensure(count == 0 || count == 3, "incomplete SQL snapshot metadata")?;
    Ok(count == 3)
}

fn binding<S: Schema>(c: &Connection, schema: &S, scope: &Scope) -> Result<(Vec<Table>, String)> {
    ensure(metadata_present(c)?, "missing SQL snapshot metadata")?;
    scope.validate()?;
    ensure(
        scope.schema == schema.identity(),
        "SQL snapshot schema mismatch",
    )?;
    let stored: String = c.query_row(
        "SELECT binding FROM snapshot_sql_binding WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let (tables, digest) = catalog(c, schema)?;
    ensure(
        stored == serde_json::to_string(&(1u32, scope, &digest))?,
        "persisted SQL snapshot binding mismatch",
    )?;
    Ok((tables, digest))
}
/// Bind only a new empty application database, or reopen its exact existing binding.
/// Does not authorize an epoch change or adopt an existing populated database.
/// Selects synchronous=FULL (preserving EXTRA) on this exclusively owned connection. Call again after
/// reopening Vesta (whose general-purpose default is NORMAL). Other operations reject
/// a weakened profile; no root Vesta defaults are changed.
pub fn bind<S: Schema>(c: &Connection, schema: &S, scope: &Scope) -> Result<()> {
    scope.validate()?;
    ensure(
        scope.schema == schema.identity(),
        "SQL snapshot schema mismatch",
    )?;
    ensure(
        c.is_autocommit(),
        "SQL snapshot bind requires its own transaction",
    )?;
    let synchronous: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    if synchronous < 2 {
        c.pragma_update(None, "synchronous", "FULL")?;
    }
    let tx = c.unchecked_transaction()?;
    let (tables, digest) = catalog(&tx, schema)?;
    let existing = metadata_present(&tx)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS snapshot_sql_binding(id INTEGER PRIMARY KEY CHECK(id=1),binding TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS snapshot_sql_progress(id INTEGER PRIMARY KEY CHECK(id=1),progress TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS snapshot_sql_rows(position INTEGER PRIMARY KEY,row TEXT NOT NULL);")?;
    let stored: Option<String> = tx
        .query_row(
            "SELECT binding FROM snapshot_sql_binding WHERE id=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let expected = serde_json::to_string(&(1u32, scope, digest))?;
    if let Some(stored) = stored {
        ensure(
            stored == expected,
            "persisted SQL snapshot binding mismatch",
        )?;
    } else {
        ensure(!existing, "missing persisted SQL snapshot binding")?;
        empty(&tx, &tables)?;
        let orphan:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM snapshot_sql_progress) OR EXISTS(SELECT 1 FROM snapshot_sql_rows)",[],|r|r.get(0))?;
        ensure(!orphan, "orphan SQL snapshot staging")?;
        tx.execute("INSERT INTO snapshot_sql_binding VALUES(1,?1)", [expected])?;
    }
    tx.commit()?;
    Ok(())
}
pub(crate) fn verify_binding<S: Schema>(c: &Connection, schema: &S, scope: &Scope) -> Result<()> {
    binding(c, schema, scope).map(|_| ())
}
pub(crate) fn progress(c: &Connection) -> Result<Option<Progress>> {
    let json: Option<String> = c
        .query_row(
            "SELECT progress FROM snapshot_sql_progress WHERE id=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    json.map(|s| {
        let p: Progress = serde_json::from_str(&s)?;
        p.manifest.validate()?;
        ensure(
            p.received <= p.manifest.rows
                && p.bytes <= p.manifest.bytes
                && (!p.complete || (p.received == p.manifest.rows && p.bytes == p.manifest.bytes)),
            "invalid SQL snapshot progress",
        )?;
        Ok(p)
    })
    .transpose()
}
fn save(c: &Connection, p: &Progress) -> Result<()> {
    c.execute("INSERT INTO snapshot_sql_progress VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET progress=excluded.progress",[serde_json::to_string(p)?])?;
    Ok(())
}
fn digest_start() -> Sha256 {
    let mut h = Sha256::new();
    h.update(b"vesta-sql-snapshot-rows-v1\0");
    h
}
fn digest_row(h: &mut Sha256, json: &str) {
    h.update((json.len() as u64).to_be_bytes());
    h.update(json.as_bytes());
}
fn visit(c: &Connection, tables: &[Table], mut f: impl FnMut(Row) -> Result<()>) -> Result<()> {
    for (i, t) in tables.iter().enumerate() {
        let sql = format!(
            "SELECT {} FROM {} ORDER BY {}",
            t.columns
                .iter()
                .map(|s| quoted(s))
                .collect::<Vec<_>>()
                .join(","),
            quoted(&t.name),
            t.keys
                .iter()
                .map(|s| quoted(s))
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut stmt = c.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let mut values = Vec::with_capacity(t.columns.len());
            let mut bytes = 0;
            for n in 0..t.columns.len() {
                let value = SqlValue::read(row.get_ref(n)?)?;
                bytes += serde_json::to_vec(&value)?.len();
                ensure(bytes <= MAX_ROW_BYTES, "snapshot row too large")?;
                values.push(value);
            }
            f(Row {
                table: i as u32,
                values,
            })?;
        }
    }
    Ok(())
}
pub fn export<S: Schema>(c: &Connection, schema: &S, scope: &Scope) -> Result<Export> {
    let tx = c.unchecked_transaction()?;
    let export = export_in(&tx, schema, scope)?;
    tx.rollback()?;
    Ok(export)
}
pub(crate) fn export_in<S: Schema>(
    tx: &rusqlite::Transaction<'_>,
    schema: &S,
    scope: &Scope,
) -> Result<Export> {
    let mut rows = Vec::new();
    let manifest = scan_in(tx, schema, scope, |row| {
        rows.push(row);
        Ok(())
    })?;
    Ok(Export { manifest, rows })
}

/// Scan the exact snapshot encoding without retaining all encoded rows in memory.
/// The schema's view implementation may still allocate the complete logical view.
/// The caller owns the read transaction, including when inspecting a dry run.
pub(crate) fn scan_in<S: Schema>(
    tx: &rusqlite::Transaction<'_>,
    schema: &S,
    scope: &Scope,
    mut consume: impl FnMut(Row) -> Result<()>,
) -> Result<Manifest> {
    let (tables, catalog_digest) = binding(tx, schema, scope)?;
    ensure(
        progress(tx)?.is_none_or(|p| p.complete),
        "SQL snapshot receive in progress",
    )?;
    schema::foreign_key_check(tx)?;
    let mut count = 0u64;
    let mut bytes = 0;
    let mut digest = digest_start();
    visit(tx, &tables, |row| {
        let json = row_json(&row)?;
        bytes += json.len() as u64;
        ensure(
            count < MAX_ROWS && bytes <= MAX_BYTES,
            "SQL snapshot quota exceeded",
        )?;
        digest_row(&mut digest, &json);
        count += 1;
        consume(row)?;
        Ok(())
    })?;
    let manifest = Manifest {
        format: 1,
        scope: scope.clone(),
        catalog_digest,
        state_digest: hash(&schema.view(tx)?)?,
        rows: count,
        bytes,
        content_digest: format!("{:x}", digest.finalize()),
    };
    manifest.validate()?;
    Ok(manifest)
}
pub fn begin<S: Schema>(
    c: &Connection,
    schema: &S,
    scope: &Scope,
    manifest: &Manifest,
) -> Result<Progress> {
    manifest.validate()?;
    let tx = c.unchecked_transaction()?;
    let (tables, catalog_digest) = binding(&tx, schema, scope)?;
    ensure(
        manifest.scope == *scope && manifest.catalog_digest == catalog_digest,
        "SQL snapshot manifest binding mismatch",
    )?;
    if let Some(p) = progress(&tx)? {
        ensure(p.manifest == *manifest, "SQL snapshot slot occupied")?;
        if p.complete {
            verify_live(&tx, schema, &tables, &p.manifest)?;
        }
        return Ok(p);
    }
    empty(&tx, &tables)?;
    let count: u64 = tx.query_row("SELECT count(*) FROM snapshot_sql_rows", [], |r| r.get(0))?;
    ensure(count == 0, "orphan SQL snapshot rows")?;
    let p = Progress {
        manifest: manifest.clone(),
        received: 0,
        bytes: 0,
        complete: false,
    };
    save(&tx, &p)?;
    tx.commit()?;
    Ok(p)
}
pub fn receive<S: Schema>(
    c: &Connection,
    schema: &S,
    scope: &Scope,
    page: &Page,
) -> Result<Progress> {
    page.encode()?;
    let tx = c.unchecked_transaction()?;
    let (tables, catalog_digest) = binding(&tx, schema, scope)?;
    let mut p = progress(&tx)?.ok_or("no SQL snapshot transfer")?;
    ensure(
        p.manifest.scope == *scope
            && p.manifest.catalog_digest == catalog_digest
            && page.manifest_digest == p.manifest.digest()?,
        "SQL snapshot page binding mismatch",
    )?;
    let end = page.offset + page.rows.len() as u64;
    ensure(
        end <= p.manifest.rows && page.offset <= p.received,
        "out-of-order SQL snapshot page",
    )?;
    if page.offset < p.received {
        ensure(end <= p.received, "partial SQL snapshot retry overlap")?;
        for (i, row) in page.rows.iter().enumerate() {
            let stored: String = tx.query_row(
                "SELECT row FROM snapshot_sql_rows WHERE position=?1",
                [page.offset + i as u64],
                |r| r.get(0),
            )?;
            ensure(stored == row_json(row)?, "conflicting SQL snapshot retry")?;
        }
        if p.complete {
            verify_live(&tx, schema, &tables, &p.manifest)?;
        }
        return Ok(p);
    }
    ensure(!p.complete, "SQL snapshot already complete")?;
    empty(&tx, &tables)?;
    for (i, row) in page.rows.iter().enumerate() {
        let table = tables
            .get(row.table as usize)
            .ok_or("unknown SQL snapshot table")?;
        ensure(
            row.values.len() == table.columns.len(),
            "SQL snapshot row width mismatch",
        )?;
        for value in &row.values {
            value.sql()?;
        }
        let json = row_json(row)?;
        p.bytes += json.len() as u64;
        ensure(
            p.bytes <= p.manifest.bytes,
            "SQL snapshot byte count exceeded",
        )?;
        tx.execute(
            "INSERT INTO snapshot_sql_rows VALUES(?1,?2)",
            params![page.offset + i as u64, json],
        )?;
    }
    p.received = end;
    save(&tx, &p)?;
    tx.commit()?;
    Ok(p)
}
pub fn finish<S: Schema>(c: &Connection, schema: &S, scope: &Scope) -> Result<Progress> {
    let tx = c.unchecked_transaction()?;
    let progress = finish_in(&tx, schema, scope)?;
    tx.commit()?;
    Ok(progress)
}
pub(crate) fn finish_in<S: Schema>(
    tx: &rusqlite::Transaction<'_>,
    schema: &S,
    scope: &Scope,
) -> Result<Progress> {
    let (tables, catalog_digest) = binding(tx, schema, scope)?;
    let mut p = progress(tx)?.ok_or("no SQL snapshot transfer")?;
    ensure(
        p.manifest.scope == *scope
            && p.manifest.catalog_digest == catalog_digest
            && p.received == p.manifest.rows
            && p.bytes == p.manifest.bytes,
        "SQL snapshot incomplete or mismatched",
    )?;
    if !p.complete {
        empty(tx, &tables)?;
        tx.pragma_update(None, "defer_foreign_keys", "ON")?;
        let mut digest = digest_start();
        let mut count = 0;
        let mut bytes = 0;
        let mut stmt =
            tx.prepare("SELECT position,row FROM snapshot_sql_rows ORDER BY position")?;
        let mut rows = stmt.query([])?;
        while let Some(record) = rows.next()? {
            ensure(
                record.get::<_, u64>(0)? == count,
                "SQL snapshot staging gap",
            )?;
            let json: String = record.get(1)?;
            let row: Row = serde_json::from_str(&json)?;
            ensure(json == row_json(&row)?, "noncanonical SQL snapshot row")?;
            let table = tables
                .get(row.table as usize)
                .ok_or("unknown SQL snapshot table")?;
            ensure(
                row.values.len() == table.columns.len(),
                "SQL snapshot row width mismatch",
            )?;
            count += 1;
            bytes += json.len() as u64;
            ensure(
                count <= p.manifest.rows && bytes <= p.manifest.bytes,
                "SQL snapshot staging quota mismatch",
            )?;
            digest_row(&mut digest, &json);
            let sql = format!(
                "INSERT INTO {} ({}) VALUES ({})",
                quoted(&table.name),
                table
                    .columns
                    .iter()
                    .map(|s| quoted(s))
                    .collect::<Vec<_>>()
                    .join(","),
                vec!["?"; table.columns.len()].join(",")
            );
            tx.execute(
                &sql,
                params_from_iter(
                    row.values
                        .iter()
                        .map(SqlValue::sql)
                        .collect::<Result<Vec<_>>>()?,
                ),
            )?;
        }
        ensure(
            count == p.manifest.rows
                && bytes == p.manifest.bytes
                && format!("{:x}", digest.finalize()) == p.manifest.content_digest,
            "SQL snapshot content mismatch",
        )?;
    }
    verify_live(tx, schema, &tables, &p.manifest)?;
    p.complete = true;
    save(tx, &p)?;
    Ok(p)
}

fn verify_live<S: Schema>(
    c: &Connection,
    schema: &S,
    tables: &[Table],
    manifest: &Manifest,
) -> Result<()> {
    schema::foreign_key_check(c)?;
    // Re-read all SQL values: catches affinity conversions and row ordering errors,
    // independently of what the application chooses to include in its View.
    let mut digest = digest_start();
    let mut count = 0;
    let mut bytes = 0;
    visit(c, tables, |row| {
        let json = row_json(&row)?;
        count += 1;
        bytes += json.len() as u64;
        ensure(
            count <= manifest.rows && bytes <= manifest.bytes,
            "restored SQL snapshot quota mismatch",
        )?;
        digest_row(&mut digest, &json);
        Ok(())
    })?;
    ensure(
        count == manifest.rows
            && bytes == manifest.bytes
            && format!("{:x}", digest.finalize()) == manifest.content_digest
            && hash(&schema.view(c)?)? == manifest.state_digest,
        "restored SQL snapshot state mismatch",
    )
}
