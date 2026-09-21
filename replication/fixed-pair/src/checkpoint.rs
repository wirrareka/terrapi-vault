//! Persisted read admission for the configured fixed pair, not a leader election protocol.
use crate::*;
use rusqlite::OptionalExtension;
use schema::RequestSchema;
use serde::de::DeserializeOwned;

pub(super) fn fresh_generation() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
pub(super) fn initialize(c: &Connection) -> Result<()> {
    c.execute(
        "INSERT OR IGNORE INTO replication_generation(id,value) VALUES(1,?1)",
        [fresh_generation()?.as_slice()],
    )?;
    let tx = c.unchecked_transaction()?;
    let tables: u64 = tx.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('replication_base','checkpoint_format')", [], |r| r.get(0))?;
    if tables == 0 {
        tx.execute_batch("CREATE TABLE replication_base(id INTEGER PRIMARY KEY CHECK(id=1),checkpoint TEXT NOT NULL);
            CREATE TABLE checkpoint_format(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
            INSERT INTO checkpoint_format VALUES(1,1);
            DELETE FROM replication_readiness;")?;
    } else {
        ensure(tables == 2, "incomplete checkpoint schema")?;
        let version: u32 = tx.query_row(
            "SELECT version FROM checkpoint_format WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        let recovery_tables: u32 = tx.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('recovery_seal','recovery_active')", [], |r|r.get(0))?;
        let sealed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='recovery_seal')", [], |r|r.get(0))?;
        // Recovery-bound databases deliberately reject older binaries, which
        // require version 1 and would otherwise ignore the new admission tables.
        // This DB compatibility marker does not change Checkpoint.format (1).
        ensure(
            (version == 1 && recovery_tables == 0) || (version == 2 && sealed),
            "unsupported checkpoint format",
        )?;
    }
    tx.commit()?;
    Ok(())
}
pub(super) fn generation(c: &Connection) -> Result<[u8; 32]> {
    let value: Vec<u8> = c.query_row(
        "SELECT value FROM replication_generation WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    value
        .try_into()
        .map_err(|_| "invalid admission generation".into())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Local history checkpoint, not external commit authorization. The default
/// numeric schema field preserves reference serialization; typed envelopes do
/// not make the reference Node or its transport schema-generic.
pub struct Checkpoint<I = u32> {
    #[serde(default)]
    pub format: u32,
    pub identity: Identity<I>,
    pub sequence: u64,
    pub view_digest: String,
    pub journal_digest: String,
    // Default only permits inspecting/cancelling pre-receipt staging metadata.
    // An empty digest can never equal a newly computed checkpoint.
    #[serde(default)]
    pub receipt_digest: String,
}
struct JsonDigest(Sha256);
impl std::io::Write for JsonDigest {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) fn base(c: &Connection) -> Result<Option<Checkpoint>> {
    base_for(c)
}
pub(crate) fn base_for<I: DeserializeOwned>(c: &Connection) -> Result<Option<Checkpoint<I>>> {
    let json: Option<String> = c
        .query_row(
            "SELECT checkpoint FROM replication_base WHERE id=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    json.map(|s| Ok(serde_json::from_str(&s)?)).transpose()
}
pub(super) fn receipt_digest_from(c: &Connection, until: u64, published: bool) -> Result<String> {
    receipt_digest_from_for(c, &reference::Proximi, until, published)
}
pub(crate) fn receipt_digest_from_for<A: RequestSchema>(
    c: &Connection,
    _adapter: &A,
    until: u64,
    published: bool,
) -> Result<String> {
    ensure(
        A::FINGERPRINT_VERSION > 0,
        "invalid request fingerprint version",
    )?;
    ensure(
        until <= i64::MAX as u64,
        "receipt prefix outside SQLite range",
    )?;
    let mut digest = JsonDigest(Sha256::new());
    digest.0.update(b"[");
    let sql = if published {
        "SELECT operation_id,sequence,receipt FROM published_receipts WHERE sequence<=?1 ORDER BY sequence"
    } else {
        "SELECT operation_id,sequence,receipt FROM operation_receipts WHERE sequence<=?1 ORDER BY sequence"
    };
    let mut stmt = c.prepare(sql)?;
    let mut rows = stmt.query([until])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let r: OperationReceipt = serde_json::from_str(&row.get::<_, String>(2)?)?;
        count += 1;
        ensure(
            r.result.sequence == count
                && r.result.sequence == row.get::<_, u64>(1)?
                && !r.result.operation_id.is_empty()
                && r.result.operation_id == row.get::<_, String>(0)?
                && r.fingerprint_version == A::FINGERPRINT_VERSION
                && r.result_version == 1
                && r.request_digest.len() == 64,
            "invalid receipt prefix",
        )?;
        if count > 1 {
            digest.0.update(b",");
        }
        serde_json::to_writer(&mut digest, &r)?;
    }
    ensure(count == until, "incomplete receipt prefix")?;
    digest.0.update(b"]");
    Ok(format!("{:x}", digest.0.finalize()))
}
pub(super) fn calculate(
    c: &Connection,
    identity: &Identity,
    quiescent: bool,
    until: Option<u64>,
) -> Result<Checkpoint> {
    calculate_for(
        c,
        &reference::Proximi,
        identity,
        &hash(&View::default())?,
        quiescent,
        until,
    )
}
// The owning protocol supplies a trusted initial-view digest and schema binding.
// Hash domain labels retain checkpoint-format-1 bytes for reference databases;
// typed identities are still included in the seed. This grants no writer authority.
pub(crate) fn calculate_for<A: RequestSchema, I>(
    c: &Connection,
    adapter: &A,
    identity: &Identity<I>,
    initial_view_digest: &str,
    quiescent: bool,
    until: Option<u64>,
) -> Result<Checkpoint<I>>
where
    A::Change: Serialize + DeserializeOwned,
    I: Clone + Serialize + DeserializeOwned + PartialEq,
{
    journal::positive_sequence_keys(c)?;
    let anchor = base_for::<I>(c)?;
    let mut applied = anchor.as_ref().map_or(0, |b| b.sequence);
    if let Some(b) = &anchor {
        ensure(
            b.format == 1
                && b.identity == *identity
                && b.receipt_digest == receipt_digest_from_for(c, adapter, b.sequence, false)?,
            "invalid base checkpoint",
        )?;
    }
    ensure(
        until.is_none_or(|n| n >= applied && n <= i64::MAX as u64),
        "checkpoint prefix before base",
    )?;
    let mut stmt =
        c.prepare("SELECT sequence,entry,operation_id FROM replication_log WHERE sequence<=?1 AND sequence>?2 ORDER BY sequence")?;
    let mut rows = stmt.query(params![until.unwrap_or(i64::MAX as u64), applied])?;
    let mut pending = false;
    let mut digest = match &anchor {
        Some(b) => b.journal_digest.clone(),
        None => hash(&("proximiio-journal-chain-v1", identity))?,
    };
    let mut previous = match &anchor {
        Some(b) => b.view_digest.clone(),
        None => initial_view_digest.to_owned(),
    };
    while let Some(row) = rows.next()? {
        ensure(!pending, "invalid journal state ordering")?;
        let e: Entry<A::Change, I> = serde_json::from_str(&row.get::<_, String>(1)?)?;
        ensure(
            &e.batch.identity == identity,
            "identity/epoch/schema mismatch",
        )?;
        // Applied entries are checksum-validated by validate_entry_for through
        // OperationReceipt::from_applied below. Pending entries have no receipt,
        // so they must still be validated here. Never trust a stored digest alone.
        if e.state != State::Applied {
            e.validate(identity)?;
        }
        ensure(
            !e.batch.operation_id.is_empty() && e.batch.operation_id == row.get::<_, String>(2)?,
            "journal operation key mismatch",
        )?;
        receipts::validate_entry_for(c, adapter, &e)?;
        ensure(
            e.sequence == applied + 1
                && e.sequence == row.get::<_, u64>(0)?
                && e.before == previous,
            "checkpoint journal chain mismatch",
        )?;
        if e.state == State::Applied {
            digest = hash(&("proximiio-journal-link-v1", &digest, &e.digest))?;
            applied += 1;
            previous = e.after.clone();
        } else {
            pending = true;
        }
    }
    ensure(
        !(quiescent || until.is_some()) || !pending,
        "checkpoint requires resolved journal",
    )?;
    ensure(
        until.is_none_or(|n| n == applied),
        "missing checkpoint prefix",
    )?;
    if until.is_none() {
        ensure(receipts::count(c)? == applied, "orphan receipt count")?;
    }
    Ok(Checkpoint {
        format: 1,
        identity: identity.clone(),
        sequence: applied,
        view_digest: previous,
        journal_digest: digest,
        receipt_digest: receipt_digest_from_for(c, adapter, applied, false)?,
    })
}
pub(super) fn current(
    c: &Connection,
    identity: &Identity,
    quiescent: bool,
) -> Result<(Checkpoint, View)> {
    current_for(
        c,
        &reference::Proximi,
        identity,
        &hash(&View::default())?,
        quiescent,
    )
}
pub(crate) fn current_for<A: RequestSchema, I>(
    c: &Connection,
    adapter: &A,
    identity: &Identity<I>,
    initial_view_digest: &str,
    quiescent: bool,
) -> Result<(Checkpoint<I>, A::View)>
where
    A::Change: Serialize + DeserializeOwned,
    I: Clone + Serialize + DeserializeOwned + PartialEq,
{
    let checkpoint = calculate_for(c, adapter, identity, initial_view_digest, quiescent, None)?;
    let view = adapter.view(c)?;
    let view_digest = hash(&view)?;
    ensure(
        view_digest == checkpoint.view_digest,
        "checkpoint data/journal mismatch",
    )?;
    Ok((checkpoint, view))
}
fn stored(c: &Connection) -> Result<Option<Checkpoint>> {
    let value: Option<String> = c
        .query_row(
            "SELECT checkpoint FROM replication_readiness WHERE id=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    value.map(|v| Ok(serde_json::from_str(&v)?)).transpose()
}
fn save(c: &Connection, checkpoint: &Checkpoint) -> Result<()> {
    c.execute("INSERT INTO replication_readiness(id,checkpoint) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint WHERE replication_readiness.checkpoint<>excluded.checkpoint",[serde_json::to_string(checkpoint)?])?;
    Ok(())
}
pub(super) fn verified_view(c: &Connection, identity: &Identity) -> Result<Option<View>> {
    let Some(marker) = stored(c)? else {
        return Ok(None);
    };
    let (actual, view) = current(c, identity, false)?;
    Ok((actual == marker).then_some(view))
}
pub(super) fn advance(c: &Connection, identity: &Identity) -> Result<()> {
    save(c, &current(c, identity, false)?.0)
}
impl Node {
    pub fn checkpoint_at(&self, sequence: u64) -> Result<Checkpoint> {
        self.connection(|c| calculate(c, &self.identity, true, Some(sequence)))
    }
    pub fn checkpoint(&self) -> Result<Checkpoint> {
        self.connection(|c| Ok(current(c, &self.identity, true)?.0))
    }
    pub fn verified_view(&self) -> Result<Option<View>> {
        ensure(
            self.role == Role::Secondary,
            "read admission is secondary-only",
        )?;
        self.connection(|c| verified_view(c, &self.identity))
    }
    /// Called only by the configured authenticated primary after complete reconciliation.
    pub fn confirm_checkpoint(&mut self, expected: Checkpoint) -> Result<()> {
        ensure(
            self.role == Role::Secondary && expected.identity == self.identity,
            "checkpoint identity/role mismatch",
        )?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            snapshot_staging::ensure_idle(&tx)?;
            ensure(
                current(&tx, &self.identity, true)?.0 == expected,
                "checkpoint mismatch",
            )?;
            save(&tx, &expected)?;
            tx.commit()?;
            Ok(())
        })
    }
    pub fn confirm_generation(
        &mut self,
        expected: Checkpoint,
        expected_generation: [u8; 32],
    ) -> Result<()> {
        ensure(
            self.connection(generation)? == expected_generation,
            "stale admission generation",
        )?;
        self.confirm_checkpoint(expected)
    }
    /// Operator action before serving a restored/replaced copy; keeps all business data.
    pub fn quarantine(&mut self) -> Result<()> {
        ensure(self.role == Role::Secondary, "quarantine is secondary-only")?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            tx.execute("DELETE FROM replication_readiness", [])?;
            tx.execute(
                "UPDATE replication_generation SET value=?1 WHERE id=1",
                [fresh_generation()?.as_slice()],
            )?;
            tx.commit()?;
            Ok(())
        })
    }
}
