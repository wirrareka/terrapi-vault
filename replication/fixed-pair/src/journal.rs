//! Revision-bound keyset pages; no cursor grants writer authority.
use crate::*;
pub(crate) mod store;

pub const MAX_PAGE_ENTRIES: u32 = 32;
pub const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn check_entry_size<C: Serialize, I: Serialize>(e: &Entry<C, I>) -> Result<()> {
    ensure(
        serde_json::to_vec(e)?.len() + usize::from(e.state != State::Prepared) < MAX_PAGE_BYTES,
        "single entry exceeds page budget",
    )
}

/// Shared replay for a complete, applied history starting at sequence one.
/// Caller owns empty-target/schema admission and the transaction's final checks
/// and commit. A successful replay is not a recovery authorization or pair ACK.
pub(crate) fn replay_history_in<A: schema::RequestSchema, I: Serialize + PartialEq>(
    tx: &Transaction<'_>,
    adapter: &A,
    identity: &Identity<I>,
    history: &[Entry<A::Change, I>],
) -> Result<()>
where
    A::Change: Serialize,
{
    for (i, e) in history.iter().enumerate() {
        e.validate(identity)?;
        check_entry_size(e)?;
        ensure(
            e.state == State::Applied
                && e.sequence == i as u64 + 1
                && e.before == hash(&adapter.view(tx)?)?,
            "invalid snapshot history",
        )?;
        schema::replay_data(
            tx,
            adapter,
            &adapter.identity(),
            &e.before,
            &e.after,
            &e.changeset,
        )?;
        store::write(tx, e)?;
        receipts::insert_for(tx, adapter, e)?;
    }
    Ok(())
}
pub(super) fn resolved(c: &Connection) -> Result<bool> {
    Ok(c.query_row("SELECT NOT EXISTS(SELECT 1 FROM replication_log WHERE json_extract(entry,'$.state') IS NOT 'Applied')", [], |r| r.get(0))?)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(deserialize = "I: Deserialize<'de>"))]
pub struct JournalHead<I = u32> {
    #[serde(default)]
    pub base: Option<Checkpoint<I>>,
    pub identity: Identity<I>,
    pub revision: [u8; 32],
    pub read_generation: [u8; 32],
    pub length: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Summary<I = u32> {
    pub schema_contract: schema_contract::Contract,
    #[serde(default)]
    pub membership: Option<[u8; 32]>,
    pub head: JournalHead<I>,
    pub role: Role,
    pub cipher_version: String,
    pub synchronous: i64,
    pub journal_mode: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalPage<C = Change, I = u32> {
    pub head: JournalHead<I>,
    pub after: u64,
    pub entries: Vec<Entry<C, I>>,
}
impl<C: Serialize, I: Serialize + PartialEq> JournalPage<C, I> {
    pub fn validate(&self, head: &JournalHead<I>, after: u64, limit: u32) -> Result<()> {
        ensure(
            limit > 0
                && limit <= MAX_PAGE_ENTRIES
                && after <= head.length
                && after >= head.base.as_ref().map_or(0, |b| b.sequence),
            "invalid page cursor/limit",
        )?;
        ensure(
            &self.head == head && self.after == after,
            "page revision/cursor mismatch",
        )?;
        ensure(
            self.entries.len() <= limit as usize
                && self.entries.len() as u64 <= head.length - after,
            "page exceeds requested range",
        )?;
        ensure(
            !self.entries.is_empty() || after == head.length,
            "premature end of journal",
        )?;
        let mut bytes = 0;
        for (i, e) in self.entries.iter().enumerate() {
            ensure(e.sequence == after + i as u64 + 1, "page sequence gap")?;
            e.validate(&head.identity)?;
            bytes += serde_json::to_vec(e)?.len() + 1;
            ensure(bytes <= MAX_PAGE_BYTES, "page byte budget exceeded")?;
        }
        Ok(())
    }
}

pub(super) fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS replication_revision(id INTEGER PRIMARY KEY CHECK(id=1),value BLOB NOT NULL CHECK(length(value)=32));
        INSERT OR IGNORE INTO replication_revision VALUES(1,randomblob(32));
        CREATE TRIGGER IF NOT EXISTS replication_revision_insert AFTER INSERT ON replication_log BEGIN UPDATE replication_revision SET value=randomblob(32) WHERE id=1; END;
        CREATE TRIGGER IF NOT EXISTS replication_revision_update AFTER UPDATE ON replication_log BEGIN UPDATE replication_revision SET value=randomblob(32) WHERE id=1; END;
        CREATE TRIGGER IF NOT EXISTS replication_revision_delete AFTER DELETE ON replication_log BEGIN UPDATE replication_revision SET value=randomblob(32) WHERE id=1; END;")?;
    Ok(())
}
pub(super) fn head(c: &Connection, identity: &Identity) -> Result<JournalHead> {
    head_for(c, identity)
}
pub(crate) fn head_for<I: Clone + serde::de::DeserializeOwned>(
    c: &Connection,
    identity: &Identity<I>,
) -> Result<JournalHead<I>> {
    positive_sequence_keys(c)?;
    let revision: Vec<u8> = c.query_row(
        "SELECT value FROM replication_revision WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let base = checkpoint::base_for(c)?;
    let floor = base.as_ref().map_or(0, |b| b.sequence);
    let (length, maximum): (u64, u64) = c.query_row(
        "SELECT count(*),coalesce(max(sequence),0) FROM replication_log WHERE sequence>?1",
        [floor],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let length = floor.checked_add(length).ok_or("journal length overflow")?;
    ensure(
        length == maximum.max(floor) && length <= i64::MAX as u64,
        "journal sequence gap",
    )?;
    Ok(JournalHead {
        base,
        identity: identity.clone(),
        revision: revision
            .try_into()
            .map_err(|_| "invalid journal revision")?,
        read_generation: checkpoint::generation(c)?,
        length,
    })
}
pub(super) fn positive_sequence_keys(c: &Connection) -> Result<()> {
    let invalid: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM replication_log WHERE sequence<=0)",
        [],
        |r| r.get(0),
    )?;
    ensure(!invalid, "nonpositive journal sequence")
}
pub(super) fn by_operation(c: &Connection, id: &str) -> Result<Option<Entry>> {
    store::by_operation(c, id)
}
pub(super) fn by_sequence(c: &Connection, sequence: u64) -> Result<Option<Entry>> {
    store::by_sequence(c, sequence)
}
pub(super) fn tail(c: &Connection) -> Result<Option<Entry>> {
    store::tail(c)
}
impl Node {
    pub fn journal_head(&self) -> Result<JournalHead> {
        self.connection(|c| head(c, &self.identity))
    }
    pub fn summary(&self) -> Result<Summary> {
        let schema_contract = self.schema_contract()?;
        self.connection(|c| {
            Ok(Summary {
                schema_contract,
                membership: recovery::activation::pair_digest(c, self.role, &self.identity)?,
                head: head(c, &self.identity)?,
                role: self.role,
                cipher_version: c.query_row("PRAGMA cipher_version", [], |r| r.get(0))?,
                synchronous: c.query_row("PRAGMA synchronous", [], |r| r.get(0))?,
                journal_mode: c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?,
            })
        })
    }
    pub fn journal_page(
        &self,
        expected: &JournalHead,
        after: u64,
        limit: u32,
    ) -> Result<JournalPage> {
        ensure(
            limit > 0
                && limit <= MAX_PAGE_ENTRIES
                && after <= expected.length
                && after >= expected.base.as_ref().map_or(0, |b| b.sequence),
            "invalid page cursor/limit",
        )?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            ensure(head(&tx, &self.identity)? == *expected, "stale journal cursor")?;
            let mut stmt = tx.prepare("SELECT sequence,length(CAST(entry AS BLOB)),entry FROM replication_log WHERE sequence>?1 ORDER BY sequence LIMIT ?2")?;
            let mut rows = stmt.query(params![after,limit])?;
            let mut entries = Vec::new();
            let mut bytes = 0;
            while let Some(row) = rows.next()? {
                let size: usize = row.get(1)?;
                ensure(size < MAX_PAGE_BYTES, "single entry exceeds page budget")?;
                if bytes + size + 1 > MAX_PAGE_BYTES { break; }
                let e: Entry = serde_json::from_str(&row.get::<_,String>(2)?)?;
                ensure(e.sequence == row.get::<_,u64>(0)?, "stored sequence mismatch")?;
                bytes += size + 1;
                entries.push(e);
            }
            let page = JournalPage { head: expected.clone(), after, entries };
            page.validate(expected, after, limit)?;
            Ok(page)
        })
    }
    pub(crate) fn operation(&self, id: &str) -> Result<Option<Entry>> {
        self.connection(|c| by_operation(c, id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journal_revision_rolls_back_with_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity {
            cluster: "test".into(),
            tenant: "one".into(),
            epoch: 1,
            schema: 1,
        };
        let mut p = Node::open(
            dir.path().join("p"),
            Role::Primary,
            identity.clone(),
            "fixture",
        )
        .unwrap();
        let mut e = p
            .prepare(Batch {
                identity,
                operation_id: "one".into(),
                changes: vec![],
            })
            .unwrap();
        let before = p.journal_head().unwrap();
        p.connection(|c| {
            let tx = c.unchecked_transaction()?;
            e.state = State::Decided;
            save(&tx, &e)?;
            assert_ne!(head(&tx, &p.identity)?, before);
            tx.rollback()?;
            Ok(())
        })
        .unwrap();
        assert_eq!(p.journal_head().unwrap(), before);
    }
}
