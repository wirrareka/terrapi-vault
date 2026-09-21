//! Resumable logical snapshot receipt inside the encrypted Vesta database.
use crate::{
    journal::{JournalHead, JournalPage, MAX_PAGE_ENTRIES},
    *,
};
use rusqlite::OptionalExtension;

pub const MAX_STAGED_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_STAGED_ENTRIES: u64 = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotManifest {
    pub head: JournalHead,
    pub checkpoint: Checkpoint,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotProgress {
    pub manifest: SnapshotManifest,
    pub token: [u8; 32],
    pub received: u64,
    pub bytes: u64,
    pub complete: bool,
}
pub(super) fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS snapshot_transfer(id INTEGER PRIMARY KEY CHECK(id=1),progress TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS snapshot_entries(sequence INTEGER PRIMARY KEY,entry TEXT NOT NULL);")?;
    Ok(())
}
fn progress(c: &Connection) -> Result<Option<SnapshotProgress>> {
    let value: Option<String> = c
        .query_row(
            "SELECT progress FROM snapshot_transfer WHERE id=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    value.map(|v| Ok(serde_json::from_str(&v)?)).transpose()
}
fn save_progress(c: &Connection, p: &SnapshotProgress) -> Result<()> {
    c.execute("INSERT INTO snapshot_transfer VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET progress=excluded.progress", [serde_json::to_string(p)?])?;
    Ok(())
}
pub(super) fn ensure_idle(c: &Connection) -> Result<()> {
    materialized::ensure_idle(c)?;
    ensure(
        progress(c)?.is_none_or(|p| p.complete),
        "snapshot transfer in progress",
    )
}
fn ensure_empty(c: &Connection) -> Result<()> {
    let occupied: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM replication_log) OR EXISTS(SELECT 1 FROM places) OR EXISTS(SELECT 1 FROM features)", [], |r| r.get(0))?;
    ensure(
        !occupied && receipts::count(c)? == 0 && checkpoint::base(c)?.is_none(),
        "snapshot target must be empty",
    )
}
fn load_token(c: &Connection, token: [u8; 32]) -> Result<SnapshotProgress> {
    let p = progress(c)?.ok_or("no snapshot transfer")?;
    ensure(
        p.token == token && checkpoint::generation(c)? == token,
        "stale snapshot token",
    )?;
    Ok(p)
}

impl Node {
    pub fn snapshot_manifest(&self) -> Result<SnapshotManifest> {
        ensure(
            self.role == Role::Primary,
            "snapshot source requires primary",
        )?;
        let checkpoint = self.checkpoint()?;
        let head = self.journal_head()?;
        ensure(
            head.base.is_none(),
            "replay snapshot requires complete history",
        )?;
        ensure(
            head.length == checkpoint.sequence,
            "snapshot requires quiescent source",
        )?;
        Ok(SnapshotManifest { head, checkpoint })
    }
    pub fn snapshot_progress(&self) -> Result<Option<SnapshotProgress>> {
        self.connection(progress)
    }
    pub fn snapshot_begin(&mut self, manifest: SnapshotManifest) -> Result<SnapshotProgress> {
        ensure(
            self.role == Role::Secondary
                && manifest.head.identity == self.identity
                && manifest.checkpoint.identity == self.identity,
            "snapshot identity/role mismatch",
        )?;
        ensure(
            manifest.head.length == manifest.checkpoint.sequence
                && manifest.head.length <= MAX_STAGED_ENTRIES
                && manifest.checkpoint.receipt_digest.len() == 64
                && manifest.checkpoint.format == 1
                && manifest.head.base.is_none(),
            "invalid snapshot length",
        )?;
        self.connection(|c| {
            recovery::activation::bootstrap(c)?;
            let tx = c.unchecked_transaction()?;
            materialized::ensure_idle(&tx)?;
            if let Some(p) = progress(&tx)? {
                ensure(
                    p.manifest == manifest,
                    "different snapshot requires explicit cancellation",
                )?;
                load_token(&tx, p.token)?;
                if p.complete {
                    ensure(
                        checkpoint::current(&tx, &self.identity, true)?.0 == manifest.checkpoint,
                        "completed snapshot no longer current",
                    )?;
                }
                return Ok(p);
            }
            publication::ensure_absent(&tx)?;
            ensure_empty(&tx)?;
            let token = checkpoint::fresh_generation()?;
            tx.execute("DELETE FROM replication_readiness", [])?;
            tx.execute(
                "UPDATE replication_generation SET value=?1 WHERE id=1",
                [token.as_slice()],
            )?;
            let p = SnapshotProgress {
                manifest,
                token,
                received: 0,
                bytes: 0,
                complete: false,
            };
            save_progress(&tx, &p)?;
            tx.commit()?;
            Ok(p)
        })
    }
    pub fn snapshot_chunk(
        &mut self,
        token: [u8; 32],
        page: JournalPage,
    ) -> Result<SnapshotProgress> {
        ensure(
            self.role == Role::Secondary,
            "snapshot receiver requires secondary",
        )?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let mut p = load_token(&tx, token)?;
            ensure(!p.complete, "snapshot already completed")?;
            page.validate(&p.manifest.head, page.after, MAX_PAGE_ENTRIES)?;
            ensure(!page.entries.is_empty(), "empty snapshot chunk")?;
            let end = page.after + page.entries.len() as u64;
            ensure(
                page.after == p.received || end <= p.received,
                "snapshot gap/partial overlap",
            )?;
            for e in &page.entries {
                ensure(e.state == State::Applied, "snapshot contains pending entry")?;
                journal::check_entry_size(e)?;
            }
            if end <= p.received {
                for e in &page.entries {
                    let old: String = tx.query_row(
                        "SELECT entry FROM snapshot_entries WHERE sequence=?1",
                        [e.sequence],
                        |r| r.get(0),
                    )?;
                    ensure(
                        serde_json::from_str::<Entry>(&old)? == *e,
                        "conflicting snapshot retry",
                    )?;
                }
                return Ok(p);
            }
            for e in page.entries {
                let json = serde_json::to_string(&e)?;
                p.bytes = p
                    .bytes
                    .checked_add(json.len() as u64)
                    .ok_or("snapshot size overflow")?;
                ensure(
                    p.bytes <= MAX_STAGED_BYTES,
                    "snapshot staging quota exceeded",
                )?;
                tx.execute(
                    "INSERT INTO snapshot_entries VALUES(?1,?2)",
                    params![e.sequence, json],
                )?;
            }
            p.received = end;
            save_progress(&tx, &p)?;
            tx.commit()?;
            Ok(p)
        })
    }
    pub fn snapshot_finish(&mut self, token: [u8; 32]) -> Result<SnapshotProgress> {
        ensure(
            self.role == Role::Secondary,
            "snapshot receiver requires secondary",
        )?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let mut p = load_token(&tx, token)?;
            if p.complete {
                ensure(
                    checkpoint::current(&tx, &self.identity, true)?.0 == p.manifest.checkpoint,
                    "completed snapshot no longer current",
                )?;
                return Ok(p);
            }
            ensure(p.received == p.manifest.head.length, "snapshot incomplete")?;
            ensure_empty(&tx)?;
            let mut count = 0;
            let mut bytes = 0;
            let mut previous = hash(&View::default())?;
            {
                let mut stmt =
                    tx.prepare("SELECT sequence,entry FROM snapshot_entries ORDER BY sequence")?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    let json: String = row.get(1)?;
                    let e: Entry = serde_json::from_str(&json)?;
                    count += 1;
                    bytes += json.len() as u64;
                    e.validate(&self.identity)?;
                    journal::check_entry_size(&e)?;
                    ensure(
                        e.state == State::Applied
                            && e.sequence == count
                            && e.sequence == row.get::<_, u64>(0)?
                            && e.before == previous,
                        "invalid snapshot history",
                    )?;
                    apply_changeset(&tx, &e)?;
                    previous = e.after.clone();
                    save(&tx, &e)?;
                }
            }
            ensure(
                count == p.received && bytes == p.bytes,
                "snapshot staging metadata mismatch",
            )?;
            ensure(
                checkpoint::current(&tx, &self.identity, true)?.0 == p.manifest.checkpoint,
                "snapshot checkpoint mismatch",
            )?;
            tx.execute("DELETE FROM replication_readiness", [])?;
            tx.execute("DELETE FROM snapshot_entries", [])?;
            p.complete = true;
            save_progress(&tx, &p)?;
            #[cfg(feature = "test-support")]
            if std::env::var("VESTA_PROTOTYPE_CRASH_SNAPSHOT").as_deref() == Ok("before_commit") {
                std::process::exit(87);
            }
            tx.commit()?;
            #[cfg(feature = "test-support")]
            if std::env::var("VESTA_PROTOTYPE_CRASH_SNAPSHOT").as_deref() == Ok("after_commit") {
                std::process::exit(88);
            }
            Ok(p)
        })
    }
    /// Discard only the selected transfer/receipt, never live business data.
    pub fn snapshot_cancel(&mut self, token: [u8; 32]) -> Result<()> {
        ensure(
            self.role == Role::Secondary,
            "snapshot receiver requires secondary",
        )?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let p = progress(&tx)?.ok_or("no snapshot transfer")?;
            ensure(p.token == token, "stale snapshot token")?;
            tx.execute("DELETE FROM snapshot_entries", [])?;
            tx.execute("DELETE FROM snapshot_transfer", [])?;
            tx.commit()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quota_failure_rolls_back_entire_chunk_and_progress() {
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
        let mut s = Node::open(
            dir.path().join("s"),
            Role::Secondary,
            identity.clone(),
            "fixture",
        )
        .unwrap();
        for id in ["one", "two"] {
            p.prepare(Batch {
                identity: identity.clone(),
                operation_id: id.into(),
                changes: vec![],
            })
            .unwrap();
            let e = p.decide(id).unwrap();
            p.apply(e).unwrap();
        }
        let m = p.snapshot_manifest().unwrap();
        let page = p.journal_page(&m.head, 0, 2).unwrap();
        let mut t = s.snapshot_begin(m).unwrap();
        let temp_store: i64 = s
            .connection(|c| Ok(c.query_row("PRAGMA temp_store", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(temp_store, 2);
        // Inject quota accounting close to the boundary, not 256 MiB of fixture data.
        t.bytes = MAX_STAGED_BYTES - serde_json::to_vec(&page.entries[0]).unwrap().len() as u64;
        s.connection(|c| save_progress(c, &t)).unwrap();
        assert!(s.snapshot_chunk(t.token, page).is_err());
        assert_eq!(s.snapshot_progress().unwrap(), Some(t));
        let count: u64 = s
            .connection(|c| {
                Ok(c.query_row("SELECT count(*) FROM snapshot_entries", [], |r| r.get(0))?)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
}
