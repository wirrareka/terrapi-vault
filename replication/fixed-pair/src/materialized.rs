//! Materialized business state + receipts, no historical changeset replay.
use crate::*;
use rusqlite::OptionalExtension;

pub const MAX_ROWS: u64 = 100_000;
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Frozen export cursor. Its head revision is the publication token, not a live journal cursor.
    #[serde(default)]
    pub publication: Option<Box<publication::Proposal>>,
    pub head: journal::JournalHead,
    pub checkpoint: Checkpoint,
    pub places: u64,
    pub features: u64,
    pub receipts: u64,
}
impl Manifest {
    pub fn rows(&self) -> Result<u64> {
        self.places
            .checked_add(self.features)
            .and_then(|n| n.checked_add(self.receipts))
            .ok_or_else(|| "snapshot row count overflow".into())
    }
    fn validate(&self) -> Result<()> {
        if let Some(p) = &self.publication {
            ensure(
                p.checkpoint == self.checkpoint
                    && p.token == self.head.revision
                    && p.primary_generation == self.head.read_generation,
                "invalid published manifest binding",
            )?;
        }
        ensure(
            self.rows()? <= MAX_ROWS
                && self.receipts == self.checkpoint.sequence
                && self.head.length == self.checkpoint.sequence
                && self.head.identity == self.checkpoint.identity
                && self.head.base.as_ref().is_none_or(|b| {
                    b.format == 1
                        && b.identity == self.checkpoint.identity
                        && b.sequence <= self.checkpoint.sequence
                })
                && self.checkpoint.format == 1
                && [
                    &self.checkpoint.view_digest,
                    &self.checkpoint.receipt_digest,
                    &self.checkpoint.journal_digest,
                ]
                .iter()
                .all(|d| d.len() == 64),
            "invalid materialized manifest",
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Row {
    Place(Place),
    Feature(Feature),
    Receipt(OperationReceipt),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Page {
    pub manifest: Manifest,
    pub after: u64,
    pub rows: Vec<Row>,
}
impl Page {
    fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        let total = self.manifest.rows()?;
        ensure(
            self.after <= total
                && self.rows.len() <= journal::MAX_PAGE_ENTRIES as usize
                && self.rows.len() as u64 <= total - self.after
                && (!self.rows.is_empty() || self.after == total),
            "invalid materialized page range",
        )?;
        let mut bytes = 0;
        for (i, row) in self.rows.iter().enumerate() {
            let n = self.after + i as u64;
            match row {
                Row::Place(_) => ensure(n < self.manifest.places, "unexpected place row")?,
                Row::Feature(_) => ensure(
                    n >= self.manifest.places && n < self.manifest.places + self.manifest.features,
                    "unexpected feature row",
                )?,
                Row::Receipt(r) => ensure(
                    n >= self.manifest.places + self.manifest.features
                        && r.result.sequence
                            == n - self.manifest.places - self.manifest.features + 1
                        && !r.result.operation_id.is_empty()
                        && r.fingerprint_version == 1
                        && r.result_version == 1
                        && r.request_digest.len() == 64,
                    "invalid materialized receipt",
                )?,
            }
            bytes += serde_json::to_vec(row)?.len() + 1;
            ensure(
                bytes <= journal::MAX_PAGE_BYTES,
                "materialized page byte limit",
            )?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Progress {
    pub manifest: Manifest,
    pub token: [u8; 32],
    pub received: u64,
    pub bytes: u64,
    pub complete: bool,
}
pub(super) fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS materialized_transfer(id INTEGER PRIMARY KEY CHECK(id=1),progress TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS materialized_rows(position INTEGER PRIMARY KEY,row TEXT NOT NULL);")?;
    Ok(())
}
fn progress(c: &Connection) -> Result<Option<Progress>> {
    let json: Option<String> = c
        .query_row(
            "SELECT progress FROM materialized_transfer WHERE id=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    json.map(|s| Ok(serde_json::from_str(&s)?)).transpose()
}
fn save_progress(c: &Connection, p: &Progress) -> Result<()> {
    c.execute("INSERT INTO materialized_transfer VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET progress=excluded.progress", [serde_json::to_string(p)?])?;
    Ok(())
}
pub(super) fn ensure_idle(c: &Connection) -> Result<()> {
    ensure(
        progress(c)?.is_none_or(|p| p.complete),
        "materialized transfer in progress",
    )
}
fn empty(c: &Connection) -> Result<()> {
    let occupied: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM replication_log) OR EXISTS(SELECT 1 FROM places) OR EXISTS(SELECT 1 FROM features) OR EXISTS(SELECT 1 FROM operation_receipts) OR EXISTS(SELECT 1 FROM replication_base)", [], |r| r.get(0))?;
    ensure(!occupied, "materialized target must be empty")
}
fn load(c: &Connection, token: [u8; 32]) -> Result<Progress> {
    let p = progress(c)?.ok_or("no materialized transfer")?;
    ensure(
        p.token == token && checkpoint::generation(c)? == token,
        "stale materialized token",
    )?;
    Ok(p)
}
fn counts(c: &Connection) -> Result<(u64, u64, u64)> {
    Ok(c.query_row("SELECT (SELECT count(*) FROM places),(SELECT count(*) FROM features),(SELECT count(*) FROM operation_receipts)", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?)
}
impl Node {
    fn published_manifest_from(&self, c: &Connection) -> Result<Manifest> {
        ensure(
            self.role == Role::Primary,
            "published export requires fixed primary",
        )?;
        let record = publication::validate(c, &self.identity)?.ok_or("no published base")?;
        ensure(
            record.phase == publication::Phase::Confirmed,
            "published base not confirmed",
        )?;
        let p = record.proposal;
        ensure(
            checkpoint::generation(c)? == p.primary_generation,
            "stale published source generation",
        )?;
        let (places, features, receipts) = c.query_row("SELECT (SELECT count(*) FROM published_places),(SELECT count(*) FROM published_features),(SELECT count(*) FROM published_receipts)", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        let m = Manifest {
            head: journal::JournalHead {
                base: None,
                identity: self.identity.clone(),
                revision: p.token,
                read_generation: p.primary_generation,
                length: p.checkpoint.sequence,
            },
            checkpoint: p.checkpoint.clone(),
            publication: Some(Box::new(p)),
            places,
            features,
            receipts,
        };
        m.validate()?;
        Ok(m)
    }
    pub fn published_manifest(&self) -> Result<Manifest> {
        self.connection(|c| self.published_manifest_from(c))
    }
    pub fn published_page(&self, manifest: &Manifest, after: u64) -> Result<Page> {
        ensure(
            self.role == Role::Primary,
            "published export requires primary",
        )?;
        ensure(
            manifest.publication.is_some(),
            "published manifest required",
        )?;
        self.materialized_page_from(manifest, after, true)
    }
    pub fn materialized_manifest(&self) -> Result<Manifest> {
        ensure(
            self.role == Role::Primary,
            "materialized source requires fixed primary",
        )?;
        self.current_materialized_manifest(false)
    }
    /// Read-only export of a verified, quiescent survivor. No writer promotion.
    /// Caller must independently fence the old writer and maintain source continuity.
    pub fn recovery_export_manifest(&self) -> Result<Manifest> {
        ensure(
            self.role == Role::Secondary,
            "recovery export requires survivor",
        )?;
        self.current_materialized_manifest(true)
    }
    fn current_materialized_manifest(&self, verified: bool) -> Result<Manifest> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            if verified {
                recovery::activation::verified_seal(&tx, self)?;
                ensure(
                    checkpoint::verified_view(&tx, &self.identity)?.is_some(),
                    "unverified recovery source",
                )?;
                snapshot_staging::ensure_idle(&tx)?;
                publication::ensure_idle(&tx)?;
            }
            let checkpoint = checkpoint::current(&tx, &self.identity, true)?.0;
            let head = journal::head(&tx, &self.identity)?;
            let (places, features, receipts) = counts(&tx)?;
            let m = Manifest {
                publication: None,
                head,
                checkpoint,
                places,
                features,
                receipts,
            };
            m.validate()?;
            Ok(m)
        })
    }
    pub fn materialized_page(&self, manifest: &Manifest, after: u64) -> Result<Page> {
        ensure(
            self.role == Role::Primary,
            "materialized source requires fixed primary",
        )?;
        ensure(manifest.publication.is_none(), "live manifest required")?;
        self.materialized_page_from(manifest, after, false)
    }
    pub fn recovery_export_page(&self, manifest: &Manifest, after: u64) -> Result<Page> {
        ensure(
            self.role == Role::Secondary && manifest.publication.is_none(),
            "invalid recovery export source",
        )?;
        ensure(
            self.current_materialized_manifest(true)? == *manifest,
            "recovery source changed",
        )?;
        self.materialized_page_from(manifest, after, false)
    }
    fn materialized_page_from(
        &self,
        manifest: &Manifest,
        after: u64,
        published: bool,
    ) -> Result<Page> {
        manifest.validate()?;
        ensure(after <= manifest.rows()?, "invalid materialized cursor")?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            if published {
                ensure(self.published_manifest_from(&tx)? == *manifest, "published source changed")?;
            } else {
                ensure(
                journal::head(&tx, &self.identity)? == manifest.head
                    && counts(&tx)? == (manifest.places, manifest.features, manifest.receipts),
                "materialized source changed",
            )?;
            }
            let mut rows = Vec::new();
            let mut bytes = 0;
            // Bounded row reads; OFFSET traversal is deliberately not yet optimized.
            for n in after
                ..manifest
                    .rows()?
                    .min(after + journal::MAX_PAGE_ENTRIES as u64)
            {
                let row = if n < manifest.places {
                    Row::Place(tx.query_row(
                        if published { "SELECT id,name FROM published_places ORDER BY id LIMIT 1 OFFSET ?1" } else { "SELECT id,name FROM places ORDER BY id LIMIT 1 OFFSET ?1" },
                        [n],
                        |r| {
                            Ok(Place {
                                id: r.get(0)?,
                                name: r.get(1)?,
                            })
                        },
                    )?)
                } else if n < manifest.places + manifest.features {
                    Row::Feature(tx.query_row(
                        if published { "SELECT id,place_id,geojson FROM published_features ORDER BY id LIMIT 1 OFFSET ?1" } else { "SELECT id,place_id,geojson FROM features ORDER BY id LIMIT 1 OFFSET ?1" },
                        [n - manifest.places],
                        |r| {
                            Ok(Feature {
                                id: r.get(0)?,
                                place_id: r.get(1)?,
                                geojson: r.get(2)?,
                            })
                        },
                    )?)
                } else {
                    let json: String = tx.query_row(
                        if published { "SELECT receipt FROM published_receipts WHERE sequence=?1" } else { "SELECT receipt FROM operation_receipts WHERE sequence=?1" },
                        [n - manifest.places - manifest.features + 1],
                        |r| r.get(0),
                    )?;
                    Row::Receipt(serde_json::from_str(&json)?)
                };
                let size = serde_json::to_vec(&row)?.len() + 1;
                ensure(
                    size <= journal::MAX_PAGE_BYTES,
                    "single materialized row exceeds page budget",
                )?;
                if bytes + size > journal::MAX_PAGE_BYTES {
                    break;
                }
                bytes += size;
                rows.push(row);
            }
            let page = Page {
                manifest: manifest.clone(),
                after,
                rows,
            };
            page.validate()?;
            Ok(page)
        })
    }
    pub fn materialized_progress(&self) -> Result<Option<Progress>> {
        self.connection(progress)
    }
    pub fn materialized_begin(&mut self, manifest: Manifest) -> Result<Progress> {
        ensure(
            self.role == Role::Secondary && manifest.checkpoint.identity == self.identity,
            "materialized identity/role mismatch",
        )?;
        manifest.validate()?;
        self.connection(|c| {
            recovery::activation::bootstrap(c)?;
            let tx = c.unchecked_transaction()?;
            if let Some(p) = progress(&tx)? {
                ensure(
                    p.manifest == manifest,
                    "different materialized transfer requires cancellation",
                )?;
                load(&tx, p.token)?;
                if p.complete {
                    ensure(
                        checkpoint::current(&tx, &self.identity, true)?.0 == manifest.checkpoint,
                        "completed materialized snapshot no longer current",
                    )?;
                }
                return Ok(p);
            }
            snapshot_staging::ensure_idle(&tx)?;
            publication::ensure_absent(&tx)?;
            empty(&tx)?;
            let token = checkpoint::fresh_generation()?;
            tx.execute("DELETE FROM replication_readiness", [])?;
            tx.execute(
                "UPDATE replication_generation SET value=?1 WHERE id=1",
                [token.as_slice()],
            )?;
            let p = Progress {
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
    pub fn materialized_chunk(&mut self, token: [u8; 32], page: Page) -> Result<Progress> {
        ensure(
            self.role == Role::Secondary,
            "materialized receiver requires secondary",
        )?;
        page.validate()?;
        ensure(!page.rows.is_empty(), "empty materialized chunk")?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let mut p = load(&tx, token)?;
            ensure(
                !p.complete && p.manifest == page.manifest,
                "materialized manifest/completion mismatch",
            )?;
            let end = page.after + page.rows.len() as u64;
            ensure(
                page.after == p.received || end <= p.received,
                "materialized gap/partial overlap",
            )?;
            for (i, row) in page.rows.iter().enumerate() {
                let position = page.after + i as u64;
                let json = serde_json::to_string(row)?;
                if end <= p.received {
                    let old: String = tx.query_row(
                        "SELECT row FROM materialized_rows WHERE position=?1",
                        [position],
                        |r| r.get(0),
                    )?;
                    ensure(old == json, "conflicting materialized retry")?;
                } else {
                    p.bytes = p
                        .bytes
                        .checked_add(json.len() as u64)
                        .ok_or("materialized size overflow")?;
                    ensure(p.bytes <= MAX_BYTES, "materialized staging quota exceeded")?;
                    tx.execute(
                        "INSERT INTO materialized_rows VALUES(?1,?2)",
                        params![position, json],
                    )?;
                }
            }
            p.received = p.received.max(end);
            save_progress(&tx, &p)?;
            tx.commit()?;
            Ok(p)
        })
    }
    pub fn materialized_finish(&mut self, token: [u8; 32]) -> Result<Progress> {
        ensure(
            self.role == Role::Secondary,
            "materialized receiver requires secondary",
        )?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let mut p = load(&tx, token)?;
            if p.complete {
                ensure(
                    checkpoint::current(&tx, &self.identity, true)?.0 == p.manifest.checkpoint,
                    "completed materialized snapshot no longer current",
                )?;
                return Ok(p);
            }
            ensure(
                p.received == p.manifest.rows()?,
                "materialized snapshot incomplete",
            )?;
            empty(&tx)?;
            let mut count = 0;
            let mut bytes = 0;
            {
                let mut stmt =
                    tx.prepare("SELECT position,row FROM materialized_rows ORDER BY position")?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    ensure(row.get::<_, u64>(0)? == count, "materialized staging gap")?;
                    let json: String = row.get(1)?;
                    let item: Row = serde_json::from_str(&json)?;
                    Page {
                        manifest: p.manifest.clone(),
                        after: count,
                        rows: vec![item.clone()],
                    }
                    .validate()?;
                    count += 1;
                    bytes += json.len() as u64;
                    match item {
                        Row::Place(v) => {
                            tx.execute("INSERT INTO places VALUES(?1,?2)", params![v.id, v.name])?;
                        }
                        Row::Feature(v) => {
                            tx.execute(
                                "INSERT INTO features VALUES(?1,?2,?3)",
                                params![v.id, v.place_id, v.geojson],
                            )?;
                        }
                        Row::Receipt(v) => {
                            tx.execute(
                                "INSERT INTO operation_receipts VALUES(?1,?2,?3)",
                                params![
                                    v.result.operation_id,
                                    v.result.sequence,
                                    serde_json::to_string(&v)?
                                ],
                            )?;
                        }
                    }
                }
            }
            ensure(
                count == p.received && bytes == p.bytes && bytes <= MAX_BYTES,
                "materialized staging metadata mismatch",
            )?;
            tx.execute(
                "INSERT INTO replication_base VALUES(1,?1)",
                [serde_json::to_string(&p.manifest.checkpoint)?],
            )?;
            ensure(
                checkpoint::current(&tx, &self.identity, true)?.0 == p.manifest.checkpoint,
                "materialized checkpoint mismatch",
            )?;
            tx.execute("DELETE FROM replication_readiness", [])?;
            tx.execute("DELETE FROM materialized_rows", [])?;
            p.complete = true;
            save_progress(&tx, &p)?;
            #[cfg(feature = "test-support")]
            if std::env::var("VESTA_PROTOTYPE_CRASH_MATERIALIZED").as_deref() == Ok("before_commit")
            {
                std::process::exit(89);
            }
            tx.commit()?;
            #[cfg(feature = "test-support")]
            if std::env::var("VESTA_PROTOTYPE_CRASH_MATERIALIZED").as_deref() == Ok("after_commit")
            {
                std::process::exit(90);
            }
            Ok(p)
        })
    }
    pub fn materialized_cancel(&mut self, token: [u8; 32]) -> Result<()> {
        ensure(
            self.role == Role::Secondary,
            "materialized receiver requires secondary",
        )?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let p = progress(&tx)?.ok_or("no materialized transfer")?;
            ensure(p.token == token, "stale materialized token")?;
            tx.execute("DELETE FROM materialized_rows", [])?;
            tx.execute("DELETE FROM materialized_transfer", [])?;
            tx.commit()?;
            Ok(())
        })
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
    fn pair(dir: &std::path::Path) -> (Node, Node) {
        (
            Node::open(dir.join("p"), Role::Primary, identity(), "fixture").unwrap(),
            Node::open(dir.join("s"), Role::Secondary, identity(), "fixture").unwrap(),
        )
    }
    fn seed(p: &mut Node, s: &mut Node) {
        commit(
            p,
            s,
            Batch {
                identity: identity(),
                operation_id: "one".into(),
                changes: vec![Change::PutPlace {
                    id: "p".into(),
                    name: "fixture".into(),
                }],
            },
        )
        .unwrap();
    }
    #[test]
    fn materialized_quota_and_page_errors_do_not_advance_staging() {
        let dir = tempfile::tempdir().unwrap();
        let (mut p, mut old) = pair(dir.path());
        seed(&mut p, &mut old);
        let mut s = Node::open(
            dir.path().join("new"),
            Role::Secondary,
            identity(),
            "fixture",
        )
        .unwrap();
        let m = p.materialized_manifest().unwrap();
        let mut t = s.materialized_begin(m.clone()).unwrap();
        let page = p.materialized_page(&m, 0).unwrap();
        let mut bad = page.clone();
        bad.after = 1;
        assert!(s.materialized_chunk(t.token, bad).is_err());
        let mut bad = page.clone();
        bad.rows.reverse();
        assert!(s.materialized_chunk(t.token, bad).is_err());
        let mut bad = page.clone();
        bad.rows = vec![Row::Place(Place {
            id: "x".into(),
            name: "x".repeat(journal::MAX_PAGE_BYTES),
        })];
        assert!(s.materialized_chunk(t.token, bad).is_err());
        t.bytes = MAX_BYTES - serde_json::to_vec(&page.rows[0]).unwrap().len() as u64;
        s.connection(|c| save_progress(c, &t)).unwrap();
        assert!(s.materialized_chunk(t.token, page).is_err());
        assert_eq!(s.materialized_progress().unwrap(), Some(t));
        let n: u64 = s
            .connection(|c| {
                Ok(c.query_row("SELECT count(*) FROM materialized_rows", [], |r| r.get(0))?)
            })
            .unwrap();
        assert_eq!(n, 0);
    }
    #[test]
    fn base_receipt_corruption_is_rejected_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (mut p, mut old) = pair(dir.path());
        seed(&mut p, &mut old);
        let path = dir.path().join("new");
        let mut s = Node::open(&path, Role::Secondary, identity(), "fixture").unwrap();
        let m = p.materialized_manifest().unwrap();
        let t = s.materialized_begin(m.clone()).unwrap();
        s.materialized_chunk(t.token, p.materialized_page(&m, 0).unwrap())
            .unwrap();
        s.materialized_finish(t.token).unwrap();
        recover(&mut p, &mut s).unwrap();
        s.connection(|c| {
            c.execute("DELETE FROM operation_receipts", [])?;
            Ok(())
        })
        .unwrap();
        assert!(s.checkpoint().is_err());
        assert!(s.verified_view().is_err());
        drop(s);
        assert!(Node::open(&path, Role::Secondary, identity(), "fixture").is_err());
    }
    #[test]
    fn checkpoint_format_upgrade_requires_new_read_admission() {
        let dir = tempfile::tempdir().unwrap();
        let (mut p, mut s) = pair(dir.path());
        seed(&mut p, &mut s);
        recover(&mut p, &mut s).unwrap();
        let before = s.receipt("one").unwrap();
        // Test-only reconstruction of pre-chain metadata; journal/receipts remain intact.
        s.connection(|c| {
            c.execute_batch("DROP TABLE replication_base; DROP TABLE checkpoint_format;")?;
            Ok(())
        })
        .unwrap();
        drop(s);
        let mut s =
            Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture").unwrap();
        assert!(s.verified_view().unwrap().is_none());
        assert_eq!(s.receipt("one").unwrap(), before);
        recover(&mut p, &mut s).unwrap();
        assert!(s.verified_view().unwrap().is_some());
    }
}
