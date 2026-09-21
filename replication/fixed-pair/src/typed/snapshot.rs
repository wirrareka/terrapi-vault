//! A frozen, bounded application + receipt snapshot. This transfers data, never
//! membership authority. A new member still needs the recovery authority protocol.
use super::*;
#[cfg(test)]
mod tests;

const MAX_PAGES: u64 = sql_snapshot::MAX_ROWS * 2;
pub const MAX_PAGE_BYTES: usize = sql_snapshot::MAX_PAGE_BYTES + 4096;
const MAX_MANIFEST_BYTES: usize = 8192;

// Uncommitted pages use placeholder bindings until the complete manifest is known.
// The caller must finalize every page in this same transaction before committing.
fn stage_page(tx: &rusqlite::Transaction<'_>, position: &mut u64, content: Content) -> Result<()> {
    let page = Page {
        manifest_digest: "0".repeat(64),
        position: *position,
        content,
    };
    tx.execute(
        "INSERT INTO node_publication_pages VALUES(?1,?2)",
        params![page.position, String::from_utf8(page.encode()?)?],
    )?;
    *position += 1;
    Ok(())
}

pub(super) fn scope(identity: &Identity<SchemaId>) -> sql_snapshot::Scope {
    sql_snapshot::Scope {
        cluster: identity.cluster.clone(),
        tenant: identity.tenant.clone(),
        epoch: identity.epoch,
        schema: identity.schema.clone(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub contract: schema_contract::Contract,
    pub checkpoint: Prefix,
    pub data: sql_snapshot::Manifest,
    pub pages: u64,
    pub receipt_bytes: u64,
}
impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.data.encode()?;
        ensure(
            matches!(self.format, 1 | capacity::RECEIPT_FORMAT_LEDGER)
                && self.checkpoint.format == 1
                && self.data.scope == scope(&self.checkpoint.identity)
                && self.data.state_digest == self.checkpoint.view_digest
                && self.pages <= MAX_PAGES
                && self.receipt_bytes <= sql_snapshot::MAX_BYTES
                && self.checkpoint.sequence
                    <= if self.format == capacity::RECEIPT_FORMAT_LEDGER {
                        capacity::MAX_RECEIPTS_V2
                    } else {
                        sql_snapshot::MAX_ROWS
                    }
                && (self.receipt_bytes == 0) == (self.checkpoint.sequence == 0)
                && [
                    &self.checkpoint.view_digest,
                    &self.checkpoint.journal_digest,
                    &self.checkpoint.receipt_digest,
                ]
                .iter()
                .all(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }),
            "invalid typed snapshot manifest",
        )?;
        let bytes = serde_json::to_vec(self)?;
        ensure(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "typed snapshot manifest too large",
        )?;
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "typed snapshot manifest too large",
        )?;
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.encode()?;
        Ok(manifest)
    }
    pub fn digest(&self) -> Result<String> {
        self.encode()?;
        hash(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Content {
    Data(sql_snapshot::Page),
    Receipts(Vec<OperationReceipt>),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub manifest_digest: String,
    pub position: u64,
    pub content: Content,
}
impl Page {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure(
            self.position < MAX_PAGES && self.manifest_digest.len() == 64,
            "invalid typed snapshot page",
        )?;
        match &self.content {
            Content::Data(page) => {
                page.encode()?;
            }
            Content::Receipts(receipts) => ensure(
                !receipts.is_empty() && receipts.len() <= sql_snapshot::MAX_PAGE_ROWS,
                "invalid receipt page count",
            )?,
        }
        let bytes = serde_json::to_vec(self)?;
        ensure(
            bytes.len() <= MAX_PAGE_BYTES,
            "typed snapshot page too large",
        )?;
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure(
            bytes.len() <= MAX_PAGE_BYTES,
            "typed snapshot page too large",
        )?;
        let page: Self = serde_json::from_slice(bytes)?;
        page.encode()?;
        Ok(page)
    }
}

impl<A: ReplicatedSchema> Node<A> {
    /// Validate every frozen page before using a publication as a pruning base.
    /// Uses bounded page buffers and the existing SQL/receipt digest encodings.
    pub(super) fn verify_publication_in(
        c: &Connection,
        manifest: &Manifest,
        identity: &Identity<SchemaId>,
        contract: &schema_contract::Contract,
    ) -> Result<()> {
        manifest.encode()?;
        ensure(
            manifest.checkpoint.identity == *identity && manifest.contract == *contract,
            "typed snapshot owner/contract mismatch",
        )?;
        let stored: String = c.query_row(
            "SELECT manifest FROM node_publication WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure(
            Manifest::decode(stored.as_bytes())? == *manifest,
            "publication changed",
        )?;
        let count: u64 = c.query_row("SELECT count(*) FROM node_publication_pages", [], |r| {
            r.get(0)
        })?;
        ensure(count == manifest.pages, "publication page count mismatch")?;
        let digest = manifest.digest()?;
        let data_digest = manifest.data.digest()?;
        let mut data_hash = Sha256::new();
        data_hash.update(b"vesta-sql-snapshot-rows-v1\0");
        let mut receipt_hash = Sha256::new();
        receipt_hash.update(b"[");
        let (mut rows, mut bytes, mut receipts, mut receipt_bytes) = (0u64, 0u64, 0u64, 0u64);
        let mut receipt_phase = false;
        for position in 0..count {
            let json: String = c.query_row(
                "SELECT page FROM node_publication_pages WHERE position=?1",
                [position],
                |r| r.get(0),
            )?;
            let page = Page::decode(json.as_bytes())?;
            ensure(
                page.position == position && page.manifest_digest == digest,
                "publication page binding mismatch",
            )?;
            match page.content {
                Content::Data(page) => {
                    ensure(
                        !receipt_phase
                            && page.manifest_digest == data_digest
                            && page.offset == rows,
                        "publication data order mismatch",
                    )?;
                    for row in page.rows {
                        let json = serde_json::to_vec(&row)?;
                        rows += 1;
                        bytes += json.len() as u64;
                        ensure(
                            rows <= manifest.data.rows && bytes <= manifest.data.bytes,
                            "publication data quota mismatch",
                        )?;
                        data_hash.update((json.len() as u64).to_be_bytes());
                        data_hash.update(json);
                    }
                }
                Content::Receipts(page) => {
                    receipt_phase = true;
                    for receipt in page {
                        receipts += 1;
                        let json = serde_json::to_vec(&receipt)?;
                        receipt_bytes += json.len() as u64;
                        ensure(
                            receipt.result.sequence == receipts
                                && receipts <= manifest.checkpoint.sequence
                                && receipt_bytes <= manifest.receipt_bytes,
                            "publication receipt prefix mismatch",
                        )?;
                        if receipts > 1 {
                            receipt_hash.update(b",");
                        }
                        receipt_hash.update(json);
                    }
                }
            }
        }
        receipt_hash.update(b"]");
        ensure(
            rows == manifest.data.rows
                && bytes == manifest.data.bytes
                && receipts == manifest.checkpoint.sequence
                && receipt_bytes == manifest.receipt_bytes
                && format!("{:x}", data_hash.finalize()) == manifest.data.content_digest
                && format!("{:x}", receipt_hash.finalize()) == manifest.checkpoint.receipt_digest,
            "publication content digest mismatch",
        )
    }

    pub(super) fn validate_manifest(&self, manifest: &Manifest) -> Result<()> {
        manifest.encode()?;
        ensure(
            manifest.checkpoint.identity == self.identity && manifest.contract == self.contract,
            "typed snapshot owner/contract mismatch",
        )
    }

    /// Publish one frozen version. Pages survive restart and remain frozen while
    /// new writes continue. Catch up the tail through the shared journal protocol.
    pub fn publish_snapshot(&mut self) -> Result<Manifest> {
        self.publish_snapshot_inner(false)
    }
    /// Atomically replace the exact expected publication. A stale caller fails
    /// without modifying the current pages. Receivers of the old version must
    /// finish before rotation or restart bootstrap into a fresh destination.
    /// This neither rotates a restored base nor grants membership authority.
    pub fn rotate_snapshot(&mut self, expected: &Manifest) -> Result<Manifest> {
        let recovery = self.connection(|c| {
            if self.admission(c).is_ok() {
                Ok(false)
            } else {
                self.recovery_export_admission(c)?;
                Ok(true)
            }
        })?;
        self.publish_snapshot_replacing(recovery, Some(expected))
    }
    pub(super) fn publish_snapshot_inner(&mut self, recovery: bool) -> Result<Manifest> {
        self.publish_snapshot_replacing(recovery, None)
    }
    fn publish_snapshot_replacing(
        &mut self,
        recovery: bool,
        expected: Option<&Manifest>,
    ) -> Result<Manifest> {
        self.connection(|c| {
            if recovery {
                if recovery::is_active(c)? {
                    self.recovery_admission(c)?;
                } else {
                    self.recovery_export_admission(c)?;
                }
            } else {
                self.admission(c)?;
            }
            let tx = c.unchecked_transaction()?;
            if let Some(json) = tx
                .query_row(
                    "SELECT manifest FROM node_publication WHERE id=1",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
            {
                let manifest = Manifest::decode(json.as_bytes())?;
                self.validate_manifest(&manifest)?;
                if let Some(expected) = expected {
                    ensure(*expected == manifest, "stale snapshot rotation")?;
                    maintenance::require_unpinned(&tx)?;
                    tx.execute("DELETE FROM node_publication_pages", [])?;
                    tx.execute("DELETE FROM node_publication WHERE id=1", [])?;
                } else {
                    self.export_checkpoint_admission(&tx, &manifest.checkpoint)?;
                    return Ok(manifest);
                }
            } else {
                ensure(
                    expected.is_none(),
                    "snapshot rotation requires existing publication",
                )?;
            }
            let checkpoint = self.current(&tx, true)?.0;
            self.export_checkpoint_admission(&tx, &checkpoint)?;
            let receipt_format = capacity::format(&tx)?;
            let receipt_limit = if receipt_format == capacity::RECEIPT_FORMAT_LEDGER {
                capacity::MAX_RECEIPTS_V2
            } else {
                sql_snapshot::MAX_ROWS
            };
            ensure(
                checkpoint.sequence <= receipt_limit,
                "snapshot receipt quota exceeded",
            )?;
            let mut pages = 0;
            let mut data_page = sql_snapshot::Page {
                format: 1,
                manifest_digest: "0".repeat(64),
                offset: 0,
                rows: Vec::new(),
            };
            let mut data_bytes = 512;
            let data = sql_snapshot::scan_in(&tx, &self.adapter, &scope(&self.identity), |row| {
                let bytes = serde_json::to_vec(&row)?.len() + 1;
                if data_page.rows.len() == sql_snapshot::MAX_PAGE_ROWS
                    || data_bytes + bytes > sql_snapshot::MAX_PAGE_BYTES
                {
                    let count = data_page.rows.len() as u64;
                    let content = Content::Data(sql_snapshot::Page {
                        format: data_page.format,
                        manifest_digest: data_page.manifest_digest.clone(),
                        offset: data_page.offset,
                        rows: std::mem::take(&mut data_page.rows),
                    });
                    stage_page(&tx, &mut pages, content)?;
                    data_page.offset += count;
                    data_bytes = 512;
                }
                data_page.rows.push(row);
                data_bytes += bytes;
                Ok(())
            })?;
            if !data_page.rows.is_empty() {
                stage_page(&tx, &mut pages, Content::Data(data_page))?;
            }
            let mut pending = Vec::new();
            let mut page_bytes = 512usize;
            let mut receipt_bytes = 0u64;
            let mut stmt =
                tx.prepare("SELECT receipt FROM operation_receipts ORDER BY sequence")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let json: String = row.get(0)?;
                let receipt: OperationReceipt = serde_json::from_str(&json)?;
                let bytes = serde_json::to_vec(&receipt)?.len();
                ensure(
                    bytes <= sql_snapshot::MAX_ROW_BYTES,
                    "snapshot receipt too large",
                )?;
                receipt_bytes += bytes as u64;
                ensure(
                    receipt_bytes <= sql_snapshot::MAX_BYTES,
                    "snapshot receipt quota exceeded",
                )?;
                if pending.len() == sql_snapshot::MAX_PAGE_ROWS
                    || page_bytes + bytes + 1 > sql_snapshot::MAX_PAGE_BYTES
                {
                    stage_page(
                        &tx,
                        &mut pages,
                        Content::Receipts(std::mem::take(&mut pending)),
                    )?;
                    page_bytes = 512;
                }
                pending.push(receipt);
                page_bytes += bytes + 1;
            }
            drop(rows);
            drop(stmt);
            if !pending.is_empty() {
                stage_page(&tx, &mut pages, Content::Receipts(pending))?;
            }
            let manifest = Manifest {
                format: receipt_format,
                contract: self.contract.clone(),
                checkpoint,
                data,
                pages,
                receipt_bytes,
            };
            self.validate_manifest(&manifest)?;
            let digest = manifest.digest()?;
            let data_digest = manifest.data.digest()?;
            for position in 0..pages {
                let json: String = tx.query_row(
                    "SELECT page FROM node_publication_pages WHERE position=?1",
                    [position],
                    |r| r.get(0),
                )?;
                let mut page = Page::decode(json.as_bytes())?;
                ensure(
                    page.position == position,
                    "snapshot staging position mismatch",
                )?;
                page.manifest_digest = digest.clone();
                if let Content::Data(data) = &mut page.content {
                    data.manifest_digest = data_digest.clone();
                }
                ensure(
                    tx.execute(
                        "UPDATE node_publication_pages SET page=?2 WHERE position=?1",
                        params![page.position, String::from_utf8(page.encode()?)?],
                    )? == 1,
                    "snapshot page finalization failed",
                )?;
            }
            tx.execute(
                "INSERT INTO node_publication VALUES(1,?1)",
                [String::from_utf8(manifest.encode()?)?],
            )?;
            tx.commit()?;
            Ok(manifest)
        })
    }
    /// Local metadata inspection, even when a stale publication cannot be exported.
    /// This does not grant page export, read admission or writer authority.
    pub fn published_snapshot(&self) -> Result<Option<Manifest>> {
        self.connection(|c| {
            self.verify_owner(c)?;
            let json: Option<String> = c
                .query_row(
                    "SELECT manifest FROM node_publication WHERE id=1",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            json.map(|json| {
                let manifest = Manifest::decode(json.as_bytes())?;
                self.validate_manifest(&manifest)?;
                Ok(manifest)
            })
            .transpose()
        })
    }
    pub fn snapshot_page(&self, manifest: &Manifest, position: u64) -> Result<Page> {
        self.connection(|c| {
            if self.admission(c).is_err() {
                self.recovery_export_admission(c)?;
            }
            self.export_checkpoint_admission(c, &manifest.checkpoint)?;
            self.validate_manifest(manifest)?;
            let stored: String = c.query_row(
                "SELECT manifest FROM node_publication WHERE id=1",
                [],
                |r| r.get(0),
            )?;
            ensure(
                Manifest::decode(stored.as_bytes())? == *manifest && position < manifest.pages,
                "snapshot publication mismatch",
            )?;
            let json: String = c.query_row(
                "SELECT page FROM node_publication_pages WHERE position=?1",
                [position],
                |r| r.get(0),
            )?;
            let page = Page::decode(json.as_bytes())?;
            ensure(
                page.position == position && page.manifest_digest == manifest.digest()?,
                "snapshot page binding mismatch",
            )?;
            Ok(page)
        })
    }
    pub(super) fn restore_manifest_in(&self, c: &Connection) -> Result<(Manifest, u64)> {
        let (json, next): (String, u64) = c.query_row(
            "SELECT manifest,progress FROM node_restore WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let manifest = Manifest::decode(json.as_bytes())?;
        self.validate_manifest(&manifest)?;
        ensure(next <= manifest.pages, "invalid snapshot progress")?;
        let (count, max): (u64, Option<u64>) = c.query_row(
            "SELECT count(*),max(position) FROM node_restore_pages",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure(
            count == next && max == next.checked_sub(1),
            "invalid snapshot staging prefix",
        )?;
        if let Some(progress) = sql_snapshot::progress(c)? {
            ensure(
                progress.manifest == manifest.data && !progress.complete,
                "orphan completed SQL snapshot",
            )?;
        }
        Ok((manifest, next))
    }
    /// Caller authenticates the source. This is bootstrap into an empty configured
    /// secondary, not a permission to replace/promote a member of an active pair.
    pub fn begin_snapshot(&mut self, manifest: &Manifest) -> Result<u64> {
        ensure(
            self.role == Role::Secondary,
            "snapshot bootstrap requires secondary",
        )?;
        self.validate_manifest(manifest)?;
        self.connection(|c| {
            self.verify_owner(c)?;
            let local_format = capacity::format(c)?;
            ensure(
                local_format == manifest.format
                    || (local_format == 1 && manifest.format == capacity::RECEIPT_FORMAT_LEDGER),
                "snapshot receipt capacity format mismatch",
            )?;
            if let Some(json) = c.query_row("SELECT manifest FROM node_restore_complete WHERE id=1", [], |r|r.get::<_,String>(0)).optional()? {
                self.admission(c)?;
                ensure(Manifest::decode(json.as_bytes())? == *manifest && checkpoint::base_for::<SchemaId>(c)?.as_ref() == Some(&manifest.checkpoint), "completed snapshot mismatch")?;
                self.current(c,false)?;
                return Ok(manifest.pages);
            }
            let restoring: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM node_restore)", [], |r| r.get(0))?;
            if restoring {
                let (stored,next) = self.restore_manifest_in(c)?;
                ensure(stored == *manifest, "snapshot slot occupied")?;
                return Ok(next);
            }
            self.admission(c)?;
            let tx = c.unchecked_transaction()?;
            ensure(self.current(&tx,true)?.0.sequence == 0 && checkpoint::base_for::<SchemaId>(&tx)?.is_none(), "snapshot target is not empty")?;
            let occupied:bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM node_restore_complete) OR EXISTS(SELECT 1 FROM node_restore_pages) OR EXISTS(SELECT 1 FROM node_publication)", [], |r| r.get(0))?;
            ensure(!occupied, "snapshot slot occupied")?;
            tx.execute("INSERT INTO node_restore VALUES(1,?1,0)", [String::from_utf8(manifest.encode()?)?])?;
            tx.execute("DELETE FROM replication_readiness", [])?;
            tx.commit()?;
            Ok(0)
        })
    }
    pub fn receive_snapshot(&mut self, page: &Page) -> Result<u64> {
        let encoded = String::from_utf8(page.encode()?)?;
        self.connection(|c| {
            self.verify_owner(c)?;
            let tx = c.unchecked_transaction()?;
            let (manifest, next) = self.restore_manifest_in(&tx)?;
            ensure(
                page.manifest_digest == manifest.digest()?
                    && page.position <= next
                    && page.position < manifest.pages,
                "snapshot page out of order or mismatched",
            )?;
            if page.position < next {
                let old: String = tx.query_row(
                    "SELECT page FROM node_restore_pages WHERE position=?1",
                    [page.position],
                    |r| r.get(0),
                )?;
                ensure(old == encoded, "conflicting snapshot page retry")?;
                return Ok(next);
            }
            let bytes: u64 = tx.query_row(
                "SELECT coalesce(sum(length(CAST(page AS BLOB))),0) FROM node_restore_pages",
                [],
                |r| r.get(0),
            )?;
            ensure(
                bytes + encoded.len() as u64 <= sql_snapshot::MAX_BYTES * 2 + MAX_PAGES * 4096,
                "snapshot staging quota exceeded",
            )?;
            tx.execute(
                "INSERT INTO node_restore_pages VALUES(?1,?2)",
                params![page.position, encoded],
            )?;
            tx.execute("UPDATE node_restore SET progress=?1 WHERE id=1", [next + 1])?;
            tx.commit()?;
            Ok(next + 1)
        })
    }
    pub fn finish_snapshot(&mut self, manifest: &Manifest) -> Result<Prefix> {
        self.finish_snapshot_installing(manifest, None)
    }
    /// Restore that installs an externally chosen admission generation instead
    /// of a fresh random one. Reserved for the participant-loss bootstrap, whose
    /// successor membership is signed against exactly this generation; a random
    /// one would make that signed installation contract unsatisfiable. Never
    /// `pub`: no application caller may choose an admission generation.
    ///
    /// Uniqueness is not weakened. The value is not chosen by the caller of the
    /// recovery: the bootstrap pre-check requires the still-empty replacement to
    /// already carry it, and that value was produced by `fresh_generation` when
    /// the file was created, exactly as in the ordinary flow. This entry only
    /// preserves it across the restore instead of rolling it again.
    pub(super) fn finish_snapshot_retaining_generation(
        &mut self,
        manifest: &Manifest,
        generation: [u8; 32],
    ) -> Result<Prefix> {
        ensure(generation != [0; 32], "zero admission generation")?;
        self.finish_snapshot_installing(manifest, Some(generation))
    }
    fn finish_snapshot_installing(
        &mut self,
        manifest: &Manifest,
        retain: Option<[u8; 32]>,
    ) -> Result<Prefix> {
        self.validate_manifest(manifest)?;
        self.connection(|c| {
            self.verify_owner(c)?;
            if let Some(json) = c
                .query_row(
                    "SELECT manifest FROM node_restore_complete WHERE id=1",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
            {
                ensure(
                    Manifest::decode(json.as_bytes())? == *manifest
                        && checkpoint::base_for::<SchemaId>(c)?
                            == Some(manifest.checkpoint.clone()),
                    "completed snapshot mismatch",
                )?;
                self.admission(c)?;
                self.current(c, false)?;
                return Ok(manifest.checkpoint.clone());
            }
            let (stored, next) = self.restore_manifest_in(c)?;
            ensure(
                stored == *manifest && next == manifest.pages,
                "snapshot incomplete",
            )?;
            sql_snapshot::begin(c, &self.adapter, &scope(&self.identity), &manifest.data)?;
            // SQL row staging has independent exact-retry checks. It remains
            // hidden behind node_restore across a crash at any page boundary.
            for position in 0..next {
                let page = load_page(c, position, manifest)?;
                if let Content::Data(data) = page.content {
                    sql_snapshot::receive(c, &self.adapter, &scope(&self.identity), &data)?;
                }
            }
            let tx = c.unchecked_transaction()?;
            let local_format = capacity::format(&tx)?;
            if manifest.format == capacity::RECEIPT_FORMAT_LEDGER && local_format == 1 {
                capacity::install_ledger(&tx, 0, 0)?;
                ensure(
                    tx.execute(
                        "UPDATE receipt_format SET version=?1 WHERE id=1 AND version=1",
                        [capacity::RECEIPT_FORMAT_LEDGER],
                    )? == 1,
                    "snapshot capacity format upgrade conflict",
                )?;
            } else {
                ensure(
                    local_format == manifest.format,
                    "snapshot receipt capacity format mismatch",
                )?;
            }
            sql_snapshot::finish_in(&tx, &self.adapter, &scope(&self.identity))?;
            let mut count = 0u64;
            let mut bytes = 0u64;
            for position in 0..next {
                if let Content::Receipts(receipts) = load_page(&tx, position, manifest)?.content {
                    for receipt in receipts {
                        count += 1;
                        let json = serde_json::to_string(&receipt)?;
                        bytes += json.len() as u64;
                        ensure(
                            count <= manifest.checkpoint.sequence
                                && receipt.result.sequence == count
                                && bytes <= manifest.receipt_bytes,
                            "invalid snapshot receipt prefix",
                        )?;
                        tx.execute(
                            "INSERT INTO operation_receipts VALUES(?1,?2,?3)",
                            params![receipt.result.operation_id, count, json],
                        )?;
                    }
                }
            }
            ensure(
                count == manifest.checkpoint.sequence
                    && bytes == manifest.receipt_bytes
                    && checkpoint::receipt_digest_from_for(&tx, &self.adapter, count, false)?
                        == manifest.checkpoint.receipt_digest,
                "snapshot receipt digest mismatch",
            )?;
            tx.execute(
                "INSERT INTO replication_base VALUES(1,?1)",
                [serde_json::to_string(&manifest.checkpoint)?],
            )?;
            let generation = match retain {
                Some(generation) => generation,
                None => checkpoint::fresh_generation()?,
            };
            tx.execute(
                "UPDATE replication_generation SET value=?1 WHERE id=1",
                [generation.as_slice()],
            )?;
            tx.execute("DELETE FROM replication_readiness", [])?;
            ensure(
                self.current(&tx, true)?.0 == manifest.checkpoint,
                "restored snapshot checkpoint mismatch",
            )?;
            tx.execute(
                "INSERT INTO node_restore_complete VALUES(1,?1)",
                [String::from_utf8(manifest.encode()?)?],
            )?;
            tx.execute("DELETE FROM node_restore", [])?;
            tx.commit()?;
            Ok(manifest.checkpoint.clone())
        })
    }
}
fn load_page(c: &Connection, position: u64, manifest: &Manifest) -> Result<Page> {
    let json: String = c.query_row(
        "SELECT page FROM node_restore_pages WHERE position=?1",
        [position],
        |r| r.get(0),
    )?;
    let page = Page::decode(json.as_bytes())?;
    ensure(
        page.position == position && page.manifest_digest == manifest.digest()?,
        "snapshot staging binding mismatch",
    )?;
    Ok(page)
}
