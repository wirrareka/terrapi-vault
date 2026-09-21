//! Local maintenance planning. A plan is not permission to delete data or write.
use super::*;
pub(super) mod certified;
pub mod compaction;
#[cfg(feature = "experimental-recovery")]
pub mod loss;
#[cfg(not(feature = "experimental-recovery"))]
pub(super) mod loss;
mod pending;
mod restores;
#[cfg(test)]
mod tests;

fn present(c: &Connection) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='node_maintenance_format')",
        [],
        |r| r.get(0),
    )?)
}
pub(super) fn history_format(c: &Connection, format: u32) -> Result<u32> {
    let tables: u32 = c.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('node_maintenance_format','node_publication_pins')", [], |r| r.get(0))?;
    match format {
        1 | 2 => {
            ensure(tables == 0, "orphan maintenance metadata")?;
            compaction::verify_metadata(c, 0)?;
            Ok(format)
        }
        3 | 4 => {
            ensure(tables == 2, "incomplete maintenance metadata")?;
            let versions = c
                .prepare("SELECT version FROM node_maintenance_format")?
                .query_map([], |r| r.get::<_, u32>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ensure(
                matches!(versions.as_slice(), [1] | [2] | [3]),
                "unsupported maintenance format",
            )?;
            if versions[0] < 3 {
                compaction::verify_metadata(c, versions[0])?;
            }
            Ok(format - 2)
        }
        _ => Err("unsupported typed lifecycle format".into()),
    }
}

/// Durable maintenance format version: 0 when the metadata is absent.
pub(super) fn maintenance_version(c: &Connection) -> Result<u32> {
    if present(c)? {
        Ok(c.query_row(
            "SELECT version FROM node_maintenance_format WHERE id=1",
            [],
            |r| r.get(0),
        )?)
    } else {
        Ok(0)
    }
}

pub(super) fn verify_certified(
    c: &Connection,
    trust: Option<&crate::recovery::transition::TrustStore>,
) -> Result<()> {
    let version = maintenance_version(c)?;
    let lineage = certified::verify_metadata(c, version, trust)?;
    if version == 3 {
        let trust = trust.ok_or("transition trust required")?;
        let rows: Vec<(u32, String)> = c
            .prepare("SELECT id,record FROM node_compaction_completion ORDER BY id")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        ensure(
            rows.len() == 1 && rows[0].0 == 1 && rows[0].1.len() <= 64 * 1024,
            "certified completion row mismatch",
        )?;
        let record: (u32, [u8; 32], [u8; 32], [u8; 32]) = serde_json::from_str(&rows[0].1)?;
        let lineage = lineage.ok_or("certified lineage missing")?;
        let certificate_json: String = c.query_row(
            "SELECT record FROM node_compaction_certificates ORDER BY sequence DESC LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        ensure(
            certificate_json.len() <= 256 * 1024,
            "certificate record limit",
        )?;
        let certificate: certified::CertificateRecord = serde_json::from_str(&certificate_json)?;
        let verified = crate::recovery::transition::verify_historical(
            &certificate.token,
            &trust.as_trust(),
            &certificate.request,
        )?;
        ensure(
            record == (1, certificate.request.id, verified.token_digest(), record.3)
                && record.3 != [0; 32]
                && lineage.last_revision == certificate.request.revision,
            "certified completion archive mismatch",
        )?;
    }
    Ok(())
}

pub(super) fn verify_current_certified(
    c: &Connection,
    authority: Option<&dyn super::CertifiedAuthority>,
) -> Result<()> {
    verify_live_certified(c, authority, false)
}

pub(super) fn verify_historical_certified(
    c: &Connection,
    authority: Option<&dyn super::CertifiedAuthority>,
) -> Result<()> {
    verify_live_certified(c, authority, true)
}

fn verify_live_certified(
    c: &Connection,
    authority: Option<&dyn super::CertifiedAuthority>,
    historical: bool,
) -> Result<()> {
    let version = maintenance_version(c)?;
    if version != 3 {
        return ensure(authority.is_none(), "unexpected certified authority");
    }
    let authority = authority.ok_or("live certified authority required")?;
    let certificate_json: String = c.query_row(
        "SELECT record FROM node_compaction_certificates ORDER BY sequence DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    ensure(
        certificate_json.len() <= 256 * 1024,
        "certificate record limit",
    )?;
    let certificate: certified::CertificateRecord = serde_json::from_str(&certificate_json)?;
    let completed_evidence = if historical {
        let completed = authority.fetch_completed_revision(&certificate.request)?;
        (
            completed.request().id,
            completed.token_digest(),
            completed.completion(),
        )
    } else {
        let completed = authority.fetch_completed(&certificate.request)?;
        (
            completed.request().id,
            completed.token_digest(),
            completed.completion(),
        )
    };
    let archived: String = c.query_row(
        "SELECT record FROM node_compaction_completion WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    ensure(
        archived.len() <= 64 * 1024,
        "certified completion row limit",
    )?;
    ensure(
        serde_json::from_str::<(u32, [u8; 32], [u8; 32], [u8; 32])>(&archived)?
            == (
                1,
                completed_evidence.0,
                completed_evidence.1,
                completed_evidence.2,
            ),
        "live certified completion mismatch",
    )
}

fn enable_in(tx: &Transaction<'_>) -> Result<()> {
    if !present(tx)? {
        tx.execute_batch("CREATE TABLE node_maintenance_format(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
            INSERT INTO node_maintenance_format VALUES(1,1);
            CREATE TABLE node_publication_pins(pin TEXT PRIMARY KEY NOT NULL,digest TEXT NOT NULL);
            UPDATE node_runtime SET format=format+2 WHERE id=1;")?;
    }
    Ok(())
}

pub(super) fn require_unpinned(c: &Connection) -> Result<()> {
    if present(c)? {
        let count: u64 = c.query_row("SELECT count(*) FROM node_publication_pins", [], |r| {
            r.get(0)
        })?;
        ensure(count == 0, "snapshot publication is pinned")?;
    }
    Ok(())
}

fn pin_key(pin: &str) -> Result<()> {
    ensure(
        !pin.is_empty()
            && pin.len() <= 128
            && pin
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid snapshot pin ID",
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompactionPlan {
    pub format: u32,
    pub role: Role,
    pub contract: schema_contract::Contract,
    pub membership: Option<[u8; 32]>,
    pub recovery_anchor: Option<Prefix>,
    pub head: Head,
    pub checkpoint: Prefix,
    /// Existing journal JSON bytes, not physical SQLite/WAL space reclamation.
    pub covered_journal_bytes: u64,
    pub covered_journal_entries: u64,
    pub unresolved_tail: bool,
    pub publication: Option<snapshot::Manifest>,
    /// Receipt count and all format quotas remain unchanged by compaction.
    pub retained_receipts: u64,
}

impl<A: ReplicatedSchema> Node<A> {
    /// Explicit opt-in to maintenance format 1 (node runtime 3/4). Old binaries
    /// reject these files. No data/history is removed by this atomic upgrade.
    pub fn enable_maintenance(&mut self) -> Result<()> {
        self.connection(|c| {
            loss::require_no_loss_recovery(c)?;
            self.admission(c)?;
            let tx = c.unchecked_transaction()?;
            self.current(&tx, true)?;
            enable_in(&tx)?;
            self.verify_owner(&tx)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Durable caller-owned pin. No TTL: release only after the transfer no longer
    /// needs this exact publication. The caller authenticates its transfer owner.
    pub fn pin_snapshot(&mut self, manifest: &snapshot::Manifest, pin: &str) -> Result<()> {
        pin_key(pin)?;
        self.validate_manifest(manifest)?;
        self.connection(|c| {
            loss::require_no_loss_recovery(c)?;
            if self.admission(c).is_err() {
                self.recovery_export_admission(c)?;
            }
            self.export_checkpoint_admission(c, &manifest.checkpoint)?;
            ensure(present(c)?, "enable maintenance before pinning")?;
            let tx = c.unchecked_transaction()?;
            let stored: String = tx.query_row(
                "SELECT manifest FROM node_publication WHERE id=1",
                [],
                |r| r.get(0),
            )?;
            ensure(
                snapshot::Manifest::decode(stored.as_bytes())? == *manifest,
                "snapshot pin publication mismatch",
            )?;
            let digest = manifest.digest()?;
            let old: Option<String> = tx
                .query_row(
                    "SELECT digest FROM node_publication_pins WHERE pin=?1",
                    [pin],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(old) = old {
                ensure(old == digest, "snapshot pin conflict")?;
            } else {
                let count: u64 =
                    tx.query_row("SELECT count(*) FROM node_publication_pins", [], |r| {
                        r.get(0)
                    })?;
                ensure(count < 1024, "snapshot pin quota exceeded")?;
                tx.execute(
                    "INSERT INTO node_publication_pins VALUES(?1,?2)",
                    params![pin, digest],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
    }

    pub fn release_snapshot_pin(&mut self, manifest: &snapshot::Manifest, pin: &str) -> Result<()> {
        pin_key(pin)?;
        self.validate_manifest(manifest)?;
        self.connection(|c| {
            loss::require_no_loss_recovery(c)?;
            // Metadata cleanup may be needed after a survivor is sealed. It
            // never grants data access, writer admission or recovery authority.
            self.verify_owner(c)?;
            ensure(present(c)?, "maintenance not enabled")?;
            let tx = c.unchecked_transaction()?;
            let old: Option<String> = tx
                .query_row(
                    "SELECT digest FROM node_publication_pins WHERE pin=?1",
                    [pin],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(old) = old {
                ensure(old == manifest.digest()?, "snapshot pin release mismatch")?;
                tx.execute("DELETE FROM node_publication_pins WHERE pin=?1", [pin])?;
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Read-only, snapshot-consistent inspection; corruption is an error, not an
    /// eligibility report. An unresolved valid tail is reported but never pruned.
    pub fn plan_compaction(&self) -> Result<CompactionPlan> {
        self.connection(|c| {
            loss::require_no_loss_recovery(c)?;
            self.admission(c)?;
            let tx = c.unchecked_transaction()?;
            let checkpoint = self.current(&tx, false)?.0;
            let head = journal::head_for(&tx, &self.identity)?;
            let (entries, bytes): (u64, u64) = tx.query_row(
                "SELECT count(*),coalesce(sum(length(CAST(entry AS BLOB))),0) FROM replication_log WHERE sequence<=?1",
                [checkpoint.sequence], |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let publication = tx.query_row("SELECT manifest FROM node_publication WHERE id=1", [], |r| r.get::<_, String>(0)).optional()?
                .map(|json| {
                    let manifest = snapshot::Manifest::decode(json.as_bytes())?;
                    self.validate_manifest(&manifest)?;
                    Ok::<_, Box<dyn std::error::Error>>(manifest)
                }).transpose()?;
            let plan = CompactionPlan {
                format: 1, role: self.role, contract: self.contract.clone(),
                membership: self.recovery_membership(&tx)?,
                recovery_anchor: self.recovery_anchor(&tx)?,
                unresolved_tail: head.length != checkpoint.sequence,
                covered_journal_bytes: bytes, covered_journal_entries: entries,
                retained_receipts: checkpoint.sequence,
                head, checkpoint, publication,
            };
            tx.rollback()?;
            Ok(plan)
        })
    }
}
