//! Fail-closed page export from a permanently fenced certified survivor, and
//! the atomic local installation of the signed successor membership.
use super::*;
use crate::recovery::transition;
#[cfg(any(test, feature = "experimental-recovery"))]
use crate::recovery::transition::roles;
use sha2::{Digest, Sha256};
#[cfg(any(test, feature = "experimental-recovery"))]
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[cfg(test)]
mod tests;

/// Singleton install marker. It is inert evidence of a decided successor
/// membership; it never opens admission (I6) and is only ever written once.
const INSTALL_TABLE: &str = "recovery_loss_active";
#[cfg(any(test, feature = "experimental-recovery"))]
const INSTALL_DDL: &str = "CREATE TABLE IF NOT EXISTS main.recovery_loss_active(\
     id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)";
/// The install record now carries the issued successor token as well, so the
/// cap is the record's old 64 KiB plus room for a token of the largest size
/// the recovery crate will ever verify.
const INSTALL_LIMIT: usize = 256 * 1024;
/// Unchanged cap for the completion receipt, which carries no token.
const COMPLETION_LIMIT: usize = 64 * 1024;
/// Mirror of the recovery crate's private `MAX_TOKEN`: every token this module
/// stores or replays is bounded before it is decoded or verified.
const MAX_TOKEN: usize = 64 * 1024;
#[cfg(any(test, feature = "experimental-recovery"))]
/// Recovery metadata a certified survivor legitimately carries: its membership
/// came from a completed recovery. Anything else under `recovery_` fails closed.
const SURVIVOR_RECOVERY_TABLES: &[&str] = &[
    "recovery_active",
    "recovery_completion",
    "recovery_cycles",
    "recovery_delivery",
    "recovery_loss_aborted",
    "recovery_loss_active",
    "recovery_loss_completion",
    "recovery_loss_cycles",
    "recovery_seal",
];
#[cfg(any(test, feature = "experimental-recovery"))]
/// A bootstrap replacement has no recovery history of its own.
const REPLACEMENT_RECOVERY_TABLES: &[&str] = &["recovery_loss_active", "recovery_loss_completion"];
/// Append-only, hash-linked history of the loss recoveries this survivor has
/// already been through. Rows are only ever appended, never rewritten.
const CYCLES_TABLE: &str = "recovery_loss_cycles";
#[cfg(any(test, feature = "experimental-recovery"))]
const CYCLES_DDL: &str = "CREATE TABLE IF NOT EXISTS main.recovery_loss_cycles(\
     revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest TEXT NOT NULL)";
const MAX_CYCLE_ROWS: u64 = 1024;
/// Append-only, hash-linked tombstones of the successor memberships this
/// survivor installed and then un-installed under an authority-signed abort.
/// A successor named here can never be installed again, and its replacement
/// identity can never come back (S10).
const ABORTED_TABLE: &str = "recovery_loss_aborted";
#[cfg(any(test, feature = "experimental-recovery"))]
const ABORTED_DDL: &str = "CREATE TABLE IF NOT EXISTS main.recovery_loss_aborted(\
     revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest TEXT NOT NULL)";
/// Singleton local completion receipt. Only its presence *together with* a live
/// completed-successor proof can reopen ordinary admission (I6).
const COMPLETION_TABLE: &str = "recovery_loss_completion";
#[cfg(any(test, feature = "experimental-recovery"))]
const COMPLETION_DDL: &str = "CREATE TABLE IF NOT EXISTS main.recovery_loss_completion(\
     id INTEGER PRIMARY KEY CHECK(id=1),receipt TEXT NOT NULL)";
/// The single error every closed participant-loss path reports.
pub(super) const CLOSED: &str = "participant-loss recovery not complete; data admission closed";
/// Entry points this release keeps shut on a loss-recovered node.
pub(super) const RETIRED: &str = "closed after participant-loss recovery in this release";

#[cfg(any(test, feature = "experimental-recovery"))]
/// The live authorities every loss entry point must consult before and after
/// its durable step (I2). Borrowed, so nothing is cached across a call.
pub struct Authorities<'a, P: transition::LossPolicy> {
    pub source: &'a transition::Journal,
    pub successor: &'a transition::Journal,
    pub policy: &'a P,
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Everything `validate` derives from signed evidence. The survivor role is a
/// result, never a parameter: it exists only inside this module and is rebuilt
/// from the durable certificate on every validation.
pub(super) struct Evidence {
    role: Role,
    manifest: snapshot::Manifest,
}

/// Durable local record of the installed successor membership.
/// Written once per node, compared byte-for-byte on retry, never repaired.
///
/// Format 2 additionally stores the exact issued successor token. It is what
/// lets a later loss authenticate this recovery's founding successor *by
/// signature* under the node's own bound trust store, instead of trusting the
/// digests the node once wrote down. Format-1 records — written before this
/// existed — still decode and still serve the first-loss flow unchanged;
/// `serde_json` omits a skipped `None`, so their bytes are untouched.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Installed {
    format: u32,
    loss: transition::LossRequest,
    loss_certificate: [u8; 32],
    loss_token_digest: [u8; 32],
    successor: transition::LossSuccessorRequest,
    successor_certificate: [u8; 32],
    successor_token_digest: [u8; 32],
    /// Format 2 only, and then always present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    successor_token: Option<String>,
    source_scope: transition::JournalScope,
    member: [u8; 32],
    generation: [u8; 32],
    /// Role derived from the pre-loss certificate (I1).
    previous_role: Role,
    /// Role the owner row must carry once this record exists.
    installed_role: Role,
    survivor_cut: transition::Checkpoint,
    publication: [u8; 32],
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Restricted capability: it owns the normal node lock, opens SQLite read-only,
/// and exposes only the exact loss-bound frozen publication. The installer
/// opens a second, read-write connection to the same file for the duration of
/// one transaction; that connection is never stored here (I3).
pub struct LossSurvivorHandle<A: ReplicatedSchema> {
    db: Vesta,
    adapter: A,
    initial: String,
    /// Bound once at `open_existing`. Every later verification uses this store
    /// and never one supplied per call.
    trust: transition::TrustStore,
    identity: Identity<SchemaId>,
    /// Derived by [`validate`] from the signed loss decision and the certificate.
    role: Role,
    contract: schema_contract::Contract,
    manifest: snapshot::Manifest,
    request: transition::LossRequest,
    /// Canonical path and (device, inode) of the file that passed validation.
    /// The installer proves it is writing to exactly this file.
    path: PathBuf,
    file: (u64, u64),
    _lock: std::fs::File,
}

#[cfg(any(test, feature = "experimental-recovery"))]
impl<A: ReplicatedSchema> LossSurvivorHandle<A> {
    pub fn open_existing(
        path: impl AsRef<Path>,
        identity: Identity<SchemaId>,
        passphrase: &str,
        adapter: A,
        trust: &crate::recovery::transition::TrustStore,
        journal: &crate::recovery::transition::Journal,
        policy: &impl crate::recovery::transition::LossPolicy,
    ) -> Result<Self> {
        let path = path.as_ref();
        let path = path
            .parent()
            .ok_or("missing parent")?
            .canonicalize()?
            .join(path.file_name().ok_or("missing filename")?);
        ensure(path.is_file() && !path.is_symlink(), "loss survivor absent")?;
        let lock = crate::typed::open_node_lock(&path)?;
        let scratch = Connection::open_in_memory()?;
        schema::initialize(&scratch, &adapter)?;
        let contract = schema_contract::describe(&scratch, &adapter)?;
        let initial = hash(&adapter.view(&scratch)?)?;
        let db = Vesta::open_read_only_with_passphrase(&path, passphrase)?;
        let metadata = std::fs::metadata(&path)?;
        let file = (metadata.dev(), metadata.ino());
        let loss = journal.fetch_loss(&trust.as_trust(), policy)?;
        let request = loss.request().clone();
        let evidence = db.with_connection(|c| {
            c.pragma_update(None, "query_only", true)?;
            Ok(validate::<A>(
                c, &adapter, &identity, &contract, &initial, trust, &request,
            ))
        })??;
        Ok(Self {
            db,
            adapter,
            initial,
            trust: trust.clone(),
            identity,
            role: evidence.role,
            contract,
            manifest: evidence.manifest,
            request,
            path,
            file,
            _lock: lock,
        })
    }

    pub fn manifest(
        &self,
        journal: &crate::recovery::transition::Journal,
        policy: &impl crate::recovery::transition::LossPolicy,
    ) -> Result<snapshot::Manifest> {
        self.revalidate(journal, policy)?;
        Ok(self.manifest.clone())
    }

    pub fn page(
        &self,
        position: u64,
        journal: &crate::recovery::transition::Journal,
        policy: &impl crate::recovery::transition::LossPolicy,
    ) -> Result<snapshot::Page> {
        self.revalidate(journal, policy)?;
        ensure(position < self.manifest.pages, "loss page out of range")?;
        self.db.with_connection(|c| {
            Ok((|| -> Result<snapshot::Page> {
                let json: String = c.query_row(
                    "SELECT page FROM node_publication_pages WHERE position=?1",
                    [position],
                    |r| r.get(0),
                )?;
                let page = snapshot::Page::decode(json.as_bytes())?;
                ensure(
                    page.position == position && page.manifest_digest == self.manifest.digest()?,
                    "loss page binding mismatch",
                )?;
                Ok(page)
            })())
        })?
    }

    fn revalidate(
        &self,
        journal: &crate::recovery::transition::Journal,
        policy: &impl crate::recovery::transition::LossPolicy,
    ) -> Result<()> {
        let loss = journal.fetch_loss(&self.trust.as_trust(), policy)?;
        ensure(loss.request() == &self.request, "loss decision changed")?;
        self.db.with_connection(|c| {
            Ok((|| -> Result<()> {
                // The owner row still has to carry exactly the role the signed
                // evidence derived, or — once the successor membership is
                // durably installed — the role that record commits it to.
                let owner = survivor_owner_role(c, &self.request, self.role)?;
                let identities: Vec<String> = c
                    .prepare("SELECT value FROM main.node_identity")?
                    .query_map([], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                ensure(
                    identities == [serde_json::to_string(&(&self.identity, owner))?],
                    "loss survivor owner mismatch",
                )?;
                Node::<A>::verify_publication_in(c, &self.manifest, &self.identity, &self.contract)
            })())
        })??;
        Ok(())
    }

    /// The validated file must still be the file this path names. Checked on
    /// both sides of the read-write open so a swap under the held lock fails.
    fn require_same_file(&self) -> Result<()> {
        let metadata = std::fs::metadata(&self.path)?;
        ensure(
            !self.path.is_symlink() && (metadata.dev(), metadata.ino()) == self.file,
            "loss survivor file replaced",
        )
    }

    /// Live authorities plus the survivor-side bindings of the successor
    /// membership. The proof is fetched here (I2); a caller can never hand in
    /// one it made itself.
    fn install_record<P: transition::LossPolicy>(
        &self,
        successor: &transition::LossSuccessorRequest,
        authorities: &Authorities<'_, P>,
    ) -> Result<Installed> {
        let trust = &self.trust;
        self.revalidate(authorities.source, authorities.policy)?;
        let loss = authorities
            .source
            .fetch_loss(&trust.as_trust(), authorities.policy)?;
        ensure(loss.request() == &self.request, "loss decision changed")?;
        let proof = authorities.successor.fetch_loss_successor(
            successor,
            &trust.as_trust(),
            authorities.policy,
        )?;
        let request = proof.request();
        ensure(
            request == successor
                && proof.loss_request() == &self.request
                && proof.loss_certificate_id() == loss.certificate_id()
                && proof.loss_token_digest() == loss.token_digest()
                && request.parent_loss_certificate == proof.loss_certificate_id()
                && request.parent_loss_token_digest == proof.loss_token_digest()
                && successor_binds(request, &self.request),
            "loss successor installation mismatch",
        )?;
        require_canonical_role(request, request.survivor_index()?, self.role)?;
        // The token is what a later loss will re-verify by signature, so it is
        // bounded here, before it is ever written down.
        ensure(
            !proof.token().is_empty() && proof.token().len() <= MAX_TOKEN,
            "loss successor token limit",
        )?;
        Ok(Installed {
            format: 2,
            loss: self.request.clone(),
            loss_certificate: loss.certificate_id(),
            loss_token_digest: loss.token_digest(),
            successor: request.clone(),
            successor_certificate: proof.certificate_id(),
            successor_token_digest: proof.token_digest(),
            successor_token: Some(proof.token().to_owned()),
            source_scope: proof.source_scope().clone(),
            member: self.request.survivor.member,
            generation: self.request.survivor.generation,
            previous_role: self.role,
            // The survivor keeps its pre-loss role. Its historical artefacts —
            // the certified compaction lineage and `recovery_active` — are keyed
            // on that role, so re-labelling it would make the node permanently
            // unverifiable. The replacement takes the lost member's role, the
            // way `recovery::activate_member` promotes the restored candidate.
            installed_role: self.role,
            survivor_cut: self.request.survivor_cut.clone(),
            publication: self.request.survivor_publication,
        })
    }

    /// Atomically install the signed successor membership in this survivor.
    ///
    /// I3: the read-write connection is a local of this method. It is never
    /// stored in the handle, never reachable through an accessor and never
    /// handed to a caller-supplied closure; it is dropped before this returns.
    /// The node lock taken by `open_existing` is held throughout, so there is
    /// no unlock/relock gap between validation and the durable write.
    pub fn install_successor<P: transition::LossPolicy>(
        &self,
        passphrase: &str,
        successor: &transition::LossSuccessorRequest,
        authorities: &Authorities<'_, P>,
    ) -> Result<()> {
        let trust = &self.trust;
        let policy = authorities.policy;
        let source_journal = authorities.source;
        let successor_journal = authorities.successor;
        let record = self.install_record(successor, authorities)?;
        let expected = serde_json::to_string(&record)?;
        ensure(
            expected.len() <= INSTALL_LIMIT,
            "loss install record too large",
        )?;
        // The survivor's owner row is never written by this install.
        let owner_expected = serde_json::to_string(&(&self.identity, self.role))?;
        self.require_same_file()?;
        let rw = Vesta::open_existing_read_write_with_passphrase(&self.path, passphrase)?;
        let identity = self.require_same_file();
        let outcome = rw.with_connection(|c| {
            Ok((|| -> Result<()> {
                identity?;
                // Same durability profile the ordinary node open configures and
                // `Node::admission` insists on. No new pragmas are introduced.
                c.pragma_update(None, "synchronous", "FULL")?;
                c.pragma_update(None, "temp_store", "MEMORY")?;
                let synchronous: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
                let mode: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
                ensure(
                    synchronous == 2 && mode == "wal",
                    "loss install durability mismatch",
                )?;
                let tx = Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
                // I4: the complete evidence validation re-runs on this very
                // connection before anything is written.
                let evidence = validate::<A>(
                    &tx,
                    &self.adapter,
                    &self.identity,
                    &self.contract,
                    &self.initial,
                    trust,
                    &self.request,
                )?;
                ensure(
                    evidence.role == self.role && evidence.manifest == self.manifest,
                    "loss install evidence changed",
                )?;
                ensure_recovery_tables(&tx, SURVIVOR_RECOVERY_TABLES)?;
                // S10 replay protection: a successor membership this node has
                // already un-installed under a signed abort is never installed
                // again, whatever a rolled-back journal file claims.
                require_not_aborted(&tx, successor, record.successor_certificate)?;
                ensure(
                    checkpoint::generation(&tx)? == self.request.survivor.generation,
                    "loss install generation mismatch",
                )?;
                let owner = owner_row(&tx)?;
                ensure(owner == owner_expected, "loss install owner mismatch")?;
                if let Some((json, current)) = read_install(&tx)? {
                    if json == expected {
                        // I5: exact retry only.
                        tx.rollback()?;
                        return Ok(());
                    }
                    // Otherwise this must be the founding record of the
                    // recovery this loss retires; anything else is a conflict.
                    ensure(
                        matches!(
                            self.request.source_kind,
                            Some(transition::SourceKind::LossSuccessor)
                        ) && current.successor_certificate == self.request.source_certificate
                            && current.successor_token_digest == self.request.source_token_digest,
                        "loss install conflict",
                    )?;
                    retire_founding(&tx, &current, &self.request)?;
                }
                tx.execute_batch(INSTALL_DDL)?;
                ensure(
                    tx.execute(
                        "INSERT INTO main.recovery_loss_active VALUES(1,?1)",
                        [&expected],
                    )? == 1,
                    "loss install write failed",
                )?;
                let after = validate::<A>(
                    &tx,
                    &self.adapter,
                    &self.identity,
                    &self.contract,
                    &self.initial,
                    trust,
                    &self.request,
                )?;
                ensure(
                    after.role == self.role
                        && after.manifest == self.manifest
                        && owner_row(&tx)? == owner_expected
                        && read_install(&tx)?.map(|(json, _)| json).as_deref()
                            == Some(expected.as_str()),
                    "loss install post-state mismatch",
                )?;
                // I2: the last live authority check sits immediately before the
                // durable commit, so a revocation in between cannot be missed.
                ensure(
                    source_journal
                        .fetch_loss(&trust.as_trust(), policy)?
                        .request()
                        == &self.request,
                    "loss decision changed",
                )?;
                let live =
                    successor_journal.fetch_loss_successor(successor, &trust.as_trust(), policy)?;
                ensure(
                    live.request() == successor
                        && live.loss_request() == &self.request
                        && live.certificate_id() == record.successor_certificate
                        && live.token_digest() == record.successor_token_digest,
                    "loss successor decision changed",
                )?;
                tx.commit()?;
                Ok(())
            })())
        })?;
        drop(rw);
        outcome?;
        // Full revalidation through the retained read-only connection. That
        // connection still points at the inode validated at `open_existing`, so
        // requiring the exact record bytes here also catches a database swapped
        // in around the read-write open: the write would have landed elsewhere.
        let (evidence, durable) = self.db.with_connection(|c| {
            Ok((|| -> Result<(Evidence, Option<String>)> {
                let evidence = validate::<A>(
                    c,
                    &self.adapter,
                    &self.identity,
                    &self.contract,
                    &self.initial,
                    trust,
                    &self.request,
                )?;
                Ok((evidence, read_install(c)?.map(|(json, _)| json)))
            })())
        })??;
        ensure(
            evidence.role == self.role
                && evidence.manifest == self.manifest
                && durable.as_deref() == Some(expected.as_str()),
            "loss install revalidation mismatch",
        )?;
        self.revalidate(source_journal, policy)?;
        successor_journal.fetch_loss_successor(successor, &trust.as_trust(), policy)?;
        Ok(())
    }

    /// Atomically un-install the successor membership this survivor installed,
    /// under the authority's signed abort (S10).
    ///
    /// The abort is never a parameter: it is fetched live from the successor
    /// journal on both sides of the durable step (I2), so a caller can no more
    /// hand in an abort than it can hand in a loss decision. A *completed*
    /// successor is never un-installed — after completion a bad replacement is
    /// an ordinary new loss — and the replacement itself is never touched: it
    /// stays installed, closed for ever, and is discarded.
    ///
    /// The result is exactly the pre-install state: export-only, with ordinary
    /// admission still shut because the pre-loss certificate is superseded.
    pub fn abort_successor_install<P: transition::LossPolicy>(
        &self,
        passphrase: &str,
        successor: &transition::LossSuccessorRequest,
        authorities: &Authorities<'_, P>,
    ) -> Result<()> {
        let trust = &self.trust;
        let policy = authorities.policy;
        let source_journal = authorities.source;
        let successor_journal = authorities.successor;
        self.revalidate(source_journal, policy)?;
        let loss = source_journal.fetch_loss(&trust.as_trust(), policy)?;
        ensure(loss.request() == &self.request, "loss decision changed")?;
        let abort =
            successor_journal.fetch_loss_successor_abort(successor, &trust.as_trust(), policy)?;
        let owner_expected = serde_json::to_string(&(&self.identity, self.role))?;
        self.require_same_file()?;
        let rw = Vesta::open_existing_read_write_with_passphrase(&self.path, passphrase)?;
        let identity = self.require_same_file();
        let outcome = rw.with_connection(|c| {
            Ok((|| -> Result<()> {
                identity?;
                c.pragma_update(None, "synchronous", "FULL")?;
                c.pragma_update(None, "temp_store", "MEMORY")?;
                let synchronous: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
                let mode: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
                ensure(
                    synchronous == 2 && mode == "wal",
                    "loss install durability mismatch",
                )?;
                let tx = Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
                // I4: the full evidence validation re-runs on this very
                // connection before anything is written.
                let evidence = validate::<A>(
                    &tx,
                    &self.adapter,
                    &self.identity,
                    &self.contract,
                    &self.initial,
                    trust,
                    &self.request,
                )?;
                ensure(
                    evidence.role == self.role && evidence.manifest == self.manifest,
                    "loss un-install evidence changed",
                )?;
                ensure_recovery_tables(&tx, SURVIVOR_RECOVERY_TABLES)?;
                ensure(
                    owner_row(&tx)? == owner_expected,
                    "loss un-install owner mismatch",
                )?;
                match read_install(&tx)? {
                    // I5: exact retry. The tombstone is already durable and the
                    // active record is already gone; nothing is repaired. Every
                    // field this abort determines must match; `parent` belongs
                    // to the chain and `visit_aborted` has already checked it.
                    None => {
                        let mut last: Option<AbortedSuccessor> = None;
                        visit_aborted(&tx, |row| {
                            last = Some(row.clone());
                            Ok(())
                        })?;
                        let row = last.ok_or("participant-loss un-install conflict")?;
                        ensure(
                            // The authority may already have superseded the
                            // attempt this abort cancelled, so the tombstone's
                            // loss is bound by lineage; every value the abort
                            // itself determines is bound exactly.
                            same_attempt(&row.loss, loss.request())
                                && row.loss_certificate == abort.abort().parent_loss_certificate
                                && row.loss_token_digest == abort.abort().parent_loss_token_digest
                                && row.successor_id == abort.abort().successor_id
                                && row.successor_certificate == abort.abort().successor_certificate
                                && row.successor_token_digest
                                    == abort.abort().successor_token_digest
                                && row.abort_certificate == abort.certificate_id()
                                && row.abort_token_digest == abort.token_digest()
                                && row.fencing_ref == abort.fencing_ref(),
                            "participant-loss un-install conflict",
                        )?;
                        tx.rollback()?;
                        return Ok(());
                    }
                    Some((_, record)) => {
                        // A completed recovery is never un-installed.
                        ensure(
                            read_completion(&tx)?.is_none(),
                            "completed participant-loss recovery cannot be un-installed",
                        )?;
                        ensure(
                            record.loss == self.request
                                && record.successor == *successor
                                && record.successor.id == abort.abort().successor_id
                                && record.successor_certificate
                                    == abort.abort().successor_certificate
                                && record.successor_token_digest
                                    == abort.abort().successor_token_digest
                                && record.loss_certificate == abort.abort().parent_loss_certificate
                                && record.loss_token_digest
                                    == abort.abort().parent_loss_token_digest
                                && record.member == self.request.survivor.member
                                && record.previous_role == self.role
                                && record.installed_role == self.role,
                            "participant-loss un-install binding mismatch",
                        )?;
                    }
                }
                let tombstone = aborted_record(&tx, &loss, &abort)?;
                let json = serde_json::to_string(&tombstone)?;
                ensure(
                    json.len() <= INSTALL_LIMIT,
                    "participant-loss tombstone too large",
                )?;
                tx.execute_batch(ABORTED_DDL)?;
                ensure(
                    tx.execute(
                        "INSERT INTO main.recovery_loss_aborted VALUES(?1,?2,?3)",
                        params![self.request.revision, json, hash(&tombstone)?],
                    )? == 1,
                    "participant-loss tombstone write failed",
                )?;
                ensure(
                    tx.execute("DELETE FROM main.recovery_loss_active WHERE id=1", [])? == 1,
                    "participant-loss un-install failed",
                )?;
                // An empty singleton table is a partial state, not an empty
                // slot, so the slot itself goes with the record.
                tx.execute_batch("DROP TABLE main.recovery_loss_active")?;
                // Post-state: no active record, no completion, the owner row
                // untouched, and the whole evidence path still validating.
                let after = validate::<A>(
                    &tx,
                    &self.adapter,
                    &self.identity,
                    &self.contract,
                    &self.initial,
                    trust,
                    &self.request,
                )?;
                ensure(
                    after.role == self.role
                        && after.manifest == self.manifest
                        && state(&tx)?.is_none()
                        && !table_exists(&tx, COMPLETION_TABLE)?
                        && owner_row(&tx)? == owner_expected,
                    "participant-loss un-install post-state mismatch",
                )?;
                // I2: the last live checks sit immediately before the commit.
                ensure(
                    source_journal
                        .fetch_loss(&trust.as_trust(), policy)?
                        .request()
                        == &self.request,
                    "loss decision changed",
                )?;
                let live = successor_journal.fetch_loss_successor_abort(
                    successor,
                    &trust.as_trust(),
                    policy,
                )?;
                ensure(
                    live.abort() == abort.abort()
                        && live.certificate_id() == abort.certificate_id()
                        && live.token_digest() == abort.token_digest(),
                    "loss successor abort changed",
                )?;
                tx.commit()?;
                Ok(())
            })())
        })?;
        drop(rw);
        outcome?;
        // Full revalidation through the retained read-only connection, which
        // still points at the inode validated at `open_existing`.
        let (evidence, durable) = self.db.with_connection(|c| {
            Ok((|| -> Result<(Evidence, Option<Installed>)> {
                let evidence = validate::<A>(
                    c,
                    &self.adapter,
                    &self.identity,
                    &self.contract,
                    &self.initial,
                    trust,
                    &self.request,
                )?;
                Ok((evidence, state(c)?))
            })())
        })??;
        ensure(
            evidence.role == self.role && evidence.manifest == self.manifest && durable.is_none(),
            "participant-loss un-install revalidation mismatch",
        )?;
        self.revalidate(source_journal, policy)?;
        successor_journal.fetch_loss_successor_abort(successor, &trust.as_trust(), policy)?;
        Ok(())
    }
}

/// The tombstone a signed abort commits this survivor to, hash-linked to the
/// tombstones already recorded.
#[cfg(any(test, feature = "experimental-recovery"))]
fn aborted_record(
    c: &Connection,
    loss: &transition::CommittedLoss,
    abort: &transition::CommittedLossSuccessorAbort,
) -> Result<AbortedSuccessor> {
    let mut parent = None;
    let mut previous: Option<u64> = None;
    visit_aborted(c, |row| {
        parent = Some(hash(row)?);
        previous = Some(row.loss.revision);
        Ok(())
    })?;
    ensure(
        previous.is_none_or(|p| p < loss.request().revision),
        "participant-loss tombstone revision reuse",
    )?;
    Ok(AbortedSuccessor {
        parent,
        loss: loss.request().clone(),
        // Taken from the abort, not from the loss read: the tombstone must
        // name exactly the decision the signed abort names as its parent.
        loss_certificate: abort.abort().parent_loss_certificate,
        loss_token_digest: abort.abort().parent_loss_token_digest,
        successor_id: abort.abort().successor_id,
        successor_certificate: abort.abort().successor_certificate,
        successor_token_digest: abort.abort().successor_token_digest,
        abort_certificate: abort.certificate_id(),
        abort_token_digest: abort.token_digest(),
        fencing_ref: abort.fencing_ref(),
    })
}

fn owner_row(c: &Connection) -> Result<String> {
    let identities: Vec<String> = c
        .prepare("SELECT value FROM main.node_identity")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(identities.len() == 1, "loss owner row mismatch")?;
    Ok(identities.into_iter().next().ok_or("loss owner row")?)
}

/// Schema lookups are always qualified to `main`, so a TEMP object can never
/// shadow a participant-loss table.
fn table_exists(c: &Connection, name: &str) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    )?)
}

/// Bounded singleton read: the row count and the largest record are measured
/// before any record is materialised.
fn singleton(c: &Connection, table: &str, column: &str, limit: usize) -> Result<Option<String>> {
    if !table_exists(c, table)? {
        return Ok(None);
    }
    let (rows, longest): (u64, u64) = c.query_row(
        &format!(
            "SELECT count(*),coalesce(max(length(CAST({column} AS BLOB))),0) FROM main.{table}"
        ),
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure(
        rows == 1 && longest <= limit as u64,
        "participant-loss singleton mismatch",
    )?;
    let (id, value): (u32, String) = c.query_row(
        &format!("SELECT id,{column} FROM main.{table} LIMIT 2"),
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure(id == 1, "participant-loss singleton mismatch")?;
    Ok(Some(value))
}

/// The `recovery_*` tables this node kind may legitimately carry. The kind is
/// decided by comparing this node's position with the successor's own
/// `survivor_index`, never by assuming a fixed slot.
#[cfg(any(test, feature = "experimental-recovery"))]
fn recovery_tables_for(record: &Installed) -> Result<&'static [&'static str]> {
    // Which participant this node is, never which slot it occupies: format 2
    // orders participants canonically, so the survivor may sit at either index.
    Ok(
        if successor_index(record)? == record.successor.survivor_index()? {
            SURVIVOR_RECOVERY_TABLES
        } else {
            REPLACEMENT_RECOVERY_TABLES
        },
    )
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Only the recovery metadata this kind of node is allowed to carry may exist.
/// An unexpected `recovery_*` table — including a completion record this slice
/// never writes — fails closed instead of being ignored.
fn ensure_recovery_tables(c: &Connection, allowed: &[&str]) -> Result<()> {
    let present: Vec<(String, String)> = c
        .prepare(
            "SELECT type,name FROM main.sqlite_schema \
             WHERE name LIKE 'recovery\\_%' ESCAPE '\\' ORDER BY type,name",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (kind, name) in present {
        ensure(
            kind == "table" && allowed.contains(&name.as_str()),
            "unexpected recovery state",
        )?;
    }
    Ok(())
}

/// The singleton install record, with the size and shape caps of I9. More than
/// one row, a wrong id or an oversized record is a conflict, never a repair.
/// Format 1 carries no successor token and format 2 always does; anything else
/// is refused rather than interpreted.
fn read_install(c: &Connection) -> Result<Option<(String, Installed)>> {
    let Some(json) = singleton(c, INSTALL_TABLE, "record", INSTALL_LIMIT)? else {
        return Ok(None);
    };
    let record: Installed = serde_json::from_str(&json)?;
    ensure(
        match (record.format, record.successor_token.as_deref()) {
            (1, None) => true,
            (2, Some(token)) => !token.is_empty() && token.len() <= MAX_TOKEN,
            _ => false,
        },
        "loss install format",
    )?;
    Ok(Some((json, record)))
}

/// One retired loss recovery: the record that founded it, the completion
/// receipt that closed it, and the loss that retired it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetiredLoss {
    parent: Option<String>,
    installed: Installed,
    completion: String,
    next: transition::LossRequest,
}

/// Walk the append-only cycle chain, verifying the hash link and every stored
/// receipt. Bounded before any row is decoded.
fn visit_cycles(c: &Connection, mut visit: impl FnMut(&RetiredLoss) -> Result<()>) -> Result<()> {
    if !table_exists(c, CYCLES_TABLE)? {
        return Ok(());
    }
    let (rows, longest): (u64, u64) = c.query_row(
        "SELECT count(*),coalesce(max(length(CAST(record AS BLOB))),0) \
         FROM main.recovery_loss_cycles",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure(
        rows <= MAX_CYCLE_ROWS && longest <= 256 * 1024,
        "participant-loss cycle limit",
    )?;
    let mut parent: Option<String> = None;
    let mut previous: Option<u64> = None;
    // The loss that retired the previous row. It must be exactly the loss the
    // next row's record was installed by, so neither a removed row nor a
    // reordered one can pass as history.
    let mut previous_next: Option<transition::LossRequest> = None;
    let mut statement = c.prepare(
        "SELECT revision,record,digest FROM main.recovery_loss_cycles ORDER BY revision",
    )?;
    let mut cursor = statement.query([])?;
    while let Some(row) = cursor.next()? {
        let revision: u64 = row.get(0)?;
        let json: String = row.get(1)?;
        let stored: String = row.get(2)?;
        let record: RetiredLoss = serde_json::from_str(&json)?;
        ensure(
            stored == hash(&record)?
                && record.parent == parent
                && revision == record.installed.loss.revision
                && previous.is_none_or(|p| p < revision)
                // Only a recovery that could found a second loss can ever have
                // been retired by one, so every retired record carries a token.
                && record.installed.format == 2
                && record.installed.successor_token.is_some()
                && record.next.revision > revision
                && match &previous_next {
                    Some(next) => *next == record.installed.loss,
                    // The oldest retirement is the pair's first loss: it was
                    // founded by a certificate, never by an earlier recovery.
                    None => record.installed.loss.kind() != transition::SourceKind::LossSuccessor,
                },
            "participant-loss cycle chain mismatch",
        )?;
        let receipt: CompletionReceipt = serde_json::from_str(&record.completion)?;
        ensure(
            receipt.0 == 1
                && receipt.1 == record.installed.successor.id
                && receipt.2 == record.installed.successor_token_digest
                && receipt.3 == record.installed.successor_certificate
                && receipt.4 != [0; 32],
            "participant-loss retired completion mismatch",
        )?;
        visit(&record)?;
        parent = Some(stored);
        previous = Some(revision);
        previous_next = Some(record.next);
    }
    Ok(())
}

/// Every member, generation and membership one recovery burns for good.
#[cfg(any(test, feature = "experimental-recovery"))]
fn retired_of(record: &Installed) -> [[u8; 32]; 8] {
    [
        record.member,
        record.generation,
        record.loss.lost_member,
        record.loss.lost_generation,
        record.loss.replacement_member,
        record.loss.replacement_generation,
        record.loss.membership,
        record.successor.membership,
    ]
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Every member, generation and membership this node has already retired —
/// through a completed recovery *or* through an aborted successor. A
/// replacement may never reuse any of them, whatever the journal says.
fn retired_identities(c: &Connection) -> Result<Vec<[u8; 32]>> {
    let mut retired = Vec::new();
    visit_cycles(c, |record| {
        retired.extend(retired_of(&record.installed));
        Ok(())
    })?;
    visit_aborted(c, |row| {
        // An aborted replacement is fenced for good: its member, generation
        // and membership are burnt exactly as a completed one's are.
        retired.extend([
            row.loss.lost_member,
            row.loss.lost_generation,
            row.loss.replacement_member,
            row.loss.replacement_generation,
            row.loss.membership,
            row.loss.replacement_membership,
        ]);
        Ok(())
    })?;
    Ok(retired)
}

/// One un-installed successor membership: the loss it belonged to, the
/// successor it activated and the signed abort that cancelled it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AbortedSuccessor {
    parent: Option<String>,
    loss: transition::LossRequest,
    /// The loss's own certificate id and token digest. `Supersedes` names the
    /// superseded loss by exactly these two values, so without them the node
    /// could not bind a superseding decision to its own tombstone.
    loss_certificate: [u8; 32],
    loss_token_digest: [u8; 32],
    successor_id: [u8; 32],
    successor_certificate: [u8; 32],
    successor_token_digest: [u8; 32],
    abort_certificate: [u8; 32],
    abort_token_digest: [u8; 32],
    /// The abort's opaque fencing reference, kept so the tombstone records
    /// *why* the replacement may never return.
    fencing_ref: [u8; 32],
}

/// Walk the append-only tombstone chain, verifying the hash link. Bounded
/// before any row is decoded, exactly like the cycle history.
fn visit_aborted(
    c: &Connection,
    mut visit: impl FnMut(&AbortedSuccessor) -> Result<()>,
) -> Result<()> {
    if !table_exists(c, ABORTED_TABLE)? {
        return Ok(());
    }
    let (rows, longest): (u64, u64) = c.query_row(
        "SELECT count(*),coalesce(max(length(CAST(record AS BLOB))),0) \
         FROM main.recovery_loss_aborted",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    // An existing table with no rows at all is a partial state, not an empty
    // history: an un-installation writes its row and drops the active record
    // in one transaction.
    ensure(
        (1..=MAX_CYCLE_ROWS).contains(&rows) && longest <= 256 * 1024,
        "participant-loss tombstone limit",
    )?;
    let mut parent: Option<String> = None;
    let mut previous: Option<u64> = None;
    let mut statement = c.prepare(
        "SELECT revision,record,digest FROM main.recovery_loss_aborted ORDER BY revision",
    )?;
    let mut cursor = statement.query([])?;
    while let Some(row) = cursor.next()? {
        let revision: u64 = row.get(0)?;
        let json: String = row.get(1)?;
        let stored: String = row.get(2)?;
        let record: AbortedSuccessor = serde_json::from_str(&json)?;
        ensure(
            stored == hash(&record)?
                && record.parent == parent
                && revision == record.loss.revision
                && previous.is_none_or(|p| p < revision)
                && record.loss_certificate != [0; 32]
                && record.loss_token_digest != [0; 32]
                && record.successor_id != [0; 32]
                && record.successor_certificate != [0; 32]
                && record.successor_token_digest != [0; 32]
                && record.abort_certificate != [0; 32]
                && record.abort_token_digest != [0; 32]
                && record.fencing_ref != [0; 32],
            "participant-loss tombstone chain mismatch",
        )?;
        visit(&record)?;
        parent = Some(stored);
        previous = Some(revision);
    }
    Ok(())
}

/// An in-flight certified maintenance would be wedged for ever once the loss
/// gates close, so it has to be resolved *before* the irreversible install and
/// never discovered afterwards (S11).
///
/// A loss that abandons one names it with `abandoned_request`, and the node
/// must carry the durable trace of having terminated exactly that request —
/// rolled back for `Completed`, finished forward for `Decided`. While the
/// pending tables are still there the operator is told which step it owes, and
/// an `abandoned_request` on a node that never had that request is refused:
/// the field can never be padding.
#[cfg(any(test, feature = "experimental-recovery"))]
fn require_maintenance_terminated(c: &Connection, loss: &transition::LossRequest) -> Result<()> {
    let pending = table_exists(c, "node_pending_certified_maintenance")?
        || table_exists(c, "node_pending_certified_progress")?;
    let trace = super::pending::terminated(c)?;
    let Some(abandoned) = loss.abandoned_request else {
        // No abandonment claimed: the old rule, unchanged. A node with pending
        // maintenance is refused outright, and a stale trace from an earlier,
        // unrelated termination may not stand in for this loss.
        ensure(!pending, "loss survivor has pending certified maintenance")?;
        return ensure(
            trace
                .as_ref()
                .is_none_or(|t| same_attempt(t.loss(), loss) || t.loss() == loss),
            "loss survivor has an unrelated terminated maintenance",
        );
    };
    if pending {
        return Err(match loss.kind() {
            transition::SourceKind::Decided => {
                "loss survivor must finish forward abandoned maintenance first"
            }
            _ => "loss survivor must roll back abandoned maintenance first",
        }
        .into());
    }
    // The trace is the only local proof that this node ever had that request
    // and that it was terminated by this very loss.
    let trace = trace.ok_or("loss survivor never abandoned that maintenance")?;
    ensure(
        trace.abandoned() == abandoned,
        "loss survivor never abandoned that maintenance",
    )?;
    ensure(
        trace.loss() == loss || same_attempt(trace.loss(), loss),
        "loss survivor abandoned maintenance for another loss",
    )?;
    ensure(
        trace.is_finished_forward() == (loss.kind() == transition::SourceKind::Decided),
        "loss survivor terminated that maintenance the other way",
    )
}

/// A node whose completion archive is the format-2, loss-authenticated one
/// names exactly one loss. Once that loss has installed — or has itself been
/// retired into the cycle history — the durable record must be the same loss.
/// Before the install there is no record at all and the termination trace
/// stands alone; that is exactly the window in which the survivor is
/// export-only and ordinary admission is shut.
pub(super) fn require_terminating_loss(
    c: &Connection,
    loss: &transition::LossRequest,
) -> Result<()> {
    let mut known = Vec::new();
    if let Some((_, record)) = read_install(c)? {
        known.push(record.loss);
    }
    visit_cycles(c, |row| {
        known.push(row.installed.loss.clone());
        Ok(())
    })?;
    ensure(
        known.is_empty() || known.iter().any(|l| same_attempt(loss, l)),
        "participant-loss termination record mismatch",
    )
}

/// Everything a superseding loss must keep identical to the loss it replaces.
/// This is the recovery crate's own rule set, mirrored so the node can never
/// accept a "supersession" the journal would have refused, and so a tombstone
/// can be recognised as belonging to the same lineage as a later attempt.
fn same_lineage(previous: &transition::LossRequest, next: &transition::LossRequest) -> bool {
    previous.format == next.format
        && previous.kind() == next.kind()
        && previous.authority_id == next.authority_id
        && previous.install == next.install
        && previous.region == next.region
        && previous.scope == next.scope
        && previous.schema == next.schema
        && previous.membership == next.membership
        && previous.source_certificate == next.source_certificate
        && previous.source_token_digest == next.source_token_digest
        && previous.source_cut == next.source_cut
        && previous.lost_member == next.lost_member
        && previous.lost_generation == next.lost_generation
        && previous.survivor == next.survivor
        && previous.survivor_cut == next.survivor_cut
        && previous.survivor_publication == next.survivor_publication
        && previous.abandoned_request == next.abandoned_request
}

/// True when `next` is `previous` itself or a loss that supersedes it.
fn same_attempt(previous: &transition::LossRequest, next: &transition::LossRequest) -> bool {
    previous == next || (next.supersedes.is_some() && same_lineage(previous, next))
}

/// A successor membership that was un-installed under a signed abort can never
/// be installed again — not from a rolled-back journal file, not ever.
#[cfg(any(test, feature = "experimental-recovery"))]
fn require_not_aborted(
    c: &Connection,
    successor: &transition::LossSuccessorRequest,
    certificate: [u8; 32],
) -> Result<()> {
    let mut conflict = false;
    visit_aborted(c, |row| {
        // Either identifier is enough: a replay can reuse the request id, the
        // certificate id, or both.
        conflict |= row.successor_id == successor.id || row.successor_certificate == certificate;
        Ok(())
    })?;
    ensure(!conflict, "aborted loss successor cannot be installed")
}

/// The tombstone that authorises `loss` to supersede an earlier attempt, read
/// from this node's own append-only history. The authority's journal ran the
/// same rule set; this file is a different trust domain and runs it again.
#[cfg(any(test, feature = "experimental-recovery"))]
fn require_supersession(c: &Connection, loss: &transition::LossRequest) -> Result<()> {
    let Some(supersedes) = loss.supersedes.as_ref() else {
        return Ok(());
    };
    let mut superseded: Option<transition::LossRequest> = None;
    visit_aborted(c, |row| {
        if row.loss_certificate == supersedes.loss_certificate
            && row.loss_token_digest == supersedes.loss_token_digest
            && row.abort_certificate == supersedes.abort_certificate
            && row.abort_token_digest == supersedes.abort_token_digest
        {
            superseded = Some(row.loss.clone());
        }
        Ok(())
    })?;
    let previous = superseded.ok_or("superseded loss has no local tombstone")?;
    ensure(
        same_lineage(&previous, loss),
        "superseding loss changes more than the replacement",
    )?;
    ensure(
        loss.revision > previous.revision
            && loss.replacement_member != previous.replacement_member
            && loss.replacement_generation != previous.replacement_generation
            && loss.replacement_membership != previous.replacement_membership,
        "superseding loss reuses a retired replacement",
    )?;
    // No identity this node has already burnt — through a completed recovery
    // or through an abort — may ever come back as the new replacement.
    let already = retired_identities(c)?;
    ensure(
        ![
            loss.replacement_member,
            loss.replacement_generation,
            loss.replacement_membership,
        ]
        .iter()
        .any(|id| already.contains(id)),
        "participant-loss identity reuse",
    )
}

/// Structural binding of a successor membership to its parent loss decision.
fn successor_binds(
    successor: &transition::LossSuccessorRequest,
    loss: &transition::LossRequest,
) -> bool {
    successor.authority_id == loss.authority_id
        && successor.install == loss.install
        && successor.region == loss.region
        && successor.scope == loss.scope
        && successor.schema == loss.schema
        && successor.membership == loss.replacement_membership
        && successor.source_certificate == loss.source_certificate
        && successor.source_token_digest == loss.source_token_digest
        && successor.source_cut == loss.source_cut
        && successor.survivor_cut == loss.survivor_cut
        && successor.survivor_publication == loss.survivor_publication
        && matches!(
            (successor.survivor(), successor.replacement()),
            (Ok(s), Ok(r))
                if s.member == loss.survivor.member
                    && s.generation == loss.survivor.generation
                    && r.member == loss.replacement_member
                    && r.generation == loss.replacement_generation
        )
}

/// The role the canonical participant order implies for `index`. Format 1
/// ordered participants `[survivor, replacement]` and carries no role, so it
/// has none; format 2 orders them `[primary, secondary]`.
#[cfg(any(test, feature = "experimental-recovery"))]
fn canonical_role(
    successor: &transition::LossSuccessorRequest,
    index: usize,
) -> Result<Option<Role>> {
    Ok(match successor.format {
        1 => None,
        2 => Some(if index == 0 {
            Role::Primary
        } else {
            Role::Secondary
        }),
        _ => return Err("unsupported loss successor format".into()),
    })
}

/// A format-2 successor states each participant's role twice: once through the
/// canonical order and once through the evidence the install derived it from.
/// They must agree, or the successor is not describing this pair.
#[cfg(any(test, feature = "experimental-recovery"))]
fn require_canonical_role(
    successor: &transition::LossSuccessorRequest,
    index: usize,
    derived: Role,
) -> Result<()> {
    ensure(
        canonical_role(successor, index)?.is_none_or(|role| role == derived),
        "loss successor role mismatch",
    )
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Installation-aware owner expectation for a survivor file. The pre-loss role
/// always comes from signed evidence (I1) and is never an input; a durable
/// install may additionally have promoted the owner row, and only then must the
/// record exist and bind exactly to this loss decision.
fn survivor_owner_role(
    c: &Connection,
    loss: &transition::LossRequest,
    derived: Role,
) -> Result<Role> {
    let Some((_, record)) = read_install(c)? else {
        return Ok(derived);
    };
    // The record may be the install of THIS loss, or the founding record of
    // the recovery this loss retires. They are told apart by exact binding,
    // never by a flag: a founding record leaves the owner row alone.
    if record.loss != *loss {
        ensure(
            matches!(
                loss.source_kind,
                Some(transition::SourceKind::LossSuccessor)
            ) && record.successor_certificate == loss.source_certificate
                && record.successor_token_digest == loss.source_token_digest
                && record.member == loss.survivor.member
                && record.generation == loss.survivor.generation
                // The role the founding successor's participant order implies
                // is the role that record already committed this node to.
                && record.installed_role == derived,
            "loss install record mismatch",
        )?;
        return Ok(derived);
    }
    ensure(
        record.loss == *loss
            // The survivor keeps its derived role: an install that claims to
            // have re-labelled it is a conflict, not a state to adopt.
            && record.previous_role == derived
            && record.installed_role == derived
            && record.member == loss.survivor.member
            && record.generation == loss.survivor.generation
            && record.survivor_cut == loss.survivor_cut
            && record.publication == loss.survivor_publication
            && successor_binds(&record.successor, loss),
        "loss install record mismatch",
    )?;
    Ok(record.installed_role)
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// The role the replacement inherits, derived from the signed source
/// certificate named by the signed loss decision. The certificate is pinned by
/// `source_certificate` + `source_token_digest`, so a caller cannot substitute
/// one; the index of the lost member inside it decides the role, exactly as I1
/// decides the survivor's. No caller-supplied role or boolean is involved.
/// The signed document a loss is founded on, supplied by the operator exactly
/// as the authority issued it. Both arms are authenticated by signature and
/// pinned to the loss's `source_certificate`/`source_token_digest`; neither
/// carries a role, so the role is always read out of the participant order.
#[cfg(any(test, feature = "experimental-recovery"))]
pub enum Founding {
    /// The certified compaction that founded an ordinary pair.
    Certificate(transition::Request, String),
    /// The completed loss successor that founded an already-recovered pair.
    Successor(transition::LossSuccessorRequest, String),
}

#[cfg(any(test, feature = "experimental-recovery"))]
impl Founding {
    /// Authenticate the document and pin it to this loss, then return the role
    /// the *lost* member held. The replacement inherits exactly that role.
    fn lost_role(
        &self,
        trust: &transition::TrustStore,
        loss: &transition::LossRequest,
    ) -> Result<Role> {
        match self {
            Self::Certificate(certificate, token) => {
                let verified =
                    transition::verify_historical(token, &trust.as_trust(), certificate)?;
                ensure(
                    verified.certificate_id() == loss.source_certificate
                        && verified.token_digest() == loss.source_token_digest
                        && certificate.membership == loss.membership
                        && certificate.authority_id == loss.authority_id
                        && certificate.install == loss.install
                        && certificate.region == loss.region
                        && certificate.scope == loss.scope
                        && certificate.schema == loss.schema,
                    "loss replacement certificate mismatch",
                )?;
                let index = sole_participant(
                    &certificate.participants,
                    loss.lost_member,
                    loss.lost_generation,
                    "certified",
                )?;
                let survivor = &certificate.participants[1 - index];
                ensure(
                    survivor.member == loss.survivor.member
                        && survivor.generation == loss.survivor.generation,
                    "loss survivor participant mismatch",
                )?;
                // The certified order is canonical: index 0 is the Primary.
                Ok(if index == 0 {
                    Role::Primary
                } else {
                    Role::Secondary
                })
            }
            Self::Successor(successor, token) => {
                let certificate =
                    transition::verify_successor_historical(token, &trust.as_trust(), successor)?;
                ensure(
                    certificate == loss.source_certificate
                        && !token.is_empty()
                        && token.len() <= MAX_TOKEN
                        && Sha256::digest(token.as_bytes()).as_slice() == loss.source_token_digest
                        && successor.format == 2
                        && successor.membership == loss.membership
                        && successor.authority_id == loss.authority_id
                        && successor.install == loss.install
                        && successor.region == loss.region
                        && successor.scope == loss.scope
                        && successor.schema == loss.schema,
                    "loss founding successor mismatch",
                )?;
                let index = sole_participant(
                    &successor.participants,
                    loss.lost_member,
                    loss.lost_generation,
                    "founding",
                )?;
                let survivor = &successor.participants[1 - index];
                ensure(
                    survivor.member == loss.survivor.member
                        && survivor.generation == loss.survivor.generation,
                    "loss survivor participant mismatch",
                )?;
                // A format-2 successor is ordered `[primary, secondary]`.
                Ok(if index == 0 {
                    Role::Primary
                } else {
                    Role::Secondary
                })
            }
        }
    }
}

/// Exactly one participant may carry this member and generation.
#[cfg(any(test, feature = "experimental-recovery"))]
fn sole_participant(
    participants: &[transition::Participant; 2],
    member: [u8; 32],
    generation: [u8; 32],
    what: &str,
) -> Result<usize> {
    let mut matches = participants
        .iter()
        .enumerate()
        .filter(|(_, p)| p.member == member && p.generation == generation);
    let index = match matches.next() {
        Some((index, _)) => index,
        None => return Err(format!("loss lost member not {what}").into()),
    };
    ensure(matches.next().is_none(), "loss lost member ambiguous")?;
    Ok(index)
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Durable installation of the same signed successor membership on the
/// replacement, which takes over the lost member's role. It depends only on
/// signed data, this node and the journals: in production the survivor is a
/// different machine and is not reachable here.
pub fn install_replacement<A: ReplicatedSchema, P: transition::LossPolicy>(
    replacement: &mut Node<A>,
    founding: &Founding,
    successor: &transition::LossSuccessorRequest,
    authorities: &Authorities<'_, P>,
) -> Result<()> {
    // The replacement verifies under the trust store it was configured with,
    // never one handed in with the call.
    let trust = replacement
        .transition_trust
        .clone()
        .ok_or("participant-loss replacement requires transition trust")?;
    let trust = &trust;
    let policy = authorities.policy;
    let loss = authorities.source.fetch_loss(&trust.as_trust(), policy)?;
    let proof = authorities
        .successor
        .fetch_loss_successor(successor, &trust.as_trust(), policy)?;
    let request = proof.request();
    let parent = proof.loss_request();
    ensure(
        request == successor
            && parent == loss.request()
            && proof.loss_certificate_id() == loss.certificate_id()
            && proof.loss_token_digest() == loss.token_digest()
            && request.parent_loss_certificate == proof.loss_certificate_id()
            && request.parent_loss_token_digest == proof.loss_token_digest()
            && successor_binds(request, parent),
        "loss replacement installation mismatch",
    )?;
    // An abandoned in-flight maintenance is the *survivor's* business: this
    // file is a fresh replacement and never had that request. The lost role
    // still comes only from the signed founding document below.
    let installed_role = founding.lost_role(trust, parent)?;
    require_canonical_role(request, roles(request)?.1, installed_role)?;
    ensure(
        !proof.token().is_empty() && proof.token().len() <= MAX_TOKEN,
        "loss successor token limit",
    )?;
    let record = Installed {
        format: 2,
        loss: parent.clone(),
        loss_certificate: proof.loss_certificate_id(),
        loss_token_digest: proof.loss_token_digest(),
        successor: request.clone(),
        successor_certificate: proof.certificate_id(),
        successor_token_digest: proof.token_digest(),
        successor_token: Some(proof.token().to_owned()),
        source_scope: proof.source_scope().clone(),
        member: parent.replacement_member,
        generation: parent.replacement_generation,
        // A replacement is always a bootstrap Secondary before the install.
        previous_role: Role::Secondary,
        installed_role,
        survivor_cut: parent.survivor_cut.clone(),
        publication: parent.survivor_publication,
    };
    let expected = serde_json::to_string(&record)?;
    ensure(
        expected.len() <= INSTALL_LIMIT,
        "loss install record too large",
    )?;
    let bootstrap_owner = serde_json::to_string(&(&replacement.identity, Role::Secondary))?;
    let installed_owner = serde_json::to_string(&(&replacement.identity, installed_role))?;
    let node = &*replacement;
    node.connection(|c| {
        let tx = Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
        let existing = read_install(&tx)?;
        // Before the install the node is a bootstrap Secondary; afterwards it
        // carries the lost member's role. Both the durable owner row and the
        // in-memory node must already agree with that, in either direction.
        let (expected_role, expected_owner) = match existing {
            Some(_) => (installed_role, &installed_owner),
            None => (Role::Secondary, &bootstrap_owner),
        };
        ensure(node.role == expected_role, "loss replacement role mismatch")?;
        node.verify_owner_as(&tx, expected_role)?;
        ensure(
            owner_row(&tx)? == *expected_owner,
            "loss replacement owner mismatch",
        )?;
        ensure_recovery_tables(&tx, REPLACEMENT_RECOVERY_TABLES)?;
        // Symmetric with the survivor: an un-installed successor membership is
        // never installed again. A bootstrap replacement has no tombstones of
        // its own, so in practice the journal's own terminal state stops it
        // first; this is the local half of the same rule.
        require_not_aborted(&tx, request, record.successor_certificate)?;
        capacity::verify_schema(&tx)?;
        capacity::verify_accounting(&tx)?;
        let base = checkpoint::base_for::<SchemaId>(&tx)?.ok_or("loss replacement base missing")?;
        let current =
            checkpoint::current_for(&tx, &node.adapter, &node.identity, &node.initial, true)?.0;
        let manifest_json: String = tx.query_row(
            "SELECT manifest FROM node_restore_complete WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure(
            manifest_json.len() <= 8192,
            "loss replacement manifest limit",
        )?;
        let manifest = snapshot::Manifest::decode(manifest_json.as_bytes())?;
        ensure(
            checkpoint::generation(&tx)? == parent.replacement_generation
                && base.sequence == parent.survivor_cut.sequence
                && id(&base)? == parent.survivor_cut.digest
                && current == base
                && manifest.checkpoint == base
                && id(&manifest)? == parent.survivor_publication,
            "loss replacement state mismatch",
        )?;
        if let Some((json, _)) = existing {
            ensure(json == expected, "loss install conflict")?;
            tx.rollback()?;
            return Ok(());
        }
        tx.execute_batch(INSTALL_DDL)?;
        ensure(
            tx.execute(
                "INSERT INTO main.recovery_loss_active VALUES(1,?1)",
                [&expected],
            )? == 1,
            "loss install write failed",
        )?;
        if installed_role != Role::Secondary {
            ensure(
                tx.execute(
                    "UPDATE node_identity SET value=?1 WHERE value=?2",
                    params![&installed_owner, &bootstrap_owner],
                )? == 1,
                "loss install promotion failed",
            )?;
        }
        node.verify_owner_as(&tx, installed_role)?;
        ensure(
            owner_row(&tx)? == installed_owner
                && read_install(&tx)?.map(|(json, _)| json).as_deref() == Some(expected.as_str()),
            "loss install post-state mismatch",
        )?;
        ensure(
            authorities
                .source
                .fetch_loss(&trust.as_trust(), policy)?
                .request()
                == parent,
            "loss decision changed",
        )?;
        let live =
            authorities
                .successor
                .fetch_loss_successor(successor, &trust.as_trust(), policy)?;
        ensure(
            live.request() == successor
                && live.loss_request() == parent
                && live.certificate_id() == record.successor_certificate
                && live.token_digest() == record.successor_token_digest,
            "loss successor decision changed",
        )?;
        tx.commit()?;
        Ok(())
    })?;
    replacement.role = installed_role;
    // I2: revalidate the durable state and re-check the live authorities after
    // the commit, the same way the survivor install does.
    let node = &*replacement;
    node.connection(|c| {
        node.verify_owner(c)?;
        ensure(
            owner_row(c)? == installed_owner
                && read_install(c)?.map(|(json, _)| json).as_deref() == Some(expected.as_str()),
            "loss install revalidation mismatch",
        )
    })?;
    ensure(
        authorities
            .source
            .fetch_loss(&trust.as_trust(), policy)?
            .request()
            == &record.loss,
        "loss decision changed",
    )?;
    authorities
        .successor
        .fetch_loss_successor(successor, &trust.as_trust(), policy)?;
    Ok(())
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Local bridge for a co-located pair: survivor first, then replacement.
/// In production the two installs run on their own machines against their own
/// journals; neither depends on the other's object.
pub fn install_pair<A: ReplicatedSchema, P: transition::LossPolicy>(
    survivor: &LossSurvivorHandle<A>,
    replacement: &mut Node<A>,
    passphrase: &str,
    founding: &Founding,
    successor: &transition::LossSuccessorRequest,
    authorities: &Authorities<'_, P>,
) -> Result<()> {
    survivor.install_successor(passphrase, successor, authorities)?;
    install_replacement(replacement, founding, successor, authorities)
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Idempotently transfer the exact loss-bound publication into an empty
/// replacement. The replacement stays a normal non-primary bootstrap node;
/// this function neither installs membership nor grants admission.
///
/// The restored state is bound to the signed `survivor_cut`, not to the older
/// `source_cut`: the publication that `validate` accepted is the survivor's
/// current one, so a tail committed after the certified cut is transferred and
/// never silently dropped. The signed `replacement_generation` is retained
/// through the restore because the successor membership is signed against it.
pub fn bootstrap_replacement<A: ReplicatedSchema>(
    survivor: &LossSurvivorHandle<A>,
    replacement: &mut Node<A>,
    journal: &crate::recovery::transition::Journal,
    policy: &impl crate::recovery::transition::LossPolicy,
) -> Result<Prefix> {
    ensure(
        replacement.role == Role::Secondary && replacement.identity == survivor.identity,
        "loss replacement owner mismatch",
    )?;
    let generation = replacement.connection(checkpoint::generation)?;
    ensure(
        generation == survivor.request.replacement_generation,
        "loss replacement generation mismatch",
    )?;
    let manifest = survivor.manifest(journal, policy)?;
    let mut next = replacement.begin_snapshot(&manifest)?;
    while next < manifest.pages {
        let page = survivor.page(next, journal, policy)?;
        next = replacement.receive_snapshot(&page)?;
    }
    let checkpoint = replacement
        .finish_snapshot_retaining_generation(&manifest, survivor.request.replacement_generation)?;
    ensure(
        checkpoint == manifest.checkpoint
            && checkpoint.sequence == survivor.request.survivor_cut.sequence
            && id(&checkpoint)? == survivor.request.survivor_cut.digest,
        "loss replacement cut mismatch",
    )?;
    ensure(
        replacement.connection(checkpoint::generation)? == survivor.request.replacement_generation,
        "loss replacement generation not retained",
    )?;
    // One final live fencing check after the durable restore, so a successful
    // return cannot race authority revocation at the last page boundary.
    survivor.revalidate(journal, policy)?;
    Ok(checkpoint)
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Read-only precondition for the future atomic local membership install.
/// The opaque proof is intentionally consumed only as installation authority;
/// it is not a completed writer capability and this function performs no ACK.
pub fn validate_successor_installation<A: ReplicatedSchema>(
    survivor: &LossSurvivorHandle<A>,
    replacement: &Node<A>,
    proof: &crate::recovery::transition::CommittedLossSuccessorTransition,
    source_journal: &crate::recovery::transition::Journal,
    policy: &impl crate::recovery::transition::LossPolicy,
) -> Result<()> {
    survivor.revalidate(source_journal, policy)?;
    let request = proof.request();
    let loss = proof.loss_request();
    ensure(
        loss == &survivor.request
            && request.authority_id == loss.authority_id
            && request.install == loss.install
            && request.region == loss.region
            && request.scope == loss.scope
            && request.schema == loss.schema
            && request.membership == loss.replacement_membership
            && request.source_certificate == loss.source_certificate
            && request.source_token_digest == loss.source_token_digest
            && request.source_cut == loss.source_cut
            && request.parent_loss_certificate == proof.loss_certificate_id()
            && request.parent_loss_token_digest == proof.loss_token_digest()
            && request.survivor_cut == loss.survivor_cut
            && request.survivor_publication == loss.survivor_publication
            && request.survivor()?.member == loss.survivor.member
            && request.survivor()?.generation == loss.survivor.generation
            && request.replacement()?.member == loss.replacement_member
            && request.replacement()?.generation == loss.replacement_generation
            && replacement.role == Role::Secondary
            && replacement.identity == survivor.identity,
        "loss successor installation mismatch",
    )?;
    replacement.connection(|c| {
        replacement.verify_owner(c)?;
        ensure(
            checkpoint::generation(c)? == loss.replacement_generation
                && checkpoint::base_for::<SchemaId>(c)?.as_ref()
                    == Some(&survivor.manifest.checkpoint)
                && checkpoint::current_for(
                    c,
                    &replacement.adapter,
                    &replacement.identity,
                    &replacement.initial,
                    true,
                )?
                .0 == survivor.manifest.checkpoint,
            "loss replacement installation mismatch",
        )
    })
}

/// Retire the recovery that founded this survivor: append it to the
/// append-only cycle history, then remove its active record and completion
/// receipt so the new install can take their place. All inside the caller's
/// transaction, so the retirement and the new record are one atomic step.
#[cfg(any(test, feature = "experimental-recovery"))]
fn retire_founding(
    c: &Connection,
    founding: &Installed,
    next: &transition::LossRequest,
) -> Result<()> {
    let completion = read_completion(c)?.ok_or("loss founding recovery incomplete")?;
    let mut parent = None;
    let mut retired = Vec::new();
    visit_cycles(c, |record| {
        parent = Some(hash(record)?);
        retired.push(record.installed.loss.revision);
        Ok(())
    })?;
    ensure(
        retired.iter().all(|r| *r < next.revision) && founding.loss.revision < next.revision,
        "participant-loss cycle revision reuse",
    )?;
    // Defence in depth: the journal refuses a reused identity too, but the
    // journal file and this node file are different trust domains. The
    // recovery being retired right now burns its own identities as well, and
    // they are not in the cycle table yet — every one of them has to be in the
    // set, or the very first retirement would let the member this pair just
    // lost walk back in as the replacement.
    let mut already = retired_identities(c)?;
    already.extend(retired_of(founding));
    ensure(
        ![
            next.replacement_member,
            next.replacement_generation,
            next.replacement_membership,
        ]
        .iter()
        .any(|id| already.contains(id)),
        "participant-loss identity reuse",
    )?;
    let record = RetiredLoss {
        parent,
        installed: founding.clone(),
        completion,
        next: next.clone(),
    };
    let json = serde_json::to_string(&record)?;
    ensure(json.len() <= 256 * 1024, "participant-loss cycle limit")?;
    c.execute_batch(CYCLES_DDL)?;
    ensure(
        c.execute(
            "INSERT INTO main.recovery_loss_cycles VALUES(?1,?2,?3)",
            params![founding.loss.revision, json, hash(&record)?],
        )? == 1,
        "participant-loss cycle write failed",
    )?;
    ensure(
        c.execute("DELETE FROM main.recovery_loss_active WHERE id=1", [])? == 1,
        "participant-loss retirement failed",
    )?;
    c.execute_batch("DROP TABLE main.recovery_loss_completion")?;
    Ok(())
}

/// What founded this survivor, read from its own durable state. A certified
/// pair is founded by its latest compaction certificate; a pair that already
/// survived a loss is founded by that recovery's completed successor, which the
/// node authenticated by signature when it installed it.
#[cfg(any(test, feature = "experimental-recovery"))]
enum SurvivorFounding {
    Certificate {
        request: transition::Request,
    },
    Successor {
        successor: transition::LossSuccessorRequest,
    },
}

#[cfg(any(test, feature = "experimental-recovery"))]
impl SurvivorFounding {
    /// `(local role, local participant)` derived from the founding document.
    fn survivor_evidence(
        &self,
        loss: &transition::LossRequest,
    ) -> Result<(Role, transition::Participant)> {
        let (participants, canonical) = match self {
            Self::Certificate { request } => (&request.participants, true),
            Self::Successor { successor } => (&successor.participants, successor.format == 2),
        };
        let mut matches = participants.iter().enumerate().filter(|(_, p)| {
            p.member == loss.survivor.member && p.generation == loss.survivor.generation
        });
        let index = matches.next().ok_or("loss survivor not certified")?.0;
        ensure(matches.next().is_none(), "loss survivor ambiguous")?;
        let lost = &participants[1 - index];
        ensure(
            lost.member == loss.lost_member && lost.generation == loss.lost_generation,
            "loss lost participant mismatch",
        )?;
        // Only a canonically ordered document carries a role at all.
        ensure(
            canonical,
            "format-1 loss recovery cannot take a second loss",
        )?;
        Ok((
            if index == 0 {
                Role::Primary
            } else {
                Role::Secondary
            },
            participants[index].clone(),
        ))
    }
}

/// Read and pin the survivor's founding document from its own durable state.
#[cfg(any(test, feature = "experimental-recovery"))]
fn survivor_founding(
    c: &Connection,
    trust: &transition::TrustStore,
    loss: &transition::LossRequest,
) -> Result<SurvivorFounding> {
    if !matches!(
        loss.source_kind,
        Some(transition::SourceKind::LossSuccessor)
    ) {
        let json: String = c.query_row(
            "SELECT record FROM node_compaction_certificates ORDER BY sequence DESC LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        ensure(json.len() <= 256 * 1024, "loss certificate limit")?;
        let certificate: certified::CertificateRecord = serde_json::from_str(&json)?;
        let verified = transition::verify_historical(
            &certificate.token,
            &trust.as_trust(),
            &certificate.request,
        )?;
        ensure(
            certificate.request.membership == loss.membership
                && verified.certificate_id() == loss.source_certificate
                && verified.token_digest() == loss.source_token_digest,
            "loss survivor evidence mismatch",
        )?;
        return Ok(SurvivorFounding::Certificate {
            request: certificate.request,
        });
    }
    // The founding recovery must be complete. Until this loss is installed it
    // is still the active record next to its receipt; the install moves both,
    // atomically, into the append-only cycle history, and the row that carries
    // them names exactly this loss as the one that retired them. Both phases
    // of that single transaction therefore have to validate.
    // A survivor whose successor was un-installed under a signed abort has no
    // active record at all (S10): it is back to "post-`decide_loss`,
    // pre-install", and its founding recovery is in the cycle history too.
    let active = read_install(c)?.map(|(_, record)| record);
    let installed = active.as_ref().is_some_and(|a| a.loss != *loss);
    let (record, receipt) = if installed {
        let founding = active.ok_or("loss founding recovery missing")?;
        let receipt = read_completion(c)?.ok_or("loss founding recovery incomplete")?;
        (founding, receipt)
    } else {
        let mut last: Option<RetiredLoss> = None;
        visit_cycles(c, |row| {
            last = Some(row.clone());
            Ok(())
        })?;
        let row = last.ok_or("loss founding recovery missing")?;
        // The retirement this loss — or the attempt it supersedes — made room
        // for. Supersession may change the replacement and nothing else, so an
        // earlier attempt's row still names this lineage.
        ensure(
            same_attempt(&row.next, loss),
            "loss founding recovery mismatch",
        )?;
        (row.installed, row.completion)
    };
    let stored: CompletionReceipt = serde_json::from_str(&receipt)?;
    ensure(
        stored.1 == record.successor.id
            && stored.2 == record.successor_token_digest
            && stored.3 == record.successor_certificate,
        "loss founding receipt mismatch",
    )?;
    // Symmetry with the replacement side: the founding successor is
    // authenticated by signature under the trust store this handle is bound
    // to, not merely by the digests this node once wrote down. A format-1
    // record predates the stored token and can found nothing.
    let token = record
        .successor_token
        .clone()
        .ok_or("founding record carries no successor token")?;
    ensure(token.len() <= MAX_TOKEN, "loss founding token limit")?;
    ensure(
        record.successor.format == 2,
        "format-1 loss recovery cannot take a second loss",
    )?;
    let certificate =
        transition::verify_successor_historical(&token, &trust.as_trust(), &record.successor)?;
    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    ensure(
        certificate == record.successor_certificate
            && certificate == loss.source_certificate
            && digest == record.successor_token_digest
            && digest == loss.source_token_digest
            && record.successor.survivor_cut == loss.source_cut
            && record.successor.membership == loss.membership
            && record.successor.authority_id == loss.authority_id
            && record.successor.install == loss.install
            && record.successor.region == loss.region
            && record.successor.scope == loss.scope
            && record.successor.schema == loss.schema,
        "loss founding successor mismatch",
    )?;
    // The local node must be the one the founding recovery left standing, and
    // it must not be the member this loss fences.
    ensure(
        record.member != loss.lost_member
            && record.generation != loss.lost_generation
            && record.member == loss.survivor.member
            && record.generation == loss.survivor.generation
            && checkpoint::generation(c)? == record.generation,
        "loss founding participant mismatch",
    )?;
    Ok(SurvivorFounding::Successor {
        successor: record.successor,
    })
}

#[cfg(any(test, feature = "experimental-recovery"))]
pub(super) fn validate<A: ReplicatedSchema>(
    c: &Connection,
    adapter: &A,
    identity: &Identity<SchemaId>,
    contract: &schema_contract::Contract,
    initial: &str,
    trust: &crate::recovery::transition::TrustStore,
    loss: &crate::recovery::transition::LossRequest,
) -> Result<Evidence> {
    let identities: Vec<String> = c
        .prepare("SELECT value FROM main.node_identity")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    // The owner row is compared once the role has been derived from signed
    // evidence below; a single row is still required up front.
    ensure(identities.len() == 1, "loss survivor owner mismatch")?;
    let runtime: Vec<(u32, String)> = c
        .prepare("SELECT format,initial_digest FROM node_runtime")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        runtime.len() == 1 && runtime[0].1 == initial,
        "loss survivor runtime mismatch",
    )?;
    // Ahead of everything else: a node still inside a certified maintenance is
    // in the pending runtime, which no shape below can even describe, and the
    // operator needs to be told which termination step it owes (S11).
    require_maintenance_terminated(c, loss)?;
    let history = history_format(c, runtime[0].0)?;
    recovery::verify_history(c, history)?;
    verify_certified(c, Some(trust))?;
    // An in-flight compaction would be wedged for ever once the loss gates
    // close, so it must be resolved before the irreversible install.
    compaction::require_idle(c)?;
    capacity::verify_schema(c)?;
    capacity::verify_accounting(c)?;
    schema_contract::verify(c, adapter, contract)?;
    sql_snapshot::verify_binding(c, adapter, &snapshot::scope(identity))?;
    ensure(
        loss.membership != loss.replacement_membership,
        "loss membership reused",
    )?;
    // A superseding decision needs this node's own tombstone for the attempt
    // it replaces: the authority's journal cannot read this file, and this
    // file cannot read the abort's journal, so both check independently.
    require_supersession(c, loss)?;
    // I1. The survivor index — and therefore the local role — is derived only
    // from the signed loss decision and the document that founded this pair:
    // the certified compaction for an ordinary pair, or the completed loss
    // successor of its previous recovery. Exactly one participant may match the
    // survivor member *and* generation, the other one must be exactly the
    // fenced member/generation, and the owner row must already carry the role
    // that the position implies. No caller can supply or influence the role.
    let founding = survivor_founding(c, trust, loss)?;
    let (role, local) = founding.survivor_evidence(loss)?;
    // Installation-aware, still never an input: the owner row carries the
    // derived role until the signed successor membership is durably installed,
    // and exactly the role that record commits it to afterwards.
    let owner = survivor_owner_role(c, loss, role)?;
    ensure(
        identities[0] == serde_json::to_string(&(identity, owner))?,
        "loss survivor owner mismatch",
    )?;
    let base = checkpoint::base_for::<SchemaId>(c)?.ok_or("loss survivor base missing")?;
    let current = checkpoint::current_for(c, adapter, identity, initial, true)?.0;
    let manifest_json: String = c.query_row(
        "SELECT manifest FROM node_publication WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    ensure(manifest_json.len() <= 8192, "loss manifest limit")?;
    let manifest = snapshot::Manifest::decode(manifest_json.as_bytes())?;
    ensure(
        local.member == loss.survivor.member
            && local.generation == loss.survivor.generation
            && current == manifest.checkpoint
            && current.sequence == loss.survivor_cut.sequence
            && id(&current)? == loss.survivor_cut.digest
            && id(&manifest)? == loss.survivor_publication,
        "loss survivor evidence mismatch",
    )?;
    // Continuity with the founding cut. A certified pair still has that exact
    // checkpoint as its base; a pair that already survived a loss may have
    // compacted past it, so the checkpoint is recomputed at that sequence.
    match founding {
        SurvivorFounding::Certificate { .. } => ensure(
            local.old_base == loss.survivor.old_base
                && local.target == loss.source_cut
                && base.sequence == loss.source_cut.sequence
                && id(&base)? == loss.source_cut.digest,
            "loss survivor evidence mismatch",
        )?,
        SurvivorFounding::Successor { .. } => {
            // The same participant clauses the certificate arm makes, read out
            // of the founding successor instead.
            ensure(
                local.old_base == loss.survivor.old_base && local.target == loss.source_cut,
                "loss survivor evidence mismatch",
            )?;
            ensure(
                base.sequence <= loss.source_cut.sequence,
                "loss survivor base past the founding cut",
            )?;
            let anchor = if base.sequence == loss.source_cut.sequence {
                base.clone()
            } else {
                checkpoint::calculate_for(
                    c,
                    adapter,
                    identity,
                    initial,
                    true,
                    Some(loss.source_cut.sequence),
                )?
            };
            ensure(
                anchor.sequence == loss.source_cut.sequence
                    && id(&anchor)? == loss.source_cut.digest,
                "loss survivor anchor mismatch",
            )?;
        }
    }
    Node::<A>::verify_publication_in(c, &manifest, identity, contract)?;
    Ok(Evidence { role, manifest })
}

fn id<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(value)?).into())
}

// ---------------------------------------------------------------------------
// S3: applied evidence, acknowledgements, completion and writer admission.
// ---------------------------------------------------------------------------

/// `(format, successor id, successor token digest, successor certificate id,
/// completion)`. It is local evidence only: admission still needs the live
/// completed-successor proof to equal it.
type CompletionReceipt = (u32, [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

fn completion_receipt(record: &Installed, completion: [u8; 32]) -> Result<String> {
    ensure(completion != [0; 32], "zero participant-loss completion")?;
    Ok(serde_json::to_string(&(
        1u32,
        record.successor.id,
        record.successor_token_digest,
        record.successor_certificate,
        completion,
    ))?)
}

fn read_completion(c: &Connection) -> Result<Option<String>> {
    let Some(json) = singleton(c, COMPLETION_TABLE, "receipt", COMPLETION_LIMIT)? else {
        return Ok(None);
    };
    let receipt: CompletionReceipt = serde_json::from_str(&json)?;
    ensure(
        receipt.0 == 1 && receipt.4 != [0; 32],
        "participant-loss completion shape",
    )?;
    Ok(Some(json))
}

/// The durable participant-loss state of a node, with the orphan check both
/// ways. `None` means this is an ordinary node and every caller must behave
/// exactly as it did before participant-loss recovery existed.
pub(crate) fn state(c: &Connection) -> Result<Option<Installed>> {
    // A view, trigger or index carrying a participant-loss table name is never
    // acceptable evidence, whatever it would return.
    let shadows: u64 = c.query_row(
        "SELECT count(*) FROM main.sqlite_schema \
         WHERE type<>'table' AND name IN \
         ('recovery_loss_active','recovery_loss_completion','recovery_loss_aborted')",
        [],
        |r| r.get(0),
    )?;
    ensure(shadows == 0, "participant-loss table shadowed")?;
    let record = read_install(c)?.map(|(_, record)| record);
    // The retired history is verified on every read, and a node that has
    // retired a recovery must still be inside one — or have un-installed it
    // again under a signed abort, which the tombstone chain accounts for.
    let mut retired = 0u64;
    let mut last_next: Option<transition::LossRequest> = None;
    // Every loss this file has ever been installed by, collected in the single
    // verified walk of the cycle chain.
    let mut known: Vec<transition::LossRequest> = Vec::new();
    visit_cycles(c, |row| {
        retired += 1;
        last_next = Some(row.next.clone());
        known.push(row.installed.loss.clone());
        known.push(row.next.clone());
        Ok(())
    })?;
    let mut last_aborted: Option<transition::LossRequest> = None;
    visit_aborted(c, |row| {
        last_aborted = Some(row.loss.clone());
        Ok(())
    })?;
    // Every tombstone belongs to the attempt this file is in, or to one of the
    // recoveries it has retired: a tombstone for an unrelated loss is not
    // history, it is an injected veto.
    if let Some(current) = record
        .as_ref()
        .map(|r| r.loss.clone())
        .or_else(|| last_aborted.clone())
    {
        known.push(current);
    }
    visit_aborted(c, |row| {
        ensure(
            known.iter().any(|loss| same_lineage(&row.loss, loss)),
            "participant-loss tombstone chain mismatch",
        )
    })?;
    match &record {
        // A retirement with no install at all is only explained by an abort of
        // exactly the install it made room for.
        None => ensure(
            retired == 0
                || last_aborted
                    .as_ref()
                    .zip(last_next.as_ref())
                    .is_some_and(|(aborted, next)| same_attempt(next, aborted)),
            "orphan participant-loss cycle history",
        )?,
        Some(record) => {
            // The active record is exactly the install the last retirement made
            // room for, and an install founded by an earlier recovery must have
            // retired it. Neither end of the history can be dropped unnoticed.
            ensure(
                last_next.is_none_or(|next| same_attempt(&next, &record.loss)),
                "participant-loss cycle chain mismatch",
            )?;
            // A *survivor* installed by a loss that was founded on an earlier
            // recovery necessarily retired that recovery in the same transaction.
            // A replacement is a new file and has nothing to retire, which is
            // exactly what tells the two apart — never a flag.
            ensure(
                retired > 0
                    || !(matches!(
                        record.loss.source_kind,
                        Some(transition::SourceKind::LossSuccessor)
                    ) && record.member == record.loss.survivor.member),
                "participant-loss cycle history missing",
            )?;
        }
    }
    ensure(
        record.is_some() || !table_exists(c, COMPLETION_TABLE)?,
        "orphan participant-loss completion",
    )?;
    Ok(record)
}

/// Index of this node inside the successor membership, from the record alone.
fn successor_index(record: &Installed) -> Result<usize> {
    let mut matches = record
        .successor
        .participants
        .iter()
        .enumerate()
        .filter(|(_, p)| p.member == record.member && p.generation == record.generation);
    let index = matches
        .next()
        .ok_or("participant-loss member not in successor")?
        .0;
    ensure(
        matches.next().is_none(),
        "participant-loss member ambiguous",
    )?;
    Ok(index)
}

/// The install record really describes this open node: the owner row, the role
/// it was installed with and the admission generation all have to agree.
fn validate_installed(
    c: &Connection,
    identity: &Identity<SchemaId>,
    role: Role,
    record: &Installed,
) -> Result<()> {
    let index = successor_index(record)?;
    ensure(
        matches!(record.format, 1 | 2)
            && record.installed_role == role
            && owner_row(c)? == serde_json::to_string(&(identity, role))?
            && checkpoint::generation(c)? == record.generation
            && record.successor.participants[index].member == record.member
            && record.survivor_cut == record.loss.survivor_cut
            && record.publication == record.loss.survivor_publication
            && successor_binds(&record.successor, &record.loss),
        "participant-loss install record mismatch",
    )
}

/// The other member of the successor membership. After an install this — not
/// the pre-loss `recovery_active` peer — is the only peer that may be admitted.
pub(crate) fn peer_member(record: &Installed) -> Result<[u8; 32]> {
    Ok(record.successor.participants[1 - successor_index(record)?].member)
}

/// Local member identity under the successor membership.
pub(crate) fn local_member(record: &Installed) -> [u8; 32] {
    record.member
}

/// Handshake digest bound to the successor membership, so a peer still holding
/// the pre-loss membership can never be paired with a recovered node.
pub(crate) fn membership_digest(record: &Installed) -> Result<[u8; 32]> {
    id(&(
        1u32,
        record.successor.membership,
        record.successor.id,
        record.successor_token_digest,
        record.successor_certificate,
    ))
}

/// Open-time certificate handling for a node whose successor membership is
/// installed. The pre-loss chain is history, never a live head, and a live
/// authority is required whatever the maintenance format says.
pub(crate) fn verify_certified_history(
    c: &Connection,
    authority: Option<&dyn crate::typed::CertifiedAuthority>,
) -> Result<()> {
    let authority = authority.ok_or(CLOSED)?;
    // A certificate terminated by this very loss (S11 branch B) was never
    // completed, so there is no completed revision to fetch. Its provenance is
    // the signed loss itself, which `verify_certified` has already bound to the
    // durable termination trace; admission still needs the live completed
    // successor of the recovery, which `admission` checks below.
    if super::maintenance_version(c)? == 3 && !super::loss_terminated_archive(c)? {
        super::verify_historical_certified(c, Some(authority))?;
    }
    Ok(())
}

/// Ordinary data admission for a node with an installed successor membership.
/// It needs the local completion receipt *and* a live completed-successor proof
/// that equals it exactly. An install-only decision can never satisfy this.
pub(crate) fn admission(
    c: &Connection,
    identity: &Identity<SchemaId>,
    role: Role,
    authority: Option<&dyn crate::typed::CertifiedAuthority>,
) -> Result<()> {
    let Some(record) = state(c)? else {
        return Ok(());
    };
    validate_installed(c, identity, role, &record)?;
    let receipt = read_completion(c)?.ok_or(CLOSED)?;
    let completed = authority
        .ok_or(CLOSED)?
        .fetch_completed_loss_successor(&record.successor)?;
    ensure(
        completed.request() == &record.successor
            && completed.token_digest() == record.successor_token_digest
            && completed.certificate_id() == record.successor_certificate
            && receipt == completion_receipt(&record, completed.completion())?,
        CLOSED,
    )
}

/// Closing gate for entry points this release does not support after a
/// participant-loss recovery. It only ever refuses.
pub(crate) fn require_no_loss_recovery(c: &Connection) -> Result<()> {
    ensure(state(c)?.is_none(), RETIRED)
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Durable local completion evidence, written on the ordinary `Node` (the
/// survivor's read-write install handle is dropped before this runs). Exact
/// retry converges; a different completion is a conflict, never a repair.
pub fn record_completion<A: ReplicatedSchema>(node: &Node<A>) -> Result<()> {
    ensure(
        node.transition_trust.is_some(),
        "participant-loss completion requires transition trust",
    )?;
    node.connection(|c| {
        let tx = Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
        let record = state(&tx)?.ok_or("participant-loss recovery is not installed")?;
        node.verify_owner_as(&tx, record.installed_role)?;
        ensure(
            node.role == record.installed_role,
            "participant-loss role mismatch",
        )?;
        validate_installed(&tx, &node.identity, node.role, &record)?;
        ensure_recovery_tables(&tx, recovery_tables_for(&record)?)?;
        let authority = node
            .certified_authority
            .as_deref()
            .ok_or("participant-loss completion authority missing")?;
        let completed = authority.fetch_completed_loss_successor(&record.successor)?;
        ensure(
            completed.request() == &record.successor
                && completed.token_digest() == record.successor_token_digest
                && completed.certificate_id() == record.successor_certificate,
            "participant-loss completion proof mismatch",
        )?;
        let receipt = completion_receipt(&record, completed.completion())?;
        ensure(
            receipt.len() <= COMPLETION_LIMIT,
            "participant-loss completion too large",
        )?;
        // Read before creating the table: a table that exists with no row is a
        // partial state, not an empty slot, and `read_completion` refuses it.
        if let Some(old) = read_completion(&tx)? {
            ensure(old == receipt, "participant-loss completion conflict")?;
            tx.rollback()?;
            return Ok(());
        }
        tx.execute_batch(COMPLETION_DDL)?;
        ensure(
            tx.execute(
                "INSERT INTO main.recovery_loss_completion VALUES(1,?1)",
                [&receipt],
            )? == 1,
            "participant-loss completion write failed",
        )?;
        ensure(
            read_completion(&tx)?.as_deref() == Some(receipt.as_str()),
            "participant-loss completion post-state mismatch",
        )?;
        // The receipt must actually open this node against the live authority,
        // inside the same transaction that wrote it.
        admission(&tx, &node.identity, node.role, Some(authority))?;
        tx.commit()?;
        Ok(())
    })
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Live read of the replacement's durable install, repeating the state checks
/// `install_replacement` made. Used only as acknowledgement evidence (I7).
fn replacement_installed<A: ReplicatedSchema>(
    node: &Node<A>,
    source_scope: &transition::JournalScope,
) -> Result<Installed> {
    ensure(
        node.transition_trust.is_some(),
        "participant-loss evidence requires transition trust",
    )?;
    node.connection(|c| {
        let record = state(c)?.ok_or("participant-loss replacement install missing")?;
        ensure(
            record.source_scope == *source_scope,
            "participant-loss source scope mismatch",
        )?;
        ensure(
            node.role == record.installed_role && record.previous_role == Role::Secondary,
            "participant-loss replacement role mismatch",
        )?;
        node.verify_owner_as(c, record.installed_role)?;
        validate_installed(c, &node.identity, record.installed_role, &record)?;
        ensure_recovery_tables(c, REPLACEMENT_RECOVERY_TABLES)?;
        capacity::verify_schema(c)?;
        capacity::verify_accounting(c)?;
        let base = checkpoint::base_for::<SchemaId>(c)?.ok_or("loss replacement base missing")?;
        let current =
            checkpoint::current_for(c, &node.adapter, &node.identity, &node.initial, true)?.0;
        let manifest_json: String = c.query_row(
            "SELECT manifest FROM node_restore_complete WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure(
            manifest_json.len() <= 8192,
            "loss replacement manifest limit",
        )?;
        let manifest = snapshot::Manifest::decode(manifest_json.as_bytes())?;
        ensure(
            base.sequence == record.survivor_cut.sequence
                && id(&base)? == record.survivor_cut.digest
                && current == base
                && manifest.checkpoint == base
                && id(&manifest)? == record.publication,
            "loss replacement state mismatch",
        )?;
        Ok(record)
    })
}

#[cfg(any(test, feature = "experimental-recovery"))]
impl<A: ReplicatedSchema> LossSurvivorHandle<A> {
    /// Live read of the survivor's durable install through the retained
    /// read-only connection, re-running the full evidence validation.
    fn installed(&self, source_scope: &transition::JournalScope) -> Result<Installed> {
        let trust = &self.trust;
        self.db.with_connection(|c| {
            Ok((|| -> Result<Installed> {
                let evidence = validate::<A>(
                    c,
                    &self.adapter,
                    &self.identity,
                    &self.contract,
                    &self.initial,
                    trust,
                    &self.request,
                )?;
                ensure(
                    evidence.role == self.role && evidence.manifest == self.manifest,
                    "loss survivor evidence changed",
                )?;
                let record = state(c)?.ok_or("participant-loss survivor install missing")?;
                ensure(
                    record.source_scope == *source_scope,
                    "participant-loss source scope mismatch",
                )?;
                ensure(
                    record.previous_role == self.role,
                    "participant-loss survivor role mismatch",
                )?;
                validate_installed(c, &self.identity, self.role, &record)?;
                ensure_recovery_tables(c, SURVIVOR_RECOVERY_TABLES)?;
                Ok(record)
            })())
        })?
    }
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// I7: fixed-pair acknowledges a participant only after live-reading **both**
/// durable installs from the actual node databases. Every other decision is
/// delegated to the external policy unchanged.
struct InstalledParticipants<'a, A: ReplicatedSchema, P: transition::LossPolicy> {
    survivor: &'a LossSurvivorHandle<A>,
    replacement: &'a Node<A>,
    policy: &'a P,
}

#[cfg(any(test, feature = "experimental-recovery"))]
impl<A: ReplicatedSchema, P: transition::LossPolicy> transition::LossPolicy
    for InstalledParticipants<'_, A, P>
{
    fn continuity_and_fencing(
        &self,
        scope: &transition::JournalScope,
        request: &transition::LossRequest,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.policy.continuity_and_fencing(scope, request)
    }
    fn survivor_prepared(
        &self,
        scope: &transition::JournalScope,
        request: &transition::LossRequest,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.policy.survivor_prepared(scope, request)
    }
    fn loss_successor_continuity(
        &self,
        scope: &transition::JournalScope,
        request: &transition::LossSuccessorRequest,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.policy.loss_successor_continuity(scope, request)
    }
    fn loss_successor_applied(
        &self,
        source_scope: &transition::JournalScope,
        loss: &transition::LossRequest,
        successor: &transition::LossSuccessorRequest,
        participant: &transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        // Both installs must be durable, whichever participant is acknowledged,
        // and both must have been installed under exactly the source journal
        // scope this successor journal records as its parent.
        let survivor = self.survivor.installed(source_scope)?;
        let replacement = replacement_installed(self.replacement, source_scope)?;
        let first = successor.survivor()?;
        let second = successor.replacement()?;
        ensure(
            survivor.loss == *loss
                && replacement.loss == *loss
                && survivor.successor == *successor
                && replacement.successor == *successor
                && survivor.member == first.member
                && survivor.generation == first.generation
                && replacement.member == second.member
                && replacement.generation == second.generation
                && (participant == first || participant == second),
            "participant-loss installation evidence missing",
        )
    }
}

#[cfg(any(test, feature = "experimental-recovery"))]
/// Local bridge from two durable installs to a completed successor membership:
/// acknowledge the survivor, then the replacement, then complete. Every step is
/// idempotent and converges on retry; a different completion id is refused.
/// The completion id is derived, never chosen: a function of the exact
/// successor request, the exact issued token and the acknowledgements that
/// authorised it. A retry always recomputes the same value.
#[cfg(any(test, feature = "experimental-recovery"))]
pub(crate) fn completion_id(
    request: &transition::LossSuccessorRequest,
    token_digest: [u8; 32],
    acknowledgements: [bool; 2],
) -> Result<[u8; 32]> {
    id(&(
        "terrapi-loss-successor-completion",
        request.id,
        token_digest,
        acknowledgements,
    ))
}

#[cfg(any(test, feature = "experimental-recovery"))]
pub fn complete_successor<A: ReplicatedSchema, P: transition::LossPolicy>(
    survivor: &LossSurvivorHandle<A>,
    replacement: &Node<A>,
    successor: &transition::LossSuccessorRequest,
    authorities: &Authorities<'_, P>,
) -> Result<()> {
    // Both nodes must have been configured with the same trust store.
    ensure(
        replacement.transition_trust.as_ref() == Some(&survivor.trust),
        "participant-loss trust mismatch",
    )?;
    let trust = &survivor.trust;
    let journal = authorities.successor;
    let decided = journal.fetch_loss_successor(successor, &trust.as_trust(), authorities.policy)?;
    if decided.acknowledgements() != [true; 2] {
        // No acknowledgement without live proof of both durable installs.
        let evidence = InstalledParticipants {
            survivor,
            replacement,
            policy: authorities.policy,
        };
        let decision = journal.fetch_loss_successor(successor, &trust.as_trust(), &evidence)?;
        for participant in decision.request().participants.iter() {
            journal.acknowledge_loss_successor(
                &decision,
                participant,
                &trust.as_trust(),
                &evidence,
            )?;
        }
    }
    let decision =
        journal.fetch_loss_successor(successor, &trust.as_trust(), authorities.policy)?;
    ensure(
        decision.acknowledgements() == [true; 2],
        "participant-loss acknowledgements incomplete",
    )?;
    let completion = completion_id(
        decision.request(),
        decision.token_digest(),
        decision.acknowledgements(),
    )?;
    journal.complete_loss_successor(
        &decision,
        completion,
        &trust.as_trust(),
        authorities.policy,
    )?;
    let completed =
        journal.fetch_completed_loss_successor(successor, &trust.as_trust(), authorities.policy)?;
    ensure(
        completed.request() == successor && completed.completion() == completion,
        "participant-loss completion conflict",
    )
}
