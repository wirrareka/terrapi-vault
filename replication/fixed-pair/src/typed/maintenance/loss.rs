//! Fail-closed page export from a permanently fenced certified survivor, and
//! the atomic local installation of the signed successor membership.
use super::*;
use crate::recovery::transition;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[cfg(test)]
mod tests;

/// Singleton install marker. It is inert evidence of a decided successor
/// membership; it never opens admission (I6) and is only ever written once.
const INSTALL_TABLE: &str = "recovery_loss_active";
const INSTALL_DDL: &str = "CREATE TABLE IF NOT EXISTS recovery_loss_active(\
     id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)";
const INSTALL_LIMIT: usize = 64 * 1024;
/// Recovery metadata a certified survivor legitimately carries: its membership
/// came from a completed recovery. Anything else under `recovery_` fails closed.
const SURVIVOR_RECOVERY_TABLES: &[&str] = &[
    "recovery_active",
    "recovery_completion",
    "recovery_cycles",
    "recovery_delivery",
    "recovery_loss_active",
    "recovery_seal",
];
/// A bootstrap replacement has no recovery history of its own.
const REPLACEMENT_RECOVERY_TABLES: &[&str] = &["recovery_loss_active"];

/// The live authorities every loss entry point must consult before and after
/// its durable step (I2). Borrowed, so nothing is cached across a call.
pub(crate) struct Authorities<'a, P: transition::LossPolicy> {
    pub(crate) source: &'a transition::Journal,
    pub(crate) successor: &'a transition::Journal,
    pub(crate) trust: &'a transition::TrustStore,
    pub(crate) policy: &'a P,
}

/// Everything `validate` derives from signed evidence. The survivor role is a
/// result, never a parameter: it exists only inside this module and is rebuilt
/// from the durable certificate on every validation.
pub(super) struct Evidence {
    role: Role,
    manifest: snapshot::Manifest,
}

/// Durable local record of the installed successor membership (format 1).
/// Written once per node, compared byte-for-byte on retry, never repaired.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Installed {
    format: u32,
    loss: transition::LossRequest,
    loss_certificate: [u8; 32],
    loss_token_digest: [u8; 32],
    successor: transition::LossSuccessorRequest,
    successor_certificate: [u8; 32],
    successor_token_digest: [u8; 32],
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

/// Restricted capability: it owns the normal node lock, opens SQLite read-only,
/// and exposes only the exact loss-bound frozen publication. The installer
/// opens a second, read-write connection to the same file for the duration of
/// one transaction; that connection is never stored here (I3).
pub(crate) struct LossSurvivorHandle<A: ReplicatedSchema> {
    db: Vesta,
    adapter: A,
    initial: String,
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

impl<A: ReplicatedSchema> LossSurvivorHandle<A> {
    pub(crate) fn open_existing(
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
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.with_extension("node-lock"))?;
        lock.try_lock()?;
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

    pub(crate) fn manifest(
        &self,
        journal: &crate::recovery::transition::Journal,
        trust: &crate::recovery::transition::TrustStore,
        policy: &impl crate::recovery::transition::LossPolicy,
    ) -> Result<snapshot::Manifest> {
        self.revalidate(journal, trust, policy)?;
        Ok(self.manifest.clone())
    }

    pub(crate) fn page(
        &self,
        position: u64,
        journal: &crate::recovery::transition::Journal,
        trust: &crate::recovery::transition::TrustStore,
        policy: &impl crate::recovery::transition::LossPolicy,
    ) -> Result<snapshot::Page> {
        self.revalidate(journal, trust, policy)?;
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
        trust: &crate::recovery::transition::TrustStore,
        policy: &impl crate::recovery::transition::LossPolicy,
    ) -> Result<()> {
        let loss = journal.fetch_loss(&trust.as_trust(), policy)?;
        ensure(loss.request() == &self.request, "loss decision changed")?;
        self.db.with_connection(|c| {
            Ok((|| -> Result<()> {
                // The owner row still has to carry exactly the role the signed
                // evidence derived, or — once the successor membership is
                // durably installed — the role that record commits it to.
                let owner = survivor_owner_role(c, &self.request, self.role)?;
                let identities: Vec<String> = c
                    .prepare("SELECT value FROM node_identity")?
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
        let trust = authorities.trust;
        self.revalidate(authorities.source, trust, authorities.policy)?;
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
        Ok(Installed {
            format: 1,
            loss: self.request.clone(),
            loss_certificate: loss.certificate_id(),
            loss_token_digest: loss.token_digest(),
            successor: request.clone(),
            successor_certificate: proof.certificate_id(),
            successor_token_digest: proof.token_digest(),
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
    pub(crate) fn install_successor<P: transition::LossPolicy>(
        &self,
        passphrase: &str,
        successor: &transition::LossSuccessorRequest,
        authorities: &Authorities<'_, P>,
    ) -> Result<()> {
        let trust = authorities.trust;
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
                ensure(
                    checkpoint::generation(&tx)? == self.request.survivor.generation,
                    "loss install generation mismatch",
                )?;
                let owner = owner_row(&tx)?;
                ensure(owner == owner_expected, "loss install owner mismatch")?;
                if let Some((json, _)) = read_install(&tx)? {
                    // I5: exact retry only. A record that differs in any byte is
                    // a conflict and is never repaired.
                    ensure(json == expected, "loss install conflict")?;
                    tx.rollback()?;
                    return Ok(());
                }
                tx.execute_batch(INSTALL_DDL)?;
                ensure(
                    tx.execute("INSERT INTO recovery_loss_active VALUES(1,?1)", [&expected])? == 1,
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
        // Full revalidation through the retained read-only connection, then a
        // live authority check on both journals.
        let evidence = self.db.with_connection(|c| {
            Ok(validate::<A>(
                c,
                &self.adapter,
                &self.identity,
                &self.contract,
                &self.initial,
                trust,
                &self.request,
            ))
        })??;
        ensure(
            evidence.role == self.role && evidence.manifest == self.manifest,
            "loss install revalidation mismatch",
        )?;
        self.revalidate(source_journal, trust, policy)?;
        successor_journal.fetch_loss_successor(successor, &trust.as_trust(), policy)?;
        Ok(())
    }
}

fn owner_row(c: &Connection) -> Result<String> {
    let identities: Vec<String> = c
        .prepare("SELECT value FROM node_identity")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(identities.len() == 1, "loss owner row mismatch")?;
    Ok(identities.into_iter().next().ok_or("loss owner row")?)
}

fn table_exists(c: &Connection, name: &str) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    )?)
}

/// Only the recovery metadata this kind of node is allowed to carry may exist.
/// An unexpected `recovery_*` table — including a completion record this slice
/// never writes — fails closed instead of being ignored.
fn ensure_recovery_tables(c: &Connection, allowed: &[&str]) -> Result<()> {
    let present: Vec<String> = c
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='table' \
             AND name LIKE 'recovery\\_%' ESCAPE '\\' ORDER BY name",
        )?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for name in present {
        ensure(
            allowed.contains(&name.as_str()),
            "unexpected recovery state",
        )?;
    }
    Ok(())
}

/// The singleton install record, with the size and shape caps of I9. More than
/// one row, a wrong id or an oversized record is a conflict, never a repair.
fn read_install(c: &Connection) -> Result<Option<(String, Installed)>> {
    if !table_exists(c, INSTALL_TABLE)? {
        return Ok(None);
    }
    let rows: Vec<(u32, String)> = c
        .prepare("SELECT id,record FROM recovery_loss_active ORDER BY id")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        rows.len() == 1 && rows[0].0 == 1 && rows[0].1.len() <= INSTALL_LIMIT,
        "loss install row mismatch",
    )?;
    let json = rows.into_iter().next().ok_or("loss install row")?.1;
    let record: Installed = serde_json::from_str(&json)?;
    ensure(record.format == 1, "loss install format")?;
    Ok(Some((json, record)))
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
        && successor.participants[0].member == loss.survivor.member
        && successor.participants[0].generation == loss.survivor.generation
        && successor.participants[1].member == loss.replacement_member
        && successor.participants[1].generation == loss.replacement_generation
}

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

/// The role the replacement inherits, derived from the signed source
/// certificate named by the signed loss decision. The certificate is pinned by
/// `source_certificate` + `source_token_digest`, so a caller cannot substitute
/// one; the index of the lost member inside it decides the role, exactly as I1
/// decides the survivor's. No caller-supplied role or boolean is involved.
fn replacement_role(
    certificate: &transition::Request,
    certificate_token: &str,
    trust: &transition::TrustStore,
    loss: &transition::LossRequest,
) -> Result<Role> {
    let verified =
        transition::verify_historical(certificate_token, &trust.as_trust(), certificate)?;
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
    let mut matches = certificate
        .participants
        .iter()
        .enumerate()
        .filter(|(_, p)| p.member == loss.lost_member && p.generation == loss.lost_generation);
    let index = matches.next().ok_or("loss lost member not certified")?.0;
    ensure(matches.next().is_none(), "loss lost member ambiguous")?;
    let survivor = &certificate.participants[1 - index];
    ensure(
        survivor.member == loss.survivor.member && survivor.generation == loss.survivor.generation,
        "loss survivor participant mismatch",
    )?;
    Ok(if index == 0 {
        Role::Primary
    } else {
        Role::Secondary
    })
}

/// Durable installation of the same signed successor membership on the
/// replacement, which takes over the lost member's role. It depends only on
/// signed data, this node and the journals: in production the survivor is a
/// different machine and is not reachable here.
pub(crate) fn install_replacement<A: ReplicatedSchema, P: transition::LossPolicy>(
    replacement: &mut Node<A>,
    certificate: &transition::Request,
    certificate_token: &str,
    successor: &transition::LossSuccessorRequest,
    authorities: &Authorities<'_, P>,
) -> Result<()> {
    let trust = authorities.trust;
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
    let installed_role = replacement_role(certificate, certificate_token, trust, parent)?;
    let record = Installed {
        format: 1,
        loss: parent.clone(),
        loss_certificate: proof.loss_certificate_id(),
        loss_token_digest: proof.loss_token_digest(),
        successor: request.clone(),
        successor_certificate: proof.certificate_id(),
        successor_token_digest: proof.token_digest(),
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
            tx.execute("INSERT INTO recovery_loss_active VALUES(1,?1)", [&expected])? == 1,
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

/// Local bridge for a co-located pair: survivor first, then replacement.
/// In production the two installs run on their own machines against their own
/// journals; neither depends on the other's object.
pub(crate) fn install_pair<A: ReplicatedSchema, P: transition::LossPolicy>(
    survivor: &LossSurvivorHandle<A>,
    replacement: &mut Node<A>,
    passphrase: &str,
    certificate: &transition::Request,
    certificate_token: &str,
    successor: &transition::LossSuccessorRequest,
    authorities: &Authorities<'_, P>,
) -> Result<()> {
    survivor.install_successor(passphrase, successor, authorities)?;
    install_replacement(
        replacement,
        certificate,
        certificate_token,
        successor,
        authorities,
    )
}

/// Idempotently transfer the exact loss-bound publication into an empty
/// replacement. The replacement stays a normal non-primary bootstrap node;
/// this function neither installs membership nor grants admission.
///
/// The restored state is bound to the signed `survivor_cut`, not to the older
/// `source_cut`: the publication that `validate` accepted is the survivor's
/// current one, so a tail committed after the certified cut is transferred and
/// never silently dropped. The signed `replacement_generation` is retained
/// through the restore because the successor membership is signed against it.
pub(crate) fn bootstrap_replacement<A: ReplicatedSchema>(
    survivor: &LossSurvivorHandle<A>,
    replacement: &mut Node<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
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
    let manifest = survivor.manifest(journal, trust, policy)?;
    let mut next = replacement.begin_snapshot(&manifest)?;
    while next < manifest.pages {
        let page = survivor.page(next, journal, trust, policy)?;
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
    survivor.revalidate(journal, trust, policy)?;
    Ok(checkpoint)
}

/// Read-only precondition for the future atomic local membership install.
/// The opaque proof is intentionally consumed only as installation authority;
/// it is not a completed writer capability and this function performs no ACK.
pub(crate) fn validate_successor_installation<A: ReplicatedSchema>(
    survivor: &LossSurvivorHandle<A>,
    replacement: &Node<A>,
    proof: &crate::recovery::transition::CommittedLossSuccessorTransition,
    source_journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::LossPolicy,
) -> Result<()> {
    survivor.revalidate(source_journal, trust, policy)?;
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
            && request.participants[0].member == loss.survivor.member
            && request.participants[0].generation == loss.survivor.generation
            && request.participants[1].member == loss.replacement_member
            && request.participants[1].generation == loss.replacement_generation
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
        .prepare("SELECT value FROM node_identity")?
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
    let history = history_format(c, runtime[0].0)?;
    recovery::verify_history(c, history)?;
    verify_certified(c, Some(trust))?;
    capacity::verify_schema(c)?;
    capacity::verify_accounting(c)?;
    schema_contract::verify(c, adapter, contract)?;
    sql_snapshot::verify_binding(c, adapter, &snapshot::scope(identity))?;
    ensure(
        loss.membership != loss.replacement_membership,
        "loss membership reused",
    )?;
    let json: String = c.query_row(
        "SELECT record FROM node_compaction_certificates ORDER BY sequence DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    ensure(json.len() <= 256 * 1024, "loss certificate limit")?;
    let certificate: certified::CertificateRecord = serde_json::from_str(&json)?;
    let verified = crate::recovery::transition::verify_historical(
        &certificate.token,
        &trust.as_trust(),
        &certificate.request,
    )?;
    // I1. The survivor index — and therefore the local role — is derived only
    // from the signed loss decision and this historically verified certificate.
    // Exactly one participant may match the survivor member *and* generation,
    // the other one must be exactly the fenced member/generation, and the owner
    // row must already carry the role that the index implies. Anything else
    // fails closed; no caller can supply or influence the role.
    let mut matches = certificate
        .request
        .participants
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            p.member == loss.survivor.member && p.generation == loss.survivor.generation
        });
    let index = matches.next().ok_or("loss survivor not certified")?.0;
    ensure(matches.next().is_none(), "loss survivor ambiguous")?;
    let lost = &certificate.request.participants[1 - index];
    ensure(
        lost.member == loss.lost_member && lost.generation == loss.lost_generation,
        "loss lost participant mismatch",
    )?;
    let role = if index == 0 {
        Role::Primary
    } else {
        Role::Secondary
    };
    // Installation-aware, still never an input: the owner row carries the
    // derived role until the signed successor membership is durably installed,
    // and exactly the role that record commits it to afterwards.
    let owner = survivor_owner_role(c, loss, role)?;
    ensure(
        identities[0] == serde_json::to_string(&(identity, owner))?,
        "loss survivor owner mismatch",
    )?;
    let local = certificate.request.participants[index].clone();
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
        certificate.request.membership == loss.membership
            && verified.certificate_id() == loss.source_certificate
            && verified.token_digest() == loss.source_token_digest
            && local.member == loss.survivor.member
            && local.generation == loss.survivor.generation
            && local.old_base == loss.survivor.old_base
            && local.target == loss.source_cut
            && base.sequence == loss.source_cut.sequence
            && id(&base)? == loss.source_cut.digest
            && current == manifest.checkpoint
            && current.sequence == loss.survivor_cut.sequence
            && id(&current)? == loss.survivor_cut.digest
            && id(&manifest)? == loss.survivor_publication,
        "loss survivor evidence mismatch",
    )?;
    Node::<A>::verify_publication_in(c, &manifest, identity, contract)?;
    Ok(Evidence { role, manifest })
}

fn id<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(value)?).into())
}
