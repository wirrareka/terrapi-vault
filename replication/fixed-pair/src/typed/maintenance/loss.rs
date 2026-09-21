//! Fail-closed page export from a permanently fenced certified survivor.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    marker::PhantomData,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[cfg(test)]
mod tests;

/// Everything `validate` derives from signed evidence. The survivor role is a
/// result, never a parameter: it exists only inside this module and is rebuilt
/// from the durable certificate on every validation.
pub(super) struct Evidence {
    role: Role,
    manifest: snapshot::Manifest,
}

/// Restricted capability: it owns the normal node lock, opens SQLite read-only,
/// and exposes only the exact loss-bound frozen publication.
pub(crate) struct LossSurvivorHandle<A: ReplicatedSchema> {
    db: Vesta,
    identity: Identity<SchemaId>,
    /// Derived by [`validate`] from the signed loss decision and the certificate.
    role: Role,
    contract: schema_contract::Contract,
    manifest: snapshot::Manifest,
    request: crate::recovery::transition::LossRequest,
    /// Canonical path and (device, inode) of the file that passed validation.
    /// Retained so a later durable step can prove it is the same file.
    path: PathBuf,
    file: (u64, u64),
    _adapter: PhantomData<A>,
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
            identity,
            role: evidence.role,
            contract,
            manifest: evidence.manifest,
            request,
            path,
            file,
            _adapter: PhantomData,
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
                // The owner row still has to carry exactly the role that the
                // signed evidence derived when this handle was opened.
                let identities: Vec<String> = c
                    .prepare("SELECT value FROM node_identity")?
                    .query_map([], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                ensure(
                    identities == [serde_json::to_string(&(&self.identity, self.role))?],
                    "loss survivor owner mismatch",
                )?;
                Node::<A>::verify_publication_in(c, &self.manifest, &self.identity, &self.contract)
            })())
        })??;
        Ok(())
    }
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
    ensure(
        identities[0] == serde_json::to_string(&(identity, role))?,
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
