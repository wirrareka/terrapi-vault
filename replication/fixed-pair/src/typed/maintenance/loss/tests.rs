//! Symmetric participant-loss evidence: a real certified pair, a real journal
//! loss decision, and a real bootstrap of the replacement. The survivor role is
//! never supplied by these tests; it is only ever asserted after derivation.
use super::*;
use crate::envelope_tests::{stock_entry, StockSchema};
use crate::recovery::transition;
use crate::typed::maintenance::tests::support;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{rand::SystemRandom, signature::EcdsaKeyPair};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};

const UNLIMITED: u64 = u64::MAX;

/// Test authority. Continuity, fencing and survivor evidence are all faked, but
/// every call really goes through the journal, so revocation is observable at
/// exactly the points the production code re-checks it.
struct Gate {
    live: AtomicBool,
    /// Remaining permitted `continuity_and_fencing` calls before hard denial.
    budget: AtomicU64,
    calls: AtomicU64,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            live: AtomicBool::new(true),
            budget: AtomicU64::new(UNLIMITED),
            calls: AtomicU64::new(0),
        })
    }
    fn allow(&self) {
        self.live.store(true, Ordering::SeqCst);
        self.budget.store(UNLIMITED, Ordering::SeqCst);
    }
    fn revoke(&self) {
        self.live.store(false, Ordering::SeqCst);
    }
    /// Deny the fencing check after exactly `n` further successful calls.
    fn revoke_after(&self, n: u64) {
        self.live.store(true, Ordering::SeqCst);
        self.budget.store(n, Ordering::SeqCst);
    }
    fn fencing_calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl transition::Policy for Gate {
    fn continuity(
        &self,
        _: &transition::JournalScope,
        _: &transition::Request,
    ) -> terrapi_vesta_recovery::Result<()> {
        ensure(self.live.load(Ordering::SeqCst), "stale test authority")
    }
    fn prepared(
        &self,
        _: &transition::JournalScope,
        _: &transition::Request,
        _: &transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        Ok(())
    }
    fn applied(
        &self,
        _: &transition::JournalScope,
        _: &transition::CommittedTransition,
        _: &transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        Ok(())
    }
    fn historical_completion(
        &self,
        _: &transition::JournalScope,
        historical: &transition::Request,
        head: &transition::Request,
    ) -> terrapi_vesta_recovery::Result<()> {
        ensure(
            self.live.load(Ordering::SeqCst)
                && (head == historical || head.revision > historical.revision)
                && head.authority_id == historical.authority_id
                && head.install == historical.install
                && head.region == historical.region
                && head.scope == historical.scope
                && head.schema == historical.schema
                && head.membership == historical.membership
                && head.source_anchor == historical.source_anchor,
            "stale historical test authority",
        )
    }
}

impl transition::LossPolicy for Gate {
    fn continuity_and_fencing(
        &self,
        _: &transition::JournalScope,
        _: &transition::LossRequest,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let remaining = self.budget.load(Ordering::SeqCst);
        if remaining == 0 {
            return Err("test fencing revoked".into());
        }
        if remaining != UNLIMITED {
            self.budget.store(remaining - 1, Ordering::SeqCst);
        }
        ensure(self.live.load(Ordering::SeqCst), "test fencing revoked")
    }
    fn survivor_prepared(
        &self,
        _: &transition::JournalScope,
        _: &transition::LossRequest,
    ) -> terrapi_vesta_recovery::Result<()> {
        ensure(self.live.load(Ordering::SeqCst), "test survivor evidence")
    }
    fn loss_successor_continuity(
        &self,
        scope: &transition::JournalScope,
        request: &transition::LossSuccessorRequest,
    ) -> terrapi_vesta_recovery::Result<()> {
        ensure(
            self.live.load(Ordering::SeqCst) && scope.membership == request.membership,
            "test successor continuity revoked",
        )
    }
    fn successor_abort_authorized(
        &self,
        _: &transition::JournalScope,
        _: &transition::LossRequest,
        _: &transition::LossSuccessorRequest,
        _: &transition::LossSuccessorAbort,
    ) -> terrapi_vesta_recovery::Result<()> {
        // Faked like every other authority fact here, but it really runs, so
        // revocation is observable exactly where the journal consults it.
        ensure(
            self.live.load(Ordering::SeqCst),
            "test successor abort revoked",
        )
    }
    fn superseded_successor_aborted(
        &self,
        _: &transition::JournalScope,
        _: &transition::LossRequest,
        _: &transition::Supersedes,
    ) -> terrapi_vesta_recovery::Result<()> {
        ensure(
            self.live.load(Ordering::SeqCst),
            "test supersession evidence revoked",
        )
    }
    // `loss_successor_applied` is deliberately left at its default deny: these
    // tests never acknowledge a participant.
}

/// Live certified authority needed to reopen the nodes after finalization and,
/// once attached, the participant-loss successor authority.
struct Live {
    journal: Mutex<transition::Journal>,
    successor: Mutex<Option<transition::Journal>>,
    trust: transition::TrustStore,
    gate: Arc<Gate>,
}

impl Live {
    fn attach_successor(&self, journal: transition::Journal) -> Result<()> {
        let mut slot = self
            .successor
            .lock()
            .map_err(|_| "test authority poisoned")?;
        *slot = Some(journal);
        Ok(())
    }
    fn detach_successor(&self) -> Result<()> {
        let mut slot = self
            .successor
            .lock()
            .map_err(|_| "test authority poisoned")?;
        *slot = None;
        Ok(())
    }
}

impl crate::typed::CertifiedAuthority for Live {
    fn fetch_completed(
        &self,
        request: &transition::Request,
    ) -> terrapi_vesta_recovery::Result<transition::CompletedTransition> {
        self.journal
            .lock()
            .map_err(|_| "test authority poisoned")?
            .fetch_completed(request, &self.trust.as_trust(), self.gate.as_ref())
    }
    fn fetch_completed_revision(
        &self,
        request: &transition::Request,
    ) -> terrapi_vesta_recovery::Result<transition::HistoricalCompletedTransition> {
        self.journal
            .lock()
            .map_err(|_| "test authority poisoned")?
            .fetch_completed_revision(request, &self.trust.as_trust(), self.gate.as_ref())
    }
    fn fetch_completed_loss_successor(
        &self,
        request: &transition::LossSuccessorRequest,
    ) -> terrapi_vesta_recovery::Result<transition::CompletedLossSuccessorTransition> {
        let slot = self
            .successor
            .lock()
            .map_err(|_| "test authority poisoned")?;
        slot.as_ref()
            .ok_or("participant-loss completion authority missing")?
            .fetch_completed_loss_successor(request, &self.trust.as_trust(), self.gate.as_ref())
    }
}

fn cut(prefix: &Prefix) -> Result<transition::Checkpoint> {
    Ok(transition::Checkpoint {
        sequence: prefix.sequence,
        digest: id(prefix)?,
    })
}

fn sign_loss(
    key: &EcdsaKeyPair,
    request: &transition::LossRequest,
    trust: &transition::TrustStore,
    certificate_id: [u8; 32],
) -> Result<String> {
    let header = B64.encode(serde_json::to_vec(&serde_json::json!({
        "alg": "ES256", "kid": "fixture", "typ": transition::LOSS_TOKEN_TYPE
    }))?);
    let claims = B64.encode(serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "iss": trust.profile.issuer,
        "aud": trust.profile.audience,
        "action": "terminate_and_replace",
        "certificate_id": certificate_id,
        "iat": 10, "nbf": 10, "exp": 20,
        "request": request,
        "request_digest": request.digest()?,
    }))?);
    let input = format!("{header}.{claims}");
    let signature = key
        .sign(&SystemRandom::new(), input.as_bytes())
        .map_err(|_| "loss token signing")?;
    Ok(format!("{input}.{}", B64.encode(signature.as_ref())))
}

/// A real certified pair plus a real durable loss decision for one of the two
/// members. Nothing here tells `loss::validate` which node survived.
struct Fixture {
    dir: tempfile::TempDir,
    identity: Identity<SchemaId>,
    trust: transition::TrustStore,
    journal: transition::Journal,
    gate: Arc<Gate>,
    live: Arc<Live>,
    certificate: transition::Request,
    certificate_token: String,
    loss: transition::LossRequest,
    loss_certificate_id: [u8; 32],
    loss_token_digest: [u8; 32],
    signer: EcdsaKeyPair,
    survivor_path: std::path::PathBuf,
    lost_path: std::path::PathBuf,
    replacement_path: std::path::PathBuf,
    survivor_checkpoint: Prefix,
    survivor_manifest: snapshot::Manifest,
    survivor_view: String,
    survivor_receipts: Vec<String>,
    survivor_capacity: (u64, u64),
}

impl Fixture {
    fn survivor_handle(&self) -> Result<LossSurvivorHandle<StockSchema>> {
        LossSurvivorHandle::open_existing(
            &self.survivor_path,
            self.identity.clone(),
            "fixture",
            StockSchema,
            &self.trust,
            &self.journal,
            self.gate.as_ref(),
        )
    }
    fn replacement(&self) -> Result<Node<StockSchema>> {
        self.open_replacement(Role::Secondary)
    }
    /// A node with a participant-loss install requires a live authority to
    /// open; a plain bootstrap node must not be given one.
    fn open_replacement(&self, role: Role) -> Result<Node<StockSchema>> {
        let installed =
            self.replacement_path.exists() && install_state(&self.replacement_path)?.0.is_some();
        if installed {
            Node::open_with_completed_transition(
                &self.replacement_path,
                role,
                self.identity.clone(),
                "fixture",
                StockSchema,
                self.trust.clone(),
                self.live.clone(),
            )
        } else {
            Node::open_with_transition_trust(
                &self.replacement_path,
                role,
                self.identity.clone(),
                "fixture",
                StockSchema,
                self.trust.clone(),
            )
        }
    }
    fn survivor_role(&self) -> Role {
        if self.certificate.participants[0].member == self.loss.survivor.member {
            Role::Primary
        } else {
            Role::Secondary
        }
    }
    fn lost_role(&self) -> Role {
        match self.survivor_role() {
            Role::Primary => Role::Secondary,
            Role::Secondary => Role::Primary,
        }
    }
    /// Ordinary node open, which the certified authority refuses once a loss has
    /// been decided. Used only to prove that refusal.
    fn open_node(&self, path: &Path, role: Role) -> Result<Node<StockSchema>> {
        Node::open_with_completed_transition(
            path,
            role,
            self.identity.clone(),
            "fixture",
            StockSchema,
            self.trust.clone(),
            self.live.clone(),
        )
    }
    /// Run `validate` against a path exactly the way the handle does: a
    /// read-only, `query_only` connection and no role input whatsoever.
    fn derive_role_at(&self, path: &Path, request: &transition::LossRequest) -> Result<Role> {
        self.derive_role_with(path, &self.identity, &self.trust, request)
    }
    fn derive_role_with(
        &self,
        path: &Path,
        identity: &Identity<SchemaId>,
        trust: &transition::TrustStore,
        request: &transition::LossRequest,
    ) -> Result<Role> {
        let scratch = Connection::open_in_memory()?;
        schema::initialize(&scratch, &StockSchema)?;
        let contract = schema_contract::describe(&scratch, &StockSchema)?;
        let initial = hash(&StockSchema.view(&scratch)?)?;
        let db = Vesta::open_read_only_with_passphrase(path, "fixture")?;
        Ok(db
            .with_connection(|c| {
                c.pragma_update(None, "query_only", true)?;
                Ok(validate::<StockSchema>(
                    c,
                    &StockSchema,
                    identity,
                    &contract,
                    &initial,
                    trust,
                    request,
                ))
            })??
            .role)
    }
}

/// The live authorities for one fixture and its successor journal.
fn authorities<'a>(
    f: &'a Fixture,
    successor_journal: &'a transition::Journal,
) -> Authorities<'a, Gate> {
    Authorities {
        source: &f.journal,
        successor: successor_journal,
        policy: f.gate.as_ref(),
    }
}

/// The signed document that founded an ordinary certified pair.
fn founding(f: &Fixture) -> Founding {
    Founding::Certificate(f.certificate.clone(), f.certificate_token.clone())
}

fn crash_founding(f: &CrashFixture) -> Founding {
    Founding::Certificate(f.certificate.clone(), f.certificate_token.clone())
}

fn receipt_rows(node: &Node<StockSchema>) -> Result<Vec<String>> {
    node.connection(|c| {
        Ok(
            c.prepare("SELECT receipt FROM operation_receipts ORDER BY sequence")?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?,
        )
    })
}

fn node_state(node: &Node<StockSchema>) -> Result<(Vec<String>, (u64, u64))> {
    let receipts = receipt_rows(node)?;
    let capacity = node.connection(|c| {
        Ok(c.query_row(
            "SELECT receipt_count,receipt_bytes FROM receipt_capacity WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    })?;
    Ok((receipts, capacity))
}

/// Build a certified fixed pair through the real pending/certified protocol,
/// optionally leave a committed tail plus a fresh frozen publication on the
/// survivor, and decide the loss of `lost` through the real journal.
fn fixture(lost: Role, tail: bool) -> Result<Fixture> {
    fixture_of(lost, tail, 1)
}

/// The same pair with a format-2 first loss. A format-1 loss carries no
/// optional fields at all, so only a format-2 one can ever be superseded.
fn fixture_v2(lost: Role, tail: bool) -> Result<Fixture> {
    fixture_of(lost, tail, 2)
}

fn fixture_of(lost: Role, tail: bool, format: u32) -> Result<Fixture> {
    let support::CertifiedPair {
        dir,
        mut p,
        mut s,
        plan,
        request: certificate,
        token,
        trust,
        key,
    } = support::certified_pair("loss-fixture-seed", [41; 32], "loss-fixture")?;
    pending::prepare_pair(&mut p, &mut s, &plan, &certificate, &token, 15, &trust)?;
    let identity = p.identity().clone();
    let primary_path = dir.path().join("candidate1");
    let secondary_path = dir.path().join("survivor");
    drop(p);
    drop(s);

    let journal_path = dir.path().join("loss-journal");
    let scope = transition::JournalScope {
        install: certificate.install.clone(),
        region: certificate.region.clone(),
        profile: trust.profile.clone(),
        scope: certificate.scope,
        schema: certificate.schema,
        membership: certificate.membership,
        source_anchor: certificate.source_anchor.clone(),
        authority_id: certificate.authority_id,
        initial_revision: certificate.revision,
    };
    let journal = transition::Journal::create(&journal_path, "journal-fixture", scope.clone())?;
    let gate = Gate::new();
    let mut hp = pending::PendingMaintenanceHandle::open_existing(
        &primary_path,
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema,
        &certificate,
        &trust,
    )?;
    let mut hs = pending::PendingMaintenanceHandle::open_existing(
        &secondary_path,
        Role::Secondary,
        identity.clone(),
        "fixture",
        StockSchema,
        &certificate,
        &trust,
    )?;
    pending::decide_prepared(&hp, &hs, &journal, 15, &trust, gate.as_ref())?;
    for handle in [&mut hp, &mut hs] {
        pending::record_decided(handle, &journal, &trust, gate.as_ref())?;
    }
    for handle in [&mut hp, &mut hs] {
        pending::apply_decided(handle, &journal, &trust, gate.as_ref())?;
    }
    for handle in [&hp, &hs] {
        pending::acknowledge_applied(handle, &journal, &trust, gate.as_ref())?;
    }
    pending::complete_authority(&hp, &hs, &journal, &trust, gate.as_ref())?;
    for handle in [&mut hp, &mut hs] {
        pending::record_complete(handle, &journal, &trust, gate.as_ref())?;
    }
    pending::finalize_pair(&mut hp, &mut hs, &journal, &trust, gate.as_ref())?;
    drop(hp);
    drop(hs);

    let live = Arc::new(Live {
        journal: Mutex::new(transition::Journal::open(
            &journal_path,
            "journal-fixture",
            scope,
            &trust.as_trust(),
        )?),
        successor: Mutex::new(None),
        trust: trust.clone(),
        gate: gate.clone(),
    });
    let mut p = Node::open_with_completed_transition(
        &primary_path,
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema,
        trust.clone(),
        live.clone(),
    )?;
    let mut s = Node::open_with_completed_transition(
        &secondary_path,
        Role::Secondary,
        identity.clone(),
        "fixture",
        StockSchema,
        trust.clone(),
        live.clone(),
    )?;
    if tail {
        let mut batch = stock_entry().batch;
        batch.operation_id = "loss-fixture-tail".into();
        commit(&mut p, &mut s, batch)?;
    }
    let survivor_index = match lost {
        Role::Primary => 1usize,
        Role::Secondary => 0usize,
    };
    let survivor: &mut Node<StockSchema> = if survivor_index == 0 { &mut p } else { &mut s };
    let published = survivor
        .published_snapshot()?
        .ok_or("fixture survivor publication missing")?;
    // `rotate_snapshot` is the only public API that freezes a new publication at
    // the current checkpoint, and it is available to either role.
    let survivor_manifest = if tail {
        survivor.rotate_snapshot(&published)?
    } else {
        published
    };
    let survivor_checkpoint = survivor.checkpoint()?;
    ensure(
        survivor_manifest.checkpoint == survivor_checkpoint,
        "fixture survivor publication is not current",
    )?;
    let survivor_view = serde_json::to_string(&survivor.view()?)?;
    let (survivor_receipts, survivor_capacity) = node_state(survivor)?;

    let replacement_path = dir.path().join("replacement");
    let replacement_generation = {
        let replacement = Node::open(
            &replacement_path,
            Role::Secondary,
            identity.clone(),
            "fixture",
            StockSchema,
        )?;
        replacement.connection(checkpoint::generation)?
    };
    let verified = transition::verify_historical(&token, &trust.as_trust(), &certificate)?;
    let lost_participant = &certificate.participants[1 - survivor_index];
    let survivor_participant = &certificate.participants[survivor_index];
    let loss = transition::LossRequest {
        format,
        id: [45; 32],
        authority_id: certificate.authority_id,
        revision: certificate.revision + 1,
        install: certificate.install.clone(),
        region: certificate.region.clone(),
        scope: certificate.scope,
        schema: certificate.schema,
        membership: certificate.membership,
        replacement_membership: [46; 32],
        source_certificate: verified.certificate_id(),
        source_token_digest: verified.token_digest(),
        source_cut: certificate.participants[0].target.clone(),
        lost_member: lost_participant.member,
        lost_generation: lost_participant.generation,
        survivor: transition::Participant {
            target: cut(&survivor_checkpoint)?,
            publication: id(&survivor_manifest)?,
            ..survivor_participant.clone()
        },
        survivor_cut: cut(&survivor_checkpoint)?,
        survivor_publication: id(&survivor_manifest)?,
        replacement_member: [47; 32],
        replacement_generation,
        fencing_ref: [48; 32],
        // A format-2 first loss is anchored to the same completed certificate;
        // only the optional fields exist at all, and only format 2 can ever be
        // superseded.
        source_kind: (format == 2).then_some(transition::SourceKind::Completed),
        abandoned_request: None,
        supersedes: None,
    };
    loss.validate()?;
    ensure(
        tail == (loss.survivor_cut != loss.source_cut),
        "fixture tail expectation mismatch",
    )?;
    let (survivor_path, lost_path) = match lost {
        Role::Primary => (secondary_path, primary_path),
        Role::Secondary => (primary_path, secondary_path),
    };
    drop(p);
    drop(s);
    let loss_token = sign_loss(&key, &loss, &trust, [49; 32])?;
    let committed = journal.decide_loss(
        loss.clone(),
        &loss_token,
        15,
        &trust.as_trust(),
        gate.as_ref(),
    )?;
    let loss_certificate_id = committed.certificate_id();
    let loss_token_digest = committed.token_digest();
    Ok(Fixture {
        dir,
        identity,
        trust,
        journal,
        gate,
        live,
        certificate,
        certificate_token: token,
        loss,
        loss_certificate_id,
        loss_token_digest,
        signer: key,
        survivor_path,
        lost_path,
        replacement_path,
        survivor_checkpoint,
        survivor_manifest,
        survivor_view,
        survivor_receipts,
        survivor_capacity,
    })
}

/// Full read-only evidence path plus a real bootstrap of the replacement, with
/// and without a tail committed after the certified cut.
fn evidence_and_bootstrap(lost: Role, tail: bool) -> Result<()> {
    let f = fixture(lost, tail)?;
    let expected_survivor = match lost {
        Role::Primary => Role::Secondary,
        Role::Secondary => Role::Primary,
    };
    if tail {
        assert!(f.loss.survivor_cut.sequence > f.loss.source_cut.sequence);
        assert_ne!(f.loss.survivor_cut, f.loss.source_cut);
    } else {
        assert_eq!(f.loss.survivor_cut, f.loss.source_cut);
    }
    let handle = f.survivor_handle()?;
    // The role was never passed in; it is the derived result of the evidence.
    assert_eq!(handle.role, expected_survivor);
    assert_eq!(handle.manifest, f.survivor_manifest);
    assert_eq!(handle.path, f.survivor_path.canonicalize()?);
    let metadata = std::fs::metadata(&f.survivor_path)?;
    assert_eq!(handle.file, (metadata.dev(), metadata.ino()));
    assert_eq!(
        handle.manifest(&f.journal, f.gate.as_ref())?,
        f.survivor_manifest
    );
    assert!(handle
        .page(f.survivor_manifest.pages, &f.journal, f.gate.as_ref())
        .is_err());
    assert!(handle.page(u64::MAX, &f.journal, f.gate.as_ref()).is_err());
    // Every page of the loss-bound publication is exportable for either role.
    for position in 0..f.survivor_manifest.pages {
        assert_eq!(
            handle.page(position, &f.journal, f.gate.as_ref())?.position,
            position
        );
    }
    assert!(f.survivor_manifest.pages > 0);

    let mut replacement = f.replacement()?;
    let checkpoint = bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    assert_eq!(cut(&checkpoint)?, f.loss.survivor_cut);
    assert_eq!(checkpoint, f.survivor_checkpoint);
    assert_eq!(
        serde_json::to_string(&replacement.view()?)?,
        f.survivor_view
    );
    let (receipts, capacity) = node_state(&replacement)?;
    assert_eq!(receipts, f.survivor_receipts);
    assert_eq!(capacity, f.survivor_capacity);
    // With a tail, the transferred history really contains the post-certified
    // operations: it is bound to the survivor cut, never truncated to the
    // certified source cut.
    assert_eq!(receipts.len() as u64, f.loss.survivor_cut.sequence);
    assert_eq!(
        tail,
        f.loss.survivor_cut.sequence > f.loss.source_cut.sequence
    );
    // The signed replacement generation survives the restore, because the
    // successor membership is signed against exactly this value.
    assert_eq!(
        replacement.connection(checkpoint::generation)?,
        f.loss.replacement_generation
    );
    // Exact retry over a completed restore: same checkpoint, no mutation.
    assert_eq!(
        bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?,
        checkpoint
    );
    assert_eq!(node_state(&replacement)?, (receipts, capacity));
    assert_eq!(
        replacement.connection(checkpoint::generation)?,
        f.loss.replacement_generation
    );
    // The replacement stays an ordinary non-primary bootstrap node.
    assert_eq!(replacement.role(), Role::Secondary);
    drop(replacement);
    drop(handle);
    drop(f);
    Ok(())
}

#[test]
fn lost_primary_survivor_evidence_and_bootstrap() -> Result<()> {
    evidence_and_bootstrap(Role::Primary, false)
}

#[test]
fn lost_secondary_survivor_evidence_and_bootstrap() -> Result<()> {
    evidence_and_bootstrap(Role::Secondary, false)
}

#[test]
fn lost_primary_survivor_tail_evidence_and_bootstrap() -> Result<()> {
    evidence_and_bootstrap(Role::Primary, true)
}

#[test]
fn lost_secondary_survivor_tail_evidence_and_bootstrap() -> Result<()> {
    evidence_and_bootstrap(Role::Secondary, true)
}

/// Regression guard: the public restore entry keeps rotating the admission
/// generation. Only the loss-bound internal entry retains a chosen one.
#[test]
fn public_finish_snapshot_rotates_generation_and_internal_entry_retains_it() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut batch = stock_entry().batch;
    batch.operation_id = "generation-contract".into();
    let identity = batch.identity.clone();
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    commit(&mut p, &mut s, batch)?;
    let manifest = p.publish_snapshot()?;
    let restore = |node: &mut Node<StockSchema>, source: &Node<StockSchema>| -> Result<()> {
        node.begin_snapshot(&manifest)?;
        for position in 0..manifest.pages {
            node.receive_snapshot(&source.snapshot_page(&manifest, position)?)?;
        }
        Ok(())
    };
    let mut rotating = Node::open(
        dir.path().join("rotating"),
        Role::Secondary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let before = rotating.connection(checkpoint::generation)?;
    restore(&mut rotating, &p)?;
    rotating.finish_snapshot(&manifest)?;
    assert_ne!(rotating.connection(checkpoint::generation)?, before);

    let mut retaining = Node::open(
        dir.path().join("retaining"),
        Role::Secondary,
        identity,
        "fixture",
        StockSchema,
    )?;
    let kept = retaining.connection(checkpoint::generation)?;
    restore(&mut retaining, &p)?;
    retaining.finish_snapshot_retaining_generation(&manifest, kept)?;
    assert_eq!(retaining.connection(checkpoint::generation)?, kept);
    assert_eq!(
        retaining.connection(checkpoint::base_for::<SchemaId>)?,
        Some(manifest.checkpoint.clone())
    );
    // Both restores produced identical state apart from the generation.
    assert_eq!(receipt_rows(&retaining)?, receipt_rows(&rotating)?);
    assert_eq!(
        serde_json::to_string(&retaining.view()?)?,
        serde_json::to_string(&rotating.view()?)?
    );
    Ok(())
}

/// Every way of mis-stating who survived must fail closed, and opening the
/// *other* node with the same decision must never re-derive a matching role.
#[test]
fn loss_evidence_rejects_every_role_and_identity_mismatch() -> Result<()> {
    let f = fixture(Role::Primary, false)?;
    assert_eq!(f.survivor_role(), Role::Secondary);
    assert_eq!(f.lost_role(), Role::Primary);
    // A decided loss closes ordinary admission for the whole old membership.
    assert!(f.open_node(&f.survivor_path, f.survivor_role()).is_err());
    assert!(f.open_node(&f.lost_path, f.lost_role()).is_err());

    let survivor = f.survivor_path.clone();
    let lost = f.lost_path.clone();
    // Baseline: the genuine decision derives Secondary on the real survivor.
    assert_eq!(f.derive_role_at(&survivor, &f.loss)?, Role::Secondary);
    // Role swap attempt: the same signed decision against the lost node derives
    // Secondary there too, which its Primary owner row refuses.
    assert_err_contains(f.derive_role_at(&lost, &f.loss), "owner mismatch");
    // And the real capability refuses to open on the lost node at all.
    assert!(LossSurvivorHandle::<StockSchema>::open_existing(
        &lost,
        f.identity.clone(),
        "fixture",
        StockSchema,
        &f.trust,
        &f.journal,
        f.gate.as_ref(),
    )
    .is_err());

    // Survivor and lost swapped: on the node we are actually opening, the
    // derived role flips to Primary and the owner row rejects it.
    let mut swapped = f.loss.clone();
    swapped.lost_member = f.loss.survivor.member;
    swapped.lost_generation = f.loss.survivor.generation;
    swapped.survivor.member = f.loss.lost_member;
    swapped.survivor.generation = f.loss.lost_generation;
    assert_err_contains(f.derive_role_at(&survivor, &swapped), "owner mismatch");

    let mut wrong_survivor_generation = f.loss.clone();
    wrong_survivor_generation.survivor.generation = [51; 32];
    assert_err_contains(
        f.derive_role_at(&survivor, &wrong_survivor_generation),
        "loss survivor not certified",
    );

    let mut wrong_lost_generation = f.loss.clone();
    wrong_lost_generation.lost_generation = [52; 32];
    assert_err_contains(
        f.derive_role_at(&survivor, &wrong_lost_generation),
        "loss lost participant mismatch",
    );

    let mut unknown_lost = f.loss.clone();
    unknown_lost.lost_member = [53; 32];
    assert_err_contains(
        f.derive_role_at(&survivor, &unknown_lost),
        "loss lost participant mismatch",
    );

    let mut unknown_survivor = f.loss.clone();
    unknown_survivor.survivor.member = [54; 32];
    assert_err_contains(
        f.derive_role_at(&survivor, &unknown_survivor),
        "loss survivor not certified",
    );

    let mut reused_membership = f.loss.clone();
    reused_membership.replacement_membership = f.loss.membership;
    assert_err_contains(
        f.derive_role_at(&survivor, &reused_membership),
        "loss membership reused",
    );

    let mut stale_cut = f.loss.clone();
    stale_cut.source_cut.sequence += 1;
    assert!(f.derive_role_at(&survivor, &stale_cut).is_err());

    let mut stale_certificate = f.loss.clone();
    stale_certificate.source_certificate = [55; 32];
    assert!(f.derive_role_at(&survivor, &stale_certificate).is_err());

    let mut stale_token = f.loss.clone();
    stale_token.source_token_digest = [57; 32];
    assert!(f.derive_role_at(&survivor, &stale_token).is_err());

    let mut wrong_membership = f.loss.clone();
    wrong_membership.membership = [58; 32];
    assert!(f.derive_role_at(&survivor, &wrong_membership).is_err());

    let mut wrong_publication = f.loss.clone();
    wrong_publication.survivor_publication = [56; 32];
    wrong_publication.survivor.publication = [56; 32];
    assert!(f.derive_role_at(&survivor, &wrong_publication).is_err());

    // A foreign owner identity is refused even with the genuine decision, and
    // an empty trust store cannot verify the certificate lineage at all.
    let mut other_identity = f.identity.clone();
    other_identity.epoch += 1;
    assert!(f
        .derive_role_with(&survivor, &other_identity, &f.trust, &f.loss)
        .is_err());
    let untrusted = transition::TrustStore {
        profile: f.trust.profile.clone(),
        keys: Vec::new(),
        max_lifetime: f.trust.max_lifetime,
    };
    assert!(f
        .derive_role_with(&survivor, &f.identity, &untrusted, &f.loss)
        .is_err());

    // The genuine decision still validates: none of the rejections mutated
    // anything on either node.
    assert_eq!(f.derive_role_at(&survivor, &f.loss)?, Role::Secondary);
    assert!(f.derive_role_at(&lost, &f.loss).is_err());
    drop(f);
    Ok(())
}

/// Live fencing is re-checked before the handle exists, before every page and
/// once more after the durable restore.
#[test]
fn loss_export_fails_closed_on_revocation_at_every_boundary() -> Result<()> {
    let f = fixture(Role::Secondary, false)?;
    f.gate.revoke();
    assert_err_contains(f.survivor_handle(), "test fencing revoked");
    f.gate.allow();
    let handle = f.survivor_handle()?;
    let pages = handle.manifest(&f.journal, f.gate.as_ref())?.pages;
    assert!(pages > 0);

    // Revoked between pages: the manifest call passes, the first page does not.
    // The partial transfer leaves staged pages but no completed restore.
    let mut replacement = f.replacement()?;
    f.gate.revoke_after(1);
    assert!(bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref()).is_err());
    assert!(replacement.connection(|c| Ok(c.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM node_restore_complete) AND EXISTS(SELECT 1 FROM node_restore)",
        [],
        |r| r.get::<_, bool>(0)
    )?))?);
    assert!(replacement.checkpoint().is_err());
    assert_eq!(
        replacement.connection(checkpoint::generation)?,
        f.loss.replacement_generation
    );

    // Partial resume that is revoked exactly at the final revalidation: the
    // manifest call and every page pass, the closing fencing check does not.
    f.gate.revoke_after(pages + 1);
    let before = f.gate.fencing_calls();
    assert!(bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref()).is_err());
    assert_eq!(f.gate.fencing_calls() - before, pages + 2);
    // The restore itself did land, so the failure really was the last check.
    assert_eq!(
        replacement.connection(checkpoint::base_for::<SchemaId>)?,
        Some(f.survivor_manifest.checkpoint.clone())
    );
    assert_eq!(
        replacement.connection(checkpoint::generation)?,
        f.loss.replacement_generation
    );

    // With live authority the same call now returns, verifying the completed
    // restore instead of repairing it.
    f.gate.allow();
    let receipts = receipt_rows(&replacement)?;
    let checkpoint = bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    assert_eq!(cut(&checkpoint)?, f.loss.survivor_cut);
    assert_eq!(receipt_rows(&replacement)?, receipts);
    assert_eq!(
        replacement.connection(checkpoint::generation)?,
        f.loss.replacement_generation
    );
    drop(replacement);
    drop(handle);
    drop(f);
    Ok(())
}

fn successor_scope(f: &Fixture) -> transition::JournalScope {
    successor_scope_of(f, &f.loss)
}

/// Scope of the successor journal a given loss decision founds. Every loss in
/// a lineage founds its own journal, so this is shared by first and later
/// losses alike.
fn successor_scope_of(f: &Fixture, loss: &transition::LossRequest) -> transition::JournalScope {
    transition::JournalScope {
        install: loss.install.clone(),
        region: loss.region.clone(),
        profile: f.trust.profile.clone(),
        scope: loss.scope,
        schema: loss.schema,
        membership: loss.replacement_membership,
        source_anchor: loss.source_cut.clone(),
        authority_id: loss.authority_id,
        initial_revision: loss.revision + 1,
    }
}

fn successor_request_with(f: &Fixture, id: [u8; 32]) -> transition::LossSuccessorRequest {
    transition::LossSuccessorRequest {
        id,
        ..successor_request(f)
    }
}

/// Format-2 successor: participants are in the canonical `[primary, secondary]`
/// order and `survivor_index` names the survivor, so the recovered pair still
/// carries its roles and can take a further loss. Both index values occur
/// naturally — a lost Primary leaves a Secondary survivor at index 1.
fn successor_request(f: &Fixture) -> transition::LossSuccessorRequest {
    successor_request_of(f, 2)
}

/// Format-1 successor, kept for the compatibility test.
fn successor_request_v1(f: &Fixture) -> transition::LossSuccessorRequest {
    successor_request_of(f, 1)
}

fn successor_request_of(f: &Fixture, format: u32) -> transition::LossSuccessorRequest {
    successor_for(
        &f.loss,
        f.loss_certificate_id,
        f.loss_token_digest,
        f.survivor_role(),
        format,
        [60; 32],
    )
}

/// The successor membership a signed loss decision implies, for either format
/// and whichever role survived. The survivor keeps its pre-loss role and the
/// replacement takes the lost one, so the canonical `[primary, secondary]`
/// order of a format-2 request follows directly from the surviving role.
/// Format 1 always orders `[survivor, replacement]` and names no role at all.
fn successor_for(
    loss: &transition::LossRequest,
    parent_certificate: [u8; 32],
    parent_token_digest: [u8; 32],
    survivor_role: Role,
    format: u32,
    id: [u8; 32],
) -> transition::LossSuccessorRequest {
    let replacement = transition::Participant {
        member: loss.replacement_member,
        generation: loss.replacement_generation,
        old_base: Some(loss.survivor_cut.clone()),
        target: loss.survivor_cut.clone(),
        plan: loss.survivor.plan,
        publication: loss.survivor_publication,
    };
    let survivor_index = u8::from(format == 2 && survivor_role == Role::Secondary);
    let participants = if survivor_index == 0 {
        [loss.survivor.clone(), replacement]
    } else {
        [replacement, loss.survivor.clone()]
    };
    transition::LossSuccessorRequest {
        format,
        id,
        authority_id: loss.authority_id,
        revision: loss.revision + 1,
        install: loss.install.clone(),
        region: loss.region.clone(),
        scope: loss.scope,
        schema: loss.schema,
        membership: loss.replacement_membership,
        source_certificate: loss.source_certificate,
        source_token_digest: loss.source_token_digest,
        source_cut: loss.source_cut.clone(),
        parent_loss_certificate: parent_certificate,
        parent_loss_token_digest: parent_token_digest,
        survivor_cut: loss.survivor_cut.clone(),
        survivor_publication: loss.survivor_publication,
        participants,
        survivor_index: (format == 2).then_some(survivor_index),
    }
}

fn sign_successor(
    key: &EcdsaKeyPair,
    request: &transition::LossSuccessorRequest,
    trust: &transition::TrustStore,
    certificate_id: [u8; 32],
) -> Result<String> {
    let header = B64.encode(serde_json::to_vec(&serde_json::json!({
        "alg": "ES256", "kid": "fixture", "typ": transition::LOSS_SUCCESSOR_TOKEN_TYPE
    }))?);
    let claims = B64.encode(serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "iss": trust.profile.issuer,
        "aud": trust.profile.audience,
        "action": "activate_loss_successor",
        "certificate_id": certificate_id,
        "iat": 10, "nbf": 10, "exp": 20,
        "request": request,
        "request_digest": request.digest()?,
    }))?);
    let input = format!("{header}.{claims}");
    let signature = key
        .sign(&SystemRandom::new(), input.as_bytes())
        .map_err(|_| "successor token signing")?;
    Ok(format!("{input}.{}", B64.encode(signature.as_ref())))
}

/// Decide a real successor transition in a real successor journal and return
/// the install-only proof. No acknowledgement is ever made.
fn successor_proof(
    f: &Fixture,
    name: &str,
) -> Result<(
    transition::Journal,
    transition::CommittedLossSuccessorTransition,
)> {
    successor_proof_with(f, name, [60; 32])
}

fn successor_proof_with(
    f: &Fixture,
    name: &str,
    id: [u8; 32],
) -> Result<(
    transition::Journal,
    transition::CommittedLossSuccessorTransition,
)> {
    let request = successor_request_with(f, id);
    let token = sign_successor(&f.signer, &request, &f.trust, [61; 32])?;
    let journal = transition::Journal::create_loss_successor(
        &f.dir.path().join(name),
        "successor-fixture",
        successor_scope(f),
        &f.journal,
        &f.trust.as_trust(),
        f.gate.as_ref(),
    )?;
    journal.decide_loss_successor(
        request.clone(),
        &token,
        15,
        &f.trust.as_trust(),
        f.gate.as_ref(),
    )?;
    let proof = journal.fetch_loss_successor(&request, &f.trust.as_trust(), f.gate.as_ref())?;
    ensure(
        proof.acknowledgements() == [false; 2],
        "fixture successor was acknowledged",
    )?;
    Ok((journal, proof))
}

/// `validate_successor_installation` is a read-only precondition bound to the
/// exact survivor, replacement and parent loss, for either surviving role.
#[test]
fn successor_installation_binds_survivor_replacement_and_parent_loss() -> Result<()> {
    let mut prepared = Vec::new();
    for lost in [Role::Primary, Role::Secondary] {
        let f = fixture(lost, true)?;
        let handle = f.survivor_handle()?;
        let mut replacement = f.replacement()?;
        let checkpoint =
            bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
        assert_eq!(cut(&checkpoint)?, f.loss.survivor_cut);
        let (journal, proof) = successor_proof(&f, "successor-journal")?;
        prepared.push((f, handle, replacement, journal, proof));
    }
    for (index, (f, handle, replacement, journal, proof)) in prepared.iter().enumerate() {
        assert_eq!(
            handle.role,
            match index {
                0 => Role::Secondary,
                _ => Role::Primary,
            }
        );
        let before = (
            receipt_rows(replacement)?,
            replacement.connection(checkpoint::generation)?,
            replacement.connection(checkpoint::base_for::<SchemaId>)?,
        );
        // Positive: the read-only precondition holds for the real pairing.
        validate_successor_installation(handle, replacement, proof, &f.journal, f.gate.as_ref())?;
        // It is verification only: nothing was written and nothing acknowledged.
        assert_eq!(
            (
                receipt_rows(replacement)?,
                replacement.connection(checkpoint::generation)?,
                replacement.connection(checkpoint::base_for::<SchemaId>)?
            ),
            before
        );
        assert_eq!(
            journal
                .fetch_loss_successor(proof.request(), &f.trust.as_trust(), f.gate.as_ref())?
                .acknowledgements(),
            [false; 2]
        );

        // Negative: a replacement restored through the public rotating path.
        let rotated_path = f.dir.path().join("rotated-replacement");
        let mut rotated = Node::open(
            &rotated_path,
            Role::Secondary,
            f.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        rotated.connection(|c| {
            c.execute(
                "UPDATE replication_generation SET value=?1 WHERE id=1",
                [f.loss.replacement_generation.as_slice()],
            )?;
            Ok(())
        })?;
        let manifest = handle.manifest(&f.journal, f.gate.as_ref())?;
        rotated.begin_snapshot(&manifest)?;
        for position in 0..manifest.pages {
            rotated.receive_snapshot(&handle.page(position, &f.journal, f.gate.as_ref())?)?;
        }
        rotated.finish_snapshot(&manifest)?;
        assert_ne!(
            rotated.connection(checkpoint::generation)?,
            f.loss.replacement_generation
        );
        assert!(validate_successor_installation(
            handle,
            &rotated,
            proof,
            &f.journal,
            f.gate.as_ref()
        )
        .is_err());
        drop(rotated);

        // Negative: a different, empty replacement node.
        let other = Node::<StockSchema>::open(
            f.dir.path().join("other-replacement"),
            Role::Secondary,
            f.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        assert!(validate_successor_installation(
            handle,
            &other,
            proof,
            &f.journal,
            f.gate.as_ref()
        )
        .is_err());
        drop(other);

        // Negative: a successor proof produced under a different loss.
        let foreign_proof = &prepared[1 - index].4;
        assert_ne!(foreign_proof.loss_request(), proof.loss_request());
        assert!(validate_successor_installation(
            handle,
            replacement,
            foreign_proof,
            &f.journal,
            f.gate.as_ref()
        )
        .is_err());

        // Negative: revoked authority.
        f.gate.revoke();
        assert!(validate_successor_installation(
            handle,
            replacement,
            proof,
            &f.journal,
            f.gate.as_ref()
        )
        .is_err());
        f.gate.allow();
        validate_successor_installation(handle, replacement, proof, &f.journal, f.gate.as_ref())?;
    }
    drop(prepared);
    Ok(())
}

/// The replacement must be an empty, correctly generationed bootstrap Secondary.
#[test]
fn loss_bootstrap_rejects_wrong_replacement_role_generation_and_state() -> Result<()> {
    let f = fixture(Role::Primary, false)?;
    let handle = f.survivor_handle()?;

    // Wrong role: an empty Primary is never a bootstrap target.
    let mut wrong_role = Node::open(
        f.dir.path().join("replacement-primary"),
        Role::Primary,
        f.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert_err_contains(
        bootstrap_replacement(&handle, &mut wrong_role, &f.journal, f.gate.as_ref()),
        "loss replacement owner mismatch",
    );
    assert_eq!(wrong_role.checkpoint()?.sequence, 0);
    drop(wrong_role);

    // Wrong generation: a different empty Secondary.
    let mut wrong_generation = Node::open(
        f.dir.path().join("replacement-other"),
        Role::Secondary,
        f.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert_ne!(
        wrong_generation.connection(checkpoint::generation)?,
        f.loss.replacement_generation
    );
    assert_err_contains(
        bootstrap_replacement(&handle, &mut wrong_generation, &f.journal, f.gate.as_ref()),
        "loss replacement generation mismatch",
    );
    assert_eq!(wrong_generation.checkpoint()?.sequence, 0);

    // Non-empty replacement carrying the signed replacement generation: the
    // emptiness guard, not the generation guard, must reject it.
    let populated_dir = f.dir.path().join("populated");
    std::fs::create_dir(&populated_dir)?;
    let mut op = Node::open(
        populated_dir.join("p"),
        Role::Primary,
        f.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut os = Node::open(
        populated_dir.join("s"),
        Role::Secondary,
        f.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut batch = stock_entry().batch;
    batch.operation_id = "populated-replacement".into();
    commit(&mut op, &mut os, batch)?;
    drop(op);
    os.connection(|c| {
        c.execute(
            "UPDATE replication_generation SET value=?1 WHERE id=1",
            [f.loss.replacement_generation.as_slice()],
        )?;
        Ok(())
    })?;
    assert_eq!(
        os.connection(checkpoint::generation)?,
        f.loss.replacement_generation
    );
    let before = receipt_rows(&os)?;
    assert!(bootstrap_replacement(&handle, &mut os, &f.journal, f.gate.as_ref()).is_err());
    assert_eq!(receipt_rows(&os)?, before);
    assert!(os.connection(|c| Ok(c.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM node_restore) AND NOT EXISTS(SELECT 1 FROM node_restore_complete)",
        [],
        |r| r.get::<_, bool>(0)
    )?))?);

    // A foreign-identity replacement is rejected as an owner mismatch.
    let mut other_identity = f.identity.clone();
    other_identity.epoch += 1;
    let mut foreign = Node::open(
        f.dir.path().join("replacement-foreign"),
        Role::Secondary,
        other_identity,
        "fixture",
        StockSchema,
    )?;
    assert!(bootstrap_replacement(&handle, &mut foreign, &f.journal, f.gate.as_ref()).is_err());
    drop(foreign);
    drop(os);
    drop(wrong_generation);
    drop(handle);
    drop(f);
    Ok(())
}

// ---------------------------------------------------------------------------
// S2: durable successor install on both nodes.
// ---------------------------------------------------------------------------

fn meta_of(path: &Path) -> PathBuf {
    let mut raw = path.as_os_str().to_owned();
    raw.push(".meta.json");
    PathBuf::from(raw)
}

/// Install record JSON (if any) and the raw owner row, read through a separate
/// read-only connection so the assertions never go through the handle.
fn install_state(path: &Path) -> Result<InstallState> {
    let db = Vesta::open_read_only_with_passphrase(path, "fixture")?;
    db.with_connection(|c| {
        Ok((|| -> Result<InstallState> {
            let record = if table_exists(c, INSTALL_TABLE)? {
                c.query_row(
                    "SELECT record FROM recovery_loss_active WHERE id=1",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
            } else {
                None
            };
            Ok((record, owner_row(c)?))
        })())
    })?
}

fn node_install_state(node: &Node<StockSchema>) -> Result<InstallState> {
    node.connection(|c| {
        let record = if table_exists(c, INSTALL_TABLE)? {
            c.query_row(
                "SELECT record FROM recovery_loss_active WHERE id=1",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        } else {
            None
        };
        Ok((record, owner_row(c)?))
    })
}

fn owner_role(row: &str) -> Result<Role> {
    let (_, role): (Identity<SchemaId>, Role) = serde_json::from_str(row)?;
    Ok(role)
}

fn decode_install(json: &str) -> Result<Installed> {
    Ok(serde_json::from_str(json)?)
}

/// Install record JSON (if any) together with the raw owner row.
type InstallState = (Option<String>, String);
/// Install state, operation receipts and admission generation of a node.
type ReplacementState = (InstallState, Vec<String>, [u8; 32]);

/// Everything an install must leave untouched on a replacement.
fn replacement_state(node: &Node<StockSchema>) -> Result<ReplacementState> {
    Ok((
        node_install_state(node)?,
        receipt_rows(node)?,
        node.connection(checkpoint::generation)?,
    ))
}

/// Raw read-write surgery on a node file whose lock is currently free.
fn tamper(path: &Path, sql: &str) -> Result<()> {
    let db = Vesta::open(path, "fixture")?;
    db.with_connection(|c| c.execute_batch(sql))?;
    Ok(())
}

/// Every ordinary mutating entry point of a typed node, for the closed-admission
/// assertions. Each returns `Err` once a loss install is durable.
fn every_mutation_is_rejected(node: &mut Node<StockSchema>) -> Result<()> {
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-loss-install".into();
    ensure(node.prepare(batch.clone()).is_err(), "prepare admitted")?;
    ensure(node.decide(&batch.operation_id).is_err(), "decide admitted")?;
    ensure(node.abort(&batch.operation_id).is_err(), "abort admitted")?;
    assert_err_contains(node.checkpoint(), "data admission closed");
    ensure(node.verified_view().is_err(), "verified view admitted")?;
    ensure(node.summary().is_err(), "summary admitted")?;
    ensure(node.journal_head().is_err(), "journal head admitted")?;
    ensure(node.plan_compaction().is_err(), "compaction plan admitted")?;
    ensure(
        node.enable_maintenance().is_err(),
        "maintenance upgrade admitted",
    )?;
    ensure(
        node.upgrade_receipt_capacity().is_err(),
        "capacity upgrade admitted",
    )?;
    ensure(node.publish_snapshot().is_err(), "publication admitted")?;
    ensure(
        node.publish_recovery_snapshot().is_err(),
        "recovery publication admitted",
    )?;
    let manifest = snapshot::Manifest::decode(
        node.connection(|c| {
            Ok(c.query_row(
                "SELECT manifest FROM node_restore_complete WHERE id=1",
                [],
                |r| r.get::<_, String>(0),
            )?)
        })?
        .as_bytes(),
    )?;
    ensure(
        node.rotate_snapshot(&manifest).is_err(),
        "rotation admitted",
    )?;
    ensure(
        node.pin_snapshot(&manifest, "after-loss").is_err(),
        "pinning admitted",
    )?;
    ensure(
        node.snapshot_page(&manifest, 0).is_err(),
        "page export admitted",
    )?;
    ensure(
        node.begin_snapshot(&manifest).is_err(),
        "snapshot bootstrap admitted",
    )?;
    ensure(
        node.finish_snapshot(&manifest).is_err(),
        "snapshot completion admitted",
    )?;
    ensure(
        node.cleanup_snapshot_staging(&manifest).is_err(),
        "staging cleanup admitted",
    )?;
    ensure(
        node.cancel_snapshot(&manifest).is_err(),
        "snapshot cancellation admitted",
    )?;
    ensure(
        node.confirm_checkpoint(manifest.checkpoint.clone())
            .is_err(),
        "read admission granted",
    )?;
    Ok(())
}

/// One full local install cycle for one surviving role, with and without a tail.
/// The survivor keeps its pre-loss role; the replacement takes the lost one.
fn install_cycle(lost: Role, tail: bool) -> Result<()> {
    let f = fixture(lost, tail)?;
    let derived = match lost {
        Role::Primary => Role::Secondary,
        Role::Secondary => Role::Primary,
    };
    let handle = f.survivor_handle()?;
    assert_eq!(handle.role, derived);
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    let live = authorities(&f, &successor_journal);
    validate_successor_installation(&handle, &replacement, &proof, &f.journal, f.gate.as_ref())?;

    // Before any install both nodes are ordinary: the replacement is admitted.
    assert!(replacement.checkpoint().is_ok());
    let before = install_state(&f.survivor_path)?;
    assert_eq!(before.0, None);
    assert_eq!(owner_role(&before.1)?, derived);

    handle.install_successor("fixture", &successor, &live)?;

    let (json, owner) = install_state(&f.survivor_path)?;
    let record = decode_install(json.as_deref().ok_or("survivor install record missing")?)?;
    // A new install is always format 2: it stores the issued successor token,
    // so a later loss can authenticate this recovery by signature.
    assert_eq!(record.format, 2);
    let stored_token = record
        .successor_token
        .clone()
        .ok_or("stored successor token missing")?;
    assert_eq!(stored_token, proof.token());
    assert_eq!(sha(&stored_token), proof.token_digest());
    assert_eq!(record.loss, f.loss);
    assert_eq!(record.loss_certificate, f.loss_certificate_id);
    assert_eq!(record.loss_token_digest, f.loss_token_digest);
    assert_eq!(record.successor, successor);
    assert_eq!(record.successor_certificate, proof.certificate_id());
    assert_eq!(record.successor_token_digest, proof.token_digest());
    assert_eq!(record.source_scope, *proof.source_scope());
    assert_eq!(record.member, f.loss.survivor.member);
    assert_eq!(record.generation, f.loss.survivor.generation);
    // The survivor keeps its derived role and its owner row is never written.
    assert_eq!(record.previous_role, derived);
    assert_eq!(record.installed_role, derived);
    assert_eq!(record.survivor_cut, f.loss.survivor_cut);
    assert_eq!(record.publication, f.loss.survivor_publication);
    assert_eq!(owner, before.1);
    assert_eq!(owner_role(&owner)?, derived);

    // Historical validation is exactly the regression a promotion would break:
    // export, page read and `validate` all stay green on the installed survivor.
    assert_eq!(
        handle.manifest(&f.journal, f.gate.as_ref())?,
        f.survivor_manifest
    );
    handle.page(0, &f.journal, f.gate.as_ref())?;
    assert_eq!(f.derive_role_at(&f.survivor_path, &f.loss)?, derived);
    assert_eq!(
        bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?,
        f.survivor_checkpoint
    );

    // Exact retry of the survivor install writes nothing.
    handle.install_successor("fixture", &successor, &live)?;
    assert_eq!(
        install_state(&f.survivor_path)?,
        (json.clone(), owner.clone())
    );

    // Replacement install: it inherits the lost member's role.
    let replacement_before = replacement_state(&replacement)?;
    install_replacement(&mut replacement, &founding(&f), &successor, &live)?;
    assert_eq!(replacement.role(), lost);
    let (rjson, rowner) = node_install_state(&replacement)?;
    let rrecord = decode_install(rjson.as_deref().ok_or("replacement record missing")?)?;
    assert_eq!(rrecord.member, f.loss.replacement_member);
    assert_eq!(rrecord.generation, f.loss.replacement_generation);
    assert_eq!(rrecord.previous_role, Role::Secondary);
    assert_eq!(rrecord.installed_role, lost);
    assert_eq!(rrecord.successor, successor);
    assert_eq!(rrecord.loss, f.loss);
    assert_eq!(owner_role(&rowner)?, lost);
    assert_eq!(lost == Role::Primary, rowner != replacement_before.0 .1);
    assert_eq!(receipt_rows(&replacement)?, replacement_before.1);
    assert_eq!(
        replacement.connection(checkpoint::generation)?,
        replacement_before.2
    );

    // Exact retry of the replacement install, on the still-open handle.
    let after = replacement_state(&replacement)?;
    install_replacement(&mut replacement, &founding(&f), &successor, &live)?;
    assert_eq!(replacement_state(&replacement)?, after);

    // A bootstrap retry on an installed replacement fails closed without
    // mutating anything (a promoted one is no longer a bootstrap Secondary).
    assert!(bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref()).is_err());
    assert_eq!(replacement_state(&replacement)?, after);

    // Both nodes are now closed to ordinary traffic and stay closed.
    every_mutation_is_rejected(&mut replacement)?;
    assert!(f.open_node(&f.survivor_path, Role::Primary).is_err());
    assert!(f.open_node(&f.survivor_path, Role::Secondary).is_err());
    assert!(f.open_node(&f.lost_path, f.lost_role()).is_err());
    assert_eq!(
        successor_journal
            .fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
            .acknowledgements(),
        [false; 2]
    );

    // Restart: the replacement reopens under its new role and only that role.
    drop(handle);
    drop(replacement);
    let handle = f.survivor_handle()?;
    assert_eq!(handle.role, derived);
    assert_eq!(f.derive_role_at(&f.survivor_path, &f.loss)?, derived);
    let other = match lost {
        Role::Primary => Role::Secondary,
        Role::Secondary => Role::Primary,
    };
    assert!(f.open_replacement(other).is_err());
    // A loss-installed node is only openable with a live authority.
    assert!(Node::<StockSchema>::open(
        &f.replacement_path,
        lost,
        f.identity.clone(),
        "fixture",
        StockSchema,
    )
    .is_err());
    let mut replacement = f.open_replacement(lost)?;
    assert_eq!(replacement.role(), lost);
    every_mutation_is_rejected(&mut replacement)?;
    handle.install_successor("fixture", &successor, &live)?;
    install_replacement(&mut replacement, &founding(&f), &successor, &live)?;
    assert_eq!(install_state(&f.survivor_path)?, (json, owner));
    assert_eq!(replacement_state(&replacement)?, after);
    drop(replacement);
    drop(handle);
    drop(f);
    Ok(())
}

#[test]
fn loss_install_for_lost_primary_without_tail() -> Result<()> {
    install_cycle(Role::Primary, false)
}

#[test]
fn loss_install_for_lost_primary_with_tail() -> Result<()> {
    install_cycle(Role::Primary, true)
}

#[test]
fn loss_install_for_lost_secondary_without_tail() -> Result<()> {
    install_cycle(Role::Secondary, false)
}

#[test]
fn loss_install_for_lost_secondary_with_tail() -> Result<()> {
    install_cycle(Role::Secondary, true)
}

/// A prepared, installable survivor plus its bootstrapped replacement. Uses the
/// lost-Secondary shape so the surviving member is already Primary.
struct Installable {
    f: Fixture,
    handle: LossSurvivorHandle<StockSchema>,
    replacement: Node<StockSchema>,
    successor_journal: transition::Journal,
    successor: transition::LossSuccessorRequest,
}

fn installable(tail: bool) -> Result<Installable> {
    let f = fixture(Role::Secondary, tail)?;
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    Ok(Installable {
        f,
        handle,
        replacement,
        successor_journal,
        successor,
    })
}

impl Installable {
    fn live(&self) -> Authorities<'_, Gate> {
        authorities(&self.f, &self.successor_journal)
    }
    fn install_survivor(&self) -> Result<()> {
        self.handle
            .install_successor("fixture", &self.successor, &self.live())
    }
    fn install_replacement_now(&mut self) -> Result<()> {
        let live = authorities(&self.f, &self.successor_journal);
        install_replacement(
            &mut self.replacement,
            &founding(&self.f),
            &self.successor,
            &live,
        )
    }
}

/// Differing records, tampered records and half-applied state are conflicts.
/// Nothing is ever repaired and nothing else is written.
#[test]
fn loss_install_rejects_conflicting_and_partial_state() -> Result<()> {
    let mut it = installable(false)?;
    // A successor decided in a second journal is a different membership record.
    let (other_journal, other_proof) =
        successor_proof_with(&it.f, "successor-journal-other", [70; 32])?;
    let other = other_proof.request().clone();
    assert_ne!(other, it.successor);

    it.install_survivor()?;
    let good = install_state(&it.f.survivor_path)?;
    assert!(good.0.is_some());

    // Different successor request: conflict, record untouched.
    assert_err_contains(
        it.handle
            .install_successor("fixture", &other, &authorities(&it.f, &other_journal)),
        "loss install conflict",
    );
    assert_eq!(install_state(&it.f.survivor_path)?, good);

    it.install_replacement_now()?;
    let replacement_good = replacement_state(&it.replacement)?;
    let certificate = it.f.certificate.clone();
    let certificate_token = it.f.certificate_token.clone();
    let other_live = authorities(&it.f, &other_journal);
    assert!(install_replacement(
        &mut it.replacement,
        &Founding::Certificate(certificate, certificate_token),
        &other,
        &other_live,
    )
    .is_err());
    assert_eq!(replacement_state(&it.replacement)?, replacement_good);

    // Surgery needs the locks released.
    let survivor_path = it.f.survivor_path.clone();
    let replacement_path = it.f.replacement_path.clone();
    drop(it.handle);
    drop(it.replacement);

    let reopen = |f: &Fixture| f.survivor_handle();
    // Tampered record.
    tamper(
        &survivor_path,
        "UPDATE recovery_loss_active SET record='{\"format\":1}' WHERE id=1",
    )?;
    assert!(reopen(&it.f).is_err());
    tamper(
        &survivor_path,
        &format!(
            "UPDATE recovery_loss_active SET record='{}' WHERE id=1",
            good.0
                .as_deref()
                .ok_or("record missing")?
                .replace('\'', "''")
        ),
    )?;
    reopen(&it.f)?;

    // Record present but the owner row was never promoted to the installed role.
    // On this shape the survivor is already Primary, so demote it instead: the
    // owner row then contradicts the record and the file fails closed.
    let demoted = serde_json::to_string(&(&it.f.identity, Role::Secondary))?;
    tamper(
        &survivor_path,
        &format!("UPDATE node_identity SET value='{demoted}'"),
    )?;
    assert!(reopen(&it.f).is_err());
    tamper(
        &survivor_path,
        &format!("UPDATE node_identity SET value='{}'", good.1),
    )?;
    reopen(&it.f)?;

    // A second install row is a conflict, not a repair.
    tamper(
        &survivor_path,
        "PRAGMA ignore_check_constraints=ON;
         INSERT INTO recovery_loss_active VALUES(2,'{}');",
    )?;
    assert!(reopen(&it.f).is_err());
    tamper(
        &survivor_path,
        "DELETE FROM recovery_loss_active WHERE id=2",
    )?;
    reopen(&it.f)?;

    // An unexpected recovery_* table blocks the install even on exact retry.
    tamper(
        &survivor_path,
        "CREATE TABLE recovery_loss_pending(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)",
    )?;
    let handle = it.f.survivor_handle()?;
    let live = authorities(&it.f, &it.successor_journal);
    assert!(handle
        .install_successor("fixture", &it.successor, &live)
        .is_err());
    assert_eq!(install_state(&survivor_path)?, good);
    drop(handle);
    tamper(&survivor_path, "DROP TABLE recovery_loss_pending")?;

    // Same for the replacement: a recovery table this release never writes
    // fails closed instead of being ignored.
    tamper(
        &replacement_path,
        "CREATE TABLE recovery_loss_pending(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)",
    )?;
    let mut replacement = it.f.replacement()?;
    assert!(
        install_replacement(&mut replacement, &founding(&it.f), &it.successor, &live,).is_err()
    );
    assert_eq!(node_install_state(&replacement)?, replacement_good.0);
    drop(replacement);
    tamper(&replacement_path, "DROP TABLE recovery_loss_pending")?;
    // A foreign recovery seal is refused even earlier, at the ordinary open.
    tamper(
        &replacement_path,
        "CREATE TABLE recovery_seal(id INTEGER PRIMARY KEY CHECK(id=1),plan TEXT NOT NULL)",
    )?;
    assert!(it.f.replacement().is_err());
    tamper(&replacement_path, "DROP TABLE recovery_seal")?;

    // The genuine retry still succeeds after every rejected attempt.
    let handle = it.f.survivor_handle()?;
    handle.install_successor("fixture", &it.successor, &live)?;
    assert_eq!(install_state(&survivor_path)?, good);
    drop(handle);
    Ok(())
}

/// The replacement install binds to the exact signed participant and state.
#[test]
fn loss_replacement_install_rejects_wrong_bindings() -> Result<()> {
    let mut it = installable(false)?;
    it.install_survivor()?;

    // A different empty replacement has neither the generation nor a base.
    let mut empty = Node::open(
        it.f.dir.path().join("empty-replacement"),
        Role::Secondary,
        it.f.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let live = authorities(&it.f, &it.successor_journal);
    assert!(install_replacement(&mut empty, &founding(&it.f), &it.successor, &live,).is_err());
    assert_eq!(node_install_state(&empty)?.0, None);
    drop(empty);

    // A replacement restored through the public rotating path loses the signed
    // generation and can never install the signed successor membership.
    let mut rotated = Node::open(
        it.f.dir.path().join("rotated-replacement"),
        Role::Secondary,
        it.f.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    rotated.connection(|c| {
        c.execute(
            "UPDATE replication_generation SET value=?1 WHERE id=1",
            [it.f.loss.replacement_generation.as_slice()],
        )?;
        Ok(())
    })?;
    let manifest = it.handle.manifest(&it.f.journal, it.f.gate.as_ref())?;
    rotated.begin_snapshot(&manifest)?;
    for position in 0..manifest.pages {
        rotated.receive_snapshot(&it.handle.page(
            position,
            &it.f.journal,
            it.f.gate.as_ref(),
        )?)?;
    }
    rotated.finish_snapshot(&manifest)?;
    assert!(install_replacement(&mut rotated, &founding(&it.f), &it.successor, &live,).is_err());
    assert_eq!(node_install_state(&rotated)?.0, None);
    drop(rotated);

    // A proof produced under a different loss never installs here.
    let other = fixture(Role::Secondary, false)?;
    let (_other_journal, other_proof) = successor_proof(&other, "successor-journal")?;
    assert_ne!(other_proof.loss_request(), &it.f.loss);
    assert!(install_replacement(
        &mut it.replacement,
        &founding(&it.f),
        other_proof.request(),
        &live,
    )
    .is_err());
    assert_eq!(node_install_state(&it.replacement)?.0, None);
    drop(other);

    // The survivor file is not an ordinary node and cannot be installed as a
    // replacement; the replacement file is not a certified survivor either.
    assert!(Node::<StockSchema>::open(
        &it.f.survivor_path,
        Role::Primary,
        it.f.identity.clone(),
        "fixture",
        StockSchema,
    )
    .is_err());
    assert!(LossSurvivorHandle::<StockSchema>::open_existing(
        &it.f.replacement_path,
        it.f.identity.clone(),
        "fixture",
        StockSchema,
        &it.f.trust,
        &it.f.journal,
        it.f.gate.as_ref(),
    )
    .is_err());

    // The genuine pairing still installs.
    it.install_replacement_now()?;
    assert!(node_install_state(&it.replacement)?.0.is_some());
    Ok(())
}

/// Replacing the database under the held lock must be detected before any write.
#[test]
fn loss_install_rejects_path_swap_under_the_lock() -> Result<()> {
    let it = installable(false)?;
    let survivor = it.f.survivor_path.clone();
    let aside = it.f.dir.path().join("survivor-aside");
    let substitute = it.f.lost_path.clone();

    std::fs::rename(&survivor, &aside)?;
    std::fs::rename(meta_of(&survivor), meta_of(&aside))?;
    std::fs::copy(&substitute, &survivor)?;
    std::fs::copy(meta_of(&substitute), meta_of(&survivor))?;

    assert!(it.install_survivor().is_err());
    // Neither the moved original nor the substitute gained an install record.
    assert_eq!(install_state(&aside)?.0, None);
    assert_eq!(install_state(&survivor)?.0, None);
    assert_eq!(install_state(&substitute)?.0, None);

    std::fs::remove_file(&survivor)?;
    std::fs::remove_file(meta_of(&survivor))?;
    std::fs::rename(&aside, &survivor)?;
    std::fs::rename(meta_of(&aside), meta_of(&survivor))?;

    // A byte-identical copy of the survivor itself is still a different file.
    // No content check could tell it apart; only the recorded (device, inode)
    // does, and the retained read-only connection still points at the original.
    let twin = it.f.dir.path().join("survivor-twin");
    std::fs::copy(&survivor, &twin)?;
    std::fs::copy(meta_of(&survivor), meta_of(&twin))?;
    std::fs::rename(&survivor, &aside)?;
    std::fs::rename(meta_of(&survivor), meta_of(&aside))?;
    std::fs::rename(&twin, &survivor)?;
    std::fs::rename(meta_of(&twin), meta_of(&survivor))?;
    assert_err_contains(it.install_survivor(), "loss survivor file replaced");
    std::fs::remove_file(&survivor)?;
    std::fs::remove_file(meta_of(&survivor))?;
    std::fs::rename(&aside, &survivor)?;
    std::fs::rename(meta_of(&aside), meta_of(&survivor))?;
    // The original, still the file the handle validated, gained nothing.
    assert_eq!(install_state(&survivor)?.0, None);

    // The same handle, still holding the same lock, installs once the real file
    // is back in place.
    it.install_survivor()?;
    assert!(install_state(&survivor)?.0.is_some());
    Ok(())
}

/// Revocation at any live boundary leaves either no record at all or exactly
/// the one inert record: never a half-applied state. The sweep must actually
/// observe all three outcomes, so the boundaries are provably exercised.
#[test]
fn loss_install_fails_closed_on_revocation_at_every_boundary() -> Result<()> {
    let mut it = installable(false)?;
    let expected_owner = install_state(&it.f.survivor_path)?.1;

    it.f.gate.revoke();
    assert!(it.install_survivor().is_err());
    assert_eq!(
        install_state(&it.f.survivor_path)?,
        (None, expected_owner.clone())
    );

    // (i) error, nothing durable; (ii) error after the commit, exactly the
    // record durable; (iii) success.
    let (mut denied, mut committed_but_failed, mut succeeded) = (false, false, false);
    let mut record: Option<String> = None;
    for budget in 0..12u64 {
        it.f.gate.revoke_after(budget);
        let outcome = it.install_survivor();
        let (json, owner) = install_state(&it.f.survivor_path)?;
        // The survivor's owner row is never written by any install attempt.
        assert_eq!(owner, expected_owner);
        match (&record, &json) {
            (None, None) => {
                assert!(outcome.is_err());
                denied = true;
            }
            (None, Some(fresh)) => {
                record = Some(fresh.clone());
                if outcome.is_err() {
                    committed_but_failed = true;
                } else {
                    succeeded = true;
                }
            }
            (Some(old), Some(fresh)) => {
                assert_eq!(old, fresh);
                if outcome.is_ok() {
                    succeeded = true;
                } else {
                    committed_but_failed = true;
                }
            }
            (Some(_), None) => panic!("durable loss install record disappeared"),
        }
    }
    assert!(denied, "no attempt was refused before the commit");
    assert!(
        committed_but_failed,
        "no attempt failed its post-commit check"
    );
    assert!(succeeded, "no attempt ever succeeded");
    let durable = record.ok_or("record missing")?;
    it.f.gate.allow();
    it.install_survivor()?;
    assert_eq!(
        install_state(&it.f.survivor_path)?,
        (Some(durable), expected_owner)
    );

    // Same three outcomes for the replacement install.
    let (mut denied, mut committed_but_failed, mut succeeded) = (false, false, false);
    let mut replacement_record: Option<String> = None;
    for budget in 0..12u64 {
        it.f.gate.revoke_after(budget);
        let outcome = it.install_replacement_now();
        let json = node_install_state(&it.replacement)?.0;
        match (&replacement_record, &json) {
            (None, None) => {
                assert!(outcome.is_err());
                denied = true;
            }
            (None, Some(fresh)) => {
                replacement_record = Some(fresh.clone());
                if outcome.is_err() {
                    committed_but_failed = true;
                } else {
                    succeeded = true;
                }
            }
            (Some(old), Some(fresh)) => {
                assert_eq!(old, fresh);
                if outcome.is_ok() {
                    succeeded = true;
                } else {
                    committed_but_failed = true;
                }
            }
            (Some(_), None) => panic!("durable replacement record disappeared"),
        }
    }
    assert!(
        denied,
        "no replacement attempt was refused before the commit"
    );
    assert!(
        committed_but_failed,
        "no replacement attempt failed its post-commit check"
    );
    assert!(succeeded, "no replacement attempt ever succeeded");
    it.f.gate.allow();
    it.install_replacement_now()?;
    assert_eq!(node_install_state(&it.replacement)?.0, replacement_record);
    // No acknowledgement was made anywhere along the way.
    assert_eq!(
        it.successor_journal
            .fetch_loss_successor(&it.successor, &it.f.trust.as_trust(), it.f.gate.as_ref())?
            .acknowledgements(),
        [false; 2]
    );
    Ok(())
}

/// The replacement's role comes from the signed source certificate the loss
/// names. No other certificate can stand in for it, and the caller supplies no
/// role, index or boolean anywhere.
#[test]
fn loss_replacement_role_requires_the_signed_source_certificate() -> Result<()> {
    let mut it = installable(false)?;
    it.install_survivor()?;
    let live = authorities(&it.f, &it.successor_journal);
    let clean = replacement_state(&it.replacement)?;
    assert_eq!(clean.0 .0, None);

    let attempt = |node: &mut Node<StockSchema>,
                   certificate: &transition::Request,
                   token: &str|
     -> Result<()> {
        install_replacement(
            node,
            &Founding::Certificate(certificate.clone(), token.into()),
            &it.successor,
            &live,
        )
    };

    // A certificate from a different membership.
    let other = fixture(Role::Secondary, false)?;
    assert_ne!(other.certificate.membership, it.f.certificate.membership);
    assert!(attempt(
        &mut it.replacement,
        &other.certificate,
        &other.certificate_token
    )
    .is_err());

    // The right certificate with someone else's token, and the reverse.
    assert!(attempt(
        &mut it.replacement,
        &it.f.certificate,
        &other.certificate_token
    )
    .is_err());
    assert!(attempt(
        &mut it.replacement,
        &other.certificate,
        &it.f.certificate_token
    )
    .is_err());
    drop(other);

    // Participants swapped relative to the truth: the token no longer binds.
    let mut swapped = it.f.certificate.clone();
    swapped.participants.swap(0, 1);
    assert!(attempt(&mut it.replacement, &swapped, &it.f.certificate_token).is_err());

    // A freshly signed certificate for the same request is still not the one
    // the loss pinned: its token digest differs.
    let resigned = certified::tests::sign(&it.f.signer, &it.f.certificate)?;
    assert_ne!(resigned, it.f.certificate_token);
    assert!(attempt(&mut it.replacement, &it.f.certificate, &resigned).is_err());

    // A validly signed certificate for a different request in the same scope.
    let mut renumbered = it.f.certificate.clone();
    renumbered.id = [71; 32];
    let renumbered_token = certified::tests::sign(&it.f.signer, &renumbered)?;
    assert!(attempt(&mut it.replacement, &renumbered, &renumbered_token).is_err());

    // A certificate whose participants are a different pair entirely.
    let mut foreign_pair = it.f.certificate.clone();
    foreign_pair.participants[0].member = [72; 32];
    foreign_pair.participants[1].member = [73; 32];
    let foreign_token = certified::tests::sign(&it.f.signer, &foreign_pair)?;
    assert!(attempt(&mut it.replacement, &foreign_pair, &foreign_token).is_err());

    // Nothing was written by any of the refusals, and the genuine certificate
    // still installs.
    assert_eq!(replacement_state(&it.replacement)?, clean);
    it.install_replacement_now()?;
    assert!(node_install_state(&it.replacement)?.0.is_some());
    assert_eq!(it.replacement.role(), Role::Secondary);
    Ok(())
}

/// A promoted replacement: the owner row and the record must agree in both
/// directions, and neither half is ever repaired.
#[test]
fn promoted_replacement_rejects_owner_and_record_disagreement() -> Result<()> {
    let f = fixture(Role::Primary, false)?;
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    let live = authorities(&f, &successor_journal);
    handle.install_successor("fixture", &successor, &live)?;
    install_replacement(&mut replacement, &founding(&f), &successor, &live)?;
    assert_eq!(replacement.role(), Role::Primary);
    let (record, promoted_owner) = node_install_state(&replacement)?;
    let record = record.ok_or("replacement record missing")?;
    let demoted_owner = serde_json::to_string(&(&f.identity, Role::Secondary))?;
    drop(replacement);

    let retry = |role: Role| -> Result<()> {
        let mut node = f.open_replacement(role)?;
        install_replacement(&mut node, &founding(&f), &successor, &live)
    };

    // Record present, owner row demoted: the node opens as Secondary but the
    // install refuses to re-apply or to repair either half.
    tamper(
        &f.replacement_path,
        &format!("UPDATE node_identity SET value='{demoted_owner}'"),
    )?;
    assert!(f.open_replacement(Role::Primary).is_err());
    assert!(retry(Role::Secondary).is_err());
    assert_eq!(
        install_state(&f.replacement_path)?,
        (Some(record.clone()), demoted_owner)
    );
    tamper(
        &f.replacement_path,
        &format!("UPDATE node_identity SET value='{promoted_owner}'"),
    )?;

    // Owner row promoted with no record: also a conflict, never a repair.
    tamper(&f.replacement_path, "DELETE FROM recovery_loss_active")?;
    assert!(retry(Role::Primary).is_err());
    assert_eq!(
        install_state(&f.replacement_path)?,
        (None, promoted_owner.clone())
    );
    tamper(
        &f.replacement_path,
        &format!(
            "INSERT INTO recovery_loss_active VALUES(1,'{}')",
            record.replace('\'', "''")
        ),
    )?;

    // Consistent again: the exact retry is a verified no-op under both the
    // reopened Primary and a fresh open.
    retry(Role::Primary)?;
    assert_eq!(
        install_state(&f.replacement_path)?,
        (Some(record), promoted_owner)
    );
    drop(handle);
    drop(f);
    Ok(())
}

// ---------------------------------------------------------------------------
// S3: acknowledgements, completion and writer admission.
// ---------------------------------------------------------------------------

fn successor_journal_handle(f: &Fixture, name: &str) -> Result<transition::Journal> {
    transition::Journal::open(
        &f.dir.path().join(name),
        "successor-fixture",
        successor_scope(f),
        &f.trust.as_trust(),
    )
}

fn open_with_authority(f: &Fixture, path: &Path, role: Role) -> Result<Node<StockSchema>> {
    Node::open_with_completed_transition(
        path,
        role,
        f.identity.clone(),
        "fixture",
        StockSchema,
        f.trust.clone(),
        f.live.clone(),
    )
}

fn capacity_of(node: &Node<StockSchema>) -> Result<(u64, u64)> {
    node.connection(|c| {
        c.query_row(
            "SELECT receipt_count,receipt_bytes FROM receipt_capacity WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(Into::into)
    })
}

/// Everything from a decided loss to the first write of the new pair.
fn recovery_cycle(lost: Role, tail: bool) -> Result<()> {
    let f = fixture(lost, tail)?;
    let derived = match lost {
        Role::Primary => Role::Secondary,
        Role::Secondary => Role::Primary,
    };
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    let live = authorities(&f, &successor_journal);

    // No install at all: no participant may be acknowledged.
    assert!(complete_successor(&handle, &replacement, &successor, &live).is_err());
    // A fabricated acknowledgement is impossible: the default-deny policy has
    // no applied-evidence implementation at all.
    let decision =
        successor_journal.fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?;
    for participant in decision.request().participants.iter() {
        assert!(successor_journal
            .acknowledge_loss_successor(
                &decision,
                participant,
                &f.trust.as_trust(),
                f.gate.as_ref()
            )
            .is_err());
    }

    // Only the survivor installed: still no acknowledgement for either side.
    handle.install_successor("fixture", &successor, &live)?;
    assert!(complete_successor(&handle, &replacement, &successor, &live).is_err());
    assert_eq!(
        successor_journal
            .fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
            .acknowledgements(),
        [false; 2]
    );

    install_replacement(&mut replacement, &founding(&f), &successor, &live)?;
    f.live
        .attach_successor(successor_journal_handle(&f, "successor-journal")?)?;

    // Both installed but not yet completed: admission stays closed on both.
    assert!(replacement.checkpoint().is_err());
    drop(replacement);
    drop(handle);
    let survivor_node = open_with_authority(&f, &f.survivor_path, derived)?;
    assert!(survivor_node.checkpoint().is_err());
    assert!(record_completion(&survivor_node).is_err());
    drop(survivor_node);
    let handle = f.survivor_handle()?;
    let replacement = f.open_replacement(lost)?;

    // Complete at the authority. The id is derived, so an exact retry always
    // converges; a conflicting id can only be injected at the journal itself.
    complete_successor(&handle, &replacement, &successor, &live)?;
    complete_successor(&handle, &replacement, &successor, &live)?;
    let decided =
        successor_journal.fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?;
    assert_eq!(
        successor_journal
            .fetch_completed_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
            .completion(),
        completion_id(
            decided.request(),
            decided.token_digest(),
            decided.acknowledgements()
        )?
    );
    assert_err_contains(
        successor_journal.complete_loss_successor(
            &decided,
            [81; 32],
            &f.trust.as_trust(),
            f.gate.as_ref(),
        ),
        "immutable replacement completion conflict",
    );
    assert_eq!(
        successor_journal
            .fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
            .acknowledgements(),
        [true; 2]
    );
    // Completed at the authority, but no local receipt yet: still closed.
    assert!(replacement.checkpoint().is_err());
    drop(replacement);
    drop(handle);

    // Record local completion, one node at a time.
    let survivor_node = open_with_authority(&f, &f.survivor_path, derived)?;
    let replacement_node = open_with_authority(&f, &f.replacement_path, lost)?;
    record_completion(&survivor_node)?;
    assert!(survivor_node.checkpoint().is_ok());
    assert!(replacement_node.checkpoint().is_err());
    record_completion(&replacement_node)?;
    record_completion(&replacement_node)?;
    assert!(replacement_node.checkpoint().is_ok());

    // The successor membership now names the new pair on both sides.
    assert_eq!(
        survivor_node.required_recovery_peer()?,
        Some(f.loss.replacement_member)
    );
    assert_eq!(
        replacement_node.required_recovery_peer()?,
        Some(f.loss.survivor.member)
    );
    assert_eq!(
        survivor_node.recovery_member_identity()?,
        Some(f.loss.survivor.member)
    );
    assert_eq!(
        replacement_node.recovery_member_identity()?,
        Some(f.loss.replacement_member)
    );

    // First write of the new pair.
    let (mut primary, mut secondary) = match lost {
        Role::Primary => (replacement_node, survivor_node),
        Role::Secondary => (survivor_node, replacement_node),
    };
    assert_eq!(primary.role(), Role::Primary);
    assert_eq!(secondary.role(), Role::Secondary);
    let before = f.survivor_receipts.len() as u64;
    assert_eq!(before, f.loss.survivor_cut.sequence);
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-participant-loss".into();
    let result = commit(&mut primary, &mut secondary, batch.clone())?;
    assert_eq!(result.sequence, before + 1);
    // Exact retry of the write is a no-op.
    assert_eq!(
        commit(&mut primary, &mut secondary, batch.clone())?.sequence,
        before + 1
    );
    // Data, receipts and capacity accounting continue from the survivor cut.
    assert_eq!(
        serde_json::to_string(&primary.view()?)?,
        serde_json::to_string(&secondary.view()?)?
    );
    let receipts = receipt_rows(&primary)?;
    assert_eq!(receipts.len() as u64, before + 1);
    assert_eq!(receipts[..before as usize], f.survivor_receipts[..]);
    assert_eq!(receipt_rows(&secondary)?, receipts);
    assert_eq!(capacity_of(&primary)?, capacity_of(&secondary)?);
    assert_eq!(capacity_of(&primary)?.0, before + 1);
    assert!(primary.receipt(&batch.operation_id)?.is_some());
    assert!(secondary.receipt(&batch.operation_id)?.is_some());

    // Maintenance and compaction stay shut on a loss-recovered pair.
    for node in [&mut primary, &mut secondary] {
        assert!(node.plan_compaction().is_err());
        assert!(node.enable_maintenance().is_err());
        assert!(node.publish_recovery_snapshot().is_err());
    }

    // Live revocation closes both nodes again without touching durable state.
    let durable = (
        install_state(&f.survivor_path)?,
        install_state(&f.replacement_path)?,
    );
    f.live.detach_successor()?;
    assert!(primary.checkpoint().is_err());
    assert!(secondary.checkpoint().is_err());
    f.live
        .attach_successor(successor_journal_handle(&f, "successor-journal")?)?;
    assert!(primary.checkpoint().is_ok());
    assert!(secondary.checkpoint().is_ok());
    f.gate.revoke();
    assert!(primary.checkpoint().is_err());
    f.gate.allow();
    assert!(primary.checkpoint().is_ok());
    assert_eq!(
        (
            install_state(&f.survivor_path)?,
            install_state(&f.replacement_path)?
        ),
        durable
    );

    // The lost member's file never becomes admissible again.
    assert!(f.open_node(&f.lost_path, f.lost_role()).is_err());
    assert!(open_with_authority(&f, &f.lost_path, Role::Primary).is_err());
    assert!(open_with_authority(&f, &f.lost_path, Role::Secondary).is_err());

    // Restart: everything converges and the pair keeps writing.
    drop(primary);
    drop(secondary);
    let survivor_node = open_with_authority(&f, &f.survivor_path, derived)?;
    let replacement_node = open_with_authority(&f, &f.replacement_path, lost)?;
    record_completion(&survivor_node)?;
    record_completion(&replacement_node)?;
    let (mut primary, mut secondary) = match lost {
        Role::Primary => (replacement_node, survivor_node),
        Role::Secondary => (survivor_node, replacement_node),
    };
    let mut next = stock_entry().batch;
    next.operation_id = "after-participant-loss-restart".into();
    assert_eq!(
        commit(&mut primary, &mut secondary, next)?.sequence,
        before + 2
    );
    assert_eq!(primary.checkpoint()?, secondary.checkpoint()?);
    drop(primary);
    drop(secondary);
    drop(f);
    Ok(())
}

#[test]
fn recovery_cycle_for_lost_primary_without_tail() -> Result<()> {
    recovery_cycle(Role::Primary, false)
}

#[test]
fn recovery_cycle_for_lost_primary_with_tail() -> Result<()> {
    recovery_cycle(Role::Primary, true)
}

#[test]
fn recovery_cycle_for_lost_secondary_without_tail() -> Result<()> {
    recovery_cycle(Role::Secondary, false)
}

#[test]
fn recovery_cycle_for_lost_secondary_with_tail() -> Result<()> {
    recovery_cycle(Role::Secondary, true)
}

/// A local completion receipt without an install record is never evidence of
/// anything: it closes the node instead of being ignored.
#[test]
fn orphan_participant_loss_completion_is_refused() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let identity = stock_entry().batch.identity;
    let path = dir.path().join("plain");
    let node = Node::open(
        &path,
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert!(node.checkpoint().is_ok());
    drop(node);
    tamper(
        &path,
        "CREATE TABLE recovery_loss_completion(id INTEGER PRIMARY KEY CHECK(id=1),receipt TEXT NOT NULL)",
    )?;
    assert!(Node::<StockSchema>::open(
        &path,
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema
    )
    .is_err());
    tamper(&path, "DROP TABLE recovery_loss_completion")?;
    let node = Node::<StockSchema>::open(&path, Role::Primary, identity, "fixture", StockSchema)?;
    assert!(node.checkpoint().is_ok());
    Ok(())
}

/// Acknowledgement evidence is read live from both node databases (I7), so a
/// tampered or missing install on either side refuses the whole ACK.
#[test]
fn acknowledgement_requires_both_durable_installs() -> Result<()> {
    let f = fixture(Role::Secondary, false)?;
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    let live = authorities(&f, &successor_journal);

    // Replacement installed, survivor not: still no acknowledgement.
    install_replacement(&mut replacement, &founding(&f), &successor, &live)?;
    assert!(complete_successor(&handle, &replacement, &successor, &live).is_err());
    handle.install_successor("fixture", &successor, &live)?;

    // Both installed: the acknowledgement is accepted.
    complete_successor(&handle, &replacement, &successor, &live)?;
    let acknowledged = successor_journal
        .fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
        .acknowledgements();
    assert_eq!(acknowledged, [true; 2]);

    // A second, independent successor decision over the same loss cannot be
    // acknowledged once either install no longer matches it.
    let (other_journal, other_proof) =
        successor_proof_with(&f, "successor-journal-other", [90; 32])?;
    let other = other_proof.request().clone();
    let other_live = authorities(&f, &other_journal);
    assert!(complete_successor(&handle, &replacement, &other, &other_live).is_err());

    // Tamper with the replacement's record: the survivor's ACK is refused too.
    let replacement_path = f.replacement_path.clone();
    let good = node_install_state(&replacement)?;
    drop(replacement);
    tamper(
        &replacement_path,
        "UPDATE recovery_loss_active SET record='{\"format\":1}' WHERE id=1",
    )?;
    let broken = f.open_replacement(Role::Secondary);
    assert!(broken.is_err());
    tamper(
        &replacement_path,
        &format!(
            "UPDATE recovery_loss_active SET record='{}' WHERE id=1",
            good.0
                .as_deref()
                .ok_or("record missing")?
                .replace('\'', "''")
        ),
    )?;
    let replacement = f.open_replacement(Role::Secondary)?;
    assert_eq!(node_install_state(&replacement)?, good);

    // Removing the replacement's record entirely refuses any further ACK on a
    // fresh successor decision, whichever participant is named.
    drop(replacement);
    tamper(&replacement_path, "DROP TABLE recovery_loss_active")?;
    let replacement = f.open_replacement(Role::Secondary)?;
    let decision =
        other_journal.fetch_loss_successor(&other, &f.trust.as_trust(), f.gate.as_ref())?;
    for participant in decision.request().participants.iter() {
        assert!(other_journal
            .acknowledge_loss_successor(
                &decision,
                participant,
                &f.trust.as_trust(),
                f.gate.as_ref()
            )
            .is_err());
    }
    assert!(complete_successor(&handle, &replacement, &other, &other_live).is_err());
    drop(replacement);
    drop(handle);
    drop(f);
    Ok(())
}

/// The lost member's own database never becomes admissible again, and the
/// pre-loss membership can never be handshaken with a recovered node.
#[test]
fn returning_lost_member_and_old_membership_stay_rejected() -> Result<()> {
    let f = fixture(Role::Primary, false)?;
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    let live = authorities(&f, &successor_journal);
    // The lost member's file is already closed before anything is installed.
    assert!(f.open_node(&f.lost_path, f.lost_role()).is_err());

    install_pair(
        &handle,
        &mut replacement,
        "fixture",
        &founding(&f),
        &successor,
        &live,
    )?;
    f.live
        .attach_successor(successor_journal_handle(&f, "successor-journal")?)?;
    complete_successor(&handle, &replacement, &successor, &live)?;
    drop(replacement);
    drop(handle);

    let survivor_node = open_with_authority(&f, &f.survivor_path, Role::Secondary)?;
    let replacement_node = open_with_authority(&f, &f.replacement_path, Role::Primary)?;
    record_completion(&survivor_node)?;
    record_completion(&replacement_node)?;

    // The handshake digest is bound to the successor membership on both sides
    // and is no longer the pre-loss membership of the certified pair.
    let survivor_summary = survivor_node.summary()?;
    let replacement_summary = replacement_node.summary()?;
    assert_eq!(survivor_summary.membership, replacement_summary.membership);
    assert_ne!(survivor_summary.membership, Some(f.certificate.membership));
    assert_eq!(
        survivor_node.required_recovery_peer()?,
        Some(f.loss.replacement_member)
    );
    assert_eq!(
        replacement_node.required_recovery_peer()?,
        Some(f.loss.survivor.member)
    );
    assert_ne!(
        survivor_node.required_recovery_peer()?,
        Some(f.loss.lost_member)
    );

    // The lost member is still unopenable, with and without an authority, and
    // stays that way across a restart.
    for _ in 0..2 {
        assert!(Node::<StockSchema>::open(
            &f.lost_path,
            Role::Primary,
            f.identity.clone(),
            "fixture",
            StockSchema
        )
        .is_err());
        assert!(open_with_authority(&f, &f.lost_path, Role::Primary).is_err());
        assert!(open_with_authority(&f, &f.lost_path, Role::Secondary).is_err());
    }
    drop(survivor_node);
    drop(replacement_node);
    drop(f);
    Ok(())
}

/// Acknowledgement evidence is bound to the source journal scope the successor
/// journal records as its parent, on both nodes.
#[test]
fn acknowledgement_binds_the_source_journal_scope() -> Result<()> {
    let f = fixture(Role::Secondary, false)?;
    let mut handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    let live = authorities(&f, &successor_journal);
    install_pair(
        &handle,
        &mut replacement,
        "fixture",
        &founding(&f),
        &successor,
        &live,
    )?;

    let survivor_path = f.survivor_path.clone();
    let replacement_path = f.replacement_path.clone();
    let good_survivor = install_state(&survivor_path)?;
    let good_replacement = node_install_state(&replacement)?;

    // Rewrite one record so it claims a different source journal region. It
    // still decodes and still binds to this loss and successor, so only the
    // source-scope check can catch it.
    let restamped = |json: &str| -> Result<String> {
        let mut record: serde_json::Value = serde_json::from_str(json)?;
        record["source_scope"]["region"] = serde_json::Value::from("elsewhere");
        Ok(serde_json::to_string(&record)?)
    };

    for (path, good) in [
        (&survivor_path, &good_survivor.0),
        (&replacement_path, &good_replacement.0),
    ] {
        let original = good.as_deref().ok_or("install record missing")?;
        drop(replacement);
        drop(handle);
        tamper(
            path,
            &format!(
                "UPDATE recovery_loss_active SET record='{}' WHERE id=1",
                restamped(original)?.replace('\'', "''")
            ),
        )?;
        let handle_again = f.survivor_handle()?;
        let replacement_again = f.open_replacement(Role::Secondary)?;
        assert!(complete_successor(&handle_again, &replacement_again, &successor, &live).is_err());
        assert_eq!(
            successor_journal
                .fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
                .acknowledgements(),
            [false; 2]
        );
        drop(replacement_again);
        drop(handle_again);
        tamper(
            path,
            &format!(
                "UPDATE recovery_loss_active SET record='{}' WHERE id=1",
                original.replace('\'', "''")
            ),
        )?;
        handle = f.survivor_handle()?;
        replacement = f.open_replacement(Role::Secondary)?;
    }

    // Restored: the genuine records acknowledge.
    assert_eq!(install_state(&survivor_path)?, good_survivor);
    assert_eq!(node_install_state(&replacement)?, good_replacement);
    complete_successor(&handle, &replacement, &successor, &live)?;
    assert_eq!(
        successor_journal
            .fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
            .acknowledgements(),
        [true; 2]
    );
    drop(replacement);
    drop(handle);
    drop(f);
    Ok(())
}

// ---------------------------------------------------------------------------
// S4: crash/retry matrix. A child process replays the whole flow from the top,
// performs one more step and then dies without running any destructor. The
// parent reopens everything from disk, proves nothing is half-applied, and the
// next child proves every earlier step is an exact idempotent no-op.
// ---------------------------------------------------------------------------

/// Everything a fresh process needs to rebuild the flow from disk.
#[derive(Serialize, Deserialize)]
struct CrashFixture {
    identity: Identity<SchemaId>,
    profile: crate::recovery::grant::Profile,
    keys: Vec<(String, Vec<u8>)>,
    max_lifetime: u64,
    certificate: transition::Request,
    certificate_token: String,
    successor: transition::LossSuccessorRequest,
    source_scope: transition::JournalScope,
    successor_scope: transition::JournalScope,
    lost: Role,
    survivor: std::path::PathBuf,
    lost_path: std::path::PathBuf,
    replacement: std::path::PathBuf,
    source_journal: std::path::PathBuf,
    successor_journal: std::path::PathBuf,
}

impl CrashFixture {
    fn trust(&self) -> transition::TrustStore {
        transition::TrustStore {
            profile: self.profile.clone(),
            keys: self.keys.clone(),
            max_lifetime: self.max_lifetime,
        }
    }
    fn survivor_role(&self) -> Role {
        match self.lost {
            Role::Primary => Role::Secondary,
            Role::Secondary => Role::Primary,
        }
    }
    fn read(dir: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(
            dir.join("crash-fixture.json"),
        )?)?)
    }
}

/// Journals, authority and policy rebuilt from disk in either process.
struct CrashWorld {
    fixture: CrashFixture,
    trust: transition::TrustStore,
    source: transition::Journal,
    successor: transition::Journal,
    gate: Arc<Gate>,
    live: Arc<Live>,
}

impl CrashWorld {
    fn open(dir: &Path) -> Result<Self> {
        let fixture = CrashFixture::read(dir)?;
        let trust = fixture.trust();
        let gate = Gate::new();
        let source = transition::Journal::open(
            &fixture.source_journal,
            "journal-fixture",
            fixture.source_scope.clone(),
            &trust.as_trust(),
        )?;
        let live = Arc::new(Live {
            journal: Mutex::new(transition::Journal::open(
                &fixture.source_journal,
                "journal-fixture",
                fixture.source_scope.clone(),
                &trust.as_trust(),
            )?),
            successor: Mutex::new(Some(transition::Journal::open(
                &fixture.successor_journal,
                "successor-fixture",
                fixture.successor_scope.clone(),
                &trust.as_trust(),
            )?)),
            trust: trust.clone(),
            gate: gate.clone(),
        });
        let successor = transition::Journal::open(
            &fixture.successor_journal,
            "successor-fixture",
            fixture.successor_scope.clone(),
            &trust.as_trust(),
        )?;
        Ok(Self {
            fixture,
            trust,
            source,
            successor,
            gate,
            live,
        })
    }
    fn authorities(&self) -> Authorities<'_, Gate> {
        Authorities {
            source: &self.source,
            successor: &self.successor,
            policy: self.gate.as_ref(),
        }
    }
    fn handle(&self) -> Result<LossSurvivorHandle<StockSchema>> {
        LossSurvivorHandle::open_existing(
            &self.fixture.survivor,
            self.fixture.identity.clone(),
            "fixture",
            StockSchema,
            &self.trust,
            &self.source,
            self.gate.as_ref(),
        )
    }
    fn open_node(&self, path: &Path, role: Role) -> Result<Node<StockSchema>> {
        let installed = install_state(path)?.0.is_some();
        if installed {
            Node::open_with_completed_transition(
                path,
                role,
                self.fixture.identity.clone(),
                "fixture",
                StockSchema,
                self.trust.clone(),
                self.live.clone(),
            )
        } else {
            Node::open_with_transition_trust(
                path,
                role,
                self.fixture.identity.clone(),
                "fixture",
                StockSchema,
                self.trust.clone(),
            )
        }
    }
    fn replacement_role(&self, installed: bool) -> Role {
        if installed {
            self.fixture.lost
        } else {
            Role::Secondary
        }
    }
    fn replacement(&self) -> Result<Node<StockSchema>> {
        let installed = install_state(&self.fixture.replacement)?.0.is_some();
        self.open_node(&self.fixture.replacement, self.replacement_role(installed))
    }
    fn acknowledgements(&self) -> Result<[bool; 2]> {
        Ok(self
            .successor
            .fetch_loss_successor(
                &self.fixture.successor,
                &self.trust.as_trust(),
                self.gate.as_ref(),
            )?
            .acknowledgements())
    }
}

/// Steps of the whole operator flow. Replaying a prefix must always be an
/// exact no-op; `stop` is the step after which the child dies.
const STEP_BOOTSTRAP_PARTIAL: u32 = 1;
const STEP_BOOTSTRAP: u32 = 2;
const STEP_SURVIVOR_INSTALL: u32 = 3;
const STEP_REPLACEMENT_INSTALL: u32 = 4;
const STEP_FIRST_ACK: u32 = 5;
const STEP_SECOND_ACK: u32 = 6;
const STEP_AUTHORITY_COMPLETION: u32 = 7;
const STEP_FIRST_RECEIPT: u32 = 8;
const STEP_LAST: u32 = STEP_FIRST_RECEIPT;

/// Replay the flow from the top and stop after `stop`. Every step before it is
/// re-executed and must converge without changing anything.
fn replay(world: &CrashWorld, stop: u32) -> Result<()> {
    let f = &world.fixture;
    let handle = world.handle()?;
    let installed = install_state(&f.replacement)?.0.is_some();
    let mut replacement = world.replacement()?;
    if installed {
        // Bootstrap is an ordinary admitted operation, so it is closed once the
        // successor membership is installed. Replaying it must fail, not repair.
        ensure(
            bootstrap_replacement(
                &handle,
                &mut replacement,
                &world.source,
                world.gate.as_ref(),
            )
            .is_err(),
            "bootstrap admitted after install",
        )?;
    } else {
        if stop == STEP_BOOTSTRAP_PARTIAL {
            // Partial transfer: begin and deliver one page only.
            let manifest = handle.manifest(&world.source, world.gate.as_ref())?;
            let next = replacement.begin_snapshot(&manifest)?;
            if next < manifest.pages {
                let page = handle.page(next, &world.source, world.gate.as_ref())?;
                replacement.receive_snapshot(&page)?;
            }
            return Ok(());
        }
        bootstrap_replacement(
            &handle,
            &mut replacement,
            &world.source,
            world.gate.as_ref(),
        )?;
        if stop == STEP_BOOTSTRAP {
            return Ok(());
        }
    }
    let live = world.authorities();
    handle.install_successor("fixture", &f.successor, &live)?;
    if stop == STEP_SURVIVOR_INSTALL {
        return Ok(());
    }
    install_replacement(&mut replacement, &crash_founding(f), &f.successor, &live)?;
    if stop == STEP_REPLACEMENT_INSTALL {
        return Ok(());
    }
    // The replacement object must be reopened under its installed role.
    drop(replacement);
    let replacement = world.replacement()?;
    if world.acknowledgements()? != [true; 2] {
        let evidence = InstalledParticipants {
            survivor: &handle,
            replacement: &replacement,
            policy: world.gate.as_ref(),
        };
        let decision = world.successor.fetch_loss_successor(
            &f.successor,
            &world.trust.as_trust(),
            &evidence,
        )?;
        for (index, participant) in decision.request().participants.iter().enumerate() {
            if decision.acknowledgements()[index] {
                continue;
            }
            world.successor.acknowledge_loss_successor(
                &decision,
                participant,
                &world.trust.as_trust(),
                &evidence,
            )?;
            if (index == 0 && stop == STEP_FIRST_ACK) || (index == 1 && stop == STEP_SECOND_ACK) {
                return Ok(());
            }
        }
    }
    if stop <= STEP_SECOND_ACK {
        return Ok(());
    }
    complete_successor(&handle, &replacement, &f.successor, &live)?;
    if stop == STEP_AUTHORITY_COMPLETION {
        return Ok(());
    }
    drop(replacement);
    drop(handle);
    let survivor_node = world.open_node(&f.survivor, f.survivor_role())?;
    record_completion(&survivor_node)?;
    if stop == STEP_FIRST_RECEIPT {
        return Ok(());
    }
    let replacement_node = world.replacement()?;
    record_completion(&replacement_node)?;
    Ok(())
}

#[test]
#[ignore = "subprocess fixture; invoked by the participant-loss crash matrix"]
fn participant_loss_crash_child() -> Result<()> {
    let dir = std::path::PathBuf::from(
        std::env::var_os("VESTA_LOSS_CRASH_DIR").ok_or("parent fixture required")?,
    );
    let stop: u32 = std::env::var("VESTA_LOSS_CRASH_STEP")?.parse()?;
    let world = CrashWorld::open(&dir)?;
    replay(&world, stop)?;
    // No destructors, no clean SQLite close, no success response to the caller.
    std::process::exit(73)
}

/// Build a certified pair, decide the loss and the successor, and persist
/// everything a fresh process needs to rebuild the flow.
fn crash_fixture(lost: Role, tail: bool) -> Result<(Fixture, transition::Journal, CrashWorld)> {
    let f = fixture(lost, tail)?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let record = CrashFixture {
        identity: f.identity.clone(),
        profile: f.trust.profile.clone(),
        keys: f.trust.keys.clone(),
        max_lifetime: f.trust.max_lifetime,
        certificate: f.certificate.clone(),
        certificate_token: f.certificate_token.clone(),
        successor: proof.request().clone(),
        source_scope: proof.source_scope().clone(),
        successor_scope: successor_scope(&f),
        lost,
        survivor: f.survivor_path.clone(),
        lost_path: f.lost_path.clone(),
        replacement: f.replacement_path.clone(),
        source_journal: f.dir.path().join("loss-journal"),
        successor_journal: f.dir.path().join("successor-journal"),
    };
    std::fs::write(
        f.dir.path().join("crash-fixture.json"),
        serde_json::to_vec(&record)?,
    )?;
    let world = CrashWorld::open(f.dir.path())?;
    Ok((f, successor_journal, world))
}

fn crash_at(dir: &Path, step: u32) -> Result<()> {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "typed::maintenance::loss::tests::participant_loss_crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("VESTA_LOSS_CRASH_DIR", dir)
        .env("VESTA_LOSS_CRASH_STEP", step.to_string())
        .status()?;
    ensure(
        status.code() == Some(73),
        &format!("participant-loss crash child failed at step {step}"),
    )
}

/// State every crash point must leave behind, checked from disk only.
fn assert_crash_state(world: &CrashWorld, step: u32) -> Result<()> {
    let f = &world.fixture;
    let survivor = install_state(&f.survivor)?;
    let replacement = install_state(&f.replacement)?;
    // A record is either absent or complete; presence follows the step exactly.
    assert_eq!(
        survivor.0.is_some(),
        step >= STEP_SURVIVOR_INSTALL,
        "survivor record at step {step}"
    );
    assert_eq!(
        replacement.0.is_some(),
        step >= STEP_REPLACEMENT_INSTALL,
        "replacement record at step {step}"
    );
    // Owner rows follow the installed roles and nothing else.
    assert_eq!(owner_role(&survivor.1)?, f.survivor_role());
    assert_eq!(
        owner_role(&replacement.1)?,
        world.replacement_role(replacement.0.is_some())
    );
    // Acknowledgement flags match the step exactly.
    let expected_acks = match step {
        s if s < STEP_FIRST_ACK => [false, false],
        STEP_FIRST_ACK => [true, false],
        _ => [true, true],
    };
    assert_eq!(
        world.acknowledgements()?,
        expected_acks,
        "acks at step {step}"
    );
    // The authority only has a completion once it was asked for one.
    let completed = world.successor.fetch_completed_loss_successor(
        &f.successor,
        &world.trust.as_trust(),
        world.gate.as_ref(),
    );
    assert_eq!(
        completed.is_ok(),
        step >= STEP_AUTHORITY_COMPLETION,
        "authority completion at step {step}"
    );
    // The survivor is unopenable until its install replaces the superseded
    // certificate head, and closed until it records completion.
    let survivor_open = world.open_node(&f.survivor, f.survivor_role());
    assert_eq!(
        survivor_open.is_ok(),
        step >= STEP_SURVIVOR_INSTALL,
        "survivor open at step {step}"
    );
    if let Ok(node) = survivor_open {
        assert_eq!(
            node.checkpoint().is_ok(),
            step >= STEP_FIRST_RECEIPT,
            "survivor admission at step {step}"
        );
        drop(node);
    }
    // The replacement is an ordinary bootstrap node until it is installed, and
    // closed from then until it records completion, which this walk never
    // reaches. A partial transfer is not admitted either.
    let replacement_node = world.replacement()?;
    assert_eq!(
        replacement_node.checkpoint().is_ok(),
        (STEP_BOOTSTRAP..STEP_REPLACEMENT_INSTALL).contains(&step),
        "replacement admission at step {step}"
    );
    drop(replacement_node);
    // The lost member never becomes openable again.
    for role in [Role::Primary, Role::Secondary] {
        assert!(
            Node::<StockSchema>::open(
                &f.lost_path,
                role,
                f.identity.clone(),
                "fixture",
                StockSchema
            )
            .is_err(),
            "lost member opened at step {step}"
        );
        assert!(
            world.open_node(&f.lost_path, role).is_err(),
            "lost member opened with authority at step {step}"
        );
    }
    Ok(())
}

/// A different successor request or completion id is refused at every point.
fn assert_wrong_inputs_refused(f: &Fixture, world: &CrashWorld, step: u32) -> Result<()> {
    let other = successor_request_with(f, [99; 32]);
    assert!(
        world
            .successor
            .fetch_loss_successor(&other, &world.trust.as_trust(), world.gate.as_ref())
            .is_err(),
        "foreign successor accepted at step {step}"
    );
    if step >= STEP_AUTHORITY_COMPLETION {
        // The completion id is derived, so a conflicting one can only be
        // injected at the journal itself. It must still be refused.
        let decision = world.successor.fetch_loss_successor(
            &world.fixture.successor,
            &world.trust.as_trust(),
            world.gate.as_ref(),
        )?;
        assert_err_contains(
            world.successor.complete_loss_successor(
                &decision,
                [98; 32],
                &world.trust.as_trust(),
                world.gate.as_ref(),
            ),
            "immutable replacement completion conflict",
        );
        // The derived id still converges on retry.
        let handle = world.handle()?;
        let replacement = world.replacement()?;
        complete_successor(
            &handle,
            &replacement,
            &world.fixture.successor,
            &world.authorities(),
        )?;
    }
    Ok(())
}

/// Every boundary of the operator flow, crashed and resumed. Each child replays
/// the whole flow from the top, so every earlier step is proved idempotent.
fn crash_matrix(lost: Role, tail: bool) -> Result<()> {
    let (f, successor_journal, world) = crash_fixture(lost, tail)?;
    let dir = f.dir.path().to_path_buf();
    drop(world);

    let mut survivor_record: Option<String> = None;
    let mut replacement_record: Option<String> = None;
    for step in STEP_BOOTSTRAP_PARTIAL..=STEP_LAST {
        crash_at(&dir, step)?;
        let world = CrashWorld::open(&dir)?;
        let survivor = install_state(&f.survivor_path)?.0;
        let replacement = install_state(&f.replacement_path)?.0;
        // Durable records never change once written.
        if let Some(previous) = &survivor_record {
            assert_eq!(survivor.as_deref(), Some(previous.as_str()));
        }
        if let Some(previous) = &replacement_record {
            assert_eq!(replacement.as_deref(), Some(previous.as_str()));
        }
        survivor_record = survivor.or(survivor_record);
        replacement_record = replacement.or(replacement_record);
        assert_crash_state(&world, step)?;
        assert_wrong_inputs_refused(&f, &world, step)?;
        drop(world);
    }

    // Resume: the whole flow replays as a no-op and the new pair writes.
    let world = CrashWorld::open(&dir)?;
    replay(&world, u32::MAX)?;
    assert_eq!(install_state(&f.survivor_path)?.0, survivor_record);
    assert_eq!(install_state(&f.replacement_path)?.0, replacement_record);
    let survivor_node = world.open_node(&f.survivor_path, f.survivor_role())?;
    let replacement_node = world.replacement()?;
    let (mut primary, mut secondary) = match lost {
        Role::Primary => (replacement_node, survivor_node),
        Role::Secondary => (survivor_node, replacement_node),
    };
    let before = f.loss.survivor_cut.sequence;
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-crash-matrix".into();
    assert_eq!(
        commit(&mut primary, &mut secondary, batch)?.sequence,
        before + 1
    );
    let receipts = receipt_rows(&primary)?;
    assert_eq!(receipts.len() as u64, before + 1);
    assert_eq!(receipts[..before as usize], f.survivor_receipts[..]);
    assert_eq!(receipt_rows(&secondary)?, receipts);
    drop(primary);
    drop(secondary);
    drop(world);
    drop(successor_journal);
    drop(f);
    Ok(())
}

/// The four crash matrices differ only in which role was lost and whether a
/// tail was committed, and each spawns one subprocess per boundary. The two
/// tail variants stay in the default run so both surviving roles and the tail
/// shape are always covered; the two no-tail variants are the redundant half
/// and are opted into with `--include-ignored`. They are skipped, not passed:
/// a default run reports them as ignored.
#[test]
#[ignore = "slow: subprocess crash matrix; run with -- --include-ignored"]
fn crash_matrix_for_lost_primary_without_tail() -> Result<()> {
    crash_matrix(Role::Primary, false)
}

#[test]
fn crash_matrix_for_lost_primary_with_tail() -> Result<()> {
    crash_matrix(Role::Primary, true)
}

#[test]
#[ignore = "slow: subprocess crash matrix; run with -- --include-ignored"]
fn crash_matrix_for_lost_secondary_without_tail() -> Result<()> {
    crash_matrix(Role::Secondary, false)
}

#[test]
fn crash_matrix_for_lost_secondary_with_tail() -> Result<()> {
    crash_matrix(Role::Secondary, true)
}

/// Security-relevant negatives assert the exact reason, so a test cannot pass
/// because something unrelated happened to fail first.
#[track_caller]
fn assert_err_contains<T>(outcome: Result<T>, expected: &str) {
    match outcome {
        Ok(_) => panic!("expected an error containing {expected:?}"),
        Err(e) => {
            let text = e.to_string();
            assert!(
                text.contains(expected),
                "expected {expected:?}, got {text:?}"
            );
        }
    }
}

/// F2: verification uses the trust store each node and handle was opened with,
/// never one handed in with the call.
#[test]
fn install_requires_the_node_and_handle_trust_store() -> Result<()> {
    let f = fixture(Role::Secondary, false)?;
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    let live = authorities(&f, &successor_journal);
    handle.install_successor("fixture", &successor, &live)?;
    drop(replacement);

    // A replacement configured with no transition trust at all.
    let mut untrusted = Node::open(
        &f.replacement_path,
        Role::Secondary,
        f.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert_err_contains(
        install_replacement(&mut untrusted, &founding(&f), &successor, &live),
        "requires transition trust",
    );
    assert_eq!(node_install_state(&untrusted)?.0, None);
    drop(untrusted);

    // A replacement configured with a trust store that does not know the signer.
    let foreign = transition::TrustStore {
        profile: f.trust.profile.clone(),
        keys: Vec::new(),
        max_lifetime: f.trust.max_lifetime,
    };
    let mut wrong = Node::open_with_transition_trust(
        &f.replacement_path,
        Role::Secondary,
        f.identity.clone(),
        "fixture",
        StockSchema,
        foreign.clone(),
    )?;
    assert!(install_replacement(&mut wrong, &founding(&f), &successor, &live,).is_err());
    assert_eq!(node_install_state(&wrong)?.0, None);
    drop(wrong);

    // A handle opened under a foreign trust store cannot even validate.
    drop(handle);
    assert!(LossSurvivorHandle::<StockSchema>::open_existing(
        &f.survivor_path,
        f.identity.clone(),
        "fixture",
        StockSchema,
        &foreign,
        &f.journal,
        f.gate.as_ref(),
    )
    .is_err());

    // The genuine configuration still installs.
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    install_replacement(&mut replacement, &founding(&f), &successor, &live)?;
    assert!(node_install_state(&replacement)?.0.is_some());
    drop(replacement);
    drop(handle);
    Ok(())
}

/// F4: an in-flight compaction or pending certified maintenance must be
/// resolved before the irreversible install, not discovered afterwards.
#[test]
fn survivor_install_requires_maintenance_idle() -> Result<()> {
    let f = fixture(Role::Secondary, false)?;
    let survivor_path = f.survivor_path.clone();
    let plan_json: String = {
        let db = Vesta::open_read_only_with_passphrase(&survivor_path, "fixture")?;
        db.with_connection(|c| {
            c.query_row(
                "SELECT plan FROM node_compaction_history ORDER BY sequence DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
        })?
    };
    let progress = compaction::Progress {
        plan: serde_json::from_str(&plan_json)?,
        phase: compaction::Phase::Prepared,
    };
    tamper(
        &survivor_path,
        &format!(
            "CREATE TABLE IF NOT EXISTS node_compaction(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL,digest TEXT NOT NULL);
             INSERT INTO node_compaction VALUES(1,'{}','{}');",
            serde_json::to_string(&progress)?.replace('\'', "''"),
            hash(&progress)?
        ),
    )?;
    // Either reason is fail-closed: the point is that an unfinished compaction
    // record stops the install before it becomes irreversible.
    assert_err_contains(f.survivor_handle(), "compaction");
    tamper(&survivor_path, "DROP TABLE node_compaction")?;
    f.survivor_handle()?;

    tamper(
        &survivor_path,
        "CREATE TABLE node_pending_certified_maintenance(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)",
    )?;
    assert_err_contains(f.survivor_handle(), "pending certified maintenance");
    tamper(
        &survivor_path,
        "DROP TABLE node_pending_certified_maintenance",
    )?;
    f.survivor_handle()?;
    Ok(())
}

/// F7: a view carrying a participant-loss table name is never evidence.
#[test]
fn shadowed_participant_loss_table_is_refused() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let identity = stock_entry().batch.identity;
    let path = dir.path().join("plain");
    let node = Node::open(
        &path,
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert!(node.checkpoint().is_ok());
    drop(node);
    tamper(
        &path,
        "CREATE VIEW recovery_loss_active AS SELECT 1 AS id, '{}' AS record",
    )?;
    assert_err_contains(
        Node::<StockSchema>::open(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
        ),
        "shadowed",
    );
    tamper(&path, "DROP VIEW recovery_loss_active")?;
    tamper(
        &path,
        "CREATE VIEW recovery_loss_completion AS SELECT 1 AS id, '[]' AS receipt",
    )?;
    assert_err_contains(
        Node::<StockSchema>::open(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
        ),
        "shadowed",
    );
    tamper(&path, "DROP VIEW recovery_loss_completion")?;
    Node::<StockSchema>::open(&path, Role::Primary, identity, "fixture", StockSchema)?;
    Ok(())
}

/// Copy a whole encrypted database, including its metadata and any write-ahead
/// log, over another path.
fn swap_database(from: &Path, to: &Path) -> Result<()> {
    let with = |path: &Path, suffix: &str| -> PathBuf {
        let mut raw = path.as_os_str().to_owned();
        raw.push(suffix);
        PathBuf::from(raw)
    };
    for suffix in ["", "-wal", "-shm"] {
        let target = with(to, suffix);
        if target.exists() {
            std::fs::remove_file(&target)?;
        }
        let source = with(from, suffix);
        if source.exists() {
            std::fs::copy(&source, &target)?;
        }
    }
    std::fs::copy(meta_of(from), meta_of(to))?;
    Ok(())
}

/// Adversarial: one node installed, the other rolled back to a copy of itself
/// taken before the bootstrap, and an old successor journal replayed after the
/// completion. Nothing may be granted in either case.
#[test]
fn stale_peer_copy_and_replayed_successor_journal_grant_nothing() -> Result<()> {
    let f = fixture(Role::Secondary, false)?;
    let replacement_path = f.replacement_path.clone();
    let stale = f.dir.path().join("replacement-before-bootstrap");
    swap_database(&replacement_path, &stale)?;

    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    let live = authorities(&f, &successor_journal);
    handle.install_successor("fixture", &successor, &live)?;
    drop(replacement);

    // Roll the replacement back to its pre-bootstrap state: the survivor is
    // installed, the replacement is empty again. Nothing may be acknowledged.
    swap_database(&stale, &replacement_path)?;
    let rolled_back = f.replacement()?;
    assert!(complete_successor(&handle, &rolled_back, &successor, &live).is_err());
    assert_eq!(
        successor_journal
            .fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
            .acknowledgements(),
        [false; 2]
    );
    drop(rolled_back);
    drop(handle);

    // The rolled-back copy still carries the signed generation, so the ordinary
    // flow simply runs again on it and finishes for real.
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    install_replacement(&mut replacement, &founding(&f), &successor, &live)?;
    let journal_path = f.dir.path().join("successor-journal");
    let before_second_ack = f.dir.path().join("successor-journal-old");
    // Snapshot the authority before either acknowledgement.
    swap_database(&journal_path, &before_second_ack)?;
    complete_successor(&handle, &replacement, &successor, &live)?;
    drop(replacement);
    drop(handle);

    f.live
        .attach_successor(successor_journal_handle(&f, "successor-journal")?)?;
    let survivor_node = open_with_authority(&f, &f.survivor_path, Role::Primary)?;
    let replacement_node = open_with_authority(&f, &f.replacement_path, Role::Secondary)?;
    record_completion(&survivor_node)?;
    record_completion(&replacement_node)?;
    assert!(survivor_node.checkpoint().is_ok());
    assert!(replacement_node.checkpoint().is_ok());

    // Replay the pre-acknowledgement journal over the live one. Admission
    // follows the live authority, so both nodes close again immediately.
    drop(survivor_node);
    drop(replacement_node);
    f.live.detach_successor()?;
    swap_database(&before_second_ack, &journal_path)?;
    f.live
        .attach_successor(successor_journal_handle(&f, "successor-journal")?)?;
    let survivor_node = open_with_authority(&f, &f.survivor_path, Role::Primary)?;
    let replacement_node = open_with_authority(&f, &f.replacement_path, Role::Secondary)?;
    // The live authority no longer has the acknowledgements, so admission
    // closes on both nodes even though their local receipts are still durable.
    assert_err_contains(survivor_node.checkpoint(), "acknowledgements incomplete");
    assert_err_contains(replacement_node.checkpoint(), "acknowledgements incomplete");
    // Nor can the rolled-back authority be talked into a fresh completion for a
    // membership whose local receipts already exist.
    assert_err_contains(
        record_completion(&survivor_node),
        "acknowledgements incomplete",
    );
    drop(survivor_node);
    drop(replacement_node);
    drop(f);
    Ok(())
}

/// Format-1 successors keep working exactly as before: they carry no role, so
/// the canonical cross-check has nothing to compare and the installs derive
/// every role from the source certificate alone.
#[test]
fn format_one_successor_still_completes_a_recovery() -> Result<()> {
    let f = fixture(Role::Primary, false)?;
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;

    let request = successor_request_v1(&f);
    assert_eq!(request.format, 1);
    assert_eq!(request.survivor_index, None);
    assert_eq!(request.survivor()?.member, f.loss.survivor.member);
    assert_eq!(request.replacement()?.member, f.loss.replacement_member);
    let token = sign_successor(&f.signer, &request, &f.trust, [61; 32])?;
    let journal = transition::Journal::create_loss_successor(
        &f.dir.path().join("successor-v1"),
        "successor-fixture",
        successor_scope(&f),
        &f.journal,
        &f.trust.as_trust(),
        f.gate.as_ref(),
    )?;
    journal.decide_loss_successor(
        request.clone(),
        &token,
        15,
        &f.trust.as_trust(),
        f.gate.as_ref(),
    )?;
    let live = authorities(&f, &journal);
    install_pair(
        &handle,
        &mut replacement,
        "fixture",
        &founding(&f),
        &request,
        &live,
    )?;
    f.live
        .attach_successor(successor_journal_handle(&f, "successor-v1")?)?;
    complete_successor(&handle, &replacement, &request, &live)?;
    drop(replacement);
    drop(handle);

    let survivor_node = open_with_authority(&f, &f.survivor_path, Role::Secondary)?;
    let replacement_node = open_with_authority(&f, &f.replacement_path, Role::Primary)?;
    record_completion(&survivor_node)?;
    record_completion(&replacement_node)?;
    let (mut primary, mut secondary) = (replacement_node, survivor_node);
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-format-one-recovery".into();
    assert_eq!(
        commit(&mut primary, &mut secondary, batch)?.sequence,
        f.loss.survivor_cut.sequence + 1
    );
    // But that pair is a dead end for a further loss: a format-1 successor
    // names no role, so nothing could prove which of its two participants
    // survived. The install record still carries the issued token, so the
    // refusal is about the successor's format and nothing else.
    let record = decode_install(
        install_state(&f.survivor_path)?
            .0
            .as_deref()
            .ok_or("survivor record missing")?,
    )?;
    assert_eq!(record.format, 2);
    assert_eq!(record.successor.format, 1);
    assert!(record.successor_token.is_some());
    assert_err_contains(
        f.derive_role_at(
            &f.survivor_path,
            &transition::LossRequest {
                format: 2,
                source_kind: Some(transition::SourceKind::LossSuccessor),
                ..f.loss.clone()
            },
        ),
        "format-1 loss recovery cannot take a second loss",
    );
    drop(primary);
    drop(secondary);
    drop(f);
    Ok(())
}

/// A format-2 successor states each role twice; the canonical order and the
/// role derived from the source certificate must agree.
#[test]
fn format_two_successor_binds_the_canonical_participant_order() -> Result<()> {
    for lost in [Role::Primary, Role::Secondary] {
        let f = fixture(lost, false)?;
        let request = successor_request(&f);
        assert_eq!(request.format, 2);
        // A lost Primary leaves a Secondary survivor, which sits at index 1.
        assert_eq!(
            request.survivor_index,
            Some(u8::from(lost == Role::Primary))
        );
        assert_eq!(request.survivor()?.member, f.loss.survivor.member);
        assert_eq!(request.replacement()?.member, f.loss.replacement_member);

        let handle = f.survivor_handle()?;
        let mut replacement = f.replacement()?;
        bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
        let (successor_journal, proof) = successor_proof(&f, "successor-journal")?;
        let successor = proof.request().clone();
        let live = authorities(&f, &successor_journal);

        // Swapping the canonical order, or relabelling which index is the
        // survivor, makes the signed roles disagree. `LossSuccessorRequest`'s
        // own shape validation refuses both before the install's canonical
        // cross-check is reached, so that check is defence in depth.
        let mut swapped = successor.clone();
        swapped.participants.swap(0, 1);
        assert_err_contains(
            handle.install_successor("fixture", &swapped, &live),
            "invalid loss successor request",
        );
        let mut relabelled = successor.clone();
        relabelled.survivor_index = Some(1 - successor.survivor_index.ok_or("survivor index")?);
        assert_err_contains(
            handle.install_successor("fixture", &relabelled, &live),
            "invalid loss successor request",
        );
        // The cross-check itself refuses a role that contradicts the canonical
        // position, for the survivor and for the replacement.
        let survivor_slot = successor.survivor_index().map_err(|e| e.to_string())?;
        assert!(require_canonical_role(&successor, survivor_slot, f.lost_role()).is_err());
        assert!(
            require_canonical_role(&successor, roles(&successor)?.1, f.survivor_role()).is_err()
        );
        require_canonical_role(&successor, survivor_slot, f.survivor_role())?;
        require_canonical_role(&successor, roles(&successor)?.1, f.lost_role())?;
        // The genuine successor installs on both nodes.
        install_pair(
            &handle,
            &mut replacement,
            "fixture",
            &founding(&f),
            &successor,
            &live,
        )?;
        drop(replacement);
        drop(handle);
        drop(f);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// S9: a second participant loss on a pair that already survived one.
//
// The provenance of the second loss is the pair's own completed format-2
// successor, not a compaction certificate. The survivor authenticates it from
// its durable install record — request, certificate id, token digest *and* the
// stored token, re-verified by signature under the handle's own trust store —
// and the replacement from the signed document the operator supplies. Neither
// side is ever told a role.
// ---------------------------------------------------------------------------

/// Which member of the recovered pair is lost the second time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Losing {
    /// The member that survived the first loss dies now.
    FirstSurvivor,
    /// The member that replaced the first lost one dies now.
    FirstReplacement,
}

/// The completed recovery a further loss is founded on.
struct FirstRecovery {
    journal: transition::Journal,
    successor: transition::LossSuccessorRequest,
    token: String,
    certificate: [u8; 32],
}

/// Ids a loss in a lineage may never share with an earlier one.
struct Ids {
    loss: [u8; 32],
    certificate: [u8; 32],
    membership: [u8; 32],
    member: [u8; 32],
    fencing: [u8; 32],
    successor: [u8; 32],
    successor_certificate: [u8; 32],
}

const SECOND_IDS: Ids = Ids {
    loss: [65; 32],
    certificate: [66; 32],
    membership: [67; 32],
    member: [68; 32],
    fencing: [69; 32],
    successor: [82; 32],
    successor_certificate: [83; 32],
};

const THIRD_IDS: Ids = Ids {
    loss: [84; 32],
    certificate: [85; 32],
    membership: [86; 32],
    member: [87; 32],
    fencing: [88; 32],
    successor: [89; 32],
    successor_certificate: [91; 32],
};

fn sha(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// Raw append-only cycle history of a node, read outside every guard.
fn cycle_rows(path: &Path) -> Result<Vec<(u64, String, String)>> {
    let db = Vesta::open_read_only_with_passphrase(path, "fixture")?;
    db.with_connection(|c| {
        Ok((|| -> Result<Vec<(u64, String, String)>> {
            if !table_exists(c, CYCLES_TABLE)? {
                return Ok(Vec::new());
            }
            Ok(c.prepare(
                "SELECT revision,record,digest FROM recovery_loss_cycles ORDER BY revision",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
        })())
    })?
}

/// Raw local completion receipt of a node, read outside every guard.
fn completion_row(path: &Path) -> Result<Option<String>> {
    let db = Vesta::open_read_only_with_passphrase(path, "fixture")?;
    db.with_connection(|c| {
        Ok((|| -> Result<Option<String>> {
            if !table_exists(c, COMPLETION_TABLE)? {
                return Ok(None);
            }
            Ok(c.query_row(
                "SELECT receipt FROM recovery_loss_completion WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?)
        })())
    })?
}

fn base_of(path: &Path) -> Result<Prefix> {
    let db = Vesta::open_read_only_with_passphrase(path, "fixture")?;
    db.with_connection(|c| {
        Ok((|| -> Result<Prefix> {
            checkpoint::base_for::<SchemaId>(c)?.ok_or_else(|| "base missing".into())
        })())
    })?
}

fn write_install(path: &Path, record: &str) -> Result<()> {
    tamper(
        path,
        &format!(
            "UPDATE recovery_loss_active SET record='{}' WHERE id=1",
            record.replace('\'', "''")
        ),
    )
}

fn write_completion(path: &Path, receipt: &str) -> Result<()> {
    tamper(
        path,
        &format!(
            "UPDATE recovery_loss_completion SET receipt='{}' WHERE id=1",
            receipt.replace('\'', "''")
        ),
    )
}

/// Drive one whole loss recovery to two writing nodes, and hand back exactly
/// what a further loss needs to be founded on.
fn recover_once(f: &Fixture) -> Result<FirstRecovery> {
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (journal, proof) = successor_proof(f, "successor-journal")?;
    let successor = proof.request().clone();
    let token = proof.token().to_owned();
    let certificate = proof.certificate_id();
    let live = authorities(f, &journal);
    install_pair(
        &handle,
        &mut replacement,
        "fixture",
        &founding(f),
        &successor,
        &live,
    )?;
    f.live
        .attach_successor(successor_journal_handle(f, "successor-journal")?)?;
    complete_successor(&handle, &replacement, &successor, &live)?;
    drop(replacement);
    drop(handle);
    for (path, role) in [
        (&f.survivor_path, f.survivor_role()),
        (&f.replacement_path, f.lost_role()),
    ] {
        let node = open_with_authority(f, path, role)?;
        record_completion(&node)?;
        ensure(node.checkpoint().is_ok(), "recovered node is not admitted")?;
        drop(node);
    }
    Ok(FirstRecovery {
        journal,
        successor,
        token,
        certificate,
    })
}

/// A recovered pair that has just lost another participant.
struct Second {
    f: Fixture,
    /// The completed recovery this loss retires; its journal is the *source*
    /// journal of this loss.
    first: FirstRecovery,
    loss: transition::LossRequest,
    certificate_id: [u8; 32],
    token_digest: [u8; 32],
    successor_id: [u8; 32],
    successor_certificate: [u8; 32],
    survivor_path: PathBuf,
    lost_path: PathBuf,
    replacement_path: PathBuf,
    survivor_role: Role,
    lost_role: Role,
    survivor_checkpoint: Prefix,
    survivor_manifest: snapshot::Manifest,
    survivor_view: String,
    survivor_receipts: Vec<String>,
    survivor_capacity: (u64, u64),
}

impl Second {
    /// The signed document that founded this pair: its previous recovery's
    /// completed successor, exactly as the authority issued it.
    fn founding(&self) -> Founding {
        Founding::Successor(self.first.successor.clone(), self.first.token.clone())
    }
    fn handle(&self) -> Result<LossSurvivorHandle<StockSchema>> {
        LossSurvivorHandle::open_existing(
            &self.survivor_path,
            self.f.identity.clone(),
            "fixture",
            StockSchema,
            &self.f.trust,
            &self.first.journal,
            self.f.gate.as_ref(),
        )
    }
    fn replacement(&self) -> Result<Node<StockSchema>> {
        let installed = install_state(&self.replacement_path)?.0.is_some();
        let role = if installed {
            self.lost_role
        } else {
            Role::Secondary
        };
        if installed {
            Node::open_with_completed_transition(
                &self.replacement_path,
                role,
                self.f.identity.clone(),
                "fixture",
                StockSchema,
                self.f.trust.clone(),
                self.f.live.clone(),
            )
        } else {
            Node::open_with_transition_trust(
                &self.replacement_path,
                role,
                self.f.identity.clone(),
                "fixture",
                StockSchema,
                self.f.trust.clone(),
            )
        }
    }
    fn open(&self, path: &Path, role: Role) -> Result<Node<StockSchema>> {
        open_with_authority(&self.f, path, role)
    }
    /// The successor membership this loss implies.
    fn successor(&self) -> transition::LossSuccessorRequest {
        successor_for(
            &self.loss,
            self.certificate_id,
            self.token_digest,
            self.survivor_role,
            2,
            self.successor_id,
        )
    }
    /// Decide it in a fresh successor journal founded on the previous one.
    fn decide(
        &self,
        name: &str,
        request: &transition::LossSuccessorRequest,
    ) -> Result<transition::Journal> {
        let token = sign_successor(
            &self.f.signer,
            request,
            &self.f.trust,
            self.successor_certificate,
        )?;
        let journal = transition::Journal::create_loss_successor(
            &self.f.dir.path().join(name),
            "successor-fixture",
            successor_scope_of(&self.f, &self.loss),
            &self.first.journal,
            &self.f.trust.as_trust(),
            self.f.gate.as_ref(),
        )?;
        journal.decide_loss_successor(
            request.clone(),
            &token,
            15,
            &self.f.trust.as_trust(),
            self.f.gate.as_ref(),
        )?;
        Ok(journal)
    }
    fn journal(&self, name: &str) -> Result<transition::Journal> {
        transition::Journal::open(
            &self.f.dir.path().join(name),
            "successor-fixture",
            successor_scope_of(&self.f, &self.loss),
            &self.f.trust.as_trust(),
        )
    }
    /// Point the live authority at this loss's successor journal.
    fn arm(&self, name: &str) -> Result<()> {
        self.f.live.attach_successor(self.journal(name)?)
    }
    fn live<'a>(&'a self, journal: &'a transition::Journal) -> Authorities<'a, Gate> {
        Authorities {
            source: &self.first.journal,
            successor: journal,
            policy: self.f.gate.as_ref(),
        }
    }
}

/// Where the next loss of a lineage falls, and the ids it must use.
struct Next<'a> {
    survivor_path: PathBuf,
    survivor_role: Role,
    lost_path: PathBuf,
    replacement_path: PathBuf,
    ids: Ids,
    tail: Option<&'a str>,
}

/// Decide the next loss of a lineage: optionally commit a tail with the pair
/// that is still whole, freeze the survivor's publication at its current
/// checkpoint, and record the decision in the founding recovery's own journal.
fn decide_next_loss(f: Fixture, first: FirstRecovery, next: Next<'_>) -> Result<Second> {
    let Next {
        survivor_path,
        survivor_role,
        lost_path,
        replacement_path,
        ids,
        tail,
    } = next;
    let lost_role = match survivor_role {
        Role::Primary => Role::Secondary,
        Role::Secondary => Role::Primary,
    };
    let mut survivor = open_with_authority(&f, &survivor_path, survivor_role)?;
    if let Some(operation) = tail {
        let mut peer = open_with_authority(&f, &lost_path, lost_role)?;
        let mut batch = stock_entry().batch;
        batch.operation_id = operation.into();
        match survivor_role {
            Role::Primary => commit(&mut survivor, &mut peer, batch)?,
            Role::Secondary => commit(&mut peer, &mut survivor, batch)?,
        };
        drop(peer);
    }
    // Exactly what a first loss needs: one frozen publication at the
    // survivor's current checkpoint.
    let survivor_manifest = match survivor.published_snapshot()? {
        Some(old) => survivor.rotate_snapshot(&old)?,
        None => survivor.publish_snapshot()?,
    };
    let survivor_checkpoint = survivor.checkpoint()?;
    ensure(
        survivor_manifest.checkpoint == survivor_checkpoint,
        "next-loss publication is not current",
    )?;
    let survivor_view = serde_json::to_string(&survivor.view()?)?;
    let (survivor_receipts, survivor_capacity) = node_state(&survivor)?;
    drop(survivor);

    let replacement_generation = {
        let node = Node::<StockSchema>::open(
            &replacement_path,
            Role::Secondary,
            f.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        node.connection(checkpoint::generation)?
    };
    // A format-2 successor is canonically ordered, so the index of the member
    // that dies now is exactly the role it holds. Nothing here is a role input
    // to the production code: it only decides which node the fixture kills.
    let lost_index = usize::from(lost_role == Role::Secondary);
    let gone = first.successor.participants[lost_index].clone();
    let alive = first.successor.participants[1 - lost_index].clone();
    let loss = transition::LossRequest {
        format: 2,
        id: ids.loss,
        authority_id: f.loss.authority_id,
        revision: first.successor.revision + 1,
        install: f.loss.install.clone(),
        region: f.loss.region.clone(),
        scope: f.loss.scope,
        schema: f.loss.schema,
        membership: first.successor.membership,
        replacement_membership: ids.membership,
        source_certificate: first.certificate,
        source_token_digest: sha(&first.token),
        source_cut: first.successor.survivor_cut.clone(),
        lost_member: gone.member,
        lost_generation: gone.generation,
        survivor: transition::Participant {
            target: cut(&survivor_checkpoint)?,
            publication: id(&survivor_manifest)?,
            ..alive
        },
        survivor_cut: cut(&survivor_checkpoint)?,
        survivor_publication: id(&survivor_manifest)?,
        replacement_member: ids.member,
        replacement_generation,
        fencing_ref: ids.fencing,
        source_kind: Some(transition::SourceKind::LossSuccessor),
        abandoned_request: None,
        supersedes: None,
    };
    loss.validate()?;
    ensure(
        tail.is_some() == (loss.survivor_cut != loss.source_cut),
        "next-loss tail expectation mismatch",
    )?;
    let token = sign_loss(&f.signer, &loss, &f.trust, ids.certificate)?;
    let committed = first.journal.decide_loss(
        loss.clone(),
        &token,
        15,
        &f.trust.as_trust(),
        f.gate.as_ref(),
    )?;
    let certificate_id = committed.certificate_id();
    let token_digest = committed.token_digest();
    Ok(Second {
        f,
        first,
        loss,
        certificate_id,
        token_digest,
        successor_id: ids.successor,
        successor_certificate: ids.successor_certificate,
        survivor_path,
        lost_path,
        replacement_path,
        survivor_role,
        lost_role,
        survivor_checkpoint,
        survivor_manifest,
        survivor_view,
        survivor_receipts,
        survivor_capacity,
    })
}

/// A certified pair, one completed loss recovery, and a real second loss.
fn second_loss(lost: Role, losing: Losing, tail: bool) -> Result<Second> {
    let f = fixture(lost, false)?;
    let first = recover_once(&f)?;
    let (survivor_path, survivor_role, lost_path) = match losing {
        Losing::FirstReplacement => (
            f.survivor_path.clone(),
            f.survivor_role(),
            f.replacement_path.clone(),
        ),
        Losing::FirstSurvivor => (
            f.replacement_path.clone(),
            f.lost_role(),
            f.survivor_path.clone(),
        ),
    };
    let replacement_path = f.dir.path().join("replacement-2");
    decide_next_loss(
        f,
        first,
        Next {
            survivor_path,
            survivor_role,
            lost_path,
            replacement_path,
            ids: SECOND_IDS,
            tail: tail.then_some("between-participant-losses"),
        },
    )
}

/// The whole node side of a second (or later) recovery, end to end.
fn recover_second(
    s: &Second,
    name: &str,
) -> Result<(transition::Journal, transition::LossSuccessorRequest)> {
    let successor = s.successor();
    let journal = s.decide(name, &successor)?;
    let live = s.live(&journal);
    let handle = s.handle()?;
    ensure(handle.role == s.survivor_role, "derived survivor role")?;
    let mut replacement = s.replacement()?;
    bootstrap_replacement(
        &handle,
        &mut replacement,
        &s.first.journal,
        s.f.gate.as_ref(),
    )?;
    install_pair(
        &handle,
        &mut replacement,
        "fixture",
        &s.founding(),
        &successor,
        &live,
    )?;
    s.arm(name)?;
    complete_successor(&handle, &replacement, &successor, &live)?;
    drop(replacement);
    drop(handle);
    for (path, role) in [
        (&s.survivor_path, s.survivor_role),
        (&s.replacement_path, s.lost_role),
    ] {
        let node = s.open(path, role)?;
        record_completion(&node)?;
        ensure(node.checkpoint().is_ok(), "recovered node is not admitted")?;
        drop(node);
    }
    Ok((journal, successor))
}

/// From a decided second loss to the first write of the twice-recovered pair,
/// for every combination of which role was lost first and which member was
/// lost second.
fn second_recovery_cycle(lost: Role, losing: Losing, tail: bool) -> Result<()> {
    let s = second_loss(lost, losing, tail)?;
    assert_eq!(s.loss.kind(), transition::SourceKind::LossSuccessor);
    assert_eq!(s.loss.source_cut, s.first.successor.survivor_cut);
    assert_eq!(tail, s.loss.survivor_cut != s.loss.source_cut);

    // I8 analogue: deciding the second loss closes the founding successor
    // journal, so the recovered pair loses admission on BOTH nodes before any
    // node-side step of the new recovery has run.
    for (path, role) in [
        (&s.survivor_path, s.survivor_role),
        (&s.lost_path, s.lost_role),
    ] {
        let node = s.open(path, role)?;
        assert_err_contains(
            node.checkpoint(),
            "loss successor superseded by participant loss",
        );
        drop(node);
    }

    let before_cycles = cycle_rows(&s.survivor_path)?;
    let (journal, successor) = recover_second(&s, "successor-journal-2")?;
    assert_eq!(successor.format, 2);
    assert_eq!(
        successor.survivor_index,
        Some(u8::from(s.survivor_role == Role::Secondary))
    );

    // The retirement and the new install are one step: exactly one more
    // verified cycle row, and the founding receipt left with it.
    let rows = cycle_rows(&s.survivor_path)?;
    assert_eq!(rows.len(), before_cycles.len() + 1);
    let retired: RetiredLoss = serde_json::from_str(&rows[rows.len() - 1].1)?;
    assert_eq!(rows[rows.len() - 1].0, s.first.successor.revision - 1);
    assert_eq!(rows[rows.len() - 1].2, hash(&retired)?);
    assert_eq!(retired.next, s.loss);
    assert_eq!(retired.installed.successor, s.first.successor);
    assert_eq!(
        retired.installed.successor_token.as_deref(),
        Some(s.first.token.as_str())
    );
    // The replacement is brand new and has retired nothing.
    assert!(cycle_rows(&s.replacement_path)?.is_empty());

    // Both records are format 2 and carry the token the authority issued for
    // this successor, verifiable under the fixture trust store alone.
    let record = decode_install(
        install_state(&s.survivor_path)?
            .0
            .as_deref()
            .ok_or("survivor record missing")?,
    )?;
    let replacement_record = decode_install(
        install_state(&s.replacement_path)?
            .0
            .as_deref()
            .ok_or("replacement record missing")?,
    )?;
    for r in [&record, &replacement_record] {
        assert_eq!(r.format, 2);
        assert_eq!(r.loss, s.loss);
        assert_eq!(r.successor, successor);
        let token = r
            .successor_token
            .clone()
            .ok_or("stored successor token missing")?;
        assert_eq!(sha(&token), r.successor_token_digest);
        assert_eq!(
            transition::verify_successor_historical(&token, &s.f.trust.as_trust(), &successor)?,
            r.successor_certificate
        );
    }
    assert_eq!(record.installed_role, s.survivor_role);
    assert_eq!(record.previous_role, s.survivor_role);
    assert_eq!(replacement_record.installed_role, s.lost_role);
    assert_eq!(replacement_record.previous_role, Role::Secondary);

    let survivor_node = s.open(&s.survivor_path, s.survivor_role)?;
    let replacement_node = s.open(&s.replacement_path, s.lost_role)?;
    // The replacement carries exactly the survivor's frozen state: view,
    // receipts and capacity accounting, at the cut the loss named.
    assert_eq!(s.survivor_manifest.checkpoint, s.survivor_checkpoint);
    assert_eq!(survivor_node.checkpoint()?, s.survivor_checkpoint);
    assert_eq!(replacement_node.checkpoint()?, s.survivor_checkpoint);
    assert_eq!(
        serde_json::to_string(&replacement_node.view()?)?,
        s.survivor_view
    );
    assert_eq!(
        serde_json::to_string(&survivor_node.view()?)?,
        s.survivor_view
    );
    assert_eq!(
        node_state(&replacement_node)?,
        (s.survivor_receipts.clone(), s.survivor_capacity)
    );
    assert_eq!(
        node_state(&survivor_node)?,
        (s.survivor_receipts.clone(), s.survivor_capacity)
    );
    // The successor membership names the new pair on both sides, and it is no
    // longer the membership the previous recovery installed.
    assert_eq!(
        survivor_node.required_recovery_peer()?,
        Some(s.loss.replacement_member)
    );
    assert_eq!(
        replacement_node.required_recovery_peer()?,
        Some(s.loss.survivor.member)
    );
    assert_eq!(
        survivor_node.recovery_member_identity()?,
        Some(s.loss.survivor.member)
    );
    assert_eq!(
        replacement_node.recovery_member_identity()?,
        Some(s.loss.replacement_member)
    );
    let membership = survivor_node.summary()?.membership;
    assert_eq!(membership, replacement_node.summary()?.membership);
    assert_eq!(membership, Some(membership_digest(&record)?));
    assert_ne!(membership, Some(membership_digest(&retired.installed)?));
    assert_ne!(membership, Some(s.f.certificate.membership));

    // First write of the twice-recovered pair.
    let before = s.survivor_receipts.len() as u64;
    assert_eq!(before, s.loss.survivor_cut.sequence);
    let (mut primary, mut secondary) = match s.survivor_role {
        Role::Primary => (survivor_node, replacement_node),
        Role::Secondary => (replacement_node, survivor_node),
    };
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-second-participant-loss".into();
    assert_eq!(
        commit(&mut primary, &mut secondary, batch.clone())?.sequence,
        before + 1
    );
    // Exact retry of the write is a no-op.
    assert_eq!(
        commit(&mut primary, &mut secondary, batch.clone())?.sequence,
        before + 1
    );
    assert_eq!(
        serde_json::to_string(&primary.view()?)?,
        serde_json::to_string(&secondary.view()?)?
    );
    // Receipts continue from the second survivor cut, on both nodes.
    let receipts = receipt_rows(&primary)?;
    assert_eq!(receipts.len() as u64, before + 1);
    assert_eq!(receipts[..before as usize], s.survivor_receipts[..]);
    assert_eq!(receipt_rows(&secondary)?, receipts);
    assert_eq!(capacity_of(&primary)?, capacity_of(&secondary)?);
    assert_eq!(capacity_of(&primary)?.0, before + 1);
    assert!(primary.receipt(&batch.operation_id)?.is_some());
    assert!(secondary.receipt(&batch.operation_id)?.is_some());

    // Neither member this lineage has fenced is ever admissible again.
    for path in [&s.lost_path, &s.f.lost_path] {
        for role in [Role::Primary, Role::Secondary] {
            let outcome = s.open(path, role);
            assert!(outcome.is_err() || outcome?.checkpoint().is_err());
        }
    }
    // Maintenance and compaction stay shut on a twice-recovered pair.
    for node in [&mut primary, &mut secondary] {
        assert!(node.plan_compaction().is_err());
        assert!(node.enable_maintenance().is_err());
        assert!(node.publish_recovery_snapshot().is_err());
    }
    drop(primary);
    drop(secondary);
    drop(journal);
    drop(s);
    Ok(())
}

#[test]
fn second_loss_of_the_first_replacement_after_a_lost_primary() -> Result<()> {
    second_recovery_cycle(Role::Primary, Losing::FirstReplacement, false)
}

#[test]
fn second_loss_of_the_first_survivor_after_a_lost_primary() -> Result<()> {
    second_recovery_cycle(Role::Primary, Losing::FirstSurvivor, true)
}

#[test]
fn second_loss_of_the_first_replacement_after_a_lost_secondary() -> Result<()> {
    second_recovery_cycle(Role::Secondary, Losing::FirstReplacement, true)
}

#[test]
fn second_loss_of_the_first_survivor_after_a_lost_secondary() -> Result<()> {
    second_recovery_cycle(Role::Secondary, Losing::FirstSurvivor, false)
}

/// A third loss on top of the second: the retired history grows by one
/// hash-linked row, every row founds the next, and the chain keeps verifying
/// on every open of the node that has now survived three times.
#[test]
fn a_third_loss_extends_the_verified_cycle_chain() -> Result<()> {
    let s = second_loss(Role::Secondary, Losing::FirstReplacement, false)?;
    let (journal, successor) = recover_second(&s, "successor-journal-2")?;
    let proof =
        journal.fetch_loss_successor(&successor, &s.f.trust.as_trust(), s.f.gate.as_ref())?;
    let second = FirstRecovery {
        token: proof.token().to_owned(),
        certificate: proof.certificate_id(),
        journal,
        successor,
    };
    let Second {
        f,
        survivor_path,
        replacement_path,
        survivor_role,
        ..
    } = s;
    let third_replacement = f.dir.path().join("replacement-3");
    // The member that survived twice survives once more, so it is its own
    // history that has to keep verifying.
    let t = decide_next_loss(
        f,
        second,
        Next {
            survivor_path,
            survivor_role,
            lost_path: replacement_path,
            replacement_path: third_replacement,
            ids: THIRD_IDS,
            tail: Some("between-second-and-third-loss"),
        },
    )?;
    assert_eq!(cycle_rows(&t.survivor_path)?.len(), 1);
    recover_second(&t, "successor-journal-3")?;

    let rows = cycle_rows(&t.survivor_path)?;
    assert_eq!(rows.len(), 2);
    let older: RetiredLoss = serde_json::from_str(&rows[0].1)?;
    let newer: RetiredLoss = serde_json::from_str(&rows[1].1)?;
    assert_eq!(rows[0].2, hash(&older)?);
    assert_eq!(rows[1].2, hash(&newer)?);
    assert_eq!(older.parent, None);
    assert_eq!(newer.parent.as_deref(), Some(rows[0].2.as_str()));
    assert!(rows[0].0 < rows[1].0);
    // Each retirement is the recovery the next row was installed by, and the
    // oldest one was founded by a certificate, not by an earlier loss.
    assert_eq!(older.next, newer.installed.loss);
    assert_eq!(newer.next, t.loss);
    assert_eq!(
        older.installed.loss.kind(),
        transition::SourceKind::Completed
    );
    assert_eq!(
        newer.installed.loss.kind(),
        transition::SourceKind::LossSuccessor
    );
    // The thrice-recovered pair writes.
    let before = t.survivor_receipts.len() as u64;
    let survivor_node = t.open(&t.survivor_path, t.survivor_role)?;
    let replacement_node = t.open(&t.replacement_path, t.lost_role)?;
    let (mut primary, mut secondary) = match t.survivor_role {
        Role::Primary => (survivor_node, replacement_node),
        Role::Secondary => (replacement_node, survivor_node),
    };
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-third-participant-loss".into();
    assert_eq!(
        commit(&mut primary, &mut secondary, batch)?.sequence,
        before + 1
    );
    assert_eq!(receipt_rows(&primary)?, receipt_rows(&secondary)?);
    drop(primary);
    drop(secondary);
    drop(t);
    Ok(())
}

/// Run the retirement step alone, inside a transaction that is always rolled
/// back: the node-side identity guard is reachable without a journal, which is
/// the point — the journal file and this node file are different trust domains.
fn retire_directly(
    path: &Path,
    founding: &Installed,
    next: &transition::LossRequest,
) -> Result<()> {
    let db = Vesta::open(path, "fixture")?;
    db.with_connection(|c| {
        Ok((|| -> Result<()> {
            let tx = c.unchecked_transaction()?;
            let outcome = retire_founding(&tx, founding, next);
            tx.rollback()?;
            outcome
        })())
    })?
}

/// Every way of mis-stating what founded a second loss fails closed, and none
/// of it is ever repaired.
#[test]
fn second_loss_evidence_rejects_every_founding_mismatch() -> Result<()> {
    let s = second_loss(Role::Primary, Losing::FirstReplacement, false)?;
    let survivor = s.survivor_path.clone();
    // Baseline: the genuine decision derives the surviving role, and no role
    // was supplied anywhere.
    assert_eq!(s.f.derive_role_at(&survivor, &s.loss)?, s.survivor_role);
    // The member this loss fences derives nothing on its own file.
    assert_err_contains(
        s.f.derive_role_at(&s.lost_path, &s.loss),
        "loss founding participant mismatch",
    );

    // Provenance the record and its receipt do not agree on.
    for loss in [
        transition::LossRequest {
            source_certificate: [101; 32],
            ..s.loss.clone()
        },
        transition::LossRequest {
            source_token_digest: [102; 32],
            ..s.loss.clone()
        },
        transition::LossRequest {
            source_cut: transition::Checkpoint {
                sequence: s.loss.source_cut.sequence,
                digest: [103; 32],
            },
            ..s.loss.clone()
        },
        transition::LossRequest {
            membership: [104; 32],
            ..s.loss.clone()
        },
    ] {
        assert_err_contains(
            s.f.derive_role_at(&survivor, &loss),
            "loss founding successor mismatch",
        );
    }

    // Participants that are not the two the founding successor names.
    for loss in [
        transition::LossRequest {
            lost_member: [105; 32],
            ..s.loss.clone()
        },
        transition::LossRequest {
            lost_generation: [106; 32],
            ..s.loss.clone()
        },
    ] {
        assert_err_contains(
            s.f.derive_role_at(&survivor, &loss),
            "loss lost participant mismatch",
        );
    }
    assert_err_contains(
        s.f.derive_role_at(
            &survivor,
            &transition::LossRequest {
                survivor: transition::Participant {
                    member: [107; 32],
                    ..s.loss.survivor.clone()
                },
                ..s.loss.clone()
            },
        ),
        "loss founding participant mismatch",
    );

    // S11 evidence is refused outright, ahead of every founding check.
    for loss in [
        transition::LossRequest {
            source_kind: Some(transition::SourceKind::Decided),
            abandoned_request: Some([108; 32]),
            ..s.loss.clone()
        },
        transition::LossRequest {
            source_kind: Some(transition::SourceKind::Completed),
            abandoned_request: Some([109; 32]),
            ..s.loss.clone()
        },
    ] {
        assert_err_contains(s.f.derive_role_at(&survivor, &loss), NOT_ENABLED);
    }
    // S10 supersession is honoured now, but this survivor has never aborted
    // anything, so it has no local authority for one.
    assert_err_contains(
        s.f.derive_role_at(
            &survivor,
            &transition::LossRequest {
                supersedes: Some(transition::Supersedes {
                    loss_certificate: [110; 32],
                    loss_token_digest: [111; 32],
                    abort_certificate: [112; 32],
                    abort_token_digest: [113; 32],
                }),
                ..s.loss.clone()
            },
        ),
        "superseded loss has no local tombstone",
    );

    // The founding recovery must be complete.
    let receipt = completion_row(&survivor)?.ok_or("founding receipt missing")?;
    tamper(&survivor, "DROP TABLE recovery_loss_completion")?;
    assert_err_contains(
        s.f.derive_role_at(&survivor, &s.loss),
        "loss founding recovery incomplete",
    );
    tamper(
        &survivor,
        &format!(
            "CREATE TABLE recovery_loss_completion(id INTEGER PRIMARY KEY CHECK(id=1),receipt TEXT NOT NULL);
             INSERT INTO recovery_loss_completion VALUES(1,'{}');",
            receipt.replace('\'', "''")
        ),
    )?;
    assert_eq!(s.f.derive_role_at(&survivor, &s.loss)?, s.survivor_role);

    // The successor states each role twice — canonical order and founding
    // evidence — and the two must agree.
    let successor = s.successor();
    let slot = successor.survivor_index().map_err(|e| e.to_string())?;
    assert!(require_canonical_role(&successor, slot, s.lost_role).is_err());
    assert!(require_canonical_role(&successor, roles(&successor)?.1, s.survivor_role).is_err());
    require_canonical_role(&successor, slot, s.survivor_role)?;
    require_canonical_role(&successor, roles(&successor)?.1, s.lost_role)?;
    let journal = s.decide("successor-journal-2", &successor)?;
    let live = s.live(&journal);
    let handle = s.handle()?;
    let mut relabelled = successor.clone();
    relabelled.survivor_index = Some(1 - u8::try_from(slot)?);
    assert_err_contains(
        handle.install_successor("fixture", &relabelled, &live),
        "invalid loss successor request",
    );
    drop(handle);

    // Node-side identity retirement. Every identity the recovery being retired
    // burns counts, not only those of recoveries retired before it.
    let founding = decode_install(
        install_state(&survivor)?
            .0
            .as_deref()
            .ok_or("founding record missing")?,
    )?;
    for reused in [
        founding.member,
        founding.generation,
        founding.loss.lost_member,
        founding.loss.lost_generation,
        founding.loss.replacement_member,
        founding.loss.replacement_generation,
        founding.loss.membership,
        founding.successor.membership,
    ] {
        for next in [
            transition::LossRequest {
                replacement_member: reused,
                ..s.loss.clone()
            },
            transition::LossRequest {
                replacement_generation: reused,
                ..s.loss.clone()
            },
            transition::LossRequest {
                replacement_membership: reused,
                ..s.loss.clone()
            },
        ] {
            assert_err_contains(
                retire_directly(&survivor, &founding, &next),
                "participant-loss identity reuse",
            );
        }
    }
    // The genuine retirement is accepted, and rolled back again.
    retire_directly(&survivor, &founding, &s.loss)?;
    assert!(cycle_rows(&survivor)?.is_empty());
    assert!(completion_row(&survivor)?.is_some());
    assert_eq!(s.f.derive_role_at(&survivor, &s.loss)?, s.survivor_role);
    drop(journal);
    drop(s);
    Ok(())
}

/// Corrupt a compact token's signature without changing its shape.
fn forge(token: &str) -> String {
    let mut bytes = token.as_bytes().to_vec();
    let at = bytes.len() - 10;
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).unwrap_or_default()
}

/// Replace the survivor's founding evidence with a successor of our own making
/// and return the loss that would be anchored to it. No journal ever sees
/// these: they exist only to reach node-side clauses a real flow cannot.
fn refound(
    s: &Second,
    successor: &transition::LossSuccessorRequest,
    token: &str,
) -> Result<transition::LossRequest> {
    let good = install_state(&s.survivor_path)?.0.ok_or("record missing")?;
    let mut record: serde_json::Value = serde_json::from_str(&good)?;
    record["successor"] = serde_json::to_value(successor)?;
    record["successor_token"] = token.into();
    record["successor_token_digest"] = serde_json::to_value(sha(token))?;
    write_install(&s.survivor_path, &serde_json::to_string(&record)?)?;
    let mut receipt: serde_json::Value =
        serde_json::from_str(&completion_row(&s.survivor_path)?.ok_or("receipt missing")?)?;
    receipt[1] = serde_json::to_value(successor.id)?;
    receipt[2] = serde_json::to_value(sha(token))?;
    write_completion(&s.survivor_path, &serde_json::to_string(&receipt)?)?;
    let index = usize::from(s.survivor_role == Role::Secondary);
    Ok(transition::LossRequest {
        source_cut: successor.survivor_cut.clone(),
        source_token_digest: sha(token),
        survivor: transition::Participant {
            target: s.loss.survivor_cut.clone(),
            publication: s.loss.survivor_publication,
            ..successor.participants[index].clone()
        },
        ..s.loss.clone()
    })
}

/// Rebuild a founding successor around a different cut, keeping it a
/// well-formed signed request.
fn recut(
    successor: &transition::LossSuccessorRequest,
    survivor_index: usize,
    cut: transition::Checkpoint,
    id: [u8; 32],
) -> transition::LossSuccessorRequest {
    let mut recut = successor.clone();
    recut.id = id;
    recut.survivor_cut = cut.clone();
    recut.participants[survivor_index].target = cut.clone();
    recut.participants[survivor_index].old_base = None;
    recut.participants[1 - survivor_index].target = cut.clone();
    recut.participants[1 - survivor_index].old_base = Some(cut);
    recut
}

/// The founding successor is authenticated by signature under the handle's own
/// trust store, never by the digests the record happens to carry, and the cut
/// it names must anchor in this node's own history.
#[test]
fn second_loss_requires_a_verifiable_founding_token() -> Result<()> {
    let s = second_loss(Role::Secondary, Losing::FirstReplacement, false)?;
    let survivor = s.survivor_path.clone();
    let good = install_state(&survivor)?.0.ok_or("record missing")?;
    let receipt = completion_row(&survivor)?.ok_or("receipt missing")?;
    assert_eq!(s.f.derive_role_at(&survivor, &s.loss)?, s.survivor_role);
    let index = usize::from(s.survivor_role == Role::Secondary);

    // A format-1 record predates the stored token. It still decodes — the node
    // still opens on it — but it can found nothing.
    let mut stripped: serde_json::Value = serde_json::from_str(&good)?;
    stripped["format"] = 1.into();
    assert!(stripped
        .as_object_mut()
        .ok_or("record object")?
        .remove("successor_token")
        .is_some());
    write_install(&survivor, &serde_json::to_string(&stripped)?)?;
    drop(s.open(&survivor, s.survivor_role)?);
    assert_err_contains(
        s.f.derive_role_at(&survivor, &s.loss),
        "founding record carries no successor token",
    );
    write_install(&survivor, &good)?;
    assert_eq!(s.f.derive_role_at(&survivor, &s.loss)?, s.survivor_role);

    // A validly signed token, issued for a different successor.
    let other = successor_for(
        &s.loss,
        s.certificate_id,
        s.token_digest,
        s.survivor_role,
        2,
        [121; 32],
    );
    let foreign = sign_successor(&s.f.signer, &other, &s.f.trust, s.first.certificate)?;
    let attempt = refound(&s, &s.first.successor, &foreign)?;
    assert_err_contains(s.f.derive_role_at(&survivor, &attempt), "request binding");

    // The genuine token with a broken signature.
    let forged = forge(&s.first.token);
    assert_ne!(forged, s.first.token);
    let attempt = refound(&s, &s.first.successor, &forged)?;
    assert_err_contains(s.f.derive_role_at(&survivor, &attempt), "signature");

    // A founding cut this node's own history does not anchor.
    let anchored = recut(
        &s.first.successor,
        index,
        transition::Checkpoint {
            sequence: s.loss.source_cut.sequence,
            digest: [123; 32],
        },
        [122; 32],
    );
    let token = sign_successor(&s.f.signer, &anchored, &s.f.trust, s.first.certificate)?;
    let attempt = refound(&s, &anchored, &token)?;
    assert_err_contains(
        s.f.derive_role_at(&survivor, &attempt),
        "loss survivor anchor mismatch",
    );

    // A founding cut below this node's own base, refused before anything is
    // recomputed at all.
    let base = base_of(&survivor)?;
    assert!(base.sequence >= 1);
    let low = recut(
        &s.first.successor,
        index,
        transition::Checkpoint {
            sequence: base.sequence - 1,
            digest: [125; 32],
        },
        [124; 32],
    );
    let token = sign_successor(&s.f.signer, &low, &s.f.trust, s.first.certificate)?;
    let attempt = refound(&s, &low, &token)?;
    assert_err_contains(
        s.f.derive_role_at(&survivor, &attempt),
        "loss survivor base past the founding cut",
    );

    // Restored: the genuine evidence still derives exactly the same role.
    write_install(&survivor, &good)?;
    write_completion(&survivor, &receipt)?;
    assert_eq!(s.f.derive_role_at(&survivor, &s.loss)?, s.survivor_role);
    drop(s);
    Ok(())
}

/// The retired history is verified on every read: a removed, rewritten,
/// reordered or orphaned cycle row closes the node instead of being ignored.
#[test]
fn second_recovery_rejects_a_tampered_cycle_history() -> Result<()> {
    let s = second_loss(Role::Primary, Losing::FirstReplacement, false)?;
    recover_second(&s, "successor-journal-2")?;
    let survivor = s.survivor_path.clone();
    let rows = cycle_rows(&survivor)?;
    assert_eq!(rows.len(), 1);
    let open = || s.open(&survivor, s.survivor_role);
    drop(open()?);
    let restore = format!(
        "DELETE FROM recovery_loss_cycles; INSERT INTO recovery_loss_cycles VALUES({},'{}','{}');",
        rows[0].0,
        rows[0].1.replace('\'', "''"),
        rows[0].2.replace('\'', "''")
    );

    // Truncated: the install says it retired a recovery, the history does not.
    tamper(&survivor, "DELETE FROM recovery_loss_cycles")?;
    assert_err_contains(open(), "participant-loss cycle history missing");
    tamper(&survivor, &restore)?;
    drop(open()?);

    // Rewritten: the stored digest no longer covers the record.
    let mut retired: RetiredLoss = serde_json::from_str(&rows[0].1)?;
    retired.next.replacement_member = [126; 32];
    tamper(
        &survivor,
        &format!(
            "UPDATE recovery_loss_cycles SET record='{}' WHERE revision={}",
            serde_json::to_string(&retired)?.replace('\'', "''"),
            rows[0].0
        ),
    )?;
    assert_err_contains(open(), "participant-loss cycle chain mismatch");
    // Rewritten with the digest recomputed: the row no longer names the
    // install it made room for.
    tamper(
        &survivor,
        &format!(
            "UPDATE recovery_loss_cycles SET record='{}',digest='{}' WHERE revision={}",
            serde_json::to_string(&retired)?.replace('\'', "''"),
            hash(&retired)?,
            rows[0].0
        ),
    )?;
    assert_err_contains(open(), "participant-loss cycle chain mismatch");
    tamper(&survivor, &restore)?;
    drop(open()?);

    // A second, unlinked row.
    tamper(
        &survivor,
        &format!(
            "INSERT INTO recovery_loss_cycles VALUES({},'{}','{}')",
            rows[0].0 + 1,
            rows[0].1.replace('\'', "''"),
            rows[0].2.replace('\'', "''")
        ),
    )?;
    assert_err_contains(open(), "participant-loss cycle chain mismatch");
    tamper(
        &survivor,
        &format!(
            "DELETE FROM recovery_loss_cycles WHERE revision={}",
            rows[0].0 + 1
        ),
    )?;
    drop(open()?);

    // An emptied singleton is a partial state, not an empty slot.
    let record = install_state(&survivor)?.0.ok_or("record missing")?;
    tamper(&survivor, "DELETE FROM recovery_loss_active WHERE id=1")?;
    assert_err_contains(open(), "participant-loss singleton mismatch");
    // A retired history with no active record at all.
    tamper(&survivor, "DROP TABLE recovery_loss_active")?;
    assert_err_contains(open(), "orphan participant-loss cycle history");
    tamper(
        &survivor,
        &format!(
            "CREATE TABLE recovery_loss_active(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL);
             INSERT INTO recovery_loss_active VALUES(1,'{}');",
            record.replace('\'', "''")
        ),
    )?;
    let node = open()?;
    assert!(node.checkpoint().is_ok());
    drop(node);
    drop(s);
    Ok(())
}

/// Boundaries of the second-recovery operator flow. Everything is dropped and
/// reopened from disk between them, and replaying a prefix is always an exact
/// no-op.
const SECOND_DECIDED: u32 = 0;
const SECOND_BOOTSTRAP: u32 = 1;
const SECOND_SURVIVOR_INSTALL: u32 = 2;
const SECOND_REPLACEMENT_INSTALL: u32 = 3;
const SECOND_ACKS: u32 = 4;
const SECOND_COMPLETION: u32 = 5;
const SECOND_FIRST_RECEIPT: u32 = 6;
const SECOND_LAST: u32 = SECOND_FIRST_RECEIPT;

/// Replay the whole second recovery from the top and stop after `stop`.
fn replay_second(
    s: &Second,
    journal: &transition::Journal,
    successor: &transition::LossSuccessorRequest,
    stop: u32,
) -> Result<()> {
    if stop < SECOND_BOOTSTRAP {
        return Ok(());
    }
    let live = s.live(journal);
    let handle = s.handle()?;
    let installed = install_state(&s.replacement_path)?.0.is_some();
    let mut replacement = s.replacement()?;
    if installed {
        // Bootstrap is ordinary admitted work, so it is closed once the
        // successor membership is installed: replaying it must fail, not
        // repair.
        ensure(
            bootstrap_replacement(
                &handle,
                &mut replacement,
                &s.first.journal,
                s.f.gate.as_ref(),
            )
            .is_err(),
            "bootstrap admitted after install",
        )?;
    } else {
        bootstrap_replacement(
            &handle,
            &mut replacement,
            &s.first.journal,
            s.f.gate.as_ref(),
        )?;
        if stop == SECOND_BOOTSTRAP {
            return Ok(());
        }
    }
    handle.install_successor("fixture", successor, &live)?;
    if stop == SECOND_SURVIVOR_INSTALL {
        return Ok(());
    }
    install_replacement(&mut replacement, &s.founding(), successor, &live)?;
    if stop == SECOND_REPLACEMENT_INSTALL {
        return Ok(());
    }
    // The replacement object must be reopened under its installed role.
    drop(replacement);
    let replacement = s.replacement()?;
    if journal
        .fetch_loss_successor(successor, &s.f.trust.as_trust(), s.f.gate.as_ref())?
        .acknowledgements()
        != [true; 2]
    {
        let evidence = InstalledParticipants {
            survivor: &handle,
            replacement: &replacement,
            policy: s.f.gate.as_ref(),
        };
        let decision = journal.fetch_loss_successor(successor, &s.f.trust.as_trust(), &evidence)?;
        for participant in decision.request().participants.iter() {
            journal.acknowledge_loss_successor(
                &decision,
                participant,
                &s.f.trust.as_trust(),
                &evidence,
            )?;
        }
    }
    if stop == SECOND_ACKS {
        return Ok(());
    }
    complete_successor(&handle, &replacement, successor, &live)?;
    if stop == SECOND_COMPLETION {
        return Ok(());
    }
    drop(replacement);
    drop(handle);
    let survivor_node = s.open(&s.survivor_path, s.survivor_role)?;
    record_completion(&survivor_node)?;
    drop(survivor_node);
    if stop == SECOND_FIRST_RECEIPT {
        return Ok(());
    }
    let replacement_node = s.open(&s.replacement_path, s.lost_role)?;
    record_completion(&replacement_node)?;
    Ok(())
}

/// State every boundary of the second recovery must leave behind, read from
/// disk only.
fn assert_second_state(
    s: &Second,
    journal: &transition::Journal,
    successor: &transition::LossSuccessorRequest,
    stop: u32,
) -> Result<()> {
    let survivor = install_state(&s.survivor_path)?;
    let record = decode_install(survivor.0.as_deref().ok_or("survivor record missing")?)?;
    let rows = cycle_rows(&s.survivor_path)?;
    // The retirement and the new record are one atomic step: either the
    // founding record with no history at all, or the new record with exactly
    // one verified retirement and the founding receipt gone with it.
    if stop < SECOND_SURVIVOR_INSTALL {
        assert_eq!(record.loss, s.f.loss, "founding record at step {stop}");
        assert!(rows.is_empty(), "cycle rows at step {stop}");
        assert!(completion_row(&s.survivor_path)?.is_some());
    } else {
        assert_eq!(record.loss, s.loss, "new record at step {stop}");
        assert_eq!(rows.len(), 1, "cycle rows at step {stop}");
        let retired: RetiredLoss = serde_json::from_str(&rows[0].1)?;
        assert_eq!(retired.next, s.loss);
        assert_eq!(retired.installed.successor, s.first.successor);
        assert_eq!(
            completion_row(&s.survivor_path)?.is_some(),
            stop >= SECOND_FIRST_RECEIPT,
            "survivor receipt at step {stop}"
        );
    }
    // No install ever writes the survivor's owner row.
    assert_eq!(owner_role(&survivor.1)?, s.survivor_role);
    let replacement = install_state(&s.replacement_path)?;
    assert_eq!(
        replacement.0.is_some(),
        stop >= SECOND_REPLACEMENT_INSTALL,
        "replacement record at step {stop}"
    );
    assert_eq!(
        owner_role(&replacement.1)?,
        if stop >= SECOND_REPLACEMENT_INSTALL {
            s.lost_role
        } else {
            Role::Secondary
        }
    );
    assert!(cycle_rows(&s.replacement_path)?.is_empty());
    // Acknowledgements and the authority completion follow the step exactly.
    assert_eq!(
        journal
            .fetch_loss_successor(successor, &s.f.trust.as_trust(), s.f.gate.as_ref())?
            .acknowledgements()
            == [true; 2],
        stop >= SECOND_ACKS,
        "acks at step {stop}"
    );
    assert_eq!(
        journal
            .fetch_completed_loss_successor(successor, &s.f.trust.as_trust(), s.f.gate.as_ref())
            .is_ok(),
        stop >= SECOND_COMPLETION,
        "authority completion at step {stop}"
    );
    // Admission opens for a node only once its own receipt is durable.
    let survivor_node = s.open(&s.survivor_path, s.survivor_role)?;
    assert_eq!(
        survivor_node.checkpoint().is_ok(),
        stop >= SECOND_FIRST_RECEIPT,
        "survivor admission at step {stop}"
    );
    drop(survivor_node);
    let replacement_node = s.replacement()?;
    assert_eq!(
        replacement_node.checkpoint().is_ok(),
        stop < SECOND_REPLACEMENT_INSTALL,
        "replacement admission at step {stop}"
    );
    drop(replacement_node);
    // The member this loss fences never becomes admissible again.
    let stale = s.open(&s.lost_path, s.lost_role);
    assert!(
        stale.is_err() || stale?.checkpoint().is_err(),
        "lost member admitted at step {stop}"
    );
    Ok(())
}

/// Every boundary of the second recovery, crashed by dropping everything and
/// reopening from disk. Each attempt replays the whole flow from the top, so
/// every earlier step is proved an exact idempotent no-op, and the survivor's
/// retirement is proved atomic with its new install.
#[test]
fn second_recovery_converges_after_a_crash_at_every_boundary() -> Result<()> {
    let s = second_loss(Role::Secondary, Losing::FirstSurvivor, false)?;
    let successor = s.successor();
    let journal = s.decide("successor-journal-2", &successor)?;
    s.arm("successor-journal-2")?;
    let mut durable: Option<String> = None;
    for stop in SECOND_DECIDED..=SECOND_LAST {
        replay_second(&s, &journal, &successor, stop)?;
        assert_second_state(&s, &journal, &successor, stop)?;
        // Once written, the new record never changes again.
        if stop >= SECOND_SURVIVOR_INSTALL {
            let current = install_state(&s.survivor_path)?.0;
            if let Some(previous) = &durable {
                assert_eq!(current.as_deref(), Some(previous.as_str()));
            }
            durable = current;
        }
    }
    // Exact replay of the whole second recovery from the top converges, and
    // the pair writes.
    replay_second(&s, &journal, &successor, u32::MAX)?;
    assert_eq!(install_state(&s.survivor_path)?.0, durable);
    assert_eq!(cycle_rows(&s.survivor_path)?.len(), 1);
    let before = s.survivor_receipts.len() as u64;
    let survivor_node = s.open(&s.survivor_path, s.survivor_role)?;
    let replacement_node = s.open(&s.replacement_path, s.lost_role)?;
    let (mut primary, mut secondary) = match s.survivor_role {
        Role::Primary => (survivor_node, replacement_node),
        Role::Secondary => (replacement_node, survivor_node),
    };
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-second-loss-crash-walk".into();
    assert_eq!(
        commit(&mut primary, &mut secondary, batch)?.sequence,
        before + 1
    );
    let receipts = receipt_rows(&primary)?;
    assert_eq!(receipts.len() as u64, before + 1);
    assert_eq!(receipts[..before as usize], s.survivor_receipts[..]);
    assert_eq!(receipt_rows(&secondary)?, receipts);
    drop(primary);
    drop(secondary);
    drop(journal);
    drop(s);
    Ok(())
}

// ---------------------------------------------------------------------------
// S10: an authority-signed abort of a decided successor, the survivor's
// un-installation of it, and the superseding loss that follows.
//
// A wrong replacement used to be permanent: the successor journal was the only
// door out of a participant loss and it only opened forwards. The abort makes
// that journal terminal, the survivor drops back to "post-`decide_loss`,
// pre-install" — export-only, admission shut — and a superseding `LossRequest`
// with a fresh replacement membership starts over.
// ---------------------------------------------------------------------------

fn sign_abort(
    key: &EcdsaKeyPair,
    abort: &transition::LossSuccessorAbort,
    trust: &transition::TrustStore,
    certificate_id: [u8; 32],
) -> Result<String> {
    let header = B64.encode(serde_json::to_vec(&serde_json::json!({
        "alg": "ES256", "kid": "fixture", "typ": transition::LOSS_SUCCESSOR_ABORT_TOKEN_TYPE
    }))?);
    let claims = B64.encode(serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "iss": trust.profile.issuer,
        "aud": trust.profile.audience,
        "action": "abort_loss_successor",
        "certificate_id": certificate_id,
        "iat": 10, "nbf": 10, "exp": 20,
        "request": abort,
        "request_digest": abort.digest()?,
    }))?);
    let input = format!("{header}.{claims}");
    let signature = key
        .sign(&SystemRandom::new(), input.as_bytes())
        .map_err(|_| "abort token signing")?;
    Ok(format!("{input}.{}", B64.encode(signature.as_ref())))
}

/// The signed cancellation of `successor`, bound to its parent loss.
fn abort_of(
    loss: &transition::LossRequest,
    parent: ([u8; 32], [u8; 32]),
    successor: &transition::LossSuccessorRequest,
    successor_certificate: [u8; 32],
    successor_token: &str,
    id: [u8; 32],
    fencing: [u8; 32],
) -> transition::LossSuccessorAbort {
    transition::LossSuccessorAbort {
        format: 2,
        id,
        authority_id: loss.authority_id,
        revision: successor.revision,
        install: loss.install.clone(),
        region: loss.region.clone(),
        scope: loss.scope,
        schema: loss.schema,
        membership: loss.replacement_membership,
        parent_loss_certificate: parent.0,
        parent_loss_token_digest: parent.1,
        successor_id: successor.id,
        successor_certificate,
        successor_token_digest: sha(successor_token),
        fencing_ref: fencing,
    }
}

/// Raw append-only tombstone rows of a node, read outside every guard.
fn tombstone_rows(path: &Path) -> Result<Vec<(u64, String, String)>> {
    let db = Vesta::open_read_only_with_passphrase(path, "fixture")?;
    db.with_connection(|c| {
        Ok((|| -> Result<Vec<(u64, String, String)>> {
            if !table_exists(c, ABORTED_TABLE)? {
                return Ok(Vec::new());
            }
            Ok(c.prepare(
                "SELECT revision,record,digest FROM recovery_loss_aborted ORDER BY revision",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
        })())
    })?
}

/// A first loss whose successor was decided, installed to some depth, and then
/// cancelled by the authority.
struct Aborted {
    f: Fixture,
    journal: transition::Journal,
    successor: transition::LossSuccessorRequest,
    successor_token: String,
    successor_certificate: [u8; 32],
    abort: transition::LossSuccessorAbort,
    abort_certificate: [u8; 32],
    abort_token_digest: [u8; 32],
    /// Snapshot of the successor journal taken before the abort, for the
    /// rolled-back-authority replay tests.
    before_abort: PathBuf,
}

/// How far the aborted attempt got before the authority cancelled it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reached {
    /// Only the survivor installed.
    SurvivorInstall,
    /// Both nodes installed.
    BothInstalls,
    /// Both installed and one participant acknowledged.
    OneAck,
}

impl Aborted {
    fn live<'a>(&'a self, journal: &'a transition::Journal) -> Authorities<'a, Gate> {
        authorities(&self.f, journal)
    }
    fn handle(&self) -> Result<LossSurvivorHandle<StockSchema>> {
        self.f.survivor_handle()
    }
}

/// Build a certified pair, lose `lost`, install the successor as far as
/// `reached`, then have the authority abort it.
fn abort_fixture(lost: Role, reached: Reached) -> Result<Aborted> {
    let f = fixture_v2(lost, false)?;
    let handle = f.survivor_handle()?;
    let mut replacement = f.replacement()?;
    bootstrap_replacement(&handle, &mut replacement, &f.journal, f.gate.as_ref())?;
    let (journal, proof) = successor_proof(&f, "successor-journal")?;
    let successor = proof.request().clone();
    let successor_token = proof.token().to_owned();
    let successor_certificate = proof.certificate_id();
    let live = authorities(&f, &journal);
    handle.install_successor("fixture", &successor, &live)?;
    if reached != Reached::SurvivorInstall {
        install_replacement(&mut replacement, &founding(&f), &successor, &live)?;
    }
    if reached == Reached::OneAck {
        // One real acknowledgement, through the live installation evidence.
        drop(replacement);
        let reopened = f.open_replacement(f.lost_role())?;
        let evidence = InstalledParticipants {
            survivor: &handle,
            replacement: &reopened,
            policy: f.gate.as_ref(),
        };
        let decision = journal.fetch_loss_successor(&successor, &f.trust.as_trust(), &evidence)?;
        journal.acknowledge_loss_successor(
            &decision,
            &decision.request().participants[0],
            &f.trust.as_trust(),
            &evidence,
        )?;
        ensure(
            journal
                .fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
                .acknowledgements()
                == [true, false],
            "abort fixture acknowledgement mismatch",
        )?;
        drop(reopened);
        replacement = f.open_replacement(f.lost_role())?;
    }
    drop(replacement);
    drop(handle);

    // Snapshot the authority before the abort: a rolled-back successor journal
    // must still not let the aborted successor be installed again.
    let before_abort = f.dir.path().join("successor-journal-before-abort");
    swap_database(&f.dir.path().join("successor-journal"), &before_abort)?;

    let abort = abort_of(
        &f.loss,
        (f.loss_certificate_id, f.loss_token_digest),
        &successor,
        successor_certificate,
        &successor_token,
        [130; 32],
        [131; 32],
    );
    let committed = journal.abort_loss_successor(
        abort.clone(),
        &sign_abort(&f.signer, &abort, &f.trust, [132; 32])?,
        15,
        &f.trust.as_trust(),
        f.gate.as_ref(),
    )?;
    let abort_certificate = committed.certificate_id();
    let abort_token_digest = committed.token_digest();
    Ok(Aborted {
        f,
        journal,
        successor,
        successor_token,
        successor_certificate,
        abort,
        abort_certificate,
        abort_token_digest,
        before_abort,
    })
}

/// The loss that supersedes an aborted attempt. It may change the replacement
/// member, generation and membership, and nothing else; the generation has to
/// be the real one of the fresh replacement file, because the successor
/// membership is signed against it.
fn superseding(
    a: &Aborted,
    member: [u8; 32],
    generation: [u8; 32],
    membership: [u8; 32],
) -> transition::LossRequest {
    transition::LossRequest {
        id: [133; 32],
        revision: a.f.loss.revision + 1,
        replacement_member: member,
        replacement_generation: generation,
        replacement_membership: membership,
        supersedes: Some(transition::Supersedes {
            loss_certificate: a.f.loss_certificate_id,
            loss_token_digest: a.f.loss_token_digest,
            abort_certificate: a.abort_certificate,
            abort_token_digest: a.abort_token_digest,
        }),
        ..a.f.loss.clone()
    }
}

/// A superseding loss decided in the source journal, plus the fresh empty
/// replacement it names.
struct Superseded {
    loss: transition::LossRequest,
    certificate_id: [u8; 32],
    token_digest: [u8; 32],
    path: PathBuf,
}

/// A superseding loss and its signed token, not yet recorded anywhere. The
/// token is signed exactly once: a re-signed token is an immutable conflict,
/// so a resume must replay this value, never mint a new one.
struct Pending {
    loss: transition::LossRequest,
    token: String,
    path: PathBuf,
}

fn pending_supersession(
    a: &Aborted,
    name: &str,
    member: [u8; 32],
    membership: [u8; 32],
) -> Result<Pending> {
    let path = a.f.dir.path().join(name);
    let generation = {
        let node = Node::<StockSchema>::open(
            &path,
            Role::Secondary,
            a.f.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        node.connection(checkpoint::generation)?
    };
    let loss = superseding(a, member, generation, membership);
    loss.validate()?;
    Ok(Pending {
        token: sign_loss(&a.f.signer, &loss, &a.f.trust, [134; 32])?,
        loss,
        path,
    })
}

/// Record it in the real source journal. Idempotent: an exact retry of the
/// same decision and token converges.
fn decide_pending(a: &Aborted, p: &Pending) -> Result<Superseded> {
    let committed = a.f.journal.decide_loss(
        p.loss.clone(),
        &p.token,
        15,
        &a.f.trust.as_trust(),
        a.f.gate.as_ref(),
    )?;
    Ok(Superseded {
        certificate_id: committed.certificate_id(),
        token_digest: committed.token_digest(),
        loss: p.loss.clone(),
        path: p.path.clone(),
    })
}

/// Decide the superseding loss against the real source journal.
fn supersede(
    a: &Aborted,
    name: &str,
    member: [u8; 32],
    membership: [u8; 32],
) -> Result<Superseded> {
    decide_pending(a, &pending_supersession(a, name, member, membership)?)
}

/// The whole node side of a superseding recovery: export, bootstrap, both
/// installs, both ACKs, completion and both local receipts.
fn recover_superseded(
    a: &Aborted,
    s: &Superseded,
    name: &str,
) -> Result<(transition::Journal, transition::LossSuccessorRequest)> {
    let successor = successor_for(
        &s.loss,
        s.certificate_id,
        s.token_digest,
        a.f.survivor_role(),
        2,
        [135; 32],
    );
    let journal = transition::Journal::create_loss_successor(
        &a.f.dir.path().join(name),
        "successor-fixture",
        successor_scope_of(&a.f, &s.loss),
        &a.f.journal,
        &a.f.trust.as_trust(),
        a.f.gate.as_ref(),
    )?;
    journal.decide_loss_successor(
        successor.clone(),
        &sign_successor(&a.f.signer, &successor, &a.f.trust, [136; 32])?,
        15,
        &a.f.trust.as_trust(),
        a.f.gate.as_ref(),
    )?;
    // The handle now validates the superseding decision, so it must be
    // reopened: the previous one is bound to the aborted one.
    let handle = LossSurvivorHandle::open_existing(
        &a.f.survivor_path,
        a.f.identity.clone(),
        "fixture",
        StockSchema,
        &a.f.trust,
        &a.f.journal,
        a.f.gate.as_ref(),
    )?;
    let mut replacement = Node::open_with_transition_trust(
        &s.path,
        Role::Secondary,
        a.f.identity.clone(),
        "fixture",
        StockSchema,
        a.f.trust.clone(),
    )?;
    let live = authorities(&a.f, &journal);
    bootstrap_replacement(&handle, &mut replacement, &a.f.journal, a.f.gate.as_ref())?;
    install_pair(
        &handle,
        &mut replacement,
        "fixture",
        &founding(&a.f),
        &successor,
        &live,
    )?;
    a.f.live.attach_successor(transition::Journal::open(
        &a.f.dir.path().join(name),
        "successor-fixture",
        successor_scope_of(&a.f, &s.loss),
        &a.f.trust.as_trust(),
    )?)?;
    complete_successor(&handle, &replacement, &successor, &live)?;
    drop(replacement);
    drop(handle);
    for (path, role) in [
        (&a.f.survivor_path, a.f.survivor_role()),
        (&s.path, a.f.lost_role()),
    ] {
        let node = open_with_authority(&a.f, path, role)?;
        record_completion(&node)?;
        ensure(
            node.checkpoint().is_ok(),
            "superseded recovery is not admitted",
        )?;
        drop(node);
    }
    Ok((journal, successor))
}

/// Abort at three depths, un-install, supersede, recover for real, write.
fn abort_and_supersede(lost: Role, reached: Reached) -> Result<()> {
    let a = abort_fixture(lost, reached)?;
    let survivor = a.f.survivor_path.clone();
    let derived = a.f.survivor_role();
    // Before the un-install the survivor still carries the aborted install and
    // is closed: the successor journal is terminal, so nothing can complete.
    assert!(install_state(&survivor)?.0.is_some());
    assert!(tombstone_rows(&survivor)?.is_empty());
    let handle = a.handle()?;
    let live = a.live(&a.journal);
    assert_err_contains(
        complete_successor(
            &handle,
            &a.f.open_replacement(match reached {
                Reached::SurvivorInstall => Role::Secondary,
                _ => a.f.lost_role(),
            })?,
            &a.successor,
            &live,
        ),
        "loss successor aborted",
    );

    // Un-install. One transaction: the tombstone appears and the active record
    // goes, or neither happens.
    handle.abort_successor_install("fixture", &a.successor, &live)?;
    let rows = tombstone_rows(&survivor)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(install_state(&survivor)?.0, None);
    assert_eq!(completion_row(&survivor)?, None);
    let tombstone: AbortedSuccessor = serde_json::from_str(&rows[0].1)?;
    assert_eq!(rows[0].0, a.f.loss.revision);
    assert_eq!(rows[0].2, hash(&tombstone)?);
    assert_eq!(tombstone.parent, None);
    assert_eq!(tombstone.loss, a.f.loss);
    assert_eq!(tombstone.loss_certificate, a.f.loss_certificate_id);
    assert_eq!(tombstone.loss_token_digest, a.f.loss_token_digest);
    assert_eq!(tombstone.successor_id, a.successor.id);
    assert_eq!(tombstone.successor_certificate, a.successor_certificate);
    assert_eq!(tombstone.successor_token_digest, sha(&a.successor_token));
    assert_eq!(tombstone.abort_certificate, a.abort_certificate);
    assert_eq!(tombstone.abort_token_digest, a.abort_token_digest);
    assert_eq!(tombstone.fencing_ref, a.abort.fencing_ref);
    // The owner row was never written by any of this.
    assert_eq!(owner_role(&install_state(&survivor)?.1)?, derived);
    // Exact retry of the un-install is a verified no-op.
    handle.abort_successor_install("fixture", &a.successor, &live)?;
    assert_eq!(tombstone_rows(&survivor)?, rows);

    // C6: the survivor is exactly "post-`decide_loss`, pre-install" — still
    // exportable through the handle, and not openable as an ordinary node at
    // all, because its pre-loss certificate is superseded.
    assert_eq!(
        handle.manifest(&a.f.journal, a.f.gate.as_ref())?,
        a.f.survivor_manifest
    );
    handle.page(0, &a.f.journal, a.f.gate.as_ref())?;
    assert!(a.f.open_node(&survivor, derived).is_err());
    assert!(open_with_authority(&a.f, &survivor, derived).is_err());
    // The aborted replacement stays installed-but-closed for ever.
    if reached != Reached::SurvivorInstall {
        let stale = a.f.open_replacement(a.f.lost_role())?;
        assert!(stale.checkpoint().is_err());
        drop(stale);
    }
    // Replay protection: even with the pre-abort successor journal swapped
    // back, the aborted successor can never be installed here again.
    drop(handle);
    swap_database(&a.before_abort, &a.f.dir.path().join("successor-journal"))?;
    let rolled_back = transition::Journal::open(
        &a.f.dir.path().join("successor-journal"),
        "successor-fixture",
        successor_scope(&a.f),
        &a.f.trust.as_trust(),
    )?;
    let handle = a.handle()?;
    assert_err_contains(
        handle.install_successor("fixture", &a.successor, &a.live(&rolled_back)),
        "aborted loss successor cannot be installed",
    );
    assert_eq!(install_state(&survivor)?.0, None);
    drop(rolled_back);
    drop(handle);
    swap_database(
        &a.f.dir.path().join("successor-journal-before-abort"),
        &a.f.dir.path().join("successor-journal"),
    )?;

    // Restart between the un-install and the superseding decision: nothing is
    // carried in memory.
    let s = supersede(&a, "replacement-superseding", [140; 32], [141; 32])?;
    assert_eq!(
        a.f.journal
            .fetch_loss(&a.f.trust.as_trust(), a.f.gate.as_ref())?
            .request(),
        &s.loss
    );
    let (journal, successor) = recover_superseded(&a, &s, "successor-journal-superseding")?;
    assert_ne!(successor.id, a.successor.id);

    // The tombstone survives the whole superseding recovery and the install
    // record now names the new replacement.
    assert_eq!(tombstone_rows(&survivor)?, rows);
    let record = decode_install(
        install_state(&survivor)?
            .0
            .as_deref()
            .ok_or("survivor record missing")?,
    )?;
    assert_eq!(record.loss, s.loss);
    assert_eq!(record.successor, successor);
    assert!(cycle_rows(&survivor)?.is_empty());

    // First write of the superseded pair.
    let survivor_node = open_with_authority(&a.f, &survivor, derived)?;
    let replacement_node = open_with_authority(&a.f, &s.path, a.f.lost_role())?;
    assert_eq!(
        survivor_node.required_recovery_peer()?,
        Some(s.loss.replacement_member)
    );
    // The aborted replacement is never a peer again.
    assert_ne!(
        survivor_node.required_recovery_peer()?,
        Some(a.f.loss.replacement_member)
    );
    let before = a.f.survivor_receipts.len() as u64;
    let (mut primary, mut secondary) = match derived {
        Role::Primary => (survivor_node, replacement_node),
        Role::Secondary => (replacement_node, survivor_node),
    };
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-superseding-recovery".into();
    assert_eq!(
        commit(&mut primary, &mut secondary, batch)?.sequence,
        before + 1
    );
    let receipts = receipt_rows(&primary)?;
    assert_eq!(receipts.len() as u64, before + 1);
    assert_eq!(receipts[..before as usize], a.f.survivor_receipts[..]);
    assert_eq!(receipt_rows(&secondary)?, receipts);
    // The aborted replacement file is still closed, after the supersession too.
    if reached != Reached::SurvivorInstall {
        let stale = a.f.open_replacement(a.f.lost_role())?;
        assert!(stale.checkpoint().is_err());
        drop(stale);
    }
    drop(primary);
    drop(secondary);
    drop(journal);
    drop(a);
    Ok(())
}

#[test]
fn abort_after_the_survivor_install_is_superseded_for_a_lost_primary() -> Result<()> {
    abort_and_supersede(Role::Primary, Reached::SurvivorInstall)
}

#[test]
fn abort_after_both_installs_is_superseded_for_a_lost_secondary() -> Result<()> {
    abort_and_supersede(Role::Secondary, Reached::BothInstalls)
}

#[test]
fn abort_after_one_acknowledgement_is_superseded_for_a_lost_primary() -> Result<()> {
    abort_and_supersede(Role::Primary, Reached::OneAck)
}

#[test]
fn abort_after_both_installs_is_superseded_for_a_lost_primary() -> Result<()> {
    abort_and_supersede(Role::Primary, Reached::BothInstalls)
}

/// Run the survivor's tombstone check alone, on a read-only connection: the
/// deeper identity layer is only reachable across several attempts, so it is
/// driven directly rather than through a third signed supersession.
fn supersession_check(path: &Path, loss: &transition::LossRequest) -> Result<()> {
    let db = Vesta::open_read_only_with_passphrase(path, "fixture")?;
    db.with_connection(|c| {
        c.pragma_update(None, "query_only", true)?;
        Ok(require_supersession(c, loss))
    })?
}

/// Write a well-formed local completion receipt straight into a survivor that
/// never earned one. Only used to reach the guard that refuses to un-install a
/// completed recovery.
fn forge_completion(path: &Path, record: &Installed) -> Result<()> {
    let receipt = serde_json::to_string(&(
        1u32,
        record.successor.id,
        record.successor_token_digest,
        record.successor_certificate,
        [142u8; 32],
    ))?;
    tamper(
        path,
        &format!(
            "CREATE TABLE IF NOT EXISTS recovery_loss_completion(id INTEGER PRIMARY KEY CHECK(id=1),receipt TEXT NOT NULL);
             INSERT INTO recovery_loss_completion VALUES(1,'{}');",
            receipt.replace('\'', "''")
        ),
    )
}

/// Every way of mis-stating an abort or a supersession fails closed, and the
/// un-installation is never partially applied.
#[test]
fn superseding_loss_evidence_rejects_every_mismatch() -> Result<()> {
    let a = abort_fixture(Role::Secondary, Reached::BothInstalls)?;
    let survivor = a.f.survivor_path.clone();
    let derived = a.f.survivor_role();
    let good = install_state(&survivor)?.0.ok_or("record missing")?;
    let record = decode_install(&good)?;

    // S11 evidence is still refused, ahead of everything else.
    for loss in [
        transition::LossRequest {
            abandoned_request: Some([143; 32]),
            ..a.f.loss.clone()
        },
        transition::LossRequest {
            source_kind: Some(transition::SourceKind::Decided),
            abandoned_request: Some([144; 32]),
            ..a.f.loss.clone()
        },
    ] {
        assert_err_contains(a.f.derive_role_at(&survivor, &loss), NOT_ENABLED);
    }

    // A supersession with no tombstone on this node is refused: the authority's
    // journal cannot vouch for this file.
    let orphan = superseding(&a, [145; 32], [146; 32], [147; 32]);
    assert_err_contains(
        a.f.derive_role_at(&survivor, &orphan),
        "superseded loss has no local tombstone",
    );

    // A journal with no abort in it cannot authorise an un-installation.
    let journal_path = a.f.dir.path().join("successor-journal");
    swap_database(&a.before_abort, &journal_path)?;
    let unaborted = transition::Journal::open(
        &journal_path,
        "successor-fixture",
        successor_scope(&a.f),
        &a.f.trust.as_trust(),
    )?;
    let handle = a.handle()?;
    assert_err_contains(
        handle.abort_successor_install("fixture", &a.successor, &a.live(&unaborted)),
        "loss successor abort missing",
    );
    assert_eq!(install_state(&survivor)?.0.as_deref(), Some(good.as_str()));
    assert!(tombstone_rows(&survivor)?.is_empty());
    drop(unaborted);
    drop(handle);
    swap_database(
        &a.f.dir.path().join("successor-journal-before-abort"),
        &journal_path,
    )?;

    // An abort recorded for a different successor authorises nothing.
    let handle = a.handle()?;
    let other = successor_request_with(&a.f, [148; 32]);
    assert_err_contains(
        handle.abort_successor_install("fixture", &other, &a.live(&a.journal)),
        "loss successor abort binding mismatch",
    );

    // A local record that no longer binds the abort is a conflict, not a state
    // to adopt. Only the un-install's own binding check can catch this: the
    // record still decodes and still belongs to this loss and successor.
    let mut restamped: serde_json::Value = serde_json::from_str(&good)?;
    restamped["successor_certificate"] = serde_json::to_value([149u8; 32])?;
    drop(handle);
    write_install(&survivor, &serde_json::to_string(&restamped)?)?;
    let handle = a.handle()?;
    assert_err_contains(
        handle.abort_successor_install("fixture", &a.successor, &a.live(&a.journal)),
        "participant-loss un-install binding mismatch",
    );
    drop(handle);
    write_install(&survivor, &good)?;

    // A completed recovery is never un-installed: after completion a bad
    // replacement is an ordinary new loss, not a rollback.
    forge_completion(&survivor, &record)?;
    let handle = a.handle()?;
    assert_err_contains(
        handle.abort_successor_install("fixture", &a.successor, &a.live(&a.journal)),
        "completed participant-loss recovery cannot be un-installed",
    );
    assert_eq!(install_state(&survivor)?.0.as_deref(), Some(good.as_str()));
    assert!(tombstone_rows(&survivor)?.is_empty());
    drop(handle);
    tamper(&survivor, "DROP TABLE recovery_loss_completion")?;

    // Only a survivor capability can un-install anything: the replacement file
    // is not a certified survivor and cannot even open one.
    assert!(LossSurvivorHandle::<StockSchema>::open_existing(
        &a.f.replacement_path,
        a.f.identity.clone(),
        "fixture",
        StockSchema,
        &a.f.trust,
        &a.f.journal,
        a.f.gate.as_ref(),
    )
    .is_err());

    // The genuine un-installation, at last.
    let handle = a.handle()?;
    handle.abort_successor_install("fixture", &a.successor, &a.live(&a.journal))?;
    assert_eq!(install_state(&survivor)?.0, None);
    assert_eq!(tombstone_rows(&survivor)?.len(), 1);

    // The replacement cannot be re-installed against the live journal either.
    let mut stale = a.f.open_replacement(a.f.lost_role())?;
    assert_err_contains(
        install_replacement(
            &mut stale,
            &founding(&a.f),
            &a.successor,
            &a.live(&a.journal),
        ),
        "loss successor aborted",
    );
    assert!(stale.checkpoint().is_err());
    drop(stale);

    // A supersession may change the replacement and nothing else.
    let mut widened = superseding(&a, [150; 32], [151; 32], [152; 32]);
    widened.survivor_publication = [153; 32];
    assert_err_contains(
        a.f.derive_role_at(&survivor, &widened),
        "superseding loss changes more than the replacement",
    );
    // The aborted replacement's own identity can never come back.
    for reused in [
        superseding(&a, a.f.loss.replacement_member, [154; 32], [155; 32]),
        superseding(&a, [156; 32], a.f.loss.replacement_generation, [157; 32]),
        superseding(&a, [158; 32], [159; 32], a.f.loss.replacement_membership),
    ] {
        assert_err_contains(
            a.f.derive_role_at(&survivor, &reused),
            "superseding loss reuses a retired replacement",
        );
    }
    // The deeper layer: an identity this file burnt for another reason is
    // refused even when it is not the previous attempt's replacement.
    let mut deep = superseding(&a, [160; 32], [161; 32], [162; 32]);
    deep.replacement_member = a.f.loss.lost_member;
    assert_err_contains(
        supersession_check(&survivor, &deep),
        "participant-loss identity reuse",
    );
    // And the genuine supersession still validates on this file.
    let s = supersede(&a, "replacement-superseding", [163; 32], [164; 32])?;
    assert_eq!(a.f.derive_role_at(&survivor, &s.loss)?, derived);
    drop(a);
    Ok(())
}

/// Abort, supersede, recover — and then lose a participant of the new pair for
/// real. The cycle history and the tombstone history coexist on one file and
/// both are verified on every read.
#[test]
fn a_second_loss_after_a_superseded_recovery_keeps_both_histories() -> Result<()> {
    let a = abort_fixture(Role::Primary, Reached::BothInstalls)?;
    let survivor = a.f.survivor_path.clone();
    let handle = a.handle()?;
    handle.abort_successor_install("fixture", &a.successor, &a.live(&a.journal))?;
    drop(handle);
    let s = supersede(&a, "replacement-superseding", [170; 32], [171; 32])?;
    let (journal, successor) = recover_superseded(&a, &s, "successor-journal-superseding")?;
    assert_eq!(tombstone_rows(&survivor)?.len(), 1);
    assert!(cycle_rows(&survivor)?.is_empty());

    // An ordinary second loss on the recovered pair: the first survivor stays,
    // the superseding replacement is the one lost now.
    let proof =
        journal.fetch_loss_successor(&successor, &a.f.trust.as_trust(), a.f.gate.as_ref())?;
    let first = FirstRecovery {
        token: proof.token().to_owned(),
        certificate: proof.certificate_id(),
        journal,
        successor,
    };
    let Aborted { f, .. } = a;
    let replacement_path = f.dir.path().join("replacement-after-supersession");
    let survivor_role = f.survivor_role();
    let second = decide_next_loss(
        f,
        first,
        Next {
            survivor_path: survivor.clone(),
            survivor_role,
            lost_path: s.path.clone(),
            replacement_path,
            ids: SECOND_IDS,
            tail: Some("between-supersession-and-second-loss"),
        },
    )?;
    recover_second(&second, "successor-journal-second")?;

    // Both histories are on the same file and both verify.
    let cycles = cycle_rows(&survivor)?;
    let tombstones = tombstone_rows(&survivor)?;
    assert_eq!(cycles.len(), 1);
    assert_eq!(tombstones.len(), 1);
    let retired: RetiredLoss = serde_json::from_str(&cycles[0].1)?;
    let tombstone: AbortedSuccessor = serde_json::from_str(&tombstones[0].1)?;
    assert_eq!(cycles[0].2, hash(&retired)?);
    assert_eq!(tombstones[0].2, hash(&tombstone)?);
    // The retired recovery is the superseding one, and the tombstone is the
    // attempt it replaced: same lineage, different replacement.
    assert_eq!(retired.next, second.loss);
    assert!(retired.installed.loss.supersedes.is_some());
    assert_eq!(
        retired.installed.loss.replacement_member,
        s.loss.replacement_member
    );
    assert_ne!(
        tombstone.loss.replacement_member,
        retired.installed.loss.replacement_member
    );
    assert_eq!(
        tombstone.loss.lost_member,
        retired.installed.loss.lost_member
    );

    // The twice-changed pair writes.
    let before = second.survivor_receipts.len() as u64;
    let survivor_node = second.open(&second.survivor_path, second.survivor_role)?;
    let replacement_node = second.open(&second.replacement_path, second.lost_role)?;
    let (mut primary, mut secondary) = match second.survivor_role {
        Role::Primary => (survivor_node, replacement_node),
        Role::Secondary => (replacement_node, survivor_node),
    };
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-supersession-and-second-loss".into();
    assert_eq!(
        commit(&mut primary, &mut secondary, batch)?.sequence,
        before + 1
    );
    assert_eq!(receipt_rows(&primary)?, receipt_rows(&secondary)?);
    drop(primary);
    drop(secondary);
    drop(second);
    Ok(())
}

/// The tombstone history is verified on every read of the node's loss state: a
/// rewritten, truncated or foreign row closes the node instead of being
/// ignored.
#[test]
fn superseded_recovery_rejects_a_tampered_tombstone_history() -> Result<()> {
    let a = abort_fixture(Role::Secondary, Reached::BothInstalls)?;
    let survivor = a.f.survivor_path.clone();
    let handle = a.handle()?;
    handle.abort_successor_install("fixture", &a.successor, &a.live(&a.journal))?;
    drop(handle);
    let s = supersede(&a, "replacement-superseding", [180; 32], [181; 32])?;
    recover_superseded(&a, &s, "successor-journal-superseding")?;
    let rows = tombstone_rows(&survivor)?;
    assert_eq!(rows.len(), 1);
    let derived = a.f.survivor_role();
    let open = || open_with_authority(&a.f, &survivor, derived);
    drop(open()?);
    let restore = format!(
        "DELETE FROM recovery_loss_aborted; INSERT INTO recovery_loss_aborted VALUES({},'{}','{}');",
        rows[0].0,
        rows[0].1.replace('\'', "''"),
        rows[0].2.replace('\'', "''")
    );

    // Truncated: the install record supersedes an attempt the file no longer
    // admits to having made.
    tamper(&survivor, "DELETE FROM recovery_loss_aborted")?;
    assert_err_contains(open(), "participant-loss tombstone limit");
    tamper(&survivor, "DROP TABLE recovery_loss_aborted")?;
    // With the table gone the supersession has no local authority at all.
    assert_err_contains(
        a.f.derive_role_at(&survivor, &s.loss),
        "superseded loss has no local tombstone",
    );
    tamper(
        &survivor,
        &format!(
            "CREATE TABLE recovery_loss_aborted(revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest TEXT NOT NULL);
             {restore}"
        ),
    )?;
    drop(open()?);

    // Rewritten: the stored digest no longer covers the record.
    let mut tombstone: AbortedSuccessor = serde_json::from_str(&rows[0].1)?;
    tombstone.abort_certificate = [182; 32];
    tamper(
        &survivor,
        &format!(
            "UPDATE recovery_loss_aborted SET record='{}' WHERE revision={}",
            serde_json::to_string(&tombstone)?.replace('\'', "''"),
            rows[0].0
        ),
    )?;
    assert_err_contains(open(), "participant-loss tombstone chain mismatch");
    // Rewritten with the digest recomputed: the supersession no longer binds.
    tamper(
        &survivor,
        &format!(
            "UPDATE recovery_loss_aborted SET record='{}',digest='{}' WHERE revision={}",
            serde_json::to_string(&tombstone)?.replace('\'', "''"),
            hash(&tombstone)?,
            rows[0].0
        ),
    )?;
    drop(open()?);
    assert_err_contains(
        a.f.derive_role_at(&survivor, &s.loss),
        "superseded loss has no local tombstone",
    );
    tamper(&survivor, &restore)?;
    drop(open()?);

    // A tombstone for a loss this file was never part of is not history.
    let mut foreign: AbortedSuccessor = serde_json::from_str(&rows[0].1)?;
    foreign.loss.lost_member = [183; 32];
    foreign.parent = Some(rows[0].2.clone());
    tamper(
        &survivor,
        &format!(
            "INSERT INTO recovery_loss_aborted VALUES({},'{}','{}')",
            rows[0].0 + 1,
            serde_json::to_string(&foreign)?.replace('\'', "''"),
            hash(&foreign)?
        ),
    )?;
    assert_err_contains(open(), "participant-loss tombstone chain mismatch");
    tamper(
        &survivor,
        &format!(
            "DELETE FROM recovery_loss_aborted WHERE revision={}",
            rows[0].0 + 1
        ),
    )?;
    let node = open()?;
    assert!(node.checkpoint().is_ok());
    drop(node);
    drop(a);
    Ok(())
}

/// Boundaries of the abort/supersede flow. Everything is dropped and reopened
/// from disk between them, and replaying a prefix is always an exact no-op.
const ABORT_DECIDED: u32 = 0;
const ABORT_UNINSTALLED: u32 = 1;
const ABORT_SUPERSEDED: u32 = 2;
const ABORT_BOOTSTRAP: u32 = 3;
const ABORT_LAST: u32 = ABORT_BOOTSTRAP;

/// Replay the whole abort/supersede flow from the top and stop after `stop`.
/// The superseding decision is signed once, up front, so a replay never needs
/// a new authority action — exactly like an operator resuming after a crash.
fn replay_abort(a: &Aborted, p: &Pending, stop: u32) -> Result<()> {
    if stop < ABORT_UNINSTALLED {
        return Ok(());
    }
    if install_state(&a.f.survivor_path)?.0.is_some() {
        let handle = a.handle()?;
        handle.abort_successor_install("fixture", &a.successor, &a.live(&a.journal))?;
        drop(handle);
    } else {
        // Exact retry of a completed un-installation converges without
        // touching the tombstone it already wrote.
        let rows = tombstone_rows(&a.f.survivor_path)?;
        let handle = a.handle()?;
        handle.abort_successor_install("fixture", &a.successor, &a.live(&a.journal))?;
        drop(handle);
        ensure(
            tombstone_rows(&a.f.survivor_path)? == rows,
            "un-install retry rewrote the tombstone",
        )?;
    }
    if stop == ABORT_UNINSTALLED {
        return Ok(());
    }
    // Only now can the authority supersede: `Journal::abort_loss_successor`
    // is already recorded and the survivor has durably un-installed. The exact
    // same decision and token are replayed on every resume.
    let s = decide_pending(a, p)?;
    ensure(
        a.f.journal
            .fetch_loss(&a.f.trust.as_trust(), a.f.gate.as_ref())?
            .request()
            == &s.loss,
        "superseding decision missing",
    )?;
    ensure(
        a.f.derive_role_at(&a.f.survivor_path, &s.loss)? == a.f.survivor_role(),
        "superseding evidence mismatch",
    )?;
    if stop == ABORT_SUPERSEDED {
        return Ok(());
    }
    let handle = LossSurvivorHandle::open_existing(
        &a.f.survivor_path,
        a.f.identity.clone(),
        "fixture",
        StockSchema,
        &a.f.trust,
        &a.f.journal,
        a.f.gate.as_ref(),
    )?;
    let mut replacement = Node::open_with_transition_trust(
        &s.path,
        Role::Secondary,
        a.f.identity.clone(),
        "fixture",
        StockSchema,
        a.f.trust.clone(),
    )?;
    bootstrap_replacement(&handle, &mut replacement, &a.f.journal, a.f.gate.as_ref())?;
    drop(replacement);
    drop(handle);
    Ok(())
}

/// State every boundary of the abort/supersede flow must leave behind.
fn assert_abort_state(a: &Aborted, p: &Pending, stop: u32) -> Result<()> {
    let survivor = install_state(&a.f.survivor_path)?;
    let tombstones = tombstone_rows(&a.f.survivor_path)?;
    // One transaction: either the aborted record with no tombstone, or the
    // tombstone with no record at all. Never both, never neither.
    assert_eq!(
        survivor.0.is_some(),
        stop < ABORT_UNINSTALLED,
        "survivor record at step {stop}"
    );
    assert_eq!(
        tombstones.len(),
        usize::from(stop >= ABORT_UNINSTALLED),
        "tombstones at step {stop}"
    );
    assert_eq!(completion_row(&a.f.survivor_path)?, None);
    assert!(cycle_rows(&a.f.survivor_path)?.is_empty());
    // The owner row is never written by an abort or an un-installation.
    assert_eq!(owner_role(&survivor.1)?, a.f.survivor_role());
    // The survivor is never admitted anywhere along this walk. While the
    // aborted install is still there it opens as a loss-installed node and is
    // closed for want of a completion receipt; once un-installed it does not
    // open at all, because its pre-loss certificate is superseded (C6).
    let opened = open_with_authority(&a.f, &a.f.survivor_path, a.f.survivor_role());
    assert_eq!(
        opened.is_ok(),
        stop < ABORT_UNINSTALLED,
        "survivor open at step {stop}"
    );
    if let Ok(node) = opened {
        assert!(
            node.checkpoint().is_err(),
            "survivor admitted at step {stop}"
        );
        drop(node);
    }
    // The superseding decision only exists from its own step on, and the
    // effective loss follows it.
    assert_eq!(
        a.f.journal
            .fetch_loss(&a.f.trust.as_trust(), a.f.gate.as_ref())?
            .request()
            == &p.loss,
        stop >= ABORT_SUPERSEDED,
        "effective loss at step {stop}"
    );
    // Its export capability keeps working throughout, against whichever
    // decision is currently effective.
    let handle = LossSurvivorHandle::<StockSchema>::open_existing(
        &a.f.survivor_path,
        a.f.identity.clone(),
        "fixture",
        StockSchema,
        &a.f.trust,
        &a.f.journal,
        a.f.gate.as_ref(),
    )?;
    assert_eq!(handle.role, a.f.survivor_role());
    drop(handle);
    // The aborted replacement stays installed and closed for ever.
    let stale = a.f.open_replacement(a.f.lost_role())?;
    assert!(stale.checkpoint().is_err(), "aborted peer at step {stop}");
    drop(stale);
    // The fresh replacement is an ordinary empty node until it is bootstrapped.
    let fresh = Node::<StockSchema>::open(
        &p.path,
        Role::Secondary,
        a.f.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert_eq!(
        fresh.checkpoint()?.sequence,
        if stop >= ABORT_BOOTSTRAP {
            a.f.loss.survivor_cut.sequence
        } else {
            0
        },
        "fresh replacement at step {stop}"
    );
    drop(fresh);
    Ok(())
}

/// Every boundary of the abort/supersede flow, crashed by dropping everything
/// and reopening from disk, then the whole recovery carried to a first write.
#[test]
fn superseded_recovery_converges_after_a_crash_at_every_boundary() -> Result<()> {
    let a = abort_fixture(Role::Secondary, Reached::BothInstalls)?;
    // The abort is already durable in the successor journal; the superseding
    // decision is signed once here and only recorded at its own step, because
    // the authority cannot supersede before the survivor has un-installed.
    let p = pending_supersession(&a, "replacement-superseding", [190; 32], [191; 32])?;
    let mut durable: Option<String> = None;
    for stop in ABORT_DECIDED..=ABORT_LAST {
        replay_abort(&a, &p, stop)?;
        assert_abort_state(&a, &p, stop)?;
        if stop >= ABORT_UNINSTALLED {
            let rows = tombstone_rows(&a.f.survivor_path)?;
            let current = rows.first().map(|row| row.1.clone());
            if let Some(previous) = &durable {
                assert_eq!(current.as_deref(), Some(previous.as_str()));
            }
            durable = current;
        }
    }
    assert!(durable.is_some());
    // Resume from the top and carry the superseding recovery all the way.
    replay_abort(&a, &p, u32::MAX)?;
    let s = decide_pending(&a, &p)?;
    let (_journal, _successor) = recover_superseded(&a, &s, "successor-journal-superseding")?;
    assert_eq!(
        tombstone_rows(&a.f.survivor_path)?
            .first()
            .map(|row| row.1.clone()),
        durable
    );
    let before = a.f.survivor_receipts.len() as u64;
    let survivor_node = open_with_authority(&a.f, &a.f.survivor_path, a.f.survivor_role())?;
    let replacement_node = open_with_authority(&a.f, &s.path, a.f.lost_role())?;
    let (mut primary, mut secondary) = match a.f.survivor_role() {
        Role::Primary => (survivor_node, replacement_node),
        Role::Secondary => (replacement_node, survivor_node),
    };
    let mut batch = stock_entry().batch;
    batch.operation_id = "after-abort-crash-walk".into();
    assert_eq!(
        commit(&mut primary, &mut secondary, batch)?.sequence,
        before + 1
    );
    let receipts = receipt_rows(&primary)?;
    assert_eq!(receipts.len() as u64, before + 1);
    assert_eq!(receipts[..before as usize], a.f.survivor_receipts[..]);
    assert_eq!(receipt_rows(&secondary)?, receipts);
    drop(primary);
    drop(secondary);
    drop(a);
    Ok(())
}
