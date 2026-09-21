//! Symmetric participant-loss evidence: a real certified pair, a real journal
//! loss decision, and a real bootstrap of the replacement. The survivor role is
//! never supplied by these tests; it is only ever asserted after derivation.
use super::*;
use crate::envelope_tests::{stock_entry, StockSchema};
use crate::recovery::transition;
use crate::typed::recovery::tests::recovered_pair_for_pending;
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

fn participant(
    node: &Node<StockSchema>,
    local: &CompactionPlan,
    plan: &compaction::PairPlan,
) -> Result<transition::Participant> {
    Ok(transition::Participant {
        member: node
            .recovery_member_identity()?
            .ok_or("fixture member identity missing")?,
        generation: node.connection(checkpoint::generation)?,
        old_base: local.head.base.as_ref().map(cut).transpose()?,
        target: cut(&local.checkpoint)?,
        plan: id(plan)?,
        publication: id(local
            .publication
            .as_ref()
            .ok_or("fixture publication missing")?)?,
    })
}

fn sign_loss(
    key: &EcdsaKeyPair,
    request: &transition::LossRequest,
    trust: &transition::TrustStore,
) -> Result<String> {
    let header = B64.encode(serde_json::to_vec(&serde_json::json!({
        "alg": "ES256", "kid": "fixture", "typ": transition::LOSS_TOKEN_TYPE
    }))?);
    let certificate_id = [49u8; 32];
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
    let dir = tempfile::tempdir()?;
    let (mut p, mut s) = recovered_pair_for_pending(dir.path())?;
    p.upgrade_receipt_capacity()?;
    s.upgrade_receipt_capacity()?;
    p.enable_maintenance()?;
    s.enable_maintenance()?;
    let old_p = p
        .plan_compaction()?
        .publication
        .ok_or("fixture primary publication missing")?;
    let old_s = s
        .plan_compaction()?
        .publication
        .ok_or("fixture secondary publication missing")?;
    let mut batch = stock_entry().batch;
    batch.operation_id = "loss-fixture-seed".into();
    commit(&mut p, &mut s, batch)?;
    p.rotate_snapshot(&old_p)?;
    s.rotate_snapshot(&old_s)?;
    let plan = compaction::PairPlan {
        id: [41; 32],
        primary: p.plan_compaction()?,
        secondary: s.plan_compaction()?,
    };
    plan.validate_certified()?;
    let certificate = transition::Request {
        format: 1,
        id: [42; 32],
        authority_id: [43; 32],
        revision: 1,
        install: "loss-fixture".into(),
        region: "test".into(),
        scope: id(p.identity())?,
        schema: id(&plan.primary.contract)?,
        membership: plan
            .primary
            .membership
            .ok_or("fixture membership missing")?,
        source_anchor: cut(plan
            .primary
            .recovery_anchor
            .as_ref()
            .ok_or("fixture anchor missing")?)?,
        participants: [
            participant(&p, &plan.primary, &plan)?,
            participant(&s, &plan.secondary, &plan)?,
        ],
    };
    let (key, public) = certified::tests::signer()?;
    let token = certified::tests::sign(&key, &certificate)?;
    let trust = transition::TrustStore {
        profile: crate::recovery::grant::Profile {
            issuer: "issuer".into(),
            audience: "audience".into(),
            token_type: transition::TOKEN_TYPE.into(),
        },
        keys: vec![("fixture".into(), public)],
        max_lifetime: 20,
    };
    pending::prepare_pair(&p, &s, &plan, &certificate, &token, 15, &trust)?;
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
    pending::complete_authority(&hp, &hs, &journal, [44; 32], &trust, gate.as_ref())?;
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
        format: 1,
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
    let loss_token = sign_loss(&key, &loss, &trust)?;
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
    transition::JournalScope {
        install: f.loss.install.clone(),
        region: f.loss.region.clone(),
        profile: f.trust.profile.clone(),
        scope: f.loss.scope,
        schema: f.loss.schema,
        membership: f.loss.replacement_membership,
        source_anchor: f.loss.source_cut.clone(),
        authority_id: f.loss.authority_id,
        initial_revision: f.loss.revision + 1,
    }
}

fn successor_request_with(f: &Fixture, id: [u8; 32]) -> transition::LossSuccessorRequest {
    transition::LossSuccessorRequest {
        id,
        ..successor_request(f)
    }
}

fn successor_request(f: &Fixture) -> transition::LossSuccessorRequest {
    transition::LossSuccessorRequest {
        format: 1,
        id: [60; 32],
        authority_id: f.loss.authority_id,
        revision: f.loss.revision + 1,
        install: f.loss.install.clone(),
        region: f.loss.region.clone(),
        scope: f.loss.scope,
        schema: f.loss.schema,
        membership: f.loss.replacement_membership,
        source_certificate: f.loss.source_certificate,
        source_token_digest: f.loss.source_token_digest,
        source_cut: f.loss.source_cut.clone(),
        parent_loss_certificate: f.loss_certificate_id,
        parent_loss_token_digest: f.loss_token_digest,
        survivor_cut: f.loss.survivor_cut.clone(),
        survivor_publication: f.loss.survivor_publication,
        // Role convention: participants[0] is the survivor (Primary in the new
        // membership), participants[1] is the replacement (Secondary).
        participants: [
            f.loss.survivor.clone(),
            transition::Participant {
                member: f.loss.replacement_member,
                generation: f.loss.replacement_generation,
                old_base: Some(f.loss.survivor_cut.clone()),
                target: f.loss.survivor_cut.clone(),
                plan: f.loss.survivor.plan,
                publication: f.loss.survivor_publication,
            },
        ],
    }
}

fn sign_successor(
    key: &EcdsaKeyPair,
    request: &transition::LossSuccessorRequest,
    trust: &transition::TrustStore,
) -> Result<String> {
    let header = B64.encode(serde_json::to_vec(&serde_json::json!({
        "alg": "ES256", "kid": "fixture", "typ": transition::LOSS_SUCCESSOR_TOKEN_TYPE
    }))?);
    let certificate_id = [61u8; 32];
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
    let token = sign_successor(&f.signer, &request, &f.trust)?;
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
    assert_eq!(record.format, 1);
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
    install_replacement(
        &mut replacement,
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )?;
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
    install_replacement(
        &mut replacement,
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )?;
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
    install_replacement(
        &mut replacement,
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )?;
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
            &self.f.certificate,
            &self.f.certificate_token,
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
        &certificate,
        &certificate_token,
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
    assert!(install_replacement(
        &mut replacement,
        &it.f.certificate,
        &it.f.certificate_token,
        &it.successor,
        &live,
    )
    .is_err());
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
    assert!(install_replacement(
        &mut empty,
        &it.f.certificate,
        &it.f.certificate_token,
        &it.successor,
        &live,
    )
    .is_err());
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
    assert!(install_replacement(
        &mut rotated,
        &it.f.certificate,
        &it.f.certificate_token,
        &it.successor,
        &live,
    )
    .is_err());
    assert_eq!(node_install_state(&rotated)?.0, None);
    drop(rotated);

    // A proof produced under a different loss never installs here.
    let other = fixture(Role::Secondary, false)?;
    let (_other_journal, other_proof) = successor_proof(&other, "successor-journal")?;
    assert_ne!(other_proof.loss_request(), &it.f.loss);
    assert!(install_replacement(
        &mut it.replacement,
        &it.f.certificate,
        &it.f.certificate_token,
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
        install_replacement(node, certificate, token, &it.successor, &live)
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
    install_replacement(
        &mut replacement,
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )?;
    assert_eq!(replacement.role(), Role::Primary);
    let (record, promoted_owner) = node_install_state(&replacement)?;
    let record = record.ok_or("replacement record missing")?;
    let demoted_owner = serde_json::to_string(&(&f.identity, Role::Secondary))?;
    drop(replacement);

    let retry = |role: Role| -> Result<()> {
        let mut node = f.open_replacement(role)?;
        install_replacement(
            &mut node,
            &f.certificate,
            &f.certificate_token,
            &successor,
            &live,
        )
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

const COMPLETION: [u8; 32] = [80; 32];

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
    assert!(complete_successor(&handle, &replacement, &successor, COMPLETION, &live).is_err());
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
    assert!(complete_successor(&handle, &replacement, &successor, COMPLETION, &live).is_err());
    assert_eq!(
        successor_journal
            .fetch_loss_successor(&successor, &f.trust.as_trust(), f.gate.as_ref())?
            .acknowledgements(),
        [false; 2]
    );

    install_replacement(
        &mut replacement,
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )?;
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

    // Complete at the authority. Exact retry converges, a different id does not.
    complete_successor(&handle, &replacement, &successor, COMPLETION, &live)?;
    complete_successor(&handle, &replacement, &successor, COMPLETION, &live)?;
    assert!(complete_successor(&handle, &replacement, &successor, [81; 32], &live).is_err());
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
    install_replacement(
        &mut replacement,
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )?;
    assert!(complete_successor(&handle, &replacement, &successor, COMPLETION, &live).is_err());
    handle.install_successor("fixture", &successor, &live)?;

    // Both installed: the acknowledgement is accepted.
    complete_successor(&handle, &replacement, &successor, COMPLETION, &live)?;
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
    assert!(complete_successor(&handle, &replacement, &other, [91; 32], &other_live).is_err());

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
    assert!(complete_successor(&handle, &replacement, &other, [91; 32], &other_live).is_err());
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
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )?;
    f.live
        .attach_successor(successor_journal_handle(&f, "successor-journal")?)?;
    complete_successor(&handle, &replacement, &successor, COMPLETION, &live)?;
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
        &f.certificate,
        &f.certificate_token,
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
        assert!(complete_successor(
            &handle_again,
            &replacement_again,
            &successor,
            COMPLETION,
            &live
        )
        .is_err());
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
    complete_successor(&handle, &replacement, &successor, COMPLETION, &live)?;
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
    completion: [u8; 32],
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
    install_replacement(
        &mut replacement,
        &f.certificate,
        &f.certificate_token,
        &f.successor,
        &live,
    )?;
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
    complete_successor(&handle, &replacement, &f.successor, f.completion, &live)?;
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
        completion: COMPLETION,
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
        let handle = world.handle()?;
        let replacement = world.replacement()?;
        assert!(
            complete_successor(
                &handle,
                &replacement,
                &world.fixture.successor,
                [98; 32],
                &world.authorities()
            )
            .is_err(),
            "conflicting completion accepted at step {step}"
        );
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

#[test]
fn crash_matrix_for_lost_primary_without_tail() -> Result<()> {
    crash_matrix(Role::Primary, false)
}

#[test]
fn crash_matrix_for_lost_primary_with_tail() -> Result<()> {
    crash_matrix(Role::Primary, true)
}

#[test]
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
        install_replacement(
            &mut untrusted,
            &f.certificate,
            &f.certificate_token,
            &successor,
            &live,
        ),
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
    assert!(install_replacement(
        &mut wrong,
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )
    .is_err());
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
    install_replacement(
        &mut replacement,
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )?;
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
    assert!(complete_successor(&handle, &rolled_back, &successor, COMPLETION, &live).is_err());
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
    install_replacement(
        &mut replacement,
        &f.certificate,
        &f.certificate_token,
        &successor,
        &live,
    )?;
    let journal_path = f.dir.path().join("successor-journal");
    let before_second_ack = f.dir.path().join("successor-journal-old");
    // Snapshot the authority before either acknowledgement.
    swap_database(&journal_path, &before_second_ack)?;
    complete_successor(&handle, &replacement, &successor, COMPLETION, &live)?;
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
