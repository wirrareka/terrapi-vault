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

/// Live certified authority needed to reopen the nodes after finalization.
struct Live {
    journal: Mutex<transition::Journal>,
    trust: transition::TrustStore,
    gate: Arc<Gate>,
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
        Node::open(
            &self.replacement_path,
            Role::Secondary,
            self.identity.clone(),
            "fixture",
            StockSchema,
        )
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
        handle.manifest(&f.journal, &f.trust, f.gate.as_ref())?,
        f.survivor_manifest
    );
    assert!(handle
        .page(
            f.survivor_manifest.pages,
            &f.journal,
            &f.trust,
            f.gate.as_ref()
        )
        .is_err());
    assert!(handle
        .page(u64::MAX, &f.journal, &f.trust, f.gate.as_ref())
        .is_err());
    // Every page of the loss-bound publication is exportable for either role.
    for position in 0..f.survivor_manifest.pages {
        assert_eq!(
            handle
                .page(position, &f.journal, &f.trust, f.gate.as_ref())?
                .position,
            position
        );
    }
    assert!(f.survivor_manifest.pages > 0);

    let mut replacement = f.replacement()?;
    let checkpoint = bootstrap_replacement(
        &handle,
        &mut replacement,
        &f.journal,
        &f.trust,
        f.gate.as_ref(),
    )?;
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
        bootstrap_replacement(
            &handle,
            &mut replacement,
            &f.journal,
            &f.trust,
            f.gate.as_ref()
        )?,
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
    assert!(f.derive_role_at(&lost, &f.loss).is_err());
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
    assert!(f.derive_role_at(&survivor, &swapped).is_err());

    let mut wrong_survivor_generation = f.loss.clone();
    wrong_survivor_generation.survivor.generation = [51; 32];
    assert!(f
        .derive_role_at(&survivor, &wrong_survivor_generation)
        .is_err());

    let mut wrong_lost_generation = f.loss.clone();
    wrong_lost_generation.lost_generation = [52; 32];
    assert!(f.derive_role_at(&survivor, &wrong_lost_generation).is_err());

    let mut unknown_lost = f.loss.clone();
    unknown_lost.lost_member = [53; 32];
    assert!(f.derive_role_at(&survivor, &unknown_lost).is_err());

    let mut unknown_survivor = f.loss.clone();
    unknown_survivor.survivor.member = [54; 32];
    assert!(f.derive_role_at(&survivor, &unknown_survivor).is_err());

    let mut reused_membership = f.loss.clone();
    reused_membership.replacement_membership = f.loss.membership;
    assert!(f.derive_role_at(&survivor, &reused_membership).is_err());

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
    assert!(f.survivor_handle().is_err());
    f.gate.allow();
    let handle = f.survivor_handle()?;
    let pages = handle
        .manifest(&f.journal, &f.trust, f.gate.as_ref())?
        .pages;
    assert!(pages > 0);

    // Revoked between pages: the manifest call passes, the first page does not.
    // The partial transfer leaves staged pages but no completed restore.
    let mut replacement = f.replacement()?;
    f.gate.revoke_after(1);
    assert!(bootstrap_replacement(
        &handle,
        &mut replacement,
        &f.journal,
        &f.trust,
        f.gate.as_ref()
    )
    .is_err());
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
    assert!(bootstrap_replacement(
        &handle,
        &mut replacement,
        &f.journal,
        &f.trust,
        f.gate.as_ref()
    )
    .is_err());
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
    let checkpoint = bootstrap_replacement(
        &handle,
        &mut replacement,
        &f.journal,
        &f.trust,
        f.gate.as_ref(),
    )?;
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
    let request = successor_request(f);
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
        let checkpoint = bootstrap_replacement(
            &handle,
            &mut replacement,
            &f.journal,
            &f.trust,
            f.gate.as_ref(),
        )?;
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
        validate_successor_installation(
            handle,
            replacement,
            proof,
            &f.journal,
            &f.trust,
            f.gate.as_ref(),
        )?;
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
        let manifest = handle.manifest(&f.journal, &f.trust, f.gate.as_ref())?;
        rotated.begin_snapshot(&manifest)?;
        for position in 0..manifest.pages {
            rotated.receive_snapshot(&handle.page(
                position,
                &f.journal,
                &f.trust,
                f.gate.as_ref(),
            )?)?;
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
            &f.trust,
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
            &f.trust,
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
            &f.trust,
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
            &f.trust,
            f.gate.as_ref()
        )
        .is_err());
        f.gate.allow();
        validate_successor_installation(
            handle,
            replacement,
            proof,
            &f.journal,
            &f.trust,
            f.gate.as_ref(),
        )?;
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
    assert!(bootstrap_replacement(
        &handle,
        &mut wrong_role,
        &f.journal,
        &f.trust,
        f.gate.as_ref()
    )
    .is_err());
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
    assert!(bootstrap_replacement(
        &handle,
        &mut wrong_generation,
        &f.journal,
        &f.trust,
        f.gate.as_ref()
    )
    .is_err());
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
    assert!(
        bootstrap_replacement(&handle, &mut os, &f.journal, &f.trust, f.gate.as_ref()).is_err()
    );
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
    assert!(
        bootstrap_replacement(&handle, &mut foreign, &f.journal, &f.trust, f.gate.as_ref())
            .is_err()
    );
    drop(foreign);
    drop(os);
    drop(wrong_generation);
    drop(handle);
    drop(f);
    Ok(())
}
