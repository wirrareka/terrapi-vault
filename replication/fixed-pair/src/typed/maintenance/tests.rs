use super::*;
use crate::envelope_tests::{stock_entry, StockSchema};

#[test]
fn planner_is_read_only_and_reports_pending_tail() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut batch = stock_entry().batch;
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert_eq!(p.plan_compaction()?.covered_journal_entries, 0);
    commit(&mut p, &mut s, batch.clone())?;
    let head = p.summary()?.head;
    let plan = p.plan_compaction()?;
    assert_eq!(plan.head, head);
    assert_eq!(plan.covered_journal_entries, 1);
    assert!(plan.covered_journal_bytes > 0);
    assert_eq!(plan.retained_receipts, 1);
    assert!(!plan.unresolved_tail);
    assert!(plan.publication.is_none());
    assert_eq!(p.summary()?.head, head);
    batch.operation_id = "pending".into();
    p.prepare(batch)?;
    let pending = p.plan_compaction()?;
    assert!(pending.unresolved_tail);
    assert_eq!(pending.checkpoint, plan.checkpoint);
    assert_eq!(pending.covered_journal_bytes, plan.covered_journal_bytes);
    Ok(())
}

#[test]
fn pins_survive_restart_block_rotation_and_release_by_exact_manifest() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let path = dir.path().join("p");
    let mut p = Node::open(
        &path,
        Role::Primary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        batch.identity.clone(),
        "fixture",
        StockSchema,
    )?;
    commit(&mut p, &mut s, batch.clone())?;
    let manifest = p.publish_snapshot()?;
    assert!(p.pin_snapshot(&manifest, "transfer-1").is_err());
    p.enable_maintenance()?;
    p.enable_maintenance()?;
    p.pin_snapshot(&manifest, "transfer-1")?;
    p.pin_snapshot(&manifest, "transfer-1")?;
    assert!(p.rotate_snapshot(&manifest).is_err());
    drop(p);
    let mut p = Node::open(&path, Role::Primary, batch.identity, "fixture", StockSchema)?;
    assert!(p.rotate_snapshot(&manifest).is_err());
    let mut wrong = manifest.clone();
    wrong.receipt_bytes += 1;
    assert!(p.release_snapshot_pin(&wrong, "transfer-1").is_err());
    p.release_snapshot_pin(&manifest, "transfer-1")?;
    p.release_snapshot_pin(&manifest, "transfer-1")?;
    assert_eq!(p.rotate_snapshot(&manifest)?, manifest);
    p.connection(|c| {
        let tx = c.unchecked_transaction()?;
        tx.execute("UPDATE node_runtime SET format=1", [])?;
        assert!(p.verify_owner(&tx).is_err());
        tx.rollback()?;
        Ok(())
    })?;
    Ok(())
}

#[test]
fn maintenance_upgrade_failure_is_atomic() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        batch.identity,
        "fixture",
        StockSchema,
    )?;
    p.connection(|c| {
        c.execute_batch("CREATE TRIGGER fail_upgrade BEFORE UPDATE ON node_runtime BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;
        Ok(())
    })?;
    assert!(p.enable_maintenance().is_err());
    p.connection(|c| {
        assert!(!present(c)?);
        p.verify_owner(c)?;
        c.execute_batch("DROP TRIGGER fail_upgrade")?;
        Ok(())
    })?;
    p.enable_maintenance()?;
    Ok(())
}

/// Shared fixture for the certified maintenance lifecycle and the
/// participant-loss flow: a recovered, maintenance-enabled pair with one
/// committed entry, a fresh publication on each node and a signed certified
/// request that has NOT yet been prepared.
#[cfg(feature = "experimental-recovery")]
pub(super) mod support {
    use super::*;
    use crate::recovery::transition;
    use crate::typed::maintenance::certified;
    use crate::typed::recovery::tests::recovered_pair_for_pending;
    use ring::signature::EcdsaKeyPair;
    use sha2::{Digest, Sha256};

    pub(crate) struct CertifiedPair {
        pub dir: tempfile::TempDir,
        pub p: Node<StockSchema>,
        pub s: Node<StockSchema>,
        pub plan: compaction::PairPlan,
        pub request: transition::Request,
        pub token: String,
        pub trust: transition::TrustStore,
        pub key: EcdsaKeyPair,
    }

    pub(crate) fn digest_of<T: Serialize>(value: &T) -> Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(value)?).into())
    }

    pub(crate) fn cut(prefix: &Prefix) -> Result<transition::Checkpoint> {
        Ok(transition::Checkpoint {
            sequence: prefix.sequence,
            digest: digest_of(prefix)?,
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
            plan: digest_of(plan)?,
            publication: digest_of(
                local
                    .publication
                    .as_ref()
                    .ok_or("fixture publication missing")?,
            )?,
        })
    }

    /// A second certified request against the same pair, chained to the one it
    /// follows. `Journal::chain` requires every participant's `old_base` to be
    /// the previous request's primary target, the same member/generation pair
    /// and the scope's original anchor, so all of that is derived here rather
    /// than restated by callers.
    pub(crate) fn next_request(
        p: &mut Node<StockSchema>,
        s: &mut Node<StockSchema>,
        previous: &transition::Request,
        plan_id: [u8; 32],
        request_id: [u8; 32],
    ) -> Result<(compaction::PairPlan, transition::Request)> {
        let plan = compaction::PairPlan {
            id: plan_id,
            primary: p.plan_compaction()?,
            secondary: s.plan_compaction()?,
        };
        plan.validate_certified()?;
        let old_base = Some(previous.participants[0].target.clone());
        let mut participants = [
            participant(p, &plan.primary, &plan)?,
            participant(s, &plan.secondary, &plan)?,
        ];
        for (next, before) in participants.iter_mut().zip(&previous.participants) {
            next.old_base = old_base.clone();
            ensure(
                next.member == before.member && next.generation == before.generation,
                "fixture membership drifted between requests",
            )?;
        }
        let request = transition::Request {
            format: 1,
            id: request_id,
            authority_id: previous.authority_id,
            revision: previous.revision + 1,
            install: previous.install.clone(),
            region: previous.region.clone(),
            scope: previous.scope,
            schema: previous.schema,
            membership: previous.membership,
            source_anchor: previous.source_anchor.clone(),
            participants,
        };
        request.validate()?;
        Ok((plan, request))
    }

    /// Build the pair and sign the request. `seed` names the single committed
    /// operation so callers can keep their fixtures distinguishable.
    pub(crate) fn certified_pair(seed: &str, id: [u8; 32], install: &str) -> Result<CertifiedPair> {
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
        batch.operation_id = seed.into();
        commit(&mut p, &mut s, batch)?;
        p.rotate_snapshot(&old_p)?;
        s.rotate_snapshot(&old_s)?;
        let plan = compaction::PairPlan {
            id,
            primary: p.plan_compaction()?,
            secondary: s.plan_compaction()?,
        };
        plan.validate_certified()?;
        let request = transition::Request {
            format: 1,
            id: [42; 32],
            authority_id: [43; 32],
            revision: 1,
            install: install.into(),
            region: "test".into(),
            scope: digest_of(p.identity())?,
            schema: digest_of(&plan.primary.contract)?,
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
        let token = certified::tests::sign(&key, &request)?;
        let trust = transition::TrustStore {
            profile: crate::recovery::grant::Profile {
                issuer: "issuer".into(),
                audience: "audience".into(),
                token_type: transition::TOKEN_TYPE.into(),
            },
            keys: vec![("fixture".into(), public)],
            max_lifetime: 20,
        };
        Ok(CertifiedPair {
            dir,
            p,
            s,
            plan,
            request,
            token,
            trust,
            key,
        })
    }

    /// Sign a maintenance abort for `request`, in the same claim shape the
    /// recovery crate's own abort tests use.
    pub(crate) fn abort_of(
        request: &transition::Request,
        id: u8,
        decided: bool,
        revision: u64,
    ) -> Result<transition::MaintenanceAbort> {
        Ok(transition::MaintenanceAbort {
            format: 2,
            id: [id; 32],
            authority_id: request.authority_id,
            revision,
            install: request.install.clone(),
            region: request.region.clone(),
            scope: request.scope,
            schema: request.schema,
            membership: request.membership,
            aborted_request: request.digest()?,
            aborted_request_id: request.id,
            aborted_revision: request.revision,
            decided,
            source_anchor: request.source_anchor.clone(),
        })
    }

    pub(crate) fn sign_abort(
        key: &EcdsaKeyPair,
        abort: &transition::MaintenanceAbort,
        window: (u64, u64),
    ) -> Result<String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
        use ring::rand::SystemRandom;
        let header = B64.encode(serde_json::to_vec(&serde_json::json!({
            "alg": "ES256", "kid": "fixture", "typ": transition::ABORT_TOKEN_TYPE
        }))?);
        let certificate_id = [77u8; 32];
        let claims = B64.encode(serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "iss": "issuer",
            "aud": "audience",
            "action": "abort_compact_pair",
            "certificate_id": certificate_id,
            "iat": window.0, "nbf": window.0, "exp": window.1,
            "request": abort,
            "request_digest": abort.digest()?,
        }))?);
        let input = format!("{header}.{claims}");
        let signature = key
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|_| "abort token signing")?;
        Ok(format!("{input}.{}", B64.encode(signature.as_ref())))
    }

    /// Journal scope for the signed request above.
    pub(crate) fn journal_scope(request: &transition::Request) -> transition::JournalScope {
        transition::JournalScope {
            install: request.install.clone(),
            region: request.region.clone(),
            profile: crate::recovery::grant::Profile {
                issuer: "issuer".into(),
                audience: "audience".into(),
                token_type: transition::TOKEN_TYPE.into(),
            },
            scope: request.scope,
            schema: request.schema,
            membership: request.membership,
            source_anchor: request.source_anchor.clone(),
            authority_id: request.authority_id,
            initial_revision: request.revision,
        }
    }
}
