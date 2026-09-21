use super::*;
use crate::envelope_tests::{stock_entry, StockSchema};
use crate::recovery::{
    decision::Scope,
    grant::{Context, Profile, Reservation},
    model::Baseline,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use std::cell::Cell;
mod cycles;
pub(crate) use cycles::recovered_pair_for_pending;

#[test]
fn active_publication_requires_unchanged_complete_recovery_evidence() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (mut p, mut s) = recovered_pair_for_pending(dir.path())?;
    p.enable_maintenance()?;
    s.enable_maintenance()?;
    let old = p
        .plan_compaction()?
        .publication
        .ok_or("publication missing")?;
    let mut batch = stock_entry().batch;
    batch.operation_id = "active-publication".into();
    commit(&mut p, &mut s, batch)?;
    assert_eq!(p.publish_recovery_snapshot()?, old);
    p.connection(|c| {
        c.execute("UPDATE recovery_completion SET receipt='{}' WHERE id=1", [])?;
        Ok(())
    })?;
    assert!(p.rotate_snapshot(&old).is_err());
    assert!(p.publish_recovery_snapshot().is_err());
    assert!(p.plan_compaction().is_err());
    p.connection(|c| {
        let stored: String = c.query_row(
            "SELECT manifest FROM node_publication WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure(
            snapshot::Manifest::decode(stored.as_bytes())? == old,
            "failed rotation changed publication",
        )
    })?;
    Ok(())
}

// Explicit test authority only. Production policies must prove fencing and
// continuity. The data bridge independently checks the actual Node files.
struct Authority {
    key: signature::EcdsaKeyPair,
    scope: Scope,
    request: DecisionRequest,
    allowed: Cell<bool>,
}
impl Authority {
    fn new(request: DecisionRequest) -> Self {
        let rng = SystemRandom::new();
        let pk = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pk.as_ref(),
            &rng,
        )
        .unwrap();
        Self {
            key,
            scope: Scope {
                install: "typed-test".into(),
                region: "test".into(),
                profile: Profile {
                    issuer: "fixture-authority".into(),
                    audience: "fixture-recovery".into(),
                    token_type: "fixture-recovery+jwt".into(),
                },
                baseline: request.plan.baseline.clone(),
            },
            request,
            allowed: Cell::new(true),
        }
    }
    fn token(&self) -> String {
        let header =
            serde_json::json!({"alg":"ES256","kid":"fixture","typ":self.scope.profile.token_type});
        let claims = serde_json::json!({"version":1,"iss":self.scope.profile.issuer,"aud":self.scope.profile.audience,"action":"replace_primary","install_id":self.scope.install,"region":self.scope.region,"grant_id":([8;32]),"iat":100,"nbf":100,"exp":200,"plan":self.request.plan,"fencing_ref":([7;32])});
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        format!(
            "{input}.{}",
            B64.encode(
                self.key
                    .sign(&SystemRandom::new(), input.as_bytes())
                    .unwrap()
                    .as_ref()
            )
        )
    }
}
impl Policy for Authority {
    fn continuity(&self, _: &Scope) -> Result<()> {
        ensure(self.allowed.get(), "test continuity denied")
    }
    fn context(&self, _: &Scope, request: &DecisionRequest) -> Result<Context> {
        ensure(request == &self.request, "test request mismatch")?;
        Ok(Context {
            profile: self.scope.profile.clone(),
            keys: vec![("fixture".into(), self.key.public_key().as_ref().to_vec())],
            now: 150,
            max_lifetime: 100,
            install_id: self.scope.install.clone(),
            region: self.scope.region.clone(),
            reservation: Some(Reservation {
                plan: request.plan.clone(),
                grant_id: [8; 32],
                fencing_ref: [7; 32],
            }),
            fencing_confirmed: self.allowed.get(),
        })
    }
    fn prepared(&self, _: &Scope, request: &DecisionRequest) -> Result<()> {
        ensure(
            request == &self.request && self.allowed.get(),
            "test preparation denied",
        )
    }
    fn applied(&self, _: &Scope, decision: &CommittedDecision, member: &Prepared) -> Result<()> {
        ensure(
            decision.request() == &self.request
                && self.request.prepared.contains(member)
                && self.allowed.get(),
            "test acknowledgement denied",
        )
    }
}

#[test]
#[ignore = "subprocess fixture; invoked by the replacement parent test"]
fn typed_replacement_crash_child() -> Result<()> {
    let path = std::path::PathBuf::from(
        std::env::var_os("VESTA_TYPED_CRASH_FIXTURE").ok_or("parent fixture required")?,
    );
    let batch = stock_entry().batch;
    let id = batch.identity.clone();
    let mut p = Node::open(
        path.join("old-primary"),
        Role::Primary,
        id.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = Node::open(
        path.join("survivor"),
        Role::Secondary,
        id,
        "fixture",
        StockSchema,
    )?;
    recover(&mut p, &mut s)?;
    let prepared = p.prepare(batch)?;
    s.stage(prepared.clone())?;
    let decided = p.decide(&prepared.batch.operation_id)?;
    s.apply(decided)?;
    // No destructors, no primary apply and no success response to the caller.
    // This is a test-binary entry point, never a product runtime crash switch.
    std::process::exit(73)
}

#[test]
fn typed_replacement_requires_authority_both_acks_completion_and_survives_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let id = batch.identity.clone();
    let ppath = dir.path().join("old-primary");
    let spath = dir.path().join("survivor");
    let cpath = dir.path().join("candidate");
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "typed::recovery::tests::typed_replacement_crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("VESTA_TYPED_CRASH_FIXTURE", dir.path())
        .status()?;
    ensure(
        status.code() == Some(73),
        "typed crash fixture did not reach durable boundary",
    )?;
    let mut p = Node::open(&ppath, Role::Primary, id.clone(), "fixture", StockSchema)?;
    let mut s = Node::open(&spath, Role::Secondary, id.clone(), "fixture", StockSchema)?;
    assert_eq!(p.status()?.entries[0].state, State::Decided);
    assert_eq!(s.status()?.entries[0].state, State::Applied);
    assert!(p.view()?.is_empty());
    let head = s.journal_head()?;
    let (client_tls, server_tls, candidate_pin, survivor_pin) =
        crate::network::tests::tls_with_pins();
    let plan = Plan {
        recovery_id: [5; 32],
        revision: 5,
        candidate: candidate_pin,
        baseline: Baseline {
            scope: serde_json::to_string(&id)?,
            revision: 4,
            digest: [4; 32],
            old_primary: [1; 32],
            survivor: survivor_pin,
            survivor_generation: head.read_generation,
            checkpoint: s.recovery_checkpoint_digest()?,
        },
    };
    s.seal_recovery_source(&plan)?;
    assert!(commit(&mut p, &mut s, batch.clone()).is_err());
    assert!(s.summary().is_err());
    assert!(s.publish_snapshot().is_err());
    let snapshot = s.publish_recovery_snapshot()?;
    let mut c = Node::open(&cpath, Role::Secondary, id.clone(), "fixture", StockSchema)?;
    c.begin_snapshot(&snapshot)?;
    for n in 0..snapshot.pages {
        c.receive_snapshot(&s.snapshot_page(&snapshot, n)?)?;
    }
    c.finish_snapshot(&snapshot)?;
    let request = DecisionRequest {
        id: [10; 32],
        prepared: [
            c.inspect_recovery(&plan, plan.candidate)?,
            s.inspect_recovery(&plan, plan.baseline.survivor)?,
        ],
        plan,
    };
    let authority = Authority::new(request.clone());
    let journal_path = dir.path().join("authority");
    let journal = Journal::create(&journal_path, "fixture", authority.scope.clone())?;
    authority.allowed.set(false);
    assert!(journal
        .decide(request.clone(), &authority.token(), &authority)
        .is_err());
    authority.allowed.set(true);
    journal.decide(request.clone(), &authority.token(), &authority)?;
    let decision = journal.fetch(&request, &authority)?;
    assert!(activate_pair(&mut c, &mut s, &journal, &request, &authority).is_err());
    for (node, member) in [
        (&mut c, request.prepared[0].member),
        (&mut s, request.prepared[1].member),
    ] {
        node.record_recovery_decision(&decision, member)?;
    }
    // Inject a failure inside the candidate role transaction after the survivor
    // has activated. Neither its role nor its receipt may partially change.
    c.connection(|db| {db.execute_batch("CREATE TRIGGER node_test_activation_fault AFTER UPDATE ON node_identity BEGIN DELETE FROM recovery_delivery; END;")?;Ok(())})?;
    assert!(activate_pair(&mut c, &mut s, &journal, &request, &authority).is_err());
    assert_eq!(c.role(), Role::Secondary);
    c.verify_recovery_decision(&decision, &request.prepared[0])?;
    assert!(c.checkpoint().is_err());
    assert!(s.checkpoint().is_err());
    c.connection(|db| {
        db.execute_batch("DROP TRIGGER node_test_activation_fault")?;
        Ok(())
    })?;
    drop(c);
    drop(s);
    let mut c = Node::open(&cpath, Role::Secondary, id.clone(), "fixture", StockSchema)?;
    let mut s = Node::open(&spath, Role::Secondary, id.clone(), "fixture", StockSchema)?;
    activate_pair(&mut c, &mut s, &journal, &request, &authority)?;
    assert_eq!(c.role(), Role::Primary);
    assert!(c.checkpoint().is_err());
    assert!(s.summary().is_err());
    assert!(commit(&mut c, &mut s, batch.clone()).is_err());
    authority.allowed.set(false);
    assert!(complete_pair(&mut c, &mut s, &journal, &request, [12; 32], &authority).is_err());
    assert!(c.checkpoint().is_err());
    authority.allowed.set(true);
    complete_pair(&mut c, &mut s, &journal, &request, [12; 32], &authority)?;
    complete_pair(&mut c, &mut s, &journal, &request, [12; 32], &authority)?;
    assert_eq!(journal.status()?.acknowledgements, [true, true]);
    assert_eq!(journal.status()?.completion, Some([12; 32]));
    assert!(complete_pair(&mut c, &mut s, &journal, &request, [13; 32], &authority).is_err());
    assert_eq!(
        c.required_recovery_peer()?,
        Some(request.plan.baseline.survivor)
    );
    assert_eq!(s.required_recovery_peer()?, Some(request.plan.candidate));
    assert!(recover(&mut p, &mut s).is_err());
    drop(c);
    drop(s);
    drop(journal);
    let mut c = Node::open(&cpath, Role::Primary, id.clone(), "fixture", StockSchema)?;
    let mut s = Node::open(&spath, Role::Secondary, id, "fixture", StockSchema)?;
    assert_eq!(commit(&mut c, &mut s, batch.clone())?.sequence, 1);
    let mut next = batch;
    next.operation_id = "after-recovery".into();
    assert_eq!(commit(&mut c, &mut s, next.clone())?.sequence, 2);
    assert_eq!(commit(&mut c, &mut s, next)?.sequence, 2);
    assert_eq!(c.checkpoint()?, s.checkpoint()?);
    use std::{
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let handle = std::thread::spawn(move || {
        crate::network::typed::serve(
            &listener,
            &mut s,
            &server_tls,
            Duration::from_secs(5),
            &shutdown,
        )
        .unwrap();
        s
    });
    let result = (|| -> Result<()> {
        let mut peer = crate::network::typed::TlsReplica::new(
            address,
            client_tls,
            c.identity.clone(),
            Duration::from_secs(5),
            &StockSchema,
        )?;
        let mut request = stock_entry().batch;
        request.operation_id = "network-after-replacement".into();
        assert_eq!(commit(&mut c, &mut peer, request.clone())?.sequence, 3);
        assert_eq!(commit(&mut c, &mut peer, request)?.sequence, 3);
        Ok(())
    })();
    stop.store(true, Ordering::SeqCst);
    let s = handle.join().map_err(|_| "recovered TLS server panicked")?;
    result?;
    assert_eq!(c.checkpoint()?, s.checkpoint()?);
    Ok(())
}
