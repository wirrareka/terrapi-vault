use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use std::cell::Cell;
use terrapi_vesta_replication::{
    recovery::{
        decision::*,
        grant::{Context, Reservation},
        model::*,
    },
    Result,
};

struct Fixture {
    key: signature::EcdsaKeyPair,
    scope: Scope,
    request: Request,
    continuity: Cell<bool>,
    valid: Cell<bool>,
    prepared: Cell<bool>,
    applied: Cell<bool>,
}
impl Fixture {
    fn new() -> Self {
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
        let baseline = Baseline {
            scope: "eu/tenant/lineage".into(),
            revision: 4,
            digest: [4; 32],
            old_primary: [1; 32],
            survivor: [2; 32],
            survivor_generation: [3; 32],
            checkpoint: [9; 32],
        };
        let plan = Plan {
            recovery_id: [5; 32],
            baseline: baseline.clone(),
            revision: 5,
            candidate: [6; 32],
        };
        Self {
            key,
            scope: Scope {
                install: "installation".into(),
                region: "eu".into(),
                profile: terrapi_vesta_replication::recovery::grant::Profile {
                    issuer: "proximi-operator-recovery".into(),
                    audience: "proximi-recovery".into(),
                    token_type: "proximi-recovery+jwt".into(),
                },
                baseline,
            },
            request: Request {
                id: [10; 32],
                prepared: [
                    Prepared {
                        member: plan.candidate,
                        generation: [11; 32],
                        checkpoint: plan.baseline.checkpoint,
                    },
                    Prepared {
                        member: plan.baseline.survivor,
                        generation: plan.baseline.survivor_generation,
                        checkpoint: plan.baseline.checkpoint,
                    },
                ],
                plan,
            },
            continuity: Cell::new(true),
            valid: Cell::new(true),
            prepared: Cell::new(true),
            applied: Cell::new(true),
        }
    }
    fn token(&self) -> String {
        let h = serde_json::json!({"alg":"ES256","kid":"fixture","typ":"proximi-recovery+jwt"});
        let p = serde_json::json!({"version":1,"iss":"proximi-operator-recovery","aud":"proximi-recovery","action":"replace_primary","install_id":self.scope.install,"region":self.scope.region,"grant_id":([8;32]),"iat":100,"nbf":100,"exp":200,"plan":self.request.plan,"fencing_ref":([7;32])});
        let input = format!(
            "{}.{}",
            B64.encode(h.to_string()),
            B64.encode(p.to_string())
        );
        let signature = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", B64.encode(signature.as_ref()))
    }
    fn create(&self, dir: &std::path::Path) -> Journal {
        Journal::create(
            &dir.join("authority"),
            "unique-test-passphrase",
            self.scope.clone(),
        )
        .unwrap()
    }
}
impl Policy for Fixture {
    fn continuity(&self, _: &Scope) -> Result<()> {
        if self.continuity.get() {
            Ok(())
        } else {
            Err("fixture continuity unknown".into())
        }
    }
    fn context(&self, _: &Scope, _: &Request) -> Result<Context> {
        Ok(Context {
            profile: self.scope.profile.clone(),
            keys: vec![("fixture".into(), self.key.public_key().as_ref().to_vec())],
            now: if self.valid.get() { 150 } else { 200 },
            max_lifetime: 100,
            install_id: self.scope.install.clone(),
            region: self.scope.region.clone(),
            reservation: Some(Reservation {
                plan: self.request.plan.clone(),
                grant_id: [8; 32],
                fencing_ref: [7; 32],
            }),
            fencing_confirmed: true,
        })
    }
    fn prepared(&self, _: &Scope, _: &Request) -> Result<()> {
        if self.prepared.get() {
            Ok(())
        } else {
            Err("fixture not prepared".into())
        }
    }
    fn applied(&self, _: &Scope, _: &CommittedDecision, _: &Prepared) -> Result<()> {
        if self.applied.get() {
            Ok(())
        } else {
            Err("fixture not applied".into())
        }
    }
}

#[test]
fn encrypted_decision_reopens_and_completes_without_reissuing_expired_grant() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let j = f.create(dir.path());
    let token = f.token();
    j.decide(f.request.clone(), &token, &f).unwrap();
    let decision = j.fetch(&f.request, &f).unwrap();
    assert_eq!(decision.request(), &f.request);
    assert_eq!(decision.grant_id(), [8; 32]);
    assert_ne!(decision.token_digest(), [0; 32]);
    f.valid.set(false);
    j.decide(f.request.clone(), &token, &f).unwrap();
    assert!(j.complete(&f.request, [12; 32], &f).is_err());
    for member in &f.request.prepared {
        j.acknowledge(&decision, member, &f).unwrap();
    }
    drop(j);
    let j = Journal::open(
        &dir.path().join("authority"),
        "unique-test-passphrase",
        f.scope.clone(),
    )
    .unwrap();
    j.complete(&f.request, [12; 32], &f).unwrap();
    j.complete(&f.request, [12; 32], &f).unwrap();
    assert!(j.complete(&f.request, [13; 32], &f).is_err());
    assert!(j.fetch(&f.request, &f).is_err());
    assert_eq!(j.status().unwrap().completion, Some([12; 32]));
    let disk = std::fs::read(dir.path().join("authority")).unwrap();
    assert!(!disk
        .windows(token.len())
        .any(|bytes| bytes == token.as_bytes()));
}

#[test]
fn rejection_preserves_empty_journal_and_acknowledgement_state() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let j = f.create(dir.path());
    let token = f.token();
    let before = j.status().unwrap();
    for flag in [&f.continuity, &f.valid, &f.prepared] {
        flag.set(false);
        assert!(j.decide(f.request.clone(), &token, &f).is_err());
        flag.set(true);
        assert_eq!(j.status().unwrap(), before);
    }
    let mut wrong = f.request.clone();
    wrong.prepared[1].generation = [66; 32];
    assert!(j.decide(wrong, &token, &f).is_err());
    assert_eq!(j.status().unwrap(), before);
    j.decide(f.request.clone(), &token, &f).unwrap();
    let decision = j.fetch(&f.request, &f).unwrap();
    f.applied.set(false);
    assert!(j
        .acknowledge(&decision, &f.request.prepared[0], &f)
        .is_err());
    assert_eq!(j.status().unwrap().acknowledgements, [false; 2]);
    f.applied.set(true);
    f.continuity.set(false);
    assert!(j.fetch(&f.request, &f).is_err());
    assert!(j
        .acknowledge(&decision, &f.request.prepared[0], &f)
        .is_err());
    assert!(j.complete(&f.request, [12; 32], &f).is_err());
}

#[test]
fn conflict_and_wrong_credentials_do_not_replace_decision() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let j = f.create(dir.path());
    let token = f.token();
    j.decide(f.request.clone(), &token, &f).unwrap();
    let original = j.status().unwrap();
    let mut other = f.request.clone();
    other.id = [19; 32];
    assert!(j.decide(other, &token, &f).is_err());
    assert!(j.decide(f.request.clone(), &f.token(), &f).is_err());
    assert_eq!(j.status().unwrap(), original);
    assert!(Journal::open(&dir.path().join("missing"), "pass", f.scope.clone()).is_err());
    assert!(!dir.path().join("missing").exists());
    assert!(Journal::create(&dir.path().join("empty-pass"), "", f.scope.clone()).is_err());
    assert!(!dir.path().join("empty-pass").exists());
    drop(j);
    assert!(Journal::open(&dir.path().join("authority"), "wrong-pass", f.scope.clone()).is_err());
    let mut wrong = f.scope.clone();
    wrong.region = "uae".into();
    assert!(Journal::open(
        &dir.path().join("authority"),
        "unique-test-passphrase",
        wrong
    )
    .is_err());
}

struct LocalEvidence<'a> {
    fixture: &'a Fixture,
    nodes: [&'a terrapi_vesta_replication::Node; 2],
}
impl Policy for LocalEvidence<'_> {
    fn continuity(&self, scope: &Scope) -> Result<()> {
        self.fixture.continuity(scope)
    }
    fn context(&self, scope: &Scope, request: &Request) -> Result<Context> {
        self.fixture.context(scope, request)
    }
    fn prepared(&self, _: &Scope, request: &Request) -> Result<()> {
        for (node, member) in self.nodes.iter().zip(&request.prepared) {
            if node.inspect_recovery(&request.plan, member.member)? != *member {
                return Err("installation changed".into());
            }
        }
        Ok(())
    }
    fn applied(&self, _: &Scope, decision: &CommittedDecision, member: &Prepared) -> Result<()> {
        let index = decision
            .request()
            .prepared
            .iter()
            .position(|p| p == member)
            .ok_or("unknown member")?;
        self.nodes[index].verify_recovery_active(decision, member)
    }
}

#[test]
fn survivor_export_to_empty_candidate_preserves_receipts_and_records_real_delivery() {
    use terrapi_vesta_replication::{
        commit, recover, recovery::installation::*, Batch, Change, Identity, Node, Role,
    };
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity {
        cluster: "pair".into(),
        tenant: "tenant".into(),
        epoch: 1,
        schema: 1,
    };
    let mut primary = Node::open(
        dir.path().join("old-primary"),
        Role::Primary,
        identity.clone(),
        "data-pass",
    )
    .unwrap();
    let mut survivor = Node::open(
        dir.path().join("survivor"),
        Role::Secondary,
        identity.clone(),
        "data-pass",
    )
    .unwrap();
    assert!(survivor.recovery_export_manifest().is_err());
    let batch = Batch {
        identity: identity.clone(),
        operation_id: "preserved-request".into(),
        changes: vec![Change::PutPlace {
            id: "place".into(),
            name: "Before failure".into(),
        }],
    };
    commit(&mut primary, &mut survivor, batch.clone()).unwrap();
    recover(&mut primary, &mut survivor).unwrap();
    drop(primary); // Actual source export below uses only the survivor.
    let mut f = Fixture::new();
    f.scope.baseline.scope = data_scope(&identity).unwrap();
    f.scope.baseline.checkpoint = checkpoint_digest(&survivor).unwrap();
    f.scope.baseline.survivor_generation = survivor.status().unwrap().read_generation;
    #[cfg(feature = "experimental-recovery")]
    let credentials = recovery_credentials();
    #[cfg(feature = "experimental-recovery")]
    {
        use terrapi_vesta_replication::network::fingerprint;
        f.scope.baseline.old_primary = fingerprint(&credentials[2].certificate);
        f.scope.baseline.survivor = fingerprint(&credentials[1].certificate);
        f.request.plan.candidate = fingerprint(&credentials[0].certificate);
    }
    f.request.plan.baseline = f.scope.baseline.clone();
    assert!(survivor.recovery_export_manifest().is_err());
    survivor.seal_recovery_source(&f.request.plan).unwrap();
    survivor.seal_recovery_source(&f.request.plan).unwrap();
    assert!(survivor.abort("nonexistent").is_err());
    assert!(survivor.verified_view().unwrap().is_some());
    let manifest = survivor.recovery_export_manifest().unwrap();
    let mut candidate = Node::open(
        dir.path().join("candidate"),
        Role::Secondary,
        identity.clone(),
        "candidate-pass",
    )
    .unwrap();
    let mut progress = candidate.materialized_begin(manifest.clone()).unwrap();
    while progress.received < manifest.rows().unwrap() {
        let page = survivor
            .recovery_export_page(&manifest, progress.received)
            .unwrap();
        progress = candidate.materialized_chunk(progress.token, page).unwrap();
    }
    candidate.materialized_finish(progress.token).unwrap();
    assert_eq!(candidate.view().unwrap(), survivor.view().unwrap());
    assert_eq!(
        candidate.receipt(&batch.operation_id).unwrap(),
        survivor.receipt(&batch.operation_id).unwrap()
    );
    f.request.prepared = [
        candidate
            .inspect_recovery(&f.request.plan, f.request.plan.candidate)
            .unwrap(),
        survivor
            .inspect_recovery(&f.request.plan, f.request.plan.baseline.survivor)
            .unwrap(),
    ];
    let journal = f.create(dir.path());
    let policy = LocalEvidence {
        fixture: &f,
        nodes: [&candidate, &survivor],
    };
    journal
        .decide(f.request.clone(), &f.token(), &policy)
        .unwrap();
    let decision = journal.fetch(&f.request, &policy).unwrap();
    assert!(journal
        .acknowledge(&decision, &f.request.prepared[0], &policy)
        .is_err());
    candidate
        .record_recovery_decision(&decision, f.request.plan.candidate)
        .unwrap();
    survivor
        .record_recovery_decision(&decision, f.request.plan.baseline.survivor)
        .unwrap();
    drop(candidate);
    let mut candidate = Node::open(
        dir.path().join("candidate"),
        Role::Secondary,
        identity.clone(),
        "candidate-pass",
    )
    .unwrap();
    candidate
        .record_recovery_decision(&decision, f.request.plan.candidate)
        .unwrap();
    let policy = LocalEvidence {
        fixture: &f,
        nodes: [&candidate, &survivor],
    };
    assert!(journal
        .acknowledge(&decision, &f.request.prepared[0], &policy)
        .is_err());
    assert!(candidate.prepare(batch.clone()).is_err()); // Delivery is not activation.
    #[cfg(feature = "experimental-recovery")]
    {
        use terrapi_vesta_replication::recovery::activation::activate_pair;
        let raw =
            terrapi_vesta::Vesta::open(dir.path().join("candidate"), "candidate-pass").unwrap();
        let version = raw
            .with_connection(|c| {
                c.query_row(
                    "SELECT version FROM checkpoint_format WHERE id=1",
                    [],
                    |r| r.get::<_, u32>(0),
                )
            })
            .unwrap();
        assert_eq!(version, 2); // Pre-recovery binaries require exactly 1.
        raw.with_connection(|c| {c.execute_batch("CREATE TRIGGER reject_candidate_activation BEFORE UPDATE ON node_identity BEGIN SELECT RAISE(ABORT,'fixture activation interruption'); END;")?;Ok(())}).unwrap();
        assert!(activate_pair(&mut candidate, &mut survivor, &journal, &f.request, &f).is_err());
        assert!(candidate.summary().is_err());
        assert!(survivor.summary().unwrap().membership.is_some());
        assert!(candidate.prepare(batch.clone()).is_err());
        raw.with_connection(|c| {
            c.execute_batch("DROP TRIGGER reject_candidate_activation;")?;
            Ok(())
        })
        .unwrap();
        drop(raw);
        drop(candidate);
        drop(survivor);
        for before in [true, false] {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "foundation_activation_child", "--ignored"])
                .env("FOUNDATION_ACTIVATION_DIR", dir.path())
                .env(
                    "FOUNDATION_ACTIVATION_SCOPE",
                    serde_json::to_string(&f.scope).unwrap(),
                )
                .env(
                    "FOUNDATION_ACTIVATION_REQUEST",
                    serde_json::to_string(&f.request).unwrap(),
                )
                .env(
                    "FOUNDATION_ACTIVATION_IDENTITY",
                    serde_json::to_string(&identity).unwrap(),
                )
                .env(
                    "FOUNDATION_ACTIVATION_BEFORE",
                    if before { "1" } else { "0" },
                )
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert_eq!(result.code(), Some(if before { 84 } else { 83 }));
        }
        candidate = Node::open(
            dir.path().join("candidate"),
            Role::Primary,
            identity.clone(),
            "candidate-pass",
        )
        .unwrap();
        survivor = Node::open(
            dir.path().join("survivor"),
            Role::Secondary,
            identity.clone(),
            "data-pass",
        )
        .unwrap();
        activate_pair(&mut candidate, &mut survivor, &journal, &f.request, &f).unwrap();
        activate_pair(&mut candidate, &mut survivor, &journal, &f.request, &f).unwrap();
        let policy = LocalEvidence {
            fixture: &f,
            nodes: [&candidate, &survivor],
        };
        for member in &f.request.prepared {
            journal.acknowledge(&decision, member, &policy).unwrap();
        }
        journal.complete(&f.request, [12; 32], &policy).unwrap();
        assert_eq!(
            commit(&mut candidate, &mut survivor, batch.clone())
                .unwrap()
                .sequence,
            1
        );
        let mut next = batch.clone();
        next.operation_id = "after-replacement".into();
        next.changes = vec![Change::PutPlace {
            id: "new-place".into(),
            name: "After replacement".into(),
        }];
        assert_eq!(
            commit(&mut candidate, &mut survivor, next)
                .unwrap()
                .sequence,
            2
        );
        assert_eq!(candidate.view().unwrap(), survivor.view().unwrap());
        drop(candidate);
        candidate = Node::open(
            dir.path().join("candidate"),
            Role::Primary,
            identity.clone(),
            "candidate-pass",
        )
        .unwrap();
        assert_eq!(
            commit(&mut candidate, &mut survivor, batch.clone())
                .unwrap()
                .sequence,
            1
        );
        let mut old = Node::open(
            dir.path().join("old-primary"),
            Role::Primary,
            identity,
            "data-pass",
        )
        .unwrap();
        assert!(commit(&mut old, &mut survivor, batch.clone()).is_err());
        assert!(activate_pair(&mut candidate, &mut survivor, &journal, &f.request, &f).is_err());
        survivor = check_recovered_tls(&mut candidate, survivor, &credentials, &batch);
        // A quarantined surviving member invalidates the new pair's admission.
        survivor.quarantine().unwrap();
        assert!(commit(&mut candidate, &mut survivor, batch).is_err());
    }
    #[cfg(not(feature = "experimental-recovery"))]
    {
        candidate.quarantine().unwrap();
        assert!(candidate
            .record_recovery_decision(&decision, f.request.plan.candidate)
            .is_err());
        assert!(candidate
            .verify_recovery_decision(&decision, &f.request.prepared[0])
            .is_err());
        let cp = survivor.checkpoint().unwrap();
        drop(survivor);
        let record = serde_json::json!({"format":1,"request":f.request,"token_digest":decision.token_digest(),"grant_id":decision.grant_id(),"checkpoint":cp,"member":f.request.plan.baseline.survivor});
        let raw = terrapi_vesta::Vesta::open(dir.path().join("survivor"), "data-pass").unwrap();
        raw.with_connection(|c| {
            c.execute_batch("CREATE TABLE recovery_active(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL);")?;
            c.execute("INSERT INTO recovery_active VALUES(1,?1)",[record.to_string()])?;Ok(())
        }).unwrap();
        drop(raw);
        let failure = Node::open(
            dir.path().join("survivor"),
            Role::Secondary,
            identity,
            "data-pass",
        )
        .err()
        .expect("default build must reject recovered active DB");
        assert!(failure
            .to_string()
            .contains("requires experimental-recovery build"));
    }
}

#[cfg(feature = "experimental-recovery")]
#[test]
#[ignore = "explicit activation subprocess entry point"]
fn foundation_activation_child() {
    use terrapi_vesta_replication::{recovery::activation::activate_pair, Identity, Node, Role};
    let dir = std::path::PathBuf::from(std::env::var_os("FOUNDATION_ACTIVATION_DIR").unwrap());
    let mut f = Fixture::new();
    f.scope = serde_json::from_str(&std::env::var("FOUNDATION_ACTIVATION_SCOPE").unwrap()).unwrap();
    f.request =
        serde_json::from_str(&std::env::var("FOUNDATION_ACTIVATION_REQUEST").unwrap()).unwrap();
    let identity: Identity =
        serde_json::from_str(&std::env::var("FOUNDATION_ACTIVATION_IDENTITY").unwrap()).unwrap();
    let journal = Journal::open(
        &dir.join("authority"),
        "unique-test-passphrase",
        f.scope.clone(),
    )
    .unwrap();
    let mut candidate = Node::open(
        dir.join("candidate"),
        Role::Secondary,
        identity.clone(),
        "candidate-pass",
    )
    .unwrap();
    let mut survivor =
        Node::open(dir.join("survivor"), Role::Secondary, identity, "data-pass").unwrap();
    if std::env::var("FOUNDATION_ACTIVATION_BEFORE").unwrap() == "1" {
        std::process::exit(84)
    }
    activate_pair(&mut candidate, &mut survivor, &journal, &f.request, &f).unwrap();
    std::process::exit(83)
}

#[cfg(feature = "experimental-recovery")]
fn recovery_credentials() -> [terrapi_vesta_replication::network::Credentials; 3] {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair as RcKey};
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = RcKey::generate().unwrap();
    let ca = params.self_signed(&key).unwrap();
    ["candidate.test", "survivor.test", "old.test"].map(|name| {
        let leaf_key = RcKey::generate().unwrap();
        let cert = CertificateParams::new(vec![name.into()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &key)
            .unwrap();
        terrapi_vesta_replication::network::Credentials {
            certificate: cert.der().to_vec(),
            private_key: leaf_key.serialize_der(),
            ca: ca.der().to_vec(),
        }
    })
}

#[cfg(feature = "experimental-recovery")]
fn check_recovered_tls(
    candidate: &mut terrapi_vesta_replication::Node,
    mut survivor: terrapi_vesta_replication::Node,
    credentials: &[terrapi_vesta_replication::network::Credentials; 3],
    batch: &terrapi_vesta_replication::Batch,
) -> terrapi_vesta_replication::Node {
    use std::{
        net::TcpListener,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    use terrapi_vesta_replication::{commit, network::*, Change, Replica};
    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    for wrong_configuration in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = if wrong_configuration { 2 } else { 0 };
        let server_tls = ServerTls::new(
            &credentials[1],
            fingerprint(&credentials[client].certificate),
        )
        .unwrap();
        let tls = ClientTls::new(
            &credentials[client],
            "survivor.test",
            fingerprint(&credentials[1].certificate),
        )
        .unwrap();
        let mut peer =
            TlsReplica::new(address, tls, batch.identity.clone(), Duration::from_secs(2)).unwrap();
        let stop = AtomicBool::new(false);
        survivor = std::thread::scope(|threads| {
            let guard = Stop(&stop);
            let signal = &stop;
            let handle = threads.spawn(move || {
                serve(
                    &listener,
                    &mut survivor,
                    &server_tls,
                    Duration::from_secs(2),
                    signal,
                )
                .unwrap();
                survivor
            });
            if wrong_configuration {
                // TLS config explicitly permits the old certificate. Persisted
                // recovery membership must still reject it before any dispatch.
                assert!(peer.summary().is_err());
            } else {
                let old_tls = ClientTls::new(
                    &credentials[2],
                    "survivor.test",
                    fingerprint(&credentials[1].certificate),
                )
                .unwrap();
                let mut old = TlsReplica::new(
                    address,
                    old_tls,
                    batch.identity.clone(),
                    Duration::from_secs(2),
                )
                .unwrap();
                assert!(old.summary().is_err());
                let mut next = batch.clone();
                next.operation_id = "tls-after-replacement".into();
                next.changes = vec![Change::PutPlace {
                    id: "tls-place".into(),
                    name: "TLS replacement".into(),
                }];
                assert_eq!(commit(candidate, &mut peer, next).unwrap().sequence, 3);
                assert_eq!(
                    commit(candidate, &mut peer, batch.clone())
                        .unwrap()
                        .sequence,
                    1
                );
            }
            drop(guard);
            let survivor = handle.join().unwrap();
            assert!(commit(candidate, &mut peer, batch.clone()).is_err());
            survivor
        });
    }
    survivor
}

#[test]
fn two_operator_connections_commit_only_one_request() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let journal = f.create(dir.path());
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|threads| {
        let handles = [20u8, 21].map(|id| {
            let path = dir.path().join("authority");
            let barrier = &barrier;
            threads.spawn(move || {
                let mut f = Fixture::new();
                f.request.id = [id; 32];
                let j = Journal::open(&path, "unique-test-passphrase", f.scope.clone()).unwrap();
                let token = f.token();
                barrier.wait();
                j.decide(f.request.clone(), &token, &f).is_ok()
            })
        });
        handles.map(|handle| handle.join().unwrap())
    });
    assert_eq!(results.into_iter().filter(|ok| *ok).count(), 1);
    assert!(journal.status().unwrap().request.is_some());
}

#[test]
fn damaged_journal_is_rejected_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let journal = f.create(dir.path());
    journal.decide(f.request.clone(), &f.token(), &f).unwrap();
    drop(journal);
    let raw =
        terrapi_vesta::Vesta::open(dir.path().join("authority"), "unique-test-passphrase").unwrap();
    raw.with_connection(|c| {
        c.execute("UPDATE recovery_decision SET digest=zeroblob(32)", [])?;
        Ok(())
    })
    .unwrap();
    drop(raw);
    assert!(Journal::open(
        &dir.path().join("authority"),
        "unique-test-passphrase",
        f.scope.clone()
    )
    .is_err());
}

#[test]
fn process_exit_before_and_after_decision_and_completion_preserves_retry() {
    for completion in [false, true] {
        for before in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let f = Fixture::new();
            let journal = f.create(dir.path());
            let token = f.token();
            if completion {
                journal.decide(f.request.clone(), &token, &f).unwrap();
                let decision = journal.fetch(&f.request, &f).unwrap();
                for member in &f.request.prepared {
                    journal.acknowledge(&decision, member, &f).unwrap();
                }
            }
            drop(journal);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "foundation_crash_child", "--ignored"])
                .env("FOUNDATION_CRASH_DIR", dir.path())
                .env("FOUNDATION_CRASH_BEFORE", if before { "1" } else { "0" })
                .env(
                    "FOUNDATION_CRASH_COMPLETION",
                    if completion { "1" } else { "0" },
                )
                .env("FOUNDATION_FIXTURE_TOKEN", &token)
                .env(
                    "FOUNDATION_FIXTURE_PUBLIC",
                    B64.encode(f.key.public_key().as_ref()),
                )
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(if before { 81 } else { 82 }));
            let journal = Journal::open(
                &dir.path().join("authority"),
                "unique-test-passphrase",
                f.scope.clone(),
            )
            .unwrap();
            if completion {
                assert_eq!(
                    journal.status().unwrap().completion,
                    if before { None } else { Some([12; 32]) }
                );
                journal.complete(&f.request, [12; 32], &f).unwrap();
            } else {
                assert_eq!(journal.status().unwrap().request.is_some(), !before);
                journal.decide(f.request.clone(), &token, &f).unwrap();
            }
        }
    }
}

#[test]
#[ignore = "explicit fixture subprocess entry point"]
fn foundation_crash_child() {
    struct CrashPolicy {
        f: Fixture,
        public: Vec<u8>,
        before: bool,
        completion: bool,
    }
    impl Policy for CrashPolicy {
        fn continuity(&self, s: &Scope) -> Result<()> {
            if self.before && self.completion {
                std::process::exit(81)
            }
            self.f.continuity(s)
        }
        fn context(&self, s: &Scope, r: &Request) -> Result<Context> {
            let mut ctx = self.f.context(s, r)?;
            ctx.keys[0].1 = self.public.clone();
            Ok(ctx)
        }
        fn prepared(&self, s: &Scope, r: &Request) -> Result<()> {
            if self.before {
                std::process::exit(81)
            }
            self.f.prepared(s, r)
        }
        fn applied(&self, s: &Scope, d: &CommittedDecision, m: &Prepared) -> Result<()> {
            self.f.applied(s, d, m)
        }
    }
    let policy = CrashPolicy {
        f: Fixture::new(),
        public: B64
            .decode(std::env::var("FOUNDATION_FIXTURE_PUBLIC").unwrap())
            .unwrap(),
        before: std::env::var("FOUNDATION_CRASH_BEFORE").unwrap() == "1",
        completion: std::env::var("FOUNDATION_CRASH_COMPLETION").unwrap() == "1",
    };
    let path = std::path::PathBuf::from(std::env::var_os("FOUNDATION_CRASH_DIR").unwrap())
        .join("authority");
    let journal = Journal::open(&path, "unique-test-passphrase", policy.f.scope.clone()).unwrap();
    if policy.completion {
        journal
            .complete(&policy.f.request, [12; 32], &policy)
            .unwrap();
    } else {
        journal
            .decide(
                policy.f.request.clone(),
                &std::env::var("FOUNDATION_FIXTURE_TOKEN").unwrap(),
                &policy,
            )
            .unwrap();
    }
    std::process::exit(82)
}
