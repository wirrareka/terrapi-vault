use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use std::cell::Cell;
use terrapi_vesta_recovery::{
    decision::*,
    grant::{Context, Reservation},
    model::*,
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
                profile: terrapi_vesta_recovery::grant::Profile {
                    issuer: "example-operator-recovery".into(),
                    audience: "example-recovery".into(),
                    token_type: "example-recovery+jwt".into(),
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
        let h = serde_json::json!({"alg":"ES256","kid":"fixture","typ":"example-recovery+jwt"});
        let p = serde_json::json!({"version":1,"iss":"example-operator-recovery","aud":"example-recovery","action":"replace_primary","install_id":self.scope.install,"region":self.scope.region,"grant_id":([8;32]),"iat":100,"nbf":100,"exp":200,"plan":self.request.plan,"fencing_ref":([7;32])});
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

#[test]
fn configured_profile_is_exact_and_never_inferred_from_token() {
    let f = Fixture::new();
    let token = f.token();
    let context = f.context(&f.scope, &f.request).unwrap();
    assert!(terrapi_vesta_recovery::grant::verify(&token, &context).is_ok());
    for field in 0..3 {
        for value in [String::new(), "other-application".into(), "x".repeat(513)] {
            let mut context = f.context(&f.scope, &f.request).unwrap();
            match field {
                0 => context.profile.issuer = value,
                1 => context.profile.audience = value,
                _ => context.profile.token_type = value,
            }
            assert!(terrapi_vesta_recovery::grant::verify(&token, &context).is_err());
            let unsigned = token.rsplit_once('.').unwrap().0;
            assert!(terrapi_vesta_recovery::grant::validate_draft(unsigned, &context).is_err());
        }
    }
}

#[test]
fn journal_trust_profile_is_bound_before_decision_and_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let mut f = Fixture::new();
    let journal = f.create(dir.path());
    let original = f.scope.clone();
    f.scope.profile.audience = "other-application".into();
    assert!(journal.decide(f.request.clone(), &f.token(), &f).is_err());
    assert!(journal.status().unwrap().request.is_none());
    drop(journal);
    assert!(Journal::open(
        &dir.path().join("authority"),
        "unique-test-passphrase",
        f.scope.clone()
    )
    .is_err());
    let journal = Journal::open(
        &dir.path().join("authority"),
        "unique-test-passphrase",
        original.clone(),
    )
    .unwrap();
    f.scope = original;
    journal.decide(f.request.clone(), &f.token(), &f).unwrap();
}

#[test]
fn legacy_control_format_and_empty_profile_are_not_silently_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut invalid = f.scope.clone();
    invalid.profile.issuer.clear();
    assert!(Journal::create(&dir.path().join("invalid"), "fixture-pass", invalid).is_err());
    assert!(!dir.path().join("invalid").exists());
    drop(f.create(dir.path()));
    let raw =
        terrapi_vesta::Vesta::open(dir.path().join("authority"), "unique-test-passphrase").unwrap();
    raw.with_connection(|c| {
        c.execute("UPDATE recovery_decision_scope SET format=1", [])?;
        Ok(())
    })
    .unwrap();
    drop(raw);
    assert!(Journal::open(
        &dir.path().join("authority"),
        "unique-test-passphrase",
        f.scope
    )
    .is_err());
}
