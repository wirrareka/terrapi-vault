use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde_json::json;
use terrapi_vesta_recovery::{
    grant::Profile,
    transition::{
        verify_historical, verify_issuance, Checkpoint, CommittedTransition, Journal, JournalScope,
        Participant, Policy, Request, TrustStore, TOKEN_TYPE,
    },
    Result,
};

const PASSPHRASE: &str = "transition-key-rotation-fixture";

fn signer() -> signature::EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
    signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap()
}

fn profile() -> Profile {
    Profile {
        issuer: "transition-authority-fixture".into(),
        audience: "transition-journal-fixture".into(),
        token_type: TOKEN_TYPE.into(),
    }
}

fn request(revision: u64, old_base: Option<Checkpoint>) -> Request {
    let target = Checkpoint {
        sequence: revision * 10 + 10,
        digest: [revision as u8 + 20; 32],
    };
    Request {
        format: 1,
        id: [revision as u8; 32],
        authority_id: [90; 32],
        revision,
        install: "transition-rotation-install".into(),
        region: "eu".into(),
        scope: [2; 32],
        schema: [3; 32],
        membership: [4; 32],
        source_anchor: Checkpoint {
            sequence: 10,
            digest: [10; 32],
        },
        participants: [
            Participant {
                member: [5; 32],
                generation: [6; 32],
                old_base: old_base.clone(),
                target: target.clone(),
                plan: [revision as u8 + 30; 32],
                publication: [revision as u8 + 40; 32],
            },
            Participant {
                member: [7; 32],
                generation: [8; 32],
                old_base,
                target,
                plan: [revision as u8 + 30; 32],
                publication: [revision as u8 + 50; 32],
            },
        ],
    }
}

fn token(
    signer: &signature::EcdsaKeyPair,
    kid: &str,
    profile: &Profile,
    request: &Request,
    certificate_id: [u8; 32],
    issued: u64,
) -> String {
    let header = json!({"alg":"ES256","kid":kid,"typ":TOKEN_TYPE});
    let claims = json!({
        "version": 1,
        "iss": profile.issuer,
        "aud": profile.audience,
        "action": "compact_pair",
        "certificate_id": certificate_id,
        "iat": issued,
        "nbf": issued,
        "exp": issued + 100,
        "request": request,
        "request_digest": request.digest().unwrap()
    });
    let signing_input = format!(
        "{}.{}",
        B64.encode(header.to_string()),
        B64.encode(claims.to_string())
    );
    let signature = signer
        .sign(&SystemRandom::new(), signing_input.as_bytes())
        .unwrap();
    format!("{signing_input}.{}", B64.encode(signature.as_ref()))
}

fn scope(profile: &Profile, request: &Request) -> JournalScope {
    JournalScope {
        install: request.install.clone(),
        region: request.region.clone(),
        profile: profile.clone(),
        scope: request.scope,
        schema: request.schema,
        membership: request.membership,
        source_anchor: request.source_anchor.clone(),
        authority_id: request.authority_id,
        initial_revision: request.revision,
    }
}

struct SimulatedAuthority;

impl Policy for SimulatedAuthority {
    fn continuity(&self, scope: &JournalScope, request: &Request) -> Result<()> {
        if scope.authority_id == request.authority_id {
            Ok(())
        } else {
            Err("simulated authority continuity mismatch".into())
        }
    }

    fn prepared(&self, _: &JournalScope, _: &Request, _: &Participant) -> Result<()> {
        Ok(())
    }

    fn applied(&self, _: &JournalScope, _: &CommittedTransition, _: &Participant) -> Result<()> {
        Ok(())
    }

    fn historical_completion(
        &self,
        scope: &JournalScope,
        historical: &Request,
        current_head: &Request,
    ) -> Result<()> {
        if scope.authority_id == historical.authority_id
            && historical.authority_id == current_head.authority_id
            && historical.revision < current_head.revision
        {
            Ok(())
        } else {
            Err("simulated historical authority mismatch".into())
        }
    }
}

fn complete(
    journal: &Journal,
    request: &Request,
    token: &str,
    now: u64,
    completion: [u8; 32],
    trust: &TrustStore,
    policy: &SimulatedAuthority,
) -> CommittedTransition {
    let trust = trust.as_trust();
    let decision = journal
        .decide(request.clone(), token, now, &trust, policy)
        .unwrap();
    for participant in &request.participants {
        journal
            .acknowledge(&decision, participant, &trust, policy)
            .unwrap();
    }
    journal
        .complete(&decision, completion, &trust, policy)
        .unwrap();
    decision
}

#[test]
fn encrypted_journal_preserves_history_across_transition_signing_key_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transition-rotation.db");
    let old_signer = signer();
    let new_signer = signer();
    let wrong_replacement = signer();
    let profile = profile();
    let full_trust = TrustStore {
        profile: profile.clone(),
        keys: vec![
            (
                "transition-2026-old".into(),
                old_signer.public_key().as_ref().to_vec(),
            ),
            (
                "transition-2026-new".into(),
                new_signer.public_key().as_ref().to_vec(),
            ),
        ],
        max_lifetime: 100,
    };
    let first = request(1, None);
    let second = request(2, Some(first.participants[0].target.clone()));
    let first_token = token(
        &old_signer,
        "transition-2026-old",
        &profile,
        &first,
        [61; 32],
        100,
    );
    let second_token = token(
        &new_signer,
        "transition-2026-new",
        &profile,
        &second,
        [62; 32],
        200,
    );
    let policy = SimulatedAuthority;
    let journal = Journal::create(&path, PASSPHRASE, scope(&profile, &first)).unwrap();
    let first_decision = complete(
        &journal,
        &first,
        &first_token,
        150,
        [71; 32],
        &full_trust,
        &policy,
    );
    let second_decision = complete(
        &journal,
        &second,
        &second_token,
        250,
        [72; 32],
        &full_trust,
        &policy,
    );
    drop(journal);

    assert!(verify_issuance(&first_token, &full_trust.as_trust(), &first, 250).is_err());
    let historical = verify_historical(&first_token, &full_trust.as_trust(), &first).unwrap();
    assert_eq!(historical.certificate_id(), first_decision.certificate_id());
    assert_eq!(historical.token_digest(), first_decision.token_digest());

    let reopened = Journal::open(
        &path,
        PASSPHRASE,
        scope(&profile, &first),
        &full_trust.as_trust(),
    )
    .unwrap();
    let stored = reopened
        .fetch_completed(&second, &full_trust.as_trust(), &policy)
        .unwrap();
    assert_eq!(stored.request(), &second);
    assert_eq!(stored.token(), second_token);
    assert_eq!(stored.token_digest(), second_decision.token_digest());
    assert_eq!(stored.certificate_id(), second_decision.certificate_id());
    assert_eq!(stored.completion(), [72; 32]);
    let historical_stored = reopened
        .fetch_completed_revision(&first, &full_trust.as_trust(), &policy)
        .unwrap();
    assert_eq!(historical_stored.token(), first_token);
    assert_eq!(historical_stored.completion(), [71; 32]);
    drop(reopened);

    let new_only = TrustStore {
        profile: profile.clone(),
        keys: vec![(
            "transition-2026-new".into(),
            new_signer.public_key().as_ref().to_vec(),
        )],
        max_lifetime: 100,
    };
    assert!(Journal::open(
        &path,
        PASSPHRASE,
        scope(&profile, &first),
        &new_only.as_trust(),
    )
    .is_err());

    let wrong_key = TrustStore {
        profile: profile.clone(),
        keys: vec![
            (
                "transition-2026-old".into(),
                old_signer.public_key().as_ref().to_vec(),
            ),
            (
                "transition-2026-new".into(),
                wrong_replacement.public_key().as_ref().to_vec(),
            ),
        ],
        max_lifetime: 100,
    };
    assert!(Journal::open(
        &path,
        PASSPHRASE,
        scope(&profile, &first),
        &wrong_key.as_trust(),
    )
    .is_err());

    let mut wrong_profile = profile.clone();
    wrong_profile.audience = "wrong-audience".into();
    let wrong_profile_trust = TrustStore {
        profile: wrong_profile,
        keys: full_trust.keys.clone(),
        max_lifetime: 100,
    };
    assert!(Journal::open(
        &path,
        PASSPHRASE,
        scope(&profile, &first),
        &wrong_profile_trust.as_trust(),
    )
    .is_err());

    let ambiguous = TrustStore {
        profile: profile.clone(),
        keys: vec![
            (
                "transition-2026-old".into(),
                old_signer.public_key().as_ref().to_vec(),
            ),
            (
                "transition-2026-new".into(),
                new_signer.public_key().as_ref().to_vec(),
            ),
            (
                "transition-2026-new".into(),
                new_signer.public_key().as_ref().to_vec(),
            ),
        ],
        max_lifetime: 100,
    };
    assert!(Journal::open(
        &path,
        PASSPHRASE,
        scope(&profile, &first),
        &ambiguous.as_trust(),
    )
    .is_err());

    // Restoring the complete external historical trust set makes the same
    // encrypted bytes verifiable again; the journal itself is not modified.
    assert!(Journal::open(
        &path,
        PASSPHRASE,
        scope(&profile, &first),
        &full_trust.as_trust(),
    )
    .is_ok());
}
