use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde_json::{json, Value};
use std::cell::Cell;
use terrapi_vesta_recovery::{grant::Profile, transition::*};

fn key() -> signature::EcdsaKeyPair {
    let rng = SystemRandom::new();
    let bytes =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
    signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        bytes.as_ref(),
        &rng,
    )
    .unwrap()
}
fn request() -> Request {
    let target = Checkpoint {
        sequence: 20,
        digest: [20; 32],
    };
    Request {
        format: 1,
        id: [1; 32],
        authority_id: [15; 32],
        revision: 1,
        install: "install".into(),
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
                old_base: None,
                target: target.clone(),
                plan: [7; 32],
                publication: [8; 32],
            },
            Participant {
                member: [9; 32],
                generation: [11; 32],
                old_base: Some(Checkpoint {
                    sequence: 10,
                    digest: [10; 32],
                }),
                target,
                plan: [7; 32],
                publication: [13; 32],
            },
        ],
    }
}
fn profile() -> Profile {
    Profile {
        issuer: "issuer".into(),
        audience: "audience".into(),
        token_type: TOKEN_TYPE.into(),
    }
}
fn claims(r: &Request) -> Value {
    json!({"version":1,"iss":"issuer","aud":"audience","action":"compact_pair","certificate_id":([14;32]),"iat":100,"nbf":100,"exp":200,"request":r,"request_digest":r.digest().unwrap()})
}
fn sign(key: &signature::EcdsaKeyPair, header: Value, claims: Value) -> String {
    sign_raw(key, &header.to_string(), &claims.to_string())
}
fn sign_raw(key: &signature::EcdsaKeyPair, header: &str, claims: &str) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(claims));
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig.as_ref()))
}

fn verify_both(token: &str, trust: &Trust<'_>, r: &Request) -> bool {
    verify_issuance(token, trust, r, 150).is_err() && verify_historical(token, trust, r).is_err()
}

#[test]
fn verifies_issuance_and_expired_historical_proof_with_external_trust() {
    let k = key();
    let r = request();
    let p = profile();
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let token = sign(
        &k,
        json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
        claims(&r),
    );
    assert_eq!(
        verify_issuance(&token, &trust, &r, 150).unwrap().request(),
        &r
    );
    assert!(verify_issuance(&token, &trust, &r, 200).is_err());
    assert_eq!(
        verify_historical(&token, &trust, &r)
            .unwrap()
            .certificate_id(),
        [14; 32]
    );
}

#[test]
fn rejects_untrusted_signature_wrong_purpose_and_claim_extensions() {
    let trusted = key();
    let attacker = key();
    let r = request();
    let p = profile();
    let keys = vec![("key".into(), trusted.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let header = json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE});
    assert!(verify_issuance(
        &sign(&attacker, header.clone(), claims(&r)),
        &trust,
        &r,
        150
    )
    .is_err());
    let mut wrong = claims(&r);
    wrong["action"] = json!("replace_primary");
    assert!(verify_issuance(&sign(&trusted, header.clone(), wrong), &trust, &r, 150).is_err());
    let mut extended = claims(&r);
    extended["extra"] = json!(true);
    assert!(verify_issuance(&sign(&trusted, header, extended), &trust, &r, 150).is_err());
    let ambiguous = vec![
        ("key".into(), trusted.public_key().as_ref().to_vec()),
        ("key".into(), trusted.public_key().as_ref().to_vec()),
    ];
    let ambiguous_trust = Trust {
        profile: &p,
        keys: &ambiguous,
        max_lifetime: 100,
    };
    let token = sign(
        &trusted,
        json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
        claims(&r),
    );
    assert!(verify_issuance(&token, &ambiguous_trust, &r, 150).is_err());
}

#[test]
fn rejects_changed_binding_digest_members_and_invalid_bases_or_times() {
    let k = key();
    let r = request();
    let p = profile();
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let header = json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE});
    let token = sign(&k, header.clone(), claims(&r));
    let mut changed = r.clone();
    changed.membership = [42; 32];
    assert!(verify_historical(&token, &trust, &changed).is_err());
    let mut bad_digest = claims(&r);
    bad_digest["request_digest"] = Value::from(vec![33; 32]);
    assert!(verify_historical(&sign(&k, header.clone(), bad_digest), &trust, &r).is_err());
    let mut duplicate = r.clone();
    duplicate.participants[1].member = duplicate.participants[0].member;
    assert!(duplicate.validate().is_err());
    let mut bad_base = r.clone();
    bad_base.participants[1].old_base.as_mut().unwrap().sequence = 21;
    assert!(bad_base.validate().is_err());
    let mut bad_time = claims(&r);
    bad_time["exp"] = json!(250);
    assert!(verify_historical(&sign(&k, header, bad_time), &trust, &r).is_err());
}

#[test]
fn permits_empty_anchor_but_rejects_signed_inverted_validity_window() {
    let k = key();
    let mut r = request();
    r.source_anchor.sequence = 0;
    r.participants[1].old_base.as_mut().unwrap().sequence = 0;
    assert!(r.validate().is_ok());
    let p = profile();
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let mut bad = claims(&r);
    bad["nbf"] = json!(200);
    let token = sign(&k, json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}), bad);
    assert!(verify_issuance(&token, &trust, &r, 150).is_err());
    assert!(verify_historical(&token, &trust, &r).is_err());
}

#[test]
fn strict_header_profile_signature_and_compact_shape_boundaries() {
    let trusted = key();
    let attacker = key();
    let r = request();
    let p = profile();
    let keys = vec![("key".into(), trusted.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let good_h = json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE});
    for h in [
        json!({"alg":"ES384","kid":"key","typ":TOKEN_TYPE}),
        json!({"alg":"ES256","kid":"key","typ":"recovery+jwt"}),
        json!({"alg":"ES256","kid":"unknown","typ":TOKEN_TYPE}),
    ] {
        assert!(verify_both(&sign(&trusted, h, claims(&r)), &trust, &r));
    }
    assert!(verify_both(
        &sign(&attacker, good_h.clone(), claims(&r)),
        &trust,
        &r
    ));
    for token in ["", "a.b", "a.b.c.d", "%%.e30.AA"] {
        assert!(verify_both(token, &trust, &r));
    }
    let input = format!(
        "{}.{}",
        B64.encode(good_h.to_string()),
        B64.encode(claims(&r).to_string())
    );
    let short = format!("{input}.{}", B64.encode([0u8; 63]));
    assert!(verify_both(&short, &trust, &r));
    assert!(verify_both(&"x".repeat(65 * 1024), &trust, &r));
    let wrong_profile = Profile {
        issuer: "wrong".into(),
        audience: p.audience.clone(),
        token_type: TOKEN_TYPE.into(),
    };
    let wrong_trust = Trust {
        profile: &wrong_profile,
        keys: &keys,
        max_lifetime: 100,
    };
    assert!(verify_both(
        &sign(&trusted, good_h, claims(&r)),
        &wrong_trust,
        &r
    ));
    for wrong in [
        Profile {
            issuer: p.issuer.clone(),
            audience: "wrong".into(),
            token_type: TOKEN_TYPE.into(),
        },
        Profile {
            issuer: p.issuer.clone(),
            audience: p.audience.clone(),
            token_type: "recovery+jwt".into(),
        },
    ] {
        let wrong_trust = Trust {
            profile: &wrong,
            keys: &keys,
            max_lifetime: 100,
        };
        let token = sign(
            &trusted,
            json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
            claims(&r),
        );
        assert!(verify_both(&token, &wrong_trust, &r));
    }
}

#[test]
fn every_request_binding_and_structural_constraint_is_enforced() {
    let k = key();
    let r = request();
    let p = profile();
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let token = sign(
        &k,
        json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
        claims(&r),
    );
    let mut changed = Vec::new();
    macro_rules! changed {
        ($body:expr) => {{
            let mut x = r.clone();
            $body(&mut x);
            changed.push(x);
        }};
    }
    changed!(|x: &mut Request| x.id = [31; 32]);
    changed!(|x: &mut Request| x.format = 2);
    changed!(|x: &mut Request| x.install = "other".into());
    changed!(|x: &mut Request| x.region = "us".into());
    changed!(|x: &mut Request| x.scope = [31; 32]);
    changed!(|x: &mut Request| x.schema = [31; 32]);
    changed!(|x: &mut Request| x.membership = [31; 32]);
    changed!(|x: &mut Request| x.source_anchor.digest = [31; 32]);
    changed!(|x: &mut Request| x.source_anchor.sequence = 9);
    changed!(|x: &mut Request| x.participants[0].member = [31; 32]);
    changed!(|x: &mut Request| x.participants[0].generation = [31; 32]);
    changed!(
        |x: &mut Request| x.participants[0].old_base = Some(Checkpoint {
            sequence: 1,
            digest: [1; 32]
        })
    );
    changed!(|x: &mut Request| x.participants[0].target.digest = [31; 32]);
    changed!(|x: &mut Request| x.participants[0].plan = [31; 32]);
    changed!(|x: &mut Request| x.participants[0].publication = [31; 32]);
    changed!(|x: &mut Request| x.participants[1].member = [31; 32]);
    changed!(|x: &mut Request| x.participants[1].generation = [31; 32]);
    changed!(|x: &mut Request| x.participants[1].old_base = None);
    changed!(|x: &mut Request| x.participants[1].target.digest = [31; 32]);
    changed!(|x: &mut Request| x.participants[1].plan = [31; 32]);
    changed!(|x: &mut Request| x.participants[1].publication = [31; 32]);
    for x in changed {
        assert!(verify_both(&token, &trust, &x));
    }
    let mut invalids = Vec::new();
    for field in 0..5 {
        let mut x = r.clone();
        match field {
            0 => x.id = [0; 32],
            1 => x.scope = [0; 32],
            2 => x.schema = [0; 32],
            3 => x.membership = [0; 32],
            _ => x.participants[0].plan = [0; 32],
        };
        invalids.push(x);
    }
    let mut x = r.clone();
    x.participants[1].plan = [22; 32];
    invalids.push(x);
    let mut x = r.clone();
    x.participants[1].generation = x.participants[0].generation;
    invalids.push(x);
    let mut x = r.clone();
    x.participants[1].target.sequence = 21;
    invalids.push(x);
    let mut x = r.clone();
    x.participants[0].target.sequence = x.source_anchor.sequence;
    x.participants[1].target = x.participants[0].target.clone();
    invalids.push(x);
    let mut x = r.clone();
    x.source_anchor.sequence = i64::MAX as u64 + 1;
    invalids.push(x);
    for x in invalids {
        assert!(x.validate().is_err());
    }
}

#[test]
fn duplicate_and_unknown_nested_json_fields_are_rejected() {
    let k = key();
    let r = request();
    let p = profile();
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let h = format!(
        r#"{{"alg":"ES256","alg":"ES256","kid":"key","typ":"{}"}}"#,
        TOKEN_TYPE
    );
    assert!(verify_both(
        &sign_raw(&k, &h, &claims(&r).to_string()),
        &trust,
        &r
    ));
    let c = claims(&r).to_string();
    let duplicate = c.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(verify_both(
        &sign_raw(
            &k,
            &json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}).to_string(),
            &duplicate
        ),
        &trust,
        &r
    ));
    let nested = c.replacen("\"format\":1", "\"format\":1,\"unknown\":true", 1);
    assert!(verify_both(
        &sign_raw(
            &k,
            &json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}).to_string(),
            &nested
        ),
        &trust,
        &r
    ));
    let nested_duplicate = c.replacen("\"format\":1", "\"format\":1,\"format\":1", 1);
    assert!(verify_both(
        &sign_raw(
            &k,
            &json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}).to_string(),
            &nested_duplicate
        ),
        &trust,
        &r
    ));
}

#[test]
fn issuance_time_edges_and_intrinsic_windows_are_exact() {
    let k = key();
    let r = request();
    let p = profile();
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let h = json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE});
    let token = sign(&k, h.clone(), claims(&r));
    assert!(verify_issuance(&token, &trust, &r, 99).is_err());
    assert!(verify_issuance(&token, &trust, &r, 100).is_ok());
    assert!(verify_issuance(&token, &trust, &r, 199).is_ok());
    assert!(verify_issuance(&token, &trust, &r, 200).is_err());
    for (iat, nbf, exp) in [
        (101, 100, 200),
        (100, 201, 200),
        (200, 200, 200),
        (201, 200, 200),
    ] {
        let mut c = claims(&r);
        c["iat"] = json!(iat);
        c["nbf"] = json!(nbf);
        c["exp"] = json!(exp);
        assert!(verify_both(&sign(&k, h.clone(), c), &trust, &r));
    }
}

#[test]
fn signed_zero_anchor_and_different_old_bases_are_valid() {
    let k = key();
    let mut r = request();
    r.source_anchor.sequence = 0;
    r.participants[0].old_base = None;
    r.participants[1].old_base = Some(Checkpoint {
        sequence: 7,
        digest: [7; 32],
    });
    let p = profile();
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let token = sign(
        &k,
        json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
        claims(&r),
    );
    assert!(verify_issuance(&token, &trust, &r, 150).is_ok());
    assert!(verify_historical(&token, &trust, &r).is_ok());
}

struct Allow {
    current: Cell<bool>,
    prepared_ok: Cell<bool>,
}
impl Policy for Allow {
    fn continuity(&self, _: &JournalScope, _: &Request) -> terrapi_vesta_recovery::Result<()> {
        if self.current.get() {
            Ok(())
        } else {
            Err("stale witness".into())
        }
    }
    fn prepared(
        &self,
        _: &JournalScope,
        _: &Request,
        _: &Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        if self.prepared_ok.get() {
            Ok(())
        } else {
            Err("prepared evidence".into())
        }
    }
    fn applied(
        &self,
        _: &JournalScope,
        _: &CommittedTransition,
        _: &Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        Ok(())
    }

    fn historical_completion(
        &self,
        _: &JournalScope,
        historical: &Request,
        current_head: &Request,
    ) -> terrapi_vesta_recovery::Result<()> {
        if self.current.get() && historical.revision < current_head.revision {
            Ok(())
        } else {
            Err("historical transition not superseded by current authority".into())
        }
    }
}

#[test]
fn encrypted_journal_reopens_and_requires_both_acks_and_current_witness() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transition.db");
    let k = key();
    let r = request();
    let p = profile();
    let scope = JournalScope {
        install: r.install.clone(),
        region: r.region.clone(),
        profile: p.clone(),
        scope: r.scope,
        schema: r.schema,
        membership: r.membership,
        source_anchor: r.source_anchor.clone(),
        authority_id: r.authority_id,
        initial_revision: r.revision,
    };
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let policy = Allow {
        current: Cell::new(true),
        prepared_ok: Cell::new(true),
    };
    let token = sign(
        &k,
        json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
        claims(&r),
    );
    let journal = Journal::create(&path, "pass", scope.clone()).unwrap();
    let decision = journal
        .decide(r.clone(), &token, 150, &trust, &policy)
        .unwrap();
    assert!(journal.fetch_completed(&r, &trust, &policy).is_err());
    assert!(journal
        .fetch_completed_revision(&r, &trust, &policy)
        .is_err());
    let resigned = sign(
        &k,
        json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
        claims(&r),
    );
    assert_ne!(resigned, token);
    assert!(journal
        .decide(r.clone(), &resigned, 150, &trust, &policy)
        .is_err());
    assert!(journal
        .complete(&decision, [30; 32], &trust, &policy)
        .is_err());
    journal
        .acknowledge(&decision, &r.participants[0], &trust, &policy)
        .unwrap();
    assert!(journal
        .complete(&decision, [30; 32], &trust, &policy)
        .is_err());
    journal
        .acknowledge(&decision, &r.participants[1], &trust, &policy)
        .unwrap();
    journal
        .complete(&decision, [30; 32], &trust, &policy)
        .unwrap();
    let completed = journal.fetch_completed(&r, &trust, &policy).unwrap();
    assert_eq!(completed.request(), &r);
    assert_eq!(completed.token(), token);
    assert_eq!(completed.token_digest(), decision.token_digest());
    assert_eq!(completed.certificate_id(), decision.certificate_id());
    assert_eq!(completed.completion(), [30; 32]);
    let mut second = r.clone();
    second.id = [41; 32];
    second.revision = 2;
    for member in &mut second.participants {
        member.old_base = Some(r.participants[0].target.clone());
        member.target = Checkpoint {
            sequence: 30,
            digest: [30; 32],
        };
        member.plan = [42; 32];
        member.publication = if member.member == r.participants[0].member {
            [43; 32]
        } else {
            [44; 32]
        };
    }
    let second_token = sign(
        &k,
        json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
        claims(&second),
    );
    let second_decision = journal
        .decide(second.clone(), &second_token, 150, &trust, &policy)
        .unwrap();
    let historical = journal
        .fetch_completed_revision(&r, &trust, &policy)
        .unwrap();
    assert_eq!(historical.request(), &r);
    assert_eq!(historical.token(), token);
    assert_eq!(historical.completion(), [30; 32]);
    let mut modified_first = r.clone();
    modified_first.id = [99; 32];
    assert!(journal
        .fetch_completed_revision(&modified_first, &trust, &policy)
        .is_err());
    let mut missing = second.clone();
    missing.revision = 3;
    assert!(journal
        .fetch_completed_revision(&missing, &trust, &policy)
        .is_err());
    let retry = journal
        .decide(second.clone(), &second_token, 150, &trust, &policy)
        .unwrap();
    assert_eq!(retry.token_digest(), second_decision.token_digest());
    assert_eq!(
        journal.fetch(&second, &trust, &policy).unwrap().token(),
        second_token
    );
    assert!(journal
        .acknowledge(&decision, &r.participants[0], &trust, &policy)
        .is_err());
    journal
        .acknowledge(&second_decision, &second.participants[0], &trust, &policy)
        .unwrap();
    journal
        .acknowledge(&second_decision, &second.participants[1], &trust, &policy)
        .unwrap();
    journal
        .complete(&second_decision, [45; 32], &trust, &policy)
        .unwrap();
    drop(journal);
    let reopened = Journal::open(&path, "pass", scope, &trust).unwrap();
    assert_eq!(
        reopened
            .fetch_completed_revision(&r, &trust, &policy)
            .unwrap()
            .completion(),
        [30; 32]
    );
    let recovered = reopened.fetch(&second, &trust, &policy).unwrap();
    assert_eq!(recovered.token(), second_token);
    assert_eq!(recovered.completion(), Some([45; 32]));
    assert_eq!(recovered.acknowledgements(), [true; 2]);
    let completed = reopened.fetch_completed(&second, &trust, &policy).unwrap();
    assert_eq!(completed.completion(), [45; 32]);
    policy.current.set(false);
    assert!(reopened.fetch_completed(&second, &trust, &policy).is_err());
    assert!(reopened
        .fetch_completed_revision(&r, &trust, &policy)
        .is_err());
    policy.current.set(true);
    reopened
        .complete(&recovered, [45; 32], &trust, &policy)
        .unwrap();
    assert!(reopened
        .complete(&recovered, [46; 32], &trust, &policy)
        .is_err());
    let mut third = second.clone();
    third.id = r.id;
    third.revision = 3;
    for member in &mut third.participants {
        member.old_base = Some(second.participants[0].target.clone());
        member.target = Checkpoint {
            sequence: 40,
            digest: [40; 32],
        };
        member.plan = [47; 32];
    }
    let third_token = sign(
        &k,
        json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
        claims(&third),
    );
    assert!(reopened
        .decide(third, &third_token, 150, &trust, &policy)
        .is_err());
    assert_eq!(
        reopened.status(&trust).unwrap().request,
        Some(second.clone())
    );
    drop(reopened);
    let reopened = Journal::open(
        &path,
        "pass",
        JournalScope {
            install: second.install.clone(),
            region: second.region.clone(),
            profile: p.clone(),
            scope: second.scope,
            schema: second.schema,
            membership: second.membership,
            source_anchor: second.source_anchor.clone(),
            authority_id: second.authority_id,
            initial_revision: 1,
        },
        &trust,
    )
    .unwrap();
    policy.current.set(false);
    assert!(reopened.decide(r, &token, 150, &trust, &policy).is_err());
}

#[test]
fn failed_prepared_evidence_rolls_back_and_exact_retry_can_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rollback.db");
    let k = key();
    let r = request();
    let p = profile();
    let scope = JournalScope {
        install: r.install.clone(),
        region: r.region.clone(),
        profile: p.clone(),
        scope: r.scope,
        schema: r.schema,
        membership: r.membership,
        source_anchor: r.source_anchor.clone(),
        authority_id: r.authority_id,
        initial_revision: r.revision,
    };
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &p,
        keys: &keys,
        max_lifetime: 100,
    };
    let policy = Allow {
        current: Cell::new(true),
        prepared_ok: Cell::new(false),
    };
    let token = sign(
        &k,
        json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
        claims(&r),
    );
    let journal = Journal::create(&path, "pass", scope).unwrap();
    assert!(journal
        .decide(r.clone(), &token, 150, &trust, &policy)
        .is_err());
    policy.prepared_ok.set(true);
    assert_eq!(
        journal
            .decide(r, &token, 150, &trust, &policy)
            .unwrap()
            .token(),
        token
    );
}

#[test]
fn missing_history_tail_and_corrupt_record_fail_reopen() {
    for corrupt in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("damage.db");
        let k = key();
        let r = request();
        let p = profile();
        let scope = JournalScope {
            install: r.install.clone(),
            region: r.region.clone(),
            profile: p.clone(),
            scope: r.scope,
            schema: r.schema,
            membership: r.membership,
            source_anchor: r.source_anchor.clone(),
            authority_id: r.authority_id,
            initial_revision: r.revision,
        };
        let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
        let trust = Trust {
            profile: &p,
            keys: &keys,
            max_lifetime: 100,
        };
        let policy = Allow {
            current: Cell::new(true),
            prepared_ok: Cell::new(true),
        };
        let token = sign(
            &k,
            json!({"alg":"ES256","kid":"key","typ":TOKEN_TYPE}),
            claims(&r),
        );
        let journal = Journal::create(&path, "pass", scope.clone()).unwrap();
        journal.decide(r, &token, 150, &trust, &policy).unwrap();
        drop(journal);
        let raw = terrapi_vesta::Vesta::open(&path, "pass").unwrap();
        raw.with_connection(|c| {
            if corrupt {
                c.execute("UPDATE transition_history SET digest=zeroblob(32)", [])?;
            } else {
                c.execute("DELETE FROM transition_history", [])?;
            }
            Ok(())
        })
        .unwrap();
        drop(raw);
        assert!(Journal::open(&path, "pass", scope, &trust).is_err());
    }
}
