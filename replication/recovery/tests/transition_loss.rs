use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde_json::json;
use std::cell::Cell;
use terrapi_vesta_recovery::{grant::Profile, transition::*, Result};

fn key() -> signature::EcdsaKeyPair {
    let r = SystemRandom::new();
    let p =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &r)
            .unwrap();
    signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, p.as_ref(), &r)
        .unwrap()
}
fn sign(k: &signature::EcdsaKeyPair, typ: &str, claims: serde_json::Value) -> String {
    let h = json!({"alg":"ES256","kid":"key","typ":typ});
    let input = format!(
        "{}.{}",
        B64.encode(h.to_string()),
        B64.encode(claims.to_string())
    );
    let s = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(s.as_ref()))
}
fn request() -> Request {
    let target = Checkpoint {
        sequence: 20,
        digest: [20; 32],
    };
    Request {
        format: 1,
        id: [1; 32],
        authority_id: [2; 32],
        revision: 1,
        install: "install".into(),
        region: "eu".into(),
        scope: [3; 32],
        schema: [4; 32],
        membership: [5; 32],
        source_anchor: Checkpoint {
            sequence: 10,
            digest: [10; 32],
        },
        participants: [
            Participant {
                member: [6; 32],
                generation: [7; 32],
                old_base: None,
                target: target.clone(),
                plan: [8; 32],
                publication: [9; 32],
            },
            Participant {
                member: [11; 32],
                generation: [12; 32],
                old_base: Some(Checkpoint {
                    sequence: 10,
                    digest: [10; 32],
                }),
                target,
                plan: [8; 32],
                publication: [13; 32],
            },
        ],
    }
}
struct P {
    ok: Cell<bool>,
    survivor_ok: Cell<bool>,
    fence_calls: Cell<u8>,
    revoke_after_first: Cell<bool>,
    expected_loss_membership: Cell<[u8; 32]>,
    installed: Cell<u8>,
    revoke_after_applied: Cell<bool>,
}
impl Policy for P {
    fn continuity(&self, _: &JournalScope, _: &Request) -> Result<()> {
        if self.ok.get() {
            Ok(())
        } else {
            Err("revoked".into())
        }
    }
    fn prepared(&self, _: &JournalScope, _: &Request, _: &Participant) -> Result<()> {
        Ok(())
    }
    fn applied(&self, _: &JournalScope, _: &CommittedTransition, _: &Participant) -> Result<()> {
        Ok(())
    }
}
impl LossPolicy for P {
    fn continuity_and_fencing(&self, scope: &JournalScope, _: &LossRequest) -> Result<()> {
        let calls = self.fence_calls.get() + 1;
        self.fence_calls.set(calls);
        if self.ok.get()
            && scope.membership == self.expected_loss_membership.get()
            && !(self.revoke_after_first.get() && calls > 1)
        {
            Ok(())
        } else {
            Err("fencing revoked".into())
        }
    }
    fn survivor_prepared(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        if self.survivor_ok.get() {
            Ok(())
        } else {
            Err("survivor evidence".into())
        }
    }
    fn loss_successor_applied(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        request: &LossSuccessorRequest,
        participant: &Participant,
    ) -> Result<()> {
        let index = request
            .participants
            .iter()
            .position(|p| p == participant)
            .ok_or("wrong installed participant")?;
        if self.installed.get() & (1 << index) == 0 {
            return Err("durable install missing".into());
        }
        if self.revoke_after_applied.get() {
            self.ok.set(false);
        }
        Ok(())
    }
    fn loss_successor_continuity(
        &self,
        scope: &JournalScope,
        request: &LossSuccessorRequest,
    ) -> Result<()> {
        if self.ok.get() && scope.membership == request.membership {
            Ok(())
        } else {
            Err("successor revoked".into())
        }
    }
}

#[test]
fn durable_loss_decision_retries_reopens_rejects_conflict_revocation_tamper_and_untrusted_rotation(
) -> Result<()> {
    let d = tempfile::tempdir()?;
    let path = d.path().join("authority");
    let k = key();
    let r = request();
    let profile = Profile {
        issuer: "issuer".into(),
        audience: "aud".into(),
        token_type: TOKEN_TYPE.into(),
    };
    let keys = vec![("key".into(), k.public_key().as_ref().to_vec())];
    let trust = Trust {
        profile: &profile,
        keys: &keys,
        max_lifetime: 100,
    };
    let scope = JournalScope {
        install: r.install.clone(),
        region: r.region.clone(),
        profile: profile.clone(),
        scope: r.scope,
        schema: r.schema,
        membership: r.membership,
        source_anchor: r.source_anchor.clone(),
        authority_id: r.authority_id,
        initial_revision: 1,
    };
    let p = P {
        ok: Cell::new(true),
        survivor_ok: Cell::new(true),
        fence_calls: Cell::new(0),
        revoke_after_first: Cell::new(false),
        expected_loss_membership: Cell::new(r.membership),
        installed: Cell::new(0),
        revoke_after_applied: Cell::new(false),
    };
    let j = Journal::create(&path, "pass", scope.clone())?;
    let claims = json!({"version":1,"iss":"issuer","aud":"aud","action":"compact_pair","certificate_id":([21;32]),"iat":100,"nbf":100,"exp":200,"request":r,"request_digest":r.digest()?});
    let token = sign(&k, TOKEN_TYPE, claims);
    let c = j.decide(r.clone(), &token, 150, &trust, &p)?;
    let make_loss = || LossRequest {
        format: 1,
        id: [23; 32],
        authority_id: r.authority_id,
        revision: 2,
        install: r.install.clone(),
        region: r.region.clone(),
        scope: r.scope,
        schema: r.schema,
        membership: r.membership,
        source_certificate: [21; 32],
        source_token_digest: c.token_digest(),
        source_cut: r.participants[0].target.clone(),
        lost_member: r.participants[0].member,
        lost_generation: r.participants[0].generation,
        survivor: Participant {
            target: Checkpoint {
                sequence: 25,
                digest: [28; 32],
            },
            publication: [29; 32],
            ..r.participants[1].clone()
        },
        survivor_cut: Checkpoint {
            sequence: 25,
            digest: [28; 32],
        },
        survivor_publication: [29; 32],
        replacement_membership: [28; 32],
        replacement_member: [24; 32],
        replacement_generation: [25; 32],
        fencing_ref: [26; 32],
    };
    let early = make_loss();
    let early_token = sign(
        &k,
        LOSS_TOKEN_TYPE,
        json!({"version":1,"iss":"issuer","aud":"aud","action":"terminate_and_replace","certificate_id":([27;32]),"iat":100,"nbf":100,"exp":200,"request":early,"request_digest":early.digest()?}),
    );
    assert!(j
        .decide_loss(early.clone(), &early_token, 150, &trust, &p)
        .is_err());
    j.acknowledge(&c, &r.participants[0], &trust, &p)?;
    assert!(j
        .decide_loss(early.clone(), &early_token, 150, &trust, &p)
        .is_err());
    j.acknowledge(&c, &r.participants[1], &trust, &p)?;
    assert!(j
        .decide_loss(early.clone(), &early_token, 150, &trust, &p)
        .is_err());
    j.complete(&c, [22; 32], &trust, &p)?;
    let loss = make_loss();
    let mut no_tail = loss.clone();
    no_tail.survivor.target = no_tail.source_cut.clone();
    no_tail.survivor_cut = no_tail.source_cut.clone();
    assert!(no_tail.validate().is_ok());
    let no_tail_activation = LossSuccessorRequest {
        format: 1,
        id: [92; 32],
        authority_id: no_tail.authority_id,
        revision: 3,
        install: no_tail.install.clone(),
        region: no_tail.region.clone(),
        scope: no_tail.scope,
        schema: no_tail.schema,
        membership: no_tail.replacement_membership,
        source_certificate: no_tail.source_certificate,
        source_token_digest: no_tail.source_token_digest,
        source_cut: no_tail.source_cut.clone(),
        parent_loss_certificate: [93; 32],
        parent_loss_token_digest: [94; 32],
        survivor_cut: no_tail.survivor_cut.clone(),
        survivor_publication: no_tail.survivor_publication,
        participants: [
            no_tail.survivor.clone(),
            Participant {
                member: no_tail.replacement_member,
                generation: no_tail.replacement_generation,
                old_base: Some(no_tail.survivor_cut.clone()),
                target: no_tail.survivor_cut.clone(),
                plan: no_tail.survivor.plan,
                publication: no_tail.survivor_publication,
            },
        ],
    };
    assert!(no_tail_activation.validate().is_ok());
    let mut mismatched_cut = loss.clone();
    mismatched_cut.survivor_cut.digest = [90; 32];
    assert!(mismatched_cut.validate().is_err());
    let mut mismatched_publication = loss.clone();
    mismatched_publication.survivor_publication = [91; 32];
    assert!(mismatched_publication.validate().is_err());
    /* exact expanded shape is exercised through make_loss above */
    /*
        format: 1,
        id: [23; 32],
        authority_id: r.authority_id,
        revision: 2,
        install: r.install.clone(),
        region: r.region.clone(),
        scope: r.scope,
        schema: r.schema,
        membership: r.membership,
        source_certificate: [21; 32],
        source_token_digest: c.token_digest(),
        source_cut: r.participants[0].target.clone(),
        lost_member: r.participants[0].member,
        lost_generation: r.participants[0].generation,
        survivor: r.participants[1].clone(),
        replacement_member: [24; 32],
        replacement_generation: [25; 32],
        fencing_ref: [26; 32],
    }; */
    let loss_token = |request: &LossRequest| {
        sign(
            &k,
            LOSS_TOKEN_TYPE,
            json!({"version":1,"iss":"issuer","aud":"aud","action":"terminate_and_replace","certificate_id":([27;32]),"iat":100,"nbf":100,"exp":200,"request":request,"request_digest":request.digest().unwrap()}),
        )
    };
    for n in 0..8 {
        let mut bad = loss.clone();
        match n {
            0 => bad.lost_member = [31; 32],
            1 => bad.lost_generation = [31; 32],
            2 => bad.survivor.generation = [31; 32],
            3 => bad.replacement_member = r.participants[1].member,
            4 => bad.revision = 4,
            5 => bad.survivor.publication = [31; 32],
            6 => bad.replacement_generation = bad.lost_generation,
            _ => bad.replacement_generation = bad.survivor.generation,
        };
        if bad.validate().is_err() {
            continue;
        }
        let t = loss_token(&bad);
        assert!(j.decide_loss(bad, &t, 150, &trust, &p).is_err());
    }
    let mut maximum_gap = loss.clone();
    maximum_gap.revision = i64::MAX as u64;
    let t = loss_token(&maximum_gap);
    assert!(j.decide_loss(maximum_gap, &t, 150, &trust, &p).is_err());
    let mut overflow = loss.clone();
    overflow.revision = i64::MAX as u64 + 1;
    assert!(overflow.validate().is_err());
    p.survivor_ok.set(false);
    let t = loss_token(&loss);
    assert!(j.decide_loss(loss.clone(), &t, 150, &trust, &p).is_err());
    p.survivor_ok.set(true);
    p.fence_calls.set(0);
    p.revoke_after_first.set(true);
    assert!(j.decide_loss(loss.clone(), &t, 150, &trust, &p).is_err());
    p.revoke_after_first.set(false);
    p.fence_calls.set(0);
    let lc = json!({"version":1,"iss":"issuer","aud":"aud","action":"terminate_and_replace","certificate_id":([27;32]),"iat":100,"nbf":100,"exp":200,"request":loss,"request_digest":loss.digest()?});
    let lt = sign(&k, LOSS_TOKEN_TYPE, lc);
    let committed = j.decide_loss(loss.clone(), &lt, 150, &trust, &p)?;
    assert!(j.fetch_completed(&r, &trust, &p).is_err());
    assert_eq!(
        j.decide_loss(loss.clone(), &lt, 150, &trust, &p)?
            .token_digest(),
        committed.token_digest()
    );
    let alternate = sign(
        &k,
        LOSS_TOKEN_TYPE,
        json!({"version":1,"iss":"issuer","aud":"aud","action":"terminate_and_replace","certificate_id":([27;32]),"iat":100,"nbf":100,"exp":200,"request":loss,"request_digest":loss.digest()?}),
    );
    assert!(j
        .decide_loss(loss.clone(), &alternate, 150, &trust, &p)
        .is_err());
    drop(j);
    let j = Journal::open(&path, "pass", scope.clone(), &trust)?;
    assert_eq!(j.fetch_loss(&trust, &p)?.token(), lt);

    let successor_path = d.path().join("successor-authority");
    let successor_scope = JournalScope {
        install: loss.install.clone(),
        region: loss.region.clone(),
        profile: profile.clone(),
        scope: loss.scope,
        schema: loss.schema,
        membership: loss.replacement_membership,
        source_anchor: loss.source_cut.clone(),
        authority_id: loss.authority_id,
        initial_revision: 3,
    };
    let interrupted_path = d.path().join("interrupted-successor");
    drop(terrapi_vesta::Vesta::create(
        &interrupted_path,
        "pass",
        terrapi_vesta::KdfParams::default(),
    )?);
    let interrupted = Journal::create_loss_successor(
        &interrupted_path,
        "pass",
        successor_scope.clone(),
        &j,
        &trust,
        &p,
    )?;
    assert!(interrupted.status(&trust)?.request.is_none());

    for (name, sql) in [
        ("nonempty-successor", "CREATE TABLE planted(value TEXT)"),
        (
            "partial-successor",
            "CREATE TABLE transition_scope(id INTEGER PRIMARY KEY,record TEXT)",
        ),
    ] {
        let planted_path = d.path().join(name);
        let planted = terrapi_vesta::Vesta::create(
            &planted_path,
            "pass",
            terrapi_vesta::KdfParams::default(),
        )?;
        planted.with_connection(|c| {
            c.execute_batch(sql)?;
            Ok(())
        })?;
        drop(planted);
        assert!(Journal::create_loss_successor(
            &planted_path,
            "pass",
            successor_scope.clone(),
            &j,
            &trust,
            &p,
        )
        .is_err());
    }
    p.fence_calls.set(0);
    p.revoke_after_first.set(true);
    assert!(Journal::create_loss_successor(
        &successor_path,
        "pass",
        successor_scope.clone(),
        &j,
        &trust,
        &p,
    )
    .is_err());
    assert!(successor_path.exists());
    p.revoke_after_first.set(false);
    p.fence_calls.set(0);
    let mut conflicting_scope = successor_scope.clone();
    conflicting_scope.membership = [29; 32];
    assert!(Journal::create_loss_successor(
        &successor_path,
        "pass",
        conflicting_scope,
        &j,
        &trust,
        &p,
    )
    .is_err());
    let successor = Journal::create_loss_successor(
        &successor_path,
        "pass",
        successor_scope.clone(),
        &j,
        &trust,
        &p,
    )?;
    let successor_request = LossSuccessorRequest {
        format: 1,
        id: [40; 32],
        authority_id: loss.authority_id,
        revision: 3,
        install: loss.install.clone(),
        region: loss.region.clone(),
        scope: loss.scope,
        schema: loss.schema,
        membership: loss.replacement_membership,
        source_certificate: loss.source_certificate,
        source_token_digest: loss.source_token_digest,
        source_cut: loss.source_cut.clone(),
        parent_loss_certificate: committed.certificate_id(),
        parent_loss_token_digest: committed.token_digest(),
        survivor_cut: loss.survivor_cut.clone(),
        survivor_publication: loss.survivor_publication,
        participants: [
            Participant {
                member: loss.survivor.member,
                generation: loss.survivor.generation,
                old_base: loss.survivor.old_base.clone(),
                target: loss.survivor_cut.clone(),
                plan: [42; 32],
                publication: loss.survivor_publication,
            },
            Participant {
                member: loss.replacement_member,
                generation: loss.replacement_generation,
                old_base: Some(loss.survivor_cut.clone()),
                target: loss.survivor_cut.clone(),
                plan: [42; 32],
                publication: loss.survivor_publication,
            },
        ],
    };
    let successor_token = sign(
        &k,
        LOSS_SUCCESSOR_TOKEN_TYPE,
        json!({"version":1,"iss":"issuer","aud":"aud","action":"activate_loss_successor","certificate_id":([45;32]),"iat":100,"nbf":100,"exp":200,"request":successor_request,"request_digest":successor_request.digest()?}),
    );
    assert!(j
        .fetch_loss_successor(&successor_request, &trust, &p)
        .is_err());
    assert!(successor
        .fetch_loss_successor(&successor_request, &trust, &p)
        .is_err());
    drop(successor);
    let successor = Journal::open(&successor_path, "pass", successor_scope.clone(), &trust)?;
    let mut wrong_revision = successor_request.clone();
    wrong_revision.revision = 4;
    let wrong_revision_token = sign(
        &k,
        LOSS_SUCCESSOR_TOKEN_TYPE,
        json!({"version":1,"iss":"issuer","aud":"aud","action":"activate_loss_successor","certificate_id":([46;32]),"iat":100,"nbf":100,"exp":200,"request":wrong_revision,"request_digest":wrong_revision.digest()?}),
    );
    assert!(successor
        .decide_loss_successor(wrong_revision, &wrong_revision_token, 150, &trust, &p)
        .is_err());
    let mut wrong_replacement = successor_request.clone();
    wrong_replacement.participants[1].generation = [48; 32];
    let wrong_replacement_token = sign(
        &k,
        LOSS_SUCCESSOR_TOKEN_TYPE,
        json!({"version":1,"iss":"issuer","aud":"aud","action":"activate_loss_successor","certificate_id":([49;32]),"iat":100,"nbf":100,"exp":200,"request":wrong_replacement,"request_digest":wrong_replacement.digest()?}),
    );
    assert!(successor
        .decide_loss_successor(wrong_replacement, &wrong_replacement_token, 150, &trust, &p,)
        .is_err());
    p.ok.set(false);
    assert!(successor
        .decide_loss_successor(successor_request.clone(), &successor_token, 150, &trust, &p,)
        .is_err());
    p.ok.set(true);
    p.fence_calls.set(0);
    p.revoke_after_first.set(true);
    assert!(successor
        .decide_loss_successor(successor_request.clone(), &successor_token, 150, &trust, &p,)
        .is_err());
    p.revoke_after_first.set(false);
    p.fence_calls.set(0);
    let successor_decision = successor.decide_loss_successor(
        successor_request.clone(),
        &successor_token,
        150,
        &trust,
        &p,
    )?;
    let installation = successor.fetch_loss_successor(&successor_request, &trust, &p)?;
    assert_eq!(installation.request(), &successor_request);
    assert_eq!(installation.token(), successor_token);
    assert_eq!(installation.source_scope(), &scope);
    assert_eq!(installation.loss_request(), &loss);
    assert_eq!(installation.loss_token_digest(), committed.token_digest());
    assert_eq!(
        installation.loss_certificate_id(),
        committed.certificate_id()
    );
    p.ok.set(false);
    assert!(successor
        .fetch_loss_successor(&successor_request, &trust, &p)
        .is_err());
    p.ok.set(true);
    assert_eq!(
        successor
            .decide_loss_successor(successor_request.clone(), &successor_token, 150, &trust, &p,)?
            .token(),
        successor_token
    );
    let resigned = sign(
        &k,
        LOSS_SUCCESSOR_TOKEN_TYPE,
        json!({"version":1,"iss":"issuer","aud":"aud","action":"activate_loss_successor","certificate_id":([45;32]),"iat":100,"nbf":100,"exp":200,"request":successor_request,"request_digest":successor_request.digest()?}),
    );
    assert!(successor
        .decide_loss_successor(successor_request.clone(), &resigned, 150, &trust, &p,)
        .is_err());
    drop(successor);
    let successor = Journal::open(&successor_path, "pass", successor_scope.clone(), &trust)?;
    assert_eq!(
        successor
            .fetch_loss_successor(&successor_request, &trust, &p)?
            .token_digest(),
        successor_decision.token_digest()
    );
    assert!(successor
        .fetch_completed_loss_successor(&successor_request, &trust, &p)
        .is_err());
    assert!(successor
        .acknowledge_loss_successor(
            &successor_decision,
            &successor_request.participants[0],
            &trust,
            &p,
        )
        .is_err());
    assert_eq!(
        successor
            .fetch_loss_successor(&successor_request, &trust, &p)?
            .acknowledgements(),
        [false; 2]
    );
    p.installed.set(1);
    p.revoke_after_applied.set(true);
    assert!(successor
        .acknowledge_loss_successor(
            &successor_decision,
            &successor_request.participants[0],
            &trust,
            &p,
        )
        .is_err());
    p.revoke_after_applied.set(false);
    p.ok.set(true);
    assert_eq!(
        successor
            .fetch_loss_successor(&successor_request, &trust, &p)?
            .acknowledgements(),
        [false; 2]
    );
    let mut forged_participant = successor_request.participants[0].clone();
    forged_participant.generation = [99; 32];
    assert!(successor
        .acknowledge_loss_successor(&successor_decision, &forged_participant, &trust, &p,)
        .is_err());
    successor.acknowledge_loss_successor(
        &successor_decision,
        &successor_request.participants[0],
        &trust,
        &p,
    )?;
    drop(successor);
    let successor = Journal::open(&successor_path, "pass", successor_scope.clone(), &trust)?;
    successor.acknowledge_loss_successor(
        &successor_decision,
        &successor_request.participants[0],
        &trust,
        &p,
    )?;
    assert!(successor
        .complete_loss_successor(&successor_decision, [47; 32], &trust, &p)
        .is_err());
    p.installed.set(3);
    successor.acknowledge_loss_successor(
        &successor_decision,
        &successor_request.participants[1],
        &trust,
        &p,
    )?;
    drop(successor);
    let successor = Journal::open(&successor_path, "pass", successor_scope.clone(), &trust)?;
    successor.complete_loss_successor(&successor_decision, [47; 32], &trust, &p)?;
    drop(successor);
    let successor = Journal::open(&successor_path, "pass", successor_scope.clone(), &trust)?;
    successor.complete_loss_successor(&successor_decision, [47; 32], &trust, &p)?;
    assert!(successor
        .complete_loss_successor(&successor_decision, [48; 32], &trust, &p)
        .is_err());
    assert_eq!(
        successor
            .fetch_completed_loss_successor(&successor_request, &trust, &p)?
            .completion(),
        [47; 32]
    );
    drop(successor);
    let successor_raw = terrapi_vesta::Vesta::open(&successor_path, "pass")?;
    successor_raw.with_connection(|c| {
        c.execute("UPDATE transition_loss_parent SET digest=zeroblob(32)", [])?;
        Ok(())
    })?;
    drop(successor_raw);
    assert!(Journal::open(&successor_path, "pass", successor_scope, &trust).is_err());

    p.ok.set(false);
    assert!(j.fetch_loss(&trust, &p).is_err());
    p.ok.set(true);
    drop(j);
    let other = key();
    let rotated = vec![("key".into(), other.public_key().as_ref().to_vec())];
    let bad = Trust {
        profile: &profile,
        keys: &rotated,
        max_lifetime: 100,
    };
    assert!(Journal::open(&path, "pass", scope.clone(), &bad).is_err());
    let raw = terrapi_vesta::Vesta::open(&path, "pass")?;
    raw.with_connection(|c| {
        c.execute("UPDATE transition_loss SET digest=zeroblob(32)", [])?;
        Ok(())
    })?;
    drop(raw);
    assert!(Journal::open(&path, "pass", scope, &trust).is_ok());
    let j = Journal::open(
        &path,
        "pass",
        JournalScope {
            install: "install".into(),
            region: "eu".into(),
            profile: profile.clone(),
            scope: [3; 32],
            schema: [4; 32],
            membership: [5; 32],
            source_anchor: Checkpoint {
                sequence: 10,
                digest: [10; 32],
            },
            authority_id: [2; 32],
            initial_revision: 1,
        },
        &trust,
    )?;
    assert!(j.fetch_loss(&trust, &p).is_err());
    Ok(())
}
