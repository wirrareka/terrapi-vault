//! S9 — second participant loss, journal side.
//!
//! A pair that has already survived one loss used to be a dead end: the
//! successor membership carried no role information, so nothing could prove
//! which of its two participants was the survivor, and a second loss was
//! unrecoverable. Format 2 names the survivor in the signed successor request
//! and lets a loss be anchored to a completed successor instead of an
//! ordinary transition.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde_json::{json, Value};
use std::cell::Cell;
use terrapi_vesta_recovery::{grant::Profile, transition::*, Result};

// ---------------------------------------------------------------- fixtures

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

fn sign(k: &signature::EcdsaKeyPair, typ: &str, claims: &Value) -> String {
    let header = json!({"alg":"ES256","kid":"key","typ":typ});
    let input = format!(
        "{}.{}",
        B64.encode(header.to_string()),
        B64.encode(claims.to_string())
    );
    let sig = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig.as_ref()))
}

fn sha(value: &str) -> [u8; 32] {
    <sha2::Sha256 as sha2::Digest>::digest(value.as_bytes()).into()
}

fn cp(sequence: u64, digest: u8) -> Checkpoint {
    Checkpoint {
        sequence,
        digest: [digest; 32],
    }
}

#[track_caller]
fn refused<T>(outcome: Result<T>, expected: &str) {
    match outcome {
        Ok(_) => panic!("expected refusal {expected:?}, got success"),
        Err(e) => assert_eq!(e.to_string(), expected, "wrong refusal"),
    }
}

#[track_caller]
fn invalid<T: std::fmt::Debug>(outcome: std::result::Result<T, &'static str>, expected: &str) {
    assert_eq!(outcome.err(), Some(expected));
}

struct Authority {
    ok: Cell<bool>,
    installed: Cell<u8>,
}
impl Default for Authority {
    fn default() -> Self {
        Self {
            ok: Cell::new(true),
            installed: Cell::new(0),
        }
    }
}
impl Policy for Authority {
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
impl LossPolicy for Authority {
    fn continuity_and_fencing(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        if self.ok.get() {
            Ok(())
        } else {
            Err("fencing revoked".into())
        }
    }
    fn survivor_prepared(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        Ok(())
    }
    fn loss_successor_applied(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        request: &LossSuccessorRequest,
        participant: &Participant,
    ) -> Result<()> {
        let i = request
            .participants
            .iter()
            .position(|p| p == participant)
            .ok_or("wrong installed participant")?;
        if self.installed.get() & (1 << i) == 0 {
            return Err("durable install missing".into());
        }
        Ok(())
    }
    fn loss_successor_continuity(&self, _: &JournalScope, _: &LossSuccessorRequest) -> Result<()> {
        if self.ok.get() {
            Ok(())
        } else {
            Err("successor revoked".into())
        }
    }
}

/// One certified pair and everything derived from it.
struct World {
    dir: tempfile::TempDir,
    k: signature::EcdsaKeyPair,
    keys: Vec<(String, Vec<u8>)>,
    profile: Profile,
    first: Request,
    first_token: String,
}

impl World {
    fn new() -> Self {
        let k = key();
        let target = cp(20, 20);
        let first = Request {
            format: 1,
            id: [1; 32],
            authority_id: [2; 32],
            revision: 1,
            install: "install".into(),
            region: "eu".into(),
            scope: [3; 32],
            schema: [4; 32],
            membership: [5; 32],
            source_anchor: cp(10, 10),
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
                    old_base: Some(cp(10, 10)),
                    target,
                    plan: [8; 32],
                    publication: [13; 32],
                },
            ],
        };
        let profile = Profile {
            issuer: "issuer".into(),
            audience: "aud".into(),
            token_type: TOKEN_TYPE.into(),
        };
        let first_token = sign(
            &k,
            TOKEN_TYPE,
            &json!({"version":1,"iss":"issuer","aud":"aud","action":"compact_pair",
                    "certificate_id":([21;32]),"iat":100,"nbf":100,"exp":200,
                    "request":first,"request_digest":first.digest().unwrap()}),
        );
        Self {
            dir: tempfile::tempdir().unwrap(),
            keys: vec![("key".into(), k.public_key().as_ref().to_vec())],
            k,
            profile,
            first,
            first_token,
        }
    }

    fn trust(&self) -> Trust<'_> {
        Trust {
            profile: &self.profile,
            keys: &self.keys,
            max_lifetime: 100,
        }
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }
    fn scope(&self) -> JournalScope {
        JournalScope {
            install: self.first.install.clone(),
            region: self.first.region.clone(),
            profile: self.profile.clone(),
            scope: self.first.scope,
            schema: self.first.schema,
            membership: self.first.membership,
            source_anchor: self.first.source_anchor.clone(),
            authority_id: self.first.authority_id,
            initial_revision: 1,
        }
    }

    /// The certified pair: revision 1 decided, acknowledged and completed.
    fn certified(&self, p: &Authority) -> Journal {
        let j = Journal::create(&self.path("authority"), "pass", self.scope()).unwrap();
        let d = j
            .decide(self.first.clone(), &self.first_token, 150, &self.trust(), p)
            .unwrap();
        for m in &self.first.participants {
            j.acknowledge(&d, m, &self.trust(), p).unwrap();
        }
        j.complete(&d, [30; 32], &self.trust(), p).unwrap();
        j
    }

    fn loss_token(&self, l: &LossRequest, certificate: u8) -> String {
        sign(
            &self.k,
            LOSS_TOKEN_TYPE,
            &json!({"version":1,"iss":"issuer","aud":"aud","action":"terminate_and_replace",
                    "certificate_id":([certificate;32]),"iat":100,"nbf":100,"exp":200,
                    "request":l,"request_digest":l.digest().unwrap()}),
        )
    }
    fn successor_token(&self, s: &LossSuccessorRequest, certificate: u8) -> String {
        sign(
            &self.k,
            LOSS_SUCCESSOR_TOKEN_TYPE,
            &json!({"version":1,"iss":"issuer","aud":"aud","action":"activate_loss_successor",
                    "certificate_id":([certificate;32]),"iat":100,"nbf":100,"exp":200,
                    "request":s,"request_digest":s.digest().unwrap()}),
        )
    }

    /// The first loss: `lost` is the index of the member that dies.
    fn first_loss(&self, lost: usize, format: u32) -> LossRequest {
        let gone = &self.first.participants[lost];
        let alive = &self.first.participants[1 - lost];
        LossRequest {
            format,
            id: [23; 32],
            authority_id: self.first.authority_id,
            revision: 2,
            install: self.first.install.clone(),
            region: self.first.region.clone(),
            scope: self.first.scope,
            schema: self.first.schema,
            membership: self.first.membership,
            source_certificate: [21; 32],
            source_token_digest: sha(&self.first_token),
            source_cut: self.first.participants[0].target.clone(),
            lost_member: gone.member,
            lost_generation: gone.generation,
            survivor: Participant {
                member: alive.member,
                generation: alive.generation,
                old_base: alive.old_base.clone(),
                target: cp(25, 28),
                plan: alive.plan,
                publication: [29; 32],
            },
            survivor_cut: cp(25, 28),
            survivor_publication: [29; 32],
            replacement_membership: [28; 32],
            replacement_member: [24; 32],
            replacement_generation: [25; 32],
            fencing_ref: [26; 32],
            source_kind: (format == 2).then_some(SourceKind::Completed),
            abandoned_request: None,
            supersedes: None,
        }
    }

    fn successor_scope(&self, loss: &LossRequest) -> JournalScope {
        JournalScope {
            install: loss.install.clone(),
            region: loss.region.clone(),
            profile: self.profile.clone(),
            scope: loss.scope,
            schema: loss.schema,
            membership: loss.replacement_membership,
            source_anchor: loss.source_cut.clone(),
            authority_id: loss.authority_id,
            initial_revision: loss.revision + 1,
        }
    }

    /// A format-2 successor request. The replacement takes the slot the lost
    /// member occupied, so the survivor's index is the *other* one.
    fn successor(
        &self,
        loss: &LossRequest,
        committed: &CommittedLoss,
        lost: usize,
        id: u8,
        plan: u8,
    ) -> LossSuccessorRequest {
        let survivor = Participant {
            member: loss.survivor.member,
            generation: loss.survivor.generation,
            old_base: loss.survivor.old_base.clone(),
            target: loss.survivor_cut.clone(),
            plan: [plan; 32],
            publication: loss.survivor_publication,
        };
        let replacement = Participant {
            member: loss.replacement_member,
            generation: loss.replacement_generation,
            old_base: Some(loss.survivor_cut.clone()),
            target: loss.survivor_cut.clone(),
            plan: [plan; 32],
            publication: loss.survivor_publication,
        };
        let mut participants = [survivor.clone(), replacement.clone()];
        participants[lost] = replacement;
        participants[1 - lost] = survivor;
        LossSuccessorRequest {
            format: 2,
            id: [id; 32],
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
            parent_loss_certificate: committed.certificate_id(),
            parent_loss_token_digest: committed.token_digest(),
            survivor_cut: loss.survivor_cut.clone(),
            survivor_publication: loss.survivor_publication,
            participants,
            survivor_index: Some(u8::try_from(1 - lost).unwrap()),
        }
    }

    /// Decide, acknowledge and complete a successor request.
    fn finish_successor(
        &self,
        journal: &Journal,
        request: &LossSuccessorRequest,
        token: &str,
        completion: u8,
        p: &Authority,
    ) -> CommittedLossSuccessorTransition {
        let d = journal
            .decide_loss_successor(request.clone(), token, 150, &self.trust(), p)
            .unwrap();
        p.installed.set(0b11);
        for m in &request.participants {
            journal
                .acknowledge_loss_successor(&d, m, &self.trust(), p)
                .unwrap();
        }
        journal
            .complete_loss_successor(&d, [completion; 32], &self.trust(), p)
            .unwrap();
        d
    }
}

/// A pair that has already survived one loss: journal `j`, successor journal
/// `a` with a completed format-2 successor.
struct Recovered {
    j: Journal,
    a: Journal,
    loss: LossRequest,
    successor: LossSuccessorRequest,
    successor_token: String,
    lost: usize,
}

fn recovered(w: &World, p: &Authority, lost: usize, loss_format: u32) -> Recovered {
    let j = w.certified(p);
    let loss = w.first_loss(lost, loss_format);
    let token = w.loss_token(&loss, 27);
    let committed = j
        .decide_loss(loss.clone(), &token, 150, &w.trust(), p)
        .unwrap();
    let a = Journal::create_loss_successor(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&loss),
        &j,
        &w.trust(),
        p,
    )
    .unwrap();
    let successor = w.successor(&loss, &committed, lost, 40, 42);
    let successor_token = w.successor_token(&successor, 45);
    w.finish_successor(&a, &successor, &successor_token, 60, p);
    Recovered {
        j,
        a,
        loss,
        successor,
        successor_token,
        lost,
    }
}

/// The second loss, anchored to the completed successor. The member that
/// survived the first loss is the one that now dies.
fn second_loss(_w: &World, r: &Recovered) -> LossRequest {
    let gone = &r.successor.participants[1 - r.lost];
    let alive = &r.successor.participants[r.lost];
    LossRequest {
        format: 2,
        id: [50; 32],
        authority_id: r.loss.authority_id,
        revision: r.successor.revision + 1,
        install: r.loss.install.clone(),
        region: r.loss.region.clone(),
        scope: r.loss.scope,
        schema: r.loss.schema,
        membership: r.loss.replacement_membership,
        source_certificate: [45; 32],
        source_token_digest: sha(&r.successor_token),
        source_cut: r.successor.survivor_cut.clone(),
        lost_member: gone.member,
        lost_generation: gone.generation,
        survivor: Participant {
            member: alive.member,
            generation: alive.generation,
            old_base: alive.old_base.clone(),
            target: cp(30, 33),
            plan: alive.plan,
            publication: [34; 32],
        },
        survivor_cut: cp(30, 33),
        survivor_publication: [34; 32],
        replacement_membership: [35; 32],
        replacement_member: [36; 32],
        replacement_generation: [37; 32],
        fencing_ref: [38; 32],
        source_kind: Some(SourceKind::LossSuccessor),
        abandoned_request: None,
        supersedes: None,
    }
}

// -------------------------------------------------------- format-1 goldens

#[test]
fn format_one_requests_still_serialise_to_their_captured_bytes() {
    // Captured from the code that existed before the format-2 fields were
    // added. `serde_json` omits a skipped `None`, so these must not move: a
    // single changed byte invalidates every stored digest and token binding
    // of every deployed format-1 journal.
    let loss_json = include_str!("golden/loss_request_format1.json").trim_end();
    let successor_json = include_str!("golden/loss_successor_request_format1.json").trim_end();

    let loss: LossRequest = serde_json::from_str(loss_json).unwrap();
    assert_eq!(loss.format, 1);
    assert_eq!(loss.source_kind, None);
    assert_eq!(loss.abandoned_request, None);
    assert_eq!(loss.supersedes, None);
    assert_eq!(loss.kind(), SourceKind::Completed);
    assert_eq!(serde_json::to_string(&loss).unwrap(), loss_json);
    assert_eq!(
        loss.digest().unwrap(),
        [
            0x68, 0x82, 0x3e, 0x3e, 0x30, 0xa1, 0x29, 0xde, 0xe7, 0xe4, 0xe9, 0x9f, 0xe9, 0x1f,
            0xcd, 0x3f, 0xbd, 0xd9, 0x02, 0x08, 0x71, 0x16, 0x5b, 0x86, 0x71, 0x3b, 0xe0, 0x8c,
            0x25, 0xe1, 0xd3, 0xc0
        ]
    );

    let successor: LossSuccessorRequest = serde_json::from_str(successor_json).unwrap();
    assert_eq!(successor.format, 1);
    assert_eq!(successor.survivor_index, None);
    assert_eq!(successor.survivor_index().unwrap(), 0);
    assert_eq!(serde_json::to_string(&successor).unwrap(), successor_json);
    assert_eq!(
        successor.digest().unwrap(),
        [
            0xd2, 0xdc, 0x1a, 0x42, 0x5b, 0x70, 0x28, 0xcf, 0x29, 0x20, 0x32, 0x21, 0xdd, 0x96,
            0xdd, 0x1a, 0xf2, 0x92, 0x04, 0x21, 0x0d, 0x50, 0xed, 0xe8, 0x94, 0x77, 0x23, 0xc7,
            0x04, 0xdc, 0x4b, 0x76
        ]
    );

    // The digests above are exactly what every issued format-1 token binds
    // through its `request_digest` claim, so an unchanged digest is an
    // unchanged token binding. That a *stored* format-1 loss token still
    // verifies after a reopen is proved end-to-end in
    // `a_format_two_successor_completes_a_recovery_cycle_for_either_survivor_index`.
}

// ----------------------------------------------------------- shape clauses

#[test]
fn a_format_one_request_refuses_every_format_two_field() {
    let w = World::new();
    let base = w.first_loss(0, 1);
    assert!(base.validate().is_ok());
    for bad in [
        LossRequest {
            source_kind: Some(SourceKind::Completed),
            ..base.clone()
        },
        LossRequest {
            abandoned_request: Some([77; 32]),
            ..base.clone()
        },
        LossRequest {
            supersedes: Some(Supersedes {
                loss_certificate: [1; 32],
                loss_token_digest: [2; 32],
                abort_certificate: [3; 32],
                abort_token_digest: [4; 32],
            }),
            ..base.clone()
        },
        LossRequest { format: 3, ..base },
    ] {
        invalid(bad.validate(), "invalid participant loss request");
        invalid(bad.digest(), "invalid participant loss request");
    }

    let r = recovered(&w, &Authority::default(), 0, 1);
    let mut format_one = r.successor.clone();
    format_one.format = 1;
    invalid(format_one.validate(), "invalid loss successor request");
    let mut indexed = r.successor;
    indexed.format = 1;
    indexed.survivor_index = None;
    // Format 1 fixes the order, so the roles change meaning entirely.
    assert_eq!(indexed.survivor_index().unwrap(), 0);
}

#[test]
fn a_format_two_loss_request_needs_a_source_kind_and_sane_optionals() {
    let w = World::new();
    let base = w.first_loss(0, 2);
    assert!(base.validate().is_ok());
    assert_eq!(base.kind(), SourceKind::Completed);

    let zero = Supersedes {
        loss_certificate: [1; 32],
        loss_token_digest: [2; 32],
        abort_certificate: [0; 32],
        abort_token_digest: [4; 32],
    };
    for bad in [
        LossRequest {
            source_kind: None,
            ..base.clone()
        },
        LossRequest {
            abandoned_request: Some([0; 32]),
            ..base.clone()
        },
        // `abandoned_request` is meaningless where nothing was in flight.
        LossRequest {
            source_kind: Some(SourceKind::LossSuccessor),
            abandoned_request: Some([77; 32]),
            ..base.clone()
        },
        LossRequest {
            supersedes: Some(zero),
            ..base.clone()
        },
    ] {
        invalid(bad.validate(), "invalid participant loss request");
    }
    // Well-formed, just not honoured yet.
    assert!(LossRequest {
        source_kind: Some(SourceKind::Decided),
        abandoned_request: Some([77; 32]),
        ..base
    }
    .validate()
    .is_ok());
}

#[test]
fn a_format_two_successor_needs_a_survivor_index_and_reindexes_every_role() {
    for lost in [0usize, 1] {
        let w = World::new();
        let p = Authority::default();
        let r = recovered(&w, &p, lost, 1);
        let s = &r.successor;
        assert_eq!(s.survivor_index, Some(u8::try_from(1 - lost).unwrap()));
        assert_eq!(s.survivor_index().unwrap(), 1 - lost);
        assert_eq!(s.survivor().unwrap().member, r.loss.survivor.member);
        assert_eq!(s.replacement().unwrap().member, r.loss.replacement_member);
        assert_eq!(roles(s).unwrap(), (1 - lost, lost));
    }

    let w = World::new();
    let p = Authority::default();
    let r = recovered(&w, &p, 0, 1);
    for bad_index in [None, Some(2u8), Some(7)] {
        let mut bad = r.successor.clone();
        bad.survivor_index = bad_index;
        invalid(bad.validate(), "invalid loss successor request");
        invalid(roles(&bad), "invalid loss successor request");
    }
}

// --------------------------------------------------------- full cycles

#[test]
fn a_format_two_successor_completes_a_recovery_cycle_for_either_survivor_index() {
    for lost in [0usize, 1] {
        let w = World::new();
        let p = Authority::default();
        let r = recovered(&w, &p, lost, 1);
        let completed =
            r.a.fetch_completed_loss_successor(&r.successor, &w.trust(), &p)
                .unwrap();
        assert_eq!(completed.completion(), [60; 32]);
        assert_eq!(completed.certificate_id(), [45; 32]);
        assert_eq!(completed.request().survivor_index().unwrap(), 1 - lost);

        // Exact retry and reopen converge on the same decision.
        let retry =
            r.a.decide_loss_successor(r.successor.clone(), &r.successor_token, 150, &w.trust(), &p)
                .unwrap();
        assert_eq!(retry.token_digest(), sha(&r.successor_token));

        // The stored format-1 loss token is re-verified against its request
        // on every read, so this proves an existing format-1 token fixture
        // still verifies under the format-2 code.
        drop(r.j);
        let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
        assert_eq!(j.fetch_loss(&w.trust(), &p).unwrap().request(), &r.loss);
        assert_eq!(r.loss.format, 1);
        drop(r.a);
        let reopened = Journal::open(
            &w.path("successor-a"),
            "pass",
            w.successor_scope(&r.loss),
            &w.trust(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .fetch_completed_loss_successor(&r.successor, &w.trust(), &p)
                .unwrap()
                .completion(),
            [60; 32]
        );
    }
}

#[test]
fn two_consecutive_losses_complete_end_to_end_with_retries_and_reopens() {
    let w = World::new();
    let p = Authority::default();
    let r = recovered(&w, &p, 0, 2);
    let loss2 = second_loss(&w, &r);
    let token2 = w.loss_token(&loss2, 91);

    let committed2 =
        r.a.decide_loss(loss2.clone(), &token2, 150, &w.trust(), &p)
            .unwrap();
    assert_eq!(committed2.request(), &loss2);
    assert_eq!(committed2.certificate_id(), [91; 32]);
    // Exact retry converges; a re-signed token is an immutable conflict.
    assert_eq!(
        r.a.decide_loss(loss2.clone(), &token2, 150, &w.trust(), &p)
            .unwrap()
            .token_digest(),
        committed2.token_digest()
    );
    refused(
        r.a.decide_loss(
            loss2.clone(),
            &w.loss_token(&loss2, 91),
            150,
            &w.trust(),
            &p,
        ),
        "immutable loss decision conflict",
    );

    // The second successor journal is founded on the first successor journal.
    let scope_b = w.successor_scope(&loss2);
    assert_eq!(scope_b.initial_revision, 5);
    assert_eq!(scope_b.source_anchor, r.successor.survivor_cut);
    let b = Journal::create_loss_successor(
        &w.path("successor-b"),
        "pass",
        scope_b.clone(),
        &r.a,
        &w.trust(),
        &p,
    )
    .unwrap();

    let gone = &r.successor.participants[1 - r.lost];
    let alive = &r.successor.participants[r.lost];
    let survivor2 = Participant {
        member: alive.member,
        generation: alive.generation,
        old_base: alive.old_base.clone(),
        target: cp(30, 33),
        plan: [52; 32],
        publication: [34; 32],
    };
    let replacement2 = Participant {
        member: loss2.replacement_member,
        generation: loss2.replacement_generation,
        old_base: Some(cp(30, 33)),
        target: cp(30, 33),
        plan: [52; 32],
        publication: [34; 32],
    };
    let mut participants = [survivor2.clone(), replacement2.clone()];
    participants[r.lost] = survivor2;
    participants[1 - r.lost] = replacement2;
    let sb = LossSuccessorRequest {
        format: 2,
        id: [55; 32],
        authority_id: loss2.authority_id,
        revision: 5,
        install: loss2.install.clone(),
        region: loss2.region.clone(),
        scope: loss2.scope,
        schema: loss2.schema,
        membership: loss2.replacement_membership,
        source_certificate: loss2.source_certificate,
        source_token_digest: loss2.source_token_digest,
        source_cut: loss2.source_cut.clone(),
        parent_loss_certificate: committed2.certificate_id(),
        parent_loss_token_digest: committed2.token_digest(),
        survivor_cut: cp(30, 33),
        survivor_publication: [34; 32],
        participants,
        survivor_index: Some(u8::try_from(r.lost).unwrap()),
    };
    assert_eq!(sb.survivor().unwrap().member, alive.member);
    assert_eq!(sb.replacement().unwrap().member, [36; 32]);
    assert_ne!(sb.survivor().unwrap().member, gone.member);

    let sb_token = w.successor_token(&sb, 95);
    w.finish_successor(&b, &sb, &sb_token, 70, &p);
    let completed = b
        .fetch_completed_loss_successor(&sb, &w.trust(), &p)
        .unwrap();
    assert_eq!(completed.completion(), [70; 32]);

    // Everything survives a reopen of both successor journals.
    drop(b);
    let b = Journal::open(&w.path("successor-b"), "pass", scope_b, &w.trust()).unwrap();
    assert_eq!(
        b.fetch_completed_loss_successor(&sb, &w.trust(), &p)
            .unwrap()
            .completion(),
        [70; 32]
    );
    let installation = b.fetch_loss_successor(&sb, &w.trust(), &p).unwrap();
    assert_eq!(installation.loss_request(), &loss2);
    assert_eq!(
        installation.loss_certificate_id(),
        committed2.certificate_id()
    );
    assert_eq!(
        installation.source_scope().membership,
        r.loss.replacement_membership
    );
    drop(r.a);
    let a = Journal::open(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&r.loss),
        &w.trust(),
    )
    .unwrap();
    assert_eq!(a.fetch_loss(&w.trust(), &p).unwrap().request(), &loss2);
}

// ------------------------------------------------- closing the old membership

#[test]
fn a_second_loss_closes_every_operation_on_the_first_successor_membership() {
    let w = World::new();
    let p = Authority::default();
    let r = recovered(&w, &p, 0, 2);
    let decision =
        r.a.decide_loss_successor(r.successor.clone(), &r.successor_token, 150, &w.trust(), &p)
            .unwrap();
    let loss2 = second_loss(&w, &r);
    r.a.decide_loss(
        loss2.clone(),
        &w.loss_token(&loss2, 91),
        150,
        &w.trust(),
        &p,
    )
    .unwrap();

    let closed = "loss successor superseded by participant loss";
    let check = |a: &Journal| {
        refused(a.fetch_loss_successor(&r.successor, &w.trust(), &p), closed);
        refused(
            a.fetch_completed_loss_successor(&r.successor, &w.trust(), &p),
            closed,
        );
        refused(
            a.acknowledge_loss_successor(&decision, &r.successor.participants[0], &w.trust(), &p),
            closed,
        );
        refused(
            a.complete_loss_successor(&decision, [61; 32], &w.trust(), &p),
            closed,
        );
        refused(
            a.decide_loss_successor(r.successor.clone(), &r.successor_token, 150, &w.trust(), &p),
            closed,
        );
        // The new survivor still needs to read the loss that closed it.
        assert_eq!(a.fetch_loss(&w.trust(), &p).unwrap().request(), &loss2);
    };
    check(&r.a);
    drop(r.a);
    let a = Journal::open(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&r.loss),
        &w.trust(),
    )
    .unwrap();
    check(&a);
}

#[test]
fn an_ordinary_transition_is_still_refused_in_a_successor_journal() {
    let w = World::new();
    let p = Authority::default();
    let r = recovered(&w, &p, 0, 1);
    let mut ordinary = w.first.clone();
    ordinary.id = [66; 32];
    ordinary.revision = 3;
    ordinary.membership = r.loss.replacement_membership;
    ordinary.source_anchor = r.loss.source_cut.clone();
    for m in &mut ordinary.participants {
        m.old_base = Some(r.loss.source_cut.clone());
        m.target = cp(40, 41);
    }
    let token = sign(
        &w.k,
        TOKEN_TYPE,
        &json!({"version":1,"iss":"issuer","aud":"aud","action":"compact_pair",
                "certificate_id":([67;32]),"iat":100,"nbf":100,"exp":200,
                "request":ordinary,"request_digest":ordinary.digest().unwrap()}),
    );
    refused(
        r.a.decide(ordinary, &token, 150, &w.trust(), &p),
        "replacement transition requires loss sequencing",
    );
}

// ------------------------------------------------ LossSuccessor source rules

#[test]
fn a_loss_from_a_successor_refuses_a_format_one_or_unfinished_successor() {
    // Format-1 successor: no role information, so no second loss.
    let w = World::new();
    let p = Authority::default();
    let j = w.certified(&p);
    let loss = w.first_loss(0, 1);
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 27), 150, &w.trust(), &p)
        .unwrap();
    let a = Journal::create_loss_successor(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&loss),
        &j,
        &w.trust(),
        &p,
    )
    .unwrap();
    let mut legacy = w.successor(&loss, &committed, 0, 40, 42);
    legacy.format = 1;
    legacy.survivor_index = None;
    legacy.participants.swap(0, 1); // format 1 fixes [survivor, replacement]
    let legacy_token = w.successor_token(&legacy, 45);
    w.finish_successor(&a, &legacy, &legacy_token, 60, &p);

    let r = Recovered {
        j,
        a,
        loss,
        successor: legacy,
        successor_token: legacy_token,
        lost: 0,
    };
    let mut loss2 = second_loss(&w, &r);
    loss2.lost_member = r.successor.participants[1].member;
    loss2.lost_generation = r.successor.participants[1].generation;
    loss2.survivor.member = r.successor.participants[0].member;
    loss2.survivor.generation = r.successor.participants[0].generation;
    loss2.survivor.old_base = r.successor.participants[0].old_base.clone();
    refused(
        r.a.decide_loss(
            loss2.clone(),
            &w.loss_token(&loss2, 91),
            150,
            &w.trust(),
            &p,
        ),
        "format-1 loss successor cannot source a loss",
    );

    // Decided but not completed, and acknowledged by only one participant.
    let w = World::new();
    let p = Authority::default();
    let j = w.certified(&p);
    let loss = w.first_loss(0, 1);
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 27), 150, &w.trust(), &p)
        .unwrap();
    let a = Journal::create_loss_successor(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&loss),
        &j,
        &w.trust(),
        &p,
    )
    .unwrap();
    let successor = w.successor(&loss, &committed, 0, 40, 42);
    let successor_token = w.successor_token(&successor, 45);
    let decision = a
        .decide_loss_successor(successor.clone(), &successor_token, 150, &w.trust(), &p)
        .unwrap();
    let r = Recovered {
        j,
        a,
        loss,
        successor,
        successor_token,
        lost: 0,
    };
    let loss2 = second_loss(&w, &r);
    let expected = "completed replacement transition required";
    refused(
        r.a.decide_loss(
            loss2.clone(),
            &w.loss_token(&loss2, 91),
            150,
            &w.trust(),
            &p,
        ),
        expected,
    );
    p.installed.set(0b01);
    r.a.acknowledge_loss_successor(&decision, &r.successor.participants[0], &w.trust(), &p)
        .unwrap();
    refused(
        r.a.decide_loss(
            loss2.clone(),
            &w.loss_token(&loss2, 91),
            150,
            &w.trust(),
            &p,
        ),
        expected,
    );
    // Both ACKs but still no completion.
    p.installed.set(0b11);
    r.a.acknowledge_loss_successor(&decision, &r.successor.participants[1], &w.trust(), &p)
        .unwrap();
    refused(
        r.a.decide_loss(
            loss2.clone(),
            &w.loss_token(&loss2, 91),
            150,
            &w.trust(),
            &p,
        ),
        expected,
    );
    r.a.complete_loss_successor(&decision, [60; 32], &w.trust(), &p)
        .unwrap();
    assert!(r
        .a
        .decide_loss(
            loss2.clone(),
            &w.loss_token(&loss2, 91),
            150,
            &w.trust(),
            &p
        )
        .is_ok());
}

#[test]
fn a_loss_from_a_successor_binds_the_exact_certificate_token_digest_and_cut() {
    let w = World::new();
    let p = Authority::default();
    let r = recovered(&w, &p, 0, 2);
    let good = second_loss(&w, &r);

    for bad in [
        LossRequest {
            source_certificate: [99; 32],
            ..good.clone()
        },
        LossRequest {
            source_token_digest: [99; 32],
            ..good.clone()
        },
        LossRequest {
            source_cut: cp(25, 99),
            ..good.clone()
        },
        LossRequest {
            membership: [99; 32],
            ..good.clone()
        },
    ] {
        refused(
            r.a.decide_loss(bad.clone(), &w.loss_token(&bad, 91), 150, &w.trust(), &p),
            "loss source mismatch",
        );
    }
    // The successor's revision counts as consumed, so the next free revision
    // is one past it, not one past the ordinary head.
    for revision in [3u64, 5] {
        let bad = LossRequest {
            revision,
            ..good.clone()
        };
        refused(
            r.a.decide_loss(bad.clone(), &w.loss_token(&bad, 91), 150, &w.trust(), &p),
            "loss participant/revision mismatch",
        );
    }
    assert_eq!(good.revision, 4);
    assert!(r
        .a
        .decide_loss(good.clone(), &w.loss_token(&good, 91), 150, &w.trust(), &p)
        .is_ok());
}

#[test]
fn a_loss_from_a_successor_refuses_wrong_participants_and_retired_identities() {
    let w = World::new();
    let p = Authority::default();
    let r = recovered(&w, &p, 0, 2);
    let good = second_loss(&w, &r);
    let alive = &r.successor.participants[r.lost];

    // A member that is not one of the successor's two participants.
    let stranger = LossRequest {
        lost_member: [88; 32],
        ..good.clone()
    };
    refused(
        r.a.decide_loss(
            stranger.clone(),
            &w.loss_token(&stranger, 91),
            150,
            &w.trust(),
            &p,
        ),
        "lost participant mismatch",
    );
    // Right member, wrong generation.
    let rolled = LossRequest {
        lost_generation: [89; 32],
        ..good.clone()
    };
    refused(
        r.a.decide_loss(
            rolled.clone(),
            &w.loss_token(&rolled, 91),
            150,
            &w.trust(),
            &p,
        ),
        "lost participant mismatch",
    );
    // Survivor generation and base must match the successor exactly.
    for bad in [
        LossRequest {
            survivor: Participant {
                generation: [87; 32],
                ..good.survivor.clone()
            },
            ..good.clone()
        },
        LossRequest {
            survivor: Participant {
                old_base: Some(cp(1, 1)),
                ..good.survivor.clone()
            },
            ..good.clone()
        },
    ] {
        refused(
            r.a.decide_loss(bad.clone(), &w.loss_token(&bad, 91), 150, &w.trust(), &p),
            "loss participant/revision mismatch",
        );
    }
    // A replacement may not reuse a member that is currently installed.
    let reused = LossRequest {
        replacement_member: alive.member,
        ..good.clone()
    };
    invalid(reused.validate(), "invalid participant loss request");

    // Nor an identity retired by the *first* loss.
    for bad in [
        LossRequest {
            replacement_member: r.loss.lost_member,
            ..good.clone()
        },
        LossRequest {
            replacement_generation: r.loss.lost_generation,
            ..good.clone()
        },
        LossRequest {
            replacement_membership: r.loss.membership,
            ..good.clone()
        },
    ] {
        refused(
            r.a.decide_loss(bad.clone(), &w.loss_token(&bad, 91), 150, &w.trust(), &p),
            "loss replacement reuses a retired identity",
        );
    }
    // And the current membership is refused by the shape clauses.
    invalid(
        LossRequest {
            replacement_membership: good.membership,
            ..good.clone()
        }
        .validate(),
        "invalid participant loss request",
    );
}

#[test]
fn a_loss_from_a_successor_is_refused_in_an_ordinary_journal() {
    let w = World::new();
    let p = Authority::default();
    let j = w.certified(&p);
    let mut bad = w.first_loss(0, 2);
    bad.source_kind = Some(SourceKind::LossSuccessor);
    refused(
        j.decide_loss(bad.clone(), &w.loss_token(&bad, 27), 150, &w.trust(), &p),
        "ordinary successor history forbidden",
    );
}

#[test]
fn decided_abandoned_and_supersedes_are_validated_but_not_yet_enabled() {
    let w = World::new();
    let p = Authority::default();
    let j = w.certified(&p);
    let base = w.first_loss(0, 2);

    let decided = LossRequest {
        source_kind: Some(SourceKind::Decided),
        ..base.clone()
    };
    assert!(decided.validate().is_ok());
    refused(
        j.decide_loss(
            decided.clone(),
            &w.loss_token(&decided, 27),
            150,
            &w.trust(),
            &p,
        ),
        "decided loss source not enabled",
    );

    let abandoned = LossRequest {
        abandoned_request: Some([77; 32]),
        ..base.clone()
    };
    assert!(abandoned.validate().is_ok());
    refused(
        j.decide_loss(
            abandoned.clone(),
            &w.loss_token(&abandoned, 27),
            150,
            &w.trust(),
            &p,
        ),
        "loss abandoned request not enabled",
    );

    let superseding = LossRequest {
        supersedes: Some(Supersedes {
            loss_certificate: [1; 32],
            loss_token_digest: [2; 32],
            abort_certificate: [3; 32],
            abort_token_digest: [4; 32],
        }),
        ..base.clone()
    };
    assert!(superseding.validate().is_ok());
    refused(
        j.decide_loss(
            superseding.clone(),
            &w.loss_token(&superseding, 27),
            150,
            &w.trust(),
            &p,
        ),
        "loss supersession not enabled",
    );

    // Nothing above was recorded; the plain format-2 request still works.
    assert!(j
        .decide_loss(base.clone(), &w.loss_token(&base, 27), 150, &w.trust(), &p)
        .is_ok());
}
