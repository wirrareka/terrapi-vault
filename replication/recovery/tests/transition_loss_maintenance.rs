//! S11 — a participant is lost while certified maintenance is in flight.
//!
//! The C1 maintenance abort cannot help here: it demands proof that *both*
//! nodes are durably rolling back, and a lost member can never give it. So the
//! signed loss decision itself has to terminate the in-flight transition, in
//! one of exactly two ways:
//!
//! * **rollback** (`Completed` + `abandoned_request`) — the survivor never
//!   applied, so nothing was written and the loss anchors to the last
//!   completed certificate; and
//! * **finish forward** (`Decided`) — the survivor already applied and its
//!   history is pruned, so rolling back is impossible. Without this branch the
//!   survivor is permanently unopenable and the pair is lost with it.
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

struct Authority {
    ok: Cell<bool>,
    installed: Cell<u8>,
    rollback_ok: Cell<bool>,
    finish_ok: Cell<bool>,
    survivor_ok: Cell<bool>,
    superseded_ok: Cell<bool>,
    abort_ok: Cell<bool>,
}
impl Default for Authority {
    fn default() -> Self {
        Self {
            ok: Cell::new(true),
            installed: Cell::new(0),
            rollback_ok: Cell::new(true),
            finish_ok: Cell::new(true),
            survivor_ok: Cell::new(true),
            superseded_ok: Cell::new(true),
            abort_ok: Cell::new(true),
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
    fn abort_applicable(&self, _: &JournalScope, _: &MaintenanceAbort) -> Result<()> {
        if self.abort_ok.get() {
            Ok(())
        } else {
            Err("nodes not aborting".into())
        }
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
        if self.survivor_ok.get() {
            Ok(())
        } else {
            Err("survivor did not apply the decided transition".into())
        }
    }
    fn maintenance_rollback_authorized(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &[u8; 32],
    ) -> Result<()> {
        if self.rollback_ok.get() {
            Ok(())
        } else {
            Err("survivor does not hold that pending request".into())
        }
    }
    fn maintenance_finish_forward_authorized(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &[u8; 32],
    ) -> Result<()> {
        if self.finish_ok.get() {
            Ok(())
        } else {
            Err("survivor has not applied that decided transition".into())
        }
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
    fn superseded_successor_aborted(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &Supersedes,
    ) -> Result<()> {
        if self.superseded_ok.get() {
            Ok(())
        } else {
            Err("no abort in the successor journal".into())
        }
    }
    fn successor_abort_authorized(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &LossSuccessorRequest,
        _: &LossSuccessorAbort,
    ) -> Result<()> {
        Ok(())
    }
}

/// An integration that never overrides the rollback hook.
struct Unaware;
impl LossPolicy for Unaware {
    fn continuity_and_fencing(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        Ok(())
    }
    fn survivor_prepared(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        Ok(())
    }
}

struct World {
    dir: tempfile::TempDir,
    k: signature::EcdsaKeyPair,
    keys: Vec<(String, Vec<u8>)>,
    profile: Profile,
    first: Request,
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
        Self {
            dir: tempfile::tempdir().unwrap(),
            keys: vec![("key".into(), k.public_key().as_ref().to_vec())],
            k,
            profile: Profile {
                issuer: "issuer".into(),
                audience: "aud".into(),
                token_type: TOKEN_TYPE.into(),
            },
            first,
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
    fn certificate_of(r: &Request) -> [u8; 32] {
        [u8::try_from(r.revision).unwrap().wrapping_add(100); 32]
    }
    fn transition_token(&self, r: &Request) -> String {
        sign(
            &self.k,
            TOKEN_TYPE,
            &json!({"version":1,"iss":"issuer","aud":"aud","action":"compact_pair",
                    "certificate_id":Self::certificate_of(r),"iat":100,"nbf":100,"exp":200,
                    "request":r,"request_digest":r.digest().unwrap()}),
        )
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

    /// Revision 1 decided, acknowledged and completed; returns its token.
    fn certified(&self, p: &Authority) -> (Journal, String) {
        let j = Journal::create(&self.path("authority"), "pass", self.scope()).unwrap();
        let token = self.transition_token(&self.first);
        let d = j
            .decide(self.first.clone(), &token, 150, &self.trust(), p)
            .unwrap();
        for m in &self.first.participants {
            j.acknowledge(&d, m, &self.trust(), p).unwrap();
        }
        j.complete(&d, [30; 32], &self.trust(), p).unwrap();
        (j, token)
    }

    /// The in-flight maintenance request: revision 2, chained to revision 1.
    fn maintenance(&self) -> Request {
        let mut r = self.first.clone();
        r.id = [41; 32];
        r.revision = 2;
        for m in &mut r.participants {
            m.old_base = Some(self.first.participants[0].target.clone());
            m.target = cp(30, 31);
            m.plan = [42; 32];
        }
        r
    }

    /// A loss anchored to `source`, losing participant `lost`.
    fn loss(
        &self,
        source: &Request,
        source_token: &str,
        lost: usize,
        revision: u64,
        kind: SourceKind,
        abandoned: Option<[u8; 32]>,
    ) -> LossRequest {
        let gone = &source.participants[lost];
        let alive = &source.participants[1 - lost];
        LossRequest {
            format: 2,
            id: [23; 32],
            authority_id: self.first.authority_id,
            revision,
            install: self.first.install.clone(),
            region: self.first.region.clone(),
            scope: self.first.scope,
            schema: self.first.schema,
            membership: self.first.membership,
            source_certificate: Self::certificate_of(source),
            source_token_digest: sha(source_token),
            source_cut: source.participants[0].target.clone(),
            lost_member: gone.member,
            lost_generation: gone.generation,
            survivor: Participant {
                member: alive.member,
                generation: alive.generation,
                old_base: alive.old_base.clone(),
                target: cp(35, 36),
                plan: alive.plan,
                publication: [29; 32],
            },
            survivor_cut: cp(35, 36),
            survivor_publication: [29; 32],
            replacement_membership: [28; 32],
            replacement_member: [24; 32],
            replacement_generation: [25; 32],
            fencing_ref: [26; 32],
            source_kind: Some(kind),
            abandoned_request: abandoned,
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

    fn successor(
        &self,
        loss: &LossRequest,
        committed: &CommittedLoss,
        id: u8,
    ) -> LossSuccessorRequest {
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
            participants: [
                Participant {
                    member: loss.replacement_member,
                    generation: loss.replacement_generation,
                    old_base: Some(loss.survivor_cut.clone()),
                    target: loss.survivor_cut.clone(),
                    plan: [52; 32],
                    publication: loss.survivor_publication,
                },
                Participant {
                    member: loss.survivor.member,
                    generation: loss.survivor.generation,
                    old_base: loss.survivor.old_base.clone(),
                    target: loss.survivor_cut.clone(),
                    plan: [52; 32],
                    publication: loss.survivor_publication,
                },
            ],
            survivor_index: Some(1),
        }
    }

    /// Found the successor journal and run it to completion.
    fn recover(&self, j: &Journal, loss: &LossRequest, c: &CommittedLoss, p: &Authority) {
        let s = Journal::create_loss_successor(
            &self.path("successor"),
            "pass",
            self.successor_scope(loss),
            j,
            &self.trust(),
            p,
        )
        .unwrap();
        let request = self.successor(loss, c, 60);
        let token = self.successor_token(&request, 95);
        let d = s
            .decide_loss_successor(request.clone(), &token, 150, &self.trust(), p)
            .unwrap();
        p.installed.set(0b11);
        for m in &request.participants {
            s.acknowledge_loss_successor(&d, m, &self.trust(), p)
                .unwrap();
        }
        s.complete_loss_successor(&d, [96; 32], &self.trust(), p)
            .unwrap();
        assert_eq!(
            s.fetch_completed_loss_successor(&request, &self.trust(), p)
                .unwrap()
                .completion(),
            [96; 32]
        );
        drop(s);
        let reopened = Journal::open(
            &self.path("successor"),
            "pass",
            self.successor_scope(loss),
            &self.trust(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .fetch_completed_loss_successor(&request, &self.trust(), p)
                .unwrap()
                .completion(),
            [96; 32]
        );
    }
}

/// A journal whose head is a decided, unfinished maintenance transition.
struct InFlight {
    j: Journal,
    first_token: String,
    maintenance: Request,
    decision: CommittedTransition,
}

fn in_flight(w: &World, p: &Authority) -> InFlight {
    let (j, first_token) = w.certified(p);
    let maintenance = w.maintenance();
    let decision = j
        .decide(
            maintenance.clone(),
            &w.transition_token(&maintenance),
            150,
            &w.trust(),
            p,
        )
        .unwrap();
    InFlight {
        j,
        first_token,
        maintenance,
        decision,
    }
}

// --------------------------------------------------- branch A — rollback

#[test]
fn a1_a_loss_rolls_back_a_decided_transition_the_survivor_never_applied() {
    let w = World::new();
    let p = Authority::default();
    let f = in_flight(&w, &p);
    let digest = f.maintenance.digest().unwrap();

    // The loss anchors to the *completed* certificate below the open head,
    // and consumes the next revision; the decided revision stays burnt.
    let loss = w.loss(
        &w.first,
        &f.first_token,
        0,
        3,
        SourceKind::Completed,
        Some(digest),
    );
    let loss_token = w.loss_token(&loss, 91);
    let committed =
        f.j.decide_loss(loss.clone(), &loss_token, 150, &w.trust(), &p)
            .unwrap();
    assert_eq!(committed.request(), &loss);
    assert_eq!(loss.source_certificate, World::certificate_of(&w.first));

    // The abandoned transition is untouched and unusable for ever.
    let status = f.j.status(&w.trust()).unwrap();
    assert_eq!(status.request, Some(f.maintenance.clone()));
    assert_eq!(status.acknowledgements, [false; 2]);
    assert_eq!(status.completion, None);
    assert_eq!((status.last_revision, status.aborted), (2, 0));
    let closed = "transition superseded by participant loss";
    refused(
        f.j.acknowledge(&f.decision, &f.maintenance.participants[1], &w.trust(), &p),
        closed,
    );
    refused(f.j.complete(&f.decision, [55; 32], &w.trust(), &p), closed);
    refused(
        f.j.decide(
            f.maintenance.clone(),
            &w.transition_token(&f.maintenance),
            150,
            &w.trust(),
            &p,
        ),
        closed,
    );

    // Exact retry converges; a re-signed token is an immutable conflict.
    assert_eq!(
        f.j.decide_loss(loss.clone(), &loss_token, 150, &w.trust(), &p)
            .unwrap()
            .token_digest(),
        committed.token_digest()
    );
    refused(
        f.j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p),
        "immutable loss decision conflict",
    );
    w.recover(&f.j, &loss, &committed, &p);
    drop(f.j);
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    assert_eq!(j.fetch_loss(&w.trust(), &p).unwrap().request(), &loss);
    assert_eq!(
        j.status(&w.trust()).unwrap().request,
        Some(f.maintenance.clone())
    );
}

#[test]
fn a2_a_loss_abandons_a_request_only_the_survivor_can_see() {
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);

    // Nothing was ever decided: the journal has no idea this request exists,
    // so the default-deny hook is the only thing that can authorize it.
    let never_decided = w.maintenance().digest().unwrap();
    let loss = w.loss(
        &w.first,
        &first_token,
        0,
        2,
        SourceKind::Completed,
        Some(never_decided),
    );
    p.rollback_ok.set(false);
    refused(
        j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p),
        "survivor does not hold that pending request",
    );
    refused(
        j.decide_loss(
            loss.clone(),
            &w.loss_token(&loss, 91),
            150,
            &w.trust(),
            &Unaware,
        ),
        "maintenance rollback evidence missing",
    );
    p.rollback_ok.set(true);
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
        .unwrap();
    assert_eq!(committed.request().abandoned_request, Some(never_decided));
    w.recover(&j, &loss, &committed, &p);
}

// ----------------------------------------------- branch B — finish forward

#[test]
fn b_a_loss_finishes_forward_a_transition_the_survivor_already_applied() {
    let w = World::new();
    let p = Authority::default();
    let f = in_flight(&w, &p);
    let digest = f.maintenance.digest().unwrap();

    // The survivor applied and acknowledged; the lost member never will.
    f.j.acknowledge(&f.decision, &f.maintenance.participants[1], &w.trust(), &p)
        .unwrap();

    let loss = w.loss(
        &f.maintenance,
        &w.transition_token(&f.maintenance),
        0,
        3,
        SourceKind::Decided,
        Some(digest),
    );
    // The source must be the decided certificate, not the completed one.
    let loss = LossRequest {
        source_token_digest: f.decision.token_digest(),
        ..loss
    };
    assert_eq!(
        loss.source_certificate,
        World::certificate_of(&f.maintenance)
    );
    assert_eq!(loss.source_cut, f.maintenance.participants[0].target);

    p.survivor_ok.set(false);
    refused(
        f.j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p),
        "survivor did not apply the decided transition",
    );
    p.survivor_ok.set(true);
    let committed =
        f.j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
            .unwrap();
    assert_eq!(committed.request(), &loss);

    // The decided record is never completed and the lost member never gains
    // an acknowledgement: the loss certificate is its only provenance now.
    let status = f.j.status(&w.trust()).unwrap();
    assert_eq!(status.request, Some(f.maintenance.clone()));
    assert_eq!(status.acknowledgements, [false, true]);
    assert_eq!(status.completion, None);
    assert_eq!(status.last_revision, 2);
    refused(
        f.j.complete(&f.decision, [55; 32], &w.trust(), &p),
        "transition superseded by participant loss",
    );
    refused(
        f.j.fetch_completed(&f.maintenance, &w.trust(), &p),
        "transition superseded by participant loss",
    );

    w.recover(&f.j, &loss, &committed, &p);
    drop(f.j);
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    assert_eq!(j.fetch_loss(&w.trust(), &p).unwrap().request(), &loss);
    let status = j.status(&w.trust()).unwrap();
    assert_eq!(status.acknowledgements, [false, true]);
    assert_eq!(status.completion, None);
}

// ---------------------------------------------------------------- negative

#[test]
fn an_open_decided_head_may_never_be_silently_ignored_by_a_loss() {
    let w = World::new();
    let p = Authority::default();
    let f = in_flight(&w, &p);

    // No `abandoned_request` at all.
    let blind = w.loss(&w.first, &f.first_token, 0, 3, SourceKind::Completed, None);
    refused(
        f.j.decide_loss(
            blind.clone(),
            &w.loss_token(&blind, 91),
            150,
            &w.trust(),
            &p,
        ),
        "open decided transition must be abandoned or sourced",
    );
    // A digest that is not the open head's.
    let wrong = w.loss(
        &w.first,
        &f.first_token,
        0,
        3,
        SourceKind::Completed,
        Some([99; 32]),
    );
    refused(
        f.j.decide_loss(
            wrong.clone(),
            &w.loss_token(&wrong, 91),
            150,
            &w.trust(),
            &p,
        ),
        "open decided transition must be abandoned or sourced",
    );
    // Even a format-1 loss, which cannot carry the field at all.
    let legacy = LossRequest {
        format: 1,
        source_kind: None,
        abandoned_request: None,
        ..blind
    };
    refused(
        f.j.decide_loss(
            legacy.clone(),
            &w.loss_token(&legacy, 91),
            150,
            &w.trust(),
            &p,
        ),
        "open decided transition must be abandoned or sourced",
    );
}

#[test]
fn rollback_is_refused_once_the_survivor_has_acknowledged() {
    let w = World::new();
    let p = Authority::default();
    let f = in_flight(&w, &p);
    let digest = f.maintenance.digest().unwrap();
    f.j.acknowledge(&f.decision, &f.maintenance.participants[1], &w.trust(), &p)
        .unwrap();

    let loss = w.loss(
        &w.first,
        &f.first_token,
        0,
        3,
        SourceKind::Completed,
        Some(digest),
    );
    refused(
        f.j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p),
        "abandoned transition already applied by the survivor",
    );
}

#[test]
fn finish_forward_is_refused_when_the_lost_member_already_acknowledged() {
    let w = World::new();
    let p = Authority::default();
    let f = in_flight(&w, &p);
    let digest = f.maintenance.digest().unwrap();
    // The member about to be lost acknowledged first.
    f.j.acknowledge(&f.decision, &f.maintenance.participants[0], &w.trust(), &p)
        .unwrap();

    let loss = LossRequest {
        source_token_digest: f.decision.token_digest(),
        ..w.loss(&f.maintenance, "", 0, 3, SourceKind::Decided, Some(digest))
    };
    refused(
        f.j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p),
        "lost participant already acknowledged; complete the transition instead",
    );
}

#[test]
fn finish_forward_needs_an_open_decided_head_and_its_exact_digest() {
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);

    // A completed head cannot be finished forward.
    let on_completed = w.loss(
        &w.first,
        &first_token,
        0,
        2,
        SourceKind::Decided,
        Some(w.first.digest().unwrap()),
    );
    refused(
        j.decide_loss(
            on_completed.clone(),
            &w.loss_token(&on_completed, 91),
            150,
            &w.trust(),
            &p,
        ),
        "decided transition required",
    );
    drop(j);

    let w2 = World::new();
    let p = Authority::default();
    let f = in_flight(&w2, &p);
    for abandoned in [None, Some([99u8; 32])] {
        let bad = LossRequest {
            source_token_digest: f.decision.token_digest(),
            ..w2.loss(&f.maintenance, "", 0, 3, SourceKind::Decided, abandoned)
        };
        refused(
            f.j.decide_loss(bad.clone(), &w2.loss_token(&bad, 91), 150, &w2.trust(), &p),
            "abandoned request must name the decided transition",
        );
    }
}

#[test]
fn a_rollback_needs_a_completed_record_below_the_abandoned_one() {
    let w = World::new();
    let p = Authority::default();
    // The journal's only record is the decided one.
    let j = Journal::create(&w.path("authority"), "pass", w.scope()).unwrap();
    let token = w.transition_token(&w.first);
    j.decide(w.first.clone(), &token, 150, &w.trust(), &p)
        .unwrap();
    let loss = w.loss(
        &w.first,
        &token,
        0,
        2,
        SourceKind::Completed,
        Some(w.first.digest().unwrap()),
    );
    refused(
        j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p),
        "completed transition required",
    );
}

#[test]
fn a_successor_journal_accepts_neither_decided_nor_an_abandoned_request() {
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);
    let loss = w.loss(&w.first, &first_token, 0, 2, SourceKind::Completed, None);
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
        .unwrap();
    let s = Journal::create_loss_successor(
        &w.path("successor"),
        "pass",
        w.successor_scope(&loss),
        &j,
        &w.trust(),
        &p,
    )
    .unwrap();

    let decided = LossRequest {
        source_kind: Some(SourceKind::Decided),
        abandoned_request: Some([77; 32]),
        revision: 4,
        ..loss.clone()
    };
    refused(
        s.decide_loss(
            decided.clone(),
            &w.loss_token(&decided, 92),
            150,
            &w.trust(),
            &p,
        ),
        "decided transition required",
    );
    // A successor-sourced loss may not carry the field at all: the shape
    // clauses refuse it before any journal state is consulted.
    let sourced = LossRequest {
        source_kind: Some(SourceKind::LossSuccessor),
        abandoned_request: Some([77; 32]),
        revision: 4,
        ..loss
    };
    assert_eq!(sourced.validate(), Err("invalid participant loss request"));
    refused(
        s.decide_loss(
            sourced.clone(),
            &w.loss_token(committed.request(), 92),
            150,
            &w.trust(),
            &p,
        ),
        "invalid participant loss request",
    );
}

// -------------------------------------------------- interaction with S6/S10

#[test]
fn a_maintenance_abort_first_then_a_plain_loss_and_never_the_other_way_round() {
    let w = World::new();
    let p = Authority::default();
    let f = in_flight(&w, &p);

    // S6 abort of the decided head: the effective head reverts to revision 1.
    let abort = MaintenanceAbort {
        format: 2,
        id: [50; 32],
        authority_id: w.first.authority_id,
        revision: 2,
        install: w.first.install.clone(),
        region: w.first.region.clone(),
        scope: w.first.scope,
        schema: w.first.schema,
        membership: w.first.membership,
        aborted_request: f.maintenance.digest().unwrap(),
        aborted_request_id: f.maintenance.id,
        aborted_revision: 2,
        decided: true,
        source_anchor: w.first.source_anchor.clone(),
    };
    let abort_token = sign(
        &w.k,
        ABORT_TOKEN_TYPE,
        &json!({"version":1,"iss":"issuer","aud":"aud","action":"abort_compact_pair",
                "certificate_id":([77;32]),"iat":100,"nbf":100,"exp":200,
                "request":abort,"request_digest":abort.digest().unwrap()}),
    );
    f.j.abort(abort.clone(), &abort_token, 150, &w.trust(), &p)
        .unwrap();

    // With the head aborted there is no open decided transition left, so an
    // ordinary loss needs no `abandoned_request` — but it still takes the
    // revision after the one the abort burnt.
    let loss = w.loss(&w.first, &f.first_token, 0, 3, SourceKind::Completed, None);
    let committed =
        f.j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
            .unwrap();
    assert_eq!(
        f.j.status(&w.trust()).unwrap().request,
        Some(w.first.clone())
    );

    // And once the loss is decided, no further abort may be recorded.
    let late = MaintenanceAbort {
        id: [51; 32],
        revision: 4,
        aborted_revision: 4,
        decided: false,
        ..abort
    };
    let late_token = sign(
        &w.k,
        ABORT_TOKEN_TYPE,
        &json!({"version":1,"iss":"issuer","aud":"aud","action":"abort_compact_pair",
                "certificate_id":([78;32]),"iat":100,"nbf":100,"exp":200,
                "request":late,"request_digest":late.digest().unwrap()}),
    );
    refused(
        f.j.abort(late, &late_token, 150, &w.trust(), &p),
        "maintenance abort superseded by participant loss",
    );
    w.recover(&f.j, &loss, &committed, &p);
}

#[test]
fn supersession_works_on_top_of_both_a_rollback_and_a_finish_forward() {
    for kind in [SourceKind::Completed, SourceKind::Decided] {
        let w = World::new();
        let p = Authority::default();
        let f = in_flight(&w, &p);
        let digest = f.maintenance.digest().unwrap();
        if kind == SourceKind::Decided {
            f.j.acknowledge(&f.decision, &f.maintenance.participants[1], &w.trust(), &p)
                .unwrap();
        }
        let loss = if kind == SourceKind::Decided {
            LossRequest {
                source_token_digest: f.decision.token_digest(),
                ..w.loss(&f.maintenance, "", 0, 3, kind, Some(digest))
            }
        } else {
            w.loss(&w.first, &f.first_token, 0, 3, kind, Some(digest))
        };
        let committed =
            f.j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
                .unwrap();

        // Found the successor journal, decide and abort its successor.
        let s = Journal::create_loss_successor(
            &w.path("successor"),
            "pass",
            w.successor_scope(&loss),
            &f.j,
            &w.trust(),
            &p,
        )
        .unwrap();
        let request = w.successor(&loss, &committed, 60);
        let token = w.successor_token(&request, 95);
        s.decide_loss_successor(request.clone(), &token, 150, &w.trust(), &p)
            .unwrap();
        let abort = LossSuccessorAbort {
            format: 2,
            id: [70; 32],
            authority_id: request.authority_id,
            revision: request.revision,
            install: request.install.clone(),
            region: request.region.clone(),
            scope: request.scope,
            schema: request.schema,
            membership: request.membership,
            parent_loss_certificate: committed.certificate_id(),
            parent_loss_token_digest: committed.token_digest(),
            successor_id: request.id,
            successor_certificate: [95; 32],
            successor_token_digest: sha(&token),
            fencing_ref: [71; 32],
        };
        let abort_token = sign(
            &w.k,
            LOSS_SUCCESSOR_ABORT_TOKEN_TYPE,
            &json!({"version":1,"iss":"issuer","aud":"aud","action":"abort_loss_successor",
                    "certificate_id":([79;32]),"iat":100,"nbf":100,"exp":200,
                    "request":abort,"request_digest":abort.digest().unwrap()}),
        );
        let committed_abort = s
            .abort_loss_successor(abort, &abort_token, 150, &w.trust(), &p)
            .unwrap();

        // The superseding loss keeps `abandoned_request` identical.
        let next = LossRequest {
            id: [80; 32],
            revision: loss.revision + 1,
            replacement_member: [81; 32],
            replacement_generation: [82; 32],
            replacement_membership: [83; 32],
            supersedes: Some(Supersedes {
                loss_certificate: committed.certificate_id(),
                loss_token_digest: committed.token_digest(),
                abort_certificate: committed_abort.certificate_id(),
                abort_token_digest: committed_abort.token_digest(),
            }),
            ..loss.clone()
        };
        f.j.decide_loss(next.clone(), &w.loss_token(&next, 92), 150, &w.trust(), &p)
            .unwrap();
        assert_eq!(f.j.fetch_loss(&w.trust(), &p).unwrap().request(), &next);
        assert_eq!(next.abandoned_request, Some(digest));

        // Dropping the abandonment on the way through is refused — by the
        // source layer, which re-runs for every superseding loss too.
        let forgetful = LossRequest {
            id: [84; 32],
            abandoned_request: None,
            replacement_member: [85; 32],
            replacement_generation: [86; 32],
            replacement_membership: [87; 32],
            revision: next.revision + 1,
            ..next
        };
        refused(
            f.j.decide_loss(
                forgetful.clone(),
                &w.loss_token(&forgetful, 93),
                150,
                &w.trust(),
                &p,
            ),
            if kind == SourceKind::Decided {
                "abandoned request must name the decided transition"
            } else {
                "open decided transition must be abandoned or sourced"
            },
        );
    }
}

#[test]
fn a_supersession_may_not_quietly_change_which_request_was_abandoned() {
    // The A2 shape: the journal cannot see the abandoned request at all, so
    // only the identical-fields rule stops a supersession from swapping it.
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);
    let abandoned = w.maintenance().digest().unwrap();
    let loss = w.loss(
        &w.first,
        &first_token,
        0,
        2,
        SourceKind::Completed,
        Some(abandoned),
    );
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
        .unwrap();

    let swapped = LossRequest {
        id: [80; 32],
        revision: 3,
        abandoned_request: Some([88; 32]),
        replacement_member: [81; 32],
        replacement_generation: [82; 32],
        replacement_membership: [83; 32],
        supersedes: Some(Supersedes {
            loss_certificate: committed.certificate_id(),
            loss_token_digest: committed.token_digest(),
            abort_certificate: [84; 32],
            abort_token_digest: [85; 32],
        }),
        ..loss.clone()
    };
    refused(
        j.decide_loss(
            swapped.clone(),
            &w.loss_token(&swapped, 92),
            150,
            &w.trust(),
            &p,
        ),
        "superseding loss changes more than the replacement",
    );
    let kept = LossRequest {
        abandoned_request: Some(abandoned),
        ..swapped
    };
    assert!(j
        .decide_loss(kept.clone(), &w.loss_token(&kept, 92), 150, &w.trust(), &p)
        .is_ok());
}
