//! S10 — successor abort and superseding loss.
//!
//! A participant loss installs a replacement *before* anyone can acknowledge
//! it, so a wrong replacement — wrong hardware, wrong site, compromised — used
//! to be permanent: the successor journal was the only door out of a loss and
//! it only opened forwards. The abort makes that journal terminal, and the
//! superseding `LossRequest` lets the authority try a different replacement
//! without re-deciding who was lost.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde_json::{json, Value};
use std::{cell::Cell, path::Path};
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

fn table_exists(path: &Path, name: &str) -> bool {
    let raw = terrapi_vesta::Vesta::open(path, "pass").unwrap();
    raw.with_connection(|c| {
        c.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [name],
            |r| r.get(0),
        )
    })
    .unwrap()
}

struct Authority {
    ok: Cell<bool>,
    installed: Cell<u8>,
    abort_ok: Cell<bool>,
    superseded_ok: Cell<bool>,
}
impl Default for Authority {
    fn default() -> Self {
        Self {
            ok: Cell::new(true),
            installed: Cell::new(0),
            abort_ok: Cell::new(true),
            superseded_ok: Cell::new(true),
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
    fn successor_abort_authorized(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &LossSuccessorRequest,
        _: &LossSuccessorAbort,
    ) -> Result<()> {
        if self.abort_ok.get() {
            Ok(())
        } else {
            Err("replacement not fenced".into())
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
}

/// An integration that overrides neither of the S10 hooks.
struct Unaware;
impl LossPolicy for Unaware {
    fn continuity_and_fencing(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        Ok(())
    }
    fn survivor_prepared(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        Ok(())
    }
    fn loss_successor_applied(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &LossSuccessorRequest,
        _: &Participant,
    ) -> Result<()> {
        Ok(())
    }
    fn loss_successor_continuity(&self, _: &JournalScope, _: &LossSuccessorRequest) -> Result<()> {
        Ok(())
    }
}

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
    fn abort_claims(&self, a: &LossSuccessorAbort, certificate: u8) -> Value {
        json!({"version":1,"iss":"issuer","aud":"aud","action":"abort_loss_successor",
               "certificate_id":([certificate;32]),"iat":100,"nbf":100,"exp":200,
               "request":a,"request_digest":a.digest().unwrap()})
    }
    fn abort_token(&self, a: &LossSuccessorAbort, certificate: u8) -> String {
        sign(
            &self.k,
            LOSS_SUCCESSOR_ABORT_TOKEN_TYPE,
            &self.abort_claims(a, certificate),
        )
    }

    /// The first loss: the primary dies.
    fn first_loss(&self) -> LossRequest {
        let gone = &self.first.participants[0];
        let alive = &self.first.participants[1];
        LossRequest {
            format: 2,
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
            source_kind: Some(SourceKind::Completed),
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

    /// A format-2 successor whose replacement takes the primary slot.
    fn successor(
        &self,
        loss: &LossRequest,
        committed: &CommittedLoss,
        id: u8,
        plan: u8,
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
                    plan: [plan; 32],
                    publication: loss.survivor_publication,
                },
                Participant {
                    member: loss.survivor.member,
                    generation: loss.survivor.generation,
                    old_base: loss.survivor.old_base.clone(),
                    target: loss.survivor_cut.clone(),
                    plan: [plan; 32],
                    publication: loss.survivor_publication,
                },
            ],
            survivor_index: Some(1),
        }
    }

    fn abort_of(
        &self,
        parent: &CommittedLoss,
        successor: &LossSuccessorRequest,
        successor_certificate: u8,
        successor_token: &str,
        id: u8,
    ) -> LossSuccessorAbort {
        LossSuccessorAbort {
            format: 2,
            id: [id; 32],
            authority_id: successor.authority_id,
            revision: successor.revision,
            install: successor.install.clone(),
            region: successor.region.clone(),
            scope: successor.scope,
            schema: successor.schema,
            membership: successor.membership,
            parent_loss_certificate: parent.certificate_id(),
            parent_loss_token_digest: parent.token_digest(),
            successor_id: successor.id,
            successor_certificate: [successor_certificate; 32],
            successor_token_digest: sha(successor_token),
            fencing_ref: [id.wrapping_add(100); 32],
        }
    }

    /// A loss that replaces only the replacement of `previous`.
    fn superseding(
        &self,
        previous: &LossRequest,
        previous_committed: &CommittedLoss,
        abort: &CommittedLossSuccessorAbort,
        id: u8,
        replacement: u8,
    ) -> LossRequest {
        LossRequest {
            id: [id; 32],
            revision: previous.revision + 1,
            replacement_member: [replacement; 32],
            replacement_generation: [replacement.wrapping_add(1); 32],
            replacement_membership: [replacement.wrapping_add(2); 32],
            supersedes: Some(Supersedes {
                loss_certificate: previous_committed.certificate_id(),
                loss_token_digest: previous_committed.token_digest(),
                abort_certificate: abort.certificate_id(),
                abort_token_digest: abort.token_digest(),
            }),
            ..previous.clone()
        }
    }
}

/// A journal, a loss, a successor journal and a decided successor in it.
struct Installed {
    j: Journal,
    a: Journal,
    loss: LossRequest,
    committed: CommittedLoss,
    successor: LossSuccessorRequest,
    successor_token: String,
    decision: CommittedLossSuccessorTransition,
}

/// `acks` = how many participants have acknowledged the successor.
fn installed(w: &World, p: &Authority, acks: usize) -> Installed {
    let j = w.certified(p);
    let loss = w.first_loss();
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 27), 150, &w.trust(), p)
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
    let successor = w.successor(&loss, &committed, 40, 42);
    let successor_token = w.successor_token(&successor, 45);
    let decision = a
        .decide_loss_successor(successor.clone(), &successor_token, 150, &w.trust(), p)
        .unwrap();
    p.installed.set(0b11);
    for m in successor.participants.iter().take(acks) {
        a.acknowledge_loss_successor(&decision, m, &w.trust(), p)
            .unwrap();
    }
    Installed {
        j,
        a,
        loss,
        committed,
        successor,
        successor_token,
        decision,
    }
}

fn abort_it(w: &World, i: &Installed, p: &Authority, id: u8) -> CommittedLossSuccessorAbort {
    let abort = w.abort_of(&i.committed, &i.successor, 45, &i.successor_token, id);
    i.a.abort_loss_successor(
        abort.clone(),
        &w.abort_token(&abort, 77),
        150,
        &w.trust(),
        p,
    )
    .unwrap()
}

// ---------------------------------------------------------------- positive

#[test]
fn a_successor_can_be_aborted_at_any_point_before_completion() {
    for acks in [0usize, 1, 2] {
        let w = World::new();
        let p = Authority::default();
        let i = installed(&w, &p, acks);
        assert_eq!(
            i.a.fetch_loss_successor(&i.successor, &w.trust(), &p)
                .unwrap()
                .acknowledgements()
                .iter()
                .filter(|a| **a)
                .count(),
            acks
        );
        assert!(!table_exists(
            &w.path("successor-a"),
            "transition_loss_successor_abort"
        ));

        let committed = abort_it(&w, &i, &p, 50);
        assert_eq!(committed.successor_id(), i.successor.id);
        assert_eq!(committed.certificate_id(), [77; 32]);
        assert_eq!(committed.fencing_ref(), [150; 32]);
        assert!(table_exists(
            &w.path("successor-a"),
            "transition_loss_successor_abort"
        ));

        // The journal is terminal, but the survivor can still read the abort
        // it needs in order to un-install.
        let fetched =
            i.a.fetch_loss_successor_abort(&i.successor, &w.trust(), &p)
                .unwrap();
        assert_eq!(fetched.token_digest(), committed.token_digest());
        drop(i.a);
        let a = Journal::open(
            &w.path("successor-a"),
            "pass",
            w.successor_scope(&i.loss),
            &w.trust(),
        )
        .unwrap();
        assert_eq!(
            a.fetch_loss_successor_abort(&i.successor, &w.trust(), &p)
                .unwrap()
                .abort(),
            committed.abort()
        );
    }
}

#[test]
fn an_exact_abort_retry_converges_before_and_after_reopening_the_journal() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 1);
    let abort = w.abort_of(&i.committed, &i.successor, 45, &i.successor_token, 50);
    let token = w.abort_token(&abort, 77);
    let first =
        i.a.abort_loss_successor(abort.clone(), &token, 150, &w.trust(), &p)
            .unwrap();
    let retry =
        i.a.abort_loss_successor(abort.clone(), &token, 150, &w.trust(), &p)
            .unwrap();
    assert_eq!(retry.token_digest(), first.token_digest());
    drop(i.a);

    let a = Journal::open(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&i.loss),
        &w.trust(),
    )
    .unwrap();
    // The crash window is resumable with the by-then expired token.
    invalid(
        verify_successor_abort_issuance(&token, &w.trust(), &abort, 400),
        "time window",
    );
    assert_eq!(
        a.abort_loss_successor(abort.clone(), &token, 400, &w.trust(), &p)
            .unwrap()
            .token_digest(),
        first.token_digest()
    );
    // Any difference is an immutable conflict.
    let resigned = w.abort_token(&abort, 77);
    assert_ne!(resigned, token);
    refused(
        a.abort_loss_successor(abort.clone(), &resigned, 150, &w.trust(), &p),
        "immutable loss successor abort conflict",
    );
    let mut renamed = abort;
    renamed.id = [59; 32];
    refused(
        a.abort_loss_successor(
            renamed.clone(),
            &w.abort_token(&renamed, 77),
            150,
            &w.trust(),
            &p,
        ),
        "immutable loss successor abort conflict",
    );
}

#[test]
fn an_abort_is_followed_by_a_superseding_loss_and_a_fresh_successor_journal() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 1);
    let abort = abort_it(&w, &i, &p, 50);
    assert!(!table_exists(&w.path("authority"), "transition_loss_chain"));

    let next = w.superseding(&i.loss, &i.committed, &abort, 60, 70);
    let next_token = w.loss_token(&next, 91);
    let committed_next =
        i.j.decide_loss(next.clone(), &next_token, 150, &w.trust(), &p)
            .unwrap();
    assert_eq!(next.revision, 3);
    assert!(table_exists(&w.path("authority"), "transition_loss_chain"));
    // The effective loss is the superseding one.
    assert_eq!(i.j.fetch_loss(&w.trust(), &p).unwrap().request(), &next);
    // Exact retry converges.
    assert_eq!(
        i.j.decide_loss(next.clone(), &next_token, 150, &w.trust(), &p)
            .unwrap()
            .token_digest(),
        committed_next.token_digest()
    );

    // The old successor journal cannot be re-founded and cannot be used.
    refused(
        Journal::create_loss_successor(
            &w.path("successor-a"),
            "pass",
            w.successor_scope(&i.loss),
            &i.j,
            &w.trust(),
            &p,
        ),
        "replacement journal scope mismatch",
    );
    refused(
        Journal::create_loss_successor(
            &w.path("successor-a"),
            "pass",
            w.successor_scope(&next),
            &i.j,
            &w.trust(),
            &p,
        ),
        "successor initialization is not pristine",
    );
    refused(
        i.a.fetch_loss_successor(&i.successor, &w.trust(), &p),
        "loss successor aborted",
    );

    // A brand new successor journal on the new membership works normally.
    let scope_b = w.successor_scope(&next);
    assert_eq!(scope_b.initial_revision, 4);
    let b = Journal::create_loss_successor(
        &w.path("successor-b"),
        "pass",
        scope_b.clone(),
        &i.j,
        &w.trust(),
        &p,
    )
    .unwrap();
    let sb = w.successor(&next, &committed_next, 80, 82);
    let sb_token = w.successor_token(&sb, 95);
    let d = b
        .decide_loss_successor(sb.clone(), &sb_token, 150, &w.trust(), &p)
        .unwrap();
    p.installed.set(0b11);
    for m in &sb.participants {
        b.acknowledge_loss_successor(&d, m, &w.trust(), &p).unwrap();
    }
    b.complete_loss_successor(&d, [96; 32], &w.trust(), &p)
        .unwrap();
    assert_eq!(
        b.fetch_completed_loss_successor(&sb, &w.trust(), &p)
            .unwrap()
            .completion(),
        [96; 32]
    );

    // Everything survives a reopen of both the source and the new successor.
    drop(i.j);
    drop(b);
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    assert_eq!(j.fetch_loss(&w.trust(), &p).unwrap().request(), &next);
    let b = Journal::open(&w.path("successor-b"), "pass", scope_b, &w.trust()).unwrap();
    assert_eq!(
        b.fetch_completed_loss_successor(&sb, &w.trust(), &p)
            .unwrap()
            .completion(),
        [96; 32]
    );
}

#[test]
fn two_supersessions_in_a_row_keep_the_chain_linked_and_monotonic() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    let abort = abort_it(&w, &i, &p, 50);

    let second = w.superseding(&i.loss, &i.committed, &abort, 60, 70);
    let committed_second =
        i.j.decide_loss(
            second.clone(),
            &w.loss_token(&second, 91),
            150,
            &w.trust(),
            &p,
        )
        .unwrap();

    // Found the second successor journal, then abort it too.
    let b = Journal::create_loss_successor(
        &w.path("successor-b"),
        "pass",
        w.successor_scope(&second),
        &i.j,
        &w.trust(),
        &p,
    )
    .unwrap();
    let sb = w.successor(&second, &committed_second, 80, 82);
    let sb_token = w.successor_token(&sb, 95);
    b.decide_loss_successor(sb.clone(), &sb_token, 150, &w.trust(), &p)
        .unwrap();
    let abort_b = w.abort_of(&committed_second, &sb, 95, &sb_token, 51);
    let committed_abort_b = b
        .abort_loss_successor(
            abort_b.clone(),
            &w.abort_token(&abort_b, 78),
            150,
            &w.trust(),
            &p,
        )
        .unwrap();

    let third = w.superseding(&second, &committed_second, &committed_abort_b, 61, 73);
    assert_eq!(third.revision, 4);
    i.j.decide_loss(
        third.clone(),
        &w.loss_token(&third, 92),
        150,
        &w.trust(),
        &p,
    )
    .unwrap();
    assert_eq!(i.j.fetch_loss(&w.trust(), &p).unwrap().request(), &third);

    // A third supersession may not resurrect any earlier replacement.
    for replacement in [24u8, 70] {
        let replay = w.superseding(
            &third,
            &committed_second,
            &committed_abort_b,
            62,
            replacement,
        );
        // (binding is checked first, so point it at the right previous loss)
        let replay = LossRequest {
            supersedes: Some(Supersedes {
                loss_certificate: i.j.fetch_loss(&w.trust(), &p).unwrap().certificate_id(),
                loss_token_digest: i.j.fetch_loss(&w.trust(), &p).unwrap().token_digest(),
                abort_certificate: committed_abort_b.certificate_id(),
                abort_token_digest: committed_abort_b.token_digest(),
            }),
            ..replay
        };
        refused(
            i.j.decide_loss(
                replay.clone(),
                &w.loss_token(&replay, 93),
                150,
                &w.trust(),
                &p,
            ),
            "superseding loss reuses a retired replacement",
        );
    }
    drop(i.j);
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    assert_eq!(j.fetch_loss(&w.trust(), &p).unwrap().request(), &third);
}

#[test]
fn a_supersession_works_on_top_of_a_loss_sourced_from_a_successor() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    p.installed.set(0b11);
    for m in &i.successor.participants {
        i.a.acknowledge_loss_successor(&i.decision, m, &w.trust(), &p)
            .unwrap();
    }
    i.a.complete_loss_successor(&i.decision, [60; 32], &w.trust(), &p)
        .unwrap();

    // Second loss, anchored to the completed successor, decided in journal A.
    let gone = &i.successor.participants[1];
    let alive = &i.successor.participants[0];
    let loss2 = LossRequest {
        id: [50; 32],
        revision: 4,
        membership: i.loss.replacement_membership,
        source_certificate: [45; 32],
        source_token_digest: sha(&i.successor_token),
        source_cut: i.successor.survivor_cut.clone(),
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
        supersedes: None,
        ..i.loss.clone()
    };
    let committed2 =
        i.a.decide_loss(
            loss2.clone(),
            &w.loss_token(&loss2, 91),
            150,
            &w.trust(),
            &p,
        )
        .unwrap();

    // Found its successor journal, decide, abort it.
    let c = Journal::create_loss_successor(
        &w.path("successor-c"),
        "pass",
        w.successor_scope(&loss2),
        &i.a,
        &w.trust(),
        &p,
    )
    .unwrap();
    let sc = w.successor(&loss2, &committed2, 80, 82);
    let sc_token = w.successor_token(&sc, 95);
    c.decide_loss_successor(sc.clone(), &sc_token, 150, &w.trust(), &p)
        .unwrap();
    let abort_c = w.abort_of(&committed2, &sc, 95, &sc_token, 52);
    let committed_abort_c = c
        .abort_loss_successor(
            abort_c.clone(),
            &w.abort_token(&abort_c, 79),
            150,
            &w.trust(),
            &p,
        )
        .unwrap();

    // Supersede the LossSuccessor-sourced loss inside journal A.
    let loss3 = w.superseding(&loss2, &committed2, &committed_abort_c, 63, 74);
    assert_eq!(loss3.revision, 5);
    assert_eq!(loss3.kind(), SourceKind::LossSuccessor);
    i.a.decide_loss(
        loss3.clone(),
        &w.loss_token(&loss3, 92),
        150,
        &w.trust(),
        &p,
    )
    .unwrap();
    assert_eq!(i.a.fetch_loss(&w.trust(), &p).unwrap().request(), &loss3);
}

// ---------------------------------------------------------------- negative

#[test]
fn a_completed_successor_can_never_be_aborted_and_an_aborted_one_never_completed() {
    // Completion first: the abort loses the race.
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 2);
    let other = Journal::open(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&i.loss),
        &w.trust(),
    )
    .unwrap();
    i.a.complete_loss_successor(&i.decision, [60; 32], &w.trust(), &p)
        .unwrap();
    let abort = w.abort_of(&i.committed, &i.successor, 45, &i.successor_token, 50);
    refused(
        other.abort_loss_successor(
            abort.clone(),
            &w.abort_token(&abort, 77),
            150,
            &w.trust(),
            &p,
        ),
        "completed loss successor cannot be aborted",
    );

    // Abort first: the completion loses the race.
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 2);
    let other = Journal::open(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&i.loss),
        &w.trust(),
    )
    .unwrap();
    abort_it(&w, &i, &p, 50);
    refused(
        other.complete_loss_successor(&i.decision, [60; 32], &w.trust(), &p),
        "loss successor aborted",
    );
}

#[test]
fn every_successor_operation_is_closed_after_an_abort() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 1);
    abort_it(&w, &i, &p, 50);

    let closed = "loss successor aborted";
    let check = |a: &Journal| {
        refused(a.fetch_loss_successor(&i.successor, &w.trust(), &p), closed);
        refused(
            a.fetch_completed_loss_successor(&i.successor, &w.trust(), &p),
            closed,
        );
        refused(
            a.acknowledge_loss_successor(&i.decision, &i.successor.participants[1], &w.trust(), &p),
            closed,
        );
        refused(
            a.complete_loss_successor(&i.decision, [60; 32], &w.trust(), &p),
            closed,
        );
        refused(
            a.decide_loss_successor(i.successor.clone(), &i.successor_token, 150, &w.trust(), &p),
            closed,
        );
        // An aborted successor can never source a further loss either.
        let mut sourced = i.loss.clone();
        sourced.source_kind = Some(SourceKind::LossSuccessor);
        sourced.revision = 4;
        refused(
            a.decide_loss(
                sourced.clone(),
                &w.loss_token(&sourced, 91),
                150,
                &w.trust(),
                &p,
            ),
            closed,
        );
        // Reading the abort itself keeps working: that is the un-install path.
        assert!(a
            .fetch_loss_successor_abort(&i.successor, &w.trust(), &p)
            .is_ok());
    };
    check(&i.a);
    drop(i.a);
    let a = Journal::open(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&i.loss),
        &w.trust(),
    )
    .unwrap();
    check(&a);
}

#[test]
fn an_abort_must_name_the_exact_successor_and_parent_loss() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    let good = w.abort_of(&i.committed, &i.successor, 45, &i.successor_token, 50);
    assert!(good.validate().is_ok());

    for bad in [
        LossSuccessorAbort {
            successor_id: [99; 32],
            ..good.clone()
        },
        LossSuccessorAbort {
            successor_certificate: [99; 32],
            ..good.clone()
        },
        LossSuccessorAbort {
            successor_token_digest: [99; 32],
            ..good.clone()
        },
        LossSuccessorAbort {
            revision: 9,
            ..good.clone()
        },
    ] {
        refused(
            i.a.abort_loss_successor(bad.clone(), &w.abort_token(&bad, 77), 150, &w.trust(), &p),
            "loss successor abort binding mismatch",
        );
    }
    for bad in [
        LossSuccessorAbort {
            parent_loss_certificate: [99; 32],
            ..good.clone()
        },
        LossSuccessorAbort {
            parent_loss_token_digest: [99; 32],
            ..good.clone()
        },
        LossSuccessorAbort {
            membership: [99; 32],
            ..good.clone()
        },
        LossSuccessorAbort {
            scope: [99; 32],
            ..good.clone()
        },
    ] {
        refused(
            i.a.abort_loss_successor(bad.clone(), &w.abort_token(&bad, 77), 150, &w.trust(), &p),
            "loss successor abort parent binding",
        );
    }
    // Nothing was recorded by any of them.
    assert!(!table_exists(
        &w.path("successor-a"),
        "transition_loss_successor_abort"
    ));
    for bad in [
        LossSuccessorAbort {
            format: 1,
            ..good.clone()
        },
        LossSuccessorAbort {
            id: [0; 32],
            ..good.clone()
        },
        LossSuccessorAbort {
            fencing_ref: [0; 32],
            ..good.clone()
        },
        LossSuccessorAbort {
            install: "  ".into(),
            ..good.clone()
        },
        LossSuccessorAbort {
            revision: 0,
            ..good.clone()
        },
    ] {
        invalid(bad.validate(), "invalid loss successor abort");
        invalid(bad.digest(), "invalid loss successor abort");
    }
}

#[test]
fn abort_tokens_must_carry_the_right_purpose_key_and_validity_window() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    let abort = w.abort_of(&i.committed, &i.successor, 45, &i.successor_token, 50);
    let attacker = key();
    let mut wrong_action = w.abort_claims(&abort, 77);
    wrong_action["action"] = json!("activate_loss_successor");

    for (token, expected) in [
        (
            sign(
                &attacker,
                LOSS_SUCCESSOR_ABORT_TOKEN_TYPE,
                &w.abort_claims(&abort, 77),
            ),
            "signature",
        ),
        (
            sign(&w.k, LOSS_SUCCESSOR_TOKEN_TYPE, &w.abort_claims(&abort, 77)),
            "header purpose",
        ),
        (
            sign(&w.k, LOSS_SUCCESSOR_ABORT_TOKEN_TYPE, &wrong_action),
            "claim purpose",
        ),
    ] {
        refused(
            i.a.abort_loss_successor(abort.clone(), &token, 150, &w.trust(), &p),
            expected,
        );
    }
    let token = w.abort_token(&abort, 77);
    for now in [250u64, 50] {
        refused(
            i.a.abort_loss_successor(abort.clone(), &token, now, &w.trust(), &p),
            "time window",
        );
    }
    refused(
        i.a.abort_loss_successor(abort.clone(), &"x".repeat(65 * 1024), 150, &w.trust(), &p),
        "token limit",
    );
    assert!(!table_exists(
        &w.path("successor-a"),
        "transition_loss_successor_abort"
    ));
    assert!(i
        .a
        .abort_loss_successor(abort, &token, 150, &w.trust(), &p)
        .is_ok());
}

#[test]
fn the_default_policy_refuses_both_the_abort_and_the_supersession() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    let abort = w.abort_of(&i.committed, &i.successor, 45, &i.successor_token, 50);
    refused(
        i.a.abort_loss_successor(
            abort.clone(),
            &w.abort_token(&abort, 77),
            150,
            &w.trust(),
            &Unaware,
        ),
        "loss successor abort evidence missing",
    );
    p.abort_ok.set(false);
    refused(
        i.a.abort_loss_successor(
            abort.clone(),
            &w.abort_token(&abort, 77),
            150,
            &w.trust(),
            &p,
        ),
        "replacement not fenced",
    );
    p.abort_ok.set(true);
    let committed = abort_it(&w, &i, &p, 50);

    let next = w.superseding(&i.loss, &i.committed, &committed, 60, 70);
    refused(
        i.j.decide_loss(
            next.clone(),
            &w.loss_token(&next, 91),
            150,
            &w.trust(),
            &Unaware,
        ),
        "superseded loss abort evidence missing",
    );
    // A superseding loss whose abort cannot be found in the other journal.
    p.superseded_ok.set(false);
    refused(
        i.j.decide_loss(next.clone(), &w.loss_token(&next, 91), 150, &w.trust(), &p),
        "no abort in the successor journal",
    );
    assert!(!table_exists(&w.path("authority"), "transition_loss_chain"));
    p.superseded_ok.set(true);
    assert!(i
        .j
        .decide_loss(next.clone(), &w.loss_token(&next, 91), 150, &w.trust(), &p)
        .is_ok());
}

#[test]
fn a_superseding_loss_may_change_nothing_but_the_replacement() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    let abort = abort_it(&w, &i, &p, 50);
    let good = w.superseding(&i.loss, &i.committed, &abort, 60, 70);

    // Fields the source binding owns are caught by it first: the superseding
    // loss still has to be a valid loss against the same certified source.
    for (bad, expected) in [
        (
            LossRequest {
                lost_member: [98; 32],
                ..good.clone()
            },
            "lost participant mismatch",
        ),
        (
            LossRequest {
                lost_generation: [98; 32],
                ..good.clone()
            },
            "lost participant mismatch",
        ),
        (
            LossRequest {
                source_certificate: [98; 32],
                ..good.clone()
            },
            "loss source mismatch",
        ),
        (
            LossRequest {
                source_token_digest: [98; 32],
                ..good.clone()
            },
            "loss source mismatch",
        ),
        (
            LossRequest {
                membership: [98; 32],
                ..good.clone()
            },
            "loss source mismatch",
        ),
        (
            LossRequest {
                source_kind: Some(SourceKind::LossSuccessor),
                ..good.clone()
            },
            "ordinary successor history forbidden",
        ),
        (
            LossRequest {
                survivor: Participant {
                    old_base: Some(cp(1, 1)),
                    ..good.survivor.clone()
                },
                ..good.clone()
            },
            "loss participant/revision mismatch",
        ),
    ] {
        refused(
            i.j.decide_loss(bad.clone(), &w.loss_token(&bad, 91), 150, &w.trust(), &p),
            expected,
        );
    }

    // Everything else that describes the loss rather than the replacement is
    // caught by the supersession clause itself.
    for bad in [
        LossRequest {
            survivor: Participant {
                plan: [98; 32],
                ..good.survivor.clone()
            },
            ..good.clone()
        },
        LossRequest {
            survivor_cut: cp(26, 28),
            survivor: Participant {
                target: cp(26, 28),
                ..good.survivor.clone()
            },
            ..good.clone()
        },
        LossRequest {
            survivor_publication: [98; 32],
            survivor: Participant {
                publication: [98; 32],
                ..good.survivor.clone()
            },
            ..good.clone()
        },
    ] {
        refused(
            i.j.decide_loss(bad.clone(), &w.loss_token(&bad, 91), 150, &w.trust(), &p),
            "superseding loss changes more than the replacement",
        );
    }

    // The replacement triple must actually change.
    for bad in [
        LossRequest {
            replacement_member: i.loss.replacement_member,
            ..good.clone()
        },
        LossRequest {
            replacement_generation: i.loss.replacement_generation,
            ..good.clone()
        },
        LossRequest {
            replacement_membership: i.loss.replacement_membership,
            ..good.clone()
        },
    ] {
        refused(
            i.j.decide_loss(bad.clone(), &w.loss_token(&bad, 91), 150, &w.trust(), &p),
            "superseding loss reuses a retired replacement",
        );
    }

    // `supersedes` must name the current effective loss.
    for bad in [
        LossRequest {
            supersedes: Some(Supersedes {
                loss_certificate: [98; 32],
                ..good.supersedes.clone().unwrap()
            }),
            ..good.clone()
        },
        LossRequest {
            supersedes: Some(Supersedes {
                loss_token_digest: [98; 32],
                ..good.supersedes.clone().unwrap()
            }),
            ..good.clone()
        },
    ] {
        refused(
            i.j.decide_loss(bad.clone(), &w.loss_token(&bad, 91), 150, &w.trust(), &p),
            "superseded loss binding mismatch",
        );
    }

    // A wrong revision is still a revision error.
    for revision in [2u64, 4] {
        let bad = LossRequest {
            revision,
            ..good.clone()
        };
        refused(
            i.j.decide_loss(bad.clone(), &w.loss_token(&bad, 91), 150, &w.trust(), &p),
            "loss participant/revision mismatch",
        );
    }
    assert!(!table_exists(&w.path("authority"), "transition_loss_chain"));

    // And once recorded, the superseded loss is no longer nameable.
    i.j.decide_loss(good.clone(), &w.loss_token(&good, 91), 150, &w.trust(), &p)
        .unwrap();
    let stale = w.superseding(&good, &i.committed, &abort, 62, 75);
    refused(
        i.j.decide_loss(
            stale.clone(),
            &w.loss_token(&stale, 92),
            150,
            &w.trust(),
            &p,
        ),
        "superseded loss binding mismatch",
    );
    // A non-superseding loss can never follow one either.
    let plain = LossRequest {
        id: [63; 32],
        supersedes: None,
        ..stale
    };
    refused(
        i.j.decide_loss(
            plain.clone(),
            &w.loss_token(&plain, 93),
            150,
            &w.trust(),
            &p,
        ),
        "immutable loss decision conflict",
    );
}

// ----------------------------------------------------- durable fail-closed

fn plant(path: &Path, sql: &str, args: &[&dyn rusqlite::ToSql]) {
    let raw = terrapi_vesta::Vesta::open(path, "pass").unwrap();
    raw.with_connection(|c| {
        c.execute(sql, args)?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn a_tampered_or_oversized_abort_row_fails_the_successor_journal_closed() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    abort_it(&w, &i, &p, 50);
    drop(i.a);
    plant(
        &w.path("successor-a"),
        "UPDATE main.transition_loss_successor_abort SET digest=zeroblob(32)",
        &[],
    );
    let a = Journal::open(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&i.loss),
        &w.trust(),
    )
    .unwrap();
    // A tampered abort row must never read as "no abort".
    let expected = "loss successor abort integrity";
    refused(
        a.fetch_loss_successor(&i.successor, &w.trust(), &p),
        expected,
    );
    refused(
        a.fetch_loss_successor_abort(&i.successor, &w.trust(), &p),
        expected,
    );
    refused(
        a.complete_loss_successor(&i.decision, [60; 32], &w.trust(), &p),
        expected,
    );

    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    abort_it(&w, &i, &p, 50);
    drop(i.a);
    let huge = "x".repeat(256 * 1024 + 1);
    plant(
        &w.path("successor-a"),
        "UPDATE main.transition_loss_successor_abort SET record=?1,digest=?2",
        &[
            &huge,
            &<sha2::Sha256 as sha2::Digest>::digest(huge.as_bytes()).to_vec(),
        ],
    );
    let a = Journal::open(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&i.loss),
        &w.trust(),
    )
    .unwrap();
    refused(
        a.fetch_loss_successor_abort(&i.successor, &w.trust(), &p),
        "loss successor abort integrity",
    );
}

#[test]
fn a_tampered_broken_or_overfull_loss_chain_fails_the_source_journal_closed() {
    // (a) digest tampering on a genuine chain row.
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    let abort = abort_it(&w, &i, &p, 50);
    let next = w.superseding(&i.loss, &i.committed, &abort, 60, 70);
    i.j.decide_loss(next.clone(), &w.loss_token(&next, 91), 150, &w.trust(), &p)
        .unwrap();
    drop(i.j);
    plant(
        &w.path("authority"),
        "UPDATE main.transition_loss_chain SET digest=zeroblob(32)",
        &[],
    );
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    refused(j.fetch_loss(&w.trust(), &p), "loss record integrity");

    // (b) a chain row planted at a revision that does not follow the root.
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    let abort = abort_it(&w, &i, &p, 50);
    let next = w.superseding(&i.loss, &i.committed, &abort, 60, 70);
    i.j.decide_loss(next.clone(), &w.loss_token(&next, 91), 150, &w.trust(), &p)
        .unwrap();
    drop(i.j);
    plant(
        &w.path("authority"),
        "UPDATE main.transition_loss_chain SET revision=9 WHERE revision=3",
        &[],
    );
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    refused(j.fetch_loss(&w.trust(), &p), "loss chain revision mismatch");

    // (c) more rows than the hard cap, rejected before any decode.
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 0);
    abort_it(&w, &i, &p, 50);
    drop(i.j);
    let raw = terrapi_vesta::Vesta::open(w.path("authority"), "pass").unwrap();
    raw.with_connection(|c| {
        c.execute_batch("CREATE TABLE IF NOT EXISTS main.transition_loss_chain(revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32)); BEGIN;")?;
        for revision in 0..4097u64 {
            c.execute(
                "INSERT INTO main.transition_loss_chain VALUES(?1,'{}',zeroblob(32))",
                [revision],
            )?;
        }
        c.execute_batch("COMMIT;")?;
        Ok(())
    })
    .unwrap();
    drop(raw);
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    refused(j.fetch_loss(&w.trust(), &p), "loss chain row limit");
}

// ------------------------------------------------------------ compatibility

#[test]
fn a_journal_that_never_aborts_or_supersedes_never_grows_the_new_tables() {
    let w = World::new();
    let p = Authority::default();
    let i = installed(&w, &p, 2);
    i.a.complete_loss_successor(&i.decision, [60; 32], &w.trust(), &p)
        .unwrap();

    for (path, table) in [
        (w.path("authority"), "transition_loss_chain"),
        (w.path("successor-a"), "transition_loss_successor_abort"),
        (w.path("successor-a"), "transition_loss_chain"),
    ] {
        assert!(!table_exists(&path, table), "{table} must not exist");
    }
    assert_eq!(
        i.a.fetch_completed_loss_successor(&i.successor, &w.trust(), &p)
            .unwrap()
            .completion(),
        [60; 32]
    );
    assert_eq!(i.j.fetch_loss(&w.trust(), &p).unwrap().request(), &i.loss);
    refused(
        i.a.fetch_loss_successor_abort(&i.successor, &w.trust(), &p),
        "loss successor abort missing",
    );
    drop(i.a);
    drop(i.j);
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    assert_eq!(j.fetch_loss(&w.trust(), &p).unwrap().request(), &i.loss);
    let a = Journal::open(
        &w.path("successor-a"),
        "pass",
        w.successor_scope(&i.loss),
        &w.trust(),
    )
    .unwrap();
    assert_eq!(
        a.fetch_completed_loss_successor(&i.successor, &w.trust(), &p)
            .unwrap()
            .completion(),
        [60; 32]
    );
    assert!(!table_exists(&w.path("authority"), "transition_loss_chain"));
}
