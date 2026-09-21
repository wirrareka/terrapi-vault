//! S12 — fixes from the independent adversarial review.
//!
//! The headline finding: a binary that predates format 2 cannot see
//! `transition_abort`, `transition_loss_chain` or
//! `transition_loss_successor_abort`, so it would read a cancelled transition
//! as live, hand a writer proof out for an aborted successor, or treat a
//! superseded loss as current. Nothing in the old format made it fail closed.
//! The fix is a one-way marker in the stored scope row, which every old reader
//! already decodes with `deny_unknown_fields`.
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

/// The raw stored scope row.
fn scope_row(path: &Path) -> String {
    let raw = terrapi_vesta::Vesta::open(path, "pass").unwrap();
    raw.with_connection(|c| {
        c.query_row("SELECT record FROM transition_scope WHERE id=1", [], |r| {
            r.get(0)
        })
    })
    .unwrap()
}

fn write_scope_row(path: &Path, record: &str) {
    let raw = terrapi_vesta::Vesta::open(path, "pass").unwrap();
    raw.with_connection(|c| {
        c.execute("UPDATE transition_scope SET record=?1 WHERE id=1", [record])?;
        Ok(())
    })
    .unwrap();
}

/// Exactly what a pre-format-2 binary did with the scope row: a strict
/// `deny_unknown_fields` decode of `JournalScope`. This is the downgrade
/// oracle — if it still succeeds, an old binary would happily carry on.
fn old_binary_accepts(path: &Path) -> bool {
    serde_json::from_str::<JournalScope>(&scope_row(path)).is_ok()
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
    fn abort_applicable(&self, _: &JournalScope, _: &MaintenanceAbort) -> Result<()> {
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
    fn maintenance_rollback_authorized(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &[u8; 32],
    ) -> Result<()> {
        Ok(())
    }
    fn maintenance_finish_forward_authorized(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &[u8; 32],
    ) -> Result<()> {
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
        Ok(())
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
    fn superseded_successor_aborted(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &Supersedes,
    ) -> Result<()> {
        Ok(())
    }
}

/// Implements every hook an ordinary loss needs, and nothing more: used to
/// prove that branch B is gated by a hook of its own.
struct OrdinaryOnly;
impl LossPolicy for OrdinaryOnly {
    fn continuity_and_fencing(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        Ok(())
    }
    fn survivor_prepared(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        Ok(())
    }
    fn maintenance_rollback_authorized(
        &self,
        _: &JournalScope,
        _: &LossRequest,
        _: &[u8; 32],
    ) -> Result<()> {
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
    fn abort_token(&self, a: &MaintenanceAbort, certificate: u8) -> String {
        sign(
            &self.k,
            ABORT_TOKEN_TYPE,
            &json!({"version":1,"iss":"issuer","aud":"aud","action":"abort_compact_pair",
                    "certificate_id":([certificate;32]),"iat":100,"nbf":100,"exp":200,
                    "request":a,"request_digest":a.digest().unwrap()}),
        )
    }
    fn successor_abort_token(&self, a: &LossSuccessorAbort, certificate: u8) -> String {
        sign(
            &self.k,
            LOSS_SUCCESSOR_ABORT_TOKEN_TYPE,
            &json!({"version":1,"iss":"issuer","aud":"aud","action":"abort_loss_successor",
                    "certificate_id":([certificate;32]),"iat":100,"nbf":100,"exp":200,
                    "request":a,"request_digest":a.digest().unwrap()}),
        )
    }

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

    fn abort_of(&self, target: &Request, id: u8) -> MaintenanceAbort {
        MaintenanceAbort {
            format: 2,
            id: [id; 32],
            authority_id: self.first.authority_id,
            revision: target.revision,
            install: self.first.install.clone(),
            region: self.first.region.clone(),
            scope: self.first.scope,
            schema: self.first.schema,
            membership: self.first.membership,
            aborted_request: target.digest().unwrap(),
            aborted_request_id: target.id,
            aborted_revision: target.revision,
            decided: true,
            source_anchor: self.first.source_anchor.clone(),
        }
    }

    fn loss(
        &self,
        source: &Request,
        source_token: &str,
        revision: u64,
        kind: SourceKind,
        abandoned: Option<[u8; 32]>,
        replacement: u8,
    ) -> LossRequest {
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
            lost_member: source.participants[0].member,
            lost_generation: source.participants[0].generation,
            survivor: Participant {
                member: source.participants[1].member,
                generation: source.participants[1].generation,
                old_base: source.participants[1].old_base.clone(),
                target: cp(35, 36),
                plan: source.participants[1].plan,
                publication: [29; 32],
            },
            survivor_cut: cp(35, 36),
            survivor_publication: [29; 32],
            replacement_membership: [replacement.wrapping_add(2); 32],
            replacement_member: [replacement; 32],
            replacement_generation: [replacement.wrapping_add(1); 32],
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
}

// ------------------------------------------------- F1: one-way format marker

#[test]
fn f1_a_decided_head_abort_locks_old_binaries_out_of_the_journal() {
    let w = World::new();
    let p = Authority::default();
    let (j, _) = w.certified(&p);
    // Before: byte-identical to a format-1 journal.
    let before = scope_row(&w.path("authority"));
    assert!(old_binary_accepts(&w.path("authority")));

    let maintenance = w.maintenance();
    j.decide(
        maintenance.clone(),
        &w.transition_token(&maintenance),
        150,
        &w.trust(),
        &p,
    )
    .unwrap();
    // A decided-head abort leaves `transition_head` untouched, so an old
    // reader would see a cancelled transition as the live head and hand out a
    // writer proof for it.
    assert_eq!(scope_row(&w.path("authority")), before);
    let abort = w.abort_of(&maintenance, 50);
    j.abort(
        abort.clone(),
        &w.abort_token(&abort, 77),
        150,
        &w.trust(),
        &p,
    )
    .unwrap();

    assert_ne!(scope_row(&w.path("authority")), before);
    assert!(!old_binary_accepts(&w.path("authority")));
    // The new reader is unaffected.
    assert_eq!(j.status(&w.trust()).unwrap().aborted, 1);
    drop(j);
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    assert_eq!(j.status(&w.trust()).unwrap().request, Some(w.first.clone()));
}

#[test]
fn f1_a_successor_abort_and_a_supersession_lock_old_binaries_out() {
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);
    let loss = w.loss(&w.first, &first_token, 2, SourceKind::Completed, None, 70);
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
        .unwrap();
    // A loss alone is format-1 state; both journals stay readable.
    assert!(old_binary_accepts(&w.path("authority")));

    let s = Journal::create_loss_successor(
        &w.path("successor"),
        "pass",
        w.successor_scope(&loss),
        &j,
        &w.trust(),
        &p,
    )
    .unwrap();
    assert!(old_binary_accepts(&w.path("successor")));
    let request = w.successor(&loss, &committed, 60);
    let token = w.successor_token(&request, 95);
    s.decide_loss_successor(request.clone(), &token, 150, &w.trust(), &p)
        .unwrap();
    assert!(old_binary_accepts(&w.path("successor")));

    // (b) successor abort — an old binary would hand out a writer proof for
    // an aborted successor.
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
    let committed_abort = s
        .abort_loss_successor(
            abort.clone(),
            &w.successor_abort_token(&abort, 79),
            150,
            &w.trust(),
            &p,
        )
        .unwrap();
    assert!(!old_binary_accepts(&w.path("successor")));

    // (c) supersession — an old binary would treat the superseded loss as live.
    assert!(old_binary_accepts(&w.path("authority")));
    let next = LossRequest {
        id: [80; 32],
        revision: 3,
        replacement_member: [81; 32],
        replacement_generation: [82; 32],
        replacement_membership: [83; 32],
        supersedes: Some(Supersedes {
            loss_certificate: committed.certificate_id(),
            loss_token_digest: committed.token_digest(),
            abort_certificate: committed_abort.certificate_id(),
            abort_token_digest: committed_abort.token_digest(),
        }),
        ..loss
    };
    j.decide_loss(next.clone(), &w.loss_token(&next, 92), 150, &w.trust(), &p)
        .unwrap();
    assert!(!old_binary_accepts(&w.path("authority")));
    assert_eq!(j.fetch_loss(&w.trust(), &p).unwrap().request(), &next);
}

#[test]
fn f1_a_marker_stripped_or_a_table_without_a_marker_fails_the_new_reader_closed() {
    let w = World::new();
    let p = Authority::default();
    let (j, _) = w.certified(&p);
    let format_one = scope_row(&w.path("authority"));
    let maintenance = w.maintenance();
    j.decide(
        maintenance.clone(),
        &w.transition_token(&maintenance),
        150,
        &w.trust(),
        &p,
    )
    .unwrap();
    let abort = w.abort_of(&maintenance, 50);
    j.abort(
        abort.clone(),
        &w.abort_token(&abort, 77),
        150,
        &w.trust(),
        &p,
    )
    .unwrap();
    drop(j);

    // Strip the marker but keep the format-2 table: fail closed.
    write_scope_row(&w.path("authority"), &format_one);
    refused(
        Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()),
        "format-2 journal state without format marker",
    );
    // A marker that is not 2 is not a marker.
    let mut wrong: Value = serde_json::from_str(&format_one).unwrap();
    wrong
        .as_object_mut()
        .unwrap()
        .insert("journal_format".into(), json!(3));
    write_scope_row(&w.path("authority"), &wrong.to_string());
    refused(
        Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()),
        "transition journal format",
    );
    // A marker on a journal with no format-2 state is simply accepted.
    let w2 = World::new();
    let p2 = Authority::default();
    let (j2, _) = w2.certified(&p2);
    drop(j2);
    let mut marked: Value = serde_json::from_str(&scope_row(&w2.path("authority"))).unwrap();
    marked
        .as_object_mut()
        .unwrap()
        .insert("journal_format".into(), json!(2));
    write_scope_row(&w2.path("authority"), &marked.to_string());
    let j2 = Journal::open(&w2.path("authority"), "pass", w2.scope(), &w2.trust()).unwrap();
    assert_eq!(j2.status(&w2.trust()).unwrap().last_revision, 1);
}

#[test]
fn f1_a_journal_that_uses_no_format_two_table_keeps_its_scope_row_byte_identical() {
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);
    let before = scope_row(&w.path("authority"));

    // A full ordinary cycle plus a plain loss and a whole successor recovery.
    let loss = w.loss(&w.first, &first_token, 2, SourceKind::Completed, None, 70);
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
    let successor_before = scope_row(&w.path("successor"));
    let request = w.successor(&loss, &committed, 60);
    let token = w.successor_token(&request, 95);
    let d = s
        .decide_loss_successor(request.clone(), &token, 150, &w.trust(), &p)
        .unwrap();
    p.installed.set(0b11);
    for m in &request.participants {
        s.acknowledge_loss_successor(&d, m, &w.trust(), &p).unwrap();
    }
    s.complete_loss_successor(&d, [96; 32], &w.trust(), &p)
        .unwrap();

    assert_eq!(scope_row(&w.path("authority")), before);
    assert_eq!(scope_row(&w.path("successor")), successor_before);
    assert!(old_binary_accepts(&w.path("authority")));
    assert!(old_binary_accepts(&w.path("successor")));
}

// ------------------------------------------- F2: branch B has its own hook

#[test]
fn f2_finish_forward_is_denied_by_a_policy_that_implements_every_other_hook() {
    let w = World::new();
    let p = Authority::default();
    let (j, _) = w.certified(&p);
    let maintenance = w.maintenance();
    let d = j
        .decide(
            maintenance.clone(),
            &w.transition_token(&maintenance),
            150,
            &w.trust(),
            &p,
        )
        .unwrap();
    j.acknowledge(&d, &maintenance.participants[1], &w.trust(), &p)
        .unwrap();

    let loss = LossRequest {
        source_token_digest: d.token_digest(),
        ..w.loss(
            &maintenance,
            "",
            3,
            SourceKind::Decided,
            Some(maintenance.digest().unwrap()),
            70,
        )
    };
    refused(
        j.decide_loss(
            loss.clone(),
            &w.loss_token(&loss, 91),
            150,
            &w.trust(),
            &OrdinaryOnly,
        ),
        "maintenance finish-forward evidence missing",
    );
    // The same policy is enough for an ordinary rollback.
    let rollback = w.loss(
        &w.first,
        &w.transition_token(&w.first),
        3,
        SourceKind::Completed,
        Some(maintenance.digest().unwrap()),
        70,
    );
    refused(
        j.decide_loss(
            rollback.clone(),
            &w.loss_token(&rollback, 91),
            150,
            &w.trust(),
            &OrdinaryOnly,
        ),
        // stopped later, by the survivor acknowledgement, not by a hook
        "abandoned transition already applied by the survivor",
    );
}

// --------------------------------------- F3: A and B are mutually exclusive

#[test]
fn f3_the_same_journal_state_can_never_satisfy_both_loss_branches() {
    // No acknowledgement at all: rollback yes, finish forward no.
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);
    let maintenance = w.maintenance();
    let d = j
        .decide(
            maintenance.clone(),
            &w.transition_token(&maintenance),
            150,
            &w.trust(),
            &p,
        )
        .unwrap();
    let digest = maintenance.digest().unwrap();
    let forward = LossRequest {
        source_token_digest: d.token_digest(),
        ..w.loss(&maintenance, "", 3, SourceKind::Decided, Some(digest), 70)
    };
    refused(
        j.decide_loss(
            forward.clone(),
            &w.loss_token(&forward, 91),
            150,
            &w.trust(),
            &p,
        ),
        "finish forward requires the survivor acknowledgement",
    );
    let back = w.loss(
        &w.first,
        &first_token,
        3,
        SourceKind::Completed,
        Some(digest),
        70,
    );
    assert!(j
        .decide_loss(back.clone(), &w.loss_token(&back, 91), 150, &w.trust(), &p)
        .is_ok());

    // Survivor acknowledged: finish forward yes, rollback no.
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);
    let maintenance = w.maintenance();
    let d = j
        .decide(
            maintenance.clone(),
            &w.transition_token(&maintenance),
            150,
            &w.trust(),
            &p,
        )
        .unwrap();
    j.acknowledge(&d, &maintenance.participants[1], &w.trust(), &p)
        .unwrap();
    let back = w.loss(
        &w.first,
        &first_token,
        3,
        SourceKind::Completed,
        Some(digest),
        70,
    );
    refused(
        j.decide_loss(back.clone(), &w.loss_token(&back, 91), 150, &w.trust(), &p),
        "abandoned transition already applied by the survivor",
    );
    let forward = LossRequest {
        source_token_digest: d.token_digest(),
        ..w.loss(&maintenance, "", 3, SourceKind::Decided, Some(digest), 70)
    };
    assert!(j
        .decide_loss(
            forward.clone(),
            &w.loss_token(&forward, 91),
            150,
            &w.trust(),
            &p
        )
        .is_ok());
}

// -------------------------------------------- F4: the loss chain is bound

/// A journal whose loss has been superseded once.
fn superseded(w: &World, p: &Authority) -> (Journal, LossRequest) {
    let (j, first_token) = w.certified(p);
    let loss = w.loss(&w.first, &first_token, 2, SourceKind::Completed, None, 70);
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), p)
        .unwrap();
    let next = LossRequest {
        id: [80; 32],
        revision: 3,
        replacement_member: [84; 32],
        replacement_generation: [85; 32],
        replacement_membership: [86; 32],
        supersedes: Some(Supersedes {
            loss_certificate: committed.certificate_id(),
            loss_token_digest: committed.token_digest(),
            abort_certificate: [87; 32],
            abort_token_digest: [88; 32],
        }),
        ..loss
    };
    j.decide_loss(next.clone(), &w.loss_token(&next, 92), 150, &w.trust(), p)
        .unwrap();
    (j, next)
}

fn raw_exec(path: &Path, sql: &str) {
    let raw = terrapi_vesta::Vesta::open(path, "pass").unwrap();
    raw.with_connection(|c| {
        c.execute(sql, [])?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn f4_truncating_the_loss_chain_can_never_resurrect_a_superseded_replacement() {
    // Deleting the last chain row would silently revert to the superseded
    // loss, and with it to a replacement that was aborted.
    let w = World::new();
    let p = Authority::default();
    let (j, next) = superseded(&w, &p);
    assert_eq!(j.fetch_loss(&w.trust(), &p).unwrap().request(), &next);
    drop(j);
    raw_exec(
        &w.path("authority"),
        "DELETE FROM main.transition_loss_chain",
    );
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    refused(j.fetch_loss(&w.trust(), &p), "loss chain truncated");

    // Deleting the head row instead.
    let w = World::new();
    let p = Authority::default();
    let (j, _) = superseded(&w, &p);
    drop(j);
    raw_exec(
        &w.path("authority"),
        "DELETE FROM main.transition_loss_head",
    );
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    refused(j.fetch_loss(&w.trust(), &p), "loss chain head missing");

    // A head that claims a row the chain does not have.
    let w = World::new();
    let p = Authority::default();
    let (j, _) = superseded(&w, &p);
    drop(j);
    raw_exec(
        &w.path("authority"),
        "UPDATE main.transition_loss_head SET rows=2",
    );
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    refused(j.fetch_loss(&w.trust(), &p), "loss chain truncated");

    // A head pointing at a revision that is not the chain tail.
    let w = World::new();
    let p = Authority::default();
    let (j, _) = superseded(&w, &p);
    drop(j);
    raw_exec(
        &w.path("authority"),
        "UPDATE main.transition_loss_head SET revision=9",
    );
    let j = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    refused(j.fetch_loss(&w.trust(), &p), "loss chain truncated");
}

// ----------------------------------- F5: retired identities are transitive

#[test]
fn f5_a_member_lost_three_losses_ago_can_never_come_back() {
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);

    // Loss 1 retires member [6], generation [7] and membership [5].
    let loss = w.loss(&w.first, &first_token, 2, SourceKind::Completed, None, 70);
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
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
    let request = w.successor(&loss, &committed, 60);
    let token = w.successor_token(&request, 95);
    let d = a
        .decide_loss_successor(request.clone(), &token, 150, &w.trust(), &p)
        .unwrap();
    p.installed.set(0b11);
    for m in &request.participants {
        a.acknowledge_loss_successor(&d, m, &w.trust(), &p).unwrap();
    }
    a.complete_loss_successor(&d, [96; 32], &w.trust(), &p)
        .unwrap();

    // Loss 2, sourced from the completed successor, must refuse the member,
    // the generation and the membership retired by loss 1 — each on its own.
    let gone = &request.participants[1];
    let alive = &request.participants[0];
    let base = LossRequest {
        id: [50; 32],
        revision: 4,
        membership: loss.replacement_membership,
        source_certificate: [95; 32],
        source_token_digest: sha(&token),
        source_cut: request.survivor_cut.clone(),
        lost_member: gone.member,
        lost_generation: gone.generation,
        survivor: Participant {
            member: alive.member,
            generation: alive.generation,
            old_base: alive.old_base.clone(),
            target: cp(40, 41),
            plan: alive.plan,
            publication: [34; 32],
        },
        survivor_cut: cp(40, 41),
        survivor_publication: [34; 32],
        replacement_membership: [90; 32],
        replacement_member: [91; 32],
        replacement_generation: [92; 32],
        source_kind: Some(SourceKind::LossSuccessor),
        supersedes: None,
        abandoned_request: None,
        ..loss.clone()
    };
    for bad in [
        LossRequest {
            // the member lost by the FIRST loss, with a brand new generation
            replacement_member: w.first.participants[0].member,
            ..base.clone()
        },
        LossRequest {
            replacement_generation: w.first.participants[0].generation,
            ..base.clone()
        },
        LossRequest {
            // the original membership
            replacement_membership: w.first.membership,
            ..base.clone()
        },
    ] {
        refused(
            a.decide_loss(bad.clone(), &w.loss_token(&bad, 93), 150, &w.trust(), &p),
            "loss replacement reuses a retired identity",
        );
    }
    let committed2 = a
        .decide_loss(base.clone(), &w.loss_token(&base, 93), 150, &w.trust(), &p)
        .unwrap();

    // And the successor journal it founds refuses them too.
    let b = Journal::create_loss_successor(
        &w.path("successor-b"),
        "pass",
        w.successor_scope(&base),
        &a,
        &w.trust(),
        &p,
    )
    .unwrap();
    let mut replay = w.successor(&base, &committed2, 61);
    replay.participants[0].member = w.first.participants[0].member;
    refused(
        b.decide_loss_successor(
            replay.clone(),
            &w.successor_token(&replay, 97),
            150,
            &w.trust(),
            &p,
        ),
        "replacement transition reuses a retired identity",
    );
}

// ------------------------------------ F6/F8: abort scope and abort lookup

#[test]
fn f6_a_maintenance_abort_is_not_available_in_a_successor_journal() {
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);
    let loss = w.loss(&w.first, &first_token, 2, SourceKind::Completed, None, 70);
    j.decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
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
    let abort = MaintenanceAbort {
        membership: loss.replacement_membership,
        source_anchor: loss.source_cut.clone(),
        revision: 3,
        aborted_revision: 3,
        decided: false,
        ..w.abort_of(&w.maintenance(), 50)
    };
    refused(
        s.abort(
            abort.clone(),
            &w.abort_token(&abort, 77),
            150,
            &w.trust(),
            &p,
        ),
        "maintenance abort is not available in a successor journal",
    );
}

#[test]
fn f1_a_handle_opened_before_the_format_bump_still_sees_a_consistent_marker() {
    let w = World::new();
    let p = Authority::default();
    let (a, first_token) = w.certified(&p);
    let loss = w.loss(&w.first, &first_token, 2, SourceKind::Completed, None, 70);
    let committed = a
        .decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
        .unwrap();

    // Handle A predates every format-2 write on this file.
    let b = Journal::open(&w.path("authority"), "pass", w.scope(), &w.trust()).unwrap();
    assert!(old_binary_accepts(&w.path("authority")));
    let next = LossRequest {
        id: [80; 32],
        revision: 3,
        replacement_member: [84; 32],
        replacement_generation: [85; 32],
        replacement_membership: [86; 32],
        supersedes: Some(Supersedes {
            loss_certificate: committed.certificate_id(),
            loss_token_digest: committed.token_digest(),
            abort_certificate: [87; 32],
            abort_token_digest: [88; 32],
        }),
        ..loss.clone()
    };
    b.decide_loss(next.clone(), &w.loss_token(&next, 92), 150, &w.trust(), &p)
        .unwrap();
    assert!(!old_binary_accepts(&w.path("authority")));

    // A's next loss-side operation sees the superseding loss, not the one it
    // was opened on.
    assert_eq!(a.fetch_loss(&w.trust(), &p).unwrap().request(), &next);

    // Strip the marker behind A's back: A must fail closed on an entry point
    // that never goes through `read_with_revision`.
    let mut stripped: Value = serde_json::from_str(&scope_row(&w.path("authority"))).unwrap();
    stripped.as_object_mut().unwrap().remove("journal_format");
    write_scope_row(&w.path("authority"), &stripped.to_string());
    refused(
        a.fetch_loss(&w.trust(), &p),
        "format-2 journal state without format marker",
    );

    // Same story in a successor journal, whose abort A never saw either.
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);
    let loss = w.loss(&w.first, &first_token, 2, SourceKind::Completed, None, 70);
    let committed = j
        .decide_loss(loss.clone(), &w.loss_token(&loss, 91), 150, &w.trust(), &p)
        .unwrap();
    let a = Journal::create_loss_successor(
        &w.path("successor"),
        "pass",
        w.successor_scope(&loss),
        &j,
        &w.trust(),
        &p,
    )
    .unwrap();
    let request = w.successor(&loss, &committed, 60);
    let token = w.successor_token(&request, 95);
    let decision = a
        .decide_loss_successor(request.clone(), &token, 150, &w.trust(), &p)
        .unwrap();
    let b = Journal::open(
        &w.path("successor"),
        "pass",
        w.successor_scope(&loss),
        &w.trust(),
    )
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
    b.abort_loss_successor(
        abort.clone(),
        &w.successor_abort_token(&abort, 79),
        150,
        &w.trust(),
        &p,
    )
    .unwrap();

    // A refuses to complete, and can still read the abort it must act on.
    refused(
        a.complete_loss_successor(&decision, [96; 32], &w.trust(), &p),
        "loss successor aborted",
    );
    assert_eq!(
        a.fetch_loss_successor_abort(&request, &w.trust(), &p)
            .unwrap()
            .abort(),
        &abort
    );

    // Marker stripped behind A's back: every bypassing entry point closes.
    let mut stripped: Value = serde_json::from_str(&scope_row(&w.path("successor"))).unwrap();
    stripped.as_object_mut().unwrap().remove("journal_format");
    write_scope_row(&w.path("successor"), &stripped.to_string());
    let missing = "format-2 journal state without format marker";
    refused(
        a.fetch_loss_successor_abort(&request, &w.trust(), &p),
        missing,
    );
    refused(
        a.complete_loss_successor(&decision, [96; 32], &w.trust(), &p),
        missing,
    );
    refused(
        a.acknowledge_loss_successor(&decision, &request.participants[0], &w.trust(), &p),
        missing,
    );
    refused(
        a.fetch_completed_loss_successor(&request, &w.trust(), &p),
        missing,
    );
    refused(
        a.abort_loss_successor(
            abort.clone(),
            &w.successor_abort_token(&abort, 79),
            150,
            &w.trust(),
            &p,
        ),
        missing,
    );
}

// ------------------------ public verifiers for loss and successor tokens

#[test]
fn a_successor_and_its_loss_can_be_authenticated_without_their_journals() {
    let w = World::new();
    let p = Authority::default();
    let (j, first_token) = w.certified(&p);
    let loss = w.loss(&w.first, &first_token, 2, SourceKind::Completed, None, 70);
    let loss_token = w.loss_token(&loss, 91);
    let committed_loss = j
        .decide_loss(loss.clone(), &loss_token, 150, &w.trust(), &p)
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
    let request = w.successor(&loss, &committed_loss, 60);
    let token = w.successor_token(&request, 95);
    let decision = s
        .decide_loss_successor(request.clone(), &token, 150, &w.trust(), &p)
        .unwrap();

    // The token a real journal stored authenticates on its own, and yields
    // exactly the certificate id the journal proof exposes.
    assert_eq!(
        verify_successor_historical(decision.token(), &w.trust(), decision.request()).unwrap(),
        decision.certificate_id()
    );
    assert_eq!(
        verify_successor_issuance(decision.token(), &w.trust(), decision.request(), 150).unwrap(),
        decision.certificate_id()
    );
    assert_eq!(
        verify_loss_historical(committed_loss.token(), &w.trust(), committed_loss.request())
            .unwrap(),
        committed_loss.certificate_id()
    );
    assert_eq!(
        verify_loss_issuance(&loss_token, &w.trust(), &loss, 150).unwrap(),
        committed_loss.certificate_id()
    );
    // The role the second loss needs is derivable from the request alone.
    assert_eq!(decision.request().survivor_index().unwrap(), 1);

    // A format-1 successor, stored by a real journal, verifies the same way.
    let w1 = World::new();
    let p1 = Authority::default();
    let (j1, first_token1) = w1.certified(&p1);
    let loss1 = w1.loss(&w1.first, &first_token1, 2, SourceKind::Completed, None, 70);
    let committed1 = j1
        .decide_loss(
            loss1.clone(),
            &w1.loss_token(&loss1, 91),
            150,
            &w1.trust(),
            &p1,
        )
        .unwrap();
    let s1 = Journal::create_loss_successor(
        &w1.path("successor"),
        "pass",
        w1.successor_scope(&loss1),
        &j1,
        &w1.trust(),
        &p1,
    )
    .unwrap();
    let mut legacy = w1.successor(&loss1, &committed1, 60);
    legacy.format = 1;
    legacy.survivor_index = None;
    legacy.participants.swap(0, 1); // format 1 fixes [survivor, replacement]
    let legacy_token = w1.successor_token(&legacy, 95);
    let legacy_decision = s1
        .decide_loss_successor(legacy.clone(), &legacy_token, 150, &w1.trust(), &p1)
        .unwrap();
    assert_eq!(
        verify_successor_historical(&legacy_token, &w1.trust(), &legacy).unwrap(),
        legacy_decision.certificate_id()
    );

    // Purpose, signer, time window and request binding are all enforced.
    let attacker = key();
    let mut wrong_action = json!({"version":1,"iss":"issuer","aud":"aud",
        "action":"abort_loss_successor","certificate_id":([95;32]),
        "iat":100,"nbf":100,"exp":200,"request":request,
        "request_digest":request.digest().unwrap()});
    wrong_action["action"] = json!("compact_pair");
    let mut tampered = request.clone();
    tampered.id = [99; 32];
    let mut reindexed = request.clone();
    reindexed.survivor_index = Some(0);
    for (t, expected) in [
        (
            sign(
                &w.k,
                LOSS_TOKEN_TYPE,
                &json!({"version":1,"iss":"issuer","aud":"aud",
                "action":"activate_loss_successor","certificate_id":([95;32]),
                "iat":100,"nbf":100,"exp":200,"request":request,
                "request_digest":request.digest().unwrap()}),
            ),
            "header purpose",
        ),
        (
            sign(&w.k, LOSS_SUCCESSOR_TOKEN_TYPE, &wrong_action),
            "claim purpose",
        ),
        (w1.successor_token(&request, 95), "signature"),
        (
            sign(
                &attacker,
                LOSS_SUCCESSOR_TOKEN_TYPE,
                &json!({"version":1,"iss":"issuer",
                "aud":"aud","action":"activate_loss_successor","certificate_id":([95;32]),
                "iat":100,"nbf":100,"exp":200,"request":request,
                "request_digest":request.digest().unwrap()}),
            ),
            "signature",
        ),
    ] {
        assert_eq!(
            verify_successor_historical(&t, &w.trust(), &request).err(),
            Some(expected)
        );
    }
    assert_eq!(
        verify_successor_historical(&token, &w.trust(), &tampered).err(),
        Some("request binding")
    );
    // Swapping the survivor index makes the request itself inadmissible, so
    // the role can never be reinterpreted by the caller.
    assert_eq!(
        verify_successor_historical(&token, &w.trust(), &reindexed).err(),
        Some("invalid loss successor request")
    );
    assert_eq!(
        verify_successor_issuance(&token, &w.trust(), &request, 400).err(),
        Some("time window")
    );
    assert_eq!(
        verify_loss_historical(&loss_token, &w.trust(), &loss1).err(),
        Some("request binding")
    );
}

#[test]
fn f8_a_recorded_abort_is_always_findable_by_the_node_that_prepared_it() {
    let w = World::new();
    let p = Authority::default();
    let (j, _) = w.certified(&p);

    // The abort consumes `last_revision + 1`, which need not be the revision
    // the abandoned request was issued for. The lookup must not care.
    let mut prepared = w.maintenance();
    prepared.revision = 7;
    prepared.id = [45; 32];
    let abort = MaintenanceAbort {
        revision: 2,
        aborted_revision: 2,
        decided: false,
        aborted_request: prepared.digest().unwrap(),
        aborted_request_id: prepared.id,
        ..w.abort_of(&w.maintenance(), 50)
    };
    assert_ne!(abort.aborted_revision, prepared.revision);
    j.abort(
        abort.clone(),
        &w.abort_token(&abort, 77),
        150,
        &w.trust(),
        &p,
    )
    .unwrap();
    let fetched = j.fetch_abort(&prepared, &w.trust(), &p).unwrap();
    assert_eq!(fetched.abort(), &abort);

    // A different request is still not found.
    let other = w.maintenance();
    refused(
        j.fetch_abort(&other, &w.trust(), &p),
        "maintenance abort missing",
    );
}
