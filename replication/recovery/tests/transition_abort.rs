//! S6 — journal abort primitives.
//!
//! An expired authority token after a certified PREPARE used to leave both
//! nodes permanently unopenable: the decision could neither be finished nor
//! replaced. These tests pin the contract of the escape hatch: an abort burns
//! a journal revision for ever, reverts the *effective* head to the last
//! completed certificate, and can never be mistaken for a transition.
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

fn profile() -> Profile {
    Profile {
        issuer: "issuer".into(),
        audience: "aud".into(),
        token_type: TOKEN_TYPE.into(),
    }
}

fn anchor() -> Checkpoint {
    Checkpoint {
        sequence: 10,
        digest: [10; 32],
    }
}

fn first_request() -> Request {
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
        source_anchor: anchor(),
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
                old_base: Some(anchor()),
                target,
                plan: [8; 32],
                publication: [13; 32],
            },
        ],
    }
}

/// A request at `revision` that chains its data lineage to `base` — which is
/// the *effective* head, not necessarily the previous revision.
fn chained(base: &Request, revision: u64, id: u8) -> Request {
    let mut r = base.clone();
    r.id = [id; 32];
    r.revision = revision;
    let seq = 20 + revision * 10;
    let target = Checkpoint {
        sequence: seq,
        digest: [id.wrapping_add(80); 32],
    };
    for m in &mut r.participants {
        m.old_base = Some(base.participants[0].target.clone());
        m.target = target.clone();
        m.plan = [id.wrapping_add(60); 32];
    }
    r
}

fn scope_of(r: &Request) -> JournalScope {
    JournalScope {
        install: r.install.clone(),
        region: r.region.clone(),
        profile: profile(),
        scope: r.scope,
        schema: r.schema,
        membership: r.membership,
        source_anchor: r.source_anchor.clone(),
        authority_id: r.authority_id,
        initial_revision: 1,
    }
}

fn certificate_of(r: &Request) -> [u8; 32] {
    [u8::try_from(r.revision).unwrap().wrapping_add(100); 32]
}

fn transition_token(k: &signature::EcdsaKeyPair, r: &Request) -> String {
    sign(
        k,
        TOKEN_TYPE,
        &json!({"version":1,"iss":"issuer","aud":"aud","action":"compact_pair",
                "certificate_id":certificate_of(r),"iat":100,"nbf":100,"exp":200,
                "request":r,"request_digest":r.digest().unwrap()}),
    )
}

/// Cancellation of a decided record.
fn abort_of(scope: &JournalScope, target: &Request, id: u8) -> MaintenanceAbort {
    MaintenanceAbort {
        format: 2,
        id: [id; 32],
        authority_id: scope.authority_id,
        revision: target.revision,
        install: scope.install.clone(),
        region: scope.region.clone(),
        scope: scope.scope,
        schema: scope.schema,
        membership: scope.membership,
        aborted_request: target.digest().unwrap(),
        aborted_request_id: target.id,
        aborted_revision: target.revision,
        decided: true,
        source_anchor: scope.source_anchor.clone(),
    }
}

/// Cancellation of an attempt that was prepared but never decided: it takes
/// the next free revision so the counter stays monotonic.
fn abort_undecided(
    scope: &JournalScope,
    never_decided: &Request,
    revision: u64,
    id: u8,
) -> MaintenanceAbort {
    MaintenanceAbort {
        decided: false,
        revision,
        aborted_revision: revision,
        ..abort_of(scope, never_decided, id)
    }
}

fn sha(value: &str) -> [u8; 32] {
    <sha2::Sha256 as sha2::Digest>::digest(value.as_bytes()).into()
}

fn abort_claims(a: &MaintenanceAbort) -> Value {
    json!({"version":1,"iss":"issuer","aud":"aud","action":"abort_compact_pair",
           "certificate_id":([77;32]),"iat":100,"nbf":100,"exp":200,
           "request":a,"request_digest":a.digest().unwrap()})
}

fn abort_token(k: &signature::EcdsaKeyPair, a: &MaintenanceAbort) -> String {
    sign(k, ABORT_TOKEN_TYPE, &abort_claims(a))
}

struct Authority {
    current: Cell<bool>,
    abort_ok: Cell<bool>,
    revoke_inside_abort: Cell<bool>,
}
impl Default for Authority {
    fn default() -> Self {
        Self {
            current: Cell::new(true),
            abort_ok: Cell::new(true),
            revoke_inside_abort: Cell::new(false),
        }
    }
}
impl Policy for Authority {
    fn continuity(&self, _: &JournalScope, _: &Request) -> Result<()> {
        if self.current.get() {
            Ok(())
        } else {
            Err("stale witness".into())
        }
    }
    fn prepared(&self, _: &JournalScope, _: &Request, _: &Participant) -> Result<()> {
        Ok(())
    }
    fn applied(&self, _: &JournalScope, _: &CommittedTransition, _: &Participant) -> Result<()> {
        Ok(())
    }
    fn abort_applicable(&self, _: &JournalScope, _: &MaintenanceAbort) -> Result<()> {
        if self.revoke_inside_abort.get() {
            self.current.set(false);
        }
        if self.abort_ok.get() {
            Ok(())
        } else {
            Err("rollback evidence missing".into())
        }
    }
    fn historical_completion(
        &self,
        _: &JournalScope,
        historical: &Request,
        head: &Request,
    ) -> Result<()> {
        if self.current.get() && historical.revision < head.revision {
            Ok(())
        } else {
            Err("historical transition not superseded".into())
        }
    }
}
impl LossPolicy for Authority {
    fn continuity_and_fencing(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        if self.current.get() {
            Ok(())
        } else {
            Err("stale witness".into())
        }
    }
    fn survivor_prepared(&self, _: &JournalScope, _: &LossRequest) -> Result<()> {
        Ok(())
    }
}

/// An integration that never overrides `abort_applicable`.
struct Unaware;
impl Policy for Unaware {
    fn continuity(&self, _: &JournalScope, _: &Request) -> Result<()> {
        Ok(())
    }
    fn prepared(&self, _: &JournalScope, _: &Request, _: &Participant) -> Result<()> {
        Ok(())
    }
    fn applied(&self, _: &JournalScope, _: &CommittedTransition, _: &Participant) -> Result<()> {
        Ok(())
    }
}

#[track_caller]
fn refused<T>(outcome: Result<T>, expected: &str) {
    match outcome {
        Ok(_) => panic!("expected refusal {expected:?}, got success"),
        Err(e) => assert_eq!(e.to_string(), expected, "wrong refusal"),
    }
}

fn abort_table_exists(path: &Path) -> bool {
    let raw = terrapi_vesta::Vesta::open(path, "pass").unwrap();
    raw.with_connection(|c| {
        c.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='transition_abort')",
            [],
            |r| r.get(0),
        )
    })
    .unwrap()
}

/// Forge an abort row directly, bypassing every `Journal::abort` guard.
fn plant_abort_row(path: &Path, revision: u64, record: &str) {
    let raw = terrapi_vesta::Vesta::open(path, "pass").unwrap();
    raw.with_connection(|c| {
        c.execute_batch("CREATE TABLE IF NOT EXISTS main.transition_abort(revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32));")?;
        c.execute(
            "INSERT INTO main.transition_abort VALUES(?1,?2,?3)",
            rusqlite::params![
                revision,
                record,
                <sha2::Sha256 as sha2::Digest>::digest(record.as_bytes()).as_slice()
            ],
        )?;
        Ok(())
    })
    .unwrap();
}

fn abort_row_json(a: &MaintenanceAbort, token: &str) -> String {
    json!({"format":2,"abort":a,"token":token,"certificate_id":([77;32])}).to_string()
}

/// Journal with revision 1 decided, acknowledged and completed.
struct Cycle {
    dir: tempfile::TempDir,
    k: signature::EcdsaKeyPair,
    keys: Vec<(String, Vec<u8>)>,
    profile: Profile,
    scope: JournalScope,
    first: Request,
}

impl Cycle {
    fn new() -> Self {
        let first = first_request();
        let k = key();
        Self {
            dir: tempfile::tempdir().unwrap(),
            keys: vec![("key".into(), k.public_key().as_ref().to_vec())],
            k,
            profile: profile(),
            scope: scope_of(&first),
            first,
        }
    }
    fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("authority")
    }
    fn trust(&self) -> Trust<'_> {
        Trust {
            profile: &self.profile,
            keys: &self.keys,
            max_lifetime: 100,
        }
    }
    /// Decide, acknowledge and complete `r` on `journal`, returning the exact
    /// token that was recorded (ECDSA signing is randomized, so re-signing the
    /// same request never reproduces it).
    fn complete(&self, journal: &Journal, r: &Request, completion: u8, p: &Authority) -> String {
        let token = transition_token(&self.k, r);
        let d = journal
            .decide(r.clone(), &token, 150, &self.trust(), p)
            .unwrap();
        for m in &r.participants {
            journal.acknowledge(&d, m, &self.trust(), p).unwrap();
        }
        journal
            .complete(&d, [completion; 32], &self.trust(), p)
            .unwrap();
        token
    }
}

// ---------------------------------------------------------------- positive

#[test]
fn abort_of_a_decided_head_reopens_the_previous_certificate_and_chains_the_next_cycle() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);

    let second = chained(&f.first, 2, 41);
    let second_token = transition_token(&f.k, &second);
    let decided = j
        .decide(second.clone(), &second_token, 150, &f.trust(), &p)
        .unwrap();
    // Before the abort the decided-but-unfinished record is the head, so the
    // last completed certificate is unreachable.
    refused(
        j.fetch_completed(&f.first, &f.trust(), &p),
        "transition unavailable",
    );
    let status = j.status(&f.trust()).unwrap();
    assert_eq!(status.request, Some(second.clone()));
    assert_eq!((status.last_revision, status.aborted), (2, 0));

    let abort = abort_of(&f.scope, &second, 50);
    let token = abort_token(&f.k, &abort);
    let committed = j.abort(abort.clone(), &token, 150, &f.trust(), &p).unwrap();
    assert_eq!(committed.abort(), &abort);
    assert_eq!(committed.certificate_id(), [77; 32]);
    assert_eq!(committed.aborted_revision(), 2);
    assert_eq!(committed.aborted_request(), second.digest().unwrap());

    // This is the whole point: the nodes reopen on the certificate they hold.
    let reopened = j.fetch_completed(&f.first, &f.trust(), &p).unwrap();
    assert_eq!(reopened.completion(), [30; 32]);
    assert_eq!(reopened.certificate_id(), certificate_of(&f.first));
    refused(j.fetch(&second, &f.trust(), &p), "transition unavailable");
    let status = j.status(&f.trust()).unwrap();
    assert_eq!(status.request, Some(f.first.clone()));
    assert_eq!((status.last_revision, status.aborted), (2, 1));
    assert_eq!(status.completion, Some([30; 32]));

    // The revision counter moved on, the data lineage did not.
    let reuse = chained(&f.first, 2, 42);
    refused(
        j.decide(
            reuse.clone(),
            &transition_token(&f.k, &reuse),
            150,
            &f.trust(),
            &p,
        ),
        "transition revision aborted",
    );
    let wrong_base = chained(&second, 3, 43);
    refused(
        j.decide(
            wrong_base.clone(),
            &transition_token(&f.k, &wrong_base),
            150,
            &f.trust(),
            &p,
        ),
        "transition chain mismatch",
    );
    let third = chained(&f.first, 3, 44);
    f.complete(&j, &third, 45, &p);
    assert_eq!(
        j.fetch_completed(&third, &f.trust(), &p)
            .unwrap()
            .completion(),
        [45; 32]
    );
    assert_eq!(j.status(&f.trust()).unwrap().last_revision, 3);
    // The cancelled decision handle is inert for ever.
    refused(
        j.acknowledge(&decided, &second.participants[0], &f.trust(), &p),
        "transition revision aborted",
    );
}

#[test]
fn a_never_decided_abort_consumes_the_next_revision_on_an_empty_journal() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    assert_eq!(
        (
            j.status(&f.trust()).unwrap().last_revision,
            j.status(&f.trust()).unwrap().aborted
        ),
        (0, 0)
    );

    let abort = abort_undecided(&f.scope, &f.first, 1, 50);
    let token = abort_token(&f.k, &abort);
    j.abort(abort.clone(), &token, 150, &f.trust(), &p).unwrap();
    let status = j.status(&f.trust()).unwrap();
    assert_eq!(status.request, None);
    assert_eq!((status.last_revision, status.aborted), (1, 1));

    refused(
        j.decide(
            f.first.clone(),
            &transition_token(&f.k, &f.first),
            150,
            &f.trust(),
            &p,
        ),
        "transition revision aborted",
    );
    // The journal is still empty, so the replacement is an *initial*
    // transition — but at the revision the abort left free.
    let mut replacement = f.first.clone();
    replacement.id = [61; 32];
    replacement.revision = 2;
    f.complete(&j, &replacement, 31, &p);
    assert_eq!(
        j.fetch_completed(&replacement, &f.trust(), &p)
            .unwrap()
            .completion(),
        [31; 32]
    );
    assert_eq!(
        j.fetch_abort(&f.first, &f.trust(), &p)
            .unwrap()
            .token_digest(),
        j.abort(abort, &token, 150, &f.trust(), &p)
            .unwrap()
            .token_digest()
    );
}

#[test]
fn a_never_decided_abort_may_not_step_over_a_decided_head_that_is_still_open() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();

    // Revision 2 is decided and unfinished. Burning revision 3 instead would
    // leave revision 2 unfinishable for ever with nothing recording why.
    let third = chained(&f.first, 3, 42);
    let skip = abort_undecided(&f.scope, &third, 3, 50);
    refused(
        j.abort(skip.clone(), &abort_token(&f.k, &skip), 150, &f.trust(), &p),
        "decided transition must be aborted first",
    );
    assert!(!abort_table_exists(&f.path()));

    // Cancel the open decision on its own revision; then the next free
    // revision may be burnt.
    let proper = abort_of(&f.scope, &second, 51);
    j.abort(
        proper.clone(),
        &abort_token(&f.k, &proper),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    j.abort(skip.clone(), &abort_token(&f.k, &skip), 150, &f.trust(), &p)
        .unwrap();
    let status = j.status(&f.trust()).unwrap();
    assert_eq!(status.request, Some(f.first.clone()));
    assert_eq!((status.last_revision, status.aborted), (3, 2));
    let fourth = chained(&f.first, 4, 43);
    f.complete(&j, &fourth, 46, &p);
    assert_eq!(
        j.fetch_completed(&fourth, &f.trust(), &p)
            .unwrap()
            .completion(),
        [46; 32]
    );
}

#[test]
fn a_planted_never_decided_abort_over_an_open_decided_head_fails_the_journal_closed() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    drop(j);

    // Correctly signed, correctly sequenced at last_revision + 1 — and still
    // inadmissible, because revision 2 is decided and not aborted.
    let skip = abort_undecided(&f.scope, &chained(&f.first, 3, 42), 3, 50);
    plant_abort_row(
        &f.path(),
        3,
        &abort_row_json(&skip, &abort_token(&f.k, &skip)),
    );
    refused(
        Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()),
        "decided transition must be aborted first",
    );
}

#[test]
fn abort_applicable_is_the_only_authority_gate_for_an_empty_journal() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    let abort = abort_undecided(&f.scope, &f.first, 1, 50);
    let token = abort_token(&f.k, &abort);

    // The first-ever certified PREPARE expired before anything was decided:
    // there is no effective head, so `continuity` has no request to be called
    // with and never fires. `abort_applicable` carries the whole burden, and
    // the journal records nothing while its gate is shut.
    p.current.set(false);
    p.abort_ok.set(false);
    refused(
        j.abort(abort.clone(), &token, 150, &f.trust(), &p),
        "rollback evidence missing",
    );
    assert!(!abort_table_exists(&f.path()));
    assert_eq!(j.status(&f.trust()).unwrap().aborted, 0);

    p.abort_ok.set(true);
    j.abort(abort, &token, 150, &f.trust(), &p).unwrap();
    assert_eq!(j.status(&f.trust()).unwrap().aborted, 1);
    assert!(!p.current.get(), "continuity was revoked throughout");
}

#[test]
fn an_exact_abort_retry_converges_before_and_after_reopening_the_journal_file() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();

    let abort = abort_of(&f.scope, &second, 50);
    let token = abort_token(&f.k, &abort);
    let first_call = j.abort(abort.clone(), &token, 150, &f.trust(), &p).unwrap();
    let retry = j.abort(abort.clone(), &token, 150, &f.trust(), &p).unwrap();
    assert_eq!(retry.token_digest(), first_call.token_digest());
    assert_eq!(retry.certificate_id(), first_call.certificate_id());
    drop(j);

    let reopened = Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()).unwrap();
    // The C2 crash window is resumable with the by-then expired token: a
    // recorded abort is never re-verified against `now`.
    refused(
        verify_abort_issuance(&token, &f.trust(), &abort, 400).map_err(Into::into),
        "time window",
    );
    let resumed = reopened
        .abort(abort.clone(), &token, 400, &f.trust(), &p)
        .unwrap();
    assert_eq!(resumed.token_digest(), first_call.token_digest());
    let fetched = reopened.fetch_abort(&second, &f.trust(), &p).unwrap();
    assert_eq!(fetched.token_digest(), first_call.token_digest());
    assert_eq!(fetched.abort(), &abort);
    refused(
        reopened.fetch_abort(&f.first, &f.trust(), &p),
        "maintenance abort missing",
    );
    assert_eq!(reopened.status(&f.trust()).unwrap().aborted, 1);
}

#[test]
fn multiple_aborts_in_sequence_keep_the_counter_monotonic_across_a_reopen() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);

    // Revision 2 is decided and then cancelled.
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let a2 = abort_of(&f.scope, &second, 50);
    j.abort(a2.clone(), &abort_token(&f.k, &a2), 150, &f.trust(), &p)
        .unwrap();

    // Revisions 3 and 4 are prepared but never decided, then cancelled.
    let third = chained(&f.first, 3, 42);
    let a3 = abort_undecided(&f.scope, &third, 3, 51);
    j.abort(a3.clone(), &abort_token(&f.k, &a3), 150, &f.trust(), &p)
        .unwrap();
    let fourth = chained(&f.first, 4, 43);
    let a4 = abort_undecided(&f.scope, &fourth, 4, 52);
    j.abort(a4.clone(), &abort_token(&f.k, &a4), 150, &f.trust(), &p)
        .unwrap();
    // No gaps: the next free slot is 5, not 6.
    let gap = abort_undecided(&f.scope, &chained(&f.first, 6, 44), 6, 53);
    refused(
        j.abort(gap.clone(), &abort_token(&f.k, &gap), 150, &f.trust(), &p),
        "maintenance abort target mismatch",
    );
    drop(j);

    let reopened = Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()).unwrap();
    let status = reopened.status(&f.trust()).unwrap();
    assert_eq!(status.request, Some(f.first.clone()));
    assert_eq!((status.last_revision, status.aborted), (4, 3));
    let fifth = chained(&f.first, 5, 45);
    f.complete(&reopened, &fifth, 46, &p);
    assert_eq!(
        reopened
            .fetch_completed(&fifth, &f.trust(), &p)
            .unwrap()
            .completion(),
        [46; 32]
    );
    for (a, r) in [(&a2, &second), (&a3, &third), (&a4, &fourth)] {
        assert_eq!(reopened.fetch_abort(r, &f.trust(), &p).unwrap().abort(), a);
    }
}

// ------------------------------------------------- abort and participant loss

fn loss_for(f: &Cycle, source: &Request, revision: u64) -> LossRequest {
    let survivor_cut = Checkpoint {
        sequence: source.participants[0].target.sequence + 5,
        digest: [28; 32],
    };
    LossRequest {
        format: 1,
        id: [23; 32],
        authority_id: f.scope.authority_id,
        revision,
        install: f.scope.install.clone(),
        region: f.scope.region.clone(),
        scope: f.scope.scope,
        schema: f.scope.schema,
        membership: f.scope.membership,
        source_certificate: certificate_of(source),
        source_token_digest: [0; 32],
        source_cut: source.participants[0].target.clone(),
        lost_member: source.participants[0].member,
        lost_generation: source.participants[0].generation,
        survivor: Participant {
            target: survivor_cut.clone(),
            publication: [29; 32],
            ..source.participants[1].clone()
        },
        survivor_cut: survivor_cut.clone(),
        survivor_publication: [29; 32],
        replacement_membership: [28; 32],
        replacement_member: [24; 32],
        replacement_generation: [25; 32],
        fencing_ref: [26; 32],
    }
}

fn loss_token(k: &signature::EcdsaKeyPair, l: &LossRequest) -> String {
    sign(
        k,
        LOSS_TOKEN_TYPE,
        &json!({"version":1,"iss":"issuer","aud":"aud","action":"terminate_and_replace",
                "certificate_id":([91;32]),"iat":100,"nbf":100,"exp":200,
                "request":l,"request_digest":l.digest().unwrap()}),
    )
}

#[test]
fn a_loss_after_an_abort_takes_the_next_revision_from_the_effective_completed_head() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    let first_token = f.complete(&j, &f.first, 30, &p);
    let source_digest = j
        .fetch_completed(&f.first, &f.trust(), &p)
        .unwrap()
        .token_digest();
    assert_eq!(source_digest, sha(&first_token));

    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let abort = abort_of(&f.scope, &second, 50);
    j.abort(
        abort.clone(),
        &abort_token(&f.k, &abort),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();

    // Source certificate = the effective (completed) head; revision =
    // last_revision + 1, which the abort pushed past the head's own revision.
    let mut stale = loss_for(&f, &f.first, 2);
    stale.source_token_digest = source_digest;
    refused(
        j.decide_loss(
            stale.clone(),
            &loss_token(&f.k, &stale),
            150,
            &f.trust(),
            &p,
        ),
        "loss participant/revision mismatch",
    );
    let mut loss = loss_for(&f, &f.first, 3);
    loss.source_token_digest = source_digest;
    let committed = j
        .decide_loss(loss.clone(), &loss_token(&f.k, &loss), 150, &f.trust(), &p)
        .unwrap();
    assert_eq!(committed.request(), &loss);

    // After the loss the journal is terminal for maintenance aborts.
    let late = abort_undecided(&f.scope, &chained(&f.first, 4, 46), 4, 54);
    refused(
        j.abort(late.clone(), &abort_token(&f.k, &late), 150, &f.trust(), &p),
        "maintenance abort superseded by participant loss",
    );
}

#[test]
fn a_loss_after_an_abort_and_a_fresh_cycle_uses_the_new_completed_head() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let abort = abort_of(&f.scope, &second, 50);
    j.abort(
        abort.clone(),
        &abort_token(&f.k, &abort),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let third = chained(&f.first, 3, 44);
    let third_token = f.complete(&j, &third, 45, &p);

    let mut loss = loss_for(&f, &third, 4);
    loss.source_token_digest = sha(&third_token);
    assert_eq!(
        j.decide_loss(loss.clone(), &loss_token(&f.k, &loss), 150, &f.trust(), &p)
            .unwrap()
            .request(),
        &loss
    );
}

// ---------------------------------------------------------------- negative

#[test]
fn a_completed_or_fully_acknowledged_record_can_never_be_aborted() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let done = abort_of(&f.scope, &f.first, 50);
    refused(
        j.abort(done.clone(), &abort_token(&f.k, &done), 150, &f.trust(), &p),
        "maintenance abort target mismatch",
    );

    // Decided and acknowledged by both, but not yet completed: the nodes have
    // already applied it, so rolling back is not an option either.
    let second = chained(&f.first, 2, 41);
    let d = j
        .decide(
            second.clone(),
            &transition_token(&f.k, &second),
            150,
            &f.trust(),
            &p,
        )
        .unwrap();
    for m in &second.participants {
        j.acknowledge(&d, m, &f.trust(), &p).unwrap();
    }
    let acked = abort_of(&f.scope, &second, 51);
    refused(
        j.abort(
            acked.clone(),
            &abort_token(&f.k, &acked),
            150,
            &f.trust(),
            &p,
        ),
        "maintenance abort target mismatch",
    );
}

#[test]
fn the_decided_flag_the_digest_the_id_and_the_revision_must_all_match_reality() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let good = abort_of(&f.scope, &second, 50);

    let mut undecided_claim = good.clone();
    undecided_claim.decided = false;
    let mut decided_claim = abort_undecided(&f.scope, &chained(&f.first, 3, 42), 3, 51);
    decided_claim.decided = true;
    let mut wrong_digest = good.clone();
    wrong_digest.aborted_request = [99; 32];
    let mut wrong_id = good.clone();
    wrong_id.aborted_request_id = [99; 32];
    let mut wrong_revision = good.clone();
    wrong_revision.revision = 1;
    wrong_revision.aborted_revision = 1;
    for bad in [
        undecided_claim,
        decided_claim,
        wrong_digest,
        wrong_id,
        wrong_revision,
    ] {
        refused(
            j.abort(bad.clone(), &abort_token(&f.k, &bad), 150, &f.trust(), &p),
            "maintenance abort target mismatch",
        );
    }
    // `revision` is the revision the abort occupies; it can never be padding,
    // so a split value is unsignable and unrecordable.
    let mut split = good.clone();
    split.revision = 3;
    refused(
        j.abort(split, &abort_token(&f.k, &good), 150, &f.trust(), &p),
        "invalid maintenance abort",
    );
}

#[test]
fn an_aborted_revision_and_an_aborted_request_id_are_unusable_for_ever() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    let second_token = transition_token(&f.k, &second);
    j.decide(second.clone(), &second_token, 150, &f.trust(), &p)
        .unwrap();
    let abort = abort_of(&f.scope, &second, 50);
    j.abort(
        abort.clone(),
        &abort_token(&f.k, &abort),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();

    // Same request, same token; same request, a freshly signed token.
    refused(
        j.decide(second.clone(), &second_token, 150, &f.trust(), &p),
        "transition revision aborted",
    );
    let resigned = transition_token(&f.k, &second);
    assert_ne!(resigned, second_token);
    refused(
        j.decide(second.clone(), &resigned, 150, &f.trust(), &p),
        "transition revision aborted",
    );
    // A different request may not reuse the burnt revision either.
    let reuse = chained(&f.first, 2, 47);
    refused(
        j.decide(
            reuse.clone(),
            &transition_token(&f.k, &reuse),
            150,
            &f.trust(),
            &p,
        ),
        "transition revision aborted",
    );
    // And the cancelled request id may not reappear at a free revision.
    let mut revived = chained(&f.first, 3, 48);
    revived.id = second.id;
    refused(
        j.decide(
            revived.clone(),
            &transition_token(&f.k, &revived),
            150,
            &f.trust(),
            &p,
        ),
        "duplicate transition request id",
    );
}

#[test]
fn a_never_decided_abort_also_burns_its_request_id() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let attempted = chained(&f.first, 2, 41);
    let abort = abort_undecided(&f.scope, &attempted, 2, 50);
    j.abort(
        abort.clone(),
        &abort_token(&f.k, &abort),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let mut revived = chained(&f.first, 3, 49);
    revived.id = attempted.id;
    refused(
        j.decide(
            revived.clone(),
            &transition_token(&f.k, &revived),
            150,
            &f.trust(),
            &p,
        ),
        "duplicate transition request id",
    );
}

#[test]
fn any_difference_from_the_recorded_abort_is_an_immutable_conflict() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let abort = abort_of(&f.scope, &second, 50);
    let token = abort_token(&f.k, &abort);
    j.abort(abort.clone(), &token, 150, &f.trust(), &p).unwrap();

    let resigned = abort_token(&f.k, &abort);
    assert_ne!(resigned, token);
    refused(
        j.abort(abort.clone(), &resigned, 150, &f.trust(), &p),
        "immutable maintenance abort conflict",
    );
    let mut renamed = abort;
    renamed.id = [59; 32];
    refused(
        j.abort(
            renamed.clone(),
            &abort_token(&f.k, &renamed),
            150,
            &f.trust(),
            &p,
        ),
        "immutable maintenance abort conflict",
    );
}

#[test]
fn abort_tokens_must_carry_the_right_purpose_key_and_validity_window() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let abort = abort_of(&f.scope, &second, 50);

    let attacker = key();
    let mut wrong_action = abort_claims(&abort);
    wrong_action["action"] = json!("compact_pair");
    let mut foreign_scope = abort.clone();
    foreign_scope.scope = [99; 32];
    for (token, expected) in [
        (
            sign(&attacker, ABORT_TOKEN_TYPE, &abort_claims(&abort)),
            "signature",
        ),
        (
            sign(&f.k, TOKEN_TYPE, &abort_claims(&abort)),
            "header purpose",
        ),
        (sign(&f.k, ABORT_TOKEN_TYPE, &wrong_action), "claim purpose"),
        (
            sign(&f.k, "terrapi-participant-loss+jwt", &abort_claims(&abort)),
            "header purpose",
        ),
    ] {
        refused(
            j.abort(abort.clone(), &token, 150, &f.trust(), &p),
            expected,
        );
    }
    let token = abort_token(&f.k, &abort);
    refused(
        j.abort(abort.clone(), &token, 250, &f.trust(), &p),
        "time window",
    );
    refused(
        j.abort(abort.clone(), &token, 50, &f.trust(), &p),
        "time window",
    );
    refused(
        j.abort(
            foreign_scope.clone(),
            &abort_token(&f.k, &foreign_scope),
            150,
            &f.trust(),
            &p,
        ),
        "maintenance abort scope binding",
    );
    refused(
        j.abort(abort.clone(), &"x".repeat(65 * 1024), 150, &f.trust(), &p),
        "token limit",
    );
    // Nothing above was recorded.
    assert_eq!(j.status(&f.trust()).unwrap().aborted, 0);
    j.abort(abort, &token, 150, &f.trust(), &p).unwrap();
}

#[test]
fn an_integration_that_does_not_implement_abort_applicable_is_denied() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let abort = abort_of(&f.scope, &second, 50);
    refused(
        j.abort(
            abort.clone(),
            &abort_token(&f.k, &abort),
            150,
            &f.trust(),
            &Unaware,
        ),
        "maintenance abort evidence missing",
    );
    assert_eq!(j.status(&f.trust()).unwrap().aborted, 0);
}

#[test]
fn revocation_between_the_two_continuity_checks_rolls_the_abort_back() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let abort = abort_of(&f.scope, &second, 50);
    let token = abort_token(&f.k, &abort);

    p.revoke_inside_abort.set(true);
    refused(
        j.abort(abort.clone(), &token, 150, &f.trust(), &p),
        "stale witness",
    );
    p.revoke_inside_abort.set(false);
    p.current.set(true);
    assert_eq!(j.status(&f.trust()).unwrap().aborted, 0);

    p.abort_ok.set(false);
    refused(
        j.abort(abort.clone(), &token, 150, &f.trust(), &p),
        "rollback evidence missing",
    );
    p.abort_ok.set(true);
    // Nothing survived the rolled-back transactions — not even the lazily
    // created table, so the journal is still bit-identical to format 1.
    assert!(!abort_table_exists(&f.path()));
    drop(j);
    let reopened = Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()).unwrap();
    reopened.abort(abort, &token, 150, &f.trust(), &p).unwrap();
    assert_eq!(reopened.status(&f.trust()).unwrap().aborted, 1);
    assert!(abort_table_exists(&f.path()));
}

#[test]
fn a_second_journal_handle_racing_the_same_revision_loses_and_fails_closed() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();

    // Two authority processes holding the same journal file; both were told
    // to cancel revision 2, with different abort identities.
    let other = Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()).unwrap();
    let winner = abort_of(&f.scope, &second, 50);
    let mut loser = abort_of(&f.scope, &second, 51);
    loser.id = [52; 32];
    j.abort(
        winner.clone(),
        &abort_token(&f.k, &winner),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    refused(
        other.abort(
            loser.clone(),
            &abort_token(&f.k, &loser),
            150,
            &f.trust(),
            &p,
        ),
        "immutable maintenance abort conflict",
    );
    // The loser converges when it retries with the winner's own abort.
    let recorded = j.fetch_abort(&second, &f.trust(), &p).unwrap();
    assert_eq!(
        other
            .abort(winner.clone(), recorded.token(), 150, &f.trust(), &p)
            .unwrap()
            .abort(),
        &winner
    );
    assert_eq!(other.status(&f.trust()).unwrap().aborted, 1);
}

#[test]
fn acknowledge_complete_and_historical_reads_refuse_an_aborted_record() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    let decided = j
        .decide(
            second.clone(),
            &transition_token(&f.k, &second),
            150,
            &f.trust(),
            &p,
        )
        .unwrap();
    j.acknowledge(&decided, &second.participants[0], &f.trust(), &p)
        .unwrap();
    let abort = abort_of(&f.scope, &second, 50);
    j.abort(
        abort.clone(),
        &abort_token(&f.k, &abort),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();

    refused(
        j.acknowledge(&decided, &second.participants[1], &f.trust(), &p),
        "transition revision aborted",
    );
    refused(
        j.complete(&decided, [55; 32], &f.trust(), &p),
        "transition revision aborted",
    );
    let third = chained(&f.first, 3, 44);
    f.complete(&j, &third, 45, &p);
    refused(
        j.fetch_completed_revision(&second, &f.trust(), &p),
        "transition revision aborted",
    );
    assert_eq!(
        j.fetch_completed_revision(&f.first, &f.trust(), &p)
            .unwrap()
            .completion(),
        [30; 32]
    );
}

// ----------------------------------------------------- durable fail-closed

#[test]
fn a_tampered_oversized_or_overfull_abort_table_fails_the_journal_closed() {
    // (a) digest mismatch on a genuine abort row.
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    let second = chained(&f.first, 2, 41);
    j.decide(
        second.clone(),
        &transition_token(&f.k, &second),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    let abort = abort_of(&f.scope, &second, 50);
    j.abort(
        abort.clone(),
        &abort_token(&f.k, &abort),
        150,
        &f.trust(),
        &p,
    )
    .unwrap();
    drop(j);
    let raw = terrapi_vesta::Vesta::open(f.path(), "pass").unwrap();
    raw.with_connection(|c| {
        c.execute("UPDATE main.transition_abort SET digest=zeroblob(32)", [])?;
        Ok(())
    })
    .unwrap();
    drop(raw);
    refused(
        Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()),
        "transition abort record integrity",
    );

    // (b) a row larger than the 256 KiB record cap, rejected before decode.
    let g = Cycle::new();
    let j = Journal::create(&g.path(), "pass", g.scope.clone()).unwrap();
    g.complete(&j, &g.first, 30, &p);
    drop(j);
    plant_abort_row(&g.path(), 2, &"x".repeat(256 * 1024 + 1));
    refused(
        Journal::open(&g.path(), "pass", g.scope.clone(), &g.trust()),
        "transition abort record limit",
    );

    // (c) more rows than the hard cap, rejected before any decode.
    let h = Cycle::new();
    let j = Journal::create(&h.path(), "pass", h.scope.clone()).unwrap();
    h.complete(&j, &h.first, 30, &p);
    drop(j);
    let raw = terrapi_vesta::Vesta::open(h.path(), "pass").unwrap();
    raw.with_connection(|c| {
        c.execute_batch("CREATE TABLE IF NOT EXISTS main.transition_abort(revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32)); BEGIN;")?;
        for revision in 0..4097u64 {
            c.execute(
                "INSERT INTO main.transition_abort VALUES(?1,'{}',zeroblob(32))",
                [revision],
            )?;
        }
        c.execute_batch("COMMIT;")?;
        Ok(())
    })
    .unwrap();
    drop(raw);
    refused(
        Journal::open(&h.path(), "pass", h.scope.clone(), &h.trust()),
        "transition abort row limit",
    );
}

#[test]
fn an_abort_row_colliding_with_a_completed_record_fails_the_journal_closed() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    drop(j);

    // A perfectly signed abort, planted against a record that was completed.
    let abort = abort_of(&f.scope, &f.first, 50);
    let token = abort_token(&f.k, &abort);
    plant_abort_row(&f.path(), 1, &abort_row_json(&abort, &token));
    refused(
        Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()),
        "maintenance abort target mismatch",
    );
}

#[test]
fn a_planted_abort_row_that_leaves_a_revision_gap_fails_the_journal_closed() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    drop(j);
    let gap = abort_undecided(&f.scope, &chained(&f.first, 7, 42), 7, 50);
    plant_abort_row(
        &f.path(),
        7,
        &abort_row_json(&gap, &abort_token(&f.k, &gap)),
    );
    // The head still says 1, the abort claims 7: the counter is not gapless.
    refused(
        Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()),
        "transition abort sequencing",
    );
}

#[test]
fn an_abort_row_bound_to_a_foreign_scope_fails_the_journal_closed() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    f.complete(&j, &f.first, 30, &p);
    drop(j);
    let mut foreign = abort_undecided(&f.scope, &chained(&f.first, 2, 42), 2, 50);
    foreign.membership = [99; 32];
    plant_abort_row(
        &f.path(),
        2,
        &abort_row_json(&foreign, &abort_token(&f.k, &foreign)),
    );
    refused(
        Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()),
        "maintenance abort scope binding",
    );
}

// ------------------------------------------------------------ compatibility

#[test]
fn a_journal_that_never_aborts_never_grows_the_table_and_behaves_as_before() {
    let f = Cycle::new();
    let p = Authority::default();
    let j = Journal::create(&f.path(), "pass", f.scope.clone()).unwrap();
    assert!(!abort_table_exists(&f.path()));

    let token = transition_token(&f.k, &f.first);
    let decided = j
        .decide(f.first.clone(), &token, 150, &f.trust(), &p)
        .unwrap();
    refused(
        j.fetch_completed(&f.first, &f.trust(), &p),
        "transition acknowledgements incomplete",
    );
    for m in &f.first.participants {
        j.acknowledge(&decided, m, &f.trust(), &p).unwrap();
    }
    j.complete(&decided, [30; 32], &f.trust(), &p).unwrap();
    let completed = j.fetch_completed(&f.first, &f.trust(), &p).unwrap();
    assert_eq!(completed.completion(), [30; 32]);
    let status = j.status(&f.trust()).unwrap();
    assert_eq!(status.request, Some(f.first.clone()));
    assert_eq!((status.last_revision, status.aborted), (1, 0));
    assert!(!abort_table_exists(&f.path()));
    drop(j);

    // Reopened by code that never created the table: identical behaviour.
    let reopened = Journal::open(&f.path(), "pass", f.scope.clone(), &f.trust()).unwrap();
    assert!(!abort_table_exists(&f.path()));
    let second = chained(&f.first, 2, 41);
    let second_token = transition_token(&f.k, &second);
    let decided = reopened
        .decide(second.clone(), &second_token, 150, &f.trust(), &p)
        .unwrap();
    for m in &second.participants {
        reopened.acknowledge(&decided, m, &f.trust(), &p).unwrap();
    }
    reopened
        .complete(&decided, [45; 32], &f.trust(), &p)
        .unwrap();
    assert_eq!(
        reopened
            .fetch_completed(&second, &f.trust(), &p)
            .unwrap()
            .completion(),
        [45; 32]
    );
    assert_eq!(
        reopened
            .fetch_completed_revision(&f.first, &f.trust(), &p)
            .unwrap()
            .completion(),
        [30; 32]
    );
    assert_eq!(
        reopened.fetch(&second, &f.trust(), &p).unwrap().token(),
        second_token
    );
    let status = reopened.status(&f.trust()).unwrap();
    assert_eq!((status.last_revision, status.aborted), (2, 0));
    refused(
        reopened.fetch_abort(&second, &f.trust(), &p),
        "maintenance abort missing",
    );
    assert!(!abort_table_exists(&f.path()));
}

#[test]
fn a_maintenance_abort_rejects_zero_ids_empty_text_and_a_split_revision() {
    let f = Cycle::new();
    let good = abort_of(&f.scope, &f.first, 50);
    assert!(good.validate().is_ok());
    assert_eq!(good.digest().unwrap(), good.digest().unwrap());
    let mut format_one = good.clone();
    format_one.format = 1;
    let mut zero_id = good.clone();
    zero_id.id = [0; 32];
    let mut zero_target = good.clone();
    zero_target.aborted_request = [0; 32];
    let mut zero_target_id = good.clone();
    zero_target_id.aborted_request_id = [0; 32];
    let mut blank = good.clone();
    blank.install = "   ".into();
    let mut huge = good.clone();
    huge.revision = u64::MAX;
    huge.aborted_revision = u64::MAX;
    let mut zero_anchor = good.clone();
    zero_anchor.source_anchor.digest = [0; 32];
    let mut split = good;
    split.revision += 1;
    for bad in [
        format_one,
        zero_id,
        zero_target,
        zero_target_id,
        blank,
        huge,
        zero_anchor,
        split,
    ] {
        assert_eq!(bad.validate(), Err("invalid maintenance abort"));
        assert!(bad.digest().is_err());
    }
}
