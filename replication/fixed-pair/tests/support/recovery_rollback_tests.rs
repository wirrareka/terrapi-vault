//! Characterization of an UNSOLVED boundary, not an anti-rollback solution.
//! All copies are closed, disposable fixtures; no live backup or real recovery.
use super::{
    authorized_recovery_tests::{seed, Harness},
    fixture,
    recovery_completion_tests::{activate, request},
    recovery_grant::{verify, Context},
    recovery_grant_tests::{claims, context, header, key},
    recovery_registry::{Crash, Registry, Result},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{rand::SystemRandom, signature::EcdsaKeyPair};
use std::path::Path;

/// Caller must drop every DB handle first. Copy the complete dedicated fixture
/// directory (including key metadata), never just a possibly uncheckpointed DB.
fn cold_clone(source: &Path, destination: &Path) {
    assert!(!destination.exists());
    std::fs::create_dir(destination).unwrap();
    let mut count = 0;
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        assert!(
            entry.file_type().unwrap().is_file(),
            "fixture must contain only regular files"
        );
        std::fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
        count += 1;
    }
    assert!(count > 0);
}
fn draft(ctx: &Context) -> String {
    let mut c = claims();
    c["plan"] = serde_json::to_value(&ctx.reservation.as_ref().unwrap().plan).unwrap();
    format!(
        "{}.{}",
        B64.encode(header().to_string()),
        B64.encode(c.to_string())
    )
}
fn issue(r: &Registry, key: &EcdsaKeyPair, ctx: &Context) -> String {
    r.issue(
        ctx,
        |input| -> Result<String> {
            let signature = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
            Ok(format!("{input}.{}", B64.encode(signature.as_ref())))
        },
        Crash::None,
    )
    .unwrap()
}
fn create(dir: &Path) {
    drop(
        Registry::create(
            &dir.join("operator.db"),
            fixture().1.baseline,
            "fixture-install",
            "eu",
        )
        .unwrap(),
    );
}

#[test]
fn cold_pre_reservation_copy_can_issue_conflicting_same_revision_grants() {
    let live = tempfile::tempdir().unwrap();
    create(live.path());
    let backup = tempfile::tempdir().unwrap();
    let restored = backup.path().join("restored");
    cold_clone(live.path(), &restored);
    let key = key();
    let a = context(&key);
    let r = Registry::open(&live.path().join("operator.db")).unwrap();
    r.reserve(&draft(&a), &a, Crash::None).unwrap();
    let token_a = issue(&r, &key, &a);
    let mut b = context(&key);
    b.reservation.as_mut().unwrap().plan.candidate = [44; 32];
    let restored = Registry::open(&restored.join("operator.db")).unwrap();
    assert_eq!(restored.load().unwrap().allocated_revision, 4);
    restored.reserve(&draft(&b), &b, Crash::None).unwrap();
    let token_b = issue(&restored, &key, &b);
    let a = verify(&token_a, &a).unwrap();
    let b = verify(&token_b, &b).unwrap();
    assert_eq!(a.plan.revision, b.plan.revision);
    assert_eq!(a.plan.baseline, b.plan.baseline);
    assert_ne!(a.plan.candidate, b.plan.candidate);
    // Passing means the known unsafe rollback is reproduced, NOT prevented.
    assert_ne!(token_a, token_b);
}

#[test]
fn reserved_copy_preserves_candidate_but_loses_published_token_at_same_revision() {
    let live = tempfile::tempdir().unwrap();
    create(live.path());
    let key = key();
    let ctx = context(&key);
    let r = Registry::open(&live.path().join("operator.db")).unwrap();
    r.reserve(&draft(&ctx), &ctx, Crash::None).unwrap();
    drop(r);
    let backup = tempfile::tempdir().unwrap();
    let restored = backup.path().join("restored");
    cold_clone(live.path(), &restored);
    let live = Registry::open(&live.path().join("operator.db")).unwrap();
    let token = issue(&live, &key, &ctx);
    let restored = Registry::open(&restored.join("operator.db")).unwrap();
    let before = restored.load().unwrap();
    let after = live.load().unwrap();
    assert_eq!(before.allocated_revision, after.allocated_revision);
    assert_eq!(before.input, after.input);
    assert!(before.token.is_none());
    assert_eq!(after.token, Some(token));
    let mut other = context(&key);
    other.reservation.as_mut().unwrap().plan.candidate = [44; 32];
    assert!(restored
        .reserve(&draft(&other), &other, Crash::None)
        .is_err());
    assert!(verify(&issue(&restored, &key, &ctx), &ctx).is_ok());
    // Membership revision alone cannot distinguish Reserved from Published.
}

#[test]
fn cold_published_copy_loses_completion_without_affecting_live_members() {
    let h = Harness::new();
    activate(&h);
    // Harness owns no open DB handles here. The backup contains copies of all
    // fixture files; only its operator DB is opened below. Live members stay put.
    let backup = tempfile::tempdir().unwrap();
    let restored = backup.path().join("restored");
    cold_clone(h.dir.path(), &restored);
    let req = request(&h, [70; 32]);
    let live = h.registry();
    let before = live.load().unwrap();
    live.complete(&req, || h.ctx(), || Ok(req.evidence.clone()), Crash::None)
        .unwrap();
    let restored = Registry::open(&restored.join("operator.db")).unwrap();
    assert_eq!(restored.load().unwrap(), before);
    assert_eq!(live.load().unwrap(), before);
    assert_eq!(live.load_completion().unwrap(), Some(req));
    assert!(restored.load_completion().unwrap().is_none());
    let other = request(&h, [71; 32]);
    restored
        .complete(
            &other,
            || h.ctx(),
            || Ok(other.evidence.clone()),
            Crash::None,
        )
        .unwrap();
    assert_eq!(restored.load_completion().unwrap(), Some(other));
    for primary in [true, false] {
        assert_eq!(h.store(primary).load(&seed(primary)).unwrap().revision, 1);
    }
    // Registry row + publication digest still match, but completion history forks.
}
