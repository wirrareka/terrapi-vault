use super::{
    fixture,
    model::Id,
    peers::{Local, Saved},
    recovery_grant::Context,
    recovery_grant_tests::{claims, context, header, key},
    recovery_registry::{Crash as RegistryCrash, Registry},
    store::{Crash, Store},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{rand::SystemRandom, signature::EcdsaKeyPair};
use std::path::Path;

pub(super) fn seed(primary: bool) -> Saved {
    let p = fixture().1;
    Local::prepared(
        p.clone(),
        if primary {
            p.candidate
        } else {
            p.baseline.survivor
        },
        [1; 32],
    )
    .unwrap()
    .saved()
}
pub(super) fn peer(primary: bool, boot: Id) -> Local {
    Local::restart(seed(!primary), boot).unwrap()
}

pub(super) struct Harness {
    pub dir: tempfile::TempDir,
    pub key: EcdsaKeyPair,
    pub token: String,
}
impl Harness {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = key();
        let ctx = context(&key);
        let registry = Registry::create(
            &dir.path().join("operator.db"),
            fixture().1.baseline,
            "fixture-install",
            "eu",
        )
        .unwrap();
        let input = format!(
            "{}.{}",
            B64.encode(header().to_string()),
            B64.encode(claims().to_string())
        );
        registry.reserve(&input, &ctx, RegistryCrash::None).unwrap();
        let token = registry
            .issue(
                &ctx,
                |input| {
                    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
                    Ok(format!("{input}.{}", B64.encode(sig.as_ref())))
                },
                RegistryCrash::None,
            )
            .unwrap();
        for primary in [true, false] {
            drop(Store::create(&Self::path(dir.path(), primary), seed(primary)).unwrap());
        }
        Self { dir, key, token }
    }
    pub fn path(dir: &Path, primary: bool) -> std::path::PathBuf {
        dir.join(if primary { "p.db" } else { "s.db" })
    }
    pub fn store(&self, primary: bool) -> Store {
        Store::open(&Self::path(self.dir.path(), primary)).unwrap()
    }
    pub fn registry(&self) -> Registry {
        Registry::open(&self.dir.path().join("operator.db")).unwrap()
    }
    pub fn ctx(&self) -> Context {
        context(&self.key)
    }
}

#[test]
fn activation_persists_exact_grant_with_state_and_retry_does_not_advance() {
    let h = Harness::new();
    let registry = h.registry();
    for primary in [true, false] {
        let store = h.store(primary);
        let initial = store.load(&seed(primary)).unwrap();
        store
            .activate_authorized(
                &initial,
                [10; 32],
                peer(primary, [11; 32]).report([10; 32]),
                &h.token,
                &registry,
                || h.ctx(),
                Crash::None,
            )
            .unwrap();
        let current = store.load(&seed(primary)).unwrap();
        assert_eq!(current.revision, 1);
        assert!(Local::restart(current.saved.clone(), [12; 32])
            .unwrap()
            .is_active());
        assert_eq!(
            store.activation_token(&current).unwrap(),
            Some(h.token.clone())
        );
        store
            .activate_authorized(
                &current,
                [12; 32],
                peer(primary, [11; 32]).report([12; 32]),
                &h.token,
                &registry,
                || h.ctx(),
                Crash::None,
            )
            .unwrap();
        assert_eq!(store.load(&seed(primary)).unwrap(), current);
    }
}

#[test]
fn rejection_leaves_both_transition_and_grant_record_unchanged() {
    let h = Harness::new();
    let registry = h.registry();
    let store = h.store(true);
    let initial = store.load(&seed(true)).unwrap();
    for mode in 0..7 {
        let mut ctx = h.ctx();
        match mode {
            0 => ctx.now = 200,
            1 => ctx.keys.clear(),
            2 => ctx.fencing_confirmed = false,
            3 => ctx.reservation = None,
            4 => ctx.region = "uae".into(),
            5 => ctx.reservation.as_mut().unwrap().plan.candidate = [44; 32],
            _ => {}
        }
        let token = if mode == 6 {
            format!("{}a", h.token)
        } else {
            h.token.clone()
        };
        assert!(store
            .activate_authorized(
                &initial,
                [10; 32],
                peer(true, [11; 32]).report([10; 32]),
                &token,
                &registry,
                || ctx,
                Crash::None
            )
            .is_err());
        assert_eq!(store.load(&seed(true)).unwrap(), initial);
        assert!(store.activation_token(&initial).unwrap().is_none());
    }
    // A correctly signed but never published alternative token is not accepted.
    let (input, _) = h.token.rsplit_once('.').unwrap();
    let sig = h.key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    let alternative = format!("{input}.{}", B64.encode(sig.as_ref()));
    assert_ne!(alternative, h.token);
    assert!(store
        .activate_authorized(
            &initial,
            [10; 32],
            peer(true, [11; 32]).report([10; 32]),
            &alternative,
            &registry,
            || h.ctx(),
            Crash::None
        )
        .is_err());
}

#[test]
fn wrong_plan_report_session_and_stale_record_never_activate() {
    let h = Harness::new();
    let registry = h.registry();
    let store = h.store(true);
    let initial = store.load(&seed(true)).unwrap();
    for mode in 0..4 {
        let mut report = peer(true, [11; 32]).report([10; 32]);
        match mode {
            0 => report.receiver_boot = [12; 32],
            1 => report.plan.candidate = [44; 32],
            2 => report.from = fixture().1.candidate,
            _ => report.to = [44; 32],
        }
        assert!(store
            .activate_authorized(
                &initial,
                [10; 32],
                report,
                &h.token,
                &registry,
                || h.ctx(),
                Crash::None
            )
            .is_err());
    }
    let other = h.store(true);
    let mut quarantined = Local::restart(initial.saved.clone(), [12; 32]).unwrap();
    quarantined.quarantine();
    other
        .update(&initial, quarantined.saved(), Crash::None)
        .unwrap();
    assert!(store
        .activate_authorized(
            &initial,
            [10; 32],
            peer(true, [11; 32]).report([10; 32]),
            &h.token,
            &registry,
            || h.ctx(),
            Crash::None
        )
        .is_err());
    let current = store.load(&seed(true)).unwrap();
    assert!(store
        .activate_authorized(
            &current,
            [10; 32],
            peer(true, [11; 32]).report([10; 32]),
            &h.token,
            &registry,
            || h.ctx(),
            Crash::None
        )
        .is_err());
    assert!(store.activation_token(&current).unwrap().is_none());
}

#[test]
fn failed_member_commit_rolls_back_grant_and_state_together() {
    let h = Harness::new();
    let registry = h.registry();
    let store = h.store(true);
    let initial = store.load(&seed(true)).unwrap();
    store.connection(|c| {c.execute_batch("CREATE TRIGGER fail_grant BEFORE INSERT ON recovery_grants BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).unwrap();
    assert!(store
        .activate_authorized(
            &initial,
            [10; 32],
            peer(true, [11; 32]).report([10; 32]),
            &h.token,
            &registry,
            || h.ctx(),
            Crash::None
        )
        .is_err());
    assert_eq!(store.load(&seed(true)).unwrap(), initial);
    assert!(store.activation_token(&initial).unwrap().is_none());
}

#[test]
fn current_registry_and_context_are_rechecked_inside_member_transaction() {
    let h = Harness::new();
    let registry = h.registry();
    let store = h.store(true);
    let initial = store.load(&seed(true)).unwrap();
    // Prove the context callback executes after the local write lock is held.
    store
        .activate_authorized(
            &initial,
            [10; 32],
            peer(true, [11; 32]).report([10; 32]),
            &h.token,
            &registry,
            || {
                let other = h.store(true);
                assert!(other
                    .connection(|c| {
                        c.busy_timeout(std::time::Duration::ZERO)?;
                        c.execute_batch("BEGIN IMMEDIATE")?;
                        c.execute_batch("ROLLBACK")?;
                        Ok(())
                    })
                    .is_err());
                let other_registry = h.registry();
                assert!(other_registry
                    .connection(|c| {
                        c.busy_timeout(std::time::Duration::ZERO)?;
                        c.execute_batch("BEGIN IMMEDIATE")?;
                        c.execute_batch("ROLLBACK")?;
                        Ok(())
                    })
                    .is_err());
                h.ctx()
            },
            Crash::None,
        )
        .unwrap();
    // A previously verified token is insufficient if the durable publication disappears.
    let current = store.load(&seed(true)).unwrap();
    registry
        .connection(|c| {
            c.execute_batch("UPDATE registry SET token=NULL")?;
            Ok(())
        })
        .unwrap();
    assert!(store
        .activate_authorized(
            &current,
            [10; 32],
            peer(true, [11; 32]).report([10; 32]),
            &h.token,
            &registry,
            || h.ctx(),
            Crash::None
        )
        .is_err());
    assert_eq!(store.load(&seed(true)).unwrap(), current);
}

#[test]
fn valid_grant_for_other_installed_plan_and_unbound_active_state_are_rejected() {
    let h = Harness::new();
    let registry = h.registry();
    let mut plan = fixture().1;
    plan.candidate = [44; 32];
    let own = Local::prepared(plan.clone(), plan.candidate, [10; 32]).unwrap();
    let other = Local::prepared(plan.clone(), plan.baseline.survivor, [11; 32]).unwrap();
    let store = Store::create(&h.dir.path().join("other.db"), own.saved()).unwrap();
    let initial = store.load(&own.saved()).unwrap();
    assert!(store
        .activate_authorized(
            &initial,
            [10; 32],
            other.report([10; 32]),
            &h.token,
            &registry,
            || h.ctx(),
            Crash::None
        )
        .is_err());
    assert_eq!(store.load(&own.saved()).unwrap(), initial);
    // Old fixture-only update is not a substitute for authorized activation.
    let store = h.store(true);
    let initial = store.load(&seed(true)).unwrap();
    let mut local = Local::restart(initial.saved.clone(), [10; 32]).unwrap();
    local
        .receive_report(peer(true, [11; 32]).report([10; 32]))
        .unwrap();
    local.activate().unwrap();
    store.update(&initial, local.saved(), Crash::None).unwrap();
    let current = store.load(&seed(true)).unwrap();
    assert!(store
        .activate_authorized(
            &current,
            [10; 32],
            peer(true, [11; 32]).report([10; 32]),
            &h.token,
            &registry,
            || h.ctx(),
            Crash::None
        )
        .is_err());
}
