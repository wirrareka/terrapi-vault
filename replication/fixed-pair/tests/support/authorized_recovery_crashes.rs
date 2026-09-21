use super::{
    authorized_recovery_tests::{peer, seed, Harness},
    peers::Local,
    recovery_grant_tests::{context, key},
    recovery_registry::Registry,
    store::{Crash, Store},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::signature::KeyPair;
use std::{path::Path, process::Command};

#[test]
#[ignore = "subprocess entry point for authorized activation crash matrix"]
fn crash_child() {
    let dir = std::env::var_os("AUTHORIZED_RECOVERY_DIR").unwrap();
    let dir = Path::new(&dir);
    let primary = std::env::var("AUTHORIZED_RECOVERY_ROLE").unwrap() == "primary";
    let crash = match std::env::var("AUTHORIZED_RECOVERY_POINT").unwrap().as_str() {
        "before" => Crash::BeforeCommit,
        "after" => Crash::AfterCommit,
        _ => panic!("bad point"),
    };
    let registry = Registry::open(&dir.join("operator.db")).unwrap();
    let token = registry.load().unwrap().token.unwrap();
    let mut ctx = context(&key());
    ctx.keys[0].1 = B64
        .decode(std::env::var("AUTHORIZED_RECOVERY_PUBLIC_KEY").unwrap())
        .unwrap();
    let store = Store::open(&Harness::path(dir, primary)).unwrap();
    let other = Store::open(&Harness::path(dir, !primary)).unwrap();
    let other = Local::restart(other.load(&seed(!primary)).unwrap().saved, [21; 32]).unwrap();
    let current = store.load(&seed(primary)).unwrap();
    store
        .activate_authorized(
            &current,
            [20; 32],
            other.report([20; 32]),
            &token,
            &registry,
            || ctx,
            crash,
        )
        .unwrap();
    panic!("crash not reached");
}

#[test]
fn four_asymmetric_crashes_preserve_atomic_binding_and_resume_same_grant() {
    for first_primary in [true, false] {
        for (point, code) in [("before", 81), ("after", 82)] {
            let h = Harness::new();
            let registry = h.registry();
            let first = h.store(first_primary);
            let initial = first.load(&seed(first_primary)).unwrap();
            first
                .activate_authorized(
                    &initial,
                    [10; 32],
                    peer(first_primary, [11; 32]).report([10; 32]),
                    &h.token,
                    &registry,
                    || h.ctx(),
                    Crash::None,
                )
                .unwrap();
            drop(first);
            drop(registry);
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "authorized_recovery_crashes::crash_child",
                    "--ignored",
                ])
                .env("AUTHORIZED_RECOVERY_DIR", h.dir.path())
                .env(
                    "AUTHORIZED_RECOVERY_ROLE",
                    if first_primary {
                        "secondary"
                    } else {
                        "primary"
                    },
                )
                .env("AUTHORIZED_RECOVERY_POINT", point)
                .env(
                    "AUTHORIZED_RECOVERY_PUBLIC_KEY",
                    B64.encode(h.key.public_key().as_ref()),
                )
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(code),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let first = h.store(first_primary);
            let second = h.store(!first_primary);
            let registry = h.registry();
            let first_record = first.load(&seed(first_primary)).unwrap();
            let second_record = second.load(&seed(!first_primary)).unwrap();
            assert_eq!(first_record.revision, 1);
            assert_eq!(second_record.revision, if point == "after" { 1 } else { 0 });
            assert_eq!(
                second.activation_token(&second_record).unwrap().is_some(),
                point == "after"
            );
            let live_first = Local::restart(first_record.saved, [30; 32]).unwrap();
            // A token saved before a crash is not an indefinitely valid permission.
            let mut expired = h.ctx();
            expired.now = 200;
            assert!(second
                .activate_authorized(
                    &second_record,
                    [31; 32],
                    live_first.report([31; 32]),
                    &h.token,
                    &registry,
                    || expired,
                    Crash::None
                )
                .is_err());
            assert_eq!(second.load(&seed(!first_primary)).unwrap(), second_record);
            assert!(second
                .activate_authorized(
                    &second_record,
                    [31; 32],
                    live_first.report([20; 32]),
                    &h.token,
                    &registry,
                    || h.ctx(),
                    Crash::None
                )
                .is_err());
            second
                .activate_authorized(
                    &second_record,
                    [31; 32],
                    live_first.report([31; 32]),
                    &h.token,
                    &registry,
                    || h.ctx(),
                    Crash::None,
                )
                .unwrap();
            let current = second.load(&seed(!first_primary)).unwrap();
            assert_eq!(current.revision, 1);
            assert_eq!(
                second.activation_token(&current).unwrap(),
                Some(h.token.clone())
            );
            assert_eq!(registry.load().unwrap().allocated_revision, 5);
        }
    }
}

#[test]
fn offline_reads_and_quarantine_survive_grant_expiry_without_reactivation() {
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
    }
    drop(registry);
    // Reads and restrictive quarantine require no registry or signing key.
    let store = h.store(true);
    let current = store.load(&seed(true)).unwrap();
    assert!(Local::restart(current.saved.clone(), [12; 32])
        .unwrap()
        .is_active());
    let mut local = Local::restart(current.saved.clone(), [12; 32]).unwrap();
    local.quarantine();
    store.update(&current, local.saved(), Crash::None).unwrap();
    drop(store);
    let store = h.store(true);
    let current = store.load(&seed(true)).unwrap();
    assert_eq!(
        store.activation_token(&current).unwrap(),
        Some(h.token.clone())
    );
    assert!(!Local::restart(current.saved.clone(), [13; 32])
        .unwrap()
        .is_active());
    let registry = h.registry();
    assert!(store
        .activate_authorized(
            &current,
            [13; 32],
            peer(true, [14; 32]).report([13; 32]),
            &h.token,
            &registry,
            || h.ctx(),
            Crash::None
        )
        .is_err());
}

#[test]
fn missing_or_corrupt_activation_binding_cannot_be_repaired_by_retry() {
    for sql in [
        "DELETE FROM recovery_grants",
        "UPDATE recovery_grants SET revision=9",
        "UPDATE recovery_grants SET token='wrong'",
    ] {
        let h = Harness::new();
        let registry = h.registry();
        let store = h.store(true);
        let initial = store.load(&seed(true)).unwrap();
        store
            .activate_authorized(
                &initial,
                [10; 32],
                peer(true, [11; 32]).report([10; 32]),
                &h.token,
                &registry,
                || h.ctx(),
                Crash::None,
            )
            .unwrap();
        store
            .connection(|c| {
                c.execute_batch(sql)?;
                Ok(())
            })
            .unwrap();
        drop(store);
        let store = h.store(true);
        let current = store.load(&seed(true)).unwrap();
        assert!(store
            .activate_authorized(
                &current,
                [12; 32],
                peer(true, [11; 32]).report([12; 32]),
                &h.token,
                &registry,
                || h.ctx(),
                Crash::None
            )
            .is_err());
        assert_eq!(store.load(&seed(true)).unwrap(), current);
    }
}
