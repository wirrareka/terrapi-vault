use super::{fixture, peers::Local, store::*};
use std::process::Command;

fn prepared(primary: bool) -> Local {
    let (_, p) = fixture();
    Local::prepared(
        p.clone(),
        if primary {
            p.candidate
        } else {
            p.baseline.survivor
        },
        [10; 32],
    )
    .unwrap()
}
fn activated(primary: bool) -> Local {
    let mut local = prepared(primary);
    local
        .receive(prepared(!primary).report(local.boot()))
        .unwrap();
    local.activate().unwrap();
    local
}

#[test]
#[ignore = "subprocess entry point; requires parent-owned fixture DB"]
fn crash_child() {
    let path = std::env::var("MEMBERSHIP_FIXTURE_DB").unwrap();
    let primary = std::env::var("MEMBERSHIP_FIXTURE_ROLE").unwrap() == "primary";
    let quarantine = std::env::var("MEMBERSHIP_FIXTURE_ACTION").unwrap() == "quarantine";
    let point = match std::env::var("MEMBERSHIP_FIXTURE_CRASH").unwrap().as_str() {
        "before" => Crash::BeforeCommit,
        "after" => Crash::AfterCommit,
        _ => panic!("bad crash point"),
    };
    let store = Store::open(std::path::Path::new(&path)).unwrap();
    let old = store.load(&prepared(primary).saved()).unwrap();
    let mut next = Local::restart(old.saved.clone(), [12; 32]).unwrap();
    if quarantine {
        next.quarantine();
    } else {
        next.receive(prepared(!primary).report(next.boot()))
            .unwrap();
        next.activate().unwrap();
    }
    store.update(&old, next.saved(), point).unwrap();
    panic!("crash point not reached");
}

#[test]
fn process_crashes_preserve_atomic_state_and_transition_record_on_both_roles() {
    for primary in [true, false] {
        for quarantine in [false, true] {
            for after in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("recovery.db");
                let initial = if quarantine {
                    activated(primary)
                } else {
                    prepared(primary)
                };
                let mut expected = initial.clone();
                if quarantine {
                    expected.quarantine();
                } else {
                    expected = activated(primary);
                }
                drop(Store::create(&path, initial.saved()).unwrap());
                let output = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "store_tests::crash_child", "--ignored"])
                    .env("MEMBERSHIP_FIXTURE_DB", &path)
                    .env(
                        "MEMBERSHIP_FIXTURE_ROLE",
                        if primary { "primary" } else { "secondary" },
                    )
                    .env(
                        "MEMBERSHIP_FIXTURE_ACTION",
                        if quarantine { "quarantine" } else { "activate" },
                    )
                    .env(
                        "MEMBERSHIP_FIXTURE_CRASH",
                        if after { "after" } else { "before" },
                    )
                    .output()
                    .unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(if after { 82 } else { 81 }),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let store = Store::open(&path).unwrap();
                let actual = store.load(&initial.saved()).unwrap();
                assert_eq!(actual.revision, u64::from(after));
                assert_eq!(
                    actual.saved,
                    if after {
                        expected.saved()
                    } else {
                        initial.saved()
                    }
                );
                store
                    .update(&actual, expected.saved(), Crash::None)
                    .unwrap();
                let done = store.load(&initial.saved()).unwrap();
                assert_eq!(done.saved, expected.saved());
                assert_eq!(done.revision, 1);
                store.update(&done, expected.saved(), Crash::None).unwrap();
                assert_eq!(done, store.load(&initial.saved()).unwrap());
            }
        }
    }
}

#[test]
fn stale_writer_cannot_overwrite_quarantine_or_admit_from_cached_active_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recovery.db");
    let s = activated(false);
    let store = Store::create(&path, s.saved()).unwrap();
    let stale = store.load(&s.saved()).unwrap();
    let other = Store::open(&path).unwrap();
    let mut stopped = s.clone();
    stopped.quarantine();
    other.update(&stale, stopped.saved(), Crash::None).unwrap();
    assert!(store.update(&stale, s.saved(), Crash::None).is_err());
    let request = activated(true).mutation(s.boot()).unwrap();
    assert!(store.admit(&stale, s.boot(), request.clone()).is_err());
    let current = store.load(&s.saved()).unwrap();
    assert!(store.admit(&current, s.boot(), request).is_err());
    assert_eq!(store.admissions().unwrap(), 0);
}

#[test]
fn admission_rechecks_session_inside_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recovery.db");
    let s = activated(false);
    let store = Store::create(&path, s.saved()).unwrap();
    let current = store.load(&s.saved()).unwrap();
    let old = activated(true).mutation(s.boot()).unwrap();
    assert!(store.admit(&current, [20; 32], old).is_err());
    store
        .admit(
            &current,
            [20; 32],
            activated(true).mutation([20; 32]).unwrap(),
        )
        .unwrap();
    assert_eq!(store.admissions().unwrap(), 1);
}

#[test]
fn status_report_is_not_a_mutation_even_when_pair_is_active() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recovery.db");
    let s = activated(false);
    let store = Store::create(&path, s.saved()).unwrap();
    let current = store.load(&s.saved()).unwrap();
    assert!(store
        .admit(&current, s.boot(), activated(true).report(s.boot()))
        .is_err());
    assert_eq!(store.admissions().unwrap(), 0);
}

#[test]
fn fixture_uses_encrypted_vesta_wal_and_full_synchronous() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recovery.db");
    let s = prepared(false);
    let store = Store::create(&path, s.saved()).unwrap();
    store
        .connection(|c| {
            let mode: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
            let sync: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
            let cipher: String = c.query_row("PRAGMA cipher_version", [], |r| r.get(0))?;
            assert_eq!(mode, "wal");
            assert_eq!(sync, 2);
            assert!(!cipher.is_empty());
            Ok(())
        })
        .unwrap();
    drop(store);
    assert!(!std::fs::read(&path)
        .unwrap()
        .starts_with(b"SQLite format 3"));
    assert!(terrapi_vesta::Vesta::open(&path, "wrong-fixture-key").is_err());
}

#[test]
fn wrong_scope_malformed_record_and_transition_log_mismatch_fail_closed() {
    for fault in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.db");
        let initial = prepared(false);
        let store = Store::create(&path, initial.saved()).unwrap();
        assert!(store.load(&prepared(true).saved()).is_err());
        let sql = match fault {
            0 => "UPDATE recovery SET record='{}'",
            1 => "UPDATE recovery SET format=2",
            _ => "DELETE FROM recovery_steps",
        };
        store
            .connection(|c| {
                c.execute_batch(sql)?;
                Ok(())
            })
            .unwrap();
        assert!(store.load(&initial.saved()).is_err());
    }
}
