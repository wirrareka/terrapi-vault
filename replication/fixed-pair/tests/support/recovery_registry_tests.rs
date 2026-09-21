use super::{
    fixture,
    recovery_grant::verify,
    recovery_grant_tests::{claims, context, header, key},
    recovery_registry::*,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{rand::SystemRandom, signature::EcdsaKeyPair};
use std::{
    path::Path,
    sync::{Arc, Barrier},
};

fn input() -> String {
    format!(
        "{}.{}",
        B64.encode(header().to_string()),
        B64.encode(claims().to_string())
    )
}
fn sign(key: &EcdsaKeyPair, input: &str) -> Result<String> {
    let sig = key
        .sign(&SystemRandom::new(), input.as_bytes())
        .map_err(|_| "test signing")?;
    Ok(format!("{input}.{}", B64.encode(sig.as_ref())))
}
fn create(path: &Path) -> Registry {
    Registry::create(path, fixture().1.baseline, "fixture-install", "eu").unwrap()
}

#[test]
fn signature_is_never_requested_before_durable_reservation_and_retry_is_exact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operator.db");
    let db = create(&path);
    let key = key();
    let ctx = context(&key);
    assert!(db
        .issue(&ctx, |_| panic!("unreserved signing"), Crash::None)
        .is_err());
    db.reserve(&input(), &ctx, Crash::None).unwrap();
    let observer = Registry::open(&path).unwrap();
    let token = db
        .issue(
            &ctx,
            |bytes| {
                assert_eq!(observer.load()?.input.as_deref(), Some(bytes));
                sign(&key, bytes)
            },
            Crash::None,
        )
        .unwrap();
    assert!(verify(&token, &ctx).is_ok());
    drop(db);
    let db = Registry::open(&path).unwrap();
    db.reserve(&input(), &ctx, Crash::None).unwrap();
    assert_eq!(
        db.issue(&ctx, |_| panic!("duplicate signing"), Crash::None)
            .unwrap(),
        token
    );
    assert_eq!(db.load().unwrap().allocated_revision, 5);
    assert!(Registry::create(&path, fixture().1.baseline, "fixture-install", "eu").is_err());
}

#[test]
fn concurrent_conflicting_reservations_choose_exactly_one_immutable_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operator.db");
    drop(create(&path));
    let gate = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|n| {
            let path = path.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                let db = Registry::open(&path).unwrap();
                let key = key();
                let mut ctx = context(&key);
                let mut c = claims();
                if n == 1 {
                    ctx.reservation.as_mut().unwrap().plan.candidate = [44; 32];
                    c["plan"] =
                        serde_json::to_value(&ctx.reservation.as_ref().unwrap().plan).unwrap();
                }
                let input = format!(
                    "{}.{}",
                    B64.encode(header().to_string()),
                    B64.encode(c.to_string())
                );
                gate.wait();
                (db.reserve(&input, &ctx, Crash::None).is_ok(), input)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|(ok, _)| *ok).count(), 1);
    let saved = Registry::open(&path).unwrap().load().unwrap();
    assert_eq!(
        saved.input.as_ref(),
        Some(&results.iter().find(|(ok, _)| *ok).unwrap().1)
    );
    assert_eq!(saved.allocated_revision, 5);
    assert!(saved.token.is_none());
}

#[test]
fn changed_time_bytes_scope_or_predecessor_cannot_rebind_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let db = create(&dir.path().join("operator.db"));
    let key = key();
    let ctx = context(&key);
    db.reserve(&input(), &ctx, Crash::None).unwrap();
    let before = db.load().unwrap();
    for field in ["exp", "install_id", "region"] {
        let mut c = claims();
        c[field] = if field == "exp" {
            serde_json::json!(199)
        } else {
            serde_json::json!("other")
        };
        let bytes = format!(
            "{}.{}",
            B64.encode(header().to_string()),
            B64.encode(c.to_string())
        );
        assert!(db.reserve(&bytes, &ctx, Crash::None).is_err());
    }
    let mut stale = context(&key);
    stale.reservation.as_mut().unwrap().plan.baseline.digest = [99; 32];
    assert!(db.reserve(&input(), &stale, Crash::None).is_err());
    assert_eq!(db.load().unwrap(), before);
    assert!(db
        .issue(
            &ctx,
            |bytes| {
                let mut c = claims();
                c["exp"] = serde_json::json!(199);
                let altered = format!(
                    "{}.{}",
                    bytes.split('.').next().unwrap(),
                    B64.encode(c.to_string())
                );
                sign(&key, &altered)
            },
            Crash::None
        )
        .is_err());
    assert_eq!(db.load().unwrap(), before);
}

#[test]
fn failed_signing_or_expired_revoked_unfenced_retry_never_releases_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let db = create(&dir.path().join("operator.db"));
    let key = key();
    let ctx = context(&key);
    db.reserve(&input(), &ctx, Crash::None).unwrap();
    let before = db.load().unwrap();
    assert!(db
        .issue(&ctx, |_| Err("signer unavailable".into()), Crash::None)
        .is_err());
    assert_eq!(db.load().unwrap(), before);
    let token = db
        .issue(&ctx, |bytes| sign(&key, bytes), Crash::None)
        .unwrap();
    for mode in 0..4 {
        let mut bad = context(&key);
        match mode {
            0 => bad.now = 200,
            1 => bad.keys.clear(),
            2 => bad.fencing_confirmed = false,
            _ => bad.reservation = None,
        }
        assert!(db
            .issue(&bad, |_| panic!("invalid retry signed"), Crash::None)
            .is_err());
        assert_eq!(db.load().unwrap().token.as_ref(), Some(&token));
    }
}

#[test]
#[ignore = "subprocess entry point for registry crash matrix"]
fn crash_child() {
    use ring::signature::KeyPair;
    use std::io::Write;
    let path = std::env::var_os("RECOVERY_REGISTRY_FIXTURE").unwrap();
    let point = std::env::var("RECOVERY_REGISTRY_POINT").unwrap();
    let db = Registry::open(Path::new(&path)).unwrap();
    let key = key();
    let ctx = context(&key);
    // Public test key only, passed back to the parent through its private pipe.
    println!(
        "fixture-public-key={}",
        B64.encode(key.public_key().as_ref())
    );
    std::io::stdout().flush().unwrap();
    match point.as_str() {
        "reserve-before" => {
            db.reserve(&input(), &ctx, Crash::BeforeCommit).unwrap();
        }
        "reserve-after" => {
            db.reserve(&input(), &ctx, Crash::AfterCommit).unwrap();
        }
        "sign-after" => {
            db.issue(&ctx, |bytes| sign(&key, bytes), Crash::AfterSign)
                .unwrap();
        }
        "issue-before" => {
            db.issue(&ctx, |bytes| sign(&key, bytes), Crash::BeforeCommit)
                .unwrap();
        }
        "issue-after" => {
            db.issue(&ctx, |bytes| sign(&key, bytes), Crash::AfterCommit)
                .unwrap();
        }
        _ => panic!("unknown crash point"),
    }
    panic!("crash was not reached");
}

#[test]
fn process_crashes_preserve_reservation_and_publication_boundaries() {
    for (point, code) in [
        ("reserve-before", 91),
        ("reserve-after", 92),
        ("sign-after", 93),
        ("issue-before", 91),
        ("issue-after", 92),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        let db = create(&path);
        let key = key();
        let ctx = context(&key);
        if !point.starts_with("reserve") {
            db.reserve(&input(), &ctx, Crash::None).unwrap();
        }
        drop(db);
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_registry_tests::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("RECOVERY_REGISTRY_FIXTURE", &path)
            .env("RECOVERY_REGISTRY_POINT", point)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(code),
            "{point}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let db = Registry::open(&path).unwrap();
        let saved = db.load().unwrap();
        assert_eq!(saved.input.is_some(), point != "reserve-before");
        assert_eq!(
            saved.allocated_revision,
            if point == "reserve-before" { 4 } else { 5 }
        );
        assert_eq!(saved.token.is_some(), point == "issue-after");
        // Child keys are ephemeral. A published child token remains immutable;
        // it cannot be silently replaced by this parent's different key.
        if point == "issue-after" {
            assert!(db
                .issue(&ctx, |_| panic!("re-signing published grant"), Crash::None)
                .is_err());
            assert_eq!(db.load().unwrap(), saved);
            let stdout = String::from_utf8(out.stdout).unwrap();
            let public = stdout
                .lines()
                .find_map(|l| l.strip_prefix("fixture-public-key="))
                .unwrap();
            let mut child_context = context(&key);
            child_context.keys[0].1 = B64.decode(public).unwrap();
            let replay = db
                .issue(
                    &child_context,
                    |_| panic!("retry re-signed grant"),
                    Crash::None,
                )
                .unwrap();
            assert_eq!(Some(&replay), saved.token.as_ref());
            assert!(verify(&replay, &child_context).is_ok());
        } else {
            db.reserve(&input(), &ctx, Crash::None).unwrap();
            let token = db
                .issue(&ctx, |bytes| sign(&key, bytes), Crash::None)
                .unwrap();
            assert!(verify(&token, &ctx).is_ok());
            assert_eq!(db.load().unwrap().allocated_revision, 5);
        }
    }
}

#[test]
fn concurrent_issuers_sign_once_and_return_identical_committed_token() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operator.db");
    let db = create(&path);
    let key = Arc::new(key());
    db.reserve(&input(), &context(&key), Crash::None).unwrap();
    drop(db);
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let key = key.clone();
            let calls = calls.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                let db = Registry::open(&path).unwrap();
                gate.wait();
                db.issue(
                    &context(&key),
                    |bytes| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        sign(&key, bytes)
                    },
                    Crash::None,
                )
                .unwrap()
            })
        })
        .collect();
    let tokens: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(tokens[0], tokens[1]);
    assert_eq!(
        Registry::open(&path).unwrap().load().unwrap().token,
        Some(tokens[0].clone())
    );
}

#[test]
fn corrupt_registry_and_missing_database_fail_closed_before_signing() {
    for sql in [
        "UPDATE registry SET format=2",
        "UPDATE registry SET allocated=7",
        "UPDATE registry SET baseline='{}'",
        "UPDATE registry SET input='broken'",
        "UPDATE registry SET token='wrong.input.signature'",
        "DELETE FROM registry",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        let db = create(&path);
        let key = key();
        let ctx = context(&key);
        db.reserve(&input(), &ctx, Crash::None).unwrap();
        db.connection(|c| {
            c.execute_batch(sql)?;
            Ok(())
        })
        .unwrap();
        drop(db);
        let db = Registry::open(&path).unwrap();
        assert!(
            db.issue(&ctx, |_| panic!("corrupt state signed"), Crash::None)
                .is_err(),
            "{sql}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.db");
    assert!(Registry::open(&path).is_err());
    assert!(!path.exists());
}
