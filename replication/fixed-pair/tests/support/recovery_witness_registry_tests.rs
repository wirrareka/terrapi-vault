use super::{
    fixture,
    recovery_grant_tests::{claims, context, header, key},
    recovery_registry::{Crash, Registry, Result},
    recovery_witness_registry::{Adapter, Cut},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair},
};
use std::{cell::Cell, path::Path};

fn allow() -> Result<()> {
    Ok(())
}
fn input() -> String {
    format!(
        "{}.{}",
        B64.encode(header().to_string()),
        B64.encode(claims().to_string())
    )
}
fn create(path: &Path) -> Registry {
    Registry::create(path, fixture().1.baseline, "fixture-install", "eu").unwrap()
}
fn sign(key: &EcdsaKeyPair, bytes: &str) -> Result<String> {
    let signature = key
        .sign(&SystemRandom::new(), bytes.as_bytes())
        .map_err(|_| "signing")?;
    Ok(format!("{bytes}.{}", B64.encode(signature.as_ref())))
}

#[test]
fn reserved_authority_restores_empty_local_projection() {
    let dir = tempfile::tempdir().unwrap();
    let authority = create(&dir.path().join("authority.db"));
    let local = create(&dir.path().join("local.db"));
    let key = key();
    let ctx = context(&key);
    authority.reserve(&input(), &ctx, Crash::None).unwrap();
    Adapter {
        authority: &authority,
        local: &local,
    }
    .reconcile(&ctx, allow)
    .unwrap();
    assert_eq!(authority.load().unwrap(), local.load().unwrap());
}

#[test]
fn unavailable_unreserved_and_invalid_context_never_sign() {
    let dir = tempfile::tempdir().unwrap();
    let authority = create(&dir.path().join("authority.db"));
    let local = create(&dir.path().join("local.db"));
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    let key = key();
    let ctx = context(&key);
    assert!(adapter
        .issue(&ctx, allow, |_| panic!("unreserved signing"), Cut::None)
        .is_err());
    let denied = || Err("unknown external continuity".into());
    assert!(adapter.reserve(&input(), &ctx, denied, Cut::None).is_err());
    assert!(authority.load().unwrap().input.is_none());
    adapter.reserve(&input(), &ctx, allow, Cut::None).unwrap();
    assert!(adapter
        .issue(&ctx, denied, |_| panic!("untrusted signing"), Cut::None)
        .is_err());
    for mode in 0..4 {
        let mut bad = context(&key);
        match mode {
            0 => bad.now = 200,
            1 => bad.keys.clear(),
            2 => bad.fencing_confirmed = false,
            _ => bad.reservation = None,
        }
        assert!(adapter
            .issue(&bad, allow, |_| panic!("invalid signing"), Cut::None)
            .is_err());
    }
    assert!(authority.load().unwrap().token.is_none());
    assert_eq!(authority.load().unwrap(), local.load().unwrap());
}

#[test]
fn publication_is_recoverable_when_access_is_lost_before_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let authority = create(&dir.path().join("authority.db"));
    let observer = Registry::open(&dir.path().join("authority.db")).unwrap();
    let local = create(&dir.path().join("local.db"));
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    let key = key();
    let ctx = context(&key);
    adapter.reserve(&input(), &ctx, allow, Cut::None).unwrap();
    let available = Cell::new(true);
    let access = || {
        if available.get() {
            Ok(())
        } else {
            Err("authority unavailable".into())
        }
    };
    assert!(adapter
        .issue(
            &ctx,
            access,
            |bytes| {
                assert_eq!(observer.load()?.input.as_deref(), Some(bytes));
                available.set(false);
                sign(&key, bytes)
            },
            Cut::None
        )
        .is_err());
    let token = authority.load().unwrap().token.unwrap();
    assert!(local.load().unwrap().token.is_none());
    assert_eq!(
        adapter
            .issue(&ctx, allow, |_| panic!("duplicate signing"), Cut::None)
            .unwrap(),
        token
    );
    assert_eq!(local.load().unwrap().token.as_deref(), Some(token.as_str()));
    assert!(super::recovery_grant::verify(&token, &ctx).is_ok());
}

#[test]
fn sql_projection_failure_leaves_authoritative_publication_for_exact_retry() {
    let dir = tempfile::tempdir().unwrap();
    let authority = create(&dir.path().join("authority.db"));
    let local = create(&dir.path().join("local.db"));
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    let key = key();
    let ctx = context(&key);
    adapter.reserve(&input(), &ctx, allow, Cut::None).unwrap();
    local.connection(|c| { c.execute_batch("CREATE TRIGGER reject_publication BEFORE UPDATE ON registry WHEN NEW.token IS NOT NULL BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")?; Ok(()) }).unwrap();
    assert!(adapter
        .issue(&ctx, allow, |bytes| sign(&key, bytes), Cut::None)
        .is_err());
    let token = authority.load().unwrap().token.unwrap();
    assert!(local.load().unwrap().token.is_none());
    local
        .connection(|c| {
            c.execute_batch("DROP TRIGGER reject_publication")?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        adapter
            .issue(
                &ctx,
                allow,
                |_| panic!("re-sign after SQL failure"),
                Cut::None
            )
            .unwrap(),
        token
    );
}

#[test]
fn conflicting_local_history_and_corrupt_authority_are_not_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let authority = create(&dir.path().join("authority.db"));
    let local = create(&dir.path().join("local.db"));
    let key = key();
    let ctx = context(&key);
    let mut other = context(&key);
    other.reservation.as_mut().unwrap().plan.candidate = [44; 32];
    let mut c = claims();
    c["plan"] = serde_json::to_value(&other.reservation.as_ref().unwrap().plan).unwrap();
    let conflicting = format!(
        "{}.{}",
        B64.encode(header().to_string()),
        B64.encode(c.to_string())
    );
    local.reserve(&conflicting, &other, Crash::None).unwrap();
    authority.reserve(&input(), &ctx, Crash::None).unwrap();
    let before = local.load().unwrap();
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    assert!(adapter
        .issue(&ctx, allow, |_| panic!("divergent signing"), Cut::None)
        .is_err());
    assert_eq!(local.load().unwrap(), before);
    assert!(authority.load().unwrap().token.is_none());
    let empty = create(&dir.path().join("empty.db"));
    authority
        .connection(|c| {
            c.execute(
                "UPDATE registry SET token=?1",
                [format!("{}.invalid", input())],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(Adapter {
        authority: &authority,
        local: &empty
    }
    .reconcile(&ctx, allow)
    .is_err());
    assert!(empty.load().unwrap().input.is_none());
}

#[test]
fn concurrent_adapters_sign_once_and_project_identical_token() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };
    let dir = tempfile::tempdir().unwrap();
    let authority_path = dir.path().join("authority.db");
    drop(create(&authority_path));
    for n in 0..2 {
        drop(create(&dir.path().join(format!("local-{n}.db"))));
    }
    let key = key();
    let gate = Barrier::new(2);
    let signatures = AtomicUsize::new(0);
    let results = std::thread::scope(|s| {
        let handles: Vec<_> = (0..2)
            .map(|n| {
                let key = &key;
                let gate = &gate;
                let signatures = &signatures;
                let authority_path = &authority_path;
                let local_path = dir.path().join(format!("local-{n}.db"));
                s.spawn(move || {
                    let authority = Registry::open(authority_path).unwrap();
                    let local = Registry::open(&local_path).unwrap();
                    let ctx = context(key);
                    let adapter = Adapter {
                        authority: &authority,
                        local: &local,
                    };
                    gate.wait();
                    adapter.reserve(&input(), &ctx, allow, Cut::None).unwrap();
                    let token = adapter
                        .issue(
                            &ctx,
                            allow,
                            |bytes| {
                                signatures.fetch_add(1, Ordering::SeqCst);
                                sign(key, bytes)
                            },
                            Cut::None,
                        )
                        .unwrap();
                    assert_eq!(local.load().unwrap().token.as_deref(), Some(token.as_str()));
                    token
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results[0], results[1]);
    assert_eq!(signatures.load(Ordering::SeqCst), 1);
}

#[test]
#[ignore = "subprocess entry point for witness/projection crash matrix"]
fn crash_child() {
    use std::io::Write;
    let dir = std::env::var_os("WITNESS_REGISTRY_FIXTURE").unwrap();
    let dir = Path::new(&dir);
    let point = std::env::var("WITNESS_REGISTRY_POINT").unwrap();
    let authority = Registry::open(&dir.join("authority.db")).unwrap();
    let local = Registry::open(&dir.join("local.db")).unwrap();
    let key = key();
    let ctx = context(&key);
    println!(
        "fixture-public-key={}",
        B64.encode(key.public_key().as_ref())
    );
    std::io::stdout().flush().unwrap();
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    let cut = match point.as_str() {
        "reservation" => Cut::AfterReservation,
        "publication" => Cut::AfterPublication,
        "projection-before" => Cut::BeforeProjectionCommit,
        "projection-after" => Cut::AfterProjectionCommit,
        _ => panic!("unknown cut"),
    };
    if point == "reservation" {
        adapter.reserve(&input(), &ctx, allow, cut).unwrap();
    } else {
        adapter.reserve(&input(), &ctx, allow, Cut::None).unwrap();
        adapter
            .issue(&ctx, allow, |bytes| sign(&key, bytes), cut)
            .unwrap();
    }
    panic!("cut not reached");
}

#[test]
fn process_crashes_recover_exact_authoritative_bytes_without_resigning() {
    for (point, code) in [
        ("reservation", 101),
        ("publication", 102),
        ("projection-before", 91),
        ("projection-after", 92),
    ] {
        let dir = tempfile::tempdir().unwrap();
        drop(create(&dir.path().join("authority.db")));
        drop(create(&dir.path().join("local.db")));
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_witness_registry_tests::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("WITNESS_REGISTRY_FIXTURE", dir.path())
            .env("WITNESS_REGISTRY_POINT", point)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(code),
            "{point}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).unwrap();
        let public = stdout
            .lines()
            .find_map(|l| l.strip_prefix("fixture-public-key="))
            .unwrap();
        let key = key();
        let mut ctx = context(&key);
        ctx.keys[0].1 = B64.decode(public).unwrap();
        let authority = Registry::open(&dir.path().join("authority.db")).unwrap();
        let local = Registry::open(&dir.path().join("local.db")).unwrap();
        let saved = authority.load().unwrap();
        assert!(saved.input.is_some());
        assert_eq!(saved.token.is_some(), point != "reservation");
        assert_eq!(
            local.load().unwrap().token.is_some(),
            point == "projection-after"
        );
        assert_eq!(
            local.load().unwrap().input.is_some(),
            point != "reservation"
        );
        let adapter = Adapter {
            authority: &authority,
            local: &local,
        };
        adapter.reconcile(&ctx, allow).unwrap();
        assert_eq!(local.load().unwrap(), saved);
        if let Some(token) = &saved.token {
            assert_eq!(
                &adapter
                    .issue(
                        &ctx,
                        allow,
                        |_| panic!("published token re-signed"),
                        Cut::None
                    )
                    .unwrap(),
                token
            );
        }
        assert_eq!(authority.load().unwrap(), saved);
    }
}

#[test]
fn empty_second_projection_cannot_allocate_another_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let authority = create(&dir.path().join("authority.db"));
    let first = create(&dir.path().join("first.db"));
    let second = create(&dir.path().join("second.db"));
    let key = key();
    let ctx = context(&key);
    let first_adapter = Adapter {
        authority: &authority,
        local: &first,
    };
    first_adapter
        .reserve(&input(), &ctx, allow, Cut::None)
        .unwrap();
    let before = authority.load().unwrap();
    let mut other = context(&key);
    other.reservation.as_mut().unwrap().plan.candidate = [44; 32];
    let mut claims = claims();
    claims["plan"] = serde_json::to_value(&other.reservation.as_ref().unwrap().plan).unwrap();
    let draft = format!(
        "{}.{}",
        B64.encode(header().to_string()),
        B64.encode(claims.to_string())
    );
    let second_adapter = Adapter {
        authority: &authority,
        local: &second,
    };
    assert!(second_adapter
        .reserve(&draft, &other, allow, Cut::None)
        .is_err());
    assert!(second_adapter
        .issue(
            &other,
            allow,
            |_| panic!("conflicting candidate signed"),
            Cut::None
        )
        .is_err());
    assert_eq!(authority.load().unwrap(), before);
    assert!(second.load().unwrap().input.is_none());
    second_adapter.reconcile(&ctx, allow).unwrap();
    assert_eq!(second.load().unwrap(), before);
}

#[test]
fn completion_rows_block_this_two_phase_adapter_on_either_side() {
    let dir = tempfile::tempdir().unwrap();
    let authority = create(&dir.path().join("authority.db"));
    let local = create(&dir.path().join("local.db"));
    let key = key();
    let ctx = context(&key);
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    adapter.reserve(&input(), &ctx, allow, Cut::None).unwrap();
    for db in [&local, &authority] {
        // Any completion row, even malformed, is outside this adapter's remit.
        db.connection(|c| {
            c.execute("INSERT INTO completion VALUES(1,1,'{}',zeroblob(32))", [])?;
            Ok(())
        })
        .unwrap();
        assert!(adapter
            .issue(
                &ctx,
                allow,
                |_| panic!("completion state signed"),
                Cut::None
            )
            .is_err());
        assert!(authority.load().unwrap().token.is_none());
        assert!(local.load().unwrap().token.is_none());
        db.connection(|c| {
            c.execute("DELETE FROM completion", [])?;
            Ok(())
        })
        .unwrap();
    }
}
