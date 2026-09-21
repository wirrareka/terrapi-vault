use super::{
    authorized_recovery_tests::{seed, Harness},
    fixture,
    recovery_completion::{token_digest, Completion, Evidence},
    recovery_completion_tests::{activate, request},
    recovery_registry::{Crash, Registry, Result},
    recovery_witness_completion::Cut,
    recovery_witness_registry::Adapter,
    store::Store,
};
use std::{cell::Cell, path::Path};

fn allow() -> Result<()> {
    Ok(())
}
fn local(h: &Harness) -> Registry {
    Registry::create(
        &h.dir.path().join("local.db"),
        fixture().1.baseline,
        "fixture-install",
        "eu",
    )
    .unwrap()
}
fn collect(dir: &Path, req: &Completion) -> Result<[Evidence; 2]> {
    let [primary, survivor] = [true, false].map(|is_primary| {
        Evidence::capture(
            &Store::open(&Harness::path(dir, is_primary))?,
            &req.plan,
            if is_primary {
                req.plan.candidate
            } else {
                req.plan.baseline.survivor
            },
            req.request_id,
            Some(req.plan.baseline.checkpoint),
        )
    });
    Ok([primary?, survivor?])
}

#[test]
fn historical_completion_restores_an_empty_projection() {
    let h = Harness::new();
    activate(&h);
    let authority = h.registry();
    let local = local(&h);
    let req = request(&h, [70; 32]);
    authority
        .complete(&req, || h.ctx(), || Ok(req.evidence.clone()), Crash::None)
        .unwrap();
    let restored = Adapter {
        authority: &authority,
        local: &local,
    }
    .reconcile_completion(&req, allow)
    .unwrap();
    assert_eq!(restored, req);
    assert_eq!(local.load_completion().unwrap(), Some(req));
    assert_eq!(authority.load().unwrap(), local.load().unwrap());
}

#[test]
fn new_completion_and_historical_retry_leave_members_unchanged() {
    let h = Harness::new();
    activate(&h);
    let authority = h.registry();
    let local = local(&h);
    let req = request(&h, [70; 32]);
    let before = [
        h.store(true).load(&seed(true)).unwrap(),
        h.store(false).load(&seed(false)).unwrap(),
    ];
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    assert_eq!(
        adapter
            .complete(
                &req,
                || h.ctx(),
                allow,
                || collect(h.dir.path(), &req),
                Cut::None
            )
            .unwrap(),
        req
    );
    assert_eq!(
        adapter
            .complete(
                &req,
                || panic!("historical retry refreshed grant"),
                allow,
                || panic!("historical retry recollected evidence"),
                Cut::None
            )
            .unwrap(),
        req
    );
    assert_eq!(
        [
            h.store(true).load(&seed(true)).unwrap(),
            h.store(false).load(&seed(false)).unwrap()
        ],
        before
    );
    // Historical completion does not reopen the grant-delivery path.
    let mut expired = h.ctx();
    expired.now = 200;
    assert!(adapter
        .issue(
            &expired,
            allow,
            |_| panic!("completion re-signed grant"),
            super::recovery_witness_registry::Cut::None
        )
        .is_err());
}

#[test]
fn denied_authority_expiry_and_changed_evidence_cannot_complete() {
    let h = Harness::new();
    activate(&h);
    let authority = h.registry();
    let local = local(&h);
    let req = request(&h, [70; 32]);
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    assert!(adapter
        .complete(
            &req,
            || panic!("denied context"),
            || Err("unknown continuity".into()),
            || panic!("denied collector"),
            Cut::None
        )
        .is_err());
    assert!(adapter
        .complete(
            &req,
            || {
                let mut ctx = h.ctx();
                ctx.now = 200;
                ctx
            },
            allow,
            || panic!("expired collector"),
            Cut::None
        )
        .is_err());
    assert!(adapter
        .complete(
            &req,
            || h.ctx(),
            allow,
            || {
                let mut evidence = collect(h.dir.path(), &req)?;
                evidence[0].activation_revision += 1;
                Ok(evidence)
            },
            Cut::None
        )
        .is_err());
    assert!(authority.load_completion().unwrap().is_none());
    assert!(local.load().unwrap().input.is_none());
    assert!(adapter.reconcile_completion(&req, allow).is_err());
}

#[test]
fn authority_commit_survives_lost_access_and_retries_without_fresh_context() {
    let h = Harness::new();
    activate(&h);
    let authority = h.registry();
    let local = local(&h);
    let req = request(&h, [70; 32]);
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    let available = Cell::new(true);
    assert!(adapter
        .complete(
            &req,
            || h.ctx(),
            || if available.get() {
                Ok(())
            } else {
                Err("lost authority".into())
            },
            || {
                let evidence = collect(h.dir.path(), &req)?;
                available.set(false);
                Ok(evidence)
            },
            Cut::None
        )
        .is_err());
    assert_eq!(authority.load_completion().unwrap(), Some(req.clone()));
    assert!(local.load().unwrap().input.is_none());
    assert!(adapter
        .reconcile_completion(&req, || Err("still unavailable".into()))
        .is_err());
    assert!(local.load_completion().unwrap().is_none());
    assert_eq!(
        adapter
            .complete(
                &req,
                || panic!("retry renewed authority"),
                allow,
                || panic!("retry recollected evidence"),
                Cut::None
            )
            .unwrap(),
        req
    );
}

#[test]
fn local_insert_failure_rolls_back_publication_and_completion_together() {
    let h = Harness::new();
    activate(&h);
    let authority = h.registry();
    let local = local(&h);
    let req = request(&h, [70; 32]);
    let before = local.load().unwrap();
    local.connection(|c| { c.execute_batch("CREATE TRIGGER reject_completion BEFORE INSERT ON completion BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")?; Ok(()) }).unwrap();
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    assert!(adapter
        .complete(
            &req,
            || h.ctx(),
            allow,
            || collect(h.dir.path(), &req),
            Cut::None
        )
        .is_err());
    assert_eq!(authority.load_completion().unwrap(), Some(req.clone()));
    assert_eq!(local.load().unwrap(), before);
    assert!(local.load_completion().unwrap().is_none());
    local
        .connection(|c| {
            c.execute_batch("DROP TRIGGER reject_completion")?;
            Ok(())
        })
        .unwrap();
    adapter.reconcile_completion(&req, allow).unwrap();
    let bytes = |r: &Registry| {
        r.connection(|c| {
            Ok(c.query_row(
                "SELECT record,digest FROM completion WHERE id=1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )?)
        })
        .unwrap()
    };
    assert_eq!(bytes(&authority), bytes(&local));
    // Equal parsed JSON is insufficient: never rewrite different immutable bytes.
    let (json, _) = bytes(&local);
    let altered = format!(" {json}");
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(altered.as_bytes());
    local
        .connection(|c| {
            c.execute(
                "UPDATE completion SET record=?1,digest=?2",
                rusqlite::params![altered, digest.as_slice()],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(local.load_completion().unwrap(), Some(req.clone()));
    let before = bytes(&local);
    assert!(adapter.reconcile_completion(&req, allow).is_err());
    assert_eq!(bytes(&local), before);
}

#[test]
fn divergent_local_completion_and_corrupt_authority_are_not_overwritten() {
    let h = Harness::new();
    activate(&h);
    let authority = h.registry();
    let local = local(&h);
    let first = request(&h, [70; 32]);
    let other = request(&h, [71; 32]);
    let adapter = Adapter {
        authority: &authority,
        local: &local,
    };
    adapter.reconcile(&h.ctx(), allow).unwrap();
    local
        .complete(
            &other,
            || h.ctx(),
            || collect(h.dir.path(), &other),
            Crash::None,
        )
        .unwrap();
    assert!(adapter
        .complete(
            &first,
            || h.ctx(),
            allow,
            || collect(h.dir.path(), &first),
            Cut::None
        )
        .is_err());
    assert_eq!(authority.load_completion().unwrap(), Some(first.clone()));
    assert_eq!(local.load_completion().unwrap(), Some(other.clone()));
    assert!(adapter
        .complete(
            &other,
            || panic!("conflict context"),
            allow,
            || panic!("conflict collect"),
            Cut::None
        )
        .is_err());
    authority
        .connection(|c| {
            c.execute("UPDATE completion SET digest=zeroblob(32)", [])?;
            Ok(())
        })
        .unwrap();
    assert!(adapter.reconcile_completion(&first, allow).is_err());
    assert_eq!(local.load_completion().unwrap(), Some(other));
}

#[test]
fn concurrent_completion_requests_have_one_authoritative_winner() {
    use std::sync::Barrier;
    let h = Harness::new();
    activate(&h);
    let requests = [request(&h, [70; 32]), request(&h, [71; 32])];
    for n in 0..2 {
        drop(
            Registry::create(
                &h.dir.path().join(format!("local-{n}.db")),
                fixture().1.baseline,
                "fixture-install",
                "eu",
            )
            .unwrap(),
        );
    }
    let gate = Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = requests
            .iter()
            .enumerate()
            .map(|(n, req)| {
                let h = &h;
                let gate = &gate;
                scope.spawn(move || {
                    let authority = h.registry();
                    let local =
                        Registry::open(&h.dir.path().join(format!("local-{n}.db"))).unwrap();
                    let adapter = Adapter {
                        authority: &authority,
                        local: &local,
                    };
                    gate.wait();
                    adapter
                        .complete(
                            req,
                            || h.ctx(),
                            allow,
                            || collect(h.dir.path(), req),
                            Cut::None,
                        )
                        .ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|v| v.is_some()).count(), 1);
    let winner = results.into_iter().flatten().next().unwrap();
    assert_eq!(h.registry().load_completion().unwrap(), Some(winner));
}

#[test]
#[ignore = "subprocess entry point for witness completion crashes"]
fn crash_child() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    let dir = std::env::var_os("WITNESS_COMPLETION_FIXTURE").unwrap();
    let dir = Path::new(&dir);
    let point = std::env::var("WITNESS_COMPLETION_POINT").unwrap();
    let authority = Registry::open(&dir.join("operator.db")).unwrap();
    let local = Registry::open(&dir.join("local.db")).unwrap();
    let token = authority.load().unwrap().token.unwrap();
    let plan = fixture().1;
    let req = Completion {
        request_id: [70; 32],
        plan: plan.clone(),
        grant_id: [8; 32],
        token_digest: token_digest(&token),
        evidence: [true, false].map(|primary| {
            Evidence::capture(
                &Store::open(&Harness::path(dir, primary)).unwrap(),
                &plan,
                if primary {
                    plan.candidate
                } else {
                    plan.baseline.survivor
                },
                [70; 32],
                Some(plan.baseline.checkpoint),
            )
            .unwrap()
        }),
    };
    let mut ctx = super::recovery_grant_tests::context(&super::recovery_grant_tests::key());
    ctx.keys[0].1 = B64
        .decode(std::env::var("WITNESS_COMPLETION_PUBLIC").unwrap())
        .unwrap();
    let cut = match point.as_str() {
        "authority" => Cut::AfterAuthority,
        "local-before" => Cut::BeforeLocalCommit,
        "local-after" => Cut::AfterLocalCommit,
        _ => panic!("unknown cut"),
    };
    Adapter {
        authority: &authority,
        local: &local,
    }
    .complete(&req, || ctx, allow, || collect(dir, &req), cut)
    .unwrap();
    panic!("cut not reached");
}

#[test]
fn process_crashes_recover_completion_and_publication_atomically() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use ring::signature::KeyPair;
    for (point, code) in [
        ("authority", 103),
        ("local-before", 91),
        ("local-after", 92),
    ] {
        let h = Harness::new();
        activate(&h);
        drop(local(&h));
        let req = request(&h, [70; 32]);
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_witness_completion_tests::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("WITNESS_COMPLETION_FIXTURE", h.dir.path())
            .env("WITNESS_COMPLETION_POINT", point)
            .env(
                "WITNESS_COMPLETION_PUBLIC",
                B64.encode(h.key.public_key().as_ref()),
            )
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(code),
            "{point}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let authority = h.registry();
        let local = Registry::open(&h.dir.path().join("local.db")).unwrap();
        assert_eq!(authority.load_completion().unwrap(), Some(req.clone()));
        let committed = point == "local-after";
        assert_eq!(local.load_completion().unwrap().is_some(), committed);
        assert_eq!(local.load().unwrap().token.is_some(), committed);
        assert_eq!(local.load().unwrap().input.is_some(), committed);
        let adapter = Adapter {
            authority: &authority,
            local: &local,
        };
        assert_eq!(
            adapter
                .complete(
                    &req,
                    || panic!("historical crash retry context"),
                    allow,
                    || panic!("historical crash retry collector"),
                    Cut::None
                )
                .unwrap(),
            req
        );
        assert_eq!(local.load().unwrap(), authority.load().unwrap());
        assert_eq!(local.load_completion().unwrap(), Some(req));
    }
}
