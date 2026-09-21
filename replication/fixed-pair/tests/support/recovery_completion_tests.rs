use super::{
    authorized_recovery_tests::{peer, seed, Harness},
    fixture,
    model::Id,
    peers::Local,
    recovery_completion::*,
    recovery_registry::{Crash, Registry},
    store::Crash as MemberCrash,
};

pub(super) fn activate(h: &Harness) {
    let registry = h.registry();
    for primary in [true, false] {
        let store = h.store(primary);
        let current = store.load(&seed(primary)).unwrap();
        store
            .activate_authorized(
                &current,
                [10; 32],
                peer(primary, [11; 32]).report([10; 32]),
                &h.token,
                &registry,
                || h.ctx(),
                MemberCrash::None,
            )
            .unwrap();
    }
}
fn evidence(h: &Harness, id: Id) -> [Evidence; 2] {
    let plan = fixture().1;
    [plan.candidate, plan.baseline.survivor].map(|member| {
        Evidence::capture(
            &h.store(member == plan.candidate),
            &plan,
            member,
            id,
            Some(plan.baseline.checkpoint),
        )
        .unwrap()
    })
}
pub(super) fn request(h: &Harness, id: Id) -> Completion {
    Completion {
        request_id: id,
        plan: fixture().1,
        grant_id: [8; 32],
        token_digest: token_digest(&h.token),
        evidence: evidence(h, id),
    }
}

#[test]
fn completion_is_immutable_history_without_member_or_registry_revision_changes() {
    let h = Harness::new();
    activate(&h);
    let r = h.registry();
    let req = request(&h, [70; 32]);
    let before = r.load().unwrap();
    let members = [
        h.store(true).load(&seed(true)).unwrap(),
        h.store(false).load(&seed(false)).unwrap(),
    ];
    assert_eq!(
        r.complete(
            &req,
            || h.ctx(),
            || Ok(evidence(&h, req.request_id)),
            Crash::None
        )
        .unwrap(),
        req
    );
    drop(r);
    let r = h.registry();
    assert_eq!(r.load_completion().unwrap(), Some(req.clone()));
    // Identical retry is a historical lookup, not a newly authorized transition.
    assert_eq!(
        r.complete(
            &req,
            || panic!("history needs no fresh authority"),
            || panic!("history must not recollect members"),
            Crash::None
        )
        .unwrap(),
        req
    );
    assert_eq!(r.load().unwrap(), before);
    assert_eq!(
        [
            h.store(true).load(&seed(true)).unwrap(),
            h.store(false).load(&seed(false)).unwrap()
        ],
        members
    );
}

#[test]
fn prepared_unattested_or_quarantined_member_cannot_supply_new_completion() {
    let h = Harness::new();
    let plan = fixture().1;
    let id = [70; 32];
    assert!(Evidence::capture(
        &h.store(true),
        &plan,
        plan.candidate,
        id,
        Some(plan.baseline.checkpoint)
    )
    .is_err());
    activate(&h);
    assert!(Evidence::capture(&h.store(true), &plan, plan.candidate, id, None).is_err());
    assert!(Evidence::capture(&h.store(true), &plan, plan.candidate, id, Some([99; 32])).is_err());
    let req = request(&h, id);
    let store = h.store(false);
    let current = store.load(&seed(false)).unwrap();
    let mut local = Local::restart(current.saved.clone(), [12; 32]).unwrap();
    local.quarantine();
    store
        .update(&current, local.saved(), MemberCrash::None)
        .unwrap();
    let r = h.registry();
    assert!(r
        .complete(
            &req,
            || h.ctx(),
            || {
                Ok([
                    req.evidence[0].clone(),
                    Evidence::capture(
                        &store,
                        &plan,
                        plan.baseline.survivor,
                        id,
                        Some(plan.baseline.checkpoint),
                    )?,
                ])
            },
            Crash::None
        )
        .is_err());
    assert!(r.load_completion().unwrap().is_none());
}

#[test]
fn wrong_roles_scope_grant_checkpoint_revision_and_request_are_rejected() {
    let h = Harness::new();
    activate(&h);
    let r = h.registry();
    let original = request(&h, [70; 32]);
    for mode in 0..10 {
        let mut req = original.clone();
        match mode {
            0 => req.evidence[1] = req.evidence[0].clone(),
            1 => req.evidence.swap(0, 1),
            2 => req.plan.baseline.scope = "other".into(),
            3 => req.grant_id = [9; 32],
            4 => req.token_digest = [9; 32],
            5 => req.evidence[0].checkpoint = [9; 32].map(|v| v + 1),
            6 => req.evidence[0].activation_revision = 9,
            7 => req.request_id = [71; 32],
            8 => req.evidence[0].token_digest = [9; 32],
            _ => req.evidence[0].request_id = [71; 32],
        }
        assert!(
            r.complete(
                &req,
                || h.ctx(),
                || Ok(original.evidence.clone()),
                Crash::None
            )
            .is_err(),
            "{mode}"
        );
        assert!(r.load_completion().unwrap().is_none());
        assert_eq!(r.load().unwrap().allocated_revision, 5);
    }
}

#[test]
fn expired_new_completion_is_blocked_but_stored_history_survives_quarantine() {
    let h = Harness::new();
    activate(&h);
    let r = h.registry();
    let req = request(&h, [70; 32]);
    let mut expired = h.ctx();
    expired.now = 200;
    assert!(r
        .complete(&req, || expired, || Ok(req.evidence.clone()), Crash::None)
        .is_err());
    assert!(r.load_completion().unwrap().is_none());
    r.complete(&req, || h.ctx(), || Ok(req.evidence.clone()), Crash::None)
        .unwrap();
    let store = h.store(true);
    let current = store.load(&seed(true)).unwrap();
    let mut local = Local::restart(current.saved.clone(), [12; 32]).unwrap();
    local.quarantine();
    store
        .update(&current, local.saved(), MemberCrash::None)
        .unwrap();
    assert_eq!(r.load_completion().unwrap(), Some(req));
    assert!(
        !Local::restart(store.load(&seed(true)).unwrap().saved, [13; 32])
            .unwrap()
            .is_active()
    );
}

#[test]
fn two_concurrent_completion_requests_leave_one_winner_and_no_new_revision() {
    use std::sync::{Arc, Barrier};
    let h = Harness::new();
    activate(&h);
    let gate = Arc::new(Barrier::new(2));
    let requests = [request(&h, [70; 32]), request(&h, [71; 32])];
    let handles: Vec<_> = requests
        .iter()
        .map(|req| {
            let path = h.dir.path().join("operator.db");
            let gate = gate.clone();
            let req = req.clone();
            let ctx = h.ctx();
            std::thread::spawn(move || {
                let r = Registry::open(&path).unwrap();
                gate.wait();
                r.complete(&req, || ctx, || Ok(req.evidence.clone()), Crash::None)
                    .is_ok()
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|v| **v).count(), 1);
    let winner = results.iter().position(|v| *v).unwrap();
    let r = h.registry();
    assert_eq!(r.load_completion().unwrap(), Some(requests[winner].clone()));
    assert_eq!(r.load().unwrap().allocated_revision, 5);
}

#[test]
fn diagnostics_distinguish_recorded_history_from_current_quarantine_and_expiry() {
    use super::recovery_diagnostics::{diagnose, Authorization, Pair};
    let h = Harness::new();
    activate(&h);
    let r = h.registry();
    let req = request(&h, [70; 32]);
    r.complete(
        &req,
        || h.ctx(),
        || Ok(evidence(&h, req.request_id)),
        Crash::None,
    )
    .unwrap();
    let p = h.store(true);
    let s = h.store(false);
    let current = p.load(&seed(true)).unwrap();
    let mut local = Local::restart(current.saved.clone(), [12; 32]).unwrap();
    local.quarantine();
    p.update(&current, local.saved(), MemberCrash::None)
        .unwrap();
    let mut ctx = h.ctx();
    ctx.now = 200;
    r.connection(|c| {
        c.pragma_update(None, "query_only", true)?;
        Ok(())
    })
    .unwrap();
    let report = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &ctx);
    assert_eq!(
        serde_json::to_value(&report).unwrap()["completion"],
        "Recorded"
    );
    assert_eq!(report.pair, Pair::Quarantined);
    assert_eq!(report.authorization, Authorization::Rejected);
    assert!(!serde_json::to_string(&report).unwrap().contains(&h.token));
    let missing = diagnose([Some(&p), Some(&s)], None, &fixture().1, &ctx);
    assert_eq!(
        serde_json::to_value(missing).unwrap()["completion"],
        "Unavailable"
    );
    r.connection(|c| {
        c.pragma_update(None, "query_only", false)?;
        c.execute_batch("UPDATE completion SET format=9")?;
        Ok(())
    })
    .unwrap();
    let corrupt = diagnose([Some(&p), Some(&s)], Some(&r), &fixture().1, &ctx);
    assert_eq!(
        serde_json::to_value(corrupt).unwrap()["completion"],
        "Invalid"
    );
}

#[test]
fn failed_commit_and_corrupt_history_never_overwrite_completion() {
    let h = Harness::new();
    activate(&h);
    let r = h.registry();
    let req = request(&h, [70; 32]);
    r.connection(|c|{c.execute_batch("CREATE TRIGGER fail_completion BEFORE INSERT ON completion BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())}).unwrap();
    assert!(r
        .complete(&req, || h.ctx(), || Ok(req.evidence.clone()), Crash::None)
        .is_err());
    assert!(r.load_completion().unwrap().is_none());
    r.connection(|c| {
        c.execute_batch("DROP TRIGGER fail_completion")?;
        Ok(())
    })
    .unwrap();
    r.complete(&req, || h.ctx(), || Ok(req.evidence.clone()), Crash::None)
        .unwrap();
    let original: (String, Vec<u8>) = r
        .connection(|c| {
            Ok(c.query_row(
                "SELECT record,digest FROM completion WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?)
        })
        .unwrap();
    for sql in [
        "UPDATE completion SET format=9",
        "UPDATE completion SET record='{}'",
        "UPDATE completion SET digest=zeroblob(32)",
    ] {
        r.connection(|c| {
            c.execute_batch(sql)?;
            Ok(())
        })
        .unwrap();
        assert!(r.load_completion().is_err());
        assert!(r
            .complete(&req, || h.ctx(), || Ok(req.evidence.clone()), Crash::None)
            .is_err());
        r.connection(|c| {
            c.execute(
                "UPDATE completion SET format=1,record=?1,digest=?2",
                rusqlite::params![original.0, original.1],
            )?;
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(r.load_completion().unwrap(), Some(req));
}

#[test]
#[ignore = "subprocess entry point for completion crash matrix"]
fn crash_child() {
    use base64::Engine;
    let dir = std::env::var_os("COMPLETION_FIXTURE_DIR").unwrap();
    let dir = std::path::Path::new(&dir);
    let crash = match std::env::var("COMPLETION_FIXTURE_POINT").unwrap().as_str() {
        "before" => Crash::BeforeCommit,
        "after" => Crash::AfterCommit,
        _ => panic!("bad crash point"),
    };
    let r = Registry::open(&dir.join("operator.db")).unwrap();
    let token = r.load().unwrap().token.unwrap();
    let plan = fixture().1;
    let id = [70; 32];
    let collect = || -> super::recovery_registry::Result<[Evidence; 2]> {
        let p = super::store::Store::open(&Harness::path(dir, true))?;
        let s = super::store::Store::open(&Harness::path(dir, false))?;
        Ok([
            Evidence::capture(
                &p,
                &plan,
                plan.candidate,
                id,
                Some(plan.baseline.checkpoint),
            )?,
            Evidence::capture(
                &s,
                &plan,
                plan.baseline.survivor,
                id,
                Some(plan.baseline.checkpoint),
            )?,
        ])
    };
    let req = Completion {
        request_id: id,
        plan: plan.clone(),
        grant_id: [8; 32],
        token_digest: token_digest(&token),
        evidence: collect().unwrap(),
    };
    let mut ctx = super::recovery_grant_tests::context(&super::recovery_grant_tests::key());
    ctx.keys[0].1 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(std::env::var("COMPLETION_FIXTURE_PUBLIC_KEY").unwrap())
        .unwrap();
    r.complete(&req, || ctx, collect, crash).unwrap();
    panic!("crash not reached");
}

#[test]
fn crashes_before_and_after_commit_retry_one_historical_record() {
    use base64::Engine;
    use ring::signature::KeyPair;
    for (point, code) in [("before", 91), ("after", 92)] {
        let h = Harness::new();
        activate(&h);
        let req = request(&h, [70; 32]);
        let before = h.registry().load().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_completion_tests::crash_child",
                "--ignored",
            ])
            .env("COMPLETION_FIXTURE_DIR", h.dir.path())
            .env("COMPLETION_FIXTURE_POINT", point)
            .env(
                "COMPLETION_FIXTURE_PUBLIC_KEY",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(h.key.public_key().as_ref()),
            )
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let r = h.registry();
        assert_eq!(r.load_completion().unwrap().is_some(), point == "after");
        assert_eq!(
            r.complete(
                &req,
                || h.ctx(),
                || Ok(evidence(&h, req.request_id)),
                Crash::None
            )
            .unwrap(),
            req
        );
        assert_eq!(r.load_completion().unwrap(), Some(req));
        assert_eq!(r.load().unwrap(), before);
        for primary in [true, false] {
            assert_eq!(h.store(primary).load(&seed(primary)).unwrap().revision, 1);
        }
    }
}
