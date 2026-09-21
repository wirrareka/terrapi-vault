use super::{
    authorized_recovery_tests::{peer, seed, Harness},
    fixture,
    recovery_completion::{token_digest, Completion, Evidence},
    recovery_grant_tests::{claims, context, header, key},
    recovery_registry::{Registry, Result},
    recovery_witness_activation::Activation,
    recovery_witness_registry::{Adapter, Cut},
    store::{Crash, Store},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::rand::SystemRandom;
use std::{cell::Cell, path::Path, time::Duration};

fn allow() -> Result<()> {
    Ok(())
}

// Expected terminal evidence, not an attestation. Complete still collects and
// checks the actual member snapshots; this request alone proves nothing.
fn completion(token: &str) -> Completion {
    let plan = fixture().1;
    let digest = token_digest(token);
    Completion {
        request_id: [70; 32],
        grant_id: [8; 32],
        token_digest: digest,
        evidence: [plan.candidate, plan.baseline.survivor].map(|member| Evidence {
            member,
            request_id: [70; 32],
            checkpoint: plan.baseline.checkpoint,
            token_digest: digest,
            activation_revision: 1,
        }),
        plan,
    }
}
fn evidence(members: &[Store; 2], req: &Completion) -> Result<[Evidence; 2]> {
    let [a, b] = [0, 1].map(|n| {
        Evidence::capture(
            &members[n],
            &req.plan,
            if n == 0 {
                req.plan.candidate
            } else {
                req.plan.baseline.survivor
            },
            req.request_id,
            Some(req.plan.baseline.checkpoint),
        )
    });
    Ok([a?, b?])
}

// Handles precede Harness so they close before its TempDir is removed.
struct Flow {
    authority: Registry,
    projection: Registry,
    members: [Store; 2],
    h: Harness,
}
impl Flow {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = key();
        let ctx = context(&key);
        let create = |name| {
            Registry::create(
                &dir.path().join(name),
                fixture().1.baseline,
                "fixture-install",
                "eu",
            )
            .unwrap()
        };
        let authority = create("operator.db");
        let projection = create("projection.db");
        let members = [true, false].map(|primary| {
            Store::create(&Harness::path(dir.path(), primary), seed(primary)).unwrap()
        });
        let adapter = Adapter {
            authority: &authority,
            local: &projection,
        };
        let input = format!(
            "{}.{}",
            B64.encode(header().to_string()),
            B64.encode(claims().to_string())
        );
        adapter.reserve(&input, &ctx, allow, Cut::None).unwrap();
        let token = adapter
            .issue(
                &ctx,
                allow,
                |bytes| {
                    let sig = key
                        .sign(&SystemRandom::new(), bytes.as_bytes())
                        .map_err(|_| "fixture sign")?;
                    Ok(format!("{bytes}.{}", B64.encode(sig.as_ref())))
                },
                Cut::None,
            )
            .unwrap();
        Self {
            authority,
            projection,
            members,
            h: Harness { dir, key, token },
        }
    }
    fn adapter(&self) -> Adapter<'_> {
        Adapter {
            authority: &self.authority,
            local: &self.projection,
        }
    }
    fn activate(&self, primary: bool) -> Result<()> {
        let member = &self.members[usize::from(!primary)];
        let current = member.load(&seed(primary))?;
        self.adapter().activate(
            member,
            Activation {
                expected: &current,
                boot: [10; 32],
                report: peer(primary, [11; 32]).report([10; 32]),
                token: &self.h.token,
            },
            || self.h.ctx(),
            allow,
            Crash::None,
        )
    }
}

#[test]
fn both_members_activate_only_through_matching_witness_and_projection() {
    let flow = Flow::new();
    let publication = flow.authority.load().unwrap();
    // The legacy read/verify helper remains compatible; it is not the new
    // witness activation boundary and does not mutate a member here.
    flow.authority
        .with_grant(
            &flow.h.token,
            || flow.h.ctx(),
            |grant| {
                assert_eq!(grant.plan, fixture().1);
                Ok(())
            },
        )
        .unwrap();
    for primary in [true, false] {
        flow.activate(primary).unwrap();
        let store = &flow.members[usize::from(!primary)];
        let activated = store.load(&seed(primary)).unwrap();
        assert_eq!(activated.revision, 1);
        assert_eq!(
            store.activation_token(&activated).unwrap(),
            Some(flow.h.token.clone())
        );
        flow.activate(primary).unwrap();
        assert_eq!(store.load(&seed(primary)).unwrap(), activated);
        assert_eq!(store.admissions().unwrap(), 0);
    }
    assert_eq!(flow.authority.load().unwrap(), publication);
    assert_eq!(flow.projection.load().unwrap(), publication);
    let req = completion(&flow.h.token);
    flow.adapter()
        .complete(
            &req,
            || flow.h.ctx(),
            allow,
            || evidence(&flow.members, &req),
            super::recovery_witness_completion::Cut::None,
        )
        .unwrap();
    for primary in [true, false] {
        let member = &flow.members[usize::from(!primary)];
        let before = member.load(&seed(primary)).unwrap();
        assert!(flow.activate(primary).is_err());
        assert_eq!(member.load(&seed(primary)).unwrap(), before);
    }
    assert_eq!(flow.authority.load_completion().unwrap(), Some(req.clone()));
    assert_eq!(flow.projection.load_completion().unwrap(), Some(req));
}

#[test]
fn missing_projection_rolled_back_authority_and_invalid_completion_deny_activation() {
    let flow = Flow::new();
    let member = &flow.members[0];
    let before = member.load(&seed(true)).unwrap();
    let empty = Registry::create(
        &flow.h.dir.path().join("empty.db"),
        fixture().1.baseline,
        "fixture-install",
        "eu",
    )
    .unwrap();
    assert!(Adapter {
        authority: &flow.authority,
        local: &empty
    }
    .activate(
        member,
        Activation {
            expected: &before,
            boot: [10; 32],
            report: peer(true, [11; 32]).report([10; 32]),
            token: &flow.h.token
        },
        || flow.h.ctx(),
        allow,
        Crash::None
    )
    .is_err());
    assert!(empty.load().unwrap().input.is_none());
    flow.authority
        .connection(|c| {
            c.execute("UPDATE registry SET token=NULL", [])?;
            Ok(())
        })
        .unwrap();
    assert!(flow.activate(true).is_err());
    flow.authority
        .connection(|c| {
            c.execute("UPDATE registry SET token=?1", [&flow.h.token])?;
            Ok(())
        })
        .unwrap();
    for db in [&flow.authority, &flow.projection] {
        db.connection(|c| {
            c.execute("INSERT INTO completion VALUES(1,0,'{}',zeroblob(32))", [])?;
            Ok(())
        })
        .unwrap();
        assert!(flow.activate(true).is_err());
        db.connection(|c| {
            c.execute("DELETE FROM completion", [])?;
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(member.load(&seed(true)).unwrap(), before);
    assert!(member.activation_token(&before).unwrap().is_none());
}

#[test]
fn denied_context_late_denial_stale_session_and_quarantine_do_not_activate() {
    let flow = Flow::new();
    let member = &flow.members[0];
    let before = member.load(&seed(true)).unwrap();
    let request = || Activation {
        expected: &before,
        boot: [10; 32],
        report: peer(true, [11; 32]).report([10; 32]),
        token: &flow.h.token,
    };
    assert!(flow
        .adapter()
        .activate(
            member,
            request(),
            || panic!("denied context called"),
            || Err("unknown continuity".into()),
            Crash::None
        )
        .is_err());
    for mode in 0..5 {
        let mut ctx = flow.h.ctx();
        match mode {
            0 => ctx.now = 200,
            1 => ctx.keys.clear(),
            2 => ctx.fencing_confirmed = false,
            3 => ctx.region = "other".into(),
            _ => ctx.reservation = None,
        }
        assert!(flow
            .adapter()
            .activate(member, request(), || ctx, allow, Crash::None)
            .is_err());
    }
    let allowed = Cell::new(true);
    assert!(flow
        .adapter()
        .activate(
            member,
            request(),
            || {
                allowed.set(false);
                flow.h.ctx()
            },
            || if allowed.get() {
                Ok(())
            } else {
                Err("denied under all locks".into())
            },
            Crash::None
        )
        .is_err());
    let mut stale = request();
    stale.report = peer(true, [11; 32]).report([12; 32]);
    assert!(flow
        .adapter()
        .activate(
            member,
            stale,
            || panic!("stale session context"),
            allow,
            Crash::None
        )
        .is_err());
    assert_eq!(member.load(&seed(true)).unwrap(), before);
    assert!(member.activation_token(&before).unwrap().is_none());
    let mut quarantined = super::peers::Local::restart(before.saved.clone(), [20; 32]).unwrap();
    quarantined.quarantine();
    member
        .update(&before, quarantined.saved(), Crash::None)
        .unwrap();
    assert!(flow
        .adapter()
        .activate(member, request(), || flow.h.ctx(), allow, Crash::None)
        .is_err());
    assert!(flow.activate(true).is_err());
    let current = member.load(&seed(true)).unwrap();
    assert!(member.activation_token(&current).unwrap().is_none());
}

#[test]
fn authority_member_and_projection_locks_are_held_when_context_is_sampled() {
    fn blocked(c: &rusqlite::Connection) -> Result<bool> {
        c.busy_timeout(Duration::ZERO)?;
        Ok(
            rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)
                .is_err(),
        )
    }
    let flow = Flow::new();
    let authority_observer = flow.h.registry();
    let projection_observer = Registry::open(&flow.h.dir.path().join("projection.db")).unwrap();
    let member_observer = flow.h.store(true);
    let current = flow.members[0].load(&seed(true)).unwrap();
    flow.adapter()
        .activate(
            &flow.members[0],
            Activation {
                expected: &current,
                boot: [10; 32],
                report: peer(true, [11; 32]).report([10; 32]),
                token: &flow.h.token,
            },
            || {
                assert!(authority_observer.connection(blocked).unwrap());
                assert!(member_observer.connection(blocked).unwrap());
                assert!(projection_observer.connection(blocked).unwrap());
                flow.h.ctx()
            },
            allow,
            Crash::None,
        )
        .unwrap();
    assert!(!authority_observer.connection(blocked).unwrap());
    assert!(!member_observer.connection(blocked).unwrap());
    assert!(!projection_observer.connection(blocked).unwrap());
}

#[test]
fn failed_member_commit_keeps_state_history_and_grant_binding_unchanged() {
    let flow = Flow::new();
    let member = &flow.members[0];
    let before = member.load(&seed(true)).unwrap();
    member.connection(|c| { c.execute_batch("CREATE TRIGGER reject_binding BEFORE INSERT ON recovery_grants BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")?; Ok(()) }).unwrap();
    assert!(flow.activate(true).is_err());
    assert_eq!(member.load(&seed(true)).unwrap(), before);
    assert!(member.activation_token(&before).unwrap().is_none());
    assert_eq!(
        flow.authority.load().unwrap(),
        flow.projection.load().unwrap()
    );
    member
        .connection(|c| {
            c.execute_batch("DROP TRIGGER reject_binding")?;
            Ok(())
        })
        .unwrap();
    flow.activate(true).unwrap();
    assert_eq!(member.load(&seed(true)).unwrap().revision, 1);
}

#[test]
fn completion_serializes_after_last_member_activation_without_lock_inversion() {
    use std::sync::mpsc::{channel, Receiver};
    fn recv<T>(rx: &Receiver<T>) -> T {
        rx.recv_timeout(Duration::from_secs(120)).unwrap()
    }
    let flow = Flow::new();
    flow.activate(true).unwrap();
    let req = completion(&flow.h.token);
    assert!(flow
        .adapter()
        .complete(
            &req,
            || flow.h.ctx(),
            allow,
            || evidence(&flow.members, &req),
            super::recovery_witness_completion::Cut::None
        )
        .is_err());
    let (ready_tx, ready_rx) = channel();
    let (start_a_tx, start_a_rx) = channel();
    let (locked_tx, locked_rx) = channel();
    let (release_tx, release_rx) = channel();
    let (start_c_tx, start_c_rx) = channel();
    let (attempt_tx, attempt_rx) = channel();
    std::thread::scope(|scope| {
        let h = &flow.h;
        let ready_a = ready_tx.clone();
        let a = scope.spawn(move || {
            let authority = h.registry();
            let projection = Registry::open(&h.dir.path().join("projection.db")).unwrap();
            let member = h.store(false);
            let current = member.load(&seed(false)).unwrap();
            ready_a.send(()).unwrap();
            recv(&start_a_rx);
            Adapter {
                authority: &authority,
                local: &projection,
            }
            .activate(
                &member,
                Activation {
                    expected: &current,
                    boot: [10; 32],
                    report: peer(false, [11; 32]).report([10; 32]),
                    token: &h.token,
                },
                || {
                    locked_tx.send(()).unwrap();
                    recv(&release_rx);
                    h.ctx()
                },
                allow,
                Crash::None,
            )
            .unwrap();
        });
        let req = &req;
        let c = scope.spawn(move || {
            let authority = h.registry();
            let projection = Registry::open(&h.dir.path().join("projection.db")).unwrap();
            let members = [h.store(true), h.store(false)];
            ready_tx.send(()).unwrap();
            recv(&start_c_rx);
            let notified = Cell::new(false);
            Adapter {
                authority: &authority,
                local: &projection,
            }
            .complete(
                req,
                || h.ctx(),
                || {
                    if !notified.replace(true) {
                        attempt_tx.send(()).unwrap();
                    }
                    Ok(())
                },
                || evidence(&members, req),
                super::recovery_witness_completion::Cut::None,
            )
            .unwrap();
        });
        recv(&ready_rx);
        recv(&ready_rx);
        start_a_tx.send(()).unwrap();
        recv(&locked_rx);
        start_c_tx.send(()).unwrap();
        recv(&attempt_rx);
        release_tx.send(()).unwrap();
        a.join().unwrap();
        c.join().unwrap();
    });
    assert_eq!(flow.authority.load_completion().unwrap(), Some(req.clone()));
    assert_eq!(flow.projection.load_completion().unwrap(), Some(req));
    assert!(flow.activate(false).is_err());
}

#[test]
#[ignore = "subprocess entry point for witness activation crash matrix"]
fn crash_child() {
    let dir = std::env::var_os("WITNESS_ACTIVATION_FIXTURE").unwrap();
    let dir = Path::new(&dir);
    let primary = std::env::var("WITNESS_ACTIVATION_ROLE").unwrap() == "primary";
    let authority = Registry::open(&dir.join("operator.db")).unwrap();
    let projection = Registry::open(&dir.join("projection.db")).unwrap();
    let member = Store::open(&Harness::path(dir, primary)).unwrap();
    let token = authority.load().unwrap().token.unwrap();
    let mut ctx = context(&key());
    ctx.keys[0].1 = B64
        .decode(std::env::var("WITNESS_ACTIVATION_PUBLIC").unwrap())
        .unwrap();
    let current = member.load(&seed(primary)).unwrap();
    let crash = match std::env::var("WITNESS_ACTIVATION_POINT").unwrap().as_str() {
        "before" => Crash::BeforeCommit,
        "after" => Crash::AfterCommit,
        _ => panic!("unknown cut"),
    };
    Adapter {
        authority: &authority,
        local: &projection,
    }
    .activate(
        &member,
        Activation {
            expected: &current,
            boot: [40; 32],
            report: peer(primary, [41; 32]).report([40; 32]),
            token: &token,
        },
        || ctx,
        allow,
        crash,
    )
    .unwrap();
    panic!("cut not reached");
}

#[test]
fn process_crashes_in_both_activation_orders_recover_then_complete() {
    use ring::signature::KeyPair;
    for primary in [true, false] {
        for (point, code) in [("before", 81), ("after", 82)] {
            let flow = Flow::new();
            flow.activate(!primary).unwrap();
            let Flow {
                authority,
                projection,
                members,
                h,
            } = flow;
            drop((authority, projection, members));
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "recovery_witness_activation_tests::crash_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("WITNESS_ACTIVATION_FIXTURE", h.dir.path())
                .env(
                    "WITNESS_ACTIVATION_ROLE",
                    if primary { "primary" } else { "survivor" },
                )
                .env("WITNESS_ACTIVATION_POINT", point)
                .env(
                    "WITNESS_ACTIVATION_PUBLIC",
                    B64.encode(h.key.public_key().as_ref()),
                )
                .output()
                .unwrap();
            assert_eq!(
                out.status.code(),
                Some(code),
                "{primary}/{point}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let authority = h.registry();
            let projection = Registry::open(&h.dir.path().join("projection.db")).unwrap();
            let members = [h.store(true), h.store(false)];
            let flow = Flow {
                authority,
                projection,
                members,
                h,
            };
            let member = &flow.members[usize::from(!primary)];
            let current = member.load(&seed(primary)).unwrap();
            assert_eq!(current.revision, u64::from(point == "after"));
            assert_eq!(
                member.activation_token(&current).unwrap().is_some(),
                point == "after"
            );
            let request = || Activation {
                expected: &current,
                boot: [70; 32],
                report: peer(primary, [71; 32]).report([70; 32]),
                token: &flow.h.token,
            };
            assert!(flow
                .adapter()
                .activate(
                    member,
                    request(),
                    || {
                        let mut ctx = flow.h.ctx();
                        ctx.now = 200;
                        ctx
                    },
                    allow,
                    Crash::None
                )
                .is_err());
            let mut stale = request();
            stale.report = peer(primary, [41; 32]).report([40; 32]);
            assert!(flow
                .adapter()
                .activate(member, stale, || flow.h.ctx(), allow, Crash::None)
                .is_err());
            assert_eq!(member.load(&seed(primary)).unwrap(), current);
            flow.activate(primary).unwrap();
            for role in [true, false] {
                assert_eq!(
                    flow.members[usize::from(!role)]
                        .load(&seed(role))
                        .unwrap()
                        .revision,
                    1
                );
            }
            let req = completion(&flow.h.token);
            flow.adapter()
                .complete(
                    &req,
                    || flow.h.ctx(),
                    allow,
                    || evidence(&flow.members, &req),
                    super::recovery_witness_completion::Cut::None,
                )
                .unwrap();
            assert_eq!(flow.authority.load_completion().unwrap(), Some(req.clone()));
            assert_eq!(flow.projection.load_completion().unwrap(), Some(req));
        }
    }
}
