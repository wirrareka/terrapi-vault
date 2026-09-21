use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};
use terrapi_vesta_replication::*;

struct Process {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl Process {
    fn start(path: &Path, role: &str, crash_apply: bool) -> Self {
        Self::start_mode(path, role, crash_apply, None)
    }
    fn start_mode(
        path: &Path,
        role: &str,
        crash_apply: bool,
        snapshot_crash: Option<&str>,
    ) -> Self {
        Self::start_modes(path, role, crash_apply, snapshot_crash, None)
    }
    fn start_modes(
        path: &Path,
        role: &str,
        crash_apply: bool,
        snapshot_crash: Option<&str>,
        materialized_crash: Option<&str>,
    ) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vesta-node"));
        cmd.arg(path)
            .arg(role)
            .env("VESTA_PROTOTYPE_PASSPHRASE", "process test passphrase")
            .env_remove("VESTA_PROTOTYPE_CRASH_APPLY")
            .env_remove("VESTA_PROTOTYPE_CRASH_SNAPSHOT")
            .env_remove("VESTA_PROTOTYPE_CRASH_MATERIALIZED")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if crash_apply {
            cmd.env("VESTA_PROTOTYPE_CRASH_APPLY", "1");
        }
        if let Some(mode) = snapshot_crash {
            cmd.env("VESTA_PROTOTYPE_CRASH_SNAPSHOT", mode);
        }
        if let Some(mode) = materialized_crash {
            cmd.env("VESTA_PROTOTYPE_CRASH_MATERIALIZED", mode);
        }
        let mut child = cmd.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }
    fn send(&mut self, request: Value) -> Option<Value> {
        writeln!(self.input, "{request}").unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        if self.output.read_line(&mut line).unwrap() == 0 {
            return None;
        }
        Some(serde_json::from_str(&line).unwrap())
    }
    fn call(&mut self, request: Value) -> Value {
        let response = self.send(request).expect("node unexpectedly exited");
        assert!(response.get("error").is_none(), "{response}");
        response["ok"].clone()
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn crash_rolls_back_readiness_together_with_data_and_journal() {
    let dir = tempfile::tempdir().unwrap();
    let pp = dir.path().join("p.vesta");
    let sp = dir.path().join("s.vesta");
    let mut p = Node::open(
        &pp,
        Role::Primary,
        batch().identity,
        "process test passphrase",
    )
    .unwrap();
    let mut s = Node::open(
        &sp,
        Role::Secondary,
        batch().identity,
        "process test passphrase",
    )
    .unwrap();
    recover(&mut p, &mut s).unwrap();
    s.stage(p.prepare(batch()).unwrap()).unwrap();
    let decision = p.decide("request-1").unwrap();
    let before_crash = s.journal_head().unwrap();
    drop(s);
    let mut child = Process::start(&sp, "secondary", true);
    assert!(child
        .send(json!({"command":"apply","entry":decision}))
        .is_none());
    assert_eq!(child.child.wait().unwrap().code(), Some(86));
    drop(child);
    let mut s = Node::open(
        &sp,
        Role::Secondary,
        batch().identity,
        "process test passphrase",
    )
    .unwrap();
    assert_eq!(s.verified_view().unwrap(), Some(View::default()));
    assert_eq!(s.journal_head().unwrap(), before_crash);
    assert!(s.receipt("request-1").unwrap().is_none());
    assert_eq!(recover(&mut p, &mut s).unwrap(), 1);
    assert_eq!(
        s.receipt("request-1").unwrap(),
        p.receipt("request-1").unwrap()
    );
    assert_eq!(s.verified_view().unwrap().unwrap().places.len(), 1);
}

#[test]
fn snapshot_finish_crashes_before_and_after_commit_recover_idempotently() {
    for (mode, code, committed) in [("before_commit", 87, false), ("after_commit", 88, true)] {
        let dir = tempfile::tempdir().unwrap();
        let mut p = Node::open(
            dir.path().join("p"),
            Role::Primary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        p.prepare(batch()).unwrap();
        let e = p.decide("request-1").unwrap();
        p.apply(e).unwrap();
        let path = dir.path().join("s");
        let mut s = Node::open(
            &path,
            Role::Secondary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        let m = p.snapshot_manifest().unwrap();
        let t = s.snapshot_begin(m.clone()).unwrap();
        s.snapshot_chunk(t.token, p.journal_page(&m.head, 0, 1).unwrap())
            .unwrap();
        let before = s.journal_head().unwrap();
        drop(s);
        let mut child = Process::start_mode(&path, "secondary", false, Some(mode));
        assert!(child
            .send(json!({"command":"snapshot_finish","token":t.token}))
            .is_none());
        assert_eq!(child.child.wait().unwrap().code(), Some(code));
        drop(child);
        let mut s = Node::open(
            &path,
            Role::Secondary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        assert_eq!(s.view().unwrap().places.len(), usize::from(committed));
        assert_eq!(s.receipt("request-1").unwrap().is_some(), committed);
        assert_eq!(s.snapshot_progress().unwrap().unwrap().complete, committed);
        if !committed {
            assert_eq!(s.journal_head().unwrap(), before);
        }
        assert!(s.verified_view().unwrap().is_none());
        s.snapshot_finish(t.token).unwrap();
        assert_eq!(
            s.receipt("request-1").unwrap(),
            p.receipt("request-1").unwrap()
        );
        s.confirm_checkpoint(p.checkpoint().unwrap()).unwrap();
        assert_eq!(s.verified_view().unwrap(), Some(p.view().unwrap()));
    }
}
fn batch() -> Batch {
    Batch {
        identity: Identity {
            cluster: "eu-pair".into(),
            tenant: "tenant-a".into(),
            epoch: 1,
            schema: 1,
        },
        operation_id: "request-1".into(),
        changes: vec![Change::PutPlace {
            id: "p1".into(),
            name: "Airport".into(),
        }],
    }
}

#[test]
fn materialized_finish_and_tail_apply_crashes_preserve_base_receipts_and_readiness() {
    for (mode, code, committed) in [("before_commit", 89, false), ("after_commit", 90, true)] {
        let dir = tempfile::tempdir().unwrap();
        let mut p = Node::open(
            dir.path().join("p"),
            Role::Primary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        p.prepare(batch()).unwrap();
        let e = p.decide("request-1").unwrap();
        p.apply(e).unwrap();
        let path = dir.path().join("s");
        let mut s = Node::open(
            &path,
            Role::Secondary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        let m = p.materialized_manifest().unwrap();
        let t = s.materialized_begin(m.clone()).unwrap();
        s.materialized_chunk(t.token, p.materialized_page(&m, 0).unwrap())
            .unwrap();
        drop(s);
        let mut child = Process::start_modes(&path, "secondary", false, None, Some(mode));
        assert!(child
            .send(json!({"command":"materialized_finish","token":t.token}))
            .is_none());
        assert_eq!(child.child.wait().unwrap().code(), Some(code));
        drop(child);
        let mut s = Node::open(
            &path,
            Role::Secondary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        assert_eq!(s.journal_head().unwrap().base.is_some(), committed);
        assert_eq!(s.receipt("request-1").unwrap().is_some(), committed);
        assert_eq!(
            s.materialized_progress().unwrap().unwrap().complete,
            committed
        );
        assert!(s.status().unwrap().entries.is_empty());
        assert!(s.verified_view().unwrap().is_none());
        s.materialized_finish(t.token).unwrap();
        recover(&mut p, &mut s).unwrap();
        let before = s.checkpoint().unwrap();
        let mut next = batch();
        next.operation_id = "next".into();
        next.changes = vec![Change::DeletePlace { id: "p1".into() }];
        s.stage(p.prepare(next).unwrap()).unwrap();
        let decision = p.decide("next").unwrap();
        drop(s);
        let mut child = Process::start(&path, "secondary", true);
        assert!(child
            .send(json!({"command":"apply","entry":decision}))
            .is_none());
        assert_eq!(child.child.wait().unwrap().code(), Some(86));
        drop(child);
        let mut s = Node::open(
            &path,
            Role::Secondary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        assert!(s.receipt("next").unwrap().is_none());
        assert_eq!(s.checkpoint_at(1).unwrap(), before);
        assert_eq!(s.verified_view().unwrap().unwrap().places.len(), 1);
        recover(&mut p, &mut s).unwrap();
        assert!(s.verified_view().unwrap().unwrap().places.is_empty());
        assert_eq!(s.checkpoint().unwrap(), p.checkpoint().unwrap());
    }
}

#[test]
fn kill_at_every_protocol_boundary_then_recover_without_losing_acknowledged_data() {
    // Boundary 0: primary prepare; 1: both prepare; 2: decision;
    // 3: secondary applied; 4: both applied (lost HTTP reply).
    for boundary in 0..=4 {
        let dir = tempfile::tempdir().unwrap();
        let pp = dir.path().join("p.vesta");
        let sp = dir.path().join("s.vesta");
        let mut p = Process::start(&pp, "primary", false);
        let mut s = Process::start(&sp, "secondary", false);
        // Complete initial database creation before injecting protocol crashes.
        s.call(json!({"command":"status"}));
        let prepared = p.call(json!({"command":"prepare","batch":batch()}));
        if boundary >= 1 {
            s.call(json!({"command":"stage","entry":prepared}));
        }
        if boundary >= 2 {
            let decision = p.call(json!({"command":"decide","operation_id":"request-1"}));
            if boundary >= 3 {
                s.call(json!({"command":"apply","entry":decision}));
            }
            if boundary >= 4 {
                p.call(json!({"command":"apply","entry":decision}));
            }
        }
        // SIGKILL: no graceful Vesta close/checkpoint on either process.
        drop(p);
        drop(s);
        let mut p = Node::open(
            &pp,
            Role::Primary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        let mut s = Node::open(
            &sp,
            Role::Secondary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        recover(&mut p, &mut s).unwrap();
        assert_eq!(p.view().unwrap(), s.view().unwrap());
        assert_eq!(p.view().unwrap().places.len(), usize::from(boundary >= 2));
        commit(&mut p, &mut s, batch()).unwrap();
        commit(&mut p, &mut s, batch()).unwrap();
        assert_eq!(p.status().unwrap().entries.len(), 1);
        assert_eq!(p.view().unwrap(), s.view().unwrap());
    }
}

#[test]
fn abrupt_exit_inside_apply_transaction_rolls_back_and_replays() {
    for crashing_role in ["primary", "secondary"] {
        let dir = tempfile::tempdir().unwrap();
        let pp = dir.path().join("p.vesta");
        let sp = dir.path().join("s.vesta");
        let mut p = Process::start(&pp, "primary", crashing_role == "primary");
        let mut s = Process::start(&sp, "secondary", crashing_role == "secondary");
        let prepared = p.call(json!({"command":"prepare","batch":batch()}));
        s.call(json!({"command":"stage","entry":prepared}));
        let decision = p.call(json!({"command":"decide","operation_id":"request-1"}));
        if crashing_role == "secondary" {
            assert!(s
                .send(json!({"command":"apply","entry":decision}))
                .is_none());
            assert_eq!(s.child.wait().unwrap().code(), Some(86));
        } else {
            s.call(json!({"command":"apply","entry":decision}));
            assert!(p
                .send(json!({"command":"apply","entry":decision}))
                .is_none());
            assert_eq!(p.child.wait().unwrap().code(), Some(86));
        }
        drop(p);
        drop(s);
        let mut p = Node::open(
            &pp,
            Role::Primary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        let mut s = Node::open(
            &sp,
            Role::Secondary,
            batch().identity,
            "process test passphrase",
        )
        .unwrap();
        let crashed = if crashing_role == "primary" { &p } else { &s };
        assert_eq!(crashed.view().unwrap(), View::default());
        assert!(crashed.receipt("request-1").unwrap().is_none());
        assert_eq!(recover(&mut p, &mut s).unwrap(), 1);
        assert_eq!(p.view().unwrap(), s.view().unwrap());
        assert_eq!(p.view().unwrap().places.len(), 1);
    }
}
