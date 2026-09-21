use super::{fixture, peers::*};

fn pair() -> (Local, Local) {
    let (_, p) = fixture();
    (
        Local::prepared(p.clone(), p.candidate, [10; 32]).unwrap(),
        Local::prepared(p.clone(), p.baseline.survivor, [11; 32]).unwrap(),
    )
}
fn active() -> (Local, Local) {
    let (mut p, mut s) = pair();
    p.receive(s.report(p.boot())).unwrap();
    s.receive(p.report(s.boot())).unwrap();
    p.activate().unwrap();
    s.activate().unwrap();
    (p, s)
}

#[test]
fn local_activation_requires_peer_prepared_report() {
    let (mut p, mut s) = pair();
    assert!(p.activate().is_err());
    assert!(s.activate().is_err());
    p.receive(s.report(p.boot())).unwrap();
    p.activate().unwrap();
    let request = p.mutation(s.boot()).unwrap();
    assert!(s.receive(request.clone()).is_err());
    s.receive(p.report(s.boot())).unwrap();
    s.activate().unwrap();
    assert!(s.receive(request).is_ok());
}

#[test]
fn lost_active_ack_is_recovered_by_reporting_durable_phase_again() {
    let (mut p, mut s) = active();
    let disk = s.saved();
    // Drop the first Active report; local saved phase must survive abstract restart.
    let _lost = s.report(p.boot());
    s = Local::restart(disk, [12; 32]).unwrap();
    p.receive(s.report(p.boot())).unwrap();
    assert!(s.receive(p.mutation(s.boot()).unwrap()).is_ok());
}

#[test]
fn receiver_restart_rejects_delayed_reports_and_old_session_mutations() {
    let (p, mut s) = active();
    let report = p.report(s.boot());
    let mutation = p.mutation(s.boot()).unwrap();
    s = Local::restart(s.saved(), [12; 32]).unwrap();
    let before = s.clone();
    assert!(s.receive(report).is_err());
    assert!(s.receive(mutation).is_err());
    assert_eq!(before, s);
    assert!(s.receive(p.mutation(s.boot()).unwrap()).is_ok());
}

#[test]
fn quarantine_survives_restart_and_stale_active_report_is_not_write_authority() {
    let (mut p, mut s) = active();
    let stale = s.report(p.boot());
    let opened_before = p.mutation(s.boot()).unwrap();
    s.quarantine();
    assert!(s.receive(opened_before).is_err());
    s = Local::restart(s.saved(), [12; 32]).unwrap();
    p.receive(stale).unwrap(); // Delayed status is possible; it cannot bypass receiver checks.
    assert!(s.receive(p.mutation(s.boot()).unwrap()).is_err());
    assert!(s.activate().is_err());
    assert!(s.receive(p.report(s.boot())).is_err());
}

#[test]
fn every_envelope_binding_is_checked_without_mutation() {
    let (p, s) = active();
    for field in 0..7 {
        let mut msg = p.mutation(s.boot()).unwrap();
        match field {
            0 => msg.plan.recovery_id = [90; 32],
            1 => msg.plan.baseline.scope = "other-tenant".into(),
            2 => msg.plan.baseline.checkpoint = [90; 32],
            3 => msg.from = msg.plan.baseline.old_primary,
            4 => msg.to = [90; 32],
            5 => msg.receiver_boot = [90; 32],
            _ => msg.plan.revision += 1,
        }
        let mut receiver = s.clone();
        assert!(receiver.receive(msg).is_err());
        assert_eq!(receiver, s);
    }
    assert!(s.mutation(p.boot()).is_err()); // Secondary never originates business writes.
}

#[test]
fn retry_and_message_reordering_do_not_regress_saved_phase() {
    let (mut p, mut s) = pair();
    let old = s.report(p.boot());
    s.receive(p.report(s.boot())).unwrap();
    s.activate().unwrap();
    p.receive(s.report(p.boot())).unwrap();
    p.activate().unwrap();
    let disk = p.saved();
    p.receive(old.clone()).unwrap();
    p.receive(old).unwrap();
    p.activate().unwrap();
    assert_eq!(disk, p.saved());
}

#[test]
fn prepared_restart_loses_volatile_peer_knowledge() {
    let (mut p, s) = pair();
    p.receive(s.report(p.boot())).unwrap();
    p = Local::restart(p.saved(), [12; 32]).unwrap();
    assert!(p.activate().is_err());
    p.receive(s.report(p.boot())).unwrap();
    p.activate().unwrap();
}

#[test]
fn invalid_member_plan_and_boot_are_rejected_at_fixture_boundary() {
    let (_, p) = fixture();
    assert!(Local::prepared(p.clone(), p.baseline.old_primary, [10; 32]).is_err());
    assert!(Local::prepared(p.clone(), p.candidate, [0; 32]).is_err());
    let mut invalid = p.clone();
    invalid.revision += 1;
    assert!(Local::prepared(invalid, p.candidate, [10; 32]).is_err());
    let (a, _) = pair();
    assert!(Local::restart(a.saved(), [0; 32]).is_err());
}

#[test]
fn all_prepare_report_activation_schedules_preserve_receiver_gate() {
    let (p, s) = pair();
    let mut states = vec![(p, s)];
    let mut i = 0;
    while i < states.len() {
        let (p, s) = states[i].clone();
        i += 1;
        // Every reachable state: restart neither, either, or both abstract peers.
        for mask in 0..4 {
            let mut a = if mask & 1 != 0 {
                Local::restart(p.saved(), [20; 32]).unwrap()
            } else {
                p.clone()
            };
            let mut b = if mask & 2 != 0 {
                Local::restart(s.saved(), [21; 32]).unwrap()
            } else {
                s.clone()
            };
            a.receive(b.report(a.boot())).unwrap();
            b.receive(a.report(b.boot())).unwrap();
            a.activate().unwrap();
            b.activate().unwrap();
            assert!(b.receive(a.mutation(b.boot()).unwrap()).is_ok());
        }
        for action in 0..4 {
            let (mut a, mut b) = (p.clone(), s.clone());
            let result = match action {
                0 => a.receive(b.report(a.boot())),
                1 => b.receive(a.report(b.boot())),
                2 => a.activate(),
                _ => b.activate(),
            };
            if result.is_err() {
                assert_eq!((a.clone(), b.clone()), (p.clone(), s.clone()));
            }
            if let Ok(request) = a.mutation(b.boot()) {
                let mut probe = b.clone();
                let accepted = probe.receive(request).is_ok();
                assert_eq!(accepted, b.is_active());
                probe.quarantine();
                assert!(probe.receive(a.mutation(probe.boot()).unwrap()).is_err());
            }
            if !states.contains(&(a.clone(), b.clone())) {
                states.push((a, b));
            }
        }
    }
    assert_eq!(states.len(), 9);
}
