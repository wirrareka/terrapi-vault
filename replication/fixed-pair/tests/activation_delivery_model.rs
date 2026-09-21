//! Abstract candidate protocol only: no runtime, persistence, crypto, or sockets.
//! A committed pair decision is irrevocable; revocation blocks new decisions.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Binding {
    // Opaque identities stand for exact, validated full content, not wire hashes.
    scope: u8,
    plan: u8,
    request: u8,
}

const PLAN: Binding = Binding {
    scope: 1,
    plan: 2,
    request: 3,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct State {
    decision: Option<Binding>,
    active: [Option<Binding>; 2],
    inbox: [Option<Binding>; 2],
    acknowledgements: [bool; 2],
    complete: bool,
    revoked: bool,
    available: bool,
    continuity: bool,
    member_continuity: [bool; 2],
    prepared: [bool; 2],
    quarantined: [bool; 2],
}

impl Default for State {
    fn default() -> Self {
        Self {
            decision: None,
            active: [None; 2],
            inbox: [None; 2],
            acknowledgements: [false; 2],
            complete: false,
            revoked: false,
            available: true,
            continuity: true,
            member_continuity: [true; 2],
            prepared: [true; 2],
            quarantined: [false; 2],
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Decide(Binding),
    Fetch(usize),
    Deliver(usize),
    Acknowledge(usize),
    Complete,
    Revoke,
}

impl State {
    fn step(&mut self, action: Action) -> Result<(), &'static str> {
        // Delivery is a separate local step: it may run after a partition.
        // Other operations represent serialized, authenticated authority calls.
        if !matches!(action, Action::Deliver(_)) && (!self.available || !self.continuity) {
            return Err("authority unavailable or continuity unknown");
        }
        match action {
            Action::Decide(binding) => {
                if binding != PLAN {
                    return Err("binding conflict");
                }
                if self.decision == Some(binding) {
                    return Ok(()); // Historical retry, not another decision.
                }
                if self.revoked
                    || self.prepared != [true; 2]
                    || self.quarantined != [false; 2]
                    || self.member_continuity != [true; 2]
                {
                    return Err("decision prerequisites missing");
                }
                self.decision = Some(binding);
            }
            Action::Fetch(member) => {
                if member >= 2 || self.decision.is_none() || self.complete {
                    return Err("no unfinished decision to deliver");
                }
                self.inbox[member] = self.decision;
            }
            Action::Deliver(member) => {
                if member >= 2
                    || !self.member_continuity[member]
                    || self.quarantined[member]
                    || !self.prepared[member]
                {
                    return Err("member not eligible");
                }
                // An inbox value represents authenticated committed evidence,
                // not a bare token or historical GET response supplied by a user.
                let binding = self.inbox[member].ok_or("no decision message")?;
                if binding != PLAN || self.active[member].is_some_and(|b| b != binding) {
                    return Err("member binding conflict");
                }
                self.active[member] = Some(binding);
            }
            Action::Acknowledge(member) => {
                // Trusted member proof captured only after its local commit.
                if member >= 2
                    || self.decision.is_none()
                    || !self.member_continuity[member]
                    || self.quarantined[member]
                    || self.active[member] != self.decision
                {
                    return Err("no matching member proof");
                }
                self.acknowledgements[member] = true;
            }
            Action::Complete => {
                if self.acknowledgements != [true; 2] {
                    return Err("two committed member proofs required");
                }
                self.complete = true;
            }
            Action::Revoke => self.revoked = true,
        }
        Ok(())
    }
}

#[test]
fn lost_decision_reply_and_duplicate_delivery_preserve_one_result() {
    let mut state = State::default();
    state.step(Action::Decide(PLAN)).unwrap(); // Reply is lost.
    let committed = state.clone();
    state.step(Action::Decide(PLAN)).unwrap();
    assert_eq!(state, committed);
    for member in [1, 0] {
        state.step(Action::Fetch(member)).unwrap();
        state.step(Action::Deliver(member)).unwrap(); // ACK is lost.
        let applied = state.clone();
        state.step(Action::Deliver(member)).unwrap();
        assert_eq!(state, applied);
        state.step(Action::Acknowledge(member)).unwrap();
    }
    state.step(Action::Complete).unwrap();
    let completed = state.clone();
    state.step(Action::Complete).unwrap();
    state.step(Action::Deliver(0)).unwrap(); // Historical local no-op only.
    assert_eq!(state, completed);
}

fn denied(state: &mut State, action: Action) {
    let before = state.clone();
    assert!(
        state.step(action).is_err(),
        "unexpected success: {action:?}"
    );
    assert_eq!(*state, before, "failed action mutated state: {action:?}");
}

#[test]
fn revocation_before_decision_blocks_but_after_decision_does_not_cancel_it() {
    let mut before = State::default();
    before.step(Action::Revoke).unwrap();
    denied(&mut before, Action::Decide(PLAN));
    let mut after = State::default();
    after.step(Action::Decide(PLAN)).unwrap();
    after.step(Action::Revoke).unwrap();
    after.step(Action::Decide(PLAN)).unwrap();
    for member in [0, 1] {
        after.step(Action::Fetch(member)).unwrap();
        after.step(Action::Deliver(member)).unwrap();
        after.step(Action::Acknowledge(member)).unwrap();
    }
    after.step(Action::Complete).unwrap();
}

#[test]
fn partition_after_fetch_allows_only_previously_committed_local_delivery() {
    let mut state = State::default();
    state.step(Action::Decide(PLAN)).unwrap();
    state.step(Action::Fetch(0)).unwrap();
    state.available = false;
    state.step(Action::Deliver(0)).unwrap();
    denied(&mut state, Action::Deliver(1));
    denied(&mut state, Action::Fetch(1));
    denied(&mut state, Action::Acknowledge(0));
    denied(&mut state, Action::Complete);
    state.available = true;
    state.step(Action::Acknowledge(0)).unwrap();
    denied(&mut state, Action::Complete);
}

#[test]
fn unknown_authority_continuity_blocks_all_new_authority_operations() {
    let mut state = State {
        continuity: false,
        ..State::default()
    };
    for action in [
        Action::Decide(PLAN),
        Action::Fetch(0),
        Action::Acknowledge(0),
        Action::Complete,
        Action::Revoke,
    ] {
        denied(&mut state, action);
    }
    denied(&mut state, Action::Deliver(0));
}

#[test]
fn wrong_scope_plan_request_or_missing_preparation_never_decides() {
    for binding in [
        Binding { scope: 9, ..PLAN },
        Binding { plan: 9, ..PLAN },
        Binding { request: 9, ..PLAN },
    ] {
        let mut state = State::default();
        denied(&mut state, Action::Decide(binding));
        state.step(Action::Decide(PLAN)).unwrap();
        denied(&mut state, Action::Decide(binding));
    }
    for member in [0, 1] {
        let mut state = State::default();
        state.prepared[member] = false;
        denied(&mut state, Action::Decide(PLAN));
    }
}

#[test]
fn restart_loses_messages_not_committed_decisions_or_member_results() {
    for delivered in [false, true] {
        let mut state = State::default();
        state.step(Action::Decide(PLAN)).unwrap();
        state.step(Action::Fetch(0)).unwrap();
        if delivered {
            state.step(Action::Deliver(0)).unwrap();
        }
        // Abstract crash boundary; NOT a filesystem/process durability test.
        state.inbox = [None; 2];
        denied(&mut state, Action::Deliver(0));
        state.step(Action::Fetch(0)).unwrap();
        state.step(Action::Deliver(0)).unwrap();
        state.step(Action::Acknowledge(0)).unwrap();
        assert_eq!(state.active, [Some(PLAN), None]);
    }
}

#[test]
fn quarantine_and_unknown_member_continuity_reject_delayed_messages() {
    for member in [0, 1] {
        for quarantine in [false, true] {
            let mut state = State::default();
            state.step(Action::Decide(PLAN)).unwrap();
            state.step(Action::Fetch(member)).unwrap();
            if quarantine {
                state.quarantined[member] = true;
            } else {
                state.member_continuity[member] = false;
            }
            denied(&mut state, Action::Deliver(member));
            denied(&mut state, Action::Acknowledge(member));
        }
    }
}

#[test]
fn completion_requires_commits_not_fetches_and_cannot_reactivate_a_restore() {
    let mut state = State::default();
    state.step(Action::Decide(PLAN)).unwrap();
    for member in [0, 1] {
        state.step(Action::Fetch(member)).unwrap();
        denied(&mut state, Action::Acknowledge(member));
        denied(&mut state, Action::Complete);
        state.step(Action::Deliver(member)).unwrap();
        state.step(Action::Acknowledge(member)).unwrap();
    }
    state.step(Action::Complete).unwrap();
    denied(&mut state, Action::Fetch(0));
    // A rolled-back member is NOT allowed to assert continuity as true.
    state.active[0] = None;
    state.member_continuity[0] = false;
    denied(&mut state, Action::Deliver(0));
}

#[test]
fn all_reachable_serialized_message_orders_preserve_safety() {
    use std::collections::{HashSet, VecDeque};
    let initial = State::default();
    let mut seen = HashSet::from([initial.clone()]);
    let mut queue = VecDeque::from([initial]);
    let actions = [
        Action::Decide(PLAN),
        Action::Fetch(0),
        Action::Fetch(1),
        Action::Deliver(0),
        Action::Deliver(1),
        Action::Acknowledge(0),
        Action::Acknowledge(1),
        Action::Complete,
        Action::Revoke,
    ];
    while let Some(state) = queue.pop_front() {
        for action in actions {
            let mut next = state.clone();
            if next.step(action).is_err() {
                assert_eq!(next, state);
            }
            for member in [0, 1] {
                if next.active[member].is_some() {
                    assert_eq!(next.active[member], next.decision);
                }
                if next.acknowledgements[member] {
                    assert_eq!(next.active[member], Some(PLAN));
                }
            }
            if next.complete {
                assert_eq!(next.acknowledgements, [true; 2]);
            }
            if state.decision.is_some() {
                assert_eq!(next.decision, state.decision);
            }
            if seen.insert(next.clone()) {
                queue.push_back(next);
            }
        }
    }
    assert!(seen.iter().any(|s| s.complete && s.revoked));
    assert!(seen.iter().any(|s| s.revoked && s.decision.is_none()));
    println!("explored {} reachable states", seen.len());
}
